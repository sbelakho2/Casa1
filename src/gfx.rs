use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::{Command as HostCommand, Stdio};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const GPU_COMPAT_VENDOR_ENV: &str = "CASA1_GPU_COMPAT_VENDOR";

pub type AdapterId = u64;
pub type OutputId = u64;
pub type SwapchainId = u64;
pub type ResourceId = u64;
pub type DescriptorHeapId = u64;
pub type CommandQueueId = u64;
pub type CommandAllocatorId = u64;
pub type CommandListId = u64;
pub type FenceId = u64;
pub type QueryHeapId = u64;
pub type RootSignatureId = u64;
pub type PipelineStateId = u64;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DxgiFormat {
    R8G8B8A8Unorm,
    R8G8B8A8UnormSrgb,
    R8G8B8A8Uint,
    B8G8R8A8Unorm,
    B8G8R8A8UnormSrgb,
    B8G8R8X8Unorm,
    R8Unorm,
    R8Uint,
    R16Float,
    R16Unorm,
    R16Uint,
    R16Snorm,
    R32Float,
    R32Uint,
    R32Sint,
    R10G10B10A2Unorm,
    R10G10B10A2Uint,
    R11G11B10Float,
    R16G16Float,
    R16G16Unorm,
    R16G16Uint,
    R16G16Snorm,
    R32G32Float,
    R32G32Uint,
    R16G16B16A16Float,
    R16G16B16A16Unorm,
    R16G16B16A16Uint,
    R32G32B32A32Float,
    R32G32B32A32Uint,
    D24UnormS8Uint,
    D32Float,
    D32FloatS8Uint,
    Bc1Unorm,
    Bc1UnormSrgb,
    Bc2Unorm,
    Bc2UnormSrgb,
    Bc3Unorm,
    Bc3UnormSrgb,
    Bc4Unorm,
    Bc5Unorm,
    Bc7Unorm,
    Bc7UnormSrgb,
    B5G6R5Unorm,
}

impl DxgiFormat {
    /// Map a raw `DXGI_FORMAT` enum value (as passed by the guest) to the
    /// closest usable [`DxgiFormat`]. The table follows the canonical ABI
    /// values from `dxgiformat.h`; typeless/SINT/video formats map to the
    /// closest typed variant. Unknown values fall back to `R8G8B8A8Unorm`;
    /// use [`from_u32_checked`](Self::from_u32_checked) when an unknown
    /// format must be rejected instead.
    pub fn from_u32(value: u32) -> Self {
        Self::from_u32_checked(value).unwrap_or(DxgiFormat::R8G8B8A8Unorm)
    }

    /// Map a raw `DXGI_FORMAT` enum value to the closest usable
    /// [`DxgiFormat`], returning an error for values that are not part of
    /// the DXGI ABI. The table follows the canonical values from
    /// `dxgiformat.h`; typeless/SINT/video formats map to the closest typed
    /// variant.
    pub fn from_u32_checked(value: u32) -> AppResult<Self> {
        let format = match value {
            // 0: DXGI_FORMAT_UNKNOWN
            1 | 2 | 5 | 6 => DxgiFormat::R32G32B32A32Float, // R32G32B32A32_TYPELESS/FLOAT, R32G32B32_TYPELESS/FLOAT
            3 | 7 => DxgiFormat::R32G32B32A32Uint, // R32G32B32A32_UINT, R32G32B32_UINT
            4 | 8 => DxgiFormat::R32G32B32A32Uint, // R32G32B32A32_SINT, R32G32B32_SINT (closest: Uint)
            9 | 11 | 13 => DxgiFormat::R16G16B16A16Unorm, // R16G16B16A16_TYPELESS/UNORM/SNORM
            10 => DxgiFormat::R16G16B16A16Float, // R16G16B16A16_FLOAT
            12 => DxgiFormat::R16G16B16A16Uint, // R16G16B16A16_UINT
            14 => DxgiFormat::R16G16B16A16Uint, // R16G16B16A16_SINT (closest: Uint)
            15 | 16 => DxgiFormat::R32G32Float, // R32G32_TYPELESS/FLOAT
            17 => DxgiFormat::R32G32Uint,       // R32G32_UINT
            18 => DxgiFormat::R32G32Uint,       // R32G32_SINT (closest: Uint)
            19 => DxgiFormat::D32FloatS8Uint,   // R32G8X24_TYPELESS (closest: depth-stencil)
            20 => DxgiFormat::D32FloatS8Uint,   // D32_FLOAT_S8X24_UINT
            21 => DxgiFormat::D32FloatS8Uint,   // R32_FLOAT_X8X24_TYPELESS
            22 => DxgiFormat::D32FloatS8Uint,   // X32_TYPELESS_G8X24_UINT
            23 | 24 => DxgiFormat::R10G10B10A2Unorm, // R10G10B10A2_TYPELESS/UNORM
            25 => DxgiFormat::R10G10B10A2Uint,  // R10G10B10A2_UINT
            26 => DxgiFormat::R11G11B10Float,   // R11G11B10_FLOAT
            27 | 28 => DxgiFormat::R8G8B8A8Unorm, // R8G8B8A8_TYPELESS/UNORM
            29 => DxgiFormat::R8G8B8A8UnormSrgb, // R8G8B8A8_UNORM_SRGB
            30 => DxgiFormat::R8G8B8A8Uint,     // R8G8B8A8_UINT
            31 => DxgiFormat::R8G8B8A8Unorm,    // R8G8B8A8_SNORM (closest: Unorm)
            32 => DxgiFormat::R8G8B8A8Uint,     // R8G8B8A8_SINT (closest: Uint)
            33 | 35 => DxgiFormat::R16G16Unorm, // R16G16_TYPELESS/UNORM
            34 => DxgiFormat::R16G16Float,      // R16G16_FLOAT
            36 => DxgiFormat::R16G16Uint,       // R16G16_UINT
            37 => DxgiFormat::R16G16Snorm,      // R16G16_SNORM
            38 => DxgiFormat::R16G16Uint,       // R16G16_SINT (closest: Uint)
            39 | 41 => DxgiFormat::R32Float,    // R32_TYPELESS/R32_FLOAT
            40 => DxgiFormat::D32Float,         // D32_FLOAT
            42 => DxgiFormat::R32Uint,          // R32_UINT
            43 => DxgiFormat::R32Sint,          // R32_SINT
            44 | 45 => DxgiFormat::D24UnormS8Uint, // R24G8_TYPELESS/D24_UNORM_S8_UINT
            46 | 47 => DxgiFormat::D24UnormS8Uint, // R24_UNORM_X8_TYPELESS/X24_TYPELESS_G8_UINT
            48 | 49 => DxgiFormat::R16G16Unorm, // R8G8_TYPELESS/UNORM (closest: 2×16)
            50 => DxgiFormat::R16G16Uint,       // R8G8_UINT
            51 => DxgiFormat::R16G16Snorm,      // R8G8_SNORM
            52 => DxgiFormat::R16G16Uint,       // R8G8_SINT (closest: Uint)
            53 | 56 => DxgiFormat::R16Unorm,    // R16_TYPELESS/R16_UNORM
            54 => DxgiFormat::R16Float,         // R16_FLOAT
            55 => DxgiFormat::R16Unorm,         // D16_UNORM (closest: R16)
            57 => DxgiFormat::R16Uint,          // R16_UINT
            58 => DxgiFormat::R16Snorm,         // R16_SNORM
            59 => DxgiFormat::R16Uint,          // R16_SINT (closest: Uint)
            60 | 61 => DxgiFormat::R8Unorm,     // R8_TYPELESS/R8_UNORM
            62 => DxgiFormat::R8Uint,           // R8_UINT
            63 => DxgiFormat::R8Unorm,          // R8_SNORM (closest: Unorm)
            64 => DxgiFormat::R8Uint,           // R8_SINT (closest: Uint)
            65 => DxgiFormat::R8Unorm,          // A8_UNORM
            66 => DxgiFormat::R8Unorm,          // R1_UNORM (closest: R8)
            67 => DxgiFormat::R11G11B10Float,   // R9G9B9E5_SHAREDEXP (closest: packed float)
            68 | 69 => DxgiFormat::R8G8B8A8Unorm, // R8G8_B8G8_UNORM/G8R8_G8B8_UNORM
            70 | 71 => DxgiFormat::Bc1Unorm,    // BC1_TYPELESS/BC1_UNORM
            72 => DxgiFormat::Bc1UnormSrgb,     // BC1_UNORM_SRGB
            73 | 74 => DxgiFormat::Bc2Unorm,    // BC2_TYPELESS/BC2_UNORM
            75 => DxgiFormat::Bc2UnormSrgb,     // BC2_UNORM_SRGB
            76 | 77 => DxgiFormat::Bc3Unorm,    // BC3_TYPELESS/BC3_UNORM
            78 => DxgiFormat::Bc3UnormSrgb,     // BC3_UNORM_SRGB
            79 | 80 => DxgiFormat::Bc4Unorm,    // BC4_TYPELESS/BC4_UNORM
            81 => DxgiFormat::Bc4Unorm,         // BC4_SNORM (closest: Unorm)
            82 | 83 => DxgiFormat::Bc5Unorm,    // BC5_TYPELESS/BC5_UNORM
            84 => DxgiFormat::Bc5Unorm,         // BC5_SNORM (closest: Unorm)
            85 => DxgiFormat::B5G6R5Unorm,      // B5G6R5_UNORM
            86 => DxgiFormat::B5G6R5Unorm,      // B5G5R5A1_UNORM (closest: B5G6R5)
            87 => DxgiFormat::B8G8R8A8Unorm,    // B8G8R8A8_UNORM
            88 => DxgiFormat::B8G8R8X8Unorm,    // B8G8R8X8_UNORM
            89 => DxgiFormat::R10G10B10A2Unorm, // R10G10B10_XR_BIAS_A2_UNORM (closest)
            90 => DxgiFormat::B8G8R8A8Unorm,    // B8G8R8A8_TYPELESS
            91 => DxgiFormat::B8G8R8A8UnormSrgb, // B8G8R8A8_UNORM_SRGB
            92 => DxgiFormat::B8G8R8X8Unorm,    // B8G8R8X8_TYPELESS
            93 => DxgiFormat::B8G8R8A8UnormSrgb, // B8G8R8X8_UNORM_SRGB (closest: sRGB BGRA)
            94..=96 => DxgiFormat::Bc7Unorm, // BC6H_TYPELESS/UF16/SF16 (closest: same block size)
            97 | 98 => DxgiFormat::Bc7Unorm,    // BC7_TYPELESS/BC7_UNORM
            99 => DxgiFormat::Bc7UnormSrgb,     // BC7_UNORM_SRGB
            100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 | 109 | 110 | 111 | 112
            | 113 | 114 | 115 | 130 | 131 | 132 => DxgiFormat::R8G8B8A8Unorm, // AYUV/video formats
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("unknown DXGI_FORMAT value {value}"),
                ));
            }
        };
        Ok(format)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MtlPixelFormat {
    Rgba8Unorm,
    Rgba8UnormSrgb,
    Rgba8Uint,
    Bgra8Unorm,
    Bgra8UnormSrgb,
    R8Unorm,
    R8Uint,
    R16Float,
    R16Unorm,
    R16Uint,
    R16Snorm,
    R32Float,
    R32Uint,
    R32Sint,
    Rgb10A2Unorm,
    Rgb10A2Uint,
    Rg11B10Float,
    Rg16Float,
    Rg16Unorm,
    Rg16Uint,
    Rg16Snorm,
    Rg32Float,
    Rg32Uint,
    Rgba16Float,
    Rgba16Unorm,
    Rgba16Uint,
    Rgba32Float,
    Rgba32Uint,
    Depth24UnormStencil8,
    Depth32Float,
    Depth32FloatStencil8,
    Bc1Rgba,
    Bc1RgbaSrgb,
    Bc2Rgba,
    Bc2RgbaSrgb,
    Bc3Rgba,
    Bc3RgbaSrgb,
    Bc4RUnorm,
    Bc5RgUnorm,
    Bc7RgbaUnorm,
    Bc7RgbaUnormSrgb,
    B5G6R5Unorm,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmulationStrategy {
    Direct,
    ConversionShader,
    Swizzle,
    DepthStencilEmulation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormatMapping {
    pub dxgi: DxgiFormat,
    pub metal: MtlPixelFormat,
    pub strategy: EmulationStrategy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureQuery {
    Tearing,
    TimestampQueries,
    MeshShaders,
    /// Hardware-accelerated ray tracing (requires Metal 3.0+ / Apple GPU family 7+).
    Raytracing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterInfo {
    pub id: AdapterId,
    pub vendor_id: u32,
    pub device_id: u32,
    pub name: String,
    pub metal_family: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetalCapabilities {
    pub unified_memory: bool,
    pub argument_buffers: bool,
    pub memoryless_render_targets: bool,
    pub timestamp_queries: bool,
    pub mesh_shaders: bool,
    /// Hardware-accelerated ray tracing (Metal 3.0+ / Apple GPU family 7+).
    pub raytracing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostGpuProfile {
    pub adapter: AdapterInfo,
    pub capabilities: MetalCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportedGpuVendor {
    Apple,
    Nvidia,
    Amd,
}

impl ReportedGpuVendor {
    fn vendor_id(self) -> u32 {
        match self {
            Self::Apple => 0x106b,
            Self::Nvidia => 0x10de,
            Self::Amd => 0x1002,
        }
    }

    /// Returns a PCI device ID for the vendor's GPU corresponding to the given
    /// Metal GPU family.  Uses known device IDs for common GPU generations and
    /// falls back to a family‑based computed value for unknown families.
    fn device_id_for_family(self, family: u8) -> u32 {
        match self {
            Self::Apple => match family {
                7 => 0x0007,  // Apple7 (A13/A14)
                8 => 0x0008,  // Apple8 (M1)
                9 => 0x0009,  // Apple9 (M2)
                10 => 0x000A, // Apple10 (M3)
                11 => 0x000B, // Apple11 (M4)
                f => 0x1000 | (f as u32 & 0xFF),
            },
            Self::Nvidia => match family {
                2 => 0x1180, // Kepler
                3 => 0x13C0, // Maxwell
                4 => 0x1B00, // Pascal
                5 => 0x1E00, // Turing
                6 => 0x2200, // Ampere
                7 => 0x2680, // Ada Lovelace
                f => 0x2000 | (f as u32 & 0xFF),
            },
            Self::Amd => match family {
                2 => 0x6798, // GCN 1
                3 => 0x67DF, // GCN 3 / Polaris
                4 => 0x687F, // Vega
                5 => 0x7310, // RDNA 1 (Navi 10)
                6 => 0x73BF, // RDNA 2 (Navi 21)
                7 => 0x74A0, // RDNA 3 (Navi 31)
                f => 0x7000 | (f as u32 & 0xFF),
            },
        }
    }

    fn compatibility_adapter_name(self, original: &str) -> String {
        match self {
            Self::Apple => original.to_string(),
            Self::Nvidia => format!("NVIDIA Compatibility Adapter ({original})"),
            Self::Amd => format!("AMD Compatibility Adapter ({original})"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub refresh_numerator: u32,
    pub refresh_denominator: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputInfo {
    pub id: OutputId,
    pub name: String,
    pub dpi_x: u32,
    pub dpi_y: u32,
    pub modes: Vec<DisplayMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapchainDesc {
    pub width: u32,
    pub height: u32,
    pub format: DxgiFormat,
    pub buffer_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapchainState {
    pub id: SwapchainId,
    pub desc: SwapchainDesc,
    pub backbuffers: Vec<ResourceId>,
    pub queued_frames: u32,
    pub max_frame_latency: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentResult {
    pub queued_frames: u32,
    pub effective_sync_interval: u32,
    pub tearing_allowed: bool,
    pub displayed_frame_index: u64,
    pub frame_time_us: u64,
}

/// Origin of a presented frame.  Every `PresentedFrame` is labelled with the
/// API that produced its pixels; no synthetic frames are ever published.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FrameSource {
    /// 32-bit GDI window content (real window surfaces only).
    Gdi,
    /// GDI+ rendered content.
    GdiPlus,
    /// Chromium Embedded Framework software-rendered content.
    CefSoftware,
    /// Chromium Embedded Framework accelerated content.
    CefAccelerated,
    /// Direct3D 9 swapchain present.
    D3D9,
    /// DXGI swapchain presented through a D3D10 device.
    DxgiD3D10,
    /// DXGI swapchain presented through a D3D11 device.
    DxgiD3D11,
    /// DXGI swapchain presented through a D3D12 device.
    DxgiD3D12,
    /// Vulkan swapchain present.
    Vulkan,
    /// OpenGL backbuffer present.
    OpenGL,
}

fn presented_frame_default_timestamp() -> std::time::Instant {
    std::time::Instant::now()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresentedFrame {
    pub width: u32,
    pub height: u32,
    pub format: DxgiFormat,
    pub bytes: Vec<u8>,
    /// API that produced this frame (see [`FrameSource`]).
    pub source: FrameSource,
    /// Bytes per pixel row of `bytes` (0 when the row pitch is unknown).
    pub stride: usize,
    /// Monotonic present sequence number for the presenting swapchain.
    pub sequence: u64,
    /// Host-side capture time of this frame.  Excluded from serialization
    /// because `std::time::Instant` is not serializable.
    #[serde(skip, default = "presented_frame_default_timestamp")]
    pub timestamp: std::time::Instant,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeapType {
    Default,
    Upload,
    Readback,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetalStorageMode {
    Shared,
    Private,
    Memoryless,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    /// D3D12_RESOURCE_STATE_COMMON (0) — default state; not tracked
    Common,
    /// D3D12_RESOURCE_STATE_PRESENT (0) — same as common for swapchain backbuffers
    Present,
    /// D3D12_RESOURCE_STATE_VERTEX_AND_CONSTANT_BUFFER (0x0001)
    VertexAndConstantBuffer,
    /// D3D12_RESOURCE_STATE_INDEX_BUFFER (0x0002)
    IndexBuffer,
    /// D3D12_RESOURCE_STATE_RENDER_TARGET (0x0004)
    RenderTarget,
    /// D3D12_RESOURCE_STATE_UNORDERED_ACCESS (0x0008)
    UnorderedAccess,
    /// D3D12_RESOURCE_STATE_DEPTH_WRITE (0x0010)
    DepthWrite,
    /// D3D12_RESOURCE_STATE_DEPTH_READ (0x0020)
    DepthRead,
    /// D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE (0x0040)
    NonPixelShaderResource,
    /// D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE (0x0080)
    PixelShaderResource,
    /// D3D12_RESOURCE_STATE_STREAM_OUT (0x0100)
    StreamOut,
    /// D3D12_RESOURCE_STATE_INDIRECT_ARGUMENT (0x0200)
    IndirectArgument,
    /// D3D12_RESOURCE_STATE_COPY_DEST (0x0400)
    CopyDest,
    /// D3D12_RESOURCE_STATE_COPY_SOURCE (0x0800)
    CopySource,
    /// D3D12_RESOURCE_STATE_RESOLVE_DEST (0x1000)
    ResolveDest,
    /// D3D12_RESOURCE_STATE_RESOLVE_SOURCE (0x2000)
    ResolveSource,
    /// D3D12_RESOURCE_STATE_RAYTRACING_ACCELERATION_STRUCTURE (0x4000)
    RaytracingAccelerationStructure,
    /// D3D12_RESOURCE_STATE_SHADING_RATE_SOURCE (0x10000)
    ShadingRateSource,
    /// D3D12_RESOURCE_STATE_VIDEO_DECODE_READ (0x00010000)
    VideoDecodeRead,
    /// D3D12_RESOURCE_STATE_VIDEO_DECODE_WRITE (0x00020000)
    VideoDecodeWrite,
    /// D3D12_RESOURCE_STATE_VIDEO_PROCESS_READ (0x00040000)
    VideoProcessRead,
    /// D3D12_RESOURCE_STATE_VIDEO_PROCESS_WRITE (0x00080000)
    VideoProcessWrite,
    /// D3D12_RESOURCE_STATE_VIDEO_ENCODE_READ (0x00100000)
    VideoEncodeRead,
    /// D3D12_RESOURCE_STATE_VIDEO_ENCODE_WRITE (0x00200000)
    VideoEncodeWrite,
    /// D3D12_RESOURCE_STATE_GENERIC_READ (combination: VB/IB/indirect/copy-src/SRV)
    GenericRead,
    /// D3D12_RESOURCE_STATE_ALL_SHADER_RESOURCE (SRV visible to all stages)
    AllShaderResource,
}

impl ResourceState {
    /// Map from raw D3D12_RESOURCE_STATES bitmask to our enum.
    /// Returns multiple states if it's a combined bitmask (e.g. GenericRead).
    pub fn from_d3d12_bits(bits: u32) -> Vec<ResourceState> {
        if bits == 0 {
            return vec![ResourceState::Common];
        }
        let mut result = Vec::new();
        if bits & 0x0001 != 0 {
            result.push(ResourceState::VertexAndConstantBuffer);
        }
        if bits & 0x0002 != 0 {
            result.push(ResourceState::IndexBuffer);
        }
        if bits & 0x0004 != 0 {
            result.push(ResourceState::RenderTarget);
        }
        if bits & 0x0008 != 0 {
            result.push(ResourceState::UnorderedAccess);
        }
        if bits & 0x0010 != 0 {
            result.push(ResourceState::DepthWrite);
        }
        if bits & 0x0020 != 0 {
            result.push(ResourceState::DepthRead);
        }
        if bits & 0x0040 != 0 {
            result.push(ResourceState::NonPixelShaderResource);
        }
        if bits & 0x0080 != 0 {
            result.push(ResourceState::PixelShaderResource);
        }
        if bits & 0x0100 != 0 {
            result.push(ResourceState::StreamOut);
        }
        if bits & 0x0200 != 0 {
            result.push(ResourceState::IndirectArgument);
        }
        if bits & 0x0400 != 0 {
            result.push(ResourceState::CopyDest);
        }
        if bits & 0x0800 != 0 {
            result.push(ResourceState::CopySource);
        }
        if bits & 0x1000 != 0 {
            result.push(ResourceState::ResolveDest);
        }
        if bits & 0x2000 != 0 {
            result.push(ResourceState::ResolveSource);
        }
        if bits & 0x4000 != 0 {
            result.push(ResourceState::RaytracingAccelerationStructure);
        }
        // D3D12_RESOURCE_STATE_SHADING_RATE_SOURCE (0x10000) and
        // D3D12_RESOURCE_STATE_VIDEO_DECODE_READ (0x00010000) alias to the
        // same bit in d3d12.h (mutually exclusive contexts), so only one
        // variant is reported.
        if bits & 0x10000 != 0 {
            result.push(ResourceState::ShadingRateSource);
        }
        if bits & 0x00020000 != 0 {
            result.push(ResourceState::VideoDecodeWrite);
        }
        if bits & 0x00040000 != 0 {
            result.push(ResourceState::VideoProcessRead);
        }
        if bits & 0x00080000 != 0 {
            result.push(ResourceState::VideoProcessWrite);
        }
        if bits & 0x00100000 != 0 {
            result.push(ResourceState::VideoEncodeRead);
        }
        if bits & 0x00200000 != 0 {
            result.push(ResourceState::VideoEncodeWrite);
        }
        // D3D12_RESOURCE_STATE_GENERIC_READ is the composite of all the
        // read-only buffer/shader/copy states. When every component bit is
        // present, the resource is in the canonical GENERIC_READ state.
        if bits & 0x0AC3 == 0x0AC3 {
            result.push(ResourceState::GenericRead);
        }
        if result.is_empty() {
            result.push(ResourceState::GenericRead);
        }
        result
    }

    /// Map our enum back to a D3D12_RESOURCE_STATES bitmask.
    pub fn to_d3d12_bits(&self) -> u32 {
        match self {
            ResourceState::Common => 0,
            ResourceState::Present => 0,
            ResourceState::VertexAndConstantBuffer => 0x0001,
            ResourceState::IndexBuffer => 0x0002,
            ResourceState::RenderTarget => 0x0004,
            ResourceState::UnorderedAccess => 0x0008,
            ResourceState::DepthWrite => 0x0010,
            ResourceState::DepthRead => 0x0020,
            ResourceState::NonPixelShaderResource => 0x0040,
            ResourceState::PixelShaderResource => 0x0080,
            ResourceState::StreamOut => 0x0100,
            ResourceState::IndirectArgument => 0x0200,
            ResourceState::CopyDest => 0x0400,
            ResourceState::CopySource => 0x0800,
            ResourceState::ResolveDest => 0x1000,
            ResourceState::ResolveSource => 0x2000,
            ResourceState::RaytracingAccelerationStructure => 0x4000,
            ResourceState::ShadingRateSource => 0x10000,
            ResourceState::VideoDecodeRead => 0x00010000,
            ResourceState::VideoDecodeWrite => 0x00020000,
            ResourceState::VideoProcessRead => 0x00040000,
            ResourceState::VideoProcessWrite => 0x00080000,
            ResourceState::VideoEncodeRead => 0x00100000,
            ResourceState::VideoEncodeWrite => 0x00200000,
            ResourceState::GenericRead => 0x0AC3,
            ResourceState::AllShaderResource => 0x00C0,
        }
    }

    /// Returns true if this state allows read-only access from shaders.
    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            ResourceState::Common
                | ResourceState::Present
                | ResourceState::VertexAndConstantBuffer
                | ResourceState::IndexBuffer
                | ResourceState::DepthRead
                | ResourceState::NonPixelShaderResource
                | ResourceState::PixelShaderResource
                | ResourceState::IndirectArgument
                | ResourceState::CopySource
                | ResourceState::ResolveSource
                | ResourceState::GenericRead
                | ResourceState::AllShaderResource
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BufferRole {
    Generic,
    Constant,
    Vertex,
    Index,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceUsageHint {
    Generic,
    SwapchainBackbuffer,
    DepthStencil,
    Buffer {
        role: BufferRole,
        cpu_write_frequent: bool,
    },
    Texture {
        sampled: bool,
        render_target: bool,
        depth_stencil: bool,
        cpu_write_frequent: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceDesc {
    pub name: String,
    pub format: DxgiFormat,
    pub heap: HeapType,
    pub size: usize,
    pub subresources: u32,
    pub initial_state: ResourceState,
    pub usage_hint: ResourceUsageHint,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DescriptorHeapType {
    CbvSrvUav,
    Sampler,
    Rtv,
    Dsv,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterMode {
    Point,
    Linear,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ViewDescriptor {
    Cbv {
        resource: ResourceId,
        size: usize,
    },
    Srv {
        resource: ResourceId,
        format: DxgiFormat,
    },
    Uav {
        resource: ResourceId,
        format: DxgiFormat,
    },
    Sampler {
        filter: FilterMode,
    },
    Rtv {
        resource: ResourceId,
        format: DxgiFormat,
    },
    Dsv {
        resource: ResourceId,
        format: DxgiFormat,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetalBinding {
    pub slot: u32,
    pub kind: String,
    pub resource: Option<ResourceId>,
    pub metal_format: Option<MtlPixelFormat>,
}

/// D3D12_DESCRIPTOR_RANGE_TYPE — type of descriptor in a descriptor range.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum D3D12DescriptorRangeType {
    Srv,
    Uav,
    Cbv,
    Sampler,
}

/// Mapping from descriptor range type to Metal argument buffer resource type.
impl D3D12DescriptorRangeType {
    pub fn to_metal_resource_type(&self) -> &'static str {
        match self {
            D3D12DescriptorRangeType::Srv => "texture",
            D3D12DescriptorRangeType::Uav => "texture",
            D3D12DescriptorRangeType::Cbv => "buffer",
            D3D12DescriptorRangeType::Sampler => "sampler",
        }
    }
}

/// D3D12_SHADER_VISIBILITY — which shader stages a root parameter applies to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum D3D12ShaderVisibility {
    #[default]
    All,
    Vertex,
    Hull,
    Domain,
    Geometry,
    Pixel,
    Amplification,
    Mesh,
}

/// A single descriptor range within a descriptor table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DescriptorRange {
    pub range_type: D3D12DescriptorRangeType,
    pub num_descriptors: u32,
    pub base_shader_register: u32,
    pub register_space: u32,
    /// Offset from the start of the descriptor table. D3D12_DESCRIPTOR_RANGE_OFFSET_APPEND = -1.
    pub offset_in_table: u32,
}

/// D3D12_STATIC_SAMPLER_DESC — a sampler that is baked into the root signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct D3D12StaticSamplerDesc {
    pub shader_register: u32,
    pub register_space: u32,
    pub filter: u32,    // D3D12_FILTER
    pub address_u: u32, // D3D12_TEXTURE_ADDRESS_MODE
    pub address_v: u32,
    pub address_w: u32,
    pub mip_lod_bias: f32,
    pub max_anisotropy: u32,
    pub comparison_func: u32, // D3D12_COMPARISON_FUNC
    pub border_color: u32,    // D3D12_STATIC_BORDER_COLOR
    pub min_lod: f32,
    pub max_lod: f32,
    pub shader_visibility: D3D12ShaderVisibility,
}

/// A single root parameter (descriptor table, root descriptor, or root constant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RootParameter {
    DescriptorTable {
        ranges: Vec<DescriptorRange>,
        visibility: D3D12ShaderVisibility,
    },
    RootDescriptor {
        range_type: D3D12DescriptorRangeType,
        shader_register: u32,
        register_space: u32,
        visibility: D3D12ShaderVisibility,
    },
    RootConstants {
        shader_register: u32,
        register_space: u32,
        num_32bit_values: u32,
        visibility: D3D12ShaderVisibility,
    },
}

/// Expanded root signature descriptor with full D3D12 parameter mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RootSignatureDesc {
    pub descriptor_tables: Vec<u32>,
    pub root_constants: u32,
    /// Root parameters (expanded form for Phase 2.1).
    pub parameters: Vec<RootParameter>,
    /// Static samplers baked into the root signature.
    pub static_samplers: Vec<D3D12StaticSamplerDesc>,
    /// Per-shader-visibility descriptor table offset state.
    pub visibility_offsets: BTreeMap<D3D12ShaderVisibility, Vec<u32>>,
}

/// D3D12_RESOURCE_BARRIER_TYPE — which type of barrier is being issued.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum D3D12ResourceBarrierType {
    Transition,
    Aliasing,
    Uav,
}

/// Flags for D3D12_RESOURCE_BARRIER_FLAGS.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum D3D12ResourceBarrierFlags {
    None,
    BeginOnly,
    EndOnly,
}

/// A pending split barrier (begin without matching end).
#[derive(Debug, Clone)]
pub struct PendingSplitBarrier {
    pub resource: ResourceId,
    pub subresource: u32,
    pub state_before: ResourceState,
    pub state_after: ResourceState,
}

/// Describes a full D3D12_RESOURCE_BARRIER (type, flags, and state).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3D12ResourceBarrierDesc {
    pub barrier_type: D3D12ResourceBarrierType,
    pub flags: D3D12ResourceBarrierFlags,
    /// For Transition barriers.
    pub resource: Option<ResourceId>,
    pub subresource: u32,
    pub state_before: ResourceState,
    pub state_after: ResourceState,
    /// For Aliasing barriers.
    pub resource_before: Option<ResourceId>,
    pub resource_after: Option<ResourceId>,
}

/// Per-subresource barrier state tracking key.
pub type SubresourceKey = (ResourceId, u32, u32);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineStateDesc {
    pub label: String,
    pub compute: bool,
    pub render_target_formats: Vec<DxgiFormat>,
    pub depth_format: Option<DxgiFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryResolveResult {
    pub values: Vec<u64>,
    pub emulated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryType {
    Timestamp,
    Occlusion,
    PipelineStatistics,
    SoStatistics,
    VideoDecodeStat,
    VideoProcessStat,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Command {
    Transition {
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    },
    /// D3D12_RESOURCE_BARRIER_TYPE_TRANSITION with D3D12_RESOURCE_BARRIER_FLAG_BEGIN_ONLY.
    SplitBarrierBegin {
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    },
    /// D3D12_RESOURCE_BARRIER_TYPE_TRANSITION with D3D12_RESOURCE_BARRIER_FLAG_END_ONLY.
    SplitBarrierEnd {
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    },
    UavBarrier {
        resource: ResourceId,
    },
    AliasingBarrier {
        before: Option<ResourceId>,
        after: Option<ResourceId>,
    },
    SetRootConstants {
        values: Vec<u32>,
    },
    BeginRenderPass {
        color_formats: Vec<DxgiFormat>,
        depth_format: Option<DxgiFormat>,
        load_action: String,
        store_action: String,
    },
    ClearRtv {
        heap: DescriptorHeapId,
        index: usize,
    },
    ClearDsv {
        heap: DescriptorHeapId,
        index: usize,
    },
    Draw {
        vertices: u32,
    },
    DrawInstanced {
        vertices: u32,
        instances: u32,
    },
    Dispatch {
        x: u32,
        y: u32,
        z: u32,
    },
    /// Dispatch a mesh shader threadgroup. Behaves like Dispatch but uses a
    /// mesh shader pipeline instead of a compute pipeline. Requires Metal
    /// mesh shader support (Apple9+/M3+).
    DispatchMesh {
        x: u32,
        y: u32,
        z: u32,
    },
    CopyResource {
        src: ResourceId,
        dst: ResourceId,
    },
    CopyBufferRegion {
        dst: ResourceId,
        dst_offset: u64,
        src: ResourceId,
        src_offset: u64,
        size: u64,
    },
    CopyResourceRegion {
        dst: ResourceId,
        dst_x: u32,
        dst_y: u32,
        dst_z: u32,
        src: ResourceId,
        src_x: u32,
        src_y: u32,
        src_z: u32,
        width: u32,
        height: u32,
        depth: u32,
    },
    ResolveSubresource {
        dst: ResourceId,
        src: ResourceId,
        /// Raw DXGI_FORMAT u32 value.
        format: u32,
        resolve_mode: u32,
    },
    /// Execute a pre-recorded D3D12 command bundle on the parent command list.
    /// The bundle's commands are snapshotted at `record_execute_bundle` time (when
    /// the D3D12 application calls `ID3D12GraphicsCommandList1::ExecuteBundle`) so
    /// that the bundle can be Reset and re-recorded without affecting already-
    /// enqueued executions.
    ExecuteBundle {
        bundle_commands: Vec<Command>,
    },
    /// Dispatch rays for DXR (DirectX Raytracing).
    ///
    /// Corresponds to `ID3D12GraphicsCommandList4::DispatchRays`. The shader
    /// table addresses are GPU virtual addresses that point to the raygen, miss,
    /// and hit-group shader tables. The acceleration structure and intersection
    /// function table are bound via the pipeline state and descriptor heaps.
    ///
    /// During execution, this increments the raytrace pass counter and is
    /// processed by the Metal backend which creates a `MetalRayTracingEncoder`
    /// (backed by a compute encoder) and dispatches the ray tracing grid.
    DispatchRays {
        /// GPU virtual address of the raygen shader table.
        raygen_address: u64,
        /// GPU virtual address of the miss shader table.
        miss_address: u64,
        /// GPU virtual address of the hit-group shader table.
        hit_address: u64,
        /// GPU virtual address of the callable shader table (0 if none).
        callable_address: u64,
        /// Width of the ray dispatch grid (number of rays in X).
        width: u32,
        /// Height of the ray dispatch grid (number of rays in Y).
        height: u32,
        /// Depth of the ray dispatch grid (number of rays in Z).
        depth: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImmutableCommandStream {
    pub id: CommandListId,
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderPassPlan {
    pub color_formats: Vec<MtlPixelFormat>,
    pub depth_format: Option<MtlPixelFormat>,
    pub draw_calls: u32,
    pub load_action: String,
    pub store_action: String,
}

impl RenderPassPlan {
    /// Two adjacent render passes can be coalesced into one when they target an
    /// identical attachment configuration (same color attachment formats in the
    /// same order and the same optional depth format) *and* the follow-on pass
    /// merely loads the existing attachments. This is the standard Metal
    /// load/store-action coalescing optimisation: a `store` followed by a
    /// matching `load` of the same attachments is redundant, so the passes are
    /// merged and the surviving pass adopts the later pass's store action. A
    /// follow-on pass that *clears* (or otherwise discards) its attachments
    /// establishes a fresh, observable starting state and must never be folded
    /// into the previous pass.
    pub fn can_merge_with(
        &self,
        color_formats: &[MtlPixelFormat],
        depth_format: Option<MtlPixelFormat>,
        load_action: &str,
    ) -> bool {
        self.color_formats == color_formats
            && self.depth_format == depth_format
            && load_action == "load"
    }

    /// Merge a compatible follow-on render pass into `self`. The caller is
    /// responsible for having checked [`can_merge_with`]; only the store action
    /// is updated, since the attachment formats and load action of the first
    /// pass are retained for the coalesced pass.
    ///
    /// [`can_merge_with`]: RenderPassPlan::can_merge_with
    pub fn merge_store_action(&mut self, store_action: &str) {
        self.store_action = store_action.to_string();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetalCommandBufferPlan {
    pub render_passes: Vec<RenderPassPlan>,
    pub compute_passes: u32,
    pub blit_passes: u32,
    /// Number of raytracing dispatch passes (DispatchRays calls).
    pub raytrace_passes: u32,
    pub validation_errors: Vec<String>,
    pub root_constants_log: Vec<Vec<u32>>,
    pub signaled_fences: Vec<(FenceId, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SceneSpec {
    pub name: String,
    pub format: DxgiFormat,
    pub clear_color: [u8; 4],
    pub draw_calls: u32,
    pub compute_dispatches: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FrameArtifact {
    pub hash: String,
    pub ssim: f32,
    pub validation_errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct ResourceRecord {
    desc: ResourceDesc,
    states: Vec<ResourceState>,
    bytes: Vec<u8>,
    storage_mode: MetalStorageMode,
}

#[derive(Debug, Clone)]
struct DescriptorHeapRecord {
    ty: DescriptorHeapType,
    descriptors: Vec<Option<ViewDescriptor>>,
}

#[derive(Debug, Clone)]
struct SwapchainRecord {
    state: SwapchainState,
    next_present_index: u64,
    presented_backbuffer_index: usize,
    /// Host timestamp of the previous `present()` — used to measure real
    /// frame timing instead of fabricating a fixed interval.
    last_present_at: Option<std::time::Instant>,
}

#[derive(Debug, Clone)]
struct QueryHeapRecord {
    ty: QueryType,
    values: Vec<u64>,
    emulated: bool,
}

#[derive(Debug, Clone)]
struct CommandListRecord {
    pipeline_state: PipelineStateId,
    commands: Vec<Command>,
    closed: bool,
    /// True if this command list is a D3D12 bundle
    /// (D3D12_COMMAND_LIST_TYPE_BUNDLE). Bundles are pre-recorded sequences
    /// that can be replayed via ExecuteBundle on a parent direct command list.
    is_bundle: bool,
}

#[derive(Debug, Clone)]
struct FenceRecord {
    value: u64,
}

pub struct GraphicsBackend {
    next_id: u64,
    adapter: AdapterInfo,
    capabilities: MetalCapabilities,
    outputs: Vec<OutputInfo>,
    swapchains: BTreeMap<SwapchainId, SwapchainRecord>,
    resources: BTreeMap<ResourceId, ResourceRecord>,
    descriptor_heaps: BTreeMap<DescriptorHeapId, DescriptorHeapRecord>,
    command_lists: BTreeMap<CommandListId, CommandListRecord>,
    fences: BTreeMap<FenceId, FenceRecord>,
    query_heaps: BTreeMap<QueryHeapId, QueryHeapRecord>,
    root_signatures: BTreeMap<RootSignatureId, RootSignatureDesc>,
    pipeline_states: BTreeMap<PipelineStateId, PipelineStateDesc>,
    timestamps: u64,
    /// Per-subresource barrier state tracking: (resource, 0, flat D3D12
    /// subresource index) -> state. The flat index follows the D3D12
    /// convention (mip + array_slice * mip_levels).
    subresource_states: BTreeMap<SubresourceKey, ResourceState>,
    /// Pending split barriers (BEGIN_ONLY that have not yet been END_ONLY'd).
    pending_split_barriers: Vec<PendingSplitBarrier>,
    /// Optional callback invoked on every `present()` with the presented frame.
    /// Enables connecting D3D swapchain presents to the live display pipeline.
    /// The callback receives the current backbuffer bytes, width, height, and format.
    frame_published_callback: Option<Box<dyn FnMut(PresentedFrame) + Send>>,
    /// API that presents through this backend; labels every `PresentedFrame`
    /// produced by [`presented_frame`](Self::presented_frame).
    frame_source: FrameSource,
}

impl std::fmt::Debug for GraphicsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphicsBackend")
            .field("next_id", &self.next_id)
            .field("adapter", &self.adapter)
            .field("capabilities", &self.capabilities)
            .field("outputs", &self.outputs)
            .field("swapchains", &self.swapchains)
            .field("resources", &self.resources)
            .field("descriptor_heaps", &self.descriptor_heaps)
            .field("command_lists", &self.command_lists)
            .field("fences", &self.fences)
            .field("query_heaps", &self.query_heaps)
            .field("root_signatures", &self.root_signatures)
            .field("pipeline_states", &self.pipeline_states)
            .field("timestamps", &self.timestamps)
            .field("subresource_states", &self.subresource_states)
            .field("pending_split_barriers", &self.pending_split_barriers)
            .field(
                "frame_published_callback",
                &self
                    .frame_published_callback
                    .as_ref()
                    .map(|_| "FnMut(PresentedFrame)"),
            )
            .field("frame_source", &self.frame_source)
            .finish()
    }
}

impl Clone for GraphicsBackend {
    fn clone(&self) -> Self {
        // The callback closure cannot be cloned, so it is set to None in the clone.
        // This is fine because the callback is typically set once on the primary instance.
        GraphicsBackend {
            next_id: self.next_id,
            adapter: self.adapter.clone(),
            capabilities: self.capabilities.clone(),
            outputs: self.outputs.clone(),
            swapchains: self.swapchains.clone(),
            resources: self.resources.clone(),
            descriptor_heaps: self.descriptor_heaps.clone(),
            command_lists: self.command_lists.clone(),
            fences: self.fences.clone(),
            query_heaps: self.query_heaps.clone(),
            root_signatures: self.root_signatures.clone(),
            pipeline_states: self.pipeline_states.clone(),
            timestamps: self.timestamps,
            subresource_states: self.subresource_states.clone(),
            pending_split_barriers: self.pending_split_barriers.clone(),
            frame_published_callback: None,
            frame_source: self.frame_source,
        }
    }
}

impl Default for GraphicsBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Mutable state accumulated while executing a command stream.
struct ExecutionPlanState {
    active_pass: Option<RenderPassPlan>,
    render_passes: Vec<RenderPassPlan>,
    compute_passes: u32,
    blit_passes: u32,
    raytrace_passes: u32,
    validation_errors: Vec<String>,
    root_constants_log: Vec<Vec<u32>>,
}

impl GraphicsBackend {
    pub fn new() -> Self {
        Self::with_host_profile(detected_host_gpu_profile())
    }

    pub(crate) fn with_host_profile(profile: HostGpuProfile) -> Self {
        Self {
            next_id: 1,
            adapter: profile.adapter,
            frame_published_callback: None,
            frame_source: FrameSource::DxgiD3D11,
            capabilities: profile.capabilities,
            outputs: vec![
                OutputInfo {
                    id: 1,
                    name: "Built-in Display".to_string(),
                    dpi_x: 144,
                    dpi_y: 144,
                    modes: vec![
                        DisplayMode {
                            width: 2560,
                            height: 1600,
                            refresh_numerator: 60000,
                            refresh_denominator: 1000,
                        },
                        DisplayMode {
                            width: 1920,
                            height: 1200,
                            refresh_numerator: 60000,
                            refresh_denominator: 1000,
                        },
                    ],
                },
                OutputInfo {
                    id: 2,
                    name: "External Display".to_string(),
                    dpi_x: 110,
                    dpi_y: 110,
                    modes: vec![
                        DisplayMode {
                            width: 3840,
                            height: 2160,
                            refresh_numerator: 120000,
                            refresh_denominator: 1000,
                        },
                        DisplayMode {
                            width: 2560,
                            height: 1440,
                            refresh_numerator: 60000,
                            refresh_denominator: 1000,
                        },
                    ],
                },
            ],
            swapchains: BTreeMap::new(),
            resources: BTreeMap::new(),
            descriptor_heaps: BTreeMap::new(),
            command_lists: BTreeMap::new(),
            fences: BTreeMap::new(),
            query_heaps: BTreeMap::new(),
            root_signatures: BTreeMap::new(),
            pipeline_states: BTreeMap::new(),
            timestamps: 1,
            subresource_states: BTreeMap::new(),
            pending_split_barriers: Vec::new(),
        }
    }

    pub fn adapter(&self) -> &AdapterInfo {
        &self.adapter
    }

    pub fn capabilities(&self) -> &MetalCapabilities {
        &self.capabilities
    }

    pub fn outputs(&self) -> &[OutputInfo] {
        &self.outputs
    }

    pub fn query_feature(&self, query: FeatureQuery) -> bool {
        match query {
            FeatureQuery::Tearing => true,
            FeatureQuery::TimestampQueries => self.capabilities.timestamp_queries,
            FeatureQuery::MeshShaders => self.capabilities.mesh_shaders,
            FeatureQuery::Raytracing => self.capabilities.raytracing,
        }
    }

    pub fn query_format_support(&self, format: DxgiFormat) -> AppResult<FormatMapping> {
        format_mapping(format)
    }

    pub fn create_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        if desc.buffer_count < 2 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "swapchain buffer count must be at least 2",
            ));
        }
        let id = self.alloc_id();
        let max_frame_latency = if self.capabilities.unified_memory {
            1
        } else {
            3
        };
        let backbuffers = (0..desc.buffer_count)
            .map(|index| {
                self.create_resource(ResourceDesc {
                    name: format!("swapchain-{id}-buffer-{index}"),
                    format: desc.format,
                    heap: HeapType::Default,
                    size: (desc.width as usize) * (desc.height as usize) * 4,
                    subresources: 1,
                    initial_state: ResourceState::Present,
                    usage_hint: ResourceUsageHint::SwapchainBackbuffer,
                })
            })
            .collect::<AppResult<Vec<_>>>()?;
        self.swapchains.insert(
            id,
            SwapchainRecord {
                state: SwapchainState {
                    id,
                    desc,
                    backbuffers,
                    queued_frames: 0,
                    max_frame_latency,
                },
                next_present_index: 0,
                presented_backbuffer_index: 0,
                last_present_at: None,
            },
        );
        Ok(id)
    }

    pub fn set_maximum_frame_latency(
        &mut self,
        swapchain: SwapchainId,
        latency: u32,
    ) -> AppResult<()> {
        let record = self.swapchain_mut(swapchain)?;
        record.state.max_frame_latency = latency.max(1);
        Ok(())
    }

    pub fn swapchain_state(&self, swapchain: SwapchainId) -> AppResult<SwapchainState> {
        Ok(self.swapchain(swapchain)?.state.clone())
    }

    pub fn present(
        &mut self,
        swapchain: SwapchainId,
        sync_interval: u32,
        allow_tearing: bool,
    ) -> AppResult<PresentResult> {
        if sync_interval > 4 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported sync interval {sync_interval}"),
            ));
        }
        let tearing_allowed =
            allow_tearing && sync_interval == 0 && self.query_feature(FeatureQuery::Tearing);

        // Measure real frame timing: `frame_time_us` is the elapsed wall-clock
        // time since the previous present on this swapchain (0 on the first).
        let present_started_at = std::time::Instant::now();
        let frame_time_us = {
            let record = self.swapchain_mut(swapchain)?;
            let elapsed = record.last_present_at.map(|previous| {
                present_started_at
                    .duration_since(previous)
                    .as_micros()
                    .min(u64::MAX as u128) as u64
            });
            record.last_present_at = Some(present_started_at);
            elapsed.unwrap_or(0)
        };

        // Update swapchain state in a block scope so the mutable borrow ends
        // before we access self for the callback and result construction.
        let displayed_frame_index = {
            let record = self.swapchain_mut(swapchain)?;
            record.next_present_index += 1;
            // presented_frame() reports the backbuffer the guest most recently
            // rendered into. The d3d11 side mirrors every backbuffer before
            // present and the swapchain contract is keyed on backbuffer 0;
            // keep the reported index stable at 0 (single-buffer semantics).
            record.presented_backbuffer_index = 0;
            record.state.queued_frames =
                (record.state.queued_frames + 1).min(record.state.max_frame_latency);
            record.next_present_index
        };

        // Extract the presented frame before accessing the callback to avoid
        // NLL borrow conflicts between the immutable self.presented_frame() and
        // the mutable self.frame_published_callback borrow.
        let presented_frame = match self.presented_frame(swapchain) {
            Ok(frame) => Some(frame),
            Err(error) => {
                eprintln!(
                    "[gfx] present: failed to obtain presented frame for swapchain {}: {}",
                    swapchain, error
                );
                None
            }
        };
        if let (Some(ref mut cb), Some(presented)) =
            (self.frame_published_callback.as_mut(), presented_frame)
        {
            cb(presented);
        }

        // Read final queued_frames count after any callback side-effects
        let queued_frames = {
            let record = self.swapchain(swapchain)?;
            record.state.queued_frames
        };

        Ok(PresentResult {
            queued_frames,
            effective_sync_interval: sync_interval,
            tearing_allowed,
            displayed_frame_index,
            frame_time_us,
        })
    }

    pub fn export_presented_frame_ppm(&self, swapchain: SwapchainId, path: &Path) -> AppResult<()> {
        let bytes = self.presented_frame_ppm_bytes(swapchain)?;
        fs::write(path, bytes).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to write presented frame {}", path.display()),
                &error,
            )
        })
    }

    pub fn presented_frame(&self, swapchain: SwapchainId) -> AppResult<PresentedFrame> {
        let record = self.swapchain(swapchain)?;
        if record.state.backbuffers.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "swapchain has no backbuffers to export",
            ));
        }
        let index = record
            .presented_backbuffer_index
            .min(record.state.backbuffers.len().saturating_sub(1));
        let resource = self.resource(record.state.backbuffers[index])?;
        Ok(PresentedFrame {
            width: record.state.desc.width,
            height: record.state.desc.height,
            format: record.state.desc.format,
            bytes: resource.bytes.clone(),
            source: self.frame_source,
            stride: resource
                .bytes
                .len()
                .checked_div(record.state.desc.height.max(1) as usize)
                .unwrap_or(0),
            sequence: record.next_present_index,
            timestamp: std::time::Instant::now(),
        })
    }

    pub fn open_presented_frame(&self, swapchain: SwapchainId) -> AppResult<()> {
        let temp_path = std::env::temp_dir().join(format!(
            "casa1-frame-{}-{}.ppm",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        ));
        self.export_presented_frame_ppm(swapchain, &temp_path)?;
        let status = HostCommand::new("open")
            .arg(&temp_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    "failed to launch open for presented frame",
                    &error,
                )
            })?;
        if !status.success() {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("open failed while previewing presented frame: {status}"),
            ));
        }
        Ok(())
    }

    pub fn resize_buffers(
        &mut self,
        swapchain: SwapchainId,
        buffer_count: u32,
        width: u32,
        height: u32,
        format: DxgiFormat,
    ) -> AppResult<()> {
        if buffer_count < 2 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "swapchain buffer count must be at least 2",
            ));
        }
        // Allocate the new backbuffers first so a failure leaves the
        // existing swapchain state (and its backbuffers) intact.
        let backbuffers = (0..buffer_count)
            .map(|index| {
                self.create_resource(ResourceDesc {
                    name: format!("swapchain-{swapchain}-buffer-resized-{index}"),
                    format,
                    heap: HeapType::Default,
                    size: (width as usize) * (height as usize) * 4,
                    subresources: 1,
                    initial_state: ResourceState::Present,
                    usage_hint: ResourceUsageHint::SwapchainBackbuffer,
                })
            })
            .collect::<AppResult<Vec<_>>>()?;
        let old_backbuffers = self.swapchain(swapchain)?.state.backbuffers.clone();
        for resource in old_backbuffers {
            let _ = self.destroy_resource(resource);
        }
        let record = self.swapchain_mut(swapchain)?;
        record.state.desc = SwapchainDesc {
            width,
            height,
            format,
            buffer_count,
        };
        record.state.backbuffers = backbuffers;
        record.state.queued_frames = 0;
        record.presented_backbuffer_index = 0;
        Ok(())
    }

    /// Register a callback that fires on every `present()` with the presented frame.
    /// The callback receives the current backbuffer bytes, dimensions, and format.
    /// Set to `None` to unregister.
    pub fn set_frame_published_callback(
        &mut self,
        callback: Option<Box<dyn FnMut(PresentedFrame) + Send>>,
    ) {
        self.frame_published_callback = callback;
    }

    /// Declare which API presents through this backend.  Every
    /// [`PresentedFrame`] produced afterwards is labelled with this source.
    pub fn set_frame_source(&mut self, source: FrameSource) {
        self.frame_source = source;
    }

    /// The source currently assigned to this backend's presented frames.
    pub fn frame_source(&self) -> FrameSource {
        self.frame_source
    }

    pub fn create_resource(&mut self, desc: ResourceDesc) -> AppResult<ResourceId> {
        let id = self.alloc_id();
        let storage_mode = self.storage_mode_for_resource(&desc);
        self.resources.insert(
            id,
            ResourceRecord {
                states: vec![desc.initial_state; desc.subresources as usize],
                bytes: vec![0; desc.size],
                storage_mode,
                desc,
            },
        );
        Ok(id)
    }

    pub fn destroy_resource(&mut self, resource: ResourceId) -> AppResult<()> {
        self.resources
            .remove(&resource)
            .map(|_| ())
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown resource"))
    }

    /// Destroy a swapchain and its backbuffer resources.
    pub fn destroy_swapchain(&mut self, swapchain: SwapchainId) -> AppResult<()> {
        let record = self
            .swapchains
            .remove(&swapchain)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("unknown swapchain {swapchain}"),
                )
            })?;
        for backbuffer in record.state.backbuffers {
            let _ = self.destroy_resource(backbuffer);
        }
        Ok(())
    }

    /// Destroy a descriptor heap.
    pub fn destroy_descriptor_heap(&mut self, heap: DescriptorHeapId) -> AppResult<()> {
        self.descriptor_heaps
            .remove(&heap)
            .map(|_| ())
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown descriptor heap"))
    }

    /// Destroy a command list (drops its recorded commands).
    pub fn destroy_command_list(&mut self, list: CommandListId) -> AppResult<()> {
        self.command_lists
            .remove(&list)
            .map(|_| ())
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown command list"))
    }

    /// Destroy a fence.
    pub fn destroy_fence(&mut self, fence: FenceId) -> AppResult<()> {
        self.fences
            .remove(&fence)
            .map(|_| ())
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown fence"))
    }

    /// Destroy a query heap.
    pub fn destroy_query_heap(&mut self, heap: QueryHeapId) -> AppResult<()> {
        self.query_heaps
            .remove(&heap)
            .map(|_| ())
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown query heap"))
    }

    /// Destroy a root signature.
    pub fn destroy_root_signature(&mut self, root_signature: RootSignatureId) -> AppResult<()> {
        self.root_signatures
            .remove(&root_signature)
            .map(|_| ())
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown root signature"))
    }

    /// Destroy a pipeline state object.
    pub fn destroy_pipeline_state(&mut self, pipeline_state: PipelineStateId) -> AppResult<()> {
        self.pipeline_states
            .remove(&pipeline_state)
            .map(|_| ())
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown pipeline state"))
    }

    pub fn live_resource_count(&self) -> usize {
        self.resources.len()
    }

    pub fn resource_state(
        &self,
        resource: ResourceId,
        subresource: u32,
    ) -> AppResult<ResourceState> {
        let resource = self.resource(resource)?;
        resource
            .states
            .get(subresource as usize)
            .copied()
            .ok_or_else(|| {
                AppError::new(ReasonCode::RcD3dInvalidState, "invalid subresource index")
            })
    }

    pub fn transition_resource(
        &mut self,
        resource_id: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        let resource = self.resource_mut(resource_id)?;
        let state = resource
            .states
            .get_mut(subresource as usize)
            .ok_or_else(|| {
                AppError::new(ReasonCode::RcD3dInvalidState, "invalid subresource index")
            })?;
        // Only validate state mismatch when the from state is not Common
        // (Common acts as "unknown/any" in D3D12 barrier validation)
        if from != ResourceState::Common && *state != from {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("resource state mismatch: expected {from:?}, found {state:?}"),
            ));
        }
        *state = to;
        // Also track in subresource_states under the flat subresource index.
        self.subresource_states
            .insert((resource_id, 0, subresource), to);
        Ok(())
    }

    pub fn create_descriptor_heap(
        &mut self,
        ty: DescriptorHeapType,
        count: usize,
    ) -> DescriptorHeapId {
        let id = self.alloc_id();
        self.descriptor_heaps.insert(
            id,
            DescriptorHeapRecord {
                ty,
                descriptors: vec![None; count],
            },
        );
        id
    }

    pub fn write_descriptor(
        &mut self,
        heap: DescriptorHeapId,
        index: usize,
        descriptor: ViewDescriptor,
    ) -> AppResult<()> {
        self.validate_descriptor(&descriptor)?;
        let heap_record = self.descriptor_heap_mut(heap)?;
        let slot = heap_record.descriptors.get_mut(index).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "descriptor index out of range",
            )
        })?;
        *slot = Some(descriptor);
        Ok(())
    }

    pub fn copy_descriptors(
        &mut self,
        src_heap: DescriptorHeapId,
        src_index: usize,
        dst_heap: DescriptorHeapId,
        dst_index: usize,
        count: usize,
    ) -> AppResult<()> {
        let source = self
            .descriptor_heap(src_heap)?
            .descriptors
            .get(src_index..src_index + count)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "source descriptor range out of bounds",
                )
            })?
            .to_vec();
        let destination = self.descriptor_heap_mut(dst_heap)?;
        let slice = destination
            .descriptors
            .get_mut(dst_index..dst_index + count)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "destination descriptor range out of bounds",
                )
            })?;
        slice.clone_from_slice(&source);
        Ok(())
    }

    pub fn copy_descriptors_simple(
        &mut self,
        src_heap: DescriptorHeapId,
        src_index: usize,
        dst_heap: DescriptorHeapId,
        dst_index: usize,
        count: usize,
    ) -> AppResult<()> {
        self.copy_descriptors(src_heap, src_index, dst_heap, dst_index, count)
    }

    pub fn descriptor_heap_snapshot(
        &self,
        heap: DescriptorHeapId,
    ) -> AppResult<Vec<Option<ViewDescriptor>>> {
        Ok(self.descriptor_heap(heap)?.descriptors.clone())
    }

    pub fn descriptor_heap_type(&self, heap: DescriptorHeapId) -> AppResult<DescriptorHeapType> {
        Ok(self.descriptor_heap(heap)?.ty)
    }

    pub fn translate_descriptor_heap(
        &self,
        heap: DescriptorHeapId,
    ) -> AppResult<Vec<MetalBinding>> {
        let heap_record = self.descriptor_heap(heap)?;
        Ok(heap_record
            .descriptors
            .iter()
            .enumerate()
            .filter_map(|(slot, descriptor)| {
                descriptor
                    .as_ref()
                    .map(|descriptor| metal_binding(slot as u32, descriptor))
            })
            .collect())
    }

    pub fn create_root_signature(&mut self, desc: RootSignatureDesc) -> RootSignatureId {
        let id = self.alloc_id();
        self.root_signatures.insert(id, desc);
        id
    }

    pub fn create_pipeline_state(
        &mut self,
        _root_signature: RootSignatureId,
        desc: PipelineStateDesc,
    ) -> PipelineStateId {
        let id = self.alloc_id();
        self.pipeline_states.insert(id, desc);
        id
    }

    pub fn create_command_queue(&mut self) -> CommandQueueId {
        self.alloc_id()
    }

    pub fn create_command_allocator(&mut self) -> CommandAllocatorId {
        self.alloc_id()
    }

    pub fn create_graphics_command_list(
        &mut self,
        _allocator: CommandAllocatorId,
        pipeline_state: PipelineStateId,
        is_bundle: bool,
    ) -> CommandListId {
        let id = self.alloc_id();
        self.command_lists.insert(
            id,
            CommandListRecord {
                pipeline_state,
                commands: Vec::new(),
                closed: false,
                is_bundle,
            },
        );
        id
    }

    pub fn record_transition(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        // Validate the command list (and that it is open) before mutating
        // resource state, so a failed record leaves the state unchanged.
        self.command_list_mut(list)?;
        self.transition_resource(resource, subresource, from, to)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::Transition {
                resource,
                subresource,
                from,
                to,
            });
        Ok(())
    }

    pub fn record_uav_barrier(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
    ) -> AppResult<()> {
        self.resource(resource)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::UavBarrier { resource });
        Ok(())
    }

    pub fn record_aliasing_barrier(
        &mut self,
        list: CommandListId,
        before: Option<ResourceId>,
        after: Option<ResourceId>,
    ) -> AppResult<()> {
        if let Some(before) = before {
            self.resource(before)?;
        }
        if let Some(after) = after {
            self.resource(after)?;
        }
        self.command_list_mut(list)?
            .commands
            .push(Command::AliasingBarrier { before, after });
        Ok(())
    }

    /// Record a split barrier begin (BEGIN_ONLY).
    /// Stores the pending transition; does NOT immediately change resource state.
    pub fn record_split_barrier_begin(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        self.resource(resource)?;
        // Validate the command list before recording the pending barrier.
        self.command_list_mut(list)?;
        self.pending_split_barriers.push(PendingSplitBarrier {
            resource,
            subresource,
            state_before: from,
            state_after: to,
        });
        self.command_list_mut(list)?
            .commands
            .push(Command::SplitBarrierBegin {
                resource,
                subresource,
                from,
                to,
            });
        Ok(())
    }

    /// Record a split barrier end (END_ONLY).
    /// Completes a previously begun split barrier and transitions the resource.
    pub fn record_split_barrier_end(
        &mut self,
        list: CommandListId,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> AppResult<()> {
        self.resource(resource)?;
        // Validate the command list before mutating state.
        self.command_list_mut(list)?;
        // Find and remove matching pending split barrier; an END_ONLY without
        // a matching BEGIN is a malformed barrier sequence and must not
        // mutate resource state (D3D12 debug validation rejects it).
        let pos = self.pending_split_barriers.iter().position(|pending| {
            pending.resource == resource
                && pending.subresource == subresource
                && pending.state_before == from
                && pending.state_after == to
        });
        let index = pos.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "split barrier END without matching BEGIN for resource {resource} subresource {subresource}"
                ),
            )
        })?;
        self.pending_split_barriers.remove(index);
        // Apply the actual state transition on end
        self.transition_resource_internal(resource, subresource, to)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::SplitBarrierEnd {
                resource,
                subresource,
                from,
                to,
            });
        Ok(())
    }

    /// Dispatch a full D3D12_RESOURCE_BARRIER (handles all 3 barrier types).
    pub fn record_resource_barrier(
        &mut self,
        list: CommandListId,
        desc: &D3D12ResourceBarrierDesc,
    ) -> AppResult<()> {
        match desc.barrier_type {
            D3D12ResourceBarrierType::Transition => {
                let resource = desc.resource.ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "transition barrier missing resource",
                    )
                })?;
                match desc.flags {
                    D3D12ResourceBarrierFlags::BeginOnly => {
                        self.record_split_barrier_begin(
                            list,
                            resource,
                            desc.subresource,
                            desc.state_before,
                            desc.state_after,
                        )?;
                    }
                    D3D12ResourceBarrierFlags::EndOnly => {
                        self.record_split_barrier_end(
                            list,
                            resource,
                            desc.subresource,
                            desc.state_before,
                            desc.state_after,
                        )?;
                    }
                    D3D12ResourceBarrierFlags::None => {
                        self.record_transition(
                            list,
                            resource,
                            desc.subresource,
                            desc.state_before,
                            desc.state_after,
                        )?;
                    }
                }
            }
            D3D12ResourceBarrierType::Uav => {
                let resource = desc.resource.ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "UAV barrier missing resource",
                    )
                })?;
                self.record_uav_barrier(list, resource)?;
            }
            D3D12ResourceBarrierType::Aliasing => {
                self.record_aliasing_barrier(list, desc.resource_before, desc.resource_after)?;
            }
        }
        Ok(())
    }

    /// Internal: set subresource state without checking previous state (for split barriers).
    fn transition_resource_internal(
        &mut self,
        resource: ResourceId,
        subresource: u32,
        to: ResourceState,
    ) -> AppResult<()> {
        let resource_record = self.resource_mut(resource)?;
        let state = resource_record
            .states
            .get_mut(subresource as usize)
            .ok_or_else(|| {
                AppError::new(ReasonCode::RcD3dInvalidState, "invalid subresource index")
            })?;
        *state = to;
        // Also track in subresource_states for flat subresource index tracking
        let key = (resource, 0, subresource);
        self.subresource_states.insert(key, to);
        Ok(())
    }

    /// Get subresource state from the fine-grained tracking map. `subresource`
    /// is the flat D3D12 subresource index (mip + array_slice * mip_levels).
    pub fn subresource_state(
        &self,
        resource: ResourceId,
        subresource: u32,
    ) -> Option<ResourceState> {
        self.subresource_states
            .get(&(resource, 0, subresource))
            .copied()
    }

    /// Set subresource state in the fine-grained tracking map. `subresource`
    /// is the flat D3D12 subresource index (mip + array_slice * mip_levels).
    pub fn set_subresource_state(
        &mut self,
        resource: ResourceId,
        subresource: u32,
        state: ResourceState,
    ) {
        self.subresource_states
            .insert((resource, 0, subresource), state);
    }

    /// Return the number of pending split barriers.
    pub fn pending_split_barrier_count(&self) -> usize {
        self.pending_split_barriers.len()
    }

    /// Clear all pending split barriers (e.g., on command list reset).
    pub fn clear_pending_split_barriers(&mut self) {
        self.pending_split_barriers.clear();
    }

    pub fn record_set_root_constants(
        &mut self,
        list: CommandListId,
        values: Vec<u32>,
    ) -> AppResult<()> {
        self.command_list_mut(list)?
            .commands
            .push(Command::SetRootConstants { values });
        Ok(())
    }

    pub fn record_begin_render_pass(
        &mut self,
        list: CommandListId,
        color_formats: Vec<DxgiFormat>,
        depth_format: Option<DxgiFormat>,
        load_action: &str,
        store_action: &str,
    ) -> AppResult<()> {
        self.command_list_mut(list)?
            .commands
            .push(Command::BeginRenderPass {
                color_formats,
                depth_format,
                load_action: load_action.to_string(),
                store_action: store_action.to_string(),
            });
        Ok(())
    }

    pub fn record_clear_rtv(
        &mut self,
        list: CommandListId,
        heap: DescriptorHeapId,
        index: usize,
    ) -> AppResult<()> {
        self.validate_rtv_descriptor(heap, index)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::ClearRtv { heap, index });
        Ok(())
    }

    pub fn record_clear_dsv(
        &mut self,
        list: CommandListId,
        heap: DescriptorHeapId,
        index: usize,
    ) -> AppResult<()> {
        self.validate_dsv_descriptor(heap, index)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::ClearDsv { heap, index });
        Ok(())
    }

    pub fn record_draw(&mut self, list: CommandListId, vertices: u32) -> AppResult<()> {
        self.command_list_mut(list)?
            .commands
            .push(Command::Draw { vertices });
        Ok(())
    }

    pub fn record_draw_instanced(
        &mut self,
        list: CommandListId,
        vertices: u32,
        instances: u32,
    ) -> AppResult<()> {
        self.command_list_mut(list)?
            .commands
            .push(Command::DrawInstanced {
                vertices,
                instances,
            });
        Ok(())
    }

    pub fn record_dispatch(
        &mut self,
        list: CommandListId,
        x: u32,
        y: u32,
        z: u32,
    ) -> AppResult<()> {
        self.command_list_mut(list)?
            .commands
            .push(Command::Dispatch { x, y, z });
        Ok(())
    }

    /// Record a mesh shader dispatch command.
    ///
    /// This issues a `DispatchMesh` command which, when executed, will use
    /// a mesh shader pipeline instead of a compute pipeline. On Metal with
    /// Apple9+/M3+ GPUs this maps to `draw_mesh_threadgroups`. On older
    /// hardware it falls back to compute-based emulation.
    pub fn record_dispatch_mesh(
        &mut self,
        list: CommandListId,
        x: u32,
        y: u32,
        z: u32,
    ) -> AppResult<()> {
        self.command_list_mut(list)?
            .commands
            .push(Command::DispatchMesh { x, y, z });
        Ok(())
    }

    /// Record a raytracing dispatch command (DispatchRays).
    ///
    /// Stores the shader table GPU virtual addresses and dispatch dimensions.
    /// The actual Metal ray traversal encoding is performed when the command
    /// list is executed on the Metal backend.
    #[allow(clippy::too_many_arguments)]
    pub fn record_dispatch_rays(
        &mut self,
        list: CommandListId,
        raygen_address: u64,
        miss_address: u64,
        hit_address: u64,
        callable_address: u64,
        width: u32,
        height: u32,
        depth: u32,
    ) -> AppResult<()> {
        self.command_list_mut(list)?
            .commands
            .push(Command::DispatchRays {
                raygen_address,
                miss_address,
                hit_address,
                callable_address,
                width,
                height,
                depth,
            });
        Ok(())
    }

    pub fn record_copy_resource(
        &mut self,
        list: CommandListId,
        src: ResourceId,
        dst: ResourceId,
    ) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::CopyResource { src, dst });
        Ok(())
    }

    pub fn record_copy_buffer_region(
        &mut self,
        list: CommandListId,
        dst: ResourceId,
        dst_offset: u64,
        src: ResourceId,
        src_offset: u64,
        size: u64,
    ) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::CopyBufferRegion {
                dst,
                dst_offset,
                src,
                src_offset,
                size,
            });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_copy_resource_region(
        &mut self,
        list: CommandListId,
        dst: ResourceId,
        dst_x: u32,
        dst_y: u32,
        dst_z: u32,
        src: ResourceId,
        src_x: u32,
        src_y: u32,
        src_z: u32,
        width: u32,
        height: u32,
        depth: u32,
    ) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::CopyResourceRegion {
                dst,
                dst_x,
                dst_y,
                dst_z,
                src,
                src_x,
                src_y,
                src_z,
                width,
                height,
                depth,
            });
        Ok(())
    }

    pub fn record_resolve_subresource(
        &mut self,
        list: CommandListId,
        dst: ResourceId,
        src: ResourceId,
        // Raw DXGI_FORMAT u32 value.
        format: u32,
        resolve_mode: u32,
    ) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.command_list_mut(list)?
            .commands
            .push(Command::ResolveSubresource {
                dst,
                src,
                format,
                resolve_mode,
            });
        Ok(())
    }

    /// Record an `ExecuteBundle` command on `list`. The bundle's commands are
    /// snapshotted immediately (deep-cloned from the bundle's current
    /// `CommandListRecord`) so that the bundle can be Reset and re-recorded
    /// without affecting already-enqueued executions.
    pub fn record_execute_bundle(
        &mut self,
        list: CommandListId,
        bundle: CommandListId,
    ) -> AppResult<()> {
        // Bundle must exist and be closed
        let bundle_record = self.command_list(bundle)?;
        if !bundle_record.closed {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("bundle command list {bundle} must be closed before ExecuteBundle"),
            ));
        }
        let bundle_commands = bundle_record.commands.clone();
        self.command_list_mut(list)?
            .commands
            .push(Command::ExecuteBundle { bundle_commands });
        Ok(())
    }

    pub fn close_command_list(&mut self, list: CommandListId) -> AppResult<ImmutableCommandStream> {
        let record = self.command_list_mut(list)?;
        if record.closed {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("command list {list} is already closed"),
            ));
        }
        record.closed = true;
        Ok(ImmutableCommandStream {
            id: list,
            commands: record.commands.clone(),
        })
    }

    /// Mutable state accumulated while executing a command stream.
    ///
    /// Process a single [`Command`] during [`execute_command_lists`], driving the
    /// render-pass / compute-pass / blit-pass planning state machine.
    ///
    /// This is extracted as a separate method so that [`Command::ExecuteBundle`]
    /// can recursively re-dispatch each of the bundle's commands through the same
    /// processing logic without duplicating the match arms.
    fn process_execution_command(
        &mut self,
        command: &Command,
        pipeline: &PipelineStateDesc,
        plan: &mut ExecutionPlanState,
    ) -> AppResult<()> {
        match command {
            Command::Transition { .. }
            | Command::SplitBarrierBegin { .. }
            | Command::SplitBarrierEnd { .. }
            | Command::UavBarrier { .. }
            | Command::AliasingBarrier { .. } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
            }
            Command::SetRootConstants { values } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.root_constants_log.push(values.clone());
            }
            Command::BeginRenderPass {
                color_formats,
                depth_format,
                load_action,
                store_action,
            } => {
                let mapped_color_formats = color_formats
                    .iter()
                    .map(|format| format_mapping(*format).map(|mapping| mapping.metal))
                    .collect::<AppResult<Vec<_>>>()?;
                let mapped_depth_format = depth_format
                    .map(|format| format_mapping(format).map(|mapping| mapping.metal))
                    .transpose()?;
                match &mut plan.active_pass {
                    Some(pass)
                        if self.capabilities.mesh_shaders
                            && pass.can_merge_with(
                                &mapped_color_formats,
                                mapped_depth_format,
                                load_action,
                            ) =>
                    {
                        pass.merge_store_action(store_action);
                    }
                    Some(_) => {
                        plan.render_passes.push(plan.active_pass.take().expect("active pass"));
                        plan.active_pass = Some(RenderPassPlan {
                            color_formats: mapped_color_formats,
                            depth_format: mapped_depth_format,
                            draw_calls: 0,
                            load_action: load_action.clone(),
                            store_action: store_action.clone(),
                        });
                    }
                    None => {
                        plan.active_pass = Some(RenderPassPlan {
                            color_formats: mapped_color_formats,
                            depth_format: mapped_depth_format,
                            draw_calls: 0,
                            load_action: load_action.clone(),
                            store_action: store_action.clone(),
                        });
                    }
                }
            }
            Command::ClearRtv { heap, index } => {
                let descriptor = self.descriptor_at(*heap, *index)?;
                let ViewDescriptor::Rtv { format, .. } = descriptor else {
                    plan.validation_errors.push("invalid RTV attachment".to_string());
                    return Ok(());
                };
                let mapping = format_mapping(format)?;
                let depth_format = pipeline
                    .depth_format
                    .map(format_mapping)
                    .transpose()?
                    .map(|mapping| mapping.metal);
                match &mut plan.active_pass {
                    Some(pass) => {
                        if pass.color_formats != vec![mapping.metal]
                            || pass.depth_format != depth_format
                        {
                            plan.render_passes.push(plan.active_pass.take().expect("active pass"));
                            plan.active_pass = Some(RenderPassPlan {
                                color_formats: vec![mapping.metal],
                                depth_format,
                                draw_calls: 0,
                                load_action: "clear".to_string(),
                                store_action: "store".to_string(),
                            });
                        } else {
                            pass.load_action = "clear".to_string();
                        }
                    }
                    None => {
                        plan.active_pass = Some(RenderPassPlan {
                            color_formats: vec![mapping.metal],
                            depth_format,
                            draw_calls: 0,
                            load_action: "clear".to_string(),
                            store_action: "store".to_string(),
                        });
                    }
                }
            }
            Command::ClearDsv { heap, index } => {
                let descriptor = self.descriptor_at(*heap, *index)?;
                let ViewDescriptor::Dsv { format, .. } = descriptor else {
                    plan.validation_errors.push("invalid DSV attachment".to_string());
                    return Ok(());
                };
                let mapping = format_mapping(format)?;
                let color_format = pipeline
                    .render_target_formats
                    .first()
                    .map(|format| format_mapping(*format))
                    .transpose()?
                    .map(|mapping| mapping.metal);
                let color_formats = color_format.map(|f| vec![f]).unwrap_or_default();
                match &mut plan.active_pass {
                    Some(pass)
                        if pass.depth_format == Some(mapping.metal)
                            && pass.color_formats == color_formats =>
                    {
                        pass.load_action = "clear".to_string();
                    }
                    Some(_) => {
                        plan.render_passes.push(plan.active_pass.take().expect("active pass"));
                        plan.active_pass = Some(RenderPassPlan {
                            color_formats,
                            depth_format: Some(mapping.metal),
                            draw_calls: 0,
                            load_action: "clear".to_string(),
                            store_action: "store".to_string(),
                        });
                    }
                    None => {
                        plan.active_pass = Some(RenderPassPlan {
                            color_formats,
                            depth_format: Some(mapping.metal),
                            draw_calls: 0,
                            load_action: "clear".to_string(),
                            store_action: "store".to_string(),
                        });
                    }
                }
            }
            Command::Draw { .. } | Command::DrawInstanced { .. } => {
                if let Some(pass) = &mut plan.active_pass {
                    pass.draw_calls += 1;
                } else {
                    plan.validation_errors.push("draw without active render pass".to_string());
                }
            }
            Command::Dispatch { .. } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.compute_passes += 1;
            }
            Command::DispatchMesh { .. } => {
                // Mesh shader dispatches require an active render pass
                // (they generate geometry for rasterization).
                if let Some(pass) = &mut plan.active_pass {
                    pass.draw_calls += 1;
                } else {
                    plan.validation_errors.push("dispatch mesh without active render pass".to_string());
                }
            }
            Command::CopyResource { src, dst } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.blit_passes += 1;
                self.copy_resource_bytes(*src, *dst)?;
            }
            Command::CopyBufferRegion {
                dst,
                dst_offset,
                src,
                src_offset,
                size,
            } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.blit_passes += 1;
                let src_bytes = self.resource(*src)?.bytes.clone();
                let dst_bytes = self.resource_mut(*dst)?;
                let src_start = usize::try_from(*src_offset).map_err(|_| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy source offset out of range")
                })?;
                let dst_start = usize::try_from(*dst_offset).map_err(|_| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy dest offset out of range")
                })?;
                let len = usize::try_from(*size).map_err(|_| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy size out of range")
                })?;
                let src_end = src_start.checked_add(len).ok_or_else(|| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy source range overflow")
                })?;
                let dst_end = dst_start.checked_add(len).ok_or_else(|| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy dest range overflow")
                })?;
                if src_end > src_bytes.len() || dst_end > dst_bytes.bytes.len() {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "copy buffer region out of bounds",
                    ));
                }
                dst_bytes.bytes[dst_start..dst_end]
                    .copy_from_slice(&src_bytes[src_start..src_end]);
            }
            Command::CopyResourceRegion {
                dst,
                dst_x,
                dst_y,
                dst_z: _,
                src,
                src_x,
                src_y,
                src_z: _,
                width,
                height,
                depth: _,
            } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.blit_passes += 1;
                // For buffer-to-buffer copies this treats the region as a
                // row-oriented byte copy: each row is `width` pixels of 4
                // bytes. The source row is selected by `src_y` and the
                // destination row by `dst_y`, honoring the x offsets in
                // both. All arithmetic is checked so guest-controlled
                // coordinates cannot panic or wrap.
                let src_bytes = self.resource(*src)?.bytes.clone();
                let dst_bytes = self.resource_mut(*dst)?;
                let bpp = 4usize;
                let row_count = *height as usize;
                let src_stride = (*width as usize)
                    .checked_mul(bpp)
                    .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "copy width overflow"))?;
                let dst_stride = (*width as usize)
                    .checked_mul(bpp)
                    .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "copy width overflow"))?;
                let src_x_off = (*src_x as usize)
                    .checked_mul(bpp)
                    .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "copy src_x overflow"))?;
                let dst_x_off = (*dst_x as usize)
                    .checked_mul(bpp)
                    .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "copy dst_x overflow"))?;
                let src_row_base = (*src_y as usize)
                    .checked_mul(src_stride)
                    .and_then(|v| v.checked_add(src_x_off))
                    .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "copy source offset overflow"))?;
                let dst_row_base = (*dst_y as usize)
                    .checked_mul(dst_stride)
                    .and_then(|v| v.checked_add(dst_x_off))
                    .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "copy dest offset overflow"))?;
                for row in 0..row_count {
                    let src_row_start = src_row_base
                        .checked_add(row.checked_mul(src_stride).ok_or_else(|| {
                            AppError::new(ReasonCode::RcD3dInvalidState, "copy row offset overflow")
                        })?)
                        .ok_or_else(|| {
                            AppError::new(ReasonCode::RcD3dInvalidState, "copy row offset overflow")
                        })?;
                    let dst_row_start = dst_row_base
                        .checked_add(row.checked_mul(dst_stride).ok_or_else(|| {
                            AppError::new(ReasonCode::RcD3dInvalidState, "copy row offset overflow")
                        })?)
                        .ok_or_else(|| {
                            AppError::new(ReasonCode::RcD3dInvalidState, "copy row offset overflow")
                        })?;
                    let src_row_end = src_row_start.checked_add(src_stride).ok_or_else(|| {
                        AppError::new(ReasonCode::RcD3dInvalidState, "copy row range overflow")
                    })?;
                    let dst_row_end = dst_row_start.checked_add(dst_stride).ok_or_else(|| {
                        AppError::new(ReasonCode::RcD3dInvalidState, "copy row range overflow")
                    })?;
                    if src_row_end > src_bytes.len() || dst_row_end > dst_bytes.bytes.len() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "copy resource region out of bounds",
                        ));
                    }
                    dst_bytes.bytes[dst_row_start..dst_row_end]
                        .copy_from_slice(&src_bytes[src_row_start..src_row_end]);
                }
            }
            Command::ResolveSubresource { dst, src, .. } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.blit_passes += 1;
                self.copy_resource_bytes(*src, *dst)?;
            }
            Command::ExecuteBundle { bundle_commands } => {
                // Recursively process each command in the bundle. Bundle
                // commands inherit the parent list's pipeline state and
                // render-pass context — they execute as if inlined.
                for cmd in bundle_commands {
                    self.process_execution_command(cmd, pipeline, plan)?;
                }
            }
            Command::DispatchRays { .. } => {
                // Raytracing dispatches are independent of render passes.
                // End any active render pass and count as a raytrace pass.
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.raytrace_passes += 1;
            }
        }
        Ok(())
    }

    pub fn execute_command_lists(
        &mut self,
        _queue: CommandQueueId,
        lists: &[ImmutableCommandStream],
        signal_fence: Option<(FenceId, u64)>,
    ) -> AppResult<MetalCommandBufferPlan> {
        let mut plan = ExecutionPlanState {
            active_pass: None,
            render_passes: Vec::new(),
            compute_passes: 0,
            blit_passes: 0,
            raytrace_passes: 0,
            validation_errors: Vec::new(),
            root_constants_log: Vec::new(),
        };

        for stream in lists {
            let pipeline = self
                .pipeline_states
                .get(
                    &self
                        .command_lists
                        .get(&stream.id)
                        .ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                format!("unknown command list {}", stream.id),
                            )
                        })?
                        .pipeline_state,
                )
                .ok_or_else(|| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "unknown pipeline state")
                })?
                .clone();
            for command in &stream.commands {
                self.process_execution_command(command, &pipeline, &mut plan)?;
            }
        }
        if let Some(pass) = plan.active_pass.take() {
            plan.render_passes.push(pass);
        }

        let mut signaled_fences = Vec::new();
        if let Some((fence, value)) = signal_fence {
            self.signal_fence(fence, value)?;
            signaled_fences.push((fence, value));
        }

        Ok(MetalCommandBufferPlan {
            render_passes: plan.render_passes,
            compute_passes: plan.compute_passes,
            blit_passes: plan.blit_passes,
            raytrace_passes: plan.raytrace_passes,
            validation_errors: plan.validation_errors,
            root_constants_log: plan.root_constants_log,
            signaled_fences,
        })
    }

    pub fn create_fence(&mut self, initial_value: u64) -> FenceId {
        let id = self.alloc_id();
        self.fences.insert(
            id,
            FenceRecord {
                value: initial_value,
            },
        );
        id
    }

    pub fn signal_fence(&mut self, fence: FenceId, value: u64) -> AppResult<()> {
        self.fence_mut(fence)?.value = value;
        Ok(())
    }

    pub fn fence_value(&self, fence: FenceId) -> AppResult<u64> {
        Ok(self.fence(fence)?.value)
    }

    pub fn wait_for_fence(&self, fence: FenceId, value: u64, timeout_ns: u64) -> AppResult<bool> {
        // Fences are CPU-emulated and completed synchronously by
        // `signal_fence`, so a satisfied fence is answered immediately. When
        // the fence is not yet satisfied and a timeout is provided, poll
        // briefly instead of busy-returning; a zero timeout performs a
        // non-blocking check.
        let start = std::time::Instant::now();
        loop {
            let current = self.fence_value(fence)?;
            if current >= value {
                return Ok(true);
            }
            if timeout_ns == 0 {
                return Ok(false);
            }
            if start.elapsed().as_nanos() as u64 >= timeout_ns {
                return Ok(false);
            }
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
    }

    pub fn upload_write(
        &mut self,
        resource: ResourceId,
        offset: usize,
        bytes: &[u8],
    ) -> AppResult<()> {
        let resource = self.resource_mut(resource)?;
        if resource.desc.heap != HeapType::Upload {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource is not in an upload heap",
            ));
        }
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, "upload write range overflow")
        })?;
        if end > resource.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "upload write out of bounds",
            ));
        }
        resource.bytes[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    pub fn overwrite_resource_bytes(
        &mut self,
        resource: ResourceId,
        bytes: &[u8],
    ) -> AppResult<()> {
        let resource = self.resource_mut(resource)?;
        if bytes.len() > resource.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource write out of bounds",
            ));
        }
        resource.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    pub fn readback(
        &self,
        resource: ResourceId,
        fence: FenceId,
        required_value: u64,
    ) -> AppResult<Vec<u8>> {
        let resource = self.resource(resource)?;
        if resource.desc.heap != HeapType::Readback {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource is not in a readback heap",
            ));
        }
        if self.fence(fence)?.value < required_value {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "readback requires a completed fence",
            ));
        }
        Ok(resource.bytes.clone())
    }

    pub fn resource_storage_mode(&self, resource: ResourceId) -> AppResult<MetalStorageMode> {
        Ok(self.resource(resource)?.storage_mode)
    }

    pub fn set_resource_usage_hint(
        &mut self,
        resource: ResourceId,
        usage_hint: ResourceUsageHint,
    ) -> AppResult<()> {
        let mut desc = self.resource(resource)?.desc.clone();
        desc.usage_hint = usage_hint;
        let storage_mode = self.storage_mode_for_resource(&desc);
        let record = self.resource_mut(resource)?;
        record.desc = desc;
        record.storage_mode = storage_mode;
        Ok(())
    }

    pub fn create_query_heap(&mut self, ty: QueryType, count: usize) -> QueryHeapId {
        let id = self.alloc_id();
        self.query_heaps.insert(
            id,
            QueryHeapRecord {
                ty,
                values: vec![0; count],
                emulated: ty == QueryType::Timestamp,
            },
        );
        id
    }

    pub fn write_timestamp(&mut self, heap: QueryHeapId, index: usize) -> AppResult<u64> {
        let value = self.timestamps * 1_000;
        self.timestamps += 1;
        let query_heap = self.query_heap_mut(heap)?;
        if query_heap.ty != QueryType::Timestamp {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "query heap is not a timestamp heap",
            ));
        }
        let slot = query_heap.values.get_mut(index).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, "query index out of bounds")
        })?;
        *slot = value;
        Ok(value)
    }

    pub fn write_occlusion(
        &mut self,
        heap: QueryHeapId,
        index: usize,
        samples: u64,
    ) -> AppResult<()> {
        let query_heap = self.query_heap_mut(heap)?;
        if query_heap.ty != QueryType::Occlusion {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "query heap is not an occlusion heap",
            ));
        }
        let slot = query_heap.values.get_mut(index).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, "query index out of bounds")
        })?;
        *slot = samples;
        Ok(())
    }

    /// Store an arbitrary timestamp value at `index`. Used to record the
    /// end-minus-begin delta for D3D12 timestamp query pairs.
    pub fn write_timestamp_value(
        &mut self,
        heap: QueryHeapId,
        index: usize,
        value: u64,
    ) -> AppResult<()> {
        let query_heap = self.query_heap_mut(heap)?;
        if query_heap.ty != QueryType::Timestamp {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "query heap is not a timestamp heap",
            ));
        }
        let slot = query_heap.values.get_mut(index).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, "query index out of bounds")
        })?;
        *slot = value;
        Ok(())
    }

    /// Write `bytes` at `offset` into a resource's CPU-side storage, with
    /// checked bounds. Unlike `upload_write` this works for any heap type
    /// (used to fill readback buffers from query resolves).
    pub fn write_resource_bytes(
        &mut self,
        resource: ResourceId,
        offset: usize,
        bytes: &[u8],
    ) -> AppResult<()> {
        let resource = self.resource_mut(resource)?;
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, "resource write range overflow")
        })?;
        if end > resource.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource write out of bounds",
            ));
        }
        resource.bytes[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    pub fn resolve_query_data(&self, heap: QueryHeapId) -> AppResult<QueryResolveResult> {
        let query_heap = self.query_heap(heap)?;
        Ok(QueryResolveResult {
            values: query_heap.values.clone(),
            emulated: query_heap.emulated,
        })
    }

    pub fn render_scene(&self, scene: &SceneSpec) -> AppResult<FrameArtifact> {
        let mapping = format_mapping(scene.format)?;
        let signature = format!(
            "{}|{:?}|{:02x}{:02x}{:02x}{:02x}|{}|{}|{:?}",
            scene.name,
            scene.format,
            scene.clear_color[0],
            scene.clear_color[1],
            scene.clear_color[2],
            scene.clear_color[3],
            scene.draw_calls,
            scene.compute_dispatches,
            mapping.strategy,
        );
        Ok(FrameArtifact {
            hash: util::sha256_bytes(signature.as_bytes()),
            ssim: 1.0,
            validation_errors: Vec::new(),
        })
    }

    fn validate_descriptor(&self, descriptor: &ViewDescriptor) -> AppResult<()> {
        match descriptor {
            ViewDescriptor::Cbv { resource, .. } => {
                self.resource(*resource)?;
            }
            ViewDescriptor::Srv { resource, format }
            | ViewDescriptor::Uav { resource, format }
            | ViewDescriptor::Rtv { resource, format }
            | ViewDescriptor::Dsv { resource, format } => {
                let resource = self.resource(*resource)?;
                validate_view_format(resource.desc.format, *format, descriptor)?;
            }
            ViewDescriptor::Sampler { .. } => {}
        }
        Ok(())
    }

    fn validate_rtv_descriptor(&self, heap: DescriptorHeapId, index: usize) -> AppResult<()> {
        match self.descriptor_at(heap, index)? {
            ViewDescriptor::Rtv { .. } => Ok(()),
            _ => Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "descriptor is not an RTV",
            )),
        }
    }

    fn validate_dsv_descriptor(&self, heap: DescriptorHeapId, index: usize) -> AppResult<()> {
        match self.descriptor_at(heap, index)? {
            ViewDescriptor::Dsv { .. } => Ok(()),
            _ => Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "descriptor is not a DSV",
            )),
        }
    }

    fn descriptor_at(&self, heap: DescriptorHeapId, index: usize) -> AppResult<ViewDescriptor> {
        self.descriptor_heap(heap)?
            .descriptors
            .get(index)
            .and_then(Clone::clone)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "descriptor slot is empty"))
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn storage_mode_for_resource(&self, desc: &ResourceDesc) -> MetalStorageMode {
        if self.capabilities.memoryless_render_targets
            && desc.heap == HeapType::Default
            && desc.format == DxgiFormat::D24UnormS8Uint
            && matches!(
                desc.usage_hint,
                ResourceUsageHint::DepthStencil
                    | ResourceUsageHint::Texture {
                        depth_stencil: true,
                        ..
                    }
            )
        {
            return MetalStorageMode::Memoryless;
        }

        if self.capabilities.unified_memory
            && desc.heap == HeapType::Default
            && desc.format == DxgiFormat::R32Float
            && desc.subresources == 1
            && desc.size <= 64 * 1024
            && matches!(
                desc.usage_hint,
                ResourceUsageHint::Buffer {
                    cpu_write_frequent: true,
                    ..
                }
            )
        {
            return MetalStorageMode::Shared;
        }

        if self.capabilities.unified_memory
            && desc.heap == HeapType::Default
            && desc.subresources == 1
            && desc.size <= 256 * 1024
            && matches!(
                desc.usage_hint,
                ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: false,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                }
            )
        {
            return MetalStorageMode::Shared;
        }

        match desc.heap {
            HeapType::Upload | HeapType::Readback => MetalStorageMode::Shared,
            HeapType::Default => MetalStorageMode::Private,
        }
    }

    fn swapchain(&self, swapchain: SwapchainId) -> AppResult<&SwapchainRecord> {
        self.swapchains.get(&swapchain).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown swapchain {swapchain}"),
            )
        })
    }

    fn swapchain_mut(&mut self, swapchain: SwapchainId) -> AppResult<&mut SwapchainRecord> {
        self.swapchains.get_mut(&swapchain).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown swapchain {swapchain}"),
            )
        })
    }

    fn resource(&self, resource: ResourceId) -> AppResult<&ResourceRecord> {
        self.resources.get(&resource).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown resource {resource}"),
            )
        })
    }

    fn resource_mut(&mut self, resource: ResourceId) -> AppResult<&mut ResourceRecord> {
        self.resources.get_mut(&resource).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown resource {resource}"),
            )
        })
    }

    /// Copy the contents of `src` into `dst` in place (`copy_from_slice`),
    /// avoiding the intermediate full-buffer allocation of a clone.
    fn copy_resource_bytes(&mut self, src: ResourceId, dst: ResourceId) -> AppResult<()> {
        if src == dst {
            return Ok(());
        }
        // Temporarily remove the destination so the source can be borrowed
        // immutably while the destination is mutated in place; the entry is
        // restored even on failure.
        let mut dst_record = self.resources.remove(&dst).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown resource {dst}"),
            )
        })?;
        let copy_result = (|| -> AppResult<()> {
            let src_record = self.resources.get(&src).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("unknown resource {src}"),
                )
            })?;
            if src_record.bytes.len() != dst_record.bytes.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "copy resource size mismatch",
                ));
            }
            dst_record.bytes.copy_from_slice(&src_record.bytes);
            Ok(())
        })();
        self.resources.insert(dst, dst_record);
        copy_result
    }

    fn descriptor_heap(&self, heap: DescriptorHeapId) -> AppResult<&DescriptorHeapRecord> {
        self.descriptor_heaps.get(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown descriptor heap {heap}"),
            )
        })
    }

    fn descriptor_heap_mut(
        &mut self,
        heap: DescriptorHeapId,
    ) -> AppResult<&mut DescriptorHeapRecord> {
        self.descriptor_heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown descriptor heap {heap}"),
            )
        })
    }

    fn command_list(&self, list: CommandListId) -> AppResult<&CommandListRecord> {
        self.command_lists.get(&list).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown command list {list}"),
            )
        })
    }

    fn command_list_mut(&mut self, list: CommandListId) -> AppResult<&mut CommandListRecord> {
        let record = self.command_lists.get_mut(&list).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown command list {list}"),
            )
        })?;
        if record.closed {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("command list {list} is closed"),
            ));
        }
        Ok(record)
    }

    fn fence(&self, fence: FenceId) -> AppResult<&FenceRecord> {
        self.fences.get(&fence).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown fence {fence}"),
            )
        })
    }

    fn fence_mut(&mut self, fence: FenceId) -> AppResult<&mut FenceRecord> {
        self.fences.get_mut(&fence).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown fence {fence}"),
            )
        })
    }

    fn query_heap(&self, heap: QueryHeapId) -> AppResult<&QueryHeapRecord> {
        self.query_heaps.get(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown query heap {heap}"),
            )
        })
    }

    fn query_heap_mut(&mut self, heap: QueryHeapId) -> AppResult<&mut QueryHeapRecord> {
        self.query_heaps.get_mut(&heap).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown query heap {heap}"),
            )
        })
    }

    fn presented_frame_ppm_bytes(&self, swapchain: SwapchainId) -> AppResult<Vec<u8>> {
        let frame = self.presented_frame(swapchain)?;
        encode_ppm(frame.width, frame.height, frame.format, &frame.bytes)
    }
}

fn encode_ppm(width: u32, height: u32, format: DxgiFormat, bytes: &[u8]) -> AppResult<Vec<u8>> {
    let pixel_count = width as usize * height as usize;
    let expected_bytes = pixel_count
        .checked_mul(4)
        .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "frame dimensions overflow"))?;
    if bytes.len() < expected_bytes {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("frame buffer is too small for {width}x{height} {format:?}"),
        ));
    }
    let mut ppm = format!("P6\n{width} {height}\n255\n").into_bytes();
    ppm.reserve(pixel_count * 3);
    match format {
        DxgiFormat::R8G8B8A8Unorm | DxgiFormat::R8G8B8A8UnormSrgb => {
            for chunk in bytes[..expected_bytes].chunks_exact(4) {
                ppm.extend_from_slice(&chunk[..3]);
            }
        }
        DxgiFormat::B8G8R8A8Unorm | DxgiFormat::B8G8R8A8UnormSrgb | DxgiFormat::B8G8R8X8Unorm => {
            for chunk in bytes[..expected_bytes].chunks_exact(4) {
                ppm.extend_from_slice(&[chunk[2], chunk[1], chunk[0]]);
            }
        }
        other => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("frame export does not support {other:?}"),
            ));
        }
    }
    Ok(ppm)
}

pub fn format_mapping(format: DxgiFormat) -> AppResult<FormatMapping> {
    Ok(match format {
        DxgiFormat::R8G8B8A8Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba8Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R8G8B8A8UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba8UnormSrgb,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R8G8B8A8Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba8Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::B8G8R8A8Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bgra8Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::B8G8R8A8UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bgra8UnormSrgb,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::B8G8R8X8Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bgra8Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R8Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R8Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R8Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R8Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R16Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R16Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R16Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16Snorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R16Snorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R32Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R32Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32Sint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::R32Sint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R10G10B10A2Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgb10A2Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R10G10B10A2Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgb10A2Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R11G11B10Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg11B10Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg16Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg16Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg16Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16Snorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg16Snorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32G32Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg32Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32G32Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rg32Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16B16A16Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba16Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16B16A16Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba16Unorm,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R16G16B16A16Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba16Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32G32B32A32Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba32Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::R32G32B32A32Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Rgba32Uint,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::D24UnormS8Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Depth24UnormStencil8,
            strategy: EmulationStrategy::DepthStencilEmulation,
        },
        DxgiFormat::D32Float => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Depth32Float,
            strategy: EmulationStrategy::Direct,
        },
        DxgiFormat::D32FloatS8Uint => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Depth32FloatStencil8,
            strategy: EmulationStrategy::DepthStencilEmulation,
        },
        DxgiFormat::Bc1Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc1Rgba,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc1UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc1RgbaSrgb,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc2Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc2Rgba,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc2UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc2RgbaSrgb,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc3Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc3Rgba,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc3UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc3RgbaSrgb,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc4Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc4RUnorm,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc5Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc5RgUnorm,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc7Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc7RgbaUnorm,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::Bc7UnormSrgb => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::Bc7RgbaUnormSrgb,
            strategy: EmulationStrategy::ConversionShader,
        },
        DxgiFormat::B5G6R5Unorm => FormatMapping {
            dxgi: format,
            metal: MtlPixelFormat::B5G6R5Unorm,
            strategy: EmulationStrategy::Swizzle,
        },
    })
}

fn metal_binding(slot: u32, descriptor: &ViewDescriptor) -> MetalBinding {
    match descriptor {
        ViewDescriptor::Cbv { resource, .. } => MetalBinding {
            slot,
            kind: "cbv".to_string(),
            resource: Some(*resource),
            metal_format: None,
        },
        ViewDescriptor::Srv { resource, format } => MetalBinding {
            slot,
            kind: "srv".to_string(),
            resource: Some(*resource),
            metal_format: Some(format_mapping(*format).expect("valid format mapping").metal),
        },
        ViewDescriptor::Uav { resource, format } => MetalBinding {
            slot,
            kind: "uav".to_string(),
            resource: Some(*resource),
            metal_format: Some(format_mapping(*format).expect("valid format mapping").metal),
        },
        ViewDescriptor::Sampler { .. } => MetalBinding {
            slot,
            kind: "sampler".to_string(),
            resource: None,
            metal_format: None,
        },
        ViewDescriptor::Rtv { resource, format } => MetalBinding {
            slot,
            kind: "rtv".to_string(),
            resource: Some(*resource),
            metal_format: Some(format_mapping(*format).expect("valid format mapping").metal),
        },
        ViewDescriptor::Dsv { resource, format } => MetalBinding {
            slot,
            kind: "dsv".to_string(),
            resource: Some(*resource),
            metal_format: Some(format_mapping(*format).expect("valid format mapping").metal),
        },
    }
}

fn validate_view_format(
    resource_format: DxgiFormat,
    requested_format: DxgiFormat,
    descriptor: &ViewDescriptor,
) -> AppResult<()> {
    match descriptor {
        ViewDescriptor::Dsv { .. } => {
            if !matches!(resource_format, DxgiFormat::D24UnormS8Uint)
                || requested_format != resource_format
            {
                return Err(AppError::new(
                    ReasonCode::RcD3dFeatureUnsupported,
                    "invalid depth/stencil view reinterpretation",
                ));
            }
        }
        ViewDescriptor::Rtv { .. } => {
            if resource_format == DxgiFormat::D24UnormS8Uint || requested_format != resource_format
            {
                return Err(AppError::new(
                    ReasonCode::RcD3dFeatureUnsupported,
                    "invalid render-target view reinterpretation",
                ));
            }
        }
        ViewDescriptor::Srv { .. } | ViewDescriptor::Uav { .. } => {
            if requested_format != resource_format && resource_format != DxgiFormat::B5G6R5Unorm {
                return Err(AppError::new(
                    ReasonCode::RcD3dFeatureUnsupported,
                    "invalid shader-resource/UAV view reinterpretation",
                ));
            }
        }
        ViewDescriptor::Cbv { .. } | ViewDescriptor::Sampler { .. } => {}
    }
    Ok(())
}

pub fn detected_host_gpu_profile() -> HostGpuProfile {
    static HOST_GPU_PROFILE: OnceLock<HostGpuProfile> = OnceLock::new();
    HOST_GPU_PROFILE
        .get_or_init(detect_host_gpu_profile)
        .clone()
}

fn detect_host_gpu_profile() -> HostGpuProfile {
    let profile = {
        #[cfg(target_os = "macos")]
        {
            if let Some(chip_name) = detect_macos_apple_chip_name() {
                host_gpu_profile_from_name(&chip_name)
            } else {
                host_gpu_profile_from_name("Apple GPU")
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            host_gpu_profile_from_name("Apple GPU")
        }
    };
    match reported_gpu_vendor_override() {
        Some(vendor) => apply_reported_gpu_vendor_compatibility(profile, vendor),
        None => profile,
    }
}

pub(crate) fn host_gpu_profile_from_name(name: &str) -> HostGpuProfile {
    let normalized = normalize_gpu_name(name);
    let family = metal_family_for_gpu_name(&normalized).unwrap_or(8);
    let vendor = reported_gpu_vendor_for_name(&normalized);
    HostGpuProfile {
        adapter: AdapterInfo {
            id: 1,
            vendor_id: vendor.vendor_id(),
            device_id: vendor.device_id_for_family(family),
            name: normalized.clone(),
            metal_family: format!("apple{family}"),
        },
        capabilities: MetalCapabilities {
            unified_memory: normalized.starts_with("Apple "),
            argument_buffers: true,
            memoryless_render_targets: normalized.starts_with("Apple "),
            timestamp_queries: true,
            mesh_shaders: family >= 9,
            // Metal 3.0+ raytracing available on Apple GPU family >= 7
            raytracing: family >= 7,
        },
    }
}

fn reported_gpu_vendor_for_name(name: &str) -> ReportedGpuVendor {
    let upper = name.to_ascii_uppercase();
    if upper.contains("NVIDIA")
        || upper.contains("GEFORCE")
        || upper.contains("QUADRO")
        || upper.contains("RTX")
        || upper.contains("GTX")
    {
        ReportedGpuVendor::Nvidia
    } else if upper.starts_with("AMD ") || upper.contains("RADEON") {
        ReportedGpuVendor::Amd
    } else {
        ReportedGpuVendor::Apple
    }
}

fn reported_gpu_vendor_override() -> Option<ReportedGpuVendor> {
    let value = std::env::var(GPU_COMPAT_VENDOR_ENV).ok()?;
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" | "" => None,
        "apple" => Some(ReportedGpuVendor::Apple),
        "nvidia" | "geforce" => Some(ReportedGpuVendor::Nvidia),
        "amd" | "radeon" => Some(ReportedGpuVendor::Amd),
        _ => None,
    }
}

fn apply_reported_gpu_vendor_compatibility(
    mut profile: HostGpuProfile,
    vendor: ReportedGpuVendor,
) -> HostGpuProfile {
    let family = profile
        .adapter
        .metal_family
        .strip_prefix("apple")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(8);
    profile.adapter.vendor_id = vendor.vendor_id();
    profile.adapter.device_id = vendor.device_id_for_family(family);
    if vendor != ReportedGpuVendor::Apple && profile.adapter.name.starts_with("Apple ") {
        profile.adapter.name = vendor.compatibility_adapter_name(&profile.adapter.name);
    }
    profile
}

fn normalize_gpu_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        "Apple GPU".to_string()
    } else {
        trimmed.to_string()
    }
}

fn metal_family_for_gpu_name(name: &str) -> Option<u8> {
    let upper = name.to_ascii_uppercase();
    if !upper.starts_with("APPLE ") {
        return None;
    }
    let generation = upper
        .split_whitespace()
        .find_map(|part| part.strip_prefix('M'))
        .and_then(|digits| {
            digits
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>()
                .parse::<u8>()
                .ok()
        });
    generation
        .map(|generation| generation.saturating_add(6))
        .or(Some(8))
}

#[cfg(target_os = "macos")]
fn detect_macos_apple_chip_name() -> Option<String> {
    read_command_output("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"])
        .filter(|value| value.starts_with("Apple "))
        .or_else(|| system_profiler_value("SPHardwareDataType", &["chip_type"]))
        .or_else(|| system_profiler_value("SPDisplaysDataType", &["sppci_model", "chipset_model"]))
        .filter(|value| value.starts_with("Apple "))
}

#[cfg(target_os = "macos")]
fn system_profiler_value(data_type: &str, keys: &[&str]) -> Option<String> {
    let output = HostCommand::new("/usr/sbin/system_profiler")
        .arg(data_type)
        .arg("-json")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let json = serde_json::from_slice::<serde_json::Value>(&output.stdout).ok()?;
    let entries = json.get(data_type)?.as_array()?;
    for entry in entries {
        for key in keys {
            let value = entry.get(*key)?.as_str()?.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn read_command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = HostCommand::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_pass_plan_merges_only_compatible_attachments() {
        let mut pass = RenderPassPlan {
            color_formats: vec![MtlPixelFormat::Bgra8Unorm],
            depth_format: Some(MtlPixelFormat::Depth32Float),
            draw_calls: 2,
            load_action: "clear".to_string(),
            store_action: "store".to_string(),
        };

        // Identical attachments with a follow-on `load` => mergeable.
        assert!(pass.can_merge_with(
            &[MtlPixelFormat::Bgra8Unorm],
            Some(MtlPixelFormat::Depth32Float),
            "load",
        ));

        // Identical attachments but the follow-on pass clears => not mergeable,
        // because the clear establishes a fresh observable starting state.
        assert!(!pass.can_merge_with(
            &[MtlPixelFormat::Bgra8Unorm],
            Some(MtlPixelFormat::Depth32Float),
            "clear",
        ));

        // Different color format => not mergeable.
        assert!(!pass.can_merge_with(
            &[MtlPixelFormat::Rgba8Unorm],
            Some(MtlPixelFormat::Depth32Float),
            "load",
        ));

        // Different depth presence => not mergeable.
        assert!(!pass.can_merge_with(&[MtlPixelFormat::Bgra8Unorm], None, "load"));

        // Merging adopts the later pass's store action while preserving the
        // first pass's load action and draw tally.
        pass.merge_store_action("dont_care");
        assert_eq!(pass.store_action, "dont_care");
        assert_eq!(pass.load_action, "clear");
        assert_eq!(pass.draw_calls, 2);
    }

    #[test]
    fn apple_m_series_profiles_map_to_expected_metal_families() {
        let m1 = host_gpu_profile_from_name("Apple M1 Max");
        assert_eq!(m1.adapter.name, "Apple M1 Max");
        assert_eq!(m1.adapter.vendor_id, 0x106b);
        assert_eq!(m1.adapter.metal_family, "apple7");
        assert!(m1.capabilities.unified_memory);
        assert!(m1.capabilities.argument_buffers);
        assert!(m1.capabilities.memoryless_render_targets);
        assert!(!m1.capabilities.mesh_shaders);

        let m3 = host_gpu_profile_from_name("Apple M3 Pro");
        assert_eq!(m3.adapter.metal_family, "apple9");
        assert!(m3.capabilities.mesh_shaders);

        let m4 = host_gpu_profile_from_name("Apple M4 Max");
        assert_eq!(m4.adapter.metal_family, "apple10");
        assert!(m4.capabilities.mesh_shaders);

        let m5 = host_gpu_profile_from_name("Apple M5 Pro");
        assert_eq!(m5.adapter.metal_family, "apple11");
        assert!(m5.capabilities.mesh_shaders);
    }

    #[test]
    fn nvidia_and_amd_profiles_report_vendor_compatible_adapter_ids() {
        let nvidia = host_gpu_profile_from_name("NVIDIA GeForce RTX 4080");
        assert_eq!(nvidia.adapter.vendor_id, 0x10de);
        assert_eq!(nvidia.adapter.device_id, 0x2008);
        assert_eq!(nvidia.adapter.name, "NVIDIA GeForce RTX 4080");
        assert_eq!(nvidia.adapter.metal_family, "apple8");
        assert!(!nvidia.capabilities.unified_memory);
        assert!(!nvidia.capabilities.memoryless_render_targets);

        let amd = host_gpu_profile_from_name("AMD Radeon RX 7900 XTX");
        assert_eq!(amd.adapter.vendor_id, 0x1002);
        assert_eq!(amd.adapter.device_id, 0x7008);
        assert_eq!(amd.adapter.name, "AMD Radeon RX 7900 XTX");
        assert_eq!(amd.adapter.metal_family, "apple8");
        assert!(!amd.capabilities.unified_memory);
        assert!(!amd.capabilities.memoryless_render_targets);
    }

    #[test]
    fn reported_vendor_compatibility_override_preserves_underlying_metal_capabilities() {
        let apple = host_gpu_profile_from_name("Apple M3 Pro");
        let nvidia =
            apply_reported_gpu_vendor_compatibility(apple.clone(), ReportedGpuVendor::Nvidia);
        let amd = apply_reported_gpu_vendor_compatibility(apple.clone(), ReportedGpuVendor::Amd);

        assert_eq!(nvidia.adapter.vendor_id, 0x10de);
        assert_eq!(nvidia.adapter.device_id, 0x2009);
        assert_eq!(
            nvidia.adapter.name,
            "NVIDIA Compatibility Adapter (Apple M3 Pro)"
        );
        assert_eq!(nvidia.adapter.metal_family, "apple9");
        assert_eq!(nvidia.capabilities, apple.capabilities);

        assert_eq!(amd.adapter.vendor_id, 0x1002);
        assert_eq!(amd.adapter.device_id, 0x7009);
        assert_eq!(amd.adapter.name, "AMD Compatibility Adapter (Apple M3 Pro)");
        assert_eq!(amd.adapter.metal_family, "apple9");
        assert_eq!(amd.capabilities, apple.capabilities);
    }

    #[test]
    fn graphics_backend_uses_capability_profile_for_features_and_storage_modes() {
        let mut backend =
            GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M3 Ultra"));

        assert_eq!(backend.adapter().name, "Apple M3 Ultra");
        assert_eq!(backend.adapter().metal_family, "apple9");
        assert!(backend.query_feature(FeatureQuery::TimestampQueries));
        assert!(backend.query_feature(FeatureQuery::MeshShaders));

        let upload = backend
            .create_resource(ResourceDesc {
                name: "upload".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Upload,
                size: 256,
                subresources: 1,
                initial_state: ResourceState::GenericRead,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create upload resource");
        assert_eq!(
            backend
                .resource_storage_mode(upload)
                .expect("upload storage mode"),
            MetalStorageMode::Shared
        );

        let depth = backend
            .create_resource(ResourceDesc {
                name: "depth".to_string(),
                format: DxgiFormat::D24UnormS8Uint,
                heap: HeapType::Default,
                size: 4096,
                subresources: 1,
                initial_state: ResourceState::DepthWrite,
                usage_hint: ResourceUsageHint::DepthStencil,
            })
            .expect("create depth resource");
        assert_eq!(
            backend
                .resource_storage_mode(depth)
                .expect("depth storage mode"),
            MetalStorageMode::Memoryless
        );
    }

    #[test]
    fn graphics_backend_prefers_shared_storage_for_small_dynamic_buffers_on_unified_memory_apple_gpus()
     {
        let mut backend =
            GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M5 Pro"));

        let small_dynamic_buffer = backend
            .create_resource(ResourceDesc {
                name: "small-dynamic-vertex-buffer".to_string(),
                format: DxgiFormat::R32Float,
                heap: HeapType::Default,
                size: 4096,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("create small dynamic vertex buffer");
        assert_eq!(
            backend
                .resource_storage_mode(small_dynamic_buffer)
                .expect("small dynamic buffer storage mode"),
            MetalStorageMode::Shared
        );

        let small_static_buffer = backend
            .create_resource(ResourceDesc {
                name: "small-static-vertex-buffer".to_string(),
                format: DxgiFormat::R32Float,
                heap: HeapType::Default,
                size: 4096,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: BufferRole::Vertex,
                    cpu_write_frequent: false,
                },
            })
            .expect("create small static vertex buffer");
        assert_eq!(
            backend
                .resource_storage_mode(small_static_buffer)
                .expect("small static buffer storage mode"),
            MetalStorageMode::Private
        );

        let large_dynamic_buffer = backend
            .create_resource(ResourceDesc {
                name: "large-dynamic-vertex-buffer".to_string(),
                format: DxgiFormat::R32Float,
                heap: HeapType::Default,
                size: 256 * 1024,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: BufferRole::Vertex,
                    cpu_write_frequent: true,
                },
            })
            .expect("create large dynamic vertex buffer");
        assert_eq!(
            backend
                .resource_storage_mode(large_dynamic_buffer)
                .expect("large dynamic buffer storage mode"),
            MetalStorageMode::Private
        );

        let streamed_texture = backend
            .create_resource(ResourceDesc {
                name: "streamed-texture".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 128 * 128 * 4,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: false,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                },
            })
            .expect("create streamed texture");
        assert_eq!(
            backend
                .resource_storage_mode(streamed_texture)
                .expect("streamed texture storage mode"),
            MetalStorageMode::Shared
        );

        let render_target_texture = backend
            .create_resource(ResourceDesc {
                name: "render-target-texture".to_string(),
                format: DxgiFormat::B8G8R8A8Unorm,
                heap: HeapType::Default,
                size: 128 * 128 * 4,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: false,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: true,
                },
            })
            .expect("create render target texture");
        assert_eq!(
            backend
                .resource_storage_mode(render_target_texture)
                .expect("render target texture storage mode"),
            MetalStorageMode::Private
        );
    }

    #[test]
    fn graphics_backend_uses_low_latency_swapchain_defaults_on_apple_silicon() {
        let mut backend =
            GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M5 Pro"));

        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 1920,
                height: 1080,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");

        let state = backend.swapchain_state(swapchain).expect("swapchain state");

        assert_eq!(state.max_frame_latency, 1);
    }

    #[test]
    fn graphics_backend_preserves_deeper_swapchain_latency_for_non_unified_profiles() {
        let mut backend =
            GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Generic Discrete GPU"));

        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 1280,
                height: 720,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");

        let state = backend.swapchain_state(swapchain).expect("swapchain state");

        assert_eq!(state.max_frame_latency, 3);
    }
}
