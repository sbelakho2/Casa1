use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::{Command as HostCommand, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// `DXGI_FORMAT_UNKNOWN` (0) — recognised ABI value with no renderable
    /// representation.
    Unknown,
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

/// How a raw `DXGI_FORMAT` value (from `dxgiformat.h`) is translated by the
/// Casa1 graphics layer. Every known DXGI format value has an explicit
/// strategy — there is no silent "closest usable" substitution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatTranslation {
    /// The value maps exactly (identity) to a [`DxgiFormat`] variant.
    Exact,
    /// The value is typeless or a view-only half of a depth-stencil pair;
    /// the same bits are interpreted as a compatible typed format.
    ViewReinterpret,
    /// Channel-order rearrangement into a bit-compatible packed format.
    Swizzle,
    /// Requires a shader pass to convert to a representable format.
    ConversionShader,
    /// Block-compressed format with no Metal-equivalent codec; must be
    /// decompressed before sampling.
    Decompression,
    /// Depth/stencil bits are emulated through a depth-stencil pass.
    DepthStencilEmulation,
    /// No translation path exists in Casa1.
    Unsupported,
}

/// Number of times the lossy [`DxgiFormat::from_u32_diagnostics`] fallback
/// has substituted [`DXGI_FORMAT_FALLBACK`] for a raw value that
/// [`from_u32_checked`](Self::from_u32_checked) rejected. Observable so that
/// substitution is never invisible.
static DXGI_FORMAT_FALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);

/// The raw value substituted by the diagnostics-only fallback.
pub const DXGI_FORMAT_FALLBACK: DxgiFormat = DxgiFormat::R8G8B8A8Unorm;

impl DxgiFormat {
    /// DIAGNOSTICS-ONLY lossy mapping of a raw `DXGI_FORMAT` enum value.
    ///
    /// Production guest-facing paths must NEVER call this: an unsupported
    /// format is substituted with [`DXGI_FORMAT_FALLBACK`]
    /// (R8G8B8A8Unorm), which silently changes the bit width, numerical
    /// interpretation, compression format and shader-visible values of the
    /// resource. Every production caller uses
    /// [`from_u32_checked`](Self::from_u32_checked) (explicit error) or
    /// [`translation_strategy`](Self::translation_strategy) (explicit plan).
    ///
    /// This wrapper exists only for diagnostics and test convenience, and
    /// every fallback it makes is recorded in a counter (see
    /// [`format_fallback_count`](Self::format_fallback_count)) so the
    /// substitution is observable.
    pub fn from_u32_diagnostics(value: u32) -> Self {
        match Self::from_u32_checked(value) {
            Ok(format) => format,
            Err(_) => {
                DXGI_FORMAT_FALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
                DXGI_FORMAT_FALLBACK
            }
        }
    }

    /// Number of lossy fallback substitutions recorded by
    /// [`from_u32_diagnostics`](Self::from_u32_diagnostics).
    pub fn format_fallback_count() -> u64 {
        DXGI_FORMAT_FALLBACK_COUNT.load(Ordering::Relaxed)
    }

    /// Map a raw `DXGI_FORMAT` enum value to its exact [`DxgiFormat`]
    /// representation, returning an error for every value that has no exact
    /// representation in the Casa1 format model.
    ///
    /// Values that are part of the DXGI ABI but lack an exact representation
    /// (typeless, SINT/SNORM variants without a variant, YUV/video, BC6H,
    /// palette formats, depth-stencil view-only halves, …) return
    /// `Err(ReasonCode::RcGfxFormatUnsupported)` — they are never silently
    /// substituted with a "closest" format. Use
    /// [`translation_strategy`](Self::translation_strategy) to query the
    /// explicit translation plan for any raw value.
    pub fn from_u32_checked(value: u32) -> AppResult<Self> {
        let format = match value {
            // Exact identity — every DXGI value with a semantically exact
            // representation maps to exactly that representation.
            0 => DxgiFormat::Unknown,            // DXGI_FORMAT_UNKNOWN
            2 => DxgiFormat::R32G32B32A32Float,  // R32G32B32A32_FLOAT
            3 => DxgiFormat::R32G32B32A32Uint,   // R32G32B32A32_UINT
            10 => DxgiFormat::R16G16B16A16Float, // R16G16B16A16_FLOAT
            11 => DxgiFormat::R16G16B16A16Unorm, // R16G16B16A16_UNORM
            12 => DxgiFormat::R16G16B16A16Uint,  // R16G16B16A16_UINT
            16 => DxgiFormat::R32G32Float,       // R32G32_FLOAT
            17 => DxgiFormat::R32G32Uint,        // R32G32_UINT
            20 => DxgiFormat::D32FloatS8Uint,    // D32_FLOAT_S8X24_UINT
            24 => DxgiFormat::R10G10B10A2Unorm,  // R10G10B10A2_UNORM
            25 => DxgiFormat::R10G10B10A2Uint,   // R10G10B10A2_UINT
            26 => DxgiFormat::R11G11B10Float,    // R11G11B10_FLOAT
            28 => DxgiFormat::R8G8B8A8Unorm,     // R8G8B8A8_UNORM
            29 => DxgiFormat::R8G8B8A8UnormSrgb, // R8G8B8A8_UNORM_SRGB
            30 => DxgiFormat::R8G8B8A8Uint,      // R8G8B8A8_UINT
            34 => DxgiFormat::R16G16Float,       // R16G16_FLOAT
            35 => DxgiFormat::R16G16Unorm,       // R16G16_UNORM
            36 => DxgiFormat::R16G16Uint,        // R16G16_UINT
            37 => DxgiFormat::R16G16Snorm,       // R16G16_SNORM
            40 => DxgiFormat::D32Float,          // D32_FLOAT
            41 => DxgiFormat::R32Float,          // R32_FLOAT
            42 => DxgiFormat::R32Uint,           // R32_UINT
            43 => DxgiFormat::R32Sint,           // R32_SINT
            45 => DxgiFormat::D24UnormS8Uint,    // D24_UNORM_S8_UINT
            54 => DxgiFormat::R16Float,          // R16_FLOAT
            56 => DxgiFormat::R16Unorm,          // R16_UNORM
            57 => DxgiFormat::R16Uint,           // R16_UINT
            58 => DxgiFormat::R16Snorm,          // R16_SNORM
            61 => DxgiFormat::R8Unorm,           // R8_UNORM
            62 => DxgiFormat::R8Uint,            // R8_UINT
            71 => DxgiFormat::Bc1Unorm,          // BC1_UNORM
            72 => DxgiFormat::Bc1UnormSrgb,      // BC1_UNORM_SRGB
            74 => DxgiFormat::Bc2Unorm,          // BC2_UNORM
            75 => DxgiFormat::Bc2UnormSrgb,      // BC2_UNORM_SRGB
            77 => DxgiFormat::Bc3Unorm,          // BC3_UNORM
            78 => DxgiFormat::Bc3UnormSrgb,      // BC3_UNORM_SRGB
            80 => DxgiFormat::Bc4Unorm,          // BC4_UNORM
            83 => DxgiFormat::Bc5Unorm,          // BC5_UNORM
            85 => DxgiFormat::B5G6R5Unorm,       // B5G6R5_UNORM
            87 => DxgiFormat::B8G8R8A8Unorm,     // B8G8R8A8_UNORM
            88 => DxgiFormat::B8G8R8X8Unorm,     // B8G8R8X8_UNORM
            91 => DxgiFormat::B8G8R8A8UnormSrgb, // B8G8R8A8_UNORM_SRGB
            98 => DxgiFormat::Bc7Unorm,          // BC7_UNORM
            99 => DxgiFormat::Bc7UnormSrgb,      // BC7_UNORM_SRGB
            // No exact representation exists for any other value. This
            // includes every DXGI format that lacks a semantically exact
            // Casa1 representation (typeless, SINT/SNORM without a variant,
            // D16, A8, R1, shared-exponent, packed YUV, BC6H, palette,
            // video) — see translation_strategy() for the explicit plan.
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcGfxFormatUnsupported,
                    format!(
                        "DXGI_FORMAT value {value} has no exact representation \
                         (translation strategy: {:?})",
                        Self::translation_strategy(value)
                    ),
                ));
            }
        };
        Ok(format)
    }

    /// The explicit translation strategy for any raw `DXGI_FORMAT` value.
    ///
    /// Every known DXGI value (per `dxgiformat.h`) is assigned an explicit
    /// strategy; unknown values report [`FormatTranslation::Unsupported`].
    /// This is a complete truth table — nothing is silently substituted.
    pub fn translation_strategy(value: u32) -> FormatTranslation {
        use FormatTranslation::*;
        match value {
            // Exact identity (all values with a DxgiFormat variant).
            0 | 2 | 3 | 10 | 11 | 12 | 16 | 17 | 20 | 24 | 25 | 26 | 28 | 29 | 30 | 34 | 35
            | 36 | 37 | 40 | 41 | 42 | 43 | 45 | 54 | 56 | 57 | 58 | 61 | 62 | 71 | 72 | 74
            | 75 | 77 | 78 | 80 | 83 | 85 | 87 | 88 | 91 | 98 | 99 => Exact,
            // Typeless storage formats: bits are viewed as a typed variant.
            1 | 5 | 9 | 15 | 23 | 27 | 33 | 39 | 48 | 53 | 60 | 70 | 73 | 76 | 79 | 82 | 90
            | 92 | 97 => ViewReinterpret,
            // Depth-stencil storage and view-only halves (R32G8X24_TYPELESS,
            // R32_FLOAT_X8X24_TYPELESS, X32_TYPELESS_G8X24_UINT,
            // R24G8_TYPELESS, R24_UNORM_X8_TYPELESS, X24_TYPELESS_G8_UINT):
            // the depth/stencil bits are shared with D32_FLOAT_S8X24_UINT and
            // D24_UNORM_S8_UINT and are only reachable through views.
            19 | 21 | 22 | 44 | 46 | 47 => ViewReinterpret,
            // Channel-order rearrangement into bit-compatible packed formats
            // (B5G5R5A1_UNORM ↔ A1BGR5, B8G8R8X8_UNORM_SRGB ↔ BGRA8 sRGB,
            // B4G4R4A4_UNORM ↔ ABGR4).
            86 | 93 | 115 => Swizzle,
            // Formats with no Metal-native equivalent that require a shader
            // pass (shared-exponent, packed 8:8:8:8, extended-range 10:10:10,
            // YUV/video family).
            67 | 68 | 69 | 89 | 100..=110 | 130..=132 => ConversionShader,
            // Block-compressed formats with no Metal codec: must be
            // decompressed before the data is shader-visible.
            94..=96 => Decompression,
            // Depth/stencil emulation path (D16_UNORM and D32_FLOAT_S8X24_UINT
            // view patterns).
            55 => DepthStencilEmulation,
            // No translation path exists (R1_UNORM, palette/indexed and
            // sampler-feedback formats have no Metal equivalent; FORCE_UINT is
            // a sentinel, not a format).
            66 | 111..=114 | 133 | 134 | 0xFFFF_FFFF => Unsupported,
            // Unknown values: no strategy exists.
            _ => Unsupported,
        }
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
    /// Same interval as `frame_time_us` but at nanosecond resolution, so
    /// sub-microsecond frame times can be measured without truncation.
    pub frame_time_ns: u64,
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

/// D3D12_TEXTURE_ADDRESS_MODE per d3d12.h — the 0-based enumeration
/// `0=WRAP, 1=MIRROR, 2=CLAMP, 3=BORDER, 4=MIRROR_ONCE`. (The 1-based
/// family is D3D11's legacy SAMPLER_ADDRESS_MODE; D3D12 is 0-based.)
/// Values outside `0..=4` are undefined and a validation error on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D3D12TextureAddressMode {
    Wrap,
    Mirror,
    Clamp,
    Border,
    MirrorOnce,
}

impl D3D12TextureAddressMode {
    /// Decode a raw D3D12_TEXTURE_ADDRESS_MODE value; `None` for every
    /// value outside `0..=4` (undefined per d3d12.h — validation error).
    pub fn from_u32(mode: u32) -> Option<Self> {
        match mode {
            0 => Some(Self::Wrap),
            1 => Some(Self::Mirror),
            2 => Some(Self::Clamp),
            3 => Some(Self::Border),
            4 => Some(Self::MirrorOnce),
            _ => None,
        }
    }

    /// The D3D12 enum member name as d3d12.h defines it.
    pub fn d3d12_name(self) -> &'static str {
        match self {
            Self::Wrap => "WRAP",
            Self::Mirror => "MIRROR",
            Self::Clamp => "CLAMP",
            Self::Border => "BORDER",
            Self::MirrorOnce => "MIRROR_ONCE",
        }
    }

    /// The closest Metal address mode for each D3D12 mode. Metal has no
    /// `mirror_once` mode, so MIRROR_ONCE maps to `mirror_clamp_to_edge`.
    pub fn metal_name(self) -> &'static str {
        match self {
            Self::Wrap => "repeat",
            Self::Mirror => "mirror_repeat",
            Self::Clamp => "clamp_to_edge",
            Self::Border => "clamp_to_border",
            Self::MirrorOnce => "mirror_clamp_to_edge",
        }
    }
}

/// D3D12_FILTER_REDUCTION_TYPE per d3d12.h — the reduction field of
/// D3D12_FILTER (bits 7-8): `0=STANDARD, 1=COMPARISON, 2=MINIMUM, 3=MAXIMUM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D3D12FilterReduction {
    Standard,
    Comparison,
    Minimum,
    Maximum,
}

impl D3D12FilterReduction {
    /// Decode a raw D3D12_FILTER_REDUCTION_TYPE value; `None` for values
    /// outside `0..=3` (undefined per d3d12.h — validation error).
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Standard),
            1 => Some(Self::Comparison),
            2 => Some(Self::Minimum),
            3 => Some(Self::Maximum),
            _ => None,
        }
    }

    /// The D3D12 enum member name as d3d12.h defines it.
    pub fn d3d12_name(self) -> &'static str {
        match self {
            Self::Standard => "STANDARD",
            Self::Comparison => "COMPARISON",
            Self::Minimum => "MINIMUM",
            Self::Maximum => "MAXIMUM",
        }
    }

    /// The raw D3D12_FILTER_REDUCTION_TYPE value.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Standard => 0,
            Self::Comparison => 1,
            Self::Minimum => 2,
            Self::Maximum => 3,
        }
    }
}

/// The documented D3D12_FILTER bit layout (d3d12.h): mip filter bits 0-1,
/// mag filter bits 2-3, min filter bits 4-5, anisotropic bit 6, reduction
/// type bits 7-8. Ground truth from the named constants:
/// `D3D12_FILTER_MIN_MAG_POINT_MIP_LINEAR = 0x1` (mip at bits 0-1),
/// `D3D12_FILTER_MIN_POINT_MAG_LINEAR_MIP_POINT = 0x4` (mag at bits 2-3),
/// `D3D12_FILTER_MIN_LINEAR_MAG_MIP_POINT = 0x10` (min at bits 4-5),
/// `D3D12_FILTER_ANISOTROPIC = 0x55` (bit 6),
/// `D3D12_FILTER_COMPARISON_* = 0x80` / `MINIMUM_* = 0x100` /
/// `MAXIMUM_* = 0x180` (reduction at bits 7-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D3D12FilterBitLayout {
    pub mip_filter_bits: (u32, u32),
    pub mag_filter_bits: (u32, u32),
    pub min_filter_bits: (u32, u32),
    pub anisotropic_bit: u32,
    pub reduction_bits: (u32, u32),
}

/// The D3D12_FILTER bit layout as d3d12.h documents it.
pub const D3D12_FILTER_BIT_LAYOUT: D3D12FilterBitLayout = D3D12FilterBitLayout {
    mip_filter_bits: (0, 1),
    mag_filter_bits: (2, 3),
    min_filter_bits: (4, 5),
    anisotropic_bit: 6,
    reduction_bits: (7, 8),
};

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

/// Observability counters for command-stream translation optimisations.
///
/// Every field is updated by real work performed during translation or
/// execution of a command stream; nothing is estimated. The counters are
/// per-[`GraphicsBackend`] instance (not process-global) so concurrent tests
/// observe only their own work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationStats {
    /// Number of stream batches translated with more than one worker thread.
    pub parallel_translation_batches: u64,
    /// Number of streams translated concurrently inside a parallel batch.
    pub streams_translated_in_parallel: u64,
    /// Number of streams translated on the calling thread (dependent or lone).
    pub streams_translated_serially: u64,
    /// Number of commands (including nested bundle commands) translated.
    pub commands_translated: u64,
    /// Barrier/total accounting from hazard analysis.
    pub barriers_considered: u64,
    pub barriers_required: u64,
    pub barriers_elided: u64,
    pub transitions_required: u64,
    pub transitions_elided: u64,
    pub uav_barriers_required: u64,
    pub uav_barriers_elided: u64,
    pub aliasing_barriers_required: u64,
    pub aliasing_barriers_elided: u64,
    /// Resource updates written directly into host-visible storage.
    pub zero_copy_updates: u64,
    /// Resource updates that represent a staged (device-private) upload.
    pub staged_copies: u64,
    /// Batched descriptor-table translation calls.
    pub descriptor_table_batches: u64,
    /// Descriptor tables translated (cached entry missing or stale).
    pub descriptor_table_uploads: u64,
    /// Descriptor-table translations served from the cache unchanged.
    pub descriptor_table_reuses: u64,
}

/// Per-kind barrier-hazard accounting produced by analysing a command stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BarrierAnalysis {
    pub barriers_considered: u64,
    pub barriers_required: u64,
    pub barriers_elided: u64,
    pub transitions_considered: u64,
    pub transitions_required: u64,
    pub transitions_elided: u64,
    pub uav_barriers_considered: u64,
    pub uav_barriers_required: u64,
    pub uav_barriers_elided: u64,
    pub aliasing_barriers_considered: u64,
    pub aliasing_barriers_required: u64,
    pub aliasing_barriers_elided: u64,
    pub split_barriers_considered: u64,
    pub split_barriers_required: u64,
    pub split_barriers_elided: u64,
}

impl BarrierAnalysis {
    /// Fold this analysis into per-backend translation counters.
    pub fn merge_into(&self, stats: &mut TranslationStats) {
        stats.barriers_considered += self.barriers_considered;
        stats.barriers_required += self.barriers_required;
        stats.barriers_elided += self.barriers_elided;
        stats.transitions_required += self.transitions_required;
        stats.transitions_elided += self.transitions_elided;
        stats.uav_barriers_required += self.uav_barriers_required;
        stats.uav_barriers_elided += self.uav_barriers_elided;
        stats.aliasing_barriers_required += self.aliasing_barriers_required;
        stats.aliasing_barriers_elided += self.aliasing_barriers_elided;
    }
}

/// A barrier command resolved into the form the hazard analyser understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslatedBarrier {
    Transition {
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    },
    SplitBarrierBegin {
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    },
    SplitBarrierEnd {
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    },
    Uav {
        resource: ResourceId,
    },
    Aliasing {
        before: Option<ResourceId>,
        after: Option<ResourceId>,
    },
}

/// A [`Command`] translated into backend form with all lookups resolved.
///
/// Translation is a pure function of the command, the owning pipeline state,
/// and the referenced descriptor heaps; execution-side effects (byte copies,
/// plan updates) happen only when a translated command is applied. Splitting
/// the two phases is what makes independent streams translatable in parallel
/// while their effects are still applied in submission order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranslatedCommand {
    Barrier(TranslatedBarrier),
    SetRootConstants {
        values: Vec<u32>,
    },
    BeginRenderPass {
        color_formats: Vec<MtlPixelFormat>,
        depth_format: Option<MtlPixelFormat>,
        load_action: String,
        store_action: String,
    },
    /// A descriptor that failed view-kind validation; recorded as a plan
    /// validation error exactly like the serial path.
    ValidationError {
        message: String,
    },
    ClearRtv {
        resource: ResourceId,
        color_formats: Vec<MtlPixelFormat>,
        depth_format: Option<MtlPixelFormat>,
    },
    ClearDsv {
        resource: ResourceId,
        color_formats: Vec<MtlPixelFormat>,
        depth_format: MtlPixelFormat,
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
        src: ResourceId,
        src_x: u32,
        src_y: u32,
        width: u32,
        height: u32,
    },
    ResolveSubresource {
        dst: ResourceId,
        src: ResourceId,
        format: u32,
        resolve_mode: u32,
    },
    ExecuteBundle {
        commands: Vec<TranslatedCommand>,
    },
    DispatchRays {
        raygen_address: u64,
        miss_address: u64,
        hit_address: u64,
        callable_address: u64,
        width: u32,
        height: u32,
        depth: u32,
    },
}

impl TranslatedCommand {
    /// Number of source commands represented, counting nested bundle commands.
    pub fn source_command_count(&self) -> u64 {
        match self {
            TranslatedCommand::ExecuteBundle { commands } => {
                1 + commands
                    .iter()
                    .map(TranslatedCommand::source_command_count)
                    .sum::<u64>()
            }
            _ => 1,
        }
    }
}

/// A translated command stream plus the dependency analysis that grouped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedStream {
    pub id: CommandListId,
    pub commands: Vec<TranslatedCommand>,
    /// Earlier streams in the same submission that share a resource with this
    /// one, and therefore had to be translated before it.
    pub depends_on: Vec<usize>,
    /// Which translation batch this stream belonged to.
    pub batch_index: usize,
    /// True when the stream was translated on a worker thread.
    pub parallel: bool,
}

/// The path an update took into resource storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceUpdatePath {
    /// The resource storage is host-visible: the bytes were written in place
    /// and no staging copy/upload was created.
    HostVisibleInPlace,
    /// The resource is device-private: on real Metal the write would go
    /// through a staging buffer, so it is accounted as a staged upload.
    StagedUpload,
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
    /// Structural similarity against a reference frame.  `None` means no
    /// SSIM was measured — a fabricated placeholder metric is never
    /// recorded.
    pub ssim: Option<f32>,
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
    /// Monotonic revision bumped on every descriptor mutation; the
    /// translation cache reuses an entry only while its revision matches.
    revision: u64,
}

/// Cache of translated descriptor tables, keyed by heap and validated by the
/// heap's revision. Owned by [`GraphicsBackend`] behind a `RefCell` because
/// `translate_descriptor_heap` is an observation-only operation.
#[derive(Debug, Clone, Default)]
struct DescriptorTranslationCache {
    entries: BTreeMap<DescriptorHeapId, (u64, Vec<MetalBinding>)>,
}

#[derive(Debug, Clone)]
struct SwapchainRecord {
    state: SwapchainState,
    next_present_index: u64,
    presented_backbuffer_index: usize,
    /// True when this swapchain's backbuffers present as NV12 (two planes).
    nv12: bool,
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
#[allow(dead_code)] // command-list bundle flag for future bundle recording
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
    /// Mutex-wrapped because the callback is `FnMut` (not `Sync`) while
    /// `GraphicsBackend` must be `Sync`; presentation stays serialized on the
    /// owner thread.
    frame_published_callback: Option<std::sync::Mutex<Box<dyn FnMut(PresentedFrame) + Send>>>,
    /// API that presents through this backend; labels every `PresentedFrame`
    /// produced by [`presented_frame`](Self::presented_frame).
    frame_source: FrameSource,
    /// IOSurface-backed present channel shared with the D3D present path.
    /// When set, [`presented_frame`](Self::presented_frame) reads the same
    /// surface bytes the present path wrote instead of the shadow gfx resource,
    /// so live consumers observe zero-copy presents.
    presented_surface: Option<crate::metal_backend::IoSurfacePresentChannel>,
    /// NV12 present channel (two Metal planes) when the swapchain format is
    /// DXGI_FORMAT_NV12. Mutually exclusive with `presented_surface`.
    presented_nv12_surface: Option<crate::metal_backend::Nv12PresentChannel>,
    /// Presents that bound both NV12 planes.
    nv12_presents: u64,
    /// Window-supplied CAMetalLayer. When set, `present()` acquires a real
    /// drawable (`nextDrawable`) and presents into it instead of leaving the
    /// frame in the internal texture/CPU backing. Headless backends leave this
    /// `None`.
    present_layer: Option<metal::MetalLayer>,
    /// Attempts to acquire a drawable from `present_layer`.
    layer_present_attempts: u64,
    /// Drawables actually presented (`nextDrawable` returned a drawable and
    /// `presentDrawable:` was committed).
    layer_presents: u64,
    /// Per-instance observability counters for translation optimisations.
    /// Mutex (not RefCell) because `GraphicsBackend` is shared through
    /// `PeHostRuntime`, which is `Send + Sync`; translation can run from a
    /// producer thread while another thread observes the counters.
    translation_stats: std::sync::Mutex<TranslationStats>,
    /// Cache of translated descriptor tables (revision-validated).
    descriptor_translation_cache: std::sync::Mutex<DescriptorTranslationCache>,
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
            .field("presented_surface", &self.presented_surface)
            .field("presented_nv12_surface", &self.presented_nv12_surface)
            .field("nv12_presents", &self.nv12_presents)
            .field("present_layer", &self.present_layer.is_some())
            .field("layer_present_attempts", &self.layer_present_attempts)
            .field("layer_presents", &self.layer_presents)
            .field("translation_stats", &self.translation_stats)
            .field(
                "descriptor_translation_cache",
                &self.descriptor_translation_cache,
            )
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
            presented_surface: self.presented_surface.clone(),
            presented_nv12_surface: self.presented_nv12_surface.clone(),
            nv12_presents: self.nv12_presents,
            present_layer: self.present_layer.clone(),
            layer_present_attempts: self.layer_present_attempts,
            layer_presents: self.layer_presents,
            translation_stats: std::sync::Mutex::new(
                *self
                    .translation_stats
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            ),
            descriptor_translation_cache: std::sync::Mutex::new(
                self.descriptor_translation_cache
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone(),
            ),
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
    /// Barrier-hazard tracking across every stream of one execution.
    hazards: HazardTracker,
}

impl ExecutionPlanState {
    fn new() -> Self {
        Self {
            active_pass: None,
            render_passes: Vec::new(),
            compute_passes: 0,
            blit_passes: 0,
            raytrace_passes: 0,
            validation_errors: Vec::new(),
            root_constants_log: Vec::new(),
            hazards: HazardTracker::default(),
        }
    }
}

/// Tracks resource hazards across a command stream so provably redundant
/// barriers can be elided.
///
/// The rules are deliberately conservative: a barrier is elided only when its
/// effect is already established by an earlier barrier in the same execution
/// (or, for transitions, when the requested destination state is already the
/// tracked state). Any unknown access — draws and dispatches, whose bound
/// resources are not carried by the command — forces subsequent barriers to
/// remain required.
#[derive(Debug, Default)]
struct HazardTracker {
    /// Last state established for a subresource by a required transition.
    states: BTreeMap<SubresourceKey, ResourceState>,
    /// Resources synchronised by a required UAV/aliasing barrier.
    synchronized_resources: BTreeSet<ResourceId>,
    /// Subresources written since their last synchronising barrier.
    dirty: BTreeSet<SubresourceKey>,
    /// True when a draw/dispatch (whose accesses are unknown) happened since
    /// the last required barrier.
    gpu_work_since_barrier: bool,
    analysis: BarrierAnalysis,
}

impl HazardTracker {
    fn decide_barrier(&mut self, barrier: &TranslatedBarrier) -> bool {
        match barrier {
            TranslatedBarrier::Transition {
                resource,
                subresource,
                from,
                to,
            } => self.transition(*resource, *subresource, *from, *to),
            TranslatedBarrier::SplitBarrierBegin { .. }
            | TranslatedBarrier::SplitBarrierEnd { .. } => self.split(),
            TranslatedBarrier::Uav { resource } => self.uav(*resource),
            TranslatedBarrier::Aliasing { before, after } => self.aliasing(*before, *after),
        }
    }

    fn transition(
        &mut self,
        resource: ResourceId,
        subresource: u32,
        from: ResourceState,
        to: ResourceState,
    ) -> bool {
        self.analysis.barriers_considered += 1;
        self.analysis.transitions_considered += 1;
        let key = (resource, 0, subresource);
        let already_in_target_state = self.states.get(&key).copied() == Some(to);
        if from == to || already_in_target_state {
            // A redundant transition establishes nothing; seed the tracked
            // state when this is the first barrier seen for the subresource.
            self.states.entry(key).or_insert(to);
            self.analysis.barriers_elided += 1;
            self.analysis.transitions_elided += 1;
            false
        } else {
            self.states.insert(key, to);
            self.dirty.remove(&key);
            self.analysis.barriers_required += 1;
            self.analysis.transitions_required += 1;
            true
        }
    }

    fn uav(&mut self, resource: ResourceId) -> bool {
        self.analysis.barriers_considered += 1;
        self.analysis.uav_barriers_considered += 1;
        let has_dirty_writes = self.dirty.iter().any(|(dirty, _, _)| *dirty == resource);
        let already_synchronized = self.synchronized_resources.contains(&resource);
        // The first UAV barrier for a resource is always required: earlier
        // submissions may have written it, and that hazard is not visible
        // from this stream alone.
        let required = has_dirty_writes || self.gpu_work_since_barrier || !already_synchronized;
        if required {
            self.synchronized_resources.insert(resource);
            self.dirty.retain(|(dirty, _, _)| *dirty != resource);
            self.gpu_work_since_barrier = false;
            self.analysis.barriers_required += 1;
            self.analysis.uav_barriers_required += 1;
            true
        } else {
            self.analysis.barriers_elided += 1;
            self.analysis.uav_barriers_elided += 1;
            false
        }
    }

    fn aliasing(&mut self, before: Option<ResourceId>, after: Option<ResourceId>) -> bool {
        self.analysis.barriers_considered += 1;
        self.analysis.aliasing_barriers_considered += 1;
        let endpoint_ready = |tracker: &Self, endpoint: Option<ResourceId>| match endpoint {
            Some(resource) => {
                tracker.synchronized_resources.contains(&resource)
                    && !tracker.dirty.iter().any(|(dirty, _, _)| *dirty == resource)
            }
            // A missing endpoint (a full aliasing barrier) cannot be proven
            // redundant.
            None => false,
        };
        let required = self.gpu_work_since_barrier
            || !endpoint_ready(self, before)
            || !endpoint_ready(self, after);
        if required {
            for resource in [before, after].into_iter().flatten() {
                self.synchronized_resources.insert(resource);
                self.dirty.retain(|(dirty, _, _)| *dirty != resource);
            }
            self.gpu_work_since_barrier = false;
            self.analysis.barriers_required += 1;
            self.analysis.aliasing_barriers_required += 1;
            true
        } else {
            self.analysis.barriers_elided += 1;
            self.analysis.aliasing_barriers_elided += 1;
            false
        }
    }

    /// Split barriers are matched begin/end pairs whose scheduling semantics
    /// cannot be proven redundant from a single stream, so they stay required.
    fn split(&mut self) -> bool {
        self.analysis.barriers_considered += 1;
        self.analysis.split_barriers_considered += 1;
        self.analysis.barriers_required += 1;
        self.analysis.split_barriers_required += 1;
        self.gpu_work_since_barrier = false;
        true
    }

    fn record_write(&mut self, resource: ResourceId, subresource: u32) {
        self.dirty.insert((resource, 0, subresource));
    }

    fn record_gpu_work(&mut self) {
        self.gpu_work_since_barrier = true;
    }
}

/// Record the hazards a translated non-barrier command introduces.
///
/// Bundle commands are only recursed into when `recurse_bundles` is set: the
/// apply path observes nested commands itself as it applies them.
fn observe_translated_hazards(
    tracker: &mut HazardTracker,
    command: &TranslatedCommand,
    recurse_bundles: bool,
) {
    match command {
        TranslatedCommand::Barrier(_) => {}
        TranslatedCommand::ExecuteBundle { commands } => {
            if recurse_bundles {
                for nested in commands {
                    observe_translated_hazards(tracker, nested, true);
                }
            }
        }
        TranslatedCommand::ClearRtv { resource, .. }
        | TranslatedCommand::ClearDsv { resource, .. } => tracker.record_write(*resource, 0),
        TranslatedCommand::Draw { .. }
        | TranslatedCommand::DrawInstanced { .. }
        | TranslatedCommand::Dispatch { .. }
        | TranslatedCommand::DispatchMesh { .. }
        | TranslatedCommand::DispatchRays { .. } => tracker.record_gpu_work(),
        TranslatedCommand::CopyResource { dst, .. }
        | TranslatedCommand::CopyBufferRegion { dst, .. }
        | TranslatedCommand::CopyResourceRegion { dst, .. }
        | TranslatedCommand::ResolveSubresource { dst, .. } => tracker.record_write(*dst, 0),
        TranslatedCommand::SetRootConstants { .. } | TranslatedCommand::BeginRenderPass { .. } => {}
        TranslatedCommand::ValidationError { .. } => {}
    }
}

/// The read-only backend state command translation consults.
///
/// Cloning this snapshot (descriptor heaps, pipeline states, and the
/// command-list → pipeline mapping) produces a `Sync` value that scoped
/// worker threads can share, which is what makes independent-stream
/// translation genuinely concurrent without touching [`GraphicsBackend`].
#[derive(Debug, Clone, Default)]
struct TranslationSnapshot {
    descriptor_heaps: BTreeMap<DescriptorHeapId, DescriptorHeapRecord>,
    command_list_pipelines: BTreeMap<CommandListId, PipelineStateId>,
    pipeline_states: BTreeMap<PipelineStateId, PipelineStateDesc>,
}

impl TranslationSnapshot {
    fn from_backend(backend: &GraphicsBackend) -> Self {
        Self {
            descriptor_heaps: backend.descriptor_heaps.clone(),
            command_list_pipelines: backend
                .command_lists
                .iter()
                .map(|(id, record)| (*id, record.pipeline_state))
                .collect(),
            pipeline_states: backend.pipeline_states.clone(),
        }
    }

    fn pipeline_for_stream(&self, list: CommandListId) -> AppResult<PipelineStateDesc> {
        let pipeline_state = self.command_list_pipelines.get(&list).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown command list {list}"),
            )
        })?;
        self.pipeline_states
            .get(pipeline_state)
            .cloned()
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "unknown pipeline state"))
    }

    fn descriptor_at(&self, heap: DescriptorHeapId, index: usize) -> AppResult<ViewDescriptor> {
        self.descriptor_heaps
            .get(&heap)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("unknown descriptor heap {heap}"),
                )
            })?
            .descriptors
            .get(index)
            .and_then(Clone::clone)
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "descriptor slot is empty"))
    }

    fn translate_commands(
        &self,
        commands: &[Command],
        pipeline: &PipelineStateDesc,
    ) -> AppResult<Vec<TranslatedCommand>> {
        commands
            .iter()
            .map(|command| self.translate_command(command, pipeline))
            .collect()
    }

    fn translate_command(
        &self,
        command: &Command,
        pipeline: &PipelineStateDesc,
    ) -> AppResult<TranslatedCommand> {
        Ok(match command {
            Command::Transition {
                resource,
                subresource,
                from,
                to,
            } => TranslatedCommand::Barrier(TranslatedBarrier::Transition {
                resource: *resource,
                subresource: *subresource,
                from: *from,
                to: *to,
            }),
            Command::SplitBarrierBegin {
                resource,
                subresource,
                from,
                to,
            } => TranslatedCommand::Barrier(TranslatedBarrier::SplitBarrierBegin {
                resource: *resource,
                subresource: *subresource,
                from: *from,
                to: *to,
            }),
            Command::SplitBarrierEnd {
                resource,
                subresource,
                from,
                to,
            } => TranslatedCommand::Barrier(TranslatedBarrier::SplitBarrierEnd {
                resource: *resource,
                subresource: *subresource,
                from: *from,
                to: *to,
            }),
            Command::UavBarrier { resource } => {
                TranslatedCommand::Barrier(TranslatedBarrier::Uav {
                    resource: *resource,
                })
            }
            Command::AliasingBarrier { before, after } => {
                TranslatedCommand::Barrier(TranslatedBarrier::Aliasing {
                    before: *before,
                    after: *after,
                })
            }
            Command::SetRootConstants { values } => TranslatedCommand::SetRootConstants {
                values: values.clone(),
            },
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
                TranslatedCommand::BeginRenderPass {
                    color_formats: mapped_color_formats,
                    depth_format: mapped_depth_format,
                    load_action: load_action.clone(),
                    store_action: store_action.clone(),
                }
            }
            Command::ClearRtv { heap, index } => {
                let descriptor = self.descriptor_at(*heap, *index)?;
                let ViewDescriptor::Rtv { resource, format } = descriptor else {
                    return Ok(TranslatedCommand::ValidationError {
                        message: "invalid RTV attachment".to_string(),
                    });
                };
                let mapping = format_mapping(format)?;
                let depth_format = pipeline
                    .depth_format
                    .map(format_mapping)
                    .transpose()?
                    .map(|mapping| mapping.metal);
                TranslatedCommand::ClearRtv {
                    resource,
                    color_formats: vec![mapping.metal],
                    depth_format,
                }
            }
            Command::ClearDsv { heap, index } => {
                let descriptor = self.descriptor_at(*heap, *index)?;
                let ViewDescriptor::Dsv { resource, format } = descriptor else {
                    return Ok(TranslatedCommand::ValidationError {
                        message: "invalid DSV attachment".to_string(),
                    });
                };
                let mapping = format_mapping(format)?;
                let color_format = pipeline
                    .render_target_formats
                    .first()
                    .map(|format| format_mapping(*format))
                    .transpose()?
                    .map(|mapping| mapping.metal);
                let color_formats = color_format.map(|format| vec![format]).unwrap_or_default();
                TranslatedCommand::ClearDsv {
                    resource,
                    color_formats,
                    depth_format: mapping.metal,
                }
            }
            Command::Draw { vertices } => TranslatedCommand::Draw {
                vertices: *vertices,
            },
            Command::DrawInstanced {
                vertices,
                instances,
            } => TranslatedCommand::DrawInstanced {
                vertices: *vertices,
                instances: *instances,
            },
            Command::Dispatch { x, y, z } => TranslatedCommand::Dispatch {
                x: *x,
                y: *y,
                z: *z,
            },
            Command::DispatchMesh { x, y, z } => TranslatedCommand::DispatchMesh {
                x: *x,
                y: *y,
                z: *z,
            },
            Command::CopyResource { src, dst } => TranslatedCommand::CopyResource {
                src: *src,
                dst: *dst,
            },
            Command::CopyBufferRegion {
                dst,
                dst_offset,
                src,
                src_offset,
                size,
            } => TranslatedCommand::CopyBufferRegion {
                dst: *dst,
                dst_offset: *dst_offset,
                src: *src,
                src_offset: *src_offset,
                size: *size,
            },
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
            } => TranslatedCommand::CopyResourceRegion {
                dst: *dst,
                dst_x: *dst_x,
                dst_y: *dst_y,
                src: *src,
                src_x: *src_x,
                src_y: *src_y,
                width: *width,
                height: *height,
            },
            Command::ResolveSubresource {
                dst,
                src,
                format,
                resolve_mode,
            } => TranslatedCommand::ResolveSubresource {
                dst: *dst,
                src: *src,
                format: *format,
                resolve_mode: *resolve_mode,
            },
            Command::ExecuteBundle { bundle_commands } => TranslatedCommand::ExecuteBundle {
                commands: self.translate_commands(bundle_commands, pipeline)?,
            },
            Command::DispatchRays {
                raygen_address,
                miss_address,
                hit_address,
                callable_address,
                width,
                height,
                depth,
            } => TranslatedCommand::DispatchRays {
                raygen_address: *raygen_address,
                miss_address: *miss_address,
                hit_address: *hit_address,
                callable_address: *callable_address,
                width: *width,
                height: *height,
                depth: *depth,
            },
        })
    }
}

/// Resources a command stream touches, used to group independent streams.
#[derive(Debug, Clone, Default)]
struct StreamAccess {
    reads: BTreeSet<ResourceId>,
    writes: BTreeSet<ResourceId>,
}

impl StreamAccess {
    fn touches(&self, resource: ResourceId) -> bool {
        self.reads.contains(&resource) || self.writes.contains(&resource)
    }

    fn intersects(&self, other: &StreamAccess) -> bool {
        self.reads.iter().any(|resource| other.touches(*resource))
            || self.writes.iter().any(|resource| other.touches(*resource))
    }

    fn merge(&mut self, other: &StreamAccess) {
        self.reads.extend(other.reads.iter().copied());
        self.writes.extend(other.writes.iter().copied());
    }
}

fn record_command_access(
    snapshot: &TranslationSnapshot,
    command: &Command,
    access: &mut StreamAccess,
) {
    match command {
        Command::Transition { resource, .. }
        | Command::SplitBarrierBegin { resource, .. }
        | Command::SplitBarrierEnd { resource, .. }
        | Command::UavBarrier { resource } => {
            // Barriers order accesses: any other stream touching the resource
            // must be translated after this one.
            access.reads.insert(*resource);
            access.writes.insert(*resource);
        }
        Command::AliasingBarrier { before, after } => {
            for resource in [before, after].into_iter().flatten() {
                access.reads.insert(*resource);
                access.writes.insert(*resource);
            }
        }
        Command::ClearRtv { heap, index } => {
            if let Ok(ViewDescriptor::Rtv { resource, .. }) = snapshot.descriptor_at(*heap, *index)
            {
                access.writes.insert(resource);
            }
        }
        Command::ClearDsv { heap, index } => {
            if let Ok(ViewDescriptor::Dsv { resource, .. }) = snapshot.descriptor_at(*heap, *index)
            {
                access.writes.insert(resource);
            }
        }
        Command::CopyResource { src, dst }
        | Command::CopyBufferRegion { src, dst, .. }
        | Command::CopyResourceRegion { src, dst, .. }
        | Command::ResolveSubresource { src, dst, .. } => {
            access.reads.insert(*src);
            access.writes.insert(*dst);
        }
        Command::ExecuteBundle { bundle_commands } => {
            for nested in bundle_commands {
                record_command_access(snapshot, nested, access);
            }
        }
        Command::SetRootConstants { .. }
        | Command::BeginRenderPass { .. }
        | Command::Draw { .. }
        | Command::DrawInstanced { .. }
        | Command::Dispatch { .. }
        | Command::DispatchMesh { .. }
        | Command::DispatchRays { .. } => {}
    }
}

fn stream_access(snapshot: &TranslationSnapshot, commands: &[Command]) -> StreamAccess {
    let mut access = StreamAccess::default();
    for command in commands {
        record_command_access(snapshot, command, &mut access);
    }
    access
}

/// Group streams into batches of mutually independent work. A stream joins the
/// current batch only when it shares no resource with any stream already in
/// that batch; conflicting streams start a new batch, which is translated
/// after the earlier ones (order preservation for dependent commands).
fn batch_streams(accesses: &[StreamAccess]) -> Vec<Vec<usize>> {
    let mut batches: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    let mut current_access = StreamAccess::default();
    for (index, access) in accesses.iter().enumerate() {
        if current.is_empty() || !access.intersects(&current_access) {
            current.push(index);
            current_access.merge(access);
        } else {
            batches.push(std::mem::take(&mut current));
            current_access = access.clone();
            current.push(index);
        }
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
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
            presented_surface: None,
            presented_nv12_surface: None,
            nv12_presents: 0,
            present_layer: None,
            layer_present_attempts: 0,
            layer_presents: 0,
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
            translation_stats: std::sync::Mutex::new(TranslationStats::default()),
            descriptor_translation_cache: std::sync::Mutex::new(
                DescriptorTranslationCache::default(),
            ),
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
                nv12: false,
                last_present_at: None,
            },
        );
        Ok(id)
    }

    /// Create a swapchain whose backbuffers present as NV12 (DXGI_FORMAT_NV12,
    /// raw value 103). The backend resource shadows stay RGBA for the guest
    /// API, while the host present channel is an NV12 IOSurface with separate
    /// luma and interleaved chroma Metal planes.
    pub fn create_nv12_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        if desc.width == 0 || desc.height == 0 || desc.width % 2 != 0 || desc.height % 2 != 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "NV12 swapchain dimensions {}x{} must be non-zero and even",
                    desc.width, desc.height
                ),
            ));
        }
        let id = self.create_swapchain(desc)?;
        if let Some(record) = self.swapchains.get_mut(&id) {
            record.nv12 = true;
        }
        Ok(id)
    }

    /// True when `swapchain` presents an NV12 (two-plane) surface.
    pub fn swapchain_is_nv12(&self, swapchain: SwapchainId) -> AppResult<bool> {
        Ok(self.swapchain(swapchain)?.nv12)
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

        // Measure real frame timing: `frame_time_us`/`frame_time_ns` are the
        // elapsed wall-clock times since the previous present on this
        // swapchain (0 on the first).  The nanosecond value is kept so
        // sub-microsecond intervals can be distinguished from "not measured".
        let present_started_at = std::time::Instant::now();
        let (frame_time_us, frame_time_ns) = {
            let record = self.swapchain_mut(swapchain)?;
            let elapsed_us = record.last_present_at.map(|previous| {
                present_started_at
                    .duration_since(previous)
                    .as_micros()
                    .min(u64::MAX as u128) as u64
            });
            let elapsed_ns = record.last_present_at.map(|previous| {
                present_started_at
                    .duration_since(previous)
                    .as_nanos()
                    .min(u64::MAX as u128) as u64
            });
            record.last_present_at = Some(present_started_at);
            (elapsed_us.unwrap_or(0), elapsed_ns.unwrap_or(0))
        };

        // Window-integrated present: when the host supplied a CAMetalLayer,
        // present the current surface/frame into a real drawable
        // (`nextDrawable` + `presentDrawable:`) instead of leaving it in the
        // internal RGBA8 texture. Headless backends have no layer and keep the
        // internal path.
        let layer = self.present_layer.clone();
        if let Some(layer) = layer {
            self.layer_present_attempts += 1;
            let mut presented = false;
            let nv12 = self.presented_nv12_surface.clone();
            if let Some(channel) = nv12.as_ref() {
                presented = channel.present_to_layer(&layer)?;
            } else if let Some(channel) = self.presented_surface.as_mut() {
                let texture = channel.metal_texture()?;
                presented = crate::metal_backend::present_texture_to_layer(texture, &layer)?;
            } else {
                let (width, height, resource) = {
                    let record = self.swapchain(swapchain)?;
                    (
                        record.state.desc.width,
                        record.state.desc.height,
                        record.state.backbuffers.first().copied(),
                    )
                };
                if let Some(bytes) = resource
                    .and_then(|resource| self.resources.get(&resource))
                    .map(|record| record.bytes.clone())
                {
                    presented = crate::metal_backend::present_bytes_to_layer(
                        &bytes, width, height, &layer,
                    )?;
                }
            }
            if presented {
                self.layer_presents += 1;
            }
        }

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
        let nv12_bound = self.presented_nv12_surface.is_some();
        if nv12_bound {
            self.nv12_presents += 1;
        }
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
        if let (Some(callback), Some(presented)) =
            (self.frame_published_callback.as_ref(), presented_frame)
        {
            let mut callback = callback
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            callback(presented);
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
            frame_time_ns,
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

    /// Share the IOSurface-backed present channel with this backend.
    ///
    /// D3D devices call this on every present so the live-preview callback
    /// (and [`presented_frame`](Self::presented_frame)) consumes the exact
    /// surface the present path wrote, with no intermediate host copy.
    pub fn set_presented_surface(
        &mut self,
        surface: Option<crate::metal_backend::IoSurfacePresentChannel>,
    ) {
        if surface.is_some() {
            self.presented_nv12_surface = None;
        }
        self.presented_surface = surface;
    }

    /// Attach the NV12 present channel (two Metal planes). Clears any pixel
    /// present channel: a swapchain presents through exactly one channel.
    pub fn set_presented_nv12_surface(
        &mut self,
        surface: Option<crate::metal_backend::Nv12PresentChannel>,
    ) {
        if surface.is_some() {
            self.presented_surface = None;
        }
        self.presented_nv12_surface = surface;
    }

    /// Attach the window-supplied CAMetalLayer used for real drawable
    /// presents. Passing `None` returns to the headless/internal path. Window
    /// integration owns attaching the layer to an NSWindow/NSView (see
    /// `mac_window::attach_cametal_layer_to_window`) and calls this afterwards.
    pub fn set_present_layer(&mut self, layer: Option<metal::MetalLayer>) {
        if let Some(layer) = &layer {
            layer.set_framebuffer_only(false);
        }
        self.present_layer = layer;
    }

    /// Borrow the attached CAMetalLayer, when present.
    pub fn present_layer(&self) -> Option<&metal::MetalLayer> {
        self.present_layer.as_ref()
    }

    /// Number of `present()` calls that attempted `nextDrawable`.
    pub fn layer_present_attempts(&self) -> u64 {
        self.layer_present_attempts
    }

    /// Number of presents that acquired a drawable and committed
    /// `presentDrawable:`. `0` with non-zero attempts means the layer could not
    /// hand out a drawable (typically not attached to a window/view).
    pub fn layer_present_count(&self) -> u64 {
        self.layer_presents
    }

    /// Borrowed NV12 surface backing the last present, when attached.
    pub fn presented_nv12_surface(&self) -> Option<&crate::metal_backend::Nv12PresentChannel> {
        self.presented_nv12_surface.as_ref()
    }

    /// Raw handle of the NV12 IOSurface, when one is attached.
    pub fn presented_nv12_surface_handle(&self) -> Option<*mut std::ffi::c_void> {
        self.presented_nv12_surface
            .as_ref()
            .map(|surface| surface.surface_ptr())
    }

    /// Pointers of the two plane textures bound by the last NV12 present.
    pub fn presented_nv12_plane_ptrs(&self) -> Option<(usize, usize)> {
        self.presented_nv12_surface
            .as_ref()
            .map(|surface| surface.plane_texture_ptrs())
    }

    /// Presents that bound both NV12 planes.
    pub fn nv12_present_count(&self) -> u64 {
        self.nv12_presents
    }

    /// Raw handle of the shared present IOSurface, when one is attached.
    /// Tests use this to prove the consumer and present path alias the same
    /// storage.
    pub fn presented_surface_handle(&self) -> Option<*mut std::ffi::c_void> {
        self.presented_surface
            .as_ref()
            .map(|surface| surface.surface_ptr())
    }

    pub fn presented_frame(&self, swapchain: SwapchainId) -> AppResult<PresentedFrame> {
        let record = self.swapchain(swapchain)?;
        if let Some(surface) = &self.presented_nv12_surface {
            // Consumers speak RGBA; the plane bytes stay queryable through
            // `presented_nv12_plane_bytes` without a conversion.
            let bytes = surface.to_rgba8()?;
            return Ok(PresentedFrame {
                width: surface.width(),
                height: surface.height(),
                format: DxgiFormat::R8G8B8A8Unorm,
                stride: surface.width() as usize * 4,
                bytes,
                source: self.frame_source,
                sequence: record.next_present_index,
                timestamp: std::time::Instant::now(),
            });
        }
        if let Some(surface) = &self.presented_surface {
            return Ok(PresentedFrame {
                width: surface.width(),
                height: surface.height(),
                format: record.state.desc.format,
                bytes: surface.read_pixels()?,
                source: self.frame_source,
                stride: surface.width() as usize * 4,
                sequence: record.next_present_index,
                timestamp: std::time::Instant::now(),
            });
        }
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

    /// Read both NV12 planes of the attached present surface (Y, UV). Used by
    /// verification code; returns an error when no NV12 channel is attached.
    pub fn presented_nv12_plane_bytes(&self) -> AppResult<(Vec<u8>, Vec<u8>)> {
        let surface = self.presented_nv12_surface.as_ref().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "no NV12 present surface is attached",
            )
        })?;
        Ok((surface.read_plane(0)?, surface.read_plane(1)?))
    }

    /// Consumer API for live preview/window callbacks: RGBA8 bytes of the
    /// presented frame. On the IOSurface path this reads the shared surface
    /// directly (no staging avatar) and converts only when the surface is BGRA.
    pub fn presented_frame_rgba(&self, swapchain: SwapchainId) -> AppResult<Vec<u8>> {
        let frame = self.presented_frame(swapchain)?;
        let mut bytes = frame.bytes;
        if matches!(
            frame.format,
            DxgiFormat::B8G8R8A8Unorm | DxgiFormat::B8G8R8A8UnormSrgb | DxgiFormat::B8G8R8X8Unorm
        ) {
            for pixel in bytes.chunks_exact_mut(4) {
                pixel.swap(0, 2);
            }
        }
        Ok(bytes)
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
        let nv12 = self.swapchain(swapchain)?.nv12;
        if nv12 && (width == 0 || height == 0 || width % 2 != 0 || height % 2 != 0) {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("NV12 swapchain resize dimensions {width}x{height} must be even"),
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
        self.frame_published_callback = callback.map(std::sync::Mutex::new);
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
        let record = self.swapchains.remove(&swapchain).ok_or_else(|| {
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
        self.descriptor_heaps.remove(&heap).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3dInvalidState, "unknown descriptor heap")
        })?;
        self.descriptor_translation_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .remove(&heap);
        Ok(())
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

    /// Real format recorded in the resource descriptor (format authority for
    /// DirectStorage uploads).
    pub fn resource_format(&self, resource: ResourceId) -> AppResult<DxgiFormat> {
        Ok(self.resource(resource)?.desc.format)
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
                revision: 0,
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
        heap_record.revision = heap_record.revision.wrapping_add(1);
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
        destination.revision = destination.revision.wrapping_add(1);
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

    /// Translate a descriptor heap into Metal bindings.
    ///
    /// The translation is cached by the heap's descriptor revision: a second
    /// call for an unchanged heap reuses the cached bindings (`descriptor_table_reuses`
    /// counter), while any `write_descriptor`/`copy_descriptors` bump in the
    /// heap's revision forces a fresh translation (`descriptor_table_uploads`).
    pub fn translate_descriptor_heap(
        &self,
        heap: DescriptorHeapId,
    ) -> AppResult<Vec<MetalBinding>> {
        let heap_record = self.descriptor_heap(heap)?;
        let revision = heap_record.revision;
        let cached = self
            .descriptor_translation_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(&heap)
            .cloned();
        if let Some((cached_revision, bindings)) = cached
            && cached_revision == revision
        {
            self.translation_stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .descriptor_table_reuses += 1;
            return Ok(bindings);
        }
        let bindings = heap_record
            .descriptors
            .iter()
            .enumerate()
            .filter_map(|(slot, descriptor)| {
                descriptor
                    .as_ref()
                    .map(|descriptor| metal_binding(slot as u32, descriptor))
            })
            .collect::<Vec<_>>();
        self.descriptor_translation_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .insert(heap, (revision, bindings.clone()));
        self.translation_stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .descriptor_table_uploads += 1;
        Ok(bindings)
    }

    /// Batched descriptor-table translation for the D3D12 descriptor-heap
    /// path: every requested table is translated in one call, and tables whose
    /// descriptors did not change are served from the revision cache instead
    /// of being re-uploaded.
    pub fn translate_descriptor_tables(
        &self,
        heaps: &[DescriptorHeapId],
    ) -> AppResult<Vec<Vec<MetalBinding>>> {
        self.translation_stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .descriptor_table_batches += 1;
        heaps
            .iter()
            .map(|&heap| self.translate_descriptor_heap(heap))
            .collect()
    }

    /// Snapshot of this backend's translation counters.
    pub fn translation_stats(&self) -> TranslationStats {
        *self
            .translation_stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Reset the translation counters (useful for per-frame measurements).
    pub fn reset_translation_stats(&mut self) {
        *self
            .translation_stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = TranslationStats::default();
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

    /// Apply a translated command, driving the render-pass / compute-pass /
    /// blit-pass planning state machine and executing its CPU-side effects.
    ///
    /// This is the single execution path shared by the serial and parallel
    /// execution methods, which is what guarantees the two produce identical
    /// plans and byte-level results.
    fn apply_translated_command(
        &mut self,
        command: &TranslatedCommand,
        plan: &mut ExecutionPlanState,
    ) -> AppResult<()> {
        if !matches!(command, TranslatedCommand::Barrier(_)) {
            observe_translated_hazards(&mut plan.hazards, command, false);
        }
        match command {
            TranslatedCommand::Barrier(barrier) => {
                // A barrier the hazard analysis proves redundant must not split
                // the active render pass: that is the real elision this path
                // performs. Required barriers keep the submission boundary.
                if plan.hazards.decide_barrier(barrier) {
                    if let Some(pass) = plan.active_pass.take() {
                        plan.render_passes.push(pass);
                    }
                }
            }
            TranslatedCommand::ValidationError { message } => {
                plan.validation_errors.push(message.clone());
            }
            TranslatedCommand::SetRootConstants { values } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.root_constants_log.push(values.clone());
            }
            TranslatedCommand::BeginRenderPass {
                color_formats,
                depth_format,
                load_action,
                store_action,
            } => match &mut plan.active_pass {
                Some(pass)
                    if self.capabilities.mesh_shaders
                        && pass.can_merge_with(color_formats, *depth_format, load_action) =>
                {
                    pass.merge_store_action(store_action);
                }
                Some(_) => {
                    plan.render_passes
                        .push(plan.active_pass.take().expect("active pass"));
                    plan.active_pass = Some(RenderPassPlan {
                        color_formats: color_formats.clone(),
                        depth_format: *depth_format,
                        draw_calls: 0,
                        load_action: load_action.clone(),
                        store_action: store_action.clone(),
                    });
                }
                None => {
                    plan.active_pass = Some(RenderPassPlan {
                        color_formats: color_formats.clone(),
                        depth_format: *depth_format,
                        draw_calls: 0,
                        load_action: load_action.clone(),
                        store_action: store_action.clone(),
                    });
                }
            },
            TranslatedCommand::ClearRtv {
                color_formats,
                depth_format,
                ..
            } => match &mut plan.active_pass {
                Some(pass) => {
                    if pass.color_formats != *color_formats || pass.depth_format != *depth_format {
                        plan.render_passes
                            .push(plan.active_pass.take().expect("active pass"));
                        plan.active_pass = Some(RenderPassPlan {
                            color_formats: color_formats.clone(),
                            depth_format: *depth_format,
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
                        color_formats: color_formats.clone(),
                        depth_format: *depth_format,
                        draw_calls: 0,
                        load_action: "clear".to_string(),
                        store_action: "store".to_string(),
                    });
                }
            },
            TranslatedCommand::ClearDsv {
                color_formats,
                depth_format,
                ..
            } => match &mut plan.active_pass {
                Some(pass)
                    if pass.depth_format == Some(*depth_format)
                        && pass.color_formats == *color_formats =>
                {
                    pass.load_action = "clear".to_string();
                }
                Some(_) => {
                    plan.render_passes
                        .push(plan.active_pass.take().expect("active pass"));
                    plan.active_pass = Some(RenderPassPlan {
                        color_formats: color_formats.clone(),
                        depth_format: Some(*depth_format),
                        draw_calls: 0,
                        load_action: "clear".to_string(),
                        store_action: "store".to_string(),
                    });
                }
                None => {
                    plan.active_pass = Some(RenderPassPlan {
                        color_formats: color_formats.clone(),
                        depth_format: Some(*depth_format),
                        draw_calls: 0,
                        load_action: "clear".to_string(),
                        store_action: "store".to_string(),
                    });
                }
            },
            TranslatedCommand::Draw { .. } | TranslatedCommand::DrawInstanced { .. } => {
                if let Some(pass) = &mut plan.active_pass {
                    pass.draw_calls += 1;
                } else {
                    plan.validation_errors
                        .push("draw without active render pass".to_string());
                }
            }
            TranslatedCommand::Dispatch { .. } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.compute_passes += 1;
            }
            TranslatedCommand::DispatchMesh { .. } => {
                // Mesh shader dispatches require an active render pass
                // (they generate geometry for rasterization).
                if let Some(pass) = &mut plan.active_pass {
                    pass.draw_calls += 1;
                } else {
                    plan.validation_errors
                        .push("dispatch mesh without active render pass".to_string());
                }
            }
            TranslatedCommand::CopyResource { src, dst } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.blit_passes += 1;
                self.copy_resource_bytes(*src, *dst)?;
            }
            TranslatedCommand::CopyBufferRegion {
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
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "copy source offset out of range",
                    )
                })?;
                let dst_start = usize::try_from(*dst_offset).map_err(|_| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "copy dest offset out of range",
                    )
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
                dst_bytes.bytes[dst_start..dst_end].copy_from_slice(&src_bytes[src_start..src_end]);
            }
            TranslatedCommand::CopyResourceRegion {
                dst,
                dst_x,
                dst_y,
                src,
                src_x,
                src_y,
                width,
                height,
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
                let src_stride = (*width as usize).checked_mul(bpp).ok_or_else(|| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy width overflow")
                })?;
                let dst_stride = (*width as usize).checked_mul(bpp).ok_or_else(|| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy width overflow")
                })?;
                let src_x_off = (*src_x as usize).checked_mul(bpp).ok_or_else(|| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy src_x overflow")
                })?;
                let dst_x_off = (*dst_x as usize).checked_mul(bpp).ok_or_else(|| {
                    AppError::new(ReasonCode::RcD3dInvalidState, "copy dst_x overflow")
                })?;
                let src_row_base = (*src_y as usize)
                    .checked_mul(src_stride)
                    .and_then(|v| v.checked_add(src_x_off))
                    .ok_or_else(|| {
                        AppError::new(ReasonCode::RcD3dInvalidState, "copy source offset overflow")
                    })?;
                let dst_row_base = (*dst_y as usize)
                    .checked_mul(dst_stride)
                    .and_then(|v| v.checked_add(dst_x_off))
                    .ok_or_else(|| {
                        AppError::new(ReasonCode::RcD3dInvalidState, "copy dest offset overflow")
                    })?;
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
            TranslatedCommand::ResolveSubresource { dst, src, .. } => {
                if let Some(pass) = plan.active_pass.take() {
                    plan.render_passes.push(pass);
                }
                plan.blit_passes += 1;
                self.copy_resource_bytes(*src, *dst)?;
            }
            TranslatedCommand::ExecuteBundle { commands } => {
                // Recursively apply each command in the bundle. Bundle
                // commands inherit the parent list's pipeline state and
                // render-pass context — they execute as if inlined.
                for command in commands {
                    self.apply_translated_command(command, plan)?;
                }
            }
            TranslatedCommand::DispatchRays { .. } => {
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

    fn finish_execution_plan(
        &mut self,
        mut plan: ExecutionPlanState,
        signal_fence: Option<(FenceId, u64)>,
    ) -> AppResult<MetalCommandBufferPlan> {
        if let Some(pass) = plan.active_pass.take() {
            plan.render_passes.push(pass);
        }
        let analysis = plan.hazards.analysis;
        analysis.merge_into(
            &mut *self
                .translation_stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );

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

    /// Translate a set of command streams serially. This is the reference
    /// translation used to prove that parallel translation is byte-identical.
    pub fn translate_command_streams(
        &self,
        lists: &[ImmutableCommandStream],
    ) -> AppResult<Vec<TranslatedStream>> {
        let snapshot = TranslationSnapshot::from_backend(self);
        let accesses = lists
            .iter()
            .map(|stream| stream_access(&snapshot, &stream.commands))
            .collect::<Vec<_>>();
        let mut streams = Vec::with_capacity(lists.len());
        for (index, stream) in lists.iter().enumerate() {
            let pipeline = snapshot.pipeline_for_stream(stream.id)?;
            let depends_on = (0..index)
                .filter(|&other| accesses[index].intersects(&accesses[other]))
                .collect();
            streams.push(TranslatedStream {
                id: stream.id,
                commands: snapshot.translate_commands(&stream.commands, &pipeline)?,
                depends_on,
                batch_index: index,
                parallel: false,
            });
        }
        Ok(streams)
    }

    /// Translate command streams concurrently where the hazard analysis proves
    /// them independent.
    ///
    /// Streams are grouped into batches: a stream joins the current batch only
    /// when it shares no resource with any stream already in that batch.
    /// Batches are translated in submission order, so a stream that depends on
    /// an earlier one is translated after it (and, if it is the only stream in
    /// its batch, on the calling thread) — dependent commands keep their order.
    /// Every stream's effects are still applied later in submission order.
    pub fn translate_streams_parallel(
        &self,
        lists: &[ImmutableCommandStream],
    ) -> AppResult<Vec<TranslatedStream>> {
        let snapshot = TranslationSnapshot::from_backend(self);
        let mut pipelines = Vec::with_capacity(lists.len());
        let mut accesses = Vec::with_capacity(lists.len());
        for stream in lists {
            pipelines.push(snapshot.pipeline_for_stream(stream.id)?);
            accesses.push(stream_access(&snapshot, &stream.commands));
        }
        let batches = batch_streams(&accesses);
        let mut translated: Vec<Option<Vec<TranslatedCommand>>> = vec![None; lists.len()];
        let mut depends_on: Vec<Vec<usize>> = vec![Vec::new(); lists.len()];
        let mut batch_indexes = vec![0usize; lists.len()];
        let mut parallel_flags = vec![false; lists.len()];

        for (batch_index, batch) in batches.iter().enumerate() {
            for &stream_index in batch {
                depends_on[stream_index] = (0..stream_index)
                    .filter(|&other| accesses[stream_index].intersects(&accesses[other]))
                    .collect();
                batch_indexes[stream_index] = batch_index;
            }
            if batch.len() == 1 {
                let stream_index = batch[0];
                translated[stream_index] =
                    Some(snapshot.translate_commands(
                        &lists[stream_index].commands,
                        &pipelines[stream_index],
                    )?);
                continue;
            }
            for &stream_index in batch {
                parallel_flags[stream_index] = true;
            }
            std::thread::scope(|scope| -> AppResult<()> {
                let handles = batch
                    .iter()
                    .map(|&stream_index| {
                        let snapshot = &snapshot;
                        let commands = &lists[stream_index].commands;
                        let pipeline = &pipelines[stream_index];
                        scope.spawn(move || snapshot.translate_commands(commands, pipeline))
                    })
                    .collect::<Vec<_>>();
                let mut results = Vec::with_capacity(handles.len());
                for handle in handles {
                    let commands = handle.join().map_err(|_| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "parallel command translation thread panicked",
                        )
                    })??;
                    results.push(commands);
                }
                for (&stream_index, commands) in batch.iter().zip(results) {
                    translated[stream_index] = Some(commands);
                }
                Ok(())
            })?;
        }

        let mut streams = Vec::with_capacity(lists.len());
        {
            let mut stats = self
                .translation_stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            stats.parallel_translation_batches +=
                batches.iter().filter(|batch| batch.len() > 1).count() as u64;
            for (index, stream) in lists.iter().enumerate() {
                let commands = translated[index].take().expect("translated stream");
                if parallel_flags[index] {
                    stats.streams_translated_in_parallel += 1;
                } else {
                    stats.streams_translated_serially += 1;
                }
                stats.commands_translated += commands
                    .iter()
                    .map(TranslatedCommand::source_command_count)
                    .sum::<u64>();
                streams.push(TranslatedStream {
                    id: stream.id,
                    depends_on: std::mem::take(&mut depends_on[index]),
                    commands,
                    batch_index: batch_indexes[index],
                    parallel: parallel_flags[index],
                });
            }
        }
        Ok(streams)
    }

    /// Analyse barrier hazards over command streams without executing them.
    ///
    /// Returns the required/elided barrier accounting; the same analysis runs
    /// during execution and feeds [`translation_stats`](Self::translation_stats).
    pub fn analyze_barriers(&self, lists: &[ImmutableCommandStream]) -> AppResult<BarrierAnalysis> {
        let snapshot = TranslationSnapshot::from_backend(self);
        let mut tracker = HazardTracker::default();
        for stream in lists {
            let pipeline = snapshot.pipeline_for_stream(stream.id)?;
            for command in snapshot.translate_commands(&stream.commands, &pipeline)? {
                match &command {
                    TranslatedCommand::Barrier(barrier) => {
                        tracker.decide_barrier(barrier);
                    }
                    other => observe_translated_hazards(&mut tracker, other, true),
                }
            }
        }
        Ok(tracker.analysis)
    }

    pub fn execute_command_lists(
        &mut self,
        _queue: CommandQueueId,
        lists: &[ImmutableCommandStream],
        signal_fence: Option<(FenceId, u64)>,
    ) -> AppResult<MetalCommandBufferPlan> {
        let snapshot = TranslationSnapshot::from_backend(self);
        let mut plan = ExecutionPlanState::new();

        for stream in lists {
            let pipeline = snapshot.pipeline_for_stream(stream.id)?;
            for command in &stream.commands {
                let translated = snapshot.translate_command(command, &pipeline)?;
                self.translation_stats
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .commands_translated += translated.source_command_count();
                self.apply_translated_command(&translated, &mut plan)?;
            }
        }
        self.finish_execution_plan(plan, signal_fence)
    }

    /// Execute command streams using parallel translation for independent
    /// streams. The translated commands are applied in submission order by the
    /// same code path as [`execute_command_lists`](Self::execute_command_lists),
    /// so the resulting plan and resource contents are identical.
    pub fn execute_command_lists_parallel(
        &mut self,
        _queue: CommandQueueId,
        lists: &[ImmutableCommandStream],
        signal_fence: Option<(FenceId, u64)>,
    ) -> AppResult<MetalCommandBufferPlan> {
        let streams = self.translate_streams_parallel(lists)?;
        let mut plan = ExecutionPlanState::new();
        for stream in &streams {
            for command in &stream.commands {
                self.apply_translated_command(command, &mut plan)?;
            }
        }
        self.finish_execution_plan(plan, signal_fence)
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
        self.record_update_path(ResourceUpdatePath::HostVisibleInPlace);
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

    /// Borrow a resource's host-visible bytes without cloning, for zero-copy
    /// consumers such as an IOSurface present channel.
    pub fn resource_bytes(&self, resource: ResourceId) -> AppResult<&[u8]> {
        Ok(self.resource(resource)?.bytes.as_slice())
    }

    /// Overwrite a resource from bytes whose storage is already owned by the
    /// caller.
    ///
    /// When the incoming buffer is exactly the resource size it is *moved*
    /// into the resource record — no element is copied — which is the
    /// zero-copy path for updates whose host-visible pixels/mapped memory
    /// already exist. The returned [`ResourceUpdatePath`] records whether the
    /// destination is host-visible (no staging required on a real device) or
    /// device-private (a staged upload) and the per-instance counters are
    /// updated accordingly.
    pub fn overwrite_resource_bytes_owned(
        &mut self,
        resource: ResourceId,
        bytes: Vec<u8>,
    ) -> AppResult<ResourceUpdatePath> {
        let record = self.resource_mut(resource)?;
        if record.storage_mode == MetalStorageMode::Memoryless {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "memoryless resource cannot be updated from the CPU",
            ));
        }
        if bytes.len() > record.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource write out of bounds",
            ));
        }
        let path = if record.storage_mode == MetalStorageMode::Shared {
            ResourceUpdatePath::HostVisibleInPlace
        } else {
            ResourceUpdatePath::StagedUpload
        };
        if bytes.len() == record.bytes.len() {
            record.bytes = bytes;
        } else {
            record.bytes[..bytes.len()].copy_from_slice(&bytes);
        }
        self.record_update_path(path);
        Ok(path)
    }

    /// Write a region of a resource, classifying the update path by the
    /// resource's storage mode.
    ///
    /// A `Shared` resource is host-visible on Metal: the bytes are written
    /// directly into the existing host mapping and no staging buffer is
    /// needed (counted as `zero_copy_updates`). A device-private resource
    /// would require a staging upload (counted as `staged_copies`) even though
    /// this CPU-side emulation writes the shadow storage in place.
    pub fn update_resource_region(
        &mut self,
        resource: ResourceId,
        offset: usize,
        bytes: &[u8],
    ) -> AppResult<ResourceUpdatePath> {
        let path = {
            let record = self.resource(resource)?;
            if record.storage_mode == MetalStorageMode::Memoryless {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "memoryless resource cannot be updated from the CPU",
                ));
            }
            if record.storage_mode == MetalStorageMode::Shared {
                ResourceUpdatePath::HostVisibleInPlace
            } else {
                ResourceUpdatePath::StagedUpload
            }
        };
        self.write_resource_bytes(resource, offset, bytes)?;
        self.record_update_path(path);
        Ok(path)
    }

    /// Overwrite a resource from host-visible memory (mapped pixels or an
    /// upload buffer), classifying the update path. See
    /// [`update_resource_region`](Self::update_resource_region).
    pub fn overwrite_resource_host_visible(
        &mut self,
        resource: ResourceId,
        bytes: &[u8],
    ) -> AppResult<ResourceUpdatePath> {
        let path = {
            let record = self.resource(resource)?;
            if record.storage_mode == MetalStorageMode::Memoryless {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "memoryless resource cannot be updated from the CPU",
                ));
            }
            if record.storage_mode == MetalStorageMode::Shared {
                ResourceUpdatePath::HostVisibleInPlace
            } else {
                ResourceUpdatePath::StagedUpload
            }
        };
        self.overwrite_resource_bytes(resource, bytes)?;
        self.record_update_path(path);
        Ok(path)
    }

    fn record_update_path(&mut self, path: ResourceUpdatePath) {
        let mut stats = self
            .translation_stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match path {
            ResourceUpdatePath::HostVisibleInPlace => stats.zero_copy_updates += 1,
            ResourceUpdatePath::StagedUpload => stats.staged_copies += 1,
        }
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
        if resource.storage_mode == MetalStorageMode::Memoryless {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "memoryless resource cannot be written from the CPU",
            ));
        }
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "resource write range overflow",
            )
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
            // No actual frame is rasterized here, so no SSIM can be measured;
            // recording a constant would fabricate a quality metric.
            ssim: None,
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

        // On unified memory every non-memoryless default-heap resource is
        // hosted in shared storage: the CPU backing *is* the host-visible
        // backing, so no separate device-private shadow is required. Discrete
        // GPUs genuinely need private storage, and those updates stay counted
        // as staged uploads. Memoryless attachments cannot be CPU-written and
        // are refused explicitly by `update_resource_region`.
        if self.capabilities.unified_memory && desc.heap == HeapType::Default {
            return MetalStorageMode::Shared;
        }

        // Constant/vertex/index buffers are rewritten every frame. On unified
        // memory a bounded dynamic buffer is host-visible, so Map/Unmap and
        // UpdateSubresource write straight into the shared backing instead of
        // creating a staging upload. Static buffers above the bound and
        // device-private resources keep the staged path.
        if self.capabilities.unified_memory
            && desc.heap == HeapType::Default
            && desc.subresources == 1
            && desc.size <= 256 * 1024
            && matches!(
                desc.usage_hint,
                ResourceUsageHint::Buffer {
                    role: BufferRole::Constant | BufferRole::Vertex | BufferRole::Index,
                    ..
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
            for chunk in bytes[..expected_bytes].as_chunks::<4>().0 {
                ppm.extend_from_slice(&chunk[..3]);
            }
        }
        DxgiFormat::B8G8R8A8Unorm | DxgiFormat::B8G8R8A8UnormSrgb | DxgiFormat::B8G8R8X8Unorm => {
            for chunk in bytes[..expected_bytes].as_chunks::<4>().0 {
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
        DxgiFormat::Unknown => {
            return Err(AppError::new(
                ReasonCode::RcGfxFormatUnsupported,
                "DXGI_FORMAT_UNKNOWN has no renderable representation",
            ));
        }
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
    fn dxgi_format_inexact_values_are_rejected_not_substituted() {
        // R8G8B8A8_TYPELESS (27), R8G8B8A8_SNORM (31), R8G8B8A8_SINT (32),
        // R8G8_UNORM (49), D16_UNORM (55), A8_UNORM (65), R1_UNORM (66),
        // BC6H (94-96), NV12 (103) — none may silently map to another format.
        for raw in [27, 31, 32, 49, 55, 65, 66, 94, 95, 96, 103, 9999] {
            assert!(
                DxgiFormat::from_u32_checked(raw).is_err(),
                "inexact DXGI value {raw} must be rejected, not substituted"
            );
        }
        let error = DxgiFormat::from_u32_checked(49).expect_err("49 must error");
        assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
    }

    #[test]
    fn dxgi_format_unsupported_via_checked_errors_and_never_substitutes() {
        // The production checked path must never substitute the lossy
        // fallback R8G8B8A8Unorm (or anything else) for an unsupported
        // format: the call fails with an explicit error instead.
        for raw in [49, 65, 66, 94, 103, 9999, u32::MAX] {
            let error = DxgiFormat::from_u32_checked(raw)
                .err()
                .unwrap_or_else(|| panic!("DXGI_FORMAT {raw} must be rejected"));
            assert_eq!(error.code, ReasonCode::RcGfxFormatUnsupported);
        }
    }

    #[test]
    fn dxgi_format_lossy_fallback_is_recorded() {
        let before = DxgiFormat::format_fallback_count();
        let format = DxgiFormat::from_u32_diagnostics(9999);
        assert_eq!(format, DXGI_FORMAT_FALLBACK);
        assert_eq!(format, DxgiFormat::R8G8B8A8Unorm);
        assert!(
            DxgiFormat::format_fallback_count() > before,
            "lossy fallback must be observable via the counter"
        );
    }

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

    fn parallel_test_resource(
        backend: &mut GraphicsBackend,
        name: &str,
        state: ResourceState,
    ) -> ResourceId {
        backend
            .create_resource(ResourceDesc {
                name: name.to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: state,
                usage_hint: ResourceUsageHint::Generic,
            })
            .expect("create resource")
    }

    #[test]
    fn parallel_translation_matches_serial_and_keeps_dependent_streams_ordered() {
        let mut backend =
            GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M3 Ultra"));
        let format = DxgiFormat::R8G8B8A8Unorm;
        let resource_a = parallel_test_resource(&mut backend, "parallel-a", ResourceState::Common);
        let resource_b = parallel_test_resource(&mut backend, "parallel-b", ResourceState::Common);
        let heap_a = backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        backend
            .write_descriptor(
                heap_a,
                0,
                ViewDescriptor::Rtv {
                    resource: resource_a,
                    format,
                },
            )
            .expect("write rtv a");
        let heap_b = backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        backend
            .write_descriptor(
                heap_b,
                0,
                ViewDescriptor::Rtv {
                    resource: resource_b,
                    format,
                },
            )
            .expect("write rtv b");
        let allocator = backend.create_command_allocator();
        let root_signature = backend.create_root_signature(RootSignatureDesc::default());
        let pipeline = backend.create_pipeline_state(
            root_signature,
            PipelineStateDesc {
                label: "parallel".to_string(),
                compute: false,
                render_target_formats: vec![format],
                depth_format: None,
            },
        );

        let mut streams = Vec::new();
        for (heap, draws) in [(heap_a, 3u32), (heap_b, 3u32), (heap_a, 6u32)] {
            let list = backend.create_graphics_command_list(allocator, pipeline, false);
            backend
                .record_begin_render_pass(list, vec![format], None, "clear", "store")
                .expect("begin pass");
            backend.record_clear_rtv(list, heap, 0).expect("clear rtv");
            backend.record_draw(list, draws).expect("draw");
            streams.push(backend.close_command_list(list).expect("close list"));
        }

        let serial_translation = backend
            .translate_command_streams(&streams)
            .expect("serial translation");
        backend.reset_translation_stats();
        let parallel_translation = backend
            .translate_streams_parallel(&streams)
            .expect("parallel translation");

        assert_eq!(parallel_translation.len(), 3);
        for (serial, parallel) in serial_translation.iter().zip(&parallel_translation) {
            assert_eq!(serial.id, parallel.id);
            assert_eq!(
                serial.commands, parallel.commands,
                "parallel translation must be byte-identical to serial translation"
            );
        }
        // Streams 0 and 1 touch disjoint resources and share a batch; stream 2
        // touches resource_a and therefore depends on stream 0.
        assert_eq!(parallel_translation[2].depends_on, vec![0]);
        assert_eq!(parallel_translation[0].batch_index, 0);
        assert_eq!(parallel_translation[1].batch_index, 0);
        assert_eq!(parallel_translation[2].batch_index, 1);
        assert!(parallel_translation[0].parallel);
        assert!(parallel_translation[1].parallel);
        assert!(
            !parallel_translation[2].parallel,
            "dependent stream stays ordered"
        );

        let stats = backend.translation_stats();
        assert_eq!(stats.parallel_translation_batches, 1);
        assert_eq!(stats.streams_translated_in_parallel, 2);
        assert_eq!(stats.streams_translated_serially, 1);
        assert_eq!(stats.commands_translated, 9);

        // The same streams executed serially and in parallel produce the same
        // plan and the same resource contents.
        let mut serial_backend = backend.clone();
        let mut parallel_backend = backend.clone();
        let serial_fence = serial_backend.create_fence(0);
        let plan_serial = serial_backend
            .execute_command_lists(0, &streams, Some((serial_fence, 1)))
            .expect("serial execution");
        let parallel_fence = parallel_backend.create_fence(0);
        let plan_parallel = parallel_backend
            .execute_command_lists_parallel(0, &streams, Some((parallel_fence, 1)))
            .expect("parallel execution");

        assert_eq!(plan_serial, plan_parallel);
        assert_eq!(plan_serial.render_passes.len(), 3);
        let draws: u32 = plan_serial
            .render_passes
            .iter()
            .map(|pass| pass.draw_calls)
            .sum();
        assert_eq!(draws, 3);
        assert_eq!(serial_backend.fence_value(serial_fence).expect("fence"), 1);
        assert_eq!(
            parallel_backend.fence_value(parallel_fence).expect("fence"),
            1
        );
    }

    #[test]
    fn duplicate_uav_and_aliasing_barriers_are_elided_only_when_no_work_intervenes() {
        let mut backend =
            GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M3 Ultra"));
        let resource_a = parallel_test_resource(&mut backend, "uav-a", ResourceState::Common);
        let resource_b = parallel_test_resource(&mut backend, "uav-b", ResourceState::Common);
        let allocator = backend.create_command_allocator();
        let root_signature = backend.create_root_signature(RootSignatureDesc::default());
        let pipeline = backend.create_pipeline_state(
            root_signature,
            PipelineStateDesc {
                label: "barriers".to_string(),
                compute: true,
                render_target_formats: Vec::new(),
                depth_format: None,
            },
        );

        let clean = backend.create_graphics_command_list(allocator, pipeline, false);
        backend
            .record_uav_barrier(clean, resource_a)
            .expect("first uav barrier");
        backend
            .record_uav_barrier(clean, resource_a)
            .expect("second uav barrier");
        backend
            .record_aliasing_barrier(clean, Some(resource_a), Some(resource_b))
            .expect("first aliasing barrier");
        backend
            .record_aliasing_barrier(clean, Some(resource_a), Some(resource_b))
            .expect("second aliasing barrier");
        let clean = backend.close_command_list(clean).expect("close clean");
        let analysis = backend
            .analyze_barriers(&[clean.clone()])
            .expect("analysis");
        assert_eq!(analysis.uav_barriers_considered, 2);
        assert_eq!(analysis.uav_barriers_required, 1);
        assert_eq!(analysis.uav_barriers_elided, 1);
        assert_eq!(analysis.aliasing_barriers_considered, 2);
        assert_eq!(analysis.aliasing_barriers_required, 1);
        assert_eq!(analysis.aliasing_barriers_elided, 1);

        // A write-capable command between the barriers makes the second pair
        // hazardous, so nothing may be elided.
        let hazardous = backend.create_graphics_command_list(allocator, pipeline, false);
        backend
            .record_uav_barrier(hazardous, resource_a)
            .expect("first uav barrier");
        backend
            .record_copy_buffer_region(hazardous, resource_a, 0, resource_b, 0, 8)
            .expect("copy into a");
        backend
            .record_uav_barrier(hazardous, resource_a)
            .expect("second uav barrier");
        backend
            .record_aliasing_barrier(hazardous, Some(resource_a), Some(resource_b))
            .expect("first aliasing barrier");
        backend
            .record_dispatch(hazardous, 1, 1, 1)
            .expect("dispatch");
        backend
            .record_aliasing_barrier(hazardous, Some(resource_a), Some(resource_b))
            .expect("second aliasing barrier");
        let hazardous = backend
            .close_command_list(hazardous)
            .expect("close hazardous");
        let analysis = backend.analyze_barriers(&[hazardous]).expect("analysis");
        assert_eq!(analysis.uav_barriers_required, 2);
        assert_eq!(analysis.uav_barriers_elided, 0);
        assert_eq!(analysis.aliasing_barriers_required, 2);
        assert_eq!(analysis.aliasing_barriers_elided, 0);
    }

    #[test]
    fn nv12_swapchain_rejects_zero_and_odd_dimensions_and_pins_state() {
        let mut backend = GraphicsBackend::new();
        for (width, height) in [(0u32, 2u32), (2, 0), (3, 2), (2, 3)] {
            let error = backend
                .create_nv12_swapchain(SwapchainDesc {
                    width,
                    height,
                    format: DxgiFormat::B8G8R8A8Unorm,
                    buffer_count: 2,
                })
                .expect_err("odd/zero NV12 swapchain dimensions must be rejected");
            assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
            assert_eq!(
                error.message,
                format!("NV12 swapchain dimensions {width}x{height} must be non-zero and even")
            );
        }

        let swapchain = backend
            .create_nv12_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("NV12 swapchain");
        assert_eq!(
            backend.swapchain_is_nv12(swapchain).expect("nv12 flag"),
            true
        );
        let state = backend.swapchain_state(swapchain).expect("swapchain state");
        assert_eq!(state.desc.width, 4);
        assert_eq!(state.desc.height, 2);
        assert_eq!(state.desc.format, DxgiFormat::B8G8R8A8Unorm);
        assert_eq!(state.desc.buffer_count, 2);
        let error = backend
            .swapchain_is_nv12(swapchain + 100)
            .expect_err("unknown swapchain must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("unknown swapchain {}", swapchain + 100)
        );

        let error = backend
            .resize_buffers(swapchain, 2, 3, 2, DxgiFormat::B8G8R8A8Unorm)
            .expect_err("NV12 resize with odd width must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "NV12 swapchain resize dimensions 3x2 must be even"
        );
        let error = backend
            .resize_buffers(swapchain, 1, 4, 2, DxgiFormat::B8G8R8A8Unorm)
            .expect_err("one backbuffer must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "swapchain buffer count must be at least 2");
        backend
            .resize_buffers(swapchain, 2, 6, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect("even NV12 resize");
        assert_eq!(
            backend
                .swapchain_state(swapchain)
                .expect("resized state")
                .desc
                .width,
            6
        );
    }

    #[test]
    fn present_layer_failures_keep_present_and_nv12_counters_consistent() {
        let Some(device) = metal::Device::system_default() else {
            return;
        };
        let mut backend = GraphicsBackend::new();
        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 8,
                height: 8,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("swapchain");
        let layer = metal::MetalLayer::new();
        layer.set_device(&device);
        layer.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
        layer.set_drawable_size(core_graphics_types::geometry::CGSize {
            width: 8.0,
            height: 8.0,
        });
        backend.set_present_layer(Some(layer));
        assert_eq!(backend.present_layer().is_some(), true);

        backend
            .present(swapchain, 1, false)
            .expect("bytes fallback present");
        assert_eq!(backend.layer_present_attempts(), 1);
        if backend.layer_present_count() == 0 {
            assert_eq!(backend.layer_present_count(), 0);
        } else {
            assert_eq!(backend.layer_present_count(), 1);
        }
        assert_eq!(backend.nv12_present_count(), 0);

        let debug = format!("{backend:?}");
        assert_eq!(debug.contains("present_layer: true"), true);
        assert_eq!(debug.contains("layer_present_attempts: 1"), true);
        assert_eq!(debug.contains("nv12_presents: 0"), true);
        backend.set_present_layer(None);
        assert_eq!(backend.present_layer().is_none(), true);
        backend
            .present(swapchain, 1, false)
            .expect("headless present");
        assert_eq!(backend.layer_present_attempts(), 1);

        if !crate::metal_backend::iosurface_capability_available()
            || !crate::metal_backend::cv_metal_texture_cache_available()
        {
            return;
        }
        let mut pixel_channel = crate::metal_backend::IoSurfacePresentChannel::new(
            8,
            8,
            crate::metal_backend::dxgi_to_metal_format(DxgiFormat::B8G8R8A8Unorm),
        )
        .expect("pixel channel");
        pixel_channel
            .write_pixels(&vec![3u8; 8 * 8 * 4])
            .expect("pixel channel write");
        let pixel_handle = pixel_channel.surface_ptr();
        backend.set_presented_surface(Some(pixel_channel));
        assert_eq!(backend.presented_surface_handle(), Some(pixel_handle));
        let layer = metal::MetalLayer::new();
        layer.set_device(&device);
        layer.set_drawable_size(core_graphics_types::geometry::CGSize {
            width: 8.0,
            height: 8.0,
        });
        backend.set_present_layer(Some(layer));
        backend
            .present(swapchain, 1, false)
            .expect("pixel-channel present");
        assert_eq!(backend.layer_present_attempts(), 2);

        let nv12 =
            crate::metal_backend::Nv12PresentChannel::new(8, 8).expect("NV12 present channel");
        nv12.fill_nv12(&vec![40u8; 64], &vec![128u8; 32])
            .expect("fill NV12 channel");
        backend.set_presented_nv12_surface(Some(nv12));
        assert_eq!(backend.presented_surface_handle(), None);
        assert_eq!(backend.presented_nv12_surface().is_some(), true);
        assert_eq!(
            backend.presented_nv12_surface_handle(),
            backend
                .presented_nv12_surface()
                .map(|surface| surface.surface_ptr())
        );
        assert_eq!(
            backend.presented_nv12_plane_ptrs(),
            backend
                .presented_nv12_surface()
                .map(|surface| surface.plane_texture_ptrs())
        );
        let (luma, chroma) = backend
            .presented_nv12_plane_bytes()
            .expect("NV12 plane bytes");
        assert_eq!(luma, vec![40u8; 64]);
        assert_eq!(chroma, vec![128u8; 32]);
        backend.present(swapchain, 1, false).expect("NV12 present");
        assert_eq!(backend.layer_present_attempts(), 3);
        assert_eq!(backend.nv12_present_count(), 1);
        let debug = format!("{backend:?}");
        assert_eq!(debug.contains("nv12_presents: 1"), true);
        assert_eq!(debug.contains("presented_nv12_surface: Some"), true);
        let frame = backend
            .presented_frame(swapchain)
            .expect("NV12 presented frame");
        assert_eq!(frame.format, DxgiFormat::R8G8B8A8Unorm);
        assert_eq!(frame.width, 8);
        assert_eq!(frame.height, 8);

        backend.set_presented_nv12_surface(None);
        assert_eq!(backend.presented_nv12_surface().is_none(), true);
        let error = backend
            .presented_nv12_plane_bytes()
            .expect_err("no NV12 channel must be an exact error");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "no NV12 present surface is attached");
    }

    #[test]
    fn present_layer_bytes_fallback_rejects_invalid_sync_without_stale_counters() {
        let mut backend = GraphicsBackend::new();
        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 8,
                height: 8,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("headless swapchain");
        let layer = metal::MetalLayer::new();
        layer.set_drawable_size(core_graphics_types::geometry::CGSize {
            width: 8.0,
            height: 8.0,
        });
        backend.set_present_layer(Some(layer));

        let result = backend
            .present(swapchain, 1, false)
            .expect("CPU-byte fallback present");
        assert_eq!(backend.layer_present_attempts(), 1);
        assert_eq!(backend.nv12_present_count(), 0);
        assert_eq!(result.effective_sync_interval, 1);
        assert_eq!(result.tearing_allowed, false);
        if backend.layer_present_count() == 0 {
            assert_eq!(
                backend.layer_present_count(),
                0,
                "an unattached layer must not report a presented drawable"
            );
        } else {
            assert_eq!(
                backend.layer_present_count(),
                1,
                "a drawable present must be counted exactly once"
            );
        }

        let error = backend
            .present(swapchain, 5, false)
            .expect_err("sync interval above 4 must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "unsupported sync interval 5");
        assert_eq!(
            backend.layer_present_attempts(),
            1,
            "a rejected present must not touch the layer"
        );
    }

    #[test]
    fn present_bytes_fallback_rejects_short_frame_on_layer() {
        let Some(device) = metal::Device::system_default() else {
            return;
        };
        let mut backend = GraphicsBackend::new();
        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 8,
                height: 8,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create swapchain");
        let backbuffer = backend
            .swapchain_state(swapchain)
            .expect("swapchain state")
            .backbuffers[0];
        backend
            .resources
            .get_mut(&backbuffer)
            .expect("backbuffer resource")
            .bytes
            .truncate(4);
        let layer = metal::MetalLayer::new();
        layer.set_device(&device);
        layer.set_pixel_format(metal::MTLPixelFormat::BGRA8Unorm);
        layer.set_drawable_size(core_graphics_types::geometry::CGSize {
            width: 8.0,
            height: 8.0,
        });
        backend.set_present_layer(Some(layer));
        let error = backend
            .present(swapchain, 1, false)
            .expect_err("short CPU bytes must not reach the drawable");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "CAMetalLayer present: 8x8 pixels need 256 bytes, got 4 (drawable 8x8)"
        );
        assert_eq!(backend.layer_present_count(), 0);

        backend
            .resources
            .get_mut(&backbuffer)
            .expect("backbuffer resource")
            .bytes = vec![0u8; 256];
        backend
            .present(swapchain, 1, false)
            .expect("full-frame present must not fail");
        let resource = backend
            .resources
            .remove(&backbuffer)
            .expect("backbuffer resource");
        backend
            .present(swapchain, 1, false)
            .expect("missing backbuffer bytes must fall through");
        backend.resources.insert(backbuffer, resource);
    }

    #[test]
    fn present_poisoned_frame_callback_panic_is_recovered_exactly_once() {
        let mut backend = GraphicsBackend::new();
        let swapchain = backend
            .create_swapchain(SwapchainDesc {
                width: 8,
                height: 8,
                format: DxgiFormat::R8G8B8A8Unorm,
                buffer_count: 2,
            })
            .expect("swapchain");
        let delivered = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&delivered);
        backend.set_frame_published_callback(Some(Box::new(move |frame| {
            assert_eq!(frame.width, 8);
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })));
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend
                .frame_published_callback
                .as_ref()
                .expect("callback installed")
                .lock()
                .expect("unpoisoned callback");
            panic!("poison the frame-published callback");
        }));
        assert_eq!(poisoned.is_err(), true);
        assert_eq!(
            backend
                .frame_published_callback
                .as_ref()
                .expect("callback installed")
                .is_poisoned(),
            true
        );

        let result = backend
            .present(swapchain, 1, false)
            .expect("a poisoned callback lock must not block present");
        assert_eq!(result.displayed_frame_index, 1);
        assert_eq!(
            delivered.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the recovered callback must run exactly once"
        );
    }

    #[test]
    fn destroy_descriptor_heap_recovers_from_panicked_cache_lock() {
        let mut backend = GraphicsBackend::new();
        let resource =
            parallel_test_resource(&mut backend, "destroy-poison", ResourceState::Common);
        let heap = backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        backend
            .write_descriptor(
                heap,
                0,
                ViewDescriptor::Rtv {
                    resource,
                    format: DxgiFormat::R8G8B8A8Unorm,
                },
            )
            .expect("write descriptor");
        assert_eq!(
            backend
                .translate_descriptor_heap(heap)
                .expect("translate before destroy")
                .len(),
            1
        );
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend
                .descriptor_translation_cache
                .lock()
                .expect("unpoisoned descriptor cache");
            panic!("poison the descriptor translation cache");
        }));
        assert_eq!(poisoned.is_err(), true);
        assert_eq!(backend.descriptor_translation_cache.is_poisoned(), true);

        backend
            .destroy_descriptor_heap(heap)
            .expect("a poisoned cache lock must not block heap destruction");
        assert_eq!(
            backend
                .descriptor_translation_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entries
                .contains_key(&heap),
            false
        );
        let error = backend
            .destroy_descriptor_heap(heap)
            .expect_err("a destroyed heap must not be destroyed twice");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "unknown descriptor heap");
    }

    #[test]
    fn translate_descriptor_heap_panicked_cache_and_stats_reuse_exactly() {
        let mut backend = GraphicsBackend::new();
        let resource = parallel_test_resource(&mut backend, "reuse-poison", ResourceState::Common);
        let heap = backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        backend
            .write_descriptor(
                heap,
                0,
                ViewDescriptor::Rtv {
                    resource,
                    format: DxgiFormat::R8G8B8A8Unorm,
                },
            )
            .expect("write descriptor");
        let first = backend
            .translate_descriptor_heap(heap)
            .expect("first translation must upload");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].slot, 0);
        assert_eq!(backend.translation_stats().descriptor_table_uploads, 1);

        let cache_poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend
                .descriptor_translation_cache
                .lock()
                .expect("unpoisoned descriptor cache");
            panic!("poison the descriptor translation cache");
        }));
        assert_eq!(cache_poison.is_err(), true);
        let stats_poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend
                .translation_stats
                .lock()
                .expect("unpoisoned translation stats");
            panic!("poison the translation stats");
        }));
        assert_eq!(stats_poison.is_err(), true);
        assert_eq!(backend.descriptor_translation_cache.is_poisoned(), true);
        assert_eq!(backend.translation_stats.is_poisoned(), true);

        let second = backend
            .translate_descriptor_heap(heap)
            .expect("poisoned locks must still serve the revision cache");
        assert_eq!(second, first);
        let stats = backend.translation_stats();
        assert_eq!(stats.descriptor_table_uploads, 1);
        assert_eq!(stats.descriptor_table_reuses, 1);
    }

    #[test]
    fn translate_descriptor_heap_panicked_cache_insert_and_upload_exactly() {
        let mut backend = GraphicsBackend::new();
        let resource = parallel_test_resource(&mut backend, "insert-poison", ResourceState::Common);
        let heap = backend.create_descriptor_heap(DescriptorHeapType::Rtv, 1);
        backend
            .write_descriptor(
                heap,
                0,
                ViewDescriptor::Rtv {
                    resource,
                    format: DxgiFormat::R8G8B8A8Unorm,
                },
            )
            .expect("write descriptor");

        let cache_poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend
                .descriptor_translation_cache
                .lock()
                .expect("unpoisoned descriptor cache");
            panic!("poison the descriptor translation cache");
        }));
        assert_eq!(cache_poison.is_err(), true);
        let stats_poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend
                .translation_stats
                .lock()
                .expect("unpoisoned translation stats");
            panic!("poison the translation stats");
        }));
        assert_eq!(stats_poison.is_err(), true);

        let bindings = backend
            .translate_descriptor_heap(heap)
            .expect("poisoned locks must not drop an uncached translation");
        assert_eq!(bindings.len(), 1);
        let stats = backend.translation_stats();
        assert_eq!(stats.descriptor_table_uploads, 1);
        assert_eq!(stats.descriptor_table_reuses, 0);
        assert_eq!(
            backend
                .descriptor_translation_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entries
                .get(&heap)
                .cloned(),
            Some((1, bindings))
        );
    }

    #[test]
    fn translate_descriptor_tables_panicked_stats_batch_is_counted() {
        let mut backend = GraphicsBackend::new();
        let heap = backend.create_descriptor_heap(DescriptorHeapType::Sampler, 0);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend
                .translation_stats
                .lock()
                .expect("unpoisoned translation stats");
            panic!("poison the translation stats");
        }));
        assert_eq!(poisoned.is_err(), true);
        assert_eq!(backend.translation_stats.is_poisoned(), true);

        let tables = backend
            .translate_descriptor_tables(&[heap])
            .expect("a poisoned stats lock must not block batch translation");
        assert_eq!(tables, vec![Vec::<MetalBinding>::new()]);
        let stats = backend.translation_stats();
        assert_eq!(stats.descriptor_table_batches, 1);
        assert_eq!(stats.descriptor_table_uploads, 1);
    }

    #[test]
    fn overwrite_resource_host_visible_recovers_panicked_stats_lock() {
        let mut backend = GraphicsBackend::new();
        let resource = parallel_test_resource(&mut backend, "update-poison", ResourceState::Common);
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend
                .translation_stats
                .lock()
                .expect("unpoisoned translation stats");
            panic!("poison the translation stats");
        }));
        assert_eq!(poisoned.is_err(), true);

        let storage = backend
            .resource_storage_mode(resource)
            .expect("storage mode");
        let path = backend
            .overwrite_resource_host_visible(resource, &[0x5A; 64])
            .expect("a poisoned stats lock must not drop the resource update");
        if storage == MetalStorageMode::Shared {
            assert_eq!(path, ResourceUpdatePath::HostVisibleInPlace);
        } else {
            assert_eq!(path, ResourceUpdatePath::StagedUpload);
        }
        assert_eq!(
            backend.resource_bytes(resource).expect("resource bytes"),
            &[0x5A; 64]
        );
        let stats = backend.translation_stats();
        if storage == MetalStorageMode::Shared {
            assert_eq!(stats.zero_copy_updates, 1);
            assert_eq!(stats.staged_copies, 0);
        } else {
            assert_eq!(stats.staged_copies, 1);
            assert_eq!(stats.zero_copy_updates, 0);
        }
    }

    #[test]
    fn gfx_shared_dynamic_buffer_update_fallback_counts_are_exact() {
        let mut backend = GraphicsBackend::new();
        let buffer = backend
            .create_resource(ResourceDesc {
                name: "gfx-dynamic-constant-buffer".to_string(),
                format: DxgiFormat::Unknown,
                heap: HeapType::Default,
                size: 256,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Buffer {
                    role: BufferRole::Constant,
                    cpu_write_frequent: true,
                },
            })
            .expect("dynamic buffer");
        let storage = backend.resource_storage_mode(buffer).expect("storage mode");
        if backend.capabilities().unified_memory {
            assert_eq!(storage, MetalStorageMode::Shared);
            let path = backend
                .update_resource_region(buffer, 0, &[0x11; 8])
                .expect("shared dynamic update");
            assert_eq!(path, ResourceUpdatePath::HostVisibleInPlace);
            let path = backend
                .overwrite_resource_host_visible(buffer, &[0x22; 16])
                .expect("shared dynamic overwrite");
            assert_eq!(path, ResourceUpdatePath::HostVisibleInPlace);
            let stats = backend.translation_stats();
            assert_eq!(stats.zero_copy_updates, 2);
            assert_eq!(stats.staged_copies, 0);
            assert_eq!(
                backend.resource_bytes(buffer).expect("bytes")[..16],
                [0x22u8; 16]
            );
        } else {
            // A discrete GPU has no host-visible default-heap buffer: the
            // update must be counted as a staged upload, never as zero-copy.
            assert_eq!(storage, MetalStorageMode::Private);
            let path = backend
                .update_resource_region(buffer, 0, &[0x11; 8])
                .expect("private dynamic update");
            assert_eq!(path, ResourceUpdatePath::StagedUpload);
            let stats = backend.translation_stats();
            assert_eq!(stats.zero_copy_updates, 0);
            assert_eq!(stats.staged_copies, 1);
        }

        let texture = backend
            .create_resource(ResourceDesc {
                name: "gfx-private-texture".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 1024,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: false,
                },
            })
            .expect("private texture");
        if backend.capabilities().unified_memory {
            // No CPU shadow: the texture's bytes are the shared host-visible
            // backing, so the update is in place and counts as zero-copy.
            assert_eq!(
                backend.resource_storage_mode(texture).expect("storage"),
                MetalStorageMode::Shared
            );
            let before = backend.translation_stats();
            let path = backend
                .update_resource_region(texture, 4, &[0x33; 4])
                .expect("shared texture update");
            assert_eq!(path, ResourceUpdatePath::HostVisibleInPlace);
            let stats = backend.translation_stats();
            assert_eq!(stats.zero_copy_updates, before.zero_copy_updates + 1);
            assert_eq!(stats.staged_copies, before.staged_copies);
        }
    }
    #[test]
    fn memoryless_resource_cpu_update_is_refused_exactly() {
        let mut backend =
            GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M3 Pro"));
        let resource = backend
            .create_resource(ResourceDesc {
                name: "memoryless-depth".to_string(),
                format: DxgiFormat::D24UnormS8Uint,
                heap: HeapType::Default,
                size: 4096,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::DepthStencil,
            })
            .expect("memoryless depth resource");
        assert_eq!(
            backend
                .resource_storage_mode(resource)
                .expect("storage mode"),
            MetalStorageMode::Memoryless
        );
        let error = backend
            .update_resource_region(resource, 0, &[1u8; 4])
            .expect_err("memoryless CPU update must be refused");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "memoryless resource cannot be updated from the CPU"
        );
        let error = backend
            .overwrite_resource_host_visible(resource, &[1u8; 4])
            .expect_err("memoryless host-visible update must be refused");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "memoryless resource cannot be updated from the CPU"
        );
        assert_eq!(backend.translation_stats().staged_copies, 0);
        assert_eq!(backend.translation_stats().zero_copy_updates, 0);
    }

    #[test]
    fn default_heap_resource_has_no_device_private_shadow_fallback_on_unified_memory() {
        let mut backend =
            GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M3 Pro"));
        let resource = backend
            .create_resource(ResourceDesc {
                name: "unified-texture".to_string(),
                format: DxgiFormat::R8G8B8A8Unorm,
                heap: HeapType::Default,
                size: 64,
                subresources: 1,
                initial_state: ResourceState::Common,
                usage_hint: ResourceUsageHint::Texture {
                    sampled: true,
                    render_target: true,
                    depth_stencil: false,
                    cpu_write_frequent: false,
                },
            })
            .expect("unified texture");
        assert_eq!(
            backend.resource_storage_mode(resource).expect("storage"),
            MetalStorageMode::Shared
        );
        let path = backend
            .update_resource_region(resource, 0, &[0x5A; 8])
            .expect("unified update");
        assert_eq!(path, ResourceUpdatePath::HostVisibleInPlace);
        assert_eq!(backend.translation_stats().staged_copies, 0);
        assert_eq!(backend.translation_stats().zero_copy_updates, 1);
    }
}
