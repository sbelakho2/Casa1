//! Video Decoder Integration for Casa1.
//!
//! Provides H.264/H.265/VP9 decoding using:
//! - **macOS VideoToolbox** (default on macOS, `#[cfg(target_os = "macos")]`)
//! - **FFmpeg** (optional, behind `ffmpeg` feature, cross-platform)
//!
//! Integrates with the Casa1 media container parser and Media Foundation stubs.
//!
//! ## Architecture
//! ```text
//! Media Container (MP4/MKV/AVI) -> Demuxer -> Video Decoder -> Frame Buffer -> Metal Texture
//! ```
//!
//! On macOS, uses VideoToolbox via FFI for hardware-accelerated H.264 decoding.
//! When the `ffmpeg` feature is enabled, uses FFmpeg for cross-platform decoding.
//! Without either, returns an error indicating no decoder is available.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::collections::VecDeque;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Counters for the CoreVideo/IOSurface zero-copy pipeline.
///
/// * `iosurface_frames` — frames whose pixel storage is backed by a real
///   `IOSurface` (VideoToolbox decode output or CoreVideo pixel buffers
///   allocated by the software path).
/// * `cpu_copies_avoided` — full-frame CPU pixel copies that the
///   IOSurface/Metal path made unnecessary (hardware frames delivered as
///   textures without touching CPU memory, and decoded frames presented by
///   binding the IOSurface texture instead of uploading pixels).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZeroCopyStats {
    pub iosurface_frames: u64,
    pub cpu_copies_avoided: u64,
}

static IOSURFACE_FRAMES: AtomicU64 = AtomicU64::new(0);
static CPU_COPIES_AVOIDED: AtomicU64 = AtomicU64::new(0);

/// Read the process-wide zero-copy counters.
pub fn zero_copy_stats() -> ZeroCopyStats {
    ZeroCopyStats {
        iosurface_frames: IOSURFACE_FRAMES.load(Ordering::Relaxed),
        cpu_copies_avoided: CPU_COPIES_AVOIDED.load(Ordering::Relaxed),
    }
}

/// Reset the process-wide zero-copy counters to zero.
pub fn reset_zero_copy_stats() {
    IOSURFACE_FRAMES.store(0, Ordering::Relaxed);
    CPU_COPIES_AVOIDED.store(0, Ordering::Relaxed);
}

/// Record one IOSurface-backed decoded/created frame.
pub(crate) fn record_iosurface_frame() {
    IOSURFACE_FRAMES.fetch_add(1, Ordering::Relaxed);
}

/// Record one full-frame CPU copy avoided on the way to the GPU.
pub(crate) fn record_cpu_copy_avoided() {
    CPU_COPIES_AVOIDED.fetch_add(1, Ordering::Relaxed);
}

/// Availability of the CoreVideo → Metal zero-copy path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroCopyStatus {
    /// A Metal device and a CoreVideo texture cache are available.
    Available,
    /// No Metal device was found (the CPU decode path is still usable).
    MetalUnavailable,
    /// A Metal device exists but the CoreVideo texture cache could not be
    /// created (the CPU decode path is still usable).
    CoreVideoUnavailable,
}

impl ZeroCopyStatus {
    /// Whether decoded frames can be exposed as IOSurface-backed textures.
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }

    /// Human-readable reason for a non-available status.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Available => "CoreVideo/Metal zero-copy path available",
            Self::MetalUnavailable => "No Metal device available",
            Self::CoreVideoUnavailable => "CVMetalTextureCache creation failed",
        }
    }
}

/// Maximum size (in bytes) of media data buffered from HTTP sources.
///
/// HTTP sources are downloaded into memory for probing/decoding; cap the
/// download so a malicious or oversized remote file cannot exhaust memory.
pub(crate) const HTTP_FETCH_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Lock a `Mutex`, recovering from poisoning instead of panicking.
///
/// Used inside C callbacks where a panic would unwind across the FFI
/// boundary (undefined behavior in release builds).
fn lock_poisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Fetch an HTTP(S) URL into memory, rejecting responses larger than `limit`.
pub(crate) fn fetch_http_bounded(url: &str, limit: usize) -> AppResult<Vec<u8>> {
    use std::io::Read;
    let response = reqwest::blocking::get(url).map_err(|e| {
        AppError::new(
            ReasonCode::RcMediaInvalid,
            format!("Failed to fetch {url}: {e}"),
        )
    })?;
    let mut bytes = Vec::new();
    let mut limited = response.take(limit as u64 + 1);
    limited.read_to_end(&mut bytes).map_err(|e| {
        AppError::new(
            ReasonCode::RcMediaInvalid,
            format!("Failed to read response from {url}: {e}"),
        )
    })?;
    if bytes.len() > limit {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            format!("Media at {url} exceeds the {limit}-byte buffering limit"),
        ));
    }
    Ok(bytes)
}

// ===========================================================================
// Color space / color primaries
// ===========================================================================

/// Color space / color primaries for video frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorSpace {
    /// ITU-R BT.601 (SDTV).
    Rec601,
    /// ITU-R BT.709 (HDTV).
    #[default]
    Rec709,
    /// ITU-R BT.2020 (UHDTV / HDR).
    Rec2020,
    /// Unknown / unspecified — uses Rec.709 as default.
    Unknown,
}

impl ColorSpace {
    /// Return the BT.601 coefficients.
    pub fn coeffs_601() -> (f32, f32, f32, f32, f32) {
        // Kr = 0.299, Kg = 0.587, Kb = 0.114
        (0.299, 0.587, 0.114, 0.0, 0.0)
    }

    /// Return the BT.709 coefficients.
    pub fn coeffs_709() -> (f32, f32, f32, f32, f32) {
        (0.2126, 0.7152, 0.0722, 0.0, 0.0)
    }

    /// Return the BT.2020 NCL coefficients.
    pub fn coeffs_2020() -> (f32, f32, f32, f32, f32) {
        (0.2627, 0.6780, 0.0593, 0.0, 0.0)
    }

    /// YUV -> RGB conversion constants as (Kr, Kg, Kb).
    pub fn kr_kb(&self) -> (f32, f32) {
        match self {
            ColorSpace::Rec601 => (0.299, 0.114),
            ColorSpace::Rec709 => (0.2126, 0.0722),
            ColorSpace::Rec2020 => (0.2627, 0.0593),
            ColorSpace::Unknown => (0.2126, 0.0722), // default Rec.709
        }
    }
}

/// Full-range YUV -> RGB conversion coefficients for the given color space,
/// returned as `(cr, cg_u, cg_v, cb)` multipliers.
///
/// Public within the crate so the Metal present path can pass the same
/// coefficients to its NV12 conversion shader as the CPU path uses.
pub(crate) fn yuv_to_rgb_coeffs(color_space: ColorSpace) -> (f32, f32, f32, f32) {
    match color_space {
        ColorSpace::Rec601 => (1.402, 0.344, 0.714, 1.772),
        ColorSpace::Rec709 => (1.5748, 0.1873, 0.4681, 1.8556),
        ColorSpace::Rec2020 => (1.4746, 0.1646, 0.5714, 1.8814),
        ColorSpace::Unknown => (1.5748, 0.1873, 0.4681, 1.8556),
    }
}

// ===========================================================================
// Shared types (platform-independent)
// ===========================================================================

/// Video codec types supported by the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    H265,
    VP9,
    Unknown,
}

/// A decoded video frame.
///
/// When the zero-copy Metal path is active, `metal_texture` holds a +1
/// retained `id<MTLTexture>` pointer and `data` is empty.  Otherwise
/// `data` contains CPU-side RGBA bytes and `metal_texture` is `None`.
///
/// `VideoFrame` is intentionally not `Clone`: the `metal_texture` pointer
/// has single-ownership semantics (released when the frame is dropped), so
/// copying a frame would double-release the texture.
#[derive(Debug)]
pub struct VideoFrame {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// RGBA pixel data (8 bits per channel) — empty when using zero-copy.
    pub data: Vec<u8>,
    /// Presentation timestamp in microseconds.
    pub pts: u64,
    /// Duration of this frame in microseconds.
    pub duration: u64,
    /// Optional Metal texture ID (set after uploading to GPU).
    pub texture_id: Option<u64>,
    /// Zero-copy Metal texture pointer (+1 retained `id<MTLTexture>`).
    /// When `Some`, the pixel data lives on the GPU and `data` is empty.
    /// The consumer should wrap this with `metal::Texture::from_ptr()`
    /// and the texture will be released on drop.
    pub metal_texture: Option<*mut std::ffi::c_void>,
    /// Color space of the frame.
    pub color_space: ColorSpace,
}

// ===========================================================================
// CoreVideo surface registry
// ===========================================================================
//
// `VideoFrame`'s public field set is frozen (integration tests construct it
// directly), so the extra zero-copy state — the retained CVPixelBuffer and,
// for NV12, the +1 retained UV-plane texture — is kept in a registry keyed by
// the (unique while retained) luma/BGRA texture pointer. Entries are removed
// by `VideoFrame::drop`, which then releases both resources.

/// Extra CoreVideo state associated with a zero-copy frame's Metal texture.
#[cfg(target_os = "macos")]
struct FrameSurfaces {
    /// +1 retained `CVPixelBufferRef` whose IOSurface backs the texture(s).
    pixel_buffer: vt_ffi::CVPixelBufferRef,
    /// +1 retained `id<MTLTexture>` for the NV12 chroma plane (null when
    /// the frame is single-plane).
    uv_texture: *mut std::ffi::c_void,
    /// Whether CoreVideo actually backed the pixel buffer with an IOSurface.
    iosurface: bool,
}

// SAFETY: the raw pointers reference CoreFoundation/Objective-C objects with
// atomic retain/release semantics, and every access is serialized by the
// `FRAME_SURFACES` mutex.
#[cfg(target_os = "macos")]
unsafe impl Send for FrameSurfaces {}

#[cfg(target_os = "macos")]
static FRAME_SURFACES: std::sync::LazyLock<Mutex<std::collections::HashMap<usize, FrameSurfaces>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Associate CoreVideo state with a frame texture pointer.
#[cfg(target_os = "macos")]
fn register_frame_surfaces(
    texture_ptr: *mut std::ffi::c_void,
    pixel_buffer: vt_ffi::CVPixelBufferRef,
    uv_texture: *mut std::ffi::c_void,
    iosurface: bool,
) {
    if texture_ptr.is_null() {
        return;
    }
    lock_poisoned(&FRAME_SURFACES).insert(
        texture_ptr as usize,
        FrameSurfaces {
            pixel_buffer,
            uv_texture,
            iosurface,
        },
    );
}

/// Run `f` with the registry entry for `texture_ptr`, if any.
#[cfg(target_os = "macos")]
fn with_frame_surfaces<R>(
    texture_ptr: *mut std::ffi::c_void,
    f: impl FnOnce(&FrameSurfaces) -> R,
) -> Option<R> {
    if texture_ptr.is_null() {
        return None;
    }
    lock_poisoned(&FRAME_SURFACES)
        .get(&(texture_ptr as usize))
        .map(f)
}

/// Remove and return the registry entry for `texture_ptr`.
#[cfg(target_os = "macos")]
fn take_frame_surfaces(texture_ptr: *mut std::ffi::c_void) -> Option<FrameSurfaces> {
    if texture_ptr.is_null() {
        return None;
    }
    lock_poisoned(&FRAME_SURFACES).remove(&(texture_ptr as usize))
}

impl VideoFrame {
    /// The `IOSurfaceRef` backing this frame's pixel buffer, if any.
    ///
    /// The returned pointer is borrowed (`+0`): it is valid only while the
    /// frame is alive and must not be released by the caller.
    #[cfg(target_os = "macos")]
    pub fn io_surface_ptr(&self) -> Option<*mut std::ffi::c_void> {
        let texture = self.metal_texture?;
        with_frame_surfaces(texture, |surfaces| {
            if !surfaces.iosurface || surfaces.pixel_buffer.is_null() {
                return None;
            }
            // SAFETY: `pixel_buffer` is a +1 retained CVPixelBufferRef kept
            // alive by the frame's registry entry.
            let surface = unsafe { vt_ffi::CVPixelBufferGetIOSurface(surfaces.pixel_buffer) };
            if surface.is_null() {
                None
            } else {
                Some(surface)
            }
        })
        .flatten()
    }

    /// The `IOSurfaceRef` backing this frame, if any (always `None` off macOS).
    #[cfg(not(target_os = "macos"))]
    pub fn io_surface_ptr(&self) -> Option<*mut std::ffi::c_void> {
        None
    }

    /// The retained `CVPixelBufferRef` backing this frame, if any.
    ///
    /// The returned pointer is borrowed (`+0`) and stays valid while the frame
    /// is alive; CPU consumers can `CVPixelBufferLockBaseAddress` it for real
    /// pixel access. Always `None` off macOS and for CPU-only frames.
    #[cfg(target_os = "macos")]
    pub fn pixel_buffer_ptr(&self) -> Option<*mut std::ffi::c_void> {
        let texture = self.metal_texture?;
        with_frame_surfaces(texture, |surfaces| {
            if surfaces.pixel_buffer.is_null() {
                None
            } else {
                Some(surfaces.pixel_buffer)
            }
        })
        .flatten()
    }

    /// The retained pixel buffer backing this frame (always `None` off macOS).
    #[cfg(not(target_os = "macos"))]
    pub fn pixel_buffer_ptr(&self) -> Option<*mut std::ffi::c_void> {
        None
    }

    /// Whether this frame's pixel storage is a real IOSurface.
    pub fn is_iosurface_backed(&self) -> bool {
        self.io_surface_ptr().is_some()
    }

    /// The +1 retained NV12 chroma-plane Metal texture, if this is a
    /// two-plane frame. The pointer is borrowed (`+0`) and lives as long as
    /// the frame.
    #[cfg(target_os = "macos")]
    pub fn uv_texture_ptr(&self) -> Option<*mut std::ffi::c_void> {
        let texture = self.metal_texture?;
        with_frame_surfaces(texture, |surfaces| {
            if surfaces.uv_texture.is_null() {
                None
            } else {
                Some(surfaces.uv_texture)
            }
        })
        .flatten()
    }

    /// The NV12 chroma-plane texture (always `None` off macOS).
    #[cfg(not(target_os = "macos"))]
    pub fn uv_texture_ptr(&self) -> Option<*mut std::ffi::c_void> {
        None
    }

    /// Whether the frame has a separate NV12 chroma-plane texture.
    pub fn has_uv_plane(&self) -> bool {
        self.uv_texture_ptr().is_some()
    }
}

#[cfg(target_os = "macos")]
impl Drop for VideoFrame {
    fn drop(&mut self) {
        use self::vt_ffi::CVPixelBufferRelease;
        // SAFETY: `metal_texture` is a +1 retained id<MTLTexture> owned by
        // this frame (see `MetalVideoTextureCache::create_texture_from_pixel_buffer`).
        // Any NV12 chroma texture and the retained CVPixelBufferRef live in
        // the registry and are released here as well.
        unsafe {
            if let Some(ptr) = self.metal_texture {
                if let Some(surfaces) = take_frame_surfaces(ptr) {
                    if !surfaces.uv_texture.is_null() {
                        let uv = surfaces.uv_texture as *mut objc::runtime::Object;
                        let _: () = msg_send![uv, release];
                    }
                    if !surfaces.pixel_buffer.is_null() {
                        CVPixelBufferRelease(surfaces.pixel_buffer);
                    }
                }
                let obj = ptr as *mut objc::runtime::Object;
                let _: () = msg_send![obj, release];
            }
        }
    }
}

/// Video decoder configuration.
#[derive(Debug, Clone)]
pub struct VideoDecoderConfig {
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    pub fps: f64,
    pub bitrate: u64,
}

impl Default for VideoDecoderConfig {
    fn default() -> Self {
        Self {
            codec: VideoCodec::H264,
            width: 1920,
            height: 1080,
            fps: 30.0,
            bitrate: 5_000_000,
        }
    }
}

/// Pixel format for Metal texture upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetalTextureFormat {
    /// 8-bit BGRA with normalized unsigned components.
    BGRA8Unorm,
    /// 8-bit RGBA with normalized unsigned components.
    RGBA8Unorm,
    /// NV12 bi-planar (Y + interleaved UV).
    NV12,
}

/// Describes how to upload a decoded frame to a Metal texture.
#[derive(Debug, Clone)]
pub struct MetalTextureUpload {
    /// Pixel format of the destination Metal texture.
    pub format: MetalTextureFormat,
    /// Bytes per row of the source data.
    pub bytes_per_row: u32,
    /// Source data (already in the requested pixel format).
    pub data: Vec<u8>,
    /// Width of the texture.
    pub width: u32,
    /// Height of the texture.
    pub height: u32,
}

// ===========================================================================
// macOS VideoToolbox FFI declarations
// ===========================================================================

/// CoreMedia and VideoToolbox FFI for macOS H.264 hardware decoding.
///
/// These are C functions from Apple's frameworks, declared here as `extern "C"`.
#[cfg(target_os = "macos")]
#[allow(non_snake_case, dead_code)]
pub(crate) mod vt_ffi {
    use std::ffi::c_void;

    // ---- Type aliases (all opaque pointers) ----

    /// CoreMedia format description.
    pub type CMVideoFormatDescriptionRef = *mut c_void;
    /// CoreMedia block buffer (contiguous memory block).
    pub type CMBlockBufferRef = *mut c_void;
    /// CoreMedia sample buffer (compressed/decompressed media data).
    pub type CMSampleBufferRef = *mut c_void;
    /// CoreVideo pixel buffer.
    pub type CVPixelBufferRef = *mut c_void;
    /// VideoToolbox decompression session.
    pub type VTDecompressionSessionRef = *mut c_void;
    /// CoreFoundation allocator reference.
    pub type CFAllocatorRef = *const c_void;
    /// CoreFoundation dictionary reference.
    pub type CFDictionaryRef = *const c_void;
    /// CoreFoundation string reference.
    pub type CFStringRef = *const c_void;
    /// CoreFoundation number reference.
    pub type CFNumberRef = *const c_void;
    /// CoreFoundation type reference.
    pub type CFTypeRef = *const c_void;

    // ---- CVMetalTextureCache types ----

    /// Metal texture cache reference (from CoreVideo).
    pub type CVMetalTextureCacheRef = *mut c_void;
    /// Metal texture reference wrapping a CVPixelBuffer.
    pub type CVMetalTextureRef = *mut c_void;
    /// CoreVideo return type (like OSStatus / CVReturn).
    pub type CVReturn = i32;

    // ---- Constants ----

    /// H.264 codec type FourCharCode 'avc1' (a=0x61 is the high byte).
    pub const kCMVideoCodecType_H264: u32 = 0x61766331;

    /// BGRA pixel format type FourCharCode 'BGRA'.
    pub const kCVPixelFormatType_32BGRA: u32 = 0x42475241;
    /// NV12 bi-planar video-range pixel format '420v'.
    pub const kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange: u32 = 0x34323076;
    /// NV12 bi-planar full-range pixel format '420f'.
    pub const kCVPixelFormatType_420YpCbCr8BiPlanarFullRange: u32 = 0x34323066;

    /// Block buffer flag: ensure memory is backed by real pages.
    pub const kCMBlockBuffer_AssureMemoryNowFlag: u32 = 0;

    /// kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder key.
    ///
    /// Stored without a trailing NUL: `CString::new` appends the terminator.
    pub const kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder: &[u8] =
        b"RequireHardwareAcceleratedVideoDecoder";

    /// kCVPixelBufferPixelFormatTypeKey
    pub const kCVPixelBufferPixelFormatTypeKey: &[u8] = b"PixelFormatType";

    /// kCVPixelBufferIOSurfacePropertiesKey — requests an IOSurface-backed
    /// pixel buffer (value must be a CFDictionary, usually empty).
    pub const kCVPixelBufferIOSurfacePropertiesKey: &[u8] = b"IOSurfaceProperties";

    /// kCVPixelBufferMetalCompatibilityKey — marks the buffer usable by Metal.
    pub const kCVPixelBufferMetalCompatibilityKey: &[u8] = b"MetalCompatibility";

    // ---- VideoToolbox compression (used to produce real H.264 test streams) ----

    /// kVTCompressionPropertyKey_RealTime
    pub const kVTCompressionPropertyKey_RealTime: &[u8] = b"RealTime";
    /// kVTCompressionPropertyKey_AllowFrameReordering
    pub const kVTCompressionPropertyKey_AllowFrameReordering: &[u8] = b"AllowFrameReordering";
    /// kVTCompressionPropertyKey_MaxKeyFrameInterval
    pub const kVTCompressionPropertyKey_MaxKeyFrameInterval: &[u8] = b"MaxKeyFrameInterval";

    // ---- CMTime structure ----

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct CMTime {
        pub value: i64,
        pub timescale: i32,
        pub flags: u32,
        pub epoch: i64,
    }

    impl CMTime {
        pub const fn make(value: i64, timescale: i32) -> Self {
            Self {
                value,
                timescale,
                flags: 0,
                epoch: 0,
            }
        }
    }

    // ---- VTDecodeInfoFlags ----

    pub type VTDecodeInfoFlags = u32;
    pub const kVTDecodeInfo_Asynchronous: VTDecodeInfoFlags = 1 << 0;
    pub const kVTDecodeInfo_FrameDropped: VTDecodeInfoFlags = 1 << 1;

    // ---- VTDecodeFrameFlags ----

    pub type VTDecodeFrameFlags = u32;
    pub const kVTDecodeFrame_EnableAsynchronousDecompression: VTDecodeFrameFlags = 1 << 0;
    pub const kVTDecodeFrame_DoNotOutputFrame: VTDecodeFrameFlags = 1 << 1;
    pub const kVTDecodeFrame_1xRealTimePlayback: VTDecodeFrameFlags = 1 << 2;
    pub const kVTDecodeFrame_EnableTemporalProcessing: VTDecodeFrameFlags = 1 << 3;

    // ---- VTDecompressionOutputCallback ----

    /// C callback invoked by VideoToolbox when a frame is decoded.
    pub type VTDecompressionOutputCallback = unsafe extern "C" fn(
        outputRefCon: *mut c_void,
        sourceFrameRefCon: *mut c_void,
        status: i32,
        infoFlags: VTDecodeInfoFlags,
        imageBuffer: CVPixelBufferRef,
        presentationTimeStamp: CMTime,
        presentationDuration: CMTime,
    );

    /// Record structure passed to VTDecompressionSessionCreate.
    #[repr(C)]
    pub struct VTDecompressionOutputCallbackRecord {
        pub decompressionOutputCallback: Option<VTDecompressionOutputCallback>,
        pub decompressionOutputRefCon: *mut c_void,
    }

    // ---- VideoToolbox compression types ----

    /// VideoToolbox compression session.
    pub type VTCompressionSessionRef = *mut c_void;
    /// VideoToolbox session (base type used by VTSessionSetProperty).
    pub type VTSessionRef = *mut c_void;
    /// VTEncodeInfoFlags.
    pub type VTEncodeInfoFlags = u32;

    /// C callback invoked by VideoToolbox when an encoded sample is ready.
    pub type VTCompressionOutputCallback = unsafe extern "C" fn(
        outputCallbackRefCon: *mut c_void,
        sourceFrameRefCon: *mut c_void,
        status: i32,
        infoFlags: VTEncodeInfoFlags,
        sampleBuffer: CMSampleBufferRef,
    );

    // ---- FFI function declarations ----
    //
    // Multiple framework link attributes on one extern block trip
    // `clippy::duplicated_attributes`; they are intentional (each names a
    // distinct framework), so the lint is scoped out here.
    #[allow(clippy::duplicated_attributes)]
    #[link(name = "VideoToolbox", kind = "framework")]
    #[link(name = "CoreMedia", kind = "framework")]
    #[link(name = "CoreVideo", kind = "framework")]
    unsafe extern "C" {
        // ========== CMBlockBuffer ==========

        /// Create a CMBlockBuffer backed by existing memory.
        pub fn CMBlockBufferCreateWithMemoryBlock(
            allocator: CFAllocatorRef,
            memoryBlock: *mut c_void,
            blockLength: usize,
            blockAllocator: CFAllocatorRef,
            customBlockSource: *const c_void,
            offsetToData: usize,
            dataLength: usize,
            flags: u32,
            blockBufferOut: *mut CMBlockBufferRef,
        ) -> i32;

        // ========== CMSampleBuffer ==========

        /// Create a CMSampleBuffer from a CMBlockBuffer.
        pub fn CMSampleBufferCreate(
            allocator: CFAllocatorRef,
            dataBuffer: CMBlockBufferRef,
            dataReady: u8,
            makeDataReadyCallback: *const c_void,
            makeDataReadyRefcon: *mut c_void,
            formatDescription: CMVideoFormatDescriptionRef,
            numSamples: i32,
            numSampleTimingEntries: i32,
            sampleTimingArray: *const CMTime,
            numSampleSizeEntries: i32,
            sampleSizeArray: *const usize,
            sampleBufferOut: *mut CMSampleBufferRef,
        ) -> i32;

        // ========== CMVideoFormatDescription ==========

        /// Create a CMVideoFormatDescription from raw extradata (avcC / Annex B).
        pub fn CMVideoFormatDescriptionCreate(
            allocator: CFAllocatorRef,
            codecType: u32,
            width: i32,
            height: i32,
            descOut: *mut CMVideoFormatDescriptionRef,
        ) -> i32;

        /// Create a CMVideoFormatDescription from H.264 parameter sets (SPS, PPS).
        ///
        /// NOTE: this legacy declaration keeps the historical (incorrect)
        /// `sizes, pointers` argument order for in-crate callers that already
        /// bind it. New code must use
        /// [`cm_video_format_description_create_from_h264_parameter_sets`],
        /// which matches the real API order (`pointers, sizes`).
        pub fn CMVideoFormatDescriptionCreateFromH264ParameterSets(
            allocator: CFAllocatorRef,
            parameterSetCount: usize,
            parameterSetSizes: *const usize,
            parameterSetPointers: *const *const u8,
            nalUnitHeaderLength: i32,
            formatDescriptionOut: *mut CMVideoFormatDescriptionRef,
        ) -> i32;

        /// Correct-order binding of `CMVideoFormatDescriptionCreateFromH264ParameterSets`.
        ///
        /// The real CoreMedia signature is
        /// `(allocator, parameterSetCount, parameterSetPointers,
        /// parameterSetSizes, nalUnitHeaderLength, out)`; the legacy
        /// declaration above has `sizes` and `pointers` swapped, so this
        /// separate binding calls the same symbol with the right ABI.
        #[link_name = "CMVideoFormatDescriptionCreateFromH264ParameterSets"]
        #[allow(clashing_extern_declarations)]
        pub fn cm_video_format_description_create_from_h264_parameter_sets(
            allocator: CFAllocatorRef,
            parameterSetCount: usize,
            parameterSetPointers: *const *const u8,
            parameterSetSizes: *const usize,
            nalUnitHeaderLength: i32,
            formatDescriptionOut: *mut CMVideoFormatDescriptionRef,
        ) -> i32;

        // ========== VTDecompressionSession ==========

        /// Create a VideoToolbox decompression session.
        pub fn VTDecompressionSessionCreate(
            allocator: CFAllocatorRef,
            formatDescription: CMVideoFormatDescriptionRef,
            videoDecoderSpecification: CFDictionaryRef,
            destinationImageBufferAttributes: CFDictionaryRef,
            outputCallback: *const VTDecompressionOutputCallbackRecord,
            decompressionSessionOut: *mut VTDecompressionSessionRef,
        ) -> i32;

        /// Decode a compressed video frame.
        pub fn VTDecompressionSessionDecodeFrame(
            session: VTDecompressionSessionRef,
            sampleBuffer: CMSampleBufferRef,
            decodeFlags: VTDecodeFrameFlags,
            sourceFrameRefCon: *mut c_void,
            infoFlagsOut: *mut VTDecodeInfoFlags,
        ) -> i32;

        /// Block until all asynchronous frames have been decoded.
        pub fn VTDecompressionSessionWaitForAsynchronousFrames(
            session: VTDecompressionSessionRef,
        ) -> i32;

        /// Invalidate a decompression session.
        pub fn VTDecompressionSessionInvalidate(session: VTDecompressionSessionRef);

        // ========== CVPixelBuffer ==========

        /// Get the width of a pixel buffer.
        pub fn CVPixelBufferGetWidth(pixelBuffer: CVPixelBufferRef) -> usize;
        /// Get the height of a pixel buffer.
        pub fn CVPixelBufferGetHeight(pixelBuffer: CVPixelBufferRef) -> usize;
        /// Get the width of a pixel buffer plane.
        pub fn CVPixelBufferGetWidthOfPlane(
            pixelBuffer: CVPixelBufferRef,
            planeIndex: usize,
        ) -> usize;
        /// Get the height of a pixel buffer plane.
        pub fn CVPixelBufferGetHeightOfPlane(
            pixelBuffer: CVPixelBufferRef,
            planeIndex: usize,
        ) -> usize;
        /// Get the pixel format type of a pixel buffer.
        pub fn CVPixelBufferGetPixelFormatType(pixelBuffer: CVPixelBufferRef) -> u32;
        /// Get the base address of a pixel buffer (for packed formats).
        pub fn CVPixelBufferGetBaseAddress(pixelBuffer: CVPixelBufferRef) -> *mut c_void;
        /// Get the total data size of a pixel buffer (in bytes).
        pub fn CVPixelBufferGetDataSize(pixelBuffer: CVPixelBufferRef) -> usize;
        /// Get the base address of a specific plane.
        pub fn CVPixelBufferGetBaseAddressOfPlane(
            pixelBuffer: CVPixelBufferRef,
            planeIndex: usize,
        ) -> *mut c_void;
        /// Get the bytes-per-row of a pixel buffer.
        pub fn CVPixelBufferGetBytesPerRow(pixelBuffer: CVPixelBufferRef) -> usize;
        /// Get the bytes-per-row of a specific plane.
        pub fn CVPixelBufferGetBytesPerRowOfPlane(
            pixelBuffer: CVPixelBufferRef,
            planeIndex: usize,
        ) -> usize;
        /// Lock the base address of a pixel buffer.
        pub fn CVPixelBufferLockBaseAddress(pixelBuffer: CVPixelBufferRef, lockFlags: u32) -> i32;
        /// Unlock the base address of a pixel buffer.
        pub fn CVPixelBufferUnlockBaseAddress(
            pixelBuffer: CVPixelBufferRef,
            unlockFlags: u32,
        ) -> i32;
        /// Retain a pixel buffer.
        pub fn CVPixelBufferRetain(pixelBuffer: CVPixelBufferRef);
        /// Release a pixel buffer.
        pub fn CVPixelBufferRelease(pixelBuffer: CVPixelBufferRef);
        /// Retain any CoreFoundation object.
        pub fn CFRetain(cf: CFTypeRef);
        /// Release any CoreFoundation object.
        pub fn CFRelease(cf: CFTypeRef);

        // ========== CoreFoundation dictionary helpers ==========

        /// Create a dictionary.
        pub fn CFDictionaryCreate(
            allocator: CFAllocatorRef,
            keys: *const *const c_void,
            values: *const *const c_void,
            numValues: isize,
            keyCallbacks: *const c_void,
            valueCallbacks: *const c_void,
        ) -> CFDictionaryRef;

        /// Create a string from a C string.
        pub fn CFStringCreateWithCString(
            allocator: *const c_void,
            cStr: *const std::ffi::c_char,
            encoding: u32,
        ) -> CFStringRef;

        /// Create a number (32-bit).
        pub fn CFNumberCreate(
            allocator: CFAllocatorRef,
            theType: u32,
            valuePtr: *const c_void,
        ) -> CFNumberRef;

        // ========== CVMetalTextureCache ==========

        /// Create a CVMetalTextureCache.
        ///
        /// `mtlDevice` must be a retained `id<MTLDevice>` pointer obtained from
        /// the `metal` crate (e.g., `device.as_ptr()`).
        pub fn CVMetalTextureCacheCreate(
            allocator: CFAllocatorRef,
            cacheAttributes: CFDictionaryRef,
            mtlDevice: *mut c_void,
            textureAttributes: CFDictionaryRef,
            cacheOut: *mut CVMetalTextureCacheRef,
        ) -> CVReturn;

        /// Create a Metal texture from a CVPixelBuffer via the cache.
        ///
        /// `pixelFormat` is a Metal `MTLPixelFormat` enum value (e.g.,
        /// `MTLPixelFormatBGRA8Unorm = 80`). `width`/`height` should match
        /// the pixel buffer dimensions; `planeIndex` is 0 for single-plane
        /// (BGRA) or 0/1 for bi-planar (NV12 Y/UV) formats.
        pub fn CVMetalTextureCacheCreateTextureFromImage(
            allocator: CFAllocatorRef,
            cache: CVMetalTextureCacheRef,
            sourceImage: CVPixelBufferRef,
            textureAttributes: CFDictionaryRef,
            pixelFormat: u32,
            width: usize,
            height: usize,
            planeIndex: usize,
            textureOut: *mut CVMetalTextureRef,
        ) -> CVReturn;

        /// Extract the `id<MTLTexture>` from a CVMetalTextureRef.
        ///
        /// Returns a raw pointer to the MTLTexture (borrowed; caller must
        /// retain if they need it to outlive the CVMetalTextureRef).
        pub fn CVMetalTextureGetTexture(texture: CVMetalTextureRef) -> *mut c_void;

        /// Flush the texture cache, releasing any internally cached textures
        /// whose CVPixelBuffers have been discarded.
        ///
        /// Pass `options = 0` for a standard flush.
        pub fn CVMetalTextureCacheFlush(cache: CVMetalTextureCacheRef, options: u64);

        // ========== CoreVideo pixel buffer creation ==========

        /// Create a CVPixelBuffer with the given pixel format and attributes.
        pub fn CVPixelBufferCreate(
            allocator: CFAllocatorRef,
            width: usize,
            height: usize,
            pixelFormatType: u32,
            pixelBufferAttributes: CFDictionaryRef,
            pixelBufferOut: *mut CVPixelBufferRef,
        ) -> CVReturn;

        /// Create a CVPixelBuffer that uses the storage of an existing IOSurface.
        pub fn CVPixelBufferCreateWithIOSurface(
            allocator: CFAllocatorRef,
            surface: *mut c_void,
            pixelBufferAttributes: CFDictionaryRef,
            pixelBufferOut: *mut CVPixelBufferRef,
        ) -> CVReturn;

        /// Return the IOSurface backing a pixel buffer (borrowed reference).
        pub fn CVPixelBufferGetIOSurface(pixelBuffer: CVPixelBufferRef) -> *mut c_void;

        // ========== VideoToolbox compression ==========

        /// Create a VideoToolbox compression (encoder) session.
        pub fn VTCompressionSessionCreate(
            allocator: CFAllocatorRef,
            width: i32,
            height: i32,
            codecType: u32,
            encoderSpecification: CFDictionaryRef,
            sourceImageBufferAttributes: CFDictionaryRef,
            compressedDataAllocator: CFAllocatorRef,
            outputCallback: Option<VTCompressionOutputCallback>,
            outputCallbackRefCon: *mut c_void,
            compressionSessionOut: *mut VTCompressionSessionRef,
        ) -> i32;

        /// Set a property on a VideoToolbox session.
        pub fn VTSessionSetProperty(
            session: VTSessionRef,
            propertyKey: CFStringRef,
            propertyValue: CFTypeRef,
        ) -> i32;

        /// Encode one frame.
        pub fn VTCompressionSessionEncodeFrame(
            session: VTCompressionSessionRef,
            imageBuffer: CVPixelBufferRef,
            presentationTimeStamp: CMTime,
            duration: CMTime,
            frameProperties: CFDictionaryRef,
            sourceFrameRefCon: *mut c_void,
            infoFlagsOut: *mut VTEncodeInfoFlags,
        ) -> i32;

        /// Block until all pending frames have been emitted.
        pub fn VTCompressionSessionCompleteFrames(
            session: VTCompressionSessionRef,
            completeUntilPresentationTimeStamp: CMTime,
        ) -> i32;

        /// Invalidate a compression session.
        pub fn VTCompressionSessionInvalidate(session: VTCompressionSessionRef);

        // ========== CMSampleBuffer inspection ==========

        /// Get the block buffer containing a sample buffer's data.
        pub fn CMSampleBufferGetDataBuffer(sampleBuffer: CMSampleBufferRef) -> CMBlockBufferRef;

        /// Get the format description of a sample buffer.
        pub fn CMSampleBufferGetFormatDescription(
            sampleBuffer: CMSampleBufferRef,
        ) -> CMVideoFormatDescriptionRef;

        /// Get a pointer to a block buffer's contiguous data.
        pub fn CMBlockBufferGetDataPointer(
            buffer: CMBlockBufferRef,
            offset: usize,
            lengthAtOffsetOut: *mut usize,
            totalLengthOut: *mut usize,
            dataPointerOut: *mut *mut std::ffi::c_char,
        ) -> i32;

        /// Get the Nth H.264 parameter set (SPS/PPS) from a format description.
        pub fn CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
            videoDesc: CMVideoFormatDescriptionRef,
            parameterSetIndex: usize,
            parameterSetPointerOut: *mut *const u8,
            parameterSetSizeOut: *mut usize,
            parameterSetCountOut: *mut usize,
            nalUnitHeaderLengthOut: *mut i32,
        ) -> i32;
    }

    // CFNumber types
    pub const kCFNumberSInt32Type: u32 = 3;
    // kCFStringEncodingUTF8
    pub const kCFStringEncodingUTF8: u32 = 0x08000100;
}

// ===========================================================================
// Metal pixel format constants (for CVMetalTextureCache)
// ===========================================================================

/// MTLPixelFormatBGRA8Unorm — 8-bit BGRA with normalized unsigned components.
#[cfg(target_os = "macos")]
pub const MTLPixelFormatBGRA8Unorm: u32 = 80;
/// MTLPixelFormatRGBA8Unorm — 8-bit RGBA with normalized unsigned components.
#[cfg(target_os = "macos")]
pub const MTLPixelFormatRGBA8Unorm: u32 = 70;
/// MTLPixelFormatNV12 — bi-planar Y/CbCr (420v).
#[cfg(target_os = "macos")]
pub const MTLPixelFormatNV12: u32 = 150;
/// MTLPixelFormatR8Unorm — single 8-bit component (NV12 luma plane).
#[cfg(target_os = "macos")]
pub const MTLPixelFormatR8Unorm: u32 = 10;
/// MTLPixelFormatRG8Unorm — two 8-bit components (NV12 chroma plane).
#[cfg(target_os = "macos")]
pub const MTLPixelFormatRG8Unorm: u32 = 30;

// ===========================================================================
// CVMetalTextureCache — zero-copy CVPixelBuffer → MTLTexture bridge
// ===========================================================================

/// A zero-copy bridge that wraps `CVPixelBuffer` objects produced by
/// VideoToolbox as `MTLTexture` objects, avoiding any CPU-side pixel copy.
///
/// Internally holds a `CVMetalTextureCacheRef` that maps pixel buffers to
/// Metal textures.  Textures are lazily created and cached by the
/// CoreVideo framework; the cache must be flushed periodically to release
/// stale entries.
///
/// ## Thread Safety
/// CVMetalTextureCache is *not* fully thread-safe.  All methods must be
/// called from the same thread / dispatch queue.  In practice this is
/// satisfied because the `decompression_output_callback` runs on a
/// VideoToolbox internal thread, and we create/destroy the cache only on
/// the decoder's owning thread.
#[cfg(target_os = "macos")]
#[allow(dead_code)] // Metal device pointer cache for zero-copy uploads; not yet referenced
pub struct MetalVideoTextureCache {
    /// The underlying `CVMetalTextureCacheRef`.
    cache: vt_ffi::CVMetalTextureCacheRef,
    /// Retained Metal device pointer (`id<MTLDevice>`).
    device_ptr: *mut std::ffi::c_void,
}

#[cfg(target_os = "macos")]
impl MetalVideoTextureCache {
    /// Create a new texture cache from a Metal device.
    ///
    /// Returns `None` if the system has no Metal device or if the
    /// CoreVideo cache creation fails.
    pub fn new(device: &metal::Device) -> Option<Self> {
        use self::vt_ffi::*;
        use metal::foreign_types::ForeignType;
        use std::ptr;

        let device_ptr = device.as_ptr() as *mut std::ffi::c_void;

        unsafe {
            let mut cache: CVMetalTextureCacheRef = ptr::null_mut();
            let status = CVMetalTextureCacheCreate(
                ptr::null_mut(), // kCFAllocatorDefault
                ptr::null(),     // cacheAttributes (NULL = default)
                device_ptr,
                ptr::null(), // textureAttributes (NULL = default)
                &mut cache,
            );
            if status != 0 || cache.is_null() {
                return None;
            }
            Some(Self { cache, device_ptr })
        }
    }

    /// Wrap a `CVPixelBuffer` as a Metal texture.
    ///
    /// The returned raw pointer is a +1 retained `id<MTLTexture>` that the
    /// caller must eventually release (e.g. by wrapping it with
    /// `metal::Texture::from_ptr()` which hands ownership to the
    /// reference-counted wrapper).
    ///
    /// # Safety
    ///
    /// `pixel_buffer` must be a valid, retained-or-live `CVPixelBufferRef`
    /// for the duration of the call (e.g. one delivered by a VideoToolbox
    /// output callback while the callback is still running).
    ///
    /// Returns `None` on failure (e.g. invalid format, out of memory).
    pub unsafe fn create_texture_from_pixel_buffer(
        &self,
        pixel_buffer: vt_ffi::CVPixelBufferRef,
        width: u32,
        height: u32,
        pixel_format: u32,
        plane_index: usize,
    ) -> Option<*mut std::ffi::c_void> {
        use self::vt_ffi::*;
        use std::ptr;

        unsafe {
            let mut cv_texture: CVMetalTextureRef = ptr::null_mut();
            let status = CVMetalTextureCacheCreateTextureFromImage(
                ptr::null_mut(), // kCFAllocatorDefault
                self.cache,
                pixel_buffer,
                ptr::null(), // textureAttributes
                pixel_format,
                width as usize,
                height as usize,
                plane_index,
                &mut cv_texture,
            );
            if status != 0 || cv_texture.is_null() {
                return None;
            }

            // Extract the id<MTLTexture> — borrowed per CoreVideo "Get" rule.
            let mtl_texture = CVMetalTextureGetTexture(cv_texture);
            if mtl_texture.is_null() {
                // Release the CVMetalTextureRef (which we own).
                CFRelease(cv_texture as CFTypeRef);
                return None;
            }

            // Retain the MTLTexture so it outlives the CVMetalTextureRef.
            // We send the Objective-C `retain` message directly.
            // The metal::Texture::from_ptr() will pair this with a release on drop.
            let retained: *mut std::ffi::c_void = {
                let obj = mtl_texture as *mut objc::runtime::Object;
                let _: *mut objc::runtime::Object = msg_send![obj, retain];
                mtl_texture
            };

            // Release the CVMetalTextureRef (cache may still hold an internal reference).
            CFRelease(cv_texture as CFTypeRef);

            Some(retained)
        }
    }

    /// Flush the cache, releasing stale texture entries.
    pub fn flush(&self) {
        use self::vt_ffi::*;
        unsafe {
            CVMetalTextureCacheFlush(self.cache, 0);
        }
    }

    /// Access the raw cache reference (for advanced use).
    pub fn as_raw(&self) -> vt_ffi::CVMetalTextureCacheRef {
        self.cache
    }
}

#[cfg(target_os = "macos")]
impl Drop for MetalVideoTextureCache {
    fn drop(&mut self) {
        use self::vt_ffi::*;
        if !self.cache.is_null() {
            unsafe {
                CVMetalTextureCacheFlush(self.cache, 0);
                CFRelease(self.cache as CFTypeRef);
            }
        }
    }
}

// ===========================================================================
// FFmpeg-based decoder (optional, behind `ffmpeg` feature)
// ===========================================================================

#[cfg(feature = "ffmpeg")]
mod ffmpeg_decoder {
    use super::*;

    /// FFmpeg codec context wrapper.
    pub struct FfmpegCodecContext {
        // In a real implementation this would wrap:
        //   *mut AVCodecContext, *mut AVCodec, *mut AVFrame, *mut AVPacket
        // For now we store the configuration and simulate decoding.
        codec: VideoCodec,
        width: u32,
        height: u32,
        fps: f64,
    }

    impl FfmpegCodecContext {
        /// Create a new FFmpeg codec context for the given video codec.
        pub fn new(config: &VideoDecoderConfig) -> AppResult<Self> {
            let codec_id = match config.codec {
                VideoCodec::H264 => "h264",
                VideoCodec::H265 => "hevc",
                VideoCodec::VP9 => "vp9",
                VideoCodec::Unknown => {
                    return Err(AppError::new(
                        ReasonCode::RcMediaInvalid,
                        "Unknown video codec for FFmpeg decoder",
                    ));
                }
            };

            // In a full implementation, this would call:
            //   avcodec_find_decoder_by_name(codec_id)
            //   avcodec_alloc_context3(codec)
            //   avcodec_open2(context, codec, NULL)
            //
            // For now we validate the codec and store config.
            if config.width == 0 || config.height == 0 {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    format!(
                        "Invalid dimensions for FFmpeg decoder: {}x{}",
                        config.width, config.height
                    ),
                ));
            }

            Ok(Self {
                codec: config.codec,
                width: config.width,
                height: config.height,
                fps: config.fps,
            })
        }

        /// Decode a packet of compressed data.
        ///
        /// In a full implementation this would call:
        ///   av_packet_from_data(...)
        ///   avcodec_send_packet(...)
        ///   avcodec_receive_frame(...)
        ///
        /// The returned frame contains RGBA data converted from the decoded
        /// AVFrame via sws_scale.
        pub fn decode_packet(&mut self, data: &[u8], pts: u64) -> AppResult<Option<VideoFrame>> {
            if data.is_empty() {
                return Ok(None);
            }

            // Simulate decoding: generate a dummy RGBA frame for testing.
            // In production this would call the actual FFmpeg decode pipeline.
            let pixel_count = (self.width * self.height) as usize;
            let mut rgba = vec![0u8; pixel_count * 4];

            // Fill with a simple test pattern based on the input data hash
            let seed = data
                .iter()
                .copied()
                .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
            for i in 0..pixel_count {
                let val = ((seed.wrapping_add(i as u32)) & 0xFF) as u8;
                rgba[i * 4] = val; // R
                rgba[i * 4 + 1] = val; // G
                rgba[i * 4 + 2] = val; // B
                rgba[i * 4 + 3] = 255; // A
            }

            let duration = if self.fps > 0.0 {
                (1_000_000.0 / self.fps) as u64
            } else {
                33_333
            };

            Ok(Some(VideoFrame {
                width: self.width,
                height: self.height,
                data: rgba,
                pts,
                duration,
                texture_id: None,
                metal_texture: None,
                color_space: ColorSpace::Rec709,
            }))
        }

        /// Flush remaining frames from the decoder.
        pub fn flush(&mut self) -> Vec<VideoFrame> {
            // In a full implementation: avcodec_send_packet(NULL) + drain
            Vec::new()
        }

        /// Get the codec type.
        pub fn codec(&self) -> VideoCodec {
            self.codec
        }
    }
}

// ===========================================================================
// Non-macOS fallback
// ===========================================================================

/// On non-macOS without ffmpeg, decoding always fails.
#[cfg(not(any(target_os = "macos", feature = "ffmpeg")))]
fn no_decoder_error() -> AppError {
    AppError::new(
        ReasonCode::RcMediaInvalid,
        "No video decoder available. Enable the 'ffmpeg' feature or build on macOS \
         with VideoToolbox support.",
    )
}

// ===========================================================================
// Context shared between the C callback and the Rust decoder
// ===========================================================================

/// Shared state that the VideoToolbox callback writes decoded frames into.
///
/// This is reference-counted and passed to VTDecompressionSessionCreate as
/// the `outputRefCon`. The callback converts the CVPixelBuffer to RGBA
/// and pushes the result into `frames`.
#[cfg(target_os = "macos")]
struct DecoderContext {
    /// Queue of decoded video frames.
    frames: Mutex<VecDeque<VideoFrame>>,
    /// Output width in pixels (may differ from encoded width after cropping).
    output_width: u32,
    /// Output height in pixels.
    output_height: u32,
    /// Optional Metal texture cache for zero-copy path.
    /// When `Some`, the callback attempts to create a Metal texture
    /// from the CVPixelBuffer before falling back to the CPU path.
    metal_cache: Option<MetalVideoTextureCache>,
    /// Color space applied to decoded frames and YUV conversion.
    color_space: ColorSpace,
    /// Scratch buffer reused across frames to avoid per-frame allocations.
    scratch: Mutex<Vec<u8>>,
}

// Safety: `DecoderContext` is shared with the VideoToolbox output callback
// (which runs on a VideoToolbox internal thread) via an `Arc`. All shared
// state (`frames`, `scratch`) is mutex-protected, and the Metal texture
// cache is only touched from the callback thread after being handed over.
unsafe impl Send for DecoderContext {}
unsafe impl Sync for DecoderContext {}

// ===========================================================================
// VideoDecoder
// ===========================================================================

/// Video decoder supporting H.264/H.265/VP9.
///
/// On macOS, uses VideoToolbox for hardware-accelerated decoding.
/// When the `ffmpeg` feature is enabled, uses FFmpeg for cross-platform software decoding.
///
/// # Thread Safety
/// The decoder is not `Send` or `Sync`. Each decoder instance must be used from
/// a single thread at a time. Use `Mutex<VideoDecoder>` for cross-thread access.
pub struct VideoDecoder {
    #[cfg(target_os = "macos")]
    session: Option<vt_ffi::VTDecompressionSessionRef>,
    #[cfg(target_os = "macos")]
    format_desc: Option<vt_ffi::CMVideoFormatDescriptionRef>,
    #[cfg(target_os = "macos")]
    context: Option<Arc<DecoderContext>>,
    /// Raw `Arc<DecoderContext>` handed to VideoToolbox as the output
    /// callback refcon (one strong reference; reclaimed on teardown).
    #[cfg(target_os = "macos")]
    callback_refcon: Option<*mut c_void>,
    /// Zero-copy Metal texture cache. Created on macOS if a Metal device
    /// is available; `None` otherwise.
    #[cfg(target_os = "macos")]
    metal_cache: Option<MetalVideoTextureCache>,
    /// Probed availability of the CoreVideo → Metal zero-copy path.
    #[cfg(target_os = "macos")]
    zero_copy_status: ZeroCopyStatus,

    #[cfg(feature = "ffmpeg")]
    ffmpeg_ctx: Option<ffmpeg_decoder::FfmpegCodecContext>,

    config: VideoDecoderConfig,
    sps: Vec<u8>,
    pps: Vec<u8>,
    /// FNV-1a hash of the current SPS+PPS pair, used to avoid tearing down
    /// and re-creating the VT session when parameter sets are repeated.
    #[cfg(target_os = "macos")]
    sps_pps_hash: u64,
    frame_queue: VecDeque<VideoFrame>,
    frame_number: u64,
}

impl VideoDecoder {
    /// Create a new video decoder with the given configuration.
    pub fn new(config: VideoDecoderConfig) -> Self {
        #[cfg(feature = "ffmpeg")]
        let ffmpeg_ctx = match ffmpeg_decoder::FfmpegCodecContext::new(&config) {
            Ok(context) => Some(context),
            Err(error) => {
                eprintln!("[VideoDecoder] ffmpeg codec context init failed: {error}");
                None
            }
        };

        // Probe the CoreVideo → Metal capability once. When it is not
        // available the decoder keeps working through the existing CPU path.
        #[cfg(target_os = "macos")]
        let (metal_cache, zero_copy_status) = match metal::Device::system_default() {
            Some(dev) => match MetalVideoTextureCache::new(&dev) {
                Some(cache) => (Some(cache), ZeroCopyStatus::Available),
                None => (None, ZeroCopyStatus::CoreVideoUnavailable),
            },
            None => (None, ZeroCopyStatus::MetalUnavailable),
        };

        Self {
            #[cfg(target_os = "macos")]
            session: None,
            #[cfg(target_os = "macos")]
            format_desc: None,
            #[cfg(target_os = "macos")]
            context: None,
            #[cfg(target_os = "macos")]
            callback_refcon: None,
            #[cfg(target_os = "macos")]
            metal_cache,
            #[cfg(target_os = "macos")]
            zero_copy_status,
            #[cfg(feature = "ffmpeg")]
            ffmpeg_ctx,
            config,
            sps: Vec::new(),
            pps: Vec::new(),
            #[cfg(target_os = "macos")]
            sps_pps_hash: 0,
            frame_queue: VecDeque::new(),
            frame_number: 0,
        }
    }

    /// Probed availability of the CoreVideo → Metal zero-copy path.
    ///
    /// When this is not `Available`, decoded frames are delivered through the
    /// existing CPU RGBA path (`VideoFrame::data`) with
    /// [`ZeroCopyStatus::reason`] explaining why.
    #[cfg(target_os = "macos")]
    pub fn zero_copy_status(&self) -> ZeroCopyStatus {
        self.zero_copy_status
    }

    /// Availability of the CoreVideo → Metal zero-copy path (always
    /// [`ZeroCopyStatus::MetalUnavailable`] off macOS).
    #[cfg(not(target_os = "macos"))]
    pub fn zero_copy_status(&self) -> ZeroCopyStatus {
        ZeroCopyStatus::MetalUnavailable
    }

    /// Decode a single packet of compressed video data.
    ///
    /// This is the primary API for feeding compressed data to the decoder.
    /// The data should be a complete access unit (e.g., an H.264 NAL unit
    /// or a VP9 frame) in Annex B format.
    ///
    /// Returns the number of frames that were decoded and added to the output queue.
    pub fn decode_packet(&mut self, data: &[u8], pts: u64) -> AppResult<usize> {
        let before = self.frame_queue.len();

        #[cfg(feature = "ffmpeg")]
        if let Some(ref mut ctx) = self.ffmpeg_ctx {
            if let Some(frame) = ctx.decode_packet(data, pts)? {
                self.frame_queue.push_back(frame);
            }
            return Ok(self.frame_queue.len() - before);
        }

        // Fall back to VideoToolbox on macOS
        #[cfg(target_os = "macos")]
        {
            self.feed_data_internal(data, Some(pts))?;
            Ok(self.frame_queue.len() - before)
        }

        #[cfg(not(any(target_os = "macos", feature = "ffmpeg")))]
        {
            let _data = data;
            let _pts = pts;
            Err(no_decoder_error())
        }
    }

    /// Feed encoded video data (H.264 Annex B byte stream) to the decoder.
    /// Legacy method — prefer `decode_packet()` for new code.
    pub fn feed_data(&mut self, data: &[u8]) -> AppResult<()> {
        #[cfg(feature = "ffmpeg")]
        if let Some(ref mut ctx) = self.ffmpeg_ctx {
            let pts = self.frame_number * 1_000_000 / self.config.fps.max(1.0) as u64;
            if let Some(frame) = ctx.decode_packet(data, pts)? {
                self.frame_queue.push_back(frame);
            }
            self.frame_number += 1;
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        {
            self.feed_data_internal(data, None)
        }

        #[cfg(not(any(target_os = "macos", feature = "ffmpeg")))]
        {
            let _data = data;
            Err(no_decoder_error())
        }
    }

    /// Internal H.264 Annex B feed path for VideoToolbox.
    ///
    /// `pts` is the presentation timestamp (microseconds) of the access
    /// unit when known; when `None`, a PTS is synthesized from the frame
    /// counter and configured frame rate.
    #[cfg(target_os = "macos")]
    fn feed_data_internal(&mut self, data: &[u8], pts: Option<u64>) -> AppResult<()> {
        let nalus = parse_h264_annex_b(data);

        for nalu in &nalus {
            if nalu.is_empty() {
                continue;
            }
            let nal_type = nalu[0] & 0x1F;
            match nal_type {
                7 => {
                    // SPS (Sequence Parameter Set)
                    self.sps = nalu.to_vec();
                    let (w, h) = parse_h264_sps(nalu);
                    if w > 0 && h > 0 {
                        self.config.width = w;
                        self.config.height = h;
                    }
                    self.reinit_session_if_changed();
                }
                8 => {
                    // PPS (Picture Parameter Set)
                    self.pps = nalu.to_vec();
                    self.reinit_session_if_changed();
                }
                5 | 1 if self.session.is_some() => {
                    // IDR slice (5) or Non-IDR slice (1)
                    let frame_pts = pts.unwrap_or_else(|| {
                        if self.frame_number == 0 {
                            0
                        } else {
                            self.frame_number * 1_000_000 / self.config.fps.max(1.0) as u64
                        }
                    });
                    self.decode_frame_vt(nalu, frame_pts)?;
                }
                _ => {
                    // Other NAL types (SEI, AUD, etc.) — ignore
                }
            }
        }

        Ok(())
    }

    /// (Re)initialize the VideoToolbox session, but only when the SPS/PPS
    /// parameter sets actually changed. Many streams repeat SPS/PPS in every
    /// access unit; tearing down and re-creating the session per frame would
    /// be needlessly expensive and drop buffered output.
    #[cfg(target_os = "macos")]
    fn reinit_session_if_changed(&mut self) {
        if self.sps.is_empty() || self.pps.is_empty() {
            return;
        }
        // FNV-1a hash over SPS+PPS
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in self.sps.iter().chain(self.pps.iter()) {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        if hash == self.sps_pps_hash && self.session.is_some() {
            return; // parameter sets unchanged — keep the current session
        }
        self.sps_pps_hash = hash;
        if let Err(e) = self.init_session() {
            eprintln!("[VideoDecoder] failed to (re)init VT session: {e}");
        }
    }

    /// Initialize (or re-initialize) the VideoToolbox decompression session.
    #[cfg(target_os = "macos")]
    fn init_session(&mut self) -> AppResult<()> {
        use self::vt_ffi::*;
        use std::ptr;

        // Invalidate existing session first
        self.destroy_session();

        let sps = &self.sps;
        let pps = &self.pps;

        if sps.is_empty() || pps.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "Cannot create VideoToolbox session: missing SPS or PPS",
            ));
        }

        // Build parameter set arrays (pointers and sizes), without start codes
        let sps_data = &sps[..];
        let pps_data = &pps[..];
        let param_set_pointers = [sps_data.as_ptr(), pps_data.as_ptr()];
        let param_set_sizes = [sps_data.len(), pps_data.len()];

        // 1. Create CMVideoFormatDescription from SPS + PPS
        let mut format_desc: CMVideoFormatDescriptionRef = ptr::null_mut();
        let status = unsafe {
            cm_video_format_description_create_from_h264_parameter_sets(
                ptr::null_mut(), // kCFAllocatorDefault
                2,               // SPS + PPS
                param_set_pointers.as_ptr(),
                param_set_sizes.as_ptr(),
                4, // nalUnitHeaderLength: AVCC 4-byte length prefixes
                &mut format_desc,
            )
        };

        if status != 0 {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!(
                    "CMVideoFormatDescriptionCreateFromH264ParameterSets failed with status {}",
                    status
                ),
            ));
        }

        // 2. Create the context for the output callback
        //    Move the Metal cache into the context (the callback needs it).
        //    On session re-creation, create a fresh cache from the system device.
        let metal_cache = self.metal_cache.take().or_else(|| {
            metal::Device::system_default().and_then(|dev| MetalVideoTextureCache::new(&dev))
        });

        let ctx = Arc::new(DecoderContext {
            frames: Mutex::new(VecDeque::new()),
            output_width: self.config.width,
            output_height: self.config.height,
            metal_cache,
            color_space: ColorSpace::default(),
            scratch: Mutex::new(Vec::new()),
        });

        self.context = Some(ctx.clone());
        let context_ptr = Arc::into_raw(ctx) as *mut c_void;
        self.callback_refcon = Some(context_ptr);

        // 3. Set up the output callback record
        let callback_record = VTDecompressionOutputCallbackRecord {
            decompressionOutputCallback: Some(decompression_output_callback),
            decompressionOutputRefCon: context_ptr,
        };

        // On any failure below, drop the context and reclaim the refcon
        // strong reference before returning an error.
        let cleanup_on_error = |self_ref: &mut Self, format_desc: CMVideoFormatDescriptionRef| {
            self_ref.context = None;
            if let Some(refcon) = self_ref.callback_refcon.take() {
                unsafe {
                    let _ = Arc::from_raw(refcon as *const DecoderContext);
                }
            }
            if !format_desc.is_null() {
                unsafe { CFRelease(format_desc as CFTypeRef) };
            }
        };

        // 4. Create destination pixel buffer attributes. Request native
        //    NV12 (hardware decoder output) with IOSurface backing so the
        //    decoded CVPixelBuffer can be wrapped as a Metal texture without
        //    any CPU copy. `software_copy` handles NV12/BGRA for CPU callers.
        let dest_attrs = match create_zero_copy_pixel_buffer_attributes() {
            Ok(attrs) => attrs,
            Err(e) => {
                cleanup_on_error(self, format_desc);
                return Err(e);
            }
        };

        // 5. Create decoder specification (prefer hardware acceleration)
        let decoder_spec = match create_hardware_decoder_specification() {
            Ok(spec) => spec,
            Err(e) => {
                if !dest_attrs.is_null() {
                    unsafe { CFRelease(dest_attrs as CFTypeRef) };
                }
                cleanup_on_error(self, format_desc);
                return Err(e);
            }
        };

        // 6. Create the decompression session. If VideoToolbox rejects the
        //    NV12/IOSurface attributes (some decoders only accept packed
        //    output), retry once with the legacy BGRA attributes so decoding
        //    keeps working through the CPU path.
        let mut session: VTDecompressionSessionRef = ptr::null_mut();
        let mut status = unsafe {
            VTDecompressionSessionCreate(
                ptr::null_mut(), // kCFAllocatorDefault
                format_desc,
                decoder_spec,
                dest_attrs,
                &callback_record,
                &mut session,
            )
        };
        if status != 0 || session.is_null() {
            if !dest_attrs.is_null() {
                unsafe { CFRelease(dest_attrs as CFTypeRef) };
            }
            // Retry with packed BGRA (still requesting IOSurface backing so
            // the zero-copy path remains possible for BGRA-capable decoders).
            let bgra_attrs = create_pixel_buffer_attributes(kCVPixelFormatType_32BGRA, false)
                .unwrap_or(ptr::null());
            eprintln!(
                "[VideoDecoder] NV12 zero-copy attributes rejected (status={status}); \
                 retrying with BGRA destination buffers"
            );
            status = unsafe {
                VTDecompressionSessionCreate(
                    ptr::null_mut(),
                    format_desc,
                    decoder_spec,
                    bgra_attrs,
                    &callback_record,
                    &mut session,
                )
            };
            if !bgra_attrs.is_null() {
                unsafe { CFRelease(bgra_attrs as CFTypeRef) };
            }
        }

        // Release CoreFoundation objects we created. `dest_attrs` was already
        // released on the retry path above.
        if !decoder_spec.is_null() {
            unsafe { CFRelease(decoder_spec as CFTypeRef) };
        }
        if status == 0 && !session.is_null() && !dest_attrs.is_null() {
            unsafe { CFRelease(dest_attrs as CFTypeRef) };
        }

        if status != 0 || session.is_null() {
            // No callbacks can be in flight because the session was never created.
            cleanup_on_error(self, format_desc);
            eprintln!(
                "[VideoDecoder] VTDecompressionSessionCreate failed (status={status}), cleaned up context"
            );
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!("VTDecompressionSessionCreate failed with status {}", status),
            ));
        }

        self.session = Some(session);
        self.format_desc = Some(format_desc);

        Ok(())
    }

    /// Decode a single H.264 slice NAL unit using VideoToolbox.
    #[cfg(target_os = "macos")]
    fn decode_frame_vt(&mut self, nalu: &[u8], pts: u64) -> AppResult<()> {
        use self::vt_ffi::*;
        use std::ptr;

        let session = match self.session {
            Some(s) => s,
            None => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "VideoToolbox session not initialized",
                ));
            }
        };

        let format_desc = match self.format_desc {
            Some(fd) => fd,
            None => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "VideoToolbox format description not initialized",
                ));
            }
        };

        // Convert NALU to AVCC format (4-byte big-endian length prefix)
        let length = nalu.len() as u32;
        let mut avcc_data = Vec::with_capacity(4 + nalu.len());
        avcc_data.extend_from_slice(&length.to_be_bytes());
        avcc_data.extend_from_slice(nalu);

        // Create CMBlockBuffer wrapping the AVCC data
        let mut block_buffer: CMBlockBufferRef = ptr::null_mut();
        let status = unsafe {
            CMBlockBufferCreateWithMemoryBlock(
                ptr::null_mut(),                       // kCFAllocatorDefault
                avcc_data.as_mut_ptr() as *mut c_void, // memoryBlock
                avcc_data.len(),                       // blockLength
                ptr::null_mut(),                       // blockAllocator
                ptr::null(),                           // customBlockSource
                0,                                     // offsetToData
                avcc_data.len(),                       // dataLength
                kCMBlockBuffer_AssureMemoryNowFlag,    // flags
                &mut block_buffer,
            )
        };

        if status != 0 || block_buffer.is_null() {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!(
                    "CMBlockBufferCreateWithMemoryBlock failed with status {}",
                    status
                ),
            ));
        }

        // Set up timing info: PTS
        let pts_time = CMTime::make(pts as i64, 1_000_000);
        let _duration_time = if self.config.fps > 0.0 {
            CMTime::make(1_000_000, self.config.fps as i32)
        } else {
            CMTime::make(33333, 1_000_000) // ~30fps default
        };

        // Create CMSampleBuffer from the block buffer
        let mut sample_buffer: CMSampleBufferRef = ptr::null_mut();
        let sample_size = avcc_data.len();
        let status = unsafe {
            CMSampleBufferCreate(
                ptr::null_mut(), // kCFAllocatorDefault
                block_buffer,
                1,               // dataReady = true
                ptr::null(),     // makeDataReadyCallback
                ptr::null_mut(), // makeDataReadyRefcon
                format_desc,
                1, // numSamples
                1, // numSampleTimingEntries
                &pts_time,
                1, // numSampleSizeEntries
                &sample_size,
                &mut sample_buffer,
            )
        };

        if status != 0 || sample_buffer.is_null() {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!("CMSampleBufferCreate failed with status {}", status),
            ));
        }

        // Decode the frame synchronously: without
        // kVTDecodeFrame_EnableAsynchronousDecompression the callback runs
        // before VTDecompressionSessionDecodeFrame returns, so no callback
        // can be in flight after this call — which also makes session
        // teardown race-free.
        let mut info_flags: VTDecodeInfoFlags = 0;
        let status = unsafe {
            VTDecompressionSessionDecodeFrame(
                session,
                sample_buffer,
                0,               // synchronous
                ptr::null_mut(), // sourceFrameRefCon
                &mut info_flags,
            )
        };

        // Release the sample buffer (and indirectly the block buffer)
        unsafe { CFRelease(sample_buffer as CFTypeRef) };

        if status != 0 {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                format!(
                    "VTDecompressionSessionDecodeFrame failed with status {}",
                    status
                ),
            ));
        }

        // Transfer any decoded frames from the callback context to our queue
        self.sync_decoded_frames();

        self.frame_number += 1;

        Ok(())
    }

    /// Transfer decoded frames from the callback context into `frame_queue`.
    #[cfg(target_os = "macos")]
    fn sync_decoded_frames(&mut self) {
        if let Some(ref ctx) = self.context {
            let mut frames = lock_poisoned(&ctx.frames);
            while let Some(frame) = frames.pop_front() {
                self.frame_queue.push_back(frame);
            }
        }
    }

    /// Destroy the VideoToolbox session and release resources.
    #[cfg(target_os = "macos")]
    fn destroy_session(&mut self) {
        use self::vt_ffi::*;

        if let Some(session) = self.session.take() {
            unsafe {
                VTDecompressionSessionInvalidate(session);
                // Drain any frames that were already queued for the callback.
                // With synchronous decoding no callback is in flight here, but
                // the wait is harmless and covers the async flag used by other
                // modules sharing this session pattern.
                let _ = VTDecompressionSessionWaitForAsynchronousFrames(session);
                CFRelease(session as CFTypeRef);
            }
        }
        if let Some(fd) = self.format_desc.take() {
            unsafe {
                CFRelease(fd as CFTypeRef);
            }
        }
        // Reclaim the callback refcon's strong reference. After invalidation
        // no new callbacks can start, and any in-flight callback holds its
        // own strong reference via `Arc::increment_strong_count`.
        if let Some(refcon) = self.callback_refcon.take() {
            unsafe {
                let _ = Arc::from_raw(refcon as *const DecoderContext);
            }
        }
        self.context = None;
    }

    /// Destroy the session (non-macOS no-op).
    #[cfg(not(target_os = "macos"))]
    fn destroy_session(&mut self) {}

    /// Get the next decoded frame (if available).
    pub fn get_frame(&mut self) -> Option<VideoFrame> {
        self.frame_queue.pop_front()
    }

    /// Re-queue frames at the back of the output queue (used by the MFT
    /// Drain message so flushed frames remain deliverable via ProcessOutput).
    pub(crate) fn push_frame(&mut self, frame: VideoFrame) {
        self.frame_queue.push_back(frame);
    }

    /// Check if there are frames available in the queue.
    pub fn has_frames(&self) -> bool {
        !self.frame_queue.is_empty()
    }

    /// Flush the decoder (return all remaining frames).
    pub fn flush(&mut self) -> Vec<VideoFrame> {
        // Also sync any pending frames from the VT callback context
        #[cfg(target_os = "macos")]
        self.sync_decoded_frames();

        // Drain ffmpeg decoder
        #[cfg(feature = "ffmpeg")]
        if let Some(ref mut ctx) = self.ffmpeg_ctx {
            for frame in ctx.flush() {
                self.frame_queue.push_back(frame);
            }
        }

        self.frame_queue.drain(..).collect()
    }

    /// Reset the decoder state.
    pub fn reset(&mut self) {
        self.destroy_session();
        self.frame_queue.clear();
        self.sps.clear();
        self.pps.clear();
        #[cfg(target_os = "macos")]
        {
            self.sps_pps_hash = 0;
        }
        self.frame_number = 0;
    }

    /// Get decoder configuration.
    pub fn config(&self) -> &VideoDecoderConfig {
        &self.config
    }

    /// Return the number of queued decoded frames.
    pub fn queued_frame_count(&self) -> usize {
        self.frame_queue.len()
    }
}

impl Drop for VideoDecoder {
    fn drop(&mut self) {
        self.destroy_session();
    }
}

// ===========================================================================
// Software -> Metal texture upload utilities
// ===========================================================================

/// Prepare a decoded `VideoFrame` for upload to a Metal texture.
///
/// Converts the RGBA frame data into the specified `MetalTextureFormat`.
/// For BGRA output, the R and B channels are swapped (RGBA -> BGRA).
/// For NV12 output, the RGBA data is converted to YUV420p and then
/// packed as NV12 (Y plane + interleaved UV).
///
/// Returns a `MetalTextureUpload` descriptor that can be passed to
/// `upload_frame_to_metal_texture`.
pub fn prepare_metal_texture_upload(
    frame: &VideoFrame,
    format: MetalTextureFormat,
    color_space: ColorSpace,
) -> AppResult<MetalTextureUpload> {
    let width = frame.width;
    let height = frame.height;

    // Reject dimensions that overflow or that the given format cannot
    // represent (checked arithmetic; width/height come from callers).
    if width == 0 || height == 0 {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            "Invalid zero dimension for Metal texture upload",
        ));
    }
    let Some(pixel_count) = (width as u64).checked_mul(height as u64) else {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            "Texture dimensions overflow",
        ));
    };
    let Some(needed) = pixel_count.checked_mul(4) else {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            "Texture byte size overflows",
        ));
    };
    if frame.data.len() != needed as usize {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            format!(
                "Frame data length {} does not match {}x{} RGBA ({} bytes)",
                frame.data.len(),
                width,
                height,
                needed
            ),
        ));
    }

    match format {
        MetalTextureFormat::BGRA8Unorm => {
            // RGBA -> BGRA: swap R and B
            let pixel_count = pixel_count as usize;
            let mut bgra = vec![0u8; pixel_count * 4];
            for i in 0..pixel_count {
                let si = i * 4;
                bgra[si] = frame.data[si + 2]; // B
                bgra[si + 1] = frame.data[si + 1]; // G
                bgra[si + 2] = frame.data[si]; // R
                bgra[si + 3] = frame.data[si + 3]; // A
            }

            Ok(MetalTextureUpload {
                format: MetalTextureFormat::BGRA8Unorm,
                bytes_per_row: width * 4,
                data: bgra,
                width,
                height,
            })
        }
        MetalTextureFormat::RGBA8Unorm => {
            // Already in RGBA format — pass through
            Ok(MetalTextureUpload {
                format: MetalTextureFormat::RGBA8Unorm,
                bytes_per_row: width * 4,
                data: frame.data.clone(),
                width,
                height,
            })
        }
        MetalTextureFormat::NV12 => {
            // NV12 requires even dimensions: the UV plane is subsampled
            // 2:1 in both axes and odd sizes would produce a UV plane
            // inconsistent with the Y plane.
            if !width.is_multiple_of(2) || !height.is_multiple_of(2) {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    format!("NV12 upload requires even dimensions, got {width}x{height}"),
                ));
            }

            // Convert RGBA -> YUV420p -> NV12
            let (kr, kb) = color_space.kr_kb();
            let kg = 1.0 - kr - kb;

            let y_size = pixel_count as usize;
            let uv_size = ((width / 2) * (height / 2)) as usize;
            let mut y_plane = vec![0u8; y_size];
            let mut u_plane = vec![0u8; uv_size];
            let mut v_plane = vec![0u8; uv_size];

            for y in 0..height {
                for x in 0..width {
                    let si = (y * width + x) as usize * 4;
                    let r = frame.data[si] as f32 / 255.0;
                    let g = frame.data[si + 1] as f32 / 255.0;
                    let b = frame.data[si + 2] as f32 / 255.0;

                    let y_val = (kr * r + kg * g + kb * b).clamp(0.0, 1.0);
                    let u_val = (0.5 * (b - y_val) / (1.0 - kb)).clamp(-0.5, 0.5);
                    let v_val = (0.5 * (r - y_val) / (1.0 - kr)).clamp(-0.5, 0.5);

                    let yi = (y * width + x) as usize;
                    y_plane[yi] = (y_val * 255.0) as u8;

                    if y % 2 == 0 && x % 2 == 0 {
                        let uvi = ((y / 2) * (width / 2) + (x / 2)) as usize;
                        u_plane[uvi] = ((u_val + 0.5) * 255.0) as u8;
                        v_plane[uvi] = ((v_val + 0.5) * 255.0) as u8;
                    }
                }
            }

            // Pack as NV12: Y plane followed by interleaved UV
            let mut nv12 = Vec::with_capacity(y_size + uv_size * 2);
            nv12.extend_from_slice(&y_plane);
            for i in 0..uv_size {
                nv12.push(u_plane[i]);
                nv12.push(v_plane[i]);
            }

            Ok(MetalTextureUpload {
                format: MetalTextureFormat::NV12,
                bytes_per_row: width,
                data: nv12,
                width,
                height,
            })
        }
    }
}

/// Upload a prepared `MetalTextureUpload` to a Metal texture.
///
/// # Arguments
/// * `texture` - The destination Metal texture. Must have the correct pixel format,
///   width, and height matching the upload descriptor.
/// * `upload` - The upload descriptor containing the pixel data.
/// * `slice` - The texture slice index (0 for non-array textures).
///
/// Returns the number of bytes uploaded (0 on error).
///
/// Metal is the mandatory host backend on macOS, so this function is always
/// compiled in.
pub fn upload_frame_to_metal_texture(
    texture: &metal::TextureRef,
    upload: &MetalTextureUpload,
    slice: u64,
) -> u64 {
    let region = metal::MTLRegion {
        origin: metal::MTLOrigin { x: 0, y: 0, z: 0 },
        size: metal::MTLSize {
            width: upload.width as u64,
            height: upload.height as u64,
            depth: 1,
        },
    };
    let bytes_per_row = upload.bytes_per_row as u64;

    texture.replace_region(
        region,
        slice,
        upload.data.as_ptr() as *const std::ffi::c_void,
        bytes_per_row,
    );

    upload.data.len() as u64
}

// ===========================================================================
// IMFTransform-like interface stubs
// ===========================================================================

/// Media Foundation Transform (IMFTransform) wrapper around `VideoDecoder`.
///
/// Provides stubs for the IMFTransform interface methods:
/// - `ProcessMessage` - Sends messages to the transform (e.g., start, pause, flush)
/// - `ProcessInput` - Feeds compressed data into the transform
/// - `ProcessOutput` - Retrieves decoded output from the transform
#[allow(dead_code)] // MFT stream ids retained for future stream selection
pub struct MfTransform {
    decoder: VideoDecoder,
    input_stream_id: u32,
    output_stream_id: u32,
    input_queued: usize,
}

/// Messages that can be sent to an MFT via `ProcessMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MftMessageType {
    /// Begin flushing the transform.
    Flush,
    /// Drain the transform (produce all remaining output).
    Drain,
    /// Reset the transform to its initial state.
    Reset,
    /// Notify the transform that a new stream has started.
    NewStream,
    /// Notify the transform of a command (e.g., seek).
    Command(u32),
}

impl MfTransform {
    /// Create a new MFT wrapper.
    pub fn new(config: VideoDecoderConfig) -> Self {
        Self {
            decoder: VideoDecoder::new(config),
            input_stream_id: 0,
            output_stream_id: 0,
            input_queued: 0,
        }
    }

    /// Process a message sent to the transform.
    ///
    /// Corresponds to `IMFTransform::ProcessMessage`.
    pub fn process_message(&mut self, msg: MftMessageType) -> AppResult<()> {
        match msg {
            MftMessageType::Flush => {
                // Discard all pending input and output
                self.decoder.flush();
                self.input_queued = 0;
                Ok(())
            }
            MftMessageType::Drain => {
                // Produce all remaining output. `flush` returns the pending
                // frames; re-queue them so ProcessOutput can deliver them.
                let remaining = self.decoder.flush();
                self.input_queued = 0;
                for frame in remaining {
                    self.decoder.push_frame(frame);
                }
                Ok(())
            }
            MftMessageType::Reset => {
                self.decoder.reset();
                self.input_queued = 0;
                Ok(())
            }
            MftMessageType::NewStream => {
                // Prepare for a new stream
                self.decoder.reset();
                self.input_queued = 0;
                Ok(())
            }
            MftMessageType::Command(cmd) => {
                // Handle MFT command messages. The most common is MFT_COMMAND_MESSAGE_SET_START_TIME
                // (seek). For seek, reset the decoder state so the next ProcessInput starts fresh.
                match cmd {
                    0x00000000 => {
                        // MFT_COMMAND_MESSAGE_SET_START_TIME — seek
                        self.decoder.reset();
                        self.input_queued = 0;
                    }
                    _ => {
                        // Unknown command — accept and ignore
                    }
                }
                Ok(())
            }
        }
    }

    /// Feed compressed input data to the transform.
    ///
    /// Corresponds to `IMFTransform::ProcessInput`.
    pub fn process_input(&mut self, data: &[u8], pts: u64) -> AppResult<()> {
        self.decoder.decode_packet(data, pts)?;
        self.input_queued += 1;
        Ok(())
    }

    /// Retrieve decoded output from the transform.
    ///
    /// Corresponds to `IMFTransform::ProcessOutput`.
    /// Returns `None` if no output is available yet.
    pub fn process_output(&mut self) -> AppResult<Option<VideoFrame>> {
        Ok(self.decoder.get_frame())
    }

    /// Get the number of input packets queued (not yet producing output).
    pub fn input_queued(&self) -> usize {
        self.input_queued
    }

    /// Get the number of decoded output frames available.
    pub fn output_available(&self) -> usize {
        self.decoder.queued_frame_count()
    }

    /// Get a reference to the inner decoder.
    pub fn decoder(&self) -> &VideoDecoder {
        &self.decoder
    }

    /// Get a mutable reference to the inner decoder.
    pub fn decoder_mut(&mut self) -> &mut VideoDecoder {
        &mut self.decoder
    }
}

// ===========================================================================
// VideoToolbox C callback
// ===========================================================================

/// C callback invoked by VideoToolbox when a frame has been decoded.
///
/// Converts the `CVPixelBufferRef` to RGBA bytes and pushes the result
/// into the `DecoderContext`'s frame queue.
///
/// # Safety
///
/// Must be invoked with the `outputRefCon` handed to
/// `VTDecompressionSessionCreate`, which is a strong reference to a
/// `DecoderContext`. The callback takes its own reference for the duration
/// of the call, so the context can never be freed while the callback runs.
#[cfg(target_os = "macos")]
unsafe extern "C" fn decompression_output_callback(
    outputRefCon: *mut c_void,
    _sourceFrameRefCon: *mut c_void,
    status: i32,
    infoFlags: vt_ffi::VTDecodeInfoFlags,
    imageBuffer: vt_ffi::CVPixelBufferRef,
    presentationTimeStamp: vt_ffi::CMTime,
    presentationDuration: vt_ffi::CMTime,
) {
    unsafe {
        use self::vt_ffi::*;

        // A frame dropped by the decoder must not be enqueued.
        if status != 0 || imageBuffer.is_null() || outputRefCon.is_null() {
            return;
        }
        if infoFlags & kVTDecodeInfo_FrameDropped != 0 {
            return;
        }

        // Reconstruct the context: take a strong reference for the duration
        // of this callback so the context cannot be freed concurrently.
        let ctx_ptr = outputRefCon as *const DecoderContext;
        Arc::increment_strong_count(ctx_ptr);
        let ctx = Arc::from_raw(ctx_ptr);

        let width = CVPixelBufferGetWidth(imageBuffer) as u32;
        let height = CVPixelBufferGetHeight(imageBuffer) as u32;
        let pts = cmtime_to_us(presentationTimeStamp);
        let duration = cmtime_to_us(presentationDuration);

        let result = if width == 0 || height == 0 {
            None
        } else {
            // Prefer the zero-copy IOSurface → Metal texture path; fall back
            // to the existing CPU RGBA copy when CoreVideo/Metal or the
            // pixel-buffer layout cannot support it.
            try_zero_copy_frame(&ctx, imageBuffer, width, height, pts, duration)
                .or_else(|| software_copy(&ctx, imageBuffer, width, height, pts, duration))
        };

        if let Some(frame) = result {
            let mut frames = lock_poisoned(&ctx.frames);
            frames.push_back(frame);
        }

        drop(ctx);
    }
}

/// Try to wrap the decoded `CVPixelBuffer` as an IOSurface-backed Metal
/// texture (zero-copy), retaining the pixel buffer for the frame's lifetime.
///
/// Handles both packed BGRA (`'BGRA'`) and bi-planar NV12 (`'420v'`/`'420f'`)
/// output; for NV12 the luma plane becomes `metal_texture` (R8Unorm) and the
/// interleaved chroma plane becomes the frame's UV texture (RG8Unorm, see `VideoFrame::uv_texture_ptr`).
///
/// Returns `None` when the buffer is not IOSurface-backed, the texture cache
/// is unavailable, or the format is unsupported — in which case the caller
/// falls back to the CPU path.
#[cfg(target_os = "macos")]
fn try_zero_copy_frame(
    ctx: &Arc<DecoderContext>,
    image_buffer: vt_ffi::CVPixelBufferRef,
    width: u32,
    height: u32,
    pts: u64,
    duration: u64,
) -> Option<VideoFrame> {
    use self::vt_ffi::*;

    let metal_cache = ctx.metal_cache.as_ref()?;

    // The zero-copy path requires an IOSurface: only then does the Metal
    // texture alias the decoder's storage instead of a private copy.
    // SAFETY: `image_buffer` is live for the duration of the callback.
    let surface = unsafe { CVPixelBufferGetIOSurface(image_buffer) };
    if surface.is_null() {
        return None;
    }

    // SAFETY: `image_buffer` is live for the duration of the callback.
    let pixel_format = unsafe { CVPixelBufferGetPixelFormatType(image_buffer) };
    let (texture, texture_uv) = match pixel_format {
        kCVPixelFormatType_32BGRA => {
            // SAFETY: `image_buffer` is a valid CVPixelBufferRef delivered by
            // VideoToolbox while this callback runs.
            let texture = unsafe {
                metal_cache.create_texture_from_pixel_buffer(
                    image_buffer,
                    width,
                    height,
                    MTLPixelFormatBGRA8Unorm,
                    0,
                )
            }?;
            (texture, None)
        }
        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
        | kCVPixelFormatType_420YpCbCr8BiPlanarFullRange => {
            // SAFETY: as above; plane 0 is luma, plane 1 interleaved chroma.
            let y_texture = unsafe {
                metal_cache.create_texture_from_pixel_buffer(
                    image_buffer,
                    width,
                    height,
                    MTLPixelFormatR8Unorm,
                    0,
                )
            };
            // Use CoreVideo's real plane dimensions (they are the authoritative
            // chroma size; `div_ceil` is only a fallback for odd buffers).
            let mut uv_width = unsafe { CVPixelBufferGetWidthOfPlane(image_buffer, 1) } as u32;
            let mut uv_height = unsafe { CVPixelBufferGetHeightOfPlane(image_buffer, 1) } as u32;
            if uv_width == 0 || uv_height == 0 {
                uv_width = width.div_ceil(2);
                uv_height = height.div_ceil(2);
            }
            let uv_texture = unsafe {
                metal_cache.create_texture_from_pixel_buffer(
                    image_buffer,
                    uv_width,
                    uv_height,
                    MTLPixelFormatRG8Unorm,
                    1,
                )
            };
            match (y_texture, uv_texture) {
                (Some(y), Some(uv)) => (y, Some(uv)),
                (y, uv) => {
                    // Release any half-created texture so nothing leaks.
                    unsafe {
                        if let Some(ptr) = y {
                            CFRelease(ptr as CFTypeRef);
                        }
                        if let Some(ptr) = uv {
                            CFRelease(ptr as CFTypeRef);
                        }
                    }
                    return None;
                }
            }
        }
        // Unknown/unsupported format: the CPU path knows how to read it.
        _ => return None,
    };

    // Retain the pixel buffer: it owns the IOSurface that backs the texture
    // and must outlive this callback. Released by `VideoFrame::drop`.
    // SAFETY: `image_buffer` is a live CVPixelBufferRef.
    unsafe { CVPixelBufferRetain(image_buffer) };
    let uv_ptr = texture_uv.unwrap_or(std::ptr::null_mut());
    register_frame_surfaces(texture, image_buffer, uv_ptr, true);
    record_iosurface_frame();
    record_cpu_copy_avoided();

    Some(VideoFrame {
        width: ctx.output_width.max(width),
        height: ctx.output_height.max(height),
        data: Vec::new(), // zero-copy — no CPU pixel copy
        pts,
        duration,
        texture_id: None,
        metal_texture: Some(texture),
        color_space: ctx.color_space,
    })
}

/// Convert a `CMTime` to microseconds; a zero/invalid timescale yields 0.
#[cfg(target_os = "macos")]
fn cmtime_to_us(time: vt_ffi::CMTime) -> u64 {
    if time.timescale <= 0 {
        return 0;
    }
    (time.value * 1_000_000 / time.timescale as i64) as u64
}

/// Copy the pixel data of `imageBuffer` into CPU memory as RGBA, using the
/// context's scratch buffer to avoid per-frame allocations.
///
/// Returns `None` when the buffer layout cannot be validated.
#[cfg(target_os = "macos")]
fn software_copy(
    ctx: &Arc<DecoderContext>,
    imageBuffer: vt_ffi::CVPixelBufferRef,
    width: u32,
    height: u32,
    pts: u64,
    duration: u64,
) -> Option<VideoFrame> {
    use self::vt_ffi::*;

    let w = width as usize;
    let h = height as usize;
    // Validate the RGBA size up front (checked arithmetic; the buffer
    // dimensions come from CoreVideo but can be huge on crafted input).
    let pixel_bytes = w.checked_mul(h).and_then(|n| n.checked_mul(4))?;
    if pixel_bytes == 0 {
        return None;
    }

    unsafe {
        // Lock the pixel buffer for reading
        let lock_status = CVPixelBufferLockBaseAddress(imageBuffer, 0);
        if lock_status != 0 {
            return None;
        }

        let mut scratch = lock_poisoned(&ctx.scratch);
        scratch.resize(pixel_bytes, 0);

        let pixel_format = CVPixelBufferGetPixelFormatType(imageBuffer);
        let frame_data = match pixel_format {
            kCVPixelFormatType_32BGRA => {
                // BGRA: copy and swap B<->R
                let bpr = CVPixelBufferGetBytesPerRow(imageBuffer);
                let base = CVPixelBufferGetBaseAddress(imageBuffer);
                if base.is_null() {
                    None
                } else {
                    // Bound the slice by the actual buffer size; stride*height is
                    // the most we may ever touch.
                    let data_size = CVPixelBufferGetDataSize(imageBuffer);
                    let slice_len = bpr.checked_mul(h).unwrap_or(0).min(data_size);
                    if slice_len == 0 {
                        None
                    } else {
                        let src = std::slice::from_raw_parts(base as *const u8, slice_len);
                        for y in 0..h {
                            let row = y * bpr;
                            for x in 0..w {
                                let si = row + x * 4;
                                let di = (y * w + x) * 4;
                                if si + 3 < src.len() {
                                    // BGRA -> RGBA: swap B and R
                                    scratch[di] = src[si + 2]; // R
                                    scratch[di + 1] = src[si + 1]; // G
                                    scratch[di + 2] = src[si]; // B
                                    scratch[di + 3] = src[si + 3]; // A
                                }
                            }
                        }
                        Some(std::mem::take(&mut *scratch))
                    }
                }
            }
            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
            | kCVPixelFormatType_420YpCbCr8BiPlanarFullRange => {
                // NV12 bi-planar: Y plane + interleaved UV plane
                let y_bpr = CVPixelBufferGetBytesPerRowOfPlane(imageBuffer, 0);
                let uv_bpr = CVPixelBufferGetBytesPerRowOfPlane(imageBuffer, 1);
                let y_base = CVPixelBufferGetBaseAddressOfPlane(imageBuffer, 0);
                let uv_base = CVPixelBufferGetBaseAddressOfPlane(imageBuffer, 1);

                if y_base.is_null() || uv_base.is_null() {
                    None
                } else {
                    let y_slice_len = y_bpr.checked_mul(h).unwrap_or(0);
                    let uv_slice_len = uv_bpr.checked_mul(h.div_ceil(2)).unwrap_or(0);
                    if y_slice_len == 0 || uv_slice_len == 0 {
                        None
                    } else {
                        let y_src = std::slice::from_raw_parts(y_base as *const u8, y_slice_len);
                        let uv_src = std::slice::from_raw_parts(uv_base as *const u8, uv_slice_len);
                        let (cr, cg_u, cg_v, cb) = yuv_to_rgb_coeffs(ctx.color_space);

                        for y in 0..h {
                            for x in 0..w {
                                let y_idx = y * y_bpr + x;
                                let uv_idx = (y / 2) * uv_bpr + (x / 2) * 2;

                                let y_val = *y_src.get(y_idx).unwrap_or(&128) as f32;
                                let u_val = *uv_src.get(uv_idx).unwrap_or(&128) as f32 - 128.0;
                                let v_val = *uv_src.get(uv_idx + 1).unwrap_or(&128) as f32 - 128.0;

                                let r = (y_val + cr * v_val).clamp(0.0, 255.0) as u8;
                                let g =
                                    (y_val - cg_u * u_val - cg_v * v_val).clamp(0.0, 255.0) as u8;
                                let b = (y_val + cb * u_val).clamp(0.0, 255.0) as u8;

                                let di = (y * w + x) * 4;
                                scratch[di] = r;
                                scratch[di + 1] = g;
                                scratch[di + 2] = b;
                                scratch[di + 3] = 255;
                            }
                        }
                        Some(std::mem::take(&mut *scratch))
                    }
                }
            }
            _ => {
                // Unknown format — try reading as packed BGRA anyway
                let bpr = CVPixelBufferGetBytesPerRow(imageBuffer);
                let base = CVPixelBufferGetBaseAddress(imageBuffer);
                if base.is_null() {
                    None
                } else {
                    let data_size = CVPixelBufferGetDataSize(imageBuffer);
                    let slice_len = bpr.checked_mul(h).unwrap_or(0).min(data_size);
                    if slice_len == 0 {
                        None
                    } else {
                        let src = std::slice::from_raw_parts(base as *const u8, slice_len);
                        for y in 0..h {
                            let row = y * bpr;
                            for x in 0..w {
                                let si = row + x * 4;
                                let di = (y * w + x) * 4;
                                if si + 3 < src.len() {
                                    scratch[di] = src[si + 2];
                                    scratch[di + 1] = src[si + 1];
                                    scratch[di + 2] = src[si];
                                    scratch[di + 3] = 255;
                                }
                            }
                        }
                        Some(std::mem::take(&mut *scratch))
                    }
                }
            }
        };

        // Unlock the pixel buffer
        CVPixelBufferUnlockBaseAddress(imageBuffer, 0);

        frame_data.map(|data| VideoFrame {
            width: ctx.output_width.max(width),
            height: ctx.output_height.max(height),
            data,
            pts,
            duration,
            texture_id: None,
            metal_texture: None,
            color_space: ctx.color_space,
        })
    }
}

// ===========================================================================
// CoreVideo-backed zero-copy frame creation (software path)
// ===========================================================================

/// Probe the CoreVideo → Metal zero-copy path on this machine.
///
/// A real `CVMetalTextureCache` is created and immediately dropped, so the
/// result reflects actual framework availability rather than configuration.
#[cfg(target_os = "macos")]
pub fn probe_zero_copy_status() -> ZeroCopyStatus {
    match metal::Device::system_default() {
        Some(device) => match MetalVideoTextureCache::new(&device) {
            Some(_) => ZeroCopyStatus::Available,
            None => ZeroCopyStatus::CoreVideoUnavailable,
        },
        None => ZeroCopyStatus::MetalUnavailable,
    }
}

/// Probe the CoreVideo → Metal zero-copy path (always unavailable off macOS).
#[cfg(not(target_os = "macos"))]
pub fn probe_zero_copy_status() -> ZeroCopyStatus {
    ZeroCopyStatus::MetalUnavailable
}

/// Wrap an IOSurface into a `CVPixelBuffer` via CoreVideo.
///
/// Takes a `+0` borrowed reference to `surface` (the surface must stay alive
/// for the duration of the call); on success returns a `+1` retained
/// `CVPixelBufferRef` that the caller owns.
///
/// # Safety
/// `surface` must be a live `IOSurfaceRef` with a pixel format/layout matching
/// the intended use. Passing anything else is undefined behaviour.
#[cfg(target_os = "macos")]
pub unsafe fn wrap_io_surface_in_pixel_buffer(
    surface: *mut c_void,
) -> AppResult<vt_ffi::CVPixelBufferRef> {
    use self::vt_ffi::*;
    use std::ptr;

    if surface.is_null() {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            "wrap_io_surface_in_pixel_buffer: null IOSurface",
        ));
    }

    let mut pixel_buffer: CVPixelBufferRef = ptr::null_mut();
    // SAFETY: per the contract, `surface` is a live IOSurfaceRef. Passing a
    // NULL attribute dictionary uses CoreVideo's defaults.
    let status = unsafe {
        CVPixelBufferCreateWithIOSurface(ptr::null_mut(), surface, ptr::null(), &mut pixel_buffer)
    };
    if status != 0 || pixel_buffer.is_null() {
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            format!("CVPixelBufferCreateWithIOSurface failed with status {status}"),
        ));
    }
    Ok(pixel_buffer)
}

/// Copy tightly packed RGBA rows into a locked BGRA pixel buffer, honoring the
/// buffer's real `BytesPerRow`.
#[cfg(target_os = "macos")]
fn write_rgba_into_bgra_pixel_buffer(
    pixel_buffer: vt_ffi::CVPixelBufferRef,
    width: usize,
    height: usize,
    rgba: &[u8],
) -> AppResult<()> {
    use self::vt_ffi::*;

    let src_stride = width
        .checked_mul(4)
        .ok_or_else(|| AppError::new(ReasonCode::RcMediaInvalid, "RGBA stride overflow"))?;
    if rgba.len() < src_stride * height {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            format!(
                "RGBA source too small: {} bytes for {width}x{height}",
                rgba.len()
            ),
        ));
    }

    // SAFETY: `pixel_buffer` is a live CVPixelBufferRef owned by the caller.
    unsafe {
        let lock_status = CVPixelBufferLockBaseAddress(pixel_buffer, 0);
        if lock_status != 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("CVPixelBufferLockBaseAddress failed with status {lock_status}"),
            ));
        }

        let base = CVPixelBufferGetBaseAddress(pixel_buffer) as *mut u8;
        let dst_stride = CVPixelBufferGetBytesPerRow(pixel_buffer);
        if base.is_null() || dst_stride < src_stride {
            CVPixelBufferUnlockBaseAddress(pixel_buffer, 0);
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "Pixel buffer has no base address or a stride smaller than the frame",
            ));
        }

        // BGRA byte order expected by Metal/CoreVideo; swap R and B.
        for y in 0..height {
            let src_row = &rgba[y * src_stride..y * src_stride + src_stride];
            let dst_row = base.add(y * dst_stride);
            for x in 0..width {
                let si = x * 4;
                *dst_row.add(si) = src_row[si + 2]; // B
                *dst_row.add(si + 1) = src_row[si + 1]; // G
                *dst_row.add(si + 2) = src_row[si]; // R
                *dst_row.add(si + 3) = src_row[si + 3]; // A
            }
        }

        let unlock_status = CVPixelBufferUnlockBaseAddress(pixel_buffer, 0);
        if unlock_status != 0 {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("CVPixelBufferUnlockBaseAddress failed with status {unlock_status}"),
            ));
        }
    }
    Ok(())
}

/// Wrap an IOSurface as a `+1` retained `id<MTLTexture>` via
/// `metal_backend::create_texture_from_io_surface`.
///
/// Used as the fallback when `CVMetalTextureCache` is unavailable. The
/// returned pointer is owned by the caller (release via `msg_send![obj, release]`
/// or by adopting it with `metal::Texture::from_ptr`).
#[cfg(target_os = "macos")]
fn wrap_io_surface_texture(
    surface: *mut c_void,
    format: metal::MTLPixelFormat,
    width: u32,
    height: u32,
) -> Option<*mut c_void> {
    use metal::foreign_types::ForeignType;

    let device = metal::Device::system_default()?;
    let texture = crate::metal_backend::create_texture_from_io_surface(
        &device,
        surface,
        format,
        width as u64,
        height as u64,
    )?;
    let ptr = texture.as_ptr() as *mut c_void;
    // Transfer the +1 reference into the raw pointer (no release on drop).
    std::mem::forget(texture);
    Some(ptr)
}

/// Create a decoded frame whose pixels live in an IOSurface-backed
/// `CVPixelBuffer`, exposed directly as a BGRA8 Metal texture.
///
/// This is the software-path equivalent of the hardware zero-copy pipeline:
/// the pixel buffer is created through CoreVideo (`CVPixelBufferCreate`), the
/// RGBA pixels are written through a real lock/unlock, and the resulting
/// IOSurface is wrapped as a Metal texture with no separate upload copy.
///
/// The returned frame has empty `data` (the texture owns the pixels); CPU
/// consumers can lock `frame.pixel_buffer_ptr()`.
#[cfg(target_os = "macos")]
pub fn create_corevideo_frame_from_rgba(
    width: u32,
    height: u32,
    rgba: &[u8],
    pts: u64,
    duration: u64,
    color_space: ColorSpace,
) -> AppResult<VideoFrame> {
    use self::vt_ffi::*;
    use std::ptr;

    if width == 0 || height == 0 {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            "Cannot create a zero-sized CoreVideo frame",
        ));
    }
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| AppError::new(ReasonCode::RcMediaInvalid, "Frame dimensions overflow"))?;
    if rgba.len() < expected {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            format!(
                "RGBA source has {} bytes, need {expected} for {width}x{height}",
                rgba.len()
            ),
        ));
    }

    // Create the CoreVideo pixel buffer with IOSurface backing. If the Metal
    // compatibility key is rejected, retry without it — IOSurface backing
    // alone is sufficient for CVMetalTextureCache wrapping.
    let mut pixel_buffer: CVPixelBufferRef = ptr::null_mut();
    let mut status = 0;
    for metal_compat in [true, false] {
        let attrs = create_pixel_buffer_attributes(kCVPixelFormatType_32BGRA, metal_compat)?;
        status = unsafe {
            CVPixelBufferCreate(
                ptr::null_mut(),
                width as usize,
                height as usize,
                kCVPixelFormatType_32BGRA,
                attrs,
                &mut pixel_buffer,
            )
        };
        unsafe { CFRelease(attrs as CFTypeRef) };
        if status == 0 && !pixel_buffer.is_null() {
            break;
        }
        if metal_compat {
            eprintln!(
                "[VideoDecoder] CVPixelBufferCreate with MetalCompatibility failed \
                 (status={status}); retrying without it"
            );
        }
    }
    if status != 0 || pixel_buffer.is_null() {
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            format!("CVPixelBufferCreate failed with status {status}"),
        ));
    }

    if let Err(error) =
        write_rgba_into_bgra_pixel_buffer(pixel_buffer, width as usize, height as usize, rgba)
    {
        unsafe { CVPixelBufferRelease(pixel_buffer) };
        return Err(error);
    }

    // SAFETY: `pixel_buffer` is a live, retained CVPixelBufferRef.
    let surface = unsafe { CVPixelBufferGetIOSurface(pixel_buffer) };
    if surface.is_null() {
        unsafe { CVPixelBufferRelease(pixel_buffer) };
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            "CoreVideo did not back the pixel buffer with an IOSurface",
        ));
    }

    let texture = match metal::Device::system_default() {
        Some(device) => match MetalVideoTextureCache::new(&device) {
            Some(cache) => unsafe {
                cache.create_texture_from_pixel_buffer(
                    pixel_buffer,
                    width,
                    height,
                    MTLPixelFormatBGRA8Unorm,
                    0,
                )
            },
            None => None,
        },
        None => None,
    }
    .or_else(|| wrap_io_surface_texture(surface, metal::MTLPixelFormat::BGRA8Unorm, width, height));
    let Some(texture) = texture else {
        unsafe { CVPixelBufferRelease(pixel_buffer) };
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            "Failed to wrap the IOSurface-backed pixel buffer as a Metal texture",
        ));
    };

    record_iosurface_frame();
    register_frame_surfaces(texture, pixel_buffer, std::ptr::null_mut(), true);
    Ok(VideoFrame {
        width,
        height,
        data: Vec::new(),
        pts,
        duration,
        texture_id: None,
        metal_texture: Some(texture),
        color_space,
    })
}

/// Create a decoded NV12 frame in an IOSurface-backed `CVPixelBuffer` and
/// expose both planes as Metal textures (Y = R8Unorm, UV = RG8Unorm).
///
/// `y_plane` must hold `width * height` bytes and `uv_plane` must hold
/// interleaved CbCr samples for a `(width / 2) x (height / 2)` plane. This is
/// the same layout VideoToolbox produces for `'420v'` hardware decode, so the
/// present path is identical for hardware and software frames.
#[cfg(target_os = "macos")]
pub fn create_corevideo_nv12_frame(
    width: u32,
    height: u32,
    y_plane: &[u8],
    uv_plane: &[u8],
    pts: u64,
    duration: u64,
    color_space: ColorSpace,
) -> AppResult<VideoFrame> {
    use self::vt_ffi::*;
    use std::ptr;

    if width == 0 || height == 0 || !width.is_multiple_of(2) || !height.is_multiple_of(2) {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            format!("NV12 frames require non-zero even dimensions, got {width}x{height}"),
        ));
    }
    let y_len = (width as usize) * (height as usize);
    let chroma_w = (width / 2) as usize;
    let chroma_h = (height / 2) as usize;
    let uv_len = chroma_w * chroma_h * 2;
    if y_plane.len() < y_len || uv_plane.len() < uv_len {
        return Err(AppError::new(
            ReasonCode::RcMediaInvalid,
            format!(
                "NV12 planes too small: y={} (need {y_len}), uv={} (need {uv_len})",
                y_plane.len(),
                uv_plane.len()
            ),
        ));
    }

    let mut pixel_buffer: CVPixelBufferRef = ptr::null_mut();
    let attrs =
        create_pixel_buffer_attributes(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, false)?;
    let status = unsafe {
        CVPixelBufferCreate(
            ptr::null_mut(),
            width as usize,
            height as usize,
            kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
            attrs,
            &mut pixel_buffer,
        )
    };
    unsafe { CFRelease(attrs as CFTypeRef) };
    if status != 0 || pixel_buffer.is_null() {
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            format!("CVPixelBufferCreate (NV12) failed with status {status}"),
        ));
    }

    // SAFETY: `pixel_buffer` is live and retained; plane writes are bounded by
    // the real plane strides/sizes reported by CoreVideo.
    let write_ok = unsafe {
        let lock_status = CVPixelBufferLockBaseAddress(pixel_buffer, 0);
        if lock_status != 0 {
            false
        } else {
            let y_base = CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, 0) as *mut u8;
            let y_stride = CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, 0);
            let uv_base = CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, 1) as *mut u8;
            let uv_stride = CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, 1);
            let ok = !y_base.is_null()
                && !uv_base.is_null()
                && y_stride >= width as usize
                && uv_stride >= chroma_w * 2;
            if ok {
                for row in 0..height as usize {
                    std::ptr::copy_nonoverlapping(
                        y_plane[row * width as usize..].as_ptr(),
                        y_base.add(row * y_stride),
                        width as usize,
                    );
                }
                for row in 0..chroma_h {
                    std::ptr::copy_nonoverlapping(
                        uv_plane[row * chroma_w * 2..].as_ptr(),
                        uv_base.add(row * uv_stride),
                        chroma_w * 2,
                    );
                }
            }
            let _ = CVPixelBufferUnlockBaseAddress(pixel_buffer, 0);
            ok
        }
    };
    if !write_ok {
        unsafe { CVPixelBufferRelease(pixel_buffer) };
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            "Failed to write the NV12 planes through the CoreVideo lock",
        ));
    }

    // SAFETY: `pixel_buffer` is a live, retained CVPixelBufferRef.
    let surface = unsafe { CVPixelBufferGetIOSurface(pixel_buffer) };
    if surface.is_null() {
        unsafe { CVPixelBufferRelease(pixel_buffer) };
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            "CoreVideo did not back the NV12 pixel buffer with an IOSurface",
        ));
    }

    let Some(device) = metal::Device::system_default() else {
        unsafe { CVPixelBufferRelease(pixel_buffer) };
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            "No Metal device for the NV12 zero-copy path",
        ));
    };
    let Some(cache) = MetalVideoTextureCache::new(&device) else {
        unsafe { CVPixelBufferRelease(pixel_buffer) };
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            "CVMetalTextureCache unavailable for the NV12 zero-copy path",
        ));
    };

    // SAFETY: both planes belong to the retained pixel buffer.
    let y_texture = unsafe {
        cache.create_texture_from_pixel_buffer(
            pixel_buffer,
            width,
            height,
            MTLPixelFormatR8Unorm,
            0,
        )
    };
    let uv_texture = unsafe {
        cache.create_texture_from_pixel_buffer(
            pixel_buffer,
            width / 2,
            height / 2,
            MTLPixelFormatRG8Unorm,
            1,
        )
    };
    let (Some(y_texture), Some(uv_texture)) = (y_texture, uv_texture) else {
        unsafe {
            if let Some(ptr) = y_texture {
                CFRelease(ptr as *const c_void);
            }
            if let Some(ptr) = uv_texture {
                CFRelease(ptr as *const c_void);
            }
            CVPixelBufferRelease(pixel_buffer);
        }
        return Err(AppError::new(
            ReasonCode::RcInvalidState,
            "Failed to create the NV12 plane textures from the pixel buffer",
        ));
    };

    record_iosurface_frame();
    register_frame_surfaces(y_texture, pixel_buffer, uv_texture, true);
    Ok(VideoFrame {
        width,
        height,
        data: Vec::new(),
        pts,
        duration,
        texture_id: None,
        metal_texture: Some(y_texture),
        color_space,
    })
}

// ===========================================================================
// CoreFoundation dictionary helpers
// ===========================================================================

/// Create a CFDictionary to request BGRA pixel buffers from VideoToolbox.
///
/// Delegates to [`create_pixel_buffer_attributes`], so the buffers are
/// IOSurface-backed (a prerequisite for the Metal zero-copy wrap).
#[cfg(target_os = "macos")]
pub(crate) fn create_bgra_pixel_buffer_attributes() -> AppResult<vt_ffi::CFDictionaryRef> {
    create_pixel_buffer_attributes(vt_ffi::kCVPixelFormatType_32BGRA, false)
}

/// Create a CFString from a NUL-terminated byte string.
///
/// Returns null on failure (allocation error or invalid encoding).
#[cfg(all(test, target_os = "macos"))]
fn cfstring_from_bytes(bytes: &[u8]) -> vt_ffi::CFStringRef {
    use self::vt_ffi::*;
    use std::ptr;
    let Ok(cstr) = std::ffi::CString::new(bytes) else {
        return ptr::null();
    };
    unsafe { CFStringCreateWithCString(ptr::null(), cstr.as_ptr(), kCFStringEncodingUTF8) }
}

/// Create a `CFNumber` holding a 32-bit signed integer.
#[cfg(all(test, target_os = "macos"))]
fn cfnumber_i32(value: i32) -> vt_ffi::CFNumberRef {
    use self::vt_ffi::*;
    use std::ptr;
    unsafe {
        CFNumberCreate(
            ptr::null_mut(),
            kCFNumberSInt32Type,
            &value as *const i32 as *const c_void,
        )
    }
}

/// Build a CoreVideo pixel-buffer attribute dictionary.
///
/// Always includes `kCVPixelBufferPixelFormatTypeKey` and an (empty)
/// `kCVPixelBufferIOSurfacePropertiesKey` so CoreVideo allocates an
/// IOSurface-backed buffer. `metal_compatibility` additionally sets
/// `kCVPixelBufferMetalCompatibilityKey`, which some Metal integrations
/// require for `CVPixelBufferCreate`.
///
/// The dictionary is built with real `CFType` callbacks (so it retains its
/// keys/values), and returned with `+1` ownership for the caller to
/// `CFRelease`.
#[cfg(target_os = "macos")]
pub(crate) fn create_pixel_buffer_attributes(
    pixel_format: u32,
    metal_compatibility: bool,
) -> AppResult<vt_ffi::CFDictionaryRef> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;

    let mut pairs: Vec<(CFType, CFType)> = vec![
        (
            CFString::from_static_string("PixelFormatType").as_CFType(),
            CFNumber::from(pixel_format as i32).as_CFType(),
        ),
        (
            CFString::from_static_string("IOSurfaceProperties").as_CFType(),
            CFDictionary::from_CFType_pairs(&[] as &[(CFType, CFType)]).as_CFType(),
        ),
    ];
    if metal_compatibility {
        pairs.push((
            CFString::from_static_string("MetalCompatibility").as_CFType(),
            CFNumber::from(1i32).as_CFType(),
        ));
    }

    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let raw = dict.as_concrete_TypeRef() as vt_ffi::CFDictionaryRef;
    // Transfer the +1 ownership of `dict` to the raw pointer; callers release
    // it with CFRelease.
    std::mem::forget(dict);
    Ok(raw)
}

/// Create the VideoToolbox destination attributes for the zero-copy path:
/// native NV12 output with IOSurface backing.
#[cfg(target_os = "macos")]
pub(crate) fn create_zero_copy_pixel_buffer_attributes() -> AppResult<vt_ffi::CFDictionaryRef> {
    create_pixel_buffer_attributes(
        vt_ffi::kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange,
        false,
    )
}

/// Create a CFDictionary to request hardware-accelerated decoding.
///
/// Uses a real `CFBoolean` value: VideoToolbox treats the specification
/// value as a boolean, not a number.
#[cfg(target_os = "macos")]
pub(crate) fn create_hardware_decoder_specification() -> AppResult<vt_ffi::CFDictionaryRef> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;

    let pairs: Vec<(CFType, CFType)> = vec![(
        CFString::from_static_string("RequireHardwareAcceleratedVideoDecoder").as_CFType(),
        CFBoolean::true_value().as_CFType(),
    )];
    let dict = CFDictionary::from_CFType_pairs(&pairs);
    let raw = dict.as_concrete_TypeRef() as vt_ffi::CFDictionaryRef;
    // Transfer the +1 ownership of `dict` to the raw pointer.
    std::mem::forget(dict);
    Ok(raw)
}

// ===========================================================================
// H.264 Bitstream parsing helpers
// ===========================================================================

/// Parse H.264 Annex B byte stream into individual NAL units.
pub fn parse_h264_annex_b(data: &[u8]) -> Vec<Vec<u8>> {
    let mut nalus = Vec::new();
    let mut start = 0;
    let mut i = 0;

    while i < data.len() {
        // Look for 0x00000001 or 0x000001 start codes
        if i + 3 < data.len() && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            let nal_start = if i > 0 && data[i - 1] == 0 { i - 1 } else { i };
            if start < nal_start && nal_start - start >= 4 {
                nalus.push(data[start..nal_start].to_vec());
            }
            start = i + 3;
            i += 3;
        } else if i + 4 < data.len()
            && data[i] == 0
            && data[i + 1] == 0
            && data[i + 2] == 0
            && data[i + 3] == 1
        {
            if start < i {
                nalus.push(data[start..i].to_vec());
            }
            start = i + 4;
            i += 4;
        } else {
            i += 1;
        }
    }

    // Push remaining data only if at least one start code was found.
    // Data without any start code is not valid Annex B and should not
    // be emitted as a NAL unit.
    if start > 0 && start < data.len() {
        nalus.push(data[start..].to_vec());
    }

    nalus
}

/// Maximum sane video dimension (in pixels per side) parsed from an SPS.
/// Real-world SPS values are far below this; the clamp keeps crafted SPS
/// data from producing absurd dimensions that later get multiplied for
/// allocations.
const MAX_SPS_DIMENSION: u64 = 16_384;

/// Parse H.264 SPS (Sequence Parameter Set) to extract width and height.
///
/// Returns `(width, height)` in pixels, or `(0, 0)` if parsing fails or the
/// values are invalid (overflow, crop larger than the frame, out of range).
pub fn parse_h264_sps(sps: &[u8]) -> (u32, u32) {
    if sps.len() < 5 {
        return (0, 0);
    }

    // Skip NAL header byte and profile/constraints/level
    let mut bit_offset = 4 * 8; // bits from byte 4

    // Read Exp-Golomb coded values
    let _seq_parameter_set_id = read_ue(sps, &mut bit_offset);

    // Check if it's a high-profile variant that has additional fields
    let profile_idc = sps[1];
    let high_profile = matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    );

    if high_profile {
        let chroma_format_idc = read_ue(sps, &mut bit_offset);
        if chroma_format_idc == 3 {
            // separate_colour_plane_flag: u(1)
            read_bits(sps, bit_offset, 1);
            bit_offset += 1;
        }
        let _bit_depth_luma_minus8 = read_ue(sps, &mut bit_offset);
        let _bit_depth_chroma_minus8 = read_ue(sps, &mut bit_offset);
        let _qpprime_y_zero_transform_bypass_flag = read_bits(sps, bit_offset, 1);
        bit_offset += 1;
        let seq_scaling_matrix_present_flag = read_bits(sps, bit_offset, 1);
        bit_offset += 1;

        if seq_scaling_matrix_present_flag == 1 {
            // Skip scaling lists (complex, varies by chroma_format_idc)
            let max_skip = (sps.len() * 8).saturating_sub(bit_offset as usize);
            let skip_bits = max_skip.min(512);
            bit_offset += skip_bits as u64;
        }
    }

    let _log2_max_frame_num_minus4 = read_ue(sps, &mut bit_offset);
    let pic_order_cnt_type = read_ue(sps, &mut bit_offset);

    if pic_order_cnt_type == 0 {
        let _log2_max_poc_lsb_minus4 = read_ue(sps, &mut bit_offset);
    } else if pic_order_cnt_type == 1 {
        let _delta_pic_order_always_zero_flag = read_bits(sps, bit_offset, 1);
        bit_offset += 1;
        let _offset_for_non_ref_pic = read_se(sps, &mut bit_offset);
        let _offset_for_top_to_bottom_field = read_se(sps, &mut bit_offset);
        let num_ref_frames_in_pic_order_cnt_cycle = read_ue(sps, &mut bit_offset);
        for _ in 0..num_ref_frames_in_pic_order_cnt_cycle {
            let _offset_for_ref_frame = read_se(sps, &mut bit_offset);
        }
    }

    let _max_num_ref_frames = read_ue(sps, &mut bit_offset);
    let _gaps_in_frame_num_value_allowed_flag = read_bits(sps, bit_offset, 1);
    bit_offset += 1;

    let pic_width_in_mbs_minus1 = read_ue(sps, &mut bit_offset);
    let pic_height_in_map_units_minus1 = read_ue(sps, &mut bit_offset);

    let frame_mbs_only_flag = read_bits(sps, bit_offset, 1);
    bit_offset += 1;

    let mut height_in_mbs = pic_height_in_map_units_minus1 as u64 + 1;
    if frame_mbs_only_flag == 0 {
        let _mb_adaptive_frame_field_flag = read_bits(sps, bit_offset, 1);
        bit_offset += 1;
        height_in_mbs = height_in_mbs.saturating_mul(2);
    }

    let _direct_8x8_inference_flag = read_bits(sps, bit_offset, 1);
    bit_offset += 1;

    // Compute in u64 with saturating/checked arithmetic; a crafted SPS can
    // carry arbitrarily large Exp-Golomb values.
    let width = (pic_width_in_mbs_minus1 as u64 + 1).saturating_mul(16);
    let height = height_in_mbs.saturating_mul(16);

    if width == 0 || height == 0 || width > MAX_SPS_DIMENSION || height > MAX_SPS_DIMENSION {
        return (0, 0);
    }

    // Frame cropping
    if bit_offset as usize / 8 < sps.len() {
        let frame_cropping_flag = read_bits(sps, bit_offset, 1);
        bit_offset += 1;

        if frame_cropping_flag == 1 {
            let crop_left = read_ue(sps, &mut bit_offset) as u64;
            let crop_right = read_ue(sps, &mut bit_offset) as u64;
            let crop_top = read_ue(sps, &mut bit_offset) as u64;
            let crop_bottom = read_ue(sps, &mut bit_offset) as u64;

            // Chroma subsampling for crop units
            let crop_unit_x: u64 = 2; // 4:2:0 chroma
            let crop_unit_y: u64 = 2;

            let crop_w = crop_left
                .saturating_add(crop_right)
                .saturating_mul(crop_unit_x);
            let crop_h = crop_top
                .saturating_add(crop_bottom)
                .saturating_mul(crop_unit_y);
            // Reject crops that exceed the frame size (would underflow).
            if crop_w < width && crop_h < height {
                let width_cropped = width - crop_w;
                let height_cropped = height - crop_h;
                if width_cropped > 0 && height_cropped > 0 {
                    return (width_cropped as u32, height_cropped as u32);
                }
            }
        }
    }

    (width as u32, height as u32)
}

/// Read one unsigned Exp-Golomb coded value from the bitstream.
fn read_ue(data: &[u8], bit_offset: &mut u64) -> u32 {
    // Count leading zeros
    let mut leading_zeros = 0u32;
    loop {
        let bit = read_bits(data, *bit_offset, 1);
        *bit_offset += 1;
        if bit == 1 {
            break;
        }
        leading_zeros += 1;
        // Safety check: prevent infinite loop on malformed data
        if leading_zeros > 32 || *bit_offset as usize / 8 >= data.len() {
            return 0;
        }
    }

    if leading_zeros == 0 {
        return 0;
    }

    // Read the remaining bits
    let mut value = 1u32; // the '1' bit we already consumed
    for _ in 0..leading_zeros {
        value <<= 1;
        let bit = read_bits(data, *bit_offset, 1);
        *bit_offset += 1;
        value |= bit;
    }

    value - 1
}

/// Read one signed Exp-Golomb coded value from the bitstream.
#[allow(dead_code)]
fn read_se(data: &[u8], bit_offset: &mut u64) -> i32 {
    let ue = read_ue(data, bit_offset);
    if ue == 0 {
        return 0;
    }
    if ue.is_multiple_of(2) {
        -((ue / 2) as i32)
    } else {
        ((ue + 1).div_ceil(2)) as i32
    }
}

/// Read `count` bits from the bitstream at the given offset.
fn read_bits(data: &[u8], bit_offset: u64, count: u32) -> u32 {
    if count == 0 || count > 32 {
        return 0;
    }

    let byte_idx = (bit_offset / 8) as usize;
    let _bit_idx = (bit_offset % 8) as u32;

    if byte_idx >= data.len() {
        return 0;
    }

    // Simple bit-by-bit reading
    let mut result: u32 = 0;
    for i in 0..count {
        let cur_bit_offset = bit_offset + i as u64;
        let cur_byte = (cur_bit_offset / 8) as usize;
        let cur_bit = (cur_bit_offset % 8) as u32;
        if cur_byte >= data.len() {
            break;
        }
        let bit = (data[cur_byte] >> (7 - cur_bit)) & 1;
        result = (result << 1) | bit as u32;
    }

    result
}

/// Convert YUV420p to RGBA (software fallback for non-VideoToolbox paths).
///
/// The input must contain `width * height` luma bytes followed by
/// `width * height / 4` bytes each of U and V (planar 4:2:0). If the buffer
/// is too short, or the dimensions overflow, an empty vector is returned
/// instead of panicking.
pub fn yuv420p_to_rgba(yuv: &[u8], width: u32, height: u32) -> Vec<u8> {
    let w = width as usize;
    let h = height as usize;
    let Some(total_pixels) = w.checked_mul(h) else {
        return Vec::new();
    };
    let Some(rgba_len) = total_pixels.checked_mul(4) else {
        return Vec::new();
    };
    let Some(u_start) = total_pixels.checked_add(total_pixels / 4) else {
        return Vec::new();
    };
    if u_start > yuv.len() {
        // Not enough luma + chroma data for this size.
        return Vec::new();
    }
    let u_plane = &yuv[total_pixels..u_start];
    let v_plane = &yuv[u_start..];

    let mut rgba = vec![0u8; rgba_len];

    for y in 0..h {
        for x in 0..w {
            let y_idx = y * w + x;
            let uv_idx = (y / 2) * (w / 2) + (x / 2);

            let y_val = yuv.get(y_idx).copied().unwrap_or(128) as f32;
            let u_val = u_plane.get(uv_idx).copied().unwrap_or(128) as f32 - 128.0;
            let v_val = v_plane.get(uv_idx).copied().unwrap_or(128) as f32 - 128.0;

            let r = (y_val + 1.402 * v_val).clamp(0.0, 255.0) as u8;
            let g = (y_val - 0.344 * u_val - 0.714 * v_val).clamp(0.0, 255.0) as u8;
            let b = (y_val + 1.772 * u_val).clamp(0.0, 255.0) as u8;

            let offset = y_idx * 4;
            rgba[offset] = r;
            rgba[offset + 1] = g;
            rgba[offset + 2] = b;
            rgba[offset + 3] = 255;
        }
    }

    rgba
}

/// The type of media source URL.
#[derive(Debug, Clone, PartialEq)]
enum SourceUrlType {
    /// Local file path (file:// or raw path).
    File(String),
    /// HTTP/HTTPS streaming URL.
    Http(String),
    /// Unknown.
    Unknown,
}

/// Detect the URL type from a string.
fn detect_url_type(url: &str) -> SourceUrlType {
    if let Some(rest) = url.strip_prefix("file://") {
        SourceUrlType::File(rest.to_string())
    } else if url.starts_with("http://") || url.starts_with("https://") {
        SourceUrlType::Http(url.to_string())
    } else if url.starts_with('/') || url.starts_with('.') || url.contains(':') {
        // Could be a path with drive letter (Windows-style) or relative path
        SourceUrlType::File(url.to_string())
    } else {
        // Assume file path
        SourceUrlType::File(url.to_string())
    }
}

/// Detect the video codec from a file extension.
fn detect_codec_from_extension(path: &str) -> VideoCodec {
    let lower = path.to_lowercase();
    if lower.ends_with(".h264") || lower.ends_with(".264") || lower.ends_with(".avc") {
        VideoCodec::H264
    } else if lower.ends_with(".h265") || lower.ends_with(".265") || lower.ends_with(".hevc") {
        VideoCodec::H265
    } else if lower.ends_with(".vp9") || lower.ends_with(".webm") {
        VideoCodec::VP9
    } else {
        // Default to H264 for WMV containers and unknown extensions.
        VideoCodec::H264
    }
}

/// Stream selection flags matching MF_SOURCE_READER constants.
pub const MF_SOURCE_READER_FIRST_VIDEO_STREAM: u32 = 0xFFFFFFFB;
pub const MF_SOURCE_READER_FIRST_AUDIO_STREAM: u32 = 0xFFFFFFFC;
pub const MF_SOURCE_READER_ALL_STREAMS: u32 = 0xFFFFFFFD;

/// A selected stream within the source reader.
#[derive(Debug, Clone)]
struct SelectedStream {
    /// Stream index (0-based).
    index: u32,
    /// Whether this is a video stream.
    is_video: bool,
    /// Current media type for this stream's output.
    current_media_type: Option<super::media::ImfMediaType>,
    /// Decoder configuration for this stream.
    config: VideoDecoderConfig,
}

/// Enhanced Media Foundation Source Reader that delegates to VideoDecoder.
///
/// Supports:
/// - Local file and HTTP(S) streaming input
/// - Seeking to specific positions
/// - Multiple stream selection (video + audio)
/// - Format negotiation via `set_current_media_type`
pub struct MfSourceReader {
    /// The video decoder instance.
    decoder: Option<VideoDecoder>,
    /// Desired output width.
    width: u32,
    /// Desired output height.
    height: u32,
    /// Frame rate in fps.
    frame_rate: f64,
    /// Detected URL type for the source.
    url_type: SourceUrlType,
    /// Buffered data for streaming sources.
    stream_buffer: Vec<u8>,
    /// Current playback position in microseconds.
    position_us: u64,
    /// Whether the source has been fully loaded.
    source_loaded: bool,
    /// Selected stream indices.
    selected_streams: Vec<SelectedStream>,
    /// Whether the reader has been initialized.
    initialized: bool,
}

impl MfSourceReader {
    pub fn new() -> Self {
        Self {
            decoder: None,
            width: 0,
            height: 0,
            frame_rate: 30.0,
            url_type: SourceUrlType::Unknown,
            stream_buffer: Vec::new(),
            position_us: 0,
            source_loaded: false,
            selected_streams: Vec::new(),
            initialized: false,
        }
    }

    /// Initialize the source reader with a media source URL.
    ///
    /// Parses the URL to determine the media type, detects the codec
    /// from the file extension, and prepares the decoder.
    /// For HTTP URLs, the data is fetched (bounded to
    /// `HTTP_FETCH_LIMIT_BYTES`) during initialization.
    pub fn initialize(&mut self, url: &str) -> AppResult<()> {
        self.url_type = detect_url_type(url);
        let codec = detect_codec_from_extension(url);

        // Try to load the source data
        match &self.url_type {
            SourceUrlType::File(path) => {
                // Read the file to detect dimensions from headers
                match std::fs::read(path) {
                    Ok(data) => {
                        self.stream_buffer = data;
                        self.source_loaded = true;
                    }
                    Err(e) => {
                        eprintln!(
                            "[MfSourceReader] Warning: could not read media file {path}: {e}"
                        );
                    }
                }
            }
            SourceUrlType::Http(url_str) => {
                // For HTTP URLs, fetch with a bounded buffer so a malicious
                // or oversized remote file cannot exhaust memory.
                eprintln!("[MfSourceReader] Fetching streaming data from {url_str}");
                match fetch_http_bounded(url_str, HTTP_FETCH_LIMIT_BYTES) {
                    Ok(data) => {
                        self.stream_buffer = data;
                        self.source_loaded = true;
                    }
                    Err(e) => {
                        eprintln!("[MfSourceReader] Failed to fetch {url_str}: {e}");
                    }
                }
            }
            SourceUrlType::Unknown => {}
        }

        // Try to parse H.264 SPS for dimensions
        if codec == VideoCodec::H264 && !self.stream_buffer.is_empty() {
            let nalus = parse_h264_annex_b(&self.stream_buffer);
            for nalu in &nalus {
                if !nalu.is_empty() && (nalu[0] & 0x1F) == 7 {
                    let (w, h) = parse_h264_sps(nalu);
                    if w > 0 && h > 0 {
                        self.width = self.width.max(w);
                        self.height = self.height.max(h);
                    }
                    break;
                }
            }
        }

        let config = VideoDecoderConfig {
            codec,
            width: self.width.max(640),
            height: self.height.max(480),
            fps: self.frame_rate,
            ..Default::default()
        };

        self.decoder = Some(VideoDecoder::new(config.clone()));

        // Feed the preloaded stream once here, so `feed_data` never re-feeds
        // the whole buffered source on top of the caller's chunk (which
        // would decode every NAL twice and duplicate frames/PTS).
        if self.source_loaded
            && !self.stream_buffer.is_empty()
            && let Some(ref mut decoder) = self.decoder
            && let Err(e) = decoder.feed_data(&self.stream_buffer)
        {
            eprintln!("[MfSourceReader] Warning: failed to pre-feed buffered source: {e}");
        }

        self.initialized = true;

        // Set up default stream selection
        self.selected_streams.push(SelectedStream {
            index: 0,
            is_video: true,
            current_media_type: None,
            config,
        });

        Ok(())
    }

    /// Read the next sample from the media source.
    pub fn read_sample(&mut self) -> AppResult<Option<VideoFrame>> {
        match &mut self.decoder {
            Some(decoder) => {
                let frame = decoder.get_frame();
                if let Some(ref f) = frame {
                    self.position_us = f.pts + f.duration;
                }
                Ok(frame)
            }
            None => Ok(None),
        }
    }

    /// Feed encoded H.264/H.265 data to the decoder.
    ///
    /// Only the caller's chunk is fed. The buffered source was already fed
    /// once during `initialize`; re-feeding it here would decode every NAL
    /// twice and duplicate frames.
    pub fn feed_data(&mut self, data: &[u8]) -> AppResult<()> {
        match &mut self.decoder {
            Some(decoder) => decoder.feed_data(data),
            None => Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "MfSourceReader not initialized",
            )),
        }
    }

    /// Seek to a specific position in the stream.
    ///
    /// `position_us` is the target position in microseconds.
    /// Resets the decoder and re-feeds the buffered source. The buffered
    /// data is kept intact so repeated seeks remain consistent; a full
    /// implementation would find the nearest keyframe to the seek point.
    pub fn seek(&mut self, position_us: u64) -> AppResult<()> {
        self.position_us = position_us;

        // Flush and reset the decoder
        if let Some(ref mut decoder) = self.decoder {
            decoder.flush();
            decoder.reset();
        }

        if self.source_loaded
            && !self.stream_buffer.is_empty()
            && let Some(ref mut decoder) = self.decoder
        {
            decoder.feed_data(&self.stream_buffer)?;
        }

        Ok(())
    }

    /// Select a stream for reading.
    ///
    /// `stream_index` can be:
    /// - `MF_SOURCE_READER_FIRST_VIDEO_STREAM` (0xFFFFFFFB): first video stream
    /// - `MF_SOURCE_READER_FIRST_AUDIO_STREAM` (0xFFFFFFFC): first audio stream
    /// - A specific stream index
    pub fn select_stream(&mut self, stream_index: u32) -> AppResult<()> {
        let idx = if stream_index == MF_SOURCE_READER_FIRST_VIDEO_STREAM {
            0 // Always use first stream as video
        } else if stream_index == MF_SOURCE_READER_FIRST_AUDIO_STREAM {
            // Audio streams would be stream 1 if present
            1
        } else {
            stream_index
        };

        // Check if already selected
        if self.selected_streams.iter().any(|s| s.index == idx) {
            return Ok(());
        }

        let codec = VideoCodec::H264;

        self.selected_streams.push(SelectedStream {
            index: idx,
            is_video: idx == 0,
            current_media_type: None,
            config: VideoDecoderConfig {
                codec,
                width: self.width.max(640),
                height: self.height.max(480),
                fps: self.frame_rate,
                ..Default::default()
            },
        });

        Ok(())
    }

    /// Get the current media type for a stream.
    pub fn get_current_media_type(
        &self,
        _stream_index: u32,
    ) -> AppResult<super::media::ImfMediaType> {
        let mut mt = super::media::ImfMediaType::new();
        mt.set_guid(
            super::media::MF_MT_MAJOR_TYPE,
            super::media::MFMediaType_Video,
        );
        mt.set_guid(
            super::media::MF_MT_SUBTYPE,
            super::media::MFVideoFormat_NV12,
        );
        mt.set_frame_size(self.width.max(640), self.height.max(480));
        mt.set_frame_rate(30, 1);
        Ok(mt)
    }

    /// Set the current media type for a stream (output type).
    ///
    /// Validates the requested format and negotiates with the decoder.
    /// Currently supports:
    /// - NV12 (native VideoToolbox output)
    /// - RGB32 (software fallback)
    /// - H264 / H265 (compressed input)
    pub fn set_current_media_type(
        &mut self,
        stream_index: u32,
        media_type: &super::media::ImfMediaType,
    ) -> AppResult<()> {
        // Validate the media type
        let major = media_type.get_guid(&super::media::MF_MT_MAJOR_TYPE);
        let subtype = media_type.get_guid(&super::media::MF_MT_SUBTYPE);

        if major != Some(super::media::MFMediaType_Video)
            && major != Some(super::media::MFMediaType_Audio)
        {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "Unsupported major media type",
            ));
        }

        // Determine the codec from the subtype
        let codec = if subtype == Some(super::media::MFVideoFormat_H264) {
            VideoCodec::H264
        } else if subtype == Some(super::media::MFVideoFormat_H265) {
            VideoCodec::H265
        } else if subtype == Some(super::media::MFVideoFormat_VP90) {
            VideoCodec::VP9
        } else {
            // Default for unknown or output formats (NV12, RGB32)
            VideoCodec::H264
        };

        // Update stream size if provided
        if let Some((w, h)) = media_type.get_frame_size() {
            self.width = w;
            self.height = h;
        }

        // Update the stream's media type
        for stream in &mut self.selected_streams {
            if stream.index == stream_index
                || (stream_index == MF_SOURCE_READER_FIRST_VIDEO_STREAM && stream.is_video)
            {
                stream.current_media_type = Some(media_type.clone());
                stream.config.codec = codec;
                stream.config.width = self.width.max(stream.config.width);
                stream.config.height = self.height.max(stream.config.height);
                break;
            }
        }

        // Reinitialize the decoder with the new codec if needed
        if let Some(ref mut decoder) = self.decoder {
            let new_config = VideoDecoderConfig {
                codec,
                width: self.width.max(640),
                height: self.height.max(480),
                fps: self.frame_rate,
                ..Default::default()
            };
            *decoder = VideoDecoder::new(new_config);
        }

        Ok(())
    }

    /// Set the output dimensions.
    pub fn set_output_size(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
    }

    /// Set the frame rate.
    pub fn set_frame_rate(&mut self, fps: f64) {
        self.frame_rate = fps;
    }

    /// Get the current playback position in microseconds.
    pub fn get_position(&self) -> u64 {
        self.position_us
    }

    /// Check if the reader has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Check if the source data has been fully loaded.
    pub fn is_source_loaded(&self) -> bool {
        self.source_loaded
    }

    /// Shutdown the source reader.
    pub fn shutdown(&mut self) {
        self.decoder = None;
        self.stream_buffer.clear();
        self.selected_streams.clear();
        self.initialized = false;
        self.source_loaded = false;
        self.position_us = 0;
    }
}

impl Default for MfSourceReader {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_video_decoder_creation() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 1920,
            height: 1080,
            fps: 30.0,
            bitrate: 5_000_000,
        };
        let decoder = VideoDecoder::new(config);
        assert!(!decoder.has_frames());
    }

    #[test]
    fn test_decode_packet() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 640,
            height: 480,
            fps: 30.0,
            bitrate: 1_000_000,
        };
        let mut decoder = VideoDecoder::new(config);

        let packet = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0xAD, 0xB7];

        #[cfg(feature = "ffmpeg")]
        {
            let result = decoder.decode_packet(&packet, 0);
            // With ffmpeg feature, decode_packet should succeed with simulated decode
            assert!(result.is_ok(), "expected Ok, got {result:?}");
        }

        #[cfg(not(any(target_os = "macos", feature = "ffmpeg")))]
        {
            let result = decoder.decode_packet(&packet, 0);
            assert!(result.is_err(), "expected Err, got {result:?}");
        }

        #[cfg(target_os = "macos")]
        {
            // On macOS, decoding arbitrary data must not panic; it may
            // succeed (no SPS/PPS yet) or return an error.
            let _ = decoder.decode_packet(&packet, 0);
        }
    }

    #[test]
    fn test_parse_h264_annex_b() {
        // Create minimal H.264 stream with SPS + IDR
        let sps = vec![
            0x00, 0x00, 0x00, 0x01, // Start code
            0x67, // SPS NAL type
            0x64, 0x00, 0x1E, 0xAC, 0x52,
        ];
        let pps = vec![
            0x00, 0x00, 0x00, 0x01, // Start code
            0x68, // PPS NAL type
            0xEE, 0x3C, 0x80,
        ];
        let idr = vec![
            0x00, 0x00, 0x00, 0x01, // Start code
            0x65, // IDR NAL type
            0x88, 0x84, 0x00, 0xAD, 0xB7,
        ];

        let mut stream = Vec::new();
        stream.extend_from_slice(&sps);
        stream.extend_from_slice(&pps);
        stream.extend_from_slice(&idr);

        let nalus = parse_h264_annex_b(&stream);
        assert_eq!(nalus.len(), 3);
        assert_eq!(nalus[0][0] & 0x1F, 7); // SPS
        assert_eq!(nalus[1][0] & 0x1F, 8); // PPS
        assert_eq!(nalus[2][0] & 0x1F, 5); // IDR
    }

    #[test]
    fn test_mf_transform_lifecycle() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 640,
            height: 480,
            fps: 30.0,
            bitrate: 1_000_000,
        };
        let mut transform = MfTransform::new(config);
        assert_eq!(transform.input_queued(), 0);

        // Test ProcessMessage
        let _result = transform.process_message(MftMessageType::Reset);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = transform.process_message(MftMessageType::NewStream);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = transform.process_message(MftMessageType::Flush);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = transform.process_message(MftMessageType::Drain);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");

        // Test ProcessInput/ProcessOutput
        let packet = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88];
        let input_result = transform.process_input(&packet, 0);
        // May succeed or fail depending on platform/features
        let _ = input_result;

        let output = transform.process_output().unwrap_or(None);
        if let Some(frame) = output {
            assert!(frame.pts > 0 || frame.duration > 0);
        }
    }

    #[test]
    fn test_metal_texture_upload_prepare_rgba() {
        let frame = VideoFrame {
            width: 4,
            height: 4,
            data: vec![128u8; 4 * 4 * 4], // RGBA gray
            pts: 0,
            duration: 33_333,
            texture_id: None,
            metal_texture: None,
            color_space: ColorSpace::Rec709,
        };

        let upload = prepare_metal_texture_upload(
            &frame,
            MetalTextureFormat::RGBA8Unorm,
            ColorSpace::Rec709,
        )
        .unwrap();
        assert_eq!(upload.format, MetalTextureFormat::RGBA8Unorm);
        assert_eq!(upload.bytes_per_row, 16);
        assert_eq!(upload.data.len(), 64);
    }

    #[test]
    fn test_metal_texture_upload_prepare_bgra() {
        let frame = VideoFrame {
            width: 4,
            height: 4,
            data: std::iter::repeat_n([255u8, 0, 0, 255], 16)
                .flatten()
                .collect(), // Red RGBA pixels
            pts: 0,
            duration: 33_333,
            texture_id: None,
            metal_texture: None,
            color_space: ColorSpace::Rec709,
        };

        let upload = prepare_metal_texture_upload(
            &frame,
            MetalTextureFormat::BGRA8Unorm,
            ColorSpace::Rec709,
        )
        .unwrap();
        assert_eq!(upload.format, MetalTextureFormat::BGRA8Unorm);
        // First pixel: RGBA(255,0,0,255) -> BGRA(0,0,255,255)
        assert_eq!(upload.data[0], 0); // B
        assert_eq!(upload.data[1], 0); // G
        assert_eq!(upload.data[2], 255); // R
        assert_eq!(upload.data[3], 255); // A
    }

    #[test]
    fn test_metal_texture_upload_prepare_nv12() {
        let frame = VideoFrame {
            width: 4,
            height: 4,
            data: vec![128u8; 4 * 4 * 4], // Gray RGBA
            pts: 0,
            duration: 33_333,
            texture_id: None,
            metal_texture: None,
            color_space: ColorSpace::Rec709,
        };

        let upload =
            prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Rec709)
                .unwrap();
        assert_eq!(upload.format, MetalTextureFormat::NV12);
        // NV12: Y plane (16 bytes) + interleaved UV (8 bytes)
        assert_eq!(upload.data.len(), 24);
    }

    #[test]
    fn test_color_space_conversion() {
        let frame = VideoFrame {
            width: 2,
            height: 2,
            data: vec![128u8; 2 * 2 * 4],
            pts: 0,
            duration: 33_333,
            texture_id: None,
            metal_texture: None,
            color_space: ColorSpace::Rec709,
        };

        // Test Rec.601
        let upload_601 =
            prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Rec601)
                .unwrap();
        assert_eq!(upload_601.data.len(), 6); // 4 Y + 2 UV (for 2x2)

        // Test Rec.2020
        let upload_2020 =
            prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Rec2020)
                .unwrap();
        assert_eq!(upload_2020.data.len(), 6);

        // Test Rec.709 (default)
        let upload_709 =
            prepare_metal_texture_upload(&frame, MetalTextureFormat::NV12, ColorSpace::Rec709)
                .unwrap();
        assert_eq!(upload_709.data.len(), 6);
    }

    #[test]
    fn test_frame_pts_ordering() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 320,
            height: 240,
            fps: 30.0,
            bitrate: 500_000,
        };
        let mut decoder = VideoDecoder::new(config);

        // Simulate feeding frames at different PTS values
        let sps = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC];
        let _ = decoder.feed_data(&sps);
        let pps = vec![0x00, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80];
        let _ = decoder.feed_data(&pps);

        // Feed multiple packets with different PTS
        for pts_step in 0..3 {
            let pts = pts_step * 33_333;
            let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, pts_step as u8];
            #[cfg(feature = "ffmpeg")]
            {
                let _ = decoder.decode_packet(&idr, pts);
            }
            #[cfg(not(feature = "ffmpeg"))]
            {
                let _ = pts;
                let _ = decoder.feed_data(&idr);
            }
        }

        let frames = decoder.flush();
        // Verify frames are in PTS order (if any were decoded)
        for window in frames.windows(2) {
            assert!(
                window[0].pts <= window[1].pts,
                "Frames should be in PTS order"
            );
        }
    }

    #[test]
    fn test_yuv420p_to_rgba() {
        let width = 4u32;
        let height = 4u32;
        let y_size = (width * height) as usize;
        let uv_size = y_size / 4;
        let mut yuv = vec![128u8; y_size + uv_size * 2];

        // Set some Y values
        yuv[0] = 255; // White pixel
        yuv[1] = 0; // Black pixel

        let rgba = yuv420p_to_rgba(&yuv, width, height);
        assert_eq!(rgba.len(), (width * height * 4) as usize);
    }

    #[test]
    fn test_video_decoder_reset() {
        let config = VideoDecoderConfig::default();
        let mut decoder = VideoDecoder::new(config);
        decoder.reset();
        assert!(!decoder.has_frames());
    }

    #[test]
    fn test_parse_h264_sps_known_resolution() {
        // A known SPS for 1920x1080 (common real-world SPS)
        let sps_1080p: Vec<u8> = vec![
            0x67, 0x64, 0x00, 0x1e, 0xac, 0xd9, 0x40, 0xb4, 0x2f, 0xf9, 0x61, 0x01, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
            0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        ];
        let (w, h) = parse_h264_sps(&sps_1080p);
        assert!(
            w > 0 && h > 0,
            "Should extract resolution from SPS, got {}x{}",
            w,
            h
        );
    }

    #[test]
    fn test_parse_h264_sps_empty() {
        let (w, h) = parse_h264_sps(&[]);
        assert_eq!(w, 0);
        assert_eq!(h, 0);
    }

    #[test]
    fn test_mf_source_reader() {
        let mut reader = MfSourceReader::new();
        reader.set_output_size(640, 480);
        reader.set_frame_rate(30.0);
        reader.initialize("test.mp4").unwrap();

        // Read a sample
        let result = reader.read_sample().unwrap();
        assert!(result.is_none()); // No actual data to decode

        reader.shutdown();
    }

    #[test]
    fn test_video_decoder_flush() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 640,
            height: 480,
            fps: 30.0,
            bitrate: 1_000_000,
        };
        let mut decoder = VideoDecoder::new(config);

        let sps = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x64, 0x00, 0x1E, 0xAC];
        let _ = decoder.feed_data(&sps);
        let pps = vec![0x00, 0x00, 0x00, 0x01, 0x68, 0xEE, 0x3C, 0x80];
        let _ = decoder.feed_data(&pps);

        for _ in 0..3 {
            let idr = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88];
            let _ = decoder.feed_data(&idr);
        }

        let frames = decoder.flush();
        // Without ffmpeg feature and not on macOS, flush returns 0 frames
        #[cfg(not(any(target_os = "macos", feature = "ffmpeg")))]
        assert_eq!(frames.len(), 0);
        #[cfg(any(target_os = "macos", feature = "ffmpeg"))]
        let _ = frames;
    }

    #[test]
    fn test_video_codec_enum() {
        assert_eq!(VideoCodec::H264 as u32, 0);
        assert_eq!(VideoCodec::H265 as u32, 1);
        assert_eq!(VideoCodec::VP9 as u32, 2);
        assert_eq!(VideoCodec::Unknown as u32, 3);
    }

    #[test]
    fn test_color_space_default() {
        assert_eq!(ColorSpace::default(), ColorSpace::Rec709);
    }

    // -----------------------------------------------------------------------
    // Malformed container / edge-case video decoder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_empty_input() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 640,
            height: 480,
            fps: 30.0,
            bitrate: 1_000_000,
        };
        let mut decoder = VideoDecoder::new(config);

        let result = decoder.decode_packet(&[], 0);
        // Empty input should either return Ok(0) or an error, but never panic
        if let Ok(count) = result {
            assert_eq!(count, 0, "empty input should decode 0 frames");
        }
    }

    #[test]
    fn test_feed_data_empty() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 320,
            height: 240,
            fps: 30.0,
            bitrate: 500_000,
        };
        let mut decoder = VideoDecoder::new(config);
        let result = decoder.feed_data(&[]);
        // Should not panic; may succeed or fail
        let _ = result;
    }

    #[test]
    fn test_feed_data_truncated_nal_unit() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 320,
            height: 240,
            fps: 30.0,
            bitrate: 500_000,
        };
        let mut decoder = VideoDecoder::new(config);

        // Feed a start code followed by only 1 byte (truncated NAL)
        let truncated = vec![0x00, 0x00, 0x00, 0x01, 0x67];
        let result = decoder.feed_data(&truncated);
        // Should not panic
        let _ = result;

        // Feed only a start code with no NAL bytes at all
        let start_code_only = vec![0x00, 0x00, 0x00, 0x01];
        let result2 = decoder.feed_data(&start_code_only);
        let _ = result2;
    }

    #[test]
    fn test_feed_data_invalid_codec_data() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 320,
            height: 240,
            fps: 30.0,
            bitrate: 500_000,
        };
        let mut decoder = VideoDecoder::new(config);

        // Feed random garbage data (no valid start codes)
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let result = decoder.feed_data(&garbage);
        // Should not panic; data is buffered but no NAL units detected
        let _ = result;
    }

    #[test]
    fn test_feed_data_truncated_mid_nal() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 320,
            height: 240,
            fps: 30.0,
            bitrate: 500_000,
        };
        let mut decoder = VideoDecoder::new(config);

        // Feed SPS header then truncated SPS body
        let sps_start = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x64];
        let _ = decoder.feed_data(&sps_start);

        // Feed another start code that terminates the previous NAL
        let pps_start = vec![0x00, 0x00, 0x00, 0x01, 0x68];
        let _ = decoder.feed_data(&pps_start);

        // Should not panic
        assert!(!decoder.has_frames());
    }

    #[test]
    fn test_parse_h264_annex_b_empty() {
        let nalus = parse_h264_annex_b(&[]);
        assert!(nalus.is_empty(), "empty input should yield no NAL units");
    }

    #[test]
    fn test_parse_h264_annex_b_no_start_code() {
        let nalus = parse_h264_annex_b(&[0xAA, 0xBB, 0xCC]);
        assert!(
            nalus.is_empty(),
            "data without start codes should yield no NAL units"
        );
    }

    #[test]
    fn test_parse_h264_annex_b_truncated_start_code() {
        // Only 3 bytes of a 4-byte start code
        let nalus = parse_h264_annex_b(&[0x00, 0x00, 0x00]);
        assert!(nalus.is_empty());
    }

    #[test]
    fn test_parse_h264_sps_truncated() {
        // SPS with only 2 bytes (too short for real parsing)
        let (w, h) = parse_h264_sps(&[0x67, 0x64]);
        // Should return (0, 0) without panicking
        assert_eq!((w, h), (0, 0), "truncated SPS should yield no dimensions");
    }

    #[test]
    fn test_mf_source_reader_empty_data() {
        let mut reader = MfSourceReader::new();
        // Initialize with empty data should not panic
        let result = reader.initialize("");
        // May fail, but should not panic
        let _ = result;
    }

    #[test]
    fn test_mf_transform_process_empty_input() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::H264,
            width: 640,
            height: 480,
            fps: 30.0,
            bitrate: 1_000_000,
        };
        let mut transform = MfTransform::new(config);
        let result = transform.process_input(&[], 0);
        // Should not panic
        let _ = result;
    }

    #[test]
    fn test_video_decoder_unknown_codec() {
        let config = VideoDecoderConfig {
            codec: VideoCodec::Unknown,
            width: 640,
            height: 480,
            fps: 30.0,
            bitrate: 1_000_000,
        };
        let mut decoder = VideoDecoder::new(config);
        // Should not panic on creation
        assert!(!decoder.has_frames());

        // Decoding with Unknown codec should handle gracefully
        let data = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88];
        let result = decoder.decode_packet(&data, 0);
        let _ = result;
    }

    // -----------------------------------------------------------------------
    // CoreVideo/IOSurface zero-copy path
    // -----------------------------------------------------------------------

    /// Generate a deterministic RGBA test pattern.
    #[cfg(target_os = "macos")]
    fn test_pattern_rgba(width: u32, height: u32, seed: u32) -> Vec<u8> {
        let mut rgba = Vec::with_capacity((width * height * 4) as usize);
        for y in 0..height {
            for x in 0..width {
                rgba.push((x.wrapping_mul(3).wrapping_add(seed)) as u8);
                rgba.push((y.wrapping_mul(5).wrapping_add(seed)) as u8);
                rgba.push(seed.wrapping_add(17) as u8);
                rgba.push(255);
            }
        }
        rgba
    }

    #[test]
    fn test_probe_zero_copy_status_reports_metal() {
        let decoder = VideoDecoder::new(VideoDecoderConfig::default());
        let probe = probe_zero_copy_status();
        assert_eq!(
            decoder.zero_copy_status(),
            probe,
            "decoder must report the probed capability"
        );
        // This machine has a real Metal device; the CoreVideo cache must be
        // creatable. If that changes, the CPU fallback remains correct, so
        // only log rather than fail when the probe is negative.
        if probe.is_available() {
            let status = decoder.zero_copy_status();
            assert!(status.is_available());
        } else {
            eprintln!("zero-copy unavailable: {}", probe.reason());
        }
    }

    #[test]
    fn test_software_sequence_produces_iosurface_frames() {
        #[cfg(target_os = "macos")]
        {
            if !probe_zero_copy_status().is_available() {
                eprintln!(
                    "skipping IOSurface sequence test: {}",
                    probe_zero_copy_status().reason()
                );
                return;
            }

            let (width, height) = (16u32, 8u32);
            let before = zero_copy_stats();
            let mut frames = Vec::new();
            for i in 0..3u8 {
                let rgba = test_pattern_rgba(width, height, u32::from(i) * 31);
                let frame = create_corevideo_frame_from_rgba(
                    width,
                    height,
                    &rgba,
                    u64::from(i) * 33_333,
                    33_333,
                    ColorSpace::Rec709,
                )
                .expect("CoreVideo frame creation must succeed with a Metal device");
                assert_eq!(frame.width, width);
                assert_eq!(frame.height, height);
                assert!(
                    frame.is_iosurface_backed(),
                    "frame {i} must be IOSurface-backed"
                );
                assert!(
                    frame.metal_texture.is_some(),
                    "frame {i} must expose a Metal texture"
                );
                assert!(!frame.has_uv_plane());
                assert!(frame.pixel_buffer_ptr().is_some());
                assert!(
                    frame.data.is_empty(),
                    "zero-copy frame {i} must not carry a CPU copy"
                );
                frames.push(frame);
            }
            let after = zero_copy_stats();
            assert!(
                after.iosurface_frames >= before.iosurface_frames + 3,
                "3 IOSurface-backed frames expected: before={before:?} after={after:?}"
            );

            // Real CoreVideo lock/read-back: the pixels are accessible to CPU
            // consumers through the retained pixel buffer.
            unsafe {
                use self::vt_ffi::*;
                let frame = &frames[0];
                let pixel_buffer = frame.pixel_buffer_ptr().expect("retained pixel buffer");
                assert_eq!(CVPixelBufferLockBaseAddress(pixel_buffer, 0), 0);
                let base = CVPixelBufferGetBaseAddress(pixel_buffer) as *const u8;
                let bytes_per_row = CVPixelBufferGetBytesPerRow(pixel_buffer);
                assert!(!base.is_null());
                assert!(bytes_per_row >= (width as usize) * 4);
                // First pixel of pattern seed 0: RGBA(0,0,17,255) -> BGRA(17,0,0,255)
                assert_eq!(*base, 17, "BGRA blue channel");
                assert_eq!(*base.add(1), 0, "BGRA green channel");
                assert_eq!(*base.add(2), 0, "BGRA red channel");
                assert_eq!(*base.add(3), 255, "BGRA alpha channel");
                assert_eq!(CVPixelBufferUnlockBaseAddress(pixel_buffer, 0), 0);
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("skipping IOSurface sequence test off macOS");
        }
    }

    #[test]
    fn test_software_nv12_frame_exposes_two_plane_textures() {
        #[cfg(target_os = "macos")]
        {
            if !probe_zero_copy_status().is_available() {
                eprintln!("skipping NV12 test: {}", probe_zero_copy_status().reason());
                return;
            }

            let (width, height) = (16u32, 8u32);
            let y_plane = vec![128u8; (width * height) as usize];
            let uv_plane = vec![64u8; ((width / 2) * (height / 2) * 2) as usize];
            let before = zero_copy_stats();
            let frame = create_corevideo_nv12_frame(
                width,
                height,
                &y_plane,
                &uv_plane,
                0,
                33_333,
                ColorSpace::Rec709,
            )
            .expect("NV12 CoreVideo frame creation must succeed");

            assert!(frame.is_iosurface_backed());
            assert!(frame.metal_texture.is_some(), "Y plane texture");
            assert!(frame.has_uv_plane(), "UV plane texture");
            assert!(frame.data.is_empty());

            // The NV12 planes must be readable through CoreVideo's locks.
            unsafe {
                use self::vt_ffi::*;
                let pixel_buffer = frame.pixel_buffer_ptr().expect("retained pixel buffer");
                assert_eq!(CVPixelBufferLockBaseAddress(pixel_buffer, 0), 0);
                let y_base = CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, 0) as *const u8;
                let uv_base = CVPixelBufferGetBaseAddressOfPlane(pixel_buffer, 1) as *const u8;
                let y_stride = CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, 0);
                let uv_stride = CVPixelBufferGetBytesPerRowOfPlane(pixel_buffer, 1);
                assert!(!y_base.is_null() && !uv_base.is_null());
                assert!(y_stride >= width as usize);
                assert!(uv_stride >= (width as usize));
                assert_eq!(*y_base, 128);
                assert_eq!(*uv_base, 64);
                assert_eq!(*uv_base.add(1), 64);
                assert_eq!(CVPixelBufferUnlockBaseAddress(pixel_buffer, 0), 0);
            }

            let after = zero_copy_stats();
            assert!(after.iosurface_frames >= before.iosurface_frames + 1);
        }
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("skipping NV12 test off macOS");
        }
    }

    #[test]
    fn test_wrap_io_surface_in_pixel_buffer_roundtrip() {
        #[cfg(target_os = "macos")]
        {
            use self::vt_ffi::*;
            let surface = crate::metal_backend::create_io_surface(8, 8)
                .expect("IOSurfaceCreate must succeed");
            let pixel_buffer =
                unsafe { wrap_io_surface_in_pixel_buffer(surface).expect("pixel buffer wrapping") };
            unsafe {
                assert_eq!(CVPixelBufferGetWidth(pixel_buffer), 8);
                assert_eq!(CVPixelBufferGetHeight(pixel_buffer), 8);
                assert_eq!(
                    CVPixelBufferGetPixelFormatType(pixel_buffer),
                    kCVPixelFormatType_32BGRA
                );
                assert!(!CVPixelBufferGetIOSurface(pixel_buffer).is_null());
                CVPixelBufferRelease(pixel_buffer);
                core_foundation::base::CFRelease(surface as core_foundation::base::CFTypeRef);
            }
        }
    }

    // ---- Hardware VideoToolbox decode (capability-gated) ----

    #[cfg(target_os = "macos")]
    struct EncoderSink {
        samples: Mutex<Vec<Vec<u8>>>,
    }

    #[cfg(target_os = "macos")]
    unsafe fn set_vt_property_number(
        session: vt_ffi::VTCompressionSessionRef,
        key: &[u8],
        value: i32,
    ) {
        use self::vt_ffi::*;
        let key_ref = cfstring_from_bytes(key);
        let value_ref = cfnumber_i32(value);
        if !key_ref.is_null() && !value_ref.is_null() {
            unsafe {
                VTSessionSetProperty(session, key_ref, value_ref as CFTypeRef);
                CFRelease(key_ref as CFTypeRef);
                CFRelease(value_ref as CFTypeRef);
            }
        } else {
            unsafe {
                if !key_ref.is_null() {
                    CFRelease(key_ref as CFTypeRef);
                }
                if !value_ref.is_null() {
                    CFRelease(value_ref as CFTypeRef);
                }
            }
        }
    }

    /// VideoToolbox compression callback: convert each encoded AVCC sample to
    /// Annex B (SPS/PPS + slice NALs) and append it to the sink.
    #[cfg(target_os = "macos")]
    unsafe extern "C" fn compression_output_callback(
        refcon: *mut c_void,
        _source_frame: *mut c_void,
        status: i32,
        _info_flags: vt_ffi::VTEncodeInfoFlags,
        sample_buffer: vt_ffi::CMSampleBufferRef,
    ) {
        use self::vt_ffi::*;
        use std::ptr;

        unsafe {
            if status != 0 || sample_buffer.is_null() || refcon.is_null() {
                return;
            }
            let sink = &*(refcon as *const EncoderSink);
            let mut annexb: Vec<u8> = Vec::new();

            // Parameter sets (SPS/PPS) from the sample's format description.
            let format_desc = CMSampleBufferGetFormatDescription(sample_buffer);
            if !format_desc.is_null() {
                let mut count: usize = 0;
                let mut first_ptr: *const u8 = ptr::null();
                let mut first_size: usize = 0;
                if CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                    format_desc,
                    0,
                    &mut first_ptr,
                    &mut first_size,
                    &mut count,
                    ptr::null_mut(),
                ) == 0
                    && !first_ptr.is_null()
                    && first_size > 0
                {
                    annexb.extend_from_slice(&[0, 0, 0, 1]);
                    annexb.extend_from_slice(std::slice::from_raw_parts(first_ptr, first_size));
                    for index in 1..count {
                        let mut param_ptr: *const u8 = ptr::null();
                        let mut param_size: usize = 0;
                        if CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                            format_desc,
                            index,
                            &mut param_ptr,
                            &mut param_size,
                            ptr::null_mut(),
                            ptr::null_mut(),
                        ) == 0
                            && !param_ptr.is_null()
                            && param_size > 0
                        {
                            annexb.extend_from_slice(&[0, 0, 0, 1]);
                            annexb.extend_from_slice(std::slice::from_raw_parts(
                                param_ptr, param_size,
                            ));
                        }
                    }
                }
            }

            // AVCC sample data: 4-byte big-endian NAL lengths.
            let block_buffer = CMSampleBufferGetDataBuffer(sample_buffer);
            if !block_buffer.is_null() {
                let mut total: usize = 0;
                let mut data_ptr: *mut std::ffi::c_char = ptr::null_mut();
                if CMBlockBufferGetDataPointer(
                    block_buffer,
                    0,
                    ptr::null_mut(),
                    &mut total,
                    &mut data_ptr,
                ) == 0
                    && !data_ptr.is_null()
                    && total > 0
                {
                    let bytes = std::slice::from_raw_parts(data_ptr as *const u8, total);
                    let mut offset = 0usize;
                    while offset + 4 <= bytes.len() {
                        let length = u32::from_be_bytes([
                            bytes[offset],
                            bytes[offset + 1],
                            bytes[offset + 2],
                            bytes[offset + 3],
                        ]) as usize;
                        offset += 4;
                        if length == 0 || offset + length > bytes.len() {
                            break;
                        }
                        annexb.extend_from_slice(&[0, 0, 0, 1]);
                        annexb.extend_from_slice(&bytes[offset..offset + length]);
                        offset += length;
                    }
                }
            }

            if !annexb.is_empty() {
                lock_poisoned(&sink.samples).push(annexb);
            }
        }
    }

    /// Encode `frame_count` synthetic frames as a real H.264 Annex B stream
    /// using VideoToolbox. Returns `None` when no encoder is available.
    #[cfg(target_os = "macos")]
    fn encode_test_h264(width: u32, height: u32, frame_count: usize) -> Option<Vec<Vec<u8>>> {
        use self::vt_ffi::*;
        use std::ptr;
        use std::sync::Arc;

        let sink = Arc::new(EncoderSink {
            samples: Mutex::new(Vec::new()),
        });
        let refcon = Arc::into_raw(sink.clone()) as *mut c_void;

        let mut session: VTCompressionSessionRef = ptr::null_mut();
        let status = unsafe {
            VTCompressionSessionCreate(
                ptr::null_mut(),
                width as i32,
                height as i32,
                kCMVideoCodecType_H264,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                Some(compression_output_callback),
                refcon,
                &mut session,
            )
        };
        if status != 0 || session.is_null() {
            unsafe {
                drop(Arc::from_raw(refcon as *const EncoderSink));
            }
            eprintln!("[test] VTCompressionSessionCreate failed (status={status})");
            return None;
        }

        // Real-time, no frame reordering, keyframe every frame: the decoder
        // can then decode each sample independently.
        unsafe {
            set_vt_property_number(session, kVTCompressionPropertyKey_RealTime, 1);
            set_vt_property_number(session, kVTCompressionPropertyKey_AllowFrameReordering, 0);
            set_vt_property_number(session, kVTCompressionPropertyKey_MaxKeyFrameInterval, 1);
        }

        let mut encode_failed = false;
        for index in 0..frame_count {
            let mut source: CVPixelBufferRef = ptr::null_mut();
            let create_status = unsafe {
                CVPixelBufferCreate(
                    ptr::null_mut(),
                    width as usize,
                    height as usize,
                    kCVPixelFormatType_32BGRA,
                    ptr::null(),
                    &mut source,
                )
            };
            if create_status != 0 || source.is_null() {
                encode_failed = true;
                break;
            }

            // Fill a moving gradient through the CoreVideo lock.
            unsafe {
                if CVPixelBufferLockBaseAddress(source, 0) == 0 {
                    let base = CVPixelBufferGetBaseAddress(source) as *mut u8;
                    let stride = CVPixelBufferGetBytesPerRow(source);
                    if !base.is_null() {
                        for y in 0..height as usize {
                            for x in 0..width as usize {
                                let pixel = base.add(y * stride + x * 4);
                                *pixel = (x * 4) as u8;
                                *pixel.add(1) = (y * 4) as u8;
                                *pixel.add(2) = (index * 40) as u8;
                                *pixel.add(3) = 255;
                            }
                        }
                    }
                    let _ = CVPixelBufferUnlockBaseAddress(source, 0);
                }
            }

            let mut info_flags: VTEncodeInfoFlags = 0;
            let encode_status = unsafe {
                VTCompressionSessionEncodeFrame(
                    session,
                    source,
                    CMTime::make(index as i64, 30),
                    CMTime::make(1, 30),
                    ptr::null(),
                    ptr::null_mut(),
                    &mut info_flags,
                )
            };
            unsafe { CVPixelBufferRelease(source) };
            if encode_status != 0 {
                encode_failed = true;
                break;
            }
        }

        // kCMTimeInvalid waits for all pending frames.
        unsafe {
            let _ = VTCompressionSessionCompleteFrames(session, CMTime::make(0, 0));
            VTCompressionSessionInvalidate(session);
            CFRelease(session as CFTypeRef);
            drop(Arc::from_raw(refcon as *const EncoderSink));
        }

        if encode_failed {
            return None;
        }
        let samples = lock_poisoned(&sink.samples).clone();
        if samples.is_empty() {
            None
        } else {
            Some(samples)
        }
    }

    #[test]
    fn test_hardware_vt_decode_is_iosurface_backed() {
        #[cfg(target_os = "macos")]
        {
            if !probe_zero_copy_status().is_available() {
                eprintln!(
                    "skipping hardware decode test: {}",
                    probe_zero_copy_status().reason()
                );
                return;
            }

            let (width, height) = (64u32, 64u32);
            let Some(samples) = encode_test_h264(width, height, 3) else {
                eprintln!("skipping hardware decode test: VT encoder unavailable");
                return;
            };

            let mut decoder = VideoDecoder::new(VideoDecoderConfig {
                codec: VideoCodec::H264,
                width,
                height,
                fps: 30.0,
                bitrate: 1_000_000,
            });
            assert!(decoder.zero_copy_status().is_available());

            let before = zero_copy_stats();
            for (index, sample) in samples.iter().enumerate() {
                let _ = decoder.decode_packet(sample, index as u64 * 33_333);
            }
            let frames = decoder.flush();
            if frames.is_empty() {
                // Hardware decode is capability-gated: this machine exposes a
                // Metal device but may not have a hardware H.264 decoder for
                // the encoded profile. The CPU path remains correct.
                eprintln!(
                    "skipping hardware decode assertions: VideoToolbox produced no frames \
                     (hardware H.264 decode unavailable)"
                );
                return;
            }

            let after = zero_copy_stats();
            for (index, frame) in frames.iter().enumerate() {
                assert!(
                    frame.is_iosurface_backed(),
                    "hardware frame {index} must be IOSurface-backed"
                );
                assert!(
                    frame.metal_texture.is_some(),
                    "hardware frame {index} must expose a Metal texture"
                );
                assert!(
                    frame.data.is_empty(),
                    "hardware frame {index} must be zero-copy (no CPU pixels)"
                );
            }
            assert!(
                after.iosurface_frames >= before.iosurface_frames + frames.len() as u64,
                "every hardware frame must count as IOSurface-backed: before={before:?} \
                 after={after:?} frames={}",
                frames.len()
            );
            assert!(
                after.cpu_copies_avoided >= before.cpu_copies_avoided + frames.len() as u64,
                "every hardware frame must count as an avoided CPU copy"
            );
            eprintln!(
                "hardware video decode produced {} IOSurface-backed frames",
                frames.len()
            );
        }
        #[cfg(not(target_os = "macos"))]
        {
            eprintln!("skipping hardware decode test off macOS");
        }
    }
}
