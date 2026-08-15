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
use std::sync::{Arc, Mutex};

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
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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
#[cfg(target_os = "macos")]
fn yuv_to_rgb_coeffs(color_space: ColorSpace) -> (f32, f32, f32, f32) {
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

#[cfg(target_os = "macos")]
impl Drop for VideoFrame {
    fn drop(&mut self) {
        // SAFETY: `metal_texture` is a +1 retained id<MTLTexture> owned by
        // this frame (see `MetalVideoTextureCache::create_texture_from_pixel_buffer`).
        if let Some(ptr) = self.metal_texture {
            unsafe {
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

    /// Block buffer flag: ensure memory is backed by real pages.
    pub const kCMBlockBuffer_AssureMemoryNowFlag: u32 = 0;

    /// kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder key.
    pub const kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder: &[u8] =
        b"RequireHardwareAcceleratedVideoDecoder\0";

    /// kCVPixelBufferPixelFormatTypeKey
    pub const kCVPixelBufferPixelFormatTypeKey: &[u8] = b"PixelFormatType\0";

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
        /// Matches the real API:
        /// `CMVideoFormatDescriptionCreateFromH264ParameterSets(allocator,
        /// parameterSetCount, parameterSetSizes, parameterSetPointers,
        /// nalUnitHeaderLength, out)`.
        pub fn CMVideoFormatDescriptionCreateFromH264ParameterSets(
            allocator: CFAllocatorRef,
            parameterSetCount: usize,
            parameterSetSizes: *const usize,
            parameterSetPointers: *const *const u8,
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

        #[cfg(target_os = "macos")]
        let metal_cache =
            metal::Device::system_default().and_then(|dev| MetalVideoTextureCache::new(&dev));

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
            CMVideoFormatDescriptionCreateFromH264ParameterSets(
                ptr::null_mut(), // kCFAllocatorDefault
                2,               // SPS + PPS
                param_set_sizes.as_ptr(),
                param_set_pointers.as_ptr(),
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
                unsafe { let _ = Arc::from_raw(refcon as *const DecoderContext); }
            }
            if !format_desc.is_null() {
                unsafe { CFRelease(format_desc as CFTypeRef) };
            }
        };

        // 4. Create destination pixel buffer attributes (request BGRA output)
        let dest_attrs = match create_bgra_pixel_buffer_attributes() {
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

        // 6. Create the decompression session
        let mut session: VTDecompressionSessionRef = ptr::null_mut();
        let status = unsafe {
            VTDecompressionSessionCreate(
                ptr::null_mut(), // kCFAllocatorDefault
                format_desc,
                decoder_spec,
                dest_attrs,
                &callback_record,
                &mut session,
            )
        };

        // Release CoreFoundation objects we created
        if !decoder_spec.is_null() {
            unsafe { CFRelease(decoder_spec as CFTypeRef) };
        }
        if !dest_attrs.is_null() {
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
            unsafe { let _ = Arc::from_raw(refcon as *const DecoderContext); }
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
                    format!(
                        "NV12 upload requires even dimensions, got {width}x{height}"
                    ),
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
#[cfg(feature = "metal")]
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

// ── Non-Metal software fallback frame storage ─────────────────────────────

/// Holds the most recently uploaded frame data for CPU-side access
/// when Metal is not available.
struct SoftwareFrameBuffer {
    /// RGBA pixel data.
    data: Vec<u8>,
    /// Frame width in pixels.
    width: u32,
    /// Frame height in pixels.
    height: u32,
    /// Bytes per row (stride).
    stride: u32,
}

impl SoftwareFrameBuffer {
    const fn new() -> Self {
        Self {
            data: Vec::new(),
            width: 0,
            height: 0,
            stride: 0,
        }
    }
}

/// Global software frame buffer for the non-Metal fallback path.
static SOFTWARE_FRAME: Mutex<SoftwareFrameBuffer> = Mutex::new(SoftwareFrameBuffer::new());

/// Non-Metal fallback for `upload_frame_to_metal_texture`.
///
/// When the `metal` feature is disabled, this function stores the uploaded
/// frame data in a global software buffer for CPU-side rendering access.
/// The RGBA data is stored as-is from the upload descriptor (conversion
/// from YUV to RGB should be done beforehand using `yuv420p_to_rgba`).
///
/// Returns the number of bytes stored (0 on error).
#[cfg(not(feature = "metal"))]
pub fn upload_frame_to_metal_texture(
    _texture: &metal::TextureRef,
    upload: &MetalTextureUpload,
    _slice: u64,
) -> u64 {
    let mut buf = match SOFTWARE_FRAME.lock() {
        Ok(b) => b,
        Err(_) => return 0,
    };

    // Determine bytes per row from upload or default to RGBA (4 bytes per pixel)
    let bpr = if upload.bytes_per_row > 0 {
        upload.bytes_per_row
    } else {
        upload.width * 4
    };

    buf.width = upload.width;
    buf.height = upload.height;
    buf.stride = bpr;
    buf.data = upload.data.clone();

    upload.data.len() as u64
}

/// Retrieve the latest software-rendered frame as RGBA bytes.
///
/// Returns `(data, width, height, stride)` where `data` is the RGBA pixel
/// buffer, or `None` if no frame has been uploaded yet.
///
/// This is the primary accessor for CPU-side rendering when Metal is not
/// available (e.g., software rendering, remote desktop, or off-screen
/// processing).
#[cfg(not(feature = "metal"))]
pub fn get_latest_software_frame() -> Option<(Vec<u8>, u32, u32, u32)> {
    let buf = SOFTWARE_FRAME.lock().ok()?;
    if buf.data.is_empty() || buf.width == 0 || buf.height == 0 {
        return None;
    }
    Some((buf.data.clone(), buf.width, buf.height, buf.stride))
}

/// Check whether a software frame is currently available.
#[cfg(not(feature = "metal"))]
pub fn has_software_frame() -> bool {
    SOFTWARE_FRAME
        .lock()
        .map(|b| !b.data.is_empty() && b.width > 0 && b.height > 0)
        .unwrap_or(false)
}

/// Clear the software frame buffer, releasing its memory.
#[cfg(not(feature = "metal"))]
pub fn clear_software_frame() {
    if let Ok(mut buf) = SOFTWARE_FRAME.lock() {
        buf.data.clear();
        buf.width = 0;
        buf.height = 0;
        buf.stride = 0;
    }
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
            // ---- ZERO-COPY PATH (CVMetalTextureCache) ----
            // Only 32BGRA pixel buffers are eligible: CoreVideo supports
            // direct BGRA texture wrapping, and requesting anything else
            // (e.g. "converting" NV12 to BGRA) yields undefined contents.
            // NV12 buffers fall through to the software path below.
            if let Some(ref metal_cache) = ctx.metal_cache {
                let pixel_format = CVPixelBufferGetPixelFormatType(imageBuffer);
                if pixel_format == kCVPixelFormatType_32BGRA {
                    let mtl_texture = metal_cache.create_texture_from_pixel_buffer(
                        imageBuffer,
                        width,
                        height,
                        MTLPixelFormatBGRA8Unorm,
                        0, // planeIndex: 0 for single-plane BGRA
                    );
                    if let Some(texture_ptr) = mtl_texture {
                        // Zero-copy succeeded — no need to lock / copy pixels.
                        let frame = VideoFrame {
                            width: ctx.output_width.max(width),
                            height: ctx.output_height.max(height),
                            data: Vec::new(), // zero-copy — no CPU data
                            pts,
                            duration,
                            texture_id: None,
                            metal_texture: Some(texture_ptr),
                            color_space: ctx.color_space,
                        };
                        Some(frame)
                    } else {
                        // Zero-copy failed — fall through to software path below.
                        software_copy(&ctx, imageBuffer, width, height, pts, duration)
                    }
                } else {
                    software_copy(&ctx, imageBuffer, width, height, pts, duration)
                }
            } else {
                software_copy(&ctx, imageBuffer, width, height, pts, duration)
            }
        };

        if let Some(frame) = result {
            let mut frames = lock_poisoned(&ctx.frames);
            frames.push_back(frame);
        }

        drop(ctx);
    }
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
        kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange => {
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
                            let g = (y_val - cg_u * u_val - cg_v * v_val).clamp(0.0, 255.0) as u8;
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
// CoreFoundation dictionary helpers
// ===========================================================================

/// Create a CFDictionary to request BGRA pixel buffers from VideoToolbox.
#[cfg(target_os = "macos")]
pub(crate) fn create_bgra_pixel_buffer_attributes() -> AppResult<vt_ffi::CFDictionaryRef> {
    use self::vt_ffi::*;
    use std::ffi::CString;
    use std::ptr;

    unsafe {
        // Key: kCVPixelBufferPixelFormatTypeKey
        let key_cstr = CString::new(kCVPixelBufferPixelFormatTypeKey).map_err(|_| {
            AppError::new(
                ReasonCode::RcMediaInvalid,
                "Invalid CString for pixel format key",
            )
        })?;
        let key_str =
            CFStringCreateWithCString(ptr::null(), key_cstr.as_ptr(), kCFStringEncodingUTF8);
        if key_str.is_null() {
            return Ok(ptr::null());
        }

        // Value: kCVPixelFormatType_32BGRA as CFNumber
        let fmt = kCVPixelFormatType_32BGRA as i32;
        let val_num = CFNumberCreate(
            ptr::null_mut(),
            kCFNumberSInt32Type,
            &fmt as *const i32 as *const c_void,
        );
        if val_num.is_null() {
            CFRelease(key_str as CFTypeRef);
            return Ok(ptr::null());
        }

        let keys: [*const c_void; 1] = [key_str];
        let values: [*const c_void; 1] = [val_num];

        let dict = CFDictionaryCreate(
            ptr::null_mut(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            ptr::null(),
            ptr::null(),
        );

        // Release intermediate objects (dictionary retains its elements)
        CFRelease(key_str as CFTypeRef);
        CFRelease(val_num as CFTypeRef);

        Ok(dict)
    }
}

/// Create a CFDictionary to request hardware-accelerated decoding.
#[cfg(target_os = "macos")]
pub(crate) fn create_hardware_decoder_specification() -> AppResult<vt_ffi::CFDictionaryRef> {
    use self::vt_ffi::*;
    use std::ffi::CString;
    use std::ptr;

    unsafe {
        // Key: kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder
        let key_cstr =
            CString::new(kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder)
                .map_err(|_| {
                    AppError::new(
                        ReasonCode::RcMediaInvalid,
                        "Invalid CString for decoder spec key",
                    )
                })?;
        let key_str =
            CFStringCreateWithCString(ptr::null(), key_cstr.as_ptr(), kCFStringEncodingUTF8);
        if key_str.is_null() {
            return Ok(ptr::null());
        }

        // Value: kCFBooleanTrue — we use a CFNumber(1) as a simple boolean.
        // CFNumberCreate with kCFNumberSInt32Type reads a 4-byte value, so
        // the backing variable must be an i32.
        let val: i32 = 1;
        let val_num = CFNumberCreate(
            ptr::null_mut(),
            kCFNumberSInt32Type,
            &val as *const i32 as *const c_void,
        );
        if val_num.is_null() {
            CFRelease(key_str as CFTypeRef);
            return Ok(ptr::null());
        }

        let keys: [*const c_void; 1] = [key_str];
        let values: [*const c_void; 1] = [val_num];

        let dict = CFDictionaryCreate(
            ptr::null_mut(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            ptr::null(),
            ptr::null(),
        );

        CFRelease(key_str as CFTypeRef);
        CFRelease(val_num as CFTypeRef);

        Ok(dict)
    }
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

            let crop_w = crop_left.saturating_add(crop_right).saturating_mul(crop_unit_x);
            let crop_h = crop_top.saturating_add(crop_bottom).saturating_mul(crop_unit_y);
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
            data: std::iter::repeat_n([255u8, 0, 0, 255], 16).flatten().collect(), // Red RGBA pixels
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
}
