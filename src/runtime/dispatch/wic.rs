//! Windows Imaging Component dispatch: the windowscodecs.dll exports, in a
//! dedicated module per the audit's modularity requirement.  The surface is
//! a real in-process WIC object model: WICCreateImagingFactory hands out an
//! IWICImagingFactory whose Create* methods build palette, scaler, clipper,
//! flip-rotator, format-converter, stream, color-context and component-info
//! objects; CreateBitmap / CreateBitmapFromMemory / CreateBitmapFromSource
//! produce software bitmaps with the documented pixel formats; the
//! transform chain (scaler/clipper/flip/converter) wraps a source and
//! produces pixels through CopyPixels.  IWICBitmap::Lock hands out a real
//! lock over the bitmap's live pixels, the decoder surface parses real PNG
//! and baseline JPEG streams into frame-decode objects, and the encoder
//! surface writes real PNG files.  Metadata handlers are still absent, so
//! the metadata entry points answer WIC_E_CODECNOTHANDLED, and the _Proxy
//! exports mirror their in-process counterparts.
//!
//! Layer contract: every export and method returns its HRESULT in EAX.

use super::super::*;
use super::unknown_preamble;
use crate::runtime::state::{GuestObjectKind, WicObjectKind, WicObjectState};
use std::io::{Read as _, Write as _};

// ── WIC GUIDs (the well-known pixel formats + the factory CLSID) ──────────

const GUID_PIXEL_FORMAT_DONT_CARE: [u8; 16] = [
    0x3b, 0xc3, 0xdd, 0x6f, 0x03, 0x4e, 0xfe, 0x4b, 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x0f,
];
const GUID_PIXEL_FORMAT_32BPP_BGRA: [u8; 16] = [
    0x44, 0xc3, 0xdd, 0x6f, 0x03, 0x4e, 0xfe, 0x4b, 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x0f,
];
const GUID_PIXEL_FORMAT_32BPP_PBGRA: [u8; 16] = [
    0x45, 0xc3, 0xdd, 0x6f, 0x03, 0x4e, 0xfe, 0x4b, 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x0f,
];
const GUID_PIXEL_FORMAT_24BPP_BGR: [u8; 16] = [
    0x24, 0xc3, 0xdd, 0x6f, 0x03, 0x4e, 0xfe, 0x4b, 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x0f,
];
const GUID_PIXEL_FORMAT_8BPP_GRAY: [u8; 16] = [
    0x2a, 0xc3, 0xdd, 0x6f, 0x03, 0x4e, 0xfe, 0x4b, 0xb1, 0x85, 0x3d, 0x77, 0x76, 0x8d, 0xc9, 0x0f,
];
const GUID_PIXEL_FORMAT_32BPP_RGBA: [u8; 16] = [
    0x2d, 0xad, 0xc7, 0xf5, 0x8d, 0x6a, 0xdd, 0x43, 0xa7, 0xa8, 0xa2, 0x99, 0x35, 0x26, 0x1e, 0xa9,
];

// ── HRESULT codes ──────────────────────────────────────────────────────────

const S_OK: u32 = 0;
const E_INVALIDARG: u32 = 0x8007_0057;

// ── WIC HRESULT codes ─────────────────────────────────────────────────────

const WIC_E_CODECNOTFOUND: u32 = 0x8898_2f02;
const WIC_E_CODECNOTHANDLED: u32 = 0x8898_2f04;
const WIC_E_NOTSUPPORTED: u32 = 0x8898_2f00;
const WIC_E_UNSUPPORTEDPIXELFORMAT: u32 = 0x8898_2f0b;
const WIC_E_INVALIDSTATE: u32 = 0x8898_2f07;

// The canonical wincodec.h values for the new lock/codec paths.  (The older
// entries above are the runtime's historical aliases; new code answers the
// real Windows error values.)
const WINCODEC_ERR_ACCESSDENIED: u32 = 0x8898_2f05;
const WINCODEC_ERR_UNKNOWNIMAGEFORMAT: u32 = 0x8898_2f07;
const WINCODEC_ERR_NOTINITIALIZED: u32 = 0x8898_2f09;
const WINCODEC_ERR_COMPONENTNOTFOUND: u32 = 0x8898_2f50;
const WINCODEC_ERR_FRAMEMISSING: u32 = 0x8898_2f82;
const WINCODEC_ERR_STREAMNOTAVAILABLE: u32 = 0x8898_2f8b;
const WINCODEC_ERR_UNSUPPORTEDOPERATION: u32 = 0x8898_2f8d;
const WINCODEC_ERR_BADIMAGE: u32 = 0x8898_2f80;
const WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT: u32 = 0x8898_2f8c;

/// The IWICBitmapLock flags (WICBitmapLockRead / WICBitmapLockWrite).
const WIC_BITMAP_LOCK_READ: u32 = 1;
const WIC_BITMAP_LOCK_WRITE: u32 = 2;

/// The object-state magic tags (stored in slots the stream/bitmap objects
/// do not otherwise use, so no external state struct is needed).
const WIC_DECODER_MAGIC: &[u8; 8] = b"WICDEC01";
const WIC_ENCODER_MAGIC: &[u8; 8] = b"WICENC01";
const WIC_FRAME_ENCODE_MAGIC: u32 = 0x5749_4346;

/// GUID_ContainerFormatPng {1b7cfaf4-713f-473c-bbcd-6137425faeaf}
const GUID_CONTAINER_FORMAT_PNG: [u8; 16] = [
    0xf4, 0xaf, 0x7c, 0x1b, 0x3f, 0x71, 0x3c, 0x47, 0xbb, 0xcd, 0x61, 0x37, 0x42, 0x5f, 0xae, 0xaf,
];
/// GUID_ContainerFormatJpeg {19e4a5aa-5662-4fc5-a0c0-1758028e1057}
const GUID_CONTAINER_FORMAT_JPEG: [u8; 16] = [
    0xaa, 0xa5, 0xe4, 0x19, 0x62, 0x56, 0xc5, 0x4f, 0xa0, 0xc0, 0x17, 0x58, 0x02, 0x8e, 0x10, 0x57,
];

const WIC_COLOR_CONTEXT_UNINITIALIZED: u32 = 0;
const WIC_COMPONENT_DECODER: u32 = 1;
const WIC_TRANSFORM_ROTATE_90: u32 = 1;
const WIC_TRANSFORM_ROTATE_180: u32 = 2;
const WIC_TRANSFORM_ROTATE_270: u32 = 3;
const WIC_TRANSFORM_FLIP_HORIZONTAL: u32 = 4;
const WIC_TRANSFORM_FLIP_VERTICAL: u32 = 8;

// The WICBitmapPaletteType values the predefined-palette initializer
// supports (the fixed grayscale and black/white tables).
const WIC_PALETTE_TYPE_CUSTOM: u32 = 0;
const WIC_PALETTE_TYPE_OPTIMAL: u32 = 1;
const WIC_PALETTE_TYPE_FIXED_BW: u32 = 2;
const WIC_PALETTE_TYPE_FIXED_GRAY4: u32 = 11;
const WIC_PALETTE_TYPE_FIXED_GRAY16: u32 = 12;
const WIC_PALETTE_TYPE_FIXED_GRAY256: u32 = 13;
/// The maximum WIC palette size in colors.
const WIC_PALETTE_MAX_COLORS: u32 = 256;

/// The default bitmap resolution the runtime reports when none was set.
const WIC_DEFAULT_DPI: f64 = 96.0;

const WIC_GUID_FORMAT_EXIF: [u8; 16] = [
    0x7e, 0xd9, 0x4a, 0x1c, 0x73, 0x2b, 0x3a, 0x4b, 0x92, 0x38, 0x02, 0x65, 0xd4, 0x43, 0xa6, 0x5c,
];
const WIC_GUID_FORMAT_TIFF: [u8; 16] = [
    0xd0, 0x3e, 0x3d, 0x16, 0x3c, 0x55, 0x4e, 0x4b, 0x88, 0x50, 0x29, 0xa4, 0x87, 0xa5, 0x8c, 0x1d,
];
const WIC_GUID_FORMAT_IPTC: [u8; 16] = [
    0xf1, 0xe0, 0x09, 0x4b, 0x1a, 0x0a, 0x4c, 0x48, 0xa9, 0x66, 0x10, 0x66, 0x39, 0x3d, 0x12, 0x30,
];
const WIC_GUID_FORMAT_XMP: [u8; 16] = [
    0x75, 0xc3, 0x5c, 0xbb, 0x53, 0x92, 0x42, 0x44, 0x9f, 0xb2, 0x21, 0x64, 0x5b, 0x5c, 0x9a, 0x9f,
];

/// The bytes-per-pixel + channel layout for the supported pixel formats.
#[derive(Debug, Clone, Copy)]
enum PixelLayout {
    Bgra,
    Pbgra,
    Rgba,
    Bgr,
    Gray,
}

fn pixel_layout(guid: &[u8; 16]) -> Option<PixelLayout> {
    if guid == &GUID_PIXEL_FORMAT_32BPP_BGRA {
        Some(PixelLayout::Bgra)
    } else if guid == &GUID_PIXEL_FORMAT_32BPP_PBGRA {
        Some(PixelLayout::Pbgra)
    } else if guid == &GUID_PIXEL_FORMAT_32BPP_RGBA {
        Some(PixelLayout::Rgba)
    } else if guid == &GUID_PIXEL_FORMAT_24BPP_BGR {
        Some(PixelLayout::Bgr)
    } else if guid == &GUID_PIXEL_FORMAT_8BPP_GRAY {
        Some(PixelLayout::Gray)
    } else {
        None
    }
}

fn layout_bytes(layout: PixelLayout) -> u32 {
    match layout {
        PixelLayout::Gray => 1,
        PixelLayout::Bgr => 3,
        _ => 4,
    }
}

impl PeHostRuntime {
    /// Route every WIC thunk to its dispatch function.
    pub(crate) fn dispatch_wic(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::WicCreateImagingFactory => {
                self.dispatch_wic_create_imaging_factory(state, memory)
            }
            HostThunk::WicCreateImagingFactoryProxy => {
                self.dispatch_wic_create_imaging_factory(state, memory)
            }
            HostThunk::WicCreateBitmapProxy => self.dispatch_wic_create_bitmap(state, memory),
            HostThunk::WicCreateBitmapScalerProxy => self.dispatch_wic_create_scaler(state, memory),
            HostThunk::WicCreateBitmapClipperProxy => {
                self.dispatch_wic_create_clipper(state, memory)
            }
            HostThunk::WicCreateBitmapFlipRotatorProxy => {
                self.dispatch_wic_create_flip_rotator(state, memory)
            }
            HostThunk::WicCreateFormatConverterProxy => {
                self.dispatch_wic_create_format_converter(state, memory)
            }
            HostThunk::WicCreatePaletteProxy => self.dispatch_wic_create_palette(state, memory),
            HostThunk::WicCreateStreamProxy => self.dispatch_wic_create_stream(state, memory),
            HostThunk::WicCreateColorContextProxy => {
                self.dispatch_wic_create_color_context(state, memory)
            }
            HostThunk::WicCreateBitmapFromSectionProxy => {
                // Section-backed bitmaps need a DIB section; none exist in
                // the runtime — the documented unsupported answer.
                let _section = guest_call_arg(state, memory, 0)?;
                let _stride = guest_call_arg_u32(state, memory, 1)?;
                let _size = guest_call_arg_u32(state, memory, 2)?;
                let _format = guest_call_arg(state, memory, 3)?;
                let _options = guest_call_arg_u32(state, memory, 4)?;
                let out = guest_call_arg(state, memory, 5)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(WIC_E_NOTSUPPORTED));
                Ok(())
            }
            HostThunk::WicCreateComponentInfo => {
                self.dispatch_wic_create_component_info(state, memory)
            }
            HostThunk::WicGetMetadataContentSize => {
                self.dispatch_wic_get_metadata_content_size(state, memory)
            }
            HostThunk::WicMapSchemaToName => self.dispatch_wic_map_schema_to_name(state, memory),
            HostThunk::WicMatchMetadataContent => {
                self.dispatch_wic_match_metadata_content(state, memory)
            }
            HostThunk::WicSerializeMetadataContent => {
                self.dispatch_wic_serialize_metadata_content(state, memory)
            }
            HostThunk::WicFactoryCreateDecoderFromFilename => {
                self.wic_factory_create_decoder_from_filename(state, memory)
            }
            HostThunk::WicFactoryCreateDecoderFromStream => {
                self.wic_factory_create_decoder_from_stream(state, memory)
            }
            HostThunk::WicFactoryCreateDecoderFromFileHandle => {
                self.wic_factory_respond(state, memory, 4, WIC_E_CODECNOTFOUND)
            }
            HostThunk::WicFactoryCreateComponentInfo => {
                self.wic_factory_create_component_info(state, memory)
            }
            HostThunk::WicFactoryCreateDecoder => {
                self.wic_factory_respond(state, memory, 2, WIC_E_CODECNOTFOUND)
            }
            HostThunk::WicFactoryCreateEncoder => self.wic_factory_create_encoder(state, memory),
            HostThunk::WicFactoryCreatePalette => self.wic_factory_create_palette(state, memory),
            HostThunk::WicFactoryCreateFormatConverter => {
                self.wic_factory_create_format_converter(state, memory)
            }
            HostThunk::WicFactoryCreateBitmapScaler => {
                self.wic_factory_create_scaler(state, memory)
            }
            HostThunk::WicFactoryCreateBitmapClipper => {
                self.wic_factory_create_clipper(state, memory)
            }
            HostThunk::WicFactoryCreateBitmapFlipRotator => {
                self.wic_factory_create_flip_rotator(state, memory)
            }
            HostThunk::WicFactoryCreateStream => self.wic_factory_create_stream(state, memory),
            HostThunk::WicFactoryCreateColorContext => {
                self.wic_factory_create_color_context(state, memory)
            }
            HostThunk::WicFactoryCreateColorTransformer => {
                self.wic_factory_respond(state, memory, 0, WIC_E_NOTSUPPORTED)
            }
            HostThunk::WicFactoryCreateBitmap => {
                self.wic_factory_create_bitmap(state, memory, false)
            }
            HostThunk::WicFactoryCreateBitmapFromSource => {
                self.wic_factory_create_bitmap_from_source(state, memory, false)
            }
            HostThunk::WicFactoryCreateBitmapFromSourceRect => {
                self.wic_factory_create_bitmap_from_source(state, memory, true)
            }
            HostThunk::WicFactoryCreateBitmapFromMemory => {
                self.wic_factory_create_bitmap(state, memory, true)
            }
            HostThunk::WicFactoryCreateBitmapFromHbitmap => {
                self.wic_factory_respond(state, memory, 3, WIC_E_NOTSUPPORTED)
            }
            HostThunk::WicFactoryCreateBitmapFromHicon => {
                self.wic_factory_respond(state, memory, 1, WIC_E_NOTSUPPORTED)
            }
            HostThunk::WicFactoryCreateComponentEnumerator => {
                self.wic_factory_respond(state, memory, 2, WIC_E_NOTSUPPORTED)
            }
            HostThunk::WicFactoryCreateFastMetadataEncoderFromFrameDecode => {
                self.wic_factory_respond(state, memory, 1, WIC_E_CODECNOTHANDLED)
            }
            HostThunk::WicFactoryCreateFastMetadataEncoderFromQueryWriter => {
                self.wic_factory_respond(state, memory, 1, WIC_E_CODECNOTHANDLED)
            }
            HostThunk::WicFactoryCreateQueryWriter => {
                self.wic_factory_respond(state, memory, 2, WIC_E_CODECNOTHANDLED)
            }
            HostThunk::WicFactoryCreateQueryWriterFromReader => {
                self.wic_factory_respond(state, memory, 2, WIC_E_CODECNOTHANDLED)
            }
            HostThunk::WicSourceGetSize => self.wic_source_get_size(state, memory),
            HostThunk::WicSourceGetPixelFormat => self.wic_source_get_pixel_format(state, memory),
            HostThunk::WicSourceGetResolution => self.wic_source_get_resolution(state, memory),
            HostThunk::WicSourceCopyPalette => self.wic_source_copy_palette(state, memory),
            HostThunk::WicSourceCopyPixels => self.wic_source_copy_pixels(state, memory),
            HostThunk::WicBitmapLock => self.wic_bitmap_lock(state, memory),
            HostThunk::WicBitmapUnlock => self.wic_bitmap_unlock(state, memory),
            HostThunk::WicLockRelease => self.wic_lock_release(state, memory),
            HostThunk::WicBitmapLockGetSize => self.wic_bitmap_lock_get_size(state, memory),
            HostThunk::WicBitmapLockGetStride => self.wic_bitmap_lock_get_stride(state, memory),
            HostThunk::WicBitmapLockGetPixelFormat => {
                self.wic_bitmap_lock_get_pixel_format(state, memory)
            }
            HostThunk::WicBitmapLockGetDataPointer => {
                self.wic_bitmap_lock_get_data_pointer(state, memory)
            }
            HostThunk::WicBitmapSetPalette => self.wic_bitmap_set_palette(state, memory),
            HostThunk::WicBitmapSetResolution => self.wic_bitmap_set_resolution(state, memory),
            HostThunk::WicDecoderQueryCapability => {
                self.wic_decoder_query_capability(state, memory)
            }
            HostThunk::WicDecoderInitialize => self.wic_decoder_initialize(state, memory),
            HostThunk::WicDecoderGetContainerFormat => {
                self.wic_decoder_get_container_format(state, memory)
            }
            HostThunk::WicDecoderGetFrameCount => self.wic_decoder_get_frame_count(state, memory),
            HostThunk::WicDecoderGetFrame => self.wic_decoder_get_frame(state, memory),
            HostThunk::WicDecoderUnsupported => {
                state.set(Register::Rax, u64::from(WIC_E_CODECNOTHANDLED));
                Ok(())
            }
            HostThunk::WicEncoderInitialize => self.wic_encoder_initialize(state, memory),
            HostThunk::WicEncoderCreateNewFrame => self.wic_encoder_create_new_frame(state, memory),
            HostThunk::WicEncoderCommit => self.wic_encoder_commit(state, memory),
            HostThunk::WicEncoderGetContainerFormat => {
                self.wic_encoder_get_container_format(state, memory)
            }
            HostThunk::WicEncoderUnsupported => {
                state.set(Register::Rax, u64::from(WIC_E_NOTSUPPORTED));
                Ok(())
            }
            HostThunk::WicFrameEncodeInitialize => self.wic_frame_encode_initialize(state, memory),
            HostThunk::WicFrameEncodeSetSize => self.wic_frame_encode_set_size(state, memory),
            HostThunk::WicFrameEncodeSetResolution => {
                self.wic_frame_encode_set_resolution(state, memory)
            }
            HostThunk::WicFrameEncodeSetPixelFormat => {
                self.wic_frame_encode_set_pixel_format(state, memory)
            }
            HostThunk::WicFrameEncodeWritePixels => {
                self.wic_frame_encode_write_pixels(state, memory)
            }
            HostThunk::WicFrameEncodeWriteSource => {
                self.wic_frame_encode_write_source(state, memory)
            }
            HostThunk::WicFrameEncodeCommit => self.wic_frame_encode_commit(state, memory),
            HostThunk::WicFrameEncodeUnsupported => {
                state.set(Register::Rax, u64::from(WIC_E_NOTSUPPORTED));
                Ok(())
            }
            HostThunk::WicScalerInitialize => self.wic_scaler_initialize(state, memory),
            HostThunk::WicScalerGetScaledWidth | HostThunk::WicScalerGetScaledHeight => {
                self.wic_scaler_get_dimensions(state, memory)
            }
            HostThunk::WicScalerGetInterpolationMode => {
                self.wic_scaler_get_interpolation(state, memory)
            }
            HostThunk::WicScalerSetInterpolationMode => {
                self.wic_scaler_set_interpolation_mode(state, memory)
            }
            HostThunk::WicClipperInitialize => self.wic_clipper_initialize(state, memory),
            HostThunk::WicClipperGetClipRect => self.wic_clipper_get_clip_rect(state, memory),
            HostThunk::WicClipperSetClipRect => self.wic_clipper_set_clip_rect(state, memory),
            HostThunk::WicFlipRotatorInitialize => self.wic_flip_rotator_initialize(state, memory),
            HostThunk::WicFlipRotatorGetTransform => self.wic_flip_get_transform(state, memory),
            HostThunk::WicFormatConverterInitialize => {
                self.wic_format_converter_initialize(state, memory)
            }
            HostThunk::WicFormatConverterCanConvert => {
                self.wic_converter_can_convert(state, memory)
            }
            HostThunk::WicFormatConverterGetPixelFormat => {
                self.wic_converter_get_pixel_format(state, memory)
            }
            HostThunk::WicFormatConverterSetPixelFormat => {
                self.wic_converter_set_pixel_format(state, memory)
            }
            HostThunk::WicPaletteInitializeCustom => {
                self.wic_palette_initialize_custom(state, memory)
            }
            HostThunk::WicPaletteInitializePredefined => {
                self.wic_palette_initialize_predefined(state, memory)
            }
            HostThunk::WicPaletteInitializeFromBitmap => {
                self.wic_palette_initialize_from_bitmap(state, memory)
            }
            HostThunk::WicPaletteInitializeFromPalette => {
                self.wic_palette_initialize_from_palette(state, memory)
            }
            HostThunk::WicPaletteGetType => self.wic_palette_get_type(state, memory),
            HostThunk::WicPaletteGetColorCount => self.wic_palette_get_color_count(state, memory),
            HostThunk::WicPaletteGetColors => self.wic_palette_get_colors(state, memory),
            HostThunk::WicPaletteIsBlackWhite => self.wic_palette_flag(state, memory, 0),
            HostThunk::WicPaletteIsGrayscale => self.wic_palette_flag(state, memory, 1),
            HostThunk::WicPaletteHasAlpha => self.wic_palette_flag(state, memory, 2),
            HostThunk::WicStreamInitializeFromIStream => {
                self.wic_stream_initialize_from_i_stream(state, memory)
            }
            HostThunk::WicStreamInitializeFromFilename => {
                self.wic_stream_initialize_from_filename(state, memory)
            }
            HostThunk::WicStreamInitializeFromMemory => {
                self.wic_stream_initialize_from_memory(state, memory)
            }
            HostThunk::WicStreamInitializeFromIStreamRegion => {
                self.wic_stream_initialize_from_i_stream_region(state, memory)
            }
            HostThunk::WicColorContextInitializeFromFilename => {
                self.wic_color_context_initialize_from_filename(state, memory)
            }
            HostThunk::WicColorContextInitializeFromMemory => {
                self.wic_color_context_initialize_from_memory(state, memory)
            }
            HostThunk::WicColorContextGetProfileBytes => {
                self.wic_color_context_get_profile_bytes(state, memory)
            }
            HostThunk::WicColorContextGetType => self.wic_color_context_get_type(state, memory),
            HostThunk::WicColorContextGetExifColorSpace => {
                self.wic_color_context_get_exif_color_space(state, memory)
            }
            HostThunk::WicColorContextSetExifColorSpace => {
                self.wic_color_context_set_exif_color_space(state, memory)
            }
            HostThunk::WicComponentInfoGetComponentType => {
                self.wic_component_info_get_component_type(state, memory)
            }
            HostThunk::WicComponentInfoGetClsid | HostThunk::WicComponentInfoGetVendorGuid => {
                self.wic_component_info_write_zero_guid(state, memory)
            }
            HostThunk::WicComponentInfoGetSigningStatus => {
                self.wic_component_info_get_signing_status(state, memory)
            }
            HostThunk::WicComponentInfoGetAuthor
            | HostThunk::WicComponentInfoGetVersion
            | HostThunk::WicComponentInfoGetSpecVersion => {
                self.wic_component_info_write_empty_string(state, memory)
            }
            HostThunk::WicComponentInfoGetFriendlyName => {
                self.wic_component_info_get_friendly_name(state, memory)
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted WIC thunk {thunk:?}"),
            )),
        }
    }

    // ── Object creation helpers ────────────────────────────────────────────

    fn wic_alloc_object(
        &mut self,
        memory: &mut MemoryImage,
        kind: WicObjectKind,
        methods: Vec<HostThunk>,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let guest_kind = match kind {
            WicObjectKind::Factory => GuestObjectKind::WicFactory,
            WicObjectKind::Bitmap => GuestObjectKind::WicBitmap,
            WicObjectKind::Palette => GuestObjectKind::WicPalette,
            WicObjectKind::Scaler => GuestObjectKind::WicScaler,
            WicObjectKind::Clipper => GuestObjectKind::WicClipper,
            WicObjectKind::FlipRotator => GuestObjectKind::WicFlipRotator,
            WicObjectKind::FormatConverter => GuestObjectKind::WicFormatConverter,
            WicObjectKind::Stream => GuestObjectKind::WicStream,
            WicObjectKind::ColorContext => GuestObjectKind::WicColorContext,
            WicObjectKind::ComponentInfo => GuestObjectKind::WicComponentInfo,
        };
        let object = self
            .alloc_guest_object(memory, guest_kind, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        let mut state = WicObjectState {
            kind,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            ..Default::default()
        };
        if kind == WicObjectKind::Factory {
            state.pixel_format = GUID_PIXEL_FORMAT_DONT_CARE;
        }
        self.wic.objects.insert(object, state);
        Ok(object)
    }

    fn wic_write_out(&self, memory: &mut MemoryImage, out: u64, object: u64) {
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
    }

    // ── The module exports ─────────────────────────────────────────────────

    /// `WICCreateImagingFactory(dwFlags, ppIFactory)` — the imaging factory
    /// object.
    pub(crate) fn dispatch_wic_create_imaging_factory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _flags = guest_call_arg_u32(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object =
            self.wic_alloc_object(memory, WicObjectKind::Factory, wic_factory_methods())?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `WICCreateBitmap_Proxy(width, height, pixelFormat, options,
    /// ppIBitmap)` — a software bitmap.
    pub(crate) fn dispatch_wic_create_bitmap(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let width = guest_call_arg_u32(state, memory, 0)?;
        let height = guest_call_arg_u32(state, memory, 1)?;
        let format = guest_call_arg(state, memory, 2)?;
        let _options = guest_call_arg_u32(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        if width == 0 || height == 0 || width > 1_000_000 || height > 1_000_000 || out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let format = read_guid(memory, format);
        let Some(layout) = pixel_layout(&format) else {
            state.set(Register::Rax, u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT));
            return Ok(());
        };
        let object = self.wic_alloc_object(memory, WicObjectKind::Bitmap, wic_bitmap_methods())?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(bitmap) = self.wic.objects.get_mut(&object) {
            bitmap.width = width;
            bitmap.height = height;
            bitmap.pixel_format = format;
            bitmap.pixels = vec![0; (width * height * layout_bytes(layout)) as usize];
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_create_transformed(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        kind: WicObjectKind,
        methods: Vec<HostThunk>,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(memory, kind, methods)?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    pub(crate) fn dispatch_wic_create_scaler(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_create_transformed(state, memory, WicObjectKind::Scaler, wic_scaler_methods())
    }

    pub(crate) fn dispatch_wic_create_clipper(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_create_transformed(state, memory, WicObjectKind::Clipper, wic_clipper_methods())
    }

    pub(crate) fn dispatch_wic_create_flip_rotator(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_create_transformed(
            state,
            memory,
            WicObjectKind::FlipRotator,
            wic_flip_rotator_methods(),
        )
    }

    pub(crate) fn dispatch_wic_create_format_converter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_create_transformed(
            state,
            memory,
            WicObjectKind::FormatConverter,
            wic_format_converter_methods(),
        )
    }

    pub(crate) fn dispatch_wic_create_palette(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_create_transformed(state, memory, WicObjectKind::Palette, wic_palette_methods())
    }

    pub(crate) fn dispatch_wic_create_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_create_transformed(state, memory, WicObjectKind::Stream, wic_stream_methods())
    }

    pub(crate) fn dispatch_wic_create_color_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_create_transformed(
            state,
            memory,
            WicObjectKind::ColorContext,
            wic_color_context_methods(),
        )
    }

    /// `WICCreateComponentInfo(clsid, ppIInfo)` — component info for the
    /// requested component class.
    pub(crate) fn dispatch_wic_create_component_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let clsid = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let _ = memory.read_bytes(clsid, 16).unwrap_or_default();
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(
            memory,
            WicObjectKind::ComponentInfo,
            wic_component_info_methods(),
        )?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(info) = self.wic.objects.get_mut(&object) {
            info.component_type = WIC_COMPONENT_DECODER;
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── The metadata helper exports ────────────────────────────────────────

    /// `WICGetMetadataContentSize(guidFormatType, pIUnknown, pcbSize)` —
    /// no metadata handlers are registered.
    pub(crate) fn dispatch_wic_get_metadata_content_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _format = guest_call_arg(state, memory, 0)?;
        let _unknown = guest_call_arg(state, memory, 1)?;
        let size_out = guest_call_arg(state, memory, 2)?;
        if size_out != 0 {
            write_guest_u32(memory, size_out, 0).ok();
        }
        state.set(Register::Rax, u64::from(WIC_E_CODECNOTHANDLED));
        Ok(())
    }

    /// `WICMapSchemaToName(guidMetadataFormat, pwzSchema, cchSchema,
    /// pwzName, pcchActual)` — the schema-name mapping for the well-known
    /// metadata formats.
    pub(crate) fn dispatch_wic_map_schema_to_name(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let format = guest_call_arg(state, memory, 0)?;
        let schema = guest_call_arg(state, memory, 1)?;
        let _capacity = guest_call_arg_u32(state, memory, 2)?;
        let name_out = guest_call_arg(state, memory, 3)?;
        let actual_out = guest_call_arg(state, memory, 4)?;
        let format_guid = read_guid(memory, format);
        let schema_text = read_utf16_string(memory, schema).unwrap_or_default();
        let known = matches!(
            &format_guid,
            &WIC_GUID_FORMAT_EXIF
                | &WIC_GUID_FORMAT_TIFF
                | &WIC_GUID_FORMAT_IPTC
                | &WIC_GUID_FORMAT_XMP
        );
        if !known {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let mapped = match schema_text.as_str() {
            "IFD" => "IFD",
            "Exif" => "Exif",
            "GPS" => "GPS",
            "Interop" => "Interop",
            "IPTC" => "IPTC",
            "XMP" => "XMP",
            "TIFF" => "TIFF",
            _ => {
                if actual_out != 0 {
                    write_guest_u32(memory, actual_out, 0).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                return Ok(());
            }
        };
        write_utf16_string(memory, name_out, mapped, 64);
        if actual_out != 0 {
            write_guest_u32(memory, actual_out, mapped.encode_utf16().count() as u32).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `WICMatchMetadataContent(guidContainerFormat, pguidVendor, pIUnknown,
    /// ppguidMetadataFormat)` — no metadata handlers are registered.
    pub(crate) fn dispatch_wic_match_metadata_content(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _container = guest_call_arg(state, memory, 0)?;
        let _vendor = guest_call_arg(state, memory, 1)?;
        let _unknown = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(WIC_E_CODECNOTHANDLED));
        Ok(())
    }

    /// `WICSerializeMetadataContent(guidContainerFormat,
    /// guidMetadataFormat, pIUnknown, dwFlags, pIStream)` — no metadata
    /// handlers are registered.
    pub(crate) fn dispatch_wic_serialize_metadata_content(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _container = guest_call_arg(state, memory, 0)?;
        let _format = guest_call_arg(state, memory, 1)?;
        let _unknown = guest_call_arg(state, memory, 2)?;
        let _flags = guest_call_arg_u32(state, memory, 3)?;
        let _stream = guest_call_arg(state, memory, 4)?;
        state.set(Register::Rax, u64::from(WIC_E_CODECNOTHANDLED));
        Ok(())
    }

    // ── IWICImagingFactory methods ─────────────────────────────────────────

    fn wic_factory_create_palette(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object =
            self.wic_alloc_object(memory, WicObjectKind::Palette, wic_palette_methods())?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_scaler(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(memory, WicObjectKind::Scaler, wic_scaler_methods())?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_clipper(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object =
            self.wic_alloc_object(memory, WicObjectKind::Clipper, wic_clipper_methods())?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_flip_rotator(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(
            memory,
            WicObjectKind::FlipRotator,
            wic_flip_rotator_methods(),
        )?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_format_converter(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(
            memory,
            WicObjectKind::FormatConverter,
            wic_format_converter_methods(),
        )?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(memory, WicObjectKind::Stream, wic_stream_methods())?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_color_context(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(
            memory,
            WicObjectKind::ColorContext,
            wic_color_context_methods(),
        )?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_component_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _clsid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(
            memory,
            WicObjectKind::ComponentInfo,
            wic_component_info_methods(),
        )?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(info) = self.wic.objects.get_mut(&object) {
            info.component_type = WIC_COMPONENT_DECODER;
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_bitmap(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        from_memory: bool,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let mut arg = 1;
        let width = guest_call_arg_u32(state, memory, arg)?;
        arg += 1;
        let height = guest_call_arg_u32(state, memory, arg)?;
        arg += 1;
        let format = guest_call_arg(state, memory, arg)?;
        arg += 1;
        let mut pixels = Vec::new();
        let mut stride = 0_u32;
        if from_memory {
            stride = guest_call_arg_u32(state, memory, arg)?;
            arg += 1;
            let size = guest_call_arg_u32(state, memory, arg)?;
            arg += 1;
            let data = guest_call_arg(state, memory, arg)?;
            arg += 1;
            pixels = memory.read_bytes(data, size as usize).unwrap_or_default();
        }
        let _options = guest_call_arg_u32(state, memory, arg)?;
        let out = guest_call_arg(state, memory, arg + 1)?;
        if width == 0 || height == 0 || width > 1_000_000 || height > 1_000_000 || out == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let format = read_guid(memory, format);
        let Some(layout) = pixel_layout(&format) else {
            state.set(Register::Rax, u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT));
            return Ok(());
        };
        let object = self.wic_alloc_object(memory, WicObjectKind::Bitmap, wic_bitmap_methods())?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(bitmap) = self.wic.objects.get_mut(&object) {
            bitmap.width = width;
            bitmap.height = height;
            bitmap.pixel_format = format;
            let expected = width * height * layout_bytes(layout);
            if pixels.len() >= expected as usize {
                bitmap.pixels = pixels[..expected as usize].to_vec();
            } else {
                bitmap.pixels = vec![0; expected as usize];
            }
            let _ = stride;
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_factory_create_bitmap_from_source(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        with_rect: bool,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let mut arg = 1;
        let source = guest_call_arg(state, memory, arg)?;
        arg += 1;
        let mut rect = None;
        if with_rect {
            let rect_ptr = guest_call_arg(state, memory, arg)?;
            arg += 1;
            let data = memory.read_bytes(rect_ptr, 16).unwrap_or_default();
            if data.len() == 16 {
                rect = Some([
                    i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
                    i32::from_le_bytes([data[4], data[5], data[6], data[7]]),
                    i32::from_le_bytes([data[8], data[9], data[10], data[11]]),
                    i32::from_le_bytes([data[12], data[13], data[14], data[15]]),
                ]);
            }
        }
        let _cache = guest_call_arg_u32(state, memory, arg)?;
        let out = guest_call_arg(state, memory, arg + 1)?;
        let Some(source_state) = self.wic.objects.get(&source).cloned() else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        let (sx, sy, sw, sh) = match rect {
            Some([x, y, w, h]) => (
                x.max(0) as u32,
                y.max(0) as u32,
                w.max(0) as u32,
                h.max(0) as u32,
            ),
            None => (0, 0, source_state.width, source_state.height),
        };
        if out == 0 || sw == 0 || sh == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let object = self.wic_alloc_object(memory, WicObjectKind::Bitmap, wic_bitmap_methods())?;
        if object == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        let pixels = wic_copy_source_pixels(&self.wic.objects, &source_state, sx, sy, sw, sh);
        if let Some(bitmap) = self.wic.objects.get_mut(&object) {
            bitmap.width = sw;
            bitmap.height = sh;
            bitmap.pixel_format = source_state.pixel_format;
            bitmap.pixels = pixels;
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// Answer a factory method with a null output and a documented WIC
    /// error (no codecs / no metadata handlers / unsupported feature).
    fn wic_factory_respond(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        out_index: usize,
        code: u32,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        if let Ok(out) = guest_call_arg(state, memory, out_index)
            && out != 0
        {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(code));
        Ok(())
    }

    fn wic_read_guest_stream(&self, stream: u64) -> Option<Vec<u8>> {
        if let Some(object) = self.wic.objects.get(&stream) {
            if object.kind == WicObjectKind::Stream {
                return Some(object.stream.clone());
            }
            return None;
        }
        self.com_streams
            .get(&stream)
            .map(|stream| stream.data.clone())
    }

    fn wic_alloc_decoder_object(
        &mut self,
        memory: &mut MemoryImage,
        bytes: &[u8],
    ) -> AppResult<std::result::Result<u64, u32>> {
        let image = match wic_decode_image(bytes) {
            Ok(image) => image,
            Err(code) => return Ok(Err(code)),
        };
        let object = self.wic_alloc_object(memory, WicObjectKind::Stream, wic_decoder_methods())?;
        if object == 0 {
            return Ok(Err(0x8007_000e));
        }
        if let Some(decoder) = self.wic.objects.get_mut(&object) {
            decoder.stream = bytes.to_vec();
            decoder.pixels = image.pixels;
            decoder.width = image.width;
            decoder.height = image.height;
            decoder.pixel_format = image.container;
            decoder.component_type = image.codec;
            decoder.exif_color_space = 1;
            decoder.profile = WIC_DECODER_MAGIC.to_vec();
            decoder.palette = vec![
                (image.dpi_x as f32).to_bits(),
                (image.dpi_y as f32).to_bits(),
            ];
        }
        Ok(Ok(object))
    }

    /// `IWICImagingFactory::CreateDecoderFromFilename(filename, access,
    /// metadataOptions, ppIDecoder)`.
    fn wic_factory_create_decoder_from_filename(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let filename = guest_call_arg(state, memory, 1)?;
        let _access = guest_call_arg_u32(state, memory, 2)?;
        let _metadata = guest_call_arg_u32(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let path = read_utf16_string(memory, filename).unwrap_or_default();
        let Ok(bytes) = std::fs::read(&path) else {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(WIC_E_CODECNOTFOUND));
            return Ok(());
        };
        match self.wic_alloc_decoder_object(memory, &bytes)? {
            Ok(object) => {
                self.wic_write_out(memory, out, object);
                state.set(Register::Rax, u64::from(S_OK));
            }
            Err(code) => {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(code));
            }
        }
        Ok(())
    }

    /// `IWICImagingFactory::CreateDecoderFromStream(pIStream,
    /// metadataOptions, ppIDecoder)`.
    fn wic_factory_create_decoder_from_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg(state, memory, 1)?;
        let _metadata = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some(bytes) = self.wic_read_guest_stream(stream) else {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if bytes.is_empty() {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(WINCODEC_ERR_UNKNOWNIMAGEFORMAT));
            return Ok(());
        }
        match self.wic_alloc_decoder_object(memory, &bytes)? {
            Ok(object) => {
                self.wic_write_out(memory, out, object);
                state.set(Register::Rax, u64::from(S_OK));
            }
            Err(code) => {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(code));
            }
        }
        Ok(())
    }

    /// `IWICImagingFactory::CreateEncoder(guidContainerFormat,
    /// pIUnknown, ppIEncoder)` — only the PNG container has an encoder.
    fn wic_factory_create_encoder(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let container_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let container = read_guid(memory, container_ptr);
        if container != GUID_CONTAINER_FORMAT_PNG {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(WINCODEC_ERR_COMPONENTNOTFOUND));
            return Ok(());
        }
        let object = self.wic_alloc_object(memory, WicObjectKind::Stream, wic_encoder_methods())?;
        if object == 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(encoder) = self.wic.objects.get_mut(&object) {
            encoder.pixel_format = container;
            encoder.component_type = 1;
            encoder.exif_color_space = 0;
            encoder.transform = 0;
            encoder.profile = WIC_ENCODER_MAGIC.to_vec();
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── The bitmap source chain (shared by bitmap/scaler/clipper/...) ─────

    fn wic_source_get_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let width_out = guest_call_arg(state, memory, 1)?;
        let height_out = guest_call_arg(state, memory, 2)?;
        let (width, height) = self
            .wic
            .objects
            .get(&this)
            .map(wic_source_dimensions)
            .unwrap_or((0, 0));
        if width_out != 0 {
            write_guest_u32(memory, width_out, width).ok();
        }
        if height_out != 0 {
            write_guest_u32(memory, height_out, height).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_source_get_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let format_out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if format_out != 0 {
            write_guest_bytes(memory, format_out, &object.pixel_format);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_source_get_resolution(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let dpi_x = guest_call_arg(state, memory, 1)?;
        let dpi_y = guest_call_arg(state, memory, 2)?;
        let (x, y) = self
            .wic
            .objects
            .get(&this)
            .map(|object| wic_source_resolution(&self.wic.objects, object))
            .unwrap_or((WIC_DEFAULT_DPI, WIC_DEFAULT_DPI));
        if dpi_x != 0 {
            write_guest_f64(memory, dpi_x, x).ok();
        }
        if dpi_y != 0 {
            write_guest_f64(memory, dpi_y, y).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_source_copy_palette(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let palette = guest_call_arg(state, memory, 1)?;
        let Some(source) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        };
        let Some(target) = self.wic.objects.get(&palette) else {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        };
        if target.kind != WicObjectKind::Palette {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        // The source's palette (empty for the non-indexed software bitmaps;
        // set for the objects that carry one).
        let colors = source.palette.clone();
        let premultiplied = source.palette_premultiplied;
        if let Some(slot) = self.wic.objects.get_mut(&palette) {
            slot.palette = colors;
            slot.palette_premultiplied = premultiplied;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_source_copy_pixels(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let rect_ptr = guest_call_arg(state, memory, 1)?;
        let stride = guest_call_arg_u32(state, memory, 2)?;
        let buffer_size = guest_call_arg_u32(state, memory, 3)?;
        let buffer = guest_call_arg(state, memory, 4)?;
        let Some(source) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        let rect = if rect_ptr != 0 {
            let data = memory.read_bytes(rect_ptr, 16).unwrap_or_default();
            if data.len() == 16 {
                Some([
                    i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
                    i32::from_le_bytes([data[4], data[5], data[6], data[7]]),
                    i32::from_le_bytes([data[8], data[9], data[10], data[11]]),
                    i32::from_le_bytes([data[12], data[13], data[14], data[15]]),
                ])
            } else {
                None
            }
        } else {
            None
        };
        let (source_width, source_height) = wic_source_dimensions(&source);
        let (x, y, w, h) = match rect {
            Some([rx, ry, rw, rh]) => (
                rx.max(0) as u32,
                ry.max(0) as u32,
                rw.max(0) as u32,
                rh.max(0) as u32,
            ),
            None => (0, 0, source_width, source_height),
        };
        // The requested rectangle must be inside the source: WIC rejects an
        // out-of-bounds or empty rectangle rather than clipping it.
        if w == 0 || h == 0 || x >= source_width || y >= source_height {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if x.saturating_add(w) > source_width || y.saturating_add(h) > source_height {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let source_pixels = wic_copy_source_pixels(&self.wic.objects, &source, x, y, w, h);
        let layout = pixel_layout(&source.pixel_format);
        let bytes = layout.map(layout_bytes).unwrap_or(0);
        if bytes == 0
            || source_pixels.len() < (w as usize).saturating_mul(h as usize * bytes as usize)
        {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        if stride < w * bytes {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let needed = (h as u64).saturating_mul(stride as u64);
        if needed > buffer_size as u64 || buffer == 0 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        for row in 0..h as usize {
            let src_start = row * w as usize * bytes as usize;
            let dst_start = row as u64 * stride as u64;
            for col in 0..w as usize * bytes as usize {
                let value = source_pixels[src_start + col];
                memory.write_u8(buffer + dst_start + col as u64, value);
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IWICBitmap methods ─────────────────────────────────────────────────

    /// `IWICBitmap::Lock(prcLock, flags, ppILock)` — a real lock object over
    /// the bitmap's live pixels.  The locked rectangle is copied into a guest
    /// buffer the lock hands out; `Unlock` commits it back.
    fn wic_bitmap_lock(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let rect_ptr = guest_call_arg(state, memory, 1)?;
        let flags = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some(bitmap) = self.wic.objects.get(&this).cloned() else {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if bitmap.kind != WicObjectKind::Bitmap {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if flags & (WIC_BITMAP_LOCK_READ | WIC_BITMAP_LOCK_WRITE) == 0
            || flags & !(WIC_BITMAP_LOCK_READ | WIC_BITMAP_LOCK_WRITE) != 0
        {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        // A second lock (including a second write lock) while one lock is
        // outstanding is the documented access-denied answer.
        if bitmap.component_type != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(WINCODEC_ERR_ACCESSDENIED));
            return Ok(());
        }
        let Some(layout) = pixel_layout(&bitmap.pixel_format) else {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(
                Register::Rax,
                u64::from(WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT),
            );
            return Ok(());
        };
        let bytes = layout_bytes(layout);
        let (x, y, w, h) = match wic_read_rect(memory, rect_ptr) {
            Some([x, y, w, h]) => (x, y, w, h),
            None if rect_ptr == 0 => (0, 0, bitmap.width as i32, bitmap.height as i32),
            None => {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        };
        if w <= 0
            || h <= 0
            || x < 0
            || y < 0
            || x as u32 + w as u32 > bitmap.width
            || y as u32 + h as u32 > bitmap.height
        {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let stride = match (w as u32).checked_mul(bytes) {
            Some(stride) => stride,
            None => {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        };
        let size = match stride.checked_mul(h as u32) {
            Some(size) => size,
            None => {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        };
        if size > 256 * 1024 * 1024 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let object =
            self.wic_alloc_object(memory, WicObjectKind::Stream, wic_bitmap_lock_methods())?;
        if object == 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        let data_pointer = self.alloc_zeroed(memory, size as usize, 16)?;
        let row_bytes = w as usize * bytes as usize;
        let bitmap_stride = bitmap.width as usize * bytes as usize;
        for row in 0..h as usize {
            let source = (y as usize + row) * bitmap_stride + x as usize * bytes as usize;
            let destination = data_pointer + row as u64 * stride as u64;
            for col in 0..row_bytes {
                let value = bitmap.pixels.get(source + col).copied().unwrap_or(0);
                memory.write_u8(destination + col as u64, value);
            }
        }
        if let Some(lock) = self.wic.objects.get_mut(&object) {
            lock.kind = WicObjectKind::Stream;
            lock.source = this;
            lock.width = w as u32;
            lock.height = h as u32;
            lock.pixel_format = bitmap.pixel_format;
            lock.clip = Some([x, y, w, h]);
            lock.interpolation = flags;
            lock.component_type = 1;
            lock.profile = data_pointer.to_le_bytes().to_vec();
            lock.stream.clear();
        }
        if let Some(source) = self.wic.objects.get_mut(&this) {
            source.component_type = 1;
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// Validate that `object` is one of our live lock objects.
    fn wic_is_live_lock(&self, object: u64) -> Option<WicObjectState> {
        let lock = self.wic.objects.get(&object)?.clone();
        if lock.component_type != 1 || lock.profile.len() != 8 {
            return None;
        }
        Some(lock)
    }

    /// Commit a live lock's guest buffer back into its bitmap.  Returns false
    /// when the lock/bitmap pair is no longer valid.
    fn wic_commit_bitmap_lock(&mut self, memory: &MemoryImage, object: u64) -> bool {
        let Some(lock) = self.wic_is_live_lock(object) else {
            return false;
        };
        let Some([x, y, w, h]) = lock.clip else {
            return false;
        };
        let Some(bitmap) = self.wic.objects.get_mut(&lock.source) else {
            return false;
        };
        if bitmap.kind != WicObjectKind::Bitmap {
            return false;
        }
        let Some(layout) = pixel_layout(&bitmap.pixel_format) else {
            return false;
        };
        let bytes = layout_bytes(layout) as usize;
        let row_bytes = w as usize * bytes;
        let stride = row_bytes;
        let data_pointer = u64::from_le_bytes([
            lock.profile[0],
            lock.profile[1],
            lock.profile[2],
            lock.profile[3],
            lock.profile[4],
            lock.profile[5],
            lock.profile[6],
            lock.profile[7],
        ]);
        if lock.interpolation & WIC_BITMAP_LOCK_WRITE != 0 {
            let bitmap_stride = bitmap.width as usize * bytes;
            for row in 0..h as usize {
                let source = data_pointer + row as u64 * stride as u64;
                let destination = (y as usize + row) * bitmap_stride + x as usize * bytes;
                for col in 0..row_bytes {
                    let Ok(value) = memory.read_u8(source + col as u64) else {
                        return false;
                    };
                    if let Some(slot) = bitmap.pixels.get_mut(destination + col) {
                        *slot = value;
                    }
                }
            }
        }
        true
    }

    fn wic_invalidate_lock(&mut self, object: u64) {
        if let Some(lock) = self.wic.objects.get_mut(&object) {
            lock.component_type = 0;
            lock.profile.clear();
            lock.stream.clear();
            lock.clip = None;
        }
    }

    /// `IWICBitmap::Unlock(pILock)` — commit the lock and invalidate it.
    fn wic_bitmap_unlock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let lock = guest_call_arg(state, memory, 1)?;
        let Some(lock_state) = self.wic_is_live_lock(lock) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if lock_state.source != this {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if !self.wic_commit_bitmap_lock(memory, lock) {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if let Some(bitmap) = self.wic.objects.get_mut(&this) {
            bitmap.component_type = 0;
        }
        self.wic_invalidate_lock(lock);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IWICBitmapLock::Release`/`IWICBitmap::Unlock` fallback: commit and
    /// invalidate without requiring the caller to pass the bitmap again.
    fn wic_lock_release(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let lock = guest_call_arg(state, memory, 0)?;
        let Some(lock_state) = self.wic_is_live_lock(lock) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !self.wic_commit_bitmap_lock(memory, lock) {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if let Some(bitmap) = self.wic.objects.get_mut(&lock_state.source) {
            bitmap.component_type = 0;
        }
        self.wic_invalidate_lock(lock);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_bitmap_lock_get_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let width_out = guest_call_arg(state, memory, 1)?;
        let height_out = guest_call_arg(state, memory, 2)?;
        let Some(lock) = self.wic_is_live_lock(this) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if width_out != 0 {
            write_guest_u32(memory, width_out, lock.width).ok();
        }
        if height_out != 0 {
            write_guest_u32(memory, height_out, lock.height).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_bitmap_lock_get_stride(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(lock) = self.wic_is_live_lock(this) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        let Some(layout) = pixel_layout(&lock.pixel_format) else {
            state.set(
                Register::Rax,
                u64::from(WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT),
            );
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, lock.width * layout_bytes(layout)).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_bitmap_lock_get_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(lock) = self.wic_is_live_lock(this) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if out != 0 {
            write_guest_bytes(memory, out, &lock.pixel_format);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_bitmap_lock_get_data_pointer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(lock) = self.wic_is_live_lock(this) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        let pointer = u64::from_le_bytes([
            lock.profile[0],
            lock.profile[1],
            lock.profile[2],
            lock.profile[3],
            lock.profile[4],
            lock.profile[5],
            lock.profile[6],
            lock.profile[7],
        ]);
        if out != 0 {
            write_guest_pointer(memory, out, pointer, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_bitmap_set_palette(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let palette = guest_call_arg(state, memory, 1)?;
        let Some(bitmap) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if bitmap.kind != WicObjectKind::Bitmap {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        let Some(target) = self.wic.objects.get(&palette) else {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        };
        if target.kind != WicObjectKind::Palette {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        // A palette can only be set on an indexed bitmap; every pixel format
        // the runtime creates is non-indexed, so the documented answer is the
        // unsupported-pixel-format error rather than a silent accept.
        state.set(Register::Rax, u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT));
        Ok(())
    }

    fn wic_bitmap_set_resolution(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let dpi_x = guest_call_arg_f64(state, memory, 1)?;
        let dpi_y = guest_call_arg_f64(state, memory, 2)?;
        if !dpi_x.is_finite() || !dpi_y.is_finite() || dpi_x <= 0.0 || dpi_y <= 0.0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some(bitmap) = self.wic.objects.get_mut(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if bitmap.kind != WicObjectKind::Bitmap {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        bitmap.profile = wic_encode_dpi(dpi_x, dpi_y);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IWICBitmapDecoder / IWICBitmapFrameDecode ─────────────────────────

    fn wic_decoder_query_capability(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let container_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(decoder) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !decoder.profile.starts_with(WIC_DECODER_MAGIC) {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        let container = read_guid(memory, container_ptr);
        if container != decoder.pixel_format {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_COMPONENTNOTFOUND));
            return Ok(());
        }
        if out != 0 {
            write_guest_u32(memory, out, 1).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_decoder_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg(state, memory, 1)?;
        let _cache = guest_call_arg_u32(state, memory, 2)?;
        let is_decoder = self
            .wic
            .objects
            .get(&this)
            .is_some_and(|object| object.profile.starts_with(WIC_DECODER_MAGIC));
        if !is_decoder {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        let Some(bytes) = self.wic_read_guest_stream(stream) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let image = match wic_decode_image(&bytes) {
            Ok(image) => image,
            Err(code) => {
                state.set(Register::Rax, u64::from(code));
                return Ok(());
            }
        };
        if let Some(decoder) = self.wic.objects.get_mut(&this) {
            decoder.stream = bytes;
            decoder.pixels = image.pixels;
            decoder.width = image.width;
            decoder.height = image.height;
            decoder.pixel_format = image.container;
            decoder.component_type = image.codec;
            decoder.exif_color_space = 1;
            decoder.palette = vec![
                (image.dpi_x as f32).to_bits(),
                (image.dpi_y as f32).to_bits(),
            ];
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_decoder_get_container_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(decoder) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !decoder.profile.starts_with(WIC_DECODER_MAGIC) || decoder.exif_color_space == 0 {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if out != 0 {
            write_guest_bytes(memory, out, &decoder.pixel_format);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_decoder_get_frame_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(decoder) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !decoder.profile.starts_with(WIC_DECODER_MAGIC) || decoder.exif_color_space == 0 {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if out != 0 {
            write_guest_u32(memory, out, 1).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_decoder_get_frame(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(decoder) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !decoder.profile.starts_with(WIC_DECODER_MAGIC) || decoder.exif_color_space == 0 {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if index != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(WINCODEC_ERR_FRAMEMISSING));
            return Ok(());
        }
        let frame =
            self.wic_alloc_object(memory, WicObjectKind::Bitmap, wic_frame_decode_methods())?;
        if frame == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        let dpi_x = decoder
            .palette
            .first()
            .map(|bits| f32::from_bits(*bits) as f64)
            .unwrap_or(WIC_DEFAULT_DPI);
        let dpi_y = decoder
            .palette
            .get(1)
            .map(|bits| f32::from_bits(*bits) as f64)
            .unwrap_or(WIC_DEFAULT_DPI);
        if let Some(frame_state) = self.wic.objects.get_mut(&frame) {
            frame_state.width = decoder.width;
            frame_state.height = decoder.height;
            frame_state.pixel_format = GUID_PIXEL_FORMAT_32BPP_BGRA;
            frame_state.pixels = decoder.pixels.clone();
            frame_state.profile = wic_encode_dpi(dpi_x, dpi_y);
        }
        self.wic_write_out(memory, out, frame);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IWICBitmapEncoder / IWICBitmapFrameEncode ─────────────────────────

    fn wic_encoder_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg(state, memory, 1)?;
        let _cache = guest_call_arg_u32(state, memory, 2)?;
        let is_encoder = self
            .wic
            .objects
            .get(&this)
            .is_some_and(|object| object.profile.starts_with(WIC_ENCODER_MAGIC));
        if !is_encoder {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if self.wic_read_guest_stream(stream).is_none() {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if let Some(encoder) = self.wic.objects.get_mut(&this) {
            encoder.source = stream;
            encoder.stream.clear();
            encoder.exif_color_space = 1;
            encoder.transform = 0;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_encoder_create_new_frame(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let _options = guest_call_arg(state, memory, 2)?;
        let is_initialized = self.wic.objects.get(&this).is_some_and(|object| {
            object.profile.starts_with(WIC_ENCODER_MAGIC) && object.exif_color_space == 1
        });
        if !is_initialized {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let frame =
            self.wic_alloc_object(memory, WicObjectKind::Bitmap, wic_frame_encode_methods())?;
        if frame == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(frame_state) = self.wic.objects.get_mut(&frame) {
            frame_state.source = this;
            frame_state.pixel_format = GUID_PIXEL_FORMAT_32BPP_BGRA;
            frame_state.component_type = WIC_FRAME_ENCODE_MAGIC;
            frame_state.interpolation = 0;
            frame_state.transform = 0;
            frame_state.width = 0;
            frame_state.height = 0;
            frame_state.profile.clear();
        }
        self.wic_write_out(memory, out, frame);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_encoder_commit(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(encoder) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !encoder.profile.starts_with(WIC_ENCODER_MAGIC)
            || encoder.exif_color_space != 1
            || encoder.transform & 2 == 0
        {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        let bytes = encoder.stream.clone();
        let mut written = false;
        if let Some(target) = self.wic.objects.get_mut(&encoder.source) {
            if target.kind == WicObjectKind::Stream {
                target.stream = bytes.clone();
                written = true;
            }
        }
        if !written {
            if let Some(target) = self.com_streams.get_mut(&encoder.source) {
                target.data = bytes;
                target.position = 0;
                target.dirty = true;
                written = true;
            }
        }
        if !written {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_STREAMNOTAVAILABLE));
            return Ok(());
        }
        if let Some(encoder) = self.wic.objects.get_mut(&this) {
            encoder.exif_color_space = 2;
            encoder.transform |= 4;
        }
        let _ = memory;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_encoder_get_container_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(encoder) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !encoder.profile.starts_with(WIC_ENCODER_MAGIC) {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if out != 0 {
            write_guest_bytes(memory, out, &encoder.pixel_format);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_is_encode_frame(&self, object: &WicObjectState) -> bool {
        object.component_type == WIC_FRAME_ENCODE_MAGIC
            && object.kind == WicObjectKind::Bitmap
            && self.wic.objects.contains_key(&object.source)
    }

    fn wic_frame_encode_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _options = guest_call_arg(state, memory, 1)?;
        let valid = self
            .wic
            .objects
            .get(&this)
            .is_some_and(|object| self.wic_is_encode_frame(object));
        state.set(
            Register::Rax,
            if valid {
                u64::from(S_OK)
            } else {
                u64::from(WINCODEC_ERR_NOTINITIALIZED)
            },
        );
        Ok(())
    }

    fn wic_frame_encode_set_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let width = guest_call_arg_u32(state, memory, 1)?;
        let height = guest_call_arg_u32(state, memory, 2)?;
        if width == 0
            || height == 0
            || width > 1_000_000
            || height > 1_000_000
            || (width as usize).saturating_mul(height as usize) > 64 * 1024 * 1024
        {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let valid = self
            .wic
            .objects
            .get(&this)
            .is_some_and(|object| self.wic_is_encode_frame(object));
        if !valid {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if let Some(frame) = self.wic.objects.get_mut(&this) {
            frame.width = width;
            frame.height = height;
            frame.pixels = vec![0; width as usize * height as usize * 4];
            frame.interpolation = 0;
            frame.transform &= !1;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_frame_encode_set_resolution(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let dpi_x = guest_call_arg_f64(state, memory, 1)?;
        let dpi_y = guest_call_arg_f64(state, memory, 2)?;
        if !dpi_x.is_finite() || !dpi_y.is_finite() || dpi_x <= 0.0 || dpi_y <= 0.0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let valid = self
            .wic
            .objects
            .get(&this)
            .is_some_and(|object| self.wic_is_encode_frame(object));
        if !valid {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if let Some(frame) = self.wic.objects.get_mut(&this) {
            frame.profile = wic_encode_dpi(dpi_x, dpi_y);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_frame_encode_set_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let format_ptr = guest_call_arg(state, memory, 1)?;
        let format = read_guid(memory, format_ptr);
        if pixel_layout(&format).is_none() {
            state.set(
                Register::Rax,
                u64::from(WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT),
            );
            return Ok(());
        }
        let valid = self
            .wic
            .objects
            .get(&this)
            .is_some_and(|object| self.wic_is_encode_frame(object));
        if !valid {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if let Some(frame) = self.wic.objects.get_mut(&this) {
            frame.pixel_format = format;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_frame_encode_write_pixels(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let line_count = guest_call_arg_u32(state, memory, 1)?;
        let stride = guest_call_arg_u32(state, memory, 2)?;
        let buffer_size = guest_call_arg_u32(state, memory, 3)?;
        let buffer = guest_call_arg(state, memory, 4)?;
        let Some(frame) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !self.wic_is_encode_frame(&frame) || frame.transform & 1 != 0 {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if frame.width == 0 || frame.height == 0 {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        let Some(layout) = pixel_layout(&frame.pixel_format) else {
            state.set(
                Register::Rax,
                u64::from(WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT),
            );
            return Ok(());
        };
        let bytes = layout_bytes(layout) as usize;
        let row_bytes = frame.width as usize * bytes;
        let written = frame.interpolation as usize;
        let rows = line_count as usize;
        if rows == 0
            || buffer == 0
            || written + rows > frame.height as usize
            || (stride as usize) < row_bytes
        {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let needed = stride as usize * rows;
        if needed > buffer_size as usize {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Ok(data) = memory.read_bytes(buffer, needed) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if let Some(frame) = self.wic.objects.get_mut(&this) {
            for row in 0..rows {
                for col in 0..frame.width as usize {
                    let source = row * stride as usize + col * bytes;
                    let mut pixel = [0_u8; 4];
                    for (index, slot) in pixel.iter_mut().enumerate().take(bytes) {
                        *slot = data.get(source + index).copied().unwrap_or(0);
                    }
                    let converted = convert_pixel(layout, PixelLayout::Bgra, &pixel);
                    let destination = (written + row) * frame.width as usize * 4 + col * 4;
                    if let Some(slot) = frame.pixels.get_mut(destination..destination + 4) {
                        slot.copy_from_slice(&converted);
                    }
                }
            }
            frame.interpolation = (written + rows) as u32;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_frame_encode_write_source(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let source_ptr = guest_call_arg(state, memory, 1)?;
        let rect_ptr = guest_call_arg(state, memory, 2)?;
        let Some(frame) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !self.wic_is_encode_frame(&frame) || frame.transform & 1 != 0 {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if frame.width == 0 || frame.height == 0 {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        let Some(source) = self.wic.objects.get(&source_ptr).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let (source_width, source_height) = wic_source_dimensions(&source);
        let (x, y, w, h) = match wic_read_rect(memory, rect_ptr) {
            Some([x, y, w, h]) => (x, y, w, h),
            None if rect_ptr == 0 => (0, 0, source_width as i32, source_height as i32),
            None => {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        };
        if w <= 0
            || h <= 0
            || x < 0
            || y < 0
            || x as u32 + w as u32 > source_width
            || y as u32 + h as u32 > source_height
        {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some(layout) = pixel_layout(&source.pixel_format) else {
            state.set(
                Register::Rax,
                u64::from(WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT),
            );
            return Ok(());
        };
        let bytes = layout_bytes(layout) as usize;
        let source_pixels = wic_copy_source_pixels(
            &self.wic.objects,
            &source,
            x as u32,
            y as u32,
            w as u32,
            h as u32,
        );
        if source_pixels.len() < w as usize * h as usize * bytes {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_BADIMAGE));
            return Ok(());
        }
        let written = frame.interpolation as usize;
        if written + h as usize > frame.height as usize || w as usize > frame.width as usize {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if let Some(frame) = self.wic.objects.get_mut(&this) {
            for row in 0..h as usize {
                for col in 0..w as usize {
                    let source = (row * w as usize + col) * bytes;
                    let mut pixel = [0_u8; 4];
                    for (index, slot) in pixel.iter_mut().enumerate().take(bytes) {
                        *slot = source_pixels[source + index];
                    }
                    let converted = convert_pixel(layout, PixelLayout::Bgra, &pixel);
                    let destination = (written + row) * frame.width as usize * 4 + col * 4;
                    if let Some(slot) = frame.pixels.get_mut(destination..destination + 4) {
                        slot.copy_from_slice(&converted);
                    }
                }
            }
            frame.interpolation = (written + h as usize) as u32;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_frame_encode_commit(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(frame) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !self.wic_is_encode_frame(&frame) || frame.transform & 1 != 0 {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        if frame.width == 0
            || frame.height == 0
            || frame.interpolation as usize != frame.height as usize
        {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let expected = frame.width as usize * frame.height as usize * 4;
        if frame.pixels.len() < expected {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_BADIMAGE));
            return Ok(());
        }
        let dpi = wic_decode_dpi(&frame);
        let encoded =
            match wic_encode_png(frame.width, frame.height, &frame.pixels[..expected], dpi) {
                Ok(encoded) => encoded,
                Err(code) => {
                    state.set(Register::Rax, u64::from(code));
                    return Ok(());
                }
            };
        let Some(encoder) = self.wic.objects.get_mut(&frame.source) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !encoder.profile.starts_with(WIC_ENCODER_MAGIC) {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        encoder.stream = encoded;
        encoder.transform |= 2;
        if let Some(frame) = self.wic.objects.get_mut(&this) {
            frame.transform |= 1;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IWICBitmapScaler / Clipper / FlipRotator / FormatConverter ────────

    fn wic_transformed_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        kind: WicObjectKind,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let source = guest_call_arg(state, memory, 1)?;
        let Some(source_state) = self.wic.objects.get(&source).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let (source_width, source_height) = wic_source_dimensions(&source_state);
        let Some(target) = self.wic.objects.get_mut(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if target.kind != kind {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        match kind {
            WicObjectKind::Scaler => {
                // Initialize(pSource, uiWidth, uiHeight, mode)
                let width = guest_call_arg_u32(state, memory, 2)?;
                let height = guest_call_arg_u32(state, memory, 3)?;
                let mode = guest_call_arg_u32(state, memory, 4)?;
                if width == 0 || height == 0 {
                    state.set(Register::Rax, u64::from(E_INVALIDARG));
                    return Ok(());
                }
                target.source = source;
                target.width = width;
                target.height = height;
                target.interpolation = mode;
            }
            WicObjectKind::FlipRotator => {
                // Initialize(pSource, transformOptions)
                let transform = guest_call_arg_u32(state, memory, 2)?;
                target.source = source;
                target.width = source_width;
                target.height = source_height;
                target.transform = transform;
            }
            WicObjectKind::FormatConverter => {
                // Initialize(pSource, guidDstFormat, dither, level,
                // cacheOptions)
                let format_ptr = guest_call_arg(state, memory, 2)?;
                let format = read_guid(memory, format_ptr);
                if pixel_layout(&format).is_none() {
                    state.set(Register::Rax, u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT));
                    return Ok(());
                }
                target.source = source;
                target.width = source_width;
                target.height = source_height;
                target.pixel_format = format;
            }
            _ => {}
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_scaler_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        // Initialize(pSource, uiWidth, uiHeight, mode)
        self.wic_transformed_initialize(state, memory, WicObjectKind::Scaler)
    }

    fn wic_clipper_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        // Initialize(pSource, prc) — the rect arrives as a pointer, so the
        // transform helper's integer reads do not apply; handled inline.
        let this = guest_call_arg(state, memory, 0)?;
        let source = guest_call_arg(state, memory, 1)?;
        let rect_ptr = guest_call_arg(state, memory, 2)?;
        if !self.wic.objects.contains_key(&source) {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let data = memory.read_bytes(rect_ptr, 16).unwrap_or_default();
        if data.len() != 16 {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        }
        let clip = [
            i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            i32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            i32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            i32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        ];
        let Some(target) = self.wic.objects.get_mut(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if target.kind != WicObjectKind::Clipper {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        target.source = source;
        target.clip = Some(clip);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_flip_rotator_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_transformed_initialize(state, memory, WicObjectKind::FlipRotator)
    }

    fn wic_format_converter_initialize(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.wic_transformed_initialize(state, memory, WicObjectKind::FormatConverter)
    }

    fn wic_scaler_get_dimensions(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, object.width).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_scaler_get_interpolation(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, object.interpolation).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_clipper_get_clip_rect(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        let clip = object
            .clip
            .unwrap_or([0, 0, object.width as i32, object.height as i32]);
        if out != 0 {
            for (i, value) in clip.iter().enumerate() {
                write_guest_u32(memory, out + (i as u64 * 4), *value as u32).ok();
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_flip_get_transform(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, object.transform).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_converter_can_convert(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let src = guest_call_arg(state, memory, 1)?;
        let dst = guest_call_arg(state, memory, 2)?;
        let src_guid = read_guid(memory, src);
        let dst_guid = read_guid(memory, dst);
        let supported = pixel_layout(&src_guid).is_some() && pixel_layout(&dst_guid).is_some();
        state.set(Register::Rax, if supported { u64::from(S_OK) } else { 1 });
        Ok(())
    }

    // ── IWICPalette methods ────────────────────────────────────────────────

    fn wic_palette_initialize_custom(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let colors = guest_call_arg(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)?;
        if colors == 0 || count == 0 || count > WIC_PALETTE_MAX_COLORS {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let mut palette = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let Ok(color) = read_guest_u32(memory, colors + (i as u64 * 4)) else {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            };
            palette.push(color);
        }
        let Some(target) = self.wic.objects.get_mut(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if target.kind != WicObjectKind::Palette {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        target.palette = palette;
        target.palette_premultiplied = false;
        target.exif_color_space = WIC_PALETTE_TYPE_CUSTOM;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_palette_initialize_from_bitmap(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let source = guest_call_arg(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)?;
        let _alpha = guest_call_arg_u32(state, memory, 3)?;
        let Some(source_state) = self.wic.objects.get(&source).cloned() else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        let colors = wic_collect_palette(&source_state);
        let Some(target) = self.wic.objects.get_mut(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if target.kind != WicObjectKind::Palette {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        target.palette = colors;
        target.palette_premultiplied = false;
        // A zero color count asks for an optimal palette; otherwise the
        // generated table is a custom one.
        target.exif_color_space = if count == 0 {
            WIC_PALETTE_TYPE_OPTIMAL
        } else {
            WIC_PALETTE_TYPE_CUSTOM
        };
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_palette_get_color_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, object.palette.len() as u32).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_palette_get_colors(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let count = guest_call_arg_u32(state, memory, 1)?;
        let colors = guest_call_arg(state, memory, 2)?;
        let actual = guest_call_arg(state, memory, 3)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        let copy = count.min(object.palette.len() as u32);
        for i in 0..copy as usize {
            write_guest_u32(memory, colors + (i as u64 * 4), object.palette[i]).ok();
        }
        if actual != 0 {
            write_guest_u32(memory, actual, copy).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_scaler_set_interpolation_mode(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let mode = guest_call_arg_u32(state, memory, 1)?;
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.interpolation = mode;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_clipper_set_clip_rect(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let rect_ptr = guest_call_arg(state, memory, 1)?;
        let data = memory.read_bytes(rect_ptr, 16).unwrap_or_default();
        if data.len() != 16 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let clip = [
            i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            i32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            i32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            i32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        ];
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.clip = Some(clip);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_converter_get_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let format_out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if format_out != 0 {
            write_guest_bytes(memory, format_out, &object.pixel_format);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_converter_set_pixel_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let format = guest_call_arg(state, memory, 1)?;
        let format = read_guid(memory, format);
        if pixel_layout(&format).is_none() {
            state.set(Register::Rax, u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT));
            return Ok(());
        }
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.pixel_format = format;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_palette_initialize_predefined(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let palette_type = guest_call_arg_u32(state, memory, 1)?;
        let add_transparent = guest_call_arg_u32(state, memory, 2)?;
        let colors = match palette_type {
            WIC_PALETTE_TYPE_FIXED_BW => vec![0xff00_0000, 0xffff_ffff],
            WIC_PALETTE_TYPE_FIXED_GRAY4 => (0..4_u32)
                .map(|step| {
                    let value = step * 85;
                    0xff00_0000 | (value << 16) | (value << 8) | value
                })
                .collect(),
            WIC_PALETTE_TYPE_FIXED_GRAY16 => (0..16_u32)
                .map(|step| {
                    let value = step * 17;
                    0xff00_0000 | (value << 16) | (value << 8) | value
                })
                .collect(),
            WIC_PALETTE_TYPE_FIXED_GRAY256 => (0..256_u32)
                .map(|value| 0xff00_0000 | (value << 16) | (value << 8) | value)
                .collect(),
            _ => {
                // The halftone/median-cut predefined tables are not provided.
                state.set(Register::Rax, u64::from(WIC_E_NOTSUPPORTED));
                return Ok(());
            }
        };
        let Some(target) = self.wic.objects.get_mut(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if target.kind != WicObjectKind::Palette {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        target.palette = colors;
        target.palette_premultiplied = false;
        if add_transparent != 0 {
            // The documented transparent entry (alpha 0).
            target.palette.push(0x0000_0000);
        }
        target.exif_color_space = palette_type;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_palette_initialize_from_palette(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let palette = guest_call_arg(state, memory, 1)?;
        let Some(other) = self.wic.objects.get(&palette).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(target) = self.wic.objects.get_mut(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if target.kind != WicObjectKind::Palette {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        target.palette = other.palette.clone();
        target.palette_premultiplied = other.palette_premultiplied;
        target.exif_color_space = other.exif_color_space;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_palette_get_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let palette_type = self
            .wic
            .objects
            .get(&this)
            .map(|object| object.exif_color_space)
            .unwrap_or(WIC_PALETTE_TYPE_CUSTOM);
        if out != 0 {
            write_guest_u32(memory, out, palette_type).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IWICPalette::IsBlackWhite` / `IsGrayscale` / `HasAlpha` — computed
    /// from the palette's ARGB entries.
    fn wic_palette_flag(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        which: u32,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let colors = self
            .wic
            .objects
            .get(&this)
            .map(|object| object.palette.as_slice())
            .unwrap_or(&[]);
        let flag = if colors.is_empty() {
            false
        } else {
            match which {
                0 => colors.iter().all(|c| {
                    let r = (c >> 16) as u8;
                    let g = (c >> 8) as u8;
                    let b = *c as u8;
                    (r == 0 || r == 255) && r == g && g == b
                }),
                1 => colors.iter().all(|c| {
                    ((c >> 16) as u8) == ((c >> 8) as u8) && ((c >> 8) as u8) == (*c as u8)
                }),
                _ => colors.iter().any(|c| (c >> 24) as u8 != 0xff),
            }
        };
        if out != 0 {
            write_guest_u32(memory, out, if flag { 1 } else { 0 }).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_stream_initialize_from_i_stream_region(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg(state, memory, 1)?;
        let offset = guest_call_arg(state, memory, 2)?;
        let size = guest_call_arg_u32(state, memory, 3)?;
        let payload = self
            .com_streams
            .get(&stream)
            .map(|s: &crate::runtime::state::ComStreamState| s.data.clone())
            .unwrap_or_default();
        let bytes: Vec<u8> = payload
            .iter()
            .skip(offset as usize)
            .take(size as usize)
            .copied()
            .collect();
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.stream = bytes;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_color_context_initialize_from_filename(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let filename = guest_call_arg(state, memory, 1)?;
        let path = read_utf16_string(memory, filename).unwrap_or_default();
        let Ok(bytes) = std::fs::read(&path) else {
            state.set(Register::Rax, 0x8007_0003);
            return Ok(());
        };
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.profile = bytes;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_color_context_get_exif_color_space(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, object.exif_color_space).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_color_context_set_exif_color_space(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let space = guest_call_arg_u32(state, memory, 1)?;
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.exif_color_space = space;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_component_info_write_zero_guid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_bytes(memory, out, &[0_u8; 16]);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_component_info_get_signing_status(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_u32(memory, out, 1).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_component_info_write_empty_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _capacity = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let actual = guest_call_arg(state, memory, 3)?;
        if out != 0 {
            write_guest_u16(memory, out, 0).ok();
        }
        if actual != 0 {
            write_guest_u32(memory, actual, 0).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IWICStream methods ─────────────────────────────────────────────────

    fn wic_stream_initialize_from_memory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let data = guest_call_arg(state, memory, 1)?;
        let size = guest_call_arg_u32(state, memory, 2)?;
        let bytes = memory.read_bytes(data, size as usize).unwrap_or_default();
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.stream = bytes;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_stream_initialize_from_filename(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let filename = guest_call_arg(state, memory, 1)?;
        let _desired = guest_call_arg_u32(state, memory, 2)?;
        let path = read_utf16_string(memory, filename).unwrap_or_default();
        let Ok(bytes) = std::fs::read(&path) else {
            state.set(Register::Rax, 0x8007_0003);
            return Ok(());
        };
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.stream = bytes;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_stream_initialize_from_i_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg(state, memory, 1)?;
        let payload = self
            .com_streams
            .get(&stream)
            .map(|s: &crate::runtime::state::ComStreamState| s.data.clone())
            .unwrap_or_default();
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.stream = payload;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IWICColorContext methods ───────────────────────────────────────────

    fn wic_color_context_initialize_from_memory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let data = guest_call_arg(state, memory, 1)?;
        let size = guest_call_arg_u32(state, memory, 2)?;
        let bytes = memory.read_bytes(data, size as usize).unwrap_or_default();
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.profile = bytes;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_color_context_get_profile_bytes(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let capacity = guest_call_arg_u32(state, memory, 2)?;
        let actual = guest_call_arg(state, memory, 3)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        let copy = capacity.min(object.profile.len() as u32) as usize;
        if buffer != 0 {
            for (i, byte) in object.profile.iter().take(copy).enumerate() {
                memory.write_u8(buffer + i as u64, *byte);
            }
        }
        if actual != 0 {
            write_guest_u32(memory, actual, object.profile.len() as u32).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_color_context_get_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.wic.objects.contains_key(&this) {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        }
        if out != 0 {
            write_guest_u32(memory, out, WIC_COLOR_CONTEXT_UNINITIALIZED).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── IWICComponentInfo methods ──────────────────────────────────────────

    fn wic_component_info_get_component_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this) else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, object.component_type).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_component_info_get_friendly_name(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _capacity = guest_call_arg_u32(state, memory, 1)?;
        let name = guest_call_arg(state, memory, 2)?;
        let actual = guest_call_arg(state, memory, 3)?;
        if name != 0 {
            write_utf16_string(memory, name, "Component", 64);
        }
        if actual != 0 {
            write_guest_u32(memory, actual, "Component".encode_utf16().count() as u32).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }
}

// ── Free helpers ───────────────────────────────────────────────────────────

fn read_guid(memory: &MemoryImage, pointer: u64) -> [u8; 16] {
    let mut guid = [0_u8; 16];
    if let Ok(bytes) = memory.read_bytes(pointer, 16) {
        guid.copy_from_slice(&bytes);
    }
    guid
}

fn write_guest_bytes(memory: &mut MemoryImage, address: u64, bytes: &[u8]) {
    for (i, byte) in bytes.iter().enumerate() {
        memory.write_u8(address + i as u64, *byte);
    }
}

fn write_utf16_string(memory: &mut MemoryImage, address: u64, text: &str, capacity: usize) {
    for (i, unit) in text
        .encode_utf16()
        .enumerate()
        .take(capacity.saturating_sub(1))
    {
        memory.write_u16(address + (i as u64 * 2), unit);
    }
    memory.write_u16(
        address + (text.encode_utf16().count().min(capacity.saturating_sub(1)) as u64 * 2),
        0,
    );
}

/// Read a `WICRect` from guest memory.
fn wic_read_rect(memory: &MemoryImage, pointer: u64) -> Option<[i32; 4]> {
    if pointer == 0 {
        return None;
    }
    let data = memory.read_bytes(pointer, 16).ok()?;
    if data.len() != 16 {
        return None;
    }
    Some([
        i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        i32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        i32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        i32::from_le_bytes([data[12], data[13], data[14], data[15]]),
    ])
}

// ── The real image codecs (PNG / baseline JPEG) ───────────────────────────

/// A decoded image in the runtime's canonical 32bpp BGRA layout.
struct WicDecodedImage {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
    container: [u8; 16],
    /// 1 = PNG, 2 = baseline JPEG.
    codec: u32,
    dpi_x: f64,
    dpi_y: f64,
}

fn wic_decode_image(bytes: &[u8]) -> std::result::Result<WicDecodedImage, u32> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        wic_decode_png(bytes)
    } else if bytes.starts_with(&[0xff, 0xd8]) {
        wic_decode_jpeg(bytes)
    } else {
        Err(WINCODEC_ERR_UNKNOWNIMAGEFORMAT)
    }
}

fn wic_png_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn wic_png_paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i32::from(a) + i32::from(b) - i32::from(c);
    let pa = (p - i32::from(a)).abs();
    let pb = (p - i32::from(b)).abs();
    let pc = (p - i32::from(c)).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Parse a real PNG: signature, IHDR, IDAT (zlib inflate + PNG filters),
/// IEND, with chunk CRC validation.
fn wic_decode_png(bytes: &[u8]) -> std::result::Result<WicDecodedImage, u32> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 8 || &bytes[..8] != SIGNATURE {
        return Err(WINCODEC_ERR_UNKNOWNIMAGEFORMAT);
    }
    let mut position = 8_usize;
    let mut width = 0_u32;
    let mut height = 0_u32;
    let mut color_type = 0_u8;
    let mut seen_header = false;
    let mut seen_end = false;
    let mut idat = Vec::new();
    let mut dpi_x = WIC_DEFAULT_DPI;
    let mut dpi_y = WIC_DEFAULT_DPI;
    while position + 8 <= bytes.len() {
        let length = u32::from_be_bytes([
            bytes[position],
            bytes[position + 1],
            bytes[position + 2],
            bytes[position + 3],
        ]) as usize;
        if length > 128 * 1024 * 1024
            || position
                .checked_add(12)
                .and_then(|value| value.checked_add(length))
                .is_none_or(|end| end > bytes.len())
        {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        let kind = &bytes[position + 4..position + 8];
        let data = &bytes[position + 8..position + 8 + length];
        let stored_crc = u32::from_be_bytes([
            bytes[position + 8 + length],
            bytes[position + 9 + length],
            bytes[position + 10 + length],
            bytes[position + 11 + length],
        ]);
        let mut crc_input = Vec::with_capacity(4 + length);
        crc_input.extend_from_slice(kind);
        crc_input.extend_from_slice(data);
        if wic_png_crc32(&crc_input) != stored_crc {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        match kind {
            b"IHDR" => {
                if seen_header || length != 13 {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                seen_header = true;
                width = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                height = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let depth = data[8];
                color_type = data[9];
                let compression = data[10];
                let filter = data[11];
                let interlace = data[12];
                if width == 0
                    || height == 0
                    || width > 1_000_000
                    || height > 1_000_000
                    || depth != 8
                    || compression != 0
                    || filter != 0
                    || interlace != 0
                {
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
                if !matches!(color_type, 0 | 2 | 4 | 6) {
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
            }
            b"IDAT" => {
                if !seen_header {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                idat.extend_from_slice(data);
            }
            b"IEND" => {
                seen_end = true;
                break;
            }
            b"pHYs" => {
                if length >= 9 && data[8] == 1 {
                    let ppu_x = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    let ppu_y = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    if ppu_x > 0 {
                        dpi_x = f64::from(ppu_x) * 0.0254;
                    }
                    if ppu_y > 0 {
                        dpi_y = f64::from(ppu_y) * 0.0254;
                    }
                }
            }
            _ => {
                // Unknown critical chunks (uppercase first letter) cannot be
                // ignored safely; ancillary chunks are skipped.
                if kind[0].is_ascii_uppercase() {
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
            }
        }
        position += 12 + length;
    }
    if !seen_header || !seen_end || idat.is_empty() {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let channels = match color_type {
        0 => 1_usize,
        2 => 3,
        4 => 2,
        6 => 4,
        _ => return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION),
    };
    let pixel_bytes = (width as usize)
        .checked_mul(height as usize)
        .and_then(|value| value.checked_mul(4))
        .ok_or(WINCODEC_ERR_BADIMAGE)?;
    if pixel_bytes > 256 * 1024 * 1024 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let row_len = (width as usize)
        .checked_mul(channels)
        .ok_or(WINCODEC_ERR_BADIMAGE)?;
    let expected = row_len
        .checked_add(1)
        .and_then(|value| value.checked_mul(height as usize))
        .ok_or(WINCODEC_ERR_BADIMAGE)?;
    let mut inflater = flate2::read::ZlibDecoder::new(idat.as_slice());
    let mut raw = Vec::with_capacity(expected);
    if inflater
        .by_ref()
        .take(expected as u64 + 1)
        .read_to_end(&mut raw)
        .is_err()
        || raw.len() != expected
    {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let mut previous = vec![0_u8; row_len];
    let mut current = vec![0_u8; row_len];
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    for row in 0..height as usize {
        let filter = raw[row * (row_len + 1)];
        let source = &raw[row * (row_len + 1) + 1..(row + 1) * (row_len + 1)];
        current.copy_from_slice(source);
        for index in 0..row_len {
            let left = if index >= channels {
                current[index - channels]
            } else {
                0
            };
            let up = previous[index];
            let up_left = if index >= channels {
                previous[index - channels]
            } else {
                0
            };
            current[index] = match filter {
                0 => current[index],
                1 => current[index].wrapping_add(left),
                2 => current[index].wrapping_add(up),
                3 => current[index].wrapping_add(((u16::from(left) + u16::from(up)) / 2) as u8),
                4 => current[index].wrapping_add(wic_png_paeth(left, up, up_left)),
                _ => return Err(WINCODEC_ERR_BADIMAGE),
            };
        }
        let destination = row * width as usize * 4;
        for column in 0..width as usize {
            let source = column * channels;
            let pixel = match color_type {
                0 => {
                    let gray = current[source];
                    [gray, gray, gray, 255]
                }
                2 => {
                    let red = current[source];
                    let green = current[source + 1];
                    let blue = current[source + 2];
                    [blue, green, red, 255]
                }
                4 => {
                    let gray = current[source];
                    [gray, gray, gray, current[source + 1]]
                }
                _ => {
                    let red = current[source];
                    let green = current[source + 1];
                    let blue = current[source + 2];
                    [blue, green, red, current[source + 3]]
                }
            };
            pixels[destination + column * 4..destination + column * 4 + 4].copy_from_slice(&pixel);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    Ok(WicDecodedImage {
        width,
        height,
        pixels,
        container: GUID_CONTAINER_FORMAT_PNG,
        codec: 1,
        dpi_x,
        dpi_y,
    })
}

fn wic_png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&wic_png_crc32(&crc_input).to_be_bytes());
}

/// Encode real PNG bytes (8-bit RGBA, filter 0 scanlines, a real zlib stream,
/// chunk CRCs) from the runtime's BGRA pixels.
fn wic_encode_png(
    width: u32,
    height: u32,
    bgra: &[u8],
    dpi: Option<(f64, f64)>,
) -> std::result::Result<Vec<u8>, u32> {
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|value| value.checked_mul(4))
        .ok_or(E_INVALIDARG)?;
    if width == 0 || height == 0 || bgra.len() < expected {
        return Err(E_INVALIDARG);
    }
    let mut raw = Vec::with_capacity(height as usize * (1 + width as usize * 4));
    for row in 0..height as usize {
        raw.push(0);
        for column in 0..width as usize {
            let source = (row * width as usize + column) * 4;
            raw.extend_from_slice(&[
                bgra[source + 2],
                bgra[source + 1],
                bgra[source],
                bgra[source + 3],
            ]);
        }
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&raw).map_err(|_| WINCODEC_ERR_BADIMAGE)?;
    let compressed = encoder.finish().map_err(|_| WINCODEC_ERR_BADIMAGE)?;
    let mut out = Vec::with_capacity(compressed.len() + 96);
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    wic_png_chunk(&mut out, b"IHDR", &header);
    if let Some((dpi_x, dpi_y)) = dpi
        && dpi_x.is_finite()
        && dpi_y.is_finite()
        && dpi_x > 0.0
        && dpi_y > 0.0
    {
        let mut physical = Vec::with_capacity(9);
        physical.extend_from_slice(&((dpi_x / 0.0254).round() as u32).to_be_bytes());
        physical.extend_from_slice(&((dpi_y / 0.0254).round() as u32).to_be_bytes());
        physical.push(1);
        wic_png_chunk(&mut out, b"pHYs", &physical);
    }
    wic_png_chunk(&mut out, b"IDAT", &compressed);
    wic_png_chunk(&mut out, b"IEND", &[]);
    Ok(out)
}

// ── Baseline JPEG (SOF0/SOF1 + SOS Huffman scan) ──────────────────────────

const WIC_JPEG_ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

struct WicJpegHuffman {
    entries: Vec<(u16, u8, u8)>,
}

impl WicJpegHuffman {
    fn build(counts: &[u8; 16], symbols: &[u8]) -> Option<Self> {
        let total: usize = counts.iter().map(|count| *count as usize).sum();
        if total != symbols.len() || total == 0 {
            return None;
        }
        let mut entries = Vec::with_capacity(total);
        let mut code = 0_u32;
        let mut symbol = 0_usize;
        for length in 1..=16_u8 {
            for _ in 0..counts[(length - 1) as usize] {
                entries.push((code as u16, length, symbols[symbol]));
                code += 1;
                symbol += 1;
            }
            if code > (1_u32 << length) {
                return None;
            }
            code <<= 1;
        }
        Some(Self { entries })
    }

    fn decode(&self, bits: &mut WicJpegBits<'_>) -> Option<u8> {
        let mut code = 0_u32;
        for length in 1..=16_u8 {
            code = (code << 1) | u32::from(bits.bit()?);
            for &(candidate, candidate_length, symbol) in &self.entries {
                if candidate_length == length && u32::from(candidate) == code {
                    return Some(symbol);
                }
            }
        }
        None
    }
}

struct WicJpegBits<'a> {
    data: &'a [u8],
    position: usize,
    buffer: u32,
    count: u32,
    marker_position: Option<usize>,
    restart_pending: bool,
}

impl<'a> WicJpegBits<'a> {
    fn new(data: &'a [u8], position: usize) -> Self {
        Self {
            data,
            position,
            buffer: 0,
            count: 0,
            marker_position: None,
            restart_pending: false,
        }
    }

    fn read_byte(&mut self) -> Option<u8> {
        while self.position < self.data.len() {
            let byte = self.data[self.position];
            if byte == 0xff {
                let next = *self.data.get(self.position + 1)?;
                if next == 0x00 {
                    self.position += 2;
                    return Some(0xff);
                }
                if (0xd0..=0xd7).contains(&next) {
                    self.restart_pending = true;
                }
                self.marker_position = Some(self.position);
                return None;
            }
            self.position += 1;
            return Some(byte);
        }
        None
    }

    fn bit(&mut self) -> Option<u8> {
        if self.count == 0 {
            let byte = self.read_byte()?;
            self.buffer = u32::from(byte);
            self.count = 8;
        }
        self.count -= 1;
        Some(((self.buffer >> self.count) & 1) as u8)
    }

    fn bits(&mut self, count: u32) -> Option<u32> {
        if count == 0 {
            return Some(0);
        }
        if count > 24 {
            return None;
        }
        while self.count < count {
            let byte = self.read_byte()?;
            self.buffer = (self.buffer << 8) | u32::from(byte);
            self.count += 8;
        }
        self.count -= count;
        Some((self.buffer >> self.count) & ((1_u32 << count) - 1))
    }

    fn align(&mut self) {
        self.buffer = 0;
        self.count = 0;
    }

    fn skip_restart(&mut self) -> bool {
        self.align();
        if self.restart_pending {
            self.restart_pending = false;
            if let Some(position) = self.marker_position.take() {
                self.position = position + 2;
                return true;
            }
        }
        while self.position + 1 < self.data.len() {
            if self.data[self.position] == 0xff {
                let next = self.data[self.position + 1];
                if (0xd0..=0xd7).contains(&next) {
                    self.position += 2;
                    return true;
                }
                if next != 0x00 {
                    return false;
                }
            }
            self.position += 1;
        }
        false
    }
}

fn wic_jpeg_extend(value: u32, size: u8) -> i32 {
    if size == 0 {
        0
    } else {
        let threshold = 1_i32 << (size - 1);
        if (value as i32) < threshold {
            value as i32 - (1_i32 << size) + 1
        } else {
            value as i32
        }
    }
}

struct WicJpegComponent {
    id: u8,
    h: usize,
    v: usize,
    tq: usize,
    dc_table: usize,
    ac_table: usize,
    dc_prediction: i32,
    blocks_x: usize,
    blocks_y: usize,
    plane_width: usize,
    plane_height: usize,
    samples: Vec<u8>,
}

fn wic_jpeg_idct(coefficients: &[i32; 64], cosine: &[[f32; 8]; 8], output: &mut [u8; 64]) {
    let mut temporary = [0_f32; 64];
    for row in 0..8 {
        for column in 0..8 {
            let mut sum = 0_f32;
            for index in 0..8 {
                sum += coefficients[row * 8 + index] as f32 * cosine[column][index];
            }
            temporary[row * 8 + column] = sum;
        }
    }
    for row in 0..8 {
        for column in 0..8 {
            let mut sum = 0_f32;
            for index in 0..8 {
                sum += temporary[index * 8 + column] * cosine[row][index];
            }
            output[row * 8 + column] = (sum + 128.0).round().clamp(0.0, 255.0) as u8;
        }
    }
}

/// Decode a real baseline JPEG: SOF0/SOF1, DQT, DHT, DRI, SOS Huffman scan,
/// dequantization, 2D IDCT, and nearest-neighbour chroma upsampling.
fn wic_decode_jpeg(bytes: &[u8]) -> std::result::Result<WicDecodedImage, u32> {
    if bytes.len() < 4 || bytes[0] != 0xff || bytes[1] != 0xd8 {
        return Err(WINCODEC_ERR_UNKNOWNIMAGEFORMAT);
    }
    let mut position = 2_usize;
    let mut width = 0_u32;
    let mut height = 0_u32;
    let mut components: Vec<WicJpegComponent> = Vec::new();
    let mut quant_tables = [[0_u16; 64]; 4];
    let mut quant_present = [false; 4];
    let mut dc_tables: [Option<WicJpegHuffman>; 4] = [None, None, None, None];
    let mut ac_tables: [Option<WicJpegHuffman>; 4] = [None, None, None, None];
    let mut restart_interval = 0_usize;
    let mut dpi_x = WIC_DEFAULT_DPI;
    let mut dpi_y = WIC_DEFAULT_DPI;
    let mut scan: Option<Vec<usize>> = None;
    let mut decoded = false;
    while position < bytes.len() {
        if bytes[position] != 0xff {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        while position < bytes.len() && bytes[position] == 0xff {
            position += 1;
        }
        let Some(marker) = bytes.get(position).copied() else {
            return Err(WINCODEC_ERR_BADIMAGE);
        };
        position += 1;
        if marker == 0xd9 {
            break;
        }
        if marker == 0x01 || marker == 0xd8 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let Some(length_bytes) = bytes.get(position..position + 2) else {
            return Err(WINCODEC_ERR_BADIMAGE);
        };
        let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
        if length < 2 || position + length > bytes.len() {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        let segment = &bytes[position + 2..position + length];
        match marker {
            0xe0 => {
                if segment.len() >= 12 && &segment[..5] == b"JFIF\0" {
                    let unit = segment[7];
                    let xd = u16::from_be_bytes([segment[8], segment[9]]);
                    let yd = u16::from_be_bytes([segment[10], segment[11]]);
                    if xd > 0 {
                        dpi_x = match unit {
                            1 => f64::from(xd),
                            2 => f64::from(xd) * 2.54,
                            _ => WIC_DEFAULT_DPI,
                        };
                    }
                    if yd > 0 {
                        dpi_y = match unit {
                            1 => f64::from(yd),
                            2 => f64::from(yd) * 2.54,
                            _ => WIC_DEFAULT_DPI,
                        };
                    }
                }
            }
            0xc0 | 0xc1 => {
                if segment.len() < 6 || segment[0] != 8 {
                    return Err(if segment.len() < 6 {
                        WINCODEC_ERR_BADIMAGE
                    } else {
                        WINCODEC_ERR_UNSUPPORTEDOPERATION
                    });
                }
                height = u32::from(u16::from_be_bytes([segment[1], segment[2]]));
                width = u32::from(u16::from_be_bytes([segment[3], segment[4]]));
                let count = segment[5] as usize;
                if width == 0
                    || height == 0
                    || width > 1_000_000
                    || height > 1_000_000
                    || (width as usize).saturating_mul(height as usize) > 64 * 1024 * 1024
                    || count == 0
                    || segment.len() < 6 + count * 3
                {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                components.clear();
                for index in 0..count {
                    let base = 6 + index * 3;
                    let sampling = segment[base + 1];
                    let h = usize::from(sampling >> 4);
                    let v = usize::from(sampling & 0x0f);
                    let tq = usize::from(segment[base + 2]);
                    if !(1..=4).contains(&h) || !(1..=4).contains(&v) || tq >= 4 {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    components.push(WicJpegComponent {
                        id: segment[base],
                        h,
                        v,
                        tq,
                        dc_table: 0,
                        ac_table: 0,
                        dc_prediction: 0,
                        blocks_x: 0,
                        blocks_y: 0,
                        plane_width: 0,
                        plane_height: 0,
                        samples: Vec::new(),
                    });
                }
            }
            0xc2 => return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION),
            0xc3 | 0xc5..=0xcf => return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION),
            0xc4 => {
                let mut cursor = 0_usize;
                while cursor < segment.len() {
                    if cursor + 17 > segment.len() {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    let class = segment[cursor] >> 4;
                    let identifier = usize::from(segment[cursor] & 0x0f);
                    if identifier >= 4 {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    cursor += 1;
                    let mut counts = [0_u8; 16];
                    counts.copy_from_slice(&segment[cursor..cursor + 16]);
                    cursor += 16;
                    let total: usize = counts.iter().map(|count| *count as usize).sum();
                    if cursor + total > segment.len() {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    let symbols = &segment[cursor..cursor + total];
                    cursor += total;
                    let Some(table) = WicJpegHuffman::build(&counts, symbols) else {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    };
                    if class == 0 {
                        dc_tables[identifier] = Some(table);
                    } else {
                        ac_tables[identifier] = Some(table);
                    }
                }
            }
            0xdb => {
                let mut cursor = 0_usize;
                while cursor < segment.len() {
                    let info = segment[cursor];
                    let precision = info >> 4;
                    let identifier = usize::from(info & 0x0f);
                    cursor += 1;
                    if identifier >= 4 {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    let mut table = [0_u16; 64];
                    if precision == 0 {
                        if cursor + 64 > segment.len() {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        for (index, slot) in table.iter_mut().enumerate() {
                            *slot = u16::from(segment[cursor + index]);
                        }
                        cursor += 64;
                    } else if precision == 1 {
                        if cursor + 128 > segment.len() {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        for (index, slot) in table.iter_mut().enumerate() {
                            *slot = u16::from_be_bytes([
                                segment[cursor + index * 2],
                                segment[cursor + index * 2 + 1],
                            ]);
                        }
                        cursor += 128;
                    } else {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    quant_tables[identifier] = table;
                    quant_present[identifier] = true;
                }
            }
            0xdd => {
                if segment.len() < 2 {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                restart_interval = u16::from_be_bytes([segment[0], segment[1]]) as usize;
            }
            0xda => {
                if decoded {
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
                if segment.is_empty() || components.is_empty() {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                let count = segment[0] as usize;
                if count == 0 || segment.len() < 4 + count * 2 {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                let mut order = Vec::with_capacity(count);
                for index in 0..count {
                    let identifier = segment[1 + index * 2];
                    let tables = segment[2 + index * 2];
                    let Some(component_index) = components
                        .iter()
                        .position(|component| component.id == identifier)
                    else {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    };
                    components[component_index].dc_table = usize::from(tables >> 4);
                    components[component_index].ac_table = usize::from(tables & 0x0f);
                    order.push(component_index);
                }
                let tail = &segment[1 + count * 2..];
                if tail.len() < 3 || tail[0] != 0 || tail[1] != 63 || tail[2] != 0 {
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
                if order.len() == 1 {
                    let component = &components[order[0]];
                    if component.h > 1 || component.v > 1 {
                        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                    }
                }
                let max_h = components
                    .iter()
                    .map(|component| component.h)
                    .max()
                    .unwrap_or(1);
                let max_v = components
                    .iter()
                    .map(|component| component.v)
                    .max()
                    .unwrap_or(1);
                let mcus_x = (width as usize).div_ceil(8 * max_h);
                let mcus_y = (height as usize).div_ceil(8 * max_v);
                for component in components.iter_mut() {
                    component.blocks_x = mcus_x * component.h;
                    component.blocks_y = mcus_y * component.v;
                    component.plane_width = component.blocks_x * 8;
                    component.plane_height = component.blocks_y * 8;
                    component.samples = vec![0_u8; component.plane_width * component.plane_height];
                    component.dc_prediction = 0;
                    if !quant_present[component.tq]
                        || dc_tables[component.dc_table].is_none()
                        || ac_tables[component.ac_table].is_none()
                    {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                }
                let mut cosine = [[0_f32; 8]; 8];
                for (x, row) in cosine.iter_mut().enumerate() {
                    for (u, value) in row.iter_mut().enumerate() {
                        let scale = if u == 0 {
                            std::f32::consts::FRAC_1_SQRT_2
                        } else {
                            1.0
                        };
                        *value = 0.5
                            * scale
                            * (((2 * x + 1) as f32 * u as f32 * std::f32::consts::PI) / 16.0).cos();
                    }
                }
                let mut bits = WicJpegBits::new(bytes, position + length);
                let mcu_count = mcus_x * mcus_y;
                for mcu in 0..mcu_count {
                    if restart_interval > 0 && mcu > 0 && mcu % restart_interval == 0 {
                        if !bits.skip_restart() {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        for component in components.iter_mut() {
                            component.dc_prediction = 0;
                        }
                    }
                    let mcu_x = mcu % mcus_x;
                    let mcu_y = mcu / mcus_x;
                    for &component_index in &order {
                        let (h, v) = {
                            let component = &components[component_index];
                            (component.h, component.v)
                        };
                        for block_y in 0..v {
                            for block_x in 0..h {
                                let component = &components[component_index];
                                let Some(dc_table) = dc_tables[component.dc_table].as_ref() else {
                                    return Err(WINCODEC_ERR_BADIMAGE);
                                };
                                let Some(ac_table) = ac_tables[component.ac_table].as_ref() else {
                                    return Err(WINCODEC_ERR_BADIMAGE);
                                };
                                let Some(category) = dc_table.decode(&mut bits) else {
                                    return Err(WINCODEC_ERR_BADIMAGE);
                                };
                                let difference = if category == 0 {
                                    0
                                } else {
                                    let Some(value) = bits.bits(u32::from(category)) else {
                                        return Err(WINCODEC_ERR_BADIMAGE);
                                    };
                                    wic_jpeg_extend(value, category)
                                };
                                let component = &mut components[component_index];
                                component.dc_prediction += difference;
                                let quant = &quant_tables[component.tq];
                                let mut coefficients = [0_i32; 64];
                                coefficients[0] = component.dc_prediction * i32::from(quant[0]);
                                let mut coefficient = 1_usize;
                                while coefficient < 64 {
                                    let Some(run_size) = ac_table.decode(&mut bits) else {
                                        return Err(WINCODEC_ERR_BADIMAGE);
                                    };
                                    let run = usize::from(run_size >> 4);
                                    let size = run_size & 0x0f;
                                    if size == 0 {
                                        if run == 15 {
                                            coefficient += 16;
                                        } else {
                                            break;
                                        }
                                    } else {
                                        coefficient += run;
                                        if coefficient >= 64 {
                                            break;
                                        }
                                        let Some(value) = bits.bits(u32::from(size)) else {
                                            return Err(WINCODEC_ERR_BADIMAGE);
                                        };
                                        let value = wic_jpeg_extend(value, size);
                                        let natural = WIC_JPEG_ZIGZAG[coefficient];
                                        coefficients[natural] =
                                            value * i32::from(quant[coefficient]);
                                        coefficient += 1;
                                    }
                                }
                                let mut block = [0_u8; 64];
                                wic_jpeg_idct(&coefficients, &cosine, &mut block);
                                let destination_x = (mcu_x * h + block_x) * 8;
                                let destination_y = (mcu_y * v + block_y) * 8;
                                for row in 0..8 {
                                    let start = (destination_y + row) * component.plane_width
                                        + destination_x;
                                    let end = start + 8;
                                    if let Some(slot) = component.samples.get_mut(start..end) {
                                        slot.copy_from_slice(&block[row * 8..row * 8 + 8]);
                                    }
                                }
                            }
                        }
                    }
                }
                decoded = true;
                scan = Some(order);
                let mut search = bits.position;
                if let Some(marker) = bits.marker_position {
                    search = marker;
                } else {
                    while search + 1 < bytes.len() {
                        if bytes[search] == 0xff
                            && bytes[search + 1] != 0
                            && !(0xd0..=0xd7).contains(&bytes[search + 1])
                        {
                            break;
                        }
                        search += 1;
                    }
                }
                position = search;
                continue;
            }
            0xe1..=0xef | 0xfe => {}
            _ => {}
        }
        position += length;
    }
    let Some(order) = scan else {
        return Err(WINCODEC_ERR_BADIMAGE);
    };
    if !decoded || width == 0 || height == 0 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    if order.len() != 3 && order.len() != 1 {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
    }
    let max_h = components
        .iter()
        .map(|component| component.h)
        .max()
        .unwrap_or(1);
    let max_v = components
        .iter()
        .map(|component| component.v)
        .max()
        .unwrap_or(1);
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    for y in 0..height as usize {
        for x in 0..width as usize {
            let (red, green, blue);
            if order.len() == 1 {
                let component = &components[order[0]];
                let sample_x = (x * component.h / max_h).min(component.plane_width - 1);
                let sample_y = (y * component.v / max_v).min(component.plane_height - 1);
                let value = component.samples[sample_y * component.plane_width + sample_x] as f32;
                red = value;
                green = value;
                blue = value;
            } else {
                let mut samples = [0_f32; 3];
                for (index, &component_index) in order.iter().enumerate() {
                    let component = &components[component_index];
                    let sample_x = (x * component.h / max_h).min(component.plane_width - 1);
                    let sample_y = (y * component.v / max_v).min(component.plane_height - 1);
                    samples[index] =
                        component.samples[sample_y * component.plane_width + sample_x] as f32;
                }
                let luminance = samples[0];
                let cb = samples[1] - 128.0;
                let cr = samples[2] - 128.0;
                red = luminance + 1.402 * cr;
                green = luminance - 0.344_136 * cb - 0.714_136 * cr;
                blue = luminance + 1.772 * cb;
            }
            let destination = (y * width as usize + x) * 4;
            pixels[destination] = blue.round().clamp(0.0, 255.0) as u8;
            pixels[destination + 1] = green.round().clamp(0.0, 255.0) as u8;
            pixels[destination + 2] = red.round().clamp(0.0, 255.0) as u8;
            pixels[destination + 3] = 255;
        }
    }
    Ok(WicDecodedImage {
        width,
        height,
        pixels,
        container: GUID_CONTAINER_FORMAT_JPEG,
        codec: 2,
        dpi_x,
        dpi_y,
    })
}

/// The effective (width, height) of a source-chain object: transformed
/// objects report their target size; bitmaps their own.
fn wic_source_dimensions(object: &WicObjectState) -> (u32, u32) {
    match object.kind {
        WicObjectKind::Scaler => (object.width, object.height),
        WicObjectKind::Clipper => {
            let Some([x, y, w, h]) = object.clip else {
                return (object.width, object.height);
            };
            let _ = (x, y);
            (w.max(0) as u32, h.max(0) as u32)
        }
        WicObjectKind::FlipRotator => {
            let rotate_quarter = matches!(
                object.transform & 0x3,
                WIC_TRANSFORM_ROTATE_90 | WIC_TRANSFORM_ROTATE_270
            );
            if rotate_quarter {
                (object.height, object.width)
            } else {
                (object.width, object.height)
            }
        }
        WicObjectKind::FormatConverter => (object.width, object.height),
        _ => (object.width, object.height),
    }
}

/// Resolve the actual pixel rectangle of a source object into a byte buffer
/// in the object's own pixel format, walking the transform chain.
fn wic_copy_source_pixels(
    objects: &std::collections::HashMap<u64, WicObjectState>,
    source: &WicObjectState,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
) -> Vec<u8> {
    let Some(layout) = pixel_layout(&source.pixel_format) else {
        return Vec::new();
    };
    let bytes = layout_bytes(layout);
    let mut out = Vec::with_capacity((w * h * bytes) as usize);
    match source.kind {
        WicObjectKind::Bitmap => {
            for row in 0..h as usize {
                let src_y = y as usize + row;
                if src_y >= source.height as usize {
                    break;
                }
                for col in 0..w as usize * bytes as usize {
                    let src = (src_y * source.width as usize * bytes as usize
                        + (x as usize * bytes as usize)
                        + col)
                        .min(source.pixels.len().saturating_sub(1));
                    out.push(source.pixels[src]);
                }
            }
        }
        WicObjectKind::FormatConverter => {
            // The converter wraps its source and translates each pixel into
            // the destination format (the converter's own pixel format).
            let Some(wrapped) = objects.get(&source.source) else {
                return out;
            };
            let (sw, sh) = wic_source_dimensions(wrapped);
            let full = wic_copy_source_pixels(objects, wrapped, 0, 0, sw, sh);
            let Some(src_layout) = pixel_layout(&wrapped.pixel_format) else {
                return out;
            };
            let src_bytes = layout_bytes(src_layout);
            for row in 0..h as usize {
                let sy = y as usize + row;
                if sy >= sh as usize {
                    break;
                }
                for col in 0..w as usize {
                    let sx = x as usize + col;
                    if sx >= sw as usize {
                        break;
                    }
                    let base = sy * sw as usize * src_bytes as usize + sx * src_bytes as usize;
                    let mut pixel = [0_u8; 4];
                    for (i, slot) in pixel.iter_mut().enumerate().take(src_bytes as usize) {
                        *slot = full.get(base + i).copied().unwrap_or(0);
                    }
                    let converted = convert_pixel(src_layout, layout, &pixel);
                    out.extend_from_slice(&converted[..bytes as usize]);
                }
            }
        }
        WicObjectKind::Clipper => {
            let clip = source
                .clip
                .unwrap_or([0, 0, source.width as i32, source.height as i32]);
            let (cx, cy, cw, ch) = (
                clip[0].max(0) as u32,
                clip[1].max(0) as u32,
                clip[2].max(0) as u32,
                clip[3].max(0) as u32,
            );
            let Some(wrapped) = objects.get(&source.source) else {
                return out;
            };
            let full = wic_copy_source_pixels(objects, wrapped, cx, cy, cw, ch);
            for row in 0..h as usize {
                let src_row = y as usize + row;
                if src_row >= ch as usize {
                    break;
                }
                for col in 0..w as usize * bytes as usize {
                    let src = (src_row * cw as usize * bytes as usize + col)
                        .min(full.len().saturating_sub(1));
                    out.push(full[src]);
                }
            }
        }
        WicObjectKind::Scaler => {
            let Some(wrapped) = objects.get(&source.source) else {
                return out;
            };
            let full =
                wic_copy_source_pixels(objects, wrapped, 0, 0, wrapped.width, wrapped.height);
            let src_layout = pixel_layout(&wrapped.pixel_format);
            let src_bytes = src_layout.map(layout_bytes).unwrap_or(1);
            for row in 0..h as usize {
                let src_y = ((y as usize + row) * wrapped.height as usize
                    / source.height.max(1) as usize)
                    .min(wrapped.height as usize - 1);
                for col in 0..w as usize {
                    let src_x = (col * wrapped.width as usize / source.width.max(1) as usize)
                        .min(wrapped.width as usize - 1);
                    for channel in 0..bytes as usize {
                        let src = (src_y * wrapped.width as usize * src_bytes as usize
                            + src_x * src_bytes as usize
                            + channel.min(src_bytes as usize - 1))
                        .min(full.len().saturating_sub(1));
                        out.push(full[src]);
                    }
                }
            }
        }
        WicObjectKind::FlipRotator => {
            let Some(wrapped) = objects.get(&source.source) else {
                return out;
            };
            let full =
                wic_copy_source_pixels(objects, wrapped, 0, 0, wrapped.width, wrapped.height);
            let src_bytes = pixel_layout(&wrapped.pixel_format)
                .map(layout_bytes)
                .unwrap_or(1);
            let transform = source.transform;
            let rotate = transform & 0x3;
            for row in 0..h as usize {
                for col in 0..w as usize {
                    let (sx, sy) = match rotate {
                        WIC_TRANSFORM_ROTATE_90 => (col, wrapped.height as usize - 1 - row),
                        WIC_TRANSFORM_ROTATE_180 => (
                            wrapped.width as usize - 1 - col,
                            wrapped.height as usize - 1 - row,
                        ),
                        WIC_TRANSFORM_ROTATE_270 => (wrapped.width as usize - 1 - col, row),
                        _ => (col, row),
                    };
                    let mut fx = sx;
                    let mut fy = sy;
                    if transform & WIC_TRANSFORM_FLIP_HORIZONTAL != 0 {
                        fx = wrapped.width as usize - 1 - fx;
                    }
                    if transform & WIC_TRANSFORM_FLIP_VERTICAL != 0 {
                        fy = wrapped.height as usize - 1 - fy;
                    }
                    for channel in 0..bytes as usize {
                        let src = (fy * wrapped.width as usize * src_bytes as usize
                            + fx * src_bytes as usize
                            + channel.min(src_bytes as usize - 1))
                        .min(full.len().saturating_sub(1));
                        out.push(full[src]);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Collect the distinct colors of a source as a palette (the honest
/// InitializeFromBitmap result).
fn wic_collect_palette(source: &WicObjectState) -> Vec<u32> {
    let layout = pixel_layout(&source.pixel_format);
    let Some(layout) = layout else {
        return Vec::new();
    };
    let bytes = layout_bytes(layout);
    let mut colors: Vec<u32> = Vec::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for px in source.pixels.chunks_exact(bytes as usize) {
        let color = match layout {
            PixelLayout::Bgra | PixelLayout::Pbgra => {
                u32::from_le_bytes([px[0], px[1], px[2], px[3]])
            }
            PixelLayout::Rgba => u32::from_le_bytes([px[2], px[1], px[0], px[3]]),
            PixelLayout::Bgr => u32::from_le_bytes([px[0], px[1], px[2], 255]),
            PixelLayout::Gray => u32::from_le_bytes([px[0], px[0], px[0], 255]),
        };
        if seen.insert(color) {
            colors.push(color);
        }
    }
    colors
}

/// Translate one pixel between the supported WIC layouts.  The pixel is
/// normalized to non-premultiplied RGBA and then written in the destination
/// layout (premultiplying for PBGRA, dropping alpha for BGR, and using the
/// Rec. 601 luminance for 8bppGray).
fn convert_pixel(src: PixelLayout, dst: PixelLayout, pixel: &[u8; 4]) -> [u8; 4] {
    let (r, g, b, a) = match src {
        PixelLayout::Bgra | PixelLayout::Rgba => (pixel[2], pixel[1], pixel[0], pixel[3]),
        PixelLayout::Pbgra => {
            let alpha = pixel[3];
            let unpremultiply = |channel: u8| {
                if alpha == 0 {
                    0
                } else {
                    ((u32::from(channel) * 255) / u32::from(alpha)).min(255) as u8
                }
            };
            (
                unpremultiply(pixel[2]),
                unpremultiply(pixel[1]),
                unpremultiply(pixel[0]),
                alpha,
            )
        }
        PixelLayout::Bgr => (pixel[2], pixel[1], pixel[0], 255),
        PixelLayout::Gray => (pixel[0], pixel[0], pixel[0], 255),
    };
    match dst {
        PixelLayout::Bgra => [b, g, r, a],
        PixelLayout::Rgba => [r, g, b, a],
        PixelLayout::Pbgra => {
            let premultiply = |channel: u8| ((u32::from(channel) * u32::from(a)) / 255) as u8;
            [premultiply(b), premultiply(g), premultiply(r), a]
        }
        PixelLayout::Bgr => [b, g, r, 0],
        PixelLayout::Gray => {
            let luma = (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
            [luma as u8, 0, 0, 0]
        }
    }
}

/// The bitmap's stored resolution encoded in the object's `profile` slot
/// (bitmaps do not carry a color profile; the slot is a per-kind union).
fn wic_encode_dpi(dpi_x: f64, dpi_y: f64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8);
    bytes.extend_from_slice(&(dpi_x as f32).to_le_bytes());
    bytes.extend_from_slice(&(dpi_y as f32).to_le_bytes());
    bytes
}

fn wic_decode_dpi(object: &WicObjectState) -> Option<(f64, f64)> {
    if object.profile.len() != 8 {
        return None;
    }
    let x = f32::from_le_bytes([
        object.profile[0],
        object.profile[1],
        object.profile[2],
        object.profile[3],
    ]) as f64;
    let y = f32::from_le_bytes([
        object.profile[4],
        object.profile[5],
        object.profile[6],
        object.profile[7],
    ]) as f64;
    if x > 0.0 && y > 0.0 && x.is_finite() && y.is_finite() {
        Some((x, y))
    } else {
        None
    }
}

/// The effective resolution of a source object: bitmaps report their stored
/// DPI, the transform chain reports the wrapped source's DPI (the WIC
/// transform contract), everything else the 96 DPI default.
fn wic_source_resolution(
    objects: &std::collections::HashMap<u64, WicObjectState>,
    object: &WicObjectState,
) -> (f64, f64) {
    let mut current = object;
    for _ in 0..32 {
        if current.kind == WicObjectKind::Bitmap {
            return wic_decode_dpi(current).unwrap_or((WIC_DEFAULT_DPI, WIC_DEFAULT_DPI));
        }
        if current.source == 0 {
            break;
        }
        let Some(wrapped) = objects.get(&current.source) else {
            break;
        };
        current = wrapped;
    }
    (WIC_DEFAULT_DPI, WIC_DEFAULT_DPI)
}

// ── The vtable builders ────────────────────────────────────────────────────

/// IWICImagingFactory vtable (IUnknown + the 25 documented methods).
#[allow(dead_code)] // the factory vtable builder
fn wic_factory_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicFactoryCreateDecoderFromFilename);
    methods.push(HostThunk::WicFactoryCreateDecoderFromStream);
    methods.push(HostThunk::WicFactoryCreateDecoderFromFileHandle);
    methods.push(HostThunk::WicFactoryCreateComponentInfo);
    methods.push(HostThunk::WicFactoryCreateDecoder);
    methods.push(HostThunk::WicFactoryCreateEncoder);
    methods.push(HostThunk::WicFactoryCreatePalette);
    methods.push(HostThunk::WicFactoryCreateFormatConverter);
    methods.push(HostThunk::WicFactoryCreateBitmapScaler);
    methods.push(HostThunk::WicFactoryCreateBitmapClipper);
    methods.push(HostThunk::WicFactoryCreateBitmapFlipRotator);
    methods.push(HostThunk::WicFactoryCreateStream);
    methods.push(HostThunk::WicFactoryCreateColorContext);
    methods.push(HostThunk::WicFactoryCreateColorTransformer);
    methods.push(HostThunk::WicFactoryCreateBitmap);
    methods.push(HostThunk::WicFactoryCreateBitmapFromSource);
    methods.push(HostThunk::WicFactoryCreateBitmapFromSourceRect);
    methods.push(HostThunk::WicFactoryCreateBitmapFromMemory);
    methods.push(HostThunk::WicFactoryCreateBitmapFromHbitmap);
    methods.push(HostThunk::WicFactoryCreateBitmapFromHicon);
    methods.push(HostThunk::WicFactoryCreateComponentEnumerator);
    methods.push(HostThunk::WicFactoryCreateFastMetadataEncoderFromFrameDecode);
    methods.push(HostThunk::WicFactoryCreateFastMetadataEncoderFromQueryWriter);
    methods.push(HostThunk::WicFactoryCreateQueryWriter);
    methods.push(HostThunk::WicFactoryCreateQueryWriterFromReader);
    methods
}

/// The IWICBitmapSource method block shared by every source object.
fn wic_source_methods(methods: &mut Vec<HostThunk>) {
    methods.push(HostThunk::WicSourceGetSize);
    methods.push(HostThunk::WicSourceGetPixelFormat);
    methods.push(HostThunk::WicSourceGetResolution);
    methods.push(HostThunk::WicSourceCopyPalette);
    methods.push(HostThunk::WicSourceCopyPixels);
}

#[allow(dead_code)] // the bitmap vtable builder
fn wic_bitmap_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    wic_source_methods(&mut methods);
    methods.push(HostThunk::WicBitmapLock);
    methods.push(HostThunk::WicBitmapSetPalette);
    methods.push(HostThunk::WicBitmapSetResolution);
    methods
}

#[allow(dead_code)] // the bitmap-lock vtable builder
fn wic_bitmap_lock_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicBitmapLockGetSize);
    methods.push(HostThunk::WicBitmapLockGetStride);
    methods.push(HostThunk::WicBitmapLockGetPixelFormat);
    methods.push(HostThunk::WicBitmapLockGetDataPointer);
    methods
}

#[allow(dead_code)] // the decoder vtable builder
fn wic_decoder_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicDecoderQueryCapability);
    methods.push(HostThunk::WicDecoderInitialize);
    methods.push(HostThunk::WicDecoderGetContainerFormat);
    methods.push(HostThunk::WicDecoderGetFrameCount);
    methods.push(HostThunk::WicDecoderGetFrame);
    methods.push(HostThunk::WicDecoderUnsupported);
    methods
}

#[allow(dead_code)] // the frame-decode vtable builder
fn wic_frame_decode_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    wic_source_methods(&mut methods);
    methods
}

#[allow(dead_code)] // the encoder vtable builder
fn wic_encoder_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicEncoderInitialize);
    methods.push(HostThunk::WicEncoderCreateNewFrame);
    methods.push(HostThunk::WicEncoderCommit);
    methods.push(HostThunk::WicEncoderGetContainerFormat);
    methods.push(HostThunk::WicEncoderUnsupported);
    methods
}

#[allow(dead_code)] // the frame-encode vtable builder
fn wic_frame_encode_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicFrameEncodeInitialize);
    methods.push(HostThunk::WicFrameEncodeSetSize);
    methods.push(HostThunk::WicFrameEncodeSetResolution);
    methods.push(HostThunk::WicFrameEncodeSetPixelFormat);
    methods.push(HostThunk::WicFrameEncodeWritePixels);
    methods.push(HostThunk::WicFrameEncodeWriteSource);
    methods.push(HostThunk::WicFrameEncodeCommit);
    methods.push(HostThunk::WicFrameEncodeUnsupported);
    methods
}

#[allow(dead_code)] // the scaler vtable builder
fn wic_scaler_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    wic_source_methods(&mut methods);
    methods.push(HostThunk::WicScalerInitialize);
    methods.push(HostThunk::WicScalerGetScaledWidth);
    methods.push(HostThunk::WicScalerGetScaledHeight);
    methods.push(HostThunk::WicScalerGetInterpolationMode);
    methods.push(HostThunk::WicScalerSetInterpolationMode);
    methods
}

#[allow(dead_code)] // the clipper vtable builder
fn wic_clipper_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    wic_source_methods(&mut methods);
    methods.push(HostThunk::WicClipperInitialize);
    methods.push(HostThunk::WicClipperGetClipRect);
    methods.push(HostThunk::WicClipperSetClipRect);
    methods
}

#[allow(dead_code)] // the flip-rotator vtable builder
fn wic_flip_rotator_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    wic_source_methods(&mut methods);
    methods.push(HostThunk::WicFlipRotatorInitialize);
    methods.push(HostThunk::WicFlipRotatorGetTransform);
    methods
}

#[allow(dead_code)] // the converter vtable builder
fn wic_format_converter_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    wic_source_methods(&mut methods);
    methods.push(HostThunk::WicFormatConverterInitialize);
    methods.push(HostThunk::WicFormatConverterCanConvert);
    methods.push(HostThunk::WicFormatConverterGetPixelFormat);
    methods.push(HostThunk::WicFormatConverterSetPixelFormat);
    methods
}

#[allow(dead_code)] // the palette vtable builder
fn wic_palette_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicPaletteInitializeCustom);
    methods.push(HostThunk::WicPaletteInitializePredefined);
    methods.push(HostThunk::WicPaletteInitializeFromBitmap);
    methods.push(HostThunk::WicPaletteInitializeFromPalette);
    methods.push(HostThunk::WicPaletteGetType);
    methods.push(HostThunk::WicPaletteGetColorCount);
    methods.push(HostThunk::WicPaletteGetColors);
    methods.push(HostThunk::WicPaletteIsBlackWhite);
    methods.push(HostThunk::WicPaletteIsGrayscale);
    methods.push(HostThunk::WicPaletteHasAlpha);
    methods
}

#[allow(dead_code)] // the stream vtable builder
fn wic_stream_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicStreamInitializeFromIStream);
    methods.push(HostThunk::WicStreamInitializeFromFilename);
    methods.push(HostThunk::WicStreamInitializeFromMemory);
    methods.push(HostThunk::WicStreamInitializeFromIStreamRegion);
    methods
}

#[allow(dead_code)] // the color-context vtable builder
fn wic_color_context_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicColorContextInitializeFromFilename);
    methods.push(HostThunk::WicColorContextInitializeFromMemory);
    methods.push(HostThunk::WicColorContextGetProfileBytes);
    methods.push(HostThunk::WicColorContextGetType);
    methods.push(HostThunk::WicColorContextGetExifColorSpace);
    methods.push(HostThunk::WicColorContextSetExifColorSpace);
    methods
}

#[allow(dead_code)] // the component-info vtable builder
fn wic_component_info_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicComponentInfoGetComponentType);
    methods.push(HostThunk::WicComponentInfoGetClsid);
    methods.push(HostThunk::WicComponentInfoGetSigningStatus);
    methods.push(HostThunk::WicComponentInfoGetAuthor);
    methods.push(HostThunk::WicComponentInfoGetVendorGuid);
    methods.push(HostThunk::WicComponentInfoGetVersion);
    methods.push(HostThunk::WicComponentInfoGetSpecVersion);
    methods.push(HostThunk::WicComponentInfoGetFriendlyName);
    methods
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        Fixture, dispatch_x86, dispatch_x86_stack, with_big_stack, x86_fixture,
    };
    use super::*;

    const FACTORY_OUT: u64 = 0x41_000;
    const FORMAT: u64 = 0x41_100;
    const TEXELS: u64 = 0x41_200;
    const BITMAP_OUT: u64 = 0x41_300;
    const CONVERTER_OUT: u64 = 0x41_400;
    const PIXELS_OUT: u64 = 0x41_500;
    const PALETTE_OUT: u64 = 0x41_600;
    const COLORS_IN: u64 = 0x41_700;
    const COLORS_OUT: u64 = 0x41_800;
    const RESOLUTION_OUT: u64 = 0x41_900;
    const RECT: u64 = 0x41_a00;
    const APPLICATION_OUT: u64 = 0x41_b00;

    fn read_ptr(fixture: &Fixture, address: u64) -> u64 {
        read_guest_pointer(&fixture.memory, address, GuestArch::X86).unwrap()
    }

    /// Create the imaging factory and return its guest pointer.
    fn create_factory(fixture: &mut Fixture) -> u64 {
        fixture.memory.map_bytes(FACTORY_OUT, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::WicCreateImagingFactory,
                &[0, FACTORY_OUT as u32]
            ),
            0
        );
        let factory = read_ptr(fixture, FACTORY_OUT);
        assert_ne!(factory, 0);
        factory
    }

    /// Create a 2x2 BGRA bitmap with the four distinct test texels.
    fn create_test_bitmap(fixture: &mut Fixture, factory: u64) -> u64 {
        fixture
            .memory
            .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_32BPP_BGRA);
        fixture.memory.map_bytes(
            TEXELS,
            &[
                0, 0, 255, 255, // opaque red (BGRA)
                0, 255, 0, 128, // half-alpha green
                255, 0, 0, 255, // opaque blue
                40, 20, 10, 200, // arbitrary
            ],
        );
        fixture.memory.map_bytes(BITMAP_OUT, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::WicFactoryCreateBitmapFromMemory,
                &[
                    factory as u32,
                    2,
                    2,
                    FORMAT as u32,
                    8,
                    16,
                    TEXELS as u32,
                    0,
                    BITMAP_OUT as u32,
                ],
            ),
            0
        );
        read_ptr(fixture, BITMAP_OUT)
    }

    #[test]
    fn format_converter_translates_between_pixel_layouts() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-convert");
            let factory = create_factory(&mut fixture);
            let bitmap = create_test_bitmap(&mut fixture, factory);

            fixture.memory.map_bytes(CONVERTER_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateFormatConverter,
                    &[factory as u32, CONVERTER_OUT as u32]
                ),
                0
            );
            let converter = read_ptr(&fixture, CONVERTER_OUT);
            assert_ne!(converter, 0);

            // BGRA -> RGBA swaps the red and blue channels.
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_32BPP_RGBA);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFormatConverterInitialize,
                    &[converter as u32, bitmap as u32, FORMAT as u32, 0, 0, 0]
                ),
                0
            );
            fixture.memory.map_bytes(PIXELS_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceCopyPixels,
                    &[converter as u32, 0, 8, 16, PIXELS_OUT as u32]
                ),
                0
            );
            let rgba = fixture.memory.read_bytes(PIXELS_OUT, 16).unwrap();
            assert_eq!(&rgba[..4], &[255, 0, 0, 255], "BGRA red -> RGBA red");
            assert_eq!(&rgba[4..8], &[0, 255, 0, 128], "green preserved");

            // Swapping the converter's format to 24bpp BGR drops alpha.
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_24BPP_BGR);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFormatConverterSetPixelFormat,
                    &[converter as u32, FORMAT as u32]
                ),
                0
            );
            fixture.memory.map_bytes(PIXELS_OUT, &[0_u8; 12]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceCopyPixels,
                    &[converter as u32, 0, 6, 12, PIXELS_OUT as u32]
                ),
                0
            );
            let bgr = fixture.memory.read_bytes(PIXELS_OUT, 12).unwrap();
            assert_eq!(&bgr[..3], &[0, 0, 255], "first pixel is BGR red");
            assert_eq!(&bgr[3..6], &[0, 255, 0], "second pixel is BGR green");
        })
    }

    #[test]
    fn copy_pixels_rejects_out_of_bounds_and_empty_rectangles() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-rect");
            let factory = create_factory(&mut fixture);
            let bitmap = create_test_bitmap(&mut fixture, factory);

            fixture.memory.map_bytes(PIXELS_OUT, &[0_u8; 64]);
            let mut rect = Vec::new();
            for value in [0_i32, 0, 4, 4] {
                rect.extend_from_slice(&value.to_le_bytes());
            }
            fixture.memory.map_bytes(RECT, &rect);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceCopyPixels,
                    &[bitmap as u32, RECT as u32, 32, 64, PIXELS_OUT as u32]
                ),
                u64::from(E_INVALIDARG),
                "a rectangle beyond the source is rejected"
            );

            let mut empty = Vec::new();
            for value in [0_i32, 0, 0, 2] {
                empty.extend_from_slice(&value.to_le_bytes());
            }
            fixture.memory.map_bytes(RECT, &empty);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceCopyPixels,
                    &[bitmap as u32, RECT as u32, 8, 16, PIXELS_OUT as u32]
                ),
                u64::from(E_INVALIDARG),
                "an empty rectangle is rejected"
            );

            // A valid sub-rectangle succeeds and copies exactly its rows.
            let mut sub = Vec::new();
            for value in [1_i32, 0, 1, 2] {
                sub.extend_from_slice(&value.to_le_bytes());
            }
            fixture.memory.map_bytes(RECT, &sub);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceCopyPixels,
                    &[bitmap as u32, RECT as u32, 4, 8, PIXELS_OUT as u32]
                ),
                0
            );
            let column = fixture.memory.read_bytes(PIXELS_OUT, 8).unwrap();
            assert_eq!(&column[..4], &[0, 255, 0, 128], "second column pixel");
        })
    }

    #[test]
    fn predefined_palettes_carry_real_color_tables_and_flags() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-palette-predefined");
            let factory = create_factory(&mut fixture);
            fixture.memory.map_bytes(PALETTE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreatePalette,
                    &[factory as u32, PALETTE_OUT as u32]
                ),
                0
            );
            let palette = read_ptr(&fixture, PALETTE_OUT);

            // Fixed black-and-white.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteInitializePredefined,
                    &[palette as u32, WIC_PALETTE_TYPE_FIXED_BW, 0]
                ),
                0
            );
            fixture.memory.map_bytes(APPLICATION_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteGetColorCount,
                    &[palette as u32, APPLICATION_OUT as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, APPLICATION_OUT).unwrap(), 2);
            fixture.memory.map_bytes(COLORS_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteGetColors,
                    &[palette as u32, 2, COLORS_OUT as u32, 0]
                ),
                0
            );
            assert_eq!(
                read_guest_u32(&fixture.memory, COLORS_OUT).unwrap(),
                0xff00_0000
            );
            assert_eq!(
                read_guest_u32(&fixture.memory, COLORS_OUT + 4).unwrap(),
                0xffff_ffff
            );
            for (thunk, expected) in [
                (HostThunk::WicPaletteIsBlackWhite, 1),
                (HostThunk::WicPaletteIsGrayscale, 1),
                (HostThunk::WicPaletteHasAlpha, 0),
            ] {
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        thunk,
                        &[palette as u32, APPLICATION_OUT as u32]
                    ),
                    0
                );
                assert_eq!(
                    read_guest_u32(&fixture.memory, APPLICATION_OUT).unwrap(),
                    expected
                );
            }
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteGetType,
                    &[palette as u32, APPLICATION_OUT as u32]
                ),
                0
            );
            assert_eq!(
                read_guest_u32(&fixture.memory, APPLICATION_OUT).unwrap(),
                WIC_PALETTE_TYPE_FIXED_BW
            );

            // The fixed grayscale tables have their documented sizes.
            for (palette_type, expected) in [
                (WIC_PALETTE_TYPE_FIXED_GRAY4, 4),
                (WIC_PALETTE_TYPE_FIXED_GRAY16, 16),
                (WIC_PALETTE_TYPE_FIXED_GRAY256, 256),
            ] {
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::WicPaletteInitializePredefined,
                        &[palette as u32, palette_type, 0]
                    ),
                    0
                );
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::WicPaletteGetColorCount,
                        &[palette as u32, APPLICATION_OUT as u32]
                    ),
                    0
                );
                assert_eq!(
                    read_guest_u32(&fixture.memory, APPLICATION_OUT).unwrap(),
                    expected
                );
            }

            // An unsupported predefined table is the honest not-supported.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteInitializePredefined,
                    &[palette as u32, 7, 0]
                ),
                u64::from(WIC_E_NOTSUPPORTED)
            );

            // A custom palette with alpha reports the real flags.
            fixture
                .memory
                .map_bytes(COLORS_IN, &0x0011_2233_u32.to_le_bytes());
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteInitializeCustom,
                    &[palette as u32, COLORS_IN as u32, 1]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteHasAlpha,
                    &[palette as u32, APPLICATION_OUT as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, APPLICATION_OUT).unwrap(), 1);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteIsBlackWhite,
                    &[palette as u32, APPLICATION_OUT as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, APPLICATION_OUT).unwrap(), 0);
            // Zero colors and a null table are invalid.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteInitializeCustom,
                    &[palette as u32, COLORS_IN as u32, 0]
                ),
                u64::from(E_INVALIDARG)
            );
        })
    }

    #[test]
    fn palette_copy_chain_preserves_colors_and_type() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-palette-copy");
            let factory = create_factory(&mut fixture);
            fixture.memory.map_bytes(PALETTE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreatePalette,
                    &[factory as u32, PALETTE_OUT as u32]
                ),
                0
            );
            let source = read_ptr(&fixture, PALETTE_OUT);
            let mut colors = Vec::new();
            colors.extend_from_slice(&0x1122_3344_u32.to_le_bytes());
            colors.extend_from_slice(&0x5566_7788_u32.to_le_bytes());
            fixture.memory.map_bytes(COLORS_IN, &colors);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteInitializeCustom,
                    &[source as u32, COLORS_IN as u32, 2]
                ),
                0
            );

            fixture.memory.map_bytes(APPLICATION_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreatePalette,
                    &[factory as u32, APPLICATION_OUT as u32]
                ),
                0
            );
            let target = read_ptr(&fixture, APPLICATION_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteInitializeFromPalette,
                    &[target as u32, source as u32]
                ),
                0
            );
            fixture.memory.map_bytes(COLORS_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteGetColors,
                    &[target as u32, 2, COLORS_OUT as u32, 0]
                ),
                0
            );
            assert_eq!(
                read_guest_u32(&fixture.memory, COLORS_OUT).unwrap(),
                0x1122_3344
            );
            assert_eq!(
                read_guest_u32(&fixture.memory, COLORS_OUT + 4).unwrap(),
                0x5566_7788
            );

            // A bitmap without an indexed palette answers CopyPalette with an
            // empty palette, and a non-palette target is rejected.
            let bitmap = create_test_bitmap(&mut fixture, factory);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceCopyPalette,
                    &[bitmap as u32, target as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicPaletteGetColorCount,
                    &[target as u32, APPLICATION_OUT as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, APPLICATION_OUT).unwrap(), 0);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceCopyPalette,
                    &[bitmap as u32, bitmap as u32]
                ),
                u64::from(E_INVALIDARG)
            );
        })
    }

    #[test]
    fn bitmap_resolution_round_trips_and_propagates() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-resolution");
            let factory = create_factory(&mut fixture);
            let bitmap = create_test_bitmap(&mut fixture, factory);

            let mut stack = Vec::new();
            stack.extend_from_slice(&(bitmap as u32).to_le_bytes());
            // 8-byte aligned doubles on the x86 stack (4 bytes of padding
            // after the 32-bit method receiver).
            stack.extend_from_slice(&[0_u8; 4]);
            stack.extend_from_slice(&150.0_f64.to_le_bytes());
            stack.extend_from_slice(&300.0_f64.to_le_bytes());
            assert_eq!(
                dispatch_x86_stack(&mut fixture, HostThunk::WicBitmapSetResolution, &stack),
                0
            );

            fixture.memory.map_bytes(RESOLUTION_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetResolution,
                    &[
                        bitmap as u32,
                        RESOLUTION_OUT as u32,
                        (RESOLUTION_OUT + 8) as u32
                    ]
                ),
                0
            );
            let dpi_x = read_guest_f64(&fixture.memory, RESOLUTION_OUT).unwrap();
            let dpi_y = read_guest_f64(&fixture.memory, RESOLUTION_OUT + 8).unwrap();
            assert_eq!((dpi_x, dpi_y), (150.0, 300.0));

            // A non-positive resolution is invalid and leaves the stored one.
            let mut invalid = Vec::new();
            invalid.extend_from_slice(&(bitmap as u32).to_le_bytes());
            invalid.extend_from_slice(&[0_u8; 4]);
            invalid.extend_from_slice(&0.0_f64.to_le_bytes());
            invalid.extend_from_slice(&96.0_f64.to_le_bytes());
            assert_eq!(
                dispatch_x86_stack(&mut fixture, HostThunk::WicBitmapSetResolution, &invalid),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetResolution,
                    &[bitmap as u32, RESOLUTION_OUT as u32, 0]
                ),
                0
            );
            assert_eq!(
                read_guest_f64(&fixture.memory, RESOLUTION_OUT).unwrap(),
                150.0
            );

            // The transform chain reports the wrapped source's resolution.
            fixture.memory.map_bytes(APPLICATION_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateBitmapScaler,
                    &[factory as u32, APPLICATION_OUT as u32]
                ),
                0
            );
            let scaler = read_ptr(&fixture, APPLICATION_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicScalerInitialize,
                    &[scaler as u32, bitmap as u32, 1, 1, 0]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetResolution,
                    &[scaler as u32, RESOLUTION_OUT as u32, 0]
                ),
                0
            );
            assert_eq!(
                read_guest_f64(&fixture.memory, RESOLUTION_OUT).unwrap(),
                150.0
            );

            // An object that never had a resolution reports the 96 DPI default.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreatePalette,
                    &[factory as u32, APPLICATION_OUT as u32]
                ),
                0
            );
            let palette = read_ptr(&fixture, APPLICATION_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetResolution,
                    &[palette as u32, RESOLUTION_OUT as u32, 0]
                ),
                0
            );
            assert_eq!(
                read_guest_f64(&fixture.memory, RESOLUTION_OUT).unwrap(),
                WIC_DEFAULT_DPI
            );
        })
    }

    #[test]
    fn dont_care_is_not_a_concrete_pixel_format() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-dontcare");
            let factory = create_factory(&mut fixture);
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_DONT_CARE);
            fixture.memory.map_bytes(BITMAP_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateBitmap,
                    &[factory as u32, 2, 2, FORMAT as u32, 0, BITMAP_OUT as u32]
                ),
                u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT)
            );
        })
    }

    #[test]
    fn bitmap_set_palette_rejects_non_indexed_bitmaps() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-setpalette");
            let factory = create_factory(&mut fixture);
            let bitmap = create_test_bitmap(&mut fixture, factory);
            fixture.memory.map_bytes(PALETTE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreatePalette,
                    &[factory as u32, PALETTE_OUT as u32]
                ),
                0
            );
            let palette = read_ptr(&fixture, PALETTE_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapSetPalette,
                    &[bitmap as u32, palette as u32]
                ),
                u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapSetPalette,
                    &[bitmap as u32, bitmap as u32]
                ),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapSetPalette,
                    &[APPLICATION_OUT as u32, palette as u32]
                ),
                u64::from(WIC_E_INVALIDSTATE)
            );
        })
    }

    // ── Codec / lock tests ─────────────────────────────────────────────────

    const STREAM_OUT: u64 = 0x42_000;
    const DECODER_OUT: u64 = 0x42_100;
    const FRAME_OUT: u64 = 0x42_200;
    const CONTAINER_OUT: u64 = 0x42_300;
    const COUNT_OUT: u64 = 0x42_310;
    const ENCODER_OUT: u64 = 0x42_400;
    const LOCK_OUT: u64 = 0x42_600;
    const LOCK_SIZE_OUT: u64 = 0x42_610;
    const LOCK_STRIDE_OUT: u64 = 0x42_620;
    const LOCK_FORMAT_OUT: u64 = 0x42_630;
    const LOCK_DATA_OUT: u64 = 0x42_640;
    const FIXTURE_BYTES: u64 = 0x44_000;
    const ENCODE_BYTES: u64 = 0x45_000;
    const FRAME_PIXELS: u64 = 0x46_000;
    const RGBA_OUT: u64 = 0x47_000;

    /// A real 3x2 RGBA PNG (IHDR + pHYs + zlib IDAT + IEND, valid CRCs).
    const PNG_FIXTURE: &[u8] = &[
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x08, 0x06, 0x00, 0x00, 0x00, 0x9d,
        0x74, 0x66, 0x1a, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0e, 0xc4,
        0x00, 0x00, 0x0e, 0xc4, 0x01, 0x95, 0x2b, 0x0e, 0x1b, 0x00, 0x00, 0x00, 0x1f, 0x49, 0x44,
        0x41, 0x54, 0x78, 0xda, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0x08, 0x1b, 0x80, 0xd4, 0x7f,
        0x06, 0x2e, 0x11, 0x39, 0x0d, 0x23, 0x1b, 0xb7, 0x80, 0xa8, 0x94, 0xbc, 0x0a, 0x00, 0x76,
        0xf2, 0x08, 0x88, 0xa6, 0xd5, 0x2f, 0x44, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44,
        0xae, 0x42, 0x60, 0x82,
    ];

    /// A real baseline 8x8 4:2:0 JPEG (red/green/blue/white quadrants),
    /// exercising chroma upsampling.
    const JPEG_FIXTURE_HEX: &str = "ffd8ffe000104a46494600010100000100010000ffdb0043000d090a0b0a080d0b0a0b0e0e0d0f13201513121213271c1e17202e2931302e292d2c333a4a3e333646372c2d405741464c4e525352323e5a615a50604a51524fffdb0043010e0e0e131113261515264f352d354f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4fffc00011080008000803012200021101031101ffc4001500010100000000000000000000000000000001ffc4001f1000010303050000000000000000000000001112130406141523415171ffc4001501010100000000000000000000000000000203ffc4001f1100010304030100000000000000000000020103040021314105115161ffda000c03010002110311003f00966d1eaf99b90c4ce1caaef3a000f90811db9042236b6d7c4fb507990946af3c9d92e5718b6abfffd9";

    fn jpeg_fixture() -> Vec<u8> {
        let text = JPEG_FIXTURE_HEX.as_bytes();
        let mut bytes = Vec::with_capacity(text.len() / 2);
        for pair in text.chunks_exact(2) {
            bytes.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
        }
        bytes
    }

    fn create_stream(fixture: &mut Fixture, factory: u64, bytes: &[u8]) -> u64 {
        fixture.memory.map_bytes(STREAM_OUT, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::WicFactoryCreateStream,
                &[factory as u32, STREAM_OUT as u32]
            ),
            0
        );
        let stream = read_ptr(fixture, STREAM_OUT);
        assert_ne!(stream, 0);
        fixture.memory.map_bytes(FIXTURE_BYTES, bytes);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::WicStreamInitializeFromMemory,
                &[stream as u32, FIXTURE_BYTES as u32, bytes.len() as u32]
            ),
            0
        );
        stream
    }

    fn create_decoder_from_stream(fixture: &mut Fixture, factory: u64, stream: u64) -> (u64, u64) {
        fixture.memory.map_bytes(DECODER_OUT, &[0_u8; 8]);
        let hr = dispatch_x86(
            fixture,
            HostThunk::WicFactoryCreateDecoderFromStream,
            &[factory as u32, stream as u32, 0, DECODER_OUT as u32],
        );
        (hr, read_ptr(fixture, DECODER_OUT))
    }

    fn decode_first_frame(fixture: &mut Fixture, decoder: u64) -> u64 {
        fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::WicDecoderGetFrame,
                &[decoder as u32, 0, FRAME_OUT as u32]
            ),
            0
        );
        let frame = read_ptr(fixture, FRAME_OUT);
        assert_ne!(frame, 0);
        frame
    }

    fn copy_frame_pixels(fixture: &mut Fixture, frame: u64, width: u32, height: u32) -> Vec<u8> {
        fixture.memory.map_bytes(
            FRAME_PIXELS,
            &vec![0_u8; width as usize * height as usize * 4],
        );
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::WicSourceCopyPixels,
                &[
                    frame as u32,
                    0,
                    width * 4,
                    width * height * 4,
                    FRAME_PIXELS as u32
                ]
            ),
            0
        );
        fixture
            .memory
            .read_bytes(FRAME_PIXELS, width as usize * height as usize * 4)
            .unwrap()
    }

    #[test]
    fn bitmap_lock_commits_writes_and_invalidates() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-lock");
            let factory = create_factory(&mut fixture);
            let bitmap = create_test_bitmap(&mut fixture, factory);
            let mut rect = Vec::new();
            for value in [1_i32, 0, 1, 2] {
                rect.extend_from_slice(&value.to_le_bytes());
            }
            fixture.memory.map_bytes(RECT, &rect);
            fixture.memory.map_bytes(LOCK_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLock,
                    &[
                        bitmap as u32,
                        RECT as u32,
                        WIC_BITMAP_LOCK_WRITE,
                        LOCK_OUT as u32
                    ]
                ),
                0
            );
            let lock = read_ptr(&fixture, LOCK_OUT);
            assert_ne!(lock, 0);
            fixture.memory.map_bytes(LOCK_SIZE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLockGetSize,
                    &[
                        lock as u32,
                        LOCK_SIZE_OUT as u32,
                        (LOCK_SIZE_OUT + 4) as u32
                    ]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, LOCK_SIZE_OUT).unwrap(), 1);
            assert_eq!(
                read_guest_u32(&fixture.memory, LOCK_SIZE_OUT + 4).unwrap(),
                2
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLockGetStride,
                    &[lock as u32, LOCK_STRIDE_OUT as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, LOCK_STRIDE_OUT).unwrap(), 4);
            fixture.memory.map_bytes(LOCK_FORMAT_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLockGetPixelFormat,
                    &[lock as u32, LOCK_FORMAT_OUT as u32]
                ),
                0
            );
            assert_eq!(
                fixture.memory.read_bytes(LOCK_FORMAT_OUT, 16).unwrap(),
                GUID_PIXEL_FORMAT_32BPP_BGRA
            );
            fixture.memory.map_bytes(LOCK_DATA_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLockGetDataPointer,
                    &[lock as u32, LOCK_DATA_OUT as u32]
                ),
                0
            );
            let data = read_ptr(&fixture, LOCK_DATA_OUT);
            assert_ne!(data, 0);
            for (index, byte) in [9_u8, 8, 7, 6, 5, 4, 3, 2].iter().enumerate() {
                fixture.memory.write_u8(data + index as u64, *byte);
            }
            // A second write lock while the first is outstanding is denied.
            fixture.memory.map_bytes(LOCK_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLock,
                    &[
                        bitmap as u32,
                        RECT as u32,
                        WIC_BITMAP_LOCK_WRITE,
                        LOCK_OUT as u32
                    ]
                ),
                u64::from(WINCODEC_ERR_ACCESSDENIED)
            );
            assert_eq!(read_ptr(&fixture, LOCK_OUT), 0);
            // Unlock commits the guest writes into the bitmap.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapUnlock,
                    &[bitmap as u32, lock as u32]
                ),
                0
            );
            let pixels = copy_frame_pixels(&mut fixture, bitmap, 2, 2);
            assert_eq!(&pixels[..4], &[0, 0, 255, 255]);
            assert_eq!(&pixels[4..8], &[9, 8, 7, 6], "first row write committed");
            assert_eq!(&pixels[8..12], &[255, 0, 0, 255]);
            assert_eq!(&pixels[12..16], &[5, 4, 3, 2], "second row write committed");
            // The lock is invalid after Unlock, and a second Unlock fails.
            for thunk in [
                HostThunk::WicBitmapLockGetSize,
                HostThunk::WicBitmapLockGetStride,
                HostThunk::WicBitmapLockGetPixelFormat,
                HostThunk::WicBitmapLockGetDataPointer,
            ] {
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        thunk.clone(),
                        &[lock as u32, LOCK_DATA_OUT as u32]
                    ),
                    u64::from(WINCODEC_ERR_NOTINITIALIZED),
                    "{thunk:?}"
                );
            }
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapUnlock,
                    &[bitmap as u32, lock as u32]
                ),
                u64::from(WINCODEC_ERR_NOTINITIALIZED)
            );
            // Empty and out-of-bounds rectangles are invalid.
            let mut empty = Vec::new();
            for value in [0_i32, 0, 0, 1] {
                empty.extend_from_slice(&value.to_le_bytes());
            }
            fixture.memory.map_bytes(RECT, &empty);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLock,
                    &[
                        bitmap as u32,
                        RECT as u32,
                        WIC_BITMAP_LOCK_WRITE,
                        LOCK_OUT as u32
                    ]
                ),
                u64::from(E_INVALIDARG)
            );
            let mut outside = Vec::new();
            for value in [1_i32, 1, 2, 2] {
                outside.extend_from_slice(&value.to_le_bytes());
            }
            fixture.memory.map_bytes(RECT, &outside);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLock,
                    &[
                        bitmap as u32,
                        RECT as u32,
                        WIC_BITMAP_LOCK_WRITE,
                        LOCK_OUT as u32
                    ]
                ),
                u64::from(E_INVALIDARG)
            );
            let mut negative = Vec::new();
            for value in [-1_i32, 0, 1, 1] {
                negative.extend_from_slice(&value.to_le_bytes());
            }
            fixture.memory.map_bytes(RECT, &negative);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLock,
                    &[
                        bitmap as u32,
                        RECT as u32,
                        WIC_BITMAP_LOCK_READ,
                        LOCK_OUT as u32
                    ]
                ),
                u64::from(E_INVALIDARG)
            );
            // Zero lock flags are invalid; the null rect locks the full bitmap.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLock,
                    &[bitmap as u32, 0, 0, LOCK_OUT as u32]
                ),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLock,
                    &[bitmap as u32, 0, WIC_BITMAP_LOCK_READ, LOCK_OUT as u32]
                ),
                0
            );
            let full_lock = read_ptr(&fixture, LOCK_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapUnlock,
                    &[bitmap as u32, full_lock as u32]
                ),
                0
            );
        })
    }

    #[test]
    fn png_decoder_exposes_real_pixels_and_resolution() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-png-decode");
            let factory = create_factory(&mut fixture);
            let stream = create_stream(&mut fixture, factory, PNG_FIXTURE);
            let (hr, decoder) = create_decoder_from_stream(&mut fixture, factory, stream);
            assert_eq!(hr, 0, "CreateDecoderFromStream(PNG)");
            assert_ne!(decoder, 0);

            fixture.memory.map_bytes(CONTAINER_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicDecoderGetContainerFormat,
                    &[decoder as u32, CONTAINER_OUT as u32]
                ),
                0
            );
            assert_eq!(
                fixture.memory.read_bytes(CONTAINER_OUT, 16).unwrap(),
                GUID_CONTAINER_FORMAT_PNG
            );
            fixture.memory.map_bytes(COUNT_OUT, &[0_u8; 4]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicDecoderGetFrameCount,
                    &[decoder as u32, COUNT_OUT as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, COUNT_OUT).unwrap(), 1);
            // A missing frame index is the real frame-missing error.
            fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicDecoderGetFrame,
                    &[decoder as u32, 3, FRAME_OUT as u32]
                ),
                u64::from(WINCODEC_ERR_FRAMEMISSING)
            );
            assert_eq!(read_ptr(&fixture, FRAME_OUT), 0);

            let frame = decode_first_frame(&mut fixture, decoder);
            fixture.memory.map_bytes(LOCK_SIZE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetSize,
                    &[
                        frame as u32,
                        LOCK_SIZE_OUT as u32,
                        (LOCK_SIZE_OUT + 4) as u32
                    ]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, LOCK_SIZE_OUT).unwrap(), 3);
            assert_eq!(
                read_guest_u32(&fixture.memory, LOCK_SIZE_OUT + 4).unwrap(),
                2
            );
            fixture.memory.map_bytes(LOCK_FORMAT_OUT, &[0u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetPixelFormat,
                    &[frame as u32, LOCK_FORMAT_OUT as u32]
                ),
                0
            );
            assert_eq!(
                fixture.memory.read_bytes(LOCK_FORMAT_OUT, 16).unwrap(),
                GUID_PIXEL_FORMAT_32BPP_BGRA
            );
            fixture.memory.map_bytes(RESOLUTION_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetResolution,
                    &[
                        frame as u32,
                        RESOLUTION_OUT as u32,
                        (RESOLUTION_OUT + 8) as u32
                    ]
                ),
                0
            );
            let dpi_x = read_guest_f64(&fixture.memory, RESOLUTION_OUT).unwrap();
            let dpi_y = read_guest_f64(&fixture.memory, RESOLUTION_OUT + 8).unwrap();
            assert!((dpi_x - 96.012).abs() < 0.05, "PNG pHYs dpi_x {dpi_x}");
            assert!((dpi_y - 96.012).abs() < 0.05, "PNG pHYs dpi_y {dpi_y}");

            let pixels = copy_frame_pixels(&mut fixture, frame, 3, 2);
            let expected: [[u8; 4]; 6] = [
                [0, 0, 255, 255],
                [0, 255, 0, 128],
                [255, 0, 0, 255],
                [30, 20, 10, 40],
                [70, 60, 50, 80],
                [110, 100, 90, 120],
            ];
            for (index, pixel) in expected.iter().enumerate() {
                assert_eq!(
                    &pixels[index * 4..index * 4 + 4],
                    &pixel[..],
                    "pixel {index}"
                );
            }

            // EXIF-style SetPixelFormat conversion through the existing
            // format converter: BGRA -> RGBA.
            fixture.memory.map_bytes(CONVERTER_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateFormatConverter,
                    &[factory as u32, CONVERTER_OUT as u32]
                ),
                0
            );
            let converter = read_ptr(&fixture, CONVERTER_OUT);
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_32BPP_RGBA);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFormatConverterInitialize,
                    &[converter as u32, frame as u32, FORMAT as u32, 0, 0, 0]
                ),
                0
            );
            fixture.memory.map_bytes(RGBA_OUT, &[0_u8; 24]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceCopyPixels,
                    &[converter as u32, 0, 12, 24, RGBA_OUT as u32]
                ),
                0
            );
            let rgba = fixture.memory.read_bytes(RGBA_OUT, 24).unwrap();
            assert_eq!(&rgba[..4], &[255, 0, 0, 255]);
            assert_eq!(&rgba[4..8], &[0, 255, 0, 128]);
        })
    }

    #[test]
    fn jpeg_decoder_decodes_baseline_scan() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-jpeg-decode");
            let factory = create_factory(&mut fixture);
            let jpeg = jpeg_fixture();
            let stream = create_stream(&mut fixture, factory, &jpeg);
            let (hr, decoder) = create_decoder_from_stream(&mut fixture, factory, stream);
            assert_eq!(hr, 0, "CreateDecoderFromStream(JPEG)");
            assert_ne!(decoder, 0);
            fixture.memory.map_bytes(CONTAINER_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicDecoderGetContainerFormat,
                    &[decoder as u32, CONTAINER_OUT as u32]
                ),
                0
            );
            assert_eq!(
                fixture.memory.read_bytes(CONTAINER_OUT, 16).unwrap(),
                GUID_CONTAINER_FORMAT_JPEG
            );
            let frame = decode_first_frame(&mut fixture, decoder);
            let pixels = copy_frame_pixels(&mut fixture, frame, 8, 8);
            let pixel = |x: usize, y: usize| {
                let base = (y * 8 + x) * 4;
                (
                    pixels[base + 2],
                    pixels[base + 1],
                    pixels[base],
                    pixels[base + 3],
                )
            };
            let (red, green, blue, alpha) = pixel(1, 1);
            assert!(
                red > 180 && green < 80 && blue < 80,
                "red quadrant {red} {green} {blue}"
            );
            let (red, green, blue, _) = pixel(6, 1);
            assert!(
                green > 180 && red < 80 && blue < 80,
                "green quadrant {red} {green} {blue}"
            );
            let (red, green, blue, _) = pixel(1, 6);
            assert!(
                blue > 180 && red < 80 && green < 80,
                "blue quadrant {red} {green} {blue}"
            );
            let (red, green, blue, _) = pixel(6, 6);
            assert!(
                red > 200 && green > 200 && blue > 200,
                "white quadrant {red} {green} {blue}"
            );
            assert_eq!(alpha, 255, "decoded frames are opaque");
        })
    }

    #[test]
    fn png_encode_decode_round_trip_is_pixel_exact() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-png-encode");
            let factory = create_factory(&mut fixture);
            // The destination stream (starts empty).
            fixture.memory.map_bytes(STREAM_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateStream,
                    &[factory as u32, STREAM_OUT as u32]
                ),
                0
            );
            let stream = read_ptr(&mut fixture, STREAM_OUT);
            assert_ne!(stream, 0);
            // The PNG encoder.
            fixture.memory.map_bytes(FORMAT, &GUID_CONTAINER_FORMAT_PNG);
            fixture.memory.map_bytes(ENCODER_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateEncoder,
                    &[factory as u32, FORMAT as u32, ENCODER_OUT as u32]
                ),
                0
            );
            let encoder = read_ptr(&fixture, ENCODER_OUT);
            assert_ne!(encoder, 0);
            // CreateNewFrame before Initialize is a real state error.
            fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCreateNewFrame,
                    &[encoder as u32, FRAME_OUT as u32, 0]
                ),
                u64::from(WINCODEC_ERR_NOTINITIALIZED)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderInitialize,
                    &[encoder as u32, stream as u32, 0]
                ),
                0
            );
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_CONTAINER_FORMAT_JPEG);
            fixture.memory.map_bytes(ENCODER_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateEncoder,
                    &[factory as u32, FORMAT as u32, ENCODER_OUT as u32]
                ),
                u64::from(WINCODEC_ERR_COMPONENTNOTFOUND),
                "only the PNG encoder exists"
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCreateNewFrame,
                    &[encoder as u32, FRAME_OUT as u32, 0]
                ),
                0
            );
            let frame = read_ptr(&fixture, FRAME_OUT);
            assert_ne!(frame, 0);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeSetSize,
                    &[frame as u32, 3, 2]
                ),
                0
            );
            let mut resolution = Vec::new();
            resolution.extend_from_slice(&(frame as u32).to_le_bytes());
            resolution.extend_from_slice(&[0_u8; 4]);
            resolution.extend_from_slice(&144.0_f64.to_le_bytes());
            resolution.extend_from_slice(&72.0_f64.to_le_bytes());
            assert_eq!(
                dispatch_x86_stack(
                    &mut fixture,
                    HostThunk::WicFrameEncodeSetResolution,
                    &resolution
                ),
                0
            );
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_32BPP_BGRA);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeSetPixelFormat,
                    &[frame as u32, FORMAT as u32]
                ),
                0
            );
            let source: [u8; 24] = [
                0, 0, 255, 255, 0, 255, 0, 128, 255, 0, 0, 255, 10, 20, 30, 40, 50, 60, 70, 80, 90,
                100, 110, 120,
            ];
            fixture.memory.map_bytes(ENCODE_BYTES, &source);
            fixture.memory.map_bytes(ENCODE_BYTES + 12, &source[12..]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeWritePixels,
                    &[frame as u32, 1, 12, 12, ENCODE_BYTES as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeWritePixels,
                    &[frame as u32, 1, 12, 12, (ENCODE_BYTES + 12) as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeCommit,
                    &[frame as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::WicEncoderCommit, &[encoder as u32]),
                0
            );
            // The encoded stream is a real PNG.
            let encoded = fixture
                .runtime
                .wic
                .objects
                .get(&stream)
                .expect("destination stream")
                .stream
                .clone();
            assert!(encoded.starts_with(b"\x89PNG\r\n\x1a\n"), "PNG signature");
            assert!(encoded.windows(4).any(|window| window == b"IDAT"));
            assert!(encoded.windows(4).any(|window| window == b"IEND"));

            // Decode the produced bytes and compare pixels.
            let (hr, decoder) = create_decoder_from_stream(&mut fixture, factory, stream);
            assert_eq!(hr, 0, "round-trip decode");
            let decoded_frame = decode_first_frame(&mut fixture, decoder);
            let decoded = copy_frame_pixels(&mut fixture, decoded_frame, 3, 2);
            assert_eq!(&decoded[..], &source[..], "encode -> decode pixel equality");
            fixture.memory.map_bytes(RESOLUTION_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetResolution,
                    &[
                        decoded_frame as u32,
                        RESOLUTION_OUT as u32,
                        (RESOLUTION_OUT + 8) as u32
                    ]
                ),
                0
            );
            assert!((read_guest_f64(&fixture.memory, RESOLUTION_OUT).unwrap() - 144.0).abs() < 0.5);
            assert!(
                (read_guest_f64(&fixture.memory, RESOLUTION_OUT + 8).unwrap() - 72.0).abs() < 0.5
            );
            // A committed frame rejects a second write.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeWritePixels,
                    &[frame as u32, 1, 12, 12, ENCODE_BYTES as u32]
                ),
                u64::from(WINCODEC_ERR_NOTINITIALIZED)
            );
        })
    }

    #[test]
    fn malformed_images_and_wrong_format_access_fail_with_real_hrs() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-malformed");
            let factory = create_factory(&mut fixture);
            let bitmap = create_test_bitmap(&mut fixture, factory);

            // Truncated PNG (no IEND) and a corrupted chunk CRC.
            let stream = create_stream(
                &mut fixture,
                factory,
                &PNG_FIXTURE[..PNG_FIXTURE.len() - 12],
            );
            assert_eq!(
                create_decoder_from_stream(&mut fixture, factory, stream).0,
                u64::from(WINCODEC_ERR_BADIMAGE)
            );
            let mut corrupt = PNG_FIXTURE.to_vec();
            corrupt[70] ^= 0xff;
            let stream = create_stream(&mut fixture, factory, &corrupt);
            assert_eq!(
                create_decoder_from_stream(&mut fixture, factory, stream).0,
                u64::from(WINCODEC_ERR_BADIMAGE)
            );
            // Truncated JPEG and a progressive (unsupported) JPEG.
            let jpeg = jpeg_fixture();
            let stream = create_stream(&mut fixture, factory, &jpeg[..20]);
            assert_eq!(
                create_decoder_from_stream(&mut fixture, factory, stream).0,
                u64::from(WINCODEC_ERR_BADIMAGE)
            );
            let progressive = [
                0xff_u8, 0xd8, 0xff, 0xc2, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01,
                0x11, 0x00, 0xff, 0xd9,
            ];
            let stream = create_stream(&mut fixture, factory, &progressive);
            assert_eq!(
                create_decoder_from_stream(&mut fixture, factory, stream).0,
                u64::from(WINCODEC_ERR_UNSUPPORTEDOPERATION)
            );

            // A valid decoder, then wrong-format accesses.
            let stream = create_stream(&mut fixture, factory, PNG_FIXTURE);
            let (hr, decoder) = create_decoder_from_stream(&mut fixture, factory, stream);
            assert_eq!(hr, 0);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicDecoderGetFrame,
                    &[bitmap as u32, 0, FRAME_OUT as u32]
                ),
                u64::from(WINCODEC_ERR_NOTINITIALIZED),
                "GetFrame on a plain bitmap"
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::WicEncoderCommit, &[decoder as u32]),
                u64::from(WINCODEC_ERR_NOTINITIALIZED),
                "EncoderCommit on a decoder"
            );
            let frame = decode_first_frame(&mut fixture, decoder);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeSetSize,
                    &[frame as u32, 1, 1]
                ),
                u64::from(WINCODEC_ERR_NOTINITIALIZED),
                "FrameEncode on a decoded frame"
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicBitmapLockGetSize,
                    &[
                        bitmap as u32,
                        LOCK_SIZE_OUT as u32,
                        (LOCK_SIZE_OUT + 4) as u32
                    ]
                ),
                u64::from(WINCODEC_ERR_NOTINITIALIZED),
                "lock getter on a bitmap"
            );
            // Encoder pixel-format validation uses the real unsupported code.
            fixture.memory.map_bytes(FORMAT, &GUID_CONTAINER_FORMAT_PNG);
            fixture.memory.map_bytes(ENCODER_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateEncoder,
                    &[factory as u32, FORMAT as u32, ENCODER_OUT as u32]
                ),
                0
            );
            let encoder = read_ptr(&fixture, ENCODER_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderInitialize,
                    &[encoder as u32, stream as u32, 0]
                ),
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeSetSize,
                    &[encoder as u32, 1, 1]
                ),
                u64::from(WINCODEC_ERR_NOTINITIALIZED),
                "FrameEncode on an encoder object"
            );
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_DONT_CARE);
            fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCreateNewFrame,
                    &[encoder as u32, FRAME_OUT as u32, 0]
                ),
                0
            );
            let encode_frame = read_ptr(&fixture, FRAME_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeSetPixelFormat,
                    &[encode_frame as u32, FORMAT as u32]
                ),
                u64::from(WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT)
            );
        })
    }
}
