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
//! (palette/tRNS, 1/2/4/8/16-bit, Adam7) and baseline/progressive JPEG streams
//! into frame-decode objects, the encoder surface writes real PNG and baseline
//! JPEG files, and metadata query readers expose PNG text and JPEG EXIF tags.
//!
//! Layer contract: every export and method returns its HRESULT in EAX.

use super::super::*;
use super::unknown_preamble;
use crate::runtime::state::{GuestObjectKind, WicObjectKind, WicObjectState};
use std::collections::HashMap;
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
const WINCODEC_ERR_COMPRESSIONNOTSUPPORTED: u32 = 0x8898_2f8a;
const WINCODEC_ERR_UNSUPPORTEDPIXELFORMAT: u32 = 0x8898_2f8c;
const WINCODEC_ERR_PROPERTYNOTFOUND: u32 = 0x8898_2f90;

/// The IWICBitmapLock flags (WICBitmapLockRead / WICBitmapLockWrite).
const WIC_BITMAP_LOCK_READ: u32 = 1;
const WIC_BITMAP_LOCK_WRITE: u32 = 2;

/// The object-state magic tags (stored in slots the stream/bitmap objects
/// do not otherwise use, so no external state struct is needed).
const WIC_DECODER_MAGIC: &[u8; 8] = b"WICDEC01";
const WIC_ENCODER_MAGIC: &[u8; 8] = b"WICENC01";
const WIC_FRAME_ENCODE_MAGIC: u32 = 0x5749_4346;
const WIC_METADATA_READER_MAGIC: &[u8; 8] = b"WICMETA1";

/// GUID_ContainerFormatPng {1b7cfaf4-713f-473c-bbcd-6137425faeaf}
const GUID_CONTAINER_FORMAT_PNG: [u8; 16] = [
    0xf4, 0xaf, 0x7c, 0x1b, 0x3f, 0x71, 0x3c, 0x47, 0xbb, 0xcd, 0x61, 0x37, 0x42, 0x5f, 0xae, 0xaf,
];
/// GUID_ContainerFormatJpeg {19e4a5aa-5662-4fc5-a0c0-1758028e1057}
const GUID_CONTAINER_FORMAT_JPEG: [u8; 16] = [
    0xaa, 0xa5, 0xe4, 0x19, 0x62, 0x56, 0xc5, 0x4f, 0xa0, 0xc0, 0x17, 0x58, 0x02, 0x8e, 0x10, 0x57,
];
/// GUID_ContainerFormatGif {1f8a5601-7d4d-4cbd-9c82-1bc8d4eeb9a5}
const GUID_CONTAINER_FORMAT_GIF: [u8; 16] = [
    0x01, 0x56, 0x8a, 0x1f, 0x4d, 0x7d, 0xbd, 0x4c, 0x9c, 0x82, 0x1b, 0xc8, 0xd4, 0xee, 0xb9, 0xa5,
];
/// GUID_ContainerFormatTiff {163bcc30-e2e9-4f0b-961d-a3e9fdb788a3}
const GUID_CONTAINER_FORMAT_TIFF: [u8; 16] = [
    0x30, 0xcc, 0x3b, 0x16, 0xe9, 0xe2, 0x0b, 0x4f, 0x96, 0x1d, 0xa3, 0xe9, 0xfd, 0xb7, 0x88, 0xa3,
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
                self.wic_decoder_get_metadata_query_reader(state, memory)
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
            HostThunk::WicFrameEncodeUnsupported => self.wic_frame_get_thumbnail(state, memory),
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

    /// `WICGetMetadataContentSize(guidFormatType, pIUnknown, pcbSize)` and
    /// `IWICMetadataQueryReader::GetMetadataByName` (the reader overload).
    pub(crate) fn dispatch_wic_get_metadata_content_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if let Some(reader) = self
            .wic
            .objects
            .get(&this)
            .filter(|object| object.profile.starts_with(WIC_METADATA_READER_MAGIC))
        {
            let entries = wic_metadata_deserialize(&reader.profile);
            let name_pointer = guest_call_arg(state, memory, 1)?;
            let value_out = guest_call_arg(state, memory, 2)?;
            if value_out == 0 {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
            let name = read_utf16_string(memory, name_pointer).unwrap_or_default();
            let Some(value) = wic_metadata_lookup(&entries, &name) else {
                state.set(Register::Rax, u64::from(WINCODEC_ERR_PROPERTYNOTFOUND));
                return Ok(());
            };
            self.wic_write_propvariant_string(memory, value_out, &value)?;
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
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
    /// ppguidMetadataFormat)` and the reader's GetEnumerator overload.
    pub(crate) fn dispatch_wic_match_metadata_content(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if self
            .wic
            .objects
            .get(&this)
            .is_some_and(|object| object.profile.starts_with(WIC_METADATA_READER_MAGIC))
        {
            let out = guest_call_arg(state, memory, 1)?;
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
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
    /// guidMetadataFormat, pIUnknown, dwFlags, pIStream)` and the reader's
    /// GetLocation overload.
    pub(crate) fn dispatch_wic_serialize_metadata_content(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if self
            .wic
            .objects
            .get(&this)
            .is_some_and(|object| object.profile.starts_with(WIC_METADATA_READER_MAGIC))
        {
            let capacity = guest_call_arg_u32(state, memory, 1)?;
            let buffer = guest_call_arg(state, memory, 2)?;
            let actual = guest_call_arg(state, memory, 3)?;
            if buffer != 0 && capacity > 0 {
                write_utf16_string(memory, buffer, "", capacity as usize);
            }
            if actual != 0 {
                write_guest_u32(memory, actual, 0).ok();
            }
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
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
    /// pIUnknown, ppIEncoder)` — PNG and JPEG encoders.
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
        if container != GUID_CONTAINER_FORMAT_PNG
            && container != GUID_CONTAINER_FORMAT_JPEG
            && container != GUID_CONTAINER_FORMAT_GIF
            && container != GUID_CONTAINER_FORMAT_TIFF
        {
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
            let count = wic_image_frame_count(&decoder.stream).max(1);
            write_guest_u32(memory, out, count).ok();
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
        let image = match wic_decode_image_frame(&decoder.stream, index) {
            Ok(image) => image,
            Err(code) => {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(code));
                return Ok(());
            }
        };
        let frame =
            self.wic_alloc_object(memory, WicObjectKind::Bitmap, wic_frame_decode_methods())?;
        if frame == 0 {
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(frame_state) = self.wic.objects.get_mut(&frame) {
            frame_state.width = image.width;
            frame_state.height = image.height;
            frame_state.pixel_format = GUID_PIXEL_FORMAT_32BPP_BGRA;
            frame_state.pixels = image.pixels;
            frame_state.profile = wic_encode_dpi(image.dpi_x, image.dpi_y);
            frame_state.source = this;
            frame_state.component_type = image.codec;
        }
        self.wic_write_out(memory, out, frame);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// The container bytes and codec tag behind a decoder or a decode frame.
    fn wic_codec_source(&self, this: u64) -> Option<(Vec<u8>, u32, [u8; 16])> {
        let object = self.wic.objects.get(&this)?;
        if object.profile.starts_with(WIC_DECODER_MAGIC) {
            return Some((
                object.stream.clone(),
                object.component_type,
                object.pixel_format,
            ));
        }
        if object.kind == WicObjectKind::Bitmap {
            let source = self.wic.objects.get(&object.source)?;
            if source.profile.starts_with(WIC_DECODER_MAGIC) {
                return Some((
                    source.stream.clone(),
                    source.component_type,
                    source.pixel_format,
                ));
            }
        }
        None
    }

    /// `IWICBitmapDecoder::GetMetadataQueryReader` and the frame-decode
    /// counterpart: build a real reader over the container's text/EXIF tags.
    fn wic_decoder_get_metadata_query_reader(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some((bytes, codec, container)) = self.wic_codec_source(this) else {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(WIC_E_CODECNOTHANDLED));
            return Ok(());
        };
        let entries = wic_image_metadata_entries(&bytes, codec);
        let object = self.wic_alloc_object(
            memory,
            WicObjectKind::ComponentInfo,
            wic_metadata_reader_methods(),
        )?;
        if object == 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(reader) = self.wic.objects.get_mut(&object) {
            reader.pixel_format = container;
            reader.profile = wic_metadata_serialize(&entries);
            reader.component_type = 0x4d45_5441;
        }
        self.wic_write_out(memory, out, object);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `GetThumbnail` for decoders and frame-decode objects.  The embedded
    /// JPEG thumbnail from EXIF IFD1 (or a PNG eXIf chunk) is decoded into a
    /// real bitmap; absent thumbnails answer WINCODEC_ERR_CODECNOTHANDLED.
    fn wic_frame_get_thumbnail(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(object) = self.wic.objects.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        if object.component_type == WIC_FRAME_ENCODE_MAGIC
            || object.profile.starts_with(WIC_ENCODER_MAGIC)
        {
            state.set(Register::Rax, u64::from(WIC_E_NOTSUPPORTED));
            return Ok(());
        }
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some((bytes, codec, _)) = self.wic_codec_source(this) else {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(WIC_E_CODECNOTHANDLED));
            return Ok(());
        };
        let Some(thumbnail) = wic_image_thumbnail(&bytes, codec) else {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(WIC_E_CODECNOTHANDLED));
            return Ok(());
        };
        let image = match wic_decode_image(&thumbnail) {
            Ok(image) => image,
            Err(code) => {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(code));
                return Ok(());
            }
        };
        let bitmap = self.wic_alloc_object(memory, WicObjectKind::Bitmap, wic_bitmap_methods())?;
        if bitmap == 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            state.set(Register::Rax, 0x8007_000e);
            return Ok(());
        }
        if let Some(target) = self.wic.objects.get_mut(&bitmap) {
            target.width = image.width;
            target.height = image.height;
            target.pixels = image.pixels;
            target.pixel_format = GUID_PIXEL_FORMAT_32BPP_BGRA;
            target.profile = wic_encode_dpi(image.dpi_x, image.dpi_y);
            target.component_type = image.codec;
        }
        self.wic_write_out(memory, out, bitmap);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_write_propvariant_string(
        &mut self,
        memory: &mut MemoryImage,
        address: u64,
        text: &str,
    ) -> AppResult<()> {
        if address == 0 {
            return Ok(());
        }
        for offset in 0..24_u64 {
            memory.write_u8(address + offset, 0);
        }
        memory.write_u16(address, 31);
        let string = self.alloc_utf16_string(memory, text)?;
        write_guest_pointer(memory, address + 8, string, self.guest_arch).ok();
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
            encoder.profile = WIC_ENCODER_MAGIC.to_vec();
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
        let frames = wic_encoder_frames(&encoder.profile);
        let bytes = if frames.is_empty() {
            encoder.stream.clone()
        } else {
            let container = encoder.pixel_format;
            let width = frames[0].0;
            let height = frames[0].1;
            if frames
                .iter()
                .any(|(w, h, _, _)| *w != width || *h != height)
            {
                state.set(Register::Rax, u64::from(WINCODEC_ERR_BADIMAGE));
                return Ok(());
            }
            let encoded = match container {
                GUID_CONTAINER_FORMAT_GIF if frames.len() == 1 => {
                    wic_encode_gif(width, height, &frames[0].3)
                }
                GUID_CONTAINER_FORMAT_GIF => {
                    let animation: Vec<WicGifAnimationFrame<'_>> = frames
                        .iter()
                        .map(|(_, _, _, pixels)| WicGifAnimationFrame {
                            bgra: pixels,
                            delay_ms: 100,
                            disposal: 1,
                        })
                        .collect();
                    wic_encode_gif_animation(width, height, &animation, 0)
                }
                GUID_CONTAINER_FORMAT_TIFF if frames.len() == 1 => {
                    wic_encode_tiff(width, height, &frames[0].3, Some(frames[0].2))
                }
                GUID_CONTAINER_FORMAT_TIFF => {
                    let pages: Vec<WicTiffPage<'_>> = frames
                        .iter()
                        .map(|(w, h, dpi, pixels)| WicTiffPage {
                            width: *w,
                            height: *h,
                            bgra: pixels,
                            dpi: Some(*dpi),
                            description: None,
                            make: None,
                            model: None,
                            datetime: None,
                        })
                        .collect();
                    wic_encode_tiff_pages(&pages)
                }
                GUID_CONTAINER_FORMAT_JPEG => {
                    wic_encode_jpeg(width, height, &frames[0].3, Some(frames[0].2))
                }
                _ => wic_encode_png(width, height, &frames[0].3, Some(frames[0].2)),
            };
            match encoded {
                Ok(encoded) => encoded,
                Err(code) => {
                    state.set(Register::Rax, u64::from(code));
                    return Ok(());
                }
            }
        };
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
        let Some(encoder) = self.wic.objects.get_mut(&frame.source) else {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        };
        if !encoder.profile.starts_with(WIC_ENCODER_MAGIC) {
            state.set(Register::Rax, u64::from(WINCODEC_ERR_NOTINITIALIZED));
            return Ok(());
        }
        // Multi-frame encoders accumulate the committed frames; the actual
        // container bytes are produced by IWICBitmapEncoder::Commit, which
        // knows whether the stream is an animation (GIF) or multi-page TIFF.
        wic_encoder_append_frame(
            &mut encoder.profile,
            frame.width,
            frame.height,
            dpi.unwrap_or((WIC_DEFAULT_DPI, WIC_DEFAULT_DPI)),
            &frame.pixels[..expected],
        );
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
#[derive(Debug)]
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
    wic_decode_image_frame(bytes, 0)
}

/// Decode one frame of a container.  PNG/JPEG are single-frame; GIF and
/// TIFF enumerate their frames here.
fn wic_decode_image_frame(bytes: &[u8], index: u32) -> std::result::Result<WicDecodedImage, u32> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        if index != 0 {
            return Err(WINCODEC_ERR_FRAMEMISSING);
        }
        wic_decode_png(bytes)
    } else if bytes.starts_with(&[0xff, 0xd8]) {
        if index != 0 {
            return Err(WINCODEC_ERR_FRAMEMISSING);
        }
        wic_decode_jpeg(bytes)
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        wic_decode_gif_frame(bytes, index)
    } else if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        wic_decode_tiff_frame(bytes, index)
    } else {
        Err(WINCODEC_ERR_UNKNOWNIMAGEFORMAT)
    }
}

fn wic_image_frame_count(bytes: &[u8]) -> u32 {
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        wic_gif_parse(bytes)
            .map(|info| info.frames.len() as u32)
            .unwrap_or(0)
    } else if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        wic_tiff_frame_offsets(bytes).len() as u32
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") || bytes.starts_with(&[0xff, 0xd8]) {
        1
    } else {
        0
    }
}

// ── GIF decoder ───────────────────────────────────────────────────────────

struct WicGifFrame {
    width: u32,
    height: u32,
    left: u32,
    top: u32,
    disposal: u8,
    delay_ms: u32,
    /// Frame-local BGRA pixels; transparent palette indices carry alpha 0.
    pixels: Vec<u8>,
}

struct WicGifInfo {
    screen_width: u32,
    screen_height: u32,
    frames: Vec<WicGifFrame>,
    comments: Vec<String>,
    applications: Vec<(String, Vec<u8>)>,
}

/// Compose GIF frames onto the logical screen following the GIF89a
/// disposal methods: 0/1 leave the canvas, 2 clears the frame rectangle
/// back to the (transparent) background, and 3 restores the canvas state
/// from before the frame was drawn.  Transparent frame pixels never
/// overwrite the canvas.
fn wic_gif_compose_frames(info: &WicGifInfo) -> Vec<Vec<u8>> {
    let screen_width = info.screen_width as usize;
    let screen_height = info.screen_height as usize;
    let mut canvas = vec![0_u8; screen_width.saturating_mul(screen_height).saturating_mul(4)];
    let mut composed = Vec::with_capacity(info.frames.len());
    for frame in &info.frames {
        let previous = (frame.disposal == 3).then(|| canvas.clone());
        let frame_width = frame.width as usize;
        let frame_height = frame.height as usize;
        for row in 0..frame_height {
            let canvas_row = frame.top as usize + row;
            if canvas_row >= screen_height {
                break;
            }
            for col in 0..frame_width {
                let canvas_col = frame.left as usize + col;
                if canvas_col >= screen_width {
                    break;
                }
                let source = (row * frame_width + col) * 4;
                let destination = (canvas_row * screen_width + canvas_col) * 4;
                if frame.pixels.get(source + 3).copied().unwrap_or(0) == 0 {
                    // Transparent pixels never replace canvas content; on a
                    // still-empty canvas retain the frame's transparent RGB
                    // so a single decoded frame reports its own palette color.
                    if canvas.get(destination + 3).copied() == Some(0) {
                        if let (Some(pixel), Some(source_pixel)) = (
                            canvas.get_mut(destination..destination + 4),
                            frame.pixels.get(source..source + 4),
                        ) {
                            pixel.copy_from_slice(source_pixel);
                        }
                    }
                    continue;
                }
                if let Some(pixel) = canvas.get_mut(destination..destination + 4) {
                    pixel.copy_from_slice(&frame.pixels[source..source + 4]);
                }
            }
        }
        composed.push(canvas.clone());
        match frame.disposal {
            2 => {
                let left = (frame.left as usize).min(screen_width);
                let right = (frame.left as usize + frame_width).min(screen_width);
                for row in
                    frame.top as usize..(frame.top as usize + frame_height).min(screen_height)
                {
                    let start = (row * screen_width + left) * 4;
                    let end = (row * screen_width + right) * 4;
                    if let Some(region) = canvas.get_mut(start..end) {
                        region.fill(0);
                    }
                }
            }
            3 => {
                if let Some(previous) = previous {
                    canvas = previous;
                }
            }
            _ => {}
        }
    }
    composed
}

/// Read a GIF sub-block chain, returning its concatenated bytes.
fn wic_gif_subblocks(bytes: &[u8], position: &mut usize) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    loop {
        let length = *bytes.get(*position)? as usize;
        *position += 1;
        if length == 0 {
            return Some(data);
        }
        let end = position.checked_add(length)?;
        let block = bytes.get(*position..end)?;
        if data.len().saturating_add(block.len()) > 64 * 1024 * 1024 {
            return None;
        }
        data.extend_from_slice(block);
        *position = end;
    }
}

fn wic_gif_palette(bytes: &[u8], offset: usize, count: usize) -> Option<Vec<[u8; 3]>> {
    let end = offset.checked_add(count.checked_mul(3)?)?;
    let table = bytes.get(offset..end)?;
    Some(
        table
            .chunks_exact(3)
            .map(|entry| [entry[0], entry[1], entry[2]])
            .collect(),
    )
}

struct WicGifBits<'a> {
    data: &'a [u8],
    position: usize,
    accumulator: u32,
    bits: u32,
}

impl WicGifBits<'_> {
    fn new(data: &[u8]) -> WicGifBits<'_> {
        WicGifBits {
            data,
            position: 0,
            accumulator: 0,
            bits: 0,
        }
    }

    fn read(&mut self, width: u32) -> Option<u16> {
        while self.bits < width {
            let byte = *self.data.get(self.position)?;
            self.position += 1;
            self.accumulator |= u32::from(byte) << self.bits;
            self.bits += 8;
        }
        let value = self.accumulator & ((1 << width) - 1);
        self.accumulator >>= width;
        self.bits -= width;
        Some(value as u16)
    }
}

/// Decode a GIF LZW block (LSB-first codes) into at most `limit` indices.
fn wic_gif_lzw_decode(data: &[u8], min_code_size: u8, limit: usize) -> Option<Vec<u8>> {
    if !(1..=11).contains(&min_code_size) {
        return None;
    }
    let clear = 1_u16 << min_code_size;
    let end = clear + 1;
    let mut dictionary: Vec<Vec<u8>> = (0..=255_u16).map(|value| vec![value as u8]).collect();
    let mut next = end + 1;
    let mut code_size = u32::from(min_code_size) + 1;
    let mut previous: Option<Vec<u8>> = None;
    let mut out = Vec::new();
    let mut bits = WicGifBits::new(data);
    while out.len() < limit {
        let Some(code) = bits.read(code_size) else {
            break;
        };
        if code == clear {
            dictionary.truncate(256);
            next = end + 1;
            code_size = u32::from(min_code_size) + 1;
            previous = None;
            continue;
        }
        if code == end {
            break;
        }
        let entry = if code < next {
            dictionary.get(code as usize)?.clone()
        } else if code == next {
            let prefix = previous.as_ref()?;
            let mut entry = prefix.clone();
            entry.push(prefix[0]);
            entry
        } else {
            return None;
        };
        let remaining = limit.saturating_sub(out.len());
        out.extend_from_slice(&entry[..entry.len().min(remaining)]);
        if let Some(prefix) = previous {
            if next < 4096 {
                let mut added = prefix;
                added.push(entry[0]);
                if dictionary.len() <= next as usize {
                    dictionary.resize(next as usize + 1, Vec::new());
                }
                dictionary[next as usize] = added;
                next += 1;
                if next == (1 << code_size) && code_size < 12 {
                    code_size += 1;
                }
            }
        }
        previous = Some(entry);
    }
    Some(out)
}

fn wic_gif_deinterlace(indexed: &[u8], width: usize, height: usize) -> Option<Vec<u8>> {
    let mut out = vec![0_u8; width.checked_mul(height)?];
    let mut source = 0_usize;
    for (start, step) in [(0, 8), (4, 8), (2, 4), (1, 2)] {
        let mut row = start;
        while row < height {
            let end = source.checked_add(width)?;
            out.get_mut(row * width..row * width + width)?
                .copy_from_slice(indexed.get(source..end)?);
            source = end;
            row += step;
        }
    }
    (source == indexed.len()).then_some(out)
}

fn wic_gif_parse(bytes: &[u8]) -> std::result::Result<WicGifInfo, u32> {
    if bytes.len() < 13 || (!bytes.starts_with(b"GIF87a") && !bytes.starts_with(b"GIF89a")) {
        return Err(WINCODEC_ERR_UNKNOWNIMAGEFORMAT);
    }
    let read_u16 = |offset: usize| -> Option<u16> {
        bytes
            .get(offset..offset + 2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
    };
    let screen_width = read_u16(6).ok_or(WINCODEC_ERR_BADIMAGE)?;
    let screen_height = read_u16(8).ok_or(WINCODEC_ERR_BADIMAGE)?;
    let packed = *bytes.get(10).ok_or(WINCODEC_ERR_BADIMAGE)?;
    if screen_width == 0 || screen_height == 0 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let mut position = 13_usize;
    let global_palette = if packed & 0x80 != 0 {
        let count = 1_usize << (usize::from(packed & 0x07) + 1);
        let palette = wic_gif_palette(bytes, position, count).ok_or(WINCODEC_ERR_BADIMAGE)?;
        position += count * 3;
        Some(palette)
    } else {
        None
    };
    let mut transparent: Option<u8> = None;
    let mut disposal = 0_u8;
    let mut delay_ms = 0_u32;
    let mut comments = Vec::new();
    let mut applications = Vec::new();
    let mut frames = Vec::new();
    loop {
        let Some(&introducer) = bytes.get(position) else {
            break;
        };
        position += 1;
        match introducer {
            0x3b => break,
            0x21 => {
                let Some(&label) = bytes.get(position) else {
                    return Err(WINCODEC_ERR_BADIMAGE);
                };
                position += 1;
                match label {
                    0xf9 => {
                        let Some(&length) = bytes.get(position) else {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        };
                        if length != 4 {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        let block = bytes
                            .get(position + 1..position + 5)
                            .ok_or(WINCODEC_ERR_BADIMAGE)?;
                        let flags = block[0];
                        disposal = (flags >> 2) & 0x07;
                        delay_ms = u32::from(u16::from_le_bytes([block[1], block[2]])) * 10;
                        transparent = (flags & 1 != 0).then_some(block[3]);
                        position += 5;
                        if bytes.get(position).copied() != Some(0) {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        position += 1;
                    }
                    0xff => {
                        let Some(&length) = bytes.get(position) else {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        };
                        let identifier = bytes
                            .get(position + 1..position + 1 + length as usize)
                            .ok_or(WINCODEC_ERR_BADIMAGE)?;
                        let identifier = String::from_utf8_lossy(identifier)
                            .trim_end_matches('\0')
                            .to_string();
                        position += 1 + length as usize;
                        let data =
                            wic_gif_subblocks(bytes, &mut position).ok_or(WINCODEC_ERR_BADIMAGE)?;
                        applications.push((identifier, data));
                    }
                    0xfe => {
                        let data =
                            wic_gif_subblocks(bytes, &mut position).ok_or(WINCODEC_ERR_BADIMAGE)?;
                        comments.push(wic_latin1(&data));
                    }
                    _ => {
                        let _ =
                            wic_gif_subblocks(bytes, &mut position).ok_or(WINCODEC_ERR_BADIMAGE)?;
                    }
                }
            }
            0x2c => {
                let header = bytes
                    .get(position..position + 9)
                    .ok_or(WINCODEC_ERR_BADIMAGE)?;
                let left = u32::from(u16::from_le_bytes([header[0], header[1]]));
                let top = u32::from(u16::from_le_bytes([header[2], header[3]]));
                let width = u32::from(u16::from_le_bytes([header[4], header[5]]));
                let height = u32::from(u16::from_le_bytes([header[6], header[7]]));
                let flags = header[8];
                position += 9;
                if width == 0 || height == 0 || width > 1_000_000 || height > 1_000_000 {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                let local_palette = if flags & 0x80 != 0 {
                    let count = 1_usize << (usize::from(flags & 0x07) + 1);
                    let palette =
                        wic_gif_palette(bytes, position, count).ok_or(WINCODEC_ERR_BADIMAGE)?;
                    position += count * 3;
                    Some(palette)
                } else {
                    None
                };
                let Some(palette) = local_palette.as_ref().or(global_palette.as_ref()) else {
                    return Err(WINCODEC_ERR_BADIMAGE);
                };
                let Some(&min_code_size) = bytes.get(position) else {
                    return Err(WINCODEC_ERR_BADIMAGE);
                };
                position += 1;
                let data = wic_gif_subblocks(bytes, &mut position).ok_or(WINCODEC_ERR_BADIMAGE)?;
                let count = (width as usize)
                    .checked_mul(height as usize)
                    .ok_or(WINCODEC_ERR_BADIMAGE)?;
                if count > 64 * 1024 * 1024 {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                let mut indexed =
                    wic_gif_lzw_decode(&data, min_code_size, count).ok_or(WINCODEC_ERR_BADIMAGE)?;
                if indexed.len() < count {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                indexed.truncate(count);
                if flags & 0x40 != 0 {
                    indexed = wic_gif_deinterlace(&indexed, width as usize, height as usize)
                        .ok_or(WINCODEC_ERR_BADIMAGE)?;
                }
                let mut pixels = vec![0_u8; count * 4];
                for (pixel, &color_index) in indexed.iter().enumerate() {
                    let color = palette
                        .get(color_index as usize)
                        .copied()
                        .ok_or(WINCODEC_ERR_BADIMAGE)?;
                    let alpha = if transparent == Some(color_index) {
                        0
                    } else {
                        255
                    };
                    pixels[pixel * 4] = color[2];
                    pixels[pixel * 4 + 1] = color[1];
                    pixels[pixel * 4 + 2] = color[0];
                    pixels[pixel * 4 + 3] = alpha;
                }
                frames.push(WicGifFrame {
                    width,
                    height,
                    left,
                    top,
                    disposal,
                    delay_ms,
                    pixels,
                });
                delay_ms = 0;
                transparent = None;
                disposal = 0;
            }
            _ => return Err(WINCODEC_ERR_BADIMAGE),
        }
    }
    if frames.is_empty() {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    Ok(WicGifInfo {
        screen_width: u32::from(screen_width),
        screen_height: u32::from(screen_height),
        frames,
        comments,
        applications,
    })
}

fn wic_decode_gif_frame(bytes: &[u8], index: u32) -> std::result::Result<WicDecodedImage, u32> {
    let info = wic_gif_parse(bytes)?;
    if info.frames.get(index as usize).is_none() {
        return Err(WINCODEC_ERR_FRAMEMISSING);
    }
    // Frames are exposed composed onto the logical screen so GetFrame and
    // CopyPixels see canvas-sized pixels; WicGifFrame keeps the raw frame
    // descriptor size/offset for metadata.
    let composed = wic_gif_compose_frames(&info);
    let pixels = composed
        .get(index as usize)
        .cloned()
        .ok_or(WINCODEC_ERR_FRAMEMISSING)?;
    Ok(WicDecodedImage {
        width: info.screen_width,
        height: info.screen_height,
        pixels,
        container: GUID_CONTAINER_FORMAT_GIF,
        codec: 3,
        dpi_x: WIC_DEFAULT_DPI,
        dpi_y: WIC_DEFAULT_DPI,
    })
}

// ── TIFF decoder (baseline, strips/tiles, PackBits + LZW) ─────────────────

fn wic_tiff_header(bytes: &[u8]) -> Option<(bool, usize)> {
    if bytes.len() < 8 {
        return None;
    }
    let little = match &bytes[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    if wic_tiff_u16(bytes, 2, little)? != 42 {
        return None;
    }
    Some((little, wic_tiff_u32(bytes, 4, little)? as usize))
}

fn wic_tiff_frame_offsets(bytes: &[u8]) -> Vec<usize> {
    let Some((little, first)) = wic_tiff_header(bytes) else {
        return Vec::new();
    };
    let mut offsets = Vec::new();
    let mut ifd = first;
    while ifd != 0 && offsets.len() < 1024 && !offsets.contains(&ifd) {
        let Some((_, next)) = wic_tiff_ifd(bytes, ifd, little) else {
            break;
        };
        offsets.push(ifd);
        ifd = next;
    }
    offsets
}

fn wic_tiff_find(entries: &[WicTiffEntry], tag: u16) -> Option<&WicTiffEntry> {
    entries.iter().find(|entry| entry.tag == tag)
}

fn wic_tiff_values(bytes: &[u8], entry: &WicTiffEntry, little: bool) -> Vec<u32> {
    let Some(data) = wic_tiff_entry_data(bytes, entry, little) else {
        return Vec::new();
    };
    match entry.kind {
        3 => data
            .chunks_exact(2)
            .map(|pair| {
                if little {
                    u32::from(u16::from_le_bytes([pair[0], pair[1]]))
                } else {
                    u32::from(u16::from_be_bytes([pair[0], pair[1]]))
                }
            })
            .collect(),
        4 => data
            .chunks_exact(4)
            .map(|quad| {
                if little {
                    u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])
                } else {
                    u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]])
                }
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn wic_tiff_scalar(bytes: &[u8], entries: &[WicTiffEntry], tag: u16, little: bool) -> Option<u32> {
    wic_tiff_find(entries, tag)
        .and_then(|entry| wic_tiff_values(bytes, entry, little).first().copied())
}

fn wic_tiff_rational(
    bytes: &[u8],
    entries: &[WicTiffEntry],
    tag: u16,
    little: bool,
) -> Option<f64> {
    let entry = wic_tiff_find(entries, tag)?;
    if entry.kind != 5 {
        return None;
    }
    let data = wic_tiff_entry_data(bytes, entry, little)?;
    if data.len() < 8 {
        return None;
    }
    let numerator = wic_tiff_u32(data, 0, little)?;
    let denominator = wic_tiff_u32(data, 4, little)?;
    (denominator != 0).then(|| f64::from(numerator) / f64::from(denominator))
}

/// Decode a TIFF LZW strip/tile (MSB-first codes with early code-size change).
fn wic_tiff_lzw_decode(data: &[u8], expected: usize) -> Option<Vec<u8>> {
    let mut dictionary: Vec<Vec<u8>> = (0..=255_u16).map(|value| vec![value as u8]).collect();
    dictionary.resize(4096, Vec::new());
    let mut code_size = 9_u32;
    let mut next = 258_usize;
    let mut previous: Option<Vec<u8>> = None;
    let mut out = Vec::with_capacity(expected.min(data.len().saturating_mul(4)));
    let mut position = 0_usize;
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    loop {
        while bits < code_size {
            let byte = *data.get(position)?;
            position += 1;
            accumulator = (accumulator << 8) | u32::from(byte);
            bits += 8;
        }
        let code = ((accumulator >> (bits - code_size)) & ((1 << code_size) - 1)) as u16;
        bits -= code_size;
        if code == 256 {
            next = 258;
            code_size = 9;
            previous = None;
            continue;
        }
        if code == 257 {
            break;
        }
        let entry = if (code as usize) < next {
            dictionary.get(code as usize)?.clone()
        } else if code as usize == next {
            let prefix = previous.as_ref()?;
            let mut entry = prefix.clone();
            entry.push(prefix[0]);
            entry
        } else {
            return None;
        };
        let remaining = expected.saturating_sub(out.len());
        out.extend_from_slice(&entry[..entry.len().min(remaining)]);
        if out.len() >= expected {
            break;
        }
        if let Some(prefix) = previous {
            if next < 4096 {
                let mut added = prefix;
                added.push(entry[0]);
                dictionary[next] = added;
                next += 1;
                if next == (1 << code_size) - 1 && code_size < 12 {
                    code_size += 1;
                }
            }
        }
        previous = Some(entry);
    }
    Some(out)
}

fn wic_tiff_packbits_decode(data: &[u8], expected: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(expected.min(data.len().saturating_mul(128)));
    let mut position = 0_usize;
    while position < data.len() && out.len() < expected {
        let header = *data.get(position)? as i8;
        position += 1;
        match header {
            0..=127 => {
                let count = header as usize + 1;
                let end = position.checked_add(count)?;
                out.extend_from_slice(data.get(position..end)?);
                position = end;
            }
            -127..=-1 => {
                let count = 1 - i32::from(header);
                let value = *data.get(position)?;
                position += 1;
                out.extend(std::iter::repeat_n(value, count as usize));
            }
            _ => {}
        }
        if out.len() > expected {
            out.truncate(expected);
        }
    }
    Some(out)
}

fn wic_tiff_deflate_decode(data: &[u8], expected: usize) -> Option<Vec<u8>> {
    let limit = expected as u64 + 1;
    let mut out = Vec::with_capacity(expected.min(data.len().saturating_mul(8)));
    let mut decoder = flate2::read::ZlibDecoder::new(data).take(limit);
    if decoder.read_to_end(&mut out).is_ok() && out.len() == expected {
        return Some(out);
    }
    out.clear();
    let mut decoder = flate2::read::DeflateDecoder::new(data).take(limit);
    if decoder.read_to_end(&mut out).is_ok() && out.len() == expected {
        Some(out)
    } else {
        None
    }
}

fn wic_tiff_decompress(
    data: &[u8],
    compression: u32,
    expected: usize,
) -> std::result::Result<Vec<u8>, u32> {
    match compression {
        1 => Ok(data.to_vec()),
        5 => wic_tiff_lzw_decode(data, expected).ok_or(WINCODEC_ERR_BADIMAGE),
        8 | 32946 => wic_tiff_deflate_decode(data, expected).ok_or(WINCODEC_ERR_BADIMAGE),
        32773 => wic_tiff_packbits_decode(data, expected).ok_or(WINCODEC_ERR_BADIMAGE),
        _ => Err(WINCODEC_ERR_COMPRESSIONNOTSUPPORTED),
    }
}

/// Undo TIFF predictor 2 (horizontal differencing) in place for a strip or
/// tile.  Only 8- and 16-bit samples are meaningful for this predictor.
#[allow(clippy::too_many_arguments)]
fn wic_tiff_apply_predictor(
    data: &mut [u8],
    row_bytes: usize,
    width: usize,
    samples: usize,
    bits: u8,
    planar: bool,
    little: bool,
) -> bool {
    let row_samples = if planar {
        width
    } else {
        width.saturating_mul(samples)
    };
    if row_bytes == 0 || row_samples == 0 || data.len() < row_bytes {
        return false;
    }
    match bits {
        8 => {
            let step = if planar { 1 } else { samples };
            let step = step.min(row_samples);
            for row in data.chunks_mut(row_bytes) {
                if row.len() < row_samples {
                    return false;
                }
                for index in step..row_samples {
                    row[index] = row[index].wrapping_add(row[index - step]);
                }
            }
            true
        }
        16 => {
            let words_per_row = row_samples;
            for row in data.chunks_mut(row_bytes) {
                if row.len() < words_per_row * 2 {
                    return false;
                }
                let word = |row: &[u8], index: usize| -> u16 {
                    let pair = [row[index * 2], row[index * 2 + 1]];
                    if little {
                        u16::from_le_bytes(pair)
                    } else {
                        u16::from_be_bytes(pair)
                    }
                };
                let step = if planar {
                    1
                } else {
                    samples.min(words_per_row)
                };
                for index in step..words_per_row {
                    let value = word(row, index).wrapping_add(word(row, index - step));
                    let bytes = if little {
                        value.to_le_bytes()
                    } else {
                        value.to_be_bytes()
                    };
                    row[index * 2] = bytes[0];
                    row[index * 2 + 1] = bytes[1];
                }
            }
            true
        }
        _ => false,
    }
}

// ── CCITT Group 3 / Group 4 (T.4 / T.6) fax decoding ──────────────────────

type WicCcittCode = (u16, u8, u16);

const CCITT_WHITE_TERMINATING: [WicCcittCode; 64] = [
    (0b0011_0101, 8, 0),
    (0b0001_11, 6, 1),
    (0b0111, 4, 2),
    (0b1000, 4, 3),
    (0b1011, 4, 4),
    (0b1100, 4, 5),
    (0b1110, 4, 6),
    (0b1111, 4, 7),
    (0b1001_1, 5, 8),
    (0b1010_0, 5, 9),
    (0b0011_1, 5, 10),
    (0b0100_0, 5, 11),
    (0b0010_00, 6, 12),
    (0b0000_11, 6, 13),
    (0b1101_00, 6, 14),
    (0b1101_01, 6, 15),
    (0b1010_10, 6, 16),
    (0b1010_11, 6, 17),
    (0b0100_111, 7, 18),
    (0b0001_100, 7, 19),
    (0b0001_000, 7, 20),
    (0b0010_111, 7, 21),
    (0b0000_011, 7, 22),
    (0b0000_100, 7, 23),
    (0b0101_000, 7, 24),
    (0b0101_011, 7, 25),
    (0b0010_011, 7, 26),
    (0b0100_100, 7, 27),
    (0b0011_000, 7, 28),
    (0b0000_0010, 8, 29),
    (0b0000_0011, 8, 30),
    (0b0001_1010, 8, 31),
    (0b0001_1011, 8, 32),
    (0b0001_0010, 8, 33),
    (0b0001_0011, 8, 34),
    (0b0001_0100, 8, 35),
    (0b0001_0101, 8, 36),
    (0b0001_0110, 8, 37),
    (0b0001_0111, 8, 38),
    (0b0010_1000, 8, 39),
    (0b0010_1001, 8, 40),
    (0b0010_1010, 8, 41),
    (0b0010_1011, 8, 42),
    (0b0010_1100, 8, 43),
    (0b0010_1101, 8, 44),
    (0b0000_0100, 8, 45),
    (0b0000_0101, 8, 46),
    (0b0000_1010, 8, 47),
    (0b0000_1011, 8, 48),
    (0b0101_0010, 8, 49),
    (0b0101_0011, 8, 50),
    (0b0101_0100, 8, 51),
    (0b0101_0101, 8, 52),
    (0b0010_0100, 8, 53),
    (0b0010_0101, 8, 54),
    (0b0101_1000, 8, 55),
    (0b0101_1001, 8, 56),
    (0b0101_1010, 8, 57),
    (0b0101_1011, 8, 58),
    (0b0100_1010, 8, 59),
    (0b0100_1011, 8, 60),
    (0b0011_0010, 8, 61),
    (0b0011_0011, 8, 62),
    (0b0011_0100, 8, 63),
];

const CCITT_WHITE_MAKEUP: [WicCcittCode; 27] = [
    (0b1101_1, 5, 64),
    (0b1001_0, 5, 128),
    (0b0101_11, 6, 192),
    (0b0110_111, 7, 256),
    (0b0011_0110, 8, 320),
    (0b0011_0111, 8, 384),
    (0b0110_0100, 8, 448),
    (0b0110_0101, 8, 512),
    (0b0110_1000, 8, 576),
    (0b0110_0111, 8, 640),
    (0b0110_0110_0, 9, 704),
    (0b0110_0110_1, 9, 768),
    (0b0110_1001_0, 9, 832),
    (0b0110_1001_1, 9, 896),
    (0b0110_1010_0, 9, 960),
    (0b0110_1010_1, 9, 1024),
    (0b0110_1011_0, 9, 1088),
    (0b0110_1011_1, 9, 1152),
    (0b0110_1100_0, 9, 1216),
    (0b0110_1100_1, 9, 1280),
    (0b0110_1101_0, 9, 1344),
    (0b0110_1101_1, 9, 1408),
    (0b0100_1100_0, 9, 1472),
    (0b0100_1100_1, 9, 1536),
    (0b0100_1101_0, 9, 1600),
    (0b0110_00, 6, 1664),
    (0b0100_1101_1, 9, 1728),
];

const CCITT_BLACK_TERMINATING: [WicCcittCode; 64] = [
    (0b0000_1101_11, 10, 0),
    (0b010, 3, 1),
    (0b11, 2, 2),
    (0b10, 2, 3),
    (0b011, 3, 4),
    (0b0011, 4, 5),
    (0b0010, 4, 6),
    (0b0001_1, 5, 7),
    (0b0001_01, 6, 8),
    (0b0001_00, 6, 9),
    (0b0000_100, 7, 10),
    (0b0000_101, 7, 11),
    (0b0000_111, 7, 12),
    (0b0000_0100, 8, 13),
    (0b0000_0111, 8, 14),
    (0b0000_1100_0, 9, 15),
    (0b0000_0101_11, 10, 16),
    (0b0000_0110_00, 10, 17),
    (0b0000_0010_00, 10, 18),
    (0b0000_1100_111, 11, 19),
    (0b0000_1101_000, 11, 20),
    (0b0000_1101_100, 11, 21),
    (0b0000_0110_111, 11, 22),
    (0b0000_0101_000, 11, 23),
    (0b0000_0010_111, 11, 24),
    (0b0000_0011_000, 11, 25),
    (0b0000_1100_1010, 12, 26),
    (0b0000_1100_1011, 12, 27),
    (0b0000_1100_1100, 12, 28),
    (0b0000_1100_1101, 12, 29),
    (0b0000_0110_1000, 12, 30),
    (0b0000_0110_1001, 12, 31),
    (0b0000_0110_1010, 12, 32),
    (0b0000_0110_1011, 12, 33),
    (0b0000_1101_0010, 12, 34),
    (0b0000_1101_0011, 12, 35),
    (0b0000_1101_0100, 12, 36),
    (0b0000_1101_0101, 12, 37),
    (0b0000_1101_0110, 12, 38),
    (0b0000_1101_0111, 12, 39),
    (0b0000_0110_1100, 12, 40),
    (0b0000_0110_1101, 12, 41),
    (0b0000_1101_1010, 12, 42),
    (0b0000_1101_1011, 12, 43),
    (0b0000_0101_0100, 12, 44),
    (0b0000_0101_0101, 12, 45),
    (0b0000_0101_0110, 12, 46),
    (0b0000_0101_0111, 12, 47),
    (0b0000_0110_0100, 12, 48),
    (0b0000_0110_0101, 12, 49),
    (0b0000_0101_0010, 12, 50),
    (0b0000_0101_0011, 12, 51),
    (0b0000_0010_0100, 12, 52),
    (0b0000_0011_0111, 12, 53),
    (0b0000_0011_1000, 12, 54),
    (0b0000_0010_0111, 12, 55),
    (0b0000_0010_1000, 12, 56),
    (0b0000_0101_1000, 12, 57),
    (0b0000_0101_1001, 12, 58),
    (0b0000_0010_1011, 12, 59),
    (0b0000_0010_1100, 12, 60),
    (0b0000_0101_1010, 12, 61),
    (0b0000_0110_0110, 12, 62),
    (0b0000_0110_0111, 12, 63),
];

const CCITT_BLACK_MAKEUP: [WicCcittCode; 27] = [
    (0b0000_0011_11, 10, 64),
    (0b0000_1100_1000, 12, 128),
    (0b0000_1100_1001, 12, 192),
    (0b0000_0101_1011, 12, 256),
    (0b0000_0011_0011, 12, 320),
    (0b0000_0011_0100, 12, 384),
    (0b0000_0011_0101, 12, 448),
    (0b0000_0011_0110_0, 13, 512),
    (0b0000_0011_0110_1, 13, 576),
    (0b0000_0010_0101_0, 13, 640),
    (0b0000_0010_0101_1, 13, 704),
    (0b0000_0010_0110_0, 13, 768),
    (0b0000_0010_0110_1, 13, 832),
    (0b0000_0011_1001_0, 13, 896),
    (0b0000_0011_1001_1, 13, 960),
    (0b0000_0011_1010_0, 13, 1024),
    (0b0000_0011_1010_1, 13, 1088),
    (0b0000_0011_1011_0, 13, 1152),
    (0b0000_0011_1011_1, 13, 1216),
    (0b0000_0010_1001_0, 13, 1280),
    (0b0000_0010_1001_1, 13, 1344),
    (0b0000_0010_1010_0, 13, 1408),
    (0b0000_0010_1010_1, 13, 1472),
    (0b0000_0010_1101_0, 13, 1536),
    (0b0000_0010_1101_1, 13, 1600),
    (0b0000_0011_0010_0, 13, 1664),
    (0b0000_0011_0010_1, 13, 1728),
];

const CCITT_EXTENDED_MAKEUP: [WicCcittCode; 13] = [
    (0b0000_0001_000, 11, 1792),
    (0b0000_0001_100, 11, 1856),
    (0b0000_0001_101, 11, 1920),
    (0b0000_0001_0010, 12, 1984),
    (0b0000_0001_0011, 12, 2048),
    (0b0000_0001_0100, 12, 2112),
    (0b0000_0001_0101, 12, 2176),
    (0b0000_0001_0110, 12, 2240),
    (0b0000_0001_0111, 12, 2304),
    (0b0000_0001_1100, 12, 2368),
    (0b0000_0001_1101, 12, 2432),
    (0b0000_0001_1110, 12, 2496),
    (0b0000_0001_1111, 12, 2560),
];

struct WicCcittBits<'a> {
    data: &'a [u8],
    position: usize,
}

impl WicCcittBits<'_> {
    fn peek(&self, offset: usize) -> Option<bool> {
        let bit = self.position.checked_add(offset)?;
        let byte = *self.data.get(bit / 8)?;
        Some((byte >> (7 - (bit % 8))) & 1 == 1)
    }

    fn next(&mut self) -> Option<bool> {
        let value = self.peek(0)?;
        self.position += 1;
        Some(value)
    }
}

fn wic_ccitt_skip_eol(bits: &mut WicCcittBits<'_>) -> bool {
    let mut zeros = 0_usize;
    loop {
        match bits.peek(0) {
            Some(false) => {
                if zeros >= 32 {
                    return false;
                }
                bits.position += 1;
                zeros += 1;
            }
            Some(true) => {
                if zeros >= 11 {
                    bits.position += 1;
                    return true;
                }
                return false;
            }
            None => return false,
        }
    }
}

fn wic_ccitt_code(bits: &mut WicCcittBits<'_>, black: bool) -> Option<u16> {
    let mut code = 0_u16;
    for length in 1..=13_u8 {
        code = (code << 1) | u16::from(bits.next()?);
        let tables: [&[WicCcittCode]; 3] = if black {
            [
                &CCITT_BLACK_TERMINATING,
                &CCITT_BLACK_MAKEUP,
                &CCITT_EXTENDED_MAKEUP,
            ]
        } else {
            [
                &CCITT_WHITE_TERMINATING,
                &CCITT_WHITE_MAKEUP,
                &CCITT_EXTENDED_MAKEUP,
            ]
        };
        for table in tables {
            for &(candidate, candidate_length, run) in table {
                if candidate_length == length && candidate == code {
                    return Some(run);
                }
            }
        }
    }
    None
}

fn wic_ccitt_run(bits: &mut WicCcittBits<'_>, black: bool) -> Option<usize> {
    let mut run = 0_usize;
    for _ in 0..64 {
        let value = usize::from(wic_ccitt_code(bits, black)?);
        run = run.checked_add(value)?;
        if value < 64 {
            return Some(run);
        }
    }
    None
}

fn wic_ccitt_fill(row: &mut [bool], start: usize, end: usize, black: bool) -> bool {
    if start > end {
        return true;
    }
    if end >= row.len() {
        return false;
    }
    row[start..=end].fill(black);
    true
}

fn wic_ccitt_decode_1d(bits: &mut WicCcittBits<'_>, width: usize, row: &mut [bool]) -> Option<()> {
    let mut x = 0_usize;
    let mut black = false;
    let mut guard = 0_usize;
    while x < width {
        guard += 1;
        if guard > width.saturating_mul(2) + 64 {
            return None;
        }
        let run = wic_ccitt_run(bits, black)?;
        if run > width - x {
            return None;
        }
        row[x..x + run].fill(black);
        x += run;
        black = !black;
    }
    Some(())
}

fn wic_ccitt_reference_runs(row: &[bool]) -> Vec<(usize, bool)> {
    if row.is_empty() {
        return Vec::new();
    }
    let mut runs = Vec::new();
    let mut color = row[0];
    for (index, &pixel) in row.iter().enumerate().skip(1) {
        if pixel != color {
            runs.push((index - 1, color));
            color = pixel;
        }
    }
    runs.push((row.len() - 1, color));
    runs
}

enum WicCcittMode {
    Pass,
    Horizontal,
    Vertical(i32),
}

fn wic_ccitt_mode(bits: &mut WicCcittBits<'_>) -> Option<WicCcittMode> {
    let mut code = 0_u16;
    for length in 1..=7_u8 {
        code = (code << 1) | u16::from(bits.next()?);
        let mode = match (length, code) {
            (1, 0b1) => Some(WicCcittMode::Vertical(0)),
            (3, 0b001) => Some(WicCcittMode::Horizontal),
            (3, 0b010) => Some(WicCcittMode::Vertical(-1)),
            (3, 0b011) => Some(WicCcittMode::Vertical(1)),
            (4, 0b0001) => Some(WicCcittMode::Pass),
            (6, 0b000010) => Some(WicCcittMode::Vertical(-2)),
            (6, 0b000011) => Some(WicCcittMode::Vertical(2)),
            (7, 0b0000010) => Some(WicCcittMode::Vertical(-3)),
            (7, 0b0000011) => Some(WicCcittMode::Vertical(3)),
            _ => None,
        };
        if let Some(mode) = mode {
            return Some(mode);
        }
    }
    None
}

fn wic_ccitt_decode_2d(
    bits: &mut WicCcittBits<'_>,
    width: usize,
    reference: &[(usize, bool)],
    row: &mut [bool],
) -> Option<()> {
    let mut x = 0_usize;
    let mut black = false;
    let mut guard = 0_usize;
    while x < width {
        guard += 1;
        if guard > width.saturating_mul(4) + 64 {
            return None;
        }
        let mut index = 0_usize;
        while index < reference.len() && reference[index].0 < x {
            index += 1;
        }
        while index < reference.len() && reference[index].1 != black {
            index += 1;
        }
        let (b1, b2) = match reference.get(index) {
            Some((end, _)) => (
                *end,
                reference
                    .get(index + 1)
                    .map(|(next, _)| *next)
                    .unwrap_or(width.saturating_sub(1))
                    .max(*end),
            ),
            None => {
                // No run of the current color remains on the reference line:
                // treat the sentinel at the end of the line as b1/b2.
                let sentinel = width.saturating_sub(1);
                (sentinel, sentinel)
            }
        };
        match wic_ccitt_mode(bits)? {
            WicCcittMode::Pass => {
                if b2 >= width || !wic_ccitt_fill(row, x, b2, black) {
                    return None;
                }
                x = b2 + 1;
            }
            WicCcittMode::Vertical(delta) => {
                let a1 = b1 as i64 + i64::from(delta);
                if a1 < x as i64 - 1 || a1 >= width as i64 {
                    return None;
                }
                let a1 = a1 as usize;
                if a1 >= x && !wic_ccitt_fill(row, x, a1, black) {
                    return None;
                }
                x = a1 + 1;
                black = !black;
            }
            WicCcittMode::Horizontal => {
                let first = wic_ccitt_run(bits, black)?;
                let second = wic_ccitt_run(bits, !black)?;
                let a1 = x.checked_add(first)?;
                let a2 = a1.checked_add(second)?;
                if a2 > width {
                    return None;
                }
                if first > 0 && !wic_ccitt_fill(row, x, a1 - 1, black) {
                    return None;
                }
                if second > 0 && !wic_ccitt_fill(row, a1, a2 - 1, !black) {
                    return None;
                }
                x = a2;
            }
        }
    }
    Some(())
}

fn wic_ccitt_decode(
    data: &[u8],
    width: usize,
    rows: usize,
    compression: u32,
    photometric: u32,
) -> Option<Vec<u8>> {
    if width == 0 || rows == 0 {
        return None;
    }
    let row_bytes = width.div_ceil(8);
    let total = row_bytes.checked_mul(rows)?;
    let mut out = vec![0_u8; total.max(1)];
    let mut bits = WicCcittBits { data, position: 0 };
    let mut reference = vec![(width - 1, false)];
    let mut row = vec![false; width];
    for row_index in 0..rows {
        let mut one_dimensional = compression == 2 || (compression == 4 && row_index == 0);
        if compression == 2 || compression == 3 {
            let saved = bits.position;
            let had_eol = wic_ccitt_skip_eol(&mut bits);
            if !had_eol {
                bits.position = saved;
            }
            if compression == 3 {
                one_dimensional = if had_eol { bits.next()? } else { true };
            }
        }
        if one_dimensional {
            wic_ccitt_decode_1d(&mut bits, width, &mut row)?;
        } else {
            wic_ccitt_decode_2d(&mut bits, width, &reference, &mut row)?;
        }
        for (x, &black) in row.iter().enumerate() {
            let sample = if photometric == 0 { black } else { !black };
            if sample {
                out[row_index * row_bytes + x / 8] |= 0x80 >> (x % 8);
            }
        }
        reference = wic_ccitt_reference_runs(&row);
    }
    Some(out)
}

fn wic_tiff_bit(data: &[u8], bit: usize) -> Option<bool> {
    let byte = *data.get(bit / 8)?;
    Some((byte >> (7 - (bit % 8))) & 1 == 1)
}

fn wic_tiff_set_bit(data: &mut [u8], bit: usize, value: bool) -> bool {
    let Some(byte) = data.get_mut(bit / 8) else {
        return false;
    };
    let mask = 0x80 >> (bit % 8);
    if value {
        *byte |= mask;
    } else {
        *byte &= !mask;
    }
    true
}

/// Copy `pixels` packed samples of `bits` per pixel from one MSB-first packed
/// row to another; this is what makes sub-byte tiled depths work.
fn wic_tiff_copy_packed_row(
    destination: &mut [u8],
    mut destination_bit: usize,
    source: &[u8],
    mut source_bit: usize,
    bits: usize,
    pixels: usize,
) -> bool {
    for _ in 0..pixels {
        for _ in 0..bits {
            let Some(value) = wic_tiff_bit(source, source_bit) else {
                return false;
            };
            if !wic_tiff_set_bit(destination, destination_bit, value) {
                return false;
            }
            source_bit += 1;
            destination_bit += 1;
        }
    }
    true
}

fn wic_tiff_pixel_sample(row: &[u8], index: usize, bits: u8, little: bool) -> Option<u8> {
    match bits {
        8 => row.get(index).copied(),
        16 => {
            let pair = row.get(index * 2..index * 2 + 2)?;
            Some(if little { pair[1] } else { pair[0] })
        }
        1 | 2 | 4 => {
            let bit = index.checked_mul(usize::from(bits))?;
            let byte = *row.get(bit / 8)?;
            let shift = 8 - usize::from(bits) - (bit % 8);
            Some((byte >> shift) & ((1_u8 << bits) - 1))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn wic_tiff_to_bgra(
    planes: &[Vec<u8>],
    width: usize,
    height: usize,
    row_bytes: usize,
    bits: u8,
    samples: usize,
    photometric: u32,
    palette: &[u32],
    little: bool,
    planar: bool,
) -> std::result::Result<Vec<u8>, u32> {
    let mut pixels = vec![0_u8; width.checked_mul(height).ok_or(WINCODEC_ERR_BADIMAGE)? * 4];
    for row in 0..height {
        let source_start = row.checked_mul(row_bytes).ok_or(WINCODEC_ERR_BADIMAGE)?;
        for col in 0..width {
            let sample = |channel: usize| -> Option<u8> {
                let (plane, index) = if planar {
                    (channel, col)
                } else {
                    (0, col * samples + channel)
                };
                let data = planes.get(plane)?;
                let row_data = data.get(source_start..source_start + row_bytes)?;
                wic_tiff_pixel_sample(row_data, index, bits, little)
            };
            let (red, green, blue) = match photometric {
                2 => {
                    if samples < 3 || !matches!(bits, 8 | 16) {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    (
                        sample(0).ok_or(WINCODEC_ERR_BADIMAGE)?,
                        sample(1).ok_or(WINCODEC_ERR_BADIMAGE)?,
                        sample(2).ok_or(WINCODEC_ERR_BADIMAGE)?,
                    )
                }
                0 | 1 => {
                    if samples != 1 || !matches!(bits, 1 | 2 | 4 | 8 | 16) {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    let raw = sample(0).ok_or(WINCODEC_ERR_BADIMAGE)?;
                    let mut value = if matches!(bits, 1 | 2 | 4) {
                        let mask = (1_u16 << bits) - 1;
                        (u16::from(raw) * 255 / mask) as u8
                    } else {
                        raw
                    };
                    if photometric == 0 {
                        value = 255 - value;
                    }
                    (value, value, value)
                }
                3 => {
                    if samples != 1 || bits == 0 || bits > 8 {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    let index = usize::from(sample(0).ok_or(WINCODEC_ERR_BADIMAGE)?);
                    let entries = 1_usize << bits;
                    if palette.len() < entries * 3 {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    let scale = |value: u32| ((value * 255 + 32767) / 65535) as u8;
                    (
                        scale(palette[index]),
                        scale(palette[entries + index]),
                        scale(palette[entries * 2 + index]),
                    )
                }
                _ => return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION),
            };
            let destination = (row * width + col) * 4;
            pixels[destination] = blue;
            pixels[destination + 1] = green;
            pixels[destination + 2] = red;
            pixels[destination + 3] = 255;
        }
    }
    Ok(pixels)
}

fn wic_tiff_blit_bgra(
    decoded: &WicDecodedImage,
    destination: &mut [u8],
    canvas_width: usize,
    canvas_height: usize,
    x: usize,
    y: usize,
) -> bool {
    for row in 0..decoded.height as usize {
        let target_row = match y.checked_add(row) {
            Some(value) if value < canvas_height => value,
            _ => break,
        };
        for col in 0..decoded.width as usize {
            let target_col = match x.checked_add(col) {
                Some(value) if value < canvas_width => value,
                _ => break,
            };
            let source = (row * decoded.width as usize + col) * 4;
            let target = (target_row * canvas_width + target_col) * 4;
            destination[target..target + 4].copy_from_slice(&decoded.pixels[source..source + 4]);
        }
    }
    true
}

fn wic_decode_tiff_frame(bytes: &[u8], index: u32) -> std::result::Result<WicDecodedImage, u32> {
    let (little, _) = wic_tiff_header(bytes).ok_or(WINCODEC_ERR_UNKNOWNIMAGEFORMAT)?;
    let offsets = wic_tiff_frame_offsets(bytes);
    if offsets.is_empty() {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let ifd = *offsets
        .get(index as usize)
        .ok_or(WINCODEC_ERR_FRAMEMISSING)?;
    let (entries, _) = wic_tiff_ifd(bytes, ifd, little).ok_or(WINCODEC_ERR_BADIMAGE)?;
    let width = wic_tiff_scalar(bytes, &entries, 256, little).ok_or(WINCODEC_ERR_BADIMAGE)?;
    let height = wic_tiff_scalar(bytes, &entries, 257, little).ok_or(WINCODEC_ERR_BADIMAGE)?;
    if width == 0 || height == 0 || width > 1_000_000 || height > 1_000_000 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let width_usize = width as usize;
    let height_usize = height as usize;
    if width_usize.saturating_mul(height_usize) > 64 * 1024 * 1024 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let compression = wic_tiff_scalar(bytes, &entries, 259, little).unwrap_or(1);
    if !matches!(compression, 1 | 2 | 3 | 4 | 5 | 7 | 8 | 32773 | 32946) {
        return Err(WINCODEC_ERR_COMPRESSIONNOTSUPPORTED);
    }
    let predictor = wic_tiff_scalar(bytes, &entries, 317, little).unwrap_or(1);
    if !matches!(predictor, 1 | 2) {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
    }
    let planar = wic_tiff_scalar(bytes, &entries, 284, little).unwrap_or(1);
    if !matches!(planar, 1 | 2) {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
    }
    let mut samples = wic_tiff_scalar(bytes, &entries, 277, little).unwrap_or(1) as usize;
    if compression == 7 && samples < 3 {
        samples = 3;
    }
    if samples == 0 || samples > 8 {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
    }
    let photometric =
        wic_tiff_scalar(bytes, &entries, 262, little).unwrap_or(if samples >= 3 { 2 } else { 1 });
    if !matches!(photometric, 0 | 1 | 2 | 3 | 6) {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
    }
    if photometric == 6 && compression != 7 {
        return Err(WINCODEC_ERR_COMPRESSIONNOTSUPPORTED);
    }
    let bits_values = wic_tiff_find(&entries, 258)
        .map(|entry| wic_tiff_values(bytes, entry, little))
        .unwrap_or_default();
    let bits = bits_values
        .first()
        .copied()
        .unwrap_or(if compression == 7 { 8 } else { 1 }) as u8;
    if bits == 0 || bits > 16 || bits_values.iter().any(|value| *value as u8 != bits) {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
    }
    if compression == 7 {
        if planar != 1 || !matches!(bits, 8) || samples < 3 {
            return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
        }
    }
    if matches!(compression, 2 | 3 | 4)
        && (bits != 1 || samples != 1 || !matches!(photometric, 0 | 1))
    {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
    }
    let palette = wic_tiff_find(&entries, 320)
        .map(|entry| wic_tiff_values(bytes, entry, little))
        .unwrap_or_default();
    let packed = |pixels: usize| -> Option<usize> {
        pixels
            .checked_mul(usize::from(bits))
            .and_then(|value| value.checked_add(7))
            .map(|value| value / 8)
    };
    let row_bytes = match photometric {
        2 => {
            if !matches!(bits, 8 | 16) || samples < 3 {
                return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
            }
            width_usize
                .checked_mul(samples)
                .and_then(|value| value.checked_mul(usize::from(bits / 8)))
                .ok_or(WINCODEC_ERR_BADIMAGE)?
        }
        0 | 1 => {
            if samples != 1 || !matches!(bits, 1 | 2 | 4 | 8 | 16) {
                return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
            }
            packed(width_usize).ok_or(WINCODEC_ERR_BADIMAGE)?
        }
        3 => {
            if samples != 1 || !(1..=8).contains(&bits) {
                return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
            }
            if palette.len() < 3 * (1_usize << bits) {
                return Err(WINCODEC_ERR_BADIMAGE);
            }
            packed(width_usize).ok_or(WINCODEC_ERR_BADIMAGE)?
        }
        6 => width_usize
            .checked_mul(samples)
            .ok_or(WINCODEC_ERR_BADIMAGE)?,
        _ => unreachable!(), // coverage: unreachable — photometric is pre-validated to 0|1|2|3|6 at the guard above, so this wildcard arm cannot be selected.
    };
    let plane_count = if planar == 2 { samples } else { 1 };
    let plane_row_bytes = if planar == 2 {
        packed(width_usize).ok_or(WINCODEC_ERR_BADIMAGE)?
    } else {
        row_bytes
    };
    let plane_stride = plane_row_bytes
        .checked_mul(height_usize)
        .ok_or(WINCODEC_ERR_BADIMAGE)?;
    let mut jpeg_pixels: Option<Vec<u8>> = None;
    let mut planes = vec![vec![0_u8; plane_stride]; plane_count];
    let tile_width = wic_tiff_scalar(bytes, &entries, 322, little);
    let tile_length = wic_tiff_scalar(bytes, &entries, 323, little);
    if let (Some(tile_width), Some(tile_length)) = (tile_width, tile_length) {
        if tile_width == 0 || tile_length == 0 {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        let tile_width = tile_width as usize;
        let tile_length = tile_length as usize;
        let pixel_bits = if planar == 2 {
            usize::from(bits)
        } else {
            samples
                .checked_mul(usize::from(bits))
                .ok_or(WINCODEC_ERR_BADIMAGE)?
        };
        let tile_row_bytes = tile_width
            .checked_mul(pixel_bits)
            .and_then(|value| value.checked_add(7))
            .map(|value| value / 8)
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
        let expected_tile = tile_row_bytes
            .checked_mul(tile_length)
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
        let across = width_usize.div_ceil(tile_width);
        let down = height_usize.div_ceil(tile_length);
        let tile_offsets = wic_tiff_find(&entries, 324)
            .map(|entry| wic_tiff_values(bytes, entry, little))
            .unwrap_or_default();
        let tile_counts = wic_tiff_find(&entries, 325)
            .map(|entry| wic_tiff_values(bytes, entry, little))
            .unwrap_or_default();
        let chunks = across.checked_mul(down).ok_or(WINCODEC_ERR_BADIMAGE)?;
        if tile_offsets.len() < chunks * plane_count || tile_counts.len() < chunks * plane_count {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        if compression == 7 {
            jpeg_pixels = Some(vec![0_u8; width_usize * height_usize * 4]);
        }
        for plane in 0..plane_count {
            for chunk in 0..chunks {
                let tile = plane * chunks + chunk;
                let start = tile_offsets[tile] as usize;
                let length = tile_counts[tile] as usize;
                let end = start.checked_add(length).ok_or(WINCODEC_ERR_BADIMAGE)?;
                let source = bytes.get(start..end).ok_or(WINCODEC_ERR_BADIMAGE)?;
                let tile_x = (chunk % across) * tile_width;
                let tile_y = (chunk / across) * tile_length;
                if compression == 7 {
                    let decoded = wic_decode_jpeg(source)?;
                    let target = jpeg_pixels.as_mut().ok_or(WINCODEC_ERR_BADIMAGE)?;
                    wic_tiff_blit_bgra(&decoded, target, width_usize, height_usize, tile_x, tile_y);
                    continue;
                }
                let mut decoded = if matches!(compression, 2 | 3 | 4) {
                    wic_ccitt_decode(source, tile_width, tile_length, compression, photometric)
                        .ok_or(WINCODEC_ERR_BADIMAGE)?
                } else {
                    wic_tiff_decompress(source, compression, expected_tile)?
                };
                if decoded.len() < expected_tile {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                if predictor == 2
                    && !wic_tiff_apply_predictor(
                        &mut decoded[..expected_tile],
                        tile_row_bytes,
                        tile_width,
                        samples,
                        bits,
                        planar == 2,
                        little,
                    )
                {
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
                let destination = &mut planes[plane];
                let columns = tile_width.min(width_usize - tile_x);
                for row in 0..tile_length {
                    let destination_row = tile_y + row;
                    if destination_row >= height_usize {
                        break;
                    }
                    let source_start = row * tile_row_bytes;
                    let source_row = &decoded[source_start..source_start + tile_row_bytes];
                    let destination_start = destination_row * plane_row_bytes;
                    let destination_row = destination
                        .get_mut(destination_start..destination_start + plane_row_bytes)
                        .ok_or(WINCODEC_ERR_BADIMAGE)?;
                    let destination_bit = tile_x * pixel_bits;
                    if !wic_tiff_copy_packed_row(
                        destination_row,
                        destination_bit,
                        source_row,
                        0,
                        pixel_bits,
                        columns,
                    ) {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                }
            }
        }
    } else {
        let rows_per_strip = wic_tiff_scalar(bytes, &entries, 278, little)
            .map(|value| value as usize)
            .filter(|value| *value != 0)
            .unwrap_or(height_usize);
        let strip_offsets = wic_tiff_find(&entries, 273)
            .map(|entry| wic_tiff_values(bytes, entry, little))
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
        let strip_counts = wic_tiff_find(&entries, 279)
            .map(|entry| wic_tiff_values(bytes, entry, little))
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
        let strips = height_usize.div_ceil(rows_per_strip);
        if strip_offsets.len() < strips * plane_count || strip_counts.len() < strips * plane_count {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        if compression == 7 {
            jpeg_pixels = Some(vec![0_u8; width_usize * height_usize * 4]);
        }
        for plane in 0..plane_count {
            for strip in 0..strips {
                let entry = plane * strips + strip;
                let start = strip_offsets[entry] as usize;
                let length = strip_counts[entry] as usize;
                let end = start.checked_add(length).ok_or(WINCODEC_ERR_BADIMAGE)?;
                let source = bytes.get(start..end).ok_or(WINCODEC_ERR_BADIMAGE)?;
                let rows = rows_per_strip.min(height_usize - strip * rows_per_strip);
                let expected = plane_row_bytes
                    .checked_mul(rows)
                    .ok_or(WINCODEC_ERR_BADIMAGE)?;
                if compression == 7 {
                    let decoded = wic_decode_jpeg(source)?;
                    let target = jpeg_pixels.as_mut().ok_or(WINCODEC_ERR_BADIMAGE)?;
                    wic_tiff_blit_bgra(
                        &decoded,
                        target,
                        width_usize,
                        height_usize,
                        0,
                        strip * rows_per_strip,
                    );
                    continue;
                }
                let mut decoded = if matches!(compression, 2 | 3 | 4) {
                    wic_ccitt_decode(source, width_usize, rows, compression, photometric)
                        .ok_or(WINCODEC_ERR_BADIMAGE)?
                } else {
                    wic_tiff_decompress(source, compression, expected)?
                };
                if decoded.len() < expected {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                if predictor == 2
                    && !wic_tiff_apply_predictor(
                        &mut decoded[..expected],
                        plane_row_bytes,
                        width_usize,
                        samples,
                        bits,
                        planar == 2,
                        little,
                    )
                {
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
                let destination = strip * rows_per_strip * plane_row_bytes;
                let target = planes
                    .get_mut(plane)
                    .ok_or(WINCODEC_ERR_BADIMAGE)?
                    .get_mut(destination..destination + expected)
                    .ok_or(WINCODEC_ERR_BADIMAGE)?;
                target.copy_from_slice(&decoded[..expected]);
            }
        }
    }
    let pixels = if let Some(pixels) = jpeg_pixels {
        pixels
    } else {
        wic_tiff_to_bgra(
            &planes,
            width_usize,
            height_usize,
            plane_row_bytes,
            bits,
            samples,
            photometric,
            &palette,
            little,
            planar == 2,
        )? // coverage: unreachable — wic_decode_tiff_frame has already validated photometric/bits/samples and allocated every plane to plane_stride, so wic_tiff_to_bgra cannot fail here.
    };
    let mut dpi_x = wic_tiff_rational(bytes, &entries, 282, little).unwrap_or(WIC_DEFAULT_DPI);
    let mut dpi_y = wic_tiff_rational(bytes, &entries, 283, little).unwrap_or(WIC_DEFAULT_DPI);
    if wic_tiff_scalar(bytes, &entries, 296, little) == Some(3) {
        dpi_x *= 2.54;
        dpi_y *= 2.54;
    }
    if !dpi_x.is_finite() || dpi_x <= 0.0 {
        dpi_x = WIC_DEFAULT_DPI;
    }
    if !dpi_y.is_finite() || dpi_y <= 0.0 {
        dpi_y = WIC_DEFAULT_DPI;
    }
    Ok(WicDecodedImage {
        width,
        height,
        pixels,
        container: GUID_CONTAINER_FORMAT_TIFF,
        codec: 4,
        dpi_x,
        dpi_y,
    })
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
    const ADAM7: [(usize, usize, usize, usize); 7] = [
        (0, 0, 8, 8),
        (4, 0, 8, 8),
        (0, 4, 4, 8),
        (2, 0, 4, 4),
        (0, 2, 2, 4),
        (1, 0, 2, 2),
        (0, 1, 1, 2),
    ];
    if bytes.len() < 8 || &bytes[..8] != SIGNATURE {
        return Err(WINCODEC_ERR_UNKNOWNIMAGEFORMAT);
    }
    let mut position = 8_usize;
    let mut width = 0_u32;
    let mut height = 0_u32;
    let mut color_type = 0_u8;
    let mut bit_depth = 0_u8;
    let mut interlace = 0_u8;
    let mut seen_header = false;
    let mut seen_end = false;
    let mut seen_idat = false;
    let mut idat = Vec::new();
    let mut palette: Vec<[u8; 4]> = Vec::new();
    let mut transparency: Vec<u8> = Vec::new();
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
                bit_depth = data[8];
                color_type = data[9];
                let compression = data[10];
                let filter = data[11];
                interlace = data[12];
                if width == 0
                    || height == 0
                    || width > 1_000_000
                    || height > 1_000_000
                    || compression != 0
                    || filter != 0
                    || interlace > 1
                {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                let depth_ok = match color_type {
                    0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
                    2 | 4 | 6 => matches!(bit_depth, 8 | 16),
                    3 => matches!(bit_depth, 1 | 2 | 4 | 8),
                    _ => false,
                };
                if !depth_ok {
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
            }
            b"PLTE" => {
                if !seen_header || seen_idat || !palette.is_empty() {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                if matches!(color_type, 0 | 4)
                    || length == 0
                    || length % 3 != 0
                    || length / 3 > WIC_PALETTE_MAX_COLORS as usize
                {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                for color in data.chunks_exact(3) {
                    palette.push([color[0], color[1], color[2], 255]);
                }
            }
            b"tRNS" => {
                if !seen_header || seen_idat || !transparency.is_empty() {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                match color_type {
                    3 => {
                        if palette.is_empty() || length == 0 || length > palette.len() {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        transparency = data.to_vec();
                    }
                    0 => {
                        if length != 2 {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        transparency = data.to_vec();
                    }
                    2 => {
                        if length != 6 {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        transparency = data.to_vec();
                    }
                    _ => return Err(WINCODEC_ERR_BADIMAGE),
                }
            }
            b"IDAT" => {
                if !seen_header {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                seen_idat = true;
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
    if color_type == 3 && (palette.is_empty() || palette.len() > WIC_PALETTE_MAX_COLORS as usize) {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let channels = match color_type {
        0 => 1_usize,
        2 => 3,
        3 => 1,
        4 => 2,
        6 => 4,
        _ => return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION), // coverage: unreachable — the IHDR depth_ok match rejects every color_type outside {0,2,3,4,6} before this re-match.
    };
    let pixel_bytes = (width as usize)
        .checked_mul(height as usize)
        .and_then(|value| value.checked_mul(4))
        .ok_or(WINCODEC_ERR_BADIMAGE)?;
    if pixel_bytes > 256 * 1024 * 1024 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let bits_per_pixel = channels
        .checked_mul(bit_depth as usize)
        .ok_or(WINCODEC_ERR_BADIMAGE)?;
    let filter_bytes = bits_per_pixel.div_ceil(8).max(1);
    let passes: &[(usize, usize, usize, usize)] = if interlace == 1 {
        &ADAM7
    } else {
        &[(0, 0, 1, 1)]
    };
    let mut expected = 0_usize;
    for &(start_x, start_y, step_x, step_y) in passes {
        let pass_width = if (width as usize) > start_x {
            (width as usize - start_x).div_ceil(step_x)
        } else {
            0
        };
        let pass_height = if (height as usize) > start_y {
            (height as usize - start_y).div_ceil(step_y)
        } else {
            0
        };
        if pass_width == 0 || pass_height == 0 {
            continue;
        }
        let row_len = pass_width
            .checked_mul(bits_per_pixel)
            .and_then(|value| value.checked_add(7))
            .map(|value| value / 8)
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
        expected = expected
            .checked_add(
                row_len
                    .checked_add(1)
                    .and_then(|value| value.checked_mul(pass_height))
                    .ok_or(WINCODEC_ERR_BADIMAGE)?,
            )
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
    }
    if expected > 512 * 1024 * 1024 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
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
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    let mut cursor = 0_usize;
    for &(start_x, start_y, step_x, step_y) in passes {
        let pass_width = if (width as usize) > start_x {
            (width as usize - start_x).div_ceil(step_x)
        } else {
            0
        };
        let pass_height = if (height as usize) > start_y {
            (height as usize - start_y).div_ceil(step_y)
        } else {
            0
        };
        if pass_width == 0 || pass_height == 0 {
            continue;
        }
        let row_len = (pass_width * bits_per_pixel).div_ceil(8);
        let mut previous = vec![0_u8; row_len];
        let mut current = vec![0_u8; row_len];
        for row in 0..pass_height {
            let filter = raw[cursor];
            let source = &raw[cursor + 1..cursor + 1 + row_len];
            cursor += row_len + 1;
            current.copy_from_slice(source);
            for index in 0..row_len {
                let left = if index >= filter_bytes {
                    current[index - filter_bytes]
                } else {
                    0
                };
                let up = previous[index];
                let up_left = if index >= filter_bytes {
                    previous[index - filter_bytes]
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
            for column in 0..pass_width {
                let mut samples = [0_u16; 4];
                for (channel, sample) in samples.iter_mut().enumerate().take(channels) {
                    *sample = wic_png_sample(&current, column * channels + channel, bit_depth);
                }
                let pixel = match color_type {
                    0 => {
                        let gray = wic_png_scale8(samples[0], bit_depth);
                        let alpha = if transparency.len() == 2
                            && samples[0] == u16::from_be_bytes([transparency[0], transparency[1]])
                        {
                            0
                        } else {
                            255
                        };
                        [gray, gray, gray, alpha]
                    }
                    2 => {
                        let transparent = transparency.len() == 6
                            && samples[0] == u16::from_be_bytes([transparency[0], transparency[1]])
                            && samples[1] == u16::from_be_bytes([transparency[2], transparency[3]])
                            && samples[2] == u16::from_be_bytes([transparency[4], transparency[5]]);
                        [
                            wic_png_scale8(samples[2], bit_depth),
                            wic_png_scale8(samples[1], bit_depth),
                            wic_png_scale8(samples[0], bit_depth),
                            if transparent { 0 } else { 255 },
                        ]
                    }
                    3 => {
                        let Some(color) = palette.get(samples[0] as usize) else {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        };
                        [
                            color[2],
                            color[1],
                            color[0],
                            transparency
                                .get(samples[0] as usize)
                                .copied()
                                .unwrap_or(255),
                        ]
                    }
                    4 => {
                        let gray = wic_png_scale8(samples[0], bit_depth);
                        [gray, gray, gray, wic_png_scale8(samples[1], bit_depth)]
                    }
                    _ => [
                        wic_png_scale8(samples[2], bit_depth),
                        wic_png_scale8(samples[1], bit_depth),
                        wic_png_scale8(samples[0], bit_depth),
                        wic_png_scale8(samples[3], bit_depth),
                    ],
                };
                let x = start_x + column * step_x;
                let y = start_y + row * step_y;
                let destination = (y * width as usize + x) * 4;
                pixels[destination..destination + 4].copy_from_slice(&pixel);
            }
            std::mem::swap(&mut previous, &mut current);
        }
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

/// Extract one native-depth sample from a packed PNG scanline.
fn wic_png_sample(row: &[u8], index: usize, depth: u8) -> u16 {
    match depth {
        8 => u16::from(row[index]),
        16 => u16::from_be_bytes([row[index * 2], row[index * 2 + 1]]),
        _ => {
            let bit = index * depth as usize;
            let shift = 8 - depth as usize - (bit % 8);
            u16::from((row[bit / 8] >> shift) & ((1_u8 << depth) - 1))
        }
    }
}

/// Scale a native-depth PNG sample to 8 bits (16-bit keeps the high byte).
fn wic_png_scale8(value: u16, depth: u8) -> u8 {
    match depth {
        16 => (value >> 8) as u8,
        8 => value as u8,
        _ => {
            let maximum = u32::from((1_u16 << depth) - 1);
            ((u32::from(value) * 255 + maximum / 2) / maximum) as u8
        }
    }
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

// ── Baseline JPEG encoder (SOF0, 4:2:0 for color) ─────────────────────────

const WIC_JPEG_DC_LUMA_COUNTS: [u8; 16] = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0];
const WIC_JPEG_DC_LUMA_SYMBOLS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const WIC_JPEG_DC_CHROMA_COUNTS: [u8; 16] = [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0];
const WIC_JPEG_DC_CHROMA_SYMBOLS: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const WIC_JPEG_AC_LUMA_COUNTS: [u8; 16] = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d];
const WIC_JPEG_AC_LUMA_SYMBOLS: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];
const WIC_JPEG_AC_CHROMA_COUNTS: [u8; 16] = [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77];
const WIC_JPEG_AC_CHROMA_SYMBOLS: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0,
    0x15, 0x62, 0x72, 0xd1, 0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5,
    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa,
];
const WIC_JPEG_LUMA_QUANT: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const WIC_JPEG_CHROMA_QUANT: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

struct WicJpegBitWriter {
    out: Vec<u8>,
    buffer: u32,
    count: u32,
}

impl WicJpegBitWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            buffer: 0,
            count: 0,
        }
    }

    fn write_bits(&mut self, value: u32, count: u8) {
        if count == 0 {
            return;
        }
        self.buffer = (self.buffer << count) | (value & ((1_u32 << count) - 1));
        self.count += u32::from(count);
        while self.count >= 8 {
            let shift = self.count - 8;
            let byte = ((self.buffer >> shift) & 0xff) as u8;
            self.out.push(byte);
            if byte == 0xff {
                self.out.push(0);
            }
            self.count -= 8;
        }
        self.buffer &= if self.count == 0 {
            0
        } else {
            (1_u32 << self.count) - 1
        };
    }

    fn flush(&mut self) {
        if self.count > 0 {
            let padding = 8 - self.count;
            let byte = (((self.buffer << padding) | ((1_u32 << padding) - 1)) & 0xff) as u8;
            self.out.push(byte);
            if byte == 0xff {
                self.out.push(0);
            }
            self.buffer = 0;
            self.count = 0;
        }
    }
}

fn wic_jpeg_amplitude(value: i32, size: u8) -> u32 {
    if value >= 0 {
        value as u32
    } else {
        (value + (1_i32 << size) - 1) as u32
    }
}

fn wic_jpeg_bit_length(value: i32) -> u8 {
    let mut magnitude = value.unsigned_abs();
    let mut length = 0_u8;
    while magnitude != 0 {
        length += 1;
        magnitude >>= 1;
    }
    length
}

fn wic_jpeg_scaled_quant(table: &[u8; 64], quality: u32) -> [u16; 64] {
    let quality = quality.clamp(1, 100);
    let scale = if quality < 50 {
        5000 / quality
    } else {
        200 - quality * 2
    };
    let mut out = [0_u16; 64];
    for (slot, value) in out.iter_mut().zip(table.iter()) {
        *slot = (((u32::from(*value) * scale + 50) / 100).clamp(1, 255)) as u16;
    }
    out
}

fn wic_jpeg_push_segment(out: &mut Vec<u8>, marker: u8, payload: &[u8]) {
    out.push(0xff);
    out.push(marker);
    out.extend_from_slice(&((payload.len() as u16 + 2).to_be_bytes()));
    out.extend_from_slice(payload);
}

fn wic_jpeg_huffman_payload(class: u8, id: u8, counts: &[u8; 16], symbols: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(17 + symbols.len());
    payload.push((class << 4) | id);
    payload.extend_from_slice(counts);
    payload.extend_from_slice(symbols);
    payload
}

fn wic_jpeg_bgra_rgb(
    bgra: &[u8],
    width: usize,
    height: usize,
    x: isize,
    y: isize,
) -> (f32, f32, f32) {
    let x = x.clamp(0, width as isize - 1) as usize;
    let y = y.clamp(0, height as isize - 1) as usize;
    let index = (y * width + x) * 4;
    (
        f32::from(bgra[index + 2]),
        f32::from(bgra[index + 1]),
        f32::from(bgra[index]),
    )
}

fn wic_jpeg_rgb_to_ycc(red: f32, green: f32, blue: f32) -> (f32, f32, f32) {
    (
        0.299 * red + 0.587 * green + 0.114 * blue,
        -0.168_736 * red - 0.331_264 * green + 0.5 * blue + 128.0,
        0.5 * red - 0.418_688 * green - 0.081_312 * blue + 128.0,
    )
}

struct WicJpegEncoderTables {
    dc_luma: WicJpegHuffman,
    ac_luma: WicJpegHuffman,
    dc_chroma: WicJpegHuffman,
    ac_chroma: WicJpegHuffman,
}

impl WicJpegEncoderTables {
    fn build() -> Option<Self> {
        Some(Self {
            dc_luma: WicJpegHuffman::build(&WIC_JPEG_DC_LUMA_COUNTS, &WIC_JPEG_DC_LUMA_SYMBOLS)?,
            ac_luma: WicJpegHuffman::build(&WIC_JPEG_AC_LUMA_COUNTS, &WIC_JPEG_AC_LUMA_SYMBOLS)?,
            dc_chroma: WicJpegHuffman::build(
                &WIC_JPEG_DC_CHROMA_COUNTS,
                &WIC_JPEG_DC_CHROMA_SYMBOLS,
            )?, // coverage: unreachable — the fixed WIC_JPEG_DC_CHROMA_* constant tables are complete, and the encoder-table test pins WicJpegEncoderTables::build() as Some.
            ac_chroma: WicJpegHuffman::build(
                &WIC_JPEG_AC_CHROMA_COUNTS,
                &WIC_JPEG_AC_CHROMA_SYMBOLS,
            )?, // coverage: unreachable — the fixed WIC_JPEG_AC_CHROMA_* constant tables are complete, and the encoder-table test pins WicJpegEncoderTables::build() as Some.
        })
    }
}

fn wic_jpeg_encode_block(
    samples: &[f32; 64],
    quant: &[u16; 64],
    cosine: &[[f32; 8]; 8],
    dc_table: &WicJpegHuffman,
    ac_table: &WicJpegHuffman,
    previous_dc: &mut i32,
    writer: &mut WicJpegBitWriter,
) -> bool {
    let mut transformed = [0_f32; 64];
    for v in 0..8 {
        for u in 0..8 {
            let mut sum = 0_f32;
            for y in 0..8 {
                for x in 0..8 {
                    sum += samples[y * 8 + x] * cosine[x][u] * cosine[y][v];
                }
            }
            transformed[v * 8 + u] = sum;
        }
    }
    let mut block = [0_i32; 64];
    for index in 0..64 {
        let quantized = (transformed[index] / f32::from(quant[index])).round() as i32;
        block[index] = if index == 0 {
            quantized.clamp(-2047, 2047)
        } else {
            quantized.clamp(-1023, 1023)
        };
    }
    let difference = block[0] - *previous_dc;
    *previous_dc = block[0];
    let size = wic_jpeg_bit_length(difference);
    if !dc_table.write(size, writer) {
        return false;
    }
    if size > 0 {
        writer.write_bits(wic_jpeg_amplitude(difference, size), size);
    }
    let mut run = 0_u8;
    for coefficient in 1..64 {
        let value = block[WIC_JPEG_ZIGZAG[coefficient]];
        if value == 0 {
            run += 1;
            continue;
        }
        while run >= 16 {
            if !ac_table.write(0xf0, writer) {
                return false;
            }
            run -= 16;
        }
        let size = wic_jpeg_bit_length(value);
        let symbol = (run << 4) | size;
        if !ac_table.write(symbol, writer) {
            return false;
        }
        writer.write_bits(wic_jpeg_amplitude(value, size), size);
        run = 0;
    }
    if run > 0 {
        return ac_table.write(0x00, writer);
    }
    true
}

/// Encode a real baseline JPEG.  Color images use 4:2:0 sampling; the
/// sampling parameter lets tests exercise 4:2:2 and 4:4:4 streams through the
/// same encoder.
fn wic_encode_jpeg_sampled(
    width: u32,
    height: u32,
    bgra: &[u8],
    dpi: Option<(f64, f64)>,
    sampling: (usize, usize),
) -> std::result::Result<Vec<u8>, u32> {
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|value| value.checked_mul(4))
        .ok_or(E_INVALIDARG)?;
    if width == 0 || height == 0 || bgra.len() < expected {
        return Err(E_INVALIDARG);
    }
    if width > 65535 || height > 65535 {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
    }
    let (sample_h, sample_v) = (sampling.0.clamp(1, 2), sampling.1.clamp(1, 2));
    let Some(tables) = WicJpegEncoderTables::build() else {
        return Err(WINCODEC_ERR_BADIMAGE); // coverage: unreachable — WicJpegEncoderTables::build() is deterministic over the fixed WIC_JPEG_* constant tables, which the encoder test pins as buildable.
    };
    let luma_quant = wic_jpeg_scaled_quant(&WIC_JPEG_LUMA_QUANT, 90);
    let chroma_quant = wic_jpeg_scaled_quant(&WIC_JPEG_CHROMA_QUANT, 90);
    let mut cosine = [[0_f32; 8]; 8];
    for (x, row) in cosine.iter_mut().enumerate() {
        for (u, value) in row.iter_mut().enumerate() {
            let scale = if u == 0 {
                std::f32::consts::FRAC_1_SQRT_2
            } else {
                1.0
            };
            *value =
                0.5 * scale * (((2 * x + 1) as f32 * u as f32 * std::f32::consts::PI) / 16.0).cos();
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(&[0xff, 0xd8]);
    let (dpi_x, dpi_y) = dpi
        .filter(|(x, y)| x.is_finite() && y.is_finite() && *x > 0.0 && *y > 0.0)
        .unwrap_or((WIC_DEFAULT_DPI, WIC_DEFAULT_DPI));
    let xdpi = (dpi_x.round() as u32).clamp(1, 65535) as u16;
    let ydpi = (dpi_y.round() as u32).clamp(1, 65535) as u16;
    let mut app0 = Vec::with_capacity(14);
    app0.extend_from_slice(b"JFIF\0");
    app0.extend_from_slice(&[1, 1, 1]);
    app0.extend_from_slice(&xdpi.to_be_bytes());
    app0.extend_from_slice(&ydpi.to_be_bytes());
    app0.extend_from_slice(&[0, 0]);
    wic_jpeg_push_segment(&mut out, 0xe0, &app0);
    let mut quant_luma = vec![0_u8];
    for coefficient in 0..64 {
        quant_luma.push(luma_quant[WIC_JPEG_ZIGZAG[coefficient]] as u8);
    }
    wic_jpeg_push_segment(&mut out, 0xdb, &quant_luma);
    let mut quant_chroma = vec![1_u8];
    for coefficient in 0..64 {
        quant_chroma.push(chroma_quant[WIC_JPEG_ZIGZAG[coefficient]] as u8);
    }
    wic_jpeg_push_segment(&mut out, 0xdb, &quant_chroma);
    let mut frame = Vec::with_capacity(15);
    frame.push(8);
    frame.extend_from_slice(&(height as u16).to_be_bytes());
    frame.extend_from_slice(&(width as u16).to_be_bytes());
    frame.push(3);
    frame.extend_from_slice(&[
        1,
        (sample_h << 4 | sample_v) as u8,
        0,
        2,
        0x11,
        1,
        3,
        0x11,
        1,
    ]);
    wic_jpeg_push_segment(&mut out, 0xc0, &frame);
    wic_jpeg_push_segment(
        &mut out,
        0xc4,
        &wic_jpeg_huffman_payload(0, 0, &WIC_JPEG_DC_LUMA_COUNTS, &WIC_JPEG_DC_LUMA_SYMBOLS),
    );
    wic_jpeg_push_segment(
        &mut out,
        0xc4,
        &wic_jpeg_huffman_payload(1, 0, &WIC_JPEG_AC_LUMA_COUNTS, &WIC_JPEG_AC_LUMA_SYMBOLS),
    );
    wic_jpeg_push_segment(
        &mut out,
        0xc4,
        &wic_jpeg_huffman_payload(
            0,
            1,
            &WIC_JPEG_DC_CHROMA_COUNTS,
            &WIC_JPEG_DC_CHROMA_SYMBOLS,
        ),
    );
    wic_jpeg_push_segment(
        &mut out,
        0xc4,
        &wic_jpeg_huffman_payload(
            1,
            1,
            &WIC_JPEG_AC_CHROMA_COUNTS,
            &WIC_JPEG_AC_CHROMA_SYMBOLS,
        ),
    );
    wic_jpeg_push_segment(&mut out, 0xda, &[3, 1, 0x00, 2, 0x11, 3, 0x11, 0, 63, 0]);
    let mcus_x = (width as usize).div_ceil(8 * sample_h);
    let mcus_y = (height as usize).div_ceil(8 * sample_v);
    let mut writer = WicJpegBitWriter::new();
    let mut dc_luma = 0_i32;
    let mut dc_chroma = [0_i32; 2];
    for mcu_y in 0..mcus_y {
        for mcu_x in 0..mcus_x {
            for block_y in 0..sample_v {
                for block_x in 0..sample_h {
                    let mut samples = [0_f32; 64];
                    for y in 0..8 {
                        for x in 0..8 {
                            let source_x = (mcu_x * 8 * sample_h + block_x * 8 + x) as isize;
                            let source_y = (mcu_y * 8 * sample_v + block_y * 8 + y) as isize;
                            let (red, green, blue) = wic_jpeg_bgra_rgb(
                                bgra,
                                width as usize,
                                height as usize,
                                source_x,
                                source_y,
                            );
                            let (luma, _, _) = wic_jpeg_rgb_to_ycc(red, green, blue);
                            samples[y * 8 + x] = luma - 128.0;
                        }
                    }
                    if !wic_jpeg_encode_block(
                        &samples,
                        &luma_quant,
                        &cosine,
                        &tables.dc_luma,
                        &tables.ac_luma,
                        &mut dc_luma,
                        &mut writer,
                    ) {
                        return Err(WINCODEC_ERR_BADIMAGE); // coverage: unreachable — the standard luma/chroma Huffman tables contain every DC category 0..11 and AC (run,size) symbol the clamped block can emit.
                    }
                }
            }
            for chroma in 0..2 {
                let mut samples = [0_f32; 64];
                for y in 0..8 {
                    for x in 0..8 {
                        let mut red = 0_f32;
                        let mut green = 0_f32;
                        let mut blue = 0_f32;
                        for dy in 0..sample_v {
                            for dx in 0..sample_h {
                                let source_x = (mcu_x * 8 * sample_h + x * sample_h + dx) as isize;
                                let source_y = (mcu_y * 8 * sample_v + y * sample_v + dy) as isize;
                                let (r, g, b) = wic_jpeg_bgra_rgb(
                                    bgra,
                                    width as usize,
                                    height as usize,
                                    source_x,
                                    source_y,
                                );
                                red += r;
                                green += g;
                                blue += b;
                            }
                        }
                        let count = (sample_h * sample_v) as f32;
                        let (_, cb, cr) =
                            wic_jpeg_rgb_to_ycc(red / count, green / count, blue / count);
                        samples[y * 8 + x] = (if chroma == 0 { cb } else { cr }) - 128.0;
                    }
                }
                if !wic_jpeg_encode_block(
                    &samples,
                    &chroma_quant,
                    &cosine,
                    &tables.dc_chroma,
                    &tables.ac_chroma,
                    &mut dc_chroma[chroma],
                    &mut writer,
                ) {
                    return Err(WINCODEC_ERR_BADIMAGE); // coverage: unreachable — the standard luma/chroma Huffman tables contain every DC category 0..11 and AC (run,size) symbol the clamped chroma block can emit.
                }
            }
        }
    }
    writer.flush();
    out.extend_from_slice(&writer.out);
    out.extend_from_slice(&[0xff, 0xd9]);
    Ok(out)
}

fn wic_encode_jpeg(
    width: u32,
    height: u32,
    bgra: &[u8],
    dpi: Option<(f64, f64)>,
) -> std::result::Result<Vec<u8>, u32> {
    wic_encode_jpeg_sampled(width, height, bgra, dpi, (2, 2))
}

// ── Multi-frame encoder frame accumulation ────────────────────────────────

/// Append one committed frame to an encoder's private accumulation buffer
/// (`profile` keeps the encoder magic in its first eight bytes).
fn wic_encoder_append_frame(
    profile: &mut Vec<u8>,
    width: u32,
    height: u32,
    dpi: (f64, f64),
    bgra: &[u8],
) {
    if profile.len() < 12 {
        profile.clear();
        profile.extend_from_slice(WIC_ENCODER_MAGIC);
        profile.extend_from_slice(&0_u32.to_le_bytes());
    }
    let count = u32::from_le_bytes([profile[8], profile[9], profile[10], profile[11]]);
    let count = count.saturating_add(1);
    profile[8..12].copy_from_slice(&count.to_le_bytes());
    profile.extend_from_slice(&width.to_le_bytes());
    profile.extend_from_slice(&height.to_le_bytes());
    profile.extend_from_slice(&(dpi.0 as f32).to_bits().to_le_bytes());
    profile.extend_from_slice(&(dpi.1 as f32).to_bits().to_le_bytes());
    profile.extend_from_slice(&(bgra.len() as u32).to_le_bytes());
    profile.extend_from_slice(bgra);
}

/// Read back the accumulated frames: (width, height, dpi, BGRA pixels).
fn wic_encoder_frames(profile: &[u8]) -> Vec<(u32, u32, (f64, f64), Vec<u8>)> {
    if profile.len() < 12 || !profile.starts_with(WIC_ENCODER_MAGIC) {
        return Vec::new();
    }
    let count = u32::from_le_bytes([profile[8], profile[9], profile[10], profile[11]]) as usize;
    let mut position = 12_usize;
    let mut frames = Vec::with_capacity(count.min(1024));
    for _ in 0..count.min(1024) {
        let Some(header) = profile.get(position..position + 20) else {
            break;
        };
        let width = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let height = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let dpi_x = f32::from_bits(u32::from_le_bytes([
            header[8], header[9], header[10], header[11],
        ])) as f64;
        let dpi_y = f32::from_bits(u32::from_le_bytes([
            header[12], header[13], header[14], header[15],
        ])) as f64;
        let length = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
        position += 20;
        let Some(pixels) = profile.get(position..position.saturating_add(length)) else {
            break;
        };
        position += length;
        frames.push((width, height, (dpi_x, dpi_y), pixels.to_vec()));
    }
    frames
}

// ── GIF encoder (palette quantization + LZW) ──────────────────────────────

fn wic_gif_quantize(bgra: &[u8]) -> ([[u8; 3]; 256], Vec<u8>, Option<u8>) {
    let transparent = bgra.chunks_exact(4).any(|pixel| pixel[3] < 128);
    let mut exact: Vec<[u8; 3]> = Vec::new();
    let mut seen: HashMap<u32, u8> = HashMap::new();
    let mut overflow = false;
    for pixel in bgra.chunks_exact(4) {
        if pixel[3] < 128 {
            continue;
        }
        let key = (u32::from(pixel[2]) << 16) | (u32::from(pixel[1]) << 8) | u32::from(pixel[0]);
        if seen.contains_key(&key) {
            continue;
        }
        if exact.len() < 256 {
            seen.insert(key, exact.len() as u8);
            exact.push([pixel[2], pixel[1], pixel[0]]);
        } else {
            overflow = true;
        }
    }
    let room = if transparent { 255 } else { 256 };
    let mut palette = [[0_u8; 3]; 256];
    let mut indices = Vec::with_capacity(bgra.len() / 4);
    if !overflow && exact.len() <= room {
        let offset = usize::from(transparent);
        for (slot, color) in exact.iter().enumerate() {
            palette[offset + slot] = *color;
        }
        for pixel in bgra.chunks_exact(4) {
            if pixel[3] < 128 {
                indices.push(0);
                continue;
            }
            let key =
                (u32::from(pixel[2]) << 16) | (u32::from(pixel[1]) << 8) | u32::from(pixel[0]);
            indices.push(seen.get(&key).copied().unwrap_or(0) + offset as u8);
        }
        return (palette, indices, transparent.then_some(0));
    }
    let start = usize::from(transparent);
    let mut colors: Vec<[u8; 3]> = Vec::with_capacity(256 - start);
    for red in [0_u8, 51, 102, 153, 204, 255] {
        for green in [0_u8, 51, 102, 153, 204, 255] {
            for blue in [0_u8, 51, 102, 153, 204, 255] {
                colors.push([red, green, blue]);
            }
        }
    }
    for step in 0..40 {
        let value = (step * 255 / 39) as u8;
        colors.push([value, value, value]);
    }
    colors.truncate(256 - start);
    for (slot, color) in colors.iter().enumerate() {
        palette[start + slot] = *color;
    }
    for pixel in bgra.chunks_exact(4) {
        if pixel[3] < 128 {
            indices.push(0);
            continue;
        }
        let mut best = start;
        let mut best_distance = u32::MAX;
        for (slot, color) in colors.iter().enumerate() {
            let red = i32::from(pixel[2]) - i32::from(color[0]);
            let green = i32::from(pixel[1]) - i32::from(color[1]);
            let blue = i32::from(pixel[0]) - i32::from(color[2]);
            let distance = (red * red + green * green + blue * blue) as u32;
            if distance < best_distance {
                best_distance = distance;
                best = start + slot;
            }
        }
        indices.push(best as u8);
    }
    (palette, indices, transparent.then_some(0))
}

struct WicGifWriter {
    out: Vec<u8>,
    accumulator: u32,
    bits: u32,
}

impl WicGifWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            accumulator: 0,
            bits: 0,
        }
    }

    fn push(&mut self, code: u16, width: u32) {
        self.accumulator |= u32::from(code) << self.bits;
        self.bits += width;
        while self.bits >= 8 {
            self.out.push(self.accumulator as u8);
            self.accumulator >>= 8;
            self.bits -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits > 0 {
            self.out.push(self.accumulator as u8);
        }
        self.out
    }
}

fn wic_gif_lzw_encode(indices: &[u8]) -> Vec<u8> {
    const CLEAR: u16 = 256;
    const END: u16 = 257;
    let mut writer = WicGifWriter::new();
    let mut code_size = 9_u32;
    let mut next = 258_u32;
    let mut dictionary: HashMap<u32, u16> = HashMap::new();
    writer.push(CLEAR, code_size);
    if let Some(&first) = indices.first() {
        let mut prefix = u32::from(first);
        for &byte in &indices[1..] {
            let key = (prefix << 8) | u32::from(byte);
            if let Some(&code) = dictionary.get(&key) {
                prefix = u32::from(code);
                continue;
            }
            writer.push(prefix as u16, code_size);
            if next > (1 << code_size) - 1 && code_size < 12 {
                code_size += 1;
            }
            if next < 4096 {
                dictionary.insert(key, next as u16);
                next += 1;
            } else {
                writer.push(CLEAR, code_size);
                dictionary.clear();
                next = 258;
                code_size = 9;
            }
            prefix = u32::from(byte);
        }
        writer.push(prefix as u16, code_size);
        if next > (1 << code_size) - 1 && code_size < 12 {
            code_size += 1;
        }
    }
    writer.push(END, code_size);
    writer.finish()
}

fn wic_gif_sub_block(out: &mut Vec<u8>, data: &[u8]) {
    for chunk in data.chunks(255) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out.push(0);
}

/// One frame of an animated GIF encode.  `disposal` follows the GIF89a
/// disposal method numbering (0-3) and `delay_ms` is the display time.
struct WicGifAnimationFrame<'a> {
    bgra: &'a [u8],
    delay_ms: u32,
    disposal: u8,
}

/// Encode a real multi-frame animated GIF89a: a NETSCAPE2.0 looping
/// application extension, per-frame graphic-control extensions carrying the
/// delay/disposal/transparent index, and a local color table per frame.
fn wic_encode_gif_animation(
    width: u32,
    height: u32,
    frames: &[WicGifAnimationFrame<'_>],
    loop_count: u16,
) -> std::result::Result<Vec<u8>, u32> {
    if width == 0 || height == 0 || width > u16::MAX as u32 || height > u16::MAX as u32 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    if frames.is_empty() {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|value| value.checked_mul(4))
        .ok_or(WINCODEC_ERR_BADIMAGE)?;
    for frame in frames {
        if frame.bgra.len() < expected || frame.disposal > 3 {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
    }
    let mut out = b"GIF89a".to_vec();
    out.extend_from_slice(&(width as u16).to_le_bytes());
    out.extend_from_slice(&(height as u16).to_le_bytes());
    out.push(0xf7);
    out.push(0);
    out.push(0);
    out.extend_from_slice(&[0_u8; 256 * 3]);
    out.extend_from_slice(&[0x21, 0xff, 11]);
    out.extend_from_slice(b"NETSCAPE2.0");
    out.extend_from_slice(&[3, 1]);
    out.extend_from_slice(&loop_count.to_le_bytes());
    out.push(0);
    for frame in frames {
        let (palette, indices, transparent) = wic_gif_quantize(&frame.bgra[..expected]);
        let compressed = wic_gif_lzw_encode(&indices);
        let delay = (frame.delay_ms / 10).min(u32::from(u16::MAX)) as u16;
        let flags = (frame.disposal << 2) | u8::from(transparent.is_some());
        out.extend_from_slice(&[0x21, 0xf9, 4, flags]);
        out.extend_from_slice(&delay.to_le_bytes());
        out.push(transparent.unwrap_or(0));
        out.push(0);
        out.push(0x2c);
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&(width as u16).to_le_bytes());
        out.extend_from_slice(&(height as u16).to_le_bytes());
        out.push(0x87);
        for color in &palette {
            out.extend_from_slice(color);
        }
        out.push(8);
        wic_gif_sub_block(&mut out, &compressed);
    }
    out.push(0x3b);
    Ok(out)
}

fn wic_encode_gif(width: u32, height: u32, bgra: &[u8]) -> std::result::Result<Vec<u8>, u32> {
    let frame = WicGifAnimationFrame {
        bgra,
        delay_ms: 100,
        disposal: 0,
    };
    wic_encode_gif_animation(width, height, &[frame], 0)
}

// ── Baseline TIFF encoder (uncompressed RGB strips, multi-page) ───────────

/// One page for the TIFF encoder.  The descriptive tags are optional and
/// written as ASCII when present; each page carries its own resolution.
struct WicTiffPage<'a> {
    width: u32,
    height: u32,
    bgra: &'a [u8],
    dpi: Option<(f64, f64)>,
    description: Option<&'a str>,
    make: Option<&'a str>,
    model: Option<&'a str>,
    datetime: Option<&'a str>,
}

fn wic_tiff_page_metadata<'a>(page: &WicTiffPage<'a>) -> Vec<(u16, &'a str)> {
    let mut entries = Vec::with_capacity(4);
    if let Some(text) = page.description {
        entries.push((270_u16, text));
    }
    if let Some(text) = page.make {
        entries.push((271, text));
    }
    if let Some(text) = page.model {
        entries.push((272, text));
    }
    if let Some(text) = page.datetime {
        entries.push((306, text));
    }
    entries
}

fn wic_tiff_push_entry(out: &mut Vec<u8>, tag: u16, kind: u16, count: u32, value: u32) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    if kind == 3 && count == 1 {
        out.extend_from_slice(&(value as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
    } else {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Encode one or more uncompressed little-endian RGB TIFF pages, each with
/// its own IFD linked by the next-IFD pointer, plus resolution and the
/// standard descriptive metadata tags.
fn wic_encode_tiff_pages(pages: &[WicTiffPage<'_>]) -> std::result::Result<Vec<u8>, u32> {
    if pages.is_empty() {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    let mut rgb_pages = Vec::with_capacity(pages.len());
    for page in pages {
        if page.width == 0 || page.height == 0 {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        let pixels = (page.width as usize)
            .checked_mul(page.height as usize)
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
        let expected = pixels.checked_mul(4).ok_or(WINCODEC_ERR_BADIMAGE)?;
        if page.bgra.len() < expected {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        let mut rgb = Vec::with_capacity(pixels * 3);
        for pixel in page.bgra[..expected].chunks_exact(4) {
            rgb.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
        }
        rgb_pages.push(rgb);
    }
    let mut data_offset = 8_usize;
    let mut data_offsets = Vec::with_capacity(pages.len());
    for rgb in &rgb_pages {
        data_offsets.push(data_offset);
        data_offset = data_offset
            .checked_add(rgb.len())
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
        if data_offset % 2 != 0 {
            data_offset += 1;
        }
    }
    let entry_counts: Vec<usize> = pages
        .iter()
        .map(|page| 13 + wic_tiff_page_metadata(page).len())
        .collect();
    let mut ifd_offsets = Vec::with_capacity(pages.len());
    let mut ifd_offset = data_offset;
    for count in &entry_counts {
        ifd_offsets.push(ifd_offset);
        ifd_offset = ifd_offset
            .checked_add(2 + count * 12 + 4)
            .ok_or(WINCODEC_ERR_BADIMAGE)?;
    }
    let mut extra_offset = ifd_offset;
    let mut bits_offsets = Vec::with_capacity(pages.len());
    for _ in pages {
        bits_offsets.push(extra_offset);
        extra_offset += 6;
    }
    let mut x_resolution_offsets = Vec::with_capacity(pages.len());
    for _ in pages {
        x_resolution_offsets.push(extra_offset);
        extra_offset += 8;
    }
    let mut y_resolution_offsets = Vec::with_capacity(pages.len());
    for _ in pages {
        y_resolution_offsets.push(extra_offset);
        extra_offset += 8;
    }
    let mut string_offsets: Vec<Vec<usize>> = Vec::with_capacity(pages.len());
    for page in pages {
        let mut offsets = Vec::new();
        for (_, text) in wic_tiff_page_metadata(page) {
            offsets.push(extra_offset);
            extra_offset = extra_offset
                .checked_add(text.len() + 1)
                .ok_or(WINCODEC_ERR_BADIMAGE)?;
        }
        string_offsets.push(offsets);
    }
    if extra_offset > u32::MAX as usize {
        return Err(WINCODEC_ERR_BADIMAGE); // coverage: unreachable — extra_offset accumulates the lengths of caller-supplied page slices and fixed per-page headers; passing 4 GiB requires an input larger than the runtime can allocate, and the checked_add arms above fail first.
    }
    let total = extra_offset;
    let mut out = vec![0_u8; total];
    out[..2].copy_from_slice(b"II");
    out[2..4].copy_from_slice(&42_u16.to_le_bytes());
    out[4..8].copy_from_slice(&(ifd_offsets[0] as u32).to_le_bytes());
    for (index, rgb) in rgb_pages.iter().enumerate() {
        let offset = data_offsets[index];
        out[offset..offset + rgb.len()].copy_from_slice(rgb);
    }
    for (page_index, page) in pages.iter().enumerate() {
        let (dpi_x, dpi_y) = page.dpi.unwrap_or((WIC_DEFAULT_DPI, WIC_DEFAULT_DPI));
        let resolution = |value: f64| -> u32 {
            if value.is_finite() && value > 0.0 {
                value.round().clamp(1.0, 65535.0) as u32
            } else {
                WIC_DEFAULT_DPI as u32
            }
        };
        let position = ifd_offsets[page_index];
        let entry_count = entry_counts[page_index];
        let mut ifd_bytes = Vec::with_capacity(2 + entry_count * 12 + 4);
        ifd_bytes.extend_from_slice(&(entry_count as u16).to_le_bytes());
        let mut entries = Vec::with_capacity(entry_count);
        entries.push((256_u16, 4_u16, 1_u32, page.width));
        entries.push((257, 4, 1, page.height));
        entries.push((258, 3, 3, bits_offsets[page_index] as u32));
        entries.push((259, 3, 1, 1));
        entries.push((262, 3, 1, 2));
        entries.push((273, 4, 1, data_offsets[page_index] as u32));
        entries.push((277, 3, 1, 3));
        entries.push((278, 4, 1, page.height));
        entries.push((279, 4, 1, rgb_pages[page_index].len() as u32));
        entries.push((282, 5, 1, x_resolution_offsets[page_index] as u32));
        entries.push((283, 5, 1, y_resolution_offsets[page_index] as u32));
        entries.push((284, 3, 1, 1));
        entries.push((296, 3, 1, 2));
        for (meta_index, (tag, text)) in wic_tiff_page_metadata(page).into_iter().enumerate() {
            entries.push((
                tag,
                2,
                text.len() as u32 + 1,
                string_offsets[page_index][meta_index] as u32,
            ));
        }
        entries.sort_by_key(|(tag, _, _, _)| *tag);
        for (tag, kind, count, value) in entries {
            wic_tiff_push_entry(&mut ifd_bytes, tag, kind, count, value);
        }
        let next = if page_index + 1 < pages.len() {
            ifd_offsets[page_index + 1] as u32
        } else {
            0
        };
        ifd_bytes.extend_from_slice(&next.to_le_bytes());
        out[position..position + ifd_bytes.len()].copy_from_slice(&ifd_bytes);
        for index in 0..3 {
            let offset = bits_offsets[page_index] + index * 2;
            out[offset..offset + 2].copy_from_slice(&8_u16.to_le_bytes());
        }
        let x_offset = x_resolution_offsets[page_index];
        out[x_offset..x_offset + 4].copy_from_slice(&resolution(dpi_x).to_le_bytes());
        out[x_offset + 4..x_offset + 8].copy_from_slice(&1_u32.to_le_bytes());
        let y_offset = y_resolution_offsets[page_index];
        out[y_offset..y_offset + 4].copy_from_slice(&resolution(dpi_y).to_le_bytes());
        out[y_offset + 4..y_offset + 8].copy_from_slice(&1_u32.to_le_bytes());
        for (meta_index, (_, text)) in wic_tiff_page_metadata(page).into_iter().enumerate() {
            let offset = string_offsets[page_index][meta_index];
            out[offset..offset + text.len()].copy_from_slice(text.as_bytes());
            out[offset + text.len()] = 0;
        }
    }
    Ok(out)
}

fn wic_encode_tiff(
    width: u32,
    height: u32,
    bgra: &[u8],
    dpi: Option<(f64, f64)>,
) -> std::result::Result<Vec<u8>, u32> {
    wic_encode_tiff_pages(&[WicTiffPage {
        width,
        height,
        bgra,
        dpi,
        description: None,
        make: None,
        model: None,
        datetime: None,
    }])
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

    fn write(&self, symbol: u8, writer: &mut WicJpegBitWriter) -> bool {
        for &(code, length, candidate) in &self.entries {
            if candidate == symbol {
                writer.write_bits(u32::from(code), length);
                return true;
            }
        }
        false
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
            } // coverage: unreachable — read_byte sets restart_pending only in the same branch that stores marker_position, and skip_restart clears the flag before taking the position, so a pending restart with no marker position cannot occur.
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
    /// Padded block stride (MCU-aligned) and height.
    blocks_x: usize,
    blocks_y: usize,
    /// Blocks actually covering the component (non-interleaved scans).
    actual_blocks_x: usize,
    actual_blocks_y: usize,
    plane_width: usize,
    plane_height: usize,
    samples: Vec<u8>,
    coefficients: Vec<[i32; 64]>,
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

#[derive(Clone, Copy)]
struct WicJpegScanParams {
    progressive: bool,
    ss: usize,
    se: usize,
    ah: u8,
    al: u8,
}

fn wic_jpeg_refine(coefficient: &mut i32, bit: u8, step: i32) {
    if bit != 0 && (*coefficient & step) == 0 {
        *coefficient += if *coefficient >= 0 { step } else { -step };
    }
}

/// Decode one block of a baseline or progressive scan into quantized
/// coefficients.  Progressive scans implement spectral selection (Ss/Se) and
/// successive approximation (Ah/Al), including AC refinement and EOB runs.
fn wic_jpeg_decode_block(
    component: &mut WicJpegComponent,
    block_index: usize,
    bits: &mut WicJpegBits<'_>,
    dc_table: &WicJpegHuffman,
    ac_table: &WicJpegHuffman,
    scan: WicJpegScanParams,
    eob_run: &mut u32,
) -> std::result::Result<(), u32> {
    if block_index >= component.coefficients.len() {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    if !scan.progressive {
        let Some(category) = dc_table.decode(bits) else {
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
        component.dc_prediction += difference;
        let dc = component.dc_prediction;
        let block = &mut component.coefficients[block_index];
        block[0] = dc;
        let mut coefficient = 1_usize;
        while coefficient < 64 {
            let Some(run_size) = ac_table.decode(bits) else {
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
                block[WIC_JPEG_ZIGZAG[coefficient]] = wic_jpeg_extend(value, size);
                coefficient += 1;
            }
        }
        return Ok(());
    }
    if scan.ss == 0 {
        if scan.ah == 0 {
            let Some(category) = dc_table.decode(bits) else {
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
            component.dc_prediction += difference;
            component.coefficients[block_index][0] = component.dc_prediction << scan.al;
        } else {
            let Some(bit) = bits.bit() else {
                return Err(WINCODEC_ERR_BADIMAGE);
            };
            component.coefficients[block_index][0] |= i32::from(bit) << scan.al;
        }
        return Ok(());
    }
    if scan.ah == 0 {
        let block = &mut component.coefficients[block_index];
        if *eob_run > 0 {
            *eob_run -= 1;
            return Ok(());
        }
        let mut coefficient = scan.ss;
        while coefficient <= scan.se && coefficient < 64 {
            let Some(run_size) = ac_table.decode(bits) else {
                return Err(WINCODEC_ERR_BADIMAGE);
            };
            let run = usize::from(run_size >> 4);
            let size = run_size & 0x0f;
            if size == 0 {
                if run == 15 {
                    coefficient += 16;
                    continue;
                }
                let mut run_length = 1_u32 << run;
                if run > 0 {
                    let Some(extra) = bits.bits(run as u32) else {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    };
                    run_length += extra;
                }
                *eob_run = run_length - 1;
                break;
            }
            coefficient += run;
            if coefficient > scan.se || coefficient >= 64 {
                return Err(WINCODEC_ERR_BADIMAGE);
            }
            let Some(value) = bits.bits(u32::from(size)) else {
                return Err(WINCODEC_ERR_BADIMAGE);
            };
            block[WIC_JPEG_ZIGZAG[coefficient]] = wic_jpeg_extend(value, size) << scan.al;
            coefficient += 1;
        }
        return Ok(());
    }
    let step = 1_i32 << scan.al;
    if *eob_run > 0 {
        let block = &mut component.coefficients[block_index];
        for coefficient in scan.ss..=scan.se {
            let index = WIC_JPEG_ZIGZAG[coefficient];
            if block[index] != 0 {
                let Some(bit) = bits.bit() else {
                    return Err(WINCODEC_ERR_BADIMAGE);
                };
                wic_jpeg_refine(&mut block[index], bit, step);
            }
        }
        *eob_run -= 1;
        return Ok(());
    }
    let mut coefficient = scan.ss;
    while coefficient <= scan.se {
        let Some(run_size) = ac_table.decode(bits) else {
            return Err(WINCODEC_ERR_BADIMAGE);
        };
        let run = usize::from(run_size >> 4);
        let size = run_size & 0x0f;
        if size == 0 {
            if run == 15 {
                let mut zeros = 16_usize;
                while coefficient <= scan.se && zeros > 0 {
                    let index = WIC_JPEG_ZIGZAG[coefficient];
                    if component.coefficients[block_index][index] != 0 {
                        let Some(bit) = bits.bit() else {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        };
                        wic_jpeg_refine(&mut component.coefficients[block_index][index], bit, step);
                    } else {
                        zeros -= 1;
                    }
                    coefficient += 1;
                }
                continue;
            }
            let mut run_length = 1_u32 << run;
            if run > 0 {
                let Some(extra) = bits.bits(run as u32) else {
                    return Err(WINCODEC_ERR_BADIMAGE);
                };
                run_length += extra;
            }
            *eob_run = run_length - 1;
            while coefficient <= scan.se {
                let index = WIC_JPEG_ZIGZAG[coefficient];
                if component.coefficients[block_index][index] != 0 {
                    let Some(bit) = bits.bit() else {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    };
                    wic_jpeg_refine(&mut component.coefficients[block_index][index], bit, step);
                }
                coefficient += 1;
            }
            return Ok(());
        }
        if size != 1 {
            return Err(WINCODEC_ERR_BADIMAGE);
        }
        let Some(sign_bit) = bits.bit() else {
            return Err(WINCODEC_ERR_BADIMAGE);
        };
        let sign = if sign_bit != 0 { step } else { -step };
        let mut zeros = run;
        loop {
            if coefficient > scan.se {
                return Err(WINCODEC_ERR_BADIMAGE);
            }
            let index = WIC_JPEG_ZIGZAG[coefficient];
            if component.coefficients[block_index][index] != 0 {
                let Some(bit) = bits.bit() else {
                    return Err(WINCODEC_ERR_BADIMAGE);
                };
                wic_jpeg_refine(&mut component.coefficients[block_index][index], bit, step);
            } else if zeros > 0 {
                zeros -= 1;
            } else {
                break;
            }
            coefficient += 1;
        }
        component.coefficients[block_index][WIC_JPEG_ZIGZAG[coefficient]] = sign;
        coefficient += 1;
    }
    Ok(())
}

/// Find the next real marker at or after `start`, skipping stuffed bytes and
/// restart markers.
fn wic_jpeg_next_marker(bytes: &[u8], start: usize) -> usize {
    let mut position = start;
    while position + 1 < bytes.len() {
        if bytes[position] == 0xff {
            let next = bytes[position + 1];
            if next == 0x00 || (0xd0..=0xd7).contains(&next) {
                position += 2;
                continue;
            }
            return position;
        }
        position += 1;
    }
    bytes.len()
}

/// Decode a real JPEG: baseline (SOF0/SOF1) or progressive (SOF2) Huffman
/// scans, spectral selection/successive approximation, restart markers,
/// 4:2:0/4:2:2/4:4:4 sampling, dequantization and 2D IDCT.
fn wic_decode_jpeg(bytes: &[u8]) -> std::result::Result<WicDecodedImage, u32> {
    if bytes.len() < 4 || bytes[0] != 0xff || bytes[1] != 0xd8 {
        return Err(WINCODEC_ERR_UNKNOWNIMAGEFORMAT);
    }
    let mut position = 2_usize;
    let mut width = 0_u32;
    let mut height = 0_u32;
    let mut progressive = false;
    let mut components: Vec<WicJpegComponent> = Vec::new();
    let mut quant_tables = [[0_u16; 64]; 4];
    let mut quant_present = [false; 4];
    let mut dc_tables: [Option<WicJpegHuffman>; 4] = [None, None, None, None];
    let mut ac_tables: [Option<WicJpegHuffman>; 4] = [None, None, None, None];
    let mut restart_interval = 0_usize;
    let mut dpi_x = WIC_DEFAULT_DPI;
    let mut dpi_y = WIC_DEFAULT_DPI;
    let mut scanned = false;
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
            0xee => {
                if segment.len() >= 12 && &segment[..5] == b"Adobe" && segment[11] == 2 {
                    // YCCK (Adobe transform 2) is a four-component color
                    // space; reject it rather than mis-render it as YCbCr.
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
                }
            }
            0xc0 | 0xc1 | 0xc2 => {
                if segment.len() < 6 || segment[0] != 8 {
                    return Err(if segment.len() < 6 {
                        WINCODEC_ERR_BADIMAGE
                    } else {
                        WINCODEC_ERR_UNSUPPORTEDOPERATION
                    });
                }
                if !components.is_empty() {
                    return Err(WINCODEC_ERR_BADIMAGE);
                }
                progressive = marker == 0xc2;
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
                if count != 1 && count != 3 {
                    // CMYK / YCCK and other multi-component color spaces.
                    return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
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
                        actual_blocks_x: 0,
                        actual_blocks_y: 0,
                        plane_width: 0,
                        plane_height: 0,
                        samples: Vec::new(),
                        coefficients: Vec::new(),
                    });
                }
            }
            0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf => {
                return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION);
            }
            0xc4 => {
                let mut cursor = 0_usize;
                while cursor < segment.len() {
                    if cursor + 17 > segment.len() {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                    let class = segment[cursor] >> 4;
                    let identifier = usize::from(segment[cursor] & 0x0f);
                    if identifier >= 4 || class > 1 {
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
                    // Re-order the zigzag-coded table into natural order so
                    // coefficients can be dequantized by natural index.
                    let mut natural = [0_u16; 64];
                    for (index, slot) in table.iter().enumerate() {
                        natural[WIC_JPEG_ZIGZAG[index]] = *slot;
                    }
                    quant_tables[identifier] = natural;
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
                if tail.len() < 3 {
                    return Err(WINCODEC_ERR_BADIMAGE); // coverage: unreachable — the preceding check requires segment.len() >= 4 + count*2, so the tail slice always has at least 3 bytes.
                }
                let ss = usize::from(tail[0]);
                let se = usize::from(tail[1]);
                let ah = tail[2] >> 4;
                let al = tail[2] & 0x0f;
                if progressive {
                    if ss > se
                        || se > 63
                        || ah > 13
                        || al > 13
                        || (ss == 0 && se != 0)
                        || (ss > 0 && count != 1)
                        || (ah != 0 && ah != al + 1)
                    {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                } else if ss != 0 || se != 63 || ah != 0 || al != 0 {
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
                let mcus_x = (width as usize).div_ceil(8 * max_h);
                let mcus_y = (height as usize).div_ceil(8 * max_v);
                for component in components.iter_mut() {
                    component.blocks_x = mcus_x * component.h;
                    component.blocks_y = mcus_y * component.v;
                    component.plane_width = component.blocks_x * 8;
                    component.plane_height = component.blocks_y * 8;
                    let component_width = (width as usize * component.h).div_ceil(max_h);
                    let component_height = (height as usize * component.v).div_ceil(max_v);
                    component.actual_blocks_x = component_width.div_ceil(8).max(1);
                    component.actual_blocks_y = component_height.div_ceil(8).max(1);
                    if component.coefficients.is_empty() {
                        component.coefficients =
                            vec![[0_i32; 64]; component.blocks_x * component.blocks_y];
                    }
                    if !quant_present[component.tq] {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                }
                for &component_index in &order {
                    let component = &components[component_index];
                    let dc_ready = dc_tables[component.dc_table].is_some();
                    let ac_ready = ac_tables[component.ac_table].is_some();
                    if (progressive && ss == 0 && !dc_ready)
                        || (progressive && ss > 0 && !ac_ready)
                        || (!progressive && (!dc_ready || !ac_ready))
                    {
                        return Err(WINCODEC_ERR_BADIMAGE);
                    }
                }
                let interleaved = count > 1;
                let (scan_mcus_x, scan_mcus_y) = if interleaved {
                    (mcus_x, mcus_y)
                } else {
                    (
                        components[order[0]].actual_blocks_x,
                        components[order[0]].actual_blocks_y,
                    )
                };
                for component in components.iter_mut() {
                    component.dc_prediction = 0;
                }
                let scan = WicJpegScanParams {
                    progressive,
                    ss,
                    se,
                    ah,
                    al,
                };
                let mut bits = WicJpegBits::new(bytes, position + length);
                let mut eob_run = 0_u32;
                let empty_dc = WicJpegHuffman {
                    entries: Vec::new(),
                };
                let empty_ac = WicJpegHuffman {
                    entries: Vec::new(),
                };
                let mcu_count = scan_mcus_x * scan_mcus_y;
                for mcu in 0..mcu_count {
                    if restart_interval > 0 && mcu > 0 && mcu % restart_interval == 0 {
                        if !bits.skip_restart() {
                            return Err(WINCODEC_ERR_BADIMAGE);
                        }
                        for component in components.iter_mut() {
                            component.dc_prediction = 0;
                        }
                        eob_run = 0;
                    }
                    let mcu_x = mcu % scan_mcus_x;
                    let mcu_y = mcu / scan_mcus_x;
                    for &component_index in &order {
                        let (h_blocks, v_blocks) = if interleaved {
                            let component = &components[component_index];
                            (component.h, component.v)
                        } else {
                            (1, 1)
                        };
                        for block_y in 0..v_blocks {
                            for block_x in 0..h_blocks {
                                let block_index = if interleaved {
                                    let component = &components[component_index];
                                    (mcu_y * component.v + block_y) * component.blocks_x
                                        + mcu_x * component.h
                                        + block_x
                                } else {
                                    mcu_y * components[component_index].blocks_x + mcu_x
                                };
                                let (dc_table, ac_table) = {
                                    let component = &components[component_index];
                                    (
                                        dc_tables[component.dc_table].as_ref().unwrap_or(&empty_dc),
                                        ac_tables[component.ac_table].as_ref().unwrap_or(&empty_ac),
                                    )
                                };
                                wic_jpeg_decode_block(
                                    &mut components[component_index],
                                    block_index,
                                    &mut bits,
                                    dc_table,
                                    ac_table,
                                    scan,
                                    &mut eob_run,
                                )?;
                            }
                        }
                    }
                }
                scanned = true;
                position = bits
                    .marker_position
                    .unwrap_or_else(|| wic_jpeg_next_marker(bytes, bits.position));
                continue;
            }
            0xe1..=0xef | 0xfe => {}
            _ => {}
        }
        position += length;
    }
    if !scanned || width == 0 || height == 0 {
        return Err(WINCODEC_ERR_BADIMAGE);
    }
    if components.len() != 1 && components.len() != 3 {
        return Err(WINCODEC_ERR_UNSUPPORTEDOPERATION); // coverage: unreachable — the SOF handler rejects every component count other than 1 and 3, and a scan (which sets `scanned`) requires a non-empty component list.
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
    let mut cosine = [[0_f32; 8]; 8];
    for (x, row) in cosine.iter_mut().enumerate() {
        for (u, value) in row.iter_mut().enumerate() {
            let scale = if u == 0 {
                std::f32::consts::FRAC_1_SQRT_2
            } else {
                1.0
            };
            *value =
                0.5 * scale * (((2 * x + 1) as f32 * u as f32 * std::f32::consts::PI) / 16.0).cos();
        }
    }
    for component in components.iter_mut() {
        if component.coefficients.is_empty() {
            return Err(WINCODEC_ERR_BADIMAGE); // coverage: unreachable — every SOS allocates coefficients for all components before it can set `scanned`, and a decode cannot leave the marker loop without a scan.
        }
        component.samples = vec![0_u8; component.plane_width * component.plane_height];
        let quant = quant_tables[component.tq];
        for block_y in 0..component.blocks_y {
            for block_x in 0..component.blocks_x {
                let source = &component.coefficients[block_y * component.blocks_x + block_x];
                let mut coefficients = [0_i32; 64];
                for (index, value) in coefficients.iter_mut().enumerate() {
                    *value = source[index] * i32::from(quant[index]);
                }
                let mut block = [0_u8; 64];
                wic_jpeg_idct(&coefficients, &cosine, &mut block);
                let destination_x = block_x * 8;
                let destination_y = block_y * 8;
                for row in 0..8 {
                    let start = (destination_y + row) * component.plane_width + destination_x;
                    let end = start + 8;
                    if let Some(slot) = component.samples.get_mut(start..end) {
                        slot.copy_from_slice(&block[row * 8..row * 8 + 8]);
                    }
                }
            }
        }
    }
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    for y in 0..height as usize {
        for x in 0..width as usize {
            let (red, green, blue);
            if components.len() == 1 {
                let component = &components[0];
                let sample_x = (x * component.h / max_h).min(component.plane_width - 1);
                let sample_y = (y * component.v / max_v).min(component.plane_height - 1);
                let value = component.samples[sample_y * component.plane_width + sample_x] as f32;
                red = value;
                green = value;
                blue = value;
            } else {
                let mut samples = [0_f32; 3];
                for (index, slot) in samples.iter_mut().enumerate() {
                    let component = &components[index];
                    let sample_x = (x * component.h / max_h).min(component.plane_width - 1);
                    let sample_y = (y * component.v / max_v).min(component.plane_height - 1);
                    *slot = component.samples[sample_y * component.plane_width + sample_x] as f32;
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

// ── Metadata readers and embedded thumbnails ──────────────────────────────

fn wic_metadata_serialize(entries: &[(String, String)]) -> Vec<u8> {
    let mut out = WIC_METADATA_READER_MAGIC.to_vec();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (key, value) in entries {
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

fn wic_metadata_deserialize(bytes: &[u8]) -> Vec<(String, String)> {
    if !bytes.starts_with(WIC_METADATA_READER_MAGIC) {
        return Vec::new();
    }
    let mut position = WIC_METADATA_READER_MAGIC.len();
    let Some(count_bytes) = bytes.get(position..position + 4) else {
        return Vec::new();
    };
    let count = u32::from_le_bytes([
        count_bytes[0],
        count_bytes[1],
        count_bytes[2],
        count_bytes[3],
    ]) as usize;
    position += 4;
    let mut entries = Vec::new();
    for _ in 0..count.min(4096) {
        let Some(key_len_bytes) = bytes.get(position..position + 4) else {
            break;
        };
        let key_len = u32::from_le_bytes([
            key_len_bytes[0],
            key_len_bytes[1],
            key_len_bytes[2],
            key_len_bytes[3],
        ]) as usize;
        position += 4;
        let Some(key) = bytes.get(position..position + key_len) else {
            break;
        };
        position += key_len;
        let Some(value_len_bytes) = bytes.get(position..position + 4) else {
            break;
        };
        let value_len = u32::from_le_bytes([
            value_len_bytes[0],
            value_len_bytes[1],
            value_len_bytes[2],
            value_len_bytes[3],
        ]) as usize;
        position += 4;
        let Some(value) = bytes.get(position..position + value_len) else {
            break;
        };
        position += value_len;
        entries.push((
            String::from_utf8_lossy(key).into_owned(),
            String::from_utf8_lossy(value).into_owned(),
        ));
    }
    entries
}

fn wic_exif_tag_name(tag: u16) -> Option<&'static str> {
    Some(match tag {
        270 => "ImageDescription",
        271 => "Make",
        272 => "Model",
        274 => "Orientation",
        305 => "Software",
        306 => "DateTime",
        315 => "Artist",
        33432 => "Copyright",
        36867 => "DateTimeOriginal",
        36868 => "DateTimeDigitized",
        _ => return None,
    })
}

fn wic_metadata_normalize_name(name: &str) -> String {
    let trimmed = name.trim_matches('\0').trim();
    if let Some(start) = trimmed.rfind("{str=")
        && let Some(end) = trimmed[start + 5..].find('}')
    {
        return trimmed[start + 5..start + 5 + end].to_string();
    }
    if let Some(start) = trimmed.rfind("{ushort=")
        && let Some(end) = trimmed[start + 8..].find('}')
        && let Ok(tag) = trimmed[start + 8..start + 8 + end].parse::<u16>()
    {
        return wic_exif_tag_name(tag)
            .map(str::to_string)
            .unwrap_or_else(|| tag.to_string());
    }
    trimmed.trim_start_matches('/').to_string()
}

fn wic_metadata_lookup(entries: &[(String, String)], name: &str) -> Option<String> {
    if let Some((_, value)) = entries.iter().find(|(key, _)| key == name) {
        return Some(value.clone());
    }
    let normalized = wic_metadata_normalize_name(name);
    entries
        .iter()
        .find(|(key, _)| key == &normalized)
        .map(|(_, value)| value.clone())
}

fn wic_png_chunks(bytes: &[u8], mut visit: impl FnMut(&[u8], &[u8])) {
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return;
    }
    let mut position = 8_usize;
    while position + 12 <= bytes.len() {
        let length = u32::from_be_bytes([
            bytes[position],
            bytes[position + 1],
            bytes[position + 2],
            bytes[position + 3],
        ]) as usize;
        let Some(end) = position
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
        else {
            break; // coverage: unreachable — on the 64-bit host a slice position is at most isize::MAX and length is u32, so position + 12 + length cannot overflow usize.
        };
        if end > bytes.len() {
            break;
        }
        let kind = &bytes[position + 4..position + 8];
        let data = &bytes[position + 8..position + 8 + length];
        visit(kind, data);
        if kind == b"IEND" {
            break;
        }
        position = end;
    }
}

fn wic_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

fn wic_png_inflate(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut inflater = flate2::read::ZlibDecoder::new(bytes);
    let mut out = Vec::new();
    inflater
        .by_ref()
        .take(16 * 1024 * 1024)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn wic_png_text_entries(bytes: &[u8]) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    wic_png_chunks(bytes, |kind, data| match kind {
        b"tEXt" => {
            let Some(split) = data.iter().position(|byte| *byte == 0) else {
                return;
            };
            let key = wic_latin1(&data[..split]);
            let value = wic_latin1(&data[split + 1..]);
            if !key.is_empty() {
                entries.push((key, value));
            }
        }
        b"iTXt" => {
            let Some(key_end) = data.iter().position(|byte| *byte == 0) else {
                return;
            };
            let key = wic_latin1(&data[..key_end]);
            let mut position = key_end + 1;
            if position + 2 > data.len() {
                return;
            }
            let compressed = data[position];
            let method = data[position + 1];
            position += 2;
            let Some(language_end) = data[position..].iter().position(|byte| *byte == 0) else {
                return;
            };
            position += language_end + 1;
            let Some(translated_end) = data[position..].iter().position(|byte| *byte == 0) else {
                return;
            };
            position += translated_end + 1;
            let text = &data[position..];
            let text = match (compressed, method) {
                (0, _) => String::from_utf8_lossy(text).into_owned(),
                (1, 0) => match wic_png_inflate(text) {
                    Some(inflated) => String::from_utf8_lossy(&inflated).into_owned(),
                    None => return,
                },
                _ => return,
            };
            if !key.is_empty() {
                entries.push((key, text));
            }
        }
        _ => {}
    });
    entries
}

fn wic_png_exif_chunk(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut exif = None;
    wic_png_chunks(bytes, |kind, data| {
        if kind == b"eXIf" && exif.is_none() {
            exif = Some(data.to_vec());
        }
    });
    exif
}

/// Locate the TIFF payload of the first APP1 Exif segment.
fn wic_jpeg_exif(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 4 || bytes[0] != 0xff || bytes[1] != 0xd8 {
        return None;
    }
    let mut position = 2_usize;
    while position + 4 <= bytes.len() {
        if bytes[position] != 0xff {
            return None;
        }
        while position < bytes.len() && bytes[position] == 0xff {
            position += 1;
        }
        let marker = *bytes.get(position)?;
        position += 1;
        if marker == 0xd9 || marker == 0xda {
            return None;
        }
        if marker == 0x01 || marker == 0xd8 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length =
            u16::from_be_bytes([*bytes.get(position)?, *bytes.get(position + 1)?]) as usize;
        if length < 2 || position + length > bytes.len() {
            return None;
        }
        let segment = &bytes[position + 2..position + length];
        if marker == 0xe1 && segment.starts_with(b"Exif\0\0") {
            return Some(&segment[6..]);
        }
        position += length;
    }
    None
}

fn wic_tiff_u16(bytes: &[u8], offset: usize, little: bool) -> Option<u16> {
    let pair = bytes.get(offset..offset + 2)?;
    Some(if little {
        u16::from_le_bytes([pair[0], pair[1]])
    } else {
        u16::from_be_bytes([pair[0], pair[1]])
    })
}

fn wic_tiff_u32(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
    let quad = bytes.get(offset..offset + 4)?;
    Some(if little {
        u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]])
    } else {
        u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]])
    })
}

struct WicTiffEntry {
    tag: u16,
    kind: u16,
    count: u32,
    offset: usize,
}

fn wic_tiff_ifd(bytes: &[u8], offset: usize, little: bool) -> Option<(Vec<WicTiffEntry>, usize)> {
    let count = wic_tiff_u16(bytes, offset, little)? as usize;
    if count > 4096 {
        return None;
    }
    let entries_start = offset + 2;
    if entries_start + count * 12 + 4 > bytes.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let base = entries_start + index * 12;
        entries.push(WicTiffEntry {
            tag: wic_tiff_u16(bytes, base, little)?,
            kind: wic_tiff_u16(bytes, base + 2, little)?,
            count: wic_tiff_u32(bytes, base + 4, little)?,
            offset: base,
        });
    }
    let next = wic_tiff_u32(bytes, entries_start + count * 12, little)? as usize;
    Some((entries, next))
}

fn wic_tiff_entry_data<'a>(
    bytes: &'a [u8],
    entry: &WicTiffEntry,
    little: bool,
) -> Option<&'a [u8]> {
    let size = match entry.kind {
        1 | 2 | 7 => 1_usize,
        3 => 2,
        4 | 9 => 4,
        5 | 10 => 8,
        _ => return None,
    };
    let total = size.checked_mul(entry.count as usize)?;
    let offset = if total <= 4 {
        entry.offset + 8
    } else {
        wic_tiff_u32(bytes, entry.offset + 8, little)? as usize
    };
    bytes.get(offset..offset.checked_add(total)?)
}

fn wic_tiff_entry_u32(bytes: &[u8], entry: &WicTiffEntry, little: bool) -> Option<u32> {
    match entry.kind {
        3 => Some(u32::from(wic_tiff_u16(bytes, entry.offset + 8, little)?)),
        4 => wic_tiff_u32(bytes, entry.offset + 8, little),
        _ => None,
    }
}

fn wic_tiff_thumbnail(tiff: &[u8]) -> Option<Vec<u8>> {
    if tiff.len() < 8 {
        return None;
    }
    let little = match &tiff[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    if wic_tiff_u16(tiff, 2, little)? != 42 {
        return None;
    }
    let ifd0 = wic_tiff_u32(tiff, 4, little)? as usize;
    let (_, next_ifd) = wic_tiff_ifd(tiff, ifd0, little)?;
    if next_ifd == 0 {
        return None;
    }
    let (entries, _) = wic_tiff_ifd(tiff, next_ifd, little)?;
    let mut offset = None;
    let mut length = None;
    for entry in &entries {
        match entry.tag {
            513 => offset = wic_tiff_entry_u32(tiff, entry, little),
            514 => length = wic_tiff_entry_u32(tiff, entry, little),
            _ => {}
        }
    }
    let (offset, length) = (offset?, length?);
    let start = offset as usize;
    let end = start.checked_add(length as usize)?;
    tiff.get(start..end).map(<[u8]>::to_vec)
}

fn wic_exif_metadata(bytes: &[u8]) -> (Vec<(String, String)>, Option<Vec<u8>>) {
    let mut entries = Vec::new();
    let Some(tiff) = wic_jpeg_exif(bytes) else {
        return (entries, None);
    };
    if tiff.len() < 8 {
        return (entries, None);
    }
    let little = match &tiff[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return (entries, None),
    };
    let magic = wic_tiff_u16(tiff, 2, little).unwrap_or(0);
    if magic != 42 {
        return (entries, None);
    }
    let Some(ifd0) = wic_tiff_u32(tiff, 4, little).map(|offset| offset as usize) else {
        return (entries, None); // coverage: unreachable — tiff.len() >= 8 is checked above, so the 4-byte read at offset 4 always succeeds.
    };
    let Some((ifd0_entries, next_ifd)) = wic_tiff_ifd(tiff, ifd0, little) else {
        return (entries, None);
    };
    for entry in &ifd0_entries {
        let Some(name) = wic_exif_tag_name(entry.tag) else {
            continue;
        };
        let Some(data) = wic_tiff_entry_data(tiff, entry, little) else {
            continue;
        };
        if entry.kind == 2 {
            let end = data
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(data.len());
            entries.push((
                name.to_string(),
                String::from_utf8_lossy(&data[..end]).into_owned(),
            ));
        } else if let Some(value) = wic_tiff_entry_u32(tiff, entry, little) {
            entries.push((name.to_string(), value.to_string()));
        }
    }
    let mut thumbnail = None;
    if next_ifd != 0 {
        thumbnail = wic_tiff_thumbnail(tiff);
    }
    (entries, thumbnail)
}

fn wic_image_metadata_entries(bytes: &[u8], codec: u32) -> Vec<(String, String)> {
    match codec {
        1 => wic_png_text_entries(bytes),
        2 => wic_exif_metadata(bytes).0,
        3 => wic_gif_metadata_entries(bytes),
        4 => wic_tiff_metadata_entries(bytes),
        _ => Vec::new(),
    }
}

fn wic_image_thumbnail(bytes: &[u8], codec: u32) -> Option<Vec<u8>> {
    match codec {
        1 => wic_png_exif_chunk(bytes).and_then(|exif| wic_tiff_thumbnail(&exif)),
        2 => wic_exif_metadata(bytes).1,
        4 => wic_tiff_thumbnail(bytes),
        _ => None,
    }
}

/// GIF comments, application extensions and frame delays as metadata text.
fn wic_gif_metadata_entries(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(info) = wic_gif_parse(bytes) else {
        return Vec::new();
    };
    let mut entries = vec![("FrameCount".to_string(), info.frames.len().to_string())];
    if let Some(frame) = info.frames.first() {
        entries.push(("FrameDelay".to_string(), frame.delay_ms.to_string()));
    }
    for (index, frame) in info.frames.iter().enumerate() {
        entries.push((format!("FrameDelay{index}"), frame.delay_ms.to_string()));
        entries.push((format!("FrameLeft{index}"), frame.left.to_string()));
        entries.push((format!("FrameTop{index}"), frame.top.to_string()));
        entries.push((format!("FrameWidth{index}"), frame.width.to_string()));
        entries.push((format!("FrameHeight{index}"), frame.height.to_string()));
        entries.push((format!("FrameDisposal{index}"), frame.disposal.to_string()));
    }
    for comment in info.comments {
        entries.push(("Comment".to_string(), comment));
    }
    for (identifier, data) in info.applications {
        if identifier.starts_with("NETSCAPE") && data.len() >= 3 && data[0] == 1 {
            let loops = u16::from_le_bytes([data[1], data[2]]);
            entries.push(("LoopCount".to_string(), loops.to_string()));
        }
        entries.push(("Application".to_string(), identifier));
        entries.push(("ApplicationData".to_string(), wic_latin1(&data)));
    }
    entries
}

/// Basic baseline TIFF tags (ImageDescription, Make, Model, DateTime).
fn wic_tiff_metadata_entries(bytes: &[u8]) -> Vec<(String, String)> {
    let mut entries = vec![(
        "FrameCount".to_string(),
        wic_tiff_frame_offsets(bytes).len().to_string(),
    )];
    let Some((little, ifd)) = wic_tiff_header(bytes) else {
        return Vec::new();
    };
    let Some((ifd_entries, _)) = wic_tiff_ifd(bytes, ifd, little) else {
        return entries;
    };
    for entry in &ifd_entries {
        let Some(name) = wic_exif_tag_name(entry.tag) else {
            continue;
        };
        let Some(data) = wic_tiff_entry_data(bytes, entry, little) else {
            continue;
        };
        if entry.kind == 2 {
            let end = data
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(data.len());
            entries.push((
                name.to_string(),
                String::from_utf8_lossy(&data[..end]).into_owned(),
            ));
        } else if let Some(value) = wic_tiff_entry_u32(bytes, entry, little) {
            entries.push((name.to_string(), value.to_string()));
        }
    }
    entries
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
    methods.push(HostThunk::WicEncoderUnsupported);
    methods.push(HostThunk::WicEncoderUnsupported);
    methods.push(HostThunk::WicFrameEncodeUnsupported);
    methods
}

#[allow(dead_code)] // the frame-decode vtable builder
fn wic_frame_decode_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    wic_source_methods(&mut methods);
    methods.push(HostThunk::WicDecoderUnsupported);
    methods.push(HostThunk::WicEncoderUnsupported);
    methods.push(HostThunk::WicFrameEncodeUnsupported);
    methods
}

#[allow(dead_code)] // the metadata-query-reader vtable builder
fn wic_metadata_reader_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::WicSourceGetPixelFormat);
    methods.push(HostThunk::WicGetMetadataContentSize);
    methods.push(HostThunk::WicMatchMetadataContent);
    methods.push(HostThunk::WicSerializeMetadataContent);
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
    fn format_converter_translates_between_pixel_layouts_and_rejects_dont_care() {
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

            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_DONT_CARE);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFormatConverterInitialize,
                    &[converter as u32, bitmap as u32, FORMAT as u32, 0, 0, 0]
                ),
                u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT),
                "DONT_CARE is not a destination format"
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFormatConverterSetPixelFormat,
                    &[converter as u32, FORMAT as u32]
                ),
                u64::from(WIC_E_UNSUPPORTEDPIXELFORMAT)
            );
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_32BPP_BGRA);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFormatConverterCanConvert,
                    &[converter as u32, FORMAT as u32, FORMAT as u32]
                ),
                0,
                "a supported pair reports success"
            );
            fixture
                .memory
                .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_DONT_CARE);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFormatConverterCanConvert,
                    &[converter as u32, FORMAT as u32, FORMAT as u32]
                ),
                1,
                "an unsupported pair returns S_FALSE"
            );
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
    fn dont_care_pixel_format_is_rejected() {
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
    fn jpeg_decoder_baseline_scan_and_truncated_scan_rejected() {
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
            let shortened = create_stream(&mut fixture, factory, &jpeg[..jpeg.len() - 12]);
            assert_eq!(
                create_decoder_from_stream(&mut fixture, factory, shortened).0,
                u64::from(WINCODEC_ERR_BADIMAGE),
                "a truncated baseline JPEG is rejected"
            );
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
                0,
                "the JPEG encoder exists alongside PNG"
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
                u64::from(WINCODEC_ERR_BADIMAGE),
                "progressive JPEG without tables or scans"
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

    // ── Adversarial codec tests ────────────────────────────────────────────

    const META_READER_OUT: u64 = 0x48_000;
    const META_VALUE_OUT: u64 = 0x48_100;
    const META_NAME: u64 = 0x49_000;
    const THUMBNAIL_OUT: u64 = 0x4a_000;

    fn build_png(
        width: u32,
        height: u32,
        depth: u8,
        color: u8,
        interlace: u8,
        extras: &[(&[u8; 4], Vec<u8>)],
        raw: &[u8],
    ) -> Vec<u8> {
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut header = Vec::with_capacity(13);
        header.extend_from_slice(&width.to_be_bytes());
        header.extend_from_slice(&height.to_be_bytes());
        header.extend_from_slice(&[depth, color, 0, 0, interlace]);
        wic_png_chunk(&mut out, b"IHDR", &header);
        for (kind, data) in extras {
            wic_png_chunk(&mut out, kind, data);
        }
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(raw).unwrap();
        let compressed = encoder.finish().unwrap();
        wic_png_chunk(&mut out, b"IDAT", &compressed);
        wic_png_chunk(&mut out, b"IEND", &[]);
        out
    }

    fn adam7_raw(width: usize, height: usize, value: impl Fn(usize, usize) -> u8) -> Vec<u8> {
        const PASSES: [(usize, usize, usize, usize); 7] = [
            (0, 0, 8, 8),
            (4, 0, 8, 8),
            (0, 4, 4, 8),
            (2, 0, 4, 4),
            (0, 2, 2, 4),
            (1, 0, 2, 2),
            (0, 1, 1, 2),
        ];
        let mut raw = Vec::new();
        for &(start_x, start_y, step_x, step_y) in &PASSES {
            if start_x >= width || start_y >= height {
                continue;
            }
            let pass_width = (width - start_x).div_ceil(step_x);
            let pass_height = (height - start_y).div_ceil(step_y);
            for row in 0..pass_height {
                raw.push(0);
                for column in 0..pass_width {
                    raw.push(value(start_x + column * step_x, start_y + row * step_y));
                }
            }
        }
        raw
    }

    fn png_text(keyword: &str, text: &str) -> Vec<u8> {
        let mut data = keyword.as_bytes().to_vec();
        data.push(0);
        data.extend_from_slice(text.as_bytes());
        data
    }

    fn png_itxt(keyword: &str, text: &str) -> Vec<u8> {
        let mut data = keyword.as_bytes().to_vec();
        data.push(0);
        data.extend_from_slice(&[0, 0]);
        data.push(0);
        data.push(0);
        data.extend_from_slice(text.as_bytes());
        data
    }

    fn write_test_utf16(fixture: &mut Fixture, address: u64, text: &str) {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        fixture.memory.map_bytes(address, &bytes);
    }

    fn read_propvariant_string(fixture: &Fixture, address: u64) -> String {
        assert_eq!(
            read_guest_u16(&fixture.memory, address).unwrap(),
            31,
            "VT_LPWSTR"
        );
        let pointer = read_ptr(fixture, address + 8);
        assert_ne!(pointer, 0);
        read_utf16_string(&fixture.memory, pointer).unwrap()
    }

    /// Pack MSB-first codes for the TIFF LZW fixture writer.
    fn tiff_lzw_literal_codes(data: &[u8]) -> Vec<u8> {
        let mut codes = vec![(256_u16, 9_u32)];
        let mut width = 9_u32;
        let mut next = 258_usize;
        for (index, byte) in data.iter().enumerate() {
            codes.push((u16::from(*byte), width));
            if index > 0 {
                next += 1;
                if next == (1 << width) - 1 && width < 12 {
                    width += 1;
                }
            }
        }
        codes.push((257, width));
        let mut out = Vec::new();
        let mut accumulator = 0_u64;
        let mut bits = 0_u32;
        for (code, width) in codes {
            accumulator = (accumulator << width) | u64::from(code);
            bits += width;
            while bits >= 8 {
                bits -= 8;
                out.push((accumulator >> bits) as u8);
            }
        }
        if bits > 0 {
            out.push((accumulator << (8 - bits)) as u8);
        }
        out
    }

    fn tiff_packbits_encode(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut position = 0_usize;
        while position < data.len() {
            let mut run = 1_usize;
            while position + run < data.len() && data[position + run] == data[position] && run < 128
            {
                run += 1;
            }
            if run >= 3 {
                out.push((257 - run) as u8);
                out.push(data[position]);
                position += run;
                continue;
            }
            let start = position;
            position += run;
            while position < data.len() && position - start < 128 {
                let mut next_run = 1_usize;
                while position + next_run < data.len()
                    && data[position + next_run] == data[position]
                    && next_run < 128
                {
                    next_run += 1;
                }
                if next_run >= 3 {
                    break;
                }
                position += next_run;
            }
            let count = (position - start).min(128);
            out.push((count - 1) as u8);
            out.extend_from_slice(&data[start..start + count]);
            position = start + count;
        }
        out
    }

    fn gif_pack_codes(codes: &[(u16, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut accumulator = 0_u32;
        let mut bits = 0_u32;
        for (code, width) in codes {
            accumulator |= u32::from(*code) << bits;
            bits += width;
            while bits >= 8 {
                out.push(accumulator as u8);
                accumulator >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 {
            out.push(accumulator as u8);
        }
        out
    }

    fn gif_literal_stream(indices: &[u8]) -> Vec<u8> {
        let mut codes = vec![(256_u16, 9_u32)];
        codes.extend(indices.iter().map(|index| (u16::from(*index), 9_u32)));
        codes.push((257, 9));
        gif_pack_codes(&codes)
    }

    fn gif_sub_blocks(out: &mut Vec<u8>, data: &[u8]) {
        for chunk in data.chunks(255) {
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
        out.push(0);
    }

    fn gif_interlaced(indices: &[u8], width: usize, height: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(indices.len());
        for (start, step) in [(0, 8), (4, 8), (2, 4), (1, 2)] {
            let mut row = start;
            while row < height {
                out.extend_from_slice(&indices[row * width..(row + 1) * width]);
                row += step;
            }
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn build_gif(
        width: u16,
        height: u16,
        palette: &[[u8; 3]; 256],
        frames: &[(Vec<u8>, Option<u8>, u16)],
        interlaced: bool,
        comment: Option<&str>,
        application: Option<(&str, &[u8])>,
    ) -> Vec<u8> {
        let mut out = b"GIF89a".to_vec();
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&[0xf7, 0, 0]);
        for color in palette {
            out.extend_from_slice(color);
        }
        if let Some(comment) = comment {
            out.extend_from_slice(&[0x21, 0xfe]);
            gif_sub_blocks(&mut out, comment.as_bytes());
        }
        if let Some((identifier, data)) = application {
            out.extend_from_slice(&[0x21, 0xff, 11]);
            let mut name = identifier.as_bytes().to_vec();
            name.resize(11, 0);
            out.extend_from_slice(&name);
            gif_sub_blocks(&mut out, data);
        }
        for (indices, transparent, delay) in frames {
            out.extend_from_slice(&[0x21, 0xf9, 4, u8::from(transparent.is_some())]);
            out.extend_from_slice(&(delay / 10).to_le_bytes());
            out.push(transparent.unwrap_or(0));
            out.push(0);
            out.push(0x2c);
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&width.to_le_bytes());
            out.extend_from_slice(&height.to_le_bytes());
            out.push(if interlaced { 0x40 } else { 0 });
            out.push(8);
            let ordered = if interlaced {
                gif_interlaced(indices, width as usize, height as usize)
            } else {
                indices.clone()
            };
            gif_sub_blocks(&mut out, &gif_literal_stream(&ordered));
        }
        out.push(0x3b);
        out
    }

    fn tiff_put_u16(out: &mut [u8], offset: usize, value: u16, little: bool) {
        out[offset..offset + 2].copy_from_slice(&if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        });
    }

    fn tiff_put_u32(out: &mut [u8], offset: usize, value: u32, little: bool) {
        out[offset..offset + 4].copy_from_slice(&if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        });
    }

    fn build_tiff_rgb(
        width: u32,
        height: u32,
        frames: &[(Vec<u8>, u16)],
        little: bool,
        metadata: &[(u16, &str)],
    ) -> Vec<u8> {
        let entry_count = 10 + metadata.len();
        let ifd_size = 2 + entry_count * 12 + 4;
        let mut data_offset = 8_usize;
        let mut data_offsets = Vec::new();
        for (payload, _) in frames {
            data_offsets.push(data_offset);
            data_offset += payload.len();
            if data_offset % 2 != 0 {
                data_offset += 1;
            }
        }
        let first_ifd = data_offset;
        let bits_offset = first_ifd + ifd_size * frames.len();
        let mut strings_offset = bits_offset + 6;
        let mut string_offsets = Vec::new();
        for (_, text) in metadata {
            string_offsets.push(strings_offset);
            strings_offset += text.len() + 1;
        }
        let total = strings_offset;
        let mut out = vec![0_u8; total];
        out[..2].copy_from_slice(if little { b"II" } else { b"MM" });
        tiff_put_u16(&mut out, 2, 42, little);
        tiff_put_u32(&mut out, 4, first_ifd as u32, little);
        for (index, (payload, _)) in frames.iter().enumerate() {
            let offset = data_offsets[index];
            out[offset..offset + payload.len()].copy_from_slice(payload);
        }
        for (index, (_, compression)) in frames.iter().enumerate() {
            let ifd = first_ifd + index * ifd_size;
            tiff_put_u16(&mut out, ifd, entry_count as u16, little);
            let mut entries = Vec::new();
            entries.push((256_u16, 4_u16, 1_u32, width));
            entries.push((257, 4, 1, height));
            entries.push((258, 3, 3, bits_offset as u32));
            entries.push((259, 3, 1, u32::from(*compression)));
            entries.push((262, 3, 1, 2));
            entries.push((273, 4, 1, data_offsets[index] as u32));
            entries.push((277, 3, 1, 3));
            entries.push((278, 4, 1, height));
            entries.push((279, 4, 1, frames[index].0.len() as u32));
            entries.push((284, 3, 1, 1));
            for (meta_index, (tag, text)) in metadata.iter().enumerate() {
                entries.push((
                    *tag,
                    2,
                    text.len() as u32 + 1,
                    string_offsets[meta_index] as u32,
                ));
            }
            entries.sort_by_key(|(tag, _, _, _)| *tag);
            for (entry_index, (tag, kind, count, value)) in entries.into_iter().enumerate() {
                let base = ifd + 2 + entry_index * 12;
                tiff_put_u16(&mut out, base, tag, little);
                tiff_put_u16(&mut out, base + 2, kind, little);
                tiff_put_u32(&mut out, base + 4, count, little);
                if kind == 3 && count == 1 {
                    tiff_put_u16(&mut out, base + 8, value as u16, little);
                    tiff_put_u16(&mut out, base + 10, 0, little);
                } else {
                    tiff_put_u32(&mut out, base + 8, value, little);
                }
            }
            let next = if index + 1 < frames.len() {
                (ifd + ifd_size) as u32
            } else {
                0
            };
            tiff_put_u32(&mut out, ifd + 2 + entry_count * 12, next, little);
        }
        for index in 0..3 {
            tiff_put_u16(&mut out, bits_offset + index * 2, 8, little);
        }
        for (index, (_, text)) in metadata.iter().enumerate() {
            let offset = string_offsets[index];
            out[offset..offset + text.len()].copy_from_slice(text.as_bytes());
            out[offset + text.len()] = 0;
        }
        out
    }

    fn metadata_reader_for(fixture: &mut Fixture, factory: u64, bytes: &[u8]) -> (u64, u64) {
        let stream = create_stream(fixture, factory, bytes);
        let (hr, decoder) = create_decoder_from_stream(fixture, factory, stream);
        assert_eq!(hr, 0, "decoder creation");
        fixture.memory.map_bytes(META_READER_OUT, &[0_u8; 8]);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::WicDecoderUnsupported,
                &[decoder as u32, META_READER_OUT as u32]
            ),
            0,
            "GetMetadataQueryReader"
        );
        let reader = read_ptr(fixture, META_READER_OUT);
        assert_ne!(reader, 0);
        (decoder, reader)
    }

    fn metadata_query(fixture: &mut Fixture, reader: u64, name: &str) -> (u64, Option<String>) {
        write_test_utf16(fixture, META_NAME, name);
        fixture.memory.map_bytes(META_VALUE_OUT, &[0_u8; 24]);
        let hr = dispatch_x86(
            fixture,
            HostThunk::WicGetMetadataContentSize,
            &[reader as u32, META_NAME as u32, META_VALUE_OUT as u32],
        );
        let value = (hr == 0).then(|| read_propvariant_string(fixture, META_VALUE_OUT));
        (hr, value)
    }

    fn exif_put_u16(out: &mut [u8], offset: usize, value: u16) {
        out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn exif_put_u32(out: &mut [u8], offset: usize, value: u32) {
        out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn exif_tiff(make: &str, model: &str, date: &str, thumbnail: &[u8]) -> Vec<u8> {
        let ifd0_offset = 8_usize;
        let ifd0_size = 2 + 3 * 12 + 4;
        let strings_start = ifd0_offset + ifd0_size;
        let make_offset = strings_start;
        let model_offset = make_offset + make.len() + 1;
        let date_offset = model_offset + model.len() + 1;
        let ifd1_offset = date_offset + date.len() + 1;
        let ifd1_size = 2 + 2 * 12 + 4;
        let thumbnail_offset = ifd1_offset + ifd1_size;
        let mut out = vec![0_u8; thumbnail_offset + thumbnail.len()];
        out[..2].copy_from_slice(b"II");
        exif_put_u16(&mut out, 2, 42);
        exif_put_u32(&mut out, 4, ifd0_offset as u32);
        exif_put_u16(&mut out, ifd0_offset, 3);
        let entry = |index: usize| ifd0_offset + 2 + index * 12;
        exif_put_u16(&mut out, entry(0), 271);
        exif_put_u16(&mut out, entry(0) + 2, 2);
        exif_put_u32(&mut out, entry(0) + 4, make.len() as u32 + 1);
        exif_put_u32(&mut out, entry(0) + 8, make_offset as u32);
        exif_put_u16(&mut out, entry(1), 272);
        exif_put_u16(&mut out, entry(1) + 2, 2);
        exif_put_u32(&mut out, entry(1) + 4, model.len() as u32 + 1);
        exif_put_u32(&mut out, entry(1) + 8, model_offset as u32);
        exif_put_u16(&mut out, entry(2), 306);
        exif_put_u16(&mut out, entry(2) + 2, 2);
        exif_put_u32(&mut out, entry(2) + 4, date.len() as u32 + 1);
        exif_put_u32(&mut out, entry(2) + 8, date_offset as u32);
        exif_put_u32(&mut out, ifd0_offset + 2 + 3 * 12, ifd1_offset as u32);
        out[make_offset..make_offset + make.len()].copy_from_slice(make.as_bytes());
        out[model_offset..model_offset + model.len()].copy_from_slice(model.as_bytes());
        out[date_offset..date_offset + date.len()].copy_from_slice(date.as_bytes());
        exif_put_u16(&mut out, ifd1_offset, 2);
        exif_put_u16(&mut out, ifd1_offset + 2, 513);
        exif_put_u16(&mut out, ifd1_offset + 4, 4);
        exif_put_u32(&mut out, ifd1_offset + 6, 1);
        exif_put_u32(&mut out, ifd1_offset + 10, thumbnail_offset as u32);
        exif_put_u16(&mut out, ifd1_offset + 14, 514);
        exif_put_u16(&mut out, ifd1_offset + 16, 4);
        exif_put_u32(&mut out, ifd1_offset + 18, 1);
        exif_put_u32(&mut out, ifd1_offset + 22, thumbnail.len() as u32);
        out[thumbnail_offset..].copy_from_slice(thumbnail);
        out
    }

    fn insert_exif(jpeg: &[u8], tiff: &[u8]) -> Vec<u8> {
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(tiff);
        let mut segment = Vec::new();
        wic_jpeg_push_segment(&mut segment, 0xe1, &payload);
        let mut out = jpeg[..2].to_vec();
        out.extend_from_slice(&segment);
        out.extend_from_slice(&jpeg[2..]);
        out
    }

    fn progressive_jpeg_fixture() -> Vec<u8> {
        let mut out = vec![0xff, 0xd8];
        let mut quant = vec![0_u8];
        quant.extend_from_slice(&[1_u8; 64]);
        wic_jpeg_push_segment(&mut out, 0xdb, &quant);
        wic_jpeg_push_segment(&mut out, 0xc2, &[8, 0, 8, 0, 8, 1, 1, 0x11, 0]);
        let tables = WicJpegEncoderTables::build().expect("standard tables");
        wic_jpeg_push_segment(
            &mut out,
            0xc4,
            &wic_jpeg_huffman_payload(0, 0, &WIC_JPEG_DC_LUMA_COUNTS, &WIC_JPEG_DC_LUMA_SYMBOLS),
        );
        wic_jpeg_push_segment(
            &mut out,
            0xc4,
            &wic_jpeg_huffman_payload(1, 0, &WIC_JPEG_AC_LUMA_COUNTS, &WIC_JPEG_AC_LUMA_SYMBOLS),
        );
        let mut writer = WicJpegBitWriter::new();
        assert!(tables.dc_luma.write(3, &mut writer));
        writer.write_bits(4, 3);
        writer.flush();
        wic_jpeg_push_segment(&mut out, 0xda, &[1, 1, 0, 0, 0, 0x01]);
        out.extend_from_slice(&writer.out);
        let mut writer = WicJpegBitWriter::new();
        writer.write_bits(1, 1);
        writer.flush();
        wic_jpeg_push_segment(&mut out, 0xda, &[1, 1, 0, 0, 0, 0x10]);
        out.extend_from_slice(&writer.out);
        let mut writer = WicJpegBitWriter::new();
        assert!(tables.ac_luma.write(0x01, &mut writer));
        writer.write_bits(1, 1);
        assert!(tables.ac_luma.write(0x00, &mut writer));
        writer.flush();
        wic_jpeg_push_segment(&mut out, 0xda, &[1, 1, 0, 1, 5, 0x01]);
        out.extend_from_slice(&writer.out);
        let mut writer = WicJpegBitWriter::new();
        assert!(tables.ac_luma.write(0x00, &mut writer));
        writer.write_bits(1, 1);
        writer.flush();
        wic_jpeg_push_segment(&mut out, 0xda, &[1, 1, 0, 1, 5, 0x10]);
        out.extend_from_slice(&writer.out);
        out.extend_from_slice(&[0xff, 0xd9]);
        out
    }

    fn progressive_restart_fixture() -> Vec<u8> {
        let mut out = vec![0xff, 0xd8];
        let mut quant = vec![0_u8];
        quant.extend_from_slice(&[1_u8; 64]);
        wic_jpeg_push_segment(&mut out, 0xdb, &quant);
        wic_jpeg_push_segment(&mut out, 0xc2, &[8, 0, 8, 0, 16, 1, 1, 0x11, 0]);
        let tables = WicJpegEncoderTables::build().expect("standard tables");
        wic_jpeg_push_segment(
            &mut out,
            0xc4,
            &wic_jpeg_huffman_payload(0, 0, &WIC_JPEG_DC_LUMA_COUNTS, &WIC_JPEG_DC_LUMA_SYMBOLS),
        );
        wic_jpeg_push_segment(
            &mut out,
            0xc4,
            &wic_jpeg_huffman_payload(1, 0, &WIC_JPEG_AC_LUMA_COUNTS, &WIC_JPEG_AC_LUMA_SYMBOLS),
        );
        wic_jpeg_push_segment(&mut out, 0xdd, &[0, 1]);
        wic_jpeg_push_segment(&mut out, 0xda, &[1, 1, 0, 0, 0, 0]);
        let mut writer = WicJpegBitWriter::new();
        assert!(tables.dc_luma.write(3, &mut writer));
        writer.write_bits(4, 3);
        writer.flush();
        out.extend_from_slice(&writer.out);
        out.extend_from_slice(&[0xff, 0xd0]);
        let mut writer = WicJpegBitWriter::new();
        assert!(tables.dc_luma.write(0, &mut writer));
        writer.flush();
        out.extend_from_slice(&writer.out);
        wic_jpeg_push_segment(&mut out, 0xda, &[1, 1, 0, 1, 63, 0]);
        let mut writer = WicJpegBitWriter::new();
        assert!(tables.ac_luma.write(0, &mut writer));
        writer.flush();
        out.extend_from_slice(&writer.out);
        out.extend_from_slice(&[0xff, 0xd0]);
        let mut writer = WicJpegBitWriter::new();
        assert!(tables.ac_luma.write(0, &mut writer));
        writer.flush();
        out.extend_from_slice(&writer.out);
        out.extend_from_slice(&[0xff, 0xd9]);
        out
    }

    fn jpeg_psnr(source: &[u8], decoded: &[u8], pixels: usize) -> f64 {
        let mut error = 0_f64;
        for index in 0..pixels {
            for channel in 0..3 {
                let difference = f64::from(source[index * 4 + channel])
                    - f64::from(decoded[index * 4 + channel]);
                error += difference * difference;
            }
        }
        let mse = error / (pixels as f64 * 3.0);
        if mse == 0.0 {
            return f64::INFINITY;
        }
        10.0 * (255.0_f64 * 255.0 / mse).log10()
    }

    #[test]
    fn png_palette_trns_low_bit_depth_and_invalid_trns_rejected() {
        let palette = vec![255, 0, 0, 0, 255, 0, 0, 0, 255];
        let png = build_png(
            4,
            1,
            8,
            3,
            0,
            &[(b"PLTE", palette), (b"tRNS", vec![0, 128])],
            &[0, 0, 1, 2, 1],
        );
        let image = wic_decode_png(&png).expect("palette PNG");
        assert_eq!(image.width, 4);
        assert_eq!(
            &image.pixels[..],
            &[0, 0, 255, 0, 0, 255, 0, 128, 255, 0, 0, 255, 0, 255, 0, 128],
            "palette colors with tRNS alpha"
        );

        let gray2 = build_png(4, 1, 2, 0, 0, &[], &[0, 0b0001_1011]);
        let image = wic_decode_png(&gray2).expect("2-bit gray PNG");
        assert_eq!(
            image
                .pixels
                .chunks_exact(4)
                .map(|pixel| pixel[0])
                .collect::<Vec<_>>(),
            vec![0, 85, 170, 255],
            "2-bit gray unpacking and scaling"
        );

        let gray4 = build_png(4, 1, 4, 0, 0, &[], &[0, 0x01, 0x23]);
        let image = wic_decode_png(&gray4).expect("4-bit gray PNG");
        assert_eq!(
            image
                .pixels
                .chunks_exact(4)
                .map(|pixel| pixel[0])
                .collect::<Vec<_>>(),
            vec![0, 17, 34, 51],
            "4-bit gray unpacking and scaling"
        );

        let gray1 = build_png(8, 1, 1, 0, 0, &[], &[0, 0b1010_1010]);
        let image = wic_decode_png(&gray1).expect("1-bit gray PNG");
        assert_eq!(
            image
                .pixels
                .chunks_exact(4)
                .map(|pixel| pixel[0])
                .collect::<Vec<_>>(),
            vec![255, 0, 255, 0, 255, 0, 255, 0],
            "1-bit gray unpacking"
        );

        let empty_trns = build_png(
            1,
            1,
            8,
            3,
            0,
            &[(b"PLTE", vec![1, 2, 3]), (b"tRNS", Vec::new())],
            &[0, 0],
        );
        assert_eq!(
            wic_decode_png(&empty_trns).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an empty palette tRNS chunk is invalid"
        );
    }

    #[test]
    fn png_16_bit_samples_and_truncated_scanlines_rejected() {
        let rgb = build_png(
            2,
            1,
            16,
            2,
            0,
            &[],
            &[
                0, 0x12, 0x34, 0xab, 0xcd, 0x00, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x01,
            ],
        );
        let image = wic_decode_png(&rgb).expect("16-bit RGB PNG");
        assert_eq!(
            &image.pixels[..],
            &[0x00, 0xab, 0x12, 255, 0x00, 0x80, 0xff, 255],
            "16-bit RGB downsamples with correct scaling"
        );

        let gray = build_png(2, 1, 16, 0, 0, &[], &[0, 0x12, 0x34, 0xab, 0xcd]);
        let image = wic_decode_png(&gray).expect("16-bit gray PNG");
        assert_eq!(
            &image.pixels[..],
            &[0x12, 0x12, 0x12, 255, 0xab, 0xab, 0xab, 255]
        );

        let transparent = build_png(2, 1, 8, 0, 0, &[(b"tRNS", vec![0, 7])], &[0, 7, 9]);
        let image = wic_decode_png(&transparent).expect("gray tRNS PNG");
        assert_eq!(
            &image.pixels[..],
            &[7, 7, 7, 0, 9, 9, 9, 255],
            "the matching gray sample is transparent"
        );

        let truncated = build_png(2, 1, 16, 0, 0, &[], &[0, 0x12]);
        assert_eq!(
            wic_decode_png(&truncated).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a short 16-bit scanline is rejected"
        );
    }

    #[test]
    fn png_adam7_interlaced_pixels_and_bad_pass_length_rejected() {
        let raw = adam7_raw(5, 5, |x, y| (x as u8) * 40 + y as u8 * 3);
        let png = build_png(5, 5, 8, 0, 1, &[], &raw);
        let image = wic_decode_png(&png).expect("Adam7 PNG");
        for y in 0..5 {
            for x in 0..5 {
                let expected = (x as u8) * 40 + y as u8 * 3;
                let pixel = &image.pixels[(y * 5 + x) * 4..(y * 5 + x) * 4 + 4];
                assert_eq!(pixel, &[expected, expected, expected, 255], "pixel {x},{y}");
            }
        }

        // A 1x1 Adam7 image exercises passes that are skipped entirely.
        let single = build_png(1, 1, 8, 0, 1, &[], &adam7_raw(1, 1, |_, _| 9));
        let image = wic_decode_png(&single).expect("1x1 Adam7 PNG");
        assert_eq!(&image.pixels[..], &[9, 9, 9, 255]);

        let short = build_png(5, 5, 8, 0, 1, &[], &raw[..raw.len() - 1]);
        assert_eq!(
            wic_decode_png(&short).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a short Adam7 pass is rejected"
        );
    }

    #[test]
    fn png_unknown_critical_chunk_and_bad_palette_index_are_rejected() {
        let critical = build_png(1, 1, 8, 0, 0, &[(b"CRIT", Vec::new())], &[0, 7]);
        assert_eq!(
            wic_decode_png(&critical).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION
        );
        let bad_index = build_png(1, 1, 8, 3, 0, &[(b"PLTE", vec![1, 2, 3])], &[0, 5]);
        assert_eq!(
            wic_decode_png(&bad_index).unwrap_err(),
            WINCODEC_ERR_BADIMAGE
        );
    }

    #[test]
    fn progressive_jpeg_spectral_refinement_and_truncated_stream_rejected() {
        let jpeg = progressive_jpeg_fixture();
        let image = wic_decode_jpeg(&jpeg).expect("progressive JPEG");
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
        let mut coefficients = [0_i32; 64];
        coefficients[0] = 9;
        coefficients[1] = 3;
        let mut expected = [0_u8; 64];
        wic_jpeg_idct(&coefficients, &cosine, &mut expected);
        for (index, value) in expected.iter().enumerate() {
            assert_eq!(
                &image.pixels[index * 4..index * 4 + 4],
                &[*value, *value, *value, 255],
                "progressive pixel {index}"
            );
        }
        assert_eq!(
            wic_decode_jpeg(&jpeg[..40]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated progressive scan is rejected"
        );
    }

    #[test]
    fn progressive_jpeg_restart_markers_and_corrupt_restart_rejected() {
        let jpeg = progressive_restart_fixture();
        let image = wic_decode_jpeg(&jpeg).expect("progressive restart JPEG");
        for y in 0..8 {
            for x in 0..16 {
                let expected = if x < 8 { 129 } else { 128 };
                let pixel = &image.pixels[(y * 16 + x) * 4..(y * 16 + x) * 4 + 4];
                assert_eq!(pixel, &[expected, expected, expected, 255], "pixel {x},{y}");
            }
        }
        let mut corrupt = jpeg.clone();
        let position = corrupt
            .windows(2)
            .position(|window| window == [0xff, 0xd0])
            .expect("restart marker");
        corrupt[position + 1] = 0xd9;
        assert_eq!(
            wic_decode_jpeg(&corrupt).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a RESTART marker replaced by EOI truncates the scan"
        );
    }

    #[test]
    fn jpeg_422_and_444_sampling_and_truncated_scan_rejected() {
        let mut bgra = vec![0_u8; 32 * 8 * 4];
        for y in 0..8 {
            for x in 0..32 {
                let index = (y * 32 + x) * 4;
                if x < 16 {
                    bgra[index..index + 4].copy_from_slice(&[0, 0, 255, 255]);
                } else {
                    bgra[index..index + 4].copy_from_slice(&[255, 0, 0, 255]);
                }
            }
        }
        let jpeg = wic_encode_jpeg_sampled(32, 8, &bgra, None, (2, 1)).expect("4:2:2 encode");
        let image = wic_decode_jpeg(&jpeg).expect("4:2:2 decode");
        for y in 0..8 {
            for x in [3_usize, 4, 27, 28] {
                let index = (y * 32 + x) * 4;
                if x < 16 {
                    assert!(image.pixels[index + 2] > 200, "red region {x},{y}");
                    assert!(image.pixels[index] < 60, "red region blue {x},{y}");
                } else {
                    assert!(image.pixels[index] > 200, "blue region {x},{y}");
                    assert!(image.pixels[index + 2] < 60, "blue region red {x},{y}");
                }
            }
        }

        let solid = [30_u8, 60, 90, 255].repeat(8 * 8);
        let jpeg = wic_encode_jpeg_sampled(8, 8, &solid, None, (1, 1)).expect("4:4:4 encode");
        let image = wic_decode_jpeg(&jpeg).expect("4:4:4 decode");
        for pixel in image.pixels.chunks_exact(4) {
            assert!((i32::from(pixel[0]) - 30).abs() <= 6);
            assert!((i32::from(pixel[1]) - 60).abs() <= 6);
            assert!((i32::from(pixel[2]) - 90).abs() <= 6);
        }

        assert_eq!(
            wic_decode_jpeg(&jpeg[..jpeg.len() / 2]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a scan truncated mid-entropy is rejected"
        );
        assert_eq!(
            wic_encode_jpeg_sampled(8, 8, &solid[..solid.len() - 1], None, (1, 1)).unwrap_err(),
            E_INVALIDARG,
            "short pixel input is invalid"
        );
    }

    #[test]
    fn jpeg_encoder_round_trip_psnr_and_truncated_stream_rejected() {
        let width = 32_u32;
        let height = 24_u32;
        let mut bgra = vec![0_u8; width as usize * height as usize * 4];
        for y in 0..height as usize {
            for x in 0..width as usize {
                let index = (y * width as usize + x) * 4;
                let red = (x * 255 / (width as usize - 1)) as u8;
                let green = (y * 255 / (height as usize - 1)) as u8;
                let blue = ((x + y) * 255 / (width as usize + height as usize - 2)) as u8;
                bgra[index..index + 4].copy_from_slice(&[blue, green, red, 255]);
            }
        }
        let jpeg = wic_encode_jpeg(width, height, &bgra, None).expect("JPEG encode");
        assert_eq!(&jpeg[..2], &[0xff, 0xd8]);
        assert!(jpeg.windows(2).any(|window| window == [0xff, 0xc0]));
        let image = wic_decode_jpeg(&jpeg).expect("JPEG decode");
        assert_eq!((image.width, image.height), (width, height));
        let psnr = jpeg_psnr(&bgra, &image.pixels, width as usize * height as usize);
        assert!(psnr > 30.0, "round-trip PSNR {psnr}");
        assert_eq!(
            jpeg_psnr(&bgra, &bgra, width as usize * height as usize),
            f64::INFINITY,
            "identical images have infinite PSNR (zero MSE boundary)"
        );
        assert_eq!(
            jpeg_psnr(&bgra, &bgra, 0).is_nan(),
            true,
            "zero-pixel input produces the NaN MSE boundary"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg[..jpeg.len() / 2]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated baseline JPEG is rejected"
        );

        with_big_stack(move || {
            let mut fixture = x86_fixture("wic-jpeg-encode-com");
            let factory = create_factory(&mut fixture);
            fixture.memory.map_bytes(STREAM_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateStream,
                    &[factory as u32, STREAM_OUT as u32]
                ),
                0
            );
            let stream = read_ptr(&fixture, STREAM_OUT);
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
            fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCreateNewFrame,
                    &[encoder as u32, FRAME_OUT as u32, 0]
                ),
                0
            );
            let frame = read_ptr(&fixture, FRAME_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeSetSize,
                    &[frame as u32, width, height]
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
            fixture.memory.map_bytes(ENCODE_BYTES, &bgra);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeWritePixels,
                    &[
                        frame as u32,
                        height,
                        width * 4,
                        bgra.len() as u32,
                        ENCODE_BYTES as u32
                    ]
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
            let encoded = fixture
                .runtime
                .wic
                .objects
                .get(&stream)
                .expect("encoded stream")
                .stream
                .clone();
            assert!(encoded.starts_with(&[0xff, 0xd8]));
            assert!(encoded.windows(2).any(|window| window == [0xff, 0xc0]));
            let decoded = wic_decode_jpeg(&encoded).expect("COM JPEG decodes");
            let psnr = jpeg_psnr(&bgra, &decoded.pixels, width as usize * height as usize);
            assert!(psnr > 28.0, "COM JPEG PSNR {psnr}");
        });
    }

    #[test]
    fn metadata_readers_expose_png_text_and_exif_tags() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-metadata-png");
            let factory = create_factory(&mut fixture);
            let png = build_png(
                2,
                2,
                8,
                6,
                0,
                &[
                    (b"tEXt", png_text("Author", "Casa")),
                    (b"iTXt", png_itxt("Comment", "wave-eight")),
                ],
                &[0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 2, 3, 4, 5, 6, 7, 8, 9],
            );
            let (_, reader) = metadata_reader_for(&mut fixture, factory, &png);
            fixture.memory.map_bytes(CONTAINER_OUT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetPixelFormat,
                    &[reader as u32, CONTAINER_OUT as u32]
                ),
                0
            );
            assert_eq!(
                fixture.memory.read_bytes(CONTAINER_OUT, 16).unwrap(),
                GUID_CONTAINER_FORMAT_PNG
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "Author"),
                (0, Some("Casa".to_string()))
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "/tEXt/{str=Comment}"),
                (0, Some("wave-eight".to_string()))
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "Missing"),
                (u64::from(WINCODEC_ERR_PROPERTYNOTFOUND), None)
            );
        });

        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-metadata-jpeg");
            let factory = create_factory(&mut fixture);
            let thumbnail = wic_encode_jpeg(4, 4, &[10_u8, 20, 30, 255].repeat(16), None)
                .expect("thumbnail encode");
            let tiff = exif_tiff("CasaCam", "Model X", "2026:10:20 12:34:56", &thumbnail);
            let main =
                wic_encode_jpeg(8, 8, &[40_u8, 50, 60, 255].repeat(64), None).expect("main encode");
            let jpeg = insert_exif(&main, &tiff);
            let (decoder, reader) = metadata_reader_for(&mut fixture, factory, &jpeg);
            assert_eq!(
                metadata_query(&mut fixture, reader, "Make"),
                (0, Some("CasaCam".to_string()))
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "Model"),
                (0, Some("Model X".to_string()))
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "DateTime"),
                (0, Some("2026:10:20 12:34:56".to_string()))
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "/app1/ifd/{ushort=271}"),
                (0, Some("CasaCam".to_string()))
            );

            let frame = decode_first_frame(&mut fixture, decoder);
            fixture.memory.map_bytes(THUMBNAIL_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeUnsupported,
                    &[frame as u32, THUMBNAIL_OUT as u32]
                ),
                0,
                "embedded EXIF thumbnail"
            );
            let thumbnail_bitmap = read_ptr(&fixture, THUMBNAIL_OUT);
            assert_ne!(thumbnail_bitmap, 0);
            fixture.memory.map_bytes(LOCK_SIZE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicSourceGetSize,
                    &[
                        thumbnail_bitmap as u32,
                        LOCK_SIZE_OUT as u32,
                        (LOCK_SIZE_OUT + 4) as u32
                    ]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, LOCK_SIZE_OUT).unwrap(), 4);
            assert_eq!(
                read_guest_u32(&fixture.memory, LOCK_SIZE_OUT + 4).unwrap(),
                4
            );
        });
    }

    #[test]
    fn absent_metadata_and_thumbnail_use_documented_errors() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-metadata-absent");
            let factory = create_factory(&mut fixture);
            let png = build_png(1, 1, 8, 0, 0, &[], &[0, 128]);
            let (decoder, reader) = metadata_reader_for(&mut fixture, factory, &png);
            assert_eq!(
                metadata_query(&mut fixture, reader, "Make"),
                (u64::from(WINCODEC_ERR_PROPERTYNOTFOUND), None)
            );
            let frame = decode_first_frame(&mut fixture, decoder);
            fixture.memory.map_bytes(THUMBNAIL_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeUnsupported,
                    &[frame as u32, THUMBNAIL_OUT as u32]
                ),
                u64::from(WIC_E_CODECNOTHANDLED)
            );
            assert_eq!(read_ptr(&fixture, THUMBNAIL_OUT), 0);
        });
    }

    #[allow(clippy::type_complexity)]
    fn build_gif_layout(
        screen_width: u16,
        screen_height: u16,
        palette: &[[u8; 3]; 256],
        frames: &[(u16, u16, u16, u16, Vec<u8>, Option<u8>, u16, u8)],
    ) -> Vec<u8> {
        let mut out = b"GIF89a".to_vec();
        out.extend_from_slice(&screen_width.to_le_bytes());
        out.extend_from_slice(&screen_height.to_le_bytes());
        out.extend_from_slice(&[0xf7, 0, 0]);
        for color in palette {
            out.extend_from_slice(color);
        }
        for (left, top, width, height, indices, transparent, delay, disposal) in frames {
            let flags = ((*disposal & 0x07) << 2) | u8::from(transparent.is_some());
            out.extend_from_slice(&[0x21, 0xf9, 4, flags]);
            out.extend_from_slice(&(delay / 10).to_le_bytes());
            out.push(transparent.unwrap_or(0));
            out.push(0);
            out.push(0x2c);
            out.extend_from_slice(&left.to_le_bytes());
            out.extend_from_slice(&top.to_le_bytes());
            out.extend_from_slice(&width.to_le_bytes());
            out.extend_from_slice(&height.to_le_bytes());
            out.push(0);
            out.push(8);
            gif_sub_blocks(&mut out, &gif_literal_stream(indices));
        }
        out.push(0x3b);
        out
    }

    fn ccitt_pack(parts: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut accumulator = 0_u8;
        let mut bits = 0_u32;
        for part in parts {
            for byte in part.bytes() {
                accumulator = (accumulator << 1) | u8::from(byte == b'1');
                bits += 1;
                if bits == 8 {
                    out.push(accumulator);
                    accumulator = 0;
                    bits = 0;
                }
            }
        }
        if bits > 0 {
            out.push(accumulator << (8 - bits));
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn build_tiff_strips(
        width: u32,
        height: u32,
        samples: u16,
        bits: &[u16],
        photometric: u16,
        compression: u16,
        predictor: u16,
        planar: u16,
        rows_per_strip: u32,
        strips: &[Vec<u8>],
        color_map: &[u32],
        little: bool,
    ) -> Vec<u8> {
        let entry_count = 11 + usize::from(!color_map.is_empty());
        let ifd_size = 2 + entry_count * 12 + 4;
        let mut data_offset = 8_usize;
        let mut data_offsets = Vec::new();
        for strip in strips {
            data_offsets.push(data_offset);
            data_offset += strip.len();
            if data_offset % 2 != 0 {
                data_offset += 1;
            }
        }
        let ifd_offset = data_offset;
        let bits_offset = ifd_offset + ifd_size;
        let color_offset = bits_offset + bits.len() * 2;
        let offsets_offset = color_offset + color_map.len() * 4;
        let counts_offset = offsets_offset + strips.len() * 4;
        let total = counts_offset + strips.len() * 4;
        let mut out = vec![0_u8; total];
        out[..2].copy_from_slice(if little { b"II" } else { b"MM" });
        tiff_put_u16(&mut out, 2, 42, little);
        tiff_put_u32(&mut out, 4, ifd_offset as u32, little);
        for (index, strip) in strips.iter().enumerate() {
            let offset = data_offsets[index];
            out[offset..offset + strip.len()].copy_from_slice(strip);
        }
        tiff_put_u16(&mut out, ifd_offset, entry_count as u16, little);
        let bits_entry = if bits.len() == 1 {
            (258_u16, 3_u16, 1_u32, u32::from(bits[0]))
        } else {
            (258, 3, bits.len() as u32, bits_offset as u32)
        };
        let offsets_entry = if strips.len() == 1 {
            (273_u16, 4_u16, 1_u32, data_offsets[0] as u32)
        } else {
            (273, 4, strips.len() as u32, offsets_offset as u32)
        };
        let counts_entry = if strips.len() == 1 {
            (279_u16, 4_u16, 1_u32, strips[0].len() as u32)
        } else {
            (279, 4, strips.len() as u32, counts_offset as u32)
        };
        let mut entries = vec![
            (256_u16, 4_u16, 1_u32, width),
            (257, 4, 1, height),
            bits_entry,
            (259, 3, 1, u32::from(compression)),
            (262, 3, 1, u32::from(photometric)),
            offsets_entry,
            (277, 3, 1, u32::from(samples)),
            (278, 4, 1, rows_per_strip),
            counts_entry,
            (284, 3, 1, u32::from(planar)),
            (317, 3, 1, u32::from(predictor)),
        ];
        if !color_map.is_empty() {
            entries.push((320, 3, color_map.len() as u32, color_offset as u32));
        }
        entries.sort_by_key(|(tag, _, _, _)| *tag);
        for (index, (tag, kind, count, value)) in entries.into_iter().enumerate() {
            let base = ifd_offset + 2 + index * 12;
            tiff_put_u16(&mut out, base, tag, little);
            tiff_put_u16(&mut out, base + 2, kind, little);
            tiff_put_u32(&mut out, base + 4, count, little);
            if kind == 3 && count == 1 {
                tiff_put_u16(&mut out, base + 8, value as u16, little);
                tiff_put_u16(&mut out, base + 10, 0, little);
            } else {
                tiff_put_u32(&mut out, base + 8, value, little);
            }
        }
        tiff_put_u32(&mut out, ifd_offset + 2 + entry_count * 12, 0, little);
        for (index, value) in bits.iter().enumerate() {
            tiff_put_u16(&mut out, bits_offset + index * 2, *value, little);
        }
        for (index, value) in color_map.iter().enumerate() {
            tiff_put_u32(&mut out, color_offset + index * 4, *value, little);
        }
        for (index, (offset, strip)) in data_offsets.iter().zip(strips.iter()).enumerate() {
            tiff_put_u32(&mut out, offsets_offset + index * 4, *offset as u32, little);
            tiff_put_u32(
                &mut out,
                counts_offset + index * 4,
                strip.len() as u32,
                little,
            );
        }
        out
    }

    fn deflate_bytes(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn tiff_predictor2_encode(row: &[u8], samples: usize) -> Vec<u8> {
        let mut out = row.to_vec();
        for index in (samples..row.len()).rev() {
            out[index] = row[index].wrapping_sub(row[index - samples]);
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn build_tiff_gray4_tiled(
        width: u32,
        height: u32,
        tile_width: u32,
        tile_height: u32,
        pixels: &[u8],
        little: bool,
    ) -> Vec<u8> {
        let across = width.div_ceil(tile_width) as usize;
        let down = height.div_ceil(tile_height) as usize;
        let row_bytes = (tile_width as usize * 4).div_ceil(8);
        let mut tiles = Vec::new();
        for tile_y in 0..down {
            for tile_x in 0..across {
                let mut tile = vec![0_u8; row_bytes * tile_height as usize];
                for row in 0..tile_height as usize {
                    let y = tile_y * tile_height as usize + row;
                    if y >= height as usize {
                        break;
                    }
                    for col in 0..tile_width as usize {
                        let x = tile_x * tile_width as usize + col;
                        if x >= width as usize {
                            break;
                        }
                        let value = pixels[y * width as usize + x] & 0x0f;
                        let bit = col * 4;
                        if bit % 8 == 0 {
                            tile[row * row_bytes + bit / 8] |= value << 4;
                        } else {
                            tile[row * row_bytes + bit / 8] |= value;
                        }
                    }
                }
                tiles.push(tile);
            }
        }
        let entry_count = 11_usize;
        let ifd_size = 2 + entry_count * 12 + 4;
        let mut data_offset = 8_usize;
        let mut data_offsets = Vec::new();
        for tile in &tiles {
            data_offsets.push(data_offset);
            data_offset += tile.len();
            if data_offset % 2 != 0 {
                data_offset += 1;
            }
        }
        let ifd_offset = data_offset;
        let bits_offset = ifd_offset + ifd_size;
        let offsets_offset = bits_offset + 2;
        let counts_offset = offsets_offset + tiles.len() * 4;
        let mut out = vec![0_u8; counts_offset + tiles.len() * 4];
        out[..2].copy_from_slice(if little { b"II" } else { b"MM" });
        tiff_put_u16(&mut out, 2, 42, little);
        tiff_put_u32(&mut out, 4, ifd_offset as u32, little);
        for (index, tile) in tiles.iter().enumerate() {
            let offset = data_offsets[index];
            out[offset..offset + tile.len()].copy_from_slice(tile);
        }
        tiff_put_u16(&mut out, ifd_offset, entry_count as u16, little);
        let entries = [
            (256_u16, 4_u16, 1_u32, width),
            (257, 4, 1, height),
            (258, 3, 1, 4),
            (259, 3, 1, 1),
            (262, 3, 1, 1),
            (277, 3, 1, 1),
            (284, 3, 1, 1),
            (322, 4, 1, tile_width),
            (323, 4, 1, tile_height),
            (324, 4, tiles.len() as u32, offsets_offset as u32),
            (325, 4, tiles.len() as u32, counts_offset as u32),
        ];
        for (index, (tag, kind, count, value)) in entries.into_iter().enumerate() {
            let base = ifd_offset + 2 + index * 12;
            tiff_put_u16(&mut out, base, tag, little);
            tiff_put_u16(&mut out, base + 2, kind, little);
            tiff_put_u32(&mut out, base + 4, count, little);
            if kind == 3 && count == 1 {
                tiff_put_u16(&mut out, base + 8, value as u16, little);
                tiff_put_u16(&mut out, base + 10, 0, little);
            } else {
                tiff_put_u32(&mut out, base + 8, value, little);
            }
        }
        tiff_put_u32(&mut out, ifd_offset + 2 + entry_count * 12, 0, little);
        tiff_put_u16(&mut out, bits_offset, 4, little);
        for (index, (offset, tile)) in data_offsets.iter().zip(tiles.iter()).enumerate() {
            tiff_put_u32(&mut out, offsets_offset + index * 4, *offset as u32, little);
            tiff_put_u32(
                &mut out,
                counts_offset + index * 4,
                tile.len() as u32,
                little,
            );
        }
        out
    }

    #[test]
    fn gif_pixels_transparency_and_interlace_decode() {
        let mut palette = [[0_u8; 3]; 256];
        palette[0] = [255, 0, 0];
        palette[1] = [0, 255, 0];
        palette[2] = [0, 0, 255];
        palette[3] = [10, 20, 30];
        let indices: Vec<u8> = (0..25_u8).map(|index| index % 4).collect();
        let gif = build_gif(
            5,
            5,
            &palette,
            &[(indices.clone(), Some(2), 5)],
            true,
            None,
            None,
        );
        assert_eq!(wic_image_frame_count(&gif), 1);
        let image = wic_decode_gif_frame(&gif, 0).expect("interlaced transparent GIF");
        assert_eq!((image.width, image.height), (5, 5));
        for (index, &color_index) in indices.iter().enumerate() {
            let pixel = &image.pixels[index * 4..index * 4 + 4];
            let expected = palette[color_index as usize];
            assert_eq!(pixel[0], expected[2], "blue at {index}");
            assert_eq!(pixel[1], expected[1], "green at {index}");
            assert_eq!(pixel[2], expected[0], "red at {index}");
            assert_eq!(pixel[3], if color_index == 2 { 0 } else { 255 });
        }
        assert_eq!(
            wic_decode_gif_frame(&gif, 1).unwrap_err(),
            WINCODEC_ERR_FRAMEMISSING
        );
    }

    #[test]
    fn gif_multi_frame_enumeration_and_missing_frame_rejected() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-gif-frames");
            let factory = create_factory(&mut fixture);
            let mut palette = [[0_u8; 3]; 256];
            palette[0] = [255, 0, 0];
            palette[1] = [0, 255, 0];
            palette[2] = [0, 0, 255];
            let gif = build_gif(
                2,
                2,
                &palette,
                &[
                    (vec![0_u8; 4], None, 50),
                    (vec![1_u8; 4], None, 100),
                    (vec![2_u8; 4], None, 0),
                ],
                false,
                None,
                None,
            );
            let stream = create_stream(&mut fixture, factory, &gif);
            let (hr, decoder) = create_decoder_from_stream(&mut fixture, factory, stream);
            assert_eq!(hr, 0);
            fixture.memory.map_bytes(LOCK_SIZE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicDecoderGetFrameCount,
                    &[decoder as u32, LOCK_SIZE_OUT as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&fixture.memory, LOCK_SIZE_OUT).unwrap(), 3);
            for index in 0..3_u32 {
                fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::WicDecoderGetFrame,
                        &[decoder as u32, index, FRAME_OUT as u32]
                    ),
                    0
                );
                let frame = read_ptr(&fixture, FRAME_OUT);
                let pixels = copy_frame_pixels(&mut fixture, frame, 2, 2);
                let expected = palette[index as usize];
                for pixel in pixels.chunks_exact(4) {
                    assert_eq!(pixel, &[expected[2], expected[1], expected[0], 255]);
                }
            }
            fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicDecoderGetFrame,
                    &[decoder as u32, 3, FRAME_OUT as u32]
                ),
                u64::from(WINCODEC_ERR_FRAMEMISSING),
                "an out-of-range frame index is rejected"
            );
            assert_eq!(read_ptr(&fixture, FRAME_OUT), 0);
        });
    }

    fn build_tiff_rgb_tiled(
        width: u32,
        height: u32,
        tile_width: u32,
        tile_height: u32,
        rgb: &[u8],
        little: bool,
    ) -> Vec<u8> {
        let across = width.div_ceil(tile_width) as usize;
        let down = height.div_ceil(tile_height) as usize;
        let mut tiles = Vec::new();
        for tile_y in 0..down {
            for tile_x in 0..across {
                let mut tile = vec![0_u8; tile_width as usize * tile_height as usize * 3];
                for row in 0..tile_height as usize {
                    let y = tile_y * tile_height as usize + row;
                    if y >= height as usize {
                        break;
                    }
                    for col in 0..tile_width as usize {
                        let x = tile_x * tile_width as usize + col;
                        if x >= width as usize {
                            break;
                        }
                        let source = (y * width as usize + x) * 3;
                        let destination = (row * tile_width as usize + col) * 3;
                        tile[destination..destination + 3]
                            .copy_from_slice(&rgb[source..source + 3]);
                    }
                }
                tiles.push(tiff_lzw_literal_codes(&tile));
            }
        }
        let entry_count = 11_usize;
        let ifd_size = 2 + entry_count * 12 + 4;
        let mut data_offset = 8_usize;
        let mut data_offsets = Vec::new();
        for tile in &tiles {
            data_offsets.push(data_offset);
            data_offset += tile.len();
            if data_offset % 2 != 0 {
                data_offset += 1;
            }
        }
        let ifd_offset = data_offset;
        let bits_offset = ifd_offset + ifd_size;
        let tile_offsets_offset = bits_offset + 6;
        let tile_counts_offset = tile_offsets_offset + tiles.len() * 4;
        let total = tile_counts_offset + tiles.len() * 4;
        let mut out = vec![0_u8; total];
        out[..2].copy_from_slice(if little { b"II" } else { b"MM" });
        tiff_put_u16(&mut out, 2, 42, little);
        tiff_put_u32(&mut out, 4, ifd_offset as u32, little);
        for (index, tile) in tiles.iter().enumerate() {
            let offset = data_offsets[index];
            out[offset..offset + tile.len()].copy_from_slice(tile);
        }
        tiff_put_u16(&mut out, ifd_offset, entry_count as u16, little);
        let entries = [
            (256_u16, 4_u16, 1_u32, width),
            (257, 4, 1, height),
            (258, 3, 3, bits_offset as u32),
            (259, 3, 1, 5),
            (262, 3, 1, 2),
            (277, 3, 1, 3),
            (284, 3, 1, 1),
            (322, 4, 1, tile_width),
            (323, 4, 1, tile_height),
            (324, 4, tiles.len() as u32, tile_offsets_offset as u32),
            (325, 4, tiles.len() as u32, tile_counts_offset as u32),
        ];
        for (index, (tag, kind, count, value)) in entries.into_iter().enumerate() {
            let base = ifd_offset + 2 + index * 12;
            tiff_put_u16(&mut out, base, tag, little);
            tiff_put_u16(&mut out, base + 2, kind, little);
            tiff_put_u32(&mut out, base + 4, count, little);
            if kind == 3 && count == 1 {
                tiff_put_u16(&mut out, base + 8, value as u16, little);
                tiff_put_u16(&mut out, base + 10, 0, little);
            } else {
                tiff_put_u32(&mut out, base + 8, value, little);
            }
        }
        tiff_put_u32(&mut out, ifd_offset + 2 + entry_count * 12, 0, little);
        for index in 0..3 {
            tiff_put_u16(&mut out, bits_offset + index * 2, 8, little);
        }
        for (index, (offset, tile)) in data_offsets.iter().zip(tiles.iter()).enumerate() {
            tiff_put_u32(
                &mut out,
                tile_offsets_offset + index * 4,
                *offset as u32,
                little,
            );
            tiff_put_u32(
                &mut out,
                tile_counts_offset + index * 4,
                tile.len() as u32,
                little,
            );
        }
        out
    }

    #[test]
    fn tiff_tiled_lzw_rgb_and_truncated_tile_rejected() {
        let width = 5_u32;
        let height = 3_u32;
        let mut rgb = Vec::new();
        for y in 0..height as usize {
            for x in 0..width as usize {
                rgb.extend_from_slice(&[(x * 30) as u8, (y * 60) as u8, 200]);
            }
        }
        let tiff = build_tiff_rgb_tiled(width, height, 4, 2, &rgb, false);
        let image = wic_decode_tiff_frame(&tiff, 0).expect("tiled LZW TIFF");
        assert_eq!((image.width, image.height), (width, height));
        for (index, pixel) in image.pixels.chunks_exact(4).enumerate() {
            assert_eq!(
                pixel,
                &[rgb[index * 3 + 2], rgb[index * 3 + 1], rgb[index * 3], 255],
                "tile pixel {index}"
            );
        }
        let truncated = &tiff[..tiff.len() - 6];
        assert_eq!(
            wic_decode_tiff_frame(truncated, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated tile payload is rejected"
        );
    }

    #[test]
    fn tiff_little_endian_packbits_and_truncated_run_rejected() {
        let width = 3_u32;
        let height = 2_u32;
        let raw = vec![
            255, 0, 0, 255, 0, 0, 255, 0, 0, // three identical red samples
            0, 255, 0, 0, 0, 255, 10, 20, 30,
        ];
        let packed = tiff_packbits_encode(&raw);
        let tiff = build_tiff_rgb(width, height, &[(packed.clone(), 32773)], true, &[]);
        let image = wic_decode_tiff_frame(&tiff, 0).expect("PackBits TIFF");
        assert_eq!((image.width, image.height), (width, height));
        let expected = [
            [0_u8, 0, 255, 255],
            [0, 0, 255, 255],
            [0, 0, 255, 255],
            [0, 255, 0, 255],
            [255, 0, 0, 255],
            [30, 20, 10, 255],
        ];
        for (index, pixel) in image.pixels.chunks_exact(4).enumerate() {
            assert_eq!(pixel, expected[index], "PackBits pixel {index}");
        }
        let truncated = build_tiff_rgb(
            width,
            height,
            &[(packed[..packed.len() - 2].to_vec(), 32773)],
            true,
            &[],
        );
        assert_eq!(
            wic_decode_tiff_frame(&truncated, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated PackBits strip is rejected"
        );
    }

    #[test]
    fn tiff_lzw_code_width_growth_and_truncated_stream_rejected() {
        let width = 20_u32;
        let height = 10_u32;
        let mut raw = Vec::new();
        for y in 0..height as usize {
            for x in 0..width as usize {
                raw.extend_from_slice(&[
                    (x * 13 + y) as u8,
                    (y * 27 + x * 5) as u8,
                    ((x + y) * 11) as u8,
                ]);
            }
        }
        assert!(raw.len() > 512, "exercises 10-bit LZW codes");
        let compressed = tiff_lzw_literal_codes(&raw);
        let tiff = build_tiff_rgb(width, height, &[(compressed.clone(), 5)], true, &[]);
        let image = wic_decode_tiff_frame(&tiff, 0).expect("LZW width growth");
        for (index, pixel) in image.pixels.chunks_exact(4).enumerate() {
            assert_eq!(
                pixel,
                &[raw[index * 3 + 2], raw[index * 3 + 1], raw[index * 3], 255]
            );
        }
        let truncated = build_tiff_rgb(
            width,
            height,
            &[(compressed[..compressed.len() - 8].to_vec(), 5)],
            true,
            &[],
        );
        assert_eq!(
            wic_decode_tiff_frame(&truncated, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated LZW code stream is rejected"
        );
    }

    #[test]
    fn tiff_big_endian_lzw_rgb_and_multi_page() {
        let raw0 = vec![255, 0, 0, 0, 255, 0];
        let raw1 = vec![0, 0, 255, 10, 20, 30];
        let frames = vec![
            (tiff_lzw_literal_codes(&raw0), 5_u16),
            (tiff_lzw_literal_codes(&raw1), 5_u16),
        ];
        let tiff = build_tiff_rgb(2, 1, &frames, false, &[]);
        assert!(tiff.starts_with(b"MM\0*"));
        assert_eq!(wic_image_frame_count(&tiff), 2);
        let first = wic_decode_tiff_frame(&tiff, 0).expect("big-endian LZW page 0");
        assert_eq!(&first.pixels[..], &[0, 0, 255, 255, 0, 255, 0, 255]);
        let second = wic_decode_tiff_frame(&tiff, 1).expect("big-endian LZW page 1");
        assert_eq!(&second.pixels[..], &[255, 0, 0, 255, 30, 20, 10, 255]);
        assert_eq!(
            wic_decode_tiff_frame(&tiff, 2).unwrap_err(),
            WINCODEC_ERR_FRAMEMISSING
        );
    }

    #[test]
    fn tiff_unsupported_compression_and_malformed_are_rejected() {
        let tiff = build_tiff_rgb(1, 1, &[(vec![1, 2, 3], 6)], true, &[]);
        assert_eq!(
            wic_decode_tiff_frame(&tiff, 0).unwrap_err(),
            WINCODEC_ERR_COMPRESSIONNOTSUPPORTED
        );
        let valid = build_tiff_rgb(2, 2, &[(vec![0_u8; 12], 1)], true, &[]);
        assert_eq!(
            wic_decode_tiff_frame(&valid[..12], 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE
        );
        assert_eq!(
            wic_decode_gif_frame(b"GIF89a\x00\x00\x00\x00\x00\x00\x00", 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE
        );
        assert_eq!(
            wic_decode_gif_frame(b"NOTAGIF", 0).unwrap_err(),
            WINCODEC_ERR_UNKNOWNIMAGEFORMAT
        );
    }

    #[test]
    fn gif_and_tiff_metadata_reader_and_malformed_metadata_rejected() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-gif-tiff-metadata");
            let factory = create_factory(&mut fixture);
            let mut palette = [[0_u8; 3]; 256];
            palette[0] = [1, 2, 3];
            let gif = build_gif(
                1,
                1,
                &palette,
                &[(vec![0], None, 50), (vec![0], None, 100)],
                false,
                Some("hello gif"),
                Some(("NETSCAPE2.0", &[1, 0, 0])),
            );
            let (_, reader) = metadata_reader_for(&mut fixture, factory, &gif);
            assert_eq!(
                metadata_query(&mut fixture, reader, "FrameCount"),
                (0, Some("2".to_string()))
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "FrameDelay1"),
                (0, Some("100".to_string()))
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "Comment"),
                (0, Some("hello gif".to_string()))
            );
            assert_eq!(
                metadata_query(&mut fixture, reader, "Application"),
                (0, Some("NETSCAPE2.0".to_string()))
            );

            let mut tiff_fixture = x86_fixture("wic-tiff-metadata");
            let tiff_factory = create_factory(&mut tiff_fixture);
            let tiff = build_tiff_rgb(
                1,
                1,
                &[(vec![10, 20, 30], 1)],
                true,
                &[
                    (270, "A baseline image"),
                    (271, "CasaCam"),
                    (272, "Model T"),
                    (306, "2026:10:22 09:19:00"),
                ],
            );
            let (decoder, reader) = metadata_reader_for(&mut tiff_fixture, tiff_factory, &tiff);
            assert_eq!(
                metadata_query(&mut tiff_fixture, reader, "ImageDescription"),
                (0, Some("A baseline image".to_string()))
            );
            assert_eq!(
                metadata_query(&mut tiff_fixture, reader, "Make"),
                (0, Some("CasaCam".to_string()))
            );
            assert_eq!(
                metadata_query(&mut tiff_fixture, reader, "Model"),
                (0, Some("Model T".to_string()))
            );
            assert_eq!(
                metadata_query(&mut tiff_fixture, reader, "DateTime"),
                (0, Some("2026:10:22 09:19:00".to_string()))
            );
            tiff_fixture.memory.map_bytes(LOCK_SIZE_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut tiff_fixture,
                    HostThunk::WicDecoderGetFrameCount,
                    &[decoder as u32, LOCK_SIZE_OUT as u32]
                ),
                0
            );
            assert_eq!(
                read_guest_u32(&tiff_fixture.memory, LOCK_SIZE_OUT).unwrap(),
                1
            );
        });
        assert_eq!(
            wic_gif_metadata_entries(b"NOTAGIF"),
            Vec::<(String, String)>::new(),
            "malformed GIF metadata is empty"
        );
    }

    #[test]
    fn gif_encode_decode_round_trip_and_invalid_size_rejected() {
        let mut bgra = Vec::new();
        for y in 0..3_u8 {
            for x in 0..4_u8 {
                bgra.extend_from_slice(&[
                    x * 60,
                    y * 80,
                    (x + y) * 30,
                    if x == 0 && y == 0 { 0 } else { 255 },
                ]);
            }
        }
        let gif = wic_encode_gif(4, 3, &bgra).expect("GIF encode");
        assert!(gif.starts_with(b"GIF89a"));
        let image = wic_decode_gif_frame(&gif, 0).expect("GIF decode");
        assert_eq!((image.width, image.height), (4, 3));
        for (index, pixel) in image.pixels.chunks_exact(4).enumerate() {
            if index == 0 {
                assert_eq!(pixel[3], 0, "transparent pixel");
            } else {
                assert_eq!(pixel[3], 255);
                assert_eq!(&pixel[..3], &bgra[index * 4..index * 4 + 3]);
            }
        }
        assert_eq!(
            wic_encode_gif(0, 1, &[]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "zero-width GIF encodes are rejected"
        );
        assert_eq!(
            wic_encode_gif(4, 3, &bgra[..bgra.len() - 1]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "short GIF pixel input is rejected"
        );
    }

    #[test]
    fn tiff_encode_decode_round_trip_and_empty_pages_rejected() {
        let mut bgra = vec![0_u8; 5 * 4 * 4];
        for y in 0..4_usize {
            for x in 0..5_usize {
                let index = (y * 5 + x) * 4;
                bgra[index..index + 4].copy_from_slice(&[
                    (x * 40) as u8,
                    (y * 50) as u8,
                    ((x + y) * 25) as u8,
                    255,
                ]);
            }
        }
        let tiff = wic_encode_tiff(5, 4, &bgra, Some((144.0, 72.0))).expect("TIFF encode");
        assert!(tiff.starts_with(b"II*\0"));
        let image = wic_decode_tiff_frame(&tiff, 0).expect("TIFF decode");
        assert_eq!((image.width, image.height), (5, 4));
        assert_eq!(&image.pixels, &bgra);
        assert!((image.dpi_x - 144.0).abs() < 0.01);
        assert!((image.dpi_y - 72.0).abs() < 0.01);
        assert_eq!(
            wic_encode_tiff_pages(&[]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an empty TIFF page list is rejected"
        );
        assert_eq!(
            wic_encode_tiff(0, 4, &bgra, None).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a zero-width TIFF page is rejected"
        );
        assert_eq!(
            wic_encode_tiff(u32::MAX, u32::MAX, &[], None).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "overflowing TIFF dimensions are rejected"
        );
        assert_eq!(
            wic_encode_tiff(5, 4, &bgra[..bgra.len() - 4], None).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "short TIFF pixel input is rejected"
        );
    }

    #[test]
    fn gif_encoder_quantizes_many_colors_overflow_boundary() {
        let width = 16_u32;
        let height = 16_u32;
        let mut bgra = Vec::new();
        for y in 0..height as usize {
            for x in 0..width as usize {
                bgra.extend_from_slice(&[
                    (x * 16) as u8,
                    (y * 16) as u8,
                    ((x * 7 + y * 11) % 256) as u8,
                    255,
                ]);
            }
        }
        let first = wic_encode_gif(width, height, &bgra).expect("GIF encode");
        let second = wic_encode_gif(width, height, &bgra).expect("GIF re-encode");
        assert_eq!(first, second, "deterministic quantization");
        let image = wic_decode_gif_frame(&first, 0).expect("quantized GIF decode");
        assert_eq!((image.width, image.height), (width, height));
        for (index, pixel) in image.pixels.chunks_exact(4).enumerate() {
            assert_eq!(pixel[3], 255);
            for channel in 0..3 {
                let delta = i32::from(pixel[channel]) - i32::from(bgra[index * 4 + channel]);
                assert!(
                    delta.abs() <= 26,
                    "quantization error {delta} at pixel {index}"
                );
            }
        }
    }

    #[test]
    fn gif_encoder_through_wic_factory_and_truncated_stream_rejected() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-gif-encode");
            let factory = create_factory(&mut fixture);
            fixture.memory.map_bytes(STREAM_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateStream,
                    &[factory as u32, STREAM_OUT as u32]
                ),
                0
            );
            let stream = read_ptr(&fixture, STREAM_OUT);
            fixture.memory.map_bytes(FORMAT, &GUID_CONTAINER_FORMAT_GIF);
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
            fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCreateNewFrame,
                    &[encoder as u32, FRAME_OUT as u32, 0]
                ),
                0
            );
            let frame = read_ptr(&fixture, FRAME_OUT);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeSetSize,
                    &[frame as u32, 2, 2]
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
            let source = [
                0_u8, 0, 255, 255, 0, 255, 0, 255, 255, 0, 0, 255, 10, 20, 30, 255,
            ];
            fixture.memory.map_bytes(ENCODE_BYTES, &source);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFrameEncodeWritePixels,
                    &[frame as u32, 2, 8, 16, ENCODE_BYTES as u32]
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
            let encoded = fixture
                .runtime
                .wic
                .objects
                .get(&stream)
                .expect("GIF stream")
                .stream
                .clone();
            assert!(encoded.starts_with(b"GIF89a"));
            let image = wic_decode_gif_frame(&encoded, 0).expect("GIF round-trip");
            assert_eq!((image.width, image.height), (2, 2));
            assert_eq!(&image.pixels[..], &source[..]);
            assert_eq!(
                wic_decode_gif_frame(&encoded[..encoded.len() - 4], 0).unwrap_err(),
                WINCODEC_ERR_BADIMAGE,
                "a truncated encoded GIF is rejected"
            );
        });
    }

    fn encode_frames_through_wic(
        container: &[u8; 16],
        width: u32,
        height: u32,
        frames: &[Vec<u8>],
    ) -> Vec<u8> {
        let container = *container;
        let frames = frames.to_vec();
        with_big_stack(move || {
            let container = container;
            let mut fixture = x86_fixture("wic-multi-frame-encode");
            let factory = create_factory(&mut fixture);
            fixture.memory.map_bytes(STREAM_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateStream,
                    &[factory as u32, STREAM_OUT as u32]
                ),
                0
            );
            let stream = read_ptr(&fixture, STREAM_OUT);
            fixture.memory.map_bytes(FORMAT, &container);
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
            for (index, source) in frames.iter().enumerate() {
                assert_eq!(source.len(), (width * height * 4) as usize);
                fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::WicEncoderCreateNewFrame,
                        &[encoder as u32, FRAME_OUT as u32, 0]
                    ),
                    0,
                    "create frame {index}"
                );
                let frame = read_ptr(&fixture, FRAME_OUT);
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::WicFrameEncodeSetSize,
                        &[frame as u32, width, height]
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
                fixture.memory.map_bytes(ENCODE_BYTES, source);
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::WicFrameEncodeWritePixels,
                        &[
                            frame as u32,
                            height,
                            width * 4,
                            source.len() as u32,
                            ENCODE_BYTES as u32,
                        ]
                    ),
                    0,
                    "write frame {index}"
                );
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::WicFrameEncodeCommit,
                        &[frame as u32]
                    ),
                    0,
                    "commit frame {index}"
                );
            }
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::WicEncoderCommit, &[encoder as u32]),
                0
            );
            fixture
                .runtime
                .wic
                .objects
                .get(&stream)
                .expect("encoded stream")
                .stream
                .clone()
        })
    }

    #[test]
    fn wic_encoder_animated_gif_and_truncated_stream_rejected() {
        let red = vec![0_u8, 0, 255, 255].repeat(4);
        let green = vec![0_u8, 255, 0, 255].repeat(4);
        let encoded = encode_frames_through_wic(
            &GUID_CONTAINER_FORMAT_GIF,
            2,
            2,
            &[red.clone(), green.clone()],
        );
        assert_eq!(wic_image_frame_count(&encoded), 2);
        let first = wic_decode_gif_frame(&encoded, 0).expect("GIF frame 0");
        assert_eq!(first.pixels, red);
        let second = wic_decode_gif_frame(&encoded, 1).expect("GIF frame 1");
        assert_eq!(second.pixels, green);
        assert_eq!(
            wic_decode_gif_frame(&encoded[..encoded.len() - 5], 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated animated GIF is rejected"
        );
    }

    #[test]
    fn wic_encoder_multi_page_tiff_and_truncated_stream_rejected() {
        let red = vec![0_u8, 0, 255, 255].repeat(4);
        let blue = vec![255_u8, 0, 0, 255].repeat(4);
        let encoded = encode_frames_through_wic(
            &GUID_CONTAINER_FORMAT_TIFF,
            2,
            2,
            &[red.clone(), blue.clone()],
        );
        assert_eq!(wic_image_frame_count(&encoded), 2);
        let first = wic_decode_tiff_frame(&encoded, 0).expect("TIFF page 0");
        assert_eq!(first.pixels, red);
        let second = wic_decode_tiff_frame(&encoded, 1).expect("TIFF page 1");
        assert_eq!(second.pixels, blue);
        assert_eq!(
            wic_decode_tiff_frame(&encoded[..8], 1).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated multi-page TIFF has no second page"
        );
    }

    #[test]
    fn cmyk_ycck_and_malformed_streams_rejected() {
        let mut cmyk = vec![0xff, 0xd8];
        wic_jpeg_push_segment(
            &mut cmyk,
            0xc0,
            &[
                8, 0, 1, 0, 1, 4, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0, 4, 0x11, 0,
            ],
        );
        cmyk.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&cmyk).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION
        );

        let mut ycck = vec![0xff, 0xd8];
        let mut adobe = b"Adobe".to_vec();
        adobe.extend_from_slice(&[0, 100, 0, 0, 0, 0, 2]);
        wic_jpeg_push_segment(&mut ycck, 0xee, &adobe);
        ycck.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&ycck).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION
        );

        let truncated = &progressive_jpeg_fixture()[..40];
        assert_eq!(
            wic_decode_jpeg(truncated).unwrap_err(),
            WINCODEC_ERR_BADIMAGE
        );
    }
    #[test]
    fn gif_offset_disposal_and_truncated_stream_rejected() {
        let mut palette = [[0_u8; 3]; 256];
        palette[0] = [255, 0, 0];
        palette[1] = [0, 255, 0];
        palette[2] = [0, 0, 255];
        let gif = build_gif_layout(
            4,
            4,
            &palette,
            &[
                (0, 0, 4, 4, vec![0_u8; 16], None, 50, 1),
                (1, 1, 2, 2, vec![1_u8; 4], None, 50, 2),
                (0, 0, 1, 1, vec![2_u8], None, 0, 0),
            ],
        );
        let info = wic_gif_parse(&gif).expect("animated GIF parse");
        assert_eq!(info.frames.len(), 3);
        assert_eq!((info.frames[1].left, info.frames[1].top), (1, 1));
        assert_eq!((info.frames[1].width, info.frames[1].height), (2, 2));
        assert_eq!(info.frames[1].disposal, 2);
        let first = wic_decode_gif_frame(&gif, 0).expect("frame 0");
        assert_eq!((first.width, first.height), (4, 4));
        assert!(
            first
                .pixels
                .chunks_exact(4)
                .all(|pixel| pixel == [0, 0, 255, 255])
        );
        let second = wic_decode_gif_frame(&gif, 1).expect("frame 1");
        for (index, pixel) in second.pixels.chunks_exact(4).enumerate() {
            let x = index % 4;
            let y = index / 4;
            let inside = (1..=2).contains(&x) && (1..=2).contains(&y);
            let expected = if inside {
                [0, 255, 0, 255]
            } else {
                [0, 0, 255, 255]
            };
            assert_eq!(pixel, expected, "offset composition at {x},{y}");
        }
        let third = wic_decode_gif_frame(&gif, 2).expect("frame 2");
        assert_eq!(&third.pixels[..4], &[255, 0, 0, 255], "top-left blue");
        for index in [5_usize, 6, 9, 10] {
            assert_eq!(
                third.pixels[index * 4 + 3],
                0,
                "disposal-2 background at pixel {index}"
            );
        }
        assert_eq!(
            &third.pixels[4..8],
            &[0, 0, 255, 255],
            "red retained at 1,0"
        );

        let transparency = build_gif_layout(
            2,
            2,
            &palette,
            &[
                (0, 0, 2, 2, vec![0_u8; 4], None, 50, 1),
                (0, 0, 2, 2, vec![1, 1, 1, 2], Some(1), 50, 0),
            ],
        );
        let image = wic_decode_gif_frame(&transparency, 1).expect("transparent frame");
        assert_eq!(&image.pixels[..4], &[0, 0, 255, 255]);
        assert_eq!(&image.pixels[4..8], &[0, 0, 255, 255]);
        assert_eq!(&image.pixels[8..12], &[0, 0, 255, 255]);
        assert_eq!(&image.pixels[12..16], &[255, 0, 0, 255]);

        let previous = build_gif_layout(
            4,
            4,
            &palette,
            &[
                (0, 0, 4, 4, vec![0_u8; 16], None, 50, 1),
                (1, 1, 2, 2, vec![1_u8; 4], None, 50, 3),
                (0, 0, 1, 1, vec![2_u8], None, 0, 0),
            ],
        );
        let restored = wic_decode_gif_frame(&previous, 2).expect("disposal-3 frame");
        assert_eq!(&restored.pixels[..4], &[255, 0, 0, 255], "blue at 0,0");
        assert_eq!(
            &restored.pixels[5 * 4..6 * 4],
            &[0, 0, 255, 255],
            "previous state restored at 1,1"
        );
        assert_eq!(
            wic_decode_gif_frame(&gif[..gif.len() - 3], 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated disposal GIF is rejected"
        );
        let oversized =
            build_gif_layout(2, 2, &palette, &[(1, 1, 2, 2, vec![0_u8; 4], None, 50, 1)]);
        let image = wic_decode_gif_frame(&oversized, 0).expect("offset frame");
        assert_eq!(
            &image.pixels[..4],
            &[0, 0, 0, 0],
            "outside the frame stays clear"
        );
        assert_eq!(
            &image.pixels[12..16],
            &[0, 0, 255, 255],
            "bottom-right pixel"
        );
    }

    #[test]
    fn gif_animation_encoder_and_invalid_disposal_rejected() {
        let mut first = vec![0_u8; 16];
        for pixel in first.chunks_exact_mut(4) {
            pixel.copy_from_slice(&[0, 0, 255, 255]);
        }
        let mut second = vec![0_u8; 16];
        for (index, pixel) in second.chunks_exact_mut(4).enumerate() {
            if index == 0 {
                pixel.copy_from_slice(&[0, 0, 0, 0]);
            } else {
                pixel.copy_from_slice(&[0, 255, 0, 255]);
            }
        }
        let mut third = vec![0_u8; 16];
        for pixel in third.chunks_exact_mut(4) {
            pixel.copy_from_slice(&[255, 0, 0, 255]);
        }
        let gif = wic_encode_gif_animation(
            2,
            2,
            &[
                WicGifAnimationFrame {
                    bgra: &first,
                    delay_ms: 40,
                    disposal: 0,
                },
                WicGifAnimationFrame {
                    bgra: &second,
                    delay_ms: 120,
                    disposal: 2,
                },
                WicGifAnimationFrame {
                    bgra: &third,
                    delay_ms: 30,
                    disposal: 3,
                },
            ],
            7,
        )
        .expect("animated GIF encode");
        assert!(gif.starts_with(b"GIF89a"));
        assert_eq!(wic_image_frame_count(&gif), 3);
        let info = wic_gif_parse(&gif).expect("animation parse");
        assert_eq!(
            info.frames
                .iter()
                .map(|frame| frame.delay_ms)
                .collect::<Vec<_>>(),
            vec![40, 120, 30]
        );
        assert_eq!(
            info.frames
                .iter()
                .map(|frame| frame.disposal)
                .collect::<Vec<_>>(),
            vec![0, 2, 3]
        );
        assert!(
            info.applications
                .iter()
                .any(|(identifier, data)| identifier == "NETSCAPE2.0"
                    && data.len() >= 3
                    && data[0] == 1
                    && u16::from_le_bytes([data[1], data[2]]) == 7)
        );
        let frame0 = wic_decode_gif_frame(&gif, 0).expect("animation frame 0");
        assert!(
            frame0
                .pixels
                .chunks_exact(4)
                .all(|pixel| pixel == [0, 0, 255, 255])
        );
        let frame1 = wic_decode_gif_frame(&gif, 1).expect("animation frame 1");
        assert_eq!(
            &frame1.pixels[..4],
            &[0, 0, 255, 255],
            "transparent pixel keeps red"
        );
        for pixel in frame1.pixels[4..].chunks_exact(4) {
            assert_eq!(pixel, [0, 255, 0, 255]);
        }
        let frame2 = wic_decode_gif_frame(&gif, 2).expect("animation frame 2");
        assert!(
            frame2
                .pixels
                .chunks_exact(4)
                .all(|pixel| pixel == [255, 0, 0, 255])
        );
        assert_eq!(
            wic_encode_gif_animation(
                2,
                2,
                &[WicGifAnimationFrame {
                    bgra: &first,
                    delay_ms: 0,
                    disposal: 4,
                }],
                0,
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an out-of-range disposal method is rejected"
        );
    }

    #[test]
    fn tiff_deflate_predictor_and_bad_predictor_bits_rejected() {
        let width = 4_usize;
        let height = 3_usize;
        let mut bgra = Vec::new();
        for y in 0..height {
            for x in 0..width {
                bgra.extend_from_slice(&[
                    (x * 60 + y * 7) as u8,
                    (y * 70 + x * 3) as u8,
                    (x * 20 + y * 40) as u8,
                    255,
                ]);
            }
        }
        let mut planes = Vec::new();
        for channel in [2_usize, 1, 0] {
            let mut plane = Vec::new();
            for row in 0..height {
                let mut line = Vec::new();
                for col in 0..width {
                    line.push(bgra[(row * width + col) * 4 + channel]);
                }
                plane.extend_from_slice(&tiff_predictor2_encode(&line, 1));
            }
            planes.push(deflate_bytes(&plane));
        }
        let tiff = build_tiff_strips(
            width as u32,
            height as u32,
            3,
            &[8, 8, 8],
            2,
            8,
            2,
            2,
            height as u32,
            &planes,
            &[],
            true,
        );
        let image = wic_decode_tiff_frame(&tiff, 0).expect("Deflate predictor planar TIFF");
        assert_eq!((image.width, image.height), (width as u32, height as u32));
        assert_eq!(image.pixels, bgra);

        let bad_bits =
            build_tiff_strips(2, 1, 1, &[4], 1, 1, 2, 1, 1, &[vec![0x12, 0x34]], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&bad_bits, 0).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "predictor 2 is only defined for 8/16-bit samples"
        );
        let deflate_wrong_size = build_tiff_strips(
            2,
            1,
            1,
            &[8],
            1,
            8,
            1,
            1,
            1,
            &[deflate_bytes(&[0_u8; 3])],
            &[],
            true,
        );
        assert_eq!(
            wic_decode_tiff_frame(&deflate_wrong_size, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a Deflate strip of the wrong size is rejected"
        );
    }

    #[test]
    fn tiff_jpeg_compressed_strip_and_truncated_payload_rejected() {
        let width = 8_usize;
        let height = 8_usize;
        let mut bgra = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let pixel = if x < width / 2 {
                    [0, 0, 255, 255]
                } else {
                    [255, 0, 0, 255]
                };
                let _ = y;
                bgra.extend_from_slice(&pixel);
            }
        }
        let jpeg =
            wic_encode_jpeg(width as u32, height as u32, &bgra, None).expect("JPEG payload encode");
        let tiff = build_tiff_strips(
            width as u32,
            height as u32,
            3,
            &[8, 8, 8],
            6,
            7,
            1,
            1,
            height as u32,
            &[jpeg],
            &[],
            true,
        );
        let image = wic_decode_tiff_frame(&tiff, 0).expect("JPEG-in-TIFF strip");
        assert_eq!((image.width, image.height), (width as u32, height as u32));
        for (index, pixel) in image.pixels.chunks_exact(4).enumerate() {
            assert_eq!(pixel[3], 255, "opaque pixel {index}");
            let left = index % width < width / 2;
            if left {
                assert!(
                    pixel[0] < 40 && pixel[1] < 40 && pixel[2] > 215,
                    "red {index}"
                );
            } else {
                assert!(
                    pixel[0] > 215 && pixel[1] < 40 && pixel[2] < 40,
                    "blue {index}"
                );
            }
        }

        let strip_bgra = [20_u8, 40, 60, 255].repeat(8 * 8);
        let strip = wic_encode_jpeg(8, 8, &strip_bgra, None).expect("strip encode");
        let multi = build_tiff_strips(
            8,
            16,
            3,
            &[8, 8, 8],
            6,
            7,
            1,
            1,
            8,
            &[strip.clone(), strip[..strip.len() / 2].to_vec()],
            &[],
            true,
        );
        assert_eq!(
            wic_decode_tiff_frame(&multi, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "the second JPEG strip is truncated"
        );
        assert_eq!(
            wic_decode_tiff_frame(&tiff[..tiff.len() / 2], 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated JPEG-in-TIFF strip is rejected"
        );
    }

    fn build_tiff_jpeg_tiled(
        width: u32,
        height: u32,
        tile_width: u32,
        tile_height: u32,
        tiles: &[Vec<u8>],
        little: bool,
    ) -> Vec<u8> {
        let entry_count = 11_usize;
        let ifd_size = 2 + entry_count * 12 + 4;
        let mut data_offset = 8_usize;
        let mut data_offsets = Vec::new();
        for tile in tiles {
            data_offsets.push(data_offset);
            data_offset += tile.len();
            if data_offset % 2 != 0 {
                data_offset += 1;
            }
        }
        let ifd_offset = data_offset;
        let bits_offset = ifd_offset + ifd_size;
        let offsets_offset = bits_offset + 6;
        let counts_offset = offsets_offset + tiles.len() * 4;
        let mut out = vec![0_u8; counts_offset + tiles.len() * 4];
        out[..2].copy_from_slice(if little { b"II" } else { b"MM" });
        tiff_put_u16(&mut out, 2, 42, little);
        tiff_put_u32(&mut out, 4, ifd_offset as u32, little);
        for (index, tile) in tiles.iter().enumerate() {
            let offset = data_offsets[index];
            out[offset..offset + tile.len()].copy_from_slice(tile);
        }
        tiff_put_u16(&mut out, ifd_offset, entry_count as u16, little);
        let entries = [
            (256_u16, 4_u16, 1_u32, width),
            (257, 4, 1, height),
            (258, 3, 3, bits_offset as u32),
            (259, 3, 1, 7),
            (262, 3, 1, 6),
            (277, 3, 1, 3),
            (284, 3, 1, 1),
            (322, 4, 1, tile_width),
            (323, 4, 1, tile_height),
            (324, 4, tiles.len() as u32, offsets_offset as u32),
            (325, 4, tiles.len() as u32, counts_offset as u32),
        ];
        for (index, (tag, kind, count, value)) in entries.into_iter().enumerate() {
            let base = ifd_offset + 2 + index * 12;
            tiff_put_u16(&mut out, base, tag, little);
            tiff_put_u16(&mut out, base + 2, kind, little);
            tiff_put_u32(&mut out, base + 4, count, little);
            if kind == 3 && count == 1 {
                tiff_put_u16(&mut out, base + 8, value as u16, little);
                tiff_put_u16(&mut out, base + 10, 0, little);
            } else {
                tiff_put_u32(&mut out, base + 8, value, little);
            }
        }
        tiff_put_u32(&mut out, ifd_offset + 2 + entry_count * 12, 0, little);
        for index in 0..3 {
            tiff_put_u16(&mut out, bits_offset + index * 2, 8, little);
        }
        for (index, (offset, tile)) in data_offsets.iter().zip(tiles.iter()).enumerate() {
            tiff_put_u32(&mut out, offsets_offset + index * 4, *offset as u32, little);
            tiff_put_u32(
                &mut out,
                counts_offset + index * 4,
                tile.len() as u32,
                little,
            );
        }
        out
    }

    #[test]
    fn tiff_jpeg_compressed_tiles_and_truncated_tile_rejected() {
        let width = 8_usize;
        let height = 8_usize;
        let tile = 4_usize;
        let colors = [
            [0_u8, 0, 255, 255],
            [0, 255, 0, 255],
            [255, 0, 0, 255],
            [0, 255, 255, 255],
        ];
        let mut tiles = Vec::new();
        for tile_y in 0..2 {
            for tile_x in 0..2 {
                let color = colors[tile_y * 2 + tile_x];
                let bgra = color.repeat(tile * tile);
                tiles.push(
                    wic_encode_jpeg(tile as u32, tile as u32, &bgra, None)
                        .expect("JPEG tile encode"),
                );
            }
        }
        let tiff = build_tiff_jpeg_tiled(
            width as u32,
            height as u32,
            tile as u32,
            tile as u32,
            &tiles,
            true,
        );
        let image = wic_decode_tiff_frame(&tiff, 0).expect("JPEG-in-TIFF tiles");
        assert_eq!((image.width, image.height), (width as u32, height as u32));
        for index in 0..width * height {
            let x = index % width;
            let y = index / width;
            let color = colors[(y / tile) * 2 + x / tile];
            let pixel = &image.pixels[index * 4..index * 4 + 4];
            assert_eq!(pixel[3], 255);
            for channel in 0..3 {
                let delta = i32::from(pixel[channel]) - i32::from(color[channel]);
                assert!(delta.abs() < 40, "tile color {channel} at {x},{y}: {delta}");
            }
        }
        let mut broken_tiles = tiles;
        let last = broken_tiles.last_mut().expect("tile");
        last.truncate(last.len() - 8);
        let broken = build_tiff_jpeg_tiled(
            width as u32,
            height as u32,
            tile as u32,
            tile as u32,
            &broken_tiles,
            true,
        );
        assert_eq!(
            wic_decode_tiff_frame(&broken, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated JPEG tile is rejected"
        );
    }

    #[test]
    fn tiff_ccitt_g3_g4_and_truncated_fax_data_rejected() {
        let expected = [255_u8, 255, 255, 0, 0, 255, 255, 255];
        // Row 0 is 1D; rows 1-3 exercise horizontal, pass and vertical modes.
        let g4 = ccitt_pack(&[
            "0111", "11", "1011", // 1D: white 2, black 2, white 4
            "001", "1000", "010", "1", // H: white 3, black 1; V0: white 4
            "0001", "1", // Pass: all white; V0 to the sentinel
            "010", "1", // VL1: white 7; V0: black 1
        ]);
        let g4_tiff = build_tiff_strips(8, 4, 1, &[1], 0, 4, 1, 1, 4, &[g4.clone()], &[], true);
        let image = wic_decode_tiff_frame(&g4_tiff, 0).expect("Group 4");
        let g4_rows = [
            [255_u8, 255, 0, 0, 255, 255, 255, 255],
            [255, 255, 255, 0, 255, 255, 255, 255],
            [255, 255, 255, 255, 255, 255, 255, 255],
            [255, 255, 255, 255, 255, 255, 255, 0],
        ];
        for (row, expected_row) in g4_rows.iter().enumerate() {
            for (x, value) in expected_row.iter().enumerate() {
                let pixel = &image.pixels[(row * 8 + x) * 4..(row * 8 + x) * 4 + 4];
                assert_eq!(pixel, [*value, *value, *value, 255], "G4 {row},{x}");
            }
        }
        let eol = "000000000001";
        let g3_1d = ccitt_pack(&[eol, "1000", "11", "1000", eol, "1000", "11", "1000"]);
        let g3_1d_tiff = build_tiff_strips(8, 2, 1, &[1], 0, 2, 1, 1, 2, &[g3_1d], &[], true);
        let image = wic_decode_tiff_frame(&g3_1d_tiff, 0).expect("Group 3 1D");
        for row in 0..2 {
            for (x, value) in expected.iter().enumerate() {
                assert_eq!(image.pixels[(row * 8 + x) * 4], *value, "G3 1D {row},{x}");
            }
        }
        let g3_2d = ccitt_pack(&[eol, "1", "1000", "11", "1000", eol, "0", "111"]);
        let g3_2d_tiff = build_tiff_strips(8, 2, 1, &[1], 0, 3, 1, 1, 2, &[g3_2d], &[], true);
        let image = wic_decode_tiff_frame(&g3_2d_tiff, 0).expect("Group 3 2D");
        for row in 0..2 {
            for (x, value) in expected.iter().enumerate() {
                assert_eq!(image.pixels[(row * 8 + x) * 4], *value, "G3 2D {row},{x}");
            }
        }

        let truncated_g4 = build_tiff_strips(
            8,
            4,
            1,
            &[1],
            0,
            4,
            1,
            1,
            4,
            &[g4[..g4.len() - 2].to_vec()],
            &[],
            true,
        );
        assert_eq!(
            wic_decode_tiff_frame(&truncated_g4, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "truncated Group 4 rows are rejected"
        );
        let short_g3 = ccitt_pack(&[eol, "1", "1000"]);
        let short_g3_tiff = build_tiff_strips(8, 2, 1, &[1], 0, 3, 1, 1, 2, &[short_g3], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&short_g3_tiff, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a Group 3 row missing its runs is rejected"
        );
    }

    #[test]
    fn tiff_sub_byte_tiled_grayscale_and_zero_tiles_rejected() {
        let width = 5_u32;
        let height = 3_u32;
        let tiles = build_tiff_gray4_tiled(
            width,
            height,
            4,
            2,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
            true,
        );
        let image = wic_decode_tiff_frame(&tiles, 0).expect("4-bit tiled grayscale");
        assert_eq!((image.width, image.height), (width, height));
        for index in 0..(width * height) as usize {
            let expected = (index as u8) * 17;
            assert_eq!(image.pixels[index * 4], expected, "sub-byte pixel {index}");
        }
        let mut zero_tiles = tiles;
        let (little, ifd) = wic_tiff_header(&zero_tiles).expect("TIFF header");
        let (entries, _) = wic_tiff_ifd(&zero_tiles, ifd, little).expect("IFD");
        let tag = wic_tiff_find(&entries, 322).expect("TileWidth");
        tiff_put_u32(&mut zero_tiles, tag.offset + 8, 0, little);
        assert_eq!(
            wic_decode_tiff_frame(&zero_tiles, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a zero tile width is rejected"
        );
    }

    #[test]
    fn tiff_encoder_multi_page_metadata_and_empty_pages_rejected() {
        let first = [0_u8, 0, 255, 255, 0, 255, 0, 255];
        let second = [255_u8, 0, 0, 255, 255, 255, 255, 255];
        let tiff = wic_encode_tiff_pages(&[
            WicTiffPage {
                width: 2,
                height: 1,
                bgra: &first,
                dpi: Some((300.0, 150.0)),
                description: Some("first page"),
                make: Some("CasaCam"),
                model: Some("Model W"),
                datetime: Some("2026:10:22 10:00:00"),
            },
            WicTiffPage {
                width: 1,
                height: 2,
                bgra: &second,
                dpi: Some((72.0, 72.0)),
                description: Some("second page"),
                make: None,
                model: None,
                datetime: None,
            },
        ])
        .expect("multi-page TIFF encode");
        assert!(tiff.starts_with(b"II*\0"));
        assert_eq!(wic_image_frame_count(&tiff), 2);
        let page0 = wic_decode_tiff_frame(&tiff, 0).expect("page 0");
        assert_eq!(page0.pixels, first);
        assert!((page0.dpi_x - 300.0).abs() < 0.01);
        assert!((page0.dpi_y - 150.0).abs() < 0.01);
        let page1 = wic_decode_tiff_frame(&tiff, 1).expect("page 1");
        assert_eq!(page1.pixels, second);
        assert!((page1.dpi_x - 72.0).abs() < 0.01);
        let entries = wic_tiff_metadata_entries(&tiff);
        assert!(entries.contains(&("FrameCount".to_string(), "2".to_string())));
        assert!(entries.contains(&("ImageDescription".to_string(), "first page".to_string())));
        assert!(entries.contains(&("Make".to_string(), "CasaCam".to_string())));
        assert!(entries.contains(&("Model".to_string(), "Model W".to_string())));
        assert!(entries.contains(&("DateTime".to_string(), "2026:10:22 10:00:00".to_string())));
        let (little, _) = wic_tiff_header(&tiff).unwrap();
        let offsets = wic_tiff_frame_offsets(&tiff);
        let (second_entries, _) = wic_tiff_ifd(&tiff, offsets[1], little).unwrap();
        let description = wic_tiff_find(&second_entries, 270).unwrap();
        let data = wic_tiff_entry_data(&tiff, description, little).unwrap();
        assert_eq!(&data[..11], b"second page");
        assert_eq!(
            wic_encode_tiff_pages(&[]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "the empty page list is rejected"
        );
        assert_eq!(
            wic_encode_tiff_pages(&[WicTiffPage {
                width: 2,
                height: 1,
                bgra: &first[..7],
                dpi: None,
                description: None,
                make: None,
                model: None,
                datetime: None,
            }])
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a page with short pixels is rejected"
        );
    }

    #[test]
    fn tiff_new_paths_reject_malformed_and_unsupported_streams() {
        let compression6 = build_tiff_strips(1, 1, 1, &[8], 1, 6, 1, 1, 1, &[vec![0]], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&compression6, 0).unwrap_err(),
            WINCODEC_ERR_COMPRESSIONNOTSUPPORTED
        );
        let predictor3 = build_tiff_strips(1, 1, 1, &[8], 1, 1, 3, 1, 1, &[vec![0]], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&predictor3, 0).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION
        );
        let planar3 = build_tiff_strips(1, 1, 1, &[8], 1, 1, 1, 3, 1, &[vec![0]], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&planar3, 0).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION
        );
        let corrupt_deflate =
            build_tiff_strips(2, 1, 1, &[8], 1, 8, 1, 1, 1, &[vec![1, 2, 3]], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&corrupt_deflate, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE
        );
        let truncated_ccitt =
            build_tiff_strips(8, 2, 1, &[1], 0, 4, 1, 1, 2, &[vec![0xff]], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&truncated_ccitt, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE
        );
        let garbage_jpeg = build_tiff_strips(
            2,
            2,
            3,
            &[8, 8, 8],
            6,
            7,
            1,
            1,
            2,
            &[b"notjpeg".to_vec()],
            &[],
            true,
        );
        assert_eq!(
            wic_decode_tiff_frame(&garbage_jpeg, 0).unwrap_err(),
            WINCODEC_ERR_UNKNOWNIMAGEFORMAT
        );
        let mut palette = [[0_u8; 3]; 256];
        palette[0] = [1, 2, 3];
        let gif = build_gif_layout(2, 2, &palette, &[(0, 0, 2, 2, vec![0_u8; 4], None, 50, 1)]);
        assert_eq!(
            wic_decode_gif_frame(&gif[..30], 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE
        );
        let broken = build_gif_layout(2, 2, &palette, &[(0, 0, 2, 2, vec![0_u8; 4], None, 50, 1)]);
        let truncated = &broken[..broken.len() - 8];
        assert_eq!(
            wic_decode_gif_frame(truncated, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE
        );
    }

    // ── Direct adversarial coverage of the codec primitives ────────────────

    fn ccitt_bits(data: &[u8]) -> WicCcittBits<'_> {
        WicCcittBits { data, position: 0 }
    }

    #[test]
    fn ccitt_bit_helpers_reject_truncated_and_overflowing_input() {
        assert_eq!(
            wic_ccitt_skip_eol(&mut ccitt_bits(&[0x00, 0x10])),
            true,
            "11 zero bits then a 1 is an EOL"
        );
        assert_eq!(
            wic_ccitt_skip_eol(&mut ccitt_bits(&[0x20])),
            false,
            "fewer than 11 zero bits is not an EOL"
        );
        assert_eq!(
            wic_ccitt_skip_eol(&mut ccitt_bits(&[0_u8; 5])),
            false,
            "more than 32 zero bits aborts the EOL search"
        );
        assert_eq!(
            wic_ccitt_skip_eol(&mut ccitt_bits(&[])),
            false,
            "empty input has no EOL"
        );
        assert_eq!(
            wic_ccitt_code(&mut ccitt_bits(&[0x00, 0x00]), true),
            None,
            "13 zero bits is not a valid black code"
        );
        assert_eq!(
            wic_ccitt_code(&mut ccitt_bits(&[0x00, 0x00]), false),
            None,
            "13 zero bits is not a valid white code"
        );
        let makeup = vec!["11011"; 64];
        assert_eq!(
            wic_ccitt_run(&mut ccitt_bits(&ccitt_pack(&makeup)), false),
            None,
            "64 makeup codes without a terminating code overflow the run"
        );
        let mut row = [false; 3];
        assert_eq!(
            wic_ccitt_fill(&mut row, 2, 1, true),
            true,
            "an empty span is a no-op success"
        );
        assert_eq!(
            wic_ccitt_fill(&mut row, 0, 3, true),
            false,
            "a span past the row is rejected"
        );
        assert_eq!(wic_ccitt_fill(&mut row, 0, 2, true), true);
        assert_eq!(row, [true, true, true]);

        assert_eq!(
            wic_ccitt_decode_1d(&mut ccitt_bits(&ccitt_pack(&["1100"])), 4, &mut [false; 4]),
            None,
            "a white run wider than the row is rejected"
        );
        let mut decoded = [false; 2];
        assert_eq!(
            wic_ccitt_decode_1d(&mut ccitt_bits(&ccitt_pack(&["0111"])), 2, &mut decoded),
            Some(())
        );
        assert_eq!(decoded, [false, false]);
        assert_eq!(wic_ccitt_reference_runs(&[]), Vec::<(usize, bool)>::new());
        assert_eq!(
            wic_ccitt_reference_runs(&[true, false, true]),
            vec![(0, true), (1, false), (2, true)]
        );
    }

    #[test]
    fn ccitt_mode_decodes_every_code_and_rejects_invalid_bits() {
        for (bits, expected) in [
            ("1", 0_i32),
            ("001", i32::MIN),
            ("010", -1),
            ("011", 1),
            ("0001", i32::MAX),
            ("000010", -2),
            ("000011", 2),
            ("0000010", -3),
            ("0000011", 3),
        ] {
            let packed = ccitt_pack(&[bits]);
            let mode = wic_ccitt_mode(&mut ccitt_bits(&packed));
            let actual = match mode {
                Some(WicCcittMode::Pass) => i32::MAX,
                Some(WicCcittMode::Horizontal) => i32::MIN,
                Some(WicCcittMode::Vertical(delta)) => delta,
                None => panic!("valid mode {bits} decoded as None"),
            };
            assert_eq!(actual, expected, "mode {bits}");
        }
        let invalid = ccitt_pack(&["0000000"]);
        assert_eq!(
            wic_ccitt_mode(&mut ccitt_bits(&invalid)).is_none(),
            true,
            "seven zero bits are not a 2D mode"
        );
    }

    #[test]
    fn ccitt_2d_rejects_invalid_modes_and_bounds() {
        let reference = [(3_usize, false)];
        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["1"])),
                4,
                &reference,
                &mut row
            ),
            Some(())
        );
        assert_eq!(row, [false; 4]);

        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["0001"])),
                4,
                &reference,
                &mut row
            ),
            Some(())
        );
        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["0001"])),
                3,
                &[(3, false)],
                &mut row[..3]
            ),
            None,
            "pass mode past the row width is rejected"
        );
        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["001", "0111", "11"])),
                4,
                &reference,
                &mut row
            ),
            Some(())
        );
        assert_eq!(row, [false, false, true, true]);
        let mut row = [false; 3];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["001", "0111", "11"])),
                3,
                &[(3, false)],
                &mut row
            ),
            None,
            "horizontal runs past the row width are rejected"
        );
        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["1", "1"])),
                4,
                &[(1, false)],
                &mut row
            ),
            Some(())
        );
        assert_eq!(row, [false, false, true, true]);
        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["011"])),
                4,
                &reference,
                &mut row
            ),
            None,
            "a vertical run past the row width is rejected"
        );
        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["0000010"])),
                4,
                &[(0, false)],
                &mut row
            ),
            None,
            "a vertical run before the current position is rejected"
        );
        let repeats = vec!["010"; 100];
        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&repeats)),
                4,
                &[(1, false), (1, true)],
                &mut row
            ),
            None,
            "a mode loop that never advances trips the guard"
        );
        let mut row = [false; 4];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["0000000"])),
                4,
                &reference,
                &mut row
            ),
            None,
            "an invalid 2D mode is rejected"
        );
    }

    #[test]
    fn ccitt_full_decode_rejects_empty_and_truncated_streams() {
        assert_eq!(
            wic_ccitt_decode(&[], 0, 1, 2, 0),
            None,
            "zero width is rejected"
        );
        assert_eq!(
            wic_ccitt_decode(&[], 1, 0, 2, 0),
            None,
            "zero rows is rejected"
        );
        assert_eq!(
            wic_ccitt_decode(&ccitt_pack(&["0111"]), 2, 1, 2, 0),
            Some(vec![0x00]),
            "1D white row without an EOL"
        );
        assert_eq!(
            wic_ccitt_decode(&ccitt_pack(&["0111"]), 2, 1, 2, 1),
            Some(vec![0xc0]),
            "photometric 1 inverts the samples"
        );
        let eol = "000000000001";
        assert_eq!(
            wic_ccitt_decode(
                &ccitt_pack(&[eol, "1", "0111", eol, "1", "0111"]),
                2,
                2,
                3,
                0
            ),
            Some(vec![0x00, 0x00]),
            "Group 3 1D rows with EOLs"
        );
        assert_eq!(
            wic_ccitt_decode(&ccitt_pack(&["0111", "1"]), 2, 2, 4, 0),
            Some(vec![0x00, 0x00]),
            "Group 4 first row 1D then 2D"
        );
        assert_eq!(
            wic_ccitt_decode(&[], 8, 1, 2, 0),
            None,
            "a missing 1D run is rejected"
        );
    }

    #[test]
    fn ccitt_short_rows_and_group3_selectors_are_rejected() {
        let mut row = [false; 2];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["0001"])),
                4,
                &[(3, false)],
                &mut row
            ),
            None,
            "pass mode into a short row fails the fill"
        );
        let mut row = [false; 2];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["1"])),
                4,
                &[(3, false)],
                &mut row
            ),
            None,
            "vertical mode into a short row fails the fill"
        );
        let mut row = [false; 2];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["001", "0111", "11"])),
                4,
                &[(3, false)],
                &mut row
            ),
            None,
            "horizontal mode into a short row fails the fill"
        );
        assert_eq!(
            wic_ccitt_decode(&ccitt_pack(&["000000000001", "0111"]), 2, 1, 2, 0),
            Some(vec![0x00]),
            "Group 3 1D accepts an EOL before the run"
        );
        assert_eq!(
            wic_ccitt_decode(&ccitt_pack(&["000000000001", "0", "1"]), 2, 1, 3, 0),
            Some(vec![0x00]),
            "Group 3 accepts a 2D row selected by a zero bit"
        );
    }

    #[test]
    fn tiff_packbits_rejects_and_clips_malformed_runs() {
        assert_eq!(wic_tiff_packbits_decode(&[0x00, 0xaa], 1), Some(vec![0xaa]));
        assert_eq!(
            wic_tiff_packbits_decode(&[0xff, 0xaa], 3),
            Some(vec![0xaa, 0xaa])
        );
        assert_eq!(
            wic_tiff_packbits_decode(&[0x02, 1, 2, 3], 2),
            Some(vec![1, 2]),
            "over-long literal output is truncated to the expected size"
        );
        assert_eq!(
            wic_tiff_packbits_decode(&[0x80, 0x00, 0xaa], 1),
            Some(vec![0xaa]),
            "the -128 header is a documented no-op"
        );
        assert_eq!(
            wic_tiff_packbits_decode(&[0x05, 0x01], 8),
            None,
            "a literal run past the buffer is rejected"
        );
        assert_eq!(
            wic_tiff_packbits_decode(&[0xfe], 8),
            None,
            "a repeat run without its value is rejected"
        );
        assert_eq!(
            wic_tiff_decompress(&[1, 2, 3], 1, 3),
            Ok(vec![1, 2, 3]),
            "compression 1 is a verbatim copy"
        );
        assert_eq!(
            wic_tiff_decompress(&[0], 9, 1).unwrap_err(),
            WINCODEC_ERR_COMPRESSIONNOTSUPPORTED
        );
    }

    #[test]
    fn tiff_predictor_rejects_unsupported_widths_and_endianness() {
        let mut data = [1_u8, 2, 3, 4];
        assert_eq!(
            wic_tiff_apply_predictor(&mut data, 4, 2, 2, 8, false, true),
            true
        );
        assert_eq!(data, [1, 2, 4, 6]);
        let mut data = [1_u8, 2];
        assert_eq!(
            wic_tiff_apply_predictor(&mut data, 2, 2, 3, 8, true, true),
            true
        );
        assert_eq!(data, [1, 3]);
        let mut data = [0_u8, 1, 0, 2];
        assert_eq!(
            wic_tiff_apply_predictor(&mut data, 4, 2, 1, 16, true, true),
            true
        );
        assert_eq!(data, [0, 1, 0, 3]);
        let mut data = [0_u8, 1, 0, 2, 0, 3, 0, 4];
        assert_eq!(
            wic_tiff_apply_predictor(&mut data, 8, 2, 2, 16, false, false),
            true
        );
        assert_eq!(data, [0, 1, 0, 2, 0, 4, 0, 6]);
        assert_eq!(
            wic_tiff_apply_predictor(&mut [1_u8], 0, 1, 1, 8, false, true),
            false,
            "zero row bytes is rejected"
        );
        assert_eq!(
            wic_tiff_apply_predictor(&mut [1_u8], 2, 1, 1, 8, false, true),
            false,
            "a row shorter than row_bytes is rejected"
        );
        assert_eq!(
            wic_tiff_apply_predictor(&mut [1_u8, 2], 2, 4, 1, 8, false, true),
            false,
            "a row shorter than the sample count is rejected"
        );
        assert_eq!(
            wic_tiff_apply_predictor(&mut [1_u8, 2], 2, 1, 1, 4, false, true),
            false,
            "sub-byte predictors are unsupported"
        );
        assert_eq!(
            wic_tiff_apply_predictor(&mut [1_u8, 2], 2, 2, 1, 16, false, true),
            false,
            "a 16-bit row with only one byte is rejected"
        );
    }

    #[test]
    fn tiff_packing_helpers_reject_truncated_buffers() {
        assert_eq!(wic_tiff_bit(&[0x80], 0), Some(true));
        assert_eq!(wic_tiff_bit(&[0x80], 1), Some(false));
        assert_eq!(wic_tiff_bit(&[0x80], 8), None);
        let mut data = [0_u8; 1];
        assert_eq!(wic_tiff_set_bit(&mut data, 0, true), true);
        assert_eq!(data, [0x80]);
        assert_eq!(wic_tiff_set_bit(&mut data, 0, false), true);
        assert_eq!(data, [0x00]);
        assert_eq!(wic_tiff_set_bit(&mut data, 8, true), false);
        let mut destination = [0_u8; 2];
        assert_eq!(
            wic_tiff_copy_packed_row(&mut destination, 0, &[0b1010_0000], 0, 4, 2),
            true
        );
        assert_eq!(destination, [0b1010_0000, 0]);
        assert_eq!(
            wic_tiff_copy_packed_row(&mut [0_u8; 1], 0, &[0], 0, 4, 3),
            false,
            "a source shorter than the packed row is rejected"
        );
        assert_eq!(
            wic_tiff_copy_packed_row(&mut [0_u8; 1], 8, &[0, 0], 0, 4, 2),
            false,
            "a destination shorter than the packed row is rejected"
        );
        assert_eq!(
            wic_tiff_pixel_sample(&[0x12, 0x34], 0, 16, true),
            Some(0x34)
        );
        assert_eq!(
            wic_tiff_pixel_sample(&[0x12, 0x34], 0, 16, false),
            Some(0x12)
        );
        assert_eq!(
            wic_tiff_pixel_sample(&[0x12, 0x34], 1, 16, true),
            None,
            "a truncated 16-bit sample is rejected"
        );
        assert_eq!(wic_tiff_pixel_sample(&[0b1100_0000], 0, 2, true), Some(3));
        assert_eq!(wic_tiff_pixel_sample(&[0x0f], 1, 4, true), Some(15));
        assert_eq!(
            wic_tiff_pixel_sample(&[0xff], 0, 3, true),
            None,
            "3-bit samples are unsupported"
        );
    }

    #[test]
    fn tiff_sample_conversion_rejects_unsupported_layouts() {
        let planar = vec![vec![10, 20], vec![30, 40], vec![50, 60]];
        assert_eq!(
            wic_tiff_to_bgra(&planar, 2, 1, 2, 8, 3, 2, &[], true, true),
            Ok(vec![50, 30, 10, 255, 60, 40, 20, 255]),
            "planar RGB samples convert to BGRA"
        );
        assert_eq!(
            wic_tiff_to_bgra(&planar, 2, 1, 2, 8, 1, 2, &[], true, true),
            Err(WINCODEC_ERR_BADIMAGE),
            "RGB with fewer than three samples is rejected"
        );
        assert_eq!(
            wic_tiff_to_bgra(&[vec![0x56]], 2, 1, 1, 4, 1, 1, &[], true, false),
            Ok(vec![85, 85, 85, 255, 102, 102, 102, 255]),
            "4-bit grayscale scales to 8 bits"
        );
        assert_eq!(
            wic_tiff_to_bgra(&[vec![5, 6]], 2, 1, 2, 8, 1, 0, &[], true, false),
            Ok(vec![250, 250, 250, 255, 249, 249, 249, 255]),
            "photometric 0 inverts grayscale"
        );
        assert_eq!(
            wic_tiff_to_bgra(&[vec![0]], 1, 1, 1, 8, 2, 1, &[], true, false),
            Err(WINCODEC_ERR_BADIMAGE),
            "grayscale with two samples is rejected"
        );
        assert_eq!(
            wic_tiff_to_bgra(&[vec![0]], 1, 1, 1, 8, 2, 3, &[], true, false),
            Err(WINCODEC_ERR_BADIMAGE),
            "a palette with two samples is rejected"
        );
        assert_eq!(
            wic_tiff_to_bgra(&[vec![0]], 1, 1, 1, 9, 1, 3, &[], true, false),
            Err(WINCODEC_ERR_BADIMAGE),
            "a palette deeper than eight bits is rejected"
        );
        assert_eq!(
            wic_tiff_to_bgra(&[vec![0]], 1, 1, 1, 3, 1, 3, &[0; 3], true, false),
            Err(WINCODEC_ERR_BADIMAGE),
            "a palette with too few entries is rejected"
        );
        assert_eq!(
            wic_tiff_to_bgra(&[vec![0]], 1, 1, 1, 4, 1, 3, &[1, 2, 3], true, false),
            Err(WINCODEC_ERR_BADIMAGE),
            "a 4-bit palette needs 16 entries"
        );
        let mut palette = vec![0_u32; 16 * 3];
        palette[0] = 65535;
        palette[16] = 32768;
        assert_eq!(
            wic_tiff_to_bgra(&[vec![0]], 1, 1, 1, 4, 1, 3, &palette, true, false),
            Ok(vec![0, 128, 255, 255]),
            "palette entries scale from 16-bit"
        );
        assert_eq!(
            wic_tiff_to_bgra(&[vec![0]], 1, 1, 1, 8, 1, 6, &[], true, false),
            Err(WINCODEC_ERR_UNSUPPORTEDOPERATION),
            "an unknown photometric interpretation is rejected"
        );
    }

    #[test]
    fn tiff_blit_boundary_clips_out_of_canvas_rows_and_columns() {
        let decoded = WicDecodedImage {
            width: 2,
            height: 2,
            pixels: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            container: GUID_CONTAINER_FORMAT_TIFF,
            codec: 4,
            dpi_x: 96.0,
            dpi_y: 96.0,
        };
        let mut destination = [0_u8; 4];
        assert_eq!(
            wic_tiff_blit_bgra(&decoded, &mut destination, 1, 1, 0, 0),
            true
        );
        assert_eq!(destination, [1, 2, 3, 4]);
        let mut destination = [0_u8; 16];
        assert_eq!(
            wic_tiff_blit_bgra(&decoded, &mut destination, 2, 2, 1, 1),
            true
        );
        assert_eq!(&destination[12..], [1, 2, 3, 4]);
        assert_eq!(&destination[..12], [0_u8; 12]);
        let mut destination = [0_u8; 16];
        assert_eq!(
            wic_tiff_blit_bgra(&decoded, &mut destination, 2, 2, 2, 0),
            true
        );
        assert_eq!(destination, [0_u8; 16], "the column clip draws nothing");
        assert_eq!(
            wic_tiff_blit_bgra(&decoded, &mut destination, 2, 2, 0, 2),
            true
        );
        assert_eq!(destination, [0_u8; 16], "the row clip draws nothing");
    }

    #[test]
    fn metadata_dispatch_rejects_png_and_exif_edge_payloads() {
        let png = build_png(
            1,
            1,
            8,
            0,
            0,
            &[(b"tEXt", png_text("Author", "Casa"))],
            &[0, 7],
        );
        assert_eq!(
            wic_image_metadata_entries(&png, 1),
            vec![("Author".to_string(), "Casa".to_string())]
        );
        let mut exif_tiff_bytes = b"II*\0\x08\0\0\0".to_vec();
        exif_tiff_bytes.extend_from_slice(&[0_u8; 8]);
        let mut jpeg = vec![0xff, 0xd8];
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&exif_tiff_bytes);
        wic_jpeg_push_segment(&mut jpeg, 0xe1, &payload);
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_image_metadata_entries(&jpeg, 2),
            Vec::<(String, String)>::new()
        );
        assert_eq!(
            wic_image_thumbnail(&png, 1),
            None,
            "a PNG without eXIf has no thumbnail"
        );
        assert_eq!(
            wic_image_thumbnail(&jpeg, 2),
            None,
            "an EXIF directory without thumbnail tags has no thumbnail"
        );
        let mut png_with_exif = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png_with_exif, b"IHDR", &png_ihdr(1, 1, 8, 0));
        wic_png_chunk(&mut png_with_exif, b"eXIf", &exif_tiff_bytes);
        wic_png_chunk(&mut png_with_exif, b"IDAT", &deflate_bytes(&[0, 0]));
        wic_png_chunk(&mut png_with_exif, b"IEND", &[]);
        assert_eq!(wic_image_thumbnail(&png_with_exif, 1), None);
    }

    #[test]
    fn metadata_entries_reject_truncated_serialized_profiles() {
        assert_eq!(
            wic_metadata_deserialize(b"NOTMAGIC").is_empty(),
            true,
            "a profile without the magic is empty"
        );
        assert_eq!(
            wic_metadata_deserialize(b"WICMETA1").is_empty(),
            true,
            "a profile without the entry count is empty"
        );
        assert_eq!(
            wic_metadata_deserialize(b"WICMETA1\x01\x00\x00\x00").is_empty(),
            true,
            "a missing key length ends the entry loop"
        );
        assert_eq!(
            wic_metadata_deserialize(b"WICMETA1\x01\x00\x00\x00\x02\x00\x00\x00A").is_empty(),
            true,
            "a truncated key ends the entry loop"
        );
        assert_eq!(
            wic_metadata_deserialize(b"WICMETA1\x01\x00\x00\x00\x01\x00\x00\x00A").is_empty(),
            true,
            "a missing value length ends the entry loop"
        );
        assert_eq!(
            wic_metadata_deserialize(b"WICMETA1\x01\x00\x00\x00\x01\x00\x00\x00A\x02\x00\x00\x00B")
                .is_empty(),
            true,
            "a truncated value ends the entry loop"
        );
        let valid = wic_metadata_serialize(&[("Author".to_string(), "Casa".to_string())]);
        assert_eq!(
            wic_metadata_deserialize(&valid),
            vec![("Author".to_string(), "Casa".to_string())]
        );
        assert_eq!(
            wic_metadata_lookup(&valid_entries(), "Missing"),
            None,
            "an absent property is a miss"
        );
    }

    fn valid_entries() -> Vec<(String, String)> {
        vec![("Orientation".to_string(), "6".to_string())]
    }

    #[test]
    fn exif_tag_mapping_rejects_unknown_tags() {
        assert_eq!(wic_exif_tag_name(270), Some("ImageDescription"));
        assert_eq!(wic_exif_tag_name(274), Some("Orientation"));
        assert_eq!(wic_exif_tag_name(305), Some("Software"));
        assert_eq!(wic_exif_tag_name(315), Some("Artist"));
        assert_eq!(wic_exif_tag_name(33432), Some("Copyright"));
        assert_eq!(wic_exif_tag_name(36867), Some("DateTimeOriginal"));
        assert_eq!(wic_exif_tag_name(36868), Some("DateTimeDigitized"));
        assert_eq!(wic_exif_tag_name(65000), None, "an unknown tag has no name");
    }

    #[test]
    fn png_chunk_scanner_rejects_truncated_and_overflowing_chunks() {
        assert_eq!(
            wic_png_chunks(b"not a png", |_, _| panic!("must not visit")),
            (),
            "a non-PNG signature returns without visiting"
        );
        let mut huge = b"\x89PNG\r\n\x1a\n".to_vec();
        huge.extend_from_slice(&0x7fff_ffff_u32.to_be_bytes());
        huge.extend_from_slice(b"IHDR");
        assert_eq!(
            wic_png_text_entries(&huge).is_empty(),
            true,
            "a chunk length past the buffer stops the scan"
        );
        let mut truncated = b"\x89PNG\r\n\x1a\n".to_vec();
        truncated.extend_from_slice(&10_u32.to_be_bytes());
        truncated.extend_from_slice(b"tEXt");
        truncated.extend_from_slice(&[0_u8; 4]);
        assert_eq!(
            wic_png_text_entries(&truncated).is_empty(),
            true,
            "a truncated chunk body stops the scan"
        );
        assert_eq!(
            wic_png_inflate(&deflate_bytes(b"hello")).as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(
            wic_png_inflate(b"not zlib"),
            None,
            "invalid zlib data has no inflated output"
        );
    }

    #[test]
    fn png_text_entries_reject_malformed_keyword_and_compression() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"tEXt", b"NO_NUL_HERE");
        assert_eq!(
            wic_png_text_entries(&png),
            Vec::<(String, String)>::new(),
            "tEXt without a NUL separator is ignored"
        );

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"iTXt", b"NO_NUL");
        assert_eq!(
            wic_png_text_entries(&png),
            Vec::<(String, String)>::new(),
            "iTXt without a keyword terminator is ignored"
        );

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"iTXt", b"K\0\x01");
        assert_eq!(
            wic_png_text_entries(&png),
            Vec::<(String, String)>::new(),
            "iTXt without the compression bytes is ignored"
        );

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"iTXt", b"K\0\0\0no-language\0translated");
        assert_eq!(
            wic_png_text_entries(&png),
            Vec::<(String, String)>::new(),
            "iTXt without a language terminator is ignored"
        );

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"iTXt", b"K\0\0\0lang\0translated");
        assert_eq!(
            wic_png_text_entries(&png),
            Vec::<(String, String)>::new(),
            "iTXt without a translated-keyword terminator is ignored"
        );

        let mut compressed = b"K\0\x01\x00\0\0".to_vec();
        compressed.extend_from_slice(&deflate_bytes(b"compressed text"));
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"iTXt", &compressed);
        assert_eq!(
            wic_png_text_entries(&png),
            vec![("K".to_string(), "compressed text".to_string())]
        );

        let mut bad = b"K\0\x01\x00lang\0\0not-zlib".to_vec();
        bad[3] = 0;
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"iTXt", &bad);
        assert_eq!(
            wic_png_text_entries(&png),
            Vec::<(String, String)>::new(),
            "invalid compressed iTXt text is ignored"
        );

        let mut unsupported = b"K\0\x02\x01lang\0\0text".to_vec();
        unsupported[3] = 0;
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"iTXt", &unsupported);
        assert_eq!(
            wic_png_text_entries(&png),
            Vec::<(String, String)>::new(),
            "unknown iTXt compression methods are ignored"
        );

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"eXIf", b"II*\0data");
        assert_eq!(wic_png_exif_chunk(&png), Some(b"II*\0data".to_vec()));
    }

    #[test]
    fn jpeg_exif_scanner_rejects_malformed_segments() {
        assert_eq!(
            wic_jpeg_exif(b"NOTJPEG"),
            None,
            "a non-JPEG stream has no EXIF"
        );
        assert_eq!(
            wic_jpeg_exif(&[0xff, 0xd8, 0x00, 0x00]),
            None,
            "an APP segment without 0xff is rejected"
        );
        assert_eq!(
            wic_jpeg_exif(&[0xff, 0xd8, 0xff, 0xd9]),
            None,
            "EOI before APP1 has no EXIF"
        );
        assert_eq!(
            wic_jpeg_exif(&[0xff, 0xd8, 0xff, 0xda, 0x00, 0x02]),
            None,
            "SOS before APP1 has no EXIF"
        );
        let mut standalone = vec![0xff, 0xd8, 0xff, 0xd8];
        wic_jpeg_push_segment(&mut standalone, 0xe1, b"Exif\0\0II*\0");
        assert_eq!(
            wic_jpeg_exif(&standalone),
            Some(&b"II*\0"[..]),
            "a standalone marker before APP1 is skipped"
        );
        assert_eq!(
            wic_jpeg_exif(&[0xff, 0xd8, 0xff, 0xe1, 0x00, 0x01]),
            None,
            "a length below two is rejected"
        );
        assert_eq!(
            wic_jpeg_exif(&[0xff, 0xd8, 0xff, 0xe1, 0x00, 0x20, 0x00]),
            None,
            "a segment past the buffer is rejected"
        );
        let mut app0 = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut app0, 0xe0, b"JFIF\0");
        assert_eq!(
            wic_jpeg_exif(&app0),
            None,
            "a stream ending after APP0 has no EXIF"
        );
    }

    #[test]
    fn tiff_ifd_and_entry_helpers_reject_truncated_metadata() {
        assert_eq!(
            wic_tiff_header(&[0_u8; 7]),
            None,
            "a TIFF shorter than its header is rejected"
        );
        assert_eq!(
            wic_tiff_header(b"XX\x2a\x00\x08\x00\x00\x00"),
            None,
            "an unknown byte order is rejected"
        );
        assert_eq!(
            wic_tiff_header(b"II\x2b\x00\x08\x00\x00\x00"),
            None,
            "a magic other than 42 is rejected"
        );
        assert_eq!(
            wic_tiff_ifd(&[0x01, 0x10], 0, true).is_none(),
            true,
            "an IFD with more than 4096 entries is rejected"
        );
        assert_eq!(
            wic_tiff_ifd(&[0x01, 0x00, 0x00, 0x00], 0, true).is_none(),
            true,
            "an IFD whose entries run past the buffer is rejected"
        );
        assert_eq!(
            wic_tiff_frame_offsets(b"NOTATIFF").is_empty(),
            true,
            "a malformed TIFF has no frames"
        );
        let entry = WicTiffEntry {
            tag: 256,
            kind: 1,
            count: 1,
            offset: 0,
        };
        assert_eq!(
            wic_tiff_values(&[0_u8; 9], &entry, true),
            Vec::<u32>::new(),
            "an entry kind without numeric values yields none"
        );
        let entry = WicTiffEntry {
            tag: 256,
            kind: 3,
            count: 1,
            offset: 0,
        };
        let mut inline = [0_u8; 10];
        tiff_put_u16(&mut inline, 8, 42, true);
        assert_eq!(wic_tiff_values(&inline, &entry, true), vec![42]);
        assert_eq!(
            wic_tiff_rational(
                &inline,
                &[WicTiffEntry {
                    tag: 282,
                    kind: 3,
                    count: 1,
                    offset: 0
                }],
                282,
                true
            ),
            None,
            "a non-rational tag is rejected"
        );
        assert_eq!(
            wic_tiff_rational(
                &inline,
                &[WicTiffEntry {
                    tag: 282,
                    kind: 5,
                    count: 0,
                    offset: 0
                }],
                282,
                true
            ),
            None,
            "an empty rational is rejected"
        );
        let mut rational = [0_u8; 24];
        tiff_put_u32(&mut rational, 8, 16, true);
        tiff_put_u32(&mut rational, 16, 3, true);
        tiff_put_u32(&mut rational, 20, 2, true);
        let entry = WicTiffEntry {
            tag: 282,
            kind: 5,
            count: 1,
            offset: 0,
        };
        assert_eq!(
            wic_tiff_rational(&rational, &[entry], 282, true),
            Some(1.5),
            "a valid rational divides numerator by denominator"
        );
        let mut zero_denominator = rational;
        tiff_put_u32(&mut zero_denominator, 20, 0, true);
        assert_eq!(
            wic_tiff_rational(
                &zero_denominator,
                &[WicTiffEntry {
                    tag: 282,
                    kind: 5,
                    count: 1,
                    offset: 0,
                }],
                282,
                true
            ),
            None,
            "a zero denominator is rejected"
        );
        assert_eq!(
            wic_tiff_entry_data(
                &rational[..12],
                &WicTiffEntry {
                    tag: 282,
                    kind: 5,
                    count: 1,
                    offset: 0
                },
                true
            ),
            None,
            "a rational past the buffer is rejected"
        );
        assert_eq!(
            wic_tiff_entry_u32(
                &inline,
                &WicTiffEntry {
                    tag: 274,
                    kind: 3,
                    count: 1,
                    offset: 0
                },
                true
            ),
            Some(42)
        );
        assert_eq!(
            wic_tiff_entry_u32(
                &inline,
                &WicTiffEntry {
                    tag: 274,
                    kind: 2,
                    count: 1,
                    offset: 0
                },
                true
            ),
            None,
            "an ASCII tag has no numeric value"
        );
    }

    #[test]
    fn tiff_thumbnail_extraction_rejects_malformed_ifd_links() {
        assert_eq!(wic_tiff_thumbnail(&[0_u8; 7]), None);
        assert_eq!(
            wic_tiff_thumbnail(b"XX\x2a\x00\x08\x00\x00\x00"),
            None,
            "an unknown byte order is rejected"
        );
        assert_eq!(
            wic_tiff_thumbnail(b"II\x2b\x00\x08\x00\x00\x00"),
            None,
            "a bad magic is rejected"
        );
        assert_eq!(
            wic_tiff_thumbnail(b"II\x2a\x00\x00\x00\x00\x00"),
            None,
            "a zero IFD offset is rejected"
        );
        let mut no_next = vec![0_u8; 30];
        no_next[..2].copy_from_slice(b"II");
        tiff_put_u16(&mut no_next, 2, 42, true);
        tiff_put_u32(&mut no_next, 4, 8, true);
        tiff_put_u16(&mut no_next, 8, 0, true);
        tiff_put_u32(&mut no_next, 10, 0, true);
        assert_eq!(
            wic_tiff_thumbnail(&no_next),
            None,
            "a zero next-IFD means no thumbnail"
        );

        let mut tiff = vec![0_u8; 59];
        tiff[..2].copy_from_slice(b"II");
        tiff_put_u16(&mut tiff, 2, 42, true);
        tiff_put_u32(&mut tiff, 4, 8, true);
        tiff_put_u16(&mut tiff, 8, 1, true);
        tiff_put_u16(&mut tiff, 10, 256, true);
        tiff_put_u16(&mut tiff, 12, 3, true);
        tiff_put_u32(&mut tiff, 14, 1, true);
        tiff_put_u16(&mut tiff, 18, 1, true);
        tiff_put_u32(&mut tiff, 22, 26, true);
        tiff_put_u16(&mut tiff, 26, 2, true);
        tiff_put_u16(&mut tiff, 28, 513, true);
        tiff_put_u16(&mut tiff, 30, 4, true);
        tiff_put_u32(&mut tiff, 32, 1, true);
        tiff_put_u32(&mut tiff, 36, 56, true);
        tiff_put_u16(&mut tiff, 40, 514, true);
        tiff_put_u16(&mut tiff, 42, 4, true);
        tiff_put_u32(&mut tiff, 44, 1, true);
        tiff_put_u32(&mut tiff, 48, 3, true);
        tiff_put_u32(&mut tiff, 52, 0, true);
        tiff[56..59].copy_from_slice(b"abc");
        assert_eq!(wic_tiff_thumbnail(&tiff), Some(b"abc".to_vec()));

        tiff_put_u16(&mut tiff, 28, 515, true);
        assert_eq!(
            wic_tiff_thumbnail(&tiff),
            None,
            "an IFD without the JPEGInterchange tags has no thumbnail"
        );
    }

    #[test]
    fn exif_metadata_rejects_non_jpeg_and_malformed_directories() {
        assert_eq!(
            wic_exif_metadata(b"NOTJPEG"),
            (Vec::<(String, String)>::new(), None)
        );
        let mut jpeg = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut jpeg, 0xe1, b"Exif\0\0II*");
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_exif_metadata(&jpeg),
            (Vec::<(String, String)>::new(), None),
            "an EXIF payload shorter than eight bytes is rejected"
        );
        let mut jpeg = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut jpeg, 0xe1, b"Exif\0\0XX\x2a\x00\x08\x00\x00\x00");
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_exif_metadata(&jpeg),
            (Vec::<(String, String)>::new(), None),
            "an unknown EXIF byte order is rejected"
        );
        let mut jpeg = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut jpeg, 0xe1, b"Exif\0\0II\x2b\x00\x08\x00\x00\x00");
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_exif_metadata(&jpeg),
            (Vec::<(String, String)>::new(), None),
            "a bad EXIF magic is rejected"
        );
        let mut jpeg = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut jpeg, 0xe1, b"Exif\0\0II\x2a\x00\xff\xff\x00\x00");
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_exif_metadata(&jpeg),
            (Vec::<(String, String)>::new(), None),
            "an out-of-range IFD offset is rejected"
        );

        let mut tiff = vec![0_u8; 60];
        tiff[..2].copy_from_slice(b"II");
        tiff_put_u16(&mut tiff, 2, 42, true);
        tiff_put_u32(&mut tiff, 4, 8, true);
        tiff_put_u16(&mut tiff, 8, 3, true);
        tiff_put_u16(&mut tiff, 10, 65000, true);
        tiff_put_u16(&mut tiff, 12, 3, true);
        tiff_put_u32(&mut tiff, 14, 1, true);
        tiff_put_u16(&mut tiff, 18, 1, true);
        tiff_put_u16(&mut tiff, 22, 274, true);
        tiff_put_u16(&mut tiff, 24, 3, true);
        tiff_put_u32(&mut tiff, 26, 1, true);
        tiff_put_u16(&mut tiff, 30, 6, true);
        tiff_put_u16(&mut tiff, 34, 271, true);
        tiff_put_u16(&mut tiff, 36, 2, true);
        tiff_put_u32(&mut tiff, 38, 10, true);
        tiff_put_u32(&mut tiff, 42, 250, true);
        tiff_put_u32(&mut tiff, 46, 0, true);
        let mut jpeg = vec![0xff, 0xd8];
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&tiff);
        wic_jpeg_push_segment(&mut jpeg, 0xe1, &payload);
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_exif_metadata(&jpeg),
            (vec![("Orientation".to_string(), "6".to_string())], None),
            "unknown tags and unreadable entries are skipped; numeric tags are kept"
        );
    }

    #[test]
    fn metadata_dispatch_rejects_unknown_codecs() {
        assert_eq!(
            wic_image_metadata_entries(b"", 9),
            Vec::<(String, String)>::new(),
            "an unknown codec has no metadata"
        );
        assert_eq!(
            wic_image_thumbnail(b"", 9),
            None,
            "an unknown codec has no thumbnail"
        );
        assert_eq!(
            wic_image_thumbnail(b"NOTATIFF", 4),
            None,
            "a malformed TIFF has no thumbnail"
        );
        assert_eq!(
            wic_image_metadata_entries(b"NOTAGIF", 3),
            Vec::<(String, String)>::new(),
            "a malformed GIF has no metadata"
        );
    }

    #[test]
    fn gif_subblocks_reject_oversized_accumulation() {
        let mut chain = Vec::new();
        let mut payload = 0_usize;
        while payload <= 64 * 1024 * 1024 {
            chain.push(255_u8);
            chain.extend_from_slice(&[0_u8; 255]);
            payload += 255;
        }
        chain.push(0);
        let mut position = 0;
        assert_eq!(
            wic_gif_subblocks(&chain, &mut position),
            None,
            "a sub-block chain larger than 64 MiB is rejected"
        );
    }

    #[test]
    fn gif_lzw_rejects_invalid_code_sizes_and_codes() {
        assert_eq!(wic_gif_lzw_decode(&[0], 0, 10), None);
        assert_eq!(wic_gif_lzw_decode(&[0], 12, 10), None);
        assert_eq!(
            wic_gif_lzw_decode(&[], 8, 10),
            Some(Vec::new()),
            "an empty code stream ends cleanly"
        );
        assert_eq!(
            wic_gif_lzw_decode(&gif_pack_codes(&[(4, 3), (5, 3)]), 2, 10),
            Some(Vec::new()),
            "the end code stops decoding"
        );
        assert_eq!(
            wic_gif_lzw_decode(&gif_pack_codes(&[(4, 3), (0, 3), (6, 3), (5, 3)]), 2, 10),
            Some(vec![0, 0, 0]),
            "a code equal to the next dictionary index repeats the prefix"
        );
        assert_eq!(
            wic_gif_lzw_decode(&gif_pack_codes(&[(4, 3), (0, 3), (7, 3)]), 2, 10),
            None,
            "a code past the next dictionary index is rejected"
        );
        let mut codes = vec![(256_u16, 9_u32)];
        for _ in 0..255 {
            codes.push((0, 9));
        }
        assert_eq!(
            wic_gif_lzw_decode(&gif_pack_codes(&codes), 8, 255),
            Some(vec![0; 255]),
            "the code width grows when the dictionary reaches 512 entries"
        );
    }

    #[test]
    fn gif_lzw_dictionary_reset_boundary_round_trips() {
        let mut state = 0x1234_5678_u32;
        let indices: Vec<u8> = (0..20_000)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 16) as u8
            })
            .collect();
        let encoded = wic_gif_lzw_encode(&indices);
        assert_eq!(
            wic_gif_lzw_decode(&encoded, 8, indices.len()),
            Some(indices),
            "the encoder reset the 4096-entry dictionary and stayed decodable"
        );
    }

    fn tiff_pack_codes(codes: &[(u16, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut accumulator = 0_u64;
        let mut bits = 0_u32;
        for (code, width) in codes {
            accumulator = (accumulator << width) | u64::from(*code);
            bits += width;
            while bits >= 8 {
                bits -= 8;
                out.push((accumulator >> bits) as u8);
            }
        }
        if bits > 0 {
            out.push((accumulator << (8 - bits)) as u8);
        }
        out
    }

    #[test]
    fn tiff_lzw_rejects_invalid_codes_and_accepts_next_index() {
        assert_eq!(
            wic_tiff_lzw_decode(&tiff_pack_codes(&[(256, 9), (257, 9)]), 10),
            Some(Vec::new()),
            "the end code stops decoding"
        );
        assert_eq!(
            wic_tiff_lzw_decode(
                &tiff_pack_codes(&[(256, 9), (0, 9), (258, 9), (257, 9)]),
                10
            ),
            Some(vec![0, 0, 0]),
            "a code equal to the next dictionary index repeats the prefix"
        );
        assert_eq!(
            wic_tiff_lzw_decode(&tiff_pack_codes(&[(256, 9), (0, 9), (259, 9)]), 10),
            None,
            "a code past the next dictionary index is rejected"
        );
        assert_eq!(
            wic_tiff_lzw_decode(&tiff_pack_codes(&[(256, 9)]), 10),
            None,
            "a stream ending after the clear code is rejected"
        );
    }

    #[test]
    fn source_dimensions_boundary_transforms() {
        let scaler = WicObjectState {
            kind: WicObjectKind::Scaler,
            width: 4,
            height: 5,
            ..Default::default()
        };
        assert_eq!(wic_source_dimensions(&scaler), (4, 5));
        let clipper = WicObjectState {
            kind: WicObjectKind::Clipper,
            width: 9,
            height: 9,
            clip: None,
            ..Default::default()
        };
        assert_eq!(wic_source_dimensions(&clipper), (9, 9));
        let clipper = WicObjectState {
            kind: WicObjectKind::Clipper,
            width: 9,
            height: 9,
            clip: Some([1, 2, 3, 4]),
            ..Default::default()
        };
        assert_eq!(wic_source_dimensions(&clipper), (3, 4));
        let clipper = WicObjectState {
            kind: WicObjectKind::Clipper,
            clip: Some([-1, -2, -3, -4]),
            ..Default::default()
        };
        assert_eq!(wic_source_dimensions(&clipper), (0, 0));
        for (transform, expected) in [
            (WIC_TRANSFORM_ROTATE_90, (5, 4)),
            (WIC_TRANSFORM_ROTATE_180, (4, 5)),
            (WIC_TRANSFORM_ROTATE_270, (5, 4)),
            (WIC_TRANSFORM_FLIP_HORIZONTAL, (4, 5)),
        ] {
            let rotator = WicObjectState {
                kind: WicObjectKind::FlipRotator,
                width: 4,
                height: 5,
                transform,
                ..Default::default()
            };
            assert_eq!(wic_source_dimensions(&rotator), expected, "{transform}");
        }
        let converter = WicObjectState {
            kind: WicObjectKind::FormatConverter,
            width: 6,
            height: 7,
            ..Default::default()
        };
        assert_eq!(wic_source_dimensions(&converter), (6, 7));
        let bitmap = bitmap_state(8, 9, vec![0; 8 * 9 * 4]);
        assert_eq!(wic_source_dimensions(&bitmap), (8, 9));
    }

    fn bitmap_state(width: u32, height: u32, pixels: Vec<u8>) -> WicObjectState {
        WicObjectState {
            kind: WicObjectKind::Bitmap,
            width,
            height,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            pixels,
            ..Default::default()
        }
    }

    #[test]
    fn copy_source_pixels_rejects_missing_wrapped_objects() {
        let mut objects = HashMap::new();
        let invalid = WicObjectState {
            kind: WicObjectKind::Bitmap,
            width: 1,
            height: 1,
            pixel_format: GUID_PIXEL_FORMAT_DONT_CARE,
            pixels: vec![1, 2, 3, 4],
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &invalid, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "an invalid source pixel format yields no pixels"
        );
        let converter = WicObjectState {
            kind: WicObjectKind::FormatConverter,
            width: 1,
            height: 1,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_RGBA,
            source: 99,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &converter, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a converter without its wrapped source yields no pixels"
        );
        objects.insert(1, invalid.clone());
        assert_eq!(
            wic_copy_source_pixels(&objects, &converter, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a converter over an invalid source yields no pixels"
        );
        let clipper = WicObjectState {
            kind: WicObjectKind::Clipper,
            source: 99,
            clip: Some([0, 0, 1, 1]),
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &clipper, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a clipper without its wrapped source yields no pixels"
        );
        let scaler = WicObjectState {
            kind: WicObjectKind::Scaler,
            width: 1,
            height: 1,
            source: 99,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &scaler, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a scaler without its wrapped source yields no pixels"
        );
        let rotator = WicObjectState {
            kind: WicObjectKind::FlipRotator,
            width: 1,
            height: 1,
            source: 99,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &rotator, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a flip-rotator without its wrapped source yields no pixels"
        );
        let palette = WicObjectState {
            kind: WicObjectKind::Palette,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &palette, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a non-source object yields no pixels"
        );
    }

    #[test]
    fn copy_source_pixels_edge_transforms() {
        let mut objects = HashMap::new();
        objects.insert(7, bitmap_state(2, 1, vec![10, 11, 12, 13, 20, 21, 22, 23]));
        assert_eq!(
            wic_copy_source_pixels(&objects, &objects[&7], 0, 0, 2, 2),
            vec![10, 11, 12, 13, 20, 21, 22, 23],
            "rows past the bitmap height are clipped"
        );
        let converter = WicObjectState {
            kind: WicObjectKind::FormatConverter,
            width: 2,
            height: 1,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_RGBA,
            source: 7,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &converter, 0, 1, 1, 1),
            Vec::<u8>::new(),
            "a converter row past the source height yields nothing"
        );
        assert_eq!(
            wic_copy_source_pixels(&objects, &converter, 2, 0, 1, 1),
            Vec::<u8>::new(),
            "a converter column past the source width yields nothing"
        );
        assert_eq!(
            wic_copy_source_pixels(&objects, &converter, 0, 0, 1, 1),
            vec![12, 11, 10, 13],
            "the converter swaps R and B"
        );
        let clipper = WicObjectState {
            kind: WicObjectKind::Clipper,
            source: 7,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            clip: Some([1, 0, 1, 1]),
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &clipper, 0, 1, 1, 1),
            Vec::<u8>::new(),
            "clipper rows past its clip rectangle yield nothing"
        );
        assert_eq!(
            wic_copy_source_pixels(&objects, &clipper, 0, 0, 1, 1),
            vec![20, 21, 22, 23],
            "the clipper returns its clipped rectangle"
        );
        let scaler = WicObjectState {
            kind: WicObjectKind::Scaler,
            width: 1,
            height: 1,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 7,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &scaler, 0, 0, 1, 1),
            vec![10, 11, 12, 13],
            "a 2x1 source scaled to 1x1 samples the first pixel"
        );
        objects.insert(
            9,
            bitmap_state(
                2,
                2,
                vec![
                    10, 11, 12, 13, 20, 21, 22, 23, 30, 31, 32, 33, 40, 41, 42, 43,
                ],
            ),
        );
        let rotator = WicObjectState {
            kind: WicObjectKind::FlipRotator,
            width: 2,
            height: 2,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 9,
            transform: WIC_TRANSFORM_ROTATE_90,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &rotator, 0, 0, 2, 2),
            vec![
                30, 31, 32, 33, 40, 41, 42, 43, 10, 11, 12, 13, 20, 21, 22, 23
            ],
            "rotate 90 reads the bottom row first"
        );
        let rotator = WicObjectState {
            kind: WicObjectKind::FlipRotator,
            width: 2,
            height: 2,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 9,
            transform: WIC_TRANSFORM_ROTATE_180,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &rotator, 0, 0, 2, 2),
            vec![
                40, 41, 42, 43, 30, 31, 32, 33, 20, 21, 22, 23, 10, 11, 12, 13
            ],
            "rotate 180 reverses both axes"
        );
        let rotator = WicObjectState {
            kind: WicObjectKind::FlipRotator,
            width: 2,
            height: 2,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 9,
            transform: WIC_TRANSFORM_ROTATE_270,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &rotator, 0, 0, 2, 2),
            vec![
                20, 21, 22, 23, 10, 11, 12, 13, 40, 41, 42, 43, 30, 31, 32, 33
            ],
            "rotate 270 reads the right column first"
        );
        let rotator = WicObjectState {
            kind: WicObjectKind::FlipRotator,
            width: 2,
            height: 2,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 9,
            transform: WIC_TRANSFORM_FLIP_HORIZONTAL,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &rotator, 0, 0, 2, 2),
            vec![
                20, 21, 22, 23, 10, 11, 12, 13, 40, 41, 42, 43, 30, 31, 32, 33
            ],
            "horizontal flip reverses each row"
        );
        objects.insert(8, bitmap_state(1, 2, vec![10, 11, 12, 13, 20, 21, 22, 23]));
        let rotator = WicObjectState {
            kind: WicObjectKind::FlipRotator,
            width: 1,
            height: 2,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 8,
            transform: WIC_TRANSFORM_FLIP_VERTICAL,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &rotator, 0, 0, 1, 2),
            vec![20, 21, 22, 23, 10, 11, 12, 13],
            "vertical flip reverses the column"
        );
        let rotator = WicObjectState {
            kind: WicObjectKind::FlipRotator,
            width: 1,
            height: 2,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 8,
            transform: 0,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &rotator, 0, 0, 1, 2),
            vec![10, 11, 12, 13, 20, 21, 22, 23],
            "no transform copies in order"
        );
    }

    #[test]
    fn palette_collection_rejects_unknown_formats_and_deduplicates() {
        let invalid = WicObjectState {
            pixel_format: GUID_PIXEL_FORMAT_DONT_CARE,
            pixels: vec![1, 2, 3, 4],
            ..Default::default()
        };
        assert_eq!(
            wic_collect_palette(&invalid),
            Vec::<u32>::new(),
            "an unknown format has no palette"
        );
        let bgra = WicObjectState {
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            pixels: vec![1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8],
            ..Default::default()
        };
        assert_eq!(
            wic_collect_palette(&bgra),
            vec![0x0403_0201, 0x0807_0605],
            "duplicate BGRA colors are collapsed"
        );
        let rgba = WicObjectState {
            pixel_format: GUID_PIXEL_FORMAT_32BPP_RGBA,
            pixels: vec![1, 2, 3, 4],
            ..Default::default()
        };
        assert_eq!(wic_collect_palette(&rgba), vec![0x0401_0203]);
        let bgr = WicObjectState {
            pixel_format: GUID_PIXEL_FORMAT_24BPP_BGR,
            pixels: vec![1, 2, 3],
            ..Default::default()
        };
        assert_eq!(wic_collect_palette(&bgr), vec![0xff03_0201]);
        let gray = WicObjectState {
            pixel_format: GUID_PIXEL_FORMAT_8BPP_GRAY,
            pixels: vec![9],
            ..Default::default()
        };
        assert_eq!(wic_collect_palette(&gray), vec![0xff09_0909]);
    }

    #[test]
    fn convert_pixel_edge_premultiplied_and_gray_layouts() {
        assert_eq!(
            convert_pixel(PixelLayout::Pbgra, PixelLayout::Bgra, &[64, 128, 255, 128]),
            [127, 255, 255, 128],
            "PBGRA channels are unpremultiplied"
        );
        assert_eq!(
            convert_pixel(PixelLayout::Pbgra, PixelLayout::Bgra, &[7, 8, 9, 0]),
            [0, 0, 0, 0],
            "zero alpha unpremultiplies to black"
        );
        assert_eq!(
            convert_pixel(PixelLayout::Bgra, PixelLayout::Pbgra, &[100, 150, 200, 128]),
            [50, 75, 100, 128],
            "PBGRA output is premultiplied"
        );
        assert_eq!(
            convert_pixel(PixelLayout::Bgra, PixelLayout::Rgba, &[1, 2, 3, 4]),
            [3, 2, 1, 4]
        );
        assert_eq!(
            convert_pixel(PixelLayout::Bgra, PixelLayout::Bgr, &[1, 2, 3, 4]),
            [1, 2, 3, 0]
        );
        assert_eq!(
            convert_pixel(PixelLayout::Bgra, PixelLayout::Gray, &[0, 0, 255, 255]),
            [76, 0, 0, 0],
            "Rec. 601 luma of pure red"
        );
        assert_eq!(
            convert_pixel(PixelLayout::Rgba, PixelLayout::Bgra, &[1, 2, 3, 4]),
            [1, 2, 3, 4]
        );
        assert_eq!(
            convert_pixel(PixelLayout::Bgr, PixelLayout::Bgra, &[1, 2, 3, 0]),
            [1, 2, 3, 255]
        );
        assert_eq!(
            convert_pixel(PixelLayout::Gray, PixelLayout::Bgra, &[7, 0, 0, 0]),
            [7, 7, 7, 255]
        );
    }

    #[test]
    fn resolution_helpers_reject_invalid_dpi_profiles() {
        assert_eq!(
            wic_decode_dpi(&WicObjectState::default()),
            None,
            "a default profile is not a DPI record"
        );
        let mut invalid = WicObjectState {
            profile: vec![0_u8; 8],
            ..Default::default()
        };
        invalid.profile[..4].copy_from_slice(&f32::NAN.to_le_bytes());
        invalid.profile[4..].copy_from_slice(&f32::NAN.to_le_bytes());
        assert_eq!(wic_decode_dpi(&invalid), None, "NaN DPI is rejected");
        let mut zero = WicObjectState {
            profile: vec![0_u8; 8],
            ..Default::default()
        };
        zero.profile[..4].copy_from_slice(&0.0_f32.to_le_bytes());
        zero.profile[4..].copy_from_slice(&96.0_f32.to_le_bytes());
        assert_eq!(wic_decode_dpi(&zero), None, "zero DPI is rejected");
        let valid = WicObjectState {
            profile: wic_encode_dpi(144.0, 72.0),
            ..Default::default()
        };
        assert_eq!(wic_decode_dpi(&valid), Some((144.0, 72.0)));

        let mut objects = HashMap::new();
        let broken = WicObjectState {
            kind: WicObjectKind::Scaler,
            source: 99,
            ..Default::default()
        };
        assert_eq!(
            wic_source_resolution(&objects, &broken),
            (WIC_DEFAULT_DPI, WIC_DEFAULT_DPI),
            "a broken source chain reports the default"
        );
        let bitmap = bitmap_state(1, 1, vec![0; 4]);
        let mut bitmap = bitmap;
        bitmap.profile = wic_encode_dpi(200.0, 100.0);
        objects.insert(5, bitmap.clone());
        assert_eq!(wic_source_resolution(&objects, &bitmap), (200.0, 100.0));
        let scaler = WicObjectState {
            kind: WicObjectKind::Scaler,
            source: 5,
            ..Default::default()
        };
        assert_eq!(wic_source_resolution(&objects, &scaler), (200.0, 100.0));
    }

    fn png_with_chunks(ihdr: &[u8], chunks: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut out, b"IHDR", ihdr);
        for (kind, data) in chunks {
            let kind: &[u8; 4] = (*kind).try_into().expect("four-byte chunk kind");
            wic_png_chunk(&mut out, kind, data);
        }
        out
    }

    fn png_ihdr(width: u32, height: u32, depth: u8, color: u8) -> Vec<u8> {
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[depth, color, 0, 0, 0]);
        ihdr
    }

    #[test]
    fn png_decode_rejects_header_and_chunk_order_violations() {
        assert_eq!(
            wic_decode_png(b"short").unwrap_err(),
            WINCODEC_ERR_UNKNOWNIMAGEFORMAT,
            "a short signature is not a PNG"
        );
        let mut huge = b"\x89PNG\r\n\x1a\n".to_vec();
        huge.extend_from_slice(&0x7fff_ffff_u32.to_be_bytes());
        huge.extend_from_slice(b"IHDR");
        assert_eq!(wic_decode_png(&huge).unwrap_err(), WINCODEC_ERR_BADIMAGE);

        let mut ihdr = png_ihdr(1, 1, 8, 0);
        ihdr.truncate(12);
        assert_eq!(
            wic_decode_png(&png_with_chunks(&ihdr, &[])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an IHDR shorter than 13 bytes is rejected"
        );
        let mut compression = png_ihdr(1, 1, 8, 0);
        compression[10] = 1;
        assert_eq!(
            wic_decode_png(&png_with_chunks(&compression, &[])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an unknown compression method is rejected"
        );
        let mut filter = png_ihdr(1, 1, 8, 0);
        filter[11] = 1;
        assert_eq!(
            wic_decode_png(&png_with_chunks(&filter, &[])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an unknown filter method is rejected"
        );
        assert_eq!(
            wic_decode_png(&png_with_chunks(
                &png_ihdr(0, 1, 8, 0),
                &[(b"IEND", Vec::new())]
            ))
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "zero width is rejected"
        );
        assert_eq!(
            wic_decode_png(&png_with_chunks(
                &png_ihdr(1, 1, 8, 5),
                &[(b"IEND", Vec::new())]
            ))
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "an unknown color type is unsupported"
        );
        let png = build_png(
            1,
            1,
            8,
            3,
            0,
            &[(b"PLTE", vec![1, 2, 3]), (b"PLTE", vec![4, 5, 6])],
            &[0, 0],
        );
        assert_eq!(
            wic_decode_png(&png).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a duplicate PLTE is rejected"
        );
        let png = build_png(1, 1, 8, 0, 0, &[(b"PLTE", vec![1, 2, 3])], &[0, 0]);
        assert_eq!(
            wic_decode_png(&png).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "PLTE is invalid for grayscale"
        );
        let png = build_png(
            1,
            1,
            8,
            0,
            0,
            &[(b"tRNS", vec![0, 1]), (b"tRNS", vec![0, 2])],
            &[0, 0],
        );
        assert_eq!(
            wic_decode_png(&png).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a duplicate tRNS is rejected"
        );
        let png = build_png(1, 1, 8, 0, 0, &[(b"tRNS", vec![0])], &[0, 0]);
        assert_eq!(
            wic_decode_png(&png).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "gray tRNS needs two bytes"
        );
        let png = build_png(1, 1, 8, 2, 0, &[(b"tRNS", vec![0, 1, 0])], &[0, 0, 0, 0]);
        assert_eq!(
            wic_decode_png(&png).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "RGB tRNS needs six bytes"
        );
        let png = build_png(1, 1, 8, 4, 0, &[(b"tRNS", vec![0, 1])], &[0, 0, 0]);
        assert_eq!(
            wic_decode_png(&png).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "tRNS is invalid for gray+alpha"
        );
        let mut idat_first = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut idat_first, b"IDAT", &deflate_bytes(&[0, 0]));
        assert_eq!(
            wic_decode_png(&idat_first).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "IDAT before IHDR is rejected"
        );
        let png = png_with_chunks(&png_ihdr(1, 1, 8, 0), &[(b"IEND", Vec::new())]);
        assert_eq!(
            wic_decode_png(&png).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a PNG without IDAT is rejected"
        );
        let ihdr = png_ihdr(1, 1, 8, 0);
        let mut duplicate = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut duplicate, b"IHDR", &ihdr);
        wic_png_chunk(&mut duplicate, b"IHDR", &ihdr);
        assert_eq!(
            wic_decode_png(&duplicate).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a duplicate IHDR is rejected"
        );
    }

    #[test]
    fn png_decode_rejects_size_and_scanline_boundaries() {
        let huge = build_png(10_000, 10_000, 8, 0, 0, &[], &[]);
        assert_eq!(
            wic_decode_png(&huge).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "buffers larger than 256 MiB are rejected"
        );
        let huge16 = build_png(8192, 8192, 16, 6, 0, &[], &[]);
        assert_eq!(
            wic_decode_png(&huge16).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "expected scanline data larger than 512 MiB is rejected"
        );
        let short = build_png(1, 1, 8, 0, 0, &[], &[0]);
        assert_eq!(
            wic_decode_png(&short).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an inflated stream shorter than expected is rejected"
        );
        let bad_filter = build_png(1, 1, 8, 6, 0, &[], &[5, 1, 2, 3, 4]);
        assert_eq!(
            wic_decode_png(&bad_filter).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an unknown scanline filter is rejected"
        );
        for filter in 1_u8..=4 {
            let png = build_png(1, 1, 8, 6, 0, &[], &[filter, 10, 20, 30, 40]);
            let image = wic_decode_png(&png).expect("filtered PNG");
            assert_eq!(
                &image.pixels[..],
                &[30, 20, 10, 40],
                "filter {filter} reconstructs the same pixel"
            );
        }
        let palette = build_png(1, 1, 4, 3, 0, &[(b"PLTE", vec![1, 2, 3])], &[0, 0xf0]);
        assert_eq!(
            wic_decode_png(&palette).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a 4-bit palette index past the table is rejected"
        );
        let mut palette_entries = vec![0_u8; 16 * 3];
        palette_entries[45..48].copy_from_slice(&[9, 8, 7]);
        let paletted = build_png(1, 1, 4, 3, 0, &[(b"PLTE", palette_entries)], &[0, 0xf0]);
        let image = wic_decode_png(&paletted).expect("4-bit palette PNG");
        assert_eq!(&image.pixels[..], &[7, 8, 9, 255]);
    }

    #[test]
    fn png_trns_edge_color_types() {
        let rgb = build_png(
            2,
            1,
            8,
            2,
            0,
            &[(b"tRNS", vec![0, 10, 0, 20, 0, 30])],
            &[0, 10, 20, 30, 11, 20, 30],
        );
        let image = wic_decode_png(&rgb).expect("RGB tRNS PNG");
        assert_eq!(
            &image.pixels[..],
            &[30, 20, 10, 0, 30, 20, 11, 255],
            "only the matching RGB sample is transparent"
        );
        let gray_alpha = build_png(1, 1, 8, 4, 0, &[], &[0, 40, 128]);
        let image = wic_decode_png(&gray_alpha).expect("gray+alpha PNG");
        assert_eq!(&image.pixels[..], &[40, 40, 40, 128]);
        let rgba = build_png(1, 1, 8, 6, 0, &[], &[0, 1, 2, 3, 4]);
        let image = wic_decode_png(&rgba).expect("RGBA PNG");
        assert_eq!(&image.pixels[..], &[3, 2, 1, 4]);
        let phys = build_png(
            1,
            1,
            8,
            0,
            0,
            &[(b"pHYs", vec![0, 0, 0x27, 0x10, 0, 0, 0x27, 0x10, 1])],
            &[0, 7],
        );
        let image = wic_decode_png(&phys).expect("pHYs PNG");
        assert_eq!(image.dpi_x as u32, 254, "pixels per metre convert to DPI");
    }

    #[test]
    fn png_encoder_rejects_invalid_dimensions_and_short_pixels() {
        assert_eq!(wic_encode_png(0, 1, &[], None).unwrap_err(), E_INVALIDARG);
        assert_eq!(
            wic_encode_png(1, 1, &[0, 0, 0], None).unwrap_err(),
            E_INVALIDARG,
            "a short pixel buffer is rejected"
        );
        let png = wic_encode_png(1, 1, &[1, 2, 3, 4], Some((72.0, 72.0))).expect("PNG encode");
        assert!(png.starts_with(b"\x89PNG"));
    }

    #[test]
    fn png_paeth_predictor_boundary_ties() {
        assert_eq!(wic_png_paeth(1, 2, 3), 1);
        assert_eq!(wic_png_paeth(0, 10, 0), 10);
        assert_eq!(wic_png_paeth(100, 0, 60), 60);
        assert_eq!(wic_png_paeth(10, 10, 0), 10);
        assert_eq!(wic_png_paeth(5, 5, 5), 5);
    }

    fn jpeg_table(counts: [u8; 16], symbols: &[u8]) -> WicJpegHuffman {
        WicJpegHuffman::build(&counts, symbols).expect("valid Huffman table")
    }

    fn jpeg_write_symbol(writer: &mut WicJpegBitWriter, table: &WicJpegHuffman, symbol: u8) {
        let (code, length) = table
            .entries
            .iter()
            .find(|(_, _, candidate)| *candidate == symbol)
            .map(|(code, length, _)| (*code, *length))
            .expect("symbol in table");
        writer.write_bits(u32::from(code), length);
    }

    fn jpeg_finish(mut writer: WicJpegBitWriter) -> Vec<u8> {
        writer.flush();
        writer.out
    }

    fn jpeg_component(blocks: usize) -> WicJpegComponent {
        WicJpegComponent {
            id: 1,
            h: 1,
            v: 1,
            tq: 0,
            dc_table: 0,
            ac_table: 0,
            dc_prediction: 0,
            blocks_x: blocks,
            blocks_y: 1,
            actual_blocks_x: blocks,
            actual_blocks_y: 1,
            plane_width: blocks * 8,
            plane_height: 8,
            samples: vec![0_u8; blocks * 64],
            coefficients: vec![[0_i32; 64]; blocks],
        }
    }

    #[test]
    fn jpeg_bit_writer_rejects_zero_width_and_stuffs_ff() {
        let mut writer = WicJpegBitWriter::new();
        writer.write_bits(7, 0);
        assert_eq!(writer.out, Vec::<u8>::new(), "zero bits writes nothing");
        writer.write_bits(0xff, 8);
        assert_eq!(
            writer.out,
            vec![0xff, 0x00],
            "a 0xff byte is stuffed after flushing out"
        );
        let mut writer = WicJpegBitWriter::new();
        writer.write_bits(1, 1);
        writer.flush();
        assert_eq!(
            writer.out,
            vec![0xff, 0x00],
            "a padded flush that yields 0xff is stuffed"
        );
    }

    #[test]
    fn jpeg_scaled_quant_boundary_quality() {
        let low = wic_jpeg_scaled_quant(&WIC_JPEG_LUMA_QUANT, 10);
        assert_eq!(low[0], 80, "quality 10 scales the DC coefficient");
        assert_eq!(low[1], 55);
        let high = wic_jpeg_scaled_quant(&WIC_JPEG_LUMA_QUANT, 100);
        assert_eq!(high[0], 1, "quality 100 clamps to one");
    }

    #[test]
    fn jpeg_huffman_rejects_invalid_tables_and_symbols() {
        assert_eq!(
            WicJpegHuffman::build(&[0_u8; 16], &[]).is_none(),
            true,
            "an empty table is rejected"
        );
        assert_eq!(
            WicJpegHuffman::build(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[]).is_none(),
            true,
            "a symbol-count mismatch is rejected"
        );
        assert_eq!(
            WicJpegHuffman::build(
                &[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                &[0, 1, 2]
            )
            .is_none(),
            true,
            "an over-subscribed table is rejected"
        );
        let table = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let mut invalid = WicJpegBits::new(&[0xff, 0xff], 0);
        assert_eq!(
            table.decode(&mut invalid),
            None,
            "a bit pattern with no code returns None"
        );
        let mut writer = WicJpegBitWriter::new();
        assert_eq!(
            table.write(1, &mut writer),
            false,
            "writing an absent symbol fails"
        );
    }

    #[test]
    fn jpeg_bit_reader_rejects_truncated_and_marker_sequences() {
        assert_eq!(
            WicJpegBits::new(&[], 0).bits(0),
            Some(0),
            "reading zero bits never touches the stream"
        );
        assert_eq!(
            WicJpegBits::new(&[], 0).bits(25),
            None,
            "more than 24 bits is rejected"
        );
        let mut bits = WicJpegBits::new(&[0x12, 0x34], 0);
        assert_eq!(bits.bits(4), Some(1));
        bits.align();
        assert_eq!(bits.bits(8), Some(0x34), "align discards the partial byte");
        let mut stuffed = WicJpegBits::new(&[0xff, 0x00, 0xab], 0);
        assert_eq!(stuffed.read_byte(), Some(0xff));
        assert_eq!(stuffed.read_byte(), Some(0xab));
        assert_eq!(WicJpegBits::new(&[], 0).read_byte(), None);
        let mut restart = WicJpegBits::new(&[0xff, 0xd0, 0xff, 0xd1], 0);
        assert_eq!(restart.read_byte(), None);
        assert_eq!(restart.skip_restart(), true);
        assert_eq!(restart.read_byte(), None);
        assert_eq!(restart.skip_restart(), true);
        let mut scanned = WicJpegBits::new(&[0x12, 0xff, 0xd3], 0);
        assert_eq!(scanned.skip_restart(), true, "a restart marker is found");
        let mut other = WicJpegBits::new(&[0x12, 0xff, 0xe0], 0);
        assert_eq!(other.skip_restart(), false, "a non-restart marker aborts");
        let mut stuffed_only = WicJpegBits::new(&[0xff, 0x00], 0);
        assert_eq!(
            stuffed_only.skip_restart(),
            false,
            "a stuffed byte is not a restart marker"
        );
    }

    #[test]
    fn jpeg_misc_helpers_reject_zero_and_invalid_inputs() {
        assert_eq!(wic_jpeg_extend(0, 0), 0, "size zero has no extension");
        assert_eq!(wic_jpeg_extend(0, 1), -1);
        assert_eq!(wic_jpeg_extend(1, 1), 1);
        let mut coefficient = 2_i32;
        wic_jpeg_refine(&mut coefficient, 0, 1);
        assert_eq!(coefficient, 2, "a zero refinement bit is a no-op");
        wic_jpeg_refine(&mut coefficient, 1, 1);
        assert_eq!(coefficient, 3);
        coefficient = -2;
        wic_jpeg_refine(&mut coefficient, 1, 1);
        assert_eq!(coefficient, -3, "negative coefficients refine downward");
        wic_jpeg_refine(&mut coefficient, 1, 1);
        assert_eq!(coefficient, -3, "an already-set bit is not added again");
        assert_eq!(
            wic_jpeg_next_marker(&[0xff, 0x00, 0xff, 0xd0, 0xff, 0xe0], 0),
            4,
            "stuffed bytes and restarts are skipped"
        );
        assert_eq!(
            wic_jpeg_next_marker(&[0x12, 0x34], 0),
            2,
            "no marker returns the end offset"
        );
        assert_eq!(wic_jpeg_next_marker(&[0xff, 0x00], 0), 2);
    }

    #[test]
    fn jpeg_block_decoder_rejects_invalid_baseline_codes() {
        let dc = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let ac = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0x00]);
        let scan = WicJpegScanParams {
            progressive: false,
            ss: 0,
            se: 63,
            ah: 0,
            al: 0,
        };
        let mut component = jpeg_component(1);
        let mut eob = 0;
        assert_eq!(
            wic_jpeg_decode_block(
                &mut component,
                1,
                &mut WicJpegBits::new(&[], 0),
                &dc,
                &ac,
                scan,
                &mut eob
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an out-of-range block index is rejected"
        );
        let mut component = jpeg_component(1);
        let mut bits = WicJpegBits::new(&[0xff, 0xff], 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a baseline DC category with no matching code is rejected"
        );

        let dc1 = jpeg_table([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0, 1]);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc1, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc1, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a DC category without its amplitude bits is rejected"
        );

        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc, 0);
        writer.write_bits(0xffff, 16);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an AC symbol without its amplitude bits is rejected"
        );
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc, 0);
        writer.write_bits(0x7fff, 15);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an invalid baseline AC code is rejected"
        );
    }

    #[test]
    fn jpeg_block_decoder_baseline_run_boundary() {
        let dc = jpeg_table([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0, 1]);
        let ac = jpeg_table(
            [0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0x00, 0x01, 0x11, 0x02, 0xf0],
        );
        let scan = WicJpegScanParams {
            progressive: false,
            ss: 0,
            se: 63,
            ah: 0,
            al: 0,
        };
        let mut component = jpeg_component(1);
        let mut eob = 0;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc, 0);
        jpeg_write_symbol(&mut writer, &ac, 0xf0);
        jpeg_write_symbol(&mut writer, &ac, 0x00);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(component.coefficients[0][1], 0);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc, 0);
        jpeg_write_symbol(&mut writer, &ac, 0x01);
        writer.write_bits(1, 1);
        jpeg_write_symbol(&mut writer, &ac, 0x00);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(component.coefficients[0][WIC_JPEG_ZIGZAG[1]], 1);
    }

    #[test]
    fn jpeg_block_decoder_rejects_progressive_dc_errors() {
        let dc = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let ac = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0x00]);
        let mut scan = WicJpegScanParams {
            progressive: true,
            ss: 0,
            se: 0,
            ah: 0,
            al: 0,
        };
        let mut component = jpeg_component(1);
        let mut eob = 0;
        let mut bits = WicJpegBits::new(&[0xff, 0xff], 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an invalid progressive DC category is rejected"
        );
        scan.ah = 1;
        let mut bits = WicJpegBits::new(&[], 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a missing DC refinement bit is rejected"
        );
        scan.ah = 0;
        let dc1 = jpeg_table([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0, 1]);
        let dc1_8 = jpeg_table([0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0], &[0, 1]);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc1_8, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc1_8, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a progressive DC amplitude without bits is rejected"
        );
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc1, 0);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        scan.al = 1;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc1, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(
            component.coefficients[0][0], 0,
            "category zero leaves the DC prediction unchanged"
        );
        scan.ah = 1;
        let mut bits = WicJpegBits::new(&[0x80], 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc1, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(
            component.coefficients[0][0], 2,
            "the DC refinement bit is shifted by Al"
        );
    }

    #[test]
    fn jpeg_block_decoder_rejects_invalid_progressive_ac_scans() {
        let dc = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let ac = jpeg_table(
            [0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0x00, 0x20, 0xf0, 0x01, 0x11],
        );
        let ac_run8 = jpeg_table([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], &[0x20]);
        let ac_one8 = jpeg_table([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], &[0x01]);
        let scan = WicJpegScanParams {
            progressive: true,
            ss: 1,
            se: 5,
            ah: 0,
            al: 0,
        };
        let mut component = jpeg_component(1);
        let mut eob = 1;
        assert_eq!(
            wic_jpeg_decode_block(
                &mut component,
                0,
                &mut WicJpegBits::new(&[], 0),
                &dc,
                &ac,
                scan,
                &mut eob
            ),
            Ok(())
        );
        assert_eq!(eob, 0, "an active EOB run consumes one block");
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0xf0);
        jpeg_write_symbol(&mut writer, &ac, 0x00);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0x20);
        writer.write_bits(3, 2);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(eob, 6, "an EOB run encodes its extra bits");
        eob = 0;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0x01);
        writer.write_bits(1, 1);
        jpeg_write_symbol(&mut writer, &ac, 0x00);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        let mut component = jpeg_component(1);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(component.coefficients[0][WIC_JPEG_ZIGZAG[1]], 1);
        eob = 0;
        let mut component = jpeg_component(1);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0x11);
        writer.write_bits(1, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        let narrow = WicJpegScanParams { se: 1, ..scan };
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, narrow, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a progressive run past Se is rejected"
        );
        let mut bits = WicJpegBits::new(&[0xff, 0xff], 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an invalid progressive AC code is rejected"
        );
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac_run8, 0x20);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac_run8, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an EOB run without its extra bits is rejected"
        );
        eob = 0;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac_one8, 0x01);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac_one8, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a coefficient without amplitude bits is rejected"
        );
    }

    #[test]
    fn jpeg_block_decoder_rejects_invalid_progressive_refinement() {
        let dc = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let ac = jpeg_table(
            [0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0x00, 0x20, 0xf0, 0x01, 0x11, 0x02],
        );
        let ac_run8 = jpeg_table([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], &[0x20]);
        let ac_eob8 = jpeg_table([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], &[0x00]);
        let ac_zrl8 = jpeg_table([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], &[0xf0]);
        let ac_one8 = jpeg_table([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], &[0x01]);
        let scan = WicJpegScanParams {
            progressive: true,
            ss: 1,
            se: 3,
            ah: 1,
            al: 0,
        };
        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 2;
        let mut eob = 1;
        let mut bits = WicJpegBits::new(&[0x80], 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(component.coefficients[0][WIC_JPEG_ZIGZAG[1]], 3);
        assert_eq!(eob, 0);
        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 1;
        let mut eob = 1;
        let mut bits = WicJpegBits::new(&[], 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an EOB refinement without its bit is rejected"
        );

        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 2;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0xf0);
        writer.write_bits(1, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        let mut eob = 0;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 2;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac_zrl8, 0xf0);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac_zrl8, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a ZRL refinement without its bit is rejected"
        );

        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 2;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0x20);
        writer.write_bits(3, 2);
        writer.write_bits(1, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        let mut eob = 0;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(eob, 6);
        assert_eq!(component.coefficients[0][WIC_JPEG_ZIGZAG[1]], 3);
        eob = 0;
        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 1;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac_run8, 0x20);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac_run8, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an EOB run missing its extra bits is rejected"
        );
        eob = 0;
        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 1;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac_eob8, 0x00);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac_eob8, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an EOB run with a missing refinement bit is rejected"
        );
        eob = 0;
        let mut component = jpeg_component(1);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0x02);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a refinement symbol with size other than one is rejected"
        );
        eob = 0;
        let mut component = jpeg_component(1);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0x01);
        writer.write_bits(1, 1);
        jpeg_write_symbol(&mut writer, &ac, 0x00);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(
            component.coefficients[0][WIC_JPEG_ZIGZAG[1]], 1,
            "a new refinement coefficient is inserted"
        );
        eob = 0;
        let mut component = jpeg_component(1);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac_one8, 0x01);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac_one8, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a refinement sign without its bit is rejected"
        );
        eob = 0;
        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 2;
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0x11);
        writer.write_bits(1, 1);
        writer.write_bits(0, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob),
            Ok(())
        );
        assert_eq!(
            component.coefficients[0][WIC_JPEG_ZIGZAG[3]], 1,
            "a run skips an existing coefficient and inserts later"
        );
        eob = 0;
        let mut component = jpeg_component(1);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac, 0x11);
        writer.write_bits(1, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        let narrow = WicJpegScanParams { se: 1, ..scan };
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, narrow, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a refinement run past Se is rejected"
        );
    }

    #[test]
    fn encoder_frames_reject_truncated_and_short_profiles() {
        assert_eq!(
            wic_encoder_frames(b"short"),
            Vec::new(),
            "a profile shorter than the magic is empty"
        );
        assert_eq!(
            wic_encoder_frames(b"NOT-THE-MAGIC-0123456789"),
            Vec::new(),
            "a profile without the magic is empty"
        );
        let mut count_only = WIC_ENCODER_MAGIC.to_vec();
        count_only.extend_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            wic_encoder_frames(&count_only),
            Vec::new(),
            "a missing frame header ends the frame list"
        );
        let mut short_pixels = WIC_ENCODER_MAGIC.to_vec();
        short_pixels.extend_from_slice(&1_u32.to_le_bytes());
        short_pixels.extend_from_slice(&1_u32.to_le_bytes());
        short_pixels.extend_from_slice(&1_u32.to_le_bytes());
        short_pixels.extend_from_slice(&0_u32.to_le_bytes());
        short_pixels.extend_from_slice(&0_u32.to_le_bytes());
        short_pixels.extend_from_slice(&8_u32.to_le_bytes());
        short_pixels.extend_from_slice(&[0_u8; 4]);
        assert_eq!(
            wic_encoder_frames(&short_pixels),
            Vec::new(),
            "a frame whose pixels run past the profile is dropped"
        );
    }

    #[test]
    fn image_frame_dispatch_rejects_unknown_and_missing_frames() {
        let mut palette = [[0_u8; 3]; 256];
        palette[0] = [1, 2, 3];
        let gif = build_gif_layout(1, 1, &palette, &[(0, 0, 1, 1, vec![0], None, 0, 1)]);
        assert_eq!(wic_decode_image_frame(&gif, 0).unwrap().width, 1);
        assert_eq!(
            wic_decode_image_frame(&gif, 1).unwrap_err(),
            WINCODEC_ERR_FRAMEMISSING
        );
        let tiff = build_tiff_rgb(1, 1, &[(vec![1, 2, 3], 1)], true, &[]);
        assert_eq!(wic_decode_image_frame(&tiff, 0).unwrap().width, 1);
        assert_eq!(
            wic_decode_image_frame(&tiff, 1).unwrap_err(),
            WINCODEC_ERR_FRAMEMISSING
        );
        let jpeg = wic_encode_jpeg(2, 2, &[0_u8, 0, 0, 255].repeat(4), None).unwrap();
        assert_eq!(wic_decode_image_frame(&jpeg, 0).unwrap().width, 2);
        assert_eq!(
            wic_decode_image_frame(&jpeg, 1).unwrap_err(),
            WINCODEC_ERR_FRAMEMISSING
        );
        assert_eq!(
            wic_decode_image_frame(b"unknown", 0).unwrap_err(),
            WINCODEC_ERR_UNKNOWNIMAGEFORMAT
        );
        assert_eq!(wic_image_frame_count(b"unknown"), 0);
    }

    fn gif_header(width: u16, height: u16, packed: u8) -> Vec<u8> {
        let mut out = b"GIF89a".to_vec();
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&[packed, 0, 0]);
        out
    }

    fn gif_frame(
        left: u16,
        top: u16,
        width: u16,
        height: u16,
        flags: u8,
        palette: Option<&[[u8; 3]; 256]>,
        data: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x2c);
        for value in [left, top, width, height] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out.push(flags);
        if let Some(palette) = palette {
            for color in palette {
                out.extend_from_slice(color);
            }
        }
        out.push(8);
        gif_sub_blocks(&mut out, data);
        out
    }

    #[test]
    fn gif_extension_parsing_rejects_malformed_blocks() {
        let header = gif_header(1, 1, 0x00);
        let mut palette = [[0_u8; 3]; 256];
        palette[0] = [9, 8, 7];
        let mut no_global = gif_header(1, 1, 0x00);
        no_global.extend_from_slice(&gif_frame(
            0,
            0,
            1,
            1,
            0x87,
            Some(&palette),
            &gif_literal_stream(&[0]),
        ));
        no_global.push(0x3b);
        let image = wic_decode_gif_frame(&no_global, 0).expect("local palette GIF");
        assert_eq!(&image.pixels[..], &[7, 8, 9, 255]);

        let mut no_trailer = build_gif_layout(1, 1, &palette, &[(0, 0, 1, 1, vec![0], None, 0, 1)]);
        no_trailer.pop();
        assert_eq!(wic_decode_gif_frame(&no_trailer, 0).unwrap().width, 1);
        assert_eq!(
            wic_decode_gif_frame(&header_with(&header, &[0x21]), 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an extension without a label is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(&header_with(&header, &[0x21, 0xf9]), 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a graphic control extension without its length is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(&header_with(&header, &[0x21, 0xf9, 3]), 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a graphic control extension with the wrong length is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(&header_with(&header, &[0x21, 0xf9, 4, 0, 0, 0, 0, 1]), 0)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a graphic control extension with a nonzero terminator is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(&header_with(&header, &[0x21, 0xff]), 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an application extension without its block size is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(&header_with(&header, &[0x99]), 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an unknown introducer byte is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(&header_with(&header, &[0x3b]), 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a GIF with no frames is rejected"
        );

        let mut extended = header.clone();
        extended.extend_from_slice(&[0x21, 0x01, 2, 0xaa, 0xbb, 0]);
        extended.extend_from_slice(&gif_frame(
            0,
            0,
            1,
            1,
            0x87,
            Some(&palette),
            &gif_literal_stream(&[0]),
        ));
        extended.push(0x3b);
        assert_eq!(wic_decode_gif_frame(&extended, 0).unwrap().width, 1);
        let parsed = wic_gif_parse(&extended).expect("extension parse");
        assert_eq!(parsed.frames.len(), 1);

        let mut app = build_gif(
            1,
            1,
            &palette,
            &[(vec![0_u8], None, 0)],
            false,
            Some("comment here"),
            Some(("AB", &[1, 2])),
        );
        let parsed = wic_gif_parse(&app).expect("application parse");
        assert_eq!(parsed.comments, vec!["comment here".to_string()]);
        assert_eq!(parsed.applications, vec![("AB".to_string(), vec![1_u8, 2])]);
        app.clear();
        app = build_gif(1, 1, &palette, &[(vec![0_u8], None, 0)], false, None, None);
        assert_eq!(wic_gif_parse(&app).unwrap().applications.len(), 0);
    }

    fn header_with(header: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut out = header.to_vec();
        out.extend_from_slice(tail);
        out
    }

    #[test]
    fn gif_frame_descriptor_rejects_invalid_sizes_and_data() {
        let header = gif_header(2, 2, 0x00);
        let palette = [[0_u8; 3]; 256];
        assert_eq!(
            wic_decode_gif_frame(
                &header_with(&header, &gif_frame(0, 0, 0, 1, 0x87, Some(&palette), &[])),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a zero-width frame is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(
                &header_with(&header, &gif_frame(0, 0, 1, 1, 0, None, &[])),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a frame without any palette is rejected"
        );
        let mut missing_min_code = gif_frame(0, 0, 1, 1, 0x87, Some(&palette), &[]);
        missing_min_code.pop();
        missing_min_code.pop();
        assert_eq!(
            wic_decode_gif_frame(&header_with(&header, &missing_min_code), 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a frame without a minimum code size is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(
                &header_with(
                    &header,
                    &gif_frame(0, 0, 10_000, 8_000, 0x87, Some(&palette), &[])
                ),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a frame with more than 64 Mi pixels is rejected"
        );
        assert_eq!(
            wic_decode_gif_frame(
                &header_with(
                    &header,
                    &gif_frame(0, 0, 2, 2, 0x87, Some(&palette), &gif_literal_stream(&[0]))
                ),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "too few decoded indices is rejected"
        );
    }

    #[test]
    fn encoder_commit_rejects_mismatched_and_oversized_frames() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-encoder-state");
            let factory = create_factory(&mut fixture);
            let stream = create_stream(&mut fixture, factory, &[]);
            let encoder = |fixture: &mut Fixture, container: &[u8; 16]| -> u64 {
                fixture.memory.map_bytes(FORMAT, container);
                fixture.memory.map_bytes(BITMAP_OUT, &[0_u8; 8]);
                assert_eq!(
                    dispatch_x86(
                        fixture,
                        HostThunk::WicFactoryCreateEncoder,
                        &[factory as u32, FORMAT as u32, BITMAP_OUT as u32]
                    ),
                    0
                );
                let encoder = read_ptr(fixture, BITMAP_OUT);
                assert_eq!(
                    dispatch_x86(
                        fixture,
                        HostThunk::WicEncoderInitialize,
                        &[encoder as u32, stream as u32, 0]
                    ),
                    0
                );
                encoder
            };
            let add_frame = |fixture: &mut Fixture, encoder: u64, width: u32, height: u32| {
                fixture.memory.map_bytes(FRAME_OUT, &[0_u8; 8]);
                assert_eq!(
                    dispatch_x86(
                        fixture,
                        HostThunk::WicEncoderCreateNewFrame,
                        &[encoder as u32, FRAME_OUT as u32, 0]
                    ),
                    0
                );
                let frame = read_ptr(fixture, FRAME_OUT);
                assert_eq!(
                    dispatch_x86(
                        fixture,
                        HostThunk::WicFrameEncodeSetSize,
                        &[frame as u32, width, height]
                    ),
                    0
                );
                fixture
                    .memory
                    .map_bytes(FORMAT, &GUID_PIXEL_FORMAT_32BPP_BGRA);
                assert_eq!(
                    dispatch_x86(
                        fixture,
                        HostThunk::WicFrameEncodeSetPixelFormat,
                        &[frame as u32, FORMAT as u32]
                    ),
                    0
                );
                let pixels = vec![0_u8; width as usize * height as usize * 4];
                fixture.memory.map_bytes(ENCODE_BYTES, &pixels);
                assert_eq!(
                    dispatch_x86(
                        fixture,
                        HostThunk::WicFrameEncodeWritePixels,
                        &[
                            frame as u32,
                            height,
                            width * 4,
                            pixels.len() as u32,
                            ENCODE_BYTES as u32
                        ]
                    ),
                    0
                );
                assert_eq!(
                    dispatch_x86(fixture, HostThunk::WicFrameEncodeCommit, &[frame as u32]),
                    0
                );
            };

            let gif_encoder = encoder(&mut fixture, &GUID_CONTAINER_FORMAT_GIF);
            add_frame(&mut fixture, gif_encoder, 2, 2);
            add_frame(&mut fixture, gif_encoder, 3, 3);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCommit,
                    &[gif_encoder as u32]
                ),
                u64::from(WINCODEC_ERR_BADIMAGE),
                "frames of different sizes are rejected"
            );

            let empty_encoder = encoder(&mut fixture, &GUID_CONTAINER_FORMAT_GIF);
            let state = fixture
                .runtime
                .wic
                .objects
                .get_mut(&empty_encoder)
                .expect("encoder state");
            state.profile = WIC_ENCODER_MAGIC.to_vec();
            state.transform |= 2;
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCommit,
                    &[empty_encoder as u32]
                ),
                0,
                "an initialized encoder with no frames commits its stream"
            );
            assert_eq!(
                fixture.runtime.wic.objects.get(&stream).unwrap().stream,
                Vec::<u8>::new()
            );

            let large_encoder = encoder(&mut fixture, &GUID_CONTAINER_FORMAT_GIF);
            add_frame(&mut fixture, large_encoder, 70_000, 1);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCommit,
                    &[large_encoder as u32]
                ),
                u64::from(WINCODEC_ERR_BADIMAGE),
                "a GIF frame wider than u16 is rejected by the encoder"
            );
        });
    }

    #[test]
    fn encoder_single_frame_containers_and_wrong_state_rejected() {
        let red = vec![0_u8, 0, 255, 255].repeat(4);
        for container in [
            GUID_CONTAINER_FORMAT_GIF,
            GUID_CONTAINER_FORMAT_TIFF,
            GUID_CONTAINER_FORMAT_JPEG,
        ] {
            let encoded = encode_frames_through_wic(&container, 2, 2, &[red.clone()]);
            assert_eq!(wic_image_frame_count(&encoded), 1);
            assert_eq!(wic_decode_image_frame(&encoded, 0).unwrap().width, 2);
        }
        with_big_stack(|| {
            let mut fixture = x86_fixture("wic-wrong-state");
            let factory = create_factory(&mut fixture);
            fixture.memory.map_bytes(BITMAP_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicEncoderCommit,
                    &[0xdead_beef_u32 as u32]
                ),
                u64::from(WINCODEC_ERR_NOTINITIALIZED),
                "committing an unknown encoder is rejected"
            );
            fixture.memory.map_bytes(RECT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicClipperGetClipRect,
                    &[0xdead_beef_u32, RECT as u32]
                ),
                u64::from(WIC_E_INVALIDSTATE),
                "a clipper method on an unknown object is rejected"
            );
            fixture.memory.map_bytes(BITMAP_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateBitmapClipper,
                    &[factory as u32, BITMAP_OUT as u32]
                ),
                0
            );
            assert_ne!(read_ptr(&fixture, BITMAP_OUT), 0);
            fixture.memory.map_bytes(BITMAP_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateBitmapFlipRotator,
                    &[factory as u32, BITMAP_OUT as u32]
                ),
                0
            );
            assert_ne!(read_ptr(&fixture, BITMAP_OUT), 0);
            fixture.memory.map_bytes(BITMAP_OUT, &[0_u8; 8]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateColorContext,
                    &[factory as u32, BITMAP_OUT as u32]
                ),
                0
            );
            assert_ne!(read_ptr(&fixture, BITMAP_OUT), 0);
            fixture.memory.map_bytes(BITMAP_OUT, &[0_u8; 8]);
            fixture.memory.map_bytes(FORMAT, &[0_u8; 16]);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WicFactoryCreateComponentInfo,
                    &[factory as u32, FORMAT as u32, BITMAP_OUT as u32]
                ),
                0
            );
            assert_ne!(read_ptr(&fixture, BITMAP_OUT), 0);
        });
    }

    #[test]
    fn tiff_decode_rejects_invalid_dimensions_and_layouts() {
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(0, 1, 1, &[8], 1, 1, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "zero width is rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(
                    10_000,
                    7_000,
                    1,
                    &[8],
                    1,
                    1,
                    1,
                    1,
                    7000,
                    &[vec![0]],
                    &[],
                    true,
                ),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "more than 64 Mi pixels is rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(
                    2,
                    2,
                    1,
                    &[8],
                    6,
                    7,
                    1,
                    1,
                    2,
                    &[b"notjpeg".to_vec()],
                    &[],
                    true,
                ),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_UNKNOWNIMAGEFORMAT,
            "JPEG-in-TIFF with fewer than three samples is coerced then fails"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(1, 1, 0, &[8], 1, 1, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "zero samples is rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(1, 1, 1, &[8], 8, 1, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "an unknown photometric interpretation is rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(1, 1, 1, &[0], 1, 1, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "zero bits per sample is rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(1, 1, 1, &[8], 1, 4, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "CCITT compression with 8-bit samples is rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(1, 1, 3, &[4], 2, 1, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "RGB with sub-byte samples is rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(1, 1, 2, &[8], 1, 1, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "grayscale with two samples is rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(1, 1, 2, &[8], 3, 1, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "palette images with two samples are rejected"
        );
        assert_eq!(
            wic_decode_tiff_frame(
                &build_tiff_strips(1, 1, 1, &[8], 3, 1, 1, 1, 1, &[vec![0]], &[], true),
                0
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a palette shorter than the bit depth requires is rejected"
        );
        let mut palette = vec![0_u32; 16 * 3];
        palette[0] = 65535;
        palette[16] = 32768;
        palette[32] = 255;
        let tiff = build_tiff_strips(1, 1, 1, &[4], 3, 1, 1, 1, 1, &[vec![0]], &palette, true);
        let image = wic_decode_tiff_frame(&tiff, 0).expect("palette strip");
        assert_eq!(&image.pixels[..], &[128, 0, 255, 255]);
        let planar_short =
            build_tiff_strips(2, 2, 3, &[8], 2, 1, 1, 2, 2, &[vec![0_u8; 12]], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&planar_short, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "planar strips with too few offsets are rejected"
        );
    }

    fn tiff_patch_tag(tiff: &mut [u8], tag: u16, replacement: u16, kind: u16, value: u32) {
        let (little, ifd) = wic_tiff_header(tiff).expect("TIFF header");
        let (entries, _) = wic_tiff_ifd(tiff, ifd, little).expect("IFD");
        let entry = wic_tiff_find(&entries, tag).expect("tag");
        tiff_put_u16(tiff, entry.offset, replacement, little);
        tiff_put_u16(tiff, entry.offset + 2, kind, little);
        tiff_put_u32(tiff, entry.offset + 4, 1, little);
        if kind == 3 {
            tiff_put_u16(tiff, entry.offset + 8, value as u16, little);
            tiff_put_u16(tiff, entry.offset + 10, 0, little);
        } else {
            tiff_put_u32(tiff, entry.offset + 8, value, little);
        }
    }

    #[test]
    fn tiff_tiled_paths_reject_missing_offsets_and_bad_predictors() {
        let tiles = build_tiff_gray4_tiled(3, 3, 4, 2, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], true);
        let mut missing_offsets = tiles.clone();
        let (little, ifd) = wic_tiff_header(&missing_offsets).unwrap();
        let (entries, _) = wic_tiff_ifd(&missing_offsets, ifd, little).unwrap();
        let offsets = wic_tiff_find(&entries, 324).unwrap();
        tiff_put_u32(&mut missing_offsets, offsets.offset + 4, 0, little);
        assert_eq!(
            wic_decode_tiff_frame(&missing_offsets, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a tiled TIFF without tile offsets is rejected"
        );
        let mut out_of_range = tiles.clone();
        let (entries, _) = wic_tiff_ifd(&out_of_range, ifd, little).unwrap();
        let offsets = wic_tiff_find(&entries, 324).unwrap();
        let array = wic_tiff_entry_data(&out_of_range, offsets, little).unwrap();
        let array_offset = (array.as_ptr() as usize) - (out_of_range.as_ptr() as usize);
        tiff_put_u32(&mut out_of_range, array_offset, 0xffff_ffff, little);
        assert_eq!(
            wic_decode_tiff_frame(&out_of_range, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a tile offset past the buffer is rejected"
        );

        let mut ccitt = tiles.clone();
        tiff_patch_tag(&mut ccitt, 258, 258, 3, 1);
        tiff_patch_tag(&mut ccitt, 259, 259, 3, 2);
        tiff_patch_tag(&mut ccitt, 262, 262, 3, 0);
        let (little, ifd) = wic_tiff_header(&ccitt).unwrap();
        let (entries, _) = wic_tiff_ifd(&ccitt, ifd, little).unwrap();
        let counts = wic_tiff_find(&entries, 325).unwrap();
        let array = wic_tiff_entry_data(&ccitt, counts, little).unwrap();
        let array_offset = (array.as_ptr() as usize) - (ccitt.as_ptr() as usize);
        tiff_put_u32(&mut ccitt, array_offset, 0, little);
        assert_eq!(
            wic_decode_tiff_frame(&ccitt, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a tiled CCITT tile with no data is rejected"
        );

        let mut truncated_tile = tiles.clone();
        let (little, ifd) = wic_tiff_header(&truncated_tile).unwrap();
        let (entries, _) = wic_tiff_ifd(&truncated_tile, ifd, little).unwrap();
        let counts = wic_tiff_find(&entries, 325).unwrap();
        let array = wic_tiff_entry_data(&truncated_tile, counts, little).unwrap();
        let array_offset = (array.as_ptr() as usize) - (truncated_tile.as_ptr() as usize);
        tiff_put_u32(&mut truncated_tile, array_offset, 1, little);
        assert_eq!(
            wic_decode_tiff_frame(&truncated_tile, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a tile whose decompressed size is short is rejected"
        );

        let mut predictor = tiles;
        tiff_patch_tag(&mut predictor, 284, 317, 3, 2);
        assert_eq!(
            wic_decode_tiff_frame(&predictor, 0).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "predictor 2 with 4-bit tiles is rejected"
        );
    }

    fn build_tiff_resolution(unit: u16, numerator: u32, denominator: u32, little: bool) -> Vec<u8> {
        let entry_count = 12_usize;
        let ifd_offset = 10_usize;
        let ifd_size = 2 + entry_count * 12 + 4;
        let rational_offset = ifd_offset + ifd_size;
        let mut out = vec![0_u8; rational_offset + 16];
        out[..2].copy_from_slice(if little { b"II" } else { b"MM" });
        tiff_put_u16(&mut out, 2, 42, little);
        tiff_put_u32(&mut out, 4, ifd_offset as u32, little);
        out[8] = 77;
        tiff_put_u16(&mut out, ifd_offset, entry_count as u16, little);
        let entries = [
            (256_u16, 3_u16, 1_u32, 1_u32),
            (257, 3, 1, 1),
            (258, 3, 1, 8),
            (259, 3, 1, 1),
            (262, 3, 1, 1),
            (273, 4, 1, 8),
            (277, 3, 1, 1),
            (278, 4, 1, 1),
            (279, 4, 1, 1),
            (282, 5, 1, rational_offset as u32),
            (283, 5, 1, (rational_offset + 8) as u32),
            (296, 3, 1, u32::from(unit)),
        ];
        for (index, (tag, kind, count, value)) in entries.iter().enumerate() {
            let base = ifd_offset + 2 + index * 12;
            tiff_put_u16(&mut out, base, *tag, little);
            tiff_put_u16(&mut out, base + 2, *kind, little);
            tiff_put_u32(&mut out, base + 4, *count, little);
            if *kind == 3 {
                tiff_put_u16(&mut out, base + 8, *value as u16, little);
            } else {
                tiff_put_u32(&mut out, base + 8, *value, little);
            }
        }
        tiff_put_u32(&mut out, ifd_offset + 2 + entry_count * 12, 0, little);
        tiff_put_u32(&mut out, rational_offset, numerator, little);
        tiff_put_u32(&mut out, rational_offset + 4, denominator, little);
        tiff_put_u32(&mut out, rational_offset + 8, numerator, little);
        tiff_put_u32(&mut out, rational_offset + 12, denominator, little);
        out
    }

    #[test]
    fn tiff_resolution_units_and_invalid_rationals() {
        let centimeters = build_tiff_resolution(3, 100, 1, true);
        let image = wic_decode_tiff_frame(&centimeters, 0).expect("centimeter TIFF");
        assert_eq!((image.dpi_x * 100.0).round() as u32, 25_400);
        assert_eq!((image.dpi_y * 100.0).round() as u32, 25_400);
        let inches = build_tiff_resolution(2, 144, 1, true);
        let image = wic_decode_tiff_frame(&inches, 0).expect("inch TIFF");
        assert_eq!(image.dpi_x, 144.0, "unit 2 uses DPI directly");
        let zero = build_tiff_resolution(2, 0, 1, true);
        let image = wic_decode_tiff_frame(&zero, 0).expect("zero DPI TIFF");
        assert_eq!(image.dpi_x, WIC_DEFAULT_DPI);
        assert_eq!(image.dpi_y, WIC_DEFAULT_DPI);
        let zero_denominator = build_tiff_resolution(2, 72, 0, true);
        let image = wic_decode_tiff_frame(&zero_denominator, 0).expect("bad denominator TIFF");
        assert_eq!(image.dpi_x, WIC_DEFAULT_DPI);
        let big_endian = build_tiff_resolution(2, 300, 1, false);
        let image = wic_decode_tiff_frame(&big_endian, 0).expect("big-endian TIFF");
        assert_eq!(image.dpi_x, 300.0);
        assert_eq!(
            wic_tiff_thumbnail(&big_endian),
            None,
            "a big-endian IFD without a next IFD has no thumbnail"
        );
        let mut jpeg = vec![0xff, 0xd8];
        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&big_endian);
        wic_jpeg_push_segment(&mut jpeg, 0xe1, &payload);
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_exif_metadata(&jpeg),
            (Vec::<(String, String)>::new(), None),
            "big-endian EXIF directories are parsed"
        );
    }

    #[test]
    fn jpeg_header_parser_rejects_malformed_segments() {
        assert_eq!(
            wic_decode_jpeg(&[0xff, 0xd8, 0x00, 0x00]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a non-marker byte after SOI is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&[0xff, 0xd8, 0xff, 0xff]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a marker byte without its code is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&[0xff, 0xd8, 0xff, 0x01, 0xff, 0xd9]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a standalone marker is skipped but no scan follows"
        );
        assert_eq!(
            wic_decode_jpeg(&[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x01]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a segment length below two is rejected"
        );
        let mut unit2 = vec![0xff, 0xd8];
        let mut jfif = b"JFIF\0".to_vec();
        jfif.extend_from_slice(&[1, 1, 2, 0, 100, 0, 100, 0, 0]);
        wic_jpeg_push_segment(&mut unit2, 0xe0, &jfif);
        unit2.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&unit2).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a JFIF-only stream has no scan"
        );
        let mut unit0 = vec![0xff, 0xd8];
        let mut jfif0 = b"JFIF\0".to_vec();
        jfif0.extend_from_slice(&[1, 1, 0, 0, 72, 0, 72, 0, 0]);
        wic_jpeg_push_segment(&mut unit0, 0xe0, &jfif0);
        unit0.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(wic_decode_jpeg(&unit0).unwrap_err(), WINCODEC_ERR_BADIMAGE);
        let mut short_sof = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut short_sof, 0xc0, &[8, 0, 1]);
        short_sof.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&short_sof).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a short SOF is rejected"
        );
        let mut precision = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut precision, 0xc0, &[7, 0, 1, 0, 1, 1, 1, 0x11, 0]);
        precision.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&precision).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "a precision other than eight is unsupported"
        );
        let mut duplicate = vec![0xff, 0xd8];
        for _ in 0..2 {
            wic_jpeg_push_segment(&mut duplicate, 0xc0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]);
        }
        duplicate.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&duplicate).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a duplicate SOF is rejected"
        );
        let mut zero_dimension = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut zero_dimension, 0xc0, &[8, 0, 0, 0, 1, 1, 1, 0x11, 0]);
        zero_dimension.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&zero_dimension).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a zero SOF dimension is rejected"
        );
        let mut odd_count = vec![0xff, 0xd8];
        let mut sof = vec![8, 0, 1, 0, 1, 4];
        sof.extend_from_slice(&[1, 0x11, 0, 2, 0x11, 0, 3, 0x11, 0, 4, 0x11, 0]);
        wic_jpeg_push_segment(&mut odd_count, 0xc0, &sof);
        odd_count.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&odd_count).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "a four-component SOF is unsupported"
        );
        let mut sampling = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut sampling, 0xc0, &[8, 0, 1, 0, 1, 1, 1, 0x01, 0]);
        sampling.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&sampling).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a zero sampling factor is rejected"
        );
        let mut lossless = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut lossless, 0xc3, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]);
        lossless.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&lossless).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "lossless SOF markers are unsupported"
        );
        let mut short_dht = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut short_dht, 0xc4, &[0]);
        short_dht.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&short_dht).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a DHT without counts is rejected"
        );
        let mut bad_id = vec![0xff, 0xd8];
        let mut dht = vec![4_u8];
        dht.extend_from_slice(&[0_u8; 16]);
        wic_jpeg_push_segment(&mut bad_id, 0xc4, &dht);
        bad_id.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&bad_id).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a Huffman table id above three is rejected"
        );
        let mut truncated_symbols = vec![0xff, 0xd8];
        let mut dht = vec![0_u8];
        dht.extend_from_slice(&[1_u8; 1]);
        dht.extend_from_slice(&[0_u8; 15]);
        wic_jpeg_push_segment(&mut truncated_symbols, 0xc4, &dht);
        truncated_symbols.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&truncated_symbols).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a DHT whose symbols run past the segment is rejected"
        );
        let mut bad_table = vec![0xff, 0xd8];
        let mut dht = vec![0_u8];
        dht.extend_from_slice(&[3_u8]);
        dht.extend_from_slice(&[0_u8; 15]);
        dht.extend_from_slice(&[0_u8, 1, 2]);
        wic_jpeg_push_segment(&mut bad_table, 0xc4, &dht);
        bad_table.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&bad_table).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an over-subscribed Huffman table is rejected"
        );
        let mut unknown = vec![0xff, 0xd8];
        wic_jpeg_push_segment(&mut unknown, 0xbf, &[]);
        unknown.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&unknown).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an unknown marker is skipped and no scan follows"
        );
    }

    #[test]
    fn jpeg_grayscale_scan_decodes_one_component() {
        let mut jpeg = vec![0xff, 0xd8];
        let mut dqt = vec![0_u8];
        dqt.extend_from_slice(&[1_u8; 64]);
        wic_jpeg_push_segment(&mut jpeg, 0xdb, &dqt);
        wic_jpeg_push_segment(&mut jpeg, 0xc0, &[8, 0, 8, 0, 8, 1, 1, 0x11, 0]);
        wic_jpeg_push_segment(
            &mut jpeg,
            0xc4,
            &wic_jpeg_huffman_payload(
                0,
                0,
                &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                &[0],
            ),
        );
        wic_jpeg_push_segment(
            &mut jpeg,
            0xc4,
            &wic_jpeg_huffman_payload(
                1,
                0,
                &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                &[0],
            ),
        );
        wic_jpeg_push_segment(&mut jpeg, 0xda, &[1, 1, 0x00, 0, 63, 0]);
        jpeg.extend_from_slice(&[0x3f]);
        jpeg.extend_from_slice(&[0xff, 0xd9]);
        let image = wic_decode_jpeg(&jpeg).expect("grayscale JPEG");
        assert_eq!((image.width, image.height), (8, 8));
        assert_eq!(image.pixels.len(), 8 * 8 * 4);
        for pixel in image.pixels.chunks_exact(4) {
            assert_eq!(pixel, [128, 128, 128, 255]);
        }
        assert_eq!(
            wic_decode_jpeg(&jpeg[..jpeg.len() - 4]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated grayscale scan is rejected"
        );
    }

    #[test]
    fn jpeg_encode_block_rejects_missing_symbols_and_long_runs() {
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
        let quant = [1_u16; 64];
        let dc = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let ac = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0x00]);
        let mut writer = WicJpegBitWriter::new();
        let mut previous = 5;
        assert_eq!(
            wic_jpeg_encode_block(
                &[0_f32; 64],
                &quant,
                &cosine,
                &dc,
                &ac,
                &mut previous,
                &mut writer
            ),
            false,
            "a DC category missing from the table fails the block"
        );
        let dc_full = jpeg_table(WIC_JPEG_DC_LUMA_COUNTS, &WIC_JPEG_DC_LUMA_SYMBOLS);
        let ac_full = jpeg_table(WIC_JPEG_AC_LUMA_COUNTS, &WIC_JPEG_AC_LUMA_SYMBOLS);
        let mut samples = [0_f32; 64];
        for y in 0..8 {
            for x in 0..8 {
                samples[y * 8 + x] = 64.0 * cosine[x][3] * cosine[y][2];
            }
        }
        let mut writer = WicJpegBitWriter::new();
        let mut previous = 0;
        assert_eq!(
            wic_jpeg_encode_block(
                &samples,
                &quant,
                &cosine,
                &dc_full,
                &ac_full,
                &mut previous,
                &mut writer
            ),
            true,
            "a sixteen-zero run encodes as ZRL plus a symbol"
        );
        let ac_no_zrl = jpeg_table([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0x09]);
        let mut writer = WicJpegBitWriter::new();
        let mut previous = 0;
        assert_eq!(
            wic_jpeg_encode_block(
                &samples,
                &quant,
                &cosine,
                &dc_full,
                &ac_no_zrl,
                &mut previous,
                &mut writer
            ),
            false,
            "a table without ZRL fails on a sixteen-zero run"
        );
        let ac_no_symbol = jpeg_table([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0xf0]);
        let mut writer = WicJpegBitWriter::new();
        let mut previous = 0;
        assert_eq!(
            wic_jpeg_encode_block(
                &samples,
                &quant,
                &cosine,
                &dc_full,
                &ac_no_symbol,
                &mut previous,
                &mut writer
            ),
            false,
            "a table without the coefficient symbol fails"
        );
        let mut writer = WicJpegBitWriter::new();
        let mut previous = 0;
        assert_eq!(
            wic_jpeg_encode_block(
                &[0_f32; 64],
                &quant,
                &cosine,
                &dc_full,
                &ac_full,
                &mut previous,
                &mut writer
            ),
            true,
            "a uniform block emits an end-of-block symbol"
        );
        let ac_no_eob = jpeg_table([0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0x01]);
        let mut writer = WicJpegBitWriter::new();
        let mut previous = 0;
        assert_eq!(
            wic_jpeg_encode_block(
                &[0_f32; 64],
                &quant,
                &cosine,
                &dc_full,
                &ac_no_eob,
                &mut previous,
                &mut writer
            ),
            false,
            "a table without EOB fails the trailing run"
        );
    }

    #[test]
    fn jpeg_encode_sampled_rejects_invalid_bounds() {
        assert_eq!(
            wic_encode_jpeg_sampled(0, 1, &[], None, (1, 1)).unwrap_err(),
            E_INVALIDARG
        );
        assert_eq!(
            wic_encode_jpeg_sampled(1, 1, &[0, 0, 0], None, (1, 1)).unwrap_err(),
            E_INVALIDARG
        );
        let pixels = vec![0_u8; 70_000 * 4];
        assert_eq!(
            wic_encode_jpeg_sampled(70_000, 1, &pixels, None, (1, 1)).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "dimensions wider than u16 are unsupported"
        );
    }

    #[test]
    fn tiff_deflate_falls_back_to_raw_and_animation_rejects_empty_frames() {
        use std::io::Write as _;
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"raw-deflate").expect("deflate write");
        let raw = encoder.finish().expect("deflate finish");
        assert_eq!(
            wic_tiff_deflate_decode(&raw, 11),
            Some(b"raw-deflate".to_vec()),
            "raw Deflate is accepted when zlib wrapping fails"
        );
        let mut zlib = Vec::new();
        let mut encoder =
            flate2::write::ZlibEncoder::new(&mut zlib, flate2::Compression::default());
        encoder.write_all(b"zlib-deflate").expect("zlib write");
        encoder.finish().expect("zlib finish");
        assert_eq!(
            wic_tiff_deflate_decode(&zlib, 12),
            Some(b"zlib-deflate".to_vec()),
            "zlib-wrapped Deflate takes the fast path"
        );
        assert_eq!(
            wic_encode_gif_animation(1, 1, &[], 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an empty animation is rejected"
        );
        assert_eq!(
            wic_encode_gif_animation(
                1,
                1,
                &[WicGifAnimationFrame {
                    bgra: &[0, 0, 0],
                    delay_ms: 0,
                    disposal: 0,
                }],
                0,
            )
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a frame with short pixels is rejected"
        );
        let planar7 = build_tiff_strips(
            1,
            1,
            3,
            &[8],
            6,
            7,
            1,
            2,
            1,
            &[b"notjpeg".to_vec()],
            &[],
            true,
        );
        assert_eq!(
            wic_decode_tiff_frame(&planar7, 0).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "JPEG-in-TIFF with planar 2 is rejected"
        );
        let photometric6 = build_tiff_strips(1, 1, 3, &[8], 6, 1, 1, 1, 1, &[vec![0]], &[], true);
        assert_eq!(
            wic_decode_tiff_frame(&photometric6, 0).unwrap_err(),
            WINCODEC_ERR_COMPRESSIONNOTSUPPORTED,
            "photometric 6 without JPEG compression is rejected"
        );
        let malformed_ifd = wic_tiff_metadata_entries(b"II*\0\xff\xff\xff\xff");
        assert_eq!(
            malformed_ifd,
            vec![("FrameCount".to_string(), "0".to_string())],
            "a malformed IFD reports only the frame count"
        );
    }

    #[test]
    fn tiff_metadata_entries_reject_numeric_and_malformed_tags() {
        assert_eq!(
            wic_tiff_metadata_entries(b"NOTATIFF"),
            Vec::<(String, String)>::new()
        );
        let mut tiff = build_tiff_rgb(1, 1, &[(vec![1, 2, 3], 1)], true, &[]);
        tiff_patch_tag(&mut tiff, 278, 274, 3, 6);
        let entries = wic_tiff_metadata_entries(&tiff);
        assert_eq!(
            entries.contains(&("FrameCount".to_string(), "1".to_string())),
            true
        );
        assert_eq!(
            entries.contains(&("Orientation".to_string(), "6".to_string())),
            true,
            "a numeric TIFF tag is formatted with its value"
        );
        tiff_patch_tag(&mut tiff, 273, 65_000, 3, 1);
        let (little, ifd) = wic_tiff_header(&tiff).unwrap();
        let (ifd_entries, _) = wic_tiff_ifd(&tiff, ifd, little).unwrap();
        let entry = wic_tiff_find(&ifd_entries, 279).unwrap();
        tiff_put_u16(&mut tiff, entry.offset, 270, little);
        tiff_put_u16(&mut tiff, entry.offset + 2, 2, little);
        tiff_put_u32(&mut tiff, entry.offset + 4, 100_000, little);
        tiff_put_u32(&mut tiff, entry.offset + 8, u32::MAX, little);
        let entries = wic_tiff_metadata_entries(&tiff);
        assert_eq!(
            entries.iter().any(|(name, _)| name == "ImageDescription"),
            false,
            "unreadable entry data is skipped"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|(name, _)| name == "Orientation")
                .count(),
            1,
            "unknown tags are skipped without dropping known ones"
        );
        assert_eq!(
            wic_tiff_values(
                &[0_u8; 8],
                &WicTiffEntry {
                    tag: 1,
                    kind: 1,
                    count: 1,
                    offset: 0
                },
                true
            ),
            Vec::<u32>::new(),
            "an entry whose data is out of range yields no values"
        );
        assert_eq!(
            wic_tiff_entry_data(
                &[0_u8; 8],
                &WicTiffEntry {
                    tag: 1,
                    kind: 11,
                    count: 1,
                    offset: 0
                },
                true
            ),
            None,
            "an unknown TIFF entry kind has no data"
        );
    }

    // ── Adversarial coverage of the remaining codec failure paths ──────────

    #[test]
    fn gif_lzw_decode_rejects_code_past_grown_dictionary() {
        let mut codes = vec![(256_u16, 9_u32)];
        for _ in 0..255 {
            codes.push((0_u16, 9));
        }
        codes.push((1023_u16, 10));
        assert_eq!(
            wic_gif_lzw_decode(&gif_pack_codes(&codes), 8, 1000),
            None,
            "a code past the grown dictionary is rejected"
        );
    }

    #[test]
    fn tiff_lzw_decode_rejects_code_past_grown_dictionary() {
        let mut codes = vec![(256_u16, 9_u32)];
        for _ in 0..254 {
            codes.push((0_u16, 9));
        }
        codes.push((1023_u16, 10));
        assert_eq!(
            wic_tiff_lzw_decode(&tiff_pack_codes(&codes), 1000),
            None,
            "a code past the grown TIFF dictionary is rejected"
        );
    }

    #[test]
    fn ccitt_decode_1d_rejects_non_advancing_zero_runs() {
        let mut parts = Vec::new();
        for _ in 0..40 {
            parts.push("00110101");
            parts.push("0000110111");
        }
        let mut row = [false; 1];
        assert_eq!(
            wic_ccitt_decode_1d(&mut ccitt_bits(&ccitt_pack(&parts)), 1, &mut row),
            None,
            "a zero-length run loop that never advances trips the guard"
        );
    }

    #[test]
    fn ccitt_decode_2d_rejects_horizontal_fill_past_short_row() {
        let mut row = [false; 3];
        assert_eq!(
            wic_ccitt_decode_2d(
                &mut ccitt_bits(&ccitt_pack(&["001", "1011", "0000110111"])),
                4,
                &[(4, false)],
                &mut row
            ),
            None,
            "the first horizontal run past a short row is rejected"
        );
    }

    #[test]
    fn tiff_decode_planar_tiles_rejects_zero_tile_dimensions() {
        let pixels: Vec<u8> = (0..32).map(|value| value as u8).collect();
        let mut planar = build_tiff_gray4_tiled(8, 4, 4, 4, &pixels, true);
        tiff_patch_tag(&mut planar, 284, 284, 3, 2);
        let image = wic_decode_tiff_frame(&planar, 0).expect("planar tiled gray4");
        assert_eq!((image.width, image.height), (8, 4));
        assert_eq!(&image.pixels[..4], &[0, 0, 0, 255]);
        assert_eq!(&image.pixels[4..8], &[17, 17, 17, 255]);
        let mut zero_tile = build_tiff_gray4_tiled(8, 4, 4, 4, &pixels, true);
        tiff_patch_tag(&mut zero_tile, 322, 322, 4, 0);
        assert_eq!(
            wic_decode_tiff_frame(&zero_tile, 0).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a planar tile with zero width is rejected"
        );
    }

    #[test]
    fn png_decode_rejects_missing_palette_and_truncated_phys_stream() {
        let phys = vec![0, 0, 0x0e, 0xc4, 0, 0, 0x0e, 0xc4, 1];
        let png = build_png(1, 1, 8, 0, 0, &[(b"pHYs", phys)], &[0, 0]);
        let image = wic_decode_png(&png).expect("PNG with pHYs");
        assert_eq!(image.dpi_x, f64::from(3780_u32) * 0.0254);
        assert_eq!(image.dpi_y, f64::from(3780_u32) * 0.0254);
        let truncated = &png[..png.len() - 12];
        assert_eq!(
            wic_decode_png(truncated).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a PNG missing IEND is rejected"
        );
        let indexed = build_png(1, 1, 8, 3, 0, &[], &[0, 0]);
        assert_eq!(
            wic_decode_png(&indexed).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an indexed PNG without a palette is rejected"
        );
    }

    #[test]
    fn jpeg_encoder_rejects_missing_huffman_symbols_after_table_build() {
        let tables = WicJpegEncoderTables::build();
        assert_eq!(
            tables.is_some(),
            true,
            "the constant encoder Huffman tables build"
        );
        let tables = tables.unwrap();
        let mut cosine = [[0.0_f32; 8]; 8];
        cosine[7][7] = 1.0;
        let mut samples = [0.0_f32; 64];
        samples[63] = 100.0;
        let quant = [1_u16; 64];
        let mut previous = 0_i32;
        let mut writer = WicJpegBitWriter::new();
        assert_eq!(
            wic_jpeg_encode_block(
                &samples,
                &quant,
                &cosine,
                &tables.dc_luma,
                &tables.ac_luma,
                &mut previous,
                &mut writer
            ),
            true,
            "a block ending on a nonzero coefficient completes"
        );
        let empty = WicJpegHuffman {
            entries: Vec::new(),
        };
        let mut previous = 0_i32;
        let mut writer = WicJpegBitWriter::new();
        assert_eq!(
            wic_jpeg_encode_block(
                &[0.0_f32; 64],
                &quant,
                &cosine,
                &empty,
                &empty,
                &mut previous,
                &mut writer
            ),
            false,
            "an empty table rejects the DC symbol"
        );
    }

    #[test]
    fn gif_quantize_rejects_palette_overflow_beyond_exact_colors() {
        let mut bgra = Vec::new();
        for index in 0..300_u32 {
            bgra.extend_from_slice(&[(index % 256) as u8, (index / 256) as u8, 0, 255]);
        }
        bgra.extend_from_slice(&[102, 51, 0, 255]);
        let (palette, indices, transparent) = wic_gif_quantize(&bgra);
        assert_eq!(
            transparent, None,
            "opaque overflow input has no transparent index"
        );
        assert_eq!(indices.len(), 301, "every pixel receives an index");
        assert_eq!(indices[300], 8, "the nearest cube color is selected");
        assert_eq!(palette[8], [0, 51, 102], "the cube palette entry is exact");
    }

    #[test]
    fn gif_lzw_encode_rejects_invalid_minimum_code_size_at_growth_boundary() {
        let indices: Vec<u8> = (0..=254).collect();
        let encoded = wic_gif_lzw_encode(&indices);
        assert_eq!(
            wic_gif_lzw_decode(&encoded, 8, indices.len() + 1),
            Some(indices),
            "the grown final code width round-trips"
        );
        assert_eq!(
            wic_gif_lzw_decode(&encoded, 0, 10),
            None,
            "an invalid minimum code size is rejected"
        );
    }

    #[test]
    fn tiff_encoder_rejects_bad_dpi_and_short_pages_after_odd_padding() {
        let one = [10_u8, 20, 30, 255];
        let tiff = wic_encode_tiff_pages(&[WicTiffPage {
            width: 1,
            height: 1,
            bgra: &one,
            dpi: None,
            description: None,
            make: None,
            model: None,
            datetime: None,
        }])
        .expect("1x1 TIFF");
        let image = wic_decode_tiff_frame(&tiff, 0).expect("decode padded TIFF");
        assert_eq!(&image.pixels, &one);
        let tiff = wic_encode_tiff_pages(&[WicTiffPage {
            width: 1,
            height: 1,
            bgra: &one,
            dpi: Some((f64::NAN, -1.0)),
            description: None,
            make: None,
            model: None,
            datetime: None,
        }])
        .expect("TIFF with invalid dpi");
        let image = wic_decode_tiff_frame(&tiff, 0).expect("decode default dpi TIFF");
        assert_eq!(image.dpi_x, 96.0);
        assert_eq!(image.dpi_y, 96.0);
        assert_eq!(
            wic_encode_tiff_pages(&[WicTiffPage {
                width: 2,
                height: 2,
                bgra: &one,
                dpi: None,
                description: None,
                make: None,
                model: None,
                datetime: None,
            }])
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "short page pixels are rejected"
        );
    }

    #[test]
    fn jpeg_bit_reader_rejects_non_restart_markers_without_pending_restart() {
        let mut bits = WicJpegBits::new(&[0xff, 0xd0], 0);
        assert_eq!(
            bits.read_byte(),
            None,
            "a restart marker stops the entropy stream"
        );
        assert_eq!(
            bits.skip_restart(),
            true,
            "a pending restart marker resumes the stream"
        );
        assert_eq!(
            WicJpegBits::new(&[0x12, 0xff, 0xe0], 0).skip_restart(),
            false,
            "a non-restart marker is not skipped"
        );
    }

    #[test]
    fn jpeg_block_decoder_rejects_truncated_dc_and_ac_runs() {
        let scan = WicJpegScanParams {
            progressive: false,
            ss: 0,
            se: 63,
            ah: 0,
            al: 0,
        };
        let dc8 = jpeg_table([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], &[1]);
        let ac0 = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0x00]);
        let mut component = jpeg_component(1);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc8, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        let mut eob = 0;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc8, &ac0, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a DC category without its amplitude bits is rejected"
        );

        let dc0 = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let ac_f1 = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0xf1]);
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &dc0, 0);
        for _ in 0..4 {
            jpeg_write_symbol(&mut writer, &ac_f1, 0xf1);
            writer.write_bits(1, 1);
        }
        jpeg_write_symbol(&mut writer, &ac_f1, 0xf1);
        let bytes = jpeg_finish(writer);
        let mut component = jpeg_component(1);
        let mut bits = WicJpegBits::new(&bytes, 0);
        let mut eob = 0;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc0, &ac_f1, scan, &mut eob),
            Ok(()),
            "an AC run past coefficient 63 stops the block"
        );
    }

    #[test]
    fn jpeg_block_decoder_rejects_truncated_progressive_ac_and_refinement() {
        let dc = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let ac = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0x00]);
        let scan = WicJpegScanParams {
            progressive: true,
            ss: 1,
            se: 5,
            ah: 0,
            al: 0,
        };
        let mut component = jpeg_component(1);
        let mut bits = WicJpegBits::new(&[0xff, 0xff], 0);
        let mut eob = 0;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an unmatched progressive AC code is rejected"
        );
        let refine = WicJpegScanParams {
            progressive: true,
            ss: 1,
            se: 5,
            ah: 1,
            al: 0,
        };
        let mut component = jpeg_component(1);
        component.coefficients[0][WIC_JPEG_ZIGZAG[1]] = 1;
        let mut bits = WicJpegBits::new(&[], 0);
        let mut eob = 1;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac, refine, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a refinement bit past the stream is rejected"
        );
    }

    fn jpeg_test_segments(segments: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0xff, 0xd8];
        for (marker, segment) in segments {
            out.extend_from_slice(&[0xff, *marker]);
            out.extend_from_slice(&((segment.len() + 2) as u16).to_be_bytes());
            out.extend_from_slice(segment);
        }
        out.extend_from_slice(&[0xff, 0xd9]);
        out
    }

    fn jpeg_test_sof(marker: u8) -> (u8, Vec<u8>) {
        (marker, vec![8, 0, 1, 0, 1, 1, 1, 0x11, 0])
    }

    fn jpeg_test_sos(id: u8, ss: u8, se: u8, ah: u8, al: u8) -> (u8, Vec<u8>) {
        (0xda, vec![1, id, 0, ss, se, (ah << 4) | al])
    }

    #[test]
    fn jpeg_marker_parser_rejects_truncated_lengths_and_invalid_dqt_precision() {
        assert_eq!(
            wic_decode_jpeg(&[0xff, 0xd8, 0xff, 0xe0, 0x00]).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a marker without its length is rejected"
        );
        let mut id4 = vec![0x04];
        id4.extend_from_slice(&[0_u8; 64]);
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[(0xdb, id4)])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a DQT identifier past 3 is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[(0xdb, vec![0_u8; 20])])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated 8-bit DQT is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[(0xdb, vec![0x10; 20])])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a truncated 16-bit DQT is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[(0xdb, vec![0x20; 20])])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an unknown DQT precision is rejected"
        );
        let mut wide = vec![0x10];
        for _ in 0..64 {
            wide.extend_from_slice(&[0, 1]);
        }
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[(0xdb, wide)])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a 16-bit DQT without a scan is rejected"
        );
    }

    #[test]
    fn jpeg_app_markers_reject_ycck_and_keep_jfif_dpi() {
        let image = wic_decode_jpeg(&jpeg_fixture()).expect("JFIF fixture");
        assert_eq!(image.dpi_x, 96.0);
        assert_eq!(image.dpi_y, 96.0);
        let mut ycck = vec![0xff, 0xd8, 0xff, 0xee, 0x00, 0x0e];
        ycck.extend_from_slice(b"Adobe\0");
        ycck.extend_from_slice(&[0, 0, 0, 0, 0, 2]);
        ycck.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&ycck).unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "Adobe transform 2 (YCCK) is rejected"
        );
        let mut adobe = vec![0xff, 0xd8, 0xff, 0xee, 0x00, 0x0e];
        adobe.extend_from_slice(b"Adobe\0");
        adobe.extend_from_slice(&[0, 0, 0, 0, 0, 1]);
        adobe.extend_from_slice(&[0xff, 0xd9]);
        assert_eq!(
            wic_decode_jpeg(&adobe).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a non-YCCK Adobe marker without a scan is rejected"
        );
    }

    #[test]
    fn jpeg_scan_header_rejects_truncated_and_invalid_parameters() {
        let mut dqt = vec![0x00];
        dqt.extend_from_slice(&[1_u8; 64]);
        let sof0 = jpeg_test_sof(0xc0);
        let sof2 = jpeg_test_sof(0xc2);
        let valid = jpeg_test_sos(1, 0, 63, 0, 0);
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[(0xdd, Vec::new())])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an empty DRI segment is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[(0xda, Vec::new())])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an empty SOS segment is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[sof0.clone(), (0xda, vec![0])])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an SOS with zero components is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[
                sof0.clone(),
                jpeg_test_sos(2, 0, 63, 0, 0)
            ]))
            .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an SOS referencing an unknown component is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[sof2, jpeg_test_sos(1, 1, 0, 0, 0)]))
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a progressive scan with ss > se is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[
                sof0.clone(),
                jpeg_test_sos(1, 1, 63, 0, 0)
            ]))
            .unwrap_err(),
            WINCODEC_ERR_UNSUPPORTEDOPERATION,
            "a baseline scan with spectral selection is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[sof0.clone(), valid.clone()])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a scan without a quantization table is rejected"
        );
        assert_eq!(
            wic_decode_jpeg(&jpeg_test_segments(&[sof0, (0xdb, dqt), valid])).unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "a scan without Huffman tables is rejected"
        );
    }

    #[test]
    fn png_and_jpeg_metadata_scanners_reject_malformed_itxt_and_exif() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        wic_png_chunk(&mut png, b"iTXt", b"K\0\0\0");
        wic_png_chunk(&mut png, b"IEND", &[]);
        assert_eq!(
            wic_png_text_entries(&png),
            Vec::<(String, String)>::new(),
            "an iTXt without a language terminator yields no entries"
        );
        assert_eq!(
            wic_jpeg_exif(&[0xff, 0xd8, 0, 0, 0, 0]),
            None,
            "a JPEG with a non-marker byte before APP1 yields no EXIF"
        );
    }

    #[test]
    fn copy_source_pixels_rejects_invalid_converter_and_missing_chain_sources() {
        let mut objects = HashMap::new();
        let invalid = WicObjectState {
            kind: WicObjectKind::Bitmap,
            width: 1,
            height: 1,
            pixel_format: GUID_PIXEL_FORMAT_DONT_CARE,
            pixels: vec![1, 2, 3, 4],
            ..Default::default()
        };
        objects.insert(1, invalid);
        let converter = WicObjectState {
            kind: WicObjectKind::FormatConverter,
            width: 1,
            height: 1,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_RGBA,
            source: 1,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &converter, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a converter over a wrapped bitmap with an invalid format yields nothing"
        );
        let clipper = WicObjectState {
            kind: WicObjectKind::Clipper,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 99,
            clip: Some([0, 0, 1, 1]),
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &clipper, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a clipper without its wrapped source yields nothing"
        );
        let scaler = WicObjectState {
            kind: WicObjectKind::Scaler,
            width: 1,
            height: 1,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 99,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &scaler, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a scaler without its wrapped source yields nothing"
        );
        let rotator = WicObjectState {
            kind: WicObjectKind::FlipRotator,
            width: 1,
            height: 1,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            source: 99,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &rotator, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a flip-rotator without its wrapped source yields nothing"
        );
        let palette = WicObjectState {
            kind: WicObjectKind::Palette,
            pixel_format: GUID_PIXEL_FORMAT_32BPP_BGRA,
            ..Default::default()
        };
        assert_eq!(
            wic_copy_source_pixels(&objects, &palette, 0, 0, 1, 1),
            Vec::<u8>::new(),
            "a non-source object yields nothing"
        );
    }

    #[test]
    fn gif_lzw_decode_rejects_full_dictionary_overflow_after_growth() {
        let mut codes = vec![(256_u16, 9_u32)];
        let mut width = 9_u32;
        let mut next = 258_usize;
        for index in 0..3_840_usize {
            codes.push((0_u16, width));
            if index > 0 && next < 4096 {
                next += 1;
                if next == (1_usize << width) && width < 12 {
                    width += 1;
                }
            }
        }
        codes.push((257_u16, width));
        assert_eq!(
            wic_gif_lzw_decode(&gif_pack_codes(&codes), 8, 4096),
            Some(vec![0_u8; 3_840]),
            "a code stream that fills the 4096-entry dictionary decodes without growing past it"
        );
    }

    #[test]
    fn tiff_lzw_decode_rejects_full_dictionary_overflow_after_growth() {
        let mut codes = vec![(256_u16, 9_u32)];
        let mut width = 9_u32;
        let mut next = 258_usize;
        for index in 0..3_840_usize {
            codes.push((0_u16, width));
            if index > 0 && next < 4096 {
                next += 1;
                if next == (1_usize << width) - 1 && width < 12 {
                    width += 1;
                }
            }
        }
        codes.push((257_u16, width));
        assert_eq!(
            wic_tiff_lzw_decode(&tiff_pack_codes(&codes), 4096),
            Some(vec![0_u8; 3_840]),
            "a TIFF LZW stream that fills the dictionary stops adding entries instead of overflowing"
        );
    }

    #[test]
    fn png_phys_boundary_ignores_zero_density_and_non_meter_units() {
        let zero = build_png(
            1,
            1,
            8,
            0,
            0,
            &[(b"pHYs", vec![0, 0, 0, 0, 0, 0, 0, 0, 1])],
            &[0, 0],
        );
        let image = wic_decode_png(&zero).expect("zero-density pHYs PNG");
        assert_eq!(image.dpi_x, WIC_DEFAULT_DPI);
        assert_eq!(image.dpi_y, WIC_DEFAULT_DPI);

        let inches = build_png(
            1,
            1,
            8,
            0,
            0,
            &[(b"pHYs", vec![0, 0, 0x03, 0xe8, 0, 0, 0x07, 0xd0, 2])],
            &[0, 0],
        );
        let image = wic_decode_png(&inches).expect("non-meter pHYs PNG");
        assert_eq!(image.dpi_x, WIC_DEFAULT_DPI);
        assert_eq!(image.dpi_y, WIC_DEFAULT_DPI);
    }

    #[test]
    fn gif_quantize_overflow_marks_transparent_pixel_index_zero() {
        let mut bgra = Vec::new();
        for index in 0..300_u32 {
            bgra.extend_from_slice(&[(index % 256) as u8, (index / 256) as u8, 0, 255]);
        }
        bgra.extend_from_slice(&[9, 9, 9, 0]);
        let (palette, indices, transparent) = wic_gif_quantize(&bgra);
        assert_eq!(transparent, Some(0));
        assert_eq!(indices.len(), 301);
        assert_eq!(
            indices[300], 0,
            "a transparent pixel uses the reserved index"
        );
        assert_eq!(
            indices[0], 1,
            "opaque colors shift past the transparent slot"
        );
        assert_eq!(palette[0], [0, 0, 0]);
    }

    #[test]
    fn gif_lzw_empty_input_boundary_encodes_only_clear_and_end() {
        let encoded = wic_gif_lzw_encode(&[]);
        assert_eq!(
            encoded,
            vec![0x00, 0x03, 0x02],
            "an empty frame emits exactly the clear and end codes"
        );
        assert_eq!(
            wic_gif_lzw_decode(&encoded, 8, 0),
            Some(Vec::new()),
            "the empty code stream decodes to no pixels"
        );
    }

    #[test]
    fn jpeg_jfif_density_units_boundary_sets_exact_dpi() {
        let mut inches = jpeg_fixture();
        inches[13] = 1;
        inches[14..16].copy_from_slice(&300_u16.to_be_bytes());
        inches[16..18].copy_from_slice(&200_u16.to_be_bytes());
        let image = wic_decode_jpeg(&inches).expect("JFIF inches");
        assert_eq!(image.dpi_x, 300.0);
        assert_eq!(image.dpi_y, 200.0);

        let mut centimeters = jpeg_fixture();
        centimeters[13] = 2;
        centimeters[14..16].copy_from_slice(&118_u16.to_be_bytes());
        centimeters[16..18].copy_from_slice(&39_u16.to_be_bytes());
        let image = wic_decode_jpeg(&centimeters).expect("JFIF centimeters");
        assert_eq!(image.dpi_x, f64::from(118_u32) * 2.54);
        assert_eq!(image.dpi_y, f64::from(39_u32) * 2.54);

        let mut zero = jpeg_fixture();
        zero[14..18].copy_from_slice(&[0, 0, 0, 0]);
        let image = wic_decode_jpeg(&zero).expect("JFIF zero density");
        assert_eq!(image.dpi_x, WIC_DEFAULT_DPI);
        assert_eq!(image.dpi_y, WIC_DEFAULT_DPI);
    }

    #[test]
    fn jpeg_truncated_and_non_jfif_app0_fall_back_to_default_dpi() {
        let mut non_jfif = jpeg_fixture();
        non_jfif[6..11].copy_from_slice(b"JFXX\0");
        let image = wic_decode_jpeg(&non_jfif).expect("a non-JFIF APP0 is skipped");
        assert_eq!(
            image.dpi_x, WIC_DEFAULT_DPI,
            "a non-JFIF APP0 must not claim the JFIF density"
        );
        assert_eq!(
            image.dpi_y, WIC_DEFAULT_DPI,
            "a non-JFIF APP0 must not claim the JFIF density"
        );

        let mut truncated = jpeg_fixture();
        truncated[4..6].copy_from_slice(&2_u16.to_be_bytes());
        drop(truncated.drain(6..20));
        let image = wic_decode_jpeg(&truncated).expect("an empty APP0 is skipped");
        assert_eq!(
            image.dpi_x, WIC_DEFAULT_DPI,
            "a truncated APP0 must not claim a density"
        );
        assert_eq!(
            image.dpi_y, WIC_DEFAULT_DPI,
            "a truncated APP0 must not claim a density"
        );
    }

    #[test]
    fn jpeg_refinement_rejects_exhausted_bits_on_nonzero_coefficients() {
        let dc = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0]);
        let ac_one = jpeg_table([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[0x01]);
        let scan = WicJpegScanParams {
            progressive: true,
            ss: 1,
            se: 63,
            ah: 1,
            al: 0,
        };
        let mut component = jpeg_component(1);
        for coefficient in 1..=8 {
            component.coefficients[0][WIC_JPEG_ZIGZAG[coefficient]] = 2;
        }
        let mut writer = WicJpegBitWriter::new();
        jpeg_write_symbol(&mut writer, &ac_one, 0x01);
        writer.write_bits(1, 1);
        let bytes = jpeg_finish(writer);
        let mut bits = WicJpegBits::new(&bytes, 0);
        let mut eob = 0;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &ac_one, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "refining nonzero coefficients past the entropy stream is rejected"
        );

        let empty = WicJpegHuffman {
            entries: Vec::new(),
        };
        let mut component = jpeg_component(1);
        let mut bits = WicJpegBits::new(&[0xff], 0);
        let mut eob = 0;
        assert_eq!(
            wic_jpeg_decode_block(&mut component, 0, &mut bits, &dc, &empty, scan, &mut eob)
                .unwrap_err(),
            WINCODEC_ERR_BADIMAGE,
            "an unmatched refinement run/size code is rejected"
        );
    }
}
