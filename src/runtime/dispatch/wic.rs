//! Windows Imaging Component dispatch: the windowscodecs.dll exports, in a
//! dedicated module per the audit's modularity requirement.  The surface is
//! a real in-process WIC object model: WICCreateImagingFactory hands out an
//! IWICImagingFactory whose Create* methods build palette, scaler, clipper,
//! flip-rotator, format-converter, stream, color-context and component-info
//! objects; CreateBitmap / CreateBitmapFromMemory / CreateBitmapFromSource
//! produce software bitmaps with the documented pixel formats; the
//! transform chain (scaler/clipper/flip/converter) wraps a source and
//! produces pixels through CopyPixels.  No codecs or metadata handlers are
//! registered, so decoder/encoder/metadata entry points answer the
//! documented WIC_E_CODECNOTFOUND / WIC_E_CODECNOTHANDLED errors and the
//! _Proxy exports mirror their in-process counterparts.
//!
//! Layer contract: every export and method returns its HRESULT in EAX.

use super::super::*;
use super::unknown_preamble;
use crate::runtime::state::{GuestObjectKind, WicObjectKind, WicObjectState};

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

const WIC_COLOR_CONTEXT_UNINITIALIZED: u32 = 0;
const WIC_COMPONENT_DECODER: u32 = 1;
const WIC_TRANSFORM_ROTATE_90: u32 = 1;
const WIC_TRANSFORM_ROTATE_180: u32 = 2;
const WIC_TRANSFORM_ROTATE_270: u32 = 3;
const WIC_TRANSFORM_FLIP_HORIZONTAL: u32 = 4;
const WIC_TRANSFORM_FLIP_VERTICAL: u32 = 8;

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
    if guid == &GUID_PIXEL_FORMAT_32BPP_BGRA || guid == &GUID_PIXEL_FORMAT_DONT_CARE {
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
                self.wic_factory_respond(state, memory, 4, WIC_E_CODECNOTFOUND)
            }
            HostThunk::WicFactoryCreateDecoderFromStream => {
                self.wic_factory_respond(state, memory, 3, WIC_E_CODECNOTFOUND)
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
            HostThunk::WicFactoryCreateEncoder => {
                self.wic_factory_respond(state, memory, 2, WIC_E_CODECNOTFOUND)
            }
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
            HostThunk::WicBitmapSetPalette => self.wic_bitmap_set_palette(state, memory),
            HostThunk::WicBitmapSetResolution => self.wic_bitmap_set_resolution(state, memory),
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
            HostThunk::WicPaletteIsBlackWhite
            | HostThunk::WicPaletteIsGrayscale
            | HostThunk::WicPaletteHasAlpha => self.wic_palette_flag_zero(state, memory),
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
        let _this = guest_call_arg(state, memory, 0)?;
        let dpi_x = guest_call_arg(state, memory, 1)?;
        let dpi_y = guest_call_arg(state, memory, 2)?;
        if dpi_x != 0 {
            write_guest_f64(memory, dpi_x, 96.0).ok();
        }
        if dpi_y != 0 {
            write_guest_f64(memory, dpi_y, 96.0).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_source_copy_palette(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let palette = guest_call_arg(state, memory, 1)?;
        let Some(target) = self.wic.objects.get(&palette).cloned() else {
            state.set(Register::Rax, 0x8007_0057);
            return Ok(());
        };
        if target.kind != WicObjectKind::Palette {
            state.set(Register::Rax, u64::from(WIC_E_NOTSUPPORTED));
            return Ok(());
        }
        // Sources without indexed formats copy an empty palette.
        if let Some(slot) = self.wic.objects.get_mut(&palette) {
            slot.palette = Vec::new();
            slot.palette_premultiplied = false;
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
        let source_pixels = wic_copy_source_pixels(&self.wic.objects, &source, x, y, w, h);
        let layout = pixel_layout(&source.pixel_format);
        let bytes = layout.map(layout_bytes).unwrap_or(0);
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

    fn wic_bitmap_lock(&mut self, state: &mut CpuState, memory: &mut MemoryImage) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _rect = guest_call_arg(state, memory, 1)?;
        let _flags = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(WIC_E_NOTSUPPORTED));
        Ok(())
    }

    fn wic_bitmap_set_palette(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _palette = guest_call_arg(state, memory, 1)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_bitmap_set_resolution(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _dpi_x = guest_call_arg_f64(state, memory, 1)?;
        let _dpi_y = guest_call_arg_f64(state, memory, 2)?;
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
        let mut palette = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            if let Ok(color) = read_guest_u32(memory, colors + (i as u64 * 4)) {
                palette.push(color);
            }
        }
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.palette = palette;
            target.palette_premultiplied = false;
        }
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
        let _count = guest_call_arg_u32(state, memory, 2)?;
        let _alpha = guest_call_arg_u32(state, memory, 3)?;
        let Some(source_state) = self.wic.objects.get(&source).cloned() else {
            state.set(Register::Rax, u64::from(WIC_E_INVALIDSTATE));
            return Ok(());
        };
        let colors = wic_collect_palette(&source_state);
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.palette = colors;
            target.palette_premultiplied = false;
        }
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
        let _this = guest_call_arg(state, memory, 0)?;
        let _type = guest_call_arg_u32(state, memory, 1)?;
        let _alpha = guest_call_arg_u32(state, memory, 2)?;
        state.set(Register::Rax, u64::from(WIC_E_NOTSUPPORTED));
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
        if let Some(target) = self.wic.objects.get_mut(&this) {
            target.palette = other.palette.clone();
            target.palette_premultiplied = other.palette_premultiplied;
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_palette_get_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_u32(memory, out, 0).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn wic_palette_flag_zero(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_u32(memory, out, 0).ok();
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
        WicObjectKind::Bitmap | WicObjectKind::FormatConverter => {
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
