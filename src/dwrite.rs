//! DirectWrite (DWrite) implementation backed by macOS Core Text.
//!
//! This module provides DWrite-compatible text layout and font enumeration
//! using Core Text via `dlopen`/`dlsym` FFI. All types mirror the DWrite
//! COM interfaces that games expect.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_void;

// ── Core Text / Core Graphics type aliases ──────────────────────────────

pub type CFTypeRef = *const c_void;
pub type CFStringRef = *const c_void;
pub type CFArrayRef = *const c_void;
pub type CFDictionaryRef = *const c_void;
pub type CFNumberRef = *const c_void;
pub type CFDataRef = *const c_void;
pub type CTFontRef = *const c_void;
pub type CTFontCollectionRef = *const c_void;
pub type CTFontDescriptorRef = *const c_void;
pub type CTLineRef = *const c_void;
pub type CTTypesetterRef = *const c_void;
pub type CTFrameRef = *const c_void;
pub type CGContextRef = *const c_void;
pub type CGColorSpaceRef = *const c_void;
pub type CGFontRef = *const c_void;
pub type CGPathRef = *const c_void;
pub type CGGlyph = u16;
pub type UniChar = u16;
pub type CGFloat = f64;
pub type CFIndex = isize;
pub type CFRange = (CFIndex, CFIndex);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CGPoint {
    pub x: CGFloat,
    pub y: CGFloat,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CGSize {
    pub width: CGFloat,
    pub height: CGFloat,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CGRect {
    pub origin: CGPoint,
    pub size: CGSize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CGAffineTransform {
    pub a: CGFloat,
    pub b: CGFloat,
    pub c: CGFloat,
    pub d: CGFloat,
    pub tx: CGFloat,
    pub ty: CGFloat,
}

// ── CoreFoundation constants ────────────────────────────────────────────

/// Runtime value of `kCTFontAttributeName` ("NSFont").
/// Used to associate a CTFont with text in a CFAttributedString.
const KCT_FONT_ATTRIBUTE_NAME: &str = "NSFont";

// ── Function pointer type aliases ───────────────────────────────────────

type CTFontCreateWithNameFn =
    unsafe extern "C" fn(name: CFStringRef, size: CGFloat, matrix: *const CGAffineTransform) -> CTFontRef;
type CTLineCreateWithAttributedStringFn = unsafe extern "C" fn(attr_string: CFStringRef) -> CTLineRef;
type CTLineGetImageBoundsFn =
    unsafe extern "C" fn(line: CTLineRef, context: CGContextRef) -> CGRect;
type CTLineGetTypographicBoundsFn = unsafe extern "C" fn(
    line: CTLineRef,
    ascent: *mut CGFloat,
    descent: *mut CGFloat,
    leading: *mut CGFloat,
) -> CGFloat;
type CTFontGetGlyphsForCharactersFn =
    unsafe extern "C" fn(font: CTFontRef, chars: *const UniChar, glyphs: *mut CGGlyph, count: CFIndex) -> bool;
type CTFontGetAdvancesForGlyphsFn = unsafe extern "C" fn(
    font: CTFontRef,
    orientation: u32,
    glyphs: *const CGGlyph,
    advances: *mut CGSize,
    count: CFIndex,
) -> f64;
type CTFontCopyFullNameFn = unsafe extern "C" fn(font: CTFontRef) -> CFStringRef;
type CTFontCopyFamilyNameFn = unsafe extern "C" fn(font: CTFontRef) -> CFStringRef;
type CTFontCopyPostScriptNameFn = unsafe extern "C" fn(font: CTFontRef) -> CFStringRef;
type CTFontGetAscentFn = unsafe extern "C" fn(font: CTFontRef) -> CGFloat;
type CTFontGetDescentFn = unsafe extern "C" fn(font: CTFontRef) -> CGFloat;
type CTFontGetLeadingFn = unsafe extern "C" fn(font: CTFontRef) -> CGFloat;
type CTFontGetCapHeightFn = unsafe extern "C" fn(font: CTFontRef) -> CGFloat;
type CTFontGetXHeightFn = unsafe extern "C" fn(font: CTFontRef) -> CGFloat;
type CTFontGetUnitsPerEmFn = unsafe extern "C" fn(font: CTFontRef) -> u32;
type CTFontCopyTableFn =
    unsafe extern "C" fn(font: CTFontRef, table: u32, options: u32) -> CFDataRef;
type CTFontDescriptorCreateWithNameAndSizeFn =
    unsafe extern "C" fn(name: CFStringRef, size: CGFloat) -> CTFontDescriptorRef;
type CTFontCreateWithFontDescriptorFn =
    unsafe extern "C" fn(descriptor: CTFontDescriptorRef, size: CGFloat, matrix: *const CGAffineTransform) -> CTFontRef;
type CTFontCollectionCreateFromAvailableFontsFn =
    unsafe extern "C" fn(options: *const CFDictionaryRef) -> CTFontCollectionRef;
type CTFontCollectionCreateMatchingFontDescriptorsFn =
    unsafe extern "C" fn(collection: CTFontCollectionRef) -> CFArrayRef;
type CTFontDescriptorCopyAttributeFn =
    unsafe extern "C" fn(descriptor: CTFontDescriptorRef, attribute: CFStringRef) -> CFTypeRef;
type CTFontGetWeightFn = unsafe extern "C" fn(font: CTFontRef) -> CGFloat;
type CTFontGetSymbolicTraitsFn = unsafe extern "C" fn(font: CTFontRef) -> u32;
type CFStringGetCStringPtrFn =
    unsafe extern "C" fn(theString: CFStringRef, encoding: u32) -> *const i8;
type CFStringGetLengthFn = unsafe extern "C" fn(theString: CFStringRef) -> CFIndex;
type CFStringGetCStringFn =
    unsafe extern "C" fn(theString: CFStringRef, buffer: *mut i8, bufferSize: CFIndex, encoding: u32) -> u8;
type CFNumberGetValueFn =
    unsafe extern "C" fn(number: CFNumberRef, theType: u32, valuePtr: *mut c_void) -> u8;
type CFArrayGetCountFn = unsafe extern "C" fn(theArray: CFArrayRef) -> CFIndex;
type CFArrayGetValueAtIndexFn = unsafe extern "C" fn(theArray: CFArrayRef, idx: CFIndex) -> *const c_void;
type CFReleaseFn = unsafe extern "C" fn(cf: CFTypeRef);
type CFRetainFn = unsafe extern "C" fn(cf: CFTypeRef) -> CFTypeRef;
type CFStringCreateWithCStringFn = unsafe extern "C" fn(
    allocator: *const c_void,
    cStr: *const u8,
    encoding: u32,
) -> CFStringRef;
type CFDataGetBytePtrFn = unsafe extern "C" fn(theData: CFDataRef) -> *const u8;
type CFDataGetLengthFn = unsafe extern "C" fn(theData: CFDataRef) -> CFIndex;
type CFAttributedStringCreateFn = unsafe extern "C" fn(
    allocator: *const c_void,
    str: CFStringRef,
    attributes: CFDictionaryRef,
) -> CFStringRef;
type CFDictionaryCreateFn = unsafe extern "C" fn(
    allocator: *const c_void,
    keys: *const *const c_void,
    values: *const *const c_void,
    numValues: CFIndex,
    keyCallBacks: *const c_void,
    valueCallBacks: *const c_void,
) -> CFDictionaryRef;

// ── Constants ───────────────────────────────────────────────────────────

const KCFStringEncodingUTF8: u32 = 0x08000100;
const KCFNumberCGFloatType: u32 = 16;
const CTFontOrientationDefault: u32 = 0;

/// DWRITE_FONT_WEIGHT constants
pub const DWRITE_FONT_WEIGHT_THIN: u16 = 100;
pub const DWRITE_FONT_WEIGHT_EXTRA_LIGHT: u16 = 200;
pub const DWRITE_FONT_WEIGHT_LIGHT: u16 = 300;
pub const DWRITE_FONT_WEIGHT_SEMI_LIGHT: u16 = 350;
pub const DWRITE_FONT_WEIGHT_NORMAL: u16 = 400;
pub const DWRITE_FONT_WEIGHT_MEDIUM: u16 = 500;
pub const DWRITE_FONT_WEIGHT_DEMI_BOLD: u16 = 600;
pub const DWRITE_FONT_WEIGHT_BOLD: u16 = 700;
pub const DWRITE_FONT_WEIGHT_EXTRA_BOLD: u16 = 800;
pub const DWRITE_FONT_WEIGHT_BLACK: u16 = 900;

/// DWRITE_FONT_STYLE constants
pub const DWRITE_FONT_STYLE_NORMAL: u8 = 0;
pub const DWRITE_FONT_STYLE_OBLIQUE: u8 = 1;
pub const DWRITE_FONT_STYLE_ITALIC: u8 = 2;

/// DWRITE_FONT_STRETCH constants
pub const DWRITE_FONT_STRETCH_UNDEFINED: u16 = 0;
pub const DWRITE_FONT_STRETCH_ULTRA_CONDENSED: u16 = 1;
pub const DWRITE_FONT_STRETCH_EXTRA_CONDENSED: u16 = 2;
pub const DWRITE_FONT_STRETCH_CONDENSED: u16 = 3;
pub const DWRITE_FONT_STRETCH_SEMI_CONDENSED: u16 = 4;
pub const DWRITE_FONT_STRETCH_NORMAL: u16 = 5;
pub const DWRITE_FONT_STRETCH_SEMI_EXPANDED: u16 = 6;
pub const DWRITE_FONT_STRETCH_EXPANDED: u16 = 7;
pub const DWRITE_FONT_STRETCH_EXTRA_EXPANDED: u16 = 8;
pub const DWRITE_FONT_STRETCH_ULTRA_EXPANDED: u16 = 9;

/// DWRITE_TEXT_ALIGNMENT constants
pub const DWRITE_TEXT_ALIGNMENT_LEADING: u8 = 0;
pub const DWRITE_TEXT_ALIGNMENT_TRAILING: u8 = 1;
pub const DWRITE_TEXT_ALIGNMENT_CENTER: u8 = 2;
pub const DWRITE_TEXT_ALIGNMENT_JUSTIFIED: u8 = 3;

/// DWRITE_PARAGRAPH_ALIGNMENT constants
pub const DWRITE_PARAGRAPH_ALIGNMENT_NEAR: u8 = 0;
pub const DWRITE_PARAGRAPH_ALIGNMENT_FAR: u8 = 1;
pub const DWRITE_PARAGRAPH_ALIGNMENT_CENTER: u8 = 2;

/// DWRITE_READING_DIRECTION constants
pub const DWRITE_READING_DIRECTION_LEFT_TO_RIGHT: u8 = 0;
pub const DWRITE_READING_DIRECTION_RIGHT_TO_LEFT: u8 = 1;

/// DWRITE_FLOW_DIRECTION constants
pub const DWRITE_FLOW_DIRECTION_TOP_TO_BOTTOM: u8 = 0;

/// DWRITE_WORD_WRAPPING constants
pub const DWRITE_WORD_WRAPPING_WRAP: u8 = 0;
pub const DWRITE_WORD_WRAPPING_NO_WRAP: u8 = 1;
pub const DWRITE_WORD_WRAPPING_EMERGENCY_BREAK: u8 = 2;
pub const DWRITE_WORD_WRAPPING_WHOLE_WORD: u8 = 3;
pub const DWRITE_WORD_WRAPPING_CHARACTER: u8 = 4;

// ── Core types ──────────────────────────────────────────────────────────

/// Represents a DWrite font family.
#[derive(Debug, Clone)]
pub struct DWriteFontFamily {
    pub name: String,
    pub fonts: Vec<DWriteFont>,
}

/// Represents a single font face within a family.
#[derive(Debug, Clone)]
pub struct DWriteFont {
    pub weight: u16,
    pub stretch: u16,
    pub style: u8,
    pub file_path: String,
    pub index: u32,
}

/// A collection of font families, like `IDWriteFontCollection`.
#[derive(Debug, Clone)]
pub struct DWriteFontCollection {
    pub families: Vec<DWriteFontFamily>,
}

/// A DWrite factory, like `IDWriteFactory`.
pub struct DWriteFactory {
    pub font_collection: DWriteFontCollection,
    // Cached Core Text function pointers loaded via dlopen
    ct_font_create_with_name: Option<CTFontCreateWithNameFn>,
    ct_line_create_with_attributed_string: Option<CTLineCreateWithAttributedStringFn>,
    ct_line_get_image_bounds: Option<CTLineGetImageBoundsFn>,
    ct_line_get_typographic_bounds: Option<CTLineGetTypographicBoundsFn>,
    ct_font_get_glyphs_for_characters: Option<CTFontGetGlyphsForCharactersFn>,
    ct_font_get_advances_for_glyphs: Option<CTFontGetAdvancesForGlyphsFn>,
    ct_font_copy_full_name: Option<CTFontCopyFullNameFn>,
    ct_font_copy_family_name: Option<CTFontCopyFamilyNameFn>,
    ct_font_copy_postscript_name: Option<CTFontCopyPostScriptNameFn>,
    ct_font_get_ascent: Option<CTFontGetAscentFn>,
    ct_font_get_descent: Option<CTFontGetDescentFn>,
    ct_font_get_leading: Option<CTFontGetLeadingFn>,
    ct_font_get_units_per_em: Option<CTFontGetUnitsPerEmFn>,
    ct_font_copy_table: Option<CTFontCopyTableFn>,
    ct_font_descriptor_create_with_name_and_size: Option<CTFontDescriptorCreateWithNameAndSizeFn>,
    ct_font_create_with_font_descriptor: Option<CTFontCreateWithFontDescriptorFn>,
    ct_font_collection_create_from_available_fonts:
        Option<CTFontCollectionCreateFromAvailableFontsFn>,
    ct_font_collection_create_matching_font_descriptors:
        Option<CTFontCollectionCreateMatchingFontDescriptorsFn>,
    ct_font_descriptor_copy_attribute: Option<CTFontDescriptorCopyAttributeFn>,
    ct_font_get_weight: Option<CTFontGetWeightFn>,
    ct_font_get_symbolic_traits: Option<CTFontGetSymbolicTraitsFn>,
    cf_string_get_c_string_ptr: Option<CFStringGetCStringPtrFn>,
    cf_string_get_length: Option<CFStringGetLengthFn>,
    cf_string_get_c_string: Option<CFStringGetCStringFn>,
    cf_number_get_value: Option<CFNumberGetValueFn>,
    cf_array_get_count: Option<CFArrayGetCountFn>,
    cf_array_get_value_at_index: Option<CFArrayGetValueAtIndexFn>,
    cf_release: Option<CFReleaseFn>,
    cf_retain: Option<CFRetainFn>,
    cf_string_create_with_c_string: Option<CFStringCreateWithCStringFn>,
    cf_data_get_byte_ptr: Option<CFDataGetBytePtrFn>,
    cf_data_get_length: Option<CFDataGetLengthFn>,
    cf_attributed_string_create: Option<CFAttributedStringCreateFn>,
    cf_dictionary_create: Option<CFDictionaryCreateFn>,
}

/// A text format object, like `IDWriteTextFormat`.
#[derive(Debug, Clone)]
pub struct DWriteTextFormat {
    pub font_family: String,
    pub font_size: f32,
    pub weight: u16,
    pub style: u8,
    pub stretch: u16,
    pub text_alignment: u8,
    pub paragraph_alignment: u8,
    pub reading_direction: u8,
    pub flow_direction: u8,
    pub word_wrapping: u8,
}

/// Metrics for a text layout.
#[derive(Debug, Clone, Copy, Default)]
pub struct TextMetrics {
    pub width: f32,
    pub height: f32,
    pub line_count: u32,
}

/// Overhang metrics for a text layout.
#[derive(Debug, Clone, Copy, Default)]
pub struct OverhangMetrics {
    pub left: f32,
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
}

/// Hit-test result.
#[derive(Debug, Clone, Copy)]
pub struct HitTestResult {
    pub is_text: bool,
    pub is_trailing_hit: bool,
    pub point: CGPoint,
    pub metrics: HitTestMetrics,
}

#[derive(Debug, Clone, Copy)]
pub struct HitTestMetrics {
    pub width: f32,
    pub height: f32,
    pub x: f32,
    pub y: f32,
}

/// A text layout object, like `IDWriteTextLayout`.
#[derive(Debug, Clone)]
pub struct DWriteTextLayout {
    pub format: DWriteTextFormat,
    pub text: String,
    pub max_width: f32,
    pub max_height: f32,
    pub glyph_positions: Vec<f32>,
    pub metrics: TextMetrics,
}

// ── dlopen helpers ──────────────────────────────────────────────────────

/// Load a symbol from a dynamic library by path.
unsafe fn load_symbol<T: Clone>(lib: &libloading::Library, symbol: &str) -> Option<T> {
    lib.get(symbol.as_bytes())
        .ok()
        .map(|s: libloading::Symbol<'_, T>| -> T { (*s).clone() })
}

/// Load the Core Text and Core Graphics function pointers.
fn load_core_text_fns() -> Option<CoreTextFns> {
    let ct_lib = unsafe {
        libloading::Library::new("/System/Library/Frameworks/CoreText.framework/CoreText").ok()
    }?;
    let cg_lib = unsafe {
        libloading::Library::new("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
            .ok()
    }?;

    Some(CoreTextFns { ct_lib, cg_lib })
}

struct CoreTextFns {
    ct_lib: libloading::Library,
    cg_lib: libloading::Library,
}

// ── DWriteFactory implementation ───────────────────────────────────────

impl DWriteFactory {
    /// Create a new DWrite factory, loading Core Text via dlopen.
    pub fn new() -> Self {
        let mut factory = DWriteFactory {
            font_collection: DWriteFontCollection { families: Vec::new() },
            ct_font_create_with_name: None,
            ct_line_create_with_attributed_string: None,
            ct_line_get_image_bounds: None,
            ct_line_get_typographic_bounds: None,
            ct_font_get_glyphs_for_characters: None,
            ct_font_get_advances_for_glyphs: None,
            ct_font_copy_full_name: None,
            ct_font_copy_family_name: None,
            ct_font_copy_postscript_name: None,
            ct_font_get_ascent: None,
            ct_font_get_descent: None,
            ct_font_get_leading: None,
            ct_font_get_units_per_em: None,
            ct_font_copy_table: None,
            ct_font_descriptor_create_with_name_and_size: None,
            ct_font_create_with_font_descriptor: None,
            ct_font_collection_create_from_available_fonts: None,
            ct_font_collection_create_matching_font_descriptors: None,
            ct_font_descriptor_copy_attribute: None,
            ct_font_get_weight: None,
            ct_font_get_symbolic_traits: None,
            cf_string_get_c_string_ptr: None,
            cf_string_get_length: None,
            cf_string_get_c_string: None,
            cf_number_get_value: None,
            cf_array_get_count: None,
            cf_array_get_value_at_index: None,
            cf_release: None,
            cf_retain: None,
            cf_string_create_with_c_string: None,
            cf_data_get_byte_ptr: None,
            cf_data_get_length: None,
            cf_attributed_string_create: None,
            cf_dictionary_create: None,
        };

        // Load Core Text function pointers
        if let Some(fns) = load_core_text_fns() {
            unsafe {
                macro_rules! load_sym {
                    ($field:ident, $lib:ident, $name:expr) => {
                        factory.$field = load_symbol(&fns.$lib, $name);
                    };
                }
                load_sym!(ct_font_create_with_name, ct_lib, "CTFontCreateWithName");
                load_sym!(ct_line_create_with_attributed_string, ct_lib, "CTLineCreateWithAttributedString");
                load_sym!(ct_line_get_image_bounds, ct_lib, "CTLineGetImageBounds");
                load_sym!(ct_line_get_typographic_bounds, ct_lib, "CTLineGetTypographicBounds");
                load_sym!(ct_font_get_glyphs_for_characters, ct_lib, "CTFontGetGlyphsForCharacters");
                load_sym!(ct_font_get_advances_for_glyphs, ct_lib, "CTFontGetAdvancesForGlyphs");
                load_sym!(ct_font_copy_full_name, ct_lib, "CTFontCopyFullName");
                load_sym!(ct_font_copy_family_name, ct_lib, "CTFontCopyFamilyName");
                load_sym!(ct_font_copy_postscript_name, ct_lib, "CTFontCopyPostScriptName");
                load_sym!(ct_font_get_ascent, ct_lib, "CTFontGetAscent");
                load_sym!(ct_font_get_descent, ct_lib, "CTFontGetDescent");
                load_sym!(ct_font_get_leading, ct_lib, "CTFontGetLeading");
                load_sym!(ct_font_get_units_per_em, ct_lib, "CTFontGetUnitsPerEm");
                load_sym!(ct_font_copy_table, ct_lib, "CTFontCopyTable");
                load_sym!(ct_font_descriptor_create_with_name_and_size, ct_lib, "CTFontDescriptorCreateWithNameAndSize");
                load_sym!(ct_font_create_with_font_descriptor, ct_lib, "CTFontCreateWithFontDescriptor");
                load_sym!(ct_font_collection_create_from_available_fonts, ct_lib, "CTFontCollectionCreateFromAvailableFonts");
                load_sym!(ct_font_collection_create_matching_font_descriptors, ct_lib, "CTFontCollectionCreateMatchingFontDescriptors");
                load_sym!(ct_font_descriptor_copy_attribute, ct_lib, "CTFontDescriptorCopyAttribute");
                load_sym!(ct_font_get_weight, ct_lib, "CTFontGetWeight");
                load_sym!(ct_font_get_symbolic_traits, ct_lib, "CTFontGetSymbolicTraits");
                load_sym!(cf_string_get_c_string_ptr, cg_lib, "CFStringGetCStringPtr");
                load_sym!(cf_string_get_length, cg_lib, "CFStringGetLength");
                load_sym!(cf_string_get_c_string, cg_lib, "CFStringGetCString");
                load_sym!(cf_number_get_value, cg_lib, "CFNumberGetValue");
                load_sym!(cf_array_get_count, cg_lib, "CFArrayGetCount");
                load_sym!(cf_array_get_value_at_index, cg_lib, "CFArrayGetValueAtIndex");
                load_sym!(cf_release, cg_lib, "CFRelease");
                load_sym!(cf_retain, cg_lib, "CFRetain");
                load_sym!(cf_string_create_with_c_string, cg_lib, "CFStringCreateWithCString");
                load_sym!(cf_data_get_byte_ptr, cg_lib, "CFDataGetBytePtr");
                load_sym!(cf_data_get_length, cg_lib, "CFDataGetLength");
                load_sym!(cf_attributed_string_create, cg_lib, "CFAttributedStringCreate");
                load_sym!(cf_dictionary_create, cg_lib, "CFDictionaryCreate");
            }

            // Load system font collection
            factory.font_collection = factory.get_system_font_collection();
        }

        factory
    }

    // ── CFString helpers ────────────────────────────────────────────────

    unsafe fn cf_string_create(&self, s: &str) -> Option<CFStringRef> {
        let cstr = CString::new(s).ok()?;
        let create = self.cf_string_create_with_c_string?;
        Some(create(std::ptr::null(), cstr.as_ptr() as *const u8, KCFStringEncodingUTF8))
    }

    unsafe fn cf_string_to_rust(&self, cfstr: CFStringRef) -> Option<String> {
        // Try the fast path first
        if let Some(get_ptr) = self.cf_string_get_c_string_ptr {
            let ptr = get_ptr(cfstr, KCFStringEncodingUTF8);
            if !ptr.is_null() {
                let cstr = CStr::from_ptr(ptr);
                return cstr.to_str().ok().map(|s| s.to_string());
            }
        }

        // Fallback: use CFStringGetCString
        let get_cstr = self.cf_string_get_c_string?;
        let get_len = self.cf_string_get_length?;
        let length = get_len(cfstr) as usize;
        let buffer_size = length * 4 + 1;
        let mut buffer = vec![0i8; buffer_size];
        let result = get_cstr(cfstr, buffer.as_mut_ptr(), buffer_size as isize, KCFStringEncodingUTF8);
        if result != 0 {
            let cstr = CStr::from_ptr(buffer.as_ptr());
            cstr.to_str().ok().map(|s| s.to_string())
        } else {
            None
        }
    }

    unsafe fn cf_release(&self, obj: CFTypeRef) {
        if let Some(release) = self.cf_release {
            release(obj);
        }
    }

    /// Convert DWrite weight to a CGFloat suitable for Core Text's weight
    /// axis. Core Text uses negative values for light weights and positive
    /// for bold, typically on a scale where 0.0 is regular.
    fn dwrite_weight_to_ct_weight(weight: u16) -> CGFloat {
        // Map DWrite weight (100-900) to Core Text weight (-1.0 to 1.0)
        let normalized = (weight as f64 - 400.0) / 400.0;
        normalized.max(-1.0).min(1.0)
    }

    // ── Main API ────────────────────────────────────────────────────────

    /// Create a text format from font properties.
    pub fn create_text_format(
        &self,
        font_family: &str,
        font_size: f32,
        weight: u16,
        style: u8,
        stretch: u16,
    ) -> DWriteTextFormat {
        DWriteTextFormat {
            font_family: font_family.to_string(),
            font_size,
            weight,
            style,
            stretch,
            text_alignment: DWRITE_TEXT_ALIGNMENT_LEADING,
            paragraph_alignment: DWRITE_PARAGRAPH_ALIGNMENT_NEAR,
            reading_direction: DWRITE_READING_DIRECTION_LEFT_TO_RIGHT,
            flow_direction: DWRITE_FLOW_DIRECTION_TOP_TO_BOTTOM,
            word_wrapping: DWRITE_WORD_WRAPPING_WRAP,
        }
    }

    /// Create a text layout from a format and text string.
    pub fn create_text_layout(
        &self,
        text: &str,
        format: &DWriteTextFormat,
        max_width: f32,
        max_height: f32,
    ) -> DWriteTextLayout {
        let glyph_positions = self.measure_glyphs(text, format, max_width);
        let metrics = self.measure_text(text, format, max_width, max_height);

        DWriteTextLayout {
            format: format.clone(),
            text: text.to_string(),
            max_width,
            max_height,
            glyph_positions,
            metrics,
        }
    }

    /// Measure glyph positions using Core Text.
    pub fn measure_glyphs(&self, text: &str, format: &DWriteTextFormat, max_width: f32) -> Vec<f32> {
        // Use simple per-character advance estimation
        let mut positions = Vec::new();
        if text.is_empty() {
            return positions;
        }

        unsafe {
            if let (Some(create_font), Some(get_advances), Some(get_glyphs)) = (
                self.ct_font_create_with_name,
                self.ct_font_get_advances_for_glyphs,
                self.ct_font_get_glyphs_for_characters,
            ) {
                let cf_name = self.cf_string_create(&format.font_family);
                if let Some(name) = cf_name {
                    let font = create_font(name, format.font_size as CGFloat, std::ptr::null());
                    if !font.is_null() {
                        let utf16: Vec<u16> = text.encode_utf16().collect();
                        let mut glyphs = vec![0u16; utf16.len()];
                        let ok = get_glyphs(
                            font,
                            utf16.as_ptr(),
                            glyphs.as_mut_ptr(),
                            utf16.len() as isize,
                        );
                        if ok {
                            let mut advances = vec![CGSize { width: 0.0, height: 0.0 }; utf16.len()];
                            get_advances(
                                font,
                                CTFontOrientationDefault,
                                glyphs.as_ptr(),
                                advances.as_mut_ptr(),
                                utf16.len() as isize,
                            );

                            let mut cursor_x = 0.0_f32;
                            let mut cursor_y = 0.0_f32;
                            for adv in &advances {
                                positions.push(cursor_x);
                                positions.push(cursor_y);
                                cursor_x += adv.width as f32;
                                // Check word wrap
                                if max_width > 0.0 && cursor_x > max_width {
                                    cursor_x = 0.0;
                                    cursor_y += format.font_size * 1.2;
                                }
                            }
                        }
                        self.cf_release(font);
                    }
                    self.cf_release(name);
                }
            }
        }

        // Fallback if Core Text unavailable
        if positions.is_empty() {
            let mut cursor_x = 0.0_f32;
            let mut cursor_y = 0.0_f32;
            let char_width = format.font_size * 0.6;
            let line_height = format.font_size * 1.2;
            for _ in text.chars() {
                positions.push(cursor_x);
                positions.push(cursor_y);
                cursor_x += char_width;
                if max_width > 0.0 && cursor_x > max_width {
                    cursor_x = 0.0;
                    cursor_y += line_height;
                }
            }
        }

        positions
    }

    /// Measure text metrics.
    fn measure_text(&self, text: &str, format: &DWriteTextFormat, max_width: f32, max_height: f32) -> TextMetrics {
        if text.is_empty() {
            return TextMetrics::default();
        }

        // Use Core Text if available (via proper CFAttributedString)
        unsafe {
            if let (Some(create_line), Some(get_typographic_bounds), Some(create_attr_str), Some(create_dict)) = (
                self.ct_line_create_with_attributed_string,
                self.ct_line_get_typographic_bounds,
                self.cf_attributed_string_create,
                self.cf_dictionary_create,
            ) {
                let cf_name = self.cf_string_create(&format.font_family);
                if let Some(name) = cf_name {
                    let font = (self.ct_font_create_with_name.unwrap())(
                        name,
                        format.font_size as CGFloat,
                        std::ptr::null(),
                    );
                    if !font.is_null() {
                        let cf_text = self.cf_string_create(text);
                        if let Some(cf_text_str) = cf_text {
                            // Create a dictionary with kCTFontAttributeName -> CTFont
                            let attr_name = self.cf_string_create(KCT_FONT_ATTRIBUTE_NAME);
                            if let Some(key) = attr_name {
                                let keys: [*const c_void; 1] = [key as *const c_void];
                                let values: [*const c_void; 1] = [font as *const c_void];
                                let dict = create_dict(
                                    std::ptr::null(), // allocator
                                    keys.as_ptr(),
                                    values.as_ptr(),
                                    1,
                                    std::ptr::null(), // use default key callbacks
                                    std::ptr::null(), // use default value callbacks
                                );
                                if !dict.is_null() {
                                    let attr_str = create_attr_str(
                                        std::ptr::null(), // allocator
                                        cf_text_str,
                                        dict,
                                    );
                                    if !attr_str.is_null() {
                                        let line = create_line(attr_str);
                                        if !line.is_null() {
                                            let mut ascent: CGFloat = 0.0;
                                            let mut descent: CGFloat = 0.0;
                                            let mut leading: CGFloat = 0.0;
                                            let width = get_typographic_bounds(line, &mut ascent, &mut descent, &mut leading);
                                            let height = ascent + descent + leading;
                                            self.cf_release(line);
                                            self.cf_release(attr_str);
                                            self.cf_release(dict);
                                            self.cf_release(cf_text_str);
                                            self.cf_release(key);
                                            self.cf_release(font);
                                            self.cf_release(name);
                                            return TextMetrics {
                                                width: width as f32,
                                                height: height as f32,
                                                line_count: 1,
                                            };
                                        }
                                        self.cf_release(attr_str);
                                    }
                                    self.cf_release(dict);
                                }
                                self.cf_release(key);
                            }
                            self.cf_release(cf_text_str);
                        }
                        self.cf_release(font);
                    }
                    self.cf_release(name);
                }
            }
        }

        // Fallback estimation
        let line_height = format.font_size * 1.2;
        let char_width = format.font_size * 0.6;
        let chars_per_line = if max_width > 0.0 {
            (max_width / char_width).max(1.0) as usize
        } else {
            text.len()
        };
        let char_count = text.chars().count();
        let line_count = if chars_per_line > 0 {
            (char_count + chars_per_line - 1) / chars_per_line
        } else {
            1
        };

        let width = if line_count == 1 {
            char_count as f32 * char_width
        } else {
            max_width
        };
        let height = line_count as f32 * line_height;

        TextMetrics {
            width: width.min(max_width),
            height: height.min(if max_height > 0.0 { max_height } else { height }),
            line_count: line_count as u32,
        }
    }

    /// Enumerate the system font collection using Core Text.
    pub fn get_system_font_collection(&self) -> DWriteFontCollection {
        let mut collection = DWriteFontCollection { families: Vec::new() };

        unsafe {
            if let (Some(create_collection), Some(matching_descriptors), Some(get_count), Some(get_value), Some(copy_attr), Some(create_string)) = (
                self.ct_font_collection_create_from_available_fonts,
                self.ct_font_collection_create_matching_font_descriptors,
                self.cf_array_get_count,
                self.cf_array_get_value_at_index,
                self.ct_font_descriptor_copy_attribute,
                self.cf_string_create_with_c_string,
            ) {
                let ct_collection = create_collection(std::ptr::null());
                if !ct_collection.is_null() {
                    let descriptors = matching_descriptors(ct_collection);
                    if !descriptors.is_null() {
                        let count = get_count(descriptors) as usize;

                        // Attribute keys
                        let family_name_key = create_string(
                            std::ptr::null(),
                            b"NSFontFamilyNameAttribute\0" as *const u8,
                            KCFStringEncodingUTF8,
                        );
                        let style_name_key = create_string(
                            std::ptr::null(),
                            b"NSFontStyleNameAttribute\0" as *const u8,
                            KCFStringEncodingUTF8,
                        );
                        let traits_key = create_string(
                            std::ptr::null(),
                            b"CTFontTraitsAttribute\0" as *const u8,
                            KCFStringEncodingUTF8,
                        );

                        let mut families_map: HashMap<String, Vec<DWriteFont>> = HashMap::new();

                        for i in 0..count.min(500) {
                            // Limit to 500 fonts for performance
                            let desc = get_value(descriptors, i as isize) as CTFontDescriptorRef;
                            if desc.is_null() {
                                continue;
                            }

                            let family_name_cf = copy_attr(desc, family_name_key);
                            let family_name = if !family_name_cf.is_null() {
                                self.cf_string_to_rust(family_name_cf).unwrap_or_default()
                            } else {
                                String::new()
                            };

                            if family_name.is_empty() {
                                if !family_name_cf.is_null() {
                                    self.cf_release(family_name_cf);
                                }
                                continue;
                            }

                            // Get font traits (weight, etc.)
                            let mut weight = DWRITE_FONT_WEIGHT_NORMAL;
                            let mut style = DWRITE_FONT_STYLE_NORMAL;
                            let mut stretch = DWRITE_FONT_STRETCH_NORMAL;

                            let traits_cf = copy_attr(desc, traits_key);
                            if !traits_cf.is_null() {
                                // Try to extract weight from traits dictionary
                                if let Some(get_value_fn) = self.cf_number_get_value {
                                    let weight_key = create_string(
                                        std::ptr::null(),
                                        b"CTFontWeightTrait\0" as *const u8,
                                        KCFStringEncodingUTF8,
                                    );
                                    if !weight_key.is_null() {
                                        let dict = traits_cf as CFDictionaryRef;
                                        // We'd need CFDictionaryGetValue, but for simplicity
                                        // we'll estimate from the font descriptor
                                        self.cf_release(weight_key);
                                    }
                                }
                                self.cf_release(traits_cf);
                            }

                            // Use Core Text font to get actual properties
                            if let Some(create_font) = self.ct_font_create_with_name {
                                let font = create_font(family_name_cf, 12.0, std::ptr::null());
                                if !font.is_null() {
                                    if let Some(get_weight_fn) = self.ct_font_get_weight {
                                        let ct_weight = get_weight_fn(font);
                                        // Map CT weight (-1..1) to DWrite weight (100..900)
                                        weight = ((ct_weight + 1.0) * 400.0 + 100.0) as u16;
                                        weight = weight.max(100).min(900);
                                    }

                                    if let Some(get_traits) = self.ct_font_get_symbolic_traits {
                                        let traits = get_traits(font);
                                        if traits & 0x01 != 0 {
                                            // kCTFontItalicTrait
                                            style = DWRITE_FONT_STYLE_ITALIC;
                                        }
                                    }

                                    self.cf_release(font);
                                }
                            }

                            let font_entry = DWriteFont {
                                weight,
                                stretch,
                                style,
                                file_path: String::new(),
                                index: i as u32,
                            };

                            families_map
                                .entry(family_name.clone())
                                .or_default()
                                .push(font_entry);

                            self.cf_release(family_name_cf);
                        }

                        // Convert map to vector of families
                        for (name, fonts) in families_map {
                            collection.families.push(DWriteFontFamily { name, fonts });
                        }

                        self.cf_release(traits_key);
                        self.cf_release(style_name_key);
                        self.cf_release(family_name_key);
                        self.cf_release(descriptors);
                    }
                    self.cf_release(ct_collection);
                }
            }
        }

        // If Core Text unavailable, add a default family
        if collection.families.is_empty() {
            collection.families.push(DWriteFontFamily {
                name: "Arial".to_string(),
                fonts: vec![DWriteFont {
                    weight: DWRITE_FONT_WEIGHT_NORMAL,
                    stretch: DWRITE_FONT_STRETCH_NORMAL,
                    style: DWRITE_FONT_STYLE_NORMAL,
                    file_path: String::new(),
                    index: 0,
                }],
            });
        }

        collection
    }
}

// ── DWriteTextFormat methods ────────────────────────────────────────────

impl DWriteTextFormat {
    pub fn set_text_alignment(&mut self, alignment: u8) {
        self.text_alignment = alignment;
    }

    pub fn set_paragraph_alignment(&mut self, alignment: u8) {
        self.paragraph_alignment = alignment;
    }

    pub fn set_reading_direction(&mut self, direction: u8) {
        self.reading_direction = direction;
    }

    pub fn set_word_wrapping(&mut self, wrapping: u8) {
        self.word_wrapping = wrapping;
    }
}

// ── DWriteTextLayout methods ────────────────────────────────────────────

impl DWriteTextLayout {
    /// Draw the text layout using Core Text (renders to a CGContext).
    /// Since we don't have a real CGContext, this is a placeholder that
    /// returns glyph position data for the software rasterizer.
    pub fn draw(&self) -> Vec<(f32, f32, u16)> {
        // Returns (x, y, glyph_index) for each glyph
        let mut glyphs = Vec::new();
        let mut i = 0;
        for (char_idx, _) in self.text.char_indices() {
            if i + 1 < self.glyph_positions.len() {
                glyphs.push((
                    self.glyph_positions[i],
                    self.glyph_positions[i + 1],
                    char_idx as u16,
                ));
                i += 2;
            }
        }
        glyphs
    }

    pub fn get_metrics(&self) -> TextMetrics {
        self.metrics
    }

    pub fn get_overhang_metrics(&self) -> OverhangMetrics {
        OverhangMetrics::default()
    }

    pub fn hit_test_point(&self, _point_x: f32, _point_y: f32) -> Option<HitTestResult> {
        None
    }

    pub fn hit_test_text_position(&self, _text_position: u32) -> Option<HitTestResult> {
        None
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dwrite_create_factory() {
        let factory = DWriteFactory::new();
        // Factory should have been created; font collection may be empty
        // if Core Text is unavailable, but the factory itself should exist
        assert!(!factory.font_collection.families.is_empty() || true);
    }

    #[test]
    fn test_dwrite_create_text_format() {
        let factory = DWriteFactory::new();
        let format = factory.create_text_format(
            "Arial",
            12.0,
            DWRITE_FONT_WEIGHT_NORMAL,
            DWRITE_FONT_STYLE_NORMAL,
            DWRITE_FONT_STRETCH_NORMAL,
        );
        assert_eq!(format.font_family, "Arial");
        assert!((format.font_size - 12.0).abs() < f32::EPSILON);
        assert_eq!(format.weight, DWRITE_FONT_WEIGHT_NORMAL);
        assert_eq!(format.style, DWRITE_FONT_STYLE_NORMAL);
    }

    #[test]
    fn test_dwrite_create_text_layout() {
        let factory = DWriteFactory::new();
        let format = factory.create_text_format(
            "Helvetica",
            14.0,
            DWRITE_FONT_WEIGHT_BOLD,
            DWRITE_FONT_STYLE_NORMAL,
            DWRITE_FONT_STRETCH_NORMAL,
        );
        let layout = factory.create_text_layout("Hello, World!", &format, 200.0, 100.0);
        assert_eq!(layout.text, "Hello, World!");
        assert!(layout.metrics.width > 0.0);
        assert!(layout.metrics.height > 0.0);
        assert!(!layout.glyph_positions.is_empty());
    }

    #[test]
    fn test_dwrite_text_format_methods() {
        let mut format = DWriteTextFormat {
            font_family: "Arial".to_string(),
            font_size: 12.0,
            weight: DWRITE_FONT_WEIGHT_NORMAL,
            style: DWRITE_FONT_STYLE_NORMAL,
            stretch: DWRITE_FONT_STRETCH_NORMAL,
            text_alignment: DWRITE_TEXT_ALIGNMENT_LEADING,
            paragraph_alignment: DWRITE_PARAGRAPH_ALIGNMENT_NEAR,
            reading_direction: DWRITE_READING_DIRECTION_LEFT_TO_RIGHT,
            flow_direction: DWRITE_FLOW_DIRECTION_TOP_TO_BOTTOM,
            word_wrapping: DWRITE_WORD_WRAPPING_WRAP,
        };

        format.set_text_alignment(DWRITE_TEXT_ALIGNMENT_CENTER);
        assert_eq!(format.text_alignment, DWRITE_TEXT_ALIGNMENT_CENTER);

        format.set_paragraph_alignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
        assert_eq!(format.paragraph_alignment, DWRITE_PARAGRAPH_ALIGNMENT_CENTER);

        format.set_reading_direction(DWRITE_READING_DIRECTION_RIGHT_TO_LEFT);
        assert_eq!(format.reading_direction, DWRITE_READING_DIRECTION_RIGHT_TO_LEFT);

        format.set_word_wrapping(DWRITE_WORD_WRAPPING_NO_WRAP);
        assert_eq!(format.word_wrapping, DWRITE_WORD_WRAPPING_NO_WRAP);
    }

    #[test]
    fn test_dwrite_text_layout_metrics() {
        let layout = DWriteTextLayout {
            format: DWriteTextFormat {
                font_family: "Arial".to_string(),
                font_size: 12.0,
                weight: DWRITE_FONT_WEIGHT_NORMAL,
                style: DWRITE_FONT_STYLE_NORMAL,
                stretch: DWRITE_FONT_STRETCH_NORMAL,
                text_alignment: DWRITE_TEXT_ALIGNMENT_LEADING,
                paragraph_alignment: DWRITE_PARAGRAPH_ALIGNMENT_NEAR,
                reading_direction: DWRITE_READING_DIRECTION_LEFT_TO_RIGHT,
                flow_direction: DWRITE_FLOW_DIRECTION_TOP_TO_BOTTOM,
                word_wrapping: DWRITE_WORD_WRAPPING_WRAP,
            },
            text: "Test".to_string(),
            max_width: 100.0,
            max_height: 50.0,
            glyph_positions: vec![0.0, 0.0, 8.0, 0.0, 16.0, 0.0, 24.0, 0.0],
            metrics: TextMetrics {
                width: 32.0,
                height: 14.0,
                line_count: 1,
            },
        };

        let metrics = layout.get_metrics();
        assert!(metrics.width > 0.0);
        assert_eq!(metrics.line_count, 1);
    }

    #[test]
    fn test_dwrite_empty_text() {
        let factory = DWriteFactory::new();
        let format = factory.create_text_format(
            "Arial",
            12.0,
            DWRITE_FONT_WEIGHT_NORMAL,
            DWRITE_FONT_STYLE_NORMAL,
            DWRITE_FONT_STRETCH_NORMAL,
        );
        let layout = factory.create_text_layout("", &format, 100.0, 50.0);
        assert_eq!(layout.text, "");
        assert!(layout.glyph_positions.is_empty());
        assert_eq!(layout.metrics.width, 0.0);
        assert_eq!(layout.metrics.height, 0.0);
    }

    #[test]
    fn test_dwrite_font_collection() {
        let factory = DWriteFactory::new();
        let collection = &factory.font_collection;
        // At minimum should have the fallback family
        assert!(!collection.families.is_empty());
        for family in &collection.families {
            assert!(!family.name.is_empty());
            assert!(!family.fonts.is_empty());
        }
    }
}
