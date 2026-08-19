//! PE Icon Extraction and ICO → ICNS Conversion for Casa1.
//!
//! This module provides:
//! - `extract_icon_from_pe()` — Extract the largest icon resource from a PE file
//! - `extract_all_icons_from_pe()` — Extract all icon resolutions from a PE file
//! - `ico_to_icns()` — Convert ICO data to macOS `.icns` format
//! - `ico_to_png()` — Convert individual icon entries to PNG bytes
//!
//! ## ICNS Format
//! The `.icns` container bundles one or more PNG-encoded icon representations.
//! Standard icon types:
//! | OSType | Size     | Scale |
//! |--------|----------|-------|
//! | ic07   | 128×128  | 1x    |
//! | ic08   | 256×256  | 1x    |
//! | ic09   | 512×512  | 1x    |
//! | ic10   | 512×512  | 2x    |
//! | ic11   | 16×16    | 1x    |
//! | ic12   | 32×32    | 1x    |
//! | ic13   | 128×128  | 2x    |
//! | ic14   | 256×256  | 2x    |

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::path::Path;

/// Directory header for an ICO file.
#[derive(Debug, Clone)]
pub struct IcoDir {
    pub reserved: u16,
    pub icon_type: u16, // 1 = ICO, 2 = CUR
    pub count: u16,
}

/// Entry in the ICO directory.
#[derive(Debug, Clone)]
pub struct IcoDirEntry {
    pub width: u8,       // 0 means 256
    pub height: u8,      // 0 means 256
    pub color_count: u8, // 0 means >= 256 colors
    pub reserved: u8,
    pub planes: u16, // For ICO, should be 0 or 1
    pub bpp: u16,    // Bits per pixel
    pub size: u32,
    pub offset: u32,
}

/// A decoded icon image with pixel data.
#[derive(Debug, Clone)]
pub struct IconImage {
    pub width: u32,
    pub height: u32,
    pub bpp: u16,
    pub data: Vec<u8>, // Raw BGRA pixel data or PNG data
    pub is_png_compressed: bool,
    /// XOR mask (icon transparency) — 1 bit per pixel, row-padded to 32 bits
    pub xor_mask: Option<Vec<u8>>,
}

/// Icon type OSType for ICNS entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IcnsType {
    Ic07, // 128x128 1x
    Ic08, // 256x256 1x
    Ic09, // 512x512 1x
    Ic10, // 512x512@2x (1024x1024)
    Ic11, // 16x16 1x
    Ic12, // 32x32 1x
    #[allow(dead_code)] // legacy ICNS type tags (ABI completeness)
    Ic13, // 128x128 2x (256x256)
    #[allow(dead_code)] // legacy ICNS type tags (ABI completeness)
    Ic14, // 256x256 2x (512x512)
    #[allow(dead_code)] // legacy ICNS type tags (ABI completeness)
    Ic04, // 16x16 1x (old format)
    #[allow(dead_code)] // legacy ICNS type tags (ABI completeness)
    Ic05, // 32x32 1x (old format)
}

impl IcnsType {
    fn ostype(&self) -> [u8; 4] {
        match self {
            Self::Ic07 => *b"ic07",
            Self::Ic08 => *b"ic08",
            Self::Ic09 => *b"ic09",
            Self::Ic10 => *b"ic10",
            Self::Ic11 => *b"ic11",
            Self::Ic12 => *b"ic12",
            Self::Ic13 => *b"ic13",
            Self::Ic14 => *b"ic14",
            Self::Ic04 => *b"ic04",
            Self::Ic05 => *b"ic05",
        }
    }

    #[allow(dead_code)] // ICNS type dimensions helper; not yet referenced
    fn dimensions(&self) -> (u32, u32) {
        match self {
            Self::Ic07 => (128, 128),
            Self::Ic08 => (256, 256),
            Self::Ic09 => (512, 512),
            Self::Ic10 => (1024, 1024),
            Self::Ic11 => (16, 16),
            Self::Ic12 => (32, 32),
            Self::Ic13 => (256, 256),
            Self::Ic14 => (512, 512),
            Self::Ic04 => (16, 16),
            Self::Ic05 => (32, 32),
        }
    }
}

/// Extract the largest icon from a PE file at the given path.
/// Returns `None` if the PE file has no icon resources.
///
/// Delegates to [`crate::pe::extract_icon_from_pe`] for the actual PE parsing.
pub fn extract_icon_from_pe(path: &Path) -> AppResult<Option<IconImage>> {
    let bytes = std::fs::read(path).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read PE file: {}", path.display()),
            &e,
        )
    })?;
    let icons = crate::pe::extract_icon_from_pe(&bytes)?;
    // pe::extract_icon_from_pe already returns the largest icon in a Vec,
    // so take the first element if present.
    Ok(icons.into_iter().next())
}

/// Extract all icons from a PE file at the given path.
///
/// Delegates to [`crate::pe::extract_all_icons_from_pe`] for the actual PE parsing.
pub fn extract_all_icons_from_pe(path: &Path) -> AppResult<Vec<IconImage>> {
    let bytes = std::fs::read(path).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read PE file: {}", path.display()),
            &e,
        )
    })?;
    crate::pe::extract_all_icons_from_pe(&bytes)
}

/// Maximum dimension (in pixels) accepted for an icon image.
const MAX_ICON_DIM: usize = 4096;

/// Parsed BITMAPINFOHEADER for a DIB icon payload.
struct DibHeader {
    /// Logical image width in pixels.
    width: u32,
    /// Doubled height (XOR mask + AND mask rows).
    doubled_height: u32,
    /// Bits per pixel from the header.
    bpp: u16,
    /// Number of palette entries (biClrUsed).
    clr_used: u32,
    /// Size of the header in bytes (the palette follows it).
    header_size: usize,
}

/// Parse the BITMAPINFOHEADER that prefixes raw (non-PNG) ICO entries and
/// PE `RT_ICON` payloads. Returns `None` when the payload is headerless
/// or malformed.
fn parse_dib_header(data: &[u8]) -> Option<DibHeader> {
    if data.len() < 40 {
        return None;
    }
    let bi_size = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if bi_size < 40 || bi_size as usize > data.len() {
        return None;
    }
    let width = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let doubled_height = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if width <= 0 || doubled_height <= 0 {
        return None;
    }
    let bpp = u16::from_le_bytes([data[14], data[15]]);
    let clr_used = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    Some(DibHeader {
        width: width as u32,
        doubled_height: doubled_height as u32,
        bpp,
        clr_used,
        header_size: bi_size as usize,
    })
}

/// Convert raw BMP/DIB icon pixel data to PNG bytes.
///
/// The icon data is a Windows DIB (BGRA bottom-up) payload, normally
/// prefixed by a 40-byte BITMAPINFOHEADER whose `biHeight` doubles the
/// logical icon height (XOR mask + AND mask). When the header is present
/// its values are authoritative and the height is halved exactly once;
/// `width`/`height`/`bpp` are fallbacks for headerless payloads, where
/// `height` is the doubled DIB height.
pub fn dib_to_png(data: &[u8], width: u32, height: u32, bpp: u16) -> AppResult<Vec<u8>> {
    let header = parse_dib_header(data);
    let (pixel_width, pixel_height, bpp) = match header.as_ref() {
        Some(h) => (
            h.width,
            h.doubled_height / 2,
            if h.bpp != 0 { h.bpp } else { bpp },
        ),
        None => (width, height / 2, bpp),
    };
    let pixel_width = pixel_width as usize;
    let pixel_height = pixel_height as usize;
    if pixel_width == 0
        || pixel_height == 0
        || pixel_width > MAX_ICON_DIM
        || pixel_height > MAX_ICON_DIM
    {
        return Err(AppError::new(
            ReasonCode::RcPeParseInvalid,
            format!("unreasonable DIB icon dimensions {pixel_width}x{pixel_height}"),
        ));
    }

    let bytes_per_pixel = match bpp {
        32 => 4,
        24 => 3,
        8 | 4 | 1 => 1,
        _ => {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!("unsupported DIB icon bit depth {bpp}"),
            ));
        }
    };
    let row_size = (pixel_width * bpp as usize).div_ceil(32) * 4;
    let rgba_bytes = pixel_width
        .checked_mul(pixel_height)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| {
            AppError::new(ReasonCode::RcPeParseInvalid, "DIB icon dimensions overflow")
        })?;
    let mut rgba = vec![0u8; rgba_bytes];

    let header_size = header.as_ref().map_or(0, |h| h.header_size);
    let palette_count = if bpp <= 8 {
        let clr_used = header.as_ref().map_or(0, |h| h.clr_used);
        if clr_used != 0 {
            clr_used as usize
        } else {
            1usize << bpp
        }
    } else {
        0
    };
    let palette_offset = header_size;
    // The XOR bitmap follows the header and the color table.
    let pixels_offset = palette_offset + palette_count * 4;

    for y in 0..pixel_height {
        let src_row = (pixel_height - 1 - y) * row_size + pixels_offset;
        for x in 0..pixel_width {
            let dst_pixel = (y * pixel_width + x) * 4;
            let pixel = if bytes_per_pixel == 4 {
                let src_pixel = src_row + x * 4;
                if src_pixel + 4 > data.len() {
                    continue;
                }
                // DIB is BGRA
                (
                    data[src_pixel + 2],
                    data[src_pixel + 1],
                    data[src_pixel],
                    data[src_pixel + 3],
                )
            } else if bytes_per_pixel == 3 {
                let src_pixel = src_row + x * 3;
                if src_pixel + 3 > data.len() {
                    continue;
                }
                (
                    data[src_pixel + 2],
                    data[src_pixel + 1],
                    data[src_pixel],
                    255,
                )
            } else {
                // Palette-indexed: extract the index (MSB-first bit order)
                let bits = x * bpp as usize;
                let Some(&byte) = data.get(src_row + bits / 8) else {
                    continue;
                };
                let index = match bpp {
                    1 => ((byte >> (7 - bits % 8)) & 1) as usize,
                    4 => ((byte >> (4 * (1 - (bits % 8) / 4))) & 0x0F) as usize,
                    _ => byte as usize,
                };
                if index >= palette_count {
                    continue;
                }
                // Palette entries are BGRX (4 bytes each)
                let entry = palette_offset + index * 4;
                let (Some(&b), Some(&g), Some(&r)) =
                    (data.get(entry), data.get(entry + 1), data.get(entry + 2))
                else {
                    continue;
                };
                (r, g, b, 255)
            };
            rgba[dst_pixel] = pixel.0;
            rgba[dst_pixel + 1] = pixel.1;
            rgba[dst_pixel + 2] = pixel.2;
            rgba[dst_pixel + 3] = pixel.3;
        }
    }

    // Encode as PNG
    encode_png(&rgba, pixel_width as u32, pixel_height as u32)
}

/// Convert an IconImage to PNG bytes. If already PNG compressed, returns as-is.
pub fn icon_to_png(icon: &IconImage) -> AppResult<Vec<u8>> {
    if icon.is_png_compressed {
        return Ok(icon.data.clone());
    }
    dib_to_png(&icon.data, icon.width, icon.height, icon.bpp)
}

/// Simple PNG encoder for RGBA data using the `png` crate.
fn encode_png(data: &[u8], width: u32, height: u32) -> AppResult<Vec<u8>> {
    let mut png_bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png_bytes, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.set_compression(png::Compression::Default);

        let mut writer = encoder.write_header().map_err(|e| {
            AppError::new(ReasonCode::RcPeParseInvalid, "png write_header failed")
                .with_hint(e.to_string())
        })?;

        writer.write_image_data(data).map_err(|e| {
            AppError::new(ReasonCode::RcPeParseInvalid, "png write_image_data failed")
                .with_hint(e.to_string())
        })?;
    }
    Ok(png_bytes)
}

/// Convert ICO data to macOS ICNS format.
/// Takes an ICO file's bytes and produces a valid `.icns` file.
pub fn ico_to_icns(ico_data: &[u8]) -> AppResult<Vec<u8>> {
    if ico_data.len() < 6 {
        return Err(AppError::new(
            ReasonCode::RcPeParseInvalid,
            "ICO data too short",
        ));
    }
    let _reserved = u16::from_le_bytes([ico_data[0], ico_data[1]]);
    let _icon_type = u16::from_le_bytes([ico_data[2], ico_data[3]]);
    let count = u16::from_le_bytes([ico_data[4], ico_data[5]]) as usize;

    // Parse ICO directory entries
    let mut entries: Vec<(IcoDirEntry, Vec<u8>)> = Vec::new();
    for i in 0..count {
        let off = 6 + i * 16;
        if off + 16 > ico_data.len() {
            break;
        }
        let entry = IcoDirEntry {
            width: ico_data[off],
            height: ico_data[off + 1],
            color_count: ico_data[off + 2],
            reserved: ico_data[off + 3],
            planes: u16::from_le_bytes([ico_data[off + 4], ico_data[off + 5]]),
            bpp: u16::from_le_bytes([ico_data[off + 6], ico_data[off + 7]]),
            size: u32::from_le_bytes([
                ico_data[off + 8],
                ico_data[off + 9],
                ico_data[off + 10],
                ico_data[off + 11],
            ]),
            offset: u32::from_le_bytes([
                ico_data[off + 12],
                ico_data[off + 13],
                ico_data[off + 14],
                ico_data[off + 15],
            ]),
        };
        let data_start = entry.offset as usize;
        if data_start >= ico_data.len() {
            // Entry points beyond the end of the file — malformed ICO;
            // skip it rather than constructing an inverted slice.
            continue;
        }
        let data_end = data_start
            .saturating_add(entry.size as usize)
            .min(ico_data.len());
        let image_data = ico_data[data_start..data_end].to_vec();
        entries.push((entry, image_data));
    }

    // Build ICNS container
    let mut icns = Vec::new();
    icns.extend_from_slice(b"icns");
    // Placeholder for total size (4 bytes)
    let size_pos = 4;
    icns.extend_from_slice(&[0; 4]);

    for (entry, image_data) in &entries {
        let display_width = if entry.width == 0 {
            256u32
        } else {
            entry.width as u32
        };
        let display_height = if entry.height == 0 {
            256u32
        } else {
            entry.height as u32
        };

        // Determine the best ICNS icon type for this size
        let icns_type = match (display_width, display_height) {
            (16, 16) => IcnsType::Ic11,
            (32, 32) => IcnsType::Ic12,
            (128, 128) => IcnsType::Ic07,
            (256, 256) => IcnsType::Ic08,
            (512, 512) => IcnsType::Ic09,
            (1024, 1024) => IcnsType::Ic10,
            _ => {
                // For non-standard sizes, map to closest
                if display_width <= 32 {
                    IcnsType::Ic12
                } else if display_width <= 128 {
                    IcnsType::Ic07
                } else if display_width <= 256 {
                    IcnsType::Ic08
                } else {
                    IcnsType::Ic09
                }
            }
        };

        // Convert icon data to PNG for ICNS
        let is_png = image_data.len() >= 8
            && image_data[0] == 0x89
            && image_data[1] == b'P'
            && image_data[2] == b'N'
            && image_data[3] == b'G';

        let png_data = if is_png {
            image_data.clone()
        } else {
            // Convert DIB to PNG
            dib_to_png(image_data, display_width, display_height, entry.bpp)?
        };

        // Write ICNS icon entry: OSType (4 bytes) + size (4 bytes) + data
        let ostype = icns_type.ostype();
        let entry_len = 8 + png_data.len() as u32;

        icns.extend_from_slice(&ostype);
        icns.extend_from_slice(&entry_len.to_be_bytes());
        icns.extend_from_slice(&png_data);
    }

    // Write total file size
    let total_size = icns.len() as u32;
    icns[size_pos..size_pos + 4].copy_from_slice(&total_size.to_be_bytes());

    Ok(icns)
}

/// Convert a list of IconImages directly to ICNS (without intermediate ICO format).
pub fn icons_to_icns(icons: &[IconImage]) -> AppResult<Vec<u8>> {
    let mut icns = Vec::new();
    icns.extend_from_slice(b"icns");
    let size_pos = 4;
    icns.extend_from_slice(&[0; 4]);

    for icon in icons {
        let icns_type = match (icon.width, icon.height) {
            (16, 16) => IcnsType::Ic11,
            (32, 32) => IcnsType::Ic12,
            (128, 128) => IcnsType::Ic07,
            (256, 256) => IcnsType::Ic08,
            (512, 512) => IcnsType::Ic09,
            (1024, 1024) => IcnsType::Ic10,
            _ => {
                if icon.width <= 32 {
                    IcnsType::Ic12
                } else if icon.width <= 128 {
                    IcnsType::Ic07
                } else if icon.width <= 256 {
                    IcnsType::Ic08
                } else {
                    IcnsType::Ic09
                }
            }
        };

        let png_data = icon_to_png(icon)?;

        let ostype = icns_type.ostype();
        let entry_len = 8 + png_data.len() as u32;

        icns.extend_from_slice(&ostype);
        icns.extend_from_slice(&entry_len.to_be_bytes());
        icns.extend_from_slice(&png_data);
    }

    let total_size = icns.len() as u32;
    icns[size_pos..size_pos + 4].copy_from_slice(&total_size.to_be_bytes());

    Ok(icns)
}

/// Validate that a `.icns` file is well-formed.
pub fn validate_icns(data: &[u8]) -> AppResult<bool> {
    if data.len() < 8 {
        return Ok(false);
    }
    if &data[0..4] != b"icns" {
        return Ok(false);
    }
    let total_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if total_size != data.len() {
        return Ok(false);
    }
    let mut pos = 8;
    while pos + 8 <= data.len() {
        let _ostype = &data[pos..pos + 4];
        let entry_size =
            u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                as usize;
        if entry_size < 8 || pos + entry_size > data.len() {
            return Ok(false);
        }
        pos += entry_size;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_png_encoding() {
        // Create a simple 2x2 RGBA image
        let data = vec![
            255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 0, 255,
        ];
        let png = encode_png(&data, 2, 2).unwrap();
        // Check PNG signature
        assert_eq!(
            &png[0..8],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
        );
        // Check IHDR chunk present
        assert!(png.windows(4).any(|w| w == b"IHDR"));
        // Check IEND chunk exists
        assert!(png.windows(4).any(|w| w == b"IEND"));
    }

    #[test]
    fn test_ico_to_icns_minimal() {
        // This test verifies the ICNS structure is valid
        // even with an empty-ish ICO (just the header)
        let ico = vec![0, 0, 1, 0, 0, 0]; // ICO header with 0 icons
        let result = ico_to_icns(&ico);
        assert!(result.is_ok(), "ico_to_icns should succeed for minimal ICO");
        let icns = result.unwrap();
        assert!(
            validate_icns(&icns).expect("validate_icns should not error on valid ICNS"),
            "generated ICNS should be valid"
        );
        assert_eq!(&icns[0..4], b"icns");
    }

    #[test]
    fn test_icons_to_icns() {
        let icons = vec![IconImage {
            width: 16,
            height: 16,
            bpp: 32,
            data: vec![0u8; 16 * 16 * 4], // transparent black
            is_png_compressed: false,
            xor_mask: None,
        }];
        let result = icons_to_icns(&icons);
        assert!(result.is_ok(), "icons_to_icns should succeed");
        let icns = result.unwrap();
        assert!(
            validate_icns(&icns).expect("validate_icns should not error on generated ICNS"),
            "generated ICNS should be valid"
        );
    }

    #[test]
    fn test_dib_to_png() {
        // Build a 4x4 32bpp DIB (BGRA, bottom-up) with a BITMAPINFOHEADER
        // whose biHeight doubles the logical height (XOR + AND masks).
        let width = 4u32;
        let bpp = 32u16;
        let row_size = (width * bpp as u32).div_ceil(32) * 4;
        let mut dib = Vec::new();
        let mut header = [0u8; 40];
        header[0..4].copy_from_slice(&40u32.to_le_bytes()); // biSize
        header[4..8].copy_from_slice(&(width as i32).to_le_bytes()); // biWidth
        header[8..12].copy_from_slice(&8i32.to_le_bytes()); // biHeight (XOR + AND)
        header[12..14].copy_from_slice(&1u16.to_le_bytes()); // biPlanes
        header[14..16].copy_from_slice(&bpp.to_le_bytes()); // biBitCount
        dib.extend_from_slice(&header);
        // XOR rows (bottom-up), all red: 4 rows x 16 bytes
        for _ in 0..4 {
            for _ in 0..width {
                dib.extend_from_slice(&[0, 0, 255, 255]); // B G R A
            }
        }
        // AND mask rows (opaque)
        dib.extend_from_slice(&vec![0u8; (4 * row_size) as usize]);

        let png = dib_to_png(&dib, 4, 4, 32).unwrap();
        assert_eq!(png[0..8], [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

        // The PNG must be 4x4 (logical height), not 4x2 (double-halved).
        let decoder = png::Decoder::new(std::io::Cursor::new(&png));
        let mut reader = decoder.read_info().unwrap();
        let mut out = vec![0u8; reader.output_buffer_size()];
        let info = reader.next_frame(&mut out).unwrap();
        assert_eq!(info.width, 4);
        assert_eq!(info.height, 4);
        let rgba = &out[..info.buffer_size()];
        for px in rgba.chunks_exact(4) {
            assert_eq!(px, [255, 0, 0, 255]);
        }
    }

    #[test]
    fn test_dib_to_png_headerless_fallback() {
        // Headerless DIB: the height argument is the doubled DIB height
        // (XOR + AND masks) and is halved exactly once.
        let width = 4u32;
        let height = 8u32;
        let bpp = 32u16;
        let row_size = (width * bpp as u32).div_ceil(32) * 4;
        let mut dib = vec![0u8; (row_size * height) as usize];
        for y in 0..4 {
            let src_y = height - 1 - y; // bottom-up: last row in DIB = top of image
            for x in 0..4 {
                let off = (src_y * row_size + x * 4) as usize;
                dib[off..off + 4].copy_from_slice(&[0, 0, 255, 255]);
            }
        }
        let png = dib_to_png(&dib, width, height, bpp).unwrap();
        assert_eq!(png[0..8], [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    }

    #[test]
    fn test_dib_to_png_palette_8bpp() {
        // 2x2 8bpp palette icon: XOR rows are bottom-up; row 0 in memory is
        // the bottom image row.
        let width = 2u32;
        let bpp = 8u16;
        let mut dib = Vec::new();
        let mut header = [0u8; 40];
        header[0..4].copy_from_slice(&40u32.to_le_bytes()); // biSize
        header[4..8].copy_from_slice(&(width as i32).to_le_bytes()); // biWidth
        header[8..12].copy_from_slice(&4i32.to_le_bytes()); // biHeight (2 XOR + 2 AND)
        header[12..14].copy_from_slice(&1u16.to_le_bytes()); // biPlanes
        header[14..16].copy_from_slice(&bpp.to_le_bytes()); // biBitCount
        header[32..36].copy_from_slice(&4u32.to_le_bytes()); // biClrUsed: 4 palette entries
        dib.extend_from_slice(&header);
        // Palette: 4 BGRX entries
        dib.extend_from_slice(&[0, 0, 0, 0]); // 0: black
        dib.extend_from_slice(&[0, 0, 255, 0]); // 1: red
        dib.extend_from_slice(&[0, 255, 0, 0]); // 2: green
        dib.extend_from_slice(&[255, 0, 0, 0]); // 3: blue
        // XOR rows (bottom-up), 4 bytes each (2 pixel bytes + padding):
        // bottom image row = [green, red], top image row = [black, blue]
        dib.extend_from_slice(&[2, 1, 0, 0]);
        dib.extend_from_slice(&[0, 3, 0, 0]);
        // AND mask rows
        dib.extend_from_slice(&[0u8; 8]);

        let png = dib_to_png(&dib, 2, 2, 8).unwrap();
        let decoder = png::Decoder::new(std::io::Cursor::new(&png));
        let mut reader = decoder.read_info().unwrap();
        let mut out = vec![0u8; reader.output_buffer_size()];
        let info = reader.next_frame(&mut out).unwrap();
        assert_eq!(info.width, 2);
        assert_eq!(info.height, 2);
        let rgba = &out[..info.buffer_size()];
        // Image row order: top row first.
        assert_eq!(&rgba[0..4], [0, 0, 0, 255]); // black
        assert_eq!(&rgba[4..8], [0, 0, 255, 255]); // blue
        assert_eq!(&rgba[8..12], [0, 255, 0, 255]); // green
        assert_eq!(&rgba[12..16], [255, 0, 0, 255]); // red
    }

    #[test]
    fn test_dib_to_png_rejects_unsupported_bpp() {
        let mut dib = vec![0u8; 40];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[4..8].copy_from_slice(&1i32.to_le_bytes());
        dib[8..12].copy_from_slice(&2i32.to_le_bytes());
        dib[14..16].copy_from_slice(&16u16.to_le_bytes()); // 16bpp is unsupported
        assert!(dib_to_png(&dib, 1, 1, 16).is_err());
    }

    #[test]
    fn test_ico_to_icns_skips_entry_beyond_eof() {
        // An entry whose offset lies beyond EOF must be skipped, not panic.
        let mut ico = vec![0, 0, 1, 0, 1, 0]; // header with 1 icon
        ico.extend_from_slice(&[32, 32, 0, 0]); // width, height, colors, reserved
        ico.extend_from_slice(&[1, 0]); // planes
        ico.extend_from_slice(&[32, 0]); // bpp
        ico.extend_from_slice(&0x1000u32.to_le_bytes()); // size
        ico.extend_from_slice(&0xFFFF_FF00u32.to_le_bytes()); // offset beyond EOF
        let icns = ico_to_icns(&ico).unwrap();
        assert_eq!(icns.len(), 8); // no entries were added
        assert!(validate_icns(&icns).unwrap_or(false));
    }

    #[test]
    fn test_validate_icns_empty() {
        assert!(
            !validate_icns(b"").expect("validate_icns should not error on empty input"),
            "empty data should not be valid ICNS"
        );
        assert!(
            !validate_icns(b"icns").expect("validate_icns should not error on truncated input"),
            "truncated ICNS header should not be valid"
        );
    }

    #[test]
    fn test_validate_icns_malformed_size() {
        // ICNS header with mismatched size field
        let mut data = b"icns".to_vec();
        data.extend_from_slice(&100u32.to_be_bytes()); // claims 100 bytes but only 8 present
        assert!(
            !validate_icns(&data).expect("validate_icns should not error on malformed ICNS"),
            "ICNS with wrong size should be invalid"
        );
    }

    #[test]
    fn test_ico_to_icns_too_short() {
        let result = ico_to_icns(&[0, 0, 1]);
        assert!(result.is_err(), "ICO data shorter than 6 bytes should fail");
    }

    #[test]
    fn test_icon_to_png_already_compressed() {
        let icon = IconImage {
            width: 16,
            height: 16,
            bpp: 32,
            data: vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A], // fake PNG header
            is_png_compressed: true,
            xor_mask: None,
        };
        let result = icon_to_png(&icon);
        assert!(
            result.is_ok(),
            "icon_to_png should succeed for PNG-compressed icons"
        );
        assert_eq!(result.unwrap(), icon.data);
    }
}
