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
    Ic13, // 128x128 2x (256x256)
    Ic14, // 256x256 2x (512x512)
    Ic04, // 16x16 1x (old format)
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

/// Convert raw BMP/DIB icon pixel data to PNG bytes.
/// The icon data is in Windows DIB format (BGRA bottom-up).
pub fn dib_to_png(data: &[u8], width: u32, height: u32, bpp: u16) -> AppResult<Vec<u8>> {
    let actual_height = height / 2; // DIB includes XOR mask (height/2) and AND mask (height/2)
    let row_size = ((width * bpp as u32 + 31) / 32) * 4;
    let pixel_height = actual_height;

    let mut rgba = vec![0u8; (width * pixel_height * 4) as usize];

    for y in 0..pixel_height {
        let src_row = (pixel_height - 1 - y) as usize * row_size as usize;
        for x in 0..width as usize {
            let src_pixel = src_row + x * (bpp as usize / 8);
            let dst_pixel = (y as usize * width as usize + x) * 4;
            if src_pixel + 4 <= data.len() {
                // DIB is BGRA
                rgba[dst_pixel as usize] = data[src_pixel + 2]; // R
                rgba[dst_pixel as usize + 1] = data[src_pixel + 1]; // G
                rgba[dst_pixel as usize + 2] = data[src_pixel]; // B
                if bpp == 32 {
                    rgba[dst_pixel as usize + 3] = data[src_pixel + 3]; // A
                } else {
                    rgba[dst_pixel as usize + 3] = 255;
                }
            }
        }
    }

    // Encode as PNG using a simple DEFLATE-based approach
    // Since we can't add a PNG dependency easily, we'll use a minimal PNG encoder
    encode_png(&rgba, width, pixel_height)
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
        let data_end = (data_start + entry.size as usize).min(ico_data.len());
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
        // Create a 4x4 32bpp DIB (BGRA, bottom-up)
        let width = 4u32;
        let height = 8u32; // DIB includes XOR + AND mask = 2x height
        let bpp = 32u16;
        let row_size = ((width * bpp as u32 + 31) / 32) * 4;
        let mut dib = vec![0u8; (row_size * height) as usize];
        // Fill top half with red pixels (B=0, G=0, R=255, A=255)
        // In DIB bottom-up, bottom rows come first, so write some test data
        for y in 0..4 {
            for x in 0..4 {
                let off = ((height - 1 - y) * row_size + x * 4) as usize;
                if off + 4 <= dib.len() {
                    dib[off] = 0; // B
                    dib[off + 1] = 0; // G
                    dib[off + 2] = 255; // R
                    dib[off + 3] = 255; // A
                }
            }
        }
        let result = dib_to_png(&dib, width, height, bpp);
        assert!(
            result.is_ok(),
            "dib_to_png should succeed for valid DIB data"
        );
        let png = result.unwrap();
        assert!(&png[0..8] == &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
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
