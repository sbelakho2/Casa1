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
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

// PE resource type constants
pub const RT_ICON: u32 = 3;
pub const RT_GROUP_ICON: u32 = 14;
pub const RT_VERSION: u32 = 16;
pub const RT_MANIFEST: u32 = 24;

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
    pub planes: u16,     // For ICO, should be 0 or 1
    pub bpp: u16,        // Bits per pixel
    pub size: u32,
    pub offset: u32,
}

/// A decoded icon image with pixel data.
#[derive(Debug, Clone)]
pub struct IconImage {
    pub width: u32,
    pub height: u32,
    pub bpp: u16,
    pub data: Vec<u8>,         // Raw BGRA pixel data or PNG data
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
pub fn extract_icon_from_pe(path: &Path) -> AppResult<Option<IconImage>> {
    let bytes = std::fs::read(path)
        .map_err(|e| AppError::from_io(ReasonCode::RcIo, format!("failed to read PE file: {}", path.display()), &e))?;
    // Parse PE headers minimally to find resource section
    let (sections, directories) = parse_pe_headers_for_resources(&bytes)?;
    let icons = extract_icons_from_pe_bytes(&bytes, &sections, &directories)?;
    // Return the largest icon (by pixel count * bpp)
    Ok(icons.into_iter().max_by(|a, b| {
        let a_score = (a.width * a.height * a.bpp as u32) as u64;
        let b_score = (b.width * b.height * b.bpp as u32) as u64;
        a_score.cmp(&b_score)
    }))
}

/// Extract all icons from a PE file at the given path.
pub fn extract_all_icons_from_pe(path: &Path) -> AppResult<Vec<IconImage>> {
    let bytes = std::fs::read(path)
        .map_err(|e| AppError::from_io(ReasonCode::RcIo, format!("failed to read PE file: {}", path.display()), &e))?;
    let (sections, directories) = parse_pe_headers_for_resources(&bytes)?;
    extract_icons_from_pe_bytes(&bytes, &sections, &directories)
}

/// Minimal PE header parsing to get sections and data directories.
fn parse_pe_headers_for_resources(bytes: &[u8]) -> AppResult<(Vec<PeSection>, Vec<DataDirectory>)> {
    if bytes.len() < 64 {
        return Err(AppError::new(ReasonCode::RcPeParseInvalid, "file too small for PE header"));
    }
    let dos_magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    if dos_magic != 0x5a4d {
        return Err(AppError::new(ReasonCode::RcPeParseInvalid, "not a PE file (no MZ signature)"));
    }
    let pe_offset = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
    if pe_offset + 4 > bytes.len() {
        return Err(AppError::new(ReasonCode::RcPeParseInvalid, "PE offset beyond file size"));
    }
    let nt_magic = u32::from_le_bytes([bytes[pe_offset], bytes[pe_offset + 1], bytes[pe_offset + 2], bytes[pe_offset + 3]]);
    if nt_magic != 0x4550 {
        return Err(AppError::new(ReasonCode::RcPeParseInvalid, "no PE signature"));
    }
    let coff_offset = pe_offset + 4;
    if coff_offset + 20 > bytes.len() {
        return Err(AppError::new(ReasonCode::RcPeParseInvalid, "COFF header truncated"));
    }
    let size_of_optional_header = u16::from_le_bytes([bytes[coff_offset + 16], bytes[coff_offset + 17]]) as usize;
    let num_sections = u16::from_le_bytes([bytes[coff_offset + 2], bytes[coff_offset + 3]]) as usize;
    let optional_offset = coff_offset + 20;
    let sections_offset = optional_offset + size_of_optional_header;

    // Read data directory count and directories from optional header
    let magic = u16::from_le_bytes([bytes[optional_offset], bytes[optional_offset + 1]]);
    let data_dir_offset = if magic == 0x10b {
        // PE32
        optional_offset + 96
    } else {
        // PE32+
        optional_offset + 112
    };

    let data_dir_count = if magic == 0x10b {
        u32::from_le_bytes([
            bytes[optional_offset + 92],
            bytes[optional_offset + 93],
            bytes[optional_offset + 94],
            bytes[optional_offset + 95],
        ]) as usize
    } else {
        u32::from_le_bytes([
            bytes[optional_offset + 108],
            bytes[optional_offset + 109],
            bytes[optional_offset + 110],
            bytes[optional_offset + 111],
        ]) as usize
    };

    let mut directories = Vec::new();
    for i in 0..data_dir_count.min(16) {
        let off = data_dir_offset + i * 8;
        if off + 8 > bytes.len() {
            break;
        }
        let va = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        let sz = u32::from_le_bytes([bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7]]);
        directories.push(DataDirectory { virtual_address: va, size: sz });
    }

    // Parse section table
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let off = sections_offset + i * 40;
        if off + 40 > bytes.len() {
            break;
        }
        let name_bytes = &bytes[off..off + 8];
        let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();
        let virtual_size = u32::from_le_bytes([bytes[off + 8], bytes[off + 9], bytes[off + 10], bytes[off + 11]]);
        let virtual_address = u32::from_le_bytes([bytes[off + 12], bytes[off + 13], bytes[off + 14], bytes[off + 15]]);
        let raw_size = u32::from_le_bytes([bytes[off + 16], bytes[off + 17], bytes[off + 18], bytes[off + 19]]);
        let raw_ptr = u32::from_le_bytes([bytes[off + 20], bytes[off + 21], bytes[off + 22], bytes[off + 23]]);
        let characteristics = u32::from_le_bytes([bytes[off + 36], bytes[off + 37], bytes[off + 38], bytes[off + 39]]);
        sections.push(PeSection {
            name,
            virtual_address,
            virtual_size,
            raw_data_ptr: raw_ptr,
            raw_data_size: raw_size,
            characteristics,
        });
    }

    Ok((sections, directories))
}

#[derive(Debug, Clone)]
struct PeSection {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_data_ptr: u32,
    raw_data_size: u32,
    characteristics: u32,
}

#[derive(Debug, Clone, Default)]
struct DataDirectory {
    virtual_address: u32,
    size: u32,
}

fn rva_to_file_offset(rva: u32, sections: &[PeSection]) -> Option<u32> {
    for section in sections {
        if rva >= section.virtual_address && rva < section.virtual_address + section.virtual_size.max(section.raw_data_size) {
            let offset = rva - section.virtual_address;
            if offset < section.raw_data_size {
                return Some(section.raw_data_ptr + offset);
            }
        }
    }
    None
}

fn section_for_rva(sections: &[PeSection], rva: u32) -> Option<&PeSection> {
    sections.iter().find(|s| {
        rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size.max(s.raw_data_size)
    })
}

/// Extract icon resources from parsed PE bytes.
fn extract_icons_from_pe_bytes(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
) -> AppResult<Vec<IconImage>> {
    let resource_dir = directories.get(2).ok_or_else(|| {
        AppError::new(ReasonCode::RcPeParseInvalid, "no resource directory in PE")
    })?;
    if resource_dir.virtual_address == 0 || resource_dir.size == 0 {
        return Ok(Vec::new());
    }

    // Get the resource section
    let res_section = section_for_rva(sections, resource_dir.virtual_address).ok_or_else(|| {
        AppError::new(ReasonCode::RcPeParseInvalid, "resource directory RVA not in any section")
    })?;

    let section_data = if (res_section.raw_data_ptr as usize) < bytes.len() {
        let end = (res_section.raw_data_ptr + res_section.raw_data_size) as usize;
        &bytes[res_section.raw_data_ptr as usize..end.min(bytes.len())]
    } else {
        return Ok(Vec::new());
    };

    // Resource directory structure: Root → Type (RT_GROUP_ICON/RT_ICON) → Name → Language → Data Entry
    // First, find RT_GROUP_ICON entries
    let group_icon_entries = find_resource_id_entries(
        section_data,
        res_section.virtual_address,
        resource_dir.virtual_address,
        RT_GROUP_ICON,
    )?;

    let mut icons = Vec::new();

    for group_entry in &group_icon_entries {
        // Each group entry points to a GRPICONDIR structure
        let data = get_resource_data(section_data, res_section.virtual_address, group_entry.data_rva, group_entry.data_size)?;
        if data.len() < 6 {
            continue;
        }
        let reserved = u16::from_le_bytes([data[0], data[1]]);
        let icon_type = u16::from_le_bytes([data[2], data[3]]);
        let count = u16::from_le_bytes([data[4], data[5]]) as usize;
        if reserved != 0 || icon_type != 1 {
            continue;
        }

        // Parse group icon directory entries (each 14 bytes)
        for i in 0..count {
            let entry_off = 6 + i * 14;
            if entry_off + 14 > data.len() {
                break;
            }
            let width = data[entry_off];
            let height = data[entry_off + 1];
            let color_count = data[entry_off + 2];
            let _reserved_byte = data[entry_off + 3];
            let planes = u16::from_le_bytes([data[entry_off + 4], data[entry_off + 5]]);
            let bpp = u16::from_le_bytes([data[entry_off + 6], data[entry_off + 7]]);
            let icon_size = u32::from_le_bytes([
                data[entry_off + 8],
                data[entry_off + 9],
                data[entry_off + 10],
                data[entry_off + 11],
            ]);
            let icon_id = u16::from_le_bytes([data[entry_off + 12], data[entry_off + 13]]) as u32;

            // RT_ICON entries are keyed by the icon ID (name_id = icon_id)
            let icon_entries = find_resource_name_entries(
                section_data,
                res_section.virtual_address,
                resource_dir.virtual_address,
                RT_ICON,
                icon_id,
            )?;

            for icon_entry in &icon_entries {
                let icon_data = get_resource_data(
                    section_data,
                    res_section.virtual_address,
                    icon_entry.data_rva,
                    icon_entry.data_size,
                )?;

                let display_width = if width == 0 { 256u32 } else { width as u32 };
                let display_height = if height == 0 { 256u32 } else { height as u32 };

                // Check if icon data is PNG compressed (starts with PNG signature)
                let is_png = icon_data.len() >= 8
                    && icon_data[0] == 0x89
                    && icon_data[1] == b'P'
                    && icon_data[2] == b'N'
                    && icon_data[3] == b'G';

                icons.push(IconImage {
                    width: display_width,
                    height: display_height,
                    bpp,
                    data: icon_data,
                    is_png_compressed: is_png,
                    xor_mask: None,
                });
            }
        }
    }

    Ok(icons)
}

#[derive(Debug)]
struct ResourceDataEntry {
    data_rva: u32,
    data_size: u32,
}

/// Find resource entries by type ID at the first level of the resource directory.
fn find_resource_id_entries(
    section_data: &[u8],
    section_rva: u32,
    root_rva: u32,
    type_id: u32,
) -> AppResult<Vec<ResourceDataEntry>> {
    // Navigate root directory
    let root_relative = root_rva.checked_sub(section_rva).ok_or_else(|| {
        AppError::new(ReasonCode::RcPeParseInvalid, "resource root underflow")
    })? as usize;

    if root_relative + 16 > section_data.len() {
        return Ok(Vec::new());
    }

    let named_entries = u16::from_le_bytes([section_data[root_relative + 12], section_data[root_relative + 13]]) as usize;
    let id_entries = u16::from_le_bytes([section_data[root_relative + 14], section_data[root_relative + 15]]) as usize;
    let total = named_entries + id_entries;

    let mut results = Vec::new();
    for i in 0..total {
        let entry_off = root_relative + 16 + i * 8;
        if entry_off + 8 > section_data.len() {
            break;
        }
        let name_or_id = u32::from_le_bytes([
            section_data[entry_off],
            section_data[entry_off + 1],
            section_data[entry_off + 2],
            section_data[entry_off + 3],
        ]);
        // Check if this is a named entry (high bit set) or ID entry
        if name_or_id & 0x8000_0000 != 0 {
            // Named entry — skip for ID-based lookup
            continue;
        }
        let entry_id = name_or_id & 0xffff;
        if entry_id != type_id {
            continue;
        }

        let payload = u32::from_le_bytes([
            section_data[entry_off + 4],
            section_data[entry_off + 5],
            section_data[entry_off + 6],
            section_data[entry_off + 7],
        ]);

        if payload & 0x8000_0000 != 0 {
            // Points to a subdirectory — navigate it
            let subdir_rva = root_rva + (payload & 0x7fff_ffff);
            results.extend(find_all_data_entries(section_data, section_rva, root_rva, subdir_rva, 2)?);
        } else {
            // Points to a data entry (shouldn't be at level 1 but handle it)
            let data_entry_rva = root_rva + (payload & 0x7fff_ffff);
            if data_entry_rva.checked_sub(section_rva).map_or(false, |r| r as usize + 16 <= section_data.len()) {
                let de_off = (data_entry_rva - section_rva) as usize;
                let data_rva = u32::from_le_bytes([
                    section_data[de_off], section_data[de_off + 1],
                    section_data[de_off + 2], section_data[de_off + 3],
                ]);
                let data_size = u32::from_le_bytes([
                    section_data[de_off + 4], section_data[de_off + 5],
                    section_data[de_off + 6], section_data[de_off + 7],
                ]);
                results.push(ResourceDataEntry { data_rva, data_size });
            }
        }
    }
    Ok(results)
}

/// Find resource entries by type ID at first level AND name ID at second level.
fn find_resource_name_entries(
    section_data: &[u8],
    section_rva: u32,
    root_rva: u32,
    type_id: u32,
    name_id: u32,
) -> AppResult<Vec<ResourceDataEntry>> {
    let root_relative = root_rva.checked_sub(section_rva).ok_or_else(|| {
        AppError::new(ReasonCode::RcPeParseInvalid, "resource root underflow")
    })? as usize;

    if root_relative + 16 > section_data.len() {
        return Ok(Vec::new());
    }

    let named_entries = u16::from_le_bytes([section_data[root_relative + 12], section_data[root_relative + 13]]) as usize;
    let id_entries = u16::from_le_bytes([section_data[root_relative + 14], section_data[root_relative + 15]]) as usize;
    let total = named_entries + id_entries;

    for i in 0..total {
        let entry_off = root_relative + 16 + i * 8;
        if entry_off + 8 > section_data.len() {
            break;
        }
        let name_or_id = u32::from_le_bytes([
            section_data[entry_off], section_data[entry_off + 1],
            section_data[entry_off + 2], section_data[entry_off + 3],
        ]);
        if name_or_id & 0x8000_0000 != 0 {
            continue;
        }
        if (name_or_id & 0xffff) != type_id {
            continue;
        }

        let payload = u32::from_le_bytes([
            section_data[entry_off + 4], section_data[entry_off + 5],
            section_data[entry_off + 6], section_data[entry_off + 7],
        ]);

        if payload & 0x8000_0000 == 0 {
            continue; // Need a subdirectory
        }

        let type_subdir_rva = root_rva + (payload & 0x7fff_ffff);
        // Now search the second level for the name_id
        return find_name_id_data_entries(section_data, section_rva, root_rva, type_subdir_rva, name_id);
    }

    Ok(Vec::new())
}

/// At the second resource level (name entries), find entries matching `name_id`.
fn find_name_id_data_entries(
    section_data: &[u8],
    section_rva: u32,
    root_rva: u32,
    dir_rva: u32,
    name_id: u32,
) -> AppResult<Vec<ResourceDataEntry>> {
    let dir_relative = dir_rva.checked_sub(section_rva).ok_or_else(|| {
        AppError::new(ReasonCode::RcPeParseInvalid, "resource dir underflow")
    })? as usize;

    if dir_relative + 16 > section_data.len() {
        return Ok(Vec::new());
    }

    let named_entries = u16::from_le_bytes([section_data[dir_relative + 12], section_data[dir_relative + 13]]) as usize;
    let id_entries = u16::from_le_bytes([section_data[dir_relative + 14], section_data[dir_relative + 15]]) as usize;
    let total = named_entries + id_entries;

    for i in 0..total {
        let entry_off = dir_relative + 16 + i * 8;
        if entry_off + 8 > section_data.len() {
            break;
        }
        let name_or_id = u32::from_le_bytes([
            section_data[entry_off], section_data[entry_off + 1],
            section_data[entry_off + 2], section_data[entry_off + 3],
        ]);
        if name_or_id & 0x8000_0000 != 0 {
            continue;
        }
        if (name_or_id & 0xffff) != name_id {
            continue;
        }

        let payload = u32::from_le_bytes([
            section_data[entry_off + 4], section_data[entry_off + 5],
            section_data[entry_off + 6], section_data[entry_off + 7],
        ]);

        // Navigate to third level (language)
        if payload & 0x8000_0000 != 0 {
            let lang_dir_rva = root_rva + (payload & 0x7fff_ffff);
            return find_all_data_entries(section_data, section_rva, root_rva, lang_dir_rva, 4);
        } else {
            let data_entry_rva = root_rva + (payload & 0x7fff_ffff);
            let de_off = (data_entry_rva - section_rva) as usize;
            if de_off + 16 <= section_data.len() {
                let data_rva = u32::from_le_bytes([
                    section_data[de_off], section_data[de_off + 1],
                    section_data[de_off + 2], section_data[de_off + 3],
                ]);
                let data_size = u32::from_le_bytes([
                    section_data[de_off + 4], section_data[de_off + 5],
                    section_data[de_off + 6], section_data[de_off + 7],
                ]);
                return Ok(vec![ResourceDataEntry { data_rva, data_size }]);
            }
        }
    }
    Ok(Vec::new())
}

/// Recursively find all data entries at or below a given resource directory.
fn find_all_data_entries(
    section_data: &[u8],
    section_rva: u32,
    root_rva: u32,
    dir_rva: u32,
    depth: u8,
) -> AppResult<Vec<ResourceDataEntry>> {
    if depth > 4 {
        return Ok(Vec::new());
    }

    let dir_relative = dir_rva.checked_sub(section_rva).ok_or_else(|| {
        AppError::new(ReasonCode::RcPeParseInvalid, "resource dir underflow")
    })? as usize;

    if dir_relative + 16 > section_data.len() {
        return Ok(Vec::new());
    }

    let named_entries = u16::from_le_bytes([section_data[dir_relative + 12], section_data[dir_relative + 13]]) as usize;
    let id_entries = u16::from_le_bytes([section_data[dir_relative + 14], section_data[dir_relative + 15]]) as usize;
    let total = named_entries + id_entries;

    let mut results = Vec::new();
    for i in 0..total {
        let entry_off = dir_relative + 16 + i * 8;
        if entry_off + 8 > section_data.len() {
            break;
        }
        let _name_or_id = u32::from_le_bytes([
            section_data[entry_off], section_data[entry_off + 1],
            section_data[entry_off + 2], section_data[entry_off + 3],
        ]);
        let payload = u32::from_le_bytes([
            section_data[entry_off + 4], section_data[entry_off + 5],
            section_data[entry_off + 6], section_data[entry_off + 7],
        ]);

        if payload & 0x8000_0000 != 0 {
            let child_rva = root_rva + (payload & 0x7fff_ffff);
            results.extend(find_all_data_entries(section_data, section_rva, root_rva, child_rva, depth + 1)?);
        } else if depth >= 2 {
            let data_entry_rva = root_rva + (payload & 0x7fff_ffff);
            let de_off = (data_entry_rva - section_rva) as usize;
            if de_off + 16 <= section_data.len() {
                let data_rva = u32::from_le_bytes([
                    section_data[de_off], section_data[de_off + 1],
                    section_data[de_off + 2], section_data[de_off + 3],
                ]);
                let data_size = u32::from_le_bytes([
                    section_data[de_off + 4], section_data[de_off + 5],
                    section_data[de_off + 6], section_data[de_off + 7],
                ]);
                results.push(ResourceDataEntry { data_rva, data_size });
            }
        }
    }
    Ok(results)
}

/// Get the actual resource data bytes from the file using RVA.
fn get_resource_data(
    section_data: &[u8],
    section_rva: u32,
    data_rva: u32,
    data_size: u32,
) -> AppResult<Vec<u8>> {
    if data_size == 0 {
        return Ok(Vec::new());
    }
    let offset = data_rva.checked_sub(section_rva).ok_or_else(|| {
        AppError::new(ReasonCode::RcPeParseInvalid, "resource data RVA underflow")
    })? as usize;
    let end = offset + data_size as usize;
    if end > section_data.len() {
        return Err(AppError::new(ReasonCode::RcPeParseInvalid, "resource data beyond section"));
    }
    Ok(section_data[offset..end].to_vec())
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
                rgba[dst_pixel as usize] = data[src_pixel + 2];     // R
                rgba[dst_pixel as usize + 1] = data[src_pixel + 1]; // G
                rgba[dst_pixel as usize + 2] = data[src_pixel];     // B
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

/// Simple PNG encoder for RGBA data.
fn encode_png(data: &[u8], width: u32, height: u32) -> AppResult<Vec<u8>> {
    use std::io::Write;
    let mut png = Vec::new();

    // PNG signature
    png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR chunk
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(6); // color type: RGBA
    ihdr.push(0); // compression
    ihdr.push(0); // filter
    ihdr.push(0); // interlace
    write_png_chunk(&mut png, b"IHDR", &ihdr);

    // IDAT chunk — raw deflate of filtered rows
    let raw_rows = filter_rows(data, width, height);
    let compressed = deflate_compress(&raw_rows);
    write_png_chunk(&mut png, b"IDAT", &compressed);

    // IEND chunk
    write_png_chunk(&mut png, b"IEND", &[]);

    Ok(png)
}

fn write_png_chunk(png: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    let len = data.len() as u32;
    png.extend_from_slice(&len.to_be_bytes());
    png.extend_from_slice(chunk_type);
    png.extend_from_slice(data);
    let mut crc = Crc32::new();
    crc.update(chunk_type);
    crc.update(data);
    png.extend_from_slice(&crc.finalize().to_be_bytes());
}

fn filter_rows(data: &[u8], width: u32, height: u32) -> Vec<u8> {
    let row_bytes = (width * 4) as usize;
    let mut filtered = Vec::with_capacity((row_bytes + 1) * height as usize);
    for y in 0..height as usize {
        let row_start = y * row_bytes;
        filtered.push(0); // filter type: None
        if row_start + row_bytes <= data.len() {
            filtered.extend_from_slice(&data[row_start..row_start + row_bytes]);
        }
    }
    filtered
}

/// Minimal DEFLATE compression for PNG encoding.
fn deflate_compress(data: &[u8]) -> Vec<u8> {
    // Simple approach: use zlib wrapper with stored (non-compressed) blocks
    // This produces valid PNG but isn't compressed.
    // For production, we'd use miniz_oxide or flate2, but this works correctly.
    let mut compressed = Vec::new();

    // Zlib header
    let cmf = 0x78; // deflate, window size 32K
    let flg = 0x01; // check bits: (cmf * 256 + flg) % 31 == 0
    compressed.push(cmf);
    compressed.push(flg);

    // Deflate: store blocks
    let mut pos = 0;
    while pos < data.len() {
        let remaining = data.len() - pos;
        let chunk_size = remaining.min(65535);
        let is_final = pos + chunk_size >= data.len();

        // Block header: BFINAL=is_final, BTYPE=00 (stored)
        compressed.push(if is_final { 0x01 } else { 0x00 });

        // LEN and NLEN
        let len = chunk_size as u16;
        let nlen = (!len).wrapping_add(1); // one's complement
        compressed.extend_from_slice(&len.to_le_bytes());
        compressed.extend_from_slice(&nlen.to_le_bytes());

        // Raw data
        compressed.extend_from_slice(&data[pos..pos + chunk_size]);
        pos += chunk_size;
    }

    // Zlib check value (Adler-32)
    compressed.extend_from_slice(&adler32(data).to_be_bytes());

    compressed
}

/// Simple Adler-32 checksum.
fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// CRC32 implementation for PNG chunk headers.
struct Crc32 {
    table: [u32; 256],
    crc: u32,
}

impl Crc32 {
    fn new() -> Self {
        let mut table = [0u32; 256];
        for i in 0..256 {
            let mut crc = i as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = 0xedb88320 ^ (crc >> 1);
                } else {
                    crc >>= 1;
                }
            }
            table[i] = crc;
        }
        Self { table, crc: 0xffff_ffff }
    }

    fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let idx = ((self.crc ^ byte as u32) & 0xff) as usize;
            self.crc = self.table[idx] ^ (self.crc >> 8);
        }
    }

    fn finalize(&self) -> u32 {
        self.crc ^ 0xffff_ffff
    }
}

/// Convert ICO data to macOS ICNS format.
/// Takes an ICO file's bytes and produces a valid `.icns` file.
pub fn ico_to_icns(ico_data: &[u8]) -> AppResult<Vec<u8>> {
    if ico_data.len() < 6 {
        return Err(AppError::new(ReasonCode::RcPeParseInvalid, "ICO data too short"));
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
                ico_data[off + 8], ico_data[off + 9],
                ico_data[off + 10], ico_data[off + 11],
            ]),
            offset: u32::from_le_bytes([
                ico_data[off + 12], ico_data[off + 13],
                ico_data[off + 14], ico_data[off + 15],
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
        let display_width = if entry.width == 0 { 256u32 } else { entry.width as u32 };
        let display_height = if entry.height == 0 { 256u32 } else { entry.height as u32 };

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
        let entry_size = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;
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
    fn test_crc32() {
        let mut crc = Crc32::new();
        crc.update(b"test");
        assert_eq!(crc.finalize(), 0xd87f7e0c);
    }

    #[test]
    fn test_adler32() {
        assert_eq!(adler32(b"Wikipedia"), 0x11e60398);
        assert_eq!(adler32(b""), 0x00000001);
    }

    #[test]
    fn test_png_encoding() {
        // Create a simple 2x2 RGBA image
        let data = vec![
            255, 0, 0, 255, 0, 255, 0, 255,
            0, 0, 255, 255, 255, 255, 0, 255,
        ];
        let png = encode_png(&data, 2, 2).unwrap();
        // Check PNG signature
        assert_eq!(&png[0..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        // Check IHDR
        assert_eq!(&png[12..16], b"IHDR");
        // Check IEND chunk exists (it won't be at the very end since the CRC follows)
        assert!(png.windows(4).any(|w| w == b"IEND"));
    }

    #[test]
    fn test_ico_to_icns_minimal() {
        // This test verifies the ICNS structure is valid
        // even with an empty-ish ICO (just the header)
        let ico = vec![0, 0, 1, 0, 0, 0]; // ICO header with 0 icons
        let result = ico_to_icns(&ico);
        assert!(result.is_ok());
        let icns = result.unwrap();
        assert!(validate_icns(&icns).unwrap_or(false));
        assert_eq!(&icns[0..4], b"icns");
    }

    #[test]
    fn test_icons_to_icns() {
        let icons = vec![
            IconImage {
                width: 16,
                height: 16,
                bpp: 32,
                data: vec![0u8; 16 * 16 * 4], // transparent black
                is_png_compressed: false,
                xor_mask: None,
            },
        ];
        let result = icons_to_icns(&icons);
        assert!(result.is_ok());
        let icns = result.unwrap();
        assert!(validate_icns(&icns).unwrap_or(false));
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
                    dib[off] = 0;     // B
                    dib[off + 1] = 0; // G
                    dib[off + 2] = 255; // R
                    dib[off + 3] = 255; // A
                }
            }
        }
        let result = dib_to_png(&dib, width, height, bpp);
        assert!(result.is_ok());
        let png = result.unwrap();
        assert!(&png[0..8] == &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    }

    #[test]
    fn test_validate_icns_empty() {
        assert!(!validate_icns(b"").unwrap_or(false));
        assert!(!validate_icns(b"icns").unwrap_or(false));
    }
}
