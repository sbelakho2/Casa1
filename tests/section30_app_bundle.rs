//! Section 30: PE Icon Extraction and ICO → ICNS Conversion Tests
//!
//! Tests for Phase 1.1–1.2: icon resource parsing from PE files, ICO/ICNS
//! conversion, and round-trip verification.

// ─────────────────────────────────────────────────────────────────────────────
// Helper: construct a minimal PE file with embedded RT_GROUP_ICON + RT_ICON
// resources for controlled unit-testing.
// ─────────────────────────────────────────────────────────────────────────────

/// Build a minimal PE32 file with a `.rsrc` section containing icon resources.
///
/// Layout (resource directory tree):
///   Root
///   ├── Type ID 14 (RT_GROUP_ICON)
///   │   └── Name ID 1
///   │       └── Language 1033 → GRPICONDIR + 1 entry (icon_id=2)
///   └── Type ID 3  (RT_ICON)
///       └── Name ID 2
///           └── Language 1033 → 32×32×32bpp DIB pixel data
fn build_test_pe_with_icon() -> Vec<u8> {
    // We'll create a resource directory structure manually.
    // For simplicity, we stub the PE headers and place the resource tree
    // in a single `.rsrc` section backed by file data.
    //
    // PE structure:
    //   [0x0000..0x0040) DOS header + e_lfanew
    //   [0x0040..0x0044) PE signature "PE\0\0"
    //   [0x0044..0x0058) COFF header (machine=0x14c, sections=1)
    //   [0x0058..0x0138) Optional header PE32 (section_alignment=0x1000,
    //                     file_alignment=0x200, image_base=0x400000,
    //                     size_of_image=0x3000, size_of_headers=0x1000,
    //                     16 data directories; resource dir at index 2)
    //   [0x0138..0x0160) Section table for .rsrc
    //   [0x1000..0x2000) .rsrc section contents
    //     Resource directory tree at RVA 0x1000
    //
    // PE32 optional header layout (offsets relative to optional header start 0x58):
    //   [0x00] Magic (2)
    //   [0x10] AddressOfEntryPoint (4)
    //   [0x1C] ImageBase (4)
    //   [0x20] SectionAlignment (4)
    //   [0x24] FileAlignment (4)
    //   [0x38] SizeOfImage (4)
    //   [0x3C] SizeOfHeaders (4)
    //   [0x5C] NumberOfRvaAndSizes (4)
    //   [0x60] Data directory 0 (RVA + Size, 8 bytes each)
    //   [0x78] Data directory 2 = resource directory (RVA=0x1000)

    let mut pe = vec![0u8; 0x1000]; // header region, zero-filled

    // ── DOS header ───────────────────────────────────────────────────────────
    pe[0] = b'M';
    pe[1] = b'Z';
    // e_lfanew at offset 0x3C -> 0x40
    pe[0x3C] = 0x40;

    // ── PE signature at 0x40 ─────────────────────────────────────────────────
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");

    // ── COFF header at 0x44 ──────────────────────────────────────────────────
    // Machine: x86
    pe[0x44..0x46].copy_from_slice(&0x014c_u16.to_le_bytes());
    // Number of sections: 1
    pe[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    // Size of optional header: 0xE0 (PE32 standard)
    pe[0x54..0x56].copy_from_slice(&0x00E0u16.to_le_bytes());
    // Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
    pe[0x56..0x58].copy_from_slice(&0x0102u16.to_le_bytes());

    // ── Optional header PE32 at 0x58 ─────────────────────────────────────────
    // Magic: PE32 (0x10b) at optional_offset+0
    pe[0x58..0x5A].copy_from_slice(&0x010Bu16.to_le_bytes());
    // AddressOfEntryPoint = 0x1000 at optional_offset+16 = 0x58+16 = 0x68
    pe[0x68..0x6C].copy_from_slice(&0x1000u32.to_le_bytes());
    // ImageBase = 0x00400000 at optional_offset+28 = 0x58+28 = 0x74
    pe[0x74..0x78].copy_from_slice(&0x00400000u32.to_le_bytes());
    // SectionAlignment = 0x1000 at optional_offset+32 = 0x58+32 = 0x78
    pe[0x78..0x7C].copy_from_slice(&0x1000u32.to_le_bytes());
    // FileAlignment = 0x200 at optional_offset+36 = 0x58+36 = 0x7C
    pe[0x7C..0x80].copy_from_slice(&0x0200u32.to_le_bytes());
    // SizeOfImage = 0x3000 at optional_offset+56 = 0x58+56 = 0x90
    pe[0x90..0x94].copy_from_slice(&0x3000u32.to_le_bytes());
    // SizeOfHeaders = 0x1000 at optional_offset+60 = 0x58+60 = 0x94
    pe[0x94..0x98].copy_from_slice(&0x1000u32.to_le_bytes());
    // NumberOfRvaAndSizes = 16 at optional_offset+92 = 0x58+92 = 0xB4
    pe[0xB4..0xB8].copy_from_slice(&16u32.to_le_bytes());

    // ── Data directory 2 (resource) at optional_offset+96+16 = 0x58+0x60+0x10 = 0xC8 ──
    // Data directories start at optional_offset+96 = 0x58+0x60 = 0xB8
    // Index 0 (0xB8-0xBF): export (all zeros)
    // Index 1 (0xC0-0xC7): import (all zeros)
    // Index 2 (0xC8-0xCF): resource directory
    // Resource directory: RVA = 0x1000, Size = 0x400
    pe[0xC8..0xCC].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0xCC..0xD0].copy_from_slice(&0x0400u32.to_le_bytes());

    // ── Section table for .rsrc starting at 0x58 + 0xE0 = 0x138 ──────────────
    let section_offset = 0x138usize;
    // Name: ".rsrc\0\0\0"
    pe[section_offset..section_offset + 8].copy_from_slice(b".rsrc\0\0\0");
    // VirtualSize = 0x0C28 (must cover group icon at 0x1100 + icon DIB at 0x1200..0x1C28)
    pe[section_offset + 8..section_offset + 12].copy_from_slice(&0x0C28u32.to_le_bytes());
    // VirtualAddress = 0x1000
    pe[section_offset + 12..section_offset + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    // SizeOfRawData = 0x0C28 (match VirtualSize so pe.rs can read all referenced data)
    pe[section_offset + 16..section_offset + 20].copy_from_slice(&0x0C28u32.to_le_bytes());
    // PointerToRawData = 0x1000
    pe[section_offset + 20..section_offset + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    // Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA
    pe[section_offset + 36..section_offset + 40].copy_from_slice(&0xC000_0040u32.to_le_bytes());

    // ── Build the .rsrc section content ─────────────────────────────────────
    // We'll assemble it separately and append.
    pe.resize(0x1000, 0); // ensure we have up to section data start

    // Resource directory layout (all RVAs are relative to image base 0x400000):
    //
    //   RVA 0x1000: Root directory
    //     [0x1000] Characteristics (0)
    //     [0x1004] TimeDateStamp (0)
    //     [0x1008] MajorVersion (0) / MinorVersion (0)
    //     [0x100C] NamedEntries (0) / IDEntries (2) ← RT_GROUP_ICON + RT_ICON
    //     [0x1010] Entry 0: ID=14 (RT_GROUP_ICON), subdir offset=0x20
    //     [0x1018] Entry 1: ID=3  (RT_ICON),      subdir offset=0x80
    //
    //   RVA 0x1020: Type subdirectory for RT_GROUP_ICON (ID=14)
    //     [0x1020] Characteristics (0)
    //     [0x1024] TimeDateStamp (0)
    //     [0x1028] MajorVersion/MinorVersion (0)
    //     [0x102C] NamedEntries(0) / IDEntries(1) ← Name ID=1
    //     [0x1030] Entry: ID=1, subdir offset=0x40
    //
    //   RVA 0x1040: Name subdirectory for group icon name=1
    //     [0x1040] Characteristics (0)
    //     [0x1044] TimeDateStamp (0)
    //     [0x1048] MajorVersion/MinorVersion (0)
    //     [0x104C] NamedEntries(0) / IDEntries(1) ← language 1033
    //     [0x1050] Entry: ID=1033, data entry offset=0x60
    //
    //   RVA 0x1060: Data entry for group icon
    //     [0x1060] DataRVA = 0x1100 (GRPICONDIR data)
    //     [0x1064] Size
    //     [0x1068] Codepage (0)
    //     [0x106C] Reserved (0)
    //
    //   RVA 0x1080: Type subdirectory for RT_ICON (ID=3)
    //     [0x1080] Characteristics (0)
    //     [0x1084] TimeDateStamp (0)
    //     [0x1088] MajorVersion/MinorVersion (0)
    //     [0x108C] NamedEntries(0) / IDEntries(1) ← Name ID=2
    //     [0x1090] Entry: ID=2, subdir offset=0xa0
    //
    //   RVA 0x10A0: Name subdirectory for icon name=2
    //     [0x10A0] Characteristics (0)
    //     [0x10A4] TimeDateStamp (0)
    //     [0x10A8] MajorVersion/MinorVersion (0)
    //     [0x10AC] NamedEntries(0) / IDEntries(1) ← language 1033
    //     [0x10B0] Entry: ID=1033, data entry offset=0xc0
    //
    //   RVA 0x10C0: Data entry for RT_ICON
    //     [0x10C0] DataRVA = 0x1200 (DIB pixel data)
    //     [0x10C4] Size
    //     [0x10C8] Codepage (0)
    //     [0x10CC] Reserved (0)
    //
    //   RVA 0x1100: GRPICONDIR data
    //     [0x1100] Reserved(0) + Type(1) + Count(1)
    //     [0x1106] 14-byte GRPICONDIRENTRY: width=32, height=32, colors=0,
    //              reserved=0, planes=1, bpp=32, size_in_bytes, icon_id=2
    //
    //   RVA 0x1200: RT_ICON bitmap data (32bpp DIB, 32×32)
    //     BMP info header + XOR mask + AND mask

    let section_rva = 0x1000u32;
    let _root_rva = section_rva;

    // Helper to write u16 and u32 at an RVA offset (relative to section start)
    let data_start = 0x1000usize;
    let w16 = |pe: &mut Vec<u8>, rva: u32, val: u16| {
        let off = data_start + (rva - section_rva) as usize;
        if off + 2 <= pe.len() {
            pe[off..off + 2].copy_from_slice(&val.to_le_bytes());
        }
    };
    let w32 = |pe: &mut Vec<u8>, rva: u32, val: u32| {
        let off = data_start + (rva - section_rva) as usize;
        if off + 4 <= pe.len() {
            pe[off..off + 4].copy_from_slice(&val.to_le_bytes());
        }
    };

    // Ensure enough space
    pe.resize(0x1400, 0);

    // Root resource directory at 0x1000
    w32(&mut pe, 0x1000, 0); // Characteristics
    w32(&mut pe, 0x1004, 0); // TimeDateStamp
    w16(&mut pe, 0x100C, 0); // NamedEntries
    w16(&mut pe, 0x100E, 2); // IDEntries (2 types: 14 and 3)

    // Entry 0: Type 14 (RT_GROUP_ICON) → subdir at offset 0x20 (relative to root)
    w32(&mut pe, 0x1010, 14);
    w32(&mut pe, 0x1014, 0x8000_0020); // subdir at RVA 0x1000 + 0x20 = 0x1020

    // Entry 1: Type 3 (RT_ICON) → subdir at offset 0x80
    w32(&mut pe, 0x1018, 3);
    w32(&mut pe, 0x101C, 0x8000_0080); // subdir at RVA 0x1000 + 0x80 = 0x1080

    // ── Type 14 subdirectory at 0x1020 ─────────────────────────────────────
    w32(&mut pe, 0x1020, 0);
    w32(&mut pe, 0x1024, 0);
    w16(&mut pe, 0x102C, 0); // Named
    w16(&mut pe, 0x102E, 1); // ID entries (=1)
    // Name ID=1 → subdir at offset 0x40 (→ 0x1040)
    w32(&mut pe, 0x1030, 1);
    w32(&mut pe, 0x1034, 0x8000_0040);

    // ── Name ID=1 subdirectory at 0x1040 (language level) ────────────────────
    w32(&mut pe, 0x1040, 0);
    w32(&mut pe, 0x1044, 0);
    w16(&mut pe, 0x104C, 0);
    w16(&mut pe, 0x104E, 1); // 1 language entry
    w32(&mut pe, 0x1050, 1033); // Language 1033 (en-US)
    w32(&mut pe, 0x1054, 0x0060); // data entry at RVA 0x1000+0x60=0x1060 (no high bit = data entry, not subdirectory)

    // ── Data entry for group icon at 0x1060 ──────────────────────────────────
    w32(&mut pe, 0x1060, 0x1100); // Data RVA → GRPICONDIR at 0x1100
    w32(&mut pe, 0x1064, 0x0014); // Size = 20 bytes (6 header + 14 entry)
    w32(&mut pe, 0x1068, 0); // Codepage
    w32(&mut pe, 0x106C, 0); // Reserved

    // ── Type 3 subdirectory at 0x1080 ──────────────────────────────────────
    w32(&mut pe, 0x1080, 0);
    w32(&mut pe, 0x1084, 0);
    w16(&mut pe, 0x108C, 0);
    w16(&mut pe, 0x108E, 1);
    // Name ID=2 → subdir at offset 0xA0 (→ 0x10A0)
    w32(&mut pe, 0x1090, 2);
    w32(&mut pe, 0x1094, 0x8000_00A0);

    // ── Name ID=2 subdirectory at 0x10A0 ────────────────────────────────────
    w32(&mut pe, 0x10A0, 0);
    w32(&mut pe, 0x10A4, 0);
    w16(&mut pe, 0x10AC, 0);
    w16(&mut pe, 0x10AE, 1);
    w32(&mut pe, 0x10B0, 1033);
    w32(&mut pe, 0x10B4, 0x00C0); // data entry at RVA 0x1000+0xC0=0x10C0 (no high bit = data entry, not subdirectory)

    // ── Data entry for RT_ICON at 0x10C0 ─────────────────────────────────────
    w32(&mut pe, 0x10C0, 0x1200); // Data RVA → icon pixels at 0x1200
    w32(&mut pe, 0x10C4, 0x0A28); // Size = 2600 bytes (approx for 32×32 32bpp DIB)
    w32(&mut pe, 0x10C8, 0);
    w32(&mut pe, 0x10CC, 0);

    // ── GRPICONDIR data at RVA 0x1100 ───────────────────────────────────────
    w16(&mut pe, 0x1100, 0); // Reserved
    w16(&mut pe, 0x1102, 1); // Type = ICO
    w16(&mut pe, 0x1104, 1); // Count = 1

    // GRPICONDIRENTRY: width=32, height=32, colors=0, reserved=0,
    //                  planes=1, bpp=32, size_in_bytes, icon_id=2
    pe[0x1106] = 32; // width
    pe[0x1107] = 32; // height
    pe[0x1108] = 0; // colors
    pe[0x1109] = 0; // reserved
    w16(&mut pe, 0x110A, 1); // planes
    w16(&mut pe, 0x110C, 32); // bpp
    w32(&mut pe, 0x110E, 0x0A28); // size
    w16(&mut pe, 0x1112, 2); // icon_id (links to RT_ICON name ID)

    // ── RT_ICON bitmap data at RVA 0x1200 ────────────────────────────────────
    // Build a minimal 32×32 32bpp DIB:
    //   BITMAPINFOHEADER (40 bytes)
    //   Pixel data (32*32*4 = 4096 bytes)  — BGRA, bottom-up
    //   AND mask (32*4 = 128 bytes) — 1bpp, row-padded to 32 bits
    let bmp_header_offset = data_start + (0x1200 - section_rva) as usize;
    // Ensure space
    pe.resize(bmp_header_offset + 0x0A28, 0);

    // BITMAPINFOHEADER (40 bytes)
    // biSize = 40
    w32(&mut pe, 0x1200, 40);
    // biWidth = 32
    w32(&mut pe, 0x1204, 32);
    // biHeight = 64 (32 pixels × 2 for XOR + AND mask)
    w32(&mut pe, 0x1208, 64);
    // biPlanes = 1
    w16(&mut pe, 0x120C, 1);
    // biBitCount = 32
    w16(&mut pe, 0x120E, 32);
    // biCompression = BI_RGB (0)
    w32(&mut pe, 0x1210, 0);
    // biSizeImage = 0 (can be 0 for BI_RGB)
    w32(&mut pe, 0x1214, 0);
    w32(&mut pe, 0x1218, 0); // biXPelsPerMeter
    w32(&mut pe, 0x121C, 0); // biYPelsPerMeter
    w32(&mut pe, 0x1220, 0); // biClrUsed
    w32(&mut pe, 0x1224, 0); // biClrImportant

    // Pixel data (32bpp BGRA): fill with a simple pattern
    // Each row: 32 * 4 = 128 bytes
    for y in 0..32u32 {
        let row_offset = bmp_header_offset + 40 + ((31 - y) * 128) as usize; // bottom-up
        for x in 0..32u32 {
            let pixel_off = row_offset + (x * 4) as usize;
            if pixel_off + 4 <= pe.len() {
                // Create a red/blue checkerboard pattern
                if (x + y) % 2 == 0 {
                    pe[pixel_off] = 0; // B
                    pe[pixel_off + 1] = 0; // G
                    pe[pixel_off + 2] = 255; // R
                } else {
                    pe[pixel_off] = 255; // B
                    pe[pixel_off + 1] = 0; // G
                    pe[pixel_off + 2] = 0; // R
                }
                pe[pixel_off + 3] = 255; // A
            }
        }
    }

    // AND mask (1bpp, row-padded to 32 bits) — 32 rows × 4 bytes = 128 bytes
    let and_mask_offset = bmp_header_offset + 40 + 4096; // after pixel data
    for i in 0..128usize {
        if and_mask_offset + i < pe.len() {
            pe[and_mask_offset + i] = 0; // fully opaque (0 = visible)
        }
    }

    pe
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_find_resource_group_icons() {
    let pe_data = build_test_pe_with_icon();
    let groups = casa1::pe::find_resource_group_icons(&pe_data)
        .expect("find_resource_group_icons should succeed");

    assert!(!groups.is_empty(), "should find at least one group icon");
    let group = &groups[0];
    assert_eq!(group.header.reserved, 0);
    assert_eq!(group.header.ty, 1); // ICO type
    assert_eq!(group.header.count, 1);
    assert!(!group.entries.is_empty(), "group should have entries");
    let entry = &group.entries[0];
    assert_eq!(entry.width, 32);
    assert_eq!(entry.height, 32);
    assert_eq!(entry.bpp, 32);
    assert_eq!(entry.planes, 1);
}

#[test]
fn test_extract_all_icons_from_pe() {
    let pe_data = build_test_pe_with_icon();
    let icons = casa1::pe::extract_all_icons_from_pe(&pe_data)
        .expect("extract_all_icons_from_pe should succeed");

    assert!(!icons.is_empty(), "should extract at least one icon");
    let icon = &icons[0];
    assert_eq!(icon.width, 32);
    assert_eq!(icon.height, 32);
    assert_eq!(icon.bpp, 32);
    assert!(!icon.data.is_empty(), "icon data should not be empty");
}

#[test]
fn test_extract_icon_from_pe() {
    let pe_data = build_test_pe_with_icon();
    let icons =
        casa1::pe::extract_icon_from_pe(&pe_data).expect("extract_icon_from_pe should succeed");

    assert!(!icons.is_empty(), "should extract at least one icon");
    // The extracted icon should be 32×32 (our test data)
    let icon = &icons[0];
    assert_eq!(icon.width, 32);
    assert_eq!(icon.height, 32);
}

#[test]
fn test_icon_dir_header_structure() {
    use casa1::pe::IconDirHeader;
    use std::mem::transmute;
    // Test repr(C) layout: reserved(u16) + type(u16) + count(u16) = 6 bytes
    let raw: [u8; 6] = [0x00, 0x00, 0x01, 0x00, 0x05, 0x00];
    let header: IconDirHeader = unsafe { transmute::<[u8; 6], IconDirHeader>(raw) };
    assert_eq!(header.reserved, 0);
    assert_eq!(header.ty, 1);
    assert_eq!(header.count, 5);
}

#[test]
fn test_icon_dir_entry_structure() {
    use casa1::pe::IconDirEntry;
    use std::mem::transmute;
    // Build a 16-byte entry: w=32, h=32, colors=0, reserved=0,
    // planes=1, bpp=32, size=4096, offset=22
    let raw: [u8; 16] = [
        32, // width
        32, // height
        0,  // colors
        0,  // reserved
        0x01, 0x00, // planes = 1 (le)
        0x20, 0x00, // bpp = 32 (le)
        0x00, 0x10, 0x00, 0x00, // size = 4096 (le)
        0x16, 0x00, 0x00, 0x00, // offset = 22 (le)
    ];
    let entry: IconDirEntry = unsafe { transmute::<[u8; 16], IconDirEntry>(raw) };
    assert_eq!(entry.width, 32);
    assert_eq!(entry.height, 32);
    assert_eq!(entry.colors, 0);
    assert_eq!(entry.planes, 1);
    assert_eq!(entry.bpp, 32);
    assert_eq!(entry.size, 4096);
    assert_eq!(entry.offset, 22);
}

#[test]
fn test_icon_image_dimensions() {
    let pe_data = build_test_pe_with_icon();
    let icons = casa1::pe::extract_all_icons_from_pe(&pe_data).expect("extract icons");

    for icon in &icons {
        assert!(icon.width > 0, "width must be positive");
        assert!(icon.height > 0, "height must be positive");
        assert!(icon.bpp == 32, "expected 32bpp");
    }
}

#[test]
fn test_ico_header_parsing() {
    // Build a minimal ICO file for testing
    let ico = build_test_ico();
    let result = casa1::icon::ico_to_icns(&ico);
    assert!(result.is_ok(), "ico_to_icns should succeed for valid ICO");
    let icns = result.unwrap();
    assert!(casa1::icon::validate_icns(&icns).unwrap_or(false));
}

#[test]
fn test_png_conversion_of_dib() {
    // Create a 4×4 32bpp DIB with XOR mask (height=8 for XOR+AND)
    let width = 4u32;
    let height = 8u32;
    let bpp = 32u16;
    let row_size = (width * bpp as u32).div_ceil(32) * 4;
    let mut dib = vec![0u8; (row_size * height) as usize];

    // Write a bottom-up DIB: 4 rows of red pixels at top, blue at bottom
    for y in 0..4 {
        let src_y = height - 1 - y; // bottom-up: last row in DIB = top of image
        for x in 0..4 {
            let off = (src_y * row_size + x * 4) as usize;
            if off + 4 <= dib.len() {
                dib[off] = 0; // B
                dib[off + 1] = 0; // G
                dib[off + 2] = 255; // R
                dib[off + 3] = 255; // A
            }
        }
    }

    let png = casa1::icon::dib_to_png(&dib, width, height, bpp).expect("dib_to_png should succeed");
    assert!(
        png[0..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
        "should produce valid PNG signature"
    );
}

#[test]
fn test_icns_structure_generation() {
    use casa1::icon::{IconImage, icons_to_icns, validate_icns};

    let icons = vec![
        IconImage {
            width: 16,
            height: 16,
            bpp: 32,
            data: vec![0u8; 16 * 16 * 4],
            is_png_compressed: false,
            xor_mask: None,
        },
        IconImage {
            width: 32,
            height: 32,
            bpp: 32,
            data: vec![0u8; 32 * 32 * 4],
            is_png_compressed: false,
            xor_mask: None,
        },
    ];

    let icns = icons_to_icns(&icons).expect("icons_to_icns should succeed");
    assert!(
        validate_icns(&icns).unwrap_or(false),
        "ICNS should be valid"
    );

    // Verify the icns magic
    assert_eq!(&icns[0..4], b"icns", "should start with icns magic");

    // Verify total size
    let total_size = u32::from_be_bytes([icns[4], icns[5], icns[6], icns[7]]) as usize;
    assert_eq!(total_size, icns.len(), "total size should match");
}

#[test]
fn test_round_trip_pe_to_icns() {
    let pe_data = build_test_pe_with_icon();
    let icons = casa1::pe::extract_all_icons_from_pe(&pe_data).expect("extract icons from PE");

    assert!(!icons.is_empty(), "should have extracted icons");

    // Convert to ICNS
    let icns = casa1::icon::icons_to_icns(&icons).expect("icons_to_icns should succeed");

    // Validate ICNS structure
    assert!(
        casa1::icon::validate_icns(&icns).unwrap_or(false),
        "ICNS output should be structurally valid"
    );

    // Verify at least one ICNS entry is present (beyond the header)
    assert!(
        icns.len() > 8,
        "ICNS should contain entries beyond the header"
    );
}

#[test]
fn test_validate_icns_rejects_invalid() {
    assert!(!casa1::icon::validate_icns(b"").unwrap_or(false));
    assert!(!casa1::icon::validate_icns(b"icns").unwrap_or(false));
    assert!(!casa1::icon::validate_icns(b"not an icns file").unwrap_or(false));
}

#[test]
fn test_ico_parsing_empty() {
    let ico = vec![0, 0, 1, 0, 0, 0]; // valid ICO header, 0 icons
    let result = casa1::icon::ico_to_icns(&ico);
    assert!(result.is_ok(), "empty ICO should produce ok");
    let icns = result.unwrap();
    assert!(casa1::icon::validate_icns(&icns).unwrap_or(false));
    // ICNS with 0 entries: just the 8-byte header
    assert_eq!(icns.len(), 8, "empty ICNS should be 8 bytes");
}

#[test]
fn test_missing_resource_returns_empty() {
    // A valid PE but with no .rsrc section
    let pe_data = build_minimal_pe_no_resources();
    let icons = casa1::pe::extract_all_icons_from_pe(&pe_data)
        .expect("should not error on PE without resources");
    assert!(icons.is_empty(), "no icons should be found");
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn build_test_ico() -> Vec<u8> {
    // Build a minimal ICO file with a single 16×16 32bpp entry
    let width = 16u32;
    let height = 16u32;
    let bpp = 32u16;
    let row_size = (width * bpp as u32).div_ceil(32) * 4;
    let pixel_data_size = (row_size * height) as usize;
    // AND mask size: row padded to 32 bits
    let and_row_size = width.div_ceil(32) * 4;
    let and_mask_size = (and_row_size * height) as usize;
    let dib_size = 40 + pixel_data_size + and_mask_size; // header + XOR + AND

    let mut ico = Vec::new();
    // ICO header
    ico.extend_from_slice(&0u16.to_le_bytes()); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // type = ICO
    ico.extend_from_slice(&1u16.to_le_bytes()); // count = 1
    // Directory entry
    ico.push(width as u8); // width
    ico.push(height as u8); // height
    ico.push(0); // color count
    ico.push(0); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // planes
    ico.extend_from_slice(&bpp.to_le_bytes()); // bpp
    ico.extend_from_slice(&(dib_size as u32).to_le_bytes()); // size
    ico.extend_from_slice(&22u32.to_le_bytes()); // offset (after header + 1 entry)

    // DIB data
    // BITMAPINFOHEADER
    ico.extend_from_slice(&40u32.to_le_bytes()); // biSize
    ico.extend_from_slice(&width.to_le_bytes()); // biWidth
    ico.extend_from_slice(&(height * 2).to_le_bytes()); // biHeight (XOR+AND)
    ico.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    ico.extend_from_slice(&bpp.to_le_bytes()); // biBitCount
    ico.extend_from_slice(&0u32.to_le_bytes()); // biCompression = BI_RGB
    ico.extend_from_slice(&0u32.to_le_bytes()); // biSizeImage
    ico.extend_from_slice(&0u32.to_le_bytes()); // biXPelsPerMeter
    ico.extend_from_slice(&0u32.to_le_bytes()); // biYPelsPerMeter
    ico.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    ico.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

    // Pixel data (bottom-up BGRA) — solid red
    for y in 0..height {
        // bottom-up: last row first
        let row_start = (height - 1 - y) as usize * row_size as usize;
        while ico.len() < 22 + 40 + row_start + (width as usize * 4) {
            ico.push(0);
        }
        for _x in 0..width as usize {
            ico.push(0); // B
            ico.push(0); // G
            ico.push(255); // R
            ico.push(255); // A
        }
        // Row padding
        while ico.len() < 22 + 40 + row_start + row_size as usize {
            ico.push(0);
        }
    }

    // AND mask (all zeros = opaque)
    for _y in 0..height {
        for _x in 0..and_row_size as usize {
            ico.push(0);
        }
    }

    ico
}

fn build_minimal_pe_no_resources() -> Vec<u8> {
    // Build a minimal PE32 file with no resource directory.
    // Size must be large enough for all section raw data (raw_data_ptr + raw_data_size).
    let mut pe = vec![0u8; 0x2000];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C] = 0x40;

    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    pe[0x44..0x46].copy_from_slice(&0x014c_u16.to_le_bytes()); // machine x86
    pe[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[0x54..0x56].copy_from_slice(&0x00E0u16.to_le_bytes()); // size of optional header
    pe[0x56..0x58].copy_from_slice(&0x0102u16.to_le_bytes()); // characteristics

    // Optional header (minimal)
    pe[0x58..0x5A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    pe[0x74..0x78].copy_from_slice(&0x00400000u32.to_le_bytes()); // image base
    // Section alignment at optional_offset + 32 = 0x58 + 32 = 0x78
    pe[0x78..0x7C].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    // File alignment at optional_offset + 36 = 0x58 + 36 = 0x7C
    pe[0x7C..0x80].copy_from_slice(&0x0200u32.to_le_bytes()); // file alignment
    pe[0x90..0x94].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
    pe[0x94..0x98].copy_from_slice(&0x1000u32.to_le_bytes()); // size of headers
    pe[0xC4..0xC8].copy_from_slice(&16u32.to_le_bytes()); // # data directories

    // No resource directory (all zeros at offset 0xB8)
    // Section: .text
    let sec_off = 0x138usize;
    pe[sec_off..sec_off + 8].copy_from_slice(b".text\0\0\0");
    pe[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual size
    pe[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
    pe[sec_off + 16..sec_off + 20].copy_from_slice(&0x0200u32.to_le_bytes()); // raw data size
    pe[sec_off + 20..sec_off + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // raw data ptr
    pe[sec_off + 36..sec_off + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // code + execute

    pe
}
