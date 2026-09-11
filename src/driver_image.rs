//! Real PE driver-image loader.
//!
//! Parses a Windows `.sys` driver image from bytes, maps its sections into a
//! zeroed image at a chosen base, applies base relocations, classifies its
//! imports into the kernel API sets (ntoskrnl / HAL / KMDF / other) behind a
//! caller-provided resolver, and describes the `DriverEntry`/unload entry
//! points.  This is the image half of the sandboxed driver island: it never
//! executes guest code; the CasaK I/O layer drives the mapped image.

/// The image is not a valid PE file.
pub const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
/// The file does not start with an MZ signature.
pub const STATUS_INVALID_IMAGE_NOT_MZ: u32 = 0xC000_012F;
/// The PE header is structurally invalid for loading.
pub const STATUS_INVALID_IMAGE_PROTECT: u32 = 0xC000_0100;
/// A 32-bit image was loaded into a 64-bit loader (or vice versa).
pub const STATUS_INVALID_IMAGE_WIN_32: u32 = 0xC000_0127;
/// A 64-bit image was loaded into a 32-bit loader.
pub const STATUS_INVALID_IMAGE_WIN_64: u32 = 0xC000_0128;
/// The PE checksum field is non-zero and does not match the computed checksum.
pub const STATUS_IMAGE_CHECKSUM_MISMATCH: u32 = 0xC000_0221;

/// The kernel API set an import belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelApiSet {
    /// `ntoskrnl.exe` and its aliases (ntkrnlpa/ntkrnlmp/ntoskrnl) — WDM.
    Ntoskrnl,
    /// `hal.dll`.
    Hal,
    /// `WdfLdr.sys` / `Wdf01000.sys` — KMDF.
    Kmdf,
    /// Any other import module (user-mode-shaped or unknown).
    Other,
}

impl KernelApiSet {
    /// Classify an import DLL name (case-insensitive) into its kernel set.
    pub fn classify(dll: &str) -> Self {
        let lower = dll.to_ascii_lowercase();
        match lower.as_str() {
            "ntoskrnl.exe" | "ntkrnlpa.exe" | "ntkrnlmp.exe" | "ntoskrnl" => Self::Ntoskrnl,
            "hal.dll" => Self::Hal,
            "wdfldr.sys" | "wdf01000.sys" | "wdfldr" | "wdf01000" => Self::Kmdf,
            _ => Self::Other,
        }
    }
}

/// One imported symbol (by name or ordinal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportRef {
    /// Imported by name (the hint is informational).
    Name(String),
    /// Imported by ordinal.
    Ordinal(u16),
}

impl ImportRef {
    /// A display name for reports (`"Name"` or `"#ordinal"`).
    pub fn display(&self) -> String {
        match self {
            ImportRef::Name(name) => name.clone(),
            ImportRef::Ordinal(ordinal) => format!("#{ordinal}"),
        }
    }
}

/// One import module and its symbols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportModule {
    /// The DLL/module name exactly as recorded in the image.
    pub dll: String,
    /// The kernel API set the module belongs to.
    pub set: KernelApiSet,
    /// The imported symbols in thunk order.
    pub symbols: Vec<ImportRef>,
    /// The first-thunk RVA (the IAT that must be patched on load).
    pub first_thunk_rva: u32,
}

/// One delay-loaded import module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayImport {
    /// The module name.
    pub dll: String,
    /// The delay import-address-table RVA.
    pub iat_rva: u32,
    /// The import-name-table RVA.
    pub int_rva: u32,
    /// The timestamp (0 for unbound).
    pub timestamp: u32,
    /// The imported symbols.
    pub symbols: Vec<ImportRef>,
}

/// One exported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSymbolInfo {
    /// The symbol name.
    pub name: String,
    /// The export RVA.
    pub rva: u32,
    /// The ordinal (base + index).
    pub ordinal: u16,
}

/// One loaded section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSection {
    /// The section name (NUL-padded names are trimmed).
    pub name: String,
    /// The section RVA.
    pub rva: u32,
    /// The virtual size.
    pub virtual_size: u32,
    /// The raw file size.
    pub raw_size: u32,
    /// The section characteristics.
    pub characteristics: u32,
    /// Whether this is the discardable `.INIT` section.
    pub is_init: bool,
}

impl LoadedSection {
    /// Whether the section is executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// Whether the section is writable.
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    /// Whether the section can be discarded after initialization.
    pub fn is_discardable(&self) -> bool {
        self.characteristics & 0x0200_0000 != 0
    }
}

/// TLS directory facts recorded from data directory 9.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInfo {
    /// The TLS directory RVA.
    pub directory_rva: u32,
    /// The directory size.
    pub directory_size: u32,
    /// The number of TLS callbacks (0 when none).
    pub callback_count: u32,
}

/// The version resource facts (`VS_FIXEDFILEINFO`) when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    /// The RT_VERSION resource RVA.
    pub resource_rva: u32,
    /// The resource size.
    pub resource_size: u32,
    /// The `dwFileVersionMS` field (0 when the fixed info is absent).
    pub file_version_ms: u32,
    /// The `dwFileVersionLS` field.
    pub file_version_ls: u32,
}

/// A parsed and mapped driver image.
pub struct LoadedDriver {
    /// The base the image was mapped at.
    pub base: u64,
    /// The image buffer (`size_of_image` bytes, sections copied, zero-filled).
    pub image: Vec<u8>,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `AddressOfEntryPoint` (the `DriverEntry` RVA).
    pub entry_rva: u32,
    /// The exported unload routine RVA, when one is exported.
    pub unload_rva: Option<u32>,
    /// The image machine (`0x8664` or `0x14C`).
    pub machine: u16,
    /// The loaded sections.
    pub sections: Vec<LoadedSection>,
    /// The import modules.
    pub imports: Vec<ImportModule>,
    /// The delay-import modules.
    pub delay_imports: Vec<DelayImport>,
    /// The exported symbols.
    pub exports: Vec<ExportSymbolInfo>,
    /// TLS facts when the image has TLS.
    pub tls: Option<TlsInfo>,
    /// Version resource facts when present.
    pub version: Option<VersionInfo>,
    /// The preferred base recorded in the header.
    pub preferred_base: u64,
}

/// A driver-import resolver: the future CasaK layer implements this to map
/// kernel API names to real host thunks.
pub trait ImportResolver {
    /// Resolve one imported symbol to an address, if the set is backed.
    fn resolve(&self, set: KernelApiSet, dll: &str, symbol: &ImportRef) -> Option<u64>;
}

/// The result of resolving every import of a driver image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    /// `(dll, symbol, set)` for every resolved import.
    pub resolved: Vec<(String, String, KernelApiSet)>,
    /// `(dll, symbol, set)` for every unresolved import.
    pub unresolved: Vec<(String, String, KernelApiSet)>,
}

/// Little-endian readers over a byte slice.
fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8).map(|bytes| {
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])
    })
}

fn read_c_string(data: &[u8], offset: usize, limit: usize) -> Option<String> {
    let tail = data.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0)? + offset;
    if end - offset > limit {
        return None;
    }
    std::str::from_utf8(data.get(offset..end)?)
        .ok()
        .map(str::to_string)
}

/// Compute the documented PE checksum over a complete file image.
///
/// The four-byte checksum field itself (optional-header offset 64) is treated
/// as zero while summing; the file length is added at the end.
pub fn pe_checksum(data: &[u8]) -> u32 {
    let checksum_field = u32_at(data, 0x3C)
        .map(|pe_offset| pe_offset as usize + 4 + 20 + 64)
        .filter(|offset| offset + 4 <= data.len());
    let mut sum: u64 = 0;
    let mut index = 0;
    while index + 1 < data.len() {
        let (low, high) = if checksum_field.is_some_and(|field| index >= field && index < field + 4)
        {
            (0_u8, 0_u8)
        } else {
            (data[index], data[index + 1])
        };
        let word = u16::from_le_bytes([low, high]) as u64;
        sum += word;
        sum = (sum & 0xFFFF) + (sum >> 16);
        index += 2;
    }
    if index < data.len() {
        sum += data[index] as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    (sum as u32).wrapping_add(data.len() as u32)
}

/// Parse, map and relocate a driver image.
///
/// `actual_base` is the address the image is mapped at; relocations are
/// applied when it differs from the preferred base recorded in the header.
pub fn load_driver_image(data: &[u8], actual_base: u64) -> Result<LoadedDriver, u32> {
    if data.len() < 0x40 || u16_at(data, 0) != Some(0x5A4D) {
        return Err(STATUS_INVALID_IMAGE_NOT_MZ);
    }
    let pe_offset = u32_at(data, 0x3C).ok_or(STATUS_INVALID_IMAGE_FORMAT)? as usize;
    if u32_at(data, pe_offset) != Some(0x0000_4550) {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    let coff = pe_offset + 4;
    let machine = u16_at(data, coff).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    if machine != 0x8664 && machine != 0x014C {
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    let number_of_sections = u16_at(data, coff + 2).ok_or(STATUS_INVALID_IMAGE_FORMAT)? as usize;
    let optional_size = u16_at(data, coff + 16).ok_or(STATUS_INVALID_IMAGE_FORMAT)? as usize;
    let optional = coff + 20;
    let magic = u16_at(data, optional).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let is_64 = match (machine, magic) {
        (0x8664, 0x020B) => true,
        (0x014C, 0x010B) => false,
        (0x8664, 0x010B) => return Err(STATUS_INVALID_IMAGE_WIN_32),
        (0x014C, 0x020B) => return Err(STATUS_INVALID_IMAGE_WIN_64),
        _ => return Err(STATUS_INVALID_IMAGE_FORMAT),
    };
    let entry_rva = u32_at(data, optional + 16).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let image_base = if is_64 {
        u64_at(data, optional + 24).ok_or(STATUS_INVALID_IMAGE_FORMAT)?
    } else {
        u32_at(data, optional + 28).ok_or(STATUS_INVALID_IMAGE_FORMAT)? as u64
    };
    let section_alignment = u32_at(data, optional + 32).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let file_alignment = u32_at(data, optional + 36).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let size_of_image = u32_at(data, optional + 56).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let size_of_headers = u32_at(data, optional + 60).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let checksum_field = u32_at(data, optional + 64).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    let subsystem = u16_at(data, optional + 68).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
    if subsystem != 1 {
        // IMAGE_SUBSYSTEM_NATIVE is required for drivers.
        return Err(STATUS_INVALID_IMAGE_FORMAT);
    }
    if section_alignment == 0
        || section_alignment < 0x1000
        || file_alignment == 0
        || file_alignment > section_alignment
        || size_of_image == 0
        || size_of_headers > size_of_image
    {
        return Err(STATUS_INVALID_IMAGE_PROTECT);
    }
    if checksum_field != 0 && pe_checksum(data) != checksum_field {
        return Err(STATUS_IMAGE_CHECKSUM_MISMATCH);
    }
    let directory_count = u32_at(data, optional + (if is_64 { 108 } else { 92 }))
        .ok_or(STATUS_INVALID_IMAGE_FORMAT)? as usize;
    let directories = optional + (if is_64 { 112 } else { 96 });
    let directory = |index: usize| -> Option<(u32, u32)> {
        if index >= directory_count {
            return None;
        }
        let offset = directories + index * 8;
        Some((u32_at(data, offset)?, u32_at(data, offset + 4)?))
    };

    // Map the sections into a zeroed image of SizeOfImage bytes.
    let mut image = vec![0_u8; size_of_image as usize];
    let headers_len = (size_of_headers as usize).min(data.len()).min(image.len());
    image[..headers_len].copy_from_slice(&data[..headers_len]);
    let section_table = optional + optional_size;
    let mut sections = Vec::with_capacity(number_of_sections);
    for index in 0..number_of_sections {
        let entry = section_table + index * 40;
        let mut name_bytes = [0_u8; 8];
        name_bytes.copy_from_slice(
            data.get(entry..entry + 8)
                .ok_or(STATUS_INVALID_IMAGE_FORMAT)?,
        );
        let name_len = name_bytes.iter().position(|byte| *byte == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_len]).into_owned();
        let virtual_size = u32_at(data, entry + 8).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
        let rva = u32_at(data, entry + 12).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
        let raw_size = u32_at(data, entry + 16).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
        let raw_offset = u32_at(data, entry + 20).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
        let characteristics = u32_at(data, entry + 36).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
        let copy_len = (raw_size as usize)
            .min(data.len().saturating_sub(raw_offset as usize))
            .min(image.len().saturating_sub(rva as usize));
        if copy_len > 0 {
            let source = raw_offset as usize;
            let target = rva as usize;
            image[target..target + copy_len].copy_from_slice(&data[source..source + copy_len]);
        }
        sections.push(LoadedSection {
            is_init: name == ".INIT",
            name,
            rva,
            virtual_size,
            raw_size,
            characteristics,
        });
    }

    // Apply base relocations when the image is not at its preferred base.
    if actual_base != image_base {
        let delta = (actual_base as i128) - (image_base as i128);
        if let Some((reloc_rva, reloc_size)) = directory(5).filter(|(_, size)| *size > 0) {
            let start = reloc_rva as usize;
            let end = start.saturating_add(reloc_size as usize).min(image.len());
            let mut cursor = start;
            while cursor + 8 <= end {
                let page_rva = u32_at(&image, cursor).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                let block_size = u32_at(&image, cursor + 4).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                if block_size == 0 {
                    break;
                }
                if block_size < 8 || cursor + block_size as usize > end {
                    return Err(STATUS_INVALID_IMAGE_FORMAT);
                }
                let entries_end = cursor + block_size as usize;
                let mut entry = cursor + 8;
                while entry + 2 <= entries_end {
                    let raw = u16_at(&image, entry).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                    let kind = (raw >> 12) as u32;
                    let offset = (raw & 0x0FFF) as u32;
                    match kind {
                        0 => {}
                        3 => {
                            let target = (page_rva + offset) as usize;
                            if target + 4 <= image.len() {
                                let old = u32_at(&image, target)
                                    .ok_or(STATUS_INVALID_IMAGE_FORMAT)?
                                    as i128;
                                let new = (old + delta) as u32;
                                image[target..target + 4].copy_from_slice(&new.to_le_bytes());
                            }
                        }
                        10 => {
                            let target = (page_rva + offset) as usize;
                            if target + 8 <= image.len() {
                                let old = u64_at(&image, target)
                                    .ok_or(STATUS_INVALID_IMAGE_FORMAT)?
                                    as i128;
                                let new = (old + delta) as u64;
                                image[target..target + 8].copy_from_slice(&new.to_le_bytes());
                            }
                        }
                        _ => {}
                    }
                    entry += 2;
                }
                cursor += block_size as usize;
            }
        }
    }

    // Imports.
    let mut imports = Vec::new();
    if let Some((import_rva, import_size)) = directory(1).filter(|(_, size)| *size > 0) {
        let mut descriptor = import_rva as usize;
        let descriptors_end = descriptor.saturating_add(import_size as usize);
        while descriptor + 20 <= descriptors_end {
            let original_first_thunk =
                u32_at(&image, descriptor).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let name_rva = u32_at(&image, descriptor + 12).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let first_thunk = u32_at(&image, descriptor + 16).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            let dll =
                read_c_string(&image, name_rva as usize, 260).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };
            let mut symbols = Vec::new();
            let mut thunk = thunk_rva as usize;
            loop {
                let value = if is_64 {
                    u64_at(&image, thunk).ok_or(STATUS_INVALID_IMAGE_FORMAT)?
                } else {
                    u32_at(&image, thunk).ok_or(STATUS_INVALID_IMAGE_FORMAT)? as u64
                };
                thunk += if is_64 { 8 } else { 4 };
                if value == 0 {
                    break;
                }
                let ordinal_flag = if is_64 {
                    0x8000_0000_0000_0000
                } else {
                    0x8000_0000
                };
                if value & ordinal_flag != 0 {
                    symbols.push(ImportRef::Ordinal((value & 0xFFFF) as u16));
                } else {
                    let name = read_c_string(&image, value as usize + 2, 260)
                        .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                    symbols.push(ImportRef::Name(name));
                }
            }
            let set = KernelApiSet::classify(&dll);
            imports.push(ImportModule {
                dll,
                set,
                symbols,
                first_thunk_rva: first_thunk,
            });
            descriptor += 20;
        }
    }

    // Delay imports.
    let mut delay_imports = Vec::new();
    if let Some((delay_rva, delay_size)) = directory(13).filter(|(_, size)| *size > 0) {
        let mut descriptor = delay_rva as usize;
        let descriptors_end = descriptor.saturating_add(delay_size as usize);
        while descriptor + 32 <= descriptors_end {
            let attributes = u32_at(&image, descriptor).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            if attributes == 0 {
                break;
            }
            let name_rva = u32_at(&image, descriptor + 4).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let iat_rva = u32_at(&image, descriptor + 12).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let int_rva = u32_at(&image, descriptor + 16).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let timestamp = u32_at(&image, descriptor + 28).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let dll = if name_rva == 0 {
                String::new()
            } else {
                read_c_string(&image, name_rva as usize, 260).ok_or(STATUS_INVALID_IMAGE_FORMAT)?
            };
            // Real delay-import descriptors store RVAs before the image is
            // loaded; attributes bit 0 tells the loader the fields are RVAs.
            let mut symbols = Vec::new();
            if attributes & 1 != 0 && int_rva != 0 {
                let mut thunk = int_rva as usize;
                loop {
                    let value = if is_64 {
                        u64_at(&image, thunk).ok_or(STATUS_INVALID_IMAGE_FORMAT)?
                    } else {
                        u32_at(&image, thunk).ok_or(STATUS_INVALID_IMAGE_FORMAT)? as u64
                    };
                    thunk += if is_64 { 8 } else { 4 };
                    if value == 0 {
                        break;
                    }
                    let ordinal_flag = if is_64 {
                        0x8000_0000_0000_0000
                    } else {
                        0x8000_0000
                    };
                    if value & ordinal_flag != 0 {
                        symbols.push(ImportRef::Ordinal((value & 0xFFFF) as u16));
                    } else {
                        let name = read_c_string(&image, value as usize + 2, 260)
                            .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                        symbols.push(ImportRef::Name(name));
                    }
                }
            }
            delay_imports.push(DelayImport {
                dll,
                iat_rva,
                int_rva,
                timestamp,
                symbols,
            });
            descriptor += 32;
        }
    }

    // Exports.
    let mut exports = Vec::new();
    let mut unload_rva = None;
    if let Some((export_rva, export_size)) = directory(0).filter(|(_, size)| *size > 0) {
        let directory_start = export_rva as usize;
        if directory_start + 40 <= image.len() && export_size >= 40 {
            let ordinal_base =
                u32_at(&image, directory_start + 16).ok_or(STATUS_INVALID_IMAGE_FORMAT)? as u16;
            let number_of_functions =
                u32_at(&image, directory_start + 20).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let number_of_names =
                u32_at(&image, directory_start + 24).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let address_of_functions =
                u32_at(&image, directory_start + 28).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let address_of_names =
                u32_at(&image, directory_start + 32).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            let address_of_ordinals =
                u32_at(&image, directory_start + 36).ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
            for index in 0..number_of_names {
                let name_pointer = u32_at(&image, (address_of_names + index * 4) as usize)
                    .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                let ordinal_index = u16_at(&image, (address_of_ordinals + index * 2) as usize)
                    .ok_or(STATUS_INVALID_IMAGE_FORMAT)? as u32;
                if ordinal_index >= number_of_functions {
                    continue;
                }
                let name = read_c_string(&image, name_pointer as usize, 260)
                    .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                let rva = u32_at(&image, (address_of_functions + ordinal_index * 4) as usize)
                    .ok_or(STATUS_INVALID_IMAGE_FORMAT)?;
                if name.eq_ignore_ascii_case("DriverUnload") && unload_rva.is_none() {
                    unload_rva = Some(rva);
                }
                exports.push(ExportSymbolInfo {
                    name,
                    rva,
                    ordinal: ordinal_base.wrapping_add(ordinal_index as u16),
                });
            }
        }
    }

    // TLS directory facts.
    let tls = directory(9)
        .filter(|(_, size)| *size > 0)
        .map(|(rva, size)| -> Result<TlsInfo, u32> {
            let mut callback_count = 0;
            let callback_array_field = if is_64 { 24 } else { 12 };
            if let Some(callbacks_va) = u64_at(&image, rva as usize + callback_array_field) {
                if callbacks_va >= actual_base {
                    let mut offset = (callbacks_va - actual_base) as usize;
                    while offset + if is_64 { 8 } else { 4 } <= image.len() {
                        let callback = if is_64 {
                            u64_at(&image, offset).unwrap_or(0)
                        } else {
                            u32_at(&image, offset).unwrap_or(0) as u64
                        };
                        offset += if is_64 { 8 } else { 4 };
                        if callback == 0 {
                            break;
                        }
                        callback_count += 1;
                    }
                }
            }
            Ok(TlsInfo {
                directory_rva: rva,
                directory_size: size,
                callback_count,
            })
        })
        .transpose()?;

    // Version resource (`VS_FIXEDFILEINFO` inside RT_VERSION).
    let version = directory(2)
        .filter(|(_, size)| *size > 0)
        .and_then(|(rva, size)| {
            let make = |resource_rva: u32, resource_size: u32, fixed: Option<(u32, u32)>| {
                let (file_version_ms, file_version_ls) = fixed.unwrap_or((0, 0));
                VersionInfo {
                    resource_rva,
                    resource_size,
                    file_version_ms,
                    file_version_ls,
                }
            };
            // Walk one resource-directory level down to RT_VERSION (type 16).
            let start = rva as usize;
            if start + 16 > image.len() {
                return None;
            }
            let named = u16_at(&image, start + 12)? as usize;
            let ids = u16_at(&image, start + 14)? as usize;
            let entry_count = named + ids;
            for index in 0..entry_count {
                let entry = start + 16 + index * 8;
                let name_or_id = u32_at(&image, entry)?;
                let offset = u32_at(&image, entry + 4)?;
                if name_or_id & 0x8000_0000 != 0 {
                    continue;
                }
                if name_or_id != 16 {
                    continue;
                }
                let level2 = start + (offset & 0x7FFF_FFFF) as usize;
                let data_entry_count =
                    u16_at(&image, level2 + 12)? as usize + u16_at(&image, level2 + 14)? as usize;
                if data_entry_count == 0 {
                    continue;
                }
                let data_entry = level2 + 16 + (data_entry_count - 1) * 8;
                let data_offset = u32_at(&image, data_entry)? & 0x7FFF_FFFF;
                let _data_size = u32_at(&image, data_entry + 4)?;
                let data = (rva + data_offset) as usize;
                let mut fixed = None;
                if data + 40 <= image.len() && u32_at(&image, data) == Some(0xFEEF_04BD) {
                    fixed = Some((
                        u32_at(&image, data + 8).unwrap_or(0),
                        u32_at(&image, data + 12).unwrap_or(0),
                    ));
                }
                return Some(make(rva, size, fixed));
            }
            Some(make(rva, size, None))
        });

    Ok(LoadedDriver {
        base: actual_base,
        image,
        size_of_image,
        entry_rva,
        unload_rva,
        machine,
        sections,
        imports,
        delay_imports,
        exports,
        tls,
        version,
        preferred_base: image_base,
    })
}

impl LoadedDriver {
    /// Resolve every import through `resolver`, reporting unresolved symbols.
    pub fn resolve_imports<R: ImportResolver>(&self, resolver: &R) -> ImportReport {
        let mut report = ImportReport {
            resolved: Vec::new(),
            unresolved: Vec::new(),
        };
        for module in &self.imports {
            for symbol in &module.symbols {
                let target = (module.dll.clone(), symbol.display(), module.set);
                match resolver.resolve(module.set, &module.dll, symbol) {
                    Some(_) => report.resolved.push(target),
                    None => report.unresolved.push(target),
                }
            }
        }
        report
    }

    /// Read a little-endian u64 from the mapped image at an RVA.
    pub fn read_u64(&self, rva: u32) -> Option<u64> {
        u64_at(&self.image, rva as usize)
    }

    /// The mapped address of an RVA.
    pub fn address_of(&self, rva: u32) -> u64 {
        self.base.wrapping_add(rva as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFERRED_BASE: u64 = 0x1_4000_0000;

    /// Build a structurally real PE64 native driver image with:
    /// - `.text` (entry stub at RVA 0x1000 holding a DIR64-referenced pointer),
    /// - `.rdata` (import descriptors + names + export table + reloc block),
    /// - imports: ntoskrnl.exe!IoCreateDevice, ntoskrnl.exe!ExAllocatePoolWithTag,
    ///   an ordinal import;
    /// - exports: DriverEntry, DriverUnload;
    /// - one DIR64 relocation at .text+0x20 targeting PREFERRED_BASE+0x1234.
    fn build_driver_image() -> Vec<u8> {
        // File layout.
        const TEXT_RVA: u32 = 0x1000;
        const TEXT_RAW: usize = 0x200;
        const RDATA_RVA: u32 = 0x2000;
        const RDATA_RAW: usize = 0x400;
        const RDATA_SIZE: usize = 0x600;
        const SIZE_OF_IMAGE: u32 = 0x3000;
        const SIZE_OF_HEADERS: u32 = 0x200;

        let mut file = vec![0_u8; RDATA_RAW + RDATA_SIZE];
        // DOS header.
        file[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        file[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature.
        file[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        file[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        file[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
        file[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes()); // optional size
        file[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // characteristics
        let optional = coff + 20;
        file[optional..optional + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        file[optional + 16..optional + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        file[optional + 24..optional + 32].copy_from_slice(&PREFERRED_BASE.to_le_bytes());
        file[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        file[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
        file[optional + 56..optional + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());
        file[optional + 60..optional + 64].copy_from_slice(&SIZE_OF_HEADERS.to_le_bytes());
        file[optional + 68..optional + 70].copy_from_slice(&1u16.to_le_bytes()); // NATIVE
        let directory_count_offset = optional + 108;
        file[directory_count_offset..directory_count_offset + 4]
            .copy_from_slice(&16u32.to_le_bytes());
        let dirs = optional + 112;
        let set_dir = |index: usize, rva: u32, size: u32, file: &mut Vec<u8>| {
            let offset = dirs + index * 8;
            file[offset..offset + 4].copy_from_slice(&rva.to_le_bytes());
            file[offset + 4..offset + 8].copy_from_slice(&size.to_le_bytes());
        };
        set_dir(0, RDATA_RVA + 0x300, 0x100, &mut file); // exports
        set_dir(1, RDATA_RVA + 0x000, 0x40, &mut file); // imports
        set_dir(5, RDATA_RVA + 0x200, 0x20, &mut file); // relocations
        // Section table.
        let section_table = optional + 0xF0;
        let write_section = |index: usize,
                             name: &[u8; 8],
                             virtual_size: u32,
                             rva: u32,
                             raw_size: u32,
                             raw: u32,
                             characteristics: u32,
                             file: &mut Vec<u8>| {
            let entry = section_table + index * 40;
            file[entry..entry + 8].copy_from_slice(name);
            file[entry + 8..entry + 12].copy_from_slice(&virtual_size.to_le_bytes());
            file[entry + 12..entry + 16].copy_from_slice(&rva.to_le_bytes());
            file[entry + 16..entry + 20].copy_from_slice(&raw_size.to_le_bytes());
            file[entry + 20..entry + 24].copy_from_slice(&raw.to_le_bytes());
            file[entry + 36..entry + 40].copy_from_slice(&characteristics.to_le_bytes());
        };
        write_section(
            0,
            b".text\0\0\0",
            0x200,
            TEXT_RVA,
            0x200,
            TEXT_RAW as u32,
            0x6000_0020,
            &mut file,
        );
        write_section(
            1,
            b".rdata\0\0",
            RDATA_SIZE as u32,
            RDATA_RVA,
            RDATA_SIZE as u32,
            RDATA_RAW as u32,
            0x4000_0040,
            &mut file,
        );
        // .text stub: [0] mov eax,1; [5] ret; pointer at +0x20.
        file[TEXT_RAW] = 0xB8;
        file[TEXT_RAW + 1..TEXT_RAW + 5].copy_from_slice(&1u32.to_le_bytes());
        file[TEXT_RAW + 5] = 0xC3;
        let pointer_value = PREFERRED_BASE + 0x1234;
        file[TEXT_RAW + 0x20..TEXT_RAW + 0x28].copy_from_slice(&pointer_value.to_le_bytes());

        // ---- .rdata content (RVAs relative to RDATA_RVA) ----
        let rdata = |offset: usize| RDATA_RAW + offset;
        // Import descriptor (20 bytes): OriginalFirstThunk=0x40, Name=0x80,
        // FirstThunk=0x60.
        let desc = rdata(0);
        file[desc..desc + 4].copy_from_slice(&(RDATA_RVA + 0x40).to_le_bytes());
        file[desc + 12..desc + 16].copy_from_slice(&(RDATA_RVA + 0x80).to_le_bytes());
        file[desc + 16..desc + 20].copy_from_slice(&(RDATA_RVA + 0x60).to_le_bytes());
        // ILT at 0x40: [IoCreateDevice H/N, ExAllocatePoolWithTag H/N, ordinal, 0].
        let ilt = rdata(0x40);
        for (index, name_rva) in [
            (RDATA_RVA + 0xC0) as u64,
            (RDATA_RVA + 0xD0) as u64,
            0x8000_0000_0000_0000u64 | 123,
            0,
        ]
        .iter()
        .enumerate()
        {
            file[ilt + index * 8..ilt + index * 8 + 8].copy_from_slice(&name_rva.to_le_bytes());
        }
        // IAT at 0x60 (same shape; patched at load).
        let iat = rdata(0x60);
        for (index, name_rva) in [
            (RDATA_RVA + 0xC0) as u64,
            (RDATA_RVA + 0xD0) as u64,
            0x8000_0000_0000_0000u64 | 123,
            0,
        ]
        .iter()
        .enumerate()
        {
            file[iat + index * 8..iat + index * 8 + 8].copy_from_slice(&name_rva.to_le_bytes());
        }
        // DLL name.
        file[rdata(0x80)..rdata(0x80) + 13].copy_from_slice(b"ntoskrnl.exe\0");
        // Hint/name entries.
        file[rdata(0xC0)..rdata(0xC0) + 2].copy_from_slice(&0u16.to_le_bytes());
        file[rdata(0xC2)..rdata(0xC2) + 15].copy_from_slice(b"IoCreateDevice\0");
        file[rdata(0xD0)..rdata(0xD0) + 2].copy_from_slice(&0u16.to_le_bytes());
        file[rdata(0xD2)..rdata(0xD2) + 22].copy_from_slice(b"ExAllocatePoolWithTag\0");

        // Relocation block at .rdata+0x200: DIR64 at .text+0x20.
        let reloc = rdata(0x200);
        file[reloc..reloc + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());
        let mut entries: Vec<u16> = Vec::new();
        entries.push((10 << 12) | 0x20);
        entries.push(0);
        let block_size = 8 + entries.len() * 2;
        file[reloc + 4..reloc + 8].copy_from_slice(&(block_size as u32).to_le_bytes());
        for (index, entry) in entries.iter().enumerate() {
            file[reloc + 8 + index * 2..reloc + 10 + index * 2]
                .copy_from_slice(&entry.to_le_bytes());
        }

        // Export directory at .rdata+0x300.
        let export = rdata(0x300);
        let functions_rva = RDATA_RVA + 0x340;
        let names_rva = RDATA_RVA + 0x350;
        let ordinals_rva = RDATA_RVA + 0x360;
        file[export + 16..export + 20].copy_from_slice(&1u32.to_le_bytes()); // ordinal base
        file[export + 20..export + 24].copy_from_slice(&2u32.to_le_bytes()); // functions
        file[export + 24..export + 28].copy_from_slice(&2u32.to_le_bytes()); // names
        file[export + 28..export + 32].copy_from_slice(&functions_rva.to_le_bytes());
        file[export + 32..export + 36].copy_from_slice(&names_rva.to_le_bytes());
        file[export + 36..export + 40].copy_from_slice(&ordinals_rva.to_le_bytes());
        let functions = rdata(0x340);
        file[functions..functions + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // DriverEntry
        file[functions + 4..functions + 8].copy_from_slice(&0x1010u32.to_le_bytes()); // DriverUnload
        let names = rdata(0x350);
        file[names..names + 4].copy_from_slice(&(RDATA_RVA + 0x370).to_le_bytes());
        file[names + 4..names + 8].copy_from_slice(&(RDATA_RVA + 0x380).to_le_bytes());
        let ordinals = rdata(0x360);
        file[ordinals..ordinals + 2].copy_from_slice(&0u16.to_le_bytes());
        file[ordinals + 2..ordinals + 4].copy_from_slice(&1u16.to_le_bytes());
        file[rdata(0x370)..rdata(0x370) + 12].copy_from_slice(b"DriverEntry\0");
        file[rdata(0x380)..rdata(0x380) + 13].copy_from_slice(b"DriverUnload\0");
        file
    }

    struct TestResolver {
        resolve_all: bool,
    }

    impl ImportResolver for TestResolver {
        fn resolve(&self, _set: KernelApiSet, _dll: &str, symbol: &ImportRef) -> Option<u64> {
            if self.resolve_all {
                return Some(0xFFFF_0000);
            }
            match symbol {
                ImportRef::Name(name) if name == "IoCreateDevice" => Some(0xFFFF_1000),
                _ => None,
            }
        }
    }

    #[test]
    fn loads_maps_and_relocates_a_real_driver_image() {
        let bytes = build_driver_image();
        let base = PREFERRED_BASE + 0x10000;
        let driver = load_driver_image(&bytes, base).expect("driver must load");
        assert_eq!(driver.size_of_image, 0x3000);
        assert_eq!(driver.machine, 0x8664);
        assert_eq!(driver.entry_rva, 0x1000);
        assert_eq!(driver.unload_rva, Some(0x1010));
        assert_eq!(driver.sections.len(), 2);
        assert!(driver.sections[0].is_executable());
        assert!(!driver.sections[1].is_executable());
        assert!(!driver.sections[1].is_discardable());
        assert!(!driver.sections[0].is_init);
        // The code stub made it into the mapped image.
        assert_eq!(driver.image[0x1000], 0xB8);
        assert_eq!(driver.image[0x1005], 0xC3);
        // Relocation: the pointer at .text+0x20 gained the delta.
        let relocated = driver.read_u64(0x1020).expect("pointer");
        assert_eq!(relocated, PREFERRED_BASE + 0x1234 + 0x10000);
        assert_eq!(driver.address_of(0x1000), base + 0x1000);
        // Export parsing.
        let names: Vec<&str> = driver.exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"DriverEntry"));
        assert!(names.contains(&"DriverUnload"));
    }

    #[test]
    fn preferred_base_load_applies_no_relocations() {
        let bytes = build_driver_image();
        let driver = load_driver_image(&bytes, PREFERRED_BASE).expect("load");
        assert_eq!(
            driver.read_u64(0x1020).expect("pointer"),
            PREFERRED_BASE + 0x1234
        );
    }

    #[test]
    fn classifies_imports_and_reports_unresolved() {
        let bytes = build_driver_image();
        let driver = load_driver_image(&bytes, PREFERRED_BASE).expect("load");
        assert_eq!(driver.imports.len(), 1);
        let module = &driver.imports[0];
        assert_eq!(module.dll, "ntoskrnl.exe");
        assert_eq!(module.set, KernelApiSet::Ntoskrnl);
        assert_eq!(module.first_thunk_rva, 0x2060);
        assert_eq!(
            module.symbols,
            vec![
                ImportRef::Name("IoCreateDevice".to_string()),
                ImportRef::Name("ExAllocatePoolWithTag".to_string()),
                ImportRef::Ordinal(123),
            ]
        );
        let partial = driver.resolve_imports(&TestResolver { resolve_all: false });
        assert_eq!(partial.resolved.len(), 1);
        assert_eq!(partial.resolved[0].1, "IoCreateDevice");
        assert_eq!(partial.unresolved.len(), 2);
        assert_eq!(partial.unresolved[0].1, "ExAllocatePoolWithTag");
        assert_eq!(partial.unresolved[1].1, "#123");
        let all = driver.resolve_imports(&TestResolver { resolve_all: true });
        assert!(all.unresolved.is_empty());
        assert_eq!(all.resolved.len(), 3);
    }

    #[test]
    fn kernel_api_sets_classify() {
        assert_eq!(
            KernelApiSet::classify("ntoskrnl.exe"),
            KernelApiSet::Ntoskrnl
        );
        assert_eq!(
            KernelApiSet::classify("NTKRNLPA.EXE"),
            KernelApiSet::Ntoskrnl
        );
        assert_eq!(KernelApiSet::classify("hal.dll"), KernelApiSet::Hal);
        assert_eq!(KernelApiSet::classify("WdfLdr.SYS"), KernelApiSet::Kmdf);
        assert_eq!(KernelApiSet::classify("Wdf01000.sys"), KernelApiSet::Kmdf);
        assert_eq!(KernelApiSet::classify("win32k.sys"), KernelApiSet::Other);
    }

    #[test]
    fn rejects_non_mz_and_non_pe() {
        assert_eq!(
            load_driver_image(&[0_u8; 128], 0).err(),
            Some(STATUS_INVALID_IMAGE_NOT_MZ)
        );
        let mut bytes = build_driver_image();
        bytes[0x80..0x84].copy_from_slice(b"PX\0\0");
        assert_eq!(
            load_driver_image(&bytes, 0).err(),
            Some(STATUS_INVALID_IMAGE_FORMAT)
        );
    }

    #[test]
    fn rejects_bad_machine_and_subsystem() {
        let mut bytes = build_driver_image();
        bytes[0x84..0x86].copy_from_slice(&0x01C0u16.to_le_bytes()); // ARM
        assert_eq!(
            load_driver_image(&bytes, 0).err(),
            Some(STATUS_INVALID_IMAGE_FORMAT)
        );
        let mut bytes = build_driver_image();
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x84 + 20 + 68..0x84 + 20 + 70].copy_from_slice(&3u16.to_le_bytes()); // CONSOLE
        assert_eq!(
            load_driver_image(&bytes, 0).err(),
            Some(STATUS_INVALID_IMAGE_FORMAT)
        );
    }

    #[test]
    fn rejects_machine_optional_header_mismatch() {
        let mut bytes = build_driver_image();
        // PE32+ magic on an x86 machine -> WIN_64 style mismatch for a 32-bit
        // loader; the loader here reports the documented statuses.
        bytes[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        assert_eq!(
            load_driver_image(&bytes, 0).err(),
            Some(STATUS_INVALID_IMAGE_WIN_64)
        );
        let mut bytes = build_driver_image();
        bytes[0x84 + 20..0x84 + 22].copy_from_slice(&0x010Bu16.to_le_bytes());
        assert_eq!(
            load_driver_image(&bytes, 0).err(),
            Some(STATUS_INVALID_IMAGE_WIN_32)
        );
    }

    #[test]
    fn rejects_checksum_mismatch() {
        let mut bytes = build_driver_image();
        let checksum_offset = 0x84 + 20 + 64;
        let computed = pe_checksum(&bytes);
        bytes[checksum_offset..checksum_offset + 4]
            .copy_from_slice(&(computed ^ 0xFFFF).to_le_bytes());
        assert_eq!(
            load_driver_image(&bytes, 0).err(),
            Some(STATUS_IMAGE_CHECKSUM_MISMATCH)
        );
        // A matching checksum loads.  The checksum field reads as zero while
        // computing, so store the value computed with the field zeroed.
        let mut bytes = build_driver_image();
        let computed = pe_checksum(&bytes);
        bytes[checksum_offset..checksum_offset + 4].copy_from_slice(&computed.to_le_bytes());
        let recomputed = pe_checksum(&bytes);
        assert_eq!(computed, recomputed, "checksum field is excluded");
        assert!(load_driver_image(&bytes, PREFERRED_BASE).is_ok());
    }

    #[test]
    fn rejects_bad_alignments() {
        let mut bytes = build_driver_image();
        bytes[0x84 + 20 + 32..0x84 + 20 + 36].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            load_driver_image(&bytes, 0).err(),
            Some(STATUS_INVALID_IMAGE_PROTECT)
        );
        let mut bytes = build_driver_image();
        bytes[0x84 + 20 + 36..0x84 + 20 + 40].copy_from_slice(&0x4000u32.to_le_bytes());
        assert_eq!(
            load_driver_image(&bytes, 0).err(),
            Some(STATUS_INVALID_IMAGE_PROTECT)
        );
    }

    #[test]
    fn pe_checksum_matches_documented_algorithm() {
        // A single word file: sum + length.
        assert_eq!(pe_checksum(&[0x01, 0x00]), 3);
        assert_eq!(pe_checksum(&[0x01]), 2);
        assert_eq!(pe_checksum(&[]), 0);
    }
}
