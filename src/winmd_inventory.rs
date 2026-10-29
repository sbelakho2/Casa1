//! Windows API universe derived from real ECMA-335 WinMD metadata.
//!
//! The PE inventory in [`crate::pe_inventory`] answers "what do real binaries
//! import?"; this module answers the complementary question "what does the
//! Windows SDK contract actually define?".  The universe is parsed from
//! `.winmd` files fetched from NuGet (see `tools/fetch_winmd.py`), never from a
//! hand-written list, and is diffed against Casa1's registry so an API that is
//! modeled but absent from the contract (or a contract API that Casa1 does not
//! model at all) is visible instead of silently biasing completeness.
//!
//! Only the metadata needed for names and ownership is decoded: the PE/COFF
//! layout, the CLI header, the metadata root streams, the table header, and the
//! `Module`/`TypeDef`/`MethodDef`/`ModuleRef`/`ImplMap`/`Assembly` tables.
//! Signature blobs are deliberately opaque; their contents never affect the
//! enumerated names.
//!
//! All output is ordered by path/namespace/name so two runs over the same
//! metadata produce byte-identical JSON.

use crate::api_database::ApiDatabase;
use crate::error::{AppError, AppResult};
use crate::pe_inventory::canonical_dll;
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Schema version for `winmd-inventory.json`.
pub const WINMD_INVENTORY_SCHEMA_VERSION: u32 = 1;

const MODULE_TABLE: usize = 0;
const TYPEDEF_TABLE: usize = 2;
const METHODDEF_TABLE: usize = 6;
const MODULEREF_TABLE: usize = 26;
const IMPLMAP_TABLE: usize = 28;
const ASSEMBLY_TABLE: usize = 32;

const TYPE_ATTRIBUTE_INTERFACE: u32 = 0x20;
const MAX_METADATA_TABLE: usize = 44;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdUniverse {
    pub schema_version: u32,
    /// SHA-256 over every discovered `.winmd` file (relative path + content).
    pub metadata_fingerprint: String,
    /// Number of `.winmd` files discovered, including files that failed to parse.
    pub winmd_file_count: usize,
    /// Unique type definitions (namespace + name) across all files.
    pub type_count: usize,
    /// Unique (module, export) functions from `ImplMap`.
    pub function_count: usize,
    /// Unique interfaces (types with the interface flag and methods).
    pub interface_count: usize,
    /// Unique methods across all interfaces.
    pub interface_method_count: usize,
    /// Type definitions that appeared more than once and were merged.
    pub duplicate_type_count: usize,
    pub files: Vec<WinmdFile>,
    pub namespaces: Vec<WinmdNamespaceStat>,
    pub modules: Vec<WinmdModuleStat>,
    pub functions: Vec<WinmdFunction>,
    pub interfaces: Vec<WinmdInterface>,
    /// Files that did not parse.  Kept so a malformed metadata drop cannot
    /// silently shrink the universe.
    pub errors: Vec<WinmdError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdFile {
    /// Metadata-root-relative path using `/` separators.
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub assembly: Option<String>,
    pub type_count: usize,
    pub method_count: usize,
    pub function_count: usize,
    pub interface_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdError {
    pub path: String,
    pub reason_code: u32,
    pub reason_name: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdNamespaceStat {
    pub namespace: String,
    pub type_count: usize,
    pub method_count: usize,
    pub function_count: usize,
    pub interface_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdModuleStat {
    pub module: String,
    pub function_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdFunction {
    /// Module name exactly as written in the `ModuleRef` row.
    pub module: String,
    /// Import name exactly as written in the `ImplMap` row.
    pub export: String,
    pub namespace: String,
    pub type_name: String,
    /// Method name owning the `ImplMap` row.
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdInterface {
    pub namespace: String,
    pub name: String,
    pub methods: Vec<String>,
}

/// A parsed `.winmd` file (the mergeable unit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedWinmd {
    pub assembly: Option<String>,
    pub types: Vec<WinmdType>,
    pub functions: Vec<WinmdFunction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdType {
    pub namespace: String,
    pub name: String,
    pub interface: bool,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdMissingExport {
    pub module: String,
    pub canonical_module: String,
    pub export: String,
    pub namespace: String,
    pub type_name: String,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdExtraRegistryExport {
    pub module: String,
    pub export: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdMissingInterfaceMethod {
    pub namespace: String,
    pub interface: String,
    pub method: String,
    /// `true` when the registry models the interface but not this method;
    /// `false` when the registry does not model the interface at all.
    pub interface_known: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdExtraRegistryInterfaceMethod {
    pub interface: String,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdModuleDiff {
    pub module: String,
    pub canonical_module: String,
    pub function_count: usize,
    pub modeled_function_count: usize,
    pub missing_function_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdTypeDiff {
    pub namespace: String,
    pub type_name: String,
    pub function_count: usize,
    pub modeled_function_count: usize,
    pub missing_function_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdInterfaceDiff {
    pub namespace: String,
    pub interface: String,
    pub method_count: usize,
    pub modeled_method_count: usize,
    pub missing_method_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdDiffSummary {
    pub metadata_function_count: usize,
    pub modeled_function_count: usize,
    pub missing_function_count: usize,
    pub registry_export_count: usize,
    pub extra_registry_export_count: usize,
    pub metadata_module_count: usize,
    pub missing_module_count: usize,
    pub interface_count: usize,
    pub fully_modeled_interface_count: usize,
    pub partially_modeled_interface_count: usize,
    pub missing_interface_count: usize,
    pub interface_method_count: usize,
    pub modeled_interface_method_count: usize,
    pub missing_interface_method_count: usize,
    pub extra_registry_interface_method_count: usize,
    pub duplicate_type_count: usize,
    pub parse_error_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdDiff {
    pub metadata_fingerprint: String,
    /// Contract `(module, export)` functions Casa1 does not model.
    pub missing_exports: Vec<WinmdMissingExport>,
    /// Registry exports for modules present in the contract that the contract
    /// does not define.
    pub extra_registry_exports: Vec<WinmdExtraRegistryExport>,
    /// Contract interface methods Casa1 does not model.
    pub missing_interface_methods: Vec<WinmdMissingInterfaceMethod>,
    /// Registry interface methods for interfaces present in the contract that
    /// the contract does not define.
    pub extra_registry_interface_methods: Vec<WinmdExtraRegistryInterfaceMethod>,
    pub modules: Vec<WinmdModuleDiff>,
    pub types: Vec<WinmdTypeDiff>,
    pub interfaces: Vec<WinmdInterfaceDiff>,
    pub summary: WinmdDiffSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinmdReport {
    pub schema_version: u32,
    pub universe: WinmdUniverse,
    pub diff: WinmdDiff,
    pub human_summary: String,
}

// ── Byte helpers ────────────────────────────────────────────────────────────

fn invalid(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcPeParseInvalid, message)
}

fn truncated(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcParserTruncated, message)
}

fn unsupported(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcInputUnsupported, message)
}

fn u16_at(bytes: &[u8], offset: usize, message: &str) -> AppResult<u16> {
    let slice = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| truncated(message))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], offset: usize, message: &str) -> AppResult<u32> {
    let slice = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| truncated(message))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn u64_at(bytes: &[u8], offset: usize, message: &str) -> AppResult<u64> {
    let slice = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or_else(|| truncated(message))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

// ── PE / CLI layout ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_pointer: u32,
    raw_size: u32,
}

fn map_rva(bytes: &[u8], sections: &[Section], rva: u32) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        let end = section.virtual_address.checked_add(span)?;
        if rva >= section.virtual_address && rva < end {
            let delta = rva - section.virtual_address;
            if delta >= section.raw_size {
                return None;
            }
            let offset = (section.raw_pointer as usize).checked_add(delta as usize)?;
            if offset <= bytes.len() {
                return Some(offset);
            }
        }
    }
    None
}

/// Extract the CLI metadata root bytes from a PE image.
fn cli_metadata<'a>(bytes: &'a [u8]) -> AppResult<&'a [u8]> {
    if bytes.len() < 2 || bytes[0] != b'M' || bytes[1] != b'Z' {
        return Err(invalid("invalid DOS signature"));
    }
    let pe = u32_at(bytes, 0x3c, "DOS header exceeds file size")? as usize;
    match bytes.get(pe..pe.saturating_add(4)) {
        Some(signature) if signature == b"PE\0\0" => {}
        Some(_) => return Err(invalid("PE signature missing")),
        None => return Err(truncated("NT headers exceed file size")),
    }
    let number_of_sections = u16_at(bytes, pe + 6, "NT headers exceed file size")? as usize;
    let optional_size = u16_at(bytes, pe + 20, "NT headers exceed file size")? as usize;
    let optional = pe + 24;
    let magic = u16_at(bytes, optional, "NT headers exceed file size")?;
    let directory_offset = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return Err(invalid("unsupported optional header magic")),
    };
    let number_of_directories = u32_at(
        bytes,
        optional + directory_offset - 4,
        "NT headers exceed file size",
    )? as usize;
    let section_table = optional + optional_size;
    let mut sections = Vec::with_capacity(number_of_sections);
    for index in 0..number_of_sections {
        let offset = section_table + index * 40;
        sections.push(Section {
            virtual_size: u32_at(bytes, offset + 8, "section table exceeds file size")?,
            virtual_address: u32_at(bytes, offset + 12, "section table exceeds file size")?,
            raw_size: u32_at(bytes, offset + 16, "section table exceeds file size")?,
            raw_pointer: u32_at(bytes, offset + 20, "section table exceeds file size")?,
        });
    }
    if number_of_directories < 15 {
        return Err(invalid("CLR metadata directory missing"));
    }
    let directory = optional + directory_offset + 14 * 8;
    let clr_rva = u32_at(bytes, directory, "NT headers exceed file size")?;
    let clr_size = u32_at(bytes, directory + 4, "NT headers exceed file size")?;
    if clr_rva == 0 || clr_size < 72 {
        return Err(invalid("CLR metadata directory missing"));
    }
    let clr_offset = map_rva(bytes, &sections, clr_rva)
        .ok_or_else(|| truncated("CLR header RVA is not mapped by any section"))?;
    if clr_offset.saturating_add(72) > bytes.len() {
        return Err(truncated("CLR header exceeds file size"));
    }
    let cb = u32_at(bytes, clr_offset, "CLR header exceeds file size")?;
    if cb < 72 || cb as usize > clr_size as usize {
        return Err(invalid("invalid CLR header"));
    }
    let metadata_rva = u32_at(bytes, clr_offset + 8, "CLR header exceeds file size")?;
    let metadata_size = u32_at(bytes, clr_offset + 12, "CLR header exceeds file size")?;
    if metadata_rva == 0 || metadata_size == 0 {
        return Err(invalid("CLR metadata directory missing"));
    }
    let metadata_offset = map_rva(bytes, &sections, metadata_rva)
        .ok_or_else(|| truncated("CLR metadata RVA is not mapped by any section"))?;
    let end = metadata_offset.saturating_add(metadata_size as usize);
    if end > bytes.len() {
        return Err(truncated("metadata directory exceeds file size"));
    }
    Ok(&bytes[metadata_offset..end])
}

// ── Metadata root streams ───────────────────────────────────────────────────

struct Streams<'a> {
    strings: &'a [u8],
    blobs: &'a [u8],
    tables: &'a [u8],
}

fn metadata_streams(metadata: &[u8]) -> AppResult<Streams<'_>> {
    if metadata.len() < 4 {
        return Err(truncated("metadata root exceeds metadata size"));
    }
    if &metadata[..4] != b"BSJB" {
        return Err(invalid("invalid metadata signature"));
    }
    if metadata.len() < 16 {
        return Err(truncated("metadata root exceeds metadata size"));
    }
    let version_length = u32_at(metadata, 12, "metadata root exceeds metadata size")? as usize;
    let after_version = 16usize
        .checked_add(version_length)
        .ok_or_else(|| truncated("metadata version string exceeds metadata size"))?;
    let aligned = (after_version + 3) & !3;
    if aligned.saturating_add(4) > metadata.len() {
        return Err(truncated("metadata stream header exceeds metadata size"));
    }
    let stream_count = u16_at(
        metadata,
        aligned + 2,
        "metadata stream header exceeds metadata size",
    )? as usize;
    let mut cursor = aligned + 4;
    let mut strings = None;
    let mut blobs = None;
    let mut tables = None;
    for _ in 0..stream_count {
        let offset = u32_at(
            metadata,
            cursor,
            "metadata stream header exceeds metadata size",
        )? as usize;
        let size = u32_at(
            metadata,
            cursor + 4,
            "metadata stream header exceeds metadata size",
        )? as usize;
        cursor += 8;
        let name_start = cursor;
        let name_end = metadata[name_start..]
            .iter()
            .position(|&byte| byte == 0)
            .map(|length| name_start + length)
            .ok_or_else(|| truncated("metadata stream name exceeds metadata size"))?;
        let name = std::str::from_utf8(&metadata[name_start..name_end])
            .map_err(|_| invalid("metadata stream name is not UTF-8"))?;
        cursor = (name_end + 1 + 3) & !3;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| truncated("metadata stream exceeds metadata size"))?;
        if end > metadata.len() {
            return Err(truncated("metadata stream exceeds metadata size"));
        }
        let body = &metadata[offset..end];
        match name {
            "#Strings" => strings = Some(body),
            "#Blob" => blobs = Some(body),
            "#~" => tables = Some(body),
            "#-" => return Err(unsupported("unsupported metadata table stream")),
            _ => {}
        }
    }
    let strings = strings.ok_or_else(|| unsupported("missing #Strings metadata heap"))?;
    let blobs = blobs.ok_or_else(|| unsupported("missing #Blob metadata heap"))?;
    let tables = tables.ok_or_else(|| unsupported("missing #~ metadata table stream"))?;
    Ok(Streams {
        strings,
        blobs,
        tables,
    })
}

// ── Table layout ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Coded {
    ResolutionScope,
    TypeDefOrRef,
    MemberRefParent,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    HasSemantics,
    TypeOrMethodDef,
}

#[derive(Debug, Clone, Copy)]
enum Col {
    U8,
    U16,
    U32,
    Str,
    Guid,
    Blob,
    Table(u8),
    Coded(Coded),
}

const fn col_table(index: u8) -> Col {
    Col::Table(index)
}

const fn col_coded(coded: Coded) -> Col {
    Col::Coded(coded)
}

fn table_columns(table: usize) -> Option<&'static [Col]> {
    const MODULE: &[Col] = &[Col::U16, Col::Str, Col::Guid, Col::Guid, Col::Guid];
    const TYPE_REF: &[Col] = &[col_coded(Coded::ResolutionScope), Col::Str, Col::Str];
    const TYPE_DEF: &[Col] = &[
        Col::U32,
        Col::Str,
        Col::Str,
        col_coded(Coded::TypeDefOrRef),
        col_table(4),
        col_table(6),
    ];
    const FIELD_PTR: &[Col] = &[col_table(4)];
    const FIELD: &[Col] = &[Col::U16, Col::Str, Col::Blob];
    const METHOD_PTR: &[Col] = &[col_table(6)];
    const METHOD_DEF: &[Col] = &[
        Col::U32,
        Col::U16,
        Col::U16,
        Col::Str,
        Col::Blob,
        col_table(8),
    ];
    const PARAM_PTR: &[Col] = &[col_table(8)];
    const PARAM: &[Col] = &[Col::U16, Col::U16, Col::Str];
    const INTERFACE_IMPL: &[Col] = &[col_table(2), col_coded(Coded::TypeDefOrRef)];
    const MEMBER_REF: &[Col] = &[col_coded(Coded::MemberRefParent), Col::Str, Col::Blob];
    const CONSTANT: &[Col] = &[Col::U8, Col::U8, col_coded(Coded::HasConstant), Col::Blob];
    const CUSTOM_ATTRIBUTE: &[Col] = &[
        col_coded(Coded::HasCustomAttribute),
        col_coded(Coded::CustomAttributeType),
        Col::Blob,
    ];
    const FIELD_MARSHAL: &[Col] = &[col_coded(Coded::HasFieldMarshal), Col::Blob];
    const DECL_SECURITY: &[Col] = &[Col::U16, col_coded(Coded::HasDeclSecurity), Col::Blob];
    const CLASS_LAYOUT: &[Col] = &[Col::U16, Col::U32, col_table(2)];
    const FIELD_LAYOUT: &[Col] = &[Col::U32, col_table(4)];
    const STANDALONE_SIG: &[Col] = &[Col::Blob];
    const EVENT_MAP: &[Col] = &[col_table(2), col_table(20)];
    const EVENT_PTR: &[Col] = &[col_table(20)];
    const EVENT: &[Col] = &[Col::U16, Col::Str, col_coded(Coded::TypeDefOrRef)];
    const PROPERTY_MAP: &[Col] = &[col_table(2), col_table(23)];
    const PROPERTY_PTR: &[Col] = &[col_table(23)];
    const PROPERTY: &[Col] = &[Col::U16, Col::Str, Col::Blob];
    const METHOD_SEMANTICS: &[Col] = &[Col::U16, col_table(6), col_coded(Coded::HasSemantics)];
    const METHOD_IMPL: &[Col] = &[
        col_table(2),
        col_coded(Coded::TypeDefOrRef),
        col_coded(Coded::TypeDefOrRef),
    ];
    const MODULE_REF: &[Col] = &[Col::Str];
    const TYPE_SPEC: &[Col] = &[Col::Blob];
    const IMPL_MAP: &[Col] = &[
        Col::U16,
        col_coded(Coded::MemberForwarded),
        Col::Str,
        col_table(26),
    ];
    const FIELD_RVA: &[Col] = &[Col::U32, col_table(4)];
    const ENC_LOG: &[Col] = &[Col::U32, Col::U32];
    const ENC_MAP: &[Col] = &[Col::U32];
    const ASSEMBLY: &[Col] = &[
        Col::U32,
        Col::U16,
        Col::U16,
        Col::U16,
        Col::U16,
        Col::U32,
        Col::Blob,
        Col::Str,
        Col::Str,
    ];
    const ASSEMBLY_PROCESSOR: &[Col] = &[Col::U32];
    const ASSEMBLY_OS: &[Col] = &[Col::U32, Col::U32, Col::U32];
    const ASSEMBLY_REF: &[Col] = &[
        Col::U16,
        Col::U16,
        Col::U16,
        Col::U16,
        Col::U32,
        Col::Blob,
        Col::Str,
        Col::Str,
        Col::Blob,
    ];
    const ASSEMBLY_REF_PROCESSOR: &[Col] = &[Col::U32, col_table(35)];
    const ASSEMBLY_REF_OS: &[Col] = &[Col::U32, Col::U32, Col::U32, col_table(35)];
    const FILE: &[Col] = &[Col::U32, Col::Str, Col::Blob];
    const EXPORTED_TYPE: &[Col] = &[
        Col::U32,
        Col::U32,
        Col::Str,
        Col::Str,
        col_coded(Coded::Implementation),
    ];
    const MANIFEST_RESOURCE: &[Col] = &[
        Col::U32,
        Col::U32,
        Col::Str,
        col_coded(Coded::Implementation),
    ];
    const NESTED_CLASS: &[Col] = &[col_table(2), col_table(2)];
    const GENERIC_PARAM: &[Col] = &[
        Col::U16,
        Col::U16,
        col_coded(Coded::TypeOrMethodDef),
        Col::Str,
    ];
    const METHOD_SPEC: &[Col] = &[col_coded(Coded::TypeDefOrRef), Col::Blob];
    const GENERIC_PARAM_CONSTRAINT: &[Col] = &[col_table(42), col_coded(Coded::TypeDefOrRef)];
    let columns = match table {
        0 => MODULE,
        1 => TYPE_REF,
        2 => TYPE_DEF,
        3 => FIELD_PTR,
        4 => FIELD,
        5 => METHOD_PTR,
        6 => METHOD_DEF,
        7 => PARAM_PTR,
        8 => PARAM,
        9 => INTERFACE_IMPL,
        10 => MEMBER_REF,
        11 => CONSTANT,
        12 => CUSTOM_ATTRIBUTE,
        13 => FIELD_MARSHAL,
        14 => DECL_SECURITY,
        15 => CLASS_LAYOUT,
        16 => FIELD_LAYOUT,
        17 => STANDALONE_SIG,
        18 => EVENT_MAP,
        19 => EVENT_PTR,
        20 => EVENT,
        21 => PROPERTY_MAP,
        22 => PROPERTY_PTR,
        23 => PROPERTY,
        24 => METHOD_SEMANTICS,
        25 => METHOD_IMPL,
        26 => MODULE_REF,
        27 => TYPE_SPEC,
        28 => IMPL_MAP,
        29 => FIELD_RVA,
        30 => ENC_LOG,
        31 => ENC_MAP,
        32 => ASSEMBLY,
        33 => ASSEMBLY_PROCESSOR,
        34 => ASSEMBLY_OS,
        35 => ASSEMBLY_REF,
        36 => ASSEMBLY_REF_PROCESSOR,
        37 => ASSEMBLY_REF_OS,
        38 => FILE,
        39 => EXPORTED_TYPE,
        40 => MANIFEST_RESOURCE,
        41 => NESTED_CLASS,
        42 => GENERIC_PARAM,
        43 => METHOD_SPEC,
        44 => GENERIC_PARAM_CONSTRAINT,
        _ => return None,
    };
    Some(columns)
}

struct Layout {
    counts: [u32; 64],
    offsets: [usize; 64],
    row_sizes: [usize; 64],
    string_size: usize,
    guid_size: usize,
    blob_size: usize,
}

fn coded_tables(coded: Coded) -> (u32, &'static [u8]) {
    match coded {
        Coded::ResolutionScope => (2, &[0, 26, 35, 1]),
        Coded::TypeDefOrRef => (2, &[2, 1, 27]),
        Coded::MemberRefParent => (3, &[2, 1, 26, 6, 27]),
        Coded::HasConstant => (2, &[4, 8, 23]),
        Coded::HasCustomAttribute => (
            5,
            &[
                6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 43, 44,
            ],
        ),
        Coded::HasFieldMarshal => (1, &[4, 8]),
        Coded::HasDeclSecurity => (2, &[2, 6, 32]),
        Coded::MemberForwarded => (1, &[4, 6]),
        Coded::Implementation => (2, &[38, 35, 39]),
        Coded::CustomAttributeType => (3, &[6, 10]),
        Coded::HasSemantics => (1, &[20, 23]),
        Coded::TypeOrMethodDef => (1, &[2, 6]),
    }
}

fn coded_size(coded: Coded, counts: &[u32; 64]) -> usize {
    let (tag_bits, tables) = coded_tables(coded);
    let max = tables
        .iter()
        .map(|&table| counts[table as usize])
        .max()
        .unwrap_or(0);
    if max < (1u32 << (16 - tag_bits)) {
        2
    } else {
        4
    }
}

fn column_size(column: Col, layout: &Layout) -> usize {
    match column {
        Col::U8 => 1,
        Col::U16 => 2,
        Col::U32 => 4,
        Col::Str => layout.string_size,
        Col::Guid => layout.guid_size,
        Col::Blob => layout.blob_size,
        Col::Table(index) => {
            if layout.counts[index as usize] >= 0x1_0000 {
                4
            } else {
                2
            }
        }
        Col::Coded(coded) => coded_size(coded, &layout.counts),
    }
}

fn table_row_size(layout: &Layout, table: usize) -> AppResult<usize> {
    let columns = table_columns(table).ok_or_else(|| unsupported("unsupported metadata table"))?;
    let mut size = 0usize;
    for column in columns {
        size = size
            .checked_add(column_size(*column, layout))
            .ok_or_else(|| truncated("metadata table rows exceed stream size"))?;
    }
    Ok(size)
}

fn table_header(tables: &[u8], heap_sizes: u8) -> AppResult<Layout> {
    if tables.len() < 24 {
        return Err(truncated("metadata table header exceeds stream size"));
    }
    if tables[0] != 0 || tables[1] != 0 {
        return Err(invalid("invalid metadata table header"));
    }
    let valid = u64_at(tables, 8, "metadata table header exceeds stream size")?;
    let mut counts = [0u32; 64];
    let mut cursor = 24usize;
    for (index, count) in counts.iter_mut().enumerate() {
        if valid & (1u64 << index) == 0 {
            continue;
        }
        if index > MAX_METADATA_TABLE {
            return Err(unsupported("unsupported metadata table"));
        }
        *count = u32_at(
            tables,
            cursor,
            "metadata table row counts exceed stream size",
        )?;
        cursor += 4;
    }
    let mut layout = Layout {
        counts,
        offsets: [0usize; 64],
        row_sizes: [0usize; 64],
        string_size: if heap_sizes & 1 != 0 { 4 } else { 2 },
        guid_size: if heap_sizes & 2 != 0 { 4 } else { 2 },
        blob_size: if heap_sizes & 4 != 0 { 4 } else { 2 },
    };
    for table in 0..=MAX_METADATA_TABLE {
        layout.row_sizes[table] = table_row_size(&layout, table)?;
    }
    let mut offset = cursor;
    for table in 0..=MAX_METADATA_TABLE {
        layout.offsets[table] = offset;
        let count = layout.counts[table] as usize;
        if count == 0 {
            continue;
        }
        let total = layout.row_sizes[table]
            .checked_mul(count)
            .ok_or_else(|| truncated("metadata table rows exceed stream size"))?;
        offset = offset
            .checked_add(total)
            .ok_or_else(|| truncated("metadata table rows exceed stream size"))?;
        if offset > tables.len() {
            return Err(truncated("metadata table rows exceed stream size"));
        }
    }
    Ok(layout)
}

fn read_table(tables: &[u8], layout: &Layout, table: usize) -> AppResult<Vec<Vec<u32>>> {
    let count = layout.counts[table] as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    let columns = table_columns(table).ok_or_else(|| unsupported("unsupported metadata table"))?;
    let sizes = columns
        .iter()
        .map(|column| column_size(*column, layout))
        .collect::<Vec<_>>();
    let row_size = layout.row_sizes[table];
    let start = layout.offsets[table];
    let end = start
        .checked_add(row_size * count)
        .ok_or_else(|| truncated("metadata table rows exceed stream size"))?;
    if end > tables.len() {
        return Err(truncated("metadata table rows exceed stream size"));
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let row_offset = start + index * row_size;
        let mut cursor = row_offset;
        let mut row = Vec::with_capacity(columns.len());
        for size in &sizes {
            let value = match size {
                1 => u32::from(tables[cursor]),
                2 => u32::from(u16::from_le_bytes([tables[cursor], tables[cursor + 1]])),
                4 => u32::from_le_bytes([
                    tables[cursor],
                    tables[cursor + 1],
                    tables[cursor + 2],
                    tables[cursor + 3],
                ]),
                _ => return Err(unsupported("unsupported metadata column width")),
            };
            row.push(value);
            cursor += size;
        }
        rows.push(row);
    }
    Ok(rows)
}

fn string_at(strings: &[u8], index: u32) -> AppResult<String> {
    if index == 0 {
        return Ok(String::new());
    }
    let start = index as usize;
    if start >= strings.len() {
        return Err(truncated("string heap index out of range"));
    }
    let end = strings[start..]
        .iter()
        .position(|&byte| byte == 0)
        .map(|length| start + length)
        .ok_or_else(|| truncated("string heap entry is not terminated"))?;
    Ok(String::from_utf8_lossy(&strings[start..end]).into_owned())
}

fn blob_at(blobs: &[u8], index: u32) -> AppResult<&[u8]> {
    if index == 0 {
        return Ok(&[]);
    }
    let start = index as usize;
    if start >= blobs.len() {
        return Err(truncated("blob heap index out of range"));
    }
    let first = blobs[start];
    let (length, prefix) = if first & 0x80 == 0 {
        (usize::from(first), 1)
    } else if first & 0xc0 == 0x80 {
        if start + 1 >= blobs.len() {
            return Err(truncated("blob heap entry exceeds heap size"));
        }
        (
            (usize::from(first & 0x3f) << 8) | usize::from(blobs[start + 1]),
            2,
        )
    } else if first & 0xe0 == 0xc0 {
        if start + 3 >= blobs.len() {
            return Err(truncated("blob heap entry exceeds heap size"));
        }
        (
            (usize::from(first & 0x1f) << 24)
                | (usize::from(blobs[start + 1]) << 16)
                | (usize::from(blobs[start + 2]) << 8)
                | usize::from(blobs[start + 3]),
            4,
        )
    } else {
        return Err(invalid("invalid blob heap header"));
    };
    let data_start = start + prefix;
    let end = data_start
        .checked_add(length)
        .ok_or_else(|| truncated("blob heap entry exceeds heap size"))?;
    if end > blobs.len() {
        return Err(truncated("blob heap entry exceeds heap size"));
    }
    Ok(&blobs[data_start..end])
}

// ── Parsing ─────────────────────────────────────────────────────────────────

/// Parse one WinMD file into its mergeable universe.
pub fn winmd_bytes(bytes: &[u8]) -> AppResult<ParsedWinmd> {
    let metadata = cli_metadata(bytes)?;
    let streams = metadata_streams(metadata)?;
    let heap_sizes = streams
        .tables
        .get(6)
        .copied()
        .ok_or_else(|| truncated("metadata table header exceeds stream size"))?;
    let layout = table_header(streams.tables, heap_sizes)?;
    let typedef = read_table(streams.tables, &layout, TYPEDEF_TABLE)?;
    let methoddef = read_table(streams.tables, &layout, METHODDEF_TABLE)?;
    let moduleref = read_table(streams.tables, &layout, MODULEREF_TABLE)?;
    let implmap = read_table(streams.tables, &layout, IMPLMAP_TABLE)?;
    let assembly = read_table(streams.tables, &layout, ASSEMBLY_TABLE)?;
    let _modules = read_table(streams.tables, &layout, MODULE_TABLE)?;

    let method_names = methoddef
        .iter()
        .map(|row| string_at(streams.strings, row[3]))
        .collect::<AppResult<Vec<_>>>()?;
    // Signatures are validated as bounded blobs but never decoded: the
    // inventory only needs names and ownership, so unknown conventions cannot
    // corrupt the universe.
    for row in &methoddef {
        let _signature = blob_at(streams.blobs, row[4])?;
    }
    let module_names = moduleref
        .iter()
        .map(|row| string_at(streams.strings, row[0]))
        .collect::<AppResult<Vec<_>>>()?;

    let mut owners: Vec<Option<(String, String, String)>> = vec![None; method_names.len()];
    let mut types = Vec::new();
    for (index, row) in typedef.iter().enumerate() {
        let name = string_at(streams.strings, row[1])?;
        let namespace = string_at(streams.strings, row[2])?;
        let start = (row[5] as usize).saturating_sub(1);
        let end = if index + 1 < typedef.len() {
            (typedef[index + 1][5] as usize).saturating_sub(1)
        } else {
            method_names.len()
        };
        if start > end || end > method_names.len() {
            return Err(truncated("TypeDef method list is out of range"));
        }
        for (method_index, owner) in owners.iter_mut().enumerate().take(end).skip(start) {
            *owner = Some((
                namespace.clone(),
                name.clone(),
                method_names[method_index].clone(),
            ));
        }
        if namespace.is_empty() {
            continue;
        }
        let methods = method_names[start..end]
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        types.push(WinmdType {
            namespace,
            name,
            interface: row[0] & TYPE_ATTRIBUTE_INTERFACE != 0,
            methods,
        });
    }

    let mut functions = Vec::new();
    for row in &implmap {
        let forwarded = row[1];
        if forwarded & 1 != 1 {
            continue;
        }
        let method_index = (forwarded >> 1) as usize;
        if method_index == 0 || method_index > method_names.len() {
            return Err(truncated("ImplMap references missing MethodDef"));
        }
        let scope = row[3] as usize;
        if scope == 0 || scope > module_names.len() {
            return Err(truncated("ImplMap references missing ModuleRef"));
        }
        let (namespace, type_name, method) = owners[method_index - 1]
            .clone()
            .ok_or_else(|| truncated("ImplMap method is not owned by a type"))?;
        functions.push(WinmdFunction {
            module: module_names[scope - 1].clone(),
            export: string_at(streams.strings, row[2])?,
            namespace,
            type_name,
            method,
        });
    }

    let assembly = assembly
        .first()
        .map(|row| string_at(streams.strings, row[7]))
        .transpose()?
        .filter(|name| !name.is_empty());
    functions.sort_by(|left, right| {
        canonical_dll(&left.module)
            .cmp(&canonical_dll(&right.module))
            .then_with(|| {
                left.export
                    .to_ascii_lowercase()
                    .cmp(&right.export.to_ascii_lowercase())
            })
            .then_with(|| left.namespace.cmp(&right.namespace))
            .then_with(|| left.type_name.cmp(&right.type_name))
            .then_with(|| left.method.cmp(&right.method))
    });
    types.sort_by(|left, right| {
        left.namespace
            .cmp(&right.namespace)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(ParsedWinmd {
        assembly,
        types,
        functions,
    })
}

// ── Universe construction ───────────────────────────────────────────────────

fn relative_slash(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn is_winmd(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("winmd"))
}

/// Walk `root` (or read the single file) and build the Windows API universe.
pub fn inventory_path(root: &Path) -> AppResult<WinmdUniverse> {
    let (base, entries) = if root.is_file() {
        (
            root.parent().unwrap_or(root).to_path_buf(),
            vec![root.to_path_buf()],
        )
    } else if root.is_dir() {
        let mut entries = Vec::new();
        let mut walk_errors = Vec::new();
        for entry in WalkDir::new(root).follow_links(false) {
            match entry {
                Ok(entry) if entry.file_type().is_file() && is_winmd(entry.path()) => {
                    entries.push(entry.path().to_path_buf());
                }
                Ok(_) => {}
                Err(error) => walk_errors.push(format!("{error}")),
            }
        }
        entries.sort();
        (root.to_path_buf(), entries)
    } else {
        return Err(AppError::new(
            ReasonCode::RcFsNotFound,
            format!("WinMD path not found: {}", root.display()),
        ));
    };

    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut fingerprints = Vec::new();
    let mut parsed_files = Vec::new();
    for path in entries {
        let relative = relative_slash(&base, &path);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                errors.push(WinmdError {
                    path: relative,
                    reason_code: ReasonCode::RcIo.as_u32(),
                    reason_name: ReasonCode::RcIo.name().to_string(),
                    message: format!("failed to read {}: {error}", path.display()),
                });
                continue;
            }
        };
        let sha256 = util::sha256_bytes(&bytes);
        fingerprints.push(format!("{relative}\0{sha256}"));
        match winmd_bytes(&bytes) {
            Ok(parsed) => {
                let method_count = parsed
                    .types
                    .iter()
                    .map(|ty| ty.methods.len())
                    .sum::<usize>();
                let interface_count = parsed
                    .types
                    .iter()
                    .filter(|ty| ty.interface && !ty.methods.is_empty())
                    .count();
                files.push(WinmdFile {
                    path: relative,
                    sha256,
                    size_bytes: bytes.len() as u64,
                    assembly: parsed.assembly.clone(),
                    type_count: parsed.types.len(),
                    method_count,
                    function_count: parsed.functions.len(),
                    interface_count,
                });
                parsed_files.push(parsed);
            }
            Err(error) => errors.push(WinmdError {
                path: relative,
                reason_code: error.code.as_u32(),
                reason_name: error.code.name().to_string(),
                message: error.message,
            }),
        }
    }
    fingerprints.sort();
    errors.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.reason_code.cmp(&right.reason_code))
            .then_with(|| left.message.cmp(&right.message))
    });
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let mut types = BTreeMap::<(String, String), (bool, BTreeSet<String>)>::new();
    let mut duplicate_type_count = 0usize;
    let mut functions = BTreeMap::<(String, String), WinmdFunction>::new();
    for parsed in parsed_files {
        for ty in parsed.types {
            let key = (ty.namespace, ty.name);
            if let Some(entry) = types.get_mut(&key) {
                duplicate_type_count += 1;
                entry.0 |= ty.interface;
                entry.1.extend(ty.methods);
            } else {
                types.insert(key, (ty.interface, ty.methods.into_iter().collect()));
            }
        }
        for function in parsed.functions {
            let key = (
                canonical_dll(&function.module),
                function.export.to_ascii_lowercase(),
            );
            functions.entry(key).or_insert(function);
        }
    }

    let mut namespaces = BTreeMap::<String, WinmdNamespaceStat>::new();
    for ((namespace, _), (interface, methods)) in &types {
        let entry = namespaces
            .entry(namespace.clone())
            .or_insert_with(|| WinmdNamespaceStat {
                namespace: namespace.clone(),
                type_count: 0,
                method_count: 0,
                function_count: 0,
                interface_count: 0,
            });
        entry.type_count += 1;
        entry.method_count += methods.len();
        if *interface && !methods.is_empty() {
            entry.interface_count += 1;
        }
    }

    let mut modules = BTreeMap::<String, (String, usize)>::new();
    for function in functions.values() {
        let namespace = namespaces
            .entry(function.namespace.clone())
            .or_insert_with(|| WinmdNamespaceStat {
                namespace: function.namespace.clone(),
                type_count: 0,
                method_count: 0,
                function_count: 0,
                interface_count: 0,
            });
        namespace.function_count += 1;
        let canonical = canonical_dll(&function.module);
        let entry = modules
            .entry(canonical)
            .or_insert_with(|| (function.module.clone(), 0));
        entry.1 += 1;
    }

    let interfaces = types
        .iter()
        .filter(|(_, (interface, methods))| *interface && !methods.is_empty())
        .map(|((namespace, name), (_, methods))| WinmdInterface {
            namespace: namespace.clone(),
            name: name.clone(),
            methods: methods.iter().cloned().collect(),
        })
        .collect::<Vec<_>>();
    let interface_method_count = interfaces
        .iter()
        .map(|interface| interface.methods.len())
        .sum();

    let functions = functions.into_values().collect::<Vec<_>>();
    let namespaces = namespaces.into_values().collect::<Vec<_>>();
    let modules = modules
        .into_values()
        .map(|(module, function_count)| WinmdModuleStat {
            module,
            function_count,
        })
        .collect::<Vec<_>>();

    Ok(WinmdUniverse {
        schema_version: WINMD_INVENTORY_SCHEMA_VERSION,
        metadata_fingerprint: util::sha256_bytes(fingerprints.join("\n").as_bytes()),
        winmd_file_count: fingerprints.len(),
        type_count: types.len(),
        function_count: functions.len(),
        interface_count: interfaces.len(),
        interface_method_count,
        duplicate_type_count,
        files,
        namespaces,
        modules,
        functions,
        interfaces,
        errors,
    })
}

// ── Registry diff ───────────────────────────────────────────────────────────

/// Diff the metadata universe against Casa1's registry.
pub fn diff_against_registry(universe: &WinmdUniverse, database: &ApiDatabase) -> WinmdDiff {
    let registry_exports = database
        .entries()
        .iter()
        .map(|entry| {
            (
                canonical_dll(&entry.dll),
                entry.export.to_ascii_lowercase(),
                entry.export.clone(),
            )
        })
        .collect::<Vec<_>>();
    let registry_export_keys = registry_exports
        .iter()
        .map(|(dll, export, _)| (dll.clone(), export.clone()))
        .collect::<BTreeSet<_>>();
    let mut registry_by_module = BTreeMap::<String, BTreeSet<String>>::new();
    for (dll, export, _) in &registry_exports {
        registry_by_module
            .entry(dll.clone())
            .or_default()
            .insert(export.clone());
    }

    let metadata_modules = universe
        .functions
        .iter()
        .map(|function| canonical_dll(&function.module))
        .collect::<BTreeSet<_>>();
    let mut metadata_exports = BTreeMap::<String, BTreeSet<String>>::new();
    for function in &universe.functions {
        metadata_exports
            .entry(canonical_dll(&function.module))
            .or_default()
            .insert(function.export.to_ascii_lowercase());
    }

    let mut missing_exports = Vec::new();
    let mut module_totals = BTreeMap::<String, (String, usize, usize, usize)>::new();
    let mut type_totals = BTreeMap::<(String, String), (usize, usize, usize)>::new();
    let mut modeled_function_count = 0usize;
    for function in &universe.functions {
        let canonical = canonical_dll(&function.module);
        let key = (canonical.clone(), function.export.to_ascii_lowercase());
        let modeled = registry_export_keys.contains(&key);
        if modeled {
            modeled_function_count += 1;
        } else {
            missing_exports.push(WinmdMissingExport {
                module: function.module.clone(),
                canonical_module: canonical.clone(),
                export: function.export.clone(),
                namespace: function.namespace.clone(),
                type_name: function.type_name.clone(),
                method: function.method.clone(),
            });
        }
        let module = module_totals
            .entry(canonical)
            .or_insert_with(|| (function.module.clone(), 0, 0, 0));
        module.1 += 1;
        if modeled {
            module.2 += 1;
        } else {
            module.3 += 1;
        }
        let ty = type_totals
            .entry((function.namespace.clone(), function.type_name.clone()))
            .or_insert((0, 0, 0));
        ty.0 += 1;
        if modeled {
            ty.1 += 1;
        } else {
            ty.2 += 1;
        }
    }

    let mut extra_registry_exports = Vec::new();
    for (dll, export, original) in &registry_exports {
        if metadata_modules.contains(dll)
            && metadata_exports
                .get(dll)
                .is_none_or(|exports| !exports.contains(export))
        {
            extra_registry_exports.push(WinmdExtraRegistryExport {
                module: dll.clone(),
                export: original.clone(),
            });
        }
    }
    extra_registry_exports.sort_by(|left, right| {
        left.module
            .cmp(&right.module)
            .then_with(|| {
                left.export
                    .to_ascii_lowercase()
                    .cmp(&right.export.to_ascii_lowercase())
            })
            .then_with(|| left.export.cmp(&right.export))
    });
    extra_registry_exports.dedup_by(|left, right| {
        left.module == right.module && left.export.eq_ignore_ascii_case(&right.export)
    });

    let registry_methods = database
        .interface_methods()
        .iter()
        .map(|method| {
            (
                method.interface.to_ascii_lowercase(),
                method.method.to_ascii_lowercase(),
                method.interface.clone(),
                method.method.clone(),
            )
        })
        .collect::<Vec<_>>();
    let registry_method_keys = registry_methods
        .iter()
        .map(|(interface, method, _, _)| (interface.clone(), method.clone()))
        .collect::<BTreeSet<_>>();
    let mut registry_by_interface = BTreeMap::<String, BTreeSet<String>>::new();
    for (interface, method, _, _) in &registry_methods {
        registry_by_interface
            .entry(interface.clone())
            .or_default()
            .insert(method.clone());
    }
    let metadata_interface_names = universe
        .interfaces
        .iter()
        .map(|interface| interface.name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut metadata_methods = BTreeMap::<String, BTreeSet<String>>::new();
    for interface in &universe.interfaces {
        metadata_methods
            .entry(interface.name.to_ascii_lowercase())
            .or_default()
            .extend(
                interface
                    .methods
                    .iter()
                    .map(|method| method.to_ascii_lowercase()),
            );
    }

    let mut missing_interface_methods = Vec::new();
    let mut interface_diffs = Vec::new();
    let mut fully_modeled_interface_count = 0usize;
    let mut partially_modeled_interface_count = 0usize;
    let mut missing_interface_count = 0usize;
    let mut modeled_interface_method_count = 0usize;
    let mut missing_interface_method_count = 0usize;
    for interface in &universe.interfaces {
        let key = interface.name.to_ascii_lowercase();
        let interface_known = registry_by_interface.contains_key(&key);
        let mut modeled = 0usize;
        let mut missing = 0usize;
        for method in &interface.methods {
            let method_key = (key.clone(), method.to_ascii_lowercase());
            if registry_method_keys.contains(&method_key) {
                modeled += 1;
                modeled_interface_method_count += 1;
            } else {
                missing += 1;
                missing_interface_method_count += 1;
                missing_interface_methods.push(WinmdMissingInterfaceMethod {
                    namespace: interface.namespace.clone(),
                    interface: interface.name.clone(),
                    method: method.clone(),
                    interface_known,
                });
            }
        }
        if missing == 0 {
            fully_modeled_interface_count += 1;
        } else {
            if modeled == 0 {
                missing_interface_count += 1;
            } else {
                partially_modeled_interface_count += 1;
            }
        }
        interface_diffs.push(WinmdInterfaceDiff {
            namespace: interface.namespace.clone(),
            interface: interface.name.clone(),
            method_count: interface.methods.len(),
            modeled_method_count: modeled,
            missing_method_count: missing,
        });
    }

    let mut extra_registry_interface_methods = Vec::new();
    for (interface, method, original_interface, original_method) in &registry_methods {
        if metadata_interface_names.contains(interface)
            && metadata_methods
                .get(interface)
                .is_none_or(|methods| !methods.contains(method))
        {
            extra_registry_interface_methods.push(WinmdExtraRegistryInterfaceMethod {
                interface: original_interface.clone(),
                method: original_method.clone(),
            });
        }
    }
    extra_registry_interface_methods.sort_by(|left, right| {
        left.interface
            .to_ascii_lowercase()
            .cmp(&right.interface.to_ascii_lowercase())
            .then_with(|| {
                left.method
                    .to_ascii_lowercase()
                    .cmp(&right.method.to_ascii_lowercase())
            })
            .then_with(|| left.interface.cmp(&right.interface))
            .then_with(|| left.method.cmp(&right.method))
    });
    extra_registry_interface_methods.dedup_by(|left, right| {
        left.interface.eq_ignore_ascii_case(&right.interface)
            && left.method.eq_ignore_ascii_case(&right.method)
    });

    let modules = module_totals
        .into_iter()
        .map(
            |(canonical_module, (module, function_count, modeled, missing))| WinmdModuleDiff {
                module,
                canonical_module,
                function_count,
                modeled_function_count: modeled,
                missing_function_count: missing,
            },
        )
        .collect::<Vec<_>>();
    let types = type_totals
        .into_iter()
        .map(
            |((namespace, type_name), (function_count, modeled, missing))| WinmdTypeDiff {
                namespace,
                type_name,
                function_count,
                modeled_function_count: modeled,
                missing_function_count: missing,
            },
        )
        .collect::<Vec<_>>();
    let missing_module_count = modules
        .iter()
        .filter(|module| module.modeled_function_count == 0 && module.missing_function_count > 0)
        .count();

    let extra_registry_export_count = extra_registry_exports.len();
    let extra_registry_interface_method_count = extra_registry_interface_methods.len();
    WinmdDiff {
        metadata_fingerprint: universe.metadata_fingerprint.clone(),
        missing_exports,
        extra_registry_exports,
        missing_interface_methods,
        extra_registry_interface_methods,
        modules,
        types,
        interfaces: interface_diffs,
        summary: WinmdDiffSummary {
            metadata_function_count: universe.functions.len(),
            modeled_function_count,
            missing_function_count: universe.functions.len() - modeled_function_count,
            registry_export_count: registry_export_keys.len(),
            extra_registry_export_count,
            metadata_module_count: universe.modules.len(),
            missing_module_count,
            interface_count: universe.interfaces.len(),
            fully_modeled_interface_count,
            partially_modeled_interface_count,
            missing_interface_count,
            interface_method_count: universe.interface_method_count,
            modeled_interface_method_count,
            missing_interface_method_count,
            extra_registry_interface_method_count,
            duplicate_type_count: universe.duplicate_type_count,
            parse_error_count: universe.errors.len(),
        },
    }
}

/// Build the complete universe + diff + deterministic human summary.
pub fn build_report(root: &Path, database: &ApiDatabase) -> AppResult<WinmdReport> {
    let universe = inventory_path(root)?;
    let diff = diff_against_registry(&universe, database);
    let human_summary = human_summary(&universe, &diff);
    Ok(WinmdReport {
        schema_version: WINMD_INVENTORY_SCHEMA_VERSION,
        universe,
        diff,
        human_summary,
    })
}

fn top_by_missing<T>(
    items: &[T],
    mut missing: impl FnMut(&T) -> usize,
    mut label: impl FnMut(&T) -> String,
) -> Vec<(usize, String)> {
    let mut ranked = items
        .iter()
        .map(|item| (missing(item), label(item)))
        .filter(|(count, _)| *count > 0)
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    ranked
}

/// Deterministic human-readable summary for CI logs and operator review.
pub fn human_summary(universe: &WinmdUniverse, diff: &WinmdDiff) -> String {
    let mut lines = Vec::new();
    lines.push("Casa1 WinMD inventory".to_string());
    lines.push(format!(
        "  metadata: {} file(s), fingerprint {}",
        universe.winmd_file_count, universe.metadata_fingerprint
    ));
    lines.push(format!(
        "  universe: {} type(s), {} function(s) in {} module(s), {} interface(s), {} interface method(s)",
        universe.type_count,
        universe.function_count,
        universe.modules.len(),
        universe.interface_count,
        universe.interface_method_count
    ));
    lines.push(format!(
        "  functions: {} metadata, {} modeled, {} missing",
        diff.summary.metadata_function_count,
        diff.summary.modeled_function_count,
        diff.summary.missing_function_count
    ));
    lines.push(format!(
        "  modules: {} in metadata, {} with no modeled export; {} registry export(s) absent from the contract",
        diff.summary.metadata_module_count,
        diff.summary.missing_module_count,
        diff.summary.extra_registry_export_count
    ));
    lines.push(format!(
        "  interfaces: {} total, {} fully modeled, {} partial, {} unmodeled",
        diff.summary.interface_count,
        diff.summary.fully_modeled_interface_count,
        diff.summary.partially_modeled_interface_count,
        diff.summary.missing_interface_count
    ));
    lines.push(format!(
        "  interface methods: {} metadata, {} modeled, {} missing; {} registry method(s) absent from the contract",
        diff.summary.interface_method_count,
        diff.summary.modeled_interface_method_count,
        diff.summary.missing_interface_method_count,
        diff.summary.extra_registry_interface_method_count
    ));
    lines.push(format!(
        "  duplicate types merged: {}; parse errors: {}",
        diff.summary.duplicate_type_count, diff.summary.parse_error_count
    ));

    let modules = top_by_missing(
        &diff.modules,
        |module| module.missing_function_count,
        |module| {
            format!(
                "{}/{} missing ({} modeled)",
                module.module, module.missing_function_count, module.modeled_function_count
            )
        },
    );
    if !modules.is_empty() {
        lines.push("  top missing modules:".to_string());
        for (missing, label) in modules.iter().take(20) {
            lines.push(format!("    {label} [{missing} missing]"));
        }
    }

    let interfaces = top_by_missing(
        &diff.interfaces,
        |interface| interface.missing_method_count,
        |interface| {
            format!(
                "{}::{} {}/{} missing",
                interface.namespace,
                interface.interface,
                interface.missing_method_count,
                interface.method_count
            )
        },
    );
    if !interfaces.is_empty() {
        lines.push("  top missing interfaces:".to_string());
        for (missing, label) in interfaces.iter().take(20) {
            lines.push(format!("    {label} [{missing} missing]"));
        }
    }

    let types = top_by_missing(
        &diff.types,
        |ty| ty.missing_function_count,
        |ty| {
            format!(
                "{}::{} {}/{} missing",
                ty.namespace, ty.type_name, ty.missing_function_count, ty.function_count
            )
        },
    );
    if !types.is_empty() {
        lines.push("  top missing types:".to_string());
        for (missing, label) in types.iter().take(20) {
            lines.push(format!("    {label} [{missing} missing]"));
        }
    }

    let mut method_counts = BTreeMap::<String, usize>::new();
    for method in &diff.missing_interface_methods {
        *method_counts.entry(method.method.clone()).or_default() += 1;
    }
    for function in &diff.missing_exports {
        *method_counts.entry(function.method.clone()).or_default() += 1;
    }
    let mut methods = method_counts.into_iter().collect::<Vec<_>>();
    methods.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    if !methods.is_empty() {
        lines.push("  top missing method names:".to_string());
        for (method, count) in methods.iter().take(20) {
            lines.push(format!("    {method} [{count} missing]"));
        }
    }

    for error in &universe.errors {
        lines.push(format!(
            "  parse error: {}: {} ({})",
            error.path, error.message, error.reason_name
        ));
    }
    lines.join("\n")
}

/// Write deterministic JSON (with a trailing newline), creating parents.
pub fn write_report(report: &WinmdReport, out: &Path) -> AppResult<()> {
    let json = serde_json::to_string_pretty(report).map_err(|error| {
        AppError::new(ReasonCode::RcIo, "failed to encode WinMD inventory report")
            .with_hint(error.to_string())
    })?;
    if let Some(parent) = out.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to create {}", parent.display()),
                &error,
            )
        })?;
    }
    fs::write(out, format!("{json}\n")).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write {}", out.display()),
            &error,
        )
    })
}

/// Default inventory output path used by callers that omit `--out`.
pub fn default_out_path() -> PathBuf {
    PathBuf::from("casa1-winmd-inventory.json")
}
