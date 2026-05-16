use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const IMAGE_DOS_SIGNATURE: u16 = 0x5a4d;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const RT_VERSION: u32 = 16;
const RT_MANIFEST: u32 = 24;

pub const STATUS_DLL_NOT_FOUND: u32 = 0xc000_0135;
pub const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xc000_0139;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_ptr: u32,
    pub raw_data_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDirectoryEntry {
    pub ty: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoadConfig {
    pub security_cookie: u64,
    pub guard_flags: u32,
    pub se_handler_table: u64,
    pub se_handler_count: u64,
    pub guard_cf_check_function_pointer: u64,
    pub guard_cf_dispatch_function_pointer: u64,
    pub guard_cf_function_table: u64,
    pub guard_cf_function_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImportSymbol {
    ByName { hint: u16, name: String },
    ByOrdinal { ordinal: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportThunk {
    pub symbol: ImportSymbol,
    pub iat_rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportDescriptor {
    pub dll_name: String,
    pub imports: Vec<ImportThunk>,
    pub delay_load: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExportTarget {
    Rva(u32),
    Forwarder(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportSymbol {
    pub ordinal: u32,
    pub name: Option<String>,
    pub target: ExportTarget,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelocationType {
    Absolute,
    HighLow,
    Dir64,
    Unsupported(u16),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelocationEntry {
    pub kind: RelocationType,
    pub offset: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelocationBlock {
    pub page_rva: u32,
    pub entries: Vec<RelocationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsDirectory {
    pub raw_data_start: u64,
    pub raw_data_end: u64,
    pub address_of_index: u64,
    pub address_of_callbacks: u64,
    pub callbacks: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    pub product_name: Option<String>,
    pub file_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManifestSource {
    Embedded,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssemblyIdentity {
    pub name: String,
    pub version: Option<String>,
    pub processor_architecture: Option<String>,
    pub public_key_token: Option<String>,
    pub type_attr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestInfo {
    pub source: ManifestSource,
    pub supported_os: Vec<String>,
    pub dpi_awareness: Option<String>,
    pub assemblies: Vec<AssemblyIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivationContextPlan {
    pub assemblies: Vec<AssemblyIdentity>,
    pub vc_runtime_assemblies: Vec<AssemblyIdentity>,
    pub vc_runtime_bindings: Vec<ActivationBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivationBinding {
    pub identity: AssemblyIdentity,
    pub activation_key: String,
    pub dlls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionMapping {
    pub name: String,
    pub virtual_address: u32,
    pub mapped_size: u32,
    pub raw_data_size: u32,
    pub protection: MemoryProtection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappedImage {
    pub preferred_base: u64,
    pub selected_base: u64,
    pub memory: Vec<u8>,
    pub sections: Vec<SectionMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedImport {
    pub requested_module: String,
    pub resolved_module: String,
    pub symbol: ImportSymbol,
    pub iat_rva: u32,
    pub export: ExportSymbol,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelayLoadResult {
    pub requested_module: String,
    pub resolved_module: String,
    pub symbol: ImportSymbol,
    pub iat_rva: u32,
    pub outcome: DelayLoadOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DelayLoadOutcome {
    Resolved(ExportSymbol),
    StructuredException { code: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleStage {
    TlsProcessAttach(u64),
    DllMainProcessAttach,
    TlsProcessDetach(u64),
    DllMainProcessDetach,
    TlsThreadAttach(u64),
    DllMainThreadAttach,
    TlsThreadDetach(u64),
    DllMainThreadDetach,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub module: String,
    pub stage: LifecycleStage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecyclePlan {
    pub load_order: Vec<String>,
    pub process_attach: Vec<LifecycleEvent>,
    pub process_detach: Vec<LifecycleEvent>,
    pub thread_start: Vec<LifecycleEvent>,
    pub thread_end: Vec<LifecycleEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedPe {
    pub machine: u16,
    pub number_of_sections: u16,
    pub characteristics: u16,
    pub optional_header_magic: u16,
    pub dll_characteristics: u16,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub data_directories: Vec<DataDirectory>,
    pub sections: Vec<PeSection>,
    pub debug_entries: Vec<DebugDirectoryEntry>,
    pub load_config: Option<LoadConfig>,
    pub imports: Vec<ImportDescriptor>,
    pub delay_imports: Vec<ImportDescriptor>,
    pub exports: Vec<ExportSymbol>,
    pub relocations: Vec<RelocationBlock>,
    pub tls_directory: Option<TlsDirectory>,
    pub version_info: VersionInfo,
    pub embedded_manifest: Option<ManifestInfo>,
    pub external_manifest: Option<ManifestInfo>,
}

impl ParsedPe {
    pub fn directory(&self, index: usize) -> DataDirectory {
        self.data_directories.get(index).copied().unwrap_or_default()
    }

    pub fn pointer_bytes(&self) -> usize {
        if self.optional_header_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            8
        } else {
            4
        }
    }

    pub fn dynamic_base(&self) -> bool {
        self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApiSetResolver {
    explicit: BTreeMap<String, String>,
}

impl ApiSetResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_mapping(mut self, contract: &str, host: &str) -> Self {
        self.explicit
            .insert(normalize_module_name(contract), normalize_module_name(host));
        self
    }

    pub fn resolve(&self, dll_name: &str) -> String {
        let normalized = normalize_module_name(dll_name);
        if let Some(host) = self.explicit.get(&normalized) {
            return host.clone();
        }
        if normalized.starts_with("api-ms-win-core-") {
            return "kernel32.dll".to_string();
        }
        if normalized.starts_with("api-ms-win-crt-") {
            return "ucrtbase.dll".to_string();
        }
        if normalized.starts_with("api-ms-win-security-") || normalized.starts_with("api-ms-win-service-") {
            return "advapi32.dll".to_string();
        }
        if normalized.starts_with("api-ms-win-shell-") {
            return "shell32.dll".to_string();
        }
        if normalized.starts_with("api-ms-win-com-") || normalized.starts_with("api-ms-win-core-com-") {
            return "ole32.dll".to_string();
        }
        if normalized.starts_with("ext-ms-win-ntuser-") {
            return "user32.dll".to_string();
        }
        normalized
    }
}

pub fn parse_from_file(path: &Path) -> AppResult<ParsedPe> {
    let bytes = fs::read(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcPeParseInvalid,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    let mut parsed = parse(&bytes)?;
    parsed.external_manifest = parse_external_manifest(path)?;
    Ok(parsed)
}

pub fn maybe_version_info_from_file(path: &Path) -> AppResult<Option<VersionInfo>> {
    let bytes = fs::read(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcPeParseInvalid,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    if bytes.len() < 2 || read_u16(&bytes, 0, "DOS signature").unwrap_or_default() != IMAGE_DOS_SIGNATURE {
        return Ok(None);
    }
    Ok(Some(parse(&bytes)?.version_info))
}

pub fn parse(bytes: &[u8]) -> AppResult<ParsedPe> {
    let dos_signature = read_u16(bytes, 0, "DOS signature")?;
    if dos_signature != IMAGE_DOS_SIGNATURE {
        return invalid("invalid DOS signature");
    }
    let pe_offset = read_u32(bytes, 0x3c, "e_lfanew")? as usize;
    checked_range(bytes, pe_offset, 24, "NT headers")?;
    let signature = read_u32(bytes, pe_offset, "NT signature")?;
    if signature != IMAGE_NT_SIGNATURE {
        return invalid("invalid PE signature");
    }

    let machine = read_u16(bytes, pe_offset + 4, "machine")?;
    let number_of_sections = read_u16(bytes, pe_offset + 6, "number of sections")?;
    let size_of_optional_header = read_u16(bytes, pe_offset + 20, "size of optional header")? as usize;
    let characteristics = read_u16(bytes, pe_offset + 22, "file characteristics")?;
    let optional_offset = pe_offset + 24;
    checked_range(bytes, optional_offset, size_of_optional_header, "optional header")?;

    let magic = read_u16(bytes, optional_offset, "optional header magic")?;
    let (pointer_bytes, minimum_optional_header_size, image_base_offset, data_directory_offset, data_directory_count_offset, format_name) =
        match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => (4_usize, 96_usize, 28_usize, 96_usize, 92_usize, "PE32"),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => (8_usize, 112_usize, 24_usize, 112_usize, 108_usize, "PE32+"),
            _ => return invalid(format!("unsupported optional header magic 0x{magic:04x}")),
        };
    if size_of_optional_header < minimum_optional_header_size {
        return invalid(format!("optional header is too small for {format_name}"));
    }

    let address_of_entry_point = read_u32(bytes, optional_offset + 16, "entry point")?;
    let image_base = read_pointer(bytes, optional_offset + image_base_offset, pointer_bytes, "image base")?;
    let section_alignment = read_u32(bytes, optional_offset + 32, "section alignment")?;
    let file_alignment = read_u32(bytes, optional_offset + 36, "file alignment")?;
    let size_of_image = read_u32(bytes, optional_offset + 56, "size of image")?;
    let size_of_headers = read_u32(bytes, optional_offset + 60, "size of headers")?;
    let dll_characteristics = read_u16(bytes, optional_offset + 70, "DLL characteristics")?;
    let number_of_rva_and_sizes =
        read_u32(bytes, optional_offset + data_directory_count_offset, "data directory count")? as usize;
    let available_directories = ((size_of_optional_header - data_directory_offset) / 8).min(number_of_rva_and_sizes);
    let mut data_directories = vec![DataDirectory::default(); 16.max(available_directories)];
    for index in 0..available_directories {
        let directory_offset = optional_offset + data_directory_offset + index * 8;
        data_directories[index] = DataDirectory {
            virtual_address: read_u32(bytes, directory_offset, "data directory RVA")?,
            size: read_u32(bytes, directory_offset + 4, "data directory size")?,
        };
    }

    let section_table_offset = optional_offset + size_of_optional_header;
    let mut sections = Vec::with_capacity(number_of_sections as usize);
    for section_index in 0..number_of_sections as usize {
        let offset = section_table_offset + section_index * 40;
        checked_range(bytes, offset, 40, "section header")?;
        let name_bytes = slice(bytes, offset, 8, "section name")?;
        let name_end = name_bytes.iter().position(|value| *value == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        let virtual_size = read_u32(bytes, offset + 8, "section virtual size")?;
        let virtual_address = read_u32(bytes, offset + 12, "section virtual address")?;
        let raw_data_size = read_u32(bytes, offset + 16, "section raw data size")?;
        let raw_data_ptr = read_u32(bytes, offset + 20, "section raw data pointer")?;
        let characteristics = read_u32(bytes, offset + 36, "section characteristics")?;
        if raw_data_size > 0 {
            checked_range(bytes, raw_data_ptr as usize, raw_data_size as usize, "section raw data")?;
        }
        let virtual_end = virtual_address
            .checked_add(align_up(virtual_size.max(raw_data_size), section_alignment)?)
            .ok_or_else(|| pe_error("section virtual range overflow"))?;
        if virtual_end > size_of_image {
            return invalid(format!("section {name} exceeds SizeOfImage"));
        }
        sections.push(PeSection {
            name,
            virtual_address,
            virtual_size,
            raw_data_ptr,
            raw_data_size,
            characteristics,
        });
    }

    if size_of_headers as usize > bytes.len() {
        return invalid("SizeOfHeaders exceeds file size");
    }

    let debug_entries = parse_debug_entries(bytes, &sections, &data_directories, size_of_headers)?;
    let load_config = parse_load_config(bytes, &sections, &data_directories, pointer_bytes)?;
    let imports = parse_import_directory(bytes, &sections, &data_directories, false, image_base, pointer_bytes)?;
    let delay_imports = parse_delay_import_directory(bytes, &sections, &data_directories, image_base, pointer_bytes)?;
    let exports = parse_export_directory(bytes, &sections, &data_directories)?;
    let relocations = parse_relocations(bytes, &sections, &data_directories)?;
    let tls_directory = parse_tls_directory(bytes, &sections, &data_directories, image_base, pointer_bytes)?;
    let version_info = parse_version_resource(bytes, &sections, &data_directories)?;
    let embedded_manifest = parse_embedded_manifest(bytes, &sections, &data_directories)?;

    Ok(ParsedPe {
        machine,
        number_of_sections,
        characteristics,
        optional_header_magic: magic,
        dll_characteristics,
        address_of_entry_point,
        image_base,
        size_of_image,
        size_of_headers,
        section_alignment,
        file_alignment,
        data_directories,
        sections,
        debug_entries,
        load_config,
        imports,
        delay_imports,
        exports,
        relocations,
        tls_directory,
        version_info,
        embedded_manifest,
        external_manifest: None,
    })
}

pub fn select_image_base(image: &ParsedPe, image_hash: &str, dtm: bool) -> u64 {
    if !image.dynamic_base() || image.relocations.is_empty() {
        return image.image_base;
    }
    let alignment = 0x1_0000_u64;
    let seed = hash_seed(image_hash);
    let randomized_seed = if dtm {
        seed
    } else {
        seed ^ runtime_seed()
    };
    if image.pointer_bytes() == 4 {
        let preferred_region = 0x1000_0000_u64;
        return preferred_region + ((randomized_seed & 0x0000_0000_0fff_0000) / alignment) * alignment;
    }
    let preferred_region = 0x0000_1800_0000_0000_u64;
    preferred_region + ((randomized_seed & 0x0000_0fff_ffff_0000) / alignment) * alignment
}

pub fn map_image(bytes: &[u8], image: &ParsedPe, image_hash: &str, dtm: bool) -> AppResult<MappedImage> {
    let selected_base = select_image_base(image, image_hash, dtm);
    let mut memory = vec![0u8; image.size_of_image as usize];
    let headers_size = image.size_of_headers as usize;
    memory[..headers_size].copy_from_slice(slice(bytes, 0, headers_size, "headers")?);

    let mut mappings = Vec::with_capacity(image.sections.len());
    for section in &image.sections {
        let mapped_size = align_up(section.virtual_size.max(section.raw_data_size), image.section_alignment)?;
        let destination = checked_range_mut(&mut memory, section.virtual_address as usize, mapped_size as usize, "mapped section")?;
        if section.raw_data_size > 0 {
            let raw_bytes = slice(
                bytes,
                section.raw_data_ptr as usize,
                section.raw_data_size as usize,
                "section raw payload",
            )?;
            destination[..raw_bytes.len()].copy_from_slice(raw_bytes);
        }
        mappings.push(SectionMapping {
            name: section.name.clone(),
            virtual_address: section.virtual_address,
            mapped_size,
            raw_data_size: section.raw_data_size,
            protection: protection_from_characteristics(section.characteristics),
        });
    }

    let mut mapped = MappedImage {
        preferred_base: image.image_base,
        selected_base,
        memory,
        sections: mappings,
    };
    apply_relocations(image, &mut mapped)?;
    Ok(mapped)
}

pub fn apply_relocations(image: &ParsedPe, mapped: &mut MappedImage) -> AppResult<()> {
    let delta = mapped.selected_base as i128 - image.image_base as i128;
    if delta == 0 {
        return Ok(());
    }
    for block in &image.relocations {
        for entry in &block.entries {
            let target_rva = block
                .page_rva
                .checked_add(entry.offset as u32)
                .ok_or_else(|| pe_error("relocation target overflow"))?;
            match entry.kind {
                RelocationType::Absolute => continue,
                RelocationType::Dir64 => {
                    let target = read_u64(&mapped.memory, target_rva as usize, "DIR64 relocation target")?;
                    let relocated = (target as i128)
                        .checked_add(delta)
                        .ok_or_else(|| pe_error("DIR64 relocation overflow"))? as u64;
                    write_u64(&mut mapped.memory, target_rva as usize, relocated)?;
                }
                RelocationType::HighLow => {
                    let target = read_u32(&mapped.memory, target_rva as usize, "HIGHLOW relocation target")?;
                    let relocated = (target as i128)
                        .checked_add(delta)
                        .ok_or_else(|| pe_error("HIGHLOW relocation overflow"))? as u32;
                    write_u32(&mut mapped.memory, target_rva as usize, relocated)?;
                }
                RelocationType::Unsupported(kind) => {
                    return invalid(format!("unsupported relocation type {kind}"));
                }
            }
        }
    }
    Ok(())
}

pub fn resolve_imports(
    image: &ParsedPe,
    export_tables: &BTreeMap<String, Vec<ExportSymbol>>,
    resolver: &ApiSetResolver,
) -> AppResult<Vec<ResolvedImport>> {
    let mut resolved = Vec::new();
    for descriptor in image.imports.iter().chain(image.delay_imports.iter()) {
        let resolved_module = resolver.resolve(&descriptor.dll_name);
        let exports = export_tables.get(&resolved_module).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcImportMissing,
                format!("missing import provider {resolved_module}"),
            )
        })?;
        for thunk in &descriptor.imports {
            let export = resolve_export_symbol(
                &thunk.symbol,
                &resolved_module,
                export_tables,
                exports,
                resolver,
                &mut BTreeSet::new(),
            )?;
            resolved.push(ResolvedImport {
                requested_module: descriptor.dll_name.clone(),
                resolved_module: resolved_module.clone(),
                symbol: thunk.symbol.clone(),
                iat_rva: thunk.iat_rva,
                export,
            });
        }
    }
    Ok(resolved)
}

pub fn resolve_delay_imports(
    image: &ParsedPe,
    export_tables: &BTreeMap<String, Vec<ExportSymbol>>,
    resolver: &ApiSetResolver,
) -> AppResult<Vec<DelayLoadResult>> {
    let mut results = Vec::new();
    for descriptor in &image.delay_imports {
        let resolved_module = resolver.resolve(&descriptor.dll_name);
        let Some(exports) = export_tables.get(&resolved_module) else {
            for thunk in &descriptor.imports {
                results.push(DelayLoadResult {
                    requested_module: descriptor.dll_name.clone(),
                    resolved_module: resolved_module.clone(),
                    symbol: thunk.symbol.clone(),
                    iat_rva: thunk.iat_rva,
                    outcome: DelayLoadOutcome::StructuredException {
                        code: STATUS_DLL_NOT_FOUND,
                    },
                });
            }
            continue;
        };
        for thunk in &descriptor.imports {
            let outcome = match lookup_export_symbol(
                &thunk.symbol,
                &resolved_module,
                export_tables,
                exports,
                resolver,
                &mut BTreeSet::new(),
            ) {
                Ok(export) => DelayLoadOutcome::Resolved(export),
                Err(ExportLookupFailure::MissingProvider(_)) => {
                    DelayLoadOutcome::StructuredException {
                        code: STATUS_DLL_NOT_FOUND,
                    }
                }
                Err(ExportLookupFailure::MissingSymbol(_)) => {
                    DelayLoadOutcome::StructuredException {
                        code: STATUS_ENTRYPOINT_NOT_FOUND,
                    }
                }
                Err(ExportLookupFailure::Parser(error)) => return Err(error),
            };
            results.push(DelayLoadResult {
                requested_module: descriptor.dll_name.clone(),
                resolved_module: resolved_module.clone(),
                symbol: thunk.symbol.clone(),
                iat_rva: thunk.iat_rva,
                outcome,
            });
        }
    }
    Ok(results)
}

pub fn plan_lifecycle(
    root_module: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
    tls_callbacks: &BTreeMap<String, Vec<u64>>,
) -> AppResult<LifecyclePlan> {
    let root = normalize_module_name(root_module);
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut load_order = Vec::new();
    visit_module(&root, dependencies, &mut visiting, &mut visited, &mut load_order)?;

    let mut process_attach = Vec::new();
    let mut process_detach = Vec::new();
    let mut thread_start = Vec::new();
    let mut thread_end = Vec::new();
    for module in &load_order {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            process_attach.push(LifecycleEvent {
                module: module.clone(),
                stage: LifecycleStage::TlsProcessAttach(*callback),
            });
        }
        process_attach.push(LifecycleEvent {
            module: module.clone(),
            stage: LifecycleStage::DllMainProcessAttach,
        });
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            thread_start.push(LifecycleEvent {
                module: module.clone(),
                stage: LifecycleStage::TlsThreadAttach(*callback),
            });
        }
        thread_start.push(LifecycleEvent {
            module: module.clone(),
            stage: LifecycleStage::DllMainThreadAttach,
        });
    }
    for module in load_order.iter().rev() {
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            thread_end.push(LifecycleEvent {
                module: module.clone(),
                stage: LifecycleStage::TlsThreadDetach(*callback),
            });
        }
        thread_end.push(LifecycleEvent {
            module: module.clone(),
            stage: LifecycleStage::DllMainThreadDetach,
        });
        for callback in tls_callbacks.get(module).into_iter().flatten() {
            process_detach.push(LifecycleEvent {
                module: module.clone(),
                stage: LifecycleStage::TlsProcessDetach(*callback),
            });
        }
        process_detach.push(LifecycleEvent {
            module: module.clone(),
            stage: LifecycleStage::DllMainProcessDetach,
        });
    }

    Ok(LifecyclePlan {
        load_order,
        process_attach,
        process_detach,
        thread_start,
        thread_end,
    })
}

pub fn build_activation_context(manifest: &ManifestInfo) -> ActivationContextPlan {
    let vc_runtime_assemblies = manifest
        .assemblies
        .iter()
        .filter(|assembly| assembly.name.starts_with("Microsoft.VC"))
        .cloned()
        .collect::<Vec<_>>();
    let mut vc_runtime_bindings = vc_runtime_assemblies
        .iter()
        .map(|identity| ActivationBinding {
            identity: identity.clone(),
            activation_key: activation_key(identity),
            dlls: vc_runtime_dlls(identity),
        })
        .collect::<Vec<_>>();
    vc_runtime_bindings.sort_by(|left, right| left.activation_key.cmp(&right.activation_key));
    ActivationContextPlan {
        assemblies: manifest.assemblies.clone(),
        vc_runtime_assemblies,
        vc_runtime_bindings,
    }
}

#[derive(Debug)]
enum ExportLookupFailure {
    MissingProvider(String),
    MissingSymbol(String),
    Parser(AppError),
}

fn parse_debug_entries(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    size_of_headers: u32,
) -> AppResult<Vec<DebugDirectoryEntry>> {
    let directory = directories.get(IMAGE_DIRECTORY_ENTRY_DEBUG).copied().unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    if directory.size % 28 != 0 {
        return invalid("debug directory size is not aligned to IMAGE_DEBUG_DIRECTORY entries");
    }
    let offset = rva_to_file_offset(directory.virtual_address, directory.size, sections, size_of_headers)?;
    let count = directory.size as usize / 28;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let entry_offset = offset + index * 28;
        checked_range(bytes, entry_offset, 28, "debug directory entry")?;
        entries.push(DebugDirectoryEntry {
            ty: read_u32(bytes, entry_offset + 12, "debug type")?,
            size_of_data: read_u32(bytes, entry_offset + 16, "debug data size")?,
            address_of_raw_data: read_u32(bytes, entry_offset + 20, "debug raw RVA")?,
            pointer_to_raw_data: read_u32(bytes, entry_offset + 24, "debug raw pointer")?,
        });
    }
    Ok(entries)
}

fn parse_load_config(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    pointer_bytes: usize,
) -> AppResult<Option<LoadConfig>> {
    let directory = directories.get(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG).copied().unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(None);
    }
    let offset = rva_to_file_offset(directory.virtual_address, 4, sections, 0)?;
    let load_config_size = read_u32(bytes, offset, "load config size")? as usize;
    let section = section_for_rva(sections, directory.virtual_address, 1, false)
        .ok_or_else(|| pe_error("load config directory is not backed by file data"))?;
    let relative = directory
        .virtual_address
        .checked_sub(section.virtual_address)
        .ok_or_else(|| pe_error("load config directory underflow"))? as usize;
    let available_size = section.raw_data_size as usize - relative;
    let present_size = load_config_size
        .max(directory.size as usize)
        .min(available_size);
    let (
        security_cookie_offset,
        se_handler_table_offset,
        se_handler_count_offset,
        guard_cf_check_offset,
        guard_cf_dispatch_offset,
        guard_cf_function_table_offset,
        guard_cf_function_count_offset,
        guard_flags_offset,
    ) = if pointer_bytes == 8 {
        (
            Some(0x58_usize),
            0x60_usize,
            0x68_usize,
            0x70_usize,
            0x78_usize,
            0x80_usize,
            0x88_usize,
            0x90_usize,
        )
    } else if present_size >= 0x48 {
        (
            Some(0x3c_usize),
            0x40_usize,
            0x44_usize,
            0x48_usize,
            0x4c_usize,
            0x50_usize,
            0x54_usize,
            0x58_usize,
        )
    } else {
        (
            None,
            0x38_usize,
            0x3c_usize,
            0x48_usize,
            0x4c_usize,
            0x50_usize,
            0x54_usize,
            0x58_usize,
        )
    };
    Ok(Some(LoadConfig {
        security_cookie: security_cookie_offset
            .map(|field_offset| {
                read_load_config_pointer(
                    bytes,
                    offset,
                    present_size,
                    field_offset,
                    pointer_bytes,
                    "SecurityCookie",
                )
            })
            .transpose()?
            .unwrap_or(0),
        guard_flags: read_load_config_u32(bytes, offset, present_size, guard_flags_offset, "GuardFlags")?,
        se_handler_table: read_load_config_pointer(
            bytes,
            offset,
            present_size,
            se_handler_table_offset,
            pointer_bytes,
            "SEHandlerTable",
        )?,
        se_handler_count: read_load_config_pointer(
            bytes,
            offset,
            present_size,
            se_handler_count_offset,
            pointer_bytes,
            "SEHandlerCount",
        )?,
        guard_cf_check_function_pointer: read_load_config_pointer(
            bytes,
            offset,
            present_size,
            guard_cf_check_offset,
            pointer_bytes,
            "GuardCFCheckFunctionPointer",
        )?,
        guard_cf_dispatch_function_pointer: read_load_config_pointer(
            bytes,
            offset,
            present_size,
            guard_cf_dispatch_offset,
            pointer_bytes,
            "GuardCFDispatchFunctionPointer",
        )?,
        guard_cf_function_table: read_load_config_pointer(
            bytes,
            offset,
            present_size,
            guard_cf_function_table_offset,
            pointer_bytes,
            "GuardCFFunctionTable",
        )?,
        guard_cf_function_count: read_load_config_pointer(
            bytes,
            offset,
            present_size,
            guard_cf_function_count_offset,
            pointer_bytes,
            "GuardCFFunctionCount",
        )?,
    }))
}

fn read_load_config_u32(
    bytes: &[u8],
    load_config_offset: usize,
    present_size: usize,
    field_offset: usize,
    label: &str,
) -> AppResult<u32> {
    if field_offset + 4 > present_size {
        return Ok(0);
    }
    read_u32(bytes, load_config_offset + field_offset, label)
}

fn read_load_config_pointer(
    bytes: &[u8],
    load_config_offset: usize,
    present_size: usize,
    field_offset: usize,
    pointer_bytes: usize,
    label: &str,
) -> AppResult<u64> {
    if field_offset + pointer_bytes > present_size {
        return Ok(0);
    }
    read_pointer(bytes, load_config_offset + field_offset, pointer_bytes, label)
}

fn parse_import_directory(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    delay_load: bool,
    image_base: u64,
    pointer_bytes: usize,
) -> AppResult<Vec<ImportDescriptor>> {
    let directory = directories.get(IMAGE_DIRECTORY_ENTRY_IMPORT).copied().unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    let mut imports = Vec::new();
    let mut descriptor_offset = rva_to_file_offset(directory.virtual_address, 20, sections, 0)?;
    let end = descriptor_offset + directory.size as usize;
    let mut iterations = 0usize;
    while descriptor_offset + 20 <= end {
        iterations += 1;
        if iterations > 4096 {
            return invalid("import descriptor table exceeded the safety limit");
        }
        let original_first_thunk = read_u32(bytes, descriptor_offset, "OriginalFirstThunk")?;
        let name_rva = read_u32(bytes, descriptor_offset + 12, "import DLL name RVA")?;
        let first_thunk = read_u32(bytes, descriptor_offset + 16, "FirstThunk")?;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let dll_name = read_c_string_from_rva(bytes, sections, name_rva, "import DLL name")?;
        let thunk_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
        let thunk_addresses = read_import_thunks(bytes, sections, thunk_rva, first_thunk, image_base, pointer_bytes)?;
        imports.push(ImportDescriptor {
            dll_name,
            imports: thunk_addresses,
            delay_load,
        });
        descriptor_offset += 20;
    }
    Ok(imports)
}

fn parse_delay_import_directory(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    image_base: u64,
    pointer_bytes: usize,
) -> AppResult<Vec<ImportDescriptor>> {
    let directory = directories.get(13).copied().unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    if directory.size % 32 != 0 {
        return invalid("delay import descriptor size is not aligned to IMAGE_DELAYLOAD_DESCRIPTOR");
    }
    let mut descriptors = Vec::new();
    let mut offset = rva_to_file_offset(directory.virtual_address, 32, sections, 0)?;
    let end = offset + directory.size as usize;
    while offset + 32 <= end {
        let name_rva = read_u32(bytes, offset + 4, "delay import DLL name RVA")?;
        let iat_rva = read_u32(bytes, offset + 12, "delay import IAT RVA")?;
        let int_rva = read_u32(bytes, offset + 16, "delay import INT RVA")?;
        if name_rva == 0 && iat_rva == 0 && int_rva == 0 {
            break;
        }
        let dll_name = read_c_string_from_rva(bytes, sections, name_rva, "delay import DLL name")?;
        let thunk_rva = if int_rva != 0 { int_rva } else { iat_rva };
        descriptors.push(ImportDescriptor {
            dll_name,
            imports: read_import_thunks(bytes, sections, thunk_rva, iat_rva, image_base, pointer_bytes)?,
            delay_load: true,
        });
        offset += 32;
    }
    Ok(descriptors)
}

fn parse_export_directory(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
) -> AppResult<Vec<ExportSymbol>> {
    let directory = directories.get(IMAGE_DIRECTORY_ENTRY_EXPORT).copied().unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    let offset = rva_to_file_offset(directory.virtual_address, 40, sections, 0)?;
    checked_range(bytes, offset, 40, "export directory")?;
    let ordinal_base = read_u32(bytes, offset + 16, "ordinal base")?;
    let number_of_functions = read_u32(bytes, offset + 20, "export function count")? as usize;
    let number_of_names = read_u32(bytes, offset + 24, "export name count")? as usize;
    let address_of_functions = read_u32(bytes, offset + 28, "AddressOfFunctions")?;
    let address_of_names = read_u32(bytes, offset + 32, "AddressOfNames")?;
    let address_of_name_ordinals = read_u32(bytes, offset + 36, "AddressOfNameOrdinals")?;

    let mut names_by_index = BTreeMap::new();
    for index in 0..number_of_names {
        let name_rva = read_u32_at_rva(bytes, sections, address_of_names, index, "export name RVA")?;
        let ordinal_index = read_u16_at_rva(bytes, sections, address_of_name_ordinals, index, "export ordinal index")? as usize;
        let name = read_c_string_from_rva(bytes, sections, name_rva, "export name")?;
        names_by_index.insert(ordinal_index, name);
    }

    let mut exports = Vec::with_capacity(number_of_functions);
    for function_index in 0..number_of_functions {
        let function_rva = read_u32_at_rva(bytes, sections, address_of_functions, function_index, "export function RVA")?;
        let target = if function_rva >= directory.virtual_address
            && function_rva < directory.virtual_address.saturating_add(directory.size)
        {
            ExportTarget::Forwarder(read_c_string_from_rva(bytes, sections, function_rva, "forwarded export")?)
        } else {
            ExportTarget::Rva(function_rva)
        };
        exports.push(ExportSymbol {
            ordinal: ordinal_base.checked_add(function_index as u32).ok_or_else(|| pe_error("ordinal overflow"))?,
            name: names_by_index.get(&function_index).cloned(),
            target,
        });
    }
    Ok(exports)
}

fn parse_relocations(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
) -> AppResult<Vec<RelocationBlock>> {
    let directory = directories.get(IMAGE_DIRECTORY_ENTRY_BASERELOC).copied().unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    let mut blocks = Vec::new();
    let offset = rva_to_file_offset(directory.virtual_address, directory.size, sections, 0)?;
    let end = offset + directory.size as usize;
    let mut cursor = offset;
    while cursor + 8 <= end {
        let page_rva = read_u32(bytes, cursor, "relocation page RVA")?;
        let block_size = read_u32(bytes, cursor + 4, "relocation block size")? as usize;
        if page_rva == 0 && block_size == 0 {
            break;
        }
        if block_size < 8 || cursor + block_size > end {
            return invalid("relocation block exceeds directory bounds");
        }
        if (block_size - 8) % 2 != 0 {
            return invalid("relocation block has a truncated entry");
        }
        let mut entries = Vec::new();
        let mut entry_offset = cursor + 8;
        while entry_offset < cursor + block_size {
            let raw = read_u16(bytes, entry_offset, "relocation entry")?;
            let kind = match raw >> 12 {
                IMAGE_REL_BASED_ABSOLUTE => RelocationType::Absolute,
                IMAGE_REL_BASED_HIGHLOW => RelocationType::HighLow,
                IMAGE_REL_BASED_DIR64 => RelocationType::Dir64,
                other => RelocationType::Unsupported(other),
            };
            entries.push(RelocationEntry {
                kind,
                offset: raw & 0x0fff,
            });
            entry_offset += 2;
        }
        blocks.push(RelocationBlock { page_rva, entries });
        cursor += block_size;
    }
    Ok(blocks)
}

fn parse_tls_directory(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    image_base: u64,
    pointer_bytes: usize,
) -> AppResult<Option<TlsDirectory>> {
    let directory = directories.get(IMAGE_DIRECTORY_ENTRY_TLS).copied().unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(None);
    }
    let directory_size = if pointer_bytes == 8 { 40 } else { 24 };
    let offset = rva_to_file_offset(directory.virtual_address, directory_size, sections, 0)?;
    checked_range(bytes, offset, directory_size as usize, "TLS directory")?;
    let raw_data_start = read_pointer(bytes, offset, pointer_bytes, "TLS raw data start")?;
    let raw_data_end = read_pointer(bytes, offset + pointer_bytes, pointer_bytes, "TLS raw data end")?;
    let address_of_index = read_pointer(bytes, offset + pointer_bytes * 2, pointer_bytes, "TLS address of index")?;
    let address_of_callbacks = read_pointer(
        bytes,
        offset + pointer_bytes * 3,
        pointer_bytes,
        "TLS address of callbacks",
    )?;
    let callbacks = if address_of_callbacks == 0 {
        Vec::new()
    } else {
        let callbacks_rva = address_of_callbacks
            .checked_sub(image_base)
            .ok_or_else(|| pe_error("TLS callback VA is below image base"))? as u32;
        read_callback_array(bytes, sections, callbacks_rva, pointer_bytes)?
    };
    Ok(Some(TlsDirectory {
        raw_data_start,
        raw_data_end,
        address_of_index,
        address_of_callbacks,
        callbacks,
    }))
}

fn parse_version_resource(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
) -> AppResult<VersionInfo> {
    let Some(blob) = find_resource_blob(bytes, sections, directories, RT_VERSION)? else {
        return Ok(VersionInfo::default());
    };
    parse_version_info_blob(&blob)
}

fn parse_embedded_manifest(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
) -> AppResult<Option<ManifestInfo>> {
    let Some(blob) = find_resource_blob(bytes, sections, directories, RT_MANIFEST)? else {
        return Ok(None);
    };
    Ok(Some(parse_manifest_bytes(&blob, ManifestSource::Embedded)?))
}

fn parse_external_manifest(path: &Path) -> AppResult<Option<ManifestInfo>> {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Ok(None);
    };
    let manifest_path = path.with_file_name(format!("{file_name}.manifest"));
    if !manifest_path.exists() {
        return Ok(None);
    }
    let contents = fs::read(&manifest_path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcPeParseInvalid,
            format!("failed to read {}", manifest_path.display()),
            &error,
        )
    })?;
    Ok(Some(parse_manifest_bytes(&contents, ManifestSource::External)?))
}

fn parse_manifest_bytes(bytes: &[u8], source: ManifestSource) -> AppResult<ManifestInfo> {
    let text = decode_manifest_bytes(bytes)?;
    let document = Document::parse(&text).map_err(|error| {
        AppError::new(ReasonCode::RcPeParseInvalid, "failed to parse manifest XML")
            .with_hint(error.to_string())
    })?;
    let mut supported_os = document
        .descendants()
        .filter(|node| node.has_tag_name(("urn:schemas-microsoft-com:compatibility.v1", "supportedOS")) || node.tag_name().name() == "supportedOS")
        .filter_map(|node| node.attribute("Id").or_else(|| node.attribute("id")))
        .map(str::to_string)
        .collect::<Vec<_>>();
    supported_os.sort();
    supported_os.dedup();

    let dpi_awareness = document.descendants().find_map(|node| {
        let name = node.tag_name().name();
        if name == "dpiAware" || name == "dpiAwareness" {
            node.text().map(|value| value.trim().to_string())
        } else {
            None
        }
    });

    let mut assemblies = document
        .descendants()
        .filter(|node| node.tag_name().name() == "assemblyIdentity")
        .filter_map(|node| {
            let name = node.attribute("name")?.to_string();
            Some(AssemblyIdentity {
                name,
                version: node.attribute("version").map(str::to_string),
                processor_architecture: node.attribute("processorArchitecture").map(str::to_string),
                public_key_token: node.attribute("publicKeyToken").map(str::to_string),
                type_attr: node.attribute("type").map(str::to_string),
            })
        })
        .collect::<Vec<_>>();
    assemblies.sort_by(|left, right| left.name.cmp(&right.name));
    assemblies.dedup_by(|left, right| left == right);

    Ok(ManifestInfo {
        source,
        supported_os,
        dpi_awareness,
        assemblies,
    })
}

fn decode_manifest_bytes(bytes: &[u8]) -> AppResult<String> {
    if bytes.starts_with(&[0xff, 0xfe]) {
        return decode_utf16(&bytes[2..]);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return invalid("big-endian UTF-16 manifests are not supported");
    }
    if bytes.len() >= 2 && bytes[1] == 0 {
        return decode_utf16(bytes);
    }
    std::str::from_utf8(bytes)
        .map(|value| value.to_string())
        .map_err(|error| {
            AppError::new(ReasonCode::RcPeParseInvalid, "manifest payload is not valid UTF-8")
                .with_hint(error.to_string())
        })
}

fn decode_utf16(bytes: &[u8]) -> AppResult<String> {
    if bytes.len() % 2 != 0 {
        return invalid("UTF-16 payload has an odd byte length");
    }
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&words)
        .map_err(|error| AppError::new(ReasonCode::RcPeParseInvalid, "invalid UTF-16 payload").with_hint(error.to_string()))
}

fn parse_version_info_blob(bytes: &[u8]) -> AppResult<VersionInfo> {
    let (root_length, _, _) = read_block_header(bytes, 0)?;
    if root_length > bytes.len() {
        return invalid("VS_VERSION_INFO length exceeds resource size");
    }
    let (key, after_key) = read_utf16_key(bytes, 6, root_length)?;
    if key != "VS_VERSION_INFO" {
        return invalid("version resource root key is not VS_VERSION_INFO");
    }
    let root_value_length = read_u16(bytes, 2, "version root value length")? as usize;
    let mut cursor = align4(after_key)?;
    let mut version = VersionInfo::default();
    if root_value_length >= 16 && cursor + root_value_length <= root_length {
        let signature = read_u32(bytes, cursor, "VS_FIXEDFILEINFO signature")?;
        if signature == 0xfeef04bd && root_value_length >= 16 {
            let file_version_ms = read_u32(bytes, cursor + 8, "dwFileVersionMS")?;
            let file_version_ls = read_u32(bytes, cursor + 12, "dwFileVersionLS")?;
            version.file_version = Some(format_version(file_version_ms, file_version_ls));
        }
    }
    cursor = align4(cursor + root_value_length)?;
    while cursor + 6 <= root_length {
        let child_length = read_u16(bytes, cursor, "version child length")? as usize;
        if child_length == 0 || cursor + child_length > root_length {
            break;
        }
        let (child_key, child_after_key) = read_utf16_key(bytes, cursor + 6, cursor + child_length)?;
        if child_key == "StringFileInfo" {
            parse_string_file_info(bytes, cursor, child_after_key, cursor + child_length, &mut version)?;
        }
        cursor = align4(cursor + child_length)?;
    }
    Ok(version)
}

fn parse_string_file_info(
    bytes: &[u8],
    block_offset: usize,
    after_key: usize,
    block_end: usize,
    version: &mut VersionInfo,
) -> AppResult<()> {
    let mut cursor = align4(after_key)?;
    let _ = block_offset;
    while cursor + 6 <= block_end {
        let table_length = read_u16(bytes, cursor, "string table length")? as usize;
        if table_length == 0 || cursor + table_length > block_end {
            break;
        }
        let (_, table_after_key) = read_utf16_key(bytes, cursor + 6, cursor + table_length)?;
        let mut string_cursor = align4(table_after_key)?;
        while string_cursor + 6 <= cursor + table_length {
            let string_length = read_u16(bytes, string_cursor, "string entry length")? as usize;
            if string_length == 0 || string_cursor + string_length > cursor + table_length {
                break;
            }
            let (name, after_name) = read_utf16_key(bytes, string_cursor + 6, string_cursor + string_length)?;
            let value_offset = align4(after_name)?;
            let value = read_utf16_value(bytes, value_offset, string_cursor + string_length);
            if name.eq_ignore_ascii_case("ProductName") && !value.is_empty() {
                version.product_name = Some(value);
            } else if name.eq_ignore_ascii_case("FileVersion") && !value.is_empty() {
                version.file_version = Some(value);
            }
            string_cursor = align4(string_cursor + string_length)?;
        }
        cursor = align4(cursor + table_length)?;
    }
    Ok(())
}

fn read_utf16_value(bytes: &[u8], mut offset: usize, end: usize) -> String {
    let mut words = Vec::new();
    while offset + 2 <= end {
        let word = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;
        if word == 0 {
            break;
        }
        words.push(word);
    }
    String::from_utf16_lossy(&words).trim().to_string()
}

fn find_resource_blob(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    type_id: u32,
) -> AppResult<Option<Vec<u8>>> {
    let directory = directories.get(IMAGE_DIRECTORY_ENTRY_RESOURCE).copied().unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(None);
    }
    let resource_section = section_for_rva(sections, directory.virtual_address, 1, true)
        .ok_or_else(|| pe_error("resource directory RVA is not covered by any section"))?;
    let section_bytes = slice(
        bytes,
        resource_section.raw_data_ptr as usize,
        resource_section.raw_data_size as usize,
        "resource section raw bytes",
    )?;
    let Some((data_rva, data_size)) = find_resource_data_entry(
        section_bytes,
        resource_section.virtual_address,
        directory.virtual_address,
        directory.virtual_address,
        Some(type_id),
        0,
    )? else {
        return Ok(None);
    };
    let offset = rva_to_file_offset(data_rva, data_size, sections, 0)?;
    Ok(Some(slice(bytes, offset, data_size as usize, "resource payload")?.to_vec()))
}

fn find_resource_data_entry(
    resource_section_bytes: &[u8],
    section_rva: u32,
    root_rva: u32,
    directory_rva: u32,
    target_id: Option<u32>,
    depth: u8,
) -> AppResult<Option<(u32, u32)>> {
    let relative = directory_rva
        .checked_sub(section_rva)
        .ok_or_else(|| pe_error("resource directory underflow"))? as usize;
    checked_range(resource_section_bytes, relative, 16, "resource directory")?;
    let named_entries = read_u16(resource_section_bytes, relative + 12, "resource named entry count")? as usize;
    let id_entries = read_u16(resource_section_bytes, relative + 14, "resource id entry count")? as usize;
    let total_entries = named_entries + id_entries;
    for index in 0..total_entries {
        let entry_offset = relative + 16 + index * 8;
        checked_range(resource_section_bytes, entry_offset, 8, "resource entry")?;
        let name = read_u32(resource_section_bytes, entry_offset, "resource entry name")?;
        if let Some(expected_id) = target_id {
            if name & 0x8000_0000 != 0 || (name & 0xffff) != expected_id {
                continue;
            }
        }
        let payload = read_u32(resource_section_bytes, entry_offset + 4, "resource entry payload")?;
        if payload & 0x8000_0000 != 0 {
            let child_rva = root_rva
                .checked_add(payload & 0x7fff_ffff)
                .ok_or_else(|| pe_error("resource subdirectory overflow"))?;
            if let Some(result) = find_resource_data_entry(
                resource_section_bytes,
                section_rva,
                root_rva,
                child_rva,
                None,
                depth + 1,
            )? {
                return Ok(Some(result));
            }
        } else if depth >= 2 {
            let data_entry_rva = root_rva
                .checked_add(payload & 0x7fff_ffff)
                .ok_or_else(|| pe_error("resource data entry overflow"))?;
            let data_relative = data_entry_rva
                .checked_sub(section_rva)
                .ok_or_else(|| pe_error("resource data entry underflow"))? as usize;
            checked_range(resource_section_bytes, data_relative, 16, "resource data entry")?;
            let offset_to_data = read_u32(resource_section_bytes, data_relative, "resource OffsetToData")?;
            let size = read_u32(resource_section_bytes, data_relative + 4, "resource Size")?;
            return Ok(Some((offset_to_data, size)));
        }
    }
    Ok(None)
}

fn read_import_thunks(
    bytes: &[u8],
    sections: &[PeSection],
    table_rva: u32,
    iat_rva: u32,
    image_base: u64,
    pointer_bytes: usize,
) -> AppResult<Vec<ImportThunk>> {
    let mut imports = Vec::new();
    let mut index = 0usize;
    let ordinal_flag = 1_u64 << (pointer_bytes * 8 - 1);
    loop {
        if index > 8192 {
            return invalid("import thunk table exceeded the safety limit");
        }
        let thunk_value = read_pointer_at_rva(bytes, sections, table_rva, index, pointer_bytes, "import thunk")?;
        if thunk_value == 0 {
            break;
        }
        let symbol = if thunk_value & ordinal_flag != 0 {
            ImportSymbol::ByOrdinal {
                ordinal: (thunk_value & 0xffff) as u16,
            }
        } else {
            let import_by_name_rva = if thunk_value >= image_base {
                thunk_value
                    .checked_sub(image_base)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| pe_error(format!("import thunk value {thunk_value:#x} does not fit in RVA space")))?
            } else {
                u32::try_from(thunk_value)
                    .map_err(|_| pe_error(format!("import thunk value {thunk_value:#x} does not fit in RVA space")))?
            };
            let hint_name_offset = rva_to_file_offset(import_by_name_rva, 2, sections, 0)?;
            let hint = read_u16(bytes, hint_name_offset, "import hint")?;
            let name = read_c_string(bytes, hint_name_offset + 2, "import name")?;
            ImportSymbol::ByName { hint, name }
        };
        imports.push(ImportThunk {
            symbol,
            iat_rva: iat_rva + (index as u32 * pointer_bytes as u32),
        });
        index += 1;
    }
    Ok(imports)
}

fn read_callback_array(
    bytes: &[u8],
    sections: &[PeSection],
    callbacks_rva: u32,
    pointer_bytes: usize,
) -> AppResult<Vec<u64>> {
    let mut callbacks = Vec::new();
    let mut index = 0usize;
    loop {
        if index > 256 {
            return invalid("TLS callback array exceeded the safety limit");
        }
        let callback = read_pointer_at_rva(bytes, sections, callbacks_rva, index, pointer_bytes, "TLS callback")?;
        if callback == 0 {
            break;
        }
        callbacks.push(callback);
        index += 1;
    }
    Ok(callbacks)
}

fn resolve_export_symbol(
    symbol: &ImportSymbol,
    current_module: &str,
    export_tables: &BTreeMap<String, Vec<ExportSymbol>>,
    exports: &[ExportSymbol],
    resolver: &ApiSetResolver,
    visited: &mut BTreeSet<String>,
) -> AppResult<ExportSymbol> {
    match lookup_export_symbol(symbol, current_module, export_tables, exports, resolver, visited) {
        Ok(export) => Ok(export),
        Err(ExportLookupFailure::MissingProvider(module)) => Err(AppError::new(
            ReasonCode::RcImportMissing,
            format!("missing forwarded import provider {module}"),
        )),
        Err(ExportLookupFailure::MissingSymbol(description)) => Err(AppError::new(
            ReasonCode::RcImportMissing,
            format!("missing import {description}"),
        )),
        Err(ExportLookupFailure::Parser(error)) => Err(error),
    }
}

fn lookup_export_symbol(
    symbol: &ImportSymbol,
    current_module: &str,
    export_tables: &BTreeMap<String, Vec<ExportSymbol>>,
    exports: &[ExportSymbol],
    resolver: &ApiSetResolver,
    visited: &mut BTreeSet<String>,
) -> Result<ExportSymbol, ExportLookupFailure> {
    let lookup_key = format!("{}::{symbol:?}", current_module);
    if !visited.insert(lookup_key) {
        return Err(ExportLookupFailure::Parser(pe_error("export forwarder cycle detected")));
    }
    let export = match symbol {
        ImportSymbol::ByName { name, .. } => exports
            .iter()
            .find(|export| export.name.as_deref() == Some(name.as_str()))
            .cloned(),
        ImportSymbol::ByOrdinal { ordinal } => exports
            .iter()
            .find(|export| export.ordinal == *ordinal as u32)
            .cloned(),
    }
    .ok_or_else(|| ExportLookupFailure::MissingSymbol(format!("{symbol:?} from {current_module}")))?;

    match &export.target {
        ExportTarget::Rva(_) => Ok(export),
        ExportTarget::Forwarder(forwarder) => {
            let (module_name, forwarded_symbol) =
                parse_forwarder_string(forwarder).map_err(ExportLookupFailure::Parser)?;
            let resolved_module = resolver.resolve(&module_name);
            let next_exports = export_tables
                .get(&resolved_module)
                .ok_or_else(|| ExportLookupFailure::MissingProvider(resolved_module.clone()))?;
            lookup_export_symbol(
                &forwarded_symbol,
                &resolved_module,
                export_tables,
                next_exports,
                resolver,
                visited,
            )
        }
    }
}

fn activation_key(identity: &AssemblyIdentity) -> String {
    format!(
        "{}|{}|{}|{}",
        identity.name.to_ascii_lowercase(),
        identity.version.as_deref().unwrap_or("*"),
        identity.processor_architecture.as_deref().unwrap_or("*"),
        identity.public_key_token.as_deref().unwrap_or("*")
    )
}

fn vc_runtime_dlls(identity: &AssemblyIdentity) -> Vec<String> {
    let name = identity.name.to_ascii_lowercase();
    if name.contains(".crt") {
        vec![
            "concrt140.dll".to_string(),
            "msvcp140.dll".to_string(),
            "vcruntime140.dll".to_string(),
            "vcruntime140_1.dll".to_string(),
        ]
    } else if name.contains(".mfc") {
        vec!["mfc140u.dll".to_string(), "mfcm140u.dll".to_string()]
    } else if name.contains(".openmp") {
        vec!["vcomp140.dll".to_string()]
    } else {
        Vec::new()
    }
}

fn parse_forwarder_string(value: &str) -> AppResult<(String, ImportSymbol)> {
    let Some((module, symbol)) = value.split_once('.') else {
        return invalid("forwarder string is missing the module separator");
    };
    if let Some(rest) = symbol.strip_prefix('#') {
        let ordinal = rest.parse::<u16>().map_err(|error| {
            AppError::new(ReasonCode::RcPeParseInvalid, "forwarder ordinal is not numeric")
                .with_hint(error.to_string())
        })?;
        Ok((normalize_module_name(module), ImportSymbol::ByOrdinal { ordinal }))
    } else {
        Ok((
            normalize_module_name(module),
            ImportSymbol::ByName {
                hint: 0,
                name: symbol.to_string(),
            },
        ))
    }
}

fn visit_module(
    module: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    load_order: &mut Vec<String>,
) -> AppResult<()> {
    if visited.contains(module) {
        return Ok(());
    }
    if !visiting.insert(module.to_string()) {
        return invalid(format!("dependency cycle detected at {module}"));
    }
    for dependency in dependencies.get(module).into_iter().flatten() {
        let dependency = normalize_module_name(dependency);
        visit_module(&dependency, dependencies, visiting, visited, load_order)?;
    }
    visiting.remove(module);
    visited.insert(module.to_string());
    load_order.push(module.to_string());
    Ok(())
}

fn protection_from_characteristics(characteristics: u32) -> MemoryProtection {
    MemoryProtection {
        read: characteristics & IMAGE_SCN_MEM_READ != 0,
        write: characteristics & IMAGE_SCN_MEM_WRITE != 0,
        execute: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
    }
}

fn format_version(ms: u32, ls: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        ms >> 16,
        ms & 0xffff,
        ls >> 16,
        ls & 0xffff
    )
}

fn normalize_module_name(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.contains('.') {
        normalized
    } else {
        format!("{normalized}.dll")
    }
}

fn hash_seed(image_hash: &str) -> u64 {
    image_hash
        .as_bytes()
        .chunks(2)
        .take(8)
        .enumerate()
        .fold(0_u64, |accumulator, (index, chunk)| {
            let byte = std::str::from_utf8(chunk)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok())
                .unwrap_or(index as u8);
            (accumulator << 8) | byte as u64
        })
}

fn runtime_seed() -> u64 {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos() as u64)
        .unwrap_or(0);
    timestamp ^ std::process::id() as u64
}

fn rva_to_file_offset(
    rva: u32,
    size: u32,
    sections: &[PeSection],
    size_of_headers: u32,
) -> AppResult<usize> {
    if size == 0 {
        return Ok(rva as usize);
    }
    if size_of_headers > 0 {
        let end = rva
            .checked_add(size)
            .ok_or_else(|| pe_error("RVA range overflow"))?;
        if rva < size_of_headers && end <= size_of_headers {
            return Ok(rva as usize);
        }
    }
    let section = section_for_rva(sections, rva, size, false)
        .ok_or_else(|| pe_error(format!("RVA 0x{rva:08x} is not backed by file data")))?;
    let relative = rva - section.virtual_address;
    Ok(section.raw_data_ptr as usize + relative as usize)
}

fn section_for_rva<'a>(
    sections: &'a [PeSection],
    rva: u32,
    size: u32,
    allow_virtual_padding: bool,
) -> Option<&'a PeSection> {
    sections.iter().find(|section| {
        let start = section.virtual_address;
        let max_size = if allow_virtual_padding {
            section.virtual_size.max(section.raw_data_size)
        } else {
            section.raw_data_size
        };
        let end = start.checked_add(max_size).unwrap_or(u32::MAX);
        let requested_end = rva.checked_add(size).unwrap_or(u32::MAX);
        rva >= start && requested_end <= end
    })
}

fn read_u16_at_rva(bytes: &[u8], sections: &[PeSection], rva: u32, index: usize, label: &str) -> AppResult<u16> {
    let offset = rva_to_file_offset(rva + (index * 2) as u32, 2, sections, 0)?;
    read_u16(bytes, offset, label)
}

fn read_u32_at_rva(bytes: &[u8], sections: &[PeSection], rva: u32, index: usize, label: &str) -> AppResult<u32> {
    let offset = rva_to_file_offset(rva + (index * 4) as u32, 4, sections, 0)?;
    read_u32(bytes, offset, label)
}

fn read_pointer_at_rva(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u32,
    index: usize,
    pointer_bytes: usize,
    label: &str,
) -> AppResult<u64> {
    match pointer_bytes {
        4 => Ok(read_u32_at_rva(bytes, sections, rva, index, label)? as u64),
        8 => read_u64_at_rva(bytes, sections, rva, index, label),
        _ => invalid(format!("unsupported pointer width {pointer_bytes}")),
    }
}

fn read_u64_at_rva(bytes: &[u8], sections: &[PeSection], rva: u32, index: usize, label: &str) -> AppResult<u64> {
    let offset = rva_to_file_offset(rva + (index * 8) as u32, 8, sections, 0)?;
    read_u64(bytes, offset, label)
}

fn read_pointer(bytes: &[u8], offset: usize, pointer_bytes: usize, label: &str) -> AppResult<u64> {
    match pointer_bytes {
        4 => Ok(read_u32(bytes, offset, label)? as u64),
        8 => read_u64(bytes, offset, label),
        _ => invalid(format!("unsupported pointer width {pointer_bytes}")),
    }
}

fn read_c_string_from_rva(bytes: &[u8], sections: &[PeSection], rva: u32, label: &str) -> AppResult<String> {
    let offset = rva_to_file_offset(rva, 1, sections, 0)?;
    read_c_string(bytes, offset, label)
}

fn read_c_string(bytes: &[u8], offset: usize, label: &str) -> AppResult<String> {
    let end = bytes[offset..]
        .iter()
        .position(|value| *value == 0)
        .map(|index| offset + index)
        .ok_or_else(|| pe_error(format!("{label} is not NUL-terminated")))?;
    std::str::from_utf8(&bytes[offset..end])
        .map(|value| value.to_string())
        .map_err(|error| AppError::new(ReasonCode::RcPeParseInvalid, format!("{label} is not valid UTF-8")).with_hint(error.to_string()))
}

fn read_block_header(bytes: &[u8], offset: usize) -> AppResult<(usize, usize, usize)> {
    let length = read_u16(bytes, offset, "resource block length")? as usize;
    let value_length = read_u16(bytes, offset + 2, "resource block value length")? as usize;
    let ty = read_u16(bytes, offset + 4, "resource block type")? as usize;
    Ok((length, value_length, ty))
}

fn read_utf16_key(bytes: &[u8], start: usize, end: usize) -> AppResult<(String, usize)> {
    if start > end {
        return invalid("UTF-16 key starts after its block end");
    }
    let mut offset = start;
    let mut words = Vec::new();
    while offset + 2 <= end {
        let word = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;
        if word == 0 {
            return Ok((String::from_utf16_lossy(&words), offset));
        }
        words.push(word);
    }
    invalid("UTF-16 key is missing a terminator")
}

fn align4(value: usize) -> AppResult<usize> {
    let aligned = (value + 3) & !3;
    if aligned < value {
        return invalid("4-byte alignment overflow");
    }
    Ok(aligned)
}

fn align_up(value: u32, alignment: u32) -> AppResult<u32> {
    if alignment == 0 {
        return invalid("alignment cannot be zero");
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - remainder)
            .ok_or_else(|| pe_error("alignment overflow"))
    }
}

fn slice<'a>(bytes: &'a [u8], offset: usize, size: usize, label: &str) -> AppResult<&'a [u8]> {
    checked_range(bytes, offset, size, label)?;
    Ok(&bytes[offset..offset + size])
}

fn checked_range(bytes: &[u8], offset: usize, size: usize, label: &str) -> AppResult<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| pe_error(format!("{label} range overflow")))?;
    if end > bytes.len() {
        return invalid(format!("{label} exceeds file size"));
    }
    Ok(())
}

fn checked_range_mut<'a>(bytes: &'a mut [u8], offset: usize, size: usize, label: &str) -> AppResult<&'a mut [u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| pe_error(format!("{label} range overflow")))?;
    if end > bytes.len() {
        return invalid(format!("{label} exceeds mapped image size"));
    }
    Ok(&mut bytes[offset..end])
}

fn read_u16(bytes: &[u8], offset: usize, label: &str) -> AppResult<u16> {
    let slice = slice(bytes, offset, 2, label)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], offset: usize, label: &str) -> AppResult<u32> {
    let slice = slice(bytes, offset, 4, label)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], offset: usize, label: &str) -> AppResult<u64> {
    let slice = slice(bytes, offset, 8, label)?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> AppResult<()> {
    let slice = checked_range_mut(bytes, offset, 4, "write_u32")?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> AppResult<()> {
    let slice = checked_range_mut(bytes, offset, 8, "write_u64")?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn pe_error(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcPeParseInvalid, message.into())
}

fn invalid<T>(message: impl Into<String>) -> AppResult<T> {
    Err(pe_error(message))
}

#[allow(dead_code)]
fn _external_manifest_path(path: &Path) -> PathBuf {
    let file_name = path.file_name().and_then(|value| value.to_str()).unwrap_or_default();
    path.with_file_name(format!("{file_name}.manifest"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_load_config_accepts_older_x86_layout() {
        let mut bytes = vec![0_u8; 0x80];
        write_u32(&mut bytes, 0x00, 0x40).expect("write load config size");
        write_u32(&mut bytes, 0x38, 0x007b_7358).expect("write SEH table");
        write_u32(&mut bytes, 0x3c, 625).expect("write SEH count");
        let sections = vec![PeSection {
            name: ".rdata".to_string(),
            virtual_address: 0x1000,
            virtual_size: bytes.len() as u32,
            raw_data_ptr: 0,
            raw_data_size: bytes.len() as u32,
            characteristics: IMAGE_SCN_MEM_READ,
        }];
        let mut directories = vec![DataDirectory::default(); IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG + 1];
        directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = DataDirectory {
            virtual_address: 0x1000,
            size: 0x40,
        };

        let load_config = parse_load_config(&bytes, &sections, &directories, 4)
            .expect("parse load config")
            .expect("load config present");

        assert_eq!(load_config.security_cookie, 0);
        assert_eq!(load_config.guard_flags, 0);
        assert_eq!(load_config.se_handler_table, 0x007b_7358);
        assert_eq!(load_config.se_handler_count, 625);
        assert_eq!(load_config.guard_cf_check_function_pointer, 0);
        assert_eq!(load_config.guard_cf_dispatch_function_pointer, 0);
        assert_eq!(load_config.guard_cf_function_table, 0);
        assert_eq!(load_config.guard_cf_function_count, 0);
    }

    #[test]
    fn parse_load_config_reads_x86_security_cookie() {
        let mut bytes = vec![0_u8; 0x80];
        write_u32(&mut bytes, 0x00, 0x60).expect("write load config size");
        write_u32(&mut bytes, 0x3c, 0x0123_4567).expect("write security cookie");
        write_u32(&mut bytes, 0x40, 0x007b_7358).expect("write SEH table");
        write_u32(&mut bytes, 0x44, 625).expect("write SEH count");
        let sections = vec![PeSection {
            name: ".rdata".to_string(),
            virtual_address: 0x1000,
            virtual_size: bytes.len() as u32,
            raw_data_ptr: 0,
            raw_data_size: bytes.len() as u32,
            characteristics: IMAGE_SCN_MEM_READ,
        }];
        let mut directories = vec![DataDirectory::default(); IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG + 1];
        directories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = DataDirectory {
            virtual_address: 0x1000,
            size: 0x60,
        };

        let load_config = parse_load_config(&bytes, &sections, &directories, 4)
            .expect("parse load config")
            .expect("load config present");

        assert_eq!(load_config.security_cookie, 0x0123_4567);
        assert_eq!(load_config.se_handler_table, 0x007b_7358);
        assert_eq!(load_config.se_handler_count, 625);
    }
}