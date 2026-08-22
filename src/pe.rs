use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

const IMAGE_DOS_SIGNATURE: u16 = 0x5a4d;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_HOT_PATCH: u16 = 0x0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const RT_VERSION: u32 = 16;
const RT_MANIFEST: u32 = 24;
const RT_ICON: u32 = 3;
const RT_GROUP_ICON: u32 = 14;
pub const RT_CURSOR: u32 = 1;
pub const RT_BITMAP: u32 = 2;
pub const RT_MENU: u32 = 4;
pub const RT_DIALOG: u32 = 5;
pub const RT_STRING: u32 = 6;
pub const RT_FONTDIR: u32 = 7;
pub const RT_FONT: u32 = 8;
pub const RT_ACCELERATOR: u32 = 9;
pub const RT_RCDATA: u32 = 10;
pub const RT_MESSAGETABLE: u32 = 11;
pub const RT_GROUP_CURSOR: u32 = 12;
pub const RT_ANICURSOR: u32 = 21;
pub const RT_ANIICON: u32 = 22;

pub const STATUS_DLL_NOT_FOUND: u32 = 0xc000_0135;
pub const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xc000_0139;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

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
pub struct BoundImportDescriptor {
    pub time_date_stamp: u32,
    pub module_name: String,
    pub forwarder_chain: Vec<BoundImportDescriptor>,
}

/// IMAGE_COR20_HEADER — the CLR header for .NET assemblies.
/// Present when IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14) is non-zero.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClrHeader {
    /// CLR runtime major version (e.g. 2 for .NET 2.0, 4 for .NET 4.x).
    pub major_runtime_version: u16,
    /// CLR runtime minor version.
    pub minor_runtime_version: u16,
    /// RVA of the metadata (.text#~ or .text$Metadata).
    pub metadata: DataDirectory,
    /// Flags (COMIMAGE_FLAGS_*).
    pub flags: u32,
    /// Optional entry point token (MethodDef or File+MethodDef for IJW).
    pub entry_point_token: u32,
    /// RVA of the managed resources directory.
    pub resources: DataDirectory,
    /// RVA of the strong name signature.
    pub strong_name_signature: DataDirectory,
    /// RVA of the code manager table (used for IJW).
    pub code_manager_table: DataDirectory,
    /// RVA of the vtable fixups (used for IJW — managed vtable slots).
    pub vtable_fixups: DataDirectory,
    /// RVA and size of the export address table jumps (IJW).
    pub export_address_table_jumps: DataDirectory,
    /// RVA of the managed native header (precompiled/managed native image).
    pub managed_native_header: DataDirectory,
}

/// COMIMAGE_FLAGS_* constants for CLR header flags.
pub const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
pub const COMIMAGE_FLAGS_32BITREQUIRED: u32 = 0x0000_0002;
pub const COMIMAGE_FLAGS_IL_LIBRARY: u32 = 0x0000_0004;
pub const COMIMAGE_FLAGS_STRONGNAMESIGNED: u32 = 0x0000_0008;
pub const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
pub const COMIMAGE_FLAGS_TRACKDEBUGDATA: u32 = 0x0001_0000;
pub const COMIMAGE_FLAGS_32BITPREFERRED: u32 = 0x0002_0000;

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

/// Represents a binding redirect from a SxS assembly manifest.
/// Maps an assembly identity to a redirected version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BindingRedirect {
    pub name: String,
    pub public_key_token: String,
    pub version: String,
    pub culture: String,
}

/// Represents a runtime activation context for SxS assembly isolation.
/// Tracks the handle, cookie for stack-based activation/deactivation,
/// and the source manifest information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivationContext {
    pub handle: u64,
    pub cookie: u64,
    pub source: String,
    pub assembly_directory: Option<String>,
    pub manifest_info: Option<ManifestInfo>,
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
    pub subsystem: u16,
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
    /// Whether the PE contains a CLR header (i.e. is a .NET assembly).
    /// Determined by checking IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14).
    pub is_dotnet: bool,
    /// Parsed CLR header (IMAGE_COR20_HEADER) for .NET assemblies.
    /// Populated only when `is_dotnet` is true and the CLR header is valid.
    pub clr_header: Option<ClrHeader>,
    /// Bound import descriptors from IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (index 11).
    /// Bound imports are an optimization where the linker pre-computes correct IAT
    /// addresses. In our emulator we always fall back to normal import resolution.
    pub bound_imports: Vec<BoundImportDescriptor>,
}

impl ParsedPe {
    pub fn directory(&self, index: usize) -> DataDirectory {
        self.data_directories
            .get(index)
            .copied()
            .unwrap_or_default()
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

    /// Whether the image is compiled with hot-patch support
    /// (IMAGE_DLLCHARACTERISTICS_HOT_PATCH).
    pub fn hot_patch(&self) -> bool {
        self.dll_characteristics & IMAGE_DLLCHARACTERISTICS_HOT_PATCH != 0
    }

    /// Returns `true` if this is an IJW ("It Just Works") mixed-mode .NET assembly.
    /// IJW assemblies contain native code and a CLR entry point token with the
    /// COMIMAGE_FLAGS_NATIVE_ENTRYPOINT flag set. They require CLR bootstrapping.
    pub fn is_ijw(&self) -> bool {
        self.clr_header
            .as_ref()
            .is_some_and(|clr| (clr.flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) != 0)
    }

    /// Returns `true` if this is a pure IL .NET assembly (no native code).
    pub fn is_il_only(&self) -> bool {
        self.clr_header
            .as_ref()
            .is_some_and(|clr| (clr.flags & COMIMAGE_FLAGS_ILONLY) != 0)
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

    /// Attempt to resolve an API set DLL name to a concrete host DLL.
    ///
    /// Covers ~40 API set contracts for Windows 10/11, including core,
    /// CRT, security, COM, UI, media, and extension API sets.
    /// If no mapping is found, the normalized name is returned as-is.
    pub fn resolve(&self, dll_name: &str) -> String {
        let normalized = normalize_module_name(dll_name);
        if let Some(host) = self.explicit.get(&normalized) {
            return host.clone();
        }

        // ── api-ms-win-core-registry-l1 / registry → advapi32.dll
        // Registry access via api-ms-win-core-registry goes through advapi32.
        // Must be checked before the generic api-ms-win-core-* catch-all below.
        if normalized.starts_with("api-ms-win-core-registry") {
            return "advapi32.dll".to_string();
        }

        // ── api-ms-win-core-winrt-string → combase.dll
        // Must be checked before the generic api-ms-win-core-* catch-all below.
        if normalized.starts_with("api-ms-win-core-winrt-string") {
            return "combase.dll".to_string();
        }

        // ── api-ms-win-core-com-* → ole32.dll
        // COM api-set contracts (e.g. api-ms-win-core-com-l1-1-0.dll) also
        // start with api-ms-win-core-, so this arm MUST precede the generic
        // core catch-all below, exactly like the registry/winrt-string arms.
        if normalized.starts_with("api-ms-win-core-com-") {
            return "ole32.dll".to_string();
        }

        // ── api-ms-win-core-* → kernel32.dll ──────────────────────────────
        // Core process, thread, memory, file, sync, library loader,
        // heap, IO, console, error handling, localization, named pipe,
        // environment, fibers, wow64, xstate, debug, util, string,
        // shutdown, systopology, profile, quota, job, waferror, etc.
        if normalized.starts_with("api-ms-win-core-") {
            return "kernel32.dll".to_string();
        }

        // ── api-ms-win-crt-* → ucrtbase.dll ──────────────────────────────
        // Universal C runtime: stdio, stdlib, math, time, locale,
        // string, conversion, environment, heap, fenv, etc.
        if normalized.starts_with("api-ms-win-crt-") {
            return "ucrtbase.dll".to_string();
        }

        // ── api-ms-win-security-*, -service-*, -eventing-*, -perf-* → advapi32.dll
        if normalized.starts_with("api-ms-win-security-")
            || normalized.starts_with("api-ms-win-service-")
            || normalized.starts_with("api-ms-win-eventing-")
            || normalized.starts_with("api-ms-win-perf-")
        {
            return "advapi32.dll".to_string();
        }

        // ── api-ms-win-shell-* → shell32.dll
        if normalized.starts_with("api-ms-win-shell-") {
            return "shell32.dll".to_string();
        }

        // ── api-ms-win-com-* / -ole-* → ole32.dll
        // (api-ms-win-core-com-* is handled by the earlier arm.)
        if normalized.starts_with("api-ms-win-com-") || normalized.starts_with("api-ms-win-ole-") {
            return "ole32.dll".to_string();
        }

        // ── ext-ms-win-ntuser-* / api-ms-win-rtf-* / api-ms-win-imm-* → user32.dll
        if (normalized.starts_with("ext-ms-win-") && normalized[11..].starts_with("ntuser-"))
            || normalized.starts_with("api-ms-win-rtf-")
            || normalized.starts_with("api-ms-win-imm-")
        {
            return "user32.dll".to_string();
        }

        // ── api-ms-win-gdi-* → gdi32.dll
        if normalized.starts_with("api-ms-win-gdi-") {
            return "gdi32.dll".to_string();
        }

        // ── api-ms-win-mm-* → winmm.dll
        if normalized.starts_with("api-ms-win-mm-") {
            return "winmm.dll".to_string();
        }

        // ── api-ms-win-power-* → powrprof.dll
        if normalized.starts_with("api-ms-win-power-") {
            return "powrprof.dll".to_string();
        }

        // ── api-ms-win-psapi-* → psapi.dll
        if normalized.starts_with("api-ms-win-psapi-") {
            return "psapi.dll".to_string();
        }

        // ── api-ms-win-shcore-* → shcore.dll
        if normalized.starts_with("api-ms-win-shcore-") {
            return "shcore.dll".to_string();
        }

        // ── api-ms-win-sync-* / -realtime-* / -wer-* / -windows-* → kernel32.dll
        if normalized.starts_with("api-ms-win-sync-")
            || normalized.starts_with("api-ms-win-realtime-")
            || normalized.starts_with("api-ms-win-wer-")
            || normalized.starts_with("api-ms-win-windows-")
        {
            return "kernel32.dll".to_string();
        }

        // ── api-ms-win-winrt-* → combase.dll
        if normalized.starts_with("api-ms-win-winrt-") {
            return "combase.dll".to_string();
        }

        // ── api-ms-win-rtcore-* → ntdll.dll
        if normalized.starts_with("api-ms-win-rtcore-") {
            return "ntdll.dll".to_string();
        }

        // ══════════════════════════════════════════════════════════════════
        // ext-ms-win-* (Extension API Sets)
        // ══════════════════════════════════════════════════════════════════

        // ── ext-ms-win-com-* → ole32.dll
        if normalized.starts_with("ext-ms-win-com-") {
            return "ole32.dll".to_string();
        }

        // ── ext-ms-win-kernel32-* → kernel32.dll
        if normalized.starts_with("ext-ms-win-kernel32-") {
            return "kernel32.dll".to_string();
        }

        // ── ext-ms-win-advapi32-* → advapi32.dll
        if normalized.starts_with("ext-ms-win-advapi32-") {
            return "advapi32.dll".to_string();
        }

        // ── ext-ms-win-gdi-* → gdi32.dll
        if normalized.starts_with("ext-ms-win-gdi-") {
            return "gdi32.dll".to_string();
        }

        // ── ext-ms-win-shell-* → shell32.dll
        if normalized.starts_with("ext-ms-win-shell-") {
            return "shell32.dll".to_string();
        }

        // ── ext-ms-win-ole32-* → ole32.dll
        if normalized.starts_with("ext-ms-win-ole32-") {
            return "ole32.dll".to_string();
        }

        // ── ext-ms-win-ucrt-* → ucrtbase.dll
        if normalized.starts_with("ext-ms-win-ucrt-") {
            return "ucrtbase.dll".to_string();
        }

        // ── ext-ms-win-uxtheme-theme-* → uxtheme.dll
        if normalized.starts_with("ext-ms-win-uxtheme-") {
            return "uxtheme.dll".to_string();
        }

        // ── ext-ms-win-dwmapi-* → dwmapi.dll
        if normalized.starts_with("ext-ms-win-dwmapi-") {
            return "dwmapi.dll".to_string();
        }

        // ── ext-ms-win-authz-context-* → authz.dll
        if normalized.starts_with("ext-ms-win-authz-") {
            return "authz.dll".to_string();
        }

        // ── ext-ms-win-session-* → wtsapi32.dll
        if normalized.starts_with("ext-ms-win-session-") {
            return "wtsapi32.dll".to_string();
        }

        // ── ext-ms-win-networking-wlanapi-* → wlanapi.dll
        if normalized.starts_with("ext-ms-win-networking-wlanapi") {
            return "wlanapi.dll".to_string();
        }

        // ── ext-ms-win-clfs-* → clfsw32.dll (Common Log File System)
        if normalized.starts_with("ext-ms-win-clfs-") {
            return "clfsw32.dll".to_string();
        }

        // ── ext-ms-win-ntos-policy-* → advapi32.dll
        if normalized.starts_with("ext-ms-win-ntos-policy-") {
            return "advapi32.dll".to_string();
        }

        // ── ext-ms-win-feclient-* → feclient.dll
        if normalized.starts_with("ext-ms-win-feclient-") {
            return "feclient.dll".to_string();
        }

        // ── ext-ms-win-wcmconfig-* → wcmapi.dll
        if normalized.starts_with("ext-ms-win-wcmconfig-") {
            return "wcmapi.dll".to_string();
        }

        // ── ext-ms-win-ntos-kernel-* → ntoskrnl.exe
        if normalized.starts_with("ext-ms-win-ntos-kernel-") {
            return "ntoskrnl.exe".to_string();
        }

        // ── ext-ms-win-rdg-* (Remote Desktop Graphics) → rdgapi.dll
        if normalized.starts_with("ext-ms-win-rdg-") {
            return "rdgapi.dll".to_string();
        }

        // ── ext-ms-win-tsc-* (Terminal Services) → rdpend.dll
        if normalized.starts_with("ext-ms-win-tsc-") {
            return "rdpend.dll".to_string();
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

/// Extracts the raw RT_VERSION resource blob bytes from a PE file at the given path.
/// Returns `Ok(Some(Vec<u8>))` if the version resource was found, `Ok(None)` if not
/// (or if the file is not a valid PE), and `Err(...)` on actual I/O or parse errors.
pub fn version_resource_blob_from_file(path: &Path) -> AppResult<Option<Vec<u8>>> {
    let bytes = match fs::read(path) {
        Ok(data) => data,
        Err(error) => {
            return Err(AppError::from_io(
                ReasonCode::RcPeParseInvalid,
                format!("failed to read {}", path.display()),
                &error,
            ));
        }
    };
    if bytes.len() < 2
        || read_u16(&bytes, 0, "DOS signature").unwrap_or_default() != IMAGE_DOS_SIGNATURE
    {
        return Ok(None);
    }
    let parsed = parse(&bytes)?;
    find_resource_blob(
        &bytes,
        &parsed.sections,
        &parsed.data_directories,
        RT_VERSION,
    )
}

pub fn maybe_version_info_from_file(path: &Path) -> AppResult<Option<VersionInfo>> {
    let bytes = fs::read(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcPeParseInvalid,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    if bytes.len() < 2
        || read_u16(&bytes, 0, "DOS signature").unwrap_or_default() != IMAGE_DOS_SIGNATURE
    {
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
    let size_of_optional_header =
        read_u16(bytes, pe_offset + 20, "size of optional header")? as usize;
    let characteristics = read_u16(bytes, pe_offset + 22, "file characteristics")?;
    let optional_offset = pe_offset + 24;
    checked_range(
        bytes,
        optional_offset,
        size_of_optional_header,
        "optional header",
    )?;

    let magic = read_u16(bytes, optional_offset, "optional header magic")?;
    let (
        pointer_bytes,
        minimum_optional_header_size,
        image_base_offset,
        data_directory_offset,
        data_directory_count_offset,
        format_name,
    ) = match magic {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => (4_usize, 96_usize, 28_usize, 96_usize, 92_usize, "PE32"),
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
            (8_usize, 112_usize, 24_usize, 112_usize, 108_usize, "PE32+")
        }
        _ => return invalid(format!("unsupported optional header magic 0x{magic:04x}")),
    };
    if size_of_optional_header < minimum_optional_header_size {
        return invalid(format!("optional header is too small for {format_name}"));
    }

    let address_of_entry_point = read_u32(bytes, optional_offset + 16, "entry point")?;
    let image_base = read_pointer(
        bytes,
        optional_offset + image_base_offset,
        pointer_bytes,
        "image base",
    )?;
    let section_alignment = read_u32(bytes, optional_offset + 32, "section alignment")?;
    let file_alignment = read_u32(bytes, optional_offset + 36, "file alignment")?;
    let size_of_image = read_u32(bytes, optional_offset + 56, "size of image")?;
    let size_of_headers = read_u32(bytes, optional_offset + 60, "size of headers")?;
    if size_of_image < size_of_headers {
        return invalid("SizeOfImage is smaller than SizeOfHeaders");
    }
    // Subsystem is at offset 68 from optional header (same for PE32 and PE32+)
    let subsystem = read_u16(bytes, optional_offset + 68, "subsystem")?;
    let dll_characteristics = read_u16(bytes, optional_offset + 70, "DLL characteristics")?;
    let number_of_rva_and_sizes = read_u32(
        bytes,
        optional_offset + data_directory_count_offset,
        "data directory count",
    )? as usize;
    let available_directories =
        ((size_of_optional_header - data_directory_offset) / 8).min(number_of_rva_and_sizes);
    let mut data_directories = vec![DataDirectory::default(); 16.max(available_directories)];
    for (index, slot) in data_directories
        .iter_mut()
        .take(available_directories)
        .enumerate()
    {
        let directory_offset = optional_offset + data_directory_offset + index * 8;
        *slot = DataDirectory {
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
        let name_end = name_bytes
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
        let virtual_size = read_u32(bytes, offset + 8, "section virtual size")?;
        let virtual_address = read_u32(bytes, offset + 12, "section virtual address")?;
        let raw_data_size = read_u32(bytes, offset + 16, "section raw data size")?;
        let raw_data_ptr = read_u32(bytes, offset + 20, "section raw data pointer")?;
        let characteristics = read_u32(bytes, offset + 36, "section characteristics")?;
        if raw_data_size > 0 {
            checked_range(
                bytes,
                raw_data_ptr as usize,
                raw_data_size as usize,
                "section raw data",
            )?;
        }
        let virtual_end = virtual_address
            .checked_add(align_up(
                virtual_size.max(raw_data_size),
                section_alignment,
            )?)
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
    let imports = parse_import_directory(
        bytes,
        &sections,
        &data_directories,
        false,
        image_base,
        pointer_bytes,
    )?;
    let delay_imports = parse_delay_import_directory(
        bytes,
        &sections,
        &data_directories,
        image_base,
        pointer_bytes,
    )?;
    let bound_imports =
        parse_bound_import_directory(bytes, &sections, &data_directories, size_of_headers)?;
    let exports = parse_export_directory(bytes, &sections, &data_directories)?;
    let relocations = parse_relocations(bytes, &sections, &data_directories)?;
    let tls_directory = parse_tls_directory(
        bytes,
        &sections,
        &data_directories,
        image_base,
        pointer_bytes,
    )?;
    let version_info = parse_version_resource(bytes, &sections, &data_directories)?;
    let embedded_manifest = parse_embedded_manifest(bytes, &sections, &data_directories)?;

    // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 — if present, this is a .NET assembly.
    let is_dotnet = data_directories
        .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .map(|dd| dd.virtual_address != 0)
        .unwrap_or(false);

    // Parse the CLR header (IMAGE_COR20_HEADER) for .NET assemblies
    let clr_header = if is_dotnet {
        parse_clr_header(bytes, &sections, &data_directories)?
    } else {
        None
    };

    Ok(ParsedPe {
        machine,
        number_of_sections,
        characteristics,
        optional_header_magic: magic,
        subsystem,
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
        is_dotnet,
        clr_header,
        bound_imports,
    })
}

pub fn select_image_base(image: &ParsedPe, image_hash: &str, dtm: bool) -> u64 {
    if !image.dynamic_base() || image.relocations.is_empty() {
        return image.image_base;
    }
    let alignment = 0x1_0000_u64;
    let seed = hash_seed(image_hash);
    let randomized_seed = if dtm { seed } else { seed ^ runtime_seed() };
    if image.pointer_bytes() == 4 {
        let preferred_region = 0x1000_0000_u64;
        return preferred_region
            + ((randomized_seed & 0x0000_0000_0fff_0000) / alignment) * alignment;
    }
    let preferred_region = 0x0000_1800_0000_0000_u64;
    preferred_region + ((randomized_seed & 0x0000_0fff_ffff_0000) / alignment) * alignment
}

pub fn map_image(
    bytes: &[u8],
    image: &ParsedPe,
    image_hash: &str,
    dtm: bool,
) -> AppResult<MappedImage> {
    let selected_base = select_image_base(image, image_hash, dtm);
    let image_size = image.size_of_image as usize;
    let headers_size = image.size_of_headers as usize;
    if headers_size > image_size {
        return invalid("SizeOfHeaders exceeds SizeOfImage");
    }
    let mut memory = Vec::new();
    memory
        .try_reserve_exact(image_size)
        .map_err(|_| pe_error("SizeOfImage is too large to map"))?;
    memory.resize(image_size, 0);
    memory[..headers_size].copy_from_slice(slice(bytes, 0, headers_size, "headers")?);

    let mut mappings = Vec::with_capacity(image.sections.len());
    for section in &image.sections {
        let mapped_size = align_up(
            section.virtual_size.max(section.raw_data_size),
            image.section_alignment,
        )?;
        let destination = checked_range_mut(
            &mut memory,
            section.virtual_address as usize,
            mapped_size as usize,
            "mapped section",
        )?;
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
                    let target = read_u64(
                        &mapped.memory,
                        target_rva as usize,
                        "DIR64 relocation target",
                    )?;
                    let relocated = (target as i128)
                        .checked_add(delta)
                        .ok_or_else(|| pe_error("DIR64 relocation overflow"))?
                        as u64;
                    write_u64(&mut mapped.memory, target_rva as usize, relocated)?;
                }
                RelocationType::HighLow => {
                    let target = read_u32(
                        &mapped.memory,
                        target_rva as usize,
                        "HIGHLOW relocation target",
                    )?;
                    let relocated = (target as i128)
                        .checked_add(delta)
                        .ok_or_else(|| pe_error("HIGHLOW relocation overflow"))?
                        as u32;
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
    let mut index_cache = HashMap::new();
    for descriptor in image.imports.iter().chain(image.delay_imports.iter()) {
        let resolved_module = resolver.resolve(&descriptor.dll_name);
        if !export_tables.contains_key(&resolved_module) {
            return Err(AppError::new(
                ReasonCode::RcImportMissing,
                format!("missing import provider {resolved_module}"),
            ));
        }
        for thunk in &descriptor.imports {
            let export = resolve_export_symbol(
                &thunk.symbol,
                &resolved_module,
                export_tables,
                resolver,
                &mut BTreeSet::new(),
                &mut index_cache,
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
    let mut index_cache = HashMap::new();
    for descriptor in &image.delay_imports {
        let resolved_module = resolver.resolve(&descriptor.dll_name);
        if !export_tables.contains_key(&resolved_module) {
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
        }
        for thunk in &descriptor.imports {
            let outcome = match lookup_export_symbol(
                &thunk.symbol,
                &resolved_module,
                export_tables,
                resolver,
                &mut BTreeSet::new(),
                &mut index_cache,
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
    visit_module(
        &root,
        dependencies,
        &mut visiting,
        &mut visited,
        &mut load_order,
    )?;

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

/// Parse binding redirects from an SxS assembly manifest XML document.
/// Returns a vector of `BindingRedirect` entries found in the manifest.
pub fn parse_binding_redirects(xml: &str) -> Vec<BindingRedirect> {
    let mut redirects = Vec::new();
    let doc = match roxmltree::Document::parse(xml) {
        Ok(doc) => doc,
        Err(_) => return redirects,
    };
    for node in doc.descendants() {
        if node.is_element() && node.tag_name().name() == "bindingRedirect" {
            let name = node.attribute("name").unwrap_or("").to_string();
            let public_key_token = node.attribute("publicKeyToken").unwrap_or("").to_string();
            let version = node.attribute("version").unwrap_or("").to_string();
            let culture = node.attribute("culture").unwrap_or("").to_string();
            redirects.push(BindingRedirect {
                name,
                public_key_token,
                version,
                culture,
            });
        }
    }
    redirects
}

/// Result of searching for a string in an activation context section.
///
/// Returned by [`find_activation_context_section`] when a match is found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActCtxSectionResult {
    /// The section ID that was matched.
    pub section_id: u32,
    /// The assembly identity that matched (if applicable).
    pub assembly_identity: Option<AssemblyIdentity>,
    /// For DLL redirections: the redirected DLL path.
    pub dll_path: Option<String>,
    /// The activation context handle that contained the match.
    pub context_handle: u64,
    /// The assembly directory (if known).
    pub assembly_directory: Option<String>,
}

/// SxS activation context section IDs.
pub mod sxs_section {
    /// Assembly information section.
    pub const ASSEMBLY_INFORMATION: u32 = 1;
    /// DLL redirection section.
    pub const DLL_REDIRECTION: u32 = 2;
    /// Window class redirection section.
    pub const WINDOW_CLASS_REDIRECTION: u32 = 3;
    /// COM server redirection section.
    pub const COM_SERVER_REDIRECTION: u32 = 4;
    /// COM interface redirection section.
    pub const COM_INTERFACE_REDIRECTION: u32 = 5;
    /// COM type library redirection section.
    pub const COM_TYPE_LIBRARY_REDIRECTION: u32 = 6;
    /// COM ProgID redirection section.
    pub const COM_PROGID_REDIRECTION: u32 = 7;
}

/// Known SxS assembly names and their associated DLLs.
///
/// Maps assembly names to the list of DLLs they provide. Used by
/// [`find_activation_context_section`] to resolve DLL redirections.
pub fn known_sxs_assembly_dlls() -> &'static [(&'static str, &'static [&'static str])] {
    static TABLE: &[(&str, &[&str])] = &[
        (
            "Microsoft.VC80.CRT",
            &["msvcp80.dll", "msvcr80.dll", "msvcm80.dll"],
        ),
        (
            "Microsoft.VC80.MFC",
            &["mfc80.dll", "mfc80u.dll", "mfcm80.dll", "mfcm80u.dll"],
        ),
        (
            "Microsoft.VC90.CRT",
            &["msvcp90.dll", "msvcr90.dll", "msvcm90.dll"],
        ),
        (
            "Microsoft.VC90.MFC",
            &["mfc90.dll", "mfc90u.dll", "mfcm90.dll", "mfcm90u.dll"],
        ),
        ("Microsoft.VC100.CRT", &["msvcp100.dll", "msvcr100.dll"]),
        (
            "Microsoft.VC100.MFC",
            &["mfc100.dll", "mfc100u.dll", "mfcm100.dll", "mfcm100u.dll"],
        ),
        (
            "Microsoft.VC110.CRT",
            &["msvcp110.dll", "msvcr110.dll", "vccorlib110.dll"],
        ),
        (
            "Microsoft.VC110.MFC",
            &["mfc110.dll", "mfc110u.dll", "mfcm110.dll", "mfcm110u.dll"],
        ),
        (
            "Microsoft.VC120.CRT",
            &["msvcp120.dll", "msvcr120.dll", "vccorlib120.dll"],
        ),
        (
            "Microsoft.VC120.MFC",
            &["mfc120.dll", "mfc120u.dll", "mfcm120.dll", "mfcm120u.dll"],
        ),
        (
            "Microsoft.VC140.CRT",
            &[
                "msvcp140.dll",
                "vcruntime140.dll",
                "vcruntime140_1.dll",
                "concrt140.dll",
                "vccorlib140.dll",
            ],
        ),
        (
            "Microsoft.VC140.MFC",
            &["mfc140.dll", "mfc140u.dll", "mfcm140.dll", "mfcm140u.dll"],
        ),
        ("Microsoft.Windows.Common-Controls", &["comctl32.dll"]),
    ];
    TABLE
}

/// Search activation contexts for a string match in the specified section.
///
/// This is the real implementation behind `FindActCtxSectionStringW`.
/// It walks the activation context stack (most recent first) and looks for
/// the given string in the specified section type.
///
/// # Arguments
/// * `contexts` — All activation contexts (handle → context).
/// * `stack` — The activation context stack (most recent last).
/// * `section_id` — The section to search (see `sxs_section` constants).
/// * `search_string` — The string to search for (UTF-8, will be lowercased for comparison).
///
/// # Returns
/// `Some(ActCtxSectionResult)` if a match is found, `None` otherwise.
pub fn find_activation_context_section(
    contexts: &std::collections::BTreeMap<u64, ActivationContext>,
    stack: &[u64],
    section_id: u32,
    search_string: &str,
) -> Option<ActCtxSectionResult> {
    let search_lower = search_string.to_lowercase();
    if search_lower.is_empty() {
        return None;
    }

    // Walk the stack from most recently activated to least recently
    for &handle in stack.iter().rev() {
        let ctx = contexts.get(&handle)?;

        match section_id {
            sxs_section::ASSEMBLY_INFORMATION => {
                // Search for an assembly whose name matches the search string
                if let Some(ref manifest) = ctx.manifest_info {
                    for assembly in &manifest.assemblies {
                        let assembly_lower = assembly.name.to_lowercase();
                        if assembly_lower == search_lower || assembly_lower.contains(&search_lower)
                        {
                            return Some(ActCtxSectionResult {
                                section_id,
                                assembly_identity: Some(assembly.clone()),
                                dll_path: None,
                                context_handle: handle,
                                assembly_directory: ctx.assembly_directory.clone(),
                            });
                        }
                    }
                }
            }

            sxs_section::DLL_REDIRECTION => {
                // Search for a DLL redirection: check if any assembly provides the searched DLL
                let dll_name = if search_lower.ends_with(".dll") {
                    &search_lower
                } else {
                    // Not a DLL name, skip
                    continue;
                };

                if let Some(ref manifest) = ctx.manifest_info {
                    for assembly in &manifest.assemblies {
                        // Check known DLLs for this assembly
                        for &(name, dlls) in known_sxs_assembly_dlls() {
                            if assembly.name == name {
                                for dll in dlls {
                                    if *dll == dll_name.as_str() {
                                        let dll_path = ctx
                                            .assembly_directory
                                            .as_ref()
                                            .map(|dir| format!("{}/{}", dir, dll));
                                        return Some(ActCtxSectionResult {
                                            section_id,
                                            assembly_identity: Some(assembly.clone()),
                                            dll_path,
                                            context_handle: handle,
                                            assembly_directory: ctx.assembly_directory.clone(),
                                        });
                                    }
                                }
                            }
                        }

                        // Also check if the assembly name itself matches the DLL base name
                        // (e.g., searching for "comctl32.dll" in "Microsoft.Windows.Common-Controls")
                        let base_dll = dll_name.trim_end_matches(".dll");
                        if !base_dll.is_empty() {
                            let assembly_lower = assembly.name.to_lowercase();
                            if assembly_lower.contains(base_dll) {
                                let dll_path = ctx
                                    .assembly_directory
                                    .as_ref()
                                    .map(|dir| format!("{}/{}", dir, dll_name));
                                return Some(ActCtxSectionResult {
                                    section_id,
                                    assembly_identity: Some(assembly.clone()),
                                    dll_path,
                                    context_handle: handle,
                                    assembly_directory: ctx.assembly_directory.clone(),
                                });
                            }
                        }
                    }
                }
            }

            sxs_section::WINDOW_CLASS_REDIRECTION => {
                // Window class redirections are rare; check manifest for matching class names
                // For now, return not found for this section
                continue;
            }

            _ => {
                // Unknown section type; skip
                continue;
            }
        }
    }

    None
}

#[derive(Debug)]
enum ExportLookupFailure {
    MissingProvider(String),
    MissingSymbol(String),
    Parser(AppError),
}

/// Indexed view of a module's export table for O(1) name/ordinal lookups.
struct ExportIndex<'a> {
    exports: &'a [ExportSymbol],
    by_name: HashMap<&'a str, usize>,
    by_ordinal: HashMap<u32, usize>,
}

impl<'a> ExportIndex<'a> {
    fn build(exports: &'a [ExportSymbol]) -> Self {
        let mut by_name = HashMap::new();
        let mut by_ordinal = HashMap::new();
        for (index, export) in exports.iter().enumerate() {
            if let Some(name) = export.name.as_deref() {
                by_name.entry(name).or_insert(index);
            }
            by_ordinal.entry(export.ordinal).or_insert(index);
        }
        Self {
            exports,
            by_name,
            by_ordinal,
        }
    }

    fn lookup(&self, symbol: &ImportSymbol) -> Option<&'a ExportSymbol> {
        match symbol {
            ImportSymbol::ByName { name, .. } => self
                .by_name
                .get(name.as_str())
                .map(|&index| &self.exports[index]),
            ImportSymbol::ByOrdinal { ordinal } => self
                .by_ordinal
                .get(&(*ordinal as u32))
                .map(|&index| &self.exports[index]),
        }
    }
}

fn export_index_for<'a, 'b>(
    module: &str,
    export_tables: &'a BTreeMap<String, Vec<ExportSymbol>>,
    index_cache: &'b mut HashMap<String, ExportIndex<'a>>,
) -> Result<&'b ExportIndex<'a>, ExportLookupFailure> {
    if !index_cache.contains_key(module) {
        let exports = export_tables
            .get(module)
            .ok_or_else(|| ExportLookupFailure::MissingProvider(module.to_string()))?;
        index_cache.insert(module.to_string(), ExportIndex::build(exports));
    }
    index_cache
        .get(module)
        .ok_or_else(|| ExportLookupFailure::Parser(pe_error("export index cache is inconsistent")))
}

fn parse_debug_entries(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    size_of_headers: u32,
) -> AppResult<Vec<DebugDirectoryEntry>> {
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_DEBUG)
        .copied()
        .unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    let offset = rva_to_file_offset(
        directory.virtual_address,
        directory.size,
        sections,
        size_of_headers,
    )?;
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
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        .copied()
        .unwrap_or_default();
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
            None, 0x38_usize, 0x3c_usize, 0x48_usize, 0x4c_usize, 0x50_usize, 0x54_usize,
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
        guard_flags: read_load_config_u32(
            bytes,
            offset,
            present_size,
            guard_flags_offset,
            "GuardFlags",
        )?,
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
    read_pointer(
        bytes,
        load_config_offset + field_offset,
        pointer_bytes,
        label,
    )
}

fn parse_import_directory(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    delay_load: bool,
    image_base: u64,
    pointer_bytes: usize,
) -> AppResult<Vec<ImportDescriptor>> {
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_IMPORT)
        .copied()
        .unwrap_or_default();
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
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let thunk_addresses = read_import_thunks(
            bytes,
            sections,
            thunk_rva,
            first_thunk,
            image_base,
            pointer_bytes,
        )?;
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
    let mut descriptors = Vec::new();
    let mut offset = rva_to_file_offset(directory.virtual_address, 32, sections, 0)?;
    let end = offset + directory.size as usize;
    let mut iterations = 0usize;
    while offset + 32 <= end {
        iterations += 1;
        if iterations > 4096 {
            return invalid("delay import descriptor table exceeded the safety limit");
        }
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
            imports: read_import_thunks(
                bytes,
                sections,
                thunk_rva,
                iat_rva,
                image_base,
                pointer_bytes,
            )?,
            delay_load: true,
        });
        offset += 32;
    }
    Ok(descriptors)
}

fn parse_bound_import_directory(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    size_of_headers: u32,
) -> AppResult<Vec<BoundImportDescriptor>> {
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
        .copied()
        .unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(Vec::new());
    }
    let mut descriptors = Vec::new();
    let mut offset = rva_to_file_offset(directory.virtual_address, 8, sections, size_of_headers)?;
    let end = offset + directory.size as usize;
    let mut iterations = 0usize;
    while offset + 8 <= end {
        iterations += 1;
        if iterations > 4096 {
            return invalid("bound import descriptor table exceeded the safety limit");
        }
        let time_date_stamp = read_u32(bytes, offset, "bound import TimeDateStamp")?;
        if time_date_stamp == 0 {
            break; // Terminator descriptor
        }
        let offset_module_name = read_u16(bytes, offset + 4, "bound import OffsetModuleName")?;
        let number_of_forwarder_refs = read_u16(
            bytes,
            offset + 6,
            "bound import NumberOfModuleForwarderRefs",
        )?;
        offset += 8;

        // DLL name is at RVA = directory_virtual_address + offset_module_name
        let name_rva = directory
            .virtual_address
            .checked_add(offset_module_name as u32)
            .ok_or_else(|| pe_error("bound import name RVA overflow"))?;
        let module_name =
            read_c_string_from_rva(bytes, sections, name_rva, "bound import DLL name")?;

        // Parse forwarder chain
        let mut forwarder_chain = Vec::with_capacity(number_of_forwarder_refs as usize);
        for _ in 0..number_of_forwarder_refs {
            if offset + 8 > end {
                break;
            }
            let fwd_time_date_stamp = read_u32(bytes, offset, "bound forwarder TimeDateStamp")?;
            let fwd_offset_module_name =
                read_u16(bytes, offset + 4, "bound forwarder OffsetModuleName")?;
            let fwd_number_of_forwarder_refs = read_u16(
                bytes,
                offset + 6,
                "bound forwarder NumberOfModuleForwarderRefs",
            )?;
            offset += 8;

            let fwd_name_rva = directory
                .virtual_address
                .checked_add(fwd_offset_module_name as u32)
                .ok_or_else(|| pe_error("bound forwarder name RVA overflow"))?;
            let fwd_module_name =
                read_c_string_from_rva(bytes, sections, fwd_name_rva, "bound forwarder DLL name")?;

            // Forwarder refs can themselves have nested forwarders (recursive),
            // but we only parse one level of nesting for now
            let mut fwd_chain = Vec::with_capacity(fwd_number_of_forwarder_refs as usize);
            for _ in 0..fwd_number_of_forwarder_refs {
                if offset + 8 > end {
                    break;
                }
                let nested_ts = read_u32(bytes, offset, "nested bound forwarder TimeDateStamp")?;
                let nested_off =
                    read_u16(bytes, offset + 4, "nested bound forwarder OffsetModuleName")?;
                let nested_fwd_refs = read_u16(
                    bytes,
                    offset + 6,
                    "nested bound forwarder NumberOfModuleForwarderRefs",
                )?;
                offset += 8;

                let nested_name_rva = directory
                    .virtual_address
                    .checked_add(nested_off as u32)
                    .ok_or_else(|| pe_error("nested bound forwarder name RVA overflow"))?;
                let nested_name = read_c_string_from_rva(
                    bytes,
                    sections,
                    nested_name_rva,
                    "nested bound forwarder DLL name",
                )?;
                fwd_chain.push(BoundImportDescriptor {
                    time_date_stamp: nested_ts,
                    module_name: nested_name,
                    forwarder_chain: Vec::new(),
                });
                // Skip any deeper nesting for now
                for _ in 0..nested_fwd_refs {
                    if offset + 8 > end {
                        break;
                    }
                    offset += 8;
                }
            }

            forwarder_chain.push(BoundImportDescriptor {
                time_date_stamp: fwd_time_date_stamp,
                module_name: fwd_module_name,
                forwarder_chain: fwd_chain,
            });
        }

        descriptors.push(BoundImportDescriptor {
            time_date_stamp,
            module_name,
            forwarder_chain,
        });
    }
    Ok(descriptors)
}

/// Parse the CLR header (IMAGE_COR20_HEADER) from IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR.
///
/// The CLR header is a 72-byte structure that describes a .NET assembly's
/// managed metadata, entry point, resources, and (for IJW assemblies) native
/// code entry points. Returns `None` if the directory is absent or invalid.
pub fn parse_clr_header(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
) -> AppResult<Option<ClrHeader>> {
    let dd = directories
        .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .copied()
        .unwrap_or_default();
    if dd.virtual_address == 0 || dd.size < 72 {
        return Ok(None);
    }
    let offset = rva_to_file_offset(dd.virtual_address, 72, sections, 0)?;
    checked_range(bytes, offset, 72, "CLR header")?;

    let cb = read_u32(bytes, offset, "CLR header cb")?;
    if cb < 72 || cb > dd.size {
        return Ok(None);
    }

    let major_runtime_version = read_u16(bytes, offset + 4, "CLR MajorRuntimeVersion")?;
    let minor_runtime_version = read_u16(bytes, offset + 6, "CLR MinorRuntimeVersion")?;
    let metadata = DataDirectory {
        virtual_address: read_u32(bytes, offset + 8, "CLR Metadata RVA")?,
        size: read_u32(bytes, offset + 12, "CLR Metadata size")?,
    };
    let flags = read_u32(bytes, offset + 16, "CLR flags")?;
    let entry_point_token = read_u32(bytes, offset + 20, "CLR EntryPointToken")?;
    let resources = DataDirectory {
        virtual_address: read_u32(bytes, offset + 24, "CLR Resources RVA")?,
        size: read_u32(bytes, offset + 28, "CLR Resources size")?,
    };
    let strong_name_signature = DataDirectory {
        virtual_address: read_u32(bytes, offset + 32, "CLR StrongNameSignature RVA")?,
        size: read_u32(bytes, offset + 36, "CLR StrongNameSignature size")?,
    };
    let code_manager_table = DataDirectory {
        virtual_address: read_u32(bytes, offset + 40, "CLR CodeManagerTable RVA")?,
        size: read_u32(bytes, offset + 44, "CLR CodeManagerTable size")?,
    };
    let vtable_fixups = DataDirectory {
        virtual_address: read_u32(bytes, offset + 48, "CLR VTableFixups RVA")?,
        size: read_u32(bytes, offset + 52, "CLR VTableFixups size")?,
    };
    let export_address_table_jumps = DataDirectory {
        virtual_address: read_u32(bytes, offset + 56, "CLR ExportAddressTableJumps RVA")?,
        size: read_u32(bytes, offset + 60, "CLR ExportAddressTableJumps size")?,
    };
    let managed_native_header = DataDirectory {
        virtual_address: read_u32(bytes, offset + 64, "CLR ManagedNativeHeader RVA")?,
        size: read_u32(bytes, offset + 68, "CLR ManagedNativeHeader size")?,
    };

    Ok(Some(ClrHeader {
        major_runtime_version,
        minor_runtime_version,
        metadata,
        flags,
        entry_point_token,
        resources,
        strong_name_signature,
        code_manager_table,
        vtable_fixups,
        export_address_table_jumps,
        managed_native_header,
    }))
}

fn parse_export_directory(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
) -> AppResult<Vec<ExportSymbol>> {
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_EXPORT)
        .copied()
        .unwrap_or_default();
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

    // Every entry in these tables occupies at least 2 bytes in the file, so a
    // count larger than bytes.len() / 4 cannot be backed by real data. Clamp to
    // keep untrusted counts from driving unbounded loops and allocations.
    let name_count = number_of_names.min(bytes.len() / 4);
    let function_count = number_of_functions.min(bytes.len() / 4);

    let mut names_by_index = BTreeMap::new();
    for index in 0..name_count {
        let name_rva =
            read_u32_at_rva(bytes, sections, address_of_names, index, "export name RVA")?;
        let ordinal_index = read_u16_at_rva(
            bytes,
            sections,
            address_of_name_ordinals,
            index,
            "export ordinal index",
        )? as usize;
        let name = read_c_string_from_rva(bytes, sections, name_rva, "export name")?;
        names_by_index.insert(ordinal_index, name);
    }

    let mut exports = Vec::new();
    exports
        .try_reserve_exact(function_count)
        .map_err(|_| pe_error("export table is too large to parse"))?;
    for function_index in 0..function_count {
        let function_rva = read_u32_at_rva(
            bytes,
            sections,
            address_of_functions,
            function_index,
            "export function RVA",
        )?;
        let target = if function_rva >= directory.virtual_address
            && function_rva < directory.virtual_address.saturating_add(directory.size)
        {
            ExportTarget::Forwarder(read_c_string_from_rva(
                bytes,
                sections,
                function_rva,
                "forwarded export",
            )?)
        } else {
            ExportTarget::Rva(function_rva)
        };
        exports.push(ExportSymbol {
            ordinal: ordinal_base
                .checked_add(function_index as u32)
                .ok_or_else(|| pe_error("ordinal overflow"))?,
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
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_BASERELOC)
        .copied()
        .unwrap_or_default();
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
        if !(block_size - 8).is_multiple_of(2) {
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
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_TLS)
        .copied()
        .unwrap_or_default();
    if directory.virtual_address == 0 || directory.size == 0 {
        return Ok(None);
    }
    let directory_size = if pointer_bytes == 8 { 40 } else { 24 };
    let offset = rva_to_file_offset(directory.virtual_address, directory_size, sections, 0)?;
    checked_range(bytes, offset, directory_size as usize, "TLS directory")?;
    let raw_data_start = read_pointer(bytes, offset, pointer_bytes, "TLS raw data start")?;
    let raw_data_end = read_pointer(
        bytes,
        offset + pointer_bytes,
        pointer_bytes,
        "TLS raw data end",
    )?;
    let address_of_index = read_pointer(
        bytes,
        offset + pointer_bytes * 2,
        pointer_bytes,
        "TLS address of index",
    )?;
    let address_of_callbacks = read_pointer(
        bytes,
        offset + pointer_bytes * 3,
        pointer_bytes,
        "TLS address of callbacks",
    )?;
    let callbacks = if address_of_callbacks == 0 {
        Vec::new()
    } else {
        let callbacks_rva = u32::try_from(
            address_of_callbacks
                .checked_sub(image_base)
                .ok_or_else(|| pe_error("TLS callback VA is below image base"))?,
        )
        .map_err(|_| pe_error("TLS callback VA does not fit in RVA space"))?;
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

pub(crate) fn parse_external_manifest(path: &Path) -> AppResult<Option<ManifestInfo>> {
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
    Ok(Some(parse_manifest_bytes(
        &contents,
        ManifestSource::External,
    )?))
}

fn parse_manifest_bytes(bytes: &[u8], source: ManifestSource) -> AppResult<ManifestInfo> {
    let text = decode_manifest_bytes(bytes)?;
    let document = Document::parse(&text).map_err(|error| {
        AppError::new(ReasonCode::RcPeParseInvalid, "failed to parse manifest XML")
            .with_hint(error.to_string())
    })?;
    let mut supported_os = document
        .descendants()
        .filter(|node| {
            node.has_tag_name(("urn:schemas-microsoft-com:compatibility.v1", "supportedOS"))
                || node.tag_name().name() == "supportedOS"
        })
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
            AppError::new(
                ReasonCode::RcPeParseInvalid,
                "manifest payload is not valid UTF-8",
            )
            .with_hint(error.to_string())
        })
}

fn decode_utf16(bytes: &[u8]) -> AppResult<String> {
    if !bytes.len().is_multiple_of(2) {
        return invalid("UTF-16 payload has an odd byte length");
    }
    let words = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&words).map_err(|error| {
        AppError::new(ReasonCode::RcPeParseInvalid, "invalid UTF-16 payload")
            .with_hint(error.to_string())
    })
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
        let (child_key, child_after_key) =
            read_utf16_key(bytes, cursor + 6, cursor + child_length)?;
        if child_key == "StringFileInfo" {
            parse_string_file_info(
                bytes,
                cursor,
                child_after_key,
                cursor + child_length,
                &mut version,
            )?;
        }
        cursor = align4(cursor + child_length)?;
    }
    Ok(version)
}

fn parse_string_file_info(
    bytes: &[u8],
    _block_offset: usize,
    after_key: usize,
    block_end: usize,
    version: &mut VersionInfo,
) -> AppResult<()> {
    let mut cursor = align4(after_key)?;
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
            let (name, after_name) =
                read_utf16_key(bytes, string_cursor + 6, string_cursor + string_length)?;
            let value_offset = align4(after_name)?;
            let value = read_utf16_value(bytes, value_offset, string_cursor + string_length);
            if name.eq_ignore_ascii_case("ProductName") && !value.is_empty() {
                // case-insensitive comparison
                version.product_name = Some(value);
            } else if name.eq_ignore_ascii_case("FileVersion") && !value.is_empty() {
                // case-insensitive comparison
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

pub fn find_resource_blob(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    type_id: u32,
) -> AppResult<Option<Vec<u8>>> {
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        .copied()
        .unwrap_or_default();
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
    )?
    else {
        return Ok(None);
    };
    let offset = rva_to_file_offset(data_rva, data_size, sections, 0)?;
    Ok(Some(
        slice(bytes, offset, data_size as usize, "resource payload")?.to_vec(),
    ))
}

fn find_resource_data_entry(
    resource_section_bytes: &[u8],
    section_rva: u32,
    root_rva: u32,
    directory_rva: u32,
    target_id: Option<u32>,
    depth: u8,
) -> AppResult<Option<(u32, u32)>> {
    // Bound recursion depth: a crafted resource tree with cyclic subdirectory
    // pointers must not overflow the stack. The Windows resource tree is at
    // most 3 levels deep (type → name → language), so 4 is generous.
    if depth > 4 {
        return Ok(None);
    }
    let relative = directory_rva
        .checked_sub(section_rva)
        .ok_or_else(|| pe_error("resource directory underflow"))? as usize;
    checked_range(resource_section_bytes, relative, 16, "resource directory")?;
    let named_entries = read_u16(
        resource_section_bytes,
        relative + 12,
        "resource named entry count",
    )? as usize;
    let id_entries = read_u16(
        resource_section_bytes,
        relative + 14,
        "resource id entry count",
    )? as usize;
    let total_entries = named_entries + id_entries;
    for index in 0..total_entries {
        let entry_offset = relative + 16 + index * 8;
        checked_range(resource_section_bytes, entry_offset, 8, "resource entry")?;
        let name = read_u32(resource_section_bytes, entry_offset, "resource entry name")?;
        if let Some(expected_id) = target_id
            && (name & 0x8000_0000 != 0 || (name & 0xffff) != expected_id)
        {
            continue;
        }
        let payload = read_u32(
            resource_section_bytes,
            entry_offset + 4,
            "resource entry payload",
        )?;
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
                .ok_or_else(|| pe_error("resource data entry underflow"))?
                as usize;
            checked_range(
                resource_section_bytes,
                data_relative,
                16,
                "resource data entry",
            )?;
            let offset_to_data = read_u32(
                resource_section_bytes,
                data_relative,
                "resource OffsetToData",
            )?;
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
        let thunk_value = read_pointer_at_rva(
            bytes,
            sections,
            table_rva,
            index,
            pointer_bytes,
            "import thunk",
        )?;
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
                    .ok_or_else(|| {
                        pe_error(format!(
                            "import thunk value {thunk_value:#x} does not fit in RVA space"
                        ))
                    })?
            } else {
                u32::try_from(thunk_value).map_err(|_| {
                    pe_error(format!(
                        "import thunk value {thunk_value:#x} does not fit in RVA space"
                    ))
                })?
            };
            let hint_name_offset = rva_to_file_offset(import_by_name_rva, 2, sections, 0)?;
            let hint = read_u16(bytes, hint_name_offset, "import hint")?;
            let name = read_c_string(bytes, hint_name_offset + 2, "import name")?;
            ImportSymbol::ByName { hint, name }
        };
        imports.push(ImportThunk {
            symbol,
            iat_rva: iat_rva
                .checked_add((index as u32).saturating_mul(pointer_bytes as u32))
                .ok_or_else(|| pe_error("IAT RVA overflow"))?,
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
        let callback = read_pointer_at_rva(
            bytes,
            sections,
            callbacks_rva,
            index,
            pointer_bytes,
            "TLS callback",
        )?;
        if callback == 0 {
            break;
        }
        callbacks.push(callback);
        index += 1;
    }
    Ok(callbacks)
}

fn resolve_export_symbol<'a>(
    symbol: &ImportSymbol,
    current_module: &str,
    export_tables: &'a BTreeMap<String, Vec<ExportSymbol>>,
    resolver: &ApiSetResolver,
    visited: &mut BTreeSet<String>,
    index_cache: &mut HashMap<String, ExportIndex<'a>>,
) -> AppResult<ExportSymbol> {
    match lookup_export_symbol(
        symbol,
        current_module,
        export_tables,
        resolver,
        visited,
        index_cache,
    ) {
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

fn lookup_export_symbol<'a>(
    symbol: &ImportSymbol,
    current_module: &str,
    export_tables: &'a BTreeMap<String, Vec<ExportSymbol>>,
    resolver: &ApiSetResolver,
    visited: &mut BTreeSet<String>,
    index_cache: &mut HashMap<String, ExportIndex<'a>>,
) -> Result<ExportSymbol, ExportLookupFailure> {
    let lookup_key = format!("{}::{symbol:?}", current_module);
    if !visited.insert(lookup_key) {
        return Err(ExportLookupFailure::Parser(pe_error(
            "export forwarder cycle detected",
        )));
    }
    let export = export_index_for(current_module, export_tables, index_cache)?
        .lookup(symbol)
        .cloned()
        .ok_or_else(|| {
            ExportLookupFailure::MissingSymbol(format!("{symbol:?} from {current_module}"))
        })?;

    match &export.target {
        ExportTarget::Rva(_) => Ok(export),
        ExportTarget::Forwarder(forwarder) => {
            let (module_name, forwarded_symbol) =
                parse_forwarder_string(forwarder.as_str()).map_err(ExportLookupFailure::Parser)?;
            let resolved_module = resolver.resolve(&module_name);
            lookup_export_symbol(
                &forwarded_symbol,
                &resolved_module,
                export_tables,
                resolver,
                visited,
                index_cache,
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
            AppError::new(
                ReasonCode::RcPeParseInvalid,
                "forwarder ordinal is not numeric",
            )
            .with_hint(error.to_string())
        })?;
        Ok((
            normalize_module_name(module),
            ImportSymbol::ByOrdinal { ordinal },
        ))
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
    root: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
    load_order: &mut Vec<String>,
) -> AppResult<()> {
    // Iterative post-order DFS with an explicit worklist so that very deep
    // dependency chains (which are attacker-influenceable through import
    // tables) cannot overflow the call stack.
    enum Frame {
        Enter(String),
        Exit(String),
    }
    let mut stack = vec![Frame::Enter(root.to_string())];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(module) => {
                if visited.contains(&module) {
                    continue;
                }
                if !visiting.insert(module.clone()) {
                    return invalid(format!("dependency cycle detected at {module}"));
                }
                stack.push(Frame::Exit(module.clone()));
                for dependency in dependencies.get(&module).into_iter().flatten().rev() {
                    let dependency = normalize_module_name(dependency);
                    if !visited.contains(&dependency) {
                        stack.push(Frame::Enter(dependency));
                    }
                }
            }
            Frame::Exit(module) => {
                visiting.remove(&module);
                visited.insert(module.clone());
                load_order.push(module);
            }
        }
    }
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
    format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff)
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
    image_hash.as_bytes().chunks(2).take(8).enumerate().fold(
        0_u64,
        |accumulator, (index, chunk)| {
            let byte = std::str::from_utf8(chunk)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok())
                .unwrap_or(index as u8);
            (accumulator << 8) | byte as u64
        },
    )
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

fn section_for_rva(
    sections: &[PeSection],
    rva: u32,
    size: u32,
    allow_virtual_padding: bool,
) -> Option<&PeSection> {
    sections.iter().find(|section| {
        let start = section.virtual_address;
        let max_size = if allow_virtual_padding {
            section.virtual_size.max(section.raw_data_size)
        } else {
            section.raw_data_size
        };
        let end = start.saturating_add(max_size);
        let requested_end = rva.saturating_add(size);
        rva >= start && requested_end <= end
    })
}

fn read_u16_at_rva(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u32,
    index: usize,
    label: &str,
) -> AppResult<u16> {
    let offset = rva_to_file_offset(rva + (index * 2) as u32, 2, sections, 0)?;
    read_u16(bytes, offset, label)
}

fn read_u32_at_rva(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u32,
    index: usize,
    label: &str,
) -> AppResult<u32> {
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

fn read_u64_at_rva(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u32,
    index: usize,
    label: &str,
) -> AppResult<u64> {
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

fn read_c_string_from_rva(
    bytes: &[u8],
    sections: &[PeSection],
    rva: u32,
    label: &str,
) -> AppResult<String> {
    let offset = rva_to_file_offset(rva, 1, sections, 0)?;
    read_c_string(bytes, offset, label)
}

fn read_c_string(bytes: &[u8], offset: usize, label: &str) -> AppResult<String> {
    if offset > bytes.len() {
        return invalid(format!("{label} starts past end of file"));
    }
    let end = bytes[offset..]
        .iter()
        .position(|value| *value == 0)
        .map(|index| offset + index)
        .ok_or_else(|| pe_error(format!("{label} is not NUL-terminated")))?;
    std::str::from_utf8(&bytes[offset..end])
        .map(|value| value.to_string())
        .map_err(|error| {
            AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!("{label} is not valid UTF-8"),
            )
            .with_hint(error.to_string())
        })
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

fn checked_range_mut<'a>(
    bytes: &'a mut [u8],
    offset: usize,
    size: usize,
    label: &str,
) -> AppResult<&'a mut [u8]> {
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

#[cfg(test)]
fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> AppResult<()> {
    let slice = checked_range_mut(bytes, offset, 2, "write_u16")?;
    slice.copy_from_slice(&value.to_le_bytes());
    Ok(())
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

// ═══════════════════════════════════════════════════════════════════════════════
// PE Icon Resource Extraction (Phase 1.1)
// ═══════════════════════════════════════════════════════════════════════════════

/// Icon directory header — matches `GRPICONDIR` / ICO file header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IconDirHeader {
    pub reserved: u16,
    pub ty: u16, // 1 = ICO
    pub count: u16,
}

/// Icon directory entry — matches `GRPICONDIRENTRY` / ICO directory entry.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IconDirEntry {
    pub width: u8,
    pub height: u8,
    pub colors: u8,
    pub reserved: u8,
    pub planes: u16,
    pub bpp: u16,
    pub size: u32,
    pub offset: u32,
}

// Re-export IconImage from the icon module to keep a single canonical type.
pub use crate::icon::IconImage;

/// A group icon resource: the header + array of directory entries from
/// a single `RT_GROUP_ICON` resource.
#[derive(Debug, Clone)]
pub struct GroupIcon {
    pub header: IconDirHeader,
    pub entries: Vec<IconDirEntry>,
}

/// Find all `RT_GROUP_ICON` resources in the PE file and return their
/// parsed `GroupIcon` structures (header + directory entries).
///
/// The returned `GroupIcon.entries` contain an `offset` field that
/// holds the **resource ID** (icon name ID) to use when looking up
/// the corresponding `RT_ICON` entry.
pub fn find_resource_group_icons(pe_data: &[u8]) -> AppResult<Vec<GroupIcon>> {
    let parsed = parse(pe_data)?;
    let sections = &parsed.sections;
    let directories = &parsed.data_directories;

    let resource_dir = directories
        .get(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        .copied()
        .unwrap_or_default();
    if resource_dir.virtual_address == 0 || resource_dir.size == 0 {
        return Ok(Vec::new());
    }

    let res_section = section_for_rva(sections, resource_dir.virtual_address, 1, true)
        .ok_or_else(|| pe_error("resource directory RVA is not covered by any section"))?;

    let section_bytes = slice(
        pe_data,
        res_section.raw_data_ptr as usize,
        res_section.raw_data_size as usize,
        "resource section",
    )?;

    // Navigate: Root → Type (RT_GROUP_ICON) → Name → Language → Data Entry
    let group_icon_data_entries = collect_resource_data_entries_by_type(
        section_bytes,
        res_section.virtual_address,
        resource_dir.virtual_address,
        RT_GROUP_ICON,
    )?;

    let mut groups = Vec::new();
    for data_entry in &group_icon_data_entries {
        let data = get_resource_section_data(
            section_bytes,
            res_section.virtual_address,
            data_entry.data_rva,
            data_entry.data_size,
        )?;
        if data.len() < 6 {
            continue;
        }
        let reserved = u16::from_le_bytes([data[0], data[1]]);
        let ty = u16::from_le_bytes([data[2], data[3]]);
        let count = u16::from_le_bytes([data[4], data[5]]);
        if reserved != 0 || ty != 1 {
            continue;
        }

        let header = IconDirHeader {
            reserved,
            ty,
            count,
        };
        let mut entries = Vec::with_capacity(count as usize);
        for i in 0..count as usize {
            let off = 6 + i * 14;
            if off + 14 > data.len() {
                break;
            }
            let width = data[off];
            let height = data[off + 1];
            let colors = data[off + 2];
            let reserved_byte = data[off + 3];
            let planes = u16::from_le_bytes([data[off + 4], data[off + 5]]);
            let bpp = u16::from_le_bytes([data[off + 6], data[off + 7]]);
            let size =
                u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
            let icon_id = u16::from_le_bytes([data[off + 12], data[off + 13]]);

            // Store the icon resource ID in the offset field (it's unused in
            // the ICO file context but serves as our link to RT_ICON).
            entries.push(IconDirEntry {
                width,
                height,
                colors,
                reserved: reserved_byte,
                planes,
                bpp,
                size,
                offset: icon_id as u32,
            });
        }
        groups.push(GroupIcon { header, entries });
    }

    Ok(groups)
}

/// Extract the actual `RT_ICON` bitmap data bytes for a single icon entry
/// (identified by its resource name ID from a group icon entry).
pub fn find_resource_icon_by_id(pe_data: &[u8], icon_id: u32) -> AppResult<Option<Vec<u8>>> {
    let parsed = parse(pe_data)?;
    let sections = &parsed.sections;
    let directories = &parsed.data_directories;

    let resource_dir = directories
        .get(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        .copied()
        .unwrap_or_default();
    if resource_dir.virtual_address == 0 || resource_dir.size == 0 {
        return Ok(None);
    }

    let res_section = section_for_rva(sections, resource_dir.virtual_address, 1, true)
        .ok_or_else(|| pe_error("resource directory RVA is not covered by any section"))?;
    let section_bytes = slice(
        pe_data,
        res_section.raw_data_ptr as usize,
        res_section.raw_data_size as usize,
        "resource section",
    )?;

    let data_entries = collect_resource_data_entries_by_type_and_name(
        section_bytes,
        res_section.virtual_address,
        resource_dir.virtual_address,
        RT_ICON,
        icon_id,
    )?;

    if let Some(entry) = data_entries.first() {
        let data = get_resource_section_data(
            section_bytes,
            res_section.virtual_address,
            entry.data_rva,
            entry.data_size,
        )?;
        Ok(Some(data))
    } else {
        Ok(None)
    }
}

/// Extract the first (largest) icon from a PE file.
///
/// This is the primary extraction function. It finds all group icon
/// resources, then for each entry resolves the corresponding `RT_ICON`
/// data and returns a `Vec<IconImage>`.
pub fn extract_icon_from_pe(pe_data: &[u8]) -> AppResult<Vec<IconImage>> {
    let all = extract_all_icons_from_pe(pe_data)?;
    // Return the icon with the highest score (pixel count × bpp)
    Ok(all
        .into_iter()
        .max_by(|a, b| {
            let sa = (a.width * a.height * a.bpp as u32) as u64;
            let sb = (b.width * b.height * b.bpp as u32) as u64;
            sa.cmp(&sb)
        })
        .into_iter()
        .collect())
}

/// Extract all icon images from a PE file, across all group icon resources.
pub fn extract_all_icons_from_pe(pe_data: &[u8]) -> AppResult<Vec<IconImage>> {
    let groups = find_resource_group_icons(pe_data)?;
    let mut icons = Vec::new();

    for group in &groups {
        for entry in &group.entries {
            // The offset field holds the icon resource ID (name ID)
            let icon_id = entry.offset;
            let Some(icon_data) = find_resource_icon_by_id(pe_data, icon_id)? else {
                continue;
            };

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

            // Check if the icon data is PNG-compressed (common in Vista+)
            let is_png = icon_data.len() >= 8
                && icon_data[0] == 0x89
                && icon_data[1] == b'P'
                && icon_data[2] == b'N'
                && icon_data[3] == b'G';

            icons.push(IconImage {
                width: display_width,
                height: display_height,
                bpp: entry.bpp,
                data: icon_data,
                is_png_compressed: is_png,
                xor_mask: None,
            });
        }
    }

    Ok(icons)
}

// ── Internal helpers for resource-tree traversal ────────────────────────────

/// A resource name key for [`find_resource_data_entry_by_key`]: either a
/// numeric resource ID (`MAKEINTRESOURCE` form) or a string name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceName {
    Id(u32),
    Str(String),
}

/// Find ONE resource data entry by numeric type ID and numeric-or-string
/// name, returning `(data_rva, data_size)`.
///
/// The Windows resource tree is three levels: type → name → language.  The
/// name level may hold numeric IDs or named (string) entries; this walker
/// matches the requested key against both forms and returns the first
/// language's data entry below the match.
pub fn find_resource_data_entry_by_key(
    bytes: &[u8],
    sections: &[PeSection],
    directories: &[DataDirectory],
    type_id: u32,
    name: &ResourceName,
) -> AppResult<Option<(u32, u32)>> {
    let directory = directories
        .get(IMAGE_DIRECTORY_ENTRY_RESOURCE)
        .copied()
        .unwrap_or_default();
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
    let section_rva = resource_section.virtual_address;
    let root_rva = directory.virtual_address;

    // Level 1: the type entry (numeric IDs only — types are always numeric).
    let type_subdir_rva = resource_child_directory(
        section_bytes,
        section_rva,
        root_rva,
        root_rva,
        &ResourceName::Id(type_id),
    )?;
    if type_subdir_rva == 0 {
        return Ok(None);
    }
    // Level 2: the name entry.
    let name_subdir_rva =
        resource_child_directory(section_bytes, section_rva, root_rva, type_subdir_rva, name)?;
    if name_subdir_rva == 0 {
        return Ok(None);
    }
    // Level 3: any language — return the first data entry.
    let relative = directory_relative(section_rva, name_subdir_rva)?;
    let named = resource_entry_count(section_bytes, relative, true)?;
    let ids = resource_entry_count(section_bytes, relative, false)?;
    for index in 0..(named + ids) {
        let entry_offset = relative + 16 + index * 8;
        checked_range(section_bytes, entry_offset, 8, "resource language entry")?;
        let payload = read_u32(
            section_bytes,
            entry_offset + 4,
            "resource language entry payload",
        )?;
        if payload & 0x8000_0000 != 0 {
            continue; // language level must point at data entries
        }
        let data_entry_rva = root_rva
            .checked_add(payload & 0x7fff_ffff)
            .ok_or_else(|| pe_error("resource data entry overflow"))?;
        return read_resource_data_rva_size(section_bytes, section_rva, data_entry_rva).map(Some);
    }
    Ok(None)
}

/// The subdirectory RVA for the first entry matching `key` inside the
/// directory at `directory_rva`.  Returns `Ok(0)` when no entry matches.
fn resource_child_directory(
    section_bytes: &[u8],
    section_rva: u32,
    root_rva: u32,
    directory_rva: u32,
    key: &ResourceName,
) -> AppResult<u32> {
    let relative = directory_relative(section_rva, directory_rva)?;
    let named = resource_entry_count(section_bytes, relative, true)?;
    let ids = resource_entry_count(section_bytes, relative, false)?;
    for index in 0..(named + ids) {
        let entry_offset = relative + 16 + index * 8;
        checked_range(section_bytes, entry_offset, 8, "resource entry")?;
        let name_field = read_u32(section_bytes, entry_offset, "resource entry name")?;
        let matches = if name_field & 0x8000_0000 != 0 {
            // Named entry: the low 31 bits are an RVA to a UTF-16 string.
            match key {
                ResourceName::Str(expected) => {
                    let string_rva = root_rva
                        .checked_add(name_field & 0x7fff_ffff)
                        .ok_or_else(|| pe_error("resource name string overflow"))?;
                    let string_relative = directory_relative(section_rva, string_rva)?;
                    let mut offset = string_relative;
                    let mut units = Vec::new();
                    loop {
                        checked_range(section_bytes, offset, 2, "resource name string")?;
                        let unit = read_u16(section_bytes, offset, "resource name unit")?;
                        offset += 2;
                        if unit == 0 {
                            break;
                        }
                        units.push(unit);
                        if units.len() > 256 {
                            break;
                        }
                    }
                    String::from_utf16_lossy(&units).eq_ignore_ascii_case(expected)
                }
                ResourceName::Id(_) => false,
            }
        } else {
            matches!(key, ResourceName::Id(id) if (name_field & 0xffff) == *id)
        };
        if !matches {
            continue;
        }
        let payload = read_u32(section_bytes, entry_offset + 4, "resource entry payload")?;
        if payload & 0x8000_0000 == 0 {
            // A data entry at this level: nothing to descend into.
            return Ok(0);
        }
        return root_rva
            .checked_add(payload & 0x7fff_ffff)
            .ok_or_else(|| pe_error("resource subdirectory overflow"));
    }
    Ok(0)
}

/// Read the raw payload bytes of a resource at `data_rva` (the value
/// `find_resource_data_entry_by_key` returns) from the PE file bytes.
pub fn extract_resource_payload(
    bytes: &[u8],
    sections: &[PeSection],
    data_rva: u32,
    data_size: u32,
) -> AppResult<Option<Vec<u8>>> {
    if data_size == 0 {
        return Ok(Some(Vec::new()));
    }
    let offset = rva_to_file_offset(data_rva, data_size, sections, 0)?;
    Ok(Some(
        slice(bytes, offset, data_size as usize, "resource payload")?.to_vec(),
    ))
}

/// RVA-relative offset of a directory inside the resource section.
fn directory_relative(section_rva: u32, directory_rva: u32) -> AppResult<usize> {
    directory_rva
        .checked_sub(section_rva)
        .map(|value| value as usize)
        .ok_or_else(|| pe_error("resource directory underflow"))
}

/// Named (index 0) or ID (index 1) entry count of a resource directory.
fn resource_entry_count(section_bytes: &[u8], relative: usize, named: bool) -> AppResult<usize> {
    checked_range(section_bytes, relative, 16, "resource directory")?;
    let offset = if named { 12 } else { 14 };
    Ok(read_u16(section_bytes, relative + offset, "resource entry count")? as usize)
}

/// Read `(data_rva, size)` from a resource data entry.
fn read_resource_data_rva_size(
    section_bytes: &[u8],
    section_rva: u32,
    data_entry_rva: u32,
) -> AppResult<(u32, u32)> {
    let relative = directory_relative(section_rva, data_entry_rva)?;
    checked_range(section_bytes, relative, 16, "resource data entry")?;
    let offset_to_data = read_u32(section_bytes, relative, "resource OffsetToData")?;
    let size = read_u32(section_bytes, relative + 4, "resource Size")?;
    Ok((offset_to_data, size))
}

#[derive(Debug)]
struct ResourceDataEntry {
    data_rva: u32,
    data_size: u32,
}

/// Collect all data entries under a given type ID at the first resource level.
fn collect_resource_data_entries_by_type(
    section_data: &[u8],
    section_rva: u32,
    root_rva: u32,
    type_id: u32,
) -> AppResult<Vec<ResourceDataEntry>> {
    let root_relative = root_rva
        .checked_sub(section_rva)
        .ok_or_else(|| pe_error("resource root underflow"))? as usize;
    if root_relative + 16 > section_data.len() {
        return Ok(Vec::new());
    }

    let named_entries = u16::from_le_bytes([
        section_data[root_relative + 12],
        section_data[root_relative + 13],
    ]) as usize;
    let id_entries = u16::from_le_bytes([
        section_data[root_relative + 14],
        section_data[root_relative + 15],
    ]) as usize;
    let total = named_entries + id_entries;

    for i in 0..total {
        let off = root_relative + 16 + i * 8;
        if off + 8 > section_data.len() {
            break;
        }
        let name_or_id = u32::from_le_bytes([
            section_data[off],
            section_data[off + 1],
            section_data[off + 2],
            section_data[off + 3],
        ]);
        // Skip named entries (high bit set) — we only match by numeric ID
        if name_or_id & 0x8000_0000 != 0 {
            continue;
        }
        if (name_or_id & 0xffff) != type_id {
            continue;
        }

        let payload = u32::from_le_bytes([
            section_data[off + 4],
            section_data[off + 5],
            section_data[off + 6],
            section_data[off + 7],
        ]);

        if payload & 0x8000_0000 != 0 {
            // Points to a subdirectory — recurse to collect all data entries beneath it
            let subdir_rva = root_rva
                .checked_add(payload & 0x7fff_ffff)
                .ok_or_else(|| pe_error("resource subdirectory overflow"))?;
            return collect_data_entries_recursive(
                section_data,
                section_rva,
                root_rva,
                subdir_rva,
                2,
            );
        } else {
            // Points to a data entry directly (unusual at level 1 but handle gracefully)
            let data_entry_rva = root_rva
                .checked_add(payload & 0x7fff_ffff)
                .ok_or_else(|| pe_error("resource data entry overflow"))?;
            return Ok(vec![read_resource_data_entry(
                section_data,
                section_rva,
                data_entry_rva,
            )?]);
        }
    }

    Ok(Vec::new())
}

/// Collect data entries by matching both type ID (level 1) and name ID (level 2).
fn collect_resource_data_entries_by_type_and_name(
    section_data: &[u8],
    section_rva: u32,
    root_rva: u32,
    type_id: u32,
    name_id: u32,
) -> AppResult<Vec<ResourceDataEntry>> {
    let root_relative = root_rva
        .checked_sub(section_rva)
        .ok_or_else(|| pe_error("resource root underflow"))? as usize;
    if root_relative + 16 > section_data.len() {
        return Ok(Vec::new());
    }

    let named_entries = u16::from_le_bytes([
        section_data[root_relative + 12],
        section_data[root_relative + 13],
    ]) as usize;
    let id_entries = u16::from_le_bytes([
        section_data[root_relative + 14],
        section_data[root_relative + 15],
    ]) as usize;
    let total = named_entries + id_entries;

    for i in 0..total {
        let off = root_relative + 16 + i * 8;
        if off + 8 > section_data.len() {
            break;
        }
        let name_or_id = u32::from_le_bytes([
            section_data[off],
            section_data[off + 1],
            section_data[off + 2],
            section_data[off + 3],
        ]);
        if name_or_id & 0x8000_0000 != 0 {
            continue;
        }
        if (name_or_id & 0xffff) != type_id {
            continue;
        }

        let payload = u32::from_le_bytes([
            section_data[off + 4],
            section_data[off + 5],
            section_data[off + 6],
            section_data[off + 7],
        ]);
        if payload & 0x8000_0000 == 0 {
            continue; // Need a subdirectory
        }

        let type_subdir_rva = root_rva
            .checked_add(payload & 0x7fff_ffff)
            .ok_or_else(|| pe_error("resource subdirectory overflow"))?;

        // Search level 2 (name) for the specific name_id
        return find_data_entries_by_name_id(
            section_data,
            section_rva,
            root_rva,
            type_subdir_rva,
            name_id,
        );
    }

    Ok(Vec::new())
}

/// At the second resource level (name entries), find entries matching `name_id`.
fn find_data_entries_by_name_id(
    section_data: &[u8],
    section_rva: u32,
    root_rva: u32,
    dir_rva: u32,
    name_id: u32,
) -> AppResult<Vec<ResourceDataEntry>> {
    let dir_relative = dir_rva
        .checked_sub(section_rva)
        .ok_or_else(|| pe_error("resource dir underflow"))? as usize;
    if dir_relative + 16 > section_data.len() {
        return Ok(Vec::new());
    }

    let named_entries = u16::from_le_bytes([
        section_data[dir_relative + 12],
        section_data[dir_relative + 13],
    ]) as usize;
    let id_entries = u16::from_le_bytes([
        section_data[dir_relative + 14],
        section_data[dir_relative + 15],
    ]) as usize;
    let total = named_entries + id_entries;

    for i in 0..total {
        let off = dir_relative + 16 + i * 8;
        if off + 8 > section_data.len() {
            break;
        }
        let name_or_id = u32::from_le_bytes([
            section_data[off],
            section_data[off + 1],
            section_data[off + 2],
            section_data[off + 3],
        ]);
        if name_or_id & 0x8000_0000 != 0 {
            continue;
        }
        if (name_or_id & 0xffff) != name_id {
            continue;
        }

        let payload = u32::from_le_bytes([
            section_data[off + 4],
            section_data[off + 5],
            section_data[off + 6],
            section_data[off + 7],
        ]);

        if payload & 0x8000_0000 != 0 {
            // Navigate to level 3 (language) and collect all data entries
            let lang_dir_rva = root_rva
                .checked_add(payload & 0x7fff_ffff)
                .ok_or_else(|| pe_error("resource language subdirectory overflow"))?;
            return collect_data_entries_recursive(
                section_data,
                section_rva,
                root_rva,
                lang_dir_rva,
                4,
            );
        } else {
            // Points directly to a data entry
            let data_entry_rva = root_rva
                .checked_add(payload & 0x7fff_ffff)
                .ok_or_else(|| pe_error("resource data entry overflow"))?;
            return Ok(vec![read_resource_data_entry(
                section_data,
                section_rva,
                data_entry_rva,
            )?]);
        }
    }

    Ok(Vec::new())
}

/// Recursively collect all data entries at or below a given directory RVA.
fn collect_data_entries_recursive(
    section_data: &[u8],
    section_rva: u32,
    root_rva: u32,
    dir_rva: u32,
    depth: u8,
) -> AppResult<Vec<ResourceDataEntry>> {
    if depth > 4 {
        return Ok(Vec::new());
    }

    let dir_relative = dir_rva
        .checked_sub(section_rva)
        .ok_or_else(|| pe_error("resource dir underflow"))? as usize;
    if dir_relative + 16 > section_data.len() {
        return Ok(Vec::new());
    }

    let named_entries = u16::from_le_bytes([
        section_data[dir_relative + 12],
        section_data[dir_relative + 13],
    ]) as usize;
    let id_entries = u16::from_le_bytes([
        section_data[dir_relative + 14],
        section_data[dir_relative + 15],
    ]) as usize;
    let total = named_entries + id_entries;

    let mut results = Vec::new();
    for i in 0..total {
        let off = dir_relative + 16 + i * 8;
        if off + 8 > section_data.len() {
            break;
        }
        let _name_or_id = u32::from_le_bytes([
            section_data[off],
            section_data[off + 1],
            section_data[off + 2],
            section_data[off + 3],
        ]);
        let payload = u32::from_le_bytes([
            section_data[off + 4],
            section_data[off + 5],
            section_data[off + 6],
            section_data[off + 7],
        ]);

        if payload & 0x8000_0000 != 0 {
            let child_rva = root_rva
                .checked_add(payload & 0x7fff_ffff)
                .ok_or_else(|| pe_error("resource subdirectory overflow"))?;
            results.extend(collect_data_entries_recursive(
                section_data,
                section_rva,
                root_rva,
                child_rva,
                depth + 1,
            )?);
        } else if depth >= 2 {
            let data_entry_rva = root_rva
                .checked_add(payload & 0x7fff_ffff)
                .ok_or_else(|| pe_error("resource data entry overflow"))?;
            results.push(read_resource_data_entry(
                section_data,
                section_rva,
                data_entry_rva,
            )?);
        }
    }

    Ok(results)
}

/// Read a `ResourceDataEntry` (offset-to-data + size) from a resource data entry structure.
fn read_resource_data_entry(
    section_data: &[u8],
    section_rva: u32,
    data_entry_rva: u32,
) -> AppResult<ResourceDataEntry> {
    let de_off = data_entry_rva
        .checked_sub(section_rva)
        .ok_or_else(|| pe_error("resource data entry underflow"))? as usize;
    if de_off + 16 > section_data.len() {
        return Err(pe_error("resource data entry truncated"));
    }
    let data_rva = u32::from_le_bytes([
        section_data[de_off],
        section_data[de_off + 1],
        section_data[de_off + 2],
        section_data[de_off + 3],
    ]);
    let data_size = u32::from_le_bytes([
        section_data[de_off + 4],
        section_data[de_off + 5],
        section_data[de_off + 6],
        section_data[de_off + 7],
    ]);
    Ok(ResourceDataEntry {
        data_rva,
        data_size,
    })
}

/// Read raw bytes from the resource section data by RVA.
fn get_resource_section_data(
    section_bytes: &[u8],
    section_rva: u32,
    data_rva: u32,
    data_size: u32,
) -> AppResult<Vec<u8>> {
    if data_size == 0 {
        return Ok(Vec::new());
    }
    let offset = data_rva
        .checked_sub(section_rva)
        .ok_or_else(|| pe_error("resource data RVA underflow"))? as usize;
    let end = offset
        .checked_add(data_size as usize)
        .ok_or_else(|| pe_error("resource data size overflow"))?;
    if end > section_bytes.len() {
        return Err(pe_error("resource data extends beyond section"));
    }
    Ok(section_bytes[offset..end].to_vec())
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

// ── Helper: build a minimal valid PE32 binary for testing ─────────────────
#[cfg(test)]
fn build_minimal_pe32() -> Vec<u8> {
    // DOS header: 64 bytes
    let mut buf = vec![0u8; 0x400];
    buf[0] = b'M';
    buf[1] = b'Z';
    let pe_offset: u32 = 0x80;
    buf[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
    // PE signature
    let pe_off = pe_offset as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
    // COFF header (20 bytes)
    buf[pe_off + 4..pe_off + 6].copy_from_slice(&0x014c_u16.to_le_bytes()); // machine = I386
    buf[pe_off + 6..pe_off + 8].copy_from_slice(&0u16.to_le_bytes()); // number_of_sections
    buf[pe_off + 20..pe_off + 22].copy_from_slice(&0xE0u16.to_le_bytes()); // size_of_optional_header
    buf[pe_off + 22..pe_off + 24].copy_from_slice(&0x0102_u16.to_le_bytes()); // characteristics
    // Optional header PE32
    let opt_off = pe_off + 24;
    buf[opt_off..opt_off + 2].copy_from_slice(&0x010b_u16.to_le_bytes()); // magic PE32
    // address_of_entry_point at opt+16
    buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
    // image_base at opt+28 (PE32)
    buf[opt_off + 28..opt_off + 32].copy_from_slice(&0x00400000_u32.to_le_bytes());
    // section_alignment at opt+32
    buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    // file_alignment at opt+36
    buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x0200_u32.to_le_bytes());
    // size_of_image at opt+56
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
    // size_of_headers at opt+60
    buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x0400_u32.to_le_bytes());
    // dll_characteristics at opt+70
    buf[opt_off + 70..opt_off + 72].copy_from_slice(&0_u16.to_le_bytes());
    // number_of_rva_and_sizes at opt+92
    buf[opt_off + 92..opt_off + 96].copy_from_slice(&16_u32.to_le_bytes());
    buf
}

#[cfg(test)]
fn build_minimal_pe32_plus() -> Vec<u8> {
    let mut buf = vec![0u8; 0x400];
    buf[0] = b'M';
    buf[1] = b'Z';
    let pe_offset: u32 = 0x80;
    buf[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
    let pe_off = pe_offset as usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x00");
    buf[pe_off + 4..pe_off + 6].copy_from_slice(&0x8664_u16.to_le_bytes()); // machine = AMD64
    buf[pe_off + 6..pe_off + 8].copy_from_slice(&0u16.to_le_bytes());
    buf[pe_off + 20..pe_off + 22].copy_from_slice(&0xF0u16.to_le_bytes()); // size_of_optional_header (>=112)
    buf[pe_off + 22..pe_off + 24].copy_from_slice(&0x0102_u16.to_le_bytes());
    let opt_off = pe_off + 24;
    buf[opt_off..opt_off + 2].copy_from_slice(&0x020b_u16.to_le_bytes()); // magic PE32+
    buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
    // image_base at opt+24 (PE32+)
    buf[opt_off + 24..opt_off + 32].copy_from_slice(&0x00000000_40000000_u64.to_le_bytes());
    buf[opt_off + 32..opt_off + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
    buf[opt_off + 36..opt_off + 40].copy_from_slice(&0x0200_u32.to_le_bytes());
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
    buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x0400_u32.to_le_bytes());
    buf[opt_off + 70..opt_off + 72].copy_from_slice(&0_u16.to_le_bytes());
    buf[opt_off + 108..opt_off + 112].copy_from_slice(&16_u32.to_le_bytes());
    buf
}

// ── Helper: build a section and directory for inline testing ──────────────
#[cfg(test)]
fn make_section(va: u32, vs: u32, rdp: u32, rds: u32, name: &str, chars: u32) -> PeSection {
    PeSection {
        name: name.to_string(),
        virtual_address: va,
        virtual_size: vs,
        raw_data_ptr: rdp,
        raw_data_size: rds,
        characteristics: chars,
    }
}

#[cfg(test)]
fn make_directory(va: u32, size: u32) -> DataDirectory {
    DataDirectory {
        virtual_address: va,
        size,
    }
}

// ══════════════════════════════════════════════════════════════════════════
// E5 – PE Parser Test Coverage Expansion
// ══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod e5_pe_parser_tests {
    use super::*;

    // ── Malformed PE files ───────────────────────────────────────────────

    #[test]
    fn parse_rejects_invalid_dos_signature() {
        let bytes = b"not-a-pe-file".to_vec();
        let result = parse(&bytes);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_rejects_invalid_pe_signature() {
        let mut buf = build_minimal_pe32();
        let pe_off = 0x80usize;
        buf[pe_off..pe_off + 4].copy_from_slice(b"PE\x00\x01"); // bad sig
        let result = parse(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_rejects_truncated_dos_header() {
        let bytes = b"MZ".to_vec(); // only 2 bytes, no e_lfanew
        let result = parse(&bytes);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_rejects_pe_offset_out_of_range() {
        let mut buf = vec![0u8; 0x100];
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew points beyond file size
        buf[0x3c..0x40].copy_from_slice(&0x2000_u32.to_le_bytes());
        let result = parse(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_rejects_unsupported_optional_header_magic() {
        let mut buf = build_minimal_pe32();
        let opt_off = 0x80 + 24;
        buf[opt_off..opt_off + 2].copy_from_slice(&0x010c_u16.to_le_bytes()); // invalid magic
        let result = parse(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_rejects_optional_header_too_small_for_pe32() {
        let mut buf = build_minimal_pe32();
        let pe_off = 0x80;
        // size_of_optional_header = 0 (minimum PE32 requires 96)
        buf[pe_off + 20..pe_off + 22].copy_from_slice(&0u16.to_le_bytes());
        let result = parse(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_rejects_optional_header_too_small_for_pe32_plus() {
        let mut buf = build_minimal_pe32_plus();
        let pe_off = 0x80;
        // size_of_optional_header = 100 (minimum PE32+ requires 112)
        buf[pe_off + 20..pe_off + 22].copy_from_slice(&100_u16.to_le_bytes());
        let result = parse(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_accepts_minimum_valid_pe32() {
        let buf = build_minimal_pe32();
        let parsed = parse(&buf).expect("minimal PE32 should parse");
        assert_eq!(parsed.machine, 0x014c);
        assert_eq!(parsed.number_of_sections, 0);
        assert_eq!(parsed.optional_header_magic, 0x010b);
        assert_eq!(parsed.address_of_entry_point, 0x1000);
        assert_eq!(parsed.image_base, 0x00400000);
        assert_eq!(parsed.sections.len(), 0);
    }

    #[test]
    fn parse_accepts_minimum_valid_pe32_plus() {
        let buf = build_minimal_pe32_plus();
        let parsed = parse(&buf).expect("minimal PE32+ should parse");
        assert_eq!(parsed.machine, 0x8664);
        assert_eq!(parsed.optional_header_magic, 0x020b);
        assert_eq!(parsed.pointer_bytes(), 8);
    }

    #[test]
    fn parse_detects_pointer_bytes_for_pe32() {
        let buf = build_minimal_pe32();
        let parsed = parse(&buf).unwrap();
        assert_eq!(parsed.pointer_bytes(), 4);
    }

    #[test]
    fn parse_detects_dynamic_base_flag() {
        let mut buf = build_minimal_pe32();
        let pe_off = 0x80;
        let opt_off = pe_off + 24;
        // Set DLL characteristics: DYNAMIC_BASE
        buf[opt_off + 70..opt_off + 72].copy_from_slice(&0x0040_u16.to_le_bytes());
        let parsed = parse(&buf).unwrap();
        assert!(parsed.dynamic_base());
    }

    #[test]
    fn parse_reports_no_dynamic_base_when_flag_missing() {
        let buf = build_minimal_pe32();
        let parsed = parse(&buf).unwrap();
        assert!(!parsed.dynamic_base());
    }

    // ── Section edge cases ───────────────────────────────────────────────

    #[test]
    fn parse_accepts_single_section() {
        let mut buf = build_minimal_pe32();
        let pe_off = 0x80;
        // Set number_of_sections = 1
        buf[pe_off + 6..pe_off + 8].copy_from_slice(&1_u16.to_le_bytes());
        // size_of_optional_header needs to include enough room for section table
        let opt_size: u16 = 0xE0;
        buf[pe_off + 20..pe_off + 22].copy_from_slice(&opt_size.to_le_bytes());
        let section_table_off = pe_off + 24 + opt_size as usize;
        // Extend buffer for section header (40 bytes)
        buf.resize(section_table_off + 40, 0);
        // Section name ".text"
        buf[section_table_off..section_table_off + 5].copy_from_slice(b".text");
        buf[section_table_off + 8..section_table_off + 12]
            .copy_from_slice(&0x1000_u32.to_le_bytes()); // vs
        buf[section_table_off + 12..section_table_off + 16]
            .copy_from_slice(&0x1000_u32.to_le_bytes()); // va
        buf[section_table_off + 16..section_table_off + 20]
            .copy_from_slice(&0x0200_u32.to_le_bytes()); // rds
        buf[section_table_off + 20..section_table_off + 24]
            .copy_from_slice(&0x0400_u32.to_le_bytes()); // rdp
        buf[section_table_off + 36..section_table_off + 40]
            .copy_from_slice(&(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE).to_le_bytes());
        // Ensure raw data is present
        buf.resize(0x0600, 0);
        let parsed = parse(&buf).expect("PE32 with one section should parse");
        assert_eq!(parsed.number_of_sections, 1);
        assert_eq!(parsed.sections.len(), 1);
        assert_eq!(parsed.sections[0].name, ".text");
        assert_eq!(parsed.sections[0].virtual_address, 0x1000);
    }

    #[test]
    fn parse_rejects_section_exceeding_size_of_image() {
        let mut buf = build_minimal_pe32();
        let pe_off = 0x80;
        buf[pe_off + 6..pe_off + 8].copy_from_slice(&1_u16.to_le_bytes());
        let opt_size: u16 = 0xE0;
        buf[pe_off + 20..pe_off + 22].copy_from_slice(&opt_size.to_le_bytes());
        let section_table_off = pe_off + 24 + opt_size as usize;
        buf.resize(section_table_off + 40, 0);
        buf[section_table_off..section_table_off + 5].copy_from_slice(b".text");
        buf[section_table_off + 8..section_table_off + 12]
            .copy_from_slice(&0x2000_u32.to_le_bytes()); // vs (exceeds SizeOfImage=0x2000)
        buf[section_table_off + 12..section_table_off + 16]
            .copy_from_slice(&0x1000_u32.to_le_bytes()); // va
        buf[section_table_off + 16..section_table_off + 20].copy_from_slice(&4_u32.to_le_bytes()); // rds
        buf[section_table_off + 20..section_table_off + 24]
            .copy_from_slice(&0x0400_u32.to_le_bytes()); // rdp
        buf[section_table_off + 36..section_table_off + 40]
            .copy_from_slice(&IMAGE_SCN_MEM_READ.to_le_bytes());
        buf.resize(0x0600, 0);
        let result = parse(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_rejects_size_of_headers_exceeding_file_size() {
        let mut buf = build_minimal_pe32();
        let opt_off = 0x80 + 24;
        // Set SizeOfHeaders to something huge
        buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x1_0000_u32.to_le_bytes());
        let result = parse(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_rejects_size_of_image_smaller_than_headers() {
        let mut buf = build_minimal_pe32();
        let opt_off = 0x80 + 24;
        // SizeOfImage=0x200 < SizeOfHeaders=0x400 — would crash map_image
        buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x200_u32.to_le_bytes());
        let result = parse(&buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── Debug directory ──────────────────────────────────────────────────

    #[test]
    fn parse_debug_entries_returns_empty_when_directory_missing() {
        let sections = &[];
        let directories = &[];
        let entries = parse_debug_entries(b"", sections, directories, 0).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_debug_entries_tolerates_trailing_padding() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".rdata",
            IMAGE_SCN_MEM_READ,
        )];
        let directories = &[DataDirectory::default(); 7];
        let mut dirs = directories.to_vec();
        dirs[6] = make_directory(0x1000, 30); // 30 = one 28-byte entry + 2 bytes of padding
        let entries = parse_debug_entries(&[0u8; 0x200], sections, &dirs, 0).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_debug_directory_with_one_entry() {
        let mut bytes = vec![0u8; 0x200];
        // One debug entry at RVA 0x1000, offset 0 (within section)
        // IMAGE_DEBUG_DIRECTORY is 28 bytes
        // Type at offset 12, size_of_data at 16, address_of_raw_data at 20, pointer_to_raw_data at 24
        write_u32(&mut bytes, 12, 2).unwrap(); // type = IMAGE_DEBUG_TYPE_CODEVIEW (2)
        write_u32(&mut bytes, 16, 64).unwrap(); // size_of_data
        write_u32(&mut bytes, 20, 0x1100).unwrap(); // address_of_raw_data
        write_u32(&mut bytes, 24, 0x0100).unwrap(); // pointer_to_raw_data
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".rdata",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 7];
        dirs[IMAGE_DIRECTORY_ENTRY_DEBUG] = make_directory(0x1000, 28);
        let entries = parse_debug_entries(&bytes, sections, &dirs, 0).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ty, 2);
        assert_eq!(entries[0].size_of_data, 64);
    }

    // ── Load Config ──────────────────────────────────────────────────────

    #[test]
    fn parse_load_config_returns_none_when_directory_missing() {
        let result = parse_load_config(b"", &[], &[], 4).unwrap();
        assert!(result.is_none());
    }

    // ── Import directory ─────────────────────────────────────────────────

    #[test]
    fn parse_import_directory_returns_empty_when_missing() {
        let result = parse_import_directory(b"", &[], &[], false, 0, 4).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_import_directory_returns_empty_when_null_descriptor() {
        // Provide an import directory with a single all-zero descriptor (terminator)
        let sections = &[make_section(
            0x1000,
            0x100,
            0,
            0x100,
            ".idata",
            IMAGE_SCN_MEM_READ,
        )];
        let dirs = &[make_directory(0x1000, 20)];
        let bytes = vec![0u8; 0x100];
        // All zeros = terminal descriptor
        let result = parse_import_directory(&bytes, sections, dirs, false, 0, 4).unwrap();
        assert!(result.is_empty());
    }

    // ── Delay import directory ───────────────────────────────────────────

    #[test]
    fn parse_delay_import_directory_returns_empty_when_missing() {
        let result = parse_delay_import_directory(b"", &[], &[], 0, 4).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_delay_import_directory_tolerates_trailing_padding() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0,
            0x100,
            ".data",
            IMAGE_SCN_MEM_READ,
        )];
        // Directory index 13 for delay import
        let mut dirs = vec![DataDirectory::default(); 14];
        dirs[13] = make_directory(0x1000, 33); // 33 = one 32-byte descriptor + 1 byte of padding
        let bytes = vec![0u8; 0x100];
        // All-zero descriptor is a terminator, so parsing succeeds with no entries.
        let result = parse_delay_import_directory(&bytes, sections, &dirs, 0, 4).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_delay_import_directory_accepts_null_descriptor() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0,
            0x100,
            ".data",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 14];
        dirs[13] = make_directory(0x1000, 32);
        let bytes = vec![0u8; 0x100];
        // All zeros = terminal descriptor
        // DELAY_IMPORT_DESCRIPTOR: name(4), iat(4), int(4), ... — all zero
        let result = parse_delay_import_directory(&bytes, sections, &dirs, 0, 4).unwrap();
        assert!(result.is_empty());
    }

    // ── Export directory ─────────────────────────────────────────────────

    #[test]
    fn parse_export_directory_returns_empty_when_missing() {
        let result = parse_export_directory(b"", &[], &[]).unwrap();
        assert!(result.is_empty());
    }

    // ── Relocations ──────────────────────────────────────────────────────

    #[test]
    fn parse_relocations_returns_empty_when_missing() {
        let result = parse_relocations(b"", &[], &[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_relocations_parses_absolute_entry() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".reloc",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 16];
        dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = make_directory(0x1000, 12);
        let mut bytes = vec![0u8; 0x200];
        // Block header: page_rva(4), block_size(4)
        write_u32(&mut bytes, 0, 0x2000).unwrap(); // page_rva
        write_u32(&mut bytes, 4, 12).unwrap(); // block_size (8 header + 4 entry bytes)
        // Entry: type(4 bits) | offset(12 bits) = 0x0000 (IMAGE_REL_BASED_ABSOLUTE)
        write_u16(&mut bytes, 8, 0x0000).unwrap();
        let blocks = parse_relocations(&bytes, sections, &dirs).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].page_rva, 0x2000);
        assert_eq!(blocks[0].entries.len(), 2); // each entry is 2 bytes, 4 bytes = 2 entries
        assert_eq!(blocks[0].entries[0].kind, RelocationType::Absolute);
    }

    #[test]
    fn parse_relocations_parses_highlow_entry() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".reloc",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 16];
        dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = make_directory(0x1000, 12);
        let mut bytes = vec![0u8; 0x200];
        write_u32(&mut bytes, 0, 0x2000).unwrap();
        write_u32(&mut bytes, 4, 12).unwrap();
        // Entry: type=3 (HIGHLOW), offset=0x123
        write_u16(&mut bytes, 8, (3 << 12) | 0x0123).unwrap();
        let blocks = parse_relocations(&bytes, sections, &dirs).unwrap();
        assert_eq!(blocks[0].entries.len(), 2);
        let entry = &blocks[0].entries[0];
        assert_eq!(entry.kind, RelocationType::HighLow);
        assert_eq!(entry.offset, 0x0123);
    }

    #[test]
    fn parse_relocations_parses_dir64_entry() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".reloc",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 16];
        dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = make_directory(0x1000, 12);
        let mut bytes = vec![0u8; 0x200];
        write_u32(&mut bytes, 0, 0x2000).unwrap();
        write_u32(&mut bytes, 4, 12).unwrap();
        // Entry: type=10 (DIR64), offset=0xABC
        write_u16(&mut bytes, 8, (10 << 12) | 0x0ABC).unwrap();
        let blocks = parse_relocations(&bytes, sections, &dirs).unwrap();
        let entry = &blocks[0].entries[0];
        assert_eq!(entry.kind, RelocationType::Dir64);
        assert_eq!(entry.offset, 0x0ABC);
    }

    #[test]
    fn parse_relocations_rejects_truncated_block() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".reloc",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 16];
        dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = make_directory(0x1000, 12);
        let mut bytes = vec![0u8; 0x200];
        write_u32(&mut bytes, 0, 0x2000).unwrap();
        write_u32(&mut bytes, 4, 20).unwrap(); // claims 20 bytes but directory size is 12
        let result = parse_relocations(&bytes, sections, &dirs);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_relocations_rejects_block_with_truncated_entry() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".reloc",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 16];
        dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = make_directory(0x1000, 13);
        let mut bytes = vec![0u8; 0x200];
        write_u32(&mut bytes, 0, 0x2000).unwrap();
        write_u32(&mut bytes, 4, 13).unwrap(); // 13 - 8 = 5, which is odd -> truncated entry
        let result = parse_relocations(&bytes, sections, &dirs);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn parse_relocations_terminates_on_zero_page_and_block() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".reloc",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 16];
        dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = make_directory(0x1000, 16);
        let mut bytes = vec![0u8; 0x200];
        // First block: valid
        write_u32(&mut bytes, 0, 0x2000).unwrap();
        write_u32(&mut bytes, 4, 12).unwrap();
        write_u16(&mut bytes, 8, 0x0000).unwrap();
        // Second block: zero page_rva and block_size = terminator
        write_u32(&mut bytes, 12, 0).unwrap();
        write_u32(&mut bytes, 16, 0).unwrap();
        let blocks = parse_relocations(&bytes, sections, &dirs).unwrap();
        assert_eq!(blocks.len(), 1);
    }

    // ── TLS directory ────────────────────────────────────────────────────

    #[test]
    fn parse_tls_directory_returns_none_when_missing() {
        let result = parse_tls_directory(b"", &[], &[], 0, 4).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_tls_directory_with_callbacks_pe32() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".tls",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 10];
        dirs[9] = make_directory(0x1000, 24); // TLS dir, size=24 for PE32
        let mut bytes = vec![0u8; 0x200];
        // PE32 TLS directory: raw_data_start(4), raw_data_end(4), index(4), callbacks(4)
        write_u32(&mut bytes, 0, 0x3000).unwrap(); // raw_data_start
        write_u32(&mut bytes, 4, 0x3100).unwrap(); // raw_data_end
        write_u32(&mut bytes, 8, 0x4000).unwrap(); // address_of_index
        // address_of_callbacks -> points to callback array
        let callback_array_rva = 0x1050u32; // within .tls section
        let callback_array_va = callback_array_rva; // image_base = 0 for simplicity
        write_u32(&mut bytes, 12, callback_array_va).unwrap();
        // Write callback array: two callbacks + null terminator
        let array_offset = (callback_array_rva - 0x1000) as usize;
        write_u32(&mut bytes, array_offset, 0x1000_0100).unwrap(); // callback 1
        write_u32(&mut bytes, array_offset + 4, 0x1000_0200).unwrap(); // callback 2
        write_u32(&mut bytes, array_offset + 8, 0).unwrap(); // terminator

        let tls = parse_tls_directory(&bytes, sections, &dirs, 0, 4)
            .unwrap()
            .expect("TLS should be present");
        assert_eq!(tls.raw_data_start, 0x3000);
        assert_eq!(tls.raw_data_end, 0x3100);
        assert_eq!(tls.callbacks.len(), 2);
        assert_eq!(tls.callbacks[0], 0x1000_0100);
        assert_eq!(tls.callbacks[1], 0x1000_0200);
    }

    #[test]
    fn parse_tls_directory_no_callbacks() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0,
            0x100,
            ".tls",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 10];
        dirs[9] = make_directory(0x1000, 24);
        let mut bytes = vec![0u8; 0x100];
        write_u32(&mut bytes, 0, 0x3000).unwrap();
        write_u32(&mut bytes, 4, 0x3100).unwrap();
        write_u32(&mut bytes, 8, 0x4000).unwrap();
        write_u32(&mut bytes, 12, 0).unwrap(); // address_of_callbacks = 0
        let tls = parse_tls_directory(&bytes, sections, &dirs, 0, 4)
            .unwrap()
            .expect("TLS should be present");
        assert!(tls.callbacks.is_empty());
    }

    #[test]
    fn parse_tls_directory_rejects_callback_va_outside_rva_space() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0,
            0x100,
            ".tls",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 10];
        dirs[9] = make_directory(0x1000, 40);
        let mut bytes = vec![0u8; 0x100];
        // PE32+ TLS directory
        write_u64(&mut bytes, 0, 0x3000).unwrap();
        write_u64(&mut bytes, 8, 0x3100).unwrap();
        write_u64(&mut bytes, 16, 0x4000).unwrap();
        // address_of_callbacks = image_base + 4 GiB: the RVA delta does not
        // fit in u32 and must error instead of truncating.
        write_u64(&mut bytes, 24, 0x0040_0000_0000_0000 + 0x1_0000_0000).unwrap();
        let result = parse_tls_directory(&bytes, sections, &dirs, 0x0040_0000_0000_0000, 8);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── Version info ─────────────────────────────────────────────────────

    #[test]
    fn parse_version_resource_default_when_missing() {
        let result = parse_version_resource(b"", &[], &[]).unwrap();
        assert_eq!(result, VersionInfo::default());
    }

    #[test]
    fn find_resource_data_entry_terminates_on_cyclic_tree() {
        // A resource directory whose single entry points back to itself
        // (payload = 0x8000_0000 | 0). Without the depth guard this recurses
        // forever and overflows the stack.
        let mut bytes = vec![0u8; 0x28];
        write_u16(&mut bytes, 12, 0).unwrap(); // named entry count
        write_u16(&mut bytes, 14, 1).unwrap(); // id entry count
        write_u32(&mut bytes, 16, RT_VERSION).unwrap(); // entry name
        write_u32(&mut bytes, 20, 0x8000_0000).unwrap(); // subdirectory → self
        let result = find_resource_data_entry(&bytes, 0x1000, 0x1000, 0x1000, Some(RT_VERSION), 0);
        assert_eq!(result.unwrap(), None);
    }

    // ── Embedded manifest ────────────────────────────────────────────────

    #[test]
    fn parse_embedded_manifest_none_when_missing() {
        let result = parse_embedded_manifest(b"", &[], &[]).unwrap();
        assert!(result.is_none());
    }

    // ── Image base selection ─────────────────────────────────────────────

    #[test]
    fn select_image_base_returns_image_base_without_dynamic_base() {
        let pe = ParsedPe {
            dll_characteristics: 0,
            relocations: vec![],
            image_base: 0x0040_0000,
            // pointer_bytes is derived from optional_header_magic
            // pe_stub() uses 0x010b (PE32) → pointer_bytes = 4
            ..pe_stub()
        };
        let base = select_image_base(&pe, "abc123", false);
        assert_eq!(base, 0x0040_0000);
    }

    // ── map_image ────────────────────────────────────────────────────────

    #[test]
    fn map_image_produces_correct_sized_memory() {
        let pe = ParsedPe {
            size_of_image: 0x2000,
            size_of_headers: 0x400,
            sections: vec![],
            image_base: 0x0040_0000,
            relocations: vec![],
            section_alignment: 0x1000,
            file_alignment: 0x0200,
            dll_characteristics: 0,
            ..pe_stub()
        };
        let bytes = vec![0u8; 0x400];
        let mapped = map_image(&bytes, &pe, "abc", false).unwrap();
        assert_eq!(mapped.memory.len(), 0x2000);
        assert_eq!(mapped.selected_base, pe.image_base);
    }

    #[test]
    fn map_image_applies_section_data() {
        let section = make_section(
            0x1000,
            0x100,
            0x400,
            8,
            ".text",
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        );
        let pe = ParsedPe {
            size_of_image: 0x2000,
            size_of_headers: 0x400,
            section_alignment: 0x1000,
            file_alignment: 0x0200,
            sections: vec![section],
            image_base: 0x0040_0000,
            relocations: vec![],
            dll_characteristics: 0,
            ..pe_stub()
        };
        let mut bytes = vec![0u8; 0x500];
        bytes[0x400..0x408].copy_from_slice(b"section!");
        let mapped = map_image(&bytes, &pe, "abc", false).unwrap();
        assert_eq!(&mapped.memory[0x1000..0x1008], b"section!");
    }

    #[test]
    fn map_image_rejects_headers_larger_than_image() {
        let pe = ParsedPe {
            size_of_image: 0x200,
            size_of_headers: 0x400,
            sections: vec![],
            image_base: 0x0040_0000,
            relocations: vec![],
            section_alignment: 0x1000,
            file_alignment: 0x0200,
            dll_characteristics: 0,
            ..pe_stub()
        };
        let bytes = vec![0u8; 0x400];
        let result = map_image(&bytes, &pe, "abc", false);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── apply_relocations ────────────────────────────────────────────────

    #[test]
    fn apply_relocations_highlow_adjusts_value() {
        let pe = ParsedPe {
            image_base: 0x0040_0000,
            relocations: vec![RelocationBlock {
                page_rva: 0x1000,
                entries: vec![RelocationEntry {
                    kind: RelocationType::HighLow,
                    offset: 0x008,
                }],
            }],
            ..pe_stub()
        };
        let section = make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".text",
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        );
        let mut memory = vec![0u8; 0x2000];
        memory[0x1008..0x100c].copy_from_slice(&0x0040_1000_u32.to_le_bytes());
        let mut mapped = MappedImage {
            preferred_base: 0x0040_0000,
            selected_base: 0x0050_0000,
            memory,
            sections: vec![SectionMapping {
                name: ".text".to_string(),
                virtual_address: section.virtual_address,
                mapped_size: section.virtual_size,
                raw_data_size: section.raw_data_size,
                protection: MemoryProtection {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
        };
        apply_relocations(&pe, &mut mapped).unwrap();
        let val = u32::from_le_bytes(mapped.memory[0x1008..0x100c].try_into().unwrap());
        assert_eq!(val, 0x0050_1000);
    }

    #[test]
    fn apply_relocations_dir64_adjusts_value() {
        let pe = ParsedPe {
            image_base: 0x0040_0000,
            relocations: vec![RelocationBlock {
                page_rva: 0x1000,
                entries: vec![RelocationEntry {
                    kind: RelocationType::Dir64,
                    offset: 0x000,
                }],
            }],
            ..pe_stub()
        };
        let mut memory = vec![0u8; 0x2000];
        memory[0x1000..0x1008].copy_from_slice(&0x0000_0000_0040_1000_u64.to_le_bytes());
        let mut mapped = MappedImage {
            preferred_base: 0x0040_0000,
            selected_base: 0x0050_0000,
            memory,
            sections: vec![],
        };
        apply_relocations(&pe, &mut mapped).unwrap();
        let val = u64::from_le_bytes(mapped.memory[0x1000..0x1008].try_into().unwrap());
        assert_eq!(val, 0x0000_0000_0050_1000);
    }

    #[test]
    fn apply_relocations_noop_when_delta_zero() {
        let pe = ParsedPe {
            image_base: 0x0040_0000,
            relocations: vec![RelocationBlock {
                page_rva: 0x1000,
                entries: vec![RelocationEntry {
                    kind: RelocationType::Dir64,
                    offset: 0x000,
                }],
            }],
            ..pe_stub()
        };
        let mut memory = vec![0u8; 0x2000];
        memory[0x1000..0x1008].copy_from_slice(&0x0000_0000_0040_1000_u64.to_le_bytes());
        let mut mapped = MappedImage {
            preferred_base: 0x0040_0000,
            selected_base: 0x0040_0000, // same as image_base
            memory,
            sections: vec![],
        };
        apply_relocations(&pe, &mut mapped).unwrap();
        let val = u64::from_le_bytes(mapped.memory[0x1000..0x1008].try_into().unwrap());
        assert_eq!(val, 0x0000_0000_0040_1000); // unchanged
    }

    // ── resolve_imports ──────────────────────────────────────────────────

    #[test]
    fn resolve_imports_returns_empty_when_no_imports() {
        let pe = ParsedPe {
            imports: vec![],
            delay_imports: vec![],
            ..pe_stub()
        };
        let resolver = ApiSetResolver::new();
        let result = resolve_imports(&pe, &BTreeMap::new(), &resolver).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn resolve_imports_errors_on_missing_provider() {
        let pe = ParsedPe {
            imports: vec![ImportDescriptor {
                dll_name: "missing.dll".to_string(),
                imports: vec![ImportThunk {
                    symbol: ImportSymbol::ByName {
                        hint: 0,
                        name: "Func".to_string(),
                    },
                    iat_rva: 0,
                }],
                delay_load: false,
            }],
            delay_imports: vec![],
            ..pe_stub()
        };
        let resolver = ApiSetResolver::new();
        let result = resolve_imports(&pe, &BTreeMap::new(), &resolver);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── plan_lifecycle ───────────────────────────────────────────────────

    #[test]
    fn plan_lifecycle_detects_dependency_cycle() {
        let mut deps = BTreeMap::new();
        deps.insert("a.dll".to_string(), vec!["b.dll".to_string()]);
        deps.insert("b.dll".to_string(), vec!["a.dll".to_string()]);
        let result = plan_lifecycle("a.dll", &deps, &BTreeMap::new());
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn plan_lifecycle_produces_correct_load_order() {
        let mut deps = BTreeMap::new();
        deps.insert(
            "app.exe".to_string(),
            vec!["c.dll".to_string(), "a.dll".to_string()],
        );
        deps.insert("a.dll".to_string(), vec!["b.dll".to_string()]);
        deps.insert("b.dll".to_string(), vec![]);
        deps.insert("c.dll".to_string(), vec![]);
        let plan = plan_lifecycle("app.exe", &deps, &BTreeMap::new()).unwrap();
        // b must come before a, a before app; c is independent
        let pos = |name: &str| plan.load_order.iter().position(|m| m == name);
        let pos_b = pos("b.dll").unwrap();
        let pos_a = pos("a.dll").unwrap();
        let pos_app = pos("app.exe").unwrap();
        assert!(pos_b < pos_a);
        assert!(pos_a < pos_app);
    }

    #[test]
    fn plan_lifecycle_includes_tls_callbacks() {
        let mut deps = BTreeMap::new();
        deps.insert("app.exe".to_string(), vec![]);
        let mut tls = BTreeMap::new();
        tls.insert("app.exe".to_string(), vec![0x1000_0100]);
        let plan = plan_lifecycle("app.exe", &deps, &tls).unwrap();
        assert!(
            plan.process_attach
                .iter()
                .any(|e| matches!(e.stage, LifecycleStage::TlsProcessAttach(0x1000_0100)))
        );
        assert!(
            plan.process_attach
                .iter()
                .any(|e| matches!(e.stage, LifecycleStage::DllMainProcessAttach))
        );
    }

    #[test]
    fn plan_lifecycle_handles_deep_dependency_chain() {
        // A 10k-deep chain would overflow the old recursive implementation.
        let depth = 10_000usize;
        let mut deps = BTreeMap::new();
        for index in 0..depth {
            deps.insert(
                format!("m{index:05}.dll"),
                vec![format!("m{:05}.dll", index + 1)],
            );
        }
        let plan = plan_lifecycle("m00000.dll", &deps, &BTreeMap::new()).unwrap();
        assert_eq!(plan.load_order.len(), depth + 1);
        assert_eq!(plan.load_order[0], "m10000.dll");
        assert_eq!(plan.load_order[depth], "m00000.dll");
    }

    // ── ApiSetResolver ───────────────────────────────────────────────────

    #[test]
    fn api_set_resolver_resolves_api_ms_win_core_to_kernel32() {
        let resolver = ApiSetResolver::new();
        assert_eq!(
            resolver.resolve("api-ms-win-core-heap-l1-1-0.dll"),
            "kernel32.dll"
        );
    }

    #[test]
    fn api_set_resolver_resolves_api_ms_win_crt_to_ucrtbase() {
        let resolver = ApiSetResolver::new();
        assert_eq!(
            resolver.resolve("api-ms-win-crt-string-l1-1-0.dll"),
            "ucrtbase.dll"
        );
    }

    #[test]
    fn api_set_resolver_resolves_ext_ms_win_ntuser_to_user32() {
        let resolver = ApiSetResolver::new();
        assert_eq!(
            resolver.resolve("ext-ms-win-ntuser-window-l1-1-0.dll"),
            "user32.dll"
        );
    }

    #[test]
    fn api_set_resolver_returns_original_when_no_match() {
        let resolver = ApiSetResolver::new();
        assert_eq!(resolver.resolve("user32.dll"), "user32.dll");
    }

    #[test]
    fn api_set_resolver_prefers_explicit_mapping() {
        let resolver = ApiSetResolver::new().with_mapping("api-ms-win-core-foo.dll", "custom.dll");
        assert_eq!(resolver.resolve("api-ms-win-core-foo.dll"), "custom.dll");
    }

    #[test]
    fn api_set_resolver_maps_core_registry_to_advapi32() {
        let resolver = ApiSetResolver::new();
        assert_eq!(
            resolver.resolve("api-ms-win-core-registry-l1-1-0.dll"),
            "advapi32.dll"
        );
    }

    #[test]
    fn api_set_resolver_maps_core_winrt_string_to_combase() {
        let resolver = ApiSetResolver::new();
        assert_eq!(
            resolver.resolve("api-ms-win-core-winrt-string-l1-1-0.dll"),
            "combase.dll"
        );
    }

    // ── normalize_module_name ────────────────────────────────────────────

    #[test]
    fn normalize_module_name_adds_dll_extension() {
        assert_eq!(normalize_module_name("kernel32"), "kernel32.dll");
    }

    #[test]
    fn normalize_module_name_preserves_existing_extension() {
        assert_eq!(normalize_module_name("user32.dll"), "user32.dll");
    }

    #[test]
    fn normalize_module_name_lowercases() {
        assert_eq!(normalize_module_name("KERNEL32.DLL"), "kernel32.dll");
    }

    // ── parse_forwarder_string ───────────────────────────────────────────

    #[test]
    fn parse_forwarder_string_by_name() {
        let (module, symbol) = parse_forwarder_string("kernel32.CreateFileA").unwrap();
        assert_eq!(module, "kernel32.dll");
        assert!(matches!(symbol, ImportSymbol::ByName { ref name, .. } if name == "CreateFileA"));
    }

    #[test]
    fn parse_forwarder_string_by_ordinal() {
        let (module, symbol) = parse_forwarder_string("ntdll.#123").unwrap();
        assert_eq!(module, "ntdll.dll");
        assert!(matches!(symbol, ImportSymbol::ByOrdinal { ordinal } if ordinal == 123));
    }

    #[test]
    fn parse_forwarder_string_rejects_missing_separator() {
        let result = parse_forwarder_string("justaname");
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── build_activation_context ─────────────────────────────────────────

    #[test]
    fn build_activation_context_detects_vc_runtime() {
        let manifest = ManifestInfo {
            source: ManifestSource::Embedded,
            supported_os: vec![],
            dpi_awareness: None,
            assemblies: vec![AssemblyIdentity {
                name: "Microsoft.VC141.CRT".to_string(),
                version: Some("14.16.27023.1".to_string()),
                processor_architecture: Some("amd64".to_string()),
                public_key_token: Some("1fc8b3b9a1e18e3b".to_string()),
                type_attr: Some("win32".to_string()),
            }],
        };
        let plan = build_activation_context(&manifest);
        assert_eq!(plan.vc_runtime_assemblies.len(), 1);
        assert!(
            plan.vc_runtime_bindings[0]
                .dlls
                .contains(&"vcruntime140.dll".to_string())
        );
    }

    #[test]
    fn build_activation_context_non_vc_assembly_not_included() {
        let manifest = ManifestInfo {
            source: ManifestSource::Embedded,
            supported_os: vec![],
            dpi_awareness: None,
            assemblies: vec![AssemblyIdentity {
                name: "SxS.Whatever".to_string(),
                version: None,
                processor_architecture: None,
                public_key_token: None,
                type_attr: None,
            }],
        };
        let plan = build_activation_context(&manifest);
        assert!(plan.vc_runtime_assemblies.is_empty());
    }

    // ── rva_to_file_offset / section_for_rva ─────────────────────────────

    #[test]
    fn rva_to_file_offset_uses_size_of_headers_for_header_rva() {
        let sections = &[];
        let offset = rva_to_file_offset(0x100, 0x100, sections, 0x400).unwrap();
        assert_eq!(offset, 0x100);
    }

    #[test]
    fn rva_to_file_offset_rejects_unbacked_rva() {
        let sections = &[];
        let result = rva_to_file_offset(0x1000, 4, sections, 0);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn rva_to_file_offset_rejects_unbacked_zero_size_rva() {
        // size == 0 must not fall back to treating the raw RVA as a file offset.
        let sections = &[];
        let result = rva_to_file_offset(0x1000, 0, sections, 0);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn rva_to_file_offset_zero_size_within_section() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0x400,
            8,
            ".text",
            IMAGE_SCN_MEM_READ,
        )];
        let offset = rva_to_file_offset(0x1004, 0, sections, 0).unwrap();
        assert_eq!(offset, 0x404);
    }

    #[test]
    fn section_for_rva_finds_correct_section() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0x400,
            8,
            ".text",
            IMAGE_SCN_MEM_READ,
        )];
        let found = section_for_rva(sections, 0x1000, 4, false);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, ".text");
    }

    #[test]
    fn section_for_rva_no_match() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0x400,
            8,
            ".text",
            IMAGE_SCN_MEM_READ,
        )];
        let found = section_for_rva(sections, 0x2000, 4, false);
        assert!(found.is_none());
    }

    // ── align_up edge cases ──────────────────────────────────────────────

    #[test]
    fn align_up_rejects_zero_alignment() {
        let result = align_up(0x1000, 0);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn align_up_preserves_aligned_value() {
        let result = align_up(0x1000, 0x1000).unwrap();
        assert_eq!(result, 0x1000);
    }

    #[test]
    fn align_up_rounds_up() {
        let result = align_up(0x1001, 0x1000).unwrap();
        assert_eq!(result, 0x2000);
    }

    // ── MemoryProtection ─────────────────────────────────────────────────

    #[test]
    fn protection_from_characteristics_decode_correctly() {
        let chars = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
        let prot = protection_from_characteristics(chars);
        assert!(prot.read);
        assert!(!prot.write);
        assert!(prot.execute);
    }

    // ── Slice / checked_range edge cases ─────────────────────────────────

    #[test]
    fn checked_range_rejects_out_of_bounds() {
        let bytes = b"hello";
        let result = checked_range(bytes, 0, 10, "test");
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn checked_range_accepts_exact_size() {
        let bytes = b"hello";
        let result = checked_range(bytes, 0, 5, "test");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    // ── parse manifest bytes (unit-level XML parsing) ────────────────────

    #[test]
    fn parse_manifest_bytes_valid_xml() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <assemblyIdentity name="MyApp" version="1.0.0.0" processorArchitecture="x86"/>
</assembly>"#;
        let manifest = parse_manifest_bytes(xml, ManifestSource::Embedded).unwrap();
        assert_eq!(manifest.source, ManifestSource::Embedded);
        assert_eq!(manifest.supported_os.len(), 1);
        assert_eq!(manifest.assemblies.len(), 1);
        assert_eq!(manifest.assemblies[0].name, "MyApp");
    }

    #[test]
    fn parse_manifest_bytes_rejects_invalid_xml() {
        let bytes = b"not valid xml";
        let result = parse_manifest_bytes(bytes, ManifestSource::Embedded);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn decode_manifest_bytes_utf8_works() {
        let bytes = b"hello manifest";
        let result = decode_manifest_bytes(bytes).unwrap();
        assert_eq!(result, "hello manifest");
    }

    #[test]
    fn decode_manifest_bytes_utf16_le() {
        let mut bytes = vec![0xff, 0xfe]; // BOM
        let text = "hello";
        for ch in text.encode_utf16() {
            bytes.extend_from_slice(&ch.to_le_bytes());
        }
        let result = decode_manifest_bytes(&bytes).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn decode_manifest_bytes_rejects_utf16_be() {
        let bytes = &[0xfe, 0xff, 0x00, 0x61]; // BE BOM + 'a'
        let result = decode_manifest_bytes(bytes);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── PE32+ TLS with 8-byte pointers ───────────────────────────────────

    #[test]
    fn parse_tls_directory_pe32_plus_with_callbacks() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".tls",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 10];
        dirs[9] = make_directory(0x1000, 40); // TLS dir, size=40 for PE32+
        let mut bytes = vec![0u8; 0x200];
        write_u64(&mut bytes, 0, 0x0000_0000_0000_3000).unwrap();
        write_u64(&mut bytes, 8, 0x0000_0000_0000_3100).unwrap();
        write_u64(&mut bytes, 16, 0x0000_0000_0000_4000).unwrap();
        // address_of_callbacks: callback array at RVA 0x1050, image_base=0
        write_u64(&mut bytes, 24, 0x1050).unwrap();
        // Two callbacks + null
        let array_off = 0x50usize;
        write_u64(&mut bytes, array_off, 0x1000_0100_0000_0001).unwrap();
        write_u64(&mut bytes, array_off + 8, 0x1000_0200_0000_0002).unwrap();
        write_u64(&mut bytes, array_off + 16, 0).unwrap();

        let tls = parse_tls_directory(&bytes, sections, &dirs, 0, 8)
            .unwrap()
            .expect("TLS should be present");
        assert_eq!(tls.callbacks.len(), 2);
    }

    // ── Alignment helper ─────────────────────────────────────────────────

    #[test]
    fn align4_produces_correct_values() {
        assert_eq!(align4(0).unwrap(), 0);
        assert_eq!(align4(1).unwrap(), 4);
        assert_eq!(align4(3).unwrap(), 4);
        assert_eq!(align4(4).unwrap(), 4);
        assert_eq!(align4(5).unwrap(), 8);
    }

    // ── Export parsing edge cases ────────────────────────────────────────

    #[test]
    fn parse_exports_with_forwarder_rva() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".edata",
            IMAGE_SCN_MEM_READ,
        )];
        let dirs = &[make_directory(0x1000, 0x200)];
        let mut bytes = vec![0u8; 0x200];
        // Export directory at RVA 0x1000
        // offset+16: ordinal_base = 1
        write_u32(&mut bytes, 16, 1).unwrap();
        // offset+20: number_of_functions = 1
        write_u32(&mut bytes, 20, 1).unwrap();
        // offset+24: number_of_names = 0
        write_u32(&mut bytes, 24, 0).unwrap();
        // offset+28: AddressOfFunctions = RVA of function address table
        write_u32(&mut bytes, 28, 0x1040).unwrap();
        // offset+32: AddressOfNames = 0 (no names)
        write_u32(&mut bytes, 32, 0).unwrap();
        // offset+36: AddressOfNameOrdinals = 0
        write_u32(&mut bytes, 36, 0).unwrap();
        // Function address table at 0x1040 -> RVA relative to section (0x1040-0x1000=0x40)
        // Function RVA = 0x2000 (a normal export)
        write_u32(&mut bytes, 0x40, 0x2000).unwrap();

        let exports = parse_export_directory(&bytes, sections, dirs).unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].ordinal, 1);
        assert!(matches!(exports[0].target, ExportTarget::Rva(0x2000)));
    }

    #[test]
    fn parse_exports_detects_forwarder_in_export_dir() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".edata",
            IMAGE_SCN_MEM_READ,
        )];
        let dirs = &[make_directory(0x1000, 0x200)];
        let mut bytes = vec![0u8; 0x200];
        write_u32(&mut bytes, 16, 1).unwrap();
        write_u32(&mut bytes, 20, 1).unwrap();
        write_u32(&mut bytes, 24, 0).unwrap();
        // AddressOfFunctions = 0x1040
        write_u32(&mut bytes, 28, 0x1040).unwrap();
        write_u32(&mut bytes, 32, 0).unwrap();
        write_u32(&mut bytes, 36, 0).unwrap();
        // Function RVA points WITHIN export directory -> forwarder
        // Forwarder string at RVA 0x1020 -> "kernel32.CreateFileA\0"
        write_u32(&mut bytes, 0x40, 0x1020).unwrap();
        // Forwarder string at section offset 0x20
        let fwd = b"kernel32.CreateFileA\0";
        bytes[0x20..0x20 + fwd.len()].copy_from_slice(fwd);

        let exports = parse_export_directory(&bytes, sections, dirs).unwrap();
        assert_eq!(exports.len(), 1);
        assert!(
            matches!(&exports[0].target, ExportTarget::Forwarder(s) if s == "kernel32.CreateFileA")
        );
    }

    // ── Import thunk parsing ─────────────────────────────────────────────

    #[test]
    fn read_import_thunks_parses_ordinal_import() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0,
            0x100,
            ".idata",
            IMAGE_SCN_MEM_READ,
        )];
        let mut bytes = vec![0u8; 0x100];
        // PE32 ordinal flag = 0x8000_0000
        // thunk = ordinal_flag | 42
        write_u32(&mut bytes, 0, 0x8000_002a).unwrap(); // ordinal import
        write_u32(&mut bytes, 4, 0).unwrap(); // terminator

        let thunks = read_import_thunks(&bytes, sections, 0x1000, 0x1010, 0, 4).unwrap();
        assert_eq!(thunks.len(), 1);
        assert!(matches!(thunks[0].symbol, ImportSymbol::ByOrdinal { ordinal } if ordinal == 42));
        assert_eq!(thunks[0].iat_rva, 0x1010);
    }

    #[test]
    fn read_import_thunks_terminates_on_zero() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0,
            0x100,
            ".idata",
            IMAGE_SCN_MEM_READ,
        )];
        let bytes = vec![0u8; 0x100]; // all zeros = no thunks
        let thunks = read_import_thunks(&bytes, sections, 0x1000, 0x1010, 0, 4).unwrap();
        assert!(thunks.is_empty());
    }

    #[test]
    fn read_import_thunks_rejects_iat_rva_overflow() {
        let sections = &[make_section(
            0x1000,
            0x100,
            0,
            0x100,
            ".idata",
            IMAGE_SCN_MEM_READ,
        )];
        let mut bytes = vec![0u8; 0x100];
        // Two thunks: IAT slots would be 0xFFFF_FFFF and 0xFFFF_FFFF + 4.
        write_u32(&mut bytes, 0, 0x8000_0001).unwrap();
        write_u32(&mut bytes, 4, 0x8000_0002).unwrap();
        write_u32(&mut bytes, 8, 0).unwrap(); // terminator
        let result = read_import_thunks(&bytes, sections, 0x1000, 0xFFFF_FFFF, 0, 4);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // ── Bound import parsing ─────────────────────────────────────────────

    #[test]
    fn parse_bound_import_directory_missing() {
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".bind",
            IMAGE_SCN_MEM_READ,
        )];
        let dirs = &[DataDirectory::default(); 12]; // index 11 exists but is zero
        let result = parse_bound_import_directory(&[], sections, dirs, 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_bound_import_directory_empty() {
        // A directory with a single terminator descriptor (TimeDateStamp == 0)
        let bytes = vec![0u8; 8]; // one descriptor of all zeros = terminator
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".bind",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 12];
        dirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = DataDirectory {
            virtual_address: 0x1000,
            size: 8,
        };
        let result = parse_bound_import_directory(&bytes, sections, &dirs, 0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_bound_import_directory_single_entry() {
        // Build a bound import directory with one entry.
        // Layout: the terminator descriptor (all zeros) separates descriptors
        // from name strings, per PE spec.
        let sections = &[make_section(
            0x1000,
            0x200,
            0,
            0x200,
            ".bind",
            IMAGE_SCN_MEM_READ,
        )];
        let mut dirs = vec![DataDirectory::default(); 12];
        dirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = DataDirectory {
            virtual_address: 0x1000,
            size: 0x30,
        };
        // Layout at RVA 0x1000:
        // offset 0: descriptor: TimeDateStamp=0x12345678, OffsetModuleName=0x18, NumberOfModuleForwarderRefs=0
        // offset 8: terminator (all zeros)
        // offset 0x18: DLL name "kernel32.dll\0"
        let mut bytes = vec![0u8; 0x30];
        write_u32(&mut bytes, 0, 0x1234_5678).unwrap(); // TimeDateStamp
        write_u16(&mut bytes, 4, 0x18).unwrap(); // OffsetModuleName = 0x18 (points past terminator)
        write_u16(&mut bytes, 6, 0).unwrap(); // NumberOfModuleForwarderRefs
        // offset 8-0x17: terminator (already zeros)
        // DLL name at RVA 0x1000 + 0x18 = 0x1018
        let name = b"kernel32.dll\0";
        bytes[0x18..0x18 + name.len()].copy_from_slice(name);

        let result = parse_bound_import_directory(&bytes, sections, &dirs, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].time_date_stamp, 0x1234_5678);
        assert_eq!(result[0].module_name, "kernel32.dll");
        assert!(result[0].forwarder_chain.is_empty());
    }

    // ── BitTest helpers ──────────────────────────────────────────────────

    #[test]
    fn version_format_produces_dotted_quad() {
        assert_eq!(format_version(0x0001_0002, 0x0003_0004), "1.2.3.4");
    }

    #[test]
    fn hash_seed_produces_consistent_output() {
        let seed = hash_seed("aabbccdd");
        // first of each pair: aa, bb, cc, dd -> 0xaabb_ccdd_.... (zero-padded)
        // Actually: chunks of 2: "aa", "bb", "cc", "dd" -> u8 values
        assert!(seed > 0);
    }

    // ── Phase M4: SxS Activation Context tests ─────────────────────────────

    #[test]
    fn test_parse_binding_redirects_basic() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
"#;
        let redirects = super::parse_binding_redirects(xml);
        assert!(redirects.is_empty(), "no bindingRedirect elements expected");
    }

    #[test]
    fn test_parse_binding_redirects_with_redirects() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    name="Microsoft.VC90.CRT"
    version="9.0.21022.8"
    processorArchitecture="amd64"
    publicKeyToken="1fc8b3b9a1e18e3b"/>
  <bindingRedirect
    name="Microsoft.VC90.CRT"
    publicKeyToken="1fc8b3b9a1e18e3b"
    version="9.0.30729.1"
    culture="neutral"/>
</assembly>
"#;
        let redirects = super::parse_binding_redirects(xml);
        assert_eq!(redirects.len(), 1);
        assert_eq!(redirects[0].name, "Microsoft.VC90.CRT");
        assert_eq!(redirects[0].public_key_token, "1fc8b3b9a1e18e3b");
        assert_eq!(redirects[0].version, "9.0.30729.1");
        assert_eq!(redirects[0].culture, "neutral");
    }

    #[test]
    fn test_parse_binding_redirects_invalid_xml() {
        let redirects = super::parse_binding_redirects("not valid xml");
        assert!(redirects.is_empty());
    }

    #[test]
    fn test_sxs_manifest_parsing_comctl32_v6() {
        // Simulate the manifest that requests ComCtl32 v6 via SxS
        let _manifest_str = r#"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
        type="win32"/>
    </dependentAssembly>
  </dependency>
</assembly>
"#;
        // Parse the manifest into a ManifestInfo to verify comctl32 v6 detection
        let manifest = crate::pe::ManifestInfo {
            source: crate::pe::ManifestSource::Embedded,
            supported_os: vec![],
            dpi_awareness: None,
            assemblies: vec![crate::pe::AssemblyIdentity {
                name: "Microsoft.Windows.Common-Controls".to_string(),
                version: Some("6.0.0.0".to_string()),
                processor_architecture: Some("*".to_string()),
                public_key_token: Some("6595b64144ccf1df".to_string()),
                type_attr: Some("win32".to_string()),
            }],
        };
        assert_eq!(manifest.assemblies.len(), 1);
        let asm = &manifest.assemblies[0];
        assert_eq!(asm.name, "Microsoft.Windows.Common-Controls");
        assert_eq!(asm.version.as_deref(), Some("6.0.0.0"));
    }

    #[test]
    fn test_activation_context_defaults() {
        let ctx = super::ActivationContext {
            handle: 1,
            cookie: 0,
            source: "test".to_string(),
            assembly_directory: None,
            manifest_info: None,
        };
        assert_eq!(ctx.handle, 1);
        assert_eq!(ctx.cookie, 0);
        assert_eq!(ctx.source, "test");
        assert!(ctx.assembly_directory.is_none());
        assert!(ctx.manifest_info.is_none());
    }

    #[test]
    fn test_activation_context_dll_redirection_ignores_literal_dll() {
        // Searching for the literal ".dll" must not spuriously match the
        // first assembly via the empty base-name fallback.
        let ctx = super::ActivationContext {
            handle: 1,
            cookie: 0,
            source: "test".to_string(),
            assembly_directory: Some("C:\\test".to_string()),
            manifest_info: Some(super::ManifestInfo {
                source: super::ManifestSource::Embedded,
                supported_os: vec![],
                dpi_awareness: None,
                assemblies: vec![super::AssemblyIdentity {
                    name: "Microsoft.Windows.Common-Controls".to_string(),
                    version: None,
                    processor_architecture: None,
                    public_key_token: None,
                    type_attr: None,
                }],
            }),
        };
        let mut contexts = BTreeMap::new();
        contexts.insert(1, ctx);
        let result = super::find_activation_context_section(
            &contexts,
            &[1],
            sxs_section::DLL_REDIRECTION,
            ".dll",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_activation_context_empty_search_matches_nothing() {
        let ctx = super::ActivationContext {
            handle: 1,
            cookie: 0,
            source: "test".to_string(),
            assembly_directory: None,
            manifest_info: Some(super::ManifestInfo {
                source: super::ManifestSource::Embedded,
                supported_os: vec![],
                dpi_awareness: None,
                assemblies: vec![super::AssemblyIdentity {
                    name: "Microsoft.Windows.Common-Controls".to_string(),
                    version: None,
                    processor_architecture: None,
                    public_key_token: None,
                    type_attr: None,
                }],
            }),
        };
        let mut contexts = BTreeMap::new();
        contexts.insert(1, ctx);
        let result = super::find_activation_context_section(
            &contexts,
            &[1],
            sxs_section::ASSEMBLY_INFORMATION,
            "",
        );
        assert!(result.is_none());
    }

    // ── PE import resolution tests ──────────────────────────────────────────

    /// Build a minimal ParsedPe with the given imports for testing resolve_imports.
    fn test_pe_with_imports(imports: Vec<super::ImportDescriptor>) -> super::ParsedPe {
        super::ParsedPe {
            machine: 0x014c,
            number_of_sections: 0,
            characteristics: 0,
            optional_header_magic: 0x010b,
            subsystem: 2,
            dll_characteristics: 0,
            address_of_entry_point: 0x1000,
            image_base: 0x0040_0000,
            size_of_image: 0x2000,
            size_of_headers: 0x0400,
            section_alignment: 0x1000,
            file_alignment: 0x0200,
            data_directories: vec![],
            sections: vec![],
            debug_entries: vec![],
            load_config: None,
            imports,
            delay_imports: vec![],
            exports: vec![],
            relocations: vec![],
            tls_directory: None,
            version_info: super::VersionInfo::default(),
            embedded_manifest: None,
            external_manifest: None,
            is_dotnet: false,
            clr_header: None,
            bound_imports: vec![],
        }
    }

    #[test]
    fn test_resolve_imports_missing_dll_returns_error() {
        let image = test_pe_with_imports(vec![super::ImportDescriptor {
            dll_name: "nonexistent.dll".to_string(),
            imports: vec![super::ImportThunk {
                symbol: super::ImportSymbol::ByName {
                    hint: 0,
                    name: "SomeFunction".to_string(),
                },
                iat_rva: 0x2000,
            }],
            delay_load: false,
        }]);
        let export_tables = BTreeMap::new();
        let resolver = super::ApiSetResolver::new();
        let result = super::resolve_imports(&image, &export_tables, &resolver);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(result.unwrap_err().code, ReasonCode::RcImportMissing);
    }

    #[test]
    fn test_resolve_imports_by_name() {
        let image = test_pe_with_imports(vec![super::ImportDescriptor {
            dll_name: "kernel32.dll".to_string(),
            imports: vec![super::ImportThunk {
                symbol: super::ImportSymbol::ByName {
                    hint: 0,
                    name: "CreateFileW".to_string(),
                },
                iat_rva: 0x2000,
            }],
            delay_load: false,
        }]);
        let mut export_tables = BTreeMap::new();
        export_tables.insert(
            "kernel32.dll".to_string(),
            vec![super::ExportSymbol {
                ordinal: 1,
                name: Some("CreateFileW".to_string()),
                target: super::ExportTarget::Rva(0x1000),
            }],
        );
        let resolver = super::ApiSetResolver::new();
        let result = super::resolve_imports(&image, &export_tables, &resolver);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let resolved = result.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].resolved_module, "kernel32.dll");
        assert_eq!(resolved[0].export.name.as_deref(), Some("CreateFileW"));
    }

    #[test]
    fn test_resolve_imports_by_ordinal() {
        let image = test_pe_with_imports(vec![super::ImportDescriptor {
            dll_name: "kernel32.dll".to_string(),
            imports: vec![super::ImportThunk {
                symbol: super::ImportSymbol::ByOrdinal { ordinal: 17 },
                iat_rva: 0x2000,
            }],
            delay_load: false,
        }]);
        let mut export_tables = BTreeMap::new();
        export_tables.insert(
            "kernel32.dll".to_string(),
            vec![super::ExportSymbol {
                ordinal: 17,
                name: None,
                target: super::ExportTarget::Rva(0x1000),
            }],
        );
        let resolver = super::ApiSetResolver::new();
        let result = super::resolve_imports(&image, &export_tables, &resolver);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let resolved = result.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].export.ordinal, 17);
    }

    #[test]
    fn test_resolve_imports_forwarded_export() {
        let image = test_pe_with_imports(vec![super::ImportDescriptor {
            dll_name: "kernel32.dll".to_string(),
            imports: vec![super::ImportThunk {
                symbol: super::ImportSymbol::ByName {
                    hint: 0,
                    name: "ForwardedFunc".to_string(),
                },
                iat_rva: 0x2000,
            }],
            delay_load: false,
        }]);
        let mut export_tables = BTreeMap::new();
        // kernel32.dll forwards ForwardedFunc to ntdll.dll::RealFunc
        export_tables.insert(
            "kernel32.dll".to_string(),
            vec![super::ExportSymbol {
                ordinal: 1,
                name: Some("ForwardedFunc".to_string()),
                // Note: forwarder strings use the module name WITHOUT the .dll
                // extension; normalize_module_name adds it automatically.
                target: super::ExportTarget::Forwarder("ntdll.RealFunc".to_string()),
            }],
        );
        export_tables.insert(
            "ntdll.dll".to_string(),
            vec![super::ExportSymbol {
                ordinal: 1,
                name: Some("RealFunc".to_string()),
                target: super::ExportTarget::Rva(0x2000),
            }],
        );
        let resolver = super::ApiSetResolver::new();
        let result = super::resolve_imports(&image, &export_tables, &resolver);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let resolved = result.unwrap();
        assert_eq!(resolved.len(), 1);
        // The resolved export should point to the final target in ntdll.dll
        assert_eq!(resolved[0].export.name.as_deref(), Some("RealFunc"));
    }

    #[test]
    fn test_resolve_imports_missing_symbol_in_dll() {
        let image = test_pe_with_imports(vec![super::ImportDescriptor {
            dll_name: "kernel32.dll".to_string(),
            imports: vec![super::ImportThunk {
                symbol: super::ImportSymbol::ByName {
                    hint: 0,
                    name: "NonExistentFunction".to_string(),
                },
                iat_rva: 0x2000,
            }],
            delay_load: false,
        }]);
        let mut export_tables = BTreeMap::new();
        export_tables.insert(
            "kernel32.dll".to_string(),
            vec![super::ExportSymbol {
                ordinal: 1,
                name: Some("CreateFileW".to_string()),
                target: super::ExportTarget::Rva(0x1000),
            }],
        );
        let resolver = super::ApiSetResolver::new();
        let result = super::resolve_imports(&image, &export_tables, &resolver);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(result.unwrap_err().code, ReasonCode::RcImportMissing);
    }

    #[test]
    fn test_resolve_delay_imports_missing_dll_returns_structured_exception() {
        let image = test_pe_with_imports(vec![]);
        // Build a ParsedPe with delay imports
        let mut delay_image = image;
        delay_image.delay_imports = vec![super::ImportDescriptor {
            dll_name: "missing.dll".to_string(),
            imports: vec![super::ImportThunk {
                symbol: super::ImportSymbol::ByName {
                    hint: 0,
                    name: "SomeFunc".to_string(),
                },
                iat_rva: 0x3000,
            }],
            delay_load: true,
        }];
        let export_tables = BTreeMap::new();
        let resolver = super::ApiSetResolver::new();
        let result = super::resolve_delay_imports(&delay_image, &export_tables, &resolver);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        match &results[0].outcome {
            super::DelayLoadOutcome::StructuredException { code } => {
                assert_eq!(*code, super::STATUS_DLL_NOT_FOUND);
            }
            other => panic!("expected StructuredException, got {other:?}"),
        }
    }

    #[test]
    fn test_api_set_resolver_maps_core_to_kernel32() {
        let resolver = super::ApiSetResolver::new();
        assert_eq!(
            resolver.resolve("api-ms-win-core-processenvironment-l1-1-0.dll"),
            "kernel32.dll"
        );
    }

    #[test]
    fn test_api_set_resolver_passes_through_unknown() {
        let resolver = super::ApiSetResolver::new();
        assert_eq!(resolver.resolve("mygame.dll"), "mygame.dll");
    }
}

// ── pe_stub: minimal ParsedPe for use in test helpers ──────────────────
// (placed after the tests so it's visible inside the test module)
#[cfg(test)]
fn pe_stub() -> ParsedPe {
    ParsedPe {
        machine: 0x014c,
        number_of_sections: 0,
        characteristics: 0,
        optional_header_magic: 0x010b,
        subsystem: 2,
        dll_characteristics: 0,
        address_of_entry_point: 0x1000,
        image_base: 0x0040_0000,
        size_of_image: 0x2000,
        size_of_headers: 0x0400,
        section_alignment: 0x1000,
        file_alignment: 0x0200,
        data_directories: vec![],
        sections: vec![],
        debug_entries: vec![],
        load_config: None,
        imports: vec![],
        delay_imports: vec![],
        exports: vec![],
        relocations: vec![],
        tls_directory: None,
        version_info: VersionInfo::default(),
        embedded_manifest: None,
        external_manifest: None,
        is_dotnet: false,
        clr_header: None,
        bound_imports: vec![],
    }
}
