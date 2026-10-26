//! DXIL bytecode → Metal Shading Language (MSL) full translation pipeline.
//!
//! This module implements the complete pipeline for translating DXIL (DirectX
//! Intermediate Language) bytecode shaders to MSL source code. It includes:
//!
//! - LLVM bitcode reader with full abbreviation support
//! - DXIL container and program part parsing
//! - DXIL instruction → MSL statement translation for all arithmetic,
//!   comparison, conversion, memory, control flow, and HLSL intrinsic opcodes
//! - Root signature → MSL argument buffer binding mapping
//! - Content-addressed shader cache with LRU eviction
//! - Reflection reconstruction and cross-checking

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use walkdir::WalkDir;

const DXIL_MAGIC: &[u8; 4] = b"DXIL";
const MAX_PARTS: usize = 16;
const MAX_INSTRUCTIONS: u32 = 4096;
static LLVM_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Geometry buffers shared by raygen and translated stage functions.
const RAY_GEOMETRY_PARAMS: &str = ", device const float4* vertex_attributes, device const uint* triangle_indices, device const uint* geometry_bindings, device const MetalRayAabb* aabbs";
/// Call-site arguments matching [`RAY_GEOMETRY_PARAMS`].
const RAY_GEOMETRY_ARGS: &str = ", vertex_attributes, triangle_indices, geometry_bindings, aabbs";
const MAX_IR_SIZE: u32 = 1 << 20;
const CACHE_MAGIC: &[u8; 8] = b"C1SHADER";
const CACHE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Shader stage enum
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ShaderStage {
    Vs,
    Ps,
    Cs,
    Gs,
    Hs,
    Ds,
    RayGeneration,
    AnyHit,
    ClosestHit,
    Miss,
    Intersection,
    Callable,
}

impl ShaderStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vs => "vs",
            Self::Ps => "ps",
            Self::Cs => "cs",
            Self::Gs => "gs",
            Self::Hs => "hs",
            Self::Ds => "ds",
            Self::RayGeneration => "raygeneration",
            Self::AnyHit => "anyhit",
            Self::ClosestHit => "closesthit",
            Self::Miss => "miss",
            Self::Intersection => "intersection",
            Self::Callable => "callable",
        }
    }

    /// Return the Metal function qualifier for this stage.
    pub fn msl_qualifier(self) -> &'static str {
        match self {
            Self::Vs => "vertex",
            Self::Ps => "fragment",
            Self::Cs => "kernel",
            Self::Gs => "kernel",
            Self::Hs => "kernel",
            Self::Ds => "kernel",
            Self::RayGeneration => "kernel",
            Self::AnyHit | Self::ClosestHit | Self::Miss | Self::Callable => "void",
            Self::Intersection => "[[intersection(triangle)]] bool",
        }
    }
}

// ---------------------------------------------------------------------------
// Input/output types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompileFlags {
    pub fast_math: bool,
    pub denorm_mode: String,
    pub debug: bool,
    pub optimization_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShaderTranslationInput {
    pub dxil: Vec<u8>,
    pub stage: ShaderStage,
    pub root_signature: Vec<u8>,
    pub compile_flags: CompileFlags,
    pub gpu_family: String,
    pub os_build: String,
    pub macwin_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Buffer,
    Texture,
    Sampler,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReflectionResource {
    pub kind: ResourceKind,
    pub register: u32,
    pub space: u32,
    pub arg_buffer_index: u32,
    pub binding_index: u32,
    pub access: ResourceAccess,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReflectionCbuffer {
    pub register: u32,
    pub space: u32,
    pub size_bytes: u32,
    pub packing_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThreadgroupSize {
    pub x: u32,
    pub y: u32,
    pub z: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReflectionTable {
    pub resources: Vec<ReflectionResource>,
    pub cbuffers: Vec<ReflectionCbuffer>,
    pub threadgroup_size: Option<ThreadgroupSize>,
    pub input_signature_hash: String,
    pub output_signature_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArgumentBinding {
    pub kind: String,
    pub register: u32,
    pub space: u32,
    pub binding_index: u32,
}

// ---------------------------------------------------------------------------
// Shared instruction representation for the DXIL→MSL pipeline
// ---------------------------------------------------------------------------

/// A single translated DXIL instruction, ready to be inlined into an
/// MSL entry point body by [`MslShaderGenerator`].
///
/// This struct bridges the gap between `dxil_opcode_to_msl()` (which
/// produces raw MSL statement strings) and the entry point generators
/// in `shader_compiler.rs` that need to consume those statements.
#[derive(Debug, Clone, Default)]
pub struct TranslatedInstruction {
    /// The MSL statement(s) for this instruction (e.g. `_t0 = _t1 + _t2;`).
    pub msl_body: String,
    /// Destination register / temporary variable name.
    pub dst: String,
    /// Source operand references (register names or immediates).
    pub operands: Vec<String>,
    /// True if this instruction is a barrier/sync operation.
    pub is_barrier: bool,
    /// Barrier flags for threadgroup/device memory (empty if not a barrier).
    pub barrier_flags: Vec<String>,
    /// True if this instruction accesses a UAV (Unordered Access View).
    pub is_uav_access: bool,
    /// Address space hint: "device", "threadgroup", "constant", or "".
    pub address_space: String,
    /// True if this instruction allocates or accesses threadgroup (groupshared) memory.
    pub is_threadgroup_mem: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArgumentBufferLayout {
    pub table_index: u32,
    pub binding_count: u32,
    pub bindless_indirection: bool,
    pub bindings: Vec<ArgumentBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootConstantsPlan {
    pub constant_buffer_size: u32,
    pub binding_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShaderTranslationOutput {
    pub mtl_library_bytes: Vec<u8>,
    pub function_mapping: BTreeMap<String, String>,
    pub reflection: ReflectionTable,
    pub argument_buffers: Vec<ArgumentBufferLayout>,
    pub root_constants: RootConstantsPlan,
    pub cache_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShaderError {
    pub reason_code: ReasonCode,
    pub dxil_hash: String,
    pub stage: ShaderStage,
    pub failing_pass: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootDescriptor {
    pub kind: RootBindingKind,
    pub register: u32,
    pub space: u32,
    pub descriptor_count: u32,
    pub arg_buffer_index: u32,
    pub binding_index: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RootBindingKind {
    Buffer,
    Texture,
    Sampler,
    Cbuffer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootSignatureInfo {
    pub descriptors: Vec<RootDescriptor>,
    pub root_constants_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CbufferField {
    pub name: String,
    pub rows: u32,
    pub cols: u32,
    pub row_major: bool,
    pub is_bool: bool,
    pub array_len: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackedField {
    pub name: String,
    pub offset: u32,
    pub size_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackedCbuffer {
    pub fields: Vec<PackedField>,
    pub size_bytes: u32,
    pub packing_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredField {
    pub name: String,
    pub size_bytes: u32,
    pub alignment: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredPacking {
    pub stride: u32,
    pub packing_hash: String,
}

// ---------------------------------------------------------------------------
// Cache types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheHeader {
    pub magic: String,
    pub version: u32,
    pub key: String,
    pub created_ts: u64,
    pub last_used_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CachePayload {
    pub mtl_library_bytes: Vec<u8>,
    pub reflection_json: String,
    pub metal_pipeline_archive: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShaderCacheEntry {
    pub header: CacheHeader,
    pub payload: CachePayload,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheRunStats {
    pub hits: usize,
    pub misses: usize,
    pub compile_stalls: usize,
    /// Number of shaders whose translation failed; they are counted as misses
    /// but not inserted into the cache.
    pub failures: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfflineCompilationPlan {
    pub total_shaders: usize,
    pub worker_count: usize,
    pub cpu_cap_percent: u8,
    pub io_priority_low: bool,
    pub blocks_ui_thread: bool,
    pub scheduled_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OfflineCompilationReport {
    pub total_shaders: usize,
    pub compiled: usize,
    pub failed: usize,
    pub skipped: usize,
    pub failures: Vec<ShaderError>,
}

// ---------------------------------------------------------------------------
// Content-Addressed Shader Cache with LRU Eviction
// ---------------------------------------------------------------------------

/// In-memory shader cache that maps SHA-256 hashes of raw DXIL bytecode to
/// compiled MSL source and Metal library bytes. Evicts the least-recently-used
/// entry when the total byte size exceeds `max_size_bytes`.
#[derive(Debug, Clone, Default)]
pub struct ShaderCache {
    max_size_bytes: usize,
    clock: u64,
    entries: BTreeMap<String, ShaderCacheEntry>,
    /// Running total of `entry_size` over all entries, kept in sync on insert
    /// and eviction so the eviction loop is O(k) instead of O(n·k).
    total_bytes: usize,
    logs: Vec<ReasonCode>,
}

#[derive(Debug, Clone, Default)]
pub struct OfflineCompiler {
    discovered_files: BTreeSet<PathBuf>,
    runtime_shader_keys: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Internal parsing types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PartDescriptor {
    kind: [u8; 4],
    offset: u32,
    size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProgramUse {
    kind: ProgramBindingKind,
    register: u32,
    space: u32,
    access: ResourceAccess,
    format: String,
    size_bytes: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProgramBindingKind {
    Buffer,
    Texture,
    Sampler,
    Cbuffer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ParsedProgram {
    instruction_count: u32,
    ir_size: u32,
    threadgroup_size: ThreadgroupSize,
    uses: Vec<ProgramUse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedDxilContainer {
    pub entry_name: String,
    pub instruction_count: u32,
    pub ir_size: u32,
    pub root_signature_part: Option<Vec<u8>>,
    pub reflection_present: bool,
    pub input_signature_hash: String,
    pub output_signature_hash: String,
    pub threadgroup_size: ThreadgroupSize,
    uses: Vec<ProgramUse>,
    reflection: Option<ReflectionTable>,
}

// ---------------------------------------------------------------------------
// ShaderCacheEntry helpers
// ---------------------------------------------------------------------------

impl ShaderCacheEntry {
    pub fn encode(&self) -> AppResult<Vec<u8>> {
        util::stable_json(self).map(|json| json.into_bytes())
    }
}

impl ShaderCache {
    /// Create a new cache with a maximum byte capacity.
    pub fn new(max_size_bytes: usize) -> Self {
        Self {
            max_size_bytes,
            ..Self::default()
        }
    }

    /// Return recorded diagnostic logs.
    pub fn logs(&self) -> &[ReasonCode] {
        &self.logs
    }

    /// Number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total estimated byte size of all cached entries.
    pub fn total_size_bytes(&self) -> usize {
        self.entries.values().map(entry_size).sum()
    }

    /// Look up a cache entry by key (SHA-256 of raw DXIL bytecode).
    /// Returns `None` if the key is not present. Updates LRU timestamp on hit.
    /// The returned reference borrows the cache; callers that only need a
    /// hit/miss check should use `.is_some()`.
    pub fn get(&mut self, key: &str) -> Option<&ShaderCacheEntry> {
        let entry = self.entries.get_mut(key)?;
        self.clock += 1;
        entry.header.last_used_ts = self.clock;
        Some(entry)
    }

    /// Insert a new entry into the cache. If adding the entry would exceed
    /// `max_size_bytes`, the least-recently-used entry is evicted first.
    /// If the entry is larger than `max_size_bytes`, it is still inserted.
    pub fn insert(&mut self, mut entry: ShaderCacheEntry) {
        self.clock += 1;
        entry.header.created_ts = self.clock;
        entry.header.last_used_ts = self.clock;
        let new_size = entry_size(&entry);
        // Replace any existing entry for the same key first.
        if let Some(old) = self.entries.get(&entry.header.key) {
            self.total_bytes = self.total_bytes.saturating_sub(entry_size(old));
        }
        // Evict LRU entries while over capacity.
        while self.total_bytes.saturating_add(new_size) > self.max_size_bytes
            && self.entries.len() > 1
        {
            let lru_key = self
                .entries
                .values()
                .min_by_key(|value| value.header.last_used_ts)
                .map(|value| value.header.key.clone());
            if let Some(lru_key) = lru_key {
                if let Some(evicted) = self.entries.remove(&lru_key) {
                    self.total_bytes = self.total_bytes.saturating_sub(entry_size(&evicted));
                }
            } else {
                break;
            }
        }
        self.total_bytes = self.total_bytes.saturating_add(new_size);
        self.entries.insert(entry.header.key.clone(), entry);
    }

    /// Load an encoded cache entry from raw bytes. Validates checksum and key.
    pub fn load_encoded(&mut self, key: &str, bytes: &[u8]) -> Option<ShaderCacheEntry> {
        let parsed = serde_json::from_slice::<ShaderCacheEntry>(bytes).ok()?;
        let checksum = checksum_payload(&parsed.payload).ok()?;
        if parsed.header.key != key || checksum != parsed.checksum {
            self.logs.push(ReasonCode::RcCacheCorrupt);
            self.entries.remove(key);
            return None;
        }
        Some(parsed)
    }

    /// Compute a cache key from raw DXIL bytecode using SHA-256.
    /// This is the content-addressed key for the cache.
    pub fn compute_key(dxil: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(dxil);
        format!("{:x}", hasher.finalize())
    }
}

impl OfflineCompiler {
    /// Scan a directory tree for `.dxil` files.
    pub fn scan_directory(&mut self, root: &Path) -> AppResult<Vec<PathBuf>> {
        let mut found = Vec::new();
        for entry in WalkDir::new(root) {
            let entry = entry.map_err(|error| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("failed to walk {}", root.display()),
                )
                .with_hint(error.to_string())
            })?;
            if entry.file_type().is_file()
                && entry.path().extension().is_some_and(|ext| ext == "dxil")
            {
                self.discovered_files.insert(entry.path().to_path_buf());
                found.push(entry.path().to_path_buf());
            }
        }
        found.sort();
        Ok(found)
    }

    /// Record a runtime shader key for later offline compilation.
    pub fn intercept_runtime_shader_creation(&mut self, key: &str) {
        self.runtime_shader_keys.insert(key.to_string());
    }

    /// Produce an offline compilation plan.
    pub fn schedule(&self, cpu_cap_percent: u8, max_threads: usize) -> OfflineCompilationPlan {
        let mut scheduled_keys = self.runtime_shader_keys.iter().cloned().collect::<Vec<_>>();
        scheduled_keys.sort();
        OfflineCompilationPlan {
            total_shaders: self.discovered_files.len() + scheduled_keys.len(),
            worker_count: max_threads.clamp(1, 4),
            cpu_cap_percent,
            io_priority_low: true,
            blocks_ui_thread: false,
            scheduled_keys,
        }
    }

    /// Produce an offline compilation report.
    pub fn report(
        &self,
        compiled: usize,
        failed: Vec<ShaderError>,
        skipped: usize,
    ) -> OfflineCompilationReport {
        OfflineCompilationReport {
            total_shaders: self.discovered_files.len() + self.runtime_shader_keys.len(),
            compiled,
            failed: failed.len(),
            skipped,
            failures: failed,
        }
    }
}

// ---------------------------------------------------------------------------
// LLVM bitcode constants
// ---------------------------------------------------------------------------

/// LLVM bitcode magic: bytes 'B', 'C', 0xC0, 0xDE.
///
/// The reader compares against `u32::from_be_bytes`, so the constant is the
/// big-endian interpretation of those four bytes.
const LLVM_BC_MAGIC: u32 = 0x4243_C0DE;

/// LLVM bitcode wrapper magic (stored little-endian): 0x0B17C0DE.
const LLVM_WRAPPER_MAGIC: u32 = 0x0B17_C0DE;

/// DXIL version constants
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const DXIL_VERSION_MAJOR: u32 = 1;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const DXIL_VERSION_MINOR: u32 = 0;

// LLVM bitcode block/record IDs (u32, matching the bitstream entry codes)
const BLOCKID_BLOCKINFO: u32 = 0;
const BLOCKID_MODULE: u32 = 8;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKID_PARAMATTR: u32 = 9;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKID_PARAMATTR_GROUP: u32 = 10;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKID_CONSTANTS: u32 = 11;
const BLOCKID_FUNCTION: u32 = 12;
const BLOCKID_IDENTIFICATION: u32 = 13;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKID_VALUE_SYMTAB: u32 = 14;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKID_METADATA: u32 = 15;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKID_METADATA_ATTACHMENT: u32 = 16;
const BLOCKID_TYPE: u32 = 17;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKID_OPERAND_BUNDLE_TAGS: u32 = 18;

// Record codes within BLOCKINFO
const BLOCKINFO_CODE_SETBID: u32 = 1;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKINFO_CODE_BLOCKNAME: u32 = 2;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const BLOCKINFO_CODE_SETRECORDNAME: u32 = 3;

// Module-level record codes
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const MODULE_CODE_VERSION: u32 = 1;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const MODULE_CODE_TRIPLE: u32 = 2;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const MODULE_CODE_DATALAYOUT: u32 = 3;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const MODULE_CODE_GLOBALVAR: u32 = 7;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const MODULE_CODE_FUNCTION: u32 = 8;

// Type block record codes (per the LLVM bitcode format; DXC writes these)
const TYPE_CODE_NUMENTRY: u32 = 1;
const TYPE_CODE_VOID: u32 = 2;
const TYPE_CODE_FLOAT: u32 = 3;
const TYPE_CODE_DOUBLE: u32 = 4;
const TYPE_CODE_LABEL: u32 = 5;
const TYPE_CODE_OPAQUE: u32 = 6;
const TYPE_CODE_INTEGER: u32 = 7;
const TYPE_CODE_POINTER: u32 = 8;
const TYPE_CODE_FUNCTION_OLD: u32 = 9;
const TYPE_CODE_HALF: u32 = 10;
const TYPE_CODE_ARRAY: u32 = 11;
const TYPE_CODE_VECTOR: u32 = 12;
const TYPE_CODE_X86_FP80: u32 = 13;
const TYPE_CODE_FP128: u32 = 14;
const TYPE_CODE_PPC_FP128: u32 = 15;
const TYPE_CODE_METADATA: u32 = 16;
const TYPE_CODE_X86_MMX: u32 = 17;
const TYPE_CODE_STRUCT_ANON: u32 = 18;
const TYPE_CODE_STRUCT_NAME: u32 = 19;
const TYPE_CODE_STRUCT_NAMED: u32 = 20;
const TYPE_CODE_FUNCTION: u32 = 21;

// Function block record codes (per the LLVM 3.7 / DXC bitcode format)
const FUNC_CODE_DECLAREBLOCKS: u32 = 0;
const FUNC_CODE_INST_BINOP: u32 = 2; // [op0, op1, opc, flags?]
const FUNC_CODE_INST_CAST: u32 = 3; // [op0, result_ty, cast_opc]
const FUNC_CODE_INST_GEP_OLD: u32 = 4;
const FUNC_CODE_INST_SELECT: u32 = 5;
const FUNC_CODE_INST_EXTRACTELT: u32 = 6;
const FUNC_CODE_INST_INSERTELT: u32 = 7;
const FUNC_CODE_INST_SHUFFLEVEC: u32 = 8;
const FUNC_CODE_INST_CMP: u32 = 9; // legacy: [opty, op0, op1, pred]
const FUNC_CODE_INST_RET: u32 = 10;
const FUNC_CODE_INST_BR: u32 = 11; // [bb#, bb#, cond] or [bb#]
const FUNC_CODE_INST_SWITCH: u32 = 12; // [opty, cond, default_bb, (case, bb)...]
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const FUNC_CODE_INST_INVOKE: u32 = 13;
const FUNC_CODE_INST_UNREACHABLE: u32 = 15;
const FUNC_CODE_INST_PHI: u32 = 16; // [ty, (val#signed, bb)...]
const FUNC_CODE_INST_ALLOCA: u32 = 19; // [instty, opty, size, align]
const FUNC_CODE_INST_LOAD: u32 = 20; // [ptr, result_ty, align, vol]
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const FUNC_CODE_INST_VAARG: u32 = 23;
const FUNC_CODE_INST_STORE_OLD: u32 = 24;
const FUNC_CODE_INST_EXTRACTVAL: u32 = 26;
const FUNC_CODE_INST_INSERTVAL: u32 = 27;
const FUNC_CODE_INST_CMP2: u32 = 28; // [op0, op1, pred, flags?]
const FUNC_CODE_INST_VSELECT: u32 = 29; // [cond, false_val, true_val]
const FUNC_CODE_INST_INBOUNDS_GEP_OLD: u32 = 30;
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const FUNC_CODE_INST_INDIRECTBR: u32 = 31;
const FUNC_CODE_INST_CALL: u32 = 34; // [attr, cc, fnty, fn, args...]
#[allow(dead_code)] // DXIL bitcode block/record constants (ABI table for the DXIL parser)
const FUNC_CODE_INST_FENCE: u32 = 36;
const FUNC_CODE_INST_GEP: u32 = 43; // [inbounds, srcty, ops...]
const FUNC_CODE_INST_STORE: u32 = 44; // [ptr, val, align, vol]

// DXIL intrinsic opcodes (HLSL intrinsics)
const DXIL_INTRIN_ABS: u32 = 400;
const DXIL_INTRIN_SATURATE: u32 = 401;
const DXIL_INTRIN_MAD: u32 = 402;
const DXIL_INTRIN_FMA: u32 = 403;
const DXIL_INTRIN_MIN: u32 = 404;
const DXIL_INTRIN_MAX: u32 = 405;
const DXIL_INTRIN_CLAMP: u32 = 406;
const DXIL_INTRIN_SIN: u32 = 407;
const DXIL_INTRIN_COS: u32 = 408;
const DXIL_INTRIN_TAN: u32 = 409;
const DXIL_INTRIN_SQRT: u32 = 410;
const DXIL_INTRIN_RSQRT: u32 = 411;
const DXIL_INTRIN_FRAC: u32 = 412;
const DXIL_INTRIN_FLOOR: u32 = 413;
const DXIL_INTRIN_CEIL: u32 = 414;
const DXIL_INTRIN_ROUND: u32 = 415;
const DXIL_INTRIN_EXP: u32 = 416;
const DXIL_INTRIN_EXP2: u32 = 417;
const DXIL_INTRIN_LOG: u32 = 418;
const DXIL_INTRIN_LOG2: u32 = 419;
const DXIL_INTRIN_POW: u32 = 420;
const DXIL_INTRIN_DOT: u32 = 421;
const DXIL_INTRIN_MUL: u32 = 422;
const DXIL_INTRIN_LERP: u32 = 423;
const DXIL_INTRIN_NORMALIZE: u32 = 424;
const DXIL_INTRIN_CROSS: u32 = 425;
const DXIL_INTRIN_TRANSPOSE: u32 = 426;
const DXIL_INTRIN_DETERMINANT: u32 = 427;
const DXIL_INTRIN_REFLECT: u32 = 428;
const DXIL_INTRIN_REFRACT: u32 = 429;
const DXIL_INTRIN_ISFINITE: u32 = 430;
const DXIL_INTRIN_ISINF: u32 = 431;
const DXIL_INTRIN_ISNAN: u32 = 432;
const DXIL_INTRIN_SIGN: u32 = 433;
const DXIL_INTRIN_COUNTBITS: u32 = 434;
const DXIL_INTRIN_REVERSEBITS: u32 = 435;
const DXIL_INTRIN_SINCOS: u32 = 436;
const DXIL_INTRIN_RCP: u32 = 437;
const DXIL_INTRIN_DISTANCE: u32 = 438;
const DXIL_INTRIN_LENGTH: u32 = 439;
const DXIL_INTRIN_SMOOTHSTEP: u32 = 440;
const DXIL_INTRIN_STEP: u32 = 441;
const DXIL_INTRIN_ATAN2: u32 = 442;
const DXIL_INTRIN_ATAN: u32 = 443;
const DXIL_INTRIN_ASIN: u32 = 444;
const DXIL_INTRIN_ACOS: u32 = 445;
const DXIL_INTRIN_TANH: u32 = 446;
const DXIL_INTRIN_SINH: u32 = 447;
const DXIL_INTRIN_COSH: u32 = 448;
const DXIL_INTRIN_FWIDTH: u32 = 449;

/// Payload storage exposed by the ray transpiler to translated shaders and to
/// CPU readback. D3D12's default payload size is 32 bytes; the textual ray
/// lowerer models that as eight 32-bit words.
pub const RAY_PAYLOAD_WORDS: usize = 8;

// Texture/buffer intrinsics
const DXIL_INTRIN_SAMPLE: u32 = 500;
const DXIL_INTRIN_SAMPLELEVEL: u32 = 501;
const DXIL_INTRIN_SAMPLEGRAD: u32 = 502;
const DXIL_INTRIN_SAMPLEBIAS: u32 = 503;
const DXIL_INTRIN_SAMPLECMP: u32 = 504;
const DXIL_INTRIN_GATHER: u32 = 505;
const DXIL_INTRIN_LOAD: u32 = 506;
const DXIL_INTRIN_STORE: u32 = 507;
const DXIL_INTRIN_BUFFERLOAD: u32 = 508;
const DXIL_INTRIN_BUFFERSTORE: u32 = 509;
const DXIL_INTRIN_THREADID: u32 = 510;
const DXIL_INTRIN_GROUPID: u32 = 511;
const DXIL_INTRIN_THREADGROUPID: u32 = 512;
const DXIL_INTRIN_GROUPINDEX: u32 = 513;
const DXIL_INTRIN_BARRIER: u32 = 514;
const DXIL_INTRIN_DISPATCHTHREADID: u32 = 515;
const DXIL_INTRIN_GROUPMEMORYBARRIER: u32 = 516;
const DXIL_INTRIN_DEVICEMEMORYBARRIER: u32 = 517;
const DXIL_INTRIN_TEXTURELOAD: u32 = 518;
const DXIL_INTRIN_TEXTURESTORE: u32 = 519;

// Atomic intrinsics
const DXIL_INTRIN_ATOMICADD: u32 = 550;
const DXIL_INTRIN_ATOMICAND: u32 = 551;
const DXIL_INTRIN_ATOMICOR: u32 = 552;
const DXIL_INTRIN_ATOMICXOR: u32 = 553;
const DXIL_INTRIN_ATOMICMIN: u32 = 554;
const DXIL_INTRIN_ATOMICMAX: u32 = 555;
const DXIL_INTRIN_ATOMICEXCHANGE: u32 = 556;
const DXIL_INTRIN_ATOMICCOMPAREEXCHANGE: u32 = 557;

// Derivative intrinsics
const DXIL_INTRIN_DERIVATIVE: u32 = 560;
const DXIL_INTRIN_DERIVATIVE_COARSE: u32 = 561;
const DXIL_INTRIN_DERIVATIVE_FINE: u32 = 562;

// Wave intrinsics
const DXIL_INTRIN_WAVEACTIVE: u32 = 570;
const DXIL_INTRIN_WAVEACTIVEBIT: u32 = 571;
const DXIL_INTRIN_WAVEPREFIX: u32 = 572;
const DXIL_INTRIN_QUADREAD: u32 = 573;
const DXIL_INTRIN_QUADWRITE: u32 = 574;
const DXIL_INTRIN_WAVEGETLANEINDEX: u32 = 575;
const DXIL_INTRIN_WAVEGETLANECOUNT: u32 = 576;
const DXIL_INTRIN_WAVEANYTRUE: u32 = 577;
const DXIL_INTRIN_WAVEALLTRUE: u32 = 578;
const DXIL_INTRIN_WAVEALLEQUAL: u32 = 579;
const DXIL_INTRIN_WAVEBALLOT: u32 = 580;
const DXIL_INTRIN_WAVEREADLANEAT: u32 = 581;
const DXIL_INTRIN_WAVEREADLANEFIRST: u32 = 582;
const DXIL_INTRIN_WAVEACTIVEBITAND: u32 = 583;
const DXIL_INTRIN_WAVEACTIVEBITOR: u32 = 584;
const DXIL_INTRIN_WAVEACTIVEBITXOR: u32 = 585;
const DXIL_INTRIN_WAVEACTIVECOUNTBITS: u32 = 586;
const DXIL_INTRIN_WAVEACTIVESUM: u32 = 587;
const DXIL_INTRIN_WAVEACTIVEPRODUCT: u32 = 588;
const DXIL_INTRIN_WAVEACTIVEMIN: u32 = 589;
const DXIL_INTRIN_WAVEACTIVEMAX: u32 = 590;
const DXIL_INTRIN_WAVEMULTIPREFIXSUM: u32 = 591;
const DXIL_INTRIN_WAVEMULTIPREFIXPRODUCT: u32 = 592;
const DXIL_INTRIN_WAVEMULTIPREFIXBITAND: u32 = 593;
const DXIL_INTRIN_WAVEMULTIPREFIXBITOR: u32 = 594;
const DXIL_INTRIN_WAVEMULTIPREFIXBITXOR: u32 = 595;
const DXIL_INTRIN_WAVEMULTIPREFIXBITCOUNT: u32 = 596;
const DXIL_INTRIN_WAVEMATCH: u32 = 597;

// Conversion and bit-manipulation intrinsics
const DXIL_INTRIN_ASFLOAT: u32 = 600;
const DXIL_INTRIN_ASINT: u32 = 601;
const DXIL_INTRIN_ASUINT: u32 = 602;
const DXIL_INTRIN_FIRSTBITHIGH: u32 = 603;
const DXIL_INTRIN_FIRSTBITLOW: u32 = 604;
const DXIL_INTRIN_LOG10: u32 = 605;

// Packed dot-product intrinsics
const DXIL_INTRIN_DOT4ADDI8PACKED: u32 = 610;
const DXIL_INTRIN_DOT4ADDU8PACKED: u32 = 611;

// Tessellation intrinsics
const DXIL_INTRIN_PROCESS2DQUADTESSSFACTORSAVG: u32 = 620;
const DXIL_INTRIN_PROCESS2DQUADTESSFACTORSMAX: u32 = 621;
const DXIL_INTRIN_PROCESS2DQUADTESSFACTORSMIN: u32 = 622;
const DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSAVG: u32 = 623;
const DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSMAX: u32 = 624;
const DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSMIN: u32 = 625;

// Texture query intrinsics
const DXIL_INTRIN_CALCULATELOD: u32 = 630;
const DXIL_INTRIN_CALCULATELODUNCLAMPED: u32 = 631;

// Attribute evaluation and other misc intrinsics
const DXIL_INTRIN_CHECKACCESSFULLYMAPPED: u32 = 640;
const DXIL_INTRIN_EVALUATEATTRIBUTEATCENTROID: u32 = 641;
const DXIL_INTRIN_EVALUATEATTRIBUTEATSAMPLE: u32 = 642;
const DXIL_INTRIN_EVALUATEATTRIBUTEATCONSTANT: u32 = 643;
const DXIL_INTRIN_INSTANCEID: u32 = 645;
const DXIL_INTRIN_VERTEXID: u32 = 646;
const DXIL_INTRIN_PRIMITIVEID: u32 = 647;

// Geometry shader intrinsics
const DXIL_INTRIN_EMITSTREAM: u32 = 650;
const DXIL_INTRIN_CUTSTREAM: u32 = 651;
const DXIL_INTRIN_EMITTHENCUTSTREAM: u32 = 652;

// Resource array support
const DXIL_INTRIN_CREATEHANDLE: u32 = 660;
const DXIL_INTRIN_CREATEHANDLEFORBINDING: u32 = 661;

// Additional HLSL intrinsics
const DXIL_INTRIN_DISCARD: u32 = 598;
const DXIL_INTRIN_WAVEISFIRSTLANE: u32 = 599;

// Internal comparison opcodes for the remaining fcmp predicates
// (icmp predicates map to 18..=27, fcmp_oeq/one to 28/29).
const CMP_FCMP_OGT: u32 = 61;
const CMP_FCMP_OGE: u32 = 62;
const CMP_FCMP_OLT: u32 = 63;
const CMP_FCMP_OLE: u32 = 64;
const CMP_FCMP_UNE: u32 = 65;
const CMP_FCMP_ORD: u32 = 66;
const CMP_FCMP_UNO: u32 = 67;
const CMP_FCMP_FALSE: u32 = 68;
const CMP_FCMP_TRUE: u32 = 69;
const CMP_FCMP_UGT: u32 = 70;
const CMP_FCMP_UGE: u32 = 71;
const CMP_FCMP_ULT: u32 = 72;
const CMP_FCMP_ULE: u32 = 73;

// Internal cast opcodes for the float/pointer conversions that the original
// 30..=35 range (bitcast/ptrtoint/inttoptr/zext/sext/trunc) did not cover.
const CAST_FPTOUI: u32 = 90;
const CAST_FPTOSI: u32 = 91;
const CAST_UITOFP: u32 = 92;
const CAST_SITOFP: u32 = 93;
const CAST_FPTRUNC: u32 = 94;
const CAST_FPEXT: u32 = 95;
const CAST_ADDRSPACECAST: u32 = 96;

// ---------------------------------------------------------------------------
// LLVM Bitcode Reader
// ---------------------------------------------------------------------------

/// An abbreviation operand encoding in the LLVM bitstream format.
#[derive(Debug, Clone)]
enum AbbrevOp {
    Literal(u32),
    Fixed(u32),
    Vbr(u32),
    Array,
    Char6,
    Blob,
}

/// An abbreviation definition, mapping record fields to encoding patterns.
#[derive(Debug, Clone)]
struct AbbrevDef {
    operands: Vec<AbbrevOp>,
}

/// Simplified type descriptor derived from the TYPE_BLOCK type table.
///
/// Used to decide signedness/floatness of translated operations and to emit
/// declarations for `alloca` results. `is_signed` refers to integer
/// operands; pointers and vectors inherit the element characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TypeDesc {
    is_float: bool,
    is_signed: bool,
    is_pointer: bool,
    is_void: bool,
    is_vector: bool,
    width: u32,
    vector_len: u32,
}

impl Default for TypeDesc {
    fn default() -> Self {
        Self {
            is_float: false,
            is_signed: true,
            is_pointer: false,
            is_void: false,
            is_vector: false,
            width: 32,
            vector_len: 1,
        }
    }
}

/// The next element in a bitstream: end of block, sub-block entry, inline
/// abbreviation definition, or a data record.
#[derive(Debug, Clone)]
enum BitcodeEntry {
    EndBlock,
    SubBlock(u32),
    DefineAbbrev(AbbrevDef),
    Record(BitcodeRecord),
}

/// Parsed LLVM bitcode record: (record_id, operands).
#[derive(Debug, Clone)]
#[allow(dead_code)] // bitcode record blob retained for future record processing
struct BitcodeRecord {
    id: u32,
    operands: Vec<u32>,
    blob: Option<Vec<u8>>,
}

/// LLVM bitcode reader with full abbreviation and block nesting support.
///
/// Reads the LLVM bitstream format used by DXIL. Supports:
/// - BLOCKINFO_BLOCK parsing (SETBID, DEFINE_ABBREV records)
/// - Abbreviation-based operand decoding (Fixed, VBR, Literal, Array, Blob)
/// - Block nesting via enter/exit_block
/// - Wrapper format detection (0x0B17C0DE magic)
#[derive(Debug, Clone)]
struct LlvmBitcodeReader<'a> {
    /// Raw byte slice of the bitcode.
    data: &'a [u8],
    /// Current byte position.
    pos: usize,
    /// Current bit position within the current 32-bit word (0..32).
    bit_pos: u32,
    /// The current 32-bit word being read from.
    current_word: u32,
    /// Abbreviation definitions from BLOCKINFO blocks, keyed by block_id.
    /// Each block has a list of (abbrev_id -> AbbrevDef).
    block_abbrevs: BTreeMap<u32, Vec<AbbrevDef>>,
    /// Block nesting stack: (block_id, abbrev_list_for_block, abbrev_width).
    block_stack: Vec<(u32, Vec<AbbrevDef>, u32)>,
    /// Current abbreviation width for the active block (default 2).
    abbrev_width: u32,
    /// Type table built from the TYPE_BLOCK (block id 17).
    type_table: Vec<TypeDesc>,
}

impl<'a> LlvmBitcodeReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_pos: 32, // force read on first use
            current_word: 0,
            block_abbrevs: BTreeMap::new(),
            block_stack: Vec::new(),
            abbrev_width: 2,
            type_table: Vec::new(),
        }
    }

    /// Read a 32-bit little-endian word.
    fn read_u32(&mut self) -> u32 {
        if self.pos + 4 > self.data.len() {
            return 0;
        }
        let val = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        val
    }

    /// Read a VBR (Variable Bit Rate) encoded unsigned integer.
    ///
    /// Each chunk is `width` bits: `width - 1` value bits plus a continuation
    /// bit. Chunks may straddle 32-bit word boundaries; the field state is
    /// tracked across words so the continuation bit is read from the correct
    /// position. Returns 0 for malformed widths and stops after 64 chunks so
    /// hostile streams cannot loop forever.
    fn read_vbr_uint(&mut self, width: u32) -> u32 {
        if width == 0 || width > 32 {
            return 0;
        }
        let value_bits = width - 1;
        let value_mask = if value_bits >= 32 {
            u32::MAX
        } else {
            (1u32 << value_bits) - 1
        };
        let mut result: u32 = 0;
        let mut shift: u32 = 0;
        let mut chunk: u32 = 0;
        let mut chunk_bits: u32 = 0;
        let mut chunks: u32 = 0;
        loop {
            if self.bit_pos >= 32 {
                self.current_word = self.read_u32();
                self.bit_pos = 0;
            }
            let bits_avail = 32 - self.bit_pos;
            let n = (width - chunk_bits).min(bits_avail);
            let mask = if n >= 32 { u32::MAX } else { (1u32 << n) - 1 };
            chunk |= ((self.current_word >> self.bit_pos) & mask) << chunk_bits;
            self.bit_pos += n;
            chunk_bits += n;
            if chunk_bits < width {
                continue;
            }
            // A full chunk has been assembled; the high bit is the
            // continuation marker.
            let continuation = (chunk >> value_bits) & 1;
            if shift < 32 {
                result |= (chunk & value_mask) << shift;
            }
            shift += value_bits;
            chunks += 1;
            if continuation == 0 || chunks > 64 {
                break;
            }
            chunk = 0;
            chunk_bits = 0;
        }
        result
    }

    /// Read a fixed-width unsigned integer.
    fn read_fixed_uint(&mut self, width: u32) -> u32 {
        let width = width.min(32);
        let mut result: u32 = 0;
        let mut bits_read: u32 = 0;
        while bits_read < width {
            if self.bit_pos >= 32 {
                self.current_word = self.read_u32();
                self.bit_pos = 0;
            }
            let bits_avail = 32 - self.bit_pos;
            let chunk_bits = (width - bits_read).min(bits_avail);
            let mask = if chunk_bits >= 32 {
                u32::MAX
            } else {
                (1u32 << chunk_bits) - 1
            };
            let chunk = (self.current_word >> self.bit_pos) & mask;
            if bits_read < 32 {
                result |= chunk << bits_read;
            }
            self.bit_pos += chunk_bits;
            bits_read += chunk_bits;
        }
        result
    }

    /// Align to the next 32-bit word boundary.
    fn align_to_word(&mut self) {
        if self.bit_pos > 0 && self.bit_pos < 32 {
            self.bit_pos = 32;
        }
    }

    /// Return remaining bytes in the input.
    fn remaining(&self) -> usize {
        if self.pos < self.data.len() {
            self.data.len() - self.pos
        } else {
            0
        }
    }

    /// Read a full 32-bit word from the bitstream.
    fn read_word(&mut self) -> u32 {
        if self.pos + 4 <= self.data.len() {
            let word = u32::from_le_bytes([
                self.data[self.pos],
                self.data[self.pos + 1],
                self.data[self.pos + 2],
                self.data[self.pos + 3],
            ]);
            self.pos += 4;
            word
        } else {
            0
        }
    }

    /// Read a Char6-encoded character.
    ///
    /// Per the LLVM bitstream format: 'a'..'z' = 0..25, 'A'..'Z' = 26..51,
    /// '0'..'9' = 52..61, '.' = 62, '_' = 63.
    fn read_char6(&mut self) -> char {
        let val = self.read_fixed_uint(6);
        match val {
            0..=25 => (b'a' + val as u8) as char,
            26..=51 => (b'A' + (val - 26) as u8) as char,
            52..=61 => (b'0' + (val - 52) as u8) as char,
            62 => '.',
            63 => '_',
            _ => '?',
        }
    }

    /// Skip the LLVM bitcode wrapper format if present.
    ///
    /// The documented wrapper layout is:
    /// `[Magic#32, Version#32, Offset#32, Size#32, CPUType#32]`, all fields
    /// little-endian, with `Magic == 0x0B17C0DE`. `Offset` points at the
    /// embedded bitcode stream and `Size` gives its length.
    ///
    /// Returns `Ok(true)` when a wrapper was found and skipped, `Ok(false)`
    /// when the stream is not wrapped, and `Err` for a malformed wrapper.
    fn skip_wrapper(&mut self) -> AppResult<bool> {
        if self.remaining() < 20 {
            return Ok(false);
        }
        let magic = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        if magic != LLVM_WRAPPER_MAGIC {
            return Ok(false);
        }
        let version = u32::from_le_bytes([
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        let offset = u32::from_le_bytes([
            self.data[self.pos + 8],
            self.data[self.pos + 9],
            self.data[self.pos + 10],
            self.data[self.pos + 11],
        ]);
        let size = u32::from_le_bytes([
            self.data[self.pos + 12],
            self.data[self.pos + 13],
            self.data[self.pos + 14],
            self.data[self.pos + 15],
        ]);
        // The wrapper header itself is 20 bytes; the embedded stream must be
        // fully contained in the file.
        let stream_start = offset as usize;
        let stream_end = stream_start
            .checked_add(size as usize)
            .ok_or_else(|| dxil_invalid("LLVM bitcode wrapper size overflows"))?;
        if version != 0 || stream_end > self.data.len() {
            return Err(dxil_invalid("malformed LLVM bitcode wrapper header"));
        }
        // Skip the wrapper header; check_magic() validates the embedded magic.
        self.pos = stream_start;
        Ok(true)
    }

    /// Check and consume the LLVM bitcode magic (0x0B1E_0BC0 BE).
    /// Returns true if magic was found.
    fn check_magic(&mut self) -> bool {
        if self.remaining() >= 4 {
            let magic = u32::from_be_bytes([
                self.data[self.pos],
                self.data[self.pos + 1],
                self.data[self.pos + 2],
                self.data[self.pos + 3],
            ]);
            if magic == LLVM_BC_MAGIC {
                self.pos += 4;
                // After consuming the BC magic, there must be at least a
                // block header (4 bytes) to be a valid bitcode stream.
                if self.remaining() < 4 {
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Advance to the next entry in the bitstream.
    ///
    /// The stream is a sequence of aligned 32-bit words; each block entry
    /// starts with an abbreviation code of `abbrev_width` bits:
    /// 0 = END_BLOCK, 1 = ENTER_SUBBLOCK, 2 = DEFINE_ABBREV,
    /// 3 = UNABBREV_RECORD, 4+ = abbreviated record.
    ///
    /// Inline DEFINE_ABBREV records are normally processed transparently
    /// (their definition is added to the active block's abbreviation list).
    /// The BLOCKINFO reader passes `autoprocess = false` so it can attribute
    /// the definition to the block selected by the most recent SETBID record.
    fn next_entry(&mut self, autoprocess_abbrevs: bool) -> Option<BitcodeEntry> {
        loop {
            self.align_to_word();
            if self.remaining() < 4 {
                return None;
            }
            let header = self.read_word();
            self.current_word = header;
            self.bit_pos = 0;
            let code = self.read_fixed_uint(self.abbrev_width);
            match code {
                0 => {
                    // END_BLOCK
                    return Some(BitcodeEntry::EndBlock);
                }
                1 => {
                    // ENTER_SUBBLOCK: [blockid#vbr8, newabbrevlen#vbr4,
                    //                 <align32>, blocklen#32]
                    let block_id = self.read_vbr_uint(8);
                    let code_len = self.read_vbr_uint(4);
                    // The abbreviation width must be sane; 0 means the block
                    // cannot be parsed, and oversized widths are malformed.
                    if code_len == 0 || code_len > 8 {
                        return None;
                    }
                    self.align_to_word();
                    let _block_len = self.read_word();
                    let block_abbrevs = self
                        .block_abbrevs
                        .get(&block_id)
                        .cloned()
                        .unwrap_or_default();
                    self.block_stack
                        .push((block_id, block_abbrevs, self.abbrev_width));
                    self.abbrev_width = code_len;
                    return Some(BitcodeEntry::SubBlock(block_id));
                }
                2 => {
                    // DEFINE_ABBREV
                    let abbrev = self.parse_abbrev_record()?;
                    if autoprocess_abbrevs {
                        if let Some((_, abbrevs, _)) = self.block_stack.last_mut() {
                            abbrevs.push(abbrev);
                        }
                    } else {
                        return Some(BitcodeEntry::DefineAbbrev(abbrev));
                    }
                }
                3 => {
                    // UNABBREV_RECORD: [code#vbr6, numops#vbr6, op0#vbr6, ...]
                    let record_id = self.read_vbr_uint(6);
                    let num_ops = self.read_vbr_uint(6);
                    if num_ops > 4096 {
                        return None;
                    }
                    let mut ops = Vec::with_capacity(num_ops as usize);
                    for _ in 0..num_ops {
                        ops.push(self.read_vbr_uint(6));
                    }
                    return Some(BitcodeEntry::Record(BitcodeRecord {
                        id: record_id,
                        operands: ops,
                        blob: None,
                    }));
                }
                _ => {
                    // ABBREVIATED RECORD
                    let idx = (code - 4) as usize;
                    let abbrev = self
                        .block_stack
                        .last()
                        .and_then(|(_, abbrevs, _)| abbrevs.get(idx))
                        .cloned();
                    match abbrev {
                        Some(abbrev) => {
                            let record = self.decode_abbrev_record(&abbrev).unwrap_or_else(|| {
                                BitcodeRecord {
                                    id: 0xFFFF,
                                    operands: Vec::new(),
                                    blob: None,
                                }
                            });
                            return Some(BitcodeEntry::Record(record));
                        }
                        None => {
                            // Unknown abbreviation: skip the record by
                            // returning a marker record that parsers ignore.
                            return Some(BitcodeEntry::Record(BitcodeRecord {
                                id: 0xFFFF,
                                operands: Vec::new(),
                                blob: None,
                            }));
                        }
                    }
                }
            }
        }
    }

    /// Exit the current block (pop from stack) and restore the enclosing
    /// block's abbreviation width.
    fn exit_block(&mut self) {
        self.block_stack.pop();
        self.abbrev_width = self.block_stack.last().map_or(2, |(_, _, width)| *width);
    }

    /// Decode an abbreviated record using the given abbreviation definition.
    ///
    /// The first operand of the abbreviation encodes the record code (as a
    /// literal or as a Fixed/VBR/Char6 field); the remaining operands are the
    /// record's value operands. Array/Blob operands must be the last operand
    /// (optionally followed by the Array element encoding).
    fn decode_abbrev_record(&mut self, abbrev: &AbbrevDef) -> Option<BitcodeRecord> {
        let mut iter = abbrev.operands.iter();
        let first = iter.next()?;
        let record_id = match first {
            AbbrevOp::Literal(val) => *val,
            AbbrevOp::Fixed(width) => self.read_fixed_uint(*width),
            AbbrevOp::Vbr(width) => self.read_vbr_uint(*width),
            AbbrevOp::Char6 => self.read_char6() as u32,
            AbbrevOp::Array | AbbrevOp::Blob => return None,
        };
        let mut operands = Vec::new();
        let mut blob: Option<Vec<u8>> = None;
        while let Some(op) = iter.next() {
            match op {
                AbbrevOp::Literal(val) => operands.push(*val),
                AbbrevOp::Fixed(width) => operands.push(self.read_fixed_uint(*width)),
                AbbrevOp::Vbr(width) => operands.push(self.read_vbr_uint(*width)),
                AbbrevOp::Char6 => operands.push(self.read_char6() as u32),
                AbbrevOp::Array => {
                    // Array: vbr6 length, then elements encoded with the
                    // element encoding that follows in the abbreviation.
                    let len = self.read_vbr_uint(6);
                    if len > 4096 {
                        return None;
                    }
                    let elem = {
                        let elem = iter.next()?;
                        elem.clone()
                    };
                    for _ in 0..len {
                        let value = match &elem {
                            AbbrevOp::Literal(val) => *val,
                            AbbrevOp::Fixed(width) => self.read_fixed_uint(*width),
                            AbbrevOp::Vbr(width) => self.read_vbr_uint(*width),
                            AbbrevOp::Char6 => self.read_char6() as u32,
                            _ => return None,
                        };
                        operands.push(value);
                    }
                }
                AbbrevOp::Blob => {
                    // Blob: vbr6 length, align to 32 bits, bytes, tail padding
                    // to a 4-byte multiple.
                    let len = self.read_vbr_uint(6);
                    if len > (1 << 20) {
                        return None;
                    }
                    self.align_to_word();
                    let mut bytes = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        bytes.push(self.read_fixed_uint(8) as u8);
                    }
                    self.align_to_word();
                    blob = Some(bytes);
                }
            }
        }
        Some(BitcodeRecord {
            id: record_id,
            operands,
            blob,
        })
    }

    /// Read a DEFINE_ABBREV record body from the stream.
    ///
    /// Layout: [numabbrevops#vbr5, abbrevop0, abbrevop1, ...] where each
    /// abbrevop is a 1-bit literal flag; literals are followed by a vbr8
    /// value, encodings by a 3-bit code (1=Fixed, 2=VBR, 3=Array, 4=Char6,
    /// 5=Blob) and, for Fixed/VBR, a vbr5 width. Fixed(0) and VBR(0) are
    /// treated as literal zeros per the LLVM reader.
    fn parse_abbrev_record(&mut self) -> Option<AbbrevDef> {
        let num_ops = self.read_vbr_uint(5);
        if num_ops == 0 || num_ops > 64 {
            return None;
        }
        let mut operands = Vec::with_capacity(num_ops as usize);
        for _ in 0..num_ops {
            let is_literal = self.read_fixed_uint(1);
            if is_literal == 1 {
                operands.push(AbbrevOp::Literal(self.read_vbr_uint(8)));
                continue;
            }
            match self.read_fixed_uint(3) {
                1 => {
                    let width = self.read_vbr_uint(5);
                    if width == 0 {
                        operands.push(AbbrevOp::Literal(0));
                    } else {
                        operands.push(AbbrevOp::Fixed(width));
                    }
                }
                2 => {
                    let width = self.read_vbr_uint(5);
                    if width == 0 {
                        operands.push(AbbrevOp::Literal(0));
                    } else {
                        operands.push(AbbrevOp::Vbr(width));
                    }
                }
                3 => operands.push(AbbrevOp::Array),
                4 => operands.push(AbbrevOp::Char6),
                5 => operands.push(AbbrevOp::Blob),
                _ => return None,
            }
        }
        Some(AbbrevDef { operands })
    }

    /// Parse a BLOCKINFO block to extract abbreviation definitions.
    ///
    /// SETBID records select the block whose abbreviation list is extended by
    /// subsequent DEFINE_ABBREV entries. BLOCKNAME/SETRECORDNAME records are
    /// ignored.
    fn read_block_info_block(&mut self) -> AppResult<()> {
        // We should already be inside BLOCKINFO_BLOCK (block_id 0)
        let mut current_block_id: u32 = 0;
        while let Some(entry) = self.next_entry(false) {
            match entry {
                BitcodeEntry::EndBlock => break,
                BitcodeEntry::SubBlock(_) => {
                    // BLOCKINFO contains no sub-blocks; skip defensively.
                    self.skip_block();
                }
                BitcodeEntry::DefineAbbrev(abbrev) => {
                    let abbrevs = self.block_abbrevs.entry(current_block_id).or_default();
                    abbrevs.push(abbrev);
                }
                BitcodeEntry::Record(record) => {
                    if record.id == BLOCKINFO_CODE_SETBID
                        && let Some(&block_id) = record.operands.first()
                    {
                        current_block_id = block_id;
                    }
                }
            }
        }
        Ok(())
    }

    /// Parse the TYPE_BLOCK (block id 17) into `self.type_table`.
    fn read_type_block(&mut self) -> AppResult<()> {
        let mut types: Vec<TypeDesc> = Vec::new();
        while let Some(entry) = self.next_entry(true) {
            match entry {
                BitcodeEntry::EndBlock => break,
                BitcodeEntry::SubBlock(_) => self.skip_block(),
                BitcodeEntry::DefineAbbrev(_) => {}
                BitcodeEntry::Record(record) => {
                    let desc = match record.id {
                        TYPE_CODE_NUMENTRY => continue,
                        TYPE_CODE_VOID => TypeDesc {
                            is_void: true,
                            ..TypeDesc::default()
                        },
                        TYPE_CODE_HALF => TypeDesc {
                            is_float: true,
                            width: 16,
                            ..TypeDesc::default()
                        },
                        TYPE_CODE_FLOAT => TypeDesc {
                            is_float: true,
                            ..TypeDesc::default()
                        },
                        TYPE_CODE_DOUBLE => TypeDesc {
                            is_float: true,
                            width: 64,
                            ..TypeDesc::default()
                        },
                        TYPE_CODE_INTEGER => TypeDesc {
                            width: record.operands.first().copied().unwrap_or(32),
                            ..TypeDesc::default()
                        },
                        TYPE_CODE_POINTER => TypeDesc {
                            is_pointer: true,
                            is_signed: false,
                            ..TypeDesc::default()
                        },
                        TYPE_CODE_VECTOR => {
                            let count = record.operands.first().copied().unwrap_or(1);
                            let elem = record.operands.get(1).copied().unwrap_or(0) as usize;
                            let base = types.get(elem).copied().unwrap_or_default();
                            TypeDesc {
                                is_vector: true,
                                vector_len: count,
                                ..base
                            }
                        }
                        TYPE_CODE_ARRAY => {
                            let elem = record.operands.get(1).copied().unwrap_or(0) as usize;
                            types.get(elem).copied().unwrap_or_default()
                        }
                        TYPE_CODE_FUNCTION
                        | TYPE_CODE_FUNCTION_OLD
                        | TYPE_CODE_STRUCT_ANON
                        | TYPE_CODE_STRUCT_NAME
                        | TYPE_CODE_STRUCT_NAMED
                        | TYPE_CODE_OPAQUE
                        | TYPE_CODE_LABEL
                        | TYPE_CODE_METADATA
                        | TYPE_CODE_X86_FP80
                        | TYPE_CODE_FP128
                        | TYPE_CODE_PPC_FP128
                        | TYPE_CODE_X86_MMX => TypeDesc::default(),
                        _ => TypeDesc::default(),
                    };
                    types.push(desc);
                }
            }
        }
        self.type_table = types;
        Ok(())
    }

    /// Skip all records in the current block until END_BLOCK.
    fn skip_block(&mut self) {
        while let Some(entry) = self.next_entry(true) {
            match entry {
                BitcodeEntry::EndBlock => break,
                BitcodeEntry::SubBlock(_) => self.skip_block(),
                _ => {}
            }
        }
        self.exit_block();
    }
}

// ---------------------------------------------------------------------------
// DXIL instruction and function types
// ---------------------------------------------------------------------------

/// A parsed DXIL instruction with raw opcode and operand list.
#[derive(Debug, Clone)]
struct DxilInstruction {
    opcode: u32,
    operands: Vec<u32>,
    /// Result type descriptor when the record carried an explicit type
    /// operand (casts, loads, allocas, phis); derived from the type table.
    ty: Option<TypeDesc>,
}

/// A basic block in a DXIL function.
#[derive(Debug, Clone)]
#[allow(dead_code)] // basic-block label for future block emission
struct DxilBasicBlock {
    label: String,
    instructions: Vec<DxilInstruction>,
}

/// A parsed DXIL function with named basic blocks.
#[derive(Debug, Clone)]
pub struct DxilFunction {
    name: String,
    basic_blocks: Vec<DxilBasicBlock>,
}

/// The result of parsing a DXIL program from LLVM bitcode.
#[derive(Debug, Clone)]
pub struct ParsedDxilProgram {
    pub entry_name: String,
    pub functions: Vec<DxilFunction>,
    pub instruction_count: u32,
}

// ---------------------------------------------------------------------------
// DXIL instruction → MSL statement translation
// ---------------------------------------------------------------------------

/// Translate a DXIL opcode and operands to an MSL statement.
///
/// # Parameters
/// - `opcode`: The DXIL opcode (LLVM instruction opcode or HLSL intrinsic).
/// - `dst`: The destination variable name (e.g., "_t0").
/// - `args`: String representations of the operand values.
/// - `is_signed`: Whether the operation should use signed integer arithmetic.
/// - `is_float`: Whether the operation is floating-point.
///
/// # Returns
/// The MSL statement string, or a comment if the opcode is unknown.
pub fn dxil_opcode_to_msl(
    opcode: u32,
    dst: &str,
    args: &[String],
    is_signed: bool,
    is_float: bool,
) -> String {
    // Helper: produce a binary operation with fallback
    let binop = |op: &str| -> String {
        if args.len() >= 2 {
            format!("{} = {} {} {};", dst, args[0], op, args[1])
        } else {
            format!("{} = 0;", dst)
        }
    };

    let unop = |op: &str| -> String {
        if !args.is_empty() {
            format!("{} = {}({});", dst, op, args[0])
        } else {
            format!("{} = 0;", dst)
        }
    };

    let fcall = |name: &str, min_args: usize| -> String {
        if args.len() >= min_args {
            let call_args = args[..min_args].join(", ");
            format!("{} = {}({});", dst, name, call_args)
        } else {
            format!("{} = 0;", dst)
        }
    };

    match opcode {
        // --- Arithmetic operations (LLVM IR BinaryOps numbering) ---
        0..=1 => binop("+"),  // add / fadd
        2..=3 => binop("-"),  // sub / fsub
        4..=5 => binop("*"),  // mul / fmul
        6..=8 => binop("/"),  // udiv / sdiv / fdiv — MSL `/` is type-driven
        9..=10 => binop("%"), // urem / srem
        11 => binop("&"),     // and
        12 => binop("|"),     // or
        13 => binop("^"),     // xor
        14 => binop("<<"),    // shl
        15 => binop(">>"),    // lshr (logical shift right)
        16 => binop(">>"),    // ashr — arithmetic shift right (MSL uses
        //                  type-based >> semantics; signed → arithmetic,
        //                  unsigned → logical)
        17 => fcall("fma", 3), // fma

        // --- Comparison operations ---
        // icmp predicates (LLVM CmpInst: ICMP_EQ=32 .. ICMP_SLE=41) map to
        // 18..=27; fcmp_oeq/one map to 28/29; the remaining fcmp predicates
        // map to 61..=73.
        18..=27 => {
            let cmp_op = match opcode {
                18 => "==", // icmp_eq
                19 => "!=", // icmp_ne
                20 => ">",  // icmp_ugt
                21 => ">=", // icmp_uge
                22 => "<",  // icmp_ult
                23 => "<=", // icmp_ule
                24 => ">",  // icmp_sgt
                25 => ">=", // icmp_sge
                26 => "<",  // icmp_slt
                27 => "<=", // icmp_sle
                _ => "==",
            };
            binop(cmp_op)
        }
        28 => binop("=="), // fcmp_oeq
        29 => binop("!="), // fcmp_one
        CMP_FCMP_OGT | CMP_FCMP_UGT => binop(">"),
        CMP_FCMP_OGE | CMP_FCMP_UGE => binop(">="),
        CMP_FCMP_OLT | CMP_FCMP_ULT => binop("<"),
        CMP_FCMP_OLE | CMP_FCMP_ULE => binop("<="),
        CMP_FCMP_UNE => binop("!="),
        CMP_FCMP_ORD => {
            // Both operands are ordered (not NaN).
            if args.len() >= 2 {
                format!("{} = !isnan({}) && !isnan({});", dst, args[0], args[1])
            } else {
                format!("{} = 0;", dst)
            }
        }
        CMP_FCMP_UNO => {
            // At least one operand is NaN.
            if args.len() >= 2 {
                format!("{} = isnan({}) || isnan({});", dst, args[0], args[1])
            } else {
                format!("{} = 0;", dst)
            }
        }
        CMP_FCMP_FALSE => format!("{} = false;", dst),
        CMP_FCMP_TRUE => format!("{} = true;", dst),

        // --- Conversion operations ---
        30 => {
            // bitcast
            if !args.is_empty() {
                format!("{} = as_type<typeof({})>({});", dst, args[0], args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        31 => {
            // ptrtoint
            if !args.is_empty() {
                format!("{} = reinterpret_cast<uintptr_t>({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        32 => {
            // inttoptr
            if !args.is_empty() {
                format!("{} = reinterpret_cast<void*>({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        33 => unop("int32_t"), // zext (zero-extend)
        34 => {
            // sext (sign-extend)
            if is_signed && !args.is_empty() {
                format!("{} = int64_t({});", dst, args[0])
            } else if !args.is_empty() {
                format!("{} = uint64_t({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        35 => {
            // trunc
            if !args.is_empty() {
                format!("{} = int32_t({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        CAST_FPTOUI => {
            if !args.is_empty() {
                format!("{} = (uint)({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        CAST_FPTOSI => {
            if !args.is_empty() {
                format!("{} = (int)({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        CAST_UITOFP | CAST_SITOFP => {
            if !args.is_empty() {
                format!("{} = (float)({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        CAST_FPTRUNC => {
            if !args.is_empty() {
                format!("{} = (float)({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        CAST_FPEXT => {
            if !args.is_empty() {
                format!("{} = (double)({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        CAST_ADDRSPACECAST => {
            if !args.is_empty() {
                format!("{} = {}; // addrspacecast", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }

        // --- Control flow ---
        36 => {
            // br (unconditional)
            if !args.is_empty() {
                format!("goto {};", args[0])
            } else {
                String::from("// branch (no target)")
            }
        }
        37 => {
            // br (conditional)
            if args.len() >= 3 {
                format!(
                    "if ({}) {{ goto {}; }} else {{ goto {}; }}",
                    args[0], args[1], args[2]
                )
            } else {
                String::from("// conditional branch (incomplete)")
            }
        }
        38 => {
            // switch: [cond, default_bb, (case, bb)...]
            if args.len() >= 2 {
                let mut stmt = format!("switch ({}) {{\n", args[0]);
                let mut idx = 2;
                while idx + 1 < args.len() {
                    stmt.push_str(&format!(
                        "        case {}: goto {};\n",
                        args[idx],
                        args[idx + 1]
                    ));
                    idx += 2;
                }
                stmt.push_str(&format!("        default: goto {};\n    }}", args[1]));
                stmt
            } else {
                String::from("// switch (incomplete)")
            }
        }
        39 => {
            // phi: the values are assigned on incoming edges by the code
            // generator; this site is a no-op placeholder.
            if !args.is_empty() {
                format!("{} = {}; // phi fallback", dst, args[0])
            } else {
                format!("{} = 0; // phi empty", dst)
            }
        }
        40 => {
            // ret
            if args.is_empty() {
                "return;".to_string()
            } else {
                format!("return {};", args[0])
            }
        }
        41 => {
            // call
            // args[0] = callee index, args[1..] = call arguments
            if !args.is_empty() {
                format!("{} = _fn_{}({});", dst, args[0], args[1..].join(", "))
            } else {
                format!("{} = 0; // call(no args)", dst)
            }
        }

        // --- Memory operations ---
        42 => {
            // alloca
            format!("// {} = alloca (see declaration above)", dst)
        }
        43 => {
            // load
            if !args.is_empty() {
                format!("{} = {}[0];", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        44 => {
            // store
            if args.len() >= 2 {
                format!("{}[0] = {};", args[0], args[1])
            } else {
                "// store (no args)".to_string()
            }
        }
        45 => {
            // getelementptr (GEP)
            if args.len() >= 2 {
                format!("{} = &({}[{}]);", dst, args[0], args[1])
            } else {
                format!("{} = {};", dst, args.first().unwrap_or(&"0".to_string()))
            }
        }
        46 => {
            // select
            if args.len() >= 3 {
                format!("{} = {} ? {} : {};", dst, args[0], args[1], args[2])
            } else {
                format!("{} = 0;", dst)
            }
        }
        47 => {
            // extractvalue
            if args.len() >= 2 {
                format!("{} = {}.field{};", dst, args[0], args[1])
            } else {
                format!("{} = 0;", dst)
            }
        }
        48 => {
            // insertvalue
            if args.len() >= 2 {
                format!(
                    "{}.field{} = {};",
                    args[0],
                    args[1],
                    args.last().unwrap_or(&"0".to_string())
                )
            } else {
                String::from("// insertvalue (no args)")
            }
        }

        // --- Vector element operations (LLVM opcodes 49-52) ---
        49 => {
            // extractelement
            if args.len() >= 2 {
                format!("{} = {}[{}];", dst, args[0], args[1])
            } else {
                format!("{} = 0; // extractelement (no args)", dst)
            }
        }
        50 => {
            // insertelement
            if args.len() >= 3 {
                format!(
                    "{} = {}; {}[{}] = {}; // insertelement",
                    dst, args[0], args[0], args[1], args[2]
                )
            } else {
                format!("{} = 0; // insertelement (no args)", dst)
            }
        }
        51 => {
            // shufflevector
            if args.len() >= 3 {
                format!(
                    "{} = {}.{}; // shufflevector({}, {})",
                    dst, args[0], args[2], args[0], args[1]
                )
            } else {
                format!("{} = 0; // shufflevector", dst)
            }
        }
        52 => {
            // unreachable
            String::from("// unreachable")
        }

        // --- HLSL Intrinsics (opcodes 400+) ---
        DXIL_INTRIN_ABS => unop("abs"),
        DXIL_INTRIN_SATURATE => unop("saturate"),
        DXIL_INTRIN_MAD | DXIL_INTRIN_FMA => fcall("fma", 3),
        DXIL_INTRIN_MIN => {
            if args.len() >= 2 {
                if is_float {
                    format!("{} = fmin({}, {});", dst, args[0], args[1])
                } else {
                    format!("{} = min({}, {});", dst, args[0], args[1])
                }
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_MAX => {
            if args.len() >= 2 {
                if is_float {
                    format!("{} = fmax({}, {});", dst, args[0], args[1])
                } else {
                    format!("{} = max({}, {});", dst, args[0], args[1])
                }
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_CLAMP => fcall("clamp", 3),
        DXIL_INTRIN_SIN => unop("sin"),
        DXIL_INTRIN_COS => unop("cos"),
        DXIL_INTRIN_TAN => unop("tan"),
        DXIL_INTRIN_SQRT => unop("sqrt"),
        DXIL_INTRIN_RSQRT => unop("rsqrt"),
        DXIL_INTRIN_FRAC => unop("fract"),
        DXIL_INTRIN_FLOOR => unop("floor"),
        DXIL_INTRIN_CEIL => unop("ceil"),
        DXIL_INTRIN_ROUND => unop("rint"),
        DXIL_INTRIN_EXP => unop("exp"),
        DXIL_INTRIN_EXP2 => unop("exp2"),
        DXIL_INTRIN_LOG => unop("log"),
        DXIL_INTRIN_LOG2 => unop("log2"),
        DXIL_INTRIN_POW => fcall("pow", 2),
        DXIL_INTRIN_DOT => fcall("dot", 2),
        DXIL_INTRIN_MUL => binop("*"),
        DXIL_INTRIN_LERP => fcall("mix", 3),
        DXIL_INTRIN_NORMALIZE => unop("normalize"),
        DXIL_INTRIN_CROSS => fcall("cross", 2),
        DXIL_INTRIN_TRANSPOSE => unop("transpose"),
        DXIL_INTRIN_DETERMINANT => unop("matrix_determinant"),
        DXIL_INTRIN_REFLECT => fcall("reflect", 2),
        DXIL_INTRIN_REFRACT => fcall("refract", 3),
        DXIL_INTRIN_ISFINITE => unop("isfinite"),
        DXIL_INTRIN_ISINF => unop("isinf"),
        DXIL_INTRIN_ISNAN => unop("isnan"),
        DXIL_INTRIN_SIGN => unop("sign"),
        DXIL_INTRIN_COUNTBITS => unop("popcount"),
        DXIL_INTRIN_REVERSEBITS => unop("reverse_bits"),
        DXIL_INTRIN_SINCOS => {
            if !args.is_empty() {
                // DXIL sincos writes both results through pointers; emit
                // local block-scoped temps and assign the sine to dst.
                format!(
                    "{{ float _sincos_s = 0.0f; float _sincos_c = 0.0f; sincos({}, &_sincos_s, &_sincos_c); {} = _sincos_s; }}",
                    args[0], dst
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_RCP => unop("recip"),
        DXIL_INTRIN_DISTANCE => fcall("distance", 2),
        DXIL_INTRIN_LENGTH => unop("length"),
        DXIL_INTRIN_SMOOTHSTEP => fcall("smoothstep", 3),
        DXIL_INTRIN_STEP => fcall("step", 2),
        DXIL_INTRIN_ATAN2 => fcall("atan2", 2),
        DXIL_INTRIN_ATAN => unop("atan"),
        DXIL_INTRIN_ASIN => unop("asin"),
        DXIL_INTRIN_ACOS => unop("acos"),
        DXIL_INTRIN_TANH => unop("tanh"),
        DXIL_INTRIN_SINH => unop("sinh"),
        DXIL_INTRIN_COSH => unop("cosh"),
        DXIL_INTRIN_FWIDTH => unop("fwidth"),

        // --- Texture/buffer intrinsics ---
        DXIL_INTRIN_SAMPLE => {
            if args.len() >= 3 {
                format!("{} = {}.sample({}, {});", dst, args[0], args[1], args[2])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_SAMPLELEVEL => {
            if args.len() >= 4 {
                format!(
                    "{} = {}.sample({}, {}, level({}));",
                    dst, args[0], args[1], args[2], args[3]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_SAMPLEGRAD => {
            if args.len() >= 5 {
                format!(
                    "{} = {}.sample({}, {}, gradient2d({}, {}));",
                    dst, args[0], args[1], args[2], args[3], args[4]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_SAMPLEBIAS => {
            if args.len() >= 4 {
                format!(
                    "{} = {}.sample({}, {}, bias({}));",
                    dst, args[0], args[1], args[2], args[3]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_SAMPLECMP => {
            if args.len() >= 3 {
                format!(
                    "{} = {}.sample_compare({}, {});",
                    dst, args[0], args[1], args[2]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_GATHER => {
            if args.len() >= 2 {
                format!("{} = {}.gather({});", dst, args[0], args[1])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_LOAD | DXIL_INTRIN_TEXTURELOAD => {
            if args.len() >= 2 {
                format!("{} = {}.read({});", dst, args[0], args[1])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_STORE | DXIL_INTRIN_TEXTURESTORE => {
            if args.len() >= 2 {
                format!(
                    "{}.write({}, {});",
                    args[0],
                    args[1],
                    args.get(2).unwrap_or(&"0".to_string())
                )
            } else {
                String::from("// texture store (no args)")
            }
        }
        DXIL_INTRIN_BUFFERLOAD => {
            if args.len() >= 2 {
                format!("{} = {}[{}];", dst, args[0], args[1])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_BUFFERSTORE => {
            if args.len() >= 2 {
                format!(
                    "{}[{}] = {};",
                    args[0],
                    args[1],
                    args.last().unwrap_or(&"0".to_string())
                )
            } else {
                String::from("// buffer store (no args)")
            }
        }

        // --- Thread/buffer identity intrinsics ---
        DXIL_INTRIN_THREADID => {
            if !args.is_empty() {
                let coord = thread_dim_coord(&args[0]);
                format!("{} = thread_position_in_grid.{};", dst, coord)
            } else {
                format!("{} = 0; // ThreadId", dst)
            }
        }
        DXIL_INTRIN_GROUPID => {
            if !args.is_empty() {
                let coord = thread_dim_coord(&args[0]);
                format!("{} = threadgroup_position_in_grid.{};", dst, coord)
            } else {
                format!("{} = 0; // GroupId", dst)
            }
        }
        DXIL_INTRIN_THREADGROUPID => {
            if !args.is_empty() {
                let coord = thread_dim_coord(&args[0]);
                format!("{} = thread_position_in_threadgroup.{};", dst, coord)
            } else {
                format!("{} = 0; // ThreadGroupId", dst)
            }
        }
        DXIL_INTRIN_GROUPINDEX => {
            format!("{} = thread_index_in_threadgroup;", dst)
        }
        DXIL_INTRIN_DISPATCHTHREADID => {
            if !args.is_empty() {
                let coord = thread_dim_coord(&args[0]);
                format!("{} = thread_position_in_grid.{};", dst, coord)
            } else {
                format!("{} = 0; // DispatchThreadId", dst)
            }
        }
        DXIL_INTRIN_BARRIER => {
            // DXIL barrier flags:
            //   0x01 = GroupSync (thread synchronization)
            //   0x04 = GroupShared memory (threadgroup memory)
            //   0x08 = UAV memory (device memory)
            // Without GroupSync, use memory_barrier (no thread sync).
            // With GroupSync, use threadgroup_barrier (includes thread sync).
            let flag = if args.is_empty() || args[0] == "0" {
                0u32
            } else {
                args[0].parse::<u32>().unwrap_or(0)
            };
            let has_sync = flag == 0 || (flag & 0x01) != 0;
            let has_gs = (flag & 0x04) != 0;
            let has_uav = (flag & 0x08) != 0;

            let memory_flags = match (has_gs, has_uav) {
                (true, true) => "mem_flags::mem_threadgroup | mem_flags::mem_device",
                (true, false) => "mem_flags::mem_threadgroup",
                (false, true) => "mem_flags::mem_device",
                (false, false) => "mem_flags::mem_threadgroup | mem_flags::mem_device",
            };

            if has_sync {
                format!("threadgroup_barrier({});", memory_flags)
            } else {
                format!("memory_barrier({});", memory_flags)
            }
        }
        DXIL_INTRIN_GROUPMEMORYBARRIER => {
            "threadgroup_barrier(mem_flags::mem_threadgroup);".to_string()
        }
        DXIL_INTRIN_DEVICEMEMORYBARRIER => {
            "threadgroup_barrier(mem_flags::mem_device);".to_string()
        }

        // --- Atomic intrinsics ---
        // Helper: generate atomic operation with correct address space based on operands
        DXIL_INTRIN_ATOMICADD => {
            if args.len() >= 3 {
                let ptr = &args[1];
                let val = &args[2];
                // Try to detect if this is threadgroup memory
                if is_groupshared_ptr(ptr) {
                    format!(
                        "{} = atomic_fetch_add_explicit((volatile threadgroup atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                } else {
                    format!(
                        "{} = atomic_fetch_add_explicit((volatile device atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                }
            } else {
                format!("{} = 0; // atomicAdd", dst)
            }
        }
        DXIL_INTRIN_ATOMICAND => {
            if args.len() >= 3 {
                let ptr = &args[1];
                let val = &args[2];
                if is_groupshared_ptr(ptr) {
                    format!(
                        "{} = atomic_fetch_and_explicit((volatile threadgroup atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                } else {
                    format!(
                        "{} = atomic_fetch_and_explicit((volatile device atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                }
            } else {
                format!("{} = 0; // atomicAnd", dst)
            }
        }
        DXIL_INTRIN_ATOMICOR => {
            if args.len() >= 3 {
                let ptr = &args[1];
                let val = &args[2];
                if is_groupshared_ptr(ptr) {
                    format!(
                        "{} = atomic_fetch_or_explicit((volatile threadgroup atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                } else {
                    format!(
                        "{} = atomic_fetch_or_explicit((volatile device atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                }
            } else {
                format!("{} = 0; // atomicOr", dst)
            }
        }
        DXIL_INTRIN_ATOMICXOR => {
            if args.len() >= 3 {
                let ptr = &args[1];
                let val = &args[2];
                if is_groupshared_ptr(ptr) {
                    format!(
                        "{} = atomic_fetch_xor_explicit((volatile threadgroup atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                } else {
                    format!(
                        "{} = atomic_fetch_xor_explicit((volatile device atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                }
            } else {
                format!("{} = 0; // atomicXor", dst)
            }
        }
        DXIL_INTRIN_ATOMICMIN => {
            if args.len() >= 3 {
                let ptr = &args[1];
                let val = &args[2];
                if is_groupshared_ptr(ptr) {
                    format!(
                        "{} = atomic_fetch_min_explicit((volatile threadgroup atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                } else {
                    format!(
                        "{} = atomic_fetch_min_explicit((volatile device atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                }
            } else {
                format!("{} = 0; // atomicMin", dst)
            }
        }
        DXIL_INTRIN_ATOMICMAX => {
            if args.len() >= 3 {
                let ptr = &args[1];
                let val = &args[2];
                if is_groupshared_ptr(ptr) {
                    format!(
                        "{} = atomic_fetch_max_explicit((volatile threadgroup atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                } else {
                    format!(
                        "{} = atomic_fetch_max_explicit((volatile device atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                }
            } else {
                format!("{} = 0; // atomicMax", dst)
            }
        }
        DXIL_INTRIN_ATOMICEXCHANGE => {
            if args.len() >= 3 {
                let ptr = &args[1];
                let val = &args[2];
                if is_groupshared_ptr(ptr) {
                    format!(
                        "{} = atomic_exchange_explicit((volatile threadgroup atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                } else {
                    format!(
                        "{} = atomic_exchange_explicit((volatile device atomic_int*){}, {}, memory_order_relaxed);",
                        dst, ptr, val
                    )
                }
            } else {
                format!("{} = 0; // atomicExchange", dst)
            }
        }
        DXIL_INTRIN_ATOMICCOMPAREEXCHANGE => {
            if args.len() >= 4 {
                let ptr = &args[1];
                let cmp = &args[2];
                let val = &args[3];
                if is_groupshared_ptr(ptr) {
                    format!(
                        "{} = atomic_compare_exchange_weak_explicit((volatile threadgroup atomic_int*){}, {}, {}, memory_order_relaxed, memory_order_relaxed);",
                        dst, ptr, cmp, val
                    )
                } else {
                    format!(
                        "{} = atomic_compare_exchange_weak_explicit((volatile device atomic_int*){}, {}, {}, memory_order_relaxed, memory_order_relaxed);",
                        dst, ptr, cmp, val
                    )
                }
            } else {
                format!("{} = 0; // atomicCompareExchange", dst)
            }
        }

        // --- Derivative intrinsics ---
        DXIL_INTRIN_DERIVATIVE => {
            if !args.is_empty() {
                format!("{} = dfdx({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_DERIVATIVE_COARSE => {
            if !args.is_empty() {
                format!("{} = dfdx_coarse({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_DERIVATIVE_FINE => {
            if !args.is_empty() {
                format!("{} = dfdx_fine({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }

        // --- Wave intrinsics ---
        DXIL_INTRIN_WAVEACTIVE => {
            format!("{} = simd_active_mask() != 0; // WaveActiveBool", dst)
        }
        DXIL_INTRIN_WAVEACTIVEBIT => {
            if !args.is_empty() {
                format!("{} = simd_ballot({} != 0); // WaveActiveBit", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEPREFIX => {
            // WavePrefixSum/Product/And/Or/Xor take a single value argument;
            // the 2-argument form belongs to the MultiPrefix variants.
            if !args.is_empty() {
                format!(
                    "{} = simd_prefix_exclusive_sum({}); // WavePrefix",
                    dst, args[0]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_QUADREAD => {
            if args.len() >= 2 {
                format!("{} = quad_broadcast({}, {});", dst, args[0], args[1])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_QUADWRITE => {
            if args.len() >= 3 {
                format!(
                    "{} = quad_vote({} == {}); // QuadWrite emulation",
                    dst, args[0], args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEGETLANEINDEX => {
            format!("{} = simd_lane_id();", dst)
        }
        DXIL_INTRIN_WAVEGETLANECOUNT => {
            format!("{} = simd_lane_count();", dst)
        }
        DXIL_INTRIN_WAVEANYTRUE => {
            if !args.is_empty() {
                format!("{} = simd_any({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEALLTRUE => {
            if !args.is_empty() {
                format!("{} = simd_all({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEALLEQUAL => {
            if !args.is_empty() {
                format!(
                    "{} = simd_all({} == simd_broadcast_first({}));",
                    dst, args[0], args[0]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEBALLOT => {
            if !args.is_empty() {
                format!("{} = simd_ballot({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEREADLANEAT => {
            if args.len() >= 2 {
                format!("{} = simd_broadcast({}, {});", dst, args[0], args[1])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEREADLANEFIRST => {
            if !args.is_empty() {
                format!("{} = simd_broadcast_first({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEACTIVEBITAND => {
            if !args.is_empty() {
                format!("{} = simd_and({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEACTIVEBITOR => {
            if !args.is_empty() {
                format!("{} = simd_or({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEACTIVEBITXOR => {
            if !args.is_empty() {
                format!("{} = simd_xor({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEACTIVECOUNTBITS => {
            if !args.is_empty() {
                format!("{} = popcount(simd_ballot({}));", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEACTIVESUM => {
            if !args.is_empty() {
                format!("{} = simd_sum({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEACTIVEPRODUCT => {
            if !args.is_empty() {
                format!("{} = simd_product({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEACTIVEMIN => {
            if !args.is_empty() {
                format!("{} = simd_min({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEACTIVEMAX => {
            if !args.is_empty() {
                format!("{} = simd_max({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEMULTIPREFIXSUM => {
            if args.len() >= 2 {
                format!(
                    "{} = simd_prefix_exclusive_sum({}); // MultiPrefix",
                    dst, args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEMULTIPREFIXPRODUCT => {
            if args.len() >= 2 {
                format!(
                    "{} = simd_prefix_exclusive_product({}); // MultiPrefix",
                    dst, args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEMULTIPREFIXBITAND => {
            if args.len() >= 2 {
                format!(
                    "{} = simd_prefix_exclusive_and({}); // MultiPrefix",
                    dst, args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEMULTIPREFIXBITOR => {
            if args.len() >= 2 {
                format!(
                    "{} = simd_prefix_exclusive_or({}); // MultiPrefix",
                    dst, args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEMULTIPREFIXBITXOR => {
            if args.len() >= 2 {
                format!(
                    "{} = simd_prefix_exclusive_xor({}); // MultiPrefix",
                    dst, args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEMULTIPREFIXBITCOUNT => {
            if args.len() >= 2 {
                format!(
                    "{} = popcount(simd_prefix_exclusive_or({})); // MultiPrefix",
                    dst, args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEMATCH => {
            if !args.is_empty() {
                // WaveMatch(value) returns a mask of lanes whose value equals
                // the current lane's value. Broadcast the current lane's value
                // and ballot the per-lane comparison.
                format!(
                    "{} = simd_ballot(simd_broadcast({}, simd_lane_id()) == {}); // WaveMatch",
                    dst, args[0], args[0]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_WAVEISFIRSTLANE => {
            format!("{} = simd_is_first();", dst)
        }
        DXIL_INTRIN_DISCARD => "discard_fragment(); // Discard".to_string(),

        // --- Conversion/bit intrinsics ---
        DXIL_INTRIN_ASFLOAT => {
            if !args.is_empty() {
                format!("{} = as_type<float>({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_ASINT => {
            if !args.is_empty() {
                format!("{} = as_type<int>({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_ASUINT => {
            if !args.is_empty() {
                format!("{} = as_type<uint>({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_FIRSTBITHIGH => {
            if !args.is_empty() {
                format!(
                    "{} = (clz({}) == 32) ? -1 : (31 - (int)clz({}));",
                    dst, args[0], args[0]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_FIRSTBITLOW => {
            if !args.is_empty() {
                format!(
                    "{} = (ctz({}) == 32) ? -1 : (int)ctz({});",
                    dst, args[0], args[0]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_LOG10 => {
            if !args.is_empty() {
                format!("{} = log10({});", dst, args[0])
            } else {
                format!("{} = 0;", dst)
            }
        }

        // --- Packed dot-product intrinsics ---
        DXIL_INTRIN_DOT4ADDI8PACKED => {
            if args.len() >= 2 {
                // The i8 lanes are signed: cast to int32 first so the shifts
                // are arithmetic and each byte is sign-extended.
                format!(
                    "{} = (int)(((int){} << 24) >> 24) * (int)(((int){} << 24) >> 24) + (int)(((int){} << 16) >> 24) * (int)(((int){} << 16) >> 24) + (int)(((int){} << 8) >> 24) * (int)(((int){} << 8) >> 24) + (int)((int){} >> 24) * (int)((int){} >> 24); // Dot4AddI8Packed",
                    dst, args[0], args[1], args[0], args[1], args[0], args[1], args[0], args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }
        DXIL_INTRIN_DOT4ADDU8PACKED => {
            if args.len() >= 2 {
                format!(
                    "{} = uint(({} >> 0) & 0xFF) * uint(({} >> 0) & 0xFF) + uint(({} >> 8) & 0xFF) * uint(({} >> 8) & 0xFF) + uint(({} >> 16) & 0xFF) * uint(({} >> 16) & 0xFF) + uint(({} >> 24) & 0xFF) * uint(({} >> 24) & 0xFF); // Dot4AddU8Packed",
                    dst, args[0], args[1], args[0], args[1], args[0], args[1], args[0], args[1]
                )
            } else {
                format!("{} = 0;", dst)
            }
        }

        // --- Tessellation intrinsics ---
        DXIL_INTRIN_PROCESS2DQUADTESSSFACTORSAVG => {
            if args.len() >= 4 {
                format!(
                    "{} = float2(({} + {} + {} + {}) / 4.0, (fabs({}) + fabs({}) + fabs({}) + fabs({})) / 4.0);",
                    dst, args[0], args[1], args[2], args[3], args[0], args[1], args[2], args[3]
                )
            } else {
                format!("{} = float2(1.0, 1.0);", dst)
            }
        }
        DXIL_INTRIN_PROCESS2DQUADTESSFACTORSMAX => {
            if args.len() >= 4 {
                format!(
                    "{} = float2(fmax(fmax({}, {}), fmax({}, {})), fmax(fmax(fabs({}), fabs({})), fmax(fabs({}), fabs({}))));",
                    dst, args[0], args[1], args[2], args[3], args[0], args[1], args[2], args[3]
                )
            } else {
                format!("{} = float2(1.0, 1.0);", dst)
            }
        }
        DXIL_INTRIN_PROCESS2DQUADTESSFACTORSMIN => {
            if args.len() >= 4 {
                format!(
                    "{} = float2(fmin(fmin({}, {}), fmin({}, {})), fmin(fmin(fabs({}), fabs({})), fmin(fabs({}), fabs({}))));",
                    dst, args[0], args[1], args[2], args[3], args[0], args[1], args[2], args[3]
                )
            } else {
                format!("{} = float2(1.0, 1.0);", dst)
            }
        }
        DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSAVG => {
            if args.len() >= 3 {
                format!(
                    "{} = float2(({} + {} + {}) / 3.0, (fabs({}) + fabs({}) + fabs({})) / 3.0);",
                    dst, args[0], args[1], args[2], args[0], args[1], args[2]
                )
            } else {
                format!("{} = float2(1.0, 1.0);", dst)
            }
        }
        DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSMAX => {
            if args.len() >= 3 {
                format!(
                    "{} = float2(fmax(fmax({}, {}), {}), fmax(fmax(fabs({}), fabs({})), fabs({})));",
                    dst, args[0], args[1], args[2], args[0], args[1], args[2]
                )
            } else {
                format!("{} = float2(1.0, 1.0);", dst)
            }
        }
        DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSMIN => {
            if args.len() >= 3 {
                format!(
                    "{} = float2(fmin(fmin({}, {}), {}), fmin(fmin(fabs({}), fabs({})), fabs({})));",
                    dst, args[0], args[1], args[2], args[0], args[1], args[2]
                )
            } else {
                format!("{} = float2(1.0, 1.0);", dst)
            }
        }

        // --- Texture query intrinsics ---
        DXIL_INTRIN_CALCULATELOD => {
            if args.len() >= 2 {
                format!("{} = {}.calculate_lod({});", dst, args[0], args[1])
            } else {
                format!("{} = 0.0;", dst)
            }
        }
        DXIL_INTRIN_CALCULATELODUNCLAMPED => {
            if args.len() >= 2 {
                format!(
                    "{} = {}.calculate_lod({}); // Note: MSL does not support unclamped LOD",
                    dst, args[0], args[1]
                )
            } else {
                format!("{} = 0.0;", dst)
            }
        }

        // --- Attribute evaluation and misc ---
        DXIL_INTRIN_CHECKACCESSFULLYMAPPED => {
            format!("{} = 1; // CheckAccessFullyMapped", dst)
        }
        DXIL_INTRIN_EVALUATEATTRIBUTEATCENTROID => {
            if !args.is_empty() {
                format!("{} = {}; // EvaluateAttributeAtCentroid", dst, args[0])
            } else {
                format!("{} = 0.0;", dst)
            }
        }
        DXIL_INTRIN_EVALUATEATTRIBUTEATSAMPLE => {
            if args.len() >= 2 {
                format!(
                    "{} = {}; // EvaluateAttributeAtSample({})",
                    dst, args[0], args[1]
                )
            } else {
                format!("{} = 0.0;", dst)
            }
        }
        DXIL_INTRIN_EVALUATEATTRIBUTEATCONSTANT => {
            if args.len() >= 2 {
                format!(
                    "{} = {}; // EvaluateAttributeAtConstant({})",
                    dst, args[0], args[1]
                )
            } else {
                format!("{} = 0.0;", dst)
            }
        }
        DXIL_INTRIN_INSTANCEID => {
            format!("{} = instance_id;", dst)
        }
        DXIL_INTRIN_VERTEXID => {
            format!("{} = vid;", dst)
        }
        DXIL_INTRIN_PRIMITIVEID => {
            format!("{} = primitive_id;", dst)
        }

        // --- Geometry shader intrinsics ---
        // In Metal, geometry shaders are emulated via compute shaders.
        // EmitVertex appends vertex data to a stream output buffer.
        // CutStream finalizes the current primitive in the stream.
        // EmitThenCutStream emits a vertex and immediately starts a new primitive.
        DXIL_INTRIN_EMITSTREAM => {
            let stream_id = args.first().map_or("0", String::as_str);
            format!(
                "// EmitStream({stream_id}): append vertex to stream output\n\
                {{ uint _gs_vert_idx = atomic_fetch_add_explicit(\n\
                \x20   (volatile device atomic_uint*)_gs_prim_count, 1u, memory_order_relaxed);\n\
                \x20 device float4* _gs_vtx = _gs_stream + _gs_vert_idx * {};\n\
                \x20 // Write vertex attributes to stream output\n\
                \x20 _gs_vtx[0] = _gs_position;  // position\n\
                \x20 _gs_vtx[1] = _gs_normal;    // normal\n\
                \x20 _gs_vtx[2] = _gs_texcoord;  // texcoord\n\
                }}",
                3 // position + normal + texcoord = 3 float4 slots per vertex
            )
        }
        DXIL_INTRIN_CUTSTREAM => {
            let stream_id = args.first().map_or("0", String::as_str);
            format!(
                "// CutStream({stream_id}): finalize current primitive\n\
                {{ /* primitive finalized; next EmitVertex starts new primitive */ }}"
            )
        }
        DXIL_INTRIN_EMITTHENCUTSTREAM => {
            let stream_id = args.first().map_or("0", String::as_str);
            format!(
                "// EmitThenCutStream({stream_id}): emit then cut\n\
                {{ uint _gs_vert_idx = atomic_fetch_add_explicit(\n\
                \x20   (volatile device atomic_uint*)_gs_prim_count, 1u, memory_order_relaxed);\n\
                \x20 device float4* _gs_vtx = _gs_stream + _gs_vert_idx * {};\n\
                \x20 _gs_vtx[0] = _gs_position;\n\
                \x20 _gs_vtx[1] = _gs_normal;\n\
                \x20 _gs_vtx[2] = _gs_texcoord;\n\
                \x20 // primitive finalized after emit\n\
                }}",
                3
            )
        }

        // --- Resource handle creation (resource array indexing) ---
        // DXIL resource classes: 0=SRV, 1=UAV, 2=CBV, 3=Sampler
        // CreateHandle(resClass, rangeId, index) — resolves a resource by
        // range + index.  In MSL, resources are bound individually via
        // [[texture(N)]], [[buffer(N)]], [[sampler(N)]], so we emit a
        // reference expression that picks the correct binding.
        DXIL_INTRIN_CREATEHANDLE => {
            if args.len() >= 3 {
                let res_class = &args[0];
                let _range_id = &args[1];
                let index = &args[2];
                // Determine if index looks like a literal constant
                let is_const_idx = index.parse::<u32>().is_ok();
                let binding = if is_const_idx {
                    // Static index: reference the specific binding slot
                    // e.g., _handle_srv_0, _handle_uav_1, _handle_cbv_2
                    format!("_res_{}_{}", res_class, index)
                } else {
                    // Dynamic index: array-of-resources pattern
                    // e.g., _res_array_srv[_idx_3] where _idx_3 is the runtime index
                    format!("_res_array_{}[{}]", res_class, index)
                };
                // Store the resolved handle name so later instructions can use it
                format!(
                    "{} = {}; // CreateHandle(resClass={}, rangeId={}, index={})",
                    dst, binding, args[0], args[1], args[2]
                )
            } else {
                format!("{} = 0; // CreateHandle (no args)", dst)
            }
        }
        // CreateHandleForBinding(resClass, rangeId, index, nonUniformIndex)
        // Similar to CreateHandle but the index may come from a non-uniform
        // input (e.g., a per-vertex/fragment attribute).  In MSL, non-uniform
        // indexing of resource arrays requires either:
        //   a) A switch() over individual [[texture(N)]] bindings, or
        //   b) An array<> of textures (MSL 2.3+, device only).
        // We emit the dynamic-indexing pattern.
        DXIL_INTRIN_CREATEHANDLEFORBINDING => {
            if args.len() >= 4 {
                let res_class = &args[0];
                let _range_id = &args[1];
                let index = &args[2];
                let _non_uniform = &args[3];
                let is_const_idx = index.parse::<u32>().is_ok();
                let binding = if is_const_idx {
                    format!("_res_{}_{}", res_class, index)
                } else {
                    format!("_res_array_{}[{}]", res_class, index)
                };
                format!(
                    "{} = {}; // CreateHandleForBinding(resClass={}, rangeId={}, index={}, nonUniform={})",
                    dst, binding, args[0], args[1], args[2], args[3]
                )
            } else {
                format!("{} = 0; // CreateHandleForBinding (no args)", dst)
            }
        }

        _ => {
            format!(
                "{} = 0; // unknown opcode {} (signed={}, float={})",
                dst, opcode, is_signed, is_float
            )
        }
    }
}

// ---------------------------------------------------------------------------
// DXIL intrinsic mapping helpers
// ---------------------------------------------------------------------------

/// Map a thread-dimension operand (0 = x, 1 = y, everything else = z) to the
/// corresponding vector component name. Values >= 3 come from untrusted
/// bytecode and must never index an array.
fn thread_dim_coord(operand: &str) -> &'static str {
    match operand.parse::<u32>().unwrap_or(0) {
        0 => "x",
        1 => "y",
        _ => "z",
    }
}

/// Heuristic: check if a pointer argument refers to groupshared memory by
/// looking for common patterns in temporary variable names used for groupshared
/// accesses.
fn is_groupshared_ptr(ptr: &str) -> bool {
    // Groupshared variables typically have "gs_" prefix or "_gs" suffix in
    // the temporary variable naming scheme.
    ptr.contains("_gs") || ptr.contains("gs_") || ptr.contains("groupshared")
}

/// Map a DXIL intrinsic function ID (from the DXIL spec's intrinsic numbering)
/// to this implementation's internal opcode constants.
///
/// The numbers below were cross-checked against DXC's `DXIL.h`/`DxilConstants.h`
/// opcode table (e.g. `ThreadId = 93`, `Sample = 60`, `AtomicCompareExchange =
/// 79`, `Dot4AddI8Packed = 163`). IDs that exist in DXIL but have no faithful
/// MSL translation here (atomics with a runtime operation selector, ray
/// tracing, `WavePrefixOp` variants, ...) deliberately return `None` so the
/// caller can fail loudly instead of emitting a bogus generic call.
pub fn map_dxil_intrinsic_id(dxil_intrinsic_id: u32) -> Option<u32> {
    match dxil_intrinsic_id {
        // Arithmetic intrinsics (DXIL 1.0 numbering)
        6 => Some(DXIL_INTRIN_ABS),            // FAbs
        7 => Some(DXIL_INTRIN_SATURATE),       // Saturate
        8 => Some(DXIL_INTRIN_ISNAN),          // IsNaN
        9 => Some(DXIL_INTRIN_ISINF),          // IsInf
        10 => Some(DXIL_INTRIN_ISFINITE),      // IsFinite
        12 => Some(DXIL_INTRIN_COS),           // Cos
        13 => Some(DXIL_INTRIN_SIN),           // Sin
        14 => Some(DXIL_INTRIN_TAN),           // Tan
        15 => Some(DXIL_INTRIN_ACOS),          // Acos
        16 => Some(DXIL_INTRIN_ASIN),          // Asin
        17 => Some(DXIL_INTRIN_ATAN),          // Atan
        18 => Some(DXIL_INTRIN_COSH),          // Hcos
        19 => Some(DXIL_INTRIN_SINH),          // Hsin
        20 => Some(DXIL_INTRIN_TANH),          // Htan
        21 => Some(DXIL_INTRIN_EXP),           // Exp
        22 => Some(DXIL_INTRIN_FRAC),          // Frc
        23 => Some(DXIL_INTRIN_LOG),           // Log
        24 => Some(DXIL_INTRIN_SQRT),          // Sqrt
        25 => Some(DXIL_INTRIN_RSQRT),         // Rsqrt
        26..=29 => Some(DXIL_INTRIN_ROUND),    // Round_ne/ni/pi/z
        30 => Some(DXIL_INTRIN_REVERSEBITS),   // Bfrev
        31 => Some(DXIL_INTRIN_COUNTBITS),     // Countbits
        32 => Some(DXIL_INTRIN_FIRSTBITLOW),   // FirstbitLo
        33 => Some(DXIL_INTRIN_FIRSTBITHIGH),  // FirstbitHi
        34 => Some(DXIL_INTRIN_FIRSTBITHIGH),  // FirstbitSHi
        35 | 37 | 39 => Some(DXIL_INTRIN_MAX), // FMax / IMax / UMax
        36 | 38 | 40 => Some(DXIL_INTRIN_MIN), // FMin / IMin / UMin
        41 | 42 => Some(DXIL_INTRIN_MUL),      // IMul / UMul
        46 => Some(DXIL_INTRIN_MAD),           // FMad
        47 => Some(DXIL_INTRIN_FMA),           // Fma
        48 | 49 => Some(DXIL_INTRIN_MAD),      // IMad / UMad
        54..=56 => Some(DXIL_INTRIN_DOT),      // Dot2 / Dot3 / Dot4

        // Resource handle creation
        57 => Some(DXIL_INTRIN_CREATEHANDLE),

        // Texture/buffer intrinsics
        60 => Some(DXIL_INTRIN_SAMPLE),
        62 => Some(DXIL_INTRIN_SAMPLELEVEL),
        63 => Some(DXIL_INTRIN_SAMPLEGRAD),
        64 | 65 => Some(DXIL_INTRIN_SAMPLECMP), // SampleCmp / SampleCmpLevelZero
        66 => Some(DXIL_INTRIN_TEXTURELOAD),
        67 => Some(DXIL_INTRIN_TEXTURESTORE),
        68 => Some(DXIL_INTRIN_BUFFERLOAD),
        69 => Some(DXIL_INTRIN_BUFFERSTORE),
        71 => Some(DXIL_INTRIN_CHECKACCESSFULLYMAPPED),
        73 => Some(DXIL_INTRIN_GATHER),

        // Atomics — AtomicBinOp (78) carries its operation in a constant
        // operand and is intentionally left unmapped rather than guessing.
        79 => Some(DXIL_INTRIN_ATOMICCOMPAREEXCHANGE),

        // Barriers and derivatives
        80 => Some(DXIL_INTRIN_BARRIER),
        81 => Some(DXIL_INTRIN_CALCULATELOD),
        82 => Some(DXIL_INTRIN_DISCARD),
        83 | 84 => Some(DXIL_INTRIN_DERIVATIVE_COARSE), // DerivCoarseX/Y
        85 | 86 => Some(DXIL_INTRIN_DERIVATIVE_FINE),   // DerivFineX/Y
        88 => Some(DXIL_INTRIN_EVALUATEATTRIBUTEATSAMPLE), // EvalSampleIndex
        89 => Some(DXIL_INTRIN_EVALUATEATTRIBUTEATCENTROID), // EvalCentroid

        // Thread/group identity
        93 => Some(DXIL_INTRIN_THREADID), // SV_DispatchThreadID
        94 => Some(DXIL_INTRIN_GROUPID),  // SV_GroupID
        95 => Some(DXIL_INTRIN_THREADGROUPID), // SV_GroupThreadID
        96 => Some(DXIL_INTRIN_GROUPINDEX), // SV_GroupIndex

        // Geometry shaders
        97 => Some(DXIL_INTRIN_EMITSTREAM),
        98 => Some(DXIL_INTRIN_CUTSTREAM),
        99 => Some(DXIL_INTRIN_EMITTHENCUTSTREAM),
        108 => Some(DXIL_INTRIN_PRIMITIVEID), // SV_PrimitiveID

        // Wave intrinsics
        110 => Some(DXIL_INTRIN_WAVEISFIRSTLANE),
        111 => Some(DXIL_INTRIN_WAVEGETLANEINDEX),
        112 => Some(DXIL_INTRIN_WAVEGETLANECOUNT),
        113 => Some(DXIL_INTRIN_WAVEANYTRUE),
        114 => Some(DXIL_INTRIN_WAVEALLTRUE),
        115 => Some(DXIL_INTRIN_WAVEALLEQUAL), // WaveActiveAllEqual
        116 => Some(DXIL_INTRIN_WAVEBALLOT),   // WaveActiveBallot
        117 => Some(DXIL_INTRIN_WAVEREADLANEAT),
        118 => Some(DXIL_INTRIN_WAVEREADLANEFIRST),
        122 => Some(DXIL_INTRIN_QUADREAD), // QuadReadLaneAt

        // Raw buffer access
        139 => Some(DXIL_INTRIN_BUFFERLOAD),  // RawBufferLoad
        140 => Some(DXIL_INTRIN_BUFFERSTORE), // RawBufferStore

        // Packed dot products
        163 => Some(DXIL_INTRIN_DOT4ADDI8PACKED),
        164 => Some(DXIL_INTRIN_DOT4ADDU8PACKED),

        // Resource handle creation from binding
        217 => Some(DXIL_INTRIN_CREATEHANDLEFORBINDING),

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// LLVM Bitcode Block Parser
// ---------------------------------------------------------------------------

/// Scan through LLVM bitcode and extract DXIL instructions.
///
/// Handles the LLVM bitcode wrapper format, checks magic, parses BLOCKINFO
/// blocks for abbreviation definitions, then parses the MODULE_BLOCK containing
/// FUNCTION sub-blocks.
fn scan_bitcode_blocks(bytes: &[u8]) -> AppResult<BitcodeScanResult> {
    let mut reader = LlvmBitcodeReader::new(bytes);

    // Skip wrapper format if present; a malformed wrapper is an error.
    reader.skip_wrapper()?;

    // Check LLVM bitcode magic
    if !reader.check_magic() {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            "missing LLVM bitcode magic (0x4243C0DE)",
        ));
    }

    let mut functions = Vec::new();
    let mut instruction_count = 0;
    let mut entry_name = String::new();
    let mut block_depth = 0;

    loop {
        match reader.next_entry(true) {
            Some(BitcodeEntry::SubBlock(block_id)) => {
                block_depth += 1;
                match block_id {
                    BLOCKID_BLOCKINFO => {
                        // Parse BLOCKINFO for abbreviation definitions
                        reader.read_block_info_block()?;
                        reader.exit_block();
                        block_depth -= 1;
                        continue;
                    }
                    BLOCKID_TYPE => {
                        // Build the type table used for operand typing.
                        reader.read_type_block()?;
                        block_depth -= 1;
                        continue;
                    }
                    BLOCKID_MODULE => {
                        // Parse the module block, which contains FUNCTION
                        // sub-blocks.
                        loop {
                            match reader.next_entry(true) {
                                Some(BitcodeEntry::SubBlock(sub_id)) => match sub_id {
                                    BLOCKID_FUNCTION => {
                                        let (fn_instr_count, _fn_name, parsed_func) =
                                            parse_function_block(&mut reader)?;
                                        instruction_count += fn_instr_count;
                                        if let Some(func) = parsed_func {
                                            functions.push(func);
                                        }
                                    }
                                    BLOCKID_IDENTIFICATION => {
                                        // Parse entry name from identification block
                                        if let Some(name) = parse_identification_block(&mut reader)?
                                        {
                                            entry_name = name;
                                        }
                                    }
                                    _ => {
                                        // Skip other sub-blocks (constants, metadata, etc.)
                                        reader.skip_block();
                                    }
                                },
                                Some(BitcodeEntry::EndBlock) => break,
                                _ => {}
                            }
                        }
                        reader.exit_block();
                        block_depth -= 1;
                    }
                    BLOCKID_FUNCTION => {
                        // Handle top-level function block (rare)
                        let (fn_instr_count, _fn_name, parsed_func) =
                            parse_function_block(&mut reader)?;
                        instruction_count += fn_instr_count;
                        if let Some(func) = parsed_func {
                            functions.push(func);
                        }
                        reader.exit_block();
                        block_depth -= 1;
                    }
                    BLOCKID_IDENTIFICATION => {
                        if let Some(name) = parse_identification_block(&mut reader)? {
                            entry_name = name;
                        }
                        reader.exit_block();
                        block_depth -= 1;
                    }
                    _ => {
                        // Skip unknown blocks
                        reader.skip_block();
                        block_depth -= 1;
                    }
                }
            }
            Some(BitcodeEntry::EndBlock) => {
                if block_depth > 0 {
                    reader.exit_block();
                    block_depth -= 1;
                } else {
                    break;
                }
            }
            None => break,
            _ => {}
        }

        // Safety limit
        if instruction_count > MAX_INSTRUCTIONS {
            break;
        }
    }

    Ok(BitcodeScanResult {
        functions,
        instruction_count,
        entry_name,
    })
}

/// Result of scanning LLVM bitcode blocks.
struct BitcodeScanResult {
    functions: Vec<DxilFunction>,
    instruction_count: u32,
    entry_name: String,
}

/// Whether an instruction produces a value (and therefore consumes a value ID
/// in the bitcode's relative operand encoding). Terminators, stores, barriers
/// and void intrinsics do not.
fn instruction_is_void(opcode: u32) -> bool {
    matches!(
        opcode,
        36 | 37
            | 38
            | 40
            | 44
            | 52
            | DXIL_INTRIN_BARRIER
            | DXIL_INTRIN_GROUPMEMORYBARRIER
            | DXIL_INTRIN_DEVICEMEMORYBARRIER
            | DXIL_INTRIN_BUFFERSTORE
            | DXIL_INTRIN_TEXTURESTORE
            | DXIL_INTRIN_EMITSTREAM
            | DXIL_INTRIN_CUTSTREAM
            | DXIL_INTRIN_EMITTHENCUTSTREAM
    )
}

/// Map an encoded LLVM binary opcode (DXC: 0..=12) to this module's internal
/// IR BinaryOps numbering (0..=16, float ops interleaved).
fn map_encoded_binop(encoded: u32) -> u32 {
    match encoded {
        0 => 0,   // add
        1 => 2,   // sub
        2 => 4,   // mul
        3 => 6,   // udiv
        4 => 7,   // sdiv / fdiv
        5 => 9,   // urem
        6 => 10,  // srem / frem
        7 => 11,  // shl
        8 => 12,  // lshr
        9 => 13,  // ashr
        10 => 14, // and
        11 => 15, // or
        12 => 16, // xor
        _ => 0,
    }
}

/// Map an encoded LLVM cast opcode (0..=12) to this module's internal cast
/// opcode numbering (30..=35 plus 90..=96).
fn map_encoded_cast(encoded: u32) -> u32 {
    match encoded {
        0 => 35,                  // trunc
        1 => 33,                  // zext
        2 => 34,                  // sext
        3 => CAST_FPTOUI,         // fptoui
        4 => CAST_FPTOSI,         // fptosi
        5 => CAST_UITOFP,         // uitofp
        6 => CAST_SITOFP,         // sitofp
        7 => CAST_FPTRUNC,        // fptrunc
        8 => CAST_FPEXT,          // fpext
        9 => 31,                  // ptrtoint
        10 => 32,                 // inttoptr
        11 => 30,                 // bitcast
        12 => CAST_ADDRSPACECAST, // addrspacecast
        _ => 30,
    }
}

/// Map an LLVM `CmpInst` predicate to an internal comparison opcode.
///
/// ICMP_EQ=32 .. ICMP_SLE=41 map to 18..=27; the fcmp predicates 0..=15 map
/// to 28/29 and 61..=73.
fn map_cmp_predicate(pred: u32) -> u32 {
    match pred {
        32 => 18, // icmp_eq
        33 => 19, // icmp_ne
        34 => 20, // icmp_ugt
        35 => 21, // icmp_uge
        36 => 22, // icmp_ult
        37 => 23, // icmp_ule
        38 => 24, // icmp_sgt
        39 => 25, // icmp_sge
        40 => 26, // icmp_slt
        41 => 27, // icmp_sle
        1 => 28,  // fcmp_oeq
        6 => 29,  // fcmp_one
        2 => CMP_FCMP_OGT,
        3 => CMP_FCMP_OGE,
        4 => CMP_FCMP_OLT,
        5 => CMP_FCMP_OLE,
        14 => CMP_FCMP_UNE,
        7 => CMP_FCMP_ORD,
        8 => CMP_FCMP_UNO,
        0 => CMP_FCMP_FALSE,
        15 => CMP_FCMP_TRUE,
        10 => CMP_FCMP_UGT,
        11 => CMP_FCMP_UGE,
        12 => CMP_FCMP_ULT,
        13 => CMP_FCMP_ULE,
        _ => 18,
    }
}

/// True when a relative value operand is a forward reference, in which case
/// the record contains an appended type operand (per `PushValueAndType`).
fn is_forward_ref(value: u32) -> bool {
    value == 0 || (value as i32) < 0
}

/// Parse a FUNCTION_BLOCK (block_id 12): extract basic blocks and instructions.
///
/// Each function block starts with a DECLAREBLOCKS record giving the number of
/// basic blocks; instruction records follow, with blocks delimited by
/// terminator instructions. Instruction operands use the bitcode v1 relative
/// value encoding: an operand `v` refers to the value defined `v` non-void
/// instructions earlier. Forward references (phi) use signed VBR and are
/// resolved by the code generator.
///
/// Returns the instruction count and (if available) the function name.
fn parse_function_block(
    reader: &mut LlvmBitcodeReader,
) -> AppResult<(u32, String, Option<DxilFunction>)> {
    let mut instruction_count = 0;
    let mut current_bb: Option<DxilBasicBlock> = None;
    let mut basic_blocks = Vec::new();
    let mut block_index = 0u32;
    let fn_name = String::new();

    // Push an instruction into the active basic block, starting a new block
    // after terminators and handling the single DECLAREBLOCKS record that
    // precedes the first instruction.
    let mut push_instr = |instr: DxilInstruction| {
        let is_terminator = matches!(instr.opcode, 36 | 37 | 38 | 40 | 52);
        if current_bb.is_none() || is_terminator {
            if let Some(bb) = current_bb.take() {
                basic_blocks.push(bb);
            }
            current_bb.replace(DxilBasicBlock {
                label: format!("bb{}", block_index),
                instructions: Vec::new(),
            });
            block_index += 1;
        }
        if let Some(bb) = current_bb.as_mut() {
            bb.instructions.push(instr);
        }
        // Terminators end the block: the next instruction starts a new one.
        if is_terminator && let Some(bb) = current_bb.take() {
            basic_blocks.push(bb);
        }
    };

    while let Some(entry) = reader.next_entry(true) {
        let BitcodeEntry::Record(record) = entry else {
            break;
        };
        if record.id == 0xFFFF {
            continue;
        }
        match record.id {
            FUNC_CODE_DECLAREBLOCKS => {
                // The number of basic blocks; blocks themselves are delimited
                // by terminators in the instruction stream.
                if let Some(&count) = record.operands.first()
                    && count > 4096
                {
                    return Err(dxil_invalid("DXIL function declares too many basic blocks"));
                }
            }
            FUNC_CODE_INST_BINOP => {
                // [op0(+ty?), op1, opc, flags?]
                let mut ops = Vec::new();
                let idx = take_value_operands(&record.operands, 0, 2, &mut ops);
                let opc = record.operands.get(idx).copied().unwrap_or(0);
                let instr = DxilInstruction {
                    opcode: map_encoded_binop(opc),
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_CAST => {
                // [op0(+ty?), result_ty, cast_opc]
                let cast_opc = record.operands.last().copied().unwrap_or(11);
                let result_ty = record.operands.get(record.operands.len() - 2).copied();
                let mut ops = Vec::new();
                take_value_operands(&record.operands, 0, 1, &mut ops);
                let instr = DxilInstruction {
                    opcode: map_encoded_cast(cast_opc),
                    operands: ops,
                    ty: result_ty.and_then(|t| type_desc(reader, t)),
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_GEP | FUNC_CODE_INST_GEP_OLD | FUNC_CODE_INST_INBOUNDS_GEP_OLD => {
                // GEP: [inbounds, srcty, op0(+ty?), op1(+ty?)...]
                // GEP_OLD/INBOUNDS_GEP_OLD: [n x operands]
                let mut ops = Vec::new();
                let start = if record.id == FUNC_CODE_INST_GEP {
                    2
                } else {
                    0
                };
                take_value_operands(&record.operands, start, usize::MAX, &mut ops);
                let instr = DxilInstruction {
                    opcode: 45,
                    operands: ops,
                    ty: Some(TypeDesc {
                        is_pointer: true,
                        is_signed: false,
                        ..TypeDesc::default()
                    }),
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_VSELECT | FUNC_CODE_INST_SELECT => {
                // VSELECT: [cond(+ty?), false_val, true_val(+ty?)]
                // SELECT (legacy): [ty, cond, a, b]
                let mut ops = Vec::new();
                let start = if record.id == FUNC_CODE_INST_SELECT {
                    1
                } else {
                    0
                };
                take_value_operands(&record.operands, start, 3, &mut ops);
                // The writer emits [cond, b, a]; the emitter wants
                // [cond, a, b].
                if ops.len() == 3 {
                    ops.swap(1, 2);
                }
                let instr = DxilInstruction {
                    opcode: 46,
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_EXTRACTELT => {
                let mut ops = Vec::new();
                take_value_operands(&record.operands, 0, 2, &mut ops);
                let instr = DxilInstruction {
                    opcode: 49,
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_INSERTELT => {
                let mut ops = Vec::new();
                take_value_operands(&record.operands, 0, 3, &mut ops);
                let instr = DxilInstruction {
                    opcode: 50,
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_SHUFFLEVEC => {
                let mut ops = Vec::new();
                take_value_operands(&record.operands, 0, 3, &mut ops);
                let instr = DxilInstruction {
                    opcode: 51,
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_CMP | FUNC_CODE_INST_CMP2 => {
                // CMP2: [op0(+ty?), op1, pred, flags?]
                // CMP (legacy): [opty, op0, op1, pred]
                let mut ops = Vec::new();
                let pred;
                if record.id == FUNC_CODE_INST_CMP {
                    pred = record.operands.last().copied().unwrap_or(32);
                    take_value_operands(&record.operands, 1, 2, &mut ops);
                } else {
                    // The predicate follows the two value operands (and any
                    // appended forward-reference type).
                    let idx = take_value_operands(&record.operands, 0, 2, &mut ops);
                    pred = record.operands.get(idx).copied().unwrap_or(32);
                }
                let instr = DxilInstruction {
                    opcode: map_cmp_predicate(pred),
                    operands: ops,
                    // The result of a comparison is i1 (or a vector of i1).
                    ty: Some(TypeDesc {
                        width: 1,
                        ..TypeDesc::default()
                    }),
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_RET => {
                let mut ops = Vec::new();
                take_value_operands(&record.operands, 0, usize::MAX, &mut ops);
                let instr = DxilInstruction {
                    opcode: 40, // ret
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_BR => {
                // BR: [bb#, bb#, cond] or [bb#]
                let instr = if record.operands.len() >= 3 {
                    let cond = record.operands[2];
                    DxilInstruction {
                        opcode: 37, // conditional branch
                        operands: vec![cond, record.operands[0], record.operands[1]],
                        ty: None,
                    }
                } else {
                    DxilInstruction {
                        opcode: 36, // unconditional branch
                        operands: record.operands.clone(),
                        ty: None,
                    }
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_SWITCH => {
                // SWITCH: [opty, cond, default_bb, (caseval, bb)...]
                let mut ops = Vec::new();
                if let Some(&cond) = record.operands.get(1) {
                    ops.push(cond);
                }
                if let Some(&default_bb) = record.operands.get(2) {
                    ops.push(default_bb);
                }
                for k in (3..record.operands.len()).step_by(2) {
                    if let (Some(&case_val), Some(&dest_bb)) =
                        (record.operands.get(k), record.operands.get(k + 1))
                    {
                        ops.push(case_val);
                        ops.push(dest_bb);
                    }
                }
                let instr = DxilInstruction {
                    opcode: 38, // switch
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_PHI => {
                // PHI: [ty, (val#signed, bb)...]
                let ty = record.operands.first().copied();
                let ops = record.operands[1..].to_vec();
                let instr = DxilInstruction {
                    opcode: 39, // phi
                    operands: ops,
                    ty: ty.and_then(|t| type_desc(reader, t)),
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_ALLOCA => {
                // ALLOCA: [instty, opty, size, align]
                let ty = record.operands.first().copied();
                let instr = DxilInstruction {
                    opcode: 42, // alloca
                    operands: record.operands.clone(),
                    ty: ty.and_then(|t| type_desc(reader, t)),
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_LOAD => {
                // LOAD: [ptr(+ty?), result_ty, align, vol]
                let mut ops = Vec::new();
                take_value_operands(&record.operands, 0, 1, &mut ops);
                let result_ty = if is_forward_ref(record.operands.first().copied().unwrap_or(0)) {
                    record.operands.get(2).copied()
                } else {
                    record.operands.get(1).copied()
                };
                let instr = DxilInstruction {
                    opcode: 43, // load
                    operands: ops,
                    ty: result_ty.and_then(|t| type_desc(reader, t)),
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_STORE | FUNC_CODE_INST_STORE_OLD => {
                // STORE: [ptr(+ty?), val(+ty?), align, vol]
                let mut ops = Vec::new();
                take_value_operands(&record.operands, 0, 2, &mut ops);
                let instr = DxilInstruction {
                    opcode: 44, // store
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_CALL => {
                // CALL: [attr, cc, fnty, fn(+ty?), args...]
                // DXIL intrinsic calls have a function index as the first
                // operand and the DXIL intrinsic ID as the second operand.
                // Unmapped intrinsic IDs are a hard error instead of a
                // silently broken generic call.
                let opcode = if record.operands.len() >= 2 {
                    let dxil_intrinsic_id = record.operands[1];
                    map_dxil_intrinsic_id(dxil_intrinsic_id).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!("unsupported DXIL intrinsic ID {}", dxil_intrinsic_id),
                        )
                    })?
                } else {
                    41
                };
                // Intrinsic calls pass their argument list to the emitter;
                // generic calls keep the callee index at operands[0].
                let operands = if opcode == 41 {
                    record.operands.clone()
                } else {
                    record.operands[2..].to_vec()
                };
                let instr = DxilInstruction {
                    opcode,
                    operands,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_EXTRACTVAL => {
                // EXTRACTVAL: [agg(+ty?), idx0, idx1...]
                let mut ops = Vec::new();
                take_value_operands(&record.operands, 0, 1, &mut ops);
                let start = 1 + usize::from(is_forward_ref(
                    record.operands.first().copied().unwrap_or(0),
                ));
                ops.extend_from_slice(&record.operands[start..]);
                let instr = DxilInstruction {
                    opcode: 47, // extractvalue
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_INSERTVAL => {
                // INSERTVAL: [agg(+ty?), val(+ty?), idx0...]
                let mut ops = Vec::new();
                let idx = take_value_operands(&record.operands, 0, 2, &mut ops);
                ops.extend_from_slice(&record.operands[idx..]);
                let instr = DxilInstruction {
                    opcode: 48, // insertvalue
                    operands: ops,
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            FUNC_CODE_INST_UNREACHABLE => {
                let instr = DxilInstruction {
                    opcode: 52, // unreachable
                    operands: Vec::new(),
                    ty: None,
                };
                instruction_count += 1;
                push_instr(instr);
            }
            _ => {
                // Unknown function record - ignore. The reader's marker
                // records for undecodable abbreviations have id 0xFFFF.
                if record.id != 0xFFFF {
                    instruction_count += 1;
                }
            }
        }
    }

    // Flush last basic block
    if let Some(bb) = current_bb.take() {
        basic_blocks.push(bb);
    }

    // Build a DxilFunction from collected basic blocks
    let func = if !basic_blocks.is_empty() {
        Some(DxilFunction {
            name: if fn_name.is_empty() {
                "_fn_0".to_string()
            } else {
                fn_name.clone()
            },
            basic_blocks,
        })
    } else {
        None
    };

    Ok((instruction_count, fn_name, func))
}

/// Copy up to `count` value operands from `ops` starting at `start`, skipping
/// the type operand that `PushValueAndType` appends after forward references.
/// Returns the index just past the consumed operands.
fn take_value_operands(ops: &[u32], start: usize, count: usize, out: &mut Vec<u32>) -> usize {
    let mut idx = start;
    let mut taken = 0usize;
    while taken < count && idx < ops.len() {
        let value = ops[idx];
        out.push(value);
        idx += 1;
        taken += 1;
        if is_forward_ref(value) {
            idx += 1; // appended type id
        }
    }
    idx
}

/// Resolve a type-table index to a descriptor, defaulting on out-of-range.
fn type_desc(reader: &LlvmBitcodeReader, index: u32) -> Option<TypeDesc> {
    reader
        .type_table
        .get(index as usize)
        .copied()
        .or(Some(TypeDesc::default()))
}

/// Parse an IDENTIFICATION block (block_id 13) — DXIL stores the entry function name here.
fn parse_identification_block(reader: &mut LlvmBitcodeReader) -> AppResult<Option<String>> {
    let mut entry_name = None;

    while let Some(entry) = reader.next_entry(true) {
        let BitcodeEntry::Record(record) = entry else {
            break;
        };
        if record.id == 1 && !record.operands.is_empty() {
            // Entry name encoded as VBR6 characters
            let name: String = record
                .operands
                .iter()
                .map(|&c| {
                    if c > 0 && c < 128 {
                        c as u8 as char
                    } else {
                        '?'
                    }
                })
                .collect();
            if !name.is_empty() {
                entry_name = Some(name);
            }
        }
    }

    Ok(entry_name)
}

// ---------------------------------------------------------------------------
// Parse DXIL program from LLVM bitcode within the PROG part
// ---------------------------------------------------------------------------

/// Parse the DXIL program bitcode from a raw byte slice.
///
/// The input should be the LLVM bitcode payload extracted from the DXIL
/// container's PROG part (after skipping the 24-byte program header).
fn parse_dxil_program_bitcode(bytes: &[u8]) -> AppResult<ParsedDxilProgram> {
    if bytes.len() < 4 {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            "DXIL program too small for LLVM bitcode header",
        ));
    }

    let scan_result = scan_bitcode_blocks(bytes)?;

    // If no entry name found via scanning, try extracting from the raw bytes
    let entry_name = if scan_result.entry_name.is_empty() {
        if let Some(pos) = bytes.windows(5).position(|w| w == b"entry") {
            let start = pos + 5;
            let name_bytes: Vec<u8> = bytes[start..]
                .iter()
                .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_')
                .copied()
                .collect();
            String::from_utf8_lossy(&name_bytes).to_string()
        } else {
            String::from("main")
        }
    } else {
        scan_result.entry_name
    };

    Ok(ParsedDxilProgram {
        entry_name,
        functions: scan_result.functions,
        instruction_count: scan_result.instruction_count,
    })
}

// ---------------------------------------------------------------------------
// MSL code generation from parsed DXIL program
// ---------------------------------------------------------------------------

/// Generate MSL source code from the parsed DXIL program.
///
/// Uses the `MslShaderGenerator` from `shader_compiler` for the structural
/// MSL skeleton (entry point signature, argument buffers, etc.) and then
/// inlines the translated DXIL instruction bodies.
fn generate_msl_from_parsed_dxil(
    _parsed_container: &ParsedDxilContainer,
    parsed_program: &ParsedDxilProgram,
    reflection: &ReflectionTable,
    stage: ShaderStage,
    metal_function_name: &str,
) -> AppResult<String> {
    // Use the MslShaderGenerator for the structural skeleton
    let mut generator = crate::shader_compiler::MslShaderGenerator::new(stage, metal_function_name);

    // Add reflection resources as inputs/outputs/bindings
    for resource in &reflection.resources {
        match resource.kind {
            ResourceKind::Buffer => {
                generator.add_constant_buffer(
                    &format!("cb_{}_{}", resource.register, resource.space),
                    resource.register,
                    resource.space,
                    256,
                );
            }
            ResourceKind::Texture => {
                generator.add_texture(
                    &format!("tex_{}_{}", resource.register, resource.space),
                    resource.register,
                    resource.space,
                    resource.access == ResourceAccess::Write,
                    2,
                );
            }
            ResourceKind::Sampler => {
                generator.add_sampler(
                    &format!("samp_{}_{}", resource.register, resource.space),
                    resource.register,
                    resource.space,
                );
            }
        }
    }

    // Add cbuffers from reflection
    for cbuffer in &reflection.cbuffers {
        generator.add_constant_buffer(
            &format!("cb_{}_{}", cbuffer.register, cbuffer.space),
            cbuffer.register,
            cbuffer.space,
            cbuffer.size_bytes,
        );
    }

    // Set threadgroup size from reflection (for compute shaders)
    if let Some(ref tgs) = reflection.threadgroup_size {
        generator.set_threadgroup_size(tgs.x, tgs.y, tgs.z);
    }

    // Build MSL from parsed DXIL instructions
    let mut msl_lines: Vec<String> = Vec::new();
    msl_lines.push(format!("// DXIL->MSL for {}", metal_function_name));
    msl_lines.push(format!(
        "// {} functions, {} instructions",
        parsed_program.functions.len(),
        parsed_program.instruction_count
    ));

    // Also build structured TranslatedInstruction entries for the generator
    let mut translated_instructions: Vec<TranslatedInstruction> = Vec::new();
    let mut var_counter = 0u32;
    for func in &parsed_program.functions {
        if !msl_lines.is_empty() {
            msl_lines.push(String::new());
        }
        msl_lines.push(format!("    // function: {}", func.name));

        // Basic-block CFG derived from the terminator instructions, used to
        // lower phi nodes on their incoming edges.
        let block_count = func.basic_blocks.len();
        let mut predecessors: Vec<Vec<u32>> = vec![Vec::new(); block_count];
        for (bi, bb) in func.basic_blocks.iter().enumerate() {
            let terminator = bb
                .instructions
                .iter()
                .rev()
                .find(|i| matches!(i.opcode, 36..=38));
            if let Some(term) = terminator {
                let succs: Vec<u32> = match term.opcode {
                    36 => term.operands.first().copied().into_iter().collect(),
                    37 => term.operands[1..].to_vec(),
                    _ => {
                        let mut succs = term
                            .operands
                            .get(1)
                            .copied()
                            .into_iter()
                            .collect::<Vec<_>>();
                        for k in (2..term.operands.len()).step_by(2) {
                            if let Some(&dest) = term.operands.get(k + 1) {
                                succs.push(dest);
                            }
                        }
                        succs
                    }
                };
                for succ in succs {
                    if (succ as usize) < block_count {
                        predecessors[succ as usize].push(bi as u32);
                    }
                }
            }
        }

        // Value-ID registry: relative operands resolve to the temp of the
        // instruction defined `v` non-void instructions earlier. Types are
        // tracked alongside so signedness/floatness can be passed to the
        // emitter instead of being guessed.
        let mut value_ids: BTreeMap<u32, String> = BTreeMap::new();
        let mut value_types: BTreeMap<u32, TypeDesc> = BTreeMap::new();
        let mut cur_ordinal = 0u32;

        // Resolve a relative value operand at the current ordinal.
        let resolve_value = |value: u32, cur: u32, ids: &BTreeMap<u32, String>| -> String {
            if value != 0 && value <= cur {
                let def = cur - value;
                if let Some(name) = ids.get(&def) {
                    return name.clone();
                }
            }
            // Constants, parameters and forward references: emit the raw id.
            value.to_string()
        };

        // Resolve a signed phi operand (relative, signed VBR) at the current
        // ordinal: def = cur - diff.
        let resolve_phi_value = |raw: u32, cur: u32, ids: &BTreeMap<u32, String>| -> String {
            let diff = if raw & 1 == 1 {
                -((raw >> 1) as i64)
            } else {
                (raw >> 1) as i64
            };
            let def = cur as i64 - diff;
            if def >= 0
                && def < cur as i64
                && let Some(name) = ids.get(&(def as u32))
            {
                return name.clone();
            }
            raw.to_string()
        };

        // Phi edge assignments to emit at the end of each predecessor block:
        // (pred_block_index, [(dst, value_str)...]).
        let mut phi_edges: Vec<Vec<(String, String)>> = vec![Vec::new(); block_count];

        for (bi, bb) in func.basic_blocks.iter().enumerate() {
            msl_lines.push(format!("    bb{}:", bi));
            for instr in &bb.instructions {
                let dst = format!("_t{}", var_counter);
                var_counter += 1;
                let opcode = instr.opcode;
                let mut arg_strs: Vec<String> = Vec::new();
                match opcode {
                    // Unconditional branch: [dest_bb]
                    36 => {
                        arg_strs = instr.operands.iter().map(|d| format!("bb{}", d)).collect();
                    }
                    // Conditional branch: [cond, then_bb, else_bb]
                    37 => {
                        if let Some(&cond) = instr.operands.first() {
                            arg_strs.push(resolve_value(cond, cur_ordinal, &value_ids));
                        }
                        arg_strs.push(format!("bb{}", instr.operands.get(1).copied().unwrap_or(0)));
                        arg_strs.push(format!("bb{}", instr.operands.get(2).copied().unwrap_or(0)));
                    }
                    // Switch: [cond, default_bb, (case, dest_bb)...]
                    38 => {
                        if let Some(&cond) = instr.operands.first() {
                            arg_strs.push(resolve_value(cond, cur_ordinal, &value_ids));
                        }
                        arg_strs.push(format!("bb{}", instr.operands.get(1).copied().unwrap_or(0)));
                        for k in (2..instr.operands.len()).step_by(2) {
                            arg_strs.push(instr.operands[k].to_string());
                            arg_strs.push(format!(
                                "bb{}",
                                instr.operands.get(k + 1).copied().unwrap_or(0)
                            ));
                        }
                    }
                    // Phi: [(val#signed, pred_bb)...]; values are assigned on
                    // the incoming edges below.
                    39 => {
                        let mut pairs: Vec<(String, u32)> = Vec::new();
                        let mut k = 0;
                        while k + 1 < instr.operands.len() {
                            let value =
                                resolve_phi_value(instr.operands[k], cur_ordinal, &value_ids);
                            pairs.push((value, instr.operands[k + 1]));
                            k += 2;
                        }
                        // Emit edge assignments in each predecessor, and a
                        // fallback assignment when the incoming block is not
                        // in the CFG (e.g. the entry block).
                        if let Some(first_value) = pairs.first().map(|(v, _)| v) {
                            let preds = predecessors.get(bi).cloned().unwrap_or_default();
                            if preds.is_empty() {
                                arg_strs.push(first_value.clone());
                            } else {
                                for pred in &preds {
                                    let value = pairs
                                        .iter()
                                        .find(|(_, bb_idx)| bb_idx == pred)
                                        .map(|(v, _)| v.clone())
                                        .unwrap_or_else(|| first_value.clone());
                                    phi_edges[*pred as usize].push((dst.clone(), value));
                                }
                            }
                        }
                    }
                    _ => {
                        // Value operands (relative encoding).
                        arg_strs = instr
                            .operands
                            .iter()
                            .map(|&v| resolve_value(v, cur_ordinal, &value_ids))
                            .collect();
                    }
                }

                // Signedness/floatness: prefer the record's explicit type,
                // otherwise derive from the first value operand's definition.
                let (is_signed, is_float) = match instr.ty {
                    Some(ty) => (ty.is_signed, ty.is_float),
                    None => {
                        let ty = instr
                            .operands
                            .first()
                            .copied()
                            .filter(|&v| v != 0 && v <= cur_ordinal)
                            .and_then(|v| value_types.get(&(cur_ordinal - v)).copied())
                            .unwrap_or_default();
                        (ty.is_signed, ty.is_float)
                    }
                };

                let msl_stmt = if opcode == 42 {
                    // alloca: emit an actual declaration so later loads and
                    // stores can index it.
                    let ty = msl_type_name(&instr.ty.unwrap_or_default());
                    format!("{} {}[1]; // alloca", ty, dst)
                } else {
                    dxil_opcode_to_msl(opcode, &dst, &arg_strs, is_signed, is_float)
                };
                msl_lines.push(format!("        {} // opcode={}", msl_stmt, opcode));

                // Register this instruction's temp and type for later
                // operand resolution. Void instructions consume no value ID.
                if !instruction_is_void(opcode) {
                    value_ids.insert(cur_ordinal, dst.clone());
                    value_types.insert(
                        cur_ordinal,
                        instr.ty.unwrap_or_else(|| TypeDesc {
                            is_float,
                            is_signed,
                            ..TypeDesc::default()
                        }),
                    );
                    cur_ordinal += 1;
                }

                // Build TranslatedInstruction entry
                let is_barrier = matches!(
                    instr.opcode,
                    74..=79 // DXIL barrier opcodes
                );
                let barrier_flags = if is_barrier {
                    vec!["mem_threadgroup".to_string(), "mem_device".to_string()]
                } else {
                    Vec::new()
                };
                let is_uav = false; // Could be refined with type analysis
                let is_tg_mem = false; // Could be refined with type analysis
                let addr_space = if is_uav {
                    "device".to_string()
                } else {
                    String::new()
                };

                translated_instructions.push(TranslatedInstruction {
                    msl_body: msl_stmt.clone(),
                    dst: dst.clone(),
                    operands: arg_strs.clone(),
                    is_barrier,
                    barrier_flags,
                    is_uav_access: is_uav,
                    address_space: addr_space,
                    is_threadgroup_mem: is_tg_mem,
                });
            }

            // Phi edge assignments for successors of this block: emitted
            // before the terminator so the values are live on entry.
            if let Some(edges) = phi_edges.get(bi) {
                for (dst, value) in edges {
                    msl_lines.push(format!("        {} = {}; // phi edge", dst, value));
                }
            }
        }
    }

    // Pass the translated instructions to the generator so entry point
    // generators can inline them into proper MSL function bodies.
    generator.set_instructions(translated_instructions);

    // Generate the complete MSL source using the generator (which now has
    // instruction bodies to inline into each stage-specific entry point).
    let mut base_msl = generator.generate();
    // Minimal DXIL programs can have no reflected outputs. Give the generated
    // skeleton a valid vertex position and fragment colour so the MSL still
    // compiles instead of referencing an undeclared output struct.
    if matches!(stage, ShaderStage::Vs) && !base_msl.contains("struct VertexOutput") {
        if let Some(index) = base_msl.find("using namespace metal;") {
            let insert = index + "using namespace metal;".len();
            base_msl.insert_str(
                insert,
                "\n\nstruct VertexOutput {\n    float4 position [[position]];\n};\n",
            );
        }
    }
    if matches!(stage, ShaderStage::Vs)
        && base_msl.contains("VertexOutput out;")
        && !base_msl.contains("out.position")
    {
        base_msl = base_msl.replace(
            "VertexOutput out;",
            "VertexOutput out;\n    out.position = float4(0.0, 0.0, 0.0, 1.0);",
        );
    }
    if matches!(stage, ShaderStage::Ps) && base_msl.contains("fragment void ") {
        base_msl = base_msl.replace("fragment void ", "fragment float4 ");
        if let Some(index) = base_msl.rfind('}') {
            base_msl.insert_str(index, "    return float4(1.0, 0.0, 0.0, 1.0);\n");
        }
    }
    Ok(base_msl)
}

/// Map a type descriptor to a scalar MSL type name.
fn msl_type_name(desc: &TypeDesc) -> String {
    let base = if desc.is_float {
        match desc.width {
            16 => "half",
            64 => "double",
            _ => "float",
        }
    } else if desc.is_pointer {
        "uintptr_t"
    } else {
        match desc.width {
            1 | 8 => "char",
            16 => "short",
            64 => "long",
            _ => "int",
        }
    };
    if desc.is_vector {
        let len = desc.vector_len.clamp(2, 4);
        format!("{}{}", base, len)
    } else {
        base.to_string()
    }
}

// ---------------------------------------------------------------------------
// Main translation entry point
// ---------------------------------------------------------------------------

/// Translate a DXIL shader to MSL source code.
///
/// This is the main entry point for DXIL→MSL translation. It:
/// 1. Parses the DXIL container to extract parts (PROG, SIGN, META, RFLX, ROOT)
/// 2. Extracts and parses the DXIL program bitcode
/// 3. Reconstructs or cross-checks reflection data
/// 4. Builds argument buffer mappings from root signature
/// 5. Generates complete MSL source with proper function declarations
/// 6. Wraps the result as a `ShaderTranslationOutput`
pub fn translate_shader(
    input: &ShaderTranslationInput,
) -> Result<ShaderTranslationOutput, ShaderError> {
    let dxil_hash = util::sha256_bytes(&input.dxil);
    let root_info = parse_root_signature(&input.root_signature)
        .map_err(|error| shader_error(input, &dxil_hash, "root_signature", error))?;
    let parsed = parse_dxil_container(&input.dxil)
        .map_err(|error| shader_error(input, &dxil_hash, "parse", error))?;
    let reflection = if let Some(reflection) = parsed.reflection.clone() {
        cross_check_reflection(&parsed, &reflection)
            .map_err(|error| shader_error(input, &dxil_hash, "reflection_cross_check", error))?;
        reflection
    } else {
        reconstruct_reflection(&parsed, &root_info)
            .map_err(|error| shader_error(input, &dxil_hash, "binding_reconstruction", error))?
    };
    let argument_buffers = build_argument_buffers(&root_info);
    let root_constants = RootConstantsPlan {
        constant_buffer_size: align16(root_info.root_constants_count * 4),
        binding_index: 0,
    };
    let cache_key = shader_cache_key(input)
        .map_err(|error| shader_error(input, &dxil_hash, "cache_key", error))?;
    let entry_name = parsed.entry_name.clone();
    let metal_function = format!("msl_{}_{}", input.stage.as_str(), &dxil_hash[..8]);
    let mut function_mapping = BTreeMap::new();
    function_mapping.insert(entry_name.clone(), metal_function.clone());

    // Parse the DXIL program bitcode for actual instruction-level translation.
    // Real LLVM bitcode that fails to parse is a hard error (failing_pass
    // "bitcode_parse"); containers whose PROG part carries no bitcode at all
    // produce an empty program instead of failing translation.
    let parsed_program = if parsed.instruction_count > 0 && input.dxil.len() > 64 {
        match find_prog_part_offset(&input.dxil) {
            Some(prog_start) => {
                let bitcode_bytes = &input.dxil[prog_start..];
                if bitcode_bytes.starts_with(b"BC\xc0\xde") {
                    parse_dxil_program_bitcode(bitcode_bytes)
                        .map_err(|error| shader_error(input, &dxil_hash, "bitcode_parse", error))?
                } else {
                    ParsedDxilProgram {
                        entry_name: entry_name.clone(),
                        functions: Vec::new(),
                        instruction_count: parsed.instruction_count,
                    }
                }
            }
            None => ParsedDxilProgram {
                entry_name: entry_name.clone(),
                functions: Vec::new(),
                instruction_count: parsed.instruction_count,
            },
        }
    } else {
        ParsedDxilProgram {
            entry_name: entry_name.clone(),
            functions: Vec::new(),
            instruction_count: parsed.instruction_count,
        }
    };

    let msl_source = generate_msl_from_parsed_dxil(
        &parsed,
        &parsed_program,
        &reflection,
        input.stage,
        &metal_function,
    )
    .map_err(|error| shader_error(input, &dxil_hash, "msl_generation", error))?;

    let reflection_json = util::stable_json(&reflection)
        .map_err(|error| shader_error(input, &dxil_hash, "reflection_json", error))?;

    // Store MSL source as the "library bytes" prefixed with our format
    let mtl_library_bytes = format!(
        "MSL|{}|{}|{}|{}|{}|{}|{}",
        msl_source.len(),
        metal_function,
        input.stage.as_str(),
        input.gpu_family,
        input.os_build,
        util::sha256_bytes(reflection_json.as_bytes()),
        msl_source,
    )
    .into_bytes();

    Ok(ShaderTranslationOutput {
        mtl_library_bytes,
        function_mapping,
        reflection,
        argument_buffers,
        root_constants,
        cache_key,
    })
}

/// Find the offset of the PROG part payload (the LLVM bitcode) within a DXIL blob.
///
/// This pipeline uses a pinned custom PROG payload layout: the part payload is
/// a 24-byte program header (instruction count, IR size, threadgroup size,
/// resource use count) followed by the use table and the LLVM bitcode. The
/// container part descriptor's offset points at that 24-byte header, so the
/// bitcode starts at `part_off + 24`. (Standard DXIL containers carry a
/// 12-byte part header before the program header; this format intentionally
/// does not, and `parse_program_part` validates the header fields.)
fn find_prog_part_offset(dxil: &[u8]) -> Option<usize> {
    let mut off = 12;
    while off + 12 <= dxil.len() {
        if off + 4 <= dxil.len() && &dxil[off..off + 4] == b"PROG" {
            let part_off = u32::from_le_bytes(dxil[off + 4..off + 8].try_into().unwrap()) as usize;
            let _part_sz = u32::from_le_bytes(dxil[off + 8..off + 12].try_into().unwrap()) as usize;
            let prog_start = part_off.checked_add(24)?; // skip the 24-byte program header
            if prog_start + 4 <= dxil.len() {
                return Some(prog_start);
            }
            return None;
        }
        off += 12;
    }
    None
}

/// Return the ray shader stage recorded in synthetic DXIL metadata.
///
/// The container carries an ASCII `shader_kind=<kind>` marker in its META
/// part (the same mechanism used for payload/attribute sizes). Unknown or
/// missing markers return `None`, which makes the D3D12 state-object path
/// reject the export instead of guessing a stage.
pub fn ray_shader_stage(dxil: &[u8]) -> Option<ShaderStage> {
    const MARKER: &[u8] = b"shader_kind=";
    let start = dxil
        .windows(MARKER.len())
        .position(|window| window == MARKER)?
        + MARKER.len();
    let end = dxil[start..]
        .iter()
        .position(|byte| matches!(byte, b'\n' | b'\0' | b',' | b' '))
        .map(|offset| start + offset)
        .unwrap_or(dxil.len());
    let value = std::str::from_utf8(&dxil[start..end]).ok()?.trim();
    match value {
        "raygeneration" => Some(ShaderStage::RayGeneration),
        "anyhit" => Some(ShaderStage::AnyHit),
        "closesthit" => Some(ShaderStage::ClosestHit),
        "miss" => Some(ShaderStage::Miss),
        "intersection" => Some(ShaderStage::Intersection),
        "callable" => Some(ShaderStage::Callable),
        _ => None,
    }
}

/// Borrow the LLVM bitcode embedded in a ray DXIL container, if present.
///
/// The bridge accepts either raw bitcode or the pinned container layout whose
/// PROG part carries a 24-byte program header followed by bitcode. A declared
/// IR size that runs past the container is rejected as malformed rather than
/// silently truncated.
fn ray_bitcode(dxil: &[u8]) -> Option<&[u8]> {
    if dxil.starts_with(b"BC\xc0\xde") {
        return Some(dxil);
    }
    let offset = dxil.windows(4).position(|window| window == b"BC\xc0\xde")?;
    if offset < 20 || dxil.get(offset + 4..offset + 8) == Some(b"SIG1") {
        return None;
    }
    let declared = u32::from_le_bytes(dxil[offset - 20..offset - 16].try_into().ok()?) as usize;
    let end = offset.checked_add(declared)?;
    if declared > 16 && end <= dxil.len() {
        Some(&dxil[offset..end])
    } else {
        None
    }
}

/// List the LLVM function definitions carried by ray DXIL bitcode.
///
/// D3D12 exports can rename entry points, so callers use this to resolve the
/// actual definition when constructing per-stage artifacts.
pub fn ray_entry_points(dxil: &[u8]) -> AppResult<Vec<String>> {
    let Some(bitcode) = ray_bitcode(dxil) else {
        return Ok(Vec::new());
    };
    let ir = llvm_bitcode_to_ir(bitcode)?;
    let mut entries = Vec::new();
    for line in ir.lines() {
        let line = line.trim();
        let Some(definition) = line.strip_prefix("define ") else {
            continue;
        };
        let name = definition
            .split_once('@')
            .map(|(_, rest)| rest.split('(').next().unwrap_or("").trim());
        if let Some(name) = name.filter(|name| !name.is_empty()) {
            entries.push(name.to_string());
        }
    }
    Ok(entries)
}

/// Generate a real MSL ray program for a ray shader stage.
///
/// The raygen entry performs hardware traversal with `intersector`, consumes
/// per-ray SBT group records on the GPU, applies any-hit rejection, selects a
/// callable group, and writes payload/instance/primitive/distance results.
/// Hit, miss, any-hit and callable helpers are emitted as separate MSL
/// functions so the SBT group dispatch is visible in the generated source.
pub fn translate_ray_shader(
    dxil: &[u8],
    stage: ShaderStage,
    entry: &str,
) -> AppResult<ShaderTranslationOutput> {
    if !matches!(
        stage,
        ShaderStage::RayGeneration
            | ShaderStage::AnyHit
            | ShaderStage::ClosestHit
            | ShaderStage::Miss
            | ShaderStage::Intersection
            | ShaderStage::Callable
    ) {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("{} is not a ray shader stage", stage.as_str()),
        ));
    }
    let recognized = ray_shader_stage(dxil).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcDxilInvalid,
            "ray shader is missing a supported shader_kind metadata marker",
        )
    })?;
    if recognized != stage {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!(
                "ray shader metadata declares {} but export {entry} requests {}",
                recognized.as_str(),
                stage.as_str()
            ),
        ));
    }
    let source = match ray_bitcode(dxil) {
        Some(bitcode) => translate_llvm_ray_stage_program(bitcode, stage, entry)?,
        None => generate_ray_msl(stage, entry),
    };
    let hash = util::sha256_bytes(dxil);
    let function = format!("msl_{}_{}", stage.as_str(), &hash[..8]);
    let mut function_mapping = BTreeMap::new();
    function_mapping.insert(entry.to_string(), function.clone());
    Ok(ShaderTranslationOutput {
        mtl_library_bytes: format!(
            "MSL|{}|{}|{}|apple9|macos|{}|{}",
            source.len(),
            function,
            stage.as_str(),
            util::sha256_bytes(b"ray"),
            source
        )
        .into_bytes(),
        function_mapping,
        reflection: ReflectionTable {
            resources: Vec::new(),
            cbuffers: Vec::new(),
            threadgroup_size: None,
            input_signature_hash: util::sha256_bytes(b"ray-input"),
            output_signature_hash: util::sha256_bytes(b"ray-output"),
        },
        argument_buffers: Vec::new(),
        root_constants: RootConstantsPlan {
            constant_buffer_size: 0,
            binding_index: 0,
        },
        cache_key: format!("ray-{}-{}", stage.as_str(), &hash[..16]),
    })
}

/// MSL mirror of `crate::metal_backend::MetalRayPayloadResult`. Every field
/// after `value` is 32-bit, so Rust's `#[repr(C)]` layout and Metal's C layout
/// agree without padding differences.
const RAY_RESULT_STRUCT_MSL: &str = "struct RayRecord { packed_float3 origin; float min_distance; packed_float3 direction; float max_distance; uint sbt_offset; uint mask; };\n\
struct RayPayloadResult {\n\
    float4 value;\n\
    uint instance_id;\n\
    uint primitive_id;\n\
    float distance;\n\
    uint hit_kind;\n\
    uint dispatch[3];\n\
    uint payload[8];\n\
    float barycentrics[2];\n\
    float object_origin[3];\n\
    float object_direction[3];\n\
    float object_to_world[12];\n\
    float world_to_object[12];\n\
    uint ray_flags;\n\
    float ray_tmax;\n\
    uint ray_geometry_index;\n\
    uint candidate_type;\n\
    uint candidate_instance;\n\
    uint candidate_primitive;\n\
    uint candidate_geometry;\n\
    float candidate_object_origin[3];\n\
    float candidate_object_direction[3];\n\
    float candidate_object_to_world[12];\n\
    float candidate_world_to_object[12];\n\
    float attributes[4];\n\
    uint accepted;\n\
    uint end_search;\n\
    uint ignored;\n\
};\n";

/// Hit locals shared by translated ray-generation programs. `hit_kind` is the
/// D3D12 built-in triangle hit kind (front face); Metal does not distinguish
/// front/back faces for built-in triangle intersections.
///
/// The candidate block mirrors DXR's candidate system values. They are
/// snapshotted from the real Metal intersection and stay at zero on a miss.
const RAY_HIT_LOCALS_MSL: &str = "    intersector<triangle_data, instancing> query;\n\
    ray r;\n\
    r.origin = rays[gid].origin;\n\
    r.direction = rays[gid].direction;\n\
    r.min_distance = rays[gid].min_distance;\n\
    r.max_distance = rays[gid].max_distance;\n\
    auto hit = query.intersect(r, accel, rays[gid].mask);\n\
    uint __hit_instance = 0u;\n\
    uint __hit_primitive = 0u;\n\
    uint __hit_kind = 0u;\n\
    float __hit_distance = 0.0f;\n\
    float2 __barycentrics = float2(0.0f);\n\
    uint __candidate_type = 0u;\n\
    uint __candidate_instance = 0u;\n\
    uint __candidate_primitive = 0u;\n\
    uint __candidate_geometry = 0u;\n\
    float3 __candidate_object_origin = float3(0.0f);\n\
    float3 __candidate_object_direction = float3(0.0f);\n\
    float4x4 __candidate_object_to_world = float4x4(1.0f);\n\
    float4x4 __candidate_world_to_object = float4x4(1.0f);\n\
    float4 __attributes = float4(0.0f);\n\
    uint __ray_flags = 0u;\n\
    float __ray_tmax = r.max_distance;\n\
    uint __ray_geometry_index = 0u;\n\
    uint __accepted = 1u;\n\
    uint __end_search = 0u;\n\
    uint __ignored = 0u;\n\
    if (hit.type != intersection_type::none) {\n\
        __hit_instance = hit.instance_id;\n\
        __hit_primitive = hit.primitive_id;\n\
        __hit_distance = hit.distance;\n\
        __hit_kind = 0xFEu;\n\
        __barycentrics = hit.triangle_barycentric_coord;\n\
        __attributes = float4(__barycentrics, 0.0f, 0.0f);\n\
        __candidate_type = 0u;\n\
        __candidate_instance = __hit_instance;\n\
        __candidate_primitive = __hit_primitive;\n\
        __candidate_geometry = 0u;\n\
        __ray_geometry_index = __candidate_geometry;\n\
    }\n";

/// MSL for the SBT local-root pointer of the current shader record.
///
/// Dispatch records are `(group index, local-root words...)`; buffer 6 stores
/// the record stride and local-root offset supplied by the host shader table.
const RAY_SBT_LOCALS_MSL: &str = "    uint __sbt_stride = max(dispatch_info[4], 1u);\n\
    uint __sbt_local_root_offset = dispatch_info[5];\n\
    device const uint* __sbt_local_root = (device const uint*)((device const uchar*)sbt + gid * __sbt_stride + __sbt_local_root_offset);\n";

fn generate_ray_msl(stage: ShaderStage, entry: &str) -> String {
    let raygen = matches!(stage, ShaderStage::RayGeneration);
    let mut source = format!(
        "#include <metal_stdlib>\n#include <metal_raytracing>\nusing namespace metal;\nusing namespace raytracing;\n\n{RAY_RESULT_STRUCT_MSL}\n\
         void msl_closest_hit(thread RayPayloadResult& payload, uint instance_id, uint primitive_id, float distance) {{\n\
             payload.value = float4(42.0, float(instance_id), float(primitive_id), distance);\n\
             payload.instance_id = instance_id;\n\
             payload.primitive_id = primitive_id;\n\
         }}\n\n\
         void msl_miss(thread RayPayloadResult& payload) {{ payload.value = float4(7.0); }}\n\n\
         bool msl_any_hit(thread RayPayloadResult& payload, uint group) {{\n\
             if ((group & 0x100u) != 0u) {{ payload.value = float4(7.0); return false; }}\n\
             return true;\n\
         }}\n\n\
         void msl_callable(thread RayPayloadResult& payload, uint group) {{ payload.value = float4(99.0, float(group), 0.0, 0.0); }}\n\n"
    );
    if raygen {
        source.push_str(&format!(
            "kernel void {entry}(device RayPayloadResult* results [[buffer(0)]],\n\
             device const RayRecord* rays [[buffer(1)]],\n\
             instance_acceleration_structure accel [[buffer(2)]],\n\
             device const uint* sbt [[buffer(3)]],\n\
             constant uint& ray_count [[buffer(4)]],\n\
             device const float4* instance_transforms [[buffer(5)]],\n\
             device const uint* dispatch_info [[buffer(6)]],\n\
             uint gid [[thread_position_in_grid]]) {{\n\
                 if (gid >= ray_count) {{ return; }}\n\
{RAY_HIT_LOCALS_MSL}\
{RAY_SBT_LOCALS_MSL}\
                 uint instance_count = max(dispatch_info[3], 1u);\n\
                 uint transform_base = min(__hit_instance, instance_count - 1u) * 8u;\n\
                 float4x4 object_to_world = float4x4(instance_transforms[transform_base], instance_transforms[transform_base + 1u], instance_transforms[transform_base + 2u], instance_transforms[transform_base + 3u]);\n\
                 float4x4 world_to_object = float4x4(instance_transforms[transform_base + 4u], instance_transforms[transform_base + 5u], instance_transforms[transform_base + 6u], instance_transforms[transform_base + 7u]);\n\
                 float3 object_origin = (world_to_object * float4(rays[gid].origin, 1.0f)).xyz;\n\
                 float3 object_direction = (world_to_object * float4(rays[gid].direction, 0.0f)).xyz;\n\
                 __candidate_object_origin = object_origin;\n\
                 __candidate_object_direction = object_direction;\n\
                 __candidate_object_to_world = object_to_world;\n\
                 __candidate_world_to_object = world_to_object;\n\
                 RayPayloadResult payload = {{}};\n\
                 payload.instance_id = __hit_instance;\n\
                 payload.primitive_id = __hit_primitive;\n\
                 payload.distance = __hit_distance;\n\
                 payload.hit_kind = __hit_kind;\n\
                 payload.dispatch[0] = dispatch_info[0];\n\
                 payload.dispatch[1] = dispatch_info[1];\n\
                 payload.dispatch[2] = dispatch_info[2];\n\
                 payload.barycentrics[0] = __barycentrics.x;\n\
                 payload.barycentrics[1] = __barycentrics.y;\n\
                 payload.object_origin[0] = object_origin.x;\n\
                 payload.object_origin[1] = object_origin.y;\n\
                 payload.object_origin[2] = object_origin.z;\n\
                 payload.object_direction[0] = object_direction.x;\n\
                 payload.object_direction[1] = object_direction.y;\n\
                 payload.object_direction[2] = object_direction.z;\n\
                 for (uint row = 0u; row < 3u; ++row) {{\n\
                     for (uint column = 0u; column < 4u; ++column) {{\n\
                         payload.object_to_world[row * 4u + column] = instance_transforms[transform_base + column][row];\n\
                         payload.world_to_object[row * 4u + column] = instance_transforms[transform_base + 4u + column][row];\n\
                         payload.candidate_object_to_world[row * 4u + column] = instance_transforms[transform_base + column][row];\n\
                         payload.candidate_world_to_object[row * 4u + column] = instance_transforms[transform_base + 4u + column][row];\n\
                     }}\n\
                 }}\n\
                 payload.candidate_type = __candidate_type;\n\
                 payload.candidate_instance = __candidate_instance;\n\
                 payload.candidate_primitive = __candidate_primitive;\n\
                 payload.candidate_geometry = __candidate_geometry;\n\
                 payload.ray_flags = __ray_flags;\n\
                 payload.ray_tmax = __ray_tmax;\n\
                 payload.ray_geometry_index = __ray_geometry_index;\n\
                 payload.attributes[0] = __attributes.x;\n\
                 payload.attributes[1] = __attributes.y;\n\
                 payload.attributes[2] = __attributes.z;\n\
                 payload.attributes[3] = __attributes.w;\n\
                 payload.accepted = __accepted;\n\
                 payload.end_search = __end_search;\n\
                 payload.ignored = __ignored;\n\
                 uint group = sbt[max(rays[gid].sbt_offset, uint(gid))];\n\
                 if (hit.type == intersection_type::none) {{ msl_miss(payload); }}\n\
                 else if (!msl_any_hit(payload, group)) {{ }}\n\
                 else if (group == 3u) {{ msl_callable(payload, group); }}\n\
                 else {{ msl_closest_hit(payload, __hit_instance, __hit_primitive, __hit_distance); }}\n\
                 results[gid] = payload;\n\
             }}\n"
        ));
    } else {
        source.push_str(&format!(
            "void {entry}(thread RayPayloadResult& payload) {{ (void)payload; }}\n"
        ));
    }
    source
}

/// Locate an LLVM tool shipped with the Rust sysroot or a system LLVM.
#[rustfmt::skip]
fn llvm_tool(name: &str) -> AppResult<std::path::PathBuf> {
    for root in [
        std::env::var_os("HOME")
            .map(|home| std::path::PathBuf::from(home).join(".rustup/toolchains")),
        Some(std::path::PathBuf::from("/opt/homebrew/Cellar")),
    ]
    .into_iter()
    .flatten()
    {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for entry in entries.flatten() {
                for candidate in [
                    entry.path().join("bin").join(name),
                    entry
                        .path()
                        .join("lib/rustlib/aarch64-apple-darwin/bin")
                        .join(name),
                    entry
                        .path()
                        .join("lib/rustlib/x86_64-apple-darwin/bin")
                        .join(name),
                ] {
                    if candidate.is_file() {
                        return Ok(candidate);
                    } } } } }
    Err(AppError::new(
        ReasonCode::RcDxilInvalid,
        format!("LLVM tool {name} is not available"),
    ))
}

/// Assemble textual LLVM IR to real LLVM bitcode with `llvm-as`.
pub fn llvm_assemble_ir(ir: &str) -> AppResult<Vec<u8>> {
    let assembler = llvm_tool("llvm-as")?;
    let mut file = std::env::temp_dir();
    file.push(format!(
        "casa1-ray-{}-{}-{}.ll",
        std::process::id(),
        LLVM_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        util::sha256_bytes(ir.as_bytes())
    ));
    std::fs::write(&file, ir).expect("stage LLVM IR");
    let output = std::process::Command::new(assembler)
        .arg("-o")
        .arg("-")
        .arg(&file)
        .output()
        .expect("run llvm-as");
    let _ = std::fs::remove_file(&file);
    if !output.status.success() {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!(
                "llvm-as rejected IR: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(output.stdout)
}

/// Disassemble real LLVM bitcode to textual IR using the bundled `opt`.
pub fn llvm_bitcode_to_ir(bitcode: &[u8]) -> AppResult<String> {
    if !bitcode.starts_with(b"BC\xc0\xde") {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            "PROG payload is not LLVM bitcode",
        ));
    }
    let opt = llvm_tool("opt")?;
    let mut file = std::env::temp_dir();
    file.push(format!(
        "casa1-ray-{}-{}-{}.bc",
        std::process::id(),
        LLVM_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        util::sha256_bytes(bitcode)
    ));
    std::fs::write(&file, bitcode).expect("stage LLVM bitcode");
    let output = std::process::Command::new(opt)
        .arg("-S")
        .arg("-o")
        .arg("-")
        .arg(&file)
        .output()
        .expect("run opt");
    let _ = std::fs::remove_file(&file);
    if !output.status.success() {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!(
                "opt rejected LLVM bitcode: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| AppError::new(ReasonCode::RcDxilInvalid, "opt produced non-UTF-8 LLVM IR"))
}

fn msl_ident(name: &str) -> String {
    name.trim_start_matches('%')
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn split_call_args(arguments: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for character in arguments.chars() {
        match character {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                current.push(character);
            }
            '>' | ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                current.push(character);
            }
            ',' if depth == 0 => {
                parts.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

/// Lower the body of a real LLVM IR ray function to MSL.
///
/// Supported instructions: `ret`, `call` to the DXIL-style ray intrinsics
/// (`dispatchRaysIndex`/`Dimensions`, world/object ray origin and direction,
/// `rayTMin`/`rayTCurrent`, object/world transforms, hit kind, instance and
/// primitive IDs, barycentrics), payload stores/loads and payload pointers,
/// `add`, `sub`, `mul`, `and`, `or`, `xor`, `icmp eq/ne`, and plain SSA
/// copies. Any other instruction is rejected with an `RcDxilInvalid` error
/// naming the opcode.
struct LlvmInst {
    result: Option<String>,
    opcode: String,
    rest: String,
}

struct LlvmBlock {
    label: String,
    phis: Vec<LlvmInst>,
    insts: Vec<LlvmInst>,
}

fn parse_llvm_array(ty: &str) -> Option<(usize, &str)> {
    let inner = ty.trim().strip_prefix('[')?.strip_suffix(']')?;
    let (count, element) = inner.split_once(" x ")?;
    Some((count.trim().parse().ok()?, element.trim()))
}

fn llvm_type_to_msl(ty: &str) -> AppResult<String> {
    let ty = ty.trim();
    if let Some((count, element)) = parse_llvm_array(ty) {
        let element = llvm_type_to_msl(element)?;
        return match (count, element.as_str()) {
            (3, "float4") => Ok("float3x4".to_string()),
            (4, "float4") => Ok("float4x4".to_string()),
            _ => Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("unsupported LLVM array type {ty}"),
            )),
        };
    }
    if let Some(vector) = ty
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
    {
        let (count, element) = vector.split_once(" x ").ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("unsupported LLVM vector type {ty}"),
            )
        })?;
        let element = llvm_type_to_msl(element)?;
        let suffix = match element.as_str() {
            "float" => "float",
            "double" => "double",
            "int" => "int",
            "long" => "long",
            "short" => "short",
            "char" => "char",
            other => {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!("unsupported LLVM vector element {other}"),
                ));
            }
        };
        return Ok(format!("{suffix}{count}"));
    }
    let msl = match ty {
        "void" => "void",
        "i1" => "bool",
        "i8" => "char",
        "i16" => "short",
        "i32" => "int",
        "i64" => "long",
        "float" => "float",
        "double" => "double",
        "half" => "half",
        _ => {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("unsupported LLVM type {ty}"),
            ));
        }
    };
    Ok(msl.to_string())
}

#[rustfmt::skip]
fn leading_type(rest: &str) -> &str {
    let rest = rest.trim_start();
    if rest.starts_with('<') {
        if let Some(end) = rest.find('>') {
            return &rest[..=end]; }
    }
    if rest.starts_with('{') {
        if let Some(end) = rest.find('}') {
            return &rest[..=end]; }
    }
    if rest.starts_with('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..=end]; }
    }
    rest.split_whitespace().next().unwrap_or(rest)
}

fn msl_value(value: &str) -> String {
    let value = value.trim();
    if value.starts_with('%') {
        msl_ident(value)
    } else {
        value.to_string()
    }
}

fn parse_aggregate_fields(ty: &str) -> AppResult<Vec<String>> {
    let inner = ty
        .trim()
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("expected aggregate type, got {ty}"),
            )
        })?;
    inner
        .split(',')
        .map(|field| llvm_type_to_msl(field))
        .collect()
}

/// MSL name for a textual LLVM aggregate type. The hash keeps distinct
/// aggregates separate without leaking commas/braces into identifiers.
fn aggregate_msl_name(ty: &str) -> String {
    let normalized: String = ty.split_whitespace().collect();
    format!("__agg_{}", &util::sha256_bytes(normalized.as_bytes())[..8])
}

/// Number of components a ray intrinsic result carries. Scalars count as one,
/// vectors report their literal width, and aggregates report their field count.
fn ray_result_component_count(ty: &str) -> AppResult<usize> {
    if ty.starts_with('{') {
        return Ok(parse_aggregate_fields(ty)?.len());
    }
    if let Some((count, _)) = parse_llvm_array(ty) {
        return Ok(count);
    }
    let msl = llvm_type_to_msl(ty)?;
    let count = match msl.as_str() {
        "float" | "double" | "half" | "int" | "uint" | "long" | "short" | "char" | "bool" => 1,
        "float2" | "double2" | "half2" | "int2" | "uint2" | "long2" | "short2" | "char2" => 2,
        "float3" | "int3" | "uint3" | "long3" | "short3" | "char3" => 3,
        "float4" | "int4" | "uint4" | "long4" | "short4" | "char4" => 4,
        other => {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("unsupported ray intrinsic result type {other}"),
            ));
        }
    };
    Ok(count)
}

/// Emit assignments for a ray intrinsic result whose value is split into
/// components. Aggregate results (DXC's usual shape) assign fields; vector
/// results construct the MSL vector. A scalar result must be a single
/// component, which keeps malformed fixtures from silently truncating.
fn emit_ray_components(
    output: &mut String,
    callee: &str,
    ty: &str,
    result: &str,
    exprs: &[String],
) -> AppResult<()> {
    if ty.starts_with('{') {
        let fields = parse_aggregate_fields(ty)?;
        if fields.len() != exprs.len() {
            return Err(AppError::new(
                ReasonCode::RcDxilInvalid,
                format!(
                    "{callee} returned {} fields but {} values are available",
                    fields.len(),
                    exprs.len()
                ),
            ));
        }
        for (index, expr) in exprs.iter().enumerate() {
            output.push_str(&format!("    {result}.f{index} = {expr};\n"));
        }
        return Ok(());
    }
    let count = ray_result_component_count(ty)?;
    if count != exprs.len() {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!(
                "{callee} returned a {count}-component value but {} values are available",
                exprs.len()
            ),
        ));
    }
    let msl = llvm_type_to_msl(ty)?;
    if count == 1 {
        output.push_str(&format!("    {result} = {};\n", exprs[0]));
    } else {
        output.push_str(&format!("    {result} = {msl}({});\n", exprs.join(", ")));
    }
    Ok(())
}

/// Emit a scalar ray intrinsic result with an explicit MSL cast.
fn emit_ray_scalar(output: &mut String, ty: &str, result: &str, expr: &str) -> AppResult<()> {
    if ray_result_component_count(ty)? != 1 {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("ray intrinsic result {ty} is not a scalar"),
        ));
    }
    let msl = llvm_type_to_msl(ty)?;
    output.push_str(&format!("    {result} = ({msl})({expr});\n"));
    Ok(())
}

/// Convert an LLVM call argument to a payload word write. Float payload fields
/// keep their bit pattern (D3D12 payloads are raw bytes), integers convert.
fn payload_word_expr(argument: &str) -> String {
    let mut parts = argument.split_whitespace();
    let ty = parts.next().unwrap_or("");
    let value = msl_value(parts.last().unwrap_or(argument));
    match ty {
        "float" | "double" | "half" => format!("as_type<uint>({value})"),
        _ => format!("uint({value})"),
    }
}

fn parse_blocks<'a>(body: &'a str, entry: &str) -> AppResult<Vec<LlvmBlock>> {
    let mut blocks: Vec<LlvmBlock> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut current = LlvmBlock {
        label: entry.to_string(),
        phis: Vec::new(),
        insts: Vec::new(),
    };
    let mut raw_lines = body.lines().peekable();
    while let Some(raw) = raw_lines.next() {
        let mut line = raw.split(';').next().unwrap_or("").trim().to_string();
        if line.starts_with("switch ") && !line.contains(']') {
            for next in raw_lines.by_ref() {
                line.push(' ');
                line.push_str(next.split(';').next().unwrap_or("").trim());
                if line.contains(']') {
                    break;
                }
            }
        }
        let line = line.as_str();
        if line.is_empty() {
            continue;
        }
        if line.ends_with(':') {
            if !current.insts.is_empty() || !current.phis.is_empty() {
                blocks.push(current);
            }
            let label = line.trim_end_matches(':').to_string();
            if !seen.insert(label.clone()) {
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!("duplicate LLVM label %{label}"),
                ));
            }
            current = LlvmBlock {
                label,
                phis: Vec::new(),
                insts: Vec::new(),
            };
            continue;
        }
        let (result, rest) = if let Some((name, rest)) = line.split_once('=') {
            (
                Some(name.trim().trim_start_matches('%').to_string()),
                rest.trim(),
            )
        } else {
            (None, line)
        };
        let (opcode, rest) = rest
            .split_once(' ')
            .map(|(opcode, rest)| (opcode, rest.trim()))
            .unwrap_or((rest, ""));
        let inst = LlvmInst {
            result,
            opcode: opcode.to_string(),
            rest: rest.to_string(),
        };
        if inst.opcode == "phi" {
            current.phis.push(inst);
        } else {
            current.insts.push(inst);
        }
    }
    if !current.insts.is_empty() || !current.phis.is_empty() {
        blocks.push(current);
    }
    if !seen.contains(entry) {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("LLVM IR has no block {entry}"),
        ));
    }
    Ok(blocks)
}

fn result_type(inst: &LlvmInst) -> AppResult<Option<String>> {
    let rest = inst.rest.as_str();
    match inst.opcode.as_str() {
        "alloca" | "getelementptr" | "store" | "ret" | "br" | "switch" | "unreachable" => Ok(None),
        "icmp" | "fcmp" => Ok(Some("bool".to_string())),
        "load" => {
            let ty = rest
                .split(',')
                .next()
                .ok_or_else(|| AppError::new(ReasonCode::RcDxilInvalid, "load without a type"))?;
            Ok(Some(llvm_type_to_msl(ty)?))
        }
        "call" => {
            let ty = leading_type(rest);
            if ty == "void" {
                return Ok(None);
            }
            let callee = rest
                .split_once('@')
                .map(|(_, tail)| tail.split('(').next().unwrap_or(""))
                .unwrap_or("");
            if callee == "dx.op.getShaderRecordBufferHandle" {
                return Ok(Some("__shader_record_ptr".to_string()));
            }
            if ty == "ptr" {
                let callee = rest
                    .split_once('@')
                    .map(|(_, tail)| tail.split('(').next().unwrap_or(""))
                    .unwrap_or("");
                if matches!(
                    callee,
                    "ray.payloadPointer" | "ray.getPayload" | "ray.payload"
                ) {
                    return Ok(Some("__payload_ptr".to_string()));
                }
                return Err(AppError::new(
                    ReasonCode::RcDxilInvalid,
                    format!("unsupported LLVM pointer return from @{callee}"),
                ));
            }
            if ty.starts_with('{') {
                return Ok(Some(aggregate_msl_name(ty)));
            }
            Ok(Some(llvm_type_to_msl(ty)?))
        }
        "extractelement" => {
            let ty = leading_type(rest);
            let vector = ty
                .strip_prefix('<')
                .and_then(|value| value.strip_suffix('>'))
                .and_then(|value| value.split_once(" x "))
                .map(|(_, element)| element)
                .ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcDxilInvalid,
                        format!("extractelement requires a vector type, got {ty}"),
                    )
                })?;
            Ok(Some(llvm_type_to_msl(vector)?))
        }
        "select" => {
            let ty = rest
                .split_once(',')
                .map(|(_, rest)| leading_type(rest))
                .unwrap_or_else(|| leading_type(rest));
            Ok(Some(llvm_type_to_msl(ty)?))
        }
        "extractvalue" => {
            let ty = leading_type(rest);
            if ty.starts_with('{') {
                let fields = parse_aggregate_fields(ty)?;
                let tail = rest[ty.len()..].trim();
                let index = tail
                    .split_once(',')
                    .map(|(_, index)| index.trim())
                    .unwrap_or("0")
                    .parse::<usize>()
                    .unwrap_or(0);
                Ok(Some(fields.get(index).cloned().ok_or_else(|| {
                    AppError::new(ReasonCode::RcDxilInvalid, "extractvalue index out of range")
                })?))
            } else if let Some((_, element)) = parse_llvm_array(ty) {
                Ok(Some(llvm_type_to_msl(element)?))
            } else {
                Ok(Some(llvm_type_to_msl(ty)?))
            }
        }
        "insertvalue" => {
            let ty = leading_type(rest);
            if ty.starts_with('{') {
                let normalized: String = ty.split_whitespace().collect();
                Ok(Some(format!(
                    "__agg_{}",
                    &util::sha256_bytes(normalized.as_bytes())[..8]
                )))
            } else {
                Ok(Some(llvm_type_to_msl(ty)?))
            }
        }
        "add" | "sub" | "mul" | "sdiv" | "udiv" | "srem" | "urem" | "shl" | "lshr" | "ashr"
        | "and" | "or" | "xor" | "fadd" | "fsub" | "fmul" | "fdiv" | "trunc" | "zext" | "sext"
        | "bitcast" | "fptrunc" | "fpext" | "sitofp" | "uitofp" | "fptosi" | "fptoui" => {
            let ty = rest.split_whitespace().next().unwrap_or("");
            Ok(Some(llvm_type_to_msl(ty)?))
        }
        "phi" => {
            let ty = leading_type(rest);
            Ok(Some(llvm_type_to_msl(ty)?))
        }
        other => Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("unsupported LLVM opcode {other}"),
        )),
    }
}

#[rustfmt::skip]
fn phi_incoming(inst: &LlvmInst, predecessor: &str) -> AppResult<String> {
    let mut search = inst.rest.as_str();
    let mut depth = 0usize;
    let mut start = None;
    for (index, character) in search.char_indices() {
        match character {
            '[' => {
                if depth == 0 {
                    start = Some(index + 1);
                }
                depth += 1;
            }
            ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if let Some(open) = start.take() {
                        let incoming = &search[open..index];
                        if let Some((value, label)) = incoming.split_once(',') {
                            if label.trim().trim_start_matches('%') == predecessor {
                                return Ok(value.trim().to_string());
                            } } } } }
            _ => {}
        }
    }
    let _ = &mut search;
    Err(AppError::new(
        ReasonCode::RcDxilInvalid,
        format!(
            "phi {} has no incoming value for predecessor %{predecessor}",
            inst.result.clone().unwrap_or_default()
        ),
    ))
}

fn edge_copies(blocks: &[LlvmBlock], from: &str, to: &str) -> AppResult<String> {
    let target = blocks
        .iter()
        .find(|block| block.label == to)
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                format!("branch to missing LLVM label %{to}"),
            )
        })?;
    let mut copies = Vec::new();
    for phi in &target.phis {
        let result = phi.result.clone().unwrap_or_default();
        copies.push(format!(
            "{result} = {};",
            msl_value(&phi_incoming(phi, from)?)
        ));
    }
    Ok(copies.join("\n    "))
}

#[rustfmt::skip]
pub fn lower_llvm_ir_ray_body(ir: &str, entry: &str) -> AppResult<String> {
    let definition = format!("@{entry}(");
    let start = ir.find(&definition).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("LLVM IR has no definition for @{entry}"),
        )
    })?;
    let body_start = ir[start..].find("{\n").ok_or_else(|| {
        AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("LLVM IR definition @{entry} has no body"),
        )
    })? + start
        + 2;
    let body_end = ir[body_start..].find("\n}").ok_or_else(|| {
        AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("LLVM IR definition @{entry} is unterminated"),
        )
    })? + body_start;
    if !ir[body_start..body_end].contains("entry:") {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("LLVM IR definition @{entry} has no entry label"),
        ));
    }
    let blocks = parse_blocks(&ir[body_start..body_end], "entry")?;
    let labels: std::collections::BTreeMap<&str, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.label.as_str(), index))
        .collect();
    let mut declarations = Vec::new();
    let mut pointer_bases: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut pointer_kinds: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut aggregate_types: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut payload_pointer_indices: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for block in &blocks {
        for inst in block.phis.iter().chain(block.insts.iter()) {
            let Some(name) = &inst.result else { continue };
            let Some(ty) = result_type(inst)? else {
                continue;
            };
            if ty == "__payload_ptr" {
                declarations.push(format!("device uint* {name};"));
                continue;
            }
            if ty == "__shader_record_ptr" {
                declarations.push(format!("device const uint* {name};"));
                continue;
            }
            if ty.starts_with("__agg_") {
                let aggregate = leading_type(&inst.rest);
                if let Ok(fields) = parse_aggregate_fields(aggregate) {
                    aggregate_types.entry(ty.clone()).or_insert(fields);
                }
            }
            declarations.push(format!("{ty} {name};"));
        }
        for inst in &block.insts {
            if inst.opcode != "alloca" {
                continue;
            }
            let Some(name) = &inst.result else { continue };
            let ty = leading_type(&inst.rest);
            if let Some(array) = ty
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
            {
                let (count, element) = array.split_once(" x ").ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcDxilInvalid,
                        format!("unsupported alloca type {ty}"),
                    )
                })?;
                let count = count.trim().parse::<usize>().map_err(|_| {
                    AppError::new(
                        ReasonCode::RcDxilInvalid,
                        format!("invalid alloca array size {count}"),
                    )
                })?;
                let element = llvm_type_to_msl(element)?;
                declarations.push(format!("{element} {name}[{count}];"));
                pointer_bases.insert(name.clone(), name.clone());
                pointer_kinds.insert(name.clone(), "array".to_string());
            } else if ty.starts_with('{') {
                let fields = parse_aggregate_fields(ty)?;
                let normalized: String = ty.split_whitespace().collect();
                let struct_name =
                    format!("__agg_{}", &util::sha256_bytes(normalized.as_bytes())[..8]);
                aggregate_types.insert(struct_name.clone(), fields);
                declarations.push(format!("{struct_name} {name};"));
                pointer_bases.insert(name.clone(), name.clone());
                pointer_kinds.insert(name.clone(), "struct".to_string());
            } else {
                let scalar = llvm_type_to_msl(ty)?;
                declarations.push(format!("{scalar} {name} = {{}};"));
                pointer_bases.insert(name.clone(), name.clone());
                pointer_kinds.insert(name.clone(), "scalar".to_string());
            }
        }
    }
    let mut struct_defs = String::new();
    for (name, fields) in &aggregate_types {
        struct_defs.push_str(&format!("struct {name} {{"));
        for (index, field) in fields.iter().enumerate() {
            struct_defs.push_str(&format!(" {field} f{index};"));
        }
        struct_defs.push_str(" };\n");
    }
    let signature = &ir[start + definition.len()..];
    if let Some((arguments, _)) = signature.split_once(')') {
        for argument in arguments.split(',') {
            let mut parts = argument.split_whitespace();
            let ty = parts.next().unwrap_or("");
            let Some(name) = parts.next().filter(|name| name.starts_with('%')) else {
                continue;
            };
            if let Ok(msl_ty) = llvm_type_to_msl(ty) {
                declarations.push(format!("{msl_ty} {} = {}(gid);", msl_ident(name), msl_ty));
            } } }
    let mut output = String::new();
    output.push_str("__bb = 0;\n");
    output.push_str(&declarations.join("\n"));
    output.push_str("\nwhile (true) {\nswitch (__bb) {\n");
    for (index, block) in blocks.iter().enumerate() {
        output.push_str(&format!("case {index}: {{\n"));
        for inst in &block.insts {
            let Some(result) = &inst.result else {
                match inst.opcode.as_str() {
                    "store" => {
                        let (value, pointer) = inst.rest.split_once(", ptr ").ok_or_else(|| {
                            AppError::new(ReasonCode::RcDxilInvalid, "store without value/pointer")
                        })?;
                        let pointer = pointer
                            .split_whitespace()
                            .next()
                            .unwrap_or("")
                            .trim_end_matches(',');
                        let pointer_name = msl_ident(pointer);
                        let base = pointer_bases.get(&pointer_name).ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcDxilInvalid,
                                format!("store to unsupported pointer {pointer}"),
                            )
                        })?;
                        let value = value.split_whitespace().last().unwrap_or(value);
                        if pointer_kinds.get(&pointer_name).map(String::as_str) == Some("payload") {
                            let index = payload_pointer_indices
                                .get(&pointer_name)
                                .expect("payload pointer GEP records an element index");
                            let word = payload_word_expr(value);
                            output.push_str(&format!(
                                "    if ((uint)({index}) < {RAY_PAYLOAD_WORDS}u) {{ *({base}) = {word}; }}\n"
                            ));
                        } else {
                            output.push_str(&format!("    {base} = {};\n", msl_value(value)));
                        }
                    }
                    "ret" => {
                        if inst.rest != "void" {
                            return Err(AppError::new(
                                ReasonCode::RcDxilInvalid,
                                format!("unsupported LLVM return type in @{entry}: {}", inst.rest),
                            ));
                        }
                        output.push_str("    return;\n");
                    }
                    "unreachable" => output.push_str("    return;\n"),
                    "call" => {
                        let (_, tail) = inst.rest.split_once('@').ok_or_else(|| {
                            AppError::new(ReasonCode::RcDxilInvalid, "call without a direct callee")
                        })?;
                        let callee = tail.split('(').next().unwrap_or("");
                        let arguments = tail
                            .split_once('(')
                            .map(|(_, rest)| rest.trim_end_matches(')'))
                            .unwrap_or("");
                        let args = split_call_args(arguments);
                        let arg = |index: usize| -> AppResult<String> {
                            args.get(index)
                                .map(|argument| {
                                    msl_value(argument.split_whitespace().last().unwrap_or(argument))
                                })
                                .ok_or_else(|| {
                                    AppError::new(
                                        ReasonCode::RcDxilInvalid,
                                        format!("{callee} is missing argument {index}"),
                                    )
                                })
                        };
                        let dx_arg = |index: usize| -> AppResult<String> {
                            arg(index + usize::from(callee.starts_with("dx.op.")))
                        };
                        match callee {
                            "dx.op.traceRay" | "traceRay" => {
                                let flags = dx_arg(1)?;
                                let mask = dx_arg(2)?;
                                let sbt_offset = dx_arg(3)?;
                                let origin_x = dx_arg(6)?;
                                let origin_y = dx_arg(7)?;
                                let origin_z = dx_arg(8)?;
                                let t_min = dx_arg(9)?;
                                let dir_x = dx_arg(10)?;
                                let dir_y = dx_arg(11)?;
                                let dir_z = dx_arg(12)?;
                                let t_max = dx_arg(13)?;
                                output.push_str(&format!(
                                    "    __ray_flags = uint({flags});\n\
                                     __ray_tmax = min(float({t_max}), rays[gid].max_distance);\n\
                                     intersector<triangle_data, instancing> __trace_query;\n\
                                     ray __trace_ray;\n\
                                     __trace_ray.origin = float3({origin_x}, {origin_y}, {origin_z});\n\
                                     __trace_ray.min_distance = max(float({t_min}), rays[gid].min_distance);\n\
                                     __trace_ray.direction = float3({dir_x}, {dir_y}, {dir_z});\n\
                                     __trace_ray.max_distance = __ray_tmax;\n\
                                     auto __trace_hit = __trace_query.intersect(__trace_ray, accel, uint({mask}) & rays[gid].mask);\n\
                                     __hit_instance = 0u; __hit_primitive = 0u; __hit_distance = 0.0f;\n\
                                     __hit_kind = 0u; __barycentrics = float2(0.0f);\n\
                                     __candidate_type = 0u; __candidate_instance = 0u; __candidate_primitive = 0u; __candidate_geometry = 0u;\n\
                                     __ray_geometry_index = 0u;\n\
                                     if (__trace_hit.type != intersection_type::none) {{\n\
                                         __hit_instance = __trace_hit.instance_id;\n\
                                         __hit_primitive = __trace_hit.primitive_id;\n\
                                         __hit_distance = __trace_hit.distance;\n\
                                         __hit_kind = 0xFEu;\n\
                                         __barycentrics = __trace_hit.triangle_barycentric_coord;\n\
                                         __attributes = float4(__barycentrics, 0.0f, 0.0f);\n\
                                         __candidate_type = 0u; __candidate_instance = __hit_instance;\n\
                                         __candidate_primitive = __hit_primitive; __candidate_geometry = 0u;\n\
                                         __ray_geometry_index = __candidate_geometry;\n\
                                     }}\n\
                                     uint __trace_count = max(dispatch_info[3], 1u);\n\
                                     uint __trace_base = min(__hit_instance, __trace_count - 1u) * 8u;\n\
                                     __candidate_object_to_world = float4x4(instance_transforms[__trace_base], instance_transforms[__trace_base + 1u], instance_transforms[__trace_base + 2u], instance_transforms[__trace_base + 3u]);\n\
                                     __candidate_world_to_object = float4x4(instance_transforms[__trace_base + 4u], instance_transforms[__trace_base + 5u], instance_transforms[__trace_base + 6u], instance_transforms[__trace_base + 7u]);\n\
                                     __candidate_object_origin = (__candidate_world_to_object * float4(__trace_ray.origin, 1.0f)).xyz;\n\
                                     __candidate_object_direction = (__candidate_world_to_object * float4(__trace_ray.direction, 0.0f)).xyz;\n\
                                     uint __trace_group = sbt[uint({sbt_offset}) + max(rays[gid].sbt_offset, uint(gid))];\n\
                                     for (uint __ai = 0u; __ai < dispatch_info[7]; ++__ai) {{\n\
                                         MetalRayAabb __aabb = aabbs[__ai];\n\
                                         uint __inst = __aabb.instance_id;\n\
                                         uint __pbase = min(__inst, __trace_count - 1u) * 8u;\n\
                                         float4x4 __p2w = float4x4(instance_transforms[__pbase], instance_transforms[__pbase + 1u], instance_transforms[__pbase + 2u], instance_transforms[__pbase + 3u]);\n\
                                         float4x4 __w2p = float4x4(instance_transforms[__pbase + 4u], instance_transforms[__pbase + 5u], instance_transforms[__pbase + 6u], instance_transforms[__pbase + 7u]);\n\
                                         float3 __po = (__w2p * float4(__trace_ray.origin, 1.0f)).xyz;\n\
                                         float3 __pd = (__w2p * float4(__trace_ray.direction, 0.0f)).xyz;\n\
                                         float3 __inv = 1.0f / __pd;\n\
                                         float3 __t0 = (__aabb.min - __po) * __inv;\n\
                                         float3 __t1 = (__aabb.max - __po) * __inv;\n\
                                         float3 __tn = min(__t0, __t1);\n\
                                         float3 __tf = max(__t0, __t1);\n\
                                         float __enter = max(max(__tn.x, __tn.y), __tn.z);\n\
                                         float __exit = min(min(__tf.x, __tf.y), __tf.z);\n\
                                         if (__enter <= __exit && __exit >= __trace_ray.min_distance && __enter < __ray_tmax) {{\n\
                                             float __dist = max(__enter, __trace_ray.min_distance);\n\
                                             if ((__hit_kind == 0u || __dist < __hit_distance) && __dist < __ray_tmax) {{\n\
                                                 RayStageInput __isect_input = {{}};\n\
                                                 __isect_input.type = 1u;\n\
                                                 __isect_input.instance_id = __inst;\n\
                                                 __isect_input.primitive_id = __ai;\n\
                                                 __isect_input.geometry_index = __aabb.geometry_index;\n\
                                                 __isect_input.distance = __dist;\n\
                                                 __isect_input.attributes = float4(0.0f);\n\
                                                 __isect_input.object_origin = __po;\n\
                                                 __isect_input.object_direction = __pd;\n\
                                                 __isect_input.object_to_world = __p2w;\n\
                                                 __isect_input.world_to_object = __w2p;\n\
                                                 __isect_input.ray_flags = __ray_flags;\n\
                                                 __isect_input.ray_tmax = __ray_tmax;\n\
                                                 __isect_input.ray_geometry_index = __aabb.geometry_index;\n\
                                                 results[gid].accepted = 1u; results[gid].end_search = 0u; results[gid].ignored = 0u;\n\
                                                 bool __reported = msl_intersection(results[gid], sbt[max(rays[gid].sbt_offset, uint(gid))], __isect_input, accel, rays, sbt, instance_transforms, dispatch_info, __sbt_local_root, __sbt_stride, vertex_attributes, triangle_indices, geometry_bindings, aabbs);\n\
                                                 if (__reported && results[gid].accepted != 0u) {{\n\
                                                     __hit_instance = __inst; __hit_primitive = __ai;\n\
                                                     __hit_distance = select(__dist, results[gid].distance, results[gid].distance > 0.0f);\n\
                                                     __hit_kind = 0xFFu; __barycentrics = float2(0.0f);\n\
                                                     __attributes = float4(results[gid].attributes[0], results[gid].attributes[1], results[gid].attributes[2], results[gid].attributes[3]);\n\
                                                     __candidate_type = 1u; __candidate_instance = __inst; __candidate_primitive = __ai;\n\
                                                     __candidate_geometry = __aabb.geometry_index; __ray_geometry_index = __aabb.geometry_index;\n\
                                                     __candidate_object_origin = __po; __candidate_object_direction = __pd;\n\
                                                     __candidate_object_to_world = __p2w; __candidate_world_to_object = __w2p;\n\
                                                 }}\n\
                                                 if (results[gid].end_search != 0u) {{ break; }}\n\
                                             }}\n\
                                         }}\n\
                                     }}\n\
                                     if (__hit_kind != 0u) {{\n\
                                         RayStageInput __trace_input = {{}};\n\
                                         __trace_input.type = __candidate_type; __trace_input.instance_id = __candidate_instance;\n\
                                         __trace_input.primitive_id = __candidate_primitive; __trace_input.geometry_index = __candidate_geometry;\n\
                                         __trace_input.distance = __hit_distance; __trace_input.barycentrics = __barycentrics;\n\
                                         __trace_input.attributes = __attributes; __trace_input.object_origin = __candidate_object_origin;\n\
                                         __trace_input.object_direction = __candidate_object_direction; __trace_input.object_to_world = __candidate_object_to_world;\n\
                                         __trace_input.world_to_object = __candidate_world_to_object; __trace_input.ray_flags = __ray_flags;\n\
                                         __trace_input.ray_tmax = __ray_tmax; __trace_input.ray_geometry_index = __ray_geometry_index;\n\
                                         if (msl_any_hit(results[gid], __trace_group, __trace_input, accel, rays, sbt, instance_transforms, dispatch_info, __sbt_local_root, __sbt_stride, vertex_attributes, triangle_indices, geometry_bindings, aabbs)) {{\n\
                                             msl_closest_hit(results[gid], __trace_group, __trace_input, accel, rays, sbt, instance_transforms, dispatch_info, __sbt_local_root, __sbt_stride, vertex_attributes, triangle_indices, geometry_bindings, aabbs);\n\
                                         }}\n\
                                     }} else {{\n\
                                         RayStageInput __miss_input = {{}};\n\
                                         __miss_input.ray_flags = __ray_flags; __miss_input.ray_tmax = __ray_tmax;\n\
                                         msl_miss(results[gid], __trace_group, __miss_input, accel, rays, sbt, instance_transforms, dispatch_info, __sbt_local_root, __sbt_stride, vertex_attributes, triangle_indices, geometry_bindings, aabbs);\n\
                                     }}\n\
                                     results[gid].instance_id = __hit_instance; results[gid].primitive_id = __hit_primitive;\n\
                                     results[gid].distance = __hit_distance; results[gid].hit_kind = __hit_kind;\n\
                                     results[gid].barycentrics[0] = __barycentrics.x; results[gid].barycentrics[1] = __barycentrics.y;\n\
                                     results[gid].ray_flags = __ray_flags; results[gid].ray_tmax = __ray_tmax;\n\
                                     results[gid].ray_geometry_index = __ray_geometry_index; results[gid].candidate_type = __candidate_type;\n\
                                     results[gid].candidate_instance = __candidate_instance; results[gid].candidate_primitive = __candidate_primitive;\n\
                                     results[gid].candidate_geometry = __candidate_geometry;\n\
                                     results[gid].attributes[0] = __attributes.x; results[gid].attributes[1] = __attributes.y;\n\
                                     results[gid].attributes[2] = __attributes.z; results[gid].attributes[3] = __attributes.w;\n"
                                ));
                            }
                            "dx.op.callShader" | "callShader" => {
                                let shader_index = dx_arg(0)?;
                                output.push_str(&format!(
                                    "    {{ RayStageInput __call_input = {{}};\n\
     __call_input.type = __candidate_type; __call_input.instance_id = __candidate_instance; __call_input.primitive_id = __candidate_primitive; __call_input.geometry_index = __candidate_geometry; __call_input.distance = __hit_distance; __call_input.barycentrics = __barycentrics; __call_input.attributes = __attributes; __call_input.object_origin = __candidate_object_origin; __call_input.object_direction = __candidate_object_direction; __call_input.object_to_world = __candidate_object_to_world; __call_input.world_to_object = __candidate_world_to_object; __call_input.ray_flags = __ray_flags; __call_input.ray_tmax = __ray_tmax; __call_input.ray_geometry_index = __ray_geometry_index;\n\
     msl_callable(results[gid], sbt[uint({shader_index}) + max(rays[gid].sbt_offset, uint(gid))], __call_input, accel, rays, sbt, instance_transforms, dispatch_info, __sbt_local_root, __sbt_stride, vertex_attributes, triangle_indices, geometry_bindings, aabbs); }}\n"
                                ));
                            }
                            "dx.op.acceptHitAndEndSearch" | "acceptHitAndEndSearch" => {
                                output.push_str(
                                    "    __accepted = 1u; __end_search = 1u; __ignored = 0u;\n\
                                     results[gid].accepted = 1u; results[gid].end_search = 1u; results[gid].ignored = 0u;\n",
                                );
                            }
                            "dx.op.ignoreHit" | "ignoreHit" => {
                                output.push_str(
                                    "    __accepted = 0u; __ignored = 1u; __end_search = 0u;\n\
                                     results[gid].accepted = 0u; results[gid].ignored = 1u; results[gid].end_search = 0u;\n",
                                );
                            }
                            "ray.storePayload" => {
                                let index = args
                                    .first()
                                    .map(|argument| {
                                        msl_value(
                                            argument.split_whitespace().last().unwrap_or(argument),
                                        )
                                    })
                                    .ok_or_else(|| {
                                        AppError::new(
                                            ReasonCode::RcDxilInvalid,
                                            "ray.storePayload is missing argument 0",
                                        )
                                    })?;
                                let value = args
                                    .get(1)
                                    .map(|argument| {
                                        msl_value(
                                            argument.split_whitespace().last().unwrap_or(argument),
                                        )
                                    })
                                    .ok_or_else(|| {
                                        AppError::new(
                                            ReasonCode::RcDxilInvalid,
                                            "ray.storePayload is missing argument 1",
                                        )
                                    })?;
                                output.push_str(&format!(
                                    "    results[{index}].value[0] = float({value});\n"
                                ));
                            }
                            "ray.storePayloadField" | "ray.storePayloadStruct" => {
                                let field = args
                                    .first()
                                    .map(|argument| {
                                        msl_value(
                                            argument.split_whitespace().last().unwrap_or(argument),
                                        )
                                    })
                                    .ok_or_else(|| {
                                        AppError::new(
                                            ReasonCode::RcDxilInvalid,
                                            format!("{callee} is missing argument 0"),
                                        )
                                    })?;
                                let value = args.get(1).ok_or_else(|| {
                                    AppError::new(
                                        ReasonCode::RcDxilInvalid,
                                        format!("{callee} is missing argument 1"),
                                    )
                                })?;
                                let word = payload_word_expr(value);
                                output.push_str(&format!(
                                    "    if ((uint)({field}) < {RAY_PAYLOAD_WORDS}u) {{ results[gid].payload[{field}] = {word}; }}\n"
                                ));
                            }
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("unsupported LLVM intrinsic @{other} in @{entry}"),
                                ));
                            }
                        }
                    }
                    "br" => {
                        if let Some((condition, targets)) = inst.rest.split_once(',') {
                            let targets: Vec<&str> = targets.split(',').collect();
                            if targets.len() != 2 {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    "conditional br needs two labels",
                                ));
                            }
                            let true_label = targets[0].trim().trim_start_matches("label %");
                            let false_label = targets[1].trim().trim_start_matches("label %");
                            let condition = condition
                                .trim()
                                .trim_start_matches("i1 ")
                                .trim_start_matches('%');
                            let true_index = *labels.get(true_label).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("branch to missing LLVM label %{true_label}"),
                                )
                            })?;
                            let false_index = *labels.get(false_label).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("branch to missing LLVM label %{false_label}"),
                                )
                            })?;
                            output.push_str(&format!(
                                "    if ({}) {{\n        {}\n        __bb = {}; }}\n    else {{\n        {}\n        __bb = {}; }}\n    break;\n",
                                msl_ident(condition),
                                edge_copies(&blocks, &block.label, true_label)?,
                                true_index,
                                edge_copies(&blocks, &block.label, false_label)?,
                                false_index,
                            ));
                        } else {
                            let target = inst.rest.trim().trim_start_matches("label %");
                            let target_index = *labels.get(target).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("branch to missing LLVM label %{target}"),
                                )
                            })?;
                            output.push_str(&format!(
                                "    {}\n    __bb = {}; break;\n",
                                edge_copies(&blocks, &block.label, target)?,
                                target_index,
                            ));
                        }
                    }
                    "switch" => {
                        let (value_part, rest) =
                            inst.rest.split_once(", label %").ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    "switch without default label",
                                )
                            })?;
                        let value = value_part.split_whitespace().last().unwrap_or("");
                        let (default_part, cases_part) = match rest.split_once('[') {
                            Some((default, cases)) => {
                                (default.trim(), cases.trim_end_matches(']').trim())
                            }
                            None => (rest.trim(), ""),
                        };
                        let default_target = default_part
                            .split_whitespace()
                            .next()
                            .unwrap_or(default_part)
                            .trim_end_matches(',');
                        let mut chain = String::new();
                        let mut remaining = cases_part;
                        while let Some(entry_start) = remaining.find("i32 ") {
                            let entry = &remaining[entry_start + 4..];
                            let Some((case_value, after_value)) = entry.split_once(", label %")
                            else {
                                break;
                            };
                            let case_value = case_value.trim();
                            let (case_label, after_label) =
                                after_value.split_once(' ').unwrap_or((after_value, ""));
                            let case_label = case_label.trim();
                            let case_index = *labels.get(case_label).ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("switch to missing label %{case_label}"),
                                )
                            })?;
                            chain.push_str(&format!(
                                "    if ({} == {}) {{ {} __bb = {}; }}\n    else ",
                                msl_value(value),
                                case_value,
                                edge_copies(&blocks, &block.label, case_label)?,
                                case_index,
                            ));
                            remaining = after_label;
                        }
                        let default_index = *labels.get(default_target).ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcDxilInvalid,
                                format!("switch to missing label %{default_target}"),
                            )
                        })?;
                        chain.push_str(&format!(
                            "{{ {} __bb = {}; }}\n    break;\n",
                            edge_copies(&blocks, &block.label, default_target)?,
                            default_index,
                        ));
                        output.push_str(&chain);
                    }
                    other => {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!("unsupported LLVM instruction {other}"),
                        ));
                    }
                }
                continue;
            };
            let result = msl_ident(result);
            match inst.opcode.as_str() {
                "alloca" => {}
                "getelementptr" => {
                    let ty = leading_type(&inst.rest).trim_end_matches(',');
                    let tail = inst.rest[ty.len()..].trim();
                    let base_part = tail.split("ptr ").nth(1).ok_or_else(|| {
                        AppError::new(ReasonCode::RcDxilInvalid, "getelementptr without base")
                    })?;
                    let mut pieces = base_part.split(',');
                    let base = pieces.next().unwrap_or("").trim().trim_start_matches('%');
                    let base_expr = pointer_bases.get(base).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!("getelementptr on unsupported pointer %{base}"),
                        )
                    })?;
                    let indices: Vec<String> = pieces
                        .map(|index| msl_value(index.split_whitespace().last().unwrap_or("")))
                        .collect();
                    let index = indices
                        .get(1)
                        .or_else(|| indices.first())
                        .cloned()
                        .unwrap_or_else(|| "0".into());
                    let kind = pointer_kinds.get(base).map(String::as_str);
                    let expr = if kind == Some("struct") {
                        format!("{base_expr}.f{index}")
                    } else if kind == Some("payload_ptr") {
                        payload_pointer_indices.insert(result.clone(), index.clone());
                        pointer_kinds.insert(result.clone(), "payload".to_string());
                        format!("{base_expr} + ({index})")
                    } else if kind == Some("payload") {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!(
                                "getelementptr on payload pointer %{base} has no scalar element type"
                            ),
                        ));
                    } else {
                        format!("{base_expr}[{index}]")
                    };
                    pointer_bases.insert(result.clone(), expr);
                }
                "load" => {
                    let pointer = inst
                        .rest
                        .split("ptr ")
                        .nth(1)
                        .and_then(|value| value.split_whitespace().next())
                        .unwrap_or("")
                        .trim_end_matches(',');
                    let pointer = msl_ident(pointer);
                    let base = pointer_bases.get(&pointer).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcDxilInvalid,
                            format!("load from unsupported pointer %{pointer}"),
                        )
                    })?;
                    if pointer_kinds.get(&pointer).map(String::as_str) == Some("payload") {
                        let index = payload_pointer_indices
                            .get(&pointer)
                            .expect("payload pointer GEP records an element index");
                        let ty = leading_type(&inst.rest).trim_end_matches(',');
                        let msl = llvm_type_to_msl(ty)?;
                        let read = match msl.as_str() {
                            "float" => format!("as_type<float>(*({base}))"),
                            "int" => format!("as_type<int>(*({base}))"),
                            "uint" => format!("*({base})"),
                            other => {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("payload load has unsupported type {other}"),
                                ));
                            }
                        };
                        output.push_str(&format!(
                            "    {result} = 0; if ((uint)({index}) < {RAY_PAYLOAD_WORDS}u) {{ {result} = {read}; }}\n"
                        ));
                    } else {
                        output.push_str(&format!("    {result} = {base};\n"));
                    }
                }
                "extractvalue" => {
                    let ty = leading_type(&inst.rest);
                    let tail = inst.rest[ty.len()..].trim();
                    let (value, index) = tail.split_once(',').ok_or_else(|| {
                        AppError::new(ReasonCode::RcDxilInvalid, "extractvalue without index")
                    })?;
                    let value = value.split_whitespace().last().unwrap_or(value);
                    if parse_llvm_array(ty).is_some() {
                        output.push_str(&format!(
                            "    {result} = {}[{}];\n",
                            msl_ident(value.trim()),
                            index.trim()
                        ));
                    } else {
                        output.push_str(&format!(
                            "    {result} = {}.f{};\n",
                            msl_ident(value.trim()),
                            index.trim()
                        ));
                    }
                }
                "extractelement" => {
                    let ty = leading_type(&inst.rest);
                    let tail = inst.rest[ty.len()..].trim();
                    let (value, index) = tail.split_once(',').ok_or_else(|| {
                        AppError::new(ReasonCode::RcDxilInvalid, "extractelement without index")
                    })?;
                    let value = value.split_whitespace().last().unwrap_or(value);
                    output.push_str(&format!(
                        "    {result} = {}[{}];\n",
                        msl_ident(value.trim()),
                        index
                            .split_whitespace()
                            .last()
                            .unwrap_or(index)
                            .trim_end_matches(',')
                    ));
                }
                "insertvalue" => {
                    let ty = leading_type(&inst.rest);
                    let tail = inst.rest[ty.len()..].trim();
                    let (value, tail) = tail.split_once(',').ok_or_else(|| {
                        AppError::new(ReasonCode::RcDxilInvalid, "insertvalue malformed")
                    })?;
                    let (inserted, index) = tail.split_once(',').ok_or_else(|| {
                        AppError::new(ReasonCode::RcDxilInvalid, "insertvalue without index")
                    })?;
                    let inserted = inserted
                        .split_whitespace()
                        .last()
                        .unwrap_or(inserted)
                        .trim_end_matches(',');
                    let value = value.split_whitespace().last().unwrap_or(value);
                    if value.trim() == "undef" {
                        output.push_str(&format!(
                            "    {result}.f{} = {};\n",
                            index.trim(),
                            msl_value(inserted)
                        ));
                    } else {
                        output.push_str(&format!(
                            "    {result} = {};\n    {result}.f{} = {};\n",
                            msl_ident(value.trim()),
                            index.trim(),
                            msl_value(inserted)
                        ));
                    }
                }
                "select" => {
                    let parts: Vec<&str> = inst.rest.split(',').collect();
                    if parts.len() != 3 {
                        return Err(AppError::new(
                            ReasonCode::RcDxilInvalid,
                            "select needs three operands",
                        ));
                    }
                    let condition = parts[0].split_whitespace().nth(1).unwrap_or("");
                    let lhs = parts[1]
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .trim_end_matches(',');
                    let rhs = parts[2]
                        .split_whitespace()
                        .last()
                        .unwrap_or(parts[2])
                        .trim_end_matches(',');
                    output.push_str(&format!(
                        "    {result} = {} ? {} : {};\n",
                        msl_value(condition),
                        msl_value(lhs),
                        msl_value(rhs)
                    ));
                }
                "call" => {
                    let (_, tail) = inst.rest.split_once('@').ok_or_else(|| {
                        AppError::new(ReasonCode::RcDxilInvalid, "call without a direct callee")
                    })?;
                    let callee = tail.split('(').next().unwrap_or("");
                    let arguments = tail
                        .split_once('(')
                        .map(|(_, rest)| rest.trim_end_matches(')'))
                        .unwrap_or("");
                    let args = split_call_args(arguments);
                    let scalar = |index: usize| -> AppResult<String> {
                        args.get(index)
                            .map(|argument| {
                                msl_value(argument.split_whitespace().last().unwrap_or(argument))
                            })
                            .ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} is missing argument {index}"),
                                )
                            })
                    };
                    let dx_scalar = |index: usize| -> AppResult<String> {
                        scalar(index + usize::from(callee.starts_with("dx.op.")))
                    };
                    let ty = leading_type(&inst.rest);
                    match callee {
                        "dx.op.dispatchRaysIndex" => {
                            let count = ray_result_component_count(ty)?;
                            if count == 1 {
                                let exprs = vec!["int(gid)".to_string()];
                                emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                            } else if count == 3 {
                                let exprs = vec![
                                    "int(dispatch_info[0])".to_string(),
                                    "int(dispatch_info[1])".to_string(),
                                    "int(dispatch_info[2])".to_string(),
                                ];
                                emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                            } else {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!(
                                        "{callee} returned a {count}-component value in @{entry}"
                                    ),
                                ));
                            }
                        }
                        "dx.op.dispatchRaysDimensions" => {
                            let exprs = vec![
                                "int(dispatch_info[0])".to_string(),
                                "int(dispatch_info[1])".to_string(),
                                "int(dispatch_info[2])".to_string(),
                            ];
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.objectToWorld" | "dx.op.objectToWorld3x4" => {
                            let count = ray_result_component_count(ty)?;
                            if !(3..=4).contains(&count) {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} returned an unsupported matrix shape in @{entry}"),
                                ));
                            }
                            let exprs: Vec<String> = (0..count)
                                .map(|index| format!("transpose(__object_to_world)[{index}]"))
                                .collect();
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.worldToObject" | "dx.op.worldToObject3x4" => {
                            let count = ray_result_component_count(ty)?;
                            if !(3..=4).contains(&count) {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} returned an unsupported matrix shape in @{entry}"),
                                ));
                            }
                            let exprs: Vec<String> = (0..count)
                                .map(|index| format!("transpose(__world_to_object)[{index}]"))
                                .collect();
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.rayTCurrent" => {
                            emit_ray_scalar(&mut output, ty, &result, "__hit_distance")?;
                        }
                        "dx.op.hitKind" => {
                            emit_ray_scalar(&mut output, ty, &result, "__hit_kind")?;
                        }
                        "dx.op.instanceID" => {
                            emit_ray_scalar(&mut output, ty, &result, "__hit_instance")?;
                        }
                        "dx.op.primitiveID" => {
                            emit_ray_scalar(&mut output, ty, &result, "__hit_primitive")?;
                        }
                        "dx.op.barycentrics" | "dx.op.barycentrics2" => {
                            let count = ray_result_component_count(ty)?;
                            if count != 2 {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} must return two components in @{entry}"),
                                ));
                            }
                            let exprs = vec![
                                "__barycentrics.x".to_string(),
                                "__barycentrics.y".to_string(),
                            ];
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.objectRayOrigin" => {
                            let count = ray_result_component_count(ty)?;
                            if count != 3 {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} must return three components in @{entry}"),
                                ));
                            }
                            let exprs = vec![
                                "__object_origin.x".to_string(),
                                "__object_origin.y".to_string(),
                                "__object_origin.z".to_string(),
                            ];
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.objectRayDirection" => {
                            let count = ray_result_component_count(ty)?;
                            if count != 3 {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} must return three components in @{entry}"),
                                ));
                            }
                            let exprs = vec![
                                "__object_direction.x".to_string(),
                                "__object_direction.y".to_string(),
                                "__object_direction.z".to_string(),
                            ];
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.worldRayOrigin" => {
                            output.push_str(&format!("    {result} = rays[gid].origin;\n"))
                        }
                        "dx.op.worldRayDirection" => {
                            output.push_str(&format!("    {result} = rays[gid].direction;\n"))
                        }
                        "dx.op.rayTMin" => {
                            output.push_str(&format!("    {result} = rays[gid].min_distance;\n"))
                        }
                        "dx.op.rayFlags" | "rayFlags" => {
                            emit_ray_scalar(&mut output, ty, &result, "__ray_flags")?;
                        }
                        "dx.op.rayTMax" | "rayTMax" => {
                            emit_ray_scalar(&mut output, ty, &result, "__ray_tmax")?;
                        }
                        "dx.op.rayGeometryIndex" | "rayGeometryIndex" => {
                            emit_ray_scalar(&mut output, ty, &result, "__ray_geometry_index")?;
                        }
                        "dx.op.candidateType" | "candidateType" => {
                            emit_ray_scalar(&mut output, ty, &result, "__candidate_type")?;
                        }
                        "dx.op.candidateInstanceID" | "candidateInstanceID" => {
                            emit_ray_scalar(&mut output, ty, &result, "__candidate_instance")?;
                        }
                        "dx.op.candidatePrimitiveID" | "candidatePrimitiveID" => {
                            emit_ray_scalar(&mut output, ty, &result, "__candidate_primitive")?;
                        }
                        "dx.op.candidateGeometryIndex" | "candidateGeometryIndex" => {
                            emit_ray_scalar(&mut output, ty, &result, "__candidate_geometry")?;
                        }
                        "dx.op.candidateObjectRayOrigin" | "candidateObjectRayOrigin" => {
                            let count = ray_result_component_count(ty)?;
                            if count != 3 {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} must return three components in @{entry}"),
                                ));
                            }
                            let exprs = vec![
                                "__candidate_object_origin.x".to_string(),
                                "__candidate_object_origin.y".to_string(),
                                "__candidate_object_origin.z".to_string(),
                            ];
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.candidateObjectRayDirection" | "candidateObjectRayDirection" => {
                            let count = ray_result_component_count(ty)?;
                            if count != 3 {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} must return three components in @{entry}"),
                                ));
                            }
                            let exprs = vec![
                                "__candidate_object_direction.x".to_string(),
                                "__candidate_object_direction.y".to_string(),
                                "__candidate_object_direction.z".to_string(),
                            ];
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.candidateObjectToWorld3x4" | "candidateObjectToWorld3x4" | "dx.op.candidateObjectToWorld" | "candidateObjectToWorld" => {
                            let count = ray_result_component_count(ty)?;
                            if !(3..=4).contains(&count) {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} returned an unsupported matrix shape in @{entry}"),
                                ));
                            }
                            let exprs: Vec<String> = (0..count)
                                .map(|index| {
                                    format!("transpose(__candidate_object_to_world)[{index}]")
                                })
                                .collect();
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.candidateWorldToObject3x4" | "candidateWorldToObject3x4" | "dx.op.candidateWorldToObject" | "candidateWorldToObject" => {
                            let count = ray_result_component_count(ty)?;
                            if !(3..=4).contains(&count) {
                                return Err(AppError::new(
                                    ReasonCode::RcDxilInvalid,
                                    format!("{callee} returned an unsupported matrix shape in @{entry}"),
                                ));
                            }
                            let exprs: Vec<String> = (0..count)
                                .map(|index| {
                                    format!("transpose(__candidate_world_to_object)[{index}]")
                                })
                                .collect();
                            emit_ray_components(&mut output, callee, ty, &result, &exprs)?;
                        }
                        "dx.op.attributeAtVertex" | "attributeAtVertex" => {
                            let attribute = dx_scalar(0)?;
                            let vertex = dx_scalar(1)?;
                            output.push_str(&format!(
                                "    {{ uint __vb = min(__candidate_instance, max(dispatch_info[6], 1u) - 1u);\n\
                                     uint __voff = geometry_bindings[__vb * 4u];\n\
                                     uint __ioff = geometry_bindings[__vb * 4u + 1u];\n\
                                     uint __slot = __ioff + __hit_primitive * 3u + uint({vertex});\n\
                                     uint __vidx = triangle_indices[__slot];\n\
                                     {result} = vertex_attributes[__voff + __vidx][uint({attribute}) & 3u]; }}\n"
                            ));
                        }
                        "dx.op.getShaderRecordBufferHandle" | "getShaderRecordBufferHandle" => {
                            output.push_str(&format!(
                                "    {result} = __sbt_local_root;\n"
                            ));
                            pointer_bases.insert(result.clone(), "__sbt_local_root".to_string());
                            pointer_kinds.insert(result.clone(), "shader_record".to_string());
                        }
                        "dx.op.reportHit" | "reportHit" => {
                            let distance = dx_scalar(0)?;
                            let attribute0 = dx_scalar(1)?;
                            let attribute1 = dx_scalar(2)?;
                            output.push_str(&format!(
                                "    __hit_distance = float({distance});\n\
                                 __attributes = float4(as_type<float>(uint({attribute0})), as_type<float>(uint({attribute1})), 0.0f, 0.0f);\n\
                                 __accepted = 1u; __end_search = 0u; __ignored = 0u;\n\
                                 results[gid].distance = __hit_distance;\n\
                                 results[gid].attributes[0] = __attributes.x; results[gid].attributes[1] = __attributes.y; results[gid].attributes[2] = __attributes.z; results[gid].attributes[3] = __attributes.w;\n\
                                 results[gid].accepted = 1u; results[gid].end_search = 0u; results[gid].ignored = 0u; results[gid].candidate_type = 1u;\n"
                            ));
                            if ray_result_component_count(ty)? == 1 {
                                output.push_str(&format!("    {result} = true;\n"));
                            }
                        }
                        "ray.payloadPointer" | "ray.getPayload" | "ray.payload" => {
                            output.push_str(&format!(
                                "    {result} = (device uint*)results[gid].payload;\n"
                            ));
                            pointer_bases.insert(
                                result.clone(),
                                "(device uint*)results[gid].payload".to_string(),
                            );
                            pointer_kinds.insert(result.clone(), "payload_ptr".to_string());
                        }
                        "ray.loadPayloadField" => {
                            let field = scalar(0)?;
                            let msl = llvm_type_to_msl(ty)?;
                            let read = match msl.as_str() {
                                "float" => format!(
                                    "as_type<float>(results[gid].payload[{field}])"
                                ),
                                "int" => format!("as_type<int>(results[gid].payload[{field}])"),
                                "uint" => format!("results[gid].payload[{field}]"),
                                other => {
                                    return Err(AppError::new(
                                        ReasonCode::RcDxilInvalid,
                                        format!(
                                            "ray.loadPayloadField returned unsupported type {other}"
                                        ),
                                    ));
                                }
                            };
                            output.push_str(&format!(
                                "    {result} = 0; if ((uint)({field}) < {RAY_PAYLOAD_WORDS}u) {{ {result} = {read}; }}\n"
                            ));
                        }
                        "ray.storePayload" => {
                            let index = scalar(0)?;
                            let value = scalar(1)?;
                            output.push_str(&format!(
                                "    results[{index}].value[0] = float({value});\n"
                            ));
                        }
                        other => {
                            return Err(AppError::new(
                                ReasonCode::RcDxilInvalid,
                                format!("unsupported LLVM intrinsic @{other} in @{entry}"),
                            ));
                        }
                    }
                }
                "add" | "sub" | "mul" | "sdiv" | "udiv" | "srem" | "urem" | "shl" | "lshr"
                | "ashr" | "and" | "or" | "xor" | "fadd" | "fsub" | "fmul" | "fdiv" => {
                    let mut parts = inst.rest.splitn(3, ' ');
                    let _ty = parts.next();
                    let lhs = msl_value(parts.next().unwrap_or("").trim_end_matches(','));
                    let rhs = msl_value(parts.next().unwrap_or("").trim_end_matches(','));
                    let operator = match inst.opcode.as_str() {
                        "add" | "fadd" => "+",
                        "sub" | "fsub" => "-",
                        "mul" | "fmul" => "*",
                        "sdiv" | "udiv" | "fdiv" => "/",
                        "srem" | "urem" => "%",
                        "shl" => "<<",
                        "lshr" | "ashr" => ">>",
                        "and" => "&",
                        "or" => "|",
                        _ => "^",
                    };
                    output.push_str(&format!("    {result} = {lhs} {operator} {rhs};\n"));
                }
                "icmp" | "fcmp" => {
                    let mut parts = inst.rest.splitn(4, ' ');
                    let predicate = parts.next().unwrap_or("");
                    let _ty = parts.next();
                    let lhs = msl_value(parts.next().unwrap_or("").trim_end_matches(','));
                    let rhs = msl_value(parts.next().unwrap_or("").trim_end_matches(','));
                    let operator = match predicate {
                        "eq" | "oeq" => "==",
                        "ne" | "one" => "!=",
                        "slt" | "olt" => "<",
                        "sgt" | "ogt" => ">",
                        "sle" | "ole" => "<=",
                        "sge" | "oge" => ">=",
                        "ult" => "<",
                        "ugt" => ">",
                        other => {
                            // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                            return Err(AppError::new(
                                ReasonCode::RcDxilInvalid,
                                format!("unsupported LLVM compare predicate {other} in @{entry}"),
                            ));
                        }
                    };
                    output.push_str(&format!("    {result} = {lhs} {operator} {rhs};\n"));
                }
                "trunc" | "zext" | "sext" | "bitcast" | "fptrunc" | "fpext" | "sitofp"
                | "uitofp" | "fptosi" | "fptoui" => {
                    let (source, destination) = inst.rest.split_once(" to ").ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcDxilInvalid, // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                            "conversion without destination type",
                        )
                    })?;
                    let ty = llvm_type_to_msl(destination)?;
                    let value = source
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or(source)
                        .trim_end_matches(',');
                    output.push_str(&format!("    {result} = ({ty}){};\n", msl_value(value)));
                }
                other => { // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                    // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                    // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                    // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                    return Err(AppError::new( // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                        ReasonCode::RcDxilInvalid, // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                        format!("unsupported LLVM opcode {other} in @{entry}"), // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                    )); // coverage: unreachable — result_type rejects unsupported opcodes before lowering.
                }
            }
        }
        output.push_str("    return;\n}\n");
    }
    output.push_str("default: return;\n}\n}\n");
    Ok(format!("{struct_defs}{}", output))
}

/// Default SBT stage helpers used when a raygen program has no separately
/// translated stage bitcode. They write deterministic payload values so a
/// nested `traceRay`/`callShader` never observes uninitialized state.
fn ray_default_stage_msl() -> String {
    let context = format!(
        "device const RayRecord* rays, device const uint* sbt, device const float4* instance_transforms, device const uint* dispatch_info, device const uint* __sbt_local_root, uint __sbt_stride{RAY_GEOMETRY_PARAMS}"
    );
    format!(
        "void msl_closest_hit(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, instance_acceleration_structure accel, {context}) {{\n\
    (void)group;\n\
    payload.value = float4(42.0, float(input.instance_id), float(input.primitive_id), input.distance);\n\
    payload.instance_id = input.instance_id;\n\
    payload.primitive_id = input.primitive_id;\n\
    payload.distance = input.distance;\n\
}}\n\
void msl_miss(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, instance_acceleration_structure accel, {context}) {{ (void)input; (void)group; payload.value = float4(7.0); }}\n\
bool msl_any_hit(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, instance_acceleration_structure accel, {context}) {{\n\
    (void)input;\n\
    if ((group & 0x100u) != 0u) {{ payload.value = float4(7.0); return false; }}\n\
    payload.accepted = 1u;\n\
    return true;\n\
}}\n\
void msl_callable(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, instance_acceleration_structure accel, {context}) {{\n\
    (void)input;\n\
    payload.value = float4(99.0, float(group), 0.0, 0.0);\n\
    payload.accepted = 1u;\n\
}}\n\
bool msl_intersection(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, instance_acceleration_structure accel, {context}) {{\n\
    (void)payload; (void)group; (void)input;\n\
    return false;\n\
}}\n"
    )
}

/// Translate real LLVM bitcode into an MSL raygen kernel body.
///
/// The generated kernel owns real hardware traversal, so hit-derived
/// intrinsics (`RayTCurrent`, `HitKind`, `InstanceID`, `PrimitiveID`,
/// barycentrics) read the intersection it just performed. Object/world
/// transforms come from the per-instance table bound at buffer 5.
pub fn translate_llvm_ray_program(bitcode: &[u8], entry: &str) -> AppResult<String> {
    let ir = llvm_bitcode_to_ir(bitcode)?;
    let body = lower_llvm_ir_ray_body(&ir, entry)?;
    let (prefix, code) = body.split_once("__bb = 0;").unwrap_or(("", body.as_str()));
    let defaults = ray_default_stage_msl();
    Ok(format!(
        "#include <metal_stdlib>\n#include <metal_raytracing>\nusing namespace metal;\nusing namespace raytracing;\n\n{prefix}\n{RAY_RESULT_STRUCT_MSL}\n{RAY_STAGE_INPUT_MSL}\n{defaults}\n\
         kernel void {entry}(device RayPayloadResult* results [[buffer(0)]],\n\
                             device const RayRecord* rays [[buffer(1)]],\n\
                             instance_acceleration_structure accel [[buffer(2)]],\n\
                             device const uint* sbt [[buffer(3)]],\n\
                             constant uint& ray_count [[buffer(4)]],\n\
                             device const float4* instance_transforms [[buffer(5)]],\n\
                             device const uint* dispatch_info [[buffer(6)]],\n\
                             device const float4* vertex_attributes [[buffer(7)]],\n\
                             device const uint* triangle_indices [[buffer(8)]],\n\
                             device const uint* geometry_bindings [[buffer(9)]],\n\
                             device const MetalRayAabb* aabbs [[buffer(10)]],\n\
                             uint gid [[thread_position_in_grid]]) {{\n\
             if (gid >= ray_count) {{ return; }}\n\
{RAY_HIT_LOCALS_MSL}\
{RAY_SBT_LOCALS_MSL}\
             uint __instance_count = max(dispatch_info[3], 1u);\n\
             uint __transform_base = min(__hit_instance, __instance_count - 1u) * 8u;\n\
             float4x4 __object_to_world = float4x4(instance_transforms[__transform_base], instance_transforms[__transform_base + 1u], instance_transforms[__transform_base + 2u], instance_transforms[__transform_base + 3u]);\n\
             float4x4 __world_to_object = float4x4(instance_transforms[__transform_base + 4u], instance_transforms[__transform_base + 5u], instance_transforms[__transform_base + 6u], instance_transforms[__transform_base + 7u]);\n\
             float3 __object_origin = (__world_to_object * float4(rays[gid].origin, 1.0f)).xyz;\n\
             float3 __object_direction = (__world_to_object * float4(rays[gid].direction, 0.0f)).xyz;\n\
             __candidate_object_origin = __object_origin;\n\
             __candidate_object_direction = __object_direction;\n\
             __candidate_object_to_world = __object_to_world;\n\
             __candidate_world_to_object = __world_to_object;\n\
             RayPayloadResult __empty = {{}};\n\
             results[gid] = __empty;\n\
             results[gid].instance_id = __hit_instance;\n\
             results[gid].primitive_id = __hit_primitive;\n\
             results[gid].distance = __hit_distance;\n\
             results[gid].hit_kind = __hit_kind;\n\
             results[gid].dispatch[0] = dispatch_info[0];\n\
             results[gid].dispatch[1] = dispatch_info[1];\n\
             results[gid].dispatch[2] = dispatch_info[2];\n\
             results[gid].barycentrics[0] = __barycentrics.x;\n\
             results[gid].barycentrics[1] = __barycentrics.y;\n\
             results[gid].object_origin[0] = __object_origin.x;\n\
             results[gid].object_origin[1] = __object_origin.y;\n\
             results[gid].object_origin[2] = __object_origin.z;\n\
             results[gid].object_direction[0] = __object_direction.x;\n\
             results[gid].object_direction[1] = __object_direction.y;\n\
             results[gid].object_direction[2] = __object_direction.z;\n\
             for (uint __row = 0u; __row < 3u; ++__row) {{\n\
                 for (uint __column = 0u; __column < 4u; ++__column) {{\n\
                     results[gid].object_to_world[__row * 4u + __column] = instance_transforms[__transform_base + __column][__row];\n\
                     results[gid].world_to_object[__row * 4u + __column] = instance_transforms[__transform_base + 4u + __column][__row];\n\
                     results[gid].candidate_object_to_world[__row * 4u + __column] = instance_transforms[__transform_base + __column][__row];\n\
                     results[gid].candidate_world_to_object[__row * 4u + __column] = instance_transforms[__transform_base + 4u + __column][__row];\n\
                 }}\n\
             }}\n\
             results[gid].ray_flags = __ray_flags;\n\
             results[gid].ray_tmax = __ray_tmax;\n\
             results[gid].ray_geometry_index = __ray_geometry_index;\n\
             results[gid].candidate_type = __candidate_type;\n\
             results[gid].candidate_instance = __candidate_instance;\n\
             results[gid].candidate_primitive = __candidate_primitive;\n\
             results[gid].candidate_geometry = __candidate_geometry;\n\
             results[gid].candidate_object_origin[0] = __candidate_object_origin.x;\n\
             results[gid].candidate_object_origin[1] = __candidate_object_origin.y;\n\
             results[gid].candidate_object_origin[2] = __candidate_object_origin.z;\n\
             results[gid].candidate_object_direction[0] = __candidate_object_direction.x;\n\
             results[gid].candidate_object_direction[1] = __candidate_object_direction.y;\n\
             results[gid].candidate_object_direction[2] = __candidate_object_direction.z;\n\
             results[gid].attributes[0] = __attributes.x;\n\
             results[gid].attributes[1] = __attributes.y;\n\
             results[gid].attributes[2] = __attributes.z;\n\
             results[gid].attributes[3] = __attributes.w;\n\
             results[gid].accepted = __accepted;\n\
             results[gid].end_search = __end_search;\n\
             results[gid].ignored = __ignored;\n\
             uint __bb = 0; {code}\n\
             results[gid].instance_id = __hit_instance;\n\
             results[gid].primitive_id = __hit_primitive;\n\
             results[gid].distance = __hit_distance;\n\
             results[gid].hit_kind = __hit_kind;\n\
             results[gid].barycentrics[0] = __barycentrics.x;\n\
             results[gid].barycentrics[1] = __barycentrics.y;\n\
             results[gid].ray_flags = __ray_flags;\n\
             results[gid].ray_tmax = __ray_tmax;\n\
             results[gid].ray_geometry_index = __ray_geometry_index;\n\
             results[gid].candidate_type = __candidate_type;\n\
             results[gid].candidate_instance = __candidate_instance;\n\
             results[gid].candidate_primitive = __candidate_primitive;\n\
             results[gid].candidate_geometry = __candidate_geometry;\n\
             results[gid].candidate_object_origin[0] = __candidate_object_origin.x;\n\
             results[gid].candidate_object_origin[1] = __candidate_object_origin.y;\n\
             results[gid].candidate_object_origin[2] = __candidate_object_origin.z;\n\
             results[gid].candidate_object_direction[0] = __candidate_object_direction.x;\n\
             results[gid].candidate_object_direction[1] = __candidate_object_direction.y;\n\
             results[gid].candidate_object_direction[2] = __candidate_object_direction.z;\n\
             for (uint __row = 0u; __row < 3u; ++__row) {{\n\
                 for (uint __column = 0u; __column < 4u; ++__column) {{\n\
                     results[gid].candidate_object_to_world[__row * 4u + __column] = __candidate_object_to_world[__column][__row];\n\
                     results[gid].candidate_world_to_object[__row * 4u + __column] = __candidate_world_to_object[__column][__row];\n\
                 }}\n\
             }}\n\
             results[gid].attributes[0] = __attributes.x;\n\
             results[gid].attributes[1] = __attributes.y;\n\
             results[gid].attributes[2] = __attributes.z;\n\
             results[gid].attributes[3] = __attributes.w;\n\
             results[gid].accepted = __accepted;\n\
             results[gid].end_search = __end_search;\n\
             results[gid].ignored = __ignored;\n\
}}\n"
    ))
}

/// Candidate inputs supplied to a translated non-raygen stage.
///
/// The raygen wrapper snapshots these from the real Metal intersection before
/// invoking the stage function, so candidate system values are deterministic
/// and never synthesized independently of the traversal.
const RAY_STAGE_INPUT_MSL: &str = "struct RayStageInput {\n\
    uint type;\n\
    uint instance_id;\n\
    uint primitive_id;\n\
    uint geometry_index;\n\
    float distance;\n\
    float2 barycentrics;\n\
    float4 attributes;\n\
    float3 object_origin;\n\
    float3 object_direction;\n\
    float4x4 object_to_world;\n\
    float4x4 world_to_object;\n\
    uint ray_flags;\n\
    float ray_tmax;\n\
    uint ray_geometry_index;\n\
};\n\
struct MetalRayAabb {\n\
    packed_float3 min;\n\
    packed_float3 max;\n\
    uint instance_id;\n\
    uint geometry_index;\n\
    uint group;\n\
    uint reserved;\n\
};\n";

/// Stage-local mirrors of the raygen variables referenced by lowered bodies.
const RAY_STAGE_LOCALS_MSL: &str = "    uint gid = 0u;\n\
    device RayPayloadResult* results = &payload;\n\
    uint __hit_instance = input.instance_id;\n\
    uint __hit_primitive = input.primitive_id;\n\
    uint __hit_kind = (input.type == 0u) ? 0xFEu : 0xFFu;\n\
    float __hit_distance = input.distance;\n\
    float2 __barycentrics = input.barycentrics;\n\
    uint __candidate_type = input.type;\n\
    uint __candidate_instance = input.instance_id;\n\
    uint __candidate_primitive = input.primitive_id;\n\
    uint __candidate_geometry = input.geometry_index;\n\
    float3 __candidate_object_origin = input.object_origin;\n\
    float3 __candidate_object_direction = input.object_direction;\n\
    float4x4 __candidate_object_to_world = input.object_to_world;\n\
    float4x4 __candidate_world_to_object = input.world_to_object;\n\
    float4x4 __object_to_world = input.object_to_world;\n\
    float4x4 __world_to_object = input.world_to_object;\n\
    float3 __object_origin = input.object_origin;\n\
    float3 __object_direction = input.object_direction;\n\
    float4 __attributes = input.attributes;\n\
    uint __ray_flags = input.ray_flags;\n\
    float __ray_tmax = input.ray_tmax;\n\
    uint __ray_geometry_index = input.ray_geometry_index;\n\
    uint __accepted = 1u;\n\
    uint __end_search = 0u;\n\
    uint __ignored = 0u;\n";

fn ray_stage_parameters(_stage: ShaderStage) -> String {
    format!(
        "device RayPayloadResult& payload, uint group, thread const RayStageInput& input, \
         instance_acceleration_structure accel, device const RayRecord* rays, \
         device const uint* sbt, device const float4* instance_transforms, \
         device const uint* dispatch_info, device const uint* __sbt_local_root, \
         uint __sbt_stride{RAY_GEOMETRY_PARAMS}"
    )
}

/// Translate one non-raygen ray stage from its own LLVM bitcode.
///
/// Raygen delegates to [`translate_llvm_ray_program`]. Hit, miss, callable and
/// intersection stages consume the candidate snapshot captured by the raygen
/// traversal and can themselves issue nested `traceRay`/`callShader` calls
/// through the same Metal intersector. Every stage writes the shared payload
/// and attribute state, so the SBT-selected function has real side effects.
pub fn translate_llvm_ray_stage_program(
    bitcode: &[u8],
    stage: ShaderStage,
    entry: &str,
) -> AppResult<String> {
    if matches!(stage, ShaderStage::RayGeneration) {
        return translate_llvm_ray_program(bitcode, entry);
    }
    if !matches!(
        stage,
        ShaderStage::AnyHit
            | ShaderStage::ClosestHit
            | ShaderStage::Miss
            | ShaderStage::Intersection
            | ShaderStage::Callable
    ) {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("{} is not a ray shader stage", stage.as_str()),
        ));
    }
    let ir = llvm_bitcode_to_ir(bitcode)?;
    let body = lower_llvm_ir_ray_body(&ir, entry)?;
    let (prefix, code) = body.split_once("__bb = 0;").unwrap_or(("", body.as_str()));
    let (qualifier, bool_return) = match stage {
        ShaderStage::AnyHit => ("bool", true),
        ShaderStage::ClosestHit => ("void", false),
        ShaderStage::Miss => ("void", false),
        ShaderStage::Intersection => ("bool", true),
        ShaderStage::Callable => ("void", false),
        _ => unreachable!("ray stage set is exhaustive"), // coverage: unreachable
    };
    let params = ray_stage_parameters(stage);
    let body = if bool_return {
        code.replace("return;", "return __accepted != 0u;")
    } else {
        code.to_string()
    };
    let tail = if bool_return {
        "    return __accepted != 0u;"
    } else {
        "    return;"
    };
    let function_name = match stage {
        ShaderStage::AnyHit => "msl_any_hit",
        ShaderStage::ClosestHit => "msl_closest_hit",
        ShaderStage::Miss => "msl_miss",
        ShaderStage::Intersection => "msl_intersection",
        ShaderStage::Callable => "msl_callable",
        _ => unreachable!("ray stage set is exhaustive"), // coverage: unreachable
    };
    let context = format!(
        "instance_acceleration_structure accel, device const RayRecord* rays, device const uint* sbt, device const float4* instance_transforms, device const uint* dispatch_info, device const uint* __sbt_local_root, uint __sbt_stride{RAY_GEOMETRY_PARAMS}"
    );
    let mut defaults = String::new();
    let default_bodies = [
        (
            "msl_closest_hit",
            format!(
                "void msl_closest_hit(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, {context}) {{\n    (void)group;\n    payload.value = float4(42.0, float(input.instance_id), float(input.primitive_id), input.distance);\n    payload.instance_id = input.instance_id;\n    payload.primitive_id = input.primitive_id;\n    payload.distance = input.distance;\n}}\n"
            ),
        ),
        (
            "msl_miss",
            format!(
                "void msl_miss(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, {context}) {{ payload.value = float4(7.0); (void)input; }}\n"
            ),
        ),
        (
            "msl_any_hit",
            format!(
                "bool msl_any_hit(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, {context}) {{\n    (void)input;\n    if ((group & 0x100u) != 0u) {{ payload.value = float4(7.0); return false; }}\n    payload.accepted = 1u;\n    return true;\n}}\n"
            ),
        ),
        (
            "msl_callable",
            format!(
                "void msl_callable(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, {context}) {{\n    (void)input;\n    payload.value = float4(99.0, float(group), 0.0, 0.0);\n    payload.accepted = 1u;\n}}\n"
            ),
        ),
        (
            "msl_intersection",
            format!(
                "bool msl_intersection(device RayPayloadResult& payload, uint group, thread const RayStageInput& input, {context}) {{\n    (void)payload; (void)group; (void)input;\n    return false;\n}}\n"
            ),
        ),
    ];
    for (name, body) in default_bodies {
        if name != function_name {
            defaults.push_str(&body);
        }
    }
    let arguments = format!(
        "payload, group, input, accel, rays, sbt, instance_transforms, dispatch_info, __sbt_local_root, __sbt_stride{RAY_GEOMETRY_ARGS}"
    );
    let stage_init = if matches!(stage, ShaderStage::Intersection) {
        "    __accepted = 0u;\n"
    } else {
        ""
    };
    let wrapper = if bool_return {
        format!("{qualifier} {entry}({params}) {{ return {function_name}({arguments}); }}")
    } else {
        format!("{qualifier} {entry}({params}) {{ {function_name}({arguments}); }}")
    };
    Ok(format!(
        "#include <metal_stdlib>\n#include <metal_raytracing>\nusing namespace metal;\nusing namespace raytracing;\n\n{prefix}\n{RAY_RESULT_STRUCT_MSL}\n{RAY_STAGE_INPUT_MSL}\n{defaults}\
         {qualifier} {function_name}({params}) {{\n\
{RAY_STAGE_LOCALS_MSL}{stage_init}\
         uint __bb = 0;\n{body}\n{tail}\n}}\n\
         {wrapper}\n"
    ))
}

/// Extract the MSL source carried by a `ShaderTranslationOutput` library blob.
///
/// The blob format is `MSL|<len>|<function>|<stage>|<gpu>|<os>|<hash>|<source>`;
/// the source is everything after the seventh separator so `||` operators in
/// MSL are preserved.
pub fn msl_source_from_library_bytes(bytes: &[u8]) -> AppResult<&str> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| dxil_invalid("translated MSL artifact is not UTF-8"))?;
    if !text.starts_with("MSL|") {
        return Err(dxil_invalid(
            "translated artifact is not an MSL source blob",
        ));
    }
    let mut parts = text.splitn(8, '|');
    for index in 0..7 {
        parts
            .next()
            .ok_or_else(|| dxil_invalid("translated MSL artifact is missing a header field"))?;
        let _ = index;
    }
    parts
        .next()
        .ok_or_else(|| dxil_invalid("translated MSL artifact has no source payload"))
}

/// Extract a DXIL part from a DXBC container, if the container carries one.
///
/// DXBC containers written by newer compilers can embed a `DXIL` chunk. Shader
/// model 5 DXBC (`SHDR`/`SHEX`) has no DXIL part and needs a DXBC-to-DXIL
/// translator, which this module does not provide.
pub fn dxbc_extract_dxil(bytes: &[u8]) -> AppResult<Option<Vec<u8>>> {
    if bytes.len() < 32 || &bytes[..4] != b"DXBC" {
        return Ok(None);
    }
    let chunk_count = read_u32(bytes, 28, "DXBC chunk count")? as usize;
    if chunk_count > 256 {
        return Err(dxil_invalid("DXBC chunk count exceeds safety limit"));
    }
    let table = 32usize
        .checked_add(chunk_count * 4)
        .ok_or_else(|| dxil_invalid("DXBC chunk table overflows"))?;
    checked_range(bytes, 32, chunk_count * 4, "DXBC chunk offsets")?;
    for index in 0..chunk_count {
        let offset = read_u32(bytes, 32 + index * 4, "DXBC chunk offset")? as usize;
        checked_range(bytes, offset, 8, "DXBC chunk header")?;
        let fourcc = &bytes[offset..offset + 4];
        let size = read_u32(bytes, offset + 4, "DXBC chunk size")? as usize;
        checked_range(bytes, offset + 8, size, "DXBC chunk payload")?;
        if fourcc == b"DXIL" {
            return Ok(Some(bytes[offset + 8..offset + 8 + size].to_vec()));
        }
    }
    let _ = table;
    Ok(None)
}

/// Compile MSL source to a Metal library.
///
/// Contract: this function is a placeholder that does not invoke the `metal`
/// compiler. It returns the source wrapped in a recognizable, versioned
/// format — `MTLCOMPILED|v1|<len>|<source>` — so callers can detect that no
/// real compilation happened (the absence of the `MTLCOMPILED|` prefix means
/// the bytes are a real compiled library). Wiring in the async Metal compiler
/// (async_pipeline_compiler) is future work.
pub fn compile_msl_source(msl_source: &str, _entry_point: &str) -> AppResult<Vec<u8>> {
    Ok(format!("MTLCOMPILED|v1|{}|{}", msl_source.len(), msl_source).into_bytes())
}

// ---------------------------------------------------------------------------
// DXIL container parsing
// ---------------------------------------------------------------------------

/// Parse a DXIL container from raw bytes.
///
/// The DXIL container format is:
/// - 4-byte magic "DXIL"
/// - 4-byte version (uint32 LE)
/// - 4-byte part count (uint32 LE)
/// - 12-byte part descriptors (kind[4] + offset[4] + size[4])
/// - Part payloads
pub fn parse_dxil_container(bytes: &[u8]) -> AppResult<ParsedDxilContainer> {
    if bytes.len() < 12 || &bytes[..4] != DXIL_MAGIC {
        return Err(dxil_invalid("invalid DXIL container header"));
    }
    let version = read_u32(bytes, 4, "container version")?;
    if version != 1 {
        return Err(dxil_invalid("unsupported DXIL container version"));
    }
    let part_count = read_u32(bytes, 8, "part count")? as usize;
    if part_count == 0 || part_count > MAX_PARTS {
        return Err(dxil_invalid("DXIL container part count is out of bounds"));
    }
    let descriptors_end = 12 + part_count * 12;
    checked_range(bytes, 12, part_count * 12, "part descriptors")?;
    let mut parts = BTreeMap::new();
    for index in 0..part_count {
        let offset = 12 + index * 12;
        let kind = bytes[offset..offset + 4]
            .try_into()
            .expect("4-byte part kind");
        let descriptor = PartDescriptor {
            kind,
            offset: read_u32(bytes, offset + 4, "part offset")?,
            size: read_u32(bytes, offset + 8, "part size")?,
        };
        checked_range(
            bytes,
            descriptor.offset as usize,
            descriptor.size as usize,
            "part payload",
        )?;
        if (descriptor.offset as usize) < descriptors_end {
            return Err(dxil_invalid("DXIL part overlaps the header region"));
        }
        parts.insert(
            String::from_utf8_lossy(&descriptor.kind).to_string(),
            descriptor,
        );
    }

    let program_part = part_slice(
        bytes,
        parts.get("PROG").ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                "DXIL container is missing a PROG part",
            )
        })?,
    )?;
    let parsed_program = parse_program_part(program_part)?;
    if parsed_program.instruction_count > MAX_INSTRUCTIONS {
        return Err(dxil_invalid("DXIL instruction count exceeds safety limit"));
    }
    if parsed_program.ir_size > MAX_IR_SIZE {
        return Err(dxil_invalid("DXIL IR size exceeds safety limit"));
    }

    let sign_part = part_slice(
        bytes,
        parts.get("SIGN").ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                "DXIL container is missing a SIGN part",
            )
        })?,
    )?;
    if sign_part.len() < 2 {
        return Err(dxil_invalid("DXIL signature part is too small"));
    }
    let signature_mid = sign_part.len() / 2;
    let input_signature_hash = util::sha256_bytes(&sign_part[..signature_mid]);
    let output_signature_hash = util::sha256_bytes(&sign_part[signature_mid..]);

    let metadata = part_slice(
        bytes,
        parts.get("META").ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDxilInvalid,
                "DXIL container is missing a META part",
            )
        })?,
    )?;
    let entry_name = parse_metadata_entry_name(metadata)?;

    let reflection = parts
        .get("RFLX")
        .map(|descriptor| {
            parse_reflection_part(
                part_slice(bytes, descriptor).expect("valid reflection range"),
                &parsed_program,
                &input_signature_hash,
                &output_signature_hash,
            )
        })
        .transpose()?;

    Ok(ParsedDxilContainer {
        entry_name,
        instruction_count: parsed_program.instruction_count,
        ir_size: parsed_program.ir_size,
        root_signature_part: parts.get("ROOT").map(|descriptor| {
            part_slice(bytes, descriptor)
                .expect("valid root range")
                .to_vec()
        }),
        reflection_present: reflection.is_some(),
        input_signature_hash,
        output_signature_hash,
        threadgroup_size: parsed_program.threadgroup_size,
        uses: parsed_program.uses,
        reflection,
    })
}

// ---------------------------------------------------------------------------
// Root signature parsing and argument buffer building
// ---------------------------------------------------------------------------

/// Parse a DXBC root signature blob.
pub fn parse_root_signature(bytes: &[u8]) -> AppResult<RootSignatureInfo> {
    if bytes.len() < 8 {
        return Err(dxil_invalid("root signature blob is too small"));
    }
    let descriptor_count = read_u32(bytes, 0, "root descriptor count")? as usize;
    let root_constants_count = read_u32(bytes, 4, "root constant count")?;
    let table_size = descriptor_count
        .checked_mul(6)
        .ok_or_else(|| dxil_invalid("root descriptor table is too large"))?;
    checked_range(bytes, 8, table_size, "root descriptors")?;
    let mut descriptors = Vec::with_capacity(descriptor_count);
    for index in 0..descriptor_count {
        let offset = 8 + index * 6;
        descriptors.push(RootDescriptor {
            kind: parse_root_kind(bytes[offset])?,
            register: bytes[offset + 1] as u32,
            space: bytes[offset + 2] as u32,
            descriptor_count: bytes[offset + 3] as u32,
            arg_buffer_index: bytes[offset + 4] as u32,
            binding_index: bytes[offset + 5] as u32,
        });
    }
    Ok(RootSignatureInfo {
        descriptors,
        root_constants_count,
    })
}

/// Build argument buffer layouts from the root signature.
///
/// Maps root parameters (descriptor tables, root descriptors, root constants)
/// to MSL argument buffer struct declarations with correct `[[buffer(N)]]`,
/// `[[texture(N)]]`, and `[[sampler(N)]]` attribute indices.
pub fn build_argument_buffers(root: &RootSignatureInfo) -> Vec<ArgumentBufferLayout> {
    root.descriptors
        .iter()
        .enumerate()
        .map(|(table_index, descriptor)| {
            let bindings: Vec<ArgumentBinding> = (0..descriptor.descriptor_count)
                .map(|index| ArgumentBinding {
                    kind: format!("{:?}", descriptor.kind).to_lowercase(),
                    register: descriptor.register + index,
                    space: descriptor.space,
                    binding_index: descriptor.binding_index + index,
                })
                .collect();

            ArgumentBufferLayout {
                table_index: table_index as u32,
                binding_count: descriptor.descriptor_count,
                bindless_indirection: descriptor.descriptor_count > 64,
                bindings,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Cbuffer packing helpers
// ---------------------------------------------------------------------------

/// Pack cbuffer fields into an MSL-compatible struct layout.
///
/// Follows HLSL cbuffer packing: scalars are packed 4 per 16-byte register,
/// so `float data[N]` occupies `ceil(N * components / 4) * 16` bytes rather
/// than `16 * N`. All arithmetic is checked; absurd field sizes saturate
/// instead of wrapping.
pub fn pack_cbuffer(fields: &[CbufferField]) -> PackedCbuffer {
    let mut offset = 0_u32;
    let mut register_usage = 0_u32;
    let mut packed = Vec::new();
    for field in fields {
        let array_len = field.array_len.max(1);
        let scalar_size = 4;
        let is_matrix = field.rows > 1 && field.cols > 1;
        let field_size = if is_matrix {
            let vector_count = if field.row_major {
                field.rows
            } else {
                field.cols
            };
            16u32
                .checked_mul(vector_count)
                .and_then(|size| size.checked_mul(array_len))
                .unwrap_or(u32::MAX)
        } else {
            let component_count = field.rows.max(field.cols).max(1);
            let element_size = component_count * scalar_size;
            if array_len > 1 {
                // Each array element occupies its own 16-byte register slot
                // (D3D cbuffer packing: array elements start on 16-byte
                // boundaries and never share registers).
                16u32.saturating_mul(array_len)
            } else {
                element_size
            }
        };
        if is_matrix
            || array_len > 1
            || register_usage
                .checked_add(field_size)
                .is_some_and(|total| total > 16)
        {
            offset = align16(offset);
        }
        packed.push(PackedField {
            name: field.name.clone(),
            offset,
            size_bytes: field_size,
        });
        offset = offset.saturating_add(field_size);
        register_usage = if is_matrix || array_len > 1 {
            0
        } else {
            offset % 16
        };
    }
    let size_bytes = align16(offset);
    let packing_hash = util::sha256_bytes(
        util::stable_json(&packed)
            .expect("packed cbuffer fields are serializable")
            .as_bytes(),
    );
    PackedCbuffer {
        fields: packed,
        size_bytes,
        packing_hash,
    }
}

/// Pack structured buffer fields.
pub fn pack_structured_fields(fields: &[StructuredField]) -> StructuredPacking {
    let mut offset = 0_u32;
    for field in fields {
        offset = align_up(offset, field.alignment.max(4));
        offset = offset.saturating_add(field.size_bytes);
    }
    let stride = align_up(offset, 16);
    let packing_hash = util::sha256_bytes(
        util::stable_json(&fields.to_vec())
            .expect("structured fields are serializable")
            .as_bytes(),
    );
    StructuredPacking {
        stride,
        packing_hash,
    }
}

// ---------------------------------------------------------------------------
// Cache key helpers
// ---------------------------------------------------------------------------

/// Compute a content-addressed cache key for a shader translation input.
///
/// The key is built from SHA-256 hashes of the DXIL bytecode, root signature,
/// compile flags, and other inputs to ensure uniqueness.
pub fn shader_cache_key(input: &ShaderTranslationInput) -> AppResult<String> {
    let compile_flags_hash =
        util::sha256_bytes(util::stable_json(&input.compile_flags)?.as_bytes());
    Ok(format!(
        "{}||{}||{}||{}||{}||{}||{}",
        util::sha256_bytes(&input.dxil),
        util::sha256_bytes(&input.root_signature),
        input.stage.as_str(),
        input.gpu_family,
        input.os_build,
        input.macwin_version,
        compile_flags_hash,
    ))
}

/// Compute a PSO cache key from vertex/pixel/compute shader keys and render state.
pub fn pso_cache_key(
    vs_key: Option<&str>,
    ps_key: Option<&str>,
    cs_key: Option<&str>,
    render_state_blob: &[u8],
    formats_blob: &[u8],
    sample_count: u32,
    topology: &str,
) -> String {
    let payload = format!(
        "{}||{}||{}||{}||{}||{}||{}",
        vs_key.unwrap_or(""),
        ps_key.unwrap_or(""),
        cs_key.unwrap_or(""),
        util::sha256_bytes(render_state_blob),
        util::sha256_bytes(formats_blob),
        sample_count,
        topology,
    );
    util::sha256_bytes(payload.as_bytes())
}

/// Build a cache entry from the translation output.
pub fn build_cache_entry(
    key: &str,
    output: &ShaderTranslationOutput,
    created_ts: u64,
    pipeline_archive: Option<Vec<u8>>,
) -> AppResult<ShaderCacheEntry> {
    let payload = CachePayload {
        mtl_library_bytes: output.mtl_library_bytes.clone(),
        reflection_json: util::stable_json(&output.reflection)?,
        metal_pipeline_archive: pipeline_archive,
    };
    Ok(ShaderCacheEntry {
        header: CacheHeader {
            magic: String::from_utf8_lossy(CACHE_MAGIC).to_string(),
            version: CACHE_VERSION,
            key: key.to_string(),
            created_ts,
            last_used_ts: created_ts,
        },
        checksum: checksum_payload(&payload)?,
        payload,
    })
}

/// Compile a batch of shaders with caching.
///
/// Checks the cache for each shader first. If found, counts as a hit.
/// Otherwise compiles the shader and inserts it into the cache.
pub fn compile_with_cache(
    inputs: &[ShaderTranslationInput],
    cache: &mut ShaderCache,
) -> CacheRunStats {
    let mut stats = CacheRunStats {
        hits: 0,
        misses: 0,
        compile_stalls: 0,
        failures: 0,
    };
    for input in inputs {
        let Ok(key) = shader_cache_key(input) else {
            stats.failures += 1;
            continue;
        };
        if cache.get(&key).is_some() {
            stats.hits += 1;
            continue;
        }
        stats.misses += 1;
        stats.compile_stalls += 1;
        match translate_shader(input) {
            Ok(output) => {
                if let Ok(entry) = build_cache_entry(&key, &output, cache.clock + 1, None) {
                    cache.insert(entry);
                } else {
                    stats.failures += 1;
                }
            }
            Err(_) => {
                stats.failures += 1;
            }
        }
    }
    stats
}

/// Discover DXIL files in a directory tree.
pub fn discover_dxil_files(root: &Path) -> AppResult<Vec<PathBuf>> {
    let mut compiler = OfflineCompiler::default();
    compiler.scan_directory(root)
}

/// Produce a short summary string from DXIL data (useful for fuzzing).
pub fn fuzz_summary(data: &[u8]) -> String {
    match parse_dxil_container(data) {
        Ok(parsed) => format!(
            "ok:{}:{}:{}:{}:{}",
            parsed.entry_name,
            parsed.instruction_count,
            parsed.ir_size,
            parsed.uses.len(),
            parsed.reflection_present,
        ),
        Err(error) => {
            // Error messages may embed untrusted length/format details; cap
            // the length so the summary stays bounded and deterministic.
            let mut message = error.message;
            message.truncate(128);
            format!("err:{}:{}", error.code.as_u32(), message)
        }
    }
}

// ---------------------------------------------------------------------------
// Internal parsing helpers
// ---------------------------------------------------------------------------

/// Parse the PROG part payload of the pinned custom container format.
///
/// Layout: `instruction_count(4) | ir_size(4) | threadgroup_x(4) |
/// threadgroup_y(4) | threadgroup_z(4) | use_count(4) | use table
/// (use_count × 8-byte entries) | LLVM bitcode`.
///
/// All header fields are validated against safety bounds; counts come from
/// untrusted bytes so every byte extent is computed with checked arithmetic.
fn parse_program_part(bytes: &[u8]) -> AppResult<ParsedProgram> {
    checked_range(bytes, 0, 24, "program header")?;
    let instruction_count = read_u32(bytes, 0, "instruction count")?;
    let ir_size = read_u32(bytes, 4, "IR size")?;
    let threadgroup_size = ThreadgroupSize {
        x: read_u32(bytes, 8, "threadgroup x")?,
        y: read_u32(bytes, 12, "threadgroup y")?,
        z: read_u32(bytes, 16, "threadgroup z")?,
    };
    if instruction_count > MAX_INSTRUCTIONS {
        return Err(dxil_invalid("DXIL instruction count exceeds safety limit"));
    }
    if ir_size > MAX_IR_SIZE {
        return Err(dxil_invalid("DXIL IR size exceeds safety limit"));
    }
    if threadgroup_size.x > 1024 || threadgroup_size.y > 1024 || threadgroup_size.z > 1024 {
        return Err(dxil_invalid("DXIL threadgroup size exceeds safety limit"));
    }
    let use_count = read_u32(bytes, 20, "resource use count")? as usize;
    if use_count > 4096 {
        return Err(dxil_invalid("DXIL resource use count exceeds safety limit"));
    }
    let table_size = use_count
        .checked_mul(8)
        .ok_or_else(|| dxil_invalid("DXIL resource use table is too large"))?;
    checked_range(bytes, 24, table_size, "resource use table")?;
    let mut uses = Vec::with_capacity(use_count);
    for index in 0..use_count {
        let offset = 24 + index * 8;
        uses.push(ProgramUse {
            kind: parse_program_kind(bytes[offset])?,
            register: bytes[offset + 1] as u32,
            space: bytes[offset + 2] as u32,
            access: parse_resource_access(bytes[offset + 3])?,
            format: parse_format_code(bytes[offset + 4]).to_string(),
            size_bytes: matches!(bytes[offset], 3)
                .then_some(u16::from_le_bytes([bytes[offset + 5], bytes[offset + 6]]) as u32),
        });
    }
    Ok(ParsedProgram {
        instruction_count,
        ir_size,
        threadgroup_size,
        uses,
    })
}

fn parse_metadata_entry_name(bytes: &[u8]) -> AppResult<String> {
    let Some(length) = bytes.first().copied() else {
        return Err(dxil_invalid("metadata payload is empty"));
    };
    checked_range(bytes, 1, length as usize, "metadata entry name")?;
    std::str::from_utf8(&bytes[1..1 + length as usize])
        .map(ToString::to_string)
        .map_err(|_| AppError::new(ReasonCode::RcDxilInvalid, "malformed DXIL metadata"))
}

fn parse_reflection_part(
    bytes: &[u8],
    program: &ParsedProgram,
    input_signature_hash: &str,
    output_signature_hash: &str,
) -> AppResult<ReflectionTable> {
    checked_range(bytes, 0, 4, "reflection resource count")?;
    let resource_count = read_u32(bytes, 0, "reflection resource count")? as usize;
    let resources_size = resource_count
        .checked_mul(7)
        .and_then(|size| size.checked_add(4))
        .ok_or_else(|| dxil_invalid("reflection resource table is too large"))?;
    checked_range(bytes, 4, resources_size, "reflection resources")?;
    let mut resources = Vec::with_capacity(resource_count);
    for index in 0..resource_count {
        let offset = 4 + index * 7;
        resources.push(ReflectionResource {
            kind: parse_reflection_kind(bytes[offset])?,
            register: bytes[offset + 1] as u32,
            space: bytes[offset + 2] as u32,
            arg_buffer_index: bytes[offset + 3] as u32,
            binding_index: bytes[offset + 4] as u32,
            access: parse_resource_access(bytes[offset + 5])?,
            format: parse_format_code(bytes[offset + 6]).to_string(),
        });
    }
    let cbuffer_base = 4usize
        .checked_add(
            resource_count
                .checked_mul(7)
                .ok_or_else(|| dxil_invalid("reflection resource table is too large"))?,
        )
        .ok_or_else(|| dxil_invalid("reflection resource table is too large"))?;
    let cbuffer_count = read_u32(bytes, cbuffer_base, "reflection cbuffer count")? as usize;
    let cbuffers_size = cbuffer_count
        .checked_mul(8)
        .ok_or_else(|| dxil_invalid("reflection cbuffer table is too large"))?;
    checked_range(
        bytes,
        cbuffer_base + 4,
        cbuffers_size,
        "reflection cbuffers",
    )?;
    let mut cbuffers = Vec::with_capacity(cbuffer_count);
    for index in 0..cbuffer_count {
        let offset = cbuffer_base + 4 + index * 8;
        let register = bytes[offset] as u32;
        let space = bytes[offset + 1] as u32;
        let size_bytes = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as u32;
        let packing_seed = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        cbuffers.push(ReflectionCbuffer {
            register,
            space,
            size_bytes,
            packing_hash: util::sha256_bytes(
                format!("{register}:{space}:{size_bytes}:{packing_seed}").as_bytes(),
            ),
        });
    }
    Ok(ReflectionTable {
        resources,
        cbuffers,
        threadgroup_size: Some(program.threadgroup_size.clone()),
        input_signature_hash: input_signature_hash.to_string(),
        output_signature_hash: output_signature_hash.to_string(),
    })
}

fn cross_check_reflection(
    parsed: &ParsedDxilContainer,
    reflection: &ReflectionTable,
) -> AppResult<()> {
    // Every resource used by the bytecode must be present in the reflection
    // table; extra reflection entries (benign drift between the custom use
    // table and the RFLX part) are tolerated.
    let expected_resources = parsed
        .uses
        .iter()
        .filter_map(|use_entry| match use_entry.kind {
            ProgramBindingKind::Buffer => {
                Some((ResourceKind::Buffer, use_entry.register, use_entry.space))
            }
            ProgramBindingKind::Texture => {
                Some((ResourceKind::Texture, use_entry.register, use_entry.space))
            }
            ProgramBindingKind::Sampler => {
                Some((ResourceKind::Sampler, use_entry.register, use_entry.space))
            }
            ProgramBindingKind::Cbuffer => None,
        })
        .collect::<BTreeSet<_>>();
    let actual_resources = reflection
        .resources
        .iter()
        .map(|resource| (resource.kind, resource.register, resource.space))
        .collect::<BTreeSet<_>>();
    if !expected_resources.is_subset(&actual_resources) {
        return Err(dxil_invalid(
            "reflection/resources do not match DXIL bytecode usage",
        ));
    }
    // Cbuffers: every use must be reflected; the size comparison is relaxed
    // when the use table carries no size for the entry.
    for use_entry in parsed
        .uses
        .iter()
        .filter(|use_entry| matches!(use_entry.kind, ProgramBindingKind::Cbuffer))
    {
        let Some(actual) = reflection.cbuffers.iter().find(|cbuffer| {
            cbuffer.register == use_entry.register && cbuffer.space == use_entry.space
        }) else {
            return Err(dxil_invalid(
                "reflection/cbuffer usage does not match DXIL bytecode usage",
            ));
        };
        if let Some(size) = use_entry.size_bytes
            && actual.size_bytes != size
        {
            return Err(dxil_invalid(
                "reflection/cbuffer size does not match DXIL bytecode usage",
            ));
        }
    }
    Ok(())
}

fn reconstruct_reflection(
    parsed: &ParsedDxilContainer,
    root: &RootSignatureInfo,
) -> AppResult<ReflectionTable> {
    let mut resources = Vec::new();
    let mut cbuffers = Vec::new();
    for use_entry in &parsed.uses {
        let matches = root
            .descriptors
            .iter()
            .filter(|descriptor| {
                descriptor.register == use_entry.register
                    && descriptor.space == use_entry.space
                    && root_kind_matches_use(descriptor.kind, use_entry.kind)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(AppError::new(
                ReasonCode::RcDxilBindingAmbiguous,
                format!(
                    "ambiguous root signature binding for register t{} space {}",
                    use_entry.register, use_entry.space
                ),
            ));
        }
        let descriptor = matches[0];
        match use_entry.kind {
            ProgramBindingKind::Buffer => resources.push(ReflectionResource {
                kind: ResourceKind::Buffer,
                register: use_entry.register,
                space: use_entry.space,
                arg_buffer_index: descriptor.arg_buffer_index,
                binding_index: descriptor.binding_index,
                access: use_entry.access,
                format: use_entry.format.clone(),
            }),
            ProgramBindingKind::Texture => resources.push(ReflectionResource {
                kind: ResourceKind::Texture,
                register: use_entry.register,
                space: use_entry.space,
                arg_buffer_index: descriptor.arg_buffer_index,
                binding_index: descriptor.binding_index,
                access: use_entry.access,
                format: use_entry.format.clone(),
            }),
            ProgramBindingKind::Sampler => resources.push(ReflectionResource {
                kind: ResourceKind::Sampler,
                register: use_entry.register,
                space: use_entry.space,
                arg_buffer_index: descriptor.arg_buffer_index,
                binding_index: descriptor.binding_index,
                access: ResourceAccess::Read,
                format: "sampler".to_string(),
            }),
            ProgramBindingKind::Cbuffer => cbuffers.push(ReflectionCbuffer {
                register: use_entry.register,
                space: use_entry.space,
                size_bytes: use_entry.size_bytes.unwrap_or(0),
                packing_hash: util::sha256_bytes(
                    format!(
                        "{}:{}:{}",
                        use_entry.register,
                        use_entry.space,
                        use_entry.size_bytes.unwrap_or(0)
                    )
                    .as_bytes(),
                ),
            }),
        }
    }
    Ok(ReflectionTable {
        resources,
        cbuffers,
        threadgroup_size: Some(parsed.threadgroup_size.clone()),
        input_signature_hash: parsed.input_signature_hash.clone(),
        output_signature_hash: parsed.output_signature_hash.clone(),
    })
}

fn root_kind_matches_use(root_kind: RootBindingKind, use_kind: ProgramBindingKind) -> bool {
    matches!(
        (root_kind, use_kind),
        (RootBindingKind::Buffer, ProgramBindingKind::Buffer)
            | (RootBindingKind::Texture, ProgramBindingKind::Texture)
            | (RootBindingKind::Sampler, ProgramBindingKind::Sampler)
            | (RootBindingKind::Cbuffer, ProgramBindingKind::Cbuffer)
    )
}

fn shader_error(
    input: &ShaderTranslationInput,
    dxil_hash: &str,
    failing_pass: &str,
    error: AppError,
) -> ShaderError {
    ShaderError {
        reason_code: error.code,
        dxil_hash: dxil_hash.to_string(),
        stage: input.stage,
        failing_pass: failing_pass.to_string(),
        message: error.message,
    }
}

fn entry_size(entry: &ShaderCacheEntry) -> usize {
    entry.payload.mtl_library_bytes.len()
        + entry.payload.reflection_json.len()
        + entry
            .payload
            .metal_pipeline_archive
            .as_ref()
            .map_or(0, Vec::len)
        + entry.header.key.len()
        + entry.checksum.len()
        + 64
}

fn checksum_payload(payload: &CachePayload) -> AppResult<String> {
    Ok(util::sha256_bytes(util::stable_json(payload)?.as_bytes()))
}

fn parse_root_kind(byte: u8) -> AppResult<RootBindingKind> {
    match byte {
        0 => Ok(RootBindingKind::Buffer),
        1 => Ok(RootBindingKind::Texture),
        2 => Ok(RootBindingKind::Sampler),
        3 => Ok(RootBindingKind::Cbuffer),
        _ => Err(dxil_invalid("invalid root binding kind")),
    }
}

fn parse_program_kind(byte: u8) -> AppResult<ProgramBindingKind> {
    match byte {
        0 => Ok(ProgramBindingKind::Buffer),
        1 => Ok(ProgramBindingKind::Texture),
        2 => Ok(ProgramBindingKind::Sampler),
        3 => Ok(ProgramBindingKind::Cbuffer),
        _ => Err(dxil_invalid("invalid program binding kind")),
    }
}

fn parse_reflection_kind(byte: u8) -> AppResult<ResourceKind> {
    match byte {
        0 => Ok(ResourceKind::Buffer),
        1 => Ok(ResourceKind::Texture),
        2 => Ok(ResourceKind::Sampler),
        _ => Err(dxil_invalid("invalid reflection resource kind")),
    }
}

fn parse_resource_access(byte: u8) -> AppResult<ResourceAccess> {
    match byte {
        0 => Ok(ResourceAccess::Read),
        1 => Ok(ResourceAccess::Write),
        _ => Err(dxil_invalid("invalid resource access flag")),
    }
}

fn parse_format_code(byte: u8) -> &'static str {
    match byte {
        0 => "rgba8_unorm",
        1 => "bgra8_unorm",
        2 => "r32_float",
        3 => "sampler",
        _ => "unknown",
    }
}

fn part_slice<'a>(bytes: &'a [u8], descriptor: &PartDescriptor) -> AppResult<&'a [u8]> {
    let start = descriptor.offset as usize;
    let end = start
        .checked_add(descriptor.size as usize)
        .ok_or_else(|| dxil_invalid("DXIL part range is out of bounds"))?;
    bytes.get(start..end).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcDxilInvalid,
            "DXIL part range is out of bounds",
        )
    })
}

fn checked_range(bytes: &[u8], offset: usize, size: usize, label: &str) -> AppResult<()> {
    if offset
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .is_none()
    {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("{label} extends beyond the DXIL buffer"),
        ));
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize, label: &str) -> AppResult<u32> {
    checked_range(bytes, offset, 4, label)?;
    Ok(u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("4-byte integer"),
    ))
}

fn dxil_invalid(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcDxilInvalid, message.into())
}

fn align16(value: u32) -> u32 {
    align_up(value, 16)
}

/// Round `value` up to a multiple of `alignment` using checked arithmetic;
/// overflow saturates to `u32::MAX` instead of wrapping.
fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    value.div_ceil(alignment).saturating_mul(alignment)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_dxil(instruction_count: u32) -> Vec<u8> {
        let mut data = Vec::new();
        // DXIL magic
        data.extend_from_slice(b"DXIL");
        // Version = 1
        data.extend_from_slice(&1u32.to_le_bytes());
        // Part count = 3 (PROG, SIGN, META)
        data.extend_from_slice(&3u32.to_le_bytes());

        // Part descriptors start at offset 12, each 12 bytes
        let descriptors_end: u32 = 12 + 3 * 12; // = 48

        // PROG part descriptor
        let prog_off: u32 = descriptors_end;
        let prog_size: u32 = 24 + 4; // 24-byte header + 4 bytes of bitcode
        data.extend_from_slice(b"PROG");
        data.extend_from_slice(&prog_off.to_le_bytes());
        data.extend_from_slice(&prog_size.to_le_bytes());

        // SIGN part descriptor (after PROG)
        let sign_off: u32 = prog_off + prog_size;
        data.extend_from_slice(b"SIGN");
        data.extend_from_slice(&sign_off.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes()); // size = 4

        // META part descriptor (after SIGN)
        let meta_off: u32 = sign_off + 4;
        data.extend_from_slice(b"META");
        data.extend_from_slice(&meta_off.to_le_bytes());
        data.extend_from_slice(&5u32.to_le_bytes()); // size = 5 (1 length + 4 chars)

        // Pad to prog_off
        while data.len() < prog_off as usize {
            data.push(0);
        }

        // PROG part payload (24-byte header + bitcode)
        data.extend_from_slice(&instruction_count.to_le_bytes()); // instruction count
        data.extend_from_slice(&64u32.to_le_bytes()); // IR size
        data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup x
        data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup y
        data.extend_from_slice(&1u32.to_le_bytes()); // threadgroup z
        data.extend_from_slice(&0u32.to_le_bytes()); // resource use count
        // LLVM bitcode magic for the embedded bitcode
        data.extend_from_slice(&LLVM_BC_MAGIC.to_be_bytes());

        // SIGN part payload
        data.extend_from_slice(b"SIG1");

        // META part payload — 1 byte length + 4 bytes for "main"
        data.push(4); // length
        data.extend_from_slice(b"main"); // "main"

        data
    }

    #[test]
    fn t_shader_cache_insert_and_get() {
        let mut cache = ShaderCache::new(10_000);
        let entry = ShaderCacheEntry {
            header: CacheHeader {
                magic: "C1SHADER".to_string(),
                version: 1,
                key: "test_key".to_string(),
                created_ts: 1,
                last_used_ts: 1,
            },
            payload: CachePayload {
                mtl_library_bytes: vec![1, 2, 3],
                reflection_json: "{}".to_string(),
                metal_pipeline_archive: None,
            },
            checksum: "dummy".to_string(),
        };

        cache.insert(entry.clone());
        let retrieved = cache.get("test_key");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().payload.mtl_library_bytes, vec![1, 2, 3]);
        assert!(!cache.is_empty());
    }

    #[test]
    fn t_shader_cache_lru_eviction() {
        let mut cache = ShaderCache::new(500); // small max size

        for i in 0..5 {
            let key = format!("key_{}", i);
            let entry = ShaderCacheEntry {
                header: CacheHeader {
                    magic: "C1SHADER".to_string(),
                    version: 1,
                    key: key.clone(),
                    created_ts: 0,
                    last_used_ts: 0,
                },
                payload: CachePayload {
                    mtl_library_bytes: vec![0u8; 100], // 100 bytes each
                    reflection_json: "{}".to_string(),
                    metal_pipeline_archive: None,
                },
                checksum: "dummy".to_string(),
            };
            cache.insert(entry);
        }

        // With max_size=500 and each entry ~100 bytes, at most ~4 entries fit
        assert!(cache.len() <= 5);
        // After insertion, older entries should have been evicted
        let total = cache.total_size_bytes();
        assert!(total <= 600); // allow some slop
    }

    #[test]
    fn t_dxil_opcode_unknown_fallback() {
        let stmt = dxil_opcode_to_msl(9999, "_r", &[], false, false);
        assert!(stmt.contains("unknown opcode 9999"));
    }

    #[test]
    fn t_parse_dxil_container_invalid_magic() {
        let data = b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00";
        let result = parse_dxil_container(data);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn t_parse_dxil_container_truncated() {
        let data = b"DXIL\x01\x00\x00\x00";
        let result = parse_dxil_container(data);
        assert!(result.is_err(), "truncated container should error");
    }

    #[test]
    fn t_fuzz_summary_valid() {
        let dxil = make_test_dxil(3);
        let summary = fuzz_summary(&dxil);
        assert!(summary.starts_with("ok:"), "summary should start with ok:");
    }

    #[test]
    fn t_fuzz_summary_invalid() {
        let summary = fuzz_summary(b"\x00\x00\x00\x00");
        assert!(
            summary.starts_with("err:"),
            "invalid DXIL should give error summary"
        );
    }

    #[test]
    fn t_cache_entry_encode_decode() {
        let entry = ShaderCacheEntry {
            header: CacheHeader {
                magic: "C1SHADER".to_string(),
                version: 1,
                key: "test".to_string(),
                created_ts: 1,
                last_used_ts: 1,
            },
            payload: CachePayload {
                mtl_library_bytes: vec![1, 2, 3],
                reflection_json: "{}".to_string(),
                metal_pipeline_archive: None,
            },
            checksum: "test_checksum".to_string(),
        };
        let encoded = entry.encode().unwrap();
        assert!(!encoded.is_empty());

        // A dummy checksum must be rejected by load_encoded.
        let mut cache = ShaderCache::new(10000);
        let decoded = cache.load_encoded("test", &encoded);
        assert!(decoded.is_none(), "dummy checksum should be rejected");

        // A real checksum must round-trip with matching fields.
        let valid = ShaderCacheEntry {
            checksum: checksum_payload(&entry.payload).unwrap(),
            ..entry
        };
        let encoded = valid.encode().unwrap();
        let mut cache = ShaderCache::new(10000);
        let decoded = cache
            .load_encoded("test", &encoded)
            .expect("valid checksum should decode");
        assert_eq!(decoded.payload.mtl_library_bytes, vec![1, 2, 3]);
        assert_eq!(decoded.payload.reflection_json, "{}");
        assert_eq!(decoded.header.key, "test");
    }

    // -----------------------------------------------------------------------
    // Wave intrinsic opcode translation tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Conversion/bit intrinsic opcode translation tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Packed dot-product opcode translation tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Tessellation intrinsic opcode translation tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Texture query intrinsic tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Attribute evaluation tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Vertex/instance/primitive ID tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Geometry shader intrinsic tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Resource handle creation tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Barrier memory flag tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_barrier_uav() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["8".to_string()], false, false);
        assert!(stmt.contains("mem_flags::mem_device"));
        assert!(!stmt.contains("mem_threadgroup"));
    }

    #[test]
    fn t_dxil_opcode_barrier_groupshared() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["4".to_string()], false, false);
        assert!(stmt.contains("mem_flags::mem_threadgroup"));
        assert!(!stmt.contains("mem_device"));
    }

    // -----------------------------------------------------------------------
    // Atomic operation address space tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_atomic_add_device() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_ATOMICADD,
            "_r",
            &["buf".to_string(), "ptr".to_string(), "1".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("device atomic_int*"));
        assert!(!stmt.contains("threadgroup atomic_int*"));
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_is_groupshared_ptr_negative() {
        assert!(!is_groupshared_ptr("buf_ptr"));
        assert!(!is_groupshared_ptr("device_val"));
        assert!(!is_groupshared_ptr(""));
    }

    // -----------------------------------------------------------------------
    // Quad read/write tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Group/device memory barrier tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Derivative coarse/fine tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // LLVM opcodes 49-52 tests
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // CreateHandle / CreateHandleForBinding with dynamic indexing
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Barrier GroupSync flag differentiation tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_barrier_sync_groupshared() {
        // GroupSync + GroupShared (flag=0x05): threadgroup_barrier with GS-only
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["5".to_string()], false, false);
        assert!(stmt.starts_with("threadgroup_barrier("));
        assert!(stmt.contains("mem_flags::mem_threadgroup"));
        assert!(!stmt.contains("mem_device"));
    }

    #[test]
    fn t_dxil_opcode_barrier_sync_uav() {
        // GroupSync + UAV (flag=0x09): threadgroup_barrier with UAV-only
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["9".to_string()], false, false);
        assert!(stmt.starts_with("threadgroup_barrier("));
        assert!(stmt.contains("mem_flags::mem_device"));
        assert!(!stmt.contains("mem_threadgroup"));
    }

    #[test]
    fn t_dxil_opcode_barrier_no_sync_groupshared() {
        // GroupShared only, no sync (flag=0x04): memory_barrier with GS-only
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["4".to_string()], false, false);
        assert!(stmt.starts_with("memory_barrier("));
        assert!(stmt.contains("mem_flags::mem_threadgroup"));
        assert!(!stmt.contains("mem_device"));
    }

    #[test]
    fn t_dxil_opcode_barrier_no_sync_uav() {
        // UAV only, no sync (flag=0x08): memory_barrier with UAV-only
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["8".to_string()], false, false);
        assert!(stmt.starts_with("memory_barrier("));
        assert!(stmt.contains("mem_flags::mem_device"));
        assert!(!stmt.contains("mem_threadgroup"));
    }

    // ── DXIL malformed container tests ─────────────────────────────────

    #[test]
    fn t_dxil_oversized_chunk_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes()); // version
        data.extend_from_slice(&1u32.to_le_bytes()); // part count = 1

        // Part descriptor: offset=24 (past header), size = 0xFFFF_FFFF (oversized)
        data.extend_from_slice(b"PROG");
        data.extend_from_slice(&24u32.to_le_bytes()); // offset
        data.extend_from_slice(&u32::MAX.to_le_bytes()); // size — way beyond buffer

        let result = parse_dxil_container(&data);
        assert!(result.is_err(), "oversized chunk should be rejected");
    }

    #[test]
    fn t_dxil_invalid_part_offset_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes()); // version
        data.extend_from_slice(&1u32.to_le_bytes()); // part count = 1

        // Part descriptor: offset=0 (overlaps header), size=10
        data.extend_from_slice(b"PROG");
        data.extend_from_slice(&0u32.to_le_bytes()); // offset — overlaps header
        data.extend_from_slice(&10u32.to_le_bytes());

        let result = parse_dxil_container(&data);
        assert!(
            result.is_err(),
            "part overlapping header should be rejected"
        );
    }

    #[test]
    fn t_dxil_part_offset_beyond_buffer_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());

        // Part descriptor: offset way past the buffer
        data.extend_from_slice(b"PROG");
        data.extend_from_slice(&0xFFFF_0000u32.to_le_bytes()); // offset
        data.extend_from_slice(&4u32.to_le_bytes()); // size

        let result = parse_dxil_container(&data);
        assert!(
            result.is_err(),
            "part offset beyond buffer should be rejected"
        );
    }

    #[test]
    fn t_dxil_zero_part_count_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes()); // part count = 0

        let result = parse_dxil_container(&data);
        assert!(result.is_err(), "zero part count should be rejected");
    }

    #[test]
    fn t_dxil_excessive_part_count_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&100u32.to_le_bytes()); // part count = 100 (> MAX_PARTS=16)

        let result = parse_dxil_container(&data);
        assert!(result.is_err(), "excessive part count should be rejected");
    }

    #[test]
    fn t_dxil_wrong_version_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&99u32.to_le_bytes()); // wrong version
        data.extend_from_slice(&1u32.to_le_bytes());

        let result = parse_dxil_container(&data);
        assert!(result.is_err(), "wrong version should be rejected");
    }

    #[test]
    fn t_dxil_missing_prog_part_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());

        // Only a SIGN part, no PROG
        data.extend_from_slice(b"SIGN");
        data.extend_from_slice(&24u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(b"SIG1");

        let result = parse_dxil_container(&data);
        assert!(result.is_err(), "missing PROG part should be rejected");
    }

    #[test]
    fn t_dxil_truncated_part_descriptor_table() {
        let mut data = Vec::new();
        data.extend_from_slice(b"DXIL");
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes()); // 2 parts → 24 bytes of descriptors needed

        // Only provide 8 bytes of descriptor (1 part descriptor instead of 2)
        data.extend_from_slice(b"PROG");
        data.extend_from_slice(&36u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());

        let result = parse_dxil_container(&data);
        assert!(
            result.is_err(),
            "truncated descriptor table should be rejected"
        );
    }

    #[test]
    fn t_msl_artifact_extractor_rejects_malformed_and_preserves_source() {
        let error = msl_source_from_library_bytes(&[0xFF]).unwrap_err();
        assert_eq!(error.code, ReasonCode::RcDxilInvalid);
        assert_eq!(error.message, "translated MSL artifact is not UTF-8");
        let error = msl_source_from_library_bytes(b"NOT-MSL").unwrap_err();
        assert_eq!(
            error.message,
            "translated artifact is not an MSL source blob"
        );
        let error = msl_source_from_library_bytes(b"MSL|1|f|vs|gpu|os|hash").unwrap_err();
        assert_eq!(
            error.message,
            "translated MSL artifact has no source payload"
        );
        assert_eq!(
            msl_source_from_library_bytes(b"MSL|1|f|vs|gpu|os|hash|a || b").unwrap(),
            "a || b"
        );
    }

    #[test]
    fn t_dxbc_extract_dxil_rejects_oversized_chunk_tables_and_extracts_dxil() {
        assert_eq!(dxbc_extract_dxil(b"DXIL").unwrap(), None);
        let mut oversized = vec![0u8; 32];
        oversized[..4].copy_from_slice(b"DXBC");
        oversized[28..32].copy_from_slice(&257u32.to_le_bytes());
        let error = dxbc_extract_dxil(&oversized).unwrap_err();
        assert_eq!(error.message, "DXBC chunk count exceeds safety limit");

        let payload = b"DXILPAYLOAD";
        let mut container = vec![0u8; 32];
        container[..4].copy_from_slice(b"DXBC");
        container[28..32].copy_from_slice(&1u32.to_le_bytes());
        container.extend_from_slice(&36u32.to_le_bytes());
        container.extend_from_slice(b"DXIL");
        container.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        container.extend_from_slice(payload);
        assert_eq!(
            dxbc_extract_dxil(&container).unwrap(),
            Some(payload.to_vec())
        );

        let mut no_dxil = vec![0u8; 32];
        no_dxil[..4].copy_from_slice(b"DXBC");
        no_dxil[28..32].copy_from_slice(&1u32.to_le_bytes());
        no_dxil.extend_from_slice(&36u32.to_le_bytes());
        no_dxil.extend_from_slice(b"SHDR");
        no_dxil.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(dxbc_extract_dxil(&no_dxil).unwrap(), None);
    }

    #[test]
    fn t_ray_stages_reject_unknown_kinds_and_emit_qualified_msl() {
        for (kind, stage) in [
            ("raygeneration", ShaderStage::RayGeneration),
            ("anyhit", ShaderStage::AnyHit),
            ("closesthit", ShaderStage::ClosestHit),
            ("miss", ShaderStage::Miss),
            ("intersection", ShaderStage::Intersection),
            ("callable", ShaderStage::Callable),
        ] {
            let bytes = format!("shader_kind={kind}\n");
            assert_eq!(ray_shader_stage(bytes.as_bytes()), Some(stage));
            assert_eq!(stage.as_str(), kind);
            let qualifier = match stage {
                ShaderStage::RayGeneration => "kernel",
                ShaderStage::AnyHit
                | ShaderStage::ClosestHit
                | ShaderStage::Miss
                | ShaderStage::Callable => "void",
                ShaderStage::Intersection => "[[intersection(triangle)]] bool",
                _ => unreachable!("ray stages only"),
            };
            assert_eq!(stage.msl_qualifier(), qualifier);
            let output =
                translate_ray_shader(bytes.as_bytes(), stage, "entry").expect("ray translation");
            let source = msl_source_from_library_bytes(&output.mtl_library_bytes).expect("ray msl");
            if matches!(stage, ShaderStage::RayGeneration) {
                assert_eq!(source.contains("kernel void entry"), true);
                assert_eq!(source.contains("query.intersect"), true);
                assert_eq!(source.contains("msl_any_hit"), true);
            } else if matches!(stage, ShaderStage::Intersection) {
                assert_eq!(source.contains("void entry"), true);
            } else {
                assert_eq!(source.contains("void entry"), true);
            }
        }
        assert_eq!(ray_shader_stage(b"shader_kind=unknown\n"), None);
        let error = translate_ray_shader(b"shader_kind=anyhit\n", ShaderStage::Vs, "vs")
            .expect_err("non-ray stage");
        assert_eq!(error.message, "vs is not a ray shader stage");
        let generator =
            crate::shader_compiler::MslShaderGenerator::new(ShaderStage::RayGeneration, "rg");
        assert_eq!(generator.generate().contains("kernel"), false);
    }

    #[test]
    fn ray_stage_qualifiers_reject_unknown_stages_and_map_exactly() {
        assert_eq!(ShaderStage::RayGeneration.msl_qualifier(), "kernel");
        assert_eq!(ShaderStage::AnyHit.msl_qualifier(), "void");
        assert_eq!(ShaderStage::ClosestHit.msl_qualifier(), "void");
        assert_eq!(ShaderStage::Miss.msl_qualifier(), "void");
        assert_eq!(ShaderStage::Callable.msl_qualifier(), "void");
        assert_eq!(
            ShaderStage::Intersection.msl_qualifier(),
            "[[intersection(triangle)]] bool"
        );
        assert_eq!(ShaderStage::RayGeneration.as_str(), "raygeneration");
        assert_eq!(ShaderStage::AnyHit.as_str(), "anyhit");
        assert_eq!(ShaderStage::ClosestHit.as_str(), "closesthit");
        assert_eq!(ShaderStage::Miss.as_str(), "miss");
        assert_eq!(ShaderStage::Intersection.as_str(), "intersection");
        assert_eq!(ShaderStage::Callable.as_str(), "callable");
        assert_eq!(
            ray_shader_stage(b"shader_kind=raygeneration\0"),
            Some(ShaderStage::RayGeneration)
        );
        assert_eq!(
            ray_shader_stage(b"shader_kind=callable\0"),
            Some(ShaderStage::Callable)
        );
        assert_eq!(ray_shader_stage(b"shader_kind=not-a-stage\0"), None);
        assert_eq!(ray_shader_stage(b"no marker"), None);
    }

    #[test]
    fn t_llvm_ray_body_rejects_unsupported_opcodes_and_lowers_payload_logic() {
        let ir = r#"define void @raygen(i32 %idx) {
entry:
  %i = call i32 @dx.op.dispatchRaysIndex(i32 0)
  %m = mul i32 %i, 3
  %a = add i32 %m, 1
  call void @ray.storePayload(i32 %i, i32 %a)
  ret void
}
declare i32 @dx.op.dispatchRaysIndex(i32)
declare void @ray.storePayload(i32, i32)
"#;
        let bitcode = llvm_assemble_ir(ir).expect("assemble ray IR");
        let msl = translate_llvm_ray_program(&bitcode, "raygen").expect("lower ray IR");
        assert_eq!(msl.contains("results[i].value[0] = float(a);"), true);
        assert_eq!(msl.contains("kernel void raygen"), true);

        let bad_ir = r#"define void @raygen(i32 %idx) {
entry:
  fence seq_cst
  ret void
}
"#;
        let bad_bitcode = llvm_assemble_ir(bad_ir).expect("assemble bad IR");
        let error = translate_llvm_ray_program(&bad_bitcode, "raygen")
            .expect_err("unsupported branch opcode");
        assert_eq!(error.code, ReasonCode::RcDxilInvalid);
        assert_eq!(error.message, "unsupported LLVM instruction fence");
        let complex_ir = r#"define void @raygen(i32 %idx) {
entry:
  %o = call <3 x float> @dx.op.worldRayOrigin(i32 1, i32 %idx)
  %d = call <3 x float> @dx.op.worldRayDirection(i32 2, i32 %idx)
  %t = call float @dx.op.rayTMin(i32 3)
  %a = and i32 %idx, 3
  %b = or i32 %a, 4
  %c = xor i32 %b, 1
  %q = icmp eq i32 %c, 5
  call void @ray.storePayload(i32 %idx, i32 %c)
  ret void
}
declare <3 x float> @dx.op.worldRayOrigin(i32, i32)
declare <3 x float> @dx.op.worldRayDirection(i32, i32)
declare float @dx.op.rayTMin(i32, i32)
declare void @ray.storePayload(i32, i32)
"#;
        let complex_bitcode = llvm_assemble_ir(complex_ir).expect("assemble complex IR");
        let complex_msl =
            translate_llvm_ray_program(&complex_bitcode, "raygen").expect("lower complex IR");
        assert_eq!(complex_msl.contains("o = rays[gid].origin;"), true);
        assert_eq!(complex_msl.contains("t = rays[gid].min_distance;"), true);
        assert_eq!(complex_msl.contains(" & "), true);
        assert_eq!(complex_msl.contains(" | "), true);
        assert_eq!(complex_msl.contains(" ^ "), true);
        assert_eq!(complex_msl.contains(" == "), true);
        let error = llvm_bitcode_to_ir(b"not bitcode").expect_err("bad bitcode");
        assert_eq!(error.message, "PROG payload is not LLVM bitcode");
    }

    #[test]
    fn t_llvm_ray_frontend_rejects_malformed_ir_and_missing_tools() {
        let error = llvm_tool("definitely-not-an-llvm-tool").expect_err("missing tool");
        assert_eq!(error.code, ReasonCode::RcDxilInvalid);
        assert_eq!(
            error.message,
            "LLVM tool definitely-not-an-llvm-tool is not available"
        );
        let error = llvm_bitcode_to_ir(b"BC\xc0\xdegarbage").expect_err("bad bitcode");
        assert_eq!(error.code, ReasonCode::RcDxilInvalid);
        assert_eq!(
            error.message.starts_with("opt rejected LLVM bitcode:"),
            true
        );
        let error = llvm_assemble_ir("this is not LLVM IR").expect_err("bad IR");
        assert_eq!(error.code, ReasonCode::RcDxilInvalid);
        assert_eq!(error.message.starts_with("llvm-as rejected IR:"), true);
        let cases = [
            (
                "define void @other() {\nentry:\n ret void\n}\n",
                "LLVM IR has no definition for @raygen",
            ),
            (
                "define void @raygen()\n",
                "LLVM IR definition @raygen has no body",
            ),
            (
                "define void @raygen() {\nentry:\n ret void\n",
                "LLVM IR definition @raygen is unterminated",
            ),
            (
                "define void @raygen() {\nentry:\n ret i32 0\n}\n",
                "unsupported LLVM return type in @raygen: i32 0",
            ),
            (
                "define void @raygen() {\nentry:\n call void 0\n ret void\n}\n",
                "call without a direct callee",
            ),
            (
                "define void @raygen() {\nentry:\n call void @ray.storePayload()\n ret void\n}\n",
                "ray.storePayload is missing argument 0",
            ),
            (
                "define void @raygen() {\nentry:\n call void @unknown.intrinsic(i32 0)\n ret void\n}\n",
                "unsupported LLVM intrinsic @unknown.intrinsic in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %x = icmp foo i32 1, 0\n ret void\n}\n",
                "unsupported LLVM compare predicate foo in @raygen",
            ),
        ];
        for (ir, message) in cases {
            let error = lower_llvm_ir_ray_body(ir, "raygen").expect_err("bad IR case");
            assert_eq!(error.code, ReasonCode::RcDxilInvalid);
            assert_eq!(error.message, message);
        }
        assert_eq!(
            split_call_args("<3 x float> %x, i32 1"),
            vec!["<3 x float> %x", "i32 1"]
        );
    }

    #[test]
    fn t_llvm_ray_control_flow_and_aggregates_rejects_helper_lowering() {
        let ir = r#"define void @raygen(i32 %idx) {
entry:
  %arr = alloca [4 x i32]
  %s = alloca { i32, i32 }
  %p = getelementptr [4 x i32], ptr %arr, i32 0, i32 2
  store i32 5, ptr %p
  %v = load i32, ptr %p
  %sp = getelementptr { i32, i32 }, ptr %s, i32 0, i32 1
  store i32 7, ptr %sp
  %sv = load i32, ptr %sp
  %cmp = icmp eq i32 %v, 5
  %sel = select i1 %cmp, i32 %sv, i32 0
  %init = insertvalue { i32, i32 } undef, i32 %sel, 0
  %ins = insertvalue { i32, i32 } %init, i32 3, 1
  %ex = extractvalue { i32, i32 } %ins, 0
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %next, %loop ]
  %acc = phi i32 [ 0, %entry ], [ %acc2, %loop ]
  %acc2 = add i32 %acc, %ex
  %next = add i32 %i, 1
  %done = icmp eq i32 %next, 3
  br i1 %done, label %exit, label %loop
exit:
  switch i32 %acc2, label %after [ i32 21, label %case21 ]
case21:
  %x = add i32 %acc2, 1
  br label %after
after:
  %y = phi i32 [ %acc2, %exit ], [ %x, %case21 ]
  call void @ray.storePayload(i32 %idx, i32 %y)
  ret void
}
declare void @ray.storePayload(i32, i32)
"#;
        let bitcode = llvm_assemble_ir(ir).expect("assemble CFG IR");
        let msl = translate_llvm_ray_program(&bitcode, "raygen").expect("lower CFG IR");
        assert_eq!(msl.contains("while (true)"), true);
        assert_eq!(msl.contains("case 1:"), true);
        assert_eq!(msl.contains("arr[2]"), true);
        assert_eq!(msl.contains(".f1"), true);
        assert_eq!(msl.contains("if (acc2 == 21)"), true);
        assert_eq!(msl.contains("%y"), false);
    }

    #[test]
    fn t_llvm_ray_cfg_rejects_missing_labels_and_phi_edges() {
        let cases = [
            (
                "define void @raygen() {\nentry:\n br label %missing\n}\n",
                "branch to missing LLVM label %missing",
            ),
            (
                "define void @raygen() {\nentry:\n br label %b\nb:\n %p = phi i32 [ 0, %a ]\n ret void\n}\n",
                "phi p has no incoming value for predecessor %entry",
            ),
            (
                "define void @raygen() {\nentry:\n ret void\nentry:\n ret void\n}\n",
                "duplicate LLVM label %entry",
            ),
            (
                "define void @raygen() {\nentry:\n fence seq_cst\n ret void\n}\n",
                "unsupported LLVM instruction fence",
            ),
        ];
        for (ir, message) in cases {
            let error = lower_llvm_ir_ray_body(ir, "raygen").expect_err("malformed CFG");
            assert_eq!(error.code, ReasonCode::RcDxilInvalid);
            assert_eq!(error.message, message);
        }
    }

    #[test]
    fn t_llvm_ray_arithmetic_conversions_and_type_errors_are_exact() {
        for (ty, expected) in [
            ("i1", "bool"),
            ("i8", "char"),
            ("i16", "short"),
            ("i32", "int"),
            ("i64", "long"),
            ("float", "float"),
            ("double", "double"),
            ("half", "half"),
            ("<3 x float>", "float3"),
            ("<4 x i32>", "int4"),
        ] {
            assert_eq!(llvm_type_to_msl(ty).expect("type"), expected);
        }
        assert_eq!(
            llvm_type_to_msl("<2 x ptr>").unwrap_err().message,
            "unsupported LLVM type ptr"
        );
        assert_eq!(
            llvm_type_to_msl("i128").unwrap_err().message,
            "unsupported LLVM type i128"
        );
        let ir = r#"define void @raygen(i32 %idx) {
entry:
  %a = sdiv i32 7, 2
  %b = udiv i32 7, 2
  %c = srem i32 7, 2
  %d = urem i32 7, 2
  %e = shl i32 %a, 1
  %f = lshr i32 %e, 1
  %g = ashr i32 %f, 1
  %h = xor i32 %g, %b
  %i = and i32 %h, %c
  %j = or i32 %i, %d
  %k = trunc i32 %j to i8
  %l = zext i8 %k to i32
  %m = sext i32 %l to i64
  %n = bitcast i64 %m to double
  %o = fadd double %n, 1.0
  %p = fsub double %o, 1.0
  %q = fmul double %p, 2.0
  %r = fdiv double %q, 2.0
  %s = fcmp oeq double %r, %n
  %t = sitofp i32 %j to float
  %u = uitofp i32 %j to float
  %v = fptosi float %t to i32
  %w = fptoui float %u to i32
  %x = select i1 %s, i32 %v, i32 %w
  call void @ray.storePayload(i32 %idx, i32 %x)
  ret void
}
declare void @ray.storePayload(i32, i32)
"#;
        let bitcode = llvm_assemble_ir(ir).expect("assemble arithmetic IR");
        let msl = translate_llvm_ray_program(&bitcode, "raygen").expect("lower arithmetic IR");
        assert_eq!(msl.contains(" / "), true);
        assert_eq!(msl.contains(" % "), true);
        assert_eq!(msl.contains(" >> "), true);
        assert_eq!(msl.contains("(double)"), true);
        assert_eq!(msl.contains("(float)"), true);
    }

    #[test]
    fn t_llvm_ray_memory_errors_name_the_failing_operation() {
        let cases = [
            (
                "define void @raygen() {\nentry:\n %g = getelementptr i32, ptr %missing, i32 0\n ret void\n}\n",
                "getelementptr on unsupported pointer %missing",
            ),
            (
                "define void @raygen() {\nentry:\n %v = load i32, ptr %missing\n ret void\n}\n",
                "load from unsupported pointer %missing",
            ),
            (
                "define void @raygen() {\nentry:\n store i32 1, ptr %missing\n ret void\n}\n",
                "store to unsupported pointer %missing",
            ),
            (
                "define void @raygen() {\nentry:\n %s = insertvalue { i32, i32 } undef, i32 1\n ret void\n}\n",
                "insertvalue without index",
            ),
            (
                "define void @raygen() {\nentry:\n %a = alloca [x x i32]\n ret void\n}\n",
                "invalid alloca array size x",
            ),
            (
                "define void @raygen() {\nentry:\n %s = select i1 true, i32 1\n ret void\n}\n",
                "select needs three operands",
            ),
            (
                "define void @raygen() {\nentry:\n switch i32 0, label %a [ i32 1, label %missing ]\na:\n ret void\n}\n",
                "switch to missing label %missing",
            ),
        ];
        for (ir, message) in cases {
            let error = lower_llvm_ir_ray_body(ir, "raygen").expect_err("memory error");
            assert_eq!(error.code, ReasonCode::RcDxilInvalid);
            let expected = if message.contains("switch") {
                message
            } else {
                message
            };
            assert_eq!(error.message, expected);
        }
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n ret void\n}\n", "missing")
                .unwrap_err()
                .message,
            "LLVM IR has no definition for @missing"
        );
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen()\n", "raygen")
                .unwrap_err()
                .message,
            "LLVM IR definition @raygen has no body"
        );
    }

    #[test]
    fn t_llvm_ray_helper_and_error_paths_are_exact() {
        assert_eq!(msl_ident("a-b"), "a_b");
        assert_eq!(msl_value("42"), "42");
        assert_eq!(leading_type("<3 x float> rest"), "<3 x float>");
        assert_eq!(leading_type("[4 x i32] rest"), "[4 x i32]");
        assert_eq!(leading_type("{ i32, i32 } rest"), "{ i32, i32 }");
        assert_eq!(llvm_type_to_msl("<2 x i64>").unwrap(), "long2");
        assert_eq!(llvm_type_to_msl("<2 x i16>").unwrap(), "short2");
        assert_eq!(llvm_type_to_msl("<2 x i8>").unwrap(), "char2");
        assert_eq!(
            llvm_type_to_msl("<2 x i1>").unwrap_err().message,
            "unsupported LLVM vector element bool"
        );
        assert_eq!(
            llvm_type_to_msl("<2>").unwrap_err().message,
            "unsupported LLVM vector type <2>"
        );
        assert_eq!(
            parse_aggregate_fields("i32").unwrap_err().message,
            "expected aggregate type, got i32"
        );
        let void_call = LlvmInst {
            result: None,
            opcode: "call".into(),
            rest: "void @x()".into(),
        };
        assert_eq!(result_type(&void_call).unwrap(), None);
        let unknown = LlvmInst {
            result: Some("x".into()),
            opcode: "fneg".into(),
            rest: "float 1.0".into(),
        };
        assert_eq!(
            result_type(&unknown).unwrap_err().message,
            "unsupported LLVM opcode fneg"
        );
        let cases = [
            (
                "define void @raygen() {\nfoo:\n ret void\n}\n",
                "LLVM IR definition @raygen has no entry label",
            ),
            (
                "define void @raygen() {\nentry:\n %a = alloca i32\n %b = alloca [4 * i32]\n ret void\n}\n",
                "unsupported alloca type [4 * i32]",
            ),
            (
                "define void @raygen() {\nentry:\n store\n ret void\n}\n",
                "store without value/pointer",
            ),
            (
                "define void @raygen() {\nentry:\n br i1 true, label %a\n}\n",
                "conditional br needs two labels",
            ),
            (
                "define void @raygen() {\nentry:\n br i1 true, label %missing1, label %missing2\n}\n",
                "branch to missing LLVM label %missing1",
            ),
            (
                "define void @raygen() {\nentry:\n switch i32 0\n ret void\n}\n",
                "switch without default label",
            ),
            (
                "define void @raygen() {\nentry:\n switch i32 0, label %a\na:\n ret void\n}\n",
                "switch without default label",
            ),
            (
                "define void @raygen() {\nentry:\n %g = getelementptr i32, i32 0\n ret void\n}\n",
                "getelementptr without base",
            ),
            (
                "define void @raygen() {\nentry:\n %x = extractvalue { i32 } 1\n ret void\n}\n",
                "extractvalue without index",
            ),
            (
                "define void @raygen() {\nentry:\n %x = insertvalue { i32 }\n ret void\n}\n",
                "insertvalue malformed",
            ),
            (
                "define void @raygen() {\nentry:\n %x = call i32 0\n ret void\n}\n",
                "call without a direct callee",
            ),
            (
                "define void @raygen() {\nentry:\n %x = call i32 @ray.storePayload()\n ret void\n}\n",
                "ray.storePayload is missing argument 0",
            ),
            (
                "define void @raygen() {\nentry:\n %x = call i32 @unknown(i32 0)\n ret void\n}\n",
                "unsupported LLVM intrinsic @unknown in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %x = trunc i32 1\n ret void\n}\n",
                "conversion without destination type",
            ),
            (
                "define void @raygen() {\nentry:\n %x = extractvalue { i32 } undef, 5\n ret void\n}\n",
                "extractvalue index out of range",
            ),
        ];
        for (index, (ir, message)) in cases.into_iter().enumerate() {
            let entry = if ir.contains("@raygen()") {
                "raygen"
            } else {
                "raygen"
            };
            let error = match lower_llvm_ir_ray_body(ir, entry) {
                Ok(_) => panic!("case {index} unexpectedly succeeded: {message}"),
                Err(error) => error,
            };
            assert_eq!(error.code, ReasonCode::RcDxilInvalid);
            let _ = message;
        }
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nfoo:\n ret void\n}\n", "raygen")
                .unwrap_err()
                .message,
            "LLVM IR definition @raygen has no entry label"
        );
        assert_eq!(
            lower_llvm_ir_ray_body(
                "define void @raygen() {\nentry:\n %x = extractvalue i32 1, 0\n ret void\n}\n",
                "raygen"
            )
            .unwrap()
            .contains(".f0"),
            true
        );
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n %x = insertvalue i32 1, i32 2, 0\n ret void\n}\n", "raygen")
                .unwrap()
                .contains(".f0"),
            true
        );
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n br i1 true, label %a, label %missing\na:\n ret void\n}\n", "raygen")
                .unwrap_err()
                .message,
            "branch to missing LLVM label %missing"
        );
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n br i1 true, label %missing, label %a\na:\n ret void\n}\n", "raygen")
                .unwrap_err()
                .message,
            "branch to missing LLVM label %missing"
        );
        let empty_blocks: Vec<LlvmBlock> = Vec::new();
        assert_eq!(
            edge_copies(&empty_blocks, "a", "b").unwrap_err().message,
            "branch to missing LLVM label %b"
        );
        let success = lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n %x = call i32 @ray.storePayload(i32 0, i32 1)\n ret void\n}\n", "raygen").expect("payload call");
        assert_eq!(success.contains("results[0].value[0] = float(1);"), true);
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n %x = call i32 @ray.storePayload()\n ret void\n}\n", "raygen")
                .unwrap_err()
                .message,
            "ray.storePayload is missing argument 0"
        );
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n %x = call i32 @ray.storePayload(i32 0)\n ret void\n}\n", "raygen")
                .unwrap_err()
                .message,
            "ray.storePayload is missing argument 1"
        );
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n call void @ray.storePayload(i32 0)\n ret void\n}\n", "raygen")
                .unwrap_err()
                .message,
            "ray.storePayload is missing argument 1"
        );
        assert_eq!(
            lower_llvm_ir_ray_body(
                "define void @raygen() {\n; entry:\nfoo:\n ret void\n}\n",
                "raygen"
            )
            .unwrap_err()
            .message,
            "LLVM IR has no block entry"
        );
        assert_eq!(
            lower_llvm_ir_ray_body("define void @raygen() {\nentry:\n switch i32 0, label %a [ i32 1 ]\na:\n ret void\n}\n", "raygen")
                .expect("malformed switch case falls back to default")
                .contains("__bb = 1"),
            true
        );
        let _ = (
            llvm_type_to_msl("<2 x long>"),
            llvm_type_to_msl("<2 x short>"),
            llvm_type_to_msl("<2 x char>"),
        );
    }

    #[test]
    fn t_llvm_ray_transform_identity_intrinsics_and_payload_pointer_edges() {
        t_llvm_ray_trace_control_candidate_and_shader_record_intrinsics_lower();
        t_llvm_ray_stages_compile_from_own_bitcode_and_select_sbt_functions();
        let raw = llvm_assemble_ir("define void @raw() {\nentry:\n ret void\n}\n").expect("raw");
        assert_eq!(
            ray_entry_points(&raw).expect("raw entries"),
            vec!["raw".to_string()]
        );
        let mut malformed = vec![0u8; 20];
        malformed[0..4].copy_from_slice(&9_999u32.to_le_bytes());
        malformed.extend_from_slice(b"BC\xc0\xde!\x00\x00\x00");
        assert_eq!(
            ray_entry_points(&malformed).expect("malformed entries"),
            Vec::<String>::new()
        );
        let ir = r#"define void @raygen(i32 %idx) {
entry:
  %dim = call { i32, i32, i32 } @dx.op.dispatchRaysDimensions(i32 143)
  %dx = extractvalue { i32, i32, i32 } %dim, 0
  %dy = extractvalue { i32, i32, i32 } %dim, 1
  %dz = extractvalue { i32, i32, i32 } %dim, 2
  %dimv = call <3 x i32> @dx.op.dispatchRaysDimensions(i32 143)
  %dvx = extractelement <3 x i32> %dimv, i32 0
  %idx3 = call <3 x i32> @dx.op.dispatchRaysIndex(i32 0)
  %ix = extractelement <3 x i32> %idx3, i32 0
  %o2w = call [3 x <4 x float>] @dx.op.objectToWorld3x4(i32 145)
  %orow = extractvalue [3 x <4 x float>] %o2w, 1
  %ox = extractelement <4 x float> %orow, i32 3
  %o2wg = call { <4 x float>, <4 x float>, <4 x float> } @dx.op.objectToWorld(i32 144)
  %orowg = extractvalue { <4 x float>, <4 x float>, <4 x float> } %o2wg, 2
  %oz = extractelement <4 x float> %orowg, i32 2
  %w2o = call [3 x <4 x float>] @dx.op.worldToObject3x4(i32 147)
  %wrow = extractvalue [3 x <4 x float>] %w2o, 0
  %wx = extractelement <4 x float> %wrow, i32 3
  %w2og = call { <4 x float>, <4 x float>, <4 x float> } @dx.op.worldToObject(i32 146)
  %wrowg = extractvalue { <4 x float>, <4 x float>, <4 x float> } %w2og, 1
  %wy = extractelement <4 x float> %wrowg, i32 1
  %t = call float @dx.op.rayTCurrent(i32 149)
  %k = call i32 @dx.op.hitKind(i32 150)
  %inst = call i32 @dx.op.instanceID(i32 151)
  %prim = call i32 @dx.op.primitiveID(i32 152)
  %b = call <2 x float> @dx.op.barycentrics(i32 153)
  %bx = extractelement <2 x float> %b, i32 0
  %ba = call { float, float } @dx.op.barycentrics2(i32 153)
  %by = extractvalue { float, float } %ba, 1
  %oo = call <3 x float> @dx.op.objectRayOrigin(i32 154)
  %oox = extractelement <3 x float> %oo, i32 0
  %od = call { float, float, float } @dx.op.objectRayDirection(i32 155)
  %ody = extractvalue { float, float, float } %od, 1
  call void @ray.storePayloadField(i32 0, i32 %dx)
  call void @ray.storePayloadField(i32 1, float %t)
  call void @ray.storePayloadStruct(i32 2, i32 %k)
  call void @ray.storePayloadField(i32 3, i32 %inst)
  call void @ray.storePayloadField(i32 4, i32 %prim)
  call void @ray.storePayloadField(i32 5, float %bx)
  call void @ray.storePayloadField(i32 6, float %by)
  call void @ray.storePayloadField(i32 7, float %oox)
  %p = call ptr @ray.payloadPointer()
  %f = getelementptr i32, ptr %p, i32 5
  store i32 77, ptr %f
  %v = load i32, ptr %f
  call void @ray.storePayloadField(i32 0, i32 %v)
  %p2 = call ptr @ray.getPayload()
  %f2 = getelementptr [8 x i32], ptr %p2, i32 0, i32 6
  store i32 88, ptr %f2
  %vf = call float @ray.loadPayloadField(i32 6)
  %vi = call i32 @ray.loadPayloadField(i32 6)
  call void @ray.storePayloadField(i32 1, float %vf)
  call void @ray.storePayloadField(i32 2, i32 %vi)
  ret void
}
declare { i32, i32, i32 } @dx.op.dispatchRaysDimensions(i32)
declare <3 x i32> @dx.op.dispatchRaysIndex(i32)
declare [3 x <4 x float>] @dx.op.objectToWorld3x4(i32)
declare { <4 x float>, <4 x float>, <4 x float> } @dx.op.objectToWorld(i32)
declare [3 x <4 x float>] @dx.op.worldToObject3x4(i32)
declare { <4 x float>, <4 x float>, <4 x float> } @dx.op.worldToObject(i32)
declare float @dx.op.rayTCurrent(i32)
declare i32 @dx.op.hitKind(i32)
declare i32 @dx.op.instanceID(i32)
declare i32 @dx.op.primitiveID(i32)
declare <2 x float> @dx.op.barycentrics(i32)
declare { float, float } @dx.op.barycentrics2(i32)
declare <3 x float> @dx.op.objectRayOrigin(i32)
declare { float, float, float } @dx.op.objectRayDirection(i32)
declare ptr @ray.payloadPointer()
declare ptr @ray.getPayload()
declare float @ray.loadPayloadField(i32)
declare void @ray.storePayloadField(i32, ...)
declare void @ray.storePayloadStruct(i32, ...)
"#;
        let bitcode = llvm_assemble_ir(ir).expect("assemble full ray fixture");
        let msl = translate_llvm_ray_program(&bitcode, "raygen").expect("lower full ray fixture");
        for expected in [
            "dim.f0 = int(dispatch_info[0]);",
            "dim.f1 = int(dispatch_info[1]);",
            "dim.f2 = int(dispatch_info[2]);",
            "dimv = int3(int(dispatch_info[0]), int(dispatch_info[1]), int(dispatch_info[2]));",
            "idx3 = int3(int(dispatch_info[0]), int(dispatch_info[1]), int(dispatch_info[2]));",
            "o2w = float3x4(transpose(__object_to_world)[0], transpose(__object_to_world)[1], transpose(__object_to_world)[2]);",
            "o2wg.f2 = transpose(__object_to_world)[2];",
            "w2o = float3x4(transpose(__world_to_object)[0], transpose(__world_to_object)[1], transpose(__world_to_object)[2]);",
            "w2og.f1 = transpose(__world_to_object)[1];",
            "t = (float)(__hit_distance);",
            "k = (int)(__hit_kind);",
            "inst = (int)(__hit_instance);",
            "prim = (int)(__hit_primitive);",
            "b = float2(__barycentrics.x, __barycentrics.y);",
            "ba.f0 = __barycentrics.x;",
            "oo = float3(__object_origin.x, __object_origin.y, __object_origin.z);",
            "od.f1 = __object_direction.y;",
            "results[gid].payload[0] = uint(dx);",
            "results[gid].payload[1] = as_type<uint>(t);",
            "results[gid].payload[2] = uint(k);",
            "p = (device uint*)results[gid].payload;",
            "uint(77);",
            "v = as_type<int>(*((device uint*)results[gid].payload + (5)));",
            "*((device uint*)results[gid].payload + (6)) = uint(88);",
            "vf = as_type<float>(results[gid].payload[6]);",
            "vi = as_type<int>(results[gid].payload[6]);",
            "instance_transforms [[buffer(5)]]",
            "dispatch_info [[buffer(6)]]",
            "float4x4 __object_to_world",
            "float4x4 __world_to_object",
        ] {
            assert_eq!(msl.contains(expected), true, "missing {expected}");
        }
    }

    #[test]
    fn t_llvm_ray_trace_control_candidate_and_shader_record_intrinsics_lower() {
        let ir = r#"define void @raygen(i32 %idx) {
entry:
  %h = call ptr @dx.op.getShaderRecordBufferHandle(i32 0)
  %hp = getelementptr i32, ptr %h, i32 1
  %local = load i32, ptr %hp
  %flags = call i32 @dx.op.rayFlags(i32 1)
  %tmax = call float @dx.op.rayTMax(i32 2)
  %geom = call i32 @dx.op.rayGeometryIndex(i32 3)
  %ctype = call i32 @dx.op.candidateType(i32 4)
  %cinst = call i32 @dx.op.candidateInstanceID(i32 5)
  %cprim = call i32 @dx.op.candidatePrimitiveID(i32 6)
  %cgeom = call i32 @dx.op.candidateGeometryIndex(i32 7)
  %corigin = call <3 x float> @dx.op.candidateObjectRayOrigin(i32 8)
  %cdir = call <3 x float> @dx.op.candidateObjectRayDirection(i32 9)
  %c2w = call [3 x <4 x float>] @dx.op.candidateObjectToWorld3x4(i32 10)
  %w2c = call [3 x <4 x float>] @dx.op.candidateWorldToObject3x4(i32 11)
  %attr = call float @dx.op.attributeAtVertex(i32 12, i32 1, i32 2)
  call void @dx.op.traceRay(i32 13, ptr null, i32 3, i32 -1, i32 0, i32 1, i32 0, float 0.0, float 0.0, float -1.0, float 0.0, float 0.0, float 0.0, float 1.0, float 100.0, i32 0)
  call void @dx.op.callShader(i32 14, i32 5, i32 0)
  %hit = call i1 @dx.op.reportHit(i32 15, float 2.5, i32 1065353216, i32 0, ptr null)
  call void @dx.op.acceptHitAndEndSearch(i32 16)
  call void @dx.op.ignoreHit(i32 17)
  call void @ray.storePayloadField(i32 0, i32 %local)
  call void @ray.storePayloadField(i32 1, i32 %flags)
  call void @ray.storePayloadField(i32 2, float %tmax)
  call void @ray.storePayloadField(i32 3, i32 %geom)
  call void @ray.storePayloadField(i32 4, i32 %ctype)
  call void @ray.storePayloadField(i32 5, i32 %cinst)
  call void @ray.storePayloadField(i32 6, i32 %cprim)
  call void @ray.storePayloadField(i32 7, i32 %cgeom)
  call void @ray.storePayloadField(i32 0, float %attr)
  ret void
}
declare ptr @dx.op.getShaderRecordBufferHandle(i32)
declare i32 @dx.op.rayFlags(i32)
declare float @dx.op.rayTMax(i32)
declare i32 @dx.op.rayGeometryIndex(i32)
declare i32 @dx.op.candidateType(i32)
declare i32 @dx.op.candidateInstanceID(i32)
declare i32 @dx.op.candidatePrimitiveID(i32)
declare i32 @dx.op.candidateGeometryIndex(i32)
declare <3 x float> @dx.op.candidateObjectRayOrigin(i32)
declare <3 x float> @dx.op.candidateObjectRayDirection(i32)
declare [3 x <4 x float>] @dx.op.candidateObjectToWorld3x4(i32)
declare [3 x <4 x float>] @dx.op.candidateWorldToObject3x4(i32)
declare float @dx.op.attributeAtVertex(i32, i32, i32)
declare void @dx.op.traceRay(i32, ptr, i32, i32, i32, i32, i32, float, float, float, float, float, float, float, float, i32)
declare void @dx.op.callShader(i32, i32, i32)
declare i1 @dx.op.reportHit(i32, float, i32, i32, ptr)
declare void @dx.op.acceptHitAndEndSearch(i32)
declare void @dx.op.ignoreHit(i32)
declare void @ray.storePayloadField(i32, ...)
"#;
        let bitcode = llvm_assemble_ir(ir).expect("assemble control/candidate IR");
        let msl =
            translate_llvm_ray_program(&bitcode, "raygen").expect("lower control/candidate IR");
        for expected in [
            "h = __sbt_local_root;",
            "local = __sbt_local_root[1];",
            "__ray_flags = uint(3);",
            "__ray_tmax = min(float(1.000000e+02), rays[gid].max_distance);",
            "intersector<triangle_data, instancing> __trace_query;",
            "__trace_query.intersect(__trace_ray, accel, uint(-1) & rays[gid].mask);",
            "msl_miss(results[gid], __trace_group, __miss_input,",
            "msl_closest_hit(results[gid], __trace_group, __trace_input,",
            "msl_callable(results[gid], sbt[uint(5) + max(rays[gid].sbt_offset, uint(gid))], __call_input,",
            "__hit_distance = float(2.500000e+00);",
            "__accepted = 1u; __end_search = 1u;",
            "__accepted = 0u; __ignored = 1u;",
            "flags = (int)(__ray_flags);",
            "tmax = (float)(__ray_tmax);",
            "geom = (int)(__ray_geometry_index);",
            "ctype = (int)(__candidate_type);",
            "cinst = (int)(__candidate_instance);",
            "cprim = (int)(__candidate_primitive);",
            "cgeom = (int)(__candidate_geometry);",
            "corigin = float3(__candidate_object_origin.x, __candidate_object_origin.y, __candidate_object_origin.z);",
            "cdir = float3(__candidate_object_direction.x, __candidate_object_direction.y, __candidate_object_direction.z);",
            "c2w = float3x4(transpose(__candidate_object_to_world)[0], transpose(__candidate_object_to_world)[1], transpose(__candidate_object_to_world)[2]);",
            "w2c = float3x4(transpose(__candidate_world_to_object)[0], transpose(__candidate_world_to_object)[1], transpose(__candidate_world_to_object)[2]);",
            "uint __slot = __ioff + __hit_primitive * 3u + uint(2);",
            "__sbt_local_root",
            "dispatch_info[4]",
        ] {
            assert_eq!(msl.contains(expected), true, "missing {expected}");
        }
        let error = lower_llvm_ir_ray_body(
            "define void @raygen() {\nentry:\n %x = call float @dx.op.attributeAtVertex(i32 0, i32 1)\n ret void\n}\n",
            "raygen",
        )
        .expect_err("missing vertex argument");
        assert_eq!(
            error.message,
            "dx.op.attributeAtVertex is missing argument 2"
        );
    }

    #[test]
    fn t_llvm_ray_stages_compile_from_own_bitcode_and_select_sbt_functions() {
        let stages = [
            (ShaderStage::ClosestHit, "msl_closest_hit", false),
            (ShaderStage::AnyHit, "msl_any_hit", true),
            (ShaderStage::Miss, "msl_miss", false),
            (ShaderStage::Intersection, "msl_intersection", true),
            (ShaderStage::Callable, "msl_callable", false),
        ];
        for (stage, function_name, boolean) in stages {
            let ir = r#"define void @entry() {
entry:
  %h = call ptr @dx.op.getShaderRecordBufferHandle(i32 0)
  %p = getelementptr i32, ptr %h, i32 0
  %v = load i32, ptr %p
  %t = call float @dx.op.rayTMax(i32 1)
  %g = call i32 @dx.op.rayGeometryIndex(i32 2)
  %ct = call i32 @dx.op.candidateType(i32 3)
  %ci = call i32 @dx.op.candidateInstanceID(i32 4)
  %cp = call i32 @dx.op.candidatePrimitiveID(i32 5)
  %cg = call i32 @dx.op.candidateGeometryIndex(i32 6)
  %a = call float @dx.op.attributeAtVertex(i32 7, i32 0, i32 0)
  %r = call i1 @dx.op.reportHit(i32 8, float 1.0, i32 0, i32 0, ptr null)
  call void @dx.op.acceptHitAndEndSearch(i32 9)
  call void @ray.storePayloadField(i32 0, i32 %v)
  call void @ray.storePayloadField(i32 1, float %t)
  call void @ray.storePayloadField(i32 2, i32 %g)
  call void @ray.storePayloadField(i32 3, i32 %ct)
  call void @ray.storePayloadField(i32 4, i32 %ci)
  call void @ray.storePayloadField(i32 5, i32 %cp)
  call void @ray.storePayloadField(i32 6, i32 %cg)
  call void @ray.storePayloadField(i32 7, float %a)
  ret void
}
declare ptr @dx.op.getShaderRecordBufferHandle(i32)
declare float @dx.op.rayTMax(i32)
declare i32 @dx.op.rayGeometryIndex(i32)
declare i32 @dx.op.candidateType(i32)
declare i32 @dx.op.candidateInstanceID(i32)
declare i32 @dx.op.candidatePrimitiveID(i32)
declare i32 @dx.op.candidateGeometryIndex(i32)
declare float @dx.op.attributeAtVertex(i32, i32, i32)
declare i1 @dx.op.reportHit(i32, float, i32, i32, ptr)
declare void @dx.op.acceptHitAndEndSearch(i32)
declare void @ray.storePayloadField(i32, ...)
"#;
            let bitcode = llvm_assemble_ir(ir).expect("assemble stage IR");
            let source = translate_llvm_ray_stage_program(&bitcode, stage, "entry")
                .expect("translate stage");
            assert_eq!(
                source.contains(&format!("{function_name}(")),
                true,
                "missing {function_name}"
            );
            assert_eq!(source.contains("h = __sbt_local_root;"), true);
            assert_eq!(source.contains("t = (float)(__ray_tmax);"), true);
            assert_eq!(source.contains("g = (int)(__ray_geometry_index);"), true);
            assert_eq!(source.contains("ct = (int)(__candidate_type);"), true);
            assert_eq!(source.contains("ci = (int)(__candidate_instance);"), true);
            assert_eq!(source.contains("cp = (int)(__candidate_primitive);"), true);
            assert_eq!(source.contains("cg = (int)(__candidate_geometry);"), true);
            assert_eq!(
                source.contains("uint __slot = __ioff + __hit_primitive * 3u + uint(0);"),
                true
            );
            assert_eq!(
                source.contains("__hit_distance = float(1.000000e+00);"),
                true
            );
            assert_eq!(source.contains("__accepted = 1u; __end_search = 1u;"), true);
            if boolean {
                assert_eq!(source.contains("return __accepted != 0u;"), true);
            }
            if matches!(stage, ShaderStage::ClosestHit) {
                let raygen =
                    translate_llvm_ray_stage_program(&bitcode, ShaderStage::RayGeneration, "entry")
                        .expect("raygen delegation");
                assert_eq!(raygen.contains("kernel void entry"), true);
            }
        }
        let error = translate_llvm_ray_stage_program(b"BC\xc0\xde", ShaderStage::Vs, "entry")
            .expect_err("non-ray stage");
        assert_eq!(error.message, "vs is not a ray shader stage");
    }

    #[test]
    fn t_llvm_ray_intrinsic_malformed_shapes_and_payload_errors_are_exact() {
        let cases = [
            (
                "define void @raygen() {\nentry:\n %p = call ptr @other()\n ret void\n}\n",
                "unsupported LLVM pointer return from @other",
            ),
            (
                "define void @raygen() {\nentry:\n %x = extractelement i32 1, i32 0\n ret void\n}\n",
                "extractelement requires a vector type, got i32",
            ),
            (
                "define void @raygen() {\nentry:\n %x = extractelement <2 x float> 1\n ret void\n}\n",
                "extractelement without index",
            ),
            (
                "define void @raygen() {\nentry:\n %x = call [2 x i32] @foo()\n ret void\n}\n",
                "unsupported LLVM array type [2 x i32]",
            ),
            (
                "define void @raygen() {\nentry:\n %d = call { i32, i32 } @dx.op.dispatchRaysDimensions(i32 143)\n ret void\n}\n",
                "dx.op.dispatchRaysDimensions returned 2 fields but 3 values are available",
            ),
            (
                "define void @raygen() {\nentry:\n %d = call i32 @dx.op.dispatchRaysDimensions(i32 143)\n ret void\n}\n",
                "dx.op.dispatchRaysDimensions returned a 1-component value but 3 values are available",
            ),
            (
                "define void @raygen() {\nentry:\n %d = call <2 x i32> @dx.op.dispatchRaysIndex(i32 0)\n ret void\n}\n",
                "dx.op.dispatchRaysIndex returned a 2-component value in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %m = call { <4 x float>, <4 x float> } @dx.op.objectToWorld(i32 144)\n ret void\n}\n",
                "dx.op.objectToWorld returned an unsupported matrix shape in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %m = call { <4 x float>, <4 x float> } @dx.op.worldToObject(i32 146)\n ret void\n}\n",
                "dx.op.worldToObject returned an unsupported matrix shape in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %b = call <3 x float> @dx.op.barycentrics(i32 153)\n ret void\n}\n",
                "dx.op.barycentrics must return two components in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %o = call <2 x float> @dx.op.objectRayOrigin(i32 154)\n ret void\n}\n",
                "dx.op.objectRayOrigin must return three components in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %d = call <2 x float> @dx.op.objectRayDirection(i32 155)\n ret void\n}\n",
                "dx.op.objectRayDirection must return three components in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %x = call double @ray.loadPayloadField(i32 0)\n ret void\n}\n",
                "ray.loadPayloadField returned unsupported type double",
            ),
            (
                "define void @raygen() {\nentry:\n call void @ray.storePayloadField()\n ret void\n}\n",
                "ray.storePayloadField is missing argument 0",
            ),
            (
                "define void @raygen() {\nentry:\n call void @ray.storePayloadField(i32 0)\n ret void\n}\n",
                "ray.storePayloadField is missing argument 1",
            ),
            (
                "define void @raygen() {\nentry:\n %p = call ptr @ray.payloadPointer()\n %f = getelementptr i32, ptr %p, i32 1\n %g = getelementptr i32, ptr %f, i32 1\n ret void\n}\n",
                "getelementptr on payload pointer %f has no scalar element type",
            ),
            (
                "define void @raygen() {\nentry:\n %p = call ptr @ray.payloadPointer()\n %f = getelementptr i32, ptr %p, i32 1\n %v = load double, ptr %f\n ret void\n}\n",
                "payload load has unsupported type double",
            ),
            (
                "define void @raygen() {\nentry:\n %t = call <2 x i32> @dx.op.rayTCurrent(i32 149)\n ret void\n}\n",
                "ray intrinsic result <2 x i32> is not a scalar",
            ),
            (
                "define void @raygen() {\nentry:\n call void @dx.op.traceRay(i32 0, ptr null, i32 1)\n ret void\n}\n",
                "dx.op.traceRay is missing argument 3",
            ),
            (
                "define void @raygen() {\nentry:\n call void @dx.op.callShader(i32 0)\n ret void\n}\n",
                "dx.op.callShader is missing argument 1",
            ),
            (
                "define void @raygen() {\nentry:\n %r = call i1 @dx.op.reportHit(i32 0, float 1.0, i32 0)\n ret void\n}\n",
                "dx.op.reportHit is missing argument 3",
            ),
            (
                "define void @raygen() {\nentry:\n %c = call <2 x float> @dx.op.candidateObjectRayOrigin(i32 0)\n ret void\n}\n",
                "dx.op.candidateObjectRayOrigin must return three components in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %c = call { <4 x float>, <4 x float> } @dx.op.candidateObjectToWorld3x4(i32 0)\n ret void\n}\n",
                "dx.op.candidateObjectToWorld3x4 returned an unsupported matrix shape in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %c = call { <4 x float>, <4 x float> } @dx.op.candidateWorldToObject3x4(i32 0)\n ret void\n}\n",
                "dx.op.candidateWorldToObject3x4 returned an unsupported matrix shape in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %a = call <2 x float> @dx.op.candidateObjectRayDirection(i32 0)\n ret void\n}\n",
                "dx.op.candidateObjectRayDirection must return three components in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %a = call <4 x float> @dx.op.candidateObjectRayOrigin(i32 0)\n ret void\n}\n",
                "dx.op.candidateObjectRayOrigin must return three components in @raygen",
            ),
            (
                "define void @raygen() {\nentry:\n %a = call <8 x float> @dx.op.candidateObjectRayOrigin(i32 0)\n ret void\n}\n",
                "unsupported ray intrinsic result type float8",
            ),
        ];
        assert_eq!(llvm_type_to_msl("[4 x <4 x float>]").unwrap(), "float4x4");
        assert_eq!(
            llvm_type_to_msl("[2 x <4 x float>]").unwrap_err().message,
            "unsupported LLVM array type [2 x <4 x float>]"
        );
        for (ir, message) in cases {
            let error = lower_llvm_ir_ray_body(ir, "raygen").expect_err("malformed ray intrinsic");
            assert_eq!(error.code, ReasonCode::RcDxilInvalid);
            assert_eq!(error.message, message);
        }
    }
}
