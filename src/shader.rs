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
use walkdir::WalkDir;

const DXIL_MAGIC: &[u8; 4] = b"DXIL";
const MAX_PARTS: usize = 16;
const MAX_INSTRUCTIONS: u32 = 4096;
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
const DXIL_VERSION_MAJOR: u32 = 1;
const DXIL_VERSION_MINOR: u32 = 0;

// LLVM bitcode block/record IDs (u32, matching the bitstream entry codes)
const BLOCKID_BLOCKINFO: u32 = 0;
const BLOCKID_MODULE: u32 = 8;
const BLOCKID_PARAMATTR: u32 = 9;
const BLOCKID_PARAMATTR_GROUP: u32 = 10;
const BLOCKID_CONSTANTS: u32 = 11;
const BLOCKID_FUNCTION: u32 = 12;
const BLOCKID_IDENTIFICATION: u32 = 13;
const BLOCKID_VALUE_SYMTAB: u32 = 14;
const BLOCKID_METADATA: u32 = 15;
const BLOCKID_METADATA_ATTACHMENT: u32 = 16;
const BLOCKID_TYPE: u32 = 17;
const BLOCKID_OPERAND_BUNDLE_TAGS: u32 = 18;

// Record codes within BLOCKINFO
const BLOCKINFO_CODE_SETBID: u32 = 1;
const BLOCKINFO_CODE_BLOCKNAME: u32 = 2;
const BLOCKINFO_CODE_SETRECORDNAME: u32 = 3;

// Module-level record codes
const MODULE_CODE_VERSION: u32 = 1;
const MODULE_CODE_TRIPLE: u32 = 2;
const MODULE_CODE_DATALAYOUT: u32 = 3;
const MODULE_CODE_GLOBALVAR: u32 = 7;
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
const FUNC_CODE_INST_INVOKE: u32 = 13;
const FUNC_CODE_INST_UNREACHABLE: u32 = 15;
const FUNC_CODE_INST_PHI: u32 = 16; // [ty, (val#signed, bb)...]
const FUNC_CODE_INST_ALLOCA: u32 = 19; // [instty, opty, size, align]
const FUNC_CODE_INST_LOAD: u32 = 20; // [ptr, result_ty, align, vol]
const FUNC_CODE_INST_VAARG: u32 = 23;
const FUNC_CODE_INST_STORE_OLD: u32 = 24;
const FUNC_CODE_INST_EXTRACTVAL: u32 = 26;
const FUNC_CODE_INST_INSERTVAL: u32 = 27;
const FUNC_CODE_INST_CMP2: u32 = 28; // [op0, op1, pred, flags?]
const FUNC_CODE_INST_VSELECT: u32 = 29; // [cond, false_val, true_val]
const FUNC_CODE_INST_INBOUNDS_GEP_OLD: u32 = 30;
const FUNC_CODE_INST_INDIRECTBR: u32 = 31;
const FUNC_CODE_INST_CALL: u32 = 34; // [attr, cc, fnty, fn, args...]
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
            let mask = if n >= 32 {
                u32::MAX
            } else {
                (1u32 << n) - 1
            };
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
                            let record = self
                                .decode_abbrev_record(&abbrev)
                                .unwrap_or_else(|| BitcodeRecord {
                                    id: 0xFFFF,
                                    operands: Vec::new(),
                                    blob: None,
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
        self.abbrev_width = self
            .block_stack
            .last()
            .map_or(2, |(_, _, width)| *width);
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
                    let elem = match iter.next() {
                        Some(elem) => elem.clone(),
                        None => return None,
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
        0..=1 => binop("+"), // add / fadd
        2..=3 => binop("-"), // sub / fsub
        4..=5 => binop("*"), // mul / fmul
        6..=8 => binop("/"), // udiv / sdiv / fdiv — MSL `/` is type-driven
        9..=10 => binop("%"), // urem / srem
        11 => binop("<<"), // shl
        12 => binop(">>"), // lshr (logical shift right)
        13 => binop(">>"), // ashr — arithmetic shift right (MSL uses
        //                  type-based >> semantics; signed → arithmetic,
        //                  unsigned → logical)
        14 => binop("&"), // and
        15 => binop("|"), // or
        16 => binop("^"), // xor
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
                    stmt.push_str(&format!("        case {}: goto {};\n", args[idx], args[idx + 1]));
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
                format!("{} = simd_prefix_exclusive_sum({}); // WavePrefix", dst, args[0])
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
        DXIL_INTRIN_DISCARD => {
            "discard_fragment(); // Discard".to_string()
        }

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
        6 => Some(DXIL_INTRIN_ABS),        // FAbs
        7 => Some(DXIL_INTRIN_SATURATE),   // Saturate
        8 => Some(DXIL_INTRIN_ISNAN),      // IsNaN
        9 => Some(DXIL_INTRIN_ISINF),      // IsInf
        10 => Some(DXIL_INTRIN_ISFINITE),  // IsFinite
        12 => Some(DXIL_INTRIN_COS),       // Cos
        13 => Some(DXIL_INTRIN_SIN),       // Sin
        14 => Some(DXIL_INTRIN_TAN),       // Tan
        15 => Some(DXIL_INTRIN_ACOS),      // Acos
        16 => Some(DXIL_INTRIN_ASIN),      // Asin
        17 => Some(DXIL_INTRIN_ATAN),      // Atan
        18 => Some(DXIL_INTRIN_COSH),      // Hcos
        19 => Some(DXIL_INTRIN_SINH),      // Hsin
        20 => Some(DXIL_INTRIN_TANH),      // Htan
        21 => Some(DXIL_INTRIN_EXP),       // Exp
        22 => Some(DXIL_INTRIN_FRAC),      // Frc
        23 => Some(DXIL_INTRIN_LOG),       // Log
        24 => Some(DXIL_INTRIN_SQRT),      // Sqrt
        25 => Some(DXIL_INTRIN_RSQRT),     // Rsqrt
        26..=29 => Some(DXIL_INTRIN_ROUND), // Round_ne/ni/pi/z
        30 => Some(DXIL_INTRIN_REVERSEBITS), // Bfrev
        31 => Some(DXIL_INTRIN_COUNTBITS), // Countbits
        32 => Some(DXIL_INTRIN_FIRSTBITLOW), // FirstbitLo
        33 => Some(DXIL_INTRIN_FIRSTBITHIGH), // FirstbitHi
        34 => Some(DXIL_INTRIN_FIRSTBITHIGH), // FirstbitSHi
        35 | 37 | 39 => Some(DXIL_INTRIN_MAX), // FMax / IMax / UMax
        36 | 38 | 40 => Some(DXIL_INTRIN_MIN), // FMin / IMin / UMin
        41 | 42 => Some(DXIL_INTRIN_MUL),    // IMul / UMul
        46 => Some(DXIL_INTRIN_MAD),         // FMad
        47 => Some(DXIL_INTRIN_FMA),         // Fma
        48 | 49 => Some(DXIL_INTRIN_MAD),    // IMad / UMad
        54..=56 => Some(DXIL_INTRIN_DOT),    // Dot2 / Dot3 / Dot4

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
        93 => Some(DXIL_INTRIN_THREADID),       // SV_DispatchThreadID
        94 => Some(DXIL_INTRIN_GROUPID),        // SV_GroupID
        95 => Some(DXIL_INTRIN_THREADGROUPID),  // SV_GroupThreadID
        96 => Some(DXIL_INTRIN_GROUPINDEX),     // SV_GroupIndex

        // Geometry shaders
        97 => Some(DXIL_INTRIN_EMITSTREAM),
        98 => Some(DXIL_INTRIN_CUTSTREAM),
        99 => Some(DXIL_INTRIN_EMITTHENCUTSTREAM),
        108 => Some(DXIL_INTRIN_PRIMITIVEID),  // SV_PrimitiveID

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
        122 => Some(DXIL_INTRIN_QUADREAD),     // QuadReadLaneAt

        // Raw buffer access
        139 => Some(DXIL_INTRIN_BUFFERLOAD),   // RawBufferLoad
        140 => Some(DXIL_INTRIN_BUFFERSTORE),  // RawBufferStore

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
                                        if let Some(name) =
                                            parse_identification_block(&mut reader)?
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
        36 | 37 | 38 | 40 | 44 | 52
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
        0 => 0,  // add
        1 => 2,  // sub
        2 => 4,  // mul
        3 => 6,  // udiv
        4 => 7,  // sdiv / fdiv
        5 => 9,  // urem
        6 => 10, // srem / frem
        7 => 11, // shl
        8 => 12, // lshr
        9 => 13, // ashr
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
        0 => 35,                 // trunc
        1 => 33,                 // zext
        2 => 34,                 // sext
        3 => CAST_FPTOUI,        // fptoui
        4 => CAST_FPTOSI,        // fptosi
        5 => CAST_UITOFP,        // uitofp
        6 => CAST_SITOFP,        // sitofp
        7 => CAST_FPTRUNC,       // fptrunc
        8 => CAST_FPEXT,         // fpext
        9 => 31,                 // ptrtoint
        10 => 32,                // inttoptr
        11 => 30,                // bitcast
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
        if is_terminator
            && let Some(bb) = current_bb.take()
        {
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
                    return Err(dxil_invalid(
                        "DXIL function declares too many basic blocks",
                    ));
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
                let start = if record.id == FUNC_CODE_INST_GEP { 2 } else { 0 };
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
                let start = if record.id == FUNC_CODE_INST_SELECT { 1 } else { 0 };
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
                let start = 1 + usize::from(
                    is_forward_ref(record.operands.first().copied().unwrap_or(0)),
                );
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
                        let mut succs = term.operands.get(1).copied().into_iter().collect::<Vec<_>>();
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
                    value_types.insert(cur_ordinal, instr.ty.unwrap_or_else(|| TypeDesc {
                        is_float,
                        is_signed,
                        ..TypeDesc::default()
                    }));
                    cur_ordinal += 1;
                }

                // Build TranslatedInstruction entry
                let is_barrier = matches!(instr.opcode, 74..=79 // DXIL barrier opcodes
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
    let base_msl = generator.generate();

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
                    parse_dxil_program_bitcode(bitcode_bytes).map_err(|error| {
                        shader_error(input, &dxil_hash, "bitcode_parse", error)
                    })?
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

/// Compile MSL source to a Metal library.
///
/// Contract: this function is a placeholder that does not invoke the `metal`
/// compiler. It returns the source wrapped in a recognizable, versioned
/// format — `MTLCOMPILED|v1|<len>|<source>` — so callers can detect that no
/// real compilation happened (the absence of the `MTLCOMPILED|` prefix means
/// the bytes are a real compiled library). Wiring in the async Metal compiler
/// (async_pipeline_compiler) is future work.
pub fn compile_msl_source(msl_source: &str, _entry_point: &str) -> AppResult<Vec<u8>> {
    Ok(format!(
        "MTLCOMPILED|v1|{}|{}",
        msl_source.len(),
        msl_source
    )
    .into_bytes())
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
                // ceil(array_len * components / 4) registers of 16 bytes
                let scalars = array_len.saturating_mul(component_count);
                scalars.div_ceil(4).saturating_mul(16)
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
    checked_range(bytes, cbuffer_base + 4, cbuffers_size, "reflection cbuffers")?;
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
    for use_entry in parsed.uses.iter().filter(|use_entry| {
        matches!(use_entry.kind, ProgramBindingKind::Cbuffer)
    }) {
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

    /// Helper: create a simple DXIL-like byte sequence for testing.
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

    /// Helper: create a simple root signature blob.
    fn make_test_root_signature(descriptor_count: u32, constants_count: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&descriptor_count.to_le_bytes());
        data.extend_from_slice(&constants_count.to_le_bytes());
        for i in 0..descriptor_count {
            data.push(0); // kind = Buffer
            data.push(i as u8); // register
            data.push(0); // space
            data.push(1); // descriptor_count
            data.push(0); // arg_buffer_index
            data.push(i as u8); // binding_index
        }
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
    fn t_shader_cache_key_consistency() {
        let input = ShaderTranslationInput {
            dxil: vec![0, 1, 2, 3],
            stage: ShaderStage::Cs,
            root_signature: vec![],
            compile_flags: CompileFlags {
                fast_math: true,
                denorm_mode: "ieee".to_string(),
                debug: false,
                optimization_level: 0,
            },
            gpu_family: "apple_gpu".to_string(),
            os_build: "macos_14".to_string(),
            macwin_version: "0.1.0".to_string(),
        };

        let key1 = shader_cache_key(&input).unwrap();
        let key2 = shader_cache_key(&input).unwrap();
        assert_eq!(key1, key2, "cache keys must be deterministic");
        assert!(key1.contains("apple_gpu"), "key should contain gpu family");
    }

    #[test]
    fn t_parse_root_signature_empty() {
        let root = parse_root_signature(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(root.descriptors.len(), 0);
        assert_eq!(root.root_constants_count, 0);
    }

    #[test]
    fn t_build_argument_buffers() {
        let root = RootSignatureInfo {
            descriptors: vec![RootDescriptor {
                kind: RootBindingKind::Buffer,
                register: 0,
                space: 0,
                descriptor_count: 3,
                arg_buffer_index: 0,
                binding_index: 0,
            }],
            root_constants_count: 0,
        };
        let bufs = build_argument_buffers(&root);
        assert_eq!(bufs.len(), 1);
        assert_eq!(bufs[0].binding_count, 3);
        assert_eq!(bufs[0].bindings[0].register, 0);
        assert_eq!(bufs[0].bindings[1].register, 1);
        assert_eq!(bufs[0].bindings[2].register, 2);
    }

    #[test]
    fn t_dxil_opcode_add_translation() {
        let stmt = dxil_opcode_to_msl(
            0,
            "_t0",
            &["_t1".to_string(), "_t2".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("+"), "add should produce + operator");
        assert!(stmt.contains("_t0"), "should assign to destination");
    }

    #[test]
    fn t_dxil_opcode_select_translation() {
        let stmt = dxil_opcode_to_msl(
            46,
            "_t0",
            &["cond".to_string(), "a".to_string(), "b".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("?"), "select should produce ternary");
        assert!(stmt.contains(":"));
    }

    #[test]
    fn t_dxil_opcode_intrinsic_abs() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_ABS, "_r", &["x".to_string()], false, false);
        assert!(stmt.contains("abs("));
    }

    #[test]
    fn t_dxil_opcode_intrinsic_saturate() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_SATURATE, "_r", &["x".to_string()], false, true);
        assert!(stmt.contains("saturate("));
    }

    #[test]
    fn t_dxil_opcode_intrinsic_sample() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_SAMPLE,
            "_r",
            &["tex".to_string(), "samp".to_string(), "coord".to_string()],
            false,
            true,
        );
        assert!(stmt.contains(".sample("));
    }

    #[test]
    fn t_dxil_opcode_intrinsic_barrier() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &[], false, false);
        assert!(stmt.contains("threadgroup_barrier"));
    }

    #[test]
    fn t_dxil_opcode_intrinsic_threadid() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_THREADID, "_r", &["0".to_string()], false, false);
        assert!(stmt.contains("thread_position_in_grid"));
    }

    #[test]
    fn t_dxil_opcode_unknown_fallback() {
        let stmt = dxil_opcode_to_msl(9999, "_r", &[], false, false);
        assert!(stmt.contains("unknown opcode 9999"));
    }

    #[test]
    fn t_parse_dxil_container_valid() {
        let dxil = make_test_dxil(5);
        let result = parse_dxil_container(&dxil);
        assert!(
            result.is_ok(),
            "valid DXIL should parse: {:?}",
            result.err()
        );
        let parsed = result.unwrap();
        assert_eq!(parsed.entry_name, "main");
        assert!(parsed.instruction_count > 0);
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
    fn t_pack_cbuffer_simple() {
        let fields = vec![CbufferField {
            name: "color".to_string(),
            rows: 1,
            cols: 4,
            row_major: false,
            is_bool: false,
            array_len: 0,
        }];
        let packed = pack_cbuffer(&fields);
        assert_eq!(packed.size_bytes, 16);
        assert_eq!(packed.fields.len(), 1);
        assert_eq!(packed.fields[0].offset, 0);
    }

    #[test]
    fn t_pack_structured_fields() {
        let fields = vec![
            StructuredField {
                name: "pos".to_string(),
                size_bytes: 12,
                alignment: 4,
            },
            StructuredField {
                name: "uv".to_string(),
                size_bytes: 8,
                alignment: 4,
            },
        ];
        let packing = pack_structured_fields(&fields);
        assert_eq!(packing.stride, 32);
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

    #[test]
    fn t_cache_compute_key() {
        let key1 = ShaderCache::compute_key(b"test_data");
        let key2 = ShaderCache::compute_key(b"test_data");
        let key3 = ShaderCache::compute_key(b"different_data");
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    // -----------------------------------------------------------------------
    // Wave intrinsic opcode translation tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_wave_get_lane_index() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_WAVEGETLANEINDEX, "_r", &[], false, false);
        assert!(stmt.contains("simd_lane_id"));
    }

    #[test]
    fn t_dxil_opcode_wave_get_lane_count() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_WAVEGETLANECOUNT, "_r", &[], false, false);
        assert!(stmt.contains("simd_lane_count"));
    }

    #[test]
    fn t_dxil_opcode_wave_any_true() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEANYTRUE,
            "_r",
            &["cond".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_any(cond)"));
    }

    #[test]
    fn t_dxil_opcode_wave_all_true() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEALLTRUE,
            "_r",
            &["cond".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_all(cond)"));
    }

    #[test]
    fn t_dxil_opcode_wave_all_equal() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEALLEQUAL,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_all(val == simd_broadcast_first(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_ballot() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEBALLOT,
            "_r",
            &["cond".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_ballot(cond)"));
    }

    #[test]
    fn t_dxil_opcode_wave_read_lane_at() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEREADLANEAT,
            "_r",
            &["val".to_string(), "lane".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_broadcast(val, lane)"));
    }

    #[test]
    fn t_dxil_opcode_wave_read_lane_first() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEREADLANEFIRST,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_broadcast_first(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_active_bitand() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEACTIVEBITAND,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_and(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_active_bitor() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEACTIVEBITOR,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_or(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_active_bitxor() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEACTIVEBITXOR,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_xor(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_active_countbits() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEACTIVECOUNTBITS,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("popcount(simd_ballot(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_active_sum() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEACTIVESUM,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_sum(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_active_product() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEACTIVEPRODUCT,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_product(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_active_min() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEACTIVEMIN,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_min(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_active_max() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEACTIVEMAX,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_max(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_multiprefix_sum() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEMULTIPREFIXSUM,
            "_r",
            &["mask".to_string(), "val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_prefix_exclusive_sum(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_multiprefix_product() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEMULTIPREFIXPRODUCT,
            "_r",
            &["mask".to_string(), "val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_prefix_exclusive_product(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_multiprefix_bitand() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEMULTIPREFIXBITAND,
            "_r",
            &["mask".to_string(), "val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_prefix_exclusive_and(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_multiprefix_bitor() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEMULTIPREFIXBITOR,
            "_r",
            &["mask".to_string(), "val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_prefix_exclusive_or(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_multiprefix_bitxor() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEMULTIPREFIXBITXOR,
            "_r",
            &["mask".to_string(), "val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_prefix_exclusive_xor(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_multiprefix_bitcount() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEMULTIPREFIXBITCOUNT,
            "_r",
            &["mask".to_string(), "val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("popcount(simd_prefix_exclusive_or(val)"));
    }

    #[test]
    fn t_dxil_opcode_wave_match() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_WAVEMATCH,
            "_r",
            &["a".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("simd_ballot(simd_broadcast(a, simd_lane_id()) == a)"));
    }

    // -----------------------------------------------------------------------
    // Conversion/bit intrinsic opcode translation tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_asfloat() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_ASFLOAT,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("as_type<float>(val)"));
    }

    #[test]
    fn t_dxil_opcode_asint() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_ASINT, "_r", &["val".to_string()], false, false);
        assert!(stmt.contains("as_type<int>(val)"));
    }

    #[test]
    fn t_dxil_opcode_asuint() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_ASUINT, "_r", &["val".to_string()], false, false);
        assert!(stmt.contains("as_type<uint>(val)"));
    }

    #[test]
    fn t_dxil_opcode_firstbithigh() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_FIRSTBITHIGH,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("clz(val)"));
        assert!(stmt.contains("31 - (int)clz(val)"));
    }

    #[test]
    fn t_dxil_opcode_firstbitlow() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_FIRSTBITLOW,
            "_r",
            &["val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("ctz(val)"));
    }

    #[test]
    fn t_dxil_opcode_log10() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_LOG10, "_r", &["val".to_string()], false, true);
        assert!(stmt.contains("log10(val)"));
    }

    // -----------------------------------------------------------------------
    // Packed dot-product opcode translation tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_dot4addi8packed() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_DOT4ADDI8PACKED,
            "_r",
            &["a".to_string(), "b".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("Dot4AddI8Packed"));
        // Sign extension: the byte is shifted left and back through an
        // arithmetic shift before multiplying.
        assert!(stmt.contains("(int)(((int)a << 24) >> 24)"));
    }

    #[test]
    fn t_dxil_opcode_dot4addu8packed() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_DOT4ADDU8PACKED,
            "_r",
            &["a".to_string(), "b".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("Dot4AddU8Packed"));
        assert!(stmt.contains("uint((a >> 0) & 0xFF)"));
    }

    // -----------------------------------------------------------------------
    // Tessellation intrinsic opcode translation tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_tess_quad_avg() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_PROCESS2DQUADTESSSFACTORSAVG,
            "_r",
            &[
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            false,
            true,
        );
        assert!(stmt.contains("(a + b + c + d) / 4.0"));
    }

    #[test]
    fn t_dxil_opcode_tess_quad_max() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_PROCESS2DQUADTESSFACTORSMAX,
            "_r",
            &[
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            false,
            true,
        );
        assert!(stmt.contains("fmax(fmax(a, b), fmax(c, d))"));
    }

    #[test]
    fn t_dxil_opcode_tess_quad_min() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_PROCESS2DQUADTESSFACTORSMIN,
            "_r",
            &[
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            false,
            true,
        );
        assert!(stmt.contains("fmin(fmin(a, b), fmin(c, d))"));
    }

    #[test]
    fn t_dxil_opcode_tess_tri_avg() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSAVG,
            "_r",
            &["a".to_string(), "b".to_string(), "c".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("(a + b + c) / 3.0"));
    }

    #[test]
    fn t_dxil_opcode_tess_tri_max() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSMAX,
            "_r",
            &["a".to_string(), "b".to_string(), "c".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("fmax(fmax(a, b), c)"));
    }

    #[test]
    fn t_dxil_opcode_tess_tri_min() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_PROCESS2DTRIANGLEFACTORSMIN,
            "_r",
            &["a".to_string(), "b".to_string(), "c".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("fmin(fmin(a, b), c)"));
    }

    // -----------------------------------------------------------------------
    // Texture query intrinsic tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_calculate_lod() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_CALCULATELOD,
            "_r",
            &["tex".to_string(), "coord".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("tex.calculate_lod(coord)"));
    }

    #[test]
    fn t_dxil_opcode_calculate_lod_unclamped() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_CALCULATELODUNCLAMPED,
            "_r",
            &["tex".to_string(), "coord".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("tex.calculate_lod(coord)"));
    }

    // -----------------------------------------------------------------------
    // Attribute evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_check_access_fully_mapped() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_CHECKACCESSFULLYMAPPED, "_r", &[], false, false);
        assert!(stmt.contains("CheckAccessFullyMapped"));
        assert!(stmt.contains("= 1"));
    }

    #[test]
    fn t_dxil_opcode_eval_attr_centroid() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_EVALUATEATTRIBUTEATCENTROID,
            "_r",
            &["attr".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("EvaluateAttributeAtCentroid"));
    }

    #[test]
    fn t_dxil_opcode_eval_attr_sample() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_EVALUATEATTRIBUTEATSAMPLE,
            "_r",
            &["attr".to_string(), "idx".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("EvaluateAttributeAtSample(idx)"));
    }

    #[test]
    fn t_dxil_opcode_eval_attr_constant() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_EVALUATEATTRIBUTEATCONSTANT,
            "_r",
            &["attr".to_string(), "idx".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("EvaluateAttributeAtConstant(idx)"));
    }

    // -----------------------------------------------------------------------
    // Vertex/instance/primitive ID tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_instance_id() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_INSTANCEID, "_r", &[], false, false);
        assert!(stmt.contains("instance_id"));
    }

    #[test]
    fn t_dxil_opcode_vertex_id() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_VERTEXID, "_r", &[], false, false);
        assert!(stmt.contains("vid"));
    }

    #[test]
    fn t_dxil_opcode_primitive_id() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_PRIMITIVEID, "_r", &[], false, false);
        assert!(stmt.contains("primitive_id"));
    }

    // -----------------------------------------------------------------------
    // Geometry shader intrinsic tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_emit_stream() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_EMITSTREAM, "", &["0".to_string()], false, false);
        assert!(stmt.contains("EmitStream(0)"));
    }

    #[test]
    fn t_dxil_opcode_cut_stream() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_CUTSTREAM, "", &["0".to_string()], false, false);
        assert!(stmt.contains("CutStream(0)"));
    }

    #[test]
    fn t_dxil_opcode_emit_then_cut_stream() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_EMITTHENCUTSTREAM,
            "",
            &["0".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("EmitThenCutStream(0)"));
    }

    // -----------------------------------------------------------------------
    // Resource handle creation tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_create_handle() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_CREATEHANDLE,
            "_r",
            &["0".to_string(), "1".to_string(), "2".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("CreateHandle(resClass=0, rangeId=1, index=2)"));
    }

    #[test]
    fn t_dxil_opcode_create_handle_for_binding() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_CREATEHANDLEFORBINDING,
            "_r",
            &[
                "0".to_string(),
                "1".to_string(),
                "2".to_string(),
                "0".to_string(),
            ],
            false,
            false,
        );
        assert!(
            stmt.contains("CreateHandleForBinding(resClass=0, rangeId=1, index=2, nonUniform=0)")
        );
    }

    // -----------------------------------------------------------------------
    // Barrier memory flag tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_barrier_default() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &[], false, false);
        assert!(
            stmt.contains(
                "threadgroup_barrier(mem_flags::mem_threadgroup | mem_flags::mem_device)"
            )
        );
    }

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

    #[test]
    fn t_dxil_opcode_barrier_all() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["12".to_string()], false, false);
        assert!(stmt.contains("mem_threadgroup | mem_flags::mem_device"));
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

    #[test]
    fn t_dxil_opcode_atomic_add_groupshared() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_ATOMICADD,
            "_r",
            &["buf".to_string(), "_gs_ptr".to_string(), "1".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("threadgroup atomic_int*"));
    }

    #[test]
    fn t_dxil_opcode_atomic_exchange_groupshared() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_ATOMICEXCHANGE,
            "_r",
            &["buf".to_string(), "gs_val".to_string(), "1".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("threadgroup atomic_int*"));
    }

    #[test]
    fn t_dxil_opcode_atomic_compare_exchange_groupshared() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_ATOMICCOMPAREEXCHANGE,
            "_r",
            &[
                "buf".to_string(),
                "groupshared_ptr".to_string(),
                "0".to_string(),
                "1".to_string(),
            ],
            false,
            false,
        );
        assert!(stmt.contains("threadgroup atomic_int*"));
        assert!(stmt.contains("atomic_compare_exchange_weak_explicit"));
    }

    // -----------------------------------------------------------------------
    // Helper function tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_is_groupshared_ptr_positive() {
        assert!(is_groupshared_ptr("_gs_val"));
        assert!(is_groupshared_ptr("gs_ptr"));
        assert!(is_groupshared_ptr("my_groupshared_var"));
        assert!(is_groupshared_ptr("val_gs"));
    }

    #[test]
    fn t_is_groupshared_ptr_negative() {
        assert!(!is_groupshared_ptr("buf_ptr"));
        assert!(!is_groupshared_ptr("device_val"));
        assert!(!is_groupshared_ptr(""));
    }

    #[test]
    fn t_map_dxil_intrinsic_id_arithmetic() {
        assert_eq!(map_dxil_intrinsic_id(6), Some(DXIL_INTRIN_ABS));
        assert_eq!(map_dxil_intrinsic_id(7), Some(DXIL_INTRIN_SATURATE));
        assert_eq!(map_dxil_intrinsic_id(8), Some(DXIL_INTRIN_ISNAN));
        assert_eq!(map_dxil_intrinsic_id(13), Some(DXIL_INTRIN_SIN));
        assert_eq!(map_dxil_intrinsic_id(12), Some(DXIL_INTRIN_COS));
        assert_eq!(map_dxil_intrinsic_id(56), Some(DXIL_INTRIN_DOT));
    }

    #[test]
    fn t_map_dxil_intrinsic_id_texture() {
        assert_eq!(map_dxil_intrinsic_id(60), Some(DXIL_INTRIN_SAMPLE));
        assert_eq!(map_dxil_intrinsic_id(62), Some(DXIL_INTRIN_SAMPLELEVEL));
        assert_eq!(map_dxil_intrinsic_id(63), Some(DXIL_INTRIN_SAMPLEGRAD));
        assert_eq!(map_dxil_intrinsic_id(81), Some(DXIL_INTRIN_CALCULATELOD));
        assert_eq!(map_dxil_intrinsic_id(66), Some(DXIL_INTRIN_TEXTURELOAD));
    }

    #[test]
    fn t_map_dxil_intrinsic_id_atomics() {
        assert_eq!(
            map_dxil_intrinsic_id(79),
            Some(DXIL_INTRIN_ATOMICCOMPAREEXCHANGE)
        );
        // AtomicBinOp carries its operation in a constant operand and is
        // deliberately left unmapped rather than guessed.
        assert_eq!(map_dxil_intrinsic_id(78), None);
    }

    #[test]
    fn t_map_dxil_intrinsic_id_thread_and_barrier() {
        assert_eq!(map_dxil_intrinsic_id(93), Some(DXIL_INTRIN_THREADID));
        assert_eq!(map_dxil_intrinsic_id(94), Some(DXIL_INTRIN_GROUPID));
        assert_eq!(map_dxil_intrinsic_id(95), Some(DXIL_INTRIN_THREADGROUPID));
        assert_eq!(map_dxil_intrinsic_id(96), Some(DXIL_INTRIN_GROUPINDEX));
        assert_eq!(map_dxil_intrinsic_id(80), Some(DXIL_INTRIN_BARRIER));
    }

    #[test]
    fn t_map_dxil_intrinsic_id_wave() {
        assert_eq!(
            map_dxil_intrinsic_id(111),
            Some(DXIL_INTRIN_WAVEGETLANEINDEX)
        );
        assert_eq!(
            map_dxil_intrinsic_id(112),
            Some(DXIL_INTRIN_WAVEGETLANECOUNT)
        );
        assert_eq!(map_dxil_intrinsic_id(116), Some(DXIL_INTRIN_WAVEBALLOT));
        assert_eq!(map_dxil_intrinsic_id(122), Some(DXIL_INTRIN_QUADREAD));
        // Variant-carrying wave ops (WaveActiveOp etc.) are unmapped.
        assert_eq!(map_dxil_intrinsic_id(119), None);
        assert_eq!(map_dxil_intrinsic_id(121), None);
    }

    #[test]
    fn t_map_dxil_intrinsic_id_geometry() {
        assert_eq!(map_dxil_intrinsic_id(97), Some(DXIL_INTRIN_EMITSTREAM));
        assert_eq!(map_dxil_intrinsic_id(98), Some(DXIL_INTRIN_CUTSTREAM));
        assert_eq!(
            map_dxil_intrinsic_id(99),
            Some(DXIL_INTRIN_EMITTHENCUTSTREAM)
        );
    }

    #[test]
    fn t_map_dxil_intrinsic_id_create_handle() {
        assert_eq!(map_dxil_intrinsic_id(57), Some(DXIL_INTRIN_CREATEHANDLE));
        assert_eq!(
            map_dxil_intrinsic_id(217),
            Some(DXIL_INTRIN_CREATEHANDLEFORBINDING)
        );
    }

    #[test]
    fn t_map_dxil_intrinsic_id_dot4() {
        assert_eq!(
            map_dxil_intrinsic_id(163),
            Some(DXIL_INTRIN_DOT4ADDI8PACKED)
        );
        assert_eq!(
            map_dxil_intrinsic_id(164),
            Some(DXIL_INTRIN_DOT4ADDU8PACKED)
        );
    }

    #[test]
    fn t_map_dxil_intrinsic_id_unknown() {
        assert_eq!(map_dxil_intrinsic_id(0), None);
        assert_eq!(map_dxil_intrinsic_id(999), None);
        assert_eq!(map_dxil_intrinsic_id(120), None);
        assert_eq!(map_dxil_intrinsic_id(230), None);
    }

    // -----------------------------------------------------------------------
    // Quad read/write tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_quad_read() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_QUADREAD,
            "_r",
            &["val".to_string(), "lane".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("quad_broadcast(val, lane)"));
    }

    #[test]
    fn t_dxil_opcode_quad_write() {
        // QuadWrite requires 3+ args to reach the quad_vote emulation
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_QUADWRITE,
            "_r",
            &["val".to_string(), "lane".to_string(), "mask".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("quad_vote"));
    }

    // -----------------------------------------------------------------------
    // Group/device memory barrier tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_group_memory_barrier() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_GROUPMEMORYBARRIER, "", &[], false, false);
        assert!(stmt.contains("threadgroup_barrier(mem_flags::mem_threadgroup)"));
    }

    #[test]
    fn t_dxil_opcode_device_memory_barrier() {
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_DEVICEMEMORYBARRIER, "", &[], false, false);
        assert!(stmt.contains("threadgroup_barrier(mem_flags::mem_device)"));
    }

    // -----------------------------------------------------------------------
    // Derivative coarse/fine tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_derivative_coarse() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_DERIVATIVE_COARSE,
            "_r",
            &["v".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("dfdx_coarse(v)"));
    }

    #[test]
    fn t_dxil_opcode_derivative_fine() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_DERIVATIVE_FINE,
            "_r",
            &["v".to_string()],
            false,
            true,
        );
        assert!(stmt.contains("dfdx_fine(v)"));
    }

    // -----------------------------------------------------------------------
    // LLVM opcodes 49-52 tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_extractelement() {
        let stmt = dxil_opcode_to_msl(
            49,
            "_r",
            &["vec".to_string(), "3".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("_r = vec[3]"));
        // Test fallback when args are missing
        let fallback = dxil_opcode_to_msl(49, "_r", &[], false, false);
        assert!(fallback.contains("extractelement (no args)"));
    }

    #[test]
    fn t_dxil_opcode_insertelement() {
        let stmt = dxil_opcode_to_msl(
            50,
            "_r",
            &["vec".to_string(), "2".to_string(), "val".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("_r = vec;"));
        assert!(stmt.contains("vec[2] = val;"));
        assert!(stmt.contains("insertelement"));
        // Test fallback when args are missing
        let fallback = dxil_opcode_to_msl(50, "_r", &[], false, false);
        assert!(fallback.contains("insertelement (no args)"));
    }

    #[test]
    fn t_dxil_opcode_shufflevector() {
        let stmt = dxil_opcode_to_msl(
            51,
            "_r",
            &["a".to_string(), "b".to_string(), "2".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("shufflevector(a, b)"));
        // Test fallback when args are missing
        let fallback = dxil_opcode_to_msl(51, "_r", &[], false, false);
        assert!(fallback.contains("shufflevector"));
    }

    #[test]
    fn t_dxil_opcode_unreachable() {
        let stmt = dxil_opcode_to_msl(52, "", &[], false, false);
        assert_eq!(stmt, "// unreachable");
    }

    // -----------------------------------------------------------------------
    // CreateHandle / CreateHandleForBinding with dynamic indexing
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_create_handle_dynamic() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_CREATEHANDLE,
            "_r",
            &["0".to_string(), "1".to_string(), "idx".to_string()],
            false,
            false,
        );
        assert!(stmt.contains("_res_array_0[idx]"));
        assert!(stmt.contains("CreateHandle(resClass=0, rangeId=1, index=idx)"));
    }

    #[test]
    fn t_dxil_opcode_create_handle_for_binding_dynamic() {
        let stmt = dxil_opcode_to_msl(
            DXIL_INTRIN_CREATEHANDLEFORBINDING,
            "_r",
            &[
                "1".to_string(),
                "2".to_string(),
                "nonconst".to_string(),
                "1".to_string(),
            ],
            false,
            false,
        );
        assert!(stmt.contains("_res_array_1[nonconst]"));
        assert!(stmt.contains("CreateHandleForBinding(resClass=1, rangeId=2"));
    }

    // -----------------------------------------------------------------------
    // Barrier GroupSync flag differentiation tests
    // -----------------------------------------------------------------------

    #[test]
    fn t_dxil_opcode_barrier_sync_no_memory() {
        // GroupSync only (flag=0x01): should produce threadgroup_barrier (has sync)
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["1".to_string()], false, false);
        assert!(stmt.starts_with("threadgroup_barrier("));
        assert!(stmt.contains("mem_flags::mem_threadgroup | mem_flags::mem_device"));
    }

    #[test]
    fn t_dxil_opcode_barrier_no_sync_both_memory() {
        // Both GroupShared + UAV but NO GroupSync (flag=0x0C = 12):
        // should produce memory_barrier (no thread sync)
        let stmt = dxil_opcode_to_msl(DXIL_INTRIN_BARRIER, "", &["12".to_string()], false, false);
        assert!(stmt.starts_with("memory_barrier("));
        assert!(stmt.contains("mem_flags::mem_threadgroup | mem_flags::mem_device"));
    }

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
}
