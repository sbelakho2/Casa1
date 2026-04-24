use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const DXIL_MAGIC: &[u8; 4] = b"DXIL";
const MAX_PARTS: usize = 16;
const MAX_INSTRUCTIONS: u32 = 4096;
const MAX_IR_SIZE: u32 = 1 << 20;
const CACHE_MAGIC: &[u8; 8] = b"C1SHADER";
const CACHE_VERSION: u32 = 1;

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
}

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

#[derive(Debug, Clone, Default)]
pub struct ShaderCache {
    max_size_bytes: usize,
    clock: u64,
    entries: BTreeMap<String, ShaderCacheEntry>,
    logs: Vec<ReasonCode>,
}

#[derive(Debug, Clone, Default)]
pub struct OfflineCompiler {
    discovered_files: BTreeSet<PathBuf>,
    runtime_shader_keys: BTreeSet<String>,
}

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

impl ShaderCacheEntry {
    pub fn encode(&self) -> AppResult<Vec<u8>> {
        util::stable_json(self).map(|json| json.into_bytes())
    }
}

impl ShaderCache {
    pub fn new(max_size_bytes: usize) -> Self {
        Self {
            max_size_bytes,
            ..Self::default()
        }
    }

    pub fn logs(&self) -> &[ReasonCode] {
        &self.logs
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn total_size_bytes(&self) -> usize {
        self.entries.values().map(entry_size).sum()
    }

    pub fn get(&mut self, key: &str) -> Option<ShaderCacheEntry> {
        let entry = self.entries.get_mut(key)?;
        self.clock += 1;
        entry.header.last_used_ts = self.clock;
        Some(entry.clone())
    }

    pub fn insert(&mut self, mut entry: ShaderCacheEntry) {
        self.clock += 1;
        entry.header.created_ts = self.clock;
        entry.header.last_used_ts = self.clock;
        let entry_size = entry_size(&entry);
        while !self.entries.is_empty() && self.total_size_bytes() + entry_size > self.max_size_bytes {
            let lru_key = self
                .entries
                .values()
                .min_by_key(|value| value.header.last_used_ts)
                .map(|value| value.header.key.clone())
                .expect("cache is not empty");
            self.entries.remove(&lru_key);
        }
        self.entries.insert(entry.header.key.clone(), entry);
    }

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
}

impl OfflineCompiler {
    pub fn scan_directory(&mut self, root: &Path) -> AppResult<Vec<PathBuf>> {
        let mut found = Vec::new();
        for entry in WalkDir::new(root) {
            let entry = entry.map_err(|error| {
                AppError::new(ReasonCode::RcIo, format!("failed to walk {}", root.display()))
                    .with_hint(error.to_string())
            })?;
            if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "dxil") {
                self.discovered_files.insert(entry.path().to_path_buf());
                found.push(entry.path().to_path_buf());
            }
        }
        found.sort();
        Ok(found)
    }

    pub fn intercept_runtime_shader_creation(&mut self, key: &str) {
        self.runtime_shader_keys.insert(key.to_string());
    }

    pub fn schedule(&self, cpu_cap_percent: u8, max_threads: usize) -> OfflineCompilationPlan {
        let mut scheduled_keys = self
            .runtime_shader_keys
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        scheduled_keys.sort();
        OfflineCompilationPlan {
            total_shaders: self.discovered_files.len() + scheduled_keys.len(),
            worker_count: max_threads.max(1).min(4),
            cpu_cap_percent,
            io_priority_low: true,
            blocks_ui_thread: false,
            scheduled_keys,
        }
    }

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

pub fn translate_shader(input: &ShaderTranslationInput) -> Result<ShaderTranslationOutput, ShaderError> {
    let dxil_hash = util::sha256_bytes(&input.dxil);
    let root_info = parse_root_signature(&input.root_signature).map_err(|error| shader_error(input, &dxil_hash, "root_signature", error))?;
    let parsed = parse_dxil_container(&input.dxil).map_err(|error| shader_error(input, &dxil_hash, "parse", error))?;
    let reflection = if let Some(reflection) = parsed.reflection.clone() {
        cross_check_reflection(&parsed, &reflection).map_err(|error| shader_error(input, &dxil_hash, "reflection_cross_check", error))?;
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
    let cache_key = shader_cache_key(input).map_err(|error| shader_error(input, &dxil_hash, "cache_key", error))?;
    let entry_name = parsed.entry_name.clone();
    let metal_function = format!("msl_{}_{}", input.stage.as_str(), &dxil_hash[..8]);
    let mut function_mapping = BTreeMap::new();
    function_mapping.insert(entry_name.clone(), metal_function.clone());
    let reflection_json = util::stable_json(&reflection).map_err(|error| shader_error(input, &dxil_hash, "reflection_json", error))?;
    let mtl_library_bytes = format!(
        "MTLB|{}|{}|{}|{}|{}|{}",
        entry_name,
        metal_function,
        input.stage.as_str(),
        input.gpu_family,
        input.os_build,
        util::sha256_bytes(reflection_json.as_bytes())
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
        let kind = bytes[offset..offset + 4].try_into().expect("4-byte part kind");
        let descriptor = PartDescriptor {
            kind,
            offset: read_u32(bytes, offset + 4, "part offset")?,
            size: read_u32(bytes, offset + 8, "part size")?,
        };
        checked_range(bytes, descriptor.offset as usize, descriptor.size as usize, "part payload")?;
        if (descriptor.offset as usize) < descriptors_end {
            return Err(dxil_invalid("DXIL part overlaps the header region"));
        }
        parts.insert(String::from_utf8_lossy(&descriptor.kind).to_string(), descriptor);
    }

    let program_part = part_slice(bytes, parts.get("PROG").ok_or_else(|| {
        AppError::new(ReasonCode::RcDxilInvalid, "DXIL container is missing a PROG part")
    })?)?;
    let parsed_program = parse_program_part(program_part)?;
    if parsed_program.instruction_count > MAX_INSTRUCTIONS {
        return Err(dxil_invalid("DXIL instruction count exceeds safety limit"));
    }
    if parsed_program.ir_size > MAX_IR_SIZE {
        return Err(dxil_invalid("DXIL IR size exceeds safety limit"));
    }

    let sign_part = part_slice(bytes, parts.get("SIGN").ok_or_else(|| {
        AppError::new(ReasonCode::RcDxilInvalid, "DXIL container is missing a SIGN part")
    })?)?;
    if sign_part.len() < 2 {
        return Err(dxil_invalid("DXIL signature part is too small"));
    }
    let signature_mid = sign_part.len() / 2;
    let input_signature_hash = util::sha256_bytes(&sign_part[..signature_mid]);
    let output_signature_hash = util::sha256_bytes(&sign_part[signature_mid..]);

    let metadata = part_slice(bytes, parts.get("META").ok_or_else(|| {
        AppError::new(ReasonCode::RcDxilInvalid, "DXIL container is missing a META part")
    })?)?;
    let entry_name = parse_metadata_entry_name(metadata)?;

    let reflection = parts
        .get("RFLX")
        .map(|descriptor| parse_reflection_part(part_slice(bytes, descriptor).expect("valid reflection range"), &parsed_program, &input_signature_hash, &output_signature_hash))
        .transpose()?;

    Ok(ParsedDxilContainer {
        entry_name,
        instruction_count: parsed_program.instruction_count,
        ir_size: parsed_program.ir_size,
        root_signature_part: parts.get("ROOT").map(|descriptor| part_slice(bytes, descriptor).expect("valid root range").to_vec()),
        reflection_present: reflection.is_some(),
        input_signature_hash,
        output_signature_hash,
        threadgroup_size: parsed_program.threadgroup_size,
        uses: parsed_program.uses,
        reflection,
    })
}

pub fn parse_root_signature(bytes: &[u8]) -> AppResult<RootSignatureInfo> {
    if bytes.len() < 8 {
        return Err(dxil_invalid("root signature blob is too small"));
    }
    let descriptor_count = read_u32(bytes, 0, "root descriptor count")? as usize;
    let root_constants_count = read_u32(bytes, 4, "root constant count")?;
    checked_range(bytes, 8, descriptor_count * 6, "root descriptors")?;
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

pub fn build_argument_buffers(root: &RootSignatureInfo) -> Vec<ArgumentBufferLayout> {
    root.descriptors
        .iter()
        .enumerate()
        .map(|(table_index, descriptor)| ArgumentBufferLayout {
            table_index: table_index as u32,
            binding_count: descriptor.descriptor_count,
            bindless_indirection: descriptor.descriptor_count > 64,
            bindings: (0..descriptor.descriptor_count)
                .map(|index| ArgumentBinding {
                    kind: format!("{:?}", descriptor.kind).to_lowercase(),
                    register: descriptor.register + index,
                    space: descriptor.space,
                    binding_index: descriptor.binding_index + index,
                })
                .collect(),
        })
        .collect()
}

pub fn pack_cbuffer(fields: &[CbufferField]) -> PackedCbuffer {
    let mut offset = 0_u32;
    let mut register_usage = 0_u32;
    let mut packed = Vec::new();
    for field in fields {
        let array_len = field.array_len.max(1);
        let scalar_size = if field.is_bool { 4 } else { 4 };
        let is_matrix = field.rows > 1 && field.cols > 1;
        let field_size = if is_matrix {
            let vector_count = if field.row_major { field.rows } else { field.cols };
            16 * vector_count * array_len
        } else {
            let component_count = field.rows.max(field.cols).max(1);
            let element_size = component_count * scalar_size;
            if array_len > 1 {
                16 * array_len
            } else {
                element_size
            }
        };
        if is_matrix || array_len > 1 || (register_usage != 0 && register_usage + field_size > 16) {
            offset = align16(offset);
        }
        packed.push(PackedField {
            name: field.name.clone(),
            offset,
            size_bytes: field_size,
        });
        offset += field_size;
        register_usage = if is_matrix || array_len > 1 { 0 } else { offset % 16 };
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

pub fn pack_structured_fields(fields: &[StructuredField]) -> StructuredPacking {
    let mut offset = 0_u32;
    for field in fields {
        offset = align_up(offset, field.alignment.max(4));
        offset += field.size_bytes;
    }
    let stride = align_up(offset, 16);
    let packing_hash = util::sha256_bytes(
        util::stable_json(&fields.to_vec())
            .expect("structured fields are serializable")
            .as_bytes(),
    );
    StructuredPacking { stride, packing_hash }
}

pub fn shader_cache_key(input: &ShaderTranslationInput) -> AppResult<String> {
    let compile_flags_hash = util::sha256_bytes(util::stable_json(&input.compile_flags)?.as_bytes());
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

pub fn compile_with_cache(
    inputs: &[ShaderTranslationInput],
    cache: &mut ShaderCache,
) -> CacheRunStats {
    let mut stats = CacheRunStats {
        hits: 0,
        misses: 0,
        compile_stalls: 0,
    };
    for input in inputs {
        let key = shader_cache_key(input).expect("cache key");
        if cache.get(&key).is_some() {
            stats.hits += 1;
            continue;
        }
        stats.misses += 1;
        stats.compile_stalls += 1;
        if let Ok(output) = translate_shader(input) {
            let entry = build_cache_entry(&key, &output, cache.clock + 1, None).expect("cache entry");
            cache.insert(entry);
        }
    }
    stats
}

pub fn discover_dxil_files(root: &Path) -> AppResult<Vec<PathBuf>> {
    let mut compiler = OfflineCompiler::default();
    compiler.scan_directory(root)
}

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
        Err(error) => format!("err:{}:{}", error.code.as_u32(), error.message),
    }
}

fn parse_program_part(bytes: &[u8]) -> AppResult<ParsedProgram> {
    checked_range(bytes, 0, 24, "program header")?;
    let instruction_count = read_u32(bytes, 0, "instruction count")?;
    let ir_size = read_u32(bytes, 4, "IR size")?;
    let threadgroup_size = ThreadgroupSize {
        x: read_u32(bytes, 8, "threadgroup x")?,
        y: read_u32(bytes, 12, "threadgroup y")?,
        z: read_u32(bytes, 16, "threadgroup z")?,
    };
    let use_count = read_u32(bytes, 20, "resource use count")? as usize;
    checked_range(bytes, 24, use_count * 8, "resource use table")?;
    let mut uses = Vec::with_capacity(use_count);
    for index in 0..use_count {
        let offset = 24 + index * 8;
        uses.push(ProgramUse {
            kind: parse_program_kind(bytes[offset])?,
            register: bytes[offset + 1] as u32,
            space: bytes[offset + 2] as u32,
            access: parse_resource_access(bytes[offset + 3])?,
            format: parse_format_code(bytes[offset + 4]).to_string(),
            size_bytes: matches!(bytes[offset], 3).then_some(u16::from_le_bytes([bytes[offset + 5], bytes[offset + 6]]) as u32),
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
    checked_range(bytes, 4, resource_count * 7 + 4, "reflection resources")?;
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
    let cbuffer_base = 4 + resource_count * 7;
    let cbuffer_count = read_u32(bytes, cbuffer_base, "reflection cbuffer count")? as usize;
    checked_range(bytes, cbuffer_base + 4, cbuffer_count * 8, "reflection cbuffers")?;
    let mut cbuffers = Vec::with_capacity(cbuffer_count);
    for index in 0..cbuffer_count {
        let offset = cbuffer_base + 4 + index * 8;
        let register = bytes[offset] as u32;
        let space = bytes[offset + 1] as u32;
        let size_bytes = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as u32;
        let packing_seed = u32::from_le_bytes([bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]]);
        cbuffers.push(ReflectionCbuffer {
            register,
            space,
            size_bytes,
            packing_hash: util::sha256_bytes(format!("{register}:{space}:{size_bytes}:{packing_seed}").as_bytes()),
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

fn cross_check_reflection(parsed: &ParsedDxilContainer, reflection: &ReflectionTable) -> AppResult<()> {
    let expected_resources = parsed
        .uses
        .iter()
        .filter_map(|use_entry| match use_entry.kind {
            ProgramBindingKind::Buffer => Some((ResourceKind::Buffer, use_entry.register, use_entry.space)),
            ProgramBindingKind::Texture => Some((ResourceKind::Texture, use_entry.register, use_entry.space)),
            ProgramBindingKind::Sampler => Some((ResourceKind::Sampler, use_entry.register, use_entry.space)),
            ProgramBindingKind::Cbuffer => None,
        })
        .collect::<BTreeSet<_>>();
    let actual_resources = reflection
        .resources
        .iter()
        .map(|resource| (resource.kind, resource.register, resource.space))
        .collect::<BTreeSet<_>>();
    if expected_resources != actual_resources {
        return Err(dxil_invalid("reflection/resources do not match DXIL bytecode usage"));
    }
    let expected_cbuffers = parsed
        .uses
        .iter()
        .filter_map(|use_entry| match use_entry.kind {
            ProgramBindingKind::Cbuffer => Some((use_entry.register, use_entry.space, use_entry.size_bytes.unwrap_or(0))),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let actual_cbuffers = reflection
        .cbuffers
        .iter()
        .map(|cbuffer| (cbuffer.register, cbuffer.space, cbuffer.size_bytes))
        .collect::<BTreeSet<_>>();
    if expected_cbuffers != actual_cbuffers {
        return Err(dxil_invalid("reflection/cbuffer usage does not match DXIL bytecode usage"));
    }
    Ok(())
}

fn reconstruct_reflection(parsed: &ParsedDxilContainer, root: &RootSignatureInfo) -> AppResult<ReflectionTable> {
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
                format!("ambiguous root signature binding for register t{} space {}", use_entry.register, use_entry.space),
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
                    format!("{}:{}:{}", use_entry.register, use_entry.space, use_entry.size_bytes.unwrap_or(0)).as_bytes(),
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

fn shader_error(input: &ShaderTranslationInput, dxil_hash: &str, failing_pass: &str, error: AppError) -> ShaderError {
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
        + entry.payload.metal_pipeline_archive.as_ref().map_or(0, Vec::len)
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
    let end = start + descriptor.size as usize;
    bytes.get(start..end).ok_or_else(|| {
        AppError::new(ReasonCode::RcDxilInvalid, "DXIL part range is out of bounds")
    })
}

fn checked_range(bytes: &[u8], offset: usize, size: usize, label: &str) -> AppResult<()> {
    if offset.checked_add(size).filter(|end| *end <= bytes.len()).is_none() {
        return Err(AppError::new(
            ReasonCode::RcDxilInvalid,
            format!("{label} extends beyond the DXIL buffer"),
        ));
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize, label: &str) -> AppResult<u32> {
    checked_range(bytes, offset, 4, label)?;
    Ok(u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4-byte integer")))
}

fn dxil_invalid(message: impl Into<String>) -> AppError {
    AppError::new(ReasonCode::RcDxilInvalid, message.into())
}

fn align16(value: u32) -> u32 {
    align_up(value, 16)
}

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        value
    } else {
        ((value + alignment - 1) / alignment) * alignment
    }
}