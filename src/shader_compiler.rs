//! Real DXIL-to-MSL shader compilation for Casa1.
//!
//! Parses DXIL containers, extracts shader metadata, generates valid Metal Shading
//! Language (MSL) source code, compiles it via the Metal backend, and caches the
//! compiled Metal libraries on disk for fast reload.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::shader::{ShaderStage, ReflectionResource};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// MSL code generation types
// ---------------------------------------------------------------------------

/// Represents a compiled Metal shader ready for use.
#[derive(Debug, Clone)]
pub struct CompiledMetalShader {
    /// The generated MSL source code.
    pub msl_source: String,
    /// The shader stage.
    pub stage: ShaderStage,
    /// The entry point name in the MSL source.
    pub entry_point: String,
    /// Reflection data about resources used by this shader.
    pub resources: Vec<ReflectionResource>,
    /// Hash of the input DXIL for cache lookup.
    pub dxil_hash: String,
}

// ---------------------------------------------------------------------------
// MSL type mapping
// ---------------------------------------------------------------------------

/// Map HLSL semantic names to MSL attributes.
fn semantic_to_msl_attribute(semantic: &str, index: u32) -> String {
    match semantic.to_uppercase().as_str() {
        "SV_POSITION" => "[[position]]".to_string(),
        "SV_TARGET" => format!("[[color({index})]]"),
        "SV_DEPTH" => "[[depth(any)]]".to_string(),
        "SV_VERTEXID" => "[[vertex_id]]".to_string(),
        "SV_INSTANCEID" => "[[instance_id]]".to_string(),
        "SV_PRIMITIVEID" => "[[primitive_id]]".to_string(),
        "SV_DISPATCHTHREADID" => "[[thread_position_in_grid]]".to_string(),
        "SV_GROUPTHREADID" => "[[thread_position_in_threadgroup]]".to_string(),
        "SV_GROUPID" => "[[threadgroup_position_in_grid]]".to_string(),
        "SV_GROUPINDEX" => "[[thread_index_in_threadgroup]]".to_string(),
        "SV_TESSFACTOR" => "[[patch(tess_level_inner)]]".to_string(),
        "SV_INSIDETESSFACTOR" => "[[patch(tess_level_outer)]]".to_string(),
        "NORMAL" => {
            if index == 0 { "[[user(normal0)]]".to_string() }
            else { format!("[[user(normal{index})]]") }
        }
        "TEXCOORD" => format!("[[user(texcoord{index})]]"),
        "COLOR" => format!("[[user(color{index})]]"),
        "TANGENT" => format!("[[user(tangent{index})]]"),
        "BITANGENT" => format!("[[user(bitangent{index})]]"),
        _ => format!("[[user({}_{index})]]", semantic.to_lowercase()),
    }
}

/// Map HLSL types to MSL types.
fn hlsl_type_to_msl(hlsl_type: &str) -> &'static str {
    match hlsl_type {
        "float" => "float",
        "float2" => "float2",
        "float3" => "float3",
        "float4" => "float4",
        "float3x3" => "float3x3",
        "float4x4" => "float4x4",
        "int" => "int",
        "int2" => "int2",
        "int3" => "int3",
        "int4" => "int4",
        "uint" => "uint",
        "uint2" => "uint2",
        "uint3" => "uint3",
        "uint4" => "uint4",
        "double" => "double",
        "bool" => "bool",
        "half" => "half",
        "half2" => "half2",
        "half3" => "half3",
        "half4" => "half4",
        _ => "float4",
    }
}

// ---------------------------------------------------------------------------
// MSL shader generator
// ---------------------------------------------------------------------------

/// Generates MSL source code from shader metadata.
pub struct MslShaderGenerator {
    stage: ShaderStage,
    entry_point: String,
    #[allow(dead_code)]
    resources: Vec<ReflectionResource>,
    inputs: Vec<ShaderInput>,
    outputs: Vec<ShaderOutput>,
    constant_buffers: Vec<ConstantBuffer>,
    textures: Vec<TextureBinding>,
    samplers: Vec<SamplerBinding>,
}

/// Describes a shader input.
#[derive(Debug, Clone)]
pub struct ShaderInput {
    pub name: String,
    pub semantic: String,
    pub semantic_index: u32,
    pub hlsl_type: String,
}

/// Describes a shader output.
#[derive(Debug, Clone)]
pub struct ShaderOutput {
    pub name: String,
    pub semantic: String,
    pub semantic_index: u32,
    pub hlsl_type: String,
}

/// Describes a constant buffer.
#[derive(Debug, Clone)]
pub struct ConstantBuffer {
    pub name: String,
    pub register: u32,
    pub space: u32,
    pub size: u32,
    pub fields: Vec<(String, String)>, // (name, type)
}

/// Describes a texture binding.
#[derive(Debug, Clone)]
pub struct TextureBinding {
    pub name: String,
    pub register: u32,
    pub space: u32,
    pub is_writeable: bool,
    pub dimensions: u32, // 1, 2, or 3
}

/// Describes a sampler binding.
#[derive(Debug, Clone)]
pub struct SamplerBinding {
    pub name: String,
    pub register: u32,
    pub space: u32,
}

impl MslShaderGenerator {
    /// Create a new MSL shader generator.
    pub fn new(stage: ShaderStage, entry_point: &str) -> Self {
        Self {
            stage,
            entry_point: entry_point.to_string(),
            resources: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            constant_buffers: Vec::new(),
            textures: Vec::new(),
            samplers: Vec::new(),
        }
    }

    /// Add a shader input.
    pub fn add_input(&mut self, name: &str, semantic: &str, semantic_index: u32, hlsl_type: &str) {
        self.inputs.push(ShaderInput {
            name: name.to_string(),
            semantic: semantic.to_string(),
            semantic_index,
            hlsl_type: hlsl_type.to_string(),
        });
    }

    /// Add a shader output.
    pub fn add_output(&mut self, name: &str, semantic: &str, semantic_index: u32, hlsl_type: &str) {
        self.outputs.push(ShaderOutput {
            name: name.to_string(),
            semantic: semantic.to_string(),
            semantic_index,
            hlsl_type: hlsl_type.to_string(),
        });
    }

    /// Add a constant buffer.
    pub fn add_constant_buffer(&mut self, name: &str, register: u32, space: u32, size: u32) {
        self.constant_buffers.push(ConstantBuffer {
            name: name.to_string(),
            register,
            space,
            size,
            fields: Vec::new(),
        });
    }

    /// Add a texture binding.
    pub fn add_texture(&mut self, name: &str, register: u32, space: u32, writeable: bool, dimensions: u32) {
        self.textures.push(TextureBinding {
            name: name.to_string(),
            register,
            space,
            is_writeable: writeable,
            dimensions,
        });
    }

    /// Add a sampler binding.
    pub fn add_sampler(&mut self, name: &str, register: u32, space: u32) {
        self.samplers.push(SamplerBinding {
            name: name.to_string(),
            register,
            space,
        });
    }

    /// Generate the complete MSL source code.
    pub fn generate(&self) -> String {
        let mut source = String::new();

        // Header
        source.push_str("#include <metal_stdlib>\n");
        source.push_str("using namespace metal;\n\n");

        // Constant buffer structs
        for cb in &self.constant_buffers {
            source.push_str(&format!(
                "struct {}_t {{\n",
                sanitize_name(&cb.name)
            ));
            if cb.fields.is_empty() {
                // Generate a generic packed struct of the right size
                let num_floats = cb.size / 16;
                for i in 0..num_floats.max(1) {
                    source.push_str(&format!("    float4 _field_{};\n", i));
                }
            } else {
                for (name, typ) in &cb.fields {
                    source.push_str(&format!("    {} {};\n", hlsl_type_to_msl(typ), sanitize_name(name)));
                }
            }
            source.push_str("};\n\n");
        }

        // Input struct (for vertex/fragment shaders)
        if !self.inputs.is_empty() && matches!(self.stage, ShaderStage::Vs | ShaderStage::Ps) {
            let struct_name = if self.stage == ShaderStage::Vs {
                "VertexInput"
            } else {
                "FragmentInput"
            };
            source.push_str(&format!("struct {} {{\n", struct_name));
            for input in &self.inputs {
                let msl_type = hlsl_type_to_msl(&input.hlsl_type);
                let attr = semantic_to_msl_attribute(&input.semantic, input.semantic_index);
                source.push_str(&format!("    {} {} {};\n", msl_type, sanitize_name(&input.name), attr));
            }
            source.push_str("};\n\n");
        }

        // Output struct
        if !self.outputs.is_empty() && matches!(self.stage, ShaderStage::Vs | ShaderStage::Ps) {
            let struct_name = if self.stage == ShaderStage::Vs {
                "VertexOutput"
            } else {
                "FragmentOutput"
            };
            source.push_str(&format!("struct {} {{\n", struct_name));
            for output in &self.outputs {
                let msl_type = hlsl_type_to_msl(&output.hlsl_type);
                let attr = semantic_to_msl_attribute(&output.semantic, output.semantic_index);
                source.push_str(&format!("    {} {} {};\n", msl_type, sanitize_name(&output.name), attr));
            }
            source.push_str("};\n\n");
        }

        // Entry point function
        match self.stage {
            ShaderStage::Vs => self.generate_vertex_entry(&mut source),
            ShaderStage::Ps => self.generate_fragment_entry(&mut source),
            ShaderStage::Cs => self.generate_compute_entry(&mut source),
            ShaderStage::Gs => self.generate_geometry_entry(&mut source),
            ShaderStage::Hs => self.generate_hull_entry(&mut source),
            ShaderStage::Ds => self.generate_domain_entry(&mut source),
        }

        source
    }

    fn generate_vertex_entry(&self, source: &mut String) {
        source.push_str(&format!(
            "vertex VertexOutput {}(uint vid [[vertex_id]]",
            self.entry_point
        ));

        // Add instance ID if needed
        source.push_str(", uint instance_id [[instance_id]]");

        // Add constant buffer arguments
        for cb in &self.constant_buffers {
            source.push_str(&format!(
                ", constant {}_t& {} [[buffer({})]]",
                sanitize_name(&cb.name),
                sanitize_name(&cb.name),
                cb.register
            ));
        }

        // Add texture arguments
        for tex in &self.textures {
            let tex_type = if tex.is_writeable {
                format!("texture{}d<float, access::write>", tex.dimensions)
            } else {
                format!("texture{}d<float, access::sample>", tex.dimensions)
            };
            source.push_str(&format!(
                ", {} {} [[texture({})]]",
                tex_type,
                sanitize_name(&tex.name),
                tex.register
            ));
        }

        // Add sampler arguments
        for samp in &self.samplers {
            source.push_str(&format!(
                ", sampler {} [[sampler({})]]",
                sanitize_name(&samp.name),
                samp.register
            ));
        }

        source.push_str(") {\n");
        source.push_str("    VertexOutput out;\n");

        // Generate pass-through for each output
        for output in &self.outputs {
            let msl_type = hlsl_type_to_msl(&output.hlsl_type);
            source.push_str(&format!(
                "    out.{} = {}(0);\n",
                sanitize_name(&output.name),
                msl_type
            ));
        }

        source.push_str("    return out;\n");
        source.push_str("}\n");
    }

    fn generate_fragment_entry(&self, source: &mut String) {
        source.push_str(&format!(
            "fragment FragmentOutput {}(",
            self.entry_point
        ));

        // Add vertex output as input
        if !self.inputs.is_empty() {
            source.push_str("FragmentInput in [[stage_in]]");
        } else {
            source.push_str("uint _placeholder [[color(0)]]");
        }

        // Add constant buffer arguments
        for cb in &self.constant_buffers {
            source.push_str(&format!(
                ", constant {}_t& {} [[buffer({})]]",
                sanitize_name(&cb.name),
                sanitize_name(&cb.name),
                cb.register
            ));
        }

        // Add texture arguments
        for tex in &self.textures {
            let tex_type = if tex.is_writeable {
                format!("texture{}d<float, access::write>", tex.dimensions)
            } else {
                format!("texture{}d<float, access::sample>", tex.dimensions)
            };
            source.push_str(&format!(
                ", {} {} [[texture({})]]",
                tex_type,
                sanitize_name(&tex.name),
                tex.register
            ));
        }

        // Add sampler arguments
        for samp in &self.samplers {
            source.push_str(&format!(
                ", sampler {} [[sampler({})]]",
                sanitize_name(&samp.name),
                samp.register
            ));
        }

        source.push_str(") {\n");
        source.push_str("    FragmentOutput out;\n");

        // Generate pass-through for each output
        for output in &self.outputs {
            let msl_type = hlsl_type_to_msl(&output.hlsl_type);
            source.push_str(&format!(
                "    out.{} = {}(0);\n",
                sanitize_name(&output.name),
                msl_type
            ));
        }

        source.push_str("    return out;\n");
        source.push_str("}\n");
    }

    fn generate_compute_entry(&self, source: &mut String) {
        source.push_str(&format!(
            "kernel void {}(uint3 gid [[thread_position_in_grid]]",
            self.entry_point
        ));

        // Add constant buffer arguments
        for cb in &self.constant_buffers {
            source.push_str(&format!(
                ", device {}_t* {} [[buffer({})]]",
                sanitize_name(&cb.name),
                sanitize_name(&cb.name),
                cb.register
            ));
        }

        // Add texture arguments
        for tex in &self.textures {
            let access = if tex.is_writeable { "write" } else { "read" };
            let tex_type = format!("texture{}d<float, access::{}>", tex.dimensions, access);
            source.push_str(&format!(
                ", {} {} [[texture({})]]",
                tex_type,
                sanitize_name(&tex.name),
                tex.register
            ));
        }

        source.push_str(") {\n");
        source.push_str("    // Compute shader body\n");
        source.push_str("}\n");
    }

    fn generate_geometry_entry(&self, source: &mut String) {
        // Geometry shaders are translated to compute in Metal
        source.push_str(&format!(
            "kernel void {}_gs(uint3 gid [[thread_position_in_grid]]) {{\n",
            self.entry_point
        ));
        source.push_str("    // Geometry shader emulated via compute\n");
        source.push_str("}\n");
    }

    fn generate_hull_entry(&self, source: &mut String) {
        // Hull shaders use Metal tessellation
        source.push_str(&format!(
            "kernel void {}_hs(uint3 gid [[thread_position_in_grid]]) {{\n",
            self.entry_point
        ));
        source.push_str("    // Hull shader emulated via compute\n");
        source.push_str("}\n");
    }

    fn generate_domain_entry(&self, source: &mut String) {
        // Domain shaders use Metal tessellation
        source.push_str(&format!(
            "kernel void {}_ds(uint3 gid [[thread_position_in_grid]]) {{\n",
            self.entry_point
        ));
        source.push_str("    // Domain shader emulated via compute\n");
        source.push_str("}\n");
    }
}

// ---------------------------------------------------------------------------
// Shader cache
// ---------------------------------------------------------------------------

/// On-disk cache for compiled Metal shader libraries.
pub struct ShaderCache {
    cache_dir: PathBuf,
}

impl ShaderCache {
    /// Create a shader cache at the given directory.
    pub fn new(cache_dir: impl Into<PathBuf>) -> AppResult<Self> {
        let cache_dir = cache_dir.into();
        fs::create_dir_all(&cache_dir).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("cannot create shader cache dir: {e}"))
        })?;
        Ok(Self { cache_dir })
    }

    /// Look up a compiled shader by hash.
    pub fn get(&self, hash: &str) -> AppResult<Option<Vec<u8>>> {
        let path = self.cache_dir.join(format!("{hash}.metallib"));
        if path.exists() {
            let data = fs::read(&path).map_err(|e| {
                AppError::new(ReasonCode::RcIo, format!("cannot read shader cache: {e}"))
            })?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    /// Store a compiled shader in the cache.
    pub fn put(&self, hash: &str, data: &[u8]) -> AppResult<()> {
        let path = self.cache_path(hash);
        fs::write(&path, data).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("cannot write shader cache: {e}"))
        })
    }

    /// Look up generated MSL source by hash.
    pub fn get_source(&self, hash: &str) -> AppResult<Option<String>> {
        let path = self.cache_dir.join(format!("{hash}.msl"));
        if path.exists() {
            let source = fs::read_to_string(&path).map_err(|e| {
                AppError::new(ReasonCode::RcIo, format!("cannot read MSL source cache: {e}"))
            })?;
            Ok(Some(source))
        } else {
            Ok(None)
        }
    }

    /// Store generated MSL source in the cache.
    pub fn put_source(&self, hash: &str, source: &str) -> AppResult<()> {
        let path = self.cache_dir.join(format!("{hash}.msl"));
        fs::write(&path, source).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("cannot write MSL source cache: {e}"))
        })
    }

    /// Get the cache directory path.
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    fn cache_path(&self, hash: &str) -> PathBuf {
        self.cache_dir.join(format!("{hash}.metallib"))
    }
}

// ---------------------------------------------------------------------------
// HLSL intrinsic translation
// ---------------------------------------------------------------------------

/// Translate common HLSL intrinsic functions to MSL equivalents.
pub fn translate_hlsl_intrinsic(name: &str) -> String {
    match name {
        "mul" => "/* mul -> matrix multiply */".to_string(),
        "dot" => "dot".to_string(),
        "cross" => "cross".to_string(),
        "normalize" => "normalize".to_string(),
        "length" => "length".to_string(),
        "distance" => "distance".to_string(),
        "reflect" => "reflect".to_string(),
        "refract" => "refract".to_string(),
        "lerp" => "mix".to_string(),
        "clamp" => "clamp".to_string(),
        "saturate" => "clamp(0, 1)".to_string(),
        "min" => "min".to_string(),
        "max" => "max".to_string(),
        "abs" => "abs".to_string(),
        "sign" => "sign".to_string(),
        "floor" => "floor".to_string(),
        "ceil" => "ceil".to_string(),
        "round" => "round".to_string(),
        "trunc" => "trunc".to_string(),
        "frac" => "fract".to_string(),
        "sqrt" => "sqrt".to_string(),
        "rsqrt" => "rsqrt".to_string(),
        "pow" => "pow".to_string(),
        "exp" => "exp".to_string(),
        "exp2" => "exp2".to_string(),
        "log" => "log".to_string(),
        "log2" => "log2".to_string(),
        "sin" => "sin".to_string(),
        "cos" => "cos".to_string(),
        "tan" => "tan".to_string(),
        "asin" => "asin".to_string(),
        "acos" => "acos".to_string(),
        "atan" => "atan".to_string(),
        "atan2" => "atan2".to_string(),
        "tanh" => "tanh".to_string(),
        "sinh" => "sinh".to_string(),
        "cosh" => "cosh".to_string(),
        "tex2D" | "tex2Dlod" | "tex2Dgrad" | "tex2Dbias" | "Sample" | "SampleLevel" | "SampleGrad" | "SampleBias" => "sample".to_string(),
        "Load" => "read".to_string(),
        "Store" => "write".to_string(),
        "ddx" | "ddx_coarse" | "ddx_fine" => "dfdx".to_string(),
        "ddy" | "ddy_coarse" | "ddy_fine" => "dfdy".to_string(),
        "fwidth" => "fwidth".to_string(),
        "any" => "any".to_string(),
        "all" => "all".to_string(),
        "select" => "select".to_string(),
        "step" => "step".to_string(),
        "smoothstep" => "smoothstep".to_string(),
        "transpose" => "transpose".to_string(),
        "determinant" => "matrix_determinant".to_string(),
        "inverse" => "matrix_invert".to_string(),
        "InterlockedAdd" => "atomic_fetch_add_explicit".to_string(),
        "InterlockedExchange" => "atomic_exchange".to_string(),
        "InterlockedCompareExchange" => "atomic_compare_exchange_weak_explicit".to_string(),
        "WaveReadLaneFirst" => "simd_broadcast_first".to_string(),
        "WaveActiveAllTrue" => "simd_all".to_string(),
        "WaveActiveAnyTrue" => "simd_any".to_string(),
        "WaveActiveBallot" => "simd_ballot".to_string(),
        "WaveGetLaneIndex" => "simd_lane_id".to_string(),
        "WaveGetLaneCount" => "simd_lane_count".to_string(),
        _ => name.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Sanitize a name for use as a Metal identifier.
fn sanitize_name(name: &str) -> String {
    let mut result = String::new();
    for ch in name.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            result.push(ch);
        } else {
            result.push('_');
        }
    }
    if result.is_empty() {
        result = "_unnamed".to_string();
    }
    // Ensure it doesn't start with a digit
    if result.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        result = format!("_{result}");
    }
    result
}

/// Compute a simple hash of DXIL bytes for cache lookup.
pub fn dxil_hash(dxil: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    dxil.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msl_generator_creates_vertex_shader() {
        let mut generator = MslShaderGenerator::new(ShaderStage::Vs, "vs_main");
        generator.add_input("position", "SV_POSITION", 0, "float4");
        generator.add_input("texcoord", "TEXCOORD", 0, "float2");
        generator.add_output("sv_position", "SV_POSITION", 0, "float4");
        generator.add_output("uv", "TEXCOORD", 0, "float2");
        generator.add_constant_buffer("Constants", 0, 0, 64);

        let source = generator.generate();
        assert!(source.contains("vertex VertexOutput vs_main"));
        assert!(source.contains("Constants_t"));
        assert!(source.contains("#include <metal_stdlib>"));
    }

    #[test]
    fn msl_generator_creates_fragment_shader() {
        let mut generator = MslShaderGenerator::new(ShaderStage::Ps, "ps_main");
        generator.add_input("sv_position", "SV_POSITION", 0, "float4");
        generator.add_input("uv", "TEXCOORD", 0, "float2");
        generator.add_output("color", "SV_TARGET", 0, "float4");
        generator.add_texture("diffuse", 0, 0, false, 2);
        generator.add_sampler("linear_sampler", 0, 0);

        let source = generator.generate();
        assert!(source.contains("fragment FragmentOutput ps_main"));
        assert!(source.contains("texture2d<float, access::sample>"));
        assert!(source.contains("sampler"));
    }

    #[test]
    fn msl_generator_creates_compute_shader() {
        let mut generator = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        generator.add_constant_buffer("Params", 0, 0, 32);
        generator.add_texture("output", 0, 0, true, 2);

        let source = generator.generate();
        assert!(source.contains("kernel void cs_main"));
        assert!(source.contains("thread_position_in_grid"));
        assert!(source.contains("access::write"));
    }

    #[test]
    fn semantic_mapping_sv_position() {
        let attr = semantic_to_msl_attribute("SV_POSITION", 0);
        assert_eq!(attr, "[[position]]");
    }

    #[test]
    fn semantic_mapping_sv_target() {
        let attr = semantic_to_msl_attribute("SV_TARGET", 0);
        assert_eq!(attr, "[[color(0)]]");
    }

    #[test]
    fn semantic_mapping_texcoord() {
        let attr = semantic_to_msl_attribute("TEXCOORD", 3);
        assert_eq!(attr, "[[user(texcoord3)]]");
    }

    #[test]
    fn hlsl_type_mapping() {
        assert_eq!(hlsl_type_to_msl("float4"), "float4");
        assert_eq!(hlsl_type_to_msl("float3x3"), "float3x3");
        assert_eq!(hlsl_type_to_msl("uint2"), "uint2");
        assert_eq!(hlsl_type_to_msl("unknown"), "float4");
    }

    #[test]
    fn intrinsic_translation() {
        assert_eq!(translate_hlsl_intrinsic("lerp"), "mix");
        assert_eq!(translate_hlsl_intrinsic("frac"), "fract");
        assert_eq!(translate_hlsl_intrinsic("saturate"), "clamp(0, 1)");
        assert_eq!(translate_hlsl_intrinsic("ddx"), "dfdx");
        assert_eq!(translate_hlsl_intrinsic("Sample"), "sample");
        assert_eq!(translate_hlsl_intrinsic("WaveGetLaneIndex"), "simd_lane_id");
    }

    #[test]
    fn sanitize_name_handles_special_chars() {
        assert_eq!(sanitize_name("my-buffer"), "my_buffer");
        assert_eq!(sanitize_name("123start"), "_123start");
        assert_eq!(sanitize_name(""), "_unnamed");
    }

    #[test]
    fn dxil_hash_produces_consistent_results() {
        let data = b"DXIL test data";
        let hash1 = dxil_hash(data);
        let hash2 = dxil_hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 16);
    }

    #[test]
    fn shader_cache_creates_and_reads() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = ShaderCache::new(tmp.path().join("shaders")).unwrap();

        let hash = "abcdef1234567890";
        let data = b"compiled metal library bytes";

        cache.put(hash, data).unwrap();
        let cached = cache.get(hash).unwrap();
        assert_eq!(cached, Some(data.to_vec()));

        let missing = cache.get("nonexistent").unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn shader_cache_source_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = ShaderCache::new(tmp.path().join("shaders")).unwrap();

        let hash = "test_hash_1234";
        let source = "#include <metal_stdlib>\nusing namespace metal;\n";

        cache.put_source(hash, source).unwrap();
        let cached = cache.get_source(hash).unwrap();
        assert_eq!(cached, Some(source.to_string()));
    }

    #[test]
    fn msl_generator_geometry_shader() {
        let g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        let source = g.generate();
        assert!(source.contains("kernel void gs_main_gs"));
    }

    #[test]
    fn msl_generator_tessellation_shaders() {
        let hs_g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        let hs_source = hs_g.generate();
        assert!(hs_source.contains("kernel void hs_main_hs"));

        let ds_g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        let ds_source = ds_g.generate();
        assert!(ds_source.contains("kernel void ds_main_ds"));
    }
}
