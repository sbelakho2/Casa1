//! Real DXIL-to-MSL shader compilation for Casa1.
//!
//! Parses DXIL containers, extracts shader metadata, generates valid Metal Shading
//! Language (MSL) source code, compiles it via the Metal backend, and caches the
//! compiled Metal libraries on disk for fast reload.

use crate::error::{AppError, AppResult};
use crate::metal_backend::{
    InputPrimitive, OutputPrimitive, OutputTopology, PartitionMode, PatchType,
};
use crate::reason::ReasonCode;
use crate::shader::{ReflectionResource, ShaderStage, TranslatedInstruction};
use sha2::{Digest, Sha256};
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
        // HLSL SV_TessFactor = outer (edge) factors, SV_InsideTessFactor = inner;
        // Metal tess_level_outer / tess_level_inner match respectively.
        "SV_TESSFACTOR" => "[[patch(tess_level_outer)]]".to_string(),
        "SV_INSIDETESSFACTOR" => "[[patch(tess_level_inner)]]".to_string(),
        "NORMAL" => {
            if index == 0 {
                "[[user(normal0)]]".to_string()
            } else {
                format!("[[user(normal{index})]]")
            }
        }
        "TEXCOORD" => format!("[[user(texcoord{index})]]"),
        "COLOR" => format!("[[user(color{index})]]"),
        "TANGENT" => format!("[[user(tangent{index})]]"),
        "BITANGENT" => format!("[[user(bitangent{index})]]"),
        _ => format!("[[user({}_{index})]]", semantic.to_lowercase()),
    }
}

/// Map HLSL semantic names to MSL attributes for **vertex** `stage_in` members.
///
/// `[[position]]` (and the other output-only attributes) are not valid on a
/// vertex function's stage-in struct; such inputs fall back to a user
/// attribute so the generated shader still compiles.
fn semantic_to_msl_vertex_input_attribute(semantic: &str, index: u32) -> String {
    match semantic.to_uppercase().as_str() {
        "SV_POSITION" | "SV_TARGET" | "SV_DEPTH" => {
            format!("[[user({}_{index})]]", semantic.to_lowercase())
        }
        _ => semantic_to_msl_attribute(semantic, index),
    }
}

/// Map HLSL types to MSL types.
///
/// Unsupported types map to an MSL error comment rather than a silently wrong
/// `float4` so that a bad type mapping fails loudly at MSL compile time instead
/// of corrupting the shader's data layout.
fn hlsl_type_to_msl(hlsl_type: &str) -> String {
    match hlsl_type {
        "float" => "float".to_string(),
        "float2" => "float2".to_string(),
        "float3" => "float3".to_string(),
        "float4" => "float4".to_string(),
        "float3x3" => "float3x3".to_string(),
        "float4x4" => "float4x4".to_string(),
        "int" => "int".to_string(),
        "int2" => "int2".to_string(),
        "int3" => "int3".to_string(),
        "int4" => "int4".to_string(),
        "uint" => "uint".to_string(),
        "uint2" => "uint2".to_string(),
        "uint3" => "uint3".to_string(),
        "uint4" => "uint4".to_string(),
        "double" => "double".to_string(),
        "bool" => "bool".to_string(),
        "half" => "half".to_string(),
        "half2" => "half2".to_string(),
        "half3" => "half3".to_string(),
        "half4" => "half4".to_string(),
        _ => format!("// ERROR: unknown HLSL type '{hlsl_type}'"),
    }
}

// ---------------------------------------------------------------------------
// MSL shader generator
// ---------------------------------------------------------------------------

/// Generates MSL source code from shader metadata.
///
/// Bridges the gap between the DXIL opcode translator (`dxil_opcode_to_msl()` in
/// `shader.rs`) and the Metal entry point templates for each shader stage.
/// The caller populates instructions via `set_instructions()`, sets stage-
/// specific parameters (threadgroup size, tessellation info, etc.), and then
/// calls `generate()` to produce the complete MSL source.
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
    /// Number of tessellation control points (hull/domain shaders).
    patch_control_points: u32,

    // ---- DXIL→MSL instruction pipeline ----
    /// Translated DXIL instruction bodies to inline into the entry point.
    instructions: Vec<TranslatedInstruction>,

    // ---- Compute shader configuration ----
    /// Threadgroup size for compute shaders.
    threadgroup_size: (u32, u32, u32),
    /// True if the shader accesses UAVs (requires `device` address space).
    has_uav: bool,
    /// True if the shader uses groupshared / threadgroup memory.
    has_group_memory: bool,

    // ---- Geometry shader (GS-as-compute) configuration ----
    /// Input primitive type for geometry shader emulation.
    input_primitive: Option<InputPrimitive>,
    /// Output primitive type for geometry shader emulation.
    output_primitive: Option<OutputPrimitive>,
    /// Maximum number of vertices the geometry shader can emit per invocation.
    max_vertex_count: u32,

    // ---- Hull/Domain shader tessellation configuration ----
    /// Patch type (triangle, quad, isoline).
    patch_type: Option<PatchType>,
    /// Partition mode (integer, fractional, pow2).
    partition_mode: Option<PartitionMode>,
    /// Output topology for tessellated patches.
    output_topology: Option<OutputTopology>,
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
            patch_control_points: 0,
            instructions: Vec::new(),
            threadgroup_size: (1, 1, 1),
            has_uav: false,
            has_group_memory: false,
            input_primitive: None,
            output_primitive: None,
            max_vertex_count: 0,
            patch_type: None,
            partition_mode: None,
            output_topology: None,
        }
    }

    // -----------------------------------------------------------------------
    // Binding registration
    // -----------------------------------------------------------------------

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
    pub fn add_texture(
        &mut self,
        name: &str,
        register: u32,
        space: u32,
        writeable: bool,
        dimensions: u32,
    ) {
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

    /// Set the number of tessellation control points (for hull/domain shaders).
    pub fn set_patch_control_points(&mut self, n: u32) {
        self.patch_control_points = n;
    }

    // -----------------------------------------------------------------------
    // DXIL→MSL instruction pipeline
    // -----------------------------------------------------------------------

    /// Set the translated DXIL instructions to inline into the entry point body.
    ///
    /// These instructions are produced by `generate_msl_from_parsed_dxil()` in
    /// `shader.rs` and consumed by each stage-specific generator (compute,
    /// geometry, hull, domain) to emit real MSL bodies instead of skeleton
    /// templates.
    pub fn set_instructions(&mut self, instructions: Vec<TranslatedInstruction>) {
        self.instructions = instructions;
    }

    /// Set the threadgroup size for compute shaders.
    ///
    /// This controls the `[[threads_per_threadgroup(N, M, O)]]` attribute on
    /// the generated compute kernel.
    pub fn set_threadgroup_size(&mut self, x: u32, y: u32, z: u32) {
        self.threadgroup_size = (x.max(1), y.max(1), z.max(1));
    }

    /// Set whether the shader accesses UAV resources.
    ///
    /// When true, UAV buffers are mapped to `device` address space in the
    /// generated MSL kernel signature.
    pub fn set_has_uav(&mut self, has_uav: bool) {
        self.has_uav = has_uav;
    }

    /// Set whether the shader uses groupshared (threadgroup) memory.
    ///
    /// When true, the generator will emit `threadgroup` variable declarations.
    pub fn set_has_group_memory(&mut self, has_group_memory: bool) {
        self.has_group_memory = has_group_memory;
    }

    // -----------------------------------------------------------------------
    // Geometry shader configuration
    // -----------------------------------------------------------------------

    /// Set the input primitive type for geometry shader emulation.
    pub fn set_input_primitive(&mut self, prim: InputPrimitive) {
        self.input_primitive = Some(prim);
    }

    /// Set the output primitive type for geometry shader emulation.
    pub fn set_output_primitive(&mut self, prim: OutputPrimitive) {
        self.output_primitive = Some(prim);
    }

    /// Set the maximum number of vertices the geometry shader can emit.
    pub fn set_max_vertex_count(&mut self, count: u32) {
        self.max_vertex_count = count;
    }

    // -----------------------------------------------------------------------
    // Tessellation configuration (hull / domain shaders)
    // -----------------------------------------------------------------------

    /// Set the patch type for tessellation.
    pub fn set_patch_type(&mut self, pt: PatchType) {
        self.patch_type = Some(pt);
    }

    /// Set the partition mode for tessellation factor computation.
    pub fn set_partition_mode(&mut self, pm: PartitionMode) {
        self.partition_mode = Some(pm);
    }

    /// Set the output topology for tessellated patches.
    pub fn set_output_topology(&mut self, top: OutputTopology) {
        self.output_topology = Some(top);
    }

    /// Generate the complete MSL source code.
    pub fn generate(&self) -> String {
        let mut source = String::new();

        // Header
        source.push_str("#include <metal_stdlib>\n");
        source.push_str("using namespace metal;\n\n");

        // Constant buffer structs
        for cb in &self.constant_buffers {
            source.push_str(&format!("struct {}_t {{\n", sanitize_name(&cb.name)));
            if cb.fields.is_empty() {
                // Generate a generic packed struct of the right size
                let num_floats = cb.size / 16;
                for i in 0..num_floats.max(1) {
                    source.push_str(&format!("    float4 _field_{};\n", i));
                }
            } else {
                for (name, typ) in &cb.fields {
                    source.push_str(&format!(
                        "    {} {};\n",
                        hlsl_type_to_msl(typ),
                        sanitize_name(name)
                    ));
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
                let attr = if self.stage == ShaderStage::Vs {
                    semantic_to_msl_vertex_input_attribute(&input.semantic, input.semantic_index)
                } else {
                    semantic_to_msl_attribute(&input.semantic, input.semantic_index)
                };
                source.push_str(&format!(
                    "    {} {} {};\n",
                    msl_type,
                    sanitize_name(&input.name),
                    attr
                ));
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
                source.push_str(&format!(
                    "    {} {} {};\n",
                    msl_type,
                    sanitize_name(&output.name),
                    attr
                ));
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

        // Add the input assembly stage-in (only when inputs are declared)
        if !self.inputs.is_empty() {
            source.push_str(", VertexInput in [[stage_in]]");
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
        source.push_str("    VertexOutput out;\n");

        // Pass through inputs to outputs (per semantic) or zero-fill
        self.emit_output_init(source);

        // Emit translated DXIL instruction body
        self.emit_instruction_body(source);

        source.push_str("    return out;\n");
        source.push_str("}\n");
    }

    fn generate_fragment_entry(&self, source: &mut String) {
        let has_outputs = !self.outputs.is_empty();
        let return_type = if has_outputs {
            "FragmentOutput"
        } else {
            "void"
        };

        source.push_str(&format!("fragment {} {}(", return_type, self.entry_point));

        // Add vertex output as input (only when inputs are present)
        if !self.inputs.is_empty() {
            source.push_str("FragmentInput in [[stage_in]]");
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

        if has_outputs {
            source.push_str("    FragmentOutput out;\n");

            // Pass through inputs to outputs (per semantic) or zero-fill
            self.emit_output_init(source);
        }

        // Emit translated DXIL instruction body
        self.emit_instruction_body(source);

        if has_outputs {
            source.push_str("    return out;\n");
        }
        source.push_str("}\n");
    }

    /// Initialize each declared output member: pass through the matching
    /// stage input (same semantic + index) where one exists, otherwise
    /// zero-fill so every output is written at least once.
    fn emit_output_init(&self, source: &mut String) {
        for output in &self.outputs {
            if let Some(input) = self.inputs.iter().find(|i| {
                i.semantic.eq_ignore_ascii_case(&output.semantic)
                    && i.semantic_index == output.semantic_index
            }) {
                source.push_str(&format!(
                    "    out.{} = in.{};\n",
                    sanitize_name(&output.name),
                    sanitize_name(&input.name)
                ));
            } else {
                let msl_type = hlsl_type_to_msl(&output.hlsl_type);
                source.push_str(&format!(
                    "    out.{} = {}(0);\n",
                    sanitize_name(&output.name),
                    msl_type
                ));
            }
        }
    }

    /// Emit the body of translated DXIL instructions into the entry point.
    ///
    /// Iterates over `self.instructions` and emits each instruction's MSL body
    /// as a properly-indented source line. Barriers are mapped to Metal
    /// `threadgroup_barrier` calls. UAV accesses are annotated.
    fn emit_instruction_body(&self, source: &mut String) {
        if self.instructions.is_empty() {
            source.push_str("    // (no translated instructions)\n");
            return;
        }

        // Check if any instructions are barriers to consolidate them
        let has_barriers = self.instructions.iter().any(|i| i.is_barrier);

        for instr in &self.instructions {
            if instr.is_barrier {
                // Map DXIL barriers to MSL threadgroup_barrier
                let flags = if instr.barrier_flags.is_empty() {
                    "mem_flags::mem_threadgroup".to_string()
                } else {
                    instr.barrier_flags.join(" | ")
                };
                source.push_str(&format!("    threadgroup_barrier({});\n", flags));
            } else if instr.is_uav_access {
                // Annotate UAV accesses with device address space hint
                source.push_str(&format!("    // UAV access: {}\n", instr.msl_body));
            } else {
                // Regular instruction body
                source.push_str(&format!("    {}\n", instr.msl_body));
            }
        }

        // Add a final barrier for any shader that has barriers (ensures
        // all threads have completed before proceeding past the kernel).
        if has_barriers {
            source.push_str(
                "    threadgroup_barrier(mem_flags::mem_threadgroup | mem_flags::mem_device);\n",
            );
        }
    }

    // -----------------------------------------------------------------------
    // Compute shader (Cs) entry point — G4
    // -----------------------------------------------------------------------

    fn generate_compute_entry(&self, source: &mut String) {
        let (tgx, tgy, tgz) = self.threadgroup_size;

        // Kernel function signature with thread position in grid
        source.push_str(&format!(
            "kernel void {}(uint3 gid [[thread_position_in_grid]]",
            self.entry_point
        ));

        // Add threadgroup position attributes for compute
        source.push_str(", uint3 gtid [[thread_position_in_threadgroup]]");
        source.push_str(", uint3 tgid [[threadgroup_position_in_grid]]");

        // Add constant buffer arguments (device address space for CBs in compute)
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

        // Add sampler arguments
        for samp in &self.samplers {
            source.push_str(&format!(
                ", sampler {} [[sampler({})]]",
                sanitize_name(&samp.name),
                samp.register
            ));
        }

        // Close signature, add threads_per_threadgroup attribute
        source.push_str(&format!(
            ") [[threads_per_threadgroup({}, {}, {})]] {{\n",
            tgx, tgy, tgz
        ));

        // ---- Threadgroup (groupshared) memory declarations ----
        if self.has_group_memory {
            source.push_str("    // Groupshared (threadgroup) memory\n");
            source.push_str("    threadgroup float4 _tg_shared[256];\n");
            source.push_str("    threadgroup float _tg_temp[64];\n\n");
        }

        // ---- UAV device address space mapping ----
        if self.has_uav {
            source.push_str("    // UAV resources are mapped via device address space buffers\n");
        }

        // Emit translated DXIL instruction body
        self.emit_instruction_body(source);

        source.push_str("}\n");
    }

    // -----------------------------------------------------------------------
    // Geometry shader (Gs) entry point — G5
    // -----------------------------------------------------------------------

    fn generate_geometry_entry(&self, source: &mut String) {
        // Geometry shaders are translated to compute in Metal.
        // Each thread in the grid processes one input primitive and emits
        // vertices to a stream output buffer.
        let input_prim = self.input_primitive.unwrap_or(InputPrimitive::Triangle);
        let _output_prim = self
            .output_primitive
            .unwrap_or(OutputPrimitive::TriangleStrip);
        let max_vtx = self.max_vertex_count.max(1);
        let input_verts = input_prim.vertex_count();

        source.push_str(&format!("kernel void {}_gs(\n", self.entry_point));

        // Input vertex buffer (the vertex data from the vertex shader)
        source.push_str("    device const float4* _gs_input_vertices [[buffer(0)]],\n");
        source.push_str("    constant uint& _gs_vertex_count [[buffer(1)]],\n");

        // Stream output buffer for emitted vertices
        source.push_str("    device float4* _gs_stream [[buffer(2)]],\n");

        // Primitive count (atomic counter for stream output)
        source.push_str("    device atomic_uint* _gs_prim_count [[buffer(3)]],\n");
        source.push_str("    uint3 gid [[thread_position_in_grid]]\n");
        source.push_str(") {\n");

        // Declare per-invocation vertex attribute storage
        source.push_str("    // Per-invocation geometry shader vertex attributes\n");
        source.push_str("    float4 _gs_position = float4(0.0, 0.0, 0.0, 1.0);\n");
        source.push_str("    float3 _gs_normal = float3(0.0, 1.0, 0.0);\n");
        source.push_str("    float2 _gs_texcoord = float2(0.0, 0.0);\n\n");

        // Load input primitive vertices
        source.push_str("    // Load input primitive vertices\n");
        source.push_str("    uint _gs_prim_id = gid.x;\n");
        let has_barriers = self.instructions.iter().any(|i| i.is_barrier);
        if has_barriers {
            // If the translated body contains barriers, every thread must reach
            // them: out-of-range invocations are clamped to the last valid
            // primitive instead of returning early (a barrier reached by only
            // some threads is undefined behaviour in Metal and can hang the GPU).
            source.push_str(&format!(
                "    uint _gs_base = (_gs_vertex_count >= {}) ? min(_gs_prim_id * {}, _gs_vertex_count - {}) : 0;\n",
                input_verts, input_verts, input_verts
            ));
            source.push_str(
                "    // NOTE: body contains barriers, so out-of-range threads are clamped, not returned.\n",
            );
        } else {
            source.push_str(&format!(
                "    uint _gs_base = _gs_prim_id * {};\n",
                input_verts
            ));
            source.push_str(&format!(
                "    if (_gs_base + {} > _gs_vertex_count) return;\n\n",
                input_verts
            ));
        }
        source.push_str(&format!(
            "    bool _gs_ok = (_gs_base + {} <= _gs_vertex_count);\n\n",
            input_verts
        ));

        // Emit translated DXIL instruction body (contains EmitVertex/CutStream calls)
        self.emit_instruction_body(source);

        // Default: if no EmitVertex was called, emit a default vertex
        source.push_str("\n    // Default emit if no EmitVertex was called\n");
        source.push_str("    if (_gs_ok) {\n");
        source.push_str("        uint _gs_out_idx = atomic_fetch_add_explicit(\n");
        source.push_str("            _gs_prim_count, 1u, memory_order_relaxed);\n");
        source.push_str("        if (_gs_out_idx < ");
        source.push_str(&max_vtx.to_string());
        source.push_str(") {\n");
        source.push_str("            device float4* _gs_out = _gs_stream + _gs_out_idx * 3;\n");
        source.push_str("            _gs_out[0] = _gs_position;\n");
        source.push_str("            _gs_out[1] = float4(_gs_normal, 0.0);\n");
        source.push_str("            _gs_out[2] = float4(_gs_texcoord, 0.0, 0.0);\n");
        source.push_str("        }\n");
        source.push_str("    }\n");

        source.push_str("}\n");
    }

    // -----------------------------------------------------------------------
    // Hull shader (Hs) entry point — G5
    // -----------------------------------------------------------------------

    fn generate_hull_entry(&self, source: &mut String) {
        // Hull shaders use Metal tessellation via compute kernel.
        // Each thread processes one output control point.
        let cp = self.patch_control_points.max(1);
        let patch = self.patch_type.unwrap_or(PatchType::Triangle);
        let partition = self.partition_mode.unwrap_or(PartitionMode::Integer);
        let _topology = self.output_topology.unwrap_or(OutputTopology::TriangleCCW);

        source.push_str(&format!("kernel void {}_hs(\n", self.entry_point));

        // Input control point buffer (from previous stage or fixed function)
        source.push_str("    device const float4* _hs_input_cp [[buffer(0)]],\n");

        // Output control point buffer
        source.push_str("    device float4* _hs_output [[buffer(1)]],\n");

        // Tessellation factor buffer (edge and inside factors)
        source.push_str("    device float* _hs_tess_factors [[buffer(2)]],\n");

        // Number of control points
        source.push_str("    constant uint& _hs_num_control_points [[buffer(3)]],\n");

        // Other binding resources (constant buffers, textures)
        for cb in &self.constant_buffers {
            source.push_str(&format!(
                "    device {}_t* {} [[buffer({})]],\n",
                sanitize_name(&cb.name),
                sanitize_name(&cb.name),
                cb.register.saturating_add(4)
            ));
        }
        for tex in &self.textures {
            let access = if tex.is_writeable { "write" } else { "read" };
            source.push_str(&format!(
                "    texture{}d<float, access::{}> {} [[texture({})]],\n",
                tex.dimensions,
                access,
                sanitize_name(&tex.name),
                tex.register
            ));
        }

        source.push_str("    uint3 gid [[thread_position_in_grid]]\n");
        source.push_str(") {\n");

        // Control point index. If the translated body contains barriers, all
        // threads must reach them, so out-of-range invocations are clamped
        // instead of returning early (divergent barriers are UB in Metal).
        let has_barriers = self.instructions.iter().any(|i| i.is_barrier);
        if has_barriers {
            source.push_str(&format!(
                "    uint _hs_cp_id = min(gid.x, {} - 1); // control point index (clamped)\n",
                cp
            ));
            source.push_str(
                "    // NOTE: body contains barriers, so out-of-range threads are clamped, not returned.\n\n",
            );
        } else {
            source.push_str("    uint _hs_cp_id = gid.x; // control point index\n");
            source.push_str(&format!("    if (_hs_cp_id >= {}) return;\n\n", cp));
        }

        // ---- Tessellation factor computation (only thread 0) ----
        source.push_str("    // Compute tessellation factors (thread 0 only)\n");
        source.push_str("    if (_hs_cp_id == 0) {\n");

        // Generate appropriate tess factor code based on patch type and partition
        let tess_factor_count = match patch {
            PatchType::Triangle => 4, // 3 edge + 1 inside
            PatchType::Quad => 6,     // 4 edge + 2 inside
            PatchType::Isoline => 2,  // 2 for isoline
        };
        let partition_fn = match partition {
            PartitionMode::Integer => "",
            PartitionMode::FractionalEven => "// fractional_even partitioning: round to even\n",
            PartitionMode::FractionalOdd => "// fractional_odd partitioning: round to odd\n",
            PartitionMode::Pow2 => "// pow2 partitioning: round to power of 2\n",
        };
        source.push_str(&format!(
            "        {}// Edge tessellation factors\n",
            partition_fn
        ));
        for i in 0..tess_factor_count.min(4) {
            // Metal stores the triangle inside factor at index 3.
            let label = if patch == PatchType::Triangle && i == 3 {
                "inside factor (placeholder)".to_string()
            } else {
                format!("edge factor {} (placeholder)", i)
            };
            source.push_str(&format!(
                "        _hs_tess_factors[{}] = 1.0; // {}\n",
                i, label
            ));
        }
        if tess_factor_count > 4 {
            source
                .push_str("        _hs_tess_factors[4] = 1.0; // inside factor 0 (placeholder)\n");
            source
                .push_str("        _hs_tess_factors[5] = 1.0; // inside factor 1 (placeholder)\n");
        }
        source.push_str("    }\n\n");

        // Emit translated DXIL instruction body (control point computation)
        self.emit_instruction_body(source);

        // Default control point write
        source.push_str("\n    // Default: write output control point\n");
        source.push_str("    _hs_output[_hs_cp_id] = _hs_input_cp[_hs_cp_id];\n");
        source.push_str("}\n");
    }

    // -----------------------------------------------------------------------
    // Domain shader (Ds) entry point — G5
    // -----------------------------------------------------------------------

    fn generate_domain_entry(&self, source: &mut String) {
        // Domain shaders use Metal tessellation via compute kernel.
        // Each thread processes one tessellated vertex.
        let cp = self.patch_control_points.max(1);
        let patch = self.patch_type.unwrap_or(PatchType::Triangle);

        source.push_str(&format!("kernel void {}_ds(\n", self.entry_point));

        // Tessellated vertex buffer (from fixed-function tessellator).
        // NOTE: not `const` — the generated body writes the tessellated
        // position back into this buffer, and MSL rejects writes through a
        // const-qualified pointer.
        source.push_str("    device float4* _ds_tessellated_vertices [[buffer(0)]],\n");

        // Control point buffer (written by hull shader)
        source.push_str("    device const float4* _ds_control_points [[buffer(1)]],\n");

        // Tessellation factor buffer
        source.push_str("    device const float* _ds_tess_factors [[buffer(2)]],\n");

        // Number of control points
        source.push_str("    constant uint& _ds_num_control_points [[buffer(3)]],\n");

        // Other binding resources
        for cb in &self.constant_buffers {
            source.push_str(&format!(
                "    device {}_t* {} [[buffer({})]],\n",
                sanitize_name(&cb.name),
                sanitize_name(&cb.name),
                cb.register.saturating_add(4)
            ));
        }
        for tex in &self.textures {
            let access = if tex.is_writeable { "write" } else { "read" };
            source.push_str(&format!(
                "    texture{}d<float, access::{}> {} [[texture({})]],\n",
                tex.dimensions,
                access,
                sanitize_name(&tex.name),
                tex.register
            ));
        }

        source.push_str("    uint3 gid [[thread_position_in_grid]]\n");
        source.push_str(") {\n");

        source.push_str("    uint _ds_vert_id = gid.x;\n\n");

        // ---- Barycentric coordinate interpolation ----
        // For triangle patches, generate barycentric (u, v, w) from tessellated vertex.
        // For quad patches, generate (u, v) UV coordinates.
        match patch {
            PatchType::Triangle => {
                source.push_str("    // Barycentric coordinates for triangle patch\n");
                source.push_str("    float _ds_u = _ds_tessellated_vertices[_ds_vert_id].x;\n");
                source.push_str("    float _ds_v = _ds_tessellated_vertices[_ds_vert_id].y;\n");
                source.push_str("    float _ds_w = 1.0 - _ds_u - _ds_v;\n");
                source.push_str("    float2 _ds_uv = float2(_ds_u, _ds_v);\n\n");
            }
            PatchType::Quad => {
                source.push_str("    // UV coordinates for quad patch\n");
                source
                    .push_str("    float2 _ds_uv = _ds_tessellated_vertices[_ds_vert_id].xy;\n\n");
            }
            PatchType::Isoline => {
                source.push_str("    // Isoline parameter (u along line)\n");
                source.push_str("    float _ds_u = _ds_tessellated_vertices[_ds_vert_id].x;\n");
                source.push_str("    float2 _ds_uv = float2(_ds_u, 0.0);\n\n");
            }
        }

        // Sample control points
        source.push_str(&format!("    // Sample {} control points\n", cp));
        source.push_str(&format!("    float4 _ds_cp[{}];\n", cp));
        source.push_str(&format!(
            "    for (uint _ds_i = 0; _ds_i < {}; _ds_i++) {{\n",
            cp
        ));
        source.push_str("        _ds_cp[_ds_i] = _ds_control_points[_ds_i];\n");
        source.push_str("    }\n\n");

        // ---- Position computation from tessellated coordinates ----
        source
            .push_str("    // Compute tessellated position from control points and barycentrics\n");
        source.push_str("    float4 _ds_position = float4(0.0, 0.0, 0.0, 1.0);\n");
        match patch {
            PatchType::Triangle => {
                source.push_str(&format!(
                    "    for (uint _ds_j = 0; _ds_j < {}; _ds_j++) {{\n",
                    cp
                ));
                source.push_str("        float _ds_weight = (_ds_j == 0) ? _ds_u : ((_ds_j == 1) ? _ds_v : _ds_w);\n");
                source.push_str("        _ds_position += _ds_weight * _ds_cp[_ds_j];\n");
                source.push_str("    }\n\n");
            }
            PatchType::Quad => {
                source.push_str("    // Bilinear interpolation for quad patches\n");
                source.push_str("    float2 _ds_st = _ds_uv;\n");
                source.push_str(&format!(
                    "    // For {} control points, perform bilinear interpolation\n",
                    cp
                ));
                source.push_str("    float4 _ds_top = mix(_ds_cp[0], _ds_cp[1], _ds_st.x);\n");
                source.push_str("    float4 _ds_bot = mix(_ds_cp[2], _ds_cp[3], _ds_st.x);\n");
                source.push_str("    _ds_position = mix(_ds_top, _ds_bot, _ds_st.y);\n\n");
            }
            PatchType::Isoline => {
                source.push_str("    // Linear interpolation along isoline\n");
                source.push_str("    _ds_position = mix(_ds_cp[0], _ds_cp[1], _ds_u);\n\n");
            }
        }

        // Emit translated DXIL instruction body
        self.emit_instruction_body(source);

        // Write output position
        source.push_str("    // Output tessellated vertex position\n");
        source.push_str("    _ds_tessellated_vertices[_ds_vert_id] = _ds_position;\n");
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
            AppError::new(
                ReasonCode::RcIo,
                format!("cannot create shader cache dir: {e}"),
            )
        })?;
        Ok(Self { cache_dir })
    }

    /// Look up a compiled shader by hash.
    pub fn get(&self, hash: &str) -> AppResult<Option<Vec<u8>>> {
        if !is_valid_cache_hash(hash) {
            return Ok(None);
        }
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
        if !is_valid_cache_hash(hash) {
            return Err(invalid_cache_hash_error(hash));
        }
        let path = self.cache_path(hash);
        fs::write(&path, data)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("cannot write shader cache: {e}")))
    }

    /// Look up generated MSL source by hash.
    pub fn get_source(&self, hash: &str) -> AppResult<Option<String>> {
        if !is_valid_cache_hash(hash) {
            return Ok(None);
        }
        let path = self.cache_dir.join(format!("{hash}.msl"));
        if path.exists() {
            let source = fs::read_to_string(&path).map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("cannot read MSL source cache: {e}"),
                )
            })?;
            Ok(Some(source))
        } else {
            Ok(None)
        }
    }

    /// Store generated MSL source in the cache.
    pub fn put_source(&self, hash: &str, source: &str) -> AppResult<()> {
        if !is_valid_cache_hash(hash) {
            return Err(invalid_cache_hash_error(hash));
        }
        let path = self.cache_dir.join(format!("{hash}.msl"));
        fs::write(&path, source).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("cannot write MSL source cache: {e}"),
            )
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

/// Cache hashes are caller-supplied strings, so reject anything that is not a
/// plain (lowercase) hex digest before joining it onto the cache directory:
/// a hash containing `/` or `..` must not escape the cache directory.
fn is_valid_cache_hash(hash: &str) -> bool {
    !hash.is_empty() && hash.len() <= 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

fn invalid_cache_hash_error(hash: &str) -> AppError {
    AppError::new(
        ReasonCode::RcIo,
        format!("invalid shader cache hash: {hash:?} (must be hex)"),
    )
}

// ---------------------------------------------------------------------------
// HLSL intrinsic translation
// ---------------------------------------------------------------------------

/// Translate common HLSL intrinsic functions to MSL equivalents.
pub fn translate_hlsl_intrinsic(name: &str) -> String {
    match name {
        // --- Math intrinsics ---
        // HLSL `mul(a, b)` is matrix/vector multiplication, which MSL performs
        // with the plain `*` operator (MSL has no mul() function).
        "mul" => "*".to_string(),
        "dot" => "dot".to_string(),
        "cross" => "cross".to_string(),
        "normalize" => "normalize".to_string(),
        "length" => "length".to_string(),
        "distance" => "distance".to_string(),
        "reflect" => "reflect".to_string(),
        "refract" => "refract".to_string(),
        "lerp" => "mix".to_string(),
        "clamp" => "clamp".to_string(),
        "saturate" => "saturate".to_string(),
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
        "rcp" => "recip".to_string(),
        "mad" => "fma".to_string(),
        "pow" => "pow".to_string(),
        "exp" => "exp".to_string(),
        "exp2" => "exp2".to_string(),
        "log" => "log".to_string(),
        "log2" => "log2".to_string(),
        "log10" => "log10".to_string(),
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

        // --- Bit manipulation intrinsics ---
        "asfloat" => "as_type<float>".to_string(),
        "asint" => "as_type<int>".to_string(),
        "asuint" => "as_type<uint>".to_string(),
        "reversebits" => "reverse_bits".to_string(),
        "countbits" => "popcount".to_string(),
        "firstbithigh" => "// firstbithigh = (clz(x)==32) ? -1 : (31-(int)clz(x))".to_string(),
        "firstbitlow" => "// firstbitlow = (ctz(x)==32) ? -1 : (int)ctz(x)".to_string(),

        // --- Texture/sample intrinsics ---
        "tex2D" | "tex2Dlod" | "tex2Dgrad" | "tex2Dbias" | "Sample" | "SampleLevel"
        | "SampleGrad" | "SampleBias" => "sample".to_string(),
        "Load" => "read".to_string(),
        "Store" => "write".to_string(),
        "CalculateLevelOfDetail" => "calculate_lod".to_string(),
        "CalculateLevelOfDetailUnclamped" => "calculate_lod".to_string(),

        // --- Derivative intrinsics ---
        "ddx" => "dfdx".to_string(),
        "ddx_coarse" => "dfdx_coarse".to_string(),
        "ddx_fine" => "dfdx_fine".to_string(),
        "ddy" => "dfdy".to_string(),
        "ddy_coarse" => "dfdy_coarse".to_string(),
        "ddy_fine" => "dfdy_fine".to_string(),
        "fwidth" => "fwidth".to_string(),

        // --- Comparison/selection intrinsics ---
        "any" => "any".to_string(),
        "all" => "all".to_string(),
        "select" => "select".to_string(),
        "step" => "step".to_string(),
        "smoothstep" => "smoothstep".to_string(),

        // --- Matrix intrinsics ---
        "transpose" => "transpose".to_string(),
        "determinant" => "matrix_determinant".to_string(),
        "inverse" => "matrix_invert".to_string(),

        // --- Atomic (Interlocked) intrinsics ---
        "InterlockedAdd" => "atomic_fetch_add_explicit".to_string(),
        "InterlockedAnd" => "atomic_fetch_and_explicit".to_string(),
        "InterlockedOr" => "atomic_fetch_or_explicit".to_string(),
        "InterlockedXor" => "atomic_fetch_xor_explicit".to_string(),
        "InterlockedMin" => "atomic_fetch_min_explicit".to_string(),
        "InterlockedMax" => "atomic_fetch_max_explicit".to_string(),
        "InterlockedExchange" => "atomic_exchange".to_string(),
        "InterlockedCompareExchange" => "atomic_compare_exchange_weak_explicit".to_string(),
        "InterlockedCompareStore" => {
            "// InterlockedCompareStore -> atomic_compare_exchange_weak_explicit (void)".to_string()
        }

        // --- Wave/SIMD intrinsics ---
        "WaveReadLaneFirst" => "simd_broadcast_first".to_string(),
        "WaveReadLaneAt" => "simd_broadcast".to_string(),
        "WaveActiveAllTrue" => "simd_all".to_string(),
        "WaveActiveAnyTrue" => "simd_any".to_string(),
        "WaveActiveAllEqual" => "simd_all".to_string(), // compare then simd_all
        "WaveActiveBallot" => "simd_ballot".to_string(),
        "WaveGetLaneIndex" => "simd_lane_id".to_string(),
        "WaveGetLaneCount" => "simd_lane_count".to_string(),
        "WaveActiveSum" => "simd_sum".to_string(),
        "WaveActiveProduct" => "simd_product".to_string(),
        "WaveActiveMin" => "simd_min".to_string(),
        "WaveActiveMax" => "simd_max".to_string(),
        "WaveActiveBitAnd" => "simd_and".to_string(),
        "WaveActiveBitOr" => "simd_or".to_string(),
        "WaveActiveBitXor" => "simd_xor".to_string(),
        "WaveActiveCountBits" => "// popcount(simd_ballot)".to_string(),
        "WaveMultiPrefixSum" => "simd_prefix_exclusive_sum".to_string(),
        "WaveMultiPrefixProduct" => "simd_prefix_exclusive_product".to_string(),
        "WaveMultiPrefixBitAnd" => "simd_prefix_exclusive_and".to_string(),
        "WaveMultiPrefixBitOr" => "simd_prefix_exclusive_or".to_string(),
        "WaveMultiPrefixBitXor" => "simd_prefix_exclusive_xor".to_string(),
        "WaveMultiPrefixCountBits" => "// popcount(simd_prefix_exclusive_or)".to_string(),
        "WaveMatch" => "// WaveMatch emulated via simd_vote".to_string(),
        "QuadReadLaneAt" => "quad_broadcast".to_string(),

        // --- Tessellation intrinsics ---
        "Process2DQuadTessFactorsAvg" => "// Process2DQuadTessFactorsAvg".to_string(),
        "Process2DQuadTessFactorsMax" => "// Process2DQuadTessFactorsMax".to_string(),
        "Process2DQuadTessFactorsMin" => "// Process2DQuadTessFactorsMin".to_string(),
        "ProcessTriTessFactorsAvg" => "// ProcessTriTessFactorsAvg".to_string(),
        "ProcessTriTessFactorsMax" => "// ProcessTriTessFactorsMax".to_string(),
        "ProcessTriTessFactorsMin" => "// ProcessTriTessFactorsMin".to_string(),

        // --- Attribute evaluation intrinsics ---
        "EvaluateAttributeAtCentroid" => "// EvaluateAttributeAtCentroid".to_string(),
        "EvaluateAttributeAtSample" => "// EvaluateAttributeAtSample".to_string(),
        "EvaluateAttributeAtConstant" => "// EvaluateAttributeAtConstant".to_string(),

        // --- Resource query intrinsics ---
        "CheckAccessFullyMapped" => "1".to_string(),

        // --- Barrier / sync intrinsics ---
        "AllMemoryBarrier" => {
            "threadgroup_barrier(mem_flags::mem_threadgroup | mem_flags::mem_device)".to_string()
        }
        "AllMemoryBarrierWithGroupSync" => {
            "threadgroup_barrier(mem_flags::mem_threadgroup | mem_flags::mem_device)".to_string()
        }
        "DeviceMemoryBarrier" => "threadgroup_barrier(mem_flags::mem_device)".to_string(),
        "DeviceMemoryBarrierWithGroupSync" => {
            "threadgroup_barrier(mem_flags::mem_device)".to_string()
        }
        "GroupMemoryBarrier" => "threadgroup_barrier(mem_flags::mem_threadgroup)".to_string(),
        "GroupMemoryBarrierWithGroupSync" => {
            "threadgroup_barrier(mem_flags::mem_threadgroup)".to_string()
        }

        // --- Utility ---
        "abort" => "abort".to_string(),
        "printf" => "// printf".to_string(),

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
    if result
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        result = format!("_{result}");
    }
    result
}

/// Compute a SHA-256 hash of DXIL bytes for cache lookup.
///
/// Uses SHA-256 instead of DefaultHasher for deterministic, collision-resistant
/// content addressing across process restarts.
pub fn dxil_hash(dxil: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(dxil);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Basic structural tests (vertex, fragment)
    // -----------------------------------------------------------------------

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
    fn vertex_shader_wires_stage_in_and_instructions() {
        let mut generator = MslShaderGenerator::new(ShaderStage::Vs, "vs_main");
        generator.add_input("position", "SV_POSITION", 0, "float4");
        generator.add_input("uv", "TEXCOORD", 0, "float2");
        generator.add_output("sv_position", "SV_POSITION", 0, "float4");
        generator.add_output("uv", "TEXCOORD", 0, "float2");
        generator.add_output("unused", "TEXCOORD", 1, "float3");
        generator.set_instructions(vec![TranslatedInstruction {
            msl_body: "_t0 = in.position;".to_string(),
            dst: "_t0".to_string(),
            operands: vec!["in.position".to_string()],
            is_barrier: false,
            barrier_flags: Vec::new(),
            is_uav_access: false,
            address_space: String::new(),
            is_threadgroup_mem: false,
        }]);

        let source = generator.generate();
        assert!(source.contains("VertexInput in [[stage_in]]"));
        assert!(source.contains("out.sv_position = in.position;"));
        assert!(source.contains("out.uv = in.uv;"));
        assert!(source.contains("out.unused = float3(0);"));
        assert!(source.contains("_t0 = in.position;"));
        // SV_POSITION as a vertex *input* must not use [[position]] (output-only).
        assert!(!source.contains("float4 position [[position]]"));
        assert!(source.contains("float4 position [[user(sv_position_0)]]"));
    }

    #[test]
    fn fragment_shader_wires_stage_in_and_instructions() {
        let mut generator = MslShaderGenerator::new(ShaderStage::Ps, "ps_main");
        generator.add_input("uv", "TEXCOORD", 0, "float2");
        generator.add_output("uv_out", "TEXCOORD", 0, "float2");
        generator.set_instructions(vec![TranslatedInstruction {
            msl_body: "_c = in.uv;".to_string(),
            dst: "_c".to_string(),
            operands: vec!["in.uv".to_string()],
            is_barrier: false,
            barrier_flags: Vec::new(),
            is_uav_access: false,
            address_space: String::new(),
            is_threadgroup_mem: false,
        }]);

        let source = generator.generate();
        assert!(source.contains("FragmentInput in [[stage_in]]"));
        assert!(source.contains("out.uv_out = in.uv;"));
        assert!(source.contains("_c = in.uv;"));
    }

    #[test]
    fn tessellation_semantics_map_to_matching_metal_patch_attributes() {
        assert_eq!(
            semantic_to_msl_attribute("SV_TESSFACTOR", 0),
            "[[patch(tess_level_outer)]]"
        );
        assert_eq!(
            semantic_to_msl_attribute("SV_INSIDETESSFACTOR", 0),
            "[[patch(tess_level_inner)]]"
        );
    }

    // -----------------------------------------------------------------------
    // Compute shader tests (G4)
    // -----------------------------------------------------------------------

    #[test]
    fn msl_generator_creates_compute_shader() {
        let mut generator = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        generator.add_constant_buffer("Params", 0, 0, 32);
        generator.add_texture("output", 0, 0, true, 2);

        let source = generator.generate();
        assert!(source.contains("kernel void cs_main"));
        assert!(source.contains("thread_position_in_grid"));
        assert!(source.contains("thread_position_in_threadgroup"));
        assert!(source.contains("threadgroup_position_in_grid"));
        assert!(source.contains("threads_per_threadgroup"));
        assert!(source.contains("access::write"));
    }

    #[test]
    fn compute_shader_has_threadgroup_size_attribute() {
        let mut g = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        g.set_threadgroup_size(16, 8, 1);
        let source = g.generate();
        assert!(source.contains("threads_per_threadgroup(16, 8, 1)"));
    }

    #[test]
    fn compute_shader_with_instructions_inlines_body() {
        let mut g = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        g.set_instructions(vec![
            TranslatedInstruction {
                msl_body: "_t0 = _t1 + _t2;".to_string(),
                dst: "_t0".to_string(),
                operands: vec!["_t1".to_string(), "_t2".to_string()],
                is_barrier: false,
                barrier_flags: Vec::new(),
                is_uav_access: false,
                address_space: String::new(),
                is_threadgroup_mem: false,
            },
            TranslatedInstruction {
                msl_body: "_t3 = _t0 * 2.0;".to_string(),
                dst: "_t3".to_string(),
                operands: vec!["_t0".to_string(), "2.0".to_string()],
                is_barrier: false,
                barrier_flags: Vec::new(),
                is_uav_access: false,
                address_space: String::new(),
                is_threadgroup_mem: false,
            },
        ]);
        let source = g.generate();
        assert!(source.contains("_t0 = _t1 + _t2;"));
        assert!(source.contains("_t3 = _t0 * 2.0;"));
    }

    #[test]
    fn compute_shader_with_barriers_maps_correctly() {
        let mut g = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        g.set_instructions(vec![TranslatedInstruction {
            msl_body: String::new(),
            dst: String::new(),
            operands: Vec::new(),
            is_barrier: true,
            barrier_flags: vec!["mem_flags::mem_threadgroup".to_string()],
            is_uav_access: false,
            address_space: String::new(),
            is_threadgroup_mem: false,
        }]);
        let source = g.generate();
        assert!(source.contains("threadgroup_barrier(mem_flags::mem_threadgroup)"));
    }

    #[test]
    fn compute_shader_with_all_memory_barrier() {
        let mut g = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        g.set_instructions(vec![TranslatedInstruction {
            msl_body: String::new(),
            dst: String::new(),
            operands: Vec::new(),
            is_barrier: true,
            barrier_flags: vec![
                "mem_flags::mem_threadgroup".to_string(),
                "mem_flags::mem_device".to_string(),
            ],
            is_uav_access: false,
            address_space: String::new(),
            is_threadgroup_mem: false,
        }]);
        let source = g.generate();
        assert!(source.contains("mem_flags::mem_threadgroup | mem_flags::mem_device"));
    }

    #[test]
    fn compute_shader_with_threadgroup_memory_declares_tg_vars() {
        let mut g = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        g.set_has_group_memory(true);
        let source = g.generate();
        assert!(source.contains("threadgroup float4 _tg_shared[256];"));
        assert!(source.contains("threadgroup float _tg_temp[64];"));
    }

    #[test]
    fn compute_shader_with_uav_adds_device_annotation() {
        let mut g = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        g.set_has_uav(true);
        let source = g.generate();
        assert!(source.contains("UAV resources are mapped via device"));
    }

    // -----------------------------------------------------------------------
    // Geometry shader tests (G5)
    // -----------------------------------------------------------------------

    #[test]
    fn msl_generator_geometry_shader_has_stream_output() {
        let mut g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        g.set_max_vertex_count(32);
        let source = g.generate();
        assert!(source.contains("kernel void gs_main_gs"));
        assert!(source.contains("_gs_input_vertices"));
        assert!(source.contains("_gs_stream"));
        assert!(source.contains("_gs_prim_count"));
        assert!(source.contains("_gs_position"));
        assert!(source.contains("_gs_normal"));
        assert!(source.contains("_gs_texcoord"));
    }

    #[test]
    fn geometry_shader_with_input_primitive() {
        let mut g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        g.set_input_primitive(InputPrimitive::Point);
        g.set_max_vertex_count(16);
        let source = g.generate();
        assert!(source.contains("_gs_base = _gs_prim_id * 1"));
    }

    #[test]
    fn geometry_shader_with_line_input() {
        let mut g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        g.set_input_primitive(InputPrimitive::Line);
        g.set_max_vertex_count(16);
        let source = g.generate();
        assert!(source.contains("_gs_base = _gs_prim_id * 2"));
    }

    #[test]
    fn geometry_shader_with_triangle_input() {
        let mut g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        g.set_input_primitive(InputPrimitive::Triangle);
        g.set_max_vertex_count(16);
        let source = g.generate();
        assert!(source.contains("_gs_base = _gs_prim_id * 3"));
    }

    #[test]
    fn geometry_shader_with_instructions_inlines_body() {
        let mut g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        g.set_max_vertex_count(32);
        g.set_instructions(vec![TranslatedInstruction {
            msl_body: "_t0 = _gs_position;".to_string(),
            dst: "_t0".to_string(),
            operands: vec!["_gs_position".to_string()],
            is_barrier: false,
            barrier_flags: Vec::new(),
            is_uav_access: false,
            address_space: String::new(),
            is_threadgroup_mem: false,
        }]);
        let source = g.generate();
        assert!(source.contains("_t0 = _gs_position;"));
    }

    #[test]
    fn geometry_shader_with_barriers_clamps_instead_of_early_return() {
        let mut g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        g.set_max_vertex_count(32);
        g.set_instructions(vec![TranslatedInstruction {
            msl_body: String::new(),
            dst: String::new(),
            operands: Vec::new(),
            is_barrier: true,
            barrier_flags: vec!["mem_flags::mem_threadgroup".to_string()],
            is_uav_access: false,
            address_space: String::new(),
            is_threadgroup_mem: false,
        }]);
        let source = g.generate();
        // No early `return` may appear before the barrier, and the default emit
        // must be guarded by the bounds flag.
        assert!(!source.contains("if (_gs_base + 3 > _gs_vertex_count) return;"));
        assert!(source.contains("min(_gs_prim_id * 3, _gs_vertex_count - 3)"));
        assert!(source.contains("bool _gs_ok"));
        assert!(source.contains("if (_gs_ok) {"));
        // Default emit must write float4-typed values into the float4 stream.
        assert!(source.contains("float4(_gs_normal, 0.0)"));
        assert!(source.contains("float4(_gs_texcoord, 0.0, 0.0)"));
    }

    #[test]
    fn geometry_shader_without_barriers_keeps_early_return() {
        let mut g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        g.set_max_vertex_count(32);
        let source = g.generate();
        assert!(source.contains("if (_gs_base + 3 > _gs_vertex_count) return;"));
    }

    #[test]
    fn hull_shader_triangle_labels_inside_factor() {
        let mut g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        let source = g.generate();
        assert!(source.contains("_hs_tess_factors[3] = 1.0; // inside factor (placeholder)"));
    }

    // -----------------------------------------------------------------------
    // Hull shader tests (G5)
    // -----------------------------------------------------------------------

    #[test]
    fn msl_generator_hull_shader_has_tessellation_buffers() {
        let mut g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        let source = g.generate();
        assert!(source.contains("kernel void hs_main_hs"));
        assert!(source.contains("_hs_input_cp"));
        assert!(source.contains("_hs_output"));
        assert!(source.contains("_hs_tess_factors"));
        assert!(source.contains("_hs_cp_id"));
    }

    #[test]
    fn hull_shader_emits_tess_factors_for_triangle() {
        let mut g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        let source = g.generate();
        assert!(source.contains("edge factor 0"));
        assert!(source.contains("edge factor 1"));
        assert!(source.contains("edge factor 2"));
    }

    #[test]
    fn hull_shader_emits_tess_factors_for_quad() {
        let mut g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        g.set_patch_control_points(4);
        g.set_patch_type(PatchType::Quad);
        let source = g.generate();
        assert!(source.contains("edge factor 0"));
        assert!(source.contains("edge factor 1"));
        assert!(source.contains("edge factor 2"));
        assert!(source.contains("edge factor 3"));
        assert!(source.contains("inside factor 0"));
        assert!(source.contains("inside factor 1"));
    }

    #[test]
    fn hull_shader_partition_mode_integer() {
        let mut g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        g.set_partition_mode(PartitionMode::Integer);
        let source = g.generate();
        // Integer mode: no specific comment prefix
        assert!(source.contains("// Edge tessellation factors"));
    }

    #[test]
    fn hull_shader_partition_mode_fractional_even() {
        let mut g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        g.set_partition_mode(PartitionMode::FractionalEven);
        let source = g.generate();
        assert!(source.contains("fractional_even"));
    }

    #[test]
    fn hull_shader_with_instructions_inlines_body() {
        let mut g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        g.set_patch_control_points(3);
        g.set_instructions(vec![TranslatedInstruction {
            msl_body: "_cp = _hs_input_cp[_hs_cp_id];".to_string(),
            dst: "_cp".to_string(),
            operands: vec!["_hs_input_cp".to_string(), "_hs_cp_id".to_string()],
            is_barrier: false,
            barrier_flags: Vec::new(),
            is_uav_access: false,
            address_space: String::new(),
            is_threadgroup_mem: false,
        }]);
        let source = g.generate();
        assert!(source.contains("_cp = _hs_input_cp[_hs_cp_id];"));
    }

    // -----------------------------------------------------------------------
    // Domain shader tests (G5)
    // -----------------------------------------------------------------------

    #[test]
    fn msl_generator_domain_shader_has_tessellation_buffers() {
        let mut g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        let source = g.generate();
        assert!(source.contains("kernel void ds_main_ds"));
        assert!(source.contains("_ds_tessellated_vertices"));
        assert!(source.contains("_ds_control_points"));
        assert!(source.contains("_ds_tess_factors"));
        // The tessellated-vertex buffer is written by the domain shader, so it
        // must not be declared `const` (MSL rejects writes through const).
        assert!(
            !source.contains("device const float4* _ds_tessellated_vertices"),
            "domain shader must write the tessellated vertex buffer"
        );
    }

    #[test]
    fn domain_shader_triangle_barycentric_interpolation() {
        let mut g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        let source = g.generate();
        assert!(source.contains("Barycentric coordinates for triangle patch"));
        assert!(source.contains("_ds_u"));
        assert!(source.contains("_ds_v"));
        assert!(source.contains("_ds_w = 1.0 - _ds_u - _ds_v"));
    }

    #[test]
    fn domain_shader_quad_uv_interpolation() {
        let mut g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        g.set_patch_control_points(4);
        g.set_patch_type(PatchType::Quad);
        let source = g.generate();
        assert!(source.contains("UV coordinates for quad patch"));
        assert!(!source.contains("_ds_w = 1.0"));
    }

    #[test]
    fn domain_shader_isoline_interpolation() {
        let mut g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        g.set_patch_control_points(2);
        g.set_patch_type(PatchType::Isoline);
        let source = g.generate();
        assert!(source.contains("Isoline parameter"));
    }

    #[test]
    fn domain_shader_triangle_position_computation() {
        let mut g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        let source = g.generate();
        assert!(source.contains("_ds_position += _ds_weight * _ds_cp[_ds_j]"));
    }

    #[test]
    fn domain_shader_quad_position_computation() {
        let mut g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        g.set_patch_control_points(4);
        g.set_patch_type(PatchType::Quad);
        let source = g.generate();
        assert!(source.contains("Bilinear interpolation for quad patches"));
        assert!(source.contains("mix(_ds_cp[0], _ds_cp[1]"));
    }

    #[test]
    fn domain_shader_with_instructions_inlines_body() {
        let mut g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        g.set_patch_control_points(3);
        g.set_patch_type(PatchType::Triangle);
        g.set_instructions(vec![TranslatedInstruction {
            msl_body: "_pos = _ds_position;".to_string(),
            dst: "_pos".to_string(),
            operands: vec!["_ds_position".to_string()],
            is_barrier: false,
            barrier_flags: Vec::new(),
            is_uav_access: false,
            address_space: String::new(),
            is_threadgroup_mem: false,
        }]);
        let source = g.generate();
        assert!(source.contains("_pos = _ds_position;"));
    }

    // -----------------------------------------------------------------------
    // Pipeline bridge tests
    // -----------------------------------------------------------------------

    #[test]
    fn empty_instructions_emits_comment() {
        let g = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        let source = g.generate();
        assert!(source.contains("(no translated instructions)"));
    }

    #[test]
    fn set_instructions_multiple_round_trip() {
        let mut g = MslShaderGenerator::new(ShaderStage::Cs, "cs_main");
        let instrs = vec![
            TranslatedInstruction {
                msl_body: "a = b + c;".to_string(),
                dst: "a".to_string(),
                operands: vec!["b".to_string(), "c".to_string()],
                is_barrier: false,
                barrier_flags: Vec::new(),
                is_uav_access: false,
                address_space: String::new(),
                is_threadgroup_mem: false,
            },
            TranslatedInstruction {
                msl_body: "d = e * f;".to_string(),
                dst: "d".to_string(),
                operands: vec!["e".to_string(), "f".to_string()],
                is_barrier: false,
                barrier_flags: Vec::new(),
                is_uav_access: false,
                address_space: String::new(),
                is_threadgroup_mem: false,
            },
        ];
        g.set_instructions(instrs);
        let source = g.generate();
        assert!(source.contains("a = b + c;"));
        assert!(source.contains("d = e * f;"));
    }

    // -----------------------------------------------------------------------
    // Semantic / type mapping tests (unchanged)
    // -----------------------------------------------------------------------

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
        assert!(
            hlsl_type_to_msl("unknown").contains("ERROR: unknown HLSL type"),
            "unknown types must fail loudly, not silently map to float4"
        );
    }

    #[test]
    fn intrinsic_translation() {
        assert_eq!(translate_hlsl_intrinsic("lerp"), "mix");
        assert_eq!(translate_hlsl_intrinsic("frac"), "fract");
        assert_eq!(translate_hlsl_intrinsic("saturate"), "saturate");
        assert_eq!(translate_hlsl_intrinsic("ddx"), "dfdx");
        assert_eq!(translate_hlsl_intrinsic("ddy"), "dfdy");
        assert_eq!(translate_hlsl_intrinsic("Sample"), "sample");
        assert_eq!(translate_hlsl_intrinsic("Load"), "read");
        assert_eq!(translate_hlsl_intrinsic("mul"), "*");
        assert_eq!(translate_hlsl_intrinsic("WaveGetLaneIndex"), "simd_lane_id");
        assert_eq!(
            translate_hlsl_intrinsic("WaveGetLaneCount"),
            "simd_lane_count"
        );
        assert_eq!(translate_hlsl_intrinsic("WaveActiveBallot"), "simd_ballot");
        assert_eq!(translate_hlsl_intrinsic("WaveActiveSum"), "simd_sum");
        assert_eq!(translate_hlsl_intrinsic("asfloat"), "as_type<float>");
        assert_eq!(translate_hlsl_intrinsic("reversebits"), "reverse_bits");
        assert_eq!(translate_hlsl_intrinsic("countbits"), "popcount");
        assert_eq!(
            translate_hlsl_intrinsic("firstbithigh"),
            "// firstbithigh = (clz(x)==32) ? -1 : (31-(int)clz(x))"
        );
        assert_eq!(
            translate_hlsl_intrinsic("firstbitlow"),
            "// firstbitlow = (ctz(x)==32) ? -1 : (int)ctz(x)"
        );
        assert_eq!(
            translate_hlsl_intrinsic("InterlockedAdd"),
            "atomic_fetch_add_explicit"
        );
        assert_eq!(
            translate_hlsl_intrinsic("InterlockedCompareExchange"),
            "atomic_compare_exchange_weak_explicit"
        );
        assert!(
            translate_hlsl_intrinsic("InterlockedCompareStore")
                .contains("atomic_compare_exchange_weak_explicit")
        );
        assert!(translate_hlsl_intrinsic("InterlockedCompareStore").contains("void"));
        assert_eq!(
            translate_hlsl_intrinsic("AllMemoryBarrier"),
            "threadgroup_barrier(mem_flags::mem_threadgroup | mem_flags::mem_device)"
        );
        assert_eq!(
            translate_hlsl_intrinsic("AllMemoryBarrierWithGroupSync"),
            "threadgroup_barrier(mem_flags::mem_threadgroup | mem_flags::mem_device)"
        );
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
        assert_eq!(hash1.len(), 64); // SHA-256 produces 64 hex chars
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

        let hash = "deadbeef1234abcd";
        let source = "#include <metal_stdlib>\nusing namespace metal;\n";

        cache.put_source(hash, source).unwrap();
        let cached = cache.get_source(hash).unwrap();
        assert_eq!(cached, Some(source.to_string()));
    }

    #[test]
    fn shader_cache_rejects_path_traversal_hashes() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache = ShaderCache::new(tmp.path().join("shaders")).unwrap();

        // A hash containing separators or `..` must never touch the filesystem.
        assert!(cache.get("../../etc/passwd").unwrap().is_none());
        assert!(cache.get("a/b").unwrap().is_none());
        assert!(cache.put("../escape", b"data").is_err());
        assert!(cache.put_source("..%2F..%2Fescape", "source").is_err());

        // The cache directory must not contain any files from the rejected hashes.
        let entries: Vec<_> = fs::read_dir(cache.cache_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries.is_empty(),
            "no files may be written for invalid hashes"
        );
    }

    #[test]
    fn msl_generator_geometry_shader() {
        let mut g = MslShaderGenerator::new(ShaderStage::Gs, "gs_main");
        g.set_max_vertex_count(32);
        let source = g.generate();
        assert!(source.contains("kernel void gs_main_gs"));
    }

    #[test]
    fn msl_generator_tessellation_shaders() {
        let mut hs_g = MslShaderGenerator::new(ShaderStage::Hs, "hs_main");
        hs_g.set_patch_control_points(3);
        hs_g.set_patch_type(PatchType::Triangle);
        let hs_source = hs_g.generate();
        assert!(hs_source.contains("kernel void hs_main_hs"));

        let mut ds_g = MslShaderGenerator::new(ShaderStage::Ds, "ds_main");
        ds_g.set_patch_control_points(3);
        ds_g.set_patch_type(PatchType::Triangle);
        let ds_source = ds_g.generate();
        assert!(ds_source.contains("kernel void ds_main_ds"));
    }
}
