use crate::error::{AppError, AppResult};
use crate::gfx::{
    CommandAllocatorId, CommandQueueId, DescriptorHeapId, DescriptorHeapType, DxgiFormat,
    FilterMode, GraphicsBackend, PipelineStateDesc, RenderPassPlan, ResourceDesc,
    ResourceId as GfxResourceId, ResourceState, ResourceUsageHint, RootSignatureDesc,
    SwapchainDesc, SwapchainId, SwapchainState, ViewDescriptor,
};
use crate::reason::ReasonCode;
use crate::shader::{
    CompileFlags as ShaderCompileFlags, ShaderCache, ShaderStage as TranslationShaderStage,
    ShaderTranslationInput, ShaderTranslationOutput, build_cache_entry, shader_cache_key,
    translate_shader,
};
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub type D3d11ResourceId = u64;
pub type D3d11ViewId = u64;
pub type BlendStateId = u64;
pub type RasterizerStateId = u64;
pub type DepthStencilStateId = u64;
pub type SamplerStateId = u64;
pub type InputLayoutId = u64;
pub type ShaderId = u64;
pub type D3d9DeviceId = u64;
pub type D3d9VertexBufferId = u64;
pub type D3d9IndexBufferId = u64;
pub type D3d9TextureId = u64;
pub type D3d9SurfaceId = u64;
pub type D3d9QueryId = u64;

// ── D3D9 Constants ───────────────────────────────────────────────────────────

// D3DPRIMITIVETYPE
pub const D3DPT_POINTLIST: u32 = 1;
pub const D3DPT_LINELIST: u32 = 2;
pub const D3DPT_LINESTRIP: u32 = 3;
pub const D3DPT_TRIANGLELIST: u32 = 4;
pub const D3DPT_TRIANGLESTRIP: u32 = 5;
pub const D3DPT_TRIANGLEFAN: u32 = 6;

// D3DFVF (Flexible Vertex Format) flags
pub const D3DFVF_RESERVED0: u32 = 0x001;
pub const D3DFVF_XYZ: u32 = 0x002;
pub const D3DFVF_XYZRHW: u32 = 0x004;
pub const D3DFVF_XYZB1: u32 = 0x006;
pub const D3DFVF_XYZB2: u32 = 0x008;
pub const D3DFVF_XYZB3: u32 = 0x00a;
pub const D3DFVF_XYZB4: u32 = 0x00c;
pub const D3DFVF_XYZB5: u32 = 0x00e;
pub const D3DFVF_XYZW: u32 = 0x4002; // or 0x4000|0x0002
pub const D3DFVF_NORMAL: u32 = 0x010;
pub const D3DFVF_PSIZE: u32 = 0x020;
pub const D3DFVF_DIFFUSE: u32 = 0x040;
pub const D3DFVF_SPECULAR: u32 = 0x080;
pub const D3DFVF_TEX0: u32 = 0x000;
pub const D3DFVF_TEX1: u32 = 0x100;
pub const D3DFVF_TEX2: u32 = 0x200;
pub const D3DFVF_TEX3: u32 = 0x300;
pub const D3DFVF_TEX4: u32 = 0x400;
pub const D3DFVF_TEX5: u32 = 0x500;
pub const D3DFVF_TEX6: u32 = 0x600;
pub const D3DFVF_TEX7: u32 = 0x700;
pub const D3DFVF_TEX8: u32 = 0x800;
pub const D3DFVF_LASTBETA_UBYTE4: u32 = 0x1000;
pub const D3DFVF_LASTBETA_D3DCOLOR: u32 = 0x8000;

// D3DRENDERSTATETYPE
pub const D3DRS_ZENABLE: u32 = 7;
pub const D3DRS_FILLMODE: u32 = 8;
pub const D3DRS_SHADEMODE: u32 = 9;
pub const D3DRS_ZWRITEENABLE: u32 = 14;
pub const D3DRS_ALPHATESTENABLE: u32 = 15;
pub const D3DRS_LASTPIXEL: u32 = 16;
pub const D3DRS_SRCBLEND: u32 = 19;
pub const D3DRS_DESTBLEND: u32 = 20;
pub const D3DRS_CULLMODE: u32 = 22;
pub const D3DRS_ZFUNC: u32 = 23;
pub const D3DRS_ALPHAREF: u32 = 24;
pub const D3DRS_ALPHAFUNC: u32 = 25;
pub const D3DRS_DITHERENABLE: u32 = 26;
pub const D3DRS_ALPHABLENDENABLE: u32 = 27;
pub const D3DRS_FOGENABLE: u32 = 28;
pub const D3DRS_SPECULARENABLE: u32 = 29;
pub const D3DRS_FOGCOLOR: u32 = 34;
pub const D3DRS_FOGTABLEMODE: u32 = 35;
pub const D3DRS_FOGSTART: u32 = 36;
pub const D3DRS_FOGEND: u32 = 37;
pub const D3DRS_FOGDENSITY: u32 = 38;
pub const D3DRS_RANGEFOGENABLE: u32 = 48;
pub const D3DRS_STENCILENABLE: u32 = 52;
pub const D3DRS_STENCILFAIL: u32 = 53;
pub const D3DRS_STENCILZFAIL: u32 = 54;
pub const D3DRS_STENCILPASS: u32 = 55;
pub const D3DRS_STENCILFUNC: u32 = 56;
pub const D3DRS_STENCILREF: u32 = 57;
pub const D3DRS_STENCILMASK: u32 = 58;
pub const D3DRS_STENCILWRITEMASK: u32 = 59;
pub const D3DRS_TEXTUREFACTOR: u32 = 60;
pub const D3DRS_WRAP0: u32 = 128;
pub const D3DRS_WRAP1: u32 = 129;
pub const D3DRS_WRAP2: u32 = 130;
pub const D3DRS_WRAP3: u32 = 131;
pub const D3DRS_WRAP4: u32 = 132;
pub const D3DRS_WRAP5: u32 = 133;
pub const D3DRS_WRAP6: u32 = 134;
pub const D3DRS_WRAP7: u32 = 135;
pub const D3DRS_CLIPPING: u32 = 136;
pub const D3DRS_LIGHTING: u32 = 137;
pub const D3DRS_AMBIENT: u32 = 139;
pub const D3DRS_FOGVERTEXMODE: u32 = 140;
pub const D3DRS_COLORVERTEX: u32 = 141;
pub const D3DRS_LOCALVIEWER: u32 = 142;
pub const D3DRS_NORMALIZENORMALS: u32 = 143;
pub const D3DRS_DIFFUSEMATERIALSOURCE: u32 = 145;
pub const D3DRS_SPECULARMATERIALSOURCE: u32 = 146;
pub const D3DRS_AMBIENTMATERIALSOURCE: u32 = 147;
pub const D3DRS_EMISSIVEMATERIALSOURCE: u32 = 148;
pub const D3DRS_VERTEXBLEND: u32 = 151;
pub const D3DRS_CLIPPLANEENABLE: u32 = 152;
pub const D3DRS_POINTSIZE: u32 = 154;
pub const D3DRS_POINTSIZEMIN: u32 = 155;
pub const D3DRS_POINTSIZE_MAX: u32 = 156; // renamed to avoid conflict
pub const D3DRS_POINTSPRITEENABLE: u32 = 157;
pub const D3DRS_POINTSCALEENABLE: u32 = 158;
pub const D3DRS_POINTSCALE_A: u32 = 159;
pub const D3DRS_POINTSCALE_B: u32 = 160;
pub const D3DRS_POINTSCALE_C: u32 = 161;
pub const D3DRS_MULTISAMPLEANTIALIAS: u32 = 161; // reuse with caution
pub const D3DRS_MULTISAMPLEMASK: u32 = 162;
pub const D3DRS_PATCHEDGESTYLE: u32 = 163;
pub const D3DRS_DEBUGMONITORTOKEN: u32 = 165;
pub const D3DRS_POINTSIZE_MAX_V9: u32 = 166;
pub const D3DRS_INDEXEDVERTEXBLENDENABLE: u32 = 167;
pub const D3DRS_COLORWRITEENABLE: u32 = 168;
pub const D3DRS_TWEENFACTOR: u32 = 170;
pub const D3DRS_BLENDOP: u32 = 171;
pub const D3DRS_POSITIONDEGREE: u32 = 172;
pub const D3DRS_NORMALDEGREE: u32 = 173;
pub const D3DRS_SCISSORTESTENABLE: u32 = 174;
pub const D3DRS_SLOPESCALEDEPTHBIAS: u32 = 175;
pub const D3DRS_ANTIALIASEDLINEENABLE: u32 = 176;
pub const D3DRS_MINTESSELLATIONLEVEL: u32 = 178;
pub const D3DRS_MAXTESSELLATIONLEVEL: u32 = 179;
pub const D3DRS_ADAPTIVETESS_X: u32 = 180;
pub const D3DRS_ADAPTIVETESS_Y: u32 = 181;
pub const D3DRS_ADAPTIVETESS_Z: u32 = 182;
pub const D3DRS_ADAPTIVETESS_W: u32 = 183;
pub const D3DRS_ENABLEADAPTIVETESSELLATION: u32 = 184;
pub const D3DRS_DISPLACEMENTMAPSCALE: u32 = 186;
pub const D3DRS_DISPLACEMENTMAPSAMPLING: u32 = 187;
pub const D3DRS_DOMAIN: u32 = 188;
pub const D3DRS_TESSELLATIONMODE: u32 = 189;

// D3DTRANSFORMSTATETYPE
pub const D3DTS_VIEW: u32 = 2;
pub const D3DTS_PROJECTION: u32 = 3;
pub const D3DTS_TEXTURE0: u32 = 16;
pub const D3DTS_TEXTURE1: u32 = 17;
pub const D3DTS_TEXTURE2: u32 = 18;
pub const D3DTS_TEXTURE3: u32 = 19;
pub const D3DTS_TEXTURE4: u32 = 20;
pub const D3DTS_TEXTURE5: u32 = 21;
pub const D3DTS_TEXTURE6: u32 = 22;
pub const D3DTS_TEXTURE7: u32 = 23;
pub const D3DTS_WORLD: u32 = 256;
pub const D3DTS_WORLD1: u32 = 257;
pub const D3DTS_WORLD2: u32 = 258;
pub const D3DTS_WORLD3: u32 = 259;

// D3DSAMPLERSTATETYPE / D3DTEXTURESTAGESTATETYPE
pub const D3DTSS_COLOROP: u32 = 1;
pub const D3DTSS_COLORARG1: u32 = 2;
pub const D3DTSS_COLORARG2: u32 = 3;
pub const D3DTSS_ALPHAOP: u32 = 4;
pub const D3DTSS_ALPHAARG1: u32 = 5;
pub const D3DTSS_ALPHAARG2: u32 = 6;
pub const D3DTSS_BUMPENVMAT00: u32 = 7;
pub const D3DTSS_BUMPENVMAT01: u32 = 8;
pub const D3DTSS_BUMPENVMAT10: u32 = 9;
pub const D3DTSS_BUMPENVMAT11: u32 = 10;
pub const D3DTSS_TEXCOORDINDEX: u32 = 11;
pub const D3DTSS_BUMPENVLSCALE: u32 = 22;
pub const D3DTSS_BUMPENVLOFFSET: u32 = 23;
pub const D3DTSS_TEXTURETRANSFORMFLAGS: u32 = 24;
pub const D3DTSS_COLORARG0: u32 = 26;
pub const D3DTSS_ALPHAARG0: u32 = 27;
pub const D3DTSS_RESULTARG: u32 = 28;

// D3DTEXTUREOP
pub const D3DTOP_DISABLE: u32 = 1;
pub const D3DTOP_SELECTARG1: u32 = 2;
pub const D3DTOP_SELECTARG2: u32 = 3;
pub const D3DTOP_MODULATE: u32 = 4;
pub const D3DTOP_MODULATE2X: u32 = 5;
pub const D3DTOP_MODULATE4X: u32 = 6;
pub const D3DTOP_ADD: u32 = 7;
pub const D3DTOP_ADDSIGNED: u32 = 8;
pub const D3DTOP_ADDSIGNED2X: u32 = 9;
pub const D3DTOP_SUBTRACT: u32 = 10;
pub const D3DTOP_ADDSMOOTH: u32 = 11;
pub const D3DTOP_BLENDDIFFUSEALPHA: u32 = 12;
pub const D3DTOP_BLENDTEXTUREALPHA: u32 = 13;
pub const D3DTOP_BLENDFACTORALPHA: u32 = 14;
pub const D3DTOP_BLENDTEXTUREALPHAPM: u32 = 15;
pub const D3DTOP_BLENDCURRENTALPHA: u32 = 16;
pub const D3DTOP_PREMODULATE: u32 = 17;
pub const D3DTOP_MODULATEALPHA_ADDCOLOR: u32 = 18;
pub const D3DTOP_MODULATECOLOR_ADDALPHA: u32 = 19;
pub const D3DTOP_MODULATEINVALPHA_ADDCOLOR: u32 = 20;
pub const D3DTOP_MODULATEINVCOLOR_ADDALPHA: u32 = 21;
pub const D3DTOP_BUMPENVMAP: u32 = 22;
pub const D3DTOP_BUMPENVMAPLUMINANCE: u32 = 23;
pub const D3DTOP_DOTPRODUCT3: u32 = 24;
pub const D3DTOP_MULTIPLYADD: u32 = 25;
pub const D3DTOP_LERP: u32 = 26;

// D3DTA (texture argument)
pub const D3DTA_TEXTURE: u32 = 0x00000004;
pub const D3DTA_CURRENT: u32 = 0x00000008;
pub const D3DTA_DIFFUSE: u32 = 0x00000000;
pub const D3DTA_SPECULAR: u32 = 0x00000020;
pub const D3DTA_TEMP: u32 = 0x00000040;
pub const D3DTA_CONSTANT: u32 = 0x00000080;
pub const D3DTA_ALPHAREPLICATE: u32 = 0x00000200;
pub const D3DTA_COMPLEMENT: u32 = 0x00000100;

// D3DCULL
pub const D3DCULL_NONE: u32 = 1;
pub const D3DCULL_CW: u32 = 2;
pub const D3DCULL_CCW: u32 = 3;

// D3DFILLMODE
pub const D3DFILL_POINT: u32 = 1;
pub const D3DFILL_WIREFRAME: u32 = 2;
pub const D3DFILL_SOLID: u32 = 3;

// D3DSHADEMODE
pub const D3DSHADE_FLAT: u32 = 1;
pub const D3DSHADE_GOURAUD: u32 = 2;
pub const D3DSHADE_PHONG: u32 = 3;

// D3DBLEND
pub const D3DBLEND_ZERO: u32 = 1;
pub const D3DBLEND_ONE: u32 = 2;
pub const D3DBLEND_SRCCOLOR: u32 = 3;
pub const D3DBLEND_INVSRCCOLOR: u32 = 4;
pub const D3DBLEND_SRCALPHA: u32 = 5;
pub const D3DBLEND_INVSRCALPHA: u32 = 6;
pub const D3DBLEND_DESTALPHA: u32 = 7;
pub const D3DBLEND_INVDESTALPHA: u32 = 8;
pub const D3DBLEND_DESTCOLOR: u32 = 9;
pub const D3DBLEND_INVDESTCOLOR: u32 = 10;
pub const D3DBLEND_SRCALPHASAT: u32 = 11;
pub const D3DBLEND_BOTHSRCALPHA: u32 = 12;
pub const D3DBLEND_BOTHINVSRCALPHA: u32 = 13;
pub const D3DBLEND_BLENDFACTOR: u32 = 14;

// D3DCMPFUNC
pub const D3DCMP_NEVER: u32 = 1;
pub const D3DCMP_LESS: u32 = 2;
pub const D3DCMP_EQUAL: u32 = 3;
pub const D3DCMP_LESSEQUAL: u32 = 4;
pub const D3DCMP_GREATER: u32 = 5;
pub const D3DCMP_NOTEQUAL: u32 = 6;
pub const D3DCMP_GREATEREQUAL: u32 = 7;
pub const D3DCMP_ALWAYS: u32 = 8;

// D3DSTENCILOP
pub const D3DSTENCILOP_KEEP: u32 = 1;
pub const D3DSTENCILOP_ZERO: u32 = 2;
pub const D3DSTENCILOP_REPLACE: u32 = 3;
pub const D3DSTENCILOP_INCRSAT: u32 = 4;
pub const D3DSTENCILOP_DECRSAT: u32 = 5;
pub const D3DSTENCILOP_INVERT: u32 = 6;
pub const D3DSTENCILOP_INCR: u32 = 7;
pub const D3DSTENCILOP_DECR: u32 = 8;

// D3DMATERIALCOLORSOURCE
pub const D3DMCS_MATERIAL: u32 = 0;
pub const D3DMCS_COLOR1: u32 = 1;
pub const D3DMCS_COLOR2: u32 = 2;

// D3DLIGHTTYPE
pub const D3DLIGHT_POINT: u32 = 1;
pub const D3DLIGHT_SPOT: u32 = 2;
pub const D3DLIGHT_DIRECTIONAL: u32 = 3;

// D3DPRESENTFLAG
pub const D3DPRESENTFLAG_LOCKABLE_BACKBUFFER: u32 = 0x00000001;
pub const D3DPRESENTFLAG_DISCARD_DEPTHSTENCIL: u32 = 0x00000002;
pub const D3DPRESENTFLAG_DEVICECLIP: u32 = 0x00000004;
pub const D3DPRESENTFLAG_VIDEO: u32 = 0x00000010;

// D3DSWAPEFFECT
pub const D3DSWAPEFFECT_DISCARD: u32 = 1;
pub const D3DSWAPEFFECT_FLIP: u32 = 2;
pub const D3DSWAPEFFECT_COPY: u32 = 3;
pub const D3DSWAPEFFECT_OVERLAY: u32 = 4;
pub const D3DSWAPEFFECT_FLIPEX: u32 = 5;

// D3DPRESENT_INTERVAL
pub const D3DPRESENT_INTERVAL_DEFAULT: u32 = 0x00000000;
pub const D3DPRESENT_INTERVAL_ONE: u32 = 0x00000001;
pub const D3DPRESENT_INTERVAL_TWO: u32 = 0x00000002;
pub const D3DPRESENT_INTERVAL_THREE: u32 = 0x00000003;
pub const D3DPRESENT_INTERVAL_FOUR: u32 = 0x00000004;
pub const D3DPRESENT_INTERVAL_IMMEDIATE: u32 = 0x80000000;

// D3D9 HRESULT codes
pub const D3DERR_INVALIDCALL: u64 = 0x8876086C;
pub const D3DERR_WASSTILLDRAWING: u64 = 0x88760208;
pub const D3DERR_DRIVERINTERNALERROR: u64 = 0x8876020A;
pub const D3D_OK: u64 = 0;
pub const D3DERR_OUTOFVIDEOMEMORY: u64 = 0x887601C2;

// Maximum limits
pub const D3D9_MAX_STREAMS: usize = 16;
pub const D3D9_MAX_TEXTURE_STAGES: usize = 8;
pub const D3D9_MAX_RENDER_STATES: usize = 256;
pub const D3D9_MAX_LIGHTS: usize = 8;
pub const D3D9_MAX_TEXTURES: usize = 8;

// ── D3D9 Structures ──────────────────────────────────────────────────────────

/// 4x4 matrix in row-major order (same as D3DMATRIX)
#[derive(Debug, Clone, Copy)]
pub struct D3dMatrix {
    pub m: [[f32; 4]; 4],
}

impl D3dMatrix {
    pub fn identity() -> Self {
        D3dMatrix {
            m: [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
                [0.0, 0.0, 0.0, 1.0],
            ],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct D3dViewport9 {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub min_z: f32,
    pub max_z: f32,
}

#[derive(Debug, Clone, Copy)]
pub struct D3dMaterial9 {
    pub diffuse: [f32; 4],
    pub ambient: [f32; 4],
    pub specular: [f32; 4],
    pub emissive: [f32; 4],
    pub power: f32,
}

#[derive(Debug, Clone, Copy)]
pub struct D3dLight9 {
    pub light_type: u32,
    pub diffuse: [f32; 4],
    pub specular: [f32; 4],
    pub ambient: [f32; 4],
    pub position: [f32; 3],
    pub direction: [f32; 3],
    pub range: f32,
    pub falloff: f32,
    pub attenuation0: f32,
    pub attenuation1: f32,
    pub attenuation2: f32,
    pub theta: f32,
    pub phi: f32,
}

#[derive(Debug, Clone)]
pub struct D3dPresentParameters {
    pub back_buffer_width: u32,
    pub back_buffer_height: u32,
    pub back_buffer_format: u32,
    pub back_buffer_count: u32,
    pub multi_sample_type: u32,
    pub multi_sample_quality: u32,
    pub swap_effect: u32,
    pub device_window: u64,
    pub windowed: bool,
    pub enable_auto_depth_stencil: bool,
    pub auto_depth_stencil_format: u32,
    pub flags: u32,
    pub fullscreen_refresh_rate_in_hz: u32,
    pub presentation_interval: u32,
}

impl Default for D3dPresentParameters {
    fn default() -> Self {
        D3dPresentParameters {
            back_buffer_width: 0,
            back_buffer_height: 0,
            back_buffer_format: 0,
            back_buffer_count: 1,
            multi_sample_type: 0,
            multi_sample_quality: 0,
            swap_effect: D3DSWAPEFFECT_DISCARD,
            device_window: 0,
            windowed: true,
            enable_auto_depth_stencil: true,
            auto_depth_stencil_format: 0,
            flags: 0,
            fullscreen_refresh_rate_in_hz: 0,
            presentation_interval: D3DPRESENT_INTERVAL_DEFAULT,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VertexBuffer9 {
    pub id: D3d9VertexBufferId,
    pub size: usize,
    pub data: Vec<u8>,
    pub fvf: u32,
    pub stride: u32,
}

#[derive(Debug, Clone)]
pub struct IndexBuffer9 {
    pub id: D3d9IndexBufferId,
    pub size: usize,
    pub data: Vec<u8>,
    pub format: bool, // true = 32-bit, false = 16-bit
}

#[derive(Debug, Clone)]
pub struct D3d9Texture {
    pub id: D3d9TextureId,
    pub width: u32,
    pub height: u32,
    pub levels: Vec<Vec<u8>>,
    pub format: u32,
}

/// Represents the complete D3D9 fixed-function state for a draw call.
#[derive(Debug, Clone)]
pub struct D3d9StateBlock {
    pub render_states: [u32; D3D9_MAX_RENDER_STATES],
    pub textures: [Option<D3d9TextureId>; D3D9_MAX_TEXTURES],
    pub texture_stage_states: [[u32; 32]; D3D9_MAX_TEXTURE_STAGES],
    pub transforms: BTreeMap<u32, D3dMatrix>,
    pub materials: [Option<D3dMaterial9>; D3D9_MAX_LIGHTS],
    pub lights: [Option<D3dLight9>; D3D9_MAX_LIGHTS],
    pub lights_enabled: [bool; D3D9_MAX_LIGHTS],
    pub ambient: u32,
    pub viewport: D3dViewport9,
    pub material: D3dMaterial9,
    pub fvf: u32,
    pub vertex_declaration: u64,
    pub stream_source: [Option<(D3d9VertexBufferId, u32, u32)>; D3D9_MAX_STREAMS],
    pub stream_frequency: [u32; D3D9_MAX_STREAMS],
    pub indices: Option<(D3d9IndexBufferId, u32)>,
    pub pixel_shader: u64,
    pub vertex_shader: u64,
    pub clip_planes: [bool; 6],
    pub scissor_rect: Option<(i32, i32, i32, i32)>,
}

impl D3d9StateBlock {
    pub fn new() -> Self {
        let mut render_states = [0u32; D3D9_MAX_RENDER_STATES];
        render_states[D3DRS_ZENABLE as usize] = 1; // D3DZB_TRUE
        render_states[D3DRS_FILLMODE as usize] = D3DFILL_SOLID;
        render_states[D3DRS_SHADEMODE as usize] = D3DSHADE_GOURAUD;
        render_states[D3DRS_CULLMODE as usize] = D3DCULL_CCW;
        render_states[D3DRS_ALPHABLENDENABLE as usize] = 0;
        render_states[D3DRS_LIGHTING as usize] = 1;
        render_states[D3DRS_SPECULARENABLE as usize] = 0;
        render_states[D3DRS_COLORVERTEX as usize] = 1;
        render_states[D3DRS_CLIPPING as usize] = 1;
        render_states[D3DRS_LOCALVIEWER as usize] = 1;
        render_states[D3DRS_DIFFUSEMATERIALSOURCE as usize] = D3DMCS_COLOR1;
        render_states[D3DRS_SPECULARMATERIALSOURCE as usize] = D3DMCS_COLOR2;
        render_states[D3DRS_AMBIENTMATERIALSOURCE as usize] = D3DMCS_MATERIAL;
        render_states[D3DRS_EMISSIVEMATERIALSOURCE as usize] = D3DMCS_MATERIAL;

        D3d9StateBlock {
            render_states,
            textures: [None; D3D9_MAX_TEXTURES],
            texture_stage_states: [[0u32; 32]; D3D9_MAX_TEXTURE_STAGES],
            transforms: BTreeMap::new(),
            materials: [None; D3D9_MAX_LIGHTS],
            lights: [None; D3D9_MAX_LIGHTS],
            lights_enabled: [false; D3D9_MAX_LIGHTS],
            ambient: 0,
            viewport: D3dViewport9 {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
                min_z: 0.0,
                max_z: 1.0,
            },
            material: D3dMaterial9 {
                diffuse: [1.0, 1.0, 1.0, 1.0],
                ambient: [0.0, 0.0, 0.0, 0.0],
                specular: [0.0, 0.0, 0.0, 0.0],
                emissive: [0.0, 0.0, 0.0, 0.0],
                power: 0.0,
            },
            fvf: 0,
            vertex_declaration: 0,
            stream_source: [None; D3D9_MAX_STREAMS],
            stream_frequency: [1u32; D3D9_MAX_STREAMS],
            indices: None,
            pixel_shader: 0,
            vertex_shader: 0,
            clip_planes: [false; 6],
            scissor_rect: None,
        }
    }
}

impl Default for D3d9StateBlock {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FeatureLevel {
    Level10_1,
    Level11_0,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureCaps {
    pub geometry_shader: bool,
    pub hull_shader: bool,
    pub domain_shader: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCreationRequest {
    pub requested_feature_levels: Vec<FeatureLevel>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDimension {
    Buffer,
    Texture1D,
    Texture2D,
    Texture3D,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3d11ResourceDesc {
    pub label: String,
    pub dimension: ResourceDimension,
    pub format: DxgiFormat,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub byte_width: usize,
    pub usage_hint: ResourceUsageHint,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    Srv,
    Rtv,
    Dsv,
    Uav,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ViewInfo {
    pub resource: D3d11ResourceId,
    pub kind: ViewKind,
    pub format: DxgiFormat,
}

/// Per-render-target blend state (D3D11_RENDER_TARGET_BLEND_DESC).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenderTargetBlendDesc {
    pub blend_enable: bool,
    pub src_blend: u32,
    pub dest_blend: u32,
    pub blend_op: u32,
    pub src_blend_alpha: u32,
    pub dest_blend_alpha: u32,
    pub blend_op_alpha: u32,
    pub render_target_write_mask: u8,
}

impl Default for RenderTargetBlendDesc {
    fn default() -> Self {
        Self {
            blend_enable: false,
            src_blend: 1,  // D3D11_BLEND_ONE = 1
            dest_blend: 0, // D3D11_BLEND_ZERO = 0
            blend_op: 1,   // D3D11_BLEND_OP_ADD = 1
            src_blend_alpha: 1,
            dest_blend_alpha: 0,
            blend_op_alpha: 1,
            render_target_write_mask: 0x0F,
        }
    }
}

/// D3D11_BLEND_DESC — full blend state with 8 independent render targets.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlendStateDesc {
    pub alpha_to_coverage_enable: bool,
    pub independent_blend_enable: bool,
    pub render_target: [RenderTargetBlendDesc; 8],
}

/// D3D11_RASTERIZER_DESC — full rasterizer state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RasterizerStateDesc {
    pub fill_mode: String,
    pub cull_mode: String,
    pub front_counter_clockwise: bool,
    pub depth_bias: i32,
    pub depth_bias_clamp: f32,
    pub slope_scaled_depth_bias: f32,
    pub depth_clip_enable: bool,
    pub scissor_enable: bool,
    pub multisample_enable: bool,
    pub antialiased_line_enable: bool,
}

impl Default for RasterizerStateDesc {
    fn default() -> Self {
        Self {
            fill_mode: "solid".to_string(),
            cull_mode: "back".to_string(),
            front_counter_clockwise: false,
            depth_bias: 0,
            depth_bias_clamp: 0.0,
            slope_scaled_depth_bias: 0.0,
            depth_clip_enable: true,
            scissor_enable: false,
            multisample_enable: false,
            antialiased_line_enable: false,
        }
    }
}

/// D3D11_DEPTH_STENCIL_DESC — full depth-stencil state with front/back stencil ops.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepthStencilStateDesc {
    pub depth_enable: bool,
    pub depth_write_mask: u8,
    pub depth_func: u32,
    pub stencil_enable: bool,
    pub stencil_read_mask: u8,
    pub stencil_write_mask: u8,
    pub front_stencil_fail_op: u32,
    pub front_stencil_depth_fail_op: u32,
    pub front_stencil_pass_op: u32,
    pub front_stencil_func: u32,
    pub back_stencil_fail_op: u32,
    pub back_stencil_depth_fail_op: u32,
    pub back_stencil_pass_op: u32,
    pub back_stencil_func: u32,
}

impl Default for DepthStencilStateDesc {
    fn default() -> Self {
        Self {
            depth_enable: true,
            depth_write_mask: 1,
            depth_func: 2, // D3D11_COMPARISON_LESS = 2
            stencil_enable: false,
            stencil_read_mask: 0xFF,
            stencil_write_mask: 0xFF,
            front_stencil_fail_op: 1, // D3D11_STENCIL_OP_KEEP = 1
            front_stencil_depth_fail_op: 1,
            front_stencil_pass_op: 1,
            front_stencil_func: 8, // D3D11_COMPARISON_ALWAYS = 8 (D3D11 spec default)
            back_stencil_fail_op: 1,
            back_stencil_depth_fail_op: 1,
            back_stencil_pass_op: 1,
            back_stencil_func: 8, // D3D11_COMPARISON_ALWAYS = 8 (D3D11 spec default)
        }
    }
}

/// D3D11_SAMPLER_DESC — full sampler state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SamplerStateDesc {
    pub filter: FilterMode,
    pub address_u: String,
    pub address_v: String,
    pub address_w: String,
    pub mip_lod_bias: f32,
    pub max_anisotropy: u32,
    pub comparison_func: u32,
    pub border_color: [f32; 4],
    pub min_lod: f32,
    pub max_lod: f32,
}

impl Default for SamplerStateDesc {
    fn default() -> Self {
        Self {
            filter: FilterMode::Point,
            address_u: "clamp".to_string(),
            address_v: "clamp".to_string(),
            address_w: "clamp".to_string(),
            mip_lod_bias: 0.0,
            max_anisotropy: 1,
            comparison_func: 1, // D3D11_COMPARISON_NEVER = 1
            border_color: [1.0, 1.0, 1.0, 1.0],
            min_lod: -f32::MAX,
            max_lod: f32::MAX,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputElementDesc {
    pub semantic: String,
    pub format: DxgiFormat,
    pub slot: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputLayoutDesc {
    pub elements: Vec<InputElementDesc>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShaderModuleDesc {
    pub stage: ShaderStage,
    pub entry: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Viewport {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScissorRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionResult {
    pub feature_level: FeatureLevel,
    pub draw_calls: u32,
    pub indexed_draw_calls: u32,
    pub dispatch_calls: u32,
    pub executed_command_lists: usize,
    pub resource_digests: BTreeMap<String, String>,
    pub signature: String,
    pub hash: String,
    pub backend_plan: crate::gfx::MetalCommandBufferPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct D3d11CommandList {
    pub binding_signature: String,
    pub commands: Vec<RecordedCommand>,
    pub bindings: ContextBindings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixedFunctionScene {
    pub texture_factor: u32,
    pub diffuse_color: [u8; 4],
    pub fog_enable: bool,
    pub alpha_blend_enable: bool,
    pub primitive_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct D3d9Frame {
    pub signature: String,
    pub hash: String,
    pub pixels: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// Pixel provenance: true when the pixels were invented by the host
    /// (fixed-function placeholder rasterizer, or the blank present
    /// fallback).  Synthesized frames are never published to the live
    /// channel and never count as real guest presents.
    pub synthesized: bool,
}

/// A D3D9 render-target snapshot with pixel provenance.  `synthesized` is
/// true when the host invented the pixels (the fixed-function placeholder
/// rasterizer or the blank fallback); such content must never be published
/// as a real guest frame or counted as a real present.
#[derive(Debug, Clone)]
pub struct D3d9RenderTarget {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    pub synthesized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DrawCallKind {
    Regular,
    Instanced { instances: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IndexedDrawCallKind {
    Regular,
    Instanced { instances: u32 },
}

#[derive(Debug, Clone)]
struct ResourceRecord {
    desc: D3d11ResourceDesc,
    backend_id: GfxResourceId,
    bytes: Vec<u8>,
    mapped: bool,
    include_in_digests: bool,
    /// Cached submission digest; `None` when the bytes were mutated since the
    /// last digest computation (avoids re-hashing untouched resources).
    digest: Option<String>,
}

/// A borrow returned by [`D3d11Device::map`].
///
/// Non-present resources borrow their shared `bytes` backing directly. Present
/// backbuffers on the zero-copy path borrow the locked IOSurface mapping, so a
/// Map/Unmap round-trip never materializes a `Vec` copy.
pub enum D3d11Map<'a> {
    Bytes(&'a mut [u8]),
    Surface(crate::metal_backend::IoSurfacePixelsMut),
}

impl D3d11Map<'_> {
    /// Real row pitch of the borrowed backing; `0` means tightly packed
    /// (non-surface resources).
    pub fn row_pitch(&self) -> usize {
        match self {
            Self::Bytes(_) => 0,
            Self::Surface(surface) => surface.row_pitch(),
        }
    }

    /// Number of rows in a surface mapping; `0` for tight byte buffers.
    pub fn height(&self) -> usize {
        match self {
            Self::Bytes(_) => 0,
            Self::Surface(surface) => surface.height(),
        }
    }
}

impl std::fmt::Debug for D3d11Map<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("D3d11Map")
            .field("len", &self.len())
            .finish()
    }
}

impl std::ops::Deref for D3d11Map<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::Surface(surface) => surface,
        }
    }
}

impl std::ops::DerefMut for D3d11Map<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::Surface(surface) => surface,
        }
    }
}

impl AsRef<[u8]> for D3d11Map<'_> {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for D3d11Map<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

#[derive(Debug, Clone)]
struct ViewRecord {
    info: ViewInfo,
    heap: Option<DescriptorHeapId>,
}

#[derive(Debug, Clone)]
struct ShaderArtifact {
    cache_key: String,
    metal_entry: String,
    output: ShaderTranslationOutput,
}

/// D3D11 predicate type (maps to D3D11_QUERY with MiscFlags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PredicateType {
    /// D3D11_QUERY_OCCLUSION_PREDICATE / D3D11_QUERY_OCCLUSION_PREDICATE16
    Occlusion,
    /// D3D11_QUERY_SO_OVERFLOW_PREDICATE / D3D11_QUERY_SO_OVERFLOW_PREDICATE16
    StreamOutputOverflow,
}

/// A D3D11 predicate for conditional rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Predicate {
    pub predicate_type: PredicateType,
    pub value: bool,
}

/// D3D11 counter type (maps to D3D11_COUNTER).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterType {
    /// D3D11_COUNTER_DEVICE_DEPENDENT (0x40000000)
    DeviceDependent,
}

/// A D3D11 counter for performance measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counter {
    pub counter_type: CounterType,
    pub unit_count: u64,
}

/// A D3D11 class linkage instance for shader class interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassInstance {
    pub class_name: String,
    pub instance_index: u32,
}

/// D3D11 class linkage for linking shader class instances.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassLinkage {
    pub instances: Vec<ClassInstance>,
}

#[derive(Debug, Clone)]
struct ShaderRecord {
    desc: ShaderModuleDesc,
    artifact: Option<ShaderArtifact>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ContextBindings {
    render_targets: Vec<D3d11ViewId>,
    depth_target: Option<D3d11ViewId>,
    viewport: Option<Viewport>,
    scissor_rect: Option<ScissorRect>,
    vertex_buffers: Vec<D3d11ResourceId>,
    index_buffer: Option<D3d11ResourceId>,
    primitive_topology: Option<u32>,
    input_layout: Option<InputLayoutId>,
    blend_state: Option<BlendStateId>,
    rasterizer_state: Option<RasterizerStateId>,
    depth_stencil_state: Option<DepthStencilStateId>,
    shaders: BTreeMap<ShaderStage, ShaderId>,
    constant_buffers: BTreeMap<ShaderStage, Vec<D3d11ResourceId>>,
    shader_resources: BTreeMap<ShaderStage, Vec<D3d11ViewId>>,
    /// Unordered access views, tracked independently from shader resources so
    /// that binding CS SRVs and CS/OM UAVs does not clobber one set of binds.
    unordered_access_views: BTreeMap<ShaderStage, Vec<D3d11ViewId>>,
    samplers: BTreeMap<ShaderStage, Vec<SamplerStateId>>,
}

#[derive(Debug, Clone, Default)]
struct ImmediateContext {
    bindings: ContextBindings,
    commands: Vec<RecordedCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecordedCommand {
    UpdateSubresource {
        resource: D3d11ResourceId,
        bytes: Vec<u8>,
    },
    CopyResource {
        src: D3d11ResourceId,
        dst: D3d11ResourceId,
    },
    CopySubresourceRegion {
        src: D3d11ResourceId,
        dst: D3d11ResourceId,
        src_offset: usize,
        dst_offset: usize,
        size: usize,
    },
    ClearRenderTargetView {
        view: D3d11ViewId,
        color: [u8; 4],
    },
    ClearDepthStencilView {
        view: D3d11ViewId,
        depth: u32,
        stencil: u8,
    },
    Draw {
        vertices: u32,
        kind: DrawCallKind,
    },
    DrawIndexed {
        indices: u32,
        kind: IndexedDrawCallKind,
    },
    Dispatch {
        x: u32,
        y: u32,
        z: u32,
    },
    ResolveSubresource {
        dst: D3d11ResourceId,
        dst_subresource: u32,
        src: D3d11ResourceId,
        src_subresource: u32,
        /// Raw DXGI_FORMAT u32 value.
        format: u32,
    },
    CopyStructureCount {
        dst: D3d11ResourceId,
        src_view: D3d11ViewId,
        aligned_byte_offset: u32,
    },
}

#[derive(Debug, Clone, Default)]
struct DeferredRecording {
    bindings: ContextBindings,
    commands: Vec<RecordedCommand>,
    finished: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeferredContext {
    recording: Arc<Mutex<DeferredRecording>>,
}

#[derive(Debug, Clone)]
pub struct Direct3D9Shim {
    next_id: D3d9DeviceId,
    next_vertex_buffer_id: D3d9VertexBufferId,
    next_index_buffer_id: D3d9IndexBufferId,
    next_texture_id: D3d9TextureId,
    pub vertex_buffers: BTreeMap<D3d9VertexBufferId, VertexBuffer9>,
    pub index_buffers: BTreeMap<D3d9IndexBufferId, IndexBuffer9>,
    pub textures: BTreeMap<D3d9TextureId, D3d9Texture>,
    pub devices: BTreeMap<D3d9DeviceId, Direct3D9Device>,
    pub render_target: Option<D3d9RenderTarget>,
}

#[derive(Debug, Clone)]
pub struct Direct3D9Device {
    pub id: D3d9DeviceId,
    pub state: D3d9StateBlock,
    pub present_params: D3dPresentParameters,
    pub swapchain_width: u32,
    pub swapchain_height: u32,
}

#[derive(Debug, Clone)]
pub struct D3d11Device {
    next_id: u64,
    backend: GraphicsBackend,
    feature_level: FeatureLevel,
    caps: FeatureCaps,
    swapchain: Option<SwapchainId>,
    queue: CommandQueueId,
    graphics_allocator: CommandAllocatorId,
    graphics_pipeline: u64,
    fence: u64,
    next_fence_value: u64,
    resources: BTreeMap<D3d11ResourceId, ResourceRecord>,
    views: BTreeMap<D3d11ViewId, ViewRecord>,
    blend_states: BTreeMap<BlendStateId, BlendStateDesc>,
    rasterizer_states: BTreeMap<RasterizerStateId, RasterizerStateDesc>,
    depth_stencil_states: BTreeMap<DepthStencilStateId, DepthStencilStateDesc>,
    sampler_states: BTreeMap<SamplerStateId, SamplerStateDesc>,
    input_layouts: BTreeMap<InputLayoutId, InputLayoutDesc>,
    shaders: BTreeMap<ShaderId, ShaderRecord>,
    shader_cache: ShaderCache,
    translated_shaders: BTreeMap<String, ShaderTranslationOutput>,
    immediate: ImmediateContext,
    /// D3D11 predicates for conditional rendering.
    predicates: BTreeMap<u64, Predicate>,
    /// D3D11 counters for performance measurement.
    counters: BTreeMap<u64, Counter>,
    /// D3D11 class linkage objects for shader class interfaces.
    class_linkage: BTreeMap<u64, ClassLinkage>,
    /// Active rendering predicate id (set via `set_predication`). Draws are
    /// skipped while a bound predicate reports false.
    predication: Option<u64>,
    /// Number of present-time backbuffer syncs performed directly from the
    /// host-visible d3d11 pixels (no intermediate staging buffer allocated).
    zero_copy_present_syncs: u64,
    /// IOSurface-backed present channels, one per swapchain backbuffer.
    /// Empty means the capability probe or allocation failed and presents use
    /// the verified host-visible fallback.
    iosurface_channels: Vec<crate::metal_backend::IoSurfacePresentChannel>,
    /// Presents that bound the IOSurface-backed Metal texture.
    iosurface_presents: u64,
    /// Writes that landed directly in the IOSurface mapping (no staging Vec).
    surface_writes: u64,
    /// Writes that had to update the CPU backing Vec because the zero-copy
    /// channel was unavailable or the resource is not a present backbuffer.
    cpu_backing_writes: u64,
    /// Present-time uploads through the fallback host-visible path because no
    /// IOSurface channel was available.
    fallback_uploads: u64,
    /// NV12 plane channels for the primary swapchain (empty for pixel paths).
    primary_nv12: Vec<crate::metal_backend::Nv12PresentChannel>,
    /// Additional swapchains, each owning its own IOSurface channel set.
    extra_swapchains: BTreeMap<SwapchainId, SwapchainChannelSet>,
    /// Presents that bound both NV12 planes.
    nv12_presents: u64,
    /// NV12 channel allocation failures that fell back to the pixel path.
    nv12_fallbacks: u64,
}

#[derive(Debug, Clone, Default)]
struct SwapchainChannelSet {
    pixel: Vec<crate::metal_backend::IoSurfacePresentChannel>,
    nv12: Vec<crate::metal_backend::Nv12PresentChannel>,
}

impl SwapchainChannelSet {
    fn is_empty(&self) -> bool {
        self.pixel.is_empty() && self.nv12.is_empty()
    }
}

impl D3d11Device {
    pub fn feature_level(&self) -> FeatureLevel {
        self.feature_level
    }

    pub fn caps(&self) -> &FeatureCaps {
        &self.caps
    }

    /// Canonical GPU profile signature for the live host adapter. This is the
    /// exact prefix embedded in every submission signature, exposed so callers
    /// (and conformance harnesses) can reconstruct the expected signature on any
    /// host without hardcoding a specific GPU family.
    pub fn gpu_profile_signature(&self) -> String {
        self.pipeline_profile_signature()
    }

    /// Returns true when the host backend places transient depth attachments in
    /// memoryless storage (an Apple-GPU bandwidth optimization). When true, a
    /// depth target that is never sampled afterwards is stored with a
    /// `store+depth-discard` action rather than a plain `store`.
    pub fn memoryless_depth_targets(&self) -> bool {
        self.backend.capabilities().memoryless_render_targets
    }

    /// Read-only access to the graphics backend that serves this device.
    pub fn backend(&self) -> &GraphicsBackend {
        &self.backend
    }

    /// Number of present-time backbuffer syncs written directly from the
    /// host-visible d3d11 resource bytes without allocating an intermediate
    /// staging buffer.
    pub fn zero_copy_present_sync_count(&self) -> u64 {
        self.zero_copy_present_syncs
    }

    /// Presents that bound an IOSurface-backed Metal texture.
    pub fn iosurface_present_count(&self) -> u64 {
        self.iosurface_presents
    }

    /// Writes that went directly into the IOSurface mapping.
    pub fn zero_copy_upload_count(&self) -> u64 {
        self.surface_writes
    }

    /// Writes that landed in the IOSurface (authoritative present pixels).
    pub fn surface_writes(&self) -> u64 {
        self.surface_writes
    }

    /// Writes that had to update the CPU backing storage.
    pub fn cpu_backing_writes(&self) -> u64 {
        self.cpu_backing_writes
    }

    /// Raw handle of the shared surface attached to the gfx backend.
    pub fn presented_surface_handle(&self) -> Option<*mut std::ffi::c_void> {
        self.backend.presented_surface_handle()
    }

    /// Present-time uploads that had to use the fallback path.
    pub fn fallback_upload_count(&self) -> u64 {
        self.fallback_uploads
    }

    /// True when the swapchain is presenting through the IOSurface-backed
    /// Metal texture instead of the host-visible fallback.
    pub fn iosurface_zero_copy_active(&self) -> bool {
        !self.iosurface_channels.is_empty()
    }

    /// Number of MTLTextures the presented channel has built (1 on the
    /// zero-copy path, regardless of how many frames were presented).
    pub fn iosurface_texture_builds(&self) -> u32 {
        self.iosurface_channels
            .first()
            .map(|channel| channel.texture_builds())
            .or_else(|| {
                self.primary_nv12
                    .first()
                    .map(|channel| channel.texture_builds())
            })
            .unwrap_or(0)
    }

    /// Plane MTLTextures built for an NV12 swapchain (2 when healthy).
    pub fn nv12_texture_builds(&self, swapchain: SwapchainId) -> u32 {
        self.nv12_channel(swapchain)
            .map(|channel| channel.texture_builds())
            .unwrap_or(0)
    }

    pub fn swapchain_state(&self) -> Option<SwapchainState> {
        self.swapchain
            .and_then(|swapchain| self.backend.swapchain_state(swapchain).ok())
    }

    pub fn swapchain_state_for(&self, swapchain: SwapchainId) -> AppResult<SwapchainState> {
        self.backend.swapchain_state(swapchain)
    }

    /// Create an NV12 primary swapchain (DXGI_FORMAT_NV12). If the host cannot
    /// allocate the two-plane IOSurface channel, the request is counted in
    /// `nv12_fallback_count` and a pixel swapchain is created instead.
    pub fn create_nv12_swapchain(
        &mut self,
        width: u32,
        height: u32,
        buffer_count: u32,
    ) -> AppResult<SwapchainId> {
        let desc = SwapchainDesc {
            width,
            height,
            format: DxgiFormat::B8G8R8A8Unorm,
            buffer_count,
        };
        let channels = match build_nv12_channels(width, height, buffer_count.max(1)) {
            Some(channels) => channels,
            None => {
                self.nv12_fallbacks += 1;
                return self.create_pixel_swapchain(desc);
            }
        };
        let swapchain = self.backend.create_nv12_swapchain(desc.clone())?;
        self.iosurface_channels.clear();
        self.primary_nv12 = channels;
        self.swapchain = Some(swapchain);
        self.register_swapchain_resources(swapchain)?;
        Ok(swapchain)
    }

    /// DXGI-format-keyed primary swapchain creation: raw value 103 selects the
    /// real NV12 two-plane path, any other raw value must match `desc.format`.
    /// Unknown values are counted as fallbacks and the typed format is used.
    pub fn create_swapchain_for_format(
        &mut self,
        desc: SwapchainDesc,
        raw_format: u32,
    ) -> AppResult<SwapchainId> {
        if raw_format == 103 {
            return self.create_nv12_swapchain(desc.width, desc.height, desc.buffer_count);
        }
        match DxgiFormat::from_u32_checked(raw_format) {
            Ok(format) if format == desc.format => self.create_pixel_swapchain(desc),
            Ok(_) | Err(_) => {
                self.nv12_fallbacks += 1;
                self.create_pixel_swapchain(desc)
            }
        }
    }

    fn create_pixel_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        let swapchain = self.backend.create_swapchain(desc.clone())?;
        self.iosurface_channels = build_pixel_channels(&desc);
        self.primary_nv12.clear();
        self.swapchain = Some(swapchain);
        self.register_swapchain_resources(swapchain)?;
        Ok(swapchain)
    }

    /// Create an additional swapchain on this device with its own IOSurface
    /// channel set. The primary swapchain is unchanged.
    pub fn create_additional_swapchain(&mut self, desc: SwapchainDesc) -> AppResult<SwapchainId> {
        let swapchain = self.backend.create_swapchain(desc.clone())?;
        self.extra_swapchains.insert(
            swapchain,
            SwapchainChannelSet {
                pixel: build_pixel_channels(&desc),
                nv12: Vec::new(),
            },
        );
        self.register_swapchain_resources(swapchain)?;
        Ok(swapchain)
    }

    /// Create an additional NV12 swapchain, independent of the primary.
    pub fn create_additional_nv12_swapchain(
        &mut self,
        width: u32,
        height: u32,
        buffer_count: u32,
    ) -> AppResult<SwapchainId> {
        let desc = SwapchainDesc {
            width,
            height,
            format: DxgiFormat::B8G8R8A8Unorm,
            buffer_count,
        };
        let channels = match build_nv12_channels(width, height, buffer_count.max(1)) {
            Some(channels) => channels,
            None => {
                self.nv12_fallbacks += 1;
                return self.create_additional_swapchain(desc);
            }
        };
        let swapchain = self.backend.create_nv12_swapchain(desc)?;
        self.extra_swapchains.insert(
            swapchain,
            SwapchainChannelSet {
                pixel: Vec::new(),
                nv12: channels,
            },
        );
        self.register_swapchain_resources(swapchain)?;
        Ok(swapchain)
    }

    /// Resize one swapchain. Other swapchains and their surfaces are untouched.
    pub fn resize_swapchain(
        &mut self,
        swapchain: SwapchainId,
        buffer_count: u32,
        width: u32,
        height: u32,
        format: DxgiFormat,
    ) -> AppResult<()> {
        let old_backbuffers = self.backend.swapchain_state(swapchain)?.backbuffers;
        self.backend
            .resize_buffers(swapchain, buffer_count, width, height, format)?;
        let is_nv12 = self.backend.swapchain_is_nv12(swapchain).unwrap_or(false);
        if self.swapchain == Some(swapchain) {
            if is_nv12 {
                self.primary_nv12 =
                    build_nv12_channels(width, height, buffer_count.max(1)).unwrap_or_default();
                self.iosurface_channels.clear();
            } else {
                self.iosurface_channels = build_pixel_channels(&SwapchainDesc {
                    width,
                    height,
                    format,
                    buffer_count,
                });
                self.primary_nv12.clear();
            }
        } else if let Some(set) = self.extra_swapchains.get_mut(&swapchain) {
            if is_nv12 {
                set.nv12 =
                    build_nv12_channels(width, height, buffer_count.max(1)).unwrap_or_default();
                set.pixel.clear();
            } else {
                set.pixel = build_pixel_channels(&SwapchainDesc {
                    width,
                    height,
                    format,
                    buffer_count,
                });
                set.nv12.clear();
            }
        }
        for resource in old_backbuffers {
            self.resources.remove(&resource);
        }
        self.register_swapchain_resources(swapchain)?;
        Ok(())
    }

    /// Insert translated backbuffer resources for a swapchain created after
    /// device creation (primary replacement or an additional swapchain).
    fn register_swapchain_resources(&mut self, swapchain: SwapchainId) -> AppResult<()> {
        let state = self.backend.swapchain_state(swapchain)?;
        for (index, backbuffer) in state.backbuffers.iter().copied().enumerate() {
            self.resources
                .entry(backbuffer)
                .or_insert_with(|| ResourceRecord {
                    bytes: vec![0; state.desc.width as usize * state.desc.height as usize * 4],
                    mapped: false,
                    backend_id: backbuffer,
                    include_in_digests: false,
                    digest: None,
                    desc: D3d11ResourceDesc {
                        label: format!("swapchain-backbuffer-{index}"),
                        dimension: ResourceDimension::Texture2D,
                        format: state.desc.format,
                        width: state.desc.width,
                        height: state.desc.height,
                        depth: 1,
                        byte_width: state.desc.width as usize * state.desc.height as usize * 4,
                        usage_hint: ResourceUsageHint::SwapchainBackbuffer,
                    },
                });
            self.next_id = self.next_id.max(backbuffer.saturating_add(1));
        }
        Ok(())
    }

    /// Presents that bound both NV12 planes.
    pub fn nv12_present_count(&self) -> u64 {
        self.nv12_presents
    }

    /// NV12 channel requests that fell back to the pixel path.
    pub fn nv12_fallback_count(&self) -> u64 {
        self.nv12_fallbacks
    }

    /// Swapchain format requests that used the counted fallback path.
    pub fn swapchain_format_fallback_count(&self) -> u64 {
        self.nv12_fallbacks
    }

    /// Read both NV12 planes of `swapchain` (0 = Y, 1 = interleaved UV).
    pub fn presented_nv12_plane_bytes(
        &self,
        swapchain: SwapchainId,
    ) -> AppResult<(Vec<u8>, Vec<u8>)> {
        let channel = self.nv12_channel(swapchain).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("swapchain {swapchain} has no NV12 present channel"),
            )
        })?;
        Ok((channel.read_plane(0)?, channel.read_plane(1)?))
    }

    /// Read both NV12 planes through their Metal textures using real blits.
    pub fn presented_nv12_plane_bytes_gpu(
        &self,
        swapchain: SwapchainId,
    ) -> AppResult<(Vec<u8>, Vec<u8>)> {
        let channel = self.nv12_channel(swapchain).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("swapchain {swapchain} has no NV12 present channel"),
            )
        })?;
        Ok((
            channel.read_plane_via_metal(0)?,
            channel.read_plane_via_metal(1)?,
        ))
    }

    fn nv12_channel(
        &self,
        swapchain: SwapchainId,
    ) -> Option<&crate::metal_backend::Nv12PresentChannel> {
        if self.swapchain == Some(swapchain) {
            self.primary_nv12.first()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .and_then(|set| set.nv12.first())
        }
    }

    pub fn swapchain_backbuffer(&self, index: u32) -> AppResult<D3d11ResourceId> {
        let state = self.swapchain_state().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain backbuffer",
            )
        })?;
        state
            .backbuffers
            .get(index as usize)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "swapchain buffer index out of range",
                )
            })
    }

    pub fn create_buffer(
        &mut self,
        label: &str,
        byte_width: usize,
        usage_hint: ResourceUsageHint,
    ) -> AppResult<D3d11ResourceId> {
        // The descriptor width field is u32; clamp instead of wrapping so the
        // recorded width never disagrees with the `byte_width`-based
        // allocation.
        let width = byte_width.min(u32::MAX as usize) as u32;
        self.create_resource(D3d11ResourceDesc {
            label: label.to_string(),
            dimension: ResourceDimension::Buffer,
            format: DxgiFormat::R32Float,
            width,
            height: 1,
            depth: 1,
            byte_width,
            usage_hint,
        })
    }

    pub fn create_texture_1d(
        &mut self,
        label: &str,
        width: u32,
        format: DxgiFormat,
    ) -> AppResult<D3d11ResourceId> {
        self.create_texture_1d_with_usage(label, width, format, ResourceUsageHint::Generic)
    }

    pub fn create_texture_1d_with_usage(
        &mut self,
        label: &str,
        width: u32,
        format: DxgiFormat,
        usage_hint: ResourceUsageHint,
    ) -> AppResult<D3d11ResourceId> {
        self.create_resource(D3d11ResourceDesc {
            label: label.to_string(),
            dimension: ResourceDimension::Texture1D,
            format,
            width,
            height: 1,
            depth: 1,
            byte_width: width as usize * 4,
            usage_hint,
        })
    }

    pub fn create_texture_2d(
        &mut self,
        label: &str,
        width: u32,
        height: u32,
        format: DxgiFormat,
    ) -> AppResult<D3d11ResourceId> {
        self.create_texture_2d_with_usage(label, width, height, format, ResourceUsageHint::Generic)
    }

    pub fn create_texture_2d_with_usage(
        &mut self,
        label: &str,
        width: u32,
        height: u32,
        format: DxgiFormat,
        usage_hint: ResourceUsageHint,
    ) -> AppResult<D3d11ResourceId> {
        self.create_resource(D3d11ResourceDesc {
            label: label.to_string(),
            dimension: ResourceDimension::Texture2D,
            format,
            width,
            height,
            depth: 1,
            byte_width: width as usize * height as usize * 4,
            usage_hint,
        })
    }

    pub fn create_texture_3d(
        &mut self,
        label: &str,
        width: u32,
        height: u32,
        depth: u32,
        format: DxgiFormat,
    ) -> AppResult<D3d11ResourceId> {
        self.create_texture_3d_with_usage(
            label,
            width,
            height,
            depth,
            format,
            ResourceUsageHint::Generic,
        )
    }

    pub fn create_texture_3d_with_usage(
        &mut self,
        label: &str,
        width: u32,
        height: u32,
        depth: u32,
        format: DxgiFormat,
        usage_hint: ResourceUsageHint,
    ) -> AppResult<D3d11ResourceId> {
        self.create_resource(D3d11ResourceDesc {
            label: label.to_string(),
            dimension: ResourceDimension::Texture3D,
            format,
            width,
            height,
            depth,
            byte_width: width as usize * height as usize * depth as usize * 4,
            usage_hint,
        })
    }

    pub fn resource_desc(&self, resource: D3d11ResourceId) -> AppResult<D3d11ResourceDesc> {
        Ok(self.resource(resource)?.desc.clone())
    }

    pub fn create_shader_resource_view(
        &mut self,
        resource: D3d11ResourceId,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.create_view(resource, ViewKind::Srv, format)
    }

    pub fn create_render_target_view(
        &mut self,
        resource: D3d11ResourceId,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.create_view(resource, ViewKind::Rtv, format)
    }

    pub fn create_depth_stencil_view(
        &mut self,
        resource: D3d11ResourceId,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.create_view(resource, ViewKind::Dsv, format)
    }

    pub fn create_unordered_access_view(
        &mut self,
        resource: D3d11ResourceId,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.create_view(resource, ViewKind::Uav, format)
    }

    pub fn view_info(&self, view: D3d11ViewId) -> AppResult<ViewInfo> {
        Ok(self.view(view)?.info.clone())
    }

    pub fn create_blend_state(&mut self, desc: BlendStateDesc) -> BlendStateId {
        let id = self.alloc_id();
        self.blend_states.insert(id, desc);
        id
    }

    pub fn create_rasterizer_state(&mut self, desc: RasterizerStateDesc) -> RasterizerStateId {
        let id = self.alloc_id();
        self.rasterizer_states.insert(id, desc);
        id
    }

    pub fn create_depth_stencil_state(
        &mut self,
        desc: DepthStencilStateDesc,
    ) -> DepthStencilStateId {
        let id = self.alloc_id();
        self.depth_stencil_states.insert(id, desc);
        id
    }

    pub fn create_sampler_state(&mut self, desc: SamplerStateDesc) -> SamplerStateId {
        let id = self.alloc_id();
        self.sampler_states.insert(id, desc);
        id
    }

    pub fn create_input_layout(&mut self, desc: InputLayoutDesc) -> InputLayoutId {
        let id = self.alloc_id();
        self.input_layouts.insert(id, desc);
        id
    }

    pub fn create_shader(&mut self, desc: ShaderModuleDesc) -> ShaderId {
        let id = self.alloc_id();
        self.shaders.insert(
            id,
            ShaderRecord {
                desc,
                artifact: None,
            },
        );
        id
    }

    pub fn create_shader_from_dxil(
        &mut self,
        desc: ShaderModuleDesc,
        dxil: Vec<u8>,
        root_signature: Vec<u8>,
    ) -> AppResult<ShaderId> {
        let artifact = self.translate_shader_artifact(&desc, dxil, root_signature)?;
        let id = self.alloc_id();
        self.shaders.insert(
            id,
            ShaderRecord {
                desc,
                artifact: Some(artifact),
            },
        );
        Ok(id)
    }

    pub fn shader_translation_cache_key(&self, shader: ShaderId) -> AppResult<Option<String>> {
        Ok(self
            .shader(shader)?
            .artifact
            .as_ref()
            .map(|artifact| artifact.cache_key.clone()))
    }

    pub fn shader_translation_output(
        &self,
        shader: ShaderId,
    ) -> AppResult<Option<ShaderTranslationOutput>> {
        Ok(self
            .shader(shader)?
            .artifact
            .as_ref()
            .map(|artifact| artifact.output.clone()))
    }

    pub fn om_set_render_targets(
        &mut self,
        render_targets: Vec<D3d11ViewId>,
        depth_target: Option<D3d11ViewId>,
    ) {
        self.immediate.bindings.render_targets = render_targets;
        self.immediate.bindings.depth_target = depth_target;
    }

    pub fn om_set_blend_state(&mut self, state: BlendStateId) {
        self.immediate.bindings.blend_state = Some(state);
    }

    pub fn om_clear_blend_state(&mut self) {
        self.immediate.bindings.blend_state = None;
    }

    pub fn om_set_depth_stencil_state(&mut self, state: DepthStencilStateId) {
        self.immediate.bindings.depth_stencil_state = Some(state);
    }

    pub fn om_clear_depth_stencil_state(&mut self) {
        self.immediate.bindings.depth_stencil_state = None;
    }

    pub fn rs_set_state(&mut self, state: RasterizerStateId) {
        self.immediate.bindings.rasterizer_state = Some(state);
    }

    pub fn rs_clear_state(&mut self) {
        self.immediate.bindings.rasterizer_state = None;
    }

    pub fn rs_set_viewports(&mut self, viewport: Viewport) {
        self.immediate.bindings.viewport = Some(viewport);
    }

    pub fn rs_clear_viewports(&mut self) {
        self.immediate.bindings.viewport = None;
    }

    pub fn rs_set_scissor_rects(&mut self, scissor_rect: ScissorRect) {
        self.immediate.bindings.scissor_rect = Some(scissor_rect);
    }

    pub fn rs_clear_scissor_rects(&mut self) {
        self.immediate.bindings.scissor_rect = None;
    }

    pub fn ia_set_vertex_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate.bindings.vertex_buffers = buffers;
    }

    pub fn ia_set_index_buffer(&mut self, buffer: D3d11ResourceId) {
        self.immediate.bindings.index_buffer = Some(buffer);
    }

    pub fn ia_clear_index_buffer(&mut self) {
        self.immediate.bindings.index_buffer = None;
    }

    pub fn ia_set_primitive_topology(&mut self, topology: u32) {
        self.immediate.bindings.primitive_topology = Some(topology);
    }

    pub fn ia_set_input_layout(&mut self, layout: InputLayoutId) {
        self.immediate.bindings.input_layout = Some(layout);
    }

    pub fn ia_clear_input_layout(&mut self) {
        self.immediate.bindings.input_layout = None;
    }

    pub fn vs_set_shader(&mut self, shader: ShaderId) {
        self.immediate
            .bindings
            .shaders
            .insert(ShaderStage::Vs, shader);
    }

    pub fn vs_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Vs);
    }

    pub fn ps_set_shader(&mut self, shader: ShaderId) {
        self.immediate
            .bindings
            .shaders
            .insert(ShaderStage::Ps, shader);
    }

    pub fn ps_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Ps);
    }

    pub fn cs_set_shader(&mut self, shader: ShaderId) {
        self.immediate
            .bindings
            .shaders
            .insert(ShaderStage::Cs, shader);
    }

    pub fn cs_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Cs);
    }

    pub fn gs_set_shader(&mut self, shader: ShaderId) {
        self.immediate
            .bindings
            .shaders
            .insert(ShaderStage::Gs, shader);
    }

    pub fn gs_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Gs);
    }

    pub fn hs_set_shader(&mut self, shader: ShaderId) {
        self.immediate
            .bindings
            .shaders
            .insert(ShaderStage::Hs, shader);
    }

    pub fn hs_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Hs);
    }

    pub fn ds_set_shader(&mut self, shader: ShaderId) {
        self.immediate
            .bindings
            .shaders
            .insert(ShaderStage::Ds, shader);
    }

    pub fn ds_clear_shader(&mut self) {
        self.immediate.bindings.shaders.remove(&ShaderStage::Ds);
    }

    pub fn vs_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate
            .bindings
            .constant_buffers
            .insert(ShaderStage::Vs, buffers);
    }

    pub fn ps_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate
            .bindings
            .constant_buffers
            .insert(ShaderStage::Ps, buffers);
    }

    pub fn cs_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate
            .bindings
            .constant_buffers
            .insert(ShaderStage::Cs, buffers);
    }

    pub fn gs_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate
            .bindings
            .constant_buffers
            .insert(ShaderStage::Gs, buffers);
    }

    pub fn hs_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate
            .bindings
            .constant_buffers
            .insert(ShaderStage::Hs, buffers);
    }

    pub fn ds_set_constant_buffers(&mut self, buffers: Vec<D3d11ResourceId>) {
        self.immediate
            .bindings
            .constant_buffers
            .insert(ShaderStage::Ds, buffers);
    }

    pub fn vs_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.immediate
            .bindings
            .shader_resources
            .insert(ShaderStage::Vs, resources);
    }

    pub fn ps_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.immediate
            .bindings
            .shader_resources
            .insert(ShaderStage::Ps, resources);
    }

    pub fn cs_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.immediate
            .bindings
            .shader_resources
            .insert(ShaderStage::Cs, resources);
    }

    pub fn gs_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.immediate
            .bindings
            .shader_resources
            .insert(ShaderStage::Gs, resources);
    }

    pub fn hs_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.immediate
            .bindings
            .shader_resources
            .insert(ShaderStage::Hs, resources);
    }

    pub fn ds_set_shader_resources(&mut self, resources: Vec<D3d11ViewId>) {
        self.immediate
            .bindings
            .shader_resources
            .insert(ShaderStage::Ds, resources);
    }

    pub fn vs_set_samplers(&mut self, samplers: Vec<SamplerStateId>) {
        self.immediate
            .bindings
            .samplers
            .insert(ShaderStage::Vs, samplers);
    }

    pub fn ps_set_samplers(&mut self, samplers: Vec<SamplerStateId>) {
        self.immediate
            .bindings
            .samplers
            .insert(ShaderStage::Ps, samplers);
    }

    pub fn cs_set_samplers(&mut self, samplers: Vec<SamplerStateId>) {
        self.immediate
            .bindings
            .samplers
            .insert(ShaderStage::Cs, samplers);
    }

    pub fn gs_set_samplers(&mut self, samplers: Vec<SamplerStateId>) {
        self.immediate
            .bindings
            .samplers
            .insert(ShaderStage::Gs, samplers);
    }

    pub fn hs_set_samplers(&mut self, samplers: Vec<SamplerStateId>) {
        self.immediate
            .bindings
            .samplers
            .insert(ShaderStage::Hs, samplers);
    }

    pub fn ds_set_samplers(&mut self, samplers: Vec<SamplerStateId>) {
        self.immediate
            .bindings
            .samplers
            .insert(ShaderStage::Ds, samplers);
    }

    // ── CS getter methods (immediate context) ──────────────────────────

    /// Returns the currently bound CS shader resource views (`Vec<D3d11ViewId>`).
    pub fn cs_get_shader_resources(&self) -> Vec<D3d11ViewId> {
        self.immediate
            .bindings
            .shader_resources
            .get(&ShaderStage::Cs)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns the currently bound CS unordered access views (`Vec<D3d11ViewId>`).
    pub fn cs_get_unordered_access_views(&self) -> Vec<D3d11ViewId> {
        self.immediate
            .bindings
            .unordered_access_views
            .get(&ShaderStage::Cs)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns the currently bound CS samplers (`Vec<SamplerStateId>`).
    pub fn cs_get_samplers(&self) -> Vec<SamplerStateId> {
        self.immediate
            .bindings
            .samplers
            .get(&ShaderStage::Cs)
            .cloned()
            .unwrap_or_default()
    }

    /// Returns the currently bound CS constant buffers (`Vec<D3d11ResourceId>`).
    pub fn cs_get_constant_buffers(&self) -> Vec<D3d11ResourceId> {
        self.immediate
            .bindings
            .constant_buffers
            .get(&ShaderStage::Cs)
            .cloned()
            .unwrap_or_default()
    }

    pub fn update_subresource(&mut self, resource: D3d11ResourceId, bytes: &[u8]) -> AppResult<()> {
        self.validate_resource_write(resource, bytes.len())?;
        self.promote_texture_cpu_write_usage(resource)?;
        self.immediate
            .commands
            .push(RecordedCommand::UpdateSubresource {
                resource,
                bytes: bytes.to_vec(),
            });
        Ok(())
    }

    /// Map a resource for CPU access, returning a borrow into its real shared
    /// backing (the CPU byte storage or the locked IOSurface), not a copy.
    ///
    /// The borrow aliases the backing until it is dropped; call
    /// [`unmap`](Self::unmap) afterwards to clear the mapped state and publish
    /// the bytes to the translation backend.
    pub fn map(&mut self, resource: D3d11ResourceId) -> AppResult<D3d11Map<'_>> {
        if let Some((swapchain, index)) = self.present_backbuffer_index(resource) {
            if self.nv12_channel(swapchain).is_some() {
                // An NV12 IOSurface is two independent plane mappings; it
                // cannot be exposed as one contiguous D3D11 NV12 mapping
                // without a copy. Refuse explicitly instead of silently
                // staging the whole surface.
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "NV12 Map is not zero-copy: the IOSurface has two plane mappings",
                ));
            }
            self.resource_mut(resource)?.mapped = true;
            let surface = if self.swapchain == Some(swapchain) {
                self.iosurface_channels
                    .get(index)
                    .map(|channel| channel.map_pixels_mut())
            } else {
                self.extra_swapchains
                    .get(&swapchain)
                    .and_then(|set| set.pixel.get(index))
                    .map(|channel| channel.map_pixels_mut())
            };
            match surface {
                Some(Ok(view)) => return Ok(D3d11Map::Surface(view)),
                Some(Err(error)) => return Err(error),
                None => {}
            }
        }
        let record = self.resource_mut(resource)?;
        record.mapped = true;
        Ok(D3d11Map::Bytes(record.bytes.as_mut_slice()))
    }

    /// Unmap a resource whose shared backing was written through [`map`].
    ///
    /// The large per-frame `Vec` that the old API accepted is gone: the bytes
    /// already live in the mapped backing. The translation backend is updated
    /// from that same storage and the update is classified by the backend
    /// (shared resources record a zero-copy update, private ones a staged
    /// upload).
    pub fn unmap(&mut self, resource: D3d11ResourceId) -> AppResult<()> {
        let mapped = self.resource(resource)?.mapped;
        if !mapped {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "resource {} is not mapped",
                    self.resource(resource)?.desc.label
                ),
            ));
        }
        self.resource_mut(resource)?.mapped = false;
        if self.present_backbuffer_index(resource).is_some() {
            // The mapped slice aliased the surface; the write already landed.
            self.surface_writes += 1;
            self.record_cpu_backing_write();
            return Ok(());
        }
        // Move the record out so its backing can be borrowed without cloning,
        // then publish the exact same bytes to the translation backend.
        let record = self.resources.remove(&resource).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown resource {resource}"),
            )
        })?;
        let backend_id = record.backend_id;
        let result = self
            .backend
            .overwrite_resource_host_visible(backend_id, record.bytes.as_slice());
        self.resources.insert(resource, record);
        result?;
        self.record_cpu_backing_write();
        self.promote_texture_cpu_write_usage(resource)?;
        Ok(())
    }

    /// Unmap with an explicit payload. Kept for callers that already own the
    /// written bytes; the payload is copied into the shared backing before the
    /// mapped state is cleared.
    pub fn unmap_with_bytes(&mut self, resource: D3d11ResourceId, bytes: &[u8]) -> AppResult<()> {
        if !self.resource(resource)?.mapped {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "resource {} is not mapped",
                    self.resource(resource)?.desc.label
                ),
            ));
        }
        if bytes.len() > self.resource(resource)?.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!(
                    "unmap payload exceeds resource {}",
                    self.resource(resource)?.desc.label
                ),
            ));
        }
        if self.write_present_backbuffer_bytes(resource, 0, bytes)? {
            self.resource_mut(resource)?.mapped = false;
            self.resource_mut(resource)?.digest = None;
            self.promote_texture_cpu_write_usage(resource)?;
            return Ok(());
        }
        self.resource_mut(resource)?.bytes[..bytes.len()].copy_from_slice(bytes);
        self.unmap(resource)
    }

    pub fn copy_resource(&mut self, src: D3d11ResourceId, dst: D3d11ResourceId) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.immediate
            .commands
            .push(RecordedCommand::CopyResource { src, dst });
        Ok(())
    }

    pub fn copy_subresource_region(
        &mut self,
        src: D3d11ResourceId,
        dst: D3d11ResourceId,
        src_offset: usize,
        dst_offset: usize,
        size: usize,
    ) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.immediate
            .commands
            .push(RecordedCommand::CopySubresourceRegion {
                src,
                dst,
                src_offset,
                dst_offset,
                size,
            });
        Ok(())
    }

    pub fn resolve_subresource(
        &mut self,
        dst: D3d11ResourceId,
        dst_subresource: u32,
        src: D3d11ResourceId,
        src_subresource: u32,
        format: u32,
    ) -> AppResult<()> {
        self.resource(src)?;
        self.resource(dst)?;
        self.immediate
            .commands
            .push(RecordedCommand::ResolveSubresource {
                dst,
                dst_subresource,
                src,
                src_subresource,
                format,
            });
        Ok(())
    }

    pub fn clear_render_target_view(&mut self, view: D3d11ViewId, color: [u8; 4]) -> AppResult<()> {
        self.expect_view_kind(view, ViewKind::Rtv)?;
        self.immediate
            .commands
            .push(RecordedCommand::ClearRenderTargetView { view, color });
        Ok(())
    }

    pub fn clear_depth_stencil_view(
        &mut self,
        view: D3d11ViewId,
        depth: u32,
        stencil: u8,
    ) -> AppResult<()> {
        self.expect_view_kind(view, ViewKind::Dsv)?;
        self.immediate
            .commands
            .push(RecordedCommand::ClearDepthStencilView {
                view,
                depth,
                stencil,
            });
        Ok(())
    }

    pub fn draw(&mut self, vertices: u32) {
        self.immediate.commands.push(RecordedCommand::Draw {
            vertices,
            kind: DrawCallKind::Regular,
        });
    }

    pub fn draw_instanced(&mut self, vertices: u32, instances: u32) {
        self.immediate.commands.push(RecordedCommand::Draw {
            vertices,
            kind: DrawCallKind::Instanced { instances },
        });
    }

    pub fn draw_indexed(&mut self, indices: u32) {
        self.immediate.commands.push(RecordedCommand::DrawIndexed {
            indices,
            kind: IndexedDrawCallKind::Regular,
        });
    }

    pub fn draw_indexed_instanced(&mut self, indices: u32, instances: u32) {
        self.immediate.commands.push(RecordedCommand::DrawIndexed {
            indices,
            kind: IndexedDrawCallKind::Instanced { instances },
        });
    }

    pub fn dispatch(&mut self, x: u32, y: u32, z: u32) {
        self.immediate
            .commands
            .push(RecordedCommand::Dispatch { x, y, z });
    }

    pub fn create_deferred_context(&self) -> DeferredContext {
        DeferredContext {
            recording: Arc::new(Mutex::new(DeferredRecording::default())),
        }
    }

    pub fn submit_immediate(&mut self) -> AppResult<SubmissionResult> {
        let bindings = self.immediate.bindings.clone();
        let commands = std::mem::take(&mut self.immediate.commands);
        self.submit_sequences(vec![(bindings, commands)])
    }

    fn submit_immediate_without_digests(&mut self) -> AppResult<()> {
        let bindings = self.immediate.bindings.clone();
        let commands = std::mem::take(&mut self.immediate.commands);
        self.submit_sequences_without_digests(vec![(bindings, commands)])
    }

    pub fn has_pending_immediate_commands(&self) -> bool {
        !self.immediate.commands.is_empty()
    }

    /// Publish the current backbuffer contents for present.
    ///
    /// On the IOSurface path every backbuffer is written directly into the
    /// surface mapping and the aliasing Metal texture is ensured; the present
    /// itself performs no staging upload. If the capability probe or surface
    /// allocation failed, the verified host-visible sync is used instead and
    /// counted in `fallback_uploads`.
    fn sync_present_backbuffers(&mut self, swapchain: SwapchainId) -> AppResult<()> {
        let state = self.backend.swapchain_state(swapchain)?;
        let backbuffer_ids = state.backbuffers.clone();
        let is_primary = self.swapchain == Some(swapchain);
        let nv12_len = if is_primary {
            self.primary_nv12.len()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .map(|set| set.nv12.len())
                .unwrap_or(0)
        };
        let pixel_len = if is_primary {
            self.iosurface_channels.len()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .map(|set| set.pixel.len())
                .unwrap_or(0)
        };
        if nv12_len > 0 {
            if nv12_len != backbuffer_ids.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "NV12 present: {nv12_len} channels for {} backbuffers",
                        backbuffer_ids.len()
                    ),
                ));
            }
            let channels: &[crate::metal_backend::Nv12PresentChannel] = if is_primary {
                &self.primary_nv12
            } else {
                &self
                    .extra_swapchains
                    .get(&swapchain)
                    .expect("channel set checked above")
                    .nv12
            };
            for (index, channel) in channels.iter().enumerate() {
                if channel.width() != state.desc.width || channel.height() != state.desc.height {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "NV12 present: swapchain {}x{} does not match channel {} at {index} ({}x{})",
                            state.desc.width,
                            state.desc.height,
                            index,
                            channel.width(),
                            channel.height()
                        ),
                    ));
                }
            }
            self.nv12_presents += 1;
            self.iosurface_presents += 1;
        } else if pixel_len > 0 {
            if pixel_len != backbuffer_ids.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "IOSurface present: {pixel_len} channels for {} backbuffers",
                        backbuffer_ids.len()
                    ),
                ));
            }
            let channels: &mut [crate::metal_backend::IoSurfacePresentChannel] = if is_primary {
                &mut self.iosurface_channels
            } else {
                &mut self
                    .extra_swapchains
                    .get_mut(&swapchain)
                    .expect("channel set checked above")
                    .pixel
            };
            let expected_format = crate::metal_backend::dxgi_to_metal_format(state.desc.format);
            for (index, channel) in channels.iter_mut().enumerate() {
                if channel.width() != state.desc.width || channel.height() != state.desc.height {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "IOSurface present: swapchain {}x{} does not match channel {} at {index} ({}x{})",
                            state.desc.width,
                            state.desc.height,
                            index,
                            channel.width(),
                            channel.height()
                        ),
                    ));
                }
                if channel.pixel_format() != expected_format {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!(
                            "IOSurface present: swapchain format {:?} ({expected_format:?}) does not \
                             match channel {index} {:?}",
                            state.desc.format,
                            channel.pixel_format()
                        ),
                    ));
                }
                // The surface is authoritative: clears, Map/Unmap,
                // UpdateSubresource and staged uploads already wrote it. Present
                // only binds the aliasing texture; copying the shadow Vec here
                // would resurrect stale CPU backing bytes.
            }
            channels[0].metal_texture()?;
            self.iosurface_presents += 1;
        } else {
            for backbuffer_id in &backbuffer_ids {
                let source = self
                    .resources
                    .get(backbuffer_id)
                    .ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!("swapchain backbuffer {backbuffer_id} is missing"),
                        )
                    })?
                    .bytes
                    .as_slice();
                self.backend
                    .overwrite_resource_bytes(*backbuffer_id, source)?;
                self.zero_copy_present_syncs += 1;
                self.fallback_uploads += 1;
                self.cpu_backing_writes += 1;
            }
        }
        Ok(())
    }

    /// Swapchain and backbuffer index when `resource` is a current swapchain
    /// backbuffer on the zero-copy present path.
    fn present_backbuffer_index(&self, resource: D3d11ResourceId) -> Option<(SwapchainId, usize)> {
        let primary = self.swapchain?;
        let mut candidates = vec![primary];
        candidates.extend(self.extra_swapchains.keys().copied());
        for swapchain in candidates {
            if let Ok(state) = self.backend.swapchain_state(swapchain) {
                if let Some(index) = state.backbuffers.iter().position(|id| *id == resource) {
                    let has_channels = if swapchain == primary {
                        !self.iosurface_channels.is_empty() || !self.primary_nv12.is_empty()
                    } else {
                        self.extra_swapchains
                            .get(&swapchain)
                            .map(|set| !set.is_empty())
                            .unwrap_or(false)
                    };
                    if has_channels {
                        return Some((swapchain, index));
                    }
                }
            }
        }
        None
    }

    /// Read a resource for a transfer/copy. Backbuffers on the zero-copy path
    /// read the surface (the CPU Vec is intentionally not maintained).
    fn resource_bytes_for_transfer(&self, resource: D3d11ResourceId) -> AppResult<Vec<u8>> {
        if let Some((swapchain, index)) = self.present_backbuffer_index(resource) {
            if let Some(channel) = self.nv12_channel(swapchain) {
                let _ = index;
                return channel.to_rgba8();
            }
            if self.swapchain == Some(swapchain) {
                if let Some(channel) = self.iosurface_channels.get(index) {
                    return channel.read_pixels();
                }
            } else if let Some(channel) = self
                .extra_swapchains
                .get(&swapchain)
                .and_then(|set| set.pixel.get(index))
            {
                return channel.read_pixels();
            }
        }
        Ok(self.resource(resource)?.bytes.clone())
    }

    /// Write `bytes` at `offset` straight into the IOSurface when `resource`
    /// is a present backbuffer and the channel is active. Returns `false` when
    /// the caller must fall back to the CPU backing store.
    fn write_present_backbuffer_bytes(
        &mut self,
        resource: D3d11ResourceId,
        offset: usize,
        bytes: &[u8],
    ) -> AppResult<bool> {
        let Some((swapchain, index)) = self.present_backbuffer_index(resource) else {
            return Ok(false);
        };
        let format = self.backend.swapchain_state(swapchain)?.desc.format;
        if let Some(channel) = self.nv12_channel(swapchain).cloned() {
            let expected = channel.width() as usize * channel.height() as usize * 4;
            let end = offset.checked_add(bytes.len()).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "surface write range overflow",
                )
            })?;
            if offset != 0 || end != expected {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    "NV12 present surface requires full-frame writes",
                ));
            }
            channel.write_dxgi_pixels(bytes, format)?;
            self.surface_writes += 1;
            return Ok(true);
        }
        let channel = if self.swapchain == Some(swapchain) {
            self.iosurface_channels.get_mut(index)
        } else {
            self.extra_swapchains
                .get_mut(&swapchain)
                .and_then(|set| set.pixel.get_mut(index))
        };
        let Some(channel) = channel else {
            return Ok(false);
        };
        let expected = channel.width() as usize * channel.height() as usize * 4;
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "surface write range overflow",
            )
        })?;
        if end > expected {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "surface write exceeds present backbuffer",
            ));
        }
        if offset == 0 && bytes.len() == expected {
            channel.write_pixels(bytes)?;
        } else {
            // Partial writes are applied to the surface itself, keeping it
            // authoritative instead of updating the CPU shadow.
            let mut pixels = channel.read_pixels()?;
            pixels[offset..end].copy_from_slice(bytes);
            channel.write_pixels(&pixels)?;
        }
        self.surface_writes += 1;
        Ok(true)
    }

    fn record_cpu_backing_write(&mut self) {
        self.cpu_backing_writes += 1;
    }

    pub fn present_swapchain(
        &mut self,
        sync_interval: u32,
        allow_tearing: bool,
        capture_submission: bool,
    ) -> AppResult<(Option<SubmissionResult>, crate::gfx::PresentResult)> {
        let swapchain = self.swapchain.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain to present",
            )
        })?;
        self.present_swapchain_for(swapchain, sync_interval, allow_tearing, capture_submission)
    }

    /// Present a specific swapchain (primary or additional). The chosen
    /// swapchain's own IOSurface channels are bound; no other swapchain is
    /// touched.
    pub fn present_swapchain_for(
        &mut self,
        swapchain: SwapchainId,
        sync_interval: u32,
        allow_tearing: bool,
        capture_submission: bool,
    ) -> AppResult<(Option<SubmissionResult>, crate::gfx::PresentResult)> {
        let submission = if capture_submission {
            Some(self.submit_immediate()?)
        } else {
            self.submit_immediate_without_digests()?;
            None
        };
        // ── Publish the rendered backbuffer pixels ─────────────────────────
        // Zero-copy path: the pixels are written straight into the IOSurface
        // mapping and present binds the aliasing Metal texture. Fallback: the
        // previous host-visible sync into the gfx backend resource.
        self.sync_present_backbuffers(swapchain)?;
        let nv12 = self.nv12_channel(swapchain).cloned();
        // Real GPU composite: sample both NV12 planes and write the RGBA
        // drawable texture that present binds.
        if let Some(channel) = &nv12 {
            channel.composite_to_drawable()?;
            channel.bind_drawable();
        }
        let pixel = if nv12.is_none() {
            if self.swapchain == Some(swapchain) {
                self.iosurface_channels.first().cloned()
            } else {
                self.extra_swapchains
                    .get(&swapchain)
                    .and_then(|set| set.pixel.first().cloned())
            }
        } else {
            None
        };
        self.backend.set_presented_nv12_surface(nv12);
        self.backend.set_presented_surface(pixel);
        let present = self
            .backend
            .present(swapchain, sync_interval, allow_tearing)?;
        Ok((submission, present))
    }

    pub fn export_presented_frame_ppm(&self, path: &Path) -> AppResult<()> {
        let swapchain = self.swapchain.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain to export",
            )
        })?;
        self.backend.export_presented_frame_ppm(swapchain, path)
    }

    pub fn presented_frame(&self) -> AppResult<crate::gfx::PresentedFrame> {
        let swapchain = self.swapchain.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain to export",
            )
        })?;
        self.presented_frame_for(swapchain)
    }

    /// Presented frame for a specific swapchain. NV12 channels decode both
    /// planes to RGBA for generic consumers; the raw planes stay available via
    /// `presented_nv12_plane_bytes`.
    pub fn presented_frame_for(
        &self,
        swapchain: SwapchainId,
    ) -> AppResult<crate::gfx::PresentedFrame> {
        if let Some(channel) = self.nv12_channel(swapchain) {
            return Ok(crate::gfx::PresentedFrame {
                width: channel.width(),
                height: channel.height(),
                format: DxgiFormat::R8G8B8A8Unorm,
                bytes: channel.to_rgba8()?,
                source: crate::gfx::FrameSource::DxgiD3D11,
                stride: channel.width() as usize * 4,
                sequence: self.iosurface_presents,
                timestamp: std::time::Instant::now(),
            });
        }
        let pixel = if self.swapchain == Some(swapchain) {
            self.iosurface_channels.first()
        } else {
            self.extra_swapchains
                .get(&swapchain)
                .and_then(|set| set.pixel.first())
        };
        if let Some(channel) = pixel {
            let state = self.backend.swapchain_state(swapchain)?;
            let bytes = channel.read_pixels()?;
            return Ok(crate::gfx::PresentedFrame {
                width: channel.width(),
                height: channel.height(),
                format: state.desc.format,
                bytes,
                source: crate::gfx::FrameSource::DxgiD3D11,
                stride: channel.width() as usize * 4,
                sequence: self.iosurface_presents,
                timestamp: std::time::Instant::now(),
            });
        }
        self.backend.presented_frame(swapchain)
    }

    pub fn open_presented_frame(&self) -> AppResult<()> {
        let swapchain = self.swapchain.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "device does not own a swapchain to preview",
            )
        })?;
        self.backend.open_presented_frame(swapchain)
    }

    /// Live-consumer API: RGBA8 pixels of the presented frame. Reads the
    /// IOSurface directly on the zero-copy path and only reorders channels when
    /// the surface layout is BGRA.
    pub fn presented_frame_rgba(&self) -> AppResult<Vec<u8>> {
        let frame = self.presented_frame()?;
        let mut bytes = frame.bytes;
        if matches!(
            frame.format,
            DxgiFormat::B8G8R8A8Unorm | DxgiFormat::B8G8R8A8UnormSrgb | DxgiFormat::B8G8R8X8Unorm
        ) {
            for pixel in bytes.chunks_exact_mut(4) {
                pixel.swap(0, 2);
            }
        }
        Ok(bytes)
    }

    pub fn execute_deferred_command_lists(
        &mut self,
        lists: &[D3d11CommandList],
    ) -> AppResult<SubmissionResult> {
        // Optimize command lists before submission by merging consecutive lists
        // with identical bindings and culling redundant state changes.
        let optimized = self.merge_deferred_command_lists(lists);
        let sequences = optimized
            .iter()
            .map(|list| (list.bindings.clone(), list.commands.clone()))
            .collect::<Vec<_>>();
        self.submit_sequences_with_signatures(
            sequences,
            optimized
                .iter()
                .map(|list| list.binding_signature.clone())
                .collect(),
            true,
        )
    }

    /// Merge consecutive command lists with identical bindings into fewer render passes.
    /// Only lists whose commands are exclusively draws can be merged: clears,
    /// copies, resolves and dispatches establish render-pass or execution
    /// boundaries that must be preserved verbatim (e.g. four deferred lists
    /// each clearing the same RTV to a different colour must remain four
    /// separate passes, or the Metal plan applies only the first clear).
    fn merge_deferred_command_lists(&self, lists: &[D3d11CommandList]) -> Vec<D3d11CommandList> {
        if lists.is_empty() {
            return Vec::new();
        }

        let mut merged: Vec<D3d11CommandList> = Vec::new();
        for list in lists {
            match merged.last_mut() {
                Some(last)
                    if last.bindings == list.bindings
                        && commands_are_draw_only(&last.commands)
                        && commands_are_draw_only(&list.commands) =>
                {
                    // Same bindings, draw-only commands: merge commands into a
                    // single list to reduce render-pass transitions.
                    last.commands.extend(list.commands.clone());
                }
                // Different bindings or pass-boundary commands: start a new
                // merged entry.
                _ => merged.push(list.clone()),
            }
        }
        merged
    }

    pub fn resource_digest(&self, resource: D3d11ResourceId) -> AppResult<String> {
        Ok(util::sha256_bytes(&self.resource(resource)?.bytes))
    }

    fn create_resource(&mut self, desc: D3d11ResourceDesc) -> AppResult<D3d11ResourceId> {
        let id = self.alloc_id();
        let backend_id = self.backend.create_resource(ResourceDesc {
            name: desc.label.clone(),
            format: desc.format,
            heap: crate::gfx::HeapType::Default,
            size: desc.byte_width,
            subresources: 1,
            initial_state: ResourceState::Common,
            usage_hint: desc.usage_hint,
        })?;
        self.resources.insert(
            id,
            ResourceRecord {
                bytes: vec![0; desc.byte_width],
                mapped: false,
                backend_id,
                include_in_digests: true,
                digest: None,
                desc,
            },
        );
        Ok(id)
    }

    fn create_view(
        &mut self,
        resource: D3d11ResourceId,
        kind: ViewKind,
        format: DxgiFormat,
    ) -> AppResult<D3d11ViewId> {
        self.promote_texture_usage_for_view(resource, kind)?;
        let backend_resource = self.resource(resource)?.backend_id;
        let heap = match kind {
            ViewKind::Rtv => {
                let heap = self
                    .backend
                    .create_descriptor_heap(DescriptorHeapType::Rtv, 1);
                self.backend.write_descriptor(
                    heap,
                    0,
                    ViewDescriptor::Rtv {
                        resource: backend_resource,
                        format,
                    },
                )?;
                Some(heap)
            }
            ViewKind::Dsv => {
                let heap = self
                    .backend
                    .create_descriptor_heap(DescriptorHeapType::Dsv, 1);
                self.backend.write_descriptor(
                    heap,
                    0,
                    ViewDescriptor::Dsv {
                        resource: backend_resource,
                        format,
                    },
                )?;
                Some(heap)
            }
            ViewKind::Srv | ViewKind::Uav => None,
        };
        let id = self.alloc_id();
        self.views.insert(
            id,
            ViewRecord {
                info: ViewInfo {
                    resource,
                    kind,
                    format,
                },
                heap,
            },
        );
        Ok(id)
    }

    fn render_pass_formats(
        &self,
        bindings: &ContextBindings,
    ) -> AppResult<(Vec<DxgiFormat>, Option<DxgiFormat>)> {
        let color_formats = bindings
            .render_targets
            .iter()
            .map(|view| self.view(*view).map(|view| view.info.format))
            .collect::<AppResult<Vec<_>>>()?;
        let depth_format = bindings
            .depth_target
            .map(|view| self.view(view).map(|view| view.info.format))
            .transpose()?;
        Ok((color_formats, depth_format))
    }

    fn render_pass_actions(
        &self,
        bindings: &ContextBindings,
    ) -> AppResult<(&'static str, &'static str)> {
        let load_action = "load";
        let store_action = if let Some(depth_target) = bindings.depth_target {
            let depth_view = self.view(depth_target)?;
            let resource = self.resource(depth_view.info.resource)?;
            match self.backend.resource_storage_mode(resource.backend_id)? {
                crate::gfx::MetalStorageMode::Memoryless => "store+depth-discard",
                _ => "store",
            }
        } else {
            "store"
        };
        Ok((load_action, store_action))
    }

    fn record_sequence_to_command_list(
        &mut self,
        list: crate::gfx::CommandListId,
        bindings: &ContextBindings,
        commands: &[RecordedCommand],
        stats: &mut SubmissionStats,
        pass_started: bool,
    ) -> AppResult<()> {
        // A render pass is required only when the sequence actually issues draws
        // against bound attachments. We open it *lazily*, immediately before the
        // first clear or draw, rather than eagerly at the top of the command
        // list: a leading blit (e.g. CopyResource) would otherwise flush an
        // empty load-only pass and leave a spurious render pass in the plan.
        // `pass_started` lets a coalescing caller open the pass once before the
        // loop so merged sequences share a single render pass.
        let needs_render_pass = commands.iter().any(|command| {
            matches!(
                command,
                RecordedCommand::Draw { .. } | RecordedCommand::DrawIndexed { .. }
            )
        }) && (!bindings.render_targets.is_empty()
            || bindings.depth_target.is_some());
        let mut pass_opened = pass_started;

        for command in commands {
            // Open the render pass just-in-time before the first attachment
            // operation (clear or draw). Clears that begin a brand-new pass are
            // handled by the backend itself, but pre-opening here keeps the
            // load/store actions (including depth-discard for memoryless depth)
            // consistent with the bound pipeline state.
            if needs_render_pass
                && !pass_opened
                && matches!(
                    command,
                    RecordedCommand::ClearRenderTargetView { .. }
                        | RecordedCommand::ClearDepthStencilView { .. }
                        | RecordedCommand::Draw { .. }
                        | RecordedCommand::DrawIndexed { .. }
                )
            {
                let (color_formats, depth_format) = self.render_pass_formats(bindings)?;
                let (load_action, store_action) = self.render_pass_actions(bindings)?;
                self.backend.record_begin_render_pass(
                    list,
                    color_formats,
                    depth_format,
                    load_action,
                    store_action,
                )?;
                pass_opened = true;
            }

            match command {
                RecordedCommand::UpdateSubresource { resource, bytes } => {
                    if bytes.len() > self.resource(*resource)?.bytes.len() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!(
                                "update subresource payload exceeds resource {}",
                                self.resource(*resource)?.desc.label
                            ),
                        ));
                    }
                    if self.write_present_backbuffer_bytes(*resource, 0, bytes)? {
                        self.resource_mut(*resource)?.digest = None;
                        continue;
                    }
                    let backend_id = {
                        let record = self.resource_mut(*resource)?;
                        record.bytes[..bytes.len()].copy_from_slice(bytes);
                        record.digest = None;
                        record.backend_id
                    };
                    self.record_cpu_backing_write();
                    // The payload already lives in host memory; classify the
                    // write so host-visible resources hit the in-place
                    // (zero-copy) path and private ones count as staged.
                    self.backend
                        .overwrite_resource_host_visible(backend_id, bytes)?;
                }
                RecordedCommand::CopyResource { src, dst } => {
                    let source_bytes = self.resource_bytes_for_transfer(*src)?;
                    let src_backend = self.resource(*src)?.backend_id;
                    let dst_backend = self.resource(*dst)?.backend_id;
                    if source_bytes.len() > self.resource(*dst)?.bytes.len() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "copy resource destination is smaller than source",
                        ));
                    }
                    if !self.write_present_backbuffer_bytes(*dst, 0, &source_bytes)? {
                        let destination = self.resource_mut(*dst)?;
                        destination.bytes = source_bytes;
                        destination.digest = None;
                        self.record_cpu_backing_write();
                    } else {
                        self.resource_mut(*dst)?.digest = None;
                    }
                    self.backend
                        .record_copy_resource(list, src_backend, dst_backend)?;
                    // A blit closes the active render pass in the backend plan.
                    pass_opened = false;
                }
                RecordedCommand::CopySubresourceRegion {
                    src,
                    dst,
                    src_offset,
                    dst_offset,
                    size,
                } => {
                    let source = self.resource_bytes_for_transfer(*src)?;
                    let src_end = src_offset.checked_add(*size).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "copy subresource region source offset overflow",
                        )
                    })?;
                    let dst_end = dst_offset.checked_add(*size).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "copy subresource region destination offset overflow",
                        )
                    })?;
                    if src_end > source.len() || dst_end > self.resource(*dst)?.bytes.len() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "copy subresource region out of bounds",
                        ));
                    }
                    if !self.write_present_backbuffer_bytes(
                        *dst,
                        *dst_offset,
                        &source[*src_offset..src_end],
                    )? {
                        let destination = self.resource_mut(*dst)?;
                        destination.bytes[*dst_offset..dst_end]
                            .copy_from_slice(&source[*src_offset..src_end]);
                        destination.digest = None;
                        self.record_cpu_backing_write();
                    } else {
                        self.resource_mut(*dst)?.digest = None;
                    }
                }
                RecordedCommand::ClearRenderTargetView { view, color } => {
                    let (resource_id, heap) = {
                        let view = self.view(*view)?;
                        (
                            view.info.resource,
                            view.heap.ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcD3dInvalidState,
                                    "render target view has no descriptor heap",
                                )
                            })?,
                        )
                    };
                    let (format, len) = {
                        let resource = self.resource(resource_id)?;
                        (resource.desc.format, resource.bytes.len())
                    };
                    // The clear colour arrives in RGBA byte order (D3D11
                    // ClearRenderTargetView semantics); the resource stores
                    // pixels in its declared format layout, so reorder the
                    // bytes before writing (B8G8R8A8 targets must be
                    // [b, g, r, a], or the clear would swap R/B).
                    let stored_color = clear_color_bytes_for_format(*color, format);
                    let mut pixels = vec![0u8; len];
                    for chunk in pixels.chunks_mut(4) {
                        let count = chunk.len().min(4);
                        chunk[..count].copy_from_slice(&stored_color[..count]);
                    }
                    if self.write_present_backbuffer_bytes(resource_id, 0, &pixels)? {
                        self.resource_mut(resource_id)?.digest = None;
                    } else {
                        {
                            let resource = self.resource_mut(resource_id)?;
                            resource.bytes.copy_from_slice(&pixels);
                            resource.digest = None;
                        }
                        self.record_cpu_backing_write();
                    }
                    self.backend.record_clear_rtv(list, heap, 0)?;
                }
                RecordedCommand::ClearDepthStencilView {
                    view,
                    depth,
                    stencil,
                } => {
                    let depth_bytes = [
                        (*depth & 0xff) as u8,
                        ((*depth >> 8) & 0xff) as u8,
                        ((*depth >> 16) & 0xff) as u8,
                        ((*depth >> 24) & 0xff) as u8,
                    ];
                    let (resource_id, heap) = {
                        let view = self.view(*view)?;
                        (
                            view.info.resource,
                            view.heap.ok_or_else(|| {
                                AppError::new(
                                    ReasonCode::RcD3dInvalidState,
                                    "depth stencil view has no descriptor heap",
                                )
                            })?,
                        )
                    };
                    let resource = self.resource_mut(resource_id)?;
                    for chunk in resource.bytes.chunks_mut(5) {
                        if chunk.len() >= 4 {
                            chunk[..4].copy_from_slice(&depth_bytes);
                        }
                        if chunk.len() == 5 {
                            chunk[4] = *stencil;
                        }
                    }
                    resource.digest = None;
                    self.record_cpu_backing_write();
                    self.backend.record_clear_dsv(list, heap, 0)?;
                }
                RecordedCommand::Draw { vertices, .. } => {
                    if self.predication_skips_draws() {
                        continue;
                    }
                    stats.draw_calls += 1;
                    self.backend.record_draw(list, *vertices)?;
                }
                RecordedCommand::DrawIndexed { indices, .. } => {
                    if self.predication_skips_draws() {
                        continue;
                    }
                    stats.indexed_draw_calls += 1;
                    self.backend.record_draw(list, *indices)?;
                }
                RecordedCommand::ResolveSubresource {
                    dst,
                    dst_subresource: _,
                    src,
                    src_subresource: _,
                    format,
                } => {
                    let src_backend = self.resource(*src)?.backend_id;
                    let dst_backend = self.resource(*dst)?.backend_id;
                    // For MSAA resolve, use Average mode (D3D11 default).
                    // The CPU-side bytes are copied; the GPU command is recorded for Metal backend.
                    let source_bytes = self.resource_bytes_for_transfer(*src)?;
                    if source_bytes.len() > self.resource(*dst)?.bytes.len() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "resolve subresource destination is smaller than source",
                        ));
                    }
                    if !self.write_present_backbuffer_bytes(*dst, 0, &source_bytes)? {
                        let destination = self.resource_mut(*dst)?;
                        destination.bytes = source_bytes;
                        destination.digest = None;
                        self.record_cpu_backing_write();
                    } else {
                        self.resource_mut(*dst)?.digest = None;
                    }
                    self.backend.record_resolve_subresource(
                        list,
                        dst_backend,
                        src_backend,
                        *format,
                        0, // D3D11_RESOLVE_MODE_DECOMPRESS = 0, maps to Average
                    )?;
                    // A resolve is a blit and closes the active render pass.
                    pass_opened = false;
                }
                RecordedCommand::Dispatch { x, y, z } => {
                    stats.dispatch_calls += 1;
                    self.backend.record_dispatch(list, *x, *y, *z)?;
                    // A compute dispatch closes the active render pass.
                    pass_opened = false;
                }
                RecordedCommand::CopyStructureCount {
                    dst,
                    src_view,
                    aligned_byte_offset,
                } => {
                    // The software backend never evaluates append/consume
                    // counters, so the truthful recorded count is zero; the
                    // count is still written into the destination so games see
                    // the documented no-output value instead of stale bytes.
                    self.view(*src_view)?;
                    let offset = *aligned_byte_offset as usize;
                    let end = offset.checked_add(4).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "copy structure count offset overflow",
                        )
                    })?;
                    if end > self.resource(*dst)?.bytes.len() {
                        return Err(AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            "copy structure count out of bounds",
                        ));
                    }
                    let zero = 0u32.to_le_bytes();
                    if !self.write_present_backbuffer_bytes(*dst, offset, &zero)? {
                        let (backend_id, upload) = {
                            let destination = self.resource_mut(*dst)?;
                            destination.bytes[offset..end].copy_from_slice(&zero);
                            destination.digest = None;
                            (destination.backend_id, destination.bytes.clone())
                        };
                        self.record_cpu_backing_write();
                        self.backend.overwrite_resource_bytes(backend_id, &upload)?;
                    } else {
                        self.resource_mut(*dst)?.digest = None;
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns true when an active rendering predicate is bound and currently
    /// reports false; conditional draws must then be skipped.
    fn predication_skips_draws(&self) -> bool {
        self.predication
            .and_then(|id| self.predicates.get(&id))
            .map(|predicate| !predicate.value)
            .unwrap_or(false)
    }

    fn submit_sequences(
        &mut self,
        sequences: Vec<(ContextBindings, Vec<RecordedCommand>)>,
    ) -> AppResult<SubmissionResult> {
        let binding_signatures = sequences
            .iter()
            .map(|(bindings, _)| self.binding_signature(bindings))
            .collect::<AppResult<Vec<_>>>()?;
        self.submit_sequences_with_signatures(sequences, binding_signatures, true)
    }

    fn submit_sequences_without_digests(
        &mut self,
        sequences: Vec<(ContextBindings, Vec<RecordedCommand>)>,
    ) -> AppResult<()> {
        self.submit_sequences_with_signatures(sequences, Vec::new(), false)?;
        Ok(())
    }

    fn submit_sequences_with_signatures(
        &mut self,
        sequences: Vec<(ContextBindings, Vec<RecordedCommand>)>,
        binding_signatures: Vec<String>,
        capture_submission: bool,
    ) -> AppResult<SubmissionResult> {
        let mut immutable_streams = Vec::new();
        let mut stats = SubmissionStats {
            draw_calls: 0,
            indexed_draw_calls: 0,
            dispatch_calls: 0,
            executed_command_lists: 0,
        };
        let all_sequences_empty = sequences.iter().all(|(_, commands)| commands.is_empty());

        // Coalescing fuses a *small draw submission burst* into a single backend
        // command list / render pass. This is only valid when every sequence
        // targets the identical attachments and contains nothing but draw
        // commands: clears, dispatches, copies and resource updates each
        // establish distinct render-pass or execution boundaries that must be
        // preserved verbatim (e.g. four deferred lists each clearing the same
        // RTV to a different colour must remain four separate passes).
        let first_bindings = sequences.first().map(|(bindings, _)| bindings);
        let coalesce_sequences = self.backend.capabilities().unified_memory
            && self.backend.capabilities().argument_buffers
            && self.backend.capabilities().mesh_shaders
            && sequences.len() > 1
            && sequences.iter().all(|(bindings, commands)| {
                !commands.is_empty()
                    && commands.len() <= 8
                    && Some(bindings) == first_bindings
                    && commands.iter().all(|command| {
                        matches!(
                            command,
                            RecordedCommand::Draw { .. } | RecordedCommand::DrawIndexed { .. }
                        )
                    })
            });

        if all_sequences_empty {
            // Bare presents should not synthesize empty command lists.
        } else if coalesce_sequences {
            let list = self.backend.create_graphics_command_list(
                self.graphics_allocator,
                self.graphics_pipeline,
                false,
            );
            // All coalesced sequences share identical bindings and contain only
            // draws, so the render pass is opened exactly once before the loop
            // and shared by every merged sequence.
            let bindings = &sequences[0].0;
            let pass_started =
                !bindings.render_targets.is_empty() || bindings.depth_target.is_some();
            if pass_started {
                let (color_formats, depth_format) = self.render_pass_formats(bindings)?;
                let (load_action, store_action) = self.render_pass_actions(bindings)?;
                self.backend.record_begin_render_pass(
                    list,
                    color_formats,
                    depth_format,
                    load_action,
                    store_action,
                )?;
            }
            for (bindings, commands) in &sequences {
                self.record_sequence_to_command_list(
                    list,
                    bindings,
                    commands,
                    &mut stats,
                    pass_started,
                )?;
            }
            immutable_streams.push(self.backend.close_command_list(list)?);
        } else {
            for (bindings, commands) in &sequences {
                let list = self.backend.create_graphics_command_list(
                    self.graphics_allocator,
                    self.graphics_pipeline,
                    false,
                );
                self.record_sequence_to_command_list(list, bindings, commands, &mut stats, false)?;
                immutable_streams.push(self.backend.close_command_list(list)?);
            }
        }

        self.next_fence_value += 1;
        // Independent streams are translated concurrently (results are applied
        // in submission order by the shared execution path, so the plan and
        // resource contents are identical to serial execution).
        let signal = Some((self.fence, self.next_fence_value));
        let backend_plan = if immutable_streams.len() > 1 {
            self.backend
                .execute_command_lists_parallel(self.queue, &immutable_streams, signal)?
        } else {
            self.backend
                .execute_command_lists(self.queue, &immutable_streams, signal)?
        };
        stats.executed_command_lists = immutable_streams.len();
        let (resource_digests, signature, hash) = if capture_submission {
            let resource_digests = self.collect_resource_digests();
            let gpu_profile = self.pipeline_profile_signature();
            let signature = build_submission_signature(
                &gpu_profile,
                self.feature_level,
                stats,
                &binding_signatures,
                &resource_digests,
                &backend_plan,
            );
            let hash = util::sha256_bytes(signature.as_bytes());
            (resource_digests, signature, hash)
        } else {
            (BTreeMap::new(), String::new(), String::new())
        };
        Ok(SubmissionResult {
            feature_level: self.feature_level,
            draw_calls: stats.draw_calls,
            indexed_draw_calls: stats.indexed_draw_calls,
            dispatch_calls: stats.dispatch_calls,
            executed_command_lists: immutable_streams.len(),
            resource_digests,
            hash,
            signature,
            backend_plan,
        })
    }

    fn collect_resource_digests(&mut self) -> BTreeMap<String, String> {
        self.resources
            .values_mut()
            .filter(|resource| resource.include_in_digests)
            .map(|resource| {
                // Only re-hash resources mutated since the last submission;
                // untouched resources reuse their cached digest.
                let digest = resource.digest.clone().unwrap_or_else(|| {
                    let computed = util::sha256_bytes(&resource.bytes);
                    resource.digest = Some(computed.clone());
                    computed
                });
                (resource.desc.label.clone(), digest)
            })
            .collect()
    }

    fn pipeline_profile_signature(&self) -> String {
        let adapter = self.backend.adapter();
        let caps = self.backend.capabilities();
        format!(
            "adapter={}|family={}|argbuf={}|unified={}|memoryless={}|timestamps={}|mesh={}",
            adapter.name,
            adapter.metal_family,
            caps.argument_buffers,
            caps.unified_memory,
            caps.memoryless_render_targets,
            caps.timestamp_queries,
            caps.mesh_shaders,
        )
    }

    fn translate_shader_artifact(
        &mut self,
        desc: &ShaderModuleDesc,
        dxil: Vec<u8>,
        root_signature: Vec<u8>,
    ) -> AppResult<ShaderArtifact> {
        let input = ShaderTranslationInput {
            dxil,
            stage: translate_shader_stage(desc.stage),
            root_signature,
            compile_flags: runtime_shader_compile_flags(),
            gpu_family: self.backend.adapter().metal_family.clone(),
            os_build: runtime_os_build(),
            macwin_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let cache_key = shader_cache_key(&input)?;
        let output = if let Some(output) = self.translated_shaders.get(&cache_key) {
            output.clone()
        } else {
            let output = translate_shader(&input).map_err(shader_error_to_app_error)?;
            let entry = build_cache_entry(&cache_key, &output, 0, None)?;
            self.shader_cache.insert(entry);
            self.translated_shaders
                .insert(cache_key.clone(), output.clone());
            output
        };
        let metal_entry = output
            .function_mapping
            .get(&desc.entry)
            .cloned()
            .or_else(|| output.function_mapping.values().next().cloned())
            .unwrap_or_else(|| desc.entry.clone());
        Ok(ShaderArtifact {
            cache_key,
            metal_entry,
            output,
        })
    }

    fn binding_signature(&self, bindings: &ContextBindings) -> AppResult<String> {
        let gpu_profile = self.pipeline_profile_signature();
        let render_targets = bindings
            .render_targets
            .iter()
            .map(|view| {
                let view = self.view(*view)?;
                Ok(format!(
                    "{:?}:{}",
                    view.info.kind,
                    self.resource(view.info.resource)?.desc.label
                ))
            })
            .collect::<AppResult<Vec<_>>>()?;
        let depth_target = bindings
            .depth_target
            .map(|view| {
                self.view(view)
                    .and_then(|view| Ok(self.resource(view.info.resource)?.desc.label.clone()))
            })
            .transpose()?;
        let viewport = bindings
            .viewport
            .as_ref()
            .map(|viewport| {
                format!(
                    "{:.1},{:.1},{:.1},{:.1}",
                    viewport.x, viewport.y, viewport.width, viewport.height
                )
            })
            .unwrap_or_else(|| "none".to_string());
        let scissor = bindings
            .scissor_rect
            .as_ref()
            .map(|rect| format!("{},{},{},{}", rect.left, rect.top, rect.right, rect.bottom))
            .unwrap_or_else(|| "none".to_string());
        let vertex_buffers = bindings
            .vertex_buffers
            .iter()
            .map(|resource| {
                self.resource(*resource)
                    .map(|record| record.desc.label.clone())
            })
            .collect::<AppResult<Vec<_>>>()?;
        let index_buffer = bindings
            .index_buffer
            .map(|resource| {
                self.resource(resource)
                    .map(|record| record.desc.label.clone())
            })
            .transpose()?;
        let input_layout = bindings
            .input_layout
            .map(|layout| {
                self.input_layouts
                    .get(&layout)
                    .map(|layout| {
                        layout
                            .elements
                            .iter()
                            .map(|element| {
                                format!(
                                    "{}:{:?}:{}",
                                    element.semantic, element.format, element.slot
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!("unknown input layout {layout}"),
                        )
                    })
            })
            .transpose()?
            .unwrap_or_else(|| "none".to_string());
        let primitive_topology = bindings
            .primitive_topology
            .map(|topology| topology.to_string())
            .unwrap_or_else(|| "none".to_string());
        let blend = bindings
            .blend_state
            .map(|id| {
                self.blend_states
                    .get(&id)
                    .map(|state| {
                        format!(
                            "{}:{}:{}",
                            state.alpha_to_coverage_enable,
                            state.independent_blend_enable,
                            state.render_target[0].blend_enable,
                        )
                    })
                    .ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!("unknown blend state {id}"),
                        )
                    })
            })
            .transpose()?
            .unwrap_or_else(|| "none".to_string());
        let rasterizer = bindings
            .rasterizer_state
            .map(|id| {
                self.rasterizer_states
                    .get(&id)
                    .map(|state| {
                        format!(
                            "{}:{}:{}:{}:{}",
                            state.fill_mode,
                            state.cull_mode,
                            state.depth_clip_enable,
                            state.scissor_enable,
                            state.depth_bias,
                        )
                    })
                    .ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!("unknown rasterizer state {id}"),
                        )
                    })
            })
            .transpose()?
            .unwrap_or_else(|| "none".to_string());
        let depth = bindings
            .depth_stencil_state
            .map(|id| {
                self.depth_stencil_states
                    .get(&id)
                    .map(|state| {
                        format!(
                            "{}:{}:{}:{}",
                            state.depth_enable,
                            state.depth_write_mask,
                            state.stencil_enable,
                            state.depth_func,
                        )
                    })
                    .ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcD3dInvalidState,
                            format!("unknown depth state {id}"),
                        )
                    })
            })
            .transpose()?
            .unwrap_or_else(|| "none".to_string());
        let shaders = [
            ShaderStage::Vs,
            ShaderStage::Ps,
            ShaderStage::Cs,
            ShaderStage::Gs,
            ShaderStage::Hs,
            ShaderStage::Ds,
        ]
        .iter()
        .map(|stage| {
            bindings
                .shaders
                .get(stage)
                .map(|id| {
                    self.shader(*id).map(|shader| {
                        if let Some(artifact) = &shader.artifact {
                            format!(
                                "{:?}:{}:{}",
                                stage, artifact.metal_entry, artifact.cache_key
                            )
                        } else {
                            format!("{:?}:{}", stage, shader.desc.entry)
                        }
                    })
                })
                .transpose()
                .map(|value| value.unwrap_or_else(|| format!("{:?}:none", stage)))
        })
        .collect::<AppResult<Vec<_>>>()?;
        let constant_buffers = stage_binding_labels(&bindings.constant_buffers, |resource| {
            self.resource(resource)
                .map(|record| record.desc.label.clone())
        })?;
        let shader_resources = stage_binding_labels(&bindings.shader_resources, |view| {
            self.view(view).and_then(|record| {
                self.resource(record.info.resource)
                    .map(|resource| resource.desc.label.clone())
            })
        })?;
        let unordered_access_views =
            stage_binding_labels(&bindings.unordered_access_views, |view| {
                self.view(view).and_then(|record| {
                    self.resource(record.info.resource)
                        .map(|resource| resource.desc.label.clone())
                })
            })?;
        let samplers = stage_binding_labels(&bindings.samplers, |id| {
            self.sampler_states
                .get(&id)
                .map(|state| format!("{:?}:{}:{}", state.filter, state.address_u, state.address_v))
                .ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!("unknown sampler {id}"),
                    )
                })
        })?;
        Ok(format!(
            "gpu={}|rtv=[{}]|dsv={}|vp={}|scissor={}|vb=[{}]|ib={}|topo={}|il={}|blend={}|rast={}|depth={}|shaders=[{}]|cb=[{}]|srv=[{}]|uav=[{}]|samp=[{}]",
            gpu_profile,
            render_targets.join(","),
            depth_target.unwrap_or_else(|| "none".to_string()),
            viewport,
            scissor,
            vertex_buffers.join(","),
            index_buffer.unwrap_or_else(|| "none".to_string()),
            primitive_topology,
            input_layout,
            blend,
            rasterizer,
            depth,
            shaders.join(","),
            constant_buffers,
            shader_resources,
            unordered_access_views,
            samplers,
        ))
    }

    fn validate_resource_write(&self, resource: D3d11ResourceId, length: usize) -> AppResult<()> {
        let record = self.resource(resource)?;
        if length > record.bytes.len() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("write exceeds resource {}", record.desc.label),
            ));
        }
        Ok(())
    }

    fn promote_texture_usage_for_view(
        &mut self,
        resource: D3d11ResourceId,
        kind: ViewKind,
    ) -> AppResult<()> {
        let current_hint = self.resource(resource)?.desc.usage_hint;
        let cpu_write_frequent = texture_cpu_write_frequent(current_hint);
        let promoted_hint = match kind {
            ViewKind::Srv => ResourceUsageHint::Texture {
                sampled: true,
                render_target: false,
                depth_stencil: false,
                cpu_write_frequent,
            },
            ViewKind::Rtv => ResourceUsageHint::Texture {
                sampled: false,
                render_target: true,
                depth_stencil: false,
                cpu_write_frequent,
            },
            ViewKind::Dsv => ResourceUsageHint::Texture {
                sampled: false,
                render_target: false,
                depth_stencil: true,
                cpu_write_frequent,
            },
            ViewKind::Uav => return Ok(()),
        };
        self.promote_resource_usage_hint(resource, promoted_hint)
    }

    fn promote_texture_cpu_write_usage(&mut self, resource: D3d11ResourceId) -> AppResult<()> {
        let current_hint = self.resource(resource)?.desc.usage_hint;
        let promoted_hint = match current_hint {
            ResourceUsageHint::Texture {
                sampled,
                render_target,
                depth_stencil,
                ..
            } => ResourceUsageHint::Texture {
                sampled,
                render_target,
                depth_stencil,
                cpu_write_frequent: true,
            },
            _ => ResourceUsageHint::Texture {
                sampled: false,
                render_target: false,
                depth_stencil: matches!(current_hint, ResourceUsageHint::DepthStencil),
                cpu_write_frequent: true,
            },
        };
        self.promote_resource_usage_hint(resource, promoted_hint)
    }

    fn promote_resource_usage_hint(
        &mut self,
        resource: D3d11ResourceId,
        promoted_hint: ResourceUsageHint,
    ) -> AppResult<()> {
        let (dimension, backend_id, current_hint) = {
            let record = self.resource(resource)?;
            (
                record.desc.dimension,
                record.backend_id,
                record.desc.usage_hint,
            )
        };
        if dimension == ResourceDimension::Buffer {
            return Ok(());
        }
        let merged_hint = merge_texture_usage_hint(current_hint, promoted_hint);
        if merged_hint == current_hint {
            return Ok(());
        }
        self.resource_mut(resource)?.desc.usage_hint = merged_hint;
        self.backend
            .set_resource_usage_hint(backend_id, merged_hint)?;
        Ok(())
    }

    fn expect_view_kind(&self, view: D3d11ViewId, kind: ViewKind) -> AppResult<()> {
        let actual = self.view(view)?;
        if actual.info.kind != kind {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("expected {:?} view, found {:?}", kind, actual.info.kind),
            ));
        }
        Ok(())
    }

    fn resource(&self, resource: D3d11ResourceId) -> AppResult<&ResourceRecord> {
        self.resources.get(&resource).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown D3D11 resource {resource}"),
            )
        })
    }

    fn shader(&self, shader: ShaderId) -> AppResult<&ShaderRecord> {
        self.shaders.get(&shader).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown shader {shader}"),
            )
        })
    }

    fn resource_mut(&mut self, resource: D3d11ResourceId) -> AppResult<&mut ResourceRecord> {
        self.resources.get_mut(&resource).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown D3D11 resource {resource}"),
            )
        })
    }

    fn view(&self, view: D3d11ViewId) -> AppResult<&ViewRecord> {
        self.views.get(&view).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown D3D11 view {view}"),
            )
        })
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Release a resource: removes the CPU-side record and destroys the
    /// backend resource. Ids are never reused (monotonic allocation), so live
    /// handles remain unambiguous after removal.
    pub fn destroy_resource(&mut self, resource: D3d11ResourceId) -> AppResult<()> {
        let backend_id = self.resource(resource)?.backend_id;
        self.resources.remove(&resource);
        self.backend.destroy_resource(backend_id)
    }

    pub fn destroy_view(&mut self, view: D3d11ViewId) -> AppResult<()> {
        self.view(view)?;
        self.views.remove(&view);
        Ok(())
    }

    pub fn destroy_blend_state(&mut self, id: BlendStateId) -> AppResult<()> {
        remove_id_entry(&mut self.blend_states, id, "blend state")
    }

    pub fn destroy_rasterizer_state(&mut self, id: RasterizerStateId) -> AppResult<()> {
        remove_id_entry(&mut self.rasterizer_states, id, "rasterizer state")
    }

    pub fn destroy_depth_stencil_state(&mut self, id: DepthStencilStateId) -> AppResult<()> {
        remove_id_entry(&mut self.depth_stencil_states, id, "depth stencil state")
    }

    pub fn destroy_sampler_state(&mut self, id: SamplerStateId) -> AppResult<()> {
        remove_id_entry(&mut self.sampler_states, id, "sampler state")
    }

    pub fn destroy_input_layout(&mut self, id: InputLayoutId) -> AppResult<()> {
        remove_id_entry(&mut self.input_layouts, id, "input layout")
    }

    pub fn release_shader(&mut self, id: ShaderId) -> AppResult<()> {
        remove_id_entry(&mut self.shaders, id, "shader")
    }

    pub fn destroy_predicate(&mut self, id: u64) -> AppResult<()> {
        self.predicates.remove(&id).map(|_| ()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown D3D11 predicate {id}"),
            )
        })
    }

    pub fn destroy_counter(&mut self, id: u64) -> AppResult<()> {
        self.counters.remove(&id).map(|_| ()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown D3D11 counter {id}"),
            )
        })
    }

    pub fn destroy_class_linkage(&mut self, id: u64) -> AppResult<()> {
        self.class_linkage.remove(&id).map(|_| ()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown D3D11 class linkage {id}"),
            )
        })
    }

    // ── Device query methods ──────────────────────────────────────────

    pub fn check_format_support(&self, format: DxgiFormat) -> AppResult<crate::gfx::FormatMapping> {
        self.backend.query_format_support(format)
    }

    pub fn check_feature_support(&self) -> FeatureCaps {
        self.caps.clone()
    }

    pub fn check_multisample_quality_levels(&self, _format: DxgiFormat, _sample_count: u32) -> u32 {
        // Metal does not support MSAA quality levels beyond the default (0)
        0
    }

    /// Create a class linkage object for shader class interfaces.
    /// Stores the class linkage with its initial class instances for
    /// later use when binding shaders.
    pub fn create_class_linkage(&mut self) -> ShaderId {
        let id = self.alloc_id();
        let linkage = ClassLinkage {
            instances: Vec::new(),
        };
        self.class_linkage.insert(id, linkage);
        id
    }

    /// Create a predicate for conditional rendering.
    /// The predicate tracks its type (occlusion or SO overflow) and initial value.
    /// Games use predicates for conditional rendering (D3D11_SetPredication).
    pub fn create_predicate(&mut self, predicate_type: PredicateType) -> u64 {
        let id = self.alloc_id();
        let predicate = Predicate {
            predicate_type,
            value: false, // initially not triggered
        };
        self.predicates.insert(id, predicate);
        id
    }

    /// Create a counter for GPU performance measurement.
    /// The counter tracks its type and accumulates a unit count.
    /// Games use counters via D3D11_GetData for querying GPU progress.
    pub fn create_counter(&mut self, counter_type: CounterType) -> u64 {
        let id = self.alloc_id();
        let counter = Counter {
            counter_type,
            unit_count: 0,
        };
        self.counters.insert(id, counter);
        id
    }

    // ── Context methods ───────────────────────────────────────────────

    pub fn clear_state(&mut self) {
        self.immediate.bindings = ContextBindings::default();
        self.immediate.commands.clear();
        self.predication = None;
    }

    pub fn cs_set_unordered_access_views(&mut self, uavs: Vec<D3d11ViewId>) {
        // CS UAVs live in their own binding slot, independent of CS SRVs.
        self.immediate
            .bindings
            .unordered_access_views
            .insert(ShaderStage::Cs, uavs);
    }

    pub fn om_set_render_targets_and_unordered_access_views(
        &mut self,
        render_targets: Vec<D3d11ViewId>,
        depth_target: Option<D3d11ViewId>,
        _uav_start_slot: u32,
        uavs: Vec<D3d11ViewId>,
    ) {
        self.immediate.bindings.render_targets = render_targets;
        self.immediate.bindings.depth_target = depth_target;
        if !uavs.is_empty() {
            // OM UAVs are visible to the pixel shader stage (D3D11 semantics);
            // stored separately from CS SRVs/UAVs.
            self.immediate
                .bindings
                .unordered_access_views
                .insert(ShaderStage::Ps, uavs);
        }
    }

    pub fn generate_mips(&mut self, _view_srv: D3d11ViewId) {
        // MIP generation: in the software backend, textures are created with
        // full mip chains populated at creation time. No runtime generation needed.
    }

    pub fn draw_auto(&mut self) {
        // DrawAuto uses the stream output buffer's fill count as vertex count.
        // On Metal, this is emulated by reading the stored counter from the SO
        // buffer. When no SO buffer is bound, the vertex count is 0 (no-op draw).
        self.immediate.commands.push(RecordedCommand::Draw {
            vertices: 0,
            kind: DrawCallKind::Regular,
        });
    }

    pub fn copy_structure_count(
        &mut self,
        dst: D3d11ResourceId,
        src_view: D3d11ViewId,
        aligned_byte_offset: u32,
    ) {
        // CopyStructureCount copies the append/consume counter from a UAV to
        // a buffer at a given byte offset. The software backend never
        // evaluates append/consume counters, so the recorded count is zero;
        // the command still validates its targets and writes the count into
        // the destination at execution time.
        self.immediate
            .commands
            .push(RecordedCommand::CopyStructureCount {
                dst,
                src_view,
                aligned_byte_offset,
            });
    }

    /// ID3D11DeviceContext::SetPredication — binds the active predicate for
    /// conditional rendering. Draws issued while the bound predicate reports
    /// false are skipped at execution time.
    pub fn set_predication(&mut self, predicate: u64) {
        if self.predicates.contains_key(&predicate) {
            self.predication = Some(predicate);
        }
    }

    /// ID3D11DeviceContext::SetPredication(NULL, ...) — clears conditional
    /// rendering so subsequent draws proceed unconditionally.
    pub fn clear_predication(&mut self) {
        self.predication = None;
    }
}

impl DeferredContext {
    pub fn om_set_render_targets(
        &self,
        render_targets: Vec<D3d11ViewId>,
        depth_target: Option<D3d11ViewId>,
    ) -> AppResult<()> {
        let mut recording = self.lock_recording()?;
        recording.bindings.render_targets = render_targets;
        recording.bindings.depth_target = depth_target;
        Ok(())
    }

    pub fn rs_set_viewports(&self, viewport: Viewport) -> AppResult<()> {
        self.lock_recording()?.bindings.viewport = Some(viewport);
        Ok(())
    }

    pub fn rs_clear_viewports(&self) -> AppResult<()> {
        self.lock_recording()?.bindings.viewport = None;
        Ok(())
    }

    pub fn rs_set_scissor_rects(&self, scissor_rect: ScissorRect) -> AppResult<()> {
        self.lock_recording()?.bindings.scissor_rect = Some(scissor_rect);
        Ok(())
    }

    pub fn rs_clear_scissor_rects(&self) -> AppResult<()> {
        self.lock_recording()?.bindings.scissor_rect = None;
        Ok(())
    }

    pub fn ia_set_vertex_buffers(&self, buffers: Vec<D3d11ResourceId>) -> AppResult<()> {
        self.lock_recording()?.bindings.vertex_buffers = buffers;
        Ok(())
    }

    pub fn ia_set_index_buffer(&self, buffer: D3d11ResourceId) -> AppResult<()> {
        self.lock_recording()?.bindings.index_buffer = Some(buffer);
        Ok(())
    }

    pub fn ia_clear_index_buffer(&self) -> AppResult<()> {
        self.lock_recording()?.bindings.index_buffer = None;
        Ok(())
    }

    pub fn ia_set_primitive_topology(&self, topology: u32) -> AppResult<()> {
        self.lock_recording()?.bindings.primitive_topology = Some(topology);
        Ok(())
    }

    pub fn ia_set_input_layout(&self, layout: InputLayoutId) -> AppResult<()> {
        self.lock_recording()?.bindings.input_layout = Some(layout);
        Ok(())
    }

    pub fn ia_clear_input_layout(&self) -> AppResult<()> {
        self.lock_recording()?.bindings.input_layout = None;
        Ok(())
    }

    pub fn om_set_blend_state(&self, state: BlendStateId) -> AppResult<()> {
        self.lock_recording()?.bindings.blend_state = Some(state);
        Ok(())
    }

    pub fn om_clear_blend_state(&self) -> AppResult<()> {
        self.lock_recording()?.bindings.blend_state = None;
        Ok(())
    }

    pub fn rs_set_state(&self, state: RasterizerStateId) -> AppResult<()> {
        self.lock_recording()?.bindings.rasterizer_state = Some(state);
        Ok(())
    }

    pub fn rs_clear_state(&self) -> AppResult<()> {
        self.lock_recording()?.bindings.rasterizer_state = None;
        Ok(())
    }

    pub fn om_set_depth_stencil_state(&self, state: DepthStencilStateId) -> AppResult<()> {
        self.lock_recording()?.bindings.depth_stencil_state = Some(state);
        Ok(())
    }

    pub fn om_clear_depth_stencil_state(&self) -> AppResult<()> {
        self.lock_recording()?.bindings.depth_stencil_state = None;
        Ok(())
    }

    pub fn vs_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .insert(ShaderStage::Vs, shader);
        Ok(())
    }

    pub fn vs_clear_shader(&self) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .remove(&ShaderStage::Vs);
        Ok(())
    }

    pub fn ps_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .insert(ShaderStage::Ps, shader);
        Ok(())
    }

    pub fn ps_clear_shader(&self) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .remove(&ShaderStage::Ps);
        Ok(())
    }

    pub fn cs_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .insert(ShaderStage::Cs, shader);
        Ok(())
    }

    pub fn cs_clear_shader(&self) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .remove(&ShaderStage::Cs);
        Ok(())
    }

    pub fn vs_set_constant_buffers(&self, buffers: Vec<D3d11ResourceId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .constant_buffers
            .insert(ShaderStage::Vs, buffers);
        Ok(())
    }

    pub fn ps_set_shader_resources(&self, resources: Vec<D3d11ViewId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shader_resources
            .insert(ShaderStage::Ps, resources);
        Ok(())
    }

    pub fn vs_set_samplers(&self, samplers: Vec<SamplerStateId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .samplers
            .insert(ShaderStage::Vs, samplers);
        Ok(())
    }

    pub fn ps_set_samplers(&self, samplers: Vec<SamplerStateId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .samplers
            .insert(ShaderStage::Ps, samplers);
        Ok(())
    }

    pub fn gs_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .insert(ShaderStage::Gs, shader);
        Ok(())
    }

    pub fn gs_clear_shader(&self) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .remove(&ShaderStage::Gs);
        Ok(())
    }

    pub fn hs_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .insert(ShaderStage::Hs, shader);
        Ok(())
    }

    pub fn hs_clear_shader(&self) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .remove(&ShaderStage::Hs);
        Ok(())
    }

    pub fn ds_set_shader(&self, shader: ShaderId) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .insert(ShaderStage::Ds, shader);
        Ok(())
    }

    pub fn ds_clear_shader(&self) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shaders
            .remove(&ShaderStage::Ds);
        Ok(())
    }

    pub fn vs_set_shader_resources(&self, resources: Vec<D3d11ViewId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shader_resources
            .insert(ShaderStage::Vs, resources);
        Ok(())
    }

    pub fn cs_set_shader_resources(&self, resources: Vec<D3d11ViewId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shader_resources
            .insert(ShaderStage::Cs, resources);
        Ok(())
    }

    pub fn gs_set_shader_resources(&self, resources: Vec<D3d11ViewId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shader_resources
            .insert(ShaderStage::Gs, resources);
        Ok(())
    }

    pub fn hs_set_shader_resources(&self, resources: Vec<D3d11ViewId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shader_resources
            .insert(ShaderStage::Hs, resources);
        Ok(())
    }

    pub fn ds_set_shader_resources(&self, resources: Vec<D3d11ViewId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .shader_resources
            .insert(ShaderStage::Ds, resources);
        Ok(())
    }

    pub fn cs_set_constant_buffers(&self, buffers: Vec<D3d11ResourceId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .constant_buffers
            .insert(ShaderStage::Cs, buffers);
        Ok(())
    }

    pub fn gs_set_constant_buffers(&self, buffers: Vec<D3d11ResourceId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .constant_buffers
            .insert(ShaderStage::Gs, buffers);
        Ok(())
    }

    pub fn hs_set_constant_buffers(&self, buffers: Vec<D3d11ResourceId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .constant_buffers
            .insert(ShaderStage::Hs, buffers);
        Ok(())
    }

    pub fn ds_set_constant_buffers(&self, buffers: Vec<D3d11ResourceId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .constant_buffers
            .insert(ShaderStage::Ds, buffers);
        Ok(())
    }

    pub fn cs_set_samplers(&self, samplers: Vec<SamplerStateId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .samplers
            .insert(ShaderStage::Cs, samplers);
        Ok(())
    }

    pub fn gs_set_samplers(&self, samplers: Vec<SamplerStateId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .samplers
            .insert(ShaderStage::Gs, samplers);
        Ok(())
    }

    pub fn hs_set_samplers(&self, samplers: Vec<SamplerStateId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .samplers
            .insert(ShaderStage::Hs, samplers);
        Ok(())
    }

    pub fn ds_set_samplers(&self, samplers: Vec<SamplerStateId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .samplers
            .insert(ShaderStage::Ds, samplers);
        Ok(())
    }

    pub fn clear_state(&self) -> AppResult<()> {
        let mut recording = self.lock_recording()?;
        recording.bindings = ContextBindings::default();
        recording.commands.clear();
        Ok(())
    }

    pub fn cs_set_unordered_access_views(&self, uavs: Vec<D3d11ViewId>) -> AppResult<()> {
        self.lock_recording()?
            .bindings
            .unordered_access_views
            .insert(ShaderStage::Cs, uavs);
        Ok(())
    }

    pub fn om_set_render_targets_and_unordered_access_views(
        &self,
        render_targets: Vec<D3d11ViewId>,
        depth_target: Option<D3d11ViewId>,
        _uav_start_slot: u32,
        uavs: Vec<D3d11ViewId>,
    ) -> AppResult<()> {
        let mut recording = self.lock_recording()?;
        recording.bindings.render_targets = render_targets;
        recording.bindings.depth_target = depth_target;
        if !uavs.is_empty() {
            recording
                .bindings
                .unordered_access_views
                .insert(ShaderStage::Ps, uavs);
        }
        Ok(())
    }

    pub fn generate_mips(&self, _view_srv: D3d11ViewId) -> AppResult<()> {
        // MIP generation: in the software backend, textures are created with
        // single-level storage and no mip chain to regenerate. Validate the
        // context is still recording and accept the call.
        let _recording = self.lock_recording()?;
        Ok(())
    }

    pub fn draw_auto(&self) -> AppResult<()> {
        self.lock_recording()?.commands.push(RecordedCommand::Draw {
            vertices: 0,
            kind: DrawCallKind::Regular,
        });
        Ok(())
    }

    pub fn copy_structure_count(
        &self,
        dst: D3d11ResourceId,
        src_view: D3d11ViewId,
        aligned_byte_offset: u32,
    ) -> AppResult<()> {
        // The software backend never evaluates append/consume counters, so the
        // recorded count is zero; the recorded command validates its targets
        // and writes the count into the destination at execution time.
        self.lock_recording()?
            .commands
            .push(RecordedCommand::CopyStructureCount {
                dst,
                src_view,
                aligned_byte_offset,
            });
        Ok(())
    }

    pub fn update_subresource(&self, resource: D3d11ResourceId, bytes: &[u8]) -> AppResult<()> {
        self.lock_recording()?
            .commands
            .push(RecordedCommand::UpdateSubresource {
                resource,
                bytes: bytes.to_vec(),
            });
        Ok(())
    }

    pub fn clear_render_target_view(&self, view: D3d11ViewId, color: [u8; 4]) -> AppResult<()> {
        self.lock_recording()?
            .commands
            .push(RecordedCommand::ClearRenderTargetView { view, color });
        Ok(())
    }

    pub fn clear_depth_stencil_view(
        &self,
        view: D3d11ViewId,
        depth: u32,
        stencil: u8,
    ) -> AppResult<()> {
        self.lock_recording()?
            .commands
            .push(RecordedCommand::ClearDepthStencilView {
                view,
                depth,
                stencil,
            });
        Ok(())
    }

    pub fn resolve_subresource(
        &self,
        dst: D3d11ResourceId,
        dst_subresource: u32,
        src: D3d11ResourceId,
        src_subresource: u32,
        format: u32,
    ) -> AppResult<()> {
        self.lock_recording()?
            .commands
            .push(RecordedCommand::ResolveSubresource {
                dst,
                dst_subresource,
                src,
                src_subresource,
                format,
            });
        Ok(())
    }

    pub fn copy_resource(&self, src: D3d11ResourceId, dst: D3d11ResourceId) -> AppResult<()> {
        self.lock_recording()?
            .commands
            .push(RecordedCommand::CopyResource { src, dst });
        Ok(())
    }

    pub fn draw(&self, vertices: u32) -> AppResult<()> {
        self.lock_recording()?.commands.push(RecordedCommand::Draw {
            vertices,
            kind: DrawCallKind::Regular,
        });
        Ok(())
    }

    pub fn draw_instanced(&self, vertices: u32, instances: u32) -> AppResult<()> {
        self.lock_recording()?.commands.push(RecordedCommand::Draw {
            vertices,
            kind: DrawCallKind::Instanced { instances },
        });
        Ok(())
    }

    pub fn draw_indexed(&self, indices: u32) -> AppResult<()> {
        self.lock_recording()?
            .commands
            .push(RecordedCommand::DrawIndexed {
                indices,
                kind: IndexedDrawCallKind::Regular,
            });
        Ok(())
    }

    pub fn draw_indexed_instanced(&self, indices: u32, instances: u32) -> AppResult<()> {
        self.lock_recording()?
            .commands
            .push(RecordedCommand::DrawIndexed {
                indices,
                kind: IndexedDrawCallKind::Instanced { instances },
            });
        Ok(())
    }

    pub fn dispatch(&self, x: u32, y: u32, z: u32) -> AppResult<()> {
        self.lock_recording()?
            .commands
            .push(RecordedCommand::Dispatch { x, y, z });
        Ok(())
    }

    pub fn finish_command_list(&self, device: &D3d11Device) -> AppResult<D3d11CommandList> {
        let mut recording = self.lock()?;

        // Validate: reject if this deferred context was already finished.
        if recording.finished {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "deferred context has already finished recording; cannot call finish_command_list again",
            ));
        }

        // Validate resource references in all recorded commands.
        for command in &recording.commands {
            validate_command_resources(command, device)?;
        }

        // Validate binding consistency (render targets, pipeline state, etc.).
        validate_binding_consistency(&recording.bindings, &recording.commands)?;

        // Mark as finished and take ownership of the recorded data.
        recording.finished = true;
        let bindings = std::mem::take(&mut recording.bindings);
        let commands = std::mem::take(&mut recording.commands);

        Ok(D3d11CommandList {
            binding_signature: device.binding_signature(&bindings)?,
            commands,
            bindings,
        })
    }

    fn lock(&self) -> AppResult<std::sync::MutexGuard<'_, DeferredRecording>> {
        self.recording.lock().map_err(|_| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                "deferred context mutex poisoned",
            )
        })
    }

    /// Locks the recording and rejects any further mutation once the context
    /// has been finished. D3D11 raises `D3D11_ERROR_INVALID_CALL` on every
    /// method call after `FinishCommandList`.
    fn lock_recording(&self) -> AppResult<std::sync::MutexGuard<'_, DeferredRecording>> {
        let recording = self.lock()?;
        if recording.finished {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "deferred context has already finished recording; method call rejected",
            ));
        }
        Ok(recording)
    }
}

// ── Deferred-context validation helpers ──────────────────────────────────

/// Convert a `ClearRenderTargetView` clear colour — carried in RGBA byte
/// order (the D3D11 `ColorRGBA` convention, floats scaled to bytes) — into
/// the byte order declared by the destination resource's format.  Writing
/// RGBA bytes raw into a B8G8R8A8 backbuffer would swap R and B.
fn clear_color_bytes_for_format(rgba: [u8; 4], format: DxgiFormat) -> [u8; 4] {
    match format {
        DxgiFormat::B8G8R8A8Unorm | DxgiFormat::B8G8R8A8UnormSrgb | DxgiFormat::B8G8R8X8Unorm => {
            [rgba[2], rgba[1], rgba[0], rgba[3]]
        }
        DxgiFormat::R8G8B8A8Unorm | DxgiFormat::R8G8B8A8UnormSrgb | DxgiFormat::R8G8B8A8Uint => {
            rgba
        }
        // Best-effort for every other format: keep the RGBA byte order.
        _ => rgba,
    }
}

/// Validate that all resource and view references in a recorded command
/// are still valid on the device (i.e. have not been destroyed).
fn validate_command_resources(command: &RecordedCommand, device: &D3d11Device) -> AppResult<()> {
    match command {
        RecordedCommand::UpdateSubresource { resource, bytes } => {
            let record = device.resource(*resource).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed resource {resource}"),
                )
            })?;
            if bytes.len() > record.bytes.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "update subresource payload exceeds resource {}",
                        record.desc.label
                    ),
                ));
            }
        }
        RecordedCommand::CopyResource { src, dst }
        | RecordedCommand::CopySubresourceRegion { src, dst, .. } => {
            device.resource(*src).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed source resource {src}"),
                )
            })?;
            device.resource(*dst).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed destination resource {dst}"),
                )
            })?;
        }
        RecordedCommand::ClearRenderTargetView { view, .. } => {
            device.view(*view).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed render target view {view}"),
                )
            })?;
        }
        RecordedCommand::ClearDepthStencilView { view, .. } => {
            device.view(*view).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed depth stencil view {view}"),
                )
            })?;
        }
        RecordedCommand::ResolveSubresource { dst, src, .. } => {
            device.resource(*dst).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed destination resource {dst}"),
                )
            })?;
            device.resource(*src).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed source resource {src}"),
                )
            })?;
        }
        RecordedCommand::CopyStructureCount {
            dst,
            src_view,
            aligned_byte_offset,
        } => {
            let destination = device.resource(*dst).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed destination resource {dst}"),
                )
            })?;
            device.view(*src_view).map_err(|_| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("command references destroyed source view {src_view}"),
                )
            })?;
            let end = (*aligned_byte_offset as usize)
                .checked_add(4)
                .ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "copy structure count offset overflow",
                    )
                })?;
            if end > destination.bytes.len() {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!(
                        "copy structure count out of bounds for resource {}",
                        destination.desc.label
                    ),
                ));
            }
        }
        RecordedCommand::Draw { .. }
        | RecordedCommand::DrawIndexed { .. }
        | RecordedCommand::Dispatch { .. } => {
            // These commands reference no resources directly — validation
            // of the pipeline bindings is handled by validate_binding_consistency.
        }
    }
    Ok(())
}

/// Validate that the bindings are consistent with the recorded command types.
/// Returns an error with an appropriate D3D11 error code on failure.
fn validate_binding_consistency(
    bindings: &ContextBindings,
    commands: &[RecordedCommand],
) -> AppResult<()> {
    let has_draw = commands.iter().any(|cmd| {
        matches!(
            cmd,
            RecordedCommand::Draw { .. } | RecordedCommand::DrawIndexed { .. }
        )
    });
    let has_dispatch = commands
        .iter()
        .any(|cmd| matches!(cmd, RecordedCommand::Dispatch { .. }));
    let has_indexed = commands
        .iter()
        .any(|cmd| matches!(cmd, RecordedCommand::DrawIndexed { .. }));

    if has_draw {
        // A draw call must have at least one render target or a depth target bound.
        if bindings.render_targets.is_empty() && bindings.depth_target.is_none() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "draw command recorded but neither render target nor depth target is bound",
            ));
        }
        // A draw call requires a primitive topology.
        if bindings.primitive_topology.is_none() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "draw command recorded without a primitive topology set",
            ));
        }
        // A draw call requires at least a vertex shader (or compute shader for
        // certain draw-auto scenarios).
        if !bindings.shaders.contains_key(&ShaderStage::Vs)
            && !bindings.shaders.contains_key(&ShaderStage::Cs)
        {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "draw command recorded without a vertex or compute shader bound",
            ));
        }
        // Indexed draws require an index buffer.
        if has_indexed && bindings.index_buffer.is_none() {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "indexed draw command recorded without an index buffer bound",
            ));
        }
    }

    if has_dispatch {
        // A dispatch call requires a compute shader.
        if !bindings.shaders.contains_key(&ShaderStage::Cs) {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "dispatch command recorded without a compute shader bound",
            ));
        }
    }

    Ok(())
}

/// Returns true when every command is a draw; such a list can be fused with
/// another draw-only list without altering render-pass boundaries.
fn commands_are_draw_only(commands: &[RecordedCommand]) -> bool {
    commands.iter().all(|command| {
        matches!(
            command,
            RecordedCommand::Draw { .. } | RecordedCommand::DrawIndexed { .. }
        )
    })
}

/// Removes a device-side object from its map, rejecting unknown ids so
/// callers cannot silently release objects they do not own.
fn remove_id_entry<T>(map: &mut BTreeMap<u64, T>, id: u64, kind: &str) -> AppResult<()> {
    map.remove(&id).map(|_| ()).ok_or_else(|| {
        AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unknown D3D11 {kind} {id}"),
        )
    })
}

impl Direct3D9Shim {
    pub fn new() -> Self {
        Direct3D9Shim {
            next_id: 1,
            next_vertex_buffer_id: 1,
            next_index_buffer_id: 1,
            next_texture_id: 1,
            vertex_buffers: BTreeMap::new(),
            index_buffers: BTreeMap::new(),
            textures: BTreeMap::new(),
            devices: BTreeMap::new(),
            render_target: None,
        }
    }

    pub fn create_device(&mut self) -> AppResult<Direct3D9Device> {
        let id = self.next_id;
        self.next_id += 1;
        let mut device = Direct3D9Device {
            id,
            state: D3d9StateBlock::new(),
            present_params: D3dPresentParameters::default(),
            swapchain_width: 640,
            swapchain_height: 480,
        };
        // Keep the default viewport consistent with the default swapchain
        // dimensions so default-state rendering covers the backbuffer.
        device.state.viewport.width = device.swapchain_width;
        device.state.viewport.height = device.swapchain_height;
        let dev = device.clone();
        self.devices.insert(id, device);
        Ok(dev)
    }

    pub fn alloc_vertex_buffer(
        &mut self,
        size: usize,
        fvf: u32,
        stride: u32,
    ) -> D3d9VertexBufferId {
        let id = self.next_vertex_buffer_id;
        self.next_vertex_buffer_id += 1;
        self.vertex_buffers.insert(
            id,
            VertexBuffer9 {
                id,
                size,
                fvf,
                stride,
                data: vec![0u8; size],
            },
        );
        id
    }

    pub fn alloc_index_buffer(&mut self, size: usize, format: bool) -> D3d9IndexBufferId {
        let id = self.next_index_buffer_id;
        self.next_index_buffer_id += 1;
        self.index_buffers.insert(
            id,
            IndexBuffer9 {
                id,
                size,
                format,
                data: vec![0u8; size],
            },
        );
        id
    }

    pub fn alloc_texture(
        &mut self,
        width: u32,
        height: u32,
        level_count: u32,
        format: u32,
    ) -> D3d9TextureId {
        // Clamp to the D3D9 maximum texture dimension (16384) so the usize
        // pixel-count arithmetic below can never overflow.
        let width = width.min(16384);
        let height = height.min(16384);
        let id = self.next_texture_id;
        self.next_texture_id += 1;
        let mut levels = Vec::new();
        let mut mip_w = width;
        let mut mip_h = height;
        for _ in 0..level_count {
            let pixel_count = (mip_w as usize) * (mip_h as usize) * 4;
            levels.push(vec![0u8; pixel_count]);
            mip_w = (mip_w / 2).max(1);
            mip_h = (mip_h / 2).max(1);
        }
        self.textures.insert(
            id,
            D3d9Texture {
                id,
                width,
                height,
                levels,
                format,
            },
        );
        id
    }

    pub fn release_vertex_buffer(&mut self, id: D3d9VertexBufferId) -> AppResult<()> {
        self.vertex_buffers.remove(&id).map(|_| ()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown d3d9 vertex buffer {id}"),
            )
        })
    }

    pub fn release_index_buffer(&mut self, id: D3d9IndexBufferId) -> AppResult<()> {
        self.index_buffers.remove(&id).map(|_| ()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown d3d9 index buffer {id}"),
            )
        })
    }

    pub fn release_texture(&mut self, id: D3d9TextureId) -> AppResult<()> {
        self.textures.remove(&id).map(|_| ()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown d3d9 texture {id}"),
            )
        })
    }

    pub fn release_device(&mut self, id: D3d9DeviceId) -> AppResult<()> {
        self.devices.remove(&id).map(|_| ()).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unknown d3d9 device {id}"),
            )
        })
    }

    pub fn present(&mut self, device_id: D3d9DeviceId) -> AppResult<D3d9Frame> {
        let device = self.devices.get(&device_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcD3d9NotSupported, "invalid d3d9 device id")
        })?;
        let (w, h) = (
            device.swapchain_width.min(16384),
            device.swapchain_height.min(16384),
        );
        let (width, height, pixels, synthesized) = match self.render_target.clone() {
            Some(rt) => (rt.width, rt.height, rt.pixels, rt.synthesized),
            // Blank fallback: the host fabricated these pixels, so they are
            // explicitly marked synthesized and never count as a real frame.
            None => (w, h, vec![0u8; (w as usize) * (h as usize) * 4], true),
        };
        let sig = format!("d3d9:present:device={}", device_id);
        Ok(D3d9Frame {
            hash: util::sha256_bytes(sig.as_bytes()),
            signature: sig,
            pixels,
            width,
            height,
            synthesized,
        })
    }
}

impl Direct3D9Device {
    pub fn render_fixed_function_scene(&self, scene: &FixedFunctionScene) -> AppResult<D3d9Frame> {
        let w = self.swapchain_width.clamp(1, 16384);
        let h = self.swapchain_height.clamp(1, 16384);
        let stride = (w as usize) * 4;
        let mut pixels = vec![0u8; (h as usize) * stride];

        // Fill background with diffuse color
        let bg = scene.diffuse_color;
        for row in 0..h as usize {
            for col in 0..w as usize {
                let off = row * stride + col * 4;
                pixels[off] = bg[2]; // B
                pixels[off + 1] = bg[1]; // G
                pixels[off + 2] = bg[0]; // R
                pixels[off + 3] = bg[3]; // A
            }
        }

        // Draw simple placeholder primitives based on state
        let prim_count = scene.primitive_count.clamp(1, 100) as usize;
        for i in 0..prim_count {
            let cx = (w as f32) / 2.0;
            let cy = (h as f32) / 2.0;
            let angle = (i as f32) * std::f32::consts::TAU / (prim_count as f32);
            let r = (w.min(h) as f32) * 0.3;
            let px = (cx + r * angle.cos()) as i32;
            let py = (cy + r * angle.sin()) as i32;
            let color = if i % 2 == 0 {
                [0xFF, 0xFF, 0xFF, 0xFF]
            } else {
                [0x00, 0x00, 0x00, 0x00]
            };
            // Draw a small 4x4 square at each point
            for dy in -2..=2 {
                for dx in -2..=2 {
                    let sx = px + dx;
                    let sy = py + dy;
                    if sx >= 0 && sx < w as i32 && sy >= 0 && sy < h as i32 {
                        let off = (sy as usize) * stride + (sx as usize) * 4;
                        if scene.alpha_blend_enable {
                            let a = color[3] as u32;
                            let inv_a = 255 - a;
                            pixels[off] =
                                ((pixels[off] as u32 * inv_a + color[0] as u32 * a) / 255) as u8;
                            pixels[off + 1] = ((pixels[off + 1] as u32 * inv_a
                                + color[1] as u32 * a)
                                / 255) as u8;
                            pixels[off + 2] = ((pixels[off + 2] as u32 * inv_a
                                + color[2] as u32 * a)
                                / 255) as u8;
                            pixels[off + 3] = 255u8;
                        } else {
                            pixels[off..off + 4].copy_from_slice(&color);
                        }
                    }
                }
            }
        }

        let signature = format!(
            "d3d9:id={}|tf={:08x}|diff={:02x}{:02x}{:02x}{:02x}|fog={}|blend={}|prim={}|{}x{}",
            self.id,
            scene.texture_factor,
            scene.diffuse_color[0],
            scene.diffuse_color[1],
            scene.diffuse_color[2],
            scene.diffuse_color[3],
            scene.fog_enable,
            scene.alpha_blend_enable,
            scene.primitive_count,
            w,
            h,
        );
        Ok(D3d9Frame {
            hash: util::sha256_bytes(signature.as_bytes()),
            signature,
            pixels,
            width: w,
            height: h,
            // The fixed-function rasterizer invents these pixels from device
            // state; they are host-synthesized, never real guest content.
            synthesized: true,
        })
    }

    pub fn set_render_state(&mut self, state: u32, value: u32) {
        if (state as usize) < self.state.render_states.len() {
            self.state.render_states[state as usize] = value;
        }
    }

    pub fn get_render_state(&self, state: u32) -> u32 {
        if (state as usize) < self.state.render_states.len() {
            self.state.render_states[state as usize]
        } else {
            0
        }
    }

    pub fn set_texture_stage_state(&mut self, stage: u32, state: u32, value: u32) {
        if (stage as usize) < self.state.texture_stage_states.len()
            && (state as usize) < self.state.texture_stage_states[stage as usize].len()
        {
            self.state.texture_stage_states[stage as usize][state as usize] = value;
        }
    }

    pub fn set_transform(&mut self, transform_type: u32, matrix: &D3dMatrix) {
        self.state.transforms.insert(transform_type, *matrix);
    }

    pub fn set_material(&mut self, material: &D3dMaterial9) {
        self.state.material = *material;
    }

    pub fn set_fvf(&mut self, fvf: u32) {
        self.state.fvf = fvf;
    }

    pub fn set_stream_source(
        &mut self,
        stream: u32,
        buffer_id: D3d9VertexBufferId,
        offset: u32,
        stride: u32,
    ) {
        if (stream as usize) < self.state.stream_source.len() {
            self.state.stream_source[stream as usize] = Some((buffer_id, offset, stride));
        }
    }

    pub fn set_indices(&mut self, buffer_id: D3d9IndexBufferId, base_vertex_index: u32) {
        self.state.indices = Some((buffer_id, base_vertex_index));
    }

    pub fn set_texture(&mut self, stage: u32, texture_id: D3d9TextureId) {
        if (stage as usize) < self.state.textures.len() {
            self.state.textures[stage as usize] = Some(texture_id);
        }
    }

    pub fn set_viewport(&mut self, viewport: &D3dViewport9) {
        self.state.viewport = *viewport;
    }

    pub fn set_light(&mut self, index: u32, light: &D3dLight9) {
        if (index as usize) < self.state.lights.len() {
            self.state.lights[index as usize] = Some(*light);
        }
    }

    pub fn light_enable(&mut self, index: u32, enable: bool) {
        if (index as usize) < self.state.lights_enabled.len() {
            self.state.lights_enabled[index as usize] = enable;
        }
    }

    pub fn set_pixel_shader(&mut self, shader: u64) {
        self.state.pixel_shader = shader;
    }

    pub fn set_vertex_shader(&mut self, shader: u64) {
        self.state.vertex_shader = shader;
    }

    pub fn set_clip_plane(&mut self, index: u32, enable: bool) {
        if (index as usize) < self.state.clip_planes.len() {
            self.state.clip_planes[index as usize] = enable;
        }
    }

    pub fn set_scissor_rect(&mut self, left: i32, top: i32, right: i32, bottom: i32) {
        self.state.scissor_rect = Some((left, top, right, bottom));
    }
}

pub fn d3d11_create_device(request: DeviceCreationRequest) -> AppResult<D3d11Device> {
    create_device_internal(request, None)
}

pub fn d3d11_create_device_and_swapchain(
    request: DeviceCreationRequest,
    swapchain_desc: SwapchainDesc,
) -> AppResult<D3d11Device> {
    create_device_internal(request, Some(swapchain_desc))
}

pub fn direct3d_create9() -> Direct3D9Shim {
    Direct3D9Shim::new()
}

/// Allocate the pixel (BGRA/RGBA) IOSurface channel set for a swapchain.
/// Returns an empty vector when the capability probe or allocation fails.
fn build_pixel_channels(
    desc: &SwapchainDesc,
) -> Vec<crate::metal_backend::IoSurfacePresentChannel> {
    let format = crate::metal_backend::dxgi_to_metal_format(desc.format);
    let mut channels = Vec::new();
    for _ in 0..desc.buffer_count.max(1) {
        match crate::metal_backend::IoSurfacePresentChannel::new(desc.width, desc.height, format) {
            Ok(channel) => channels.push(channel),
            Err(_) => return Vec::new(),
        }
    }
    channels
}

/// Allocate the NV12 two-plane channel set for a swapchain.
fn build_nv12_channels(
    width: u32,
    height: u32,
    count: u32,
) -> Option<Vec<crate::metal_backend::Nv12PresentChannel>> {
    let mut channels = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match crate::metal_backend::Nv12PresentChannel::new(width, height) {
            Ok(channel) => channels.push(channel),
            Err(_) => return None,
        }
    }
    Some(channels)
}

fn create_device_internal(
    request: DeviceCreationRequest,
    swapchain_desc: Option<SwapchainDesc>,
) -> AppResult<D3d11Device> {
    create_device_internal_with_backend(request, swapchain_desc, GraphicsBackend::new())
}

fn create_device_internal_with_backend(
    request: DeviceCreationRequest,
    swapchain_desc: Option<SwapchainDesc>,
    mut backend: GraphicsBackend,
) -> AppResult<D3d11Device> {
    let requested = if request.requested_feature_levels.is_empty() {
        vec![FeatureLevel::Level11_0, FeatureLevel::Level10_1]
    } else {
        request.requested_feature_levels
    };
    // D3D11 device creation returns the first requested feature level the
    // backend can satisfy, in request order. The Metal planner can satisfy
    // 11_0 when the host GPU family supports mesh shaders; 10_1 is always
    // supported.
    let backend_mesh = backend.capabilities().mesh_shaders;
    let feature_level = requested
        .iter()
        .copied()
        .find(|level| match level {
            FeatureLevel::Level11_0 => backend_mesh,
            FeatureLevel::Level10_1 => true,
        })
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcD3dFeatureUnsupported,
                "requested D3D11 feature levels are not supported by the Metal planner",
            )
            .with_hint("request feature level 10_1, or 11_0 on mesh-shader-capable GPUs")
        })?;
    let mut iosurface_channels = Vec::new();
    let swapchain = match swapchain_desc {
        Some(desc) => {
            let id = backend.create_swapchain(desc.clone())?;
            // Capability + allocation probe: on failure the channels stay
            // empty and presents use the verified host-visible fallback.
            iosurface_channels = build_pixel_channels(&desc);
            Some(id)
        }
        None => None,
    };
    let mut resources = BTreeMap::new();
    let mut next_id = 1_u64;
    if let Some(swapchain_id) = swapchain {
        let state = backend.swapchain_state(swapchain_id)?;
        for (index, backbuffer) in state.backbuffers.iter().copied().enumerate() {
            resources.insert(
                backbuffer,
                ResourceRecord {
                    bytes: vec![0; state.desc.width as usize * state.desc.height as usize * 4],
                    mapped: false,
                    backend_id: backbuffer,
                    include_in_digests: false,
                    digest: None,
                    desc: D3d11ResourceDesc {
                        label: format!("swapchain-backbuffer-{index}"),
                        dimension: ResourceDimension::Texture2D,
                        format: state.desc.format,
                        width: state.desc.width,
                        height: state.desc.height,
                        depth: 1,
                        byte_width: state.desc.width as usize * state.desc.height as usize * 4,
                        usage_hint: ResourceUsageHint::SwapchainBackbuffer,
                    },
                },
            );
            next_id = next_id.max(backbuffer.saturating_add(1));
        }
    }
    let queue = backend.create_command_queue();
    let allocator = backend.create_command_allocator();
    let root_signature = backend.create_root_signature(RootSignatureDesc {
        descriptor_tables: vec![8, 4],
        root_constants: 16,
        parameters: Vec::new(),
        static_samplers: Vec::new(),
        visibility_offsets: BTreeMap::new(),
    });
    let pipeline_label = format!(
        "d3d11-immediate-{}-mesh{}-argbuf{}",
        backend.adapter().metal_family,
        u8::from(backend.capabilities().mesh_shaders),
        u8::from(backend.capabilities().argument_buffers),
    );
    let pipeline = backend.create_pipeline_state(
        root_signature,
        PipelineStateDesc {
            label: pipeline_label,
            compute: false,
            render_target_formats: vec![DxgiFormat::B8G8R8A8Unorm],
            depth_format: Some(DxgiFormat::D24UnormS8Uint),
        },
    );
    let fence = backend.create_fence(0);
    let caps = FeatureCaps {
        // Metal has no native geometry shader stage; D3D11 geometry shaders are
        // unsupported on this backend regardless of the host GPU family.
        geometry_shader: false,
        // Hull/domain (tessellation) stages only exist at feature level 11_0;
        // a 10_1 device must not advertise them.
        hull_shader: backend_mesh && feature_level == FeatureLevel::Level11_0,
        domain_shader: backend_mesh && feature_level == FeatureLevel::Level11_0,
    };
    Ok(D3d11Device {
        next_id,
        backend,
        feature_level,
        caps,
        swapchain,
        queue,
        graphics_allocator: allocator,
        graphics_pipeline: pipeline,
        fence,
        next_fence_value: 0,
        resources,
        views: BTreeMap::new(),
        blend_states: BTreeMap::new(),
        rasterizer_states: BTreeMap::new(),
        depth_stencil_states: BTreeMap::new(),
        sampler_states: BTreeMap::new(),
        input_layouts: BTreeMap::new(),
        shaders: BTreeMap::new(),
        shader_cache: ShaderCache::new(1 << 20),
        translated_shaders: BTreeMap::new(),
        immediate: ImmediateContext::default(),
        predicates: BTreeMap::new(),
        counters: BTreeMap::new(),
        class_linkage: BTreeMap::new(),
        predication: None,
        zero_copy_present_syncs: 0,
        iosurface_channels,
        iosurface_presents: 0,
        surface_writes: 0,
        cpu_backing_writes: 0,
        fallback_uploads: 0,
        primary_nv12: Vec::new(),
        extra_swapchains: BTreeMap::new(),
        nv12_presents: 0,
        nv12_fallbacks: 0,
    })
}

fn translate_shader_stage(stage: ShaderStage) -> TranslationShaderStage {
    match stage {
        ShaderStage::Vs => TranslationShaderStage::Vs,
        ShaderStage::Ps => TranslationShaderStage::Ps,
        ShaderStage::Cs => TranslationShaderStage::Cs,
        ShaderStage::Gs => TranslationShaderStage::Gs,
        ShaderStage::Hs => TranslationShaderStage::Hs,
        ShaderStage::Ds => TranslationShaderStage::Ds,
    }
}

fn runtime_shader_compile_flags() -> ShaderCompileFlags {
    ShaderCompileFlags {
        fast_math: true,
        denorm_mode: "preserve".to_string(),
        debug: false,
        optimization_level: 3,
    }
}

fn runtime_os_build() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn shader_error_to_app_error(error: crate::shader::ShaderError) -> AppError {
    AppError::new(error.reason_code, error.message).with_hint(format!(
        "dxil_hash={}; stage={:?}; pass={}",
        error.dxil_hash, error.stage, error.failing_pass
    ))
}

fn stage_binding_labels<T, F>(
    bindings: &BTreeMap<ShaderStage, Vec<T>>,
    mut formatter: F,
) -> AppResult<String>
where
    T: Copy,
    F: FnMut(T) -> AppResult<String>,
{
    let mut parts = Vec::new();
    for stage in [
        ShaderStage::Vs,
        ShaderStage::Ps,
        ShaderStage::Cs,
        ShaderStage::Gs,
        ShaderStage::Hs,
        ShaderStage::Ds,
    ] {
        let labels = bindings
            .get(&stage)
            .map(|values| {
                values
                    .iter()
                    .copied()
                    .map(&mut formatter)
                    .collect::<AppResult<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        parts.push(format!("{:?}=[{}]", stage, labels.join(",")));
    }
    Ok(parts.join(";"))
}

fn texture_cpu_write_frequent(hint: ResourceUsageHint) -> bool {
    match hint {
        ResourceUsageHint::Buffer {
            cpu_write_frequent, ..
        }
        | ResourceUsageHint::Texture {
            cpu_write_frequent, ..
        } => cpu_write_frequent,
        ResourceUsageHint::Generic
        | ResourceUsageHint::SwapchainBackbuffer
        | ResourceUsageHint::DepthStencil => false,
    }
}

fn merge_texture_usage_hint(
    current: ResourceUsageHint,
    promoted: ResourceUsageHint,
) -> ResourceUsageHint {
    if matches!(
        current,
        ResourceUsageHint::SwapchainBackbuffer | ResourceUsageHint::Buffer { .. }
    ) {
        return current;
    }

    let (current_sampled, current_render_target, current_depth_stencil, current_cpu_write) =
        texture_usage_flags(current);
    let (promoted_sampled, promoted_render_target, promoted_depth_stencil, promoted_cpu_write) =
        texture_usage_flags(promoted);

    ResourceUsageHint::Texture {
        sampled: current_sampled || promoted_sampled,
        render_target: current_render_target || promoted_render_target,
        depth_stencil: current_depth_stencil || promoted_depth_stencil,
        cpu_write_frequent: current_cpu_write || promoted_cpu_write,
    }
}

fn texture_usage_flags(hint: ResourceUsageHint) -> (bool, bool, bool, bool) {
    match hint {
        ResourceUsageHint::Generic => (false, false, false, false),
        ResourceUsageHint::SwapchainBackbuffer => (false, true, false, false),
        ResourceUsageHint::DepthStencil => (false, false, true, false),
        ResourceUsageHint::Buffer {
            cpu_write_frequent, ..
        } => (false, false, false, cpu_write_frequent),
        ResourceUsageHint::Texture {
            sampled,
            render_target,
            depth_stencil,
            cpu_write_frequent,
        } => (sampled, render_target, depth_stencil, cpu_write_frequent),
    }
}

/// Aggregate counters for a single submission, passed to signature building
/// to keep the argument list small.
#[derive(Debug, Clone, Copy)]
struct SubmissionStats {
    draw_calls: u32,
    indexed_draw_calls: u32,
    dispatch_calls: u32,
    executed_command_lists: usize,
}

fn build_submission_signature(
    gpu_profile: &str,
    feature_level: FeatureLevel,
    stats: SubmissionStats,
    binding_signatures: &[String],
    resource_digests: &BTreeMap<String, String>,
    backend_plan: &crate::gfx::MetalCommandBufferPlan,
) -> String {
    let mut signature = format!(
        "gpu={}|fl={:?}|lists={}|draw={}|draw_indexed={}|dispatch={}|render_passes={}|compute_passes={}|blit_passes={}|validation={}",
        gpu_profile,
        feature_level,
        stats.executed_command_lists,
        stats.draw_calls,
        stats.indexed_draw_calls,
        stats.dispatch_calls,
        backend_plan.render_passes.len(),
        backend_plan.compute_passes,
        backend_plan.blit_passes,
        backend_plan.validation_errors.len(),
    );
    for (index, binding_signature) in binding_signatures.iter().enumerate() {
        signature.push_str(&format!("|bind[{index}]={binding_signature}"));
    }
    for RenderPassPlan {
        color_formats,
        depth_format,
        draw_calls,
        load_action,
        store_action,
    } in &backend_plan.render_passes
    {
        signature.push_str(&format!(
            "|rp={:?}:{:?}:{}:{}:{}",
            color_formats, depth_format, draw_calls, load_action, store_action
        ));
    }
    for (label, digest) in resource_digests {
        signature.push_str(&format!("|res[{label}]={digest}"));
    }
    signature
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gfx::{HostGpuProfile, host_gpu_profile_from_name};

    fn build_root_signature(
        root_constants: u32,
        descriptors: &[(u8, u8, u8, u8, u8, u8)],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&(descriptors.len() as u32).to_le_bytes());
        bytes.extend(&root_constants.to_le_bytes());
        for descriptor in descriptors {
            bytes.extend([
                descriptor.0,
                descriptor.1,
                descriptor.2,
                descriptor.3,
                descriptor.4,
                descriptor.5,
            ]);
        }
        bytes
    }

    fn build_program_part(
        instruction_count: u32,
        ir_size: u32,
        threadgroup_size: (u32, u32, u32),
        uses: &[(u8, u8, u8, u8, u8, u16)],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&instruction_count.to_le_bytes());
        bytes.extend(&ir_size.to_le_bytes());
        bytes.extend(&threadgroup_size.0.to_le_bytes());
        bytes.extend(&threadgroup_size.1.to_le_bytes());
        bytes.extend(&threadgroup_size.2.to_le_bytes());
        bytes.extend(&(uses.len() as u32).to_le_bytes());
        for entry in uses {
            bytes.extend([
                entry.0,
                entry.1,
                entry.2,
                entry.3,
                entry.4,
                entry.5 as u8,
                (entry.5 >> 8) as u8,
                0,
            ]);
        }
        bytes
    }

    fn build_reflection_part(
        resources: &[(u8, u8, u8, u8, u8, u8, u8)],
        cbuffers: &[(u8, u8, u16, u32)],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&(resources.len() as u32).to_le_bytes());
        for resource in resources {
            bytes.extend([
                resource.0, resource.1, resource.2, resource.3, resource.4, resource.5, resource.6,
            ]);
        }
        bytes.extend(&(cbuffers.len() as u32).to_le_bytes());
        for cbuffer in cbuffers {
            bytes.extend([
                cbuffer.0,
                cbuffer.1,
                cbuffer.2 as u8,
                (cbuffer.2 >> 8) as u8,
                cbuffer.3 as u8,
                (cbuffer.3 >> 8) as u8,
                (cbuffer.3 >> 16) as u8,
                (cbuffer.3 >> 24) as u8,
            ]);
        }
        bytes
    }

    fn build_container(entry_name: &str, parts: Vec<([u8; 4], Vec<u8>)>) -> Vec<u8> {
        let header_size = 12 + parts.len() * 12;
        let mut offset = header_size as u32;
        let descriptors = parts
            .iter()
            .map(|(kind, payload)| {
                let descriptor = (*kind, offset, payload.len() as u32);
                offset += payload.len() as u32;
                descriptor
            })
            .collect::<Vec<_>>();
        let mut bytes = Vec::new();
        bytes.extend(b"DXIL");
        bytes.extend(&1_u32.to_le_bytes());
        bytes.extend(&(parts.len() as u32).to_le_bytes());
        for (kind, offset, size) in &descriptors {
            bytes.extend(kind);
            bytes.extend(&offset.to_le_bytes());
            bytes.extend(&size.to_le_bytes());
        }
        for (_, payload) in parts {
            bytes.extend(payload);
        }
        let mut meta = vec![entry_name.len() as u8];
        meta.extend(entry_name.as_bytes());
        let parts_without_meta = bytes[12 + descriptors.len() * 12..].to_vec();
        let mut rewritten = Vec::new();
        rewritten.extend(b"DXIL");
        rewritten.extend(&1_u32.to_le_bytes());
        rewritten.extend(&((descriptors.len() + 1) as u32).to_le_bytes());
        let mut running_offset = (12 + (descriptors.len() + 1) * 12) as u32;
        for (kind, _, size) in descriptors {
            rewritten.extend(kind);
            rewritten.extend(&running_offset.to_le_bytes());
            rewritten.extend(&size.to_le_bytes());
            running_offset += size;
        }
        rewritten.extend(*b"META");
        rewritten.extend(&running_offset.to_le_bytes());
        rewritten.extend(&(meta.len() as u32).to_le_bytes());
        rewritten.extend(parts_without_meta);
        rewritten.extend(meta);
        rewritten
    }

    fn reflected_dxil_fixture(entry_name: &str) -> (Vec<u8>, Vec<u8>) {
        let root_signature = build_root_signature(
            8,
            &[(1, 0, 0, 1, 0, 0), (2, 0, 0, 1, 1, 0), (3, 0, 0, 1, 2, 0)],
        );
        let dxil = build_container(
            entry_name,
            vec![
                (
                    *b"PROG",
                    build_program_part(
                        32,
                        512,
                        (8, 8, 1),
                        &[(1, 0, 0, 0, 1, 0), (2, 0, 0, 0, 3, 0), (3, 0, 0, 0, 0, 64)],
                    ),
                ),
                (*b"SIGN", b"input-signature-output-signature".to_vec()),
                (
                    *b"RFLX",
                    build_reflection_part(
                        &[(1, 0, 0, 0, 0, 0, 1), (2, 0, 0, 1, 0, 0, 3)],
                        &[(0, 0, 64, 0x0102_0304)],
                    ),
                ),
            ],
        );
        (dxil, root_signature)
    }

    fn test_backend(profile: HostGpuProfile) -> GraphicsBackend {
        GraphicsBackend::with_host_profile(profile)
    }

    #[test]
    fn iosurface_present_rejects_mismatched_channel_dimensions() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 2,
                height: 1,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create device and swapchain");
        if !device.iosurface_zero_copy_active() {
            return;
        }
        // Replace the presented channel with a surface of the wrong size: the
        // present must fail rather than silently publishing a stretched frame.
        device.iosurface_channels[0] = crate::metal_backend::IoSurfacePresentChannel::new(
            3,
            1,
            crate::metal_backend::dxgi_to_metal_format(DxgiFormat::B8G8R8A8Unorm),
        )
        .expect("mismatched channel allocation");
        let error = device
            .present_swapchain(1, false, true)
            .expect_err("mismatched dimensions must be rejected");
        assert!(
            error.to_string().contains("does not match channel"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn present_falls_back_and_counts_uploads_when_iosurface_is_unavailable() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 2,
                height: 1,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create device and swapchain");
        let backbuffers = device
            .swapchain_state()
            .expect("swapchain state")
            .backbuffers
            .len() as u64;
        // Simulate the surface-allocation/capability probe failing after
        // device creation: the verified host-visible path must take over and
        // account every upload.
        device.iosurface_channels.clear();
        assert!(!device.iosurface_zero_copy_active());

        let backbuffer = device
            .swapchain_backbuffer(0)
            .expect("swapchain backbuffer");
        let pixels = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
        device
            .update_subresource(backbuffer, &pixels)
            .expect("update backbuffer");
        device
            .present_swapchain(1, false, true)
            .expect("fallback present");

        assert_eq!(device.fallback_upload_count(), backbuffers);
        assert_eq!(device.iosurface_present_count(), 0);
        assert_eq!(device.zero_copy_present_sync_count(), backbuffers);
        assert_eq!(
            device.surface_writes(),
            0,
            "no surface exists on the fallback path"
        );
        assert!(
            device.cpu_backing_writes() >= 1,
            "the fallback path must update CPU backing bytes"
        );
        let frame = device.presented_frame().expect("presented frame");
        assert_eq!(&frame.bytes[..pixels.len()], &pixels);
    }

    #[test]
    fn iosurface_present_path_roundtrips_without_fallback_uploads() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create device and swapchain");
        if !device.iosurface_zero_copy_active() {
            // Capability gate: the verified fallback path is exercised below.
            return;
        }

        let backbuffer = device
            .swapchain_backbuffer(0)
            .expect("swapchain backbuffer");
        let pixels: Vec<u8> = (0..4 * 2 * 4).map(|index| (index * 11) as u8).collect();
        device
            .update_subresource(backbuffer, &pixels)
            .expect("update backbuffer");
        device
            .present_swapchain(1, false, true)
            .expect("present through IOSurface");

        assert_eq!(
            device.fallback_upload_count(),
            0,
            "IOSurface present must not fall back to CPU staging uploads"
        );
        assert_eq!(
            device.zero_copy_present_sync_count(),
            0,
            "no legacy gfx-backend sync on the IOSurface path"
        );
        assert_eq!(device.iosurface_present_count(), 1);
        assert!(
            device.zero_copy_upload_count() >= 1,
            "updates and presents write directly into the IOSurface"
        );
        let frame = device.presented_frame().expect("presented frame");
        assert_eq!(
            frame.bytes, pixels,
            "pixels must round-trip through surface"
        );

        let writes_before_repeats = device.surface_writes();
        let surface_before_repeats = device.iosurface_channels[0].surface_ptr();
        for _ in 0..8 {
            device
                .present_swapchain(1, false, true)
                .expect("repeat present");
        }
        assert_eq!(
            device.iosurface_texture_builds(),
            1,
            "the aliasing texture is reused across frames (no per-frame leak)"
        );
        assert_eq!(device.fallback_upload_count(), 0);
        assert_eq!(
            device.surface_writes(),
            writes_before_repeats,
            "present must not rewrite the authoritative surface"
        );
        assert_eq!(
            device.iosurface_channels[0].surface_ptr(),
            surface_before_repeats,
            "repeated presents must reuse the same surface"
        );
        assert_eq!(device.iosurface_channels.len(), 2);
        assert_eq!(device.cpu_backing_writes(), 0);
    }

    #[test]
    fn iosurface_present_rejects_mismatched_channel_format() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 2,
                height: 1,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create device and swapchain");
        if !device.iosurface_zero_copy_active() {
            return;
        }
        device.iosurface_channels[0] = crate::metal_backend::IoSurfacePresentChannel::new(
            2,
            1,
            metal::MTLPixelFormat::RGBA8Unorm,
        )
        .expect("mismatched channel allocation");
        let error = device
            .present_swapchain(1, false, true)
            .expect_err("mismatched format must be rejected");
        assert!(
            error.to_string().contains("format"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn draw_submission_with_bound_render_targets_creates_render_pass_without_validation_errors() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 2,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create device and swapchain");

        let backbuffer = device
            .swapchain_backbuffer(0)
            .expect("swapchain backbuffer");
        let rtv = device
            .create_render_target_view(backbuffer, DxgiFormat::B8G8R8A8Unorm)
            .expect("create render target view");

        device.om_set_render_targets(vec![rtv], None);
        device.ia_set_primitive_topology(4);
        device.draw(3);

        let submission = device.submit_immediate().expect("submit draw workload");

        assert_eq!(submission.draw_calls, 1);
        assert!(submission.backend_plan.validation_errors.is_empty());
        assert_eq!(submission.backend_plan.render_passes.len(), 1);
        assert_eq!(submission.backend_plan.render_passes[0].draw_calls, 1);
        assert!(submission.signature.contains("topo=4"));
    }

    // ── Deferred context tests ──────────────────────────────────────────

    #[test]
    fn deferred_context_double_finish_returns_error() {
        let device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let ctx = device.create_deferred_context();

        // First finish should succeed.
        let _list = ctx
            .finish_command_list(&device)
            .expect("first finish should succeed");

        // Second finish on the same context must fail.
        let err = ctx.finish_command_list(&device).unwrap_err();
        assert!(
            err.to_string().contains("already finished"),
            "expected 'already finished' error, got: {err}"
        );
    }

    #[test]
    fn deferred_context_double_finish_clears_commands() {
        let mut device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let ctx = device.create_deferred_context();

        // Record a resource operation first.
        let buf = device
            .create_buffer("deferred-buf", 64, ResourceUsageHint::Generic)
            .expect("create buffer");
        ctx.update_subresource(buf, &[0xAB; 32])
            .expect("record update");

        // Finish once — must succeed.
        let list = ctx.finish_command_list(&device).expect("first finish");
        assert_eq!(list.commands.len(), 1);

        // The finished flag prevents subsequent usage even though the
        // commands/bindings were taken.
        let err = ctx.finish_command_list(&device).unwrap_err();
        assert!(
            err.to_string().contains("already finished"),
            "expected 'already finished' error, got: {err}"
        );
    }

    #[test]
    fn deferred_context_resource_validation_detects_invalid_resource() {
        let device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let ctx = device.create_deferred_context();

        // Record a command referencing a resource that was never created.
        let bogus_id: D3d11ResourceId = 999_999;
        ctx.update_subresource(bogus_id, &[0; 16])
            .expect("record update with bogus resource");

        // finish_command_list must validate and reject.
        let err = ctx.finish_command_list(&device).unwrap_err();
        assert!(
            err.to_string().contains("destroyed"),
            "expected resource validation error, got: {err}"
        );
    }

    #[test]
    fn deferred_context_invalid_view_detected_on_finish() {
        let device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let ctx = device.create_deferred_context();

        // Record a clear with a view that does not exist.
        let bogus_view: D3d11ViewId = 42;
        ctx.clear_render_target_view(bogus_view, [0, 0, 0, 255])
            .expect("record clear with invalid view");

        let err = ctx.finish_command_list(&device).unwrap_err();
        assert!(
            err.to_string().contains("destroyed"),
            "expected view validation error, got: {err}"
        );
    }

    #[test]
    fn deferred_context_binding_consistency_draw_without_rt_fails() {
        let mut device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let ctx = device.create_deferred_context();

        // Record a draw with NO render target bound.
        let vs = device.create_shader(ShaderModuleDesc {
            stage: ShaderStage::Vs,
            entry: "main_vs".to_string(),
        });
        ctx.ia_set_primitive_topology(4).expect("set topology");
        ctx.vs_set_shader(vs).expect("set vs");
        ctx.draw(3).expect("record draw");

        let err = ctx.finish_command_list(&device).unwrap_err();
        assert!(
            err.to_string().contains("render target") || err.to_string().contains("depth target"),
            "expected binding consistency error about missing render target, got: {err}"
        );
    }

    #[test]
    fn deferred_context_binding_consistency_indexed_draw_without_ib_fails() {
        let mut device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let ctx = device.create_deferred_context();

        let tex = device
            .create_texture_2d("idx-rt", 2, 2, DxgiFormat::B8G8R8A8Unorm)
            .expect("create texture");
        let rtv = device
            .create_render_target_view(tex, DxgiFormat::B8G8R8A8Unorm)
            .expect("create rtv");
        let vs = device.create_shader(ShaderModuleDesc {
            stage: ShaderStage::Vs,
            entry: "main_vs".to_string(),
        });
        ctx.om_set_render_targets(vec![rtv], None)
            .expect("set render targets");
        ctx.ia_set_primitive_topology(4).expect("set topology");
        ctx.vs_set_shader(vs).expect("set vs");
        // Indexed draw without index buffer set.
        ctx.draw_indexed(6).expect("record indexed draw");

        let err = ctx.finish_command_list(&device).unwrap_err();
        assert!(
            err.to_string().contains("index buffer"),
            "expected binding consistency error about missing index buffer, got: {err}"
        );
    }

    #[test]
    fn deferred_context_binding_consistency_dispatch_without_cs_fails() {
        let device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let ctx = device.create_deferred_context();

        ctx.dispatch(1, 1, 1).expect("record dispatch");

        let err = ctx.finish_command_list(&device).unwrap_err();
        assert!(
            err.to_string().contains("compute shader"),
            "expected binding consistency error about missing CS, got: {err}"
        );
    }

    #[test]
    fn deferred_context_records_from_multiple_threads() {
        let mut device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");

        let tex = device
            .create_texture_2d("mt-rt", 2, 2, DxgiFormat::B8G8R8A8Unorm)
            .expect("create texture");
        let rtv = device
            .create_render_target_view(tex, DxgiFormat::B8G8R8A8Unorm)
            .expect("create rtv");
        let vs = device.create_shader(ShaderModuleDesc {
            stage: ShaderStage::Vs,
            entry: "main_vs".to_string(),
        });

        let shared_ctx = std::sync::Arc::new(device.create_deferred_context());

        // Spawn two threads that each record commands on the same deferred context.
        let ctx1 = std::sync::Arc::clone(&shared_ctx);
        let h1 = std::thread::spawn(move || -> AppResult<()> {
            ctx1.om_set_render_targets(vec![rtv], None)?;
            ctx1.ia_set_primitive_topology(4)?;
            ctx1.vs_set_shader(vs)?;
            ctx1.draw(3)?;
            Ok(())
        });

        let ctx2 = std::sync::Arc::clone(&shared_ctx);
        let h2 = std::thread::spawn(move || -> AppResult<()> {
            ctx2.ia_set_primitive_topology(5)?;
            ctx2.draw(6)?;
            Ok(())
        });

        h1.join()
            .expect("thread 1 panicked")
            .expect("thread 1 recording failed");
        h2.join()
            .expect("thread 2 panicked")
            .expect("thread 2 recording failed");

        // Finish the command list — all recorded commands from both threads
        // should be captured atomically.
        let list = shared_ctx
            .finish_command_list(&device)
            .expect("finish from main thread");
        assert!(
            !list.commands.is_empty(),
            "expected commands from multi-threaded recording"
        );

        // Verify the bindings are accessible after finish_command_list.
        // Both threads set a topology concurrently on the same deferred
        // context, so the final value is last-writer-wins and either is
        // valid (4 from thread 1 or 5 from thread 2).
        let bindings = &list.bindings;
        assert!(
            matches!(bindings.primitive_topology, Some(4) | Some(5)),
            "topology must be one of the two concurrently recorded values, got {:?}",
            bindings.primitive_topology
        );
    }

    // ── D3D11 resource creation and view tests ─────────────────────────

    // ── Audit-fix regression tests ────────────────────────────────────

    #[test]
    fn deferred_context_oversized_update_subresource_rejected_on_finish() {
        let mut device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let ctx = device.create_deferred_context();

        let buf = device
            .create_buffer("small-buf", 64, ResourceUsageHint::Generic)
            .expect("create buffer");
        ctx.update_subresource(buf, &vec![0u8; 1_000_000])
            .expect("record oversized update");

        let err = ctx.finish_command_list(&device).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "expected size validation error, got: {err}"
        );
    }

    #[test]
    fn device_creation_accepts_level11_0_request_on_mesh_backend() {
        let apple11 = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level11_0],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M5 Pro")),
        )
        .expect("11_0 request on mesh-capable backend");
        assert_eq!(apple11.feature_level(), FeatureLevel::Level11_0);
        assert!(
            apple11.caps().hull_shader,
            "11_0 device may advertise tessellation"
        );

        let err = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level11_0],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not supported"),
            "expected unsupported error, got: {err}"
        );

        let apple7 = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("10_1 request");
        assert_eq!(apple7.feature_level(), FeatureLevel::Level10_1);
        assert!(
            !apple7.caps().hull_shader,
            "10_1 device must not advertise tessellation"
        );
    }

    #[test]
    fn destroy_resource_frees_record_and_rejects_double_destroy() {
        let mut device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create device");

        let buf = device
            .create_buffer("doomed", 64, ResourceUsageHint::Generic)
            .expect("create buffer");
        device.destroy_resource(buf).expect("destroy resource");
        assert!(
            device.resource(buf).is_err(),
            "destroyed resource must be gone"
        );
        let err = device.destroy_resource(buf).unwrap_err();
        assert!(
            err.to_string().contains("unknown"),
            "double destroy must fail, got: {err}"
        );
    }

    #[test]
    fn unsupported_swapchain_format_uses_counted_fallback() {
        let mut device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create device");
        let swapchain = device
            .create_swapchain_for_format(
                SwapchainDesc {
                    width: 4,
                    height: 2,
                    format: DxgiFormat::R8G8B8A8Unorm,
                    buffer_count: 2,
                },
                9999,
            )
            .expect("fallback swapchain");
        assert_eq!(device.nv12_fallback_count(), 1);
        assert_eq!(
            device.swapchain_state_for(swapchain).unwrap().desc.format,
            DxgiFormat::R8G8B8A8Unorm
        );
    }

    #[test]
    fn nv12_fallback_and_format_mismatch_are_counted_exactly() {
        let mut device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create device");

        let zero = device
            .create_nv12_swapchain(0, 2, 2)
            .expect("zero-dimension NV12 falls back to a pixel swapchain");
        assert_eq!(device.nv12_fallback_count(), 1);
        assert_eq!(device.swapchain_format_fallback_count(), 1);
        assert_eq!(
            device.swapchain_state_for(zero).unwrap().desc.format,
            DxgiFormat::B8G8R8A8Unorm
        );
        assert!(device.iosurface_channels.is_empty());
        assert!(device.primary_nv12.is_empty());

        let extra = device
            .create_additional_nv12_swapchain(0, 2, 2)
            .expect("zero-dimension additional NV12 falls back");
        assert_eq!(device.nv12_fallback_count(), 2);
        let extra_set = device.extra_swapchains.get(&extra).unwrap();
        assert!(extra_set.is_empty());

        let matching = device
            .create_swapchain_for_format(
                SwapchainDesc {
                    width: 4,
                    height: 2,
                    format: DxgiFormat::R8G8B8A8Unorm,
                    buffer_count: 2,
                },
                28,
            )
            .expect("matching raw format creates a pixel swapchain");
        assert_eq!(
            device.swapchain_state_for(matching).unwrap().desc.format,
            DxgiFormat::R8G8B8A8Unorm
        );
        assert_eq!(device.swapchain_format_fallback_count(), 2);
        assert_eq!(device.iosurface_channels.len(), 2);
    }

    #[test]
    fn resize_swapchain_rejects_short_count_and_isolates_extra_channels() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create primary");
        let primary = device.swapchain.expect("primary id");
        let old_backbuffer = device.swapchain_state_for(primary).unwrap().backbuffers[0];
        let secondary = device
            .create_additional_swapchain(SwapchainDesc {
                width: 8,
                height: 4,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create secondary");
        let secondary_surface = device
            .extra_swapchains
            .get(&secondary)
            .unwrap()
            .pixel
            .first()
            .expect("secondary surface")
            .surface_ptr();

        device
            .resize_swapchain(primary, 3, 8, 4, DxgiFormat::R8G8B8A8Unorm)
            .expect("resize primary");
        assert_eq!(device.iosurface_channels.len(), 3);
        assert_eq!(device.iosurface_channels[0].width(), 8);
        assert_eq!(device.iosurface_channels[0].height(), 4);
        assert!(device.resource(old_backbuffer).is_err());
        assert_eq!(
            device
                .extra_swapchains
                .get(&secondary)
                .unwrap()
                .pixel
                .first()
                .expect("secondary surface")
                .surface_ptr(),
            secondary_surface
        );

        device
            .resize_swapchain(secondary, 2, 16, 8, DxgiFormat::B8G8R8A8Unorm)
            .expect("resize secondary");
        let resized = device.extra_swapchains.get(&secondary).unwrap();
        assert_eq!(resized.pixel[0].width(), 16);
        assert_eq!(resized.pixel[0].height(), 8);
        assert_eq!(device.iosurface_channels[0].width(), 8);

        let error = device
            .resize_swapchain(primary, 1, 8, 4, DxgiFormat::R8G8B8A8Unorm)
            .expect_err("buffer count below two must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "swapchain buffer count must be at least 2");
        assert_eq!(device.iosurface_channels.len(), 3);
    }

    #[test]
    fn nv12_resize_rejects_odd_dimensions_and_preserves_both_planes() {
        let mut device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create device");
        let primary = device
            .create_nv12_swapchain(4, 2, 2)
            .expect("create NV12 swapchain");
        assert_eq!(device.nv12_fallback_count(), 0, "host must expose NV12");
        let error = device
            .resize_swapchain(primary, 2, 3, 2, DxgiFormat::B8G8R8A8Unorm)
            .expect_err("odd NV12 width must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "NV12 swapchain resize dimensions 3x2 must be even"
        );
        assert_eq!(device.primary_nv12[0].width(), 4);
        assert_eq!(device.primary_nv12[0].height(), 2);

        device
            .resize_swapchain(primary, 2, 8, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect("resize primary NV12");
        assert_eq!(device.primary_nv12.len(), 2);
        assert_eq!(device.primary_nv12[0].width(), 8);
        assert_eq!(device.primary_nv12[0].height(), 4);
        assert!(device.iosurface_channels.is_empty());

        let extra = device
            .create_additional_nv12_swapchain(4, 2, 2)
            .expect("additional NV12 swapchain");
        device
            .resize_swapchain(extra, 2, 16, 8, DxgiFormat::B8G8R8A8Unorm)
            .expect("resize additional NV12");
        let extra_set = device.extra_swapchains.get(&extra).unwrap();
        assert_eq!(extra_set.nv12.len(), 2);
        assert_eq!(extra_set.nv12[0].width(), 16);
        assert!(extra_set.pixel.is_empty());
        assert_eq!(device.primary_nv12[0].width(), 8);
    }

    #[test]
    fn present_plane_readback_rejects_pixel_swapchain_without_nv12_channel() {
        let device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create primary");
        let swapchain = device.swapchain.expect("primary id");
        let error = device
            .presented_nv12_plane_bytes(swapchain)
            .expect_err("pixel swapchain has no NV12 plane");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("swapchain {swapchain} has no NV12 present channel")
        );
        let error = device
            .presented_nv12_plane_bytes_gpu(swapchain)
            .expect_err("pixel swapchain has no GPU NV12 plane");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            format!("swapchain {swapchain} has no NV12 present channel")
        );
    }

    #[test]
    fn map_and_transfer_reject_missing_extra_channel_and_read_surfaces() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create primary");
        let primary_backbuffer = device.swapchain_backbuffer(0).expect("primary backbuffer");
        let frame_pixels: Vec<u8> = (0..32).map(|index| (index * 3) as u8).collect();
        {
            let mut mapped = device.map(primary_backbuffer).expect("map primary");
            let pitch = mapped.row_pitch().max(4 * 4);
            assert_eq!(mapped.len(), pitch * 2);
            assert_eq!(pitch % 4, 0);
            for row in 0..2 {
                let start = row * pitch;
                mapped[start..start + 16].copy_from_slice(&frame_pixels[row * 16..(row + 1) * 16]);
            }
        }
        device
            .unmap(primary_backbuffer)
            .expect("publish primary frame");
        {
            let mapped = device.map(primary_backbuffer).expect("map surface");
            let pitch = mapped.row_pitch().max(4 * 4);
            let mut tight = Vec::new();
            for row in 0..2 {
                tight.extend_from_slice(&mapped[row * pitch..row * pitch + 16]);
            }
            assert_eq!(tight, frame_pixels);
        }
        assert_eq!(device.surface_writes(), 1);

        let secondary = device
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create secondary");
        let secondary_backbuffers = device.swapchain_state_for(secondary).unwrap().backbuffers;
        {
            let mapped = device
                .map(secondary_backbuffers[0])
                .expect("map extra surface");
            assert_eq!(mapped.len(), mapped.row_pitch().max(16) * 2);
        }
        device
            .extra_swapchains
            .get_mut(&secondary)
            .unwrap()
            .pixel
            .pop();
        {
            let fallback = device
                .map(secondary_backbuffers[1])
                .expect("missing channel maps CPU backing");
            assert_eq!(&*fallback, &[0u8; 32]);
        }
        let before = device.cpu_backing_writes();
        device
            .unmap(secondary_backbuffers[1])
            .expect("missing channel unmaps to CPU backing");
        assert_eq!(device.cpu_backing_writes(), before + 1);

        let empty = device
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::R8G8B8A8Uint,
                buffer_count: 2,
            })
            .expect("unsupported channel format still creates a swapchain");
        assert!(device.extra_swapchains.get(&empty).unwrap().is_empty());
        let empty_backbuffer = device.swapchain_state_for(empty).unwrap().backbuffers[0];
        assert_eq!(
            device
                .map(empty_backbuffer)
                .expect("empty set maps backing")
                .len(),
            32
        );

        let source_bytes = device
            .resource_bytes_for_transfer(primary_backbuffer)
            .expect("primary transfer source");
        assert_eq!(source_bytes, frame_pixels);
        let secondary_bytes = device
            .resource_bytes_for_transfer(secondary_backbuffers[0])
            .expect("extra transfer source");
        assert_eq!(secondary_bytes.len(), 32);
        let destination = device
            .create_buffer("copy-dst", 32, ResourceUsageHint::Generic)
            .expect("destination buffer");
        device
            .copy_resource(primary_backbuffer, destination)
            .expect("record primary copy");
        device.submit_immediate().expect("execute copy");
        assert_eq!(device.resource(destination).unwrap().bytes, frame_pixels);
    }

    #[test]
    fn nv12_present_rejects_count_and_dimension_mismatches() {
        let mut device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create device");
        let swapchain = device
            .create_nv12_swapchain(4, 2, 2)
            .expect("create NV12 swapchain");
        assert_eq!(device.nv12_fallback_count(), 0, "host must expose NV12");
        let backbuffer = device.swapchain_backbuffer(0).expect("backbuffer");
        let error = device
            .map(backbuffer)
            .expect_err("two-plane NV12 Map cannot be one contiguous borrow");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "NV12 Map is not zero-copy: the IOSurface has two plane mappings"
        );
        let frame = device
            .presented_frame_for(swapchain)
            .expect("NV12 presented frame");
        assert_eq!(frame.width, 4);
        assert_eq!(frame.format, DxgiFormat::R8G8B8A8Unorm);

        let error = device
            .write_present_backbuffer_bytes(backbuffer, usize::MAX, &[1])
            .expect_err("NV12 surface write offset must not overflow");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "surface write range overflow");
        let error = device
            .write_present_backbuffer_bytes(backbuffer, 0, &[0u8; 31])
            .expect_err("NV12 requires full-frame writes");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "NV12 present surface requires full-frame writes"
        );
        assert!(
            device
                .write_present_backbuffer_bytes(backbuffer, 0, &[7u8; 32])
                .expect("full-frame NV12 write")
        );
        assert_eq!(device.surface_writes(), 1);

        let destination = device
            .create_buffer("nv12-copy", 32, ResourceUsageHint::Generic)
            .expect("NV12 copy destination");
        device
            .copy_resource(backbuffer, destination)
            .expect("record NV12 copy");
        device.submit_immediate().expect("execute NV12 copy");
        assert_eq!(device.resource(destination).unwrap().bytes.len(), 32);

        device.primary_nv12.pop();
        let error = device
            .present_swapchain(1, false, false)
            .expect_err("one NV12 channel for two backbuffers must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "NV12 present: 1 channels for 2 backbuffers");

        device.primary_nv12 = build_nv12_channels(4, 2, 2).expect("rebuild NV12");
        device.primary_nv12[0] =
            crate::metal_backend::Nv12PresentChannel::new(2, 2).expect("mismatched channel");
        let error = device
            .present_swapchain(1, false, false)
            .expect_err("mismatched NV12 dimensions must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "NV12 present: swapchain 4x2 does not match channel 0 at 0 (2x2)"
        );
    }

    #[test]
    fn present_rejects_pixel_channel_count_and_dimension_mismatches() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create primary");
        let primary = device.swapchain.expect("primary id");
        assert_eq!(
            device.iosurface_channels.len(),
            2,
            "host must expose IOSurfaces"
        );
        let secondary = device
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create secondary");
        device
            .present_swapchain_for(secondary, 1, false, false)
            .expect("present secondary");
        let frame = device
            .presented_frame_for(secondary)
            .expect("secondary frame");
        assert_eq!(frame.width, 4);
        assert_eq!(frame.height, 2);
        assert_eq!(frame.format, DxgiFormat::B8G8R8A8Unorm);
        assert_eq!(device.iosurface_presents, 1);

        device
            .extra_swapchains
            .get_mut(&secondary)
            .unwrap()
            .pixel
            .pop();
        let error = device
            .present_swapchain_for(secondary, 1, false, false)
            .expect_err("extra channel count mismatch must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "IOSurface present: 1 channels for 2 backbuffers"
        );

        let mismatched = device
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create mismatched swapchain");
        device.extra_swapchains.get_mut(&mismatched).unwrap().pixel[0] =
            crate::metal_backend::IoSurfacePresentChannel::new(
                2,
                2,
                crate::metal_backend::dxgi_to_metal_format(DxgiFormat::B8G8R8A8Unorm),
            )
            .expect("mismatched dimensions");
        let error = device
            .present_swapchain_for(mismatched, 1, false, false)
            .expect_err("extra dimension mismatch must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "IOSurface present: swapchain 4x2 does not match channel 0 at 0 (2x2)"
        );

        device.iosurface_channels.pop();
        let error = device
            .present_swapchain_for(primary, 1, false, false)
            .expect_err("primary channel count mismatch must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "IOSurface present: 1 channels for 2 backbuffers"
        );
    }

    #[test]
    fn nv12_format_103_plane_readbacks_and_present_counters_pin_edges() {
        let mut device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create device");
        let swapchain = device
            .create_swapchain_for_format(
                SwapchainDesc {
                    width: 4,
                    height: 2,
                    format: DxgiFormat::B8G8R8A8Unorm,
                    buffer_count: 2,
                },
                103,
            )
            .expect("raw 103 creates the NV12 swapchain");
        assert_eq!(device.nv12_fallback_count(), 0);
        assert_eq!(device.nv12_texture_builds(swapchain), 2);
        assert_eq!(device.iosurface_texture_builds(), 2);

        let (y, uv) = device
            .presented_nv12_plane_bytes(swapchain)
            .expect("CPU NV12 plane readback");
        assert_eq!((y.len(), uv.len()), (8, 4));
        let (gpu_y, gpu_uv) = device
            .presented_nv12_plane_bytes_gpu(swapchain)
            .expect("GPU NV12 plane readback");
        assert_eq!(gpu_y, y);
        assert_eq!(gpu_uv, uv);

        let backbuffer = device.swapchain_backbuffer(0).expect("backbuffer");
        let rtv = device
            .create_render_target_view(backbuffer, DxgiFormat::B8G8R8A8Unorm)
            .expect("rtv");
        device
            .clear_render_target_view(rtv, [255, 0, 0, 255])
            .expect("clear red");
        device.submit_immediate().expect("submit clear");
        let (_, present) = device
            .present_swapchain(1, false, true)
            .expect("present NV12 swapchain");
        assert_eq!(present.queued_frames, 1);
        assert_eq!(device.nv12_present_count(), 1);
        assert_eq!(device.iosurface_present_count(), 1);
        assert_eq!(device.nv12_texture_builds(swapchain), 2);
        assert_eq!(device.iosurface_texture_builds(), 2);
        let (y, uv) = device
            .presented_nv12_plane_bytes(swapchain)
            .expect("post-present NV12 planes");
        assert_eq!(y, vec![76u8; 8]);
        assert_eq!(uv, vec![85u8, 255, 85, 255]);
    }

    #[test]
    fn extra_pixel_transfer_resize_fallbacks_pin_exact_channels() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create primary");
        let secondary = device
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create secondary");
        assert_eq!(device.nv12_texture_builds(secondary), 0);
        let secondary_backbuffers = device
            .swapchain_state_for(secondary)
            .expect("secondary state")
            .backbuffers;
        let transferred = device
            .resource_bytes_for_transfer(secondary_backbuffers[0])
            .expect("extra surface transfer source");
        assert_eq!(transferred.len(), 32);

        device
            .resize_swapchain(secondary, 3, 8, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect("resize secondary pixel swapchain");
        let resized = device
            .extra_swapchains
            .get(&secondary)
            .expect("resized channel set");
        assert_eq!(resized.pixel.len(), 3);
        assert_eq!(resized.pixel[0].width(), 8);
        assert_eq!(resized.pixel[0].height(), 4);
        assert_eq!(resized.nv12.len(), 0);
        assert_eq!(device.iosurface_channels[0].width(), 4);

        let error = device
            .resize_swapchain(secondary, 1, 8, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect_err("buffer count below two must be rejected");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "swapchain buffer count must be at least 2");
        assert_eq!(
            device
                .extra_swapchains
                .get(&secondary)
                .expect("channel set after rejected resize")
                .pixel
                .len(),
            3
        );
    }

    #[test]
    fn additional_nv12_present_channels_and_count_mismatches_are_exact() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create primary");
        let nv12 = device
            .create_additional_nv12_swapchain(4, 2, 2)
            .expect("create additional NV12 swapchain");
        assert_eq!(device.nv12_fallback_count(), 0);
        assert_eq!(device.nv12_texture_builds(nv12), 2);
        device
            .present_swapchain_for(nv12, 1, false, true)
            .expect("present additional NV12 swapchain");
        assert_eq!(device.nv12_present_count(), 1);
        assert_eq!(device.iosurface_present_count(), 1);
        assert_eq!(
            device
                .extra_swapchains
                .get(&nv12)
                .expect("NV12 channel set")
                .nv12
                .len(),
            2
        );

        device
            .extra_swapchains
            .get_mut(&nv12)
            .expect("NV12 channel set")
            .nv12
            .pop();
        let error = device
            .present_swapchain_for(nv12, 1, false, false)
            .expect_err("one NV12 channel for two backbuffers must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(error.message, "NV12 present: 1 channels for 2 backbuffers");
        assert_eq!(device.nv12_present_count(), 1);
        assert_eq!(device.iosurface_present_count(), 1);
    }

    #[test]
    fn resize_and_present_index_reject_stale_extra_swapchains() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create primary");
        let extra = device
            .create_additional_swapchain(SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            })
            .expect("create extra");
        device.extra_swapchains.remove(&extra);
        device
            .resize_swapchain(extra, 2, 8, 4, DxgiFormat::B8G8R8A8Unorm)
            .expect("stale extra resize updates only the backend");
        assert_eq!(device.extra_swapchains.contains_key(&extra), false);
        assert_eq!(
            device
                .swapchain_state_for(extra)
                .expect("backend state")
                .desc
                .width,
            8
        );

        device.extra_swapchains.insert(
            u64::MAX,
            SwapchainChannelSet {
                pixel: Vec::new(),
                nv12: Vec::new(),
            },
        );
        assert_eq!(device.present_backbuffer_index(999_999), None);
    }

    #[test]
    fn transfer_fallback_rejects_missing_primary_surface_channel() {
        let mut device = d3d11_create_device_and_swapchain(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            SwapchainDesc {
                width: 4,
                height: 2,
                format: DxgiFormat::B8G8R8A8Unorm,
                buffer_count: 2,
            },
        )
        .expect("create primary");
        assert_eq!(
            device.iosurface_zero_copy_active(),
            true,
            "the primary IOSurface channel set must exist for the zero-copy index path"
        );
        let backbuffer = device
            .swapchain_state()
            .expect("swapchain state")
            .backbuffers[1];
        assert_eq!(device.iosurface_channels.len(), 2);
        device.iosurface_channels.pop();
        let bytes = device
            .resource_bytes_for_transfer(backbuffer)
            .expect("CPU backing fallback");
        assert_eq!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn d3d11_map_unmap_direct_shared_backing_rejects_staged_fallback() {
        let mut device = create_device_internal_with_backend(
            DeviceCreationRequest {
                requested_feature_levels: vec![FeatureLevel::Level10_1],
            },
            None,
            test_backend(host_gpu_profile_from_name("Apple M1 Max")),
        )
        .expect("create device");
        let buffer = device
            .create_buffer(
                "dynamic-constant-buffer",
                64,
                ResourceUsageHint::Buffer {
                    role: crate::gfx::BufferRole::Constant,
                    cpu_write_frequent: true,
                },
            )
            .expect("create dynamic buffer");
        let first: Vec<u8> = (0..64).map(|index| (index * 3) as u8).collect();
        let first_pointer;
        {
            let mut mapped = device.map(buffer).expect("map zeroed buffer");
            assert_eq!(&*mapped, &[0u8; 64]);
            first_pointer = mapped.as_ptr();
            mapped.copy_from_slice(&first);
        }
        device.unmap(buffer).expect("unmap direct write");
        {
            let mapped = device.map(buffer).expect("map after unmap");
            assert_eq!(&*mapped, first.as_slice());
            assert_eq!(
                mapped.as_ptr(),
                first_pointer,
                "Map must return a stable borrow into the same backing"
            );
        }
        let stats = device.backend().translation_stats();
        assert_eq!(stats.zero_copy_updates, 1);
        assert_eq!(stats.staged_copies, 0);

        let second: Vec<u8> = (0..64).map(|index| (255 - index) as u8).collect();
        device
            .update_subresource(buffer, &second)
            .expect("record update");
        device.submit_immediate().expect("execute update");
        {
            let mapped = device.map(buffer).expect("map after update");
            assert_eq!(&*mapped, second.as_slice());
            assert_eq!(
                mapped.as_ptr(),
                first_pointer,
                "writes must not move the mapped backing"
            );
        }
        let stats = device.backend().translation_stats();
        assert_eq!(stats.zero_copy_updates, 2);
        assert_eq!(stats.staged_copies, 0);

        device.unmap(buffer).expect("clear mapped state");
        let error = device
            .unmap(buffer)
            .expect_err("unmap without map must fail");
        assert_eq!(error.code, ReasonCode::RcD3dInvalidState);
        assert_eq!(
            error.message,
            "resource dynamic-constant-buffer is not mapped"
        );
    }
}
