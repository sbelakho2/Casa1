use crate::canonical::{GfxFrame, GuestException, PerfMetric};
use crate::cpu::{
    CpuEngineConfig, CpuExecutionEngine, CpuState, DecodedInstruction, DecodedOpcode, GuestArch,
    IrInstruction, MemoryImage, Register,
};
use crate::d3d11::{
    d3d11_create_device, d3d11_create_device_and_swapchain, D3d11Device, D3d11ResourceId,
    D3d11ViewId, DeviceCreationRequest, FeatureLevel, InputElementDesc, InputLayoutDesc,
    InputLayoutId, ResourceDimension, ShaderStage as D3d11ShaderStage, ViewKind,
};
use crate::error::{AppError, AppResult};
use crate::ge::GameEnvironment;
use crate::gfx::{DxgiFormat, SwapchainDesc};
use crate::pe::{self, ApiSetResolver, ExportSymbol, ExportTarget, ImportSymbol, ResolvedImport};
use crate::live::{LiveAudioChunk, LiveFrame, LiveInputEvent, LivePeSession};
use crate::reason::ReasonCode;
use crate::shader::parse_dxil_container;
use crate::trace::TraceEvent;
use crate::audio::{AudioSamples, AudioSubsystem, SampleFormat, SourceBuffer, VoiceId, WaveFormat};
use crate::user32::{KeyboardDevice, KeyboardLayoutId, KeyModifiers, Message, MessageKind, User32Subsystem};
use crate::util;
use crate::win32::{CreationDisposition, Win32Subsystem};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SYNTHETIC_PID_DTM: u32 = 4242;
const STACK_BASE: u64 = 0x0000_7fff_1000_0000;
const STACK_SIZE: usize = 0x1_0000;
const THUNK_BASE: u64 = 0x0000_7fff_8000_0000;
const CRT_DATA_BASE: u64 = 0x0000_7fff_8100_0000;
const CRT_HEAP_BASE: u64 = 0x0000_7fff_8200_0000;
const MEMORY_BASIC_INFORMATION64_SIZE: u64 = 48;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x0002_0000;
const MEM_IMAGE: u32 = 0x0100_0000;
const E_INVALIDARG: u64 = 0x8007_0057;
const INVALID_HANDLE_VALUE: u64 = u64::MAX;
const PE_RUNTIME_INSTRUCTION_BUDGET: u64 = 25_000_000;
const KEYBOARD_REPLAY_ENV: &str = "CASA1_KEYBOARD_REPLAY_JSON";
const PE_RUNTIME_BUDGET_ENV: &str = "CASA1_PE_RUNTIME_BUDGET";
const EXPORT_FINAL_FRAME_ENV: &str = "CASA1_EXPORT_FINAL_FRAME";
const TRACE_CATEGORIES_ENV: &str = "CASA1_TRACE_CATEGORIES";
const INSTRUCTION_CACHE_LIMIT: usize = 8_192;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_LOCK_VIOLATION: u32 = 33;
const ERROR_ALREADY_EXISTS: u32 = 183;

#[derive(Debug, Clone)]
pub struct PeExecutionResult {
    pub synthetic_pid: u32,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub guest_exceptions: Vec<GuestException>,
    pub gfx_frames: Vec<GfxFrame>,
    pub perf: Vec<PerfMetric>,
    pub trace_events: Vec<TraceEvent>,
}

#[derive(Debug, Default)]
pub struct PeExecutionOptions {
    pub live_session: Option<LivePeSession>,
}

#[derive(Debug, Clone, Deserialize)]
struct KeyboardReplayEvent {
    scancode: u16,
    #[serde(default)]
    shift: bool,
    #[serde(default)]
    altgr: bool,
}

#[derive(Debug, Clone)]
enum HostThunk {
    D3D11CreateDevice,
    D3D11CreateDeviceAndSwapChain,
    D3D11DeviceCreateBuffer,
    D3D11DeviceCreateShaderResourceView,
    D3D11DeviceCreateInputLayout,
    D3D11DeviceCreateVertexShader,
    D3D11DeviceCreatePixelShader,
    D3D11DeviceCreateComputeShader,
    D3D11DeviceGetImmediateContext,
    D3D11DeviceContextVSSetConstantBuffers,
    D3D11DeviceContextPSSetShaderResources,
    D3D11DeviceContextVSSetShader,
    D3D11DeviceContextPSSetShader,
    D3D11DeviceContextCSSetShader,
    D3D11DeviceContextIASetInputLayout,
    D3D11DeviceContextUpdateSubresource,
    DXGISwapChainGetBuffer,
    DXGISwapChainPresent,
    XAudio2Create,
    GuestObjectAddRef,
    GuestObjectRelease,
    UnsupportedMethod { name: String },
    XAudio2CreateMasteringVoice,
    XAudio2CreateSourceVoice,
    XAudio2StartEngine,
    XAudio2StopEngine,
    XAudio2SourceVoiceStart,
    XAudio2SourceVoiceStop,
    XAudio2SourceVoiceSubmitSourceBuffer,
    XAudio2SourceVoiceFlushSourceBuffers,
    XAudio2VoiceDestroyVoice,
    RegisterClassExW,
    CreateWindowExW,
    PeekMessageW,
    DispatchMessageW,
    DefWindowProcW,
    CreateFileW,
    ReadFile,
    WriteFile,
    CloseHandle,
    Calloc,
    Free,
    Malloc,
    SetNewMode,
    CSpecificHandler,
    PArgc,
    PArgv,
    Cexit,
    ConfigureNarrowArgv,
    CrtAtExit,
    CrtExit,
    InitializeNarrowEnvironment,
    Initterm,
    InittermE,
    SetAppType,
    SetInvalidParameterHandler,
    Abort,
    Exit,
    Signal,
    AcrtIobFunc,
    PCommode,
    PFmode,
    StdioCommonVfprintf,
    Fwrite,
    Strlen,
    Strncmp,
    PEnviron,
    SetUserMathErr,
    DeleteCriticalSection,
    EnterCriticalSection,
    GetLastError,
    InitializeCriticalSection,
    LeaveCriticalSection,
    SetUnhandledExceptionFilter,
    Beep,
    Sleep,
    TlsGetValue,
    VirtualProtect,
    VirtualQuery,
    ExitProcess,
    MessageBoxW,
    Unsupported { dll: String, symbol: String },
}

#[derive(Debug, Clone, Default)]
struct CrtGlobals {
    argc_ptr: u64,
    argv_ptr_ptr: u64,
    environ_ptr_ptr: u64,
    commode_ptr: u64,
    fmode_ptr: u64,
    iob_streams: [u64; 3],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuestObjectKind {
    XAudio2Engine,
    XAudio2MasteringVoice,
    XAudio2SourceVoice,
    D3d11Device,
    D3d11DeviceContext,
    DxgiSwapChain,
    D3d11Buffer,
    D3d11Texture2D,
    D3d11View,
    D3d11InputLayout,
    D3d11Shader,
}

#[derive(Debug, Clone, Copy)]
struct GuestObjectMeta {
    kind: GuestObjectKind,
    refcount: u32,
}

#[derive(Debug, Clone)]
struct GuestXAudio2Engine {
    mastering_voice: Option<u64>,
    source_voices: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
struct GuestXAudio2Voice {
    engine_object: u64,
    voice_id: VoiceId,
}

struct GuestD3d11Device {
    device: D3d11Device,
    context_object: u64,
    swapchain_object: Option<u64>,
    backbuffer_objects: BTreeMap<u32, u64>,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11Context {
    device_object: u64,
}

#[derive(Debug, Clone, Copy)]
struct GuestDxgiSwapChain {
    device_object: u64,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11Texture2D {
    device_object: u64,
    resource_id: D3d11ResourceId,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11Buffer {
    device_object: u64,
    resource_id: D3d11ResourceId,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11View {
    device_object: u64,
    view_id: D3d11ViewId,
    kind: ViewKind,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11InputLayout {
    device_object: u64,
    layout_id: InputLayoutId,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11Shader {
    device_object: u64,
    shader_id: u64,
    stage: D3d11ShaderStage,
}

struct PeHostRuntime {
    audio: AudioSubsystem,
    win32: Win32Subsystem,
    user32: User32Subsystem,
    live_session: Option<LivePeSession>,
    live_keyboard_device: Option<String>,
    pending_keyboard_replay: Vec<KeyboardReplayEvent>,
    keyboard_replay_device: Option<String>,
    keyboard_replay_injected: bool,
    host_thunks: BTreeMap<u64, HostThunk>,
    guest_objects: BTreeMap<u64, GuestObjectMeta>,
    xaudio_engines: BTreeMap<u64, GuestXAudio2Engine>,
    xaudio_mastering_voices: BTreeMap<u64, GuestXAudio2Voice>,
    xaudio_source_voices: BTreeMap<u64, GuestXAudio2Voice>,
    d3d11_devices: BTreeMap<u64, GuestD3d11Device>,
    d3d11_contexts: BTreeMap<u64, GuestD3d11Context>,
    d3d11_swapchains: BTreeMap<u64, GuestDxgiSwapChain>,
    d3d11_buffers: BTreeMap<u64, GuestD3d11Buffer>,
    d3d11_textures: BTreeMap<u64, GuestD3d11Texture2D>,
    d3d11_views: BTreeMap<u64, GuestD3d11View>,
    d3d11_input_layouts: BTreeMap<u64, GuestD3d11InputLayout>,
    d3d11_shaders: BTreeMap<u64, GuestD3d11Shader>,
    instruction_cache: BTreeMap<u64, CachedInstruction>,
    allowed_trace_categories: Option<BTreeSet<String>>,
    trace_events: Vec<TraceEvent>,
    gfx_frames: Vec<GfxFrame>,
    next_trace_index: u64,
    next_thunk_address: u64,
    next_data_address: u64,
    next_heap_address: u64,
    heap_allocations: BTreeMap<u64, usize>,
    critical_sections: BTreeMap<u64, usize>,
    signal_handlers: BTreeMap<i32, u64>,
    tls_slots: BTreeMap<u32, u64>,
    atexit_handlers: Vec<u64>,
    last_error: u32,
    invalid_parameter_handler: u64,
    unhandled_exception_filter: u64,
    mapped_image_base: u64,
    mapped_image_size: u64,
    teb_base: u64,
    peb_base: u64,
    globals: CrtGlobals,
    stdout: String,
    stderr: String,
    next_frame_index: u32,
    next_audio_buffer_tag: u64,
    dtm: bool,
}

#[derive(Debug, Clone)]
struct CachedInstruction {
    bytes: Vec<u8>,
    decoded: DecodedInstruction,
    ir: Vec<IrInstruction>,
}

pub fn synthetic_pid(dtm: bool) -> u32 {
    if dtm {
        SYNTHETIC_PID_DTM
    } else {
        std::process::id().saturating_add(10_000)
    }
}

pub fn is_pe_image(path: &Path) -> AppResult<bool> {
    let bytes = fs::read(path).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", path.display()),
            &error,
        )
    })?;
    Ok(bytes.starts_with(b"MZ"))
}

pub fn execute(
    program: &Path,
    ge: &GameEnvironment,
    _cwd: &Path,
    env: &BTreeMap<String, String>,
    dtm: bool,
    test_id: &str,
) -> AppResult<PeExecutionResult> {
    execute_with_options(
        program,
        ge,
        _cwd,
        env,
        dtm,
        test_id,
        PeExecutionOptions::default(),
    )
}

pub fn execute_with_options(
    program: &Path,
    ge: &GameEnvironment,
    _cwd: &Path,
    env: &BTreeMap<String, String>,
    dtm: bool,
    test_id: &str,
    options: PeExecutionOptions,
) -> AppResult<PeExecutionResult> {
    let bytes = fs::read(program).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", program.display()),
            &error,
        )
    })?;
    let image = pe::parse_from_file(program)?;
    if image.machine != 0x8664 {
        return Err(AppError::new(
            ReasonCode::RcPeParseInvalid,
            format!("unsupported PE machine 0x{:04x}", image.machine),
        )
        .with_hint("only x86_64 PE32+ images are currently executable"));
    }

    let live_mode = options.live_session.is_some();
    let mut runtime = PeHostRuntime::new(
        ge.clone(),
        dtm,
        load_keyboard_replay(env)?,
        options.live_session,
        load_trace_categories(env),
    );

    let export_tables = export_tables();
    let resolver = ApiSetResolver::new();
    let resolved_imports = pe::resolve_imports(&image, &export_tables, &resolver)?;
    let image_hash = util::sha256_bytes(&bytes);
    let mapped = pe::map_image(&bytes, &image, &image_hash, dtm)?;
    let mut memory = MemoryImage::default();
    memory.map_bytes(mapped.selected_base, &mapped.memory);
    runtime.seed_process_state(&mut memory, program, mapped.selected_base, image.size_of_image as u64)?;
    runtime.bind_imports(mapped.selected_base, &mut memory, &resolved_imports)?;

    let config = CpuEngineConfig::from_profile(GuestArch::X64, &ge.config.winver, env!("CARGO_PKG_VERSION"), None)?;
    let engine = CpuExecutionEngine::new(config);
    let instruction_budget = pe_runtime_instruction_budget(env, live_mode)?;
    let mut state = CpuState::new(GuestArch::X64);
    let stack_bottom = STACK_BASE;
    memory.map_bytes(stack_bottom, &vec![0_u8; STACK_SIZE]);
    let stack_top = stack_bottom + STACK_SIZE as u64;
    let rsp = stack_top - 8;
    memory.write_u64(rsp, 0);
    state.set(Register::Rsp, rsp);
    state.segment_bases.gs = runtime.teb_base;
    state.rip = mapped.selected_base + image.address_of_entry_point as u64;

    let mut steps = 0_u64;
    let mut exit_code = 0_i32;
    loop {
        steps += 1;
        if steps > instruction_budget {
            let rip = state.rip;
            let window = read_window(&memory, rip, 15)
                .map(|bytes| {
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_else(|_| "<unavailable>".to_string());
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!(
                    "PE runtime exceeded the instruction budget for {test_id} at {rip:#x}: {window}"
                ),
            ));
        }
        if steps & 0xff == 0 {
            runtime.poll_live_input()?;
        }
        if runtime.host_thunks.contains_key(&state.rip) {
            if let Some(code) = runtime.dispatch_import(state.rip, &mut state, &mut memory)? {
                exit_code = code;
                break;
            }
            continue;
        }
        let opcode = memory
            .read_u8(state.rip)
            .map_err(|error| annotate_guest_fault(error, &memory, &state))?;
        match opcode {
            0xFF => match memory.read_u8(state.rip + 1)? {
                0x15 | 0x25 => {
                    let displacement = read_i32_from_memory(&memory, state.rip + 2)?;
                    let next_rip = state.rip + 6;
                    let slot_address = (next_rip as i128 + displacement as i128) as u64;
                    let target = memory.read_u64(slot_address)?;

                    if runtime.host_thunks.contains_key(&target) {
                        if memory.read_u8(state.rip + 1)? == 0x15 {
                            let call_rsp = state.get(Register::Rsp).wrapping_sub(8);
                            memory.write_u64(call_rsp, next_rip);
                            state.set(Register::Rsp, call_rsp);
                        }
                        if let Some(code) = runtime.dispatch_import(target, &mut state, &mut memory)? {
                            exit_code = code;
                            break;
                        }
                    } else if memory.read_u8(state.rip + 1)? == 0x15 {
                        let call_rsp = state.get(Register::Rsp).wrapping_sub(8);
                        memory.write_u64(call_rsp, next_rip);
                        state.set(Register::Rsp, call_rsp);
                        state.rip = target;
                    } else {
                        state.rip = target;
                    }
                }
                _ => {
                    let cached = decode_current_instruction_cached(
                        &engine,
                        &memory,
                        &mut runtime.instruction_cache,
                        state.rip,
                    )
                        .map_err(|error| annotate_guest_fault(error, &memory, &state))?;
                    let instruction = cached.decoded.clone();
                    let _ = engine.execute_ir_without_memory_hash(&mut state, &mut memory, &cached.ir)
                        .map_err(|error| annotate_guest_fault(error, &memory, &state))?;
                    if instruction.opcode == DecodedOpcode::Ret {
                            let next_rip = memory.read_u64(state.get(Register::Rsp))?;
                            state.set(Register::Rsp, state.get(Register::Rsp).wrapping_add(8));
                            if next_rip == 0 {
                                break;
                            }
                            state.rip = next_rip;
                    } else if !instruction_controls_rip(instruction.opcode) {
                        state.rip = state.rip.wrapping_add(instruction.size as u64);
                    }
                }
            },
            _ => {
                let cached = decode_current_instruction_cached(
                    &engine,
                    &memory,
                    &mut runtime.instruction_cache,
                    state.rip,
                )
                    .map_err(|error| annotate_guest_fault(error, &memory, &state))?;
                let instruction = cached.decoded.clone();
                let _ = engine.execute_ir_without_memory_hash(&mut state, &mut memory, &cached.ir)
                    .map_err(|error| annotate_guest_fault(error, &memory, &state))?;
                if instruction.opcode == DecodedOpcode::Ret {
                        let next_rip = memory.read_u64(state.get(Register::Rsp))?;
                        state.set(Register::Rsp, state.get(Register::Rsp).wrapping_add(8));
                        if next_rip == 0 {
                            break;
                        }
                        state.rip = next_rip;
                } else if !instruction_controls_rip(instruction.opcode) {
                    state.rip = state.rip.wrapping_add(instruction.size as u64);
                }
            }
        }
    }

    let perf = vec![PerfMetric {
        metric_id: "pe_runtime_steps".to_string(),
        value: steps as f64,
        unit: "instructions".to_string(),
    }];
    runtime.export_final_frame_if_requested(env)?;

    let mut trace_events = vec![trace_event(
        1,
        "process",
        "NtContinue",
        BTreeMap::from([
            ("mode".to_string(), Value::String("pe-runtime".to_string())),
            (
                "entrypoint".to_string(),
                json!(format!("{:#x}", mapped.selected_base + image.address_of_entry_point as u64)),
            ),
        ]),
        json!(exit_code),
        vec![image_hash],
    )];
    trace_events.extend(runtime.trace_events);

    Ok(PeExecutionResult {
        synthetic_pid: synthetic_pid(dtm),
        stdout: runtime.stdout,
        stderr: runtime.stderr,
        exit_code,
        guest_exceptions: Vec::new(),
        gfx_frames: runtime.gfx_frames,
        perf,
        trace_events,
    })
}

impl PeHostRuntime {
    fn new(
        ge: GameEnvironment,
        dtm: bool,
        pending_keyboard_replay: Vec<KeyboardReplayEvent>,
        live_session: Option<LivePeSession>,
        allowed_trace_categories: Option<BTreeSet<String>>,
    ) -> Self {
        let mut user32 = User32Subsystem::new(KeyboardLayoutId::Us);
        let keyboard_replay_device = if pending_keyboard_replay.is_empty() {
            None
        } else {
            Some(user32.register_keyboard_device(&KeyboardDevice {
                vendor_id: 0xca51,
                product_id: 0x0001,
                serial: "pe-runtime-replay".to_string(),
            }))
        };
        let live_keyboard_device = if live_session.is_some() {
            Some(user32.register_keyboard_device(&KeyboardDevice {
                vendor_id: 0xca51,
                product_id: 0x0002,
                serial: "pe-runtime-live".to_string(),
            }))
        } else {
            None
        };
        Self {
            audio: AudioSubsystem::new(),
            win32: Win32Subsystem::new_with_live_pacing(ge, dtm, live_session.is_some()),
            user32,
            live_session,
            live_keyboard_device,
            pending_keyboard_replay,
            keyboard_replay_device,
            keyboard_replay_injected: false,
            host_thunks: BTreeMap::new(),
            guest_objects: BTreeMap::new(),
            xaudio_engines: BTreeMap::new(),
            xaudio_mastering_voices: BTreeMap::new(),
            xaudio_source_voices: BTreeMap::new(),
            d3d11_devices: BTreeMap::new(),
            d3d11_contexts: BTreeMap::new(),
            d3d11_swapchains: BTreeMap::new(),
            d3d11_buffers: BTreeMap::new(),
            d3d11_textures: BTreeMap::new(),
            d3d11_views: BTreeMap::new(),
            d3d11_input_layouts: BTreeMap::new(),
            d3d11_shaders: BTreeMap::new(),
            instruction_cache: BTreeMap::new(),
            allowed_trace_categories,
            trace_events: Vec::new(),
            gfx_frames: Vec::new(),
            next_trace_index: 2,
            next_thunk_address: THUNK_BASE,
            next_data_address: CRT_DATA_BASE,
            next_heap_address: CRT_HEAP_BASE,
            heap_allocations: BTreeMap::new(),
            critical_sections: BTreeMap::new(),
            signal_handlers: BTreeMap::new(),
            tls_slots: BTreeMap::new(),
            atexit_handlers: Vec::new(),
            last_error: 0,
            invalid_parameter_handler: 0,
            unhandled_exception_filter: 0,
            mapped_image_base: 0,
            mapped_image_size: 0,
            teb_base: 0,
            peb_base: 0,
            globals: CrtGlobals::default(),
            stdout: String::new(),
            stderr: String::new(),
            next_frame_index: 0,
            next_audio_buffer_tag: 1,
            dtm,
        }
    }

    fn poll_live_input(&mut self) -> AppResult<()> {
        let Some(input_rx) = self
            .live_session
            .as_ref()
            .map(|session| session.input_rx.clone())
        else {
            return Ok(());
        };
        while let Ok(event) = input_rx.try_recv() {
            match event {
                LiveInputEvent::KeyDown {
                    scancode,
                    shift,
                    altgr,
                } => {
                    let Some(hwnd) = self.user32.get_focus().or(self.user32.get_foreground_window()) else {
                        continue;
                    };
                    let Some(device_id) = self.live_keyboard_device.as_deref() else {
                        continue;
                    };
                    self.user32.inject_keyboard_input(
                        hwnd,
                        device_id,
                        scancode,
                        KeyModifiers { shift, altgr },
                    )?;
                    self.push_trace(
                        "input",
                        "LiveKeyboardInput",
                        BTreeMap::from([
                            ("scancode".to_string(), json!(scancode)),
                            ("shift".to_string(), json!(shift)),
                            ("altgr".to_string(), json!(altgr)),
                        ]),
                        json!(hwnd),
                    );
                }
                LiveInputEvent::CloseRequested => {
                    self.user32.post_quit_message(0)?;
                    self.push_trace("input", "LiveCloseRequested", BTreeMap::new(), json!(0));
                }
            }
        }
        Ok(())
    }

    fn publish_live_frame(&self, frame: LiveFrame) {
        if let Some(session) = &self.live_session {
            let _ = session.frame_tx.try_send(frame);
        }
    }

    fn export_final_frame_if_requested(&self, env: &BTreeMap<String, String>) -> AppResult<()> {
        let Some(path) = env.get(EXPORT_FINAL_FRAME_ENV).map(String::as_str) else {
            return Ok(());
        };
        if path.trim().is_empty() {
            return Ok(());
        }
        let export_path = Path::new(path);
        if let Some(parent) = export_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::from_io(
                    ReasonCode::RcIo,
                    format!("failed to create {}", parent.display()),
                    &error,
                )
            })?;
        }
        let Some(device) = self
            .d3d11_devices
            .values()
            .find(|device| device.swapchain_object.is_some())
        else {
            return Ok(());
        };
        device.device.export_presented_frame_ppm(export_path)
    }

    fn publish_live_audio(&self, chunk: LiveAudioChunk) {
        if let Some(session) = &self.live_session {
            let _ = session.audio_tx.try_send(chunk);
        }
    }

    fn inject_keyboard_replay_if_needed(&mut self, hwnd: u32) -> AppResult<()> {
        if self.keyboard_replay_injected || self.pending_keyboard_replay.is_empty() {
            return Ok(());
        }
        let Some(device_id) = self.keyboard_replay_device.clone() else {
            return Ok(());
        };
        for event in &self.pending_keyboard_replay {
            self.user32.inject_keyboard_input(
                hwnd,
                &device_id,
                event.scancode,
                KeyModifiers {
                    shift: event.shift,
                    altgr: event.altgr,
                },
            )?;
        }
        self.keyboard_replay_injected = true;
        self.push_trace(
            "input",
            "KeyboardReplay",
            BTreeMap::from([("events".to_string(), json!(self.pending_keyboard_replay.len()))]),
            json!(hwnd),
        );
        Ok(())
    }

    fn seed_process_state(
        &mut self,
        memory: &mut MemoryImage,
        program: &Path,
        mapped_image_base: u64,
        mapped_image_size: u64,
    ) -> AppResult<()> {
        self.mapped_image_base = mapped_image_base;
        self.mapped_image_size = mapped_image_size;

        let program_string = self.alloc_c_string(memory, &program.display().to_string())?;
        let argv_array = self.alloc_pointer_array(memory, &[program_string, 0])?;
        let argv_ptr_ptr = self.alloc_pointer(memory, argv_array)?;
        let argc_ptr = self.alloc_u32(memory, 1)?;
        let environ_array = self.alloc_pointer_array(memory, &[0])?;
        let environ_ptr_ptr = self.alloc_pointer(memory, environ_array)?;
        let commode_ptr = self.alloc_u32(memory, 0)?;
        let fmode_ptr = self.alloc_u32(memory, 0)?;
        let startup_owner = self.alloc_zeroed(memory, 0x20, 16)?;
        let peb_base = self.alloc_zeroed(memory, 0x100, 16)?;
        let teb_base = self.alloc_zeroed(memory, 0x100, 16)?;
        write_u64(memory, teb_base + 0x30, peb_base);
        write_u64(memory, peb_base + 0x08, startup_owner);

        let mut iob_streams = [0_u64; 3];
        for stream in &mut iob_streams {
            *stream = self.alloc_zeroed(memory, 0x80, 16)?;
        }

        self.teb_base = teb_base;
        self.peb_base = peb_base;

        self.globals = CrtGlobals {
            argc_ptr,
            argv_ptr_ptr,
            environ_ptr_ptr,
            commode_ptr,
            fmode_ptr,
            iob_streams,
        };
        Ok(())
    }

    fn bind_imports(
        &mut self,
        selected_base: u64,
        memory: &mut MemoryImage,
        resolved_imports: &[ResolvedImport],
    ) -> AppResult<()> {
        for import in resolved_imports {
            let slot_va = selected_base + import.iat_rva as u64;
            let thunk_address = self.next_thunk_address;
            self.next_thunk_address += 0x10;
            self.host_thunks
                .insert(thunk_address, HostThunk::from_import(import));
            memory.write_u64(slot_va, thunk_address);
        }
        Ok(())
    }

    fn dispatch_import(
        &mut self,
        thunk_address: u64,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<Option<i32>> {
        let thunk = self.host_thunks.get(&thunk_address).cloned().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown PE host thunk at {thunk_address:#x}"),
            )
        })?;
        let return_address = memory.read_u64(state.get(Register::Rsp))?;
        state.set(Register::Rsp, state.get(Register::Rsp).wrapping_add(8));

        match thunk {
            HostThunk::D3D11CreateDevice => {
                let stack = state.get(Register::Rsp);
                if state.get(Register::Rcx) != 0 || state.get(Register::R8) != 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let request = DeviceCreationRequest {
                        requested_feature_levels: read_d3d_feature_levels(
                            memory,
                            memory.read_u64(stack + 0x20)?,
                            memory.read_u64(stack + 0x28)? as u32,
                        )?,
                    };
                    let pp_device = memory.read_u64(stack + 0x38)?;
                    let p_feature_level = memory.read_u64(stack + 0x40)?;
                    let pp_context = memory.read_u64(stack + 0x48)?;
                    let device = d3d11_create_device(request)?;
                    let feature_level = device.feature_level();
                    let device_object = self.alloc_d3d11_device_object(memory, device)?;
                    let context_object = self.d3d11_device(device_object)?.context_object;
                    if pp_device != 0 {
                        write_u64(memory, pp_device, device_object);
                    }
                    if p_feature_level != 0 {
                        write_u32(memory, p_feature_level, d3d_feature_level_value(feature_level));
                    }
                    if pp_context != 0 {
                        let _ = self.add_ref_guest_object(context_object)?;
                        write_u64(memory, pp_context, context_object);
                    }
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "d3d12",
                        "D3D11CreateDevice",
                        BTreeMap::from([("feature_level".to_string(), json!(format!("{:?}", feature_level)))]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::D3D11CreateDeviceAndSwapChain => {
                let stack = state.get(Register::Rsp);
                if state.get(Register::Rcx) != 0 || state.get(Register::R8) != 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let request = DeviceCreationRequest {
                        requested_feature_levels: read_d3d_feature_levels(
                            memory,
                            memory.read_u64(stack + 0x20)?,
                            memory.read_u64(stack + 0x28)? as u32,
                        )?,
                    };
                    let swapchain_desc = read_swapchain_desc(memory, memory.read_u64(stack + 0x38)?)?;
                    let pp_swapchain = memory.read_u64(stack + 0x40)?;
                    let pp_device = memory.read_u64(stack + 0x48)?;
                    let p_feature_level = memory.read_u64(stack + 0x50)?;
                    let pp_context = memory.read_u64(stack + 0x58)?;
                    if pp_swapchain == 0 || pp_device == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                    } else {
                        let device = d3d11_create_device_and_swapchain(request, swapchain_desc.clone())?;
                        let feature_level = device.feature_level();
                        let device_object = self.alloc_d3d11_device_object(memory, device)?;
                        let (swapchain_object, context_object) = {
                            let device_host = self.d3d11_device(device_object)?;
                            (device_host.swapchain_object.unwrap_or(0), device_host.context_object)
                        };
                        let _ = self.add_ref_guest_object(swapchain_object)?;
                        write_u64(memory, pp_swapchain, swapchain_object);
                        write_u64(memory, pp_device, device_object);
                        if p_feature_level != 0 {
                            write_u32(memory, p_feature_level, d3d_feature_level_value(feature_level));
                        }
                        if pp_context != 0 {
                            let _ = self.add_ref_guest_object(context_object)?;
                            write_u64(memory, pp_context, context_object);
                        }
                        state.set(Register::Rax, 0);
                        self.push_trace(
                            "dxgi",
                            "D3D11CreateDeviceAndSwapChain",
                            BTreeMap::from([
                                ("width".to_string(), json!(swapchain_desc.width)),
                                ("height".to_string(), json!(swapchain_desc.height)),
                                ("buffer_count".to_string(), json!(swapchain_desc.buffer_count)),
                                ("format".to_string(), json!(format!("{:?}", swapchain_desc.format))),
                            ]),
                            json!(0),
                        );
                    }
                }
                self.last_error = 0;
            }
            HostThunk::D3D11DeviceCreateBuffer => {
                self.dispatch_d3d11_create_buffer(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateShaderResourceView => {
                self.dispatch_d3d11_create_shader_resource_view(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateInputLayout => {
                self.dispatch_d3d11_create_input_layout(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateVertexShader => {
                self.dispatch_d3d11_create_shader(memory, state, D3d11ShaderStage::Vs, "ID3D11Device::CreateVertexShader")?;
            }
            HostThunk::D3D11DeviceCreatePixelShader => {
                self.dispatch_d3d11_create_shader(memory, state, D3d11ShaderStage::Ps, "ID3D11Device::CreatePixelShader")?;
            }
            HostThunk::D3D11DeviceCreateComputeShader => {
                self.dispatch_d3d11_create_shader(memory, state, D3d11ShaderStage::Cs, "ID3D11Device::CreateComputeShader")?;
            }
            HostThunk::D3D11DeviceGetImmediateContext => {
                let device_object = state.get(Register::Rcx);
                if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("GetImmediateContext on non-device object {device_object:#x}"),
                    ));
                }
                let out_ptr = state.get(Register::Rdx);
                if out_ptr != 0 {
                    let context_object = self.d3d11_device(device_object)?.context_object;
                    let _ = self.add_ref_guest_object(context_object)?;
                    write_u64(memory, out_ptr, context_object);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("d3d12", "ID3D11Device::GetImmediateContext", BTreeMap::new(), json!(0));
            }
            HostThunk::D3D11DeviceContextVSSetConstantBuffers => {
                self.dispatch_d3d11_vs_set_constant_buffers(memory, state)?;
            }
            HostThunk::D3D11DeviceContextPSSetShaderResources => {
                self.dispatch_d3d11_ps_set_shader_resources(memory, state)?;
            }
            HostThunk::D3D11DeviceContextVSSetShader => {
                self.dispatch_d3d11_set_shader(state, D3d11ShaderStage::Vs, "ID3D11DeviceContext::VSSetShader")?;
            }
            HostThunk::D3D11DeviceContextPSSetShader => {
                self.dispatch_d3d11_set_shader(state, D3d11ShaderStage::Ps, "ID3D11DeviceContext::PSSetShader")?;
            }
            HostThunk::D3D11DeviceContextCSSetShader => {
                self.dispatch_d3d11_set_shader(state, D3d11ShaderStage::Cs, "ID3D11DeviceContext::CSSetShader")?;
            }
            HostThunk::D3D11DeviceContextIASetInputLayout => {
                self.dispatch_d3d11_ia_set_input_layout(state)?;
            }
            HostThunk::D3D11DeviceContextUpdateSubresource => {
                let context = self.d3d11_context(state.get(Register::Rcx))?;
                let texture = self.d3d11_texture(state.get(Register::Rdx))?;
                let stack = state.get(Register::Rsp);
                if texture.device_object != context.device_object
                    || state.get(Register::R8) != 0
                    || state.get(Register::R9) != 0
                {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "UpdateSubresource requires subresource 0, null box, and a resource owned by the same device",
                    ));
                }
                let src_data = memory.read_u64(stack + 0x20)?;
                let src_row_pitch = memory.read_u64(stack + 0x28)? as usize;
                let src_depth_pitch = memory.read_u64(stack + 0x30)? as usize;
                let desc = self
                    .d3d11_device(context.device_object)?
                    .device
                    .resource_desc(texture.resource_id)?;
                let bytes = linearize_texture_update(memory, src_data, src_row_pitch, src_depth_pitch, &desc)?;
                self.d3d11_device_mut(context.device_object)?
                    .device
                    .update_subresource(texture.resource_id, &bytes)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "d3d12",
                    "ID3D11DeviceContext::UpdateSubresource",
                    BTreeMap::from([
                        ("bytes".to_string(), json!(bytes.len())),
                        ("row_pitch".to_string(), json!(src_row_pitch)),
                    ]),
                    json!(0),
                );
            }
            HostThunk::DXGISwapChainGetBuffer => {
                let swapchain_object = state.get(Register::Rcx);
                let index = state.get(Register::Rdx) as u32;
                let out_ptr = state.get(Register::R9);
                if out_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let texture_object = self.ensure_d3d11_backbuffer_object(memory, swapchain_object, index)?;
                    let _ = self.add_ref_guest_object(texture_object)?;
                    write_u64(memory, out_ptr, texture_object);
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "dxgi",
                        "IDXGISwapChain::GetBuffer",
                        BTreeMap::from([("index".to_string(), json!(index))]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::DXGISwapChainPresent => {
                let swapchain_object = state.get(Register::Rcx);
                let sync_interval = state.get(Register::Rdx) as u32;
                let flags = state.get(Register::R8) as u32;
                let allow_tearing = flags & 0x0200 != 0;
                let device_object = self.d3d11_swapchain(swapchain_object)?.device_object;
                let live_mode = self.live_session.is_some();
                let (frame_record, displayed_frame_index, queued_frames, live_frame) = {
                    let device_host = self.d3d11_device_mut(device_object)?;
                    let (submission, present) = device_host
                        .device
                        .present_swapchain(sync_interval, allow_tearing, !live_mode)?;
                    let presented_frame = if live_mode {
                        Some(device_host.device.presented_frame()?)
                    } else {
                        None
                    };
                    let frame_record = if live_mode {
                        None
                    } else {
                        let backbuffer = device_host.device.swapchain_backbuffer(0)?;
                        let hash = device_host.device.resource_digest(backbuffer)?;
                        let state = device_host
                            .device
                            .swapchain_state()
                            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, "swapchain state disappeared before present completed"))?;
                        let submission = submission.ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcD3dInvalidState,
                                "non-live present is missing submission metadata",
                            )
                        })?;
                        Some((
                            hash,
                            BTreeMap::from([
                                ("submission_hash".to_string(), submission.hash),
                                ("width".to_string(), state.desc.width.to_string()),
                                ("height".to_string(), state.desc.height.to_string()),
                                ("format".to_string(), format!("{:?}", state.desc.format)),
                                ("displayed_frame_index".to_string(), present.displayed_frame_index.to_string()),
                            ]),
                        ))
                    };
                    let live_frame = presented_frame.map(|frame| LiveFrame {
                        width: frame.width,
                        height: frame.height,
                        format: frame.format,
                        bytes: frame.bytes,
                        displayed_frame_index: present.displayed_frame_index,
                    });
                    (frame_record, present.displayed_frame_index, present.queued_frames, live_frame)
                };
                if let Some(frame) = live_frame {
                    self.publish_live_frame(frame);
                }
                if let Some((frame_hash, metadata)) = frame_record {
                    self.gfx_frames.push(GfxFrame {
                        scene_id: "pe-runtime-d3d11".to_string(),
                        frame_index: self.next_frame_index,
                        hash: frame_hash,
                        ssim: 1.0,
                        metadata,
                    });
                    self.next_frame_index = self.next_frame_index.saturating_add(1);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "dxgi",
                    "IDXGISwapChain::Present",
                    BTreeMap::from([
                        ("sync_interval".to_string(), json!(sync_interval)),
                        ("allow_tearing".to_string(), json!(allow_tearing)),
                        ("queued_frames".to_string(), json!(queued_frames)),
                    ]),
                    json!(displayed_frame_index),
                );
            }
            HostThunk::XAudio2Create => {
                let out_ptr = state.get(Register::Rcx);
                if out_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let engine_object = self.alloc_xaudio2_engine_object(memory)?;
                    write_u64(memory, out_ptr, engine_object);
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "audio",
                        "XAudio2Create",
                        BTreeMap::from([
                            ("flags".to_string(), json!(state.get(Register::Rdx) as u32)),
                            ("processor".to_string(), json!(state.get(Register::R8))),
                        ]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::GuestObjectAddRef => {
                state.set(Register::Rax, self.add_ref_guest_object(state.get(Register::Rcx))? as u64);
                self.last_error = 0;
            }
            HostThunk::GuestObjectRelease => {
                state.set(Register::Rax, self.release_guest_object(state.get(Register::Rcx))? as u64);
                self.last_error = 0;
            }
            HostThunk::XAudio2CreateMasteringVoice => {
                let engine_object = state.get(Register::Rcx);
                if self.guest_object_kind(engine_object)? != GuestObjectKind::XAudio2Engine {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("XAudio2 mastering voice call on non-engine object {engine_object:#x}"),
                    ));
                }
                let out_ptr = state.get(Register::Rdx);
                let stack = state.get(Register::Rsp);
                if out_ptr == 0
                    || self.xaudio_engine(engine_object)?.mastering_voice.is_some()
                    || memory.read_u64(stack + 0x28)? != 0
                    || memory.read_u64(stack + 0x30)? != 0
                {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let default_device = self
                        .audio
                        .devices()
                        .into_iter()
                        .find(|device| device.id == self.audio.default_device())
                        .ok_or_else(|| AppError::new(ReasonCode::RcAudioUnsupported, "no default audio device is available"))?;
                    let channels = match state.get(Register::R8) as u16 {
                        0 => default_device.channels,
                        value => value,
                    };
                    let sample_rate = match state.get(Register::R9) as u32 {
                        0 => default_device.sample_rate,
                        value => value,
                    };
                    let voice_id = self.audio.create_mastering_voice(WaveFormat {
                        channels,
                        sample_rate,
                        sample_format: SampleFormat::Float32,
                    })?;
                    self.audio.start_voice(voice_id)?;
                    let voice_object = self.alloc_xaudio2_mastering_voice_object(memory, engine_object, voice_id)?;
                    self.xaudio_engine_mut(engine_object)?.mastering_voice = Some(voice_object);
                    write_u64(memory, out_ptr, voice_object);
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "audio",
                        "IXAudio2::CreateMasteringVoice",
                        BTreeMap::from([
                            ("channels".to_string(), json!(channels)),
                            ("sample_rate".to_string(), json!(sample_rate)),
                            ("flags".to_string(), json!(read_guest_u32(memory, stack + 0x20)?)),
                        ]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::XAudio2CreateSourceVoice => {
                let engine_object = state.get(Register::Rcx);
                if self.guest_object_kind(engine_object)? != GuestObjectKind::XAudio2Engine {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!("XAudio2 source voice call on non-engine object {engine_object:#x}"),
                    ));
                }
                let out_ptr = state.get(Register::Rdx);
                let stack = state.get(Register::Rsp);
                let max_frequency_ratio_bits = read_guest_u32(memory, stack + 0x20)?;
                let callback = memory.read_u64(stack + 0x28)?;
                let sends = memory.read_u64(stack + 0x30)?;
                let effect_chain = memory.read_u64(stack + 0x38)?;
                let Some(mastering_object) = self.xaudio_engine(engine_object)?.mastering_voice else {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = 0;
                    state.rip = return_address;
                    return Ok(None);
                };
                if out_ptr == 0 || callback != 0 || sends != 0 || effect_chain != 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let mastering_voice = self.xaudio_mastering_voice(mastering_object)?;
                    let format = read_wave_format(memory, state.get(Register::R8))?;
                    let voice_id = self.audio.create_source_voice(format.clone(), mastering_voice.voice_id)?;
                    let voice_object = self.alloc_xaudio2_source_voice_object(memory, engine_object, voice_id)?;
                    self.xaudio_engine_mut(engine_object)?.source_voices.push(voice_object);
                    write_u64(memory, out_ptr, voice_object);
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "audio",
                        "IXAudio2::CreateSourceVoice",
                        BTreeMap::from([
                            ("channels".to_string(), json!(format.channels)),
                            ("sample_rate".to_string(), json!(format.sample_rate)),
                            ("sample_format".to_string(), json!(format!("{:?}", format.sample_format))),
                            ("flags".to_string(), json!(state.get(Register::R9) as u32)),
                            ("max_frequency_ratio_bits".to_string(), json!(max_frequency_ratio_bits)),
                        ]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::XAudio2StartEngine => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("audio", "IXAudio2::StartEngine", BTreeMap::new(), json!(0));
            }
            HostThunk::XAudio2StopEngine => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("audio", "IXAudio2::StopEngine", BTreeMap::new(), json!(0));
            }
            HostThunk::XAudio2SourceVoiceStart => {
                let source_object = state.get(Register::Rcx);
                let source_voice = self.xaudio_source_voice(source_object)?;
                self.audio.start_voice(source_voice.voice_id)?;
                self.drain_xaudio2_engine(source_voice.engine_object)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "audio",
                    "IXAudio2SourceVoice::Start",
                    BTreeMap::from([("flags".to_string(), json!(state.get(Register::Rdx) as u32))]),
                    json!(0),
                );
            }
            HostThunk::XAudio2SourceVoiceStop => {
                let source_voice = self.xaudio_source_voice(state.get(Register::Rcx))?;
                self.audio.stop_voice(source_voice.voice_id)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "audio",
                    "IXAudio2SourceVoice::Stop",
                    BTreeMap::from([("flags".to_string(), json!(state.get(Register::Rdx) as u32))]),
                    json!(0),
                );
            }
            HostThunk::XAudio2SourceVoiceSubmitSourceBuffer => {
                let source_object = state.get(Register::Rcx);
                let buffer_ptr = state.get(Register::Rdx);
                if state.get(Register::R8) != 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let source_voice = self.xaudio_source_voice(source_object)?;
                    let format = self.audio.voice_format(source_voice.voice_id)?;
                    let (samples, audio_bytes) = read_xaudio2_buffer(memory, buffer_ptr, &format)?;
                    let tag = format!("guest-buffer-{}", self.next_audio_buffer_tag);
                    self.next_audio_buffer_tag += 1;
                    self.audio.submit_source_buffer(
                        source_voice.voice_id,
                        SourceBuffer { tag, samples },
                    )?;
                    if self.audio.voice_started(source_voice.voice_id)? {
                        self.drain_xaudio2_engine(source_voice.engine_object)?;
                    }
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "audio",
                        "IXAudio2SourceVoice::SubmitSourceBuffer",
                        BTreeMap::from([("audio_bytes".to_string(), json!(audio_bytes))]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::XAudio2SourceVoiceFlushSourceBuffers => {
                let source_voice = self.xaudio_source_voice(state.get(Register::Rcx))?;
                self.audio.flush_source_buffers(source_voice.voice_id)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "audio",
                    "IXAudio2SourceVoice::FlushSourceBuffers",
                    BTreeMap::new(),
                    json!(0),
                );
            }
            HostThunk::XAudio2VoiceDestroyVoice => {
                self.destroy_xaudio2_voice_object(state.get(Register::Rcx))?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("audio", "IXAudio2Voice::DestroyVoice", BTreeMap::new(), json!(0));
            }
            HostThunk::RegisterClassExW => {
                let class = state.get(Register::Rcx);
                let class_name_ptr = memory.read_u64(class + 64)?;
                let class_name = read_utf16_string(memory, class_name_ptr)?;
                let atom = self.user32.register_class_ex_w(&class_name);
                state.set(Register::Rax, atom as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "RegisterClassExW",
                    BTreeMap::from([("class_name".to_string(), json!(class_name))]),
                    json!(atom),
                );
            }
            HostThunk::CreateWindowExW => {
                let class_name = read_utf16_string(memory, state.get(Register::Rdx))?;
                let title = read_utf16_string(memory, state.get(Register::R8))?;
                let style = state.get(Register::R9) as u32;
                let stack = state.get(Register::Rsp);
                let width = memory.read_u64(stack + 0x30)? as u32;
                let height = memory.read_u64(stack + 0x38)? as u32;
                let hwnd = self.user32.create_window_ex_w(
                    &class_name,
                    &title,
                    width.max(1),
                    height.max(1),
                    style & 0x1000_0000 != 0,
                    false,
                    1,
                )?;
                state.set(Register::Rax, hwnd as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "CreateWindowExW",
                    BTreeMap::from([
                        ("class_name".to_string(), json!(class_name)),
                        ("title".to_string(), json!(title)),
                        ("width".to_string(), json!(width)),
                        ("height".to_string(), json!(height)),
                    ]),
                    json!(hwnd),
                );
                self.inject_keyboard_replay_if_needed(hwnd)?;
                self.poll_live_input()?;
            }
            HostThunk::PeekMessageW => {
                let msg_ptr = state.get(Register::Rcx);
                let remove = memory.read_u64(state.get(Register::Rsp) + 0x20)? as u32 & 0x0001 != 0;
                self.poll_live_input()?;
                if let Some(message) = self.user32.peek_message_w(remove) {
                    write_win64_msg(memory, msg_ptr, &message)?;
                    state.set(Register::Rax, 1);
                    self.push_trace(
                        "input",
                        "PeekMessageW",
                        BTreeMap::from([("remove".to_string(), json!(remove))]),
                        json!(message_id(message.kind)),
                    );
                } else {
                    state.set(Register::Rax, 0);
                }
                self.last_error = 0;
            }
            HostThunk::DispatchMessageW => {
                let message = read_win64_msg(memory, state.get(Register::Rcx))?;
                let result = self.user32.dispatch_message_w(&message)?;
                state.set(Register::Rax, result as i64 as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "DispatchMessageW",
                    BTreeMap::from([("message".to_string(), json!(message_id(message.kind)))]),
                    json!(result),
                );
            }
            HostThunk::DefWindowProcW => {
                let message = Message {
                    hwnd: (state.get(Register::Rcx) != 0).then_some(state.get(Register::Rcx) as u32),
                    kind: message_kind(state.get(Register::Rdx) as u32)?,
                    wparam: state.get(Register::R8) as i64,
                    lparam: state.get(Register::R9) as i64,
                    translated: false,
                    device_id: None,
                };
                let result = self.user32.def_window_proc_w(&message)?;
                state.set(Register::Rax, result as i64 as u64);
                self.last_error = 0;
            }
            HostThunk::CreateFileW => {
                let stack = state.get(Register::Rsp);
                let path = read_utf16_string(memory, state.get(Register::Rcx))?;
                let security_attributes = state.get(Register::R9);
                let creation_raw = read_guest_u32(memory, stack + 0x20)?;
                let flags_and_attributes = read_guest_u32(memory, stack + 0x28)?;
                let template_file = memory.read_u64(stack + 0x30)?;
                let desired_access = file_access_from_win32(state.get(Register::Rdx) as u32);
                let share_mode = share_mode_from_win32(state.get(Register::R8) as u32);

                if security_attributes != 0 || template_file != 0 {
                    state.set(Register::Rax, INVALID_HANDLE_VALUE);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    match creation_disposition_from_win32(creation_raw).and_then(|creation| {
                        self.win32.create_file_w(
                            &path,
                            desired_access,
                            share_mode,
                            creation,
                            false,
                            flags_and_attributes & 0x4000_0000 != 0,
                        )
                    }) {
                        Ok(handle) => {
                            state.set(Register::Rax, handle as u64);
                            self.last_error = 0;
                            self.push_trace(
                                "file",
                                "CreateFileW",
                                BTreeMap::from([
                                    ("path".to_string(), json!(path)),
                                    ("desired_access".to_string(), json!(state.get(Register::Rdx) as u32)),
                                    ("share_mode".to_string(), json!(state.get(Register::R8) as u32)),
                                    ("creation_disposition".to_string(), json!(creation_raw)),
                                ]),
                                json!(handle),
                            );
                        }
                        Err(error) => {
                            state.set(Register::Rax, INVALID_HANDLE_VALUE);
                            self.last_error = last_error_from_app_error(&error);
                        }
                    }
                }
            }
            HostThunk::ReadFile => {
                let stack = state.get(Register::Rsp);
                let handle = state.get(Register::Rcx) as u32;
                let buffer_ptr = state.get(Register::Rdx);
                let length = state.get(Register::R8) as usize;
                let bytes_read_ptr = state.get(Register::R9);
                let overlapped = memory.read_u64(stack + 0x20)?;

                if overlapped != 0 || (buffer_ptr == 0 && length != 0) {
                    if bytes_read_ptr != 0 {
                        write_u32(memory, bytes_read_ptr, 0);
                    }
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    match self.win32.read_file(handle, length) {
                        Ok(bytes) => {
                            if !bytes.is_empty() {
                                memory.map_bytes(buffer_ptr, &bytes);
                            }
                            if bytes_read_ptr != 0 {
                                write_u32(memory, bytes_read_ptr, bytes.len() as u32);
                            }
                            state.set(Register::Rax, 1);
                            self.last_error = 0;
                            self.push_trace(
                                "file",
                                "ReadFile",
                                BTreeMap::from([
                                    ("handle".to_string(), json!(handle)),
                                    ("requested_bytes".to_string(), json!(length as u32)),
                                ]),
                                json!(bytes.len() as u32),
                            );
                        }
                        Err(error) => {
                            if bytes_read_ptr != 0 {
                                write_u32(memory, bytes_read_ptr, 0);
                            }
                            state.set(Register::Rax, 0);
                            self.last_error = last_error_from_app_error(&error);
                        }
                    }
                }
            }
            HostThunk::WriteFile => {
                let stack = state.get(Register::Rsp);
                let handle = state.get(Register::Rcx) as u32;
                let buffer_ptr = state.get(Register::Rdx);
                let length = state.get(Register::R8) as usize;
                let bytes_written_ptr = state.get(Register::R9);
                let overlapped = memory.read_u64(stack + 0x20)?;

                if overlapped != 0 || (buffer_ptr == 0 && length != 0) {
                    if bytes_written_ptr != 0 {
                        write_u32(memory, bytes_written_ptr, 0);
                    }
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    match read_window(memory, buffer_ptr, length).and_then(|bytes| self.win32.write_file(handle, &bytes)) {
                        Ok(written) => {
                            if bytes_written_ptr != 0 {
                                write_u32(memory, bytes_written_ptr, written);
                            }
                            state.set(Register::Rax, 1);
                            self.last_error = 0;
                            self.push_trace(
                                "file",
                                "WriteFile",
                                BTreeMap::from([
                                    ("handle".to_string(), json!(handle)),
                                    ("bytes".to_string(), json!(written)),
                                ]),
                                json!(1),
                            );
                        }
                        Err(error) => {
                            if bytes_written_ptr != 0 {
                                write_u32(memory, bytes_written_ptr, 0);
                            }
                            state.set(Register::Rax, 0);
                            self.last_error = last_error_from_app_error(&error);
                        }
                    }
                }
            }
            HostThunk::CloseHandle => {
                let handle = state.get(Register::Rcx) as u32;
                match self.win32.close_handle(handle) {
                    Ok(()) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "CloseHandle",
                            BTreeMap::from([("handle".to_string(), json!(handle))]),
                            json!(1),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::Calloc => {
                let count = state.get(Register::Rcx);
                let size = state.get(Register::Rdx);
                let total = count.saturating_mul(size).max(1);
                state.set(Register::Rax, self.alloc_heap(memory, total as usize, true)?);
                self.last_error = 0;
            }
            HostThunk::Free => {
                let address = state.get(Register::Rcx);
                self.heap_allocations.remove(&address);
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::Malloc => {
                let size = state.get(Register::Rcx).max(1);
                state.set(Register::Rax, self.alloc_heap(memory, size as usize, true)?);
                self.last_error = 0;
            }
            HostThunk::SetNewMode => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::CSpecificHandler => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::PArgc => {
                state.set(Register::Rax, self.globals.argc_ptr);
                self.last_error = 0;
            }
            HostThunk::PArgv => {
                state.set(Register::Rax, self.globals.argv_ptr_ptr);
                self.last_error = 0;
            }
            HostThunk::Cexit => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ConfigureNarrowArgv => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::CrtAtExit => {
                let callback = state.get(Register::Rcx);
                if callback != 0 {
                    self.atexit_handlers.push(callback);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::CrtExit => {
                return Ok(Some(state.get(Register::Rcx) as i32));
            }
            HostThunk::InitializeNarrowEnvironment => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::Initterm => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::InittermE => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::SetAppType => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::SetInvalidParameterHandler => {
                let previous = self.invalid_parameter_handler;
                self.invalid_parameter_handler = state.get(Register::Rcx);
                state.set(Register::Rax, previous);
                self.last_error = 0;
            }
            HostThunk::Abort => {
                return Ok(Some(134));
            }
            HostThunk::Exit => {
                return Ok(Some(state.get(Register::Rcx) as i32));
            }
            HostThunk::Signal => {
                let signal = state.get(Register::Rcx) as i32;
                let handler = state.get(Register::Rdx);
                let previous = self.signal_handlers.insert(signal, handler).unwrap_or(0);
                state.set(Register::Rax, previous);
                self.last_error = 0;
            }
            HostThunk::AcrtIobFunc => {
                let index = (state.get(Register::Rcx) as usize).min(self.globals.iob_streams.len().saturating_sub(1));
                state.set(Register::Rax, self.globals.iob_streams[index]);
                self.last_error = 0;
            }
            HostThunk::PCommode => {
                state.set(Register::Rax, self.globals.commode_ptr);
                self.last_error = 0;
            }
            HostThunk::PFmode => {
                state.set(Register::Rax, self.globals.fmode_ptr);
                self.last_error = 0;
            }
            HostThunk::StdioCommonVfprintf => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::Fwrite => {
                let ptr = state.get(Register::Rcx);
                let size = state.get(Register::Rdx);
                let count = state.get(Register::R8);
                let stream = state.get(Register::R9);
                let total = size.saturating_mul(count) as usize;
                let mut bytes = Vec::with_capacity(total);
                for offset in 0..total {
                    bytes.push(memory.read_u8(ptr + offset as u64)?);
                }
                let text = String::from_utf8_lossy(&bytes);
                if stream == self.globals.iob_streams[2] {
                    self.stderr.push_str(&text);
                } else {
                    self.stdout.push_str(&text);
                }
                state.set(Register::Rax, count);
                self.last_error = 0;
            }
            HostThunk::Strlen => {
                state.set(Register::Rax, read_c_string(memory, state.get(Register::Rcx))?.len() as u64);
                self.last_error = 0;
            }
            HostThunk::Strncmp => {
                let left = read_c_string_limit(memory, state.get(Register::Rcx), state.get(Register::R8) as usize)?;
                let right = read_c_string_limit(memory, state.get(Register::Rdx), state.get(Register::R8) as usize)?;
                let result = match left.cmp(&right) {
                    std::cmp::Ordering::Less => -1_i32,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                state.set(Register::Rax, result as i64 as u64);
                self.last_error = 0;
            }
            HostThunk::PEnviron => {
                state.set(Register::Rax, self.globals.environ_ptr_ptr);
                self.last_error = 0;
            }
            HostThunk::SetUserMathErr => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::DeleteCriticalSection => {
                self.critical_sections.remove(&state.get(Register::Rcx));
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::EnterCriticalSection => {
                let address = state.get(Register::Rcx);
                *self.critical_sections.entry(address).or_insert(0) += 1;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::GetLastError => {
                state.set(Register::Rax, self.last_error as u64);
            }
            HostThunk::InitializeCriticalSection => {
                self.critical_sections.entry(state.get(Register::Rcx)).or_insert(0);
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::LeaveCriticalSection => {
                let address = state.get(Register::Rcx);
                if let Some(depth) = self.critical_sections.get_mut(&address) {
                    *depth = depth.saturating_sub(1);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::SetUnhandledExceptionFilter => {
                let previous = self.unhandled_exception_filter;
                self.unhandled_exception_filter = state.get(Register::Rcx);
                state.set(Register::Rax, previous);
                self.last_error = 0;
            }
            HostThunk::Beep => {
                let frequency = state.get(Register::Rcx) as u32;
                let duration_ms = state.get(Register::Rdx) as u32;
                play_host_beep(frequency, duration_ms, self.dtm)?;
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace(
                    "audio",
                    "Beep",
                    BTreeMap::from([
                        ("frequency_hz".to_string(), json!(frequency)),
                        ("duration_ms".to_string(), json!(duration_ms)),
                    ]),
                    json!(1),
                );
            }
            HostThunk::Sleep => {
                let milliseconds = state.get(Register::Rcx);
                self.win32.sleep(milliseconds);
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "time",
                    "Sleep",
                    BTreeMap::from([("milliseconds".to_string(), json!(milliseconds))]),
                    json!(0),
                );
            }
            HostThunk::TlsGetValue => {
                let slot = state.get(Register::Rcx) as u32;
                let value = self.tls_slots.get(&slot).copied().unwrap_or(0);
                state.set(Register::Rax, value);
                self.last_error = 0;
            }
            HostThunk::VirtualProtect => {
                let old_protect_ptr = state.get(Register::R9);
                if old_protect_ptr != 0 {
                    write_u32(memory, old_protect_ptr, PAGE_EXECUTE_READWRITE);
                }
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::VirtualQuery => {
                let address = state.get(Register::Rcx);
                let buffer = state.get(Register::Rdx);
                let length = state.get(Register::R8);
                if length < MEMORY_BASIC_INFORMATION64_SIZE {
                    state.set(Register::Rax, 0);
                    self.last_error = 24;
                } else {
                    let (allocation_base, region_size, ty) = if address >= self.mapped_image_base
                        && address < self.mapped_image_base + self.mapped_image_size
                    {
                        (
                            self.mapped_image_base,
                            self.mapped_image_size - (address - self.mapped_image_base),
                            MEM_IMAGE,
                        )
                    } else if address >= STACK_BASE && address < STACK_BASE + STACK_SIZE as u64 {
                        (STACK_BASE, STACK_BASE + STACK_SIZE as u64 - address, MEM_PRIVATE)
                    } else {
                        let allocation_base = self.heap_allocations.range(..=address).next_back().map(|(base, _)| *base).unwrap_or(address);
                        let allocation_size = self.heap_allocations.get(&allocation_base).copied().unwrap_or(0x1000) as u64;
                        (allocation_base, allocation_size, MEM_PRIVATE)
                    };
                    write_u64(memory, buffer, address);
                    write_u64(memory, buffer + 8, allocation_base);
                    write_u32(memory, buffer + 16, PAGE_EXECUTE_READWRITE);
                    write_u32(memory, buffer + 20, 0);
                    write_u64(memory, buffer + 24, region_size.max(0x1000));
                    write_u32(memory, buffer + 32, MEM_COMMIT);
                    write_u32(memory, buffer + 36, PAGE_EXECUTE_READWRITE);
                    write_u32(memory, buffer + 40, ty);
                    write_u32(memory, buffer + 44, 0);
                    state.set(Register::Rax, MEMORY_BASIC_INFORMATION64_SIZE);
                    self.last_error = 0;
                }
            }
            HostThunk::ExitProcess => {
                let code = state.get(Register::Rcx) as i32;
                self.push_trace(
                    "process",
                    "ExitProcess",
                    BTreeMap::from([("exit_code".to_string(), json!(code))]),
                    json!(code),
                );
                return Ok(Some(code));
            }
            HostThunk::MessageBoxW => {
                let text = read_utf16_string(memory, state.get(Register::Rdx))?;
                let caption = read_utf16_string(memory, state.get(Register::R8))?;
                show_host_message_box(&caption, &text, self.dtm)?;
                self.push_trace(
                    "input",
                    "MessageBoxW",
                    BTreeMap::from([
                        ("text".to_string(), json!(text)),
                        ("caption".to_string(), json!(caption)),
                    ]),
                    json!(1),
                );
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::UnsupportedMethod { name } => {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported guest method dispatch {name}"),
                ));
            }
            HostThunk::Unsupported { dll, symbol } => {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported PE import {dll}!{symbol}"),
                ));
            }
        }

        state.rip = return_address;
        Ok(None)
    }

    fn push_trace(
        &mut self,
        category: &str,
        call_id: &str,
        parameters: BTreeMap<String, Value>,
        return_value: Value,
    ) {
        if let Some(allowed_trace_categories) = &self.allowed_trace_categories {
            if !allowed_trace_categories.contains(category) {
                return;
            }
        }
        self.trace_events.push(trace_event(
            self.next_trace_index,
            category,
            call_id,
            parameters,
            return_value,
            Vec::new(),
        ));
        self.next_trace_index += 1;
    }

    fn alloc_zeroed(&mut self, memory: &mut MemoryImage, size: usize, align: u64) -> AppResult<u64> {
        let address = align_up_u64(self.next_data_address, align);
        self.next_data_address = address
            .checked_add(size as u64)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "PE runtime data allocation overflow"))?;
        memory.map_bytes(address, &vec![0; size]);
        Ok(address)
    }

    fn alloc_c_string(&mut self, memory: &mut MemoryImage, value: &str) -> AppResult<u64> {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        let address = self.alloc_zeroed(memory, bytes.len(), 1)?;
        memory.map_bytes(address, &bytes);
        Ok(address)
    }

    fn alloc_pointer_array(&mut self, memory: &mut MemoryImage, values: &[u64]) -> AppResult<u64> {
        let address = self.alloc_zeroed(memory, values.len() * 8, 8)?;
        for (index, value) in values.iter().enumerate() {
            write_u64(memory, address + (index as u64 * 8), *value);
        }
        Ok(address)
    }

    fn alloc_pointer(&mut self, memory: &mut MemoryImage, value: u64) -> AppResult<u64> {
        let address = self.alloc_zeroed(memory, 8, 8)?;
        write_u64(memory, address, value);
        Ok(address)
    }

    fn alloc_u32(&mut self, memory: &mut MemoryImage, value: u32) -> AppResult<u64> {
        let address = self.alloc_zeroed(memory, 4, 4)?;
        write_u32(memory, address, value);
        Ok(address)
    }

    fn alloc_heap(&mut self, memory: &mut MemoryImage, size: usize, zeroed: bool) -> AppResult<u64> {
        let address = align_up_u64(self.next_heap_address, 16);
        self.next_heap_address = address
            .checked_add(size.max(1) as u64)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "PE runtime heap allocation overflow"))?;
        let bytes = if zeroed {
            vec![0; size.max(1)]
        } else {
            vec![0; size.max(1)]
        };
        memory.map_bytes(address, &bytes);
        self.heap_allocations.insert(address, size.max(1));
        Ok(address)
    }

    fn alloc_host_thunk(&mut self, thunk: HostThunk) -> u64 {
        let address = self.next_thunk_address;
        self.next_thunk_address += 0x10;
        self.host_thunks.insert(address, thunk);
        address
    }

    fn alloc_guest_vtable(&mut self, memory: &mut MemoryImage, methods: Vec<HostThunk>) -> AppResult<u64> {
        let entries = methods
            .into_iter()
            .map(|method| self.alloc_host_thunk(method))
            .collect::<Vec<_>>();
        self.alloc_pointer_array(memory, &entries)
    }

    fn alloc_guest_object(
        &mut self,
        memory: &mut MemoryImage,
        kind: GuestObjectKind,
        vtable: u64,
    ) -> AppResult<u64> {
        let address = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, address, vtable);
        self.guest_objects.insert(
            address,
            GuestObjectMeta {
                kind,
                refcount: 1,
            },
        );
        Ok(address)
    }

    fn guest_object_kind(&self, address: u64) -> AppResult<GuestObjectKind> {
        self.guest_objects
            .get(&address)
            .map(|object| object.kind)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown guest object {address:#x}")))
    }

    fn add_ref_guest_object(&mut self, address: u64) -> AppResult<u32> {
        let object = self
            .guest_objects
            .get_mut(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown guest object {address:#x}")))?;
        object.refcount = object.refcount.saturating_add(1);
        Ok(object.refcount)
    }

    fn release_guest_object(&mut self, address: u64) -> AppResult<u32> {
        let refcount = {
            let object = self
                .guest_objects
                .get_mut(&address)
                .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown guest object {address:#x}")))?;
            object.refcount = object.refcount.saturating_sub(1);
            object.refcount
        };
        if refcount != 0 {
            return Ok(refcount);
        }
        match self.guest_object_kind(address)? {
            GuestObjectKind::XAudio2Engine => self.destroy_xaudio2_engine_object(address)?,
            GuestObjectKind::XAudio2MasteringVoice | GuestObjectKind::XAudio2SourceVoice => {
                self.destroy_xaudio2_voice_object(address)?
            }
            GuestObjectKind::D3d11Device => self.destroy_d3d11_device_object(address)?,
            GuestObjectKind::D3d11DeviceContext => {
                if let Some(context) = self.d3d11_contexts.remove(&address) {
                    let _ = self.release_guest_object(context.device_object)?;
                }
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::DxgiSwapChain => {
                if let Some(swapchain) = self.d3d11_swapchains.remove(&address) {
                    let _ = self.release_guest_object(swapchain.device_object)?;
                }
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::D3d11Buffer => self.destroy_d3d11_buffer_object(address)?,
            GuestObjectKind::D3d11Texture2D => self.destroy_d3d11_texture_object(address)?,
            GuestObjectKind::D3d11View => self.destroy_d3d11_view_object(address)?,
            GuestObjectKind::D3d11InputLayout => self.destroy_d3d11_input_layout_object(address)?,
            GuestObjectKind::D3d11Shader => self.destroy_d3d11_shader_object(address)?,
        }
        Ok(0)
    }

    fn alloc_xaudio2_engine_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("IXAudio2::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("IXAudio2::RegisterForCallbacks"),
                unsupported_method("IXAudio2::UnregisterForCallbacks"),
                HostThunk::XAudio2CreateSourceVoice,
                unsupported_method("IXAudio2::CreateSubmixVoice"),
                HostThunk::XAudio2CreateMasteringVoice,
                HostThunk::XAudio2StartEngine,
                HostThunk::XAudio2StopEngine,
                unsupported_method("IXAudio2::CommitChanges"),
                unsupported_method("IXAudio2::GetPerformanceData"),
                unsupported_method("IXAudio2::SetDebugConfiguration"),
            ],
        )?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::XAudio2Engine, vtable)?;
        self.xaudio_engines.insert(
            object,
            GuestXAudio2Engine {
                mastering_voice: None,
                source_voices: Vec::new(),
            },
        );
        Ok(object)
    }

    fn alloc_xaudio2_mastering_voice_object(
        &mut self,
        memory: &mut MemoryImage,
        engine_object: u64,
        voice_id: VoiceId,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("IXAudio2Voice::GetVoiceDetails"),
                unsupported_method("IXAudio2Voice::SetOutputVoices"),
                unsupported_method("IXAudio2Voice::SetEffectChain"),
                unsupported_method("IXAudio2Voice::EnableEffect"),
                unsupported_method("IXAudio2Voice::DisableEffect"),
                unsupported_method("IXAudio2Voice::GetEffectState"),
                unsupported_method("IXAudio2Voice::SetEffectParameters"),
                unsupported_method("IXAudio2Voice::GetEffectParameters"),
                unsupported_method("IXAudio2Voice::SetFilterParameters"),
                unsupported_method("IXAudio2Voice::GetFilterParameters"),
                unsupported_method("IXAudio2Voice::SetOutputFilterParameters"),
                unsupported_method("IXAudio2Voice::GetOutputFilterParameters"),
                unsupported_method("IXAudio2Voice::SetVolume"),
                unsupported_method("IXAudio2Voice::GetVolume"),
                unsupported_method("IXAudio2Voice::SetChannelVolumes"),
                unsupported_method("IXAudio2Voice::GetChannelVolumes"),
                unsupported_method("IXAudio2Voice::SetOutputMatrix"),
                unsupported_method("IXAudio2Voice::GetOutputMatrix"),
                HostThunk::XAudio2VoiceDestroyVoice,
            ],
        )?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::XAudio2MasteringVoice, vtable)?;
        self.xaudio_mastering_voices.insert(
            object,
            GuestXAudio2Voice {
                engine_object,
                voice_id,
            },
        );
        Ok(object)
    }

    fn alloc_xaudio2_source_voice_object(
        &mut self,
        memory: &mut MemoryImage,
        engine_object: u64,
        voice_id: VoiceId,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("IXAudio2Voice::GetVoiceDetails"),
                unsupported_method("IXAudio2Voice::SetOutputVoices"),
                unsupported_method("IXAudio2Voice::SetEffectChain"),
                unsupported_method("IXAudio2Voice::EnableEffect"),
                unsupported_method("IXAudio2Voice::DisableEffect"),
                unsupported_method("IXAudio2Voice::GetEffectState"),
                unsupported_method("IXAudio2Voice::SetEffectParameters"),
                unsupported_method("IXAudio2Voice::GetEffectParameters"),
                unsupported_method("IXAudio2Voice::SetFilterParameters"),
                unsupported_method("IXAudio2Voice::GetFilterParameters"),
                unsupported_method("IXAudio2Voice::SetOutputFilterParameters"),
                unsupported_method("IXAudio2Voice::GetOutputFilterParameters"),
                unsupported_method("IXAudio2Voice::SetVolume"),
                unsupported_method("IXAudio2Voice::GetVolume"),
                unsupported_method("IXAudio2Voice::SetChannelVolumes"),
                unsupported_method("IXAudio2Voice::GetChannelVolumes"),
                unsupported_method("IXAudio2Voice::SetOutputMatrix"),
                unsupported_method("IXAudio2Voice::GetOutputMatrix"),
                HostThunk::XAudio2VoiceDestroyVoice,
                HostThunk::XAudio2SourceVoiceStart,
                HostThunk::XAudio2SourceVoiceStop,
                HostThunk::XAudio2SourceVoiceSubmitSourceBuffer,
                HostThunk::XAudio2SourceVoiceFlushSourceBuffers,
                unsupported_method("IXAudio2SourceVoice::Discontinuity"),
                unsupported_method("IXAudio2SourceVoice::ExitLoop"),
                unsupported_method("IXAudio2SourceVoice::GetState"),
                unsupported_method("IXAudio2SourceVoice::SetFrequencyRatio"),
                unsupported_method("IXAudio2SourceVoice::GetFrequencyRatio"),
                unsupported_method("IXAudio2SourceVoice::SetSourceSampleRate"),
            ],
        )?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::XAudio2SourceVoice, vtable)?;
        self.xaudio_source_voices.insert(
            object,
            GuestXAudio2Voice {
                engine_object,
                voice_id,
            },
        );
        Ok(object)
    }

    fn destroy_xaudio2_engine_object(&mut self, address: u64) -> AppResult<()> {
        let engine = self
            .xaudio_engines
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown XAudio2 engine {address:#x}")))?;
        for source in engine.source_voices {
            let _ = self.destroy_xaudio2_voice_object(source);
        }
        if let Some(mastering_voice) = engine.mastering_voice {
            let _ = self.destroy_xaudio2_voice_object(mastering_voice);
        }
        self.guest_objects.remove(&address);
        Ok(())
    }

    fn destroy_xaudio2_voice_object(&mut self, address: u64) -> AppResult<()> {
        if let Some(voice) = self.xaudio_source_voices.remove(&address) {
            self.audio.destroy_voice(voice.voice_id)?;
            if let Some(engine) = self.xaudio_engines.get_mut(&voice.engine_object) {
                engine.source_voices.retain(|candidate| *candidate != address);
            }
            self.guest_objects.remove(&address);
            return Ok(());
        }
        if let Some(voice) = self.xaudio_mastering_voices.remove(&address) {
            let dependent_sources = self
                .xaudio_engines
                .get(&voice.engine_object)
                .map(|engine| engine.source_voices.clone())
                .unwrap_or_default();
            for source in dependent_sources {
                let _ = self.destroy_xaudio2_voice_object(source);
            }
            self.audio.destroy_voice(voice.voice_id)?;
            if let Some(engine) = self.xaudio_engines.get_mut(&voice.engine_object) {
                engine.mastering_voice = None;
                engine.source_voices.clear();
            }
            self.guest_objects.remove(&address);
            return Ok(());
        }
        Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unknown XAudio2 voice object {address:#x}"),
        ))
    }

    fn xaudio_engine(&self, address: u64) -> AppResult<&GuestXAudio2Engine> {
        self.xaudio_engines
            .get(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown XAudio2 engine {address:#x}")))
    }

    fn xaudio_engine_mut(&mut self, address: u64) -> AppResult<&mut GuestXAudio2Engine> {
        self.xaudio_engines
            .get_mut(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown XAudio2 engine {address:#x}")))
    }

    fn xaudio_source_voice(&self, address: u64) -> AppResult<GuestXAudio2Voice> {
        self.xaudio_source_voices
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown XAudio2 source voice {address:#x}")))
    }

    fn xaudio_mastering_voice(&self, address: u64) -> AppResult<GuestXAudio2Voice> {
        self.xaudio_mastering_voices
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown XAudio2 mastering voice {address:#x}")))
    }

    fn drain_xaudio2_engine(&mut self, engine_object: u64) -> AppResult<()> {
        let (mastering_object, source_objects) = {
            let engine = self.xaudio_engine(engine_object)?;
            (engine.mastering_voice, engine.source_voices.clone())
        };
        let Some(mastering_object) = mastering_object else {
            return Ok(());
        };
        let mastering_voice = self.xaudio_mastering_voice(mastering_object)?;
        let mut frames = 0_usize;
        for source_object in &source_objects {
            if let Some(source) = self.xaudio_source_voices.get(source_object) {
                if self.audio.voice_started(source.voice_id)? {
                    frames = frames.max(self.audio.queued_source_frames(source.voice_id)?);
                }
            }
        }
        if frames == 0 {
            return Ok(());
        }
        let format = self.audio.voice_format(mastering_voice.voice_id)?;
        let output = self.audio.render_xaudio2(mastering_voice.voice_id, frames)?;
        if self.live_session.is_some() && output.samples.iter().any(|sample| *sample != 0.0) {
            self.publish_live_audio(LiveAudioChunk {
                format: format.clone(),
                samples: output.samples.clone(),
            });
        } else if !self.dtm && output.samples.iter().any(|sample| *sample != 0.0) {
            self.audio.play_render_output(&output, &format)?;
        }
        self.push_trace(
            "audio",
            "XAudio2Render",
            BTreeMap::from([
                ("frames".to_string(), json!(frames)),
                ("latency_ms".to_string(), json!(output.latency_ms)),
                ("callbacks".to_string(), json!(output.voice_callbacks.len())),
            ]),
            json!(output.crc32),
        );
        Ok(())
    }

    fn alloc_d3d11_device_object(&mut self, memory: &mut MemoryImage, device: D3d11Device) -> AppResult<u64> {
        let mut device_methods = vec![unsupported_method("ID3D11Device::unsupported"); 43];
        device_methods[0] = unsupported_method("ID3D11Device::QueryInterface");
        device_methods[1] = HostThunk::GuestObjectAddRef;
        device_methods[2] = HostThunk::GuestObjectRelease;
        device_methods[3] = HostThunk::D3D11DeviceCreateBuffer;
        device_methods[7] = HostThunk::D3D11DeviceCreateShaderResourceView;
        device_methods[11] = HostThunk::D3D11DeviceCreateInputLayout;
        device_methods[12] = HostThunk::D3D11DeviceCreateVertexShader;
        device_methods[15] = HostThunk::D3D11DeviceCreatePixelShader;
        device_methods[18] = HostThunk::D3D11DeviceCreateComputeShader;
        device_methods[40] = HostThunk::D3D11DeviceGetImmediateContext;

        let mut context_methods = vec![unsupported_method("ID3D11DeviceContext::unsupported"); 70];
        context_methods[0] = unsupported_method("ID3D11DeviceContext::QueryInterface");
        context_methods[1] = HostThunk::GuestObjectAddRef;
        context_methods[2] = HostThunk::GuestObjectRelease;
        context_methods[7] = HostThunk::D3D11DeviceContextVSSetConstantBuffers;
        context_methods[8] = HostThunk::D3D11DeviceContextPSSetShaderResources;
        context_methods[9] = HostThunk::D3D11DeviceContextPSSetShader;
        context_methods[11] = HostThunk::D3D11DeviceContextVSSetShader;
        context_methods[17] = HostThunk::D3D11DeviceContextIASetInputLayout;
        context_methods[48] = HostThunk::D3D11DeviceContextUpdateSubresource;
        context_methods[69] = HostThunk::D3D11DeviceContextCSSetShader;

        let mut swapchain_methods = vec![unsupported_method("IDXGISwapChain::unsupported"); 14];
        swapchain_methods[0] = unsupported_method("IDXGISwapChain::QueryInterface");
        swapchain_methods[1] = HostThunk::GuestObjectAddRef;
        swapchain_methods[2] = HostThunk::GuestObjectRelease;
        swapchain_methods[8] = HostThunk::DXGISwapChainPresent;
        swapchain_methods[9] = HostThunk::DXGISwapChainGetBuffer;

        let device_vtable = self.alloc_guest_vtable(memory, device_methods)?;
        let context_vtable = self.alloc_guest_vtable(memory, context_methods)?;
        let swapchain_vtable = if device.swapchain_state().is_some() {
            Some(self.alloc_guest_vtable(memory, swapchain_methods)?)
        } else {
            None
        };

        let device_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11Device, device_vtable)?;
        let context_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11DeviceContext, context_vtable)?;
        let swapchain_object = if let Some(vtable) = swapchain_vtable {
            Some(self.alloc_guest_object(memory, GuestObjectKind::DxgiSwapChain, vtable)?)
        } else {
            None
        };
        if let Some(context_meta) = self.guest_objects.get_mut(&context_object) {
            context_meta.refcount = 0;
        }
        if let Some(swapchain_object) = swapchain_object {
            if let Some(swapchain_meta) = self.guest_objects.get_mut(&swapchain_object) {
                swapchain_meta.refcount = 0;
            }
        }

        let _ = self.add_ref_guest_object(device_object)?;
        if swapchain_object.is_some() {
            let _ = self.add_ref_guest_object(device_object)?;
        }

        self.d3d11_contexts
            .insert(context_object, GuestD3d11Context { device_object });
        if let Some(swapchain_object) = swapchain_object {
            self.d3d11_swapchains
                .insert(swapchain_object, GuestDxgiSwapChain { device_object });
        }
        self.d3d11_devices.insert(
            device_object,
            GuestD3d11Device {
                device,
                context_object,
                swapchain_object,
                backbuffer_objects: BTreeMap::new(),
            },
        );
        Ok(device_object)
    }

    fn alloc_d3d11_texture_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        resource_id: D3d11ResourceId,
    ) -> AppResult<u64> {
        let texture_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11Texture2D::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ],
        )?;
        let texture_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11Texture2D, texture_vtable)?;
        if let Some(texture_meta) = self.guest_objects.get_mut(&texture_object) {
            texture_meta.refcount = 0;
        }
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_textures.insert(
            texture_object,
            GuestD3d11Texture2D {
                device_object,
                resource_id,
            },
        );
        Ok(texture_object)
    }

    fn alloc_d3d11_buffer_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        resource_id: D3d11ResourceId,
    ) -> AppResult<u64> {
        let buffer_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11Buffer::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("ID3D11DeviceChild::GetDevice"),
                unsupported_method("ID3D11DeviceChild::GetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateDataInterface"),
            ],
        )?;
        let buffer_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11Buffer, buffer_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_buffers.insert(
            buffer_object,
            GuestD3d11Buffer {
                device_object,
                resource_id,
            },
        );
        Ok(buffer_object)
    }

    fn alloc_d3d11_view_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        view_id: D3d11ViewId,
        kind: ViewKind,
    ) -> AppResult<u64> {
        let view_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11View::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("ID3D11DeviceChild::GetDevice"),
                unsupported_method("ID3D11DeviceChild::GetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateDataInterface"),
            ],
        )?;
        let view_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11View, view_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_views.insert(
            view_object,
            GuestD3d11View {
                device_object,
                view_id,
                kind,
            },
        );
        Ok(view_object)
    }

    fn alloc_d3d11_input_layout_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        layout_id: InputLayoutId,
    ) -> AppResult<u64> {
        let layout_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11InputLayout::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("ID3D11DeviceChild::GetDevice"),
                unsupported_method("ID3D11DeviceChild::GetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateDataInterface"),
            ],
        )?;
        let layout_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11InputLayout, layout_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_input_layouts.insert(
            layout_object,
            GuestD3d11InputLayout {
                device_object,
                layout_id,
            },
        );
        Ok(layout_object)
    }

    fn alloc_d3d11_shader_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        shader_id: u64,
        stage: D3d11ShaderStage,
    ) -> AppResult<u64> {
        let shader_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11DeviceChild::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("ID3D11DeviceChild::GetDevice"),
                unsupported_method("ID3D11DeviceChild::GetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateDataInterface"),
            ],
        )?;
        let shader_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11Shader, shader_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_shaders.insert(
            shader_object,
            GuestD3d11Shader {
                device_object,
                shader_id,
                stage,
            },
        );
        Ok(shader_object)
    }

    fn destroy_d3d11_device_object(&mut self, address: u64) -> AppResult<()> {
        let device = self
            .d3d11_devices
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 device {address:#x}")))?;
        for texture_object in device.backbuffer_objects.into_values() {
            let _ = self.destroy_d3d11_texture_object(texture_object);
        }
        self.d3d11_contexts.remove(&device.context_object);
        self.guest_objects.remove(&device.context_object);
        if let Some(swapchain_object) = device.swapchain_object {
            self.d3d11_swapchains.remove(&swapchain_object);
            self.guest_objects.remove(&swapchain_object);
        }
        self.guest_objects.remove(&address);
        Ok(())
    }

    fn destroy_d3d11_texture_object(&mut self, address: u64) -> AppResult<()> {
        let texture = self
            .d3d11_textures
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 texture {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(texture.device_object)?;
        Ok(())
    }

    fn destroy_d3d11_buffer_object(&mut self, address: u64) -> AppResult<()> {
        let buffer = self
            .d3d11_buffers
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 buffer {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(buffer.device_object)?;
        Ok(())
    }

    fn destroy_d3d11_view_object(&mut self, address: u64) -> AppResult<()> {
        let view = self
            .d3d11_views
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 view {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(view.device_object)?;
        Ok(())
    }

    fn destroy_d3d11_input_layout_object(&mut self, address: u64) -> AppResult<()> {
        let input_layout = self
            .d3d11_input_layouts
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 input layout {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(input_layout.device_object)?;
        Ok(())
    }

    fn destroy_d3d11_shader_object(&mut self, address: u64) -> AppResult<()> {
        let shader = self
            .d3d11_shaders
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 shader {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(shader.device_object)?;
        Ok(())
    }

    fn d3d11_device(&self, address: u64) -> AppResult<&GuestD3d11Device> {
        self.d3d11_devices
            .get(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 device {address:#x}")))
    }

    fn d3d11_device_mut(&mut self, address: u64) -> AppResult<&mut GuestD3d11Device> {
        self.d3d11_devices
            .get_mut(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 device {address:#x}")))
    }

    fn d3d11_context(&self, address: u64) -> AppResult<GuestD3d11Context> {
        self.d3d11_contexts
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 context {address:#x}")))
    }

    fn d3d11_swapchain(&self, address: u64) -> AppResult<GuestDxgiSwapChain> {
        self.d3d11_swapchains
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown DXGI swapchain {address:#x}")))
    }

    fn d3d11_texture(&self, address: u64) -> AppResult<GuestD3d11Texture2D> {
        self.d3d11_textures
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 texture {address:#x}")))
    }

    fn d3d11_buffer(&self, address: u64) -> AppResult<GuestD3d11Buffer> {
        self.d3d11_buffers
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 buffer {address:#x}")))
    }

    fn d3d11_view(&self, address: u64) -> AppResult<GuestD3d11View> {
        self.d3d11_views
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 view {address:#x}")))
    }

    fn d3d11_input_layout(&self, address: u64) -> AppResult<GuestD3d11InputLayout> {
        self.d3d11_input_layouts
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 input layout {address:#x}")))
    }

    fn d3d11_shader(&self, address: u64) -> AppResult<GuestD3d11Shader> {
        self.d3d11_shaders
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 shader {address:#x}")))
    }

    fn d3d11_resource_owner_and_id(&self, address: u64) -> AppResult<(u64, D3d11ResourceId)> {
        match self.guest_object_kind(address)? {
            GuestObjectKind::D3d11Buffer => {
                let buffer = self.d3d11_buffer(address)?;
                Ok((buffer.device_object, buffer.resource_id))
            }
            GuestObjectKind::D3d11Texture2D => {
                let texture = self.d3d11_texture(address)?;
                Ok((texture.device_object, texture.resource_id))
            }
            kind => Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported D3D11 resource object kind {:?} for object {address:#x}", kind),
            )),
        }
    }

    fn dispatch_d3d11_create_buffer(&mut self, memory: &mut MemoryImage, state: &mut CpuState) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateBuffer on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let initial_data_ptr = state.get(Register::R8);
        let out_ptr = state.get(Register::R9);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let byte_width = read_d3d11_buffer_byte_width(memory, desc_ptr)?;
        let resource_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_buffer("guest-constant-buffer", byte_width)
        {
            Ok(resource_id) => resource_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        if initial_data_ptr != 0 {
            let src_ptr = read_guest_u64(memory, initial_data_ptr)?;
            if src_ptr != 0 {
                let bytes = read_guest_bytes(memory, src_ptr, byte_width)?;
                self.d3d11_device_mut(device_object)?
                    .device
                    .update_subresource(resource_id, &bytes)?;
            }
        }
        let buffer_object = self.alloc_d3d11_buffer_object(memory, device_object, resource_id)?;
        write_u64(memory, out_ptr, buffer_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateBuffer",
            BTreeMap::from([
                ("byte_width".to_string(), json!(byte_width)),
                ("initialized".to_string(), json!(initial_data_ptr != 0)),
            ]),
            json!(buffer_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_shader_resource_view(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateShaderResourceView on non-device object {device_object:#x}"),
            ));
        }
        let resource_object = state.get(Register::Rdx);
        let desc_ptr = state.get(Register::R8);
        let out_ptr = state.get(Register::R9);
        if resource_object == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let (resource_device_object, resource_id) = self.d3d11_resource_owner_and_id(resource_object)?;
        if resource_device_object != device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let default_format = self.d3d11_device(device_object)?.device.resource_desc(resource_id)?.format;
        let format = if desc_ptr == 0 {
            default_format
        } else {
            read_d3d11_view_format(memory, desc_ptr, default_format)?
        };
        let view_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_shader_resource_view(resource_id, format)
        {
            Ok(view_id) => view_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let view_object = self.alloc_d3d11_view_object(memory, device_object, view_id, ViewKind::Srv)?;
        write_u64(memory, out_ptr, view_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateShaderResourceView",
            BTreeMap::from([("format".to_string(), json!(format!("{:?}", format)))]),
            json!(view_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_input_layout(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateInputLayout on non-device object {device_object:#x}"),
            ));
        }
        let stack = state.get(Register::Rsp);
        let desc_ptr = state.get(Register::Rdx);
        let num_elements = state.get(Register::R8) as u32;
        let bytecode_ptr = state.get(Register::R9);
        let bytecode_len = memory.read_u64(stack + 0x20)? as usize;
        let out_ptr = memory.read_u64(stack + 0x28)?;
        if desc_ptr == 0 || num_elements == 0 || bytecode_ptr == 0 || bytecode_len == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = read_d3d11_input_layout_desc(memory, desc_ptr, num_elements)?;
        let layout_id = self.d3d11_device_mut(device_object)?.device.create_input_layout(desc);
        let layout_object = self.alloc_d3d11_input_layout_object(memory, device_object, layout_id)?;
        write_u64(memory, out_ptr, layout_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateInputLayout",
            BTreeMap::from([
                ("elements".to_string(), json!(num_elements)),
                ("bytecode_len".to_string(), json!(bytecode_len)),
            ]),
            json!(layout_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_vs_set_constant_buffers(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let start_slot = state.get(Register::Rdx) as u32;
        let num_buffers = state.get(Register::R8) as usize;
        let buffers_ptr = state.get(Register::R9);
        if start_slot != 0 || (num_buffers != 0 && buffers_ptr == 0) {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut buffers = Vec::new();
        if num_buffers != 0 {
            let objects = read_guest_pointer_array(memory, buffers_ptr, num_buffers)?;
            if !objects.iter().all(|object| *object == 0) {
                buffers.reserve(objects.len());
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let buffer = self.d3d11_buffer(object)?;
                    if buffer.device_object != context.device_object {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    buffers.push(buffer.resource_id);
                }
            }
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .vs_set_constant_buffers(buffers.clone());
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::VSSetConstantBuffers",
            BTreeMap::from([("count".to_string(), json!(buffers.len()))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d11_ps_set_shader_resources(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let start_slot = state.get(Register::Rdx) as u32;
        let num_views = state.get(Register::R8) as usize;
        let views_ptr = state.get(Register::R9);
        if start_slot != 0 || (num_views != 0 && views_ptr == 0) {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut views = Vec::new();
        if num_views != 0 {
            let objects = read_guest_pointer_array(memory, views_ptr, num_views)?;
            if !objects.iter().all(|object| *object == 0) {
                views.reserve(objects.len());
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let view = self.d3d11_view(object)?;
                    if view.device_object != context.device_object || view.kind != ViewKind::Srv {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    views.push(view.view_id);
                }
            }
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .ps_set_shader_resources(views.clone());
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::PSSetShaderResources",
            BTreeMap::from([("count".to_string(), json!(views.len()))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d11_ia_set_input_layout(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let layout_object = state.get(Register::Rdx);
        if layout_object == 0 {
            self.d3d11_device_mut(context.device_object)?.device.ia_clear_input_layout();
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace("d3d12", "ID3D11DeviceContext::IASetInputLayout", BTreeMap::new(), json!(0));
            return Ok(());
        }
        let input_layout = self.d3d11_input_layout(layout_object)?;
        if input_layout.device_object != context.device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .ia_set_input_layout(input_layout.layout_id);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::IASetInputLayout",
            BTreeMap::new(),
            json!(layout_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_shader(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
        stage: D3d11ShaderStage,
        trace_name: &str,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("{trace_name} on non-device object {device_object:#x}"),
            ));
        }
        let stack = state.get(Register::Rsp);
        let bytecode_ptr = state.get(Register::Rdx);
        let bytecode_len = state.get(Register::R8) as usize;
        let class_linkage = state.get(Register::R9);
        let out_ptr = memory.read_u64(stack + 0x20)?;
        if bytecode_ptr == 0 || bytecode_len == 0 || out_ptr == 0 || class_linkage != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let bytecode = read_guest_bytes(memory, bytecode_ptr, bytecode_len)?;
        let parsed = match parse_dxil_container(&bytecode) {
            Ok(parsed) => parsed,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let Some(root_signature) = parsed.root_signature_part.clone() else {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        };
        let entry_name = parsed.entry_name.clone();
        let shader_id = match self.d3d11_device_mut(device_object)?.device.create_shader_from_dxil(
            crate::d3d11::ShaderModuleDesc {
                stage,
                entry: entry_name.clone(),
            },
            bytecode,
            root_signature,
        ) {
            Ok(shader_id) => shader_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let shader_object = self.alloc_d3d11_shader_object(memory, device_object, shader_id, stage)?;
        write_u64(memory, out_ptr, shader_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        let cache_key = self
            .d3d11_device(device_object)?
            .device
            .shader_translation_cache_key(shader_id)?
            .unwrap_or_default();
        self.push_trace(
            "d3d12",
            trace_name,
            BTreeMap::from([
                ("bytes".to_string(), json!(bytecode_len)),
                ("entry".to_string(), json!(entry_name)),
                ("cache_key".to_string(), json!(cache_key)),
            ]),
            json!(shader_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_set_shader(
        &mut self,
        state: &mut CpuState,
        stage: D3d11ShaderStage,
        trace_name: &str,
    ) -> AppResult<()> {
        let context_object = state.get(Register::Rcx);
        let shader_object = state.get(Register::Rdx);
        let class_instances = state.get(Register::R8);
        let class_instance_count = state.get(Register::R9);
        let context = self.d3d11_context(context_object)?;
        if class_instances != 0 || class_instance_count != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        if shader_object == 0 {
            let device = &mut self.d3d11_device_mut(context.device_object)?.device;
            match stage {
                D3d11ShaderStage::Vs => device.vs_clear_shader(),
                D3d11ShaderStage::Ps => device.ps_clear_shader(),
                D3d11ShaderStage::Cs => device.cs_clear_shader(),
            }
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace("d3d12", trace_name, BTreeMap::new(), json!(0));
            return Ok(());
        }
        let shader = self.d3d11_shader(shader_object)?;
        if shader.device_object != context.device_object || shader.stage != stage {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let cache_key = {
            let device = &mut self.d3d11_device_mut(context.device_object)?.device;
            match stage {
                D3d11ShaderStage::Vs => device.vs_set_shader(shader.shader_id),
                D3d11ShaderStage::Ps => device.ps_set_shader(shader.shader_id),
                D3d11ShaderStage::Cs => device.cs_set_shader(shader.shader_id),
            }
            device.shader_translation_cache_key(shader.shader_id)?.unwrap_or_default()
        };
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            trace_name,
            BTreeMap::from([("cache_key".to_string(), json!(cache_key))]),
            json!(shader_object),
        );
        Ok(())
    }

    fn ensure_d3d11_backbuffer_object(
        &mut self,
        memory: &mut MemoryImage,
        swapchain_object: u64,
        index: u32,
    ) -> AppResult<u64> {
        let device_object = self.d3d11_swapchain(swapchain_object)?.device_object;
        if let Some(existing) = self
            .d3d11_device(device_object)?
            .backbuffer_objects
            .get(&index)
            .copied()
        {
            return Ok(existing);
        }
        let resource_id = self.d3d11_device(device_object)?.device.swapchain_backbuffer(index)?;
        let texture_object = self.alloc_d3d11_texture_object(memory, device_object, resource_id)?;
        self.d3d11_device_mut(device_object)?
            .backbuffer_objects
            .insert(index, texture_object);
        Ok(texture_object)
    }
}

impl HostThunk {
    fn from_import(import: &ResolvedImport) -> Self {
        let dll = import.resolved_module.to_ascii_lowercase();
        match (&dll[..], &import.symbol) {
            ("d3d11.dll", ImportSymbol::ByName { name, .. }) if name == "D3D11CreateDevice" => {
                Self::D3D11CreateDevice
            }
            ("d3d11.dll", ImportSymbol::ByName { name, .. }) if name == "D3D11CreateDeviceAndSwapChain" => {
                Self::D3D11CreateDeviceAndSwapChain
            }
            ("xaudio2_9.dll", ImportSymbol::ByName { name, .. }) if name == "XAudio2Create" => {
                Self::XAudio2Create
            }
            ("xaudio2_9redist.dll", ImportSymbol::ByName { name, .. }) if name == "XAudio2Create" => {
                Self::XAudio2Create
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "RegisterClassExW" => {
                Self::RegisterClassExW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateWindowExW" => {
                Self::CreateWindowExW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "PeekMessageW" => {
                Self::PeekMessageW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DispatchMessageW" => {
                Self::DispatchMessageW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DefWindowProcW" => {
                Self::DefWindowProcW
            }
            ("kernel32.dll", ImportSymbol::ByOrdinal { ordinal: 17 }) => Self::CreateFileW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFileW" => Self::CreateFileW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReadFile" => Self::ReadFile,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WriteFile" => Self::WriteFile,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CloseHandle" => Self::CloseHandle,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteCriticalSection" => {
                Self::DeleteCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "EnterCriticalSection" => {
                Self::EnterCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetLastError" => Self::GetLastError,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeCriticalSection" => {
                Self::InitializeCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LeaveCriticalSection" => {
                Self::LeaveCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetUnhandledExceptionFilter" => {
                Self::SetUnhandledExceptionFilter
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "Beep" => Self::Beep,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "Sleep" || name == "Forwarded" => {
                Self::Sleep
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsGetValue" => Self::TlsGetValue,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualProtect" => Self::VirtualProtect,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualQuery" => Self::VirtualQuery,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "Sleep" => Self::Sleep,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ExitProcess" => Self::ExitProcess,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_set_new_mode" => Self::SetNewMode,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "calloc" => Self::Calloc,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "free" => Self::Free,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "malloc" => Self::Malloc,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__C_specific_handler" => {
                Self::CSpecificHandler
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p___argc" => Self::PArgc,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p___argv" => Self::PArgv,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_cexit" => Self::Cexit,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_configure_narrow_argv" => {
                Self::ConfigureNarrowArgv
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_crt_atexit" => Self::CrtAtExit,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_exit" => Self::CrtExit,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_initialize_narrow_environment" => {
                Self::InitializeNarrowEnvironment
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_initterm" => Self::Initterm,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_initterm_e" => Self::InittermE,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_set_app_type" => Self::SetAppType,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_set_invalid_parameter_handler" => {
                Self::SetInvalidParameterHandler
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "abort" => Self::Abort,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "exit" => Self::Exit,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "signal" => Self::Signal,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__acrt_iob_func" => Self::AcrtIobFunc,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p__commode" => Self::PCommode,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p__fmode" => Self::PFmode,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__stdio_common_vfprintf" => {
                Self::StdioCommonVfprintf
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "fwrite" => Self::Fwrite,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "strlen" => Self::Strlen,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "strncmp" => Self::Strncmp,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p__environ" => Self::PEnviron,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__setusermatherr" => {
                Self::SetUserMathErr
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MessageBoxW" => Self::MessageBoxW,
            (_, ImportSymbol::ByName { name, .. }) => Self::Unsupported {
                dll: import.resolved_module.clone(),
                symbol: name.clone(),
            },
            (_, ImportSymbol::ByOrdinal { ordinal }) => Self::Unsupported {
                dll: import.resolved_module.clone(),
                symbol: format!("ordinal#{ordinal}"),
            },
        }
    }
}

fn decode_current_instruction(
    engine: &CpuExecutionEngine,
    memory: &MemoryImage,
    rip: u64,
) -> AppResult<DecodedInstruction> {
    let bytes = read_window(memory, rip, 15)?;
    for len in (1..=bytes.len()).rev() {
        if let Ok(decoded) = engine.decode_block(&bytes[..len], rip) {
            if decoded.len() == 1 && decoded[0].size == len {
                return Ok(decoded.into_iter().next().expect("decoded instruction"));
            }
        }
    }
    let window = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    Err(AppError::new(
        ReasonCode::RcUnimplInsn,
        format!("failed to decode guest instruction at {rip:#x}: {window}"),
    ))
}

fn decode_current_instruction_cached(
    engine: &CpuExecutionEngine,
    memory: &MemoryImage,
    instruction_cache: &mut BTreeMap<u64, CachedInstruction>,
    rip: u64,
) -> AppResult<CachedInstruction> {
    if let Some(cached) = instruction_cache.get(&rip) {
        if read_window(memory, rip, cached.decoded.size)? == cached.bytes {
            return Ok(cached.clone());
        }
    }

    let decoded = decode_current_instruction(engine, memory, rip)?;
    let bytes = read_window(memory, rip, decoded.size)?;
    let ir = crate::cpu::lower_to_ir(std::slice::from_ref(&decoded))?;
    let cached = CachedInstruction { bytes, decoded, ir };

    if instruction_cache.len() >= INSTRUCTION_CACHE_LIMIT && !instruction_cache.contains_key(&rip) {
        instruction_cache.clear();
    }
    instruction_cache.insert(rip, cached.clone());
    Ok(cached)
}

fn annotate_guest_fault(error: AppError, memory: &MemoryImage, state: &CpuState) -> AppError {
    let rip = state.rip;
    let window = read_window(memory, rip, 15)
        .map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|_| "<unavailable>".to_string());
    let registers = format!(
        "rax={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x} rsp={:#x} rbp={:#x}",
        state.get(Register::Rax),
        state.get(Register::Rcx),
        state.get(Register::Rdx),
        state.get(Register::Rsi),
        state.get(Register::Rdi),
        state.get(Register::Rsp),
        state.get(Register::Rbp),
    );
    let mut wrapped = AppError::new(
        error.code,
        format!("{} while executing guest instruction at {rip:#x}: {window} | {registers}", error.message),
    );
    for hint in error.reproduction_hints {
        wrapped = wrapped.with_hint(hint);
    }
    wrapped
}

fn instruction_controls_rip(opcode: DecodedOpcode) -> bool {
    matches!(
        opcode,
        DecodedOpcode::CallRel
            | DecodedOpcode::CallMemory
            | DecodedOpcode::CallRegister
            | DecodedOpcode::Jcc
            | DecodedOpcode::JmpRel
            | DecodedOpcode::JmpRegister
            | DecodedOpcode::JmpMemory
    )
}

fn pe_runtime_instruction_budget(env: &BTreeMap<String, String>, live_mode: bool) -> AppResult<u64> {
    match env.get(PE_RUNTIME_BUDGET_ENV) {
        None => Ok(if live_mode {
            u64::MAX
        } else {
            PE_RUNTIME_INSTRUCTION_BUDGET
        }),
        Some(raw) => raw.parse::<u64>().map_err(|error| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("invalid {PE_RUNTIME_BUDGET_ENV} value {raw:?}"),
            )
            .with_hint(error.to_string())
        }),
    }
}

fn read_window(memory: &MemoryImage, address: u64, len: usize) -> AppResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(len);
    for offset in 0..len {
        bytes.push(memory.read_u8(address + offset as u64)?);
    }
    Ok(bytes)
}

fn read_i32_from_memory(memory: &MemoryImage, address: u64) -> AppResult<i32> {
    let bytes = read_window(memory, address, 4)?;
    Ok(i32::from_le_bytes(bytes.try_into().expect("disp32")))
}

fn read_c_string(memory: &MemoryImage, address: u64) -> AppResult<String> {
    let bytes = read_c_string_limit(memory, address, usize::MAX)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_c_string_limit(memory: &MemoryImage, address: u64, limit: usize) -> AppResult<Vec<u8>> {
    if address == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = Vec::new();
    let mut cursor = address;
    while bytes.len() < limit {
        let byte = memory.read_u8(cursor)?;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
        cursor = cursor.wrapping_add(1);
    }
    Ok(bytes)
}

fn read_utf16_string(memory: &MemoryImage, address: u64) -> AppResult<String> {
    if address == 0 {
        return Ok(String::new());
    }
    let mut code_units = Vec::new();
    let mut cursor = address;
    loop {
        let low = memory.read_u8(cursor)?;
        let high = memory.read_u8(cursor + 1)?;
        let code_unit = u16::from_le_bytes([low, high]);
        if code_unit == 0 {
            break;
        }
        code_units.push(code_unit);
        cursor = cursor.wrapping_add(2);
    }
    Ok(String::from_utf16_lossy(&code_units))
}

fn file_access_from_win32(desired_access: u32) -> crate::ge::FileAccess {
    crate::ge::FileAccess {
        read: desired_access & (GENERIC_READ | GENERIC_ALL) != 0,
        write: desired_access & (GENERIC_WRITE | GENERIC_ALL) != 0,
        delete: desired_access & GENERIC_ALL != 0,
    }
}

fn share_mode_from_win32(share_mode: u32) -> crate::ge::ShareMode {
    crate::ge::ShareMode {
        read: share_mode & FILE_SHARE_READ != 0,
        write: share_mode & FILE_SHARE_WRITE != 0,
        delete: share_mode & FILE_SHARE_DELETE != 0,
    }
}

fn creation_disposition_from_win32(value: u32) -> AppResult<CreationDisposition> {
    match value {
        CREATE_NEW => Ok(CreationDisposition::CreateNew),
        CREATE_ALWAYS => Ok(CreationDisposition::CreateAlways),
        OPEN_EXISTING => Ok(CreationDisposition::OpenExisting),
        OPEN_ALWAYS => Ok(CreationDisposition::OpenAlways),
        TRUNCATE_EXISTING => Ok(CreationDisposition::TruncateExisting),
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported CreateFileW disposition {other}"),
        )),
    }
}

fn last_error_from_app_error(error: &AppError) -> u32 {
    match error.code {
        ReasonCode::RcFsNotFound => ERROR_FILE_NOT_FOUND,
        ReasonCode::RcFsPathInvalid => ERROR_PATH_NOT_FOUND,
        ReasonCode::RcWin32InvalidHandle => ERROR_INVALID_HANDLE,
        ReasonCode::RcFsSharingViolation => ERROR_SHARING_VIOLATION,
        ReasonCode::RcFsLockViolation => ERROR_LOCK_VIOLATION,
        ReasonCode::RcFsAlreadyExists => ERROR_ALREADY_EXISTS,
        ReasonCode::RcCliInvalid => ERROR_INVALID_PARAMETER,
        _ => ERROR_ACCESS_DENIED,
    }
}

fn load_keyboard_replay(env: &BTreeMap<String, String>) -> AppResult<Vec<KeyboardReplayEvent>> {
    let Some(raw) = env.get(KEYBOARD_REPLAY_ENV) else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<KeyboardReplayEvent>>(raw).map_err(|error| {
        AppError::new(
            ReasonCode::RcCliInvalid,
            format!("invalid {KEYBOARD_REPLAY_ENV} payload"),
        )
        .with_hint(error.to_string())
    })
}

fn load_trace_categories(env: &BTreeMap<String, String>) -> Option<BTreeSet<String>> {
    let raw = env.get(TRACE_CATEGORIES_ENV)?;
    Some(
        raw.split(',')
            .map(str::trim)
            .filter(|category| !category.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
    )
}

fn read_wave_format(memory: &MemoryImage, address: u64) -> AppResult<WaveFormat> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "source voice format pointer must not be null",
        ));
    }
    let format_tag = read_guest_u16(memory, address)?;
    let channels = read_guest_u16(memory, address + 2)?;
    let sample_rate = read_guest_u32(memory, address + 4)?;
    let block_align = read_guest_u16(memory, address + 12)?;
    let bits_per_sample = read_guest_u16(memory, address + 14)?;
    let sample_format = match (format_tag, bits_per_sample) {
        (1, 16) => SampleFormat::Pcm16,
        (3, 32) => SampleFormat::Float32,
        _ => {
            return Err(AppError::new(
                ReasonCode::RcAudioUnsupported,
                format!(
                    "unsupported WAVEFORMATEX tag={format_tag} bits_per_sample={bits_per_sample}"
                )
            ))
        }
    };
    let expected_block_align = channels as usize
        * match sample_format {
            SampleFormat::Pcm16 => 2,
            SampleFormat::Float32 => 4,
        };
    if block_align as usize != expected_block_align {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            format!("invalid WAVEFORMATEX block align {block_align}; expected {expected_block_align}"),
        ));
    }
    Ok(WaveFormat {
        channels,
        sample_rate,
        sample_format,
    })
}

fn read_xaudio2_buffer(
    memory: &MemoryImage,
    address: u64,
    format: &WaveFormat,
) -> AppResult<(AudioSamples, u32)> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "XAUDIO2_BUFFER pointer must not be null",
        ));
    }
    let audio_bytes = read_guest_u32(memory, address + 4)?;
    let audio_data = memory.read_u64(address + 8)?;
    let play_begin = read_guest_u32(memory, address + 16)?;
    let play_length = read_guest_u32(memory, address + 20)?;
    let loop_begin = read_guest_u32(memory, address + 24)?;
    let loop_length = read_guest_u32(memory, address + 28)?;
    let loop_count = read_guest_u32(memory, address + 32)?;
    if audio_bytes == 0 || audio_data == 0 || play_begin != 0 || play_length != 0 || loop_begin != 0 || loop_length != 0 || loop_count != 0 {
        return Err(AppError::new(
            ReasonCode::RcAudioUnsupported,
            "only full, non-looping XAUDIO2_BUFFER payloads are currently supported",
        ));
    }
    let bytes = read_guest_bytes(memory, audio_data, audio_bytes as usize)?;
    let samples = match format.sample_format {
        SampleFormat::Pcm16 => {
            if bytes.len() % 2 != 0 {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("PCM16 source buffer length {} is not sample-aligned", bytes.len()),
                ));
            }
            let values = bytes
                .chunks_exact(2)
                .map(|chunk| i16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            AudioSamples::Pcm16(values)
        }
        SampleFormat::Float32 => {
            if bytes.len() % 4 != 0 {
                return Err(AppError::new(
                    ReasonCode::RcAudioUnsupported,
                    format!("float32 source buffer length {} is not sample-aligned", bytes.len()),
                ));
            }
            let values = bytes
                .chunks_exact(4)
                .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect::<Vec<_>>();
            AudioSamples::Float32(values)
        }
    };
    Ok((samples, audio_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::Operand;
    use crate::ge::{GameEnvironment, GeArch};
    use tempfile::TempDir;

    fn build_root_signature(root_constants: u32, descriptors: &[(u8, u8, u8, u8, u8, u8)]) -> Vec<u8> {
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

    fn embedded_root_pixel_shader_dxil() -> Vec<u8> {
        let root_signature = build_root_signature(4, &[(1, 0, 0, 1, 0, 0)]);
        build_container(
            "main_ps",
            vec![
                (
                    *b"PROG",
                    build_program_part(12, 256, (1, 1, 1), &[(1, 0, 0, 0, 0, 0)]),
                ),
                (*b"SIGN", b"input-signature-output-signature".to_vec()),
                (*b"ROOT", root_signature),
            ],
        )
    }

    #[test]
    fn decode_current_instruction_accepts_rip_relative_add_imm8_to_memory() {
        let rip = 0x1000;
        let target = 0x1040;
        let displacement = (target as i64 - (rip as i64 + 7)) as i32;
        let bytes = [
            0x83,
            0x05,
            displacement as u8,
            (displacement >> 8) as u8,
            (displacement >> 16) as u8,
            (displacement >> 24) as u8,
            0x01,
            0xB8,
            0x05,
            0x00,
            0x00,
            0x00,
            0x66,
            0x2E,
            0x0F,
        ];
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(rip, &bytes);

        let decoded = decode_current_instruction(&engine, &memory, rip).expect("decode current instruction");

        assert_eq!(decoded.opcode, DecodedOpcode::AddImm);
        assert_eq!(decoded.size, 7);
        assert!(matches!(decoded.operands.first(), Some(Operand::Memory(_))));
    }

    #[test]
    fn decode_current_instruction_prefers_full_c7_memory_immediate_length() {
        let rip = 0x2000;
        let bytes = [
            0xC7, 0x44, 0x24, 0x60, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x57, 0xC0, 0x0F, 0x11,
            0x05, 0xE8,
        ];
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(rip, &bytes);

        let decoded = decode_current_instruction(&engine, &memory, rip).expect("decode current instruction");

        assert_eq!(decoded.opcode, DecodedOpcode::MovStoreImm);
        assert_eq!(decoded.size, 8);
        assert!(matches!(decoded.operands.first(), Some(Operand::Memory(_))));
    }

    #[test]
    fn decode_current_instruction_handles_operand_size_prefixed_c7_imm16() {
        let rip = 0x3000;
        let bytes = [
            0x66, 0xC7, 0x05, 0x10, 0x00, 0x00, 0x00, 0x07, 0xFF, 0x90, 0x90, 0x90, 0x90,
            0x90, 0x90,
        ];
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(rip, &bytes);

        let decoded = decode_current_instruction(&engine, &memory, rip).expect("decode current instruction");

        assert_eq!(decoded.opcode, DecodedOpcode::MovStoreImm);
        assert_eq!(decoded.size, 9);
        assert!(matches!(decoded.operands.first(), Some(Operand::Memory(_))));
    }

    #[test]
    fn decode_current_instruction_handles_d1_shr_on_extended_register() {
        let rip = 0x4000;
        let bytes = [
            0x41, 0xD1, 0xEB, 0x45, 0x01, 0xD3, 0x41, 0xC1, 0xEB, 0x02, 0x46, 0x8D, 0x14,
            0xDD, 0x00,
        ];
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(rip, &bytes);

        let decoded = decode_current_instruction(&engine, &memory, rip).expect("decode current instruction");

        assert_eq!(decoded.opcode, DecodedOpcode::ShrImm);
        assert_eq!(decoded.size, 3);
    }

    #[test]
    fn decode_current_instruction_handles_two_operand_imul() {
        let rip = 0x5000;
        let bytes = [
            0x4C, 0x0F, 0xAF, 0xDA, 0x49, 0xC1, 0xEB, 0x22, 0x45, 0x01, 0xDB, 0x47, 0x8D,
            0x1C, 0x5B,
        ];
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(rip, &bytes);

        let decoded = decode_current_instruction(&engine, &memory, rip).expect("decode current instruction");

        assert_eq!(decoded.opcode, DecodedOpcode::ImulReg);
        assert_eq!(decoded.size, 4);
    }

    #[test]
    fn decode_current_instruction_handles_rip_relative_mov_load_length() {
        let rip = 0x7000;
        let bytes = [
            0x8B, 0x05, 0x61, 0x5A, 0x00, 0x00,
            0x83, 0xF8, 0x03,
            0x74, 0x11,
            0x83, 0xF8, 0x02,
            0x0F,
        ];
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(rip, &bytes);

        let decoded = decode_current_instruction(&engine, &memory, rip).expect("decode current instruction");

        assert_eq!(decoded.opcode, DecodedOpcode::MovLoad);
        assert_eq!(decoded.size, 6);
        assert!(matches!(decoded.operands.first(), Some(Operand::Register(Register::Rax))));
        assert!(matches!(decoded.operands.get(1), Some(Operand::Memory(_))));
    }

    #[test]
    fn decode_current_instruction_handles_movsx_byte_to_extended_dword() {
        let rip = 0x6000;
        let bytes = [
            0x44, 0x0F, 0xBE, 0xC2, 0x45, 0x8D, 0x58, 0xBF, 0x41, 0x80, 0xFB, 0x19, 0x77,
            0x17, 0x41,
        ];
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        memory.map_bytes(rip, &bytes);

        let decoded = decode_current_instruction(&engine, &memory, rip).expect("decode current instruction");

        assert_eq!(decoded.opcode, DecodedOpcode::Movsx);
        assert_eq!(decoded.size, 4);
    }

    #[test]
    fn runtime_does_not_auto_advance_after_jmp_register() {
        let rip = 0x8000;
        let target = 0x9000;
        let bytes = [0xFF, 0xE2, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        let mut state = CpuState::new(GuestArch::X64);
        memory.map_bytes(rip, &bytes);
        memory.map_bytes(target, &[0x90]);
        state.rip = rip;
        state.set(Register::Rdx, target);

        let instruction = decode_current_instruction(&engine, &memory, state.rip).expect("decode current instruction");
        let ir = crate::cpu::lower_to_ir(std::slice::from_ref(&instruction)).expect("lower jmp rdx");
        let _ = engine
            .execute_ir_without_memory_hash(&mut state, &mut memory, &ir)
            .expect("execute jmp rdx");
        if !instruction_controls_rip(instruction.opcode) {
            state.rip = state.rip.wrapping_add(instruction.size as u64);
        }

        assert_eq!(instruction.opcode, DecodedOpcode::JmpRegister);
        assert_eq!(state.rip, target);
    }

    #[test]
    fn decode_current_instruction_cache_refreshes_when_instruction_bytes_change() {
        let rip = 0xA000;
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        let mut instruction_cache = BTreeMap::new();

        memory.map_bytes(rip, &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
        let first = decode_current_instruction_cached(&engine, &memory, &mut instruction_cache, rip)
            .expect("decode cached nop");
        assert_eq!(first.decoded.opcode, DecodedOpcode::Nop);

        memory.map_bytes(rip, &[0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
        let second = decode_current_instruction_cached(&engine, &memory, &mut instruction_cache, rip)
            .expect("decode cached ret");

        assert_eq!(second.decoded.opcode, DecodedOpcode::Ret);
        assert_eq!(second.decoded.size, 1);
    }

    #[test]
    fn pe_runtime_d3d11_pixel_shader_thunks_translate_and_bind_dxil() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "shader-thunk", GeArch::X64, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let device = d3d11_create_device(DeviceCreationRequest {
            requested_feature_levels: vec![FeatureLevel::Level10_1],
        })
        .expect("create d3d11 device");
        let device_object = runtime
            .alloc_d3d11_device_object(&mut memory, device)
            .expect("alloc guest d3d11 device");
        let context_object = runtime
            .d3d11_device(device_object)
            .expect("device host")
            .context_object;

        let device_vtable = memory.read_u64(device_object).expect("device vtable");
        let create_pixel_shader_thunk = memory
            .read_u64(device_vtable + 15 * 8)
            .expect("CreatePixelShader thunk");
        let context_vtable = memory.read_u64(context_object).expect("context vtable");
        let ps_set_shader_thunk = memory
            .read_u64(context_vtable + 9 * 8)
            .expect("PSSetShader thunk");

        let stack_base = 0x20_000;
        memory.map_bytes(stack_base, &vec![0_u8; 0x100]);
        let bytecode_address = 0x21_000;
        let bytecode = embedded_root_pixel_shader_dxil();
        memory.map_bytes(bytecode_address, &bytecode);
        let shader_out_ptr = 0x22_000;
        memory.map_bytes(shader_out_ptr, &[0; 8]);

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, bytecode_address);
        state.set(Register::R8, bytecode.len() as u64);
        state.set(Register::R9, 0);
        memory.write_u64(stack_base, 0xDEAD_BEEF);
        memory.write_u64(stack_base + 0x28, shader_out_ptr);

        runtime
            .dispatch_import(create_pixel_shader_thunk, &mut state, &mut memory)
            .expect("dispatch CreatePixelShader");
        assert_eq!(state.get(Register::Rax), 0);
        let shader_object = memory.read_u64(shader_out_ptr).expect("read shader object");
        let guest_shader = runtime.d3d11_shader(shader_object).expect("guest shader metadata");
        assert_eq!(guest_shader.stage, D3d11ShaderStage::Ps);

        state.set(Register::Rsp, stack_base + 0x40);
        memory.write_u64(stack_base + 0x40, 0xCAFE_BABE);
        state.set(Register::Rcx, context_object);
        state.set(Register::Rdx, shader_object);
        state.set(Register::R8, 0);
        state.set(Register::R9, 0);
        runtime
            .dispatch_import(ps_set_shader_thunk, &mut state, &mut memory)
            .expect("dispatch PSSetShader");
        assert_eq!(state.get(Register::Rax), 0);

        let device_host = runtime.d3d11_device(device_object).expect("device host after bind");
        let cache_key = device_host
            .device
            .shader_translation_cache_key(guest_shader.shader_id)
            .expect("shader cache key")
            .expect("translated shader cache key");
        let submission = runtime
            .d3d11_device_mut(device_object)
            .expect("mutable device host")
            .device
            .submit_immediate()
            .expect("submit immediate with bound shader");
        assert!(submission.signature.contains(&cache_key));
        assert!(submission.signature.contains("msl_ps_"));

        state.set(Register::Rsp, stack_base + 0x80);
        memory.write_u64(stack_base + 0x80, 0xABCD_EF01);
        state.set(Register::Rcx, context_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, 0);
        runtime
            .dispatch_import(ps_set_shader_thunk, &mut state, &mut memory)
            .expect("dispatch PSSetShader null clear");
        assert_eq!(state.get(Register::Rax), 0);

        let cleared_submission = runtime
            .d3d11_device_mut(device_object)
            .expect("mutable device host after clear")
            .device
            .submit_immediate()
            .expect("submit immediate after clearing shader");
        assert!(!cleared_submission.signature.contains(&cache_key));

        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D11Device::CreatePixelShader"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D11DeviceContext::PSSetShader"));
    }
}

fn read_d3d_feature_levels(
    memory: &MemoryImage,
    address: u64,
    count: u32,
) -> AppResult<Vec<FeatureLevel>> {
    if count == 0 {
        return Ok(vec![FeatureLevel::Level10_1]);
    }
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "feature level array pointer must not be null when a non-zero feature level count is supplied",
        ));
    }
    let mut levels = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        let value = read_guest_u32(memory, address + index * 4)?;
        levels.push(match value {
            0xa100 => FeatureLevel::Level10_1,
            0xb000 => FeatureLevel::Level11_0,
            other => {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("unsupported D3D feature level {other:#x}"),
                ))
            }
        });
    }
    Ok(levels)
}

fn d3d_feature_level_value(level: FeatureLevel) -> u32 {
    match level {
        FeatureLevel::Level10_1 => 0xa100,
        FeatureLevel::Level11_0 => 0xb000,
    }
}

fn read_swapchain_desc(memory: &MemoryImage, address: u64) -> AppResult<SwapchainDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "swapchain descriptor pointer must not be null",
        ));
    }
    let width = read_guest_u32(memory, address)?;
    let height = read_guest_u32(memory, address + 4)?;
    let format = map_dxgi_format(read_guest_u32(memory, address + 16)?)?;
    let sample_count = read_guest_u32(memory, address + 28)?;
    let sample_quality = read_guest_u32(memory, address + 32)?;
    let buffer_count = read_guest_u32(memory, address + 40)?;
    let output_window = memory.read_u64(address + 48)?;
    if sample_count != 1 || sample_quality != 0 || output_window == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!(
                "only single-sample windowed DXGI swapchains with a valid output window are currently supported (sample_count={sample_count}, sample_quality={sample_quality}, output_window={output_window:#x})"
            ),
        ));
    }
    Ok(SwapchainDesc {
        width,
        height,
        format,
        buffer_count,
    })
}

fn map_dxgi_format(value: u32) -> AppResult<DxgiFormat> {
    match value {
        28 => Ok(DxgiFormat::R8G8B8A8Unorm),
        87 => Ok(DxgiFormat::B8G8R8A8Unorm),
        45 => Ok(DxgiFormat::D24UnormS8Uint),
        other => Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported DXGI format {other}"),
        )),
    }
}

fn read_d3d11_buffer_byte_width(memory: &MemoryImage, address: u64) -> AppResult<usize> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "buffer descriptor pointer must not be null",
        ));
    }
    let byte_width = read_guest_u32(memory, address)? as usize;
    if byte_width == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "buffer byte width must be greater than zero",
        ));
    }
    Ok(byte_width)
}

fn read_d3d11_view_format(memory: &MemoryImage, address: u64, default_format: DxgiFormat) -> AppResult<DxgiFormat> {
    if address == 0 {
        return Ok(default_format);
    }
    let raw = read_guest_u32(memory, address)?;
    if raw == 0 {
        return Ok(default_format);
    }
    map_dxgi_format(raw)
}

fn read_d3d11_input_layout_desc(memory: &MemoryImage, address: u64, count: u32) -> AppResult<InputLayoutDesc> {
    if address == 0 || count == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "input layout elements pointer and count must describe at least one element",
        ));
    }
    let mut elements = Vec::with_capacity(count as usize);
    for index in 0..count as u64 {
        let element_address = address + index * 32;
        let semantic_name_ptr = read_guest_u64(memory, element_address)?;
        if semantic_name_ptr == 0 {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("input element {index} semantic name pointer must not be null"),
            ));
        }
        let semantic = String::from_utf8_lossy(&read_c_string_limit(memory, semantic_name_ptr, 64)?).to_string();
        let format = map_dxgi_format(read_guest_u32(memory, element_address + 12)?)?;
        let slot = read_guest_u32(memory, element_address + 16)?;
        elements.push(InputElementDesc {
            semantic,
            format,
            slot,
        });
    }
    Ok(InputLayoutDesc { elements })
}

fn read_guest_pointer_array(memory: &MemoryImage, address: u64, count: usize) -> AppResult<Vec<u64>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "guest pointer array must not be null when count is non-zero",
        ));
    }
    let mut pointers = Vec::with_capacity(count);
    for index in 0..count as u64 {
        pointers.push(read_guest_u64(memory, address + index * 8)?);
    }
    Ok(pointers)
}

fn linearize_texture_update(
    memory: &MemoryImage,
    src_ptr: u64,
    row_pitch: usize,
    _depth_pitch: usize,
    desc: &crate::d3d11::D3d11ResourceDesc,
) -> AppResult<Vec<u8>> {
    if src_ptr == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "source upload pointer must not be null",
        ));
    }
    match desc.dimension {
        ResourceDimension::Buffer => read_guest_bytes(memory, src_ptr, desc.byte_width),
        ResourceDimension::Texture2D => {
            let bytes_per_pixel = match desc.format {
                DxgiFormat::R8G8B8A8Unorm | DxgiFormat::B8G8R8A8Unorm | DxgiFormat::D24UnormS8Uint => 4,
                _ => {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!("unsupported upload format {:?}", desc.format),
                    ))
                }
            };
            let expected_row_pitch = desc.width as usize * bytes_per_pixel;
            if row_pitch < expected_row_pitch {
                return Err(AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("row pitch {row_pitch} is smaller than the expected row pitch {expected_row_pitch}"),
                ));
            }
            let mut bytes = Vec::with_capacity(desc.byte_width);
            for row in 0..desc.height as usize {
                let row_ptr = src_ptr + (row * row_pitch) as u64;
                bytes.extend(read_guest_bytes(memory, row_ptr, expected_row_pitch)?);
            }
            Ok(bytes)
        }
        _ => Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported resource upload dimension {:?}", desc.dimension),
        )),
    }
}

fn write_win64_msg(memory: &mut MemoryImage, address: u64, message: &Message) -> AppResult<()> {
    write_u64(memory, address, message.hwnd.unwrap_or(0) as u64);
    write_u32(memory, address + 8, message_id(message.kind));
    write_u32(memory, address + 12, 0);
    write_u64(memory, address + 16, message.wparam as u64);
    write_u64(memory, address + 24, message.lparam as u64);
    write_u32(memory, address + 32, 0);
    write_u32(memory, address + 36, 0);
    write_u32(memory, address + 40, 0);
    write_u32(memory, address + 44, 0);
    Ok(())
}

fn read_win64_msg(memory: &MemoryImage, address: u64) -> AppResult<Message> {
    Ok(Message {
        hwnd: match memory.read_u64(address)? {
            0 => None,
            hwnd => Some(hwnd as u32),
        },
        kind: message_kind(read_u32(memory, address + 8)?)?,
        wparam: memory.read_u64(address + 16)? as i64,
        lparam: memory.read_u64(address + 24)? as i64,
        translated: false,
        device_id: None,
    })
}

fn message_id(kind: MessageKind) -> u32 {
    match kind {
        MessageKind::Create => 0x0001,
        MessageKind::Destroy => 0x0002,
        MessageKind::Size => 0x0005,
        MessageKind::Activate => 0x0006,
        MessageKind::SetFocus => 0x0007,
        MessageKind::KillFocus => 0x0008,
        MessageKind::Quit => 0x0012,
        MessageKind::ShowWindow => 0x0018,
        MessageKind::WindowPosChanging => 0x0046,
        MessageKind::InputDeviceChange => 0x00fe,
        MessageKind::Input | MessageKind::RawInput => 0x00ff,
        MessageKind::NcCreate => 0x0081,
        MessageKind::NcDestroy => 0x0082,
        MessageKind::KeyDown => 0x0100,
        MessageKind::KeyUp => 0x0101,
        MessageKind::Char => 0x0102,
        MessageKind::DeadChar => 0x0103,
        MessageKind::MouseMove => 0x0200,
        MessageKind::MouseWheel => 0x020a,
        MessageKind::XButtonDown => 0x020b,
        MessageKind::MouseHWheel => 0x020e,
    }
}

fn message_kind(message_id: u32) -> AppResult<MessageKind> {
    match message_id {
        0x0001 => Ok(MessageKind::Create),
        0x0002 => Ok(MessageKind::Destroy),
        0x0005 => Ok(MessageKind::Size),
        0x0006 => Ok(MessageKind::Activate),
        0x0007 => Ok(MessageKind::SetFocus),
        0x0008 => Ok(MessageKind::KillFocus),
        0x0012 => Ok(MessageKind::Quit),
        0x0018 => Ok(MessageKind::ShowWindow),
        0x0046 => Ok(MessageKind::WindowPosChanging),
        0x0081 => Ok(MessageKind::NcCreate),
        0x0082 => Ok(MessageKind::NcDestroy),
        0x00fe => Ok(MessageKind::InputDeviceChange),
        0x00ff => Ok(MessageKind::Input),
        0x0100 => Ok(MessageKind::KeyDown),
        0x0101 => Ok(MessageKind::KeyUp),
        0x0102 => Ok(MessageKind::Char),
        0x0103 => Ok(MessageKind::DeadChar),
        0x0200 => Ok(MessageKind::MouseMove),
        0x020a => Ok(MessageKind::MouseWheel),
        0x020b => Ok(MessageKind::XButtonDown),
        0x020e => Ok(MessageKind::MouseHWheel),
        _ => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported window message {message_id:#x}"),
        )),
    }
}

fn unsupported_method(name: &str) -> HostThunk {
    HostThunk::UnsupportedMethod {
        name: name.to_string(),
    }
}

fn align_up_u64(value: u64, align: u64) -> u64 {
    if align <= 1 {
        return value;
    }
    let mask = align - 1;
    (value + mask) & !mask
}

fn read_guest_u16(memory: &MemoryImage, address: u64) -> AppResult<u16> {
    Ok(u16::from_le_bytes([
        memory.read_u8(address)?,
        memory.read_u8(address + 1)?,
    ]))
}

fn read_guest_u32(memory: &MemoryImage, address: u64) -> AppResult<u32> {
    Ok(u32::from_le_bytes([
        memory.read_u8(address)?,
        memory.read_u8(address + 1)?,
        memory.read_u8(address + 2)?,
        memory.read_u8(address + 3)?,
    ]))
}

fn read_guest_u64(memory: &MemoryImage, address: u64) -> AppResult<u64> {
    Ok(u64::from_le_bytes([
        memory.read_u8(address)?,
        memory.read_u8(address + 1)?,
        memory.read_u8(address + 2)?,
        memory.read_u8(address + 3)?,
        memory.read_u8(address + 4)?,
        memory.read_u8(address + 5)?,
        memory.read_u8(address + 6)?,
        memory.read_u8(address + 7)?,
    ]))
}

fn read_guest_bytes(memory: &MemoryImage, address: u64, len: usize) -> AppResult<Vec<u8>> {
    let mut bytes = Vec::with_capacity(len);
    for offset in 0..len {
        bytes.push(memory.read_u8(address + offset as u64)?);
    }
    Ok(bytes)
}

fn read_u32(memory: &MemoryImage, address: u64) -> AppResult<u32> {
    Ok(u32::from_le_bytes([
        memory.read_u8(address)?,
        memory.read_u8(address + 1)?,
        memory.read_u8(address + 2)?,
        memory.read_u8(address + 3)?,
    ]))
}

fn write_u32(memory: &mut MemoryImage, address: u64, value: u32) {
    memory.map_bytes(address, &value.to_le_bytes());
}

fn write_u64(memory: &mut MemoryImage, address: u64, value: u64) {
    memory.write_u64(address, value);
}

fn show_host_message_box(title: &str, text: &str, dtm: bool) -> AppResult<()> {
    if dtm {
        return Ok(());
    }
    let status = Command::new("osascript")
        .arg("-e")
        .arg(format!(
            "display dialog {} with title {} buttons {{\"OK\"}} default button \"OK\" giving up after 1",
            apple_script_string(text),
            apple_script_string(title),
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| AppError::from_io(ReasonCode::RcIo, "failed to launch osascript for MessageBoxW", &error))?;
    if !status.success() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("osascript failed while showing MessageBoxW: {status}"),
        ));
    }
    Ok(())
}

fn play_host_beep(frequency_hz: u32, duration_ms: u32, dtm: bool) -> AppResult<()> {
    if dtm {
        return Ok(());
    }
    let temp_path = std::env::temp_dir().join(format!(
        "casa1-beep-{}-{}.wav",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0)
    ));
    let wav = synthesize_beep_wav(frequency_hz.max(37), duration_ms.max(10));
    fs::write(&temp_path, wav).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write host beep WAV {}", temp_path.display()),
            &error,
        )
    })?;
    let status = Command::new("afplay")
        .arg(&temp_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| AppError::from_io(ReasonCode::RcIo, "failed to launch afplay for Beep", &error))?;
    let _ = fs::remove_file(&temp_path);
    if !status.success() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("afplay failed while playing Beep: {status}"),
        ));
    }
    Ok(())
}

fn synthesize_beep_wav(frequency_hz: u32, duration_ms: u32) -> Vec<u8> {
    let sample_rate = 44_100_u32;
    let samples = ((sample_rate as u64 * duration_ms as u64) / 1000) as usize;
    let mut pcm = Vec::with_capacity(samples * 2);
    let amplitude = i16::MAX as f32 * 0.2;
    for index in 0..samples {
        let phase = (index as f32 * frequency_hz as f32 * std::f32::consts::TAU) / sample_rate as f32;
        let sample = (phase.sin() * amplitude) as i16;
        pcm.extend_from_slice(&sample.to_le_bytes());
    }

    let data_len = pcm.len() as u32;
    let mut wav = Vec::with_capacity(44 + pcm.len());
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16_u32.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&(sample_rate * 2).to_le_bytes());
    wav.extend_from_slice(&2_u16.to_le_bytes());
    wav.extend_from_slice(&16_u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    wav.extend_from_slice(&pcm);
    wav
}

fn apple_script_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn trace_event(
    event_index: u64,
    category: &str,
    call_id: &str,
    parameters: BTreeMap<String, Value>,
    return_value: Value,
    side_effect_hashes: Vec<String>,
) -> TraceEvent {
    TraceEvent {
        event_index,
        category: category.to_string(),
        call_id: call_id.to_string(),
        parameters,
        return_value,
        get_last_error: None,
        side_effect_hashes,
    }
}

fn export_tables() -> BTreeMap<String, Vec<ExportSymbol>> {
    BTreeMap::from([
        (
            "kernel32.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 17,
                    name: None,
                    target: ExportTarget::Rva(0x1000),
                },
                ExportSymbol {
                    ordinal: 100,
                    name: Some("CreateFileW".to_string()),
                    target: ExportTarget::Rva(0x1010),
                },
                ExportSymbol {
                    ordinal: 101,
                    name: Some("Sleep".to_string()),
                    target: ExportTarget::Rva(0x1020),
                },
                ExportSymbol {
                    ordinal: 102,
                    name: Some("Forwarded".to_string()),
                    target: ExportTarget::Forwarder("kernelbase.Sleep".to_string()),
                },
                ExportSymbol {
                    ordinal: 103,
                    name: Some("ExitProcess".to_string()),
                    target: ExportTarget::Rva(0x1030),
                },
                ExportSymbol {
                    ordinal: 104,
                    name: Some("DeleteCriticalSection".to_string()),
                    target: ExportTarget::Rva(0x1040),
                },
                ExportSymbol {
                    ordinal: 105,
                    name: Some("EnterCriticalSection".to_string()),
                    target: ExportTarget::Rva(0x1050),
                },
                ExportSymbol {
                    ordinal: 106,
                    name: Some("GetLastError".to_string()),
                    target: ExportTarget::Rva(0x1060),
                },
                ExportSymbol {
                    ordinal: 107,
                    name: Some("InitializeCriticalSection".to_string()),
                    target: ExportTarget::Rva(0x1070),
                },
                ExportSymbol {
                    ordinal: 108,
                    name: Some("LeaveCriticalSection".to_string()),
                    target: ExportTarget::Rva(0x1080),
                },
                ExportSymbol {
                    ordinal: 109,
                    name: Some("SetUnhandledExceptionFilter".to_string()),
                    target: ExportTarget::Rva(0x1090),
                },
                ExportSymbol {
                    ordinal: 110,
                    name: Some("Beep".to_string()),
                    target: ExportTarget::Rva(0x10a0),
                },
                ExportSymbol {
                    ordinal: 111,
                    name: Some("TlsGetValue".to_string()),
                    target: ExportTarget::Rva(0x10b0),
                },
                ExportSymbol {
                    ordinal: 112,
                    name: Some("VirtualProtect".to_string()),
                    target: ExportTarget::Rva(0x10c0),
                },
                ExportSymbol {
                    ordinal: 113,
                    name: Some("VirtualQuery".to_string()),
                    target: ExportTarget::Rva(0x10d0),
                },
                ExportSymbol {
                    ordinal: 114,
                    name: Some("ReadFile".to_string()),
                    target: ExportTarget::Rva(0x10e0),
                },
                ExportSymbol {
                    ordinal: 115,
                    name: Some("WriteFile".to_string()),
                    target: ExportTarget::Rva(0x10f0),
                },
                ExportSymbol {
                    ordinal: 116,
                    name: Some("CloseHandle".to_string()),
                    target: ExportTarget::Rva(0x1100),
                },
            ],
        ),
        (
            "kernelbase.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("Sleep".to_string()),
                target: ExportTarget::Rva(0x2000),
            }],
        ),
        (
            "ucrtbase.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("_set_new_mode".to_string()),
                    target: ExportTarget::Rva(0x2100),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("calloc".to_string()),
                    target: ExportTarget::Rva(0x2110),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("free".to_string()),
                    target: ExportTarget::Rva(0x2120),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("malloc".to_string()),
                    target: ExportTarget::Rva(0x2130),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("__C_specific_handler".to_string()),
                    target: ExportTarget::Rva(0x2140),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("__p___argc".to_string()),
                    target: ExportTarget::Rva(0x2150),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("__p___argv".to_string()),
                    target: ExportTarget::Rva(0x2160),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("_cexit".to_string()),
                    target: ExportTarget::Rva(0x2170),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("_configure_narrow_argv".to_string()),
                    target: ExportTarget::Rva(0x2180),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("_crt_atexit".to_string()),
                    target: ExportTarget::Rva(0x2190),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("_exit".to_string()),
                    target: ExportTarget::Rva(0x21a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("_initialize_narrow_environment".to_string()),
                    target: ExportTarget::Rva(0x21b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("_initterm".to_string()),
                    target: ExportTarget::Rva(0x21c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("_initterm_e".to_string()),
                    target: ExportTarget::Rva(0x21d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("_set_app_type".to_string()),
                    target: ExportTarget::Rva(0x21e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("_set_invalid_parameter_handler".to_string()),
                    target: ExportTarget::Rva(0x21f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("abort".to_string()),
                    target: ExportTarget::Rva(0x2200),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("exit".to_string()),
                    target: ExportTarget::Rva(0x2210),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("signal".to_string()),
                    target: ExportTarget::Rva(0x2220),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("__acrt_iob_func".to_string()),
                    target: ExportTarget::Rva(0x2230),
                },
                ExportSymbol {
                    ordinal: 21,
                    name: Some("__p__commode".to_string()),
                    target: ExportTarget::Rva(0x2240),
                },
                ExportSymbol {
                    ordinal: 22,
                    name: Some("__p__fmode".to_string()),
                    target: ExportTarget::Rva(0x2250),
                },
                ExportSymbol {
                    ordinal: 23,
                    name: Some("__stdio_common_vfprintf".to_string()),
                    target: ExportTarget::Rva(0x2260),
                },
                ExportSymbol {
                    ordinal: 24,
                    name: Some("fwrite".to_string()),
                    target: ExportTarget::Rva(0x2270),
                },
                ExportSymbol {
                    ordinal: 25,
                    name: Some("strlen".to_string()),
                    target: ExportTarget::Rva(0x2280),
                },
                ExportSymbol {
                    ordinal: 26,
                    name: Some("strncmp".to_string()),
                    target: ExportTarget::Rva(0x2290),
                },
                ExportSymbol {
                    ordinal: 27,
                    name: Some("__p__environ".to_string()),
                    target: ExportTarget::Rva(0x22a0),
                },
                ExportSymbol {
                    ordinal: 28,
                    name: Some("__setusermatherr".to_string()),
                    target: ExportTarget::Rva(0x22b0),
                },
            ],
        ),
        (
            "user32.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("RegisterClassExW".to_string()),
                    target: ExportTarget::Rva(0x2ff0),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CreateWindowExW".to_string()),
                    target: ExportTarget::Rva(0x3000),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("PeekMessageW".to_string()),
                    target: ExportTarget::Rva(0x3010),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DispatchMessageW".to_string()),
                    target: ExportTarget::Rva(0x3020),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DefWindowProcW".to_string()),
                    target: ExportTarget::Rva(0x3030),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("MessageBoxW".to_string()),
                    target: ExportTarget::Rva(0x3040),
                },
            ],
        ),
        (
            "d3d11.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3D11CreateDevice".to_string()),
                    target: ExportTarget::Rva(0x4000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3D11CreateDeviceAndSwapChain".to_string()),
                    target: ExportTarget::Rva(0x4010),
                },
            ],
        ),
        (
            "xaudio2_9.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("XAudio2Create".to_string()),
                target: ExportTarget::Rva(0x5000),
            }],
        ),
    ])
}