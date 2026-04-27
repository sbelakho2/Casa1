use crate::canonical::{GfxFrame, GuestException, PerfMetric};
use crate::cpu::{
    CpuEngineConfig, CpuExecutionEngine, CpuState, DecodedInstruction, DecodedOpcode, GuestArch,
    MemoryImage, Register, TranslatedBlock,
};
use crate::d3d12::{
    CommandAllocatorId as D3d12CommandAllocatorId, CommandListId as D3d12CommandListId,
    CommandQueueId as D3d12CommandQueueId, D3d12Runtime, DescriptorHeapId as D3d12DescriptorHeapId,
    FenceId as D3d12FenceId, ImmutableCommandStream, PipelineStateDesc,
    PipelineStateId as D3d12PipelineStateId, ResourceId as D3d12ResourceId,
    RootSignatureDesc, RootSignatureId as D3d12RootSignatureId,
    SwapchainId as D3d12SwapchainId,
};
use crate::d3d11::{
    d3d11_create_device, d3d11_create_device_and_swapchain, BlendStateDesc, D3d11Device,
    D3d11ResourceId, D3d11ViewId, DepthStencilStateDesc, DeviceCreationRequest, FeatureLevel,
    InputElementDesc, InputLayoutDesc, InputLayoutId, RasterizerStateDesc, ResourceDimension,
    SamplerStateDesc, ScissorRect, ShaderStage as D3d11ShaderStage, ViewKind, Viewport,
};
use crate::error::{AppError, AppResult};
use crate::ge::{GameEnvironment, RegistryView};
use crate::gfx::{
    BufferRole, DescriptorHeapType, DxgiFormat, ResourceState, ResourceUsageHint, SwapchainDesc,
    ViewDescriptor,
};
use crate::pe::{self, ApiSetResolver, ExportSymbol, ExportTarget, ImportSymbol, ResolvedImport};
use crate::live::{LiveAudioChunk, LiveFrame, LiveInputEvent, LivePeSession};
use crate::reason::ReasonCode;
use crate::shader::parse_dxil_container;
use crate::trace::TraceEvent;
use crate::audio::{AudioSamples, AudioSubsystem, SampleFormat, SourceBuffer, VoiceId, WaveFormat};
use crate::user32::{
    KeyboardDevice, KeyboardLayoutId, KeyModifiers, Message, MessageKind, User32Subsystem,
    WindowClassInfo, GWL_WNDPROC,
};
use crate::util;
use crate::win32::{ApartmentModel, CreationDisposition, FindData, SeekOrigin, Win32Subsystem};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const SYNTHETIC_PID_DTM: u32 = 4242;
const STACK_BASE: u64 = 0x0000_7fff_1000_0000;
const X86_STACK_BASE: u64 = 0x7000_0000;
const STACK_SIZE: usize = 0x1_0000;
const THUNK_BASE: u64 = 0x0000_7fff_8000_0000;
const X86_THUNK_BASE: u64 = 0x7100_0000;
const CRT_DATA_BASE: u64 = 0x0000_7fff_8100_0000;
const X86_CRT_DATA_BASE: u64 = 0x7200_0000;
const CRT_HEAP_BASE: u64 = 0x0000_7fff_8200_0000;
const X86_CRT_HEAP_BASE: u64 = 0x7300_0000;
const DESCRIPTOR_HANDLE_BASE: u64 = 0x0000_7fff_8300_0000;
const DESCRIPTOR_HANDLE_STRIDE: u64 = 0x20;
const MEMORY_BASIC_INFORMATION64_SIZE: u64 = 48;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_PRIVATE: u32 = 0x0002_0000;
const MEM_IMAGE: u32 = 0x0100_0000;
const E_INVALIDARG: u64 = 0x8007_0057;
const DXGI_ERROR_NOT_FOUND: u64 = 0x887A_0002;
const INVALID_HANDLE_VALUE: u64 = u64::MAX;
const DXGI_ADAPTER_DESC_DESCRIPTION_CHARS: usize = 128;
const D3D12_FEATURE_D3D12_OPTIONS: u32 = 0;
const D3D12_FEATURE_FEATURE_LEVELS: u32 = 2;
const D3D12_FEATURE_SHADER_MODEL: u32 = 7;
const D3D12_FEATURE_ROOT_SIGNATURE: u32 = 12;
const D3D12_FEATURE_ARCHITECTURE1: u32 = 16;
const D3D12_FEATURE_D3D12_OPTIONS5: u32 = 27;
const D3D12_FEATURE_D3D12_OPTIONS7: u32 = 32;
const D3D12_ROOT_SIGNATURE_VERSION_1: u32 = 0x1;
const D3D12_ROOT_SIGNATURE_VERSION_1_1: u32 = 0x2;
const D3D_FEATURE_LEVEL_11_0: u32 = 0xB000;
const D3D_FEATURE_LEVEL_11_1: u32 = 0xB100;
const D3D_FEATURE_LEVEL_12_0: u32 = 0xC000;
const D3D_FEATURE_LEVEL_12_1: u32 = 0xC100;
const D3D_FEATURE_LEVEL_12_2: u32 = 0xC200;
const D3D_SHADER_MODEL_6_5: u32 = 0x65;
const D3D_SHADER_MODEL_6_6: u32 = 0x66;
const D3D12_RENDER_PASS_TIER_1: u32 = 1;
const D3D12_RAYTRACING_TIER_NOT_SUPPORTED: u32 = 0;
const D3D12_MESH_SHADER_TIER_NOT_SUPPORTED: u32 = 0;
const D3D12_MESH_SHADER_TIER_1: u32 = 10;
const D3D12_SAMPLER_FEEDBACK_TIER_NOT_SUPPORTED: u32 = 0;
const D3D12_RESOURCE_BINDING_TIER_3: u32 = 3;
const D3D12_RESOURCE_HEAP_TIER_2: u32 = 2;
const D3D12_CONSERVATIVE_RASTERIZATION_TIER_1: u32 = 1;
const D3D12_TILED_RESOURCES_TIER_2: u32 = 2;
const PE_RUNTIME_INSTRUCTION_BUDGET: u64 = 25_000_000;
const KEYBOARD_REPLAY_ENV: &str = "CASA1_KEYBOARD_REPLAY_JSON";
const PE_RUNTIME_BUDGET_ENV: &str = "CASA1_PE_RUNTIME_BUDGET";
const EXPORT_FINAL_FRAME_ENV: &str = "CASA1_EXPORT_FINAL_FRAME";
const TRACE_CATEGORIES_ENV: &str = "CASA1_TRACE_CATEGORIES";
const INSTRUCTION_CACHE_LIMIT: usize = 65_536;
const BASIC_BLOCK_CACHE_LIMIT: usize = 16_384;
const BASIC_BLOCK_MAX_INSTRUCTIONS: usize = 32;
const BASIC_BLOCK_MAX_BYTES: usize = 512;
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
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_WINDOW_HANDLE: u32 = 1_400;
const ERROR_CLASS_DOES_NOT_EXIST: u32 = 1_411;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const E_NOINTERFACE: u64 = 0x8000_4002;
const E_ACCESSDENIED: u64 = 0x8007_0005;
const S_FALSE: u64 = 1;
const SW_SHOWNORMAL: i32 = 1;
const SHELL_LINK_CLSID: &str = "{00021401-0000-0000-C000-000000000046}";
const IID_IUNKNOWN: &str = "{00000000-0000-0000-C000-000000000046}";
const IID_IPERSIST: &str = "{0000010C-0000-0000-C000-000000000046}";
const IID_IPERSISTFILE: &str = "{0000010B-0000-0000-C000-000000000046}";
const IID_ISHELLLINKW: &str = "{000214F9-0000-0000-C000-000000000046}";
const CSIDL_DESKTOP: i32 = 0x0000;
const CSIDL_PROGRAMS: i32 = 0x0002;
const CSIDL_PERSONAL: i32 = 0x0005;
const CSIDL_FAVORITES: i32 = 0x0006;
const CSIDL_STARTUP: i32 = 0x0007;
const CSIDL_RECENT: i32 = 0x0008;
const CSIDL_SENDTO: i32 = 0x0009;
const CSIDL_STARTMENU: i32 = 0x000b;
const CSIDL_DESKTOPDIRECTORY: i32 = 0x0010;
const CSIDL_NETHOOD: i32 = 0x0013;
const CSIDL_FONTS: i32 = 0x0014;
const CSIDL_TEMPLATES: i32 = 0x0015;
const CSIDL_APPDATA: i32 = 0x001a;
const CSIDL_LOCAL_APPDATA: i32 = 0x001c;
const CSIDL_INTERNET_CACHE: i32 = 0x0020;
const CSIDL_COOKIES: i32 = 0x0021;
const CSIDL_HISTORY: i32 = 0x0022;
const CSIDL_COMMON_APPDATA: i32 = 0x0023;
const CSIDL_WINDOWS: i32 = 0x0024;
const CSIDL_SYSTEM: i32 = 0x0025;
const CSIDL_PROGRAM_FILES: i32 = 0x0026;
const CSIDL_MYPICTURES: i32 = 0x0027;
const CSIDL_PROFILE: i32 = 0x0028;
const CSIDL_SYSTEMX86: i32 = 0x0029;
const CSIDL_PROGRAM_FILESX86: i32 = 0x002a;
const CSIDL_COMMON_TEMPLATES: i32 = 0x002d;
const CSIDL_COMMON_DOCUMENTS: i32 = 0x002e;
const CSIDL_COMMON_ADMINTOOLS: i32 = 0x002f;
const CSIDL_ADMINTOOLS: i32 = 0x0030;

type U64Map<V> = HashMap<u64, V, U64IdentityBuildHasher>;

#[derive(Clone, Copy, Default)]
struct U64IdentityBuildHasher;

#[derive(Default)]
struct U64IdentityHasher(u64);

impl BuildHasher for U64IdentityBuildHasher {
    type Hasher = U64IdentityHasher;

    fn build_hasher(&self) -> Self::Hasher {
        U64IdentityHasher::default()
    }
}

impl Hasher for U64IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut hash = 0_u64;
        for (index, byte) in bytes.iter().take(8).enumerate() {
            hash |= u64::from(*byte) << (index * 8);
        }
        for &byte in &bytes[8..] {
            hash = hash.rotate_left(5) ^ u64::from(byte);
        }
        self.0 = hash;
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }

    fn write_usize(&mut self, value: usize) {
        self.0 = value as u64;
    }
}
const ERROR_MORE_DATA: u32 = 234;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_LOCK_VIOLATION: u32 = 33;
const ERROR_ALREADY_EXISTS: u32 = 183;
const STILL_ACTIVE: u32 = 259;
const INIT_ONCE_CHECK_ONLY: u32 = 0x0000_0001;
const INIT_ONCE_INIT_FAILED: u32 = 0x0000_0004;
const IDOK: i32 = 1;
const IDCANCEL: i32 = 2;
const IDABORT: i32 = 3;
const IDRETRY: i32 = 4;
const IDIGNORE: i32 = 5;
const IDYES: i32 = 6;
const IDNO: i32 = 7;
const IDTRYAGAIN: i32 = 10;
const IDCONTINUE: i32 = 11;
const CP_ACP: u32 = 0;
const DEFAULT_ANSI_CODE_PAGE: u32 = 1252;
const CT_CTYPE1: u32 = 1;
const CT_CTYPE2: u32 = 2;
const CT_CTYPE3: u32 = 4;
const C1_UPPER: u16 = 0x0001;
const C1_LOWER: u16 = 0x0002;
const C1_DIGIT: u16 = 0x0004;
const C1_SPACE: u16 = 0x0008;
const C1_PUNCT: u16 = 0x0010;
const C1_CNTRL: u16 = 0x0020;
const C1_BLANK: u16 = 0x0040;
const C1_XDIGIT: u16 = 0x0080;
const C1_ALPHA: u16 = 0x0100;
const LCMAP_LOWERCASE: u32 = 0x0000_0100;
const LCMAP_UPPERCASE: u32 = 0x0000_0200;
const LCMAP_LINGUISTIC_CASING: u32 = 0x0100_0000;
const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
const HKEY_CURRENT_USER: u32 = 0x8000_0001;
const HKEY_LOCAL_MACHINE: u32 = 0x8000_0002;
const HKEY_USERS: u32 = 0x8000_0003;
const HKEY_CURRENT_CONFIG: u32 = 0x8000_0005;
const REG_CREATED_NEW_KEY: u32 = 1;
const REG_OPENED_EXISTING_KEY: u32 = 2;
const KEY_WOW64_64KEY: u32 = 0x0100;
const KEY_WOW64_32KEY: u32 = 0x0200;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;
const INVALID_FILE_ATTRIBUTES: u64 = 0xFFFF_FFFF;
const INVALID_SET_FILE_POINTER: u64 = 0xFFFF_FFFF;
const STD_INPUT_HANDLE: u32 = u32::MAX - 9;
const STD_OUTPUT_HANDLE: u32 = u32::MAX - 10;
const STD_ERROR_HANDLE: u32 = u32::MAX - 11;
const FILE_TYPE_UNKNOWN: u32 = 0;
const FILE_TYPE_DISK: u32 = 1;
const FILE_TYPE_CHAR: u32 = 2;
const PROCESS_HEAP_HANDLE: u64 = 0x1000;
const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const DRIVE_FIXED: u32 = 3;
const WIN32_FIND_DATAW_FILE_NAME_CHARS: usize = 260;
const WIN32_FIND_DATAW_ALT_FILE_NAME_CHARS: usize = 14;

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
    CreateDXGIFactory1,
    CreateDXGIFactory2,
    DXGIFactoryEnumAdapters,
    DXGIFactoryEnumAdapters1,
    DXGIAdapterGetDesc,
    DXGIAdapterGetDesc1,
    DXGIFactoryCreateSwapChain,
    DXGIFactoryCreateSwapChainForHwnd,
    D3D11CreateDevice,
    D3D11CreateDeviceAndSwapChain,
    D3D12CreateDevice,
    D3D12DeviceCreateCommandQueue,
    D3D12DeviceCreateCommandAllocator,
    D3D12DeviceCreateCommandList,
    D3D12DeviceCheckFeatureSupport,
    D3D12DeviceCreateDescriptorHeap,
    D3D12DeviceCreateRenderTargetView,
    D3D12DeviceCreateFence,
    D3D12CommandQueueExecuteCommandLists,
    D3D12CommandQueueSignal,
    D3D12DescriptorHeapGetCpuHandleForHeapStart,
    D3D12GraphicsCommandListResourceBarrier,
    D3D12GraphicsCommandListClearRenderTargetView,
    D3D12GraphicsCommandListDrawInstanced,
    D3D12GraphicsCommandListClose,
    D3D12FenceGetCompletedValue,
    D3D11DeviceCreateBuffer,
    D3D11DeviceCreateTexture2D,
    D3D11DeviceCreateShaderResourceView,
    D3D11DeviceCreateRenderTargetView,
    D3D11DeviceCreateDepthStencilView,
    D3D11DeviceCreateBlendState,
    D3D11DeviceCreateDepthStencilState,
    D3D11DeviceCreateRasterizerState,
    D3D11DeviceCreateSamplerState,
    D3D11DeviceCreateInputLayout,
    D3D11DeviceCreateVertexShader,
    D3D11DeviceCreatePixelShader,
    D3D11DeviceCreateComputeShader,
    D3D11DeviceGetImmediateContext,
    D3D11DeviceContextDrawIndexed,
    D3D11DeviceContextDraw,
    D3D11DeviceContextDrawIndexedInstanced,
    D3D11DeviceContextDrawInstanced,
    D3D11DeviceContextVSSetConstantBuffers,
    D3D11DeviceContextPSSetShaderResources,
    D3D11DeviceContextPSSetSamplers,
    D3D11DeviceContextVSSetShader,
    D3D11DeviceContextPSSetShader,
    D3D11DeviceContextCSSetShader,
    D3D11DeviceContextIASetInputLayout,
    D3D11DeviceContextIASetVertexBuffers,
    D3D11DeviceContextIASetIndexBuffer,
    D3D11DeviceContextIASetPrimitiveTopology,
    D3D11DeviceContextOMSetRenderTargets,
    D3D11DeviceContextOMSetBlendState,
    D3D11DeviceContextOMSetDepthStencilState,
    D3D11DeviceContextRSSetState,
    D3D11DeviceContextRSSetViewports,
    D3D11DeviceContextRSSetScissorRects,
    D3D11DeviceContextUpdateSubresource,
    DXGISwapChainGetBuffer,
    DXGISwapChainPresent,
    DXGISwapChainResizeBuffers,
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
    RegisterClassW,
    RegisterClassExW,
    GetClassInfoW,
    GetDlgItem,
    GetClientRect,
    GetWindowRect,
    EnableWindow,
    IsWindowEnabled,
    GetSystemMenu,
    EnableMenuItem,
    SetDlgItemTextW,
    SetClassLongW,
    CreateWindowExW,
    DialogBoxParamW,
    EndDialog,
    CreateDialogParamW,
    ShowWindow,
    GetDC,
    ReleaseDC,
    SetForegroundWindow,
    DestroyWindow,
    InvalidateRect,
    BeginPaint,
    FillRect,
    EndPaint,
    ScreenToClient,
    SetWindowPos,
    GetSysColor,
    LoadCursorW,
    LoadBitmapW,
    CheckDlgButton,
    GetMessagePos,
    IsWindowVisible,
    GetSystemMetrics,
    GetDlgItemTextW,
    IsWindow,
    FindWindowExW,
    CallWindowProcW,
    CreatePopupMenu,
    AppendMenuW,
    TrackPopupMenu,
    PostQuitMessage,
    SetTimer,
    SystemParametersInfoW,
    SendMessageTimeoutW,
    ExitWindowsEx,
    SetWindowTextW,
    GetWindowLongW,
    SetWindowLongW,
    LoadImageW,
    PeekMessageW,
    DispatchMessageW,
    DefWindowProcW,
    SendMessageW,
    GetDeviceCaps,
    SelectObject,
    CreateFontIndirectW,
    DeleteObject,
    SetBkMode,
    SetTextColor,
    DrawTextW,
    MulDiv,
    SetCurrentDirectoryW,
    GetFullPathNameW,
    GetFileAttributesW,
    SetFileAttributesW,
    SetErrorMode,
    GetACP,
    IsValidCodePage,
    GetCPInfo,
    GetStringTypeW,
    LCMapStringW,
    SetDefaultDllDirectories,
    GetSystemDirectoryW,
    GetWindowsDirectoryW,
    GetTempPathW,
    GetTempFileNameW,
    GetModuleFileNameW,
    GetDiskFreeSpaceW,
    GetFileSize,
    FindFirstFileW,
    FindNextFileW,
    FindClose,
    LoadLibraryA,
    LoadLibraryW,
    LoadLibraryExW,
    FreeLibrary,
    InitCommonControls,
    OleInitialize,
    OleUninitialize,
    CoCreateInstance,
    CoTaskMemFree,
    CommandLineToArgvW,
    SHGetFileInfoW,
    SHGetFolderPathW,
    SHGetPathFromIDListW,
    SHGetSpecialFolderLocation,
    ShellLinkQueryInterface,
    ShellLinkAddRef,
    ShellLinkRelease,
    ShellLinkGetPathW,
    ShellLinkGetIDList,
    ShellLinkSetIDList,
    ShellLinkGetDescriptionW,
    ShellLinkSetDescriptionW,
    ShellLinkGetWorkingDirectoryW,
    ShellLinkSetWorkingDirectoryW,
    ShellLinkGetArgumentsW,
    ShellLinkSetArgumentsW,
    ShellLinkGetHotkey,
    ShellLinkSetHotkey,
    ShellLinkGetShowCmd,
    ShellLinkSetShowCmd,
    ShellLinkGetIconLocationW,
    ShellLinkSetIconLocationW,
    ShellLinkSetRelativePath,
    ShellLinkResolve,
    ShellLinkSetPathW,
    ShellLinkPersistGetClassID,
    ShellLinkPersistIsDirty,
    ShellLinkPersistLoad,
    ShellLinkPersistSave,
    ShellLinkPersistSaveCompleted,
    ShellLinkPersistGetCurFile,
    MultiByteToWideChar,
    WideCharToMultiByte,
    LstrcmpiW,
    LstrlenW,
    LstrcpyA,
    LstrcpyW,
    LstrcpynW,
    LstrcatW,
    GetCommandLineA,
    GetCommandLineW,
    GetEnvironmentStringsW,
    FreeEnvironmentStringsW,
    CharNextW,
    CharPrevW,
    CreateDirectoryW,
    RemoveDirectoryW,
    DeleteFileW,
    WritePrivateProfileStringW,
    CreateProcessW,
    CreateEventW,
    SetEvent,
    ResetEvent,
    IsDebuggerPresent,
    InitOnceBeginInitialize,
    InitOnceComplete,
    InitializeSRWLock,
    AcquireSRWLockExclusive,
    ReleaseSRWLockExclusive,
    AcquireSRWLockShared,
    ReleaseSRWLockShared,
    TryAcquireSRWLockExclusive,
    TryAcquireSRWLockShared,
    WaitForSingleObject,
    GetExitCodeProcess,
    GetModuleHandleA,
    GetModuleHandleW,
    GetProcAddress,
    WsprintfW,
    CreateFileW,
    GetSystemTimeAsFileTime,
    CompareFileTime,
    SetFileTime,
    RegCreateKeyExW,
    RegOpenKeyExW,
    RegSetValueExW,
    RegQueryValueExW,
    RegCloseKey,
    SetFilePointer,
    ReadFile,
    WriteFile,
    LocalAlloc,
    GlobalAlloc,
    GlobalLock,
    GlobalUnlock,
    GlobalFree,
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
    GetVersion,
    GetLastError,
    SetLastError,
    GetCurrentThreadId,
    GetCurrentProcessId,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    IsProcessorFeaturePresent,
    GetProcessHeap,
    GetProcessHeaps,
    HeapAlloc,
    HeapFree,
    HeapReAlloc,
    HeapSize,
    GetStartupInfoW,
    InitializeSListHead,
    GetStdHandle,
    GetFileType,
    GetTickCount,
    InitializeCriticalSection,
    InitializeCriticalSectionAndSpinCount,
    LeaveCriticalSection,
    SetUnhandledExceptionFilter,
    Beep,
    Sleep,
    TlsAlloc,
    TlsGetValue,
    TlsSetValue,
    TlsFree,
    VirtualAlloc,
    VirtualProtect,
    VirtualQuery,
    ExitProcess,
    MessageBoxW,
    MessageBoxIndirectW,
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
    DxgiFactory,
    DxgiAdapter,
    D3d11Device,
    D3d11DeviceContext,
    DxgiSwapChain,
    D3d12Device,
    D3d12CommandQueue,
    D3d12CommandAllocator,
    D3d12DescriptorHeap,
    D3d12GraphicsCommandList,
    D3d12Fence,
    D3d12Resource,
    D3d11Buffer,
    D3d11Texture2D,
    D3d11View,
    D3d11InputLayout,
    D3d11Shader,
    D3d11BlendState,
    D3d11RasterizerState,
    D3d11DepthStencilState,
    D3d11SamplerState,
    ShellLinkInterface,
}

#[derive(Debug, Clone, Copy)]
struct GuestObjectMeta {
    kind: GuestObjectKind,
    refcount: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellLinkInterfaceKind {
    ShellLinkW,
    PersistFile,
}

#[derive(Debug, Clone, Copy)]
struct GuestShellLinkInterface {
    state_id: u64,
    kind: ShellLinkInterfaceKind,
}

#[derive(Debug, Clone)]
struct GuestShellLinkState {
    shell_link_object: u64,
    persist_file_object: Option<u64>,
    refcount: u32,
    path: String,
    arguments: String,
    description: String,
    working_directory: String,
    hotkey: u16,
    icon_location: String,
    icon_index: i32,
    show_cmd: i32,
    current_file: Option<String>,
    dirty: bool,
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

#[derive(Debug, Clone, Copy)]
struct GuestDxgiFactory;

#[derive(Debug, Clone, Copy)]
struct GuestDxgiAdapter {
    factory_object: u64,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d12Device;

#[derive(Debug, Clone, Copy)]
struct GuestD3d12CommandQueue {
    device_object: u64,
    queue_id: D3d12CommandQueueId,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d12CommandAllocator {
    device_object: u64,
    allocator_id: D3d12CommandAllocatorId,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d12DescriptorHeap {
    device_object: u64,
    heap_id: D3d12DescriptorHeapId,
    ty: DescriptorHeapType,
    cpu_handle_start: u64,
    descriptor_count: usize,
}

#[derive(Debug, Clone)]
struct GuestD3d12CommandList {
    device_object: u64,
    allocator_object: u64,
    command_list_id: Option<D3d12CommandListId>,
    closed_stream: Option<ImmutableCommandStream>,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d12Fence {
    device_object: u64,
    fence_id: D3d12FenceId,
}

#[derive(Debug, Clone)]
struct GuestD3d12SwapChain {
    device_object: u64,
    swapchain_id: D3d12SwapchainId,
    backbuffer_objects: BTreeMap<u32, u64>,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d12Resource {
    device_object: u64,
    resource_id: D3d12ResourceId,
    format: DxgiFormat,
    swapchain_backbuffer: bool,
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

#[derive(Debug, Clone, Copy)]
struct GuestD3d11BlendState {
    device_object: u64,
    state_id: u64,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11RasterizerState {
    device_object: u64,
    state_id: u64,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11DepthStencilState {
    device_object: u64,
    state_id: u64,
}

#[derive(Debug, Clone, Copy)]
struct GuestD3d11SamplerState {
    device_object: u64,
    state_id: u64,
}

struct PeHostRuntime {
    audio: AudioSubsystem,
    win32: Win32Subsystem,
    user32: User32Subsystem,
    guest_arch: GuestArch,
    live_session: Option<LivePeSession>,
    live_keyboard_device: Option<String>,
    pending_keyboard_replay: Vec<KeyboardReplayEvent>,
    keyboard_replay_device: Option<String>,
    keyboard_replay_injected: bool,
    host_thunks: U64Map<HostThunk>,
    guest_objects: BTreeMap<u64, GuestObjectMeta>,
    shell_link_interfaces: BTreeMap<u64, GuestShellLinkInterface>,
    shell_link_states: BTreeMap<u64, GuestShellLinkState>,
    xaudio_engines: BTreeMap<u64, GuestXAudio2Engine>,
    xaudio_mastering_voices: BTreeMap<u64, GuestXAudio2Voice>,
    xaudio_source_voices: BTreeMap<u64, GuestXAudio2Voice>,
    d3d12_runtime: D3d12Runtime,
    d3d12_guest_root_signature: Option<D3d12RootSignatureId>,
    d3d12_guest_pipeline_state: Option<D3d12PipelineStateId>,
    dxgi_factories: BTreeMap<u64, GuestDxgiFactory>,
    dxgi_adapters: BTreeMap<u64, GuestDxgiAdapter>,
    d3d12_devices: BTreeMap<u64, GuestD3d12Device>,
    d3d12_command_queues: BTreeMap<u64, GuestD3d12CommandQueue>,
    d3d12_command_allocators: BTreeMap<u64, GuestD3d12CommandAllocator>,
    d3d12_descriptor_heaps: BTreeMap<u64, GuestD3d12DescriptorHeap>,
    d3d12_command_lists: BTreeMap<u64, GuestD3d12CommandList>,
    d3d12_fences: BTreeMap<u64, GuestD3d12Fence>,
    d3d12_swapchains: BTreeMap<u64, GuestD3d12SwapChain>,
    d3d12_resources: BTreeMap<u64, GuestD3d12Resource>,
    d3d11_devices: BTreeMap<u64, GuestD3d11Device>,
    d3d11_contexts: BTreeMap<u64, GuestD3d11Context>,
    d3d11_swapchains: BTreeMap<u64, GuestDxgiSwapChain>,
    d3d11_buffers: BTreeMap<u64, GuestD3d11Buffer>,
    d3d11_textures: BTreeMap<u64, GuestD3d11Texture2D>,
    d3d11_views: BTreeMap<u64, GuestD3d11View>,
    d3d11_input_layouts: BTreeMap<u64, GuestD3d11InputLayout>,
    d3d11_shaders: BTreeMap<u64, GuestD3d11Shader>,
    d3d11_blend_states: BTreeMap<u64, GuestD3d11BlendState>,
    d3d11_rasterizer_states: BTreeMap<u64, GuestD3d11RasterizerState>,
    d3d11_depth_stencil_states: BTreeMap<u64, GuestD3d11DepthStencilState>,
    d3d11_sampler_states: BTreeMap<u64, GuestD3d11SamplerState>,
    instruction_cache: U64Map<CachedInstructionEntry>,
    instruction_cache_lru: VecDeque<(u64, u64)>,
    instruction_cache_generation: u64,
    basic_block_cache: U64Map<CachedBlockEntry>,
    basic_block_cache_lru: VecDeque<(u64, u64)>,
    basic_block_cache_generation: u64,
    allowed_trace_categories: Option<BTreeSet<String>>,
    trace_events: Vec<TraceEvent>,
    gfx_frames: Vec<GfxFrame>,
    next_trace_index: u64,
    next_thunk_address: u64,
    next_data_address: u64,
    next_device_context_handle: u64,
    next_gdi_object_handle: u64,
    next_descriptor_handle: u64,
    next_heap_address: u64,
    heap_allocations: BTreeMap<u64, usize>,
    critical_sections: BTreeMap<u64, usize>,
    srw_locks: BTreeMap<u64, i32>,
    signal_handlers: BTreeMap<i32, u64>,
    tls_slots: BTreeMap<u32, u64>,
    tls_vector_ptr: u64,
    init_once_pending: BTreeSet<u64>,
    init_once_completed: BTreeMap<u64, u64>,
    atexit_handlers: Vec<u64>,
    module_handles: BTreeMap<String, u64>,
    module_names_by_handle: BTreeMap<u64, String>,
    device_contexts: BTreeMap<u64, Option<u32>>,
    dialog_procs: BTreeMap<u32, u64>,
    dc_selected_objects: BTreeMap<u64, u64>,
    dc_background_modes: BTreeMap<u64, i32>,
    dc_text_colors: BTreeMap<u64, u32>,
    gdi_objects: BTreeMap<u64, String>,
    recent_wide_writes: BTreeMap<u64, String>,
    error_mode: u32,
    last_error: u32,
    invalid_parameter_handler: u64,
    unhandled_exception_filter: u64,
    mapped_image_base: u64,
    mapped_image_size: u64,
    teb_base: u64,
    peb_base: u64,
    main_module_name: String,
    main_module_path: String,
    main_module_exports: Vec<ExportSymbol>,
    globals: CrtGlobals,
    command_line: String,
    command_line_ansi_ptr: u64,
    command_line_wide_ptr: u64,
    process_environment: BTreeMap<String, String>,
    current_directory: String,
    stdout: String,
    stderr: String,
    steam_401389_recent_blocks: VecDeque<String>,
    steam_401389_first_over_0x1000: Option<String>,
    steam_401389_expected_esi_after_401434: Option<u32>,
    steam_401389_saved_esi_slot_addr: Option<u64>,
    next_frame_index: u32,
    next_audio_buffer_tag: u64,
    published_live_frame: bool,
    dtm: bool,
}

#[derive(Debug)]
struct CachedInstruction {
    bytes: Vec<u8>,
    decoded: DecodedInstruction,
}

#[derive(Debug)]
struct CachedInstructionEntry {
    cached: Arc<CachedInstruction>,
    generation: u64,
}

#[derive(Debug)]
struct CachedBlock {
    bytes: Vec<u8>,
    translated: TranslatedBlock,
    end_rip: u64,
}

#[derive(Debug)]
struct CachedBlockEntry {
    cached: Arc<CachedBlock>,
    generation: u64,
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
    args: &[String],
    ge: &GameEnvironment,
    _cwd: &Path,
    env: &BTreeMap<String, String>,
    dtm: bool,
    test_id: &str,
) -> AppResult<PeExecutionResult> {
    execute_with_options(
        program,
        args,
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
    args: &[String],
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
    let guest_arch = match image.machine {
        0x8664 => GuestArch::X64,
        0x014c => GuestArch::X86,
        _ => {
            return Err(AppError::new(
                ReasonCode::RcPeParseInvalid,
                format!("unsupported PE machine 0x{:04x}", image.machine),
            )
            .with_hint("only x86_64 and x86 PE images are currently executable"));
        }
    };

    let live_mode = options.live_session.is_some();
    let mut runtime = PeHostRuntime::new(
        ge.clone(),
        dtm,
        load_keyboard_replay(env)?,
        options.live_session,
        load_trace_categories(env),
    );
    runtime.set_guest_arch(guest_arch);
    runtime.process_environment = env.clone();
    let staged_program_path = runtime.stage_main_module(program)?;
    runtime.current_directory = initial_guest_current_directory(runtime.win32.ge(), _cwd, &staged_program_path);

    let resolver = ApiSetResolver::new();
    let resolved_imports = resolve_imports_for_runtime(&image, &resolver);
    let image_hash = util::sha256_bytes(&bytes);
    let mapped = pe::map_image(&bytes, &image, &image_hash, dtm)?;
    let mut memory = MemoryImage::default();
    memory.map_bytes(mapped.selected_base, &mapped.memory);
    runtime.set_main_module(&staged_program_path, mapped.selected_base, &image.exports);
    runtime.seed_process_state(
        &mut memory,
        &staged_program_path,
        args,
        mapped.selected_base,
        image.size_of_image as u64,
    )?;
    runtime.initialize_main_thread_tls(&mut memory, &image, mapped.selected_base)?;
    runtime.bind_imports(mapped.selected_base, &mut memory, &resolved_imports)?;

    let config = CpuEngineConfig::from_profile(guest_arch, &ge.config.winver, env!("CARGO_PKG_VERSION"), None)?;
    let mut engine = CpuExecutionEngine::new(config);
    let instruction_budget = pe_runtime_instruction_budget(env, live_mode)?;
    let mut state = CpuState::new(guest_arch);
    let guest_pointer_bytes = guest_arch.pointer_bytes() as u64;
    let stack_bottom = stack_base_for_arch(guest_arch);
    memory.map_bytes(stack_bottom, &vec![0_u8; STACK_SIZE]);
    let stack_top = stack_bottom + STACK_SIZE as u64;
    let rsp = stack_top - guest_pointer_bytes;
    write_guest_pointer(&mut memory, rsp, 0, guest_arch)?;
    state.set(Register::Rsp, rsp);
    if guest_arch == GuestArch::X64 {
        state.segment_bases.gs = runtime.teb_base;
    } else {
        state.segment_bases.fs = runtime.teb_base;
    }
    state.rip = mapped.selected_base + image.address_of_entry_point as u64;

    let mut steps = 0_u64;
    let mut exit_code = 0_i32;
    loop {
        if runtime.host_thunks.contains_key(&state.rip) {
            advance_runtime_steps(
                &mut runtime,
                &mut steps,
                instruction_budget,
                1,
                &memory,
                &state,
                test_id,
            )?;
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
                    advance_runtime_steps(
                        &mut runtime,
                        &mut steps,
                        instruction_budget,
                        1,
                        &memory,
                        &state,
                        test_id,
                    )?;
                    let next_rip = state.rip + 6;
                    let slot_address = if guest_arch == GuestArch::X64 {
                        let displacement = read_i32_from_memory(&memory, state.rip + 2)?;
                        (next_rip as i128 + displacement as i128) as u64
                    } else {
                        read_u32(&memory, state.rip + 2)? as u64
                    };
                    let target = read_guest_pointer(&memory, slot_address, guest_arch)?;

                    if runtime.host_thunks.contains_key(&target) {
                        if memory.read_u8(state.rip + 1)? == 0x15 {
                            let call_rsp = state.get(Register::Rsp).wrapping_sub(guest_pointer_bytes);
                            write_guest_pointer(&mut memory, call_rsp, next_rip, guest_arch)?;
                            state.set(Register::Rsp, call_rsp);
                        }
                        if let Some(code) = runtime.dispatch_import(target, &mut state, &mut memory)? {
                            exit_code = code;
                            break;
                        }
                    } else if memory.read_u8(state.rip + 1)? == 0x15 {
                        let call_rsp = state.get(Register::Rsp).wrapping_sub(guest_pointer_bytes);
                        write_guest_pointer(&mut memory, call_rsp, next_rip, guest_arch)?;
                        state.set(Register::Rsp, call_rsp);
                        state.rip = target;
                    } else {
                        state.rip = target;
                    }
                }
                _ => {}
            },
            _ => {}
        }

        if guest_arch == GuestArch::X86 && state.rip == 0x401390 {
            let record_base = read_guest_u32(&memory, 0x42a270).unwrap_or(0) as u64;
            let current_index = state.get(Register::Rsi) as u32;
            let record_address = record_base + u64::from(current_index) * 0x1c;
            let record_opcode = read_guest_u32(&memory, record_address).unwrap_or(u32::MAX);
            if record_opcode == 0 {
                let previous_index = current_index.saturating_sub(1);
                let previous_record = if record_base != 0 {
                    let previous_address = record_base + u64::from(previous_index) * 0x1c;
                    let fields = (0..7)
                        .map(|slot| {
                            let value = read_guest_u32(&memory, previous_address + slot * 4)
                                .unwrap_or(0) as u64;
                            format!("{slot}:{value:#x}")
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("addr={previous_address:#x} fields=[{fields}]")
                } else {
                    "<unavailable>".to_string()
                };
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "steam 401389 reached zero-filled record at index {current_index:#x} (addr {record_address:#x})"
                    ),
                )
                .with_hint(format!(
                    "steam-401389 zero-record record_base={record_base:#x} previous_index={previous_index:#x} previous_record={previous_record}"
                )));
            }
        }

        if guest_arch == GuestArch::X86 && state.rip == 0x401389 {
            runtime.steam_401389_expected_esi_after_401434 = None;
            runtime.steam_401389_saved_esi_slot_addr = None;
        }
        if guest_arch == GuestArch::X86 && state.rip == 0x4013a8 {
            if let Some(expected_esi) = runtime.steam_401389_expected_esi_after_401434.take() {
                runtime.steam_401389_saved_esi_slot_addr = None;
                let actual_esi = state.get(Register::Rsi) as u32;
                if actual_esi != expected_esi {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam 401434 clobbered callee-saved ESI across return to 0x4013a8: expected {expected_esi:#x}, saw {actual_esi:#x}"
                        ),
                    ));
                }
            }
        }
        let cached_block = decode_basic_block_cached(
            &mut engine,
            &memory,
            &mut runtime.instruction_cache,
            &mut runtime.instruction_cache_lru,
            &mut runtime.instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            &mut runtime.basic_block_cache,
            &mut runtime.basic_block_cache_lru,
            &mut runtime.basic_block_cache_generation,
            BASIC_BLOCK_CACHE_LIMIT,
            state.rip,
        )
        .map_err(|error| annotate_guest_fault(error, &memory, &state))?;
        let block_start_rip = state.rip;
        let esi_before = state.get(Register::Rsi) as u32;
        let contains_steam_4013c0 = cached_block
            .translated
            .decoded
            .iter()
            .any(|instruction| instruction.address == 0x4013c0);
        let contains_steam_4013ba = cached_block
            .translated
            .decoded
            .iter()
            .any(|instruction| instruction.address == 0x4013ba);
        let contains_steam_4013a3 = cached_block
            .translated
            .decoded
            .iter()
            .any(|instruction| instruction.address == 0x4013a3);
        let contains_steam_402a57 = cached_block
            .translated
            .decoded
            .iter()
            .any(|instruction| instruction.address == 0x402a57);
        let watched_esi_slot_before = runtime
            .steam_401389_saved_esi_slot_addr
            .and_then(|address| read_guest_u32(&memory, address).ok().map(|value| (address, value)));
        let touches_steam_401389_helper = guest_arch == GuestArch::X86
            && cached_block
                .translated
                .decoded
                .iter()
                .any(|instruction| (0x401389..=0x4013fc).contains(&instruction.address));
        if guest_arch == GuestArch::X86 && contains_steam_402a57 {
            if let Some(expected_esi) = runtime.steam_401389_expected_esi_after_401434 {
                let saved_esi = read_guest_u32(&memory, state.get(Register::Rbp).wrapping_sub(0x2b8))
                    .unwrap_or(0);
                if saved_esi != expected_esi {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam 401434 corrupted its saved ESI slot before epilogue: expected {expected_esi:#x}, saved slot holds {saved_esi:#x}"
                        ),
                    ));
                }
            }
        }
        if state.rip <= 0x19026bf1 && cached_block.end_rip > 0x19026bf1 {
            let this_ptr = state.get(Register::Rcx) & state.arch.register_mask();
            let first = read_guest_pointer(&memory, this_ptr, guest_arch).unwrap_or(0);
            let second = read_guest_pointer(&memory, first, guest_arch).unwrap_or(0);
            if second != 0 {
                let field_4c = read_u32(&memory, second + 0x4c).unwrap_or(0) as u64;
                if read_u32(&memory, second + 0x48).unwrap_or(0) as u64 == u64::from(DEFAULT_ANSI_CODE_PAGE)
                    && field_4c >= 0x1_0000
                {
                    write_u32(&mut memory, second + 0x48, field_4c as u32);
                }
            }
        }
        let consumed_instructions = cached_block.translated.decoded.len().max(1) as u64;
        advance_runtime_steps(
            &mut runtime,
            &mut steps,
            instruction_budget,
            consumed_instructions,
            &memory,
            &state,
            test_id,
        )?;
        let _ = engine
            .execute_ir_without_memory_hash(&mut state, &mut memory, &cached_block.translated.ir)
            .map_err(|error| {
                let mut wrapped = annotate_guest_fault(error, &memory, &state);
                if !runtime.steam_401389_recent_blocks.is_empty() {
                    wrapped = wrapped.with_hint(format!(
                        "steam-401389 recent-blocks {}",
                        runtime
                            .steam_401389_recent_blocks
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" || ")
                    ));
                }
                if let Some(block) = runtime.steam_401389_first_over_0x1000.as_deref() {
                    wrapped = wrapped.with_hint(format!("steam-401389 first-over-0x1000 {block}"));
                }
                wrapped
            })?;
        if guest_arch == GuestArch::X86
            && runtime.steam_401389_expected_esi_after_401434.is_some()
            && runtime.steam_401389_saved_esi_slot_addr.is_none()
        {
            if let Some(expected_esi) = runtime.steam_401389_expected_esi_after_401434 {
                let candidate = state.get(Register::Rbp).wrapping_sub(0x2b8);
                if read_guest_u32(&memory, candidate).ok() == Some(expected_esi) {
                    runtime.steam_401389_saved_esi_slot_addr = Some(candidate);
                }
            }
        }
        if let Some((watched_address, before_value)) = watched_esi_slot_before {
            if let Ok(after_value) = read_guest_u32(&memory, watched_address) {
                if after_value != before_value {
                    let decoded_addresses = cached_block
                        .translated
                        .decoded
                        .iter()
                        .map(|instruction| format!("{:#x}", instruction.address))
                        .collect::<Vec<_>>()
                        .join(",");
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "steam 401434 overwrote saved ESI slot at {watched_address:#x} from {before_value:#x} to {after_value:#x} while executing block {block_start_rip:#x} addrs=[{decoded_addresses}]"
                        ),
                    ));
                }
            }
        }
        if touches_steam_401389_helper {
            let record_base = read_guest_u32(&memory, 0x42a270).ok().map(u64::from);
            let summarize_record = |index: u32| {
                record_base
                    .map(|base| {
                        let record_address = base + u64::from(index) * 0x1c;
                        let fields = (0..7)
                            .map(|slot| {
                                let value = read_guest_u32(&memory, record_address + slot * 4)
                                    .ok()
                                    .map(u64::from)
                                    .unwrap_or(0);
                                format!("{slot}:{value:#x}")
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        format!("addr={record_address:#x} fields=[{fields}]")
                    })
                    .unwrap_or_else(|| "<unavailable>".to_string())
            };
            let decoded_addresses = cached_block
                .translated
                .decoded
                .iter()
                .map(|instruction| format!("{:#x}", instruction.address))
                .collect::<Vec<_>>()
                .join(",");
            let esi_after = state.get(Register::Rsi) as u32;
            let helper_arg = read_guest_u32(&memory, state.get(Register::Rsp) + 8)
                .ok()
                .map(u64::from)
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<unavailable>".to_string());
            let block_summary = format!(
                "block_start={block_start_rip:#x} addrs=[{decoded_addresses}] esi_before={esi_before:#x} esi_after={esi_after:#x} eax_after={:#x} helper_arg={} before_record={} after_record={}",
                state.get(Register::Rax),
                helper_arg,
                summarize_record(esi_before),
                summarize_record(esi_after),
            );
            if runtime.steam_401389_first_over_0x1000.is_none() && esi_after >= 0x1000 {
                runtime.steam_401389_first_over_0x1000 = Some(block_summary.clone());
            }
            if runtime.steam_401389_recent_blocks.len() == 4 {
                runtime.steam_401389_recent_blocks.pop_front();
            }
            runtime.steam_401389_recent_blocks.push_back(block_summary);
        }
        if guest_arch == GuestArch::X86 && contains_steam_4013a3 {
            runtime.steam_401389_expected_esi_after_401434 = Some(esi_before);
        }
        if guest_arch == GuestArch::X86 && contains_steam_4013c0 {
            let esi_after = state.get(Register::Rsi) as u32;
            if esi_before < 0x1000 && esi_after >= 0x1000 {
                let record_base = read_guest_u32(&memory, 0x42a270).unwrap_or(0) as u64;
                let previous_record = if record_base != 0 {
                    let record_address = record_base + u64::from(esi_before) * 0x1c;
                    let fields = (0..7)
                        .map(|slot| {
                            let value = read_guest_u32(&memory, record_address + slot * 4)
                                .unwrap_or(0) as u64;
                            format!("{slot}:{value:#x}")
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("addr={record_address:#x} fields=[{fields}]")
                } else {
                    "<unavailable>".to_string()
                };
                let current_record = if record_base != 0 {
                    let record_address = record_base + u64::from(esi_after) * 0x1c;
                    let fields = (0..7)
                        .map(|slot| {
                            let value = read_guest_u32(&memory, record_address + slot * 4)
                                .unwrap_or(0) as u64;
                            format!("{slot}:{value:#x}")
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("addr={record_address:#x} fields=[{fields}]")
                } else {
                    "<unavailable>".to_string()
                };
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "steam 401389 transition block {block_start_rip:#x} jumped across 0x1000 from {esi_before:#x} to {esi_after:#x}"
                    ),
                )
                .with_hint(format!(
                    "steam-401389 threshold-jump record_base={record_base:#x} previous_record={previous_record} current_record={current_record}"
                )));
            }
            if esi_after > 0x10000 {
                let record_base = read_guest_u32(&memory, 0x42a270).unwrap_or(0) as u64;
                let previous_record = if record_base != 0 {
                    let record_address = record_base + u64::from(esi_before) * 0x1c;
                    let fields = (0..7)
                        .map(|slot| {
                            let value = read_guest_u32(&memory, record_address + slot * 4)
                                .unwrap_or(0) as u64;
                            format!("{slot}:{value:#x}")
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("addr={record_address:#x} fields=[{fields}]")
                } else {
                    "<unavailable>".to_string()
                };
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "steam 401389 transition block {block_start_rip:#x} jumped from {esi_before:#x} to large index {esi_after:#x}"
                    ),
                )
                .with_hint(format!(
                    "steam-401389 transition record_base={record_base:#x} previous_record={previous_record}"
                )));
            }
        }
        if guest_arch == GuestArch::X86 && contains_steam_4013ba {
            let esi_after = state.get(Register::Rsi) as u32;
            if esi_before < 0x1000 && esi_after >= 0x1000 {
                let record_base = read_guest_u32(&memory, 0x42a270).unwrap_or(0) as u64;
                let current_record = if record_base != 0 {
                    let record_address = record_base + u64::from(esi_after) * 0x1c;
                    let fields = (0..7)
                        .map(|slot| {
                            let value = read_guest_u32(&memory, record_address + slot * 4)
                                .unwrap_or(0) as u64;
                            format!("{slot}:{value:#x}")
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("addr={record_address:#x} fields=[{fields}]")
                } else {
                    "<unavailable>".to_string()
                };
                let previous_record = if record_base != 0 {
                    let record_address = record_base + u64::from(esi_before) * 0x1c;
                    let fields = (0..7)
                        .map(|slot| {
                            let value = read_guest_u32(&memory, record_address + slot * 4)
                                .unwrap_or(0) as u64;
                            format!("{slot}:{value:#x}")
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("addr={record_address:#x} fields=[{fields}]")
                } else {
                    "<unavailable>".to_string()
                };
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!(
                        "steam 401389 linear scan crossed 0x1000 via inc esi from {esi_before:#x} to {esi_after:#x}"
                    ),
                )
                .with_hint(format!(
                    "steam-401389 inc-esi record_base={record_base:#x} previous_record={previous_record} current_record={current_record}"
                )));
            }
        }
        let last_instruction = cached_block
            .translated
            .decoded
            .last()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "translated basic block was empty"))?;
        if last_instruction.opcode == DecodedOpcode::Ret {
            if state.rip == 0 {
                break;
            }
        } else if !instruction_controls_rip(last_instruction.opcode) {
            state.rip = cached_block.end_rip;
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
            guest_arch: GuestArch::X64,
            live_session,
            live_keyboard_device,
            pending_keyboard_replay,
            keyboard_replay_device,
            keyboard_replay_injected: false,
            host_thunks: U64Map::default(),
            guest_objects: BTreeMap::new(),
            shell_link_interfaces: BTreeMap::new(),
            shell_link_states: BTreeMap::new(),
            xaudio_engines: BTreeMap::new(),
            xaudio_mastering_voices: BTreeMap::new(),
            xaudio_source_voices: BTreeMap::new(),
            d3d12_runtime: D3d12Runtime::new(),
            d3d12_guest_root_signature: None,
            d3d12_guest_pipeline_state: None,
            dxgi_factories: BTreeMap::new(),
            dxgi_adapters: BTreeMap::new(),
            d3d12_devices: BTreeMap::new(),
            d3d12_command_queues: BTreeMap::new(),
            d3d12_command_allocators: BTreeMap::new(),
            d3d12_descriptor_heaps: BTreeMap::new(),
            d3d12_command_lists: BTreeMap::new(),
            d3d12_fences: BTreeMap::new(),
            d3d12_swapchains: BTreeMap::new(),
            d3d12_resources: BTreeMap::new(),
            d3d11_devices: BTreeMap::new(),
            d3d11_contexts: BTreeMap::new(),
            d3d11_swapchains: BTreeMap::new(),
            d3d11_buffers: BTreeMap::new(),
            d3d11_textures: BTreeMap::new(),
            d3d11_views: BTreeMap::new(),
            d3d11_input_layouts: BTreeMap::new(),
            d3d11_shaders: BTreeMap::new(),
            d3d11_blend_states: BTreeMap::new(),
            d3d11_rasterizer_states: BTreeMap::new(),
            d3d11_depth_stencil_states: BTreeMap::new(),
            d3d11_sampler_states: BTreeMap::new(),
            instruction_cache: U64Map::default(),
            instruction_cache_lru: VecDeque::new(),
            instruction_cache_generation: 0,
            basic_block_cache: U64Map::default(),
            basic_block_cache_lru: VecDeque::new(),
            basic_block_cache_generation: 0,
            allowed_trace_categories,
            trace_events: Vec::new(),
            gfx_frames: Vec::new(),
            next_trace_index: 2,
            next_thunk_address: THUNK_BASE,
            next_data_address: CRT_DATA_BASE,
            next_device_context_handle: 0x9000,
            next_gdi_object_handle: 0xa000,
            next_descriptor_handle: DESCRIPTOR_HANDLE_BASE,
            next_heap_address: CRT_HEAP_BASE,
            heap_allocations: BTreeMap::new(),
            critical_sections: BTreeMap::new(),
            srw_locks: BTreeMap::new(),
            signal_handlers: BTreeMap::new(),
            tls_slots: BTreeMap::new(),
            tls_vector_ptr: 0,
            init_once_pending: BTreeSet::new(),
            init_once_completed: BTreeMap::new(),
            atexit_handlers: Vec::new(),
            module_handles: BTreeMap::new(),
            module_names_by_handle: BTreeMap::new(),
            device_contexts: BTreeMap::new(),
            dialog_procs: BTreeMap::new(),
            dc_selected_objects: BTreeMap::new(),
            dc_background_modes: BTreeMap::new(),
            dc_text_colors: BTreeMap::new(),
            gdi_objects: BTreeMap::new(),
            recent_wide_writes: BTreeMap::new(),
            error_mode: 0,
            last_error: 0,
            invalid_parameter_handler: 0,
            unhandled_exception_filter: 0,
            mapped_image_base: 0,
            mapped_image_size: 0,
            teb_base: 0,
            peb_base: 0,
            main_module_name: String::new(),
            main_module_path: String::new(),
            main_module_exports: Vec::new(),
            globals: CrtGlobals::default(),
            command_line: String::new(),
            command_line_ansi_ptr: 0,
            command_line_wide_ptr: 0,
            process_environment: BTreeMap::new(),
            current_directory: "C:\\".to_string(),
            stdout: String::new(),
            stderr: String::new(),
            steam_401389_recent_blocks: VecDeque::new(),
            steam_401389_first_over_0x1000: None,
            steam_401389_expected_esi_after_401434: None,
            steam_401389_saved_esi_slot_addr: None,
            next_frame_index: 0,
            next_audio_buffer_tag: 1,
            published_live_frame: false,
            dtm,
        }
    }

    fn set_guest_arch(&mut self, guest_arch: GuestArch) {
        self.guest_arch = guest_arch;
        self.next_thunk_address = thunk_base_for_arch(guest_arch);
        self.next_data_address = data_base_for_arch(guest_arch);
        self.next_heap_address = heap_base_for_arch(guest_arch);
    }

    fn stage_main_module(&mut self, source_program: &Path) -> AppResult<String> {
        let file_name = source_program
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("program.exe");
        let guest_program_path = format!("{}\\{}", self.win32.get_temp_path_w()?, file_name);
        self.win32.stage_host_file_w(source_program, &guest_program_path)?;
        Ok(guest_program_path)
    }

    fn set_main_module(&mut self, guest_program_path: &str, mapped_image_base: u64, exports: &[ExportSymbol]) {
        let main_module_name = normalize_module_name(module_file_name(guest_program_path));
        self.main_module_name = main_module_name.clone();
        self.main_module_path = guest_program_path.to_string();
        self.main_module_exports = exports.to_vec();
        if !main_module_name.is_empty() {
            self.module_handles.insert(main_module_name.clone(), mapped_image_base);
            self.module_names_by_handle.insert(mapped_image_base, main_module_name);
        }
    }

    fn get_or_create_module_handle(&mut self, module_name: &str) -> u64 {
        let normalized = normalize_module_name(module_name);
        if normalized.is_empty() || normalized.ends_with(".exe") {
            return self.mapped_image_base;
        }
        if let Some(&handle) = self.module_handles.get(&normalized) {
            return handle;
        }
        let handle = self.next_data_address;
        self.next_data_address += self.guest_arch.pointer_bytes() as u64;
        self.module_names_by_handle.insert(handle, normalized.clone());
        self.module_handles.insert(normalized, handle);
        handle
    }

    fn resolve_main_module_export(&self, symbol: &ImportSymbol) -> u64 {
        let export = match symbol {
            ImportSymbol::ByName { name, .. } => self
                .main_module_exports
                .iter()
                .find(|export| export.name.as_deref() == Some(name.as_str())),
            ImportSymbol::ByOrdinal { ordinal } => self
                .main_module_exports
                .iter()
                .find(|export| export.ordinal == u32::from(*ordinal)),
        };
        match export.map(|export| &export.target) {
            Some(ExportTarget::Rva(rva)) => self.mapped_image_base + u64::from(*rva),
            _ => 0,
        }
    }

    fn resolve_proc_address(&mut self, module_handle: u64, symbol: ImportSymbol) -> u64 {
        if module_handle == self.mapped_image_base {
            return self.resolve_main_module_export(&symbol);
        }
        let Some(module_name) = self.module_names_by_handle.get(&module_handle).cloned() else {
            return 0;
        };
        let thunk = HostThunk::from_import(&ResolvedImport {
            requested_module: module_name.clone(),
            resolved_module: module_name,
            symbol: symbol.clone(),
            iat_rva: 0,
            export: synthetic_export_symbol(&symbol),
        });
        if matches!(thunk, HostThunk::Unsupported { .. }) {
            return 0;
        }
        let thunk_address = self.next_thunk_address;
        self.next_thunk_address += 0x10;
        self.host_thunks.insert(thunk_address, thunk);
        thunk_address
    }

    fn launch_guest_child_process(
        &mut self,
        application: &str,
        command_line: &str,
        environment: &BTreeMap<String, String>,
        cwd: &str,
        inherit_handles: bool,
    ) -> AppResult<crate::win32::CreateProcessResult> {
        let result = self
            .win32
            .create_process_w(application, command_line, environment, cwd, inherit_handles)?;
        let host_program = self.win32.guest_path_to_host_path(application)?;
        if !host_program.exists() {
            return Err(AppError::new(
                ReasonCode::RcFsNotFound,
                format!("child executable not found: {}", host_program.display()),
            ));
        }
        if !is_pe_image(&host_program)? {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("CreateProcessW only supports PE children: {}", host_program.display()),
            ));
        }

        let host_cwd = self
            .win32
            .guest_path_to_host_path(cwd)
            .ok()
            .or_else(|| host_program.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        let child_test_id = environment
            .get("CASA1_TEST_ID")
            .map(String::as_str)
            .unwrap_or("nested-pe-child");
        let child = execute_with_options(
            &host_program,
            &result.argv.iter().skip(1).cloned().collect::<Vec<_>>(),
            self.win32.ge(),
            &host_cwd,
            environment,
            self.dtm,
            child_test_id,
            PeExecutionOptions::default(),
        )?;
        let exit_code = child.exit_code as u32;
        self.win32.set_process_exit_code(result.process_handle, exit_code)?;
        self.win32.set_thread_exit_code(result.thread_handle, exit_code)?;
        Ok(result)
    }

    fn alloc_utf16_string(&mut self, memory: &mut MemoryImage, value: &str) -> AppResult<u64> {
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        let address = self.alloc_zeroed(memory, bytes.len(), 2)?;
        memory.map_bytes(address, &bytes);
        Ok(address)
    }

    fn shell_special_folder_path(&mut self, raw_csidl: i32) -> AppResult<Option<String>> {
        let Some(path) = shell_special_folder_path(
            &self.win32.ge().config.user_name,
            raw_csidl,
            self.guest_arch,
        ) else {
            return Ok(None);
        };
        self.ensure_guest_directory_path(&path)?;
        Ok(Some(path))
    }

    fn ensure_guest_directory_path(&mut self, path: &str) -> AppResult<()> {
        if self.win32.get_file_attributes_w(path).is_ok() {
            return Ok(());
        }
        let Some(drive_prefix) = windows_drive_prefix(path) else {
            return Err(AppError::new(
                ReasonCode::RcFsPathInvalid,
                format!("{} is missing a drive prefix", path),
            ));
        };
        let mut current = format!("{}\\", drive_prefix);
        let suffix = &path[drive_prefix.len()..];
        for component in suffix
            .trim_start_matches(['\\', '/'])
            .split(['\\', '/'])
            .filter(|component| !component.is_empty())
        {
            if !current.ends_with('\\') {
                current.push('\\');
            }
            current.push_str(component);
            if self.win32.get_file_attributes_w(&current).is_err() {
                match self.win32.sync_existing_path_w(&current) {
                    Ok(()) => {}
                    Err(error) if error.code == ReasonCode::RcFsNotFound => {
                        match self.win32.create_directory_w(&current) {
                            Ok(_) => {}
                            Err(create_error) if create_error.code == ReasonCode::RcFsAlreadyExists => {
                                self.win32.sync_existing_path_w(&current)?;
                            }
                            Err(create_error) => return Err(create_error),
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn alloc_utf16_environment_block(
        &mut self,
        memory: &mut MemoryImage,
        environment: &BTreeMap<String, String>,
    ) -> AppResult<u64> {
        let mut bytes = Vec::new();
        for (key, value) in environment {
            for unit in format!("{key}={value}").encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&0_u16.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());

        let address = self.alloc_heap(memory, bytes.len().max(2), false)?;
        memory.map_bytes(address, &bytes);
        Ok(address)
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
                LiveInputEvent::KeyUp {
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
                    self.user32.inject_keyboard_input_up(
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
                            ("pressed".to_string(), json!(false)),
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
        guest_program_path: &str,
        args: &[String],
        mapped_image_base: u64,
        mapped_image_size: u64,
    ) -> AppResult<()> {
        self.mapped_image_base = mapped_image_base;
        self.mapped_image_size = mapped_image_size;
        self.win32.ensure_default_locale_registry()?;
        self.command_line = build_windows_command_line(guest_program_path, args);
        self.command_line_ansi_ptr = 0;
        self.command_line_wide_ptr = 0;

        let mut argv_values = Vec::with_capacity(args.len() + 2);
        argv_values.push(self.alloc_c_string(memory, guest_program_path)?);
        for arg in args {
            argv_values.push(self.alloc_c_string(memory, arg)?);
        }
        argv_values.push(0);
        let argv_array = self.alloc_pointer_array(memory, &argv_values)?;
        let argv_ptr_ptr = self.alloc_pointer(memory, argv_array)?;
        let argc_ptr = self.alloc_u32(memory, (args.len() + 1) as u32)?;
        let environ_array = self.alloc_pointer_array(memory, &[0])?;
        let environ_ptr_ptr = self.alloc_pointer(memory, environ_array)?;
        let commode_ptr = self.alloc_u32(memory, 0)?;
        let fmode_ptr = self.alloc_u32(memory, 0)?;
        let startup_owner = self.alloc_zeroed(memory, 0x20, 16)?;
        let peb_base = self.alloc_zeroed(memory, 0x100, 16)?;
        let teb_base = self.alloc_zeroed(memory, 0x100, 16)?;
        write_guest_pointer(memory, teb_base + 0x30, peb_base, self.guest_arch)?;
        write_guest_pointer(memory, peb_base + 0x08, startup_owner, self.guest_arch)?;
        if self.guest_arch == GuestArch::X86 {
            let tls_vector_ptr = self.alloc_zeroed(memory, 4096 * self.guest_arch.pointer_bytes(), 16)?;
            let static_tls_block = self.alloc_zeroed(memory, 0x2000, 16)?;
            write_guest_pointer(memory, teb_base + 0x2c, tls_vector_ptr, self.guest_arch)?;
            write_guest_pointer(memory, tls_vector_ptr, static_tls_block, self.guest_arch)?;
            self.tls_slots.insert(0, static_tls_block);
            self.tls_vector_ptr = tls_vector_ptr;
        } else {
            self.tls_vector_ptr = 0;
        }

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

    fn initialize_main_thread_tls(
        &mut self,
        memory: &mut MemoryImage,
        image: &pe::ParsedPe,
        mapped_image_base: u64,
    ) -> AppResult<()> {
        if self.guest_arch != GuestArch::X86 || self.tls_vector_ptr == 0 {
            return Ok(());
        }
        let Some(tls_directory) = image.tls_directory.as_ref() else {
            return Ok(());
        };

        let raw_data_size = tls_directory
            .raw_data_end
            .saturating_sub(tls_directory.raw_data_start) as usize;
        let raw_data = if raw_data_size == 0 {
            Vec::new()
        } else {
            let raw_data_base = mapped_image_base
                .wrapping_add(tls_directory.raw_data_start.saturating_sub(image.image_base));
            read_window(memory, raw_data_base, raw_data_size)?
        };

        let slot_zero_block = self.alloc_zeroed(memory, raw_data.len().max(0x2000), 16)?;
        if !raw_data.is_empty() {
            memory.map_bytes(slot_zero_block, &raw_data);
        }
        self.tls_slots.insert(0, slot_zero_block);
        self.sync_guest_tls_slot(memory, 0, slot_zero_block)?;

        let index_address = mapped_image_base
            .wrapping_add(tls_directory.address_of_index.saturating_sub(image.image_base));
        write_u32(memory, index_address, 0);
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
            write_guest_pointer(memory, slot_va, thunk_address, self.guest_arch)?;
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
        let thunk_name = format!("{thunk:?}");
        let callee_saved_before = if self.guest_arch == GuestArch::X86 {
            Some((
                state.get(Register::Rbx),
                state.get(Register::Rsi),
                state.get(Register::Rdi),
                state.get(Register::Rbp),
            ))
        } else {
            None
        };
        let return_address = read_guest_pointer(memory, state.get(Register::Rsp), self.guest_arch)?;
        state.set(
            Register::Rsp,
            state.get(Register::Rsp).wrapping_add(self.guest_arch.pointer_bytes() as u64),
        );

        match thunk {
            HostThunk::CreateDXGIFactory1 => {
                let out_ptr = state.get(Register::Rdx);
                if out_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let factory_object = self.alloc_dxgi_factory_object(memory)?;
                    write_u64(memory, out_ptr, factory_object);
                    let adapter_name = self.d3d12_runtime.device_info().adapter.name;
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "dxgi",
                        "CreateDXGIFactory1",
                        BTreeMap::from([("adapter".to_string(), json!(adapter_name))]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::CreateDXGIFactory2 => {
                let flags = state.get(Register::Rcx) as u32;
                let out_ptr = state.get(Register::R8);
                if out_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let factory_object = self.alloc_dxgi_factory_object(memory)?;
                    write_u64(memory, out_ptr, factory_object);
                    let adapter_name = self.d3d12_runtime.device_info().adapter.name;
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "dxgi",
                        "CreateDXGIFactory2",
                        BTreeMap::from([
                            ("adapter".to_string(), json!(adapter_name)),
                            ("flags".to_string(), json!(flags)),
                        ]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::DXGIFactoryEnumAdapters => {
                self.dispatch_dxgi_factory_enum_adapters(memory, state, false)?;
            }
            HostThunk::DXGIFactoryEnumAdapters1 => {
                self.dispatch_dxgi_factory_enum_adapters(memory, state, true)?;
            }
            HostThunk::DXGIAdapterGetDesc => {
                self.dispatch_dxgi_adapter_get_desc(memory, state, false)?;
            }
            HostThunk::DXGIAdapterGetDesc1 => {
                self.dispatch_dxgi_adapter_get_desc(memory, state, true)?;
            }
            HostThunk::DXGIFactoryCreateSwapChain => {
                self.dispatch_dxgi_create_swapchain(memory, state)?;
            }
            HostThunk::DXGIFactoryCreateSwapChainForHwnd => {
                self.dispatch_dxgi_create_swapchain_for_hwnd(memory, state)?;
            }
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
            HostThunk::D3D12CreateDevice => {
                let adapter_object = state.get(Register::Rcx);
                let minimum_feature_level = state.get(Register::Rdx) as u32;
                let out_ptr = state.get(Register::R9);
                let device_info = self.d3d12_runtime.device_info();
                let max_feature_level = supported_d3d12_feature_level(&device_info);
                let adapter_ok = if adapter_object == 0 {
                    true
                } else {
                    matches!(self.guest_object_kind(adapter_object), Ok(GuestObjectKind::DxgiAdapter))
                };
                if out_ptr == 0 || !adapter_ok || (minimum_feature_level != 0 && minimum_feature_level > max_feature_level) {
                    state.set(Register::Rax, E_INVALIDARG);
                } else {
                    let device_object = self.alloc_d3d12_device_object(memory)?;
                    write_u64(memory, out_ptr, device_object);
                    state.set(Register::Rax, 0);
                    self.push_trace(
                        "d3d12",
                        "D3D12CreateDevice",
                        BTreeMap::from([
                            ("adapter".to_string(), json!(device_info.adapter.name)),
                            (
                                "minimum_feature_level".to_string(),
                                json!(format!("0x{minimum_feature_level:04x}")),
                            ),
                            (
                                "max_feature_level".to_string(),
                                json!(format!("0x{max_feature_level:04x}")),
                            ),
                            ("unified_memory".to_string(), json!(device_info.features.unified_memory)),
                        ]),
                        json!(0),
                    );
                }
                self.last_error = 0;
            }
            HostThunk::D3D12DeviceCreateCommandQueue => {
                self.dispatch_d3d12_create_command_queue(memory, state)?;
            }
            HostThunk::D3D12DeviceCreateCommandAllocator => {
                self.dispatch_d3d12_create_command_allocator(memory, state)?;
            }
            HostThunk::D3D12DeviceCreateCommandList => {
                self.dispatch_d3d12_create_command_list(memory, state)?;
            }
            HostThunk::D3D12DeviceCheckFeatureSupport => {
                self.dispatch_d3d12_check_feature_support(memory, state)?;
            }
            HostThunk::D3D12DeviceCreateDescriptorHeap => {
                self.dispatch_d3d12_create_descriptor_heap(memory, state)?;
            }
            HostThunk::D3D12DeviceCreateRenderTargetView => {
                self.dispatch_d3d12_create_render_target_view(state)?;
            }
            HostThunk::D3D12DeviceCreateFence => {
                self.dispatch_d3d12_create_fence(memory, state)?;
            }
            HostThunk::D3D12CommandQueueExecuteCommandLists => {
                self.dispatch_d3d12_command_queue_execute_command_lists(memory, state)?;
            }
            HostThunk::D3D12CommandQueueSignal => {
                self.dispatch_d3d12_command_queue_signal(state)?;
            }
            HostThunk::D3D12DescriptorHeapGetCpuHandleForHeapStart => {
                self.dispatch_d3d12_descriptor_heap_get_cpu_handle_for_heap_start(state)?;
            }
            HostThunk::D3D12GraphicsCommandListResourceBarrier => {
                self.dispatch_d3d12_graphics_command_list_resource_barrier(memory, state)?;
            }
            HostThunk::D3D12GraphicsCommandListClearRenderTargetView => {
                self.dispatch_d3d12_graphics_command_list_clear_render_target_view(memory, state)?;
            }
            HostThunk::D3D12GraphicsCommandListDrawInstanced => {
                self.dispatch_d3d12_graphics_command_list_draw_instanced(memory, state)?;
            }
            HostThunk::D3D12GraphicsCommandListClose => {
                self.dispatch_d3d12_graphics_command_list_close(state)?;
            }
            HostThunk::D3D12FenceGetCompletedValue => {
                self.dispatch_d3d12_fence_get_completed_value(state)?;
            }
            HostThunk::D3D11DeviceCreateBuffer => {
                self.dispatch_d3d11_create_buffer(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateTexture2D => {
                self.dispatch_d3d11_create_texture2d(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateShaderResourceView => {
                self.dispatch_d3d11_create_shader_resource_view(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateRenderTargetView => {
                self.dispatch_d3d11_create_render_target_view(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateDepthStencilView => {
                self.dispatch_d3d11_create_depth_stencil_view(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateBlendState => {
                self.dispatch_d3d11_create_blend_state(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateDepthStencilState => {
                self.dispatch_d3d11_create_depth_stencil_state(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateRasterizerState => {
                self.dispatch_d3d11_create_rasterizer_state(memory, state)?;
            }
            HostThunk::D3D11DeviceCreateSamplerState => {
                self.dispatch_d3d11_create_sampler_state(memory, state)?;
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
            HostThunk::D3D11DeviceContextDrawIndexed => {
                self.dispatch_d3d11_draw_indexed(state)?;
            }
            HostThunk::D3D11DeviceContextDraw => {
                self.dispatch_d3d11_draw(state)?;
            }
            HostThunk::D3D11DeviceContextDrawIndexedInstanced => {
                self.dispatch_d3d11_draw_indexed_instanced(memory, state)?;
            }
            HostThunk::D3D11DeviceContextDrawInstanced => {
                self.dispatch_d3d11_draw_instanced(memory, state)?;
            }
            HostThunk::D3D11DeviceContextVSSetConstantBuffers => {
                self.dispatch_d3d11_vs_set_constant_buffers(memory, state)?;
            }
            HostThunk::D3D11DeviceContextPSSetShaderResources => {
                self.dispatch_d3d11_ps_set_shader_resources(memory, state)?;
            }
            HostThunk::D3D11DeviceContextPSSetSamplers => {
                self.dispatch_d3d11_ps_set_samplers(memory, state)?;
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
            HostThunk::D3D11DeviceContextIASetVertexBuffers => {
                self.dispatch_d3d11_ia_set_vertex_buffers(memory, state)?;
            }
            HostThunk::D3D11DeviceContextIASetIndexBuffer => {
                self.dispatch_d3d11_ia_set_index_buffer(state)?;
            }
            HostThunk::D3D11DeviceContextIASetPrimitiveTopology => {
                self.dispatch_d3d11_ia_set_primitive_topology(state)?;
            }
            HostThunk::D3D11DeviceContextOMSetRenderTargets => {
                self.dispatch_d3d11_om_set_render_targets(memory, state)?;
            }
            HostThunk::D3D11DeviceContextOMSetBlendState => {
                self.dispatch_d3d11_om_set_blend_state(state)?;
            }
            HostThunk::D3D11DeviceContextOMSetDepthStencilState => {
                self.dispatch_d3d11_om_set_depth_stencil_state(state)?;
            }
            HostThunk::D3D11DeviceContextRSSetState => {
                self.dispatch_d3d11_rs_set_state(state)?;
            }
            HostThunk::D3D11DeviceContextRSSetViewports => {
                self.dispatch_d3d11_rs_set_viewports(memory, state)?;
            }
            HostThunk::D3D11DeviceContextRSSetScissorRects => {
                self.dispatch_d3d11_rs_set_scissor_rects(memory, state)?;
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
                self.dispatch_dxgi_swapchain_get_buffer(memory, state)?;
            }
            HostThunk::DXGISwapChainPresent => {
                self.dispatch_dxgi_swapchain_present(state)?;
            }
            HostThunk::DXGISwapChainResizeBuffers => {
                self.dispatch_dxgi_swapchain_resize_buffers(memory, state)?;
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
                let object = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, self.add_ref_guest_object(object)? as u64);
                self.last_error = 0;
            }
            HostThunk::GuestObjectRelease => {
                let object = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, self.release_guest_object(object)? as u64);
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
            HostThunk::RegisterClassW => {
                let class = guest_call_arg(state, memory, 0)?;
                let guest_class = read_guest_window_class(memory, class, self.guest_arch, false)?;
                let class_name = read_utf16_string(memory, guest_class.class_name_ptr)?;
                let atom = self.user32.register_class_info(
                    &class_name,
                    WindowClassInfo {
                        style: guest_class.style,
                        wnd_proc: guest_class.wnd_proc,
                        cls_extra: guest_class.cls_extra,
                        wnd_extra: guest_class.wnd_extra,
                        instance: guest_class.instance,
                        icon: guest_class.icon,
                        cursor: guest_class.cursor,
                        background: guest_class.background,
                        menu_name: guest_class.menu_name,
                        class_name_ptr: guest_class.class_name_ptr,
                    },
                );
                state.set(Register::Rax, atom as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "RegisterClassW",
                    BTreeMap::from([
                        ("class_name".to_string(), json!(class_name)),
                        ("wnd_proc".to_string(), json!(format!("{:#x}", guest_class.wnd_proc))),
                    ]),
                    json!(atom),
                );
            }
            HostThunk::RegisterClassExW => {
                let class = guest_call_arg(state, memory, 0)?;
                let guest_class = read_guest_window_class(memory, class, self.guest_arch, true)?;
                let class_name = read_utf16_string(memory, guest_class.class_name_ptr)?;
                let atom = self.user32.register_class_info(
                    &class_name,
                    WindowClassInfo {
                        style: guest_class.style,
                        wnd_proc: guest_class.wnd_proc,
                        cls_extra: guest_class.cls_extra,
                        wnd_extra: guest_class.wnd_extra,
                        instance: guest_class.instance,
                        icon: guest_class.icon,
                        cursor: guest_class.cursor,
                        background: guest_class.background,
                        menu_name: guest_class.menu_name,
                        class_name_ptr: guest_class.class_name_ptr,
                    },
                );
                state.set(Register::Rax, atom as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "RegisterClassExW",
                    BTreeMap::from([
                        ("class_name".to_string(), json!(class_name)),
                        ("wnd_proc".to_string(), json!(format!("{:#x}", guest_class.wnd_proc))),
                    ]),
                    json!(atom),
                );
            }
            HostThunk::GetClassInfoW => {
                let instance = guest_call_arg(state, memory, 0)?;
                let class_name_ptr = guest_call_arg(state, memory, 1)?;
                let class_info_ptr = guest_call_arg(state, memory, 2)?;
                let class_name = if class_name_ptr == 0 {
                    String::new()
                } else if class_name_ptr >> 16 == 0 {
                    format!("#{}", class_name_ptr & 0xffff)
                } else {
                    read_utf16_string(memory, class_name_ptr)?
                };
                let found = self.user32.ensure_class_available(&class_name).is_some();
                if found && class_info_ptr != 0 {
                    let class_info = self.user32.class_info(&class_name).unwrap_or(WindowClassInfo {
                        style: 0,
                        wnd_proc: 0,
                        cls_extra: 0,
                        wnd_extra: 0,
                        instance: 0,
                        icon: 0,
                        cursor: 0,
                        background: 0,
                        menu_name: 0,
                        class_name_ptr,
                    });
                    write_guest_window_class(memory, class_info_ptr, self.guest_arch, class_info)?;
                }
                state.set(Register::Rax, u64::from(found));
                self.last_error = if found { 0 } else { ERROR_CLASS_DOES_NOT_EXIST };
                self.push_trace(
                    "input",
                    "GetClassInfoW",
                    BTreeMap::from([
                        ("instance".to_string(), json!(instance)),
                        ("class_name".to_string(), json!(class_name)),
                    ]),
                    json!(found),
                );
            }
            HostThunk::GetDlgItem => {
                let parent = guest_call_arg(state, memory, 0)? as u32;
                let item_id = guest_call_arg(state, memory, 1)? as i32;
                let hwnd = self.user32.get_dlg_item(parent, item_id)?.unwrap_or(0);
                state.set(Register::Rax, hwnd as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "GetDlgItem",
                    BTreeMap::from([
                        ("parent".to_string(), json!(parent)),
                        ("item_id".to_string(), json!(item_id)),
                    ]),
                    json!(hwnd),
                );
            }
            HostThunk::GetClientRect | HostThunk::GetWindowRect => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let rect_ptr = guest_call_arg(state, memory, 1)?;
                if rect_ptr == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    match self.user32.window_state(hwnd) {
                        Ok(window) => {
                            let left = 0_i32;
                            let top = 0_i32;
                            let right = window.width as i32;
                            let bottom = window.height as i32;
                            memory.map_bytes(rect_ptr, &left.to_le_bytes());
                            memory.map_bytes(rect_ptr + 4, &top.to_le_bytes());
                            memory.map_bytes(rect_ptr + 8, &right.to_le_bytes());
                            memory.map_bytes(rect_ptr + 12, &bottom.to_le_bytes());
                            state.set(Register::Rax, 1);
                            self.last_error = 0;
                            self.push_trace(
                                "input",
                                match thunk {
                                    HostThunk::GetClientRect => "GetClientRect",
                                    _ => "GetWindowRect",
                                },
                                BTreeMap::from([
                                    ("hwnd".to_string(), json!(hwnd)),
                                    ("left".to_string(), json!(left)),
                                    ("top".to_string(), json!(top)),
                                    ("right".to_string(), json!(right)),
                                    ("bottom".to_string(), json!(bottom)),
                                ]),
                                json!(1),
                            );
                        }
                        Err(_) => {
                            state.set(Register::Rax, 0);
                            self.last_error = ERROR_INVALID_WINDOW_HANDLE;
                        }
                    }
                }
            }
            HostThunk::SetDlgItemTextW => {
                let parent = guest_call_arg(state, memory, 0)? as u32;
                let item_id = guest_call_arg(state, memory, 1)? as i32;
                let text_ptr = guest_call_arg(state, memory, 2)?;
                let text = if text_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, text_ptr)?
                };
                let hwnd = self.user32.get_dlg_item(parent, item_id)?.unwrap_or(0);
                let changed = hwnd != 0 && self.user32.set_window_text_w(hwnd, &text);
                state.set(Register::Rax, u64::from(changed));
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SetDlgItemTextW",
                    BTreeMap::from([
                        ("parent".to_string(), json!(parent)),
                        ("item_id".to_string(), json!(item_id)),
                        ("text".to_string(), json!(text)),
                    ]),
                    json!(changed),
                );
            }
            HostThunk::SetClassLongW => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let index = guest_call_arg(state, memory, 1)? as i32;
                let new_long = guest_call_arg(state, memory, 2)? as u32;
                let existed = self.user32.has_window(hwnd);
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SetClassLongW",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("index".to_string(), json!(index)),
                        ("value".to_string(), json!(new_long)),
                    ]),
                    json!(existed),
                );
            }
            HostThunk::CreateWindowExW => {
                let class_name = read_utf16_string(memory, guest_call_arg(state, memory, 1)?)?;
                let title_ptr = guest_call_arg(state, memory, 2)?;
                let title = if title_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, title_ptr)?
                };
                let style = guest_call_arg_u32(state, memory, 3)?;
                let width = guest_call_arg(state, memory, 6)? as u32;
                let height = guest_call_arg(state, memory, 7)? as u32;
                let parent = guest_call_arg(state, memory, 8)? as u32;
                let hwnd = self.user32.create_window_ex_w(
                    &class_name,
                    &title,
                    width.max(1),
                    height.max(1),
                    style & 0x1000_0000 != 0,
                    false,
                    (parent != 0).then_some(parent),
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
            HostThunk::DialogBoxParamW => {
                let template_name_ptr = guest_call_arg(state, memory, 1)?;
                let parent = guest_call_arg(state, memory, 2)? as u32;
                let dialog_proc = guest_call_arg(state, memory, 3)?;
                let init_param = guest_call_arg(state, memory, 4)?;
                let template_name = if template_name_ptr >> 16 == 0 {
                    format!("resource#{}", template_name_ptr & 0xffff)
                } else {
                    read_utf16_string(memory, template_name_ptr)?
                };
                self.user32.register_class_ex_w("#32770");
                let hwnd = self.user32.create_window_ex_w(
                    "#32770",
                    &template_name,
                    1,
                    1,
                    false,
                    false,
                    (parent != 0).then_some(parent),
                    1,
                )?;
                if dialog_proc != 0 {
                    self.dialog_procs.insert(hwnd, dialog_proc);
                }
                let init_dialog_result = if dialog_proc == 0 {
                    0_i64
                } else {
                    self.execute_guest_callback(
                        state,
                        memory,
                        dialog_proc,
                        &[hwnd as u64, 0x110, 0, init_param],
                        "DialogBoxParamW::WM_INITDIALOG",
                    )? as i64
                };
                let dialog_result = if let Some(dialog_result) = self.user32.take_dialog_result(hwnd) {
                    dialog_result
                } else {
                    if self.user32.has_window(hwnd) {
                        let _ = self.user32.show_window(hwnd, 5)?;
                    }
                    self.run_modal_dialog_loop(state, memory, hwnd)?
                        .unwrap_or(init_dialog_result)
                };
                state.set(Register::Rax, dialog_result as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "DialogBoxParamW",
                    BTreeMap::from([
                        ("template".to_string(), json!(template_name)),
                        ("dialog_proc".to_string(), json!(format!("{dialog_proc:#x}"))),
                    ]),
                    json!(dialog_result),
                );
                self.inject_keyboard_replay_if_needed(hwnd)?;
                self.poll_live_input()?;
            }
            HostThunk::CreateDialogParamW => {
                let template_name_ptr = guest_call_arg(state, memory, 1)?;
                let parent = guest_call_arg(state, memory, 2)? as u32;
                let dialog_proc = guest_call_arg(state, memory, 3)?;
                let init_param = guest_call_arg(state, memory, 4)?;
                let template_name = if template_name_ptr >> 16 == 0 {
                    format!("resource#{}", template_name_ptr & 0xffff)
                } else {
                    read_utf16_string(memory, template_name_ptr)?
                };
                self.user32.register_class_ex_w("#32770");
                let hwnd = self.user32.create_window_ex_w(
                    "#32770",
                    &template_name,
                    1,
                    1,
                    false,
                    false,
                    (parent != 0).then_some(parent),
                    1,
                )?;
                if dialog_proc != 0 {
                    self.dialog_procs.insert(hwnd, dialog_proc);
                    let _ = self.execute_guest_callback(
                        state,
                        memory,
                        dialog_proc,
                        &[hwnd as u64, 0x110, 0, init_param],
                        "CreateDialogParamW::WM_INITDIALOG",
                    )?;
                }
                state.set(Register::Rax, hwnd as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "CreateDialogParamW",
                    BTreeMap::from([
                        ("template".to_string(), json!(template_name)),
                        ("dialog_proc".to_string(), json!(format!("{dialog_proc:#x}"))),
                    ]),
                    json!(hwnd),
                );
                self.inject_keyboard_replay_if_needed(hwnd)?;
                self.poll_live_input()?;
            }
            HostThunk::ShowWindow => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let command = guest_call_arg(state, memory, 1)? as i32;
                let existed = self.user32.has_window(hwnd);
                let was_visible = self.user32.show_window(hwnd, command)?;
                state.set(Register::Rax, u64::from(was_visible));
                self.last_error = if existed { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "ShowWindow",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("command".to_string(), json!(command)),
                    ]),
                    json!(was_visible),
                );
            }
            HostThunk::EnableWindow => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let enabled = guest_call_arg(state, memory, 1)? != 0;
                if self.user32.has_window(hwnd) {
                    let was_enabled = self.user32.enable_window(hwnd, enabled)?;
                    state.set(Register::Rax, u64::from(was_enabled));
                    self.last_error = 0;
                    self.push_trace(
                        "input",
                        "EnableWindow",
                        BTreeMap::from([
                            ("hwnd".to_string(), json!(hwnd)),
                            ("enabled".to_string(), json!(enabled)),
                        ]),
                        json!(was_enabled),
                    );
                } else {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_WINDOW_HANDLE;
                }
            }
            HostThunk::IsWindowEnabled => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let enabled = self.user32.is_window_enabled(hwnd);
                state.set(Register::Rax, u64::from(enabled));
                self.last_error = if enabled || self.user32.has_window(hwnd) {
                    0
                } else {
                    ERROR_INVALID_WINDOW_HANDLE
                };
                self.push_trace(
                    "input",
                    "IsWindowEnabled",
                    BTreeMap::from([("hwnd".to_string(), json!(hwnd))]),
                    json!(enabled),
                );
            }
            HostThunk::GetSystemMenu => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let revert = guest_call_arg(state, memory, 1)? != 0;
                let menu = if self.user32.has_window(hwnd) && !revert {
                    0x8000_u64 | u64::from(hwnd)
                } else {
                    0
                };
                state.set(Register::Rax, menu);
                self.last_error = if menu != 0 || (revert && self.user32.has_window(hwnd)) {
                    0
                } else {
                    ERROR_INVALID_WINDOW_HANDLE
                };
                self.push_trace(
                    "input",
                    "GetSystemMenu",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("revert".to_string(), json!(revert)),
                    ]),
                    json!(menu),
                );
            }
            HostThunk::EnableMenuItem => {
                let menu = guest_call_arg(state, memory, 0)?;
                let item = guest_call_arg(state, memory, 1)? as u32;
                let flags = guest_call_arg(state, memory, 2)? as u32;
                let previous = if menu == 0 { u32::MAX } else { 0 };
                state.set(Register::Rax, u64::from(previous));
                self.last_error = if menu == 0 { ERROR_INVALID_WINDOW_HANDLE } else { 0 };
                self.push_trace(
                    "input",
                    "EnableMenuItem",
                    BTreeMap::from([
                        ("menu".to_string(), json!(menu)),
                        ("item".to_string(), json!(item)),
                        ("flags".to_string(), json!(flags)),
                    ]),
                    json!(previous),
                );
            }
            HostThunk::GetDC => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let valid = hwnd == 0 || self.user32.has_window(hwnd);
                let hdc = if valid {
                    let hdc = self.next_device_context_handle;
                    self.next_device_context_handle = self.next_device_context_handle.wrapping_add(4);
                    self.device_contexts.insert(hdc, (hwnd != 0).then_some(hwnd));
                    hdc
                } else {
                    0
                };
                state.set(Register::Rax, hdc);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "GetDC",
                    BTreeMap::from([("hwnd".to_string(), json!(hwnd))]),
                    json!(hdc),
                );
            }
            HostThunk::EndDialog => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let result = guest_call_arg(state, memory, 1)? as i64;
                let ended = self.user32.end_dialog(hwnd, result)?;
                if ended {
                    self.dialog_procs.remove(&hwnd);
                }
                state.set(Register::Rax, u64::from(ended));
                self.last_error = if ended { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "EndDialog",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("result".to_string(), json!(result)),
                    ]),
                    json!(ended),
                );
            }
            HostThunk::ReleaseDC => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let hdc = guest_call_arg(state, memory, 1)?;
                let released = self.device_contexts.remove(&hdc).is_some();
                state.set(Register::Rax, u64::from(released));
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "ReleaseDC",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("hdc".to_string(), json!(hdc)),
                    ]),
                    json!(released),
                );
            }
            HostThunk::SetForegroundWindow => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let updated = if self.user32.has_window(hwnd) {
                    self.user32.set_foreground_window(hwnd)?;
                    true
                } else {
                    false
                };
                state.set(Register::Rax, u64::from(updated));
                self.last_error = if updated { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "SetForegroundWindow",
                    BTreeMap::from([("hwnd".to_string(), json!(hwnd))]),
                    json!(updated),
                );
            }
            HostThunk::DestroyWindow => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let destroyed = self.user32.destroy_window(hwnd)?;
                 if destroyed {
                    self.dialog_procs.remove(&hwnd);
                }
                state.set(Register::Rax, u64::from(destroyed));
                self.last_error = if destroyed { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "DestroyWindow",
                    BTreeMap::from([("hwnd".to_string(), json!(hwnd))]),
                    json!(destroyed),
                );
            }
            HostThunk::InvalidateRect => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let rect_ptr = guest_call_arg(state, memory, 1)?;
                let erase = guest_call_arg(state, memory, 2)? != 0;
                let invalidated = hwnd == 0 || self.user32.has_window(hwnd);
                state.set(Register::Rax, u64::from(invalidated));
                self.last_error = if invalidated { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "InvalidateRect",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("rect_ptr".to_string(), json!(format!("{rect_ptr:#x}"))),
                        ("erase".to_string(), json!(erase)),
                    ]),
                    json!(invalidated),
                );
            }
            HostThunk::BeginPaint => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let paint_ptr = guest_call_arg(state, memory, 1)?;
                let hdc = if paint_ptr != 0 && self.user32.has_window(hwnd) {
                    let hdc = self.next_device_context_handle;
                    self.next_device_context_handle = self.next_device_context_handle.wrapping_add(4);
                    self.device_contexts.insert(hdc, Some(hwnd));
                    let window = self.user32.window_state(hwnd)?;
                    match self.guest_arch {
                        GuestArch::X86 => {
                            memory.map_bytes(paint_ptr, &(hdc as u32).to_le_bytes());
                            memory.map_bytes(paint_ptr + 4, &0_u32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 8, &0_i32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 12, &0_i32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 16, &(window.width as i32).to_le_bytes());
                            memory.map_bytes(paint_ptr + 20, &(window.height as i32).to_le_bytes());
                            memory.map_bytes(paint_ptr + 24, &0_u32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 28, &0_u32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 32, &[0; 32]);
                        }
                        GuestArch::X64 => {
                            memory.map_bytes(paint_ptr, &hdc.to_le_bytes());
                            memory.map_bytes(paint_ptr + 8, &0_u32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 12, &0_i32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 16, &0_i32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 20, &(window.width as i32).to_le_bytes());
                            memory.map_bytes(paint_ptr + 24, &(window.height as i32).to_le_bytes());
                            memory.map_bytes(paint_ptr + 28, &0_u32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 32, &0_u32.to_le_bytes());
                            memory.map_bytes(paint_ptr + 36, &[0; 32]);
                        }
                    }
                    hdc
                } else {
                    0
                };
                state.set(Register::Rax, hdc);
                self.last_error = if hdc != 0 { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "BeginPaint",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("paint_ptr".to_string(), json!(format!("{paint_ptr:#x}"))),
                    ]),
                    json!(hdc),
                );
            }
            HostThunk::FillRect => {
                let hdc = guest_call_arg(state, memory, 0)?;
                let rect_ptr = guest_call_arg(state, memory, 1)?;
                let brush = guest_call_arg(state, memory, 2)?;
                let filled = self.device_contexts.contains_key(&hdc) && rect_ptr != 0 && brush != 0;
                state.set(Register::Rax, u64::from(filled));
                self.last_error = if filled { 0 } else { ERROR_INVALID_PARAMETER };
                self.push_trace(
                    "input",
                    "FillRect",
                    BTreeMap::from([
                        ("hdc".to_string(), json!(hdc)),
                        ("rect_ptr".to_string(), json!(format!("{rect_ptr:#x}"))),
                        ("brush".to_string(), json!(brush)),
                    ]),
                    json!(filled),
                );
            }
            HostThunk::EndPaint => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let paint_ptr = guest_call_arg(state, memory, 1)?;
                let ended = if self.user32.has_window(hwnd) && paint_ptr != 0 {
                    let hdc = match self.guest_arch {
                        GuestArch::X86 => read_guest_u32(memory, paint_ptr)? as u64,
                        GuestArch::X64 => read_guest_u64(memory, paint_ptr)?,
                    };
                    self.device_contexts.remove(&hdc);
                    true
                } else {
                    false
                };
                state.set(Register::Rax, u64::from(ended));
                self.last_error = if ended { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "EndPaint",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("paint_ptr".to_string(), json!(format!("{paint_ptr:#x}"))),
                    ]),
                    json!(ended),
                );
            }
            HostThunk::ScreenToClient => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let point_ptr = guest_call_arg(state, memory, 1)?;
                let converted = self.user32.has_window(hwnd) && point_ptr != 0;
                state.set(Register::Rax, u64::from(converted));
                self.last_error = if converted { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "ScreenToClient",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("point_ptr".to_string(), json!(format!("{point_ptr:#x}"))),
                    ]),
                    json!(converted),
                );
            }
            HostThunk::SetWindowPos => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let insert_after = guest_call_arg(state, memory, 1)?;
                let x = guest_call_arg(state, memory, 2)? as i32;
                let y = guest_call_arg(state, memory, 3)? as i32;
                let cx = guest_call_arg(state, memory, 4)? as i32;
                let cy = guest_call_arg(state, memory, 5)? as i32;
                let flags = guest_call_arg_u32(state, memory, 6)?;
                let updated = if self.user32.has_window(hwnd) {
                    const SWP_SHOWWINDOW: u32 = 0x0040;
                    const SWP_HIDEWINDOW: u32 = 0x0080;
                    if flags & SWP_SHOWWINDOW != 0 {
                        let _ = self.user32.show_window(hwnd, 1)?;
                    }
                    if flags & SWP_HIDEWINDOW != 0 {
                        let _ = self.user32.show_window(hwnd, 0)?;
                    }
                    true
                } else {
                    false
                };
                state.set(Register::Rax, u64::from(updated));
                self.last_error = if updated { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "SetWindowPos",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("insert_after".to_string(), json!(insert_after)),
                        ("x".to_string(), json!(x)),
                        ("y".to_string(), json!(y)),
                        ("cx".to_string(), json!(cx)),
                        ("cy".to_string(), json!(cy)),
                        ("flags".to_string(), json!(flags)),
                    ]),
                    json!(updated),
                );
            }
            HostThunk::GetSysColor => {
                let index = guest_call_arg(state, memory, 0)? as i32;
                let color = match index {
                    5 => 0x00ff_ffff,
                    8 => 0x0000_0000,
                    15 => 0x00f0_f0f0,
                    18 => 0x0000_0000,
                    _ => 0x00c0_c0c0,
                };
                state.set(Register::Rax, color as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "GetSysColor",
                    BTreeMap::from([("index".to_string(), json!(index))]),
                    json!(color),
                );
            }
            HostThunk::LoadCursorW => {
                let instance = guest_call_arg(state, memory, 0)?;
                let name_ptr = guest_call_arg(state, memory, 1)?;
                let source = if name_ptr == 0 {
                    String::new()
                } else if name_ptr >> 16 == 0 {
                    format!("resource#{}", name_ptr & 0xffff)
                } else {
                    read_utf16_string(memory, name_ptr)?
                };
                let handle = self.user32.load_image_w(&source, 2, 0, 0, 0) as u64;
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "LoadCursorW",
                    BTreeMap::from([
                        ("instance".to_string(), json!(instance)),
                        ("source".to_string(), json!(source)),
                    ]),
                    json!(handle),
                );
            }
            HostThunk::LoadBitmapW => {
                let instance = guest_call_arg(state, memory, 0)?;
                let name_ptr = guest_call_arg(state, memory, 1)?;
                let source = if name_ptr == 0 {
                    String::new()
                } else if name_ptr >> 16 == 0 {
                    format!("resource#{}", name_ptr & 0xffff)
                } else {
                    read_utf16_string(memory, name_ptr)?
                };
                let handle = self.user32.load_image_w(&source, 0, 0, 0, 0) as u64;
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "LoadBitmapW",
                    BTreeMap::from([
                        ("instance".to_string(), json!(instance)),
                        ("source".to_string(), json!(source)),
                    ]),
                    json!(handle),
                );
            }
            HostThunk::CheckDlgButton => {
                let parent = guest_call_arg(state, memory, 0)? as u32;
                let item_id = guest_call_arg(state, memory, 1)? as i32;
                let check = guest_call_arg(state, memory, 2)? as u32;
                let changed = self.user32.get_dlg_item(parent, item_id)?.is_some();
                state.set(Register::Rax, u64::from(changed));
                self.last_error = if changed { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "CheckDlgButton",
                    BTreeMap::from([
                        ("parent".to_string(), json!(parent)),
                        ("item_id".to_string(), json!(item_id)),
                        ("check".to_string(), json!(check)),
                    ]),
                    json!(changed),
                );
            }
            HostThunk::GetMessagePos => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("input", "GetMessagePos", BTreeMap::new(), json!(0));
            }
            HostThunk::IsWindowVisible => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let visible = self
                    .user32
                    .window_state(hwnd)
                    .map(|window| window.visible)
                    .unwrap_or(false);
                state.set(Register::Rax, u64::from(visible));
                self.last_error = if visible || self.user32.has_window(hwnd) {
                    0
                } else {
                    ERROR_INVALID_WINDOW_HANDLE
                };
                self.push_trace(
                    "input",
                    "IsWindowVisible",
                    BTreeMap::from([("hwnd".to_string(), json!(hwnd))]),
                    json!(visible),
                );
            }
            HostThunk::GetSystemMetrics => {
                let index = guest_call_arg(state, memory, 0)? as i32;
                let value = match index {
                    0 => 1024,
                    1 => 768,
                    2 | 3 | 11 | 12 => 17,
                    4 => 23,
                    5 | 6 => 1,
                    7 | 8 => 4,
                    32 | 33 => 32,
                    49 | 50 => 16,
                    _ => 0,
                };
                state.set(Register::Rax, value as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "GetSystemMetrics",
                    BTreeMap::from([("index".to_string(), json!(index))]),
                    json!(value),
                );
            }
            HostThunk::GetDlgItemTextW => {
                let parent = guest_call_arg(state, memory, 0)? as u32;
                let item_id = guest_call_arg(state, memory, 1)? as i32;
                let buffer = guest_call_arg(state, memory, 2)?;
                let max = guest_call_arg_u32(state, memory, 3)?;
                let item_hwnd = self.user32.get_dlg_item(parent, item_id)?.unwrap_or(0);
                let text = if item_hwnd == 0 {
                    String::new()
                } else {
                    self.user32.window_state(item_hwnd).map(|window| window.title).unwrap_or_default()
                };
                let copied = text.encode_utf16().count().min(max.saturating_sub(1) as usize) as u32;
                let _ = write_utf16_api_string(memory, buffer, max, &text)?;
                state.set(Register::Rax, copied as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "GetDlgItemTextW",
                    BTreeMap::from([
                        ("parent".to_string(), json!(parent)),
                        ("item_id".to_string(), json!(item_id)),
                        ("max".to_string(), json!(max)),
                        ("text".to_string(), json!(text)),
                    ]),
                    json!(copied),
                );
            }
            HostThunk::IsWindow => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let exists = self.user32.has_window(hwnd);
                state.set(Register::Rax, u64::from(exists));
                self.last_error = if exists { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "IsWindow",
                    BTreeMap::from([("hwnd".to_string(), json!(hwnd))]),
                    json!(exists),
                );
            }
            HostThunk::FindWindowExW => {
                let parent = guest_call_arg(state, memory, 0)? as u32;
                let after = guest_call_arg(state, memory, 1)? as u32;
                let class_ptr = guest_call_arg(state, memory, 2)?;
                let title_ptr = guest_call_arg(state, memory, 3)?;
                let class_name = if class_ptr == 0 {
                    None
                } else if class_ptr >> 16 == 0 {
                    Some(format!("#{}", class_ptr & 0xffff))
                } else {
                    Some(read_utf16_string(memory, class_ptr)?)
                };
                let title = if title_ptr == 0 {
                    None
                } else {
                    Some(read_utf16_string(memory, title_ptr)?)
                };
                let hwnd = self
                    .user32
                    .find_window_ex_w(parent, after, class_name.as_deref(), title.as_deref())
                    .unwrap_or(0);
                state.set(Register::Rax, hwnd as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "FindWindowExW",
                    BTreeMap::from([
                        ("parent".to_string(), json!(parent)),
                        ("after".to_string(), json!(after)),
                        ("class_name".to_string(), json!(class_name)),
                        ("title".to_string(), json!(title)),
                    ]),
                    json!(hwnd),
                );
            }
            HostThunk::CallWindowProcW => {
                let proc = guest_call_arg(state, memory, 0)?;
                let hwnd = guest_call_arg(state, memory, 1)? as u32;
                let message_id = guest_call_arg(state, memory, 2)?;
                let wparam = guest_call_arg(state, memory, 3)?;
                let lparam = guest_call_arg(state, memory, 4)?;
                let result = if proc == 0 {
                    0
                } else {
                    self.execute_guest_callback(
                        state,
                        memory,
                        proc,
                        &[u64::from(hwnd), message_id, wparam, lparam],
                        "CallWindowProcW",
                    )?
                };
                state.set(Register::Rax, result);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "CallWindowProcW",
                    BTreeMap::from([
                        ("proc".to_string(), json!(format!("{proc:#x}"))),
                        ("hwnd".to_string(), json!(hwnd)),
                        ("message".to_string(), json!(format!("{message_id:#x}"))),
                        ("wparam".to_string(), json!(wparam)),
                        ("lparam".to_string(), json!(lparam)),
                    ]),
                    json!(result),
                );
            }
            HostThunk::CreatePopupMenu => {
                let handle = self.next_gdi_object_handle;
                self.next_gdi_object_handle = self.next_gdi_object_handle.wrapping_add(4);
                self.gdi_objects.insert(handle, "popup-menu".to_string());
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace("input", "CreatePopupMenu", BTreeMap::new(), json!(handle));
            }
            HostThunk::AppendMenuW => {
                let menu = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let item = guest_call_arg(state, memory, 2)?;
                let text_ptr = guest_call_arg(state, memory, 3)?;
                let text = if text_ptr == 0 {
                    None
                } else if text_ptr >> 16 == 0 {
                    Some(format!("resource#{}", text_ptr & 0xffff))
                } else {
                    Some(read_utf16_string(memory, text_ptr)?)
                };
                let appended = self.gdi_objects.contains_key(&menu);
                state.set(Register::Rax, u64::from(appended));
                self.last_error = if appended { 0 } else { ERROR_INVALID_PARAMETER };
                self.push_trace(
                    "input",
                    "AppendMenuW",
                    BTreeMap::from([
                        ("menu".to_string(), json!(menu)),
                        ("flags".to_string(), json!(flags)),
                        ("item".to_string(), json!(item)),
                        ("text".to_string(), json!(text)),
                    ]),
                    json!(appended),
                );
            }
            HostThunk::TrackPopupMenu => {
                let menu = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let x = guest_call_arg(state, memory, 2)? as i32;
                let y = guest_call_arg(state, memory, 3)? as i32;
                let reserved = guest_call_arg(state, memory, 4)?;
                let hwnd = guest_call_arg(state, memory, 5)? as u32;
                let rect_ptr = guest_call_arg(state, memory, 6)?;
                let tracked = self.gdi_objects.contains_key(&menu) && (hwnd == 0 || self.user32.has_window(hwnd));
                state.set(Register::Rax, u64::from(tracked));
                self.last_error = if tracked { 0 } else { ERROR_INVALID_PARAMETER };
                self.push_trace(
                    "input",
                    "TrackPopupMenu",
                    BTreeMap::from([
                        ("menu".to_string(), json!(menu)),
                        ("flags".to_string(), json!(flags)),
                        ("x".to_string(), json!(x)),
                        ("y".to_string(), json!(y)),
                        ("reserved".to_string(), json!(reserved)),
                        ("hwnd".to_string(), json!(hwnd)),
                        ("rect_ptr".to_string(), json!(format!("{rect_ptr:#x}"))),
                    ]),
                    json!(tracked),
                );
            }
            HostThunk::PostQuitMessage => {
                let exit_code = guest_call_arg(state, memory, 0)? as i32;
                self.user32.post_quit_message(exit_code)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "PostQuitMessage",
                    BTreeMap::from([("exit_code".to_string(), json!(exit_code))]),
                    json!(0),
                );
            }
            HostThunk::SetTimer => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let timer_id = guest_call_arg(state, memory, 1)? as u32;
                let elapse = guest_call_arg(state, memory, 2)? as u32;
                let callback = guest_call_arg(state, memory, 3)?;
                let result = if timer_id == 0 { 1 } else { timer_id };
                state.set(Register::Rax, result as u64);
                self.last_error = if hwnd == 0 || self.user32.has_window(hwnd) { 0 } else { ERROR_INVALID_WINDOW_HANDLE };
                self.push_trace(
                    "input",
                    "SetTimer",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("timer_id".to_string(), json!(timer_id)),
                        ("elapse".to_string(), json!(elapse)),
                        ("callback".to_string(), json!(format!("{callback:#x}"))),
                    ]),
                    json!(result),
                );
            }
            HostThunk::SystemParametersInfoW => {
                let action = guest_call_arg_u32(state, memory, 0)?;
                let param = guest_call_arg(state, memory, 1)? as u32;
                let value_ptr = guest_call_arg(state, memory, 2)?;
                let win_ini = guest_call_arg_u32(state, memory, 3)?;
                let success = match action {
                    0x0030 if value_ptr != 0 => {
                        memory.map_bytes(value_ptr, &0_i32.to_le_bytes());
                        memory.map_bytes(value_ptr + 4, &0_i32.to_le_bytes());
                        memory.map_bytes(value_ptr + 8, &1024_i32.to_le_bytes());
                        memory.map_bytes(value_ptr + 12, &768_i32.to_le_bytes());
                        true
                    }
                    _ => true,
                };
                state.set(Register::Rax, u64::from(success));
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SystemParametersInfoW",
                    BTreeMap::from([
                        ("action".to_string(), json!(format!("{action:#x}"))),
                        ("param".to_string(), json!(param)),
                        ("value_ptr".to_string(), json!(format!("{value_ptr:#x}"))),
                        ("win_ini".to_string(), json!(win_ini)),
                    ]),
                    json!(success),
                );
            }
            HostThunk::SendMessageTimeoutW => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let message_id = guest_call_arg(state, memory, 1)? as u32;
                let wparam = guest_call_arg(state, memory, 2)? as i64;
                let lparam = guest_call_arg(state, memory, 3)? as i64;
                let flags = guest_call_arg_u32(state, memory, 4)?;
                let timeout = guest_call_arg_u32(state, memory, 5)?;
                let result_ptr = guest_call_arg(state, memory, 6)?;
                let result = self.dispatch_window_message(
                    state,
                    memory,
                    hwnd,
                    message_id,
                    wparam,
                    lparam,
                    "SendMessageTimeoutW::WindowProc",
                )?;
                if result_ptr != 0 {
                    write_guest_pointer(memory, result_ptr, result as u64, self.guest_arch)?;
                }
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SendMessageTimeoutW",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("message".to_string(), json!(format!("{message_id:#x}"))),
                        ("wparam".to_string(), json!(wparam)),
                        ("lparam".to_string(), json!(lparam)),
                        ("flags".to_string(), json!(flags)),
                        ("timeout".to_string(), json!(timeout)),
                        ("result_ptr".to_string(), json!(format!("{result_ptr:#x}"))),
                    ]),
                    json!(result),
                );
            }
            HostThunk::ExitWindowsEx => {
                let flags = guest_call_arg_u32(state, memory, 0)?;
                let reason = guest_call_arg_u32(state, memory, 1)?;
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "ExitWindowsEx",
                    BTreeMap::from([
                        ("flags".to_string(), json!(flags)),
                        ("reason".to_string(), json!(reason)),
                    ]),
                    json!(1),
                );
            }
            HostThunk::SetWindowTextW => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let title_ptr = guest_call_arg(state, memory, 1)?;
                let title = if title_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, title_ptr)?
                };
                let updated = self.user32.set_window_text_w(hwnd, &title);
                state.set(Register::Rax, u64::from(updated));
                self.last_error = if updated {
                    0
                } else {
                    ERROR_INVALID_WINDOW_HANDLE
                };
                self.push_trace(
                    "input",
                    "SetWindowTextW",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("title".to_string(), json!(title)),
                    ]),
                    json!(updated),
                );
            }
            HostThunk::GetWindowLongW => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let index = guest_call_arg(state, memory, 1)? as i32;
                let value = self.user32.get_window_long_w(hwnd, index).unwrap_or(0);
                state.set(Register::Rax, value);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "GetWindowLongW",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("index".to_string(), json!(index)),
                    ]),
                    json!(value),
                );
            }
            HostThunk::SetWindowLongW => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let index = guest_call_arg(state, memory, 1)? as i32;
                let value = guest_call_arg(state, memory, 2)?;
                let previous = self.user32.set_window_long_w(hwnd, index, value).unwrap_or(0);
                state.set(Register::Rax, previous);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SetWindowLongW",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("index".to_string(), json!(index)),
                        ("value".to_string(), json!(value)),
                    ]),
                    json!(previous),
                );
            }
            HostThunk::LoadImageW => {
                let instance = guest_call_arg(state, memory, 0)?;
                let name_ptr = guest_call_arg(state, memory, 1)?;
                let image_type = guest_call_arg_u32(state, memory, 2)?;
                let width = guest_call_arg(state, memory, 3)? as i32;
                let height = guest_call_arg(state, memory, 4)? as i32;
                let flags = guest_call_arg_u32(state, memory, 5)?;
                let source = if name_ptr == 0 {
                    String::new()
                } else if name_ptr >> 16 == 0 {
                    format!("resource#{}", name_ptr & 0xffff)
                } else {
                    read_utf16_string(memory, name_ptr)?
                };
                let handle = self
                    .user32
                    .load_image_w(&source, image_type, width, height, flags);
                state.set(Register::Rax, handle as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "LoadImageW",
                    BTreeMap::from([
                        ("instance".to_string(), json!(instance)),
                        ("source".to_string(), json!(source)),
                        ("image_type".to_string(), json!(image_type)),
                        ("width".to_string(), json!(width)),
                        ("height".to_string(), json!(height)),
                        ("flags".to_string(), json!(flags)),
                    ]),
                    json!(handle),
                );
            }
            HostThunk::GetDeviceCaps => {
                let hdc = guest_call_arg(state, memory, 0)?;
                let index = guest_call_arg(state, memory, 1)? as i32;
                let value = if self.device_contexts.contains_key(&hdc) {
                    match index {
                        8 => 2560,
                        10 => 1600,
                        12 => 32,
                        14 => 1,
                        88 | 90 => 144,
                        _ => 0,
                    }
                } else {
                    0
                };
                state.set(Register::Rax, value as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "GetDeviceCaps",
                    BTreeMap::from([
                        ("hdc".to_string(), json!(hdc)),
                        ("index".to_string(), json!(index)),
                    ]),
                    json!(value),
                );
            }
            HostThunk::SelectObject => {
                let hdc = guest_call_arg(state, memory, 0)?;
                let object = guest_call_arg(state, memory, 1)?;
                let selected = self.device_contexts.contains_key(&hdc);
                let previous = if selected {
                    self.dc_selected_objects.insert(hdc, object).unwrap_or(0)
                } else {
                    0
                };
                state.set(Register::Rax, previous);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SelectObject",
                    BTreeMap::from([
                        ("hdc".to_string(), json!(hdc)),
                        ("object".to_string(), json!(object)),
                    ]),
                    json!(previous),
                );
            }
            HostThunk::CreateFontIndirectW => {
                let logfont_ptr = guest_call_arg(state, memory, 0)?;
                let height = if logfont_ptr == 0 {
                    0
                } else {
                    read_i32_from_memory(memory, logfont_ptr)?
                };
                let face_name = if logfont_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, logfont_ptr + 28).unwrap_or_default()
                };
                let handle = if logfont_ptr == 0 {
                    0
                } else {
                    let handle = self.next_gdi_object_handle;
                    self.next_gdi_object_handle = self.next_gdi_object_handle.wrapping_add(4);
                    self.gdi_objects.insert(handle, "font".to_string());
                    handle
                };
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "CreateFontIndirectW",
                    BTreeMap::from([
                        ("height".to_string(), json!(height)),
                        ("face_name".to_string(), json!(face_name)),
                    ]),
                    json!(handle),
                );
            }
            HostThunk::DeleteObject => {
                let object = guest_call_arg(state, memory, 0)?;
                let deleted = self.gdi_objects.remove(&object).is_some();
                self.dc_selected_objects.retain(|_, selected| *selected != object);
                state.set(Register::Rax, u64::from(deleted));
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "DeleteObject",
                    BTreeMap::from([("object".to_string(), json!(object))]),
                    json!(deleted),
                );
            }
            HostThunk::SetBkMode => {
                let hdc = guest_call_arg(state, memory, 0)?;
                let mode = guest_call_arg(state, memory, 1)? as i32;
                let previous = if self.device_contexts.contains_key(&hdc) {
                    self.dc_background_modes.insert(hdc, mode).unwrap_or(2)
                } else {
                    0
                };
                state.set(Register::Rax, previous as i64 as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SetBkMode",
                    BTreeMap::from([
                        ("hdc".to_string(), json!(hdc)),
                        ("mode".to_string(), json!(mode)),
                    ]),
                    json!(previous),
                );
            }
            HostThunk::SetTextColor => {
                let hdc = guest_call_arg(state, memory, 0)?;
                let color = guest_call_arg(state, memory, 1)? as u32;
                let previous = if self.device_contexts.contains_key(&hdc) {
                    self.dc_text_colors.insert(hdc, color).unwrap_or(0)
                } else {
                    0
                };
                state.set(Register::Rax, previous as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SetTextColor",
                    BTreeMap::from([
                        ("hdc".to_string(), json!(hdc)),
                        ("color".to_string(), json!(color)),
                    ]),
                    json!(previous),
                );
            }
            HostThunk::DrawTextW => {
                let hdc = guest_call_arg(state, memory, 0)?;
                let text_ptr = guest_call_arg(state, memory, 1)?;
                let text_len = guest_call_arg(state, memory, 2)? as i32;
                let rect_ptr = guest_call_arg(state, memory, 3)?;
                let format = guest_call_arg(state, memory, 4)? as u32;
                let text = if text_ptr == 0 {
                    String::new()
                } else if text_len < 0 {
                    read_utf16_string(memory, text_ptr)?
                } else {
                    let mut code_units = Vec::with_capacity(text_len as usize);
                    for index in 0..text_len as u64 {
                        let low = memory.read_u8(text_ptr + index * 2)?;
                        let high = memory.read_u8(text_ptr + index * 2 + 1)?;
                        code_units.push(u16::from_le_bytes([low, high]));
                    }
                    String::from_utf16_lossy(&code_units)
                };
                let char_count = text.chars().count().max(1) as i32;
                let line_height = 18;
                let rendered_height = line_height;
                if rect_ptr != 0 && format & 0x0400 != 0 {
                    let left = read_i32_from_memory(memory, rect_ptr)?;
                    let top = read_i32_from_memory(memory, rect_ptr + 4)?;
                    let right = left + char_count * 8;
                    let bottom = top + rendered_height;
                    memory.map_bytes(rect_ptr, &left.to_le_bytes());
                    memory.map_bytes(rect_ptr + 4, &top.to_le_bytes());
                    memory.map_bytes(rect_ptr + 8, &right.to_le_bytes());
                    memory.map_bytes(rect_ptr + 12, &bottom.to_le_bytes());
                }
                let drawn = if self.device_contexts.contains_key(&hdc) {
                    rendered_height
                } else {
                    0
                };
                state.set(Register::Rax, drawn as i64 as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "DrawTextW",
                    BTreeMap::from([
                        ("hdc".to_string(), json!(hdc)),
                        ("text".to_string(), json!(text)),
                        ("format".to_string(), json!(format)),
                    ]),
                    json!(drawn),
                );
            }
            HostThunk::SendMessageW => {
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let message_id = guest_call_arg(state, memory, 1)? as u32;
                let wparam = guest_call_arg(state, memory, 2)? as i64;
                let lparam = guest_call_arg(state, memory, 3)? as i64;
                let result = self.dispatch_window_message(
                    state,
                    memory,
                    hwnd,
                    message_id,
                    wparam,
                    lparam,
                    "SendMessageW::WindowProc",
                )?;
                state.set(Register::Rax, result as i64 as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "SendMessageW",
                    BTreeMap::from([
                        ("hwnd".to_string(), json!(hwnd)),
                        ("message".to_string(), json!(format!("{message_id:#x}"))),
                        ("wparam".to_string(), json!(wparam)),
                        ("lparam".to_string(), json!(lparam)),
                    ]),
                    json!(result),
                );
            }
            HostThunk::MulDiv => {
                let number = guest_call_arg(state, memory, 0)? as i32;
                let numerator = guest_call_arg(state, memory, 1)? as i32;
                let denominator = guest_call_arg(state, memory, 2)? as i32;
                let result = if denominator == 0 {
                    -1_i32
                } else {
                    let product = i64::from(number) * i64::from(numerator);
                    let abs_denominator = i64::from(denominator).abs();
                    let rounded = (product.abs() + (abs_denominator / 2)) / abs_denominator;
                    let signed = if (product < 0) ^ (denominator < 0) {
                        -(rounded as i64)
                    } else {
                        rounded as i64
                    };
                    signed.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
                };
                state.set(Register::Rax, result as i64 as u64);
                self.last_error = 0;
                self.push_trace(
                    "input",
                    "MulDiv",
                    BTreeMap::from([
                        ("number".to_string(), json!(number)),
                        ("numerator".to_string(), json!(numerator)),
                        ("denominator".to_string(), json!(denominator)),
                    ]),
                    json!(result),
                );
            }
            HostThunk::PeekMessageW => {
                let msg_ptr = guest_call_arg(state, memory, 0)?;
                let remove = guest_call_arg_u32(state, memory, 4)? & 0x0001 != 0;
                self.poll_live_input()?;
                if let Some(message) = self.user32.peek_message_w(remove) {
                    match state.arch {
                        GuestArch::X64 => write_win64_msg(memory, msg_ptr, &message)?,
                        GuestArch::X86 => write_win32_msg(memory, msg_ptr, &message)?,
                    }
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
                let msg_ptr = guest_call_arg(state, memory, 0)?;
                let message = match state.arch {
                    GuestArch::X64 => read_win64_msg(memory, msg_ptr)?,
                    GuestArch::X86 => read_win32_msg(memory, msg_ptr)?,
                };
                let result = if let Some(hwnd) = message.hwnd {
                    self.dispatch_window_message(
                        state,
                        memory,
                        hwnd,
                        message_id(message.kind),
                        message.wparam,
                        message.lparam,
                        "DispatchMessageW::WindowProc",
                    )?
                } else {
                    self.user32.dispatch_message_w(&message)?
                };
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
                let hwnd = guest_call_arg(state, memory, 0)? as u32;
                let message_id = guest_call_arg(state, memory, 1)? as u32;
                let wparam = guest_call_arg(state, memory, 2)? as i64;
                let lparam = guest_call_arg(state, memory, 3)? as i64;
                let message = Message {
                    hwnd: (hwnd != 0).then_some(hwnd),
                    kind: message_kind(message_id)?,
                    wparam,
                    lparam,
                    translated: false,
                    device_id: None,
                };
                let result = self.user32.def_window_proc_w(&message)?;
                state.set(Register::Rax, result as i64 as u64);
                self.last_error = 0;
            }
            HostThunk::SetCurrentDirectoryW => {
                let path = read_utf16_string(memory, guest_call_arg(state, memory, 0)?)?;
                self.current_directory = resolve_guest_path(&self.current_directory, &path);
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "SetCurrentDirectoryW",
                    BTreeMap::from([("path".to_string(), json!(self.current_directory.clone()))]),
                    json!(1),
                );
            }
            HostThunk::GetFullPathNameW => {
                let raw_path = read_utf16_string(memory, guest_call_arg(state, memory, 0)?)?;
                let size = guest_call_arg_u32(state, memory, 1)?;
                let buffer = guest_call_arg(state, memory, 2)?;
                let file_part_ptr = guest_call_arg(state, memory, 3)?;
                let path = resolve_full_guest_path(&self.current_directory, &raw_path);
                let path_length = path.encode_utf16().count() as u32;
                let result = write_utf16_api_string(memory, buffer, size, &path)?;
                let file_part = if buffer != 0 && size > path_length {
                    windows_file_part_offset(&path)
                        .map(|offset| buffer + offset)
                        .unwrap_or(0)
                } else {
                    0
                };
                if file_part_ptr != 0 {
                    write_guest_pointer(memory, file_part_ptr, file_part, self.guest_arch)?;
                }
                state.set(Register::Rax, result as u64);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "GetFullPathNameW",
                    BTreeMap::from([
                        ("path_raw".to_string(), json!(raw_path)),
                        ("path".to_string(), json!(path)),
                        ("cwd".to_string(), json!(self.current_directory.clone())),
                        ("file_part".to_string(), json!(file_part)),
                    ]),
                    json!(result),
                );
            }
            HostThunk::GetFileAttributesW => {
                let path_ptr = guest_call_arg(state, memory, 0)?;
                let raw_path = read_utf16_string(memory, path_ptr)?;
                let path = resolve_guest_path(&self.current_directory, &raw_path);
                match self.win32.get_file_attributes_w(&path) {
                    Ok(attributes) => {
                        let raw_attributes = file_attributes_mask(&attributes);
                        state.set(Register::Rax, raw_attributes as u64);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "GetFileAttributesW",
                            BTreeMap::from([
                                ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                                ("path_ptr".to_string(), json!(format!("{path_ptr:#x}"))),
                                ("path_raw".to_string(), json!(raw_path)),
                                ("path".to_string(), json!(path)),
                                ("cwd".to_string(), json!(self.current_directory.clone())),
                            ]),
                            json!(raw_attributes),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, INVALID_FILE_ATTRIBUTES);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::FindFirstFileW => {
                let path_ptr = guest_call_arg(state, memory, 0)?;
                let find_data_ptr = guest_call_arg(state, memory, 1)?;
                let raw_path = read_utf16_string(memory, path_ptr)?;
                let path = resolve_guest_path(&self.current_directory, &raw_path);
                if find_data_ptr == 0 {
                    state.set(Register::Rax, INVALID_HANDLE_VALUE);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    match self.win32.find_first_file_w(&path) {
                        Ok((handle, find_data)) => {
                            write_find_data_w(memory, find_data_ptr, &find_data)?;
                            state.set(Register::Rax, handle as u64);
                            self.last_error = 0;
                            self.push_trace(
                                "file",
                                "FindFirstFileW",
                                BTreeMap::from([
                                    ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                                    ("path_ptr".to_string(), json!(format!("{path_ptr:#x}"))),
                                    ("path_raw".to_string(), json!(raw_path)),
                                    ("path".to_string(), json!(path)),
                                    ("cwd".to_string(), json!(self.current_directory.clone())),
                                    ("find_data_ptr".to_string(), json!(format!("{find_data_ptr:#x}"))),
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
            HostThunk::FindNextFileW => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let find_data_ptr = guest_call_arg(state, memory, 1)?;
                if find_data_ptr == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    match self.win32.find_next_file_w(handle) {
                        Ok(Some(find_data)) => {
                            write_find_data_w(memory, find_data_ptr, &find_data)?;
                            state.set(Register::Rax, 1);
                            self.last_error = 0;
                            self.push_trace(
                                "file",
                                "FindNextFileW",
                                BTreeMap::from([
                                    ("handle".to_string(), json!(handle)),
                                    ("find_data_ptr".to_string(), json!(format!("{find_data_ptr:#x}"))),
                                ]),
                                json!(1),
                            );
                        }
                        Ok(None) => {
                            state.set(Register::Rax, 0);
                            self.last_error = ERROR_NO_MORE_FILES;
                        }
                        Err(error) => {
                            state.set(Register::Rax, 0);
                            self.last_error = last_error_from_app_error(&error);
                        }
                    }
                }
            }
            HostThunk::FindClose => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                match self.win32.find_close(handle) {
                    Ok(()) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "FindClose",
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
            HostThunk::SetFileAttributesW => {
                let path_ptr = guest_call_arg(state, memory, 0)?;
                let raw_path = read_utf16_string(memory, path_ptr)?;
                let path = resolve_guest_path(&self.current_directory, &raw_path);
                let raw_attributes = guest_call_arg_u32(state, memory, 1)?;
                let attributes = file_attributes_from_mask(raw_attributes);
                let attribute_refs = attributes.iter().map(String::as_str).collect::<Vec<_>>();
                match self.win32.set_file_attributes_w(&path, &attribute_refs) {
                    Ok(()) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "SetFileAttributesW",
                            BTreeMap::from([
                                ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                                ("path_ptr".to_string(), json!(format!("{path_ptr:#x}"))),
                                ("path_raw".to_string(), json!(raw_path)),
                                ("path".to_string(), json!(path)),
                                ("cwd".to_string(), json!(self.current_directory.clone())),
                                ("raw_attributes".to_string(), json!(raw_attributes)),
                                ("attributes".to_string(), json!(attributes)),
                            ]),
                            json!(1),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::SetErrorMode => {
                let new_mode = guest_call_arg_u32(state, memory, 0)?;
                let previous_mode = self.error_mode;
                self.error_mode = new_mode;
                state.set(Register::Rax, previous_mode as u64);
                self.last_error = 0;
                self.push_trace(
                    "kernel32",
                    "SetErrorMode",
                    BTreeMap::from([("mode".to_string(), json!(new_mode))]),
                    json!(previous_mode),
                );
            }
            HostThunk::SetDefaultDllDirectories => {
                let flags = guest_call_arg_u32(state, memory, 0)?;
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace(
                    "kernel32",
                    "SetDefaultDllDirectories",
                    BTreeMap::from([("flags".to_string(), json!(flags))]),
                    json!(1),
                );
            }
            HostThunk::GetSystemDirectoryW => {
                let buffer = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg_u32(state, memory, 1)?;
                let path = "C:\\Windows\\System32";
                let result = write_utf16_api_string(memory, buffer, size, path)?;
                state.set(Register::Rax, result as u64);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "GetSystemDirectoryW",
                    BTreeMap::from([("path".to_string(), json!(path))]),
                    json!(result),
                );
            }
            HostThunk::GetWindowsDirectoryW => {
                let buffer = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg_u32(state, memory, 1)?;
                let path = "C:\\Windows";
                let result = write_utf16_api_string(memory, buffer, size, path)?;
                state.set(Register::Rax, result as u64);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "GetWindowsDirectoryW",
                    BTreeMap::from([("path".to_string(), json!(path))]),
                    json!(result),
                );
            }
            HostThunk::GetTempPathW => {
                let buffer = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg_u32(state, memory, 1)?;
                let path = self.win32.get_temp_path_w()?;
                let result = write_utf16_api_string(memory, buffer, size, &path)?;
                state.set(Register::Rax, result as u64);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "GetTempPathW",
                    BTreeMap::from([("path".to_string(), json!(path))]),
                    json!(result),
                );
            }
            HostThunk::GetTempFileNameW => {
                let path_ptr = guest_call_arg(state, memory, 0)?;
                let prefix_ptr = guest_call_arg(state, memory, 1)?;
                let unique = guest_call_arg_u32(state, memory, 2)?;
                let buffer = guest_call_arg(state, memory, 3)?;
                let requested_path = if path_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, path_ptr)?
                };
                let prefix = if prefix_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, prefix_ptr)?
                };
                let resolved_path = if requested_path.is_empty() {
                    self.win32.get_temp_path_w()?
                } else {
                    resolve_guest_path(&self.current_directory, &requested_path)
                };
                let temp_file = self.win32.get_temp_file_name_w(&resolved_path, &prefix)?;
                if buffer != 0 {
                    let mut bytes = Vec::with_capacity((temp_file.encode_utf16().count() + 1) * 2);
                    for unit in temp_file.encode_utf16() {
                        bytes.extend_from_slice(&unit.to_le_bytes());
                    }
                    bytes.extend_from_slice(&0_u16.to_le_bytes());
                    memory.map_bytes(buffer, &bytes);
                }
                state.set(Register::Rax, u64::from(if unique == 0 { 1 } else { unique }));
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "GetTempFileNameW",
                    BTreeMap::from([
                        ("path".to_string(), json!(requested_path)),
                        ("path_resolved".to_string(), json!(resolved_path)),
                        ("prefix".to_string(), json!(prefix)),
                        ("generated".to_string(), json!(temp_file)),
                        ("unique".to_string(), json!(unique)),
                    ]),
                    state.get(Register::Rax).into(),
                );
            }
            HostThunk::GetModuleFileNameW => {
                let module_handle = guest_call_arg(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let size = guest_call_arg_u32(state, memory, 2)?;
                let path = if module_handle == 0 || module_handle == self.mapped_image_base {
                    self.main_module_path.clone()
                } else {
                    self.module_names_by_handle
                        .get(&module_handle)
                        .cloned()
                        .unwrap_or_default()
                };
                let result = write_utf16_api_string(memory, buffer, size, &path)?;
                state.set(Register::Rax, result as u64);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "GetModuleFileNameW",
                    BTreeMap::from([
                        ("module_handle".to_string(), json!(format!("{module_handle:#x}"))),
                        ("path".to_string(), json!(path)),
                    ]),
                    json!(result),
                );
            }
            HostThunk::GetDiskFreeSpaceW => {
                let root_path_ptr = guest_call_arg(state, memory, 0)?;
                let sectors_per_cluster_ptr = guest_call_arg(state, memory, 1)?;
                let bytes_per_sector_ptr = guest_call_arg(state, memory, 2)?;
                let free_clusters_ptr = guest_call_arg(state, memory, 3)?;
                let total_clusters_ptr = guest_call_arg(state, memory, 4)?;
                let root_path = if root_path_ptr == 0 {
                    None
                } else {
                    Some(read_utf16_string(memory, root_path_ptr)?)
                };
                if sectors_per_cluster_ptr == 0
                    || bytes_per_sector_ptr == 0
                    || free_clusters_ptr == 0
                    || total_clusters_ptr == 0
                {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let sectors_per_cluster = 8_u32;
                    let bytes_per_sector = 512_u32;
                    let total_clusters = 4_194_304_u32;
                    let free_clusters = 3_145_728_u32;
                    write_u32(memory, sectors_per_cluster_ptr, sectors_per_cluster);
                    write_u32(memory, bytes_per_sector_ptr, bytes_per_sector);
                    write_u32(memory, free_clusters_ptr, free_clusters);
                    write_u32(memory, total_clusters_ptr, total_clusters);
                    state.set(Register::Rax, 1);
                    self.last_error = 0;
                    self.push_trace(
                        "file",
                        "GetDiskFreeSpaceW",
                        BTreeMap::from([
                            ("root_path".to_string(), json!(root_path)),
                            ("sectors_per_cluster".to_string(), json!(sectors_per_cluster)),
                            ("bytes_per_sector".to_string(), json!(bytes_per_sector)),
                            ("free_clusters".to_string(), json!(free_clusters)),
                            ("total_clusters".to_string(), json!(total_clusters)),
                        ]),
                        json!(1),
                    );
                }
            }
            HostThunk::GetFileSize => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let high_ptr = guest_call_arg(state, memory, 1)?;
                match self.win32.get_file_size_ex(handle) {
                    Ok(size) => {
                        if high_ptr != 0 {
                            write_u32(memory, high_ptr, (size >> 32) as u32);
                        }
                        state.set(Register::Rax, (size as u32) as u64);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "GetFileSize",
                            BTreeMap::from([("handle".to_string(), json!(handle))]),
                            json!(size),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, u32::MAX as u64);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::FreeLibrary => {
                let handle = guest_call_arg(state, memory, 0)?;
                let released = handle != 0
                    && (handle == self.mapped_image_base
                        || self.module_handles.values().any(|value| *value == handle));
                state.set(Register::Rax, u64::from(released));
                self.last_error = if released { 0 } else { ERROR_INVALID_HANDLE };
                self.push_trace(
                    "kernel32",
                    "FreeLibrary",
                    BTreeMap::from([("handle".to_string(), json!(handle))]),
                    json!(released),
                );
            }
            HostThunk::LoadLibraryA => {
                let path_ptr = guest_call_arg(state, memory, 0)?;
                let path = if path_ptr == 0 {
                    String::new()
                } else {
                    read_c_string(memory, path_ptr)?
                };
                let handle = if path.is_empty() {
                    0
                } else {
                    self.get_or_create_module_handle(&path)
                };
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "kernel32",
                    "LoadLibraryA",
                    BTreeMap::from([("path".to_string(), json!(path))]),
                    json!(handle),
                );
            }
            HostThunk::LoadLibraryW => {
                let path_ptr = guest_call_arg(state, memory, 0)?;
                let path = if path_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, path_ptr)?
                };
                let handle = if path.is_empty() {
                    0
                } else {
                    self.get_or_create_module_handle(&path)
                };
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "kernel32",
                    "LoadLibraryW",
                    BTreeMap::from([("path".to_string(), json!(path))]),
                    json!(handle),
                );
            }
            HostThunk::LoadLibraryExW => {
                let path_ptr = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 2)?;
                let path = if path_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, path_ptr)?
                };
                let handle = if path.is_empty() {
                    0
                } else {
                    self.get_or_create_module_handle(&path)
                };
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "kernel32",
                    "LoadLibraryExW",
                    BTreeMap::from([
                        ("path".to_string(), json!(path)),
                        ("flags".to_string(), json!(flags)),
                    ]),
                    json!(handle),
                );
            }
            HostThunk::InitCommonControls => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("comctl32", "InitCommonControls", BTreeMap::new(), json!(0));
            }
            HostThunk::OleInitialize => {
                let thread_handle = self.win32.current_thread_handle();
                self.win32.co_initialize_ex(thread_handle, ApartmentModel::Sta)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("ole32", "OleInitialize", BTreeMap::new(), json!(0));
            }
            HostThunk::OleUninitialize => {
                let thread_handle = self.win32.current_thread_handle();
                self.win32.co_uninitialize(thread_handle)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("ole32", "OleUninitialize", BTreeMap::new(), json!(0));
            }
            HostThunk::CoCreateInstance => {
                let clsid_ptr = guest_call_arg(state, memory, 0)?;
                let outer = guest_call_arg(state, memory, 1)?;
                let clsctx = guest_call_arg_u32(state, memory, 2)?;
                let iid_ptr = guest_call_arg(state, memory, 3)?;
                let object_ptr = guest_call_arg(state, memory, 4)?;
                if object_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                    return Ok(None);
                }
                if object_ptr != 0 {
                    write_guest_pointer(memory, object_ptr, 0, self.guest_arch)?;
                }
                let clsid = read_guid_string(memory, clsid_ptr)?;
                let iid = read_guid_string(memory, iid_ptr)?;
                if outer == 0
                    && clsid.eq_ignore_ascii_case(SHELL_LINK_CLSID)
                    && is_shell_link_interface_iid(&iid)
                {
                    let shell_link_object = self.alloc_shell_link_object(memory)?;
                    let interface_object = if iid.eq_ignore_ascii_case(IID_ISHELLLINKW)
                        || iid.eq_ignore_ascii_case(IID_IUNKNOWN)
                    {
                        shell_link_object
                    } else {
                        self.ensure_shell_link_persist_file_object(memory, shell_link_object)?
                    };
                    write_guest_pointer(memory, object_ptr, interface_object, self.guest_arch)?;
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                    self.push_trace(
                        "ole32",
                        "CoCreateInstance",
                        BTreeMap::from([
                            ("clsid".to_string(), json!(clsid)),
                            ("iid".to_string(), json!(iid)),
                            ("clsctx".to_string(), json!(clsctx)),
                        ]),
                        json!(0),
                    );
                } else {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "unsupported CoCreateInstance clsid={} iid={} clsctx={:#x} outer={:#x}",
                            clsid, iid, clsctx, outer
                        ),
                    ));
                }
            }
            HostThunk::CoTaskMemFree => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace("ole32", "CoTaskMemFree", BTreeMap::new(), json!(0));
            }
            HostThunk::CommandLineToArgvW => {
                let command_line_ptr = guest_call_arg(state, memory, 0)?;
                let argc_ptr = guest_call_arg(state, memory, 1)?;
                let command_line = if command_line_ptr == 0 {
                    self.command_line.clone()
                } else {
                    read_utf16_string(memory, command_line_ptr)?
                };
                let argv = util::split_command_line(&command_line)?;
                let mut argv_values = Vec::with_capacity(argv.len() + 1);
                for arg in &argv {
                    argv_values.push(self.alloc_utf16_string(memory, arg)?);
                }
                argv_values.push(0);
                let argv_array = self.alloc_pointer_array(memory, &argv_values)?;
                if argc_ptr != 0 {
                    write_u32(memory, argc_ptr, argv.len() as u32);
                }
                state.set(Register::Rax, argv_array);
                self.last_error = 0;
                self.push_trace(
                    "shell32",
                    "CommandLineToArgvW",
                    BTreeMap::from([("command_line".to_string(), json!(command_line))]),
                    json!(argv),
                );
            }
            HostThunk::SHGetFileInfoW => {
                let path = guest_call_arg(state, memory, 0)?;
                let info_ptr = guest_call_arg(state, memory, 2)?;
                let info_size = guest_call_arg_u32(state, memory, 3)? as usize;
                let flags = guest_call_arg_u32(state, memory, 4)?;
                if info_ptr != 0 && info_size != 0 {
                    memory.map_bytes(info_ptr, &vec![0; info_size]);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "shell32",
                    "SHGetFileInfoW",
                    BTreeMap::from([
                        ("path".to_string(), json!(if path == 0 { String::new() } else { read_utf16_string(memory, path).unwrap_or_default() })),
                        ("flags".to_string(), json!(flags)),
                    ]),
                    json!(0),
                );
            }
            HostThunk::SHGetFolderPathW => {
                let hwnd = guest_call_arg(state, memory, 0)?;
                let raw_csidl = guest_call_arg(state, memory, 1)? as i32;
                let token = guest_call_arg(state, memory, 2)?;
                let flags = guest_call_arg_u32(state, memory, 3)?;
                let path_buffer = guest_call_arg(state, memory, 4)?;
                if path_buffer == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else if let Some(path) = self.shell_special_folder_path(raw_csidl)? {
                    write_utf16_fixed_buffer(memory, path_buffer, WIN32_FIND_DATAW_FILE_NAME_CHARS, &path);
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                    self.push_trace(
                        "shell32",
                        "SHGetFolderPathW",
                        BTreeMap::from([
                            ("hwnd".to_string(), json!(hwnd)),
                            ("csidl".to_string(), json!(raw_csidl)),
                            ("token".to_string(), json!(token)),
                            ("flags".to_string(), json!(flags)),
                            ("path".to_string(), json!(path)),
                        ]),
                        json!(0),
                    );
                } else {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                }
            }
            HostThunk::SHGetPathFromIDListW => {
                let pidl = guest_call_arg(state, memory, 0)?;
                let path_buffer = guest_call_arg(state, memory, 1)?;
                if pidl == 0 || path_buffer == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let path = read_utf16_string(memory, pidl)?;
                    write_utf16_fixed_buffer(memory, path_buffer, WIN32_FIND_DATAW_FILE_NAME_CHARS, &path);
                    state.set(Register::Rax, 1);
                    self.last_error = 0;
                    self.push_trace(
                        "shell32",
                        "SHGetPathFromIDListW",
                        BTreeMap::from([
                            ("pidl".to_string(), json!(format!("{pidl:#x}"))),
                            ("path".to_string(), json!(path)),
                        ]),
                        json!(1),
                    );
                }
            }
            HostThunk::SHGetSpecialFolderLocation => {
                let hwnd = guest_call_arg(state, memory, 0)?;
                let raw_csidl = guest_call_arg(state, memory, 1)? as i32;
                let pidl_out = guest_call_arg(state, memory, 2)?;
                if pidl_out == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else if let Some(path) = self.shell_special_folder_path(raw_csidl)? {
                    let pidl = self.alloc_utf16_string(memory, &path)?;
                    write_guest_pointer(memory, pidl_out, pidl, self.guest_arch)?;
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                    self.push_trace(
                        "shell32",
                        "SHGetSpecialFolderLocation",
                        BTreeMap::from([
                            ("hwnd".to_string(), json!(hwnd)),
                            ("csidl".to_string(), json!(raw_csidl)),
                            ("path".to_string(), json!(path)),
                            ("pidl_out".to_string(), json!(format!("{pidl_out:#x}"))),
                        ]),
                        json!(0),
                    );
                } else {
                    write_guest_pointer(memory, pidl_out, 0, self.guest_arch)?;
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                }
            }
            HostThunk::ShellLinkQueryInterface => {
                let this = guest_call_arg(state, memory, 0)?;
                let iid_ptr = guest_call_arg(state, memory, 1)?;
                let object_ptr = guest_call_arg(state, memory, 2)?;
                let iid = read_guid_string(memory, iid_ptr)?;
                let result = self.shell_link_query_interface(memory, this, &iid, object_ptr)?;
                state.set(Register::Rax, result);
                self.last_error = 0;
            }
            HostThunk::ShellLinkAddRef => {
                let this = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, self.add_ref_shell_link_object(this)? as u64);
                self.last_error = 0;
            }
            HostThunk::ShellLinkRelease => {
                let this = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, self.release_shell_link_object(this)? as u64);
                self.last_error = 0;
            }
            HostThunk::ShellLinkGetPathW => {
                let this = guest_call_arg(state, memory, 0)?;
                let file_ptr = guest_call_arg(state, memory, 1)?;
                let cch = guest_call_arg_u32(state, memory, 2)?;
                let find_data_ptr = guest_call_arg(state, memory, 3)?;
                let _flags = guest_call_arg_u32(state, memory, 4)?;
                let path = self.shell_link_state_for_interface(this)?.path.clone();
                if find_data_ptr != 0 {
                    memory.map_bytes(find_data_ptr, &vec![0; 592]);
                }
                let written = write_utf16_api_string(memory, file_ptr, cch, &path)?;
                state.set(Register::Rax, written as u64);
                self.last_error = 0;
            }
            HostThunk::ShellLinkGetIDList => {
                let this = guest_call_arg(state, memory, 0)?;
                let out_ptr = guest_call_arg(state, memory, 1)?;
                if out_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let path = self.shell_link_state_for_interface(this)?.path.clone();
                    let pidl = self.alloc_utf16_string(memory, &path)?;
                    write_guest_pointer(memory, out_ptr, pidl, self.guest_arch)?;
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                }
            }
            HostThunk::ShellLinkSetIDList => {
                let this = guest_call_arg(state, memory, 0)?;
                let pidl = guest_call_arg(state, memory, 1)?;
                let value = if pidl == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, pidl)?
                };
                self.set_shell_link_path(this, value)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkGetDescriptionW => {
                let this = guest_call_arg(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let cch = guest_call_arg_u32(state, memory, 2)?;
                let description = self.shell_link_state_for_interface(this)?.description.clone();
                let written = write_utf16_api_string(memory, buffer, cch, &description)?;
                state.set(Register::Rax, written as u64);
                self.last_error = 0;
            }
            HostThunk::ShellLinkSetDescriptionW => {
                let this = guest_call_arg(state, memory, 0)?;
                let value = read_utf16_string(memory, guest_call_arg(state, memory, 1)?)?;
                self.set_shell_link_description(this, value)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkGetWorkingDirectoryW => {
                let this = guest_call_arg(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let cch = guest_call_arg_u32(state, memory, 2)?;
                let working_directory = self.shell_link_state_for_interface(this)?.working_directory.clone();
                let written = write_utf16_api_string(memory, buffer, cch, &working_directory)?;
                state.set(Register::Rax, written as u64);
                self.last_error = 0;
            }
            HostThunk::ShellLinkSetWorkingDirectoryW => {
                let this = guest_call_arg(state, memory, 0)?;
                let raw_value = read_utf16_string(memory, guest_call_arg(state, memory, 1)?)?;
                let value = if raw_value.is_empty() {
                    String::new()
                } else {
                    resolve_guest_path(&self.current_directory, &raw_value)
                };
                self.set_shell_link_working_directory(this, value)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkGetArgumentsW => {
                let this = guest_call_arg(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let cch = guest_call_arg_u32(state, memory, 2)?;
                let arguments = self.shell_link_state_for_interface(this)?.arguments.clone();
                let written = write_utf16_api_string(memory, buffer, cch, &arguments)?;
                state.set(Register::Rax, written as u64);
                self.last_error = 0;
            }
            HostThunk::ShellLinkSetArgumentsW => {
                let this = guest_call_arg(state, memory, 0)?;
                let value = read_utf16_string(memory, guest_call_arg(state, memory, 1)?)?;
                self.set_shell_link_arguments(this, value)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkGetHotkey => {
                let this = guest_call_arg(state, memory, 0)?;
                let out_ptr = guest_call_arg(state, memory, 1)?;
                if out_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let hotkey = self.shell_link_state_for_interface(this)?.hotkey;
                    memory.map_bytes(out_ptr, &hotkey.to_le_bytes());
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                }
            }
            HostThunk::ShellLinkSetHotkey => {
                let this = guest_call_arg(state, memory, 0)?;
                let hotkey = guest_call_arg(state, memory, 1)? as u16;
                let state_ref = self.shell_link_state_for_interface_mut(this)?;
                state_ref.hotkey = hotkey;
                state_ref.dirty = true;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkGetShowCmd => {
                let this = guest_call_arg(state, memory, 0)?;
                let out_ptr = guest_call_arg(state, memory, 1)?;
                if out_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let show_cmd = self.shell_link_state_for_interface(this)?.show_cmd;
                    memory.map_bytes(out_ptr, &show_cmd.to_le_bytes());
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                }
            }
            HostThunk::ShellLinkSetShowCmd => {
                let this = guest_call_arg(state, memory, 0)?;
                let show_cmd = guest_call_arg(state, memory, 1)? as i32;
                self.set_shell_link_show_cmd(this, show_cmd)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkGetIconLocationW => {
                let this = guest_call_arg(state, memory, 0)?;
                let icon_path_ptr = guest_call_arg(state, memory, 1)?;
                let cch = guest_call_arg_u32(state, memory, 2)?;
                let icon_index_ptr = guest_call_arg(state, memory, 3)?;
                let shell_link_state = self.shell_link_state_for_interface(this)?.clone();
                let written = write_utf16_api_string(memory, icon_path_ptr, cch, &shell_link_state.icon_location)?;
                if icon_index_ptr != 0 {
                    memory.map_bytes(icon_index_ptr, &shell_link_state.icon_index.to_le_bytes());
                }
                state.set(Register::Rax, written as u64);
                self.last_error = 0;
            }
            HostThunk::ShellLinkSetIconLocationW => {
                let this = guest_call_arg(state, memory, 0)?;
                let raw_value = read_utf16_string(memory, guest_call_arg(state, memory, 1)?)?;
                let icon_index = guest_call_arg(state, memory, 2)? as i32;
                let value = if raw_value.is_empty() {
                    String::new()
                } else {
                    resolve_guest_path(&self.current_directory, &raw_value)
                };
                self.set_shell_link_icon_location(this, value, icon_index)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkSetRelativePath => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkResolve => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkSetPathW => {
                let this = guest_call_arg(state, memory, 0)?;
                let raw_value = read_utf16_string(memory, guest_call_arg(state, memory, 1)?)?;
                let value = if raw_value.is_empty() {
                    String::new()
                } else {
                    resolve_guest_path(&self.current_directory, &raw_value)
                };
                self.set_shell_link_path(this, value)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkPersistGetClassID => {
                let clsid_ptr = guest_call_arg(state, memory, 1)?;
                if clsid_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    write_shell_link_clsid(memory, clsid_ptr);
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                }
            }
            HostThunk::ShellLinkPersistIsDirty => {
                let this = guest_call_arg(state, memory, 0)?;
                state.set(
                    Register::Rax,
                    if self.shell_link_state_for_interface(this)?.dirty { 0 } else { S_FALSE },
                );
                self.last_error = 0;
            }
            HostThunk::ShellLinkPersistLoad => {
                let this = guest_call_arg(state, memory, 0)?;
                let path_ptr = guest_call_arg(state, memory, 1)?;
                let path = if path_ptr == 0 {
                    String::new()
                } else {
                    resolve_guest_path(&self.current_directory, &read_utf16_string(memory, path_ptr)?)
                };
                let state_ref = self.shell_link_state_for_interface_mut(this)?;
                state_ref.current_file = if path.is_empty() { None } else { Some(path) };
                state_ref.dirty = false;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkPersistSave => {
                let this = guest_call_arg(state, memory, 0)?;
                let path_ptr = guest_call_arg(state, memory, 1)?;
                let remember = guest_call_arg(state, memory, 2)? != 0;
                let requested_path = if path_ptr == 0 {
                    None
                } else {
                    Some(read_utf16_string(memory, path_ptr)?)
                };
                let result = self.save_shell_link(this, requested_path.as_deref(), remember)?;
                state.set(Register::Rax, result);
                self.last_error = 0;
            }
            HostThunk::ShellLinkPersistSaveCompleted => {
                let this = guest_call_arg(state, memory, 0)?;
                let path_ptr = guest_call_arg(state, memory, 1)?;
                let completed_path = if path_ptr == 0 {
                    None
                } else {
                    Some(resolve_guest_path(
                        &self.current_directory,
                        &read_utf16_string(memory, path_ptr)?,
                    ))
                };
                self.complete_shell_link_save(this, completed_path)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ShellLinkPersistGetCurFile => {
                let this = guest_call_arg(state, memory, 0)?;
                let out_ptr = guest_call_arg(state, memory, 1)?;
                if out_ptr == 0 {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let current_file = self
                        .shell_link_state_for_interface(this)?
                        .current_file
                        .clone()
                        .unwrap_or_default();
                    let buffer = self.alloc_utf16_string(memory, &current_file)?;
                    write_guest_pointer(memory, out_ptr, buffer, self.guest_arch)?;
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                }
            }
            HostThunk::WideCharToMultiByte => {
                let code_page = guest_call_arg_u32(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let wide_ptr = guest_call_arg(state, memory, 2)?;
                let wide_len = guest_call_arg(state, memory, 3)? as i32;
                let multi_ptr = guest_call_arg(state, memory, 4)?;
                let multi_len = guest_call_arg(state, memory, 5)? as i32;
                let _default_char_ptr = guest_call_arg(state, memory, 6)?;
                let used_default_ptr = guest_call_arg(state, memory, 7)?;

                if used_default_ptr != 0 {
                    write_u32(memory, used_default_ptr, 0);
                }

                if wide_ptr == 0 && wide_len != 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let normalized_code_page = if code_page == CP_ACP {
                        DEFAULT_ANSI_CODE_PAGE
                    } else {
                        code_page
                    };
                    let wide_units = if wide_len < 0 {
                        read_utf16_string(memory, wide_ptr)?
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect::<Vec<_>>()
                    } else {
                        (0..wide_len as usize)
                            .map(|index| read_guest_u16(memory, wide_ptr + (index as u64 * 2)))
                            .collect::<AppResult<Vec<_>>>()?
                    };
                    match self.win32.wide_char_to_multi_byte(normalized_code_page, &wide_units) {
                        Ok(encoded) => {
                            let required = encoded.len() as u32;
                            if multi_ptr == 0 || multi_len == 0 {
                                state.set(Register::Rax, required as u64);
                                self.last_error = 0;
                            } else if multi_len < required as i32 {
                                state.set(Register::Rax, 0);
                                self.last_error = ERROR_INSUFFICIENT_BUFFER;
                            } else {
                                if !encoded.is_empty() {
                                    memory.map_bytes(multi_ptr, &encoded);
                                }
                                state.set(Register::Rax, required as u64);
                                self.last_error = 0;
                            }
                            self.push_trace(
                                "locale",
                                "WideCharToMultiByte",
                                BTreeMap::from([
                                    ("code_page".to_string(), json!(normalized_code_page)),
                                    ("wide_len".to_string(), json!(wide_len)),
                                    ("multi_len".to_string(), json!(multi_len)),
                                ]),
                                json!(required),
                            );
                        }
                        Err(error) => {
                            state.set(Register::Rax, 0);
                            self.last_error = last_error_from_app_error(&error);
                        }
                    }
                }
            }
            HostThunk::InitializeSListHead => {
                let list_head = guest_call_arg(state, memory, 0)?;
                if list_head != 0 {
                    let header_size = if self.guest_arch == GuestArch::X64 { 16 } else { 8 };
                    memory.map_bytes(list_head, &vec![0; header_size]);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "memory",
                    "InitializeSListHead",
                    BTreeMap::from([("list_head".to_string(), json!(format!("{list_head:#x}")))]),
                    json!(0),
                );
            }
            HostThunk::MultiByteToWideChar => {
                let code_page = guest_call_arg_u32(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let multi_ptr = guest_call_arg(state, memory, 2)?;
                let multi_len = guest_call_arg(state, memory, 3)? as i32;
                let wide_ptr = guest_call_arg(state, memory, 4)?;
                let wide_len = guest_call_arg(state, memory, 5)? as i32;

                if multi_ptr == 0 && multi_len != 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let normalized_code_page = if code_page == CP_ACP {
                        DEFAULT_ANSI_CODE_PAGE
                    } else {
                        code_page
                    };
                    let multi_bytes = if multi_len < 0 {
                        let mut bytes = read_c_string(memory, multi_ptr)?.into_bytes();
                        bytes.push(0);
                        bytes
                    } else {
                        read_window(memory, multi_ptr, multi_len as usize)?
                    };
                    match self.win32.multi_byte_to_wide_char(normalized_code_page, &multi_bytes) {
                        Ok(wide_units) => {
                            let required = wide_units.len() as u32;
                            if wide_ptr == 0 || wide_len == 0 {
                                state.set(Register::Rax, required as u64);
                                self.last_error = 0;
                            } else if wide_len < required as i32 {
                                state.set(Register::Rax, 0);
                                self.last_error = ERROR_INSUFFICIENT_BUFFER;
                            } else {
                                let encoded = wide_units
                                    .iter()
                                    .flat_map(|unit| unit.to_le_bytes())
                                    .collect::<Vec<_>>();
                                if !encoded.is_empty() {
                                    memory.map_bytes(wide_ptr, &encoded);
                                }
                                state.set(Register::Rax, required as u64);
                                self.last_error = 0;
                            }
                            self.push_trace(
                                "locale",
                                "MultiByteToWideChar",
                                BTreeMap::from([
                                    ("code_page".to_string(), json!(normalized_code_page)),
                                    ("multi_len".to_string(), json!(multi_len)),
                                    ("wide_len".to_string(), json!(wide_len)),
                                ]),
                                json!(required),
                            );
                        }
                        Err(error) => {
                            state.set(Register::Rax, 0);
                            self.last_error = last_error_from_app_error(&error);
                        }
                    }
                }
            }
            HostThunk::LstrcmpiW => {
                let left_ptr = guest_call_arg(state, memory, 0)?;
                let right_ptr = guest_call_arg(state, memory, 1)?;
                let left = if left_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, left_ptr)?
                };
                let right = if right_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, right_ptr)?
                };
                let result = match left.to_lowercase().cmp(&right.to_lowercase()) {
                    std::cmp::Ordering::Less => -1_i32,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                if self.guest_arch == GuestArch::X86 {
                    let return_address = read_guest_u32(memory, state.get(Register::Rsp))
                        .ok()
                        .map(u64::from);
                    if return_address == Some(0x401a01) {
                        let record_address = read_guest_u32(memory, state.get(Register::Rbp) + 8)
                            .ok()
                            .map(u64::from);
                        let record_base = read_guest_u32(memory, 0x42a270).ok().map(u64::from);
                        let record_index = record_address.and_then(|address| {
                            record_base.and_then(|base| {
                                address
                                    .checked_sub(base)
                                    .map(|offset| offset / 0x1c)
                            })
                        });
                        if record_index == Some(0x6ac) && result != 0 {
                            return Err(AppError::new(
                                ReasonCode::RcUnimplInsn,
                                format!(
                                    "steam opcode 0x1a compare mismatched for record 0x6ac: left={left:?} right={right:?} result={result}"
                                ),
                            )
                            .with_hint(format!(
                                "steam-0x1a compare record_address={} left_ptr={left_ptr:#x} right_ptr={right_ptr:#x}",
                                record_address
                                    .map(|value| format!("{value:#x}"))
                                    .unwrap_or_else(|| "<unavailable>".to_string())
                            )));
                        }
                    }
                }
                state.set(Register::Rax, result as i64 as u64);
                self.last_error = 0;
            }
            HostThunk::LstrlenW => {
                let string_ptr = guest_call_arg(state, memory, 0)?;
                let length = if string_ptr == 0 {
                    0
                } else {
                    read_utf16_string(memory, string_ptr)?.encode_utf16().count() as u64
                };
                state.set(Register::Rax, length);
                self.last_error = 0;
            }
            HostThunk::LstrcpyA => {
                let destination = guest_call_arg(state, memory, 0)?;
                let source = guest_call_arg(state, memory, 1)?;
                let text = if source == 0 {
                    Vec::new()
                } else {
                    let mut bytes = read_c_string(memory, source)?.into_bytes();
                    bytes.push(0);
                    bytes
                };
                if destination != 0 {
                    memory.map_bytes(destination, &text);
                }
                state.set(Register::Rax, destination);
                self.last_error = 0;
            }
            HostThunk::LstrcpyW => {
                let destination = guest_call_arg(state, memory, 0)?;
                let source = guest_call_arg(state, memory, 1)?;
                let source_text = if source == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, source)?
                };
                let text = if source == 0 {
                    Vec::new()
                } else {
                    let mut bytes = Vec::new();
                    for unit in source_text.encode_utf16() {
                        bytes.extend_from_slice(&unit.to_le_bytes());
                    }
                    bytes.extend_from_slice(&0_u16.to_le_bytes());
                    bytes
                };
                if destination != 0 {
                    memory.map_bytes(destination, &text);
                }
                state.set(Register::Rax, destination);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "lstrcpyW",
                    BTreeMap::from([
                        ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                        ("destination".to_string(), json!(format!("{destination:#x}"))),
                        ("source".to_string(), json!(source_text)),
                    ]),
                    json!(destination),
                );
            }
            HostThunk::LstrcpynW => {
                let destination = guest_call_arg(state, memory, 0)?;
                let source = guest_call_arg(state, memory, 1)?;
                let max_count = guest_call_arg(state, memory, 2)? as usize;
                let source_text = if source == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, source)?
                };
                if destination != 0 && max_count != 0 {
                    let units = source_text.encode_utf16().collect::<Vec<_>>();
                    let copy_count = units.len().min(max_count.saturating_sub(1));
                    let mut bytes = Vec::with_capacity((copy_count + 1) * 2);
                    for unit in units.iter().take(copy_count) {
                        bytes.extend_from_slice(&unit.to_le_bytes());
                    }
                    bytes.extend_from_slice(&0_u16.to_le_bytes());
                    memory.map_bytes(destination, &bytes);
                    self.recent_wide_writes.insert(
                        destination,
                        String::from_utf16_lossy(&units[..copy_count]),
                    );
                }
                state.set(Register::Rax, destination);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "lstrcpynW",
                    BTreeMap::from([
                        ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                        ("destination".to_string(), json!(format!("{destination:#x}"))),
                        ("source".to_string(), json!(source_text)),
                        ("max_count".to_string(), json!(max_count)),
                    ]),
                    json!(destination),
                );
            }
            HostThunk::LstrcatW => {
                let destination = guest_call_arg(state, memory, 0)?;
                let source = guest_call_arg(state, memory, 1)?;
                let destination_before = if destination == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, destination)?
                };
                let source_text = if source == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, source)?
                };
                let mut combined = destination_before.clone();
                if source != 0 {
                    combined.push_str(&source_text);
                }
                if destination != 0 {
                    let mut bytes = Vec::new();
                    for unit in combined.encode_utf16() {
                        bytes.extend_from_slice(&unit.to_le_bytes());
                    }
                    bytes.extend_from_slice(&0_u16.to_le_bytes());
                    memory.map_bytes(destination, &bytes);
                    self.recent_wide_writes.insert(destination, combined.clone());
                }
                state.set(Register::Rax, destination);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "lstrcatW",
                    BTreeMap::from([
                        ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                        ("destination".to_string(), json!(format!("{destination:#x}"))),
                        ("destination_before".to_string(), json!(destination_before)),
                        ("source".to_string(), json!(source_text)),
                    ]),
                    json!(combined),
                );
            }
            HostThunk::GetCommandLineA => {
                if self.command_line_ansi_ptr == 0 {
                    let command_line = self.command_line.clone();
                    self.command_line_ansi_ptr = self.alloc_c_string(memory, &command_line)?;
                }
                state.set(Register::Rax, self.command_line_ansi_ptr);
                self.last_error = 0;
            }
            HostThunk::GetCommandLineW => {
                if self.command_line_wide_ptr == 0 {
                    let command_line = self.command_line.clone();
                    self.command_line_wide_ptr = self.alloc_utf16_string(memory, &command_line)?;
                }
                state.set(Register::Rax, self.command_line_wide_ptr);
                self.last_error = 0;
            }
            HostThunk::GetEnvironmentStringsW => {
                let environment = self.process_environment.clone();
                let address = self.alloc_utf16_environment_block(memory, &environment)?;
                state.set(Register::Rax, address);
                self.last_error = 0;
            }
            HostThunk::FreeEnvironmentStringsW => {
                let address = guest_call_arg(state, memory, 0)?;
                if address != 0 {
                    self.heap_allocations.remove(&address);
                }
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::GetACP => {
                state.set(Register::Rax, u64::from(DEFAULT_ANSI_CODE_PAGE));
                self.last_error = 0;
            }
            HostThunk::IsValidCodePage => {
                let code_page = guest_call_arg_u32(state, memory, 0)?;
                let valid = matches!(code_page, DEFAULT_ANSI_CODE_PAGE | 65001);
                state.set(Register::Rax, if valid { 1 } else { 0 });
                self.last_error = if valid { 0 } else { ERROR_INVALID_PARAMETER };
            }
            HostThunk::GetCPInfo => {
                let code_page = guest_call_arg_u32(state, memory, 0)?;
                let cp_info = guest_call_arg(state, memory, 1)?;
                let max_char_size = match code_page {
                    DEFAULT_ANSI_CODE_PAGE => Some(1_u32),
                    65001 => Some(4_u32),
                    _ => None,
                };
                if let Some(max_char_size) = max_char_size {
                    if cp_info != 0 {
                        write_u32(memory, cp_info, max_char_size);
                        memory.map_bytes(cp_info + 4, &[b'?', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                    }
                    state.set(Register::Rax, 1);
                    self.last_error = 0;
                } else {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                }
            }
            HostThunk::GetStringTypeW => {
                let info_type = guest_call_arg_u32(state, memory, 0)?;
                let string_ptr = guest_call_arg(state, memory, 1)?;
                let char_count = guest_call_arg(state, memory, 2)? as i32;
                let output_ptr = guest_call_arg(state, memory, 3)?;

                if string_ptr == 0 || output_ptr == 0 || char_count == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else if !matches!(info_type, CT_CTYPE1 | CT_CTYPE2 | CT_CTYPE3) {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let wide_units = if char_count < 0 {
                        read_utf16_string(memory, string_ptr)?
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect::<Vec<_>>()
                    } else {
                        (0..char_count as usize)
                            .map(|index| read_guest_u16(memory, string_ptr + (index as u64 * 2)))
                            .collect::<AppResult<Vec<_>>>()?
                    };
                    let classifications = wide_units
                        .into_iter()
                        .map(|unit| classify_wide_char_type(info_type, unit))
                        .flat_map(|mask| mask.to_le_bytes())
                        .collect::<Vec<_>>();
                    if !classifications.is_empty() {
                        memory.map_bytes(output_ptr, &classifications);
                    }
                    state.set(Register::Rax, 1);
                    self.last_error = 0;
                }
            }
            HostThunk::LCMapStringW => {
                let _locale = guest_call_arg_u32(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let source_ptr = guest_call_arg(state, memory, 2)?;
                let source_len = guest_call_arg(state, memory, 3)? as i32;
                let destination_ptr = guest_call_arg(state, memory, 4)?;
                let destination_len = guest_call_arg(state, memory, 5)? as i32;

                if source_ptr == 0 || source_len == 0 || (flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE)) == (LCMAP_LOWERCASE | LCMAP_UPPERCASE) {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let source_units = if source_len < 0 {
                        read_utf16_string(memory, source_ptr)?
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect::<Vec<_>>()
                    } else {
                        (0..source_len as usize)
                            .map(|index| read_guest_u16(memory, source_ptr + (index as u64 * 2)))
                            .collect::<AppResult<Vec<_>>>()?
                    };
                    let mapped_units = if flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE) != 0 {
                        source_units
                            .iter()
                            .copied()
                            .map(|unit| {
                                let Some(original) = char::from_u32(unit as u32) else {
                                    return unit;
                                };
                                let mapped = if flags & LCMAP_UPPERCASE != 0 {
                                    original.to_uppercase().collect::<Vec<_>>()
                                } else {
                                    original.to_lowercase().collect::<Vec<_>>()
                                };
                                let Some(&candidate) = mapped.first() else {
                                    return unit;
                                };
                                if mapped.len() != 1 {
                                    return unit;
                                }
                                let mut encoded = [0_u16; 2];
                                if candidate.encode_utf16(&mut encoded).len() != 1 {
                                    return unit;
                                }
                                if self
                                    .win32
                                    .wide_char_to_multi_byte(DEFAULT_ANSI_CODE_PAGE, &encoded[..1])
                                    .is_err()
                                {
                                    return unit;
                                }
                                encoded[0]
                            })
                            .collect::<Vec<_>>()
                    } else {
                        source_units.clone()
                    };
                    let required = mapped_units.len() as u32;
                    if destination_ptr == 0 || destination_len == 0 {
                        state.set(Register::Rax, required as u64);
                        self.last_error = 0;
                    } else if destination_len < required as i32 {
                        state.set(Register::Rax, 0);
                        self.last_error = ERROR_INSUFFICIENT_BUFFER;
                    } else {
                        let encoded = mapped_units
                            .iter()
                            .flat_map(|unit| unit.to_le_bytes())
                            .collect::<Vec<_>>();
                        if !encoded.is_empty() {
                            memory.map_bytes(destination_ptr, &encoded);
                            self.recent_wide_writes
                                .insert(destination_ptr, String::from_utf16_lossy(&mapped_units));
                        }
                        state.set(Register::Rax, required as u64);
                        self.last_error = 0;
                    }
                }
            }
            HostThunk::CharNextW => {
                let current = guest_call_arg(state, memory, 0)?;
                let next = if current == 0
                    || u16::from_le_bytes([memory.read_u8(current)?, memory.read_u8(current + 1)?]) == 0
                {
                    current
                } else {
                    current + 2
                };
                state.set(Register::Rax, next);
                self.last_error = 0;
            }
            HostThunk::CharPrevW => {
                let start = guest_call_arg(state, memory, 0)?;
                let current = guest_call_arg(state, memory, 1)?;
                let previous = if current <= start {
                    start
                } else {
                    current - 2
                };
                state.set(Register::Rax, previous);
                self.last_error = 0;
            }
            HostThunk::CreateDirectoryW => {
                let path = resolve_guest_path(
                    &self.current_directory,
                    &read_utf16_string(memory, guest_call_arg(state, memory, 0)?)?,
                );
                match self.win32.create_directory_w(&path) {
                    Ok(created_path) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "CreateDirectoryW",
                            BTreeMap::from([("path".to_string(), json!(created_path))]),
                            json!(1),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::RemoveDirectoryW => {
                let path = resolve_guest_path(
                    &self.current_directory,
                    &read_utf16_string(memory, guest_call_arg(state, memory, 0)?)?,
                );
                match self.win32.remove_directory_w(&path) {
                    Ok(()) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "RemoveDirectoryW",
                            BTreeMap::from([("path".to_string(), json!(path))]),
                            json!(1),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::DeleteFileW => {
                let path = resolve_guest_path(
                    &self.current_directory,
                    &read_utf16_string(memory, guest_call_arg(state, memory, 0)?)?,
                );
                match self.win32.delete_file_w(&path) {
                    Ok(()) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "DeleteFileW",
                            BTreeMap::from([("path".to_string(), json!(path))]),
                            json!(1),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::WritePrivateProfileStringW => {
                let section_ptr = guest_call_arg(state, memory, 0)?;
                let key_ptr = guest_call_arg(state, memory, 1)?;
                let value_ptr = guest_call_arg(state, memory, 2)?;
                let file_ptr = guest_call_arg(state, memory, 3)?;
                let result = (|| -> AppResult<String> {
                    if file_ptr == 0 {
                        return Err(AppError::new(
                            ReasonCode::RcFsNotFound,
                            "WritePrivateProfileStringW requires a file path",
                        ));
                    }
                    if section_ptr == 0 && (key_ptr != 0 || value_ptr != 0) {
                        return Err(AppError::new(
                            ReasonCode::RcCliInvalid,
                            "WritePrivateProfileStringW requires a section when key or value is present",
                        ));
                    }
                    let path = resolve_guest_path(
                        &self.current_directory,
                        &read_utf16_string(memory, file_ptr)?,
                    );
                    if section_ptr == 0 && key_ptr == 0 && value_ptr == 0 {
                        return Ok(path);
                    }
                    if let Some(parent) = windows_parent_directory(&path) {
                        self.ensure_guest_directory_path(&parent)?;
                    }
                    let section = read_utf16_string(memory, section_ptr)?;
                    let key = if key_ptr == 0 {
                        None
                    } else {
                        Some(read_utf16_string(memory, key_ptr)?)
                    };
                    let value = if value_ptr == 0 {
                        None
                    } else {
                        Some(read_utf16_string(memory, value_ptr)?)
                    };
                    let host_path = self.win32.guest_path_to_host_path(&path)?;
                    let (mut ini_sections, prefer_utf16) = read_ini_document(&host_path)?;
                    update_ini_document(&mut ini_sections, &section, key.as_deref(), value.as_deref());
                    let bytes = serialize_ini_document(&ini_sections, prefer_utf16);
                    self.win32.write_file_overwrite_w(&path, &bytes)?;
                    Ok(path)
                })();
                match result {
                    Ok(path) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "WritePrivateProfileStringW",
                            BTreeMap::from([
                                ("path".to_string(), json!(path)),
                                (
                                    "section".to_string(),
                                    json!(if section_ptr == 0 {
                                        String::new()
                                    } else {
                                        read_utf16_string(memory, section_ptr).unwrap_or_default()
                                    }),
                                ),
                                (
                                    "key".to_string(),
                                    json!(if key_ptr == 0 {
                                        String::new()
                                    } else {
                                        read_utf16_string(memory, key_ptr).unwrap_or_default()
                                    }),
                                ),
                            ]),
                            json!(1),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::CreateProcessW => {
                let application_name_ptr = guest_call_arg(state, memory, 0)?;
                let command_line_ptr = guest_call_arg(state, memory, 1)?;
                let inherit_handles = guest_call_arg_u32(state, memory, 4)? != 0;
                let environment_ptr = guest_call_arg(state, memory, 6)?;
                let current_directory_ptr = guest_call_arg(state, memory, 7)?;
                let process_information_ptr = guest_call_arg(state, memory, 9)?;
                if process_information_ptr == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                    self.push_trace(
                        "process",
                        "CreateProcessW",
                        BTreeMap::from([("failure".to_string(), json!("null PROCESS_INFORMATION"))]),
                        json!(0),
                    );
                    return Ok(None);
                }

                let application_name = if application_name_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, application_name_ptr)?
                };
                let command_line = if command_line_ptr == 0 {
                    application_name.clone()
                } else {
                    read_utf16_string(memory, command_line_ptr)?
                };
                let guest_application = if !application_name.is_empty() {
                    resolve_guest_path(&self.current_directory, &application_name)
                } else {
                    let argv = util::split_command_line(&command_line)?;
                    let Some(program) = argv.first() else {
                        state.set(Register::Rax, 0);
                        self.last_error = ERROR_INVALID_PARAMETER;
                        self.push_trace(
                            "process",
                            "CreateProcessW",
                            BTreeMap::from([("failure".to_string(), json!("empty command line"))]),
                            json!(0),
                        );
                        return Ok(None);
                    };
                    resolve_guest_path(&self.current_directory, program)
                };
                let guest_cwd = if current_directory_ptr == 0 {
                    self.current_directory.clone()
                } else {
                    resolve_guest_path(&self.current_directory, &read_utf16_string(memory, current_directory_ptr)?)
                };
                let environment = if environment_ptr == 0 {
                    self.process_environment.clone()
                } else {
                    read_utf16_environment_block(memory, environment_ptr)?
                };
                let result = self.launch_guest_child_process(
                    &guest_application,
                    &command_line,
                    &environment,
                    &guest_cwd,
                    inherit_handles,
                )?;
                write_guest_pointer(
                    memory,
                    process_information_ptr,
                    u64::from(result.process_handle),
                    self.guest_arch,
                )?;
                write_guest_pointer(
                    memory,
                    process_information_ptr + self.guest_arch.pointer_bytes() as u64,
                    u64::from(result.thread_handle),
                    self.guest_arch,
                )?;
                write_u32(
                    memory,
                    process_information_ptr + (self.guest_arch.pointer_bytes() as u64 * 2),
                    result.process_id,
                );
                write_u32(
                    memory,
                    process_information_ptr + (self.guest_arch.pointer_bytes() as u64 * 2) + 4,
                    result.thread_id,
                );
                state.set(Register::Rax, 1);
                self.last_error = 0;
                let exit_code = self
                    .win32
                    .process_state(result.process_handle)?
                    .exit_code
                    .unwrap_or(STILL_ACTIVE);
                self.push_trace(
                    "process",
                    "CreateProcessW",
                    BTreeMap::from([
                        ("application".to_string(), json!(guest_application)),
                        ("command_line".to_string(), json!(command_line)),
                        ("cwd".to_string(), json!(guest_cwd)),
                    ]),
                    json!(exit_code),
                );
            }
            HostThunk::CreateEventW => {
                let security_attributes_ptr = guest_call_arg(state, memory, 0)?;
                let manual_reset = guest_call_arg_u32(state, memory, 1)? != 0;
                let initial_state = guest_call_arg_u32(state, memory, 2)? != 0;
                let _name_ptr = guest_call_arg(state, memory, 3)?;
                let inherit_offset = if self.guest_arch == GuestArch::X64 { 16 } else { 8 };
                let inheritable = if security_attributes_ptr == 0 {
                    false
                } else {
                    read_u32(memory, security_attributes_ptr + inherit_offset)? != 0
                };
                let handle = self.win32.create_event(manual_reset, initial_state, inheritable);
                state.set(Register::Rax, u64::from(handle));
                self.last_error = 0;
                self.push_trace(
                    "sync",
                    "CreateEventW",
                    BTreeMap::from([
                        ("manual_reset".to_string(), json!(manual_reset)),
                        ("initial_state".to_string(), json!(initial_state)),
                        ("inheritable".to_string(), json!(inheritable)),
                    ]),
                    json!(handle),
                );
            }
            HostThunk::SetEvent => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                match self.win32.set_event(handle) {
                    Ok(()) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::ResetEvent => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                match self.win32.reset_event(handle) {
                    Ok(()) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::IsDebuggerPresent => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::InitOnceBeginInitialize => {
                let init_once = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let pending_ptr = guest_call_arg(state, memory, 2)?;
                let context_ptr_ptr = guest_call_arg(state, memory, 3)?;
                let pending = !self.init_once_completed.contains_key(&init_once);
                if pending && flags & INIT_ONCE_CHECK_ONLY == 0 {
                    self.init_once_pending.insert(init_once);
                }
                if pending_ptr != 0 {
                    write_u32(memory, pending_ptr, u32::from(pending));
                }
                if context_ptr_ptr != 0 {
                    let context = self.init_once_completed.get(&init_once).copied().unwrap_or(0);
                    write_guest_pointer(memory, context_ptr_ptr, context, self.guest_arch)?;
                }
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::InitOnceComplete => {
                let init_once = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let context = guest_call_arg(state, memory, 2)?;
                self.init_once_pending.remove(&init_once);
                if flags & INIT_ONCE_INIT_FAILED != 0 {
                    self.init_once_completed.remove(&init_once);
                } else {
                    self.init_once_completed.insert(init_once, context);
                }
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::InitializeSRWLock => {
                let lock = guest_call_arg(state, memory, 0)?;
                self.srw_locks.insert(lock, 0);
                write_guest_pointer(memory, lock, 0, self.guest_arch)?;
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::AcquireSRWLockExclusive => {
                let lock = guest_call_arg(state, memory, 0)?;
                self.srw_locks.insert(lock, -1);
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ReleaseSRWLockExclusive => {
                let lock = guest_call_arg(state, memory, 0)?;
                self.srw_locks.insert(lock, 0);
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::AcquireSRWLockShared => {
                let lock = guest_call_arg(state, memory, 0)?;
                let readers = self.srw_locks.get(&lock).copied().unwrap_or(0).max(0) + 1;
                self.srw_locks.insert(lock, readers);
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::ReleaseSRWLockShared => {
                let lock = guest_call_arg(state, memory, 0)?;
                let readers = self.srw_locks.get(&lock).copied().unwrap_or(1).max(1) - 1;
                self.srw_locks.insert(lock, readers);
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::TryAcquireSRWLockExclusive => {
                let lock = guest_call_arg(state, memory, 0)?;
                self.srw_locks.insert(lock, -1);
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::TryAcquireSRWLockShared => {
                let lock = guest_call_arg(state, memory, 0)?;
                let readers = self.srw_locks.get(&lock).copied().unwrap_or(0).max(0) + 1;
                self.srw_locks.insert(lock, readers);
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::WaitForSingleObject => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let timeout = guest_call_arg_u32(state, memory, 1)?;
                let result = self.win32.wait_for_single_object(handle, timeout, false, None)?;
                state.set(Register::Rax, u64::from(result.code()));
                self.last_error = 0;
                self.push_trace(
                    "process",
                    "WaitForSingleObject",
                    BTreeMap::from([
                        ("handle".to_string(), json!(format!("{handle:#x}"))),
                        ("timeout_ms".to_string(), json!(timeout)),
                    ]),
                    json!(result.code()),
                );
            }
            HostThunk::GetExitCodeProcess => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let exit_code_ptr = guest_call_arg(state, memory, 1)?;
                let exit_code = self.win32.process_state(handle)?.exit_code.unwrap_or(STILL_ACTIVE);
                if exit_code_ptr != 0 {
                    write_u32(memory, exit_code_ptr, exit_code);
                }
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace(
                    "process",
                    "GetExitCodeProcess",
                    BTreeMap::from([("handle".to_string(), json!(format!("{handle:#x}")))]),
                    json!(exit_code),
                );
            }
            HostThunk::CreateFileW => {
                let path_ptr = guest_call_arg(state, memory, 0)?;
                let raw_path = read_utf16_string(memory, path_ptr)?;
                let recovered_raw_path = if return_address == 0x405d7f {
                    windows_drive_prefix(&raw_path)
                        .filter(|_| raw_path[2..].is_empty())
                        .and_then(|drive_prefix| self.recent_wide_writes.get(&path_ptr).cloned().filter(|candidate| {
                            candidate.len() > raw_path.len()
                                && windows_drive_prefix(candidate)
                                    .map(|candidate_drive| candidate_drive.eq_ignore_ascii_case(drive_prefix))
                                    .unwrap_or(false)
                        }))
                } else {
                    None
                };
                let effective_raw_path = recovered_raw_path.as_deref().unwrap_or(&raw_path);
                let path = resolve_guest_path(&self.current_directory, effective_raw_path);
                let desired_access_raw = guest_call_arg_u32(state, memory, 1)?;
                let share_mode_raw = guest_call_arg_u32(state, memory, 2)?;
                let security_attributes = guest_call_arg(state, memory, 3)?;
                let creation_raw = guest_call_arg_u32(state, memory, 4)?;
                let flags_and_attributes = guest_call_arg_u32(state, memory, 5)?;
                let template_file = guest_call_arg(state, memory, 6)?;
                let desired_access = file_access_from_win32(desired_access_raw);
                let share_mode = share_mode_from_win32(share_mode_raw);

                if security_attributes != 0 || template_file != 0 {
                    state.set(Register::Rax, INVALID_HANDLE_VALUE);
                    self.last_error = ERROR_INVALID_PARAMETER;
                    self.push_trace(
                        "file",
                        "CreateFileW",
                        BTreeMap::from([
                            ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                            ("path_ptr".to_string(), json!(format!("{path_ptr:#x}"))),
                            ("path_raw".to_string(), json!(raw_path.clone())),
                            ("path_recovered".to_string(), json!(recovered_raw_path.clone())),
                            ("path".to_string(), json!(path.clone())),
                            ("cwd".to_string(), json!(self.current_directory.clone())),
                            ("desired_access".to_string(), json!(desired_access_raw)),
                            ("share_mode".to_string(), json!(share_mode_raw)),
                            ("creation_disposition".to_string(), json!(creation_raw)),
                            ("error".to_string(), json!(ERROR_INVALID_PARAMETER)),
                        ]),
                        json!(INVALID_HANDLE_VALUE),
                    );
                } else {
                    match creation_disposition_from_win32(creation_raw).and_then(|creation| {
                        self.win32.create_file_w(
                            &path,
                            desired_access,
                            share_mode,
                            creation,
                            false,
                            flags_and_attributes & FILE_FLAG_OVERLAPPED != 0,
                            flags_and_attributes & FILE_FLAG_BACKUP_SEMANTICS != 0,
                        )
                    }) {
                        Ok(handle) => {
                            state.set(Register::Rax, handle as u64);
                            self.last_error = 0;
                            self.push_trace(
                                "file",
                                "CreateFileW",
                                BTreeMap::from([
                                    ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                                    ("path_ptr".to_string(), json!(format!("{path_ptr:#x}"))),
                                    ("path_raw".to_string(), json!(raw_path)),
                                    ("path_recovered".to_string(), json!(recovered_raw_path.clone())),
                                    ("path".to_string(), json!(path)),
                                    ("cwd".to_string(), json!(self.current_directory.clone())),
                                    ("desired_access".to_string(), json!(desired_access_raw)),
                                    ("share_mode".to_string(), json!(share_mode_raw)),
                                    ("creation_disposition".to_string(), json!(creation_raw)),
                                ]),
                                json!(handle),
                            );
                        }
                        Err(error) => {
                            state.set(Register::Rax, INVALID_HANDLE_VALUE);
                            self.last_error = last_error_from_app_error(&error);
                            self.push_trace(
                                "file",
                                "CreateFileW",
                                BTreeMap::from([
                                    ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                                    ("path_ptr".to_string(), json!(format!("{path_ptr:#x}"))),
                                    ("path_raw".to_string(), json!(raw_path)),
                                    ("path_recovered".to_string(), json!(recovered_raw_path)),
                                    ("path".to_string(), json!(path)),
                                    ("cwd".to_string(), json!(self.current_directory.clone())),
                                    ("desired_access".to_string(), json!(desired_access_raw)),
                                    ("share_mode".to_string(), json!(share_mode_raw)),
                                    ("creation_disposition".to_string(), json!(creation_raw)),
                                    ("error".to_string(), json!(self.last_error)),
                                ]),
                                json!(INVALID_HANDLE_VALUE),
                            );
                        }
                    }
                }
            }
            HostThunk::RegCreateKeyExW => {
                let hkey = guest_call_arg_u32(state, memory, 0)?;
                let subkey_ptr = guest_call_arg(state, memory, 1)?;
                let _reserved = guest_call_arg_u32(state, memory, 2)?;
                let _class_ptr = guest_call_arg(state, memory, 3)?;
                let _options = guest_call_arg_u32(state, memory, 4)?;
                let sam_desired = guest_call_arg_u32(state, memory, 5)?;
                let _security_attributes_ptr = guest_call_arg(state, memory, 6)?;
                let result_ptr = guest_call_arg(state, memory, 7)?;
                let disposition_ptr = guest_call_arg(state, memory, 8)?;

                if result_ptr == 0 {
                    state.set(Register::Rax, ERROR_INVALID_PARAMETER as u64);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let subkey = if subkey_ptr == 0 {
                        String::new()
                    } else {
                        read_utf16_string(memory, subkey_ptr)?
                    };
                    let view = registry_view_from_sam_desired(sam_desired, self.guest_arch);
                    match resolve_registry_root_key(&self.win32, hkey, view).and_then(|(hive, base_key, key_view)| {
                        let full_key = normalize_registry_runtime_key(&hive, &join_registry_subkey(&base_key, &subkey));
                        let created = if full_key.is_empty() {
                            false
                        } else {
                            self.win32.create_registry_key(&hive, &full_key, key_view)?
                        };
                        Ok((hive, full_key, key_view, created))
                    }) {
                        Ok((hive, full_key, key_view, created)) => {
                            let handle = self.win32.open_registry_key(&hive, &full_key, key_view, false);
                            write_u32(memory, result_ptr, handle);
                            if disposition_ptr != 0 {
                                write_u32(
                                    memory,
                                    disposition_ptr,
                                    if created {
                                        REG_CREATED_NEW_KEY
                                    } else {
                                        REG_OPENED_EXISTING_KEY
                                    },
                                );
                            }
                            state.set(Register::Rax, 0);
                            self.last_error = 0;
                            self.push_trace(
                                "registry",
                                "RegCreateKeyExW",
                                BTreeMap::from([
                                    ("hive".to_string(), json!(hive)),
                                    ("subkey".to_string(), json!(full_key)),
                                    ("sam_desired".to_string(), json!(sam_desired)),
                                    (
                                        "disposition".to_string(),
                                        json!(if created {
                                            REG_CREATED_NEW_KEY
                                        } else {
                                            REG_OPENED_EXISTING_KEY
                                        }),
                                    ),
                                ]),
                                json!(handle),
                            );
                        }
                        Err(error) => {
                            write_u32(memory, result_ptr, 0);
                            if disposition_ptr != 0 {
                                write_u32(memory, disposition_ptr, 0);
                            }
                            let status = last_error_from_app_error(&error);
                            state.set(Register::Rax, status as u64);
                            self.last_error = status;
                        }
                    }
                }
            }
            HostThunk::RegOpenKeyExW => {
                let hkey = guest_call_arg_u32(state, memory, 0)?;
                let subkey_ptr = guest_call_arg(state, memory, 1)?;
                let _options = guest_call_arg_u32(state, memory, 2)?;
                let sam_desired = guest_call_arg_u32(state, memory, 3)?;
                let result_ptr = guest_call_arg(state, memory, 4)?;

                if result_ptr == 0 {
                    state.set(Register::Rax, ERROR_INVALID_PARAMETER as u64);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let subkey = if subkey_ptr == 0 {
                        String::new()
                    } else {
                        read_utf16_string(memory, subkey_ptr)?
                    };
                    let view = registry_view_from_sam_desired(sam_desired, self.guest_arch);
                    match resolve_registry_root_key(&self.win32, hkey, view).and_then(|(hive, base_key, key_view)| {
                        let full_key = normalize_registry_runtime_key(&hive, &join_registry_subkey(&base_key, &subkey));
                        let exists = full_key.is_empty() || self.win32.registry_key_exists(&hive, &full_key, key_view)?;
                        if exists {
                            Ok((hive, full_key, key_view))
                        } else {
                            Err(AppError::new(ReasonCode::RcFsNotFound, "registry key not found"))
                        }
                    }) {
                        Ok((hive, full_key, key_view)) => {
                            let handle = self.win32.open_registry_key(&hive, &full_key, key_view, false);
                            write_u32(memory, result_ptr, handle);
                            state.set(Register::Rax, 0);
                            self.last_error = 0;
                            self.push_trace(
                                "registry",
                                "RegOpenKeyExW",
                                BTreeMap::from([
                                    ("hive".to_string(), json!(hive)),
                                    ("subkey".to_string(), json!(full_key)),
                                    ("sam_desired".to_string(), json!(sam_desired)),
                                ]),
                                json!(handle),
                            );
                        }
                        Err(error) => {
                            write_u32(memory, result_ptr, 0);
                            let status = last_error_from_app_error(&error);
                            state.set(Register::Rax, status as u64);
                            self.last_error = status;
                        }
                    }
                }
            }
            HostThunk::RegSetValueExW => {
                let hkey = guest_call_arg_u32(state, memory, 0)?;
                let value_name_ptr = guest_call_arg(state, memory, 1)?;
                let reserved = guest_call_arg_u32(state, memory, 2)?;
                let value_type = guest_call_arg_u32(state, memory, 3)?;
                let data_ptr = guest_call_arg(state, memory, 4)?;
                let data_len = guest_call_arg_u32(state, memory, 5)?;

                if reserved != 0 || (data_ptr == 0 && data_len != 0) {
                    state.set(Register::Rax, ERROR_INVALID_PARAMETER as u64);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let value_name = if value_name_ptr == 0 {
                        String::new()
                    } else {
                        read_utf16_string(memory, value_name_ptr)?
                    };
                    let (hive, key_path, key_view) = resolve_registry_root_key(
                        &self.win32,
                        hkey,
                        registry_view_from_sam_desired(0, self.guest_arch),
                    )?;
                    let normalized_key = normalize_registry_runtime_key(&hive, &key_path);
                    match decode_registry_value_data(memory, data_ptr, data_len, value_type).and_then(|(kind, data)| {
                        self.win32
                            .ge()
                            .registry_set_value(&hive, &normalized_key, &value_name, &kind, data, key_view)
                    }) {
                        Ok(()) => {
                            state.set(Register::Rax, 0);
                            self.last_error = 0;
                            self.push_trace(
                                "registry",
                                "RegSetValueExW",
                                BTreeMap::from([
                                    ("hive".to_string(), json!(hive)),
                                    ("subkey".to_string(), json!(normalized_key)),
                                    ("value_name".to_string(), json!(value_name)),
                                    ("value_type".to_string(), json!(value_type)),
                                ]),
                                json!(0),
                            );
                        }
                        Err(error) => {
                            let status = last_error_from_app_error(&error);
                            state.set(Register::Rax, status as u64);
                            self.last_error = status;
                        }
                    }
                }
            }
            HostThunk::RegQueryValueExW => {
                let hkey = guest_call_arg_u32(state, memory, 0)?;
                let value_name_ptr = guest_call_arg(state, memory, 1)?;
                let reserved_ptr = guest_call_arg(state, memory, 2)?;
                let value_type_ptr = guest_call_arg(state, memory, 3)?;
                let data_ptr = guest_call_arg(state, memory, 4)?;
                let data_len_ptr = guest_call_arg(state, memory, 5)?;

                if reserved_ptr != 0 || data_len_ptr == 0 {
                    state.set(Register::Rax, ERROR_INVALID_PARAMETER as u64);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let value_name = if value_name_ptr == 0 {
                        String::new()
                    } else {
                        read_utf16_string(memory, value_name_ptr)?
                    };
                    let (hive, key_path, key_view) = resolve_registry_root_key(
                        &self.win32,
                        hkey,
                        registry_view_from_sam_desired(0, self.guest_arch),
                    )?;
                    let normalized_key = normalize_registry_runtime_key(&hive, &key_path);
                    match self
                        .win32
                        .registry_get_value(&hive, &normalized_key, &value_name, key_view)?
                    {
                        Some(value) => {
                            let type_code = registry_value_type_to_win32(&value.value_type)?;
                            let encoded = encode_registry_value_data(&value)?;
                            let buffer_capacity = read_u32(memory, data_len_ptr)?;
                            write_u32(memory, data_len_ptr, encoded.len() as u32);
                            if value_type_ptr != 0 {
                                write_u32(memory, value_type_ptr, type_code);
                            }
                            if data_ptr != 0 && buffer_capacity < encoded.len() as u32 {
                                state.set(Register::Rax, ERROR_MORE_DATA as u64);
                                self.last_error = ERROR_MORE_DATA;
                            } else {
                                if data_ptr != 0 && !encoded.is_empty() {
                                    memory.map_bytes(data_ptr, &encoded);
                                }
                                state.set(Register::Rax, 0);
                                self.last_error = 0;
                                self.push_trace(
                                    "registry",
                                    "RegQueryValueExW",
                                    BTreeMap::from([
                                        ("hive".to_string(), json!(hive)),
                                        ("subkey".to_string(), json!(normalized_key)),
                                        ("value_name".to_string(), json!(value_name)),
                                    ]),
                                    json!(value.data),
                                );
                            }
                        }
                        None => {
                            write_u32(memory, data_len_ptr, 0);
                            if value_type_ptr != 0 {
                                write_u32(memory, value_type_ptr, 0);
                            }
                            state.set(Register::Rax, ERROR_FILE_NOT_FOUND as u64);
                            self.last_error = ERROR_FILE_NOT_FOUND;
                        }
                    }
                }
            }
            HostThunk::RegCloseKey => {
                let hkey = guest_call_arg_u32(state, memory, 0)?;
                let status = match hkey {
                    HKEY_CLASSES_ROOT | HKEY_CURRENT_USER | HKEY_LOCAL_MACHINE | HKEY_USERS | HKEY_CURRENT_CONFIG => {
                        0
                    }
                    _ => match self.win32.close_handle(hkey) {
                        Ok(()) => 0,
                        Err(error) => last_error_from_app_error(&error),
                    },
                };
                state.set(Register::Rax, status as u64);
                self.last_error = status;
                if status == 0 {
                    self.push_trace(
                        "registry",
                        "RegCloseKey",
                        BTreeMap::from([("handle".to_string(), json!(hkey))]),
                        json!(0),
                    );
                }
            }
            HostThunk::SetFilePointer => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let distance_low = guest_call_arg(state, memory, 1)? as u32;
                let distance_high_ptr = guest_call_arg(state, memory, 2)?;
                let move_method = guest_call_arg_u32(state, memory, 3)?;

                let distance_high = if distance_high_ptr == 0 {
                    (distance_low as i32 as i64 >> 32) as i32
                } else {
                    read_guest_i32(memory, distance_high_ptr)?
                };
                let distance = ((distance_high as i64) << 32) | distance_low as i64;
                let origin = match move_method {
                    0 => Ok(SeekOrigin::Begin),
                    1 => Ok(SeekOrigin::Current),
                    2 => Ok(SeekOrigin::End),
                    _ => Err(AppError::new(
                        ReasonCode::RcCliInvalid,
                        format!("unsupported SetFilePointer move method {move_method}"),
                    )),
                };

                match origin.and_then(|origin| self.win32.set_file_pointer_ex(handle, distance, origin)) {
                    Ok(position) => {
                        if distance_high_ptr != 0 {
                            write_u32(memory, distance_high_ptr, (position >> 32) as u32);
                        }
                        state.set(Register::Rax, position as u32 as u64);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "SetFilePointer",
                            BTreeMap::from([
                                ("handle".to_string(), json!(handle)),
                                ("distance".to_string(), json!(distance)),
                                ("move_method".to_string(), json!(move_method)),
                            ]),
                            json!(position),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, INVALID_SET_FILE_POINTER);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::CompareFileTime => {
                let left = read_filetime(memory, guest_call_arg(state, memory, 0)?)?;
                let right = read_filetime(memory, guest_call_arg(state, memory, 1)?)?;
                let result = match left.cmp(&right) {
                    std::cmp::Ordering::Less => -1_i32,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                };
                state.set(Register::Rax, result as i64 as u64);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "CompareFileTime",
                    BTreeMap::from([
                        ("left".to_string(), json!(left)),
                        ("right".to_string(), json!(right)),
                    ]),
                    json!(result),
                );
            }
            HostThunk::SetFileTime => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let creation_time_ticks = read_optional_filetime(memory, guest_call_arg(state, memory, 1)?)?;
                let last_access_time_ticks = read_optional_filetime(memory, guest_call_arg(state, memory, 2)?)?;
                let last_write_time_ticks = read_optional_filetime(memory, guest_call_arg(state, memory, 3)?)?;
                match self.win32.set_file_time(
                    handle,
                    creation_time_ticks,
                    last_access_time_ticks,
                    last_write_time_ticks,
                ) {
                    Ok(()) => {
                        state.set(Register::Rax, 1);
                        self.last_error = 0;
                        self.push_trace(
                            "file",
                            "SetFileTime",
                            BTreeMap::from([
                                ("handle".to_string(), json!(handle)),
                                ("creation_time_ticks".to_string(), json!(creation_time_ticks)),
                                (
                                    "last_access_time_ticks".to_string(),
                                    json!(last_access_time_ticks),
                                ),
                                ("last_write_time_ticks".to_string(), json!(last_write_time_ticks)),
                            ]),
                            json!(1),
                        );
                    }
                    Err(error) => {
                        state.set(Register::Rax, 0);
                        self.last_error = last_error_from_app_error(&error);
                    }
                }
            }
            HostThunk::ReadFile => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let buffer_ptr = guest_call_arg(state, memory, 1)?;
                let length = guest_call_arg(state, memory, 2)? as usize;
                let bytes_read_ptr = guest_call_arg(state, memory, 3)?;
                let overlapped = guest_call_arg(state, memory, 4)?;

                if handle == STD_INPUT_HANDLE {
                    if bytes_read_ptr != 0 {
                        write_u32(memory, bytes_read_ptr, 0);
                    }
                    state.set(Register::Rax, 1);
                    self.last_error = 0;
                } else if overlapped != 0 || (buffer_ptr == 0 && length != 0) {
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
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let buffer_ptr = guest_call_arg(state, memory, 1)?;
                let length = guest_call_arg(state, memory, 2)? as usize;
                let bytes_written_ptr = guest_call_arg(state, memory, 3)?;
                let overlapped = guest_call_arg(state, memory, 4)?;

                if handle == STD_OUTPUT_HANDLE || handle == STD_ERROR_HANDLE {
                    let bytes = read_window(memory, buffer_ptr, length)?;
                    let text = String::from_utf8_lossy(&bytes);
                    if handle == STD_ERROR_HANDLE {
                        self.stderr.push_str(&text);
                    } else {
                        self.stdout.push_str(&text);
                    }
                    if bytes_written_ptr != 0 {
                        write_u32(memory, bytes_written_ptr, length as u32);
                    }
                    state.set(Register::Rax, 1);
                    self.last_error = 0;
                    self.push_trace(
                        "file",
                        "WriteFile",
                        BTreeMap::from([
                            ("handle".to_string(), json!(handle)),
                            ("bytes".to_string(), json!(length as u32)),
                        ]),
                        json!(1),
                    );
                } else if overlapped != 0 || (buffer_ptr == 0 && length != 0) {
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
            HostThunk::LocalAlloc | HostThunk::GlobalAlloc => {
                let _flags = guest_call_arg_u32(state, memory, 0)?;
                let bytes = guest_call_arg(state, memory, 1)? as usize;
                let handle = self.alloc_heap(memory, bytes.max(1), true)?;
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "memory",
                    match thunk {
                        HostThunk::LocalAlloc => "LocalAlloc",
                        _ => "GlobalAlloc",
                    },
                    BTreeMap::from([("bytes".to_string(), json!(bytes as u64))]),
                    json!(handle),
                );
            }
            HostThunk::GlobalLock => {
                let handle = guest_call_arg(state, memory, 0)?;
                let result = if handle == 0 || !self.heap_allocations.contains_key(&handle) {
                    self.last_error = ERROR_INVALID_HANDLE;
                    0
                } else {
                    self.last_error = 0;
                    handle
                };
                state.set(Register::Rax, result);
                self.push_trace(
                    "memory",
                    "GlobalLock",
                    BTreeMap::from([("handle".to_string(), json!(handle))]),
                    json!(result),
                );
            }
            HostThunk::GlobalUnlock => {
                let handle = guest_call_arg(state, memory, 0)?;
                if handle == 0 || !self.heap_allocations.contains_key(&handle) {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_HANDLE;
                } else {
                    state.set(Register::Rax, 0);
                    self.last_error = 0;
                }
                self.push_trace(
                    "memory",
                    "GlobalUnlock",
                    BTreeMap::from([("handle".to_string(), json!(handle))]),
                    json!(0),
                );
            }
            HostThunk::GlobalFree => {
                let handle = guest_call_arg(state, memory, 0)?;
                if handle != 0 {
                    self.heap_allocations.remove(&handle);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "memory",
                    "GlobalFree",
                    BTreeMap::from([("handle".to_string(), json!(handle))]),
                    json!(0),
                );
            }
            HostThunk::CloseHandle => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
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
                let count = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg(state, memory, 1)?;
                let total = count.saturating_mul(size).max(1);
                let address = self.alloc_heap(memory, total as usize, true)?;
                state.set(Register::Rax, address);
                self.last_error = 0;
            }
            HostThunk::Free => {
                let address = guest_call_arg(state, memory, 0)?;
                self.heap_allocations.remove(&address);
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::Malloc => {
                let size = guest_call_arg(state, memory, 0)?.max(1);
                let address = self.alloc_heap(memory, size as usize, true)?;
                state.set(Register::Rax, address);
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
                let callback = guest_call_arg(state, memory, 0)?;
                if callback != 0 {
                    self.atexit_handlers.push(callback);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::CrtExit => {
                return Ok(Some(guest_call_arg(state, memory, 0)? as i32));
            }
            HostThunk::InitializeNarrowEnvironment => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::Initterm => {
                if self.guest_arch == GuestArch::X86 {
                    let first = guest_call_arg(state, memory, 0)?;
                    let last = guest_call_arg(state, memory, 1)?;
                    let stride = self.guest_arch.pointer_bytes() as u64;
                    let mut cursor = first;
                    while cursor < last {
                        let callback = read_guest_pointer(memory, cursor, self.guest_arch)?;
                        if callback != 0 {
                            let _ = self.execute_guest_callback(state, memory, callback, &[], "_initterm")?;
                        }
                        cursor = cursor.wrapping_add(stride);
                    }
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::InittermE => {
                let mut result = 0_u64;
                if self.guest_arch == GuestArch::X86 {
                    let first = guest_call_arg(state, memory, 0)?;
                    let last = guest_call_arg(state, memory, 1)?;
                    let stride = self.guest_arch.pointer_bytes() as u64;
                    let mut cursor = first;
                    while cursor < last {
                        let callback = read_guest_pointer(memory, cursor, self.guest_arch)?;
                        if callback != 0 {
                            result = self.execute_guest_callback(state, memory, callback, &[], "_initterm_e")?;
                            if result != 0 {
                                break;
                            }
                        }
                        cursor = cursor.wrapping_add(stride);
                    }
                }
                state.set(Register::Rax, result);
                self.last_error = 0;
            }
            HostThunk::SetAppType => {
                state.set(Register::Rax, 0);
                self.last_error = 0;
            }
            HostThunk::SetInvalidParameterHandler => {
                let previous = self.invalid_parameter_handler;
                self.invalid_parameter_handler = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, previous);
                self.last_error = 0;
            }
            HostThunk::Abort => {
                return Ok(Some(134));
            }
            HostThunk::Exit => {
                return Ok(Some(guest_call_arg(state, memory, 0)? as i32));
            }
            HostThunk::Signal => {
                let signal = guest_call_arg(state, memory, 0)? as i32;
                let handler = guest_call_arg(state, memory, 1)?;
                let previous = self.signal_handlers.insert(signal, handler).unwrap_or(0);
                state.set(Register::Rax, previous);
                self.last_error = 0;
            }
            HostThunk::AcrtIobFunc => {
                let index = (guest_call_arg(state, memory, 0)? as usize).min(self.globals.iob_streams.len().saturating_sub(1));
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
                let ptr = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg(state, memory, 1)?;
                let count = guest_call_arg(state, memory, 2)?;
                let stream = guest_call_arg(state, memory, 3)?;
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
                let string_ptr = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, read_c_string(memory, string_ptr)?.len() as u64);
                self.last_error = 0;
            }
            HostThunk::Strncmp => {
                let count = guest_call_arg(state, memory, 2)? as usize;
                let left = read_c_string_limit(memory, guest_call_arg(state, memory, 0)?, count)?;
                let right = read_c_string_limit(memory, guest_call_arg(state, memory, 1)?, count)?;
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
            HostThunk::GetModuleHandleA => {
                let name_ptr = guest_call_arg(state, memory, 0)?;
                let (module_name, handle) = if name_ptr == 0 {
                    (None, self.mapped_image_base)
                } else {
                    let module_name = read_c_string(memory, name_ptr)?;
                    let handle = self.get_or_create_module_handle(&module_name);
                    (Some(module_name), handle)
                };
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "kernel32",
                    "GetModuleHandleA",
                    BTreeMap::from([("module".to_string(), json!(module_name))]),
                    json!(handle),
                );
            }
            HostThunk::GetModuleHandleW => {
                let name_ptr = guest_call_arg(state, memory, 0)?;
                let (module_name, handle) = if name_ptr == 0 {
                    (None, self.mapped_image_base)
                } else {
                    let module_name = read_utf16_string(memory, name_ptr)?;
                    let handle = self.get_or_create_module_handle(&module_name);
                    (Some(module_name), handle)
                };
                state.set(Register::Rax, handle);
                self.last_error = 0;
                self.push_trace(
                    "kernel32",
                    "GetModuleHandleW",
                    BTreeMap::from([("module".to_string(), json!(module_name))]),
                    json!(handle),
                );
            }
            HostThunk::GetProcAddress => {
                let module_handle = guest_call_arg(state, memory, 0)?;
                let proc_arg = guest_call_arg(state, memory, 1)?;
                let symbol = if proc_arg <= u16::MAX as u64 {
                    ImportSymbol::ByOrdinal {
                        ordinal: proc_arg as u16,
                    }
                } else {
                    ImportSymbol::ByName {
                        hint: 0,
                        name: read_c_string(memory, proc_arg)?,
                    }
                };
                let symbol_name = match &symbol {
                    ImportSymbol::ByName { name, .. } => name.clone(),
                    ImportSymbol::ByOrdinal { ordinal } => format!("ordinal#{ordinal}"),
                };
                let module_name = self
                    .module_names_by_handle
                    .get(&module_handle)
                    .cloned()
                    .or_else(|| {
                        (module_handle == self.mapped_image_base && !self.main_module_name.is_empty())
                            .then(|| self.main_module_name.clone())
                    })
                    .unwrap_or_default();
                let address = self.resolve_proc_address(module_handle, symbol);
                state.set(Register::Rax, address);
                self.last_error = 0;
                self.push_trace(
                    "kernel32",
                    "GetProcAddress",
                    BTreeMap::from([
                        ("module".to_string(), json!(module_name)),
                        ("symbol".to_string(), json!(symbol_name)),
                    ]),
                    json!(address),
                );
            }
            HostThunk::WsprintfW => {
                let buffer = guest_call_arg(state, memory, 0)?;
                let format_ptr = guest_call_arg(state, memory, 1)?;
                let format_string = read_utf16_string(memory, format_ptr)?;
                let rendered = format_wsprintf_w(state, memory, &format_string, 2)?;
                let mut bytes = Vec::with_capacity((rendered.encode_utf16().count() + 1) * 2);
                for unit in rendered.encode_utf16() {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                bytes.extend_from_slice(&0_u16.to_le_bytes());
                memory.map_bytes(buffer, &bytes);
                self.recent_wide_writes.insert(buffer, rendered.clone());
                state.set(Register::Rax, rendered.encode_utf16().count() as u64);
                self.last_error = 0;
                self.push_trace(
                    "file",
                    "wsprintfW",
                    BTreeMap::from([
                        ("caller_rip".to_string(), json!(format!("{return_address:#x}"))),
                        ("buffer".to_string(), json!(format!("{buffer:#x}"))),
                        ("format".to_string(), json!(format_string)),
                    ]),
                    json!(rendered),
                );
            }
            HostThunk::GetLastError => {
                state.set(Register::Rax, self.last_error as u64);
            }
            HostThunk::SetLastError => {
                let value = guest_call_arg_u32(state, memory, 0)?;
                self.last_error = value;
                state.set(Register::Rax, 0);
                self.push_trace("kernel32", "SetLastError", BTreeMap::new(), json!(value));
            }
            HostThunk::GetCurrentThreadId => {
                let thread_id = 1_u32;
                state.set(Register::Rax, u64::from(thread_id));
                self.last_error = 0;
                self.push_trace("thread", "GetCurrentThreadId", BTreeMap::new(), json!(thread_id));
            }
            HostThunk::GetCurrentProcessId => {
                let process_id = std::process::id();
                state.set(Register::Rax, u64::from(process_id));
                self.last_error = 0;
                self.push_trace("process", "GetCurrentProcessId", BTreeMap::new(), json!(process_id));
            }
            HostThunk::QueryPerformanceCounter => {
                let counter_ptr = guest_call_arg(state, memory, 0)?;
                if counter_ptr == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let counter = current_host_ticks_100ns();
                    write_u64(memory, counter_ptr, counter);
                    state.set(Register::Rax, 1);
                    self.last_error = 0;
                    self.push_trace(
                        "time",
                        "QueryPerformanceCounter",
                        BTreeMap::from([("counter".to_string(), json!(format!("{counter_ptr:#x}")))]),
                        json!(counter),
                    );
                }
            }
            HostThunk::QueryPerformanceFrequency => {
                let frequency_ptr = guest_call_arg(state, memory, 0)?;
                if frequency_ptr == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let frequency = self.win32.query_performance_frequency();
                    write_u64(memory, frequency_ptr, frequency);
                    state.set(Register::Rax, 1);
                    self.last_error = 0;
                    self.push_trace(
                        "time",
                        "QueryPerformanceFrequency",
                        BTreeMap::from([("frequency".to_string(), json!(format!("{frequency_ptr:#x}")))]),
                        json!(frequency),
                    );
                }
            }
            HostThunk::IsProcessorFeaturePresent => {
                let feature = guest_call_arg_u32(state, memory, 0)?;
                let present = is_processor_feature_present(feature);
                state.set(Register::Rax, u64::from(present));
                self.last_error = 0;
                self.push_trace(
                    "cpu",
                    "IsProcessorFeaturePresent",
                    BTreeMap::from([("feature".to_string(), json!(feature))]),
                    json!(present),
                );
            }
            HostThunk::GetProcessHeap => {
                state.set(Register::Rax, PROCESS_HEAP_HANDLE);
                self.last_error = 0;
                self.push_trace("memory", "GetProcessHeap", BTreeMap::new(), json!(PROCESS_HEAP_HANDLE));
            }
            HostThunk::GetProcessHeaps => {
                let count = guest_call_arg_u32(state, memory, 0)?;
                let heaps_ptr = guest_call_arg(state, memory, 1)?;
                if count != 0 && heaps_ptr != 0 {
                    write_guest_pointer(memory, heaps_ptr, PROCESS_HEAP_HANDLE, self.guest_arch)?;
                }
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace(
                    "memory",
                    "GetProcessHeaps",
                    BTreeMap::from([
                        ("count".to_string(), json!(count)),
                        ("buffer".to_string(), json!(format!("{heaps_ptr:#x}"))),
                    ]),
                    json!(1),
                );
            }
            HostThunk::HeapAlloc => {
                let heap = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let bytes = guest_call_arg(state, memory, 2)? as usize;
                if heap != PROCESS_HEAP_HANDLE {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let address = self.alloc_heap(memory, bytes.max(1), (flags & HEAP_ZERO_MEMORY) != 0)?;
                    state.set(Register::Rax, address);
                    self.last_error = 0;
                    self.push_trace(
                        "memory",
                        "HeapAlloc",
                        BTreeMap::from([
                            ("heap".to_string(), json!(format!("{heap:#x}"))),
                            ("flags".to_string(), json!(flags)),
                            ("bytes".to_string(), json!(bytes as u64)),
                        ]),
                        json!(address),
                    );
                }
            }
            HostThunk::HeapFree => {
                let heap = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let address = guest_call_arg(state, memory, 2)?;
                let freed = heap == PROCESS_HEAP_HANDLE && self.heap_allocations.remove(&address).is_some();
                state.set(Register::Rax, u64::from(freed));
                self.last_error = if freed { 0 } else { ERROR_INVALID_PARAMETER };
                self.push_trace(
                    "memory",
                    "HeapFree",
                    BTreeMap::from([
                        ("heap".to_string(), json!(format!("{heap:#x}"))),
                        ("flags".to_string(), json!(flags)),
                        ("address".to_string(), json!(format!("{address:#x}"))),
                    ]),
                    json!(freed),
                );
            }
            HostThunk::HeapReAlloc => {
                let heap = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let address = guest_call_arg(state, memory, 2)?;
                let bytes = guest_call_arg(state, memory, 3)? as usize;
                if heap != PROCESS_HEAP_HANDLE {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else if address == 0 {
                    let new_address = self.alloc_heap(memory, bytes.max(1), (flags & HEAP_ZERO_MEMORY) != 0)?;
                    state.set(Register::Rax, new_address);
                    self.last_error = 0;
                } else if let Some(old_size) = self.heap_allocations.remove(&address) {
                    let new_address = self.alloc_heap(memory, bytes.max(1), (flags & HEAP_ZERO_MEMORY) != 0)?;
                    let copy_len = old_size.min(bytes.max(1));
                    let mut copied = Vec::with_capacity(copy_len);
                    for offset in 0..copy_len {
                        copied.push(memory.read_u8(address + offset as u64)?);
                    }
                    memory.map_bytes(new_address, &copied);
                    state.set(Register::Rax, new_address);
                    self.last_error = 0;
                    self.push_trace(
                        "memory",
                        "HeapReAlloc",
                        BTreeMap::from([
                            ("heap".to_string(), json!(format!("{heap:#x}"))),
                            ("flags".to_string(), json!(flags)),
                            ("old_address".to_string(), json!(format!("{address:#x}"))),
                            ("bytes".to_string(), json!(bytes as u64)),
                        ]),
                        json!(new_address),
                    );
                } else {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                }
            }
            HostThunk::HeapSize => {
                let heap = guest_call_arg(state, memory, 0)?;
                let flags = guest_call_arg_u32(state, memory, 1)?;
                let address = guest_call_arg(state, memory, 2)?;
                let size = if heap == PROCESS_HEAP_HANDLE {
                    self.heap_allocations.get(&address).copied().map(|size| size as u64)
                } else {
                    None
                };
                let result = size.unwrap_or_else(|| match self.guest_arch {
                    GuestArch::X64 => u64::MAX,
                    GuestArch::X86 => u32::MAX as u64,
                });
                state.set(Register::Rax, result);
                self.last_error = if size.is_some() { 0 } else { ERROR_INVALID_PARAMETER };
                self.push_trace(
                    "memory",
                    "HeapSize",
                    BTreeMap::from([
                        ("heap".to_string(), json!(format!("{heap:#x}"))),
                        ("flags".to_string(), json!(flags)),
                        ("address".to_string(), json!(format!("{address:#x}"))),
                    ]),
                    json!(result),
                );
            }
            HostThunk::GetStartupInfoW => {
                let startup_info = guest_call_arg(state, memory, 0)?;
                if startup_info != 0 {
                    let size = match self.guest_arch {
                        GuestArch::X64 => 104_u32,
                        GuestArch::X86 => 68_u32,
                    };
                    memory.map_bytes(startup_info, &vec![0; size as usize]);
                    write_u32(memory, startup_info, size);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "process",
                    "GetStartupInfoW",
                    BTreeMap::from([("startup_info".to_string(), json!(format!("{startup_info:#x}")))]),
                    json!(0),
                );
            }
            HostThunk::GetStdHandle => {
                let which = guest_call_arg_u32(state, memory, 0)?;
                let handle = match which {
                    STD_INPUT_HANDLE | STD_OUTPUT_HANDLE | STD_ERROR_HANDLE => which,
                    _ => INVALID_HANDLE_VALUE as u32,
                };
                state.set(Register::Rax, u64::from(handle));
                self.last_error = if handle == INVALID_HANDLE_VALUE as u32 {
                    ERROR_INVALID_PARAMETER
                } else {
                    0
                };
                self.push_trace("kernel32", "GetStdHandle", BTreeMap::new(), json!(handle));
            }
            HostThunk::GetFileType => {
                let handle = guest_call_arg_u32(state, memory, 0)?;
                let file_type = match handle {
                    STD_INPUT_HANDLE | STD_OUTPUT_HANDLE | STD_ERROR_HANDLE => FILE_TYPE_CHAR,
                    0 | u32::MAX => FILE_TYPE_UNKNOWN,
                    _ => FILE_TYPE_DISK,
                };
                state.set(Register::Rax, u64::from(file_type));
                self.last_error = if file_type == FILE_TYPE_UNKNOWN {
                    ERROR_INVALID_HANDLE
                } else {
                    0
                };
                self.push_trace("file", "GetFileType", BTreeMap::new(), json!(file_type));
            }
            HostThunk::GetSystemTimeAsFileTime => {
                let file_time_ptr = guest_call_arg(state, memory, 0)?;
                let ticks = current_guest_filetime_ticks(self.dtm);
                if file_time_ptr != 0 {
                    write_u64(memory, file_time_ptr, ticks);
                }
                state.set(Register::Rax, 0);
                self.last_error = 0;
                self.push_trace(
                    "time",
                    "GetSystemTimeAsFileTime",
                    BTreeMap::from([("file_time".to_string(), json!(format!("{file_time_ptr:#x}")))]),
                    json!(ticks),
                );
            }
            HostThunk::GetTickCount => {
                let milliseconds = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_millis() as u64)
                    .unwrap_or(0)
                    & u32::MAX as u64;
                state.set(Register::Rax, milliseconds);
                self.last_error = 0;
                self.push_trace("time", "GetTickCount", BTreeMap::new(), json!(milliseconds));
            }
            HostThunk::InitializeCriticalSection => {
                self.critical_sections.entry(state.get(Register::Rcx)).or_insert(0);
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::InitializeCriticalSectionAndSpinCount => {
                let critical_section = guest_call_arg(state, memory, 0)?;
                let spin_count = guest_call_arg_u32(state, memory, 1)?;
                self.critical_sections.entry(critical_section).or_insert(0);
                state.set(Register::Rax, 1);
                self.last_error = 0;
                self.push_trace(
                    "sync",
                    "InitializeCriticalSectionAndSpinCount",
                    BTreeMap::from([
                        ("critical_section".to_string(), json!(format!("{critical_section:#x}"))),
                        ("spin_count".to_string(), json!(spin_count)),
                    ]),
                    json!(1),
                );
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
            HostThunk::GetVersion => {
                const WINDOWS_10_BUILD_22H2: u32 = (19045u32 << 16) | 10u32;
                state.set(Register::Rax, WINDOWS_10_BUILD_22H2 as u64);
                self.last_error = 0;
                self.push_trace("kernel32", "GetVersion", BTreeMap::new(), json!(WINDOWS_10_BUILD_22H2));
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
                let milliseconds = guest_call_arg(state, memory, 0)?;
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
            HostThunk::TlsAlloc => {
                if let Some(slot) = (0_u32..4096).find(|slot| !self.tls_slots.contains_key(slot)) {
                    self.tls_slots.insert(slot, 0);
                    self.sync_guest_tls_slot(memory, slot, 0)?;
                    state.set(Register::Rax, u64::from(slot));
                    self.last_error = 0;
                    self.push_trace("thread", "TlsAlloc", BTreeMap::new(), json!(slot));
                } else {
                    state.set(Register::Rax, u32::MAX as u64);
                    self.last_error = ERROR_INVALID_PARAMETER;
                }
            }
            HostThunk::TlsGetValue => {
                let slot = guest_call_arg_u32(state, memory, 0)?;
                let value = self.tls_slots.get(&slot).copied().unwrap_or(0);
                state.set(Register::Rax, value);
                self.last_error = 0;
            }
            HostThunk::TlsSetValue => {
                let slot = guest_call_arg_u32(state, memory, 0)?;
                let value = guest_call_arg(state, memory, 1)?;
                let stored = if let Some(entry) = self.tls_slots.get_mut(&slot) {
                    *entry = value;
                    self.sync_guest_tls_slot(memory, slot, value)?;
                    true
                } else {
                    false
                };
                state.set(Register::Rax, u64::from(stored));
                self.last_error = if stored { 0 } else { ERROR_INVALID_PARAMETER };
                self.push_trace(
                    "thread",
                    "TlsSetValue",
                    BTreeMap::from([
                        ("slot".to_string(), json!(slot)),
                        ("value".to_string(), json!(format!("{value:#x}"))),
                    ]),
                    json!(stored),
                );
            }
            HostThunk::TlsFree => {
                let slot = guest_call_arg_u32(state, memory, 0)?;
                let freed = self.tls_slots.remove(&slot).is_some();
                if freed {
                    self.sync_guest_tls_slot(memory, slot, 0)?;
                }
                state.set(Register::Rax, u64::from(freed));
                self.last_error = if freed { 0 } else { ERROR_INVALID_PARAMETER };
                self.push_trace(
                    "thread",
                    "TlsFree",
                    BTreeMap::from([("slot".to_string(), json!(slot))]),
                    json!(freed),
                );
            }
            HostThunk::VirtualAlloc => {
                let requested_address = guest_call_arg(state, memory, 0)?;
                let bytes = guest_call_arg(state, memory, 1)? as usize;
                let allocation_type = guest_call_arg_u32(state, memory, 2)?;
                let protect = guest_call_arg_u32(state, memory, 3)?;
                if bytes == 0 || allocation_type & (MEM_COMMIT | MEM_RESERVE) == 0 {
                    state.set(Register::Rax, 0);
                    self.last_error = ERROR_INVALID_PARAMETER;
                } else {
                    let address = self.alloc_private_pages(memory, requested_address, bytes)?;
                    state.set(Register::Rax, address);
                    self.last_error = 0;
                    self.push_trace(
                        "memory",
                        "VirtualAlloc",
                        BTreeMap::from([
                            ("address".to_string(), json!(format!("{requested_address:#x}"))),
                            ("bytes".to_string(), json!(bytes as u64)),
                            ("allocation_type".to_string(), json!(format!("0x{allocation_type:08x}"))),
                            ("protect".to_string(), json!(format!("0x{protect:08x}"))),
                        ]),
                        json!(address),
                    );
                }
            }
            HostThunk::VirtualProtect => {
                let old_protect_ptr = guest_call_arg(state, memory, 3)?;
                if old_protect_ptr != 0 {
                    write_u32(memory, old_protect_ptr, PAGE_EXECUTE_READWRITE);
                }
                state.set(Register::Rax, 1);
                self.last_error = 0;
            }
            HostThunk::VirtualQuery => {
                let address = guest_call_arg(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let length = guest_call_arg(state, memory, 2)?;
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
                let code = guest_call_arg(state, memory, 0)? as i32;
                self.push_trace(
                    "process",
                    "ExitProcess",
                    BTreeMap::from([("exit_code".to_string(), json!(code))]),
                    json!(code),
                );
                return Ok(Some(code));
            }
            HostThunk::MessageBoxW => {
                let text_ptr = guest_call_arg(state, memory, 1)?;
                let caption_ptr = guest_call_arg(state, memory, 2)?;
                let style = guest_call_arg_u32(state, memory, 3)?;
                let text = if text_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, text_ptr)?
                };
                let caption = if caption_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, caption_ptr)?
                };
                show_host_message_box(&caption, &text, self.dtm)?;
                let response = message_box_response(style);
                self.push_trace(
                    "input",
                    "MessageBoxW",
                    BTreeMap::from([
                        ("text".to_string(), json!(text)),
                        ("caption".to_string(), json!(caption)),
                        ("style".to_string(), json!(style)),
                    ]),
                    json!(response),
                );
                state.set(Register::Rax, response as i64 as u64);
                self.last_error = 0;
            }
            HostThunk::MessageBoxIndirectW => {
                let params = guest_call_arg(state, memory, 0)?;
                let (text_offset, caption_offset, style_offset) = if self.guest_arch == GuestArch::X86 {
                    (12_u64, 16_u64, 20_u64)
                } else {
                    (24_u64, 32_u64, 40_u64)
                };
                let text_ptr = if params == 0 {
                    0
                } else {
                    read_guest_pointer(memory, params + text_offset, self.guest_arch)?
                };
                let caption_ptr = if params == 0 {
                    0
                } else {
                    read_guest_pointer(memory, params + caption_offset, self.guest_arch)?
                };
                let style = if params == 0 { 0 } else { read_guest_u32(memory, params + style_offset)? };
                let text = if text_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, text_ptr)?
                };
                let caption = if caption_ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, caption_ptr)?
                };
                show_host_message_box(&caption, &text, self.dtm)?;
                let response = message_box_response(style);
                self.push_trace(
                    "input",
                    "MessageBoxIndirectW",
                    BTreeMap::from([
                        ("text".to_string(), json!(text)),
                        ("caption".to_string(), json!(caption)),
                        ("style".to_string(), json!(style)),
                    ]),
                    json!(response),
                );
                state.set(Register::Rax, response as i64 as u64);
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

        if self.guest_arch == GuestArch::X86 {
            if let Some((rbx_before, rsi_before, rdi_before, rbp_before)) = callee_saved_before {
                let rbx_after = state.get(Register::Rbx);
                let rsi_after = state.get(Register::Rsi);
                let rdi_after = state.get(Register::Rdi);
                let rbp_after = state.get(Register::Rbp);
                if rbx_after != rbx_before
                    || rsi_after != rsi_before
                    || rdi_after != rdi_before
                    || rbp_after != rbp_before
                {
                    return Err(AppError::new(
                        ReasonCode::RcUnimplInsn,
                        format!(
                            "x86 host thunk {thunk_name} clobbered callee-saved registers before returning to {return_address:#x}: ebx {rbx_before:#x}->{rbx_after:#x}, esi {rsi_before:#x}->{rsi_after:#x}, edi {rdi_before:#x}->{rdi_after:#x}, ebp {rbp_before:#x}->{rbp_after:#x}"
                        ),
                    ));
                }
            }
            state.set(
                Register::Rsp,
                state.get(Register::Rsp).wrapping_add(thunk.x86_arg_bytes()),
            );
        }
        state.rip = return_address;
        Ok(None)
    }

    fn dispatch_queued_message(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        message: &Message,
        label: &str,
    ) -> AppResult<i64> {
        if let Some(hwnd) = message.hwnd {
            return self.dispatch_window_message(
                state,
                memory,
                hwnd,
                message_id(message.kind),
                message.wparam,
                message.lparam,
                label,
            );
        }
        self.user32.dispatch_message_w(message)
    }

    fn dispatch_window_message(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        hwnd: u32,
        message_id: u32,
        wparam: i64,
        lparam: i64,
        label: &str,
    ) -> AppResult<i64> {
        if let Some(dialog_proc) = self.dialog_procs.get(&hwnd).copied() {
            return Ok(self.execute_guest_callback(
                state,
                memory,
                dialog_proc,
                &[
                    u64::from(hwnd),
                    message_id as u64,
                    wparam as u64,
                    lparam as u64,
                ],
                label,
            )? as i64);
        }
        if let Some(window_proc) = self.user32.get_window_long_w(hwnd, GWL_WNDPROC) {
            if window_proc != 0 {
                return Ok(self.execute_guest_callback(
                    state,
                    memory,
                    window_proc,
                    &[
                        u64::from(hwnd),
                        message_id as u64,
                        wparam as u64,
                        lparam as u64,
                    ],
                    label,
                )? as i64);
            }
        }
        if let Ok(kind) = message_kind(message_id) {
            if self.user32.has_window(hwnd) {
                self.user32.send_message_w(hwnd, kind, wparam, lparam)
            } else {
                Ok(0)
            }
        } else {
            Ok(match message_id {
                0x00F3 | 0x040F => 1,
                _ => 0,
            })
        }
    }

    fn run_modal_dialog_loop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        hwnd: u32,
    ) -> AppResult<Option<i64>> {
        loop {
            if let Some(dialog_result) = self.user32.take_dialog_result(hwnd) {
                return Ok(Some(dialog_result));
            }
            self.poll_live_input()?;
            let Some(message) = self.user32.get_message_w() else {
                return Ok(None);
            };
            let _ = self.dispatch_queued_message(state, memory, &message, "DialogBoxParamW::DispatchMessage")?;
            if message.kind == MessageKind::Quit {
                self.user32.post_quit_message(message.wparam as i32)?;
                return Ok(None);
            }
        }
    }

    fn execute_guest_callback(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        entrypoint: u64,
        args: &[u64],
        label: &str,
    ) -> AppResult<u64> {
        if self.guest_arch != GuestArch::X86 {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("guest callback execution is only implemented for x86: {label}"),
            ));
        }

        let config = CpuEngineConfig::from_profile(
            self.guest_arch,
            &self.win32.ge().config.winver,
            env!("CARGO_PKG_VERSION"),
            None,
        )?;
        let mut engine = CpuExecutionEngine::new(config);
        let instruction_budget = pe_runtime_instruction_budget(&BTreeMap::new(), false)?;
        let guest_pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let original_rsp = state.get(Register::Rsp);
        let callback_rsp = original_rsp.wrapping_sub((args.len() as u64 + 1) * guest_pointer_bytes);
        write_guest_pointer(memory, callback_rsp, 0, self.guest_arch)?;
        for (index, arg) in args.iter().enumerate() {
            write_guest_pointer(
                memory,
                callback_rsp + guest_pointer_bytes * (index as u64 + 1),
                *arg,
                self.guest_arch,
            )?;
        }
        state.set(Register::Rsp, callback_rsp);
        state.rip = entrypoint;

        let mut steps = 0_u64;
        loop {
            if self.host_thunks.contains_key(&state.rip) {
                advance_runtime_steps(self, &mut steps, instruction_budget, 1, memory, state, label)?;
                if let Some(code) = self.dispatch_import(state.rip, state, memory)? {
                    state.set(Register::Rax, code as u64);
                    break;
                }
                continue;
            }

            let opcode = memory
                .read_u8(state.rip)
                .map_err(|error| annotate_guest_fault(error, memory, state))?;
            match opcode {
                0xFF => match memory.read_u8(state.rip + 1)? {
                    0x15 | 0x25 => {
                        advance_runtime_steps(self, &mut steps, instruction_budget, 1, memory, state, label)?;
                        let next_rip = state.rip + 6;
                        let slot_address = read_u32(memory, state.rip + 2)? as u64;
                        let target = read_guest_pointer(memory, slot_address, self.guest_arch)?;

                        if self.host_thunks.contains_key(&target) {
                            if memory.read_u8(state.rip + 1)? == 0x15 {
                                let call_rsp = state.get(Register::Rsp).wrapping_sub(guest_pointer_bytes);
                                write_guest_pointer(memory, call_rsp, next_rip, self.guest_arch)?;
                                state.set(Register::Rsp, call_rsp);
                            }
                            if let Some(code) = self.dispatch_import(target, state, memory)? {
                                state.set(Register::Rax, code as u64);
                                break;
                            }
                        } else if memory.read_u8(state.rip + 1)? == 0x15 {
                            let call_rsp = state.get(Register::Rsp).wrapping_sub(guest_pointer_bytes);
                            write_guest_pointer(memory, call_rsp, next_rip, self.guest_arch)?;
                            state.set(Register::Rsp, call_rsp);
                            state.rip = target;
                        } else {
                            state.rip = target;
                        }
                        continue;
                    }
                    _ => {}
                },
                _ => {}
            }

            let cached_block = decode_basic_block_cached(
                &mut engine,
                memory,
                &mut self.instruction_cache,
                &mut self.instruction_cache_lru,
                &mut self.instruction_cache_generation,
                INSTRUCTION_CACHE_LIMIT,
                &mut self.basic_block_cache,
                &mut self.basic_block_cache_lru,
                &mut self.basic_block_cache_generation,
                BASIC_BLOCK_CACHE_LIMIT,
                state.rip,
            )
            .map_err(|error| annotate_guest_fault(error, memory, state))?;
            let consumed_instructions = cached_block.translated.decoded.len().max(1) as u64;
            advance_runtime_steps(
                self,
                &mut steps,
                instruction_budget,
                consumed_instructions,
                memory,
                state,
                label,
            )?;
            let _ = engine
                .execute_ir_without_memory_hash(state, memory, &cached_block.translated.ir)
                .map_err(|error| annotate_guest_fault(error, memory, state))?;
            let last_instruction = cached_block
                .translated
                .decoded
                .last()
                .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, "translated basic block was empty"))?;
            if last_instruction.opcode == DecodedOpcode::Ret {
                if state.rip == 0 {
                    break;
                }
            } else if !instruction_controls_rip(last_instruction.opcode) {
                state.rip = cached_block.end_rip;
            }
        }

        state.set(Register::Rsp, original_rsp);
        Ok(state.get(Register::Rax))
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
        let pointer_bytes = self.guest_arch.pointer_bytes();
        let address = self.alloc_zeroed(memory, values.len() * pointer_bytes, pointer_bytes as u64)?;
        for (index, value) in values.iter().enumerate() {
            write_guest_pointer(memory, address + (index as u64 * pointer_bytes as u64), *value, self.guest_arch)?;
        }
        Ok(address)
    }

    fn alloc_pointer(&mut self, memory: &mut MemoryImage, value: u64) -> AppResult<u64> {
        let pointer_bytes = self.guest_arch.pointer_bytes();
        let address = self.alloc_zeroed(memory, pointer_bytes, pointer_bytes as u64)?;
        write_guest_pointer(memory, address, value, self.guest_arch)?;
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

    fn alloc_private_pages(&mut self, memory: &mut MemoryImage, requested_address: u64, size: usize) -> AppResult<u64> {
        let size = align_up_u64(size.max(1) as u64, 0x1000) as usize;
        let address = if requested_address == 0 {
            align_up_u64(self.next_heap_address, 0x1000)
        } else {
            requested_address & !0xfff
        };
        let end = address.checked_add(size as u64).ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, "PE runtime virtual allocation overflow")
        })?;
        self.next_heap_address = self.next_heap_address.max(end);
        memory.map_bytes(address, &vec![0; size]);
        self.heap_allocations.insert(address, size);
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

    fn sync_guest_tls_slot(&self, memory: &mut MemoryImage, slot: u32, value: u64) -> AppResult<()> {
        if self.tls_vector_ptr != 0 {
            let slot_address = self
                .tls_vector_ptr
                .wrapping_add(slot as u64 * self.guest_arch.pointer_bytes() as u64);
            write_guest_pointer(memory, slot_address, value, self.guest_arch)?;
        }
        Ok(())
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
            GuestObjectKind::DxgiFactory => self.destroy_dxgi_factory_object(address)?,
            GuestObjectKind::DxgiAdapter => self.destroy_dxgi_adapter_object(address)?,
            GuestObjectKind::D3d11Device => self.destroy_d3d11_device_object(address)?,
            GuestObjectKind::D3d11DeviceContext => {
                if let Some(context) = self.d3d11_contexts.remove(&address) {
                    let _ = self.release_guest_object(context.device_object)?;
                }
                self.guest_objects.remove(&address);
            }
            GuestObjectKind::DxgiSwapChain => self.destroy_dxgi_swapchain_object(address)?,
            GuestObjectKind::D3d12Device => self.destroy_d3d12_device_object(address)?,
            GuestObjectKind::D3d12CommandQueue => self.destroy_d3d12_command_queue_object(address)?,
            GuestObjectKind::D3d12CommandAllocator => self.destroy_d3d12_command_allocator_object(address)?,
            GuestObjectKind::D3d12DescriptorHeap => self.destroy_d3d12_descriptor_heap_object(address)?,
            GuestObjectKind::D3d12GraphicsCommandList => self.destroy_d3d12_command_list_object(address)?,
            GuestObjectKind::D3d12Fence => self.destroy_d3d12_fence_object(address)?,
            GuestObjectKind::D3d12Resource => self.destroy_d3d12_resource_object(address)?,
            GuestObjectKind::D3d11Buffer => self.destroy_d3d11_buffer_object(address)?,
            GuestObjectKind::D3d11Texture2D => self.destroy_d3d11_texture_object(address)?,
            GuestObjectKind::D3d11View => self.destroy_d3d11_view_object(address)?,
            GuestObjectKind::D3d11InputLayout => self.destroy_d3d11_input_layout_object(address)?,
            GuestObjectKind::D3d11Shader => self.destroy_d3d11_shader_object(address)?,
            GuestObjectKind::D3d11BlendState => self.destroy_d3d11_blend_state_object(address)?,
            GuestObjectKind::D3d11RasterizerState => self.destroy_d3d11_rasterizer_state_object(address)?,
            GuestObjectKind::D3d11DepthStencilState => self.destroy_d3d11_depth_stencil_state_object(address)?,
            GuestObjectKind::D3d11SamplerState => self.destroy_d3d11_sampler_state_object(address)?,
            GuestObjectKind::ShellLinkInterface => self.destroy_shell_link_interface_object(address)?,
        }
        Ok(0)
    }

    fn alloc_shell_link_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("IShellLinkW::reserved"); 21];
        methods[0] = HostThunk::ShellLinkQueryInterface;
        methods[1] = HostThunk::ShellLinkAddRef;
        methods[2] = HostThunk::ShellLinkRelease;
        methods[3] = HostThunk::ShellLinkGetPathW;
        methods[4] = HostThunk::ShellLinkGetIDList;
        methods[5] = HostThunk::ShellLinkSetIDList;
        methods[6] = HostThunk::ShellLinkGetDescriptionW;
        methods[7] = HostThunk::ShellLinkSetDescriptionW;
        methods[8] = HostThunk::ShellLinkGetWorkingDirectoryW;
        methods[9] = HostThunk::ShellLinkSetWorkingDirectoryW;
        methods[10] = HostThunk::ShellLinkGetArgumentsW;
        methods[11] = HostThunk::ShellLinkSetArgumentsW;
        methods[12] = HostThunk::ShellLinkGetHotkey;
        methods[13] = HostThunk::ShellLinkSetHotkey;
        methods[14] = HostThunk::ShellLinkGetShowCmd;
        methods[15] = HostThunk::ShellLinkSetShowCmd;
        methods[16] = HostThunk::ShellLinkGetIconLocationW;
        methods[17] = HostThunk::ShellLinkSetIconLocationW;
        methods[18] = HostThunk::ShellLinkSetRelativePath;
        methods[19] = HostThunk::ShellLinkResolve;
        methods[20] = HostThunk::ShellLinkSetPathW;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ShellLinkInterface, vtable)?;
        self.shell_link_interfaces.insert(
            object,
            GuestShellLinkInterface {
                state_id: object,
                kind: ShellLinkInterfaceKind::ShellLinkW,
            },
        );
        self.shell_link_states.insert(
            object,
            GuestShellLinkState {
                shell_link_object: object,
                persist_file_object: None,
                refcount: 1,
                path: String::new(),
                arguments: String::new(),
                description: String::new(),
                working_directory: String::new(),
                hotkey: 0,
                icon_location: String::new(),
                icon_index: 0,
                show_cmd: SW_SHOWNORMAL,
                current_file: None,
                dirty: false,
            },
        );
        Ok(object)
    }

    fn ensure_shell_link_persist_file_object(
        &mut self,
        memory: &mut MemoryImage,
        shell_link_object: u64,
    ) -> AppResult<u64> {
        let state_id = self.shell_link_interface(shell_link_object)?.state_id;
        if let Some(object) = self.shell_link_state(state_id)?.persist_file_object {
            return Ok(object);
        }
        let mut methods = vec![unsupported_method("IPersistFile::reserved"); 9];
        methods[0] = HostThunk::ShellLinkQueryInterface;
        methods[1] = HostThunk::ShellLinkAddRef;
        methods[2] = HostThunk::ShellLinkRelease;
        methods[3] = HostThunk::ShellLinkPersistGetClassID;
        methods[4] = HostThunk::ShellLinkPersistIsDirty;
        methods[5] = HostThunk::ShellLinkPersistLoad;
        methods[6] = HostThunk::ShellLinkPersistSave;
        methods[7] = HostThunk::ShellLinkPersistSaveCompleted;
        methods[8] = HostThunk::ShellLinkPersistGetCurFile;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ShellLinkInterface, vtable)?;
        self.shell_link_interfaces.insert(
            object,
            GuestShellLinkInterface {
                state_id,
                kind: ShellLinkInterfaceKind::PersistFile,
            },
        );
        self.shell_link_state_mut(state_id)?.persist_file_object = Some(object);
        Ok(object)
    }

    fn shell_link_interface(&self, address: u64) -> AppResult<GuestShellLinkInterface> {
        self.shell_link_interfaces.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown shell link interface object {address:#x}"),
            )
        })
    }

    fn shell_link_state(&self, state_id: u64) -> AppResult<&GuestShellLinkState> {
        self.shell_link_states.get(&state_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown shell link state {state_id:#x}"),
            )
        })
    }

    fn shell_link_state_mut(&mut self, state_id: u64) -> AppResult<&mut GuestShellLinkState> {
        self.shell_link_states.get_mut(&state_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown shell link state {state_id:#x}"),
            )
        })
    }

    fn shell_link_state_for_interface(&self, address: u64) -> AppResult<&GuestShellLinkState> {
        let interface = self.shell_link_interface(address)?;
        self.shell_link_state(interface.state_id)
    }

    fn shell_link_state_for_interface_mut(&mut self, address: u64) -> AppResult<&mut GuestShellLinkState> {
        let interface = self.shell_link_interface(address)?;
        self.shell_link_state_mut(interface.state_id)
    }

    fn add_ref_shell_link_object(&mut self, address: u64) -> AppResult<u32> {
        let state_id = self.shell_link_interface(address)?.state_id;
        let state = self.shell_link_state_mut(state_id)?;
        state.refcount = state.refcount.saturating_add(1);
        Ok(state.refcount)
    }

    fn release_shell_link_object(&mut self, address: u64) -> AppResult<u32> {
        let state_id = self.shell_link_interface(address)?.state_id;
        let refcount = {
            let state = self.shell_link_state_mut(state_id)?;
            state.refcount = state.refcount.saturating_sub(1);
            state.refcount
        };
        if refcount == 0 {
            self.destroy_shell_link_state(state_id)?;
        }
        Ok(refcount)
    }

    fn destroy_shell_link_interface_object(&mut self, address: u64) -> AppResult<()> {
        let state_id = self.shell_link_interface(address)?.state_id;
        self.destroy_shell_link_state(state_id)
    }

    fn destroy_shell_link_state(&mut self, state_id: u64) -> AppResult<()> {
        if let Some(state) = self.shell_link_states.remove(&state_id) {
            self.shell_link_interfaces.remove(&state.shell_link_object);
            self.guest_objects.remove(&state.shell_link_object);
            if let Some(persist_file_object) = state.persist_file_object {
                self.shell_link_interfaces.remove(&persist_file_object);
                self.guest_objects.remove(&persist_file_object);
            }
        }
        Ok(())
    }

    fn shell_link_query_interface(
        &mut self,
        memory: &mut MemoryImage,
        address: u64,
        iid: &str,
        out_ptr: u64,
    ) -> AppResult<u64> {
        if out_ptr == 0 {
            return Ok(E_INVALIDARG);
        }
        write_guest_pointer(memory, out_ptr, 0, self.guest_arch)?;
        let interface = self.shell_link_interface(address)?;
        let state_id = interface.state_id;
        let object = if iid.eq_ignore_ascii_case(IID_IUNKNOWN) || iid.eq_ignore_ascii_case(IID_ISHELLLINKW) {
            self.shell_link_state(state_id)?.shell_link_object
        } else if iid.eq_ignore_ascii_case(IID_IPERSIST) || iid.eq_ignore_ascii_case(IID_IPERSISTFILE) {
            let shell_link_object = self.shell_link_state(state_id)?.shell_link_object;
            self.ensure_shell_link_persist_file_object(memory, shell_link_object)?
        } else {
            return Ok(E_NOINTERFACE);
        };
        let _ = self.add_ref_shell_link_object(object)?;
        write_guest_pointer(memory, out_ptr, object, self.guest_arch)?;
        Ok(0)
    }

    fn set_shell_link_path(&mut self, address: u64, value: String) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.path = value;
        state.dirty = true;
        Ok(())
    }

    fn set_shell_link_arguments(&mut self, address: u64, value: String) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.arguments = value;
        state.dirty = true;
        Ok(())
    }

    fn set_shell_link_description(&mut self, address: u64, value: String) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.description = value;
        state.dirty = true;
        Ok(())
    }

    fn set_shell_link_working_directory(&mut self, address: u64, value: String) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.working_directory = value;
        state.dirty = true;
        Ok(())
    }

    fn set_shell_link_icon_location(&mut self, address: u64, value: String, icon_index: i32) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.icon_location = value;
        state.icon_index = icon_index;
        state.dirty = true;
        Ok(())
    }

    fn set_shell_link_show_cmd(&mut self, address: u64, show_cmd: i32) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.show_cmd = show_cmd;
        state.dirty = true;
        Ok(())
    }

    fn save_shell_link(
        &mut self,
        address: u64,
        requested_path: Option<&str>,
        remember: bool,
    ) -> AppResult<u64> {
        let snapshot = self.shell_link_state_for_interface(address)?.clone();
        if snapshot.path.is_empty() {
            return Ok(E_INVALIDARG);
        }
        let save_path = if let Some(path) = requested_path {
            resolve_guest_path(&self.current_directory, path)
        } else if let Some(path) = snapshot.current_file.clone() {
            path
        } else {
            return Ok(E_INVALIDARG);
        };
        if let Some(parent) = windows_parent_directory(&save_path) {
            self.ensure_guest_directory_path(&parent)?;
        }
        let bytes = self.shell_link_file_bytes(&snapshot)?;
        match self.win32.write_file_overwrite_w(&save_path, &bytes) {
            Ok(_) => {
                let state = self.shell_link_state_for_interface_mut(address)?;
                if remember || state.current_file.is_none() {
                    state.current_file = Some(save_path);
                }
                state.dirty = false;
                Ok(0)
            }
            Err(_) => Ok(E_ACCESSDENIED),
        }
    }

    fn complete_shell_link_save(&mut self, address: u64, completed_path: Option<String>) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        if let Some(path) = completed_path {
            state.current_file = Some(path);
        }
        state.dirty = false;
        Ok(())
    }

    fn shell_link_file_bytes(&self, state: &GuestShellLinkState) -> AppResult<Vec<u8>> {
        let target_attributes = self
            .win32
            .get_file_attributes_w(&state.path)
            .map(|attributes| file_attributes_mask(&attributes))
            .unwrap_or(FILE_ATTRIBUTE_NORMAL);
        let target_size = self
            .win32
            .guest_path_to_host_path(&state.path)
            .ok()
            .and_then(|host_path| fs::metadata(host_path).ok())
            .map(|metadata| if metadata.is_dir() { 0 } else { metadata.len().min(u64::from(u32::MAX)) as u32 })
            .unwrap_or(0);
        let target_write_time = self
            .win32
            .ge()
            .get_file_metadata(&state.path)
            .map(|metadata| metadata.last_write_time_ticks)
            .unwrap_or(0);
        let mut link_flags = 0x0000_0002_u32 | 0x0000_0080_u32;
        if !state.description.is_empty() {
            link_flags |= 0x0000_0004;
        }
        if !state.working_directory.is_empty() {
            link_flags |= 0x0000_0010;
        }
        if !state.arguments.is_empty() {
            link_flags |= 0x0000_0020;
        }
        if !state.icon_location.is_empty() {
            link_flags |= 0x0000_0040;
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x4c_u32.to_le_bytes());
        bytes.extend_from_slice(&[0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
        bytes.extend_from_slice(&link_flags.to_le_bytes());
        bytes.extend_from_slice(&target_attributes.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&target_write_time.to_le_bytes());
        bytes.extend_from_slice(&target_size.to_le_bytes());
        bytes.extend_from_slice(&state.icon_index.to_le_bytes());
        bytes.extend_from_slice(&(if state.show_cmd == 0 { SW_SHOWNORMAL } else { state.show_cmd }).to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&build_shell_link_link_info(&state.path));
        if !state.description.is_empty() {
            append_shell_link_string(&mut bytes, &state.description);
        }
        if !state.working_directory.is_empty() {
            append_shell_link_string(&mut bytes, &state.working_directory);
        }
        if !state.arguments.is_empty() {
            append_shell_link_string(&mut bytes, &state.arguments);
        }
        if !state.icon_location.is_empty() {
            append_shell_link_string(&mut bytes, &state.icon_location);
        }
        Ok(bytes)
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
        device_methods[5] = HostThunk::D3D11DeviceCreateTexture2D;
        device_methods[7] = HostThunk::D3D11DeviceCreateShaderResourceView;
        device_methods[9] = HostThunk::D3D11DeviceCreateRenderTargetView;
        device_methods[10] = HostThunk::D3D11DeviceCreateDepthStencilView;
        device_methods[20] = HostThunk::D3D11DeviceCreateBlendState;
        device_methods[21] = HostThunk::D3D11DeviceCreateDepthStencilState;
        device_methods[22] = HostThunk::D3D11DeviceCreateRasterizerState;
        device_methods[23] = HostThunk::D3D11DeviceCreateSamplerState;
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
        context_methods[10] = HostThunk::D3D11DeviceContextPSSetSamplers;
        context_methods[11] = HostThunk::D3D11DeviceContextVSSetShader;
        context_methods[12] = HostThunk::D3D11DeviceContextDrawIndexed;
        context_methods[13] = HostThunk::D3D11DeviceContextDraw;
        context_methods[20] = HostThunk::D3D11DeviceContextDrawIndexedInstanced;
        context_methods[21] = HostThunk::D3D11DeviceContextDrawInstanced;
        context_methods[17] = HostThunk::D3D11DeviceContextIASetInputLayout;
        context_methods[18] = HostThunk::D3D11DeviceContextIASetVertexBuffers;
        context_methods[19] = HostThunk::D3D11DeviceContextIASetIndexBuffer;
        context_methods[24] = HostThunk::D3D11DeviceContextIASetPrimitiveTopology;
        context_methods[33] = HostThunk::D3D11DeviceContextOMSetRenderTargets;
        context_methods[35] = HostThunk::D3D11DeviceContextOMSetBlendState;
        context_methods[36] = HostThunk::D3D11DeviceContextOMSetDepthStencilState;
        context_methods[43] = HostThunk::D3D11DeviceContextRSSetState;
        context_methods[44] = HostThunk::D3D11DeviceContextRSSetViewports;
        context_methods[45] = HostThunk::D3D11DeviceContextRSSetScissorRects;
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

    fn alloc_d3d11_blend_state_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        state_id: u64,
    ) -> AppResult<u64> {
        let state_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11BlendState::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("ID3D11DeviceChild::GetDevice"),
                unsupported_method("ID3D11DeviceChild::GetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateDataInterface"),
            ],
        )?;
        let state_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11BlendState, state_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_blend_states.insert(
            state_object,
            GuestD3d11BlendState {
                device_object,
                state_id,
            },
        );
        Ok(state_object)
    }

    fn alloc_d3d11_rasterizer_state_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        state_id: u64,
    ) -> AppResult<u64> {
        let state_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11RasterizerState::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("ID3D11DeviceChild::GetDevice"),
                unsupported_method("ID3D11DeviceChild::GetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateDataInterface"),
            ],
        )?;
        let state_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11RasterizerState, state_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_rasterizer_states.insert(
            state_object,
            GuestD3d11RasterizerState {
                device_object,
                state_id,
            },
        );
        Ok(state_object)
    }

    fn alloc_d3d11_depth_stencil_state_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        state_id: u64,
    ) -> AppResult<u64> {
        let state_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11DepthStencilState::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("ID3D11DeviceChild::GetDevice"),
                unsupported_method("ID3D11DeviceChild::GetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateDataInterface"),
            ],
        )?;
        let state_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11DepthStencilState, state_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_depth_stencil_states.insert(
            state_object,
            GuestD3d11DepthStencilState {
                device_object,
                state_id,
            },
        );
        Ok(state_object)
    }

    fn alloc_d3d11_sampler_state_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        state_id: u64,
    ) -> AppResult<u64> {
        let state_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D11SamplerState::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method("ID3D11DeviceChild::GetDevice"),
                unsupported_method("ID3D11DeviceChild::GetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateData"),
                unsupported_method("ID3D11DeviceChild::SetPrivateDataInterface"),
            ],
        )?;
        let state_object = self.alloc_guest_object(memory, GuestObjectKind::D3d11SamplerState, state_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d11_sampler_states.insert(
            state_object,
            GuestD3d11SamplerState {
                device_object,
                state_id,
            },
        );
        Ok(state_object)
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

    fn destroy_d3d11_blend_state_object(&mut self, address: u64) -> AppResult<()> {
        let state = self
            .d3d11_blend_states
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 blend state {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(state.device_object)?;
        Ok(())
    }

    fn destroy_d3d11_rasterizer_state_object(&mut self, address: u64) -> AppResult<()> {
        let state = self
            .d3d11_rasterizer_states
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 rasterizer state {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(state.device_object)?;
        Ok(())
    }

    fn destroy_d3d11_depth_stencil_state_object(&mut self, address: u64) -> AppResult<()> {
        let state = self
            .d3d11_depth_stencil_states
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 depth stencil state {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(state.device_object)?;
        Ok(())
    }

    fn destroy_d3d11_sampler_state_object(&mut self, address: u64) -> AppResult<()> {
        let state = self
            .d3d11_sampler_states
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 sampler state {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(state.device_object)?;
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

    fn d3d11_blend_state(&self, address: u64) -> AppResult<GuestD3d11BlendState> {
        self.d3d11_blend_states
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 blend state {address:#x}")))
    }

    fn d3d11_rasterizer_state(&self, address: u64) -> AppResult<GuestD3d11RasterizerState> {
        self.d3d11_rasterizer_states
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 rasterizer state {address:#x}")))
    }

    fn d3d11_depth_stencil_state(&self, address: u64) -> AppResult<GuestD3d11DepthStencilState> {
        self.d3d11_depth_stencil_states
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 depth stencil state {address:#x}")))
    }

    fn d3d11_sampler_state(&self, address: u64) -> AppResult<GuestD3d11SamplerState> {
        self.d3d11_sampler_states
            .get(&address)
            .copied()
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D11 sampler state {address:#x}")))
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
        let (label, usage_hint) = read_d3d11_buffer_usage(memory, desc_ptr)?;
        let resource_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_buffer(&label, byte_width, usage_hint)
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
                ("label".to_string(), json!(label)),
                (
                    "usage_hint".to_string(),
                    json!(match usage_hint {
                        ResourceUsageHint::Buffer {
                            role,
                            cpu_write_frequent,
                        } => format!("{:?}:{}", role, cpu_write_frequent),
                        other => format!("{:?}", other),
                    }),
                ),
            ]),
            json!(buffer_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_texture2d(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateTexture2D on non-device object {device_object:#x}"),
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
        let desc = match read_d3d11_texture2d_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let resource_id = match self
            .d3d11_device_mut(device_object)?
            .device
            .create_texture_2d_with_usage(&desc.label, desc.width, desc.height, desc.format, desc.usage_hint)
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
                let bytes = read_guest_bytes(memory, src_ptr, desc.byte_width)?;
                self.d3d11_device_mut(device_object)?
                    .device
                    .update_subresource(resource_id, &bytes)?;
            }
        }
        let texture_object = self.alloc_d3d11_texture_object(memory, device_object, resource_id)?;
        write_u64(memory, out_ptr, texture_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateTexture2D",
            BTreeMap::from([
                ("width".to_string(), json!(desc.width)),
                ("height".to_string(), json!(desc.height)),
                ("format".to_string(), json!(format!("{:?}", desc.format))),
                ("label".to_string(), json!(desc.label)),
            ]),
            json!(texture_object),
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

    fn dispatch_d3d11_create_depth_stencil_view(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateDepthStencilView on non-device object {device_object:#x}"),
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
            .create_depth_stencil_view(resource_id, format)
        {
            Ok(view_id) => view_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let view_object = self.alloc_d3d11_view_object(memory, device_object, view_id, ViewKind::Dsv)?;
        write_u64(memory, out_ptr, view_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateDepthStencilView",
            BTreeMap::from([("format".to_string(), json!(format!("{:?}", format)))]),
            json!(view_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_render_target_view(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateRenderTargetView on non-device object {device_object:#x}"),
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
            .create_render_target_view(resource_id, format)
        {
            Ok(view_id) => view_id,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let view_object = self.alloc_d3d11_view_object(memory, device_object, view_id, ViewKind::Rtv)?;
        write_u64(memory, out_ptr, view_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateRenderTargetView",
            BTreeMap::from([("format".to_string(), json!(format!("{:?}", format)))]),
            json!(view_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_blend_state(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateBlendState on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_blend_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let state_id = self.d3d11_device_mut(device_object)?.device.create_blend_state(desc.clone());
        let state_object = self.alloc_d3d11_blend_state_object(memory, device_object, state_id)?;
        write_u64(memory, out_ptr, state_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateBlendState",
            BTreeMap::from([
                ("blend_enable".to_string(), json!(desc.blend_enable)),
                ("alpha_to_coverage".to_string(), json!(desc.alpha_to_coverage)),
            ]),
            json!(state_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_depth_stencil_state(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateDepthStencilState on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_depth_stencil_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let state_id = self
            .d3d11_device_mut(device_object)?
            .device
            .create_depth_stencil_state(desc.clone());
        let state_object = self.alloc_d3d11_depth_stencil_state_object(memory, device_object, state_id)?;
        write_u64(memory, out_ptr, state_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateDepthStencilState",
            BTreeMap::from([
                ("depth_enable".to_string(), json!(desc.depth_enable)),
                ("depth_write".to_string(), json!(desc.depth_write)),
            ]),
            json!(state_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_rasterizer_state(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateRasterizerState on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_rasterizer_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let state_id = self
            .d3d11_device_mut(device_object)?
            .device
            .create_rasterizer_state(desc.clone());
        let state_object = self.alloc_d3d11_rasterizer_state_object(memory, device_object, state_id)?;
        write_u64(memory, out_ptr, state_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateRasterizerState",
            BTreeMap::from([
                ("fill_mode".to_string(), json!(desc.fill_mode)),
                ("cull_mode".to_string(), json!(desc.cull_mode)),
            ]),
            json!(state_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_create_sampler_state(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d11Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D11Device::CreateSamplerState on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R8);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = match read_d3d11_sampler_desc(memory, desc_ptr) {
            Ok(desc) => desc,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        let state_id = self.d3d11_device_mut(device_object)?.device.create_sampler_state(desc.clone());
        let state_object = self.alloc_d3d11_sampler_state_object(memory, device_object, state_id)?;
        write_u64(memory, out_ptr, state_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11Device::CreateSamplerState",
            BTreeMap::from([
                ("filter".to_string(), json!(format!("{:?}", desc.filter))),
                ("address_u".to_string(), json!(desc.address_u)),
                ("address_v".to_string(), json!(desc.address_v)),
            ]),
            json!(state_object),
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

    fn dispatch_d3d11_ps_set_samplers(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let start_slot = state.get(Register::Rdx) as u32;
        let num_samplers = state.get(Register::R8) as usize;
        let samplers_ptr = state.get(Register::R9);
        if start_slot != 0 || (num_samplers != 0 && samplers_ptr == 0) {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut samplers = Vec::new();
        if num_samplers != 0 {
            let objects = read_guest_pointer_array(memory, samplers_ptr, num_samplers)?;
            if !objects.iter().all(|object| *object == 0) {
                samplers.reserve(objects.len());
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let sampler = self.d3d11_sampler_state(object)?;
                    if sampler.device_object != context.device_object {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    samplers.push(sampler.state_id);
                }
            }
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .ps_set_samplers(samplers.clone());
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::PSSetSamplers",
            BTreeMap::from([("count".to_string(), json!(samplers.len()))]),
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

    fn dispatch_d3d11_ia_set_vertex_buffers(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let start_slot = state.get(Register::Rdx) as u32;
        let num_buffers = state.get(Register::R8) as usize;
        let buffers_ptr = state.get(Register::R9);
        let stack = state.get(Register::Rsp);
        let strides_ptr = memory.read_u64(stack + 0x20)?;
        let offsets_ptr = memory.read_u64(stack + 0x28)?;
        if start_slot != 0 || (num_buffers != 0 && (buffers_ptr == 0 || strides_ptr == 0 || offsets_ptr == 0)) {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut buffers = Vec::new();
        if num_buffers != 0 {
            let objects = read_guest_pointer_array(memory, buffers_ptr, num_buffers)?;
            for index in 0..num_buffers as u64 {
                let _ = read_guest_u32(memory, strides_ptr + index * 4)?;
                let _ = read_guest_u32(memory, offsets_ptr + index * 4)?;
            }
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
            .ia_set_vertex_buffers(buffers.clone());
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::IASetVertexBuffers",
            BTreeMap::from([("count".to_string(), json!(buffers.len()))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d11_ia_set_index_buffer(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let buffer_object = state.get(Register::Rdx);
        let format = state.get(Register::R8) as u32;
        let offset = state.get(Register::R9) as u32;
        if buffer_object == 0 {
            self.d3d11_device_mut(context.device_object)?.device.ia_clear_index_buffer();
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace("d3d12", "ID3D11DeviceContext::IASetIndexBuffer", BTreeMap::new(), json!(0));
            return Ok(());
        }
        if format != 42 && format != 57 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let buffer = self.d3d11_buffer(buffer_object)?;
        if buffer.device_object != context.device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .ia_set_index_buffer(buffer.resource_id);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::IASetIndexBuffer",
            BTreeMap::from([
                ("format".to_string(), json!(format)),
                ("offset".to_string(), json!(offset)),
            ]),
            json!(buffer_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_ia_set_primitive_topology(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let topology = state.get(Register::Rdx) as u32;
        self.d3d11_device_mut(context.device_object)?
            .device
            .ia_set_primitive_topology(topology);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::IASetPrimitiveTopology",
            BTreeMap::from([("topology".to_string(), json!(topology))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d11_om_set_render_targets(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let count = state.get(Register::Rdx) as usize;
        let render_targets_ptr = state.get(Register::R8);
        let depth_view_object = state.get(Register::R9);
        if count != 0 && render_targets_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut render_targets = Vec::new();
        if count != 0 {
            let objects = read_guest_pointer_array(memory, render_targets_ptr, count)?;
            if !objects.iter().all(|object| *object == 0) {
                render_targets.reserve(objects.len());
                for object in objects {
                    if object == 0 {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    let view = self.d3d11_view(object)?;
                    if view.device_object != context.device_object || view.kind != ViewKind::Rtv {
                        state.set(Register::Rax, E_INVALIDARG);
                        self.last_error = 0;
                        return Ok(());
                    }
                    render_targets.push(view.view_id);
                }
            }
        }
        let depth_target = if depth_view_object == 0 {
            None
        } else {
            let view = self.d3d11_view(depth_view_object)?;
            if view.device_object != context.device_object || view.kind != ViewKind::Dsv {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
            Some(view.view_id)
        };
        self.d3d11_device_mut(context.device_object)?
            .device
            .om_set_render_targets(render_targets.clone(), depth_target);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::OMSetRenderTargets",
            BTreeMap::from([
                ("count".to_string(), json!(render_targets.len())),
                ("depth_bound".to_string(), json!(depth_target.is_some())),
            ]),
            json!(depth_view_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_om_set_blend_state(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let blend_state_object = state.get(Register::Rdx);
        if blend_state_object == 0 {
            self.d3d11_device_mut(context.device_object)?.device.om_clear_blend_state();
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace("d3d12", "ID3D11DeviceContext::OMSetBlendState", BTreeMap::new(), json!(0));
            return Ok(());
        }
        let blend_state = self.d3d11_blend_state(blend_state_object)?;
        if blend_state.device_object != context.device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .om_set_blend_state(blend_state.state_id);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::OMSetBlendState",
            BTreeMap::new(),
            json!(blend_state_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_om_set_depth_stencil_state(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let depth_stencil_state_object = state.get(Register::Rdx);
        let stencil_ref = state.get(Register::R8) as u32;
        if depth_stencil_state_object == 0 {
            self.d3d11_device_mut(context.device_object)?
                .device
                .om_clear_depth_stencil_state();
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace(
                "d3d12",
                "ID3D11DeviceContext::OMSetDepthStencilState",
                BTreeMap::from([("stencil_ref".to_string(), json!(stencil_ref))]),
                json!(0),
            );
            return Ok(());
        }
        let depth_stencil_state = self.d3d11_depth_stencil_state(depth_stencil_state_object)?;
        if depth_stencil_state.device_object != context.device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .om_set_depth_stencil_state(depth_stencil_state.state_id);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::OMSetDepthStencilState",
            BTreeMap::from([("stencil_ref".to_string(), json!(stencil_ref))]),
            json!(depth_stencil_state_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_rs_set_state(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let rasterizer_state_object = state.get(Register::Rdx);
        if rasterizer_state_object == 0 {
            self.d3d11_device_mut(context.device_object)?.device.rs_clear_state();
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace("d3d12", "ID3D11DeviceContext::RSSetState", BTreeMap::new(), json!(0));
            return Ok(());
        }
        let rasterizer_state = self.d3d11_rasterizer_state(rasterizer_state_object)?;
        if rasterizer_state.device_object != context.device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .rs_set_state(rasterizer_state.state_id);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::RSSetState",
            BTreeMap::new(),
            json!(rasterizer_state_object),
        );
        Ok(())
    }

    fn dispatch_d3d11_rs_set_viewports(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let count = state.get(Register::Rdx) as usize;
        let viewports_ptr = state.get(Register::R8);
        if count == 0 {
            self.d3d11_device_mut(context.device_object)?.device.rs_clear_viewports();
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace("d3d12", "ID3D11DeviceContext::RSSetViewports", BTreeMap::new(), json!(0));
            return Ok(());
        }
        if count != 1 || viewports_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let viewport = match read_d3d11_viewport(memory, viewports_ptr) {
            Ok(viewport) => viewport,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        self.d3d11_device_mut(context.device_object)?
            .device
            .rs_set_viewports(viewport.clone());
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::RSSetViewports",
            BTreeMap::from([
                ("width".to_string(), json!(viewport.width)),
                ("height".to_string(), json!(viewport.height)),
            ]),
            json!(count),
        );
        Ok(())
    }

    fn dispatch_d3d11_rs_set_scissor_rects(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let count = state.get(Register::Rdx) as usize;
        let rects_ptr = state.get(Register::R8);
        if count == 0 {
            self.d3d11_device_mut(context.device_object)?
                .device
                .rs_clear_scissor_rects();
            state.set(Register::Rax, 0);
            self.last_error = 0;
            self.push_trace("d3d12", "ID3D11DeviceContext::RSSetScissorRects", BTreeMap::new(), json!(0));
            return Ok(());
        }
        if count != 1 || rects_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let rect = match read_d3d11_scissor_rect(memory, rects_ptr) {
            Ok(rect) => rect,
            Err(_) => {
                state.set(Register::Rax, E_INVALIDARG);
                self.last_error = 0;
                return Ok(());
            }
        };
        self.d3d11_device_mut(context.device_object)?
            .device
            .rs_set_scissor_rects(rect.clone());
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::RSSetScissorRects",
            BTreeMap::from([
                ("left".to_string(), json!(rect.left)),
                ("top".to_string(), json!(rect.top)),
                ("right".to_string(), json!(rect.right)),
                ("bottom".to_string(), json!(rect.bottom)),
            ]),
            json!(count),
        );
        Ok(())
    }

    fn dispatch_d3d11_draw(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let vertex_count = state.get(Register::Rdx) as u32;
        let start_vertex_location = state.get(Register::R8) as u32;
        if start_vertex_location != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?.device.draw(vertex_count);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::Draw",
            BTreeMap::from([("vertices".to_string(), json!(vertex_count))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d11_draw_instanced(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let vertex_count_per_instance = state.get(Register::Rdx) as u32;
        let instance_count = state.get(Register::R8) as u32;
        let start_vertex_location = state.get(Register::R9) as u32;
        let start_instance_location = read_guest_u32(memory, state.get(Register::Rsp) + 0x20)?;
        if start_vertex_location != 0 || start_instance_location != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .draw_instanced(vertex_count_per_instance, instance_count);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::DrawInstanced",
            BTreeMap::from([
                ("vertices_per_instance".to_string(), json!(vertex_count_per_instance)),
                ("instances".to_string(), json!(instance_count)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d11_draw_indexed(&mut self, state: &mut CpuState) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let index_count = state.get(Register::Rdx) as u32;
        let start_index_location = state.get(Register::R8) as u32;
        let base_vertex_location = state.get(Register::R9) as i32;
        if start_index_location != 0 || base_vertex_location != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?.device.draw_indexed(index_count);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::DrawIndexed",
            BTreeMap::from([("indices".to_string(), json!(index_count))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d11_draw_indexed_instanced(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let context = self.d3d11_context(state.get(Register::Rcx))?;
        let index_count_per_instance = state.get(Register::Rdx) as u32;
        let instance_count = state.get(Register::R8) as u32;
        let start_index_location = state.get(Register::R9) as u32;
        let stack = state.get(Register::Rsp);
        let base_vertex_location = read_guest_u32(memory, stack + 0x20)? as i32;
        let start_instance_location = read_guest_u32(memory, stack + 0x28)?;
        if start_index_location != 0 || base_vertex_location != 0 || start_instance_location != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d11_device_mut(context.device_object)?
            .device
            .draw_indexed_instanced(index_count_per_instance, instance_count);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D11DeviceContext::DrawIndexedInstanced",
            BTreeMap::from([
                ("indices_per_instance".to_string(), json!(index_count_per_instance)),
                ("instances".to_string(), json!(instance_count)),
            ]),
            json!(0),
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

    fn alloc_dxgi_factory_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("IDXGIFactory::unsupported"); 26];
        methods[0] = unsupported_method("IDXGIFactory::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[7] = HostThunk::DXGIFactoryEnumAdapters;
        methods[10] = HostThunk::DXGIFactoryCreateSwapChain;
        methods[12] = HostThunk::DXGIFactoryEnumAdapters1;
        methods[15] = HostThunk::DXGIFactoryCreateSwapChainForHwnd;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::DxgiFactory, vtable)?;
        self.dxgi_factories.insert(object, GuestDxgiFactory);
        Ok(object)
    }

    fn alloc_dxgi_adapter_object(&mut self, memory: &mut MemoryImage, factory_object: u64) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("IDXGIAdapter::unsupported"); 11];
        methods[0] = unsupported_method("IDXGIAdapter::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[8] = HostThunk::DXGIAdapterGetDesc;
        methods[10] = HostThunk::DXGIAdapterGetDesc1;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::DxgiAdapter, vtable)?;
        let _ = self.add_ref_guest_object(factory_object)?;
        self.dxgi_adapters.insert(object, GuestDxgiAdapter { factory_object });
        Ok(object)
    }

    fn alloc_d3d12_device_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("ID3D12Device::unsupported"); 44];
        methods[0] = unsupported_method("ID3D12Device::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[8] = HostThunk::D3D12DeviceCreateCommandQueue;
        methods[9] = HostThunk::D3D12DeviceCreateCommandAllocator;
        methods[12] = HostThunk::D3D12DeviceCreateCommandList;
        methods[13] = HostThunk::D3D12DeviceCheckFeatureSupport;
        methods[14] = HostThunk::D3D12DeviceCreateDescriptorHeap;
        methods[20] = HostThunk::D3D12DeviceCreateRenderTargetView;
        methods[36] = HostThunk::D3D12DeviceCreateFence;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d12Device, vtable)?;
        self.d3d12_devices.insert(object, GuestD3d12Device);
        Ok(object)
    }

    fn alloc_d3d12_command_queue_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        queue_id: D3d12CommandQueueId,
    ) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("ID3D12CommandQueue::unsupported"); 19];
        methods[0] = unsupported_method("ID3D12CommandQueue::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[10] = HostThunk::D3D12CommandQueueExecuteCommandLists;
        methods[14] = HostThunk::D3D12CommandQueueSignal;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d12CommandQueue, vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d12_command_queues.insert(
            object,
            GuestD3d12CommandQueue {
                device_object,
                queue_id,
            },
        );
        Ok(object)
    }

    fn alloc_d3d12_command_allocator_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        allocator_id: D3d12CommandAllocatorId,
    ) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("ID3D12CommandAllocator::unsupported"); 9];
        methods[0] = unsupported_method("ID3D12CommandAllocator::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d12CommandAllocator, vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d12_command_allocators.insert(
            object,
            GuestD3d12CommandAllocator {
                device_object,
                allocator_id,
            },
        );
        Ok(object)
    }

    fn alloc_d3d12_descriptor_heap_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        heap_id: D3d12DescriptorHeapId,
        ty: DescriptorHeapType,
        descriptor_count: usize,
    ) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("ID3D12DescriptorHeap::unsupported"); 11];
        methods[0] = unsupported_method("ID3D12DescriptorHeap::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[9] = HostThunk::D3D12DescriptorHeapGetCpuHandleForHeapStart;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d12DescriptorHeap, vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        let cpu_handle_start = self.next_descriptor_handle;
        self.next_descriptor_handle = self
            .next_descriptor_handle
            .saturating_add(descriptor_count as u64 * DESCRIPTOR_HANDLE_STRIDE);
        self.d3d12_descriptor_heaps.insert(
            object,
            GuestD3d12DescriptorHeap {
                device_object,
                heap_id,
                ty,
                cpu_handle_start,
                descriptor_count,
            },
        );
        Ok(object)
    }

    fn alloc_d3d12_command_list_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        allocator_object: u64,
        command_list_id: D3d12CommandListId,
    ) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("ID3D12GraphicsCommandList::unsupported"); 49];
        methods[0] = unsupported_method("ID3D12GraphicsCommandList::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[9] = HostThunk::D3D12GraphicsCommandListClose;
        methods[12] = HostThunk::D3D12GraphicsCommandListDrawInstanced;
        methods[26] = HostThunk::D3D12GraphicsCommandListResourceBarrier;
        methods[48] = HostThunk::D3D12GraphicsCommandListClearRenderTargetView;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d12GraphicsCommandList, vtable)?;
        let _ = self.add_ref_guest_object(allocator_object)?;
        self.d3d12_command_lists.insert(
            object,
            GuestD3d12CommandList {
                device_object,
                allocator_object,
                command_list_id: Some(command_list_id),
                closed_stream: None,
            },
        );
        Ok(object)
    }

    fn alloc_d3d12_fence_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        fence_id: D3d12FenceId,
    ) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("ID3D12Fence::unsupported"); 11];
        methods[0] = unsupported_method("ID3D12Fence::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[8] = HostThunk::D3D12FenceGetCompletedValue;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d12Fence, vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d12_fences.insert(
            object,
            GuestD3d12Fence {
                device_object,
                fence_id,
            },
        );
        Ok(object)
    }

    fn alloc_d3d12_swapchain_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        swapchain_id: D3d12SwapchainId,
    ) -> AppResult<u64> {
        let mut methods = vec![unsupported_method("IDXGISwapChain::unsupported"); 18];
        methods[0] = unsupported_method("IDXGISwapChain::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[8] = HostThunk::DXGISwapChainPresent;
        methods[9] = HostThunk::DXGISwapChainGetBuffer;
        methods[13] = HostThunk::DXGISwapChainResizeBuffers;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::DxgiSwapChain, vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d12_swapchains.insert(
            object,
            GuestD3d12SwapChain {
                device_object,
                swapchain_id,
                backbuffer_objects: BTreeMap::new(),
            },
        );
        Ok(object)
    }

    fn alloc_d3d12_resource_object(
        &mut self,
        memory: &mut MemoryImage,
        device_object: u64,
        resource_id: D3d12ResourceId,
        format: DxgiFormat,
        swapchain_backbuffer: bool,
    ) -> AppResult<u64> {
        let resource_vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method("ID3D12Resource::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ],
        )?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::D3d12Resource, resource_vtable)?;
        let _ = self.add_ref_guest_object(device_object)?;
        self.d3d12_resources.insert(
            object,
            GuestD3d12Resource {
                device_object,
                resource_id,
                format,
                swapchain_backbuffer,
            },
        );
        Ok(object)
    }

    fn ensure_d3d12_guest_pipeline_state(&mut self) -> D3d12PipelineStateId {
        if let Some(pipeline_state) = self.d3d12_guest_pipeline_state {
            return pipeline_state;
        }
        let root_signature = self.d3d12_runtime.create_root_signature(RootSignatureDesc {
            descriptor_tables: Vec::new(),
            root_constants: 0,
        });
        let pipeline_state = self.d3d12_runtime.create_pipeline_state(
            root_signature,
            PipelineStateDesc {
                label: "guest-default".to_string(),
                compute: false,
                render_target_formats: Vec::new(),
                depth_format: None,
            },
        );
        self.d3d12_guest_root_signature = Some(root_signature);
        self.d3d12_guest_pipeline_state = Some(pipeline_state);
        pipeline_state
    }

    fn destroy_dxgi_factory_object(&mut self, address: u64) -> AppResult<()> {
        self.dxgi_factories.remove(&address);
        self.guest_objects.remove(&address);
        Ok(())
    }

    fn destroy_dxgi_adapter_object(&mut self, address: u64) -> AppResult<()> {
        let adapter = self
            .dxgi_adapters
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown DXGI adapter {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(adapter.factory_object)?;
        Ok(())
    }

    fn destroy_dxgi_swapchain_object(&mut self, address: u64) -> AppResult<()> {
        if let Some(swapchain) = self.d3d11_swapchains.remove(&address) {
            let _ = self.release_guest_object(swapchain.device_object)?;
            self.guest_objects.remove(&address);
            return Ok(());
        }
        if let Some(swapchain) = self.d3d12_swapchains.remove(&address) {
            for resource_object in swapchain.backbuffer_objects.into_values() {
                let _ = self.release_guest_object(resource_object)?;
            }
            let _ = self.release_guest_object(swapchain.device_object)?;
            self.guest_objects.remove(&address);
            return Ok(());
        }
        Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unknown DXGI swapchain {address:#x}"),
        ))
    }

    fn destroy_d3d12_device_object(&mut self, address: u64) -> AppResult<()> {
        self.d3d12_devices.remove(&address);
        self.guest_objects.remove(&address);
        Ok(())
    }

    fn destroy_d3d12_command_queue_object(&mut self, address: u64) -> AppResult<()> {
        if let Some(queue) = self.d3d12_command_queues.remove(&address) {
            let _ = self.release_guest_object(queue.device_object)?;
        }
        self.guest_objects.remove(&address);
        Ok(())
    }

    fn destroy_d3d12_command_allocator_object(&mut self, address: u64) -> AppResult<()> {
        let allocator = self
            .d3d12_command_allocators
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D12 command allocator {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(allocator.device_object)?;
        Ok(())
    }

    fn destroy_d3d12_descriptor_heap_object(&mut self, address: u64) -> AppResult<()> {
        let heap = self
            .d3d12_descriptor_heaps
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D12 descriptor heap {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(heap.device_object)?;
        Ok(())
    }

    fn destroy_d3d12_command_list_object(&mut self, address: u64) -> AppResult<()> {
        let command_list = self
            .d3d12_command_lists
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D12 command list {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(command_list.allocator_object)?;
        Ok(())
    }

    fn destroy_d3d12_fence_object(&mut self, address: u64) -> AppResult<()> {
        if let Some(fence) = self.d3d12_fences.remove(&address) {
            let _ = self.release_guest_object(fence.device_object)?;
        }
        self.guest_objects.remove(&address);
        Ok(())
    }

    fn destroy_d3d12_resource_object(&mut self, address: u64) -> AppResult<()> {
        let resource = self
            .d3d12_resources
            .remove(&address)
            .ok_or_else(|| AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D12 resource {address:#x}")))?;
        self.guest_objects.remove(&address);
        let _ = self.release_guest_object(resource.device_object)?;
        Ok(())
    }

    fn d3d12_command_queue(&self, address: u64) -> AppResult<GuestD3d12CommandQueue> {
        self.d3d12_command_queues.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D12 command queue {address:#x}"),
            )
        })
    }

    fn d3d12_fence(&self, address: u64) -> AppResult<GuestD3d12Fence> {
        self.d3d12_fences.get(&address).copied().ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("unknown D3D12 fence {address:#x}"))
        })
    }

    fn d3d12_command_allocator(&self, address: u64) -> AppResult<GuestD3d12CommandAllocator> {
        self.d3d12_command_allocators.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D12 command allocator {address:#x}"),
            )
        })
    }

    fn d3d12_descriptor_heap(&self, address: u64) -> AppResult<GuestD3d12DescriptorHeap> {
        self.d3d12_descriptor_heaps.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D12 descriptor heap {address:#x}"),
            )
        })
    }

    fn d3d12_command_list(&self, address: u64) -> AppResult<&GuestD3d12CommandList> {
        self.d3d12_command_lists.get(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D12 command list {address:#x}"),
            )
        })
    }

    fn d3d12_command_list_mut(&mut self, address: u64) -> AppResult<&mut GuestD3d12CommandList> {
        self.d3d12_command_lists.get_mut(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D12 command list {address:#x}"),
            )
        })
    }

    fn d3d12_swapchain(&self, address: u64) -> AppResult<&GuestD3d12SwapChain> {
        self.d3d12_swapchains.get(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D12 swapchain {address:#x}"),
            )
        })
    }

    fn d3d12_swapchain_mut(&mut self, address: u64) -> AppResult<&mut GuestD3d12SwapChain> {
        self.d3d12_swapchains.get_mut(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D12 swapchain {address:#x}"),
            )
        })
    }

    fn d3d12_resource(&self, address: u64) -> AppResult<GuestD3d12Resource> {
        self.d3d12_resources.get(&address).copied().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown D3D12 resource {address:#x}"),
            )
        })
    }

    fn dxgi_adapter(&self, address: u64) -> AppResult<GuestDxgiAdapter> {
        self.dxgi_adapters.get(&address).copied().ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, format!("unknown DXGI adapter {address:#x}"))
        })
    }

    fn open_d3d12_command_list_id(&self, address: u64) -> AppResult<D3d12CommandListId> {
        self.d3d12_command_list(address)?
            .command_list_id
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, format!("D3D12 command list {address:#x} is already closed")))
    }

    fn decode_d3d12_cpu_descriptor_handle(
        &self,
        handle: u64,
        expected_type: DescriptorHeapType,
    ) -> AppResult<(GuestD3d12DescriptorHeap, usize)> {
        self.d3d12_descriptor_heaps
            .values()
            .find_map(|heap| {
                let byte_len = heap.descriptor_count as u64 * DESCRIPTOR_HANDLE_STRIDE;
                if handle < heap.cpu_handle_start || handle >= heap.cpu_handle_start + byte_len {
                    return None;
                }
                let offset = handle - heap.cpu_handle_start;
                if offset % DESCRIPTOR_HANDLE_STRIDE != 0 {
                    return None;
                }
                Some((*heap, (offset / DESCRIPTOR_HANDLE_STRIDE) as usize))
            })
            .ok_or_else(|| AppError::new(ReasonCode::RcD3dInvalidState, format!("unknown CPU descriptor handle {handle:#x}")))
            .and_then(|(heap, index)| {
                if heap.ty != expected_type {
                    return Err(AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!("descriptor heap type mismatch for handle {handle:#x}: expected {:?}, found {:?}", expected_type, heap.ty),
                    ));
                }
                Ok((heap, index))
            })
    }

    fn ensure_d3d12_backbuffer_object(
        &mut self,
        memory: &mut MemoryImage,
        swapchain_object: u64,
        index: u32,
    ) -> AppResult<u64> {
        let (device_object, swapchain_id, existing) = {
            let swapchain = self.d3d12_swapchain(swapchain_object)?;
            (
                swapchain.device_object,
                swapchain.swapchain_id,
                swapchain.backbuffer_objects.get(&index).copied(),
            )
        };
        if let Some(existing) = existing {
            return Ok(existing);
        }
        let resource_id = self
            .d3d12_runtime
            .swapchain_state(swapchain_id)?
            .backbuffers
            .get(index as usize)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcD3dInvalidState,
                    format!("swapchain backbuffer index {index} is out of bounds"),
                )
            })?;
        let format = self.d3d12_runtime.swapchain_state(swapchain_id)?.desc.format;
        let resource_object = self.alloc_d3d12_resource_object(memory, device_object, resource_id, format, true)?;
        self.d3d12_swapchain_mut(swapchain_object)?
            .backbuffer_objects
            .insert(index, resource_object);
        Ok(resource_object)
    }

    fn create_d3d12_swapchain_from_desc(
        &mut self,
        memory: &mut MemoryImage,
        queue_object: u64,
        desc: SwapchainDesc,
    ) -> AppResult<u64> {
        let queue = self.d3d12_command_queue(queue_object)?;
        let swapchain_id = self.d3d12_runtime.create_swapchain(desc)?;
        self.alloc_d3d12_swapchain_object(memory, queue.device_object, swapchain_id)
    }

    fn dispatch_dxgi_factory_enum_adapters(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
        extended: bool,
    ) -> AppResult<()> {
        let factory_object = state.get(Register::Rcx);
        if self.guest_object_kind(factory_object)? != GuestObjectKind::DxgiFactory {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("IDXGIFactory::EnumAdapters on non-factory object {factory_object:#x}"),
            ));
        }
        let adapter_index = state.get(Register::Rdx) as u32;
        let out_ptr = state.get(Register::R8);
        if out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        if adapter_index != 0 {
            write_u64(memory, out_ptr, 0);
            state.set(Register::Rax, DXGI_ERROR_NOT_FOUND);
            self.last_error = 0;
            return Ok(());
        }

        let device_info = self.d3d12_runtime.device_info();
        let adapter_object = self.alloc_dxgi_adapter_object(memory, factory_object)?;
        write_u64(memory, out_ptr, adapter_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "dxgi",
            if extended {
                "IDXGIFactory1::EnumAdapters1"
            } else {
                "IDXGIFactory::EnumAdapters"
            },
            BTreeMap::from([
                ("index".to_string(), json!(adapter_index)),
                ("adapter".to_string(), json!(device_info.adapter.name)),
                ("vendor_id".to_string(), json!(format!("0x{:04x}", device_info.adapter.vendor_id))),
                ("device_id".to_string(), json!(format!("0x{:04x}", device_info.adapter.device_id))),
            ]),
            json!(adapter_object),
        );
        Ok(())
    }

    fn dispatch_dxgi_adapter_get_desc(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
        extended: bool,
    ) -> AppResult<()> {
        let adapter_object = state.get(Register::Rcx);
        let desc_ptr = state.get(Register::Rdx);
        if self.guest_object_kind(adapter_object)? != GuestObjectKind::DxgiAdapter {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("IDXGIAdapter::GetDesc on non-adapter object {adapter_object:#x}"),
            ));
        }
        if desc_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }

        let _ = self.dxgi_adapter(adapter_object)?;
        let device_info = self.d3d12_runtime.device_info();
        let bytes = build_dxgi_adapter_desc_bytes(
            &device_info.adapter,
            device_info.features.unified_memory,
            extended,
        );
        memory.map_bytes(desc_ptr, &bytes);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "dxgi",
            if extended {
                "IDXGIAdapter1::GetDesc1"
            } else {
                "IDXGIAdapter::GetDesc"
            },
            BTreeMap::from([
                ("adapter".to_string(), json!(device_info.adapter.name)),
                ("vendor_id".to_string(), json!(format!("0x{:04x}", device_info.adapter.vendor_id))),
                ("device_id".to_string(), json!(format!("0x{:04x}", device_info.adapter.device_id))),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_dxgi_create_swapchain(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let factory_object = state.get(Register::Rcx);
        if self.guest_object_kind(factory_object)? != GuestObjectKind::DxgiFactory {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("IDXGIFactory::CreateSwapChain on non-factory object {factory_object:#x}"),
            ));
        }
        let queue_object = state.get(Register::Rdx);
        let desc_ptr = state.get(Register::R8);
        let out_ptr = state.get(Register::R9);
        if out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = read_swapchain_desc(memory, desc_ptr)?;
        let swapchain_object = self.create_d3d12_swapchain_from_desc(memory, queue_object, desc.clone())?;
        write_u64(memory, out_ptr, swapchain_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "dxgi",
            "IDXGIFactory::CreateSwapChain",
            BTreeMap::from([
                ("width".to_string(), json!(desc.width)),
                ("height".to_string(), json!(desc.height)),
                ("buffer_count".to_string(), json!(desc.buffer_count)),
                ("format".to_string(), json!(format!("{:?}", desc.format))),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_dxgi_create_swapchain_for_hwnd(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let factory_object = state.get(Register::Rcx);
        if self.guest_object_kind(factory_object)? != GuestObjectKind::DxgiFactory {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("IDXGIFactory2::CreateSwapChainForHwnd on non-factory object {factory_object:#x}"),
            ));
        }
        let queue_object = state.get(Register::Rdx);
        let hwnd = state.get(Register::R8);
        let desc_ptr = state.get(Register::R9);
        let stack = state.get(Register::Rsp);
        let out_ptr = memory.read_u64(stack + 0x30)?;
        if hwnd == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let desc = read_swapchain_desc1(memory, desc_ptr)?;
        let swapchain_object = self.create_d3d12_swapchain_from_desc(memory, queue_object, desc.clone())?;
        write_u64(memory, out_ptr, swapchain_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "dxgi",
            "IDXGIFactory2::CreateSwapChainForHwnd",
            BTreeMap::from([
                ("width".to_string(), json!(desc.width)),
                ("height".to_string(), json!(desc.height)),
                ("buffer_count".to_string(), json!(desc.buffer_count)),
                ("format".to_string(), json!(format!("{:?}", desc.format))),
                ("hwnd".to_string(), json!(hwnd)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_dxgi_swapchain_get_buffer(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let swapchain_object = state.get(Register::Rcx);
        let index = state.get(Register::Rdx) as u32;
        let out_ptr = state.get(Register::R9);
        if out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let resource_object = if self.d3d11_swapchains.contains_key(&swapchain_object) {
            self.ensure_d3d11_backbuffer_object(memory, swapchain_object, index)?
        } else if self.d3d12_swapchains.contains_key(&swapchain_object) {
            self.ensure_d3d12_backbuffer_object(memory, swapchain_object, index)?
        } else {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("GetBuffer on unknown DXGI swapchain {swapchain_object:#x}"),
            ));
        };
        let _ = self.add_ref_guest_object(resource_object)?;
        write_u64(memory, out_ptr, resource_object);
        let mut trace_params = BTreeMap::from([("index".to_string(), json!(index))]);
        if let Some(resource) = self.d3d12_resources.get(&resource_object) {
            trace_params.insert("resource_id".to_string(), json!(resource.resource_id));
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "dxgi",
            "IDXGISwapChain::GetBuffer",
            trace_params,
            json!(0),
        );
        Ok(())
    }

    fn dispatch_dxgi_swapchain_present(&mut self, state: &mut CpuState) -> AppResult<()> {
        let swapchain_object = state.get(Register::Rcx);
        let sync_interval = state.get(Register::Rdx) as u32;
        let flags = state.get(Register::R8) as u32;
        let allow_tearing = flags & 0x0200 != 0;
        if self.d3d11_swapchains.contains_key(&swapchain_object) {
            self.dispatch_d3d11_swapchain_present(sync_interval, allow_tearing, swapchain_object, state)
        } else if self.d3d12_swapchains.contains_key(&swapchain_object) {
            self.dispatch_d3d12_swapchain_present(sync_interval, allow_tearing, swapchain_object, state)
        } else {
            Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("Present on unknown DXGI swapchain {swapchain_object:#x}"),
            ))
        }
    }

    fn dispatch_dxgi_swapchain_resize_buffers(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let swapchain_object = state.get(Register::Rcx);
        let buffer_count = state.get(Register::Rdx) as u32;
        let width = state.get(Register::R8) as u32;
        let height = state.get(Register::R9) as u32;
        if !self.d3d12_swapchains.contains_key(&swapchain_object) {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ResizeBuffers on non-D3D12 swapchain {swapchain_object:#x}"),
            ));
        }
        let stack = state.get(Register::Rsp);
        let format_raw = read_guest_u32(memory, stack + 0x20)?;
        let flags = read_guest_u32(memory, stack + 0x28)?;
        let swapchain = self.d3d12_swapchain(swapchain_object)?.clone();
        let current_desc = self.d3d12_runtime.swapchain_state(swapchain.swapchain_id)?.desc;
        let resolved_buffer_count = if buffer_count == 0 { current_desc.buffer_count } else { buffer_count };
        let resolved_width = if width == 0 { current_desc.width } else { width };
        let resolved_height = if height == 0 { current_desc.height } else { height };
        let resolved_format = if format_raw == 0 {
            current_desc.format
        } else {
            map_dxgi_format(format_raw)?
        };
        for resource_object in swapchain.backbuffer_objects.values().copied().collect::<Vec<_>>() {
            let _ = self.release_guest_object(resource_object)?;
        }
        self.d3d12_swapchain_mut(swapchain_object)?.backbuffer_objects.clear();
        self.d3d12_runtime.resize_buffers(
            swapchain.swapchain_id,
            resolved_buffer_count,
            resolved_width,
            resolved_height,
            resolved_format,
        )?;
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "dxgi",
            "IDXGISwapChain::ResizeBuffers",
            BTreeMap::from([
                ("buffer_count".to_string(), json!(resolved_buffer_count)),
                ("width".to_string(), json!(resolved_width)),
                ("height".to_string(), json!(resolved_height)),
                ("format".to_string(), json!(format!("{:?}", resolved_format))),
                ("flags".to_string(), json!(flags)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d11_swapchain_present(
        &mut self,
        sync_interval: u32,
        allow_tearing: bool,
        swapchain_object: u64,
        state: &mut CpuState,
    ) -> AppResult<()> {
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
            self.published_live_frame = true;
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
        Ok(())
    }

    fn dispatch_d3d12_swapchain_present(
        &mut self,
        sync_interval: u32,
        allow_tearing: bool,
        swapchain_object: u64,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let swapchain_id = self.d3d12_swapchain(swapchain_object)?.swapchain_id;
        let present = self.d3d12_runtime.present(swapchain_id, sync_interval, allow_tearing)?;
        let frame = self.d3d12_runtime.presented_frame(swapchain_id)?;
        let displayed_frame_index = present.displayed_frame_index;
        let queued_frames = present.queued_frames;
        let live_frame = LiveFrame {
            width: frame.width,
            height: frame.height,
            format: frame.format,
            bytes: frame.bytes.clone(),
            displayed_frame_index,
        };
        if self.live_session.is_some() {
            self.publish_live_frame(live_frame);
            self.published_live_frame = true;
        } else {
            self.gfx_frames.push(GfxFrame {
                scene_id: "pe-runtime-d3d12".to_string(),
                frame_index: self.next_frame_index,
                hash: util::sha256_bytes(&frame.bytes),
                ssim: 1.0,
                metadata: BTreeMap::from([
                    ("width".to_string(), frame.width.to_string()),
                    ("height".to_string(), frame.height.to_string()),
                    ("format".to_string(), format!("{:?}", frame.format)),
                    ("displayed_frame_index".to_string(), displayed_frame_index.to_string()),
                ]),
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
        Ok(())
    }

    fn dispatch_d3d12_create_command_queue(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d12Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D12Device::CreateCommandQueue on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R9);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let (queue_type, priority, flags, node_mask) = read_d3d12_command_queue_desc(memory, desc_ptr)?;
        let queue_id = self.d3d12_runtime.create_command_queue();
        let queue_object = self.alloc_d3d12_command_queue_object(memory, device_object, queue_id)?;
        write_u64(memory, out_ptr, queue_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12Device::CreateCommandQueue",
            BTreeMap::from([
                ("flags".to_string(), json!(flags)),
                ("node_mask".to_string(), json!(node_mask)),
                ("priority".to_string(), json!(priority)),
                ("type".to_string(), json!(queue_type)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_create_command_allocator(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d12Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D12Device::CreateCommandAllocator on non-device object {device_object:#x}"),
            ));
        }
        let command_list_type = state.get(Register::Rdx) as u32;
        let out_ptr = state.get(Register::R9);
        if out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let allocator_id = self.d3d12_runtime.create_command_allocator();
        let allocator_object = self.alloc_d3d12_command_allocator_object(memory, device_object, allocator_id)?;
        write_u64(memory, out_ptr, allocator_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12Device::CreateCommandAllocator",
            BTreeMap::from([("type".to_string(), json!(command_list_type))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_create_command_list(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d12Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D12Device::CreateCommandList on non-device object {device_object:#x}"),
            ));
        }
        let node_mask = state.get(Register::Rdx) as u32;
        let command_list_type = state.get(Register::R8) as u32;
        let allocator_object = state.get(Register::R9);
        let stack = state.get(Register::Rsp);
        let initial_state = memory.read_u64(stack + 0x20)?;
        let out_ptr = memory.read_u64(stack + 0x30)?;
        if allocator_object == 0 || out_ptr == 0 || initial_state != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let allocator = self.d3d12_command_allocator(allocator_object)?;
        if allocator.device_object != device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let pipeline_state = self.ensure_d3d12_guest_pipeline_state();
        let command_list_id = self
            .d3d12_runtime
            .create_graphics_command_list(allocator.allocator_id, pipeline_state);
        let command_list_object = self.alloc_d3d12_command_list_object(
            memory,
            device_object,
            allocator_object,
            command_list_id,
        )?;
        write_u64(memory, out_ptr, command_list_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12Device::CreateCommandList",
            BTreeMap::from([
                ("node_mask".to_string(), json!(node_mask)),
                ("type".to_string(), json!(command_list_type)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_check_feature_support(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d12Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D12Device::CheckFeatureSupport on non-device object {device_object:#x}"),
            ));
        }
        let feature = state.get(Register::Rdx) as u32;
        let data_ptr = state.get(Register::R8);
        let data_size = state.get(Register::R9) as usize;
        if data_ptr == 0 || data_size == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }

        let device_info = self.d3d12_runtime.device_info();
        let Some(trace_params) = write_d3d12_feature_support(memory, feature, data_ptr, data_size, &device_info)? else {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        };
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace("d3d12", "ID3D12Device::CheckFeatureSupport", trace_params, json!(0));
        Ok(())
    }

    fn dispatch_d3d12_create_descriptor_heap(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d12Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D12Device::CreateDescriptorHeap on non-device object {device_object:#x}"),
            ));
        }
        let desc_ptr = state.get(Register::Rdx);
        let out_ptr = state.get(Register::R9);
        if desc_ptr == 0 || out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let (heap_type, descriptor_count, flags, node_mask) = read_d3d12_descriptor_heap_desc(memory, desc_ptr)?;
        let heap_id = self.d3d12_runtime.create_descriptor_heap(heap_type, descriptor_count);
        let heap_object = self.alloc_d3d12_descriptor_heap_object(
            memory,
            device_object,
            heap_id,
            heap_type,
            descriptor_count,
        )?;
        write_u64(memory, out_ptr, heap_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12Device::CreateDescriptorHeap",
            BTreeMap::from([
                ("type".to_string(), json!(format!("{:?}", heap_type))),
                ("descriptor_count".to_string(), json!(descriptor_count)),
                ("flags".to_string(), json!(flags)),
                ("node_mask".to_string(), json!(node_mask)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_create_render_target_view(&mut self, state: &mut CpuState) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d12Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D12Device::CreateRenderTargetView on non-device object {device_object:#x}"),
            ));
        }
        let resource = self.d3d12_resource(state.get(Register::Rdx))?;
        let descriptor_handle = state.get(Register::R9);
        let (heap, index) = self.decode_d3d12_cpu_descriptor_handle(descriptor_handle, DescriptorHeapType::Rtv)?;
        if resource.device_object != device_object || heap.device_object != device_object {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                "RTV resource and descriptor heap must belong to the same D3D12 device",
            ));
        }
        self.d3d12_runtime.write_descriptor(
            heap.heap_id,
            index,
            ViewDescriptor::Rtv {
                resource: resource.resource_id,
                format: resource.format,
            },
        )?;
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12Device::CreateRenderTargetView",
            BTreeMap::from([
                ("descriptor_index".to_string(), json!(index)),
                ("format".to_string(), json!(format!("{:?}", resource.format))),
                ("resource_id".to_string(), json!(resource.resource_id)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_create_fence(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let device_object = state.get(Register::Rcx);
        if self.guest_object_kind(device_object)? != GuestObjectKind::D3d12Device {
            return Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("ID3D12Device::CreateFence on non-device object {device_object:#x}"),
            ));
        }
        let initial_value = state.get(Register::Rdx);
        let flags = state.get(Register::R8) as u32;
        let stack = state.get(Register::Rsp);
        let out_ptr = memory.read_u64(stack + 0x20)?;
        if out_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let fence_id = self.d3d12_runtime.create_fence(initial_value);
        let fence_object = self.alloc_d3d12_fence_object(memory, device_object, fence_id)?;
        write_u64(memory, out_ptr, fence_object);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12Device::CreateFence",
            BTreeMap::from([
                ("flags".to_string(), json!(flags)),
                ("initial_value".to_string(), json!(initial_value)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_command_queue_execute_command_lists(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let queue = self.d3d12_command_queue(state.get(Register::Rcx))?;
        let count = state.get(Register::Rdx) as usize;
        let lists_ptr = state.get(Register::R8);
        if count != 0 && lists_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let mut streams = Vec::with_capacity(count);
        if count != 0 {
            let command_list_objects = read_guest_pointer_array(memory, lists_ptr, count)?;
            for command_list_object in command_list_objects {
                let command_list = self.d3d12_command_list(command_list_object)?;
                if command_list.device_object != queue.device_object {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = 0;
                    return Ok(());
                }
                let stream = command_list.closed_stream.clone().ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        format!("D3D12 command list {command_list_object:#x} must be closed before execute"),
                    )
                })?;
                streams.push(stream);
            }
        }
        let (render_passes, compute_passes, blit_passes) = if streams.is_empty() {
            (0, 0, 0)
        } else {
            let plan = self.d3d12_runtime.execute_command_lists(queue.queue_id, &streams, None)?;
            (plan.render_passes.len(), plan.compute_passes, plan.blit_passes)
        };
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12CommandQueue::ExecuteCommandLists",
            BTreeMap::from([
                ("command_lists".to_string(), json!(count)),
                ("render_passes".to_string(), json!(render_passes)),
                ("compute_passes".to_string(), json!(compute_passes)),
                ("blit_passes".to_string(), json!(blit_passes)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_command_queue_signal(&mut self, state: &mut CpuState) -> AppResult<()> {
        let queue = self.d3d12_command_queue(state.get(Register::Rcx))?;
        let fence = self.d3d12_fence(state.get(Register::Rdx))?;
        let value = state.get(Register::R8);
        if fence.device_object != queue.device_object {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d12_runtime.signal_fence(fence.fence_id, value)?;
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12CommandQueue::Signal",
            BTreeMap::from([
                ("queue_id".to_string(), json!(queue.queue_id)),
                ("value".to_string(), json!(value)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_descriptor_heap_get_cpu_handle_for_heap_start(
        &mut self,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let heap = self.d3d12_descriptor_heap(state.get(Register::Rcx))?;
        state.set(Register::Rax, heap.cpu_handle_start);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12DescriptorHeap::GetCPUDescriptorHandleForHeapStart",
            BTreeMap::from([
                ("descriptor_count".to_string(), json!(heap.descriptor_count)),
                ("type".to_string(), json!(format!("{:?}", heap.ty))),
            ]),
            json!(heap.cpu_handle_start),
        );
        Ok(())
    }

    fn dispatch_d3d12_graphics_command_list_resource_barrier(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let command_list_object = state.get(Register::Rcx);
        let barrier_count = state.get(Register::Rdx) as usize;
        let barriers_ptr = state.get(Register::R8);
        if barrier_count != 0 && barriers_ptr == 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let command_list_id = self.open_d3d12_command_list_id(command_list_object)?;
        for index in 0..barrier_count {
            let barrier_address = barriers_ptr + index as u64 * 32;
            let barrier = read_d3d12_resource_barrier(memory, barrier_address)?;
            let resource = self.d3d12_resource(barrier.resource_object)?;
            let subresource = if barrier.subresource == u32::MAX { 0 } else { barrier.subresource };
            let current_state = self.d3d12_runtime.resource_state(resource.resource_id, subresource)?;
            let from = map_d3d12_resource_state(barrier.state_before, resource, Some(current_state), true)?;
            let to = map_d3d12_resource_state(barrier.state_after, resource, Some(current_state), false)?;
            self.d3d12_runtime
                .record_transition(command_list_id, resource.resource_id, subresource, from, to)?;
        }
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12GraphicsCommandList::ResourceBarrier",
            BTreeMap::from([("barriers".to_string(), json!(barrier_count))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_graphics_command_list_clear_render_target_view(
        &mut self,
        _memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let command_list_id = self.open_d3d12_command_list_id(state.get(Register::Rcx))?;
        let descriptor_handle = state.get(Register::Rdx);
        let num_rects = state.get(Register::R9) as u32;
        if num_rects != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let (heap, index) = self.decode_d3d12_cpu_descriptor_handle(descriptor_handle, DescriptorHeapType::Rtv)?;
        self.d3d12_runtime.record_clear_rtv(command_list_id, heap.heap_id, index)?;
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12GraphicsCommandList::ClearRenderTargetView",
            BTreeMap::from([("descriptor_index".to_string(), json!(index))]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_graphics_command_list_draw_instanced(
        &mut self,
        memory: &mut MemoryImage,
        state: &mut CpuState,
    ) -> AppResult<()> {
        let command_list_id = self.open_d3d12_command_list_id(state.get(Register::Rcx))?;
        let vertex_count = state.get(Register::Rdx) as u32;
        let instance_count = state.get(Register::R8) as u32;
        let start_vertex = state.get(Register::R9) as u32;
        let start_instance = read_guest_u32(memory, state.get(Register::Rsp) + 0x20)?;
        if start_vertex != 0 || start_instance != 0 {
            state.set(Register::Rax, E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        self.d3d12_runtime
            .record_draw_instanced(command_list_id, vertex_count, instance_count)?;
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12GraphicsCommandList::DrawInstanced",
            BTreeMap::from([
                ("instances".to_string(), json!(instance_count)),
                ("vertices".to_string(), json!(vertex_count)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_graphics_command_list_close(&mut self, state: &mut CpuState) -> AppResult<()> {
        let command_list_object = state.get(Register::Rcx);
        let command_list_id = {
            let command_list = self.d3d12_command_list_mut(command_list_object)?;
            match command_list.command_list_id.take() {
                Some(command_list_id) => command_list_id,
                None => {
                    state.set(Register::Rax, E_INVALIDARG);
                    self.last_error = 0;
                    return Ok(());
                }
            }
        };
        let stream = self.d3d12_runtime.close_command_list(command_list_id)?;
        let stream_id = stream.id;
        let command_count = stream.commands.len();
        let command_list = self.d3d12_command_list_mut(command_list_object)?;
        command_list.closed_stream = Some(stream);
        state.set(Register::Rax, 0);
        self.last_error = 0;
        self.push_trace(
            "d3d12",
            "ID3D12GraphicsCommandList::Close",
            BTreeMap::from([
                ("command_list_id".to_string(), json!(stream_id)),
                ("commands".to_string(), json!(command_count)),
            ]),
            json!(0),
        );
        Ok(())
    }

    fn dispatch_d3d12_fence_get_completed_value(&mut self, state: &mut CpuState) -> AppResult<()> {
        let fence = self.d3d12_fence(state.get(Register::Rcx))?;
        let value = self.d3d12_runtime.fence_value(fence.fence_id)?;
        state.set(Register::Rax, value);
        self.last_error = 0;
        self.push_trace("d3d12", "ID3D12Fence::GetCompletedValue", BTreeMap::new(), json!(value));
        Ok(())
    }
}

impl HostThunk {
    fn from_import(import: &ResolvedImport) -> Self {
        let dll = import.resolved_module.to_ascii_lowercase();
        match (&dll[..], &import.symbol) {
            ("dxgi.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDXGIFactory1" => {
                Self::CreateDXGIFactory1
            }
            ("dxgi.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDXGIFactory2" => {
                Self::CreateDXGIFactory2
            }
            ("d3d11.dll", ImportSymbol::ByName { name, .. }) if name == "D3D11CreateDevice" => {
                Self::D3D11CreateDevice
            }
            ("d3d11.dll", ImportSymbol::ByName { name, .. }) if name == "D3D11CreateDeviceAndSwapChain" => {
                Self::D3D11CreateDeviceAndSwapChain
            }
            ("d3d12.dll", ImportSymbol::ByName { name, .. }) if name == "D3D12CreateDevice" => {
                Self::D3D12CreateDevice
            }
            ("xaudio2_9.dll", ImportSymbol::ByName { name, .. }) if name == "XAudio2Create" => {
                Self::XAudio2Create
            }
            ("xaudio2_9redist.dll", ImportSymbol::ByName { name, .. }) if name == "XAudio2Create" => {
                Self::XAudio2Create
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "RegisterClassW" => {
                Self::RegisterClassW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "RegisterClassExW" => {
                Self::RegisterClassExW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetClassInfoW" => {
                Self::GetClassInfoW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDlgItem" => Self::GetDlgItem,
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetClientRect" => {
                Self::GetClientRect
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowRect" => {
                Self::GetWindowRect
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EnableWindow" => {
                Self::EnableWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "IsWindowEnabled" => {
                Self::IsWindowEnabled
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemMenu" => {
                Self::GetSystemMenu
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EnableMenuItem" => {
                Self::EnableMenuItem
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "InvalidateRect" => {
                Self::InvalidateRect
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "BeginPaint" => {
                Self::BeginPaint
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "FillRect" => {
                Self::FillRect
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EndPaint" => {
                Self::EndPaint
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ScreenToClient" => {
                Self::ScreenToClient
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetWindowPos" => {
                Self::SetWindowPos
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSysColor" => {
                Self::GetSysColor
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadCursorW" => {
                Self::LoadCursorW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadBitmapW" => {
                Self::LoadBitmapW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CheckDlgButton" => {
                Self::CheckDlgButton
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMessagePos" => {
                Self::GetMessagePos
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "IsWindowVisible" => {
                Self::IsWindowVisible
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemMetrics" => {
                Self::GetSystemMetrics
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDlgItemTextW" => {
                Self::GetDlgItemTextW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "IsWindow" => {
                Self::IsWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "FindWindowExW" => {
                Self::FindWindowExW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CallWindowProcW" => {
                Self::CallWindowProcW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CreatePopupMenu" => {
                Self::CreatePopupMenu
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "AppendMenuW" => {
                Self::AppendMenuW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "TrackPopupMenu" => {
                Self::TrackPopupMenu
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "PostQuitMessage" => {
                Self::PostQuitMessage
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetTimer" => {
                Self::SetTimer
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SystemParametersInfoW" => {
                Self::SystemParametersInfoW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SendMessageTimeoutW" => {
                Self::SendMessageTimeoutW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ExitWindowsEx" => {
                Self::ExitWindowsEx
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetDlgItemTextW" => {
                Self::SetDlgItemTextW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetClassLongW" => {
                Self::SetClassLongW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateWindowExW" => {
                Self::CreateWindowExW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DialogBoxParamW" => {
                Self::DialogBoxParamW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EndDialog" => {
                Self::EndDialog
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDialogParamW" => {
                Self::CreateDialogParamW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ShowWindow" => {
                Self::ShowWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDC" => Self::GetDC,
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseDC" => {
                Self::ReleaseDC
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetForegroundWindow" => {
                Self::SetForegroundWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DestroyWindow" => {
                Self::DestroyWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetWindowTextW" => {
                Self::SetWindowTextW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowLongW" => {
                Self::GetWindowLongW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetWindowLongW" => {
                Self::SetWindowLongW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadImageW" => {
                Self::LoadImageW
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
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SendMessageW" => {
                Self::SendMessageW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDeviceCaps" => {
                Self::GetDeviceCaps
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SelectObject" => {
                Self::SelectObject
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFontIndirectW" => {
                Self::CreateFontIndirectW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteObject" => {
                Self::DeleteObject
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetBkMode" => Self::SetBkMode,
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetTextColor" => {
                Self::SetTextColor
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DrawTextW" => Self::DrawTextW,
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "wsprintfW" => {
                Self::WsprintfW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetCurrentDirectoryW" => {
                Self::SetCurrentDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFullPathNameW" => {
                Self::GetFullPathNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "MulDiv" => Self::MulDiv,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileAttributesW" => {
                Self::GetFileAttributesW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FindFirstFileW" => {
                Self::FindFirstFileW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FindNextFileW" => {
                Self::FindNextFileW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FindClose" => {
                Self::FindClose
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetFileAttributesW" => {
                Self::SetFileAttributesW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetErrorMode" => {
                Self::SetErrorMode
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetDefaultDllDirectories" => {
                Self::SetDefaultDllDirectories
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemDirectoryW" => {
                Self::GetSystemDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowsDirectoryW" => {
                Self::GetWindowsDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTempPathW" => {
                Self::GetTempPathW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTempFileNameW" => {
                Self::GetTempFileNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleFileNameW" => {
                Self::GetModuleFileNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDiskFreeSpaceW" => {
                Self::GetDiskFreeSpaceW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileSize" => {
                Self::GetFileSize
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteFileW" => {
                Self::DeleteFileW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WritePrivateProfileStringW" => {
                Self::WritePrivateProfileStringW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateProcessW" => {
                Self::CreateProcessW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateEventW" => {
                Self::CreateEventW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetEvent" => Self::SetEvent,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ResetEvent" => Self::ResetEvent,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "IsDebuggerPresent" => {
                Self::IsDebuggerPresent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitOnceBeginInitialize" => {
                Self::InitOnceBeginInitialize
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitOnceComplete" => {
                Self::InitOnceComplete
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeSRWLock" => {
                Self::InitializeSRWLock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "AcquireSRWLockExclusive" => {
                Self::AcquireSRWLockExclusive
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseSRWLockExclusive" => {
                Self::ReleaseSRWLockExclusive
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "AcquireSRWLockShared" => {
                Self::AcquireSRWLockShared
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseSRWLockShared" => {
                Self::ReleaseSRWLockShared
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TryAcquireSRWLockExclusive" => {
                Self::TryAcquireSRWLockExclusive
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TryAcquireSRWLockShared" => {
                Self::TryAcquireSRWLockShared
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WaitForSingleObject" => {
                Self::WaitForSingleObject
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetExitCodeProcess" => {
                Self::GetExitCodeProcess
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryA" => {
                Self::LoadLibraryA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryW" => {
                Self::LoadLibraryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryExW" => {
                Self::LoadLibraryExW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FreeLibrary" => {
                Self::FreeLibrary
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrlenA" => Self::Strlen,
            ("kernel32.dll", ImportSymbol::ByOrdinal { ordinal: 17 }) => Self::CreateFileW,
            ("comctl32.dll", ImportSymbol::ByOrdinal { ordinal: 17 }) => Self::InitCommonControls,
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "OleInitialize" => Self::OleInitialize,
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "OleUninitialize" => Self::OleUninitialize,
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoCreateInstance" => {
                Self::CoCreateInstance
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoTaskMemFree" => Self::CoTaskMemFree,
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "CommandLineToArgvW" => {
                Self::CommandLineToArgvW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHGetFileInfoW" => Self::SHGetFileInfoW,
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHGetFolderPathW" => {
                Self::SHGetFolderPathW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHGetPathFromIDListW" => {
                Self::SHGetPathFromIDListW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHGetSpecialFolderLocation" => {
                Self::SHGetSpecialFolderLocation
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "MultiByteToWideChar" => {
                Self::MultiByteToWideChar
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WideCharToMultiByte" => {
                Self::WideCharToMultiByte
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcmpiW" => Self::LstrcmpiW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrlenW" => Self::LstrlenW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcpyA" => Self::LstrcpyA,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcpyW" => Self::LstrcpyW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcpynW" => Self::LstrcpynW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcatW" => Self::LstrcatW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCommandLineA" => Self::GetCommandLineA,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCommandLineW" => Self::GetCommandLineW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetEnvironmentStringsW" => {
                Self::GetEnvironmentStringsW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FreeEnvironmentStringsW" => {
                Self::FreeEnvironmentStringsW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetACP" => Self::GetACP,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "IsValidCodePage" => Self::IsValidCodePage,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCPInfo" => Self::GetCPInfo,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetStringTypeW" => Self::GetStringTypeW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LCMapStringW" => Self::LCMapStringW,
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CharNextW" => Self::CharNextW,
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CharPrevW" => Self::CharPrevW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDirectoryW" => Self::CreateDirectoryW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "RemoveDirectoryW" => Self::RemoveDirectoryW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFileW" => Self::CreateFileW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CompareFileTime" => {
                Self::CompareFileTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetFileTime" => Self::SetFileTime,
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegCreateKeyExW" => {
                Self::RegCreateKeyExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegOpenKeyExW" => {
                Self::RegOpenKeyExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegSetValueExW" => {
                Self::RegSetValueExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegQueryValueExW" => {
                Self::RegQueryValueExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegCloseKey" => {
                Self::RegCloseKey
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetFilePointer" => {
                Self::SetFilePointer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReadFile" => Self::ReadFile,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WriteFile" => Self::WriteFile,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LocalAlloc" => Self::LocalAlloc,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GlobalAlloc" => Self::GlobalAlloc,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GlobalLock" => Self::GlobalLock,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GlobalUnlock" => {
                Self::GlobalUnlock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GlobalFree" => Self::GlobalFree,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CloseHandle" => Self::CloseHandle,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteCriticalSection" => {
                Self::DeleteCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "EnterCriticalSection" => {
                Self::EnterCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleHandleA" => {
                Self::GetModuleHandleA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleHandleW" => {
                Self::GetModuleHandleW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcAddress" => {
                Self::GetProcAddress
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetVersion" => Self::GetVersion,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetLastError" => Self::GetLastError,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetLastError" => Self::SetLastError,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCurrentThreadId" => {
                Self::GetCurrentThreadId
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCurrentProcessId" => {
                Self::GetCurrentProcessId
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "QueryPerformanceCounter" => {
                Self::QueryPerformanceCounter
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "QueryPerformanceFrequency" => {
                Self::QueryPerformanceFrequency
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "IsProcessorFeaturePresent" => {
                Self::IsProcessorFeaturePresent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessHeap" => Self::GetProcessHeap,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessHeaps" => Self::GetProcessHeaps,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapAlloc" => Self::HeapAlloc,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapFree" => Self::HeapFree,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapReAlloc" => Self::HeapReAlloc,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapSize" => Self::HeapSize,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetStartupInfoW" => Self::GetStartupInfoW,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeSListHead" => Self::InitializeSListHead,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetStdHandle" => Self::GetStdHandle,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileType" => Self::GetFileType,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemTimeAsFileTime" => {
                Self::GetSystemTimeAsFileTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTickCount" => Self::GetTickCount,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeCriticalSection" => {
                Self::InitializeCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeCriticalSectionAndSpinCount" => {
                Self::InitializeCriticalSectionAndSpinCount
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
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsAlloc" => Self::TlsAlloc,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsGetValue" => Self::TlsGetValue,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsSetValue" => Self::TlsSetValue,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsFree" => Self::TlsFree,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualAlloc" => Self::VirtualAlloc,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualProtect" => Self::VirtualProtect,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualQuery" => Self::VirtualQuery,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetCurrentThreadId" => {
                Self::GetCurrentThreadId
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetCurrentProcessId" => {
                Self::GetCurrentProcessId
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "QueryPerformanceCounter" => {
                Self::QueryPerformanceCounter
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "QueryPerformanceFrequency" => {
                Self::QueryPerformanceFrequency
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "IsProcessorFeaturePresent" => {
                Self::IsProcessorFeaturePresent
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessHeap" => Self::GetProcessHeap,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessHeaps" => Self::GetProcessHeaps,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "HeapAlloc" => Self::HeapAlloc,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "HeapFree" => Self::HeapFree,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "HeapReAlloc" => Self::HeapReAlloc,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "HeapSize" => Self::HeapSize,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetStartupInfoW" => Self::GetStartupInfoW,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeSListHead" => Self::InitializeSListHead,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetStdHandle" => Self::GetStdHandle,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileType" => Self::GetFileType,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetACP" => Self::GetACP,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FindFirstFileW" => {
                Self::FindFirstFileW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FindNextFileW" => {
                Self::FindNextFileW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FindClose" => {
                Self::FindClose
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetEnvironmentStringsW" => {
                Self::GetEnvironmentStringsW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FreeEnvironmentStringsW" => {
                Self::FreeEnvironmentStringsW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "IsValidCodePage" => Self::IsValidCodePage,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetCPInfo" => Self::GetCPInfo,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetStringTypeW" => Self::GetStringTypeW,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LCMapStringW" => Self::LCMapStringW,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemTimeAsFileTime" => {
                Self::GetSystemTimeAsFileTime
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetTickCount" => Self::GetTickCount,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeCriticalSectionAndSpinCount" => {
                Self::InitializeCriticalSectionAndSpinCount
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateEventW" => {
                Self::CreateEventW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "SetEvent" => Self::SetEvent,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "ResetEvent" => Self::ResetEvent,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "IsDebuggerPresent" => {
                Self::IsDebuggerPresent
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryA" => {
                Self::LoadLibraryA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryW" => {
                Self::LoadLibraryW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "InitOnceBeginInitialize" => {
                Self::InitOnceBeginInitialize
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "InitOnceComplete" => {
                Self::InitOnceComplete
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeSRWLock" => {
                Self::InitializeSRWLock
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "AcquireSRWLockExclusive" => {
                Self::AcquireSRWLockExclusive
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseSRWLockExclusive" => {
                Self::ReleaseSRWLockExclusive
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "AcquireSRWLockShared" => {
                Self::AcquireSRWLockShared
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseSRWLockShared" => {
                Self::ReleaseSRWLockShared
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TryAcquireSRWLockExclusive" => {
                Self::TryAcquireSRWLockExclusive
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TryAcquireSRWLockShared" => {
                Self::TryAcquireSRWLockShared
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "Sleep" => Self::Sleep,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TlsAlloc" => Self::TlsAlloc,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TlsGetValue" => Self::TlsGetValue,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TlsSetValue" => Self::TlsSetValue,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TlsFree" => Self::TlsFree,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualAlloc" => Self::VirtualAlloc,
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
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MessageBoxIndirectW" => {
                Self::MessageBoxIndirectW
            }
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

    fn x86_arg_bytes(&self) -> u64 {
        match self {
            Self::GetVersion
            | Self::GetLastError
            | Self::GetCurrentThreadId
            | Self::GetCurrentProcessId
            | Self::GetProcessHeap
            | Self::GetTickCount
            | Self::WsprintfW
            | Self::OleUninitialize
            | Self::GetCommandLineA
            | Self::GetCommandLineW
            | Self::GetEnvironmentStringsW
            | Self::GetACP
            | Self::IsValidCodePage
            | Self::PArgc
            | Self::PArgv
            | Self::Cexit
            | Self::InitializeNarrowEnvironment
            | Self::Abort
            | Self::PCommode
            | Self::PFmode
            | Self::PEnviron
            | Self::Calloc
            | Self::Free
            | Self::Malloc
            | Self::SetNewMode
            | Self::ConfigureNarrowArgv
            | Self::CrtAtExit
            | Self::Initterm
            | Self::InittermE
            | Self::SetAppType
            | Self::SetInvalidParameterHandler
            | Self::Signal
            | Self::AcrtIobFunc
            | Self::Fwrite
            | Self::Strlen
            | Self::Strncmp
            | Self::GetMessagePos
            | Self::CreatePopupMenu
            | Self::SetUserMathErr
            | Self::TlsAlloc => 0,
            Self::QueryPerformanceCounter
            | Self::QueryPerformanceFrequency
            | Self::IsProcessorFeaturePresent
            | Self::SetLastError
            | Self::GetStartupInfoW
            | Self::InitializeSListHead
            | Self::GetStdHandle
            | Self::GetFileType
            | Self::FreeEnvironmentStringsW => 4,
            Self::GetCPInfo => 8,
            Self::GetStringTypeW => 16,
            Self::LCMapStringW => 24,
            Self::CreateEventW => 16,
            Self::IsDebuggerPresent => 0,
            Self::InitOnceBeginInitialize => 16,
            Self::InitOnceComplete => 12,
            Self::InitializeSRWLock
            | Self::AcquireSRWLockExclusive
            | Self::ReleaseSRWLockExclusive
            | Self::AcquireSRWLockShared
            | Self::ReleaseSRWLockShared
            | Self::TryAcquireSRWLockExclusive
            | Self::TryAcquireSRWLockShared => 4,
            Self::SetEvent | Self::ResetEvent => 4,
            Self::GetProcessHeaps => 8,
            Self::HeapAlloc | Self::HeapFree | Self::HeapSize => 12,
            Self::HeapReAlloc => 16,
            Self::InitializeCriticalSectionAndSpinCount => 8,
            Self::GetSystemTimeAsFileTime => 4,
            Self::SetFileAttributesW | Self::FindFirstFileW | Self::FindNextFileW => 8,
            Self::FindClose => 4,
            Self::ShellLinkAddRef | Self::ShellLinkRelease | Self::ShellLinkPersistIsDirty => 4,
            Self::SetCurrentDirectoryW
            | Self::GetFullPathNameW
            | Self::GetFileAttributesW
            | Self::SetErrorMode
            | Self::SetDefaultDllDirectories
            | Self::FreeLibrary
            | Self::RegisterClassW
            | Self::IsWindowEnabled
            | Self::GetWindowLongW
            | Self::GetModuleHandleA
            | Self::GetModuleHandleW
            | Self::CloseHandle
            | Self::CrtExit
            | Self::DeleteCriticalSection
            | Self::EnterCriticalSection
            | Self::InitializeCriticalSection
            | Self::LeaveCriticalSection
            | Self::SetUnhandledExceptionFilter
            | Self::Sleep
            | Self::ExitProcess
            | Self::OleInitialize
            | Self::CoTaskMemFree
            | Self::LstrlenW
            | Self::CharNextW
            | Self::GetDC
            | Self::CreateFontIndirectW
            | Self::DeleteObject
            | Self::SetForegroundWindow
            | Self::RemoveDirectoryW
            | Self::DeleteFileW
            | Self::GetSysColor
            | Self::IsWindowVisible
            | Self::GetSystemMetrics
            | Self::IsWindow
            | Self::PostQuitMessage
            | Self::LoadLibraryA
            | Self::LoadLibraryW
            => 4,
            Self::TlsGetValue | Self::TlsFree => 4,
            Self::TlsSetValue => 8,
            Self::MessageBoxIndirectW => 4,
            Self::CSpecificHandler
            | Self::Beep
            | Self::GetProcAddress
            | Self::GetFileSize
            | Self::LocalAlloc
            | Self::GlobalAlloc
            | Self::LstrcmpiW
            | Self::CompareFileTime
            | Self::LstrcpyA
            | Self::LstrcpyW
            | Self::LstrcatW
            | Self::GetClientRect
            | Self::GetWindowRect
            | Self::EnableWindow
            | Self::GetSystemMenu
            | Self::CharPrevW
            | Self::EndDialog
            | Self::ReleaseDC
            | Self::ScreenToClient
            | Self::LoadCursorW
            | Self::LoadBitmapW
            | Self::GetDeviceCaps
            | Self::SelectObject
            | Self::SetBkMode
            | Self::SetTextColor
            | Self::CreateDirectoryW
            | Self::WaitForSingleObject
            | Self::ExitWindowsEx
            | Self::GetExitCodeProcess => 8,
            Self::GetSystemDirectoryW | Self::GetWindowsDirectoryW | Self::GetTempPathW => 8,
            Self::GetModuleFileNameW => 12,
            Self::GetTempFileNameW => 16,
            Self::LoadLibraryExW
            | Self::GetClassInfoW
            | Self::SetDlgItemTextW
            | Self::SetClassLongW
            | Self::SetWindowLongW
            | Self::EnableMenuItem
            | Self::InvalidateRect
            | Self::FillRect
            | Self::CheckDlgButton
            | Self::MulDiv
            | Self::VirtualQuery
            | Self::FindWindowExW
            | Self::AppendMenuW
            | Self::SetTimer
            | Self::SystemParametersInfoW
            | Self::LstrcpynW => 12,
            Self::MessageBoxW
            | Self::VirtualAlloc
            | Self::VirtualProtect
            | Self::GetDlgItemTextW
            | Self::WritePrivateProfileStringW => 16,
            Self::CreateProcessW => 40,
            Self::DrawTextW => 20,
            Self::CallWindowProcW => 20,
            Self::DialogBoxParamW => 20,
            Self::CreateDialogParamW => 20,
            Self::GetDiskFreeSpaceW => 20,
            Self::SetFileTime => 16,
            Self::ShowWindow => 8,
            Self::GetDlgItem => 8,
            Self::BeginPaint | Self::EndPaint => 8,
            Self::DestroyWindow => 4,
            Self::SetWindowTextW => 8,
            Self::LoadImageW => 24,
            Self::DispatchMessageW => 4,
            Self::SendMessageW => 16,
            Self::GlobalLock | Self::GlobalUnlock | Self::GlobalFree => 4,
            Self::PeekMessageW => 20,
            Self::RegCreateKeyExW => 36,
            Self::RegOpenKeyExW => 20,
            Self::RegSetValueExW => 24,
            Self::RegQueryValueExW => 24,
            Self::RegCloseKey => 4,
            Self::SetFilePointer => 16,
            Self::ReadFile
            | Self::WriteFile
            | Self::SHGetFileInfoW
            | Self::SHGetFolderPathW
            | Self::CoCreateInstance
            | Self::ShellLinkGetPathW => 20,
            Self::ShellLinkGetIDList
            | Self::ShellLinkSetIDList
            | Self::ShellLinkPersistGetClassID
            | Self::ShellLinkPersistGetCurFile
            | Self::ShellLinkGetHotkey
            | Self::ShellLinkSetHotkey
            | Self::ShellLinkGetShowCmd
            | Self::ShellLinkSetShowCmd
            | Self::ShellLinkSetDescriptionW
            | Self::ShellLinkSetWorkingDirectoryW
            | Self::ShellLinkSetArgumentsW
            | Self::ShellLinkPersistSaveCompleted => 8,
            Self::ShellLinkQueryInterface
            | Self::ShellLinkGetDescriptionW
            | Self::ShellLinkGetWorkingDirectoryW
            | Self::ShellLinkGetArgumentsW
            | Self::ShellLinkSetIconLocationW
            | Self::ShellLinkSetRelativePath
            | Self::ShellLinkResolve
            | Self::ShellLinkPersistLoad
            | Self::ShellLinkPersistSave => 12,
            Self::ShellLinkGetIconLocationW => 16,
            Self::ShellLinkSetPathW => 8,
            Self::CommandLineToArgvW | Self::SHGetPathFromIDListW => 8,
            Self::CreateFileW
            | Self::StdioCommonVfprintf
            | Self::SetWindowPos
            | Self::TrackPopupMenu
            | Self::SendMessageTimeoutW => 28,
            Self::MultiByteToWideChar => 24,
            Self::WideCharToMultiByte => 32,
            Self::SHGetSpecialFolderLocation => 12,
            _ => 0,
        }
    }
}

fn resolve_imports_for_runtime(image: &pe::ParsedPe, resolver: &ApiSetResolver) -> Vec<ResolvedImport> {
    image
        .imports
        .iter()
        .chain(image.delay_imports.iter())
        .flat_map(|descriptor| {
            let resolved_module = resolver.resolve(&descriptor.dll_name);
            descriptor.imports.iter().map(move |thunk| ResolvedImport {
                requested_module: descriptor.dll_name.clone(),
                resolved_module: resolved_module.clone(),
                symbol: thunk.symbol.clone(),
                iat_rva: thunk.iat_rva,
                export: synthetic_export_symbol(&thunk.symbol),
            })
        })
        .collect()
}

fn synthetic_export_symbol(symbol: &ImportSymbol) -> ExportSymbol {
    match symbol {
        ImportSymbol::ByName { name, .. } => ExportSymbol {
            ordinal: 0,
            name: Some(name.clone()),
            target: ExportTarget::Rva(0),
        },
        ImportSymbol::ByOrdinal { ordinal } => ExportSymbol {
            ordinal: *ordinal as u32,
            name: None,
            target: ExportTarget::Rva(0),
        },
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
    instruction_cache: &mut U64Map<CachedInstructionEntry>,
    instruction_cache_lru: &mut VecDeque<(u64, u64)>,
    instruction_cache_generation: &mut u64,
    instruction_cache_limit: usize,
    rip: u64,
) -> AppResult<Arc<CachedInstruction>> {
    if let Some(cached) = instruction_cache.get_mut(&rip) {
        if read_window(memory, rip, cached.cached.decoded.size)? == cached.cached.bytes.as_slice() {
            *instruction_cache_generation = instruction_cache_generation.saturating_add(1);
            cached.generation = *instruction_cache_generation;
            instruction_cache_lru.push_back((rip, cached.generation));
            return Ok(Arc::clone(&cached.cached));
        }
    }

    let decoded = decode_current_instruction(engine, memory, rip)?;
    let bytes = read_window(memory, rip, decoded.size)?;
    *instruction_cache_generation = instruction_cache_generation.saturating_add(1);
    let cached = Arc::new(CachedInstruction {
        bytes,
        decoded,
    });
    let generation = *instruction_cache_generation;

    instruction_cache.insert(
        rip,
        CachedInstructionEntry {
            cached: Arc::clone(&cached),
            generation,
        },
    );
    instruction_cache_lru.push_back((rip, generation));
    trim_instruction_cache(instruction_cache, instruction_cache_lru, instruction_cache_limit);
    Ok(cached)
}

fn decode_basic_block_cached(
    engine: &mut CpuExecutionEngine,
    memory: &MemoryImage,
    instruction_cache: &mut U64Map<CachedInstructionEntry>,
    instruction_cache_lru: &mut VecDeque<(u64, u64)>,
    instruction_cache_generation: &mut u64,
    instruction_cache_limit: usize,
    basic_block_cache: &mut U64Map<CachedBlockEntry>,
    basic_block_cache_lru: &mut VecDeque<(u64, u64)>,
    basic_block_cache_generation: &mut u64,
    basic_block_cache_limit: usize,
    rip: u64,
) -> AppResult<Arc<CachedBlock>> {
    if let Some(cached) = basic_block_cache.get_mut(&rip) {
        if read_window(memory, rip, cached.cached.bytes.len())? == cached.cached.bytes.as_slice() {
            *basic_block_cache_generation = basic_block_cache_generation.saturating_add(1);
            cached.generation = *basic_block_cache_generation;
            basic_block_cache_lru.push_back((rip, cached.generation));
            return Ok(Arc::clone(&cached.cached));
        }
    }

    let mut current_rip = rip;
    let mut bytes = Vec::new();
    let mut end_rip = rip;
    for _ in 0..BASIC_BLOCK_MAX_INSTRUCTIONS {
        let cached_instruction = decode_current_instruction_cached(
            engine,
            memory,
            instruction_cache,
            instruction_cache_lru,
            instruction_cache_generation,
            instruction_cache_limit,
            current_rip,
        )?;
        let decoded = &cached_instruction.decoded;
        let decoded_bytes = cached_instruction.bytes.as_slice();
        if !bytes.is_empty() && bytes.len() + decoded_bytes.len() > BASIC_BLOCK_MAX_BYTES {
            break;
        }
        end_rip = current_rip + decoded.size as u64;
        bytes.extend_from_slice(decoded_bytes);
        if instruction_controls_rip(decoded.opcode) || decoded.opcode == DecodedOpcode::Ret {
            break;
        }
        current_rip = end_rip;
    }

    if bytes.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("failed to build basic block at {rip:#x}"),
        ));
    }

    let translated = engine.translate_block(&bytes, rip)?;
    *basic_block_cache_generation = basic_block_cache_generation.saturating_add(1);
    let cached = Arc::new(CachedBlock {
        bytes,
        translated,
        end_rip,
    });
    let generation = *basic_block_cache_generation;
    basic_block_cache.insert(
        rip,
        CachedBlockEntry {
            cached: Arc::clone(&cached),
            generation,
        },
    );
    basic_block_cache_lru.push_back((rip, generation));
    trim_basic_block_cache(
        basic_block_cache,
        basic_block_cache_lru,
        basic_block_cache_limit,
    );
    Ok(cached)
}

fn trim_instruction_cache(
    instruction_cache: &mut U64Map<CachedInstructionEntry>,
    instruction_cache_lru: &mut VecDeque<(u64, u64)>,
    instruction_cache_limit: usize,
) {
    while instruction_cache.len() > instruction_cache_limit {
        let Some((rip, generation)) = instruction_cache_lru.pop_front() else {
            break;
        };
        let remove = instruction_cache
            .get(&rip)
            .map(|cached| cached.generation == generation)
            .unwrap_or(false);
        if remove {
            instruction_cache.remove(&rip);
        }
    }
}

fn trim_basic_block_cache(
    basic_block_cache: &mut U64Map<CachedBlockEntry>,
    basic_block_cache_lru: &mut VecDeque<(u64, u64)>,
    basic_block_cache_limit: usize,
) {
    while basic_block_cache.len() > basic_block_cache_limit {
        let Some((rip, generation)) = basic_block_cache_lru.pop_front() else {
            break;
        };
        let remove = basic_block_cache
            .get(&rip)
            .map(|cached| cached.generation == generation)
            .unwrap_or(false);
        if remove {
            basic_block_cache.remove(&rip);
        }
    }
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
    if rip == 0x401390 {
        let state_table = read_guest_u32(memory, 0x42a250).ok().map(u64::from);
        let record_base = read_guest_u32(memory, 0x42a270).ok().map(u64::from);
        let slot_values = state_table
            .map(|base| {
                (0..8)
                    .map(|index| {
                        let value = read_guest_u32(memory, base + 0x6c + index * 4)
                            .ok()
                            .map(u64::from)
                            .unwrap_or(0);
                        format!("{index}:{value:#x}")
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_else(|| "<unavailable>".to_string());
        let class_block = [0x4291e0_u64, 0x4291e4, 0x4291f0, 0x4291f4, 0x429204]
            .into_iter()
            .map(|address| {
                let value = read_guest_u32(memory, address)
                    .ok()
                    .map(u64::from)
                    .unwrap_or(0);
                format!("{address:#x}={value:#x}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let stack_probe = [state.get(Register::Rsp) + 4, state.get(Register::Rsp) + 8, state.get(Register::Rsp) + 12]
            .into_iter()
            .map(|address| {
                let value = read_guest_u32(memory, address)
                    .ok()
                    .map(u64::from)
                    .unwrap_or(0);
                format!("{address:#x}={value:#x}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let current_index = read_guest_u32(memory, state.get(Register::Rsp) + 8)
            .ok()
            .map(u64::from);
        let current_record = current_index
            .zip(record_base)
            .map(|(index, base)| {
                let record_address = base + index * 0x1c;
                let fields = (0..7)
                    .map(|slot| {
                        let value = read_guest_u32(memory, record_address + slot * 4)
                            .ok()
                            .map(u64::from)
                            .unwrap_or(0);
                        format!("{slot}:{value:#x}")
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("addr={record_address:#x} fields=[{fields}]")
            })
            .unwrap_or_else(|| "<unavailable>".to_string());
        wrapped = wrapped.with_hint(format!(
            "steam-401390 probe state_table={} record_base={} slot_6c=[{}] class_block=[{}] stack=[{}] current_record={}",
            state_table
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<unavailable>".to_string()),
            record_base
                .map(|value| format!("{value:#x}"))
                .unwrap_or_else(|| "<unavailable>".to_string()),
            slot_values,
            class_block,
            stack_probe,
            current_record,
        ));
    }
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

fn advance_runtime_steps(
    runtime: &mut PeHostRuntime,
    steps: &mut u64,
    instruction_budget: u64,
    consumed_instructions: u64,
    memory: &MemoryImage,
    state: &CpuState,
    test_id: &str,
) -> AppResult<()> {
    let next_steps = steps.saturating_add(consumed_instructions);
    if next_steps > instruction_budget {
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
        let register_context = match state.arch {
            GuestArch::X64 => format!(
                " rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x}",
                state.get(Register::Rax),
                state.get(Register::Rbx),
                state.get(Register::Rcx),
                state.get(Register::Rdx),
                state.get(Register::Rsi),
                state.get(Register::Rdi),
            ),
            GuestArch::X86 => format!(
                " eax={:#x} ebx={:#x} ecx={:#x} edx={:#x} esi={:#x} edi={:#x} ebp={:#x} esp={:#x}",
                state.get(Register::Rax),
                state.get(Register::Rbx),
                state.get(Register::Rcx),
                state.get(Register::Rdx),
                state.get(Register::Rsi),
                state.get(Register::Rdi),
                state.get(Register::Rbp),
                state.get(Register::Rsp),
            ),
        };
        return Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!(
                "PE runtime exceeded the instruction budget for {test_id} at {rip:#x}: {window} steps={next_steps} budget={instruction_budget}{register_context}"
            ),
        ));
    }

    let previous_poll_bucket = *steps >> 8;
    let next_poll_bucket = next_steps >> 8;
    *steps = next_steps;
    for _ in previous_poll_bucket..next_poll_bucket {
        runtime.poll_live_input()?;
    }
    Ok(())
}

fn pe_runtime_instruction_budget(env: &BTreeMap<String, String>, live_mode: bool) -> AppResult<u64> {
    match env
        .get(PE_RUNTIME_BUDGET_ENV)
        .cloned()
        .or_else(|| std::env::var(PE_RUNTIME_BUDGET_ENV).ok())
    {
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

fn registry_view_from_sam_desired(sam_desired: u32, guest_arch: GuestArch) -> RegistryView {
    if sam_desired & KEY_WOW64_64KEY != 0 {
        RegistryView::Native64
    } else if sam_desired & KEY_WOW64_32KEY != 0 {
        RegistryView::Wow6432
    } else if guest_arch == GuestArch::X86 {
        RegistryView::Wow6432
    } else {
        RegistryView::Native
    }
}

fn resolve_registry_root_key(
    win32: &Win32Subsystem,
    hkey: u32,
    requested_view: RegistryView,
) -> AppResult<(String, String, RegistryView)> {
    match hkey {
        HKEY_CLASSES_ROOT => Ok(("HKCR".to_string(), String::new(), requested_view)),
        HKEY_CURRENT_USER => Ok(("HKCU".to_string(), String::new(), requested_view)),
        HKEY_LOCAL_MACHINE => Ok(("HKLM".to_string(), String::new(), requested_view)),
        HKEY_USERS => Ok(("HKCU".to_string(), String::new(), requested_view)),
        HKEY_CURRENT_CONFIG => Ok((
            "HKLM".to_string(),
            "System\\CurrentControlSet\\Hardware Profiles\\Current".to_string(),
            requested_view,
        )),
        _ => {
            let key = win32.key_state(hkey)?;
            Ok((key.hive, key.key, key.view))
        }
    }
}

fn join_registry_subkey(base: &str, suffix: &str) -> String {
    if base.is_empty() {
        suffix.trim_matches('\\').to_string()
    } else if suffix.is_empty() {
        base.trim_matches('\\').to_string()
    } else {
        format!("{}\\{}", base.trim_matches('\\'), suffix.trim_matches('\\'))
    }
}

fn normalize_registry_runtime_key(hive: &str, key: &str) -> String {
    if hive == "HKCU" {
        key.strip_prefix(".DEFAULT\\")
            .or_else(|| key.strip_prefix(".Default\\"))
            .unwrap_or(key)
            .trim_matches('\\')
            .to_string()
    } else {
        key.trim_matches('\\').to_string()
    }
}

fn registry_value_type_to_win32(value_type: &str) -> AppResult<u32> {
    match value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" => Ok(REG_SZ),
        "REG_EXPAND_SZ" => Ok(REG_EXPAND_SZ),
        "REG_BINARY" => Ok(REG_BINARY),
        "REG_DWORD" => Ok(REG_DWORD),
        "REG_MULTI_SZ" => Ok(REG_MULTI_SZ),
        "REG_QWORD" => Ok(REG_QWORD),
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type {other}"),
        )),
    }
}

fn decode_registry_value_data(
    memory: &MemoryImage,
    data_ptr: u64,
    data_len: u32,
    value_type: u32,
) -> AppResult<(String, Value)> {
    let bytes = if data_ptr == 0 || data_len == 0 {
        Vec::new()
    } else {
        memory.read_bytes(data_ptr, data_len as usize)?
    };
    match value_type {
        REG_SZ | REG_EXPAND_SZ => {
            let units = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            let trimmed = units
                .iter()
                .copied()
                .take_while(|unit| *unit != 0)
                .collect::<Vec<_>>();
            Ok((
                if value_type == REG_SZ {
                    "REG_SZ".to_string()
                } else {
                    "REG_EXPAND_SZ".to_string()
                },
                json!(String::from_utf16_lossy(&trimmed)),
            ))
        }
        REG_DWORD => {
            if bytes.len() < 4 {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    "REG_DWORD data is shorter than 4 bytes",
                ));
            }
            Ok(("REG_DWORD".to_string(), json!(u32::from_le_bytes(bytes[..4].try_into().expect("dword")))))
        }
        REG_QWORD => {
            if bytes.len() < 8 {
                return Err(AppError::new(
                    ReasonCode::RcCliInvalid,
                    "REG_QWORD data is shorter than 8 bytes",
                ));
            }
            Ok(("REG_QWORD".to_string(), json!(u64::from_le_bytes(bytes[..8].try_into().expect("qword")))))
        }
        REG_BINARY => Ok((
            "REG_BINARY".to_string(),
            json!(bytes.into_iter().map(u64::from).collect::<Vec<_>>()),
        )),
        REG_MULTI_SZ => {
            let units = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            let mut items = Vec::new();
            let mut current = Vec::new();
            for unit in units {
                if unit == 0 {
                    if current.is_empty() {
                        break;
                    }
                    items.push(String::from_utf16_lossy(&current));
                    current.clear();
                } else {
                    current.push(unit);
                }
            }
            Ok(("REG_MULTI_SZ".to_string(), json!(items)))
        }
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type code {other}"),
        )),
    }
}

fn encode_registry_value_data(value: &crate::ge::StoredRegistryValue) -> AppResult<Vec<u8>> {
    match value.value_type.to_ascii_uppercase().as_str() {
        "REG_SZ" | "REG_EXPAND_SZ" => {
            let text = value.data.as_str().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("registry string value has non-string data: {:?}", value.data),
                )
            })?;
            Ok(text
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(|unit| unit.to_le_bytes())
                .collect())
        }
        "REG_DWORD" => {
            let number = value.data.as_u64().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("registry dword value has non-numeric data: {:?}", value.data),
                )
            })?;
            Ok((number as u32).to_le_bytes().to_vec())
        }
        "REG_QWORD" => {
            let number = value.data.as_u64().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("registry qword value has non-numeric data: {:?}", value.data),
                )
            })?;
            Ok(number.to_le_bytes().to_vec())
        }
        "REG_BINARY" => {
            let bytes = value.data.as_array().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("registry binary value has non-array data: {:?}", value.data),
                )
            })?;
            bytes
                .iter()
                .map(|item| {
                    item.as_u64().map(|byte| byte as u8).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcCliInvalid,
                            format!("registry binary value contains non-byte data: {item:?}"),
                        )
                    })
                })
                .collect()
        }
        "REG_MULTI_SZ" => {
            let items = value.data.as_array().ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("registry multi-string value has non-array data: {:?}", value.data),
                )
            })?;
            let mut encoded = Vec::new();
            for item in items {
                let text = item.as_str().ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcCliInvalid,
                        format!("registry multi-string value contains non-string data: {item:?}"),
                    )
                })?;
                encoded.extend(text.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
                encoded.extend_from_slice(&0u16.to_le_bytes());
            }
            encoded.extend_from_slice(&0u16.to_le_bytes());
            Ok(encoded)
        }
        other => Err(AppError::new(
            ReasonCode::RcCliInvalid,
            format!("unsupported registry value type {other}"),
        )),
    }
}

fn read_window(memory: &MemoryImage, address: u64, len: usize) -> AppResult<Vec<u8>> {
    memory.read_bytes(address, len)
}

fn read_i32_from_memory(memory: &MemoryImage, address: u64) -> AppResult<i32> {
    let bytes = read_window(memory, address, 4)?;
    Ok(i32::from_le_bytes(bytes.try_into().expect("disp32")))
}

#[derive(Debug, Clone, Copy)]
struct GuestWindowClass {
    style: u32,
    wnd_proc: u64,
    cls_extra: i32,
    wnd_extra: i32,
    instance: u64,
    icon: u64,
    cursor: u64,
    background: u64,
    menu_name: u64,
    class_name_ptr: u64,
}

fn read_guest_window_class(
    memory: &MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    extended: bool,
) -> AppResult<GuestWindowClass> {
    let base = if extended { 4 } else { 0 };
    Ok(match guest_arch {
        GuestArch::X86 => GuestWindowClass {
            style: read_guest_u32(memory, address + base)?,
            wnd_proc: read_guest_u32(memory, address + base + 4)? as u64,
            cls_extra: read_guest_u32(memory, address + base + 8)? as i32,
            wnd_extra: read_guest_u32(memory, address + base + 12)? as i32,
            instance: read_guest_u32(memory, address + base + 16)? as u64,
            icon: read_guest_u32(memory, address + base + 20)? as u64,
            cursor: read_guest_u32(memory, address + base + 24)? as u64,
            background: read_guest_u32(memory, address + base + 28)? as u64,
            menu_name: read_guest_u32(memory, address + base + 32)? as u64,
            class_name_ptr: read_guest_u32(memory, address + base + 36)? as u64,
        },
        GuestArch::X64 => GuestWindowClass {
            style: read_guest_u32(memory, address + base)?,
            wnd_proc: read_guest_pointer(memory, address + 8, guest_arch)?,
            cls_extra: read_guest_u32(memory, address + 16)? as i32,
            wnd_extra: read_guest_u32(memory, address + 20)? as i32,
            instance: read_guest_pointer(memory, address + 24, guest_arch)?,
            icon: read_guest_pointer(memory, address + 32, guest_arch)?,
            cursor: read_guest_pointer(memory, address + 40, guest_arch)?,
            background: read_guest_pointer(memory, address + 48, guest_arch)?,
            menu_name: read_guest_pointer(memory, address + 56, guest_arch)?,
            class_name_ptr: read_guest_pointer(memory, address + 64, guest_arch)?,
        },
    })
}

fn write_guest_window_class(
    memory: &mut MemoryImage,
    address: u64,
    guest_arch: GuestArch,
    class_info: WindowClassInfo,
) -> AppResult<()> {
    match guest_arch {
        GuestArch::X86 => {
            write_u32(memory, address, class_info.style);
            write_u32(memory, address + 4, class_info.wnd_proc as u32);
            write_u32(memory, address + 8, class_info.cls_extra as u32);
            write_u32(memory, address + 12, class_info.wnd_extra as u32);
            write_u32(memory, address + 16, class_info.instance as u32);
            write_u32(memory, address + 20, class_info.icon as u32);
            write_u32(memory, address + 24, class_info.cursor as u32);
            write_u32(memory, address + 28, class_info.background as u32);
            write_u32(memory, address + 32, class_info.menu_name as u32);
            write_u32(memory, address + 36, class_info.class_name_ptr as u32);
        }
        GuestArch::X64 => {
            write_u32(memory, address, class_info.style);
            write_u32(memory, address + 4, 0);
            write_guest_pointer(memory, address + 8, class_info.wnd_proc, guest_arch)?;
            write_u32(memory, address + 16, class_info.cls_extra as u32);
            write_u32(memory, address + 20, class_info.wnd_extra as u32);
            write_guest_pointer(memory, address + 24, class_info.instance, guest_arch)?;
            write_guest_pointer(memory, address + 32, class_info.icon, guest_arch)?;
            write_guest_pointer(memory, address + 40, class_info.cursor, guest_arch)?;
            write_guest_pointer(memory, address + 48, class_info.background, guest_arch)?;
            write_guest_pointer(memory, address + 56, class_info.menu_name, guest_arch)?;
            write_guest_pointer(memory, address + 64, class_info.class_name_ptr, guest_arch)?;
        }
    }
    Ok(())
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

fn classify_wide_char_type(info_type: u32, code_unit: u16) -> u16 {
    match info_type {
        CT_CTYPE1 => {
            let Some(ch) = char::from_u32(u32::from(code_unit)) else {
                return 0;
            };
            let mut mask = 0;
            if ch.is_uppercase() {
                mask |= C1_UPPER;
            }
            if ch.is_lowercase() {
                mask |= C1_LOWER;
            }
            if ch.is_numeric() {
                mask |= C1_DIGIT;
            }
            if ch.is_whitespace() {
                mask |= C1_SPACE;
            }
            if ch == ' ' || ch == '\t' {
                mask |= C1_BLANK;
            }
            if ch.is_control() {
                mask |= C1_CNTRL;
            }
            if ch.is_alphabetic() {
                mask |= C1_ALPHA;
            }
            if ch.is_ascii_hexdigit() {
                mask |= C1_XDIGIT;
            }
            if !ch.is_control() && !ch.is_whitespace() && !ch.is_alphanumeric() {
                mask |= C1_PUNCT;
            }
            mask
        }
        CT_CTYPE2 | CT_CTYPE3 => 0,
        _ => 0,
    }
}

fn read_utf16_environment_block(memory: &MemoryImage, address: u64) -> AppResult<BTreeMap<String, String>> {
    let mut cursor = address;
    let mut environment = BTreeMap::new();
    loop {
        let entry = read_utf16_string(memory, cursor)?;
        if entry.is_empty() {
            break;
        }
        if let Some((key, value)) = entry.split_once('=') {
            environment.insert(key.to_string(), value.to_string());
        }
        cursor = cursor.wrapping_add(((entry.encode_utf16().count() + 1) * 2) as u64);
    }
    Ok(environment)
}

fn module_file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn build_windows_command_line(program: &str, args: &[String]) -> String {
    std::iter::once(program.to_string())
        .chain(args.iter().cloned())
        .map(|arg| {
            if arg.contains([' ', '\t', '"']) {
                format!("\"{}\"", arg.replace('"', "\\\""))
            } else {
                arg
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
    use crate::gfx::{host_gpu_profile_from_name, GraphicsBackend};
    use crate::pe::{ExportSymbol, ExportTarget};
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

    fn read_guest_utf16_string(memory: &MemoryImage, address: u64, max_units: usize) -> String {
        let mut units = Vec::new();
        for index in 0..max_units {
            let unit = read_guest_u16(memory, address + (index as u64 * 2)).expect("read utf16 code unit");
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16(&units).expect("decode utf16 string")
    }

    fn configure_runtime_for_test_arch(runtime: &mut PeHostRuntime, guest_arch: GuestArch) {
        runtime.guest_arch = guest_arch;
        runtime.next_thunk_address = thunk_base_for_arch(guest_arch);
        runtime.next_data_address = data_base_for_arch(guest_arch);
        runtime.next_heap_address = heap_base_for_arch(guest_arch);
    }

    fn write_test_guid(memory: &mut MemoryImage, address: u64, data1: u32) {
        write_u32(memory, address, data1);
        memory.map_bytes(address + 4, &0_u16.to_le_bytes());
        memory.map_bytes(address + 6, &0_u16.to_le_bytes());
        memory.map_bytes(address + 8, &[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
    }

    fn dispatch_x86_thunk(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: u64,
        args: &[u32],
    ) -> u64 {
        let stack = 0x50_000;
        memory.map_bytes(stack, &vec![0_u8; 0x200]);
        write_u32(memory, stack, 0xDEAD_BEEF);
        for (index, arg) in args.iter().enumerate() {
            write_u32(memory, stack + 4 + (index as u64 * 4), *arg);
        }
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, stack);
        runtime
            .dispatch_import(thunk, &mut state, memory)
            .expect("dispatch x86 thunk");
        state.get(Register::Rax)
    }

    #[test]
    fn shell_special_folder_path_maps_program_files_for_x86() {
        assert_eq!(
            shell_special_folder_path("casa1", CSIDL_PROGRAM_FILES, GuestArch::X86),
            Some("C:\\Program Files (x86)".to_string())
        );
        assert_eq!(
            shell_special_folder_path("casa1", CSIDL_APPDATA, GuestArch::X64),
            Some("C:\\users\\casa1\\AppData\\Roaming".to_string())
        );
    }

    #[test]
    fn shell_link_persist_file_save_writes_shortcut_in_x86_runtime() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "shell-link", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let co_create_instance = runtime.alloc_host_thunk(HostThunk::CoCreateInstance);
        let clsid_ptr = 0x40_000;
        let iid_shell_link_ptr = 0x40_020;
        let iid_persist_file_ptr = 0x40_040;
        let shell_link_out_ptr = 0x40_060;
        let persist_file_out_ptr = 0x40_080;
        write_test_guid(&mut memory, clsid_ptr, 0x0002_1401);
        write_test_guid(&mut memory, iid_shell_link_ptr, 0x0002_14F9);
        write_test_guid(&mut memory, iid_persist_file_ptr, 0x0000_010B);
        memory.map_bytes(shell_link_out_ptr, &[0; 4]);
        memory.map_bytes(persist_file_out_ptr, &[0; 4]);

        let hresult = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            co_create_instance,
            &[
                clsid_ptr as u32,
                0,
                1,
                iid_shell_link_ptr as u32,
                shell_link_out_ptr as u32,
            ],
        );
        assert_eq!(hresult, 0);
        let shell_link_object = read_u32(&memory, shell_link_out_ptr).expect("shell link out") as u64;

        let shell_link_vtable = read_u32(&memory, shell_link_object).expect("shell link vtable") as u64;
        let query_interface_thunk = read_u32(&memory, shell_link_vtable).expect("query interface thunk") as u64;
        let set_description_thunk = read_u32(&memory, shell_link_vtable + 7 * 4).expect("set description thunk") as u64;
        let set_working_directory_thunk =
            read_u32(&memory, shell_link_vtable + 9 * 4).expect("set working dir thunk") as u64;
        let set_arguments_thunk = read_u32(&memory, shell_link_vtable + 11 * 4).expect("set arguments thunk") as u64;
        let set_icon_location_thunk =
            read_u32(&memory, shell_link_vtable + 17 * 4).expect("set icon thunk") as u64;
        let set_path_thunk = read_u32(&memory, shell_link_vtable + 20 * 4).expect("set path thunk") as u64;

        let target_path_ptr = runtime
            .alloc_utf16_string(&mut memory, "C:\\Program Files (x86)\\Steam\\Steam.exe")
            .expect("target path ptr");
        let working_directory_ptr = runtime
            .alloc_utf16_string(&mut memory, "C:\\Program Files (x86)\\Steam")
            .expect("working dir ptr");
        let description_ptr = runtime.alloc_utf16_string(&mut memory, "Steam").expect("description ptr");
        let arguments_ptr = runtime.alloc_utf16_string(&mut memory, "-silent").expect("arguments ptr");
        let icon_path_ptr = runtime
            .alloc_utf16_string(&mut memory, "C:\\Program Files (x86)\\Steam\\Steam.exe")
            .expect("icon path ptr");

        assert_eq!(
            dispatch_x86_thunk(&mut runtime, &mut memory, set_path_thunk, &[shell_link_object as u32, target_path_ptr as u32]),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_working_directory_thunk,
                &[shell_link_object as u32, working_directory_ptr as u32],
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_description_thunk,
                &[shell_link_object as u32, description_ptr as u32],
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_arguments_thunk,
                &[shell_link_object as u32, arguments_ptr as u32],
            ),
            0
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_icon_location_thunk,
                &[shell_link_object as u32, icon_path_ptr as u32, 0],
            ),
            0
        );

        let hresult = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            query_interface_thunk,
            &[
                shell_link_object as u32,
                iid_persist_file_ptr as u32,
                persist_file_out_ptr as u32,
            ],
        );
        assert_eq!(hresult, 0);
        let persist_file_object = read_u32(&memory, persist_file_out_ptr).expect("persist file out") as u64;
        let persist_file_vtable = read_u32(&memory, persist_file_object).expect("persist file vtable") as u64;
        let save_thunk = read_u32(&memory, persist_file_vtable + 6 * 4).expect("save thunk") as u64;

        let shortcut_path = "C:\\users\\casa1\\Desktop\\Steam.lnk";
        let shortcut_path_ptr = runtime
            .alloc_utf16_string(&mut memory, shortcut_path)
            .expect("shortcut path ptr");
        let hresult = dispatch_x86_thunk(
            &mut runtime,
            &mut memory,
            save_thunk,
            &[persist_file_object as u32, shortcut_path_ptr as u32, 1],
        );
        assert_eq!(hresult, 0);

        let host_shortcut_path = runtime
            .win32
            .guest_path_to_host_path(shortcut_path)
            .expect("shortcut host path");
        let shortcut_bytes = fs::read(&host_shortcut_path).expect("read shortcut bytes");
        assert_eq!(&shortcut_bytes[..4], &0x4c_u32.to_le_bytes());
        assert!(shortcut_bytes.windows("Steam.exe".len()).any(|window| window == b"Steam.exe"));
        assert_eq!(
            runtime
                .shell_link_state_for_interface(shell_link_object)
                .expect("shell link state")
                .current_file
                .as_deref(),
            Some(shortcut_path)
        );
    }

    #[test]
    fn write_private_profile_string_w_updates_ini_file_in_x86_runtime() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "ini-write", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let thunk = runtime.alloc_host_thunk(HostThunk::WritePrivateProfileStringW);
        let ini_path = "C:\\users\\casa1\\AppData\\Roaming\\Steam\\config\\steam.ini";
        let path_ptr = runtime.alloc_utf16_string(&mut memory, ini_path).expect("path ptr");
        let section_ptr = runtime.alloc_utf16_string(&mut memory, "Steam").expect("section ptr");
        let key_ptr = runtime.alloc_utf16_string(&mut memory, "Language").expect("key ptr");
        let english_ptr = runtime.alloc_utf16_string(&mut memory, "english").expect("value ptr");
        let french_ptr = runtime.alloc_utf16_string(&mut memory, "french").expect("updated value ptr");

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[
                    section_ptr as u32,
                    key_ptr as u32,
                    english_ptr as u32,
                    path_ptr as u32,
                ],
            ),
            1
        );
        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[
                    section_ptr as u32,
                    key_ptr as u32,
                    french_ptr as u32,
                    path_ptr as u32,
                ],
            ),
            1
        );

        let host_ini_path = runtime
            .win32
            .guest_path_to_host_path(ini_path)
            .expect("host ini path");
        let ini_text = String::from_utf8(fs::read(&host_ini_path).expect("read ini bytes")).expect("ini text");
        assert_eq!(ini_text, "[Steam]\nLanguage=french\n");
    }

    #[test]
    fn reg_create_key_ex_w_creates_and_reopens_key_in_x86_runtime() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "reg-create", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let thunk = runtime.alloc_host_thunk(HostThunk::RegCreateKeyExW);
        let subkey_ptr = runtime
            .alloc_utf16_string(&mut memory, "Software\\Casa1\\Steam")
            .expect("subkey ptr");
        let first_result_ptr = 0x41_000;
        let first_disposition_ptr = 0x41_004;
        let second_result_ptr = 0x41_008;
        let second_disposition_ptr = 0x41_00c;
        memory.map_bytes(first_result_ptr, &[0; 4]);
        memory.map_bytes(first_disposition_ptr, &[0; 4]);
        memory.map_bytes(second_result_ptr, &[0; 4]);
        memory.map_bytes(second_disposition_ptr, &[0; 4]);

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[
                    HKEY_CURRENT_USER,
                    subkey_ptr as u32,
                    0,
                    0,
                    0,
                    0,
                    0,
                    first_result_ptr as u32,
                    first_disposition_ptr as u32,
                ],
            ),
            0
        );
        assert_ne!(read_u32(&memory, first_result_ptr).expect("first handle"), 0);
        assert_eq!(
            read_u32(&memory, first_disposition_ptr).expect("first disposition"),
            REG_CREATED_NEW_KEY
        );
        assert!(
            runtime
                .win32
                .registry_key_exists("HKCU", "Software\\Casa1\\Steam", RegistryView::Native)
                .expect("registry exists")
        );

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[
                    HKEY_CURRENT_USER,
                    subkey_ptr as u32,
                    0,
                    0,
                    0,
                    0,
                    0,
                    second_result_ptr as u32,
                    second_disposition_ptr as u32,
                ],
            ),
            0
        );
        assert_ne!(read_u32(&memory, second_result_ptr).expect("second handle"), 0);
        assert_eq!(
            read_u32(&memory, second_disposition_ptr).expect("second disposition"),
            REG_OPENED_EXISTING_KEY
        );
    }

    #[test]
    fn reg_set_value_ex_w_writes_registry_string_in_x86_runtime() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "reg-set", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        runtime
            .win32
            .create_registry_key("HKCU", "Software\\Casa1\\Steam", RegistryView::Native)
            .expect("create registry key");
        let handle = runtime
            .win32
            .open_registry_key("HKCU", "Software\\Casa1\\Steam", RegistryView::Native, false);
        let thunk = runtime.alloc_host_thunk(HostThunk::RegSetValueExW);
        let value_name_ptr = runtime
            .alloc_utf16_string(&mut memory, "Language")
            .expect("value name ptr");
        let value_units = "english\0".encode_utf16().collect::<Vec<_>>();
        let value_ptr = 0x42_000;
        let mut value_bytes = Vec::new();
        for unit in value_units {
            value_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        memory.map_bytes(value_ptr, &value_bytes);

        assert_eq!(
            dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                thunk,
                &[
                    handle,
                    value_name_ptr as u32,
                    0,
                    REG_SZ,
                    value_ptr as u32,
                    value_bytes.len() as u32,
                ],
            ),
            0
        );

        let stored = runtime
            .win32
            .registry_get_value("HKCU", "Software\\Casa1\\Steam", "Language", RegistryView::Native)
            .expect("registry get value")
            .expect("stored registry value");
        assert_eq!(stored.value_type, "REG_SZ");
        assert_eq!(stored.data, json!("english"));
    }

    #[test]
    fn local_alloc_returns_heap_backed_handle_in_x86_runtime() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "local-alloc", GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        configure_runtime_for_test_arch(&mut runtime, GuestArch::X86);
        let mut memory = MemoryImage::default();

        let thunk = runtime.alloc_host_thunk(HostThunk::LocalAlloc);
        let handle = dispatch_x86_thunk(&mut runtime, &mut memory, thunk, &[0, 64]);

        assert_ne!(handle, 0);
        assert_eq!(runtime.heap_allocations.get(&handle).copied(), Some(64));
    }

    fn dispatch_feature_support_query(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        state: &mut CpuState,
        thunk: u64,
        device_object: u64,
        feature: u32,
        data_ptr: u64,
        data_size: usize,
        return_slot: u64,
    ) {
        state.set(Register::Rsp, return_slot);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, feature as u64);
        state.set(Register::R8, data_ptr);
        state.set(Register::R9, data_size as u64);
        memory.write_u64(return_slot, 0x3333_0000 + feature as u64);
        runtime
            .dispatch_import(thunk, state, memory)
            .expect("dispatch CheckFeatureSupport");
        assert_eq!(state.get(Register::Rax), 0);
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
        let mut instruction_cache = U64Map::default();
        let mut instruction_cache_lru = VecDeque::new();
        let mut instruction_cache_generation = 0;

        memory.map_bytes(rip, &[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
        let first = decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            rip,
        )
            .expect("decode cached nop");
        assert_eq!(first.decoded.opcode, DecodedOpcode::Nop);

        memory.map_bytes(rip, &[0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
        let second = decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            rip,
        )
            .expect("decode cached ret");

        assert_eq!(second.decoded.opcode, DecodedOpcode::Ret);
        assert_eq!(second.decoded.size, 1);
    }

    #[test]
    fn decode_current_instruction_cache_evicts_old_entries_without_clearing_hot_entries() {
        let base_rip = 0xB000;
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        let mut instruction_cache = U64Map::default();
        let mut instruction_cache_lru = VecDeque::new();
        let mut instruction_cache_generation = 0;

        memory.map_bytes(base_rip, &[0x90; 15]);
        memory.map_bytes(base_rip + 0x10, &[0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
        memory.map_bytes(base_rip + 0x20, &[0x50, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);

        decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            2,
            base_rip,
        )
        .expect("decode first instruction");
        decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            2,
            base_rip + 0x10,
        )
        .expect("decode second instruction");
        decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            2,
            base_rip,
        )
        .expect("refresh first instruction");
        decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            2,
            base_rip + 0x20,
        )
        .expect("decode third instruction");

        assert!(instruction_cache.contains_key(&base_rip));
        assert!(instruction_cache.contains_key(&(base_rip + 0x20)));
        assert!(!instruction_cache.contains_key(&(base_rip + 0x10)));
        assert_eq!(instruction_cache.len(), 2);
    }

    #[test]
    fn decode_current_instruction_cache_reuses_shared_entry_on_hit() {
        let rip = 0xC000;
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        let mut instruction_cache = U64Map::default();
        let mut instruction_cache_lru = VecDeque::new();
        let mut instruction_cache_generation = 0;

        memory.map_bytes(rip, &[0x90; 15]);
        let first = decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            rip,
        )
        .expect("decode cached nop");
        let second = decode_current_instruction_cached(
            &engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            rip,
        )
        .expect("reuse cached nop");

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn decode_basic_block_cache_reuses_shared_entry_on_hit() {
        let rip = 0xD000;
        let config = CpuEngineConfig::from_profile(
            GuestArch::X64,
            "win11-23h2",
            env!("CARGO_PKG_VERSION"),
            None,
        )
        .expect("cpu config");
        let mut engine = CpuExecutionEngine::new(config);
        let mut memory = MemoryImage::default();
        let mut instruction_cache = U64Map::default();
        let mut instruction_cache_lru = VecDeque::new();
        let mut instruction_cache_generation = 0;
        let mut basic_block_cache = U64Map::default();
        let mut basic_block_cache_lru = VecDeque::new();
        let mut basic_block_cache_generation = 0;

        let mut bytes = vec![0x90; 32];
        bytes[2] = 0xC3;
        memory.map_bytes(rip, &bytes);
        let first = decode_basic_block_cached(
            &mut engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            &mut basic_block_cache,
            &mut basic_block_cache_lru,
            &mut basic_block_cache_generation,
            BASIC_BLOCK_CACHE_LIMIT,
            rip,
        )
        .expect("decode cached block");
        let second = decode_basic_block_cached(
            &mut engine,
            &memory,
            &mut instruction_cache,
            &mut instruction_cache_lru,
            &mut instruction_cache_generation,
            INSTRUCTION_CACHE_LIMIT,
            &mut basic_block_cache,
            &mut basic_block_cache_lru,
            &mut basic_block_cache_generation,
            BASIC_BLOCK_CACHE_LIMIT,
            rip,
        )
        .expect("reuse cached block");

        assert!(Arc::ptr_eq(&first, &second));
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

    #[test]
    fn host_thunk_from_import_maps_dxgi_and_d3d12_creation_imports() {
        let dxgi_import = ResolvedImport {
            requested_module: "dxgi.dll".to_string(),
            resolved_module: "dxgi.dll".to_string(),
            symbol: ImportSymbol::ByName {
                hint: 0,
                name: "CreateDXGIFactory1".to_string(),
            },
            iat_rva: 0x1000,
            export: ExportSymbol {
                ordinal: 1,
                name: Some("CreateDXGIFactory1".to_string()),
                target: ExportTarget::Rva(0x4100),
            },
        };
        let d3d12_import = ResolvedImport {
            requested_module: "d3d12.dll".to_string(),
            resolved_module: "d3d12.dll".to_string(),
            symbol: ImportSymbol::ByName {
                hint: 0,
                name: "D3D12CreateDevice".to_string(),
            },
            iat_rva: 0x1010,
            export: ExportSymbol {
                ordinal: 1,
                name: Some("D3D12CreateDevice".to_string()),
                target: ExportTarget::Rva(0x4200),
            },
        };

        assert!(matches!(HostThunk::from_import(&dxgi_import), HostThunk::CreateDXGIFactory1));
        assert!(matches!(HostThunk::from_import(&d3d12_import), HostThunk::D3D12CreateDevice));
    }

    #[test]
    fn host_thunk_from_import_maps_virtual_alloc() {
        let import = ResolvedImport {
            requested_module: "kernel32.dll".to_string(),
            resolved_module: "kernel32.dll".to_string(),
            symbol: ImportSymbol::ByName {
                hint: 0,
                name: "VirtualAlloc".to_string(),
            },
            iat_rva: 0x1020,
            export: ExportSymbol {
                ordinal: 118,
                name: Some("VirtualAlloc".to_string()),
                target: ExportTarget::Rva(0x1110),
            },
        };

        assert!(matches!(HostThunk::from_import(&import), HostThunk::VirtualAlloc));
    }

    #[test]
    fn pe_runtime_command_line_to_argv_w_returns_wide_argv_array() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "cmdline-to-argv", GeArch::X64, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let mut state = CpuState::new(GuestArch::X64);
        let thunk = runtime.alloc_host_thunk(HostThunk::CommandLineToArgvW);
        let stack_base = 0x40_000;
        let argc_ptr = 0x41_000;

        runtime.command_line = "\"C:\\\\Program Files\\\\Steam\\\\Steam.exe\" -silent".to_string();

        memory.map_bytes(stack_base, &vec![0_u8; 0x100]);
        memory.map_bytes(argc_ptr, &[0; 4]);

        let command_line = runtime.command_line.clone();
        let command_line_ptr = runtime
            .alloc_utf16_string(&mut memory, &command_line)
            .expect("alloc command line");

        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, command_line_ptr);
        state.set(Register::Rdx, argc_ptr);
        memory.write_u64(stack_base, 0x1234_5678);

        runtime
            .dispatch_import(thunk, &mut state, &mut memory)
            .expect("dispatch CommandLineToArgvW");

        let argv_ptr = state.get(Register::Rax);
        assert_ne!(argv_ptr, 0);
        assert_eq!(read_guest_u32(&memory, argc_ptr).expect("argc"), 2);

        let arg0_ptr = read_guest_pointer(&memory, argv_ptr, GuestArch::X64).expect("argv[0]");
        let arg1_ptr = read_guest_pointer(&memory, argv_ptr + 8, GuestArch::X64).expect("argv[1]");
        let end_ptr = read_guest_pointer(&memory, argv_ptr + 16, GuestArch::X64).expect("argv[2]");

        assert_eq!(read_guest_utf16_string(&memory, arg0_ptr, 128), "C:\\Program Files\\Steam\\Steam.exe");
        assert_eq!(read_guest_utf16_string(&memory, arg1_ptr, 128), "-silent");
        assert_eq!(end_ptr, 0);
    }

    #[test]
    fn pe_runtime_d3d12_queue_and_fence_thunks_signal_runtime_fence() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "d3d12-thunk", GeArch::X64, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();
        let stack_base = 0x30_000;
        let factory_out_ptr = 0x31_000;
        let device_out_ptr = 0x31_008;
        let queue_out_ptr = 0x31_010;
        let fence_out_ptr = 0x31_018;
        let queue_desc_ptr = 0x32_000;

        memory.map_bytes(stack_base, &vec![0_u8; 0x100]);
        memory.map_bytes(factory_out_ptr, &[0; 8]);
        memory.map_bytes(device_out_ptr, &[0; 8]);
        memory.map_bytes(queue_out_ptr, &[0; 8]);
        memory.map_bytes(fence_out_ptr, &[0; 8]);
        memory.map_bytes(queue_desc_ptr, &[0; 16]);

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, factory_out_ptr);
        memory.write_u64(stack_base, 0xAA55_AA55);

        let create_factory = runtime.alloc_host_thunk(HostThunk::CreateDXGIFactory1);
        runtime
            .dispatch_import(create_factory, &mut state, &mut memory)
            .expect("dispatch CreateDXGIFactory1");
        let factory_object = memory.read_u64(factory_out_ptr).expect("factory object");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime.guest_object_kind(factory_object).expect("factory kind"), GuestObjectKind::DxgiFactory);

        state.set(Register::Rsp, stack_base + 0x20);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, device_out_ptr);
        memory.write_u64(stack_base + 0x20, 0xBB66_BB66);

        let create_device = runtime.alloc_host_thunk(HostThunk::D3D12CreateDevice);
        runtime
            .dispatch_import(create_device, &mut state, &mut memory)
            .expect("dispatch D3D12CreateDevice");
        let device_object = memory.read_u64(device_out_ptr).expect("device object");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime.guest_object_kind(device_object).expect("device kind"), GuestObjectKind::D3d12Device);

        let device_vtable = memory.read_u64(device_object).expect("device vtable");
        let create_queue_thunk = memory
            .read_u64(device_vtable + 8 * 8)
            .expect("CreateCommandQueue thunk");
        let create_fence_thunk = memory
            .read_u64(device_vtable + 36 * 8)
            .expect("CreateFence thunk");

        state.set(Register::Rsp, stack_base + 0x40);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, queue_desc_ptr);
        state.set(Register::R8, 0);
        state.set(Register::R9, queue_out_ptr);
        memory.write_u64(stack_base + 0x40, 0xCC77_CC77);

        runtime
            .dispatch_import(create_queue_thunk, &mut state, &mut memory)
            .expect("dispatch CreateCommandQueue");
        let queue_object = memory.read_u64(queue_out_ptr).expect("queue object");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(
            runtime.guest_object_kind(queue_object).expect("queue kind"),
            GuestObjectKind::D3d12CommandQueue
        );

        state.set(Register::Rsp, stack_base + 0x60);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, 0);
        memory.write_u64(stack_base + 0x60, 0xDD88_DD88);
        memory.write_u64(stack_base + 0x60 + 0x28, fence_out_ptr);

        runtime
            .dispatch_import(create_fence_thunk, &mut state, &mut memory)
            .expect("dispatch CreateFence");
        let fence_object = memory.read_u64(fence_out_ptr).expect("fence object");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime.guest_object_kind(fence_object).expect("fence kind"), GuestObjectKind::D3d12Fence);

        let queue_vtable = memory.read_u64(queue_object).expect("queue vtable");
        let signal_thunk = memory.read_u64(queue_vtable + 14 * 8).expect("Signal thunk");
        state.set(Register::Rsp, stack_base + 0x80);
        state.set(Register::Rcx, queue_object);
        state.set(Register::Rdx, fence_object);
        state.set(Register::R8, 7);
        memory.write_u64(stack_base + 0x80, 0xEE99_EE99);
        runtime
            .dispatch_import(signal_thunk, &mut state, &mut memory)
            .expect("dispatch Signal");
        assert_eq!(state.get(Register::Rax), 0);

        let fence_vtable = memory.read_u64(fence_object).expect("fence vtable");
        let get_completed_value_thunk = memory
            .read_u64(fence_vtable + 8 * 8)
            .expect("GetCompletedValue thunk");
        state.set(Register::Rsp, stack_base + 0xA0);
        state.set(Register::Rcx, fence_object);
        memory.write_u64(stack_base + 0xA0, 0xFFAA_FFAA);
        runtime
            .dispatch_import(get_completed_value_thunk, &mut state, &mut memory)
            .expect("dispatch GetCompletedValue");
        assert_eq!(state.get(Register::Rax), 7);

        assert!(runtime.trace_events.iter().any(|event| event.call_id == "CreateDXGIFactory1"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "D3D12CreateDevice"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12Device::CreateCommandQueue"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12Device::CreateFence"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12CommandQueue::Signal"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12Fence::GetCompletedValue"));
    }

    #[test]
    fn pe_runtime_dxgi_adapter_enumeration_exposes_vendor_compatible_descriptors() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "dxgi-adapter", GeArch::X64, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.d3d12_runtime = D3d12Runtime::from_backend(GraphicsBackend::with_host_profile(
            host_gpu_profile_from_name("NVIDIA GeForce RTX 4080"),
        ));
        let mut memory = MemoryImage::default();
        let stack_base = 0x34_000;
        let factory_out_ptr = 0x35_000;
        let adapter_out_ptr = 0x35_008;
        let desc1_ptr = 0x36_000;

        memory.map_bytes(stack_base, &vec![0_u8; 0x100]);
        memory.map_bytes(factory_out_ptr, &[0; 8]);
        memory.map_bytes(adapter_out_ptr, &[0; 8]);
        memory.map_bytes(desc1_ptr, &[0; 320]);

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, factory_out_ptr);
        memory.write_u64(stack_base, 0x1111_0001);

        let create_factory = runtime.alloc_host_thunk(HostThunk::CreateDXGIFactory1);
        runtime
            .dispatch_import(create_factory, &mut state, &mut memory)
            .expect("dispatch CreateDXGIFactory1");
        let factory_object = memory.read_u64(factory_out_ptr).expect("factory object");

        let factory_vtable = memory.read_u64(factory_object).expect("factory vtable");
        let enum_adapters1_thunk = memory
            .read_u64(factory_vtable + 12 * 8)
            .expect("EnumAdapters1 thunk");
        state.set(Register::Rsp, stack_base + 0x20);
        state.set(Register::Rcx, factory_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, adapter_out_ptr);
        memory.write_u64(stack_base + 0x20, 0x1111_0002);
        runtime
            .dispatch_import(enum_adapters1_thunk, &mut state, &mut memory)
            .expect("dispatch EnumAdapters1");
        let adapter_object = memory.read_u64(adapter_out_ptr).expect("adapter object");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime.guest_object_kind(adapter_object).expect("adapter kind"), GuestObjectKind::DxgiAdapter);

        let adapter_vtable = memory.read_u64(adapter_object).expect("adapter vtable");
        let get_desc1_thunk = memory.read_u64(adapter_vtable + 10 * 8).expect("GetDesc1 thunk");
        state.set(Register::Rsp, stack_base + 0x40);
        state.set(Register::Rcx, adapter_object);
        state.set(Register::Rdx, desc1_ptr);
        memory.write_u64(stack_base + 0x40, 0x1111_0003);
        runtime
            .dispatch_import(get_desc1_thunk, &mut state, &mut memory)
            .expect("dispatch GetDesc1");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(read_guest_u32(&memory, desc1_ptr + 256).expect("vendor id"), 0x10de);
        assert_eq!(read_guest_u32(&memory, desc1_ptr + 260).expect("device id"), 0x2008);
        assert_eq!(read_guest_u32(&memory, desc1_ptr + 304).expect("flags"), 0);
        assert_eq!(
            read_guest_utf16_string(&memory, desc1_ptr, DXGI_ADAPTER_DESC_DESCRIPTION_CHARS),
            "NVIDIA GeForce RTX 4080"
        );

        state.set(Register::Rsp, stack_base + 0x60);
        state.set(Register::Rcx, factory_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, adapter_out_ptr);
        memory.write_u64(stack_base + 0x60, 0x1111_0004);
        runtime
            .dispatch_import(enum_adapters1_thunk, &mut state, &mut memory)
            .expect("dispatch EnumAdapters1 miss");
        assert_eq!(state.get(Register::Rax), DXGI_ERROR_NOT_FOUND);

        assert!(runtime.trace_events.iter().any(|event| event.call_id == "IDXGIFactory1::EnumAdapters1"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "IDXGIAdapter1::GetDesc1"));
    }

    #[test]
    fn pe_runtime_d3d12_check_feature_support_covers_common_startup_queries() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "d3d12-feature-support", GeArch::X64, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.d3d12_runtime = D3d12Runtime::from_backend(GraphicsBackend::with_host_profile(
            host_gpu_profile_from_name("Apple M3 Pro"),
        ));
        let mut memory = MemoryImage::default();
        let stack_base = 0x44_000;
        let factory_out_ptr = 0x45_000;
        let adapter_out_ptr = 0x45_008;
        let device_out_ptr = 0x45_010;
        let feature_levels_requested_ptr = 0x46_000;
        let feature_levels_ptr = 0x46_020;
        let shader_model_ptr = 0x46_040;
        let root_signature_ptr = 0x46_048;
        let architecture_ptr = 0x46_050;
        let options_ptr = 0x46_070;
        let options5_ptr = 0x46_0c0;
        let options7_ptr = 0x46_0d0;

        memory.map_bytes(stack_base, &vec![0_u8; 0x120]);
        memory.map_bytes(factory_out_ptr, &[0; 8]);
        memory.map_bytes(adapter_out_ptr, &[0; 8]);
        memory.map_bytes(device_out_ptr, &[0; 8]);
        memory.map_bytes(feature_levels_requested_ptr, &[0; 12]);
        memory.map_bytes(feature_levels_ptr, &[0; 24]);
        memory.map_bytes(shader_model_ptr, &[0; 4]);
        memory.map_bytes(root_signature_ptr, &[0; 4]);
        memory.map_bytes(architecture_ptr, &[0; 20]);
        memory.map_bytes(options_ptr, &[0; 60]);
        memory.map_bytes(options5_ptr, &[0; 12]);
        memory.map_bytes(options7_ptr, &[0; 8]);

        write_u32(&mut memory, feature_levels_requested_ptr, D3D_FEATURE_LEVEL_12_2);
        write_u32(&mut memory, feature_levels_requested_ptr + 4, D3D_FEATURE_LEVEL_12_1);
        write_u32(&mut memory, feature_levels_requested_ptr + 8, D3D_FEATURE_LEVEL_12_0);
        write_u32(&mut memory, feature_levels_ptr, 3);
        write_u64(&mut memory, feature_levels_ptr + 8, feature_levels_requested_ptr);
        write_u32(&mut memory, shader_model_ptr, 0x67);
        write_u32(&mut memory, root_signature_ptr, 3);
        write_u32(&mut memory, architecture_ptr, 0);

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, factory_out_ptr);
        memory.write_u64(stack_base, 0x2222_0001);

        let create_factory = runtime.alloc_host_thunk(HostThunk::CreateDXGIFactory1);
        runtime
            .dispatch_import(create_factory, &mut state, &mut memory)
            .expect("dispatch CreateDXGIFactory1");
        let factory_object = memory.read_u64(factory_out_ptr).expect("factory object");

        let factory_vtable = memory.read_u64(factory_object).expect("factory vtable");
        let enum_adapters_thunk = memory.read_u64(factory_vtable + 7 * 8).expect("EnumAdapters thunk");
        state.set(Register::Rsp, stack_base + 0x20);
        state.set(Register::Rcx, factory_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, adapter_out_ptr);
        memory.write_u64(stack_base + 0x20, 0x2222_0002);
        runtime
            .dispatch_import(enum_adapters_thunk, &mut state, &mut memory)
            .expect("dispatch EnumAdapters");
        let adapter_object = memory.read_u64(adapter_out_ptr).expect("adapter object");

        state.set(Register::Rsp, stack_base + 0x40);
        state.set(Register::Rcx, adapter_object);
        state.set(Register::Rdx, D3D_FEATURE_LEVEL_11_0 as u64);
        state.set(Register::R8, 0);
        state.set(Register::R9, device_out_ptr);
        memory.write_u64(stack_base + 0x40, 0x2222_0003);
        let create_device = runtime.alloc_host_thunk(HostThunk::D3D12CreateDevice);
        runtime
            .dispatch_import(create_device, &mut state, &mut memory)
            .expect("dispatch D3D12CreateDevice");
        let device_object = memory.read_u64(device_out_ptr).expect("device object");
        assert_eq!(state.get(Register::Rax), 0);

        let device_vtable = memory.read_u64(device_object).expect("device vtable");
        let check_feature_support_thunk = memory
            .read_u64(device_vtable + 13 * 8)
            .expect("CheckFeatureSupport thunk");

        dispatch_feature_support_query(
            &mut runtime,
            &mut memory,
            &mut state,
            check_feature_support_thunk,
            device_object,
            D3D12_FEATURE_FEATURE_LEVELS,
            feature_levels_ptr,
            24,
            stack_base + 0x60,
        );
        assert_eq!(read_guest_u32(&memory, feature_levels_ptr + 16).expect("max feature level"), D3D_FEATURE_LEVEL_12_2);

        dispatch_feature_support_query(
            &mut runtime,
            &mut memory,
            &mut state,
            check_feature_support_thunk,
            device_object,
            D3D12_FEATURE_ARCHITECTURE1,
            architecture_ptr,
            20,
            stack_base + 0x68,
        );
        assert_eq!(read_guest_u32(&memory, architecture_ptr + 4).expect("tile based"), 1);
        assert_eq!(read_guest_u32(&memory, architecture_ptr + 8).expect("uma"), 1);
        assert_eq!(read_guest_u32(&memory, architecture_ptr + 12).expect("cache coherent uma"), 1);
        assert_eq!(read_guest_u32(&memory, architecture_ptr + 16).expect("isolated mmu"), 0);

        dispatch_feature_support_query(
            &mut runtime,
            &mut memory,
            &mut state,
            check_feature_support_thunk,
            device_object,
            D3D12_FEATURE_SHADER_MODEL,
            shader_model_ptr,
            4,
            stack_base + 0x70,
        );
        assert_eq!(read_guest_u32(&memory, shader_model_ptr).expect("shader model"), D3D_SHADER_MODEL_6_6);

        dispatch_feature_support_query(
            &mut runtime,
            &mut memory,
            &mut state,
            check_feature_support_thunk,
            device_object,
            D3D12_FEATURE_ROOT_SIGNATURE,
            root_signature_ptr,
            4,
            stack_base + 0x78,
        );
        assert_eq!(
            read_guest_u32(&memory, root_signature_ptr).expect("root signature version"),
            D3D12_ROOT_SIGNATURE_VERSION_1_1
        );

        dispatch_feature_support_query(
            &mut runtime,
            &mut memory,
            &mut state,
            check_feature_support_thunk,
            device_object,
            D3D12_FEATURE_D3D12_OPTIONS,
            options_ptr,
            60,
            stack_base + 0x80,
        );
        assert_eq!(read_guest_u32(&memory, options_ptr + 16).expect("resource binding tier"), D3D12_RESOURCE_BINDING_TIER_3);
        assert_eq!(read_guest_u32(&memory, options_ptr + 56).expect("resource heap tier"), D3D12_RESOURCE_HEAP_TIER_2);

        dispatch_feature_support_query(
            &mut runtime,
            &mut memory,
            &mut state,
            check_feature_support_thunk,
            device_object,
            D3D12_FEATURE_D3D12_OPTIONS5,
            options5_ptr,
            12,
            stack_base + 0x88,
        );
        assert_eq!(read_guest_u32(&memory, options5_ptr + 4).expect("render pass tier"), D3D12_RENDER_PASS_TIER_1);
        assert_eq!(read_guest_u32(&memory, options5_ptr + 8).expect("raytracing tier"), D3D12_RAYTRACING_TIER_NOT_SUPPORTED);

        dispatch_feature_support_query(
            &mut runtime,
            &mut memory,
            &mut state,
            check_feature_support_thunk,
            device_object,
            D3D12_FEATURE_D3D12_OPTIONS7,
            options7_ptr,
            8,
            stack_base + 0x90,
        );
        assert_eq!(read_guest_u32(&memory, options7_ptr).expect("mesh shader tier"), D3D12_MESH_SHADER_TIER_1);
        assert_eq!(
            read_guest_u32(&memory, options7_ptr + 4).expect("sampler feedback tier"),
            D3D12_SAMPLER_FEEDBACK_TIER_NOT_SUPPORTED
        );

        assert!(runtime.trace_events.iter().any(|event| event.call_id == "IDXGIFactory::EnumAdapters"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12Device::CheckFeatureSupport"));
    }

    #[test]
    fn pe_runtime_d3d12_swapchain_and_command_list_thunks_submit_and_present() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "d3d12-swapchain", GeArch::X64, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        let mut memory = MemoryImage::default();

        let stack_base = 0x40_000;
        let factory_out_ptr = 0x41_000;
        let device_out_ptr = 0x41_008;
        let queue_out_ptr = 0x41_010;
        let swapchain_out_ptr = 0x41_018;
        let backbuffer_out_ptr = 0x41_020;
        let allocator_out_ptr = 0x41_028;
        let command_list_out_ptr = 0x41_030;
        let command_list_array_ptr = 0x41_038;
        let descriptor_heap_out_ptr = 0x41_040;
        let queue_desc_ptr = 0x42_000;
        let swapchain_desc1_ptr = 0x42_100;
        let descriptor_heap_desc_ptr = 0x42_140;
        let first_barrier_ptr = 0x42_180;
        let second_barrier_ptr = 0x42_1a0;

        memory.map_bytes(stack_base, &vec![0_u8; 0x280]);
        memory.map_bytes(factory_out_ptr, &[0; 8]);
        memory.map_bytes(device_out_ptr, &[0; 8]);
        memory.map_bytes(queue_out_ptr, &[0; 8]);
        memory.map_bytes(swapchain_out_ptr, &[0; 8]);
        memory.map_bytes(backbuffer_out_ptr, &[0; 8]);
        memory.map_bytes(allocator_out_ptr, &[0; 8]);
        memory.map_bytes(command_list_out_ptr, &[0; 8]);
        memory.map_bytes(command_list_array_ptr, &[0; 8]);
        memory.map_bytes(descriptor_heap_out_ptr, &[0; 8]);
        memory.map_bytes(queue_desc_ptr, &[0; 16]);
        memory.map_bytes(swapchain_desc1_ptr, &[0; 64]);
        memory.map_bytes(descriptor_heap_desc_ptr, &[0; 16]);
        memory.map_bytes(first_barrier_ptr, &[0; 32]);
        memory.map_bytes(second_barrier_ptr, &[0; 32]);

        write_u32(&mut memory, swapchain_desc1_ptr, 2);
        write_u32(&mut memory, swapchain_desc1_ptr + 4, 2);
        write_u32(&mut memory, swapchain_desc1_ptr + 8, 28);
        write_u32(&mut memory, swapchain_desc1_ptr + 16, 1);
        write_u32(&mut memory, swapchain_desc1_ptr + 20, 0);
        write_u32(&mut memory, swapchain_desc1_ptr + 28, 2);

        write_u32(&mut memory, descriptor_heap_desc_ptr, 2);
        write_u32(&mut memory, descriptor_heap_desc_ptr + 4, 1);
        write_u32(&mut memory, descriptor_heap_desc_ptr + 8, 0);
        write_u32(&mut memory, descriptor_heap_desc_ptr + 12, 0);

        let mut state = CpuState::new(GuestArch::X64);
        state.set(Register::Rsp, stack_base);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, factory_out_ptr);
        memory.write_u64(stack_base, 0x1000_0001);

        let create_factory = runtime.alloc_host_thunk(HostThunk::CreateDXGIFactory1);
        runtime
            .dispatch_import(create_factory, &mut state, &mut memory)
            .expect("dispatch CreateDXGIFactory1");
        let factory_object = memory.read_u64(factory_out_ptr).expect("factory object");

        state.set(Register::Rsp, stack_base + 0x20);
        state.set(Register::Rcx, 0);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, device_out_ptr);
        memory.write_u64(stack_base + 0x20, 0x1000_0002);

        let create_device = runtime.alloc_host_thunk(HostThunk::D3D12CreateDevice);
        runtime
            .dispatch_import(create_device, &mut state, &mut memory)
            .expect("dispatch D3D12CreateDevice");
        let device_object = memory.read_u64(device_out_ptr).expect("device object");

        let device_vtable = memory.read_u64(device_object).expect("device vtable");
        let create_queue_thunk = memory
            .read_u64(device_vtable + 8 * 8)
            .expect("CreateCommandQueue thunk");
        let create_allocator_thunk = memory
            .read_u64(device_vtable + 9 * 8)
            .expect("CreateCommandAllocator thunk");
        let create_command_list_thunk = memory
            .read_u64(device_vtable + 12 * 8)
            .expect("CreateCommandList thunk");
        let create_descriptor_heap_thunk = memory
            .read_u64(device_vtable + 14 * 8)
            .expect("CreateDescriptorHeap thunk");
        let create_rtv_thunk = memory
            .read_u64(device_vtable + 20 * 8)
            .expect("CreateRenderTargetView thunk");

        state.set(Register::Rsp, stack_base + 0x40);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, queue_desc_ptr);
        state.set(Register::R8, 0);
        state.set(Register::R9, queue_out_ptr);
        memory.write_u64(stack_base + 0x40, 0x1000_0003);
        runtime
            .dispatch_import(create_queue_thunk, &mut state, &mut memory)
            .expect("dispatch CreateCommandQueue");
        let queue_object = memory.read_u64(queue_out_ptr).expect("queue object");

        let factory_vtable = memory.read_u64(factory_object).expect("factory vtable");
        let create_swapchain_for_hwnd_thunk = memory
            .read_u64(factory_vtable + 15 * 8)
            .expect("CreateSwapChainForHwnd thunk");
        state.set(Register::Rsp, stack_base + 0x60);
        state.set(Register::Rcx, factory_object);
        state.set(Register::Rdx, queue_object);
        state.set(Register::R8, 0x1234);
        state.set(Register::R9, swapchain_desc1_ptr);
        memory.write_u64(stack_base + 0x60, 0x1000_0004);
        memory.write_u64(stack_base + 0x60 + 0x28, 0);
        memory.write_u64(stack_base + 0x60 + 0x30, 0);
        memory.write_u64(stack_base + 0x60 + 0x38, swapchain_out_ptr);
        runtime
            .dispatch_import(create_swapchain_for_hwnd_thunk, &mut state, &mut memory)
            .expect("dispatch CreateSwapChainForHwnd");
        let swapchain_object = memory.read_u64(swapchain_out_ptr).expect("swapchain object");
        assert_eq!(runtime.guest_object_kind(swapchain_object).expect("swapchain kind"), GuestObjectKind::DxgiSwapChain);

        let swapchain_vtable = memory.read_u64(swapchain_object).expect("swapchain vtable");
        let resize_buffers_thunk = memory
            .read_u64(swapchain_vtable + 13 * 8)
            .expect("ResizeBuffers thunk");
        state.set(Register::Rsp, stack_base + 0x78);
        state.set(Register::Rcx, swapchain_object);
        state.set(Register::Rdx, 2);
        state.set(Register::R8, 4);
        state.set(Register::R9, 4);
        memory.write_u64(stack_base + 0x78, 0x1000_0004_5);
        write_u32(&mut memory, stack_base + 0x78 + 0x28, 28);
        write_u32(&mut memory, stack_base + 0x78 + 0x30, 0);
        runtime
            .dispatch_import(resize_buffers_thunk, &mut state, &mut memory)
            .expect("dispatch ResizeBuffers");
        assert_eq!(state.get(Register::Rax), 0);

        state.set(Register::Rsp, stack_base + 0x80);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, descriptor_heap_desc_ptr);
        state.set(Register::R8, 0);
        state.set(Register::R9, descriptor_heap_out_ptr);
        memory.write_u64(stack_base + 0x80, 0x1000_0005);
        runtime
            .dispatch_import(create_descriptor_heap_thunk, &mut state, &mut memory)
            .expect("dispatch CreateDescriptorHeap");
        let descriptor_heap_object = memory.read_u64(descriptor_heap_out_ptr).expect("descriptor heap object");
        assert_eq!(
            runtime.guest_object_kind(descriptor_heap_object).expect("descriptor heap kind"),
            GuestObjectKind::D3d12DescriptorHeap
        );
        let descriptor_heap_vtable = memory.read_u64(descriptor_heap_object).expect("descriptor heap vtable");
        let get_cpu_handle_thunk = memory
            .read_u64(descriptor_heap_vtable + 9 * 8)
            .expect("GetCPUDescriptorHandleForHeapStart thunk");
        state.set(Register::Rsp, stack_base + 0x98);
        state.set(Register::Rcx, descriptor_heap_object);
        memory.write_u64(stack_base + 0x98, 0x1000_0006);
        runtime
            .dispatch_import(get_cpu_handle_thunk, &mut state, &mut memory)
            .expect("dispatch GetCPUDescriptorHandleForHeapStart");
        let rtv_handle = state.get(Register::Rax);

        let get_buffer_thunk = memory.read_u64(swapchain_vtable + 9 * 8).expect("GetBuffer thunk");
        state.set(Register::Rsp, stack_base + 0xB0);
        state.set(Register::Rcx, swapchain_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, backbuffer_out_ptr);
        memory.write_u64(stack_base + 0xB0, 0x1000_0007);
        runtime
            .dispatch_import(get_buffer_thunk, &mut state, &mut memory)
            .expect("dispatch GetBuffer");
        let backbuffer_object = memory.read_u64(backbuffer_out_ptr).expect("backbuffer object");
        assert_eq!(runtime.guest_object_kind(backbuffer_object).expect("backbuffer kind"), GuestObjectKind::D3d12Resource);

        state.set(Register::Rsp, stack_base + 0xC8);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, backbuffer_object);
        state.set(Register::R8, 0);
        state.set(Register::R9, rtv_handle);
        memory.write_u64(stack_base + 0xC8, 0x1000_0008);
        runtime
            .dispatch_import(create_rtv_thunk, &mut state, &mut memory)
            .expect("dispatch CreateRenderTargetView");

        state.set(Register::Rsp, stack_base + 0xE0);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, allocator_out_ptr);
        memory.write_u64(stack_base + 0xE0, 0x1000_0009);
        runtime
            .dispatch_import(create_allocator_thunk, &mut state, &mut memory)
            .expect("dispatch CreateCommandAllocator");
        let allocator_object = memory.read_u64(allocator_out_ptr).expect("allocator object");
        assert_eq!(
            runtime.guest_object_kind(allocator_object).expect("allocator kind"),
            GuestObjectKind::D3d12CommandAllocator
        );

        state.set(Register::Rsp, stack_base + 0x100);
        state.set(Register::Rcx, device_object);
        state.set(Register::Rdx, 0);
        state.set(Register::R8, 0);
        state.set(Register::R9, allocator_object);
        memory.write_u64(stack_base + 0x100, 0x1000_000a);
        memory.write_u64(stack_base + 0x100 + 0x28, 0);
        memory.write_u64(stack_base + 0x100 + 0x38, command_list_out_ptr);
        runtime
            .dispatch_import(create_command_list_thunk, &mut state, &mut memory)
            .expect("dispatch CreateCommandList");
        let command_list_object = memory.read_u64(command_list_out_ptr).expect("command list object");
        assert_eq!(
            runtime.guest_object_kind(command_list_object).expect("command list kind"),
            GuestObjectKind::D3d12GraphicsCommandList
        );

        let command_list_vtable = memory.read_u64(command_list_object).expect("command list vtable");
        let resource_barrier_thunk = memory
            .read_u64(command_list_vtable + 26 * 8)
            .expect("ResourceBarrier thunk");
        let clear_rtv_thunk = memory
            .read_u64(command_list_vtable + 48 * 8)
            .expect("ClearRenderTargetView thunk");
        let draw_instanced_thunk = memory
            .read_u64(command_list_vtable + 12 * 8)
            .expect("DrawInstanced thunk");
        let close_thunk = memory
            .read_u64(command_list_vtable + 9 * 8)
            .expect("Close thunk");

        write_u32(&mut memory, first_barrier_ptr, 0);
        memory.write_u64(first_barrier_ptr + 8, backbuffer_object);
        write_u32(&mut memory, first_barrier_ptr + 16, 0);
        write_u32(&mut memory, first_barrier_ptr + 20, 0);
        write_u32(&mut memory, first_barrier_ptr + 24, 0x4);
        state.set(Register::Rsp, stack_base + 0x120);
        state.set(Register::Rcx, command_list_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, first_barrier_ptr);
        memory.write_u64(stack_base + 0x120, 0x1000_000b);
        runtime
            .dispatch_import(resource_barrier_thunk, &mut state, &mut memory)
            .expect("dispatch ResourceBarrier to render target");

        state.set(Register::Rsp, stack_base + 0x138);
        state.set(Register::Rcx, command_list_object);
        state.set(Register::Rdx, rtv_handle);
        state.set(Register::R8, 0);
        state.set(Register::R9, 0);
        memory.write_u64(stack_base + 0x138, 0x1000_000c);
        runtime
            .dispatch_import(clear_rtv_thunk, &mut state, &mut memory)
            .expect("dispatch ClearRenderTargetView");

        state.set(Register::Rsp, stack_base + 0x150);
        state.set(Register::Rcx, command_list_object);
        state.set(Register::Rdx, 3);
        state.set(Register::R8, 2);
        state.set(Register::R9, 0);
        memory.write_u64(stack_base + 0x150, 0x1000_000d);
        write_u32(&mut memory, stack_base + 0x150 + 0x28, 0);
        runtime
            .dispatch_import(draw_instanced_thunk, &mut state, &mut memory)
            .expect("dispatch DrawInstanced");

        write_u32(&mut memory, second_barrier_ptr, 0);
        memory.write_u64(second_barrier_ptr + 8, backbuffer_object);
        write_u32(&mut memory, second_barrier_ptr + 16, 0);
        write_u32(&mut memory, second_barrier_ptr + 20, 0x4);
        write_u32(&mut memory, second_barrier_ptr + 24, 0);
        state.set(Register::Rsp, stack_base + 0x168);
        state.set(Register::Rcx, command_list_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, second_barrier_ptr);
        memory.write_u64(stack_base + 0x168, 0x1000_000e);
        runtime
            .dispatch_import(resource_barrier_thunk, &mut state, &mut memory)
            .expect("dispatch ResourceBarrier to present");

        state.set(Register::Rsp, stack_base + 0x180);
        state.set(Register::Rcx, command_list_object);
        memory.write_u64(stack_base + 0x180, 0x1000_000f);
        runtime
            .dispatch_import(close_thunk, &mut state, &mut memory)
            .expect("dispatch Close");
        assert_eq!(state.get(Register::Rax), 0);

        let queue_vtable = memory.read_u64(queue_object).expect("queue vtable");
        let execute_thunk = memory
            .read_u64(queue_vtable + 10 * 8)
            .expect("ExecuteCommandLists thunk");
        memory.write_u64(command_list_array_ptr, command_list_object);
        state.set(Register::Rsp, stack_base + 0x198);
        state.set(Register::Rcx, queue_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, command_list_array_ptr);
        memory.write_u64(stack_base + 0x198, 0x1000_0010);
        runtime
            .dispatch_import(execute_thunk, &mut state, &mut memory)
            .expect("dispatch ExecuteCommandLists");
        assert_eq!(state.get(Register::Rax), 0);

        let present_thunk = memory.read_u64(swapchain_vtable + 8 * 8).expect("Present thunk");
        state.set(Register::Rsp, stack_base + 0x1b0);
        state.set(Register::Rcx, swapchain_object);
        state.set(Register::Rdx, 1);
        state.set(Register::R8, 0);
        memory.write_u64(stack_base + 0x1b0, 0x1000_0011);
        runtime
            .dispatch_import(present_thunk, &mut state, &mut memory)
            .expect("dispatch Present");
        assert_eq!(state.get(Register::Rax), 0);
        assert_eq!(runtime.gfx_frames.len(), 1);
        assert_eq!(runtime.gfx_frames[0].scene_id, "pe-runtime-d3d12");

        assert!(runtime.trace_events.iter().any(|event| event.call_id == "IDXGIFactory2::CreateSwapChainForHwnd"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "IDXGISwapChain::ResizeBuffers"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "IDXGISwapChain::GetBuffer"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12Device::CreateDescriptorHeap"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12DescriptorHeap::GetCPUDescriptorHandleForHeapStart"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12Device::CreateRenderTargetView"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12Device::CreateCommandAllocator"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12Device::CreateCommandList"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12GraphicsCommandList::ResourceBarrier"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12GraphicsCommandList::ClearRenderTargetView"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12GraphicsCommandList::DrawInstanced"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12GraphicsCommandList::Close"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "ID3D12CommandQueue::ExecuteCommandLists"));
        assert!(runtime.trace_events.iter().any(|event| event.call_id == "IDXGISwapChain::Present"));
    }

    #[test]
    fn pe_runtime_live_input_enqueues_held_and_tapped_key_transitions() {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), "live-input", GeArch::X64, "win11-23h2")
            .expect("create ge");
        let (host_session, pe_session) = crate::live::new_live_session();
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), Some(pe_session), None);
        let device_id = runtime
            .live_keyboard_device
            .clone()
            .expect("live keyboard device registered");

        runtime.user32.register_class_ex_w("LiveInputTestWindow");
        let hwnd = runtime
            .user32
            .create_window_ex_w(
                "LiveInputTestWindow",
                "Live Input Test",
                320,
                240,
                true,
                false,
                None,
                1,
            )
            .expect("create window");
        while runtime.user32.get_message_w().is_some() {}

        host_session
            .input_tx
            .send(LiveInputEvent::KeyDown {
                scancode: 0x1e,
                shift: false,
                altgr: false,
            })
            .expect("send held-left keydown");
        runtime.poll_live_input().expect("poll held-left keydown");

        let held_key_down = runtime.user32.get_message_w().expect("held keydown message");
        assert_eq!(held_key_down.hwnd, Some(hwnd));
        assert_eq!(held_key_down.kind, MessageKind::KeyDown);
        assert_eq!(held_key_down.lparam, 0x1e);
        assert_eq!(held_key_down.device_id.as_deref(), Some(device_id.as_str()));
        assert!(runtime.user32.get_message_w().is_none());

        host_session
            .input_tx
            .send(LiveInputEvent::KeyUp {
                scancode: 0x1e,
                shift: false,
                altgr: false,
            })
            .expect("send held-left keyup");
        host_session
            .input_tx
            .send(LiveInputEvent::KeyDown {
                scancode: 0x1c,
                shift: false,
                altgr: false,
            })
            .expect("send enter keydown");
        host_session
            .input_tx
            .send(LiveInputEvent::KeyUp {
                scancode: 0x1c,
                shift: false,
                altgr: false,
            })
            .expect("send enter keyup");
        runtime.poll_live_input().expect("poll release and tap events");

        let held_key_up = runtime.user32.get_message_w().expect("held keyup message");
        let tap_key_down = runtime.user32.get_message_w().expect("tap keydown message");
        let tap_key_up = runtime.user32.get_message_w().expect("tap keyup message");

        assert_eq!(held_key_up.kind, MessageKind::KeyUp);
        assert_eq!(held_key_up.lparam, 0x1e);
        assert_eq!(held_key_up.device_id.as_deref(), Some(device_id.as_str()));
        assert_eq!(tap_key_down.kind, MessageKind::KeyDown);
        assert_eq!(tap_key_down.lparam, 0x1c);
        assert_eq!(tap_key_down.device_id.as_deref(), Some(device_id.as_str()));
        assert_eq!(tap_key_up.kind, MessageKind::KeyUp);
        assert_eq!(tap_key_up.lparam, 0x1c);
        assert_eq!(tap_key_up.device_id.as_deref(), Some(device_id.as_str()));
        assert!(runtime.user32.get_message_w().is_none());
    }
}

fn read_d3d12_command_queue_desc(memory: &MemoryImage, address: u64) -> AppResult<(u32, i32, u32, u32)> {
    Ok((
        read_guest_u32(memory, address)?,
        read_guest_u32(memory, address + 4)? as i32,
        read_guest_u32(memory, address + 8)?,
        read_guest_u32(memory, address + 12)?,
    ))
}

fn read_d3d12_descriptor_heap_desc(
    memory: &MemoryImage,
    address: u64,
) -> AppResult<(DescriptorHeapType, usize, u32, u32)> {
    let heap_type = match read_guest_u32(memory, address)? {
        0 => DescriptorHeapType::CbvSrvUav,
        1 => DescriptorHeapType::Sampler,
        2 => DescriptorHeapType::Rtv,
        3 => DescriptorHeapType::Dsv,
        other => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported D3D12 descriptor heap type {other}"),
            ))
        }
    };
    Ok((
        heap_type,
        read_guest_u32(memory, address + 4)? as usize,
        read_guest_u32(memory, address + 8)?,
        read_guest_u32(memory, address + 12)?,
    ))
}

#[derive(Debug, Clone, Copy)]
struct D3d12TransitionBarrierDesc {
    resource_object: u64,
    subresource: u32,
    state_before: u32,
    state_after: u32,
}

fn read_d3d12_resource_barrier(memory: &MemoryImage, address: u64) -> AppResult<D3d12TransitionBarrierDesc> {
    let barrier_type = read_guest_u32(memory, address)?;
    if barrier_type != 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported D3D12 resource barrier type {barrier_type}"),
        ));
    }
    let resource_object = memory.read_u64(address + 8)?;
    if resource_object == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "D3D12 transition barriers must reference a non-null resource object",
        ));
    }
    Ok(D3d12TransitionBarrierDesc {
        resource_object,
        subresource: read_guest_u32(memory, address + 16)?,
        state_before: read_guest_u32(memory, address + 20)?,
        state_after: read_guest_u32(memory, address + 24)?,
    })
}

fn map_d3d12_resource_state(
    raw: u32,
    resource: GuestD3d12Resource,
    current: Option<ResourceState>,
    prefer_current_if_common: bool,
) -> AppResult<ResourceState> {
    match raw {
        0 => {
            if prefer_current_if_common {
                current.ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcD3dInvalidState,
                        "missing current resource state for D3D12 common/present barrier mapping",
                    )
                })
            } else if resource.swapchain_backbuffer {
                Ok(ResourceState::Present)
            } else {
                Ok(ResourceState::Common)
            }
        }
        0x0000_0004 => Ok(ResourceState::RenderTarget),
        0x0000_0008 => Ok(ResourceState::UnorderedAccess),
        0x0000_0010 => Ok(ResourceState::DepthWrite),
        0x0000_0400 => Ok(ResourceState::CopyDest),
        0x0000_0800 => Ok(ResourceState::CopySource),
        0x0000_0080 => Ok(ResourceState::PixelShaderResource),
        0x0000_0001 | 0x0000_0002 | 0x0000_0040 | 0x0000_0200 | 0x0000_0AC3 => {
            Ok(ResourceState::GenericRead)
        }
        other => Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported D3D12 resource state {other:#x}"),
        )),
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

fn supported_d3d12_feature_level(device_info: &crate::d3d12::D3d12DeviceInfo) -> u32 {
    if device_info.features.mesh_shaders {
        D3D_FEATURE_LEVEL_12_2
    } else {
        D3D_FEATURE_LEVEL_12_1
    }
}

fn supported_d3d12_shader_model(device_info: &crate::d3d12::D3d12DeviceInfo) -> u32 {
    if device_info.features.mesh_shaders {
        D3D_SHADER_MODEL_6_6
    } else {
        D3D_SHADER_MODEL_6_5
    }
}

fn write_d3d12_feature_support(
    memory: &mut MemoryImage,
    feature: u32,
    address: u64,
    size: usize,
    device_info: &crate::d3d12::D3d12DeviceInfo,
) -> AppResult<Option<BTreeMap<String, Value>>> {
    let capabilities = &device_info.features;
    match feature {
        D3D12_FEATURE_D3D12_OPTIONS => {
            if size < 60 {
                return Ok(None);
            }
            write_u32(memory, address, bool_to_u32(false));
            write_u32(memory, address + 4, bool_to_u32(true));
            write_u32(memory, address + 8, 0);
            write_u32(memory, address + 12, D3D12_TILED_RESOURCES_TIER_2);
            write_u32(memory, address + 16, D3D12_RESOURCE_BINDING_TIER_3);
            write_u32(memory, address + 20, bool_to_u32(false));
            write_u32(memory, address + 24, bool_to_u32(true));
            write_u32(memory, address + 28, bool_to_u32(false));
            write_u32(memory, address + 32, D3D12_CONSERVATIVE_RASTERIZATION_TIER_1);
            write_u32(memory, address + 36, 40);
            write_u32(memory, address + 40, bool_to_u32(true));
            write_u32(memory, address + 44, 0);
            write_u32(memory, address + 48, bool_to_u32(false));
            write_u32(memory, address + 52, bool_to_u32(false));
            write_u32(memory, address + 56, D3D12_RESOURCE_HEAP_TIER_2);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("D3D12_OPTIONS")),
                ("resource_binding_tier".to_string(), json!(D3D12_RESOURCE_BINDING_TIER_3)),
                ("resource_heap_tier".to_string(), json!(D3D12_RESOURCE_HEAP_TIER_2)),
            ])))
        }
        D3D12_FEATURE_FEATURE_LEVELS => {
            if size < 24 {
                return Ok(None);
            }
            let count = read_guest_u32(memory, address)? as usize;
            let levels_ptr = read_guest_u64(memory, address + 8)?;
            let max_supported = match select_supported_d3d12_feature_level(
                memory,
                levels_ptr,
                count,
                supported_d3d12_feature_level(device_info),
            )? {
                Some(level) => level,
                None => return Ok(None),
            };
            write_u32(memory, address + 16, max_supported);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("FEATURE_LEVELS")),
                (
                    "max_feature_level".to_string(),
                    json!(format!("0x{max_supported:04x}")),
                ),
            ])))
        }
        D3D12_FEATURE_SHADER_MODEL => {
            if size < 4 {
                return Ok(None);
            }
            let requested = read_guest_u32(memory, address)?;
            if requested != 0 && !is_known_shader_model(requested) {
                return Ok(None);
            }
            let supported = supported_d3d12_shader_model(device_info);
            let highest = if requested == 0 { supported } else { requested.min(supported) };
            write_u32(memory, address, highest);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("SHADER_MODEL")),
                ("highest_shader_model".to_string(), json!(format!("0x{highest:02x}"))),
            ])))
        }
        D3D12_FEATURE_ROOT_SIGNATURE => {
            if size < 4 {
                return Ok(None);
            }
            let requested = read_guest_u32(memory, address)?;
            if requested != 0 && requested < D3D12_ROOT_SIGNATURE_VERSION_1 {
                return Ok(None);
            }
            let highest = if requested == 0 {
                D3D12_ROOT_SIGNATURE_VERSION_1_1
            } else {
                requested.min(D3D12_ROOT_SIGNATURE_VERSION_1_1)
            };
            write_u32(memory, address, highest);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("ROOT_SIGNATURE")),
                ("highest_version".to_string(), json!(highest)),
            ])))
        }
        D3D12_FEATURE_ARCHITECTURE1 => {
            if size < 20 {
                return Ok(None);
            }
            let node_index = read_guest_u32(memory, address)?;
            write_u32(memory, address + 4, bool_to_u32(capabilities.memoryless_render_targets));
            write_u32(memory, address + 8, bool_to_u32(capabilities.unified_memory));
            write_u32(memory, address + 12, bool_to_u32(capabilities.unified_memory));
            write_u32(memory, address + 16, bool_to_u32(false));
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("ARCHITECTURE1")),
                ("node_index".to_string(), json!(node_index)),
                ("uma".to_string(), json!(capabilities.unified_memory)),
            ])))
        }
        D3D12_FEATURE_D3D12_OPTIONS5 => {
            if size < 12 {
                return Ok(None);
            }
            write_u32(memory, address, bool_to_u32(false));
            write_u32(memory, address + 4, D3D12_RENDER_PASS_TIER_1);
            write_u32(memory, address + 8, D3D12_RAYTRACING_TIER_NOT_SUPPORTED);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("D3D12_OPTIONS5")),
                ("render_pass_tier".to_string(), json!(D3D12_RENDER_PASS_TIER_1)),
                ("raytracing_tier".to_string(), json!(D3D12_RAYTRACING_TIER_NOT_SUPPORTED)),
            ])))
        }
        D3D12_FEATURE_D3D12_OPTIONS7 => {
            if size < 8 {
                return Ok(None);
            }
            let mesh_shader_tier = if capabilities.mesh_shaders {
                D3D12_MESH_SHADER_TIER_1
            } else {
                D3D12_MESH_SHADER_TIER_NOT_SUPPORTED
            };
            write_u32(memory, address, mesh_shader_tier);
            write_u32(memory, address + 4, D3D12_SAMPLER_FEEDBACK_TIER_NOT_SUPPORTED);
            Ok(Some(BTreeMap::from([
                ("feature".to_string(), json!("D3D12_OPTIONS7")),
                ("mesh_shader_tier".to_string(), json!(mesh_shader_tier)),
            ])))
        }
        _ => Ok(None),
    }
}

fn select_supported_d3d12_feature_level(
    memory: &MemoryImage,
    address: u64,
    count: usize,
    supported: u32,
) -> AppResult<Option<u32>> {
    if count == 0 {
        return Ok(Some(supported));
    }
    if address == 0 {
        return Ok(None);
    }
    let mut best = 0;
    for index in 0..count as u64 {
        let requested = read_guest_u32(memory, address + index * 4)?;
        if !is_known_d3d12_feature_level(requested) {
            return Ok(None);
        }
        if requested <= supported && requested > best {
            best = requested;
        }
    }
    Ok(Some(best))
}

fn is_known_d3d12_feature_level(value: u32) -> bool {
    matches!(
        value,
        D3D_FEATURE_LEVEL_11_0
            | D3D_FEATURE_LEVEL_11_1
            | D3D_FEATURE_LEVEL_12_0
            | D3D_FEATURE_LEVEL_12_1
            | D3D_FEATURE_LEVEL_12_2
    )
}

fn is_known_shader_model(value: u32) -> bool {
    value == 0x51 || (0x60..=0x69).contains(&value)
}

fn bool_to_u32(value: bool) -> u32 {
    if value { 1 } else { 0 }
}

fn build_dxgi_adapter_desc_bytes(
    adapter: &crate::d3d12::AdapterInfo,
    unified_memory: bool,
    extended: bool,
) -> Vec<u8> {
    let total_len = if extended { 308 } else { 304 };
    let mut bytes = vec![0_u8; total_len];
    for (index, unit) in adapter
        .name
        .encode_utf16()
        .take(DXGI_ADAPTER_DESC_DESCRIPTION_CHARS.saturating_sub(1))
        .enumerate()
    {
        let offset = index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    bytes[256..260].copy_from_slice(&adapter.vendor_id.to_le_bytes());
    bytes[260..264].copy_from_slice(&adapter.device_id.to_le_bytes());
    bytes[264..268].copy_from_slice(&0_u32.to_le_bytes());
    bytes[268..272].copy_from_slice(&1_u32.to_le_bytes());
    let dedicated_video_memory = if unified_memory { 0_u64 } else { 8 * 1024 * 1024 * 1024 };
    let dedicated_system_memory = 0_u64;
    let shared_system_memory = if unified_memory {
        16 * 1024 * 1024 * 1024_u64
    } else {
        2 * 1024 * 1024 * 1024_u64
    };
    bytes[272..280].copy_from_slice(&dedicated_video_memory.to_le_bytes());
    bytes[280..288].copy_from_slice(&dedicated_system_memory.to_le_bytes());
    bytes[288..296].copy_from_slice(&shared_system_memory.to_le_bytes());
    bytes[296..300].copy_from_slice(&adapter.device_id.to_le_bytes());
    bytes[300..304].copy_from_slice(&adapter.vendor_id.to_le_bytes());
    if extended {
        bytes[304..308].copy_from_slice(&0_u32.to_le_bytes());
    }
    bytes
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

fn read_swapchain_desc1(memory: &MemoryImage, address: u64) -> AppResult<SwapchainDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "swapchain descriptor pointer must not be null",
        ));
    }
    let width = read_guest_u32(memory, address)?;
    let height = read_guest_u32(memory, address + 4)?;
    let format = map_dxgi_format(read_guest_u32(memory, address + 8)?)?;
    let sample_count = read_guest_u32(memory, address + 16)?;
    let sample_quality = read_guest_u32(memory, address + 20)?;
    let buffer_count = read_guest_u32(memory, address + 28)?;
    if sample_count != 1 || sample_quality != 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!(
                "only single-sample DXGI swapchain desc1 values are currently supported (sample_count={sample_count}, sample_quality={sample_quality})"
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

fn read_d3d11_buffer_usage(memory: &MemoryImage, address: u64) -> AppResult<(String, ResourceUsageHint)> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "buffer descriptor pointer must not be null",
        ));
    }
    let usage = read_guest_u32(memory, address + 4)?;
    let bind_flags = read_guest_u32(memory, address + 8)?;
    let cpu_access_flags = read_guest_u32(memory, address + 12)?;
    let role = if bind_flags & 0x4 != 0 {
        BufferRole::Constant
    } else if bind_flags & 0x1 != 0 {
        BufferRole::Vertex
    } else if bind_flags & 0x2 != 0 {
        BufferRole::Index
    } else {
        BufferRole::Generic
    };
    let cpu_write_frequent = usage == 2 || (cpu_access_flags & 0x0001_0000) != 0;
    let label = match (role, cpu_write_frequent) {
        (BufferRole::Constant, true) => "guest-dynamic-constant-buffer",
        (BufferRole::Constant, false) => "guest-constant-buffer",
        (BufferRole::Vertex, true) => "guest-dynamic-vertex-buffer",
        (BufferRole::Vertex, false) => "guest-vertex-buffer",
        (BufferRole::Index, true) => "guest-dynamic-index-buffer",
        (BufferRole::Index, false) => "guest-index-buffer",
        (BufferRole::Generic, true) => "guest-dynamic-buffer",
        (BufferRole::Generic, false) => "guest-buffer",
    };
    Ok((
        label.to_string(),
        ResourceUsageHint::Buffer {
            role,
            cpu_write_frequent,
        },
    ))
}

struct GuestTexture2dDesc {
    width: u32,
    height: u32,
    format: DxgiFormat,
    byte_width: usize,
    label: String,
    usage_hint: ResourceUsageHint,
}

fn read_d3d11_texture2d_desc(memory: &MemoryImage, address: u64) -> AppResult<GuestTexture2dDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "texture2d descriptor pointer must not be null",
        ));
    }
    let width = read_guest_u32(memory, address)?;
    let height = read_guest_u32(memory, address + 4)?;
    let mip_levels = read_guest_u32(memory, address + 8)?;
    let array_size = read_guest_u32(memory, address + 12)?;
    let format = map_dxgi_format(read_guest_u32(memory, address + 16)?)?;
    let sample_count = read_guest_u32(memory, address + 20)?;
    let usage = read_guest_u32(memory, address + 28)?;
    let bind_flags = read_guest_u32(memory, address + 32)?;
    let cpu_access_flags = read_guest_u32(memory, address + 36)?;
    if width == 0 || height == 0 || mip_levels > 1 || array_size != 1 || sample_count != 1 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "only simple 2D textures with one mip, one array slice, and sample count 1 are supported",
        ));
    }
    let cpu_write_frequent = usage == 2 || (cpu_access_flags & 0x0001_0000) != 0;
    let render_target = (bind_flags & 0x20) != 0;
    let depth_stencil = (bind_flags & 0x40) != 0;
    let sampled = (bind_flags & 0x8) != 0;
    let label = if depth_stencil {
        "guest-depth-texture"
    } else if render_target && sampled {
        "guest-renderable-sampled-texture"
    } else if render_target {
        "guest-render-target-texture"
    } else if sampled && cpu_write_frequent {
        "guest-streamed-shader-resource-texture"
    } else if sampled {
        "guest-shader-resource-texture"
    } else {
        "guest-texture2d"
    };
    let usage_hint = if depth_stencil {
        ResourceUsageHint::Texture {
            sampled,
            render_target,
            depth_stencil: true,
            cpu_write_frequent,
        }
    } else {
        ResourceUsageHint::Texture {
            sampled,
            render_target,
            depth_stencil: false,
            cpu_write_frequent,
        }
    };
    Ok(GuestTexture2dDesc {
        width,
        height,
        format,
        byte_width: width as usize * height as usize * 4,
        label: label.to_string(),
        usage_hint,
    })
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

fn read_d3d11_blend_desc(memory: &MemoryImage, address: u64) -> AppResult<BlendStateDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "blend state descriptor pointer must not be null",
        ));
    }
    Ok(BlendStateDesc {
        alpha_to_coverage: read_guest_u32(memory, address)? != 0,
        blend_enable: read_guest_u32(memory, address + 8)? != 0,
    })
}

fn read_d3d11_depth_stencil_desc(memory: &MemoryImage, address: u64) -> AppResult<DepthStencilStateDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "depth-stencil descriptor pointer must not be null",
        ));
    }
    let depth_write_mask = read_guest_u32(memory, address + 4)?;
    if depth_write_mask > 1 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported depth write mask {depth_write_mask}"),
        ));
    }
    Ok(DepthStencilStateDesc {
        depth_enable: read_guest_u32(memory, address)? != 0,
        depth_write: depth_write_mask != 0,
    })
}

fn read_d3d11_rasterizer_desc(memory: &MemoryImage, address: u64) -> AppResult<RasterizerStateDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "rasterizer descriptor pointer must not be null",
        ));
    }
    let fill_mode = match read_guest_u32(memory, address)? {
        2 => "wireframe",
        3 => "solid",
        raw => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported fill mode {raw}"),
            ));
        }
    };
    let cull_mode = match read_guest_u32(memory, address + 4)? {
        1 => "none",
        2 => "front",
        3 => "back",
        raw => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported cull mode {raw}"),
            ));
        }
    };
    Ok(RasterizerStateDesc {
        fill_mode: fill_mode.to_string(),
        cull_mode: cull_mode.to_string(),
    })
}

fn read_d3d11_sampler_desc(memory: &MemoryImage, address: u64) -> AppResult<SamplerStateDesc> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "sampler descriptor pointer must not be null",
        ));
    }
    let filter = match read_guest_u32(memory, address)? {
        0 => crate::gfx::FilterMode::Point,
        21 => crate::gfx::FilterMode::Linear,
        raw => {
            return Err(AppError::new(
                ReasonCode::RcD3dInvalidState,
                format!("unsupported sampler filter {raw}"),
            ));
        }
    };
    let address_u = map_d3d11_texture_address_mode(read_guest_u32(memory, address + 4)?)?;
    let address_v = map_d3d11_texture_address_mode(read_guest_u32(memory, address + 8)?)?;
    Ok(SamplerStateDesc {
        filter,
        address_u,
        address_v,
    })
}

fn map_d3d11_texture_address_mode(value: u32) -> AppResult<String> {
    match value {
        1 => Ok("wrap".to_string()),
        3 => Ok("clamp".to_string()),
        raw => Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            format!("unsupported texture address mode {raw}"),
        )),
    }
}

fn read_d3d11_viewport(memory: &MemoryImage, address: u64) -> AppResult<Viewport> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "viewport pointer must not be null",
        ));
    }
    let width = read_guest_f32(memory, address + 8)?;
    let height = read_guest_f32(memory, address + 12)?;
    if width <= 0.0 || height <= 0.0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "viewport width and height must be positive",
        ));
    }
    Ok(Viewport {
        x: read_guest_f32(memory, address)?,
        y: read_guest_f32(memory, address + 4)?,
        width,
        height,
    })
}

fn read_d3d11_scissor_rect(memory: &MemoryImage, address: u64) -> AppResult<ScissorRect> {
    if address == 0 {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "scissor rect pointer must not be null",
        ));
    }
    let rect = ScissorRect {
        left: read_guest_i32(memory, address)?,
        top: read_guest_i32(memory, address + 4)?,
        right: read_guest_i32(memory, address + 8)?,
        bottom: read_guest_i32(memory, address + 12)?,
    };
    if rect.right <= rect.left || rect.bottom <= rect.top {
        return Err(AppError::new(
            ReasonCode::RcD3dInvalidState,
            "scissor rect must have positive width and height",
        ));
    }
    Ok(rect)
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

fn write_win32_msg(memory: &mut MemoryImage, address: u64, message: &Message) -> AppResult<()> {
    write_u32(memory, address, message.hwnd.unwrap_or(0));
    write_u32(memory, address + 4, message_id(message.kind));
    write_u32(memory, address + 8, message.wparam as u32);
    write_u32(memory, address + 12, message.lparam as u32);
    write_u32(memory, address + 16, 0);
    write_u32(memory, address + 20, 0);
    write_u32(memory, address + 24, 0);
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

fn read_win32_msg(memory: &MemoryImage, address: u64) -> AppResult<Message> {
    Ok(Message {
        hwnd: match read_u32(memory, address)? {
            0 => None,
            hwnd => Some(hwnd),
        },
        kind: message_kind(read_u32(memory, address + 4)?)?,
        wparam: read_u32(memory, address + 8)? as i64,
        lparam: read_u32(memory, address + 12)? as i32 as i64,
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

fn read_guest_i32(memory: &MemoryImage, address: u64) -> AppResult<i32> {
    Ok(i32::from_le_bytes([
        memory.read_u8(address)?,
        memory.read_u8(address + 1)?,
        memory.read_u8(address + 2)?,
        memory.read_u8(address + 3)?,
    ]))
}

fn read_guest_f32(memory: &MemoryImage, address: u64) -> AppResult<f32> {
    Ok(f32::from_bits(read_guest_u32(memory, address)?))
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

fn read_filetime(memory: &MemoryImage, address: u64) -> AppResult<u64> {
    let low = read_u32(memory, address)? as u64;
    let high = read_u32(memory, address + 4)? as u64;
    Ok(low | (high << 32))
}

fn read_guid_string(memory: &MemoryImage, address: u64) -> AppResult<String> {
    let data1 = read_u32(memory, address)?;
    let data2 = read_guest_u16(memory, address + 4)?;
    let data3 = read_guest_u16(memory, address + 6)?;
    let data4 = memory.read_bytes(address + 8, 8)?;
    Ok(format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        data1,
        data2,
        data3,
        data4[0],
        data4[1],
        data4[2],
        data4[3],
        data4[4],
        data4[5],
        data4[6],
        data4[7],
    ))
}

fn write_shell_link_clsid(memory: &mut MemoryImage, address: u64) {
    write_u32(memory, address, 0x0002_1401);
    memory.map_bytes(address + 4, &0_u16.to_le_bytes());
    memory.map_bytes(address + 6, &0_u16.to_le_bytes());
    memory.map_bytes(address + 8, &[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]);
}

fn is_shell_link_interface_iid(iid: &str) -> bool {
    iid.eq_ignore_ascii_case(IID_IUNKNOWN)
        || iid.eq_ignore_ascii_case(IID_ISHELLLINKW)
        || iid.eq_ignore_ascii_case(IID_IPERSIST)
        || iid.eq_ignore_ascii_case(IID_IPERSISTFILE)
}

fn current_guest_filetime_ticks(dtm: bool) -> u64 {
    if dtm {
        0
    } else {
        current_host_ticks_100ns()
    }
}

fn current_host_ticks_100ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos().div_euclid(100) as u64)
        .unwrap_or(0)
}

fn is_processor_feature_present(feature: u32) -> bool {
    match feature {
        0 => false,
        1 => false,
        2 => true,
        3 => true,
        6 => true,
        7 => false,
        8 => true,
        9 => true,
        10 => true,
        11 => true,
        12 => true,
        13 => true,
        14 => true,
        15 => true,
        17 => true,
        _ => false,
    }
}

fn read_optional_filetime(memory: &MemoryImage, address: u64) -> AppResult<Option<u64>> {
    if address == 0 {
        Ok(None)
    } else {
        Ok(Some(read_filetime(memory, address)?))
    }
}

fn write_filetime(memory: &mut MemoryImage, address: u64, ticks: u64) {
    write_u64(memory, address, ticks);
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

fn stack_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => STACK_BASE,
        GuestArch::X86 => X86_STACK_BASE,
    }
}

fn thunk_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => THUNK_BASE,
        GuestArch::X86 => X86_THUNK_BASE,
    }
}

fn data_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => CRT_DATA_BASE,
        GuestArch::X86 => X86_CRT_DATA_BASE,
    }
}

fn heap_base_for_arch(arch: GuestArch) -> u64 {
    match arch {
        GuestArch::X64 => CRT_HEAP_BASE,
        GuestArch::X86 => X86_CRT_HEAP_BASE,
    }
}

fn read_guest_pointer(memory: &MemoryImage, address: u64, arch: GuestArch) -> AppResult<u64> {
    match arch {
        GuestArch::X64 => memory.read_u64(address),
        GuestArch::X86 => Ok(read_u32(memory, address)? as u64),
    }
}

fn write_guest_pointer(memory: &mut MemoryImage, address: u64, value: u64, arch: GuestArch) -> AppResult<()> {
    match arch {
        GuestArch::X64 => {
            write_u64(memory, address, value);
            Ok(())
        }
        GuestArch::X86 => {
            let narrowed = u32::try_from(value).map_err(|_| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("guest pointer {value:#x} does not fit in x86 address space"),
                )
            })?;
            write_u32(memory, address, narrowed);
            Ok(())
        }
    }
}

fn guest_call_arg(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<u64> {
    match state.arch {
        GuestArch::X64 => match index {
            0 => Ok(state.get(Register::Rcx)),
            1 => Ok(state.get(Register::Rdx)),
            2 => Ok(state.get(Register::R8)),
            3 => Ok(state.get(Register::R9)),
            _ => read_guest_pointer(memory, state.get(Register::Rsp) + 0x20 + ((index - 4) as u64 * 8), GuestArch::X64),
        },
        GuestArch::X86 => read_guest_pointer(memory, state.get(Register::Rsp) + (index as u64 * 4), GuestArch::X86),
    }
}

fn guest_call_arg_u32(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<u32> {
    Ok(guest_call_arg(state, memory, index)? as u32)
}

fn write_utf16_api_string(memory: &mut MemoryImage, buffer: u64, size: u32, value: &str) -> AppResult<u32> {
    let units = value.encode_utf16().collect::<Vec<_>>();
    let required_without_nul = units.len() as u32;
    let required_with_nul = required_without_nul + 1;
    if buffer != 0 && size != 0 {
        let copy_units = units.len().min(size.saturating_sub(1) as usize);
        let mut bytes = Vec::with_capacity((copy_units + 1) * 2);
        for unit in units.iter().take(copy_units) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        memory.map_bytes(buffer, &bytes);
    }
    Ok(if size <= required_without_nul {
        required_with_nul
    } else {
        required_without_nul
    })
}

fn write_utf16_fixed_buffer(memory: &mut MemoryImage, buffer: u64, len: usize, value: &str) {
    let mut bytes = vec![0_u8; len * 2];
    for (index, unit) in value.encode_utf16().take(len.saturating_sub(1)).enumerate() {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    memory.map_bytes(buffer, &bytes);
}

fn write_find_data_w(memory: &mut MemoryImage, address: u64, data: &FindData) -> AppResult<()> {
    write_u32(memory, address, file_attributes_mask(&data.attributes));
    write_filetime(memory, address + 4, data.creation_time_ticks);
    write_filetime(memory, address + 12, data.last_access_time_ticks);
    write_filetime(memory, address + 20, data.last_write_time_ticks);
    write_u32(memory, address + 28, (data.size >> 32) as u32);
    write_u32(memory, address + 32, data.size as u32);
    write_u32(memory, address + 36, 0);
    write_u32(memory, address + 40, 0);
    write_utf16_fixed_buffer(memory, address + 44, WIN32_FIND_DATAW_FILE_NAME_CHARS, &data.file_name);
    write_utf16_fixed_buffer(
        memory,
        address + 44 + (WIN32_FIND_DATAW_FILE_NAME_CHARS * 2) as u64,
        WIN32_FIND_DATAW_ALT_FILE_NAME_CHARS,
        "",
    );
    Ok(())
}

fn message_box_response(style: u32) -> i32 {
    match style & 0x0000_000f {
        0x0000_0000 => IDOK,
        0x0000_0001 => IDOK,
        0x0000_0002 => IDIGNORE,
        0x0000_0003 => IDYES,
        0x0000_0004 => IDYES,
        0x0000_0005 => IDRETRY,
        0x0000_0006 => IDCONTINUE,
        _ => IDCANCEL,
    }
}

fn format_wsprintf_w(
    state: &CpuState,
    memory: &MemoryImage,
    format_string: &str,
    first_arg_index: usize,
) -> AppResult<String> {
    let chars = format_string.chars().collect::<Vec<_>>();
    let mut rendered = String::new();
    let mut cursor = 0usize;
    let mut arg_index = first_arg_index;
    while cursor < chars.len() {
        if chars[cursor] != '%' {
            rendered.push(chars[cursor]);
            cursor += 1;
            continue;
        }
        cursor += 1;
        if cursor < chars.len() && chars[cursor] == '%' {
            rendered.push('%');
            cursor += 1;
            continue;
        }
        while cursor < chars.len() && matches!(chars[cursor], '-' | '+' | ' ' | '#' | '0') {
            cursor += 1;
        }
        while cursor < chars.len() && chars[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor < chars.len() && chars[cursor] == '.' {
            cursor += 1;
            while cursor < chars.len() && chars[cursor].is_ascii_digit() {
                cursor += 1;
            }
        }
        let mut wide_modifier = false;
        if cursor < chars.len() && matches!(chars[cursor], 'l' | 'w') {
            wide_modifier = true;
            cursor += 1;
            if cursor < chars.len() && chars[cursor] == 'l' {
                cursor += 1;
            }
        }
        let specifier = *chars.get(cursor).ok_or_else(|| {
            AppError::new(ReasonCode::RcUnimplInsn, "unterminated wsprintfW format specifier")
        })?;
        cursor += 1;
        let raw = guest_call_arg(state, memory, arg_index)?;
        arg_index += 1;
        match specifier {
            'd' | 'i' => rendered.push_str(&(raw as u32 as i32).to_string()),
            'u' => rendered.push_str(&(raw as u32).to_string()),
            'x' => rendered.push_str(&format!("{:x}", raw as u32)),
            'X' => rendered.push_str(&format!("{:X}", raw as u32)),
            'p' => rendered.push_str(&format!("{raw:#x}")),
            'c' | 'C' => {
                rendered.push(char::from_u32((raw as u32) & 0xffff).unwrap_or('?'));
            }
            's' => {
                if raw != 0 {
                    rendered.push_str(&read_utf16_string(memory, raw)?);
                }
            }
            'S' => {
                if raw != 0 {
                    if wide_modifier {
                        rendered.push_str(&read_utf16_string(memory, raw)?);
                    } else {
                        rendered.push_str(&read_c_string(memory, raw)?);
                    }
                }
            }
            other => {
                return Err(AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unsupported wsprintfW format specifier %{other}"),
                ))
            }
        }
    }
    Ok(rendered)
}

fn resolve_full_guest_path(current_directory: &str, path: &str) -> String {
    normalize_windows_path(&resolve_guest_path(current_directory, path))
}

fn resolve_guest_path(current_directory: &str, path: &str) -> String {
    if path.is_empty() {
        return current_directory.to_string();
    }
    if path.starts_with("\\\\") {
        return path.to_string();
    }
    if let Some(drive_prefix) = windows_drive_prefix(path) {
        let remainder = &path[2..];
        if remainder.is_empty() {
            return format!("{drive_prefix}\\");
        }
        if remainder.starts_with(['\\', '/']) {
            let trimmed = remainder.trim_start_matches(['\\', '/']);
            return if trimmed.is_empty() {
                format!("{drive_prefix}\\")
            } else {
                format!("{drive_prefix}\\{trimmed}")
            };
        }
        let base = drive_relative_base(current_directory, drive_prefix);
        return if remainder.is_empty() {
            base
        } else {
            format!("{}\\{}", base.trim_end_matches(['\\', '/']), remainder)
        };
    }
    if path.starts_with(['\\', '/']) {
        let drive_prefix = windows_drive_prefix(current_directory).unwrap_or("C:");
        let trimmed = path.trim_start_matches(['\\', '/']);
        return if trimmed.is_empty() {
            format!("{drive_prefix}\\")
        } else {
            format!("{drive_prefix}\\{trimmed}")
        };
    }
    let base = current_directory.trim_end_matches(['\\', '/']);
    if base.is_empty() {
        format!("C:\\{}", path.trim_start_matches(['\\', '/']))
    } else {
        format!("{}\\{}", base, path.trim_start_matches(['\\', '/']))
    }
}

fn normalize_windows_path(path: &str) -> String {
    let normalized = path.replace('/', "\\");
    if normalized.starts_with("\\\\") {
        return normalize_unc_windows_path(&normalized);
    }
    if let Some(drive_prefix) = windows_drive_prefix(&normalized) {
        let mut segments = Vec::new();
        for segment in normalized[2..].split('\\') {
            match segment {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                _ => segments.push(segment),
            }
        }
        return if segments.is_empty() {
            format!("{drive_prefix}\\")
        } else {
            format!("{drive_prefix}\\{}", segments.join("\\"))
        };
    }
    normalized
}

fn normalize_unc_windows_path(path: &str) -> String {
    let mut parts = path.trim_start_matches(['\\', '/']).split(['\\', '/']).filter(|part| !part.is_empty());
    let Some(server) = parts.next() else {
        return "\\\\".to_string();
    };
    let Some(share) = parts.next() else {
        return format!("\\\\{server}");
    };
    let mut segments = Vec::new();
    for segment in parts {
        match segment {
            "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    if segments.is_empty() {
        format!("\\\\{server}\\{share}")
    } else {
        format!("\\\\{server}\\{share}\\{}", segments.join("\\"))
    }
}

fn initial_guest_current_directory(ge: &GameEnvironment, host_cwd: &Path, guest_program_path: &str) -> String {
    let candidate = ge.normalize_host_path(host_cwd);
    if is_windows_absolute_path(&candidate) {
        if let Some(drive_prefix) = windows_drive_prefix(&candidate) {
            let drive = &drive_prefix[..1];
            if ge
                .active_drive_mappings()
                .iter()
                .any(|mapping| mapping.drive.eq_ignore_ascii_case(drive))
            {
                return candidate;
            }
        }
    }
    windows_parent_path(guest_program_path).unwrap_or_else(|| "C:\\".to_string())
}

fn drive_relative_base(current_directory: &str, drive_prefix: &str) -> String {
    if let Some(current_drive) = windows_drive_prefix(current_directory) {
        if current_drive.eq_ignore_ascii_case(drive_prefix) {
            let trimmed = current_directory.trim_end_matches(['\\', '/']);
            return if trimmed.len() <= 2 {
                format!("{drive_prefix}\\")
            } else {
                trimmed.to_string()
            };
        }
    }
    format!("{drive_prefix}\\")
}

fn windows_parent_path(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    if let Some(drive_prefix) = windows_drive_prefix(trimmed) {
        let remainder = &trimmed[2..];
        if remainder.is_empty() || remainder == "\\" {
            return Some(format!("{drive_prefix}\\"));
        }
    }
    let separator = trimmed.rfind(['\\', '/'])?;
    if separator == 2 && windows_drive_prefix(trimmed).is_some() {
        Some(trimmed[..=separator].to_string())
    } else {
        Some(trimmed[..separator].to_string())
    }
}

fn windows_file_part_offset(path: &str) -> Option<u64> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return None;
    }
    let component_start = match trimmed.rfind(['\\', '/']) {
        Some(index) => index + 1,
        None if windows_drive_prefix(trimmed).is_some() => return None,
        None => 0,
    };
    Some((path[..component_start].encode_utf16().count() * 2) as u64)
}

fn windows_drive_prefix(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some(&path[..2])
    } else {
        None
    }
}

fn normalize_module_name(module_name: &str) -> String {
    let module_name = module_name.replace('\\', "/");
    let file_name = Path::new(&module_name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(module_name.as_str())
        .trim();
    let normalized = file_name.to_ascii_lowercase();
    if normalized.is_empty() {
        String::new()
    } else if normalized.contains('.') {
        normalized
    } else {
        format!("{normalized}.dll")
    }
}

fn is_windows_absolute_path(path: &str) -> bool {
    path.starts_with("\\\\")
        || matches!(path.as_bytes(), [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic())
}

fn shell_special_folder_path(user_name: &str, raw_csidl: i32, guest_arch: GuestArch) -> Option<String> {
    let csidl = raw_csidl & 0x00ff;
    let user_root = format!("C:\\users\\{user_name}");
    let roaming = format!("{user_root}\\AppData\\Roaming");
    let local = format!("{user_root}\\AppData\\Local");
    let program_files = if guest_arch == GuestArch::X86 {
        "C:\\Program Files (x86)"
    } else {
        "C:\\Program Files"
    };
    let path = match csidl {
        CSIDL_DESKTOP | CSIDL_DESKTOPDIRECTORY => format!("{user_root}\\Desktop"),
        CSIDL_PROGRAMS => format!("{roaming}\\Microsoft\\Windows\\Start Menu\\Programs"),
        CSIDL_PERSONAL => format!("{user_root}\\Documents"),
        CSIDL_FAVORITES => format!("{user_root}\\Favorites"),
        CSIDL_STARTUP => format!("{roaming}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        CSIDL_RECENT => format!("{user_root}\\Recent"),
        CSIDL_SENDTO => format!("{user_root}\\AppData\\Roaming\\Microsoft\\Windows\\SendTo"),
        CSIDL_STARTMENU => format!("{roaming}\\Microsoft\\Windows\\Start Menu"),
        CSIDL_NETHOOD => format!("{roaming}\\Microsoft\\Windows\\Network Shortcuts"),
        CSIDL_FONTS => "C:\\Windows\\Fonts".to_string(),
        CSIDL_TEMPLATES => format!("{roaming}\\Microsoft\\Windows\\Templates"),
        CSIDL_APPDATA => roaming,
        CSIDL_LOCAL_APPDATA => local,
        CSIDL_INTERNET_CACHE => format!("{local}\\Microsoft\\Windows\\INetCache"),
        CSIDL_COOKIES => format!("{local}\\Microsoft\\Windows\\INetCookies"),
        CSIDL_HISTORY => format!("{local}\\Microsoft\\Windows\\History"),
        CSIDL_COMMON_APPDATA => "C:\\ProgramData".to_string(),
        CSIDL_WINDOWS => "C:\\Windows".to_string(),
        CSIDL_SYSTEM | CSIDL_SYSTEMX86 => "C:\\Windows\\System32".to_string(),
        CSIDL_PROGRAM_FILES => program_files.to_string(),
        CSIDL_MYPICTURES => format!("{user_root}\\Pictures"),
        CSIDL_PROFILE => user_root,
        CSIDL_PROGRAM_FILESX86 => "C:\\Program Files (x86)".to_string(),
        CSIDL_COMMON_TEMPLATES => "C:\\ProgramData\\Microsoft\\Windows\\Templates".to_string(),
        CSIDL_COMMON_DOCUMENTS => "C:\\Users\\Public\\Documents".to_string(),
        CSIDL_COMMON_ADMINTOOLS => {
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools".to_string()
        }
        CSIDL_ADMINTOOLS => {
            format!("{roaming}\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools")
        }
        _ => return None,
    };
    Some(path)
}

fn windows_parent_directory(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    let separator = trimmed.rfind(['\\', '/'])?;
    if separator == 2 && trimmed.as_bytes().get(1) == Some(&b':') {
        Some(trimmed[..=separator].to_string())
    } else if separator == 0 {
        None
    } else {
        Some(trimmed[..separator].to_string())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IniSection {
    name: String,
    entries: Vec<(String, String)>,
}

fn read_ini_document(host_path: &Path) -> AppResult<(Vec<IniSection>, bool)> {
    match fs::read(host_path) {
        Ok(bytes) => Ok(parse_ini_document(&bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), false)),
        Err(error) => Err(AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read {}", host_path.display()),
            &error,
        )),
    }
}

fn parse_ini_document(bytes: &[u8]) -> (Vec<IniSection>, bool) {
    let (text, prefer_utf16) = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        (String::from_utf16_lossy(&units), true)
    } else {
        (String::from_utf8_lossy(bytes).into_owned(), false)
    };
    let mut sections = Vec::<IniSection>::new();
    let mut current_section: Option<usize> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            let name = trimmed[1..trimmed.len() - 1].trim().to_string();
            let index = ini_section_index(&sections, &name).unwrap_or_else(|| {
                sections.push(IniSection {
                    name: name.clone(),
                    entries: Vec::new(),
                });
                sections.len() - 1
            });
            current_section = Some(index);
            continue;
        }
        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let Some(section_index) = current_section else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.to_string();
        if key.is_empty() {
            continue;
        }
        let entries = &mut sections[section_index].entries;
        if let Some(entry_index) = ini_entry_index(entries, key) {
            entries[entry_index].1 = value;
        } else {
            entries.push((key.to_string(), value));
        }
    }
    (sections, prefer_utf16)
}

fn serialize_ini_document(sections: &[IniSection], prefer_utf16: bool) -> Vec<u8> {
    let mut text = String::new();
    for (section_index, section) in sections.iter().enumerate() {
        if section_index != 0 {
            text.push('\n');
        }
        text.push('[');
        text.push_str(&section.name);
        text.push_str("]\n");
        for (key, value) in &section.entries {
            text.push_str(key);
            text.push('=');
            text.push_str(value);
            text.push('\n');
        }
    }
    if prefer_utf16 {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    } else {
        text.into_bytes()
    }
}

fn update_ini_document(sections: &mut Vec<IniSection>, section: &str, key: Option<&str>, value: Option<&str>) {
    let Some(section_index) = ini_section_index(sections, section) else {
        if key.is_none() || value.is_none() {
            return;
        }
        sections.push(IniSection {
            name: section.to_string(),
            entries: vec![(key.unwrap().to_string(), value.unwrap().to_string())],
        });
        return;
    };
    if key.is_none() {
        sections.remove(section_index);
        return;
    }
    let entries = &mut sections[section_index].entries;
    let key = key.unwrap();
    if value.is_none() {
        if let Some(entry_index) = ini_entry_index(entries, key) {
            entries.remove(entry_index);
        }
        if entries.is_empty() {
            sections.remove(section_index);
        }
        return;
    }
    if let Some(entry_index) = ini_entry_index(entries, key) {
        entries[entry_index].1 = value.unwrap().to_string();
    } else {
        entries.push((key.to_string(), value.unwrap().to_string()));
    }
}

fn ini_section_index(sections: &[IniSection], section: &str) -> Option<usize> {
    sections
        .iter()
        .position(|candidate| candidate.name.eq_ignore_ascii_case(section))
}

fn ini_entry_index(entries: &[(String, String)], key: &str) -> Option<usize> {
    entries
        .iter()
        .position(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
}

fn build_shell_link_link_info(path: &str) -> Vec<u8> {
    let normalized = normalize_windows_path(path);
    let (local_base_path, common_path_suffix) = if let Some((parent, leaf)) = normalized.rsplit_once('\\') {
        let base = if parent.ends_with(':') {
            format!("{parent}\\")
        } else {
            format!("{parent}\\")
        };
        (base, leaf.to_string())
    } else {
        (normalized.clone(), String::new())
    };
    let local_base_path_ansi = local_base_path.as_bytes().to_vec();
    let common_path_suffix_ansi = common_path_suffix.as_bytes().to_vec();
    let local_base_path_unicode = encode_shell_link_utf16(&local_base_path);
    let common_path_suffix_unicode = encode_shell_link_utf16(&common_path_suffix);
    let volume_id = build_shell_link_volume_id(&normalized);

    let volume_id_offset = 0x24_u32;
    let local_base_path_offset = volume_id_offset + volume_id.len() as u32;
    let common_path_suffix_offset = local_base_path_offset + local_base_path_ansi.len() as u32 + 1;
    let local_base_path_offset_unicode = common_path_suffix_offset + common_path_suffix_ansi.len() as u32 + 1;
    let common_path_suffix_offset_unicode = local_base_path_offset_unicode + local_base_path_unicode.len() as u32;
    let link_info_size = common_path_suffix_offset_unicode + common_path_suffix_unicode.len() as u32;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&link_info_size.to_le_bytes());
    bytes.extend_from_slice(&0x24_u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0001_u32.to_le_bytes());
    bytes.extend_from_slice(&volume_id_offset.to_le_bytes());
    bytes.extend_from_slice(&local_base_path_offset.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&common_path_suffix_offset.to_le_bytes());
    bytes.extend_from_slice(&local_base_path_offset_unicode.to_le_bytes());
    bytes.extend_from_slice(&common_path_suffix_offset_unicode.to_le_bytes());
    bytes.extend_from_slice(&volume_id);
    bytes.extend_from_slice(&local_base_path_ansi);
    bytes.push(0);
    bytes.extend_from_slice(&common_path_suffix_ansi);
    bytes.push(0);
    bytes.extend_from_slice(&local_base_path_unicode);
    bytes.extend_from_slice(&common_path_suffix_unicode);
    bytes
}

fn build_shell_link_volume_id(path: &str) -> Vec<u8> {
    let volume_label = windows_drive_prefix(path)
        .map(|prefix| prefix.trim_end_matches(':'))
        .unwrap_or("C")
        .as_bytes()
        .to_vec();
    let volume_id_size = 0x10_u32 + volume_label.len() as u32 + 1;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&volume_id_size.to_le_bytes());
    bytes.extend_from_slice(&DRIVE_FIXED.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0x10_u32.to_le_bytes());
    bytes.extend_from_slice(&volume_label);
    bytes.push(0);
    bytes
}

fn append_shell_link_string(bytes: &mut Vec<u8>, value: &str) {
    let code_units = value.encode_utf16().collect::<Vec<_>>();
    bytes.extend_from_slice(&(code_units.len() as u16).to_le_bytes());
    for code_unit in code_units {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
}

fn encode_shell_link_utf16(value: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for code_unit in value.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

fn file_attributes_mask(attributes: &[String]) -> u32 {
    let mut raw = 0_u32;
    for attribute in attributes {
        match attribute.as_str() {
            "directory" => raw |= FILE_ATTRIBUTE_DIRECTORY,
            "readonly" => raw |= FILE_ATTRIBUTE_READONLY,
            "hidden" => raw |= FILE_ATTRIBUTE_HIDDEN,
            "system" => raw |= FILE_ATTRIBUTE_SYSTEM,
            "archive" => raw |= FILE_ATTRIBUTE_ARCHIVE,
            "reparse_point" => raw |= FILE_ATTRIBUTE_REPARSE_POINT,
            _ => {}
        }
    }
    if raw == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        raw
    }
}

fn file_attributes_from_mask(raw: u32) -> Vec<String> {
    let mut attributes = Vec::new();
    if raw & FILE_ATTRIBUTE_DIRECTORY != 0 {
        attributes.push("directory".to_string());
    }
    if raw & FILE_ATTRIBUTE_READONLY != 0 {
        attributes.push("readonly".to_string());
    }
    if raw & FILE_ATTRIBUTE_HIDDEN != 0 {
        attributes.push("hidden".to_string());
    }
    if raw & FILE_ATTRIBUTE_SYSTEM != 0 {
        attributes.push("system".to_string());
    }
    if raw & FILE_ATTRIBUTE_ARCHIVE != 0 {
        attributes.push("archive".to_string());
    }
    if raw & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        attributes.push("reparse_point".to_string());
    }
    attributes
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
    let mut kernel32_exports = vec![
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
            ordinal: 118,
            name: Some("SetCurrentDirectoryW".to_string()),
            target: ExportTarget::Rva(0x1018),
        },
        ExportSymbol {
            ordinal: 119,
            name: Some("GetFileAttributesW".to_string()),
            target: ExportTarget::Rva(0x101c),
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
            ordinal: 117,
            name: Some("GetTickCount".to_string()),
            target: ExportTarget::Rva(0x1068),
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
            ordinal: 118,
            name: Some("VirtualAlloc".to_string()),
            target: ExportTarget::Rva(0x1110),
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
    ];
    extend_named_exports(
        &mut kernel32_exports,
        0x0200,
        0x2000,
        &[
            "GetFullPathNameW",
            "GetFileSize",
            "MoveFileW",
            "SetFileAttributesW",
            "GetModuleFileNameW",
            "CopyFileW",
            "SetEnvironmentVariableW",
            "GetEnvironmentStringsW",
            "FreeEnvironmentStringsW",
            "GetWindowsDirectoryW",
            "GetTempPathW",
            "GetCommandLineW",
            "GetVersion",
            "SetErrorMode",
            "GetSystemTimeAsFileTime",
            "CreateEventW",
            "SetEvent",
            "ResetEvent",
            "IsDebuggerPresent",
            "InitOnceBeginInitialize",
            "InitOnceComplete",
            "InitializeSRWLock",
            "AcquireSRWLockExclusive",
            "ReleaseSRWLockExclusive",
            "AcquireSRWLockShared",
            "ReleaseSRWLockShared",
            "TryAcquireSRWLockExclusive",
            "TryAcquireSRWLockShared",
            "WaitForSingleObject",
            "GetCurrentProcess",
            "CompareFileTime",
            "GlobalUnlock",
            "GlobalLock",
            "CreateThread",
            "CreateDirectoryW",
            "CreateProcessW",
            "RemoveDirectoryW",
            "lstrcmpiA",
            "GetTempFileNameW",
            "lstrcpyA",
            "lstrcpyW",
            "MoveFileExW",
            "lstrcatW",
            "GetSystemDirectoryW",
            "GetProcAddress",
            "GetModuleHandleA",
            "GlobalFree",
            "GlobalAlloc",
            "GetShortPathNameW",
            "SearchPathW",
            "lstrcmpiW",
            "SetFileTime",
            "ExpandEnvironmentStringsW",
            "lstrcmpW",
            "GetDiskFreeSpaceW",
            "lstrlenW",
            "lstrcpynW",
            "GetExitCodeProcess",
            "FindFirstFileW",
            "FindNextFileW",
            "DeleteFileW",
            "SetFilePointer",
            "FindClose",
            "MulDiv",
            "MultiByteToWideChar",
            "lstrlenA",
            "WideCharToMultiByte",
            "GetPrivateProfileStringW",
            "WritePrivateProfileStringW",
            "FreeLibrary",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExW",
            "GetModuleHandleW",
        ],
    );
    BTreeMap::from([
        (
            "kernel32.dll".to_string(),
            kernel32_exports,
        ),
        (
            "kernelbase.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("Sleep".to_string()),
                    target: ExportTarget::Rva(0x2000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("GetTickCount".to_string()),
                    target: ExportTarget::Rva(0x2010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("GetSystemTimeAsFileTime".to_string()),
                    target: ExportTarget::Rva(0x2020),
                },
            ],
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
            "dxgi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CreateDXGIFactory1".to_string()),
                    target: ExportTarget::Rva(0x4100),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CreateDXGIFactory2".to_string()),
                    target: ExportTarget::Rva(0x4110),
                },
            ],
        ),
        (
            "d3d12.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("D3D12CreateDevice".to_string()),
                target: ExportTarget::Rva(0x4200),
            }],
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

fn extend_named_exports(exports: &mut Vec<ExportSymbol>, starting_ordinal: u32, starting_rva: u32, names: &[&str]) {
    for (index, name) in names.iter().enumerate() {
        exports.push(ExportSymbol {
            ordinal: starting_ordinal + index as u32,
            name: Some((*name).to_string()),
            target: ExportTarget::Rva(starting_rva + index as u32 * 0x10),
        });
    }
}