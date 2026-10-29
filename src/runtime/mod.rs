//! Windows PE guest runtime: split into focused modules (state, execution,
//! loader, process, thread, scheduler, callback, guest_memory, events,
//! dispatch).  `crate::pe_runtime` is a re-export shim over this module.

mod state;
pub(crate) use self::state::*;
mod loader;
mod thread;
pub(crate) use self::thread::*;
mod thread_context;
pub(crate) use self::thread_context::*;
mod shared;
pub(crate) use self::shared::*;
pub mod handle_table;
pub mod object_manager;
pub(crate) mod process;
pub(crate) mod scheduler;
pub(crate) use self::scheduler::*;
mod callback;
pub(crate) use self::callback::*;
pub(crate) mod dispatch;

mod thunk_types;
pub use self::thunk_types::*;
mod lifecycle;
pub use self::lifecycle::*;
mod sessions;
pub use self::sessions::*;
mod alloc_impl;
mod clr_tbs_impl;
mod com_objects_impl;
mod device_io_impl;
mod execution_glue_impl;
mod iat_impl;
mod import_registry;
mod lifecycle_impl;
mod live_io_impl;
mod object_impl;
mod router;
mod thunk_catalog;
mod window_paint_impl;
pub use self::import_registry::*;
mod execution_support;
pub(crate) use self::execution_support::*;
mod registry_helpers;
pub(crate) use self::registry_helpers::*;
mod window_helpers;
pub(crate) use self::window_helpers::*;
mod crt_helpers;
pub(crate) use self::crt_helpers::*;
mod guest_memory;
pub(crate) use self::guest_memory::*;
mod device_paths;
pub use self::device_paths::*;
mod version_info;
pub(crate) use self::version_info::*;
mod boot_helpers;
pub(crate) use self::boot_helpers::*;
mod gpu_descriptors;
pub(crate) use self::gpu_descriptors::*;
mod message_helpers;
pub(crate) use self::message_helpers::*;
mod preview_render;
pub(crate) use self::preview_render::*;
mod thunk_support;
pub(crate) use self::thunk_support::*;
mod net_helpers;
pub(crate) use self::net_helpers::*;
mod iphlp_helpers;
pub(crate) use self::iphlp_helpers::*;
mod time_helpers;
pub(crate) use self::time_helpers::*;
mod gdiplus_helpers;
pub(crate) use self::gdiplus_helpers::*;
mod system_info;
pub(crate) use self::system_info::*;
mod call_helpers;
pub(crate) use self::call_helpers::*;
mod api_string_helpers;
pub(crate) use self::api_string_helpers::*;
mod path_helpers;
pub(crate) use self::path_helpers::*;
mod ini_helpers;
pub(crate) use self::ini_helpers::*;
mod search_path;
pub(crate) use self::search_path::*;
mod shlwapi_helpers;
pub(crate) use self::shlwapi_helpers::*;
mod host_ui;
pub(crate) use self::host_ui::*;
mod exports;
pub use self::exports::*;
mod steam_cli;
pub use self::steam_cli::*;

#[cfg(test)]
use crate::api_database::WindowsVersion;
use crate::audio::{
    AudioSamples, AudioSubsystem, SampleFormat, SourceBuffer, VoiceId, WaveFormat,
    default_output_matrix,
};
use crate::canonical::{GfxFrame, GuestException, PerfMetric};
use crate::cpu::{
    CpuEngineConfig, CpuExecutionEngine, CpuState, DecodedInstruction, DecodedOpcode, GuestArch,
    MemoryImage, Register, TranslatedBlock,
};
use crate::d3d11::{
    BlendStateDesc, D3DERR_INVALIDCALL, D3DERR_OUTOFVIDEOMEMORY, D3d9DeviceId, D3d9StateBlock,
    D3d11Device, D3d11ResourceId, D3d11ViewId, D3dLight9, D3dMaterial9, D3dMatrix,
    D3dPresentParameters, D3dViewport9, DepthStencilStateDesc, DeviceCreationRequest, FeatureLevel,
    FixedFunctionScene, InputElementDesc, InputLayoutDesc, InputLayoutId, RasterizerStateDesc,
    ResourceDimension, SamplerStateDesc, ScissorRect, ShaderModuleDesc,
    ShaderStage as D3d11ShaderStage, ViewKind, Viewport, d3d11_create_device,
    d3d11_create_device_and_swapchain, direct3d_create9,
};
use crate::d3d12::{
    CommandAllocatorId as D3d12CommandAllocatorId, CommandListId as D3d12CommandListId,
    CommandQueueId as D3d12CommandQueueId, D3d12Runtime, DescriptorHeapId as D3d12DescriptorHeapId,
    FenceId as D3d12FenceId, ImmutableCommandStream, PipelineStateDesc,
    PipelineStateId as D3d12PipelineStateId, ResourceId as D3d12ResourceId, RootSignatureDesc,
    RootSignatureId as D3d12RootSignatureId, SwapchainId as D3d12SwapchainId,
};
use crate::error::{AppError, AppResult};
use crate::ge::{GameEnvironment, RegistryView};
use crate::gfx::{
    BufferRole, DescriptorHeapType, DxgiFormat, ResourceState, ResourceUsageHint, SwapchainDesc,
    ViewDescriptor,
};
#[cfg(test)]
use crate::host_thunks::{ArchMask, LastErrorBehavior, Subsystem, SupportPolicy, ThunkMetadata};
use crate::host_thunks::{ImplementationLevel, lookup_thunk_metadata, ordinal_import_name};
use crate::host_thunks::{
    read_guest_bytes_checked as host_read_guest_bytes_checked,
    validate_guest_pointer as host_validate_guest_pointer,
    write_guest_bytes_checked as host_write_guest_bytes_checked,
};
use crate::live::{LiveAudioChunk, LiveFrame, LiveInputEvent, LivePeSession};
use crate::network::{AddressFamily, NetworkStack, SockAddr};
use crate::pe::{self, ApiSetResolver, ExportSymbol, ExportTarget, ImportSymbol, ResolvedImport};
use crate::real_fs::{RealFilesystem, WindowsPathResolver, parse_ntfs_path};
use crate::real_win32::BCryptContext;
use crate::reason::ReasonCode;
use crate::runtime::dispatch::com::ComMethod;
use crate::runtime::dispatch::dshow::dshow_filter_graph_methods;
use crate::runtime::dispatch::mf::mf_dxgi_device_manager_methods;
use crate::shader::parse_dxil_container;
use crate::telemetry::TelemetryCollector;
use crate::threads::{
    FIBER_MANAGER, GuestApcQueue, GuestConditionVariable, GuestSRWLock, GuestTimerQueue,
};
use crate::trace::TraceEvent;
use crate::user32::DeviceAxis;
use crate::user32::DirectInputDataFormat;
use crate::user32::RawInputRegistration;
use crate::user32::{
    GDIPLUS_DASH_STYLE_SOLID, GDIPLUS_LINE_CAP_FLAT, GDIPLUS_LINE_JOIN_MITER, GWL_WNDPROC,
    GdiplusBitmap, GdiplusBrush, GdiplusContainer, GdiplusGraphicsState, GdiplusImage,
    GdiplusImageAttributes, GdiplusLineBrush, GdiplusMatrix, GdiplusObject, GdiplusPath,
    GdiplusPathElement, GdiplusPen, GdiplusPointF, GdiplusSolidFill, GdiplusStatus,
    GdiplusTextureBrush, KeyModifiers, KeyboardDevice, KeyboardLayoutId, Message, MessageKind,
    MouseButton, MouseButtonEvent, MouseDevice, Rect, User32Subsystem, WS_VISIBLE, WindowClassInfo,
    WindowPlacement, WindowPreview,
};
use crate::util;
use crate::win32::{
    ApartmentModel, CreationDisposition, FileInformation, FindData, SeekOrigin, WaitStatus,
    Win32Subsystem,
};
use crate::winhttp::{WinHttpStack, WinHttpWebSocketBufferType, WinHttpWebSocketCloseStatus};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::CStr;
use std::fs;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Dynamic-import log
// ---------------------------------------------------------------------------

/// One dynamically-resolved import: a (DLL, name) pair recorded when the
/// runtime resolves an export at runtime rather than from the static import
/// table.
///
/// Identity is ALWAYS by (DLL + name) — never by name alone — because the
/// same export name can exist in several modules.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DynamicImport {
    /// DLL the export was resolved in (lowercase, with extension).
    pub dll: String,
    /// Resolved export name (ordinals are recorded as `ordinal#N`).
    pub name: String,
}

/// Shared dynamic-import log.
///
/// GetProcAddress / LdrGetProcedureAddress / delay-load resolution /
/// forwarded-export following / API-set redirection record (DLL, name) pairs
/// here so the generic import-coverage report
/// ([`crate::import_coverage::coverage_for_pe_with_runtime_trace`]) can
/// account for imports that never appear in any import table.
pub static DYNAMIC_IMPORT_LOG: std::sync::LazyLock<Mutex<Vec<DynamicImport>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::new()));

/// Record a dynamically-resolved (DLL, name) import.
pub fn clear_dynamic_import_log_static() {
    if let Ok(mut log) = DYNAMIC_IMPORT_LOG.lock() {
        log.clear();
    }
}

pub fn record_dynamic_import(dll: &str, name: &str) {
    if dll.is_empty() || name.is_empty() {
        return;
    }
    let mut log = DYNAMIC_IMPORT_LOG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dll = dll.to_ascii_lowercase();
    if !log
        .iter()
        .any(|entry| entry.dll == dll && entry.name == name)
    {
        log.push(DynamicImport {
            dll,
            name: name.to_string(),
        });
    }
}

/// Take (and clear) the recorded dynamic imports.
pub fn drain_dynamic_import_log() -> Vec<DynamicImport> {
    let mut log = DYNAMIC_IMPORT_LOG
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    std::mem::take(&mut *log)
}

// Global state for ISteamNetworkingSockets and ISteamNetworkingMessages
// PE runtime dispatch. Initialised lazily on first API call.
static STEAM_NET_SOCKETS: Mutex<Option<crate::steam_integration::SteamNetworkingSockets>> =
    Mutex::new(None);
static STEAM_NET_MESSAGES: Mutex<Option<crate::steam_integration::SteamNetworkingMessages>> =
    Mutex::new(None);

// Global state for K1-K3, K5-K7 Steam API interfaces.
// Initialised lazily on first API call.
static STEAM_USER_STATS: Mutex<Option<crate::steam_integration::SteamUserStats>> = Mutex::new(None);
static STEAM_FRIENDS: Mutex<Option<crate::steam_integration::SteamFriends>> = Mutex::new(None);
static STEAM_MATCHMAKING: Mutex<Option<crate::steam_integration::SteamMatchmaking>> =
    Mutex::new(None);
static STEAM_REMOTE_STORAGE: Mutex<Option<crate::steam_integration::SteamRemoteStorage>> =
    Mutex::new(None);
static STEAM_SCREENSHOTS: Mutex<Option<crate::steam_integration::SteamScreenshots>> =
    Mutex::new(None);
static STEAM_MUSIC: Mutex<Option<crate::steam_integration::SteamMusic>> = Mutex::new(None);

const SYNTHETIC_PID_DTM: u32 = 4242;
const LIVE_UI_DEBUG_LIMIT: usize = 32;
const WINDOW_MSG_DEBUG_LIMIT: usize = 128;
const STACK_BASE: u64 = 0x0000_7fff_1000_0000;

const X86_STACK_BASE: u64 = 0x7000_0000;
/// Main thread stack size.  64 KB was far too small for complex apps like
/// Steam — the guest stack overflows almost immediately, the guest RSP
/// gets corrupted to point into a code page, and the ARM64 host crashes
/// with EXC_BAD_ACCESS when a function prologue tries to use that value
/// as the hardware stack pointer.  1 MB matches the Windows default and
/// gives Steam plenty of room for its deep call chains at startup.
const STACK_SIZE: usize = 0x10_0000;
const THUNK_BASE: u64 = 0x0000_7fff_8000_0000;
const X86_THUNK_BASE: u64 = 0x7100_0000;
const CRT_DATA_BASE: u64 = 0x0000_7fff_8100_0000;
const X86_CRT_DATA_BASE: u64 = 0x7200_0000;
const CRT_HEAP_BASE: u64 = 0x0000_7fff_8200_0000;
const X86_CRT_HEAP_BASE: u64 = 0x7300_0000;
/// Secondary x86 heap region at 512 MB, well above typical PE image load
/// addresses (~0x400000). Used when the primary region (0x73000000) is
/// exhausted to avoid reusing still-mapped pages.
const X86_CRT_HEAP_BASE_2: u64 = 0x2000_0000;
const PRIVATE_PAGES_BASE: u64 = 0x0000_7fff_8400_0000;
const X86_PRIVATE_PAGES_BASE: u64 = 0x7400_0000;
const AF_INET: i32 = 2;
const AF_UNSPEC: i32 = 0;
const AF_INET6: i32 = 23;
const IPPROTO_TCP: i32 = 6;
const SOCK_STREAM: i32 = 1;
const FIONBIO: u32 = 0x8004_667e;
const FIONREAD: u32 = 0x4004_667f;
const SIO_BASE_HANDLE: u32 = 0x4800_0022;
const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xc800_0006;
const WSAEAFNOSUPPORT: i32 = 10047;
const WSAEFAULT: i32 = 10014;
const WSAEINVAL: i32 = 10022;
const WSAENOTSOCK: i32 = 10038;
const WSAEWOULDBLOCK: i32 = 10035;
const WSAENOPROTOOPT: i32 = 10042;
const WSAECONNREFUSED: i32 = 10061;
const WSAHOST_NOT_FOUND: i32 = 11001;
const WSANO_RECOVERY: i32 = 11003;
// Winsock level/option identifiers used by the getsockopt surface.
const SOL_SOCKET: i32 = 0xFFFF;
const SO_DEBUG: i32 = 0x0001;
const SO_ACCEPTCONN: i32 = 0x0002;
const SO_REUSEADDR: i32 = 0x0004;
const SO_KEEPALIVE: i32 = 0x0008;
const SO_DONTROUTE: i32 = 0x0010;
const SO_BROADCAST: i32 = 0x0020;
const SO_SNDBUF: i32 = 0x1001;
const SO_RCVBUF: i32 = 0x1002;
const SO_ERROR: i32 = 0x1007;
const SO_TYPE: i32 = 0x1008;
const TCP_NODELAY: i32 = 0x0001;
const IPPROTO_IP: i32 = 0;
const IP_TTL: i32 = 4;
// WSAPoll revents/events flags.
const POLLRDNORM: u16 = 0x0100;
const POLLWRNORM: u16 = 0x0010;
const POLLERR: u16 = 0x0001;
const POLLNVAL: u16 = 0x0020;
// getnameinfo flags and EAI_* error codes (ws2tcpip.h).
const NI_NUMERICHOST: u32 = 0x02;
const NI_NAMEREQD: u32 = 0x04;
const NI_NUMERICSERV: u32 = 0x08;
const NI_DGRAM: u32 = 0x10;
const EAI_NONAME: i32 = WSAHOST_NOT_FOUND;
const EAI_FAIL: i32 = WSANO_RECOVERY;
const EAI_FAMILY: i32 = WSAEAFNOSUPPORT;
// iphlpapi / netapi32 documented codes.
const NO_ERROR: u32 = 0;
const ERROR_INVALID_LEVEL: u32 = 124;
const ERROR_NOT_SUPPORTED: u32 = 50;
const NERR_UserNotFound: u32 = 2221;
const NERR_InvalidComputer: u32 = 2351;
// MIB interface / route constants.
const MIB_IF_ADMIN_STATUS_UP: u32 = 1;
const MIB_IPROUTE_TYPE_DIRECT: u32 = 3;
const MIB_IPPROTO_NETMGMT: u32 = 3;
// IP_ADAPTER_* flags (iphlpapi.h).
const IP_ADAPTER_DDNS_ENABLED: u32 = 0x0000_0001;
const IP_ADAPTER_REGISTER_ADAPTER_SUFFIX: u32 = 0x0000_0002;
const IP_ADAPTER_DHCP_ENABLED: u32 = 0x0000_0004;
const IP_ADAPTER_IPV4_ENABLED: u32 = 0x0000_0080;
const IP_ADAPTER_IPV6_ENABLED: u32 = 0x0000_0100;
const DESCRIPTOR_HANDLE_BASE: u64 = 0x0000_7fff_8300_0000;
const DESCRIPTOR_HANDLE_STRIDE: u64 = 0x20;
const MEMORY_BASIC_INFORMATION32_SIZE: u64 = 28;
const MEMORY_BASIC_INFORMATION64_SIZE: u64 = 48;
const TIME_ZONE_INFORMATION_SIZE: usize = 172;
const TIME_ZONE_NAME_CAPACITY: usize = 32;
const TIME_ZONE_ID_UNKNOWN: u32 = 0;
const TIME_ZONE_ID_STANDARD: u32 = 1;
const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
const X86_EXCEPTION_RECORD_SIZE: u64 = 80;
const X86_CONTEXT_SIZE: u64 = 716;
const X86_EXCEPTION_CHAIN_END: u64 = 0xffff_ffff;
const X86_CONTEXT_FLAGS_FULL: u32 = 0x0001_0007;
const X86_CONTEXT_OFFSET_SEG_GS: u64 = 0x8c;
const X86_CONTEXT_OFFSET_SEG_FS: u64 = 0x90;
const X86_CONTEXT_OFFSET_SEG_ES: u64 = 0x94;
const X86_CONTEXT_OFFSET_SEG_DS: u64 = 0x98;
const X86_CONTEXT_OFFSET_EDI: u64 = 0x9c;
const X86_CONTEXT_OFFSET_ESI: u64 = 0xa0;
const X86_CONTEXT_OFFSET_EBX: u64 = 0xa4;
const X86_CONTEXT_OFFSET_EDX: u64 = 0xa8;
const X86_CONTEXT_OFFSET_ECX: u64 = 0xac;
const X86_CONTEXT_OFFSET_EAX: u64 = 0xb0;
const X86_CONTEXT_OFFSET_EBP: u64 = 0xb4;
const X86_CONTEXT_OFFSET_EIP: u64 = 0xb8;
const X86_CONTEXT_OFFSET_SEG_CS: u64 = 0xbc;
const X86_CONTEXT_OFFSET_EFLAGS: u64 = 0xc0;
const X86_CONTEXT_OFFSET_ESP: u64 = 0xc4;
const X86_CONTEXT_OFFSET_SEG_SS: u64 = 0xc8;
const X86_EXCEPTION_CONTINUE_EXECUTION: u32 = 0;
const X86_EXCEPTION_CONTINUE_SEARCH: u32 = 1;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_GUARD: u32 = 0x100;

/// Translate Windows page-protection flags to the canonical VM protection
/// model.
fn civil_day_of_week(year: u16, month: u16, day: u16) -> u16 {
    // 1970-01-01 was a Thursday (4).
    let days = days_since_1970(i64::from(year), i64::from(month), i64::from(day));
    ((days + 4).rem_euclid(7)) as u16
}

fn days_since_1970(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn current_guest_utc_components() -> AppResult<(u16, u16, u16, u16, u16, u16)> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = duration.as_secs() / 86400;
    let mut year = 1970_i64;
    let mut remaining = days as i64;
    loop {
        let days_in_year = if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
            366
        } else {
            365
        };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days: [i64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1_i64;
    for &days_in_month in &month_days {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }
    let secs_of_day = duration.as_secs() % 86400;
    Ok((
        year as u16,
        month as u16,
        (remaining + 1) as u16,
        (secs_of_day / 3600) as u16,
        ((secs_of_day % 3600) / 60) as u16,
        (secs_of_day % 60) as u16,
    ))
}

fn write_date_time_result(
    memory: &mut MemoryImage,
    state: &mut CpuState,
    text: &str,
    buffer_ptr: u64,
    buffer_size: i32,
    last_error: &mut u32,
) {
    let utf16: Vec<u16> = text.encode_utf16().collect();
    let required = utf16.len() + 1;
    if buffer_ptr == 0 || buffer_size <= 0 {
        state.set(Register::Rax, required as u64);
        return;
    }
    if (buffer_size as usize) < required {
        state.set(Register::Rax, 0);
        *last_error = ERROR_INSUFFICIENT_BUFFER;
        return;
    }
    for (i, &unit) in utf16.iter().enumerate() {
        memory.write_u16(buffer_ptr + i as u64 * 2, unit);
    }
    memory.write_u16(buffer_ptr + utf16.len() as u64 * 2, 0);
    state.set(Register::Rax, utf16.len() as u64);
    *last_error = 0;
}

const ERROR_RESOURCE_NOT_FOUND: u32 = 1_815;

const FULL_WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

const ABBR_WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const FULL_MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

const ABBR_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn guest_pointer_size(guest_arch: GuestArch) -> u64 {
    if guest_arch == GuestArch::X86 { 4 } else { 8 }
}

fn resource_name_from_arg(memory: &MemoryImage, arg: u64) -> AppResult<crate::pe::ResourceName> {
    if arg >> 16 == 0 {
        Ok(crate::pe::ResourceName::Id(arg as u32 & 0xffff))
    } else if arg == 0 {
        Ok(crate::pe::ResourceName::Id(0))
    } else {
        Ok(crate::pe::ResourceName::Str(read_c_string(memory, arg)?))
    }
}

fn resource_type_id(name: &crate::pe::ResourceName) -> u32 {
    match name {
        crate::pe::ResourceName::Id(id) => *id,
        crate::pe::ResourceName::Str(text) => match text.to_ascii_uppercase().as_str() {
            "RT_CURSOR" => 1,
            "RT_BITMAP" => 2,
            "RT_ICON" => 3,
            "RT_MENU" => 4,
            "RT_DIALOG" => 5,
            "RT_STRING" => 6,
            "RT_FONTDIR" => 7,
            "RT_FONT" => 8,
            "RT_ACCELERATOR" => 9,
            "RT_RCDATA" => 10,
            "RT_MESSAGETABLE" => 11,
            "RT_GROUP_CURSOR" => 12,
            "RT_GROUP_ICON" => 14,
            "RT_VERSION" => 16,
            "RT_DLGINCLUDE" => 17,
            "RT_PLUGPLAY" => 19,
            "RT_HTML" => 23,
            "RT_MANIFEST" => 24,
            _ => 0,
        },
    }
}

fn format_time_tokens(
    memory: &MemoryImage,
    format_ptr: u64,
    hour: u16,
    minute: u16,
    second: u16,
    force24: bool,
) -> AppResult<String> {
    let format = read_utf16_string(memory, format_ptr)?;
    let units: Vec<u16> = format.encode_utf16().collect();
    let meridian = if hour < 12 { "AM" } else { "PM" };
    let hour12 = hour % 12;
    let hour12_display = if hour12 == 0 { 12 } else { hour12 };
    let mut out = String::new();
    let mut index = 0usize;
    while index < units.len() {
        let unit = units[index];
        let ch = char::from_u32(u32::from(unit)).unwrap_or('?');
        match ch {
            '\'' => {
                index += 1;
                let mut closed = false;
                while index < units.len() {
                    let current = units[index];
                    if current == b'\'' as u16 {
                        if index + 1 < units.len() && units[index + 1] == b'\'' as u16 {
                            out.push('\'');
                            index += 2;
                            continue;
                        }
                        closed = true;
                        index += 1;
                        break;
                    }
                    out.push(char::from_u32(u32::from(current)).unwrap_or('?'));
                    index += 1;
                }
                if !closed {
                    break;
                }
            }
            'h' | 'H' => {
                let mut count = 0usize;
                while index + count < units.len()
                    && (units[index + count] == b'h' as u16 || units[index + count] == b'H' as u16)
                {
                    count += 1;
                }
                let value = if unit == b'h' as u16 && !force24 {
                    hour12_display
                } else {
                    hour
                };
                if count >= 2 {
                    out.push_str(&format!("{:02}", value));
                } else {
                    out.push_str(&value.to_string());
                }
                index += count;
            }
            'm' => {
                let mut count = 0usize;
                while index + count < units.len() && units[index + count] == b'm' as u16 {
                    count += 1;
                }
                if count >= 2 {
                    out.push_str(&format!("{:02}", minute));
                } else {
                    out.push_str(&minute.to_string());
                }
                index += count;
            }
            's' => {
                let mut count = 0usize;
                while index + count < units.len() && units[index + count] == b's' as u16 {
                    count += 1;
                }
                if count >= 2 {
                    out.push_str(&format!("{:02}", second));
                } else {
                    out.push_str(&second.to_string());
                }
                index += count;
            }
            't' => {
                let mut count = 0usize;
                while index + count < units.len() && units[index + count] == b't' as u16 {
                    count += 1;
                }
                if force24 {
                    // TIME_FORCE24HOURFORMAT: the meridian token renders empty.
                } else if count >= 2 {
                    out.push_str(meridian);
                } else {
                    out.push_str(&meridian[..1]);
                }
                index += count;
            }
            other => {
                out.push(char::from_u32(u32::from(other)).unwrap_or('?'));
                index += 1;
            }
        }
    }
    Ok(out)
}

fn format_date_tokens(
    memory: &MemoryImage,
    format_ptr: u64,
    year: u16,
    month: u16,
    day: u16,
    dow: u16,
) -> AppResult<String> {
    let format = read_utf16_string(memory, format_ptr)?;
    let units: Vec<u16> = format.encode_utf16().collect();
    let mut out = String::new();
    let mut index = 0usize;
    while index < units.len() {
        let unit = units[index];
        let ch = char::from_u32(u32::from(unit)).unwrap_or('?');
        match ch {
            '\'' => {
                // Quoted literal: copy until the closing quote; '' is an
                // escaped quote.
                index += 1;
                let mut closed = false;
                while index < units.len() {
                    let current = units[index];
                    if current == b'\'' as u16 {
                        if index + 1 < units.len() && units[index + 1] == b'\'' as u16 {
                            out.push('\'');
                            index += 2;
                            continue;
                        }
                        closed = true;
                        index += 1;
                        break;
                    }
                    out.push(char::from_u32(u32::from(current)).unwrap_or('?'));
                    index += 1;
                }
                if !closed {
                    break;
                }
            }
            'd' => {
                let mut count = 0usize;
                while index + count < units.len() && units[index + count] == b'd' as u16 {
                    count += 1;
                }
                match count {
                    1 => out.push_str(&day.to_string()),
                    2 => out.push_str(&format!("{:02}", day)),
                    3 => out.push_str(ABBR_WEEKDAYS[dow as usize]),
                    _ => out.push_str(FULL_WEEKDAYS[dow as usize]),
                }
                index += count;
            }
            'M' => {
                let mut count = 0usize;
                while index + count < units.len() && units[index + count] == b'M' as u16 {
                    count += 1;
                }
                let month_index = (month as usize).saturating_sub(1);
                match count {
                    1 => out.push_str(&month.to_string()),
                    2 => out.push_str(&format!("{:02}", month)),
                    3 => out.push_str(ABBR_MONTHS[month_index]),
                    _ => out.push_str(FULL_MONTHS[month_index]),
                }
                index += count;
            }
            'y' => {
                let mut count = 0usize;
                while index + count < units.len() && units[index + count] == b'y' as u16 {
                    count += 1;
                }
                match count {
                    1 => out.push_str(&format!("{}", year % 100)),
                    2 => out.push_str(&format!("{:02}", year % 100)),
                    _ => out.push_str(&format!("{:04}", year)),
                }
                index += count;
            }
            other => {
                out.push(char::from_u32(u32::from(other)).unwrap_or('?'));
                index += 1;
            }
        }
    }
    Ok(out)
}

fn file_type_description(path: &str, attributes: u32) -> String {
    if attributes & 0x10 != 0 {
        return "File folder".to_string();
    }
    let extension = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    match extension.as_str() {
        "txt" | "log" | "ini" | "md" | "csv" => "Text Document".to_string(),
        "exe" | "com" | "bat" | "cmd" | "msi" => "Application".to_string(),
        "dll" | "sys" | "drv" => "Application Extension".to_string(),
        "jpg" | "jpeg" | "png" | "bmp" | "gif" | "tif" | "tiff" | "webp" => {
            "Image File".to_string()
        }
        "mp3" | "wav" | "flac" | "ogg" | "aac" | "wma" => "Audio File".to_string(),
        "mp4" | "avi" | "mov" | "mkv" | "wmv" | "webm" => "Video File".to_string(),
        "pdf" => "PDF Document".to_string(),
        "zip" | "rar" | "7z" | "tar" | "gz" => "Compressed Folder".to_string(),
        "html" | "htm" | "xml" | "css" | "js" => "Web Document".to_string(),
        "doc" | "docx" => "Word Document".to_string(),
        "xls" | "xlsx" => "Excel Sheet".to_string(),
        "ppt" | "pptx" => "PowerPoint Presentation".to_string(),
        "" if path.ends_with(['\\', '/']) => "File folder".to_string(),
        _ => "Unknown File Type".to_string(),
    }
}

fn protection_from_page_flags(flags: u32) -> crate::vm::VmProtection {
    let flags = flags & !PAGE_GUARD;
    crate::vm::VmProtection {
        read: flags & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)
            != 0,
        write: flags & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE) != 0,
        execute: flags & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE) != 0,
    }
}

/// Translate the canonical VM protection model back to Windows page flags.
fn page_flags_from_protection(protection: &crate::vm::VmProtection) -> u32 {
    match (protection.read, protection.write, protection.execute) {
        (false, false, false) => PAGE_NOACCESS,
        (true, false, false) => PAGE_READONLY,
        (true, true, false) => PAGE_READWRITE,
        (false, false, true) => PAGE_EXECUTE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        _ => PAGE_NOACCESS,
    }
}
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_DECOMMIT: u32 = 0x4000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_PRIVATE: u32 = 0x0002_0000;
const MEM_FREE: u32 = 0x0001_0000;
const MEM_IMAGE: u32 = 0x0100_0000;
const CREATE_SUSPENDED: u32 = 0x0000_0004;
const STARTF_USESHOWWINDOW: u32 = 0x0001;
const STARTF_USESTDHANDLES: u32 = 0x0100;
#[allow(dead_code)]
const E_NOTIMPL: u64 = 0x8000_4001;
const E_INVALIDARG: u64 = 0x8007_0057;
/// CLASS_E_CLASSNOTAVAILABLE — returned when CoCreateInstance cannot find a
/// registered class factory for the requested CLSID.
const CLASS_E_CLASSNOTAVAILABLE: u64 = 0x8004_0154;
const DXGI_ERROR_NOT_FOUND: u64 = 0x887A_0002;
const INVALID_HANDLE_VALUE: u64 = u64::MAX;
pub(crate) const DLL_PROCESS_DETACH: u32 = 0;
pub(crate) const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_THREAD_ATTACH: u32 = 2;
const DLL_THREAD_DETACH: u32 = 3;

/// Reason codes for DllMain entry point notifications.
///
/// These map 1:1 to the Windows `DLL_PROCESS_ATTACH`, `DLL_PROCESS_DETACH`,
/// `DLL_THREAD_ATTACH`, and `DLL_THREAD_DETACH` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DllReason {
    ProcessAttach,
    ProcessDetach,
    ThreadAttach,
    ThreadDetach,
}

impl DllReason {
    /// Convert this `DllReason` to the raw u32 value expected by Windows DllMain.
    pub fn to_raw(self) -> u32 {
        match self {
            DllReason::ProcessAttach => DLL_PROCESS_ATTACH,
            DllReason::ProcessDetach => DLL_PROCESS_DETACH,
            DllReason::ThreadAttach => DLL_THREAD_ATTACH,
            DllReason::ThreadDetach => DLL_THREAD_DETACH,
        }
    }
}
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
const D3D12_RAYTRACING_TIER_1_1: u32 = 11;
const D3D12_MESH_SHADER_TIER_NOT_SUPPORTED: u32 = 0;
const D3D12_MESH_SHADER_TIER_1: u32 = 10;
const D3D12_SAMPLER_FEEDBACK_TIER_NOT_SUPPORTED: u32 = 0;
const D3D12_RESOURCE_BINDING_TIER_3: u32 = 3;
const D3D12_RESOURCE_HEAP_TIER_2: u32 = 2;
const D3D12_CONSERVATIVE_RASTERIZATION_TIER_1: u32 = 1;
const D3D12_TILED_RESOURCES_TIER_2: u32 = 2;
const PE_RUNTIME_INSTRUCTION_BUDGET: u64 = 25_000_000;
/// Wall-clock interval (ms) of the host-side block-dispatch safepoint.
///
/// The GUI scheduler requires this: it is an order of magnitude faster
/// than Steam's own 250 ms polls, so a guest spin cannot freeze the
/// guest clock or starve pending threads, timers, APCs and the live
/// watchdog for longer than this interval.
const SAFEPOINT_INTERVAL_MS: u64 = 2;
const KEYBOARD_REPLAY_ENV: &str = "CASA1_KEYBOARD_REPLAY_JSON";
const PE_RUNTIME_BUDGET_ENV: &str = "CASA1_PE_RUNTIME_BUDGET";

/// Set by the deadline watchdog thread (or the main loop) once the
/// wall-clock run deadline has elapsed.  Checked by the main loop AND by
/// `advance_runtime_steps`, so a run blocked inside nested guest callbacks
/// (message dispatch / window procs) still terminates.
pub static RUN_DEADLINE_EXPIRED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Publish the run-deadline cancellation and wake a cooperative pump blocked
/// on a guest wait/timer deadline.  The watchdog thread uses this exact path
/// so cancellation is not delayed until the next guest event.
pub(crate) fn expire_run_deadline() {
    RUN_DEADLINE_EXPIRED.store(true, std::sync::atomic::Ordering::Release);
    crate::runtime::scheduler::notify_pump_wake();
}
/// Optional wall-clock run deadline in seconds (e.g. `CASA1_PE_RUNTIME_DEADLINE_SECS=600`).
/// Steam's main loop is wait-bound and never exits on its own; the deadline
/// ends the run with exit code -2 (the timeout convention) so diagnostic
/// artifacts are still produced.  Unset means unbounded (existing behavior).
const PE_RUNTIME_DEADLINE_ENV: &str = "CASA1_PE_RUNTIME_DEADLINE_SECS";
const EXPORT_FINAL_FRAME_ENV: &str = "CASA1_EXPORT_FINAL_FRAME";
const TRACE_CATEGORIES_ENV: &str = "CASA1_TRACE_CATEGORIES";
const INSTRUCTION_CACHE_LIMIT: usize = 65_536;
const BASIC_BLOCK_CACHE_LIMIT: usize = 16_384;
const BASIC_BLOCK_MAX_INSTRUCTIONS: usize = 32;
const BASIC_BLOCK_MAX_BYTES: usize = 512;
const WINDOWS_EPOCH_OFFSET_100NS: u64 = 116_444_736_000_000_000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_READ_DATA: u32 = 0x0000_0001;
#[allow(dead_code)] // guest ABI constants (file access-rights table)
const FILE_LIST_DIRECTORY: u32 = 0x0000_0001; // alias of FILE_READ_DATA
const FILE_WRITE_DATA: u32 = 0x0000_0002;
#[allow(dead_code)] // guest ABI constants (file access-rights table)
const FILE_ADD_FILE: u32 = 0x0000_0002; // alias of FILE_WRITE_DATA
const FILE_APPEND_DATA: u32 = 0x0000_0004;
#[allow(dead_code)] // guest ABI constants (file access-rights table)
const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004; // alias of FILE_APPEND_DATA
const FILE_READ_EA: u32 = 0x0000_0008;
const FILE_WRITE_EA: u32 = 0x0000_0010;
const FILE_EXECUTE: u32 = 0x0000_0020;
const FILE_TRAVERSE: u32 = 0x0000_0020; // alias of FILE_EXECUTE
const FILE_DELETE_CHILD: u32 = 0x0000_0040;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const STANDARD_RIGHTS_REQUIRED: u32 = DELETE_ACCESS | READ_CONTROL | WRITE_DAC | WRITE_OWNER;
const FILE_GENERIC_READ: u32 =
    FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
const FILE_GENERIC_WRITE: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | READ_CONTROL
    | SYNCHRONIZE;
const FILE_GENERIC_EXECUTE: u32 = FILE_READ_ATTRIBUTES | FILE_EXECUTE | FILE_TRAVERSE | SYNCHRONIZE;
const FILE_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const CREATE_NEW: u32 = 1;
const CREATE_ALWAYS: u32 = 2;
const OPEN_EXISTING: u32 = 3;
static LIVE_UI_DEBUG_EMISSIONS: AtomicUsize = AtomicUsize::new(0);
static WINDOW_MSG_DEBUG_EMISSIONS: AtomicUsize = AtomicUsize::new(0);

fn emit_live_ui_debug(message: String) {
    if LIVE_UI_DEBUG_EMISSIONS.fetch_add(1, AtomicOrdering::Relaxed) < LIVE_UI_DEBUG_LIMIT {
        eprintln!("{message}");
    }
}

fn emit_window_msg_debug(message: String) {
    if WINDOW_MSG_DEBUG_EMISSIONS.fetch_add(1, AtomicOrdering::Relaxed) < WINDOW_MSG_DEBUG_LIMIT {
        eprintln!("{message}");
    }
}
const OPEN_ALWAYS: u32 = 4;
const TRUNCATE_EXISTING: u32 = 5;
/// Maximum UTF-16 code units accepted for a CreateFileW path. 32,768 units
/// comfortably covers `\\?\` extended-length paths.
const MAX_CREATE_FILE_PATH_UTF16_UNITS: usize = 32_768;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// FILE_FLAG_DELETE_ON_CLOSE is 0x0400_0000; 0x0800_0000 is
/// FILE_FLAG_SEQUENTIAL_SCAN and must never trigger deletion.
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
#[allow(dead_code)] // guest ABI constant (CreateFile flags table)
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_OPERATION_ABORTED: u32 = 995;
const ERROR_IO_PENDING: u32 = 997;
const ERROR_IO_INCOMPLETE: u32 = 996;
const ERROR_BROKEN_PIPE: u32 = 109;
const ERROR_PIPE_NOT_AVAILABLE: u32 = 231;
const ERROR_SEM_TIMEOUT: u32 = 121;
const ERROR_INVALID_WINDOW_HANDLE: u32 = 1_400;
const ERROR_CLASS_DOES_NOT_EXIST: u32 = 1_411;
const ERROR_CLIPBOARD_NOT_OPEN: u32 = 1_418;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_ADDRESS: u32 = 487;
const ERROR_INVALID_FUNCTION: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_SUCCESS: u32 = 0;
const ERROR_DIR_NOT_EMPTY: u32 = 145;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_ENVVAR_NOT_FOUND: u32 = 203;
const ERROR_OLD_WIN_VERSION: u32 = 1_150;
const ERROR_TIMEOUT: u32 = 1460;
const APPMODEL_ERROR_NO_PACKAGE: u32 = 15_700;
/// setupapi.dll error codes (setupapi.h / winerror.h): a property value
/// requested by `SetupDiGetDeviceRegistryPropertyW` does not exist.
const ERROR_INVALID_DATA: u32 = 13;
/// setupapi.dll error codes: the glyph outline could not be produced
/// (bitmap fonts — the runtime's font model).
const ERROR_CANNOT_COMPLETE: u32 = 1_003;
/// setupapi.dll error codes: the device information element does not name a
/// known device instance.
const ERROR_INVALID_DEVINST: u32 = 1_004;
/// setupapi.dll error codes: `SetupDiGetSelectedDriverW` when no driver is
/// selected for the device.
const ERROR_NO_DEVICE_SELECTED: u32 = 575;
/// setupapi.dll error codes: an SP_DEVINFO_DATA buffer smaller than the
/// struct size.
const ERROR_INVALID_USER_BUFFER: u32 = 1_784;
/// GDI error return value (`GetGlyphOutlineW` failure).
const GDI_ERROR: u32 = 0xFFFF_FFFF;
const VER_MINORVERSION: u32 = 0x0000_0001;
const VER_MAJORVERSION: u32 = 0x0000_0002;
const VER_BUILDNUMBER: u32 = 0x0000_0004;
const VER_PLATFORMID: u32 = 0x0000_0008;
const VER_SERVICEPACKMINOR: u32 = 0x0000_0010;
const VER_SERVICEPACKMAJOR: u32 = 0x0000_0020;
const VER_SUITENAME: u32 = 0x0000_0040;
const VER_PRODUCT_TYPE: u32 = 0x0000_0080;
const VER_EQUAL: u8 = 1;
const VER_GREATER: u8 = 2;
const VER_GREATER_EQUAL: u8 = 3;
const VER_LESS: u8 = 4;
const VER_LESS_EQUAL: u8 = 5;
const VER_AND: u8 = 6;
const VER_OR: u8 = 7;
const VER_PLATFORM_WIN32_NT: u32 = 2;
const VER_NT_WORKSTATION: u8 = 1;
const OSVERSIONINFOW_SIZE: u32 = 20;
const OSVERSIONINFOEXW_SIZE: u32 = 284;
const LOCALE_EN_US: u32 = 0x0409;
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

// ── CRT errno values (MSVC errno.h numbering) ────────────────────────────────
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EPERM: i32 = 1;
const ENOENT: i32 = 2;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ESRCH: i32 = 3;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EINTR: i32 = 4;
const EIO: i32 = 5;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENXIO: i32 = 6;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const E2BIG: i32 = 7;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENOEXEC: i32 = 8;
const EBADF: i32 = 9;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ECHILD: i32 = 10;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EAGAIN: i32 = 11;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EFAULT: i32 = 14;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EXDEV: i32 = 18;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENODEV: i32 = 19;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENOTDIR: i32 = 20;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENFILE: i32 = 23;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EMFILE: i32 = 24;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENOTTY: i32 = 25;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EFBIG: i32 = 27;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENOSPC: i32 = 28;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ESPIPE: i32 = 29;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EROFS: i32 = 30;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EMLINK: i32 = 31;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EPIPE: i32 = 32;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EDOM: i32 = 33;
const ERANGE: i32 = 34;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const EDEADLK: i32 = 36;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENAMETOOLONG: i32 = 38;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENOLCK: i32 = 39;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENOSYS: i32 = 40;
#[allow(dead_code)] // MSVC CRT errno ABI constants (errno table) for guest CRT emulation
const ENOTEMPTY: i32 = 41;
/// `_TRUNCATE` sentinel for the `*_s` string functions (x86 `size_t` is 32-bit).
const CRTT_TRUNCATE: u64 = 0xFFFF_FFFF;
/// `_TRUNCATE` as a full-width `size_t` (x64 guests).
const CRTT_TRUNCATE_64: u64 = u64::MAX;
// ── CRT stat mode bits (_stat structs) ───────────────────────────────────────
#[allow(dead_code)] // MSVC CRT stat mode ABI constants
const S_IFMT: u32 = 0xF000;
const S_IFDIR: u32 = 0x4000;
#[allow(dead_code)] // MSVC CRT stat mode ABI constants
const S_IFCHR: u32 = 0x2000;
const S_IFREG: u32 = 0x8000;
const S_IREAD: u32 = 0x0100;
const S_IWRITE: u32 = 0x0080;
#[allow(dead_code)] // MSVC CRT stat mode ABI constants
const S_IEXEC: u32 = 0x0040;
// ── CRT stdio constants ──────────────────────────────────────────────────────
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;
const EOF: i32 = -1;
/// Access-mode bits used by `_access`/`_waccess`.
const ACCESS_EXISTS: i32 = 0;
const ACCESS_WRITE: i32 = 2;
const ACCESS_READ: i32 = 4;
const ACCESS_READ_WRITE: i32 = 6;
/// Maximum element size accepted by the CRT qsort shim (bytes).
const CRT_QSORT_MAX_ELEMENT_SIZE: usize = 4096;
/// Maximum element count accepted by the CRT qsort shim.
const CRT_QSORT_MAX_COUNT: usize = 1 << 20;

type U64Map<V> = HashMap<u64, V, U64IdentityBuildHasher>;

/// One directly-patched guest IAT slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatPatchEntry {
    /// Guest virtual address of the IAT slot.
    pub slot_va: u64,
    /// Main image base used to turn `iat_rva` back into a slot address.
    pub selected_base: u64,
    /// IAT RVA inside the selected image.
    pub iat_rva: u32,
    pub module: String,
    pub symbol: ImportSymbol,
    /// Thunk address written by normal import binding.
    pub bound_value: u64,
    /// Value currently installed in the slot by the patch table.
    pub patched_value: u64,
    pub module_handle: u64,
}

/// Registry of stable guest IAT slots that currently contain a direct host
/// thunk address.  The guest IAT itself stays in guest memory and remains
/// readable/writable; this table mirrors the writes so a replaced thunk can be
/// propagated and a module unload can invalidate (re-arm) the slot.
#[derive(Debug, Clone, Default)]
pub struct IatPatchTable {
    entries: BTreeMap<u64, IatPatchEntry>,
    patched_targets: BTreeSet<u64>,
    pub(crate) patched: u64,
    pub(crate) dispatch_bypasses: u64,
    pub(crate) repatched: u64,
    pub(crate) invalidated: u64,
}

/// Public view of the IAT patch counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IatMetrics {
    pub patched: u64,
    pub dispatch_bypasses: u64,
    pub repatched: u64,
    pub invalidated: u64,
    /// Explicit audit metric aliases.
    pub iat_patched: u64,
    pub iat_dispatch_bypasses: u64,
}

impl IatPatchTable {
    /// Record or replace a patch.  Returns true when the slot was newly
    /// patched (an idempotent re-record returns false).
    pub fn patch(&mut self, entry: IatPatchEntry) -> bool {
        let slot = entry.slot_va;
        let target = entry.patched_value;
        if let Some(previous) = self.entries.get_mut(&slot) {
            if previous.patched_value != target {
                self.patched_targets.remove(&previous.patched_value);
                self.patched_targets.insert(target);
                previous.patched_value = target;
                previous.bound_value = entry.bound_value;
                previous.module = entry.module;
                previous.symbol = entry.symbol;
                previous.module_handle = entry.module_handle;
            }
            return false;
        }
        self.patched_targets.insert(target);
        self.entries.insert(slot, entry);
        self.patched += 1;
        true
    }

    pub fn unpatch(&mut self, slot_va: u64) -> Option<IatPatchEntry> {
        let entry = self.entries.remove(&slot_va)?;
        self.patched_targets.remove(&entry.patched_value);
        Some(entry)
    }

    /// Replace every slot that still holds `old` with `new`.  Returns the
    /// affected slot addresses so the caller can write guest memory.
    pub fn repatch(&mut self, old: u64, new: u64) -> Vec<u64> {
        let mut slots = Vec::new();
        for entry in self.entries.values_mut() {
            if entry.patched_value == old {
                entry.patched_value = new;
                slots.push(entry.slot_va);
            }
        }
        if self.patched_targets.remove(&old) {
            self.patched_targets.insert(new);
        }
        self.repatched += slots.len() as u64;
        slots
    }

    /// Slots bound to a module handle, in ascending slot order.
    pub fn slots_for_module(&self, handle: u64) -> Vec<u64> {
        self.entries
            .values()
            .filter(|entry| entry.module_handle == handle)
            .map(|entry| entry.slot_va)
            .collect()
    }

    /// Slots whose current patched target is `target`.
    pub fn slots_for_target(&self, target: u64) -> Vec<u64> {
        self.entries
            .values()
            .filter(|entry| entry.patched_value == target)
            .map(|entry| entry.slot_va)
            .collect()
    }

    /// Replace one slot's patched target (the caller has verified the guest
    /// slot still holds the old value).
    pub fn set_patched_value(&mut self, slot_va: u64, new: u64) -> bool {
        let Some(entry) = self.entries.get_mut(&slot_va) else {
            return false;
        };
        let old = entry.patched_value;
        if old == new {
            return false;
        }
        entry.patched_value = new;
        self.patched_targets.remove(&old);
        self.patched_targets.insert(new);
        self.repatched += 1;
        true
    }

    pub fn is_patched_target(&self, target: u64) -> bool {
        self.patched_targets.contains(&target)
    }

    pub fn record_dispatch(&mut self, target: u64) -> bool {
        if self.patched_targets.contains(&target) {
            self.dispatch_bypasses += 1;
            true
        } else {
            false
        }
    }

    pub fn entry(&self, slot_va: u64) -> Option<&IatPatchEntry> {
        self.entries.get(&slot_va)
    }

    pub fn symbol_name(entry: &IatPatchEntry) -> String {
        match &entry.symbol {
            ImportSymbol::ByName { name, .. } => name.clone(),
            ImportSymbol::ByOrdinal { ordinal } => format!("ordinal#{ordinal}"),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn metrics(&self) -> IatMetrics {
        IatMetrics {
            patched: self.patched,
            dispatch_bypasses: self.dispatch_bypasses,
            repatched: self.repatched,
            invalidated: self.invalidated,
            iat_patched: self.patched,
            iat_dispatch_bypasses: self.dispatch_bypasses,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct U64IdentityBuildHasher;

#[derive(Default)]
pub(crate) struct U64IdentityHasher(u64);

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
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_SHARING_VIOLATION: u32 = 32;
const ERROR_LOCK_VIOLATION: u32 = 33;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_UNKNOWN_REVISION: u32 = 1305;
const STILL_ACTIVE: u32 = 259;
const GET_MODULE_HANDLE_EX_FLAG_PIN: u32 = 0x0000_0001;
const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x0000_0002;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x0000_0004;
const INIT_ONCE_CHECK_ONLY: u32 = 0x0000_0001;
const INIT_ONCE_INIT_FAILED: u32 = 0x0000_0004;
const IDOK: i32 = 1;
const IDCANCEL: i32 = 2;
#[allow(dead_code)]
const IDABORT: i32 = 3;
const IDRETRY: i32 = 4;
const IDIGNORE: i32 = 5;
const IDYES: i32 = 6;
#[allow(dead_code)]
const IDNO: i32 = 7;
#[allow(dead_code)]
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
#[allow(dead_code)]
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
const DEFAULT_SECURITY_COOKIE_X86: u64 = 0xbb40_e64e;
const DEFAULT_SECURITY_COOKIE_X64: u64 = 0x0000_2b99_2ddf_a232;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;
const INVALID_FILE_ATTRIBUTES: u64 = 0xFFFF_FFFF;
const INVALID_SET_FILE_POINTER: u64 = 0xFFFF_FFFF;
const STD_INPUT_HANDLE: u32 = u32::MAX - 9;
const STD_OUTPUT_HANDLE: u32 = u32::MAX - 10;
const STD_ERROR_HANDLE: u32 = u32::MAX - 11;
const FILE_TYPE_UNKNOWN: u32 = 0;
#[allow(dead_code)] // guest ABI constant (GetFileType table)
const FILE_TYPE_DISK: u32 = 1;
const FILE_TYPE_CHAR: u32 = 2;
const PROCESS_HEAP_HANDLE: u64 = 0x1000;
const RTL_USER_PROCESS_PARAMETERS_NORMALIZED: u32 = 0x0000_0001;
const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const DRIVE_UNKNOWN: u32 = 0;
const WIN32_FIND_DATAW_FILE_NAME_CHARS: usize = 260;
const WIN32_FIND_DATAW_ALT_FILE_NAME_CHARS: usize = 14;

/// Maximum character size (bytes per char) of a Windows code page the
/// runtime recognizes, or `None` for unknown/invalid code pages.
///
/// The recognized set is the canonical Windows NLS code page table: the
/// ANSI SBCS pages (1250–1258), the OEM SBCS pages, the East-Asian DBCS
/// pages (932/936/949/950), and UTF-8 (65001).  The runtime's conversions
/// (wide_char_to_multi_byte / multi_byte_to_wide_char) route every
/// non-ACP/UTF-8 page through iconv, so a page recognized here can be
/// converted.
fn guest_code_page_max_char_size(code_page: u32) -> Option<u32> {
    match code_page {
        // ANSI single-byte pages.
        1250..=1258 => Some(1),
        // OEM single-byte pages (including Thai 874).
        437 | 708 | 720 | 737 | 775 | 850 | 852 | 855 | 857 | 858 | 860 | 861 | 862 | 863 | 864
        | 865 | 866 | 869 | 874 => Some(1),
        // East-Asian double-byte pages.
        932 | 936 | 949 | 950 => Some(2),
        // UTF-8 (up to 4 bytes per code point).
        65001 => Some(4),
        _ => None,
    }
}

/// Real host memory figures for `GlobalMemoryStatusEx`
/// (total/available physical and page-file bytes).
///
/// Queried from the host via `sysctlbyname` (hw.memsize, hw.pagesize,
/// vm.page_free_count, vm.swapusage); falls back to the previous fixed
/// figures when the host cannot be queried.  Returns
/// (total_phys, avail_phys, total_page, avail_page).
fn host_memory_status() -> (u64, u64, u64, u64) {
    // Defaults: the fixed figures previously reported.
    let mut total_phys: u64 = 16 * 1024 * 1024 * 1024;
    let mut avail_phys: u64 = 8 * 1024 * 1024 * 1024;

    // SAFETY: sysctlbyname with a well-formed NUL-terminated name and a
    // caller-sized output buffer; the kernel validates the MIB name.
    let (total_page, avail_page) = unsafe {
        let sysctl_u64 = |name: &str| -> Option<u64> {
            let c_name = std::ffi::CString::new(name).ok()?;
            let mut len: libc::size_t = 0;
            if libc::sysctlbyname(
                c_name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            ) != 0
                || len == 0
            {
                return None;
            }
            let mut buf = vec![0u8; len];
            if libc::sysctlbyname(
                c_name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return None;
            }
            match buf.len() {
                8 => Some(u64::from_le_bytes(buf.try_into().unwrap())),
                4 => Some(u32::from_le_bytes(buf.try_into().unwrap()) as u64),
                _ => None,
            }
        };

        if let Some(memsize) = sysctl_u64("hw.memsize") {
            total_phys = memsize.max(1);
        }
        let page_size = sysctl_u64("hw.pagesize").unwrap_or(4096).max(1);
        if let Some(free_pages) = sysctl_u64("vm.page_free_count") {
            avail_phys = free_pages.saturating_mul(page_size).min(total_phys);
        }
        // vm.swapusage is struct xsw_usage { xsu_total, xsu_avail, ... }
        // — the first two u64 fields are total and available swap bytes.
        match (|| {
            let c_name = std::ffi::CString::new("vm.swapusage").ok()?;
            let mut len: libc::size_t = 0;
            if libc::sysctlbyname(
                c_name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            ) != 0
                || len < 16
            {
                return None;
            }
            let mut buf = vec![0u8; len];
            if libc::sysctlbyname(
                c_name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return None;
            }
            Some(buf)
        })() {
            Some(raw) => {
                let swap_total = u64::from_le_bytes(raw[0..8].try_into().unwrap());
                let swap_avail = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                let total = total_phys.saturating_add(swap_total).max(1);
                let available = avail_phys.saturating_add(swap_avail).min(total);
                (total, available)
            }
            None => {
                let total = total_phys.saturating_mul(2).max(1);
                (total, avail_phys.min(total))
            }
        }
    };
    (total_phys, avail_phys, total_page, avail_page)
}

/// How a PE execution ended.  The structured termination is authoritative;
/// `exit_code` keeps its legacy meaning (-2 for harness cancellation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExecutionTermination {
    /// The guest exited normally (ExitProcess / main-thread return).
    GuestExit { code: i32 },
    /// The host run deadline (CASA1_PE_RUNTIME_DEADLINE_SECS) cancelled the
    /// run: harness cancellation, never a fake guest result.
    HarnessDeadline,
    /// The instruction budget was exhausted.
    InstructionBudget,
    /// An unsupported/unimplemented guest instruction was reached.
    UnsupportedInstruction,
    /// An unhandled guest exception (fault) terminated the run.
    GuestException,
    /// Any other host-side error.
    HostError,
}

pub struct PeExecutionResult {
    pub synthetic_pid: u32,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub guest_exceptions: Vec<GuestException>,
    pub gfx_frames: Vec<GfxFrame>,
    pub perf: Vec<PerfMetric>,
    pub trace_events: Vec<TraceEvent>,
    /// Steam run instrumentation: milestone counters and first-failure
    /// records snapshotted from the shared static at the end of the run.
    pub milestones: crate::steam_milestones::SteamMilestones,
    /// Steam run instrumentation: self-identifying run provenance (env-side
    /// fields; content hashes are filled in by the runner for Steam jobs).
    pub provenance: crate::steam_milestones::RunProvenance,
    /// Authoritative termination reason.
    pub termination: ExecutionTermination,
    /// Error detail for non-guest terminations (message of the underlying
    /// error when one exists).
    pub termination_detail: Option<String>,
    /// JIT telemetry: requested mode, activity, and block counters.
    pub jit_telemetry: JitTelemetry,
}

/// Legacy exit code for a termination (kept for compatibility: harness
/// cancellation and budget exhaustion both map to -2).
pub fn legacy_exit_code(termination: ExecutionTermination) -> i32 {
    match termination {
        ExecutionTermination::GuestExit { code } => code,
        ExecutionTermination::HarnessDeadline | ExecutionTermination::InstructionBudget => -2,
        ExecutionTermination::UnsupportedInstruction
        | ExecutionTermination::GuestException
        | ExecutionTermination::HostError => -2,
    }
}

impl ExecutionTermination {
    /// Stable machine-readable variant name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::GuestExit { .. } => "GuestExit",
            Self::HarnessDeadline => "HarnessDeadline",
            Self::InstructionBudget => "InstructionBudget",
            Self::UnsupportedInstruction => "UnsupportedInstruction",
            Self::GuestException => "GuestException",
            Self::HostError => "HostError",
        }
    }
}

/// JIT telemetry block reported with every PE execution result and Steam
/// bootstrap artifact: what the caller requested, whether the JIT machinery
/// actually ran, and why it fell back to the AOT interpreter when it did not.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct JitTelemetry {
    /// Requested mode: "auto" | "enabled" | "disabled".
    pub requested: String,
    /// True when JIT-compiled blocks actually executed during the run.
    pub active: bool,
    pub blocks_compiled: u64,
    pub blocks_executed: u64,
    /// Reason the JIT stayed inactive despite being requested (e.g. the
    /// macOS 26 MAP_JIT restriction for ad-hoc-signed binaries).
    pub fallback_reason: Option<String>,
    /// Total IR instructions lowered to native ARM64 emission while compiling
    /// blocks (per-opcode detail in `JIT_NATIVE_LOWERED`, summed here).
    #[serde(default)]
    pub native_lowered: u64,
    /// Total IR instructions executed through the universal interpreter
    /// helper (`jit_helper_execute_insn`, one instruction per call) instead
    /// of native lowering.
    #[serde(default)]
    pub helper_fallback: u64,
    /// Install/update AOT pipeline counters: persisted profile targets
    /// loaded, blocks precompiled before entry, AOT hits/misses/rejections,
    /// and profile targets written after the run.
    #[serde(default)]
    pub aot: Option<crate::jit::AotRunSummary>,
}

impl Default for JitTelemetry {
    fn default() -> Self {
        Self {
            requested: "auto".to_string(),
            active: false,
            blocks_compiled: 0,
            blocks_executed: 0,
            fallback_reason: None,
            native_lowered: 0,
            helper_fallback: 0,
            aot: None,
        }
    }
}

impl JitTelemetry {
    pub(crate) fn from_mode(
        mode: &crate::runner::JitMode,
        blocks_compiled: u64,
        blocks_executed: u64,
        native_lowered: u64,
        helper_fallback: u64,
    ) -> Self {
        let requested = mode.as_str().to_string();
        let active = blocks_compiled > 0 || blocks_executed > 0;
        let fallback_reason = if matches!(mode, crate::runner::JitMode::Enabled) && !active {
            Some(
                "macos-26-map-jit-dormant: MAP_JIT execution is blocked for \
                 ad-hoc-signed binaries — JIT stays inactive, the AOT interpreter executes"
                    .to_string(),
            )
        } else {
            None
        };
        Self {
            requested,
            active,
            blocks_compiled,
            blocks_executed,
            fallback_reason,
            native_lowered,
            helper_fallback,
            aot: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct PeExecutionOptions {
    pub live_session: Option<LivePeSession>,
    /// JIT policy requested by the caller (None = Auto).
    pub jit_mode: Option<crate::runner::JitMode>,
    /// When true, the SteamService named-pipe listener is created before the
    /// guest runs so a Steam client can connect to it.
    pub steam_ipc: bool,
    /// Generic runtime-event observers attached for the duration of the run
    /// (the Steam workload passes its `SteamMilestoneObserver` here; empty
    /// by default — the runtime works perfectly with no observer attached).
    pub observers: Vec<Box<dyn crate::runtime_events::RuntimeObserver>>,
    /// Named-pipe listeners pre-created before the guest runs (generic
    /// workload workaround for services the workload cannot execute — see
    /// [`crate::win32::NamedPipeService::create_compat_listener`]).
    pub compat_named_pipes: Vec<String>,
    /// Optional first-thread start routine/parameter for a child created by
    /// `NtCreateProcess` + `NtCreateThreadEx` (the runner job's
    /// `thread_start`): the guest begins executing at this preferred-base
    /// address with this thread parameter instead of the image entry point,
    /// exactly like the Windows thread-start semantics.  `None` for every
    /// ordinary run.
    pub thread_start: Option<(u64, u64)>,
    /// Scheduler mode requested by the caller.  `None` keeps the deterministic
    /// cooperative scheduler (byte-identical single-host-thread execution);
    /// `Some(workers)` runs ready guest threads concurrently on a bounded pool
    /// of native host workers (real parallel JIT slice execution, with host
    /// thunks and process-wide subsystems serialized through
    /// `ProcessShared`).  `CASA1_SCHEDULER` / `CASA1_SCHEDULER_WORKERS` remain
    /// as a host-environment override when this is `None`.
    pub scheduler_workers: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KeyboardReplayEvent {
    scancode: u16,
    #[serde(default)]
    shift: bool,
    #[serde(default)]
    altgr: bool,
}

/// A single Windows menu item
#[derive(Debug, Clone)]
struct MenuItem {
    id: u32,
    flags: u32,
    text: String,
    sub_menu: Option<u32>,
    state: u32,
}

/// A Windows menu (HMENU)
#[derive(Debug, Clone)]
#[allow(dead_code)] // menu state retained for future menu APIs
pub(crate) struct Menu {
    handle: u32,
    items: Vec<MenuItem>,
    is_popup: bool,
}

/// Scrollbar state for a window's horizontal or vertical scrollbar
#[derive(Debug, Clone)]
pub(crate) struct ScrollBarInfo {
    pub min: i32,
    pub max: i32,
    pub pos: i32,
    pub page: i32,
    pub enabled: bool,
    pub visible: bool,
}

/// Represents a common control window's state
#[derive(Debug, Clone)]
#[allow(dead_code)] // common-control state retained for future control APIs
pub(crate) struct CommonControlState {
    /// Registered class name
    class_name: String,
    /// Control-specific data stored as serialized bytes
    data: Vec<u8>,
}

/// Holds ImageList metadata
#[derive(Debug, Clone)]
pub(crate) struct ImageListInfo {
    pub image_count: i32,
    pub image_width: i32,
    pub image_height: i32,
    pub flags: u32,
    pub images: Vec<Vec<u8>>,
}

/// Outcome of one [`PeHostRuntime::get_message_pump`] iteration — the
/// shared retrieval loop behind `GetMessageW` and `GetMessageA`.
pub(crate) enum GetMessagePumpOutcome {
    /// A message was retrieved from the thread's queue and written into the
    /// guest MSG structure; the caller applies the API-specific result and
    /// trace.
    Retrieved(Message),
    /// A pumped guest thread (or timer callback) requested process exit;
    /// the caller must propagate the code so the run terminates.
    ProcessExit(i32),
    /// No message was available and the scheduler was serviced (guest
    /// threads pumped, timers fired, callbacks drained); the caller loops
    /// and tries again.
    Idle,
}

impl Default for ProgressBarState {
    fn default() -> Self {
        Self {
            min: 0,
            max: 100,
            pos: 0,
            step: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// #[cfg(test)] helpers — accessible from integration tests via casa1::pe_runtime
// ---------------------------------------------------------------------------

/// Execute Steam.exe from the `steam-live-run-x86` GE with deterministic mode
/// and a configurable instruction budget.
///
/// This function opens the GE, resolves the Steam.exe host path, builds the
/// environment map, and calls [`execute_with_options`].  The caller receives
/// the full [`PeExecutionResult`] and can inspect trace events, exit code, etc.
///
/// # Panics
/// Panics if the GE cannot be opened or Steam.exe is not found.
#[doc(hidden)]
pub fn regression_test_steam_bootstrap(
    budget: u64,
    dtm: bool,
    trace_categories: Option<&[&str]>,
) -> PeExecutionResult {
    use crate::ge::GameEnvironment;

    let ge = GameEnvironment::open("steam-live-run-x86")
        .expect("failed to open steam-live-run-x86 GE — is the workspace correct?");

    let steam_host_path = ge.root.join("drive_c").join("Steam.exe");
    assert!(
        steam_host_path.is_file(),
        "Steam.exe not found at {} — check GE contents",
        steam_host_path.display()
    );

    let mut env = BTreeMap::new();
    env.insert("CASA1_PE_RUNTIME_BUDGET".to_string(), budget.to_string());
    if let Some(categories) = trace_categories {
        env.insert("CASA1_TRACE_CATEGORIES".to_string(), categories.join(","));
    }

    let options = PeExecutionOptions::default();

    execute_with_options(
        &steam_host_path,
        &[], // no command-line arguments
        &ge,
        &ge.root.join("drive_c"), // cwd
        &env,
        dtm,
        "regression_test_steam_bootstrap",
        options,
    )
    .expect("Steam.exe execution failed")
}

// ---------------------------------------------------------------------------
// C ABI bridge for fast-thunk dispatch
// ---------------------------------------------------------------------------

/// C ABI bridge called by the ARM64 fast-thunk trampoline.
///
/// # Arguments (ARM64 C ABI)
/// - `x0 = runtime_ptr`:   raw pointer to the [`PeHostRuntime`] instance
/// - `x1 = state_ptr`:     raw pointer to the [`CpuState`]
/// - `x2 = memory_ptr`:    raw pointer to the [`MemoryImage`]
/// - `x3 = thunk_address`: the guest thunk address being dispatched
///
/// # Returns
/// - `-1`  → "continue execution" (no exit code)
/// - `-2`  → "error during dispatch"
/// - `>=0` → guest exit code
// SAFETY: extern FFI declaration — the function signature matches the C library prototype
#[allow(dead_code)] // legacy fast-thunk dispatcher (path disabled — see 54243); flagged for the API database
unsafe extern "C" fn fast_thunk_host_dispatcher(
    runtime_ptr: *mut std::ffi::c_void,
    state_ptr: *mut CpuState,
    memory_ptr: *mut MemoryImage,
    thunk_address: u64,
) -> i32 {
    // SAFETY: guest memory access and FFI for PE runtime emulation
    unsafe {
        let runtime = &mut *(runtime_ptr as *mut PeHostRuntime);
        let state = &mut *state_ptr;
        let memory = &mut *memory_ptr;
        match runtime.dispatch_import(thunk_address, state, memory) {
            Ok(Some(code)) => code,
            Ok(None) => -1, // Continue
            Err(_) => -2,   // Error
        }
    }
}

/// Read a D3D11_TEXTURE1D_DESC from guest memory and return the width and format.
fn read_d3d11_texture1d_desc(memory: &MemoryImage, desc_ptr: u64) -> AppResult<D3d11Texture1dDesc> {
    let width = memory.read_u32(desc_ptr)?;
    let format_raw = memory.read_u32(desc_ptr + 12)?;
    Ok(D3d11Texture1dDesc {
        width,
        // Guest-facing production path: never substitute an unsupported
        // format — reject with an explicit error.
        format: DxgiFormat::from_u32_checked(format_raw)?,
    })
}

/// Read a D3D11_TEXTURE3D_DESC from guest memory and return key fields.
fn read_d3d11_texture3d_desc(memory: &MemoryImage, desc_ptr: u64) -> AppResult<D3d11Texture3dDesc> {
    let width = memory.read_u32(desc_ptr)?;
    let height = memory.read_u32(desc_ptr + 4)?;
    let depth = memory.read_u32(desc_ptr + 8)?;
    let format_raw = memory.read_u32(desc_ptr + 16)?;
    Ok(D3d11Texture3dDesc {
        width,
        height,
        depth,
        // Guest-facing production path: never substitute an unsupported
        // format — reject with an explicit error.
        format: DxgiFormat::from_u32_checked(format_raw)?,
    })
}

struct D3d11Texture1dDesc {
    width: u32,
    format: DxgiFormat,
}

struct D3d11Texture3dDesc {
    width: u32,
    height: u32,
    depth: u32,
    format: DxgiFormat,
}

/// Exact JIT construction rule (single source of truth for `set_guest_arch`).
///
/// - `Disabled` never constructs the JIT runtime.
/// - `Enabled` is an explicit caller override: it constructs the runtime
///   regardless of the probe result and regardless of deterministic mode.
/// - `Auto` constructs the runtime iff the executable-memory capability probe
///   actually executed its ARM64 stub AND the run is not deterministic
///   (`dtm`, i.e. replay/record mode).  Deterministic runs therefore stay
///   interpreter-only under `Auto`, preserving byte-for-byte replay
///   behaviour and host-independent timing.
pub(crate) fn jit_construction_selected(
    mode: &crate::runner::JitMode,
    deterministic: bool,
    capability_available: bool,
) -> bool {
    match mode {
        crate::runner::JitMode::Disabled => false,
        crate::runner::JitMode::Enabled => true,
        crate::runner::JitMode::Auto => capability_available && !deterministic,
    }
}

impl Drop for PeHostRuntime {
    fn drop(&mut self) {
        // Unregister the process-wide current-observer slot only when it
        // still points at THIS runtime's list (a concurrently-created
        // runtime must not be clobbered).
        crate::runtime_events::clear_current_observers(&self.observers);
        crate::cef_bridge::set_event_observers(None);
        crate::media::clear_mf_async_state(self.guest_pid);
        crate::driver_island::forget_runtime(self);
        // Drop inline-API target registrations that pointed at this runtime's
        // thunk range.  A concurrently live runtime with the same synthetic
        // address range would re-register on its own binding path.
        let owner = self as *const PeHostRuntime as u64;
        for address in self.host_thunks.keys().copied().collect::<Vec<_>>() {
            crate::jit::unregister_inline_api_target(address, owner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::Operand;
    use crate::ge::{FileAccess, GameEnvironment, GeArch, ShareMode};
    use crate::gfx::{GraphicsBackend, host_gpu_profile_from_name};
    use crate::pe::{ExportSymbol, ExportTarget};
    use tempfile::TempDir;

    #[path = "support.rs"]
    mod support;

    #[path = "clr.rs"]
    mod clr;
    #[path = "com.rs"]
    mod com;
    #[path = "files.rs"]
    mod files;
    #[path = "gdi.rs"]
    mod gdi;
    #[path = "gpu.rs"]
    mod gpu;
    #[path = "kernel.rs"]
    mod kernel;
    #[path = "media.rs"]
    mod media;
    #[path = "memory.rs"]
    mod memory;
    #[path = "misc.rs"]
    mod misc;
    #[path = "network.rs"]
    mod network;
    #[path = "process.rs"]
    mod process;
    #[path = "registry.rs"]
    mod registry;
    #[path = "user.rs"]
    mod user;

    fn read_guest_utf16_string(memory: &MemoryImage, address: u64, max_units: usize) -> String {
        let mut units = Vec::new();
        for index in 0..max_units {
            let unit =
                read_guest_u16(memory, address + (index as u64 * 2)).expect("read utf16 code unit");
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16(&units).expect("decode utf16 string")
    }
}
