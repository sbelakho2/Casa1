//! Worker-side execution of the concurrency-safe host API subset.
//!
//! A production worker that reaches a host thunk normally stops with a host
//! barrier and lets the runtime owner execute it.  This module classifies the
//! thunk surface and implements the small, deliberately conservative subset
//! that is safe to execute *on the worker itself*:
//!
//! * stateless calls read only the calling thread's
//!   [`GuestThreadContext`](super::super::GuestThreadContext) and constant
//!   data (clock/time, thread/process identity, last-error, CPU features,
//!   pure formatting helpers), and
//! * read-mostly calls read process-wide values the owner publishes behind
//!   per-subsystem `RwLock`s (version, system/CPU information, memory
//!   status).
//!
//! Everything else — loader, registry, handles, allocation, GPU, COM, TPM,
//! driver island — remains owner-only and is still executed exactly once on
//! the existing host-barrier path.
//!
//! The worker implementation mirrors the owner's dispatch arms byte for
//! byte, including x86 stdcall argument cleanup and the per-thread
//! last-error slot.  A failure to reproduce an owner path (missing published
//! version, guest memory that the worker view cannot service) returns the
//! barrier verdict rather than guessing.

use super::super::{
    ABBR_MONTHS, ABBR_WEEKDAYS, C1_ALPHA, C1_DIGIT, C1_LOWER, C1_SPACE, C1_UPPER, CP_ACP,
    CT_CTYPE1, ERROR_ENVVAR_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_PATH_NOT_FOUND, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
    FILE_TYPE_CHAR, FILE_TYPE_UNKNOWN, FULL_MONTHS, FULL_WEEKDAYS, GuestThreadContext,
    HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS,
    HostThunk, KEY_WOW64_32KEY, KEY_WOW64_64KEY, PROCESS_HEAP_HANDLE, ProcessShared,
    STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, WINDOWS_EPOCH_OFFSET_100NS,
    WorkerLocale, WorkerRegistry, WorkerRegistryKey, WorkerVersion, civil_day_of_week,
    classify_wide_char_type, current_guest_utc_components, current_host_ticks_100ns,
    current_host_time_zone_information, encode_registry_value_data,
    encode_registry_value_data_ansi, filetime_ticks_to_systemtime, guest_code_page_max_char_size,
    is_processor_feature_present, local_timezone_bias_minutes, locale_name_to_lcid,
    normalize_registry_runtime_key, registry_value_type_to_win32, resolve_full_guest_path,
    shlwapi_format_time_interval, systemtime_to_filetime_ticks, windows_file_part_offset,
};
use super::{BarrierReason, WorkerCategory};
use crate::cpu::{GuestArch, Register};
use crate::host_thunks::ThunkConcurrency;
use crate::jit::GuestSliceMemory;
use crate::win32::{CP_THREAD_ACP, CP_UTF8, cp1252_uppercase};
use std::cell::Cell;

/// The concurrency-safe worker implementation of one host thunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerApi {
    GetLastError,
    SetLastError,
    GetCurrentThreadId,
    GetCurrentThread,
    GetCurrentProcessId,
    GetCurrentProcess,
    GetTickCount,
    GetTickCount64,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    GetSystemTimeAsFileTime,
    GetSystemTimePreciseAsFileTime,
    GetVersion,
    GetVersionExW,
    GetVersionExA,
    IsWow64Process,
    GetSystemInfo,
    GetNativeSystemInfo,
    GlobalMemoryStatusEx,
    IsProcessorFeaturePresent,
    CharNextW,
    CharPrevW,
    StrFromTimeIntervalW,
    Strlen,
    LstrlenW,
    LstrcmpW,
    LstrcmpiW,
    CompareStringW,
    MultiByteToWideChar,
    WideCharToMultiByte,
    GetACP,
    GetOEMCP,
    GetCPInfo,
    IsValidCodePage,
    LocaleNameToLCID,
    GetProcessHeap,
    GetProcessHeaps,
    HeapSize,
    GetTimeZoneInformation,
    GetDateFormatW,
    GetTimeFormatW,
    GetEnvironmentVariableW,
    RegQueryValueExA,
    RegQueryValueExW,
    GetFileAttributesW,
    GetFileAttributesA,
    GetFileAttributesExW,
    GetFileSize,
    GetFileSizeEx,
    GetSystemTime,
    GetComputerNameW,
    TlsGetValue,
    FlsGetValue,
    InterlockedIncrement,
    InterlockedDecrement,
    InterlockedExchangeAdd,
    GetExitCodeThread,
    GetExitCodeProcess,
    GetThreadPriority,
    RegEnumKeyExW,
    RegEnumValueW,
    RegQueryInfoKeyW,
    ShRegGetValueW,
    LcMapStringW,
    LcMapStringEx,
    CharUpperW,
    IsCharAlphaW,
    IsCharAlphaNumericW,
    IsCharLowerW,
    IsCharUpperW,
    IsCharSpaceW,
    TlsSetValue,
    FlsSetValue,
    SystemTimeToTzSpecificLocalTime,
    GetSystemMetrics,
    GetFullPathNameW,
    GetLongPathNameW,
    GetShortPathNameW,
    GetFileType,
}

impl WorkerApi {
    pub(crate) const fn class(self) -> ThunkConcurrency {
        match self {
            Self::GetVersion
            | Self::GetVersionExW
            | Self::GetVersionExA
            | Self::GetSystemInfo
            | Self::GetNativeSystemInfo
            | Self::GlobalMemoryStatusEx
            | Self::IsWow64Process
            | Self::MultiByteToWideChar
            | Self::WideCharToMultiByte
            | Self::GetACP
            | Self::GetOEMCP
            | Self::HeapSize
            | Self::GetEnvironmentVariableW
            | Self::RegQueryValueExA
            | Self::RegQueryValueExW
            | Self::GetFileAttributesW
            | Self::GetFileAttributesA
            | Self::GetFileAttributesExW
            | Self::GetFileSize
            | Self::GetFileSizeEx
            | Self::GetExitCodeThread
            | Self::GetExitCodeProcess
            | Self::GetThreadPriority
            | Self::RegEnumKeyExW
            | Self::RegEnumValueW
            | Self::RegQueryInfoKeyW
            | Self::ShRegGetValueW
            | Self::GetSystemMetrics
            | Self::GetFullPathNameW
            | Self::GetLongPathNameW
            | Self::GetShortPathNameW
            | Self::GetFileType => ThunkConcurrency::ReadMostly,
            _ => ThunkConcurrency::Stateless,
        }
    }

    pub(crate) const fn category(self) -> WorkerCategory {
        match self {
            Self::GetLastError
            | Self::SetLastError
            | Self::GetCurrentThreadId
            | Self::GetCurrentThread => WorkerCategory::ThreadState,
            Self::GetCurrentProcessId | Self::GetCurrentProcess => WorkerCategory::Identity,
            Self::GetTickCount
            | Self::GetTickCount64
            | Self::QueryPerformanceCounter
            | Self::QueryPerformanceFrequency
            | Self::GetSystemTimeAsFileTime
            | Self::GetSystemTimePreciseAsFileTime
            | Self::GetTimeZoneInformation
            | Self::GetSystemTime
            | Self::SystemTimeToTzSpecificLocalTime => WorkerCategory::Clock,
            Self::GetVersion | Self::GetVersionExW | Self::GetVersionExA => WorkerCategory::Version,
            Self::IsWow64Process
            | Self::GetSystemInfo
            | Self::GetNativeSystemInfo
            | Self::IsProcessorFeaturePresent
            | Self::GetComputerNameW
            | Self::GetSystemMetrics => WorkerCategory::SystemInfo,
            Self::GlobalMemoryStatusEx => WorkerCategory::MemoryStatus,
            Self::CharNextW
            | Self::CharPrevW
            | Self::StrFromTimeIntervalW
            | Self::Strlen
            | Self::LstrlenW
            | Self::LstrcmpW
            | Self::LstrcmpiW
            | Self::CompareStringW
            | Self::MultiByteToWideChar
            | Self::WideCharToMultiByte => WorkerCategory::StringConversion,
            Self::GetACP
            | Self::GetOEMCP
            | Self::GetCPInfo
            | Self::IsValidCodePage
            | Self::LocaleNameToLCID
            | Self::GetDateFormatW
            | Self::GetTimeFormatW
            | Self::LcMapStringW
            | Self::LcMapStringEx
            | Self::CharUpperW
            | Self::IsCharAlphaW
            | Self::IsCharAlphaNumericW
            | Self::IsCharLowerW
            | Self::IsCharUpperW
            | Self::IsCharSpaceW => WorkerCategory::Nls,
            Self::GetProcessHeap | Self::GetProcessHeaps | Self::HeapSize => WorkerCategory::Heap,
            Self::GetEnvironmentVariableW => WorkerCategory::Environment,
            Self::RegQueryValueExA
            | Self::RegQueryValueExW
            | Self::RegEnumKeyExW
            | Self::RegEnumValueW
            | Self::RegQueryInfoKeyW
            | Self::ShRegGetValueW => WorkerCategory::Registry,
            Self::GetFileAttributesW
            | Self::GetFileAttributesA
            | Self::GetFileAttributesExW
            | Self::GetFileSize
            | Self::GetFileSizeEx => WorkerCategory::FileSystem,
            Self::GetFullPathNameW | Self::GetLongPathNameW | Self::GetShortPathNameW => {
                WorkerCategory::Path
            }
            Self::TlsGetValue | Self::FlsGetValue | Self::TlsSetValue | Self::FlsSetValue => {
                WorkerCategory::Tls
            }
            Self::InterlockedIncrement
            | Self::InterlockedDecrement
            | Self::InterlockedExchangeAdd => WorkerCategory::Interlocked,
            Self::GetExitCodeThread
            | Self::GetExitCodeProcess
            | Self::GetThreadPriority
            | Self::GetFileType => WorkerCategory::ObjectStatus,
        }
    }
}

/// Why a worker could not reproduce the owner's semantics for one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerFallback {
    LockContention,
    GuestMemoryWrite,
    UnsupportedInput,
}

impl WorkerFallback {
    pub(crate) const fn barrier_reason(self) -> BarrierReason {
        match self {
            Self::LockContention => BarrierReason::LockContention,
            Self::GuestMemoryWrite => BarrierReason::GuestMemoryWrite,
            Self::UnsupportedInput => BarrierReason::UnsupportedInput,
        }
    }
}

thread_local! {
    /// The first concrete reason a worker path failed.  Helpers mark it at the
    /// exact failing step; `execute` keeps returning `bool`, so a `false`
    /// carries the precise cause to the dispatcher.
    static WORKER_FALLBACK: Cell<Option<WorkerFallback>> = const { Cell::new(None) };
}

pub(super) fn mark_fallback(reason: WorkerFallback) {
    WORKER_FALLBACK.with(|slot| {
        if slot.get().is_none() {
            slot.set(Some(reason));
        }
    });
}

fn take_fallback() -> WorkerFallback {
    WORKER_FALLBACK.with(|slot| slot.take().unwrap_or(WorkerFallback::UnsupportedInput))
}

fn clear_fallback() {
    WORKER_FALLBACK.with(|slot| slot.set(None));
}

/// Map a registered host thunk to its worker implementation, if it has one.
pub(crate) fn worker_api(thunk: &HostThunk) -> Option<WorkerApi> {
    Some(match thunk {
        HostThunk::GetLastError => WorkerApi::GetLastError,
        HostThunk::SetLastError => WorkerApi::SetLastError,
        HostThunk::GetCurrentThreadId => WorkerApi::GetCurrentThreadId,
        HostThunk::GetCurrentThread => WorkerApi::GetCurrentThread,
        HostThunk::GetCurrentProcessId => WorkerApi::GetCurrentProcessId,
        HostThunk::GetCurrentProcess => WorkerApi::GetCurrentProcess,
        HostThunk::GetTickCount => WorkerApi::GetTickCount,
        HostThunk::GetTickCount64 => WorkerApi::GetTickCount64,
        HostThunk::QueryPerformanceCounter => WorkerApi::QueryPerformanceCounter,
        HostThunk::QueryPerformanceFrequency => WorkerApi::QueryPerformanceFrequency,
        HostThunk::GetSystemTimeAsFileTime => WorkerApi::GetSystemTimeAsFileTime,
        HostThunk::GetSystemTimePreciseAsFileTime => WorkerApi::GetSystemTimePreciseAsFileTime,
        HostThunk::GetVersion => WorkerApi::GetVersion,
        HostThunk::GetVersionExW => WorkerApi::GetVersionExW,
        HostThunk::GetVersionExA => WorkerApi::GetVersionExA,
        HostThunk::IsWow64Process => WorkerApi::IsWow64Process,
        HostThunk::GetSystemInfo => WorkerApi::GetSystemInfo,
        HostThunk::GetNativeSystemInfo => WorkerApi::GetNativeSystemInfo,
        HostThunk::GlobalMemoryStatusEx => WorkerApi::GlobalMemoryStatusEx,
        HostThunk::IsProcessorFeaturePresent => WorkerApi::IsProcessorFeaturePresent,
        HostThunk::CharNextW => WorkerApi::CharNextW,
        HostThunk::CharPrevW => WorkerApi::CharPrevW,
        HostThunk::StrFromTimeIntervalW => WorkerApi::StrFromTimeIntervalW,
        HostThunk::Strlen => WorkerApi::Strlen,
        HostThunk::LstrlenW => WorkerApi::LstrlenW,
        HostThunk::LstrcmpW => WorkerApi::LstrcmpW,
        HostThunk::LstrcmpiW => WorkerApi::LstrcmpiW,
        HostThunk::CompareStringW => WorkerApi::CompareStringW,
        HostThunk::MultiByteToWideChar => WorkerApi::MultiByteToWideChar,
        HostThunk::WideCharToMultiByte => WorkerApi::WideCharToMultiByte,
        HostThunk::GetACP => WorkerApi::GetACP,
        HostThunk::GetOEMCP => WorkerApi::GetOEMCP,
        HostThunk::GetCPInfo => WorkerApi::GetCPInfo,
        HostThunk::IsValidCodePage => WorkerApi::IsValidCodePage,
        HostThunk::LocaleNameToLCID => WorkerApi::LocaleNameToLCID,
        HostThunk::GetProcessHeap => WorkerApi::GetProcessHeap,
        HostThunk::GetProcessHeaps => WorkerApi::GetProcessHeaps,
        HostThunk::HeapSize => WorkerApi::HeapSize,
        HostThunk::GetTimeZoneInformation => WorkerApi::GetTimeZoneInformation,
        HostThunk::GetDateFormatW => WorkerApi::GetDateFormatW,
        HostThunk::GetTimeFormatW => WorkerApi::GetTimeFormatW,
        HostThunk::GetEnvironmentVariableW => WorkerApi::GetEnvironmentVariableW,
        HostThunk::RegQueryValueExA => WorkerApi::RegQueryValueExA,
        HostThunk::RegQueryValueExW => WorkerApi::RegQueryValueExW,
        HostThunk::GetFileAttributesW => WorkerApi::GetFileAttributesW,
        HostThunk::GetFileAttributesA => WorkerApi::GetFileAttributesA,
        HostThunk::GetFileAttributesExW => WorkerApi::GetFileAttributesExW,
        HostThunk::GetFileSize => WorkerApi::GetFileSize,
        HostThunk::GetFileSizeEx => WorkerApi::GetFileSizeEx,
        HostThunk::GetSystemTime => WorkerApi::GetSystemTime,
        HostThunk::GetComputerNameW => WorkerApi::GetComputerNameW,
        HostThunk::TlsGetValue => WorkerApi::TlsGetValue,
        HostThunk::FlsGetValue => WorkerApi::FlsGetValue,
        HostThunk::InterlockedIncrement => WorkerApi::InterlockedIncrement,
        HostThunk::InterlockedDecrement => WorkerApi::InterlockedDecrement,
        HostThunk::InterlockedExchangeAdd => WorkerApi::InterlockedExchangeAdd,
        HostThunk::GetExitCodeThread => WorkerApi::GetExitCodeThread,
        HostThunk::GetExitCodeProcess => WorkerApi::GetExitCodeProcess,
        HostThunk::GetThreadPriority => WorkerApi::GetThreadPriority,
        HostThunk::RegEnumKeyExW => WorkerApi::RegEnumKeyExW,
        HostThunk::RegEnumValueW => WorkerApi::RegEnumValueW,
        HostThunk::RegQueryInfoKeyW => WorkerApi::RegQueryInfoKeyW,
        HostThunk::SHRegGetValueW => WorkerApi::ShRegGetValueW,
        HostThunk::LCMapStringW => WorkerApi::LcMapStringW,
        HostThunk::LCMapStringEx => WorkerApi::LcMapStringEx,
        HostThunk::CharUpperW => WorkerApi::CharUpperW,
        HostThunk::IsCharAlphaW => WorkerApi::IsCharAlphaW,
        HostThunk::IsCharAlphaNumericW => WorkerApi::IsCharAlphaNumericW,
        HostThunk::IsCharLowerW => WorkerApi::IsCharLowerW,
        HostThunk::IsCharUpperW => WorkerApi::IsCharUpperW,
        HostThunk::IsCharSpaceW => WorkerApi::IsCharSpaceW,
        HostThunk::TlsSetValue => WorkerApi::TlsSetValue,
        HostThunk::FlsSetValue => WorkerApi::FlsSetValue,
        HostThunk::SystemTimeToTzSpecificLocalTime => WorkerApi::SystemTimeToTzSpecificLocalTime,
        HostThunk::GetSystemMetrics => WorkerApi::GetSystemMetrics,
        HostThunk::GetFullPathNameW => WorkerApi::GetFullPathNameW,
        HostThunk::GetLongPathNameW => WorkerApi::GetLongPathNameW,
        HostThunk::GetShortPathNameW => WorkerApi::GetShortPathNameW,
        HostThunk::GetFileType => WorkerApi::GetFileType,
        _ => return None,
    })
}

/// The canonical concurrency class of a registered thunk.
pub(crate) fn thunk_class(thunk: &HostThunk) -> ThunkConcurrency {
    worker_api(thunk).map_or(ThunkConcurrency::OwnerOnly, WorkerApi::class)
}

/// Why a lock-free guest-memory operation could not be serviced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AtomicGuestError {
    /// The view has no lock-free primitive (fall back to the owner).
    Unavailable,
    /// The address range is not mapped for atomic access.
    Fault,
}

/// A worker-safe view of guest memory.
pub(crate) trait WorkerMemoryView {
    fn load(&self, address: u64, len: usize) -> Option<u64>;
    fn store(&self, address: u64, bytes: &[u8]) -> bool;

    /// Lock-free 32-bit fetch-add; returns the PREVIOUS value.  Views that
    /// cannot guarantee atomicity return [`AtomicGuestError::Unavailable`] so
    /// the thunk falls back to the owner barrier instead of guessing.
    fn atomic_fetch_add_u32(&self, address: u64, value: u32) -> Result<u32, AtomicGuestError> {
        let _ = (address, value);
        Err(AtomicGuestError::Unavailable)
    }
}

impl WorkerMemoryView for GuestSliceMemory {
    fn load(&self, address: u64, len: usize) -> Option<u64> {
        GuestSliceMemory::load(self, address, len).ok()
    }

    fn store(&self, address: u64, bytes: &[u8]) -> bool {
        GuestSliceMemory::store(self, address, bytes).is_ok()
    }

    fn atomic_fetch_add_u32(&self, address: u64, value: u32) -> Result<u32, AtomicGuestError> {
        self.atomic_fetch_add(address, u64::from(value), 4)
            .map(|(previous, _)| previous as u32)
            .map_err(|_| AtomicGuestError::Fault)
    }
}

/// Execute `entry` on the calling worker.
///
/// Returns `true` when the thunk ran and the guest state now continues at
/// its return address.  Returns `false` when the caller must fall back to the
/// owner (owner-only thunk, missing published state, or guest memory the
/// worker view cannot service); the caller restores the context snapshot it
/// took before calling.
pub(crate) fn invoke_parallel_api(
    shared: &ProcessShared,
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    entry: &super::super::ParallelThunk,
) -> bool {
    try_invoke_parallel_api(shared, context, memory, entry).is_ok()
}

/// Execute `entry` on the calling worker, reporting the exact fallback reason
/// when the owner barrier is required.
pub(crate) fn try_invoke_parallel_api(
    shared: &ProcessShared,
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    entry: &super::super::ParallelThunk,
) -> Result<(), WorkerFallback> {
    clear_fallback();
    let Some(api) = entry.api else {
        return Err(WorkerFallback::UnsupportedInput);
    };
    let rsp = context.state.get(Register::Rsp);
    if rsp == 0 {
        return Err(WorkerFallback::UnsupportedInput);
    }
    let pointer_bytes = context.state.arch.pointer_bytes() as u64;
    let Some(return_address) = memory.load(rsp, pointer_bytes as usize) else {
        mark_fallback(WorkerFallback::UnsupportedInput);
        return Err(take_fallback());
    };
    context
        .state
        .set(Register::Rsp, rsp.wrapping_add(pointer_bytes));
    if !execute(api, shared, context, memory) {
        return Err(take_fallback());
    }
    if context.state.arch == GuestArch::X86 {
        context.state.set(
            Register::Rsp,
            context
                .state
                .get(Register::Rsp)
                .wrapping_add(entry.x86_arg_bytes),
        );
    }
    context.state.rip = return_address;
    Ok(())
}

fn execute(
    api: WorkerApi,
    shared: &ProcessShared,
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
) -> bool {
    match api {
        WorkerApi::GetLastError => {
            context
                .state
                .set(Register::Rax, u64::from(context.last_error));
            true
        }
        WorkerApi::SetLastError => {
            let Some(value) = read_arg(context, memory, 0) else {
                return false;
            };
            context.last_error = value as u32;
            context.state.set(Register::Rax, 0);
            true
        }
        WorkerApi::GetCurrentThreadId => {
            context
                .state
                .set(Register::Rax, u64::from(context.thread_id));
            context.last_error = 0;
            true
        }
        WorkerApi::GetCurrentThread => {
            context.state.set(Register::Rax, u64::from(context.handle));
            context.last_error = 0;
            true
        }
        WorkerApi::GetCurrentProcessId => {
            let Some(identity) = shared.worker_identity_snapshot() else {
                return false;
            };
            context
                .state
                .set(Register::Rax, u64::from(identity.process_id));
            context.last_error = 0;
            true
        }
        WorkerApi::GetCurrentProcess => {
            let Some(identity) = shared.worker_identity_snapshot() else {
                return false;
            };
            context
                .state
                .set(Register::Rax, u64::from(identity.process_handle));
            context.last_error = 0;
            true
        }
        WorkerApi::GetTickCount => {
            let Some(clock) = shared.worker_clock_snapshot() else {
                return false;
            };
            context.state.set(
                Register::Rax,
                clock.clock.tick_count64() & u64::from(u32::MAX),
            );
            context.last_error = 0;
            true
        }
        WorkerApi::GetTickCount64 => {
            let Some(clock) = shared.worker_clock_snapshot() else {
                return false;
            };
            context.state.set(Register::Rax, clock.clock.tick_count64());
            context.last_error = 0;
            true
        }
        WorkerApi::QueryPerformanceCounter => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
            } else {
                let Some(clock) = shared.worker_clock_snapshot() else {
                    return false;
                };
                if !write_u64(
                    memory,
                    pointer,
                    clock.clock.query_performance_counter() as u64,
                ) {
                    return false;
                }
                context.state.set(Register::Rax, 1);
                context.last_error = 0;
            }
            true
        }
        WorkerApi::QueryPerformanceFrequency => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
            } else {
                let Some(clock) = shared.worker_clock_snapshot() else {
                    return false;
                };
                if !write_u64(
                    memory,
                    pointer,
                    clock.clock.query_performance_frequency() as u64,
                ) {
                    return false;
                }
                context.state.set(Register::Rax, 1);
                context.last_error = 0;
            }
            true
        }
        WorkerApi::GetSystemTimeAsFileTime => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(clock) = shared.worker_clock_snapshot() else {
                return false;
            };
            let ticks = if clock.dtm {
                WINDOWS_EPOCH_OFFSET_100NS
                    .saturating_add(clock.deterministic_tick_ms.saturating_mul(10_000))
            } else {
                current_host_ticks_100ns()
            };
            if pointer != 0 && !write_u64(memory, pointer, ticks) {
                return false;
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::GetSystemTimePreciseAsFileTime => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(clock) = shared.worker_clock_snapshot() else {
                return false;
            };
            let ticks = clock.clock.system_time_precise_file_time();
            if pointer != 0 && !write_u64(memory, pointer, ticks) {
                return false;
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::GetVersion => {
            let Some(version) = shared.worker_version_snapshot() else {
                return false;
            };
            let Some(version) = version else {
                return false;
            };
            let packed = (version.build << 16)
                | ((version.major & 0xff) << 8)
                | (version.minor & 0xff)
                | 0x8000_0000;
            context.state.set(Register::Rax, u64::from(packed));
            context.last_error = 0;
            true
        }
        WorkerApi::GetVersionExW => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(version) = shared.worker_version_snapshot() else {
                return false;
            };
            let Some(version) = version else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            write_version_info_w(context, memory, pointer, &version)
        }
        WorkerApi::GetVersionExA => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(version) = shared.worker_version_snapshot() else {
                return false;
            };
            let Some(version) = version else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            write_version_info_a(context, memory, pointer, &version)
        }
        WorkerApi::IsWow64Process => {
            // The owner reads (and ignores) the process handle argument, so
            // an unreadable first argument must stay on the barrier too.
            if read_arg(context, memory, 0).is_none() {
                return false;
            }
            let Some(pointer) = read_arg(context, memory, 1) else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
            } else {
                if !write_u32(memory, pointer, 0) {
                    return false;
                }
                context.state.set(Register::Rax, 1);
                context.last_error = 0;
            }
            true
        }
        WorkerApi::GetSystemInfo | WorkerApi::GetNativeSystemInfo => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            if pointer != 0 && !write_system_info(memory, pointer, context.state.arch) {
                return false;
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::GlobalMemoryStatusEx => {
            let Some(pointer) = read_arg(context, memory, 0) else {
                return false;
            };
            if pointer == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let Some(status) = shared.worker_memory_status_snapshot() else {
                return false;
            };
            let Some(status) = status else {
                return false;
            };
            let total_virt: u64 = 2 * 1024 * 1024 * 1024;
            let avail_virt: u64 = 1024 * 1024 * 1024;
            let memory_load =
                ((status.total_phys - status.avail_phys) * 100 / status.total_phys) as u32;
            if !write_u32(memory, pointer, 64)
                || !write_u32(memory, pointer + 4, memory_load)
                || !write_u64(memory, pointer + 8, status.total_phys)
                || !write_u64(memory, pointer + 16, status.avail_phys)
                || !write_u64(memory, pointer + 24, status.total_page)
                || !write_u64(memory, pointer + 32, status.avail_page)
                || !write_u64(memory, pointer + 40, total_virt)
                || !write_u64(memory, pointer + 48, avail_virt)
            {
                return false;
            }
            context.state.set(Register::Rax, 1);
            true
        }
        WorkerApi::IsProcessorFeaturePresent => {
            let Some(feature) = read_arg(context, memory, 0) else {
                return false;
            };
            context.state.set(
                Register::Rax,
                u64::from(is_processor_feature_present(feature as u32)),
            );
            context.last_error = 0;
            true
        }
        WorkerApi::CharNextW => {
            let Some(current) = read_arg(context, memory, 0) else {
                return false;
            };
            let next = if current == 0 {
                current
            } else {
                let Some(unit) = read_u16(memory, current) else {
                    return false;
                };
                if unit == 0 { current } else { current + 2 }
            };
            context.state.set(Register::Rax, next);
            context.last_error = 0;
            true
        }
        WorkerApi::CharPrevW => {
            let Some(start) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(current) = read_arg(context, memory, 1) else {
                return false;
            };
            let previous = if current <= start { start } else { current - 2 };
            context.state.set(Register::Rax, previous);
            context.last_error = 0;
            true
        }
        WorkerApi::StrFromTimeIntervalW => {
            let Some(buffer) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(buffer_len) = read_arg(context, memory, 1) else {
                return false;
            };
            let Some(milliseconds) = read_arg(context, memory, 2) else {
                return false;
            };
            let Some(digits) = read_arg(context, memory, 3) else {
                return false;
            };
            let written = if buffer == 0 || buffer_len == 0 {
                0
            } else {
                match shlwapi_format_time_interval(milliseconds as u32, digits as i32) {
                    Some(formatted) => {
                        let units: Vec<u16> = formatted.encode_utf16().collect();
                        let copy_units = units.len().min((buffer_len as usize).saturating_sub(1));
                        let mut bytes = Vec::with_capacity((copy_units + 1) * 2);
                        for unit in units.iter().take(copy_units) {
                            bytes.extend_from_slice(&unit.to_le_bytes());
                        }
                        bytes.extend_from_slice(&0_u16.to_le_bytes());
                        if !write_bytes(memory, buffer, &bytes) {
                            return false;
                        }
                        copy_units as u32
                    }
                    None => {
                        if !write_u16(memory, buffer, 0) {
                            return false;
                        }
                        0
                    }
                }
            };
            context.state.set(Register::Rax, u64::from(written));
            context.last_error = 0;
            true
        }
        WorkerApi::Strlen => {
            let Some([string_ptr]) = read_args::<1>(context, memory) else {
                return false;
            };
            let Some(text) = read_c_string_lossy(memory, string_ptr) else {
                return false;
            };
            context.state.set(Register::Rax, text.len() as u64);
            context.last_error = 0;
            true
        }
        WorkerApi::LstrlenW => {
            let Some([string_ptr]) = read_args::<1>(context, memory) else {
                return false;
            };
            let Some(text) = read_utf16_lossy(memory, string_ptr) else {
                return false;
            };
            context
                .state
                .set(Register::Rax, text.encode_utf16().count() as u64);
            context.last_error = 0;
            true
        }
        WorkerApi::LstrcmpW | WorkerApi::LstrcmpiW => {
            let Some([left_ptr, right_ptr]) = read_args::<2>(context, memory) else {
                return false;
            };
            let left = if left_ptr == 0 {
                String::new()
            } else {
                let Some(text) = read_utf16_lossy(memory, left_ptr) else {
                    return false;
                };
                text
            };
            let right = if right_ptr == 0 {
                String::new()
            } else {
                let Some(text) = read_utf16_lossy(memory, right_ptr) else {
                    return false;
                };
                text
            };
            let result = if api == WorkerApi::LstrcmpiW {
                match left.to_lowercase().cmp(&right.to_lowercase()) {
                    std::cmp::Ordering::Less => -1_i32,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                }
            } else {
                match left.encode_utf16().cmp(right.encode_utf16()) {
                    std::cmp::Ordering::Less => -1_i32,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                }
            };
            context.state.set(Register::Rax, result as i64 as u64);
            context.last_error = 0;
            true
        }
        WorkerApi::CompareStringW => {
            let Some([_locale, flags, str1_ptr, str1_len, str2_ptr, str2_len]) =
                read_args::<6>(context, memory)
            else {
                return false;
            };
            // The owner reads the NUL-terminated strings and then takes the
            // requested prefix; unreadable input degrades to the empty string
            // exactly like `read_utf16_string(..).unwrap_or_default()`.
            let s1 = take_utf16_prefix(
                read_utf16_lossy(memory, str1_ptr).unwrap_or_default(),
                str1_len as i32,
            );
            let s2 = take_utf16_prefix(
                read_utf16_lossy(memory, str2_ptr).unwrap_or_default(),
                str2_len as i32,
            );
            const NORM_IGNORECASE: u32 = 0x0000_0001;
            const NORM_IGNORECASE_NONSPACE: u32 = 0x0000_0002;
            let flags = flags as u32;
            let result = if flags & (NORM_IGNORECASE | NORM_IGNORECASE_NONSPACE) != 0 {
                match s1.to_lowercase().cmp(&s2.to_lowercase()) {
                    std::cmp::Ordering::Less => 1_u64,
                    std::cmp::Ordering::Equal => 2,
                    std::cmp::Ordering::Greater => 3,
                }
            } else {
                match s1.cmp(&s2) {
                    std::cmp::Ordering::Less => 1_u64,
                    std::cmp::Ordering::Equal => 2,
                    std::cmp::Ordering::Greater => 3,
                }
            };
            context.state.set(Register::Rax, result);
            true
        }
        WorkerApi::MultiByteToWideChar => {
            let Some([code_page, _flags, multi_ptr, multi_len, wide_ptr, wide_len]) =
                read_args::<6>(context, memory)
            else {
                return false;
            };
            let multi_len = multi_len as i32;
            let wide_len = wide_len as i32;
            if multi_ptr == 0 && multi_len != 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let normalized_code_page = if code_page as u32 == CP_ACP {
                1252
            } else {
                code_page as u32
            };
            let multi_bytes = if multi_len < 0 {
                let Some(text) = read_c_string_lossy(memory, multi_ptr) else {
                    return false;
                };
                let mut bytes = text.into_bytes();
                bytes.push(0);
                bytes
            } else {
                let Some(bytes) = read_raw(memory, multi_ptr, multi_len as usize) else {
                    return false;
                };
                bytes
            };
            let Some(locale) = shared.worker_locale_snapshot() else {
                return false;
            };
            let converted = multi_byte_to_wide(normalized_code_page, &multi_bytes, locale);
            match converted {
                Conversion::Value(wide_units) => {
                    let required = wide_units.len() as u32;
                    if wide_ptr == 0 || wide_len == 0 {
                        context.state.set(Register::Rax, u64::from(required));
                        context.last_error = 0;
                    } else if wide_len < required as i32 {
                        context.state.set(Register::Rax, 0);
                        context.last_error = ERROR_INSUFFICIENT_BUFFER;
                    } else {
                        let encoded = wide_units
                            .iter()
                            .flat_map(|unit| unit.to_le_bytes())
                            .collect::<Vec<_>>();
                        if !encoded.is_empty() && !write_bytes(memory, wide_ptr, &encoded) {
                            return false;
                        }
                        context.state.set(Register::Rax, u64::from(required));
                        context.last_error = 0;
                    }
                    true
                }
                Conversion::Invalid => {
                    context.state.set(Register::Rax, 0);
                    context.last_error = ERROR_INVALID_PARAMETER;
                    true
                }
                Conversion::Unsupported => false,
            }
        }
        WorkerApi::WideCharToMultiByte => {
            let Some(
                [
                    code_page,
                    _flags,
                    wide_ptr,
                    wide_len,
                    multi_ptr,
                    multi_len,
                    _default_char_ptr,
                    used_default_ptr,
                ],
            ) = read_args::<8>(context, memory)
            else {
                return false;
            };
            let wide_len = wide_len as i32;
            let multi_len = multi_len as i32;
            if used_default_ptr != 0 && !write_u32(memory, used_default_ptr, 0) {
                return false;
            }
            if wide_ptr == 0 && wide_len != 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let normalized_code_page = if code_page as u32 == CP_ACP {
                1252
            } else {
                code_page as u32
            };
            let wide_units = if wide_len < 0 {
                let Some(text) = read_utf16_lossy(memory, wide_ptr) else {
                    return false;
                };
                text.encode_utf16().chain(std::iter::once(0)).collect()
            } else {
                let Some(units) = read_utf16_units(memory, wide_ptr, wide_len as usize) else {
                    return false;
                };
                units
            };
            let Some(locale) = shared.worker_locale_snapshot() else {
                return false;
            };
            let converted = wide_to_multi_byte(normalized_code_page, &wide_units, locale);
            match converted {
                Conversion::Value(encoded) => {
                    let required = encoded.len() as u32;
                    if multi_ptr == 0 || multi_len == 0 {
                        context.state.set(Register::Rax, u64::from(required));
                        context.last_error = 0;
                    } else if multi_len < required as i32 {
                        context.state.set(Register::Rax, 0);
                        context.last_error = ERROR_INSUFFICIENT_BUFFER;
                    } else {
                        if !encoded.is_empty() && !write_bytes(memory, multi_ptr, &encoded) {
                            return false;
                        }
                        context.state.set(Register::Rax, u64::from(required));
                        context.last_error = 0;
                    }
                    true
                }
                Conversion::Invalid => {
                    context.state.set(Register::Rax, 0);
                    context.last_error = ERROR_INVALID_PARAMETER;
                    true
                }
                Conversion::Unsupported => false,
            }
        }
        WorkerApi::GetACP => {
            let Some(locale) = shared.worker_locale_snapshot() else {
                return false;
            };
            context.state.set(Register::Rax, u64::from(locale.acp));
            context.last_error = 0;
            true
        }
        WorkerApi::GetOEMCP => {
            let Some(locale) = shared.worker_locale_snapshot() else {
                return false;
            };
            context.state.set(Register::Rax, u64::from(locale.oemcp));
            context.last_error = 0;
            true
        }
        WorkerApi::GetCPInfo => {
            let Some([code_page, cp_info]) = read_args::<2>(context, memory) else {
                return false;
            };
            let Some(max_char_size) = guest_code_page_max_char_size(code_page as u32) else {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            };
            if cp_info != 0 {
                if !write_u32(memory, cp_info, max_char_size) {
                    return false;
                }
                if !write_bytes(
                    memory,
                    cp_info + 4,
                    &[b'?', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ) {
                    return false;
                }
            }
            context.state.set(Register::Rax, 1);
            context.last_error = 0;
            true
        }
        WorkerApi::IsValidCodePage => {
            let Some(code_page) = read_arg(context, memory, 0) else {
                return false;
            };
            let valid = guest_code_page_max_char_size(code_page as u32).is_some();
            context.state.set(Register::Rax, u64::from(valid));
            context.last_error = if valid { 0 } else { ERROR_INVALID_PARAMETER };
            true
        }
        WorkerApi::LocaleNameToLCID => {
            let Some([locale_name_ptr, _flags]) = read_args::<2>(context, memory) else {
                return false;
            };
            const LOCALE_EN_US: u32 = 0x0409;
            if locale_name_ptr == 0 {
                context.state.set(Register::Rax, u64::from(LOCALE_EN_US));
                context.last_error = 0;
                return true;
            }
            let Some(locale_name) = read_utf16_lossy(memory, locale_name_ptr) else {
                return false;
            };
            if let Some(result) = locale_name_to_lcid(&locale_name) {
                context.state.set(Register::Rax, u64::from(result));
                context.last_error = 0;
            } else {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
            }
            true
        }
        WorkerApi::GetProcessHeap => {
            context.state.set(Register::Rax, PROCESS_HEAP_HANDLE);
            context.last_error = 0;
            true
        }
        WorkerApi::GetProcessHeaps => {
            let Some([count, heaps_ptr]) = read_args::<2>(context, memory) else {
                return false;
            };
            if count != 0
                && heaps_ptr != 0
                && !write_pointer(memory, heaps_ptr, PROCESS_HEAP_HANDLE, context.state.arch)
            {
                return false;
            }
            context.state.set(Register::Rax, 1);
            context.last_error = 0;
            true
        }
        WorkerApi::HeapSize => {
            let Some([heap, _flags, address]) = read_args::<3>(context, memory) else {
                return false;
            };
            let size = if heap == PROCESS_HEAP_HANDLE {
                let Some(heap_snapshot) = shared.worker_heap_snapshot() else {
                    return false;
                };
                heap_snapshot.get(&address).map(|size| *size as u64)
            } else {
                None
            };
            let result = size.unwrap_or(match context.state.arch {
                GuestArch::X64 => u64::MAX,
                GuestArch::X86 => u32::MAX as u64,
            });
            context.state.set(Register::Rax, result);
            context.last_error = if size.is_some() {
                0
            } else {
                ERROR_INVALID_PARAMETER
            };
            true
        }
        WorkerApi::GetTimeZoneInformation => {
            let Some([time_zone_information_ptr]) = read_args::<1>(context, memory) else {
                return false;
            };
            let Some(clock) = shared.worker_clock_snapshot() else {
                return false;
            };
            let dtm = clock.dtm;
            let info = current_host_time_zone_information(dtm);
            if time_zone_information_ptr != 0
                && !write_time_zone_information_worker(memory, time_zone_information_ptr, &info)
            {
                return false;
            }
            context.state.set(Register::Rax, u64::from(info.result));
            context.last_error = 0;
            true
        }
        WorkerApi::GetDateFormatW => {
            let Some(
                [
                    _locale,
                    flags,
                    date_ptr,
                    format_ptr,
                    buffer_ptr,
                    buffer_size,
                ],
            ) = read_args::<6>(context, memory)
            else {
                return false;
            };
            let flags = flags as u32;
            let (year, month, day, dow) = if date_ptr != 0 {
                let y = memory.load(date_ptr, 2).unwrap_or(0) as u16;
                let m = memory.load(date_ptr + 2, 2).unwrap_or(0) as u16;
                let d = memory.load(date_ptr + 6, 2).unwrap_or(0) as u16;
                (y, m, d, civil_day_of_week(y, m, d))
            } else {
                let (y, m, d, _h, _mi, _s) = current_guest_utc_components().unwrap_or_default();
                (y, m, d, civil_day_of_week(y, m, d))
            };
            let date_str = if format_ptr != 0 {
                let Some(formatted) =
                    format_date_tokens_worker(memory, format_ptr, year, month, day, dow)
                else {
                    return false;
                };
                formatted
            } else if flags & 0x02 != 0 {
                format!(
                    "{}, {} {}, {}",
                    FULL_WEEKDAYS[dow as usize],
                    FULL_MONTHS[(month as usize).saturating_sub(1)],
                    day,
                    year
                )
            } else {
                format!("{}/{}/{}", month, day, year)
            };
            write_date_time_result_worker(
                memory,
                context,
                &date_str,
                buffer_ptr,
                buffer_size as i32,
            )
        }
        WorkerApi::GetTimeFormatW => {
            let Some(
                [
                    _locale,
                    flags,
                    time_ptr,
                    format_ptr,
                    buffer_ptr,
                    buffer_size,
                ],
            ) = read_args::<6>(context, memory)
            else {
                return false;
            };
            let flags = flags as u32;
            let (hour, minute, second) = if time_ptr != 0 {
                (
                    memory.load(time_ptr + 8, 2).unwrap_or(0) as u16,
                    memory.load(time_ptr + 10, 2).unwrap_or(0) as u16,
                    memory.load(time_ptr + 12, 2).unwrap_or(0) as u16,
                )
            } else {
                let (_y, _m, _d, h, mi, s) = current_guest_utc_components().unwrap_or_default();
                (h, mi, s)
            };
            let force24 = flags & 0x08 != 0;
            let no_marker = flags & 0x04 != 0;
            let time_str = if format_ptr != 0 {
                let Some(formatted) =
                    format_time_tokens_worker(memory, format_ptr, hour, minute, second, force24)
                else {
                    return false;
                };
                formatted
            } else {
                let (h12, meridian) = if force24 || no_marker {
                    (hour, "")
                } else {
                    let h12 = hour % 12;
                    (
                        if h12 == 0 { 12 } else { h12 },
                        if hour < 12 { "AM" } else { "PM" },
                    )
                };
                let mut text = format!(
                    "{}{}{:02}",
                    if force24 || no_marker {
                        format!("{:02}", h12)
                    } else {
                        h12.to_string()
                    },
                    ":",
                    minute,
                );
                if flags & 0x02 == 0 {
                    text.push_str(&format!(":{:02}", second));
                }
                if !meridian.is_empty() {
                    text.push(' ');
                    text.push_str(meridian);
                }
                text
            };
            write_date_time_result_worker(
                memory,
                context,
                &time_str,
                buffer_ptr,
                buffer_size as i32,
            )
        }
        WorkerApi::GetEnvironmentVariableW => {
            let Some([name_ptr, buffer_ptr, buffer_len]) = read_args::<3>(context, memory) else {
                return false;
            };
            let buffer_len = buffer_len as u32 as usize;
            if name_ptr == 0 || (buffer_ptr == 0 && buffer_len != 0) {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let Some(name) = read_utf16_lossy(memory, name_ptr) else {
                return false;
            };
            let Some(environment) = shared.worker_environment_snapshot() else {
                return false;
            };
            let value = environment
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(&name))
                .map(|(_, value)| value.clone());
            let Some(value) = value else {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_ENVVAR_NOT_FOUND;
                return true;
            };
            let required = value.encode_utf16().count() + 1;
            if buffer_len == 0 {
                context.state.set(Register::Rax, required as u64);
                context.last_error = 0;
            } else if required > buffer_len {
                context.state.set(Register::Rax, required as u64);
                context.last_error = ERROR_INSUFFICIENT_BUFFER;
            } else {
                let bytes = value
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>();
                if !write_bytes(memory, buffer_ptr, &bytes) {
                    return false;
                }
                context
                    .state
                    .set(Register::Rax, value.encode_utf16().count() as u64);
                context.last_error = 0;
            }
            true
        }
        WorkerApi::RegQueryValueExA | WorkerApi::RegQueryValueExW => {
            query_registry_value(api, shared, context, memory)
        }
        WorkerApi::GetFileAttributesW => {
            let Some(path_ptr) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(raw_path) = read_utf16_lossy(memory, path_ptr) else {
                return false;
            };
            if raw_path.is_empty() {
                context.state.set(Register::Rax, INVALID_FILE_ATTRIBUTES);
                context.last_error = ERROR_PATH_NOT_FOUND;
                return true;
            }
            if !is_canonical_guest_absolute(&raw_path) {
                return false;
            }
            let Some(files) = shared.worker_filesystem_snapshot() else {
                return false;
            };
            let Some(metadata) = files.entries.get(&raw_path) else {
                return false;
            };
            context.state.set(
                Register::Rax,
                u64::from(attributes_mask_w(&metadata.attributes)),
            );
            context.last_error = 0;
            true
        }
        WorkerApi::GetFileAttributesA => {
            let Some(path_ptr) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(raw_path) = read_c_string_lossy(memory, path_ptr) else {
                return false;
            };
            if raw_path.is_empty() {
                context.state.set(Register::Rax, INVALID_FILE_ATTRIBUTES);
                context.last_error = ERROR_PATH_NOT_FOUND;
                return true;
            }
            if !is_canonical_guest_absolute(&raw_path) {
                return false;
            }
            let Some(files) = shared.worker_filesystem_snapshot() else {
                return false;
            };
            let Some(metadata) = files.entries.get(&raw_path) else {
                return false;
            };
            context.state.set(
                Register::Rax,
                u64::from(attributes_mask_a(&metadata.attributes)),
            );
            context.last_error = 0;
            true
        }
        WorkerApi::GetFileAttributesExW => {
            let Some([path_ptr, info_level, information_ptr]) = read_args::<3>(context, memory)
            else {
                return false;
            };
            let Some(raw_path) = read_utf16_lossy(memory, path_ptr) else {
                return false;
            };
            if raw_path.is_empty() {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_PATH_NOT_FOUND;
                return true;
            }
            if info_level != 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            if !is_canonical_guest_absolute(&raw_path) {
                return false;
            }
            let Some(files) = shared.worker_filesystem_snapshot() else {
                return false;
            };
            let Some(metadata) = files.entries.get(&raw_path) else {
                return false;
            };
            if information_ptr != 0
                && !write_file_attribute_data_worker(memory, information_ptr, metadata)
            {
                return false;
            }
            context.state.set(Register::Rax, 1);
            context.last_error = 0;
            true
        }
        WorkerApi::GetFileSize => {
            let Some([handle, high_ptr]) = read_args::<2>(context, memory) else {
                return false;
            };
            let handle = handle as u32;
            if handle == 0 {
                context.state.set(Register::Rax, u64::from(u32::MAX));
                context.last_error = ERROR_INVALID_HANDLE;
                return true;
            }
            let Some(files) = shared.worker_filesystem_snapshot() else {
                return false;
            };
            let Some(size) = files.sizes.get(&handle).copied() else {
                return false;
            };
            if high_ptr != 0 && !write_u32(memory, high_ptr, (size >> 32) as u32) {
                return false;
            }
            context.state.set(Register::Rax, (size as u32) as u64);
            context.last_error = 0;
            true
        }
        WorkerApi::GetFileSizeEx => {
            let Some([handle, size_ptr]) = read_args::<2>(context, memory) else {
                return false;
            };
            let Some(files) = shared.worker_filesystem_snapshot() else {
                return false;
            };
            let Some(size) = files.sizes.get(&(handle as u32)).copied() else {
                return false;
            };
            if size_ptr != 0 && !write_pointer(memory, size_ptr, size, context.state.arch) {
                return false;
            }
            // The owner preserves last-error on success for GetFileSizeEx.
            context.state.set(Register::Rax, 1);
            true
        }
        WorkerApi::GetSystemTime => {
            let Some(system_time_ptr) = read_arg(context, memory, 0) else {
                return false;
            };
            if system_time_ptr == 0 {
                return true;
            }
            let (year, month, day, hour, minute, second, millis) = host_utc_components();
            if !write_u16(memory, system_time_ptr, year)
                || !write_u16(memory, system_time_ptr + 2, month)
                || !write_u16(memory, system_time_ptr + 4, 0)
                || !write_u16(memory, system_time_ptr + 6, day)
                || !write_u16(memory, system_time_ptr + 8, hour)
                || !write_u16(memory, system_time_ptr + 10, minute)
                || !write_u16(memory, system_time_ptr + 12, second)
                || !write_u16(memory, system_time_ptr + 14, millis)
            {
                return false;
            }
            // The owner preserves last-error on GetSystemTime success.
            true
        }
        WorkerApi::GetComputerNameW => {
            let Some([buffer_ptr, size_ptr]) = read_args::<2>(context, memory) else {
                return false;
            };
            if size_ptr == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let Some(buffer_size) = read_u32(memory, size_ptr) else {
                return false;
            };
            let Some(result) =
                write_utf16_api_string_worker(memory, buffer_ptr, buffer_size, "CASA1")
            else {
                return false;
            };
            if !write_u32(memory, size_ptr, result + 1) {
                return false;
            }
            if buffer_size > 0 && result >= buffer_size {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_MORE_DATA;
            } else {
                context.state.set(Register::Rax, 1);
                context.last_error = 0;
            }
            true
        }
        WorkerApi::TlsGetValue => {
            let Some(slot) = read_arg(context, memory, 0) else {
                return false;
            };
            let slot = slot as u32;
            if slot >= 4096 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let value = if context.tls_vector_ptr != 0 {
                let pointer_bytes = context.state.arch.pointer_bytes() as u64;
                let address = context
                    .tls_vector_ptr
                    .wrapping_add(u64::from(slot) * pointer_bytes);
                let Some(value) = memory.load(address, context.state.arch.pointer_bytes()) else {
                    return false;
                };
                value
            } else {
                context.tls_slots.get(&slot).copied().unwrap_or(0)
            };
            context.state.set(Register::Rax, value);
            context.last_error = 0;
            true
        }
        WorkerApi::FlsGetValue => {
            let Some(slot) = read_arg(context, memory, 0) else {
                return false;
            };
            match context.fls_slots.get(&(slot as u32)).copied() {
                Some(value) => {
                    context.state.set(Register::Rax, value);
                    context.last_error = 0;
                }
                None => {
                    context.state.set(Register::Rax, 0);
                    context.last_error = ERROR_INVALID_PARAMETER;
                }
            }
            true
        }
        WorkerApi::InterlockedIncrement
        | WorkerApi::InterlockedDecrement
        | WorkerApi::InterlockedExchangeAdd => {
            let Some([destination, operand]) = read_args::<2>(context, memory) else {
                return false;
            };
            let addend = match api {
                WorkerApi::InterlockedIncrement => 1,
                WorkerApi::InterlockedDecrement => u32::MAX,
                _ => operand as u32,
            };
            match memory.atomic_fetch_add_u32(destination, addend) {
                Ok(previous) => {
                    let result = match api {
                        WorkerApi::InterlockedIncrement => previous.wrapping_add(1),
                        WorkerApi::InterlockedDecrement => previous.wrapping_sub(1),
                        _ => previous,
                    };
                    context.state.set(Register::Rax, u64::from(result));
                    context.last_error = 0;
                    true
                }
                Err(AtomicGuestError::Fault) => {
                    // The owner reports an unmapped destination as
                    // ERROR_INVALID_PARAMETER and returns 0.
                    context.state.set(Register::Rax, 0);
                    context.last_error = ERROR_INVALID_PARAMETER;
                    true
                }
                Err(AtomicGuestError::Unavailable) => false,
            }
        }
        WorkerApi::GetExitCodeThread => {
            let Some([handle, exit_code_ptr]) = read_args::<2>(context, memory) else {
                return false;
            };
            let handle = handle as u32;
            if handle == 0 {
                if exit_code_ptr != 0 && !write_u32(memory, exit_code_ptr, 0) {
                    return false;
                }
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_HANDLE;
                return true;
            }
            let Some(objects) = shared.worker_object_status_snapshot() else {
                return false;
            };
            let Some(exit_code) = objects.thread_exit_codes.get(&handle).copied() else {
                return false;
            };
            if exit_code_ptr != 0 && !write_u32(memory, exit_code_ptr, exit_code) {
                return false;
            }
            context.state.set(Register::Rax, 1);
            context.last_error = 0;
            true
        }
        WorkerApi::GetExitCodeProcess => {
            let Some([handle, exit_code_ptr]) = read_args::<2>(context, memory) else {
                return false;
            };
            let handle = handle as u32;
            if handle == 0 {
                if exit_code_ptr != 0 && !write_u32(memory, exit_code_ptr, 0) {
                    return false;
                }
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_HANDLE;
                return true;
            }
            let Some(objects) = shared.worker_object_status_snapshot() else {
                return false;
            };
            let Some(exit_code) = objects.process_exit_codes.get(&handle).copied() else {
                return false;
            };
            if exit_code_ptr != 0 && !write_u32(memory, exit_code_ptr, exit_code) {
                return false;
            }
            context.state.set(Register::Rax, 1);
            context.last_error = 0;
            true
        }
        WorkerApi::GetThreadPriority => {
            let Some(handle) = read_arg(context, memory, 0) else {
                return false;
            };
            let handle = handle as u32;
            if handle == 0 {
                context.state.set(Register::Rax, u64::from(u32::MAX));
                context.last_error = ERROR_INVALID_HANDLE;
                return true;
            }
            let Some(objects) = shared.worker_object_status_snapshot() else {
                return false;
            };
            let Some(priority) = objects.thread_priorities.get(&handle).copied() else {
                return false;
            };
            context.state.set(Register::Rax, priority as u64);
            context.last_error = 0;
            true
        }
        WorkerApi::RegEnumKeyExW => {
            let Some([hkey, index, name_ptr, name_size_ptr, _reserved, _last_write]) =
                read_args::<6>(context, memory)
            else {
                return false;
            };
            if name_size_ptr == 0 {
                context
                    .state
                    .set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let Some(registry) = shared.worker_registry_snapshot() else {
                return false;
            };
            let Some(key) = worker_registry_key_entry(&registry, hkey as u32, context.state.arch)
            else {
                mark_fallback(WorkerFallback::UnsupportedInput);
                return false;
            };
            let Some(name_size) = read_u32(memory, name_size_ptr) else {
                return false;
            };
            if index as usize >= key.subkeys.len() {
                if !write_u32(memory, name_size_ptr, 0) {
                    return false;
                }
                if name_ptr != 0 && name_size > 0 && !write_u16(memory, name_ptr, 0) {
                    return false;
                }
                context
                    .state
                    .set(Register::Rax, u64::from(ERROR_NO_MORE_ITEMS));
                context.last_error = ERROR_NO_MORE_ITEMS;
                return true;
            }
            let Some(char_count) = write_utf16_api_string_worker(
                memory,
                name_ptr,
                name_size,
                &key.subkeys[index as usize],
            ) else {
                return false;
            };
            if !write_u32(memory, name_size_ptr, char_count) {
                return false;
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::RegEnumValueW => {
            let Some(
                [
                    hkey,
                    index,
                    name_ptr,
                    name_size_ptr,
                    _reserved,
                    type_ptr,
                    data_ptr,
                    data_size_ptr,
                ],
            ) = read_args::<8>(context, memory)
            else {
                return false;
            };
            if name_size_ptr == 0 {
                context
                    .state
                    .set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let Some(registry) = shared.worker_registry_snapshot() else {
                return false;
            };
            let Some(key) = worker_registry_key_entry(&registry, hkey as u32, context.state.arch)
            else {
                mark_fallback(WorkerFallback::UnsupportedInput);
                return false;
            };
            let Some(name_size) = read_u32(memory, name_size_ptr) else {
                return false;
            };
            let Some((value_name, stored)) = key.values.iter().nth(index as usize) else {
                if !write_u32(memory, name_size_ptr, 0) {
                    return false;
                }
                if name_ptr != 0 && !write_u16(memory, name_ptr, 0) {
                    return false;
                }
                context
                    .state
                    .set(Register::Rax, u64::from(ERROR_NO_MORE_ITEMS));
                context.last_error = ERROR_NO_MORE_ITEMS;
                return true;
            };
            let type_code = registry_value_type_to_win32(&stored.value_type).unwrap_or(1);
            let data_bytes = encode_registry_value_data(stored).unwrap_or_default();
            let Some(char_count) =
                write_utf16_api_string_worker(memory, name_ptr, name_size, value_name)
            else {
                return false;
            };
            if !write_u32(memory, name_size_ptr, char_count) {
                return false;
            }
            if type_ptr != 0 && !write_u32(memory, type_ptr, type_code) {
                return false;
            }
            if data_size_ptr != 0 {
                let Some(data_capacity) = read_u32(memory, data_size_ptr) else {
                    return false;
                };
                let written = data_bytes.len().min(data_capacity as usize);
                if data_ptr != 0
                    && written > 0
                    && !write_bytes(memory, data_ptr, &data_bytes[..written])
                {
                    return false;
                }
                if !write_u32(memory, data_size_ptr, data_bytes.len() as u32) {
                    return false;
                }
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::RegQueryInfoKeyW => {
            let Some(
                [
                    hkey,
                    class_ptr,
                    class_size_ptr,
                    _reserved,
                    subkeys_ptr,
                    max_subkey_ptr,
                    max_class_ptr,
                    values_ptr,
                    max_value_name_ptr,
                    max_value_data_ptr,
                    _security_descriptor_ptr,
                    last_write_ptr,
                ],
            ) = read_args::<12>(context, memory)
            else {
                return false;
            };
            let Some(registry) = shared.worker_registry_snapshot() else {
                return false;
            };
            let Some(key) = worker_registry_key_entry(&registry, hkey as u32, context.state.arch)
            else {
                mark_fallback(WorkerFallback::UnsupportedInput);
                return false;
            };
            let max_subkey = key
                .subkeys
                .iter()
                .map(|name| name.encode_utf16().count() as u32 + 1)
                .max()
                .unwrap_or(0);
            let max_value = key
                .values
                .keys()
                .map(|name| name.encode_utf16().count() as u32 + 1)
                .max()
                .unwrap_or(0);
            let mut written = true;
            if subkeys_ptr != 0 {
                written &= write_u32(memory, subkeys_ptr, key.subkeys.len() as u32);
            }
            if max_subkey_ptr != 0 {
                written &= write_u32(memory, max_subkey_ptr, max_subkey);
            }
            if values_ptr != 0 {
                written &= write_u32(memory, values_ptr, key.values.len() as u32);
            }
            if max_value_name_ptr != 0 {
                written &= write_u32(memory, max_value_name_ptr, max_value);
            }
            if max_value_data_ptr != 0 {
                written &= write_u32(memory, max_value_data_ptr, 0);
            }
            if class_ptr != 0 && class_size_ptr != 0 {
                written &= write_u16(memory, class_ptr, 0);
            }
            if class_size_ptr != 0 {
                written &= write_u32(memory, class_size_ptr, 0);
            }
            if max_class_ptr != 0 {
                written &= write_u32(memory, max_class_ptr, 0);
            }
            if last_write_ptr != 0 {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let filetime = now.saturating_add(11_644_473_600) * 10_000_000;
                written &= write_u32(memory, last_write_ptr, filetime as u32);
                written &= write_u32(memory, last_write_ptr + 4, (filetime >> 32) as u32);
            }
            if !written {
                return false;
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::ShRegGetValueW => {
            const SRRF_RT_ANY: u32 = 0xFFFF;
            let Some(
                [
                    hkey,
                    sub_key_ptr,
                    value_ptr,
                    srrf_flags,
                    type_ptr,
                    data_ptr,
                    data_size_ptr,
                ],
            ) = read_args::<7>(context, memory)
            else {
                return false;
            };
            let sub_key = if sub_key_ptr != 0 {
                let Some(sub_key) = read_utf16_lossy(memory, sub_key_ptr) else {
                    return false;
                };
                sub_key
            } else {
                String::new()
            };
            if !sub_key.is_empty() {
                // The snapshot indexes roots and open key handles; an
                // arbitrary subkey path is resolved by the owner from the
                // live registry database.
                mark_fallback(WorkerFallback::UnsupportedInput);
                return false;
            }
            let value_name = if value_ptr != 0 {
                let Some(value_name) = read_utf16_lossy(memory, value_ptr) else {
                    return false;
                };
                value_name
            } else {
                String::new()
            };
            let Some(registry) = shared.worker_registry_snapshot() else {
                return false;
            };
            let Some(key) = worker_registry_key_entry(&registry, hkey as u32, context.state.arch)
            else {
                mark_fallback(WorkerFallback::UnsupportedInput);
                return false;
            };
            let Some(stored) = key.values.get(&value_name) else {
                context
                    .state
                    .set(Register::Rax, u64::from(ERROR_FILE_NOT_FOUND));
                context.last_error = 0;
                return true;
            };
            let Some(type_code) = registry_value_type_to_win32(&stored.value_type).ok() else {
                mark_fallback(WorkerFallback::UnsupportedInput);
                return false;
            };
            let Ok(encoded) = encode_registry_value_data(stored) else {
                mark_fallback(WorkerFallback::UnsupportedInput);
                return false;
            };
            let srrf_flags = srrf_flags as u32;
            if srrf_flags & SRRF_RT_ANY != 0 {
                let mask = match type_code {
                    1 => 0x0002,
                    2 => 0x0004,
                    7 => 0x0008,
                    3 => 0x0010,
                    4 => 0x0020,
                    11 => 0x0040,
                    _ => 0,
                };
                if srrf_flags & mask == 0 {
                    context
                        .state
                        .set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    context.last_error = 0;
                    return true;
                }
            }
            if type_ptr != 0 && !write_u32(memory, type_ptr, type_code) {
                return false;
            }
            let available = encoded.len() as u32;
            if data_size_ptr != 0 {
                let Some(capacity) = read_u32(memory, data_size_ptr) else {
                    return false;
                };
                if data_ptr != 0 && capacity < available {
                    if !write_u32(memory, data_size_ptr, available) {
                        return false;
                    }
                    context.state.set(Register::Rax, u64::from(ERROR_MORE_DATA));
                    context.last_error = 0;
                    return true;
                }
                if data_ptr != 0 && !encoded.is_empty() && !write_bytes(memory, data_ptr, &encoded)
                {
                    return false;
                }
                if !write_u32(memory, data_size_ptr, available) {
                    return false;
                }
            }
            context.state.set(Register::Rax, 0);
            context.last_error = 0;
            true
        }
        WorkerApi::LcMapStringW | WorkerApi::LcMapStringEx => {
            let args = if api == WorkerApi::LcMapStringW {
                read_args::<6>(context, memory).map(
                    |[_, flags, source, source_len, destination, destination_len]| {
                        (flags, source, source_len, destination, destination_len)
                    },
                )
            } else {
                let Some(
                    [
                        locale_name_ptr,
                        flags,
                        source,
                        source_len,
                        destination,
                        destination_len,
                    ],
                ) = read_args::<6>(context, memory)
                else {
                    return false;
                };
                if locale_name_ptr != 0 {
                    let Some(locale_name) = read_utf16_lossy(memory, locale_name_ptr) else {
                        return false;
                    };
                    if locale_name_to_lcid(&locale_name).is_none() {
                        context.state.set(Register::Rax, 0);
                        context.last_error = ERROR_INVALID_PARAMETER;
                        return true;
                    }
                }
                Some((flags, source, source_len, destination, destination_len))
            };
            let Some((flags, source, source_len, destination, destination_len)) = args else {
                return false;
            };
            lcmap_string_worker(
                context,
                memory,
                flags as u32,
                source,
                source_len as i32,
                destination,
                destination_len as i32,
            )
        }
        WorkerApi::CharUpperW => {
            let Some(value) = read_arg(context, memory, 0) else {
                return false;
            };
            if value <= u16::MAX as u64 {
                context
                    .state
                    .set(Register::Rax, u64::from(cp1252_uppercase(value as u32)));
            } else {
                let Some(text) = read_utf16_lossy(memory, value) else {
                    return false;
                };
                let mut bytes = Vec::new();
                for unit in text.encode_utf16() {
                    let upper = cp1252_uppercase(u32::from(unit));
                    let unit = if upper <= u16::MAX as u32 {
                        upper as u16
                    } else {
                        unit
                    };
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                bytes.extend_from_slice(&0_u16.to_le_bytes());
                if !write_bytes(memory, value, &bytes) {
                    return false;
                }
                context.state.set(Register::Rax, value);
            }
            context.last_error = 0;
            true
        }
        WorkerApi::IsCharAlphaW
        | WorkerApi::IsCharAlphaNumericW
        | WorkerApi::IsCharLowerW
        | WorkerApi::IsCharUpperW
        | WorkerApi::IsCharSpaceW => {
            let Some(character) = read_arg(context, memory, 0) else {
                return false;
            };
            let mask = classify_wide_char_type(CT_CTYPE1, character as u16);
            let result = match api {
                WorkerApi::IsCharAlphaW => mask & C1_ALPHA != 0,
                WorkerApi::IsCharAlphaNumericW => mask & (C1_ALPHA | C1_DIGIT) != 0,
                WorkerApi::IsCharLowerW => mask & C1_LOWER != 0,
                WorkerApi::IsCharUpperW => mask & C1_UPPER != 0,
                WorkerApi::IsCharSpaceW => mask & C1_SPACE != 0,
                _ => unreachable!(),
            };
            context.state.set(Register::Rax, u64::from(result));
            context.last_error = 0;
            true
        }
        WorkerApi::TlsSetValue => {
            let Some([slot, value]) = read_args::<2>(context, memory) else {
                return false;
            };
            let slot = slot as u32;
            if slot >= 4096 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            if context.tls_vector_ptr != 0 {
                let pointer_bytes = context.state.arch.pointer_bytes() as u64;
                let address = context
                    .tls_vector_ptr
                    .wrapping_add(u64::from(slot) * pointer_bytes);
                if !write_pointer(memory, address, value, context.state.arch) {
                    return false;
                }
                if let Some(entry) = context.tls_slots.get_mut(&slot) {
                    *entry = value;
                }
            } else {
                context.tls_slots.insert(slot, value);
            }
            context.state.set(Register::Rax, 1);
            context.last_error = 0;
            true
        }
        WorkerApi::FlsSetValue => {
            let Some([slot, value]) = read_args::<2>(context, memory) else {
                return false;
            };
            let stored = if let Some(entry) = context.fls_slots.get_mut(&(slot as u32)) {
                *entry = value;
                true
            } else {
                false
            };
            context.state.set(Register::Rax, u64::from(stored));
            context.last_error = if stored { 0 } else { ERROR_INVALID_PARAMETER };
            true
        }
        WorkerApi::SystemTimeToTzSpecificLocalTime => {
            let Some([_timezone_ptr, system_time_ptr, local_time_ptr]) =
                read_args::<3>(context, memory)
            else {
                return false;
            };
            if system_time_ptr == 0 || local_time_ptr == 0 {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_INVALID_PARAMETER;
                return true;
            }
            let Some(year) = read_u16(memory, system_time_ptr) else {
                return false;
            };
            let Some(month) = read_u16(memory, system_time_ptr + 2) else {
                return false;
            };
            let Some(day) = read_u16(memory, system_time_ptr + 6) else {
                return false;
            };
            let Some(hour) = read_u16(memory, system_time_ptr + 8) else {
                return false;
            };
            let Some(minute) = read_u16(memory, system_time_ptr + 10) else {
                return false;
            };
            let Some(second) = read_u16(memory, system_time_ptr + 12) else {
                return false;
            };
            let Some(milliseconds) = read_u16(memory, system_time_ptr + 14) else {
                return false;
            };
            let filetime = systemtime_to_filetime_ticks(
                i32::from(year),
                i32::from(month),
                i32::from(day),
                i32::from(hour),
                i32::from(minute),
                i32::from(second),
                i32::from(milliseconds),
            );
            let bias = i128::from(local_timezone_bias_minutes()) * 600_000_000_i128;
            let biased = (i128::from(filetime) - bias).max(0) as u64;
            let (year, month, day_of_week, day, hour, minute, second, milliseconds) =
                filetime_ticks_to_systemtime(biased);
            let mut written = write_u16(memory, local_time_ptr, year);
            written &= write_u16(memory, local_time_ptr + 2, month);
            written &= write_u16(memory, local_time_ptr + 4, day_of_week);
            written &= write_u16(memory, local_time_ptr + 6, day);
            written &= write_u16(memory, local_time_ptr + 8, hour);
            written &= write_u16(memory, local_time_ptr + 10, minute);
            written &= write_u16(memory, local_time_ptr + 12, second);
            written &= write_u16(memory, local_time_ptr + 14, milliseconds);
            if !written {
                return false;
            }
            // The owner preserves last-error on this success path.
            context.state.set(Register::Rax, 1);
            true
        }
        WorkerApi::GetSystemMetrics => {
            let Some(index) = read_arg(context, memory, 0) else {
                return false;
            };
            let Some(display) = shared.worker_display_snapshot() else {
                return false;
            };
            let index = index as i32;
            let (screen_w, screen_h) = (display.screen_width, display.screen_height);
            let value = match index {
                0 => screen_w,
                1 => screen_h,
                2 | 3 => 17,
                4 => 23,
                5 | 6 => 1,
                7 | 8 => 4,
                9 => 17,
                10 => 17,
                11 | 12 => 32,
                13 | 14 => 32,
                15 => 19,
                16 => screen_w,
                17 => screen_h,
                18 => 0,
                19 => 1,
                20 => 17,
                21 => 17,
                22 => 0,
                23 => 0,
                24 | 25 => 0,
                26 | 27 => 0,
                28 => 80,
                29 => 80,
                30 | 31 => 16,
                32 | 33 => 4,
                34 => 80,
                35 => 80,
                36 | 37 => 4,
                38 | 39 => 75,
                40 => 0,
                41 => 0,
                42 => 0,
                43 => 5,
                44 => 0,
                45 | 46 => 2,
                47 | 48 => 28,
                49 | 50 => 16,
                51 => 18,
                52 | 53 => 12,
                54 | 55 => 16,
                56 => 0,
                57 => 160,
                58 => 28,
                59 => 2560,
                60 => 1600,
                61 => 2560,
                62 => 1600,
                63 => 0,
                67 => 0,
                68 | 69 => 4,
                70 => 0,
                71 | 72 => 13,
                73 => 0,
                74 => 0,
                75 => 1,
                76 => 0,
                77 => 0,
                78 => screen_w,
                79 => screen_h,
                80 => display.monitor_count,
                81 => 1,
                82 => 1,
                83 | 84 => 1,
                86 => 0,
                87 => 0,
                88 => 0,
                89 => 0,
                90 => display.screen_dpi,
                91 => 1,
                92 => 4,
                94 => 0,
                95 => 0,
                0x1000 => 0,
                0x2000 => 0,
                0x2001 => 0,
                0x2002 => 1,
                0x2003 => 0,
                0x2004 => 0,
                _ => 0,
            };
            context.state.set(Register::Rax, u64::from(value));
            context.last_error = 0;
            true
        }
        WorkerApi::GetFullPathNameW => {
            let Some([path_ptr, size, buffer, file_part_ptr]) = read_args::<4>(context, memory)
            else {
                return false;
            };
            let size = size as u32;
            let Some(raw_path) = read_utf16_lossy(memory, path_ptr) else {
                return false;
            };
            if raw_path.is_empty() {
                context.state.set(Register::Rax, 0);
                context.last_error = ERROR_PATH_NOT_FOUND;
                return true;
            }
            let Some(current_directory) = shared.worker_current_directory_snapshot() else {
                return false;
            };
            let path = resolve_full_guest_path(&current_directory, &raw_path);
            let path_length = path.encode_utf16().count() as u32;
            let Some(result) = write_utf16_api_string_worker(memory, buffer, size, &path) else {
                return false;
            };
            let file_part = if buffer != 0 && size >= path_length.saturating_add(1) {
                windows_file_part_offset(&path)
                    .map(|offset| buffer + offset)
                    .unwrap_or(0)
            } else {
                0
            };
            if file_part_ptr != 0
                && !write_pointer(memory, file_part_ptr, file_part, context.state.arch)
            {
                return false;
            }
            context.state.set(Register::Rax, u64::from(result));
            context.last_error = if buffer != 0 && size != 0 && size <= path_length {
                ERROR_INSUFFICIENT_BUFFER
            } else {
                0
            };
            true
        }
        WorkerApi::GetLongPathNameW | WorkerApi::GetShortPathNameW => {
            let Some([path_ptr, buffer, buffer_size]) = read_args::<3>(context, memory) else {
                return false;
            };
            let Some(raw_path) = read_utf16_lossy(memory, path_ptr) else {
                return false;
            };
            let Some(current_directory) = shared.worker_current_directory_snapshot() else {
                return false;
            };
            let path = resolve_full_guest_path(&current_directory, &raw_path);
            let Some(result) =
                write_utf16_api_string_worker(memory, buffer, buffer_size as u32, &path)
            else {
                return false;
            };
            context.state.set(Register::Rax, u64::from(result));
            context.last_error = 0;
            true
        }
        WorkerApi::GetFileType => {
            let Some(handle) = read_arg(context, memory, 0) else {
                return false;
            };
            let handle = handle as u32;
            let file_type = match handle {
                STD_INPUT_HANDLE | STD_OUTPUT_HANDLE | STD_ERROR_HANDLE => FILE_TYPE_CHAR,
                0 | u32::MAX => FILE_TYPE_UNKNOWN,
                _ => {
                    let Some(objects) = shared.worker_object_status_snapshot() else {
                        return false;
                    };
                    objects
                        .file_types
                        .get(&handle)
                        .copied()
                        .unwrap_or(FILE_TYPE_UNKNOWN)
                }
            };
            context.state.set(Register::Rax, u64::from(file_type));
            context.last_error = if file_type == FILE_TYPE_UNKNOWN {
                ERROR_INVALID_HANDLE
            } else {
                0
            };
            true
        }
    }
}

const INVALID_FILE_ATTRIBUTES: u64 = u32::MAX as u64;

/// The owner resolves a drive-absolute path to itself.  Only that exact form
/// is serviced on the worker; relative/UNC/`.`/`..`/duplicate-separator input
/// falls back so the owner's resolver stays authoritative.
fn is_canonical_guest_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return false;
    }
    if bytes.len() == 3 {
        return true;
    }
    if path.contains('/') || path.ends_with('\\') || path.contains("\\\\") {
        return false;
    }
    !path
        .split('\\')
        .skip(1)
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

fn attributes_mask_w(attributes: &[String]) -> u32 {
    let mut raw = 0_u32;
    for attribute in attributes {
        match attribute.as_str() {
            "directory" => raw |= FILE_ATTRIBUTE_DIRECTORY,
            "readonly" => raw |= FILE_ATTRIBUTE_READONLY,
            "hidden" => raw |= 0x0000_0002,
            "system" => raw |= 0x0000_0004,
            "archive" => raw |= 0x0000_0020,
            "reparse_point" => raw |= 0x0000_0400,
            _ => {}
        }
    }
    if raw == 0 { FILE_ATTRIBUTE_NORMAL } else { raw }
}

fn attributes_mask_a(attributes: &[String]) -> u32 {
    let mut raw = 0x80_u32; // FILE_ATTRIBUTE_NORMAL
    for attribute in attributes {
        match attribute.as_str() {
            "readonly" => raw |= 0x01,
            "hidden" => raw |= 0x02,
            "system" => raw |= 0x04,
            "directory" => raw |= 0x10,
            "archive" => raw |= 0x20,
            "device" => raw |= 0x40,
            "temporary" => raw |= 0x100,
            "compressed" => raw |= 0x800,
            "offline" => raw |= 0x1000,
            _ => {}
        }
    }
    raw
}

fn filetime_worker(memory: &dyn WorkerMemoryView, address: u64, ticks: u64) -> bool {
    write_u32(memory, address, ticks as u32) && write_u32(memory, address + 4, (ticks >> 32) as u32)
}

fn write_file_attribute_data_worker(
    memory: &dyn WorkerMemoryView,
    address: u64,
    data: &super::WorkerFileMetadata,
) -> bool {
    let attributes = if data.is_directory {
        attributes_mask_w(&data.attributes) | FILE_ATTRIBUTE_DIRECTORY
    } else {
        attributes_mask_w(&data.attributes)
    };
    write_u32(memory, address, attributes)
        && filetime_worker(memory, address + 4, data.creation_time_ticks)
        && filetime_worker(memory, address + 12, data.last_access_time_ticks)
        && filetime_worker(memory, address + 20, data.last_write_time_ticks)
        && write_u32(memory, address + 28, (data.size >> 32) as u32)
        && write_u32(memory, address + 32, data.size as u32)
}

/// Mirrors `write_utf16_api_string`: size-query/truncation/success contract.
fn write_utf16_api_string_worker(
    memory: &dyn WorkerMemoryView,
    buffer: u64,
    size: u32,
    value: &str,
) -> Option<u32> {
    let units: Vec<u16> = value.encode_utf16().collect();
    let required_without_nul = units.len() as u32;
    let required_with_nul = required_without_nul + 1;
    if buffer != 0 && size != 0 {
        let copy_units = units.len().min(size.saturating_sub(1) as usize);
        let mut bytes = vec![0_u8; (copy_units + 1) * 2];
        for (index, unit) in units.iter().take(copy_units).enumerate() {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        if !write_bytes(memory, buffer, &bytes) {
            return None;
        }
    }
    Some(if size <= required_without_nul {
        required_with_nul
    } else {
        required_without_nul
    })
}

fn host_utc_components() -> (u16, u16, u16, u16, u16, u16, u16) {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = duration.as_secs() / 86_400;
    let mut year = 1970_i64;
    let mut remaining = days as i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let days_in_year = if leap { 366 } else { 365 };
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
    for days_in_month in month_days {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }
    let secs_of_day = duration.as_secs() % 86_400;
    (
        year as u16,
        month as u16,
        (remaining + 1) as u16,
        (secs_of_day / 3_600) as u16,
        ((secs_of_day % 3_600) / 60) as u16,
        (secs_of_day % 60) as u16,
        (duration.as_millis() % 1000) as u16,
    )
}

fn take_utf16_prefix(text: String, length: i32) -> String {
    if length < 0 {
        text
    } else {
        let units: Vec<u16> = text.encode_utf16().take(length as usize).collect();
        String::from_utf16_lossy(&units)
    }
}

fn write_time_zone_information_worker(
    memory: &dyn WorkerMemoryView,
    address: u64,
    info: &super::super::HostTimeZoneInformation,
) -> bool {
    const TIME_ZONE_INFORMATION_SIZE: usize = 172;
    const TIME_ZONE_NAME_CAPACITY: usize = 32;
    if !write_bytes(memory, address, &[0_u8; TIME_ZONE_INFORMATION_SIZE]) {
        return false;
    }
    if !write_u32(memory, address, info.bias_minutes as u32) {
        return false;
    }
    if !write_utf16_fixed(
        memory,
        address + 4,
        TIME_ZONE_NAME_CAPACITY,
        &info.standard_name,
    ) {
        return false;
    }
    if !write_u32(memory, address + 84, 0) {
        return false;
    }
    if !write_utf16_fixed(
        memory,
        address + 88,
        TIME_ZONE_NAME_CAPACITY,
        &info.daylight_name,
    ) {
        return false;
    }
    write_u32(memory, address + 168, 0)
}

fn write_utf16_fixed(
    memory: &dyn WorkerMemoryView,
    address: u64,
    capacity: usize,
    value: &str,
) -> bool {
    let mut bytes = vec![0_u8; capacity * 2];
    for (index, unit) in value
        .encode_utf16()
        .take(capacity.saturating_sub(1))
        .enumerate()
    {
        let offset = index * 2;
        bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    write_bytes(memory, address, &bytes)
}

fn write_date_time_result_worker(
    memory: &dyn WorkerMemoryView,
    context: &mut GuestThreadContext,
    text: &str,
    buffer_ptr: u64,
    buffer_size: i32,
) -> bool {
    let utf16: Vec<u16> = text.encode_utf16().collect();
    let required = utf16.len() + 1;
    if buffer_ptr == 0 || buffer_size <= 0 {
        context.state.set(Register::Rax, required as u64);
        return true;
    }
    if (buffer_size as usize) < required {
        context.state.set(Register::Rax, 0);
        context.last_error = ERROR_INSUFFICIENT_BUFFER;
        return true;
    }
    let bytes = utf16
        .iter()
        .chain(std::iter::once(&0_u16))
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    if !write_bytes(memory, buffer_ptr, &bytes) {
        return false;
    }
    context.state.set(Register::Rax, utf16.len() as u64);
    context.last_error = 0;
    true
}

fn format_date_tokens_worker(
    memory: &dyn WorkerMemoryView,
    format_ptr: u64,
    year: u16,
    month: u16,
    day: u16,
    dow: u16,
) -> Option<String> {
    let format = read_utf16_lossy(memory, format_ptr)?;
    let units: Vec<u16> = format.encode_utf16().collect();
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
    Some(out)
}

fn format_time_tokens_worker(
    memory: &dyn WorkerMemoryView,
    format_ptr: u64,
    hour: u16,
    minute: u16,
    second: u16,
    force24: bool,
) -> Option<String> {
    let format = read_utf16_lossy(memory, format_ptr)?;
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
    Some(out)
}

fn read_c_string_lossy(memory: &dyn WorkerMemoryView, address: u64) -> Option<String> {
    if address == 0 {
        return Some(String::new());
    }
    let mut bytes = Vec::new();
    let mut cursor = address;
    loop {
        let Some(byte) = memory.load(cursor, 1) else {
            mark_fallback(WorkerFallback::UnsupportedInput);
            return None;
        };
        let byte = byte as u8;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
        cursor = cursor.wrapping_add(1);
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn read_utf16_lossy(memory: &dyn WorkerMemoryView, address: u64) -> Option<String> {
    if address == 0 {
        return Some(String::new());
    }
    let mut units = Vec::new();
    let mut cursor = address;
    loop {
        let Some(unit) = memory.load(cursor, 2) else {
            mark_fallback(WorkerFallback::UnsupportedInput);
            return None;
        };
        let unit = unit as u16;
        if unit == 0 {
            break;
        }
        units.push(unit);
        cursor = cursor.wrapping_add(2);
    }
    Some(String::from_utf16_lossy(&units))
}

fn read_utf16_units(
    memory: &dyn WorkerMemoryView,
    address: u64,
    length: usize,
) -> Option<Vec<u16>> {
    let mut units = Vec::with_capacity(length);
    for index in 0..length {
        let Some(unit) = memory.load(address.wrapping_add((index as u64) * 2), 2) else {
            mark_fallback(WorkerFallback::UnsupportedInput);
            return None;
        };
        units.push(unit as u16);
    }
    Some(units)
}

fn read_raw(memory: &dyn WorkerMemoryView, address: u64, length: usize) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(length);
    let mut offset = 0usize;
    while offset < length {
        let chunk = (length - offset).min(8);
        let Some(value) = memory.load(address.wrapping_add(offset as u64), chunk) else {
            mark_fallback(WorkerFallback::UnsupportedInput);
            return None;
        };
        for index in 0..chunk {
            bytes.push((value >> (index * 8)) as u8);
        }
        offset += chunk;
    }
    Some(bytes)
}

fn write_pointer(memory: &dyn WorkerMemoryView, address: u64, value: u64, arch: GuestArch) -> bool {
    match arch {
        GuestArch::X86 => write_u32(memory, address, value as u32),
        GuestArch::X64 => write_u64(memory, address, value),
    }
}

enum Conversion<T> {
    Value(T),
    Invalid,
    Unsupported,
}

fn multi_byte_to_wide(code_page: u32, bytes: &[u8], locale: WorkerLocale) -> Conversion<Vec<u16>> {
    let cp = if code_page == CP_ACP || code_page == CP_THREAD_ACP {
        locale.acp
    } else {
        code_page
    };
    match cp {
        CP_UTF8 => match std::str::from_utf8(bytes) {
            Ok(text) => Conversion::Value(text.encode_utf16().collect()),
            Err(_) => Conversion::Invalid,
        },
        1252 if locale.acp == 1252 => Conversion::Value(
            bytes
                .iter()
                .map(|byte| decode_cp1252(*byte) as u16)
                .collect(),
        ),
        _ => Conversion::Unsupported,
    }
}

fn wide_to_multi_byte(code_page: u32, wide: &[u16], locale: WorkerLocale) -> Conversion<Vec<u8>> {
    let cp = if code_page == CP_ACP || code_page == CP_THREAD_ACP {
        locale.acp
    } else {
        code_page
    };
    let Ok(text) = String::from_utf16(wide) else {
        return Conversion::Invalid;
    };
    match cp {
        CP_UTF8 => Conversion::Value(text.into_bytes()),
        1252 if locale.acp == 1252 => {
            let mut encoded = Vec::with_capacity(text.len());
            for ch in text.chars() {
                let Some(byte) = encode_cp1252(ch) else {
                    return Conversion::Invalid;
                };
                encoded.push(byte);
            }
            Conversion::Value(encoded)
        }
        _ => Conversion::Unsupported,
    }
}

fn decode_cp1252(byte: u8) -> char {
    match byte {
        0x80 => '€',
        0x82 => '‚',
        0x83 => 'ƒ',
        0x84 => '„',
        0x85 => '…',
        0x86 => '†',
        0x87 => '‡',
        0x88 => 'ˆ',
        0x89 => '‰',
        0x8A => 'Š',
        0x8B => '‹',
        0x8C => 'Œ',
        0x8E => 'Ž',
        0x91 => '‘',
        0x92 => '’',
        0x93 => '“',
        0x94 => '”',
        0x95 => '•',
        0x96 => '–',
        0x97 => '—',
        0x98 => '˜',
        0x99 => '™',
        0x9A => 'š',
        0x9B => '›',
        0x9C => 'œ',
        0x9E => 'ž',
        0x9F => 'Ÿ',
        other => char::from(other),
    }
}

fn encode_cp1252(ch: char) -> Option<u8> {
    match ch {
        '€' => Some(0x80),
        '‚' => Some(0x82),
        'ƒ' => Some(0x83),
        '„' => Some(0x84),
        '…' => Some(0x85),
        '†' => Some(0x86),
        '‡' => Some(0x87),
        'ˆ' => Some(0x88),
        '‰' => Some(0x89),
        'Š' => Some(0x8A),
        '‹' => Some(0x8B),
        'Œ' => Some(0x8C),
        'Ž' => Some(0x8E),
        '‘' => Some(0x91),
        '’' => Some(0x92),
        '“' => Some(0x93),
        '”' => Some(0x94),
        '•' => Some(0x95),
        '–' => Some(0x96),
        '—' => Some(0x97),
        '˜' => Some(0x98),
        '™' => Some(0x99),
        'š' => Some(0x9A),
        '›' => Some(0x9B),
        'œ' => Some(0x9C),
        'ž' => Some(0x9E),
        'Ÿ' => Some(0x9F),
        '\u{0081}' => Some(0x81),
        '\u{008d}' => Some(0x8D),
        '\u{008f}' => Some(0x8F),
        '\u{0090}' => Some(0x90),
        '\u{009d}' => Some(0x9D),
        other if (other as u32) < 0x80 || (other as u32) >= 0xA0 && (other as u32) <= 0xFF => {
            Some(other as u8)
        }
        _ => None,
    }
}

fn worker_registry_view(sam_desired: u32, guest_arch: GuestArch) -> u8 {
    if sam_desired & KEY_WOW64_64KEY != 0 {
        2 // Native64
    } else if sam_desired & KEY_WOW64_32KEY != 0 || guest_arch == GuestArch::X86 {
        1 // Wow6432
    } else {
        0 // Native
    }
}

fn root_registry_key(hkey: u32) -> Option<(&'static str, &'static str)> {
    match hkey {
        HKEY_CLASSES_ROOT => Some(("HKCR", "")),
        HKEY_CURRENT_USER => Some(("HKCU", "")),
        HKEY_LOCAL_MACHINE => Some(("HKLM", "")),
        HKEY_USERS => Some(("HKCU", "")),
        HKEY_CURRENT_CONFIG => Some((
            "HKLM",
            "System\\CurrentControlSet\\Hardware Profiles\\Current",
        )),
        _ => None,
    }
}

fn worker_registry_key_entry<'a>(
    registry: &'a WorkerRegistry,
    hkey: u32,
    arch: GuestArch,
) -> Option<&'a WorkerRegistryKey> {
    if let Some((hive, base_key)) = root_registry_key(hkey) {
        let view = worker_registry_view(0, arch);
        let normalized = normalize_registry_runtime_key(hive, base_key);
        registry
            .roots
            .get(&(hkey, view))
            .filter(|entry| entry.hive == hive && entry.key == normalized)
    } else {
        registry.keys.get(&hkey)
    }
}

fn lcmap_string_worker(
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    flags: u32,
    source_ptr: u64,
    source_len: i32,
    destination_ptr: u64,
    destination_len: i32,
) -> bool {
    const LCMAP_LOWERCASE: u32 = 0x0000_0100;
    const LCMAP_UPPERCASE: u32 = 0x0000_0200;
    if source_ptr == 0
        || source_len == 0
        || (flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE)) == (LCMAP_LOWERCASE | LCMAP_UPPERCASE)
    {
        context.state.set(Register::Rax, 0);
        context.last_error = ERROR_INVALID_PARAMETER;
        return true;
    }
    let source_units = if source_len < 0 {
        let Some(text) = read_utf16_lossy(memory, source_ptr) else {
            return false;
        };
        text.encode_utf16().chain(std::iter::once(0)).collect()
    } else {
        let Some(units) = read_utf16_units(memory, source_ptr, source_len as usize) else {
            return false;
        };
        units
    };
    let mapped_units = if flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE) != 0 {
        source_units
            .into_iter()
            .map(|unit| {
                let Some(original) = char::from_u32(u32::from(unit)) else {
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
                if encode_cp1252(candidate).is_none() {
                    return unit;
                }
                encoded[0]
            })
            .collect::<Vec<_>>()
    } else {
        source_units
    };
    let required = mapped_units.len() as u32;
    if destination_ptr == 0 || destination_len == 0 {
        context.state.set(Register::Rax, u64::from(required));
        context.last_error = 0;
        return true;
    }
    if destination_len < required as i32 {
        context.state.set(Register::Rax, 0);
        context.last_error = ERROR_INSUFFICIENT_BUFFER;
        return true;
    }
    let encoded = mapped_units
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    if !encoded.is_empty() && !write_bytes(memory, destination_ptr, &encoded) {
        return false;
    }
    context.state.set(Register::Rax, u64::from(required));
    context.last_error = 0;
    true
}

fn query_registry_value(
    api: WorkerApi,
    shared: &ProcessShared,
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
) -> bool {
    let Some(
        [
            hkey,
            value_name_ptr,
            reserved_ptr,
            value_type_ptr,
            data_ptr,
            data_len_ptr,
        ],
    ) = read_args::<6>(context, memory)
    else {
        return false;
    };
    if reserved_ptr != 0 || data_len_ptr == 0 {
        context
            .state
            .set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
        context.last_error = ERROR_INVALID_PARAMETER;
        return true;
    }
    let value_name = if value_name_ptr == 0 {
        String::new()
    } else if api == WorkerApi::RegQueryValueExA {
        let Some(name) = read_c_string_lossy(memory, value_name_ptr) else {
            return false;
        };
        name
    } else {
        let Some(name) = read_utf16_lossy(memory, value_name_ptr) else {
            return false;
        };
        name
    };
    let Some(registry) = shared.worker_registry_snapshot() else {
        return false;
    };
    let key = if let Some((hive, base_key)) = root_registry_key(hkey as u32) {
        let view = worker_registry_view(0, context.state.arch);
        let normalized = normalize_registry_runtime_key(hive, base_key);
        registry
            .roots
            .get(&(hkey as u32, view))
            .filter(|entry| entry.hive == hive && entry.key == normalized)
    } else {
        registry.keys.get(&(hkey as u32))
    };
    let Some(key) = key else {
        return false;
    };
    let value = key.values.get(&value_name);
    let Some(value) = value else {
        if !write_u32(memory, data_len_ptr, 0) {
            return false;
        }
        if value_type_ptr != 0 && !write_u32(memory, value_type_ptr, 0) {
            return false;
        }
        context
            .state
            .set(Register::Rax, u64::from(ERROR_FILE_NOT_FOUND));
        context.last_error = ERROR_FILE_NOT_FOUND;
        return true;
    };
    let Ok(type_code) = registry_value_type_to_win32(&value.value_type) else {
        return false;
    };
    let encoded = if api == WorkerApi::RegQueryValueExA {
        encode_registry_value_data_ansi(value)
    } else {
        encode_registry_value_data(value)
    };
    let Ok(encoded) = encoded else {
        return false;
    };
    let Some(buffer_capacity) = read_u32(memory, data_len_ptr) else {
        return false;
    };
    if !write_u32(memory, data_len_ptr, encoded.len() as u32) {
        return false;
    }
    if value_type_ptr != 0 && !write_u32(memory, value_type_ptr, type_code) {
        return false;
    }
    if data_ptr != 0 && buffer_capacity < encoded.len() as u32 {
        context.state.set(Register::Rax, u64::from(ERROR_MORE_DATA));
        context.last_error = ERROR_MORE_DATA;
    } else {
        if data_ptr != 0 && !encoded.is_empty() && !write_bytes(memory, data_ptr, &encoded) {
            return false;
        }
        context.state.set(Register::Rax, 0);
        context.last_error = 0;
    }
    true
}

fn read_args<const N: usize>(
    context: &GuestThreadContext,
    memory: &dyn WorkerMemoryView,
) -> Option<[u64; N]> {
    let mut values = [0_u64; N];
    for (index, value) in values.iter_mut().enumerate() {
        *value = read_arg(context, memory, index)?;
    }
    Some(values)
}

fn read_arg(
    context: &GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    index: usize,
) -> Option<u64> {
    let state = &context.state;
    let value = match state.arch {
        GuestArch::X64 => match index {
            0 => Some(state.get(Register::Rcx)),
            1 => Some(state.get(Register::Rdx)),
            2 => Some(state.get(Register::R8)),
            3 => Some(state.get(Register::R9)),
            _ => memory.load(
                state.get(Register::Rsp) + 0x20 + ((index - 4) as u64 * 8),
                8,
            ),
        },
        GuestArch::X86 => memory.load(state.get(Register::Rsp) + (index as u64 * 4), 4),
    };
    if value.is_none() {
        mark_fallback(WorkerFallback::UnsupportedInput);
    }
    value
}

fn read_u16(memory: &dyn WorkerMemoryView, address: u64) -> Option<u16> {
    let value = memory.load(address, 2).map(|value| value as u16);
    if value.is_none() {
        mark_fallback(WorkerFallback::UnsupportedInput);
    }
    value
}

fn write_bytes(memory: &dyn WorkerMemoryView, address: u64, bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + 8).min(bytes.len());
        if !memory.store(address + offset as u64, &bytes[offset..end]) {
            mark_fallback(WorkerFallback::GuestMemoryWrite);
            return false;
        }
        offset = end;
    }
    true
}

fn write_u16(memory: &dyn WorkerMemoryView, address: u64, value: u16) -> bool {
    write_bytes(memory, address, &value.to_le_bytes())
}

fn write_u32(memory: &dyn WorkerMemoryView, address: u64, value: u32) -> bool {
    write_bytes(memory, address, &value.to_le_bytes())
}

fn write_u64(memory: &dyn WorkerMemoryView, address: u64, value: u64) -> bool {
    write_bytes(memory, address, &value.to_le_bytes())
}

fn write_version_info_w(
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    pointer: u64,
    version: &WorkerVersion,
) -> bool {
    const VER_PLATFORM_WIN32_NT: u32 = 2;
    const OSVERSIONINFOEXW_SIZE: u32 = 0x11C;
    let Some(reported_size) = read_u32(memory, pointer) else {
        return false;
    };
    if !write_u32(memory, pointer + 0x04, version.major)
        || !write_u32(memory, pointer + 0x08, version.minor)
        || !write_u32(memory, pointer + 0x0C, version.build)
        || !write_u32(memory, pointer + 0x10, VER_PLATFORM_WIN32_NT)
        || !write_bytes(memory, pointer + 0x14, &[0_u8; 0x100])
    {
        return false;
    }
    if reported_size >= OSVERSIONINFOEXW_SIZE
        && (!write_u16(memory, pointer + 0x114, version.service_pack_major)
            || !write_u16(memory, pointer + 0x116, version.service_pack_minor)
            || !write_u16(memory, pointer + 0x118, version.suite_mask)
            || !write_bytes(memory, pointer + 0x11A, &[version.product_type, 0]))
    {
        return false;
    }
    if !write_u32(memory, pointer, reported_size) {
        return false;
    }
    context.state.set(Register::Rax, 1);
    context.last_error = 0;
    true
}

fn write_version_info_a(
    context: &mut GuestThreadContext,
    memory: &dyn WorkerMemoryView,
    pointer: u64,
    version: &WorkerVersion,
) -> bool {
    const VER_PLATFORM_WIN32_NT: u32 = 2;
    const OSVERSIONINFOEXA_SIZE: u32 = 0x9C;
    let Some(reported_size) = read_u32(memory, pointer) else {
        return false;
    };
    if !write_u32(memory, pointer + 0x04, version.major)
        || !write_u32(memory, pointer + 0x08, version.minor)
        || !write_u32(memory, pointer + 0x0C, version.build)
        || !write_u32(memory, pointer + 0x10, VER_PLATFORM_WIN32_NT)
        || !write_bytes(memory, pointer + 0x14, &[0_u8; 0x80])
    {
        return false;
    }
    if reported_size >= OSVERSIONINFOEXA_SIZE
        && (!write_u16(memory, pointer + 0x94, version.service_pack_major)
            || !write_u16(memory, pointer + 0x96, version.service_pack_minor)
            || !write_u16(memory, pointer + 0x98, version.suite_mask)
            || !write_bytes(memory, pointer + 0x9A, &[version.product_type, 0]))
    {
        return false;
    }
    if !write_u32(memory, pointer, reported_size) {
        return false;
    }
    context.state.set(Register::Rax, 1);
    context.last_error = 0;
    true
}

fn read_u32(memory: &dyn WorkerMemoryView, address: u64) -> Option<u32> {
    let value = memory.load(address, 4).map(|value| value as u32);
    if value.is_none() {
        mark_fallback(WorkerFallback::UnsupportedInput);
    }
    value
}

fn write_system_info(memory: &dyn WorkerMemoryView, pointer: u64, guest_arch: GuestArch) -> bool {
    const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
    const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
    let (arch, pointer_size) = match guest_arch {
        GuestArch::X86 => (PROCESSOR_ARCHITECTURE_INTEL, 4u64),
        GuestArch::X64 => (PROCESSOR_ARCHITECTURE_AMD64, 8),
    };
    let max_address: u64 = if pointer_size == 8 {
        0x7FFE_FFFF_FFFF
    } else {
        0x7FFF_FFFF
    };
    let processor_level: u16 = if arch == PROCESSOR_ARCHITECTURE_INTEL {
        6
    } else {
        21
    };
    let mut offset = pointer;
    let mut ok = write_u16(memory, offset, arch);
    offset += 2;
    ok &= write_u16(memory, offset, 0);
    offset += 2;
    ok &= write_u32(memory, offset, 4096);
    offset += 4;
    ok &= write_u64(memory, offset, 0x10000);
    offset += pointer_size;
    ok &= write_u64(memory, offset, max_address);
    offset += pointer_size;
    ok &= write_u64(memory, offset, 0xFF);
    offset += pointer_size;
    ok &= write_u32(memory, offset, 8);
    offset += 4;
    ok &= write_u32(memory, offset, 0);
    offset += 4;
    ok &= write_u32(memory, offset, 0x10000);
    offset += 4;
    ok &= write_u16(memory, offset, processor_level);
    offset += 2;
    ok &= write_u16(memory, offset, 0);
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anticheat::MonotonicClock;
    use crate::cpu::CpuState;
    use crate::ge::StoredRegistryValue;
    use crate::runtime::{
        BarrierReason, GuestThreadContext, ParallelThunk, ProcessShared, WorkerCategory,
        WorkerClock, WorkerDisplayMetrics, WorkerEnvironment, WorkerFileMetadata, WorkerFileSystem,
        WorkerIdentity, WorkerLocale, WorkerMemoryStatus, WorkerObjectStatus, WorkerRegistry,
        WorkerRegistryKey, WorkerVersion,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const THUNK: u64 = 0x7000;
    const RETURN_ADDRESS: u64 = 0x9000;
    const STACK: u64 = 0x200;

    struct TestMemory {
        bytes: std::cell::RefCell<Vec<u8>>,
    }

    impl TestMemory {
        fn new() -> Self {
            Self {
                bytes: std::cell::RefCell::new(vec![0_u8; 0x2000]),
            }
        }
    }

    impl WorkerMemoryView for TestMemory {
        fn load(&self, address: u64, len: usize) -> Option<u64> {
            let start = usize::try_from(address).ok()?;
            let bytes = self.bytes.borrow();
            let slice = bytes.get(start..start.checked_add(len)?)?;
            let mut value = 0_u64;
            for (index, byte) in slice.iter().enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
            Some(value)
        }

        fn store(&self, address: u64, bytes: &[u8]) -> bool {
            let Ok(start) = usize::try_from(address) else {
                return false;
            };
            let mut target = self.bytes.borrow_mut();
            let Some(slot) = target.get_mut(start..) else {
                return false;
            };
            if slot.len() < bytes.len() {
                return false;
            }
            slot[..bytes.len()].copy_from_slice(bytes);
            true
        }

        fn atomic_fetch_add_u32(&self, address: u64, value: u32) -> Result<u32, AtomicGuestError> {
            let start = usize::try_from(address).map_err(|_| AtomicGuestError::Fault)?;
            let mut target = self.bytes.borrow_mut();
            let Some(slot) = target.get_mut(start..start + 4) else {
                return Err(AtomicGuestError::Fault);
            };
            let previous = u32::from_le_bytes(slot.try_into().expect("four bytes"));
            slot.copy_from_slice(&previous.wrapping_add(value).to_le_bytes());
            Ok(previous)
        }
    }

    fn registry_with_value(value: &str) -> WorkerRegistry {
        let mut registry = WorkerRegistry::default();
        let mut values = BTreeMap::new();
        values.insert(
            "Demo".to_string(),
            StoredRegistryValue {
                value_type: "REG_SZ".to_string(),
                data: json!(value),
            },
        );
        values.insert(
            "Ansi".to_string(),
            StoredRegistryValue {
                value_type: "REG_SZ".to_string(),
                data: json!("hi"),
            },
        );
        values.insert(
            "Count".to_string(),
            StoredRegistryValue {
                value_type: "REG_DWORD".to_string(),
                data: json!(7),
            },
        );
        let roots = [
            (HKEY_CLASSES_ROOT, "HKCR", ""),
            (HKEY_CURRENT_USER, "HKCU", ""),
            (HKEY_LOCAL_MACHINE, "HKLM", ""),
            (HKEY_USERS, "HKCU", ""),
            (
                HKEY_CURRENT_CONFIG,
                "HKLM",
                "System\\CurrentControlSet\\Hardware Profiles\\Current",
            ),
        ];
        for (handle, hive, base) in roots {
            for view in 0..=2 {
                registry.roots.insert(
                    (handle, view),
                    WorkerRegistryKey {
                        hive: hive.to_string(),
                        key: base.to_string(),
                        subkeys: vec!["Child".to_string(), "DemoSub".to_string()],
                        values: values.clone(),
                    },
                );
            }
        }
        registry.keys.insert(
            0x1234,
            WorkerRegistryKey {
                hive: "HKCU".to_string(),
                key: "Software\\Casa".to_string(),
                subkeys: vec!["Child".to_string()],
                values,
            },
        );
        registry
    }

    fn filesystem_snapshot() -> WorkerFileSystem {
        let mut files = WorkerFileSystem::default();
        files.entries.insert(
            "C:\\game\\data.bin".to_string(),
            WorkerFileMetadata {
                size: 12_345,
                attributes: vec!["readonly".to_string()],
                creation_time_ticks: 0x0102_0304_0506_0708,
                last_access_time_ticks: 0x1112_1314_1516_1718,
                last_write_time_ticks: 0x2122_2324_2526_2728,
                is_directory: false,
            },
        );
        files.entries.insert(
            "C:\\game".to_string(),
            WorkerFileMetadata {
                size: 0,
                attributes: vec!["directory".to_string()],
                creation_time_ticks: 1,
                last_access_time_ticks: 2,
                last_write_time_ticks: 3,
                is_directory: true,
            },
        );
        files.sizes.insert(0x10, 12_345);
        files
    }

    fn object_status_snapshot() -> WorkerObjectStatus {
        let mut objects = WorkerObjectStatus::default();
        objects.thread_exit_codes.insert(0x20, 0x1234);
        objects.process_exit_codes.insert(0x21, 0x5678);
        objects.thread_priorities.insert(0x22, -2);
        objects.file_types.insert(0x10, 1);
        objects
    }

    fn environment(process_id: u32) -> WorkerEnvironment {
        let mut environment = BTreeMap::new();
        environment.insert("CASA_TEST".to_string(), "value".to_string());
        let mut heap = BTreeMap::new();
        heap.insert(0x5000, 77_usize);
        WorkerEnvironment {
            identity: WorkerIdentity {
                process_id,
                process_handle: 0x44,
            },
            clock: WorkerClock {
                clock: Arc::new(MonotonicClock::new()),
                dtm: false,
                deterministic_tick_ms: 0,
            },
            version: Some(WorkerVersion {
                major: 10,
                minor: 0,
                build: 22631,
                service_pack_major: 0,
                service_pack_minor: 0,
                suite_mask: 0,
                product_type: 1,
            }),
            memory_status: Some(WorkerMemoryStatus {
                total_phys: 16 * 1024 * 1024 * 1024,
                avail_phys: 8 * 1024 * 1024 * 1024,
                total_page: 32 * 1024 * 1024 * 1024,
                avail_page: 16 * 1024 * 1024 * 1024,
            }),
            locale: WorkerLocale {
                acp: 1252,
                oemcp: 437,
            },
            environment,
            heap,
            registry: registry_with_value("hello"),
            files: filesystem_snapshot(),
            objects: object_status_snapshot(),
            current_directory: "C:\\game".to_string(),
            display: WorkerDisplayMetrics {
                screen_width: 2560,
                screen_height: 1600,
                screen_dpi: 96,
                monitor_count: 1,
            },
        }
    }

    fn x64_context(thread_id: u32) -> GuestThreadContext {
        let mut context = GuestThreadContext::new(thread_id, CpuState::new(GuestArch::X64));
        context.state.set(Register::Rsp, STACK);
        context
    }

    fn x86_context(thread_id: u32) -> GuestThreadContext {
        let mut context = GuestThreadContext::new(thread_id, CpuState::new(GuestArch::X86));
        context.state.set(Register::Rsp, STACK);
        context
    }

    fn thunk_address(context: &GuestThreadContext) -> u64 {
        THUNK + u64::from(context.thread_id) * 0x40
    }

    fn invoke(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thunk: HostThunk,
    ) -> bool {
        let address = thunk_address(context);
        shared.publish_thunk(address, &thunk);
        context.state.rip = address;
        let pointer = context.state.arch.pointer_bytes() as u64;
        let rsp = context.state.get(Register::Rsp);
        if rsp != 0 {
            let pushed = rsp - pointer;
            assert_eq!(
                memory.store(pushed, &RETURN_ADDRESS.to_le_bytes()[..pointer as usize]),
                true
            );
            context.state.set(Register::Rsp, pushed);
        }
        let executed = shared.run_worker_api(context, memory, address);
        if !executed {
            context.state.set(Register::Rsp, rsp);
        }
        executed
    }

    fn set_x86_arg(memory: &TestMemory, index: u64, value: u32) {
        assert_eq!(memory.store(STACK + index * 4, &value.to_le_bytes()), true);
    }

    fn invoke_x86(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thunk: HostThunk,
        args: &[u64],
    ) -> bool {
        context.state.set(Register::Rsp, STACK);
        for (index, value) in args.iter().enumerate() {
            set_x86_arg(memory, index as u64, *value as u32);
        }
        invoke(shared, context, memory, thunk)
    }

    fn store_ascii(memory: &TestMemory, address: u64, text: &str) {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        assert_eq!(memory.store(address, &bytes), true);
    }

    fn store_utf16(memory: &TestMemory, address: u64, text: &str) {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        assert_eq!(memory.store(address, &bytes), true);
    }

    fn load_utf16(memory: &TestMemory, address: u64, max_units: usize) -> String {
        let mut units = Vec::new();
        for index in 0..max_units {
            let unit = memory.load(address + index as u64 * 2, 2).unwrap_or(0) as u16;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        String::from_utf16_lossy(&units)
    }

    const C_STR: u64 = 0x1000;
    const W_ABC: u64 = 0x1010;
    const W_ABC_UPPER: u64 = 0x1020;
    const W_DATE_FMT: u64 = 0x1040;
    const W_TIME_FMT: u64 = 0x1060;
    const SYSTEMTIME_DATE: u64 = 0x1100;
    const SYSTEMTIME_TIME: u64 = 0x1120;
    const ENV_NAME: u64 = 0x1140;
    const ENV_BUFFER: u64 = 0x1180;
    const MULTI_IN: u64 = 0x1200;
    const WIDE_IN: u64 = 0x1210;
    const MULTI_OUT: u64 = 0x1220;
    const WIDE_OUT: u64 = 0x1240;
    const REG_NAME: u64 = 0x1260;
    const REG_BUF: u64 = 0x1280;
    const REG_LEN: u64 = 0x12c0;
    const REG_TYPE: u64 = 0x12c4;
    const CP_INFO: u64 = 0x12d0;
    const HEAPS_OUT: u64 = 0x12e0;
    const TZ_OUT: u64 = 0x1300;
    const DATE_OUT: u64 = 0x1320;
    const TIME_OUT: u64 = 0x1340;
    const ANSI_NAME: u64 = 0x1360;

    fn prepare_hammer_memory(memory: &TestMemory) {
        store_ascii(memory, C_STR, "abc");
        store_utf16(memory, W_ABC, "abc");
        store_utf16(memory, W_ABC_UPPER, "ABC");
        store_utf16(memory, W_DATE_FMT, "yyyy-MM-dd");
        store_utf16(memory, W_TIME_FMT, "HH:mm:ss");
        assert_eq!(memory.store(SYSTEMTIME_DATE, &2024_u16.to_le_bytes()), true);
        assert_eq!(
            memory.store(SYSTEMTIME_DATE + 2, &3_u16.to_le_bytes()),
            true
        );
        assert_eq!(
            memory.store(SYSTEMTIME_DATE + 6, &5_u16.to_le_bytes()),
            true
        );
        assert_eq!(
            memory.store(SYSTEMTIME_TIME + 8, &14_u16.to_le_bytes()),
            true
        );
        assert_eq!(
            memory.store(SYSTEMTIME_TIME + 10, &5_u16.to_le_bytes()),
            true
        );
        assert_eq!(
            memory.store(SYSTEMTIME_TIME + 12, &9_u16.to_le_bytes()),
            true
        );
        store_utf16(memory, ENV_NAME, "CASA_TEST");
        assert_eq!(memory.store(MULTI_IN, &[b'A', 0]), true);
        store_utf16(memory, WIDE_IN, "A");
        store_utf16(memory, REG_NAME, "Demo");
        store_ascii(memory, ANSI_NAME, "Ansi");
    }

    fn hammer_x64_iteration(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thread: u32,
    ) {
        let expected_version = (22631_u64 << 16) | (10_u64 << 8) | 0x8000_0000;
        assert_eq!(
            invoke(shared, context, memory, HostThunk::GetCurrentThreadId),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::from(0x100 + thread));
        assert_eq!(
            invoke(shared, context, memory, HostThunk::GetCurrentProcessId),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1234);
        assert_eq!(invoke(shared, context, memory, HostThunk::GetVersion), true);
        assert_eq!(context.state.get(Register::Rax), expected_version);

        context.state.set(Register::Rcx, C_STR);
        assert_eq!(invoke(shared, context, memory, HostThunk::Strlen), true);
        assert_eq!(context.state.get(Register::Rax), 3);

        context.state.set(Register::Rcx, W_ABC);
        assert_eq!(invoke(shared, context, memory, HostThunk::LstrlenW), true);
        assert_eq!(context.state.get(Register::Rax), 3);

        context.state.set(Register::Rcx, W_ABC);
        context.state.set(Register::Rdx, W_ABC);
        assert_eq!(invoke(shared, context, memory, HostThunk::LstrcmpW), true);
        assert_eq!(context.state.get(Register::Rax), 0);
        context.state.set(Register::Rdx, W_ABC_UPPER);
        assert_eq!(invoke(shared, context, memory, HostThunk::LstrcmpW), true);
        assert_eq!(context.state.get(Register::Rax), 1);
        context.state.set(Register::Rdx, W_ABC_UPPER);
        assert_eq!(invoke(shared, context, memory, HostThunk::LstrcmpiW), true);
        assert_eq!(context.state.get(Register::Rax), 0);

        assert_eq!(invoke(shared, context, memory, HostThunk::GetACP), true);
        assert_eq!(context.state.get(Register::Rax), 1252);
        assert_eq!(invoke(shared, context, memory, HostThunk::GetOEMCP), true);
        assert_eq!(context.state.get(Register::Rax), 437);

        context.state.set(Register::Rcx, 1252);
        context.state.set(Register::Rdx, CP_INFO);
        assert_eq!(invoke(shared, context, memory, HostThunk::GetCPInfo), true);
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(CP_INFO, 4), Some(1));

        context.state.set(Register::Rcx, 65001);
        assert_eq!(
            invoke(shared, context, memory, HostThunk::IsValidCodePage),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(context.last_error, 0);
        context.state.set(Register::Rcx, 12_345);
        assert_eq!(
            invoke(shared, context, memory, HostThunk::IsValidCodePage),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        context.state.set(Register::Rcx, 0);
        assert_eq!(
            invoke(shared, context, memory, HostThunk::LocaleNameToLCID),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x0409);

        assert_eq!(
            invoke(shared, context, memory, HostThunk::GetProcessHeap),
            true
        );
        assert_eq!(context.state.get(Register::Rax), PROCESS_HEAP_HANDLE);
        context.state.set(Register::Rcx, 1);
        context.state.set(Register::Rdx, HEAPS_OUT);
        assert_eq!(
            invoke(shared, context, memory, HostThunk::GetProcessHeaps),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(HEAPS_OUT, 8), Some(PROCESS_HEAP_HANDLE));

        context.state.set(Register::Rcx, PROCESS_HEAP_HANDLE);
        context.state.set(Register::Rdx, 0);
        context.state.set(Register::R8, 0x5000);
        assert_eq!(invoke(shared, context, memory, HostThunk::HeapSize), true);
        assert_eq!(context.state.get(Register::Rax), 77);
        assert_eq!(context.last_error, 0);
        context.state.set(Register::R8, 0x5001);
        assert_eq!(invoke(shared, context, memory, HostThunk::HeapSize), true);
        assert_eq!(context.state.get(Register::Rax), u64::MAX);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        context.state.set(Register::Rcx, TZ_OUT);
        assert_eq!(
            invoke(shared, context, memory, HostThunk::GetTimeZoneInformation),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.load(TZ_OUT, 4), Some(0));
        assert_eq!(memory.load(TZ_OUT + 4, 6), Some(0x00_43_00_54_00_55));

        context.state.set(Register::Rcx, ENV_NAME);
        context.state.set(Register::Rdx, ENV_BUFFER);
        context.state.set(Register::R8, 16);
        assert_eq!(
            invoke(shared, context, memory, HostThunk::GetEnvironmentVariableW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 5);
        assert_eq!(memory.load(ENV_BUFFER, 5), Some(0x6c_0061_0076));
    }

    fn hammer_x86_iteration(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
    ) {
        assert_eq!(
            invoke_x86(
                shared,
                context,
                memory,
                HostThunk::MultiByteToWideChar,
                &[65001, 0, MULTI_IN, 1, WIDE_OUT, 4],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(WIDE_OUT, 2), Some(0x41));

        assert_eq!(
            invoke_x86(
                shared,
                context,
                memory,
                HostThunk::WideCharToMultiByte,
                &[65001, 0, WIDE_IN, 1, MULTI_OUT, 4, 0, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(MULTI_OUT, 1), Some(0x41));

        assert_eq!(
            invoke_x86(
                shared,
                context,
                memory,
                HostThunk::CompareStringW,
                &[0x0409, 1, W_ABC, 3, W_ABC_UPPER, 3],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 2);

        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                shared,
                context,
                memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.load(REG_LEN, 4), Some(12));
        assert_eq!(memory.load(REG_TYPE, 4), Some(1));
        assert_eq!(memory.load(REG_BUF, 2), Some(0x68));

        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                shared,
                context,
                memory,
                HostThunk::RegQueryValueExA,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    ANSI_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.load(REG_LEN, 4), Some(3));
        assert_eq!(memory.load(REG_BUF, 3), Some(0x0000_6968));

        assert_eq!(
            invoke_x86(
                shared,
                context,
                memory,
                HostThunk::GetDateFormatW,
                &[0, 0, SYSTEMTIME_DATE, W_DATE_FMT, DATE_OUT, 16],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 10);
        assert_eq!(memory.load(DATE_OUT, 2), Some(0x32));

        assert_eq!(
            invoke_x86(
                shared,
                context,
                memory,
                HostThunk::GetTimeFormatW,
                &[0, 0, SYSTEMTIME_TIME, W_TIME_FMT, TIME_OUT, 16],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 8);
        assert_eq!(memory.load(TIME_OUT, 2), Some(0x31));
    }

    #[test]
    fn parallel_api_stateless_hammer_has_exact_per_thread_results() {
        let shared = Arc::new(ProcessShared::new());
        let mut environment = environment(0x1234);
        environment.clock.dtm = true;
        environment.clock.deterministic_tick_ms = 0;
        shared.publish_environment(environment);
        const THREADS: u32 = 8;
        const X64_CALLS: u32 = 100;
        const X86_CALLS: u32 = 50;
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let x64_shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x64_context(0x100 + thread);
                let memory = TestMemory::new();
                prepare_hammer_memory(&memory);
                for _ in 0..X64_CALLS {
                    hammer_x64_iteration(&x64_shared, &mut context, &memory, thread);
                }
            }));
            let x86_shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x86_context(0x180 + thread);
                let memory = TestMemory::new();
                prepare_hammer_memory(&memory);
                for _ in 0..X86_CALLS {
                    hammer_x86_iteration(&x86_shared, &mut context, &memory);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("stateless hammer worker");
        }
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(
            metrics.parallel_dispatched,
            u64::from(THREADS * (X64_CALLS * 20 + X86_CALLS * 7))
        );
        assert_eq!(
            metrics.stateless_dispatched,
            u64::from(THREADS * (X64_CALLS * 14 + X86_CALLS * 3))
        );
        assert_eq!(
            metrics.read_mostly_dispatched,
            u64::from(THREADS * (X64_CALLS * 6 + X86_CALLS * 4))
        );
        assert_eq!(metrics.barrier_calls, 0);
        assert_eq!(metrics.owner_only_barriers, 0);
        assert_eq!(metrics.fallback_barriers, 0);
    }

    #[test]
    fn parallel_api_last_error_isolation_under_concurrency() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x1234));
        const THREADS: u32 = 8;
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let expected = 0x5000 + thread;
                let mut context = x64_context(0x200 + thread);
                let memory = TestMemory::new();
                context.state.set(Register::Rcx, u64::from(expected));
                assert_eq!(
                    invoke(&shared, &mut context, &memory, HostThunk::SetLastError),
                    true
                );
                shared.with_process(|| std::thread::yield_now());
                assert_eq!(
                    invoke(&shared, &mut context, &memory, HostThunk::GetLastError),
                    true
                );
                assert_eq!(context.state.get(Register::Rax), u64::from(expected));
                assert_eq!(context.last_error, expected);
            }));
        }
        for worker in workers {
            worker.join().expect("last-error worker");
        }
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, u64::from(THREADS * 2));
        assert_eq!(metrics.barrier_calls, 0);
    }

    #[test]
    fn parallel_api_read_mostly_readers_race_writer_consistency() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(100));
        let stop = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicU64::new(0));
        let mut readers = Vec::new();
        for thread in 0..4 {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            let reads = Arc::clone(&reads);
            readers.push(std::thread::spawn(move || {
                let mut context = x86_context(0x300 + thread);
                let memory = TestMemory::new();
                prepare_hammer_memory(&memory);
                while !stop.load(Ordering::Acquire) {
                    // A writer holding the per-subsystem lock makes the worker
                    // fall back to the owner barrier by design; only inspect
                    // the value when the worker actually serviced the read.
                    if !invoke(
                        &shared,
                        &mut context,
                        &memory,
                        HostThunk::GetCurrentProcessId,
                    ) {
                        continue;
                    }
                    let pid = context.state.get(Register::Rax);
                    assert_eq!(pid == 100 || pid == 101, true);

                    if !invoke_x86(
                        &shared,
                        &mut context,
                        &memory,
                        HostThunk::GetEnvironmentVariableW,
                        &[ENV_NAME, ENV_BUFFER, 16],
                    ) {
                        continue;
                    }
                    assert_eq!(context.state.get(Register::Rax), 5);
                    let first = memory.load(ENV_BUFFER, 2);
                    assert_eq!(first == Some(0x76) || first == Some(0x6f), true);

                    assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
                    if !invoke_x86(
                        &shared,
                        &mut context,
                        &memory,
                        HostThunk::RegQueryValueExW,
                        &[
                            u64::from(HKEY_CURRENT_USER),
                            REG_NAME,
                            0,
                            REG_TYPE,
                            REG_BUF,
                            REG_LEN,
                        ],
                    ) {
                        continue;
                    }
                    assert_eq!(context.state.get(Register::Rax), 0);
                    assert_eq!(memory.load(REG_LEN, 4), Some(12));
                    let first = memory.load(REG_BUF, 2);
                    assert_eq!(first == Some(0x68) || first == Some(0x6f), true);
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for iteration in 0..2_000 {
            let mut environment = environment(100);
            let value = if iteration % 2 == 0 { "other" } else { "value" };
            environment.identity = WorkerIdentity {
                process_id: if iteration % 2 == 0 { 101 } else { 100 },
                process_handle: 0x44,
            };
            environment
                .environment
                .insert("CASA_TEST".to_string(), value.to_string());
            environment.registry =
                registry_with_value(if value == "value" { "hello" } else { "other" });
            shared.publish_environment(environment);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while reads.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Release);
        for reader in readers {
            reader.join().expect("read-mostly reader");
        }
        assert_eq!(reads.load(Ordering::Relaxed) > 0, true);
    }

    #[test]
    fn parallel_api_owner_only_thunk_stays_on_barrier() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(7));
        let mut context = x64_context(0x400);
        let memory = TestMemory::new();
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CreateFileW),
            false
        );
        assert_eq!(context.state.get(Register::Rsp), STACK);
        assert_eq!(context.state.rip, thunk_address(&context));
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, 0);
        assert_eq!(metrics.barrier_calls, 1);
        assert_eq!(metrics.owner_only_barriers, 1);
        assert_eq!(metrics.fallback_barriers, 0);
    }

    #[test]
    fn parallel_api_mixed_parallel_and_barrier_calls_no_deadlock() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(9));
        const THREADS: u32 = 6;
        const ROUNDS: u32 = 200;
        let started = std::time::Instant::now();
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x64_context(0x500 + thread);
                let memory = TestMemory::new();
                for _ in 0..ROUNDS {
                    assert_eq!(
                        invoke(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::GetCurrentThreadId
                        ),
                        true
                    );
                    shared.with_process(|| std::thread::yield_now());
                    assert_eq!(
                        invoke(&shared, &mut context, &memory, HostThunk::CreateFileW),
                        false
                    );
                }
            }));
        }
        for worker in workers {
            worker.join().expect("mixed worker");
        }
        assert_eq!(started.elapsed() < std::time::Duration::from_secs(5), true);
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, u64::from(THREADS * ROUNDS));
        assert_eq!(metrics.barrier_calls, u64::from(THREADS * ROUNDS));
        assert_eq!(shared.process_operations(), u64::from(THREADS * ROUNDS));
    }

    #[test]
    fn parallel_api_classification_and_names_are_canonical() {
        assert_eq!(
            thunk_class(&HostThunk::GetTickCount64),
            ThunkConcurrency::Stateless
        );
        assert_eq!(
            thunk_class(&HostThunk::GetVersion),
            ThunkConcurrency::ReadMostly
        );
        assert_eq!(
            thunk_class(&HostThunk::CreateFileW),
            ThunkConcurrency::OwnerOnly
        );
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("GetLastError"),
            ThunkConcurrency::Stateless
        );
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("GetSystemInfo"),
            ThunkConcurrency::ReadMostly
        );
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("CreateFileW"),
            ThunkConcurrency::OwnerOnly
        );
        for thunk in [
            HostThunk::Strlen,
            HostThunk::LstrlenW,
            HostThunk::LstrcmpW,
            HostThunk::LstrcmpiW,
            HostThunk::CompareStringW,
            HostThunk::GetCPInfo,
            HostThunk::IsValidCodePage,
            HostThunk::LocaleNameToLCID,
            HostThunk::GetProcessHeap,
            HostThunk::GetProcessHeaps,
            HostThunk::GetTimeZoneInformation,
            HostThunk::GetDateFormatW,
            HostThunk::GetTimeFormatW,
        ] {
            assert_eq!(thunk_class(&thunk), ThunkConcurrency::Stateless);
        }
        for thunk in [
            HostThunk::MultiByteToWideChar,
            HostThunk::WideCharToMultiByte,
            HostThunk::GetACP,
            HostThunk::GetOEMCP,
            HostThunk::HeapSize,
            HostThunk::GetEnvironmentVariableW,
            HostThunk::RegQueryValueExA,
            HostThunk::RegQueryValueExW,
        ] {
            assert_eq!(thunk_class(&thunk), ThunkConcurrency::ReadMostly);
        }
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("lstrlenA"),
            ThunkConcurrency::Stateless
        );
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("MultiByteToWideChar"),
            ThunkConcurrency::ReadMostly
        );
        assert_eq!(
            crate::host_thunks::classify_thunk_concurrency("RegQueryValueExW"),
            ThunkConcurrency::ReadMostly
        );

        assert_eq!(worker_registry_view(0, GuestArch::X64), 0);
        assert_eq!(worker_registry_view(KEY_WOW64_32KEY, GuestArch::X64), 1);
        assert_eq!(worker_registry_view(KEY_WOW64_64KEY, GuestArch::X86), 2);
        assert_eq!(root_registry_key(HKEY_CLASSES_ROOT), Some(("HKCR", "")));
        assert_eq!(root_registry_key(HKEY_CURRENT_USER), Some(("HKCU", "")));
        assert_eq!(root_registry_key(HKEY_LOCAL_MACHINE), Some(("HKLM", "")));
        assert_eq!(root_registry_key(HKEY_USERS), Some(("HKCU", "")));
        assert_eq!(
            root_registry_key(HKEY_CURRENT_CONFIG),
            Some((
                "HKLM",
                "System\\CurrentControlSet\\Hardware Profiles\\Current"
            ))
        );
        assert_eq!(root_registry_key(0x1234), None);
        for byte in 0..=u8::MAX {
            assert_eq!(encode_cp1252(decode_cp1252(byte)), Some(byte));
        }
        assert_eq!(encode_cp1252('\u{0100}'), None);
    }

    #[test]
    fn parallel_api_invalid_arguments_boundary_outcomes_are_exact() {
        let shared = ProcessShared::new();
        let mut context = x64_context(0x600);
        let memory = TestMemory::new();
        shared.publish_environment(environment(11));

        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::QueryPerformanceCounter
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::QueryPerformanceFrequency
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::IsWow64Process),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::GlobalMemoryStatusEx
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExA),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn parallel_api_missing_state_and_memory_fall_back_to_barrier() {
        let shared = ProcessShared::new();
        let mut context = x64_context(0x700);
        let memory = TestMemory::new();
        // No environment published: version has no snapshot.
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersion),
            false
        );
        assert_eq!(context.state.rip, thunk_address(&context));
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, 0);
        assert_eq!(metrics.barrier_calls, 1);
        assert_eq!(metrics.fallback_barriers, 1);
        assert_eq!(metrics.owner_only_barriers, 0);

        // VersionEx* also refuse to guess without a published version.
        let mut context_w = x64_context(0x702);
        let memory_w = TestMemory::new();
        assert_eq!(
            invoke(&shared, &mut context_w, &memory_w, HostThunk::GetVersionExW),
            false
        );
        assert_eq!(
            invoke(&shared, &mut context_w, &memory_w, HostThunk::GetVersionExA),
            false
        );

        // A published version but unmapped output pointer.
        shared.publish_environment(environment(3));
        context.state.set(Register::Rcx, 0x1_0000);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExW),
            false
        );

        // No stack at all.
        context.state.set(Register::Rsp, 0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetTickCount64),
            false
        );

        // Globals without a memory-status snapshot.
        let shared = ProcessShared::new();
        let mut context = x64_context(0x701);
        let memory = TestMemory::new();
        shared.publish_thunk(THUNK, &HostThunk::GlobalMemoryStatusEx);
        context.state.rip = THUNK;
        assert_eq!(memory.store(STACK, &RETURN_ADDRESS.to_le_bytes()), true);
        context.state.set(Register::Rsp, STACK);
        context.state.set(Register::Rcx, 0x300);
        let entry = shared.parallel_thunk(THUNK).expect("published thunk");
        assert_eq!(
            super::invoke_parallel_api(&shared, &mut context, &memory, &entry),
            false
        );

        // x64 stack arguments (index >= 4) are not used by the safe subset
        // but the reader must fail closed rather than fabricate a value.
        context.state.set(Register::Rsp, STACK);
        assert_eq!(super::read_arg(&context, &memory, 4), Some(0));
        context.state.set(Register::Rsp, 0x1_0000);
        assert_eq!(super::read_arg(&context, &memory, 4), None);

        // String-conversion boundaries.  Invalid UTF-8/UTF-16 and an
        // unencodable CP1252 character map to ERROR_INVALID_PARAMETER; a
        // too-small destination maps to ERROR_INSUFFICIENT_BUFFER.
        let shared = ProcessShared::new();
        shared.publish_environment(environment(12));
        let memory = TestMemory::new();
        prepare_hammer_memory(&memory);
        let mut context = x86_context(0x640);

        assert_eq!(memory.store(MULTI_IN, &[0xff]), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[65001, 0, MULTI_IN, 1, WIDE_OUT, 4],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(memory.store(WIDE_IN, &0xD800_u16.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[65001, 0, WIDE_IN, 1, MULTI_OUT, 4, 0, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        assert_eq!(memory.store(MULTI_IN, b"AB"), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[65001, 0, MULTI_IN, 2, WIDE_OUT, 1],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INSUFFICIENT_BUFFER);

        assert_eq!(memory.store(WIDE_IN, &[0x41, 0, 0x42, 0]), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[65001, 0, WIDE_IN, 2, MULTI_OUT, 1, 0, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INSUFFICIENT_BUFFER);

        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[65001, 0, 0, 1, WIDE_OUT, 4],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // CP1252 cannot encode U+0100 (the owner reports RcCliInvalid).
        assert_eq!(memory.store(WIDE_IN, &0x0100_u16.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[1252, 0, WIDE_IN, 1, MULTI_OUT, 4, 0, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // Input/format pointers outside the view fall back to the barrier.
        for (thunk, args) in [
            (HostThunk::Strlen, vec![0x5000]),
            (HostThunk::LstrlenW, vec![0x5000]),
            (HostThunk::LstrcmpW, vec![0x5000, 0x5000]),
            (HostThunk::LstrcmpW, vec![W_ABC, 0x5000]),
            (HostThunk::LstrcmpiW, vec![0x5000, W_ABC]),
            (HostThunk::LocaleNameToLCID, vec![0x5000, 0]),
            (
                HostThunk::GetEnvironmentVariableW,
                vec![0x5000, ENV_BUFFER, 16],
            ),
            (
                HostThunk::MultiByteToWideChar,
                vec![65001, 0, 0x5000, 0xFFFF_FFFF, WIDE_OUT, 4],
            ),
            (
                HostThunk::WideCharToMultiByte,
                vec![65001, 0, 0x5000, 0xFFFF_FFFF, MULTI_OUT, 4, 0, 0],
            ),
            (
                HostThunk::WideCharToMultiByte,
                vec![65001, 0, WIDE_IN, 0x7FFF_FFFF, MULTI_OUT, 4, 0, 0],
            ),
            (
                HostThunk::GetDateFormatW,
                vec![0, 0, SYSTEMTIME_DATE, 0x5000, DATE_OUT, 16],
            ),
            (
                HostThunk::GetTimeFormatW,
                vec![0, 0, SYSTEMTIME_TIME, 0x5000, TIME_OUT, 16],
            ),
            (
                HostThunk::RegQueryValueExA,
                vec![
                    u64::from(HKEY_CURRENT_USER),
                    0x5000,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN,
                ],
            ),
            (
                HostThunk::RegQueryValueExW,
                vec![
                    u64::from(HKEY_CURRENT_USER),
                    0x5000,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    0x5000,
                ],
            ),
        ] {
            let mut context = x86_context(0x680);
            assert_eq!(
                invoke_x86(&shared, &mut context, &memory, thunk, &args),
                false,
                "an unreadable input must fall back to the barrier"
            );
        }

        // The default value name (NULL) is looked up as the empty name; an
        // unreadable data-length pointer fails closed.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(ERROR_FILE_NOT_FOUND)
        );
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    0x5000
                ],
            ),
            false
        );

        // A code page the worker cannot reproduce exactly stays on the owner
        // barrier rather than guessing.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[932, 0, MULTI_IN, 1, WIDE_OUT, 4],
            ),
            false
        );
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[932, 0, WIDE_IN, 1, MULTI_OUT, 4, 0, 0],
            ),
            false
        );

        // CP_ACP and CP_THREAD_ACP both resolve through the published locale.
        assert_eq!(memory.store(MULTI_IN, &[b'A', 0]), true);
        store_utf16(&memory, WIDE_IN, "A");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[0, 0, MULTI_IN, 1, WIDE_OUT, 4],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[3, 0, MULTI_IN, 1, WIDE_OUT, 4],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[0, 0, WIDE_IN, 1, MULTI_OUT, 4, 0, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[3, 0, WIDE_IN, 1, MULTI_OUT, 4, 0, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);

        // A NULL source with a non-zero length is the documented Invalid
        // Parameter case for the wide conversion.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[65001, 0, 0, 1, MULTI_OUT, 4, 0, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // GetCPInfo rejects an unknown code page while IsValidCodePage simply
        // reports false.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetCPInfo,
                &[12_345, CP_INFO],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // A valid locale name resolves even though the runtime models en-US.
        store_utf16(&memory, ANSI_NAME, "en-US");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::LocaleNameToLCID,
                &[ANSI_NAME, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x0409);
        assert_eq!(context.last_error, 0);

        // Environment argument validation.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetEnvironmentVariableW,
                &[ENV_NAME, ENV_BUFFER, 0],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 6);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetEnvironmentVariableW,
                &[ENV_NAME, 0, 1],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);
        // An overflowing input length is an unreadable window, not a guess.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[65001, 0, MULTI_IN, i32::MAX as u64, WIDE_OUT, 4],
            ),
            false
        );

        // CompareStringW honours the requested prefix length exactly.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::CompareStringW,
                &[0x0409, 0, W_ABC, 2, W_ABC, 3],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);

        // Registry boundary errors: reserved argument, missing value and a
        // buffer that cannot hold the encoded value.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    1,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(ERROR_INVALID_PARAMETER)
        );
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        store_utf16(&memory, REG_NAME, "Missing");
        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(ERROR_FILE_NOT_FOUND)
        );
        assert_eq!(context.last_error, ERROR_FILE_NOT_FOUND);
        assert_eq!(memory.load(REG_LEN, 4), Some(0));
        assert_eq!(memory.load(REG_TYPE, 4), Some(0));

        store_utf16(&memory, REG_NAME, "Demo");
        assert_eq!(memory.store(REG_LEN, &4_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::from(ERROR_MORE_DATA));
        assert_eq!(context.last_error, ERROR_MORE_DATA);
        assert_eq!(memory.load(REG_LEN, 4), Some(12));

        // Date formatting's too-small buffer is ERROR_INSUFFICIENT_BUFFER.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 0, SYSTEMTIME_DATE, W_DATE_FMT, DATE_OUT, 4],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INSUFFICIENT_BUFFER);

        // A value whose type the owner cannot encode falls back to the
        // barrier; a malformed value of a known type does too, while an empty
        // REG_BINARY succeeds with a zero-length write.
        let mut environment = environment(13);
        let mut registry = registry_with_value("hello");
        for key in registry
            .roots
            .values_mut()
            .chain(registry.keys.values_mut())
        {
            key.values.insert(
                "BadType".to_string(),
                StoredRegistryValue {
                    value_type: "REG_UNKNOWN".to_string(),
                    data: json!("x"),
                },
            );
            key.values.insert(
                "BadData".to_string(),
                StoredRegistryValue {
                    value_type: "REG_DWORD".to_string(),
                    data: json!("not-a-number"),
                },
            );
            key.values.insert(
                "EmptyBin".to_string(),
                StoredRegistryValue {
                    value_type: "REG_BINARY".to_string(),
                    data: json!([]),
                },
            );
        }
        environment.registry = registry;
        shared.publish_environment(environment);

        store_utf16(&memory, REG_NAME, "BadType");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            false
        );
        store_utf16(&memory, REG_NAME, "BadData");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            false
        );
        store_utf16(&memory, REG_NAME, "EmptyBin");
        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ],
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.load(REG_LEN, 4), Some(0));
        assert_eq!(memory.load(REG_TYPE, 4), Some(3));
    }

    #[test]
    fn parallel_api_worker_success_paths_have_exact_results() {
        let shared = ProcessShared::new();
        let mut environment = environment(0x2222);
        environment.clock.dtm = true;
        shared.publish_environment(environment);
        let memory = TestMemory::new();

        let mut context = x64_context(0x800);
        context.state.set(Register::Rax, 0xDEAD);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetCurrentProcess),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x44);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetCurrentThread),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x800);

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetTickCount),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax) <= u64::from(u32::MAX),
            true
        );

        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetTickCount64),
            true
        );
        assert_eq!(context.last_error, 0);

        // QueryPerformanceCounter/Frequency and the two FILETIME APIs.
        for thunk in [
            HostThunk::QueryPerformanceCounter,
            HostThunk::QueryPerformanceFrequency,
        ] {
            context.state.set(Register::Rcx, 0x1000);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk), true);
            assert_eq!(context.state.get(Register::Rax), 1);
            assert_eq!(context.last_error, 0);
        }
        for thunk in [
            HostThunk::GetSystemTimeAsFileTime,
            HostThunk::GetSystemTimePreciseAsFileTime,
        ] {
            context.state.set(Register::Rcx, 0x1000);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk), true);
            assert_eq!(context.state.get(Register::Rax), 0);
        }

        // Null output pointers are valid for the FILETIME APIs.
        for thunk in [
            HostThunk::GetSystemTimeAsFileTime,
            HostThunk::GetSystemTimePreciseAsFileTime,
        ] {
            context.state.set(Register::Rcx, 0);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk), true);
            assert_eq!(context.state.get(Register::Rax), 0);
        }

        context.state.set(Register::Rcx, 0x1200);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(0x1204, 4), Some(10));

        context.state.set(Register::Rcx, 0x1300);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExA),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(0x1304, 4), Some(10));

        // Extended variant writes the service-pack tail.
        assert_eq!(memory.store(0x1200, &0x11C_u32.to_le_bytes()), true);
        assert_eq!(memory.store(0x1300, &0x9C_u32.to_le_bytes()), true);
        context.state.set(Register::Rcx, 0x1200);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExW),
            true
        );
        assert_eq!(memory.load(0x1214, 2), Some(0));
        context.state.set(Register::Rcx, 0x1300);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersionExA),
            true
        );

        context.state.set(Register::Rcx, 0x1400);
        context.state.set(Register::Rdx, 0x1500);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::IsWow64Process),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(0x1500, 4), Some(0));

        for thunk in [HostThunk::GetSystemInfo, HostThunk::GetNativeSystemInfo] {
            context.state.set(Register::Rcx, 0x1600);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk.clone()), true);
            assert_eq!(context.state.get(Register::Rax), 0);
            assert_eq!(memory.load(0x1600, 2), Some(9));
            // Null pointer is accepted.
            context.state.set(Register::Rcx, 0);
            assert_eq!(invoke(&shared, &mut context, &memory, thunk.clone()), true);
            assert_eq!(context.state.get(Register::Rax), 0);
        }

        context.state.set(Register::Rcx, 0x1700);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::GlobalMemoryStatusEx
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(0x1700, 4), Some(64));

        context.state.set(Register::Rcx, 2);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::IsProcessorFeaturePresent
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        context.state.set(Register::Rcx, 0);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::IsProcessorFeaturePresent
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);

        // CharNextW: null pointer, NUL unit and a real code unit.
        context.state.set(Register::Rcx, 0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharNextW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.store(0x1800, &0_u16.to_le_bytes()), true);
        context.state.set(Register::Rcx, 0x1800);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharNextW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1800);
        assert_eq!(memory.store(0x1800, &0x41_u16.to_le_bytes()), true);
        context.state.set(Register::Rcx, 0x1800);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharNextW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1802);

        context.state.set(Register::Rcx, 0x1800);
        context.state.set(Register::Rdx, 0x1800);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharPrevW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1800);
        context.state.set(Register::Rdx, 0x1802);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CharPrevW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x1800);

        // StrFromTimeIntervalW: success, truncation, null buffer and an
        // invalid digit count.
        context.state.set(Register::Rcx, 0x1900);
        context.state.set(Register::Rdx, 8);
        context.state.set(Register::R8, 3_723_000);
        context.state.set(Register::R9, 4);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::StrFromTimeIntervalW
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax) > 0, true);
        context.state.set(Register::Rcx, 0);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::StrFromTimeIntervalW
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        context.state.set(Register::Rcx, 0x1900);
        context.state.set(Register::R9, 0);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::StrFromTimeIntervalW
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);

        // The string helpers accept NULL as the empty string.
        prepare_hammer_memory(&memory);
        context.state.set(Register::Rcx, 0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::Strlen),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::LstrlenW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);

        let mut x86 = x86_context(0xE00);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::CompareStringW,
                &[0x0409, 0, W_ABC, 0xFFFF_FFFF, W_ABC, 3],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 2);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::CompareStringW,
                &[0x0409, 0, W_ABC, 3, W_ABC_UPPER, 3],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 3);

        // Negative lengths use the NUL terminator (including it for the
        // wide-to-multi conversion), and NULL destinations query the size.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[65001, 0, MULTI_IN, 0xFFFF_FFFF, WIDE_OUT, 4],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 2);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::MultiByteToWideChar,
                &[65001, 0, MULTI_IN, 1, 0, 4],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[65001, 0, WIDE_IN, 0xFFFF_FFFF, MULTI_OUT, 4, 0, 0],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 2);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::WideCharToMultiByte,
                &[65001, 0, WIDE_IN, 1, 0, 4, 0, 0],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 1);

        // GetCPInfo accepts a NULL output pointer.
        assert_eq!(
            invoke_x86(&shared, &mut x86, &memory, HostThunk::GetCPInfo, &[1252, 0]),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 1);

        // LocaleNameToLCID rejects an unknown locale name.
        store_utf16(&memory, ANSI_NAME, "zz-ZZ");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::LocaleNameToLCID,
                &[ANSI_NAME, 0],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 0);
        assert_eq!(x86.last_error, ERROR_INVALID_PARAMETER);

        // GetProcessHeaps writes nothing when the buffer is omitted.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetProcessHeaps,
                &[0, HEAPS_OUT],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetProcessHeaps,
                &[1, HEAPS_OUT],
            ),
            true
        );
        assert_eq!(memory.load(HEAPS_OUT, 4), Some(PROCESS_HEAP_HANDLE));

        // HeapSize on a non-process heap is the arch-specific sentinel.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::HeapSize,
                &[0x2000, 0, 0x5000],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), u32::MAX as u64);
        assert_eq!(x86.last_error, ERROR_INVALID_PARAMETER);

        // A NULL TIME_ZONE_INFORMATION pointer still reports the zone id.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetTimeZoneInformation,
                &[0],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 0);

        // Default date/time pictures (no format string).
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 0, SYSTEMTIME_DATE, 0, DATE_OUT, 32],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 8);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 2, SYSTEMTIME_DATE, 0, DATE_OUT, 32],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 22);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetTimeFormatW,
                &[0, 0, SYSTEMTIME_TIME, 0, TIME_OUT, 32],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 10);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetTimeFormatW,
                &[0, 8, SYSTEMTIME_TIME, 0, TIME_OUT, 32],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 8);

        // Every date token width, quoted literals, escaped quotes and an
        // unterminated literal.
        store_utf16(&memory, ANSI_NAME, "d dd ddd dddd M MM MMM MMMM y yy yyyy");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 0, SYSTEMTIME_DATE, ANSI_NAME, DATE_OUT, 64],
            ),
            true
        );
        assert_eq!(
            load_utf16(&memory, DATE_OUT, 64),
            "5 05 Tue Tuesday 3 03 Mar March 24 24 2024"
        );
        store_utf16(&memory, ANSI_NAME, "'Lit''eral'");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 0, SYSTEMTIME_DATE, ANSI_NAME, DATE_OUT, 64],
            ),
            true
        );
        assert_eq!(load_utf16(&memory, DATE_OUT, 64), "Lit'eral");
        store_utf16(&memory, ANSI_NAME, "'oops");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 0, SYSTEMTIME_DATE, ANSI_NAME, DATE_OUT, 64],
            ),
            true
        );
        assert_eq!(load_utf16(&memory, DATE_OUT, 64), "oops");

        // Every time token width, a quoted literal, and the force-24 form.
        store_utf16(&memory, ANSI_NAME, "h hh H HH m mm s ss t tt");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetTimeFormatW,
                &[0, 0, SYSTEMTIME_TIME, ANSI_NAME, TIME_OUT, 64],
            ),
            true
        );
        assert_eq!(
            load_utf16(&memory, TIME_OUT, 64),
            "2 02 14 14 5 05 9 09 P PM"
        );
        store_utf16(&memory, ANSI_NAME, "'T'");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetTimeFormatW,
                &[0, 0, SYSTEMTIME_TIME, ANSI_NAME, TIME_OUT, 64],
            ),
            true
        );
        assert_eq!(load_utf16(&memory, TIME_OUT, 64), "T");
        store_utf16(&memory, ANSI_NAME, "t");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetTimeFormatW,
                &[0, 8, SYSTEMTIME_TIME, ANSI_NAME, TIME_OUT, 64],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 0);
        assert_eq!(load_utf16(&memory, TIME_OUT, 64), "");

        // Buffer-size queries preserve the guest last-error value.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 0, SYSTEMTIME_DATE, W_DATE_FMT, 0, 64],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 11);

        // Direct helper coverage for escaped and unterminated quoted
        // literals in both formatters, plus the "today"/"now" paths.
        let helper = TestMemory::new();
        store_utf16(&helper, ANSI_NAME, "'a''b'");
        assert_eq!(
            format_date_tokens_worker(&helper, ANSI_NAME, 2024, 3, 5, 2).unwrap(),
            "a'b"
        );
        store_utf16(&helper, ANSI_NAME, "'oops");
        assert_eq!(
            format_date_tokens_worker(&helper, ANSI_NAME, 2024, 3, 5, 2).unwrap(),
            "oops"
        );
        store_utf16(&helper, ANSI_NAME, "'a''b'");
        assert_eq!(
            format_time_tokens_worker(&helper, ANSI_NAME, 14, 5, 9, false).unwrap(),
            "a'b"
        );
        store_utf16(&helper, ANSI_NAME, "'oops");
        assert_eq!(
            format_time_tokens_worker(&helper, ANSI_NAME, 14, 5, 9, false).unwrap(),
            "oops"
        );
        store_utf16(&memory, ANSI_NAME, "'X'");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 0, 0, ANSI_NAME, DATE_OUT, 16],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 1);
        assert_eq!(load_utf16(&memory, DATE_OUT, 16), "X");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetTimeFormatW,
                &[0, 0, 0, ANSI_NAME, TIME_OUT, 16],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 1);
        assert_eq!(load_utf16(&memory, TIME_OUT, 16), "X");

        // Comparison ordering: every Less/Equal/Greater arm in both the
        // case-folding and case-sensitive paths.
        store_utf16(&memory, 0x13A0, "a");
        store_utf16(&memory, 0x13B0, "b");
        context.state.set(Register::Rcx, 0x13A0);
        context.state.set(Register::Rdx, 0x13B0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::LstrcmpW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::MAX);
        context.state.set(Register::Rcx, 0);
        context.state.set(Register::Rdx, 0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::LstrcmpW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        context.state.set(Register::Rcx, 0x13A0);
        context.state.set(Register::Rdx, 0x13B0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::LstrcmpiW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::MAX);
        context.state.set(Register::Rcx, 0x13B0);
        context.state.set(Register::Rdx, 0x13A0);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::LstrcmpiW),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);

        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::CompareStringW,
                &[0x0409, 1, 0x13A0, 1, 0x13B0, 1],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::CompareStringW,
                &[0x0409, 1, 0x13B0, 1, 0x13A0, 1],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 3);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::CompareStringW,
                &[0x0409, 0, 0x13A0, 1, 0x13A0, 1],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 2);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetDateFormatW,
                &[0, 0, SYSTEMTIME_DATE, W_DATE_FMT, DATE_OUT, 0],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 11);

        // Environment read: size query, insufficient buffer, missing value
        // and case-insensitive lookup.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetEnvironmentVariableW,
                &[ENV_NAME, 0, 0],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 6);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetEnvironmentVariableW,
                &[ENV_NAME, ENV_BUFFER, 3],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 6);
        assert_eq!(x86.last_error, ERROR_INSUFFICIENT_BUFFER);
        store_utf16(&memory, ENV_NAME, "casa_test");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetEnvironmentVariableW,
                &[ENV_NAME, ENV_BUFFER, 16],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 5);
        store_utf16(&memory, ENV_NAME, "MISSING_ENV");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::GetEnvironmentVariableW,
                &[ENV_NAME, ENV_BUFFER, 16],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 0);
        assert_eq!(x86.last_error, ERROR_ENVVAR_NOT_FOUND);

        // Registry: an opened key handle, NULL type/data pointers and an
        // unknown handle that must fall back to the barrier.
        store_utf16(&memory, REG_NAME, "Demo");
        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::RegQueryValueExW,
                &[0x1234, REG_NAME, 0, 0, 0, REG_LEN],
            ),
            true
        );
        assert_eq!(x86.state.get(Register::Rax), 0);
        assert_eq!(memory.load(REG_LEN, 4), Some(12));
        assert_eq!(
            invoke_x86(
                &shared,
                &mut x86,
                &memory,
                HostThunk::RegQueryValueExW,
                &[0x9999, REG_NAME, 0, REG_TYPE, REG_BUF, REG_LEN],
            ),
            false
        );
    }

    struct FailingMemory<'a> {
        inner: &'a TestMemory,
        remaining: std::cell::Cell<usize>,
    }

    impl WorkerMemoryView for FailingMemory<'_> {
        fn load(&self, address: u64, len: usize) -> Option<u64> {
            self.inner.load(address, len)
        }

        fn store(&self, address: u64, bytes: &[u8]) -> bool {
            if self.remaining.get() == 0 {
                return false;
            }
            self.remaining.set(self.remaining.get() - 1);
            self.inner.store(address, bytes)
        }
    }

    fn prepare_call(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thunk: HostThunk,
    ) -> u64 {
        let address = thunk_address(context);
        shared.publish_thunk(address, &thunk);
        context.state.rip = address;
        let pointer = context.state.arch.pointer_bytes() as u64;
        let pushed = context.state.get(Register::Rsp) - pointer;
        assert_eq!(
            memory.store(pushed, &RETURN_ADDRESS.to_le_bytes()[..pointer as usize]),
            true
        );
        context.state.set(Register::Rsp, pushed);
        address
    }

    fn prepare_x86_call(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thunk: HostThunk,
        args: &[u64],
    ) -> u64 {
        context.state.set(Register::Rsp, STACK);
        for (index, value) in args.iter().enumerate() {
            set_x86_arg(memory, index as u64, *value as u32);
        }
        prepare_call(shared, context, memory, thunk)
    }

    #[test]
    fn parallel_api_out_of_bounds_reads_and_writes_fail_closed() {
        assert_eq!(format!("{:?}", ProcessShared::new()).is_empty(), false);
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x4444));
        let memory = TestMemory::new();
        let mut context = x64_context(0xA00);
        let entry = prepare_call(&shared, &mut context, &memory, HostThunk::CharNextW);
        context.state.set(Register::Rcx, 0x1FFF);
        assert_eq!(shared.run_worker_api(&mut context, &memory, entry), false);

        // Version info headers that cannot be read at all.
        context.state.set(Register::Rsp, STACK);
        let entry = prepare_call(&shared, &mut context, &memory, HostThunk::GetVersionExW);
        context.state.set(Register::Rcx, 0x1FFF);
        assert_eq!(shared.run_worker_api(&mut context, &memory, entry), false);

        // A return-address fetch beyond the view.
        context.state.set(Register::Rsp, 0x1FFF);
        assert_eq!(shared.run_worker_api(&mut context, &memory, entry), false);

        // VersionExA's size header cannot be read.
        context.state.set(Register::Rsp, STACK);
        let entry = prepare_call(&shared, &mut context, &memory, HostThunk::GetVersionExA);
        context.state.set(Register::Rcx, 0x1FFF);
        assert_eq!(shared.run_worker_api(&mut context, &memory, entry), false);

        // A thunk entry with no worker implementation is a barrier.
        let barrier_only = ParallelThunk {
            api: None,
            class: crate::host_thunks::ThunkConcurrency::OwnerOnly,
            x86_arg_bytes: 0,
        };
        assert_eq!(
            super::invoke_parallel_api(&shared, &mut context, &memory, &barrier_only),
            false
        );
    }

    #[test]
    fn parallel_api_unreadable_stack_arguments_fall_back_to_barrier() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x6666));
        let memory = TestMemory::new();
        let first_arg = [
            HostThunk::SetLastError,
            HostThunk::QueryPerformanceCounter,
            HostThunk::QueryPerformanceFrequency,
            HostThunk::GetSystemTimeAsFileTime,
            HostThunk::GetSystemTimePreciseAsFileTime,
            HostThunk::GetVersionExW,
            HostThunk::GetVersionExA,
            HostThunk::GetSystemInfo,
            HostThunk::GetNativeSystemInfo,
            HostThunk::GlobalMemoryStatusEx,
            HostThunk::IsProcessorFeaturePresent,
            HostThunk::CharNextW,
            HostThunk::CharPrevW,
            HostThunk::StrFromTimeIntervalW,
            HostThunk::Strlen,
            HostThunk::LstrlenW,
            HostThunk::LstrcmpW,
            HostThunk::LstrcmpiW,
            HostThunk::CompareStringW,
            HostThunk::MultiByteToWideChar,
            HostThunk::WideCharToMultiByte,
            HostThunk::GetCPInfo,
            HostThunk::IsValidCodePage,
            HostThunk::LocaleNameToLCID,
            HostThunk::GetProcessHeaps,
            HostThunk::HeapSize,
            HostThunk::GetTimeZoneInformation,
            HostThunk::GetDateFormatW,
            HostThunk::GetTimeFormatW,
            HostThunk::GetEnvironmentVariableW,
            HostThunk::RegQueryValueExA,
            HostThunk::RegQueryValueExW,
        ];
        for (index, thunk) in first_arg.into_iter().enumerate() {
            let mut context = x86_context(0xC00 + index as u32);
            context.state.set(Register::Rsp, 0x2000);
            let address = prepare_call(&shared, &mut context, &memory, thunk);
            assert_eq!(
                shared.run_worker_api(&mut context, &memory, address),
                false,
                "an unreadable first argument must fall back to the barrier"
            );
        }

        // IsWow64Process reads its output pointer from the second argument.
        let mut context = x86_context(0xC80);
        context.state.set(Register::Rsp, 0x1FFC);
        let address = prepare_call(&shared, &mut context, &memory, HostThunk::IsWow64Process);
        assert_eq!(shared.run_worker_api(&mut context, &memory, address), false);

        // CharPrevW reads a second argument.
        let mut context = x86_context(0xC81);
        context.state.set(Register::Rsp, 0x1FFC);
        let address = prepare_call(&shared, &mut context, &memory, HostThunk::CharPrevW);
        assert_eq!(shared.run_worker_api(&mut context, &memory, address), false);

        // IsWow64Process also reads (and ignores) its first argument, so a
        // first-argument-only fault must not execute the thunk.
        struct LoadHoleMemory<'a> {
            inner: &'a TestMemory,
            hole: u64,
        }
        impl WorkerMemoryView for LoadHoleMemory<'_> {
            fn load(&self, address: u64, len: usize) -> Option<u64> {
                if address == self.hole {
                    None
                } else {
                    self.inner.load(address, len)
                }
            }

            fn store(&self, address: u64, bytes: &[u8]) -> bool {
                self.inner.store(address, bytes)
            }
        }
        let mut context = x86_context(0xC82);
        let hole_memory = TestMemory::new();
        let address = prepare_call(
            &shared,
            &mut context,
            &hole_memory,
            HostThunk::IsWow64Process,
        );
        let hole = LoadHoleMemory {
            inner: &hole_memory,
            hole: STACK,
        };
        assert_eq!(shared.run_worker_api(&mut context, &hole, address), false);

        // StrFromTimeIntervalW reads arguments 1..3 after a readable buffer.
        for (index, stack) in [(1_u32, 0x1FFC_u64), (2, 0x1FF8), (3, 0x1FF4)] {
            let mut context = x86_context(0xC90 + index);
            context.state.set(Register::Rsp, stack);
            let address = prepare_call(
                &shared,
                &mut context,
                &memory,
                HostThunk::StrFromTimeIntervalW,
            );
            assert_eq!(
                shared.run_worker_api(&mut context, &memory, address),
                false,
                "an unreadable argument {index} must fall back to the barrier"
            );
        }
    }

    #[test]
    fn parallel_api_write_faults_fall_back_to_barrier() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x5555));
        let memory = TestMemory::new();
        prepare_hammer_memory(&memory);
        // Seed a full-size version header so the writers get past the size read.
        assert_eq!(memory.store(0x1B00, &0x11C_u32.to_le_bytes()), true);
        assert_eq!(memory.store(0x1D00, &0x9C_u32.to_le_bytes()), true);
        let cases: &[(HostThunk, [u64; 4])] = &[
            (HostThunk::QueryPerformanceCounter, [0x1B00, 0, 0, 0]),
            (HostThunk::QueryPerformanceFrequency, [0x1B00, 0, 0, 0]),
            (HostThunk::GetSystemTimeAsFileTime, [0x1B00, 0, 0, 0]),
            (HostThunk::GetSystemTimePreciseAsFileTime, [0x1B00, 0, 0, 0]),
            (HostThunk::GetVersionExW, [0x1B00, 0, 0, 0]),
            (HostThunk::GetVersionExA, [0x1D00, 0, 0, 0]),
            (HostThunk::IsWow64Process, [0, 0x1B00, 0, 0]),
            (HostThunk::GetSystemInfo, [0x1B00, 0, 0, 0]),
            (HostThunk::GetNativeSystemInfo, [0x1B00, 0, 0, 0]),
            (HostThunk::GlobalMemoryStatusEx, [0x1B00, 0, 0, 0]),
            (HostThunk::StrFromTimeIntervalW, [0x1B00, 8, 3_723_000, 4]),
            (HostThunk::GetCPInfo, [1252, CP_INFO, 0, 0]),
            (HostThunk::GetProcessHeaps, [1, HEAPS_OUT, 0, 0]),
            (HostThunk::GetTimeZoneInformation, [TZ_OUT, 0, 0, 0]),
            (
                HostThunk::GetEnvironmentVariableW,
                [ENV_NAME, ENV_BUFFER, 16, 0],
            ),
        ];
        for (index, (thunk, args)) in cases.iter().enumerate() {
            let mut context = x64_context(0xB00 + index as u32);
            context.state.rip = THUNK;
            context.state.set(Register::Rcx, args[0]);
            context.state.set(Register::Rdx, args[1]);
            context.state.set(Register::R8, args[2]);
            context.state.set(Register::R9, args[3]);
            context.state.set(Register::Rax, 0xDEAD);
            let entry = prepare_call(&shared, &mut context, &memory, thunk.clone());
            let mut saw_false = false;
            for allowed in 0..=40 {
                let failing = FailingMemory {
                    inner: &memory,
                    remaining: std::cell::Cell::new(allowed),
                };
                context.state.set(Register::Rsp, STACK);
                let entry = prepare_call(&shared, &mut context, &memory, thunk.clone());
                context.state.set(Register::Rcx, args[0]);
                context.state.set(Register::Rdx, args[1]);
                context.state.set(Register::R8, args[2]);
                context.state.set(Register::R9, args[3]);
                if !shared.run_worker_api(&mut context, &failing, entry) {
                    saw_false = true;
                }
            }
            let _ = entry;
            assert_eq!(
                saw_false, true,
                "a write fault must fall back to the barrier (case {index}: {thunk:?})"
            );
        }

        // Six- and eight-argument writers use the x86 stack form.
        let x86_cases: Vec<(HostThunk, Vec<u64>)> = vec![
            (
                HostThunk::MultiByteToWideChar,
                vec![65001, 0, MULTI_IN, 1, WIDE_OUT, 4],
            ),
            (
                HostThunk::WideCharToMultiByte,
                vec![65001, 0, WIDE_IN, 1, MULTI_OUT, 4, 0, 0x1C00],
            ),
            (
                HostThunk::RegQueryValueExW,
                vec![
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN,
                ],
            ),
            (
                HostThunk::RegQueryValueExA,
                vec![
                    u64::from(HKEY_CURRENT_USER),
                    ANSI_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN,
                ],
            ),
            (
                HostThunk::GetDateFormatW,
                vec![0, 0, SYSTEMTIME_DATE, W_DATE_FMT, DATE_OUT, 16],
            ),
            (
                HostThunk::GetTimeFormatW,
                vec![0, 0, SYSTEMTIME_TIME, W_TIME_FMT, TIME_OUT, 16],
            ),
        ];
        for (index, (thunk, args)) in x86_cases.iter().enumerate() {
            let mut saw_false = false;
            for allowed in 0..=64 {
                let mut context = x86_context(0xB40 + index as u32);
                assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
                let address = prepare_x86_call(&shared, &mut context, &memory, thunk.clone(), args);
                let failing = FailingMemory {
                    inner: &memory,
                    remaining: std::cell::Cell::new(allowed),
                };
                if !shared.run_worker_api(&mut context, &failing, address) {
                    saw_false = true;
                }
            }
            assert_eq!(
                saw_false, true,
                "an x86 write fault must fall back to the barrier (case {index}: {thunk:?})"
            );
        }

        // Invalid digits take the formatting helper's failure branch.
        let mut context = x64_context(0xB80);
        let entry = prepare_call(
            &shared,
            &mut context,
            &memory,
            HostThunk::StrFromTimeIntervalW,
        );
        context.state.set(Register::Rcx, 0x1B00);
        context.state.set(Register::Rdx, 8);
        context.state.set(Register::R8, 1000);
        context.state.set(Register::R9, 0);
        let failing = FailingMemory {
            inner: &memory,
            remaining: std::cell::Cell::new(0),
        };
        assert_eq!(shared.run_worker_api(&mut context, &failing, entry), false);
    }

    #[test]
    fn parallel_api_deterministic_filetime_uses_guest_clock_exactly() {
        let shared = ProcessShared::new();
        let mut environment = environment(0x7777);
        environment.clock.dtm = true;
        environment.clock.deterministic_tick_ms = 1234;
        shared.publish_environment(environment);
        let memory = TestMemory::new();
        let mut context = x64_context(0xD00);
        context.state.set(Register::Rcx, 0x1B00);
        assert_eq!(
            invoke(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetSystemTimeAsFileTime
            ),
            true
        );
        let expected = WINDOWS_EPOCH_OFFSET_100NS + 1234 * 10_000;
        assert_eq!(memory.load(0x1B00, 8), Some(expected));
        assert_eq!(context.last_error, 0);
    }

    #[test]
    fn parallel_api_x86_stdcall_cleanup_and_stack_args_are_exact() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x3333));
        let mut context = x86_context(0x900);
        let memory = TestMemory::new();
        set_x86_arg(&memory, 0, 0xCAFE);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::SetLastError),
            true
        );
        assert_eq!(context.last_error, 0xCAFE);
        assert_eq!(context.state.get(Register::Rsp), STACK + 4);
        assert_eq!(context.state.rip, RETURN_ADDRESS);

        // A 4-byte x86 out pointer is written through the worker view.
        context.state.set(Register::Rsp, STACK);
        set_x86_arg(&memory, 0, 0x1A00);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetSystemInfo),
            true
        );
        assert_eq!(memory.load(0x1A00, 2), Some(0));
        assert_eq!(context.state.get(Register::Rsp), STACK + 4);
    }

    const W_THREAD_ID: usize = 0;
    const W_VERSION: usize = 1;
    const W_ENV: usize = 2;
    const W_REGISTRY: usize = 3;
    const W_FILE_EX: usize = 4;
    const W_FILE_ATTR_W: usize = 5;
    const W_FILE_ATTR_A: usize = 6;
    const W_FILE_SIZE_EX: usize = 7;
    const W_FILE_SIZE: usize = 8;
    const W_COMPUTER_NAME: usize = 9;
    const W_TLS: usize = 10;
    const W_FLS: usize = 11;
    const W_EXIT_THREAD: usize = 12;
    const W_EXIT_PROCESS: usize = 13;
    const W_THREAD_PRIORITY: usize = 14;
    const W_INTERLOCKED: usize = 15;
    const W_REG_ENUM_KEY: usize = 16;
    const W_REG_ENUM_VALUE: usize = 17;
    const W_REG_INFO: usize = 18;
    const W_SHREG: usize = 19;
    const W_LCMAP: usize = 20;
    const W_CHAR_UPPER: usize = 21;
    const W_IS_CHAR: usize = 22;
    const W_TLS_SET: usize = 23;
    const W_FLS_SET: usize = 24;
    const W_TZ: usize = 25;
    const W_METRICS: usize = 26;
    const W_FULL_PATH: usize = 27;
    const W_LONG_PATH: usize = 28;
    const W_SHORT_PATH: usize = 29;
    const W_FILE_TYPE: usize = 30;
    const W_OWNER_ONLY: usize = 31;
    const W_COUNT: usize = 32;

    const W_FILE_PATH: u64 = 0x1F00;
    const W_DIR_PATH: u64 = 0x1F40;
    const W_ANSI_FILE_PATH: u64 = 0x1F80;
    const W_ATTR_OUT: u64 = 0x1E00;
    const W_SIZE_OUT: u64 = 0x1E80;
    const W_HIGH_OUT: u64 = 0x1E84;
    const W_COMPUTER_BUF: u64 = 0x1E90;
    const W_COMPUTER_LEN: u64 = 0x1EC0;
    const W_EXIT_THREAD_OUT: u64 = 0x1EC4;
    const W_EXIT_PROCESS_OUT: u64 = 0x1EC8;
    const W_INTERLOCKED_CELL: u64 = 0x1ED0;
    const W_REG_NAME_OUT: u64 = 0x1800;
    const W_REG_DATA_OUT: u64 = 0x1840;
    const W_REG_NAME_SIZE: u64 = 0x1880;
    const W_REG_DATA_SIZE: u64 = 0x1884;
    const W_REG_TYPE_OUT: u64 = 0x1888;
    const W_REG_SUBKEY_OUT: u64 = 0x1890;
    const W_LCMAP_SRC: u64 = 0x18A0;
    const W_LCMAP_DST: u64 = 0x18C0;
    const W_CHAR_BUF: u64 = 0x18E0;
    const W_TZ_IN: u64 = 0x1900;
    const W_TZ_OUT: u64 = 0x1910;
    const W_PATH_OUT: u64 = 0x1940;
    const W_PATH_PART: u64 = 0x1A40;
    const W_INFO_SUBKEYS: u64 = 0x1A60;
    const W_INFO_MAX_SUBKEY: u64 = 0x1A64;
    const W_INFO_VALUES: u64 = 0x1A68;
    const W_INFO_MAX_VALUE: u64 = 0x1A6C;
    const W_INFO_MAX_DATA: u64 = 0x1A70;

    fn workload_thunk(index: usize) -> HostThunk {
        match index {
            W_THREAD_ID => HostThunk::GetCurrentThreadId,
            W_VERSION => HostThunk::GetVersion,
            W_ENV => HostThunk::GetEnvironmentVariableW,
            W_REGISTRY => HostThunk::RegQueryValueExW,
            W_FILE_EX => HostThunk::GetFileAttributesExW,
            W_FILE_ATTR_W => HostThunk::GetFileAttributesW,
            W_FILE_ATTR_A => HostThunk::GetFileAttributesA,
            W_FILE_SIZE_EX => HostThunk::GetFileSizeEx,
            W_FILE_SIZE => HostThunk::GetFileSize,
            W_COMPUTER_NAME => HostThunk::GetComputerNameW,
            W_TLS => HostThunk::TlsGetValue,
            W_FLS => HostThunk::FlsGetValue,
            W_EXIT_THREAD => HostThunk::GetExitCodeThread,
            W_EXIT_PROCESS => HostThunk::GetExitCodeProcess,
            W_THREAD_PRIORITY => HostThunk::GetThreadPriority,
            W_INTERLOCKED => HostThunk::InterlockedIncrement,
            W_REG_ENUM_KEY => HostThunk::RegEnumKeyExW,
            W_REG_ENUM_VALUE => HostThunk::RegEnumValueW,
            W_REG_INFO => HostThunk::RegQueryInfoKeyW,
            W_SHREG => HostThunk::SHRegGetValueW,
            W_LCMAP => HostThunk::LCMapStringW,
            W_CHAR_UPPER => HostThunk::CharUpperW,
            W_IS_CHAR => HostThunk::IsCharAlphaW,
            W_TLS_SET => HostThunk::TlsSetValue,
            W_FLS_SET => HostThunk::FlsSetValue,
            W_TZ => HostThunk::SystemTimeToTzSpecificLocalTime,
            W_METRICS => HostThunk::GetSystemMetrics,
            W_FULL_PATH => HostThunk::GetFullPathNameW,
            W_LONG_PATH => HostThunk::GetLongPathNameW,
            W_SHORT_PATH => HostThunk::GetShortPathNameW,
            W_FILE_TYPE => HostThunk::GetFileType,
            W_OWNER_ONLY => HostThunk::CreateFileW,
            _ => HostThunk::GetLastError,
        }
    }

    fn workload_address(thread: u32, index: usize) -> u64 {
        0x4000 + u64::from(thread) * 0x100 + index as u64 * 8
    }

    fn publish_workload(shared: &ProcessShared, thread: u32) {
        for index in 0..W_COUNT {
            shared.publish_thunk(workload_address(thread, index), &workload_thunk(index));
        }
    }

    fn store_u16_values(memory: &TestMemory, address: u64, values: &[u16]) {
        let bytes = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        assert_eq!(memory.store(address, &bytes), true);
    }

    fn prepare_workload_memory(memory: &TestMemory) {
        prepare_hammer_memory(memory);
        store_utf16(memory, W_FILE_PATH, "C:\\game\\data.bin");
        store_utf16(memory, W_DIR_PATH, "C:\\game");
        store_ascii(memory, W_ANSI_FILE_PATH, "C:\\game\\data.bin");
        assert_eq!(memory.store(W_INTERLOCKED_CELL, &5_u32.to_le_bytes()), true);
        assert_eq!(memory.store(W_COMPUTER_LEN, &16_u32.to_le_bytes()), true);
        assert_eq!(memory.store(W_REG_NAME_SIZE, &64_u32.to_le_bytes()), true);
        assert_eq!(memory.store(W_REG_DATA_SIZE, &64_u32.to_le_bytes()), true);
        store_utf16(memory, W_LCMAP_SRC, "hello");
        store_utf16(memory, W_CHAR_BUF, "Abc");
        store_u16_values(memory, W_TZ_IN, &[2024, 1, 2, 3, 4, 5, 6, 7, 8]);
        store_utf16(memory, W_PATH_OUT, "");
        assert_eq!(
            memory.store(W_PATH_PART, &0xFFFF_FFFF_u64.to_le_bytes()),
            true
        );
    }

    /// Call a pre-published thunk without touching the dispatch table, so the
    /// measurement loop measures the API dispatch path with no writer traffic.
    fn call_published(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thread: u32,
        index: usize,
        args: &[u64],
    ) -> bool {
        context.state.set(Register::Rsp, STACK);
        for (arg_index, value) in args.iter().enumerate() {
            set_x86_arg(memory, arg_index as u64, *value as u32);
        }
        let pointer = context.state.arch.pointer_bytes() as u64;
        let pushed = STACK - pointer;
        assert_eq!(
            memory.store(pushed, &RETURN_ADDRESS.to_le_bytes()[..pointer as usize]),
            true
        );
        context.state.set(Register::Rsp, pushed);
        context.state.rip = workload_address(thread, index);
        let executed = shared.run_worker_api(context, memory, workload_address(thread, index));
        if !executed {
            context.state.set(Register::Rsp, STACK);
        }
        executed
    }

    fn mixed_workload(
        shared: &ProcessShared,
        context: &mut GuestThreadContext,
        memory: &TestMemory,
        thread: u32,
    ) -> Vec<(u64, u32)> {
        let mut results = Vec::with_capacity(W_COUNT);
        macro_rules! record {
            ($index:expr, $args:expr) => {{
                let executed = call_published(shared, context, memory, thread, $index, $args);
                if executed {
                    results.push((context.state.get(Register::Rax), context.last_error));
                } else {
                    results.push((0xDEAD, 0xDEAD));
                }
            }};
        }
        record!(W_THREAD_ID, &[]);
        record!(W_VERSION, &[]);
        record!(W_ENV, &[ENV_NAME, ENV_BUFFER, 16]);
        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
        record!(
            W_REGISTRY,
            &[
                u64::from(HKEY_CURRENT_USER),
                REG_NAME,
                0,
                REG_TYPE,
                REG_BUF,
                REG_LEN
            ]
        );
        results.push((memory.load(REG_LEN, 4).unwrap_or(0), 0));
        record!(W_FILE_EX, &[W_FILE_PATH, 0, W_ATTR_OUT]);
        results.push((memory.load(W_ATTR_OUT, 4).unwrap_or(0), 0));
        results.push((memory.load(W_ATTR_OUT + 32, 4).unwrap_or(0), 0));
        record!(W_FILE_ATTR_W, &[W_DIR_PATH]);
        record!(W_FILE_ATTR_A, &[W_ANSI_FILE_PATH]);
        record!(W_FILE_SIZE_EX, &[0x10, W_SIZE_OUT]);
        results.push((memory.load(W_SIZE_OUT, 8).unwrap_or(0), 0));
        record!(W_FILE_SIZE, &[0x10, W_HIGH_OUT]);
        record!(W_COMPUTER_NAME, &[W_COMPUTER_BUF, W_COMPUTER_LEN]);
        results.push((memory.load(W_COMPUTER_BUF, 2).unwrap_or(0), 0));
        record!(W_TLS, &[3]);
        record!(W_FLS, &[2]);
        record!(W_EXIT_THREAD, &[0x20, W_EXIT_THREAD_OUT]);
        results.push((memory.load(W_EXIT_THREAD_OUT, 4).unwrap_or(0), 0));
        record!(W_EXIT_PROCESS, &[0x21, W_EXIT_PROCESS_OUT]);
        results.push((memory.load(W_EXIT_PROCESS_OUT, 4).unwrap_or(0), 0));
        record!(W_THREAD_PRIORITY, &[0x22]);
        record!(W_INTERLOCKED, &[W_INTERLOCKED_CELL]);
        results.push((memory.load(W_INTERLOCKED_CELL, 4).unwrap_or(0), 0));
        record!(
            W_REG_ENUM_KEY,
            &[
                u64::from(HKEY_CURRENT_USER),
                0,
                W_REG_NAME_OUT,
                W_REG_NAME_SIZE,
                0,
                0
            ]
        );
        results.push((memory.load(W_REG_NAME_SIZE, 4).unwrap_or(0), 0));
        results.push((memory.load(W_REG_NAME_OUT, 2).unwrap_or(0), 0));
        record!(
            W_REG_ENUM_VALUE,
            &[
                u64::from(HKEY_CURRENT_USER),
                0,
                W_REG_NAME_OUT,
                W_REG_NAME_SIZE,
                0,
                W_REG_TYPE_OUT,
                W_REG_DATA_OUT,
                W_REG_DATA_SIZE
            ]
        );
        results.push((memory.load(W_REG_NAME_SIZE, 4).unwrap_or(0), 0));
        results.push((memory.load(W_REG_TYPE_OUT, 4).unwrap_or(0), 0));
        results.push((memory.load(W_REG_DATA_SIZE, 4).unwrap_or(0), 0));
        results.push((memory.load(W_REG_DATA_OUT, 2).unwrap_or(0), 0));
        record!(
            W_REG_INFO,
            &[
                u64::from(HKEY_CURRENT_USER),
                0,
                0,
                0,
                W_INFO_SUBKEYS,
                W_INFO_MAX_SUBKEY,
                0,
                W_INFO_VALUES,
                W_INFO_MAX_VALUE,
                W_INFO_MAX_DATA,
                0,
                0
            ]
        );
        results.push((memory.load(W_INFO_SUBKEYS, 4).unwrap_or(0), 0));
        results.push((memory.load(W_INFO_VALUES, 4).unwrap_or(0), 0));
        record!(
            W_SHREG,
            &[
                u64::from(HKEY_CURRENT_USER),
                0,
                REG_NAME,
                0,
                W_REG_TYPE_OUT,
                W_REG_DATA_OUT,
                W_REG_DATA_SIZE
            ]
        );
        results.push((memory.load(W_REG_DATA_SIZE, 4).unwrap_or(0), 0));
        results.push((memory.load(W_REG_DATA_OUT, 2).unwrap_or(0), 0));
        record!(W_LCMAP, &[0x0409, 0x0200, W_LCMAP_SRC, 5, W_LCMAP_DST, 8]);
        results.push((memory.load(W_LCMAP_DST, 2).unwrap_or(0), 0));
        record!(W_CHAR_UPPER, &[W_CHAR_BUF]);
        results.push((memory.load(W_CHAR_BUF, 2).unwrap_or(0), 0));
        record!(W_IS_CHAR, &[u64::from(b'A' as u32)]);
        record!(W_TLS_SET, &[3, 0x1234]);
        record!(W_FLS_SET, &[2, 0x88]);
        record!(W_TZ, &[0, W_TZ_IN, W_TZ_OUT]);
        results.push((memory.load(W_TZ_OUT, 2).unwrap_or(0), 0));
        record!(W_METRICS, &[0]);
        record!(W_FULL_PATH, &[W_LCMAP_SRC, 128, W_PATH_OUT, W_PATH_PART]);
        results.push((memory.load(W_PATH_PART, 4).unwrap_or(0), 0));
        results.push((memory.load(W_PATH_OUT, 2).unwrap_or(0), 0));
        store_utf16(memory, W_LCMAP_SRC, "data.bin");
        record!(W_LONG_PATH, &[W_LCMAP_SRC, W_PATH_OUT, 128]);
        results.push((memory.load(W_PATH_OUT, 2).unwrap_or(0), 0));
        record!(W_SHORT_PATH, &[W_LCMAP_SRC, W_PATH_OUT, 128]);
        results.push((memory.load(W_PATH_OUT, 2).unwrap_or(0), 0));
        record!(W_FILE_TYPE, &[0x10]);
        record!(W_OWNER_ONLY, &[]);
        results
    }

    #[test]
    fn parallel_api_mixed_workload_ratio_and_serial_reference_match() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x1234));
        const THREADS: u32 = 16;
        const ITERATIONS: u32 = 40;
        for thread in 0..THREADS {
            publish_workload(&shared, thread);
        }
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x86_context(0x1000 + thread);
                context.tls_slots.insert(3, 0xABCD);
                context.fls_slots.insert(2, 0x77);
                context.last_error = 0x99;
                let memory = TestMemory::new();
                prepare_workload_memory(&memory);
                let mut parallel_results = Vec::new();
                for _ in 0..ITERATIONS {
                    parallel_results.extend(mixed_workload(&shared, &mut context, &memory, thread));
                }

                // Serial reference: identical environment, thread id and
                // memory seed, run exactly once per iteration on the owner.
                let reference = ProcessShared::new();
                reference.publish_environment(environment(0x1234));
                publish_workload(&reference, thread);
                let mut reference_context = x86_context(0x1000 + thread);
                reference_context.tls_slots.insert(3, 0xABCD);
                reference_context.fls_slots.insert(2, 0x77);
                reference_context.last_error = 0x99;
                let reference_memory = TestMemory::new();
                prepare_workload_memory(&reference_memory);
                let mut reference_results = Vec::new();
                for _ in 0..ITERATIONS {
                    reference_results.extend(mixed_workload(
                        &reference,
                        &mut reference_context,
                        &reference_memory,
                        thread,
                    ));
                }
                assert_eq!(
                    parallel_results, reference_results,
                    "worker results must match the serial owner reference byte-for-byte"
                );
            }));
        }
        for worker in workers {
            worker.join().expect("mixed workload worker");
        }

        let snapshot = shared.api_dispatch_snapshot();
        println!(
            "parallel ratio={}% {}",
            snapshot.parallel_percent(),
            shared.api_dispatch_log_line()
        );
        assert!(
            snapshot.parallel_percent() >= 96,
            "parallel dispatch ratio must exceed the pinned 96% threshold: {}",
            shared.api_dispatch_log_line()
        );
        assert_eq!(
            snapshot.totals.parallel_dispatched,
            u64::from(THREADS * ITERATIONS * (W_COUNT as u32 - 1))
        );
        assert_eq!(
            snapshot.totals.barrier_calls,
            u64::from(THREADS * ITERATIONS)
        );
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::OwnerOnly)
                .map(|(_, count)| *count),
            Some(u64::from(THREADS * ITERATIONS))
        );
        assert_eq!(snapshot.totals.fallback_barriers, 0);
        let expected_categories = [
            (WorkerCategory::ThreadState, 1_u32),
            (WorkerCategory::Version, 1),
            (WorkerCategory::Environment, 1),
            (WorkerCategory::Registry, 5),
            (WorkerCategory::FileSystem, 5),
            (WorkerCategory::SystemInfo, 2),
            (WorkerCategory::Tls, 4),
            (WorkerCategory::ObjectStatus, 4),
            (WorkerCategory::Interlocked, 1),
            (WorkerCategory::Path, 3),
            (WorkerCategory::Nls, 3),
            (WorkerCategory::Clock, 1),
        ];
        for (category, per_iteration) in expected_categories {
            assert_eq!(
                snapshot
                    .categories
                    .iter()
                    .find(|(entry, _, _)| *entry == category)
                    .map(|(_, dispatched, _)| *dispatched),
                Some(u64::from(THREADS * ITERATIONS * per_iteration)),
                "category {category:?} dispatch count"
            );
        }
        for (reason, count) in snapshot.fallbacks {
            let expected = if reason == BarrierReason::OwnerOnly {
                u64::from(THREADS * ITERATIONS)
            } else {
                0
            };
            assert_eq!(count, expected, "fallback reason {reason:?}");
        }
        let line = shared.api_dispatch_log_line();
        assert_eq!(line.contains("filesystem:"), true);
        assert_eq!(line.contains("path:"), true);
        assert_eq!(line.contains("registry:"), true);
        assert_eq!(line.contains("owner-only:"), true);
    }

    #[test]
    fn parallel_api_fallback_reasons_are_accounted_exactly() {
        // Unsupported input: no published version snapshot.
        let shared = ProcessShared::new();
        let memory = TestMemory::new();
        let mut context = x64_context(0xA00);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::GetVersion),
            false
        );
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::UnsupportedInput)
                .map(|(_, count)| *count),
            Some(1)
        );
        assert_eq!(snapshot.totals.fallback_barriers, 1);
        assert_eq!(
            snapshot
                .categories
                .iter()
                .find(|(category, _, _)| *category == WorkerCategory::Version)
                .map(|(_, _, fallbacks)| *fallbacks),
            Some(1)
        );

        // Owner-only: a thunk with no worker implementation.
        let shared = ProcessShared::new();
        shared.publish_environment(environment(5));
        let mut context = x64_context(0xA10);
        assert_eq!(
            invoke(&shared, &mut context, &memory, HostThunk::CreateFileW),
            false
        );
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::OwnerOnly)
                .map(|(_, count)| *count),
            Some(1)
        );
        assert_eq!(snapshot.totals.owner_only_barriers, 1);

        // Unsupported category: a known worker API deliberately classified
        // owner-only must not execute and must be attributed separately.
        let shared = ProcessShared::new();
        shared.publish_environment(environment(6));
        let address = workload_address(0xAA0, 0);
        shared.thunks.write().unwrap().insert(
            address,
            ParallelThunk {
                api: Some(WorkerApi::GetTickCount64),
                class: crate::host_thunks::ThunkConcurrency::OwnerOnly,
                x86_arg_bytes: 0,
            },
        );
        let mut context = x64_context(0xAA0);
        context.state.rip = address;
        assert_eq!(shared.run_worker_api(&mut context, &memory, address), false);
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::UnsupportedCategory)
                .map(|(_, count)| *count),
            Some(1)
        );

        // Lock contention: a write-held subsystem lock must fall back rather
        // than block, attributed to the filesystem category.
        let shared = ProcessShared::new();
        shared.publish_environment(environment(7));
        let mut context = x86_context(0xAB0);
        publish_workload(&shared, 0xAB0);
        let guard = shared.files.write().unwrap();
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0xAB0,
                W_FILE_SIZE_EX,
                &[0x10, W_SIZE_OUT]
            ),
            false
        );
        drop(guard);
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::LockContention)
                .map(|(_, count)| *count),
            Some(1)
        );
        assert_eq!(
            snapshot
                .categories
                .iter()
                .find(|(category, _, _)| *category == WorkerCategory::FileSystem)
                .map(|(_, _, fallbacks)| *fallbacks),
            Some(1)
        );
        assert_eq!(
            snapshot
                .category_reasons
                .iter()
                .find(|(category, reason, _)| {
                    *category == WorkerCategory::FileSystem
                        && *reason == BarrierReason::LockContention
                })
                .map(|(_, _, count)| *count),
            Some(1)
        );

        // Guest-memory write fault: the first store fails.
        let shared = ProcessShared::new();
        shared.publish_environment(environment(8));
        let mut context = x64_context(0xAC0);
        let entry = prepare_call(&shared, &mut context, &memory, HostThunk::GetSystemInfo);
        context.state.set(Register::Rcx, 0x1A00);
        let failing = FailingMemory {
            inner: &memory,
            remaining: std::cell::Cell::new(0),
        };
        assert_eq!(shared.run_worker_api(&mut context, &failing, entry), false);
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::GuestMemoryWrite)
                .map(|(_, count)| *count),
            Some(1)
        );
        assert_eq!(
            snapshot
                .categories
                .iter()
                .find(|(category, _, _)| *category == WorkerCategory::SystemInfo)
                .map(|(_, _, fallbacks)| *fallbacks),
            Some(1)
        );
    }

    #[test]
    fn parallel_api_new_categories_match_owner_error_codes() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x2222));
        let memory = TestMemory::new();
        prepare_workload_memory(&memory);
        let mut context = x86_context(0x1200);
        context.tls_slots.insert(3, 0xABCD);
        context.fls_slots.insert(2, 0x77);
        context.last_error = 0x99;
        publish_workload(&shared, 0x1200);

        // Filesystem: empty path and a non-zero info level.
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_FILE_EX,
                &[0, 0, W_ATTR_OUT]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_PATH_NOT_FOUND);
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_FILE_EX,
                &[W_FILE_PATH, 1, W_ATTR_OUT]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // A canonical absolute path that is not in the cache falls back.
        store_utf16(&memory, W_FILE_PATH, "C:\\game\\missing.bin");
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_FILE_EX,
                &[W_FILE_PATH, 0, W_ATTR_OUT]
            ),
            false
        );
        // The owner's resolver would produce the same canonical string.
        store_utf16(&memory, W_FILE_PATH, "C:\\game\\data.bin");
        assert_eq!(is_canonical_guest_absolute("C:\\game\\data.bin"), true);
        assert_eq!(is_canonical_guest_absolute("C:\\game\\..\\data.bin"), false);
        assert_eq!(is_canonical_guest_absolute("data.bin"), false);

        // Attribute formatting for both W and A.
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_FILE_ATTR_W,
                &[W_DIR_PATH]
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(FILE_ATTRIBUTE_DIRECTORY)
        );
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_FILE_ATTR_A,
                &[W_ANSI_FILE_PATH]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x81_u64);

        // GetFileSizeEx preserves last-error; its size is the cache value.
        context.last_error = 0x99;
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_FILE_SIZE_EX,
                &[0x10, W_SIZE_OUT]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(W_SIZE_OUT, 8), Some(12_345));
        assert_eq!(context.last_error, 0x99);
        // An unknown handle is not guessed.
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_FILE_SIZE_EX,
                &[0x11, W_SIZE_OUT]
            ),
            false
        );

        // GetFileSize with a null handle reports the exact sentinel.
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_FILE_SIZE,
                &[0, W_HIGH_OUT]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::from(u32::MAX));
        assert_eq!(context.last_error, ERROR_INVALID_HANDLE);

        // TLS/FLS reads are thread-context exact and out-of-range TLS fails.
        assert_eq!(
            call_published(&shared, &mut context, &memory, 0x1200, W_TLS, &[3]),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0xABCD);
        assert_eq!(
            call_published(&shared, &mut context, &memory, 0x1200, W_TLS, &[4096]),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);
        assert_eq!(
            call_published(&shared, &mut context, &memory, 0x1200, W_FLS, &[2]),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0x77);
        assert_eq!(
            call_published(&shared, &mut context, &memory, 0x1200, W_FLS, &[9]),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // Object status: exact exit codes and a sign-extended priority.
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_EXIT_THREAD,
                &[0x20, W_EXIT_THREAD_OUT]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(W_EXIT_THREAD_OUT, 4), Some(0x1234));
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_EXIT_PROCESS,
                &[0x21, W_EXIT_PROCESS_OUT]
            ),
            true
        );
        assert_eq!(memory.load(W_EXIT_PROCESS_OUT, 4), Some(0x5678));
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_THREAD_PRIORITY,
                &[0x22]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0xFFFF_FFFE_u64);
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_THREAD_PRIORITY,
                &[0]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::from(u32::MAX));
        assert_eq!(context.last_error, ERROR_INVALID_HANDLE);
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_EXIT_THREAD,
                &[0, W_EXIT_THREAD_OUT]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.load(W_EXIT_THREAD_OUT, 4), Some(0));
        assert_eq!(context.last_error, ERROR_INVALID_HANDLE);

        // Interlocked: previous/add semantics and unmapped-address error.
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_INTERLOCKED,
                &[W_INTERLOCKED_CELL]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 6);
        assert_eq!(memory.load(W_INTERLOCKED_CELL, 4), Some(6));
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_INTERLOCKED,
                &[0x3000]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // Computer name: exact success, size query and truncation.
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_COMPUTER_NAME,
                &[W_COMPUTER_BUF, W_COMPUTER_LEN]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(memory.load(W_COMPUTER_BUF, 2), Some(u64::from(b'C' as u16)));
        assert_eq!(memory.load(W_COMPUTER_LEN, 4), Some(6));
        assert_eq!(memory.store(W_COMPUTER_LEN, &3_u32.to_le_bytes()), true);
        assert_eq!(
            call_published(
                &shared,
                &mut context,
                &memory,
                0x1200,
                W_COMPUTER_NAME,
                &[W_COMPUTER_BUF, W_COMPUTER_LEN]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_MORE_DATA);
        // The owner reports the required size incl. the NUL (6) plus one for
        // the truncation path.
        assert_eq!(memory.load(W_COMPUTER_LEN, 4), Some(7));

        // GetSystemTime writes a plausible SYSTEMTIME and, like the owner,
        // preserves last-error.
        context.last_error = 0x77;
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetSystemTime,
                &[W_COMPUTER_BUF],
            ),
            true
        );
        assert_eq!(context.last_error, 0x77);
        let year = memory.load(W_COMPUTER_BUF, 2).unwrap_or(0);
        assert_eq!(year >= 2024, true);
        assert_eq!(memory.load(W_COMPUTER_BUF + 2, 2).unwrap_or(0) >= 1, true);
    }

    fn adversary_locked_read(
        shared: &ProcessShared,
        lock_files: bool,
        memory: &TestMemory,
        context: &mut GuestThreadContext,
        thread: u32,
        index: usize,
        args: &[u64],
    ) -> bool {
        if lock_files {
            let guard = shared.files.write().unwrap();
            let executed = call_published(shared, context, memory, thread, index, args);
            drop(guard);
            executed
        } else {
            let guard = shared.registry.write().unwrap();
            let executed = call_published(shared, context, memory, thread, index, args);
            drop(guard);
            executed
        }
    }

    #[test]
    fn parallel_api_lock_contention_and_writer_reader_race_stay_exact() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x3333));
        const THREADS: u32 = 4;
        for thread in 0..THREADS {
            publish_workload(&shared, thread);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicU64::new(0));
        let mut readers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            let completed = Arc::clone(&completed);
            readers.push(std::thread::spawn(move || {
                let mut context = x86_context(0x1300 + thread);
                let memory = TestMemory::new();
                prepare_workload_memory(&memory);
                while !stop.load(Ordering::Acquire) {
                    if thread % 2 == 0 {
                        let _ = adversary_locked_read(
                            &shared,
                            true,
                            &memory,
                            &mut context,
                            thread,
                            W_FILE_SIZE_EX,
                            &[0x10, W_SIZE_OUT],
                        );
                    } else {
                        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
                        let _ = adversary_locked_read(
                            &shared,
                            false,
                            &memory,
                            &mut context,
                            thread,
                            W_REGISTRY,
                            &[
                                u64::from(HKEY_CURRENT_USER),
                                REG_NAME,
                                0,
                                REG_TYPE,
                                REG_BUF,
                                REG_LEN,
                            ],
                        );
                    }
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for iteration in 0..500 {
            let mut environment = environment(0x3333);
            environment.files.entries.insert(
                "C:\\game\\data.bin".to_string(),
                WorkerFileMetadata {
                    size: 100 + iteration,
                    attributes: vec!["readonly".to_string()],
                    creation_time_ticks: iteration,
                    last_access_time_ticks: iteration,
                    last_write_time_ticks: iteration,
                    is_directory: false,
                },
            );
            shared.publish_environment(environment);
        }
        stop.store(true, Ordering::Release);
        for reader in readers {
            reader.join().expect("contended reader");
        }
        assert_eq!(completed.load(Ordering::Relaxed) > 0, true);
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(snapshot.totals.barrier_calls > 0, true);
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::LockContention)
                .map(|(_, count)| *count)
                .is_some(),
            true
        );
    }

    #[test]
    fn parallel_api_interlocked_hammer_is_lock_free_and_exact() {
        struct SharedAtomicMemory {
            bytes: std::sync::Mutex<Vec<u8>>,
        }
        impl WorkerMemoryView for SharedAtomicMemory {
            fn load(&self, address: u64, len: usize) -> Option<u64> {
                let start = usize::try_from(address).ok()?;
                let bytes = self.bytes.lock().unwrap();
                let slice = bytes.get(start..start.checked_add(len)?)?;
                let mut value = 0_u64;
                for (index, byte) in slice.iter().enumerate() {
                    value |= u64::from(*byte) << (index * 8);
                }
                Some(value)
            }

            fn store(&self, address: u64, bytes: &[u8]) -> bool {
                let Ok(start) = usize::try_from(address) else {
                    return false;
                };
                let mut target = self.bytes.lock().unwrap();
                let Some(slot) = target.get_mut(start..start + bytes.len()) else {
                    return false;
                };
                slot.copy_from_slice(bytes);
                true
            }

            fn atomic_fetch_add_u32(
                &self,
                address: u64,
                value: u32,
            ) -> Result<u32, AtomicGuestError> {
                let start = usize::try_from(address).map_err(|_| AtomicGuestError::Fault)?;
                let mut target = self.bytes.lock().unwrap();
                let Some(slot) = target.get_mut(start..start + 4) else {
                    return Err(AtomicGuestError::Fault);
                };
                let previous = u32::from_le_bytes(slot.try_into().expect("four bytes"));
                slot.copy_from_slice(&previous.wrapping_add(value).to_le_bytes());
                Ok(previous)
            }
        }

        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x4444));
        const CELL: u64 = 0x300;
        let memory = Arc::new(SharedAtomicMemory {
            bytes: std::sync::Mutex::new(vec![0_u8; 0x2000]),
        });
        assert_eq!(memory.store(CELL, &0_u32.to_le_bytes()), true);
        const THREADS: u32 = 8;
        const ROUNDS: u32 = 500;
        for thread in 0..THREADS {
            publish_workload(&shared, 0x1400 + thread);
            let pointer = 4_u64;
            assert_eq!(
                memory.store(
                    STACK - pointer,
                    &RETURN_ADDRESS.to_le_bytes()[..pointer as usize]
                ),
                true
            );
            assert_eq!(memory.store(STACK, &(CELL as u32).to_le_bytes()), true);
        }
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            let memory = Arc::clone(&memory);
            workers.push(std::thread::spawn(move || {
                let mut context = x86_context(0x1400 + thread);
                for _ in 0..ROUNDS {
                    let address = workload_address(0x1400 + thread, W_INTERLOCKED);
                    context.state.set(Register::Rsp, STACK - 4);
                    context.state.rip = address;
                    assert_eq!(
                        shared.run_worker_api(&mut context, memory.as_ref(), address),
                        true
                    );
                }
            }));
        }
        for worker in workers {
            worker.join().expect("interlocked worker");
        }
        assert_eq!(memory.load(CELL, 4), Some(u64::from(THREADS * ROUNDS)));
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(
            snapshot.totals.parallel_dispatched,
            u64::from(THREADS * ROUNDS)
        );
        assert_eq!(snapshot.totals.barrier_calls, 0);
        assert_eq!(
            snapshot
                .categories
                .iter()
                .find(|(category, _, _)| *category == WorkerCategory::Interlocked)
                .map(|(_, dispatched, _)| *dispatched),
            Some(u64::from(THREADS * ROUNDS))
        );
    }

    #[test]
    fn parallel_api_mixed_parallel_barrier_new_categories_no_deadlock() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x5555));
        const THREADS: u32 = 6;
        const ROUNDS: u32 = 100;
        for thread in 0..THREADS {
            publish_workload(&shared, thread);
        }
        let started = std::time::Instant::now();
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x86_context(0x1500 + thread);
                context.tls_slots.insert(3, 0xABCD);
                let memory = TestMemory::new();
                prepare_workload_memory(&memory);
                for _ in 0..ROUNDS {
                    assert_eq!(
                        call_published(
                            &shared,
                            &mut context,
                            &memory,
                            thread,
                            W_FILE_SIZE_EX,
                            &[0x10, W_SIZE_OUT]
                        ),
                        true
                    );
                    shared.with_process(|| std::thread::yield_now());
                    assert_eq!(
                        call_published(&shared, &mut context, &memory, thread, W_OWNER_ONLY, &[]),
                        false
                    );
                    assert_eq!(
                        call_published(&shared, &mut context, &memory, thread, W_TLS, &[3]),
                        true
                    );
                }
            }));
        }
        for worker in workers {
            worker.join().expect("mixed new-category worker");
        }
        assert_eq!(
            started.elapsed() < std::time::Duration::from_secs(5),
            true,
            "mixed parallel/barrier dispatch must not deadlock"
        );
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(
            snapshot.totals.parallel_dispatched,
            u64::from(THREADS * ROUNDS * 2)
        );
        assert_eq!(snapshot.totals.barrier_calls, u64::from(THREADS * ROUNDS));
        assert_eq!(shared.process_operations(), u64::from(THREADS * ROUNDS));
    }

    #[test]
    fn parallel_api_new_wave_cache_invalidation_and_error_paths_are_exact() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x6000));
        let memory = TestMemory::new();
        prepare_workload_memory(&memory);
        let mut context = x86_context(0x1600);

        // Registry key-existence/value reads.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegEnumKeyExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    W_REG_NAME_OUT,
                    W_REG_NAME_SIZE,
                    0,
                    0
                ]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.load(W_REG_NAME_SIZE, 4), Some(5));
        assert_eq!(load_utf16(&memory, W_REG_NAME_OUT, 16), "Child");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegEnumKeyExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    9,
                    W_REG_NAME_OUT,
                    W_REG_NAME_SIZE,
                    0,
                    0
                ]
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(ERROR_NO_MORE_ITEMS)
        );
        assert_eq!(context.last_error, ERROR_NO_MORE_ITEMS);
        assert_eq!(memory.load(W_REG_NAME_SIZE, 4), Some(0));
        assert_eq!(memory.store(W_REG_NAME_SIZE, &64_u32.to_le_bytes()), true);

        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegEnumValueW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    W_REG_NAME_OUT,
                    W_REG_NAME_SIZE,
                    0,
                    W_REG_TYPE_OUT,
                    W_REG_DATA_OUT,
                    W_REG_DATA_SIZE
                ]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(load_utf16(&memory, W_REG_NAME_OUT, 16), "Ansi");
        assert_eq!(memory.load(W_REG_TYPE_OUT, 4), Some(1));
        assert_eq!(memory.load(W_REG_DATA_SIZE, 4), Some(6));
        assert_eq!(memory.load(W_REG_DATA_OUT, 2), Some(0x68));
        assert_eq!(memory.store(W_REG_NAME_SIZE, &64_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegEnumValueW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    99,
                    W_REG_NAME_OUT,
                    W_REG_NAME_SIZE,
                    0,
                    W_REG_TYPE_OUT,
                    W_REG_DATA_OUT,
                    W_REG_DATA_SIZE
                ]
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(ERROR_NO_MORE_ITEMS)
        );
        assert_eq!(context.last_error, ERROR_NO_MORE_ITEMS);

        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryInfoKeyW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    0,
                    0,
                    W_INFO_SUBKEYS,
                    W_INFO_MAX_SUBKEY,
                    0,
                    W_INFO_VALUES,
                    W_INFO_MAX_VALUE,
                    W_INFO_MAX_DATA,
                    0,
                    0
                ]
            ),
            true
        );
        assert_eq!(memory.load(W_INFO_SUBKEYS, 4), Some(2));
        assert_eq!(memory.load(W_INFO_VALUES, 4), Some(3));
        assert_eq!(memory.load(W_INFO_MAX_SUBKEY, 4), Some(8));
        assert_eq!(memory.store(W_REG_DATA_SIZE, &64_u32.to_le_bytes()), true);

        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::SHRegGetValueW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    REG_NAME,
                    0,
                    W_REG_TYPE_OUT,
                    W_REG_DATA_OUT,
                    W_REG_DATA_SIZE
                ]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(memory.load(W_REG_DATA_SIZE, 4), Some(12));
        assert_eq!(memory.load(W_REG_DATA_OUT, 2), Some(0x68));
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::SHRegGetValueW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    REG_NAME,
                    0x20,
                    W_REG_TYPE_OUT,
                    W_REG_DATA_OUT,
                    W_REG_DATA_SIZE
                ]
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(ERROR_INVALID_PARAMETER)
        );
        assert_eq!(context.last_error, 0);
        assert_eq!(memory.store(W_REG_DATA_SIZE, &1_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::SHRegGetValueW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    REG_NAME,
                    0,
                    W_REG_TYPE_OUT,
                    W_REG_DATA_OUT,
                    W_REG_DATA_SIZE
                ]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::from(ERROR_MORE_DATA));
        assert_eq!(context.last_error, 0);
        assert_eq!(memory.load(W_REG_DATA_SIZE, 4), Some(12));
        store_utf16(&memory, W_CHAR_BUF, "Nope");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::SHRegGetValueW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    W_CHAR_BUF,
                    0,
                    W_REG_TYPE_OUT,
                    W_REG_DATA_OUT,
                    W_REG_DATA_SIZE
                ]
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(ERROR_FILE_NOT_FOUND)
        );
        assert_eq!(context.last_error, 0);

        // NLS mapping and classification.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::LCMapStringW,
                &[0x0409, 0x0200, W_LCMAP_SRC, 5, W_LCMAP_DST, 8]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 5);
        assert_eq!(memory.load(W_LCMAP_DST, 2), Some(0x48));
        store_utf16(&memory, W_CHAR_BUF, "Abc");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::CharUpperW,
                &[W_CHAR_BUF]
            ),
            true
        );
        assert_eq!(memory.load(W_CHAR_BUF, 2), Some(0x41));
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::IsCharAlphaW,
                &[u64::from(b'A' as u32)]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::IsCharAlphaW,
                &[u64::from(b'1' as u32)]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::LCMapStringW,
                &[0x0409, 0x0200, 0, 5, W_LCMAP_DST, 8]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::LCMapStringW,
                &[0x0409, 0x0200, W_LCMAP_SRC, 5, W_LCMAP_DST, 2]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INSUFFICIENT_BUFFER);
        store_utf16(&memory, W_CHAR_BUF, "not-a-locale");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::LCMapStringEx,
                &[W_CHAR_BUF, 0x0200, W_LCMAP_SRC, 5, W_LCMAP_DST, 8]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::CharUpperW,
                &[u64::from(b'a' as u32)]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::from(b'A' as u32));
        for (thunk, character) in [
            (HostThunk::IsCharAlphaNumericW, b'7'),
            (HostThunk::IsCharLowerW, b'a'),
            (HostThunk::IsCharUpperW, b'A'),
            (HostThunk::IsCharSpaceW, b' '),
        ] {
            assert_eq!(
                invoke_x86(
                    &shared,
                    &mut context,
                    &memory,
                    thunk,
                    &[u64::from(character as u32)]
                ),
                true
            );
            assert_eq!(context.state.get(Register::Rax), 1);
        }

        // TLS/FLS setters are thread-local.
        assert_eq!(memory.store(W_TZ_IN, &TZ_SYSTEMTIME), true);
        context.tls_slots.insert(3, 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::TlsSetValue,
                &[3, 0xDEAD]
            ),
            true
        );
        assert_eq!(context.tls_slots.get(&3), Some(&0xDEAD));
        context.tls_vector_ptr = W_TZ_OUT;
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::TlsSetValue,
                &[5, 0xBEEF]
            ),
            true
        );
        assert_eq!(memory.load(W_TZ_OUT + 5 * 4, 4), Some(0xBEEF));
        context.tls_vector_ptr = 0;
        context.fls_slots.insert(2, 1);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::FlsSetValue,
                &[2, 0x55]
            ),
            true
        );
        assert_eq!(context.fls_slots.get(&2), Some(&0x55));
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::FlsSetValue,
                &[9, 0x55]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // Time-zone conversion equals the documented host bias exactly.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::SystemTimeToTzSpecificLocalTime,
                &[0, W_TZ_IN, W_TZ_OUT]
            ),
            true
        );
        let filetime = systemtime_to_filetime_ticks(2024, 1, 2, 3, 4, 5, 7);
        let biased = (i128::from(filetime)
            - i128::from(local_timezone_bias_minutes()) * 600_000_000)
            .max(0) as u64;
        let (year, month, day_of_week, day, hour, minute, second, milliseconds) =
            filetime_ticks_to_systemtime(biased);
        let expected = [
            year,
            month,
            day_of_week,
            day,
            hour,
            minute,
            second,
            milliseconds,
        ];
        for (index, value) in expected.into_iter().enumerate() {
            assert_eq!(
                memory.load(W_TZ_OUT + index as u64 * 2, 2),
                Some(u64::from(value))
            );
        }

        // Display metrics.
        for (index, expected) in [(0_u64, 2560_u64), (1, 1600), (28, 80), (80, 1), (90, 96)] {
            assert_eq!(
                invoke_x86(
                    &shared,
                    &mut context,
                    &memory,
                    HostThunk::GetSystemMetrics,
                    &[index]
                ),
                true
            );
            assert_eq!(context.state.get(Register::Rax), expected);
            assert_eq!(context.last_error, 0);
        }

        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::SystemTimeToTzSpecificLocalTime,
                &[0, 0, W_TZ_OUT]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_INVALID_PARAMETER);

        // Path canonicalization and the required-size/truncation contract.
        store_utf16(&memory, W_LCMAP_SRC, "");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFullPathNameW,
                &[W_LCMAP_SRC, 128, W_PATH_OUT, 0]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 0);
        assert_eq!(context.last_error, ERROR_PATH_NOT_FOUND);
        store_utf16(&memory, W_LCMAP_SRC, "data.bin");
        let expected_path = resolve_full_guest_path("C:\\game", "data.bin");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFullPathNameW,
                &[W_LCMAP_SRC, 128, W_PATH_OUT, W_PATH_PART]
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            expected_path.encode_utf16().count() as u64
        );
        assert_eq!(load_utf16(&memory, W_PATH_OUT, 128), expected_path);
        assert_eq!(
            memory.load(W_PATH_PART, 4),
            Some(W_PATH_OUT + windows_file_part_offset(&expected_path).unwrap_or(0) as u32 as u64)
        );
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFullPathNameW,
                &[W_LCMAP_SRC, 4, W_PATH_OUT, 0]
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            expected_path.encode_utf16().count() as u64 + 1
        );
        assert_eq!(context.last_error, ERROR_INSUFFICIENT_BUFFER);
        for thunk in [HostThunk::GetLongPathNameW, HostThunk::GetShortPathNameW] {
            assert_eq!(
                invoke_x86(
                    &shared,
                    &mut context,
                    &memory,
                    thunk,
                    &[W_LCMAP_SRC, W_PATH_OUT, 128]
                ),
                true
            );
            assert_eq!(context.last_error, 0);
            assert_eq!(load_utf16(&memory, W_PATH_OUT, 128), expected_path);
        }

        // Simple handle queries.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFileType,
                &[0x10]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), 1);
        assert_eq!(context.last_error, 0);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFileType,
                &[u64::from(STD_OUTPUT_HANDLE)]
            ),
            true
        );
        assert_eq!(context.state.get(Register::Rax), u64::from(FILE_TYPE_CHAR));
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFileType,
                &[0x99]
            ),
            true
        );
        assert_eq!(
            context.state.get(Register::Rax),
            u64::from(FILE_TYPE_UNKNOWN)
        );
        assert_eq!(context.last_error, ERROR_INVALID_HANDLE);

        // Cache invalidation: a republished registry/file snapshot wins.
        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ]
            ),
            true
        );
        assert_eq!(memory.load(REG_BUF, 2), Some(0x68));
        let mut changed = environment(0x6000);
        changed.registry = registry_with_value("zulu");
        shared.publish_environment(changed);
        assert_eq!(memory.store(REG_LEN, &16_u32.to_le_bytes()), true);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegQueryValueExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    REG_NAME,
                    0,
                    REG_TYPE,
                    REG_BUF,
                    REG_LEN
                ]
            ),
            true
        );
        assert_eq!(memory.load(REG_BUF, 2), Some(0x7a));
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFileSizeEx,
                &[0x10, W_SIZE_OUT]
            ),
            true
        );
        assert_eq!(memory.load(W_SIZE_OUT, 8), Some(12_345));
        let mut changed = environment(0x6000);
        changed.files.sizes.insert(0x10, 999);
        shared.publish_environment(changed);
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFileSizeEx,
                &[0x10, W_SIZE_OUT]
            ),
            true
        );
        assert_eq!(memory.load(W_SIZE_OUT, 8), Some(999));
    }

    const TZ_SYSTEMTIME: [u8; 16] = [
        0xe8, 0x07, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x07,
        0x00,
    ];

    #[test]
    fn parallel_api_new_wave_unreadable_pointers_and_unknown_handles_fall_back() {
        let shared = ProcessShared::new();
        shared.publish_environment(environment(0x6100));
        let memory = TestMemory::new();
        prepare_workload_memory(&memory);
        let mut context = x86_context(0x1700);

        // Unreadable name-size pointer on an otherwise valid registry key.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegEnumKeyExW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    0,
                    W_REG_NAME_OUT,
                    0x9000,
                    0,
                    0
                ]
            ),
            false
        );
        // Unknown registry handle.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::RegEnumKeyExW,
                &[0xDEAD, 0, W_REG_NAME_OUT, W_REG_NAME_SIZE, 0, 0]
            ),
            false
        );
        // SHRegGetValueW subkey paths are owner-resolved from the live DB.
        store_utf16(&memory, W_LCMAP_SRC, "Sub");
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::SHRegGetValueW,
                &[
                    u64::from(HKEY_CURRENT_USER),
                    W_LCMAP_SRC,
                    REG_NAME,
                    0,
                    W_REG_TYPE_OUT,
                    W_REG_DATA_OUT,
                    W_REG_DATA_SIZE
                ]
            ),
            false
        );
        // A TLS vector that the worker view cannot write is a guest-write
        // fallback, never a silent update of the thread map.
        context.tls_vector_ptr = 0x9000;
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::TlsSetValue,
                &[0, 1]
            ),
            false
        );
        assert_eq!(context.tls_slots.get(&0), None);
        context.tls_vector_ptr = 0;
        // Unreadable SYSTEMTIME input.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::SystemTimeToTzSpecificLocalTime,
                &[0, 0x9000, W_TZ_OUT]
            ),
            false
        );
        // Unreadable path input.
        assert_eq!(
            invoke_x86(
                &shared,
                &mut context,
                &memory,
                HostThunk::GetFullPathNameW,
                &[0x9000, 128, W_PATH_OUT, 0]
            ),
            false
        );

        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(snapshot.totals.fallback_barriers, 6);
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::UnsupportedInput)
                .map(|(_, count)| *count),
            Some(5)
        );
        assert_eq!(
            snapshot
                .fallbacks
                .iter()
                .find(|(reason, _)| *reason == BarrierReason::GuestMemoryWrite)
                .map(|(_, count)| *count),
            Some(1)
        );
        assert_eq!(
            snapshot
                .categories
                .iter()
                .find(|(category, _, _)| *category == WorkerCategory::Registry)
                .map(|(_, _, fallbacks)| *fallbacks),
            Some(3)
        );
    }

    #[test]
    fn parallel_api_new_wave_mixed_parallel_barrier_no_deadlock() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x6200));
        const THREADS: u32 = 8;
        const ROUNDS: u32 = 100;
        for thread in 0..THREADS {
            publish_workload(&shared, thread);
        }
        let started = std::time::Instant::now();
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x86_context(0x1800 + thread);
                context.fls_slots.insert(2, 0);
                let memory = TestMemory::new();
                prepare_workload_memory(&memory);
                for _ in 0..ROUNDS {
                    assert_eq!(
                        call_published(
                            &shared,
                            &mut context,
                            &memory,
                            thread,
                            W_REG_ENUM_KEY,
                            &[
                                u64::from(HKEY_CURRENT_USER),
                                0,
                                W_REG_NAME_OUT,
                                W_REG_NAME_SIZE,
                                0,
                                0
                            ]
                        ),
                        true
                    );
                    assert_eq!(
                        call_published(
                            &shared,
                            &mut context,
                            &memory,
                            thread,
                            W_FULL_PATH,
                            &[W_LCMAP_SRC, 128, W_PATH_OUT, W_PATH_PART]
                        ),
                        true
                    );
                    shared.with_process(|| std::thread::yield_now());
                    assert_eq!(
                        call_published(&shared, &mut context, &memory, thread, W_OWNER_ONLY, &[]),
                        false
                    );
                    assert_eq!(
                        call_published(
                            &shared,
                            &mut context,
                            &memory,
                            thread,
                            W_FLS_SET,
                            &[2, 0x88]
                        ),
                        true
                    );
                }
            }));
        }
        for worker in workers {
            worker.join().expect("new-wave mixed worker");
        }
        assert_eq!(
            started.elapsed() < std::time::Duration::from_secs(5),
            true,
            "new-wave parallel/barrier mix must not deadlock"
        );
        let snapshot = shared.api_dispatch_snapshot();
        assert_eq!(
            snapshot.totals.parallel_dispatched,
            u64::from(THREADS * ROUNDS * 3)
        );
        assert_eq!(snapshot.totals.barrier_calls, u64::from(THREADS * ROUNDS));
        assert_eq!(shared.process_operations(), u64::from(THREADS * ROUNDS));
    }

    #[test]
    fn parallel_api_new_wave_last_error_isolation_under_parallel_calls() {
        let shared = Arc::new(ProcessShared::new());
        shared.publish_environment(environment(0x6300));
        const THREADS: u32 = 16;
        const ROUNDS: u32 = 50;
        let mut workers = Vec::new();
        for thread in 0..THREADS {
            let shared = Arc::clone(&shared);
            workers.push(std::thread::spawn(move || {
                let mut context = x86_context(0x1A00 + thread);
                let memory = TestMemory::new();
                prepare_workload_memory(&memory);
                let expected = 0x5000 + thread;
                for _ in 0..ROUNDS {
                    assert_eq!(
                        invoke_x86(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::SetLastError,
                            &[u64::from(expected)]
                        ),
                        true
                    );
                    assert_eq!(
                        invoke_x86(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::SystemTimeToTzSpecificLocalTime,
                            &[0, W_TZ_IN, W_TZ_OUT]
                        ),
                        true
                    );
                    assert_eq!(context.last_error, expected);
                    assert_eq!(
                        invoke_x86(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::GetSystemMetrics,
                            &[0]
                        ),
                        true
                    );
                    assert_eq!(context.last_error, 0);
                    assert_eq!(
                        invoke_x86(
                            &shared,
                            &mut context,
                            &memory,
                            HostThunk::SetLastError,
                            &[u64::from(expected)]
                        ),
                        true
                    );
                    assert_eq!(
                        invoke_x86(&shared, &mut context, &memory, HostThunk::GetLastError, &[]),
                        true
                    );
                    assert_eq!(context.state.get(Register::Rax), u64::from(expected));
                }
            }));
        }
        for worker in workers {
            worker.join().expect("last-error isolation worker");
        }
        let metrics = shared.api_dispatch_metrics();
        assert_eq!(metrics.parallel_dispatched, u64::from(THREADS * ROUNDS * 5));
        assert_eq!(metrics.barrier_calls, 0);
        assert_eq!(metrics.fallback_barriers, 0);
    }
}
