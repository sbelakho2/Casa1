//! API coverage evidence registry (oracle- and suite-backed).
//!
//! The registry maps (DLL, export) pairs to the CONTRACT that proves their
//! semantic coverage.  Evidence is NEVER inferred from the existence of a
//! Rust test — each [`ApiCoverageEvidence`] row names the actual contract
//! that exercises the API and asserts its observable behavior:
//!
//! - `windows-oracle:<category>` — a differential contract run by the
//!   standalone `windows_reference/` executable on real Windows.  Only a
//!   real Windows capture of that category may promote an API to
//!   [`CoverageLevel::Differential`].
//! - `casa1-conformance:<suite>` — the named conformance suite genuinely
//!   exercising the API (a section suite such as `section47`, or a named
//!   unit suite such as `runtime_unit` / the new `evidence_core_*` tests).
//!   Promotes to [`CoverageLevel::Conformance`].
//! - `casa1-scenario:<suite>` — the named subsystem scenario test.
//!   Promotes to [`CoverageLevel::SubsystemScenario`].
//!
//! [`ApiDatabase::from_thunk_metadata`] merges this registry after seeding
//! the implementation entries: when the (DLL, export, arch, Windows version)
//! key matches, the entry's [`CoverageLevel`] takes the registry's level.

use crate::api_database::{ArchSet, CoverageLevel, WindowsVersion};

/// One piece of coverage evidence for an API (a differential oracle
/// contract, a conformance suite, or a subsystem scenario test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiCoverageEvidence {
    /// Exporting DLL (lowercase, with extension).
    pub dll: &'static str,
    /// Export name.
    pub export: &'static str,
    /// Guest architectures the evidence applies to.
    pub arch: ArchSet,
    /// Windows versions the evidence applies to.
    pub windows_version: WindowsVersion,
    /// Proven semantic coverage level.
    pub level: CoverageLevel,
    /// The contract that produces the evidence: `windows-oracle:<category>`
    /// (the differential vector category the Windows reference executable
    /// runs), `casa1-conformance:<suite>` (a verified conformance suite), or
    /// `casa1-scenario:<suite>` (a subsystem scenario test).
    pub evidence_id: &'static str,
}

/// Convenience constructor for registry rows (any arch, any Windows version).
const fn evidence(
    dll: &'static str,
    export: &'static str,
    evidence_id: &'static str,
) -> ApiCoverageEvidence {
    ApiCoverageEvidence {
        dll,
        export,
        arch: ArchSet::Any,
        windows_version: WindowsVersion::Any,
        level: CoverageLevel::Differential,
        evidence_id,
    }
}

/// Conformance-suite evidence constructor.
///
/// `suite` is the actual test file / section / named unit test that
/// exercises the API as a conformance test; the evidence id is composed as
/// `casa1-conformance:<suite>`.
macro_rules! conformance_evidence {
    ($dll:expr, $export:expr, $suite:expr) => {
        crate::api_coverage::ApiCoverageEvidence {
            dll: $dll,
            export: $export,
            arch: ArchSet::Any,
            windows_version: WindowsVersion::Any,
            level: CoverageLevel::Conformance,
            evidence_id: concat!("casa1-conformance:", $suite),
        }
    };
}

/// Subsystem-scenario evidence constructor.
///
/// `suite` is the named subsystem scenario test; the evidence id is
/// composed as `casa1-scenario:<suite>`.  No scenario rows exist yet —
/// the constructor is the contract for subsystem-scenario evidence.
#[allow(unused_macros)]
macro_rules! scenario_evidence {
    ($dll:expr, $export:expr, $suite:expr) => {
        crate::api_coverage::ApiCoverageEvidence {
            dll: $dll,
            export: $export,
            arch: ArchSet::Any,
            windows_version: WindowsVersion::Any,
            level: CoverageLevel::SubsystemScenario,
            evidence_id: concat!("casa1-scenario:", $suite),
        }
    };
}

/// The static coverage-evidence registry.
///
/// Every row's `evidence_id` is a REAL contract: either the
/// `windows-oracle:<category>` differential vectors that the standalone
/// Windows reference executable (windows_reference/) runs, or a
/// `casa1-conformance:<suite>` / `casa1-scenario:<suite>` row naming a
/// suite that genuinely drives the API and asserts its behavior.  An API
/// may only be promoted to `Differential` with a real Windows capture
/// behind it, and to `Conformance` with a verified suite behind it.
pub static COVERAGE_EVIDENCE: &[ApiCoverageEvidence] = &[
    evidence("kernel32.dll", "CreateFileW", "windows-oracle:file_sharing"),
    evidence(
        "kernel32.dll",
        "VirtualAlloc",
        "windows-oracle:virtual_memory",
    ),
    evidence("kernel32.dll", "TlsAlloc", "windows-oracle:thread_tls"),
    evidence("kernel32.dll", "lstrcmpiW", "windows-oracle:case_fold"),
    evidence("kernel32.dll", "CompareStringW", "windows-oracle:case_fold"),
    evidence(
        "kernel32.dll",
        "GetFullPathNameW",
        "windows-oracle:path_normalize",
    ),
    evidence("kernel32.dll", "LockFileEx", "windows-oracle:file_lock"),
    evidence("kernel32.dll", "UnlockFileEx", "windows-oracle:file_lock"),
    evidence(
        "kernel32.dll",
        "DeleteFileW",
        "windows-oracle:delete_semantics",
    ),
    evidence(
        "kernel32.dll",
        "CreateEventW",
        "windows-oracle:synchronization",
    ),
    evidence(
        "kernel32.dll",
        "CreateMutexW",
        "windows-oracle:synchronization",
    ),
    evidence(
        "kernel32.dll",
        "CreateSemaphoreW",
        "windows-oracle:synchronization",
    ),
    evidence(
        "kernel32.dll",
        "WaitForSingleObject",
        "windows-oracle:synchronization",
    ),
    evidence(
        "kernel32.dll",
        "ReleaseMutex",
        "windows-oracle:synchronization",
    ),
    evidence("kernel32.dll", "RegOpenKeyExW", "windows-oracle:registry"),
    evidence(
        "kernel32.dll",
        "RegQueryValueExW",
        "windows-oracle:registry",
    ),
    evidence("kernel32.dll", "GetModuleHandleW", "windows-oracle:api_set"),
    evidence("kernel32.dll", "GetProcAddress", "windows-oracle:api_set"),
    // The clock domain: GetTickCount64 / GetSystemTimeAsFileTime /
    // QueryPerformanceCounter(+Frequency) deltas across a guest sleep
    // (windows-oracle:time_clock).
    evidence(
        "kernel32.dll",
        "GetTickCount64",
        "windows-oracle:time_clock",
    ),
    evidence(
        "kernel32.dll",
        "GetSystemTimeAsFileTime",
        "windows-oracle:time_clock",
    ),
    evidence(
        "kernel32.dll",
        "QueryPerformanceCounter",
        "windows-oracle:time_clock",
    ),
    evidence(
        "kernel32.dll",
        "QueryPerformanceFrequency",
        "windows-oracle:time_clock",
    ),
    // The environment block: present/missing/length-prefix semantics of
    // GetEnvironmentVariableW and the sorted block entries of
    // GetEnvironmentStringsW (windows-oracle:environment).
    evidence(
        "kernel32.dll",
        "GetEnvironmentVariableW",
        "windows-oracle:environment",
    ),
    evidence(
        "kernel32.dll",
        "GetEnvironmentStringsW",
        "windows-oracle:environment",
    ),
    // File metadata: attribute projections, exact sizes after writes and
    // pointer movement relative to start/end (windows-oracle:file_metadata).
    evidence(
        "kernel32.dll",
        "GetFileAttributesW",
        "windows-oracle:file_metadata",
    ),
    evidence(
        "kernel32.dll",
        "GetFileSizeEx",
        "windows-oracle:file_metadata",
    ),
    evidence(
        "kernel32.dll",
        "SetFilePointerEx",
        "windows-oracle:file_metadata",
    ),
    // Directory enumeration: entry names + attributes over the fixture
    // layout, sorted order, no-match/missing-dir failures and exhaustion
    // (windows-oracle:directory_enumeration).
    evidence(
        "kernel32.dll",
        "FindFirstFileW",
        "windows-oracle:directory_enumeration",
    ),
    evidence(
        "kernel32.dll",
        "FindNextFileW",
        "windows-oracle:directory_enumeration",
    ),
    evidence(
        "kernel32.dll",
        "FindClose",
        "windows-oracle:directory_enumeration",
    ),
    // The version domain: GetVersionExW vs RtlGetVersion consistency and
    // the Windows-10-family shape (windows-oracle:version).
    evidence("kernel32.dll", "GetVersionExW", "windows-oracle:version"),
    // The error domain: SetLastError/GetLastError round-trip plus the
    // ERROR_* ↔ NTSTATUS mapping after real failures
    // (windows-oracle:error_domain).
    evidence(
        "kernel32.dll",
        "SetLastError",
        "windows-oracle:error_domain",
    ),
    evidence(
        "kernel32.dll",
        "GetLastError",
        "windows-oracle:error_domain",
    ),
    // String operators: lstrlenW/lstrcpyW lengths, the case-SENSITIVE
    // lstrcmpW comparison and CharUpperW case mapping
    // (windows-oracle:string_ops).
    evidence("kernel32.dll", "lstrlenW", "windows-oracle:string_ops"),
    evidence("kernel32.dll", "lstrcmpW", "windows-oracle:string_ops"),
    evidence("kernel32.dll", "lstrcpyW", "windows-oracle:string_ops"),
    evidence("kernel32.dll", "CharUpperW", "windows-oracle:string_ops"),
    // Anonymous section mappings: mapping/view size and content visibility
    // after writes (windows-oracle:section_mapping).
    evidence(
        "kernel32.dll",
        "CreateFileMappingW",
        "windows-oracle:section_mapping",
    ),
    evidence(
        "kernel32.dll",
        "MapViewOfFile",
        "windows-oracle:section_mapping",
    ),
    evidence(
        "kernel32.dll",
        "UnmapViewOfFile",
        "windows-oracle:section_mapping",
    ),
    // Process heap: allocation success, size ≥ requested, 16-byte alignment,
    // HEAP_ZERO_MEMORY zeroing and free-invalidation (windows-oracle:heap).
    evidence("kernel32.dll", "HeapAlloc", "windows-oracle:heap"),
    evidence("kernel32.dll", "HeapFree", "windows-oracle:heap"),
    evidence("kernel32.dll", "HeapSize", "windows-oracle:heap"),
    // The d3d12 enum categories are covered by the Windows reference's
    // d3d12_* differential vectors.
    evidence(
        "d3d12.dll",
        "D3D12CreateDevice",
        "windows-oracle:d3d12_device",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateCommandQueue",
        "windows-oracle:d3d12_command_queue",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateCommandAllocator",
        "windows-oracle:d3d12_command_allocator",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateCommandList",
        "windows-oracle:d3d12_command_list",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCheckFeatureSupport",
        "windows-oracle:d3d12_feature_support",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateDescriptorHeap",
        "windows-oracle:d3d12_descriptor_heap",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateRenderTargetView",
        "windows-oracle:d3d12_render_target_view",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateFence",
        "windows-oracle:d3d12_fence",
    ),
    evidence(
        "d3d12.dll",
        "D3D12CommandQueueExecuteCommandLists",
        "windows-oracle:d3d12_command_queue",
    ),
    evidence(
        "d3d12.dll",
        "D3D12CommandQueueSignal",
        "windows-oracle:d3d12_fence",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DescriptorHeapGetCpuHandleForHeapStart",
        "windows-oracle:d3d12_descriptor_heap",
    ),
    evidence(
        "d3d12.dll",
        "D3D12GraphicsCommandListResourceBarrier",
        "windows-oracle:d3d12_resource_barrier",
    ),
    evidence(
        "d3d12.dll",
        "D3D12GraphicsCommandListClearRenderTargetView",
        "windows-oracle:d3d12_render_target_view",
    ),
    evidence(
        "d3d12.dll",
        "D3D12GraphicsCommandListDrawInstanced",
        "windows-oracle:d3d12_draw",
    ),
    evidence(
        "d3d12.dll",
        "D3D12GraphicsCommandListClose",
        "windows-oracle:d3d12_command_list",
    ),
    // ------------------------------------------------------------------
    // Casa1 conformance suites: every row names a suite that genuinely
    // drives the API through the real dispatch path and asserts its
    // observable behavior (verified per row — see the named test).
    // ------------------------------------------------------------------
    conformance_evidence!(
        "kernel32.dll",
        "AcquireSRWLockExclusive",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "AcquireSRWLockShared",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!("kernel32.dll", "Beep", "evidence_core_misc_kernel32_thunks"),
    conformance_evidence!("kernel32.dll", "CallNamedPipeW", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "CloseHandle", "section38"),
    conformance_evidence!(
        "kernel32.dll",
        "CompareFileTime",
        "evidence_core_time_and_filetime_thunks"
    ),
    conformance_evidence!("kernel32.dll", "ConnectNamedPipe", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "ConvertFiberToThread",
        "evidence_core_fiber_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "ConvertThreadToFiber",
        "evidence_core_fiber_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "CopyFileW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!("kernel32.dll", "CreateDirectoryW", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "CreateEventA",
        "evidence_core_event_and_semaphore_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "CreateFiber",
        "evidence_core_fiber_manager_create_switch_delete"
    ),
    conformance_evidence!("kernel32.dll", "CreateFileA", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "CreateIoCompletionPort",
        "evidence_core_iocp_thunks_round_trip"
    ),
    conformance_evidence!("kernel32.dll", "CreateNamedPipeW", "win32_unit"),
    conformance_evidence!("kernel32.dll", "CreateProcessW", "section29"),
    conformance_evidence!("kernel32.dll", "CreateThread", "section49"),
    conformance_evidence!(
        "kernel32.dll",
        "DebugBreak",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "DecodePointer",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!("kernel32.dll", "DeleteCriticalSection", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "DeleteFiber",
        "evidence_core_fiber_thunks_round_trip"
    ),
    conformance_evidence!("kernel32.dll", "DuplicateHandle", "section29"),
    conformance_evidence!(
        "kernel32.dll",
        "EncodePointer",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!("kernel32.dll", "EnterCriticalSection", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "ExitProcess", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "ExitThread", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "FileTimeToSystemTime",
        "evidence_core_time_and_filetime_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "FindFirstFileExW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!("kernel32.dll", "FlushFileBuffers", "section38"),
    conformance_evidence!("kernel32.dll", "Forwarded", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "FreeEnvironmentStringsW",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!("kernel32.dll", "FreeLibrary", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "GetCommandLineA",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetCommandLineW",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetCurrentDirectoryA", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "GetCurrentDirectoryW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetCurrentProcess", "section50"),
    conformance_evidence!("kernel32.dll", "GetCurrentProcessId", "section50"),
    conformance_evidence!("kernel32.dll", "GetCurrentThread", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "GetCurrentThreadId", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "GetDiskFreeSpaceA",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetDiskFreeSpaceExW", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "GetDiskFreeSpaceW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetExitCodeProcess",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetExitCodeThread", "section49"),
    conformance_evidence!(
        "kernel32.dll",
        "GetFileAttributesA",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetFileAttributesExW", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "GetFileInformationByHandle",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetFileSize",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetFileTime",
        "evidence_core_time_and_filetime_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetFileType", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "GetModuleFileNameA", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "GetModuleFileNameW", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "GetModuleHandleA", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "GetModuleHandleExA",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetModuleHandleExW",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetOverlappedResult", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "GetProcessHeap",
        "evidence_core_global_heap_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetProcessHeaps",
        "evidence_core_global_heap_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetQueuedCompletionStatus",
        "evidence_core_iocp_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetQueuedCompletionStatusEx",
        "evidence_core_iocp_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetShortPathNameW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetStartupInfoW",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetStdHandle",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetStringTypeW",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetSystemDirectoryW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetSystemInfo", "section50"),
    conformance_evidence!(
        "kernel32.dll",
        "GetSystemTime",
        "evidence_core_time_and_filetime_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetTempFileNameW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetTempPathW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!("kernel32.dll", "GetTickCount", "section50"),
    conformance_evidence!("kernel32.dll", "GetTimeZoneInformation", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "GetVersion",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GetWindowsDirectoryW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GlobalAlloc",
        "evidence_core_global_heap_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GlobalFree",
        "evidence_core_global_heap_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GlobalLock",
        "evidence_core_global_heap_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "GlobalUnlock",
        "evidence_core_global_heap_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "HeapReAlloc",
        "evidence_core_global_heap_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "InitOnceBeginInitialize",
        "evidence_core_init_once_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "InitOnceComplete",
        "evidence_core_init_once_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "InitOnceExecuteOnce",
        "evidence_core_init_once_thunks_round_trip"
    ),
    conformance_evidence!("kernel32.dll", "InitializeCriticalSection", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "InitializeCriticalSectionAndSpinCount",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "InitializeCriticalSectionEx",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "InitializeSListHead",
        "evidence_core_global_heap_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "InitializeSRWLock",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "IsProcessorFeaturePresent",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "LCMapStringW",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!("kernel32.dll", "LeaveCriticalSection", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "LoadLibraryA",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "LoadLibraryExA",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "LoadLibraryExW",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "LoadLibraryW",
        "evidence_core_loader_and_process_info_thunks"
    ),
    conformance_evidence!("kernel32.dll", "LocalAlloc", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "LocalFree", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "MoveFileExW", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "MulDiv",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "MultiByteToWideChar",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "OpenEventA",
        "evidence_core_event_and_semaphore_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "OpenEventW",
        "evidence_core_event_and_semaphore_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "OpenMutexW",
        "evidence_core_event_and_semaphore_thunks"
    ),
    conformance_evidence!("kernel32.dll", "OpenProcess", "section29"),
    conformance_evidence!(
        "kernel32.dll",
        "OpenSemaphoreW",
        "evidence_core_event_and_semaphore_thunks"
    ),
    conformance_evidence!("kernel32.dll", "OpenThread", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "OutputDebugStringA",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "OutputDebugStringW",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!("kernel32.dll", "PeekNamedPipe", "win32_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "PostQueuedCompletionStatus",
        "evidence_core_iocp_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "ProcessIdToSessionId",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!("kernel32.dll", "ReadFile", "section38"),
    conformance_evidence!(
        "kernel32.dll",
        "ReleaseSRWLockExclusive",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "ReleaseSRWLockShared",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "ReleaseSemaphore",
        "evidence_core_event_and_semaphore_thunks"
    ),
    conformance_evidence!("kernel32.dll", "RemoveDirectoryA", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "RemoveDirectoryW", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "ResetEvent",
        "evidence_core_event_and_semaphore_thunks"
    ),
    conformance_evidence!("kernel32.dll", "ResumeThread", "section49"),
    conformance_evidence!("kernel32.dll", "SetCurrentDirectoryW", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "SetEndOfFile", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "SetEnvironmentVariableW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "SetErrorMode",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!("kernel32.dll", "SetEvent", "section50"),
    conformance_evidence!(
        "kernel32.dll",
        "SetFileAttributesW",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "SetFilePointer",
        "evidence_core_filesystem_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "SetFileTime",
        "evidence_core_time_and_filetime_thunks"
    ),
    conformance_evidence!("kernel32.dll", "SetHandleInformation", "section50"),
    conformance_evidence!(
        "kernel32.dll",
        "SetUnhandledExceptionFilter",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!("kernel32.dll", "Sleep", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "SleepEx", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "SwitchToFiber",
        "evidence_core_fiber_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "SystemTimeToFileTime",
        "evidence_core_time_and_filetime_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "SystemTimeToTzSpecificLocalTime",
        "evidence_core_time_and_filetime_thunks"
    ),
    conformance_evidence!("kernel32.dll", "TerminateProcess", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "TerminateThread", "section49"),
    conformance_evidence!("kernel32.dll", "TlsFree", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "TlsGetValue", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "TlsSetValue", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "TryAcquireSRWLockExclusive",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "TryAcquireSRWLockShared",
        "evidence_core_srw_lock_thunks_round_trip"
    ),
    conformance_evidence!("kernel32.dll", "TryEnterCriticalSection", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "UnhandledExceptionFilter",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!("kernel32.dll", "VerSetConditionMask", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "VerifyVersionInfoW", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "VirtualFree", "section50"),
    conformance_evidence!("kernel32.dll", "VirtualProtect", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "VirtualQuery", "section50"),
    conformance_evidence!("kernel32.dll", "WaitForMultipleObjects", "runtime_unit"),
    conformance_evidence!("kernel32.dll", "WaitForSingleObjectEx", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "WideCharToMultiByte",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "WriteConsoleW",
        "evidence_core_misc_kernel32_thunks"
    ),
    conformance_evidence!("kernel32.dll", "WriteFile", "section38"),
    conformance_evidence!("kernel32.dll", "WritePrivateProfileStringW", "runtime_unit"),
    conformance_evidence!(
        "kernel32.dll",
        "lstrcatW",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "lstrcpyA",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "lstrcpynW",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!(
        "kernel32.dll",
        "lstrlenA",
        "evidence_core_string_and_codepage_thunks"
    ),
    conformance_evidence!("ntdll.dll", "LdrAddRefDll", "section48"),
    conformance_evidence!("ntdll.dll", "LdrGetDllHandle", "section48"),
    conformance_evidence!("ntdll.dll", "LdrGetProcedureAddress", "section48"),
    conformance_evidence!("ntdll.dll", "LdrLoadDll", "section48"),
    conformance_evidence!("ntdll.dll", "LdrLockLoaderLock", "section48"),
    conformance_evidence!("ntdll.dll", "LdrRemoveRefDll", "section48"),
    conformance_evidence!("ntdll.dll", "LdrUnloadDll", "section48"),
    conformance_evidence!("ntdll.dll", "LdrUnlockLoaderLock", "section48"),
    conformance_evidence!("ntdll.dll", "NtAllocateVirtualMemory", "section47"),
    conformance_evidence!("ntdll.dll", "NtClearEvent", "ntdll_sync_unit"),
    conformance_evidence!("ntdll.dll", "NtClose", "section50"),
    conformance_evidence!("ntdll.dll", "NtCreateEvent", "section47"),
    conformance_evidence!("ntdll.dll", "NtCreateFile", "section50"),
    conformance_evidence!("ntdll.dll", "NtCreateKey", "section47"),
    conformance_evidence!("ntdll.dll", "NtCreateSection", "ntdll_loader_unit"),
    conformance_evidence!(
        "ntdll.dll",
        "NtCreateThreadEx",
        "evidence_core_nt_thread_and_process_thunks"
    ),
    conformance_evidence!(
        "ntdll.dll",
        "NtDelayExecution",
        "evidence_core_nt_memory_and_wait_thunks"
    ),
    conformance_evidence!("ntdll.dll", "NtDeleteKey", "ntdll_registry_unit"),
    conformance_evidence!("ntdll.dll", "NtDeleteValueKey", "ntdll_registry_unit"),
    conformance_evidence!(
        "ntdll.dll",
        "NtDeviceIoControlFile",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!("ntdll.dll", "NtDuplicateObject", "section50"),
    conformance_evidence!("ntdll.dll", "NtEnumerateKey", "ntdll_registry_unit"),
    conformance_evidence!(
        "ntdll.dll",
        "NtEnumerateValueKey",
        "evidence_core_nt_enumerate_value_key_lists_values_in_order"
    ),
    conformance_evidence!("ntdll.dll", "NtFreeVirtualMemory", "section50"),
    conformance_evidence!(
        "ntdll.dll",
        "NtGetContextThread",
        "evidence_core_nt_thread_and_process_thunks"
    ),
    conformance_evidence!("ntdll.dll", "NtMapViewOfSection", "section50"),
    conformance_evidence!("ntdll.dll", "NtOpenKey", "ntdll_registry_unit"),
    conformance_evidence!("ntdll.dll", "NtProtectVirtualMemory", "ntdll_memory_unit"),
    conformance_evidence!("ntdll.dll", "NtQueryInformationProcess", "section47"),
    conformance_evidence!("ntdll.dll", "NtQueryInformationThread", "section49"),
    conformance_evidence!("ntdll.dll", "NtQueryKey", "ntdll_registry_unit"),
    conformance_evidence!("ntdll.dll", "NtQueryObject", "section50"),
    conformance_evidence!(
        "ntdll.dll",
        "NtQueryPerformanceCounter",
        "evidence_core_nt_memory_and_wait_thunks"
    ),
    conformance_evidence!("ntdll.dll", "NtQuerySection", "section50"),
    conformance_evidence!("ntdll.dll", "NtQuerySystemInformation", "section50"),
    conformance_evidence!("ntdll.dll", "NtQuerySystemTime", "section50"),
    conformance_evidence!("ntdll.dll", "NtQueryTimerResolution", "section50"),
    conformance_evidence!("ntdll.dll", "NtQueryValueKey", "section47"),
    conformance_evidence!("ntdll.dll", "NtQueryVirtualMemory", "section47"),
    conformance_evidence!(
        "ntdll.dll",
        "NtReadVirtualMemory",
        "evidence_core_nt_memory_and_wait_thunks"
    ),
    conformance_evidence!("ntdll.dll", "NtResumeThread", "section49"),
    conformance_evidence!(
        "ntdll.dll",
        "NtSetContextThread",
        "evidence_core_nt_thread_and_process_thunks"
    ),
    conformance_evidence!("ntdll.dll", "NtSetEvent", "section47"),
    conformance_evidence!("ntdll.dll", "NtSetInformationThread", "section49"),
    conformance_evidence!("ntdll.dll", "NtSetTimerResolution", "section50"),
    conformance_evidence!("ntdll.dll", "NtSetValueKey", "section47"),
    conformance_evidence!("ntdll.dll", "NtSuspendThread", "section49"),
    conformance_evidence!(
        "ntdll.dll",
        "NtTerminateProcess",
        "evidence_core_nt_thread_and_process_thunks"
    ),
    conformance_evidence!(
        "ntdll.dll",
        "NtTerminateThread",
        "evidence_core_nt_thread_and_process_thunks"
    ),
    conformance_evidence!("ntdll.dll", "NtUnmapViewOfSection", "section50"),
    conformance_evidence!(
        "ntdll.dll",
        "NtWaitForMultipleObjects",
        "evidence_core_nt_memory_and_wait_thunks"
    ),
    conformance_evidence!("ntdll.dll", "NtWaitForSingleObject", "section49"),
    conformance_evidence!("ntdll.dll", "NtWriteVirtualMemory", "section47"),
    conformance_evidence!(
        "ntdll.dll",
        "RtlAllocateHeap",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!(
        "ntdll.dll",
        "RtlCaptureContext",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!("ntdll.dll", "RtlCompareUnicodeString", "ntdll_rtl_unit"),
    conformance_evidence!("ntdll.dll", "RtlEqualUnicodeString", "ntdll_rtl_unit"),
    conformance_evidence!(
        "ntdll.dll",
        "RtlFreeAnsiString",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!(
        "ntdll.dll",
        "RtlFreeHeap",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!(
        "ntdll.dll",
        "RtlFreeUnicodeString",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!("ntdll.dll", "RtlGetVersion", "section50"),
    conformance_evidence!(
        "ntdll.dll",
        "RtlInitAnsiString",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!("ntdll.dll", "RtlInitUnicodeString", "ntdll_rtl_unit"),
    conformance_evidence!(
        "ntdll.dll",
        "RtlLookupFunctionEntry",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!("ntdll.dll", "RtlNtStatusToDosError", "section50"),
    conformance_evidence!(
        "ntdll.dll",
        "RtlRaiseException",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
    conformance_evidence!(
        "ntdll.dll",
        "RtlSizeHeap",
        "evidence_core_nt_rtl_and_io_thunks"
    ),
];

/// Look up coverage evidence for a (DLL, export, arch, winver) key,
/// returning the strongest applicable evidence row.
pub fn coverage_evidence_for(
    dll: &str,
    export: &str,
    arch: ArchSet,
    windows_version: WindowsVersion,
) -> Option<&'static ApiCoverageEvidence> {
    let dll_key = dll.to_ascii_lowercase();
    COVERAGE_EVIDENCE.iter().find(|row| {
        row.dll.eq_ignore_ascii_case(&dll_key)
            && row.export.eq_ignore_ascii_case(export)
            && (row.arch == ArchSet::Any || row.arch == arch)
            && (row.windows_version == WindowsVersion::Any
                || row.windows_version == windows_version)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Suites that exist in this repository and genuinely exercise the APIs
    /// they evidence: section test files, the module unit-test suites, and
    /// the named `evidence_core_*` unit tests added with the evidence
    /// registry.  A `casa1-conformance:<suite>` row may only name one of
    /// these (or a section file present under tests/).
    const KNOWN_SUITES: &[&str] = &[
        "section18",
        "section29",
        "section38",
        "section47",
        "section48",
        "section49",
        "section50",
        "runtime_unit",
        "win32_unit",
        "vm_unit",
        "ntdll_memory_unit",
        "ntdll_sync_unit",
        "ntdll_object_unit",
        "ntdll_registry_unit",
        "ntdll_rtl_unit",
        "ntdll_loader_unit",
        "ntdll_ldr_unit",
        "ntdll_system_unit",
        "ntdll_thread_unit",
        "ntdll_process_unit",
        "ntdll_mod_unit",
        "evidence_core_global_heap_thunks_round_trip",
        "evidence_core_string_and_codepage_thunks",
        "evidence_core_time_and_filetime_thunks",
        "evidence_core_fiber_thunks_round_trip",
        "evidence_core_init_once_thunks_round_trip",
        "evidence_core_srw_lock_thunks_round_trip",
        "evidence_core_loader_and_process_info_thunks",
        "evidence_core_event_and_semaphore_thunks",
        "evidence_core_filesystem_thunks",
        "evidence_core_misc_kernel32_thunks",
        "evidence_core_iocp_thunks_round_trip",
        "evidence_core_nt_memory_and_wait_thunks",
        "evidence_core_nt_thread_and_process_thunks",
        "evidence_core_nt_rtl_and_io_thunks",
        "evidence_core_fiber_manager_create_switch_delete",
        "evidence_core_nt_enumerate_value_key_lists_values_in_order",
    ];

    #[test]
    fn evidence_never_inferred_from_rust_tests() {
        // Every row names a REAL contract: a differential oracle category or
        // a named conformance/scenario suite that genuinely exercises the API.
        for row in COVERAGE_EVIDENCE {
            if row.evidence_id.starts_with("windows-oracle:") {
                assert_eq!(row.level, CoverageLevel::Differential);
            } else if let Some(suite) = row.evidence_id.strip_prefix("casa1-conformance:") {
                assert_eq!(row.level, CoverageLevel::Conformance);
                assert!(
                    KNOWN_SUITES.contains(&suite),
                    "conformance evidence must name a known suite, got {suite}"
                );
            } else if let Some(suite) = row.evidence_id.strip_prefix("casa1-scenario:") {
                assert_eq!(row.level, CoverageLevel::SubsystemScenario);
                assert!(
                    KNOWN_SUITES.contains(&suite),
                    "scenario evidence must name a known suite, got {suite}"
                );
            } else {
                panic!(
                    "evidence id {} must be windows-oracle:<cat>, \
                     casa1-conformance:<suite> or casa1-scenario:<suite>",
                    row.evidence_id
                );
            }
        }
    }

    #[test]
    fn conformance_suites_exist_as_test_files() {
        // The section suites referenced by the registry exist in tests/.
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for row in COVERAGE_EVIDENCE {
            let Some(suite) = row.evidence_id.strip_prefix("casa1-conformance:") else {
                continue;
            };
            if KNOWN_SUITES.contains(&suite) {
                continue;
            }
            let path = manifest_dir.join("tests").join(format!("{suite}.rs"));
            assert!(
                path.is_file(),
                "conformance suite {suite} must be a real test file at {}",
                path.display()
            );
        }
    }

    #[test]
    fn registry_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for row in COVERAGE_EVIDENCE {
            assert!(
                seen.insert((row.dll, row.export)),
                "duplicate evidence key {}!{}",
                row.dll,
                row.export
            );
        }
    }

    #[test]
    fn create_file_w_evidence_resolves() {
        let evidence = coverage_evidence_for(
            "KERNEL32.DLL",
            "createfilew",
            ArchSet::Any,
            WindowsVersion::Any,
        )
        .expect("CreateFileW evidence");
        assert_eq!(evidence.evidence_id, "windows-oracle:file_sharing");
        assert_eq!(evidence.level, CoverageLevel::Differential);
    }

    #[test]
    fn unknown_apis_have_no_evidence() {
        assert!(
            coverage_evidence_for(
                "kernel32.dll",
                "NoSuchExport",
                ArchSet::Any,
                WindowsVersion::Any
            )
            .is_none()
        );
    }
}
