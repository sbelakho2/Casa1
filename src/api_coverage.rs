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
    // == evidence-ui-mm ==
    //
    // UI + multimedia families (user32/gdi32/shell32/comctl32/winmm).  The
    // windows-oracle differential categories do not cover these DLLs, so the
    // rows below are backed by the casa1-conformance suites that drive the
    // guest-facing APIs:
    //
    // - casa1-conformance:runtime-dispatch-tests — src/runtime/mod.rs tests:
    //   host-thunk dispatch tests (register_class_w_create_window_roundtrip
    //   _dispatch, message_pump_peek_get_dispatch_send_and_def_window_proc,
    //   paint_dc_monitor_and_timer_dispatch, dialog_item_set_get_dispatch,
    //   gdi_bitmap_draw_dispatch, shell32_pidl_folder_and_drag_dispatch,
    //   comctl32_imagelist_dispatch) plus the pre-existing dispatch tests
    //   (get_class_info_ex_w_writes_extended_class_layout_in_x86_runtime,
    //   set_clipboard_data_reads_exact_block_and_returns_handle,
    //   set_class_long_w_dispatch_returns_previous_value,
    //   get_message_pumps_pending_guest_thread,
    //   resolve_proc_address_and_dispatch_get_message_w_for_quit_on_x86,
    //   resolve_proc_address_and_dispatch_translate_message_for_keydown_on_x86,
    //   wsprintf_a_formats_flags_width_and_specifiers,
    //   pe_runtime_command_line_to_argv_w_returns_wide_argv_array).
    // - casa1-conformance:user32-unit-tests — src/user32.rs tests
    //   (clipboard, class-long, desktop window, thread/process id, timers).
    // - casa1-conformance:winmm-unit-tests — src/winmm.rs tests
    //   (wave out/in round trips, midi in/out, mmio chunking/read/fourcc,
    //   timeGetTime + timer periods, PlaySoundW failure domain).
    // - casa1-conformance:section1-pe-runtime — tests/section1.rs real
    //   Windows PE probes (user32 register/create/peek/dispatch pump,
    //   MessageBoxW + Beep UI-audio probe).
    //
    // APIs whose implementation cannot be driven in-process honestly
    // (DialogBoxParamA/SHBrowseForFolderW need an AppKit modal panel) are
    // deliberately left without a row.
    evidence_conformance(
        "user32.dll",
        "BeginPaint",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "CloseClipboard",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "CreateWindowExW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "DefWindowProcW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "DestroyWindow",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "DispatchMessageW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "EmptyClipboard",
        "casa1-conformance:user32-unit-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "EndDialog",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "EndPaint",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetClassInfoExW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetDC",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetDesktopWindow",
        "casa1-conformance:user32-unit-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetDlgItem",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetDlgItemInt",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetMessageW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetMonitorInfoW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetWindowLongW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetWindowRect",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetWindowTextLengthA",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetWindowTextW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "GetWindowThreadProcessId",
        "casa1-conformance:user32-unit-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "InvalidateRect",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "IsWindowVisible",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "KillTimer",
        "casa1-conformance:user32-unit-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "LoadCursorW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "LoadIconW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "MessageBoxW",
        "casa1-conformance:section1-pe-runtime",
    ),
    evidence_conformance(
        "user32.dll",
        "MonitorFromPoint",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "MonitorFromWindow",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "MoveWindow",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "MsgWaitForMultipleObjects",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "OpenClipboard",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "PeekMessageW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "PostThreadMessageW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "RedrawWindow",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "RegisterClassExW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "RegisterClassW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "ReleaseDC",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "SendMessageW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "SetClassLongW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "SetClipboardData",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "SetDlgItemInt",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "SetDlgItemTextA",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "SetWindowLongW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "SetWindowPos",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "SetWindowTextW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "ShowWindow",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "TranslateMessage",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "UnregisterClassW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "UpdateWindow",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "user32.dll",
        "wsprintfA",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    // gdi32 — the gdi_bitmap_draw_dispatch dispatch test drives the whole
    // drawing surface (memory DC, DIB, blits, objects, fonts, DC state).
    evidence_conformance(
        "gdi32.dll",
        "BitBlt",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "CreateCompatibleDC",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "CreateDIBSection",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "CreateFontIndirectW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "CreateFontW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "CreatePen",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "CreateRectRgn",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "CreateRoundRectRgn",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "CreateSolidBrush",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "DeleteObject",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "FrameRect",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "GetStockObject",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "GetTextExtentPoint32W",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "GetTextMetricsW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "LineTo",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "MoveToEx",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "Rectangle",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "SelectObject",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "SetBkColor",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "SetBkMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "SetTextColor",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "gdi32.dll",
        "StretchBlt",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    // shell32 — the shell32_pidl_folder_and_drag_dispatch dispatch test
    // (folders, PIDL round trips, shell items, execute, drag-and-drop).
    evidence_conformance(
        "shell32.dll",
        "CommandLineToArgvW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "DoDragDrop",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "DragAcceptFiles",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "DragFinish",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "DragQueryFileW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "ILCreateFromPathW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "ILFree",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "RegisterDragDrop",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHBindToParent",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHCreateItemFromIDList",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHCreateItemFromParsingName",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHGetDataFromIDListW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHGetDesktopFolder",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHGetFolderPathW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHGetKnownFolderPath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHGetPathFromIDListW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHGetSpecialFolderPathW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHParseDisplayName",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "SHSimpleIDListFromPath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "shell32.dll",
        "ShellExecuteExW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    // comctl32 — the comctl32_imagelist_dispatch dispatch test.
    evidence_conformance(
        "comctl32.dll",
        "ImageList_Add",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_BeginDrag",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_Create",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_Destroy",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_DragEnter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_DragLeave",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_DragMove",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_Draw",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_DrawEx",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_EndDrag",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_GetImageCount",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_Remove",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_ReplaceIcon",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_SetDragCursorImage",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "ImageList_SetImageCount",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    evidence_conformance(
        "comctl32.dll",
        "InitCommonControlsEx",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    // winmm — the src/winmm.rs subsystem tests (wave in/out round trips,
    // midi in/out, mmio chunking/read/fourcc, timeGetTime + timer periods,
    // PlaySoundW failure domain).
    evidence_conformance(
        "winmm.dll",
        "PlaySoundW",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiInClose",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiInOpen",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiInReset",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiInStart",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiInStop",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiOutClose",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiOutGetDevCapsW",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiOutGetNumDevs",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiOutLongMsg",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiOutOpen",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiOutReset",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "midiOutShortMsg",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "mmioAscend",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "mmioClose",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "mmioCreateChunk",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "mmioDescend",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "mmioOpenW",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "mmioRead",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "mmioStringToFOURCCW",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "mmioWrite",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "timeBeginPeriod",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "timeEndPeriod",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "timeGetTime",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInAddBuffer",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInClose",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInGetDevCapsW",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInGetNumDevs",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInOpen",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInPrepareHeader",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInStart",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInStop",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveInUnprepareHeader",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutClose",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutGetDevCapsW",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutGetNumDevs",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutGetVolume",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutOpen",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutPrepareHeader",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutReset",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutSetVolume",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutUnprepareHeader",
        "casa1-conformance:winmm-unit-tests",
    ),
    evidence_conformance(
        "winmm.dll",
        "waveOutWrite",
        "casa1-conformance:winmm-unit-tests",
    ),
    // == evidence-crt-net ==
    // CRT + network/crypto families (msvcrt, ucrtbase, ws2_32, winhttp,
    // advapi32, bcrypt, crypt32).  Rows below this marker are owned by the
    // evidence-crt-net pass; they may name either a `windows-oracle:<category>`
    // differential contract or a `casa1-conformance:<suite>` row backed by a
    // real suite:
    //   - runtime-unit-tests  -> src/runtime/mod.rs `crt_*`/guest-thunk tests
    //   - network-unit-tests  -> src/network.rs NetworkStack tests
    //   - winhttp-unit-tests  -> src/winhttp.rs WinHttpStack tests
    //   - section11           -> tests/section11.rs (winsock/http/crypto)
    //   - section34           -> tests/section34_phase3.rs (websocket)
    //   - section37           -> tests/section37_integration.rs
    //   - section50           -> tests/section50_win32_nt_consistency.rs
    // The named suite genuinely drives the API (the export's thunk or the
    // backend it dispatches into) and asserts observable behavior.

    // -- msvcrt.dll / ucrtbase.dll --
    // The CRT surface is the guest printf/string/memory/conversion engine in
    // runtime/mod.rs, proven by the crt_* guest-thunk unit tests; the printf
    // engine additionally matches the reference via windows-oracle:crt_printf.
    evidence(
        "msvcrt.dll",
        "__stdio_common_vfprintf",
        "windows-oracle:crt_printf",
    ),
    evidence(
        "ucrtbase.dll",
        "__stdio_common_vfprintf",
        "windows-oracle:crt_printf",
    ),
    conformance(
        "msvcrt.dll",
        "_errno",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_set_invalid_parameter_handler",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_beginthreadex",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_endthreadex",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance("msvcrt.dll", "atof", "casa1-conformance:runtime-unit-tests"),
    conformance(
        "msvcrt.dll",
        "qsort",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "fopen",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "fwrite",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "fread",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "fclose",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "fgets",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "malloc",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "memcmp",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "strcmp",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "strncmp",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "abort",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance("msvcrt.dll", "abs", "casa1-conformance:runtime-unit-tests"),
    conformance("msvcrt.dll", "atoi", "casa1-conformance:runtime-unit-tests"),
    conformance("msvcrt.dll", "atol", "casa1-conformance:runtime-unit-tests"),
    conformance(
        "msvcrt.dll",
        "bsearch",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "calloc",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance("msvcrt.dll", "exit", "casa1-conformance:runtime-unit-tests"),
    conformance(
        "msvcrt.dll",
        "fflush",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance("msvcrt.dll", "free", "casa1-conformance:runtime-unit-tests"),
    conformance("msvcrt.dll", "labs", "casa1-conformance:runtime-unit-tests"),
    conformance(
        "msvcrt.dll",
        "memcpy",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "memmove",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "memset",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance("msvcrt.dll", "rand", "casa1-conformance:runtime-unit-tests"),
    conformance(
        "msvcrt.dll",
        "realloc",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "setlocale",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "signal",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "srand",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "strcat",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "strcpy",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "strlen",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance("msvcrt.dll", "time", "casa1-conformance:runtime-unit-tests"),
    conformance(
        "msvcrt.dll",
        "__C_specific_handler",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "__acrt_iob_func",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "__p___argc",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "__p___argv",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "__p__commode",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "__p__environ",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "__p__fmode",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "__setusermatherr",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_cexit",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_configure_narrow_argv",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_crt_atexit",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_exit",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_initialize_narrow_environment",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_initterm",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_initterm_e",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_set_app_type",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "msvcrt.dll",
        "_set_new_mode",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_set_invalid_parameter_handler",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "abort",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "calloc",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "exit",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "free",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "fwrite",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "malloc",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "signal",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "strlen",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "strncmp",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "__C_specific_handler",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "__acrt_iob_func",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "__p___argc",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "__p___argv",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "__p__commode",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "__p__environ",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "__p__fmode",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "__setusermatherr",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_cexit",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_configure_narrow_argv",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_crt_atexit",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_exit",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_initialize_narrow_environment",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_initterm",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_initterm_e",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_set_app_type",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ucrtbase.dll",
        "_set_new_mode",
        "casa1-conformance:runtime-unit-tests",
    ),
    // -- ws2_32.dll --
    // The socket semantics live in the network stack (src/network.rs) that
    // the winsock thunks dispatch into; section11 drives the stack against
    // the Windows error-domain oracles, and the remaining thunks are covered
    // by runtime guest-thunk unit tests.
    conformance("ws2_32.dll", "socket", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "bind", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "connect", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "recv", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "send", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "select", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "shutdown", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "closesocket", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "ioctlsocket", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "getaddrinfo", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "freeaddrinfo", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "WSAStartup", "casa1-conformance:section11"),
    conformance("ws2_32.dll", "WSACleanup", "casa1-conformance:section11"),
    conformance(
        "ws2_32.dll",
        "WSAGetLastError",
        "casa1-conformance:section11",
    ),
    conformance(
        "ws2_32.dll",
        "WSASetLastError",
        "casa1-conformance:section11",
    ),
    conformance(
        "ws2_32.dll",
        "getsockname",
        "casa1-conformance:network-unit-tests",
    ),
    conformance(
        "ws2_32.dll",
        "setsockopt",
        "casa1-conformance:network-unit-tests",
    ),
    conformance(
        "ws2_32.dll",
        "htonl",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ws2_32.dll",
        "htons",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ws2_32.dll",
        "ntohl",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ws2_32.dll",
        "ntohs",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ws2_32.dll",
        "WSASocketA",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ws2_32.dll",
        "WSAIoctl",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "ws2_32.dll",
        "__WSAFDIsSet",
        "casa1-conformance:runtime-unit-tests",
    ),
    // -- winhttp.dll --
    // The WinHttpStack (src/winhttp.rs) backs the WinHttp thunks; section11
    // replays the request lifecycle against the route/cookie oracles,
    // section34 covers the WebSocket upgrade surface, and the remaining
    // thunks are covered by runtime guest-thunk unit tests.
    conformance("winhttp.dll", "WinHttpOpen", "casa1-conformance:section11"),
    conformance(
        "winhttp.dll",
        "WinHttpCloseHandle",
        "casa1-conformance:section11",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpConnect",
        "casa1-conformance:section11",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpOpenRequest",
        "casa1-conformance:section11",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpSendRequest",
        "casa1-conformance:section11",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpReceiveResponse",
        "casa1-conformance:section11",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpQueryHeaders",
        "casa1-conformance:section11",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpReadData",
        "casa1-conformance:section11",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpQueryOption",
        "casa1-conformance:winhttp-unit-tests",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpSetOption",
        "casa1-conformance:winhttp-unit-tests",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpWebSocketCompleteUpgrade",
        "casa1-conformance:section34",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpWebSocketSend",
        "casa1-conformance:section34",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpWebSocketReceive",
        "casa1-conformance:section34",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpWebSocketClose",
        "casa1-conformance:section34",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpWebSocketQueryCloseStatus",
        "casa1-conformance:section34",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpAddRequestHeaders",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpWriteData",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpSetCredentials",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpGetProxyForUrl",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "winhttp.dll",
        "WinHttpGetIEProxyConfigForCurrentUser",
        "casa1-conformance:runtime-unit-tests",
    ),
    // -- advapi32.dll --
    // The Reg* family is the registry domain shared with the Windows
    // reference (windows-oracle:registry); the identity/security/eventlog
    // thunks are covered by runtime guest-thunk unit tests.
    evidence("advapi32.dll", "RegOpenKeyExW", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegOpenKeyExA", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegOpenKeyA", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegCreateKeyExW", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegCreateKeyExA", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegCloseKey", "windows-oracle:registry"),
    evidence(
        "advapi32.dll",
        "RegQueryValueExW",
        "windows-oracle:registry",
    ),
    evidence(
        "advapi32.dll",
        "RegQueryValueExA",
        "windows-oracle:registry",
    ),
    evidence("advapi32.dll", "RegSetValueExW", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegSetValueExA", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegDeleteValueW", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegDeleteKeyW", "windows-oracle:registry"),
    evidence("advapi32.dll", "RegEnumKeyExW", "windows-oracle:registry"),
    conformance(
        "advapi32.dll",
        "GetUserNameW",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "advapi32.dll",
        "InitializeSecurityDescriptor",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "advapi32.dll",
        "SetSecurityDescriptorDacl",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "advapi32.dll",
        "ReportEventW",
        "casa1-conformance:runtime-unit-tests",
    ),
    // -- bcrypt.dll --
    // Full guest-thunk round trips (hash/RNG/AES-CBC/keypair/properties/
    // import/derive) in the runtime unit suite; the crypto backend is the
    // BCryptContext the real Windows layer and the guest thunks share.
    conformance(
        "bcrypt.dll",
        "BCryptOpenAlgorithmProvider",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptCloseAlgorithmProvider",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptCreateHash",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptHashData",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptHash",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptGenRandom",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptGenerateSymmetricKey",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptEncrypt",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptDecrypt",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptGenerateKeyPair",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptFinalizeKeyPair",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptDestroyKey",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptDestroyHash",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptGetProperty",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptSetProperty",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptImportKey",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "bcrypt.dll",
        "BCryptDeriveKey",
        "casa1-conformance:runtime-unit-tests",
    ),
    // -- crypt32.dll --
    // Certificate-store lifecycle (open/add/enum/find/delete/close), PFX
    // blob detection/import and the name/key-usage/chain-policy thunks are
    // driven through the guest thunks in the runtime unit suite.
    conformance(
        "crypt32.dll",
        "CertOpenStore",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertCloseStore",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertAddCertificateContextToStore",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertEnumCertificatesInStore",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertFindCertificateInStore",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertDeleteCertificateFromStore",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertDuplicateCertificateContext",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertFreeCertificateContext",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertFreeCertificateChain",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertGetNameStringW",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertGetIntendedKeyUsage",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertOpenSystemStoreW",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertVerifyCertificateChainPolicy",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CryptAcquireCertificatePrivateKey",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "CertFindExtension",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "PFXImportCertStore",
        "casa1-conformance:runtime-unit-tests",
    ),
    conformance(
        "crypt32.dll",
        "PFXIsPFXBlob",
        "casa1-conformance:runtime-unit-tests",
    ),
    // == evidence-gfx-tail ==
    //
    // Remaining implemented families (gdiplus/libcef/oleaut32/wininet/
    // steam_api/steam_api64/usp10/dwmapi/winspool.drv/ole32/version/psapi).
    // The rows below are backed by suites that drive the guest-facing API
    // and assert observable behavior:
    //
    // - casa1-conformance:runtime-dispatch-tests — src/runtime/mod.rs
    //   HostThunk dispatch tests (guest-register/stack args, guest-memory
    //   in/out buffers, observable state): the gdiplus_*_dispatch tests
    //   (startup/shutdown, graphics+brushes+pens, bitmap pixels+lockbits,
    //   bitmap factories+queries, path build, matrix, world transform+clip,
    //   save/restore/containers, draw primitives, fill primitives, draw
    //   image, text+font, pen+quality state, image attributes+stub ops),
    //   the cef_*_thunks_dispatch tests (string conversions, URL parts,
    //   cross-origin whitelist, cookie manager + misc), the
    //   oleaut32_*_dispatch tests (BSTR/Variant/SafeArray round trips),
    //   ole32_ole_initialize_uninitialize_dispatch,
    //   ole32_co_create_instance_ex_dispatch_fills_multi_qi,
    //   wininet_http_roundtrip_dispatch (loopback HTTP server),
    //   wininet_url_and_option_dispatch, wininet_ftp_failure_domain_dispatch,
    //   steam_api_*_dispatch, steam_internal_*_dispatch, usp10_*_dispatch,
    //   dwm_*_dispatch, winspool_*_dispatch, version_dll_query_roundtrip_dispatch,
    //   psapi_module_file_name_and_information_dispatch.
    // - casa1-conformance:cef-unit-tests — src/cef_bridge.rs CefBridge
    //   tests that drive the bridge methods the thunk arms forward into
    //   (cef_initialize_and_shutdown, cef_create_browser_and_query_frames,
    //   cef_navigation, cef_javascript_execution, cef_browser_lifecycle,
    //   cef_error_handling, steam_web_helper_tick).
    // - casa1-conformance:section28-com — tests/section28_com.rs COM/OLE
    //   host-function tests (t28c_02 CoInitializeEx/CoUninitialize,
    //   t28c_05/05b BSTR, t28c_06/06b-06g VariantInit/Copy/Clear,
    //   t28c_07/07b/07c SafeArray, t28c_09 class-object register/revoke,
    //   t28c_11 CoGetClassObject, t28c_13 CoCreateGuid).
    //
    conformance(
        "gdiplus.dll",
        "GdipAddPathArc",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipAddPathBezier",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipAddPathEllipse",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipAddPathLine",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipAddPathRectangle",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipBeginContainer",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipBitmapGetPixel",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipBitmapLockBits",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipBitmapSetPixel",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipBitmapUnlockBits",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCloneImage",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipClosePathFigure",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateBitmapFromFile",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateBitmapFromGdiDib",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateBitmapFromGraphics",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateBitmapFromHBITMAP",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateBitmapFromScan0",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateBitmapFromStream",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateFont",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateFontFamilyFromName",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateFromHDC",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateHBITMAPFromBitmap",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateHICONFromBitmap",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateImageAttributes",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateImageFromFile",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateLineBrush",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateMatrix",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreatePath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreatePen1",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreatePen2",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateSolidFill",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipCreateTextureBrush",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDeleteBrush",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDeleteFont",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDeleteFontFamily",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDeleteGraphics",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDeleteMatrix",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDeletePath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDeletePen",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDisposeImage",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDisposeImageAttributes",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawArc",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawClosedCurve",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawCurve",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawEllipse",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawImage",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawImageRect",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawImageRectRect",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawLine",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawLines",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawPath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawPie",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawPolygon",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawRectangle",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipDrawString",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipEndContainer",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipFillEllipse",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipFillPath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipFillPie",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipFillPolygon",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipFillRectangle",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipFillRegion",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetClip",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetClipBounds",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetCompositingMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetCompositingQuality",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetFontHeight",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetImageHeight",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetImagePixelFormat",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetImageRawFormat",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetImageType",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetImageWidth",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetInterpolationMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetMatrixElements",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetPenColor",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetPenDashStyle",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetPenWidth",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetPixelOffsetMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetSmoothingMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipGetWorldTransform",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipImageForceValidation",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipInvertMatrix",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipMeasureCharacterRanges",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipMeasureString",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipMultiplyMatrix",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipResetClip",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipResetWorldTransform",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipRestoreGraphics",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipRotateMatrix",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSaveGraphics",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSaveImageToFile",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSaveImageToStream",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipScaleMatrix",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetClipPath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetClipRect",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetClipRegion",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetCompositingMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetCompositingQuality",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetImageAttributesColorKeys",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetImageAttributesColorMatrix",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetInterpolationMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetMatrixElements",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetPathFillMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetPenColor",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetPenDashStyle",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetPenEndCap",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetPenLineJoin",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetPenStartCap",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetPenWidth",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetPixelOffsetMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetSmoothingMode",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetTextRenderingHint",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipSetWorldTransform",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipStartPathFigure",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdipTranslateMatrix",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdiplusShutdown",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdiplus.dll",
        "GdiplusStartup",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_initialize",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_shutdown",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_host_create_browser",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_host_create_browser_sync",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_get_host",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_get_main_frame",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_is_valid",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_go_back",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_go_forward",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_reload",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_reload_ignore_cache",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_frame_load_url",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_frame_execute_java_script",
        "casa1-conformance:cef-unit-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_add_cross_origin_whitelist_entry",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_remove_cross_origin_whitelist_entry",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_clear_cross_origin_whitelist",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_cookie_manager_delete_cookies",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_cookie_manager_flush_store",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_cookie_manager_get_global",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_cookie_manager_set_cookie",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_cookie_manager_set_supported_schemes",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_cookie_manager_visit_all_cookies",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_create_url",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_do_message_loop_work",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_frame_load_string",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_get_minimal_libcef_version",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_parse_url",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_quit_message_loop",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_register_extension",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_run_message_loop",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_settings_create",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_browser_stop_load",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_string_utf16_to_utf8",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_string_utf8_to_utf16",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_string_utf8_to_wide",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_string_wide_to_utf8",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "libcef.dll",
        "cef_window_info_create",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "oleaut32.dll",
        "VariantClear",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayAccessData",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayCreate",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayCreateVector",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayDestroy",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayGetElement",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayGetLBound",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayGetUBound",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayPutElement",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SafeArrayUnaccessData",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SysAllocString",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SysAllocStringLen",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SysFreeString",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SysStringLen",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "VariantCopy",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "VariantInit",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "oleaut32.dll",
        "SysReAllocString",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "oleaut32.dll",
        "VariantChangeType",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "ole32.dll",
        "CoInitializeEx",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "ole32.dll",
        "CoUninitialize",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "ole32.dll",
        "CoCreateGuid",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "ole32.dll",
        "CoGetClassObject",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "ole32.dll",
        "CoRegisterClassObject",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "ole32.dll",
        "CoRevokeClassObject",
        "casa1-conformance:section28-com",
    ),
    conformance(
        "ole32.dll",
        "OleInitialize",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "ole32.dll",
        "OleUninitialize",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "ole32.dll",
        "CoCreateInstanceEx",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "HttpOpenRequestW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "HttpSendRequestW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetConnectW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetOpenW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetReadFile",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "FtpFindFirstFileW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "FtpGetFileW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "FtpOpenFileW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "FtpPutFileW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetCanonicalizeUrlW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetCloseHandle",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetCrackUrlW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetGetConnectedState",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetSetOptionW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "wininet.dll",
        "InternetSetStatusCallback",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_GetSteamInstallPath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_Init",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_RegisterCallResult",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_RegisterCallback",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_RestartAppIfNecessary",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_RunCallbacks",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_SetMiniDumpComment",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_Shutdown",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_UnregisterCallResult",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_UnregisterCallback",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamAPI_WriteMiniDump",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamInternal_ContextInit",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamInternal_CreateInterface",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamInternal_FindOrCreateGameInterface",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api.dll",
        "SteamInternal_FindOrCreateUserInterface",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_GetSteamInstallPath",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_Init",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_RegisterCallResult",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_RegisterCallback",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_RestartAppIfNecessary",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_RunCallbacks",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_SetMiniDumpComment",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_Shutdown",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_UnregisterCallResult",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_UnregisterCallback",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamAPI_WriteMiniDump",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamInternal_ContextInit",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamInternal_CreateInterface",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamInternal_FindOrCreateGameInterface",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "steam_api64.dll",
        "SteamInternal_FindOrCreateUserInterface",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptApplyDigitSubstitution",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptBreak",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptCacheGetHeight",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptFreeCache",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptGetProperties",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptItemize",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptLayout",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptPlace",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptRecordDigitSubstitution",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptShape",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptStringAnalyse",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptStringFree",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptStringOut",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "usp10.dll",
        "ScriptString_pSize",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmEnableBlurBehindWindow",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmEnableComposition",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmExtendFrameIntoClientArea",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmFlush",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmGetColorizationColor",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmGetWindowAttribute",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmIsCompositionEnabled",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmRegisterThumbnail",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmSetIconicLivePreviewBitmap",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmSetIconicThumbnail",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmSetWindowAttribute",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmUnregisterThumbnail",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwmapi.dll",
        "DwmUpdateThumbnailProperties",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "AddPrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "ClosePrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "DeletePrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "EndDocPrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "EndPagePrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "EnumPrinters",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "GetPrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "OpenPrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "ReadPrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "SetPrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "StartDocPrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "StartPagePrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "winspool.drv",
        "WritePrinter",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "version.dll",
        "VerQueryValueW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "version.dll",
        "GetFileVersionInfoSizeW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "version.dll",
        "GetFileVersionInfoW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "psapi.dll",
        "GetModuleFileNameExW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "psapi.dll",
        "GetModuleInformation",
        "casa1-conformance:runtime-dispatch-tests",
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
    // == evidence-tail-final ==
    //
    // The FINAL implemented-without-evidence surface:
    //
    // 1. The evidence-core rows lost to the evidence-ui-mm conflict
    //    resolution (kernel32/ntdll exports backed by the reconstructed
    //    evidence_core_* unit tests in runtime/mod.rs, threads.rs and
    //    ntdll/registry.rs, the runtime_unit / win32_unit test modules,
    //    and the section29/38/49/50 section suites).
    // 2. The tail families named below, each backed by the suite that
    //    genuinely drives the export and asserts observable behavior:
    //    - kernel32/kernelbase tail (GetCPInfo, GetDriveTypeW,
    //      GetProcessAffinityMask, GlobalMemoryStatusEx,
    //      InterlockedPushEntrySList, IsValidCodePage, SetThreadPriority;
    //      kernelbase routes through the kernel32 thunk tests):
    //      runtime-dispatch-tests.
    //    - xinput1_3/xinput1_4 (all exports): xinput_exports_dispatch_roundtrip
    //      (runtime-dispatch-tests) plus the real_win32 xinput state
    //      round-trip / battery / keystroke / enable unit tests.
    //    - d2d1 factory + matrix helpers: d2d-unit-tests (src/d2d.rs).
    //    - urlmon bind ctx / moniker / status callback:
    //      urlmon_bind_ctx_moniker_and_status_callback_dispatch
    //      (runtime-dispatch-tests).
    //    - user32 EnumWindows/EnumChildWindows/MapWindowPoints/SetTimer,
    //      gdi32 CreateICW/DeleteDC, advapi32 event-source, d3d9 factory
    //      creation, dinput8 creation, dxgi factory2, wintrust:
    //      runtime-dispatch-tests.
    //    - d3d11 device creation + xaudio2 engine: section1-pe-runtime
    //      (real Windows PE probes).
    //    - dwrite factory: dwrite-unit-tests (src/dwrite.rs).
    //    - webview2 environment: webview2-unit-tests (src/webview2.rs).
    //
    // DialogBoxParamA and SHBrowseForFolderW remain deliberately
    // unevidenced (they need an AppKit modal panel — documented above).
    conformance(
        "kernel32.dll",
        "GetCPInfo",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernel32.dll",
        "GetDriveTypeW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernel32.dll",
        "GetProcessAffinityMask",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernel32.dll",
        "GlobalMemoryStatusEx",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernel32.dll",
        "InterlockedPushEntrySList",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernel32.dll",
        "IsValidCodePage",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernel32.dll",
        "SetThreadPriority",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernelbase.dll",
        "GetFileAttributesExW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernelbase.dll",
        "GetFileInformationByHandle",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernelbase.dll",
        "GetSystemTimeAsFileTime",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernelbase.dll",
        "GetTickCount",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernelbase.dll",
        "GetTimeZoneInformation",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernelbase.dll",
        "Sleep",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "kernelbase.dll",
        "VerifyVersionInfoW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_3.dll",
        "XInputEnable",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_3.dll",
        "XInputGetBatteryInformation",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_3.dll",
        "XInputGetCapabilities",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_3.dll",
        "XInputGetDSoundAudioDeviceGuids",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_3.dll",
        "XInputGetKeystroke",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_3.dll",
        "XInputGetState",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_3.dll",
        "XInputSetState",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_4.dll",
        "XInputEnable",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_4.dll",
        "XInputGetBatteryInformation",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_4.dll",
        "XInputGetCapabilities",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_4.dll",
        "XInputGetKeystroke",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_4.dll",
        "XInputGetState",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xinput1_4.dll",
        "XInputSetState",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "user32.dll",
        "EnumChildWindows",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "user32.dll",
        "EnumWindows",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "user32.dll",
        "MapWindowPoints",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "user32.dll",
        "SetTimer",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "d2d1.dll",
        "D2D1CreateFactory",
        "casa1-conformance:d2d-unit-tests",
    ),
    conformance(
        "d2d1.dll",
        "D2D1InvertMatrix",
        "casa1-conformance:d2d-unit-tests",
    ),
    conformance(
        "d2d1.dll",
        "D2D1IsMatrixInvertible",
        "casa1-conformance:d2d-unit-tests",
    ),
    conformance(
        "d2d1.dll",
        "D2D1MakeRotateMatrix",
        "casa1-conformance:d2d-unit-tests",
    ),
    conformance(
        "d2d1.dll",
        "D2D1MakeSkewMatrix",
        "casa1-conformance:d2d-unit-tests",
    ),
    conformance(
        "urlmon.dll",
        "CreateAsyncBindCtx",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "urlmon.dll",
        "CreateURLMoniker",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "urlmon.dll",
        "RegisterBindStatusCallback",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdi32.dll",
        "CreateICW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "gdi32.dll",
        "DeleteDC",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "advapi32.dll",
        "DeregisterEventSource",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "advapi32.dll",
        "RegisterEventSourceW",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "d3d11.dll",
        "D3D11CreateDevice",
        "casa1-conformance:section1-pe-runtime",
    ),
    conformance(
        "d3d11.dll",
        "D3D11CreateDeviceAndSwapChain",
        "casa1-conformance:section1-pe-runtime",
    ),
    conformance(
        "d3d9.dll",
        "Direct3DCreate9",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "d3d9.dll",
        "Direct3DCreate9Ex",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dxgi.dll",
        "CreateDXGIFactory1",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dxgi.dll",
        "CreateDXGIFactory2",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dinput8.dll",
        "DirectInput8Create",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "dwrite.dll",
        "DWriteCreateFactory",
        "casa1-conformance:dwrite-unit-tests",
    ),
    conformance(
        "webview2.dll",
        "CreateWebView2Environment",
        "casa1-conformance:webview2-unit-tests",
    ),
    conformance(
        "wintrust.dll",
        "WinVerifyTrust",
        "casa1-conformance:runtime-dispatch-tests",
    ),
    conformance(
        "xaudio2_9.dll",
        "XAudio2Create",
        "casa1-conformance:section1-pe-runtime",
    ),
    conformance(
        "kernel32.dll",
        "DisableThreadLibraryCalls",
        "casa1-conformance:evidence_core_kernel32_disable_thread_library_calls_thunk",
    ),
    conformance(
        "kernel32.dll",
        "ExpandEnvironmentStringsW",
        "casa1-conformance:evidence_core_kernel32_environment_expand_thunks",
    ),
    conformance(
        "kernel32.dll",
        "GetFileInformationByHandleEx",
        "casa1-conformance:evidence_core_kernel32_file_info_version_move_search_thunks",
    ),
    conformance(
        "kernel32.dll",
        "GetPrivateProfileStringW",
        "casa1-conformance:evidence_core_kernel32_ini_thunks",
    ),
    conformance(
        "kernel32.dll",
        "GetVersionExA",
        "casa1-conformance:evidence_core_kernel32_file_info_version_move_search_thunks",
    ),
    conformance(
        "kernel32.dll",
        "InterlockedCompareExchange",
        "casa1-conformance:evidence_core_kernel32_interlocked_thunks",
    ),
    conformance(
        "kernel32.dll",
        "InterlockedDecrement",
        "casa1-conformance:evidence_core_kernel32_interlocked_thunks",
    ),
    conformance(
        "kernel32.dll",
        "InterlockedExchange",
        "casa1-conformance:evidence_core_kernel32_interlocked_thunks",
    ),
    conformance(
        "kernel32.dll",
        "InterlockedExchangeAdd",
        "casa1-conformance:evidence_core_kernel32_interlocked_thunks",
    ),
    conformance(
        "kernel32.dll",
        "InterlockedIncrement",
        "casa1-conformance:evidence_core_kernel32_interlocked_thunks",
    ),
    conformance(
        "kernel32.dll",
        "MoveFileW",
        "casa1-conformance:evidence_core_kernel32_file_info_version_move_search_thunks",
    ),
    conformance(
        "kernel32.dll",
        "SearchPathW",
        "casa1-conformance:evidence_core_kernel32_file_info_version_move_search_thunks",
    ),
    conformance(
        "kernel32.dll",
        "lstrcmpiA",
        "casa1-conformance:evidence_core_kernel32_file_info_version_move_search_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathAppendW",
        "casa1-conformance:evidence_shlwapi_path_append_combine_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathCombineW",
        "casa1-conformance:evidence_shlwapi_path_append_combine_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathFindExtensionW",
        "casa1-conformance:evidence_shlwapi_path_find_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathFindFileNameW",
        "casa1-conformance:evidence_shlwapi_path_find_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathStripPathW",
        "casa1-conformance:evidence_shlwapi_path_find_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathRemoveExtensionW",
        "casa1-conformance:evidence_shlwapi_path_find_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathRemoveFileSpecW",
        "casa1-conformance:evidence_shlwapi_path_remove_spec_and_root_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathSkipRootW",
        "casa1-conformance:evidence_shlwapi_path_remove_spec_and_root_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathIsRootW",
        "casa1-conformance:evidence_shlwapi_path_remove_spec_and_root_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathIsRelativeW",
        "casa1-conformance:evidence_shlwapi_path_remove_spec_and_root_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathGetDriveNumberW",
        "casa1-conformance:evidence_shlwapi_path_remove_spec_and_root_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathAddBackslashW",
        "casa1-conformance:evidence_shlwapi_path_remove_spec_and_root_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathRemoveBackslashW",
        "casa1-conformance:evidence_shlwapi_path_remove_spec_and_root_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathRemoveBlanksW",
        "casa1-conformance:evidence_shlwapi_path_remove_spec_and_root_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathCanonicalizeW",
        "casa1-conformance:evidence_shlwapi_path_canonicalize_and_match_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathMatchSpecW",
        "casa1-conformance:evidence_shlwapi_path_canonicalize_and_match_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrChrW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrChrIW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrRChrW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrStrW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrStrIW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrCmpIW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrCmpW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrCmpNIW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrCmpNW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrCpyNW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrCpyW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrCatW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrToIntW",
        "casa1-conformance:evidence_shlwapi_string_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "ChrCmpIW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "IntlStrEqWorkerW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "IsCharAlphaW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "IsCharAlphaNumericW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "IsCharLowerW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "IsCharUpperW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "IsCharSpaceW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "ParseURLW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "StrFromTimeIntervalW",
        "casa1-conformance:evidence_shlwapi_char_class_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathFileExistsW",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "PathIsDirectoryW",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "SHRegGetValueW",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "SHRegSetValueW",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "SHDeleteKeyW",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "SHDeleteEmptyKeyW",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "SHSearchMapInt",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "GetMenuContextHelpId",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "SetMenuContextHelpId",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "UrlCanonicalizeW",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    conformance(
        "shlwapi.dll",
        "UrlCombineW",
        "casa1-conformance:evidence_shlwapi_fs_registry_and_url_thunks",
    ),
    // ntdll.dll tail: the implemented NT surface lost to the evidence-ui-mm
    // conflict resolution (section47/48/49/50 suites, the evidence_core_*
    // round-trip tests, and the ntdll_*_unit module tests).
];

/// Evidence-ui-mm: conformance-backed rows (additive; the differential
/// `evidence()` helper above is untouched).
const fn evidence_conformance(
    dll: &'static str,
    export: &'static str,
    evidence_id: &'static str,
) -> ApiCoverageEvidence {
    ApiCoverageEvidence {
        dll,
        export,
        arch: ArchSet::Any,
        windows_version: WindowsVersion::Any,
        level: CoverageLevel::Conformance,
        evidence_id,
    }
}

/// Convenience constructor for `casa1-conformance:<suite>` rows (any arch,
/// any Windows version) owned by the evidence-crt-net pass.
const fn conformance(
    dll: &'static str,
    export: &'static str,
    evidence_id: &'static str,
) -> ApiCoverageEvidence {
    ApiCoverageEvidence {
        dll,
        export,
        arch: ArchSet::Any,
        windows_version: WindowsVersion::Any,
        level: CoverageLevel::Conformance,
        evidence_id,
    }
}

/// Look up oracle-backed coverage evidence for a (DLL, export, arch, winver)
/// key, returning the strongest applicable evidence row.
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
        "evidence_core_kernel32_disable_thread_library_calls_thunk",
        "evidence_core_kernel32_environment_expand_thunks",
        "evidence_core_kernel32_file_info_version_move_search_thunks",
        "evidence_core_kernel32_ini_thunks",
        "evidence_core_kernel32_interlocked_thunks",
        "evidence_shlwapi_char_class_and_url_thunks",
        "evidence_shlwapi_fs_registry_and_url_thunks",
        "evidence_shlwapi_path_append_combine_thunks",
        "evidence_shlwapi_path_canonicalize_and_match_thunks",
        "evidence_shlwapi_path_find_thunks",
        "evidence_shlwapi_path_remove_spec_and_root_thunks",
        "evidence_shlwapi_string_thunks",
        "cef-unit-tests",
        "network-unit-tests",
        "runtime-dispatch-tests",
        "runtime-unit-tests",
        "section1-pe-runtime",
        "section11",
        "section28-com",
        "section34",
        "user32-unit-tests",
        "winhttp-unit-tests",
        "winmm-unit-tests",
        "d2d-unit-tests",
        "dwrite-unit-tests",
        "webview2-unit-tests",
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
