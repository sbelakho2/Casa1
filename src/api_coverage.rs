//! API coverage evidence registry (oracle-backed).
//!
//! The registry maps (DLL, export) pairs to the ORACLE CONTRACT that proves
//! their semantic coverage.  Evidence is NEVER inferred from the existence of
//! a Rust test — each [`ApiCoverageEvidence`] row names the actual
//! differential-oracle contract (`windows-oracle:<category>`) that exercises
//! the API against the real Windows reference executable.
//!
//! [`ApiDatabase::from_thunk_metadata`] merges this registry after seeding
//! the implementation entries: when the (DLL, export, arch, Windows version)
//! key matches, the entry's [`CoverageLevel`] takes the registry's level.

use crate::api_database::{ArchSet, CoverageLevel, WindowsVersion};

/// One piece of oracle-backed coverage evidence for an API.
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
    /// The oracle contract that produces the evidence — the actual
    /// differential vector category the Windows reference executable runs.
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

/// The static coverage-evidence registry.
///
/// Every row's `evidence_id` is a REAL oracle contract: the
/// `windows-oracle:<category>` differential vectors that the standalone
/// Windows reference executable (windows_reference/) runs.  An API may only
/// be promoted to `Differential` with one of these contracts behind it.
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

    #[test]
    fn evidence_never_inferred_from_rust_tests() {
        // Every row names a real contract: either the differential
        // windows-oracle:<category> vectors run by the standalone Windows
        // reference executable, or a casa1-conformance:<suite> suite that
        // drives the guest-facing API and asserts observable behavior.
        for row in COVERAGE_EVIDENCE {
            assert!(
                row.evidence_id.starts_with("windows-oracle:")
                    || row.evidence_id.starts_with("casa1-conformance:"),
                "evidence must name the oracle contract or a conformance suite, got {}",
                row.evidence_id
            );
            assert!(
                matches!(
                    row.level,
                    CoverageLevel::Differential | CoverageLevel::Conformance
                ),
                "evidence levels are Differential or Conformance, got {:?}",
                row.level
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
