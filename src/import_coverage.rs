//! Import coverage report system (Gap 7.1).
//!
//! Two paths live here:
//!
//! 1. **Regression snapshot** — the legacy hand-curated Steam.exe import list
//!    ([`steam_exe_imports_regression_snapshot`]) and the report generators
//!    built on it (`generate_import_coverage_report*`).  These are kept ONLY
//!    as a regression snapshot of the historical report format.
//! 2. **Canonical fixture-derived coverage** —
//!    [`coverage_for_steam_fixture`] parses the ACTUAL Steam executable's
//!    import tables (via [`crate::pe::parse_from_file`]), classifies every
//!    import against the canonical [`ThunkMetadata`]
//!    ([`crate::host_thunks::THUNK_METADATA`]), and emits a structured
//!    report (JSON-serializable) with the implementation quality and
//!    Steam-criticality of each import.

use crate::host_thunks::ImplementationLevel;
use crate::pe::{ExportSymbol, ImportSymbol, ParsedPe};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Known Steam.exe imports — REGRESSION SNAPSHOT ONLY
// ---------------------------------------------------------------------------

/// **Regression snapshot.**  Hand-curated representative list of DLLs that
/// Steam.exe imports from, along with the function names it requires from
/// each DLL.
///
/// This list is kept ONLY as a regression snapshot of the legacy report
/// format (`generate_import_coverage_report*`).  The canonical, authoritative
/// coverage path is [`coverage_for_steam_fixture`], which derives imports
/// from the real Steam.exe binary instead of a hand-maintained copy.
pub fn steam_exe_imports_regression_snapshot() -> BTreeMap<String, Vec<String>> {
    let mut m = BTreeMap::new();

    // kernel32.dll
    m.insert(
        "kernel32.dll".to_string(),
        vec![
            "GetModuleHandleA".into(),
            "GetModuleHandleW".into(),
            "GetProcAddress".into(),
            "LoadLibraryA".into(),
            "LoadLibraryW".into(),
            "LoadLibraryExA".into(),
            "LoadLibraryExW".into(),
            "FreeLibrary".into(),
            "GetModuleFileNameA".into(),
            "GetModuleFileNameW".into(),
            "CreateFileA".into(),
            "CreateFileW".into(),
            "ReadFile".into(),
            "WriteFile".into(),
            "CloseHandle".into(),
            "GetFileSize".into(),
            "GetFileSizeEx".into(),
            "SetFilePointer".into(),
            "SetFilePointerEx".into(),
            "FlushFileBuffers".into(),
            "DeleteFileA".into(),
            "DeleteFileW".into(),
            "MoveFileA".into(),
            "MoveFileW".into(),
            "MoveFileExA".into(),
            "MoveFileExW".into(),
            "FindFirstFileA".into(),
            "FindFirstFileW".into(),
            "FindNextFileA".into(),
            "FindNextFileW".into(),
            "FindClose".into(),
            "CreateDirectoryA".into(),
            "CreateDirectoryW".into(),
            "RemoveDirectoryA".into(),
            "RemoveDirectoryW".into(),
            "GetFileAttributesA".into(),
            "GetFileAttributesW".into(),
            "SetFileAttributesA".into(),
            "SetFileAttributesW".into(),
            "GetCurrentDirectoryA".into(),
            "GetCurrentDirectoryW".into(),
            "SetCurrentDirectoryA".into(),
            "SetCurrentDirectoryW".into(),
            "GetTempPathA".into(),
            "GetTempPathW".into(),
            "GetTempFileNameA".into(),
            "GetTempFileNameW".into(),
            "CreateProcessA".into(),
            "CreateProcessW".into(),
            "TerminateProcess".into(),
            "GetExitCodeProcess".into(),
            "WaitForSingleObject".into(),
            "WaitForMultipleObjects".into(),
            "Sleep".into(),
            "SleepEx".into(),
            "GetTickCount".into(),
            "GetTickCount64".into(),
            "QueryPerformanceCounter".into(),
            "QueryPerformanceFrequency".into(),
            "GetSystemTime".into(),
            "GetSystemTimeAsFileTime".into(),
            "GetLocalTime".into(),
            "CreateMutexA".into(),
            "CreateMutexW".into(),
            "OpenMutexA".into(),
            "OpenMutexW".into(),
            "CreateSemaphoreA".into(),
            "CreateSemaphoreW".into(),
            "CreateEventA".into(),
            "CreateEventW".into(),
            "SetEvent".into(),
            "ResetEvent".into(),
            "InitializeCriticalSection".into(),
            "EnterCriticalSection".into(),
            "LeaveCriticalSection".into(),
            "DeleteCriticalSection".into(),
            "CreateThread".into(),
            "ExitThread".into(),
            "GetCurrentThreadId".into(),
            "GetCurrentProcessId".into(),
            "TlsAlloc".into(),
            "TlsFree".into(),
            "TlsGetValue".into(),
            "TlsSetValue".into(),
            "HeapAlloc".into(),
            "HeapFree".into(),
            "HeapCreate".into(),
            "HeapDestroy".into(),
            "GetProcessHeap".into(),
            "VirtualAlloc".into(),
            "VirtualFree".into(),
            "VirtualProtect".into(),
            "VirtualQuery".into(),
            "GetLastError".into(),
            "SetLastError".into(),
            "FormatMessageA".into(),
            "FormatMessageW".into(),
            "MultiByteToWideChar".into(),
            "WideCharToMultiByte".into(),
            "lstrlenA".into(),
            "lstrlenW".into(),
            "lstrcpyA".into(),
            "lstrcpyW".into(),
            "lstrcatA".into(),
            "lstrcatW".into(),
            "lstrcmpA".into(),
            "lstrcmpW".into(),
            "lstrcmpiA".into(),
            "lstrcmpiW".into(),
            "GetVersionExA".into(),
            "GetVersionExW".into(),
            "GetComputerNameA".into(),
            "GetComputerNameW".into(),
            "GetEnvironmentVariableA".into(),
            "GetEnvironmentVariableW".into(),
            "SetEnvironmentVariableA".into(),
            "SetEnvironmentVariableW".into(),
            "ExpandEnvironmentStringsA".into(),
            "ExpandEnvironmentStringsW".into(),
            "GetCommandLineA".into(),
            "GetCommandLineW".into(),
            "GetStartupInfoA".into(),
            "GetStartupInfoW".into(),
            "GlobalAlloc".into(),
            "GlobalFree".into(),
            "GlobalLock".into(),
            "GlobalUnlock".into(),
            "GlobalHandle".into(),
            "LocalAlloc".into(),
            "LocalFree".into(),
            "CreateActCtxW".into(),
            "ActivateActCtx".into(),
            "DeactivateActCtx".into(),
            "ReleaseActCtx".into(),
            "FindActCtxSectionStringW".into(),
            "GetSystemInfo".into(),
            "IsWow64Process".into(),
            "GetNativeSystemInfo".into(),
            "DebugBreak".into(),
            "OutputDebugStringA".into(),
            "OutputDebugStringW".into(),
            "IsDebuggerPresent".into(),
            "SetUnhandledExceptionFilter".into(),
            "UnhandledExceptionFilter".into(),
            "GetStdHandle".into(),
            "WriteConsoleA".into(),
            "WriteConsoleW".into(),
        ],
    );

    // user32.dll
    m.insert(
        "user32.dll".to_string(),
        vec![
            "CreateWindowExA".into(),
            "CreateWindowExW".into(),
            "DestroyWindow".into(),
            "ShowWindow".into(),
            "UpdateWindow".into(),
            "GetMessageA".into(),
            "GetMessageW".into(),
            "TranslateMessage".into(),
            "DispatchMessageA".into(),
            "DispatchMessageW".into(),
            "SendMessageA".into(),
            "SendMessageW".into(),
            "PostMessageA".into(),
            "PostMessageW".into(),
            "PostQuitMessage".into(),
            "PeekMessageA".into(),
            "PeekMessageW".into(),
            "DefWindowProcA".into(),
            "DefWindowProcW".into(),
            "RegisterClassA".into(),
            "RegisterClassW".into(),
            "RegisterClassExA".into(),
            "RegisterClassExW".into(),
            "GetClientRect".into(),
            "GetWindowRect".into(),
            "SetWindowPos".into(),
            "MoveWindow".into(),
            "GetDC".into(),
            "ReleaseDC".into(),
            "BeginPaint".into(),
            "EndPaint".into(),
            "InvalidateRect".into(),
            "ValidateRect".into(),
            "SetWindowTextA".into(),
            "SetWindowTextW".into(),
            "GetWindowTextA".into(),
            "GetWindowTextW".into(),
            "GetWindowTextLengthA".into(),
            "GetWindowTextLengthW".into(),
            "SetTimer".into(),
            "KillTimer".into(),
            "GetSystemMetrics".into(),
            "LoadCursorA".into(),
            "LoadCursorW".into(),
            "LoadIconA".into(),
            "LoadIconW".into(),
            "LoadImageA".into(),
            "LoadImageW".into(),
            "MessageBoxA".into(),
            "MessageBoxW".into(),
            "GetDlgItem".into(),
            "SetDlgItemTextA".into(),
            "SetDlgItemTextW".into(),
            "GetDlgItemTextA".into(),
            "GetDlgItemTextW".into(),
            "DialogBoxParamA".into(),
            "DialogBoxParamW".into(),
            "EndDialog".into(),
            "CreateDialogParamA".into(),
            "CreateDialogParamW".into(),
            "IsDialogMessageA".into(),
            "IsDialogMessageW".into(),
            "EnableWindow".into(),
            "IsWindowEnabled".into(),
            "IsWindowVisible".into(),
            "IsWindow".into(),
            "GetParent".into(),
            "SetParent".into(),
            "GetForegroundWindow".into(),
            "SetForegroundWindow".into(),
            "GetFocus".into(),
            "SetFocus".into(),
            "GetActiveWindow".into(),
            "SetActiveWindow".into(),
            "GetKeyState".into(),
            "GetAsyncKeyState".into(),
            "GetKeyboardState".into(),
            "MapVirtualKeyA".into(),
            "MapVirtualKeyW".into(),
            "VkKeyScanA".into(),
            "VkKeyScanW".into(),
            "TrackPopupMenu".into(),
            "CreateMenu".into(),
            "CreatePopupMenu".into(),
            "AppendMenuA".into(),
            "AppendMenuW".into(),
            "InsertMenuA".into(),
            "InsertMenuW".into(),
            "DrawMenuBar".into(),
            "LoadMenuA".into(),
            "LoadMenuW".into(),
            "GetMenu".into(),
            "SetMenu".into(),
            "DestroyMenu".into(),
            "GetSubMenu".into(),
            "GetMenuItemCount".into(),
            "GetMenuItemID".into(),
            "CheckMenuItem".into(),
            "EnableMenuItem".into(),
            "GetCursorPos".into(),
            "SetCursorPos".into(),
            "ShowCursor".into(),
            "ClipCursor".into(),
            "GetClipCursor".into(),
            "ScreenToClient".into(),
            "ClientToScreen".into(),
            "GetWindowLongA".into(),
            "GetWindowLongW".into(),
            "GetWindowLongPtrA".into(),
            "GetWindowLongPtrW".into(),
            "SetWindowLongA".into(),
            "SetWindowLongW".into(),
            "SetWindowLongPtrA".into(),
            "SetWindowLongPtrW".into(),
            "GetClassLongA".into(),
            "GetClassLongW".into(),
            "SetClassLongA".into(),
            "SetClassLongW".into(),
            "AdjustWindowRect".into(),
            "AdjustWindowRectEx".into(),
            "GetDesktopWindow".into(),
            "GetWindowThreadProcessId".into(),
            "EnumWindows".into(),
            "EnumChildWindows".into(),
            "GetClassNameA".into(),
            "GetClassNameW".into(),
            "RegisterWindowMessageA".into(),
            "RegisterWindowMessageW".into(),
            "SendMessageTimeoutA".into(),
            "SendMessageTimeoutW".into(),
            "SendNotifyMessageA".into(),
            "SendNotifyMessageW".into(),
            "PostThreadMessageA".into(),
            "PostThreadMessageW".into(),
            "WaitMessage".into(),
            "MsgWaitForMultipleObjects".into(),
            "MsgWaitForMultipleObjectsEx".into(),
            "GetMessagePos".into(),
            "GetMessageTime".into(),
            "TranslateAcceleratorA".into(),
            "TranslateAcceleratorW".into(),
            "LoadAcceleratorsA".into(),
            "LoadAcceleratorsW".into(),
            "SetCapture".into(),
            "ReleaseCapture".into(),
            "GetCapture".into(),
            "GetDoubleClickTime".into(),
            "RegisterHotKey".into(),
            "UnregisterHotKey".into(),
            "FlashWindow".into(),
            "FlashWindowEx".into(),
            "GetWindow".into(),
            "IsChild".into(),
            "BringWindowToTop".into(),
            "ShowOwnedPopups".into(),
            "OpenClipboard".into(),
            "CloseClipboard".into(),
            "EmptyClipboard".into(),
            "SetClipboardData".into(),
            "GetClipboardData".into(),
            "IsClipboardFormatAvailable".into(),
            "CountClipboardFormats".into(),
            "EnumClipboardFormats".into(),
            "RegisterClipboardFormatA".into(),
            "RegisterClipboardFormatW".into(),
        ],
    );

    // gdi32.dll
    m.insert(
        "gdi32.dll".to_string(),
        vec![
            "CreateCompatibleDC".into(),
            "CreateCompatibleBitmap".into(),
            "CreateBitmap".into(),
            "CreateDIBSection".into(),
            "CreateDIBitmap".into(),
            "SelectObject".into(),
            "DeleteObject".into(),
            "DeleteDC".into(),
            "BitBlt".into(),
            "StretchBlt".into(),
            "StretchDIBits".into(),
            "SetDIBitsToDevice".into(),
            "GetDIBits".into(),
            "SetBitmapBits".into(),
            "GetBitmapBits".into(),
            "CreateSolidBrush".into(),
            "CreatePen".into(),
            "CreateFontA".into(),
            "CreateFontW".into(),
            "CreateFontIndirectA".into(),
            "CreateFontIndirectW".into(),
            "SetTextColor".into(),
            "SetBkColor".into(),
            "SetBkMode".into(),
            "TextOutA".into(),
            "TextOutW".into(),
            "DrawTextA".into(),
            "DrawTextW".into(),
            "GetTextExtentPoint32A".into(),
            "GetTextExtentPoint32W".into(),
            "GetTextMetricsA".into(),
            "GetTextMetricsW".into(),
            "Rectangle".into(),
            "FillRect".into(),
            "FrameRect".into(),
            "RoundRect".into(),
            "Ellipse".into(),
            "LineTo".into(),
            "MoveToEx".into(),
            "Polygon".into(),
            "Polyline".into(),
            "SetPixel".into(),
            "GetPixel".into(),
            "PatBlt".into(),
            "MaskBlt".into(),
            "PlgBlt".into(),
            "CreatePalette".into(),
            "SelectPalette".into(),
            "RealizePalette".into(),
            "GetDeviceCaps".into(),
            "GetSystemPaletteEntries".into(),
            "CreateHalftonePalette".into(),
            "GetObjectA".into(),
            "GetObjectW".into(),
            "GetStockObject".into(),
            "SetROP2".into(),
            "SetStretchBltMode".into(),
            "GetBrushOrgEx".into(),
            "SetBrushOrgEx".into(),
            "GetClipBox".into(),
            "SelectClipRgn".into(),
            "ExtSelectClipRgn".into(),
            "OffsetClipRgn".into(),
            "SaveDC".into(),
            "RestoreDC".into(),
            "CreateRectRgn".into(),
            "CreateRectRgnIndirect".into(),
            "CombineRgn".into(),
            "OffsetRgn".into(),
            "GetRegionData".into(),
            "ExtCreatePen".into(),
            "CreatePatternBrush".into(),
            "CreateHatchBrush".into(),
            "SetWorldTransform".into(),
            "ModifyWorldTransform".into(),
            "SetGraphicsMode".into(),
            "SetMapMode".into(),
            "SetViewportOrgEx".into(),
            "SetWindowOrgEx".into(),
            "SetViewportExtEx".into(),
            "SetWindowExtEx".into(),
            "DPtoLP".into(),
            "LPtoDP".into(),
            "GetWorldTransform".into(),
            "GetMapMode".into(),
            "GetCurrentObject".into(),
            "GetObjectType".into(),
            "EnumFontFamiliesExA".into(),
            "EnumFontFamiliesExW".into(),
            "AddFontResourceA".into(),
            "AddFontResourceW".into(),
            "RemoveFontResourceA".into(),
            "RemoveFontResourceW".into(),
            "GetCharABCWidthsA".into(),
            "GetCharABCWidthsW".into(),
            "GetCharacterPlacementA".into(),
            "GetCharacterPlacementW".into(),
        ],
    );

    // advapi32.dll
    m.insert(
        "advapi32.dll".to_string(),
        vec![
            "RegOpenKeyExA".into(),
            "RegOpenKeyExW".into(),
            "RegCreateKeyExA".into(),
            "RegCreateKeyExW".into(),
            "RegCloseKey".into(),
            "RegSetValueExA".into(),
            "RegSetValueExW".into(),
            "RegQueryValueExA".into(),
            "RegQueryValueExW".into(),
            "RegDeleteKeyA".into(),
            "RegDeleteKeyW".into(),
            "RegDeleteValueA".into(),
            "RegDeleteValueW".into(),
            "RegEnumKeyExA".into(),
            "RegEnumKeyExW".into(),
            "RegEnumValueA".into(),
            "RegEnumValueW".into(),
            "RegNotifyChangeKeyValue".into(),
            "OpenProcessToken".into(),
            "GetTokenInformation".into(),
            "AdjustTokenPrivileges".into(),
            "LookupPrivilegeValueA".into(),
            "LookupPrivilegeValueW".into(),
            "CheckTokenMembership".into(),
            "DuplicateTokenEx".into(),
            "GetUserNameA".into(),
            "GetUserNameW".into(),
            "ConvertSidToStringSidA".into(),
            "ConvertSidToStringSidW".into(),
            "ConvertStringSidToSidA".into(),
            "ConvertStringSidToSidW".into(),
            "EqualSid".into(),
            "GetLengthSid".into(),
            "CopySid".into(),
            "InitializeSecurityDescriptor".into(),
            "SetSecurityDescriptorDacl".into(),
            "GetSecurityDescriptorDacl".into(),
            "InitializeAcl".into(),
            "AddAccessAllowedAce".into(),
            "CryptAcquireContextA".into(),
            "CryptAcquireContextW".into(),
            "CryptGenRandom".into(),
            "CryptReleaseContext".into(),
            "CryptCreateHash".into(),
            "CryptHashData".into(),
            "CryptGetHashParam".into(),
            "CryptDestroyHash".into(),
            "CryptDeriveKey".into(),
            "CryptEncrypt".into(),
            "CryptDecrypt".into(),
            "CryptDestroyKey".into(),
            "CryptImportKey".into(),
            "CryptExportKey".into(),
            "CryptSetKeyParam".into(),
            "CryptGenKey".into(),
            "StartServiceCtrlDispatcherA".into(),
            "StartServiceCtrlDispatcherW".into(),
            "RegisterServiceCtrlHandlerA".into(),
            "RegisterServiceCtrlHandlerW".into(),
            "SetServiceStatus".into(),
            "OpenSCManagerA".into(),
            "OpenSCManagerW".into(),
            "OpenServiceA".into(),
            "OpenServiceW".into(),
            "CreateServiceA".into(),
            "CreateServiceW".into(),
            "StartServiceA".into(),
            "StartServiceW".into(),
            "ControlService".into(),
            "CloseServiceHandle".into(),
            "DeleteService".into(),
            "QueryServiceStatus".into(),
            "QueryServiceStatusEx".into(),
            "GetFileSecurityA".into(),
            "GetFileSecurityW".into(),
            "SetFileSecurityA".into(),
            "SetFileSecurityW".into(),
            "AccessCheck".into(),
            "MapGenericMask".into(),
        ],
    );

    // shell32.dll
    m.insert(
        "shell32.dll".to_string(),
        vec![
            "SHGetFolderPathA".into(),
            "SHGetFolderPathW".into(),
            "SHGetSpecialFolderPathA".into(),
            "SHGetSpecialFolderPathW".into(),
            "SHGetDesktopFolder".into(),
            "SHBrowseForFolderW".into(),
            "SHGetPathFromIDListW".into(),
            "ILCreateFromPathW".into(),
            "ILFree".into(),
            "SHGetFileInfoA".into(),
            "SHGetFileInfoW".into(),
            "SHGetMalloc".into(),
            "DragAcceptFiles".into(),
            "DragQueryFileW".into(),
            "DragFinish".into(),
            "DragQueryPoint".into(),
            "ShellExecuteA".into(),
            "ShellExecuteW".into(),
            "ShellExecuteExA".into(),
            "ShellExecuteExW".into(),
            "SHGetSpecialFolderLocation".into(),
            "SHGetFolderLocation".into(),
            "SHParseDisplayName".into(),
            "SHCreateItemFromParsingName".into(),
            "ExtractIconW".into(),
        ],
    );

    // ole32.dll
    m.insert(
        "ole32.dll".to_string(),
        vec![
            "CoInitialize".into(),
            "CoInitializeEx".into(),
            "CoUninitialize".into(),
            "CoCreateInstance".into(),
            "CoGetClassObject".into(),
            "CoTaskMemAlloc".into(),
            "CoTaskMemFree".into(),
            "CoTaskMemRealloc".into(),
            "CoInitializeSecurity".into(),
            "CoGetCallContext".into(),
            "CoSetProxyBlanket".into(),
            "CoGetApartmentType".into(),
            "CoGetCurrentProcess".into(),
            "CoRegisterClassObject".into(),
            "CoRevokeClassObject".into(),
            "CoResumeClassObjects".into(),
            "CoSuspendClassObjects".into(),
            "CreateStreamOnHGlobal".into(),
            "GetHGlobalFromStream".into(),
            "CoCreateGuid".into(),
            "StringFromGUID2".into(),
            "IIDFromString".into(),
            "CLSIDFromString".into(),
            "StringFromCLSID".into(),
            "ProgIDFromCLSID".into(),
            "CLSIDFromProgID".into(),
            "OleInitialize".into(),
            "OleUninitialize".into(),
            "RegisterDragDrop".into(),
            "RevokeDragDrop".into(),
            "DoDragDrop".into(),
            "CreateBindCtx".into(),
            "CreateFileMoniker".into(),
            "MkParseDisplayName".into(),
            "CoGetMalloc".into(),
            "CoGetObjectContext".into(),
            "CoGetInterfaceAndReleaseStream".into(),
            "CoMarshalInterThreadInterfaceInStream".into(),
            "CoReleaseMarshalData".into(),
        ],
    );

    // crypt32.dll
    m.insert(
        "crypt32.dll".to_string(),
        vec![
            "CertOpenStore".into(),
            "CertCloseStore".into(),
            "CertOpenSystemStoreA".into(),
            "CertOpenSystemStoreW".into(),
            "CertEnumCertificatesInStore".into(),
            "CertFindCertificateInStore".into(),
            "CertGetCertificateChain".into(),
            "CertFreeCertificateChain".into(),
            "CertVerifyCertificateChainPolicy".into(),
            "CertDeleteCertificateFromStore".into(),
            "CertAddCertificateContextToStore".into(),
            "CertDuplicateCertificateContext".into(),
            "CertFreeCertificateContext".into(),
            "CryptAcquireCertificatePrivateKey".into(),
            "PFXImportCertStore".into(),
            "PFXIsPFXBlob".into(),
            "CertFindExtension".into(),
            "CertGetNameStringA".into(),
            "CertGetNameStringW".into(),
            "CertGetIssuerCertificateFromStore".into(),
            "CertEnumCRLsInStore".into(),
            "CertFindCRLInStore".into(),
        ],
    );

    // winhttp.dll
    m.insert(
        "winhttp.dll".to_string(),
        vec![
            "WinHttpOpen".into(),
            "WinHttpConnect".into(),
            "WinHttpOpenRequest".into(),
            "WinHttpSendRequest".into(),
            "WinHttpReceiveResponse".into(),
            "WinHttpReadData".into(),
            "WinHttpWriteData".into(),
            "WinHttpCloseHandle".into(),
            "WinHttpSetOption".into(),
            "WinHttpQueryOption".into(),
            "WinHttpQueryHeaders".into(),
            "WinHttpAddRequestHeaders".into(),
            "WinHttpSetCredentials".into(),
            "WinHttpSetTimeouts".into(),
            "WinHttpGetProxyForUrl".into(),
            "WinHttpCrackUrl".into(),
            "WinHttpCreateUrl".into(),
            "WinHttpDetectAutoProxyConfigUrl".into(),
            "WinHttpGetIEProxyConfigForCurrentUser".into(),
            "WinHttpWebSocketCompleteUpgrade".into(),
            "WinHttpWebSocketSend".into(),
            "WinHttpWebSocketReceive".into(),
            "WinHttpWebSocketClose".into(),
            "WinHttpWebSocketQueryCloseStatus".into(),
            "WinHttpGetProxySettingsVersion".into(),
            "WinHttpSetProxySettingsPerUser".into(),
        ],
    );

    // wininet.dll
    m.insert(
        "wininet.dll".to_string(),
        vec![
            "InternetOpenA".into(),
            "InternetOpenW".into(),
            "InternetConnectA".into(),
            "InternetConnectW".into(),
            "HttpOpenRequestA".into(),
            "HttpOpenRequestW".into(),
            "HttpSendRequestA".into(),
            "HttpSendRequestW".into(),
            "InternetReadFile".into(),
            "InternetWriteFile".into(),
            "InternetCloseHandle".into(),
            "InternetSetOptionA".into(),
            "InternetSetOptionW".into(),
            "InternetQueryOptionA".into(),
            "InternetQueryOptionW".into(),
            "HttpQueryInfoA".into(),
            "HttpQueryInfoW".into(),
            "HttpAddRequestHeadersA".into(),
            "HttpAddRequestHeadersW".into(),
            "InternetSetCookieA".into(),
            "InternetSetCookieW".into(),
            "InternetGetCookieA".into(),
            "InternetGetCookieW".into(),
            "InternetSetStatusCallback".into(),
            "InternetErrorDlg".into(),
            "InternetCanonicalizeUrlA".into(),
            "InternetCanonicalizeUrlW".into(),
            "InternetCrackUrlA".into(),
            "InternetCrackUrlW".into(),
            "InternetCreateUrlA".into(),
            "InternetCreateUrlW".into(),
            "FindFirstUrlCacheEntryA".into(),
            "FindFirstUrlCacheEntryW".into(),
            "FindNextUrlCacheEntryA".into(),
            "FindNextUrlCacheEntryW".into(),
            "FindCloseUrlCache".into(),
            "DeleteUrlCacheEntryA".into(),
            "DeleteUrlCacheEntryW".into(),
            "FtpOpenFileA".into(),
            "FtpOpenFileW".into(),
            "FtpGetFileA".into(),
            "FtpGetFileW".into(),
            "FtpPutFileA".into(),
            "FtpPutFileW".into(),
            "FtpDeleteFileA".into(),
            "FtpDeleteFileW".into(),
            "FtpRenameFileA".into(),
            "FtpRenameFileW".into(),
            "FtpCreateDirectoryA".into(),
            "FtpCreateDirectoryW".into(),
            "FtpRemoveDirectoryA".into(),
            "FtpRemoveDirectoryW".into(),
            "FtpFindFirstFileA".into(),
            "FtpFindFirstFileW".into(),
            "InternetGetConnectedState".into(),
            "InternetAutodial".into(),
            "InternetAttemptConnect".into(),
        ],
    );

    // ws2_32.dll
    m.insert(
        "ws2_32.dll".to_string(),
        vec![
            "WSAStartup".into(),
            "WSACleanup".into(),
            "socket".into(),
            "closesocket".into(),
            "connect".into(),
            "bind".into(),
            "listen".into(),
            "accept".into(),
            "send".into(),
            "recv".into(),
            "sendto".into(),
            "recvfrom".into(),
            "select".into(),
            "ioctlsocket".into(),
            "getsockopt".into(),
            "setsockopt".into(),
            "getsockname".into(),
            "getpeername".into(),
            "gethostbyname".into(),
            "getaddrinfo".into(),
            "freeaddrinfo".into(),
            "getnameinfo".into(),
            "WSAGetLastError".into(),
            "WSASetLastError".into(),
            "WSARecv".into(),
            "WSASend".into(),
            "WSARecvFrom".into(),
            "WSASendTo".into(),
            "WSASocketA".into(),
            "WSASocketW".into(),
            "WSAIoctl".into(),
            "WSAEventSelect".into(),
            "WSAEnumNetworkEvents".into(),
            "WSACreateEvent".into(),
            "WSACloseEvent".into(),
            "WSAWaitForMultipleEvents".into(),
            "WSAResetEvent".into(),
            "WSAConnect".into(),
            "htons".into(),
            "ntohs".into(),
            "htonl".into(),
            "ntohl".into(),
            "inet_addr".into(),
            "inet_ntoa".into(),
            "inet_pton".into(),
            "inet_ntop".into(),
            "shutdown".into(),
            "WSAAddressToStringA".into(),
            "WSAAddressToStringW".into(),
            "WSAStringToAddressA".into(),
            "WSAStringToAddressW".into(),
        ],
    );

    // dinput8.dll
    m.insert("dinput8.dll".to_string(), vec!["DirectInput8Create".into()]);

    // xinput1_4.dll
    m.insert(
        "xinput1_4.dll".to_string(),
        vec![
            "XInputGetState".into(),
            "XInputSetState".into(),
            "XInputGetCapabilities".into(),
            "XInputGetDSoundAudioDeviceGuids".into(),
            "XInputEnable".into(),
            "XInputGetBatteryInformation".into(),
            "XInputGetKeystroke".into(),
            "XInputGetAudioDeviceIds".into(),
        ],
    );

    // version.dll
    m.insert(
        "version.dll".to_string(),
        vec![
            "GetFileVersionInfoA".into(),
            "GetFileVersionInfoW".into(),
            "GetFileVersionInfoSizeA".into(),
            "GetFileVersionInfoSizeW".into(),
            "VerQueryValueA".into(),
            "VerQueryValueW".into(),
        ],
    );

    // imm32.dll
    m.insert(
        "imm32.dll".to_string(),
        vec![
            "ImmGetContext".into(),
            "ImmReleaseContext".into(),
            "ImmGetCompositionStringA".into(),
            "ImmGetCompositionStringW".into(),
            "ImmSetCompositionStringA".into(),
            "ImmSetCompositionStringW".into(),
            "ImmGetCandidateListA".into(),
            "ImmGetCandidateListW".into(),
            "ImmGetCandidateListCountA".into(),
            "ImmGetCandidateListCountW".into(),
            "ImmNotifyIME".into(),
            "ImmAssociateContext".into(),
            "ImmAssociateContextEx".into(),
        ],
    );

    // msacm32.dll
    m.insert(
        "msacm32.dll".to_string(),
        vec![
            "acmDriverEnum".into(),
            "acmDriverDetailsA".into(),
            "acmDriverDetailsW".into(),
            "acmFormatTagDetailsA".into(),
            "acmFormatTagDetailsW".into(),
            "acmFormatEnumA".into(),
            "acmFormatEnumW".into(),
            "acmStreamOpen".into(),
            "acmStreamClose".into(),
            "acmStreamConvert".into(),
            "acmStreamSize".into(),
            "acmStreamPrepareHeader".into(),
            "acmStreamUnprepareHeader".into(),
        ],
    );

    // winmm.dll
    m.insert(
        "winmm.dll".to_string(),
        vec![
            "timeBeginPeriod".into(),
            "timeEndPeriod".into(),
            "timeGetTime".into(),
            "timeGetDevCaps".into(),
            "waveOutOpen".into(),
            "waveOutClose".into(),
            "waveOutWrite".into(),
            "waveOutPrepareHeader".into(),
            "waveOutUnprepareHeader".into(),
            "waveOutGetDevCapsA".into(),
            "waveOutGetDevCapsW".into(),
            "waveOutGetNumDevs".into(),
            "waveOutGetVolume".into(),
            "waveOutSetVolume".into(),
            "waveOutPause".into(),
            "waveOutRestart".into(),
            "waveOutReset".into(),
            "waveOutGetPosition".into(),
            "midiOutOpen".into(),
            "midiOutClose".into(),
            "midiOutShortMsg".into(),
            "midiOutLongMsg".into(),
            "midiOutGetDevCapsA".into(),
            "midiOutGetDevCapsW".into(),
            "midiOutGetNumDevs".into(),
            "midiOutReset".into(),
            "PlaySoundA".into(),
            "PlaySoundW".into(),
            "auxGetNumDevs".into(),
            "mixerOpen".into(),
            "mixerClose".into(),
            "mixerGetControlDetailsA".into(),
            "mixerGetControlDetailsW".into(),
            "mixerGetDevCapsA".into(),
            "mixerGetDevCapsW".into(),
            "mixerGetID".into(),
            "mixerGetLineControlsA".into(),
            "mixerGetLineControlsW".into(),
            "mixerGetLineInfoA".into(),
            "mixerGetLineInfoW".into(),
            "mixerGetNumDevs".into(),
            "mixerMessage".into(),
            "mixerSetControlDetails".into(),
        ],
    );

    m
}

// ---------------------------------------------------------------------------
// Coverage report data structures
// ---------------------------------------------------------------------------

/// Coverage status for a single import function.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportCoverageEntry {
    /// The DLL name (lowercase).
    pub dll: String,
    /// The function name.
    pub function: String,
    /// Whether the function has a real (non-stub) implementation.
    pub covered: bool,
    /// A note about the implementation status (e.g. "stub", "real", "partial").
    pub status: String,
}

/// Per-DLL coverage summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DllCoverageReport {
    /// DLL name.
    pub dll: String,
    /// Total number of imports required from this DLL.
    pub total: usize,
    /// Number of imports that have real implementations.
    pub covered: usize,
    /// Number of imports that are stubs or missing.
    pub missing: usize,
    /// Coverage percentage (0.0–100.0).
    pub coverage_percent: f64,
    /// List of covered function names.
    pub covered_functions: Vec<String>,
    /// List of missing function names.
    pub missing_functions: Vec<String>,
}

/// Overall import coverage report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportCoverageReport {
    /// Total number of imports across all DLLs.
    pub total_imports: usize,
    /// Total number of covered imports.
    pub covered_imports: usize,
    /// Total number of missing imports.
    pub missing_imports: usize,
    /// Overall coverage percentage (0.0–100.0).
    pub overall_coverage_percent: f64,
    /// Per-DLL coverage breakdown.
    pub dll_reports: Vec<DllCoverageReport>,
    /// Individual import entries.
    pub entries: Vec<ImportCoverageEntry>,
}

/// Generate an import coverage report by cross-referencing the regression
/// snapshot of known Steam.exe imports with the PE runtime's registered
/// export tables.
///
/// "Covered" is derived from the authoritative runtime export registry
/// ([`crate::pe_runtime::export_tables`]), so the report reflects the actual
/// state of the implemented API surface instead of a hand-maintained copy.
///
/// Kept as a regression snapshot: the canonical fixture-derived coverage is
/// [`coverage_for_steam_fixture`].
pub fn generate_import_coverage_report() -> ImportCoverageReport {
    let steam_imports = steam_exe_imports_regression_snapshot();

    // Pre-index the runtime's registered export names (lowercased) per DLL
    // so each import lookup is O(1) instead of a linear scan.
    let covered_by_dll: std::collections::HashMap<String, std::collections::HashSet<String>> =
        crate::pe_runtime::export_tables()
            .into_iter()
            .map(|(dll, exports)| {
                let names = exports
                    .into_iter()
                    .filter_map(|e| e.name)
                    .map(|n| n.to_lowercase())
                    .collect();
                (dll.to_lowercase(), names)
            })
            .collect();

    let mut entries = Vec::new();
    let mut dll_reports = Vec::new();
    let mut total_imports = 0usize;
    let mut total_covered = 0usize;
    let mut total_missing = 0usize;

    for (dll, functions) in &steam_imports {
        let dll_covered = covered_by_dll.get(&dll.to_lowercase());

        let mut dll_total = 0usize;
        let mut dll_covered_count = 0usize;
        let mut dll_missing_count = 0usize;
        let mut dll_covered_functions = Vec::new();
        let mut dll_missing_functions = Vec::new();

        for func in functions {
            dll_total += 1;
            let func_lower = func.to_lowercase();
            let is_covered = dll_covered.is_some_and(|names| names.contains(&func_lower));

            let status = if is_covered {
                "real".to_string()
            } else {
                "missing".to_string()
            };

            entries.push(ImportCoverageEntry {
                dll: dll.clone(),
                function: func.clone(),
                covered: is_covered,
                status,
            });

            if is_covered {
                dll_covered_count += 1;
                dll_covered_functions.push(func.clone());
            } else {
                dll_missing_count += 1;
                dll_missing_functions.push(func.clone());
            }
        }

        let coverage_percent = if dll_total > 0 {
            (dll_covered_count as f64 / dll_total as f64) * 100.0
        } else {
            0.0
        };

        total_imports += dll_total;
        total_covered += dll_covered_count;
        total_missing += dll_missing_count;

        dll_reports.push(DllCoverageReport {
            dll: dll.clone(),
            total: dll_total,
            covered: dll_covered_count,
            missing: dll_missing_count,
            coverage_percent,
            covered_functions: dll_covered_functions,
            missing_functions: dll_missing_functions,
        });
    }

    let overall_coverage_percent = if total_imports > 0 {
        (total_covered as f64 / total_imports as f64) * 100.0
    } else {
        0.0
    };

    ImportCoverageReport {
        total_imports,
        covered_imports: total_covered,
        missing_imports: total_missing,
        overall_coverage_percent,
        dll_reports,
        entries,
    }
}

/// Generate the import coverage report as a `serde_json::Value`.
///
/// Returns a JSON object with the following structure:
/// ```json
/// {
///   "total_imports": 500,
///   "covered_imports": 450,
///   "missing_imports": 50,
///   "overall_coverage_percent": 90.0,
///   "dlls": {
///     "kernel32.dll": {
///       "total": 100,
///       "covered": 95,
///       "missing": 5,
///       "coverage_percent": 95.0,
///       "missing_functions": ["..."]
///     }
///   }
/// }
/// ```
pub fn generate_import_coverage_json() -> Value {
    let report = generate_import_coverage_report();

    let mut dll_map = serde_json::Map::new();
    for dll_report in &report.dll_reports {
        let mut dll_obj = serde_json::Map::new();
        dll_obj.insert("total".into(), Value::Number(dll_report.total.into()));
        dll_obj.insert("covered".into(), Value::Number(dll_report.covered.into()));
        dll_obj.insert("missing".into(), Value::Number(dll_report.missing.into()));
        dll_obj.insert(
            "coverage_percent".into(),
            Value::from(
                serde_json::Number::from_f64(dll_report.coverage_percent)
                    .unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
        dll_obj.insert(
            "covered_functions".into(),
            Value::Array(
                dll_report
                    .covered_functions
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        dll_obj.insert(
            "missing_functions".into(),
            Value::Array(
                dll_report
                    .missing_functions
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        dll_map.insert(dll_report.dll.clone(), Value::Object(dll_obj));
    }

    let mut root = serde_json::Map::new();
    root.insert(
        "total_imports".into(),
        Value::Number(report.total_imports.into()),
    );
    root.insert(
        "covered_imports".into(),
        Value::Number(report.covered_imports.into()),
    );
    root.insert(
        "missing_imports".into(),
        Value::Number(report.missing_imports.into()),
    );
    root.insert(
        "overall_coverage_percent".into(),
        Value::from(
            serde_json::Number::from_f64(report.overall_coverage_percent)
                .unwrap_or_else(|| serde_json::Number::from(0)),
        ),
    );
    root.insert("dlls".into(), Value::Object(dll_map));
    root.insert(
        "entries".into(),
        serde_json::to_value(&report.entries).unwrap_or(Value::Array(vec![])),
    );

    Value::Object(root)
}

/// Generate a human-readable coverage report as a string.
///
/// This produces a summary table showing per-DLL coverage statistics.
pub fn generate_import_coverage_text() -> String {
    let report = generate_import_coverage_report();
    let mut lines = Vec::new();

    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push("              Steam.exe Import Coverage Report                ".to_string());
    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push(format!(
        "Overall: {}/{} imports covered ({:.1}%)",
        report.covered_imports, report.total_imports, report.overall_coverage_percent
    ));
    lines.push(String::new());
    lines.push(format!(
        "{:<20} {:>8} {:>8} {:>8} {:>10}",
        "DLL", "Total", "Covered", "Missing", "Coverage%"
    ));
    lines.push("─".repeat(60));

    for dll_report in &report.dll_reports {
        lines.push(format!(
            "{:<20} {:>8} {:>8} {:>8} {:>9.1}%",
            dll_report.dll,
            dll_report.total,
            dll_report.covered,
            dll_report.missing,
            dll_report.coverage_percent
        ));
    }

    lines.push("─".repeat(60));
    lines.push(format!(
        "{:<20} {:>8} {:>8} {:>8} {:>9.1}%",
        "TOTAL",
        report.total_imports,
        report.covered_imports,
        report.missing_imports,
        report.overall_coverage_percent
    ));

    // Show missing functions for DLLs with < 100% coverage
    for dll_report in &report.dll_reports {
        if !dll_report.missing_functions.is_empty() {
            lines.push(String::new());
            lines.push(format!(
                "Missing from {} ({} functions):",
                dll_report.dll,
                dll_report.missing_functions.len()
            ));
            for func in &dll_report.missing_functions {
                lines.push(format!("  - {}", func));
            }
        }
    }

    lines.join("\n")
}

/// Per-DLL lookup index over an export table, built once per DLL so that
/// per-thunk coverage checks are O(log n)/O(1) instead of linear scans.
struct ExportIndex {
    names: std::collections::HashSet<String>,
    ordinals: std::collections::HashSet<u32>,
}

impl ExportIndex {
    fn new(exports: &[ExportSymbol]) -> Self {
        let mut names = std::collections::HashSet::new();
        let mut ordinals = std::collections::HashSet::new();
        for export in exports {
            ordinals.insert(export.ordinal);
            if let Some(name) = &export.name {
                names.insert(name.clone());
            }
        }
        Self { names, ordinals }
    }

    fn contains(&self, symbol: &ImportSymbol) -> bool {
        match symbol {
            ImportSymbol::ByName { name, .. } => self.names.contains(name),
            ImportSymbol::ByOrdinal { ordinal } => self.ordinals.contains(&(*ordinal as u32)),
        }
    }
}

/// Generate a coverage report from a parsed PE file's imports.
///
/// This cross-references the actual imports from a PE file with the
/// registered DLL exports in the runtime.
pub fn generate_pe_coverage_report(
    pe: &ParsedPe,
    export_tables: &BTreeMap<String, Vec<ExportSymbol>>,
) -> ImportCoverageReport {
    let mut entries = Vec::new();
    let mut dll_reports_map: BTreeMap<String, DllCoverageReportBuilder> = BTreeMap::new();

    // Collect all imports from the PE
    for import_desc in &pe.imports {
        let dll_lower = import_desc.dll_name.to_lowercase();
        let export_index = export_tables
            .get(&dll_lower)
            .map(|exports| ExportIndex::new(exports));
        let builder = dll_reports_map
            .entry(dll_lower.clone())
            .or_insert_with(|| DllCoverageReportBuilder::new(dll_lower.clone()));

        for thunk in &import_desc.imports {
            let func_name = match &thunk.symbol {
                ImportSymbol::ByName { name, .. } => name.clone(),
                ImportSymbol::ByOrdinal { ordinal } => format!("#{}", ordinal),
            };

            let is_covered = export_index
                .as_ref()
                .is_some_and(|index| index.contains(&thunk.symbol));

            let status = if is_covered {
                "real".to_string()
            } else {
                "missing".to_string()
            };

            entries.push(ImportCoverageEntry {
                dll: dll_lower.clone(),
                function: func_name.clone(),
                covered: is_covered,
                status,
            });

            builder.add(func_name, is_covered);
        }
    }

    // Also check delay imports
    for import_desc in &pe.delay_imports {
        let dll_lower = import_desc.dll_name.to_lowercase();
        let export_index = export_tables
            .get(&dll_lower)
            .map(|exports| ExportIndex::new(exports));
        let builder = dll_reports_map
            .entry(dll_lower.clone())
            .or_insert_with(|| DllCoverageReportBuilder::new(dll_lower.clone()));

        for thunk in &import_desc.imports {
            let func_name = match &thunk.symbol {
                ImportSymbol::ByName { name, .. } => name.clone(),
                ImportSymbol::ByOrdinal { ordinal } => format!("#{}", ordinal),
            };

            let is_covered = export_index
                .as_ref()
                .is_some_and(|index| index.contains(&thunk.symbol));

            builder.add(func_name, is_covered);
        }
    }

    // Build final report
    let mut dll_reports: Vec<DllCoverageReport> =
        dll_reports_map.into_values().map(|b| b.build()).collect();
    dll_reports.sort_by(|a, b| a.dll.cmp(&b.dll));

    let total_imports: usize = dll_reports.iter().map(|d| d.total).sum();
    let covered_imports: usize = dll_reports.iter().map(|d| d.covered).sum();
    let missing_imports: usize = dll_reports.iter().map(|d| d.missing).sum();
    let overall_coverage_percent = if total_imports > 0 {
        (covered_imports as f64 / total_imports as f64) * 100.0
    } else {
        0.0
    };

    ImportCoverageReport {
        total_imports,
        covered_imports,
        missing_imports,
        overall_coverage_percent,
        dll_reports,
        entries,
    }
}

// Helper builder for DllCoverageReport
struct DllCoverageReportBuilder {
    dll: String,
    covered_functions: Vec<String>,
    missing_functions: Vec<String>,
}

impl DllCoverageReportBuilder {
    fn new(dll: String) -> Self {
        Self {
            dll,
            covered_functions: Vec::new(),
            missing_functions: Vec::new(),
        }
    }

    fn add(&mut self, function: String, covered: bool) {
        if covered {
            self.covered_functions.push(function);
        } else {
            self.missing_functions.push(function);
        }
    }

    fn build(self) -> DllCoverageReport {
        let total = self.covered_functions.len() + self.missing_functions.len();
        let covered = self.covered_functions.len();
        let missing = self.missing_functions.len();
        let coverage_percent = if total > 0 {
            (covered as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        DllCoverageReport {
            dll: self.dll,
            total,
            covered,
            missing,
            coverage_percent,
            covered_functions: self.covered_functions,
            missing_functions: self.missing_functions,
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical fixture-derived Steam import coverage
// ---------------------------------------------------------------------------

/// A single Steam.exe import classified against the canonical thunk metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SteamImportEntry {
    /// SHA-256 of the Steam executable the import was parsed from.
    pub steam_sha256: String,
    /// Version info of the Steam executable (PE `FileVersion`), if present.
    pub image_version: Option<String>,
    /// DLL the import comes from (lowercase, e.g. `"kernel32.dll"`).
    pub dll: String,
    /// Import name as resolved from the import table (ordinal-only imports
    /// are resolved to their canonical name where the runtime maps them,
    /// otherwise `ordinal#N`).
    pub import: String,
    /// Implementation quality of the host thunk for this import
    /// ([`ImplementationLevel`]).
    pub implementation: ImplementationLevel,
    /// Whether this import is Steam-bootstrap-critical.
    pub steam_critical: bool,
    /// Whether this import was actually invoked in the E2E run (false unless
    /// the invoked-set flag/parameter was supplied).
    pub invoked_in_e2e: bool,
}

/// Fixture-derived Steam import coverage report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SteamCoverageReport {
    /// Path of the Steam executable the report was derived from.
    pub steam_exe_path: String,
    /// SHA-256 of the Steam executable.
    pub steam_sha256: String,
    /// PE version info of the Steam executable, if present.
    pub image_version: Option<String>,
    /// Total number of imports in the executable.
    pub total_imports: usize,
    /// Per-implementation-level import counts (Implemented/Partial/Stub/Unsupported).
    pub by_implementation: BTreeMap<String, usize>,
    /// All classified imports.
    pub entries: Vec<SteamImportEntry>,
    /// Steam-critical imports whose implementation is `Stub` or `Unsupported`.
    ///
    /// The release requirement is that no *runtime-reached* Steam-critical
    /// API is `Stub` or `Unsupported`; this field lists the candidates that
    /// would fail the gate if they are ever invoked.
    pub critical_not_working: Vec<SteamImportEntry>,
    /// Whether the invoked-in-E2E flag was supplied for this report.
    pub invoked_in_e2e: bool,
}

impl SteamCoverageReport {
    /// Steam-critical imports that were actually invoked in the E2E run and
    /// whose implementation is `Stub` or `Unsupported` — the exact set the
    /// release gate asserts to be empty.
    pub fn invoked_critical_violations(&self) -> Vec<&SteamImportEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.invoked_in_e2e
                    && entry.steam_critical
                    && !entry.implementation.has_working_implementation()
            })
            .collect()
    }
}

/// Generate the fixture-derived Steam import coverage report.
///
/// Parses the ACTUAL Steam executable's import tables via
/// [`crate::pe::parse_from_file`], classifies every import against the
/// canonical [`ThunkMetadata`] table
/// ([`crate::host_thunks::THUNK_METADATA`]), and emits a structured report.
///
/// Every entry carries `invoked_in_e2e: false` unless an invoked set is
/// supplied via [`coverage_for_steam_fixture_with_invoked`].
pub fn coverage_for_steam_fixture(
    steam_exe_path: &Path,
) -> crate::error::AppResult<SteamCoverageReport> {
    coverage_for_steam_fixture_with_invoked(steam_exe_path, &[])
}

/// Generate the fixture-derived Steam import coverage report with an invoked
/// set.
///
/// `invoked` lists the API names that were actually dispatched during an E2E
/// run (e.g. from [`crate::pe_runtime::PeExecutionResult::trace_events`] via
/// [`invoked_api_names_from_trace`]); matching entries get
/// `invoked_in_e2e: true`.
pub fn coverage_for_steam_fixture_with_invoked(
    steam_exe_path: &Path,
    invoked: &[String],
) -> crate::error::AppResult<SteamCoverageReport> {
    use crate::pe::ImportSymbol;

    let parsed = crate::pe::parse_from_file(steam_exe_path)?;
    let steam_sha256 = crate::util::sha256_file(steam_exe_path)?;
    let image_version = parsed.version_info.file_version.clone();
    let invoked_set: std::collections::HashSet<String> = invoked
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    let mut entries = Vec::new();
    for descriptor in parsed.imports.iter().chain(parsed.delay_imports.iter()) {
        let dll = descriptor.dll_name.to_ascii_lowercase();
        for import in &descriptor.imports {
            let name = match &import.symbol {
                ImportSymbol::ByName { name, .. } => name.clone(),
                ImportSymbol::ByOrdinal { ordinal } => {
                    crate::host_thunks::ordinal_import_name(&dll, *ordinal)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("ordinal#{ordinal}"))
                }
            };
            let (implementation, steam_critical) =
                crate::pe_runtime::import_implementation_quality(&dll, &import.symbol);
            let invoked_in_e2e = invoked_set.contains(&name.to_ascii_lowercase());
            entries.push(SteamImportEntry {
                steam_sha256: steam_sha256.clone(),
                image_version: image_version.clone(),
                dll: dll.clone(),
                import: name,
                implementation,
                steam_critical,
                invoked_in_e2e,
            });
        }
    }

    entries.sort_by(|a, b| a.dll.cmp(&b.dll).then_with(|| a.import.cmp(&b.import)));

    let mut by_implementation = BTreeMap::new();
    for entry in &entries {
        let label = match entry.implementation {
            ImplementationLevel::Implemented => "Implemented",
            ImplementationLevel::Partial => "Partial",
            ImplementationLevel::Stub => "Stub",
            ImplementationLevel::Unsupported => "Unsupported",
        };
        *by_implementation.entry(label.to_string()).or_insert(0) += 1;
    }

    let critical_not_working = entries
        .iter()
        .filter(|entry| entry.steam_critical && !entry.implementation.has_working_implementation())
        .cloned()
        .collect();

    Ok(SteamCoverageReport {
        steam_exe_path: steam_exe_path.display().to_string(),
        steam_sha256,
        image_version,
        total_imports: entries.len(),
        by_implementation,
        entries,
        critical_not_working,
        invoked_in_e2e: !invoked_set.is_empty(),
    })
}

/// Extract the set of invoked API names from a PE runtime trace.
///
/// Each trace event's `call_id` is the dispatched API name (e.g.
/// `"CreateFileW"`); duplicate calls collapse into a single name so the set
/// can be fed to [`coverage_for_steam_fixture_with_invoked`].
pub fn invoked_api_names_from_trace(trace_events: &[crate::trace::TraceEvent]) -> Vec<String> {
    let mut names: Vec<String> = trace_events
        .iter()
        .map(|event| event.call_id.clone())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Generate the fixture-derived coverage report as pretty JSON.
pub fn coverage_for_steam_fixture_json(steam_exe_path: &Path) -> crate::error::AppResult<Value> {
    let report = coverage_for_steam_fixture(steam_exe_path)?;
    serde_json::to_value(&report).map_err(|error| {
        crate::error::AppError::new(
            crate::reason::ReasonCode::RcDiagnosticsExportFailed,
            format!("failed to serialize Steam coverage report: {error}"),
        )
    })
}

/// Generate a structured human-readable rendering of the fixture-derived
/// coverage report (the section40-style telemetry view).
pub fn coverage_for_steam_fixture_text(steam_exe_path: &Path) -> crate::error::AppResult<String> {
    let report = coverage_for_steam_fixture(steam_exe_path)?;
    let mut lines = Vec::new();
    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push("      Steam.exe Import Coverage (fixture-derived)              ".to_string());
    lines.push("═══════════════════════════════════════════════════════════════".to_string());
    lines.push(format!("exe:     {}", report.steam_exe_path));
    lines.push(format!("sha256:  {}", report.steam_sha256));
    lines.push(format!(
        "version: {}",
        report.image_version.as_deref().unwrap_or("<none>")
    ));
    lines.push(format!("imports: {}", report.total_imports));
    lines.push(format!(
        "invoked-in-e2e flag: {}",
        if report.invoked_in_e2e { "yes" } else { "no" }
    ));
    lines.push(String::new());
    lines.push(format!("{:<14} {:>6}", "Implementation", "Count"));
    lines.push("─".repeat(24));
    for label in ["Implemented", "Partial", "Stub", "Unsupported"] {
        lines.push(format!(
            "{:<14} {:>6}",
            label,
            report.by_implementation.get(label).copied().unwrap_or(0)
        ));
    }
    lines.push(String::new());
    if report.critical_not_working.is_empty() {
        lines.push(
            "No Steam-critical import is Stub/Unsupported on the static surface.".to_string(),
        );
    } else {
        lines.push(format!(
            "Steam-critical imports NOT working ({}):",
            report.critical_not_working.len()
        ));
        for entry in &report.critical_not_working {
            lines.push(format!(
                "  - {}!{} [{:?}]",
                entry.dll, entry.import, entry.implementation
            ));
        }
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_coverage_report_is_not_empty() {
        let report = generate_import_coverage_report();
        assert!(report.total_imports > 0, "report should have imports");
        assert!(
            report.covered_imports > 0,
            "report should have covered imports"
        );
        assert!(
            !report.dll_reports.is_empty(),
            "report should have per-DLL breakdowns"
        );
    }

    #[test]
    fn test_coverage_json_is_valid() {
        let json = generate_import_coverage_json();
        assert!(json.is_object(), "JSON should be an object");
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("total_imports"));
        assert!(obj.contains_key("covered_imports"));
        assert!(obj.contains_key("missing_imports"));
        assert!(obj.contains_key("overall_coverage_percent"));
        assert!(obj.contains_key("dlls"));
        assert!(obj.contains_key("entries"));
    }

    #[test]
    fn test_coverage_text_is_readable() {
        let text = generate_import_coverage_text();
        assert!(text.contains("Steam.exe Import Coverage Report"));
        assert!(text.contains("Overall:"));
        assert!(text.contains("DLL"));
    }

    #[test]
    fn test_steam_exe_imports_contains_known_dlls() {
        let imports = steam_exe_imports_regression_snapshot();
        assert!(imports.contains_key("kernel32.dll"));
        assert!(imports.contains_key("user32.dll"));
        assert!(imports.contains_key("gdi32.dll"));
        assert!(imports.contains_key("advapi32.dll"));
        assert!(imports.contains_key("shell32.dll"));
        assert!(imports.contains_key("ole32.dll"));
        assert!(imports.contains_key("crypt32.dll"));
    }

    #[test]
    fn test_steam_exe_imports_are_unique_and_attributed() {
        let imports = steam_exe_imports_regression_snapshot();
        for (dll, functions) in &imports {
            let mut seen = std::collections::HashSet::new();
            for func in functions {
                assert!(seen.insert(func), "duplicate import {func} in {dll}");
            }
        }

        let kernel32 = imports.get("kernel32.dll").unwrap();
        assert_eq!(
            kernel32
                .iter()
                .filter(|f| *f == "WaitForSingleObject")
                .count(),
            1,
            "WaitForSingleObject must not be duplicated"
        );
        assert_eq!(
            kernel32.iter().filter(|f| *f == "GetTickCount64").count(),
            1,
            "GetTickCount64 must not be duplicated"
        );
        assert!(
            !kernel32.contains(&"GetUserNameA".to_string())
                && !kernel32.contains(&"GetUserNameW".to_string()),
            "GetUserNameA/W are advapi32 exports, not kernel32"
        );

        let shell32 = imports.get("shell32.dll").unwrap();
        assert!(
            !shell32.contains(&"DoDragDrop".to_string()),
            "DoDragDrop is an ole32 export, not shell32"
        );

        let advapi32 = imports.get("advapi32.dll").unwrap();
        assert!(
            advapi32.contains(&"GetUserNameA".to_string())
                && advapi32.contains(&"GetUserNameW".to_string()),
            "GetUserNameA/W must be listed under advapi32"
        );

        let ole32 = imports.get("ole32.dll").unwrap();
        assert!(
            ole32.contains(&"DoDragDrop".to_string()),
            "DoDragDrop must be listed under ole32"
        );
    }

    #[test]
    fn test_coverage_is_derived_from_authoritative_export_registry() {
        // The report must track the real PE runtime export registry, not a
        // hand-maintained copy: any drift between the two fails CI.
        let report = generate_import_coverage_report();
        let registry = crate::pe_runtime::export_tables();

        let mut expected_total = 0usize;
        let mut expected_covered = 0usize;
        for (dll, functions) in steam_exe_imports_regression_snapshot() {
            expected_total += functions.len();
            let exports = registry.get(&dll);
            for func in &functions {
                let covered = exports.is_some_and(|table| {
                    table
                        .iter()
                        .any(|e| e.name.as_deref() == Some(func.as_str()))
                });
                if covered {
                    expected_covered += 1;
                }
            }
        }

        assert_eq!(report.total_imports, expected_total);
        assert_eq!(report.covered_imports, expected_covered);
        assert_eq!(report.missing_imports, expected_total - expected_covered);
    }

    #[test]
    fn test_kernel32_has_core_functions() {
        let imports = steam_exe_imports_regression_snapshot();
        let kernel32 = imports.get("kernel32.dll").unwrap();
        assert!(kernel32.contains(&"GetProcAddress".to_string()));
        assert!(kernel32.contains(&"LoadLibraryA".to_string()));
        assert!(kernel32.contains(&"CreateFileW".to_string()));
        assert!(kernel32.contains(&"GetLastError".to_string()));
    }

    #[test]
    fn test_pe_coverage_report_with_empty_pe() {
        let pe = crate::pe::ParsedPe {
            machine: 0,
            number_of_sections: 0,
            characteristics: 0,
            optional_header_magic: 0,
            subsystem: 0,
            dll_characteristics: 0,
            address_of_entry_point: 0,
            image_base: 0,
            size_of_image: 0,
            size_of_headers: 0,
            section_alignment: 0,
            file_alignment: 0,
            data_directories: vec![],
            sections: vec![],
            debug_entries: vec![],
            load_config: None,
            imports: vec![],
            delay_imports: vec![],
            exports: vec![],
            relocations: vec![],
            tls_directory: None,
            version_info: crate::pe::VersionInfo::default(),
            embedded_manifest: None,
            external_manifest: None,
            is_dotnet: false,
            clr_header: None,
            bound_imports: vec![],
        };
        let export_tables = BTreeMap::new();
        let report = generate_pe_coverage_report(&pe, &export_tables);
        assert_eq!(report.total_imports, 0);
        assert_eq!(report.covered_imports, 0);
        assert_eq!(report.missing_imports, 0);
    }

    #[test]
    fn test_dll_coverage_report_builder() {
        let mut builder = DllCoverageReportBuilder::new("test.dll".to_string());
        builder.add("Func1".to_string(), true);
        builder.add("Func2".to_string(), false);
        builder.add("Func3".to_string(), true);
        let report = builder.build();
        assert_eq!(report.dll, "test.dll");
        assert_eq!(report.total, 3);
        assert_eq!(report.covered, 2);
        assert_eq!(report.missing, 1);
        assert!((report.coverage_percent - 66.66666666666667).abs() < 0.01);
    }

    // -----------------------------------------------------------------
    // Canonical fixture-derived coverage tests
    // -----------------------------------------------------------------

    /// Path to the tracked Steam.exe fixture (committed to the repo).
    fn tracked_steam_fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("ges")
            .join("steam")
            .join("drive_c")
            .join("Steam")
            .join("Steam.exe")
    }

    #[test]
    fn test_tracked_steam_fixture_parses() {
        let path = tracked_steam_fixture();
        assert!(
            path.is_file(),
            "tracked Steam fixture missing at {}",
            path.display()
        );
        let pe = crate::pe::parse_from_file(&path).expect("parse Steam.exe");
        assert!(pe.machine != 0, "PE machine field must be set");
        assert!(
            !pe.imports.is_empty(),
            "Steam.exe must import from at least one DLL"
        );
    }

    #[test]
    fn test_coverage_for_steam_fixture_covers_all_imports() {
        let report = coverage_for_steam_fixture(&tracked_steam_fixture()).expect("coverage report");
        assert!(
            report.total_imports > 300,
            "unexpectedly small import surface"
        );
        assert!(!report.steam_sha256.is_empty());
        assert!(
            report.by_implementation.values().sum::<usize>() == report.total_imports,
            "by_implementation must account for every import"
        );
        // The fixture's imports must all be classified (no import may fall
        // through to an unclassified default).
        assert!(
            report.entries.iter().all(|e| !e.import.is_empty()),
            "every entry must carry an import name"
        );
        // No entry may be marked invoked without the flag.
        assert!(
            report.entries.iter().all(|e| !e.invoked_in_e2e),
            "invoked_in_e2e must be false without an invoked set"
        );
    }

    #[test]
    fn test_coverage_for_steam_fixture_json_roundtrip() {
        let json = coverage_for_steam_fixture_json(&tracked_steam_fixture()).expect("json report");
        let obj = json.as_object().expect("object");
        for key in [
            "steam_exe_path",
            "steam_sha256",
            "image_version",
            "total_imports",
            "by_implementation",
            "entries",
            "critical_not_working",
            "invoked_in_e2e",
        ] {
            assert!(obj.contains_key(key), "missing report field {key}");
        }
        let entries = obj["entries"].as_array().expect("entries array");
        let first = entries.first().expect("at least one entry");
        for key in [
            "steam_sha256",
            "image_version",
            "dll",
            "import",
            "implementation",
            "steam_critical",
            "invoked_in_e2e",
        ] {
            assert!(
                first.as_object().unwrap().contains_key(key),
                "missing entry field {key}"
            );
        }
    }

    #[test]
    fn test_coverage_for_steam_fixture_with_invoked_marks_entries() {
        let invoked = vec!["CreateFileW".to_string(), "GetProcAddress".to_string()];
        let report = coverage_for_steam_fixture_with_invoked(&tracked_steam_fixture(), &invoked)
            .expect("coverage report");
        assert!(report.invoked_in_e2e);
        let marked: Vec<_> = report
            .entries
            .iter()
            .filter(|entry| entry.invoked_in_e2e)
            .map(|entry| entry.import.as_str())
            .collect();
        assert_eq!(marked, vec!["CreateFileW", "GetProcAddress"]);
        // No violation may be reported for these two implemented APIs.
        assert!(
            report.invoked_critical_violations().is_empty(),
            "implemented APIs must not violate the release gate"
        );
    }

    #[test]
    fn test_invoked_api_names_from_trace_dedups() {
        let events = vec![
            crate::trace::TraceEvent {
                event_index: 1,
                category: "process".to_string(),
                call_id: "GetModuleHandleW".to_string(),
                parameters: BTreeMap::new(),
                return_value: json!(0),
                get_last_error: None,
                side_effect_hashes: vec![],
            },
            crate::trace::TraceEvent {
                event_index: 2,
                category: "process".to_string(),
                call_id: "GetModuleHandleW".to_string(),
                parameters: BTreeMap::new(),
                return_value: json!(0),
                get_last_error: None,
                side_effect_hashes: vec![],
            },
            crate::trace::TraceEvent {
                event_index: 3,
                category: "file".to_string(),
                call_id: "CreateFileW".to_string(),
                parameters: BTreeMap::new(),
                return_value: json!(1),
                get_last_error: None,
                side_effect_hashes: vec![],
            },
        ];
        let names = invoked_api_names_from_trace(&events);
        assert_eq!(
            names,
            vec!["CreateFileW".to_string(), "GetModuleHandleW".to_string()]
        );
    }

    #[test]
    fn test_coverage_for_steam_fixture_text_is_structured() {
        let text = coverage_for_steam_fixture_text(&tracked_steam_fixture()).expect("text report");
        assert!(text.contains("Steam.exe Import Coverage (fixture-derived)"));
        assert!(text.contains("sha256:"));
        assert!(text.contains("Implemented"));
        assert!(text.contains("Unsupported"));
    }

    #[test]
    fn test_critical_not_working_invariant_and_release_gate() {
        let report = coverage_for_steam_fixture(&tracked_steam_fixture()).expect("coverage report");
        // Every entry in critical_not_working must be steam-critical with a
        // non-working implementation.
        assert!(report.critical_not_working.iter().all(
            |entry| entry.steam_critical && !entry.implementation.has_working_implementation()
        ));
        // The tracked fixture's bootstrap-critical surface is fully working:
        // the bootstrapper does not import any steam-critical API that lacks
        // a host thunk, so the static surface has no violations and the
        // release gate (over the empty invoked set) is trivially satisfied.
        assert!(
            report.critical_not_working.is_empty(),
            "unexpected static violations: {:#?}",
            report.critical_not_working
        );
        assert!(
            report.invoked_critical_violations().is_empty(),
            "invoked critical violations must be empty"
        );
        // Sanity: steam-critical entries ARE present and marked.
        let create_file = report
            .entries
            .iter()
            .find(|entry| entry.import == "CreateFileW")
            .expect("CreateFileW import");
        assert!(create_file.steam_critical);
        assert_eq!(create_file.implementation, ImplementationLevel::Implemented);
    }
}
