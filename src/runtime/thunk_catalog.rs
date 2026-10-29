//! `HostThunk` import-name catalog (verbatim).

use super::*;

impl HostThunk {
    /// Patch 6b: shared name → thunk table for the CRT-family DLLs
    /// (ucrtbase.dll / msvcrt.dll).  Only names not covered by the explicit
    /// arms above belong here.
    pub(crate) fn crt_thunk_from_name(name: &str) -> Option<Self> {
        use HostThunk::*;
        Some(match name {
            "_errno" | "__errno" => CrtErrno,
            "_doserrno" => CrtDoserrno,
            "_get_errno" => GetErrno,
            "_set_errno" => SetErrno,
            "__stdio_common_vsnprintf_s" => StdioCommonVsnprintfS,
            "__stdio_common_vsprintf_s" => StdioCommonVsprintfS,
            "__stdio_common_vsnprintf" => StdioCommonVsnprintf,
            "memcpy" => Memcpy,
            "memmove" => Memmove,
            "memset" => Memset,
            "memcmp" => Memcmp,
            "memchr" => Memchr,
            "strcpy" => Strcpy,
            "strncpy" => Strncpy,
            "strlen" => Strlen,
            "strcat" => Strcat,
            "strncat" => Strncat,
            "strcmp" => Strcmp,
            "strncmp" => Strncmp,
            "strchr" => Strchr,
            "strstr" => Strstr,
            "strrchr" => Strrchr,
            "wcsncmp" => Wcsncmp,
            "_stricmp" => Stricmp,
            "_strnicmp" => Strnicmp,
            "strerror" => Strerror,
            "_strerror" => StrerrorPrefix,
            "wcslen" => Wcslen,
            "wcscpy" => Wcscpy,
            "wcscat" => Wcscat,
            "wcscmp" => Wcscmp,
            "wcsncpy" => Wcsncpy,
            "wcsrchr" => Wcsrchr,
            "wcschr" => Wcschr,
            "wcsstr" => Wcsstr,
            "wcsnlen" => Wcsnlen,
            "_wcsicmp" => Wcsicmp,
            "_wcsnicmp" => Wcsnicmp,
            "strcpy_s" => StrcpyS,
            "strncpy_s" => StrncpyS,
            "strcat_s" => StrcatS,
            "strncat_s" => StrncatS,
            "memcpy_s" => MemcpyS,
            "memmove_s" => MemmoveS,
            "wcscpy_s" => WcscpyS,
            "wcsncpy_s" => WcsncpyS,
            "isalpha" => Isalpha,
            "isdigit" => Isdigit,
            "isalnum" => Isalnum,
            "isxdigit" => Isxdigit,
            "isspace" => Isspace,
            "isupper" => Isupper,
            "islower" => Islower,
            "ispunct" => Ispunct,
            "isprint" => Isprint,
            "isgraph" => Isgraph,
            "iscntrl" => Iscntrl,
            "tolower" => Tolower,
            "toupper" => Toupper,
            "atoi" => Atoi,
            "atol" => Atol,
            "atof" => Atof,
            "atan2" => CrtAtan2,
            "ceil" => CrtCeil,
            "cos" => CrtCos,
            "exp" => CrtExp,
            "fabs" => CrtFabs,
            "floor" => CrtFloor,
            "log" => CrtLog,
            "pow" => CrtPow,
            "sin" => CrtSin,
            "sqrt" => CrtSqrt,
            "tan" => CrtTan,
            "printf" => CrtPrintf,
            "sprintf" => CrtSprintf,
            "vsprintf" => CrtVsprintf,
            "sscanf" => CrtSscanf,
            "strtol" => Strtol,
            "strtoul" => Strtoul,
            "_strtoi64" => Strtoi64,
            "_strtoi64_s" => Strtoi64S,
            "_strtoui64" => Strtoui64,
            "_strtoui64_s" => Strtoui64S,
            "abs" => Abs,
            "labs" => Labs,
            "div" => Div,
            "ldiv" => Ldiv,
            "qsort" => Qsort,
            "bsearch" => Bsearch,
            "_getcwd" => Getcwd,
            "_wgetcwd" => Wgetcwd,
            "_chdir" => Chdir,
            "_wchdir" => Wchdir,
            "_access" => Access,
            "_waccess" => Waccess,
            "_chmod" => Chmod,
            "_wchmod" => Wchmod,
            "_stat" => Stat,
            "_wstat" => Wstat,
            "_stat64" => Stat64,
            "_wstat64" => Wstat64,
            "fstat" | "_fstat" => Fstat,
            "_fstat64" => Fstat64,
            "getenv" => Getenv,
            "_wgetenv" => Wgetenv,
            "_dupenv_s" => DupenvS,
            "_wdupenv_s" => WdupenvS,
            "_putenv" => Putenv,
            "_wputenv" => Wputenv,
            "_splitpath" => Splitpath,
            "_wsplitpath" => Wsplitpath,
            "_splitpath_s" => SplitpathS,
            "_wsplitpath_s" => WsplitpathS,
            "_makepath" => Makepath,
            "_wmakepath" => Wmakepath,
            "_makepath_s" => MakepathS,
            "_wmakepath_s" => WmakepathS,
            "rand" => Rand,
            "srand" => Srand,
            "clock" => Clock,
            "time" => Time,
            "_time64" => Time64,
            "_beginthreadex" => Beginthreadex,
            "_endthreadex" => Endthreadex,
            "_beginthread" => Beginthread,
            "_endthread" => Endthread,
            "fopen" => Fopen,
            "_wfopen" => Wfopen,
            "fopen_s" => FopenS,
            "_wfopen_s" => WfopenS,
            "_fsopen" => Fsopen,
            "freopen" => Freopen,
            "_fdopen" => Fdopen,
            "fclose" => Fclose,
            "fflush" => Fflush,
            "fread" => Fread,
            "fgets" => Fgets,
            "fputs" => Fputs,
            "fgetc" => Fgetc,
            "fputc" => Fputc,
            "fseek" => Fseek,
            "ftell" => Ftell,
            "fread_s" => FreadS,
            "fwrite_s" => FwriteS,
            "_fcloseall" => Fcloseall,
            "_flushall" => Flushall,
            "_lock" => Lock,
            "_unlock" => Unlock,
            "_fileno" => Fileno,
            "_filelength" => Filelength,
            "_filelengthi64" => Filelengthi64,
            "_chsize" => Chsize,
            "_isatty" => Isatty,
            "_commit" => Commit,
            _ => return None,
        })
    }

    /// Patch 6c: name → thunk table for the vcruntime140.dll family.  The
    /// exports are the CRT string/memory primitives (identical semantics to
    /// the ucrtbase/msvcrt names), so the shared CRT table covers them.
    pub(crate) fn vcrt_thunk_from_name(name: &str) -> Option<Self> {
        let thunk = Self::crt_thunk_from_name(name)?;
        // Only the exports the runtime actually registers for vcruntime140.dll
        // belong to this table (the shared table covers many more names that
        // vcruntime140.dll does not export).
        match name {
            "memcpy" | "memmove" | "memset" | "strchr" | "strlen" | "strncmp" | "strncpy"
            | "strrchr" | "strstr" | "wcschr" | "wcslen" | "wcsncmp" | "wcsncpy" | "wcsrchr"
            | "wcsstr" => Some(thunk),
            _ => None,
        }
    }

    /// Patch 6c: name → thunk table for msvcp140.dll (the MSVC C++ runtime
    /// helper surface: C11 threads wrappers, STL throw helpers and the
    /// random_device entropy pair).
    pub(crate) fn msvcp_thunk_from_name(name: &str) -> Option<Self> {
        use HostThunk::*;
        Some(match name {
            "_Cnd_broadcast" => MsvcpCndBroadcast,
            "_Cnd_destroy" => MsvcpCndDestroy,
            "_Cnd_init" => MsvcpCndInit,
            "_Cnd_signal" => MsvcpCndSignal,
            "_Cnd_wait" => MsvcpCndWait,
            "_Mtx_current" => MsvcpMtxCurrent,
            "_Mtx_destroy" => MsvcpMtxDestroy,
            "_Mtx_init" => MsvcpMtxInit,
            "_Mtx_lock" => MsvcpMtxLock,
            "_Mtx_reset" => MsvcpMtxReset,
            "_Mtx_unlock" => MsvcpMtxUnlock,
            "_Xbad_alloc" => MsvcpXbadAlloc,
            "_Xinvalid_argument" => MsvcpXinvalidArgument,
            "_Xlength_error" => MsvcpXlengthError,
            "_Xout_of_range" => MsvcpXoutOfRange,
            "_Xoverflow_error" => MsvcpXoverflowError,
            "_Xruntime_error" => MsvcpXruntimeError,
            "std::_Throw_C_error" => MsvcpThrowCError,
            "std::_Throw_Cpp_error" => MsvcpThrowCppError,
            "std::random_device::_Get" => MsvcpRandomDeviceGet,
            "std::random_device::_Init" => MsvcpRandomDeviceInit,
            _ => return None,
        })
    }

    pub(crate) fn from_import(import: &ResolvedImport) -> Self {
        let dll = import.resolved_module.to_ascii_lowercase();
        match (&dll[..], &import.symbol) {
            ("tbs.dll", ImportSymbol::ByName { name, .. }) if name == "Tbsi_Context_Create" => {
                Self::TbsiContextCreate
            }
            ("tbs.dll", ImportSymbol::ByName { name, .. }) if name == "Tbsip_Submit_Command" => {
                Self::TbsipSubmitCommand
            }
            ("tbs.dll", ImportSymbol::ByName { name, .. }) if name == "Tbsip_Context_Close" => {
                Self::TbsipContextClose
            }
            ("dxgi.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDXGIFactory1" => {
                Self::CreateDXGIFactory1
            }
            ("dxgi.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDXGIFactory2" => {
                Self::CreateDXGIFactory2
            }
            ("d3d11.dll", ImportSymbol::ByName { name, .. }) if name == "D3D11CreateDevice" => {
                Self::D3D11CreateDevice
            }
            ("d3d11.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D11CreateDeviceAndSwapChain" =>
            {
                Self::D3D11CreateDeviceAndSwapChain
            }
            ("d3d12.dll", ImportSymbol::ByName { name, .. }) if name == "D3D12CreateDevice" => {
                Self::D3D12CreateDevice
            }
            ("dml.dll", ImportSymbol::ByName { name, .. }) if name == "DMLCreateDevice" => {
                Self::DMLCreateDevice
            }
            ("dml.dll", ImportSymbol::ByName { name, .. }) if name == "DMLCreateDevice1" => {
                Self::DMLCreateDevice1
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "Direct3DCreate9" => {
                Self::Direct3DCreate9
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "Direct3DCreate9Ex" => {
                Self::Direct3DCreate9Ex
            }
            ("xaudio2_9.dll", ImportSymbol::ByName { name, .. }) if name == "XAudio2Create" => {
                Self::XAudio2Create
            }
            ("xaudio2_9redist.dll", ImportSymbol::ByName { name, .. })
                if name == "XAudio2Create" =>
            {
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
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetClassInfoExW" => {
                Self::GetClassInfoExW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDlgItem" => {
                Self::GetDlgItem
            }
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
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "RedrawWindow" => {
                Self::RedrawWindow
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
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadIconW" => {
                Self::LoadIconW
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
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MonitorFromWindow" => {
                Self::MonitorFromWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MonitorFromRect" => {
                Self::MonitorFromRect
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EnumDisplayMonitors" => {
                Self::EnumDisplayMonitors
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EnumDisplayDevicesW" => {
                Self::EnumDisplayDevicesW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMonitorInfoW" => {
                Self::GetMonitorInfoW
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
            // I2 — Menus
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateMenu" => {
                Self::CreateMenu
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DestroyMenu" => {
                Self::DestroyMenu
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "InsertMenuW" => {
                Self::InsertMenuW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "InsertMenuItemW" => {
                Self::InsertMenuItemW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ModifyMenuW" => {
                Self::ModifyMenuW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "RemoveMenu" => {
                Self::RemoveMenu
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMenu" => Self::GetMenu,
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetMenu" => Self::SetMenu,
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSubMenu" => {
                Self::GetSubMenu
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMenuItemCount" => {
                Self::GetMenuItemCount
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMenuItemID" => {
                Self::GetMenuItemID
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMenuState" => {
                Self::GetMenuState
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMenuStringW" => {
                Self::GetMenuStringW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DrawMenuBar" => {
                Self::DrawMenuBar
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CheckMenuItem" => {
                Self::CheckMenuItem
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "HiliteMenuItem" => {
                Self::HiliteMenuItem
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadMenuW" => {
                Self::LoadMenuW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadMenuIndirectW" => {
                Self::LoadMenuIndirectW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "PostQuitMessage" => {
                Self::PostQuitMessage
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "PostThreadMessageW" => {
                Self::PostThreadMessageW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetTimer" => {
                Self::SetTimer
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "AnimateWindow" => {
                Self::AnimateWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DrawAnimatedRects" => {
                Self::DrawAnimatedRects
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "SystemParametersInfoW" =>
            {
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
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMessageW" => {
                Self::GetMessageW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetMessageA" => {
                Self::GetMessageA
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "PostMessageA" => {
                Self::PostMessageA
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "PostMessageW" => {
                Self::PostMessageW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFocus" => {
                Self::GetFocus
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetFocus" => {
                Self::SetFocus
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowTextA" => {
                Self::GetWindowTextA
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "TranslateMessage" => {
                Self::TranslateMessage
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
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDC" => Self::GetDC,
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseDC" => {
                Self::ReleaseDC
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "FillRect" => {
                Self::FillRect
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "DrawTextW" => {
                Self::DrawTextW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "DrawTextExW" => {
                Self::DrawTextExW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDCW" => {
                Self::CreateDCW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateCompatibleBitmap" =>
            {
                Self::CreateCompatibleBitmap
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetObjectW" => {
                Self::GetObjectW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetPixel" => {
                Self::GetPixel
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetPixel" => {
                Self::SetPixel
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCharWidthW" => {
                Self::GetCharWidthW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetGlyphOutlineW" => {
                Self::GetGlyphOutlineW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "Ellipse" => Self::Ellipse,
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "InvertRect" => {
                Self::InvertRect
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetRgnBox" => {
                Self::GetRgnBox
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CombineRgn" => {
                Self::CombineRgn
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "AlphaBlend" => {
                Self::AlphaBlend
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "TransparentBlt" => {
                Self::TransparentBlt
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GdiFlush" => {
                Self::GdiFlush
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GdiComment" => {
                Self::GdiComment
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SelectObject" => {
                Self::SelectObject
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFontW" => {
                Self::CreateFontW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFontIndirectW" => {
                Self::CreateFontIndirectW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteObject" => {
                Self::DeleteObject
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetBkMode" => {
                Self::SetBkMode
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetTextColor" => {
                Self::SetTextColor
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetBkColor" => {
                Self::SetBkColor
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetStockObject" => {
                Self::GetStockObject
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateSolidBrush" => {
                Self::CreateSolidBrush
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "FrameRect" => {
                Self::FrameRect
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreatePen" => {
                Self::CreatePen
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateRectRgn" => {
                Self::CreateRectRgn
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateRoundRectRgn" => {
                Self::CreateRoundRectRgn
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetMapMode" => {
                Self::SetMapMode
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTextMetricsW" => {
                Self::GetTextMetricsW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "ExtTextOutW" => {
                Self::ExtTextOutW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTextExtentPoint32A" => {
                Self::GetTextExtentPoint32A
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTextExtentPoint32W" => {
                Self::GetTextExtentPoint32W
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTextExtentExPointW" => {
                Self::GetTextExtentExPointW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetRect" => Self::SetRect,
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CopyRect" => {
                Self::CopyRect
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "InflateRect" => {
                Self::InflateRect
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "OffsetRect" => {
                Self::OffsetRect
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "PatBlt" => Self::PatBlt,
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "BitBlt" => Self::BitBlt,
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "StretchBlt" => {
                Self::StretchBlt
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "Rectangle" => {
                Self::Rectangle
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTextColor" => {
                Self::GetTextColor
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetBkColor" => {
                Self::GetBkColor
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetBkMode" => {
                Self::GetBkMode
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "MoveToEx" => {
                Self::MoveToEx
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "LineTo" => Self::LineTo,
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DrawTextA" => {
                Self::DrawTextA
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DrawTextW" => {
                Self::DrawTextW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "wsprintfW" => {
                Self::WsprintfW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetCurrentDirectoryW" =>
            {
                Self::SetCurrentDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCurrentDirectoryW" =>
            {
                Self::GetCurrentDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFullPathNameW" => {
                Self::GetFullPathNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "MulDiv" => Self::MulDiv,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileAttributesW" => {
                Self::GetFileAttributesW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetFileAttributesExW" =>
            {
                Self::GetFileAttributesExW
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
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetDefaultDllDirectories" =>
            {
                Self::SetDefaultDllDirectories
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetSystemDirectoryW" =>
            {
                Self::GetSystemDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetWindowsDirectoryW" =>
            {
                Self::GetWindowsDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTempPathW" => {
                Self::GetTempPathW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTempPath2W" => {
                Self::GetTempPath2W
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTempFileNameW" => {
                Self::GetTempFileNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleFileNameA" => {
                Self::GetModuleFileNameA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleFileNameW" => {
                Self::GetModuleFileNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDiskFreeSpaceW" => {
                Self::GetDiskFreeSpaceW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetDiskFreeSpaceExW" =>
            {
                Self::GetDiskFreeSpaceExW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileSize" => {
                Self::GetFileSize
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteFileW" => {
                Self::DeleteFileW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "WritePrivateProfileStringW" =>
            {
                Self::WritePrivateProfileStringW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateProcessW" => {
                Self::CreateProcessW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateProcessA" => {
                Self::CreateProcessA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateNamedPipeW" => {
                Self::CreateNamedPipeW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ConnectNamedPipe" => {
                Self::ConnectNamedPipe
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "DisconnectNamedPipe" =>
            {
                Self::DisconnectNamedPipe
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CallNamedPipeW" => {
                Self::CallNamedPipeW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WaitNamedPipeW" => {
                Self::WaitNamedPipeW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetNamedPipeInfo" => {
                Self::GetNamedPipeInfo
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetNamedPipeHandleState" =>
            {
                Self::SetNamedPipeHandleState
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "PeekNamedPipe" => {
                Self::PeekNamedPipe
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFileMappingW" => {
                Self::CreateFileMappingW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "MapViewOfFile" => {
                Self::MapViewOfFile
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "UnmapViewOfFile" => {
                Self::UnmapViewOfFile
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenProcess" => {
                Self::OpenProcess
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "WaitForMultipleObjects" =>
            {
                Self::WaitForMultipleObjects
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateThread" => {
                Self::CreateThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateIoCompletionPort" =>
            {
                Self::CreateIoCompletionPort
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "PostQueuedCompletionStatus" =>
            {
                Self::PostQueuedCompletionStatus
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetQueuedCompletionStatus" =>
            {
                Self::GetQueuedCompletionStatus
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetQueuedCompletionStatusEx" =>
            {
                Self::GetQueuedCompletionStatusEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetFileCompletionNotificationModes" =>
            {
                Self::SetFileCompletionNotificationModes
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateEventA" => {
                Self::CreateEventA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateEventW" => {
                Self::CreateEventW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenEventA" => {
                Self::OpenEventA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenEventW" => {
                Self::OpenEventW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetEvent" => {
                Self::SetEvent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ResetEvent" => {
                Self::ResetEvent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "IsDebuggerPresent" => {
                Self::IsDebuggerPresent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CheckRemoteDebuggerPresent" =>
            {
                Self::CheckRemoteDebuggerPresent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetSystemFirmwareTable" =>
            {
                Self::GetSystemFirmwareTable
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetVolumeInformationW" =>
            {
                Self::GetVolumeInformationW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitOnceBeginInitialize" =>
            {
                Self::InitOnceBeginInitialize
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitOnceComplete" => {
                Self::InitOnceComplete
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitOnceExecuteOnce" =>
            {
                Self::InitOnceExecuteOnce
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "InitializeSRWLock" => {
                Self::InitializeSRWLock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "AcquireSRWLockExclusive" =>
            {
                Self::AcquireSRWLockExclusive
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "ReleaseSRWLockExclusive" =>
            {
                Self::ReleaseSRWLockExclusive
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "AcquireSRWLockShared" =>
            {
                Self::AcquireSRWLockShared
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "ReleaseSRWLockShared" =>
            {
                Self::ReleaseSRWLockShared
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "TryAcquireSRWLockExclusive" =>
            {
                Self::TryAcquireSRWLockExclusive
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "TryAcquireSRWLockShared" =>
            {
                Self::TryAcquireSRWLockShared
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "WaitForSingleObject" =>
            {
                Self::WaitForSingleObject
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetExitCodeThread" => {
                Self::GetExitCodeThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetExitCodeProcess" => {
                Self::GetExitCodeProcess
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TerminateProcess" => {
                Self::TerminateProcess
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryA" => {
                Self::LoadLibraryA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryW" => {
                Self::LoadLibraryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryExA" => {
                Self::LoadLibraryExA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryExW" => {
                Self::LoadLibraryExW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FreeLibrary" => {
                Self::FreeLibrary
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrlenA" => {
                Self::Strlen
            }
            ("kernel32.dll", ImportSymbol::ByOrdinal { ordinal: 17 }) => Self::CreateFileW,
            ("comctl32.dll", ImportSymbol::ByOrdinal { ordinal: 17 }) => Self::InitCommonControls,
            ("asycfilt.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("asycfilt.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("browseui.dll", ImportSymbol::ByName { name, .. })
                if name == "SHCreateExplorerTaskband" =>
            {
                Self::ShCreateExplorerTaskband
            }
            ("browseui.dll", ImportSymbol::ByName { name, .. }) if name == "SHOpenFolderWindow" => {
                Self::ShOpenFolderWindow
            }
            ("credssp.dll", ImportSymbol::ByName { name, .. })
                if name == "CredSSPGetClientCredential" =>
            {
                Self::CredSspGetClientCredential
            }
            ("credssp.dll", ImportSymbol::ByName { name, .. })
                if name == "CredSSPGetServerCredential" =>
            {
                Self::CredSspGetServerCredential
            }
            ("cryptdlg.dll", ImportSymbol::ByName { name, .. }) if name == "CertDigestDigest" => {
                Self::CertDigestDigest
            }
            ("cryptdlg.dll", ImportSymbol::ByName { name, .. })
                if name == "CertSelectCertificate" =>
            {
                Self::CertSelectCertificate
            }
            ("dplay.dll", ImportSymbol::ByName { name, .. }) if name == "DirectPlayCreate" => {
                Self::DirectPlayCreate
            }
            ("dplay.dll", ImportSymbol::ByName { name, .. }) if name == "DirectPlayEnumerateW" => {
                Self::DirectPlayEnumerateW
            }
            ("ir50_qc.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("ir50_qc.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("ir50_qcx.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("ir50_qcx.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("kerberos.dll", ImportSymbol::ByName { name, .. }) if name == "KerbLogon" => {
                Self::KerbLogon
            }
            ("kerberos.dll", ImportSymbol::ByName { name, .. }) if name == "KerbRetrieveTicket" => {
                Self::KerbRetrieveTicket
            }
            ("mscorlib.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("mscorlib.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("msimtf.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("msimtf.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("msmdlocal.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("msmdlocal.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("mtxdm.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("mtxdm.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("netutils.dll", ImportSymbol::ByName { name, .. }) if name == "NetGetAnyDCName" => {
                Self::NetGetAnyDcName
            }
            ("netutils.dll", ImportSymbol::ByName { name, .. }) if name == "NetGetDCName" => {
                Self::NetGetDcName
            }
            ("presentationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("presentationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("presentationframework.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("presentationframework.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("sens.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("sens.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("shdocvw.dll", ImportSymbol::ByName { name, .. }) if name == "SHCreateLinks" => {
                Self::ShCreateLinks
            }
            ("shdocvw.dll", ImportSymbol::ByName { name, .. })
                if name == "SHNavigateToFavorite" =>
            {
                Self::ShNavigateToFavorite
            }
            ("wbemdisp.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("wbemdisp.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("webview2.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("webview2.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("windowsbase.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("windowsbase.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("winrsmgr.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("winrsmgr.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("wkssvc.dll", ImportSymbol::ByName { name, .. }) if name == "NetWkstaGetInfo" => {
                Self::NetWkstaGetInfo
            }
            ("wkssvc.dll", ImportSymbol::ByName { name, .. }) if name == "NetWkstaSetInfo" => {
                Self::NetWkstaSetInfo
            }
            ("wmi.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("wmi.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("wuapi.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("wuapi.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("x3daudio1_7.dll", ImportSymbol::ByName { name, .. })
                if name == "X3DAudioCalculate" =>
            {
                Self::X3dAudioCalculate
            }
            ("x3daudio1_7.dll", ImportSymbol::ByName { name, .. })
                if name == "X3DAudioInitialize" =>
            {
                Self::X3dAudioInitialize
            }
            ("xactengine3_7.dll", ImportSymbol::ByName { name, .. })
                if name == "XACT3CreateEngine" =>
            {
                Self::Xact3CreateEngine
            }
            ("xactengine3_7.dll", ImportSymbol::ByName { name, .. })
                if name == "XACT3CreateEngineWithFlags" =>
            {
                Self::Xact3CreateEngineWithFlags
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtCreateFileMapping" => {
                Self::NtCreateFileMapping
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtCreateProcess" => {
                Self::NtCreateProcess
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "IMFAsyncResult" => {
                Self::ImfAsyncResult
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "IMFGetService" => {
                Self::ImfGetService
            }
            ("wsock32.dll", ImportSymbol::ByName { name, .. }) if name == "WSAStartup" => {
                Self::WsaStartup
            }
            ("browser.dll", ImportSymbol::ByName { name, .. }) if name == "BrowserServerEnum" => {
                Self::BrowserServerEnum
            }
            ("cngaudit.dll", ImportSymbol::ByName { name, .. }) if name == "CngAuditLog" => {
                Self::CngAuditLog
            }
            ("dpaddr.dll", ImportSymbol::ByName { name, .. }) if name == "DP8SPCreate" => {
                Self::Dp8spCreate
            }
            ("dpaddr.dll", ImportSymbol::ByName { name, .. })
                if name == "DirectPlay8AddressCreate" =>
            {
                Self::DirectPlay8AddressCreate
            }
            ("gdiplus.dll", ImportSymbol::ByName { name, .. }) if name == "GdipCreateGraphics" => {
                Self::GdipCreateGraphics
            }
            ("mmdevapi.dll", ImportSymbol::ByName { name, .. })
                if name == "ActivateAudioInterfaceAsync" =>
            {
                Self::ActivateAudioInterfaceAsync
            }
            ("msftedit.dll", ImportSymbol::ByName { name, .. })
                if name == "MsftEditRegisterClass" =>
            {
                Self::MsftEditRegisterClass
            }
            ("riched32.dll", ImportSymbol::ByName { name, .. })
                if name == "RichEditANSIWndClass" =>
            {
                Self::RichEditAnsiWndClass
            }
            ("srvsvc.dll", ImportSymbol::ByName { name, .. }) if name == "NetServerGetInfo" => {
                Self::NetServerGetInfo
            }
            ("w32topl.dll", ImportSymbol::ByName { name, .. }) if name == "DsBindToTopology" => {
                Self::DsBindToTopology
            }
            ("xaudio2_8.dll", ImportSymbol::ByName { name, .. }) if name == "XAudio2Create" => {
                Self::XAudio2Create
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "IPersistFile" => {
                Self::IPersistFile
            }
            ("mshtml.dll", ImportSymbol::ByName { name, .. }) if name == "IHTMLDocument2" => {
                Self::IhtmlDocument2
            }
            ("scrobj.dll", ImportSymbol::ByName { name, .. }) if name == "IActiveScript" => {
                Self::IActiveScript
            }
            ("d3d12.dll", ImportSymbol::ByName { name, .. }) if name == "ID3D12Heap" => {
                Self::ID3d12Heap
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "IMFMediaSink" => {
                Self::ImfMediaSink
            }
            ("atl.dll", ImportSymbol::ByName { name, .. }) if name == "AtlModuleAddTermFunc" => {
                Self::AtlModuleAddTermFunc
            }
            ("atl.dll", ImportSymbol::ByName { name, .. }) if name == "AtlModuleLoadTypeLib" => {
                Self::AtlModuleLoadTypeLib
            }
            ("atl.dll", ImportSymbol::ByName { name, .. }) if name == "AtlModuleRegisterServer" => {
                Self::AtlModuleRegisterServer
            }
            ("atl.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleRegisterTypeLib" =>
            {
                Self::AtlModuleRegisterTypeLib
            }
            ("atl.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleUnregisterServer" =>
            {
                Self::AtlModuleUnregisterServer
            }
            ("atl.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleUnregisterTypeLib" =>
            {
                Self::AtlModuleUnregisterTypeLib
            }
            ("atl.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleUpdateRegistryFromResource" =>
            {
                Self::AtlModuleUpdateRegistryFromResource
            }
            ("windowscodecsext.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateAvifDecoder" =>
            {
                Self::WicCreateAvifDecoder
            }
            ("windowscodecsext.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateAvifEncoder" =>
            {
                Self::WicCreateAvifEncoder
            }
            ("windowscodecsext.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateHeifDecoder" =>
            {
                Self::WicCreateHeifDecoder
            }
            ("windowscodecsext.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateHeifEncoder" =>
            {
                Self::WicCreateHeifEncoder
            }
            ("windowscodecsext.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateWebpDecoder" =>
            {
                Self::WicCreateWebpDecoder
            }
            ("windowscodecsext.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateWebpEncoder" =>
            {
                Self::WicCreateWebpEncoder
            }
            ("actxprxy.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("actxprxy.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("actxprxy.dll", ImportSymbol::ByName { name, .. }) if name == "DllInstall" => {
                Self::DllInstall
            }
            ("actxprxy.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("actxprxy.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("atl100.dll", ImportSymbol::ByName { name, .. }) if name == "AtlModuleAddTermFunc" => {
                Self::AtlModuleAddTermFunc
            }
            ("atl100.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleRegisterServer" =>
            {
                Self::AtlModuleRegisterServer
            }
            ("atl100.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleRegisterTypeLib" =>
            {
                Self::AtlModuleRegisterTypeLib
            }
            ("atl100.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleUnregisterServer" =>
            {
                Self::AtlModuleUnregisterServer
            }
            ("atl100.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleUnregisterTypeLib" =>
            {
                Self::AtlModuleUnregisterTypeLib
            }
            ("atl80.dll", ImportSymbol::ByName { name, .. }) if name == "AtlModuleAddTermFunc" => {
                Self::AtlModuleAddTermFunc
            }
            ("atl80.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleRegisterServer" =>
            {
                Self::AtlModuleRegisterServer
            }
            ("atl80.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleRegisterTypeLib" =>
            {
                Self::AtlModuleRegisterTypeLib
            }
            ("atl80.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleUnregisterServer" =>
            {
                Self::AtlModuleUnregisterServer
            }
            ("atl80.dll", ImportSymbol::ByName { name, .. })
                if name == "AtlModuleUnregisterTypeLib" =>
            {
                Self::AtlModuleUnregisterTypeLib
            }
            ("gameoverlayrenderer.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayCreateHook" =>
            {
                Self::OverlayCreateHook
            }
            ("gameoverlayrenderer.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayHookWindow" =>
            {
                Self::OverlayHookWindow
            }
            ("gameoverlayrenderer.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayPresent" =>
            {
                Self::OverlayPresent
            }
            ("gameoverlayrenderer.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayReset" =>
            {
                Self::OverlayReset
            }
            ("gameoverlayrenderer.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayUnhookWindow" =>
            {
                Self::OverlayUnhookWindow
            }
            ("gameoverlayrenderer64.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayCreateHook" =>
            {
                Self::OverlayCreateHook
            }
            ("gameoverlayrenderer64.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayHookWindow" =>
            {
                Self::OverlayHookWindow
            }
            ("gameoverlayrenderer64.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayPresent" =>
            {
                Self::OverlayPresent
            }
            ("gameoverlayrenderer64.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayReset" =>
            {
                Self::OverlayReset
            }
            ("gameoverlayrenderer64.dll", ImportSymbol::ByName { name, .. })
                if name == "OverlayUnhookWindow" =>
            {
                Self::OverlayUnhookWindow
            }
            ("msvcp140_1.dll", ImportSymbol::ByName { name, .. }) if name == "_Cnd_init" => {
                Self::CndInit
            }
            ("msvcp140_1.dll", ImportSymbol::ByName { name, .. }) if name == "_Mtx_destroy" => {
                Self::MtxDestroy
            }
            ("msvcp140_1.dll", ImportSymbol::ByName { name, .. }) if name == "_Mtx_init" => {
                Self::MtxInit
            }
            ("msvcp140_1.dll", ImportSymbol::ByName { name, .. }) if name == "_Mtx_lock" => {
                Self::MtxLock
            }
            ("msvcp140_1.dll", ImportSymbol::ByName { name, .. }) if name == "_Mtx_unlock" => {
                Self::MtxUnlock
            }
            ("msvcp140_2.dll", ImportSymbol::ByName { name, .. }) if name == "_Cnd_init" => {
                Self::CndInit
            }
            ("msvcp140_2.dll", ImportSymbol::ByName { name, .. }) if name == "_Mtx_destroy" => {
                Self::MtxDestroy
            }
            ("msvcp140_2.dll", ImportSymbol::ByName { name, .. }) if name == "_Mtx_init" => {
                Self::MtxInit
            }
            ("msvcp140_2.dll", ImportSymbol::ByName { name, .. }) if name == "_Mtx_lock" => {
                Self::MtxLock
            }
            ("msvcp140_2.dll", ImportSymbol::ByName { name, .. }) if name == "_Mtx_unlock" => {
                Self::MtxUnlock
            }
            ("steam.dll", ImportSymbol::ByName { name, .. }) if name == "Steam_BGetSteamID" => {
                Self::SteamBGetSteamId
            }
            ("steam.dll", ImportSymbol::ByName { name, .. })
                if name == "Steam_BIsSubscribedApp" =>
            {
                Self::SteamBIsSubscribedApp
            }
            ("steam.dll", ImportSymbol::ByName { name, .. }) if name == "Steam_BLoggedOn" => {
                Self::SteamBLoggedOn
            }
            ("steam.dll", ImportSymbol::ByName { name, .. }) if name == "Steam_NotifyOfLogin" => {
                Self::SteamNotifyOfLogin
            }
            ("steam.dll", ImportSymbol::ByName { name, .. }) if name == "Steam_NotifyOfLogoff" => {
                Self::SteamNotifyOfLogoff
            }
            ("vcruntime140_1.dll", ImportSymbol::ByName { name, .. })
                if name == "__C_specific_handler" =>
            {
                Self::CCSpecificHandler
            }
            ("vcruntime140_1.dll", ImportSymbol::ByName { name, .. })
                if name == "__current_exception" =>
            {
                Self::CurrentException
            }
            ("vcruntime140_1.dll", ImportSymbol::ByName { name, .. })
                if name == "__current_exception_context" =>
            {
                Self::CurrentExceptionContext
            }
            ("vcruntime140_1.dll", ImportSymbol::ByName { name, .. })
                if name == "__processing_throw" =>
            {
                Self::ProcessingThrow
            }
            ("vcruntime140_1.dll", ImportSymbol::ByName { name, .. }) if name == "_chkstk" => {
                Self::Chkstk
            }
            ("certcli.dll", ImportSymbol::ByName { name, .. }) if name == "CertSrvBackupEnd" => {
                Self::CertSrvBackupEnd
            }
            ("certcli.dll", ImportSymbol::ByName { name, .. })
                if name == "CertSrvBackupPrepare" =>
            {
                Self::CertSrvBackupPrepare
            }
            ("certcli.dll", ImportSymbol::ByName { name, .. }) if name == "CertSrvRestoreEnd" => {
                Self::CertSrvRestoreEnd
            }
            ("certcli.dll", ImportSymbol::ByName { name, .. })
                if name == "CertSrvRestorePrepare" =>
            {
                Self::CertSrvRestorePrepare
            }
            ("d3dx10_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX10CompileFromFile" =>
            {
                Self::D3dx10CompileFromFile
            }
            ("d3dx10_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX10CreateTextureFromFileW" =>
            {
                Self::D3dx10CreateTextureFromFileW
            }
            ("d3dx10_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX10GetImageInfoFromFile" =>
            {
                Self::D3dx10GetImageInfoFromFile
            }
            ("d3dx10_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX10SaveTextureToMemory" =>
            {
                Self::D3dx10SaveTextureToMemory
            }
            ("gameux.dll", ImportSymbol::ByName { name, .. }) if name == "GAMEUX_SHFOLDERPATH" => {
                Self::GameuxShfolderpath
            }
            ("gameux.dll", ImportSymbol::ByName { name, .. })
                if name == "GameExplorer_Initialize" =>
            {
                Self::GameExplorerInitialize
            }
            ("gameux.dll", ImportSymbol::ByName { name, .. })
                if name == "GameExplorer_SetUserAccess" =>
            {
                Self::GameExplorerSetUserAccess
            }
            ("gameux.dll", ImportSymbol::ByName { name, .. })
                if name == "GameExplorer_VerifyAccess" =>
            {
                Self::GameExplorerVerifyAccess
            }
            ("jscript.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("jscript.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("jscript.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("jscript.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("mscorwks.dll", ImportSymbol::ByName { name, .. })
                if name == "ClrCreateManagedInstance" =>
            {
                Self::ClrCreateManagedInstance
            }
            ("mscorwks.dll", ImportSymbol::ByName { name, .. }) if name == "CorBindToRuntime" => {
                Self::CorBindToRuntime
            }
            ("mscorwks.dll", ImportSymbol::ByName { name, .. }) if name == "CorBindToRuntimeEx" => {
                Self::CorBindToRuntimeEx
            }
            ("mscorwks.dll", ImportSymbol::ByName { name, .. }) if name == "GetCLRRuntimeHost" => {
                Self::GetClrRuntimeHost
            }
            ("mshtml.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateHTMLPropertyPage" =>
            {
                Self::CreateHtmlPropertyPage
            }
            ("mshtml.dll", ImportSymbol::ByName { name, .. })
                if name == "IEFrameFactory_Constructor" =>
            {
                Self::IeFrameFactoryConstructor
            }
            ("mshtml.dll", ImportSymbol::ByName { name, .. }) if name == "ShowHTMLDialogEx" => {
                Self::ShowHtmlDialogEx
            }
            ("mshtml.dll", ImportSymbol::ByName { name, .. }) if name == "IHTMLDocument2" => {
                Self::IhtmlDocument2
            }
            ("ntdsapi.dll", ImportSymbol::ByName { name, .. }) if name == "DsBind" => Self::DsBind,
            ("ntdsapi.dll", ImportSymbol::ByName { name, .. }) if name == "DsBindWithCred" => {
                Self::DsBindWithCred
            }
            ("ntdsapi.dll", ImportSymbol::ByName { name, .. }) if name == "DsMakeSpnW" => {
                Self::DsMakeSpnW
            }
            ("ntdsapi.dll", ImportSymbol::ByName { name, .. }) if name == "DsUnbind" => {
                Self::DsUnbind
            }
            ("vbscript.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("vbscript.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("vbscript.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("vbscript.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("wbemcomn.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("wbemcomn.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("wbemcomn.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("wbemcomn.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("activeds.dll", ImportSymbol::ByName { name, .. }) if name == "ADsBuildEnumerator" => {
                Self::AdsBuildEnumerator
            }
            ("activeds.dll", ImportSymbol::ByName { name, .. }) if name == "ADsGetObject" => {
                Self::AdsGetObject
            }
            ("activeds.dll", ImportSymbol::ByName { name, .. }) if name == "ADsOpenObject" => {
                Self::AdsOpenObject
            }
            ("audioendpoint.dll", ImportSymbol::ByName { name, .. })
                if name == "DllGetClassObject" =>
            {
                Self::DllGetClassObject
            }
            ("audioendpoint.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("audioendpoint.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("certadm.dll", ImportSymbol::ByName { name, .. }) if name == "CertSrvAdminGetCA" => {
                Self::CertSrvAdminGetCa
            }
            ("certadm.dll", ImportSymbol::ByName { name, .. }) if name == "CertSrvAdminGetCert" => {
                Self::CertSrvAdminGetCert
            }
            ("certadm.dll", ImportSymbol::ByName { name, .. }) if name == "CertSrvAdminSetCA" => {
                Self::CertSrvAdminSetCa
            }
            ("clbcatq.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("clbcatq.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("clbcatq.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("d3d10_1.dll", ImportSymbol::ByName { name, .. }) if name == "D3D10CreateDevice1" => {
                Self::D3d10CreateDevice1
            }
            ("d3d10_1.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10CreateDeviceAndSwapChain1" =>
            {
                Self::D3d10CreateDeviceAndSwapChain1
            }
            ("d3d10_1.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10CreateEffectFromMemory" =>
            {
                Self::D3d10CreateEffectFromMemory
            }
            ("dhcpcsvc6.dll", ImportSymbol::ByName { name, .. })
                if name == "Dhcpv6ReleaseParams" =>
            {
                Self::Dhcpv6ReleaseParams
            }
            ("dhcpcsvc6.dll", ImportSymbol::ByName { name, .. }) if name == "Dhcpv6RenewParams" => {
                Self::Dhcpv6RenewParams
            }
            ("dhcpcsvc6.dll", ImportSymbol::ByName { name, .. })
                if name == "Dhcpv6RequestParams" =>
            {
                Self::Dhcpv6RequestParams
            }
            ("dinput8.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("dinput8.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("dinput8.dll", ImportSymbol::ByName { name, .. }) if name == "GetdfDIJoystick" => {
                Self::GetdfDIJoystick
            }
            ("encapi.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("encapi.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("encapi.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("fastprox.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("fastprox.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("fastprox.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("fwpuclnt.dll", ImportSymbol::ByName { name, .. }) if name == "FWPS_FILTER" => {
                Self::FwpsFilter
            }
            ("fwpuclnt.dll", ImportSymbol::ByName { name, .. }) if name == "FwpsOpenToken" => {
                Self::FwpsOpenToken
            }
            ("fwpuclnt.dll", ImportSymbol::ByName { name, .. })
                if name == "FwpsQueryTokenInformation" =>
            {
                Self::FwpsQueryTokenInformation
            }
            ("ieframe.dll", ImportSymbol::ByName { name, .. }) if name == "IEGetFrameComponent" => {
                Self::IeGetFrameComponent
            }
            ("ieframe.dll", ImportSymbol::ByName { name, .. }) if name == "IEGetWriteableHlink" => {
                Self::IeGetWriteableHlink
            }
            ("ieframe.dll", ImportSymbol::ByName { name, .. }) if name == "IEHlink" => {
                Self::IeHlink
            }
            ("loadperf.dll", ImportSymbol::ByName { name, .. })
                if name == "LoadPerfCounterTextStringsW" =>
            {
                Self::LoadPerfCounterTextStringsW
            }
            ("loadperf.dll", ImportSymbol::ByName { name, .. })
                if name == "SetServiceAsTrusted" =>
            {
                Self::SetServiceAsTrusted
            }
            ("loadperf.dll", ImportSymbol::ByName { name, .. })
                if name == "UnloadPerfCounterTextStringsW" =>
            {
                Self::UnloadPerfCounterTextStringsW
            }
            ("msdart.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("msdart.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("msdart.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("msdxm.ocx", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("msdxm.ocx", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("msdxm.ocx", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("msimsg.dll", ImportSymbol::ByName { name, .. }) if name == "MsiFormatRecordW" => {
                Self::MsiFormatRecordW
            }
            ("msimsg.dll", ImportSymbol::ByName { name, .. })
                if name == "MsiGetLastErrorRecord" =>
            {
                Self::MsiGetLastErrorRecord
            }
            ("msimsg.dll", ImportSymbol::ByName { name, .. }) if name == "MsiProcessMessage" => {
                Self::MsiProcessMessage
            }
            ("mspatcha.dll", ImportSymbol::ByName { name, .. })
                if name == "ApplyPatchToFileExW" =>
            {
                Self::ApplyPatchToFileExW
            }
            ("mspatcha.dll", ImportSymbol::ByName { name, .. }) if name == "ApplyPatchToFileW" => {
                Self::ApplyPatchToFileW
            }
            ("mspatcha.dll", ImportSymbol::ByName { name, .. })
                if name == "GetPatchFileSignature" =>
            {
                Self::GetPatchFileSignature
            }
            ("printui.dll", ImportSymbol::ByName { name, .. }) if name == "PrintUIEntry" => {
                Self::PrintUiEntry
            }
            ("printui.dll", ImportSymbol::ByName { name, .. }) if name == "PrintUIToDevice" => {
                Self::PrintUiToDevice
            }
            ("printui.dll", ImportSymbol::ByName { name, .. }) if name == "PrintUIToFile" => {
                Self::PrintUiToFile
            }
            ("samlib.dll", ImportSymbol::ByName { name, .. }) if name == "SamCloseHandle" => {
                Self::SamCloseHandle
            }
            ("samlib.dll", ImportSymbol::ByName { name, .. }) if name == "SamConnect" => {
                Self::SamConnect
            }
            ("samlib.dll", ImportSymbol::ByName { name, .. }) if name == "SamOpenDomain" => {
                Self::SamOpenDomain
            }
            ("scecli.dll", ImportSymbol::ByName { name, .. })
                if name == "ScGenerateRelativeName" =>
            {
                Self::ScGenerateRelativeName
            }
            ("scecli.dll", ImportSymbol::ByName { name, .. })
                if name == "ScRemoveAllPrivileges" =>
            {
                Self::ScRemoveAllPrivileges
            }
            ("scecli.dll", ImportSymbol::ByName { name, .. })
                if name == "ScSetSecurityDescriptor" =>
            {
                Self::ScSetSecurityDescriptor
            }
            ("scrrun.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("scrrun.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("scrrun.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("winrnr.dll", ImportSymbol::ByName { name, .. }) if name == "RNRCancelQuery" => {
                Self::RnrCancelQuery
            }
            ("winrnr.dll", ImportSymbol::ByName { name, .. }) if name == "RNRInitialize" => {
                Self::RnrInitialize
            }
            ("winrnr.dll", ImportSymbol::ByName { name, .. }) if name == "RNRQuery" => {
                Self::RnrQuery
            }
            ("winsta.dll", ImportSymbol::ByName { name, .. })
                if name == "WinStationCloseServer" =>
            {
                Self::WinStationCloseServer
            }
            ("winsta.dll", ImportSymbol::ByName { name, .. }) if name == "WinStationEnumerate" => {
                Self::WinStationEnumerate
            }
            ("winsta.dll", ImportSymbol::ByName { name, .. }) if name == "WinStationOpenServer" => {
                Self::WinStationOpenServer
            }
            ("wmp.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("wmp.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("wmp.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("xapofx1_5.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFX" => {
                Self::CreateFx
            }
            ("xapofx1_5.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("xapofx1_5.dll", ImportSymbol::ByName { name, .. }) if name == "XAudio2Create" => {
                Self::XAudio2Create
            }
            ("xinput9_1_0.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetCapabilities" =>
            {
                Self::XInputGetCapabilities
            }
            ("xinput9_1_0.dll", ImportSymbol::ByName { name, .. }) if name == "XInputGetState" => {
                Self::XInputGetState
            }
            ("xinput9_1_0.dll", ImportSymbol::ByName { name, .. }) if name == "XInputSetState" => {
                Self::XInputSetState
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitCommonControlsEx" =>
            {
                Self::InitCommonControlsEx
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_Create" => {
                Self::ImageList_Create
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_Destroy" => {
                Self::ImageList_Destroy
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_Add" => {
                Self::ImageList_Add
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_Remove" => {
                Self::ImageList_Remove
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_GetImageCount" =>
            {
                Self::ImageList_GetImageCount
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_SetImageCount" =>
            {
                Self::ImageList_SetImageCount
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_GetImageInfo" =>
            {
                Self::ImageList_GetImageInfo
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_BeginDrag" =>
            {
                Self::ImageList_BeginDrag
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_DragEnter" =>
            {
                Self::ImageList_DragEnter
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_DragLeave" =>
            {
                Self::ImageList_DragLeave
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_DragMove" => {
                Self::ImageList_DragMove
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_DragShowNolock" =>
            {
                Self::ImageList_DragShowNolock
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_EndDrag" => {
                Self::ImageList_EndDrag
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_GetDragImage" =>
            {
                Self::ImageList_GetDragImage
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_SetDragCursorImage" =>
            {
                Self::ImageList_SetDragCursorImage
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_ReplaceIcon" =>
            {
                Self::ImageList_ReplaceIcon
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_SetBkColor" =>
            {
                Self::ImageList_SetBkColor
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_GetBkColor" =>
            {
                Self::ImageList_GetBkColor
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_Draw" => {
                Self::ImageList_Draw
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_DrawEx" => {
                Self::ImageList_DrawEx
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "OleInitialize" => {
                Self::OleInitialize
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "OleUninitialize" => {
                Self::OleUninitialize
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoCreateInstance" => {
                Self::CoCreateInstance
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoTaskMemFree" => {
                Self::CoTaskMemFree
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "VariantClear" => {
                Self::VariantClear
            }
            ("oleaut32.dll", ImportSymbol::ByOrdinal { ordinal: 9 }) => Self::VariantClear,
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoGetClassObject" => {
                Self::CoGetClassObject
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoRegisterClassObject" => {
                Self::CoRegisterClassObject
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoRevokeClassObject" => {
                Self::CoRevokeClassObject
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoCreateInstanceEx" => {
                Self::CoCreateInstanceEx
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoCreateGuid" => {
                Self::CoCreateGuid
            }

            ("CLSIDFromString", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::ClsidFromString
            }
            ("StringFromCLSID", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::StringFromClsid
            }
            ("StringFromGUID2", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::StringFromGuid2
            }
            ("ProgIDFromCLSID", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::ProgidFromClsid
            }
            ("CLSIDFromProgID", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::ClsidFromProgid
            }
            ("CoTaskMemAlloc", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoTaskMemAlloc
            }
            ("CoTaskMemFree", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoTaskMemFree
            }
            ("CoTaskMemRealloc", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoTaskMemRealloc
            }
            ("CoFileTimeNow", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoFileTimeNow
            }
            ("CoDosDateTimeToFileTime", ImportSymbol::ByName { name, .. })
                if name == "ole32.dll" =>
            {
                Self::CoDosDateTimeToFileTime
            }
            ("CoAddRefServerProcess", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoAddRefServerProcess
            }
            ("CoReleaseServerProcess", ImportSymbol::ByName { name, .. })
                if name == "ole32.dll" =>
            {
                Self::CoReleaseServerProcess
            }
            ("CoSuspendClassObjects", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoSuspendClassObjects
            }
            ("CoResumeClassObjects", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoResumeClassObjects
            }
            ("CoGetCurrentProcess", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoGetCurrentProcess
            }
            ("CoGetApartmentType", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoGetApartmentType
            }
            ("CoInitialize", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoInitialize
            }
            ("CoInitializeSecurity", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoInitializeSecurity
            }
            ("CoImpersonateClient", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoImpersonateClient
            }
            ("CoRevertToSelf", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoRevertToSelf
            }
            ("CoAllowSetForegroundWindow", ImportSymbol::ByName { name, .. })
                if name == "ole32.dll" =>
            {
                Self::CoAllowSetForegroundWindow
            }
            ("CoDisconnectObject", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoDisconnectObject
            }
            ("CoLockObjectExternal", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoLockObjectExternal
            }
            ("CoRegisterMessageFilter", ImportSymbol::ByName { name, .. })
                if name == "ole32.dll" =>
            {
                Self::CoRegisterMessageFilter
            }
            ("CoRegisterPSClsid", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoRegisterPsClsid
            }
            ("CoGetPSClsid", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoGetPsClsid
            }
            ("CoGetTreatAsClass", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoGetTreatAsClass
            }
            ("CoGetCallContext", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoGetCallContext
            }
            ("CoSetProxyBlanket", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoSetProxyBlanket
            }
            ("CoCopyProxy", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoCopyProxy
            }
            ("CoLoadLibrary", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoLoadLibrary
            }
            ("CoFreeLibrary", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoFreeLibrary
            }
            ("CoFreeUnusedLibraries", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoFreeUnusedLibraries
            }
            ("CoFreeAllLibraries", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoFreeAllLibraries
            }
            ("DllCanUnloadNow", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::DllCanUnloadNow
            }
            ("DllRegisterServer", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::DllRegisterServer
            }
            ("DllUnregisterServer", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::DllUnregisterServer
            }
            ("DllGetClassObject", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::DllGetClassObject
            }
            ("CoMarshalInterThreadInterfaceInStream", ImportSymbol::ByName { name, .. })
                if name == "ole32.dll" =>
            {
                Self::CoMarshalInterThreadInterfaceInStream
            }
            ("CoGetInterfaceAndReleaseStream", ImportSymbol::ByName { name, .. })
                if name == "ole32.dll" =>
            {
                Self::CoGetInterfaceAndReleaseStream
            }
            ("CreateBindCtx", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CreateBindCtx
            }
            ("MkParseDisplayName", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::MkParseDisplayName
            }
            ("OleDuplicateData", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::OleDuplicateData
            }
            ("OleSetMenuDescriptor", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::OleSetMenuDescriptor
            }
            ("CoGetClassObjectFromUrl", ImportSymbol::ByName { name, .. })
                if name == "ole32.dll" =>
            {
                Self::CoGetClassObjectFromUrl
            }
            ("CoGetInstanceFromFile", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoGetInstanceFromFile
            }
            ("CoGetInstanceFromIStorage", ImportSymbol::ByName { name, .. })
                if name == "ole32.dll" =>
            {
                Self::CoGetInstanceFromIStorage
            }
            ("CoInstall", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoInstall
            }
            ("CoIsHandlerConnected", ImportSymbol::ByName { name, .. }) if name == "ole32.dll" => {
                Self::CoIsHandlerConnected
            }
            ("SysStringByteLen", ImportSymbol::ByName { name, .. }) if name == "oleaut32.dll" => {
                Self::SysStringByteLen
            }
            ("SafeArrayGetDim", ImportSymbol::ByName { name, .. }) if name == "oleaut32.dll" => {
                Self::SafeArrayGetDim
            }
            ("BSTR_UserSize", ImportSymbol::ByName { name, .. }) if name == "oleaut32.dll" => {
                Self::BstrUserSize
            }
            ("BSTR_UserMarshal", ImportSymbol::ByName { name, .. }) if name == "oleaut32.dll" => {
                Self::BstrUserMarshal
            }
            ("BSTR_UserUnmarshal", ImportSymbol::ByName { name, .. }) if name == "oleaut32.dll" => {
                Self::BstrUserUnmarshal
            }
            ("BSTR_UserFree", ImportSymbol::ByName { name, .. }) if name == "oleaut32.dll" => {
                Self::BstrUserFree
            }
            ("LHashValOfNameSys", ImportSymbol::ByName { name, .. }) if name == "oleaut32.dll" => {
                Self::LHashValOfNameSys
            }
            ("VariantChangeTypeEx", ImportSymbol::ByName { name, .. })
                if name == "oleaut32.dll" =>
            {
                Self::VariantChangeTypeEx
            }
            ("VariantCopyInd", ImportSymbol::ByName { name, .. }) if name == "oleaut32.dll" => {
                Self::VariantCopyInd
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFStartup" => Self::MfStartup,
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFShutdown" => {
                Self::MfShutdown
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFRequireProtectedEnvironment" =>
            {
                Self::MfRequireProtectedEnvironment
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFGetService" => {
                Self::MfGetService
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateAttributes" => {
                Self::MfCreateAttributes
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateMediaType" => {
                Self::MfCreateMediaType
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateMemoryBuffer" => {
                Self::MfCreateMemoryBuffer
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateSample" => {
                Self::MfCreateSample
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateEventQueue" => {
                Self::MfCreateEventQueue
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreatePresentationClock" =>
            {
                Self::MfCreatePresentationClock
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateTopology" => {
                Self::MfCreateTopology
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateTopologyNode" => {
                Self::MfCreateTopologyNode
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateSourceResolver" => {
                Self::MfCreateSourceResolver
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateMediaSession" => {
                Self::MfCreateMediaSession
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSourceReaderFromURL" =>
            {
                Self::MfCreateSourceReaderFromUrl
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSourceReaderFromByteStream" =>
            {
                Self::MfCreateSourceReaderFromByteStream
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSinkWriterFromURL" =>
            {
                Self::MfCreateSinkWriterFromUrl
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreatePresentationDescriptor" =>
            {
                Self::MfCreatePresentationDescriptor
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateMFByteStreamOnStream" =>
            {
                Self::MfCreateMfByteStreamOnStream
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateMediaBufferFromMediaType" =>
            {
                Self::MfCreateMediaBufferFromMediaType
            }
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFTEnumEx" => Self::MftEnumEx,
            ("mf.dll", ImportSymbol::ByName { name, .. }) if name == "MFEnumDeviceSources" => {
                Self::MfEnumDeviceSources
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFStartup" => {
                Self::MfStartup
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFShutdown" => {
                Self::MfShutdown
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFGetService" => {
                Self::MfGetService
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateMediaType" => {
                Self::MfCreateMediaType
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateMemoryBuffer" => {
                Self::MfCreateMemoryBuffer
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateSample" => {
                Self::MfCreateSample
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreatePresentationClock" =>
            {
                Self::MfCreatePresentationClock
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreatePresentationDescriptor" =>
            {
                Self::MfCreatePresentationDescriptor
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateTopology" => {
                Self::MfCreateTopology
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSourceReaderFromByteStream" =>
            {
                Self::MfCreateSourceReaderFromByteStream
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSourceReaderFromURL" =>
            {
                Self::MfCreateSourceReaderFromUrl
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFTEnumEx" => {
                Self::MftEnumEx
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateMFByteStreamOnStream" =>
            {
                Self::MfCreateMfByteStreamOnStream
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateFile" => {
                Self::MfCreateFile
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateTempFile" => {
                Self::MfCreateTempFile
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateMediaBufferFromMediaType" =>
            {
                Self::MfCreateMediaBufferFromMediaType
            }
            ("mfreadwrite.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSourceReaderFromByteStream" =>
            {
                Self::MfCreateSourceReaderFromByteStream
            }
            ("mfreadwrite.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSourceReaderFromURL" =>
            {
                Self::MfCreateSourceReaderFromUrl
            }
            ("mfreadwrite.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSinkWriterFromMediaSink" =>
            {
                Self::MfCreateSinkWriterFromMediaSink
            }
            ("mfreadwrite.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSinkWriterFromURL" =>
            {
                Self::MfCreateSinkWriterFromUrl
            }
            ("mfreadwrite.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSourceReaderFromMFByteStream" =>
            {
                Self::MfCreateSourceReaderFromMfByteStream
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CLSIDFromString" => {
                Self::ClsidFromString
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "StringFromCLSID" => {
                Self::StringFromClsid
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "StringFromIID" => {
                Self::StringFromClsid
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "StringFromGUID2" => {
                Self::StringFromGuid2
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "ProgIDFromCLSID" => {
                Self::ProgidFromClsid
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CLSIDFromProgID" => {
                Self::ClsidFromProgid
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoTaskMemAlloc" => {
                Self::CoTaskMemAlloc
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoTaskMemRealloc" => {
                Self::CoTaskMemRealloc
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoFileTimeNow" => {
                Self::CoFileTimeNow
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. })
                if name == "CoDosDateTimeToFileTime" =>
            {
                Self::CoDosDateTimeToFileTime
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoAddRefServerProcess" => {
                Self::CoAddRefServerProcess
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. })
                if name == "CoReleaseServerProcess" =>
            {
                Self::CoReleaseServerProcess
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoSuspendClassObjects" => {
                Self::CoSuspendClassObjects
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoResumeClassObjects" => {
                Self::CoResumeClassObjects
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoGetCurrentProcess" => {
                Self::CoGetCurrentProcess
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoGetApartmentType" => {
                Self::CoGetApartmentType
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoInitialize" => {
                Self::CoInitialize
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoInitializeSecurity" => {
                Self::CoInitializeSecurity
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoImpersonateClient" => {
                Self::CoImpersonateClient
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoRevertToSelf" => {
                Self::CoRevertToSelf
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. })
                if name == "CoAllowSetForegroundWindow" =>
            {
                Self::CoAllowSetForegroundWindow
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoDisconnectObject" => {
                Self::CoDisconnectObject
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoLockObjectExternal" => {
                Self::CoLockObjectExternal
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. })
                if name == "CoRegisterMessageFilter" =>
            {
                Self::CoRegisterMessageFilter
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoRegisterPSClsid" => {
                Self::CoRegisterPsClsid
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoGetPSClsid" => {
                Self::CoGetPsClsid
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoGetTreatAsClass" => {
                Self::CoGetTreatAsClass
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoGetCallContext" => {
                Self::CoGetCallContext
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoSetProxyBlanket" => {
                Self::CoSetProxyBlanket
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoCopyProxy" => {
                Self::CoCopyProxy
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoLoadLibrary" => {
                Self::CoLoadLibrary
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoFreeLibrary" => {
                Self::CoFreeLibrary
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoFreeUnusedLibraries" => {
                Self::CoFreeUnusedLibraries
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoFreeAllLibraries" => {
                Self::CoFreeAllLibraries
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. })
                if name == "CoMarshalInterThreadInterfaceInStream" =>
            {
                Self::CoMarshalInterThreadInterfaceInStream
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. })
                if name == "CoGetInterfaceAndReleaseStream" =>
            {
                Self::CoGetInterfaceAndReleaseStream
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateBindCtx" => {
                Self::CreateBindCtx
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "MkParseDisplayName" => {
                Self::MkParseDisplayName
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "OleDuplicateData" => {
                Self::OleDuplicateData
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "OleSetMenuDescriptor" => {
                Self::OleSetMenuDescriptor
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. })
                if name == "CoGetClassObjectFromUrl" =>
            {
                Self::CoGetClassObjectFromUrl
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoGetInstanceFromFile" => {
                Self::CoGetInstanceFromFile
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. })
                if name == "CoGetInstanceFromIStorage" =>
            {
                Self::CoGetInstanceFromIStorage
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoInstall" => {
                Self::CoInstall
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoIsHandlerConnected" => {
                Self::CoIsHandlerConnected
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SysStringByteLen" => {
                Self::SysStringByteLen
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SafeArrayGetDim" => {
                Self::SafeArrayGetDim
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "BSTR_UserSize" => {
                Self::BstrUserSize
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "BSTR_UserMarshal" => {
                Self::BstrUserMarshal
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "BSTR_UserUnmarshal" => {
                Self::BstrUserUnmarshal
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "BSTR_UserFree" => {
                Self::BstrUserFree
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "LHashValOfNameSys" => {
                Self::LHashValOfNameSys
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. })
                if name == "VariantChangeTypeEx" =>
            {
                Self::VariantChangeTypeEx
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "VariantCopyInd" => {
                Self::VariantCopyInd
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SysAllocString" => {
                Self::SysAllocString
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SysReAllocString" => {
                Self::SysReAllocString
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SysFreeString" => {
                Self::SysFreeString
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SysAllocStringLen" => {
                Self::SysAllocStringLen
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SysStringLen" => {
                Self::SysStringLen
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "VariantInit" => {
                Self::VariantInit
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "VariantCopy" => {
                Self::VariantCopy
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "VariantChangeType" => {
                Self::VariantChangeType
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SafeArrayCreate" => {
                Self::SafeArrayCreate
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SafeArrayDestroy" => {
                Self::SafeArrayDestroy
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. })
                if name == "SafeArrayAccessData" =>
            {
                Self::SafeArrayAccessData
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. })
                if name == "SafeArrayUnaccessData" =>
            {
                Self::SafeArrayUnaccessData
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. })
                if name == "SafeArrayGetElement" =>
            {
                Self::SafeArrayGetElement
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. })
                if name == "SafeArrayPutElement" =>
            {
                Self::SafeArrayPutElement
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SafeArrayGetLBound" => {
                Self::SafeArrayGetLBound
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "SafeArrayGetUBound" => {
                Self::SafeArrayGetUBound
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. })
                if name == "SafeArrayCreateVector" =>
            {
                Self::SafeArrayCreateVector
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "CommandLineToArgvW" => {
                Self::CommandLineToArgvW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "IsUserAnAdmin" => {
                Self::IsUserAnAdmin
            }
            ("shell32.dll", ImportSymbol::ByOrdinal { ordinal: 680 }) => Self::IsUserAnAdmin,
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHGetFileInfoW" => {
                Self::SHGetFileInfoW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHGetFolderPathW" => {
                Self::SHGetFolderPathW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHGetPathFromIDListW" =>
            {
                Self::SHGetPathFromIDListW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHGetSpecialFolderLocation" =>
            {
                Self::SHGetSpecialFolderLocation
            }
            // ── Phase L: COM/Shell Completion ──
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHGetDesktopFolder" => {
                Self::SHGetDesktopFolder
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHBrowseForFolderW" => {
                Self::SHBrowseForFolderW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "ILCreateFromPathW" => {
                Self::ILCreateFromPathW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "ILFree" => Self::ILFree,
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHParseDisplayName" => {
                Self::SHParseDisplayName
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHCreateItemFromParsingName" =>
            {
                Self::SHCreateItemFromParsingName
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHCreateItemFromIDList" =>
            {
                Self::SHCreateItemFromIDList
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHGetDataFromIDListW" =>
            {
                Self::SHGetDataFromIDListW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHBindToParent" => {
                Self::SHBindToParent
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHGetSpecialFolderPathW" =>
            {
                Self::SHGetSpecialFolderPathW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHSimpleIDListFromPath" =>
            {
                Self::SHSimpleIDListFromPath
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "RegisterDragDrop" => {
                Self::RegisterDragDrop
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "DoDragDrop" => {
                Self::DoDragDrop
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "DragAcceptFiles" => {
                Self::DragAcceptFiles
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "DragQueryFileW" => {
                Self::DragQueryFileW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "DragFinish" => {
                Self::DragFinish
            }
            ("urlmon.dll", ImportSymbol::ByName { name, .. }) if name == "CreateURLMoniker" => {
                Self::CreateURLMoniker
            }
            ("urlmon.dll", ImportSymbol::ByName { name, .. }) if name == "CreateAsyncBindCtx" => {
                Self::CreateAsyncBindCtx
            }
            ("urlmon.dll", ImportSymbol::ByName { name, .. })
                if name == "RegisterBindStatusCallback" =>
            {
                Self::RegisterBindStatusCallback
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "MultiByteToWideChar" =>
            {
                Self::MultiByteToWideChar
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "WideCharToMultiByte" =>
            {
                Self::WideCharToMultiByte
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcmpiW" => {
                Self::LstrcmpiW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcmpW" => {
                Self::LstrcmpW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrlenW" => {
                Self::LstrlenW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcpyA" => {
                Self::LstrcpyA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcpyW" => {
                Self::LstrcpyW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcpynW" => {
                Self::LstrcpynW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcatW" => {
                Self::LstrcatW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CharUpperW" => {
                Self::CharUpperW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCommandLineA" => {
                Self::GetCommandLineA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCommandLineW" => {
                Self::GetCommandLineW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "OutputDebugStringA" => {
                Self::OutputDebugStringA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "OutputDebugStringW" => {
                Self::OutputDebugStringW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetEnvironmentVariableW" =>
            {
                Self::SetEnvironmentVariableW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetEnvironmentVariableW" =>
            {
                Self::GetEnvironmentVariableW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetEnvironmentStringsW" =>
            {
                Self::GetEnvironmentStringsW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "FreeEnvironmentStringsW" =>
            {
                Self::FreeEnvironmentStringsW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetACP" => Self::GetACP,
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetOEMCP" => {
                Self::GetOEMCP
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "IsValidCodePage" => {
                Self::IsValidCodePage
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCPInfo" => {
                Self::GetCPInfo
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetStringTypeW" => {
                Self::GetStringTypeW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LCMapStringW" => {
                Self::LCMapStringW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LCMapStringEx" => {
                Self::LCMapStringEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LocaleNameToLCID" => {
                Self::LocaleNameToLCID
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CharNextW" => {
                Self::CharNextW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CharPrevW" => {
                Self::CharPrevW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDirectoryW" => {
                Self::CreateDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "RemoveDirectoryW" => {
                Self::RemoveDirectoryW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFileW" => {
                Self::CreateFileW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "AreFileApisANSI" => {
                Self::AreFileApisANSI
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CompareFileTime" => {
                Self::CompareFileTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetFileTime" => {
                Self::SetFileTime
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegCreateKeyExA" => {
                Self::RegCreateKeyExA
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegCreateKeyExW" => {
                Self::RegCreateKeyExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegOpenKeyA" => {
                Self::RegOpenKeyA
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegOpenKeyExA" => {
                Self::RegOpenKeyExA
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegOpenKeyExW" => {
                Self::RegOpenKeyExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegSetValueExA" => {
                Self::RegSetValueExA
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegSetValueExW" => {
                Self::RegSetValueExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegQueryValueExA" => {
                Self::RegQueryValueExA
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegQueryValueExW" => {
                Self::RegQueryValueExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegCloseKey" => {
                Self::RegCloseKey
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeSecurityDescriptor" =>
            {
                Self::InitializeSecurityDescriptor
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetSecurityDescriptorDacl" =>
            {
                Self::SetSecurityDescriptorDacl
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "SystemFunction036" || name == "RtlGenRandom" =>
            {
                Self::SystemFunction036
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetFilePointer" => {
                Self::SetFilePointer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReadFile" => {
                Self::ReadFile
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WriteFile" => {
                Self::WriteFile
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetOverlappedResult" =>
            {
                Self::GetOverlappedResult
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FlushFileBuffers" => {
                Self::FlushFileBuffers
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCommState" => {
                Self::GetCommState
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetCommState" => {
                Self::SetCommState
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCommTimeouts" => {
                Self::GetCommTimeouts
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetCommTimeouts" => {
                Self::SetCommTimeouts
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "PurgeComm" => {
                Self::PurgeComm
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ClearCommError" => {
                Self::ClearCommError
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "EscapeCommFunction" => {
                Self::EscapeCommFunction
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LocalAlloc" => {
                Self::LocalAlloc
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LocalLock" => {
                Self::LocalLock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LocalUnlock" => {
                Self::LocalUnlock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LocalFree" => {
                Self::LocalFree
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GlobalAlloc" => {
                Self::GlobalAlloc
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GlobalLock" => {
                Self::GlobalLock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GlobalUnlock" => {
                Self::GlobalUnlock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GlobalFree" => {
                Self::GlobalFree
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CloseHandle" => {
                Self::CloseHandle
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetHandleInformation" =>
            {
                Self::SetHandleInformation
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DuplicateHandle" => {
                Self::DuplicateHandle
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "DeleteCriticalSection" =>
            {
                Self::DeleteCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "EnterCriticalSection" =>
            {
                Self::EnterCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "TryEnterCriticalSection" =>
            {
                Self::TryEnterCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleHandleA" => {
                Self::GetModuleHandleA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleHandleExA" => {
                Self::GetModuleHandleExA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleHandleW" => {
                Self::GetModuleHandleW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleHandleExW" => {
                Self::GetModuleHandleExW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcAddress" => {
                Self::GetProcAddress
            }
            ("psapi.dll", ImportSymbol::ByName { name, .. }) if name == "EnumProcesses" => {
                Self::EnumProcesses
            }
            ("psapi.dll", ImportSymbol::ByName { name, .. }) if name == "EnumProcessModules" => {
                Self::EnumProcessModules
            }
            ("psapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleBaseNameA" => {
                Self::GetModuleBaseNameA
            }
            ("psapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleBaseNameW" => {
                Self::GetModuleBaseNameW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiGetClassDevsW" =>
            {
                Self::SetupDiGetClassDevsW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiDestroyDeviceInfoList" =>
            {
                Self::SetupDiDestroyDeviceInfoList
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiEnumDeviceInfo" =>
            {
                Self::SetupDiEnumDeviceInfo
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiGetDeviceInstanceIdW" =>
            {
                Self::SetupDiGetDeviceInstanceIdW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiGetDeviceRegistryPropertyW" =>
            {
                Self::SetupDiGetDeviceRegistryPropertyW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiOpenDeviceInfoW" =>
            {
                Self::SetupDiOpenDeviceInfoW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiSetDeviceRegistryPropertyW" =>
            {
                Self::SetupDiSetDeviceRegistryPropertyW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiCallClassInstaller" =>
            {
                Self::SetupDiCallClassInstaller
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiGetClassDescriptionW" =>
            {
                Self::SetupDiGetClassDescriptionW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiBuildDriverInfoList" =>
            {
                Self::SetupDiBuildDriverInfoList
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiDestroyDriverInfoList" =>
            {
                Self::SetupDiDestroyDriverInfoList
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiEnumDriverInfoW" =>
            {
                Self::SetupDiEnumDriverInfoW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiGetSelectedDriverW" =>
            {
                Self::SetupDiGetSelectedDriverW
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiInstallDevice" =>
            {
                Self::SetupDiInstallDevice
            }
            ("setupapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetupDiUninstallDevice" =>
            {
                Self::SetupDiUninstallDevice
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetVersion" => {
                Self::GetVersion
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetLastError" => {
                Self::GetLastError
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetLastError" => {
                Self::SetLastError
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 8 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 8 }) => Self::Htonl,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 9 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 9 }) => Self::Htons,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "getaddrinfo" => {
                Self::Getaddrinfo
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "freeaddrinfo" => {
                Self::Freeaddrinfo
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 2 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 2 }) => Self::Bind,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "bind" => Self::Bind,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 4 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 4 }) => Self::Connect,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "connect" => Self::Connect,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 6 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 6 }) => Self::Getsockname,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "getsockname" => {
                Self::Getsockname
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 10 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 10 }) => Self::Ioctlsocket,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "ioctlsocket" => {
                Self::Ioctlsocket
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 14 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 14 }) => Self::Ntohl,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 15 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 15 }) => Self::Ntohs,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 3 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 3 }) => Self::Closesocket,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "closesocket" => {
                Self::Closesocket
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 16 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 16 }) => Self::Recv,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "recv" => Self::Recv,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 19 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 19 }) => Self::Send,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "send" => Self::Send,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 18 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 18 }) => Self::Select,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "select" => Self::Select,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 21 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 21 }) => Self::Setsockopt,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "setsockopt" => {
                Self::Setsockopt
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 22 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 22 }) => Self::Shutdown,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "shutdown" => {
                Self::Shutdown
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 23 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 23 }) => Self::Socket,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "socket" => Self::Socket,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 111 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 111 }) => Self::WsaGetLastError,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSAGetLastError" => {
                Self::WsaGetLastError
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 112 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 112 }) => Self::WsaSetLastError,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSASetLastError" => {
                Self::WsaSetLastError
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 115 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 115 }) => Self::WsaStartup,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSAStartup" => {
                Self::WsaStartup
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 116 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 116 }) => Self::WsaCleanup,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSACleanup" => {
                Self::WsaCleanup
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 151 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 151 }) => Self::WsaFdIsSet,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "__WSAFDIsSet" => {
                Self::WsaFdIsSet
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSAIoctl" => {
                Self::WsaIoctl
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSARecv" => Self::WsaRecv,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSARecvFrom" => {
                Self::WsaRecvFrom
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSASend" => Self::WsaSend,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSASendTo" => {
                Self::WsaSendTo
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSASocketA" => {
                Self::WsaSocketA
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 1 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 1 }) => Self::Accept,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "accept" => Self::Accept,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSAAccept" => {
                Self::WsaAccept
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 13 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 13 }) => Self::Listen,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "listen" => Self::Listen,
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 7 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 7 }) => Self::Getsockopt,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "getsockopt" => {
                Self::Getsockopt
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSAConnect" => {
                Self::WsaConnect
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSAPoll" => Self::WsaPoll,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSASocketW" => {
                Self::WsaSocketW
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "WSADuplicateSocketW" => {
                Self::WsaDuplicateSocketW
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 52 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 52 }) => Self::Gethostbyname,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "gethostbyname" => {
                Self::Gethostbyname
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 51 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 51 }) => Self::Gethostbyaddr,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "gethostbyaddr" => {
                Self::Gethostbyaddr
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 57 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 57 }) => Self::Gethostname,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "gethostname" => {
                Self::Gethostname
            }
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "getnameinfo" => {
                Self::Getnameinfo
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 53 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 53 }) => Self::Getprotobyname,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "getprotobyname" => {
                Self::Getprotobyname
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 55 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 55 }) => Self::Getservbyname,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "getservbyname" => {
                Self::Getservbyname
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 11 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 11 }) => Self::InetAddr,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "inet_addr" => {
                Self::InetAddr
            }
            ("ws2_32.dll", ImportSymbol::ByOrdinal { ordinal: 12 })
            | ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 12 }) => Self::InetNtoa,
            ("ws2_32.dll", ImportSymbol::ByName { name, .. }) if name == "inet_ntoa" => {
                Self::InetNtoa
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "AcceptSecurityContext" =>
            {
                Self::AcceptSecurityContext
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "AcquireCredentialsHandleW" =>
            {
                Self::AcquireCredentialsHandleW
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. }) if name == "CompleteAuthToken" => {
                Self::CompleteAuthToken
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. }) if name == "DecryptMessage" => {
                Self::DecryptMessage
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "DeleteSecurityContext" =>
            {
                Self::DeleteSecurityContext
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. }) if name == "EncryptMessage" => {
                Self::EncryptMessage
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "EnumerateSecurityPackagesW" =>
            {
                Self::EnumerateSecurityPackagesW
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "FreeCredentialsHandle" =>
            {
                Self::FreeCredentialsHandle
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. }) if name == "GetUserNameExW" => {
                Self::GetUserNameExW
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImpersonateSecurityContext" =>
            {
                Self::ImpersonateSecurityContext
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeSecurityContextW" =>
            {
                Self::InitializeSecurityContextW
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. }) if name == "MakeSignature" => {
                Self::MakeSignature
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "QueryContextAttributesW" =>
            {
                Self::QueryContextAttributesW
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. })
                if name == "RevertSecurityContext" =>
            {
                Self::RevertSecurityContext
            }
            ("secur32.dll", ImportSymbol::ByName { name, .. }) if name == "VerifySignature" => {
                Self::VerifySignature
            }
            ("netapi32.dll", ImportSymbol::ByName { name, .. }) if name == "NetApiBufferFree" => {
                Self::NetApiBufferFree
            }
            ("netapi32.dll", ImportSymbol::ByName { name, .. }) if name == "NetServerEnum" => {
                Self::NetServerEnum
            }
            ("netapi32.dll", ImportSymbol::ByName { name, .. }) if name == "NetUserGetInfo" => {
                Self::NetUserGetInfo
            }
            ("netapi32.dll", ImportSymbol::ByName { name, .. }) if name == "NetWkstaGetInfo" => {
                Self::NetWkstaGetInfo
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetAdaptersInfo" => {
                Self::GetAdaptersInfo
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. })
                if name == "GetAdaptersAddresses" =>
            {
                Self::GetAdaptersAddresses
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetIfTable" => {
                Self::GetIfTable
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetIfEntry" => {
                Self::GetIfEntry
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetIpAddrTable" => {
                Self::GetIpAddrTable
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetIpForwardTable" => {
                Self::GetIpForwardTable
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetNetworkParams" => {
                Self::GetNetworkParams
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetBestInterface" => {
                Self::GetBestInterface
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetBestRoute" => {
                Self::GetBestRoute
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetRTTAndHopCount" => {
                Self::GetRTTAndHopCount
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "NotifyAddrChange" => {
                Self::NotifyAddrChange
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. }) if name == "NotifyRouteChange" => {
                Self::NotifyRouteChange
            }
            ("iphlpapi.dll", ImportSymbol::ByName { name, .. })
                if name == "CancelMibChangeNotify2" =>
            {
                Self::CancelMibChangeNotify2
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCurrentThread" => {
                Self::GetCurrentThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCurrentThreadId" => {
                Self::GetCurrentThreadId
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCurrentProcessId" =>
            {
                Self::GetCurrentProcessId
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetCurrentProcess" => {
                Self::GetCurrentProcess
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "ProcessIdToSessionId" =>
            {
                Self::ProcessIdToSessionId
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "QueryPerformanceCounter" =>
            {
                Self::QueryPerformanceCounter
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "QueryPerformanceFrequency" =>
            {
                Self::QueryPerformanceFrequency
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "VerSetConditionMask" =>
            {
                Self::VerSetConditionMask
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VerifyVersionInfoW" => {
                Self::VerifyVersionInfoW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "IsProcessorFeaturePresent" =>
            {
                Self::IsProcessorFeaturePresent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessHeap" => {
                Self::GetProcessHeap
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessHeaps" => {
                Self::GetProcessHeaps
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapAlloc" => {
                Self::HeapAlloc
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapFree" => {
                Self::HeapFree
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapReAlloc" => {
                Self::HeapReAlloc
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapSize" => {
                Self::HeapSize
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetStartupInfoW" => {
                Self::GetStartupInfoW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeSListHead" =>
            {
                Self::InitializeSListHead
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetStdHandle" => {
                Self::GetStdHandle
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileType" => {
                Self::GetFileType
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetFileInformationByHandle" =>
            {
                Self::GetFileInformationByHandle
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetSystemTimeAsFileTime" =>
            {
                Self::GetSystemTimeAsFileTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetSystemTimePreciseAsFileTime" =>
            {
                Self::GetSystemTimePreciseAsFileTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetTimeZoneInformation" =>
            {
                Self::GetTimeZoneInformation
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTickCount" => {
                Self::GetTickCount
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTickCount64" => {
                Self::GetTickCount64
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCurrentPackageId" =>
            {
                Self::GetCurrentPackageId
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeCriticalSection" =>
            {
                Self::InitializeCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeCriticalSectionAndSpinCount" =>
            {
                Self::InitializeCriticalSectionAndSpinCount
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeCriticalSectionEx" =>
            {
                Self::InitializeCriticalSectionEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "EncodePointer" => {
                Self::EncodePointer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DecodePointer" => {
                Self::DecodePointer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "UnhandledExceptionFilter" =>
            {
                Self::UnhandledExceptionFilter
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SleepConditionVariableCS" =>
            {
                Self::SleepConditionVariableCS
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "WakeAllConditionVariable" =>
            {
                Self::WakeAllConditionVariable
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "LeaveCriticalSection" =>
            {
                Self::LeaveCriticalSection
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetUnhandledExceptionFilter" =>
            {
                Self::SetUnhandledExceptionFilter
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "AddVectoredExceptionHandler" =>
            {
                Self::AddVectoredExceptionHandler
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "RemoveVectoredExceptionHandler" =>
            {
                Self::RemoveVectoredExceptionHandler
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "AddVectoredContinueHandler" =>
            {
                Self::AddVectoredContinueHandler
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "RemoveVectoredContinueHandler" =>
            {
                Self::RemoveVectoredContinueHandler
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "Beep" => Self::Beep,
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "Sleep" || name == "Forwarded" =>
            {
                Self::Sleep
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsAlloc" => {
                Self::TlsAlloc
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsGetValue" => {
                Self::TlsGetValue
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsSetValue" => {
                Self::TlsSetValue
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TlsFree" => {
                Self::TlsFree
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FlsAlloc" => {
                Self::FlsAlloc
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FlsGetValue" => {
                Self::FlsGetValue
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FlsSetValue" => {
                Self::FlsSetValue
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FlsFree" => {
                Self::FlsFree
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualAlloc" => {
                Self::VirtualAlloc
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualFree" => {
                Self::VirtualFree
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualProtect" => {
                Self::VirtualProtect
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualQuery" => {
                Self::VirtualQuery
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WriteProcessMemory" => {
                Self::WriteProcessMemory
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "WriteProcessMemory" =>
            {
                Self::WriteProcessMemory
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetOverlappedResult" =>
            {
                Self::GetOverlappedResult
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetCurrentThread" => {
                Self::GetCurrentThread
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetExitCodeThread" =>
            {
                Self::GetExitCodeThread
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetExitCodeProcess" =>
            {
                Self::GetExitCodeProcess
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCurrentThreadId" =>
            {
                Self::GetCurrentThreadId
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCurrentProcessId" =>
            {
                Self::GetCurrentProcessId
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCurrentProcess" =>
            {
                Self::GetCurrentProcess
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "ProcessIdToSessionId" =>
            {
                Self::ProcessIdToSessionId
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "QueryPerformanceCounter" =>
            {
                Self::QueryPerformanceCounter
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "QueryPerformanceFrequency" =>
            {
                Self::QueryPerformanceFrequency
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "VerSetConditionMask" =>
            {
                Self::VerSetConditionMask
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "VerifyVersionInfoW" =>
            {
                Self::VerifyVersionInfoW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "IsProcessorFeaturePresent" =>
            {
                Self::IsProcessorFeaturePresent
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessHeap" => {
                Self::GetProcessHeap
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessHeaps" => {
                Self::GetProcessHeaps
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "HeapAlloc" => {
                Self::HeapAlloc
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "HeapFree" => {
                Self::HeapFree
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "HeapReAlloc" => {
                Self::HeapReAlloc
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "HeapSize" => {
                Self::HeapSize
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetStartupInfoW" => {
                Self::GetStartupInfoW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeSListHead" =>
            {
                Self::InitializeSListHead
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetStdHandle" => {
                Self::GetStdHandle
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileType" => {
                Self::GetFileType
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetFileInformationByHandle" =>
            {
                Self::GetFileInformationByHandle
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetACP" => {
                Self::GetACP
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetOEMCP" => {
                Self::GetOEMCP
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetFileAttributesExW" =>
            {
                Self::GetFileAttributesExW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FindFirstFileW" => {
                Self::FindFirstFileW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FindNextFileW" => {
                Self::FindNextFileW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FindClose" => {
                Self::FindClose
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetEnvironmentStringsW" =>
            {
                Self::GetEnvironmentStringsW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SetEnvironmentVariableW" =>
            {
                Self::SetEnvironmentVariableW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetEnvironmentVariableW" =>
            {
                Self::GetEnvironmentVariableW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "FreeEnvironmentStringsW" =>
            {
                Self::FreeEnvironmentStringsW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "IsValidCodePage" => {
                Self::IsValidCodePage
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetCPInfo" => {
                Self::GetCPInfo
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetStringTypeW" => {
                Self::GetStringTypeW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LCMapStringW" => {
                Self::LCMapStringW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LCMapStringEx" => {
                Self::LCMapStringEx
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LocaleNameToLCID" => {
                Self::LocaleNameToLCID
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetSystemTimeAsFileTime" =>
            {
                Self::GetSystemTimeAsFileTime
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetSystemTimePreciseAsFileTime" =>
            {
                Self::GetSystemTimePreciseAsFileTime
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetTimeZoneInformation" =>
            {
                Self::GetTimeZoneInformation
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetTickCount" => {
                Self::GetTickCount
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetTickCount64" => {
                Self::GetTickCount64
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCurrentPackageId" =>
            {
                Self::GetCurrentPackageId
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetTempPath2W" => {
                Self::GetTempPath2W
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "AreFileApisANSI" => {
                Self::AreFileApisANSI
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "TryEnterCriticalSection" =>
            {
                Self::TryEnterCriticalSection
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeCriticalSectionAndSpinCount" =>
            {
                Self::InitializeCriticalSectionAndSpinCount
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeCriticalSectionEx" =>
            {
                Self::InitializeCriticalSectionEx
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "EncodePointer" => {
                Self::EncodePointer
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "DecodePointer" => {
                Self::DecodePointer
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SleepConditionVariableCS" =>
            {
                Self::SleepConditionVariableCS
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "WakeAllConditionVariable" =>
            {
                Self::WakeAllConditionVariable
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateIoCompletionPort" =>
            {
                Self::CreateIoCompletionPort
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "PostQueuedCompletionStatus" =>
            {
                Self::PostQueuedCompletionStatus
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetQueuedCompletionStatus" =>
            {
                Self::GetQueuedCompletionStatus
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetQueuedCompletionStatusEx" =>
            {
                Self::GetQueuedCompletionStatusEx
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SetFileCompletionNotificationModes" =>
            {
                Self::SetFileCompletionNotificationModes
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateEventA" => {
                Self::CreateEventA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateEventW" => {
                Self::CreateEventW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SetHandleInformation" =>
            {
                Self::SetHandleInformation
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "DuplicateHandle" => {
                Self::DuplicateHandle
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "OpenEventA" => {
                Self::OpenEventA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "OpenEventW" => {
                Self::OpenEventW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "SetEvent" => {
                Self::SetEvent
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "ResetEvent" => {
                Self::ResetEvent
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "IsDebuggerPresent" =>
            {
                Self::IsDebuggerPresent
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "OutputDebugStringA" =>
            {
                Self::OutputDebugStringA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "OutputDebugStringW" =>
            {
                Self::OutputDebugStringW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryA" => {
                Self::LoadLibraryA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryW" => {
                Self::LoadLibraryW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryExA" => {
                Self::LoadLibraryExA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryExW" => {
                Self::LoadLibraryExW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetModuleHandleExA" =>
            {
                Self::GetModuleHandleExA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetModuleHandleExW" =>
            {
                Self::GetModuleHandleExW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "InitOnceBeginInitialize" =>
            {
                Self::InitOnceBeginInitialize
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "InitOnceComplete" => {
                Self::InitOnceComplete
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "InitOnceExecuteOnce" =>
            {
                Self::InitOnceExecuteOnce
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeSRWLock" =>
            {
                Self::InitializeSRWLock
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "AcquireSRWLockExclusive" =>
            {
                Self::AcquireSRWLockExclusive
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "ReleaseSRWLockExclusive" =>
            {
                Self::ReleaseSRWLockExclusive
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "AcquireSRWLockShared" =>
            {
                Self::AcquireSRWLockShared
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "ReleaseSRWLockShared" =>
            {
                Self::ReleaseSRWLockShared
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "TryAcquireSRWLockExclusive" =>
            {
                Self::TryAcquireSRWLockExclusive
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "TryAcquireSRWLockShared" =>
            {
                Self::TryAcquireSRWLockShared
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "Sleep" => Self::Sleep,
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TerminateProcess" => {
                Self::TerminateProcess
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TlsAlloc" => {
                Self::TlsAlloc
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TlsGetValue" => {
                Self::TlsGetValue
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TlsSetValue" => {
                Self::TlsSetValue
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "TlsFree" => {
                Self::TlsFree
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FlsAlloc" => {
                Self::FlsAlloc
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FlsGetValue" => {
                Self::FlsGetValue
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FlsSetValue" => {
                Self::FlsSetValue
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "FlsFree" => {
                Self::FlsFree
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualAlloc" => {
                Self::VirtualAlloc
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "VirtualFree" => {
                Self::VirtualFree
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateProcessA" => {
                Self::CreateProcessA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateNamedPipeW" => {
                Self::CreateNamedPipeW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "ConnectNamedPipe" => {
                Self::ConnectNamedPipe
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "DisconnectNamedPipe" =>
            {
                Self::DisconnectNamedPipe
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CallNamedPipeW" => {
                Self::CallNamedPipeW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "WaitNamedPipeW" => {
                Self::WaitNamedPipeW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetNamedPipeInfo" => {
                Self::GetNamedPipeInfo
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SetNamedPipeHandleState" =>
            {
                Self::SetNamedPipeHandleState
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "PeekNamedPipe" => {
                Self::PeekNamedPipe
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateFileMappingW" =>
            {
                Self::CreateFileMappingW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "MapViewOfFile" => {
                Self::MapViewOfFile
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "UnmapViewOfFile" => {
                Self::UnmapViewOfFile
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "OpenProcess" => {
                Self::OpenProcess
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "WaitForMultipleObjects" =>
            {
                Self::WaitForMultipleObjects
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ExitProcess" => {
                Self::ExitProcess
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlNtStatusToDosError" => {
                Self::RtlNtStatusToDosError
            }
            ("api-ms-win-core-synch-l1-2-0.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeCriticalSectionEx" =>
            {
                Self::InitializeCriticalSectionEx
            }
            ("api-ms-win-core-synch-l1-2-0.dll", ImportSymbol::ByName { name, .. })
                if name == "SleepConditionVariableCS" =>
            {
                Self::SleepConditionVariableCS
            }
            ("api-ms-win-core-synch-l1-2-0.dll", ImportSymbol::ByName { name, .. })
                if name == "WakeAllConditionVariable" =>
            {
                Self::WakeAllConditionVariable
            }
            ("api-ms-win-core-fibers-l1-1-1.dll", ImportSymbol::ByName { name, .. })
                if name == "FlsAlloc" =>
            {
                Self::FlsAlloc
            }
            ("api-ms-win-core-fibers-l1-1-1.dll", ImportSymbol::ByName { name, .. })
                if name == "FlsGetValue" =>
            {
                Self::FlsGetValue
            }
            ("api-ms-win-core-fibers-l1-1-1.dll", ImportSymbol::ByName { name, .. })
                if name == "FlsSetValue" =>
            {
                Self::FlsSetValue
            }
            ("api-ms-win-core-fibers-l1-1-1.dll", ImportSymbol::ByName { name, .. })
                if name == "FlsFree" =>
            {
                Self::FlsFree
            }
            ("api-ms-win-core-localization-l1-2-1.dll", ImportSymbol::ByName { name, .. })
                if name == "LCMapStringEx" =>
            {
                Self::LCMapStringEx
            }
            ("api-ms-win-core-localization-l1-2-1.dll", ImportSymbol::ByName { name, .. })
                if name == "LocaleNameToLCID" =>
            {
                Self::LocaleNameToLCID
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_set_new_mode" => {
                Self::SetNewMode
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "calloc" => Self::Calloc,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "free" => Self::Free,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "malloc" => Self::Malloc,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "realloc" => {
                Self::Realloc
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. })
                if name == "__C_specific_handler" =>
            {
                Self::CSpecificHandler
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p___argc" => {
                Self::PArgc
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p___argv" => {
                Self::PArgv
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_cexit" => Self::Cexit,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. })
                if name == "_configure_narrow_argv" =>
            {
                Self::ConfigureNarrowArgv
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_crt_atexit" => {
                Self::CrtAtExit
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_exit" => Self::CrtExit,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. })
                if name == "_initialize_narrow_environment" =>
            {
                Self::InitializeNarrowEnvironment
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_initterm" => {
                Self::Initterm
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_initterm_e" => {
                Self::InittermE
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "_set_app_type" => {
                Self::SetAppType
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. })
                if name == "_set_invalid_parameter_handler" =>
            {
                Self::SetInvalidParameterHandler
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "abort" => Self::Abort,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "exit" => Self::Exit,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "signal" => Self::Signal,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "setlocale" => {
                Self::Setlocale
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__acrt_iob_func" => {
                Self::AcrtIobFunc
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p__commode" => {
                Self::PCommode
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p__fmode" => {
                Self::PFmode
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. })
                if name == "__stdio_common_vfprintf" =>
            {
                Self::StdioCommonVfprintf
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "fwrite" => Self::Fwrite,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "strlen" => Self::Strlen,
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "strncmp" => {
                Self::Strncmp
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__p__environ" => {
                Self::PEnviron
            }
            ("ucrtbase.dll", ImportSymbol::ByName { name, .. }) if name == "__setusermatherr" => {
                Self::SetUserMathErr
            }
            // -- msvcrt.dll (C runtime, mirrors ucrtbase) — P0.3 --
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "_set_new_mode" => {
                Self::SetNewMode
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "calloc" => Self::Calloc,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "free" => Self::Free,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "malloc" => Self::Malloc,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "realloc" => Self::Realloc,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "__C_specific_handler" => {
                Self::CSpecificHandler
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "__p___argc" => {
                Self::PArgc
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "__p___argv" => {
                Self::PArgv
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "_cexit" => Self::Cexit,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. })
                if name == "_configure_narrow_argv" =>
            {
                Self::ConfigureNarrowArgv
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "_crt_atexit" => {
                Self::CrtAtExit
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "_exit" => Self::CrtExit,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. })
                if name == "_initialize_narrow_environment" =>
            {
                Self::InitializeNarrowEnvironment
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "_initterm" => {
                Self::Initterm
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "_initterm_e" => {
                Self::InittermE
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "_set_app_type" => {
                Self::SetAppType
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. })
                if name == "_set_invalid_parameter_handler" =>
            {
                Self::SetInvalidParameterHandler
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "abort" => Self::Abort,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "exit" => Self::Exit,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "signal" => Self::Signal,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "setlocale" => {
                Self::Setlocale
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "__acrt_iob_func" => {
                Self::AcrtIobFunc
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "__p__commode" => {
                Self::PCommode
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "__p__fmode" => {
                Self::PFmode
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. })
                if name == "__stdio_common_vfprintf" =>
            {
                Self::StdioCommonVfprintf
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "fwrite" => Self::Fwrite,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "strlen" => Self::Strlen,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "strncmp" => Self::Strncmp,
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "__p__environ" => {
                Self::PEnviron
            }
            ("msvcrt.dll", ImportSymbol::ByName { name, .. }) if name == "__setusermatherr" => {
                Self::SetUserMathErr
            }
            // -- Patch 6b: CRT / UCRT surface (shared name table) --
            ("ucrtbase.dll" | "msvcrt.dll", ImportSymbol::ByName { name, .. })
                if let Some(thunk) = Self::crt_thunk_from_name(name) =>
            {
                thunk
            }
            // -- Patch 6c: vcruntime140.dll / msvcp140.dll surfaces --
            ("vcruntime140.dll", ImportSymbol::ByName { name, .. })
                if let Some(thunk) = Self::vcrt_thunk_from_name(name) =>
            {
                thunk
            }
            ("msvcp140.dll", ImportSymbol::ByName { name, .. })
                if let Some(thunk) = Self::msvcp_thunk_from_name(name) =>
            {
                thunk
            }
            // -- usp10.dll (Uniscribe) — P0.3 --
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptStringAnalyse" => {
                Self::ScriptStringAnalyse
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptStringFree" => {
                Self::ScriptStringFree
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptStringOut" => {
                Self::ScriptStringOut
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptString_pSize" => {
                Self::ScriptString_pSize
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptItemize" => {
                Self::ScriptItemize
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptShape" => {
                Self::ScriptShape
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptPlace" => {
                Self::ScriptPlace
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptLayout" => {
                Self::ScriptLayout
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptBreak" => {
                Self::ScriptBreak
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptGetProperties" => {
                Self::ScriptGetProperties
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. })
                if name == "ScriptRecordDigitSubstitution" =>
            {
                Self::ScriptRecordDigitSubstitution
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. })
                if name == "ScriptApplyDigitSubstitution" =>
            {
                Self::ScriptApplyDigitSubstitution
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptCacheGetHeight" => {
                Self::ScriptCacheGetHeight
            }
            ("usp10.dll", ImportSymbol::ByName { name, .. }) if name == "ScriptFreeCache" => {
                Self::ScriptFreeCache
            }
            // -- Window Manager Enhancements (Phase 2.2) ---
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetLayeredWindowAttributes" =>
            {
                Self::SetLayeredWindowAttributes
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "UpdateLayeredWindow" => {
                Self::UpdateLayeredWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetWindowRgn" => {
                Self::SetWindowRgn
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "PrintWindow" => {
                Self::PrintWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "Shell_NotifyIconW" => {
                Self::ShellNotifyIconW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetWindowCompositionAttribute" =>
            {
                Self::SetWindowCompositionAttribute
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowPlacement" => {
                Self::GetWindowPlacement
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetWindowPlacement" => {
                Self::SetWindowPlacement
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetProcessDPIAware" => {
                Self::SetProcessDPIAware
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDpiForWindow" => {
                Self::GetDpiForWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetProcessDPIAwareness" =>
            {
                Self::SetProcessDPIAwareness
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDpiForMonitor" => {
                Self::GetDpiForMonitor
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetThreadDpiAwarenessContext" =>
            {
                Self::SetThreadDpiAwarenessContext
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetThreadDpiAwarenessContext" =>
            {
                Self::GetThreadDpiAwarenessContext
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "EnableNonClientDpiScaling" =>
            {
                Self::EnableNonClientDpiScaling
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "AdjustWindowRectExForDpi" =>
            {
                Self::AdjustWindowRectExForDpi
            }
            // -- Phase 2.3: user32.dll window management imports --------------------
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "BringWindowToTop" => {
                Self::BringWindowToTop
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTopWindow" => {
                Self::GetTopWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetNextWindow" => {
                Self::GetNextWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindow" => {
                Self::GetWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowTextW" => {
                Self::GetWindowTextW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowTextLengthW" => {
                Self::GetWindowTextLengthW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetUpdateRect" => {
                Self::GetUpdateRect
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ValidateRect" => {
                Self::ValidateRect
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "InvalidateRgn" => {
                Self::InvalidateRgn
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetWindowLongPtrW" => {
                Self::SetWindowLongPtrW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowLongPtrW" => {
                Self::GetWindowLongPtrW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetParent" => {
                Self::GetParent
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetParent" => {
                Self::SetParent
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MessageBoxW" => {
                Self::MessageBoxW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MessageBoxIndirectW" => {
                Self::MessageBoxIndirectW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegEnumKeyExW" => {
                Self::RegEnumKeyExW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegDeleteKeyW" => {
                Self::RegDeleteKeyW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegDeleteValueW" => {
                Self::RegDeleteValueW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetUserNameW" => {
                Self::GetUserNameW
            }
            // -- advapi32: access tokens, SCM, CryptoAPI (mid families) --
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "AdjustTokenPrivileges" =>
            {
                Self::AdjustTokenPrivileges
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "AllocateAndInitializeSid" =>
            {
                Self::AllocateAndInitializeSid
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "CheckTokenMembership" =>
            {
                Self::CheckTokenMembership
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "DuplicateTokenEx" => {
                Self::DuplicateTokenEx
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "FreeSid" => {
                Self::FreeSid
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetTokenInformation" =>
            {
                Self::GetTokenInformation
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImpersonateLoggedOnUser" =>
            {
                Self::ImpersonateLoggedOnUser
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "LookupPrivilegeValueW" =>
            {
                Self::LookupPrivilegeValueW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenProcessToken" => {
                Self::OpenProcessToken
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenThreadToken" => {
                Self::OpenThreadToken
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RevertToSelf" => {
                Self::RevertToSelf
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "GetUserNameA" => {
                Self::GetUserNameA
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "LogonUserW" => {
                Self::LogonUserW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CloseServiceHandle" => {
                Self::CloseServiceHandle
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "ControlService" => {
                Self::ControlService
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateServiceW" => {
                Self::CreateServiceW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteService" => {
                Self::DeleteService
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenSCManagerW" => {
                Self::OpenSCManagerW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenServiceW" => {
                Self::OpenServiceW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "QueryServiceStatus" => {
                Self::QueryServiceStatus
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "StartServiceW" => {
                Self::StartServiceW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "CryptAcquireContextW" =>
            {
                Self::CryptAcquireContextW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptCreateHash" => {
                Self::CryptCreateHash
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptDecrypt" => {
                Self::CryptDecrypt
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptDeriveKey" => {
                Self::CryptDeriveKey
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptDestroyHash" => {
                Self::CryptDestroyHash
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptDestroyKey" => {
                Self::CryptDestroyKey
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptEncrypt" => {
                Self::CryptEncrypt
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptGenRandom" => {
                Self::CryptGenRandom
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptGetHashParam" => {
                Self::CryptGetHashParam
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CryptHashData" => {
                Self::CryptHashData
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "CryptReleaseContext" =>
            {
                Self::CryptReleaseContext
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegEnumValueW" => {
                Self::RegEnumValueW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegFlushKey" => {
                Self::RegFlushKey
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegOpenCurrentUser" => {
                Self::RegOpenCurrentUser
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RegQueryInfoKeyW" => {
                Self::RegQueryInfoKeyW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "EventRegister" => {
                Self::EventRegister
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "EventUnregister" => {
                Self::EventUnregister
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "EventWrite" => {
                Self::EventWrite
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetComputerNameW" => {
                Self::GetComputerNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetLongPathNameW" => {
                Self::GetLongPathNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetShortPathNameW" => {
                Self::GetShortPathNameW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreatePipe" => {
                Self::CreatePipe
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetNativeSystemInfo" =>
            {
                Self::GetNativeSystemInfo
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemInfo" => {
                Self::GetSystemInfo
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "IsWow64Process" => {
                Self::IsWow64Process
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetProductInfo" => {
                Self::GetProductInfo
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetVersionExW" => {
                Self::GetVersionExW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetLongPathNameW" => {
                Self::GetLongPathNameW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetShortPathNameW" =>
            {
                Self::GetShortPathNameW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetNativeSystemInfo" =>
            {
                Self::GetNativeSystemInfo
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemInfo" => {
                Self::GetSystemInfo
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "IsWow64Process" => {
                Self::IsWow64Process
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetProductInfo" => {
                Self::GetProductInfo
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetVersionExW" => {
                Self::GetVersionExW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetComputerNameW" => {
                Self::GetComputerNameW
            }
            ("version.dll", ImportSymbol::ByName { name, .. })
                if name == "GetFileVersionInfoSizeW" =>
            {
                Self::GetFileVersionInfoSizeW
            }
            ("version.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileVersionInfoW" => {
                Self::GetFileVersionInfoW
            }
            ("version.dll", ImportSymbol::ByName { name, .. }) if name == "VerQueryValueW" => {
                Self::VerQueryValueW
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoInitializeEx" => {
                Self::CoInitializeEx
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "CoUninitialize" => {
                Self::CoUninitialize
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHGetKnownFolderPath" =>
            {
                Self::SHGetKnownFolderPath
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "ShellExecuteExW" => {
                Self::ShellExecuteExW
            }
            // -- shell32: icon/path/notify helpers (mid families) ---------
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "ExtractIconW" => {
                Self::ExtractIconW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "ExtractIconExW" => {
                Self::ExtractIconExW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathAppendW" => {
                Self::PathAppendW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathCombineW" => {
                Self::PathCombineW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathFileExistsW" => {
                Self::PathFileExistsW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathFindExtensionW" => {
                Self::PathFindExtensionW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathFindFileNameW" => {
                Self::PathFindFileNameW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathIsDirectoryW" => {
                Self::PathIsDirectoryW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathIsNetworkPathW" => {
                Self::PathIsNetworkPathW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathMakeUniqueName" => {
                Self::PathMakeUniqueName
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathRelativePathToW" => {
                Self::PathRelativePathToW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "PathRemoveFileSpecW" => {
                Self::PathRemoveFileSpecW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHChangeNotify" => {
                Self::SHChangeNotify
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. })
                if name == "SHCreateDirectoryExW" =>
            {
                Self::SHCreateDirectoryExW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHCreateShellItem" => {
                Self::SHCreateShellItem
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHFileOperationW" => {
                Self::SHFileOperationW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHGetMalloc" => {
                Self::SHGetMalloc
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "SHUpdateImageW" => {
                Self::SHUpdateImageW
            }
            ("shell32.dll", ImportSymbol::ByName { name, .. }) if name == "ShellExecuteW" => {
                Self::ShellExecuteW
            }
            // -- WinHTTP (winhttp.dll) -------------------------------------------
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpOpen" => {
                Self::WinHttpOpen
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpCloseHandle" => {
                Self::WinHttpCloseHandle
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpConnect" => {
                Self::WinHttpConnect
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpOpenRequest" => {
                Self::WinHttpOpenRequest
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpSendRequest" => {
                Self::WinHttpSendRequest
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpReceiveResponse" =>
            {
                Self::WinHttpReceiveResponse
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpReadData" => {
                Self::WinHttpReadData
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpQueryDataAvailable" =>
            {
                Self::WinHttpQueryDataAvailable
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpQueryHeaders" => {
                Self::WinHttpQueryHeaders
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpSetOption" => {
                Self::WinHttpSetOption
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpSetStatusCallback" =>
            {
                Self::WinHttpSetStatusCallback
            }
            // -- Phase 3.1: Extended WinHTTP APIs --------------------------------
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpAddRequestHeaders" =>
            {
                Self::WinHttpAddRequestHeaders
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpWriteData" => {
                Self::WinHttpWriteData
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpSetCredentials" =>
            {
                Self::WinHttpSetCredentials
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpQueryAuthSchemes" =>
            {
                Self::WinHttpQueryAuthSchemes
            }
            // -- WinINet (wininet.dll) -------------------------------------------
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetOpenW" => {
                Self::InternetOpenW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetConnectW" => {
                Self::InternetConnectW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "HttpOpenRequestW" => {
                Self::HttpOpenRequestW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "HttpSendRequestW" => {
                Self::HttpSendRequestW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetReadFile" => {
                Self::InternetReadFile
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetCloseHandle" => {
                Self::InternetCloseHandle
            }
            // -- Phase 3.1: Extended WinINet APIs --------------------------------
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "InternetQueryDataAvailable" =>
            {
                Self::InternetQueryDataAvailable
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetSetOptionW" => {
                Self::InternetSetOptionW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "InternetGetLastResponseInfoW" =>
            {
                Self::InternetGetLastResponseInfoW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "InternetSetStatusCallback" =>
            {
                Self::InternetSetStatusCallback
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetCrackUrlW" => {
                Self::InternetCrackUrlW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "InternetCanonicalizeUrlW" =>
            {
                Self::InternetCanonicalizeUrlW
            }
            // -- J1: WinHTTP WebSocket, QueryOption & Proxy ---------------------------
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpWebSocketCompleteUpgrade" =>
            {
                Self::WinHttpWebSocketCompleteUpgrade
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpWebSocketSend" =>
            {
                Self::WinHttpWebSocketSend
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpWebSocketReceive" =>
            {
                Self::WinHttpWebSocketReceive
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpWebSocketClose" =>
            {
                Self::WinHttpWebSocketClose
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpWebSocketQueryCloseStatus" =>
            {
                Self::WinHttpWebSocketQueryCloseStatus
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpQueryOption" => {
                Self::WinHttpQueryOption
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpGetProxyForUrl" =>
            {
                Self::WinHttpGetProxyForUrl
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpGetIEProxyConfigForCurrentUser" =>
            {
                Self::WinHttpGetIEProxyConfigForCurrentUser
            }
            // -- J3: WinINet FTP operations -------------------------------------------
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "FtpGetFileW" => {
                Self::FtpGetFileW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "FtpPutFileW" => {
                Self::FtpPutFileW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "FtpOpenFileW" => {
                Self::FtpOpenFileW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "FtpFindFirstFileW" => {
                Self::FtpFindFirstFileW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "FtpDeleteFileW" => {
                Self::FtpDeleteFileW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "FtpRenameFileW" => {
                Self::FtpRenameFileW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "FtpSetCurrentDirectoryW" =>
            {
                Self::FtpSetCurrentDirectoryW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "FtpGetCurrentDirectoryW" =>
            {
                Self::FtpGetCurrentDirectoryW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "FtpCreateDirectoryW" => {
                Self::FtpCreateDirectoryW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "FtpRemoveDirectoryW" => {
                Self::FtpRemoveDirectoryW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "InternetGetConnectedState" =>
            {
                Self::InternetGetConnectedState
            }
            // -- Phase 1.3.3: Missing kernel32.dll imports for Steam.exe ---------------
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetFilePointerEx" => {
                Self::SetFilePointerEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileSizeEx" => {
                Self::GetFileSizeEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileTime" => {
                Self::GetFileTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetEndOfFile" => {
                Self::SetEndOfFile
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SleepEx" => {
                Self::SleepEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CopyFileW" => {
                Self::CopyFileW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "MoveFileExW" => {
                Self::MoveFileExW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFileA" => {
                Self::CreateFileA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "RemoveDirectoryA" => {
                Self::RemoveDirectoryA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileAttributesA" => {
                Self::GetFileAttributesA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCurrentDirectoryA" =>
            {
                Self::GetCurrentDirectoryA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDriveTypeW" => {
                Self::GetDriveTypeW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CompareStringW" => {
                Self::CompareStringW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GlobalMemoryStatusEx" =>
            {
                Self::GlobalMemoryStatusEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapValidate" => {
                Self::HeapValidate
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapSetInformation" => {
                Self::HeapSetInformation
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapLock" => {
                Self::HeapLock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapUnlock" => {
                Self::HeapUnlock
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "HeapWalk" => {
                Self::HeapWalk
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "HeapQueryInformation" =>
            {
                Self::HeapQueryInformation
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "IsBadWritePtr" => {
                Self::IsBadWritePtr
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SwitchToThread" => {
                Self::SwitchToThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenThread" => {
                Self::OpenThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetThreadPriority" => {
                Self::SetThreadPriority
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "TerminateThread" => {
                Self::TerminateThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ExitThread" => {
                Self::ExitThread
            }
            ("api-ms-win-core-processthreads-l1-1-0.dll", ImportSymbol::ByName { name, .. })
                if name == "ExitThread" =>
            {
                Self::ExitThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SuspendThread" => {
                Self::SuspendThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ResumeThread" => {
                Self::ResumeThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetThreadAffinityMask" =>
            {
                Self::SetThreadAffinityMask
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetProcessAffinityMask" =>
            {
                Self::GetProcessAffinityMask
            }
            // -- Phase 4.4: Synchronization primitives (kernel32) ----------------------
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateMutexW" => {
                Self::CreateMutexW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateMutexA" => {
                Self::CreateMutexA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenMutexW" => {
                Self::OpenMutexW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseMutex" => {
                Self::ReleaseMutex
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateSemaphoreW" => {
                Self::CreateSemaphoreW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateSemaphoreA" => {
                Self::CreateSemaphoreA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenSemaphoreW" => {
                Self::OpenSemaphoreW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseSemaphore" => {
                Self::ReleaseSemaphore
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "PulseEvent" => {
                Self::PulseEvent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeConditionVariable" =>
            {
                Self::InitializeConditionVariable
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "WakeConditionVariable" =>
            {
                Self::WakeConditionVariable
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetThreadPriority" => {
                Self::GetThreadPriority
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetThreadTimes" => {
                Self::GetThreadTimes
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateRemoteThread" => {
                Self::CreateRemoteThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "QueueUserAPC" => {
                Self::QueueUserAPC
            }
            // -- Phase 4.4: Thread pool APIs (kernel32) --------------------------------
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "QueueUserWorkItem" => {
                Self::QueueUserWorkItem
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateThreadpoolWork" =>
            {
                Self::CreateThreadpoolWork
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SubmitThreadpoolWork" =>
            {
                Self::SubmitThreadpoolWork
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "WaitForThreadpoolWorkCallbacks" =>
            {
                Self::WaitForThreadpoolWorkCallbacks
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CloseThreadpoolWork" =>
            {
                Self::CloseThreadpoolWork
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateThreadpoolTimer" =>
            {
                Self::CreateThreadpoolTimer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetThreadpoolTimer" => {
                Self::SetThreadpoolTimer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CloseThreadpoolTimer" =>
            {
                Self::CloseThreadpoolTimer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateThreadpoolWait" =>
            {
                Self::CreateThreadpoolWait
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetThreadpoolWait" => {
                Self::SetThreadpoolWait
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CloseThreadpoolWait" =>
            {
                Self::CloseThreadpoolWait
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateTimerQueueTimer" =>
            {
                Self::CreateTimerQueueTimer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "DeleteTimerQueueTimer" =>
            {
                Self::DeleteTimerQueueTimer
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "RegisterWaitForSingleObject" =>
            {
                Self::RegisterWaitForSingleObject
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "UnregisterWaitEx" => {
                Self::UnregisterWaitEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DebugBreak" => {
                Self::DebugBreak
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "RaiseException" => {
                Self::RaiseException
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlUnwind" => {
                Self::RtlUnwind
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlRestoreContext" => {
                Self::RtlRestoreContext
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "RtlUnwind" => {
                Self::RtlUnwind
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "RtlRestoreContext" => {
                Self::RtlRestoreContext
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetConsoleMode" => {
                Self::GetConsoleMode
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetConsoleMode" => {
                Self::SetConsoleMode
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "WriteConsoleW" => {
                Self::WriteConsoleW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReadConsoleA" => {
                Self::ReadConsoleA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReadConsoleW" => {
                Self::ReadConsoleW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetConsoleCP" => {
                Self::GetConsoleCP
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SetStdHandle" => {
                Self::SetStdHandle
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DeviceIoControl" => {
                Self::DeviceIoControl
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetProcessAffinityMask" =>
            {
                Self::SetProcessAffinityMask
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InterlockedPushEntrySList" =>
            {
                Self::InterlockedPushEntrySList
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FindResourceA" => {
                Self::FindResourceA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SizeofResource" => {
                Self::SizeofResource
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadResource" => {
                Self::LoadResource
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "LockResource" => {
                Self::LockResource
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SystemTimeToFileTime" =>
            {
                Self::SystemTimeToFileTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemTime" => {
                Self::GetSystemTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "FileTimeToSystemTime" =>
            {
                Self::FileTimeToSystemTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SystemTimeToTzSpecificLocalTime" =>
            {
                Self::SystemTimeToTzSpecificLocalTime
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDateFormatW" => {
                Self::GetDateFormatW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTimeFormatW" => {
                Self::GetTimeFormatW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "WaitForSingleObjectEx" =>
            {
                Self::WaitForSingleObjectEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "FindFirstFileExW" => {
                Self::FindFirstFileExW
            }
            // -- Phase M4: SxS Activation Context API (kernel32.dll) ----------
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateActCtxW" => {
                Self::CreateActCtxW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ActivateActCtx" => {
                Self::ActivateActCtx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DeactivateActCtx" => {
                Self::DeactivateActCtx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseActCtx" => {
                Self::ReleaseActCtx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "FindActCtxSectionStringW" =>
            {
                Self::FindActCtxSectionStringW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDiskFreeSpaceA" => {
                Self::GetDiskFreeSpaceA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GenerateConsoleCtrlEvent" =>
            {
                Self::GenerateConsoleCtrlEvent
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "SetConsoleCtrlHandler" =>
            {
                Self::SetConsoleCtrlHandler
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "ConvertThreadToFiber" =>
            {
                Self::ConvertThreadToFiber
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "ConvertFiberToThread" =>
            {
                Self::ConvertFiberToThread
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFiber" => {
                Self::CreateFiber
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteFiber" => {
                Self::DeleteFiber
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SwitchToFiber" => {
                Self::SwitchToFiber
            }
            // kernelbase.dll aliases for Phase 1.3.3 additions
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "SetFilePointerEx" => {
                Self::SetFilePointerEx
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileSizeEx" => {
                Self::GetFileSizeEx
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CompareStringW" => {
                Self::CompareStringW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GlobalMemoryStatusEx" =>
            {
                Self::GlobalMemoryStatusEx
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "SleepEx" => {
                Self::SleepEx
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "SwitchToThread" => {
                Self::SwitchToThread
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "OpenThread" => {
                Self::OpenThread
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SetThreadPriority" =>
            {
                Self::SetThreadPriority
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetProcessAffinityMask" =>
            {
                Self::GetProcessAffinityMask
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "RaiseException" => {
                Self::RaiseException
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SystemTimeToFileTime" =>
            {
                Self::SystemTimeToFileTime
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetSystemTime" => {
                Self::GetSystemTime
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "FileTimeToSystemTime" =>
            {
                Self::FileTimeToSystemTime
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SystemTimeToTzSpecificLocalTime" =>
            {
                Self::SystemTimeToTzSpecificLocalTime
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "WaitForSingleObjectEx" =>
            {
                Self::WaitForSingleObjectEx
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetDriveTypeW" => {
                Self::GetDriveTypeW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CopyFileW" => {
                Self::CopyFileW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "MoveFileExW" => {
                Self::MoveFileExW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "SetEndOfFile" => {
                Self::SetEndOfFile
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetFileTime" => {
                Self::GetFileTime
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "DebugBreak" => {
                Self::DebugBreak
            }
            // -- Phase 4.4: kernelbase.dll aliases for synchronization primitives --------
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateMutexW" => {
                Self::CreateMutexW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateMutexA" => {
                Self::CreateMutexA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "OpenMutexW" => {
                Self::OpenMutexW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseMutex" => {
                Self::ReleaseMutex
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateSemaphoreW" => {
                Self::CreateSemaphoreW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "CreateSemaphoreA" => {
                Self::CreateSemaphoreA
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "OpenSemaphoreW" => {
                Self::OpenSemaphoreW
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "ReleaseSemaphore" => {
                Self::ReleaseSemaphore
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "PulseEvent" => {
                Self::PulseEvent
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeConditionVariable" =>
            {
                Self::InitializeConditionVariable
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "WakeConditionVariable" =>
            {
                Self::WakeConditionVariable
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "GetThreadPriority" =>
            {
                Self::GetThreadPriority
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "GetThreadTimes" => {
                Self::GetThreadTimes
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateRemoteThread" =>
            {
                Self::CreateRemoteThread
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. }) if name == "QueueUserAPC" => {
                Self::QueueUserAPC
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "QueueUserWorkItem" =>
            {
                Self::QueueUserWorkItem
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateThreadpoolWork" =>
            {
                Self::CreateThreadpoolWork
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SubmitThreadpoolWork" =>
            {
                Self::SubmitThreadpoolWork
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "WaitForThreadpoolWorkCallbacks" =>
            {
                Self::WaitForThreadpoolWorkCallbacks
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CloseThreadpoolWork" =>
            {
                Self::CloseThreadpoolWork
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateThreadpoolTimer" =>
            {
                Self::CreateThreadpoolTimer
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SetThreadpoolTimer" =>
            {
                Self::SetThreadpoolTimer
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CloseThreadpoolTimer" =>
            {
                Self::CloseThreadpoolTimer
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateThreadpoolWait" =>
            {
                Self::CreateThreadpoolWait
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "SetThreadpoolWait" =>
            {
                Self::SetThreadpoolWait
            }
            ("kernelbase.dll", ImportSymbol::ByName { name, .. })
                if name == "CloseThreadpoolWait" =>
            {
                Self::CloseThreadpoolWait
            }
            // -- Phase 1.3.3: Missing user32.dll imports for Steam.exe ------------------
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetWindowThreadProcessId" =>
            {
                Self::GetWindowThreadProcessId
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "KillTimer" => {
                Self::KillTimer
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MoveWindow" => {
                Self::MoveWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDesktopWindow" => {
                Self::GetDesktopWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "MsgWaitForMultipleObjects" =>
            {
                Self::MsgWaitForMultipleObjects
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "UpdateWindow" => {
                Self::UpdateWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "UnregisterClassW" => {
                Self::UnregisterClassW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "wsprintfA" => {
                Self::WsprintfA
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DialogBoxParamA" => {
                Self::DialogBoxParamA
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetDlgItemInt" => {
                Self::SetDlgItemInt
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetDlgItemInt" => {
                Self::GetDlgItemInt
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetDlgItemTextA" => {
                Self::SetDlgItemTextA
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "IsDialogMessageW" => {
                Self::IsDialogMessageW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SendDlgItemMessageW" => {
                Self::SendDlgItemMessageW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "DefDlgProcW" => {
                Self::DefDlgProcW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "OpenClipboard" => {
                Self::OpenClipboard
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "CloseClipboard" => {
                Self::CloseClipboard
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetClipboardData" => {
                Self::SetClipboardData
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EmptyClipboard" => {
                Self::EmptyClipboard
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetClipboardData" => {
                Self::GetClipboardData
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "IsClipboardFormatAvailable" =>
            {
                Self::IsClipboardFormatAvailable
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EnumClipboardFormats" => {
                Self::EnumClipboardFormats
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetWindowTextLengthA" => {
                Self::GetWindowTextLengthA
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetProcessWindowStation" =>
            {
                Self::GetProcessWindowStation
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EnumWindows" => {
                Self::EnumWindows
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MonitorFromPoint" => {
                Self::MonitorFromPoint
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EnumChildWindows" => {
                Self::EnumChildWindows
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MapWindowPoints" => {
                Self::MapWindowPoints
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetUserObjectInformationW" =>
            {
                Self::GetUserObjectInformationW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "AllowSetForegroundWindow" =>
            {
                Self::AllowSetForegroundWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "MessageBoxA" => {
                Self::MessageBoxA
            }
            // --- I3: Scrollbars ---
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetScrollInfo" => {
                Self::SetScrollInfo
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetScrollInfo" => {
                Self::GetScrollInfo
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetScrollPos" => {
                Self::SetScrollPos
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetScrollPos" => {
                Self::GetScrollPos
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "SetScrollRange" => {
                Self::SetScrollRange
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetScrollRange" => {
                Self::GetScrollRange
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ShowScrollBar" => {
                Self::ShowScrollBar
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "EnableScrollBar" => {
                Self::EnableScrollBar
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ScrollWindow" => {
                Self::ScrollWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ScrollDC" => {
                Self::ScrollDC
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "ScrollWindowEx" => {
                Self::ScrollWindowEx
            }
            // -- Phase 1.3.3: Missing gdi32.dll imports for Steam.exe -------------------
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "AddFontMemResourceEx" => {
                Self::AddFontMemResourceEx
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. })
                if name == "RemoveFontMemResourceEx" =>
            {
                Self::RemoveFontMemResourceEx
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "TextOutW" => {
                Self::TextOutW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDIBSection" => {
                Self::CreateDIBSection
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "DeleteDC" => {
                Self::DeleteDC
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateICW" => {
                Self::CreateICW
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateCompatibleDC" => {
                Self::CreateCompatibleDC
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SwapBuffers" => {
                Self::SwapBuffers
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "SetPixelFormat" => {
                Self::SetPixelFormat
            }
            ("gdi32.dll", ImportSymbol::ByName { name, .. }) if name == "ChoosePixelFormat" => {
                Self::ChoosePixelFormat
            }
            // -- Phase 1.3.3: Missing advapi32.dll imports for Steam.exe ----------------
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "RegisterEventSourceW" =>
            {
                Self::RegisterEventSourceW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "DeregisterEventSource" =>
            {
                Self::DeregisterEventSource
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "ReportEventW" => {
                Self::ReportEventW
            }
            // -- Phase 1.3.3: Missing psapi.dll imports for Steam.exe -------------------
            ("psapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleFileNameExW" => {
                Self::GetModuleFileNameExW
            }
            ("psapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetModuleInformation" => {
                Self::GetModuleInformation
            }
            ("psapi.dll", ImportSymbol::ByName { name, .. }) if name == "GetProcessMemoryInfo" => {
                Self::GetProcessMemoryInfo
            }
            // -- Phase 1.3.3: Missing bcrypt.dll imports for Steam.exe ------------------
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptGenRandom" => {
                Self::BCryptGenRandom
            }
            // -- Phase O1: BCrypt algorithm suite (18 functions) --------------------------
            ("bcrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptOpenAlgorithmProvider" =>
            {
                Self::BCryptOpenAlgorithmProvider
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptCloseAlgorithmProvider" =>
            {
                Self::BCryptCloseAlgorithmProvider
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptGenerateSymmetricKey" =>
            {
                Self::BCryptGenerateSymmetricKey
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptGenerateKeyPair" =>
            {
                Self::BCryptGenerateKeyPair
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptFinalizeKeyPair" =>
            {
                Self::BCryptFinalizeKeyPair
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptEncrypt" => {
                Self::BCryptEncrypt
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptDecrypt" => {
                Self::BCryptDecrypt
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptHash" => {
                Self::BCryptHash
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptHashData" => {
                Self::BCryptHashData
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptCreateHash" => {
                Self::BCryptCreateHash
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptDestroyHash" => {
                Self::BCryptDestroyHash
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptDestroyKey" => {
                Self::BCryptDestroyKey
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptGetProperty" => {
                Self::BCryptGetProperty
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptSetProperty" => {
                Self::BCryptSetProperty
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptDeriveKey" => {
                Self::BCryptDeriveKey
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptSecretAgreement" =>
            {
                Self::BCryptSecretAgreement
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptImportKey" => {
                Self::BCryptImportKey
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptSignHash" => {
                Self::BCryptSignHash
            }
            ("bcrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptVerifySignature" =>
            {
                Self::BCryptVerifySignature
            }
            // -- Phase 1.3.3: Missing crypt32.dll imports for Steam.exe -----------------
            ("crypt32.dll", ImportSymbol::ByName { name, .. }) if name == "CertOpenStore" => {
                Self::CertOpenStore
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. }) if name == "CertCloseStore" => {
                Self::CertCloseStore
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertGetCertificateChain" =>
            {
                Self::CertGetCertificateChain
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertCreateCertificateContext" =>
            {
                Self::CertCreateCertificateContext
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertFreeCertificateContext" =>
            {
                Self::CertFreeCertificateContext
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertAddCertificateContextToStore" =>
            {
                Self::CertAddCertificateContextToStore
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertFreeCertificateChain" =>
            {
                Self::CertFreeCertificateChain
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertOpenSystemStoreW" =>
            {
                Self::CertOpenSystemStoreW
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertFindCertificateInStore" =>
            {
                Self::CertFindCertificateInStore
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. }) if name == "CertGetNameStringW" => {
                Self::CertGetNameStringW
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertDuplicateCertificateContext" =>
            {
                Self::CertDuplicateCertificateContext
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertVerifyCertificateChainPolicy" =>
            {
                Self::CertVerifyCertificateChainPolicy
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertEnumCertificatesInStore" =>
            {
                Self::CertEnumCertificatesInStore
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertDeleteCertificateFromStore" =>
            {
                Self::CertDeleteCertificateFromStore
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CryptAcquireCertificatePrivateKey" =>
            {
                Self::CryptAcquireCertificatePrivateKey
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. }) if name == "PFXImportCertStore" => {
                Self::PFXImportCertStore
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. }) if name == "PFXIsPFXBlob" => {
                Self::PFXIsPFXBlob
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. }) if name == "CertFindExtension" => {
                Self::CertFindExtension
            }
            ("crypt32.dll", ImportSymbol::ByName { name, .. })
                if name == "CertGetIntendedKeyUsage" =>
            {
                Self::CertGetIntendedKeyUsage
            }
            // -- Phase O4: PPL (Protected Process Light) detection --------------------------
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "IsProtectedProcess" => {
                Self::IsProtectedProcess
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "IsProtectedProcessLight" =>
            {
                Self::IsProtectedProcessLight
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlIsProtectedProcess" => {
                Self::RtlIsProtectedProcess
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "RtlIsProtectedProcessLight" =>
            {
                Self::RtlIsProtectedProcessLight
            }
            // -- Phase O3: Code integrity enforcement -------------------------------------
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtQueryInformationProcess" =>
            {
                Self::NtQueryInformationProcess
            }
            // -- Stage-4 NTDLL foundation: the native Windows API layer --------------------
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtAllocateVirtualMemory" =>
            {
                Self::NtAllocateVirtualMemory
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtFreeVirtualMemory" => {
                Self::NtFreeVirtualMemory
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtProtectVirtualMemory" =>
            {
                Self::NtProtectVirtualMemory
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtQueryVirtualMemory" => {
                Self::NtQueryVirtualMemory
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtReadVirtualMemory" => {
                Self::NtReadVirtualMemory
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtWriteVirtualMemory" => {
                Self::NtWriteVirtualMemory
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtClose" => Self::NtClose,
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtDuplicateObject" => {
                Self::NtDuplicateObject
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtQueryObject" => {
                Self::NtQueryObject
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtOpenDirectoryObject" => {
                Self::NtOpenDirectoryObject
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtQueryDirectoryObject" =>
            {
                Self::NtQueryDirectoryObject
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtQueryVolumeInformationFile" =>
            {
                Self::NtQueryVolumeInformationFile
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtAttestationChallenge" =>
            {
                Self::NtAttestationChallenge
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtAttestationQuote" => {
                Self::NtAttestationQuote
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtAttestationVerify" => {
                Self::NtAttestationVerify
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtAttestationEnrollProvider" =>
            {
                Self::NtAttestationEnrollProvider
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtAttestationRevokeProvider" =>
            {
                Self::NtAttestationRevokeProvider
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtCreateEvent" => {
                Self::NtCreateEvent
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtSetEvent" => {
                Self::NtSetEvent
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtClearEvent" => {
                Self::NtClearEvent
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtWaitForSingleObject" => {
                Self::NtWaitForSingleObject
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtWaitForMultipleObjects" =>
            {
                Self::NtWaitForMultipleObjects
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtDelayExecution" => {
                Self::NtDelayExecution
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtTestAlert" => {
                Self::NtTestAlert
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtCreateSection" => {
                Self::NtCreateSection
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtMapViewOfSection" => {
                Self::NtMapViewOfSection
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtUnmapViewOfSection" => {
                Self::NtUnmapViewOfSection
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtQuerySection" => {
                Self::NtQuerySection
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtCreateFile" => {
                Self::NtCreateFile
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtLoadDriver" => {
                Self::NtLoadDriver
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtUnloadDriver" => {
                Self::NtUnloadDriver
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtDeviceIoControlFile" => {
                Self::NtDeviceIoControlFile
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtReadFile" => {
                Self::NtReadFile
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtWriteFile" => {
                Self::NtWriteFile
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtCreateKey" => {
                Self::NtCreateKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtOpenKey" => {
                Self::NtOpenKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtQueryValueKey" => {
                Self::NtQueryValueKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtSetValueKey" => {
                Self::NtSetValueKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtDeleteKey" => {
                Self::NtDeleteKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtDeleteValueKey" => {
                Self::NtDeleteValueKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtEnumerateKey" => {
                Self::NtEnumerateKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtEnumerateValueKey" => {
                Self::NtEnumerateValueKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtQueryKey" => {
                Self::NtQueryKey
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtQueryInformationThread" =>
            {
                Self::NtQueryInformationThread
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtGetContextThread" => {
                Self::NtGetContextThread
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtSetContextThread" => {
                Self::NtSetContextThread
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtSuspendThread" => {
                Self::NtSuspendThread
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtResumeThread" => {
                Self::NtResumeThread
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtTerminateProcess" => {
                Self::NtTerminateProcess
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtTerminateThread" => {
                Self::NtTerminateThread
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtCreateThreadEx" => {
                Self::NtCreateThreadEx
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtSetInformationThread" =>
            {
                Self::NtSetInformationThread
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtQuerySystemInformation" =>
            {
                Self::NtQuerySystemInformation
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtQueryPerformanceCounter" =>
            {
                Self::NtQueryPerformanceCounter
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "NtQueryTimerResolution" =>
            {
                Self::NtQueryTimerResolution
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtSetTimerResolution" => {
                Self::NtSetTimerResolution
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "NtQuerySystemTime" => {
                Self::NtQuerySystemTime
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlInitUnicodeString" => {
                Self::RtlInitUnicodeString
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlInitAnsiString" => {
                Self::RtlInitAnsiString
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlFreeUnicodeString" => {
                Self::RtlFreeUnicodeString
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlFreeAnsiString" => {
                Self::RtlFreeAnsiString
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "RtlCompareUnicodeString" =>
            {
                Self::RtlCompareUnicodeString
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlEqualUnicodeString" => {
                Self::RtlEqualUnicodeString
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlGetVersion" => {
                Self::RtlGetVersion
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlCaptureContext" => {
                Self::RtlCaptureContext
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "RtlLookupFunctionEntry" =>
            {
                Self::RtlLookupFunctionEntry
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlRaiseException" => {
                Self::RtlRaiseException
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlAllocateHeap" => {
                Self::RtlAllocateHeap
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlFreeHeap" => {
                Self::RtlFreeHeap
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "RtlSizeHeap" => {
                Self::RtlSizeHeap
            }
            // -- Stage-4 Ldr loader chain: the native loader surface ----------
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "LdrLoadDll" => {
                Self::LdrLoadDll
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "LdrUnloadDll" => {
                Self::LdrUnloadDll
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "LdrGetDllHandle" => {
                Self::LdrGetDllHandle
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. })
                if name == "LdrGetProcedureAddress" =>
            {
                Self::LdrGetProcedureAddress
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "LdrLockLoaderLock" => {
                Self::LdrLockLoaderLock
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "LdrUnlockLoaderLock" => {
                Self::LdrUnlockLoaderLock
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "LdrAddRefDll" => {
                Self::LdrAddRefDll
            }
            ("ntdll.dll", ImportSymbol::ByName { name, .. }) if name == "LdrRemoveRefDll" => {
                Self::LdrRemoveRefDll
            }
            // -- Phase O5: Credential guard simulation ------------------------------------
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CredIsProtected" => {
                Self::CredIsProtected
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CredProtectW" => {
                Self::CredProtectW
            }
            ("advapi32.dll", ImportSymbol::ByName { name, .. }) if name == "CredUnprotectW" => {
                Self::CredUnprotectW
            }
            // -- Phase 2.1: libcef.dll CEF imports for Steam UI --------------------------
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_initialize" => {
                Self::CefInitialize
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_shutdown" => {
                Self::CefShutdown
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_get_minimal_libcef_version" =>
            {
                Self::CefGetMinimalLibcefVersion
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_browser_host_create_browser" =>
            {
                Self::CefBrowserHostCreateBrowser
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_browser_host_create_browser_sync" =>
            {
                Self::CefBrowserHostCreateBrowserSync
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_browser_get_host" => {
                Self::CefBrowserGetHost
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_browser_get_main_frame" =>
            {
                Self::CefBrowserGetMainFrame
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_browser_is_valid" => {
                Self::CefBrowserIsValid
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_frame_load_url" => {
                Self::CefFrameLoadUrl
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_frame_load_string" =>
            {
                Self::CefFrameLoadString
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_browser_go_back" => {
                Self::CefBrowserGoBack
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_browser_go_forward" =>
            {
                Self::CefBrowserGoForward
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_browser_reload" => {
                Self::CefBrowserReload
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_browser_reload_ignore_cache" =>
            {
                Self::CefBrowserReloadIgnoreCache
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_browser_stop_load" =>
            {
                Self::CefBrowserStopLoad
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_frame_execute_java_script" =>
            {
                Self::CefFrameExecuteJavaScript
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_run_message_loop" => {
                Self::CefRunMessageLoop
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_do_message_loop_work" =>
            {
                Self::CefDoMessageLoopWork
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_quit_message_loop" =>
            {
                Self::CefQuitMessageLoop
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_window_info_create" =>
            {
                Self::CefWindowInfoCreate
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_browser_settings_create" =>
            {
                Self::CefBrowserSettingsCreate
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_string_utf8_to_utf16" =>
            {
                Self::CefStringUtf8ToUtf16
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_string_utf16_to_utf8" =>
            {
                Self::CefStringUtf16ToUtf8
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_string_utf8_to_wide" =>
            {
                Self::CefStringUtf8ToWide
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_string_wide_to_utf8" =>
            {
                Self::CefStringWideToUtf8
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_add_cross_origin_whitelist_entry" =>
            {
                Self::CefAddCrossOriginWhitelistEntry
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_remove_cross_origin_whitelist_entry" =>
            {
                Self::CefRemoveCrossOriginWhitelistEntry
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_clear_cross_origin_whitelist" =>
            {
                Self::CefClearCrossOriginWhitelist
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_parse_url" => {
                Self::CefParseUrl
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. }) if name == "cef_create_url" => {
                Self::CefCreateUrl
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_register_extension" =>
            {
                Self::CefRegisterExtension
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_cookie_manager_get_global" =>
            {
                Self::CefCookieManagerGetGlobal
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_cookie_manager_set_supported_schemes" =>
            {
                Self::CefCookieManagerSetSupportedSchemes
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_cookie_manager_set_cookie" =>
            {
                Self::CefCookieManagerSetCookie
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_cookie_manager_visit_all_cookies" =>
            {
                Self::CefCookieManagerVisitAllCookies
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_cookie_manager_delete_cookies" =>
            {
                Self::CefCookieManagerDeleteCookies
            }
            ("libcef.dll", ImportSymbol::ByName { name, .. })
                if name == "cef_cookie_manager_flush_store" =>
            {
                Self::CefCookieManagerFlushStore
            }
            // ── WebView2 (webview2.dll) imports ─────────────────────────────────
            ("webview2.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateWebView2Environment" =>
            {
                Self::WebView2CreateEnvironment
            }
            ("webview2.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateWebView2EnvironmentWithDetails" =>
            {
                Self::WebView2CreateEnvironmentWithDetails
            }
            // -- DirectInput8 (Phase 4.3) --
            ("dinput8.dll", ImportSymbol::ByName { name, .. }) if name == "DirectInput8Create" => {
                Self::DirectInput8Create
            }
            // -- Raw Input (Phase 4.3) --
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "RegisterRawInputDevices" =>
            {
                Self::RegisterRawInputDevices
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetRawInputData" => {
                Self::GetRawInputData
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetRawInputDeviceInfoW" =>
            {
                Self::GetRawInputDeviceInfoW
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetRegisteredRawInputDevices" =>
            {
                Self::GetRegisteredRawInputDevices
            }
            // -- Touch / Pointer Input (Phase 6.x) --
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "RegisterTouchWindow" => {
                Self::RegisterTouchWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "UnregisterTouchWindow" =>
            {
                Self::UnregisterTouchWindow
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetTouchInputInfo" => {
                Self::GetTouchInputInfo
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "CloseTouchInputHandle" =>
            {
                Self::CloseTouchInputHandle
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializeTouchInjection" =>
            {
                Self::InitializeTouchInjection
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "InitializePointerDevice" =>
            {
                Self::InitializePointerDevice
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetPointerInfo" => {
                Self::GetPointerInfo
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetPointerPenInfo" => {
                Self::GetPointerPenInfo
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "SkipPointerFrameMessages" =>
            {
                Self::SkipPointerFrame
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetPointerDeviceCaps" => {
                Self::GetPointerDeviceCaps
            }
            ("user32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetPointerDeviceRects" =>
            {
                Self::GetPointerDeviceRects
            }
            ("user32.dll", ImportSymbol::ByName { name, .. }) if name == "GetPointerFrameInfo" => {
                Self::GetPointerFrameInfo
            }
            // -- XInput (Phase 5.2.1) --
            ("xinput1_3.dll", ImportSymbol::ByName { name, .. }) if name == "XInputGetState" => {
                Self::XInputGetState
            }
            ("xinput1_3.dll", ImportSymbol::ByName { name, .. }) if name == "XInputSetState" => {
                Self::XInputSetState
            }
            ("xinput1_3.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetCapabilities" =>
            {
                Self::XInputGetCapabilities
            }
            ("xinput1_3.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetDSoundAudioDeviceGuids" =>
            {
                Self::XInputGetDSoundAudioDeviceGuids
            }
            ("xinput1_3.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetBatteryInformation" =>
            {
                Self::XInputGetBatteryInformation
            }
            ("xinput1_3.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetKeystroke" =>
            {
                Self::XInputGetKeystroke
            }
            ("xinput1_3.dll", ImportSymbol::ByName { name, .. }) if name == "XInputEnable" => {
                Self::XInputEnable
            }
            ("xinput1_4.dll", ImportSymbol::ByName { name, .. }) if name == "XInputGetState" => {
                Self::XInputGetState
            }
            ("xinput1_4.dll", ImportSymbol::ByName { name, .. }) if name == "XInputSetState" => {
                Self::XInputSetState
            }
            ("xinput1_4.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetCapabilities" =>
            {
                Self::XInputGetCapabilities
            }
            ("xinput1_4.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetDSoundAudioDeviceGuids" =>
            {
                Self::XInputGetDSoundAudioDeviceGuids
            }
            ("xinput1_4.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetBatteryInformation" =>
            {
                Self::XInputGetBatteryInformation
            }
            ("xinput1_4.dll", ImportSymbol::ByName { name, .. })
                if name == "XInputGetKeystroke" =>
            {
                Self::XInputGetKeystroke
            }
            ("xinput1_4.dll", ImportSymbol::ByName { name, .. }) if name == "XInputEnable" => {
                Self::XInputEnable
            }
            // -- Steam Input API (Phase 5.2.4) --
            ("steam_api.dll", ImportSymbol::ByName { name, .. })
            | ("steam_api64.dll", ImportSymbol::ByName { name, .. }) => {
                match name.as_str() {
                    "SteamAPI_ISteamInput_Init" => Self::SteamAPI_ISteamInput_Init,
                    "SteamAPI_ISteamInput_Shutdown" => Self::SteamAPI_ISteamInput_Shutdown,
                    "SteamAPI_ISteamInput_RunFrame" => Self::SteamAPI_ISteamInput_RunFrame,
                    "SteamAPI_ISteamInput_GetConnectedControllers" => {
                        Self::SteamAPI_ISteamInput_GetConnectedControllers
                    }
                    "SteamAPI_ISteamInput_GetActionSetHandle" => {
                        Self::SteamAPI_ISteamInput_GetActionSetHandle
                    }
                    "SteamAPI_ISteamInput_GetDigitalActionHandle" => {
                        Self::SteamAPI_ISteamInput_GetDigitalActionHandle
                    }
                    "SteamAPI_ISteamInput_GetAnalogActionHandle" => {
                        Self::SteamAPI_ISteamInput_GetAnalogActionHandle
                    }
                    "SteamAPI_ISteamInput_ActivateActionSet" => {
                        Self::SteamAPI_ISteamInput_ActivateActionSet
                    }
                    "SteamAPI_ISteamInput_GetCurrentActionSet" => {
                        Self::SteamAPI_ISteamInput_GetCurrentActionSet
                    }
                    "SteamAPI_ISteamInput_GetDigitalActionData" => {
                        Self::SteamAPI_ISteamInput_GetDigitalActionData
                    }
                    "SteamAPI_ISteamInput_GetAnalogActionData" => {
                        Self::SteamAPI_ISteamInput_GetAnalogActionData
                    }
                    "SteamAPI_ISteamInput_TriggerRepeatedHapticPulse" => {
                        Self::SteamAPI_ISteamInput_TriggerRepeatedHapticPulse
                    }
                    "SteamAPI_ISteamInput_GetControllerInputType" => {
                        Self::SteamAPI_ISteamInput_GetControllerInputType
                    }
                    "SteamAPI_ISteamInput_GetMotionData" => {
                        Self::SteamAPI_ISteamInput_GetMotionData
                    }
                    "SteamAPI_ISteamInput_ShowBindingPanel" => {
                        Self::SteamAPI_ISteamInput_ShowBindingPanel
                    }
                    "SteamAPI_ISteamInput_GetGlyphForActionHandle" => {
                        Self::SteamAPI_ISteamInput_GetGlyphForActionHandle
                    }
                    // -- Steam Networking Sockets (Phase 5.4) --
                    "SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP" => {
                        Self::SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP
                    }
                    "SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress" => {
                        Self::SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress
                    }
                    "SteamAPI_ISteamNetworkingSockets_SendMessageToConnection" => {
                        Self::SteamAPI_ISteamNetworkingSockets_SendMessageToConnection
                    }
                    "SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnListenSocket" => {
                        Self::SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnListenSocket
                    }
                    "SteamAPI_ISteamNetworkingSockets_CloseConnection" => {
                        Self::SteamAPI_ISteamNetworkingSockets_CloseConnection
                    }
                    "SteamAPI_ISteamNetworkingSockets_DestroyListenSocket" => {
                        Self::SteamAPI_ISteamNetworkingSockets_DestroyListenSocket
                    }
                    "SteamAPI_ISteamNetworkingSockets_CreateListenSocket" => {
                        Self::SteamAPI_ISteamNetworkingSockets_CreateListenSocket
                    }
                    "SteamAPI_ISteamNetworkingSockets_ConnectBySteamID" => {
                        Self::SteamAPI_ISteamNetworkingSockets_ConnectBySteamID
                    }
                    "SteamAPI_ISteamNetworkingSockets_AcceptConnection" => {
                        Self::SteamAPI_ISteamNetworkingSockets_AcceptConnection
                    }
                    "SteamAPI_ISteamNetworkingSockets_GetConnectionStatus" => {
                        Self::SteamAPI_ISteamNetworkingSockets_GetConnectionStatus
                    }
                    "SteamAPI_ISteamNetworkingSockets_GetConnectionName" => {
                        Self::SteamAPI_ISteamNetworkingSockets_GetConnectionName
                    }
                    // -- Steam Networking Messages (Phase 5.5) --
                    "SteamAPI_ISteamNetworkingMessages_SendMessageToUser" => {
                        Self::SteamAPI_ISteamNetworkingMessages_SendMessageToUser
                    }
                    "SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel" => {
                        Self::SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel
                    }
                    "SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser" => {
                        Self::SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser
                    }
                    // -- K1: ISteamUserStats (achievements, stats, leaderboards) --
                    "SteamAPI_ISteamUserStats_RequestCurrentStats" => {
                        Self::SteamAPI_ISteamUserStats_RequestCurrentStats
                    }
                    "SteamAPI_ISteamUserStats_GetStat" => Self::SteamAPI_ISteamUserStats_GetStat,
                    "SteamAPI_ISteamUserStats_SetStat" => Self::SteamAPI_ISteamUserStats_SetStat,
                    "SteamAPI_ISteamUserStats_GetStatFloat" => {
                        Self::SteamAPI_ISteamUserStats_GetStatFloat
                    }
                    "SteamAPI_ISteamUserStats_SetStatFloat" => {
                        Self::SteamAPI_ISteamUserStats_SetStatFloat
                    }
                    "SteamAPI_ISteamUserStats_GetAchievement" => {
                        Self::SteamAPI_ISteamUserStats_GetAchievement
                    }
                    "SteamAPI_ISteamUserStats_SetAchievement" => {
                        Self::SteamAPI_ISteamUserStats_SetAchievement
                    }
                    "SteamAPI_ISteamUserStats_ClearAchievement" => {
                        Self::SteamAPI_ISteamUserStats_ClearAchievement
                    }
                    "SteamAPI_ISteamUserStats_GetAchievementName" => {
                        Self::SteamAPI_ISteamUserStats_GetAchievementName
                    }
                    "SteamAPI_ISteamUserStats_GetNumAchievements" => {
                        Self::SteamAPI_ISteamUserStats_GetNumAchievements
                    }
                    "SteamAPI_ISteamUserStats_FindOrCreateLeaderboard" => {
                        Self::SteamAPI_ISteamUserStats_FindOrCreateLeaderboard
                    }
                    "SteamAPI_ISteamUserStats_UploadLeaderboardScore" => {
                        Self::SteamAPI_ISteamUserStats_UploadLeaderboardScore
                    }
                    "SteamAPI_ISteamUserStats_DownloadLeaderboardEntries" => {
                        Self::SteamAPI_ISteamUserStats_DownloadLeaderboardEntries
                    }
                    "SteamAPI_ISteamUserStats_GetLeaderboardEntryCount" => {
                        Self::SteamAPI_ISteamUserStats_GetLeaderboardEntryCount
                    }
                    "SteamAPI_ISteamUserStats_GetLeaderboardName" => {
                        Self::SteamAPI_ISteamUserStats_GetLeaderboardName
                    }
                    "SteamAPI_ISteamUserStats_GetLeaderboardSortMethod" => {
                        Self::SteamAPI_ISteamUserStats_GetLeaderboardSortMethod
                    }
                    "SteamAPI_ISteamUserStats_GetLeaderboardDisplayType" => {
                        Self::SteamAPI_ISteamUserStats_GetLeaderboardDisplayType
                    }
                    "SteamAPI_ISteamUserStats_AttachLeaderboardUGC" => {
                        Self::SteamAPI_ISteamUserStats_AttachLeaderboardUGC
                    }
                    // -- K2: ISteamFriends --
                    "SteamAPI_ISteamFriends_GetPersonaName" => {
                        Self::SteamAPI_ISteamFriends_GetPersonaName
                    }
                    "SteamAPI_ISteamFriends_SetPersonaName" => {
                        Self::SteamAPI_ISteamFriends_SetPersonaName
                    }
                    "SteamAPI_ISteamFriends_GetPersonaState" => {
                        Self::SteamAPI_ISteamFriends_GetPersonaState
                    }
                    "SteamAPI_ISteamFriends_SetPersonaState" => {
                        Self::SteamAPI_ISteamFriends_SetPersonaState
                    }
                    "SteamAPI_ISteamFriends_GetFriendCount" => {
                        Self::SteamAPI_ISteamFriends_GetFriendCount
                    }
                    "SteamAPI_ISteamFriends_GetFriendByIndex" => {
                        Self::SteamAPI_ISteamFriends_GetFriendByIndex
                    }
                    "SteamAPI_ISteamFriends_GetFriendPersonaName" => {
                        Self::SteamAPI_ISteamFriends_GetFriendPersonaName
                    }
                    "SteamAPI_ISteamFriends_GetFriendPersonaState" => {
                        Self::SteamAPI_ISteamFriends_GetFriendPersonaState
                    }
                    "SteamAPI_ISteamFriends_GetFriendGamePlayed" => {
                        Self::SteamAPI_ISteamFriends_GetFriendGamePlayed
                    }
                    "SteamAPI_ISteamFriends_SetFriendPersonaState" => {
                        Self::SteamAPI_ISteamFriends_SetFriendPersonaState
                    }
                    "SteamAPI_ISteamFriends_AddFriend" => Self::SteamAPI_ISteamFriends_AddFriend,
                    "SteamAPI_ISteamFriends_RemoveFriend" => {
                        Self::SteamAPI_ISteamFriends_RemoveFriend
                    }
                    "SteamAPI_ISteamFriends_InviteFriend" => {
                        Self::SteamAPI_ISteamFriends_InviteFriend
                    }
                    "SteamAPI_ISteamFriends_AcceptInvite" => {
                        Self::SteamAPI_ISteamFriends_AcceptInvite
                    }
                    "SteamAPI_ISteamFriends_DeclineInvite" => {
                        Self::SteamAPI_ISteamFriends_DeclineInvite
                    }
                    "SteamAPI_ISteamFriends_GetInviteCount" => {
                        Self::SteamAPI_ISteamFriends_GetInviteCount
                    }
                    "SteamAPI_ISteamFriends_GetInviteByIndex" => {
                        Self::SteamAPI_ISteamFriends_GetInviteByIndex
                    }
                    "SteamAPI_ISteamFriends_SendFriendMessage" => {
                        Self::SteamAPI_ISteamFriends_SendFriendMessage
                    }
                    "SteamAPI_ISteamFriends_GetFriendMessage" => {
                        Self::SteamAPI_ISteamFriends_GetFriendMessage
                    }
                    "SteamAPI_ISteamFriends_GetFriendMessageCount" => {
                        Self::SteamAPI_ISteamFriends_GetFriendMessageCount
                    }
                    "SteamAPI_ISteamFriends_JoinClan" => Self::SteamAPI_ISteamFriends_JoinClan,
                    "SteamAPI_ISteamFriends_LeaveClan" => Self::SteamAPI_ISteamFriends_LeaveClan,
                    "SteamAPI_ISteamFriends_GetClanCount" => {
                        Self::SteamAPI_ISteamFriends_GetClanCount
                    }
                    "SteamAPI_ISteamFriends_GetClanByIndex" => {
                        Self::SteamAPI_ISteamFriends_GetClanByIndex
                    }
                    "SteamAPI_ISteamFriends_GetClanName" => {
                        Self::SteamAPI_ISteamFriends_GetClanName
                    }
                    "SteamAPI_ISteamFriends_IsClanMember" => {
                        Self::SteamAPI_ISteamFriends_IsClanMember
                    }
                    "SteamAPI_ISteamFriends_SetRichPresence" => {
                        Self::SteamAPI_ISteamFriends_SetRichPresence
                    }
                    "SteamAPI_ISteamFriends_ClearRichPresence" => {
                        Self::SteamAPI_ISteamFriends_ClearRichPresence
                    }
                    "SteamAPI_ISteamFriends_ActivateGameOverlayToWebPage" => {
                        Self::SteamAPI_ISteamFriends_ActivateGameOverlayToWebPage
                    }
                    "SteamAPI_ISteamFriends_ActivateGameOverlayToFriends" => {
                        Self::SteamAPI_ISteamFriends_ActivateGameOverlayToFriends
                    }
                    "SteamAPI_ISteamFriends_ActivateGameOverlay" => {
                        Self::SteamAPI_ISteamFriends_ActivateGameOverlay
                    }
                    "SteamAPI_ISteamFriends_ActivateGameOverlayToUser" => {
                        Self::SteamAPI_ISteamFriends_ActivateGameOverlayToUser
                    }
                    "SteamAPI_ISteamFriends_ActivateGameOverlayToStore" => {
                        Self::SteamAPI_ISteamFriends_ActivateGameOverlayToStore
                    }
                    "SteamAPI_ISteamFriends_ActivateGameOverlayToInviteDialog" => {
                        Self::SteamAPI_ISteamFriends_ActivateGameOverlayToInviteDialog
                    }
                    "SteamAPI_ISteamFriends_GetSmallFriendAvatar" => {
                        Self::SteamAPI_ISteamFriends_GetSmallFriendAvatar
                    }
                    "SteamAPI_ISteamFriends_GetMediumFriendAvatar" => {
                        Self::SteamAPI_ISteamFriends_GetMediumFriendAvatar
                    }
                    "SteamAPI_ISteamFriends_GetLargeFriendAvatar" => {
                        Self::SteamAPI_ISteamFriends_GetLargeFriendAvatar
                    }
                    // -- K3: ISteamMatchmaking (lobbies) --
                    "SteamAPI_ISteamMatchmaking_CreateLobby" => {
                        Self::SteamAPI_ISteamMatchmaking_CreateLobby
                    }
                    "SteamAPI_ISteamMatchmaking_JoinLobby" => {
                        Self::SteamAPI_ISteamMatchmaking_JoinLobby
                    }
                    "SteamAPI_ISteamMatchmaking_LeaveLobby" => {
                        Self::SteamAPI_ISteamMatchmaking_LeaveLobby
                    }
                    "SteamAPI_ISteamMatchmaking_GetLobbyData" => {
                        Self::SteamAPI_ISteamMatchmaking_GetLobbyData
                    }
                    "SteamAPI_ISteamMatchmaking_SetLobbyData" => {
                        Self::SteamAPI_ISteamMatchmaking_SetLobbyData
                    }
                    "SteamAPI_ISteamMatchmaking_GetLobbyMemberCount" => {
                        Self::SteamAPI_ISteamMatchmaking_GetLobbyMemberCount
                    }
                    "SteamAPI_ISteamMatchmaking_GetLobbyMemberByIndex" => {
                        Self::SteamAPI_ISteamMatchmaking_GetLobbyMemberByIndex
                    }
                    "SteamAPI_ISteamMatchmaking_GetLobbyMemberData" => {
                        Self::SteamAPI_ISteamMatchmaking_GetLobbyMemberData
                    }
                    "SteamAPI_ISteamMatchmaking_SetLobbyMemberData" => {
                        Self::SteamAPI_ISteamMatchmaking_SetLobbyMemberData
                    }
                    "SteamAPI_ISteamMatchmaking_GetLobbyOwner" => {
                        Self::SteamAPI_ISteamMatchmaking_GetLobbyOwner
                    }
                    "SteamAPI_ISteamMatchmaking_SetLobbyOwner" => {
                        Self::SteamAPI_ISteamMatchmaking_SetLobbyOwner
                    }
                    "SteamAPI_ISteamMatchmaking_SetLobbyJoinable" => {
                        Self::SteamAPI_ISteamMatchmaking_SetLobbyJoinable
                    }
                    "SteamAPI_ISteamMatchmaking_SendLobbyChatMessage" => {
                        Self::SteamAPI_ISteamMatchmaking_SendLobbyChatMessage
                    }
                    "SteamAPI_ISteamMatchmaking_RequestLobbyList" => {
                        Self::SteamAPI_ISteamMatchmaking_RequestLobbyList
                    }
                    "SteamAPI_ISteamMatchmaking_GetLobbyByIndex" => {
                        Self::SteamAPI_ISteamMatchmaking_GetLobbyByIndex
                    }
                    "SteamAPI_ISteamMatchmaking_GetLobbyCount" => {
                        Self::SteamAPI_ISteamMatchmaking_GetLobbyCount
                    }
                    // -- K5: ISteamRemoteStorage (cloud storage) --
                    "SteamAPI_ISteamRemoteStorage_FileWrite" => {
                        Self::SteamAPI_ISteamRemoteStorage_FileWrite
                    }
                    "SteamAPI_ISteamRemoteStorage_FileRead" => {
                        Self::SteamAPI_ISteamRemoteStorage_FileRead
                    }
                    "SteamAPI_ISteamRemoteStorage_FileDelete" => {
                        Self::SteamAPI_ISteamRemoteStorage_FileDelete
                    }
                    "SteamAPI_ISteamRemoteStorage_FileExists" => {
                        Self::SteamAPI_ISteamRemoteStorage_FileExists
                    }
                    "SteamAPI_ISteamRemoteStorage_FileSize" => {
                        Self::SteamAPI_ISteamRemoteStorage_FileSize
                    }
                    "SteamAPI_ISteamRemoteStorage_FileTime" => {
                        Self::SteamAPI_ISteamRemoteStorage_FileTime
                    }
                    "SteamAPI_ISteamRemoteStorage_GetFileCount" => {
                        Self::SteamAPI_ISteamRemoteStorage_GetFileCount
                    }
                    "SteamAPI_ISteamRemoteStorage_GetFileName" => {
                        Self::SteamAPI_ISteamRemoteStorage_GetFileName
                    }
                    "SteamAPI_ISteamRemoteStorage_GetFileSize" => {
                        Self::SteamAPI_ISteamRemoteStorage_GetFileSize
                    }
                    "SteamAPI_ISteamRemoteStorage_GetQuotaUsed" => {
                        Self::SteamAPI_ISteamRemoteStorage_GetQuotaUsed
                    }
                    "SteamAPI_ISteamRemoteStorage_GetQuotaTotal" => {
                        Self::SteamAPI_ISteamRemoteStorage_GetQuotaTotal
                    }
                    "SteamAPI_ISteamRemoteStorage_IsCloudEnabledForAccount" => {
                        Self::SteamAPI_ISteamRemoteStorage_IsCloudEnabledForAccount
                    }
                    "SteamAPI_ISteamRemoteStorage_IsCloudEnabledForApp" => {
                        Self::SteamAPI_ISteamRemoteStorage_IsCloudEnabledForApp
                    }
                    "SteamAPI_ISteamRemoteStorage_UGCDownload" => {
                        Self::SteamAPI_ISteamRemoteStorage_UGCDownload
                    }
                    "SteamAPI_ISteamRemoteStorage_UGCSubscribe" => {
                        Self::SteamAPI_ISteamRemoteStorage_UGCSubscribe
                    }
                    "SteamAPI_ISteamRemoteStorage_UGCUnsubscribe" => {
                        Self::SteamAPI_ISteamRemoteStorage_UGCUnsubscribe
                    }
                    // -- K6: ISteamScreenshots --
                    "SteamAPI_ISteamScreenshots_WriteScreenshot" => {
                        Self::SteamAPI_ISteamScreenshots_WriteScreenshot
                    }
                    "SteamAPI_ISteamScreenshots_AddScreenshotToLibrary" => {
                        Self::SteamAPI_ISteamScreenshots_AddScreenshotToLibrary
                    }
                    "SteamAPI_ISteamScreenshots_TriggerScreenshot" => {
                        Self::SteamAPI_ISteamScreenshots_TriggerScreenshot
                    }
                    "SteamAPI_ISteamScreenshots_HookScreenshots" => {
                        Self::SteamAPI_ISteamScreenshots_HookScreenshots
                    }
                    "SteamAPI_ISteamScreenshots_IsScreenshotsHooked" => {
                        Self::SteamAPI_ISteamScreenshots_IsScreenshotsHooked
                    }
                    "SteamAPI_ISteamScreenshots_GetScreenshotCount" => {
                        Self::SteamAPI_ISteamScreenshots_GetScreenshotCount
                    }
                    "SteamAPI_ISteamScreenshots_GetScreenshotByIndex" => {
                        Self::SteamAPI_ISteamScreenshots_GetScreenshotByIndex
                    }
                    "SteamAPI_ISteamScreenshots_GetScreenshotFilePath" => {
                        Self::SteamAPI_ISteamScreenshots_GetScreenshotFilePath
                    }
                    "SteamAPI_ISteamScreenshots_GetScreenshotThumbnailPath" => {
                        Self::SteamAPI_ISteamScreenshots_GetScreenshotThumbnailPath
                    }
                    "SteamAPI_ISteamScreenshots_TagUser" => {
                        Self::SteamAPI_ISteamScreenshots_TagUser
                    }
                    "SteamAPI_ISteamScreenshots_TagPublishedFile" => {
                        Self::SteamAPI_ISteamScreenshots_TagPublishedFile
                    }
                    // -- K7: ISteamMusic (stubs) --
                    "SteamAPI_ISteamMusic_IsEnabled" => Self::SteamAPI_ISteamMusic_IsEnabled,
                    "SteamAPI_ISteamMusic_SetEnabled" => Self::SteamAPI_ISteamMusic_SetEnabled,
                    "SteamAPI_ISteamMusic_IsPlaying" => Self::SteamAPI_ISteamMusic_IsPlaying,
                    "SteamAPI_ISteamMusic_Play" => Self::SteamAPI_ISteamMusic_Play,
                    "SteamAPI_ISteamMusic_Pause" => Self::SteamAPI_ISteamMusic_Pause,
                    "SteamAPI_ISteamMusic_PlayNext" => Self::SteamAPI_ISteamMusic_PlayNext,
                    "SteamAPI_ISteamMusic_PlayPrevious" => Self::SteamAPI_ISteamMusic_PlayPrevious,
                    "SteamAPI_ISteamMusic_SetVolume" => Self::SteamAPI_ISteamMusic_SetVolume,
                    "SteamAPI_ISteamMusic_GetVolume" => Self::SteamAPI_ISteamMusic_GetVolume,
                    // -- Steam API flat exports (Phase B3) --
                    "SteamAPI_Init" => Self::SteamAPI_Init,
                    "SteamAPI_Shutdown" => Self::SteamAPI_Shutdown,
                    "SteamAPI_RestartAppIfNecessary" => Self::SteamAPI_RestartAppIfNecessary,
                    "SteamAPI_RegisterCallback" => Self::SteamAPI_RegisterCallback,
                    "SteamAPI_UnregisterCallback" => Self::SteamAPI_UnregisterCallback,
                    "SteamAPI_RegisterCallResult" => Self::SteamAPI_RegisterCallResult,
                    "SteamAPI_UnregisterCallResult" => Self::SteamAPI_UnregisterCallResult,
                    "SteamAPI_RunCallbacks" => Self::SteamAPI_RunCallbacks,
                    "SteamAPI_GetSteamInstallPath" => Self::SteamAPI_GetSteamInstallPath,
                    "SteamAPI_WriteMiniDump" => Self::SteamAPI_WriteMiniDump,
                    "SteamAPI_SetMiniDumpComment" => Self::SteamAPI_SetMiniDumpComment,
                    "SteamInternal_CreateInterface" => Self::SteamInternal_CreateInterface,
                    "SteamInternal_FindOrCreateUserInterface" => {
                        Self::SteamInternal_FindOrCreateUserInterface
                    }
                    "SteamInternal_FindOrCreateGameInterface" => {
                        Self::SteamInternal_FindOrCreateGameInterface
                    }
                    "SteamInternal_ContextInit" => Self::SteamInternal_ContextInit,
                    _ => Self::Unsupported {
                        dll: import.resolved_module.clone(),
                        symbol: name.clone(),
                    },
                }
            }
            // -- SteamVR / OpenVR (Phase 5.3.1) --
            ("openvr_api.dll", ImportSymbol::ByName { name, .. })
            | ("openvr_api64.dll", ImportSymbol::ByName { name, .. }) => match name.as_str() {
                "VR_Init" => Self::SteamVR_Init,
                "VR_Shutdown" => Self::SteamVR_Shutdown,
                "VR_IsHmdPresent" => Self::SteamVR_IsHmdPresent,
                "VR_IsRuntimeInstalled" => Self::SteamVR_IsRuntimeInstalled,
                "VR_GetStringForHmdError" => Self::SteamVR_GetStringForHmdError,
                "VR_RuntimePath" => Self::SteamVR_RuntimePath,
                "VR_GetGenericInterface" => Self::SteamVR_GetGenericInterface,
                _ => Self::Unsupported {
                    dll: import.resolved_module.clone(),
                    symbol: name.clone(),
                },
            },
            // ── Phase 2.7: GDI+ (gdiplus.dll) ──────────────────────────────────
            ("gdiplus.dll", ImportSymbol::ByName { name, .. }) => {
                match name.as_str() {
                    "GdiplusStartup" => Self::GdiplusStartup,
                    "GdiplusShutdown" => Self::GdiplusShutdown,
                    "GdipCreateFromHDC" => Self::GdipCreateFromHDC,
                    "GdipDeleteGraphics" => Self::GdipDeleteGraphics,
                    // Drawing primitives
                    "GdipDrawLine" => Self::GdipDrawLine,
                    "GdipDrawLines" => Self::GdipDrawLines,
                    "GdipDrawRectangle" => Self::GdipDrawRectangle,
                    "GdipFillRectangle" => Self::GdipFillRectangle,
                    "GdipDrawEllipse" => Self::GdipDrawEllipse,
                    "GdipFillEllipse" => Self::GdipFillEllipse,
                    "GdipDrawPie" => Self::GdipDrawPie,
                    "GdipFillPie" => Self::GdipFillPie,
                    "GdipDrawPolygon" => Self::GdipDrawPolygon,
                    "GdipFillPolygon" => Self::GdipFillPolygon,
                    "GdipDrawArc" => Self::GdipDrawArc,
                    "GdipDrawCurve" => Self::GdipDrawCurve,
                    "GdipDrawClosedCurve" => Self::GdipDrawClosedCurve,
                    "GdipDrawString" => Self::GdipDrawString,
                    // Brushes
                    "GdipCreateSolidFill" => Self::GdipCreateSolidFill,
                    "GdipCreateLineBrush" => Self::GdipCreateLineBrush,
                    "GdipCreateTextureBrush" => Self::GdipCreateTextureBrush,
                    "GdipDeleteBrush" => Self::GdipDeleteBrush,
                    "GdipFillRegion" => Self::GdipFillRegion,
                    // Pens
                    "GdipCreatePen1" => Self::GdipCreatePen1,
                    "GdipCreatePen2" => Self::GdipCreatePen2,
                    "GdipSetPenWidth" => Self::GdipSetPenWidth,
                    "GdipGetPenWidth" => Self::GdipGetPenWidth,
                    "GdipSetPenColor" => Self::GdipSetPenColor,
                    "GdipGetPenColor" => Self::GdipGetPenColor,
                    "GdipSetPenDashStyle" => Self::GdipSetPenDashStyle,
                    "GdipGetPenDashStyle" => Self::GdipGetPenDashStyle,
                    "GdipSetPenLineJoin" => Self::GdipSetPenLineJoin,
                    "GdipSetPenStartCap" => Self::GdipSetPenStartCap,
                    "GdipSetPenEndCap" => Self::GdipSetPenEndCap,
                    "GdipDeletePen" => Self::GdipDeletePen,
                    // Paths
                    "GdipCreatePath" => Self::GdipCreatePath,
                    "GdipDeletePath" => Self::GdipDeletePath,
                    "GdipAddPathLine" => Self::GdipAddPathLine,
                    "GdipAddPathRectangle" => Self::GdipAddPathRectangle,
                    "GdipAddPathEllipse" => Self::GdipAddPathEllipse,
                    "GdipAddPathArc" => Self::GdipAddPathArc,
                    "GdipAddPathBezier" => Self::GdipAddPathBezier,
                    "GdipClosePathFigure" => Self::GdipClosePathFigure,
                    "GdipStartPathFigure" => Self::GdipStartPathFigure,
                    "GdipSetPathFillMode" => Self::GdipSetPathFillMode,
                    "GdipDrawPath" => Self::GdipDrawPath,
                    "GdipFillPath" => Self::GdipFillPath,
                    // Transforms
                    "GdipCreateMatrix" => Self::GdipCreateMatrix,
                    "GdipDeleteMatrix" => Self::GdipDeleteMatrix,
                    "GdipSetMatrixElements" => Self::GdipSetMatrixElements,
                    "GdipGetMatrixElements" => Self::GdipGetMatrixElements,
                    "GdipTranslateMatrix" => Self::GdipTranslateMatrix,
                    "GdipRotateMatrix" => Self::GdipRotateMatrix,
                    "GdipScaleMatrix" => Self::GdipScaleMatrix,
                    "GdipInvertMatrix" => Self::GdipInvertMatrix,
                    "GdipMultiplyMatrix" => Self::GdipMultiplyMatrix,
                    "GdipSetWorldTransform" => Self::GdipSetWorldTransform,
                    "GdipResetWorldTransform" => Self::GdipResetWorldTransform,
                    "GdipGetWorldTransform" => Self::GdipGetWorldTransform,
                    // Clipping
                    "GdipSetClipRect" => Self::GdipSetClipRect,
                    "GdipSetClipPath" => Self::GdipSetClipPath,
                    "GdipSetClipRegion" => Self::GdipSetClipRegion,
                    "GdipResetClip" => Self::GdipResetClip,
                    "GdipGetClipBounds" => Self::GdipGetClipBounds,
                    "GdipGetClip" => Self::GdipGetClip,
                    // Containers
                    "GdipSaveGraphics" => Self::GdipSaveGraphics,
                    "GdipRestoreGraphics" => Self::GdipRestoreGraphics,
                    "GdipBeginContainer" => Self::GdipBeginContainer,
                    "GdipEndContainer" => Self::GdipEndContainer,
                    // Bitmap interop
                    "GdipCreateBitmapFromHBITMAP" => Self::GdipCreateBitmapFromHBITMAP,
                    "GdipCreateBitmapFromFile" => Self::GdipCreateBitmapFromFile,
                    "GdipCreateBitmapFromGraphics" => Self::GdipCreateBitmapFromGraphics,
                    "GdipDisposeImage" => Self::GdipDisposeImage,
                    "GdipGetImageWidth" => Self::GdipGetImageWidth,
                    "GdipGetImageHeight" => Self::GdipGetImageHeight,
                    "GdipGetImagePixelFormat" => Self::GdipGetImagePixelFormat,
                    "GdipBitmapGetPixel" => Self::GdipBitmapGetPixel,
                    "GdipBitmapSetPixel" => Self::GdipBitmapSetPixel,
                    "GdipBitmapLockBits" => Self::GdipBitmapLockBits,
                    "GdipBitmapUnlockBits" => Self::GdipBitmapUnlockBits,
                    // Text/Font
                    "GdipCreateFont" => Self::GdipCreateFont,
                    "GdipDeleteFont" => Self::GdipDeleteFont,
                    "GdipCreateFontFamilyFromName" => Self::GdipCreateFontFamilyFromName,
                    "GdipDeleteFontFamily" => Self::GdipDeleteFontFamily,
                    "GdipSetTextRenderingHint" => Self::GdipSetTextRenderingHint,
                    "GdipMeasureString" => Self::GdipMeasureString,
                    "GdipMeasureCharacterRanges" => Self::GdipMeasureCharacterRanges,
                    // Image attributes
                    "GdipCreateImageAttributes" => Self::GdipCreateImageAttributes,
                    "GdipDisposeImageAttributes" => Self::GdipDisposeImageAttributes,
                    "GdipSetImageAttributesColorKeys" => Self::GdipSetImageAttributesColorKeys,
                    "GdipSetImageAttributesColorMatrix" => Self::GdipSetImageAttributesColorMatrix,
                    // Quality settings
                    "GdipSetSmoothingMode" => Self::GdipSetSmoothingMode,
                    "GdipGetSmoothingMode" => Self::GdipGetSmoothingMode,
                    "GdipSetCompositingMode" => Self::GdipSetCompositingMode,
                    "GdipGetCompositingMode" => Self::GdipGetCompositingMode,
                    "GdipSetCompositingQuality" => Self::GdipSetCompositingQuality,
                    "GdipGetCompositingQuality" => Self::GdipGetCompositingQuality,
                    "GdipSetInterpolationMode" => Self::GdipSetInterpolationMode,
                    "GdipGetInterpolationMode" => Self::GdipGetInterpolationMode,
                    "GdipSetPixelOffsetMode" => Self::GdipSetPixelOffsetMode,
                    "GdipGetPixelOffsetMode" => Self::GdipGetPixelOffsetMode,
                    // Image drawing (existing + new)
                    "GdipDrawImage" => Self::GdipDrawImage,
                    "GdipDrawImageRect" => Self::GdipDrawImageRect,
                    "GdipDrawImageRectRect" => Self::GdipDrawImageRectRect,
                    "GdipGetImageType" => Self::GdipGetImageType,
                    "GdipGetImageRawFormat" => Self::GdipGetImageRawFormat,
                    "GdipCloneImage" => Self::GdipCloneImage,
                    "GdipSaveImageToFile" => Self::GdipSaveImageToFile,
                    "GdipSaveImageToStream" => Self::GdipSaveImageToStream,
                    "GdipCreateBitmapFromStream" => Self::GdipCreateBitmapFromStream,
                    "GdipCreateBitmapFromScan0" => Self::GdipCreateBitmapFromScan0,
                    "GdipCreateHICONFromBitmap" => Self::GdipCreateHICONFromBitmap,
                    "GdipCreateHBITMAPFromBitmap" => Self::GdipCreateHBITMAPFromBitmap,
                    "GdipCreateImageFromFile" => Self::GdipCreateImageFromFile,
                    "GdipImageForceValidation" => Self::GdipImageForceValidation,
                    "GdipGetFontHeight" => Self::GdipGetFontHeight,
                    "GdipCreateBitmapFromGdiDib" => Self::GdipCreateBitmapFromGdiDib,
                    _ => Self::Unsupported {
                        dll: import.resolved_module.clone(),
                        symbol: name.clone(),
                    },
                }
            }
            // -- DWrite exports --
            ("dwrite.dll", ImportSymbol::ByName { name, .. }) if name == "DWriteCreateFactory" => {
                Self::DWriteCreateFactory
            }
            // -- D2D exports --
            ("d2d1.dll", ImportSymbol::ByName { name, .. }) if name == "D2D1CreateFactory" => {
                Self::D2D1CreateFactory
            }
            ("d2d1.dll", ImportSymbol::ByName { name, .. }) if name == "D2D1MakeRotateMatrix" => {
                Self::D2D1MakeRotateMatrix
            }
            ("d2d1.dll", ImportSymbol::ByName { name, .. }) if name == "D2D1MakeSkewMatrix" => {
                Self::D2D1MakeSkewMatrix
            }
            ("d2d1.dll", ImportSymbol::ByName { name, .. }) if name == "D2D1IsMatrixInvertible" => {
                Self::D2D1IsMatrixInvertible
            }
            ("d2d1.dll", ImportSymbol::ByName { name, .. }) if name == "D2D1InvertMatrix" => {
                Self::D2D1InvertMatrix
            }
            // -- winspool.drv / Printing (Phase Print) --
            ("winspool.drv", ImportSymbol::ByName { name, .. })
                if name == "OpenPrinterW" || name == "OpenPrinter" =>
            {
                Self::OpenPrinterW
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. }) if name == "ClosePrinter" => {
                Self::ClosePrinter
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. })
                if name == "StartDocPrinterW" || name == "StartDocPrinter" =>
            {
                Self::StartDocPrinterW
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. }) if name == "EndDocPrinter" => {
                Self::EndDocPrinter
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. }) if name == "StartPagePrinter" => {
                Self::StartPagePrinter
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. }) if name == "EndPagePrinter" => {
                Self::EndPagePrinter
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. }) if name == "WritePrinter" => {
                Self::WritePrinter
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. }) if name == "ReadPrinter" => {
                Self::ReadPrinter
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. })
                if name == "EnumPrintersW" || name == "EnumPrinters" =>
            {
                Self::EnumPrintersW
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. })
                if name == "GetPrinterW" || name == "GetPrinter" =>
            {
                Self::GetPrinterW
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. })
                if name == "SetPrinterW" || name == "SetPrinter" =>
            {
                Self::SetPrinterW
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. })
                if name == "AddPrinterW" || name == "AddPrinter" =>
            {
                Self::AddPrinterW
            }
            ("winspool.drv", ImportSymbol::ByName { name, .. }) if name == "DeletePrinter" => {
                Self::DeletePrinter
            }
            // -- WinMM (Windows Multimedia) audio (Phase 2.5) --
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutOpen" => {
                Self::WaveOutOpen
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutClose" => {
                Self::WaveOutClose
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutPrepareHeader" => {
                Self::WaveOutPrepareHeader
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. })
                if name == "waveOutUnprepareHeader" =>
            {
                Self::WaveOutUnprepareHeader
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutWrite" => {
                Self::WaveOutWrite
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutReset" => {
                Self::WaveOutReset
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutGetVolume" => {
                Self::WaveOutGetVolume
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutSetVolume" => {
                Self::WaveOutSetVolume
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutGetDevCapsW" => {
                Self::WaveOutGetDevCapsW
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutGetNumDevs" => {
                Self::WaveOutGetNumDevs
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInOpen" => {
                Self::WaveInOpen
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInClose" => {
                Self::WaveInClose
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInPrepareHeader" => {
                Self::WaveInPrepareHeader
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInUnprepareHeader" => {
                Self::WaveInUnprepareHeader
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInAddBuffer" => {
                Self::WaveInAddBuffer
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInStart" => {
                Self::WaveInStart
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInStop" => {
                Self::WaveInStop
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInGetDevCapsW" => {
                Self::WaveInGetDevCapsW
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "waveInGetNumDevs" => {
                Self::WaveInGetNumDevs
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutOpen" => {
                Self::MidiOutOpen
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutClose" => {
                Self::MidiOutClose
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutShortMsg" => {
                Self::MidiOutShortMsg
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutLongMsg" => {
                Self::MidiOutLongMsg
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutReset" => {
                Self::MidiOutReset
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutGetDevCapsW" => {
                Self::MidiOutGetDevCapsW
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutGetNumDevs" => {
                Self::MidiOutGetNumDevs
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiInOpen" => {
                Self::MidiInOpen
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiInClose" => {
                Self::MidiInClose
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiInStart" => {
                Self::MidiInStart
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiInStop" => {
                Self::MidiInStop
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "midiInReset" => {
                Self::MidiInReset
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "timeGetTime" => {
                Self::TimeGetTime
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "timeBeginPeriod" => {
                Self::TimeBeginPeriod
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "timeEndPeriod" => {
                Self::TimeEndPeriod
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "PlaySoundW" => {
                Self::PlaySoundW
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "mmioOpenW" => {
                Self::MmioOpenW
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "mmioClose" => {
                Self::MmioClose
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "mmioRead" => {
                Self::MmioRead
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "mmioWrite" => {
                Self::MmioWrite
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "mmioAscend" => {
                Self::MmioAscend
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "mmioDescend" => {
                Self::MmioDescend
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "mmioCreateChunk" => {
                Self::MmioCreateChunk
            }
            ("winmm.dll", ImportSymbol::ByName { name, .. }) if name == "mmioStringToFOURCCW" => {
                Self::MmioStringToFOURCCW
            }
            // -- winmmbase.dll: the same wave/midi device surface (the
            //    exports dispatch into the shared winmm device model).
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutOpen" => {
                Self::WaveOutOpen
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutClose" => {
                Self::WaveOutClose
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutWrite" => {
                Self::WaveOutWrite
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutReset" => {
                Self::WaveOutReset
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutGetVolume" => {
                Self::WaveOutGetVolume
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutSetVolume" => {
                Self::WaveOutSetVolume
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. })
                if name == "waveOutGetDevCapsW" =>
            {
                Self::WaveOutGetDevCapsW
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveOutGetNumDevs" => {
                Self::WaveOutGetNumDevs
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveInOpen" => {
                Self::WaveInOpen
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveInClose" => {
                Self::WaveInClose
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. })
                if name == "waveInPrepareHeader" =>
            {
                Self::WaveInPrepareHeader
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. })
                if name == "waveInUnprepareHeader" =>
            {
                Self::WaveInUnprepareHeader
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveInAddBuffer" => {
                Self::WaveInAddBuffer
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveInStart" => {
                Self::WaveInStart
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveInStop" => {
                Self::WaveInStop
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveInGetDevCapsW" => {
                Self::WaveInGetDevCapsW
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "waveInGetNumDevs" => {
                Self::WaveInGetNumDevs
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutOpen" => {
                Self::MidiOutOpen
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutClose" => {
                Self::MidiOutClose
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutShortMsg" => {
                Self::MidiOutShortMsg
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutLongMsg" => {
                Self::MidiOutLongMsg
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutReset" => {
                Self::MidiOutReset
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. })
                if name == "midiOutGetDevCapsW" =>
            {
                Self::MidiOutGetDevCapsW
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiOutGetNumDevs" => {
                Self::MidiOutGetNumDevs
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiInOpen" => {
                Self::MidiInOpen
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiInClose" => {
                Self::MidiInClose
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiInStart" => {
                Self::MidiInStart
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiInStop" => {
                Self::MidiInStop
            }
            ("winmmbase.dll", ImportSymbol::ByName { name, .. }) if name == "midiInReset" => {
                Self::MidiInReset
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmIsCompositionEnabled" =>
            {
                Self::DwmIsCompositionEnabled
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. }) if name == "DwmEnableComposition" => {
                Self::DwmEnableComposition
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmEnableBlurBehindWindow" =>
            {
                Self::DwmEnableBlurBehindWindow
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmExtendFrameIntoClientArea" =>
            {
                Self::DwmExtendFrameIntoClientArea
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmGetColorizationColor" =>
            {
                Self::DwmGetColorizationColor
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmGetWindowAttribute" =>
            {
                Self::DwmGetWindowAttribute
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmSetWindowAttribute" =>
            {
                Self::DwmSetWindowAttribute
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. }) if name == "DwmFlush" => {
                Self::DwmFlush
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. }) if name == "DwmRegisterThumbnail" => {
                Self::DwmRegisterThumbnail
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmUpdateThumbnailProperties" =>
            {
                Self::DwmUpdateThumbnailProperties
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmUnregisterThumbnail" =>
            {
                Self::DwmUnregisterThumbnail
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmSetIconicThumbnail" =>
            {
                Self::DwmSetIconicThumbnail
            }
            ("dwmapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DwmSetIconicLivePreviewBitmap" =>
            {
                Self::DwmSetIconicLivePreviewBitmap
            }
            ("wintrust.dll", ImportSymbol::ByName { name, .. }) if name == "WinVerifyTrust" => {
                Self::WinVerifyTrust
            }
            // -- kernel32 core surface (interlocked / environment / INI /
            //    file-info / version / search / loader-lock) -----------------
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "DisableThreadLibraryCalls" =>
            {
                Self::DisableThreadLibraryCalls
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "ExpandEnvironmentStringsW" =>
            {
                Self::ExpandEnvironmentStringsW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetFileInformationByHandleEx" =>
            {
                Self::GetFileInformationByHandleEx
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "GetPrivateProfileStringW" =>
            {
                Self::GetPrivateProfileStringW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "GetVersionExA" => {
                Self::GetVersionExA
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InterlockedCompareExchange" =>
            {
                Self::InterlockedCompareExchange
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InterlockedDecrement" =>
            {
                Self::InterlockedDecrement
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InterlockedExchange" =>
            {
                Self::InterlockedExchange
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InterlockedExchangeAdd" =>
            {
                Self::InterlockedExchangeAdd
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. })
                if name == "InterlockedIncrement" =>
            {
                Self::InterlockedIncrement
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "MoveFileW" => {
                Self::MoveFileW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "SearchPathW" => {
                Self::SearchPathW
            }
            ("kernel32.dll", ImportSymbol::ByName { name, .. }) if name == "lstrcmpiA" => {
                Self::LstrcmpiA
            }
            // -- shlwapi.dll: path helpers -----------------------------------
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathAppendW" => {
                Self::PathAppendW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathCombineW" => {
                Self::PathCombineW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathFileExistsW" => {
                Self::PathFileExistsW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathFindExtensionW" => {
                Self::PathFindExtensionW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathFindFileNameW" => {
                Self::PathFindFileNameW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathRemoveFileSpecW" => {
                Self::PathRemoveFileSpecW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. })
                if name == "PathRemoveExtensionW" =>
            {
                Self::PathRemoveExtensionW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathRemoveBlanksW" => {
                Self::PathRemoveBlanksW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathIsDirectoryW" => {
                Self::PathIsDirectoryW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathIsRelativeW" => {
                Self::PathIsRelativeW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathCanonicalizeW" => {
                Self::PathCanonicalizeW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathMatchSpecW" => {
                Self::PathMatchSpecW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathStripPathW" => {
                Self::PathStripPathW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathGetDriveNumberW" => {
                Self::PathGetDriveNumberW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathAddBackslashW" => {
                Self::PathAddBackslashW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. })
                if name == "PathRemoveBackslashW" =>
            {
                Self::PathRemoveBackslashW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathSkipRootW" => {
                Self::PathSkipRootW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "PathIsRootW" => {
                Self::PathIsRootW
            }
            // -- shlwapi.dll: string / char-class helpers --------------------
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "ChrCmpIW" => {
                Self::ChrCmpIW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "IntlStrEqWorkerW" => {
                Self::IntlStrEqWorkerW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "IsCharAlphaW" => {
                Self::IsCharAlphaW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "IsCharAlphaNumericW" => {
                Self::IsCharAlphaNumericW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "IsCharLowerW" => {
                Self::IsCharLowerW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "IsCharUpperW" => {
                Self::IsCharUpperW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "IsCharSpaceW" => {
                Self::IsCharSpaceW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "ParseURLW" => {
                Self::ParseURLW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrChrW" => {
                Self::StrChrW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrChrIW" => {
                Self::StrChrIW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrRChrW" => {
                Self::StrRChrW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrStrW" => {
                Self::StrStrW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrStrIW" => {
                Self::StrStrIW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrCmpIW" => {
                Self::StrCmpIW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrCmpNIW" => {
                Self::StrCmpNIW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrCmpNW" => {
                Self::StrCmpNW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrCmpW" => {
                Self::StrCmpW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrCpyNW" => {
                Self::StrCpyNW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrCpyW" => {
                Self::StrCpyW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrCatW" => {
                Self::StrCatW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "StrToIntW" => {
                Self::StrToIntW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. })
                if name == "StrFromTimeIntervalW" =>
            {
                Self::StrFromTimeIntervalW
            }
            // -- shlwapi.dll: registry / URL / misc helpers ------------------
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "SHRegGetValueW" => {
                Self::SHRegGetValueW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "SHRegSetValueW" => {
                Self::SHRegSetValueW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "SHDeleteKeyW" => {
                Self::SHDeleteKeyW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "SHDeleteEmptyKeyW" => {
                Self::SHDeleteEmptyKeyW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "SHSearchMapInt" => {
                Self::SHSearchMapInt
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. })
                if name == "GetMenuContextHelpId" =>
            {
                Self::GetMenuContextHelpId
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SetMenuContextHelpId" =>
            {
                Self::SetMenuContextHelpId
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "UrlCanonicalizeW" => {
                Self::UrlCanonicalizeW
            }
            ("shlwapi.dll", ImportSymbol::ByName { name, .. }) if name == "UrlCombineW" => {
                Self::UrlCombineW
            }
            ("mf.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateSinkWriterFromMediaSink" =>
            {
                Self::MfCreateSinkWriterFromMediaSink
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateMediaSession" => {
                Self::MfCreateMediaSession
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFAddPeriodicCallback" =>
            {
                Self::MfAddPeriodicCallback
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCancelPeriodicCallback" =>
            {
                Self::MfCancelPeriodicCallback
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. }) if name == "MFGetSystemTime" => {
                Self::MfGetSystemTime
            }
            ("mfplat.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateDXGIDeviceManager" =>
            {
                Self::MfCreateDxgiDeviceManager
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "NCryptCreatePersistedKey" =>
            {
                Self::NCryptCreatePersistedKey
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptDecrypt" => {
                Self::NCryptDecrypt
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptDeleteKey" => {
                Self::NCryptDeleteKey
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptDeriveKey" => {
                Self::NCryptDeriveKey
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptEncrypt" => {
                Self::NCryptEncrypt
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptExportKey" => {
                Self::NCryptExportKey
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptFinalizeKey" => {
                Self::NCryptFinalizeKey
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptFreeBuffer" => {
                Self::NCryptFreeBuffer
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptGetProperty" => {
                Self::NCryptGetProperty
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptImportKey" => {
                Self::NCryptImportKey
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptIsAlgSupported" => {
                Self::NCryptIsAlgSupported
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptOpenKey" => {
                Self::NCryptOpenKey
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "NCryptOpenStorageProvider" =>
            {
                Self::NCryptOpenStorageProvider
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "NCryptSecretAgreement" =>
            {
                Self::NCryptSecretAgreement
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptSetProperty" => {
                Self::NCryptSetProperty
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. }) if name == "NCryptSignHash" => {
                Self::NCryptSignHash
            }
            ("ncrypt.dll", ImportSymbol::ByName { name, .. })
                if name == "NCryptVerifySignature" =>
            {
                Self::NCryptVerifySignature
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. }) if name == "I_RpcExceptionFilter" => {
                Self::IRpcExceptionFilter
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. }) if name == "RpcBindingFree" => {
                Self::RpcBindingFree
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. })
                if name == "RpcBindingFromStringBindingW" =>
            {
                Self::RpcBindingFromStringBindingW
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. })
                if name == "RpcStringBindingComposeW" =>
            {
                Self::RpcStringBindingComposeW
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. }) if name == "RpcStringFreeW" => {
                Self::RpcStringFreeW
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. }) if name == "UuidCreate" => {
                Self::UuidCreate
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. }) if name == "UuidCreateSequential" => {
                Self::UuidCreateSequential
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. }) if name == "UuidFromStringW" => {
                Self::UuidFromStringW
            }
            ("rpcrt4.dll", ImportSymbol::ByName { name, .. }) if name == "UuidToStringW" => {
                Self::UuidToStringW
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. })
                if name == "InitPropVariantFromGUIDAsString" =>
            {
                Self::InitPropVariantFromGUIDAsString
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. })
                if name == "InitPropVariantFromString" =>
            {
                Self::InitPropVariantFromString
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. })
                if name == "PSGetNameFromPropertyKey" =>
            {
                Self::PSGetNameFromPropertyKey
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. })
                if name == "PSGetPropertyDescriptionFromName" =>
            {
                Self::PSGetPropertyDescriptionFromName
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. })
                if name == "PSGetPropertyKeyFromName" =>
            {
                Self::PSGetPropertyKeyFromName
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. })
                if name == "PSPropertyKeyFromString" =>
            {
                Self::PSPropertyKeyFromString
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. })
                if name == "PSStringFromPropertyKey" =>
            {
                Self::PSStringFromPropertyKey
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. }) if name == "PropVariantClear" => {
                Self::PropVariantClear
            }
            ("propsys.dll", ImportSymbol::ByName { name, .. }) if name == "PropVariantCopy" => {
                Self::PropVariantCopy
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImmGetCompositionStringW" =>
            {
                Self::ImmGetCompositionStringW
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. }) if name == "ImmGetContext" => {
                Self::ImmGetContext
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. }) if name == "ImmGetDefaultIMEWnd" => {
                Self::ImmGetDefaultIMEWnd
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. }) if name == "ImmGetVirtualKey" => {
                Self::ImmGetVirtualKey
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. }) if name == "ImmIsIME" => {
                Self::ImmIsIME
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. }) if name == "ImmNotifyIME" => {
                Self::ImmNotifyIME
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. }) if name == "ImmReleaseContext" => {
                Self::ImmReleaseContext
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImmSetCompositionStringW" =>
            {
                Self::ImmSetCompositionStringW
            }
            ("imm32.dll", ImportSymbol::ByName { name, .. }) if name == "ImmSimulateHotKey" => {
                Self::ImmSimulateHotKey
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "BeginBufferedPaint" => {
                Self::BeginBufferedPaint
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. })
                if name == "BeginPanningFeedback" =>
            {
                Self::BeginPanningFeedback
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "BufferedPaintInit" => {
                Self::BufferedPaintInit
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "BufferedPaintUnInit" => {
                Self::BufferedPaintUnInit
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "CloseThemeData" => {
                Self::CloseThemeData
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "DrawThemeBackground" => {
                Self::DrawThemeBackground
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "DrawThemeText" => {
                Self::DrawThemeText
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. })
                if name == "EnableThemeDialogTexture" =>
            {
                Self::EnableThemeDialogTexture
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "EndBufferedPaint" => {
                Self::EndBufferedPaint
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. })
                if name == "GetThemeBackgroundContentRect" =>
            {
                Self::GetThemeBackgroundContentRect
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "GetThemeColor" => {
                Self::GetThemeColor
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "GetThemeFont" => {
                Self::GetThemeFont
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "GetThemePartSize" => {
                Self::GetThemePartSize
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "GetThemeSysColor" => {
                Self::GetThemeSysColor
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "GetThemeSysFont" => {
                Self::GetThemeSysFont
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "GetThemeTextExtent" => {
                Self::GetThemeTextExtent
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "IsAppThemed" => {
                Self::IsAppThemed
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "IsThemeActive" => {
                Self::IsThemeActive
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "OpenThemeData" => {
                Self::OpenThemeData
            }
            ("uxtheme.dll", ImportSymbol::ByName { name, .. }) if name == "SetWindowTheme" => {
                Self::SetWindowTheme
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. }) if name == "BindImage" => {
                Self::BindImage
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. }) if name == "BindImageEx" => {
                Self::BindImageEx
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. }) if name == "CheckSumMappedFile" => {
                Self::CheckSumMappedFile
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageAddCertificate" =>
            {
                Self::ImageAddCertificate
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageEnumerateCertificates" =>
            {
                Self::ImageEnumerateCertificates
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageGetCertificateData" =>
            {
                Self::ImageGetCertificateData
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageGetCertificateHeader" =>
            {
                Self::ImageGetCertificateHeader
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageGetDigestStream" =>
            {
                Self::ImageGetDigestStream
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. }) if name == "ImageLoad" => {
                Self::ImageLoad
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageRemoveCertificate" =>
            {
                Self::ImageRemoveCertificate
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. }) if name == "ImageUnload" => {
                Self::ImageUnload
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. }) if name == "ImagehlpApiVersion" => {
                Self::ImagehlpApiVersion
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. }) if name == "MapAndLoad" => {
                Self::MapAndLoad
            }
            ("imagehlp.dll", ImportSymbol::ByName { name, .. }) if name == "UnMapAndLoad" => {
                Self::UnMapAndLoad
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidD_FreePreparsedData" => {
                Self::HidDFreePreparsedData
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidD_GetAttributes" => {
                Self::HidDGetAttributes
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidD_GetHidGuid" => {
                Self::HidDGetHidGuid
            }
            ("hid.dll", ImportSymbol::ByName { name, .. })
                if name == "HidD_GetManufacturerString" =>
            {
                Self::HidDGetManufacturerString
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidD_GetPreparsedData" => {
                Self::HidDGetPreparsedData
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidD_GetProductString" => {
                Self::HidDGetProductString
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidP_GetButtonCaps" => {
                Self::HidPGetButtonCaps
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidP_GetCaps" => {
                Self::HidPGetCaps
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidP_GetUsageValue" => {
                Self::HidPGetUsageValue
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidP_GetUsages" => {
                Self::HidPGetUsages
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidP_GetValueCaps" => {
                Self::HidPGetValueCaps
            }
            ("hid.dll", ImportSymbol::ByName { name, .. }) if name == "HidP_SetUsages" => {
                Self::HidPSetUsages
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmDriverClose" => {
                Self::AcmDriverClose
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmDriverEnum" => {
                Self::AcmDriverEnum
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmDriverOpen" => {
                Self::AcmDriverOpen
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmFormatDetailsW" => {
                Self::AcmFormatDetailsW
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmFormatEnumW" => {
                Self::AcmFormatEnumW
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmFormatSuggest" => {
                Self::AcmFormatSuggest
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmMetrics" => {
                Self::AcmMetrics
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmStreamClose" => {
                Self::AcmStreamClose
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmStreamConvert" => {
                Self::AcmStreamConvert
            }
            ("msacm32.dll", ImportSymbol::ByName { name, .. }) if name == "acmStreamOpen" => {
                Self::AcmStreamOpen
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmDriverClose" => {
                Self::AcmDriverClose
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmDriverEnum" => {
                Self::AcmDriverEnum
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmDriverMessage" => {
                Self::AcmDriverMessage
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmDriverOpen" => {
                Self::AcmDriverOpen
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmFormatDetails" => {
                Self::AcmFormatDetails
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmFormatEnum" => {
                Self::AcmFormatEnum
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmFormatSuggest" => {
                Self::AcmFormatSuggest
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmMetrics" => {
                Self::AcmMetrics
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmStreamClose" => {
                Self::AcmStreamClose
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmStreamConvert" => {
                Self::AcmStreamConvert
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmStreamOpen" => {
                Self::AcmStreamOpen
            }
            ("msacm32.drv", ImportSymbol::ByName { name, .. }) if name == "acmStreamSize" => {
                Self::AcmStreamSize
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiCloseAllHandles" => {
                Self::MsiCloseAllHandles
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiCloseHandle" => {
                Self::MsiCloseHandle
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiConfigureProductW" => {
                Self::MsiConfigureProductW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiCreateRecord" => {
                Self::MsiCreateRecord
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiDatabaseCommit" => {
                Self::MsiDatabaseCommit
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiDatabaseOpenViewW" => {
                Self::MsiDatabaseOpenViewW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiEnumProductsW" => {
                Self::MsiEnumProductsW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiGetProductInfoW" => {
                Self::MsiGetProductInfoW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiGetPropertyW" => {
                Self::MsiGetPropertyW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiInstallProductW" => {
                Self::MsiInstallProductW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiOpenDatabaseW" => {
                Self::MsiOpenDatabaseW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiOpenPackageW" => {
                Self::MsiOpenPackageW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiQueryProductInfoW" => {
                Self::MsiQueryProductInfoW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiRecordDataSize" => {
                Self::MsiRecordDataSize
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiRecordGetInteger" => {
                Self::MsiRecordGetInteger
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiRecordGetStringW" => {
                Self::MsiRecordGetStringW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiRecordReadStream" => {
                Self::MsiRecordReadStream
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiRecordSetInteger" => {
                Self::MsiRecordSetInteger
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiRecordSetStringW" => {
                Self::MsiRecordSetStringW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiReinstallProductW" => {
                Self::MsiReinstallProductW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiSetPropertyW" => {
                Self::MsiSetPropertyW
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiViewClose" => {
                Self::MsiViewClose
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiViewExecute" => {
                Self::MsiViewExecute
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiViewFetch" => {
                Self::MsiViewFetch
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiViewGetColumnInfo" => {
                Self::MsiViewGetColumnInfo
            }
            ("msi.dll", ImportSymbol::ByName { name, .. }) if name == "MsiViewModify" => {
                Self::MsiViewModify
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IMoniker" => {
                Self::OleIidMoniker
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IPersist" => {
                Self::OleIidPersist
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IStream" => {
                Self::OleIidStream
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IStorage" => {
                Self::OleIidStorage
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IMalloc" => {
                Self::OleIidMalloc
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IDropTarget" => {
                Self::OleIidDropTarget
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IDataObject" => {
                Self::OleIidDataObject
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IOleObject" => {
                Self::OleIidOleObject
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IOleInPlaceObject" => {
                Self::OleIidInPlaceObject
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IObjectWithSite" => {
                Self::OleIidObjectWithSite
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "IServiceProvider" => {
                Self::OleIidServiceProvider
            }
            ("ole32.dll", ImportSymbol::ByName { name, .. }) if name == "GetRunningObjectTable" => {
                Self::OleGetRunningObjectTable
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateDispTypeInfo" => {
                Self::OleCreateDispTypeInfo
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "CreateStdDispatch" => {
                Self::OleCreateStdDispatch
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "DispGetIDsOfNames" => {
                Self::OleDispGetIdsOfNames
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "DispGetParam" => {
                Self::OleDispGetParam
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "DispInvoke" => {
                Self::OleDispInvoke
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadRegTypeLib" => {
                Self::OleLoadRegTypeLib
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "LoadTypeLib" => {
                Self::OleLoadTypeLib
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. })
                if name == "QueryPathOfRegTypeLib" =>
            {
                Self::OleQueryPathOfRegTypeLib
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "RegisterTypeLib" => {
                Self::OleRegisterTypeLib
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "UnRegisterTypeLib" => {
                Self::OleUnRegisterTypeLib
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "IEnumVARIANT" => {
                Self::OleIidEnumVariant
            }
            ("oleaut32.dll", ImportSymbol::ByName { name, .. }) if name == "IConnectionPoint" => {
                Self::OleIidConnectionPoint
            }
            ("ddraw.dll", ImportSymbol::ByName { name, .. }) if name == "DirectDrawCreate" => {
                Self::DirectDrawCreate
            }
            ("ddraw.dll", ImportSymbol::ByName { name, .. }) if name == "DirectDrawCreateEx" => {
                Self::DirectDrawCreateEx
            }
            ("ddraw.dll", ImportSymbol::ByName { name, .. })
                if name == "DirectDrawEnumerateExW" =>
            {
                Self::DirectDrawEnumerateExW
            }
            ("ddraw.dll", ImportSymbol::ByName { name, .. }) if name == "DirectDrawEnumerateW" => {
                Self::DirectDrawEnumerateW
            }
            ("ddraw.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("ddraw.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("ddraw.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("ddraw.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "D3DPERF_BeginEvent" => {
                Self::D3dPerfBeginEvent
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "D3DPERF_EndEvent" => {
                Self::D3dPerfEndEvent
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "D3DPERF_GetStatus" => {
                Self::D3dPerfGetStatus
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DPERF_QueryRepeatFrame" =>
            {
                Self::D3dPerfQueryRepeatFrame
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "D3DPERF_SetMarker" => {
                Self::D3dPerfSetMarker
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "D3DPERF_SetOptions" => {
                Self::D3dPerfSetOptions
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "DebugSetLevel" => {
                Self::DebugSetLevel
            }
            ("d3d9.dll", ImportSymbol::ByName { name, .. }) if name == "DebugSetMute" => {
                Self::DebugSetMute
            }
            ("d3d10.dll", ImportSymbol::ByName { name, .. }) if name == "D3D10CreateDevice" => {
                Self::D3d10CreateDevice
            }
            ("d3d10.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10CreateDeviceAndSwapChain" =>
            {
                Self::D3d10CreateDeviceAndSwapChain
            }
            ("d3d10.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10CreateEffectFromMemory" =>
            {
                Self::D3d10CreateEffectFromMemory
            }
            ("d3d10.dll", ImportSymbol::ByName { name, .. }) if name == "D3D10CreateStateBlock" => {
                Self::D3d10CreateStateBlock
            }
            ("d3d10.dll", ImportSymbol::ByName { name, .. }) if name == "D3D10RegisterLayers" => {
                Self::D3d10CoreRegisterLayers
            }
            ("d3d10core.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10CoreCreateDevice" =>
            {
                Self::D3d10CoreCreateDevice
            }
            ("d3d10core.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10CoreCreateLayeredDevice" =>
            {
                Self::D3d10CoreCreateLayeredDevice
            }
            ("d3d10core.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10CoreGetSupportedVersions" =>
            {
                Self::D3d10CoreGetSupportedVersions
            }
            ("d3d10core.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10CoreRegisterLayers" =>
            {
                Self::D3d10CoreRegisterLayers
            }
            ("d3d10level9.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10Level9CreateDevice" =>
            {
                Self::D3d10Level9CreateDevice
            }
            ("d3d10level9.dll", ImportSymbol::ByName { name, .. })
                if name == "D3D10Level9GetSupportedVersions" =>
            {
                Self::D3d10Level9GetSupportedVersions
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. }) if name == "D3DCompile" => {
                Self::D3dCompile
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. }) if name == "D3DCompile2" => {
                Self::D3dCompile2
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DCompileFromFile" =>
            {
                Self::D3dCompileFromFile
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DCreateLinker" =>
            {
                Self::D3dCreateLinker
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DDisassemble" =>
            {
                Self::D3dDisassemble
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DGetBlobPart" =>
            {
                Self::D3dGetBlobPart
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DGetTraceInstructionOffsets" =>
            {
                Self::D3dGetTraceInstructionOffsets
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DLoadModule" =>
            {
                Self::D3dLoadModule
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. }) if name == "D3DReflect" => {
                Self::D3dReflect
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DSetBlobPart" =>
            {
                Self::D3dSetBlobPart
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DSetTraceInstructionOffsets" =>
            {
                Self::D3dSetTraceInstructionOffsets
            }
            ("d3dcompiler_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DStripShader" =>
            {
                Self::D3dStripShader
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. }) if name == "D3DCompile" => {
                Self::D3dCompile
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. }) if name == "D3DCompile2" => {
                Self::D3dCompile2
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DCompileFromFile" =>
            {
                Self::D3dCompileFromFile
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DCreateLinker" =>
            {
                Self::D3dCreateLinker
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DDisassemble" =>
            {
                Self::D3dDisassemble
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DGetBlobPart" =>
            {
                Self::D3dGetBlobPart
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DGetTraceInstructionOffsets" =>
            {
                Self::D3dGetTraceInstructionOffsets
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DLoadModule" =>
            {
                Self::D3dLoadModule
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. }) if name == "D3DReflect" => {
                Self::D3dReflect
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DSetBlobPart" =>
            {
                Self::D3dSetBlobPart
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DSetTraceInstructionOffsets" =>
            {
                Self::D3dSetTraceInstructionOffsets
            }
            ("d3dcompiler_47.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DStripShader" =>
            {
                Self::D3dStripShader
            }
            ("d3dx9_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11CompileFromFile" =>
            {
                Self::D3dx11CompileFromFile
            }
            ("d3dx9_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11CreateAsyncShaderResourceViewProcessor" =>
            {
                Self::D3dx11CreateAsyncShaderResourceViewProcessor
            }
            ("d3dx9_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11CreateShaderResourceViewFromFile" =>
            {
                Self::D3dx11CreateShaderResourceViewFromFile
            }
            ("d3dx9_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11CreateTextureFromFileW" =>
            {
                Self::D3dx11CreateTextureFromFileW
            }
            ("d3dx9_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11FilterTexture" =>
            {
                Self::D3dx11FilterTexture
            }
            ("d3dx9_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11GetImageInfoFromFile" =>
            {
                Self::D3dx11GetImageInfoFromFile
            }
            ("d3dx9_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11SaveTextureToFileW" =>
            {
                Self::D3dx11SaveTextureToFileW
            }
            ("d3dx9_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11SaveTextureToMemory" =>
            {
                Self::D3dx11SaveTextureToMemory
            }
            ("d3dx11_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11CompileFromFileW" =>
            {
                Self::D3dx11CompileFromFileW
            }
            ("d3dx11_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11CreateShaderResourceViewFromFileW" =>
            {
                Self::D3dx11CreateShaderResourceViewFromFileW
            }
            ("d3dx11_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11CreateTextureFromFileW" =>
            {
                Self::D3dx11CreateTextureFromFileW
            }
            ("d3dx11_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11CreateTextureFromMemory" =>
            {
                Self::D3dx11CreateTextureFromMemory
            }
            ("d3dx11_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11GetImageInfoFromFileW" =>
            {
                Self::D3dx11GetImageInfoFromFileW
            }
            ("d3dx11_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11LoadTextureFromTexture" =>
            {
                Self::D3dx11LoadTextureFromTexture
            }
            ("d3dx11_43.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DX11SaveTextureToFileW" =>
            {
                Self::D3dx11SaveTextureToFileW
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "ChooseColorW" => {
                Self::ChooseColorW
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "ChooseFontW" => {
                Self::ChooseFontW
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. })
                if name == "CommDlgExtendedError" =>
            {
                Self::CommDlgExtendedError
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "FindTextW" => {
                Self::FindTextW
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "ImageList_GetIcon" => {
                Self::ImageListGetIcon
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_GetIconSize" =>
            {
                Self::ImageListGetIconSize
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. })
                if name == "ImageList_SetIconSize" =>
            {
                Self::ImageListSetIconSize
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "InitCommonControls" => {
                Self::InitCommonControls
            }
            ("comctl32.dll", ImportSymbol::ByName { name, .. }) if name == "PropertySheetW" => {
                Self::PropertySheetW
            }
            ("cfgmgr32.dll", ImportSymbol::ByName { name, .. })
                if name == "CM_Free_Device_ID_List" =>
            {
                Self::CmFreeDeviceIdList
            }
            ("cfgmgr32.dll", ImportSymbol::ByName { name, .. })
                if name == "CM_Get_DevNode_Status" =>
            {
                Self::CmGetDevNodeStatus
            }
            ("cfgmgr32.dll", ImportSymbol::ByName { name, .. })
                if name == "CM_Get_Device_ID_ListW" =>
            {
                Self::CmGetDeviceIdListW
            }
            ("cfgmgr32.dll", ImportSymbol::ByName { name, .. })
                if name == "CM_Get_Device_ID_List_SizeW" =>
            {
                Self::CmGetDeviceIdListSizeW
            }
            ("cfgmgr32.dll", ImportSymbol::ByName { name, .. }) if name == "CM_Locate_DevNodeW" => {
                Self::CmLocateDevNodeW
            }
            ("powrprof.dll", ImportSymbol::ByName { name, .. })
                if name == "PowerGetActiveScheme" =>
            {
                Self::PowerGetActiveScheme
            }
            ("powrprof.dll", ImportSymbol::ByName { name, .. }) if name == "PowerReadACValue" => {
                Self::PowerReadACValue
            }
            ("powrprof.dll", ImportSymbol::ByName { name, .. }) if name == "PowerReadDCValue" => {
                Self::PowerReadDCValue
            }
            ("powrprof.dll", ImportSymbol::ByName { name, .. })
                if name == "PowerSetActiveScheme" =>
            {
                Self::PowerSetActiveScheme
            }
            ("wimgapi.dll", ImportSymbol::ByName { name, .. }) if name == "WIMApplyImage" => {
                Self::WimApplyImage
            }
            ("wimgapi.dll", ImportSymbol::ByName { name, .. }) if name == "WIMCloseHandle" => {
                Self::WimCloseHandle
            }
            ("wimgapi.dll", ImportSymbol::ByName { name, .. }) if name == "WIMCreateFile" => {
                Self::WimCreateFile
            }
            ("wimgapi.dll", ImportSymbol::ByName { name, .. }) if name == "WIMLoadImage" => {
                Self::WimLoadImage
            }
            ("wimgapi.dll", ImportSymbol::ByName { name, .. })
                if name == "WIMUnmountImageHandle" =>
            {
                Self::WimUnmountImageHandle
            }
            ("wintypes.dll", ImportSymbol::ByName { name, .. }) if name == "RoActivateInstance" => {
                Self::RoActivateInstance
            }
            ("wintypes.dll", ImportSymbol::ByName { name, .. })
                if name == "RoGetActivationFactory" =>
            {
                Self::RoGetActivationFactory
            }
            ("wintypes.dll", ImportSymbol::ByName { name, .. }) if name == "RoInitialize" => {
                Self::RoInitialize
            }
            ("wintypes.dll", ImportSymbol::ByName { name, .. }) if name == "RoUninitialize" => {
                Self::RoUninitialize
            }
            ("xmllite.dll", ImportSymbol::ByName { name, .. }) if name == "CreateXmlReader" => {
                Self::CreateXmlReader
            }
            ("xmllite.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateXmlReaderInputWithEncoding" =>
            {
                Self::CreateXmlReaderInputWithEncoding
            }
            ("xmllite.dll", ImportSymbol::ByName { name, .. }) if name == "CreateXmlWriter" => {
                Self::CreateXmlWriter
            }
            ("xmllite.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateXmlWriterOutputWithEncoding" =>
            {
                Self::CreateXmlWriterOutputWithEncoding
            }
            ("urlmon.dll", ImportSymbol::ByName { name, .. })
                if name == "CoInternetIsFeatureEnabled" =>
            {
                Self::CoInternetIsFeatureEnabled
            }
            ("urlmon.dll", ImportSymbol::ByName { name, .. })
                if name == "CoInternetSetFeatureEnabled" =>
            {
                Self::CoInternetSetFeatureEnabled
            }
            ("urlmon.dll", ImportSymbol::ByName { name, .. })
                if name == "ObtainUserAgentString" =>
            {
                Self::ObtainUserAgentString
            }
            ("urlmon.dll", ImportSymbol::ByName { name, .. })
                if name == "URLDownloadToCacheFileW" =>
            {
                Self::UrlDownloadToCacheFileW
            }
            ("urlmon.dll", ImportSymbol::ByName { name, .. }) if name == "URLDownloadToFileW" => {
                Self::UrlDownloadToFileW
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpCrackUrl" => {
                Self::WinHttpCrackUrl
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. }) if name == "WinHttpCreateUrl" => {
                Self::WinHttpCreateUrl
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpDetectAutoProxyConfigUrl" =>
            {
                Self::WinHttpDetectAutoProxyConfigUrl
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpTimeFromSystemTime" =>
            {
                Self::WinHttpTimeFromSystemTime
            }
            ("winhttp.dll", ImportSymbol::ByName { name, .. })
                if name == "WinHttpTimeToSystemTime" =>
            {
                Self::WinHttpTimeToSystemTime
            }
            ("sapi.dll", ImportSymbol::ByName { name, .. }) if name == "SpCreateObjectFromKey" => {
                Self::SpCreateObjectFromKey
            }
            ("sapi.dll", ImportSymbol::ByName { name, .. })
                if name == "SpCreateObjectFromToken" =>
            {
                Self::SpCreateObjectFromToken
            }
            ("sapi.dll", ImportSymbol::ByName { name, .. }) if name == "SpEnumTokens" => {
                Self::SpEnumTokens
            }
            ("sapi.dll", ImportSymbol::ByName { name, .. }) if name == "SpGetCategoryFromId" => {
                Self::SpGetCategoryFromId
            }
            ("sapi.dll", ImportSymbol::ByName { name, .. }) if name == "SpGetDescription" => {
                Self::SpGetDescription
            }
            ("rasapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RasDial" => {
                Self::RasDial
            }
            ("rasapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RasEnumConnections" => {
                Self::RasEnumConnections
            }
            ("rasapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "RasGetConnectionStatus" =>
            {
                Self::RasGetConnectionStatus
            }
            ("rasapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RasGetErrorString" => {
                Self::RasGetErrorString
            }
            ("rasapi32.dll", ImportSymbol::ByName { name, .. }) if name == "RasHangUp" => {
                Self::RasHangUp
            }
            ("rasapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "RasSetEntryProperties" =>
            {
                Self::RasSetEntryProperties
            }
            ("wbemprox.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("wbemprox.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("wbemprox.dll", ImportSymbol::ByName { name, .. }) if name == "WMIClose" => {
                Self::WmiClose
            }
            ("wbemprox.dll", ImportSymbol::ByName { name, .. }) if name == "WMIConnect" => {
                Self::WmiConnect
            }
            ("wbemprox.dll", ImportSymbol::ByName { name, .. }) if name == "WMIInitialize" => {
                Self::WmiInitialize
            }
            ("wbemprox.dll", ImportSymbol::ByName { name, .. }) if name == "WMIQuery" => {
                Self::WmiQuery
            }
            ("uiautomationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "UiaGetPatternProvider" =>
            {
                Self::UiaGetPatternProvider
            }
            ("uiautomationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "UiaGetRuntimeId" =>
            {
                Self::UiaGetRuntimeId
            }
            ("uiautomationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "UiaGetUpdatedCache" =>
            {
                Self::UiaGetUpdatedCache
            }
            ("uiautomationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "UiaLookupId" =>
            {
                Self::UiaLookupId
            }
            ("uiautomationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "UiaNavigate" =>
            {
                Self::UiaNavigate
            }
            ("uiautomationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "UiaRaiseAutomationEvent" =>
            {
                Self::UiaRaiseAutomationEvent
            }
            ("uiautomationcore.dll", ImportSymbol::ByName { name, .. })
                if name == "UiaRaiseAutomationPropertyChangedEvent" =>
            {
                Self::UiaRaiseAutomationPropertyChangedEvent
            }
            ("oleacc.dll", ImportSymbol::ByName { name, .. })
                if name == "AccessibleObjectFromEvent" =>
            {
                Self::AccessibleObjectFromEvent
            }
            ("oleacc.dll", ImportSymbol::ByName { name, .. })
                if name == "AccessibleObjectFromPoint" =>
            {
                Self::AccessibleObjectFromPoint
            }
            ("oleacc.dll", ImportSymbol::ByName { name, .. })
                if name == "AccessibleObjectFromWindow" =>
            {
                Self::AccessibleObjectFromWindow
            }
            ("oleacc.dll", ImportSymbol::ByName { name, .. })
                if name == "GetAccessibleObjectFromWindow" =>
            {
                Self::GetAccessibleObjectFromWindow
            }
            ("oleacc.dll", ImportSymbol::ByName { name, .. }) if name == "GetOleaccVersionInfo" => {
                Self::GetOleaccVersionInfo
            }
            ("oleacc.dll", ImportSymbol::ByName { name, .. })
                if name == "WindowFromAccessibleObject" =>
            {
                Self::WindowFromAccessibleObject
            }
            ("dhcpcsvc.dll", ImportSymbol::ByName { name, .. }) if name == "DhcpCApiCleanup" => {
                Self::DhcpCApiCleanup
            }
            ("dhcpcsvc.dll", ImportSymbol::ByName { name, .. }) if name == "DhcpCApiInitialize" => {
                Self::DhcpCApiInitialize
            }
            ("dhcpcsvc.dll", ImportSymbol::ByName { name, .. }) if name == "DhcpReleaseParams" => {
                Self::DhcpReleaseParams
            }
            ("dhcpcsvc.dll", ImportSymbol::ByName { name, .. }) if name == "DhcpRenewParams" => {
                Self::DhcpRenewParams
            }
            ("dhcpcsvc.dll", ImportSymbol::ByName { name, .. }) if name == "DhcpRequestParams" => {
                Self::DhcpRequestParams
            }
            ("dnsapi.dll", ImportSymbol::ByName { name, .. })
                if name == "DnsFlushResolverCache" =>
            {
                Self::DnsFlushResolverCache
            }
            ("dnsapi.dll", ImportSymbol::ByName { name, .. }) if name == "DnsQueryConfig" => {
                Self::DnsQueryConfig
            }
            ("dnsapi.dll", ImportSymbol::ByName { name, .. }) if name == "DnsQuery_W" => {
                Self::DnsQueryW
            }
            ("dnsapi.dll", ImportSymbol::ByName { name, .. }) if name == "DnsRecordListFree" => {
                Self::DnsRecordListFree
            }
            ("newdev.dll", ImportSymbol::ByName { name, .. }) if name == "DiInstallDevice" => {
                Self::DiInstallDevice
            }
            ("newdev.dll", ImportSymbol::ByName { name, .. }) if name == "DiInstallDriverW" => {
                Self::DiInstallDriverW
            }
            ("newdev.dll", ImportSymbol::ByName { name, .. }) if name == "DiUninstallDevice" => {
                Self::DiUninstallDevice
            }
            ("newdev.dll", ImportSymbol::ByName { name, .. })
                if name == "UpdateDriverForPlugAndPlayDevicesW" =>
            {
                Self::UpdateDriverForPlugAndPlayDevicesW
            }
            ("wtsapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "WTSEnumerateSessionsW" =>
            {
                Self::WtsEnumerateSessionsW
            }
            ("wtsapi32.dll", ImportSymbol::ByName { name, .. }) if name == "WTSFreeMemory" => {
                Self::WtsFreeMemory
            }
            ("wtsapi32.dll", ImportSymbol::ByName { name, .. })
                if name == "WTSQuerySessionInformationW" =>
            {
                Self::WtsQuerySessionInformationW
            }
            ("wtsapi32.dll", ImportSymbol::ByName { name, .. }) if name == "WTSQueryUserToken" => {
                Self::WtsQueryUserToken
            }
            ("vssapi.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateVssBackupComponents" =>
            {
                Self::CreateVssBackupComponents
            }
            ("vssapi.dll", ImportSymbol::ByName { name, .. }) if name == "VssFreeComponent" => {
                Self::VssFreeComponent
            }
            ("vssapi.dll", ImportSymbol::ByName { name, .. })
                if name == "VssFreeSnapshotProperties" =>
            {
                Self::VssFreeSnapshotProperties
            }
            ("vssapi.dll", ImportSymbol::ByName { name, .. })
                if name == "VssFreeWriterMetadata" =>
            {
                Self::VssFreeWriterMetadata
            }
            ("comsvcs.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("comsvcs.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("comsvcs.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("comsvcs.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("riched20.dll", ImportSymbol::ByName { name, .. }) if name == "CreateTextServices" => {
                Self::CreateTextServices
            }
            ("riched20.dll", ImportSymbol::ByName { name, .. }) if name == "ITextDocument" => {
                Self::ITextDocument
            }
            ("riched20.dll", ImportSymbol::ByName { name, .. })
                if name == "RichEdit10ANSIWndClass" =>
            {
                Self::RichEdit10AnsiWndClass
            }
            ("riched20.dll", ImportSymbol::ByName { name, .. })
                if name == "ShutdownTextServices" =>
            {
                Self::ShutdownTextServices
            }
            ("dpnet.dll", ImportSymbol::ByName { name, .. }) if name == "DP8SPCreate" => {
                Self::Dp8spCreate
            }
            ("dpnet.dll", ImportSymbol::ByName { name, .. }) if name == "DirectPlay8Create" => {
                Self::DirectPlay8Create
            }
            ("dpnet.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("dpnet.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("dsound.dll", ImportSymbol::ByName { name, .. })
                if name == "DirectSoundCaptureCreate8" =>
            {
                Self::DirectSoundCaptureCreate8
            }
            ("dsound.dll", ImportSymbol::ByName { name, .. })
                if name == "DirectSoundCaptureEnumerateW" =>
            {
                Self::DirectSoundCaptureEnumerateW
            }
            ("dsound.dll", ImportSymbol::ByName { name, .. }) if name == "DirectSoundCreate8" => {
                Self::DirectSoundCreate8
            }
            ("dsound.dll", ImportSymbol::ByName { name, .. })
                if name == "DirectSoundEnumerateW" =>
            {
                Self::DirectSoundEnumerateW
            }
            ("msxml6.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("msxml6.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("msxml6.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("msxml6.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("rsaenh.dll", ImportSymbol::ByName { name, .. }) if name == "CPAcquireContext" => {
                Self::CpAcquireContext
            }
            ("rsaenh.dll", ImportSymbol::ByName { name, .. }) if name == "CPDecrypt" => {
                Self::CpDecrypt
            }
            ("rsaenh.dll", ImportSymbol::ByName { name, .. }) if name == "CPEncrypt" => {
                Self::CpEncrypt
            }
            ("rsaenh.dll", ImportSymbol::ByName { name, .. }) if name == "CPGenKey" => {
                Self::CpGenKey
            }
            ("rsaenh.dll", ImportSymbol::ByName { name, .. }) if name == "CPHashData" => {
                Self::CpHashData
            }
            ("rsaenh.dll", ImportSymbol::ByName { name, .. }) if name == "CPReleaseContext" => {
                Self::CpReleaseContext
            }
            ("rsaenh.dll", ImportSymbol::ByName { name, .. }) if name == "CPVerifySignature" => {
                Self::CpVerifySignature
            }
            ("cryptng.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptCloseAlgorithmProvider" =>
            {
                Self::BCryptCloseAlgorithmProvider
            }
            ("cryptng.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptDecrypt" => {
                Self::BCryptDecrypt
            }
            ("cryptng.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptEncrypt" => {
                Self::BCryptEncrypt
            }
            ("cryptng.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptGenRandom" => {
                Self::BCryptGenRandom
            }
            ("cryptng.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptGenerateSymmetricKey" =>
            {
                Self::BCryptGenerateSymmetricKey
            }
            ("cryptng.dll", ImportSymbol::ByName { name, .. }) if name == "BCryptHash" => {
                Self::BCryptHash
            }
            ("cryptng.dll", ImportSymbol::ByName { name, .. })
                if name == "BCryptOpenAlgorithmProvider" =>
            {
                Self::BCryptOpenAlgorithmProvider
            }
            ("dpapi.dll", ImportSymbol::ByName { name, .. }) if name == "CryptProtectData" => {
                Self::CryptProtectData
            }
            ("dpapi.dll", ImportSymbol::ByName { name, .. }) if name == "CryptProtectMemory" => {
                Self::CryptProtectMemory
            }
            ("dpapi.dll", ImportSymbol::ByName { name, .. }) if name == "CryptUnprotectData" => {
                Self::CryptUnprotectData
            }
            ("dpapi.dll", ImportSymbol::ByName { name, .. }) if name == "CryptUnprotectMemory" => {
                Self::CryptUnprotectMemory
            }
            ("wintrust.dll", ImportSymbol::ByName { name, .. }) if name == "WTGetSignatureInfo" => {
                Self::WtGetSignatureInfo
            }
            ("wintrust.dll", ImportSymbol::ByName { name, .. })
                if name == "WTHelperGetProvPrivateDataFromChain" =>
            {
                Self::WtHelperGetProvPrivateDataFromChain
            }
            ("wintrust.dll", ImportSymbol::ByName { name, .. })
                if name == "WTHelperGetProvSignerFromChain" =>
            {
                Self::WtHelperGetProvSignerFromChain
            }
            ("wintrust.dll", ImportSymbol::ByName { name, .. })
                if name == "WTHelperProvDataFromStateData" =>
            {
                Self::WtHelperProvDataFromStateData
            }
            ("cryptdll.dll", ImportSymbol::ByName { name, .. }) if name == "CryptDecodeObject" => {
                Self::CryptDecodeObject
            }
            ("cryptdll.dll", ImportSymbol::ByName { name, .. }) if name == "CryptEncodeObject" => {
                Self::CryptEncodeObject
            }
            ("cryptdll.dll", ImportSymbol::ByName { name, .. }) if name == "CryptExportPKCS8" => {
                Self::CryptExportPkcs8
            }
            ("sspicli.dll", ImportSymbol::ByName { name, .. }) if name == "FreeContextBuffer" => {
                Self::FreeContextBuffer
            }
            ("sspicli.dll", ImportSymbol::ByName { name, .. })
                if name == "QuerySecurityPackageInfoW" =>
            {
                Self::QuerySecurityPackageInfoW
            }
            ("sspicli.dll", ImportSymbol::ByName { name, .. }) if name == "SSPIInitialize" => {
                Self::SspiInitialize
            }
            ("schannel.dll", ImportSymbol::ByName { name, .. })
                if name == "InitSecurityInterfaceW" =>
            {
                Self::InitSecurityInterfaceW
            }
            ("schannel.dll", ImportSymbol::ByName { name, .. }) if name == "SslGetDataToWrite" => {
                Self::SslGetDataToWrite
            }
            ("schannel.dll", ImportSymbol::ByName { name, .. }) if name == "SslLoadCertificate" => {
                Self::SslLoadCertificate
            }
            ("cryptui.dll", ImportSymbol::ByName { name, .. }) if name == "CryptUIDlgCertMgr" => {
                Self::CryptUiDlgCertMgr
            }
            ("cryptui.dll", ImportSymbol::ByName { name, .. })
                if name == "CryptUIDlgSelectCertificateW" =>
            {
                Self::CryptUiDlgSelectCertificateW
            }
            ("cryptui.dll", ImportSymbol::ByName { name, .. })
                if name == "CryptUIDlgSelectStoreW" =>
            {
                Self::CryptUiDlgSelectStoreW
            }
            ("cryptui.dll", ImportSymbol::ByName { name, .. })
                if name == "CryptUIDlgViewCertificateW" =>
            {
                Self::CryptUiDlgViewCertificateW
            }
            ("wmcodecdsp.dll", ImportSymbol::ByName { name, .. })
                if name == "WMCDSPCreateAudioDecoder" =>
            {
                Self::WmcdspCreateAudioDecoder
            }
            ("wmcodecdsp.dll", ImportSymbol::ByName { name, .. })
                if name == "WMCDSPCreateAudioEncoder" =>
            {
                Self::WmcdspCreateAudioEncoder
            }
            ("wmcodecdsp.dll", ImportSymbol::ByName { name, .. })
                if name == "WMCDSPCreateConverter" =>
            {
                Self::WmcdspCreateConverter
            }
            ("wmcodecdsp.dll", ImportSymbol::ByName { name, .. })
                if name == "WMCDSPCreateDecoder" =>
            {
                Self::WmcdspCreateDecoder
            }
            ("wmcodecdsp.dll", ImportSymbol::ByName { name, .. })
                if name == "WMCDSPCreateEncoder" =>
            {
                Self::WmcdspCreateEncoder
            }
            ("wmcodecdsp.dll", ImportSymbol::ByName { name, .. })
                if name == "WMCDSPCreateProcessor" =>
            {
                Self::WmcdspCreateProcessor
            }
            ("wmcodecdsp.dll", ImportSymbol::ByName { name, .. })
                if name == "WMCDSPCreateResampler" =>
            {
                Self::WmcdspCreateResampler
            }
            ("wmvcore.dll", ImportSymbol::ByName { name, .. }) if name == "WMCreateEditor" => {
                Self::WmCreateEditor
            }
            ("wmvcore.dll", ImportSymbol::ByName { name, .. }) if name == "WMCreateIndexer" => {
                Self::WmCreateIndexer
            }
            ("wmvcore.dll", ImportSymbol::ByName { name, .. })
                if name == "WMCreateProfileManager" =>
            {
                Self::WmCreateProfileManager
            }
            ("wmvcore.dll", ImportSymbol::ByName { name, .. }) if name == "WMCreateReader" => {
                Self::WmCreateReader
            }
            ("wmvcore.dll", ImportSymbol::ByName { name, .. }) if name == "WMCreateSyncReader" => {
                Self::WmCreateSyncReader
            }
            ("wmvcore.dll", ImportSymbol::ByName { name, .. }) if name == "WMCreateWriter" => {
                Self::WmCreateWriter
            }
            ("wmvcore.dll", ImportSymbol::ByName { name, .. })
                if name == "WMIsContentProtected" =>
            {
                Self::WmIsContentProtected
            }
            ("audioses.dll", ImportSymbol::ByName { name, .. })
                if name == "AudioSessionFromGuid" =>
            {
                Self::AudioSessionFromGuid
            }
            ("audioses.dll", ImportSymbol::ByName { name, .. })
                if name == "AudioSessionFromHWND" =>
            {
                Self::AudioSessionFromHwnd
            }
            ("audioses.dll", ImportSymbol::ByName { name, .. })
                if name == "AudioSessionFromString" =>
            {
                Self::AudioSessionFromString
            }
            ("audioses.dll", ImportSymbol::ByName { name, .. }) if name == "AudioSessionize" => {
                Self::AudioSessionize
            }
            ("audioses.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("audioses.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("msdmo.dll", ImportSymbol::ByName { name, .. }) if name == "DMOEnum" => Self::DmoEnum,
            ("msdmo.dll", ImportSymbol::ByName { name, .. }) if name == "DMOGetName" => {
                Self::DmoGetName
            }
            ("msdmo.dll", ImportSymbol::ByName { name, .. }) if name == "DMOGetTypes" => {
                Self::DmoGetTypes
            }
            ("msdmo.dll", ImportSymbol::ByName { name, .. }) if name == "DMOGuidToStr" => {
                Self::DmoGuidToStr
            }
            ("msdmo.dll", ImportSymbol::ByName { name, .. }) if name == "DMOStrToGuid" => {
                Self::DmoStrToGuid
            }
            ("msdmo.dll", ImportSymbol::ByName { name, .. }) if name == "MOFree" => Self::MoFree,
            ("colorcnv.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("colorcnv.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("colorcnv.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("mfaacenc.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("mfaacenc.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("mfaacenc.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("mfh264enc.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("mfh264enc.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("mfh264enc.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("mfmpeg2src.dll", ImportSymbol::ByName { name, .. })
                if name == "DllGetClassObject" =>
            {
                Self::DllGetClassObject
            }
            ("mfmpeg2src.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("mfmpeg2src.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("mfvpxdec.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("mfvpxdec.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("mfvpxdec.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("mp3dmod.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("mp3dmod.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("mp3dmod.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("mpg4decdmod.dll", ImportSymbol::ByName { name, .. })
                if name == "DllGetClassObject" =>
            {
                Self::DllGetClassObject
            }
            ("mpg4decdmod.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("mpg4decdmod.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("msmpeg2adec.dll", ImportSymbol::ByName { name, .. })
                if name == "DllGetClassObject" =>
            {
                Self::DllGetClassObject
            }
            ("msmpeg2adec.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("msmpeg2adec.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("msmpeg2vdec.dll", ImportSymbol::ByName { name, .. })
                if name == "DllGetClassObject" =>
            {
                Self::DllGetClassObject
            }
            ("msmpeg2vdec.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("msmpeg2vdec.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("resampledmo.dll", ImportSymbol::ByName { name, .. })
                if name == "DllGetClassObject" =>
            {
                Self::DllGetClassObject
            }
            ("resampledmo.dll", ImportSymbol::ByName { name, .. })
                if name == "DllRegisterServer" =>
            {
                Self::DllRegisterServer
            }
            ("resampledmo.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("evr.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateVideoMediaType" => {
                Self::MfCreateVideoMediaType
            }
            ("evr.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateVideoMixer" => {
                Self::MfCreateVideoMixer
            }
            ("evr.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateVideoPresenter" => {
                Self::MfCreateVideoPresenter
            }
            ("evr.dll", ImportSymbol::ByName { name, .. }) if name == "MFCreateVideoRenderer" => {
                Self::MfCreateVideoRenderer
            }
            ("evr.dll", ImportSymbol::ByName { name, .. })
                if name == "MFCreateVideoSampleAllocator" =>
            {
                Self::MfCreateVideoSampleAllocator
            }
            ("amstream.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("amstream.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("amstream.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("amstream.dll", ImportSymbol::ByName { name, .. })
                if name == "DllUnregisterServer" =>
            {
                Self::DllUnregisterServer
            }
            ("qedit.dll", ImportSymbol::ByName { name, .. }) if name == "AMGetErrorText" => {
                Self::AmGetErrorText
            }
            ("qedit.dll", ImportSymbol::ByName { name, .. }) if name == "CreateErrorInfo" => {
                Self::CreateErrorInfo
            }
            ("qedit.dll", ImportSymbol::ByName { name, .. }) if name == "CreateFilter" => {
                Self::CreateFilter
            }
            ("dxva2.dll", ImportSymbol::ByName { name, .. })
                if name == "DXVA2CreateDirect3DDeviceManager9" =>
            {
                Self::Dxva2CreateDirect3DDeviceManager9
            }
            ("dxva2.dll", ImportSymbol::ByName { name, .. })
                if name == "DXVA2CreateVideoService" =>
            {
                Self::Dxva2CreateVideoService
            }
            ("dxva2.dll", ImportSymbol::ByName { name, .. })
                if name == "DXVA2GetVideoProcessorCaps" =>
            {
                Self::Dxva2GetVideoProcessorCaps
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTAcquireKeyedMutex" =>
            {
                Self::D3DKMTAcquireKeyedMutex
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTAcquireKeyedMutex2" =>
            {
                Self::D3DKMTAcquireKeyedMutex2
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTCloseAdapter" => {
                Self::D3DKMTCloseAdapter
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTReleaseKeyedMutex" =>
            {
                Self::D3DKMTReleaseKeyedMutex
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTReleaseKeyedMutex2" =>
            {
                Self::D3DKMTReleaseKeyedMutex2
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTCreateSwapChain" =>
            {
                Self::D3DKMTCreateSwapChain
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTDestroyAllocation" =>
            {
                Self::D3DKMTDestroyAllocation
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTDestroySwapchain" =>
            {
                Self::D3DKMTDestroySwapchain
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTEvict" => {
                Self::D3DKMTEvict
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTMakeResident" => {
                Self::D3DKMTMakeResident
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTOpenAdapterFromLuid" =>
            {
                Self::D3DKMTOpenAdapterFromLuid
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTOpenAdapterFromGdiDisplayName" =>
            {
                Self::D3DKMTOpenAdapterFromGdiDisplayName
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTOpenAdapterFromDeviceName" =>
            {
                Self::D3DKMTOpenAdapterFromDeviceName
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTOpenDevice" => {
                Self::D3DKMTOpenDevice
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTQueryStatistics" =>
            {
                Self::D3DKMTQueryStatistics
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTQuerySwapChainInfo" =>
            {
                Self::D3DKMTQuerySwapChainInfo
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTSignalSynchronizationObject" =>
            {
                Self::D3DKMTSignalSynchronizationObject
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTSignalSynchronizationObject2" =>
            {
                Self::D3DKMTSignalSynchronizationObject2
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTWaitForSynchronizationObject" =>
            {
                Self::D3DKMTWaitForSynchronizationObject
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTWaitForSynchronizationObject2" =>
            {
                Self::D3DKMTWaitForSynchronizationObject2
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTCreateAllocation" =>
            {
                Self::D3DKMTCreateAllocation
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTCreateContext" => {
                Self::D3DKMTCreateContext
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTCreateDevice" => {
                Self::D3DKMTCreateDevice
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTCreateSynchronizationObject" =>
            {
                Self::D3DKMTCreateSynchronizationObject
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTDestroyContext" =>
            {
                Self::D3DKMTDestroyContext
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTDestroySynchronizationObject" =>
            {
                Self::D3DKMTDestroySynchronizationObject
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTDestroyDevice" => {
                Self::D3DKMTDestroyDevice
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTEnumAdapters" => {
                Self::D3DKMTEnumAdapters
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTEnumOutputs" => {
                Self::D3DKMTEnumOutputs
            }
            ("d3d8thk.dll" | "gdi32.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTEscape" =>
            {
                Self::D3DKMTEscape
            }
            ("d3d8thk.dll" | "gdi32.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTMapGpuVirtualAddress" =>
            {
                Self::D3DKMTMapGpuVirtualAddress
            }
            ("d3d8thk.dll" | "gdi32.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTPagingFence" =>
            {
                Self::D3DKMTPagingFence
            }
            ("d3d8thk.dll" | "gdi32.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTQueryVideoMemoryInfo" =>
            {
                Self::D3DKMTQueryVideoMemoryInfo
            }
            ("d3d8thk.dll" | "gdi32.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTSubmitCommand" =>
            {
                Self::D3DKMTSubmitCommand
            }
            ("d3d8thk.dll" | "gdi32.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTUnmapGpuVirtualAddress" =>
            {
                Self::D3DKMTUnmapGpuVirtualAddress
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTGetDisplayModeList" =>
            {
                Self::D3DKMTGetDisplayModeList
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTGetDisplayModeList2" =>
            {
                Self::D3DKMTGetDisplayModeList2
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTGetGammaRamp" => {
                Self::D3DKMTGetGammaRamp
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTOpenAdapterFromHdc" =>
            {
                Self::D3DKMTOpenAdapterFromHdc
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTOpenKeyedMutex" =>
            {
                Self::D3DKMTOpenKeyedMutex
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTOpenKeyedMutex2" =>
            {
                Self::D3DKMTOpenKeyedMutex2
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTOpenResource" => {
                Self::D3DKMTOpenResource
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTOpenResource2" => {
                Self::D3DKMTOpenResource2
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTPnPStart" => {
                Self::D3DKMTPnPStart
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTPnPStop" => {
                Self::D3DKMTPnPStop
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTPowerComponent" =>
            {
                Self::D3DKMTPowerComponent
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTPresent" => {
                Self::D3DKMTPresent
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTQueryAdapterInfo" =>
            {
                Self::D3DKMTQueryAdapterInfo
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTQueryAllocationResidency" =>
            {
                Self::D3DKMTQueryAllocationResidency
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTRender" => {
                Self::D3DKMTRender
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTSetAllocationPriority" =>
            {
                Self::D3DKMTSetAllocationPriority
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTSetCursor" => {
                Self::D3DKMTSetCursor
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTSetCursorPosition" =>
            {
                Self::D3DKMTSetCursorPosition
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. })
                if name == "D3DKMTSetDisplayPrivateDriverFormat" =>
            {
                Self::D3DKMTSetDisplayPrivateDriverFormat
            }
            ("d3d8thk.dll", ImportSymbol::ByName { name, .. }) if name == "D3DKMTSetGammaRamp" => {
                Self::D3DKMTSetGammaRamp
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetAttachDatabase" => {
                Self::JetAttachDatabase
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetBeginTransaction" => {
                Self::JetBeginTransaction
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetCloseDatabase" => {
                Self::JetCloseDatabase
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetCloseTable" => {
                Self::JetCloseTable
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetCommitTransaction" => {
                Self::JetCommitTransaction
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetCreateDatabase" => {
                Self::JetCreateDatabase
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetDetachDatabase" => {
                Self::JetDetachDatabase
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetGetTableColumnInfo" => {
                Self::JetGetTableColumnInfo
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetInit" => Self::JetInit,
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetOpenDatabase" => {
                Self::JetOpenDatabase
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetOpenTable" => {
                Self::JetOpenTable
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetRollback" => {
                Self::JetRollback
            }
            ("esent.dll", ImportSymbol::ByName { name, .. }) if name == "JetTerm" => Self::JetTerm,
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPAccept" => {
                Self::WSPAccept
            }
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPBind" => Self::WSPBind,
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPCleanup" => {
                Self::WSPCleanup
            }
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPConnect" => {
                Self::WSPConnect
            }
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPListen" => {
                Self::WSPListen
            }
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPRecv" => Self::WSPRecv,
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPSend" => Self::WSPSend,
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPSocket" => {
                Self::WSPSocket
            }
            ("msafd.dll", ImportSymbol::ByName { name, .. }) if name == "WSPStartup" => {
                Self::WSPStartup
            }
            ("mswsock.dll", ImportSymbol::ByName { name, .. }) if name == "AcceptEx" => {
                Self::AcceptEx
            }
            ("mswsock.dll", ImportSymbol::ByName { name, .. }) if name == "EnumProtocolsW" => {
                Self::EnumProtocolsW
            }
            ("mswsock.dll", ImportSymbol::ByName { name, .. })
                if name == "GetAcceptExSockaddrs" =>
            {
                Self::GetAcceptExSockaddrs
            }
            ("mswsock.dll", ImportSymbol::ByName { name, .. }) if name == "TransmitFile" => {
                Self::TransmitFile
            }
            ("mswsock.dll", ImportSymbol::ByName { name, .. })
                if name == "WSAGetOverlappedResult" =>
            {
                Self::WSAGetOverlappedResult
            }
            ("mswsock.dll", ImportSymbol::ByName { name, .. }) if name == "WSARecvEx" => {
                Self::WSARecvEx
            }
            ("mswsock.dll", ImportSymbol::ByName { name, .. }) if name == "WSASocketW" => {
                Self::WSASocketW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "HttpAddRequestHeadersW" =>
            {
                Self::HttpAddRequestHeadersW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "HttpQueryInfoW" => {
                Self::HttpQueryInfoW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "InternetAttemptConnect" =>
            {
                Self::InternetAttemptConnect
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetOpenUrlW" => {
                Self::InternetOpenUrlW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. })
                if name == "InternetQueryOptionW" =>
            {
                Self::InternetQueryOptionW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetReadFileExW" => {
                Self::InternetReadFileExW
            }
            ("wininet.dll", ImportSymbol::ByName { name, .. }) if name == "InternetWriteFile" => {
                Self::InternetWriteFile
            }
            ("dinput.dll", ImportSymbol::ByName { name, .. }) if name == "DirectInputCreateEx" => {
                Self::DirectInputCreateEx
            }
            ("dinput.dll", ImportSymbol::ByName { name, .. }) if name == "DirectInputCreateW" => {
                Self::DirectInputCreateW
            }
            ("dinput.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("dinput.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("dinput.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("dinput.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_bind_s" => {
                Self::LdapBindS
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_count_entries" => {
                Self::LdapCountEntries
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_first_entry" => {
                Self::LdapFirstEntry
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_get_dn" => {
                Self::LdapGetDn
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_get_values" => {
                Self::LdapGetValues
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_init" => {
                Self::LdapInit
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_memfree" => {
                Self::LdapMemfree
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_msgfree" => {
                Self::LdapMsgfree
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_next_entry" => {
                Self::LdapNextEntry
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_result" => {
                Self::LdapResult
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_search" => {
                Self::LdapSearch
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_search_s" => {
                Self::LdapSearchS
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_unbind" => {
                Self::LdapUnbind
            }
            ("wldap32.dll", ImportSymbol::ByName { name, .. }) if name == "ldap_value_free_len" => {
                Self::LdapValueFreeLen
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. }) if name == "HttpAddUrl" => {
                Self::HttpAddUrl
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. })
                if name == "HttpCreateHttpHandle" =>
            {
                Self::HttpCreateHttpHandle
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. }) if name == "HttpInitialize" => {
                Self::HttpInitialize
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. })
                if name == "HttpReceiveHttpRequest" =>
            {
                Self::HttpReceiveHttpRequest
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. }) if name == "HttpRemoveUrl" => {
                Self::HttpRemoveUrl
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. })
                if name == "HttpSendHttpResponse" =>
            {
                Self::HttpSendHttpResponse
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. })
                if name == "HttpSendResponseEntityBody" =>
            {
                Self::HttpSendResponseEntityBody
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. }) if name == "HttpTerminate" => {
                Self::HttpTerminate
            }
            ("httpapi.dll", ImportSymbol::ByName { name, .. })
                if name == "HttpWaitForDisconnect" =>
            {
                Self::HttpWaitForDisconnect
            }
            ("pdh.dll", ImportSymbol::ByName { name, .. }) if name == "PdhAddCounter" => {
                Self::PdhAddCounter
            }
            ("pdh.dll", ImportSymbol::ByName { name, .. }) if name == "PdhCloseQuery" => {
                Self::PdhCloseQuery
            }
            ("pdh.dll", ImportSymbol::ByName { name, .. }) if name == "PdhCollectQueryData" => {
                Self::PdhCollectQueryData
            }
            ("pdh.dll", ImportSymbol::ByName { name, .. }) if name == "PdhEnumCounters" => {
                Self::PdhEnumCounters
            }
            ("pdh.dll", ImportSymbol::ByName { name, .. }) if name == "PdhEnumObjects" => {
                Self::PdhEnumObjects
            }
            ("pdh.dll", ImportSymbol::ByName { name, .. })
                if name == "PdhGetFormattedCounterValue" =>
            {
                Self::PdhGetFormattedCounterValue
            }
            ("pdh.dll", ImportSymbol::ByName { name, .. }) if name == "PdhOpenQuery" => {
                Self::PdhOpenQuery
            }
            ("pdh.dll", ImportSymbol::ByName { name, .. }) if name == "PdhRemoveCounter" => {
                Self::PdhRemoveCounter
            }
            ("wevtapi.dll", ImportSymbol::ByName { name, .. }) if name == "EvtClose" => {
                Self::EvtClose
            }
            ("wevtapi.dll", ImportSymbol::ByName { name, .. }) if name == "EvtCreateBookmark" => {
                Self::EvtCreateBookmark
            }
            ("wevtapi.dll", ImportSymbol::ByName { name, .. }) if name == "EvtNext" => {
                Self::EvtNext
            }
            ("wevtapi.dll", ImportSymbol::ByName { name, .. }) if name == "EvtOpenLog" => {
                Self::EvtOpenLog
            }
            ("wevtapi.dll", ImportSymbol::ByName { name, .. }) if name == "EvtOpenSession" => {
                Self::EvtOpenSession
            }
            ("wevtapi.dll", ImportSymbol::ByName { name, .. }) if name == "EvtQuery" => {
                Self::EvtQuery
            }
            ("wevtapi.dll", ImportSymbol::ByName { name, .. }) if name == "EvtRender" => {
                Self::EvtRender
            }
            ("wevtapi.dll", ImportSymbol::ByName { name, .. }) if name == "EvtSubscribe" => {
                Self::EvtSubscribe
            }
            ("wlanapi.dll", ImportSymbol::ByName { name, .. }) if name == "WlanCloseHandle" => {
                Self::WlanCloseHandle
            }
            ("wlanapi.dll", ImportSymbol::ByName { name, .. }) if name == "WlanConnect" => {
                Self::WlanConnect
            }
            ("wlanapi.dll", ImportSymbol::ByName { name, .. }) if name == "WlanDisconnect" => {
                Self::WlanDisconnect
            }
            ("wlanapi.dll", ImportSymbol::ByName { name, .. }) if name == "WlanEnumInterfaces" => {
                Self::WlanEnumInterfaces
            }
            ("wlanapi.dll", ImportSymbol::ByName { name, .. })
                if name == "WlanGetAvailableNetworkList" =>
            {
                Self::WlanGetAvailableNetworkList
            }
            ("wlanapi.dll", ImportSymbol::ByName { name, .. }) if name == "WlanOpenHandle" => {
                Self::WlanOpenHandle
            }
            ("wlanapi.dll", ImportSymbol::ByName { name, .. }) if name == "WlanQueryInterface" => {
                Self::WlanQueryInterface
            }
            ("wlanapi.dll", ImportSymbol::ByName { name, .. }) if name == "WlanScan" => {
                Self::WlanScan
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "GetOpenFileNameW" => {
                Self::GetOpenFileNameW
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "GetSaveFileNameW" => {
                Self::GetSaveFileNameW
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "PageSetupDlgW" => {
                Self::PageSetupDlgW
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "PrintDlgExW" => {
                Self::PrintDlgExW
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "PrintDlgW" => {
                Self::PrintDlgW
            }
            ("comdlg32.dll", ImportSymbol::ByName { name, .. }) if name == "ReplaceTextW" => {
                Self::ReplaceTextW
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateAppContainerProfile" =>
            {
                Self::CreateAppContainerProfile
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. })
                if name == "CreateEnvironmentBlock" =>
            {
                Self::CreateEnvironmentBlock
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. })
                if name == "DeleteAppContainerProfile" =>
            {
                Self::DeleteAppContainerProfile
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. })
                if name == "DestroyEnvironmentBlock" =>
            {
                Self::DestroyEnvironmentBlock
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. })
                if name == "GetAppContainerProfilePath" =>
            {
                Self::GetAppContainerProfilePath
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. }) if name == "GetProfileType" => {
                Self::GetProfileType
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. })
                if name == "GetProfilesDirectoryW" =>
            {
                Self::GetProfilesDirectoryW
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. }) if name == "LoadUserProfileW" => {
                Self::LoadUserProfileW
            }
            ("userenv.dll", ImportSymbol::ByName { name, .. }) if name == "UnloadUserProfile" => {
                Self::UnloadUserProfile
            }
            ("mpr.dll", ImportSymbol::ByName { name, .. }) if name == "WNetAddConnection2W" => {
                Self::WNetAddConnection2W
            }
            ("mpr.dll", ImportSymbol::ByName { name, .. }) if name == "WNetCancelConnection2W" => {
                Self::WNetCancelConnection2W
            }
            ("mpr.dll", ImportSymbol::ByName { name, .. }) if name == "WNetCloseEnum" => {
                Self::WNetCloseEnum
            }
            ("mpr.dll", ImportSymbol::ByName { name, .. }) if name == "WNetEnumResourceW" => {
                Self::WNetEnumResourceW
            }
            ("mpr.dll", ImportSymbol::ByName { name, .. }) if name == "WNetGetConnectionW" => {
                Self::WNetGetConnectionW
            }
            ("mpr.dll", ImportSymbol::ByName { name, .. }) if name == "WNetGetUserW" => {
                Self::WNetGetUserW
            }
            ("mpr.dll", ImportSymbol::ByName { name, .. }) if name == "WNetOpenEnumW" => {
                Self::WNetOpenEnumW
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "TF_CreateCategoryMgr" => {
                Self::TfCreateCategoryMgr
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. })
                if name == "TF_CreateDisplayAttributeMgr" =>
            {
                Self::TfCreateDisplayAttributeMgr
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "TF_CreateThreadMgr" => {
                Self::TfCreateThreadMgr
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "TF_GetThreadMgr" => {
                Self::TfGetThreadMgr
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "TF_InitSystem" => {
                Self::TfInitSystem
            }
            ("msctf.dll", ImportSymbol::ByName { name, .. }) if name == "TF_UninitSystem" => {
                Self::TfUninitSystem
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. }) if name == "BASIC_CLASS_AddRef" => {
                Self::BasicClassAddRef
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. })
                if name == "BASIC_CLASS_GetIDsOfNames" =>
            {
                Self::BasicClassGetIDsOfNames
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. }) if name == "BASIC_CLASS_Invoke" => {
                Self::BasicClassInvoke
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. })
                if name == "BASIC_CLASS_QueryInterface" =>
            {
                Self::BasicClassQueryInterface
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. })
                if name == "BASIC_CLASS_Release" =>
            {
                Self::BasicClassRelease
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. })
                if name == "BASIC_DISPINTERFACE_Invoke" =>
            {
                Self::BasicDispatchInvoke
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. }) if name == "DllCall" => {
                Self::DllCall
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. }) if name == "DllFunc" => {
                Self::DllFunc
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. }) if name == "DllMain" => {
                Self::DllMain
            }
            ("msvbvm60.dll", ImportSymbol::ByName { name, .. }) if name == "DllProc" => {
                Self::DllProc
            }
            ("mscoree.dll", ImportSymbol::ByName { name, .. }) if name == "CLRCreateInstance" => {
                Self::ClrCreateInstance
            }
            ("mscoree.dll", ImportSymbol::ByName { name, .. }) if name == "CorBindToRuntime" => {
                Self::CorBindToRuntime
            }
            ("mscoree.dll", ImportSymbol::ByName { name, .. }) if name == "CorBindToRuntimeEx" => {
                Self::CorBindToRuntimeEx
            }
            ("mscoree.dll", ImportSymbol::ByName { name, .. })
                if name == "GetCORSystemDirectory" =>
            {
                Self::GetCorSystemDirectory
            }
            ("mscoree.dll", ImportSymbol::ByName { name, .. })
                if name == "GetRequestedRuntimeInfo" =>
            {
                Self::GetRequestedRuntimeInfo
            }
            ("mscoree.dll", ImportSymbol::ByName { name, .. }) if name == "LoadLibraryShim" => {
                Self::LoadLibraryShim
            }
            ("quartz.dll", ImportSymbol::ByName { name, .. }) if name == "AMGetErrorTextW" => {
                Self::AmGetErrorTextW
            }
            ("quartz.dll", ImportSymbol::ByName { name, .. }) if name == "DllCanUnloadNow" => {
                Self::DllCanUnloadNow
            }
            ("quartz.dll", ImportSymbol::ByName { name, .. }) if name == "DllGetClassObject" => {
                Self::DllGetClassObject
            }
            ("quartz.dll", ImportSymbol::ByName { name, .. }) if name == "DllRegisterServer" => {
                Self::DllRegisterServer
            }
            ("quartz.dll", ImportSymbol::ByName { name, .. }) if name == "DllUnregisterServer" => {
                Self::DllUnregisterServer
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateBitmapClipper_Proxy" =>
            {
                Self::WicCreateBitmapClipperProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateBitmapFlipRotator_Proxy" =>
            {
                Self::WicCreateBitmapFlipRotatorProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateBitmapFromSection_Proxy" =>
            {
                Self::WicCreateBitmapFromSectionProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateBitmapScaler_Proxy" =>
            {
                Self::WicCreateBitmapScalerProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateBitmap_Proxy" =>
            {
                Self::WicCreateBitmapProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateColorContext_Proxy" =>
            {
                Self::WicCreateColorContextProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateComponentInfo" =>
            {
                Self::WicCreateComponentInfo
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateFormatConverter_Proxy" =>
            {
                Self::WicCreateFormatConverterProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateImagingFactory" =>
            {
                Self::WicCreateImagingFactory
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateImagingFactory_Proxy" =>
            {
                Self::WicCreateImagingFactoryProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreatePalette_Proxy" =>
            {
                Self::WicCreatePaletteProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICCreateStream_Proxy" =>
            {
                Self::WicCreateStreamProxy
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICGetMetadataContentSize" =>
            {
                Self::WicGetMetadataContentSize
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICMapSchemaToName" =>
            {
                Self::WicMapSchemaToName
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICMatchMetadataContent" =>
            {
                Self::WicMatchMetadataContent
            }
            ("windowscodecs.dll", ImportSymbol::ByName { name, .. })
                if name == "WICSerializeMetadataContent" =>
            {
                Self::WicSerializeMetadataContent
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glBegin" => {
                Self::GlBegin
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glBegin" => Self::GlBegin,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glBindTexture" => {
                Self::GlBindTexture
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glBindTexture" => {
                Self::GlBindTexture
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glBlendFunc" => {
                Self::GlBlendFunc
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glBlendFunc" => {
                Self::GlBlendFunc
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glClear" => {
                Self::GlClear
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glClear" => Self::GlClear,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glClearColor" => {
                Self::GlClearColor
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glClearColor" => {
                Self::GlClearColor
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glColor3f" => {
                Self::GlColor3f
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glColor3f" => {
                Self::GlColor3f
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glColor4f" => {
                Self::GlColor4f
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glColor4f" => {
                Self::GlColor4f
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glColorPointer" => {
                Self::GlColorPointer
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glColorPointer" => {
                Self::GlColorPointer
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glCullFace" => {
                Self::GlCullFace
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glCullFace" => {
                Self::GlCullFace
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glDeleteTextures" => {
                Self::GlDeleteTextures
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glDeleteTextures" => {
                Self::GlDeleteTextures
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glDepthFunc" => {
                Self::GlDepthFunc
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glDepthFunc" => {
                Self::GlDepthFunc
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glDisable" => {
                Self::GlDisable
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glDisable" => {
                Self::GlDisable
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. })
                if name == "glDisableClientState" =>
            {
                Self::GlDisableClientState
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glDisableClientState" => {
                Self::GlDisableClientState
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glDrawArrays" => {
                Self::GlDrawArrays
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glDrawArrays" => {
                Self::GlDrawArrays
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glDrawElements" => {
                Self::GlDrawElements
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glDrawElements" => {
                Self::GlDrawElements
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glEnable" => {
                Self::GlEnable
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glEnable" => {
                Self::GlEnable
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. })
                if name == "glEnableClientState" =>
            {
                Self::GlEnableClientState
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glEnableClientState" => {
                Self::GlEnableClientState
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glEnd" => Self::GlEnd,
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glEnd" => Self::GlEnd,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glFinish" => {
                Self::GlFinish
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glFinish" => {
                Self::GlFinish
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glFlush" => {
                Self::GlFlush
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glFlush" => Self::GlFlush,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glFogf" => Self::GlFogf,
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glFogf" => Self::GlFogf,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glFogi" => Self::GlFogi,
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glFogi" => Self::GlFogi,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glFrontFace" => {
                Self::GlFrontFace
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glFrontFace" => {
                Self::GlFrontFace
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glGenTextures" => {
                Self::GlGenTextures
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glGenTextures" => {
                Self::GlGenTextures
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glGetError" => {
                Self::GlGetError
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glGetError" => {
                Self::GlGetError
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glGetString" => {
                Self::GlGetString
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glGetString" => {
                Self::GlGetString
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glHint" => Self::GlHint,
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glHint" => Self::GlHint,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glLightfv" => {
                Self::GlLightfv
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glLightfv" => {
                Self::GlLightfv
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glLoadIdentity" => {
                Self::GlLoadIdentity
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glLoadIdentity" => {
                Self::GlLoadIdentity
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glMaterialfv" => {
                Self::GlMaterialfv
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glMaterialfv" => {
                Self::GlMaterialfv
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glMatrixMode" => {
                Self::GlMatrixMode
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glMatrixMode" => {
                Self::GlMatrixMode
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glNormalPointer" => {
                Self::GlNormalPointer
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glNormalPointer" => {
                Self::GlNormalPointer
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glOrtho" => {
                Self::GlOrtho
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glOrtho" => Self::GlOrtho,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glPopMatrix" => {
                Self::GlPopMatrix
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glPopMatrix" => {
                Self::GlPopMatrix
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glPushMatrix" => {
                Self::GlPushMatrix
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glPushMatrix" => {
                Self::GlPushMatrix
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glReadPixels" => {
                Self::GlReadPixels
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glReadPixels" => {
                Self::GlReadPixels
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glRotatef" => {
                Self::GlRotatef
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glRotatef" => {
                Self::GlRotatef
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glScalef" => {
                Self::GlScalef
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glScalef" => {
                Self::GlScalef
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glShadeModel" => {
                Self::GlShadeModel
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glShadeModel" => {
                Self::GlShadeModel
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexCoord2f" => {
                Self::GlTexCoord2f
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexCoord2f" => {
                Self::GlTexCoord2f
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexCoordPointer" => {
                Self::GlTexCoordPointer
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexCoordPointer" => {
                Self::GlTexCoordPointer
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexImage2D" => {
                Self::GlTexImage2D
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexImage2D" => {
                Self::GlTexImage2D
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexParameterf" => {
                Self::GlTexParameterf
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexParameterf" => {
                Self::GlTexParameterf
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexParameteri" => {
                Self::GlTexParameteri
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glTexParameteri" => {
                Self::GlTexParameteri
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glTranslatef" => {
                Self::GlTranslatef
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glTranslatef" => {
                Self::GlTranslatef
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glVertex2f" => {
                Self::GlVertex2f
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glVertex2f" => {
                Self::GlVertex2f
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glVertex3f" => {
                Self::GlVertex3f
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glVertex3f" => {
                Self::GlVertex3f
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glVertexPointer" => {
                Self::GlVertexPointer
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glVertexPointer" => {
                Self::GlVertexPointer
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "glViewport" => {
                Self::GlViewport
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "glViewport" => {
                Self::GlViewport
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluBuild2DMipmaps" => {
                Self::GluBuild2DMipmaps
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluBuild2DMipmaps" => {
                Self::GluBuild2DMipmaps
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluCylinder" => {
                Self::GluCylinder
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluCylinder" => {
                Self::GluCylinder
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluDeleteQuadric" => {
                Self::GluDeleteQuadric
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluDeleteQuadric" => {
                Self::GluDeleteQuadric
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluDisk" => {
                Self::GluDisk
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluDisk" => Self::GluDisk,
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluErrorString" => {
                Self::GluErrorString
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluErrorString" => {
                Self::GluErrorString
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluLookAt" => {
                Self::GluLookAt
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluLookAt" => {
                Self::GluLookAt
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluLookAt" => {
                Self::GluLookAt
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluLookAt" => {
                Self::GluLookAt
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluNewQuadric" => {
                Self::GluNewQuadric
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluNewQuadric" => {
                Self::GluNewQuadric
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluNewTess" => {
                Self::GluNewTess
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluNewTess" => {
                Self::GluNewTess
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluOrtho2D" => {
                Self::GluOrtho2D
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluOrtho2D" => {
                Self::GluOrtho2D
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluPartialDisk" => {
                Self::GluPartialDisk
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluPartialDisk" => {
                Self::GluPartialDisk
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluPerspective" => {
                Self::GluPerspective
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluPerspective" => {
                Self::GluPerspective
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluPerspective" => {
                Self::GluPerspective
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluPerspective" => {
                Self::GluPerspective
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluPickMatrix" => {
                Self::GluPickMatrix
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluPickMatrix" => {
                Self::GluPickMatrix
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluProject" => {
                Self::GluProject
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluProject" => {
                Self::GluProject
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluScaleImage" => {
                Self::GluScaleImage
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluScaleImage" => {
                Self::GluScaleImage
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluSphere" => {
                Self::GluSphere
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluSphere" => {
                Self::GluSphere
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. })
                if name == "gluTessBeginPolygon" =>
            {
                Self::GluTessBeginPolygon
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluTessBeginPolygon" => {
                Self::GluTessBeginPolygon
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluTessEndPolygon" => {
                Self::GluTessEndPolygon
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluTessEndPolygon" => {
                Self::GluTessEndPolygon
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluTessVertex" => {
                Self::GluTessVertex
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluTessVertex" => {
                Self::GluTessVertex
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "gluUnProject" => {
                Self::GluUnProject
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "gluUnProject" => {
                Self::GluUnProject
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. })
                if name == "wglChoosePixelFormat" =>
            {
                Self::WglChoosePixelFormat
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "wglChoosePixelFormat" => {
                Self::WglChoosePixelFormat
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "wglCreateContext" => {
                Self::WglCreateContext
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "wglCreateContext" => {
                Self::WglCreateContext
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "wglDeleteContext" => {
                Self::WglDeleteContext
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "wglDeleteContext" => {
                Self::WglDeleteContext
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. })
                if name == "wglDescribePixelFormat" =>
            {
                Self::WglDescribePixelFormat
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. })
                if name == "wglDescribePixelFormat" =>
            {
                Self::WglDescribePixelFormat
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "wglGetPixelFormat" => {
                Self::WglGetPixelFormat
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "wglGetPixelFormat" => {
                Self::WglGetPixelFormat
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "wglGetProcAddress" => {
                Self::WglGetProcAddress
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "wglGetProcAddress" => {
                Self::WglGetProcAddress
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "wglMakeCurrent" => {
                Self::WglMakeCurrent
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "wglMakeCurrent" => {
                Self::WglMakeCurrent
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "wglSetPixelFormat" => {
                Self::WglSetPixelFormat
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "wglSetPixelFormat" => {
                Self::WglSetPixelFormat
            }
            ("opengl32.dll", ImportSymbol::ByName { name, .. }) if name == "wglSwapBuffers" => {
                Self::WglSwapBuffers
            }
            ("glu32.dll", ImportSymbol::ByName { name, .. }) if name == "wglSwapBuffers" => {
                Self::WglSwapBuffers
            }
            (_, ImportSymbol::ByName { name, .. }) => Self::Unsupported {
                dll: import.resolved_module.clone(),
                symbol: name.clone(),
            },
            ("wsock32.dll", ImportSymbol::ByOrdinal { ordinal: 1142 }) => {
                // Non-standard wsock32 ordinal — maps to WSAStartup (likely early Winsock init call)
                Self::WsaStartup
            }
            // -- XInput ordinal resolution (Phase 5.2.1) --
            ("xinput1_3.dll", ImportSymbol::ByOrdinal { ordinal: 100, .. }) => Self::XInputGetState,
            ("xinput1_3.dll", ImportSymbol::ByOrdinal { ordinal: 101, .. }) => Self::XInputSetState,
            ("xinput1_3.dll", ImportSymbol::ByOrdinal { ordinal: 102, .. }) => {
                Self::XInputGetCapabilities
            }
            ("xinput1_3.dll", ImportSymbol::ByOrdinal { ordinal: 103, .. }) => {
                Self::XInputGetDSoundAudioDeviceGuids
            }
            ("xinput1_3.dll", ImportSymbol::ByOrdinal { ordinal: 105, .. }) => {
                Self::XInputGetBatteryInformation
            }
            ("xinput1_3.dll", ImportSymbol::ByOrdinal { ordinal: 108, .. }) => {
                Self::XInputGetKeystroke
            }
            ("xinput1_3.dll", ImportSymbol::ByOrdinal { ordinal: 109, .. }) => Self::XInputEnable,
            ("xinput1_4.dll", ImportSymbol::ByOrdinal { ordinal: 100, .. }) => Self::XInputGetState,
            ("xinput1_4.dll", ImportSymbol::ByOrdinal { ordinal: 101, .. }) => Self::XInputSetState,
            ("xinput1_4.dll", ImportSymbol::ByOrdinal { ordinal: 102, .. }) => {
                Self::XInputGetCapabilities
            }
            ("xinput1_4.dll", ImportSymbol::ByOrdinal { ordinal: 103, .. }) => {
                Self::XInputGetDSoundAudioDeviceGuids
            }
            ("xinput1_4.dll", ImportSymbol::ByOrdinal { ordinal: 105, .. }) => {
                Self::XInputGetBatteryInformation
            }
            ("xinput1_4.dll", ImportSymbol::ByOrdinal { ordinal: 108, .. }) => {
                Self::XInputGetKeystroke
            }
            ("xinput1_4.dll", ImportSymbol::ByOrdinal { ordinal: 109, .. }) => Self::XInputEnable,
            (_, ImportSymbol::ByOrdinal { ordinal }) => Self::Unsupported {
                dll: import.resolved_module.clone(),
                symbol: format!("ordinal#{ordinal}"),
            },
        }
    }

    pub(crate) fn x86_arg_bytes(&self) -> u64 {
        match self {
            Self::GetVersion
            | Self::GetLastError
            | Self::GetCurrentThread
            | Self::GetCurrentThreadId
            | Self::GetCurrentProcessId
            | Self::GetCurrentProcess
            | Self::GetProcessHeap
            | Self::GetTickCount
            | Self::GetTickCount64
            | Self::OleUninitialize
            | Self::GetCommandLineA
            | Self::GetCommandLineW
            | Self::GetEnvironmentStringsW
            | Self::IsUserAnAdmin
            | Self::GetACP
            | Self::GetOEMCP
            | Self::GetMessagePos
            | Self::CreatePopupMenu
            | Self::SetUserMathErr
            | Self::AreFileApisANSI
            | Self::TlsAlloc
            | Self::WsaCleanup
            | Self::WsaGetLastError
            | Self::IsDebuggerPresent
            | Self::InitCommonControls
            | Self::ImageList_EndDrag
            | Self::ImageList_GetDragImage
            | Self::CoUninitialize
            | Self::SetProcessDPIAware
            | Self::GetThreadDpiAwarenessContext
            | Self::SwitchToThread
            | Self::DebugBreak
            | Self::GetConsoleCP
            | Self::ConvertFiberToThread
            | Self::GetDesktopWindow
            | Self::EmptyClipboard
            | Self::GetProcessWindowStation
            | Self::GetFocus
            | Self::GdiFlush
            | Self::SteamVR_Shutdown
            | Self::SteamVR_IsHmdPresent
            | Self::SteamVR_IsRuntimeInstalled
            | Self::SteamVR_RuntimePath
            | Self::SteamAPI_Init
            | Self::SteamAPI_Shutdown
            | Self::SteamAPI_RunCallbacks
            | Self::SteamAPI_GetSteamInstallPath
            | Self::WaveOutGetNumDevs
            | Self::WaveInGetNumDevs
            | Self::MidiOutGetNumDevs
            | Self::TimeGetTime
            | Self::DwmFlush
            | Self::CreateMenu
            | Self::NtTestAlert
            | Self::DelayLoadResolve { .. } => 0,
            Self::QueryPerformanceCounter
            | Self::QueryPerformanceFrequency
            | Self::IsProcessorFeaturePresent
            | Self::SetLastError
            | Self::GetStartupInfoW
            | Self::InitializeSListHead
            | Self::GetStdHandle
            | Self::GetFileType
            | Self::EncodePointer
            | Self::DecodePointer
            | Self::FreeEnvironmentStringsW
            | Self::IsValidCodePage
            | Self::Closesocket
            | Self::WsaSetLastError
            | Self::Htonl
            | Self::Htons
            | Self::Ntohl
            | Self::Ntohs
            | Self::GetStockObject
            | Self::CreateSolidBrush
            | Self::InitializeSRWLock
            | Self::AcquireSRWLockExclusive
            | Self::ReleaseSRWLockExclusive
            | Self::AcquireSRWLockShared
            | Self::ReleaseSRWLockShared
            | Self::TryAcquireSRWLockExclusive
            | Self::TryAcquireSRWLockShared
            | Self::SetEvent
            | Self::ResetEvent
            | Self::FlsAlloc
            | Self::GetSystemTimeAsFileTime
            | Self::GetSystemTimePreciseAsFileTime
            | Self::GetTimeZoneInformation
            | Self::FindClose
            | Self::ShellLinkAddRef
            | Self::ShellLinkRelease
            | Self::ShellLinkPersistIsDirty
            | Self::SetCurrentDirectoryW
            | Self::GetFileAttributesW
            | Self::SetErrorMode
            | Self::SetDefaultDllDirectories
            | Self::FreeLibrary
            | Self::RegisterClassW
            | Self::RegisterClassExW
            | Self::IsWindowEnabled
            | Self::GetModuleHandleA
            | Self::GetModuleHandleW
            | Self::CloseHandle
            | Self::DeleteCriticalSection
            | Self::EnterCriticalSection
            | Self::TryEnterCriticalSection
            | Self::InitializeCriticalSection
            | Self::LeaveCriticalSection
            | Self::WakeAllConditionVariable
            | Self::UnhandledExceptionFilter
            | Self::SetUnhandledExceptionFilter
            | Self::RemoveVectoredExceptionHandler
            | Self::Sleep
            | Self::ExitProcess
            | Self::OleInitialize
            | Self::CoTaskMemFree
            | Self::VariantClear
            | Self::LstrlenW
            | Self::CharNextW
            | Self::CharUpperW
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
            | Self::OutputDebugStringA
            | Self::OutputDebugStringW
            | Self::LoadLibraryA
            | Self::LoadLibraryW
            | Self::InitCommonControlsEx
            | Self::ImageList_Destroy
            | Self::ImageList_GetImageCount
            | Self::ImageList_GetBkColor
            | Self::ImageList_DragShowNolock
            | Self::ImageList_DragLeave
            | Self::TlsGetValue
            | Self::TlsFree
            | Self::FlsGetValue
            | Self::FlsFree
            | Self::RtlNtStatusToDosError
            | Self::MessageBoxIndirectW
            | Self::GetTextColor
            | Self::GetBkColor
            | Self::GetBkMode
            | Self::DestroyWindow
            | Self::TranslateMessage
            | Self::DispatchMessageW
            | Self::LocalLock
            | Self::LocalUnlock
            | Self::LocalFree
            | Self::GlobalLock
            | Self::GlobalUnlock
            | Self::GlobalFree
            | Self::RegCloseKey
            | Self::FlushFileBuffers
            | Self::DisconnectNamedPipe
            | Self::UnmapViewOfFile
            | Self::GetNativeSystemInfo
            | Self::GetSystemInfo
            | Self::GetVersionExW
            | Self::ShellExecuteExW
            | Self::GetDpiForWindow
            | Self::SetProcessDPIAwareness
            | Self::SetThreadDpiAwarenessContext
            | Self::EnableNonClientDpiScaling
            | Self::BringWindowToTop
            | Self::GetTopWindow
            | Self::GetWindowTextLengthW
            | Self::GetParent
            | Self::SetEndOfFile
            | Self::RemoveDirectoryA
            | Self::GetFileAttributesA
            | Self::GetDriveTypeW
            | Self::GlobalMemoryStatusEx
            | Self::SuspendThread
            | Self::ResumeThread
            | Self::LockResource
            | Self::GetSystemTime
            | Self::ConvertThreadToFiber
            | Self::DeleteFiber
            | Self::SwitchToFiber
            | Self::CreateActCtxW
            | Self::ReleaseActCtx
            | Self::UpdateWindow
            | Self::OpenClipboard
            | Self::CloseClipboard
            | Self::GetClipboardData
            | Self::IsClipboardFormatAvailable
            | Self::EnumClipboardFormats
            | Self::GetWindowTextLengthA
            | Self::AllowSetForegroundWindow
            | Self::RemoveFontMemResourceEx
            | Self::DeleteDC
            | Self::CreateCompatibleDC
            | Self::SwapBuffers
            | Self::DeregisterEventSource
            | Self::BCryptDestroyHash
            | Self::BCryptDestroyKey
            | Self::CertFreeCertificateContext
            | Self::CertFreeCertificateChain
            | Self::CertDuplicateCertificateContext
            | Self::CertDeleteCertificateFromStore
            | Self::PFXIsPFXBlob
            | Self::IsProtectedProcess
            | Self::IsProtectedProcessLight
            | Self::XAudio2SourceVoiceDiscontinuity
            | Self::XAudio2SourceVoiceExitLoop
            | Self::XAudio2CommitChanges
            | Self::XAudio2RegisterForCallbacks
            | Self::XAudio2UnregisterForCallbacks
            | Self::XAudio2GetPerformanceData
            | Self::XAudio2SetDebugConfiguration
            | Self::XAPO_UnlockForProcess
            | Self::DirectInputDevice8Acquire
            | Self::DirectInputDevice8Unacquire
            | Self::DirectInputDevice8Poll
            | Self::DirectInputDevice8UnacquireObj
            | Self::UnregisterTouchWindow
            | Self::CloseTouchInputHandle
            | Self::InitializePointerDevice
            | Self::SkipPointerFrame
            | Self::XInputEnable
            | Self::SteamAPI_ISteamInput_Init
            | Self::SteamAPI_ISteamInput_Shutdown
            | Self::SteamVR_GetStringForHmdError
            | Self::SteamVR_IVRCompositor_GetFrameTimeRemaining
            | Self::SteamVR_IVRCompositor_CanRenderScene
            | Self::SteamVR_IVRChaperone_GetCalibrationState
            | Self::SteamAPI_ISteamNetworkingSockets_CreateListenSocket
            | Self::SteamAPI_RestartAppIfNecessary
            | Self::SteamAPI_UnregisterCallback
            | Self::SteamAPI_SetMiniDumpComment
            | Self::SteamInternal_CreateInterface
            | Self::SteamInternal_ContextInit
            | Self::SteamAPI_ISteamUserStats_RequestCurrentStats
            | Self::SteamAPI_ISteamUserStats_GetNumAchievements
            | Self::SteamAPI_ISteamFriends_GetPersonaName
            | Self::SteamAPI_ISteamFriends_GetPersonaState
            | Self::SteamAPI_ISteamFriends_GetInviteCount
            | Self::SteamAPI_ISteamFriends_GetClanCount
            | Self::SteamAPI_ISteamFriends_ClearRichPresence
            | Self::SteamAPI_ISteamFriends_ActivateGameOverlayToFriends
            | Self::SteamAPI_ISteamMatchmaking_RequestLobbyList
            | Self::SteamAPI_ISteamMatchmaking_GetLobbyCount
            | Self::SteamAPI_ISteamRemoteStorage_GetFileCount
            | Self::SteamAPI_ISteamRemoteStorage_GetQuotaUsed
            | Self::SteamAPI_ISteamRemoteStorage_GetQuotaTotal
            | Self::SteamAPI_ISteamRemoteStorage_IsCloudEnabledForAccount
            | Self::SteamAPI_ISteamRemoteStorage_IsCloudEnabledForApp
            | Self::SteamAPI_ISteamScreenshots_TriggerScreenshot
            | Self::SteamAPI_ISteamScreenshots_IsScreenshotsHooked
            | Self::SteamAPI_ISteamScreenshots_GetScreenshotCount
            | Self::SteamAPI_ISteamMusic_IsEnabled
            | Self::SteamAPI_ISteamMusic_IsPlaying
            | Self::SteamAPI_ISteamMusic_Play
            | Self::SteamAPI_ISteamMusic_Pause
            | Self::SteamAPI_ISteamMusic_PlayNext
            | Self::SteamAPI_ISteamMusic_PlayPrevious
            | Self::SteamAPI_ISteamMusic_GetVolume
            | Self::SteamVR_IVRRenderModels_GetRenderModelCount
            | Self::ReleaseMutex
            | Self::PulseEvent
            | Self::InitializeConditionVariable
            | Self::WakeConditionVariable
            | Self::GetThreadPriority
            | Self::SubmitThreadpoolWork
            | Self::CloseThreadpoolWork
            | Self::CloseThreadpoolTimer
            | Self::CloseThreadpoolWait
            | Self::CoRevokeClassObject
            | Self::CoCreateGuid
            | Self::SysAllocString
            | Self::SysFreeString
            | Self::SysStringLen
            | Self::VariantInit
            | Self::SafeArrayDestroy
            | Self::SafeArrayUnaccessData
            | Self::ScriptStringFree
            | Self::ScriptString_pSize
            | Self::ScriptFreeCache
            | Self::GdiplusShutdown
            | Self::GdipDeleteGraphics
            | Self::GdipDeleteBrush
            | Self::GdipDeletePen
            | Self::GdipDeletePath
            | Self::GdipClosePathFigure
            | Self::GdipStartPathFigure
            | Self::GdipCreateMatrix
            | Self::GdipDeleteMatrix
            | Self::GdipInvertMatrix
            | Self::GdipResetWorldTransform
            | Self::GdipResetClip
            | Self::GdipDisposeImage
            | Self::GdipDeleteFont
            | Self::GdipDeleteFontFamily
            | Self::GdipCreateImageAttributes
            | Self::GdipDisposeImageAttributes
            | Self::GdipImageForceValidation
            | Self::WaveOutClose
            | Self::WaveOutReset
            | Self::WaveInClose
            | Self::WaveInStart
            | Self::WaveInStop
            | Self::MidiOutClose
            | Self::MidiOutReset
            | Self::MidiInClose
            | Self::MidiInStart
            | Self::MidiInStop
            | Self::MidiInReset
            | Self::TimeBeginPeriod
            | Self::TimeEndPeriod
            | Self::DwmIsCompositionEnabled
            | Self::DwmEnableComposition
            | Self::DwmUnregisterThumbnail
            | Self::WinHttpGetIEProxyConfigForCurrentUser
            | Self::DestroyMenu
            | Self::GetMenu
            | Self::GetMenuItemCount
            | Self::DrawMenuBar
            | Self::LoadMenuIndirectW
            | Self::SHGetDesktopFolder
            | Self::SHBrowseForFolderW
            | Self::ILCreateFromPathW
            | Self::ILFree
            | Self::SHSimpleIDListFromPath
            | Self::Freeaddrinfo
            | Self::DragFinish
            | Self::SetFocus
            | Self::GdiComment
            | Self::SetupDiDestroyDeviceInfoList
            | Self::ExitThread => 4,
            Self::SetEnvironmentVariableW
            | Self::GetCPInfo
            | Self::SystemFunction036
            | Self::LocaleNameToLCID
            | Self::SetFileCompletionNotificationModes
            | Self::WsaStartup
            | Self::Shutdown
            | Self::WsaFdIsSet
            | Self::InternetGetConnectedState
            | Self::GetProcessHeaps
            | Self::GetCurrentPackageId
            | Self::InitializeCriticalSectionAndSpinCount
            | Self::SetFileAttributesW
            | Self::FindFirstFileW
            | Self::FindNextFileW
            | Self::GetCurrentDirectoryW
            | Self::GetWindowLongW
            | Self::AddVectoredExceptionHandler
            | Self::ImageList_Remove
            | Self::ImageList_SetImageCount
            | Self::ImageList_DragMove
            | Self::ImageList_SetBkColor
            | Self::MonitorFromWindow
            | Self::GetMonitorInfoW
            | Self::MonitorFromRect
            | Self::ProcessIdToSessionId
            | Self::TlsSetValue
            | Self::FlsSetValue
            | Self::CSpecificHandler
            | Self::Beep
            | Self::GetProcAddress
            | Self::GetFileSize
            | Self::GetFileInformationByHandle
            | Self::LocalAlloc
            | Self::GlobalAlloc
            | Self::LstrcmpiW
            | Self::LstrcmpW
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
            | Self::LoadIconW
            | Self::LoadCursorW
            | Self::LoadBitmapW
            | Self::GetDeviceCaps
            | Self::SelectObject
            | Self::SetBkMode
            | Self::SetTextColor
            | Self::SetBkColor
            | Self::SetMapMode
            | Self::GetTextMetricsW
            | Self::CopyRect
            | Self::CreateDirectoryW
            | Self::WaitForSingleObject
            | Self::ExitWindowsEx
            | Self::GetExitCodeThread
            | Self::GetExitCodeProcess
            | Self::TerminateProcess
            | Self::GetSystemDirectoryW
            | Self::GetWindowsDirectoryW
            | Self::GetTempPathW
            | Self::GetTempPath2W
            | Self::ShowWindow
            | Self::GetDlgItem
            | Self::BeginPaint
            | Self::EndPaint
            | Self::SetWindowTextW
            | Self::InitializeSecurityDescriptor
            | Self::ShellLinkGetIDList
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
            | Self::ShellLinkPersistSaveCompleted
            | Self::ShellLinkSetPathW
            | Self::CommandLineToArgvW
            | Self::SHGetPathFromIDListW
            | Self::RegDeleteKeyW
            | Self::RegDeleteValueW
            | Self::GetUserNameW
            | Self::GetComputerNameW
            | Self::GetFileVersionInfoSizeW
            | Self::ConnectNamedPipe
            | Self::WaitNamedPipeW
            | Self::CoInitializeEx
            | Self::IsWow64Process
            | Self::SetWindowCompositionAttribute
            | Self::GetWindowPlacement
            | Self::SetWindowPlacement
            | Self::ShellNotifyIconW
            | Self::GetNextWindow
            | Self::GetWindow
            | Self::GetUpdateRect
            | Self::ValidateRect
            | Self::GetWindowLongPtrW
            | Self::SetParent
            | Self::GetFileSizeEx
            | Self::SleepEx
            | Self::GetCurrentDirectoryA
            | Self::HeapWalk
            | Self::IsBadWritePtr
            | Self::SetThreadPriority
            | Self::TerminateThread
            | Self::SetThreadAffinityMask
            | Self::RtlRestoreContext
            | Self::GetConsoleMode
            | Self::SetConsoleMode
            | Self::SetStdHandle
            | Self::SetProcessAffinityMask
            | Self::InterlockedPushEntrySList
            | Self::SizeofResource
            | Self::LoadResource
            | Self::SystemTimeToFileTime
            | Self::FileTimeToSystemTime
            | Self::SetConsoleCtrlHandler
            | Self::ActivateActCtx
            | Self::DeactivateActCtx
            | Self::GetWindowThreadProcessId
            | Self::KillTimer
            | Self::UnregisterClassW
            | Self::IsDialogMessageW
            | Self::SetClipboardData
            | Self::EnumWindows
            | Self::GetScrollPos
            | Self::ChoosePixelFormat
            | Self::RegisterEventSourceW
            | Self::BCryptCloseAlgorithmProvider
            | Self::BCryptFinalizeKeyPair
            | Self::CertCloseStore
            | Self::CertOpenSystemStoreW
            | Self::CertEnumCertificatesInStore
            | Self::RtlIsProtectedProcess
            | Self::RtlIsProtectedProcessLight
            | Self::CredIsProtected
            | Self::XAudio2VoiceGetVoiceDetails
            | Self::XAudio2VoiceSetOutputVoices
            | Self::XAudio2VoiceSetEffectChain
            | Self::XAudio2VoiceEnableEffect
            | Self::XAudio2VoiceDisableEffect
            | Self::XAudio2VoiceSetFilterParameters
            | Self::XAudio2VoiceGetFilterParameters
            | Self::XAudio2VoiceSetOutputFilterParameters
            | Self::XAudio2VoiceGetOutputFilterParameters
            | Self::XAudio2VoiceSetVolume
            | Self::XAudio2VoiceGetVolume
            | Self::XAudio2SourceVoiceGetState
            | Self::XAudio2SourceVoiceSetFrequencyRatio
            | Self::XAudio2SourceVoiceGetFrequencyRatio
            | Self::XAudio2SourceVoiceSetSourceSampleRate
            | Self::XAPO_GetRegistrationProperties
            | Self::XAPO_LockForProcess
            | Self::DirectInputDevice8SetDataFormat
            | Self::DirectInputDevice8GetCapabilities
            | Self::DirectInputDevice8SendForceFeedbackCommand
            | Self::DirectInputDevice8SetForceFeedbackState
            | Self::RegisterTouchWindow
            | Self::GetPointerInfo
            | Self::GetPointerPenInfo
            | Self::GetPointerDeviceCaps
            | Self::GetPointerFrameInfo
            | Self::XInputGetState
            | Self::XInputSetState
            | Self::SteamAPI_ISteamInput_RunFrame
            | Self::SteamAPI_ISteamInput_GetActionSetHandle
            | Self::SteamAPI_ISteamInput_GetDigitalActionHandle
            | Self::SteamAPI_ISteamInput_GetAnalogActionHandle
            | Self::SteamAPI_ISteamInput_GetCurrentActionSet
            | Self::SteamAPI_ISteamInput_GetControllerInputType
            | Self::SteamAPI_ISteamInput_GetMotionData
            | Self::SteamAPI_ISteamInput_ShowBindingPanel
            | Self::SteamAPI_ISteamInput_GetGlyphForActionHandle
            | Self::SteamVR_Init
            | Self::SteamVR_GetGenericInterface
            | Self::SteamVR_IVRSystem_GetTrackedDeviceClass
            | Self::SteamVR_IVRSystem_IsTrackedDeviceConnected
            | Self::SteamVR_IVRCompositor_GetCumulativeStats
            | Self::SteamVR_IVRCompositor_SetExplicitTimingMode
            | Self::SteamVR_IVRCompositor_SetExplicitTimingLastPose
            | Self::SteamVR_IVRChaperone_GetPlayAreaRect
            | Self::SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress
            | Self::SteamAPI_ISteamNetworkingSockets_ConnectBySteamID
            | Self::SteamAPI_ISteamNetworkingSockets_AcceptConnection
            | Self::SteamAPI_ISteamNetworkingMessages_CloseSessionWithUser
            | Self::SteamAPI_RegisterCallback
            | Self::SteamAPI_RegisterCallResult
            | Self::SteamAPI_UnregisterCallResult
            | Self::SteamInternal_FindOrCreateUserInterface
            | Self::SteamInternal_FindOrCreateGameInterface
            | Self::SteamAPI_ISteamUserStats_SetAchievement
            | Self::SteamAPI_ISteamUserStats_ClearAchievement
            | Self::SteamAPI_ISteamUserStats_GetAchievementName
            | Self::SteamAPI_ISteamUserStats_GetLeaderboardEntryCount
            | Self::SteamAPI_ISteamUserStats_GetLeaderboardName
            | Self::SteamAPI_ISteamUserStats_GetLeaderboardSortMethod
            | Self::SteamAPI_ISteamUserStats_GetLeaderboardDisplayType
            | Self::SteamAPI_ISteamFriends_SetPersonaName
            | Self::SteamAPI_ISteamFriends_SetPersonaState
            | Self::SteamAPI_ISteamFriends_GetFriendCount
            | Self::SteamAPI_ISteamFriends_GetFriendByIndex
            | Self::SteamAPI_ISteamFriends_RemoveFriend
            | Self::SteamAPI_ISteamFriends_AcceptInvite
            | Self::SteamAPI_ISteamFriends_DeclineInvite
            | Self::SteamAPI_ISteamFriends_GetInviteByIndex
            | Self::SteamAPI_ISteamFriends_GetFriendMessageCount
            | Self::SteamAPI_ISteamFriends_LeaveClan
            | Self::SteamAPI_ISteamFriends_GetClanByIndex
            | Self::SteamAPI_ISteamFriends_GetClanName
            | Self::SteamAPI_ISteamFriends_IsClanMember
            | Self::SteamAPI_ISteamFriends_ActivateGameOverlayToWebPage
            | Self::SteamAPI_ISteamFriends_ActivateGameOverlay
            | Self::SteamAPI_ISteamFriends_ActivateGameOverlayToStore
            | Self::SteamAPI_ISteamFriends_ActivateGameOverlayToInviteDialog
            | Self::SteamAPI_ISteamMatchmaking_JoinLobby
            | Self::SteamAPI_ISteamMatchmaking_LeaveLobby
            | Self::SteamAPI_ISteamMatchmaking_GetLobbyMemberCount
            | Self::SteamAPI_ISteamMatchmaking_GetLobbyOwner
            | Self::SteamAPI_ISteamMatchmaking_GetLobbyByIndex
            | Self::SteamAPI_ISteamRemoteStorage_FileDelete
            | Self::SteamAPI_ISteamRemoteStorage_FileExists
            | Self::SteamAPI_ISteamRemoteStorage_FileSize
            | Self::SteamAPI_ISteamRemoteStorage_FileTime
            | Self::SteamAPI_ISteamRemoteStorage_GetFileName
            | Self::SteamAPI_ISteamRemoteStorage_GetFileSize
            | Self::SteamAPI_ISteamRemoteStorage_UGCSubscribe
            | Self::SteamAPI_ISteamRemoteStorage_UGCUnsubscribe
            | Self::SteamAPI_ISteamScreenshots_HookScreenshots
            | Self::SteamAPI_ISteamScreenshots_GetScreenshotByIndex
            | Self::SteamAPI_ISteamScreenshots_GetScreenshotFilePath
            | Self::SteamAPI_ISteamScreenshots_GetScreenshotThumbnailPath
            | Self::SteamAPI_ISteamMusic_SetEnabled
            | Self::SteamAPI_ISteamMusic_SetVolume
            | Self::SteamVR_IVRRenderModels_FreeRenderModel
            | Self::SteamVR_IVRRenderModels_GetRenderModelName
            | Self::SteamVR_IVRRenderModels_GetRenderModelNameByIndex
            | Self::SteamVR_IVRRenderModels_GetRenderModelThumbnail
            | Self::WaitForThreadpoolWorkCallbacks
            | Self::SysReAllocString
            | Self::SysAllocStringLen
            | Self::VariantCopy
            | Self::SafeArrayAccessData
            | Self::SafeArrayCreateVector
            | Self::ScriptGetProperties
            | Self::ScriptRecordDigitSubstitution
            | Self::GdipCreateFromHDC
            | Self::GdipCreateSolidFill
            | Self::GdipSetPenWidth
            | Self::GdipGetPenWidth
            | Self::GdipSetPenColor
            | Self::GdipGetPenColor
            | Self::GdipSetPenDashStyle
            | Self::GdipGetPenDashStyle
            | Self::GdipSetPenLineJoin
            | Self::GdipSetPenStartCap
            | Self::GdipSetPenEndCap
            | Self::GdipCreatePath
            | Self::GdipSetPathFillMode
            | Self::GdipGetMatrixElements
            | Self::GdipSetWorldTransform
            | Self::GdipGetWorldTransform
            | Self::GdipGetClipBounds
            | Self::GdipGetClip
            | Self::GdipSaveGraphics
            | Self::GdipRestoreGraphics
            | Self::GdipEndContainer
            | Self::GdipCreateBitmapFromFile
            | Self::GdipGetImageWidth
            | Self::GdipGetImageHeight
            | Self::GdipGetImagePixelFormat
            | Self::GdipBitmapUnlockBits
            | Self::GdipSetTextRenderingHint
            | Self::GdipSetSmoothingMode
            | Self::GdipGetSmoothingMode
            | Self::GdipSetCompositingMode
            | Self::GdipGetCompositingMode
            | Self::GdipSetCompositingQuality
            | Self::GdipGetCompositingQuality
            | Self::GdipSetInterpolationMode
            | Self::GdipGetInterpolationMode
            | Self::GdipSetPixelOffsetMode
            | Self::GdipGetPixelOffsetMode
            | Self::GdipGetImageType
            | Self::GdipGetImageRawFormat
            | Self::GdipCloneImage
            | Self::GdipCreateBitmapFromStream
            | Self::GdipCreateHICONFromBitmap
            | Self::GdipCreateImageFromFile
            | Self::WaveOutGetVolume
            | Self::WaveOutSetVolume
            | Self::MidiOutShortMsg
            | Self::MmioClose
            | Self::MmioAscend
            | Self::MmioStringToFOURCCW
            | Self::DwmEnableBlurBehindWindow
            | Self::DwmExtendFrameIntoClientArea
            | Self::DwmGetColorizationColor
            | Self::DwmUpdateThumbnailProperties
            | Self::DwmSetIconicThumbnail
            | Self::FtpDeleteFileW
            | Self::FtpSetCurrentDirectoryW
            | Self::FtpCreateDirectoryW
            | Self::FtpRemoveDirectoryW
            | Self::SetMenu
            | Self::GetSubMenu
            | Self::GetMenuItemID
            | Self::LoadMenuW
            | Self::RegisterDragDrop
            | Self::DragAcceptFiles
            | Self::InvertRect
            | Self::SetupDiInstallDevice
            | Self::SetupDiUninstallDevice
            | Self::SetupDiDestroyDriverInfoList => 8,
            Self::GetEnvironmentVariableW
            | Self::SetHandleInformation
            | Self::Ioctlsocket
            | Self::Socket
            | Self::GetModuleHandleExA
            | Self::GetModuleHandleExW
            | Self::Bind
            | Self::Connect
            | Self::Getsockname
            | Self::OpenEventA
            | Self::OpenEventW
            | Self::InitOnceComplete
            | Self::HeapAlloc
            | Self::HeapFree
            | Self::HeapSize
            | Self::InitializeCriticalSectionEx
            | Self::SleepConditionVariableCS
            | Self::GetFileAttributesExW
            | Self::ImageList_GetImageInfo
            | Self::ImageList_Add
            | Self::ImageList_DragEnter
            | Self::ImageList_ReplaceIcon
            | Self::EnumProcesses
            | Self::OpenProcess
            | Self::GetModuleFileNameA
            | Self::GetModuleFileNameW
            | Self::LoadLibraryExA
            | Self::LoadLibraryExW
            | Self::GetClassInfoW
            | Self::GetClassInfoExW
            | Self::SetDlgItemTextW
            | Self::SetClassLongW
            | Self::SetWindowLongW
            | Self::EnableMenuItem
            | Self::InvalidateRect
            | Self::FillRect
            | Self::FrameRect
            | Self::CreatePen
            | Self::InflateRect
            | Self::OffsetRect
            | Self::LineTo
            | Self::CheckDlgButton
            | Self::MulDiv
            | Self::VirtualQuery
            | Self::VirtualFree
            | Self::AnimateWindow
            | Self::LstrcpynW
            | Self::RegOpenKeyA
            | Self::ShellLinkQueryInterface
            | Self::ShellLinkGetDescriptionW
            | Self::ShellLinkGetWorkingDirectoryW
            | Self::ShellLinkGetArgumentsW
            | Self::ShellLinkSetIconLocationW
            | Self::ShellLinkSetRelativePath
            | Self::ShellLinkResolve
            | Self::ShellLinkPersistLoad
            | Self::ShellLinkPersistSave
            | Self::SHGetSpecialFolderLocation
            | Self::GetLongPathNameW
            | Self::GetShortPathNameW
            | Self::SetWindowRgn
            | Self::PrintWindow
            | Self::GetWindowTextW
            | Self::InvalidateRgn
            | Self::SetWindowLongPtrW
            | Self::CopyFileW
            | Self::MoveFileExW
            | Self::HeapValidate
            | Self::HeapLock
            | Self::HeapUnlock
            | Self::OpenThread
            | Self::GetProcessAffinityMask
            | Self::FindResourceA
            | Self::SystemTimeToTzSpecificLocalTime
            | Self::WaitForSingleObjectEx
            | Self::CreateFiber
            | Self::SetDlgItemTextA
            | Self::MonitorFromPoint
            | Self::EnumChildWindows
            | Self::GetScrollInfo
            | Self::ShowScrollBar
            | Self::EnableScrollBar
            | Self::SetPixelFormat
            | Self::GetProcessMemoryInfo
            | Self::BCryptGenRandom
            | Self::CertCreateCertificateContext
            | Self::PFXImportCertStore
            | Self::CertFindExtension
            | Self::XAudio2VoiceGetEffectState
            | Self::XAudio2VoiceSetChannelVolumes
            | Self::XAudio2VoiceGetChannelVolumes
            | Self::DirectInput8CreateDevice
            | Self::DirectInputDevice8SetCooperativeLevel
            | Self::DirectInputDevice8GetDeviceState
            | Self::RegisterRawInputDevices
            | Self::GetRegisteredRawInputDevices
            | Self::InitializeTouchInjection
            | Self::GetPointerDeviceRects
            | Self::XInputGetCapabilities
            | Self::XInputGetDSoundAudioDeviceGuids
            | Self::XInputGetBatteryInformation
            | Self::XInputGetKeystroke
            | Self::SteamAPI_ISteamInput_GetConnectedControllers
            | Self::SteamAPI_ISteamInput_ActivateActionSet
            | Self::SteamAPI_ISteamInput_GetDigitalActionData
            | Self::SteamAPI_ISteamInput_GetAnalogActionData
            | Self::SteamVR_IVRSystem_GetBoolTrackedDeviceProperty
            | Self::SteamVR_IVRSystem_GetFloatTrackedDeviceProperty
            | Self::SteamVR_IVRSystem_GetInt32TrackedDeviceProperty
            | Self::SteamVR_IVRSystem_GetUint64TrackedDeviceProperty
            | Self::SteamVR_IVRSystem_GetRecommendedRenderTargetSize
            | Self::SteamVR_IVRSystem_GetEyeToHeadTransform
            | Self::SteamVR_IVRSystem_PollNextEvent
            | Self::SteamVR_IVRCompositor_GetFrameTiming
            | Self::SteamVR_IVRChaperone_GetPlayAreaSize
            | Self::SteamAPI_ISteamNetworkingSockets_DestroyListenSocket
            | Self::SteamAPI_ISteamNetworkingSockets_GetConnectionStatus
            | Self::SteamAPI_WriteMiniDump
            | Self::SteamAPI_ISteamUserStats_GetStat
            | Self::SteamAPI_ISteamUserStats_SetStat
            | Self::SteamAPI_ISteamUserStats_GetStatFloat
            | Self::SteamAPI_ISteamUserStats_SetStatFloat
            | Self::SteamAPI_ISteamUserStats_GetAchievement
            | Self::SteamAPI_ISteamUserStats_AttachLeaderboardUGC
            | Self::SteamAPI_ISteamFriends_GetFriendPersonaName
            | Self::SteamAPI_ISteamFriends_GetFriendPersonaState
            | Self::SteamAPI_ISteamFriends_SetFriendPersonaState
            | Self::SteamAPI_ISteamFriends_AddFriend
            | Self::SteamAPI_ISteamFriends_GetSmallFriendAvatar
            | Self::SteamAPI_ISteamFriends_GetMediumFriendAvatar
            | Self::SteamAPI_ISteamFriends_GetLargeFriendAvatar
            | Self::SteamAPI_ISteamFriends_InviteFriend
            | Self::SteamAPI_ISteamFriends_JoinClan
            | Self::SteamAPI_ISteamFriends_SetRichPresence
            | Self::SteamAPI_ISteamFriends_ActivateGameOverlayToUser
            | Self::SteamAPI_ISteamMatchmaking_CreateLobby
            | Self::SteamAPI_ISteamMatchmaking_GetLobbyMemberByIndex
            | Self::SteamAPI_ISteamMatchmaking_SetLobbyJoinable
            | Self::SteamAPI_ISteamMatchmaking_SendLobbyChatMessage
            | Self::SteamAPI_ISteamRemoteStorage_UGCDownload
            | Self::CreateMutexW
            | Self::CreateMutexA
            | Self::OpenMutexW
            | Self::OpenSemaphoreW
            | Self::ReleaseSemaphore
            | Self::QueueUserAPC
            | Self::QueueUserWorkItem
            | Self::CreateThreadpoolWork
            | Self::CreateThreadpoolTimer
            | Self::CreateThreadpoolWait
            | Self::SetThreadpoolWait
            | Self::SafeArrayCreate
            | Self::SafeArrayGetElement
            | Self::SafeArrayPutElement
            | Self::SafeArrayGetLBound
            | Self::SafeArrayGetUBound
            | Self::ScriptCacheGetHeight
            | Self::GdiplusStartup
            | Self::GdipCreateTextureBrush
            | Self::GdipFillRegion
            | Self::GdipDrawPath
            | Self::GdipFillPath
            | Self::GdipRotateMatrix
            | Self::GdipMultiplyMatrix
            | Self::GdipSetClipPath
            | Self::GdipSetClipRegion
            | Self::GdipCreateBitmapFromHBITMAP
            | Self::GdipCreateFontFamilyFromName
            | Self::GdipCreateHBITMAPFromBitmap
            | Self::GdipGetFontHeight
            | Self::GdipCreateBitmapFromGdiDib
            | Self::WaveOutPrepareHeader
            | Self::WaveOutUnprepareHeader
            | Self::WaveOutWrite
            | Self::WaveOutGetDevCapsW
            | Self::WaveInPrepareHeader
            | Self::WaveInUnprepareHeader
            | Self::WaveInAddBuffer
            | Self::WaveInGetDevCapsW
            | Self::MidiOutLongMsg
            | Self::MidiOutGetDevCapsW
            | Self::MmioOpenW
            | Self::MmioRead
            | Self::MmioWrite
            | Self::MmioDescend
            | Self::MmioCreateChunk
            | Self::DwmRegisterThumbnail
            | Self::FtpRenameFileW
            | Self::FtpGetCurrentDirectoryW
            | Self::RemoveMenu
            | Self::GetMenuState
            | Self::CheckMenuItem
            | Self::SHCreateItemFromIDList
            | Self::CreateURLMoniker
            | Self::CreateCompatibleBitmap
            | Self::GetObjectW
            | Self::GetPixel
            | Self::GetRgnBox
            | Self::SetupDiEnumDeviceInfo
            | Self::SetupDiCallClassInstaller
            | Self::SetupDiGetSelectedDriverW
            | Self::SetupDiBuildDriverInfoList => 12,
            Self::GetStringTypeW
            | Self::DisconnectEx
            | Self::Send
            | Self::Recv
            | Self::Getaddrinfo
            | Self::CreateIoCompletionPort
            | Self::PostQueuedCompletionStatus
            | Self::CreateEventA
            | Self::CreateEventW
            | Self::InitOnceBeginInitialize
            | Self::InitOnceExecuteOnce
            | Self::HeapReAlloc
            | Self::GetFullPathNameW
            | Self::ImageList_BeginDrag
            | Self::ImageList_SetDragCursorImage
            | Self::EnumDisplayMonitors
            | Self::EnumDisplayDevicesW
            | Self::WaitForMultipleObjects
            | Self::EnumProcessModules
            | Self::GetModuleBaseNameA
            | Self::GetTempFileNameW
            | Self::FindWindowExW
            | Self::AppendMenuW
            | Self::SystemParametersInfoW
            | Self::MessageBoxW
            | Self::VirtualAlloc
            | Self::VirtualProtect
            | Self::GetDlgItemTextW
            | Self::WritePrivateProfileStringW
            | Self::GetTextExtentPoint32A
            | Self::GetTextExtentPoint32W
            | Self::CreateRectRgn
            | Self::MoveToEx
            | Self::DrawAnimatedRects
            | Self::VerSetConditionMask
            | Self::VerifyVersionInfoW
            | Self::GetDiskFreeSpaceExW
            | Self::SetFileTime
            | Self::RedrawWindow
            | Self::GetMessageW
            | Self::SendMessageW
            | Self::PostThreadMessageW
            | Self::SetTimer
            | Self::SetSecurityDescriptorDacl
            | Self::SetFilePointer
            | Self::ShellLinkGetIconLocationW
            | Self::CreatePipe
            | Self::GetFileVersionInfoW
            | Self::VerQueryValueW
            | Self::SHGetKnownFolderPath
            | Self::GetNamedPipeInfo
            | Self::SetNamedPipeHandleState
            | Self::GetDpiForMonitor
            | Self::SetLayeredWindowAttributes
            | Self::GetFileTime
            | Self::HeapSetInformation
            | Self::HeapQueryInformation
            | Self::RaiseException
            | Self::RtlUnwind
            | Self::SetDlgItemInt
            | Self::GetDlgItemInt
            | Self::DefDlgProcW
            | Self::MapWindowPoints
            | Self::MessageBoxA
            | Self::SetScrollInfo
            | Self::SetScrollPos
            | Self::GetScrollRange
            | Self::AddFontMemResourceEx
            | Self::CreateICW
            | Self::GetModuleFileNameExW
            | Self::GetModuleInformation
            | Self::BCryptOpenAlgorithmProvider
            | Self::BCryptGenerateKeyPair
            | Self::BCryptHashData
            | Self::BCryptSecretAgreement
            | Self::CertAddCertificateContextToStore
            | Self::CertGetIntendedKeyUsage
            | Self::XAudio2VoiceSetEffectParameters
            | Self::XAudio2VoiceGetEffectParameters
            | Self::XAudio2VoiceSetOutputMatrix
            | Self::XAudio2VoiceGetOutputMatrix
            | Self::DirectInputDevice8EnumObjects
            | Self::DirectInputDevice8SetProperty
            | Self::GetRawInputDeviceInfoW
            | Self::GetTouchInputInfo
            | Self::SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnListenSocket
            | Self::SteamAPI_ISteamNetworkingSockets_GetConnectionName
            | Self::SteamAPI_ISteamUserStats_FindOrCreateLeaderboard
            | Self::SteamAPI_ISteamMatchmaking_SetLobbyData
            | Self::SteamAPI_ISteamFriends_GetFriendGamePlayed
            | Self::SteamAPI_ISteamMatchmaking_GetLobbyData
            | Self::SteamAPI_ISteamRemoteStorage_FileWrite
            | Self::SteamAPI_ISteamRemoteStorage_FileRead
            | Self::SteamVR_IVRRenderModels_LoadRenderModel
            | Self::CreateSemaphoreW
            | Self::CreateSemaphoreA
            | Self::SetThreadpoolTimer
            | Self::VariantChangeType
            | Self::ScriptLayout
            | Self::ScriptBreak
            | Self::ScriptApplyDigitSubstitution
            | Self::GdipDrawLines
            | Self::GdipDrawPolygon
            | Self::GdipCreatePen1
            | Self::GdipCreatePen2
            | Self::GdipTranslateMatrix
            | Self::GdipScaleMatrix
            | Self::GdipCreateBitmapFromGraphics
            | Self::GdipBitmapGetPixel
            | Self::GdipBitmapSetPixel
            | Self::GdipDrawImage
            | Self::GdipSaveImageToFile
            | Self::GdipSaveImageToStream
            | Self::PlaySoundW
            | Self::DwmGetWindowAttribute
            | Self::DwmSetWindowAttribute
            | Self::DwmSetIconicLivePreviewBitmap
            | Self::WinHttpWebSocketSend
            | Self::WinHttpWebSocketClose
            | Self::WinHttpWebSocketQueryCloseStatus
            | Self::WinHttpQueryOption
            | Self::WinHttpGetProxyForUrl
            | Self::FtpPutFileW
            | Self::FtpOpenFileW
            | Self::FtpFindFirstFileW
            | Self::InsertMenuItemW
            | Self::HiliteMenuItem
            | Self::SHCreateItemFromParsingName
            | Self::SHBindToParent
            | Self::SHGetSpecialFolderPathW
            | Self::DoDragDrop
            | Self::DragQueryFileW
            | Self::CreateAsyncBindCtx
            | Self::RegisterBindStatusCallback
            | Self::GetMessageA
            | Self::PostMessageA
            | Self::PostMessageW
            | Self::GetWindowTextA
            | Self::CombineRgn
            | Self::SetPixel
            | Self::GetCharWidthW
            | Self::GetModuleBaseNameW
            | Self::SetupDiGetClassDevsW
            | Self::SetupDiGetClassDescriptionW
            | Self::SetupDiEnumDriverInfoW => 16,
            Self::Setsockopt
            | Self::GetQueuedCompletionStatus
            | Self::Select
            | Self::ImageList_Create
            | Self::WriteProcessMemory
            | Self::Rectangle
            | Self::DrawTextW
            | Self::DrawTextA
            | Self::SetRect
            | Self::CallWindowProcW
            | Self::DialogBoxParamW
            | Self::CreateDialogParamW
            | Self::GetDiskFreeSpaceW
            | Self::PeekMessageW
            | Self::RegOpenKeyExA
            | Self::RegOpenKeyExW
            | Self::ReadFile
            | Self::WriteFile
            | Self::GetOverlappedResult
            | Self::SHGetFileInfoW
            | Self::SHGetFolderPathW
            | Self::CoCreateInstance
            | Self::ShellLinkGetPathW
            | Self::MapViewOfFile
            | Self::GetProductInfo
            | Self::AdjustWindowRectExForDpi
            | Self::SetFilePointerEx
            | Self::WriteConsoleW
            | Self::ReadConsoleA
            | Self::ReadConsoleW
            | Self::GetDiskFreeSpaceA
            | Self::FindActCtxSectionStringW
            | Self::MsgWaitForMultipleObjects
            | Self::DialogBoxParamA
            | Self::SendDlgItemMessageW
            | Self::GetUserObjectInformationW
            | Self::SetScrollRange
            | Self::ScrollWindow
            | Self::TextOutW
            | Self::BCryptSetProperty
            | Self::CertOpenStore
            | Self::CertVerifyCertificateChainPolicy
            | Self::CredUnprotectW
            | Self::NtQueryInformationProcess
            | Self::XAudio2CreateSubmixVoice
            | Self::DirectInput8Create
            | Self::DirectInput8EnumDevices
            | Self::DirectInputDevice8GetDeviceData
            | Self::GetRawInputData
            | Self::SteamVR_IVRSystem_GetProjectionMatrix
            | Self::SteamVR_IVRSystem_GetDeviceToAbsoluteTrackingPose
            | Self::SteamVR_IVRCompositor_Submit
            | Self::SteamVR_IVRCompositor_WaitGetPoses
            | Self::SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP
            | Self::SteamAPI_ISteamNetworkingSockets_CloseConnection
            | Self::SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel
            | Self::SteamAPI_ISteamMatchmaking_SetLobbyMemberData
            | Self::SteamAPI_ISteamFriends_SendFriendMessage
            | Self::SteamAPI_ISteamMatchmaking_SetLobbyOwner
            | Self::SteamAPI_ISteamScreenshots_TagUser
            | Self::SteamAPI_ISteamScreenshots_TagPublishedFile
            | Self::SteamAPI_ISteamScreenshots_WriteScreenshot
            | Self::SteamAPI_ISteamScreenshots_AddScreenshotToLibrary
            | Self::CoGetClassObject
            | Self::CoRegisterClassObject
            | Self::GdipFillPolygon
            | Self::GdipDrawCurve
            | Self::GdipDrawClosedCurve
            | Self::GdipAddPathLine
            | Self::GdipAddPathRectangle
            | Self::GdipAddPathEllipse
            | Self::GdipBeginContainer
            | Self::GdipBitmapLockBits
            | Self::GdipCreateFont
            | Self::GdipSetImageAttributesColorKeys
            | Self::MidiOutOpen
            | Self::MidiInOpen
            | Self::WinHttpWebSocketReceive
            | Self::FtpGetFileW
            | Self::InsertMenuW
            | Self::ModifyMenuW
            | Self::GetMenuStringW
            | Self::SHParseDisplayName
            | Self::SHGetDataFromIDListW
            | Self::GetThreadTimes
            | Self::Ellipse
            | Self::SetupDiOpenDeviceInfoW
            | Self::SetupDiGetDeviceInstanceIdW
            | Self::SetupDiSetDeviceRegistryPropertyW => 20,
            Self::LCMapStringW
            | Self::WsaSocketA
            | Self::GetQueuedCompletionStatusEx
            | Self::ImageList_Draw
            | Self::CreateThread
            | Self::PatBlt
            | Self::LoadImageW
            | Self::CreateRoundRectRgn
            | Self::RegSetValueExA
            | Self::RegSetValueExW
            | Self::RegQueryValueExA
            | Self::RegQueryValueExW
            | Self::MultiByteToWideChar
            | Self::RegEnumKeyExW
            | Self::PeekNamedPipe
            | Self::CreateFileMappingW
            | Self::CompareStringW
            | Self::GetDateFormatW
            | Self::GetTimeFormatW
            | Self::FindFirstFileExW
            | Self::MoveWindow
            | Self::CreateDIBSection
            | Self::BCryptGetProperty
            | Self::CertFindCertificateInStore
            | Self::CertGetNameStringW
            | Self::CryptAcquireCertificatePrivateKey
            | Self::CredProtectW
            | Self::XAPO_Process
            | Self::SteamVR_IVRSystem_GetStringTrackedDeviceProperty
            | Self::SteamVR_IVRSystem_GetProjectionRaw
            | Self::SteamAPI_ISteamNetworkingSockets_SendMessageToConnection
            | Self::SteamAPI_ISteamNetworkingMessages_SendMessageToUser
            | Self::SteamAPI_ISteamUserStats_UploadLeaderboardScore
            | Self::SteamAPI_ISteamUserStats_DownloadLeaderboardEntries
            | Self::CoCreateInstanceEx
            | Self::GdipDrawLine
            | Self::GdipDrawRectangle
            | Self::GdipFillRectangle
            | Self::GdipDrawEllipse
            | Self::GdipFillEllipse
            | Self::GdipSetClipRect
            | Self::GdipSetImageAttributesColorMatrix
            | Self::GdipDrawImageRect
            | Self::GdipCreateBitmapFromScan0
            | Self::WaveOutOpen
            | Self::SteamAPI_ISteamFriends_GetFriendMessage
            | Self::SteamAPI_ISteamMatchmaking_GetLobbyMemberData
            | Self::WaveInOpen
            | Self::DrawTextExW => 24,
            Self::DuplicateHandle
            | Self::WsaRecv
            | Self::WsaSend
            | Self::CreateFileW
            | Self::ConnectEx
            | Self::SetWindowPos
            | Self::TrackPopupMenu
            | Self::SendMessageTimeoutW
            | Self::GetTextExtentExPointW
            | Self::CallNamedPipeW
            | Self::CreateFileA
            | Self::ScrollDC
            | Self::BCryptGenerateSymmetricKey
            | Self::BCryptHash
            | Self::BCryptCreateHash
            | Self::BCryptDeriveKey
            | Self::BCryptVerifySignature
            | Self::SteamAPI_ISteamInput_TriggerRepeatedHapticPulse
            | Self::CreateRemoteThread
            | Self::ScriptStringAnalyse
            | Self::ScriptItemize
            | Self::GdipDrawString
            | Self::GdipAddPathArc
            | Self::GdipSetMatrixElements
            | Self::WinHttpWebSocketCompleteUpgrade
            | Self::GetGlyphOutlineW => 28,
            Self::WideCharToMultiByte
            | Self::ExtTextOutW
            | Self::CreateNamedPipeW
            | Self::DeviceIoControl
            | Self::ScrollWindowEx
            | Self::BCryptSignHash
            | Self::CertGetCertificateChain
            | Self::ScriptStringOut
            | Self::ScriptPlace
            | Self::GdipDrawPie
            | Self::GdipFillPie
            | Self::GdipDrawArc
            | Self::GdipCreateLineBrush => 32,
            Self::WsaRecvFrom
            | Self::WsaSendTo
            | Self::LCMapStringEx
            | Self::RegCreateKeyExA
            | Self::RegCreateKeyExW
            | Self::WsaIoctl
            | Self::UpdateLayeredWindow
            | Self::ReportEventW
            | Self::BCryptImportKey
            | Self::GdipAddPathBezier
            | Self::GdipMeasureString
            | Self::GdipMeasureCharacterRanges => 36,
            Self::ImageList_DrawEx
            | Self::CreateProcessW
            | Self::CreateProcessA
            | Self::BCryptEncrypt
            | Self::BCryptDecrypt
            | Self::ScriptShape => 40,
            Self::AlphaBlend | Self::TransparentBlt => 44,
            Self::CreateWindowExW => 48,
            Self::CreateFontW | Self::GdipDrawImageRectRect => 56,
            // -- Stage-4 NTDLL foundation: Nt*/Rtl* x86 stack-arg sizes -------
            Self::NtClose
            | Self::NtClearEvent
            | Self::NtDeleteKey
            | Self::NtQuerySystemTime
            | Self::RtlFreeUnicodeString
            | Self::RtlFreeAnsiString
            | Self::RtlGetVersion
            | Self::RtlCaptureContext
            | Self::RtlRaiseException
            | Self::LdrUnloadDll => 4,
            Self::NtSetEvent
            | Self::NtDelayExecution
            | Self::NtUnmapViewOfSection
            | Self::NtGetContextThread
            | Self::NtSetContextThread
            | Self::NtTerminateProcess
            | Self::NtTerminateThread
            | Self::NtSuspendThread
            | Self::NtResumeThread
            | Self::NtQueryPerformanceCounter
            | Self::NtSetTimerResolution
            | Self::NtQueryTimerResolution
            | Self::RtlInitUnicodeString
            | Self::RtlInitAnsiString
            | Self::LdrUnlockLoaderLock
            | Self::LdrAddRefDll
            | Self::LdrRemoveRefDll => 8,
            Self::NtWaitForSingleObject
            | Self::NtDeleteValueKey
            | Self::RtlCompareUnicodeString
            | Self::RtlEqualUnicodeString
            | Self::RtlLookupFunctionEntry
            | Self::RtlAllocateHeap
            | Self::RtlFreeHeap
            | Self::RtlSizeHeap
            | Self::LdrLockLoaderLock => 12,
            Self::NtOpenDirectoryObject => 12,
            Self::NtFreeVirtualMemory
            | Self::NtSetInformationThread
            | Self::NtQuerySystemInformation => 16,
            Self::NtAttestationVerify => 16,
            Self::NtAttestationEnrollProvider => 16,
            Self::NtAttestationRevokeProvider => 4,
            Self::NtProtectVirtualMemory
            | Self::NtReadVirtualMemory
            | Self::NtWriteVirtualMemory
            | Self::NtQueryObject
            | Self::NtCreateEvent
            | Self::NtWaitForMultipleObjects
            | Self::NtQuerySection
            | Self::NtOpenKey
            | Self::NtQueryKey
            | Self::NtQueryInformationThread
            | Self::NtQueryVolumeInformationFile
            | Self::NtAttestationChallenge => 20,
            Self::NtAttestationQuote => 24,
            Self::NtAllocateVirtualMemory
            | Self::NtQueryVirtualMemory
            | Self::NtSetValueKey
            | Self::NtEnumerateKey
            | Self::NtEnumerateValueKey
            | Self::NtQueryValueKey
            | Self::LdrLoadDll
            | Self::LdrGetDllHandle
            | Self::LdrGetProcedureAddress => 16,
            Self::NtCreateSection
            | Self::NtDuplicateObject
            | Self::NtCreateKey
            | Self::NtQueryDirectoryObject => 28,
            Self::NtCreateThreadEx | Self::NtDeviceIoControlFile | Self::NtMapViewOfSection => 40,
            Self::NtCreateFile => 44,
            Self::NtReadFile | Self::NtWriteFile => 36,
            Self::NtLoadDriver | Self::NtUnloadDriver => 4,
            // ── kernel32 core surface (x86 stdcall byte counts) ────────────
            Self::GetCommState
            | Self::SetCommState
            | Self::GetCommTimeouts
            | Self::SetCommTimeouts
            | Self::PurgeComm
            | Self::EscapeCommFunction => 8,
            Self::ClearCommError => 12,
            Self::DisableThreadLibraryCalls => 4,
            Self::ExpandEnvironmentStringsW => 12,
            Self::GetFileInformationByHandleEx => 16,
            Self::GetPrivateProfileStringW => 24,
            Self::GetVersionExA => 4,
            Self::InterlockedCompareExchange => 12,
            Self::InterlockedDecrement => 4,
            Self::InterlockedExchange => 8,
            Self::InterlockedExchangeAdd => 8,
            Self::InterlockedIncrement => 4,
            Self::MoveFileW => 8,
            Self::SearchPathW => 24,
            Self::LstrcmpiA => 8,
            // ── shlwapi.dll path helpers ───────────────────────────────────
            Self::PathAppendW
            | Self::PathCombineW
            | Self::PathCanonicalizeW
            | Self::PathMatchSpecW
            | Self::ChrCmpIW
            | Self::ParseURLW
            | Self::StrChrW
            | Self::StrChrIW
            | Self::StrStrW
            | Self::StrStrIW
            | Self::StrCmpIW
            | Self::StrCmpW
            | Self::StrCpyW
            | Self::StrCatW
            | Self::SHDeleteKeyW
            | Self::SHDeleteEmptyKeyW
            | Self::SetMenuContextHelpId => 8,
            Self::PathFileExistsW
            | Self::PathFindExtensionW
            | Self::PathFindFileNameW
            | Self::PathRemoveFileSpecW
            | Self::PathRemoveExtensionW
            | Self::PathRemoveBlanksW
            | Self::PathIsDirectoryW
            | Self::PathIsRelativeW
            | Self::PathStripPathW
            | Self::PathGetDriveNumberW
            | Self::PathAddBackslashW
            | Self::PathRemoveBackslashW
            | Self::PathSkipRootW
            | Self::PathIsRootW
            | Self::IsCharAlphaW
            | Self::IsCharAlphaNumericW
            | Self::IsCharLowerW
            | Self::IsCharUpperW
            | Self::IsCharSpaceW
            | Self::StrToIntW
            | Self::GetMenuContextHelpId => 4,
            Self::IntlStrEqWorkerW
            | Self::StrCmpNIW
            | Self::StrCmpNW
            | Self::StrCpyNW
            | Self::StrFromTimeIntervalW
            | Self::UrlCanonicalizeW
            | Self::SHSearchMapInt => 16,
            Self::StrRChrW => 12,
            Self::SHRegGetValueW | Self::SHRegSetValueW => 28,
            Self::UrlCombineW => 20,
            // IActivateAudioInterfaceAsyncOperation (this = first arg).
            Self::AudioActivationOperationQueryInterface
            | Self::AudioActivationOperationGetActivateResult => 12,
            // IAudioClient / IAudioRenderClient methods (this = first arg).
            Self::AudioClientQueryInterface
            | Self::AudioClientGetService
            | Self::AudioRenderClientQueryInterface
            | Self::AudioRenderClientGetBuffer
            | Self::AudioRenderClientReleaseBuffer
            | Self::AudioClientIsOffloadCapable
            | Self::AudioClientGetCurrentSharedModeEnginePeriod => 12,
            Self::AudioClientInitialize => 28,
            Self::AudioClientGetBufferSize
            | Self::AudioClientGetStreamLatency
            | Self::AudioClientGetCurrentPadding
            | Self::AudioClientGetMixFormat
            | Self::AudioClientSetEventHandle
            | Self::AudioClientSetClientProperties => 8,
            Self::AudioClientIsFormatSupported => 16,
            Self::AudioClientGetDevicePeriod | Self::AudioClientGetBufferSizeLimits => 12,
            Self::AudioClientStart | Self::AudioClientStop | Self::AudioClientReset => 4,
            Self::AudioClientGetSharedModeEnginePeriod => 24,
            Self::AudioClientInitializeSharedAudioStream => 20,
            // Audio service objects (IAudioClock/volume/session/capture).
            Self::AudioServiceQueryInterface
            | Self::AudioClockGetPosition
            | Self::AudioSimpleVolumeSetMasterVolume
            | Self::AudioSimpleVolumeSetMute
            | Self::AudioStreamVolumeGetChannelVolume
            | Self::AudioStreamVolumeGetAllVolumes
            | Self::AudioSessionControlSetDisplayName
            | Self::AudioSessionControlSetIconPath
            | Self::AudioSessionControlSetGroupingParam
            | Self::AudioCaptureClientReleaseBuffer => 12,
            Self::AudioClockGetFrequency
            | Self::AudioClockGetState
            | Self::AudioSimpleVolumeGetMasterVolume
            | Self::AudioSimpleVolumeGetMute
            | Self::AudioStreamVolumeGetChannelCount
            | Self::AudioSessionControlGetState
            | Self::AudioSessionControlGetDisplayName
            | Self::AudioSessionControlGetIconPath
            | Self::AudioSessionControlGetGroupingParam
            | Self::AudioSessionControlRegisterNotification
            | Self::AudioSessionControlUnregisterNotification
            | Self::AudioSessionControl2GetSessionIdentifier
            | Self::AudioSessionControl2GetSessionInstanceIdentifier
            | Self::AudioSessionControl2GetProcessId
            | Self::AudioSessionControl2SetDuckingPreference
            | Self::AudioCaptureClientGetNextPacketSize => 8,
            Self::AudioStreamVolumeSetChannelVolume => 20,
            Self::AudioStreamVolumeSetAllVolumes => 16,
            Self::AudioSessionControl2IsSystemSoundsSession => 4,
            Self::AudioCaptureClientGetBuffer => 24,
            // XACT3: the factory takes (flags, out-engine); the guest-object
            // vtable methods carry their stdcall argument byte count on the
            // thunk itself (see `crate::xact`).
            Self::Xact3CreateEngine | Self::Xact3CreateEngineWithFlags => 8,
            Self::Xact3Method { x86_arg_bytes, .. } => u64::from(*x86_arg_bytes),
            Self::WebBrowserMethod(method) => method.x86_arg_bytes(),
            // DirectPlay: the guest-object vtable methods carry their stdcall
            // argument byte count on the thunk itself (see `crate::dplay`).
            Self::Dplay8Method { x86_arg_bytes, .. } => u64::from(*x86_arg_bytes),
            Self::DirectPlay8AddressCreate => 12,
            Self::DriverIslandShim { function } => function.x86_arg_bytes(),
            Self::ComMethod(method) => method.x86_arg_bytes(),
            _ => 0,
        }
    }
}
