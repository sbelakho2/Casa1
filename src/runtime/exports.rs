//! Export-table registry (verbatim).

use super::*;

pub fn export_tables() -> BTreeMap<String, Vec<ExportSymbol>> {
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
            ordinal: 118,
            name: Some("GetTickCount64".to_string()),
            target: ExportTarget::Rva(0x1070),
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
            ordinal: 119,
            name: Some("UnhandledExceptionFilter".to_string()),
            target: ExportTarget::Rva(0x1120),
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
            ordinal: 119,
            name: Some("VirtualFree".to_string()),
            target: ExportTarget::Rva(0x1118),
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
        ExportSymbol {
            ordinal: 900,
            name: Some("GenerateConsoleCtrlEvent".to_string()),
            target: ExportTarget::Rva(0x20a0),
        },
    ];

    extend_named_exports(
        &mut kernel32_exports,
        0x0200,
        0x2000,
        &[
            "GetCurrentDirectoryW",
            "GetFullPathNameW",
            "GetFileSize",
            "FlushFileBuffers",
            "MoveFileW",
            "SetFileAttributesW",
            "GetModuleFileNameA",
            "GetModuleFileNameW",
            "CopyFileW",
            "SetEnvironmentVariableW",
            "GetEnvironmentVariableW",
            "GetEnvironmentStringsW",
            "FreeEnvironmentStringsW",
            "GetWindowsDirectoryW",
            "GetTempPathW",
            "GetCommandLineW",
            "GetVersion",
            "VerifyVersionInfoW",
            "SetErrorMode",
            "GetSystemTimeAsFileTime",
            "GetTimeZoneInformation",
            "GetFileInformationByHandle",
            "GetFileAttributesExW",
            "CreateIoCompletionPort",
            "PostQueuedCompletionStatus",
            "GetQueuedCompletionStatus",
            "GetQueuedCompletionStatusEx",
            "CreateEventA",
            "CreateEventW",
            "OpenEventA",
            "OpenEventW",
            "ProcessIdToSessionId",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "TryEnterCriticalSection",
            "SetEvent",
            "ResetEvent",
            "IsDebuggerPresent",
            "InitOnceBeginInitialize",
            "InitOnceComplete",
            "InitOnceExecuteOnce",
            "InitializeSRWLock",
            "AcquireSRWLockExclusive",
            "ReleaseSRWLockExclusive",
            "AcquireSRWLockShared",
            "ReleaseSRWLockShared",
            "TryAcquireSRWLockExclusive",
            "TryAcquireSRWLockShared",
            "WaitForSingleObject",
            "GetCurrentThread",
            "GetCurrentProcess",
            "DuplicateHandle",
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
            "CharUpperW",
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
            "GetDiskFreeSpaceExW",
            "lstrlenW",
            "lstrcpynW",
            "GetExitCodeThread",
            "GetExitCodeProcess",
            "TerminateProcess",
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
            "LoadLibraryExA",
            "LoadLibraryExW",
            "GetModuleHandleW",
        ],
    );
    let mut ole32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("CoInitializeEx".to_string()),
            target: ExportTarget::Rva(0x6000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("CoUninitialize".to_string()),
            target: ExportTarget::Rva(0x6010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("CoCreateInstance".to_string()),
            target: ExportTarget::Rva(0x6020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("CoCreateInstanceEx".to_string()),
            target: ExportTarget::Rva(0x6030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("CoGetClassObject".to_string()),
            target: ExportTarget::Rva(0x6040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("CoRegisterClassObject".to_string()),
            target: ExportTarget::Rva(0x6050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("CoRevokeClassObject".to_string()),
            target: ExportTarget::Rva(0x6060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("CoTaskMemAlloc".to_string()),
            target: ExportTarget::Rva(0x6070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("CoTaskMemFree".to_string()),
            target: ExportTarget::Rva(0x6080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("CoTaskMemRealloc".to_string()),
            target: ExportTarget::Rva(0x6090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("CoCreateGuid".to_string()),
            target: ExportTarget::Rva(0x60a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("StringFromGUID2".to_string()),
            target: ExportTarget::Rva(0x60b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("CLSIDFromString".to_string()),
            target: ExportTarget::Rva(0x60c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("CoInitializeSecurity".to_string()),
            target: ExportTarget::Rva(0x60d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("CoSetProxyBlanket".to_string()),
            target: ExportTarget::Rva(0x60e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("CoCopyProxy".to_string()),
            target: ExportTarget::Rva(0x60f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("CoGetCallContext".to_string()),
            target: ExportTarget::Rva(0x6100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("CoGetApartmentType".to_string()),
            target: ExportTarget::Rva(0x6110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("CoAllowSetForegroundWindow".to_string()),
            target: ExportTarget::Rva(0x6120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("CoDisconnectObject".to_string()),
            target: ExportTarget::Rva(0x6130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("CoLockObjectExternal".to_string()),
            target: ExportTarget::Rva(0x6140),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("CoMarshalInterThreadInterfaceInStream".to_string()),
            target: ExportTarget::Rva(0x6150),
        },
        ExportSymbol {
            ordinal: 23,
            name: Some("CoGetInterfaceAndReleaseStream".to_string()),
            target: ExportTarget::Rva(0x6160),
        },
        ExportSymbol {
            ordinal: 24,
            name: Some("CoInitialize".to_string()),
            target: ExportTarget::Rva(0x6170),
        },
        ExportSymbol {
            ordinal: 25,
            name: Some("OleInitialize".to_string()),
            target: ExportTarget::Rva(0x6180),
        },
        ExportSymbol {
            ordinal: 26,
            name: Some("OleUninitialize".to_string()),
            target: ExportTarget::Rva(0x6190),
        },
        ExportSymbol {
            ordinal: 27,
            name: Some("OleSetMenuDescriptor".to_string()),
            target: ExportTarget::Rva(0x61a0),
        },
        ExportSymbol {
            ordinal: 28,
            name: Some("OleDuplicateData".to_string()),
            target: ExportTarget::Rva(0x61b0),
        },
        ExportSymbol {
            ordinal: 29,
            name: Some("CreateBindCtx".to_string()),
            target: ExportTarget::Rva(0x61c0),
        },
        ExportSymbol {
            ordinal: 30,
            name: Some("MkParseDisplayName".to_string()),
            target: ExportTarget::Rva(0x61d0),
        },
    ];
    ole32_exports.push(ExportSymbol {
        ordinal: 1,
        name: Some("IMoniker".to_string()),
        target: ExportTarget::Rva(0x2a000),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 2,
        name: Some("IPersist".to_string()),
        target: ExportTarget::Rva(0x2a010),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 3,
        name: Some("IStream".to_string()),
        target: ExportTarget::Rva(0x2a020),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 4,
        name: Some("IStorage".to_string()),
        target: ExportTarget::Rva(0x2a030),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 5,
        name: Some("IMalloc".to_string()),
        target: ExportTarget::Rva(0x2a040),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 6,
        name: Some("IDropTarget".to_string()),
        target: ExportTarget::Rva(0x2a050),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 7,
        name: Some("IDataObject".to_string()),
        target: ExportTarget::Rva(0x2a060),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 8,
        name: Some("IOleObject".to_string()),
        target: ExportTarget::Rva(0x2a070),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 9,
        name: Some("IOleInPlaceObject".to_string()),
        target: ExportTarget::Rva(0x2a080),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 10,
        name: Some("IObjectWithSite".to_string()),
        target: ExportTarget::Rva(0x2a090),
    });
    ole32_exports.push(ExportSymbol {
        ordinal: 11,
        name: Some("IServiceProvider".to_string()),
        target: ExportTarget::Rva(0x2a0a0),
    });
    extend_named_exports(
        &mut ole32_exports,
        100,
        0x61e0,
        &[
            "StringFromCLSID",
            "StringFromIID",
            "StringFromGUID2",
            "CoGetInstanceFromFile",
            "CoGetInstanceFromIStorage",
            "CoRegisterMessageFilter",
            "CoRegisterPSClsid",
            "CoDosDateTimeToFileTime",
            "CoFileTimeNow",
            "CoGetCurrentProcess",
            "CoImpersonateClient",
            "CoRevertToSelf",
            "CoResumeClassObjects",
            "CoSuspendClassObjects",
            "CoAddRefServerProcess",
            "CoReleaseServerProcess",
            "CoGetClassObjectFromUrl",
            "CoGetPSClsid",
            "CoGetTreatAsClass",
            "CoInstall",
            "CoIsHandlerConnected",
            "CoLoadLibrary",
            "CoFreeLibrary",
            "CoFreeAllLibraries",
            "CoFreeUnusedLibraries",
            "DllGetClassObject",
            "DllCanUnloadNow",
            "DllRegisterServer",
            "DllUnregisterServer",
            "ProgIDFromCLSID",
            "CLSIDFromProgID",
        ],
    );

    let mut shell32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("SHGetFolderPathW".to_string()),
            target: ExportTarget::Rva(0x7000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("SHGetKnownFolderPath".to_string()),
            target: ExportTarget::Rva(0x7010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("SHGetFileInfoW".to_string()),
            target: ExportTarget::Rva(0x7020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("ShellExecuteW".to_string()),
            target: ExportTarget::Rva(0x7030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("ShellExecuteExW".to_string()),
            target: ExportTarget::Rva(0x7040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("SHParseDisplayName".to_string()),
            target: ExportTarget::Rva(0x7050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("SHCreateItemFromParsingName".to_string()),
            target: ExportTarget::Rva(0x7060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("SHCreateItemFromIDList".to_string()),
            target: ExportTarget::Rva(0x7070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("ILCreateFromPathW".to_string()),
            target: ExportTarget::Rva(0x7080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("ILFree".to_string()),
            target: ExportTarget::Rva(0x7090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("SHGetMalloc".to_string()),
            target: ExportTarget::Rva(0x70a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("SHBrowseForFolderW".to_string()),
            target: ExportTarget::Rva(0x70b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("SHGetPathFromIDListW".to_string()),
            target: ExportTarget::Rva(0x70c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("DragQueryFileW".to_string()),
            target: ExportTarget::Rva(0x70d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("DragFinish".to_string()),
            target: ExportTarget::Rva(0x70e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("DragAcceptFiles".to_string()),
            target: ExportTarget::Rva(0x70f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("ExtractIconW".to_string()),
            target: ExportTarget::Rva(0x7100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("ExtractIconExW".to_string()),
            target: ExportTarget::Rva(0x7110),
        },
        ExportSymbol {
            ordinal: 90,
            name: Some("IPersistFile".to_string()),
            target: ExportTarget::Rva(0x24400),
        },
    ];
    extend_named_exports(
        &mut shell32_exports,
        100,
        0x7120,
        &[
            "SHGetSpecialFolderPathW",
            "SHGetDesktopFolder",
            "SHGetDataFromIDListW",
            "SHBindToParent",
            "SHSimpleIDListFromPath",
            "PathIsNetworkPathW",
            "PathIsDirectoryW",
            "PathFileExistsW",
            "PathFindFileNameW",
            "PathFindExtensionW",
            "PathCombineW",
            "PathAppendW",
            "PathRemoveFileSpecW",
            "PathRelativePathToW",
            "PathMakeUniqueName",
            "SHCreateDirectoryExW",
            "SHFileOperationW",
            "SHChangeNotify",
            "SHUpdateImageW",
            "SHCreateShellItem",
            "RegisterDragDrop",
            "DoDragDrop",
        ],
    );

    let advapi32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("RegOpenKeyExW".to_string()),
            target: ExportTarget::Rva(0x8000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("RegCloseKey".to_string()),
            target: ExportTarget::Rva(0x8010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("RegQueryValueExW".to_string()),
            target: ExportTarget::Rva(0x8020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("RegEnumKeyExW".to_string()),
            target: ExportTarget::Rva(0x8030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("RegEnumValueW".to_string()),
            target: ExportTarget::Rva(0x8040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("RegSetValueExW".to_string()),
            target: ExportTarget::Rva(0x8050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("RegCreateKeyExW".to_string()),
            target: ExportTarget::Rva(0x8060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("RegDeleteKeyW".to_string()),
            target: ExportTarget::Rva(0x8070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("RegDeleteValueW".to_string()),
            target: ExportTarget::Rva(0x8080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("RegQueryInfoKeyW".to_string()),
            target: ExportTarget::Rva(0x8090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("RegFlushKey".to_string()),
            target: ExportTarget::Rva(0x80a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("RegOpenCurrentUser".to_string()),
            target: ExportTarget::Rva(0x80b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("OpenProcessToken".to_string()),
            target: ExportTarget::Rva(0x80c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("OpenThreadToken".to_string()),
            target: ExportTarget::Rva(0x80d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("GetTokenInformation".to_string()),
            target: ExportTarget::Rva(0x80e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("LookupPrivilegeValueW".to_string()),
            target: ExportTarget::Rva(0x80f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("AdjustTokenPrivileges".to_string()),
            target: ExportTarget::Rva(0x8100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("DuplicateTokenEx".to_string()),
            target: ExportTarget::Rva(0x8110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("GetUserNameW".to_string()),
            target: ExportTarget::Rva(0x8120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("GetUserNameA".to_string()),
            target: ExportTarget::Rva(0x8130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("LogonUserW".to_string()),
            target: ExportTarget::Rva(0x8140),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("ImpersonateLoggedOnUser".to_string()),
            target: ExportTarget::Rva(0x8150),
        },
        ExportSymbol {
            ordinal: 23,
            name: Some("RevertToSelf".to_string()),
            target: ExportTarget::Rva(0x8160),
        },
        ExportSymbol {
            ordinal: 24,
            name: Some("AllocateAndInitializeSid".to_string()),
            target: ExportTarget::Rva(0x8170),
        },
        ExportSymbol {
            ordinal: 25,
            name: Some("FreeSid".to_string()),
            target: ExportTarget::Rva(0x8180),
        },
        ExportSymbol {
            ordinal: 26,
            name: Some("CheckTokenMembership".to_string()),
            target: ExportTarget::Rva(0x8190),
        },
        ExportSymbol {
            ordinal: 27,
            name: Some("CryptAcquireContextW".to_string()),
            target: ExportTarget::Rva(0x81a0),
        },
        ExportSymbol {
            ordinal: 28,
            name: Some("CryptReleaseContext".to_string()),
            target: ExportTarget::Rva(0x81b0),
        },
        ExportSymbol {
            ordinal: 29,
            name: Some("CryptGenRandom".to_string()),
            target: ExportTarget::Rva(0x81c0),
        },
        ExportSymbol {
            ordinal: 30,
            name: Some("CryptCreateHash".to_string()),
            target: ExportTarget::Rva(0x81d0),
        },
        ExportSymbol {
            ordinal: 31,
            name: Some("CryptHashData".to_string()),
            target: ExportTarget::Rva(0x81e0),
        },
        ExportSymbol {
            ordinal: 32,
            name: Some("CryptGetHashParam".to_string()),
            target: ExportTarget::Rva(0x81f0),
        },
        ExportSymbol {
            ordinal: 33,
            name: Some("CryptDeriveKey".to_string()),
            target: ExportTarget::Rva(0x8200),
        },
        ExportSymbol {
            ordinal: 34,
            name: Some("CryptEncrypt".to_string()),
            target: ExportTarget::Rva(0x8210),
        },
        ExportSymbol {
            ordinal: 35,
            name: Some("CryptDecrypt".to_string()),
            target: ExportTarget::Rva(0x8220),
        },
        ExportSymbol {
            ordinal: 36,
            name: Some("CryptDestroyKey".to_string()),
            target: ExportTarget::Rva(0x8230),
        },
        ExportSymbol {
            ordinal: 37,
            name: Some("CryptDestroyHash".to_string()),
            target: ExportTarget::Rva(0x8240),
        },
        ExportSymbol {
            ordinal: 38,
            name: Some("EventRegister".to_string()),
            target: ExportTarget::Rva(0x8250),
        },
        ExportSymbol {
            ordinal: 39,
            name: Some("EventUnregister".to_string()),
            target: ExportTarget::Rva(0x8260),
        },
        ExportSymbol {
            ordinal: 40,
            name: Some("EventWrite".to_string()),
            target: ExportTarget::Rva(0x8270),
        },
        ExportSymbol {
            ordinal: 41,
            name: Some("StartServiceW".to_string()),
            target: ExportTarget::Rva(0x8280),
        },
        ExportSymbol {
            ordinal: 42,
            name: Some("OpenSCManagerW".to_string()),
            target: ExportTarget::Rva(0x8290),
        },
        ExportSymbol {
            ordinal: 43,
            name: Some("OpenServiceW".to_string()),
            target: ExportTarget::Rva(0x82a0),
        },
        ExportSymbol {
            ordinal: 44,
            name: Some("ControlService".to_string()),
            target: ExportTarget::Rva(0x82b0),
        },
        ExportSymbol {
            ordinal: 45,
            name: Some("QueryServiceStatus".to_string()),
            target: ExportTarget::Rva(0x82c0),
        },
        ExportSymbol {
            ordinal: 46,
            name: Some("CloseServiceHandle".to_string()),
            target: ExportTarget::Rva(0x82d0),
        },
        ExportSymbol {
            ordinal: 47,
            name: Some("CreateServiceW".to_string()),
            target: ExportTarget::Rva(0x82e0),
        },
        ExportSymbol {
            ordinal: 48,
            name: Some("DeleteService".to_string()),
            target: ExportTarget::Rva(0x82f0),
        },
    ];

    let gdi32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("CreateDCW".to_string()),
            target: ExportTarget::Rva(0x9000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("DeleteDC".to_string()),
            target: ExportTarget::Rva(0x9010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("CreateCompatibleDC".to_string()),
            target: ExportTarget::Rva(0x9020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("CreateCompatibleBitmap".to_string()),
            target: ExportTarget::Rva(0x9030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("CreateDIBSection".to_string()),
            target: ExportTarget::Rva(0x9040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("SelectObject".to_string()),
            target: ExportTarget::Rva(0x9050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("DeleteObject".to_string()),
            target: ExportTarget::Rva(0x9060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("BitBlt".to_string()),
            target: ExportTarget::Rva(0x9070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("StretchBlt".to_string()),
            target: ExportTarget::Rva(0x9080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("GetDC".to_string()),
            target: ExportTarget::Rva(0x9090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("ReleaseDC".to_string()),
            target: ExportTarget::Rva(0x90a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("GetDeviceCaps".to_string()),
            target: ExportTarget::Rva(0x90b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("CreateFontW".to_string()),
            target: ExportTarget::Rva(0x90c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("CreateFontIndirectW".to_string()),
            target: ExportTarget::Rva(0x90d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("GetTextMetricsW".to_string()),
            target: ExportTarget::Rva(0x90e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("GetStockObject".to_string()),
            target: ExportTarget::Rva(0x90f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("GetPixel".to_string()),
            target: ExportTarget::Rva(0x9100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("SetPixel".to_string()),
            target: ExportTarget::Rva(0x9110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("TextOutW".to_string()),
            target: ExportTarget::Rva(0x9120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("GetTextExtentPoint32W".to_string()),
            target: ExportTarget::Rva(0x9130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("DrawTextW".to_string()),
            target: ExportTarget::Rva(0x9140),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("DrawTextExW".to_string()),
            target: ExportTarget::Rva(0x9150),
        },
        ExportSymbol {
            ordinal: 23,
            name: Some("GetGlyphOutlineW".to_string()),
            target: ExportTarget::Rva(0x9160),
        },
        ExportSymbol {
            ordinal: 24,
            name: Some("GetCharWidthW".to_string()),
            target: ExportTarget::Rva(0x9170),
        },
        ExportSymbol {
            ordinal: 25,
            name: Some("CreatePen".to_string()),
            target: ExportTarget::Rva(0x9180),
        },
        ExportSymbol {
            ordinal: 26,
            name: Some("CreateSolidBrush".to_string()),
            target: ExportTarget::Rva(0x9190),
        },
        ExportSymbol {
            ordinal: 27,
            name: Some("MoveToEx".to_string()),
            target: ExportTarget::Rva(0x91a0),
        },
        ExportSymbol {
            ordinal: 28,
            name: Some("LineTo".to_string()),
            target: ExportTarget::Rva(0x91b0),
        },
        ExportSymbol {
            ordinal: 29,
            name: Some("Rectangle".to_string()),
            target: ExportTarget::Rva(0x91c0),
        },
        ExportSymbol {
            ordinal: 30,
            name: Some("Ellipse".to_string()),
            target: ExportTarget::Rva(0x91d0),
        },
        ExportSymbol {
            ordinal: 31,
            name: Some("FillRect".to_string()),
            target: ExportTarget::Rva(0x91e0),
        },
        ExportSymbol {
            ordinal: 32,
            name: Some("FrameRect".to_string()),
            target: ExportTarget::Rva(0x91f0),
        },
        ExportSymbol {
            ordinal: 33,
            name: Some("InvertRect".to_string()),
            target: ExportTarget::Rva(0x9200),
        },
        ExportSymbol {
            ordinal: 34,
            name: Some("SetBkMode".to_string()),
            target: ExportTarget::Rva(0x9210),
        },
        ExportSymbol {
            ordinal: 35,
            name: Some("SetBkColor".to_string()),
            target: ExportTarget::Rva(0x9220),
        },
        ExportSymbol {
            ordinal: 36,
            name: Some("SetTextColor".to_string()),
            target: ExportTarget::Rva(0x9230),
        },
        ExportSymbol {
            ordinal: 37,
            name: Some("GetRgnBox".to_string()),
            target: ExportTarget::Rva(0x9240),
        },
        ExportSymbol {
            ordinal: 38,
            name: Some("CreateRectRgn".to_string()),
            target: ExportTarget::Rva(0x9250),
        },
        ExportSymbol {
            ordinal: 39,
            name: Some("CreateRoundRectRgn".to_string()),
            target: ExportTarget::Rva(0x9260),
        },
        ExportSymbol {
            ordinal: 40,
            name: Some("CombineRgn".to_string()),
            target: ExportTarget::Rva(0x9270),
        },
        ExportSymbol {
            ordinal: 41,
            name: Some("GetObjectW".to_string()),
            target: ExportTarget::Rva(0x9280),
        },
        ExportSymbol {
            ordinal: 42,
            name: Some("AlphaBlend".to_string()),
            target: ExportTarget::Rva(0x9290),
        },
        ExportSymbol {
            ordinal: 43,
            name: Some("TransparentBlt".to_string()),
            target: ExportTarget::Rva(0x92a0),
        },
        ExportSymbol {
            ordinal: 44,
            name: Some("GdiFlush".to_string()),
            target: ExportTarget::Rva(0x92b0),
        },
        ExportSymbol {
            ordinal: 45,
            name: Some("GdiComment".to_string()),
            target: ExportTarget::Rva(0x92c0),
        },
    ];

    let gdiplus_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("GdiplusStartup".to_string()),
            target: ExportTarget::Rva(0x9300),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("GdiplusShutdown".to_string()),
            target: ExportTarget::Rva(0x9310),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("GdipCreateBitmapFromHBITMAP".to_string()),
            target: ExportTarget::Rva(0x9320),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("GdipCreateBitmapFromFile".to_string()),
            target: ExportTarget::Rva(0x9330),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("GdipCreateBitmapFromStream".to_string()),
            target: ExportTarget::Rva(0x9340),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("GdipCreateBitmapFromScan0".to_string()),
            target: ExportTarget::Rva(0x9350),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("GdipCreateHICONFromBitmap".to_string()),
            target: ExportTarget::Rva(0x9360),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("GdipCreateHBITMAPFromBitmap".to_string()),
            target: ExportTarget::Rva(0x9370),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("GdipCreateImageFromFile".to_string()),
            target: ExportTarget::Rva(0x9380),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("GdipImageForceValidation".to_string()),
            target: ExportTarget::Rva(0x9390),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("GdipDrawImage".to_string()),
            target: ExportTarget::Rva(0x93a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("GdipDrawImageRect".to_string()),
            target: ExportTarget::Rva(0x93b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("GdipDrawImageRectRect".to_string()),
            target: ExportTarget::Rva(0x93c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("GdipGetImageWidth".to_string()),
            target: ExportTarget::Rva(0x93d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("GdipGetImageHeight".to_string()),
            target: ExportTarget::Rva(0x93e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("GdipGetImagePixelFormat".to_string()),
            target: ExportTarget::Rva(0x93f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("GdipGetImageType".to_string()),
            target: ExportTarget::Rva(0x9400),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("GdipGetImageRawFormat".to_string()),
            target: ExportTarget::Rva(0x9410),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("GdipDisposeImage".to_string()),
            target: ExportTarget::Rva(0x9420),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("GdipCloneImage".to_string()),
            target: ExportTarget::Rva(0x9430),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("GdipSaveImageToFile".to_string()),
            target: ExportTarget::Rva(0x9440),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("GdipSaveImageToStream".to_string()),
            target: ExportTarget::Rva(0x9450),
        },
        ExportSymbol {
            ordinal: 23,
            name: Some("GdipCreateGraphics".to_string()),
            target: ExportTarget::Rva(0x9460),
        },
        ExportSymbol {
            ordinal: 24,
            name: Some("GdipDeleteGraphics".to_string()),
            target: ExportTarget::Rva(0x9470),
        },
        ExportSymbol {
            ordinal: 25,
            name: Some("GdipDrawString".to_string()),
            target: ExportTarget::Rva(0x9480),
        },
        ExportSymbol {
            ordinal: 26,
            name: Some("GdipMeasureString".to_string()),
            target: ExportTarget::Rva(0x9490),
        },
        ExportSymbol {
            ordinal: 27,
            name: Some("GdipCreateFont".to_string()),
            target: ExportTarget::Rva(0x94a0),
        },
        ExportSymbol {
            ordinal: 28,
            name: Some("GdipDeleteFont".to_string()),
            target: ExportTarget::Rva(0x94b0),
        },
        ExportSymbol {
            ordinal: 29,
            name: Some("GdipGetFontHeight".to_string()),
            target: ExportTarget::Rva(0x94c0),
        },
        ExportSymbol {
            ordinal: 30,
            name: Some("GdipCreateFontFamilyFromName".to_string()),
            target: ExportTarget::Rva(0x94d0),
        },
        ExportSymbol {
            ordinal: 31,
            name: Some("GdipDeleteFontFamily".to_string()),
            target: ExportTarget::Rva(0x94e0),
        },
        ExportSymbol {
            ordinal: 32,
            name: Some("GdipCreateSolidFill".to_string()),
            target: ExportTarget::Rva(0x94f0),
        },
        ExportSymbol {
            ordinal: 33,
            name: Some("GdipCreateLineBrush".to_string()),
            target: ExportTarget::Rva(0x9500),
        },
        ExportSymbol {
            ordinal: 34,
            name: Some("GdipDeleteBrush".to_string()),
            target: ExportTarget::Rva(0x9510),
        },
        ExportSymbol {
            ordinal: 35,
            name: Some("GdipFillRectangle".to_string()),
            target: ExportTarget::Rva(0x9520),
        },
        ExportSymbol {
            ordinal: 36,
            name: Some("GdipFillEllipse".to_string()),
            target: ExportTarget::Rva(0x9530),
        },
        ExportSymbol {
            ordinal: 37,
            name: Some("GdipCreatePen1".to_string()),
            target: ExportTarget::Rva(0x9540),
        },
        ExportSymbol {
            ordinal: 38,
            name: Some("GdipDeletePen".to_string()),
            target: ExportTarget::Rva(0x9550),
        },
        ExportSymbol {
            ordinal: 39,
            name: Some("GdipDrawLine".to_string()),
            target: ExportTarget::Rva(0x9560),
        },
        ExportSymbol {
            ordinal: 40,
            name: Some("GdipDrawRectangle".to_string()),
            target: ExportTarget::Rva(0x9570),
        },
        ExportSymbol {
            ordinal: 41,
            name: Some("GdipDrawEllipse".to_string()),
            target: ExportTarget::Rva(0x9580),
        },
        ExportSymbol {
            ordinal: 42,
            name: Some("GdipCreatePath".to_string()),
            target: ExportTarget::Rva(0x9590),
        },
        ExportSymbol {
            ordinal: 43,
            name: Some("GdipDeletePath".to_string()),
            target: ExportTarget::Rva(0x95a0),
        },
        ExportSymbol {
            ordinal: 44,
            name: Some("GdipAddPathLine".to_string()),
            target: ExportTarget::Rva(0x95b0),
        },
        ExportSymbol {
            ordinal: 45,
            name: Some("GdipAddPathRectangle".to_string()),
            target: ExportTarget::Rva(0x95c0),
        },
        ExportSymbol {
            ordinal: 46,
            name: Some("GdipDrawPath".to_string()),
            target: ExportTarget::Rva(0x95d0),
        },
        ExportSymbol {
            ordinal: 47,
            name: Some("GdipFillPath".to_string()),
            target: ExportTarget::Rva(0x95e0),
        },
        ExportSymbol {
            ordinal: 48,
            name: Some("GdipSetSmoothingMode".to_string()),
            target: ExportTarget::Rva(0x95f0),
        },
        ExportSymbol {
            ordinal: 49,
            name: Some("GdipSetInterpolationMode".to_string()),
            target: ExportTarget::Rva(0x9600),
        },
        ExportSymbol {
            ordinal: 50,
            name: Some("GdipGetClip".to_string()),
            target: ExportTarget::Rva(0x9610),
        },
        ExportSymbol {
            ordinal: 51,
            name: Some("GdipSetClipRect".to_string()),
            target: ExportTarget::Rva(0x9620),
        },
        ExportSymbol {
            ordinal: 52,
            name: Some("GdipSetClipPath".to_string()),
            target: ExportTarget::Rva(0x9630),
        },
        ExportSymbol {
            ordinal: 53,
            name: Some("GdipResetClip".to_string()),
            target: ExportTarget::Rva(0x9640),
        },
        ExportSymbol {
            ordinal: 54,
            name: Some("GdipCreateBitmapFromGdiDib".to_string()),
            target: ExportTarget::Rva(0x9650),
        },
        // ── Phase 2.7 extended exports ──────────────────────────────────────────
        ExportSymbol {
            ordinal: 55,
            name: Some("GdipCreateFromHDC".to_string()),
            target: ExportTarget::Rva(0x9660),
        },
        ExportSymbol {
            ordinal: 56,
            name: Some("GdipDrawLines".to_string()),
            target: ExportTarget::Rva(0x9670),
        },
        ExportSymbol {
            ordinal: 57,
            name: Some("GdipDrawPie".to_string()),
            target: ExportTarget::Rva(0x9680),
        },
        ExportSymbol {
            ordinal: 58,
            name: Some("GdipFillPie".to_string()),
            target: ExportTarget::Rva(0x9690),
        },
        ExportSymbol {
            ordinal: 59,
            name: Some("GdipDrawPolygon".to_string()),
            target: ExportTarget::Rva(0x96a0),
        },
        ExportSymbol {
            ordinal: 60,
            name: Some("GdipFillPolygon".to_string()),
            target: ExportTarget::Rva(0x96b0),
        },
        ExportSymbol {
            ordinal: 61,
            name: Some("GdipDrawArc".to_string()),
            target: ExportTarget::Rva(0x96c0),
        },
        ExportSymbol {
            ordinal: 62,
            name: Some("GdipDrawCurve".to_string()),
            target: ExportTarget::Rva(0x96d0),
        },
        ExportSymbol {
            ordinal: 63,
            name: Some("GdipDrawClosedCurve".to_string()),
            target: ExportTarget::Rva(0x96e0),
        },
        ExportSymbol {
            ordinal: 64,
            name: Some("GdipCreatePen2".to_string()),
            target: ExportTarget::Rva(0x96f0),
        },
        ExportSymbol {
            ordinal: 65,
            name: Some("GdipSetPenWidth".to_string()),
            target: ExportTarget::Rva(0x9700),
        },
        ExportSymbol {
            ordinal: 66,
            name: Some("GdipGetPenWidth".to_string()),
            target: ExportTarget::Rva(0x9710),
        },
        ExportSymbol {
            ordinal: 67,
            name: Some("GdipSetPenColor".to_string()),
            target: ExportTarget::Rva(0x9720),
        },
        ExportSymbol {
            ordinal: 68,
            name: Some("GdipGetPenColor".to_string()),
            target: ExportTarget::Rva(0x9730),
        },
        ExportSymbol {
            ordinal: 69,
            name: Some("GdipSetPenDashStyle".to_string()),
            target: ExportTarget::Rva(0x9740),
        },
        ExportSymbol {
            ordinal: 70,
            name: Some("GdipGetPenDashStyle".to_string()),
            target: ExportTarget::Rva(0x9750),
        },
        ExportSymbol {
            ordinal: 71,
            name: Some("GdipSetPenLineJoin".to_string()),
            target: ExportTarget::Rva(0x9760),
        },
        ExportSymbol {
            ordinal: 72,
            name: Some("GdipSetPenStartCap".to_string()),
            target: ExportTarget::Rva(0x9770),
        },
        ExportSymbol {
            ordinal: 73,
            name: Some("GdipSetPenEndCap".to_string()),
            target: ExportTarget::Rva(0x9780),
        },
        ExportSymbol {
            ordinal: 74,
            name: Some("GdipCreateTextureBrush".to_string()),
            target: ExportTarget::Rva(0x9790),
        },
        ExportSymbol {
            ordinal: 75,
            name: Some("GdipAddPathEllipse".to_string()),
            target: ExportTarget::Rva(0x97a0),
        },
        ExportSymbol {
            ordinal: 76,
            name: Some("GdipAddPathArc".to_string()),
            target: ExportTarget::Rva(0x97b0),
        },
        ExportSymbol {
            ordinal: 77,
            name: Some("GdipAddPathBezier".to_string()),
            target: ExportTarget::Rva(0x97c0),
        },
        ExportSymbol {
            ordinal: 78,
            name: Some("GdipClosePathFigure".to_string()),
            target: ExportTarget::Rva(0x97d0),
        },
        ExportSymbol {
            ordinal: 79,
            name: Some("GdipStartPathFigure".to_string()),
            target: ExportTarget::Rva(0x97e0),
        },
        ExportSymbol {
            ordinal: 80,
            name: Some("GdipSetPathFillMode".to_string()),
            target: ExportTarget::Rva(0x97f0),
        },
        ExportSymbol {
            ordinal: 81,
            name: Some("GdipCreateMatrix".to_string()),
            target: ExportTarget::Rva(0x9800),
        },
        ExportSymbol {
            ordinal: 82,
            name: Some("GdipDeleteMatrix".to_string()),
            target: ExportTarget::Rva(0x9810),
        },
        ExportSymbol {
            ordinal: 83,
            name: Some("GdipSetMatrixElements".to_string()),
            target: ExportTarget::Rva(0x9820),
        },
        ExportSymbol {
            ordinal: 84,
            name: Some("GdipGetMatrixElements".to_string()),
            target: ExportTarget::Rva(0x9830),
        },
        ExportSymbol {
            ordinal: 85,
            name: Some("GdipTranslateMatrix".to_string()),
            target: ExportTarget::Rva(0x9840),
        },
        ExportSymbol {
            ordinal: 86,
            name: Some("GdipRotateMatrix".to_string()),
            target: ExportTarget::Rva(0x9850),
        },
        ExportSymbol {
            ordinal: 87,
            name: Some("GdipScaleMatrix".to_string()),
            target: ExportTarget::Rva(0x9860),
        },
        ExportSymbol {
            ordinal: 88,
            name: Some("GdipInvertMatrix".to_string()),
            target: ExportTarget::Rva(0x9870),
        },
        ExportSymbol {
            ordinal: 89,
            name: Some("GdipMultiplyMatrix".to_string()),
            target: ExportTarget::Rva(0x9880),
        },
        ExportSymbol {
            ordinal: 90,
            name: Some("GdipSetWorldTransform".to_string()),
            target: ExportTarget::Rva(0x9890),
        },
        ExportSymbol {
            ordinal: 91,
            name: Some("GdipResetWorldTransform".to_string()),
            target: ExportTarget::Rva(0x98a0),
        },
        ExportSymbol {
            ordinal: 92,
            name: Some("GdipGetWorldTransform".to_string()),
            target: ExportTarget::Rva(0x98b0),
        },
        ExportSymbol {
            ordinal: 93,
            name: Some("GdipSetClipRegion".to_string()),
            target: ExportTarget::Rva(0x98c0),
        },
        ExportSymbol {
            ordinal: 94,
            name: Some("GdipGetClipBounds".to_string()),
            target: ExportTarget::Rva(0x98d0),
        },
        ExportSymbol {
            ordinal: 95,
            name: Some("GdipSaveGraphics".to_string()),
            target: ExportTarget::Rva(0x98e0),
        },
        ExportSymbol {
            ordinal: 96,
            name: Some("GdipRestoreGraphics".to_string()),
            target: ExportTarget::Rva(0x98f0),
        },
        ExportSymbol {
            ordinal: 97,
            name: Some("GdipBeginContainer".to_string()),
            target: ExportTarget::Rva(0x9900),
        },
        ExportSymbol {
            ordinal: 98,
            name: Some("GdipEndContainer".to_string()),
            target: ExportTarget::Rva(0x9910),
        },
        ExportSymbol {
            ordinal: 99,
            name: Some("GdipCreateBitmapFromGraphics".to_string()),
            target: ExportTarget::Rva(0x9920),
        },
        ExportSymbol {
            ordinal: 100,
            name: Some("GdipBitmapGetPixel".to_string()),
            target: ExportTarget::Rva(0x9930),
        },
        ExportSymbol {
            ordinal: 101,
            name: Some("GdipBitmapSetPixel".to_string()),
            target: ExportTarget::Rva(0x9940),
        },
        ExportSymbol {
            ordinal: 102,
            name: Some("GdipBitmapLockBits".to_string()),
            target: ExportTarget::Rva(0x9950),
        },
        ExportSymbol {
            ordinal: 103,
            name: Some("GdipBitmapUnlockBits".to_string()),
            target: ExportTarget::Rva(0x9960),
        },
        ExportSymbol {
            ordinal: 104,
            name: Some("GdipSetTextRenderingHint".to_string()),
            target: ExportTarget::Rva(0x9970),
        },
        ExportSymbol {
            ordinal: 105,
            name: Some("GdipMeasureCharacterRanges".to_string()),
            target: ExportTarget::Rva(0x9980),
        },
        ExportSymbol {
            ordinal: 106,
            name: Some("GdipCreateImageAttributes".to_string()),
            target: ExportTarget::Rva(0x9990),
        },
        ExportSymbol {
            ordinal: 107,
            name: Some("GdipDisposeImageAttributes".to_string()),
            target: ExportTarget::Rva(0x99a0),
        },
        ExportSymbol {
            ordinal: 108,
            name: Some("GdipSetImageAttributesColorKeys".to_string()),
            target: ExportTarget::Rva(0x99b0),
        },
        ExportSymbol {
            ordinal: 109,
            name: Some("GdipSetImageAttributesColorMatrix".to_string()),
            target: ExportTarget::Rva(0x99c0),
        },
        ExportSymbol {
            ordinal: 110,
            name: Some("GdipGetSmoothingMode".to_string()),
            target: ExportTarget::Rva(0x99d0),
        },
        ExportSymbol {
            ordinal: 111,
            name: Some("GdipSetCompositingMode".to_string()),
            target: ExportTarget::Rva(0x99e0),
        },
        ExportSymbol {
            ordinal: 112,
            name: Some("GdipGetCompositingMode".to_string()),
            target: ExportTarget::Rva(0x99f0),
        },
        ExportSymbol {
            ordinal: 113,
            name: Some("GdipSetCompositingQuality".to_string()),
            target: ExportTarget::Rva(0x9a00),
        },
        ExportSymbol {
            ordinal: 114,
            name: Some("GdipGetCompositingQuality".to_string()),
            target: ExportTarget::Rva(0x9a10),
        },
        ExportSymbol {
            ordinal: 115,
            name: Some("GdipGetInterpolationMode".to_string()),
            target: ExportTarget::Rva(0x9a20),
        },
        ExportSymbol {
            ordinal: 116,
            name: Some("GdipSetPixelOffsetMode".to_string()),
            target: ExportTarget::Rva(0x9a30),
        },
        ExportSymbol {
            ordinal: 117,
            name: Some("GdipGetPixelOffsetMode".to_string()),
            target: ExportTarget::Rva(0x9a40),
        },
        ExportSymbol {
            ordinal: 118,
            name: Some("GdipFillRegion".to_string()),
            target: ExportTarget::Rva(0x9a50),
        },
    ];

    let ws2_32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("WSAStartup".to_string()),
            target: ExportTarget::Rva(0xa000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("WSACleanup".to_string()),
            target: ExportTarget::Rva(0xa010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("socket".to_string()),
            target: ExportTarget::Rva(0xa020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("bind".to_string()),
            target: ExportTarget::Rva(0xa030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("listen".to_string()),
            target: ExportTarget::Rva(0xa040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("accept".to_string()),
            target: ExportTarget::Rva(0xa050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("connect".to_string()),
            target: ExportTarget::Rva(0xa060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("send".to_string()),
            target: ExportTarget::Rva(0xa070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("recv".to_string()),
            target: ExportTarget::Rva(0xa080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("closesocket".to_string()),
            target: ExportTarget::Rva(0xa090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("setsockopt".to_string()),
            target: ExportTarget::Rva(0xa0a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("getsockopt".to_string()),
            target: ExportTarget::Rva(0xa0b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("ioctlsocket".to_string()),
            target: ExportTarget::Rva(0xa0c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("gethostbyname".to_string()),
            target: ExportTarget::Rva(0xa0d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("gethostbyaddr".to_string()),
            target: ExportTarget::Rva(0xa0e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("getaddrinfo".to_string()),
            target: ExportTarget::Rva(0xa0f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("freeaddrinfo".to_string()),
            target: ExportTarget::Rva(0xa100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("getnameinfo".to_string()),
            target: ExportTarget::Rva(0xa110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("WSAGetLastError".to_string()),
            target: ExportTarget::Rva(0xa120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("WSASocketW".to_string()),
            target: ExportTarget::Rva(0xa130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("WSASend".to_string()),
            target: ExportTarget::Rva(0xa140),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("WSARecv".to_string()),
            target: ExportTarget::Rva(0xa150),
        },
        ExportSymbol {
            ordinal: 23,
            name: Some("WSAPoll".to_string()),
            target: ExportTarget::Rva(0xa160),
        },
        ExportSymbol {
            ordinal: 24,
            name: Some("WSAConnect".to_string()),
            target: ExportTarget::Rva(0xa170),
        },
        ExportSymbol {
            ordinal: 25,
            name: Some("WSAAccept".to_string()),
            target: ExportTarget::Rva(0xa180),
        },
        ExportSymbol {
            ordinal: 26,
            name: Some("htonl".to_string()),
            target: ExportTarget::Rva(0xa190),
        },
        ExportSymbol {
            ordinal: 27,
            name: Some("htons".to_string()),
            target: ExportTarget::Rva(0xa1a0),
        },
        ExportSymbol {
            ordinal: 28,
            name: Some("ntohl".to_string()),
            target: ExportTarget::Rva(0xa1b0),
        },
        ExportSymbol {
            ordinal: 29,
            name: Some("ntohs".to_string()),
            target: ExportTarget::Rva(0xa1c0),
        },
        ExportSymbol {
            ordinal: 30,
            name: Some("inet_addr".to_string()),
            target: ExportTarget::Rva(0xa1d0),
        },
        ExportSymbol {
            ordinal: 31,
            name: Some("inet_ntoa".to_string()),
            target: ExportTarget::Rva(0xa1e0),
        },
        ExportSymbol {
            ordinal: 32,
            name: Some("select".to_string()),
            target: ExportTarget::Rva(0xa1f0),
        },
        ExportSymbol {
            ordinal: 33,
            name: Some("shutdown".to_string()),
            target: ExportTarget::Rva(0xa200),
        },
        ExportSymbol {
            ordinal: 34,
            name: Some("gethostname".to_string()),
            target: ExportTarget::Rva(0xa210),
        },
        ExportSymbol {
            ordinal: 35,
            name: Some("getprotobyname".to_string()),
            target: ExportTarget::Rva(0xa220),
        },
        ExportSymbol {
            ordinal: 36,
            name: Some("getservbyname".to_string()),
            target: ExportTarget::Rva(0xa230),
        },
        ExportSymbol {
            ordinal: 37,
            name: Some("WSASendTo".to_string()),
            target: ExportTarget::Rva(0xa240),
        },
        ExportSymbol {
            ordinal: 38,
            name: Some("WSARecvFrom".to_string()),
            target: ExportTarget::Rva(0xa250),
        },
        ExportSymbol {
            ordinal: 39,
            name: Some("WSADuplicateSocketW".to_string()),
            target: ExportTarget::Rva(0xa260),
        },
        ExportSymbol {
            ordinal: 40,
            name: Some("WSAIoctl".to_string()),
            target: ExportTarget::Rva(0xa270),
        },
        ExportSymbol {
            ordinal: 41,
            name: Some("WSASetLastError".to_string()),
            target: ExportTarget::Rva(0xa280),
        },
        ExportSymbol {
            ordinal: 42,
            name: Some("__WSAFDIsSet".to_string()),
            target: ExportTarget::Rva(0xa290),
        },
    ];

    let winmm_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("waveOutOpen".to_string()),
            target: ExportTarget::Rva(0xb000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("waveOutClose".to_string()),
            target: ExportTarget::Rva(0xb010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("waveOutPrepareHeader".to_string()),
            target: ExportTarget::Rva(0xb020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("waveOutUnprepareHeader".to_string()),
            target: ExportTarget::Rva(0xb030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("waveOutWrite".to_string()),
            target: ExportTarget::Rva(0xb040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("waveOutReset".to_string()),
            target: ExportTarget::Rva(0xb050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("waveOutGetVolume".to_string()),
            target: ExportTarget::Rva(0xb060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("waveOutSetVolume".to_string()),
            target: ExportTarget::Rva(0xb070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("waveOutGetDevCapsW".to_string()),
            target: ExportTarget::Rva(0xb080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("waveOutGetNumDevs".to_string()),
            target: ExportTarget::Rva(0xb090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("waveInOpen".to_string()),
            target: ExportTarget::Rva(0xb0a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("waveInClose".to_string()),
            target: ExportTarget::Rva(0xb0b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("waveInPrepareHeader".to_string()),
            target: ExportTarget::Rva(0xb0c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("waveInUnprepareHeader".to_string()),
            target: ExportTarget::Rva(0xb0d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("waveInAddBuffer".to_string()),
            target: ExportTarget::Rva(0xb0e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("waveInStart".to_string()),
            target: ExportTarget::Rva(0xb0f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("waveInStop".to_string()),
            target: ExportTarget::Rva(0xb100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("waveInGetDevCapsW".to_string()),
            target: ExportTarget::Rva(0xb110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("waveInGetNumDevs".to_string()),
            target: ExportTarget::Rva(0xb120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("midiOutOpen".to_string()),
            target: ExportTarget::Rva(0xb130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("midiOutClose".to_string()),
            target: ExportTarget::Rva(0xb140),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("midiOutShortMsg".to_string()),
            target: ExportTarget::Rva(0xb150),
        },
        ExportSymbol {
            ordinal: 23,
            name: Some("midiOutLongMsg".to_string()),
            target: ExportTarget::Rva(0xb160),
        },
        ExportSymbol {
            ordinal: 24,
            name: Some("midiOutReset".to_string()),
            target: ExportTarget::Rva(0xb170),
        },
        ExportSymbol {
            ordinal: 25,
            name: Some("midiOutGetDevCapsW".to_string()),
            target: ExportTarget::Rva(0xb180),
        },
        ExportSymbol {
            ordinal: 26,
            name: Some("midiOutGetNumDevs".to_string()),
            target: ExportTarget::Rva(0xb190),
        },
        ExportSymbol {
            ordinal: 27,
            name: Some("midiInOpen".to_string()),
            target: ExportTarget::Rva(0xb1a0),
        },
        ExportSymbol {
            ordinal: 28,
            name: Some("midiInClose".to_string()),
            target: ExportTarget::Rva(0xb1b0),
        },
        ExportSymbol {
            ordinal: 29,
            name: Some("midiInStart".to_string()),
            target: ExportTarget::Rva(0xb1c0),
        },
        ExportSymbol {
            ordinal: 30,
            name: Some("midiInStop".to_string()),
            target: ExportTarget::Rva(0xb1d0),
        },
        ExportSymbol {
            ordinal: 31,
            name: Some("midiInReset".to_string()),
            target: ExportTarget::Rva(0xb1e0),
        },
        ExportSymbol {
            ordinal: 32,
            name: Some("timeGetTime".to_string()),
            target: ExportTarget::Rva(0xb1f0),
        },
        ExportSymbol {
            ordinal: 33,
            name: Some("timeBeginPeriod".to_string()),
            target: ExportTarget::Rva(0xb200),
        },
        ExportSymbol {
            ordinal: 34,
            name: Some("timeEndPeriod".to_string()),
            target: ExportTarget::Rva(0xb210),
        },
        ExportSymbol {
            ordinal: 35,
            name: Some("PlaySoundW".to_string()),
            target: ExportTarget::Rva(0xb220),
        },
        ExportSymbol {
            ordinal: 36,
            name: Some("mmioOpenW".to_string()),
            target: ExportTarget::Rva(0xb230),
        },
        ExportSymbol {
            ordinal: 37,
            name: Some("mmioClose".to_string()),
            target: ExportTarget::Rva(0xb240),
        },
        ExportSymbol {
            ordinal: 38,
            name: Some("mmioRead".to_string()),
            target: ExportTarget::Rva(0xb250),
        },
        ExportSymbol {
            ordinal: 39,
            name: Some("mmioWrite".to_string()),
            target: ExportTarget::Rva(0xb260),
        },
        ExportSymbol {
            ordinal: 40,
            name: Some("mmioAscend".to_string()),
            target: ExportTarget::Rva(0xb270),
        },
        ExportSymbol {
            ordinal: 41,
            name: Some("mmioDescend".to_string()),
            target: ExportTarget::Rva(0xb280),
        },
        ExportSymbol {
            ordinal: 42,
            name: Some("mmioCreateChunk".to_string()),
            target: ExportTarget::Rva(0xb290),
        },
        ExportSymbol {
            ordinal: 43,
            name: Some("mmioStringToFOURCCW".to_string()),
            target: ExportTarget::Rva(0xb2a0),
        },
    ];

    let crypt32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("CertOpenSystemStoreW".to_string()),
            target: ExportTarget::Rva(0xc000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("CertCloseStore".to_string()),
            target: ExportTarget::Rva(0xc010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("CertFindCertificateInStore".to_string()),
            target: ExportTarget::Rva(0xc020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("CertGetNameStringW".to_string()),
            target: ExportTarget::Rva(0xc030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("CertFreeCertificateContext".to_string()),
            target: ExportTarget::Rva(0xc040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("CertCreateCertificateContext".to_string()),
            target: ExportTarget::Rva(0xc050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("CertDuplicateCertificateContext".to_string()),
            target: ExportTarget::Rva(0xc060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("CertGetCertificateChain".to_string()),
            target: ExportTarget::Rva(0xc070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("CertVerifyCertificateChainPolicy".to_string()),
            target: ExportTarget::Rva(0xc080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("CertOpenStore".to_string()),
            target: ExportTarget::Rva(0xc090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("CertEnumCertificatesInStore".to_string()),
            target: ExportTarget::Rva(0xc0a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("CertAddCertificateContextToStore".to_string()),
            target: ExportTarget::Rva(0xc0b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("CertDeleteCertificateFromStore".to_string()),
            target: ExportTarget::Rva(0xc0c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("CryptAcquireCertificatePrivateKey".to_string()),
            target: ExportTarget::Rva(0xc0d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("PFXImportCertStore".to_string()),
            target: ExportTarget::Rva(0xc0e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("PFXIsPFXBlob".to_string()),
            target: ExportTarget::Rva(0xc0f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("CertFindExtension".to_string()),
            target: ExportTarget::Rva(0xc100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("CertGetIntendedKeyUsage".to_string()),
            target: ExportTarget::Rva(0xc110),
        },
    ];

    let setupapi_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("SetupDiGetClassDevsW".to_string()),
            target: ExportTarget::Rva(0xd000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("SetupDiDestroyDeviceInfoList".to_string()),
            target: ExportTarget::Rva(0xd010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("SetupDiEnumDeviceInfo".to_string()),
            target: ExportTarget::Rva(0xd020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("SetupDiGetDeviceInstanceIdW".to_string()),
            target: ExportTarget::Rva(0xd030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("SetupDiGetDeviceRegistryPropertyW".to_string()),
            target: ExportTarget::Rva(0xd040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("SetupDiOpenDeviceInfoW".to_string()),
            target: ExportTarget::Rva(0xd050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("SetupDiSetDeviceRegistryPropertyW".to_string()),
            target: ExportTarget::Rva(0xd060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("SetupDiCallClassInstaller".to_string()),
            target: ExportTarget::Rva(0xd070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("SetupDiGetClassDescriptionW".to_string()),
            target: ExportTarget::Rva(0xd080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("SetupDiBuildDriverInfoList".to_string()),
            target: ExportTarget::Rva(0xd090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("SetupDiDestroyDriverInfoList".to_string()),
            target: ExportTarget::Rva(0xd0a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("SetupDiEnumDriverInfoW".to_string()),
            target: ExportTarget::Rva(0xd0b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("SetupDiGetSelectedDriverW".to_string()),
            target: ExportTarget::Rva(0xd0c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("SetupDiInstallDevice".to_string()),
            target: ExportTarget::Rva(0xd0d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("SetupDiUninstallDevice".to_string()),
            target: ExportTarget::Rva(0xd0e0),
        },
    ];

    let iphlpapi_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("GetAdaptersInfo".to_string()),
            target: ExportTarget::Rva(0xe000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("GetAdaptersAddresses".to_string()),
            target: ExportTarget::Rva(0xe010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("GetIpForwardTable".to_string()),
            target: ExportTarget::Rva(0xe020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("GetNetworkParams".to_string()),
            target: ExportTarget::Rva(0xe030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("GetIfEntry".to_string()),
            target: ExportTarget::Rva(0xe040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("GetIfTable".to_string()),
            target: ExportTarget::Rva(0xe050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("GetIpAddrTable".to_string()),
            target: ExportTarget::Rva(0xe060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("GetRTTAndHopCount".to_string()),
            target: ExportTarget::Rva(0xe070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("GetBestInterface".to_string()),
            target: ExportTarget::Rva(0xe080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("GetBestRoute".to_string()),
            target: ExportTarget::Rva(0xe090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("NotifyAddrChange".to_string()),
            target: ExportTarget::Rva(0xe0a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("NotifyRouteChange".to_string()),
            target: ExportTarget::Rva(0xe0b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("CancelMibChangeNotify2".to_string()),
            target: ExportTarget::Rva(0xe0c0),
        },
    ];

    let comctl32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("InitCommonControlsEx".to_string()),
            target: ExportTarget::Rva(0xf000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("InitCommonControls".to_string()),
            target: ExportTarget::Rva(0xf010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("ImageList_Create".to_string()),
            target: ExportTarget::Rva(0xf020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("ImageList_Destroy".to_string()),
            target: ExportTarget::Rva(0xf030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("ImageList_GetImageCount".to_string()),
            target: ExportTarget::Rva(0xf040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("ImageList_SetImageCount".to_string()),
            target: ExportTarget::Rva(0xf050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("ImageList_Add".to_string()),
            target: ExportTarget::Rva(0xf060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("ImageList_ReplaceIcon".to_string()),
            target: ExportTarget::Rva(0xf070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("ImageList_Remove".to_string()),
            target: ExportTarget::Rva(0xf080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("ImageList_GetIcon".to_string()),
            target: ExportTarget::Rva(0xf090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("ImageList_Draw".to_string()),
            target: ExportTarget::Rva(0xf0a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("ImageList_DrawEx".to_string()),
            target: ExportTarget::Rva(0xf0b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("ImageList_GetIconSize".to_string()),
            target: ExportTarget::Rva(0xf0c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("ImageList_SetIconSize".to_string()),
            target: ExportTarget::Rva(0xf0d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("ImageList_BeginDrag".to_string()),
            target: ExportTarget::Rva(0xf0e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("ImageList_EndDrag".to_string()),
            target: ExportTarget::Rva(0xf0f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("ImageList_DragEnter".to_string()),
            target: ExportTarget::Rva(0xf100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("ImageList_DragLeave".to_string()),
            target: ExportTarget::Rva(0xf110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("ImageList_DragMove".to_string()),
            target: ExportTarget::Rva(0xf120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("ImageList_SetDragCursorImage".to_string()),
            target: ExportTarget::Rva(0xf130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("PropertySheetW".to_string()),
            target: ExportTarget::Rva(0xf140),
        },
    ];

    let shlwapi_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("PathCombineW".to_string()),
            target: ExportTarget::Rva(0x10000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("PathAppendW".to_string()),
            target: ExportTarget::Rva(0x10010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("PathFindFileNameW".to_string()),
            target: ExportTarget::Rva(0x10020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("PathFindExtensionW".to_string()),
            target: ExportTarget::Rva(0x10030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("PathRemoveFileSpecW".to_string()),
            target: ExportTarget::Rva(0x10040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("PathIsDirectoryW".to_string()),
            target: ExportTarget::Rva(0x10050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("PathFileExistsW".to_string()),
            target: ExportTarget::Rva(0x10060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("PathIsRelativeW".to_string()),
            target: ExportTarget::Rva(0x10070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("PathIsRootW".to_string()),
            target: ExportTarget::Rva(0x10080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("StrStrW".to_string()),
            target: ExportTarget::Rva(0x10090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("StrCatW".to_string()),
            target: ExportTarget::Rva(0x100a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("StrCmpW".to_string()),
            target: ExportTarget::Rva(0x100b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("StrCmpIW".to_string()),
            target: ExportTarget::Rva(0x100c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("StrChrW".to_string()),
            target: ExportTarget::Rva(0x100d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("StrRChrW".to_string()),
            target: ExportTarget::Rva(0x100e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("StrCpyW".to_string()),
            target: ExportTarget::Rva(0x100f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("StrToIntW".to_string()),
            target: ExportTarget::Rva(0x10100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("StrFromTimeIntervalW".to_string()),
            target: ExportTarget::Rva(0x10110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("SHRegGetValueW".to_string()),
            target: ExportTarget::Rva(0x10120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("SHRegSetValueW".to_string()),
            target: ExportTarget::Rva(0x10130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("UrlCanonicalizeW".to_string()),
            target: ExportTarget::Rva(0x10140),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("UrlCombineW".to_string()),
            target: ExportTarget::Rva(0x10150),
        },
        ExportSymbol {
            ordinal: 23,
            name: Some("ParseURLW".to_string()),
            target: ExportTarget::Rva(0x10160),
        },
        ExportSymbol {
            ordinal: 24,
            name: Some("SHDeleteKeyW".to_string()),
            target: ExportTarget::Rva(0x10170),
        },
        ExportSymbol {
            ordinal: 25,
            name: Some("SHDeleteEmptyKeyW".to_string()),
            target: ExportTarget::Rva(0x10180),
        },
        ExportSymbol {
            ordinal: 26,
            name: Some("SHSearchMapInt".to_string()),
            target: ExportTarget::Rva(0x10190),
        },
        ExportSymbol {
            ordinal: 27,
            name: Some("GetMenuContextHelpId".to_string()),
            target: ExportTarget::Rva(0x101a0),
        },
        ExportSymbol {
            ordinal: 28,
            name: Some("SetMenuContextHelpId".to_string()),
            target: ExportTarget::Rva(0x101b0),
        },
        ExportSymbol {
            ordinal: 29,
            name: Some("IsCharAlphaW".to_string()),
            target: ExportTarget::Rva(0x101c0),
        },
        ExportSymbol {
            ordinal: 30,
            name: Some("IsCharAlphaNumericW".to_string()),
            target: ExportTarget::Rva(0x101d0),
        },
        ExportSymbol {
            ordinal: 31,
            name: Some("IsCharLowerW".to_string()),
            target: ExportTarget::Rva(0x101e0),
        },
        ExportSymbol {
            ordinal: 32,
            name: Some("IsCharUpperW".to_string()),
            target: ExportTarget::Rva(0x101f0),
        },
        ExportSymbol {
            ordinal: 33,
            name: Some("IsCharSpaceW".to_string()),
            target: ExportTarget::Rva(0x10200),
        },
        ExportSymbol {
            ordinal: 34,
            name: Some("ChrCmpIW".to_string()),
            target: ExportTarget::Rva(0x10210),
        },
        ExportSymbol {
            ordinal: 35,
            name: Some("IntlStrEqWorkerW".to_string()),
            target: ExportTarget::Rva(0x10220),
        },
        ExportSymbol {
            ordinal: 36,
            name: Some("PathRemoveExtensionW".to_string()),
            target: ExportTarget::Rva(0x10230),
        },
        ExportSymbol {
            ordinal: 37,
            name: Some("PathRemoveBlanksW".to_string()),
            target: ExportTarget::Rva(0x10240),
        },
        ExportSymbol {
            ordinal: 38,
            name: Some("PathCanonicalizeW".to_string()),
            target: ExportTarget::Rva(0x10250),
        },
        ExportSymbol {
            ordinal: 39,
            name: Some("PathMatchSpecW".to_string()),
            target: ExportTarget::Rva(0x10260),
        },
        ExportSymbol {
            ordinal: 40,
            name: Some("PathStripPathW".to_string()),
            target: ExportTarget::Rva(0x10270),
        },
        ExportSymbol {
            ordinal: 41,
            name: Some("PathGetDriveNumberW".to_string()),
            target: ExportTarget::Rva(0x10280),
        },
        ExportSymbol {
            ordinal: 42,
            name: Some("PathAddBackslashW".to_string()),
            target: ExportTarget::Rva(0x10290),
        },
        ExportSymbol {
            ordinal: 43,
            name: Some("PathRemoveBackslashW".to_string()),
            target: ExportTarget::Rva(0x102a0),
        },
        ExportSymbol {
            ordinal: 44,
            name: Some("PathSkipRootW".to_string()),
            target: ExportTarget::Rva(0x102b0),
        },
        ExportSymbol {
            ordinal: 45,
            name: Some("StrChrIW".to_string()),
            target: ExportTarget::Rva(0x102c0),
        },
        ExportSymbol {
            ordinal: 46,
            name: Some("StrStrIW".to_string()),
            target: ExportTarget::Rva(0x102d0),
        },
        ExportSymbol {
            ordinal: 47,
            name: Some("StrCmpNIW".to_string()),
            target: ExportTarget::Rva(0x102e0),
        },
        ExportSymbol {
            ordinal: 48,
            name: Some("StrCmpNW".to_string()),
            target: ExportTarget::Rva(0x102f0),
        },
        ExportSymbol {
            ordinal: 49,
            name: Some("StrCpyNW".to_string()),
            target: ExportTarget::Rva(0x10300),
        },
    ];

    let version_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("GetFileVersionInfoW".to_string()),
            target: ExportTarget::Rva(0x11000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("GetFileVersionInfoSizeW".to_string()),
            target: ExportTarget::Rva(0x11010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("VerQueryValueW".to_string()),
            target: ExportTarget::Rva(0x11020),
        },
    ];

    let dwrite_exports = vec![ExportSymbol {
        ordinal: 1,
        name: Some("DWriteCreateFactory".to_string()),
        target: ExportTarget::Rva(0x12000),
    }];

    let propsys_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("PSGetPropertyDescriptionFromName".to_string()),
            target: ExportTarget::Rva(0x13000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("PSGetPropertyKeyFromName".to_string()),
            target: ExportTarget::Rva(0x13010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("PSGetNameFromPropertyKey".to_string()),
            target: ExportTarget::Rva(0x13020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("PSPropertyKeyFromString".to_string()),
            target: ExportTarget::Rva(0x13030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("PSStringFromPropertyKey".to_string()),
            target: ExportTarget::Rva(0x13040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("InitPropVariantFromString".to_string()),
            target: ExportTarget::Rva(0x13050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("InitPropVariantFromGUIDAsString".to_string()),
            target: ExportTarget::Rva(0x13060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("PropVariantClear".to_string()),
            target: ExportTarget::Rva(0x13070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("PropVariantCopy".to_string()),
            target: ExportTarget::Rva(0x13080),
        },
    ];

    let mmdevapi_exports = vec![ExportSymbol {
        ordinal: 1,
        name: Some("ActivateAudioInterfaceAsync".to_string()),
        target: ExportTarget::Rva(0x14000),
    }];

    let dsound_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("DirectSoundCreate8".to_string()),
            target: ExportTarget::Rva(0x15000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("DirectSoundEnumerateW".to_string()),
            target: ExportTarget::Rva(0x15010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("DirectSoundCaptureCreate8".to_string()),
            target: ExportTarget::Rva(0x15020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("DirectSoundCaptureEnumerateW".to_string()),
            target: ExportTarget::Rva(0x15030),
        },
    ];

    let bcrypt_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("BCryptOpenAlgorithmProvider".to_string()),
            target: ExportTarget::Rva(0x16000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("BCryptCloseAlgorithmProvider".to_string()),
            target: ExportTarget::Rva(0x16010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("BCryptGenerateSymmetricKey".to_string()),
            target: ExportTarget::Rva(0x16020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("BCryptGenerateKeyPair".to_string()),
            target: ExportTarget::Rva(0x16030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("BCryptFinalizeKeyPair".to_string()),
            target: ExportTarget::Rva(0x16040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("BCryptEncrypt".to_string()),
            target: ExportTarget::Rva(0x16050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("BCryptDecrypt".to_string()),
            target: ExportTarget::Rva(0x16060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("BCryptHash".to_string()),
            target: ExportTarget::Rva(0x16070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("BCryptHashData".to_string()),
            target: ExportTarget::Rva(0x16080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("BCryptCreateHash".to_string()),
            target: ExportTarget::Rva(0x16090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("BCryptDestroyHash".to_string()),
            target: ExportTarget::Rva(0x160a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("BCryptDestroyKey".to_string()),
            target: ExportTarget::Rva(0x160b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("BCryptGetProperty".to_string()),
            target: ExportTarget::Rva(0x160c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("BCryptSetProperty".to_string()),
            target: ExportTarget::Rva(0x160d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("BCryptGenRandom".to_string()),
            target: ExportTarget::Rva(0x160e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("BCryptDeriveKey".to_string()),
            target: ExportTarget::Rva(0x160f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("BCryptImportKey".to_string()),
            target: ExportTarget::Rva(0x16100),
        },
    ];

    let dwmapi_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("DwmIsCompositionEnabled".to_string()),
            target: ExportTarget::Rva(0x17000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("DwmEnableComposition".to_string()),
            target: ExportTarget::Rva(0x17010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("DwmEnableBlurBehindWindow".to_string()),
            target: ExportTarget::Rva(0x17020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("DwmExtendFrameIntoClientArea".to_string()),
            target: ExportTarget::Rva(0x17030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("DwmGetColorizationColor".to_string()),
            target: ExportTarget::Rva(0x17040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("DwmGetWindowAttribute".to_string()),
            target: ExportTarget::Rva(0x17050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("DwmSetWindowAttribute".to_string()),
            target: ExportTarget::Rva(0x17060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("DwmFlush".to_string()),
            target: ExportTarget::Rva(0x17070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("DwmRegisterThumbnail".to_string()),
            target: ExportTarget::Rva(0x17080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("DwmUpdateThumbnailProperties".to_string()),
            target: ExportTarget::Rva(0x17090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("DwmUnregisterThumbnail".to_string()),
            target: ExportTarget::Rva(0x170a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("DwmSetIconicThumbnail".to_string()),
            target: ExportTarget::Rva(0x170b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("DwmSetIconicLivePreviewBitmap".to_string()),
            target: ExportTarget::Rva(0x170c0),
        },
    ];

    let uxtheme_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("BeginPanningFeedback".to_string()),
            target: ExportTarget::Rva(0x18000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("BeginBufferedPaint".to_string()),
            target: ExportTarget::Rva(0x18010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("EndBufferedPaint".to_string()),
            target: ExportTarget::Rva(0x18020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("BufferedPaintInit".to_string()),
            target: ExportTarget::Rva(0x18030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("BufferedPaintUnInit".to_string()),
            target: ExportTarget::Rva(0x18040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("OpenThemeData".to_string()),
            target: ExportTarget::Rva(0x18050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("CloseThemeData".to_string()),
            target: ExportTarget::Rva(0x18060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("DrawThemeBackground".to_string()),
            target: ExportTarget::Rva(0x18070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("DrawThemeText".to_string()),
            target: ExportTarget::Rva(0x18080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("GetThemeColor".to_string()),
            target: ExportTarget::Rva(0x18090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("GetThemeFont".to_string()),
            target: ExportTarget::Rva(0x180a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("GetThemePartSize".to_string()),
            target: ExportTarget::Rva(0x180b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("GetThemeTextExtent".to_string()),
            target: ExportTarget::Rva(0x180c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("GetThemeBackgroundContentRect".to_string()),
            target: ExportTarget::Rva(0x180d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("GetThemeSysColor".to_string()),
            target: ExportTarget::Rva(0x180e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("GetThemeSysFont".to_string()),
            target: ExportTarget::Rva(0x180f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("IsAppThemed".to_string()),
            target: ExportTarget::Rva(0x18100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("IsThemeActive".to_string()),
            target: ExportTarget::Rva(0x18110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("SetWindowTheme".to_string()),
            target: ExportTarget::Rva(0x18120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("EnableThemeDialogTexture".to_string()),
            target: ExportTarget::Rva(0x18130),
        },
    ];

    let secur32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("GetUserNameExW".to_string()),
            target: ExportTarget::Rva(0x19000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("AcquireCredentialsHandleW".to_string()),
            target: ExportTarget::Rva(0x19010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("FreeCredentialsHandle".to_string()),
            target: ExportTarget::Rva(0x19020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("InitializeSecurityContextW".to_string()),
            target: ExportTarget::Rva(0x19030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("AcceptSecurityContext".to_string()),
            target: ExportTarget::Rva(0x19040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("CompleteAuthToken".to_string()),
            target: ExportTarget::Rva(0x19050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("DeleteSecurityContext".to_string()),
            target: ExportTarget::Rva(0x19060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("ImpersonateSecurityContext".to_string()),
            target: ExportTarget::Rva(0x19070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("RevertSecurityContext".to_string()),
            target: ExportTarget::Rva(0x19080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("QueryContextAttributesW".to_string()),
            target: ExportTarget::Rva(0x19090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("EncryptMessage".to_string()),
            target: ExportTarget::Rva(0x190a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("DecryptMessage".to_string()),
            target: ExportTarget::Rva(0x190b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("MakeSignature".to_string()),
            target: ExportTarget::Rva(0x190c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("VerifySignature".to_string()),
            target: ExportTarget::Rva(0x190d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("EnumerateSecurityPackagesW".to_string()),
            target: ExportTarget::Rva(0x190e0),
        },
    ];

    let mscoree_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("CorBindToRuntimeEx".to_string()),
            target: ExportTarget::Rva(0x1a000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("CorBindToRuntime".to_string()),
            target: ExportTarget::Rva(0x1a010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("CLRCreateInstance".to_string()),
            target: ExportTarget::Rva(0x1a020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("GetCORSystemDirectory".to_string()),
            target: ExportTarget::Rva(0x1a030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("GetRequestedRuntimeInfo".to_string()),
            target: ExportTarget::Rva(0x1a040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("LoadLibraryShim".to_string()),
            target: ExportTarget::Rva(0x1a050),
        },
    ];

    let imm32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("ImmGetContext".to_string()),
            target: ExportTarget::Rva(0x1b000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("ImmReleaseContext".to_string()),
            target: ExportTarget::Rva(0x1b010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("ImmSetCompositionStringW".to_string()),
            target: ExportTarget::Rva(0x1b020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("ImmGetCompositionStringW".to_string()),
            target: ExportTarget::Rva(0x1b030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("ImmGetDefaultIMEWnd".to_string()),
            target: ExportTarget::Rva(0x1b040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("ImmSimulateHotKey".to_string()),
            target: ExportTarget::Rva(0x1b050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("ImmIsIME".to_string()),
            target: ExportTarget::Rva(0x1b060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("ImmGetVirtualKey".to_string()),
            target: ExportTarget::Rva(0x1b070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("ImmNotifyIME".to_string()),
            target: ExportTarget::Rva(0x1b080),
        },
    ];

    let oleacc_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("AccessibleObjectFromWindow".to_string()),
            target: ExportTarget::Rva(0x1c000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("AccessibleObjectFromEvent".to_string()),
            target: ExportTarget::Rva(0x1c010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("AccessibleObjectFromPoint".to_string()),
            target: ExportTarget::Rva(0x1c020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("WindowFromAccessibleObject".to_string()),
            target: ExportTarget::Rva(0x1c030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("GetAccessibleObjectFromWindow".to_string()),
            target: ExportTarget::Rva(0x1c040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("GetOleaccVersionInfo".to_string()),
            target: ExportTarget::Rva(0x1c050),
        },
    ];

    let oleaut32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("SysAllocString".to_string()),
            target: ExportTarget::Rva(0x1d000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("SysFreeString".to_string()),
            target: ExportTarget::Rva(0x1d010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("SysReAllocString".to_string()),
            target: ExportTarget::Rva(0x1d020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("SysAllocStringLen".to_string()),
            target: ExportTarget::Rva(0x1d030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("SysStringLen".to_string()),
            target: ExportTarget::Rva(0x1d040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("SysStringByteLen".to_string()),
            target: ExportTarget::Rva(0x1d050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("VariantInit".to_string()),
            target: ExportTarget::Rva(0x1d060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("VariantClear".to_string()),
            target: ExportTarget::Rva(0x1d070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("VariantCopy".to_string()),
            target: ExportTarget::Rva(0x1d080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("VariantCopyInd".to_string()),
            target: ExportTarget::Rva(0x1d090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("VariantChangeType".to_string()),
            target: ExportTarget::Rva(0x1d0a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("VariantChangeTypeEx".to_string()),
            target: ExportTarget::Rva(0x1d0b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("SafeArrayCreate".to_string()),
            target: ExportTarget::Rva(0x1d0c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("SafeArrayDestroy".to_string()),
            target: ExportTarget::Rva(0x1d0d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("SafeArrayGetDim".to_string()),
            target: ExportTarget::Rva(0x1d0e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("SafeArrayGetElement".to_string()),
            target: ExportTarget::Rva(0x1d0f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("SafeArrayPutElement".to_string()),
            target: ExportTarget::Rva(0x1d100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("SafeArrayAccessData".to_string()),
            target: ExportTarget::Rva(0x1d110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("SafeArrayUnaccessData".to_string()),
            target: ExportTarget::Rva(0x1d120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("SafeArrayGetLBound".to_string()),
            target: ExportTarget::Rva(0x1d130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("SafeArrayGetUBound".to_string()),
            target: ExportTarget::Rva(0x1d140),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("SafeArrayCreateVector".to_string()),
            target: ExportTarget::Rva(0x1d150),
        },
        ExportSymbol {
            ordinal: 23,
            name: Some("BSTR_UserFree".to_string()),
            target: ExportTarget::Rva(0x1d160),
        },
        ExportSymbol {
            ordinal: 24,
            name: Some("BSTR_UserMarshal".to_string()),
            target: ExportTarget::Rva(0x1d170),
        },
        ExportSymbol {
            ordinal: 25,
            name: Some("BSTR_UserUnmarshal".to_string()),
            target: ExportTarget::Rva(0x1d180),
        },
        ExportSymbol {
            ordinal: 26,
            name: Some("BSTR_UserSize".to_string()),
            target: ExportTarget::Rva(0x1d190),
        },
        ExportSymbol {
            ordinal: 27,
            name: Some("CreateDispTypeInfo".to_string()),
            target: ExportTarget::Rva(0x1d1a0),
        },
        ExportSymbol {
            ordinal: 28,
            name: Some("CreateStdDispatch".to_string()),
            target: ExportTarget::Rva(0x1d1b0),
        },
        ExportSymbol {
            ordinal: 29,
            name: Some("DispGetIDsOfNames".to_string()),
            target: ExportTarget::Rva(0x1d1c0),
        },
        ExportSymbol {
            ordinal: 30,
            name: Some("DispInvoke".to_string()),
            target: ExportTarget::Rva(0x1d1d0),
        },
        ExportSymbol {
            ordinal: 31,
            name: Some("DispGetParam".to_string()),
            target: ExportTarget::Rva(0x1d1e0),
        },
        ExportSymbol {
            ordinal: 32,
            name: Some("LoadTypeLib".to_string()),
            target: ExportTarget::Rva(0x1d1f0),
        },
        ExportSymbol {
            ordinal: 33,
            name: Some("LoadRegTypeLib".to_string()),
            target: ExportTarget::Rva(0x1d200),
        },
        ExportSymbol {
            ordinal: 34,
            name: Some("RegisterTypeLib".to_string()),
            target: ExportTarget::Rva(0x1d210),
        },
        ExportSymbol {
            ordinal: 35,
            name: Some("UnRegisterTypeLib".to_string()),
            target: ExportTarget::Rva(0x1d220),
        },
        ExportSymbol {
            ordinal: 36,
            name: Some("QueryPathOfRegTypeLib".to_string()),
            target: ExportTarget::Rva(0x1d230),
        },
        ExportSymbol {
            ordinal: 37,
            name: Some("LHashValOfNameSys".to_string()),
            target: ExportTarget::Rva(0x1d240),
        },
        ExportSymbol {
            ordinal: 38,
            name: Some("IEnumVARIANT".to_string()),
            target: ExportTarget::Rva(0x2b000),
        },
        ExportSymbol {
            ordinal: 39,
            name: Some("IConnectionPoint".to_string()),
            target: ExportTarget::Rva(0x2b010),
        },
    ];

    let rpcrt4_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("UuidCreate".to_string()),
            target: ExportTarget::Rva(0x1e000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("UuidCreateSequential".to_string()),
            target: ExportTarget::Rva(0x1e010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("UuidToStringW".to_string()),
            target: ExportTarget::Rva(0x1e020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("UuidFromStringW".to_string()),
            target: ExportTarget::Rva(0x1e030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("RpcStringFreeW".to_string()),
            target: ExportTarget::Rva(0x1e040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("RpcBindingFromStringBindingW".to_string()),
            target: ExportTarget::Rva(0x1e050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("RpcBindingFree".to_string()),
            target: ExportTarget::Rva(0x1e060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("RpcStringBindingComposeW".to_string()),
            target: ExportTarget::Rva(0x1e070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("I_RpcExceptionFilter".to_string()),
            target: ExportTarget::Rva(0x1e080),
        },
    ];

    let comdlg32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("GetOpenFileNameW".to_string()),
            target: ExportTarget::Rva(0x1f000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("GetSaveFileNameW".to_string()),
            target: ExportTarget::Rva(0x1f010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("ChooseColorW".to_string()),
            target: ExportTarget::Rva(0x1f020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("ChooseFontW".to_string()),
            target: ExportTarget::Rva(0x1f030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("PageSetupDlgW".to_string()),
            target: ExportTarget::Rva(0x1f040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("PrintDlgW".to_string()),
            target: ExportTarget::Rva(0x1f050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("PrintDlgExW".to_string()),
            target: ExportTarget::Rva(0x1f060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("FindTextW".to_string()),
            target: ExportTarget::Rva(0x1f070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("ReplaceTextW".to_string()),
            target: ExportTarget::Rva(0x1f080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("CommDlgExtendedError".to_string()),
            target: ExportTarget::Rva(0x1f090),
        },
    ];

    let wininet_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("InternetOpenW".to_string()),
            target: ExportTarget::Rva(0x20000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("InternetCloseHandle".to_string()),
            target: ExportTarget::Rva(0x20010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("InternetConnectW".to_string()),
            target: ExportTarget::Rva(0x20020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("InternetReadFile".to_string()),
            target: ExportTarget::Rva(0x20030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("InternetReadFileExW".to_string()),
            target: ExportTarget::Rva(0x20040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("InternetWriteFile".to_string()),
            target: ExportTarget::Rva(0x20050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("InternetOpenUrlW".to_string()),
            target: ExportTarget::Rva(0x20060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("InternetSetOptionW".to_string()),
            target: ExportTarget::Rva(0x20070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("InternetQueryOptionW".to_string()),
            target: ExportTarget::Rva(0x20080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("InternetGetConnectedState".to_string()),
            target: ExportTarget::Rva(0x20090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("HttpOpenRequestW".to_string()),
            target: ExportTarget::Rva(0x200a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("HttpSendRequestW".to_string()),
            target: ExportTarget::Rva(0x200b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("HttpQueryInfoW".to_string()),
            target: ExportTarget::Rva(0x200c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("HttpAddRequestHeadersW".to_string()),
            target: ExportTarget::Rva(0x200d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("InternetCrackUrlW".to_string()),
            target: ExportTarget::Rva(0x200e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("InternetCanonicalizeUrlW".to_string()),
            target: ExportTarget::Rva(0x200f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("InternetAttemptConnect".to_string()),
            target: ExportTarget::Rva(0x20100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("InternetSetStatusCallback".to_string()),
            target: ExportTarget::Rva(0x20110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("FtpGetFileW".to_string()),
            target: ExportTarget::Rva(0x20120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("FtpPutFileW".to_string()),
            target: ExportTarget::Rva(0x20130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("FtpOpenFileW".to_string()),
            target: ExportTarget::Rva(0x20140),
        },
        ExportSymbol {
            ordinal: 22,
            name: Some("FtpFindFirstFileW".to_string()),
            target: ExportTarget::Rva(0x20150),
        },
    ];

    let urlmon_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("URLDownloadToFileW".to_string()),
            target: ExportTarget::Rva(0x21000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("URLDownloadToCacheFileW".to_string()),
            target: ExportTarget::Rva(0x21010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("CoInternetSetFeatureEnabled".to_string()),
            target: ExportTarget::Rva(0x21020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("CoInternetIsFeatureEnabled".to_string()),
            target: ExportTarget::Rva(0x21030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("CreateURLMoniker".to_string()),
            target: ExportTarget::Rva(0x21040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("CreateAsyncBindCtx".to_string()),
            target: ExportTarget::Rva(0x21050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("RegisterBindStatusCallback".to_string()),
            target: ExportTarget::Rva(0x21060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("ObtainUserAgentString".to_string()),
            target: ExportTarget::Rva(0x21070),
        },
    ];

    let wintrust_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("WinVerifyTrust".to_string()),
            target: ExportTarget::Rva(0x22000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("WTHelperProvDataFromStateData".to_string()),
            target: ExportTarget::Rva(0x22010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("WTHelperGetProvSignerFromChain".to_string()),
            target: ExportTarget::Rva(0x22020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("WTHelperGetProvPrivateDataFromChain".to_string()),
            target: ExportTarget::Rva(0x22030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("WTGetSignatureInfo".to_string()),
            target: ExportTarget::Rva(0x22040),
        },
    ];

    let xinput13_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("XInputGetState".to_string()),
            target: ExportTarget::Rva(0x23000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("XInputSetState".to_string()),
            target: ExportTarget::Rva(0x23010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("XInputGetCapabilities".to_string()),
            target: ExportTarget::Rva(0x23020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("XInputEnable".to_string()),
            target: ExportTarget::Rva(0x23030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("XInputGetDSoundAudioDeviceGuids".to_string()),
            target: ExportTarget::Rva(0x23040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("XInputGetBatteryInformation".to_string()),
            target: ExportTarget::Rva(0x23050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("XInputGetKeystroke".to_string()),
            target: ExportTarget::Rva(0x23060),
        },
    ];

    let mfplat_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("MFStartup".to_string()),
            target: ExportTarget::Rva(0x24000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("MFShutdown".to_string()),
            target: ExportTarget::Rva(0x24010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("MFCreateMediaType".to_string()),
            target: ExportTarget::Rva(0x24020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("MFCreateMFByteStreamOnStream".to_string()),
            target: ExportTarget::Rva(0x24030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("MFCreateMemoryBuffer".to_string()),
            target: ExportTarget::Rva(0x24040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("MFCreateMediaBufferFromMediaType".to_string()),
            target: ExportTarget::Rva(0x24050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("MFCreateSample".to_string()),
            target: ExportTarget::Rva(0x24060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("MFCreateSourceReaderFromURL".to_string()),
            target: ExportTarget::Rva(0x24070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("MFCreateSourceReaderFromByteStream".to_string()),
            target: ExportTarget::Rva(0x24080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("MFCreatePresentationDescriptor".to_string()),
            target: ExportTarget::Rva(0x24090),
        },
        ExportSymbol {
            ordinal: 11,
            name: Some("MFGetService".to_string()),
            target: ExportTarget::Rva(0x240a0),
        },
        ExportSymbol {
            ordinal: 12,
            name: Some("MFTEnumEx".to_string()),
            target: ExportTarget::Rva(0x240b0),
        },
        ExportSymbol {
            ordinal: 13,
            name: Some("MFCreateMediaSession".to_string()),
            target: ExportTarget::Rva(0x240c0),
        },
        ExportSymbol {
            ordinal: 14,
            name: Some("MFCreateTopology".to_string()),
            target: ExportTarget::Rva(0x240d0),
        },
        ExportSymbol {
            ordinal: 15,
            name: Some("MFCreatePresentationClock".to_string()),
            target: ExportTarget::Rva(0x240e0),
        },
        ExportSymbol {
            ordinal: 16,
            name: Some("MFAddPeriodicCallback".to_string()),
            target: ExportTarget::Rva(0x240f0),
        },
        ExportSymbol {
            ordinal: 17,
            name: Some("MFCancelPeriodicCallback".to_string()),
            target: ExportTarget::Rva(0x24100),
        },
        ExportSymbol {
            ordinal: 18,
            name: Some("MFGetSystemTime".to_string()),
            target: ExportTarget::Rva(0x24110),
        },
        ExportSymbol {
            ordinal: 19,
            name: Some("MFCreateDXGIDeviceManager".to_string()),
            target: ExportTarget::Rva(0x24120),
        },
        ExportSymbol {
            ordinal: 20,
            name: Some("MFCreateFile".to_string()),
            target: ExportTarget::Rva(0x24130),
        },
        ExportSymbol {
            ordinal: 21,
            name: Some("MFCreateTempFile".to_string()),
            target: ExportTarget::Rva(0x24140),
        },
        ExportSymbol {
            ordinal: 90,
            name: Some("IMFAsyncResult".to_string()),
            target: ExportTarget::Rva(0x24200),
        },
        ExportSymbol {
            ordinal: 91,
            name: Some("IMFGetService".to_string()),
            target: ExportTarget::Rva(0x24210),
        },
    ];

    let cfgmgr32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("CM_Get_Device_ID_ListW".to_string()),
            target: ExportTarget::Rva(0x25000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("CM_Free_Device_ID_List".to_string()),
            target: ExportTarget::Rva(0x25010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("CM_Locate_DevNodeW".to_string()),
            target: ExportTarget::Rva(0x25020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("CM_Get_DevNode_Status".to_string()),
            target: ExportTarget::Rva(0x25030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("CM_Get_Device_ID_List_SizeW".to_string()),
            target: ExportTarget::Rva(0x25040),
        },
    ];

    let powrprof_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("PowerGetActiveScheme".to_string()),
            target: ExportTarget::Rva(0x26000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("PowerSetActiveScheme".to_string()),
            target: ExportTarget::Rva(0x26010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("PowerReadDCValue".to_string()),
            target: ExportTarget::Rva(0x26020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("PowerReadACValue".to_string()),
            target: ExportTarget::Rva(0x26030),
        },
    ];

    let dnsapi_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("DnsQuery_W".to_string()),
            target: ExportTarget::Rva(0x27000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("DnsQueryConfig".to_string()),
            target: ExportTarget::Rva(0x27010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("DnsRecordListFree".to_string()),
            target: ExportTarget::Rva(0x27020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("DnsFlushResolverCache".to_string()),
            target: ExportTarget::Rva(0x27030),
        },
    ];

    let wintypes_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("RoGetActivationFactory".to_string()),
            target: ExportTarget::Rva(0x28000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("RoInitialize".to_string()),
            target: ExportTarget::Rva(0x28010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("RoUninitialize".to_string()),
            target: ExportTarget::Rva(0x28020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("RoActivateInstance".to_string()),
            target: ExportTarget::Rva(0x28030),
        },
    ];

    let sspicli_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("SSPIInitialize".to_string()),
            target: ExportTarget::Rva(0x29000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("QuerySecurityPackageInfoW".to_string()),
            target: ExportTarget::Rva(0x29010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("FreeContextBuffer".to_string()),
            target: ExportTarget::Rva(0x29020),
        },
    ];

    let newdev_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("DiInstallDevice".to_string()),
            target: ExportTarget::Rva(0x2a000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("DiInstallDriverW".to_string()),
            target: ExportTarget::Rva(0x2a010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("DiUninstallDevice".to_string()),
            target: ExportTarget::Rva(0x2a020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("UpdateDriverForPlugAndPlayDevicesW".to_string()),
            target: ExportTarget::Rva(0x2a030),
        },
    ];

    let wtsapi32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("WTSQueryUserToken".to_string()),
            target: ExportTarget::Rva(0x2b000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("WTSFreeMemory".to_string()),
            target: ExportTarget::Rva(0x2b010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("WTSEnumerateSessionsW".to_string()),
            target: ExportTarget::Rva(0x2b020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("WTSQuerySessionInformationW".to_string()),
            target: ExportTarget::Rva(0x2b030),
        },
    ];

    let mpr_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("WNetAddConnection2W".to_string()),
            target: ExportTarget::Rva(0x2c000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("WNetCancelConnection2W".to_string()),
            target: ExportTarget::Rva(0x2c010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("WNetGetConnectionW".to_string()),
            target: ExportTarget::Rva(0x2c020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("WNetEnumResourceW".to_string()),
            target: ExportTarget::Rva(0x2c030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("WNetOpenEnumW".to_string()),
            target: ExportTarget::Rva(0x2c040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("WNetCloseEnum".to_string()),
            target: ExportTarget::Rva(0x2c050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("WNetGetUserW".to_string()),
            target: ExportTarget::Rva(0x2c060),
        },
    ];

    let msacm32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("acmDriverOpen".to_string()),
            target: ExportTarget::Rva(0x2d000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("acmDriverClose".to_string()),
            target: ExportTarget::Rva(0x2d010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("acmStreamOpen".to_string()),
            target: ExportTarget::Rva(0x2d020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("acmStreamClose".to_string()),
            target: ExportTarget::Rva(0x2d030),
        },
        ExportSymbol {
            ordinal: 5,
            name: Some("acmStreamConvert".to_string()),
            target: ExportTarget::Rva(0x2d040),
        },
        ExportSymbol {
            ordinal: 6,
            name: Some("acmFormatSuggest".to_string()),
            target: ExportTarget::Rva(0x2d050),
        },
        ExportSymbol {
            ordinal: 7,
            name: Some("acmFormatEnumW".to_string()),
            target: ExportTarget::Rva(0x2d060),
        },
        ExportSymbol {
            ordinal: 8,
            name: Some("acmFormatDetailsW".to_string()),
            target: ExportTarget::Rva(0x2d070),
        },
        ExportSymbol {
            ordinal: 9,
            name: Some("acmMetrics".to_string()),
            target: ExportTarget::Rva(0x2d080),
        },
        ExportSymbol {
            ordinal: 10,
            name: Some("acmDriverEnum".to_string()),
            target: ExportTarget::Rva(0x2d090),
        },
    ];

    let netapi32_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("NetServerEnum".to_string()),
            target: ExportTarget::Rva(0x2e000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("NetApiBufferFree".to_string()),
            target: ExportTarget::Rva(0x2e010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("NetUserGetInfo".to_string()),
            target: ExportTarget::Rva(0x2e020),
        },
        ExportSymbol {
            ordinal: 4,
            name: Some("NetWkstaGetInfo".to_string()),
            target: ExportTarget::Rva(0x2e030),
        },
    ];

    let tbs_exports = vec![
        ExportSymbol {
            ordinal: 1,
            name: Some("Tbsi_Context_Create".to_string()),
            target: ExportTarget::Rva(0x7000),
        },
        ExportSymbol {
            ordinal: 2,
            name: Some("Tbsip_Submit_Command".to_string()),
            target: ExportTarget::Rva(0x7010),
        },
        ExportSymbol {
            ordinal: 3,
            name: Some("Tbsip_Context_Close".to_string()),
            target: ExportTarget::Rva(0x7020),
        },
    ];

    let mut tables = BTreeMap::from([
        ("advapi32.dll".to_string(), advapi32_exports),
        ("tbs.dll".to_string(), tbs_exports),
        ("bcrypt.dll".to_string(), bcrypt_exports),
        ("cfgmgr32.dll".to_string(), cfgmgr32_exports),
        ("comctl32.dll".to_string(), comctl32_exports),
        ("comdlg32.dll".to_string(), comdlg32_exports),
        ("crypt32.dll".to_string(), crypt32_exports),
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
            "d3d12.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3D12CreateDevice".to_string()),
                    target: ExportTarget::Rva(0x4200),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ID3D12Heap".to_string()),
                    target: ExportTarget::Rva(0x4210),
                },
            ],
        ),
        ("dnsapi.dll".to_string(), dnsapi_exports),
        ("dsound.dll".to_string(), dsound_exports),
        ("dwmapi.dll".to_string(), dwmapi_exports),
        ("dwrite.dll".to_string(), dwrite_exports),
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
        ("gdi32.dll".to_string(), gdi32_exports),
        ("gdiplus.dll".to_string(), gdiplus_exports),
        ("imm32.dll".to_string(), imm32_exports),
        ("iphlpapi.dll".to_string(), iphlpapi_exports),
        ("kernel32.dll".to_string(), kernel32_exports),
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
                ExportSymbol {
                    ordinal: 4,
                    name: Some("GetTimeZoneInformation".to_string()),
                    target: ExportTarget::Rva(0x2030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("GetFileInformationByHandle".to_string()),
                    target: ExportTarget::Rva(0x2040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("GetFileAttributesExW".to_string()),
                    target: ExportTarget::Rva(0x2050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("VerifyVersionInfoW".to_string()),
                    target: ExportTarget::Rva(0x2060),
                },
            ],
        ),
        (
            "libcef.dll".to_string(),
            crate::cef_bridge::register_libcef_dll_exports(),
        ),
        ("mfplat.dll".to_string(), mfplat_exports),
        ("mmdevapi.dll".to_string(), mmdevapi_exports),
        ("mpr.dll".to_string(), mpr_exports),
        ("msacm32.dll".to_string(), msacm32_exports),
        ("mscoree.dll".to_string(), mscoree_exports),
        (
            "msvcrt.dll".to_string(),
            vec![
                // Modern msvcrt forwards most C runtime functions to ucrtbase.
                // These exports mirror the ucrtbase export table so that guest
                // code importing from msvcrt.dll can resolve them.
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
                    name: Some("realloc".to_string()),
                    target: ExportTarget::Rva(0x2140),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("__C_specific_handler".to_string()),
                    target: ExportTarget::Rva(0x2150),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("__p___argc".to_string()),
                    target: ExportTarget::Rva(0x2160),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("__p___argv".to_string()),
                    target: ExportTarget::Rva(0x2170),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("_cexit".to_string()),
                    target: ExportTarget::Rva(0x2180),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("_configure_narrow_argv".to_string()),
                    target: ExportTarget::Rva(0x2190),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("_crt_atexit".to_string()),
                    target: ExportTarget::Rva(0x21a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("_exit".to_string()),
                    target: ExportTarget::Rva(0x21b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("_initialize_narrow_environment".to_string()),
                    target: ExportTarget::Rva(0x21c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("_initterm".to_string()),
                    target: ExportTarget::Rva(0x21d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("_initterm_e".to_string()),
                    target: ExportTarget::Rva(0x21e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("_set_app_type".to_string()),
                    target: ExportTarget::Rva(0x21f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("_set_invalid_parameter_handler".to_string()),
                    target: ExportTarget::Rva(0x2200),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("abort".to_string()),
                    target: ExportTarget::Rva(0x2210),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("exit".to_string()),
                    target: ExportTarget::Rva(0x2220),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("_beginthreadex".to_string()),
                    target: ExportTarget::Rva(0x2230),
                },
                ExportSymbol {
                    ordinal: 21,
                    name: Some("_endthreadex".to_string()),
                    target: ExportTarget::Rva(0x2240),
                },
                ExportSymbol {
                    ordinal: 22,
                    name: Some("__acrt_iob_func".to_string()),
                    target: ExportTarget::Rva(0x2250),
                },
                ExportSymbol {
                    ordinal: 23,
                    name: Some("__p__commode".to_string()),
                    target: ExportTarget::Rva(0x2260),
                },
                ExportSymbol {
                    ordinal: 24,
                    name: Some("__p__fmode".to_string()),
                    target: ExportTarget::Rva(0x2270),
                },
                ExportSymbol {
                    ordinal: 25,
                    name: Some("__stdio_common_vfprintf".to_string()),
                    target: ExportTarget::Rva(0x2280),
                },
                ExportSymbol {
                    ordinal: 26,
                    name: Some("fwrite".to_string()),
                    target: ExportTarget::Rva(0x2290),
                },
                ExportSymbol {
                    ordinal: 27,
                    name: Some("strlen".to_string()),
                    target: ExportTarget::Rva(0x22a0),
                },
                ExportSymbol {
                    ordinal: 28,
                    name: Some("strncmp".to_string()),
                    target: ExportTarget::Rva(0x22b0),
                },
                ExportSymbol {
                    ordinal: 29,
                    name: Some("__p__environ".to_string()),
                    target: ExportTarget::Rva(0x22c0),
                },
                ExportSymbol {
                    ordinal: 30,
                    name: Some("__setusermatherr".to_string()),
                    target: ExportTarget::Rva(0x22d0),
                },
                ExportSymbol {
                    ordinal: 31,
                    name: Some("memcpy".to_string()),
                    target: ExportTarget::Rva(0x22e0),
                },
                ExportSymbol {
                    ordinal: 32,
                    name: Some("memset".to_string()),
                    target: ExportTarget::Rva(0x22f0),
                },
                ExportSymbol {
                    ordinal: 33,
                    name: Some("memmove".to_string()),
                    target: ExportTarget::Rva(0x2300),
                },
                ExportSymbol {
                    ordinal: 34,
                    name: Some("memcmp".to_string()),
                    target: ExportTarget::Rva(0x2310),
                },
                ExportSymbol {
                    ordinal: 35,
                    name: Some("strcmp".to_string()),
                    target: ExportTarget::Rva(0x2320),
                },
                ExportSymbol {
                    ordinal: 36,
                    name: Some("strcpy".to_string()),
                    target: ExportTarget::Rva(0x2330),
                },
                ExportSymbol {
                    ordinal: 37,
                    name: Some("strcat".to_string()),
                    target: ExportTarget::Rva(0x2340),
                },
                ExportSymbol {
                    ordinal: 38,
                    name: Some("sprintf".to_string()),
                    target: ExportTarget::Rva(0x2350),
                },
                ExportSymbol {
                    ordinal: 39,
                    name: Some("vsprintf".to_string()),
                    target: ExportTarget::Rva(0x2360),
                },
                ExportSymbol {
                    ordinal: 40,
                    name: Some("sscanf".to_string()),
                    target: ExportTarget::Rva(0x2370),
                },
                ExportSymbol {
                    ordinal: 41,
                    name: Some("fopen".to_string()),
                    target: ExportTarget::Rva(0x2380),
                },
                ExportSymbol {
                    ordinal: 42,
                    name: Some("fclose".to_string()),
                    target: ExportTarget::Rva(0x2390),
                },
                ExportSymbol {
                    ordinal: 43,
                    name: Some("fread".to_string()),
                    target: ExportTarget::Rva(0x23a0),
                },
                ExportSymbol {
                    ordinal: 44,
                    name: Some("fgets".to_string()),
                    target: ExportTarget::Rva(0x23b0),
                },
                ExportSymbol {
                    ordinal: 45,
                    name: Some("fflush".to_string()),
                    target: ExportTarget::Rva(0x23c0),
                },
                ExportSymbol {
                    ordinal: 46,
                    name: Some("sqrt".to_string()),
                    target: ExportTarget::Rva(0x23d0),
                },
                ExportSymbol {
                    ordinal: 47,
                    name: Some("pow".to_string()),
                    target: ExportTarget::Rva(0x23e0),
                },
                ExportSymbol {
                    ordinal: 48,
                    name: Some("cos".to_string()),
                    target: ExportTarget::Rva(0x23f0),
                },
                ExportSymbol {
                    ordinal: 49,
                    name: Some("sin".to_string()),
                    target: ExportTarget::Rva(0x2400),
                },
                ExportSymbol {
                    ordinal: 50,
                    name: Some("tan".to_string()),
                    target: ExportTarget::Rva(0x2410),
                },
                ExportSymbol {
                    ordinal: 51,
                    name: Some("atan2".to_string()),
                    target: ExportTarget::Rva(0x2420),
                },
                ExportSymbol {
                    ordinal: 52,
                    name: Some("log".to_string()),
                    target: ExportTarget::Rva(0x2430),
                },
                ExportSymbol {
                    ordinal: 53,
                    name: Some("exp".to_string()),
                    target: ExportTarget::Rva(0x2440),
                },
                ExportSymbol {
                    ordinal: 54,
                    name: Some("fabs".to_string()),
                    target: ExportTarget::Rva(0x2450),
                },
                ExportSymbol {
                    ordinal: 55,
                    name: Some("floor".to_string()),
                    target: ExportTarget::Rva(0x2460),
                },
                ExportSymbol {
                    ordinal: 56,
                    name: Some("ceil".to_string()),
                    target: ExportTarget::Rva(0x2470),
                },
                ExportSymbol {
                    ordinal: 57,
                    name: Some("rand".to_string()),
                    target: ExportTarget::Rva(0x2480),
                },
                ExportSymbol {
                    ordinal: 58,
                    name: Some("srand".to_string()),
                    target: ExportTarget::Rva(0x2490),
                },
                ExportSymbol {
                    ordinal: 59,
                    name: Some("time".to_string()),
                    target: ExportTarget::Rva(0x24a0),
                },
                ExportSymbol {
                    ordinal: 60,
                    name: Some("qsort".to_string()),
                    target: ExportTarget::Rva(0x24b0),
                },
                ExportSymbol {
                    ordinal: 61,
                    name: Some("bsearch".to_string()),
                    target: ExportTarget::Rva(0x24c0),
                },
                ExportSymbol {
                    ordinal: 62,
                    name: Some("abs".to_string()),
                    target: ExportTarget::Rva(0x24d0),
                },
                ExportSymbol {
                    ordinal: 63,
                    name: Some("labs".to_string()),
                    target: ExportTarget::Rva(0x24e0),
                },
                ExportSymbol {
                    ordinal: 64,
                    name: Some("atoi".to_string()),
                    target: ExportTarget::Rva(0x24f0),
                },
                ExportSymbol {
                    ordinal: 65,
                    name: Some("atol".to_string()),
                    target: ExportTarget::Rva(0x2500),
                },
                ExportSymbol {
                    ordinal: 66,
                    name: Some("atof".to_string()),
                    target: ExportTarget::Rva(0x2510),
                },
                ExportSymbol {
                    ordinal: 67,
                    name: Some("signal".to_string()),
                    target: ExportTarget::Rva(0x2520),
                },
                ExportSymbol {
                    ordinal: 68,
                    name: Some("setlocale".to_string()),
                    target: ExportTarget::Rva(0x2530),
                },
            ],
        ),
        ("netapi32.dll".to_string(), netapi32_exports),
        ("newdev.dll".to_string(), newdev_exports),
        (
            "ntdll.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("RtlNtStatusToDosError".to_string()),
                    target: ExportTarget::Rva(0x2300),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("NtQueryInformationProcess".to_string()),
                    target: ExportTarget::Rva(0x2310),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("NtAllocateVirtualMemory".to_string()),
                    target: ExportTarget::Rva(0x2320),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("NtFreeVirtualMemory".to_string()),
                    target: ExportTarget::Rva(0x2330),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("NtProtectVirtualMemory".to_string()),
                    target: ExportTarget::Rva(0x2340),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("NtQueryVirtualMemory".to_string()),
                    target: ExportTarget::Rva(0x2350),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("NtReadVirtualMemory".to_string()),
                    target: ExportTarget::Rva(0x2360),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("NtWriteVirtualMemory".to_string()),
                    target: ExportTarget::Rva(0x2370),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("NtClose".to_string()),
                    target: ExportTarget::Rva(0x2380),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("NtDuplicateObject".to_string()),
                    target: ExportTarget::Rva(0x2390),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("NtQueryObject".to_string()),
                    target: ExportTarget::Rva(0x23A0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("NtCreateEvent".to_string()),
                    target: ExportTarget::Rva(0x23B0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("NtSetEvent".to_string()),
                    target: ExportTarget::Rva(0x23C0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("NtClearEvent".to_string()),
                    target: ExportTarget::Rva(0x23D0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("NtWaitForSingleObject".to_string()),
                    target: ExportTarget::Rva(0x23E0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("NtWaitForMultipleObjects".to_string()),
                    target: ExportTarget::Rva(0x23F0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("NtDelayExecution".to_string()),
                    target: ExportTarget::Rva(0x2400),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("NtCreateSection".to_string()),
                    target: ExportTarget::Rva(0x2410),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("NtMapViewOfSection".to_string()),
                    target: ExportTarget::Rva(0x2420),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("NtUnmapViewOfSection".to_string()),
                    target: ExportTarget::Rva(0x2430),
                },
                ExportSymbol {
                    ordinal: 21,
                    name: Some("NtQuerySection".to_string()),
                    target: ExportTarget::Rva(0x2440),
                },
                ExportSymbol {
                    ordinal: 22,
                    name: Some("NtCreateFile".to_string()),
                    target: ExportTarget::Rva(0x2450),
                },
                ExportSymbol {
                    ordinal: 23,
                    name: Some("NtDeviceIoControlFile".to_string()),
                    target: ExportTarget::Rva(0x2460),
                },
                ExportSymbol {
                    ordinal: 24,
                    name: Some("NtCreateKey".to_string()),
                    target: ExportTarget::Rva(0x2470),
                },
                ExportSymbol {
                    ordinal: 25,
                    name: Some("NtOpenKey".to_string()),
                    target: ExportTarget::Rva(0x2480),
                },
                ExportSymbol {
                    ordinal: 26,
                    name: Some("NtQueryValueKey".to_string()),
                    target: ExportTarget::Rva(0x2490),
                },
                ExportSymbol {
                    ordinal: 27,
                    name: Some("NtSetValueKey".to_string()),
                    target: ExportTarget::Rva(0x24A0),
                },
                ExportSymbol {
                    ordinal: 28,
                    name: Some("NtDeleteKey".to_string()),
                    target: ExportTarget::Rva(0x24B0),
                },
                ExportSymbol {
                    ordinal: 29,
                    name: Some("NtDeleteValueKey".to_string()),
                    target: ExportTarget::Rva(0x24C0),
                },
                ExportSymbol {
                    ordinal: 30,
                    name: Some("NtEnumerateKey".to_string()),
                    target: ExportTarget::Rva(0x24D0),
                },
                ExportSymbol {
                    ordinal: 31,
                    name: Some("NtEnumerateValueKey".to_string()),
                    target: ExportTarget::Rva(0x24E0),
                },
                ExportSymbol {
                    ordinal: 32,
                    name: Some("NtQueryKey".to_string()),
                    target: ExportTarget::Rva(0x24F0),
                },
                ExportSymbol {
                    ordinal: 33,
                    name: Some("NtQueryInformationThread".to_string()),
                    target: ExportTarget::Rva(0x2500),
                },
                ExportSymbol {
                    ordinal: 34,
                    name: Some("NtGetContextThread".to_string()),
                    target: ExportTarget::Rva(0x2510),
                },
                ExportSymbol {
                    ordinal: 35,
                    name: Some("NtSetContextThread".to_string()),
                    target: ExportTarget::Rva(0x2520),
                },
                ExportSymbol {
                    ordinal: 36,
                    name: Some("NtSuspendThread".to_string()),
                    target: ExportTarget::Rva(0x2530),
                },
                ExportSymbol {
                    ordinal: 37,
                    name: Some("NtResumeThread".to_string()),
                    target: ExportTarget::Rva(0x2540),
                },
                ExportSymbol {
                    ordinal: 38,
                    name: Some("NtTerminateProcess".to_string()),
                    target: ExportTarget::Rva(0x2550),
                },
                ExportSymbol {
                    ordinal: 39,
                    name: Some("NtTerminateThread".to_string()),
                    target: ExportTarget::Rva(0x2560),
                },
                ExportSymbol {
                    ordinal: 40,
                    name: Some("NtCreateThreadEx".to_string()),
                    target: ExportTarget::Rva(0x2570),
                },
                ExportSymbol {
                    ordinal: 41,
                    name: Some("NtSetInformationThread".to_string()),
                    target: ExportTarget::Rva(0x2580),
                },
                ExportSymbol {
                    ordinal: 42,
                    name: Some("NtQuerySystemInformation".to_string()),
                    target: ExportTarget::Rva(0x2590),
                },
                ExportSymbol {
                    ordinal: 43,
                    name: Some("NtQueryPerformanceCounter".to_string()),
                    target: ExportTarget::Rva(0x25A0),
                },
                ExportSymbol {
                    ordinal: 44,
                    name: Some("NtQueryTimerResolution".to_string()),
                    target: ExportTarget::Rva(0x25B0),
                },
                ExportSymbol {
                    ordinal: 45,
                    name: Some("NtSetTimerResolution".to_string()),
                    target: ExportTarget::Rva(0x25C0),
                },
                ExportSymbol {
                    ordinal: 46,
                    name: Some("NtQuerySystemTime".to_string()),
                    target: ExportTarget::Rva(0x25D0),
                },
                ExportSymbol {
                    ordinal: 47,
                    name: Some("RtlInitUnicodeString".to_string()),
                    target: ExportTarget::Rva(0x25E0),
                },
                ExportSymbol {
                    ordinal: 48,
                    name: Some("RtlInitAnsiString".to_string()),
                    target: ExportTarget::Rva(0x25F0),
                },
                ExportSymbol {
                    ordinal: 49,
                    name: Some("RtlFreeUnicodeString".to_string()),
                    target: ExportTarget::Rva(0x2600),
                },
                ExportSymbol {
                    ordinal: 50,
                    name: Some("RtlFreeAnsiString".to_string()),
                    target: ExportTarget::Rva(0x2610),
                },
                ExportSymbol {
                    ordinal: 51,
                    name: Some("RtlCompareUnicodeString".to_string()),
                    target: ExportTarget::Rva(0x2620),
                },
                ExportSymbol {
                    ordinal: 52,
                    name: Some("RtlEqualUnicodeString".to_string()),
                    target: ExportTarget::Rva(0x2630),
                },
                ExportSymbol {
                    ordinal: 53,
                    name: Some("RtlGetVersion".to_string()),
                    target: ExportTarget::Rva(0x2640),
                },
                ExportSymbol {
                    ordinal: 54,
                    name: Some("RtlCaptureContext".to_string()),
                    target: ExportTarget::Rva(0x2650),
                },
                ExportSymbol {
                    ordinal: 55,
                    name: Some("RtlLookupFunctionEntry".to_string()),
                    target: ExportTarget::Rva(0x2660),
                },
                ExportSymbol {
                    ordinal: 56,
                    name: Some("RtlRaiseException".to_string()),
                    target: ExportTarget::Rva(0x2670),
                },
                ExportSymbol {
                    ordinal: 57,
                    name: Some("RtlAllocateHeap".to_string()),
                    target: ExportTarget::Rva(0x2680),
                },
                ExportSymbol {
                    ordinal: 58,
                    name: Some("RtlFreeHeap".to_string()),
                    target: ExportTarget::Rva(0x2690),
                },
                ExportSymbol {
                    ordinal: 59,
                    name: Some("RtlSizeHeap".to_string()),
                    target: ExportTarget::Rva(0x26A0),
                },
                ExportSymbol {
                    ordinal: 60,
                    name: Some("LdrLoadDll".to_string()),
                    target: ExportTarget::Rva(0x26B0),
                },
                ExportSymbol {
                    ordinal: 61,
                    name: Some("LdrUnloadDll".to_string()),
                    target: ExportTarget::Rva(0x26C0),
                },
                ExportSymbol {
                    ordinal: 62,
                    name: Some("LdrGetDllHandle".to_string()),
                    target: ExportTarget::Rva(0x26D0),
                },
                ExportSymbol {
                    ordinal: 63,
                    name: Some("LdrGetProcedureAddress".to_string()),
                    target: ExportTarget::Rva(0x26E0),
                },
                ExportSymbol {
                    ordinal: 64,
                    name: Some("LdrLockLoaderLock".to_string()),
                    target: ExportTarget::Rva(0x26F0),
                },
                ExportSymbol {
                    ordinal: 65,
                    name: Some("LdrUnlockLoaderLock".to_string()),
                    target: ExportTarget::Rva(0x2700),
                },
                ExportSymbol {
                    ordinal: 66,
                    name: Some("LdrAddRefDll".to_string()),
                    target: ExportTarget::Rva(0x2710),
                },
                ExportSymbol {
                    ordinal: 67,
                    name: Some("LdrRemoveRefDll".to_string()),
                    target: ExportTarget::Rva(0x2720),
                },
                ExportSymbol {
                    ordinal: 68,
                    name: Some("NtLoadDriver".to_string()),
                    target: ExportTarget::Rva(0x2730),
                },
                ExportSymbol {
                    ordinal: 69,
                    name: Some("NtUnloadDriver".to_string()),
                    target: ExportTarget::Rva(0x2740),
                },
                ExportSymbol {
                    ordinal: 70,
                    name: Some("NtOpenDirectoryObject".to_string()),
                    target: ExportTarget::Rva(0x2750),
                },
                ExportSymbol {
                    ordinal: 71,
                    name: Some("NtQueryDirectoryObject".to_string()),
                    target: ExportTarget::Rva(0x2760),
                },
                ExportSymbol {
                    ordinal: 72,
                    name: Some("NtQueryVolumeInformationFile".to_string()),
                    target: ExportTarget::Rva(0x2770),
                },
                ExportSymbol {
                    ordinal: 73,
                    name: Some("NtAttestationChallenge".to_string()),
                    target: ExportTarget::Rva(0x2780),
                },
                ExportSymbol {
                    ordinal: 74,
                    name: Some("NtAttestationQuote".to_string()),
                    target: ExportTarget::Rva(0x2790),
                },
                ExportSymbol {
                    ordinal: 75,
                    name: Some("NtAttestationVerify".to_string()),
                    target: ExportTarget::Rva(0x27A0),
                },
                ExportSymbol {
                    ordinal: 76,
                    name: Some("NtAttestationEnrollProvider".to_string()),
                    target: ExportTarget::Rva(0x27B0),
                },
                ExportSymbol {
                    ordinal: 77,
                    name: Some("NtAttestationRevokeProvider".to_string()),
                    target: ExportTarget::Rva(0x27C0),
                },
                ExportSymbol {
                    ordinal: 99,
                    name: Some("NtCreateFileMapping".to_string()),
                    target: ExportTarget::Rva(0x23f0),
                },
                ExportSymbol {
                    ordinal: 100,
                    name: Some("NtCreateProcess".to_string()),
                    target: ExportTarget::Rva(0x2400),
                },
            ],
        ),
        ("ole32.dll".to_string(), ole32_exports),
        ("oleacc.dll".to_string(), oleacc_exports),
        ("oleaut32.dll".to_string(), oleaut32_exports),
        ("powrprof.dll".to_string(), powrprof_exports),
        ("propsys.dll".to_string(), propsys_exports),
        ("psapi.dll".to_string(), Vec::new()),
        ("rpcrt4.dll".to_string(), rpcrt4_exports),
        ("secur32.dll".to_string(), secur32_exports),
        ("setupapi.dll".to_string(), setupapi_exports),
        (
            "scrobj.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("IActiveScript".to_string()),
                target: ExportTarget::Rva(0x24600),
            }],
        ),
        ("shell32.dll".to_string(), shell32_exports),
        ("shlwapi.dll".to_string(), shlwapi_exports),
        ("sspicli.dll".to_string(), sspicli_exports),
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
        ("urlmon.dll".to_string(), urlmon_exports),
        (
            "usp10.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("ScriptStringAnalyse".to_string()),
                    target: ExportTarget::Rva(0x4000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ScriptStringFree".to_string()),
                    target: ExportTarget::Rva(0x4010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("ScriptStringOut".to_string()),
                    target: ExportTarget::Rva(0x4020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("ScriptString_pSize".to_string()),
                    target: ExportTarget::Rva(0x4030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("ScriptItemize".to_string()),
                    target: ExportTarget::Rva(0x4040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("ScriptShape".to_string()),
                    target: ExportTarget::Rva(0x4050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("ScriptPlace".to_string()),
                    target: ExportTarget::Rva(0x4060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("ScriptLayout".to_string()),
                    target: ExportTarget::Rva(0x4070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("ScriptBreak".to_string()),
                    target: ExportTarget::Rva(0x4080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("ScriptGetProperties".to_string()),
                    target: ExportTarget::Rva(0x4090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("ScriptRecordDigitSubstitution".to_string()),
                    target: ExportTarget::Rva(0x40a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("ScriptApplyDigitSubstitution".to_string()),
                    target: ExportTarget::Rva(0x40b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("ScriptCacheGetHeight".to_string()),
                    target: ExportTarget::Rva(0x40c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("ScriptFreeCache".to_string()),
                    target: ExportTarget::Rva(0x40d0),
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
                    name: Some("GetMessageW".to_string()),
                    target: ExportTarget::Rva(0x3010),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("TranslateMessage".to_string()),
                    target: ExportTarget::Rva(0x3020),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("PeekMessageW".to_string()),
                    target: ExportTarget::Rva(0x3030),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("DispatchMessageW".to_string()),
                    target: ExportTarget::Rva(0x3040),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("DefWindowProcW".to_string()),
                    target: ExportTarget::Rva(0x3050),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("MessageBoxW".to_string()),
                    target: ExportTarget::Rva(0x3060),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("LoadIconW".to_string()),
                    target: ExportTarget::Rva(0x3070),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("PostThreadMessageW".to_string()),
                    target: ExportTarget::Rva(0x3080),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("RedrawWindow".to_string()),
                    target: ExportTarget::Rva(0x3090),
                },
            ],
        ),
        ("uxtheme.dll".to_string(), uxtheme_exports),
        ("version.dll".to_string(), version_exports),
        ("wininet.dll".to_string(), wininet_exports),
        ("winmm.dll".to_string(), winmm_exports),
        ("wintrust.dll".to_string(), wintrust_exports),
        ("wintypes.dll".to_string(), wintypes_exports),
        ("ws2_32.dll".to_string(), ws2_32_exports),
        ("wtsapi32.dll".to_string(), wtsapi32_exports),
        (
            "xaudio2_9.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("XAudio2Create".to_string()),
                target: ExportTarget::Rva(0x5000),
            }],
        ),
        ("xinput1_3.dll".to_string(), xinput13_exports),
        (
            "xinput1_4.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("XInputGetState".to_string()),
                    target: ExportTarget::Rva(0x23000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("XInputSetState".to_string()),
                    target: ExportTarget::Rva(0x23010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("XInputGetCapabilities".to_string()),
                    target: ExportTarget::Rva(0x23020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("XInputEnable".to_string()),
                    target: ExportTarget::Rva(0x23030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("XInputGetBatteryInformation".to_string()),
                    target: ExportTarget::Rva(0x23050),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("XInputGetKeystroke".to_string()),
                    target: ExportTarget::Rva(0x23060),
                },
            ],
        ),
        (
            "xinput9_1_0.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("XInputGetState".to_string()),
                    target: ExportTarget::Rva(0x23000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("XInputSetState".to_string()),
                    target: ExportTarget::Rva(0x23010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("XInputGetCapabilities".to_string()),
                    target: ExportTarget::Rva(0x23020),
                },
            ],
        ),
        // ── New synthetic export tables added by automated task ──
        (
            "browseui.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("SHOpenFolderWindow".to_string()),
                    target: ExportTarget::Rva(0x2f000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("SHCreateExplorerTaskband".to_string()),
                    target: ExportTarget::Rva(0x2f010),
                },
            ],
        ),
        (
            "d3d8thk.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3DKMTCreateAllocation".to_string()),
                    target: ExportTarget::Rva(0x30000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3DKMTQueryAllocationResidency".to_string()),
                    target: ExportTarget::Rva(0x30010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3DKMTSetAllocationPriority".to_string()),
                    target: ExportTarget::Rva(0x30020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3DKMTOpenResource".to_string()),
                    target: ExportTarget::Rva(0x30030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("D3DKMTCreateDevice".to_string()),
                    target: ExportTarget::Rva(0x30040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("D3DKMTDestroyDevice".to_string()),
                    target: ExportTarget::Rva(0x30050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("D3DKMTCreateContext".to_string()),
                    target: ExportTarget::Rva(0x30060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("D3DKMTDestroyContext".to_string()),
                    target: ExportTarget::Rva(0x30070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("D3DKMTPresent".to_string()),
                    target: ExportTarget::Rva(0x30080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("D3DKMTCloseAdapter".to_string()),
                    target: ExportTarget::Rva(0x30090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("D3DKMTOpenAdapterFromHdc".to_string()),
                    target: ExportTarget::Rva(0x300a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("D3DKMTGetDisplayModeList".to_string()),
                    target: ExportTarget::Rva(0x300b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("D3DKMTEnumAdapters".to_string()),
                    target: ExportTarget::Rva(0x300c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("D3DKMTQueryAdapterInfo".to_string()),
                    target: ExportTarget::Rva(0x300d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("D3DKMTCreateSynchronizationObject".to_string()),
                    target: ExportTarget::Rva(0x300e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("D3DKMTRender".to_string()),
                    target: ExportTarget::Rva(0x300f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("D3DKMTOpenKeyedMutex".to_string()),
                    target: ExportTarget::Rva(0x30100),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("D3DKMTSetDisplayPrivateDriverFormat".to_string()),
                    target: ExportTarget::Rva(0x30110),
                },
            ],
        ),
        (
            "d3dcompiler_43.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3DCompile".to_string()),
                    target: ExportTarget::Rva(0x31000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3DCompile2".to_string()),
                    target: ExportTarget::Rva(0x31010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3DCompileFromFile".to_string()),
                    target: ExportTarget::Rva(0x31020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3DDisassemble".to_string()),
                    target: ExportTarget::Rva(0x31030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("D3DReflect".to_string()),
                    target: ExportTarget::Rva(0x31040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("D3DStripShader".to_string()),
                    target: ExportTarget::Rva(0x31050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("D3DGetBlobPart".to_string()),
                    target: ExportTarget::Rva(0x31060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("D3DSetBlobPart".to_string()),
                    target: ExportTarget::Rva(0x31070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("D3DCreateLinker".to_string()),
                    target: ExportTarget::Rva(0x31080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("D3DLoadModule".to_string()),
                    target: ExportTarget::Rva(0x31090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("D3DGetTraceInstructionOffsets".to_string()),
                    target: ExportTarget::Rva(0x310a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("D3DSetTraceInstructionOffsets".to_string()),
                    target: ExportTarget::Rva(0x310b0),
                },
            ],
        ),
        (
            "d3dcompiler_47.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3DCompile".to_string()),
                    target: ExportTarget::Rva(0x32000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3DCompile2".to_string()),
                    target: ExportTarget::Rva(0x32010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3DCompileFromFile".to_string()),
                    target: ExportTarget::Rva(0x32020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3DDisassemble".to_string()),
                    target: ExportTarget::Rva(0x32030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("D3DReflect".to_string()),
                    target: ExportTarget::Rva(0x32040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("D3DStripShader".to_string()),
                    target: ExportTarget::Rva(0x32050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("D3DGetBlobPart".to_string()),
                    target: ExportTarget::Rva(0x32060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("D3DSetBlobPart".to_string()),
                    target: ExportTarget::Rva(0x32070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("D3DCreateLinker".to_string()),
                    target: ExportTarget::Rva(0x32080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("D3DLoadModule".to_string()),
                    target: ExportTarget::Rva(0x32090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("D3DGetTraceInstructionOffsets".to_string()),
                    target: ExportTarget::Rva(0x320a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("D3DSetTraceInstructionOffsets".to_string()),
                    target: ExportTarget::Rva(0x320b0),
                },
            ],
        ),
        (
            "d3dx10_43.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3DX10CreateTextureFromFileW".to_string()),
                    target: ExportTarget::Rva(0x33000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3DX10CompileFromFile".to_string()),
                    target: ExportTarget::Rva(0x33010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3DX10SaveTextureToMemory".to_string()),
                    target: ExportTarget::Rva(0x33020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3DX10GetImageInfoFromFile".to_string()),
                    target: ExportTarget::Rva(0x33030),
                },
            ],
        ),
        (
            "d3dx9_43.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3DX11CreateTextureFromFileW".to_string()),
                    target: ExportTarget::Rva(0x34000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3DX11CompileFromFile".to_string()),
                    target: ExportTarget::Rva(0x34010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3DX11SaveTextureToMemory".to_string()),
                    target: ExportTarget::Rva(0x34020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3DX11GetImageInfoFromFile".to_string()),
                    target: ExportTarget::Rva(0x34030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("D3DX11SaveTextureToFileW".to_string()),
                    target: ExportTarget::Rva(0x34040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("D3DX11FilterTexture".to_string()),
                    target: ExportTarget::Rva(0x34050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("D3DX11CreateShaderResourceViewFromFile".to_string()),
                    target: ExportTarget::Rva(0x34060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("D3DX11CreateAsyncShaderResourceViewProcessor".to_string()),
                    target: ExportTarget::Rva(0x34070),
                },
            ],
        ),
        (
            "dhcpcsvc.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DhcpRequestParams".to_string()),
                    target: ExportTarget::Rva(0x35000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DhcpRenewParams".to_string()),
                    target: ExportTarget::Rva(0x35010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DhcpReleaseParams".to_string()),
                    target: ExportTarget::Rva(0x35020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DhcpCApiCleanup".to_string()),
                    target: ExportTarget::Rva(0x35030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DhcpCApiInitialize".to_string()),
                    target: ExportTarget::Rva(0x35040),
                },
            ],
        ),
        (
            "dhcpcsvc6.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("Dhcpv6RequestParams".to_string()),
                    target: ExportTarget::Rva(0x36000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("Dhcpv6RenewParams".to_string()),
                    target: ExportTarget::Rva(0x36010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("Dhcpv6ReleaseParams".to_string()),
                    target: ExportTarget::Rva(0x36020),
                },
            ],
        ),
        (
            "dinput8.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DirectInput8Create".to_string()),
                    target: ExportTarget::Rva(0x37000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x37010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x37020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("GetdfDIJoystick".to_string()),
                    target: ExportTarget::Rva(0x37030),
                },
            ],
        ),
        (
            "dxva2.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DXVA2CreateDirect3DDeviceManager9".to_string()),
                    target: ExportTarget::Rva(0x38000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DXVA2CreateVideoService".to_string()),
                    target: ExportTarget::Rva(0x38010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DXVA2GetVideoProcessorCaps".to_string()),
                    target: ExportTarget::Rva(0x38020),
                },
            ],
        ),
        (
            "evr.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("MFCreateVideoRenderer".to_string()),
                    target: ExportTarget::Rva(0x39000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("MFCreateVideoMixer".to_string()),
                    target: ExportTarget::Rva(0x39010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("MFCreateVideoPresenter".to_string()),
                    target: ExportTarget::Rva(0x39020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("MFCreateVideoSampleAllocator".to_string()),
                    target: ExportTarget::Rva(0x39030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("MFCreateVideoMediaType".to_string()),
                    target: ExportTarget::Rva(0x39040),
                },
            ],
        ),
        (
            "fwpuclnt.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("FWPS_FILTER".to_string()),
                    target: ExportTarget::Rva(0x3a000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("FwpsOpenToken".to_string()),
                    target: ExportTarget::Rva(0x3a010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("FwpsQueryTokenInformation".to_string()),
                    target: ExportTarget::Rva(0x3a020),
                },
            ],
        ),
        (
            "gameux.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("GameExplorer_Initialize".to_string()),
                    target: ExportTarget::Rva(0x3b000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("GameExplorer_VerifyAccess".to_string()),
                    target: ExportTarget::Rva(0x3b010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("GameExplorer_SetUserAccess".to_string()),
                    target: ExportTarget::Rva(0x3b020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("GAMEUX_SHFOLDERPATH".to_string()),
                    target: ExportTarget::Rva(0x3b030),
                },
            ],
        ),
        (
            "glu32.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("gluPerspective".to_string()),
                    target: ExportTarget::Rva(0x3c000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("gluLookAt".to_string()),
                    target: ExportTarget::Rva(0x3c010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("gluOrtho2D".to_string()),
                    target: ExportTarget::Rva(0x3c020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("gluProject".to_string()),
                    target: ExportTarget::Rva(0x3c030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("gluUnProject".to_string()),
                    target: ExportTarget::Rva(0x3c040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("gluPickMatrix".to_string()),
                    target: ExportTarget::Rva(0x3c050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("gluErrorString".to_string()),
                    target: ExportTarget::Rva(0x3c060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("gluBuild2DMipmaps".to_string()),
                    target: ExportTarget::Rva(0x3c070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("gluScaleImage".to_string()),
                    target: ExportTarget::Rva(0x3c080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("gluNewQuadric".to_string()),
                    target: ExportTarget::Rva(0x3c090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("gluDeleteQuadric".to_string()),
                    target: ExportTarget::Rva(0x3c0a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("gluSphere".to_string()),
                    target: ExportTarget::Rva(0x3c0b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("gluCylinder".to_string()),
                    target: ExportTarget::Rva(0x3c0c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("gluDisk".to_string()),
                    target: ExportTarget::Rva(0x3c0d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("gluPartialDisk".to_string()),
                    target: ExportTarget::Rva(0x3c0e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("gluNewTess".to_string()),
                    target: ExportTarget::Rva(0x3c0f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("gluTessBeginPolygon".to_string()),
                    target: ExportTarget::Rva(0x3c100),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("gluTessEndPolygon".to_string()),
                    target: ExportTarget::Rva(0x3c110),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("gluTessVertex".to_string()),
                    target: ExportTarget::Rva(0x3c120),
                },
            ],
        ),
        (
            "hid.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("HidP_GetCaps".to_string()),
                    target: ExportTarget::Rva(0x3d000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("HidP_GetButtonCaps".to_string()),
                    target: ExportTarget::Rva(0x3d010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("HidP_GetValueCaps".to_string()),
                    target: ExportTarget::Rva(0x3d020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("HidP_GetUsages".to_string()),
                    target: ExportTarget::Rva(0x3d030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("HidP_GetUsageValue".to_string()),
                    target: ExportTarget::Rva(0x3d040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("HidP_SetUsages".to_string()),
                    target: ExportTarget::Rva(0x3d050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("HidD_GetAttributes".to_string()),
                    target: ExportTarget::Rva(0x3d060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("HidD_GetHidGuid".to_string()),
                    target: ExportTarget::Rva(0x3d070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("HidD_GetPreparsedData".to_string()),
                    target: ExportTarget::Rva(0x3d080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("HidD_FreePreparsedData".to_string()),
                    target: ExportTarget::Rva(0x3d090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("HidD_GetManufacturerString".to_string()),
                    target: ExportTarget::Rva(0x3d0a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("HidD_GetProductString".to_string()),
                    target: ExportTarget::Rva(0x3d0b0),
                },
            ],
        ),
        (
            "httpapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("HttpInitialize".to_string()),
                    target: ExportTarget::Rva(0x3e000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("HttpTerminate".to_string()),
                    target: ExportTarget::Rva(0x3e010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("HttpCreateHttpHandle".to_string()),
                    target: ExportTarget::Rva(0x3e020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("HttpAddUrl".to_string()),
                    target: ExportTarget::Rva(0x3e030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("HttpRemoveUrl".to_string()),
                    target: ExportTarget::Rva(0x3e040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("HttpReceiveHttpRequest".to_string()),
                    target: ExportTarget::Rva(0x3e050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("HttpSendHttpResponse".to_string()),
                    target: ExportTarget::Rva(0x3e060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("HttpSendResponseEntityBody".to_string()),
                    target: ExportTarget::Rva(0x3e070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("HttpWaitForDisconnect".to_string()),
                    target: ExportTarget::Rva(0x3e080),
                },
            ],
        ),
        (
            "ieframe.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("IEHlink".to_string()),
                    target: ExportTarget::Rva(0x3f000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("IEGetWriteableHlink".to_string()),
                    target: ExportTarget::Rva(0x3f010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("IEGetFrameComponent".to_string()),
                    target: ExportTarget::Rva(0x3f020),
                },
            ],
        ),
        (
            "imagehlp.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("ImageLoad".to_string()),
                    target: ExportTarget::Rva(0x40000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ImageUnload".to_string()),
                    target: ExportTarget::Rva(0x40010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("ImageGetDigestStream".to_string()),
                    target: ExportTarget::Rva(0x40020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("ImageGetCertificateHeader".to_string()),
                    target: ExportTarget::Rva(0x40030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("ImageGetCertificateData".to_string()),
                    target: ExportTarget::Rva(0x40040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("ImageEnumerateCertificates".to_string()),
                    target: ExportTarget::Rva(0x40050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("ImageAddCertificate".to_string()),
                    target: ExportTarget::Rva(0x40060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("ImageRemoveCertificate".to_string()),
                    target: ExportTarget::Rva(0x40070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("MapAndLoad".to_string()),
                    target: ExportTarget::Rva(0x40080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("UnMapAndLoad".to_string()),
                    target: ExportTarget::Rva(0x40090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("BindImage".to_string()),
                    target: ExportTarget::Rva(0x400a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("BindImageEx".to_string()),
                    target: ExportTarget::Rva(0x400b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("ImagehlpApiVersion".to_string()),
                    target: ExportTarget::Rva(0x400c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("CheckSumMappedFile".to_string()),
                    target: ExportTarget::Rva(0x400d0),
                },
            ],
        ),
        (
            "kerberos.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("KerbLogon".to_string()),
                    target: ExportTarget::Rva(0x41000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("KerbRetrieveTicket".to_string()),
                    target: ExportTarget::Rva(0x41010),
                },
            ],
        ),
        (
            "loadperf.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("LoadPerfCounterTextStringsW".to_string()),
                    target: ExportTarget::Rva(0x42000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("UnloadPerfCounterTextStringsW".to_string()),
                    target: ExportTarget::Rva(0x42010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("SetServiceAsTrusted".to_string()),
                    target: ExportTarget::Rva(0x42020),
                },
            ],
        ),
        (
            "msacm32.drv".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("acmDriverOpen".to_string()),
                    target: ExportTarget::Rva(0x43000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("acmDriverClose".to_string()),
                    target: ExportTarget::Rva(0x43010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("acmDriverEnum".to_string()),
                    target: ExportTarget::Rva(0x43020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("acmMetrics".to_string()),
                    target: ExportTarget::Rva(0x43030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("acmFormatSuggest".to_string()),
                    target: ExportTarget::Rva(0x43040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("acmFormatEnum".to_string()),
                    target: ExportTarget::Rva(0x43050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("acmFormatDetails".to_string()),
                    target: ExportTarget::Rva(0x43060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("acmStreamOpen".to_string()),
                    target: ExportTarget::Rva(0x43070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("acmStreamClose".to_string()),
                    target: ExportTarget::Rva(0x43080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("acmStreamConvert".to_string()),
                    target: ExportTarget::Rva(0x43090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("acmStreamSize".to_string()),
                    target: ExportTarget::Rva(0x430a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("acmDriverMessage".to_string()),
                    target: ExportTarget::Rva(0x430b0),
                },
            ],
        ),
        (
            "msdmo.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DMOEnum".to_string()),
                    target: ExportTarget::Rva(0x44000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DMOGetName".to_string()),
                    target: ExportTarget::Rva(0x44010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DMOGetTypes".to_string()),
                    target: ExportTarget::Rva(0x44020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DMOGuidToStr".to_string()),
                    target: ExportTarget::Rva(0x44030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DMOStrToGuid".to_string()),
                    target: ExportTarget::Rva(0x44040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("MOFree".to_string()),
                    target: ExportTarget::Rva(0x44050),
                },
            ],
        ),
        (
            "msftedit.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("MsftEditRegisterClass".to_string()),
                target: ExportTarget::Rva(0x45000),
            }],
        ),
        (
            "mshtml.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("ShowHTMLDialogEx".to_string()),
                    target: ExportTarget::Rva(0x46000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("IEFrameFactory_Constructor".to_string()),
                    target: ExportTarget::Rva(0x46010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CreateHTMLPropertyPage".to_string()),
                    target: ExportTarget::Rva(0x46020),
                },
                ExportSymbol {
                    ordinal: 90,
                    name: Some("IHTMLDocument2".to_string()),
                    target: ExportTarget::Rva(0x24500),
                },
            ],
        ),
        (
            "msi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("MsiOpenPackageW".to_string()),
                    target: ExportTarget::Rva(0x47000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("MsiCloseHandle".to_string()),
                    target: ExportTarget::Rva(0x47010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("MsiGetPropertyW".to_string()),
                    target: ExportTarget::Rva(0x47020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("MsiSetPropertyW".to_string()),
                    target: ExportTarget::Rva(0x47030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("MsiInstallProductW".to_string()),
                    target: ExportTarget::Rva(0x47040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("MsiConfigureProductW".to_string()),
                    target: ExportTarget::Rva(0x47050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("MsiReinstallProductW".to_string()),
                    target: ExportTarget::Rva(0x47060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("MsiQueryProductInfoW".to_string()),
                    target: ExportTarget::Rva(0x47070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("MsiEnumProductsW".to_string()),
                    target: ExportTarget::Rva(0x47080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("MsiGetProductInfoW".to_string()),
                    target: ExportTarget::Rva(0x47090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("MsiOpenDatabaseW".to_string()),
                    target: ExportTarget::Rva(0x470a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("MsiDatabaseOpenViewW".to_string()),
                    target: ExportTarget::Rva(0x470b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("MsiViewExecute".to_string()),
                    target: ExportTarget::Rva(0x470c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("MsiViewFetch".to_string()),
                    target: ExportTarget::Rva(0x470d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("MsiViewClose".to_string()),
                    target: ExportTarget::Rva(0x470e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("MsiRecordGetStringW".to_string()),
                    target: ExportTarget::Rva(0x470f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("MsiRecordSetStringW".to_string()),
                    target: ExportTarget::Rva(0x47100),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("MsiRecordDataSize".to_string()),
                    target: ExportTarget::Rva(0x47110),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("MsiCloseAllHandles".to_string()),
                    target: ExportTarget::Rva(0x47120),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("MsiCreateRecord".to_string()),
                    target: ExportTarget::Rva(0x47130),
                },
                ExportSymbol {
                    ordinal: 21,
                    name: Some("MsiDatabaseCommit".to_string()),
                    target: ExportTarget::Rva(0x47140),
                },
                ExportSymbol {
                    ordinal: 22,
                    name: Some("MsiRecordGetInteger".to_string()),
                    target: ExportTarget::Rva(0x47150),
                },
                ExportSymbol {
                    ordinal: 23,
                    name: Some("MsiRecordReadStream".to_string()),
                    target: ExportTarget::Rva(0x47160),
                },
                ExportSymbol {
                    ordinal: 24,
                    name: Some("MsiRecordSetInteger".to_string()),
                    target: ExportTarget::Rva(0x47170),
                },
                ExportSymbol {
                    ordinal: 25,
                    name: Some("MsiViewGetColumnInfo".to_string()),
                    target: ExportTarget::Rva(0x47180),
                },
                ExportSymbol {
                    ordinal: 26,
                    name: Some("MsiViewModify".to_string()),
                    target: ExportTarget::Rva(0x47190),
                },
            ],
        ),
        (
            "mspatcha.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("ApplyPatchToFileW".to_string()),
                    target: ExportTarget::Rva(0x48000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ApplyPatchToFileExW".to_string()),
                    target: ExportTarget::Rva(0x48010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("GetPatchFileSignature".to_string()),
                    target: ExportTarget::Rva(0x48020),
                },
            ],
        ),
        (
            "ncrypt.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("NCryptOpenStorageProvider".to_string()),
                    target: ExportTarget::Rva(0x49000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("NCryptCreatePersistedKey".to_string()),
                    target: ExportTarget::Rva(0x49010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("NCryptOpenKey".to_string()),
                    target: ExportTarget::Rva(0x49020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("NCryptFinalizeKey".to_string()),
                    target: ExportTarget::Rva(0x49030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("NCryptEncrypt".to_string()),
                    target: ExportTarget::Rva(0x49040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("NCryptDecrypt".to_string()),
                    target: ExportTarget::Rva(0x49050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("NCryptExportKey".to_string()),
                    target: ExportTarget::Rva(0x49060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("NCryptImportKey".to_string()),
                    target: ExportTarget::Rva(0x49070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("NCryptDeleteKey".to_string()),
                    target: ExportTarget::Rva(0x49080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("NCryptFreeBuffer".to_string()),
                    target: ExportTarget::Rva(0x49090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("NCryptIsAlgSupported".to_string()),
                    target: ExportTarget::Rva(0x490a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("NCryptGetProperty".to_string()),
                    target: ExportTarget::Rva(0x490b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("NCryptSetProperty".to_string()),
                    target: ExportTarget::Rva(0x490c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("NCryptSignHash".to_string()),
                    target: ExportTarget::Rva(0x490d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("NCryptVerifySignature".to_string()),
                    target: ExportTarget::Rva(0x490e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("NCryptSecretAgreement".to_string()),
                    target: ExportTarget::Rva(0x490f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("NCryptDeriveKey".to_string()),
                    target: ExportTarget::Rva(0x49100),
                },
            ],
        ),
        (
            "opengl32.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("wglCreateContext".to_string()),
                    target: ExportTarget::Rva(0x4a000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("wglDeleteContext".to_string()),
                    target: ExportTarget::Rva(0x4a010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("wglMakeCurrent".to_string()),
                    target: ExportTarget::Rva(0x4a020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("wglGetProcAddress".to_string()),
                    target: ExportTarget::Rva(0x4a030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("wglSwapBuffers".to_string()),
                    target: ExportTarget::Rva(0x4a040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("wglSetPixelFormat".to_string()),
                    target: ExportTarget::Rva(0x4a050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("wglGetPixelFormat".to_string()),
                    target: ExportTarget::Rva(0x4a060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("wglDescribePixelFormat".to_string()),
                    target: ExportTarget::Rva(0x4a070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("wglChoosePixelFormat".to_string()),
                    target: ExportTarget::Rva(0x4a080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("glClear".to_string()),
                    target: ExportTarget::Rva(0x4a090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("glClearColor".to_string()),
                    target: ExportTarget::Rva(0x4a0a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("glViewport".to_string()),
                    target: ExportTarget::Rva(0x4a0b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("glMatrixMode".to_string()),
                    target: ExportTarget::Rva(0x4a0c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("glLoadIdentity".to_string()),
                    target: ExportTarget::Rva(0x4a0d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("glBegin".to_string()),
                    target: ExportTarget::Rva(0x4a0e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("glEnd".to_string()),
                    target: ExportTarget::Rva(0x4a0f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("glVertex2f".to_string()),
                    target: ExportTarget::Rva(0x4a100),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("glVertex3f".to_string()),
                    target: ExportTarget::Rva(0x4a110),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("glTexCoord2f".to_string()),
                    target: ExportTarget::Rva(0x4a120),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("glColor3f".to_string()),
                    target: ExportTarget::Rva(0x4a130),
                },
                ExportSymbol {
                    ordinal: 21,
                    name: Some("glColor4f".to_string()),
                    target: ExportTarget::Rva(0x4a140),
                },
                ExportSymbol {
                    ordinal: 22,
                    name: Some("glEnable".to_string()),
                    target: ExportTarget::Rva(0x4a150),
                },
                ExportSymbol {
                    ordinal: 23,
                    name: Some("glDisable".to_string()),
                    target: ExportTarget::Rva(0x4a160),
                },
                ExportSymbol {
                    ordinal: 24,
                    name: Some("glBindTexture".to_string()),
                    target: ExportTarget::Rva(0x4a170),
                },
                ExportSymbol {
                    ordinal: 25,
                    name: Some("glGenTextures".to_string()),
                    target: ExportTarget::Rva(0x4a180),
                },
                ExportSymbol {
                    ordinal: 26,
                    name: Some("glDeleteTextures".to_string()),
                    target: ExportTarget::Rva(0x4a190),
                },
                ExportSymbol {
                    ordinal: 27,
                    name: Some("glTexImage2D".to_string()),
                    target: ExportTarget::Rva(0x4a1a0),
                },
                ExportSymbol {
                    ordinal: 28,
                    name: Some("glTexParameteri".to_string()),
                    target: ExportTarget::Rva(0x4a1b0),
                },
                ExportSymbol {
                    ordinal: 29,
                    name: Some("glTexParameterf".to_string()),
                    target: ExportTarget::Rva(0x4a1c0),
                },
                ExportSymbol {
                    ordinal: 30,
                    name: Some("glBlendFunc".to_string()),
                    target: ExportTarget::Rva(0x4a1d0),
                },
                ExportSymbol {
                    ordinal: 31,
                    name: Some("glDepthFunc".to_string()),
                    target: ExportTarget::Rva(0x4a1e0),
                },
                ExportSymbol {
                    ordinal: 32,
                    name: Some("glCullFace".to_string()),
                    target: ExportTarget::Rva(0x4a1f0),
                },
                ExportSymbol {
                    ordinal: 33,
                    name: Some("glFrontFace".to_string()),
                    target: ExportTarget::Rva(0x4a200),
                },
                ExportSymbol {
                    ordinal: 34,
                    name: Some("glHint".to_string()),
                    target: ExportTarget::Rva(0x4a210),
                },
                ExportSymbol {
                    ordinal: 35,
                    name: Some("glShadeModel".to_string()),
                    target: ExportTarget::Rva(0x4a220),
                },
                ExportSymbol {
                    ordinal: 36,
                    name: Some("glFlush".to_string()),
                    target: ExportTarget::Rva(0x4a230),
                },
                ExportSymbol {
                    ordinal: 37,
                    name: Some("glFinish".to_string()),
                    target: ExportTarget::Rva(0x4a240),
                },
                ExportSymbol {
                    ordinal: 38,
                    name: Some("glGetString".to_string()),
                    target: ExportTarget::Rva(0x4a250),
                },
                ExportSymbol {
                    ordinal: 39,
                    name: Some("glGetError".to_string()),
                    target: ExportTarget::Rva(0x4a260),
                },
                ExportSymbol {
                    ordinal: 40,
                    name: Some("glReadPixels".to_string()),
                    target: ExportTarget::Rva(0x4a270),
                },
                ExportSymbol {
                    ordinal: 41,
                    name: Some("glDrawArrays".to_string()),
                    target: ExportTarget::Rva(0x4a280),
                },
                ExportSymbol {
                    ordinal: 42,
                    name: Some("glDrawElements".to_string()),
                    target: ExportTarget::Rva(0x4a290),
                },
                ExportSymbol {
                    ordinal: 43,
                    name: Some("glVertexPointer".to_string()),
                    target: ExportTarget::Rva(0x4a2a0),
                },
                ExportSymbol {
                    ordinal: 44,
                    name: Some("glTexCoordPointer".to_string()),
                    target: ExportTarget::Rva(0x4a2b0),
                },
                ExportSymbol {
                    ordinal: 45,
                    name: Some("glColorPointer".to_string()),
                    target: ExportTarget::Rva(0x4a2c0),
                },
                ExportSymbol {
                    ordinal: 46,
                    name: Some("glNormalPointer".to_string()),
                    target: ExportTarget::Rva(0x4a2d0),
                },
                ExportSymbol {
                    ordinal: 47,
                    name: Some("glEnableClientState".to_string()),
                    target: ExportTarget::Rva(0x4a2e0),
                },
                ExportSymbol {
                    ordinal: 48,
                    name: Some("glDisableClientState".to_string()),
                    target: ExportTarget::Rva(0x4a2f0),
                },
                ExportSymbol {
                    ordinal: 49,
                    name: Some("glPushMatrix".to_string()),
                    target: ExportTarget::Rva(0x4a300),
                },
                ExportSymbol {
                    ordinal: 50,
                    name: Some("glPopMatrix".to_string()),
                    target: ExportTarget::Rva(0x4a310),
                },
                ExportSymbol {
                    ordinal: 51,
                    name: Some("glRotatef".to_string()),
                    target: ExportTarget::Rva(0x4a320),
                },
                ExportSymbol {
                    ordinal: 52,
                    name: Some("glTranslatef".to_string()),
                    target: ExportTarget::Rva(0x4a330),
                },
                ExportSymbol {
                    ordinal: 53,
                    name: Some("glScalef".to_string()),
                    target: ExportTarget::Rva(0x4a340),
                },
                ExportSymbol {
                    ordinal: 54,
                    name: Some("glOrtho".to_string()),
                    target: ExportTarget::Rva(0x4a350),
                },
                ExportSymbol {
                    ordinal: 55,
                    name: Some("gluPerspective".to_string()),
                    target: ExportTarget::Rva(0x4a360),
                },
                ExportSymbol {
                    ordinal: 56,
                    name: Some("gluLookAt".to_string()),
                    target: ExportTarget::Rva(0x4a370),
                },
                ExportSymbol {
                    ordinal: 57,
                    name: Some("glLightfv".to_string()),
                    target: ExportTarget::Rva(0x4a380),
                },
                ExportSymbol {
                    ordinal: 58,
                    name: Some("glMaterialfv".to_string()),
                    target: ExportTarget::Rva(0x4a390),
                },
                ExportSymbol {
                    ordinal: 59,
                    name: Some("glFogi".to_string()),
                    target: ExportTarget::Rva(0x4a3a0),
                },
                ExportSymbol {
                    ordinal: 60,
                    name: Some("glFogf".to_string()),
                    target: ExportTarget::Rva(0x4a3b0),
                },
            ],
        ),
        (
            "qedit.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("AMGetErrorText".to_string()),
                    target: ExportTarget::Rva(0x4b000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CreateErrorInfo".to_string()),
                    target: ExportTarget::Rva(0x4b010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CreateFilter".to_string()),
                    target: ExportTarget::Rva(0x4b020),
                },
            ],
        ),
        (
            "riched20.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("RichEdit10ANSIWndClass".to_string()),
                    target: ExportTarget::Rva(0x4c000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ITextDocument".to_string()),
                    target: ExportTarget::Rva(0x4c010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CreateTextServices".to_string()),
                    target: ExportTarget::Rva(0x4c020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("ShutdownTextServices".to_string()),
                    target: ExportTarget::Rva(0x4c030),
                },
            ],
        ),
        (
            "riched32.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("RichEditANSIWndClass".to_string()),
                target: ExportTarget::Rva(0x4d000),
            }],
        ),
        (
            "shdocvw.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("SHCreateLinks".to_string()),
                    target: ExportTarget::Rva(0x4e000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("SHNavigateToFavorite".to_string()),
                    target: ExportTarget::Rva(0x4e010),
                },
            ],
        ),
        (
            "uiautomationcore.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("UiaGetPatternProvider".to_string()),
                    target: ExportTarget::Rva(0x4f000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("UiaGetRuntimeId".to_string()),
                    target: ExportTarget::Rva(0x4f010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("UiaRaiseAutomationEvent".to_string()),
                    target: ExportTarget::Rva(0x4f020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("UiaRaiseAutomationPropertyChangedEvent".to_string()),
                    target: ExportTarget::Rva(0x4f030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("UiaLookupId".to_string()),
                    target: ExportTarget::Rva(0x4f040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("UiaNavigate".to_string()),
                    target: ExportTarget::Rva(0x4f050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("UiaGetUpdatedCache".to_string()),
                    target: ExportTarget::Rva(0x4f060),
                },
            ],
        ),
        (
            "userenv.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CreateAppContainerProfile".to_string()),
                    target: ExportTarget::Rva(0x50000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DeleteAppContainerProfile".to_string()),
                    target: ExportTarget::Rva(0x50010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("GetAppContainerProfilePath".to_string()),
                    target: ExportTarget::Rva(0x50020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("GetProfilesDirectoryW".to_string()),
                    target: ExportTarget::Rva(0x50030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("GetProfileType".to_string()),
                    target: ExportTarget::Rva(0x50040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("LoadUserProfileW".to_string()),
                    target: ExportTarget::Rva(0x50050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("UnloadUserProfile".to_string()),
                    target: ExportTarget::Rva(0x50060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("CreateEnvironmentBlock".to_string()),
                    target: ExportTarget::Rva(0x50070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("DestroyEnvironmentBlock".to_string()),
                    target: ExportTarget::Rva(0x50080),
                },
            ],
        ),
        (
            "winhttp.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WinHttpOpen".to_string()),
                    target: ExportTarget::Rva(0x51000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WinHttpCloseHandle".to_string()),
                    target: ExportTarget::Rva(0x51010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WinHttpConnect".to_string()),
                    target: ExportTarget::Rva(0x51020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WinHttpOpenRequest".to_string()),
                    target: ExportTarget::Rva(0x51030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("WinHttpSendRequest".to_string()),
                    target: ExportTarget::Rva(0x51040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("WinHttpReceiveResponse".to_string()),
                    target: ExportTarget::Rva(0x51050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("WinHttpReadData".to_string()),
                    target: ExportTarget::Rva(0x51060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("WinHttpWriteData".to_string()),
                    target: ExportTarget::Rva(0x51070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("WinHttpQueryHeaders".to_string()),
                    target: ExportTarget::Rva(0x51080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("WinHttpSetOption".to_string()),
                    target: ExportTarget::Rva(0x51090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("WinHttpQueryOption".to_string()),
                    target: ExportTarget::Rva(0x510a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("WinHttpAddRequestHeaders".to_string()),
                    target: ExportTarget::Rva(0x510b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("WinHttpSetCredentials".to_string()),
                    target: ExportTarget::Rva(0x510c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("WinHttpTimeFromSystemTime".to_string()),
                    target: ExportTarget::Rva(0x510d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("WinHttpTimeToSystemTime".to_string()),
                    target: ExportTarget::Rva(0x510e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("WinHttpCrackUrl".to_string()),
                    target: ExportTarget::Rva(0x510f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("WinHttpCreateUrl".to_string()),
                    target: ExportTarget::Rva(0x51100),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("WinHttpDetectAutoProxyConfigUrl".to_string()),
                    target: ExportTarget::Rva(0x51110),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("WinHttpGetProxyForUrl".to_string()),
                    target: ExportTarget::Rva(0x51120),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("WinHttpGetIEProxyConfigForCurrentUser".to_string()),
                    target: ExportTarget::Rva(0x51130),
                },
                ExportSymbol {
                    ordinal: 21,
                    name: Some("WinHttpWebSocketCompleteUpgrade".to_string()),
                    target: ExportTarget::Rva(0x51140),
                },
                ExportSymbol {
                    ordinal: 22,
                    name: Some("WinHttpWebSocketSend".to_string()),
                    target: ExportTarget::Rva(0x51150),
                },
                ExportSymbol {
                    ordinal: 23,
                    name: Some("WinHttpWebSocketReceive".to_string()),
                    target: ExportTarget::Rva(0x51160),
                },
                ExportSymbol {
                    ordinal: 24,
                    name: Some("WinHttpWebSocketClose".to_string()),
                    target: ExportTarget::Rva(0x51170),
                },
                ExportSymbol {
                    ordinal: 25,
                    name: Some("WinHttpWebSocketQueryCloseStatus".to_string()),
                    target: ExportTarget::Rva(0x51180),
                },
            ],
        ),
        (
            "winmmbase.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("waveOutOpen".to_string()),
                    target: ExportTarget::Rva(0x52000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("waveOutClose".to_string()),
                    target: ExportTarget::Rva(0x52010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("waveOutWrite".to_string()),
                    target: ExportTarget::Rva(0x52020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("waveOutReset".to_string()),
                    target: ExportTarget::Rva(0x52030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("waveOutGetVolume".to_string()),
                    target: ExportTarget::Rva(0x52040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("waveOutSetVolume".to_string()),
                    target: ExportTarget::Rva(0x52050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("waveOutGetDevCapsW".to_string()),
                    target: ExportTarget::Rva(0x52060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("waveOutGetNumDevs".to_string()),
                    target: ExportTarget::Rva(0x52070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("waveInOpen".to_string()),
                    target: ExportTarget::Rva(0x52080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("waveInClose".to_string()),
                    target: ExportTarget::Rva(0x52090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("waveInPrepareHeader".to_string()),
                    target: ExportTarget::Rva(0x520a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("waveInUnprepareHeader".to_string()),
                    target: ExportTarget::Rva(0x520b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("waveInAddBuffer".to_string()),
                    target: ExportTarget::Rva(0x520c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("waveInStart".to_string()),
                    target: ExportTarget::Rva(0x520d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("waveInStop".to_string()),
                    target: ExportTarget::Rva(0x520e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("waveInGetDevCapsW".to_string()),
                    target: ExportTarget::Rva(0x520f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("waveInGetNumDevs".to_string()),
                    target: ExportTarget::Rva(0x52100),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("midiOutOpen".to_string()),
                    target: ExportTarget::Rva(0x52110),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("midiOutClose".to_string()),
                    target: ExportTarget::Rva(0x52120),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("midiOutShortMsg".to_string()),
                    target: ExportTarget::Rva(0x52130),
                },
                ExportSymbol {
                    ordinal: 21,
                    name: Some("midiOutLongMsg".to_string()),
                    target: ExportTarget::Rva(0x52140),
                },
                ExportSymbol {
                    ordinal: 22,
                    name: Some("midiOutReset".to_string()),
                    target: ExportTarget::Rva(0x52150),
                },
                ExportSymbol {
                    ordinal: 23,
                    name: Some("midiOutGetDevCapsW".to_string()),
                    target: ExportTarget::Rva(0x52160),
                },
                ExportSymbol {
                    ordinal: 24,
                    name: Some("midiOutGetNumDevs".to_string()),
                    target: ExportTarget::Rva(0x52170),
                },
                ExportSymbol {
                    ordinal: 25,
                    name: Some("midiInOpen".to_string()),
                    target: ExportTarget::Rva(0x52180),
                },
                ExportSymbol {
                    ordinal: 26,
                    name: Some("midiInClose".to_string()),
                    target: ExportTarget::Rva(0x52190),
                },
                ExportSymbol {
                    ordinal: 27,
                    name: Some("midiInStart".to_string()),
                    target: ExportTarget::Rva(0x521a0),
                },
                ExportSymbol {
                    ordinal: 28,
                    name: Some("midiInStop".to_string()),
                    target: ExportTarget::Rva(0x521b0),
                },
                ExportSymbol {
                    ordinal: 29,
                    name: Some("midiInReset".to_string()),
                    target: ExportTarget::Rva(0x521c0),
                },
            ],
        ),
        (
            "wldap32.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("ldap_init".to_string()),
                    target: ExportTarget::Rva(0x53000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ldap_bind_s".to_string()),
                    target: ExportTarget::Rva(0x53010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("ldap_search_s".to_string()),
                    target: ExportTarget::Rva(0x53020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("ldap_search".to_string()),
                    target: ExportTarget::Rva(0x53030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("ldap_result".to_string()),
                    target: ExportTarget::Rva(0x53040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("ldap_first_entry".to_string()),
                    target: ExportTarget::Rva(0x53050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("ldap_next_entry".to_string()),
                    target: ExportTarget::Rva(0x53060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("ldap_get_values".to_string()),
                    target: ExportTarget::Rva(0x53070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("ldap_get_dn".to_string()),
                    target: ExportTarget::Rva(0x53080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("ldap_memfree".to_string()),
                    target: ExportTarget::Rva(0x53090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("ldap_unbind".to_string()),
                    target: ExportTarget::Rva(0x530a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("ldap_count_entries".to_string()),
                    target: ExportTarget::Rva(0x530b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("ldap_msgfree".to_string()),
                    target: ExportTarget::Rva(0x530c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("ldap_value_free_len".to_string()),
                    target: ExportTarget::Rva(0x530d0),
                },
            ],
        ),
        (
            "wmvcore.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WMCreateReader".to_string()),
                    target: ExportTarget::Rva(0x54000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WMCreateWriter".to_string()),
                    target: ExportTarget::Rva(0x54010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WMCreateEditor".to_string()),
                    target: ExportTarget::Rva(0x54020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WMCreateSyncReader".to_string()),
                    target: ExportTarget::Rva(0x54030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("WMCreateProfileManager".to_string()),
                    target: ExportTarget::Rva(0x54040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("WMCreateIndexer".to_string()),
                    target: ExportTarget::Rva(0x54050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("WMIsContentProtected".to_string()),
                    target: ExportTarget::Rva(0x54060),
                },
            ],
        ),
        (
            "x3daudio1_7.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("X3DAudioInitialize".to_string()),
                    target: ExportTarget::Rva(0x55000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("X3DAudioCalculate".to_string()),
                    target: ExportTarget::Rva(0x55010),
                },
            ],
        ),
        (
            "xactengine3_7.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("XACT3CreateEngine".to_string()),
                    target: ExportTarget::Rva(0x56000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("XACT3CreateEngineWithFlags".to_string()),
                    target: ExportTarget::Rva(0x56010),
                },
            ],
        ),
        (
            "xaudio2_8.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("XAudio2Create".to_string()),
                target: ExportTarget::Rva(0x57000),
            }],
        ),
        (
            "xmllite.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CreateXmlReader".to_string()),
                    target: ExportTarget::Rva(0x58000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CreateXmlReaderInputWithEncoding".to_string()),
                    target: ExportTarget::Rva(0x58010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CreateXmlWriter".to_string()),
                    target: ExportTarget::Rva(0x58020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("CreateXmlWriterOutputWithEncoding".to_string()),
                    target: ExportTarget::Rva(0x58030),
                },
            ],
        ),
        // ── Media/Graphics DLLs ──────────────────────────────────────────────
        (
            "mf.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("MFStartup".to_string()),
                    target: ExportTarget::Rva(0x59000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("MFShutdown".to_string()),
                    target: ExportTarget::Rva(0x59010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("MFCreateMediaType".to_string()),
                    target: ExportTarget::Rva(0x59020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("MFCreateMediaSession".to_string()),
                    target: ExportTarget::Rva(0x59030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("MFCreateSourceResolver".to_string()),
                    target: ExportTarget::Rva(0x59040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("MFCreateTopology".to_string()),
                    target: ExportTarget::Rva(0x59050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("MFCreateTopologyNode".to_string()),
                    target: ExportTarget::Rva(0x59060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("MFGetService".to_string()),
                    target: ExportTarget::Rva(0x59070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("MFCreateSample".to_string()),
                    target: ExportTarget::Rva(0x59080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("MFCreateMemoryBuffer".to_string()),
                    target: ExportTarget::Rva(0x59090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("MFCreateEventQueue".to_string()),
                    target: ExportTarget::Rva(0x590a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("MFCreateAttributes".to_string()),
                    target: ExportTarget::Rva(0x590b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("MFEnumDeviceSources".to_string()),
                    target: ExportTarget::Rva(0x590c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("MFTEnumEx".to_string()),
                    target: ExportTarget::Rva(0x590d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("MFCreateSourceReaderFromURL".to_string()),
                    target: ExportTarget::Rva(0x590e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("MFCreateSourceReaderFromByteStream".to_string()),
                    target: ExportTarget::Rva(0x590f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("MFCreateSinkWriterFromURL".to_string()),
                    target: ExportTarget::Rva(0x59100),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("MFCreateSinkWriterFromMediaSink".to_string()),
                    target: ExportTarget::Rva(0x59110),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("MFCreatePresentationClock".to_string()),
                    target: ExportTarget::Rva(0x59120),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("MFRequireProtectedEnvironment".to_string()),
                    target: ExportTarget::Rva(0x59130),
                },
                ExportSymbol {
                    ordinal: 90,
                    name: Some("IMFMediaSink".to_string()),
                    target: ExportTarget::Rva(0x24300),
                },
            ],
        ),
        (
            "mfreadwrite.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("MFCreateSourceReaderFromURL".to_string()),
                    target: ExportTarget::Rva(0x5a000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("MFCreateSourceReaderFromByteStream".to_string()),
                    target: ExportTarget::Rva(0x5a010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("MFCreateSourceReaderFromMFByteStream".to_string()),
                    target: ExportTarget::Rva(0x5a020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("MFCreateSinkWriterFromURL".to_string()),
                    target: ExportTarget::Rva(0x5a030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("MFCreateSinkWriterFromMediaSink".to_string()),
                    target: ExportTarget::Rva(0x5a040),
                },
            ],
        ),
        (
            "d2d1.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D2D1CreateFactory".to_string()),
                    target: ExportTarget::Rva(0x5b000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D2D1MakeRotateMatrix".to_string()),
                    target: ExportTarget::Rva(0x5b010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D2D1MakeSkewMatrix".to_string()),
                    target: ExportTarget::Rva(0x5b020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D2D1IsMatrixInvertible".to_string()),
                    target: ExportTarget::Rva(0x5b030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("D2D1InvertMatrix".to_string()),
                    target: ExportTarget::Rva(0x5b040),
                },
            ],
        ),
        (
            "d3d10.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3D10CreateDevice".to_string()),
                    target: ExportTarget::Rva(0x5c000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3D10CreateDeviceAndSwapChain".to_string()),
                    target: ExportTarget::Rva(0x5c010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3D10CreateEffectFromMemory".to_string()),
                    target: ExportTarget::Rva(0x5c020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3D10CreateStateBlock".to_string()),
                    target: ExportTarget::Rva(0x5c030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("D3D10RegisterLayers".to_string()),
                    target: ExportTarget::Rva(0x5c040),
                },
            ],
        ),
        (
            "d3d10_1.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3D10CreateDevice1".to_string()),
                    target: ExportTarget::Rva(0x5d000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3D10CreateDeviceAndSwapChain1".to_string()),
                    target: ExportTarget::Rva(0x5d010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3D10CreateEffectFromMemory".to_string()),
                    target: ExportTarget::Rva(0x5d020),
                },
            ],
        ),
        // ── System DLLs ───────────────────────────────────────────────────────
        (
            "wlanapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WlanOpenHandle".to_string()),
                    target: ExportTarget::Rva(0x5e000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WlanCloseHandle".to_string()),
                    target: ExportTarget::Rva(0x5e010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WlanEnumInterfaces".to_string()),
                    target: ExportTarget::Rva(0x5e020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WlanGetAvailableNetworkList".to_string()),
                    target: ExportTarget::Rva(0x5e030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("WlanQueryInterface".to_string()),
                    target: ExportTarget::Rva(0x5e040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("WlanScan".to_string()),
                    target: ExportTarget::Rva(0x5e050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("WlanConnect".to_string()),
                    target: ExportTarget::Rva(0x5e060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("WlanDisconnect".to_string()),
                    target: ExportTarget::Rva(0x5e070),
                },
            ],
        ),
        (
            "wevtapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("EvtOpenSession".to_string()),
                    target: ExportTarget::Rva(0x5f000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("EvtOpenLog".to_string()),
                    target: ExportTarget::Rva(0x5f010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("EvtQuery".to_string()),
                    target: ExportTarget::Rva(0x5f020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("EvtNext".to_string()),
                    target: ExportTarget::Rva(0x5f030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("EvtClose".to_string()),
                    target: ExportTarget::Rva(0x5f040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("EvtRender".to_string()),
                    target: ExportTarget::Rva(0x5f050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("EvtSubscribe".to_string()),
                    target: ExportTarget::Rva(0x5f060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("EvtCreateBookmark".to_string()),
                    target: ExportTarget::Rva(0x5f070),
                },
            ],
        ),
        (
            "printui.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("PrintUIToDevice".to_string()),
                    target: ExportTarget::Rva(0x60000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("PrintUIToFile".to_string()),
                    target: ExportTarget::Rva(0x60010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("PrintUIEntry".to_string()),
                    target: ExportTarget::Rva(0x60020),
                },
            ],
        ),
        (
            "winspool.drv".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("OpenPrinter".to_string()),
                    target: ExportTarget::Rva(0x61000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ClosePrinter".to_string()),
                    target: ExportTarget::Rva(0x61010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("StartDocPrinter".to_string()),
                    target: ExportTarget::Rva(0x61020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("EndDocPrinter".to_string()),
                    target: ExportTarget::Rva(0x61030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("StartPagePrinter".to_string()),
                    target: ExportTarget::Rva(0x61040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("EndPagePrinter".to_string()),
                    target: ExportTarget::Rva(0x61050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("WritePrinter".to_string()),
                    target: ExportTarget::Rva(0x61060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("ReadPrinter".to_string()),
                    target: ExportTarget::Rva(0x61070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("EnumPrinters".to_string()),
                    target: ExportTarget::Rva(0x61080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("GetPrinter".to_string()),
                    target: ExportTarget::Rva(0x61090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("SetPrinter".to_string()),
                    target: ExportTarget::Rva(0x610a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("AddPrinter".to_string()),
                    target: ExportTarget::Rva(0x610b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("DeletePrinter".to_string()),
                    target: ExportTarget::Rva(0x610c0),
                },
            ],
        ),
        (
            "sapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("SpCreateObjectFromToken".to_string()),
                    target: ExportTarget::Rva(0x62000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("SpCreateObjectFromKey".to_string()),
                    target: ExportTarget::Rva(0x62010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("SpGetCategoryFromId".to_string()),
                    target: ExportTarget::Rva(0x62020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("SpEnumTokens".to_string()),
                    target: ExportTarget::Rva(0x62030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("SpGetDescription".to_string()),
                    target: ExportTarget::Rva(0x62040),
                },
            ],
        ),
        (
            "rasapi32.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("RasDial".to_string()),
                    target: ExportTarget::Rva(0x63000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("RasHangUp".to_string()),
                    target: ExportTarget::Rva(0x63010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("RasEnumConnections".to_string()),
                    target: ExportTarget::Rva(0x63020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("RasGetErrorString".to_string()),
                    target: ExportTarget::Rva(0x63030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("RasGetConnectionStatus".to_string()),
                    target: ExportTarget::Rva(0x63040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("RasSetEntryProperties".to_string()),
                    target: ExportTarget::Rva(0x63050),
                },
            ],
        ),
        // ── C++ Runtime DLLs ──────────────────────────────────────────────────
        (
            "msvcp140.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("_Mtx_init".to_string()),
                    target: ExportTarget::Rva(0x64000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("_Mtx_destroy".to_string()),
                    target: ExportTarget::Rva(0x64010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("_Mtx_lock".to_string()),
                    target: ExportTarget::Rva(0x64020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("_Mtx_unlock".to_string()),
                    target: ExportTarget::Rva(0x64030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("_Cnd_init".to_string()),
                    target: ExportTarget::Rva(0x64040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("_Cnd_destroy".to_string()),
                    target: ExportTarget::Rva(0x64050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("_Cnd_signal".to_string()),
                    target: ExportTarget::Rva(0x64060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("_Cnd_broadcast".to_string()),
                    target: ExportTarget::Rva(0x64070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("_Cnd_wait".to_string()),
                    target: ExportTarget::Rva(0x64080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("_Xbad_alloc".to_string()),
                    target: ExportTarget::Rva(0x64090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("_Xinvalid_argument".to_string()),
                    target: ExportTarget::Rva(0x640a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("_Xlength_error".to_string()),
                    target: ExportTarget::Rva(0x640b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("_Xout_of_range".to_string()),
                    target: ExportTarget::Rva(0x640c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("_Xoverflow_error".to_string()),
                    target: ExportTarget::Rva(0x640d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("_Xruntime_error".to_string()),
                    target: ExportTarget::Rva(0x640e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("std::_Throw_C_error".to_string()),
                    target: ExportTarget::Rva(0x640f0),
                },
                ExportSymbol {
                    ordinal: 17,
                    name: Some("std::_Throw_Cpp_error".to_string()),
                    target: ExportTarget::Rva(0x64100),
                },
                ExportSymbol {
                    ordinal: 18,
                    name: Some("std::random_device::_Init".to_string()),
                    target: ExportTarget::Rva(0x64110),
                },
                ExportSymbol {
                    ordinal: 19,
                    name: Some("std::random_device::_Get".to_string()),
                    target: ExportTarget::Rva(0x64120),
                },
                ExportSymbol {
                    ordinal: 20,
                    name: Some("_Mtx_current".to_string()),
                    target: ExportTarget::Rva(0x64130),
                },
                ExportSymbol {
                    ordinal: 21,
                    name: Some("_Mtx_reset".to_string()),
                    target: ExportTarget::Rva(0x64140),
                },
            ],
        ),
        (
            "vcruntime140.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("memcpy".to_string()),
                    target: ExportTarget::Rva(0x65000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("memset".to_string()),
                    target: ExportTarget::Rva(0x65010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("memmove".to_string()),
                    target: ExportTarget::Rva(0x65020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("strchr".to_string()),
                    target: ExportTarget::Rva(0x65030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("strrchr".to_string()),
                    target: ExportTarget::Rva(0x65040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("strstr".to_string()),
                    target: ExportTarget::Rva(0x65050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("strncmp".to_string()),
                    target: ExportTarget::Rva(0x65060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("strncpy".to_string()),
                    target: ExportTarget::Rva(0x65070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("strlen".to_string()),
                    target: ExportTarget::Rva(0x65080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("wcschr".to_string()),
                    target: ExportTarget::Rva(0x65090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("wcsrchr".to_string()),
                    target: ExportTarget::Rva(0x650a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("wcsstr".to_string()),
                    target: ExportTarget::Rva(0x650b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("wcsncmp".to_string()),
                    target: ExportTarget::Rva(0x650c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("wcsncpy".to_string()),
                    target: ExportTarget::Rva(0x650d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("wcslen".to_string()),
                    target: ExportTarget::Rva(0x650e0),
                },
            ],
        ),
        (
            "vcruntime140_1.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("__C_specific_handler".to_string()),
                    target: ExportTarget::Rva(0x66000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("_chkstk".to_string()),
                    target: ExportTarget::Rva(0x66010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("__current_exception".to_string()),
                    target: ExportTarget::Rva(0x66020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("__current_exception_context".to_string()),
                    target: ExportTarget::Rva(0x66030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("__processing_throw".to_string()),
                    target: ExportTarget::Rva(0x66040),
                },
            ],
        ),
        (
            "msvcp140_1.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("_Mtx_init".to_string()),
                    target: ExportTarget::Rva(0x67000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("_Mtx_destroy".to_string()),
                    target: ExportTarget::Rva(0x67010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("_Mtx_lock".to_string()),
                    target: ExportTarget::Rva(0x67020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("_Mtx_unlock".to_string()),
                    target: ExportTarget::Rva(0x67030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("_Cnd_init".to_string()),
                    target: ExportTarget::Rva(0x67040),
                },
            ],
        ),
        (
            "msvcp140_2.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("_Mtx_init".to_string()),
                    target: ExportTarget::Rva(0x68000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("_Mtx_destroy".to_string()),
                    target: ExportTarget::Rva(0x68010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("_Mtx_lock".to_string()),
                    target: ExportTarget::Rva(0x68020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("_Mtx_unlock".to_string()),
                    target: ExportTarget::Rva(0x68030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("_Cnd_init".to_string()),
                    target: ExportTarget::Rva(0x68040),
                },
            ],
        ),
        // ── COM/OLE DLLs ───────────────────────────────────────────────────────
        (
            "actxprxy.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x69000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0x69010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x69020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x69030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DllInstall".to_string()),
                    target: ExportTarget::Rva(0x69040),
                },
            ],
        ),
        (
            "atl.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("AtlModuleAddTermFunc".to_string()),
                    target: ExportTarget::Rva(0x6a000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("AtlModuleRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x6a010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("AtlModuleUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x6a020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("AtlModuleRegisterTypeLib".to_string()),
                    target: ExportTarget::Rva(0x6a030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("AtlModuleUnregisterTypeLib".to_string()),
                    target: ExportTarget::Rva(0x6a040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("AtlModuleLoadTypeLib".to_string()),
                    target: ExportTarget::Rva(0x6a050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("AtlModuleUpdateRegistryFromResource".to_string()),
                    target: ExportTarget::Rva(0x6a060),
                },
            ],
        ),
        (
            "atl100.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("AtlModuleAddTermFunc".to_string()),
                    target: ExportTarget::Rva(0x6b000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("AtlModuleRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x6b010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("AtlModuleUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x6b020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("AtlModuleRegisterTypeLib".to_string()),
                    target: ExportTarget::Rva(0x6b030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("AtlModuleUnregisterTypeLib".to_string()),
                    target: ExportTarget::Rva(0x6b040),
                },
            ],
        ),
        (
            "atl80.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("AtlModuleAddTermFunc".to_string()),
                    target: ExportTarget::Rva(0x6c000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("AtlModuleRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x6c010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("AtlModuleUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x6c020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("AtlModuleRegisterTypeLib".to_string()),
                    target: ExportTarget::Rva(0x6c030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("AtlModuleUnregisterTypeLib".to_string()),
                    target: ExportTarget::Rva(0x6c040),
                },
            ],
        ),
        // ── Storage/Setup DLLs ─────────────────────────────────────────────────
        (
            "msimsg.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("MsiFormatRecordW".to_string()),
                    target: ExportTarget::Rva(0x6d000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("MsiGetLastErrorRecord".to_string()),
                    target: ExportTarget::Rva(0x6d010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("MsiProcessMessage".to_string()),
                    target: ExportTarget::Rva(0x6d020),
                },
            ],
        ),
        (
            "wimgapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WIMCreateFile".to_string()),
                    target: ExportTarget::Rva(0x6e000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WIMCloseHandle".to_string()),
                    target: ExportTarget::Rva(0x6e010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WIMLoadImage".to_string()),
                    target: ExportTarget::Rva(0x6e020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WIMUnmountImageHandle".to_string()),
                    target: ExportTarget::Rva(0x6e030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("WIMApplyImage".to_string()),
                    target: ExportTarget::Rva(0x6e040),
                },
            ],
        ),
        (
            "vssapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CreateVssBackupComponents".to_string()),
                    target: ExportTarget::Rva(0x6f000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("VssFreeSnapshotProperties".to_string()),
                    target: ExportTarget::Rva(0x6f010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("VssFreeWriterMetadata".to_string()),
                    target: ExportTarget::Rva(0x6f020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("VssFreeComponent".to_string()),
                    target: ExportTarget::Rva(0x6f030),
                },
            ],
        ),
        // ── Steam-related DLLs ─────────────────────────────────────────────────
        (
            "steam_api.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("SteamAPI_Init".to_string()),
                    target: ExportTarget::Rva(0x70000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("SteamAPI_Shutdown".to_string()),
                    target: ExportTarget::Rva(0x70010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("SteamAPI_RestartAppIfNecessary".to_string()),
                    target: ExportTarget::Rva(0x70020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("SteamAPI_RegisterCallback".to_string()),
                    target: ExportTarget::Rva(0x70030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("SteamAPI_UnregisterCallback".to_string()),
                    target: ExportTarget::Rva(0x70040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("SteamAPI_RegisterCallResult".to_string()),
                    target: ExportTarget::Rva(0x70050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("SteamAPI_UnregisterCallResult".to_string()),
                    target: ExportTarget::Rva(0x70060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("SteamAPI_RunCallbacks".to_string()),
                    target: ExportTarget::Rva(0x70070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("SteamAPI_GetSteamInstallPath".to_string()),
                    target: ExportTarget::Rva(0x70080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("SteamAPI_WriteMiniDump".to_string()),
                    target: ExportTarget::Rva(0x70090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("SteamAPI_SetMiniDumpComment".to_string()),
                    target: ExportTarget::Rva(0x700a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("SteamInternal_CreateInterface".to_string()),
                    target: ExportTarget::Rva(0x700b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("SteamInternal_FindOrCreateUserInterface".to_string()),
                    target: ExportTarget::Rva(0x700c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("SteamInternal_FindOrCreateGameInterface".to_string()),
                    target: ExportTarget::Rva(0x700d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("SteamInternal_ContextInit".to_string()),
                    target: ExportTarget::Rva(0x700e0),
                },
            ],
        ),
        (
            "steam_api64.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("SteamAPI_Init".to_string()),
                    target: ExportTarget::Rva(0x71000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("SteamAPI_Shutdown".to_string()),
                    target: ExportTarget::Rva(0x71010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("SteamAPI_RestartAppIfNecessary".to_string()),
                    target: ExportTarget::Rva(0x71020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("SteamAPI_RegisterCallback".to_string()),
                    target: ExportTarget::Rva(0x71030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("SteamAPI_UnregisterCallback".to_string()),
                    target: ExportTarget::Rva(0x71040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("SteamAPI_RegisterCallResult".to_string()),
                    target: ExportTarget::Rva(0x71050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("SteamAPI_UnregisterCallResult".to_string()),
                    target: ExportTarget::Rva(0x71060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("SteamAPI_RunCallbacks".to_string()),
                    target: ExportTarget::Rva(0x71070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("SteamAPI_GetSteamInstallPath".to_string()),
                    target: ExportTarget::Rva(0x71080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("SteamAPI_WriteMiniDump".to_string()),
                    target: ExportTarget::Rva(0x71090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("SteamAPI_SetMiniDumpComment".to_string()),
                    target: ExportTarget::Rva(0x710a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("SteamInternal_CreateInterface".to_string()),
                    target: ExportTarget::Rva(0x710b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("SteamInternal_FindOrCreateUserInterface".to_string()),
                    target: ExportTarget::Rva(0x710c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("SteamInternal_FindOrCreateGameInterface".to_string()),
                    target: ExportTarget::Rva(0x710d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("SteamInternal_ContextInit".to_string()),
                    target: ExportTarget::Rva(0x710e0),
                },
            ],
        ),
        (
            "Steam.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("Steam_BGetSteamID".to_string()),
                    target: ExportTarget::Rva(0x72000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("Steam_BIsSubscribedApp".to_string()),
                    target: ExportTarget::Rva(0x72010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("Steam_BLoggedOn".to_string()),
                    target: ExportTarget::Rva(0x72020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("Steam_NotifyOfLogin".to_string()),
                    target: ExportTarget::Rva(0x72030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("Steam_NotifyOfLogoff".to_string()),
                    target: ExportTarget::Rva(0x72040),
                },
            ],
        ),
        (
            "GameOverlayRenderer.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("OverlayHookWindow".to_string()),
                    target: ExportTarget::Rva(0x73000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("OverlayUnhookWindow".to_string()),
                    target: ExportTarget::Rva(0x73010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("OverlayPresent".to_string()),
                    target: ExportTarget::Rva(0x73020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("OverlayReset".to_string()),
                    target: ExportTarget::Rva(0x73030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("OverlayCreateHook".to_string()),
                    target: ExportTarget::Rva(0x73040),
                },
            ],
        ),
        (
            "GameOverlayRenderer64.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("OverlayHookWindow".to_string()),
                    target: ExportTarget::Rva(0x74000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("OverlayUnhookWindow".to_string()),
                    target: ExportTarget::Rva(0x74010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("OverlayPresent".to_string()),
                    target: ExportTarget::Rva(0x74020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("OverlayReset".to_string()),
                    target: ExportTarget::Rva(0x74030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("OverlayCreateHook".to_string()),
                    target: ExportTarget::Rva(0x74040),
                },
            ],
        ),
        // ── Network/Security DLLs ──────────────────────────────────────────────
        (
            "winrnr.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("RNRInitialize".to_string()),
                    target: ExportTarget::Rva(0x75000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("RNRQuery".to_string()),
                    target: ExportTarget::Rva(0x75010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("RNRCancelQuery".to_string()),
                    target: ExportTarget::Rva(0x75020),
                },
            ],
        ),
        (
            "cryptng.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("BCryptOpenAlgorithmProvider".to_string()),
                    target: ExportTarget::Rva(0x76000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("BCryptCloseAlgorithmProvider".to_string()),
                    target: ExportTarget::Rva(0x76010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("BCryptGenerateSymmetricKey".to_string()),
                    target: ExportTarget::Rva(0x76020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("BCryptEncrypt".to_string()),
                    target: ExportTarget::Rva(0x76030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("BCryptDecrypt".to_string()),
                    target: ExportTarget::Rva(0x76040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("BCryptHash".to_string()),
                    target: ExportTarget::Rva(0x76050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("BCryptGenRandom".to_string()),
                    target: ExportTarget::Rva(0x76060),
                },
            ],
        ),
        (
            "dpapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CryptProtectData".to_string()),
                    target: ExportTarget::Rva(0x77000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CryptUnprotectData".to_string()),
                    target: ExportTarget::Rva(0x77010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CryptProtectMemory".to_string()),
                    target: ExportTarget::Rva(0x77020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("CryptUnprotectMemory".to_string()),
                    target: ExportTarget::Rva(0x77030),
                },
            ],
        ),
        // ── Audio/Video DLLs ───────────────────────────────────────────────────
        (
            "wmcodecdsp.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WMCDSPCreateDecoder".to_string()),
                    target: ExportTarget::Rva(0x78000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WMCDSPCreateEncoder".to_string()),
                    target: ExportTarget::Rva(0x78010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WMCDSPCreateProcessor".to_string()),
                    target: ExportTarget::Rva(0x78020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WMCDSPCreateResampler".to_string()),
                    target: ExportTarget::Rva(0x78030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("WMCDSPCreateConverter".to_string()),
                    target: ExportTarget::Rva(0x78040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("WMCDSPCreateAudioDecoder".to_string()),
                    target: ExportTarget::Rva(0x78050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("WMCDSPCreateAudioEncoder".to_string()),
                    target: ExportTarget::Rva(0x78060),
                },
            ],
        ),
        (
            "mp3dmod.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x79000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x79010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x79020),
                },
            ],
        ),
        (
            "colorcnv.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x7a000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x7a010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x7a020),
                },
            ],
        ),
        (
            "resampledmo.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x7b000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x7b010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x7b020),
                },
            ],
        ),
        (
            "mfh264enc.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x7c000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x7c010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x7c020),
                },
            ],
        ),
        (
            "mfmpeg2src.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x7d000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x7d010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x7d020),
                },
            ],
        ),
        // ── Graphics: Direct3D 9/10/11 Legacy ──────────────────────────────────────
        (
            "d3d9.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("Direct3DCreate9".to_string()),
                    target: ExportTarget::Rva(0x7e000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("Direct3DCreate9Ex".to_string()),
                    target: ExportTarget::Rva(0x7e010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3DPERF_BeginEvent".to_string()),
                    target: ExportTarget::Rva(0x7e020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3DPERF_EndEvent".to_string()),
                    target: ExportTarget::Rva(0x7e030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("D3DPERF_SetMarker".to_string()),
                    target: ExportTarget::Rva(0x7e040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("D3DPERF_QueryRepeatFrame".to_string()),
                    target: ExportTarget::Rva(0x7e050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("D3DPERF_SetOptions".to_string()),
                    target: ExportTarget::Rva(0x7e060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("D3DPERF_GetStatus".to_string()),
                    target: ExportTarget::Rva(0x7e070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("DebugSetLevel".to_string()),
                    target: ExportTarget::Rva(0x7e080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("DebugSetMute".to_string()),
                    target: ExportTarget::Rva(0x7e090),
                },
            ],
        ),
        (
            "d3d10core.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3D10CoreCreateDevice".to_string()),
                    target: ExportTarget::Rva(0x7f000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3D10CoreCreateLayeredDevice".to_string()),
                    target: ExportTarget::Rva(0x7f010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3D10CoreGetSupportedVersions".to_string()),
                    target: ExportTarget::Rva(0x7f020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3D10CoreRegisterLayers".to_string()),
                    target: ExportTarget::Rva(0x7f030),
                },
            ],
        ),
        (
            "d3d10level9.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3D10Level9CreateDevice".to_string()),
                    target: ExportTarget::Rva(0x80000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3D10Level9GetSupportedVersions".to_string()),
                    target: ExportTarget::Rva(0x80010),
                },
            ],
        ),
        (
            "d3dx11_43.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("D3DX11CreateTextureFromFileW".to_string()),
                    target: ExportTarget::Rva(0x81000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("D3DX11CreateShaderResourceViewFromFileW".to_string()),
                    target: ExportTarget::Rva(0x81010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("D3DX11CompileFromFileW".to_string()),
                    target: ExportTarget::Rva(0x81020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("D3DX11SaveTextureToFileW".to_string()),
                    target: ExportTarget::Rva(0x81030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("D3DX11GetImageInfoFromFileW".to_string()),
                    target: ExportTarget::Rva(0x81040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("D3DX11CreateTextureFromMemory".to_string()),
                    target: ExportTarget::Rva(0x81050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("D3DX11LoadTextureFromTexture".to_string()),
                    target: ExportTarget::Rva(0x81060),
                },
            ],
        ),
        // ── Windows Imaging Component (WIC) ───────────────────────────────────────
        (
            "windowscodecs.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WICCreateImagingFactory_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WICCreateColorContext_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WICCreateBitmap_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WICCreateBitmapFromSection_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("WICCreateStream_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("WICCreateFormatConverter_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("WICCreatePalette_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("WICCreateBitmapScaler_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("WICCreateBitmapClipper_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("WICCreateBitmapFlipRotator_Proxy".to_string()),
                    target: ExportTarget::Rva(0x82090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("WICCreateImagingFactory".to_string()),
                    target: ExportTarget::Rva(0x820a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("WICGetMetadataContentSize".to_string()),
                    target: ExportTarget::Rva(0x820b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("WICMapSchemaToName".to_string()),
                    target: ExportTarget::Rva(0x820c0),
                },
                ExportSymbol {
                    ordinal: 14,
                    name: Some("WICSerializeMetadataContent".to_string()),
                    target: ExportTarget::Rva(0x820d0),
                },
                ExportSymbol {
                    ordinal: 15,
                    name: Some("WICMatchMetadataContent".to_string()),
                    target: ExportTarget::Rva(0x820e0),
                },
                ExportSymbol {
                    ordinal: 16,
                    name: Some("WICCreateComponentInfo".to_string()),
                    target: ExportTarget::Rva(0x820f0),
                },
            ],
        ),
        (
            "windowscodecsext.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WICCreateHeifDecoder".to_string()),
                    target: ExportTarget::Rva(0x83000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WICCreateHeifEncoder".to_string()),
                    target: ExportTarget::Rva(0x83010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WICCreateWebpDecoder".to_string()),
                    target: ExportTarget::Rva(0x83020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WICCreateWebpEncoder".to_string()),
                    target: ExportTarget::Rva(0x83030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("WICCreateAvifDecoder".to_string()),
                    target: ExportTarget::Rva(0x83040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("WICCreateAvifEncoder".to_string()),
                    target: ExportTarget::Rva(0x83050),
                },
            ],
        ),
        // ── Legacy DirectDraw / DirectInput / DirectPlay ──────────────────────────
        (
            "ddraw.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DirectDrawCreate".to_string()),
                    target: ExportTarget::Rva(0x84000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DirectDrawCreateEx".to_string()),
                    target: ExportTarget::Rva(0x84010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DirectDrawEnumerateExW".to_string()),
                    target: ExportTarget::Rva(0x84020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DirectDrawEnumerateW".to_string()),
                    target: ExportTarget::Rva(0x84030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0x84040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x84050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x84060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x84070),
                },
            ],
        ),
        (
            "dinput.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DirectInputCreateW".to_string()),
                    target: ExportTarget::Rva(0x85000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DirectInputCreateEx".to_string()),
                    target: ExportTarget::Rva(0x85010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0x85020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x85030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x85040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x85050),
                },
            ],
        ),
        (
            "dplay.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DirectPlayCreate".to_string()),
                    target: ExportTarget::Rva(0x86000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DirectPlayEnumerateW".to_string()),
                    target: ExportTarget::Rva(0x86010),
                },
            ],
        ),
        (
            "dpnet.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DirectPlay8Create".to_string()),
                    target: ExportTarget::Rva(0x87000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DP8SPCreate".to_string()),
                    target: ExportTarget::Rva(0x87010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0x87020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x87030),
                },
            ],
        ),
        (
            "dpaddr.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DP8SPCreate".to_string()),
                    target: ExportTarget::Rva(0x88000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DirectPlay8AddressCreate".to_string()),
                    target: ExportTarget::Rva(0x88010),
                },
            ],
        ),
        // ── DirectShow ────────────────────────────────────────────────────────────
        (
            "quartz.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("AMGetErrorTextW".to_string()),
                    target: ExportTarget::Rva(0x89000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0x89010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x89020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x89030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x89040),
                },
            ],
        ),
        (
            "amstream.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0x8a000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x8a010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x8a020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x8a030),
                },
            ],
        ),
        // ── Media Foundation Codecs ───────────────────────────────────────────────
        (
            "mfaacenc.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x8b000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x8b010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x8b020),
                },
            ],
        ),
        (
            "mfvpxdec.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x8c000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x8c010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x8c020),
                },
            ],
        ),
        (
            "msmpeg2adec.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x8d000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x8d010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x8d020),
                },
            ],
        ),
        (
            "msmpeg2vdec.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x8e000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x8e010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x8e020),
                },
            ],
        ),
        (
            "mpg4decdmod.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x8f000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x8f010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x8f020),
                },
            ],
        ),
        (
            "encapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x90000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x90010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x90020),
                },
            ],
        ),
        // ── Windows Media Player / Indeo ──────────────────────────────────────────
        (
            "msdxm.ocx".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x91000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x91010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x91020),
                },
            ],
        ),
        (
            "wmp.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x92000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x92010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x92020),
                },
            ],
        ),
        (
            "ir50_qc.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x93000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x93010),
                },
            ],
        ),
        (
            "ir50_qcx.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x94000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x94010),
                },
            ],
        ),
        // ── Audio: Core Audio API ─────────────────────────────────────────────────
        (
            "audioses.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("AudioSessionize".to_string()),
                    target: ExportTarget::Rva(0x95000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("AudioSessionFromHWND".to_string()),
                    target: ExportTarget::Rva(0x95010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("AudioSessionFromGuid".to_string()),
                    target: ExportTarget::Rva(0x95020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("AudioSessionFromString".to_string()),
                    target: ExportTarget::Rva(0x95030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x95040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x95050),
                },
            ],
        ),
        (
            "audioendpoint.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0x96000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0x96010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0x96020),
                },
            ],
        ),
        (
            "xapofx1_5.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("XAudio2Create".to_string()),
                    target: ExportTarget::Rva(0x97000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CreateFX".to_string()),
                    target: ExportTarget::Rva(0x97010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0x97020),
                },
            ],
        ),
        // ── Security / Cryptography ───────────────────────────────────────────────
        (
            "cryptui.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CryptUIDlgCertMgr".to_string()),
                    target: ExportTarget::Rva(0x98000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CryptUIDlgSelectCertificateW".to_string()),
                    target: ExportTarget::Rva(0x98010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CryptUIDlgViewCertificateW".to_string()),
                    target: ExportTarget::Rva(0x98020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("CryptUIDlgSelectStoreW".to_string()),
                    target: ExportTarget::Rva(0x98030),
                },
            ],
        ),
        (
            "cryptdlg.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CertDigestDigest".to_string()),
                    target: ExportTarget::Rva(0x99000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CertSelectCertificate".to_string()),
                    target: ExportTarget::Rva(0x99010),
                },
            ],
        ),
        (
            "credssp.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CredSSPGetServerCredential".to_string()),
                    target: ExportTarget::Rva(0x9a000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CredSSPGetClientCredential".to_string()),
                    target: ExportTarget::Rva(0x9a010),
                },
            ],
        ),
        (
            "schannel.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("InitSecurityInterfaceW".to_string()),
                    target: ExportTarget::Rva(0x9b000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("SslGetDataToWrite".to_string()),
                    target: ExportTarget::Rva(0x9b010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("SslLoadCertificate".to_string()),
                    target: ExportTarget::Rva(0x9b020),
                },
            ],
        ),
        (
            "cryptdll.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CryptEncodeObject".to_string()),
                    target: ExportTarget::Rva(0x9c000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CryptDecodeObject".to_string()),
                    target: ExportTarget::Rva(0x9c010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CryptExportPKCS8".to_string()),
                    target: ExportTarget::Rva(0x9c020),
                },
            ],
        ),
        (
            "scecli.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("ScGenerateRelativeName".to_string()),
                    target: ExportTarget::Rva(0x9d000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ScRemoveAllPrivileges".to_string()),
                    target: ExportTarget::Rva(0x9d010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("ScSetSecurityDescriptor".to_string()),
                    target: ExportTarget::Rva(0x9d020),
                },
            ],
        ),
        (
            "rsaenh.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CPAcquireContext".to_string()),
                    target: ExportTarget::Rva(0x9e000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CPReleaseContext".to_string()),
                    target: ExportTarget::Rva(0x9e010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CPGenKey".to_string()),
                    target: ExportTarget::Rva(0x9e020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("CPEncrypt".to_string()),
                    target: ExportTarget::Rva(0x9e030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("CPDecrypt".to_string()),
                    target: ExportTarget::Rva(0x9e040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("CPHashData".to_string()),
                    target: ExportTarget::Rva(0x9e050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("CPVerifySignature".to_string()),
                    target: ExportTarget::Rva(0x9e060),
                },
            ],
        ),
        (
            "cngaudit.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("CngAuditLog".to_string()),
                target: ExportTarget::Rva(0x9f000),
            }],
        ),
        (
            "certadm.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CertSrvAdminGetCA".to_string()),
                    target: ExportTarget::Rva(0xa0000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CertSrvAdminSetCA".to_string()),
                    target: ExportTarget::Rva(0xa0010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CertSrvAdminGetCert".to_string()),
                    target: ExportTarget::Rva(0xa0020),
                },
            ],
        ),
        (
            "certcli.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CertSrvBackupPrepare".to_string()),
                    target: ExportTarget::Rva(0xa1000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CertSrvBackupEnd".to_string()),
                    target: ExportTarget::Rva(0xa1010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("CertSrvRestorePrepare".to_string()),
                    target: ExportTarget::Rva(0xa1020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("CertSrvRestoreEnd".to_string()),
                    target: ExportTarget::Rva(0xa1030),
                },
            ],
        ),
        // ── Network: Winsock / DNS ────────────────────────────────────────────────
        (
            "mswsock.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WSARecvEx".to_string()),
                    target: ExportTarget::Rva(0xa2000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("TransmitFile".to_string()),
                    target: ExportTarget::Rva(0xa2010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("AcceptEx".to_string()),
                    target: ExportTarget::Rva(0xa2020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("GetAcceptExSockaddrs".to_string()),
                    target: ExportTarget::Rva(0xa2030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("EnumProtocolsW".to_string()),
                    target: ExportTarget::Rva(0xa2040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("WSAGetOverlappedResult".to_string()),
                    target: ExportTarget::Rva(0xa2050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("WSASocketW".to_string()),
                    target: ExportTarget::Rva(0xa2060),
                },
            ],
        ),
        (
            "msafd.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WSPStartup".to_string()),
                    target: ExportTarget::Rva(0xa3000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WSPCleanup".to_string()),
                    target: ExportTarget::Rva(0xa3010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WSPSocket".to_string()),
                    target: ExportTarget::Rva(0xa3020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WSPBind".to_string()),
                    target: ExportTarget::Rva(0xa3030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("WSPListen".to_string()),
                    target: ExportTarget::Rva(0xa3040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("WSPAccept".to_string()),
                    target: ExportTarget::Rva(0xa3050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("WSPConnect".to_string()),
                    target: ExportTarget::Rva(0xa3060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("WSPSend".to_string()),
                    target: ExportTarget::Rva(0xa3070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("WSPRecv".to_string()),
                    target: ExportTarget::Rva(0xa3080),
                },
            ],
        ),
        // ── .NET / Runtime ────────────────────────────────────────────────────────
        (
            "mscorwks.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CorBindToRuntimeEx".to_string()),
                    target: ExportTarget::Rva(0xa4000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("CorBindToRuntime".to_string()),
                    target: ExportTarget::Rva(0xa4010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("GetCLRRuntimeHost".to_string()),
                    target: ExportTarget::Rva(0xa4020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("ClrCreateManagedInstance".to_string()),
                    target: ExportTarget::Rva(0xa4030),
                },
            ],
        ),
        (
            "mscorlib.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xa5000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xa5010),
                },
            ],
        ),
        (
            "msvbvm60.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllCall".to_string()),
                    target: ExportTarget::Rva(0xa6000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllFunc".to_string()),
                    target: ExportTarget::Rva(0xa6010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllMain".to_string()),
                    target: ExportTarget::Rva(0xa6020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllProc".to_string()),
                    target: ExportTarget::Rva(0xa6030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("BASIC_CLASS_AddRef".to_string()),
                    target: ExportTarget::Rva(0xa6040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("BASIC_CLASS_Release".to_string()),
                    target: ExportTarget::Rva(0xa6050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("BASIC_CLASS_QueryInterface".to_string()),
                    target: ExportTarget::Rva(0xa6060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("BASIC_CLASS_Invoke".to_string()),
                    target: ExportTarget::Rva(0xa6070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("BASIC_DISPINTERFACE_Invoke".to_string()),
                    target: ExportTarget::Rva(0xa6080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("BASIC_CLASS_GetIDsOfNames".to_string()),
                    target: ExportTarget::Rva(0xa6090),
                },
            ],
        ),
        // ── WPF / Presentation ────────────────────────────────────────────────────
        (
            "presentationframework.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xa7000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xa7010),
                },
            ],
        ),
        (
            "presentationcore.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xa8000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xa8010),
                },
            ],
        ),
        (
            "windowsbase.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xa9000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xa9010),
                },
            ],
        ),
        // ── Scripting ─────────────────────────────────────────────────────────────
        (
            "vbscript.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xaa000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xaa010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xaa020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0xaa030),
                },
            ],
        ),
        (
            "jscript.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xab000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xab010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xab020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0xab030),
                },
            ],
        ),
        (
            "scrrun.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xac000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xac010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xac020),
                },
            ],
        ),
        // ── XML ───────────────────────────────────────────────────────────────────
        (
            "msxml6.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xad000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xad010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xad020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0xad030),
                },
            ],
        ),
        // ── Text Services ─────────────────────────────────────────────────────────
        (
            "msctf.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("TF_CreateThreadMgr".to_string()),
                    target: ExportTarget::Rva(0xae000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("TF_CreateCategoryMgr".to_string()),
                    target: ExportTarget::Rva(0xae010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("TF_CreateDisplayAttributeMgr".to_string()),
                    target: ExportTarget::Rva(0xae020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("TF_GetThreadMgr".to_string()),
                    target: ExportTarget::Rva(0xae030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("TF_InitSystem".to_string()),
                    target: ExportTarget::Rva(0xae040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("TF_UninitSystem".to_string()),
                    target: ExportTarget::Rva(0xae050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xae060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xae070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xae080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0xae090),
                },
            ],
        ),
        (
            "msimtf.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xaf000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xaf010),
                },
            ],
        ),
        // ── WMI ───────────────────────────────────────────────────────────────────
        (
            "wbemprox.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WMIInitialize".to_string()),
                    target: ExportTarget::Rva(0xb0000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WMIClose".to_string()),
                    target: ExportTarget::Rva(0xb0010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WMIConnect".to_string()),
                    target: ExportTarget::Rva(0xb0020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("WMIQuery".to_string()),
                    target: ExportTarget::Rva(0xb0030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb0040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb0050),
                },
            ],
        ),
        (
            "wbemcomn.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb1000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb1010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xb1020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0xb1030),
                },
            ],
        ),
        (
            "fastprox.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb2000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb2010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xb2020),
                },
            ],
        ),
        (
            "wbemdisp.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb3000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb3010),
                },
            ],
        ),
        (
            "wmi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb4000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb4010),
                },
            ],
        ),
        // ── WebView2 ──────────────────────────────────────────────────────────────
        (
            "webview2.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("CreateWebView2Environment".to_string()),
                    target: ExportTarget::Rva(0xb5000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb5010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb5020),
                },
            ],
        ),
        // ── COM / OLE Support ─────────────────────────────────────────────────────
        (
            "asycfilt.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb6000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb6010),
                },
            ],
        ),
        (
            "comsvcs.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb7000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb7010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xb7020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DllCanUnloadNow".to_string()),
                    target: ExportTarget::Rva(0xb7030),
                },
            ],
        ),
        (
            "clbcatq.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb8000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb8010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xb8020),
                },
            ],
        ),
        (
            "mtxdm.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xb9000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xb9010),
                },
            ],
        ),
        // ── ESENT / Database ──────────────────────────────────────────────────────
        (
            "esent.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("JetInit".to_string()),
                    target: ExportTarget::Rva(0xba000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("JetTerm".to_string()),
                    target: ExportTarget::Rva(0xba010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("JetCreateDatabase".to_string()),
                    target: ExportTarget::Rva(0xba020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("JetAttachDatabase".to_string()),
                    target: ExportTarget::Rva(0xba030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("JetDetachDatabase".to_string()),
                    target: ExportTarget::Rva(0xba040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("JetOpenTable".to_string()),
                    target: ExportTarget::Rva(0xba050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("JetCloseTable".to_string()),
                    target: ExportTarget::Rva(0xba060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("JetOpenDatabase".to_string()),
                    target: ExportTarget::Rva(0xba070),
                },
                ExportSymbol {
                    ordinal: 9,
                    name: Some("JetCloseDatabase".to_string()),
                    target: ExportTarget::Rva(0xba080),
                },
                ExportSymbol {
                    ordinal: 10,
                    name: Some("JetBeginTransaction".to_string()),
                    target: ExportTarget::Rva(0xba090),
                },
                ExportSymbol {
                    ordinal: 11,
                    name: Some("JetCommitTransaction".to_string()),
                    target: ExportTarget::Rva(0xba0a0),
                },
                ExportSymbol {
                    ordinal: 12,
                    name: Some("JetRollback".to_string()),
                    target: ExportTarget::Rva(0xba0b0),
                },
                ExportSymbol {
                    ordinal: 13,
                    name: Some("JetGetTableColumnInfo".to_string()),
                    target: ExportTarget::Rva(0xba0c0),
                },
            ],
        ),
        // ── OLE DB ───────────────────────────────────────────────────────────────
        (
            "msdart.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xbb000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xbb010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DllGetClassObject".to_string()),
                    target: ExportTarget::Rva(0xbb020),
                },
            ],
        ),
        // ── Performance Counters ──────────────────────────────────────────────────
        (
            "pdh.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("PdhOpenQuery".to_string()),
                    target: ExportTarget::Rva(0xbc000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("PdhCloseQuery".to_string()),
                    target: ExportTarget::Rva(0xbc010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("PdhAddCounter".to_string()),
                    target: ExportTarget::Rva(0xbc020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("PdhRemoveCounter".to_string()),
                    target: ExportTarget::Rva(0xbc030),
                },
                ExportSymbol {
                    ordinal: 5,
                    name: Some("PdhCollectQueryData".to_string()),
                    target: ExportTarget::Rva(0xbc040),
                },
                ExportSymbol {
                    ordinal: 6,
                    name: Some("PdhGetFormattedCounterValue".to_string()),
                    target: ExportTarget::Rva(0xbc050),
                },
                ExportSymbol {
                    ordinal: 7,
                    name: Some("PdhEnumObjects".to_string()),
                    target: ExportTarget::Rva(0xbc060),
                },
                ExportSymbol {
                    ordinal: 8,
                    name: Some("PdhEnumCounters".to_string()),
                    target: ExportTarget::Rva(0xbc070),
                },
            ],
        ),
        // ── Terminal Services / WinStation ────────────────────────────────────────
        (
            "winsta.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("WinStationOpenServer".to_string()),
                    target: ExportTarget::Rva(0xbd000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("WinStationCloseServer".to_string()),
                    target: ExportTarget::Rva(0xbd010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("WinStationEnumerate".to_string()),
                    target: ExportTarget::Rva(0xbd020),
                },
            ],
        ),
        // ── Windows Update ────────────────────────────────────────────────────────
        (
            "wuapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xbe000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xbe010),
                },
            ],
        ),
        (
            "sens.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xbf000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xbf010),
                },
            ],
        ),
        // ── SSAS / Analysis Services ──────────────────────────────────────────────
        (
            "msmdlocal.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xc0000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xc0010),
                },
            ],
        ),
        // ── WinRM ─────────────────────────────────────────────────────────────────
        (
            "winrsmgr.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DllRegisterServer".to_string()),
                    target: ExportTarget::Rva(0xc1000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DllUnregisterServer".to_string()),
                    target: ExportTarget::Rva(0xc1010),
                },
            ],
        ),
        // ── Network Management APIs ───────────────────────────────────────────────
        (
            "netutils.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("NetGetDCName".to_string()),
                    target: ExportTarget::Rva(0xc2000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("NetGetAnyDCName".to_string()),
                    target: ExportTarget::Rva(0xc2010),
                },
            ],
        ),
        (
            "samlib.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("SamConnect".to_string()),
                    target: ExportTarget::Rva(0xc3000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("SamCloseHandle".to_string()),
                    target: ExportTarget::Rva(0xc3010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("SamOpenDomain".to_string()),
                    target: ExportTarget::Rva(0xc3020),
                },
            ],
        ),
        (
            "activeds.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("ADsGetObject".to_string()),
                    target: ExportTarget::Rva(0xc4000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("ADsOpenObject".to_string()),
                    target: ExportTarget::Rva(0xc4010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("ADsBuildEnumerator".to_string()),
                    target: ExportTarget::Rva(0xc4020),
                },
            ],
        ),
        (
            "ntdsapi.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("DsBind".to_string()),
                    target: ExportTarget::Rva(0xc5000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("DsUnbind".to_string()),
                    target: ExportTarget::Rva(0xc5010),
                },
                ExportSymbol {
                    ordinal: 3,
                    name: Some("DsBindWithCred".to_string()),
                    target: ExportTarget::Rva(0xc5020),
                },
                ExportSymbol {
                    ordinal: 4,
                    name: Some("DsMakeSpnW".to_string()),
                    target: ExportTarget::Rva(0xc5030),
                },
            ],
        ),
        (
            "w32topl.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("DsBindToTopology".to_string()),
                target: ExportTarget::Rva(0xc6000),
            }],
        ),
        // ── Server / Workstation APIs ─────────────────────────────────────────────
        (
            "wkssvc.dll".to_string(),
            vec![
                ExportSymbol {
                    ordinal: 1,
                    name: Some("NetWkstaGetInfo".to_string()),
                    target: ExportTarget::Rva(0xc7000),
                },
                ExportSymbol {
                    ordinal: 2,
                    name: Some("NetWkstaSetInfo".to_string()),
                    target: ExportTarget::Rva(0xc7010),
                },
            ],
        ),
        (
            "srvsvc.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("NetServerGetInfo".to_string()),
                target: ExportTarget::Rva(0xc8000),
            }],
        ),
        (
            "browser.dll".to_string(),
            vec![ExportSymbol {
                ordinal: 1,
                name: Some("BrowserServerEnum".to_string()),
                target: ExportTarget::Rva(0xc9000),
            }],
        ),
    ]);
    merge_registered_surface_exports(&mut tables);
    tables
}

/// Merge the host-thunk metadata surface into the registered export
/// tables.
///
/// Every (DLL, export) covered by [`crate::host_thunks::THUNK_METADATA`]
/// must be present in the registered export surface and vice versa
/// (asserted by tests/section45_thunk_metadata.rs).  These are the
/// metadata entries that the per-DLL synthetic tables above predate.
pub(crate) fn merge_registered_surface_exports(tables: &mut BTreeMap<String, Vec<ExportSymbol>>) {
    const SURFACE: &[(&str, &[&str])] = &[
        (
            "advapi32.dll",
            &[
                "DeregisterEventSource",
                "InitializeSecurityDescriptor",
                "RegCreateKeyExA",
                "RegOpenKeyA",
                "RegOpenKeyExA",
                "RegQueryValueExA",
                "RegSetValueExA",
                "RegisterEventSourceW",
                "ReportEventW",
                "SetSecurityDescriptorDacl",
            ],
        ),
        ("crypt32.dll", &["CertFreeCertificateChain"]),
        (
            "gdi32.dll",
            &[
                "AddFontMemResourceEx",
                "ChoosePixelFormat",
                "CreateICW",
                "RemoveFontMemResourceEx",
                "SetPixelFormat",
                "SwapBuffers",
            ],
        ),
        (
            "kernel32.dll",
            &[
                "CallNamedPipeW",
                "CompareStringW",
                "ConnectNamedPipe",
                "ConvertFiberToThread",
                "ConvertThreadToFiber",
                "CreateFiber",
                "CreateFileA",
                "CreateFileMappingW",
                "CreateMutexW",
                "CreateNamedPipeW",
                "CreateSemaphoreW",
                "DebugBreak",
                "DecodePointer",
                "DeleteFiber",
                "DeviceIoControl",
                "DisableThreadLibraryCalls",
                "EncodePointer",
                "ExitThread",
                "FileTimeToSystemTime",
                "FindFirstFileExW",
                "FindResourceA",
                "GetACP",
                "GetCPInfo",
                "GetCommandLineA",
                "GetConsoleCP",
                "GetConsoleMode",
                "GetCurrentDirectoryA",
                "GetCurrentProcessId",
                "GetCurrentThreadId",
                "GetDateFormatW",
                "GetDiskFreeSpaceA",
                "GetDriveTypeW",
                "GetFileAttributesA",
                "GetFileInformationByHandleEx",
                "GetFileSizeEx",
                "GetFileTime",
                "GetFileType",
                "GetModuleHandleExA",
                "GetModuleHandleExW",
                "GetOEMCP",
                "GetOverlappedResult",
                "GetProcessAffinityMask",
                "GetProcessHeap",
                "GetProcessHeaps",
                "GetStartupInfoW",
                "GetStdHandle",
                "GetStringTypeW",
                "GetSystemInfo",
                "GetSystemTime",
                "GetTickCount64",
                "GetTimeFormatW",
                "GetVersionExA",
                "GetVersionExW",
                "GlobalMemoryStatusEx",
                "HeapAlloc",
                "HeapFree",
                "HeapLock",
                "HeapQueryInformation",
                "HeapReAlloc",
                "HeapSetInformation",
                "HeapSize",
                "HeapUnlock",
                "HeapValidate",
                "HeapWalk",
                "InitializeCriticalSectionAndSpinCount",
                "InitializeCriticalSectionEx",
                "InitializeSListHead",
                "InterlockedCompareExchange",
                "InterlockedDecrement",
                "InterlockedExchange",
                "InterlockedExchangeAdd",
                "InterlockedIncrement",
                "InterlockedPushEntrySList",
                "IsBadWritePtr",
                "IsProcessorFeaturePresent",
                "IsValidCodePage",
                "LCMapStringW",
                "LoadResource",
                "LocalAlloc",
                "LocalFree",
                "LockResource",
                "MapViewOfFile",
                "OpenMutexW",
                "OpenProcess",
                "OpenSemaphoreW",
                "OpenThread",
                "PeekNamedPipe",
                "QueryPerformanceCounter",
                "QueryPerformanceFrequency",
                "RaiseException",
                "ReadConsoleA",
                "ReadConsoleW",
                "ReleaseMutex",
                "ReleaseSemaphore",
                "RemoveDirectoryA",
                "ResumeThread",
                "RtlUnwind",
                "SetConsoleCtrlHandler",
                "SetConsoleMode",
                "SetEndOfFile",
                "SetFilePointerEx",
                "SetHandleInformation",
                "SetLastError",
                "SetProcessAffinityMask",
                "SetStdHandle",
                "SetThreadAffinityMask",
                "SetThreadPriority",
                "SizeofResource",
                "SleepEx",
                "SuspendThread",
                "SwitchToFiber",
                "SwitchToThread",
                "SystemTimeToFileTime",
                "SystemTimeToTzSpecificLocalTime",
                "TerminateThread",
                "TlsAlloc",
                "TlsFree",
                "TlsSetValue",
                "UnmapViewOfFile",
                "VerSetConditionMask",
                "WaitForMultipleObjects",
                "WaitForSingleObjectEx",
                "WriteConsoleW",
            ],
        ),
        ("msvcrt.dll", &["_errno", "printf"]),
        (
            "psapi.dll",
            &[
                "EnumProcesses",
                "GetModuleBaseNameW",
                "GetModuleFileNameExW",
                "GetModuleInformation",
                "GetProcessMemoryInfo",
            ],
        ),
        ("shell32.dll", &["CommandLineToArgvW", "IsUserAnAdmin"]),
        (
            "user32.dll",
            &[
                "AllowSetForegroundWindow",
                "BeginPaint",
                "CloseClipboard",
                "DestroyWindow",
                "DialogBoxParamA",
                "EmptyClipboard",
                "EndDialog",
                "EndPaint",
                "EnumChildWindows",
                "EnumWindows",
                "GetClassInfoExW",
                "GetDC",
                "GetDesktopWindow",
                "GetDlgItem",
                "GetDlgItemInt",
                "GetFocus",
                "GetMessageA",
                "GetMonitorInfoW",
                "GetProcessWindowStation",
                "GetSystemMetrics",
                "GetUserObjectInformationW",
                "GetWindowLongW",
                "GetWindowRect",
                "GetWindowTextA",
                "GetWindowTextLengthA",
                "GetWindowTextW",
                "GetWindowThreadProcessId",
                "InvalidateRect",
                "IsWindowVisible",
                "KillTimer",
                "LoadCursorW",
                "MapWindowPoints",
                "MessageBoxA",
                "MonitorFromPoint",
                "MonitorFromWindow",
                "MoveWindow",
                "MsgWaitForMultipleObjects",
                "OpenClipboard",
                "PostMessageA",
                "PostMessageW",
                "RegisterClassW",
                "ReleaseDC",
                "SendMessageW",
                "SetClassLongW",
                "SetClipboardData",
                "SetDlgItemInt",
                "SetDlgItemTextA",
                "SetFocus",
                "SetTimer",
                "SetWindowLongW",
                "SetWindowPos",
                "SetWindowTextW",
                "ShowWindow",
                "UnregisterClassW",
                "UpdateWindow",
                "wsprintfA",
            ],
        ),
        ("ws2_32.dll", &["WSASocketA", "getsockname"]),
        ("wsock32.dll", &["WSAStartup"]),
    ];
    for (dll, names) in SURFACE {
        let table = tables.entry(dll.to_string()).or_default();
        // Continue each DLL's ordinal sequence (the synthetic tables are
        // ordinal-continuous; tests/section1.rs asserts that).
        let next_ordinal = table
            .iter()
            .map(|export| export.ordinal)
            .max()
            .map_or(1, |max| max + 1);
        let base_rva = table
            .iter()
            .filter_map(|export| match export.target {
                ExportTarget::Rva(rva) => Some(rva),
                ExportTarget::Forwarder(_) => None,
            })
            .max()
            .map_or(0x1000, |max| max + 0x10);
        for (index, name) in names.iter().enumerate() {
            table.push(ExportSymbol {
                ordinal: next_ordinal + index as u32,
                name: Some((*name).to_string()),
                target: ExportTarget::Rva(base_rva + index as u32 * 0x10),
            });
        }
    }
}

pub(crate) fn extend_named_exports(
    exports: &mut Vec<ExportSymbol>,
    starting_ordinal: u32,
    starting_rva: u32,
    names: &[&str],
) {
    for (index, name) in names.iter().enumerate() {
        exports.push(ExportSymbol {
            ordinal: starting_ordinal + index as u32,
            name: Some((*name).to_string()),
            target: ExportTarget::Rva(starting_rva + index as u32 * 0x10),
        });
    }
}
