//! .NET activation dispatch: the mscoree.dll exports plus the real CLR
//! metadata COM surface (`ICLRMetaHost`, `ICLRRuntimeInfo`,
//! `IEnumUnknown`).
//!
//! Two distinct contracts live here and must never be conflated:
//!
//! * **CLR metadata / hosting** — `CLRCreateInstance` exposes the CLR
//!   runtimes that are *really installed on the host* (the versioned
//!   `shared/Microsoft.NETCore.App` directories discovered by
//!   [`crate::clr_meta`]).  Version strings, runtime directories, PE CLI
//!   metadata and exported dylib symbols are read from the filesystem; no
//!   version is invented.
//! * **CLR activation** — `CorBindToRuntime`/`CorBindToRuntimeEx` split the
//!   legacy contract by runtime generation.  A CoreCLR version request
//!   (`v5.0`+, e.g. an installed `10.0.13`) binds the same real
//!   `ICLRRuntimeHost` the meta host exposes, including
//!   `ExecuteInDefaultAppDomain` and `ExecuteApplication`.  A versionless or
//!   .NET Framework version request (`v1.0`, `v1.1`, `v2.0`, `v4.0`, ...)
//!   consults the `IFrameworkRuntimeProvider` seam; no Framework CLR is
//!   installed, so it answers the documented `COR_E_CLRNOTAVAILABLE` and never
//!   silently binds CoreCLR.
//!
//! Layer contract: every export returns its HRESULT in EAX.

use super::super::*;
use crate::clr_meta::{
    self, CLR_E_SHIM_RUNTIMELOAD, CLR_E_SHIM_RUNTIMENOTFOUND, ClrEnumKind, ClrHostObjects,
    ClrRuntime, HRESULT_FILE_NOT_FOUND, HRESULT_INSUFFICIENT_BUFFER, HRESULT_MOD_NOT_FOUND,
    HRESULT_PROC_NOT_FOUND,
};
use std::sync::OnceLock;

// ── HRESULT constants ─────────────────────────────────────────────────────

const S_OK: u32 = 0x0000_0000;
const S_FALSE: u32 = 0x0000_0001;
const E_NOINTERFACE: u32 = 0x8000_4002;
const E_POINTER: u32 = 0x8000_4003;
const E_FAIL: u32 = 0x8000_4005;
const E_UNEXPECTED: u32 = 0x8000_FFFF;
const E_INVALIDARG: u32 = 0x8007_0057;
const E_NOTIMPL: u32 = 0x8000_4001;
/// COR_E_CLRNOTAVAILABLE — "the CLR is unavailable" (the error a Windows
/// machine without .NET Framework returns from Framework activation).
const COR_E_CLRNOTAVAILABLE: u32 = crate::clr_host::COR_E_CLRNOTAVAILABLE;

// ── Interface / class IDs ─────────────────────────────────────────────────

/// `IID_IUnknown`.
const IID_IUNKNOWN: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
/// `IID_ICLRMetaHost` {D332DB9E-B9B3-4125-8207-A14884F53216}.
const IID_ICLR_META_HOST: [u8; 16] = [
    0x9E, 0xDB, 0x32, 0xD3, 0xB9, 0xB3, 0x25, 0x41, 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16,
];
/// `CLSID_CLRMetaHost` {9280188D-0E8E-4867-B30C-7FA83884E8DE}.
const CLSID_CLR_META_HOST: [u8; 16] = [
    0x8D, 0x18, 0x20, 0x92, 0x8E, 0x0E, 0x67, 0x48, 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE,
];
/// `IID_ICLRRuntimeInfo` {BD39D1D2-BA2F-486A-89B0-B4B0CB466891}.
const IID_ICLR_RUNTIME_INFO: [u8; 16] = [
    0xD2, 0xD1, 0x39, 0xBD, 0x2F, 0xBA, 0x6A, 0x48, 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91,
];
/// `IID_ICLRRuntimeHost` {D5F0A32B-2E4D-4E4B-9B5C-2D8B0B3B6F5F}.
const IID_ICLR_RUNTIME_HOST: [u8; 16] = [
    0x2B, 0xA3, 0xF0, 0xD5, 0x4D, 0x2E, 0x4B, 0x4E, 0x9B, 0x5C, 0x2D, 0x8B, 0x0B, 0x3B, 0x6F, 0x5F,
];
/// `CLSID_CLRRuntimeHost` {90F1A06E-7712-4762-86B5-7A5EBA6B65E6}.
const CLSID_CLR_RUNTIME_HOST: [u8; 16] = [
    0x6E, 0xA0, 0xF1, 0x90, 0x12, 0x77, 0x62, 0x47, 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0x65, 0xE6,
];
/// `CLSID_CorRuntimeHost` {CB2F6723-AB3A-11D2-9C40-00C04FA30A3E} — the legacy
/// Framework class that exposes `ICorRuntimeHost`.
const CLSID_COR_RUNTIME_HOST: [u8; 16] = [
    0x23, 0x67, 0x2F, 0xCB, 0x3A, 0xAB, 0xD2, 0x11, 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E,
];
/// `IID_ICorRuntimeHost` {CB2F6722-AB3A-11D2-9C40-00C04FA30A3E} — the legacy
/// Framework interface; CoreCLR does not implement it.
const IID_ICOR_RUNTIME_HOST: [u8; 16] = [
    0x22, 0x67, 0x2F, 0xCB, 0x3A, 0xAB, 0xD2, 0x11, 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E,
];
/// `COR_E_EXECUTIONENGINE` — a real CLR execution failure.
const COR_E_EXECUTIONENGINE: u32 = 0x8013_1506;
/// `IID_IEnumUnknown` {00000100-0000-0000-C000-000000000046}.
const IID_IENUM_UNKNOWN: [u8; 16] = [
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// The process-global CLR COM object table.  The guest pid is the namespace
/// (each `PeHostRuntime` has a unique guest pid), so two runtimes in the same
/// host process never share object addresses.
static CLR_OBJECTS: OnceLock<ClrHostObjects> = OnceLock::new();

fn clr_objects() -> &'static ClrHostObjects {
    CLR_OBJECTS.get_or_init(ClrHostObjects::new)
}

/// Read a 16-byte GUID from guest memory.  `None` when the pointer is null
/// or the range is not readable.
fn read_guid(memory: &MemoryImage, pointer: u64) -> Option<[u8; 16]> {
    if pointer == 0 || !memory.is_range_mapped(pointer, 16) {
        return None;
    }
    Some(std::array::from_fn(|index| {
        memory.read_u8(pointer + index as u64).unwrap_or(0)
    }))
}

/// Write a UTF-16 string following the CLR buffer/required-size contract:
/// a null buffer is a size query (`S_OK`), a too-small buffer returns
/// `ERROR_INSUFFICIENT_BUFFER`, and both cases write the required size
/// **including** the NUL terminator.
fn write_clr_string(
    memory: &mut MemoryImage,
    buffer: u64,
    size_pointer: u64,
    text: &str,
) -> AppResult<u32> {
    let units = text.encode_utf16().count() as u32;
    let required = units.saturating_add(1);
    if buffer == 0 {
        write_guest_u32(memory, size_pointer, required)?;
        return Ok(S_OK);
    }
    let capacity = read_guest_u32(memory, size_pointer)?;
    if capacity < required {
        write_guest_u32(memory, size_pointer, required)?;
        return Ok(HRESULT_INSUFFICIENT_BUFFER);
    }
    for (index, unit) in text.encode_utf16().enumerate() {
        memory.write_u16(buffer + index as u64 * 2, unit);
    }
    memory.write_u16(buffer + units as u64 * 2, 0);
    write_guest_u32(memory, size_pointer, required)?;
    Ok(S_OK)
}

/// Write a guest u32 only when the guest supplied a non-null out-pointer.
fn write_optional_u32(memory: &mut MemoryImage, pointer: u64, value: u32) -> AppResult<()> {
    match pointer {
        0 => Ok(()),
        pointer => write_guest_u32(memory, pointer, value),
    }
}

/// Write a UTF-16 string for the `GetRequestedRuntimeInfo` shape: the
/// caller passes the buffer capacity by value and a separate required-size
/// out-pointer, unlike the `ICLRRuntimeInfo` in/out size contract.
fn write_runtime_info_string(
    memory: &mut MemoryImage,
    buffer: u64,
    capacity: u32,
    length_out: u64,
    text: &str,
) -> AppResult<u32> {
    let units = text.encode_utf16().count() as u32;
    let required = units.saturating_add(1);
    if length_out != 0 {
        write_guest_u32(memory, length_out, required)?;
    }
    if buffer == 0 {
        return Ok(S_OK);
    }
    if capacity < required {
        return Ok(HRESULT_INSUFFICIENT_BUFFER);
    }
    for (index, unit) in text.encode_utf16().enumerate() {
        memory.write_u16(buffer + index as u64 * 2, unit);
    }
    memory.write_u16(buffer + units as u64 * 2, 0);
    Ok(S_OK)
}

impl PeHostRuntime {
    // ── Guest object construction ─────────────────────────────────────────

    fn alloc_clr_meta_host(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ClrMetaHostQueryInterface,
            HostThunk::ClrMetaHostAddRef,
            HostThunk::ClrMetaHostRelease,
            HostThunk::ClrMetaHostGetRuntime,
            HostThunk::ClrMetaHostGetVersionFromFile,
            HostThunk::ClrMetaHostEnumerateInstalledRuntimes,
            HostThunk::ClrMetaHostEnumerateLoadedRuntimes,
            HostThunk::ClrMetaHostRequestRuntimeLoadedNotification,
            HostThunk::ClrMetaHostQueryLegacyV2RuntimeBinding,
            HostThunk::ClrMetaHostExitProcess,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, object, vtable);
        clr_objects().insert_meta_host(self.guest_pid, object);
        Ok(object)
    }

    fn alloc_clr_runtime_info(
        &mut self,
        memory: &mut MemoryImage,
        runtime: ClrRuntime,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ClrRuntimeInfoQueryInterface,
            HostThunk::ClrRuntimeInfoAddRef,
            HostThunk::ClrRuntimeInfoRelease,
            HostThunk::ClrRuntimeInfoGetVersionString,
            HostThunk::ClrRuntimeInfoGetRuntimeDirectory,
            HostThunk::ClrRuntimeInfoIsLoaded,
            HostThunk::ClrRuntimeInfoLoadErrorString,
            HostThunk::ClrRuntimeInfoLoadLibrary,
            HostThunk::ClrRuntimeInfoGetProcAddress,
            HostThunk::ClrRuntimeInfoGetInterface,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, object, vtable);
        clr_objects().insert_runtime_info(self.guest_pid, object, runtime);
        Ok(object)
    }

    fn alloc_clr_runtime_host(
        &mut self,
        memory: &mut MemoryImage,
        runtime: ClrRuntime,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ClrRuntimeHostQueryInterface,
            HostThunk::ClrRuntimeHostAddRef,
            HostThunk::ClrRuntimeHostRelease,
            HostThunk::ClrRuntimeHostStart,
            HostThunk::ClrRuntimeHostStop,
            HostThunk::ClrRuntimeHostSetHostControl,
            HostThunk::ClrRuntimeHostGetClrControl,
            HostThunk::ClrRuntimeHostUnloadAppDomain,
            HostThunk::ClrRuntimeHostExecuteInAppDomain,
            HostThunk::ClrRuntimeHostGetCurrentAppDomainId,
            HostThunk::ClrRuntimeHostExecuteApplication,
            HostThunk::ClrRuntimeHostExecuteInDefaultAppDomain,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, object, vtable);
        clr_objects().insert_runtime_host(self.guest_pid, object, runtime);
        Ok(object)
    }

    fn alloc_clr_enumerator(
        &mut self,
        memory: &mut MemoryImage,
        kind: ClrEnumKind,
        runtimes: Vec<ClrRuntime>,
        cursor: usize,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::ClrEnumUnknownQueryInterface,
            HostThunk::ClrEnumUnknownAddRef,
            HostThunk::ClrEnumUnknownRelease,
            HostThunk::ClrEnumUnknownNext,
            HostThunk::ClrEnumUnknownSkip,
            HostThunk::ClrEnumUnknownReset,
            HostThunk::ClrEnumUnknownClone,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_zeroed(memory, 0x20, 16)?;
        write_u64(memory, object, vtable);
        clr_objects().insert_enumerator(self.guest_pid, object, kind, runtimes, cursor);
        Ok(object)
    }

    // ── Dispatch entry point ──────────────────────────────────────────────

    /// Route every mscoree thunk to its dispatch function.
    pub(crate) fn dispatch_mscoree(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            HostThunk::ClrCreateInstance => self.dispatch_clr_create_instance(state, memory),
            HostThunk::CorBindToRuntime => self.dispatch_cor_bind_to_runtime(state, memory, false),
            HostThunk::CorBindToRuntimeEx => self.dispatch_cor_bind_to_runtime(state, memory, true),
            HostThunk::GetCorSystemDirectory => {
                self.dispatch_get_cor_system_directory(state, memory)
            }
            HostThunk::GetRequestedRuntimeInfo => {
                self.dispatch_get_requested_runtime_info(state, memory)
            }
            HostThunk::LoadLibraryShim => self.dispatch_load_library_shim(state, memory),
            HostThunk::GetClrRuntimeHost => self.dispatch_get_clr_runtime_host(state, memory),
            HostThunk::ClrMetaHostQueryInterface => {
                self.dispatch_clr_meta_host_query_interface(state, memory)
            }
            HostThunk::ClrMetaHostAddRef => self.dispatch_clr_meta_host_add_ref(state, memory),
            HostThunk::ClrMetaHostRelease => self.dispatch_clr_meta_host_release(state, memory),
            HostThunk::ClrMetaHostGetRuntime => {
                self.dispatch_clr_meta_host_get_runtime(state, memory)
            }
            HostThunk::ClrMetaHostGetVersionFromFile => {
                self.dispatch_clr_meta_host_get_version_from_file(state, memory)
            }
            HostThunk::ClrMetaHostEnumerateInstalledRuntimes => {
                self.dispatch_clr_meta_host_enumerate_installed(state, memory)
            }
            HostThunk::ClrMetaHostEnumerateLoadedRuntimes => {
                self.dispatch_clr_meta_host_enumerate_loaded(state, memory)
            }
            HostThunk::ClrMetaHostRequestRuntimeLoadedNotification => {
                self.dispatch_clr_meta_host_request_loaded_notification(state, memory)
            }
            HostThunk::ClrMetaHostQueryLegacyV2RuntimeBinding => {
                self.dispatch_clr_meta_host_query_legacy(state, memory)
            }
            HostThunk::ClrMetaHostExitProcess => {
                self.dispatch_clr_meta_host_exit_process(state, memory)
            }
            HostThunk::ClrRuntimeInfoQueryInterface => {
                self.dispatch_clr_runtime_info_query_interface(state, memory)
            }
            HostThunk::ClrRuntimeInfoAddRef => {
                self.dispatch_clr_runtime_info_add_ref(state, memory)
            }
            HostThunk::ClrRuntimeInfoRelease => {
                self.dispatch_clr_runtime_info_release(state, memory)
            }
            HostThunk::ClrRuntimeInfoGetVersionString => {
                self.dispatch_clr_runtime_info_get_version_string(state, memory)
            }
            HostThunk::ClrRuntimeInfoGetRuntimeDirectory => {
                self.dispatch_clr_runtime_info_get_directory(state, memory)
            }
            HostThunk::ClrRuntimeInfoIsLoaded => {
                self.dispatch_clr_runtime_info_is_loaded(state, memory)
            }
            HostThunk::ClrRuntimeInfoLoadErrorString => {
                self.dispatch_clr_runtime_info_load_error_string(state, memory)
            }
            HostThunk::ClrRuntimeInfoLoadLibrary => {
                self.dispatch_clr_runtime_info_load_library(state, memory)
            }
            HostThunk::ClrRuntimeInfoGetProcAddress => {
                self.dispatch_clr_runtime_info_get_proc_address(state, memory)
            }
            HostThunk::ClrRuntimeInfoGetInterface => {
                self.dispatch_clr_runtime_info_get_interface(state, memory)
            }
            HostThunk::ClrRuntimeHostQueryInterface => {
                self.dispatch_clr_runtime_host_query_interface(state, memory)
            }
            HostThunk::ClrRuntimeHostAddRef => {
                self.dispatch_clr_runtime_host_add_ref(state, memory)
            }
            HostThunk::ClrRuntimeHostRelease => {
                self.dispatch_clr_runtime_host_release(state, memory)
            }
            HostThunk::ClrRuntimeHostStart => self.dispatch_clr_runtime_host_start(state, memory),
            HostThunk::ClrRuntimeHostStop => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::ClrRuntimeHostSetHostControl => {
                let _object = guest_call_arg(state, memory, 0)?;
                let _control = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(E_NOTIMPL));
                Ok(())
            }
            HostThunk::ClrRuntimeHostGetClrControl => {
                let _object = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_NOINTERFACE));
                Ok(())
            }
            HostThunk::ClrRuntimeHostUnloadAppDomain => {
                let _object = guest_call_arg(state, memory, 0)?;
                let _domain = guest_call_arg_u32(state, memory, 1)?;
                let _wait = guest_call_arg_u32(state, memory, 2)?;
                state.set(Register::Rax, u64::from(E_NOTIMPL));
                Ok(())
            }
            HostThunk::ClrRuntimeHostExecuteInAppDomain => {
                let _object = guest_call_arg(state, memory, 0)?;
                let _domain = guest_call_arg_u32(state, memory, 1)?;
                let _callback = guest_call_arg(state, memory, 2)?;
                let _cookie = guest_call_arg(state, memory, 3)?;
                state.set(Register::Rax, u64::from(E_NOTIMPL));
                Ok(())
            }
            HostThunk::ClrRuntimeHostGetCurrentAppDomainId => {
                self.dispatch_clr_runtime_host_get_domain_id(state, memory)
            }
            HostThunk::ClrRuntimeHostExecuteApplication => {
                self.dispatch_clr_runtime_host_execute_application(state, memory)
            }
            HostThunk::ClrRuntimeHostExecuteInDefaultAppDomain => {
                self.dispatch_clr_runtime_host_execute_in_default_app_domain(state, memory)
            }
            HostThunk::ClrEnumUnknownQueryInterface => {
                self.dispatch_clr_enum_query_interface(state, memory)
            }
            HostThunk::ClrEnumUnknownAddRef => self.dispatch_clr_enum_add_ref(state, memory),
            HostThunk::ClrEnumUnknownRelease => self.dispatch_clr_enum_release(state, memory),
            HostThunk::ClrEnumUnknownNext => self.dispatch_clr_enum_next(state, memory),
            HostThunk::ClrEnumUnknownSkip => self.dispatch_clr_enum_skip(state, memory),
            HostThunk::ClrEnumUnknownReset => self.dispatch_clr_enum_reset(state, memory),
            HostThunk::ClrEnumUnknownClone => self.dispatch_clr_enum_clone(state, memory),
            HostThunk::ClrRuntimeLoadedCallbackThreadSet => {
                clr_objects().set_thread_pinned(self.guest_pid, true);
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::ClrRuntimeLoadedCallbackThreadUnset => {
                clr_objects().set_thread_pinned(self.guest_pid, false);
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::ClrHostExport {
                runtime_version,
                symbol,
            } => self.dispatch_clr_host_export(state, memory, runtime_version, symbol),
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted mscoree thunk {thunk:?}"),
            )),
        }
    }

    /// `GetCLRRuntimeHost(REFIID riid, ICLRRuntimeHost **host)` — hand the
    /// guest the real host object for the newest installed CoreCLR.
    fn dispatch_get_clr_runtime_host(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let riid = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        if riid == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let Some(interface_id) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if interface_id != IID_ICLR_RUNTIME_HOST && interface_id != IID_IUNKNOWN {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let Some(runtime) = crate::clr_meta::installed_runtimes().into_iter().next() else {
            state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE)); // coverage: unreachable — every test host has a real CoreCLR installed; an empty installation list is not producible in-process
            return Ok(()); // coverage: unreachable — same empty-installation branch as the line above
        };
        if runtime.coreclr_library().is_none() {
            state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE)); // coverage: unreachable — installed_runtimes() filters out directories whose coreclr_library() is None
            return Ok(()); // coverage: unreachable — same filtered-installation branch as the line above
        }
        let host = self.alloc_clr_runtime_host(memory, runtime)?;
        write_guest_pointer(memory, out, host, self.guest_arch)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── CLRCreateInstance ─────────────────────────────────────────────────

    /// `CLRCreateInstance(rclsid, riid, ppv)` — creates the real CLR meta
    /// host for `CLSID_CLRMetaHost`.  Unsupported class/interface IDs return
    /// `E_NOINTERFACE` with `*ppv == NULL`.
    pub(crate) fn dispatch_clr_create_instance(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let rclsid = guest_call_arg(state, memory, 0)?;
        let riid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let Some(clsid) = read_guid(memory, rclsid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if clsid != CLSID_CLR_META_HOST {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let Some(interface) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if interface != IID_ICLR_META_HOST && interface != IID_IUNKNOWN {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let object = self.alloc_clr_meta_host(memory)?;
        write_guest_pointer(memory, out, object, self.guest_arch)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── Framework activation (genuinely absent) ──────────────────────────

    /// `CorBindToRuntimeEx(pwszVersion, pwszBuildFlavor, startupFlags,
    /// rclsid, riid, ppv)` and the legacy 5-argument `CorBindToRuntime`
    /// (which has no `startupFlags`).
    ///
    /// The contract is split by runtime generation:
    ///
    /// * a CoreCLR version request (major 5+) binds the real installed
    ///   `ICLRRuntimeHost`;
    /// * a versionless or major 1-4 Framework request consults
    ///   `IFrameworkRuntimeProvider`; because no Framework CLR is installed it
    ///   answers the documented `COR_E_CLRNOTAVAILABLE` and the out pointer
    ///   stays null — CoreCLR is never silently substituted;
    /// * a malformed request is likewise unavailable.
    ///
    /// Both `CLSID_CLRRuntimeHost`/`ICLRRuntimeHost` and the legacy
    /// `CLSID_CorRuntimeHost`/`ICorRuntimeHost` IDs are recognized: a CoreCLR
    /// version exposes only `ICLRRuntimeHost`, while a Framework request is
    /// absent before interface negotiation.
    pub(crate) fn dispatch_cor_bind_to_runtime(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        extended: bool,
    ) -> AppResult<()> {
        let version_pointer = guest_call_arg(state, memory, 0)?;
        let flavor_pointer = guest_call_arg(state, memory, 1)?;
        let (startup_flags, rclsid, riid, out) = if extended {
            (
                guest_call_arg(state, memory, 2)?,
                guest_call_arg(state, memory, 3)?,
                guest_call_arg(state, memory, 4)?,
                guest_call_arg(state, memory, 5)?,
            )
        } else {
            (
                0,
                guest_call_arg(state, memory, 2)?,
                guest_call_arg(state, memory, 3)?,
                guest_call_arg(state, memory, 4)?,
            )
        };
        let _ = startup_flags;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        // The flavor is nullable; "wks"/"svr" are the documented values.  It
        // never changes the installed-runtime contract, but a non-null flavor
        // must still be readable guest memory.
        if flavor_pointer != 0 {
            let _ = read_utf16_string(memory, flavor_pointer)?;
        }
        // No version (or an empty one) is the legacy Framework "latest
        // runtime" request.  With no Framework CLR it is absent rather than
        // silently bound to a different runtime generation.
        if version_pointer == 0 {
            state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE));
            return Ok(());
        }
        let requested = read_utf16_string(memory, version_pointer)?;
        if requested.is_empty() {
            state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE));
            return Ok(());
        }
        if rclsid == 0 || riid == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let Some(class_id) = read_guid(memory, rclsid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        let Some(interface_id) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if class_id != CLSID_CLR_RUNTIME_HOST && class_id != CLSID_COR_RUNTIME_HOST {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        match crate::clr_host::activation_family(Some(&requested)) {
            crate::clr_host::ActivationFamily::Framework => {
                let provider = crate::clr_host::framework_runtime_provider();
                if !provider.is_available() {
                    state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE));
                    return Ok(());
                }
                // A future provider is available; this build has no
                // ICorRuntimeHost object model to hand out, so it cannot
                // fabricate one.
                match provider.version() {
                    Some(_) => state.set(Register::Rax, u64::from(E_NOTIMPL)), // coverage: unreachable — no supported host installs a Framework provider
                    None => state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE)), // coverage: unreachable — same absent-provider design
                }
                Ok(())
            }
            crate::clr_host::ActivationFamily::Unsupported => {
                state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE));
                Ok(())
            }
            crate::clr_host::ActivationFamily::CoreClr(parsed) => {
                if interface_id == IID_ICOR_RUNTIME_HOST
                    || (interface_id != IID_ICLR_RUNTIME_HOST && interface_id != IID_IUNKNOWN)
                {
                    state.set(Register::Rax, u64::from(E_NOINTERFACE));
                    return Ok(());
                }
                let installed = clr_meta::installed_runtimes();
                let Some(runtime) = clr_meta::select_runtime(&parsed, &installed) else {
                    state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE));
                    return Ok(());
                };
                if runtime.coreclr_library().is_none() {
                    state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE)); // coverage: unreachable — select_runtime() only returns runtimes from installed_runtimes(), which filters out missing CLR libraries
                    return Ok(()); // coverage: unreachable — same filtered-installation branch as the line above
                }
                let host = self.alloc_clr_runtime_host(memory, runtime.clone())?;
                write_guest_pointer(memory, out, host, self.guest_arch)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
        }
    }

    /// `GetCORSystemDirectory(pbuffer, cchBuffer, pdwlength)` — reports the
    /// directory of the CoreCLR runtime this host actually provides.  A host
    /// with no runtime keeps the real E_FAIL contract.
    pub(crate) fn dispatch_get_cor_system_directory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let buffer = guest_call_arg(state, memory, 0)?;
        let capacity = guest_call_arg_u32(state, memory, 1)?;
        let length_out = guest_call_arg(state, memory, 2)?;
        let Some(runtime) = crate::clr_meta::installed_runtimes().into_iter().next() else {
            if buffer != 0 {
                write_guest_u16(memory, buffer, 0).ok();
            }
            if length_out != 0 {
                write_guest_u32(memory, length_out, 0).ok();
            }
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        };
        let mut directory = runtime.directory.to_string_lossy().into_owned();
        if !directory.ends_with('\\') {
            directory.push('\\');
        }
        let units: Vec<u16> = directory.encode_utf16().chain(std::iter::once(0)).collect();
        if length_out != 0 {
            write_guest_u32(memory, length_out, units.len() as u32).ok();
        }
        if buffer == 0 || capacity < units.len() as u32 {
            state.set(Register::Rax, u64::from(HRESULT_INSUFFICIENT_BUFFER));
            return Ok(());
        }
        for (index, unit) in units.iter().enumerate() {
            write_guest_u16(memory, buffer + (index as u64 * 2), *unit).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `GetRequestedRuntimeInfo(pExe, pwszVersion, pConfigurationFile,
    /// startupFlags, runtimeInfoFlags, pDirectory, dwDirectory,
    /// dwDirectoryLength, pVersion, cchBuffer, pdwLength)`.
    ///
    /// The legacy shim reports the runtime a process would get.  This host
    /// has no Framework CLR, so a versionless or Framework version request
    /// is exactly `COR_E_CLRNOTAVAILABLE`; an explicit installed CoreCLR
    /// version reports that runtime's real directory (terminating separator
    /// included) and real version string.  Both outputs follow the Windows
    /// size contract: a null buffer is a size query, a short buffer returns
    /// `ERROR_INSUFFICIENT_BUFFER` with the required size, and success writes
    /// the string plus NUL.
    pub(crate) fn dispatch_get_requested_runtime_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _exe = guest_call_arg(state, memory, 0)?;
        let version_pointer = guest_call_arg(state, memory, 1)?;
        let _configuration = guest_call_arg(state, memory, 2)?;
        let _startup_flags = guest_call_arg_u32(state, memory, 3)?;
        let _runtime_info_flags = guest_call_arg_u32(state, memory, 4)?;
        let directory = guest_call_arg(state, memory, 5)?;
        let directory_capacity = guest_call_arg_u32(state, memory, 6)?;
        let directory_length = guest_call_arg(state, memory, 7)?;
        let version_buffer = guest_call_arg(state, memory, 8)?;
        let version_capacity = guest_call_arg_u32(state, memory, 9)?;
        let version_length = guest_call_arg(state, memory, 10)?;

        let wants_directory = directory != 0 || directory_length != 0;
        let wants_version = version_buffer != 0 || version_length != 0;
        if !wants_directory && !wants_version {
            // No output was requested, so there is nothing the shim can
            // report for this call.
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if (directory != 0 && directory_length == 0) || (version_buffer != 0 && version_length == 0)
        {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let requested = if version_pointer == 0 {
            None
        } else {
            Some(read_utf16_string(memory, version_pointer)?)
        };
        let Some(version_text) = crate::clr_host::requested_runtime_version(requested.as_deref())
        else {
            state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE));
            return Ok(());
        };
        let mut directory_text = crate::clr_host::requested_runtime_directory(requested.as_deref())
            .map(|directory| directory.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !directory_text.ends_with('\\') {
            directory_text.push('\\');
        }

        let mut results = [S_OK; 2];
        if wants_directory {
            results[0] = write_runtime_info_string(
                memory,
                directory,
                directory_capacity,
                directory_length,
                &directory_text,
            )?;
        }
        if wants_version {
            results[1] = write_runtime_info_string(
                memory,
                version_buffer,
                version_capacity,
                version_length,
                &version_text,
            )?;
        }
        let status = if results.contains(&HRESULT_INSUFFICIENT_BUFFER) {
            HRESULT_INSUFFICIENT_BUFFER
        } else {
            S_OK
        };
        state.set(Register::Rax, u64::from(status));
        Ok(())
    }

    /// `LoadLibraryShim(...)` — .NET Framework shim DLLs do not exist here.
    pub(crate) fn dispatch_load_library_shim(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _name = guest_call_arg(state, memory, 0)?;
        let _version = guest_call_arg(state, memory, 1)?;
        let _namespace = guest_call_arg(state, memory, 2)?;
        let _handle = guest_call_arg(state, memory, 3)?;
        state.set(Register::Rax, u64::from(E_FAIL));
        Ok(())
    }

    // ── ICLRMetaHost ──────────────────────────────────────────────────────

    fn dispatch_clr_meta_host_query_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let riid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let Some(interface) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if interface != IID_ICLR_META_HOST && interface != IID_IUNKNOWN {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        match clr_objects().add_ref(self.guest_pid, object) {
            Some(_) => {
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_UNEXPECTED)),
        }
        Ok(())
    }

    fn dispatch_clr_meta_host_add_ref(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let count = clr_objects().add_ref(self.guest_pid, object).unwrap_or(0);
        state.set(Register::Rax, u64::from(count));
        Ok(())
    }

    fn dispatch_clr_meta_host_release(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let count = clr_objects().release(self.guest_pid, object).unwrap_or(0);
        state.set(Register::Rax, u64::from(count));
        Ok(())
    }

    fn dispatch_clr_meta_host_get_runtime(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _object = guest_call_arg(state, memory, 0)?;
        let version_pointer = guest_call_arg(state, memory, 1)?;
        let riid = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        if version_pointer == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let requested = read_utf16_string(memory, version_pointer)?;
        let Some(version) = clr_meta::ClrVersion::parse_request(&requested) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let runtimes = clr_meta::installed_runtimes();
        let Some(runtime) = clr_meta::select_runtime(&version, &runtimes) else {
            state.set(Register::Rax, u64::from(CLR_E_SHIM_RUNTIMENOTFOUND));
            return Ok(());
        };
        let Some(interface) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if interface != IID_ICLR_RUNTIME_INFO && interface != IID_IUNKNOWN {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let object = self.alloc_clr_runtime_info(memory, runtime.clone())?;
        write_guest_pointer(memory, out, object, self.guest_arch)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn dispatch_clr_meta_host_get_version_from_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _object = guest_call_arg(state, memory, 0)?;
        let path_pointer = guest_call_arg(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let size_pointer = guest_call_arg(state, memory, 3)?;
        if size_pointer == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        if path_pointer == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let guest_path = read_utf16_string(memory, path_pointer)?;
        let host_path = match self.win32.guest_path_to_host_path(&guest_path) {
            Ok(path) => path,
            Err(_) => {
                state.set(Register::Rax, u64::from(HRESULT_FILE_NOT_FOUND));
                return Ok(());
            }
        };
        match clr_meta::version_from_file(&host_path) {
            Ok(version) => {
                let result = write_clr_string(memory, buffer, size_pointer, &version)?;
                state.set(Register::Rax, u64::from(result));
            }
            Err(error) => {
                state.set(Register::Rax, u64::from(error.hresult()));
            }
        }
        Ok(())
    }

    fn dispatch_clr_meta_host_enumerate_installed(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _object = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let runtimes = clr_meta::installed_runtimes();
        let enumerator = self.alloc_clr_enumerator(memory, ClrEnumKind::Installed, runtimes, 0)?;
        write_guest_pointer(memory, out, enumerator, self.guest_arch)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn dispatch_clr_meta_host_enumerate_loaded(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _object = guest_call_arg(state, memory, 0)?;
        let _process = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let installed = clr_meta::installed_runtimes();
        let loaded = clr_objects()
            .loaded_versions(self.guest_pid)
            .into_iter()
            .filter_map(|version| clr_meta::ClrVersion::parse_directory_name(&version))
            .filter_map(|version| clr_meta::select_runtime(&version, &installed).cloned())
            .collect();
        let enumerator = self.alloc_clr_enumerator(memory, ClrEnumKind::Loaded, loaded, 0)?;
        write_guest_pointer(memory, out, enumerator, self.guest_arch)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn dispatch_clr_meta_host_request_loaded_notification(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _object = guest_call_arg(state, memory, 0)?;
        let callback = guest_call_arg(state, memory, 1)?;
        if callback == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if clr_objects().register_loaded_callback(self.guest_pid, callback) {
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            // The CLR allows exactly one runtime-loaded callback per process.
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
        }
        Ok(())
    }

    fn dispatch_clr_meta_host_query_legacy(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _object = guest_call_arg(state, memory, 0)?;
        let _riid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        // Legacy V2 binding always targets the .NET Framework CLR, which is
        // genuinely absent on this host.
        state.set(Register::Rax, u64::from(E_NOINTERFACE));
        Ok(())
    }

    fn dispatch_clr_meta_host_exit_process(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _object = guest_call_arg(state, memory, 0)?;
        let exit_code = guest_call_arg_u32(state, memory, 1)?;
        self.process_exit_requested = Some(exit_code);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── ICLRRuntimeInfo ──────────────────────────────────────────────────

    fn dispatch_clr_runtime_info_query_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let riid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let Some(interface) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if interface != IID_ICLR_RUNTIME_INFO && interface != IID_IUNKNOWN {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        match clr_objects().add_ref(self.guest_pid, object) {
            Some(_) => {
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_UNEXPECTED)),
        }
        Ok(())
    }

    fn dispatch_clr_runtime_info_add_ref(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let count = clr_objects().add_ref(self.guest_pid, object).unwrap_or(0);
        state.set(Register::Rax, u64::from(count));
        Ok(())
    }

    fn dispatch_clr_runtime_info_release(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let count = clr_objects().release(self.guest_pid, object).unwrap_or(0);
        state.set(Register::Rax, u64::from(count));
        Ok(())
    }

    fn dispatch_clr_runtime_info_get_version_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let size_pointer = guest_call_arg(state, memory, 2)?;
        if size_pointer == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        match clr_objects().with_runtime_info(self.guest_pid, object, 0, |runtime| {
            runtime.version_string()
        }) {
            Some(version) => {
                let result = write_clr_string(memory, buffer, size_pointer, &version)?;
                state.set(Register::Rax, u64::from(result));
            }
            None => state.set(Register::Rax, u64::from(E_UNEXPECTED)),
        }
        Ok(())
    }

    fn dispatch_clr_runtime_info_get_directory(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let size_pointer = guest_call_arg(state, memory, 2)?;
        if size_pointer == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        match clr_objects().with_runtime_info(self.guest_pid, object, 0, |runtime| {
            runtime.directory.to_string_lossy().into_owned()
        }) {
            Some(directory) => {
                let result = write_clr_string(memory, buffer, size_pointer, &directory)?;
                state.set(Register::Rax, u64::from(result));
            }
            None => state.set(Register::Rax, u64::from(E_UNEXPECTED)),
        }
        Ok(())
    }

    fn dispatch_clr_runtime_info_is_loaded(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let _process = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let Some(version) = clr_objects().with_runtime_info(self.guest_pid, object, 0, |runtime| {
            runtime.version_string()
        }) else {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        };
        let loaded = clr_objects().is_loaded(self.guest_pid, &version);
        write_guest_u32(memory, out, u32::from(loaded))?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn dispatch_clr_runtime_info_load_error_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let _resource_id = guest_call_arg(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let size_pointer = guest_call_arg(state, memory, 3)?;
        let _locale = guest_call_arg(state, memory, 4)?;
        if size_pointer == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let Some(error) = clr_objects().load_error(self.guest_pid, object) else {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        };
        let message = match error {
            S_OK => String::new(),
            E_NOINTERFACE => "No such interface supported.".to_string(),
            CLR_E_SHIM_RUNTIMELOAD => "The runtime could not be loaded.".to_string(),
            other => format!("Runtime error 0x{other:08X}"),
        };
        let result = write_clr_string(memory, buffer, size_pointer, &message)?;
        state.set(Register::Rax, u64::from(result));
        Ok(())
    }

    fn dispatch_clr_runtime_info_load_library(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let name_pointer = guest_call_arg(state, memory, 1)?;
        let handle_out = guest_call_arg(state, memory, 2)?;
        if handle_out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, handle_out, 0, self.guest_arch).ok();
        if name_pointer == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let name = read_utf16_string(memory, name_pointer)?;
        let Some(exists) = clr_objects().with_runtime_info(self.guest_pid, object, 0, |runtime| {
            runtime.directory.join(&name).is_file()
        }) else {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        };
        let result = if exists {
            // The runtime directory exists and holds the named file, but a
            // guest process cannot map a CoreCLR managed assembly into its
            // address space: report the real shim load failure, never a
            // fabricated module handle.
            clr_objects().with_runtime_info(self.guest_pid, object, CLR_E_SHIM_RUNTIMELOAD, |_| ());
            CLR_E_SHIM_RUNTIMELOAD
        } else {
            clr_objects().with_runtime_info(self.guest_pid, object, HRESULT_MOD_NOT_FOUND, |_| ());
            HRESULT_MOD_NOT_FOUND
        };
        state.set(Register::Rax, u64::from(result));
        Ok(())
    }

    fn dispatch_clr_runtime_info_get_proc_address(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let name_pointer = guest_call_arg(state, memory, 1)?;
        let proc_out = guest_call_arg(state, memory, 2)?;
        if proc_out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, proc_out, 0, self.guest_arch).ok();
        if name_pointer == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let symbol = read_c_string(memory, name_pointer)?;
        if symbol.is_empty() {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let resolved = clr_objects().with_runtime_info(self.guest_pid, object, 0, |runtime| {
            let available = clr_meta::native_export_available(runtime, &symbol);
            (runtime.version_string(), available)
        });
        match resolved {
            Some((version, true)) => {
                let thunk = self.alloc_host_thunk(HostThunk::ClrHostExport {
                    runtime_version: version,
                    symbol,
                });
                write_guest_pointer(memory, proc_out, thunk, self.guest_arch)?;
                clr_objects().with_runtime_info(self.guest_pid, object, 0, |_| ());
                state.set(Register::Rax, u64::from(S_OK));
            }
            Some((_, false)) => {
                clr_objects().with_runtime_info(
                    self.guest_pid,
                    object,
                    HRESULT_PROC_NOT_FOUND,
                    |_| (),
                );
                state.set(Register::Rax, u64::from(HRESULT_PROC_NOT_FOUND));
            }
            None => state.set(Register::Rax, u64::from(E_UNEXPECTED)),
        }
        Ok(())
    }

    fn dispatch_clr_runtime_info_get_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let rclsid = guest_call_arg(state, memory, 1)?;
        let riid = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        // Unknown objects are rejected before touching the caller's GUID
        // pointers: the object identity is the primary contract.
        let Some(runtime) = clr_objects().runtime_info(self.guest_pid, object) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if rclsid == 0 || riid == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let Some(class_id) = read_guid(memory, rclsid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        let Some(interface_id) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if interface_id != IID_ICLR_RUNTIME_HOST && interface_id != IID_IUNKNOWN {
            clr_objects().with_runtime_info(self.guest_pid, object, E_NOINTERFACE, |_| ());
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if class_id != CLSID_CLR_RUNTIME_HOST {
            clr_objects().with_runtime_info(self.guest_pid, object, E_NOINTERFACE, |_| ());
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let host = self.alloc_clr_runtime_host(memory, runtime)?;
        write_guest_pointer(memory, out, host, self.guest_arch)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── ICLRRuntimeHost ──────────────────────────────────────────────────

    fn dispatch_clr_runtime_host_query_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let riid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let Some(interface_id) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if interface_id != IID_ICLR_RUNTIME_HOST && interface_id != IID_IUNKNOWN {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if clr_objects()
            .runtime_host_state(self.guest_pid, object)
            .is_none()
        {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        }
        clr_objects().add_ref(self.guest_pid, object);
        write_guest_pointer(memory, out, object, self.guest_arch)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn dispatch_clr_runtime_host_add_ref(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        match clr_objects().add_ref(self.guest_pid, object) {
            Some(count) => state.set(Register::Rax, u64::from(count)),
            None => state.set(Register::Rax, 0),
        }
        Ok(())
    }

    fn dispatch_clr_runtime_host_release(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        match clr_objects().release(self.guest_pid, object) {
            Some(count) => state.set(Register::Rax, u64::from(count)),
            None => state.set(Register::Rax, 0),
        }
        Ok(())
    }

    fn dispatch_clr_runtime_host_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let Some((runtime, _)) = clr_objects().runtime_host_state(self.guest_pid, object) else {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        };
        if runtime.coreclr_library().is_none() {
            state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE)); // coverage: unreachable — a runtime host is only allocated from installed_runtimes(), which filters out missing CLR libraries
            return Ok(()); // coverage: unreachable — same filtered-installation branch as the line above
        }
        clr_objects().start_runtime_host(self.guest_pid, object);
        let version = runtime.version_string();
        self.notify_clr_runtime_loaded(state, memory, &version)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn dispatch_clr_runtime_host_get_domain_id(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        let Some((_, started)) = clr_objects().runtime_host_state(self.guest_pid, object) else {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        };
        write_guest_u32(memory, out, u32::from(started))?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn dispatch_clr_runtime_host_execute_application(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let application = guest_call_arg(state, memory, 1)?;
        let manifest_count = guest_call_arg_u32(state, memory, 2)?;
        let manifest_paths = guest_call_arg(state, memory, 3)?;
        let activation_count = guest_call_arg_u32(state, memory, 4)?;
        let activation_data = guest_call_arg(state, memory, 5)?;
        let result = guest_call_arg(state, memory, 6)?;
        if result == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_u32(memory, result, 0)?;
        if application == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if clr_objects()
            .runtime_host_state(self.guest_pid, object)
            .is_none()
        {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        }
        if (manifest_count != 0 && manifest_paths == 0)
            || (activation_count != 0 && activation_data == 0)
        {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let guest_application = read_utf16_string(memory, application)?;
        let host_application = match self.win32.guest_path_to_host_path(&guest_application) {
            Ok(path) => path,
            Err(_) => {
                state.set(Register::Rax, u64::from(HRESULT_FILE_NOT_FOUND));
                return Ok(());
            }
        };
        let pointer_size = if self.guest_arch == GuestArch::X64 {
            8
        } else {
            4
        };
        let mut arguments = Vec::with_capacity(activation_count as usize);
        for index in 0..activation_count {
            let slot = activation_data + u64::from(index) * pointer_size;
            let pointer = read_guest_pointer(memory, slot, self.guest_arch)?;
            if pointer != 0 {
                arguments.push(read_utf16_string(memory, pointer)?);
            }
        }
        // Manifest paths name activation manifests; the runtime entry point
        // receives the activation data as its command line.
        let _ = (manifest_paths, manifest_count);
        match crate::clr_host::execute_assembly(&host_application, &arguments) {
            Ok(code) => {
                write_guest_u32(memory, result, code as u32)?;
                clr_objects().start_runtime_host(self.guest_pid, object);
                state.set(Register::Rax, u64::from(S_OK));
            }
            #[rustfmt::skip]
            Err(crate::clr_host::ClrHostError::NoRuntime) => { // coverage: unreachable — host_for() fails only when no CoreCLR is installed, and tests require one
                state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE)); // coverage: unreachable — same missing-CoreCLR host-installation arm as the line above
            } // coverage: unreachable — same missing-CoreCLR host-installation arm as the lines above
            Err(crate::clr_host::ClrHostError::AssemblyNotFound(_)) => {
                state.set(Register::Rax, u64::from(HRESULT_FILE_NOT_FOUND));
            }
            #[rustfmt::skip]
            Err(crate::clr_host::ClrHostError::InvalidArgument(_)) => { // coverage: unreachable — read_utf16_string stops at NUL, so activation data never contains the interior NUL CString::new rejects
                state.set(Register::Rax, u64::from(E_INVALIDARG)); // coverage: unreachable — same NUL-free activation-data arm as the line above
            } // coverage: unreachable — same NUL-free activation-data arm as the lines above
            Err(_) => {
                state.set(Register::Rax, u64::from(COR_E_EXECUTIONENGINE));
            }
        }
        Ok(())
    }

    fn dispatch_clr_runtime_host_execute_in_default_app_domain(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let assembly = guest_call_arg(state, memory, 1)?;
        let type_name = guest_call_arg(state, memory, 2)?;
        let method_name = guest_call_arg(state, memory, 3)?;
        let argument = guest_call_arg(state, memory, 4)?;
        let result = guest_call_arg(state, memory, 5)?;
        if result == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_u32(memory, result, 0)?;
        if assembly == 0 || type_name == 0 || method_name == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some(_) = clr_objects().runtime_host_state(self.guest_pid, object) else {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        };
        let guest_assembly = read_utf16_string(memory, assembly)?;
        let host_assembly = match self.win32.guest_path_to_host_path(&guest_assembly) {
            Ok(path) => path,
            Err(_) => {
                state.set(Register::Rax, u64::from(HRESULT_FILE_NOT_FOUND));
                return Ok(());
            }
        };
        let type_name = read_utf16_string(memory, type_name)?;
        let method_name = read_utf16_string(memory, method_name)?;
        let argument = if argument == 0 {
            None
        } else {
            Some(read_utf16_string(memory, argument)?)
        };
        match crate::clr_host::execute_in_default_app_domain(
            &host_assembly,
            &type_name,
            &method_name,
            argument.as_deref(),
        ) {
            Ok(value) => {
                write_guest_u32(memory, result, value as u32)?;
                clr_objects().start_runtime_host(self.guest_pid, object);
                state.set(Register::Rax, u64::from(S_OK));
            }
            #[rustfmt::skip]
            Err(crate::clr_host::ClrHostError::NoRuntime) => { // coverage: unreachable — host_for() fails only when no CoreCLR is installed, and tests require one
                state.set(Register::Rax, u64::from(COR_E_CLRNOTAVAILABLE)); // coverage: unreachable — same missing-CoreCLR host-installation arm as the line above
            } // coverage: unreachable — same missing-CoreCLR host-installation arm as the lines above
            Err(crate::clr_host::ClrHostError::AssemblyNotFound(_)) => {
                state.set(Register::Rax, u64::from(HRESULT_FILE_NOT_FOUND));
            }
            Err(crate::clr_host::ClrHostError::InvalidArgument(_)) => {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
            }
            Err(error) => {
                self.last_error = 0;
                let _ = error;
                state.set(Register::Rax, u64::from(COR_E_EXECUTIONENGINE));
            }
        }
        Ok(())
    }

    // ── IEnumUnknown ─────────────────────────────────────────────────────

    fn dispatch_clr_enum_query_interface(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let riid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let Some(interface) = read_guid(memory, riid) else {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        };
        if interface != IID_IENUM_UNKNOWN && interface != IID_IUNKNOWN {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        match clr_objects().add_ref(self.guest_pid, object) {
            Some(_) => {
                write_guest_pointer(memory, out, object, self.guest_arch)?;
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_UNEXPECTED)),
        }
        Ok(())
    }

    fn dispatch_clr_enum_add_ref(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let count = clr_objects().add_ref(self.guest_pid, object).unwrap_or(0);
        state.set(Register::Rax, u64::from(count));
        Ok(())
    }

    fn dispatch_clr_enum_release(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let count = clr_objects().release(self.guest_pid, object).unwrap_or(0);
        state.set(Register::Rax, u64::from(count));
        Ok(())
    }

    fn dispatch_clr_enum_next(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let count = guest_call_arg_u32(state, memory, 1)?;
        let items = guest_call_arg(state, memory, 2)?;
        let fetched_pointer = guest_call_arg(state, memory, 3)?;
        if count == 0 {
            write_optional_u32(memory, fetched_pointer, 0)?;
            state.set(Register::Rax, u64::from(S_FALSE));
            return Ok(());
        }
        if items == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        if count > 1 && fetched_pointer == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let mut fetched = 0_u32;
        for index in 0..count {
            let Some(runtime) = clr_objects().next_enum_item(self.guest_pid, object) else {
                break;
            };
            let item = self.alloc_clr_runtime_info(memory, runtime)?;
            let slot = items + u64::from(index) * self.guest_arch.pointer_bytes() as u64;
            write_guest_pointer(memory, slot, item, self.guest_arch)?;
            fetched += 1;
        }
        write_optional_u32(memory, fetched_pointer, fetched)?;
        state.set(
            Register::Rax,
            u64::from(if fetched == count { S_OK } else { S_FALSE }),
        );
        Ok(())
    }

    fn dispatch_clr_enum_skip(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let count = guest_call_arg_u32(state, memory, 1)? as usize;
        let skipped = clr_objects()
            .skip_enum_items(self.guest_pid, object, count)
            .unwrap_or(0);
        state.set(
            Register::Rax,
            u64::from(if skipped == count { S_OK } else { S_FALSE }),
        );
        Ok(())
    }

    fn dispatch_clr_enum_reset(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let result = if clr_objects().reset_enum(self.guest_pid, object).is_some() {
            S_OK
        } else {
            E_UNEXPECTED
        };
        state.set(Register::Rax, u64::from(result));
        Ok(())
    }

    fn dispatch_clr_enum_clone(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let object = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_POINTER));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let Some((kind, runtimes, cursor)) = clr_objects().clone_enum(self.guest_pid, object)
        else {
            state.set(Register::Rax, u64::from(E_UNEXPECTED));
            return Ok(());
        };
        let enumerator = self.alloc_clr_enumerator(memory, kind, runtimes, cursor)?;
        write_guest_pointer(memory, out, enumerator, self.guest_arch)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── Host runtime loaded notification ─────────────────────────────────

    /// Mark a runtime as loaded for this guest pid and invoke the registered
    /// `RequestRuntimeLoadedNotification` callback exactly once for the
    /// transition.  This is the entry point the managed-execution path calls
    /// when it has loaded a real CoreCLR (`execute_managed_image`); it is
    /// deliberately not triggered by enumeration or version queries.
    #[allow(dead_code)] // integration hook for execute_managed_image + tests
    pub(crate) fn notify_clr_runtime_loaded(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        runtime_version: &str,
    ) -> AppResult<bool> {
        let Some(version) = clr_meta::ClrVersion::parse_directory_name(runtime_version) else {
            return Ok(false);
        };
        let installed = clr_meta::installed_runtimes();
        let Some(runtime) = clr_meta::select_runtime(&version, &installed).cloned() else {
            return Ok(false);
        };
        let newly_loaded = clr_objects().mark_loaded(self.guest_pid, &runtime.version_string());
        if !newly_loaded {
            return Ok(false);
        }
        let Some(callback) = clr_objects().loaded_callback(self.guest_pid) else {
            return Ok(true);
        };
        let runtime_info = self.alloc_clr_runtime_info(memory, runtime)?;
        let thread_set = self.alloc_host_thunk(HostThunk::ClrRuntimeLoadedCallbackThreadSet);
        let thread_unset = self.alloc_host_thunk(HostThunk::ClrRuntimeLoadedCallbackThreadUnset);
        let callback_args = [runtime_info, thread_set, thread_unset];
        self.execute_guest_callback(
            state,
            memory,
            callback,
            &callback_args,
            "ICLRMetaHost::RuntimeLoadedCallback",
        )?;
        clr_objects().release(self.guest_pid, runtime_info);
        Ok(true)
    }

    /// Invoke a symbol resolved by `ICLRRuntimeInfo::GetProcAddress`.
    ///
    /// The symbol is resolved in the real runtime directory each time.  Casa1
    /// cannot transplant a host dylib function into the guest CPU, so the
    /// guest arguments are passed through unchanged (the host ABI) and the
    /// bridge reports success after the call; the host function's own return
    /// value is not reinterpreted as a guest HRESULT.
    fn dispatch_clr_host_export(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        runtime_version: &str,
        symbol: &str,
    ) -> AppResult<()> {
        let Some(version) = clr_meta::ClrVersion::parse_directory_name(runtime_version) else {
            state.set(Register::Rax, u64::from(HRESULT_PROC_NOT_FOUND));
            return Ok(());
        };
        let installed = clr_meta::installed_runtimes();
        let Some(runtime) = clr_meta::select_runtime(&version, &installed) else {
            state.set(Register::Rax, u64::from(HRESULT_PROC_NOT_FOUND));
            return Ok(());
        };
        let library_path = runtime
            .coreclr_library()
            .or_else(|| runtime.hostfxr_library())
            .unwrap();
        // SAFETY: this is a signed runtime library from the host installation.
        // GetProcAddress only hands out thunks for symbols that loaded from
        // this exact library, so a load failure here is a host installation
        // fault (panic rather than silently fabricating a proc result).
        let library = unsafe { libloading::Library::new(&library_path) }.unwrap();
        // SAFETY: symbol presence was checked by GetProcAddress; the ABI is
        // passed through as four machine words (the documented host ABI).
        let function = unsafe {
            library
                .get::<unsafe extern "C" fn(u64, u64, u64, u64) -> u64>(symbol.as_bytes())
                .ok()
        };
        let Some(function) = function else {
            state.set(Register::Rax, u64::from(HRESULT_PROC_NOT_FOUND));
            return Ok(());
        };
        let args = match self.guest_arch {
            GuestArch::X64 => [
                state.get(Register::Rcx),
                state.get(Register::Rdx),
                state.get(Register::R8),
                state.get(Register::R9),
            ],
            GuestArch::X86 => {
                let rsp = state.get(Register::Rsp);
                [
                    read_guest_pointer(memory, rsp, GuestArch::X86)?,
                    read_guest_pointer(memory, rsp + 4, GuestArch::X86)?,
                    read_guest_pointer(memory, rsp + 8, GuestArch::X86)?,
                    read_guest_pointer(memory, rsp + 12, GuestArch::X86)?,
                ]
            }
        };
        // SAFETY: the resolved pointer comes from the loaded library, and the
        // call passes the guest's machine-word arguments through unchanged.
        unsafe {
            function(args[0], args[1], args[2], args[3]);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use crate::runtime::dispatch::test_support::{
        Fixture, dispatch_x86, with_big_stack, x86_fixture,
    };
    use tempfile::TempDir;

    const STACK: u64 = 0x50_000;

    fn write_guid(memory: &mut MemoryImage, address: u64, guid: [u8; 16]) {
        memory.map_bytes(address, &guid);
    }

    fn words(memory: &mut MemoryImage, address: u64, count: usize) -> u64 {
        memory.map_bytes(address, &vec![0_u8; count * 4]);
        address
    }

    fn read_u32_at(memory: &MemoryImage, address: u64) -> u32 {
        memory.read_u32(address).expect("read guest u32")
    }

    fn read_ptr_at(memory: &MemoryImage, address: u64) -> u64 {
        u64::from(read_u32_at(memory, address))
    }

    fn create_meta_host(fixture: &mut Fixture) -> u64 {
        let clsid = words(&mut fixture.memory, 0x41_000, 4);
        let riid = words(&mut fixture.memory, 0x41_020, 4);
        let out = words(&mut fixture.memory, 0x41_040, 1);
        write_guid(&mut fixture.memory, clsid, CLSID_CLR_META_HOST);
        write_guid(&mut fixture.memory, riid, IID_ICLR_META_HOST);
        assert_eq!(
            dispatch_x86(
                fixture,
                HostThunk::ClrCreateInstance,
                &[clsid as u32, riid as u32, out as u32],
            ),
            0
        );
        let object = read_ptr_at(&fixture.memory, out);
        assert_ne!(object, 0, "CLRCreateInstance returns a real meta host");
        object
    }

    fn method(fixture: &mut Fixture, object: u64, index: u64) -> u64 {
        let vtable = read_ptr_at(&fixture.memory, object);
        assert_ne!(vtable, 0, "object has a vtable");
        u64::from(read_u32_at(&fixture.memory, vtable + index * 4))
    }

    fn call_x86(fixture: &mut Fixture, target: u64, args: &[u32]) -> u64 {
        fixture.memory.map_bytes(STACK - 0x800, &[0_u8; 0x1000]);
        write_u32(&mut fixture.memory, STACK, 0xDEAD_BEEF);
        for (index, arg) in args.iter().enumerate() {
            write_u32(&mut fixture.memory, STACK + 4 + index as u64 * 4, *arg);
        }
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, STACK);
        fixture
            .runtime
            .dispatch_import(target, &mut state, &mut fixture.memory)
            .expect("dispatch vtable method");
        state.get(Register::Rax)
    }

    fn call_method(fixture: &mut Fixture, object: u64, index: u64, args: &[u32]) -> u64 {
        let target = method(fixture, object, index);
        let mut all = Vec::with_capacity(args.len() + 1);
        all.push(object as u32);
        all.extend_from_slice(args);
        call_x86(fixture, target, &all)
    }

    fn call_thunk(fixture: &mut Fixture, thunk: HostThunk, args: &[u32]) -> u64 {
        let target = fixture.runtime.alloc_host_thunk(thunk);
        call_x86(fixture, target, args)
    }

    fn read_wide(memory: &MemoryImage, address: u64) -> String {
        read_utf16_string(memory, address).expect("read utf16")
    }

    fn real_version() -> String {
        crate::clr_meta::installed_runtimes()
            .first()
            .expect("a real runtime is installed")
            .version_string()
    }

    fn x64_runtime(name: &str) -> (PeHostRuntime, MemoryImage, TempDir) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), name, GeArch::X64, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.guest_arch = GuestArch::X64;
        runtime.next_thunk_address = thunk_base_for_arch(GuestArch::X64);
        runtime.next_data_address = data_base_for_arch(GuestArch::X64);
        runtime.next_heap_address = heap_base_for_arch(GuestArch::X64);
        runtime
            .win32
            .reset_address_space(private_pages_base_for_arch(GuestArch::X64));
        (runtime, MemoryImage::default(), temp_dir)
    }

    fn get_runtime(fixture: &mut Fixture, meta: u64, requested: &str) -> (u64, u64) {
        let version = fixture
            .runtime
            .alloc_utf16_string(&mut fixture.memory, requested)
            .expect("version string");
        let riid = words(&mut fixture.memory, 0x41_200, 4);
        let out = words(&mut fixture.memory, 0x41_240, 1);
        write_guid(&mut fixture.memory, riid, IID_ICLR_RUNTIME_INFO);
        let hr = call_method(fixture, meta, 3, &[version as u32, riid as u32, out as u32]);
        (hr, read_ptr_at(&fixture.memory, out))
    }

    #[test]
    fn clr_create_instance_rejects_unknown_ids_and_nulls_with_zeroed_out() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-create-invalid");
            let clsid = words(&mut fixture.memory, 0x41_000, 4);
            let riid = words(&mut fixture.memory, 0x41_020, 4);
            let out = words(&mut fixture.memory, 0x41_040, 1);
            write_guid(&mut fixture.memory, clsid, CLSID_CLR_META_HOST);
            write_guid(&mut fixture.memory, riid, IID_ICLR_META_HOST);

            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrCreateInstance,
                    &[clsid as u32, riid as u32, 0],
                ),
                u64::from(E_POINTER)
            );

            let wrong_clsid = words(&mut fixture.memory, 0x41_060, 4);
            write_guid(&mut fixture.memory, wrong_clsid, IID_IUNKNOWN);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrCreateInstance,
                    &[wrong_clsid as u32, riid as u32, out as u32],
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);

            let wrong_riid = words(&mut fixture.memory, 0x41_080, 4);
            write_guid(&mut fixture.memory, wrong_riid, CLSID_CLR_META_HOST);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrCreateInstance,
                    &[clsid as u32, wrong_riid as u32, out as u32],
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);

            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrCreateInstance,
                    &[0, riid as u32, out as u32],
                ),
                u64::from(E_POINTER)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrCreateInstance,
                    &[clsid as u32, 0, out as u32],
                ),
                u64::from(E_POINTER)
            );
        })
    }

    #[test]
    fn clr_meta_host_qoi_and_refcounts_are_exact() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-qoi");
            let meta = create_meta_host(&mut fixture);
            let iid = words(&mut fixture.memory, 0x41_100, 4);
            let out = words(&mut fixture.memory, 0x41_140, 1);
            write_guid(&mut fixture.memory, iid, IID_ICLR_META_HOST);
            assert_eq!(
                call_method(&mut fixture, meta, 0, &[iid as u32, out as u32]),
                0
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), meta);
            assert_eq!(call_method(&mut fixture, meta, 2, &[]), 1);
            assert_eq!(call_method(&mut fixture, meta, 1, &[]), 2);
            assert_eq!(call_method(&mut fixture, meta, 2, &[]), 1);

            write_guid(&mut fixture.memory, iid, IID_ICLR_RUNTIME_INFO);
            assert_eq!(
                call_method(&mut fixture, meta, 0, &[iid as u32, out as u32]),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);
            assert_eq!(
                call_method(&mut fixture, meta, 0, &[iid as u32, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, meta, 0, &[0, out as u32]),
                u64::from(E_POINTER)
            );

            assert_eq!(call_method(&mut fixture, meta, 2, &[]), 0);
            assert_eq!(call_method(&mut fixture, meta, 2, &[]), 0);
            write_guid(&mut fixture.memory, iid, IID_ICLR_META_HOST);
            assert_eq!(
                call_method(&mut fixture, meta, 0, &[iid as u32, out as u32]),
                u64::from(E_UNEXPECTED),
                "a destroyed object can no longer be queried"
            );
        })
    }

    #[test]
    fn clr_get_runtime_rejects_malformed_and_absent_versions() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-get-runtime-invalid");
            let meta = create_meta_host(&mut fixture);
            let version = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "v8")
                .expect("malformed version");
            let riid = words(&mut fixture.memory, 0x41_200, 4);
            let out = words(&mut fixture.memory, 0x41_240, 1);
            write_guid(&mut fixture.memory, riid, IID_ICLR_RUNTIME_INFO);
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    3,
                    &[version as u32, riid as u32, out as u32]
                ),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                call_method(&mut fixture, meta, 3, &[0, riid as u32, out as u32]),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                call_method(&mut fixture, meta, 3, &[version as u32, riid as u32, 0]),
                u64::from(E_POINTER)
            );

            let absent = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "v999.999.999")
                .expect("absent version");
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    3,
                    &[absent as u32, riid as u32, out as u32]
                ),
                u64::from(CLR_E_SHIM_RUNTIMENOTFOUND)
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);

            let installed = crate::clr_meta::installed_runtimes();
            let runtime = installed.first().expect("a real runtime is installed");
            let (hr, info) = get_runtime(&mut fixture, meta, &runtime.version_string());
            assert_eq!(hr, 0);
            assert_ne!(info, 0);
            let unsupported = words(&mut fixture.memory, 0x41_260, 4);
            write_guid(&mut fixture.memory, unsupported, IID_IENUM_UNKNOWN);
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    3,
                    &[absent as u32, unsupported as u32, out as u32]
                ),
                u64::from(CLR_E_SHIM_RUNTIMENOTFOUND),
                "an absent version is reported before the interface check"
            );
            let valid = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, &runtime.version_string())
                .expect("valid version");
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    3,
                    &[valid as u32, unsupported as u32, out as u32]
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);
            assert_eq!(
                call_method(&mut fixture, meta, 3, &[valid as u32, 0, out as u32]),
                u64::from(E_POINTER)
            );
            assert_eq!(call_method(&mut fixture, info, 2, &[]), 0);
        })
    }

    #[test]
    fn clr_get_version_from_file_matches_managed_and_rejects_non_managed() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-version-from-file");
            let meta = create_meta_host(&mut fixture);
            let runtime = crate::clr_meta::installed_runtimes()
                .into_iter()
                .next()
                .expect("a real runtime is installed");
            let source = runtime.directory.join("System.Runtime.dll");
            fixture
                .runtime
                .win32
                .stage_host_file_w(&source, "C:\\clr\\System.Runtime.dll")
                .expect("stage managed assembly");
            let path = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\System.Runtime.dll")
                .expect("guest path");
            let size = words(&mut fixture.memory, 0x41_300, 1);
            // Size query: null buffer.
            assert_eq!(
                call_method(&mut fixture, meta, 4, &[path as u32, 0, size as u32]),
                0
            );
            assert_eq!(read_u32_at(&fixture.memory, size), 11);

            let buffer = words(&mut fixture.memory, 0x41_320, 16);
            write_u32(&mut fixture.memory, size, 5);
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    4,
                    &[path as u32, buffer as u32, size as u32]
                ),
                u64::from(HRESULT_INSUFFICIENT_BUFFER)
            );
            assert_eq!(read_u32_at(&fixture.memory, size), 11);
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    4,
                    &[path as u32, buffer as u32, size as u32]
                ),
                0
            );
            assert_eq!(read_u32_at(&fixture.memory, size), 11);
            assert_eq!(read_wide(&fixture.memory, buffer), "v4.0.30319");

            let native_source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("ges/steam-live-run-x86/drive_c/nsExec.dll");
            fixture
                .runtime
                .win32
                .stage_host_file_w(&native_source, "C:\\clr\\native.dll")
                .expect("stage native PE");
            let native_path = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\native.dll")
                .expect("native path");
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    4,
                    &[native_path as u32, buffer as u32, size as u32]
                ),
                u64::from(CLR_E_SHIM_RUNTIMELOAD),
                "a native PE has no CLI metadata"
            );

            let text_source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
            fixture
                .runtime
                .win32
                .stage_host_file_w(&text_source, "C:\\clr\\not-pe.txt")
                .expect("stage text file");
            let text_path = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\not-pe.txt")
                .expect("text path");
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    4,
                    &[text_path as u32, buffer as u32, size as u32]
                ),
                u64::from(crate::clr_meta::HRESULT_BAD_FORMAT),
                "a non-PE file is rejected as a bad image format"
            );

            let missing = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\missing.dll")
                .expect("missing path");
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    4,
                    &[missing as u32, buffer as u32, size as u32]
                ),
                u64::from(HRESULT_FILE_NOT_FOUND)
            );
            let relative = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "no-drive-path.dll")
                .expect("relative path");
            assert_eq!(
                call_method(
                    &mut fixture,
                    meta,
                    4,
                    &[relative as u32, buffer as u32, size as u32]
                ),
                u64::from(HRESULT_FILE_NOT_FOUND),
                "a path without a drive never resolves through the GE"
            );
            assert_eq!(
                call_method(&mut fixture, meta, 4, &[path as u32, buffer as u32, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, meta, 4, &[0, buffer as u32, size as u32]),
                u64::from(E_INVALIDARG)
            );
        })
    }

    #[test]
    fn clr_enumeration_lifetime_query_interface_and_absent_items_are_exact() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-enumeration");
            let meta = create_meta_host(&mut fixture);
            let out = words(&mut fixture.memory, 0x41_040, 1);
            let iid = words(&mut fixture.memory, 0x41_060, 4);
            let item = words(&mut fixture.memory, 0x41_080, 1);
            let fetched = words(&mut fixture.memory, 0x41_0A0, 1);

            assert_eq!(
                call_method(&mut fixture, meta, 5, &[0]),
                u64::from(E_POINTER)
            );
            assert_eq!(call_method(&mut fixture, meta, 5, &[out as u32]), 0);
            let enumerator = read_ptr_at(&fixture.memory, out);
            assert_ne!(enumerator, 0);

            write_guid(&mut fixture.memory, iid, IID_IENUM_UNKNOWN);
            assert_eq!(
                call_method(&mut fixture, enumerator, 0, &[iid as u32, out as u32]),
                0
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), enumerator);
            assert_eq!(call_method(&mut fixture, enumerator, 1, &[]), 3);
            assert_eq!(call_method(&mut fixture, enumerator, 2, &[]), 2);
            assert_eq!(call_method(&mut fixture, enumerator, 2, &[]), 1);
            write_guid(&mut fixture.memory, iid, IID_ICLR_RUNTIME_INFO);
            assert_eq!(
                call_method(&mut fixture, enumerator, 0, &[iid as u32, out as u32]),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);

            let installed = crate::clr_meta::installed_runtimes();
            assert!(!installed.is_empty());
            assert_eq!(
                call_method(
                    &mut fixture,
                    enumerator,
                    3,
                    &[0, item as u32, fetched as u32]
                ),
                u64::from(S_FALSE)
            );
            assert_eq!(read_u32_at(&fixture.memory, fetched), 0);
            assert_eq!(
                call_method(&mut fixture, enumerator, 3, &[0, item as u32, 0]),
                u64::from(S_FALSE),
                "celt=0 permits a null pceltFetched"
            );
            assert_eq!(
                call_method(&mut fixture, enumerator, 0, &[0, out as u32]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, enumerator, 0, &[iid as u32, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, enumerator, 3, &[2, item as u32, 0]),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                call_method(&mut fixture, enumerator, 3, &[1, 0, fetched as u32]),
                u64::from(E_POINTER)
            );

            for index in 0..installed.len() {
                assert_eq!(
                    call_method(
                        &mut fixture,
                        enumerator,
                        3,
                        &[1, item as u32, fetched as u32]
                    ),
                    0,
                    "installed runtime {index} is enumerated"
                );
                assert_eq!(read_u32_at(&fixture.memory, fetched), 1);
                let info = read_ptr_at(&fixture.memory, item);
                let version_size = words(&mut fixture.memory, 0x41_0C0, 1);
                let version_buffer = words(&mut fixture.memory, 0x41_0E0, 32);
                assert_eq!(
                    call_method(&mut fixture, info, 3, &[0, version_size as u32]),
                    0
                );
                assert_eq!(
                    call_method(
                        &mut fixture,
                        info,
                        3,
                        &[version_buffer as u32, version_size as u32]
                    ),
                    0
                );
                assert_eq!(
                    read_wide(&fixture.memory, version_buffer),
                    installed[index].version_string()
                );
                assert_eq!(call_method(&mut fixture, info, 2, &[]), 0);
            }
            assert_eq!(
                call_method(
                    &mut fixture,
                    enumerator,
                    3,
                    &[1, item as u32, fetched as u32]
                ),
                u64::from(S_FALSE)
            );
            assert_eq!(read_u32_at(&fixture.memory, fetched), 0);

            assert_eq!(
                call_method(&mut fixture, enumerator, 4, &[1]),
                u64::from(S_FALSE),
                "skip at the end skips nothing"
            );
            assert_eq!(call_method(&mut fixture, enumerator, 5, &[]), 0);
            assert_eq!(
                call_method(&mut fixture, enumerator, 4, &[installed.len() as u32]),
                0
            );
            assert_eq!(
                call_method(&mut fixture, enumerator, 4, &[1]),
                u64::from(S_FALSE)
            );
            assert_eq!(call_method(&mut fixture, enumerator, 5, &[]), 0);
            assert_eq!(
                call_method(
                    &mut fixture,
                    enumerator,
                    3,
                    &[1, item as u32, fetched as u32]
                ),
                0
            );
            let first = read_ptr_at(&fixture.memory, item);
            assert_eq!(call_method(&mut fixture, first, 2, &[]), 0);

            let clone_out = words(&mut fixture.memory, 0x41_100, 1);
            assert_eq!(
                call_method(&mut fixture, enumerator, 6, &[0]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, enumerator, 6, &[clone_out as u32]),
                0
            );
            let clone = read_ptr_at(&fixture.memory, clone_out);
            assert_ne!(clone, enumerator);
            assert!(
                installed.len() >= 2,
                "the host exposes at least two runtimes"
            );
            assert_eq!(
                call_method(&mut fixture, clone, 3, &[1, item as u32, fetched as u32]),
                0,
                "the clone keeps the source cursor"
            );
            let clone_info = read_ptr_at(&fixture.memory, item);
            let clone_size = words(&mut fixture.memory, 0x41_120, 1);
            let clone_buffer = words(&mut fixture.memory, 0x41_140, 32);
            assert_eq!(
                call_method(&mut fixture, clone_info, 3, &[0, clone_size as u32]),
                0
            );
            assert_eq!(
                call_method(
                    &mut fixture,
                    clone_info,
                    3,
                    &[clone_buffer as u32, clone_size as u32]
                ),
                0
            );
            assert_eq!(
                read_wide(&fixture.memory, clone_buffer),
                installed[1].version_string()
            );
            assert_eq!(call_method(&mut fixture, clone_info, 2, &[]), 0);
            assert_eq!(call_method(&mut fixture, clone, 2, &[]), 0);
            assert_eq!(
                call_method(&mut fixture, enumerator, 3, &[1, item as u32, 0]),
                0,
                "celt=1 permits a null pceltFetched"
            );
            assert_eq!(call_method(&mut fixture, enumerator, 2, &[]), 0);
            write_guid(&mut fixture.memory, iid, IID_IENUM_UNKNOWN);
            assert_eq!(
                call_method(&mut fixture, enumerator, 0, &[iid as u32, out as u32]),
                u64::from(E_UNEXPECTED),
                "a destroyed enumerator cannot be queried"
            );

            assert_eq!(
                call_method(&mut fixture, meta, 6, &[0, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(call_method(&mut fixture, meta, 6, &[0, out as u32]), 0);
            let loaded = read_ptr_at(&fixture.memory, out);
            assert_eq!(
                call_method(&mut fixture, loaded, 3, &[1, item as u32, fetched as u32]),
                u64::from(S_FALSE),
                "no runtime is loaded before hosting starts"
            );
            assert_eq!(read_u32_at(&fixture.memory, fetched), 0);
            assert_eq!(call_method(&mut fixture, loaded, 2, &[]), 0);
            assert_eq!(call_method(&mut fixture, enumerator, 2, &[]), 0);
        })
    }

    #[test]
    fn clr_runtime_info_rejects_hosting_interfaces_and_reports_real_proc_address() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-runtime-info");
            let meta = create_meta_host(&mut fixture);
            let (hr, info) = get_runtime(&mut fixture, meta, &real_version());
            assert_eq!(hr, 0);
            assert_ne!(info, 0);

            let qi_iid = words(&mut fixture.memory, 0x41_280, 4);
            let qi_out = words(&mut fixture.memory, 0x41_2A0, 1);
            write_guid(&mut fixture.memory, qi_iid, IID_ICLR_RUNTIME_INFO);
            assert_eq!(
                call_method(&mut fixture, info, 0, &[qi_iid as u32, qi_out as u32]),
                0
            );
            assert_eq!(read_ptr_at(&fixture.memory, qi_out), info);
            assert_eq!(call_method(&mut fixture, info, 1, &[]), 3);
            assert_eq!(call_method(&mut fixture, info, 2, &[]), 2);
            assert_eq!(call_method(&mut fixture, info, 2, &[]), 1);
            write_guid(&mut fixture.memory, qi_iid, IID_IENUM_UNKNOWN);
            assert_eq!(
                call_method(&mut fixture, info, 0, &[qi_iid as u32, qi_out as u32]),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, qi_out), 0);
            assert_eq!(
                call_method(&mut fixture, info, 0, &[qi_iid as u32, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, info, 0, &[0, qi_out as u32]),
                u64::from(E_POINTER)
            );

            let size = words(&mut fixture.memory, 0x41_300, 1);
            let buffer = words(&mut fixture.memory, 0x41_320, 64);
            assert_eq!(
                call_method(&mut fixture, info, 6, &[0, 0, size as u32, 0]),
                0
            );
            assert_eq!(read_u32_at(&fixture.memory, size), 1);
            assert_eq!(
                call_method(&mut fixture, info, 6, &[0, buffer as u32, size as u32, 0]),
                0
            );
            assert_eq!(read_wide(&fixture.memory, buffer), "");
            assert_eq!(call_method(&mut fixture, info, 3, &[0, size as u32]), 0);
            let required = read_u32_at(&fixture.memory, size);
            assert_eq!(read_u32_at(&mut fixture.memory, size), required);
            assert_eq!(
                call_method(&mut fixture, info, 3, &[buffer as u32, size as u32]),
                0
            );
            assert_eq!(read_wide(&fixture.memory, buffer), real_version());

            assert_eq!(
                call_method(&mut fixture, info, 3, &[buffer as u32, 0]),
                u64::from(E_POINTER)
            );

            assert_eq!(call_method(&mut fixture, info, 4, &[0, size as u32]), 0);
            assert_eq!(
                call_method(&mut fixture, info, 4, &[buffer as u32, size as u32]),
                0
            );
            assert_eq!(
                call_method(&mut fixture, info, 4, &[buffer as u32, 0]),
                u64::from(E_POINTER)
            );
            let directory = read_wide(&fixture.memory, buffer);
            let runtime = crate::clr_meta::installed_runtimes()
                .into_iter()
                .find(|runtime| runtime.version_string() == real_version())
                .expect("selected runtime");
            assert_eq!(directory, runtime.directory.to_string_lossy());

            let loaded_out = words(&mut fixture.memory, 0x41_390, 1);
            assert_eq!(
                call_method(&mut fixture, info, 5, &[0, loaded_out as u32]),
                0
            );
            assert_eq!(read_u32_at(&fixture.memory, loaded_out), 0);
            assert_eq!(
                call_method(&mut fixture, info, 5, &[0, 0]),
                u64::from(E_POINTER)
            );

            let clsid = words(&mut fixture.memory, 0x41_3C0, 4);
            let iid = words(&mut fixture.memory, 0x41_3E0, 4);
            let interface_out = words(&mut fixture.memory, 0x41_400, 1);
            write_guid(&mut fixture.memory, clsid, CLSID_CLR_META_HOST);
            write_guid(&mut fixture.memory, iid, IID_ICLR_META_HOST);
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    9,
                    &[clsid as u32, iid as u32, interface_out as u32]
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, interface_out), 0);
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    9,
                    &[0, iid as u32, interface_out as u32]
                ),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    9,
                    &[clsid as u32, 0, interface_out as u32]
                ),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, info, 9, &[clsid as u32, iid as u32, 0]),
                u64::from(E_POINTER)
            );

            // The failed GetInterface is the object's last status.
            assert_eq!(
                call_method(&mut fixture, info, 6, &[0, buffer as u32, size as u32, 0]),
                0
            );
            assert_eq!(
                read_wide(&fixture.memory, buffer),
                "No such interface supported."
            );

            let absent_name = fixture
                .runtime
                .alloc_c_string(&mut fixture.memory, "casa1_no_such_clr_export_42")
                .expect("absent symbol");
            let proc_out = words(&mut fixture.memory, 0x41_420, 1);
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    8,
                    &[absent_name as u32, proc_out as u32]
                ),
                u64::from(HRESULT_PROC_NOT_FOUND)
            );
            assert_eq!(read_ptr_at(&fixture.memory, proc_out), 0);
            assert_eq!(
                call_method(&mut fixture, info, 6, &[0, buffer as u32, size as u32, 0]),
                0
            );
            assert_eq!(
                read_wide(&fixture.memory, buffer),
                "Runtime error 0x8007007F"
            );

            let present_name = fixture
                .runtime
                .alloc_c_string(&mut fixture.memory, "coreclr_set_error_writer")
                .expect("present symbol");
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    8,
                    &[present_name as u32, proc_out as u32]
                ),
                0
            );
            let proc = read_ptr_at(&fixture.memory, proc_out);
            assert_ne!(proc, 0);
            assert_eq!(
                call_x86(&mut fixture, proc, &[0]),
                0,
                "the resolved CoreCLR export is callable through the host bridge"
            );
            assert_eq!(
                call_method(&mut fixture, info, 8, &[0, proc_out as u32]),
                u64::from(E_INVALIDARG)
            );
            let empty_name = fixture
                .runtime
                .alloc_c_string(&mut fixture.memory, "")
                .expect("empty symbol");
            assert_eq!(
                call_method(&mut fixture, info, 8, &[empty_name as u32, proc_out as u32]),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                call_method(&mut fixture, info, 8, &[present_name as u32, 0]),
                u64::from(E_POINTER)
            );

            let missing_name = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "casa1-missing.dll")
                .expect("missing library");
            let handle_out = words(&mut fixture.memory, 0x41_440, 1);
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    7,
                    &[missing_name as u32, handle_out as u32]
                ),
                u64::from(HRESULT_MOD_NOT_FOUND)
            );
            assert_eq!(read_ptr_at(&fixture.memory, handle_out), 0);
            let existing_name = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "System.Runtime.dll")
                .expect("existing assembly");
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    7,
                    &[existing_name as u32, handle_out as u32]
                ),
                u64::from(CLR_E_SHIM_RUNTIMELOAD)
            );
            assert_eq!(read_ptr_at(&fixture.memory, handle_out), 0);
            assert_eq!(
                call_method(&mut fixture, info, 6, &[0, 0, size as u32, 0]),
                0
            );
            assert_eq!(read_u32_at(&fixture.memory, size), 33);
            assert_eq!(
                call_method(&mut fixture, info, 6, &[0, buffer as u32, size as u32, 0]),
                0
            );
            assert_eq!(
                read_wide(&fixture.memory, buffer),
                "The runtime could not be loaded."
            );
            assert_eq!(
                call_method(&mut fixture, info, 7, &[0, handle_out as u32]),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                call_method(&mut fixture, info, 7, &[existing_name as u32, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, info, 6, &[0, buffer as u32, 0, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(call_method(&mut fixture, info, 2, &[]), 0);
            write_guid(&mut fixture.memory, qi_iid, IID_ICLR_RUNTIME_INFO);
            assert_eq!(
                call_method(&mut fixture, info, 0, &[qi_iid as u32, qi_out as u32]),
                u64::from(E_UNEXPECTED),
                "a destroyed runtime info object cannot be queried"
            );
        })
    }

    #[test]
    fn clr_runtime_host_executes_delegates_and_reports_real_failures() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-runtime-host");
            // The mscorwks export hands out the same real host object.
            let export_iid = words(&mut fixture.memory, 0x41_200, 4);
            let export_out = words(&mut fixture.memory, 0x41_220, 1);
            write_guid(&mut fixture.memory, export_iid, IID_ICLR_RUNTIME_HOST);
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::GetClrRuntimeHost,
                    &[export_iid as u32, export_out as u32]
                ),
                0
            );
            let export_host = read_ptr_at(&fixture.memory, export_out);
            assert_ne!(export_host, 0, "GetCLRRuntimeHost returns a real host");
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::GetClrRuntimeHost,
                    &[export_iid as u32, 0]
                ),
                u64::from(E_POINTER)
            );
            write_guid(&mut fixture.memory, export_iid, IID_IENUM_UNKNOWN);
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::GetClrRuntimeHost,
                    &[export_iid as u32, export_out as u32]
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, export_out), 0);
            assert_eq!(call_method(&mut fixture, export_host, 2, &[]), 0);

            // An explicit installed CoreCLR version binds a real host; a
            // Framework version stays genuinely absent.
            let legacy_version = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, &real_version())
                .expect("coreclr version");
            let legacy_clsid = words(&mut fixture.memory, 0x41_240, 4);
            let legacy_iid = words(&mut fixture.memory, 0x41_260, 4);
            write_guid(&mut fixture.memory, legacy_clsid, CLSID_CLR_RUNTIME_HOST);
            write_guid(&mut fixture.memory, legacy_iid, IID_ICLR_RUNTIME_HOST);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[
                        legacy_version as u32,
                        0,
                        0,
                        legacy_clsid as u32,
                        legacy_iid as u32,
                        export_out as u32
                    ]
                ),
                0
            );
            let bound = read_ptr_at(&fixture.memory, export_out);
            assert_ne!(bound, 0, "CoreCLR version binds a real host");
            assert_eq!(call_method(&mut fixture, bound, 2, &[]), 0);

            let framework_version = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "v4.0.30319")
                .expect("framework version");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[
                        framework_version as u32,
                        0,
                        0,
                        legacy_clsid as u32,
                        legacy_iid as u32,
                        export_out as u32
                    ]
                ),
                u64::from(COR_E_CLRNOTAVAILABLE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, export_out), 0);

            let meta = create_meta_host(&mut fixture);
            let (hr, info) = get_runtime(&mut fixture, meta, &real_version());
            assert_eq!(hr, 0);
            assert_ne!(info, 0);

            let clsid = words(&mut fixture.memory, 0x41_280, 4);
            let iid = words(&mut fixture.memory, 0x41_2A0, 4);
            let host_out = words(&mut fixture.memory, 0x41_2C0, 1);
            write_guid(&mut fixture.memory, clsid, CLSID_CLR_RUNTIME_HOST);
            write_guid(&mut fixture.memory, iid, IID_ICLR_RUNTIME_HOST);
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    9,
                    &[clsid as u32, iid as u32, host_out as u32]
                ),
                0
            );
            let host = read_ptr_at(&fixture.memory, host_out);
            assert_ne!(host, 0, "ICLRRuntimeHost is a real host object");

            // A riid pointer readable for only four bytes cannot carry a full
            // GUID: GetCLRRuntimeHost reports E_POINTER instead of reading
            // past the mapped range.
            let short_riid = words(&mut fixture.memory, 0x41_600, 1);
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::GetClrRuntimeHost,
                    &[short_riid as u32, export_out as u32]
                ),
                u64::from(E_POINTER)
            );

            // CorBindToRuntimeEx validates both GUID pointers and the
            // interface ID; restore the real IDs between sub-cases.
            let bind_clsid = words(&mut fixture.memory, 0x41_6C0, 4);
            let bind_iid = words(&mut fixture.memory, 0x41_6E0, 4);
            write_guid(&mut fixture.memory, bind_clsid, CLSID_CLR_RUNTIME_HOST);
            write_guid(&mut fixture.memory, bind_iid, IID_ICLR_RUNTIME_HOST);
            let short_clsid = words(&mut fixture.memory, 0x41_620, 1);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[
                        legacy_version as u32,
                        0,
                        0,
                        short_clsid as u32,
                        bind_iid as u32,
                        export_out as u32
                    ]
                ),
                u64::from(E_POINTER)
            );
            let short_iid = words(&mut fixture.memory, 0x41_640, 1);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[
                        legacy_version as u32,
                        0,
                        0,
                        bind_clsid as u32,
                        short_iid as u32,
                        export_out as u32
                    ]
                ),
                u64::from(E_POINTER)
            );
            write_guid(&mut fixture.memory, bind_iid, IID_IENUM_UNKNOWN);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[
                        legacy_version as u32,
                        0,
                        0,
                        bind_clsid as u32,
                        bind_iid as u32,
                        export_out as u32
                    ]
                ),
                u64::from(E_NOINTERFACE)
            );

            // ICLRRuntimeInfo::GetInterface applies the same GUID contract on
            // a live runtime-info object.
            let info_short_clsid = words(&mut fixture.memory, 0x41_660, 1);
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    9,
                    &[info_short_clsid as u32, iid as u32, host_out as u32]
                ),
                u64::from(E_POINTER)
            );
            let info_short_iid = words(&mut fixture.memory, 0x41_680, 1);
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    9,
                    &[clsid as u32, info_short_iid as u32, host_out as u32]
                ),
                u64::from(E_POINTER)
            );
            let info_bad_clsid = words(&mut fixture.memory, 0x41_6A0, 4);
            write_guid(&mut fixture.memory, info_bad_clsid, CLSID_CLR_META_HOST);
            assert_eq!(
                call_method(
                    &mut fixture,
                    info,
                    9,
                    &[info_bad_clsid as u32, iid as u32, host_out as u32]
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, host_out), 0);

            // A valid host IID succeeds and hands back the same object with
            // one extra reference.
            write_guid(&mut fixture.memory, iid, IID_ICLR_RUNTIME_HOST);
            assert_eq!(
                call_method(&mut fixture, host, 0, &[iid as u32, host_out as u32]),
                0
            );
            assert_eq!(read_ptr_at(&fixture.memory, host_out), host);
            assert_eq!(call_method(&mut fixture, host, 2, &[]), 1);

            // Only the documented host interfaces are exposed.
            write_guid(&mut fixture.memory, iid, IID_IENUM_UNKNOWN);
            assert_eq!(
                call_method(&mut fixture, host, 0, &[iid as u32, host_out as u32]),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, host_out), 0);

            assert_eq!(call_method(&mut fixture, host, 1, &[]), 2);
            assert_eq!(call_method(&mut fixture, host, 2, &[]), 1);
            assert_eq!(call_method(&mut fixture, host, 3, &[]), 0, "Start");
            let domain_out = words(&mut fixture.memory, 0x41_2E0, 1);
            assert_eq!(call_method(&mut fixture, host, 9, &[domain_out as u32]), 0);
            assert_eq!(read_u32_at(&fixture.memory, domain_out), 1);

            let result = words(&mut fixture.memory, 0x41_300, 1);
            assert_eq!(
                call_method(&mut fixture, host, 11, &[0, 0, 0, 0, result as u32]),
                u64::from(E_INVALIDARG)
            );

            let missing = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\missing.dll")
                .expect("missing path");
            let type_name = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "Casa1.Missing")
                .expect("type");
            let method_name = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "Run")
                .expect("method");
            let argument = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "arg")
                .expect("argument");
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    11,
                    &[
                        missing as u32,
                        type_name as u32,
                        method_name as u32,
                        argument as u32,
                        result as u32
                    ]
                ),
                u64::from(HRESULT_FILE_NOT_FOUND)
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 0);

            // A real managed assembly with an absent type is the CLR's own
            // execution failure, never a fabricated success.
            let runtime = crate::clr_meta::installed_runtimes()
                .into_iter()
                .next()
                .expect("a real runtime is installed");
            let source = runtime.directory.join("System.Runtime.dll");
            fixture
                .runtime
                .win32
                .stage_host_file_w(&source, "C:\\clr\\System.Runtime.dll")
                .expect("stage managed assembly");
            let assembly = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\System.Runtime.dll")
                .expect("assembly path");
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    11,
                    &[
                        assembly as u32,
                        type_name as u32,
                        method_name as u32,
                        argument as u32,
                        result as u32
                    ]
                ),
                u64::from(COR_E_EXECUTIONENGINE)
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 0);

            // ExecuteApplication runs a real entry point; libraries and
            // missing files are refused with exact host statuses.
            assert_eq!(
                call_method(&mut fixture, host, 10, &[0, 0, 0, 0, 0, result as u32]),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                call_method(&mut fixture, host, 10, &[assembly as u32, 0, 0, 0, 0, 0]),
                u64::from(E_POINTER)
            );
            let missing_app = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\missing.exe")
                .expect("missing app");
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    10,
                    &[missing_app as u32, 0, 0, 0, 0, result as u32]
                ),
                u64::from(HRESULT_FILE_NOT_FOUND)
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 0);
            let no_drive_app = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "no-drive-path.dll")
                .expect("in-guest app path");
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    10,
                    &[no_drive_app as u32, 0, 0, 0, 0, result as u32]
                ),
                u64::from(HRESULT_FILE_NOT_FOUND),
                "a guest path without a drive cannot be mapped to the host"
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 0);
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    10,
                    &[assembly as u32, 0, 0, 0, 0, result as u32]
                ),
                u64::from(COR_E_EXECUTIONENGINE),
                "a managed library has no entry point"
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 0);

            // Every remaining ICLRRuntimeHost method has a pinned contract.
            assert_eq!(call_method(&mut fixture, host, 4, &[]), 0, "Stop");
            assert_eq!(
                call_method(&mut fixture, host, 5, &[0]),
                u64::from(E_NOTIMPL),
                "SetHostControl"
            );
            assert_eq!(
                call_method(&mut fixture, host, 6, &[0]),
                u64::from(E_NOINTERFACE),
                "GetCLRControl"
            );
            assert_eq!(
                call_method(&mut fixture, host, 6, &[host_out as u32]),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, host_out), 0);
            assert_eq!(
                call_method(&mut fixture, host, 7, &[0, 0]),
                u64::from(E_NOTIMPL),
                "UnloadAppDomain"
            );
            assert_eq!(
                call_method(&mut fixture, host, 8, &[0, 0, 0]),
                u64::from(E_NOTIMPL),
                "ExecuteInAppDomain"
            );
            assert_eq!(
                call_method(&mut fixture, host, 9, &[0]),
                u64::from(E_POINTER)
            );

            // Unknown objects and malformed interface pointers are exact.
            write_guid(&mut fixture.memory, iid, IID_ICLR_RUNTIME_HOST);
            assert_eq!(
                call_method(&mut fixture, host, 0, &[iid as u32, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(&mut fixture, host, 0, &[0, host_out as u32]),
                u64::from(E_POINTER),
                "a null riid is E_POINTER"
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrRuntimeHostQueryInterface,
                    &[0xDEAD, iid as u32, host_out as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::ClrRuntimeHostAddRef, &[0xDEAD]),
                0
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::ClrRuntimeHostRelease, &[0xDEAD]),
                0
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::ClrRuntimeHostStart, &[0xDEAD]),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrRuntimeHostGetCurrentAppDomainId,
                    &[0xDEAD, domain_out as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrRuntimeHostExecuteApplication,
                    &[0xDEAD, assembly as u32, 0, 0, 0, 0, result as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ClrRuntimeHostExecuteInDefaultAppDomain,
                    &[
                        0xDEAD,
                        assembly as u32,
                        type_name as u32,
                        method_name as u32,
                        0,
                        result as u32
                    ]
                ),
                u64::from(E_UNEXPECTED)
            );

            // ExecuteApplication argument validation and a real entry point.
            assert_eq!(
                call_method(&mut fixture, host, 10, &[assembly as u32, 0, 0, 0, 0, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    10,
                    &[assembly as u32, 1, 0, 0, 0, result as u32]
                ),
                u64::from(E_INVALIDARG),
                "manifest count without paths"
            );
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    10,
                    &[assembly as u32, 0, 0, 1, 0, result as u32]
                ),
                u64::from(E_INVALIDARG),
                "activation count without data"
            );

            let runtime_dir = crate::clr_meta::installed_runtimes()
                .into_iter()
                .next()
                .expect("a real runtime is installed")
                .directory;
            let corelib = runtime_dir.join("System.Private.CoreLib.dll");
            fixture
                .runtime
                .win32
                .stage_host_file_w(&corelib, "C:\\clr\\System.Private.CoreLib.dll")
                .expect("stage corelib");
            let corelib_guest = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\System.Private.CoreLib.dll")
                .expect("corelib path");
            let environment = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "System.Environment")
                .expect("type");
            let processor_count = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "get_ProcessorCount")
                .expect("method");
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    11,
                    &[
                        corelib_guest as u32,
                        environment as u32,
                        processor_count as u32,
                        0,
                        result as u32
                    ]
                ),
                0,
                "a real managed method executes through ICLRRuntimeHost"
            );
            assert_ne!(read_u32_at(&fixture.memory, result), 0);
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    11,
                    &[
                        corelib_guest as u32,
                        0,
                        processor_count as u32,
                        0,
                        result as u32
                    ]
                ),
                u64::from(E_INVALIDARG)
            );
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    11,
                    &[
                        corelib_guest as u32,
                        environment as u32,
                        processor_count as u32,
                        0,
                        0
                    ]
                ),
                u64::from(E_POINTER)
            );
            let empty_type = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "")
                .expect("empty type name");
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    11,
                    &[
                        corelib_guest as u32,
                        empty_type as u32,
                        processor_count as u32,
                        0,
                        result as u32
                    ]
                ),
                u64::from(E_INVALIDARG),
                "an empty type name is refused before CLR execution"
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 0);
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    11,
                    &[
                        no_drive_app as u32,
                        environment as u32,
                        processor_count as u32,
                        0,
                        result as u32
                    ]
                ),
                u64::from(HRESULT_FILE_NOT_FOUND),
                "a guest path without a drive cannot be mapped to the host"
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 0);

            let entry_fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/Casa1Entry.dll");
            fixture
                .runtime
                .win32
                .stage_host_file_w(&entry_fixture, "C:\\clr\\Casa1Entry.dll")
                .expect("stage managed app");
            let entry_guest = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "C:\\clr\\Casa1Entry.dll")
                .expect("entry path");
            let one = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "one")
                .expect("arg one");
            let two = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "two")
                .expect("arg two");
            let activation = words(&mut fixture.memory, 0x41_500, 2);
            write_guest_pointer(&mut fixture.memory, activation, one, GuestArch::X86)
                .expect("arg pointer");
            write_guest_pointer(&mut fixture.memory, activation + 4, two, GuestArch::X86)
                .expect("arg pointer");
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    10,
                    &[
                        entry_guest as u32,
                        0,
                        0,
                        2,
                        activation as u32,
                        result as u32
                    ]
                ),
                0,
                "the managed entry point runs with activation data"
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 9);

            // A null activation pointer is skipped rather than dereferenced;
            // the remaining arguments still reach the entry point.
            let sparse_activation = words(&mut fixture.memory, 0x41_540, 3);
            write_guest_pointer(&mut fixture.memory, sparse_activation, one, GuestArch::X86)
                .expect("arg pointer");
            write_guest_pointer(
                &mut fixture.memory,
                sparse_activation + 8,
                two,
                GuestArch::X86,
            )
            .expect("arg pointer");
            assert_eq!(
                call_method(
                    &mut fixture,
                    host,
                    10,
                    &[
                        entry_guest as u32,
                        0,
                        0,
                        3,
                        sparse_activation as u32,
                        result as u32
                    ]
                ),
                0,
                "a null activation pointer is skipped"
            );
            assert_eq!(read_u32_at(&fixture.memory, result), 9);

            // CorBind: malformed arguments and unparsable/absent versions.
            let bad_version = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "not-a-version")
                .expect("bad version");
            let absent_coreclr = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "9.9.9")
                .expect("absent version");
            let empty_version = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "")
                .expect("empty version");
            for args in [
                [legacy_version, 0, 0, legacy_clsid, legacy_iid, 0],
                [0, 0, 0, legacy_clsid, legacy_iid, export_out],
                [empty_version, 0, 0, legacy_clsid, legacy_iid, export_out],
                [legacy_version, 0, 0, 0, legacy_iid, export_out],
                [legacy_version, 0, 0, legacy_clsid, 0, export_out],
            ] {
                assert_ne!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::CorBindToRuntimeEx,
                        &args.map(|value| value as u32)
                    ),
                    0
                );
            }
            write_guid(&mut fixture.memory, legacy_clsid, IID_IENUM_UNKNOWN);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[legacy_version, 0, 0, legacy_clsid, legacy_iid, export_out]
                        .map(|value| value as u32)
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[bad_version, 0, 0, export_iid, legacy_iid, export_out]
                        .map(|value| value as u32)
                ),
                u64::from(E_NOINTERFACE)
            );
            write_guid(&mut fixture.memory, legacy_clsid, CLSID_CLR_RUNTIME_HOST);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[bad_version, 0, 0, legacy_clsid, legacy_iid, export_out]
                        .map(|value| value as u32)
                ),
                u64::from(COR_E_CLRNOTAVAILABLE)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[absent_coreclr, 0, 0, legacy_clsid, legacy_iid, export_out]
                        .map(|value| value as u32)
                ),
                u64::from(COR_E_CLRNOTAVAILABLE)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetClrRuntimeHost,
                    &[export_iid as u32, 0]
                ),
                u64::from(E_POINTER)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetClrRuntimeHost,
                    &[0, export_out as u32]
                ),
                u64::from(E_POINTER)
            );
        })
    }

    #[test]
    fn clr_runtime_host_execute_application_x64_rejects_missing_assembly_with_eight_byte_pointers()
    {
        with_big_stack(|| {
            let (mut runtime, mut memory, _temp) = x64_runtime("clr-runtime-host-x64");
            let riid = 0x41_000_u64;
            let host_out = 0x41_020_u64;
            memory.map_bytes(riid, &IID_ICLR_RUNTIME_HOST);
            memory.map_bytes(host_out, &[0_u8; 8]);
            let get_host = runtime.alloc_host_thunk(HostThunk::GetClrRuntimeHost);
            let mut state = CpuState::new(GuestArch::X64);
            state.set(Register::Rcx, riid);
            state.set(Register::Rdx, host_out);
            runtime
                .dispatch_import(get_host, &mut state, &mut memory)
                .expect("dispatch GetClrRuntimeHost");
            assert_eq!(state.get(Register::Rax), 0);
            let host = memory.read_u64(host_out).expect("host pointer");
            assert_ne!(host, 0, "x64 GetCLRRuntimeHost returns a real host");

            let application = runtime
                .alloc_utf16_string(&mut memory, "C:\\clr\\missing64.dll")
                .expect("application path");
            let one = runtime
                .alloc_utf16_string(&mut memory, "one")
                .expect("arg one");
            let two = runtime
                .alloc_utf16_string(&mut memory, "two")
                .expect("arg two");
            let activation = 0x42_000_u64;
            let mut activation_bytes = [0_u8; 24];
            activation_bytes[0..8].copy_from_slice(&one.to_le_bytes());
            activation_bytes[16..24].copy_from_slice(&two.to_le_bytes());
            memory.map_bytes(activation, &activation_bytes);
            let stack = 0x58_000_u64;
            memory.map_bytes(stack, &[0_u8; 0x100]);
            let result = 0x43_000_u64;
            memory.map_bytes(result, &[0_u8; 8]);
            write_u64(&mut memory, stack + 0x28, 3);
            write_u64(&mut memory, stack + 0x30, activation);
            write_u64(&mut memory, stack + 0x38, result);
            let execute = runtime.alloc_host_thunk(HostThunk::ClrRuntimeHostExecuteApplication);
            let mut state = CpuState::new(GuestArch::X64);
            state.set(Register::Rsp, stack);
            state.set(Register::Rcx, host);
            state.set(Register::Rdx, application);
            state.set(Register::R8, 0);
            state.set(Register::R9, 0);
            runtime
                .dispatch_import(execute, &mut state, &mut memory)
                .expect("dispatch ExecuteApplication");
            assert_eq!(
                state.get(Register::Rax),
                u64::from(HRESULT_FILE_NOT_FOUND),
                "the x64 arm reads three eight-byte activation pointers before refusing a missing assembly"
            );
            assert_eq!(memory.read_u32(result).expect("result code"), 0);
        })
    }

    #[test]
    fn clr_loaded_notification_refuses_duplicates_and_invokes_the_real_callback() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-loaded-notification");
            let meta = create_meta_host(&mut fixture);
            assert_eq!(
                call_method(&mut fixture, meta, 7, &[0]),
                u64::from(E_INVALIDARG)
            );

            let marker = words(&mut fixture.memory, 0x41_500, 1);
            let callback_address = 0x1000_0000_u64;
            let mut callback_bytes = vec![
                0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
                0xA3, // mov [marker], eax
            ];
            callback_bytes.extend_from_slice(&(marker as u32).to_le_bytes());
            callback_bytes.push(0xC3);
            fixture.memory.map_bytes(callback_address, &callback_bytes);
            assert_eq!(
                call_method(&mut fixture, meta, 7, &[callback_address as u32]),
                0
            );
            assert_eq!(
                call_method(&mut fixture, meta, 7, &[callback_address as u32]),
                u64::from(E_UNEXPECTED),
                "the CLR permits exactly one loaded callback"
            );

            let mut state = CpuState::new(GuestArch::X86);
            fixture.memory.map_bytes(STACK - 0x800, &[0_u8; 0x1000]);
            state.set(Register::Rsp, STACK);
            assert_eq!(
                fixture
                    .runtime
                    .notify_clr_runtime_loaded(&mut state, &mut fixture.memory, "v8")
                    .expect("malformed version"),
                false
            );
            assert_eq!(
                fixture
                    .runtime
                    .notify_clr_runtime_loaded(&mut state, &mut fixture.memory, "999.0.0")
                    .expect("absent version"),
                false
            );
            let version = real_version();
            assert_eq!(
                fixture
                    .runtime
                    .notify_clr_runtime_loaded(&mut state, &mut fixture.memory, &version)
                    .expect("loaded runtime"),
                true
            );
            let delivered = u64::from(read_u32_at(&fixture.memory, marker));
            assert_ne!(delivered, 0, "the callback receives a runtime-info object");
            assert_eq!(
                fixture
                    .runtime
                    .notify_clr_runtime_loaded(&mut state, &mut fixture.memory, &version)
                    .expect("second notification"),
                false,
                "a runtime is reported loaded only once"
            );

            let thread_set = fixture
                .runtime
                .alloc_host_thunk(HostThunk::ClrRuntimeLoadedCallbackThreadSet);
            let thread_unset = fixture
                .runtime
                .alloc_host_thunk(HostThunk::ClrRuntimeLoadedCallbackThreadUnset);
            assert_eq!(call_x86(&mut fixture, thread_set, &[]), 0);
            assert_eq!(
                clr_objects().thread_pinned(fixture.runtime.guest_pid),
                Some(true)
            );
            assert_eq!(call_x86(&mut fixture, thread_unset, &[]), 0);
            assert_eq!(
                clr_objects().thread_pinned(fixture.runtime.guest_pid),
                Some(false)
            );

            let (hr, info) = get_runtime(&mut fixture, meta, &version);
            assert_eq!(hr, 0);
            let loaded_out = words(&mut fixture.memory, 0x41_540, 1);
            assert_eq!(
                call_method(&mut fixture, info, 5, &[0, loaded_out as u32]),
                0
            );
            assert_eq!(read_u32_at(&fixture.memory, loaded_out), 1);
            assert_eq!(call_method(&mut fixture, info, 2, &[]), 0);

            let out = words(&mut fixture.memory, 0x41_560, 1);
            let item = words(&mut fixture.memory, 0x41_580, 1);
            let fetched = words(&mut fixture.memory, 0x41_5A0, 1);
            assert_eq!(
                call_method(&mut fixture, meta, 6, &[0, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(call_method(&mut fixture, meta, 6, &[0, out as u32]), 0);
            let loaded = read_ptr_at(&fixture.memory, out);
            assert_eq!(
                call_method(&mut fixture, loaded, 3, &[1, item as u32, fetched as u32]),
                0
            );
            assert_eq!(read_u32_at(&fixture.memory, fetched), 1);
            let info = read_ptr_at(&fixture.memory, item);
            let size = words(&mut fixture.memory, 0x41_5C0, 1);
            let buffer = words(&mut fixture.memory, 0x41_5E0, 32);
            assert_eq!(call_method(&mut fixture, info, 3, &[0, size as u32]), 0);
            assert_eq!(
                call_method(&mut fixture, info, 3, &[buffer as u32, size as u32]),
                0
            );
            assert_eq!(read_wide(&fixture.memory, buffer), version);
            assert_eq!(call_method(&mut fixture, info, 2, &[]), 0);
            assert_eq!(call_method(&mut fixture, loaded, 2, &[]), 0);
        })
    }

    #[test]
    fn clr_meta_host_legacy_binding_and_exit_are_framework_absent() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-legacy");
            let meta = create_meta_host(&mut fixture);
            let iid = words(&mut fixture.memory, 0x41_060, 4);
            let out = words(&mut fixture.memory, 0x41_080, 1);
            write_guid(&mut fixture.memory, iid, IID_ICLR_META_HOST);
            assert_eq!(
                call_method(&mut fixture, meta, 8, &[iid as u32, out as u32]),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);
            assert_eq!(
                call_method(&mut fixture, meta, 8, &[iid as u32, 0]),
                u64::from(E_POINTER)
            );
            assert_eq!(call_method(&mut fixture, meta, 9, &[7]), 0);
            assert_eq!(fixture.runtime.process_exit_requested, Some(7));

            let mut state = CpuState::new(GuestArch::X86);
            fixture.memory.map_bytes(STACK - 0x800, &[0_u8; 0x1000]);
            state.set(Register::Rsp, STACK);
            assert_eq!(
                fixture
                    .runtime
                    .notify_clr_runtime_loaded(&mut state, &mut fixture.memory, &real_version())
                    .expect("loaded without callback"),
                true
            );
            assert_eq!(
                fixture
                    .runtime
                    .notify_clr_runtime_loaded(&mut state, &mut fixture.memory, &real_version())
                    .expect("duplicate load"),
                false
            );

            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &[0, 0, 0, 0, 0, out as u32],
                ),
                u64::from(COR_E_CLRNOTAVAILABLE),
                "the .NET Framework CLR is genuinely absent"
            );
            let directory_buffer = words(&mut fixture.memory, 0x41_600, 16);
            let length = words(&mut fixture.memory, 0x41_640, 1);
            // The host has a real CoreCLR: a 16-char buffer is too small, so
            // the call reports the required size instead of failing absent.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetCorSystemDirectory,
                    &[directory_buffer as u32, 16, length as u32],
                ),
                0x8007_007A,
                "insufficient CoreCLR directory buffer"
            );
            assert_ne!(read_u32_at(&fixture.memory, length), 0);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &[0, 0, 0, 0, 0, 0, 0, 0, 0],
                ),
                u64::from(E_FAIL)
            );
            assert_eq!(
                dispatch_x86(&mut fixture, HostThunk::LoadLibraryShim, &[0, 0, 0, 0],),
                u64::from(E_FAIL)
            );
        })
    }

    #[test]
    fn clr_host_export_thunk_rejects_malformed_absent_and_unknown_symbols() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-host-export-edges");
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrHostExport {
                        runtime_version: "v8".to_string(),
                        symbol: "coreclr_set_error_writer".to_string(),
                    },
                    &[]
                ),
                u64::from(HRESULT_PROC_NOT_FOUND),
                "a malformed runtime version cannot resolve a host export"
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrHostExport {
                        runtime_version: "999.0.0".to_string(),
                        symbol: "coreclr_set_error_writer".to_string(),
                    },
                    &[]
                ),
                u64::from(HRESULT_PROC_NOT_FOUND)
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrHostExport {
                        runtime_version: real_version(),
                        symbol: "casa1_no_such_clr_export_42".to_string(),
                    },
                    &[]
                ),
                u64::from(HRESULT_PROC_NOT_FOUND),
                "a symbol missing from the real dylib is rejected at call time"
            );
        })
    }

    #[test]
    fn clr_host_export_x64_passes_register_arguments_without_abi_mismatch() {
        with_big_stack(|| {
            let (mut runtime, mut memory, _temp) = x64_runtime("clr-host-export-x64");
            let thunk = runtime.alloc_host_thunk(HostThunk::ClrHostExport {
                runtime_version: real_version(),
                symbol: "coreclr_set_error_writer".to_string(),
            });
            let stack = 0x58_000_u64;
            memory.map_bytes(stack, &[0_u8; 0x400]);
            write_u64(&mut memory, stack, 0xDEAD_BEEF);
            let mut state = CpuState::new(GuestArch::X64);
            state.set(Register::Rsp, stack);
            runtime
                .dispatch_import(thunk, &mut state, &mut memory)
                .expect("dispatch host export");
            assert_eq!(state.get(Register::Rax), 0);
        })
    }

    #[test]
    fn clr_runtime_info_unknown_objects_are_rejected() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("clr-unknown-object");
            let size = words(&mut fixture.memory, 0x41_060, 1);
            let buffer = words(&mut fixture.memory, 0x41_080, 32);
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoGetVersionString,
                    &[0xDEAD_0000, buffer as u32, size as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoGetRuntimeDirectory,
                    &[0xDEAD_0000, buffer as u32, size as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoLoadErrorString,
                    &[0xDEAD_0000, 0, buffer as u32, size as u32, 0]
                ),
                u64::from(E_UNEXPECTED)
            );
            let symbol = fixture
                .runtime
                .alloc_c_string(&mut fixture.memory, "coreclr_initialize")
                .expect("symbol");
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoGetProcAddress,
                    &[0xDEAD_0000, symbol as u32, size as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoAddRef,
                    &[0xDEAD_0000]
                ),
                0,
                "an unknown object has no refcount"
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoRelease,
                    &[0xDEAD_0000]
                ),
                0
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoLoadLibrary,
                    &[0xDEAD_0000, buffer as u32, size as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoGetInterface,
                    &[0xDEAD_0000, buffer as u32, size as u32, size as u32]
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrRuntimeInfoIsLoaded,
                    &[0xDEAD_0000, 0, size as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                call_thunk(&mut fixture, HostThunk::ClrEnumUnknownReset, &[0xDEAD_0000]),
                u64::from(E_UNEXPECTED)
            );
            assert_eq!(
                call_thunk(
                    &mut fixture,
                    HostThunk::ClrEnumUnknownClone,
                    &[0xDEAD_0000, size as u32]
                ),
                u64::from(E_UNEXPECTED)
            );
            let mut state = CpuState::new(GuestArch::X86);
            let error = fixture
                .runtime
                .dispatch_mscoree(&HostThunk::GetProcAddress, &mut state, &mut fixture.memory)
                .expect_err("an unrouted mscoree thunk is an implementation error");
            assert_eq!(error.code, crate::reason::ReasonCode::RcUnimplInsn);
            assert_eq!(read_u32_at(&fixture.memory, size), 0);
        })
    }

    fn alloc_wide(fixture: &mut Fixture, text: &str) -> u64 {
        fixture
            .runtime
            .alloc_utf16_string(&mut fixture.memory, text)
            .expect("allocate wide string")
    }

    fn bind_expected_hr(request: &str) -> u64 {
        let crate::clr_host::ActivationFamily::CoreClr(parsed) =
            crate::clr_host::activation_family(Some(request))
        else {
            return u64::from(COR_E_CLRNOTAVAILABLE);
        };
        let installed = crate::clr_meta::installed_runtimes();
        if crate::clr_meta::select_runtime(&parsed, &installed).is_some() {
            u64::from(S_OK)
        } else {
            u64::from(COR_E_CLRNOTAVAILABLE)
        }
    }

    fn bind_ex_args(
        version: u64,
        flavor: u64,
        flags: u32,
        clsid: u64,
        iid: u64,
        out: u64,
    ) -> [u32; 6] {
        [
            version as u32,
            flavor as u32,
            flags,
            clsid as u32,
            iid as u32,
            out as u32,
        ]
    }

    fn requested_info_args(
        version: u64,
        directory: u64,
        directory_capacity: u32,
        directory_length: u64,
        version_buffer: u64,
        version_capacity: u32,
        version_length: u64,
    ) -> [u32; 11] {
        [
            0,
            version as u32,
            0,
            0,
            0,
            directory as u32,
            directory_capacity,
            directory_length as u32,
            version_buffer as u32,
            version_capacity,
            version_length as u32,
        ]
    }

    #[test]
    fn cor_bind_framework_versions_flavors_flags_and_riids_are_exactly_absent() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("cor-bind-framework-absent");
            let out = words(&mut fixture.memory, 0x41_000, 1);
            let clsid = words(&mut fixture.memory, 0x41_020, 4);
            let iid = words(&mut fixture.memory, 0x41_040, 4);

            let mut versions = Vec::new();
            for version in [
                "v1.0.3650",
                "v1.1.4322",
                "v2.0.50727",
                "v4.0.30319",
                "1.0",
                "1.1",
                "2.0",
                "4.0",
                "v3.5",
            ] {
                versions.push(alloc_wide(&mut fixture, version));
            }
            let mut flavors = Vec::new();
            for flavor in ["wks", "svr", "bogus"] {
                flavors.push(alloc_wide(&mut fixture, flavor));
            }
            let ids = [
                (CLSID_CLR_RUNTIME_HOST, IID_ICLR_RUNTIME_HOST),
                (CLSID_CLR_RUNTIME_HOST, IID_IUNKNOWN),
                (CLSID_COR_RUNTIME_HOST, IID_ICOR_RUNTIME_HOST),
                (CLSID_COR_RUNTIME_HOST, IID_ICLR_RUNTIME_HOST),
                (CLSID_COR_RUNTIME_HOST, IID_IUNKNOWN),
            ];

            for version in &versions {
                for flavor in std::iter::once(0).chain(flavors.iter().copied()) {
                    for (class, interface) in ids {
                        write_guid(&mut fixture.memory, clsid, class);
                        write_guid(&mut fixture.memory, iid, interface);
                        for flags in [0_u32, 1, 0xFFFF_FFFF] {
                            assert_eq!(
                                dispatch_x86(
                                    &mut fixture,
                                    HostThunk::CorBindToRuntimeEx,
                                    &bind_ex_args(*version, flavor, flags, clsid, iid, out),
                                ),
                                u64::from(COR_E_CLRNOTAVAILABLE),
                                "a Framework request is genuinely absent"
                            );
                            assert_eq!(read_ptr_at(&fixture.memory, out), 0);
                        }
                    }
                }
            }

            // The legacy CorBindToRuntime has no startupFlags argument; its
            // CLSID/RIID/out arguments are in the Ex positions minus one.
            write_guid(&mut fixture.memory, clsid, CLSID_COR_RUNTIME_HOST);
            write_guid(&mut fixture.memory, iid, IID_ICOR_RUNTIME_HOST);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntime,
                    &[
                        versions[3] as u32,
                        flavors[0] as u32,
                        clsid as u32,
                        iid as u32,
                        out as u32,
                    ],
                ),
                u64::from(COR_E_CLRNOTAVAILABLE),
                "the 5-argument export keeps the Framework-absent contract"
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);

            // Versionless and empty requests are the Framework latest-runtime
            // request, not a CoreCLR bind.
            let empty = alloc_wide(&mut fixture, "");
            for version in [0_u32, empty as u32] {
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::CorBindToRuntimeEx,
                        &bind_ex_args(u64::from(version), 0, 0, clsid, iid, out),
                    ),
                    u64::from(COR_E_CLRNOTAVAILABLE)
                );
                assert_eq!(read_ptr_at(&fixture.memory, out), 0);
            }
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &bind_ex_args(versions[3], 0, 0, clsid, iid, 0),
                ),
                u64::from(E_POINTER)
            );
        })
    }

    #[test]
    fn cor_bind_coreclr_versions_bind_real_host_and_reject_framework_interfaces() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("cor-bind-coreclr");
            let out = words(&mut fixture.memory, 0x41_000, 1);
            let clsid = words(&mut fixture.memory, 0x41_020, 4);
            let iid = words(&mut fixture.memory, 0x41_040, 4);
            let version = alloc_wide(&mut fixture, &real_version());

            write_guid(&mut fixture.memory, clsid, CLSID_CLR_RUNTIME_HOST);
            write_guid(&mut fixture.memory, iid, IID_ICLR_RUNTIME_HOST);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &bind_ex_args(version, 0, 0xFFFF_FFFF, clsid, iid, out),
                ),
                0,
                "an installed CoreCLR version binds the real host"
            );
            let host = read_ptr_at(&fixture.memory, out);
            assert_ne!(host, 0);
            assert_eq!(call_method(&mut fixture, host, 2, &[]), 0);

            // Both runtime class IDs are accepted; the interface decides what
            // the runtime can actually expose.
            write_guid(&mut fixture.memory, clsid, CLSID_COR_RUNTIME_HOST);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntime,
                    &[version as u32, 0, clsid as u32, iid as u32, out as u32],
                ),
                0,
                "the legacy export binds the same real CoreCLR host"
            );
            assert_ne!(read_ptr_at(&fixture.memory, out), 0);

            // CoreCLR does not implement the legacy Framework interface.
            write_guid(&mut fixture.memory, iid, IID_ICOR_RUNTIME_HOST);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &bind_ex_args(version, 0, 0, clsid, iid, out),
                ),
                u64::from(E_NOINTERFACE)
            );
            assert_eq!(read_ptr_at(&fixture.memory, out), 0);
            write_guid(&mut fixture.memory, iid, IID_IENUM_UNKNOWN);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &bind_ex_args(version, 0, 0, clsid, iid, out),
                ),
                u64::from(E_NOINTERFACE)
            );

            // Unknown class IDs are rejected before the runtime is touched.
            write_guid(&mut fixture.memory, clsid, IID_ICLR_RUNTIME_HOST);
            write_guid(&mut fixture.memory, iid, IID_ICLR_RUNTIME_HOST);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &bind_ex_args(version, 0, 0, clsid, iid, out),
                ),
                u64::from(E_NOINTERFACE)
            );

            // Null out/CLSID/RIID pointers follow the COM pointer contract.
            write_guid(&mut fixture.memory, clsid, CLSID_CLR_RUNTIME_HOST);
            write_guid(&mut fixture.memory, iid, IID_ICLR_RUNTIME_HOST);
            for args in [
                bind_ex_args(version, 0, 0, clsid, iid, 0),
                bind_ex_args(version, 0, 0, 0, iid, out),
                bind_ex_args(version, 0, 0, clsid, 0, out),
                bind_ex_args(version, 0, 0, 0, 0, out),
            ] {
                assert_eq!(
                    dispatch_x86(&mut fixture, HostThunk::CorBindToRuntimeEx, &args),
                    u64::from(E_POINTER)
                );
            }

            // "8.0" resolves only when an 8.x CoreCLR is installed.
            let eight = alloc_wide(&mut fixture, "8.0");
            let expected = bind_expected_hr("8.0");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CorBindToRuntimeEx,
                    &bind_ex_args(eight, 0, 0, clsid, iid, out),
                ),
                expected
            );
            assert_eq!(read_ptr_at(&fixture.memory, out) != 0, expected == 0);

            for text in ["9.9.9", "v8", "not-a-version", "4.0.30319"] {
                let request = alloc_wide(&mut fixture, text);
                let expected = bind_expected_hr(text);
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::CorBindToRuntimeEx,
                        &bind_ex_args(request, 0, 0, clsid, iid, out),
                    ),
                    expected,
                    "{text} cannot bind a runtime"
                );
                assert_eq!(read_ptr_at(&fixture.memory, out), 0);
            }
        })
    }

    #[test]
    fn get_requested_runtime_info_reports_real_install_buffers_and_absent_failure() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("get-requested-runtime-info");
            let runtime = crate::clr_meta::installed_runtimes()
                .into_iter()
                .next()
                .expect("a real CoreCLR runtime is installed");
            let version_text = runtime.version_string();
            let expected_directory = format!("{}\\", runtime.directory.to_string_lossy());
            let directory_units = expected_directory.encode_utf16().count() as u32 + 1;
            let version_units = version_text.encode_utf16().count() as u32 + 1;
            let request = alloc_wide(&mut fixture, &version_text);

            let directory_length = words(&mut fixture.memory, 0x41_100, 1);
            let version_length = words(&mut fixture.memory, 0x41_120, 1);
            let directory_buffer = words(&mut fixture.memory, 0x42_000, 128);
            let version_buffer = words(&mut fixture.memory, 0x42_400, 64);

            // Size query: null buffers report the required units including NUL.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &requested_info_args(request, 0, 0, directory_length, 0, 0, version_length),
                ),
                0
            );
            assert_eq!(
                read_u32_at(&fixture.memory, directory_length),
                directory_units
            );
            assert_eq!(read_u32_at(&fixture.memory, version_length), version_units);

            // Short buffers report the required size and fail with the exact
            // Windows insufficient-buffer status.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &requested_info_args(
                        request,
                        directory_buffer,
                        directory_units - 1,
                        directory_length,
                        version_buffer,
                        version_units - 1,
                        version_length,
                    ),
                ),
                u64::from(HRESULT_INSUFFICIENT_BUFFER)
            );
            assert_eq!(
                read_u32_at(&fixture.memory, directory_length),
                directory_units
            );
            assert_eq!(read_u32_at(&fixture.memory, version_length), version_units);

            // Exact capacities succeed and write the real directory/version.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &requested_info_args(
                        request,
                        directory_buffer,
                        directory_units,
                        directory_length,
                        version_buffer,
                        version_units,
                        version_length,
                    ),
                ),
                0
            );
            assert_eq!(
                read_wide(&fixture.memory, directory_buffer),
                expected_directory
            );
            assert_eq!(read_wide(&fixture.memory, version_buffer), version_text);
            assert_eq!(
                read_u32_at(&fixture.memory, directory_length),
                directory_units
            );
            assert_eq!(read_u32_at(&fixture.memory, version_length), version_units);

            // A non-null buffer with no length out-pointer is E_POINTER.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &requested_info_args(request, directory_buffer, 128, 0, 0, 0, 0),
                ),
                u64::from(E_POINTER)
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &requested_info_args(request, 0, 0, 0, version_buffer, 64, 0),
                ),
                u64::from(E_POINTER)
            );
            // No output requested at all keeps the legacy shim E_FAIL.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &requested_info_args(request, 0, 0, 0, 0, 0, 0),
                ),
                u64::from(E_FAIL)
            );

            // Framework, garbage, absent and versionless requests are absent.
            for text in ["v4.0.30319", "v2.0", "garbage", "999.0.0"] {
                let request = alloc_wide(&mut fixture, text);
                write_u32(&mut fixture.memory, directory_length, 0);
                write_u32(&mut fixture.memory, version_length, 0);
                assert_eq!(
                    dispatch_x86(
                        &mut fixture,
                        HostThunk::GetRequestedRuntimeInfo,
                        &requested_info_args(
                            request,
                            directory_buffer,
                            directory_units,
                            directory_length,
                            version_buffer,
                            version_units,
                            version_length,
                        ),
                    ),
                    u64::from(COR_E_CLRNOTAVAILABLE),
                    "{text} is not an installed runtime"
                );
                assert_eq!(read_u32_at(&fixture.memory, directory_length), 0);
                assert_eq!(read_u32_at(&fixture.memory, version_length), 0);
            }
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &requested_info_args(
                        0,
                        directory_buffer,
                        directory_units,
                        directory_length,
                        version_buffer,
                        version_units,
                        version_length,
                    ),
                ),
                u64::from(COR_E_CLRNOTAVAILABLE),
                "a versionless request is the absent Framework latest runtime"
            );

            // "8.0" reports the installed 8.x runtime exactly when present.
            // Its directory can differ in length from the newest runtime, so
            // use roomy buffers for this conditional selection.
            let eight = alloc_wide(&mut fixture, "8.0");
            let expected = bind_expected_hr("8.0");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GetRequestedRuntimeInfo,
                    &requested_info_args(
                        eight,
                        directory_buffer,
                        256,
                        directory_length,
                        version_buffer,
                        64,
                        version_length,
                    ),
                ),
                expected
            );
            if expected == 0 {
                assert_eq!(
                    read_wide(&fixture.memory, version_buffer),
                    crate::clr_host::requested_runtime_version(Some("8.0"))
                        .expect("selected runtime")
                );
            }
        })
    }
}
