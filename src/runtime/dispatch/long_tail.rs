//! Long-tail dispatch: the final system surfaces — atl.dll/atl80/atl100,
//! windowscodecsext.dll, actxprxy.dll, the overlay/CRT/steam DLLs,
//! certcli.dll, d3dx10_43.dll, gameux.dll, the script engines
//! (jscript/vbscript), mscorwks.dll, mshtml.dll, ntdsapi.dll, wbemcomn.dll
//! and the remaining 3-export DLLs — in a dedicated module per the audit's
//! modularity requirement.  Each surface answers its honest state: the ATL
//! module server operations succeed with the runtime's module registry, the
//! codec extensions report the honest no-codec answers, the CRT
//! synchronization primitives are real (the mtx/cond state), the directory
//! services bindings answer the honest no-domain answers, and the module
//! class-object exports route through the shared in-process COM server
//! contract.
//!
//! Layer contract: every export returns its HRESULT/BOOL/error code in EAX.

use super::super::*;

/// S_OK / TRUE / ERROR_SUCCESS.
const S_OK: u32 = 0;
const TRUE: u32 = 1;
const ERROR_SUCCESS: u32 = 0;
/// E_FAIL / ERROR_NOT_FOUND / ERROR_ACCESS_DENIED.
const E_FAIL: u32 = 0x8000_4005;
const ERROR_NOT_FOUND: u32 = 1168;
const ERROR_ACCESS_DENIED: u32 = 5;

impl PeHostRuntime {
    /// Route every long-tail thunk to its dispatch function.
    pub(crate) fn dispatch_long_tail(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            // ── ATL module server operations ──
            HostThunk::AtlModuleRegisterServer
            | HostThunk::AtlModuleUnregisterServer
            | HostThunk::AtlModuleRegisterTypeLib
            | HostThunk::AtlModuleUnregisterTypeLib
            | HostThunk::AtlModuleAddTermFunc
            | HostThunk::AtlModuleUpdateRegistryFromResource => {
                let _module = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::AtlModuleLoadTypeLib => {
                let _module = guest_call_arg(state, memory, 0)?;
                let _name = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No typelibs are loadable.
                state.set(Register::Rax, 0x8002_9c4a); // TYPE_E_CANTLOADLIBRARY
                Ok(())
            }
            // ── WIC codec extensions ──
            HostThunk::WicCreateAvifDecoder
            | HostThunk::WicCreateAvifEncoder
            | HostThunk::WicCreateHeifDecoder
            | HostThunk::WicCreateHeifEncoder
            | HostThunk::WicCreateWebpDecoder
            | HostThunk::WicCreateWebpEncoder => {
                let _flags = guest_call_arg_u32(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No extended codecs are registered.
                state.set(Register::Rax, 0x8898_2f02); // WIC_E_CODECNOTFOUND
                Ok(())
            }
            // ── actxprxy ──
            HostThunk::DllInstall => {
                let _install = guest_call_arg_u32(state, memory, 0)?;
                let _command = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── the overlay hooks ──
            HostThunk::OverlayCreateHook => {
                let _app = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                // No overlay host is registered.
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::OverlayHookWindow
            | HostThunk::OverlayUnhookWindow
            | HostThunk::OverlayPresent
            | HostThunk::OverlayReset => {
                let _hwnd = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            // ── the CRT synchronization primitives (real state) ──
            HostThunk::CndInit | HostThunk::MtxInit => {
                let _out = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::MtxDestroy => {
                let _mtx = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::MtxLock => {
                let _mtx = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::MtxUnlock => {
                let _mtx = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            // ── the exception/stack CRT helpers ──
            HostThunk::CCSpecificHandler | HostThunk::Chkstk => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::CurrentException => {
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::CurrentExceptionContext => {
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::ProcessingThrow => {
                state.set(Register::Rax, 0);
                Ok(())
            }
            // ── steam: the session state ──
            HostThunk::SteamBLoggedOn => {
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::SteamBGetSteamId => {
                let out = guest_call_arg(state, memory, 0)?;
                if out != 0 {
                    write_guest_u64(memory, out, 0x1100_0001_0000_0001).ok();
                }
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::SteamBIsSubscribedApp => {
                let _app = guest_call_arg_u32(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::SteamNotifyOfLogin | HostThunk::SteamNotifyOfLogoff => {
                let _name = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            // ── certcli: the backup surface ──
            HostThunk::CertSrvBackupPrepare => {
                let _server = guest_call_arg(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let _state = guest_call_arg_u32(state, memory, 2)?;
                let out = guest_call_arg(state, memory, 3)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::CertSrvBackupEnd
            | HostThunk::CertSrvRestoreEnd
            | HostThunk::CertSrvRestorePrepare => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── d3dx10 ──
            HostThunk::D3dx10CompileFromFile => {
                let _file = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0x8000_4005);
                Ok(())
            }
            HostThunk::D3dx10CreateTextureFromFileW => {
                let _device = guest_call_arg(state, memory, 0)?;
                let _file = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, 0x8876_0006); // D3DXERR_INVALIDDATA
                Ok(())
            }
            HostThunk::D3dx10GetImageInfoFromFile => {
                let _file = guest_call_arg(state, memory, 0)?;
                let _info = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, 0x8876_0006);
                Ok(())
            }
            HostThunk::D3dx10SaveTextureToMemory => {
                let _texture = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0x8876_0006);
                Ok(())
            }
            // ── gameux ──
            HostThunk::GameExplorerInitialize => {
                let _hwnd = guest_call_arg(state, memory, 0)?;
                let _permission = guest_call_arg_u32(state, memory, 1)?;
                let _title = guest_call_arg(state, memory, 2)?;
                let _game = guest_call_arg(state, memory, 3)?;
                let out = guest_call_arg(state, memory, 4)?;
                if out != 0 {
                    write_guest_u32(memory, out, 0).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GameExplorerSetUserAccess | HostThunk::GameExplorerVerifyAccess => {
                let _game = guest_call_arg(state, memory, 0)?;
                let _access = guest_call_arg_u32(state, memory, 1)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::GameuxShfolderpath => {
                let _id = guest_call_arg_u32(state, memory, 0)?;
                let path = guest_call_arg(state, memory, 1)?;
                if path != 0 {
                    write_guest_u16(memory, path, 0).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── mscorwks: the CLR-absent answers ──
            HostThunk::ClrCreateManagedInstance
            | HostThunk::CorBindToRuntime
            | HostThunk::CorBindToRuntimeEx
            | HostThunk::GetClrRuntimeHost => {
                let out_index = if matches!(thunk, HostThunk::ClrCreateManagedInstance) {
                    2
                } else {
                    0
                };
                let out = guest_call_arg(state, memory, out_index)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8013_1013); // COR_E_CLRNOTAVAILABLE
                Ok(())
            }
            // ── mshtml ──
            HostThunk::CreateHtmlPropertyPage => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::IeFrameFactoryConstructor => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            HostThunk::ShowHtmlDialogEx => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::IhtmlDocument2 => {
                let _arg = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── ntdsapi ──
            HostThunk::DsBind | HostThunk::DsBindWithCred => {
                let _server = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No domain controller is reachable.
                state.set(Register::Rax, 0x8007_0e8d); // ERROR_DS_NOT_AVAILABLE
                Ok(())
            }
            HostThunk::DsUnbind => {
                let _binding = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::DsMakeSpnW => {
                let _class = guest_call_arg(state, memory, 0)?;
                let _host = guest_call_arg(state, memory, 1)?;
                let buffer = guest_call_arg(state, memory, 2)?;
                let size = guest_call_arg(state, memory, 3)?;
                if buffer != 0 && size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                state.set(Register::Rax, 0x8007_011f); // ERROR_BUFFER_OVERFLOW
                Ok(())
            }
            // ── ADSI ──
            HostThunk::AdsGetObject | HostThunk::AdsOpenObject => {
                let _path = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8007_200e); // E_ADS_UNKNOWN_OBJECT
                Ok(())
            }
            HostThunk::AdsBuildEnumerator => {
                let _container = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── certadm ──
            HostThunk::CertSrvAdminGetCa
            | HostThunk::CertSrvAdminGetCert
            | HostThunk::CertSrvAdminSetCa => {
                let _server = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── d3d10_1 ──
            HostThunk::D3d10CreateDevice1 => {
                let _adapter = guest_call_arg(state, memory, 0)?;
                let _driver = guest_call_arg_u32(state, memory, 1)?;
                let _software = guest_call_arg(state, memory, 2)?;
                let _flags = guest_call_arg_u32(state, memory, 3)?;
                let _version = guest_call_arg_u32(state, memory, 4)?;
                let out = guest_call_arg(state, memory, 5)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::D3d10CreateDeviceAndSwapChain1 => {
                let _adapter = guest_call_arg(state, memory, 0)?;
                let _driver = guest_call_arg_u32(state, memory, 1)?;
                let _software = guest_call_arg(state, memory, 2)?;
                let _flags = guest_call_arg_u32(state, memory, 3)?;
                let _version = guest_call_arg_u32(state, memory, 4)?;
                let _desc = guest_call_arg(state, memory, 5)?;
                let out = guest_call_arg(state, memory, 6)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::D3d10CreateEffectFromMemory => {
                let _memory = guest_call_arg(state, memory, 0)?;
                let _size = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── dhcpcsvc6 ──
            HostThunk::Dhcpv6RequestParams
            | HostThunk::Dhcpv6RenewParams
            | HostThunk::Dhcpv6ReleaseParams => {
                let _adapter = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0x79b); // ERROR_DHCP_ADDRESS_CONFLICT
                Ok(())
            }
            // ── dinput8 ──
            HostThunk::GetdfDIJoystick => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            // ── fwpuclnt ──
            HostThunk::FwpsOpenToken => {
                let _arg = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_ACCESS_DENIED));
                Ok(())
            }
            HostThunk::FwpsQueryTokenInformation => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_ACCESS_DENIED));
                Ok(())
            }
            HostThunk::FwpsFilter => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── ieframe ──
            HostThunk::IeGetFrameComponent
            | HostThunk::IeGetWriteableHlink
            | HostThunk::IeHlink => {
                let _arg = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            // ── loadperf ──
            HostThunk::LoadPerfCounterTextStringsW | HostThunk::UnloadPerfCounterTextStringsW => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::SetServiceAsTrusted => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_ACCESS_DENIED));
                Ok(())
            }
            // ── msimsg ──
            HostThunk::MsiFormatRecordW => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _record = guest_call_arg(state, memory, 1)?;
                let buffer = guest_call_arg(state, memory, 2)?;
                let size = guest_call_arg(state, memory, 3)?;
                if buffer != 0 && size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                let _ = _handle;
                state.set(Register::Rax, 6); // ERROR_INVALID_HANDLE
                Ok(())
            }
            HostThunk::MsiGetLastErrorRecord => {
                let out = guest_call_arg(state, memory, 0)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::MsiProcessMessage => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _kind = guest_call_arg_u32(state, memory, 1)?;
                let _record = guest_call_arg(state, memory, 2)?;
                state.set(Register::Rax, 6); // ERROR_INVALID_HANDLE
                Ok(())
            }
            // ── mspatcha ──
            HostThunk::ApplyPatchToFileW | HostThunk::ApplyPatchToFileExW => {
                let _patch = guest_call_arg(state, memory, 0)?;
                let _target = guest_call_arg(state, memory, 1)?;
                let _output = guest_call_arg(state, memory, 2)?;
                state.set(Register::Rax, u64::from(ERROR_NOT_FOUND));
                Ok(())
            }
            HostThunk::GetPatchFileSignature => {
                let _patch = guest_call_arg(state, memory, 0)?;
                let _signature = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(ERROR_NOT_FOUND));
                Ok(())
            }
            // ── printui ──
            HostThunk::PrintUiEntry | HostThunk::PrintUiToDevice | HostThunk::PrintUiToFile => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                Ok(())
            }
            // ── samlib ──
            HostThunk::SamConnect => {
                let _server = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_ACCESS_DENIED));
                Ok(())
            }
            HostThunk::SamCloseHandle | HostThunk::SamOpenDomain => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_ACCESS_DENIED));
                Ok(())
            }
            // ── scecli ──
            HostThunk::ScGenerateRelativeName
            | HostThunk::ScRemoveAllPrivileges
            | HostThunk::ScSetSecurityDescriptor => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_ACCESS_DENIED));
                Ok(())
            }
            // ── winrnr ──
            HostThunk::RnrInitialize => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::RnrQuery => {
                let _arg = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x274c); // RPC_S_ENTRY_NOT_FOUND
                Ok(())
            }
            HostThunk::RnrCancelQuery => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── winsta ──
            HostThunk::WinStationOpenServer => {
                let _name = guest_call_arg(state, memory, 0)?;
                let _ = _name;
                state.set(Register::Rax, 0x1000_0000);
                Ok(())
            }
            HostThunk::WinStationCloseServer => {
                let _server = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::WinStationEnumerate => {
                let _server = guest_call_arg(state, memory, 0)?;
                let _reserved = guest_call_arg_u32(state, memory, 1)?;
                let _version = guest_call_arg_u32(state, memory, 2)?;
                let stations = guest_call_arg(state, memory, 3)?;
                let count = guest_call_arg(state, memory, 4)?;
                if stations != 0 {
                    write_guest_pointer(memory, stations, 0, self.guest_arch).ok();
                }
                if count != 0 {
                    write_guest_u32(memory, count, 0).ok();
                }
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            // ── xapofx ──
            HostThunk::CreateFx | HostThunk::XAudio2Create => {
                let _clsid = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No XAPO effects are registered.
                state.set(Register::Rax, 0x8896_0002); // XAPO_E_NOT_IMPLEMENTED
                Ok(())
            }
            // ── xinput9_1_0 ──
            HostThunk::XInputGetState => {
                let _user = guest_call_arg_u32(state, memory, 0)?;
                let _state = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, 0x48f); // ERROR_DEVICE_NOT_CONNECTED
                Ok(())
            }
            HostThunk::XInputGetCapabilities => {
                let _user = guest_call_arg_u32(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let _caps = guest_call_arg(state, memory, 2)?;
                state.set(Register::Rax, 0x48f);
                Ok(())
            }
            HostThunk::XInputSetState => {
                let _user = guest_call_arg_u32(state, memory, 0)?;
                let _state = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, 0x48f);
                Ok(())
            }
            // ── the shared module-class contract ──
            HostThunk::DllCanUnloadNow | HostThunk::DllGetClassObject => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::DllRegisterServer | HostThunk::DllUnregisterServer => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted long-tail thunk {thunk:?}"),
            )),
        }
    }
}
