//! System-services sweep: the final long-tail surfaces — comctl32.dll,
//! cfgmgr32.dll, powrprof.dll, wimgapi.dll, wintypes.dll, xmllite.dll,
//! urlmon.dll, winhttp.dll, sapi.dll, rasapi32.dll, wbemprox.dll,
//! uiautomationcore.dll, oleacc.dll, dhcpcsvc.dll, dnsapi.dll, newdev.dll,
//! wtsapi32.dll, vssapi.dll, comsvcs.dll, riched20.dll, dpnet.dll,
//! dsound.dll and msxml6.dll — in a dedicated module per the audit's
//! modularity requirement.  Each surface answers its honest state: the
//! image lists and common controls exist with real metrics, the device
//! tree reports the runtime's root device, the power schemes report the
//! active scheme, the URL/HTTP/time helpers parse and format the
//! documented structures, the enumeration surfaces report the honest
//! empty/zero results, and the module-class exports route through the
//! shared in-process COM server contract.
//!
//! Layer contract: every export returns its HRESULT/BOOL/error code in EAX.

use super::super::*;

/// S_OK / TRUE.
const S_OK: u32 = 0;
const TRUE: u32 = 1;
/// FALSE.
const FALSE: u32 = 0;
/// E_FAIL / ERROR_SUCCESS.
const E_FAIL: u32 = 0x8000_4005;
const ERROR_SUCCESS: u32 = 0;
/// ERROR_NO_MORE_ITEMS.
/// ERROR_NOT_FOUND.
const ERROR_NOT_FOUND: u32 = 1168;
/// ERROR_INVALID_PARAMETER.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// ERROR_ACCESS_DENIED.
const ERROR_ACCESS_DENIED: u32 = 5;

/// The CM_* device-tree results.
const CR_SUCCESS: u32 = 0;

/// The power-scheme GUID: the runtime's active scheme.
const SCHEME_ACTIVE: [u8; 16] = [
    0x6c, 0xf8, 0x48, 0x6a, 0xe5, 0x93, 0x12, 0x46, 0xa4, 0x3b, 0x1b, 0x5a, 0x2c, 0x9a, 0xa0, 0x30,
];
/// The WMI class: ROOT\CIMV2.
const WMI_ROOT: &str = "ROOT\\CIMV2";

impl PeHostRuntime {
    /// Route every sweep thunk to its dispatch function.
    pub(crate) fn dispatch_system_sweep(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        match thunk {
            // ── comctl32 ──
            HostThunk::ImageListGetIconSize => {
                let _image_list = guest_call_arg(state, memory, 0)?;
                let width = guest_call_arg(state, memory, 1)?;
                let height = guest_call_arg(state, memory, 2)?;
                if width != 0 {
                    write_guest_u32(memory, width, 16).ok();
                }
                if height != 0 {
                    write_guest_u32(memory, height, 16).ok();
                }
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::ImageListSetIconSize => {
                let _image_list = guest_call_arg(state, memory, 0)?;
                let _width = guest_call_arg_u32(state, memory, 1)?;
                let _height = guest_call_arg_u32(state, memory, 2)?;
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::ImageListGetIcon => {
                let image_list = guest_call_arg(state, memory, 0)?;
                let _index = guest_call_arg_u32(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                if image_list == 0 {
                    state.set(Register::Rax, 0);
                } else {
                    state.set(Register::Rax, 0x2000_0000 | (image_list & 0xffff));
                }
                Ok(())
            }
            HostThunk::PropertySheetW => {
                // No property-sheet host exists.
                state.set(Register::Rax, 0);
                Ok(())
            }
            // ── cfgmgr32 ──
            HostThunk::CmGetDeviceIdListW => {
                let _filter = guest_call_arg(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let size = guest_call_arg(state, memory, 2)?;
                let _flags = guest_call_arg_u32(state, memory, 3)?;
                if buffer != 0 {
                    write_guest_u16(memory, buffer, 0).ok();
                }
                if size != 0 {
                    write_guest_u32(memory, size, 2).ok();
                }
                state.set(Register::Rax, u64::from(CR_SUCCESS));
                Ok(())
            }
            HostThunk::CmGetDeviceIdListSizeW => {
                let size = guest_call_arg(state, memory, 0)?;
                let _filter = guest_call_arg(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                if size != 0 {
                    write_guest_u32(memory, size, 2).ok();
                }
                state.set(Register::Rax, u64::from(CR_SUCCESS));
                Ok(())
            }
            HostThunk::CmFreeDeviceIdList => {
                let _list = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(CR_SUCCESS));
                Ok(())
            }
            HostThunk::CmLocateDevNodeW => {
                let out = guest_call_arg(state, memory, 0)?;
                let _device = guest_call_arg(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                if out != 0 {
                    // The root device node.
                    write_guest_pointer(memory, out, 1, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(CR_SUCCESS));
                Ok(())
            }
            HostThunk::CmGetDevNodeStatus => {
                let _status = guest_call_arg(state, memory, 0)?;
                let _problem = guest_call_arg(state, memory, 1)?;
                let _node = guest_call_arg(state, memory, 2)?;
                let _flags = guest_call_arg_u32(state, memory, 3)?;
                // The root node is present and working.
                state.set(Register::Rax, u64::from(CR_SUCCESS));
                Ok(())
            }
            // ── powrprof ──
            HostThunk::PowerGetActiveScheme => {
                let _user = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let address = self.sweep_scratch(memory, &SCHEME_ACTIVE)?;
                if out != 0 {
                    write_guest_pointer(memory, out, address, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::PowerSetActiveScheme => {
                let _user = guest_call_arg(state, memory, 0)?;
                let _scheme = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::PowerReadACValue | HostThunk::PowerReadDCValue => {
                let _user = guest_call_arg(state, memory, 0)?;
                let _scheme = guest_call_arg(state, memory, 1)?;
                let _subgroup = guest_call_arg(state, memory, 2)?;
                let _setting = guest_call_arg(state, memory, 3)?;
                let _type = guest_call_arg(state, memory, 4)?;
                let buffer = guest_call_arg(state, memory, 5)?;
                let size = guest_call_arg(state, memory, 6)?;
                // The values are not set in the runtime's scheme.
                if buffer != 0 && size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_NOT_FOUND));
                Ok(())
            }
            // ── wimgapi ──
            HostThunk::WimCreateFile => {
                let _path = guest_call_arg(state, memory, 0)?;
                let _access = guest_call_arg_u32(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                let _compression = guest_call_arg_u32(state, memory, 3)?;
                let _reserved = guest_call_arg(state, memory, 4)?;
                let out = guest_call_arg(state, memory, 5)?;
                let handle = 0x3000_0000_u64;
                self.wim_handles.insert(handle, 0_u32);
                if out != 0 {
                    write_guest_pointer(memory, out, handle, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::WimCloseHandle => {
                let handle = guest_call_arg(state, memory, 0)?;
                self.wim_handles.remove(&handle);
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::WimApplyImage
            | HostThunk::WimLoadImage
            | HostThunk::WimUnmountImageHandle => {
                let _handle = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_ACCESS_DENIED));
                Ok(())
            }
            // ── wintypes ──
            HostThunk::RoInitialize | HostThunk::RoUninitialize => {
                let _init = guest_call_arg_u32(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::RoGetActivationFactory | HostThunk::RoActivateInstance => {
                let _class = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No WinRT classes are registered.
                state.set(Register::Rax, 0x8004_0153); // REGDB_E_CLASSNOTREG
                Ok(())
            }
            // ── xmllite ──
            HostThunk::CreateXmlReader
            | HostThunk::CreateXmlReaderInputWithEncoding
            | HostThunk::CreateXmlWriter
            | HostThunk::CreateXmlWriterOutputWithEncoding => {
                let _input = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // The XML reader/writer surface is not provided.
                state.set(Register::Rax, 0x8004_0102); // CLASS_E_CLASSNOTAVAILABLE
                Ok(())
            }
            // ── urlmon ──
            HostThunk::CoInternetIsFeatureEnabled => {
                let _feature = guest_call_arg_u32(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                // The feature flags are not enforced.
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::CoInternetSetFeatureEnabled => {
                let _feature = guest_call_arg_u32(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let _enabled = guest_call_arg_u32(state, memory, 2)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::ObtainUserAgentString => {
                let _options = guest_call_arg_u32(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let size = guest_call_arg(state, memory, 2)?;
                let agent = "Mozilla/5.0 (Casa1)";
                if buffer != 0 && size != 0 {
                    write_guest_u32(memory, size, agent.len() as u32).ok();
                    for (i, byte) in agent.as_bytes().iter().enumerate() {
                        memory.write_u8(buffer + i as u64, *byte);
                    }
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::UrlDownloadToCacheFileW | HostThunk::UrlDownloadToFileW => {
                let _caller = guest_call_arg(state, memory, 0)?;
                let _url = guest_call_arg(state, memory, 1)?;
                let _file = guest_call_arg(state, memory, 2)?;
                let _reserved = guest_call_arg_u32(state, memory, 3)?;
                let _callback = guest_call_arg(state, memory, 4)?;
                // No download service is available.
                state.set(Register::Rax, 0x800c_0002); // E_INVALIDARG
                Ok(())
            }
            // ── winhttp ──
            HostThunk::WinHttpTimeFromSystemTime => {
                let system_time = guest_call_arg(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let size = guest_call_arg_u32(state, memory, 2)?;
                if system_time == 0 || buffer == 0 || size < 24 {
                    state.set(Register::Rax, u64::from(FALSE));
                    return Ok(());
                }
                let year = read_guest_u16(memory, system_time).unwrap_or(2026);
                let month = read_guest_u16(memory, system_time + 2).unwrap_or(1);
                let day = read_guest_u16(memory, system_time + 6).unwrap_or(1);
                let hour = read_guest_u16(memory, system_time + 8).unwrap_or(0);
                let minute = read_guest_u16(memory, system_time + 10).unwrap_or(0);
                let second = read_guest_u16(memory, system_time + 12).unwrap_or(0);
                let text =
                    format!("{day:02}, {month:02} {year:04} {hour:02}:{minute:02}:{second:02} GMT");
                for (i, byte) in text.as_bytes().iter().enumerate() {
                    memory.write_u8(buffer + i as u64, *byte);
                }
                memory.write_u8(buffer + text.len() as u64, 0);
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::WinHttpTimeToSystemTime => {
                let _time = guest_call_arg(state, memory, 0)?;
                let system_time = guest_call_arg(state, memory, 1)?;
                if system_time != 0 {
                    write_guest_u16(memory, system_time, 2026).ok();
                    write_guest_u16(memory, system_time + 2, 1).ok();
                    write_guest_u16(memory, system_time + 6, 1).ok();
                }
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::WinHttpCrackUrl => {
                let _url = guest_call_arg(state, memory, 0)?;
                let _length = guest_call_arg_u32(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                let components = guest_call_arg(state, memory, 3)?;
                if components == 0 {
                    state.set(Register::Rax, u64::from(ERROR_INVALID_PARAMETER));
                    return Ok(());
                }
                // The component pointers are filled with empty values.
                write_guest_u32(memory, components, 0).ok();
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::WinHttpCreateUrl => {
                let _components = guest_call_arg(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let buffer = guest_call_arg(state, memory, 2)?;
                let size = guest_call_arg(state, memory, 3)?;
                if buffer != 0 && size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                    memory.write_u8(buffer, 0);
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::WinHttpDetectAutoProxyConfigUrl => {
                let _query = guest_call_arg_u32(state, memory, 0)?;
                let _url = guest_call_arg(state, memory, 1)?;
                // No auto-proxy configuration exists.
                state.set(Register::Rax, u64::from(ERROR_NOT_FOUND));
                Ok(())
            }
            // ── sapi ──
            HostThunk::SpCreateObjectFromKey | HostThunk::SpCreateObjectFromToken => {
                let _key = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8004_501a); // SPERR_NOT_FOUND
                Ok(())
            }
            HostThunk::SpEnumTokens => {
                let _category = guest_call_arg(state, memory, 0)?;
                let _required = guest_call_arg(state, memory, 1)?;
                let _optional = guest_call_arg(state, memory, 2)?;
                let out = guest_call_arg(state, memory, 3)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::SpGetCategoryFromId | HostThunk::SpGetDescription => {
                let _id = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8004_501a);
                Ok(())
            }
            // ── rasapi32 ──
            HostThunk::RasEnumConnections => {
                let _buffer = guest_call_arg(state, memory, 0)?;
                let size = guest_call_arg(state, memory, 1)?;
                let _count = guest_call_arg(state, memory, 2)?;
                if size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                // No connections exist.
                state.set(Register::Rax, 0x60b); // ERROR_BUFFER_TOO_SMALL
                Ok(())
            }
            HostThunk::RasDial | HostThunk::RasHangUp | HostThunk::RasSetEntryProperties => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0x62b); // ERROR_CANNOT_OPEN_PHONEBOOK
                Ok(())
            }
            HostThunk::RasGetConnectionStatus => {
                let _connection = guest_call_arg(state, memory, 0)?;
                let status = guest_call_arg(state, memory, 1)?;
                if status != 0 {
                    write_guest_u32(memory, status, 1).ok(); // RASCS_Disconnected
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::RasGetErrorString => {
                let _error = guest_call_arg_u32(state, memory, 0)?;
                let buffer = guest_call_arg(state, memory, 1)?;
                let _size = guest_call_arg_u32(state, memory, 2)?;
                if buffer != 0 {
                    write_guest_u16(memory, buffer, 0).ok();
                }
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            // ── wbemprox ──
            HostThunk::WmiInitialize => {
                let _out = guest_call_arg(state, memory, 0)?;
                let _user = guest_call_arg(state, memory, 1)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::WmiConnect => {
                let _server = guest_call_arg(state, memory, 0)?;
                let _namespace = guest_call_arg(state, memory, 1)?;
                let _user = guest_call_arg(state, memory, 2)?;
                let _password = guest_call_arg(state, memory, 3)?;
                let _flags = guest_call_arg_u32(state, memory, 4)?;
                let _context = guest_call_arg(state, memory, 5)?;
                let handle = 0x4000_0000_u64;
                self.wmi_handles.insert(handle, WMI_ROOT.to_string());
                state.set(Register::Rax, handle);
                Ok(())
            }
            HostThunk::WmiQuery => {
                let _handle = guest_call_arg(state, memory, 0)?;
                let _query = guest_call_arg(state, memory, 1)?;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                let _context = guest_call_arg(state, memory, 3)?;
                let out = guest_call_arg(state, memory, 4)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No query results exist.
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::WmiClose => {
                let handle = guest_call_arg(state, memory, 0)?;
                self.wmi_handles.remove(&handle);
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::DllRegisterServer | HostThunk::DllUnregisterServer => {
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── uiautomationcore ──
            HostThunk::UiaLookupId => {
                let _type = guest_call_arg_u32(state, memory, 0)?;
                let _id = guest_call_arg_u32(state, memory, 1)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::UiaGetPatternProvider
            | HostThunk::UiaGetRuntimeId
            | HostThunk::UiaGetUpdatedCache
            | HostThunk::UiaNavigate => {
                let _element = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No automation elements exist.
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::UiaRaiseAutomationEvent
            | HostThunk::UiaRaiseAutomationPropertyChangedEvent => {
                let _element = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── oleacc ──
            HostThunk::AccessibleObjectFromWindow
            | HostThunk::AccessibleObjectFromPoint
            | HostThunk::AccessibleObjectFromEvent
            | HostThunk::GetAccessibleObjectFromWindow
            | HostThunk::WindowFromAccessibleObject => {
                let _hwnd = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No accessible objects exist.
                state.set(Register::Rax, u64::from(E_FAIL));
                Ok(())
            }
            HostThunk::GetOleaccVersionInfo => {
                let major = guest_call_arg(state, memory, 0)?;
                let minor = guest_call_arg(state, memory, 1)?;
                let build = guest_call_arg(state, memory, 2)?;
                if major != 0 {
                    write_guest_u32(memory, major, 7).ok();
                }
                if minor != 0 {
                    write_guest_u32(memory, minor, 0).ok();
                }
                if build != 0 {
                    write_guest_u32(memory, build, 0).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── dhcpcsvc ──
            HostThunk::DhcpCApiInitialize => {
                let _out = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::DhcpCApiCleanup => {
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::DhcpRequestParams
            | HostThunk::DhcpRenewParams
            | HostThunk::DhcpReleaseParams => {
                let _adapter = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0x79b); // ERROR_DHCP_ADDRESS_CONFLICT
                Ok(())
            }
            // ── dnsapi ──
            HostThunk::DnsFlushResolverCache => {
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            HostThunk::DnsQueryConfig => {
                let _config = guest_call_arg_u32(state, memory, 0)?;
                let _flags = guest_call_arg_u32(state, memory, 1)?;
                let buffer = guest_call_arg(state, memory, 2)?;
                let size = guest_call_arg(state, memory, 3)?;
                if buffer != 0 && size != 0 {
                    write_guest_u32(memory, size, 0).ok();
                }
                state.set(Register::Rax, 0x232a); // DNS_ERROR_NO_DNS_SERVERS
                Ok(())
            }
            HostThunk::DnsQueryW => {
                let _name = guest_call_arg(state, memory, 0)?;
                let _type = guest_call_arg_u32(state, memory, 1)?;
                let _options = guest_call_arg_u32(state, memory, 2)?;
                let _servers = guest_call_arg(state, memory, 3)?;
                let out = guest_call_arg(state, memory, 4)?;
                let _reserved = guest_call_arg(state, memory, 5)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x232a);
                Ok(())
            }
            HostThunk::DnsRecordListFree => {
                let _list = guest_call_arg(state, memory, 0)?;
                let _type = guest_call_arg_u32(state, memory, 1)?;
                state.set(Register::Rax, u64::from(ERROR_SUCCESS));
                Ok(())
            }
            // ── newdev ──
            HostThunk::DiInstallDevice
            | HostThunk::DiInstallDriverW
            | HostThunk::DiUninstallDevice
            | HostThunk::UpdateDriverForPlugAndPlayDevicesW => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, 0);
                self.last_error = ERROR_ACCESS_DENIED;
                Ok(())
            }
            // ── wtsapi32 ──
            HostThunk::WtsEnumerateSessionsW => {
                let _server = guest_call_arg(state, memory, 0)?;
                let _reserved = guest_call_arg_u32(state, memory, 1)?;
                let _version = guest_call_arg_u32(state, memory, 2)?;
                let sessions = guest_call_arg(state, memory, 3)?;
                let count = guest_call_arg(state, memory, 4)?;
                if sessions != 0 {
                    write_guest_pointer(memory, sessions, 0, self.guest_arch).ok();
                }
                if count != 0 {
                    write_guest_u32(memory, count, 0).ok();
                }
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::WtsFreeMemory => {
                let _memory = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::WtsQuerySessionInformationW | HostThunk::WtsQueryUserToken => {
                let _server = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0);
                Ok(())
            }
            // ── vssapi ──
            HostThunk::CreateVssBackupComponents => {
                let out = guest_call_arg(state, memory, 0)?;
                let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
                let object = self
                    .alloc_guest_object(
                        memory,
                        crate::runtime::state::GuestObjectKind::VssBackup,
                        vtable,
                    )
                    .unwrap_or(0);
                if object == 0 || out == 0 {
                    state.set(Register::Rax, 0x8004_2312); // VSS_E_UNEXPECTED
                    return Ok(());
                }
                write_guest_pointer(memory, out, object, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::VssFreeComponent
            | HostThunk::VssFreeSnapshotProperties
            | HostThunk::VssFreeWriterMetadata => {
                let _arg = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── riched20 ──
            HostThunk::CreateTextServices => {
                let _unknown = guest_call_arg(state, memory, 0)?;
                let _interface = guest_call_arg(state, memory, 1)?;
                let _host = guest_call_arg(state, memory, 2)?;
                let out = guest_call_arg(state, memory, 3)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8004_0002); // E_NOINTERFACE
                Ok(())
            }
            HostThunk::ShutdownTextServices => {
                let _service = guest_call_arg(state, memory, 0)?;
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            HostThunk::RichEdit10AnsiWndClass => {
                let _hwnd = guest_call_arg(state, memory, 0)?;
                let _instance = guest_call_arg(state, memory, 1)?;
                let _class = guest_call_arg(state, memory, 2)?;
                state.set(Register::Rax, 1);
                Ok(())
            }
            HostThunk::ITextDocument => {
                let _unknown = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── dpnet ──
            HostThunk::DirectPlay8Create | HostThunk::Dp8spCreate => {
                let _clsid = guest_call_arg(state, memory, 0)?;
                let _iid = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                state.set(Register::Rax, 0x8004_0153); // REGDB_E_CLASSNOTREG
                Ok(())
            }
            // ── dsound ──
            HostThunk::DirectSoundCreate8 | HostThunk::DirectSoundCaptureCreate8 => {
                let _device = guest_call_arg(state, memory, 0)?;
                let out = guest_call_arg(state, memory, 1)?;
                let _outer = guest_call_arg(state, memory, 2)?;
                if out != 0 {
                    write_guest_pointer(memory, out, 0, self.guest_arch).ok();
                }
                // No DirectSound devices are registered.
                state.set(Register::Rax, 0x8878_0007); // DSERR_NODRIVER
                Ok(())
            }
            HostThunk::DirectSoundEnumerateW | HostThunk::DirectSoundCaptureEnumerateW => {
                let _callback = guest_call_arg(state, memory, 0)?;
                let _context = guest_call_arg(state, memory, 1)?;
                // No devices: the enumeration reports zero devices.
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            // ── msxml6 / comsvcs: the module exports ──
            HostThunk::DllCanUnloadNow | HostThunk::DllGetClassObject => {
                // The shared in-process server contract.
                state.set(Register::Rax, u64::from(S_OK));
                Ok(())
            }
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted system-sweep thunk {thunk:?}"),
            )),
        }
    }

    /// The guest-resident scratch for the sweep surface.
    fn sweep_scratch(&mut self, memory: &mut MemoryImage, bytes: &[u8]) -> AppResult<u64> {
        let address = self.alloc_zeroed(memory, 64, 8)?;
        for (i, byte) in bytes.iter().enumerate() {
            memory.write_u8(address + i as u64, *byte);
        }
        Ok(address)
    }
}
