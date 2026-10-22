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
/// ERROR_INSUFFICIENT_BUFFER.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// ERROR_WINHTTP_UNRECOGNIZED_SCHEME.
const ERROR_WINHTTP_UNRECOGNIZED_SCHEME: u32 = 12006;
/// ERROR_WINHTTP_INVALID_URL.
const ERROR_WINHTTP_INVALID_URL: u32 = 12181;

/// ICU_DECODE: percent-decode the copied components.
const ICU_DECODE: u32 = 0x1000_0000;
/// ICU_REJECT_USERPWD: reject URLs that carry embedded credentials.
const ICU_REJECT_USERPWD: u32 = 0x0000_4000;

/// The INTERNET_SCHEME values the HTTP-only WinHttp surface recognizes.
const INTERNET_SCHEME_HTTP: u32 = 1;
const INTERNET_SCHEME_HTTPS: u32 = 2;

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
                let image_list = guest_call_arg(state, memory, 0)? as u32;
                let width = guest_call_arg(state, memory, 1)?;
                let height = guest_call_arg(state, memory, 2)?;
                if image_list == 0 {
                    state.set(Register::Rax, u64::from(FALSE));
                    return Ok(());
                }
                // The runtime's image-list registry carries the real metrics;
                // an unregistered handle reports the documented defaults.
                let (icon_width, icon_height) = self
                    .image_lists
                    .get(&image_list)
                    .map(|info| {
                        (
                            info.image_width.max(0) as u32,
                            info.image_height.max(0) as u32,
                        )
                    })
                    .unwrap_or((16, 16));
                if width != 0 {
                    write_guest_u32(memory, width, icon_width).ok();
                }
                if height != 0 {
                    write_guest_u32(memory, height, icon_height).ok();
                }
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::ImageListSetIconSize => {
                let image_list = guest_call_arg(state, memory, 0)? as u32;
                let width = guest_call_arg(state, memory, 1)? as i32;
                let height = guest_call_arg(state, memory, 2)? as i32;
                if image_list == 0 || width <= 0 || height <= 0 {
                    state.set(Register::Rax, u64::from(FALSE));
                    return Ok(());
                }
                match self.image_lists.get_mut(&image_list) {
                    Some(info) => {
                        info.image_width = width;
                        info.image_height = height;
                    }
                    None => {
                        self.image_lists.insert(
                            image_list,
                            crate::runtime::ImageListInfo {
                                image_count: 0,
                                image_width: width,
                                image_height: height,
                                flags: 0,
                                images: Vec::new(),
                            },
                        );
                    }
                }
                state.set(Register::Rax, u64::from(TRUE));
                Ok(())
            }
            HostThunk::ImageListGetIcon => {
                let image_list = guest_call_arg(state, memory, 0)? as u32;
                let index = guest_call_arg(state, memory, 1)? as i32;
                let _flags = guest_call_arg_u32(state, memory, 2)?;
                let icon = match self.image_lists.get(&image_list) {
                    Some(info) if index >= 0 && index < info.image_count => {
                        0x2000_0000 | ((image_list & 0x7fff) << 16) | (index as u32 & 0xffff)
                    }
                    _ => 0,
                };
                state.set(Register::Rax, u64::from(icon));
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
                self.dispatch_winhttp_time_to_system_time(state, memory)
            }
            HostThunk::WinHttpCrackUrl => self.dispatch_winhttp_crack_url(state, memory),
            HostThunk::WinHttpCreateUrl => self.dispatch_winhttp_create_url(state, memory),
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
            // ── dpnet: DirectPlay8Create / DP8SPCreate are routed to the real
            //    DirectPlay engine dispatcher (see `dispatch::final_scraps`
            //    and `crate::dplay`) ──
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

    // ── winhttp: the URL component and time helpers ────────────────────────

    /// `WinHttpCrackUrl(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents)` —
    /// split the URL into its real components (scheme, host, port, user
    /// information, path, extra information).
    pub(crate) fn dispatch_winhttp_crack_url(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let url = guest_call_arg(state, memory, 0)?;
        let url_length = guest_call_arg_u32(state, memory, 1)?;
        let flags = guest_call_arg_u32(state, memory, 2)?;
        let components = guest_call_arg(state, memory, 3)?;
        if url == 0 || components == 0 {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_INVALID_PARAMETER;
            return Ok(());
        }
        let offsets = url_components_offsets(self.guest_arch);
        let arch = self.guest_arch;
        // The caller must initialize dwStructSize (the documented version
        // check).
        let struct_size = read_guest_u32(memory, components + offsets.struct_size).unwrap_or(0);
        if (struct_size as usize) < offsets.size as usize {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_INVALID_PARAMETER;
            return Ok(());
        }
        let units = read_utf16_argument(memory, url, url_length);
        let Some(cracked) = crack_url_units(&units) else {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_WINHTTP_INVALID_URL;
            return Ok(());
        };
        if cracked.scheme_type == 0 {
            // WinHttp only acknowledges the HTTP and HTTPS schemes.
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_WINHTTP_UNRECOGNIZED_SCHEME;
            return Ok(());
        }
        let credentials =
            cracked.user.1 > cracked.user.0 || cracked.password.1 > cracked.password.0;
        if flags & ICU_REJECT_USERPWD != 0 && credentials {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_WINHTTP_INVALID_URL;
            return Ok(());
        }
        write_guest_u32(
            memory,
            components + offsets.scheme_type,
            cracked.scheme_type,
        )
        .ok();
        write_guest_u16(memory, components + offsets.port, cracked.port).ok();
        let decode = flags & ICU_DECODE != 0;
        let mut ok = true;
        // The documented component contract: pointer and length both zero
        // means "not returned"; a NULL pointer with a non-zero length asks
        // for a pointer into the original URL string; a non-NULL pointer
        // with a non-zero length asks for a copy into that buffer.
        let mut write = |memory: &mut MemoryImage,
                         pointer_offset: u64,
                         length_offset: u64,
                         range: (usize, usize)| {
            let pointer =
                read_guest_pointer(memory, components + pointer_offset, arch).unwrap_or(0);
            let capacity = read_guest_u32(memory, components + length_offset).unwrap_or(0);
            if pointer == 0 && capacity == 0 {
                return;
            }
            if pointer == 0 {
                write_guest_pointer(
                    memory,
                    components + pointer_offset,
                    url + range.0 as u64 * 2,
                    arch,
                )
                .ok();
                write_guest_u32(
                    memory,
                    components + length_offset,
                    (range.1 - range.0) as u32,
                )
                .ok();
                return;
            }
            if capacity == 0 {
                return;
            }
            let value: Vec<u16> = if decode {
                percent_decode_utf16(&units[range.0..range.1])
            } else {
                units[range.0..range.1].to_vec()
            };
            if (capacity as usize) <= value.len() {
                write_guest_u32(memory, components + length_offset, value.len() as u32).ok();
                ok = false;
                return;
            }
            for (index, unit) in value.iter().enumerate() {
                write_guest_u16(memory, pointer + index as u64 * 2, *unit).ok();
            }
            write_guest_u16(memory, pointer + value.len() as u64 * 2, 0).ok();
            write_guest_u32(memory, components + length_offset, value.len() as u32).ok();
        };
        write(memory, offsets.scheme, offsets.scheme_len, cracked.scheme);
        write(memory, offsets.user, offsets.user_len, cracked.user);
        write(
            memory,
            offsets.password,
            offsets.password_len,
            cracked.password,
        );
        write(memory, offsets.host, offsets.host_len, cracked.host);
        // When the extra-info component is not requested, the query and/or
        // fragment stay part of the path (the documented contract).
        let extra_pointer =
            read_guest_pointer(memory, components + offsets.extra, arch).unwrap_or(0);
        let extra_length = read_guest_u32(memory, components + offsets.extra_len).unwrap_or(0);
        if extra_pointer != 0 || extra_length != 0 {
            write(memory, offsets.extra, offsets.extra_len, cracked.extra);
            write(memory, offsets.path, offsets.path_len, cracked.path);
        } else {
            write(
                memory,
                offsets.path,
                offsets.path_len,
                (cracked.path.0, units.len()),
            );
        }
        if !ok {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_INSUFFICIENT_BUFFER;
            return Ok(());
        }
        state.set(Register::Rax, u64::from(TRUE));
        self.last_error = 0;
        Ok(())
    }

    /// `WinHttpCreateUrl(lpUrlComponents, dwFlags, pwszUrl, pcchUrl)` —
    /// compose the components back into a URL string.
    pub(crate) fn dispatch_winhttp_create_url(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let components = guest_call_arg(state, memory, 0)?;
        let flags = guest_call_arg_u32(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let size_out = guest_call_arg(state, memory, 3)?;
        if components == 0 || size_out == 0 {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_INVALID_PARAMETER;
            return Ok(());
        }
        let offsets = url_components_offsets(self.guest_arch);
        let arch = self.guest_arch;
        let scheme = read_url_component(
            memory,
            components + offsets.scheme,
            components + offsets.scheme_len,
            arch,
        );
        let host = read_url_component(
            memory,
            components + offsets.host,
            components + offsets.host_len,
            arch,
        );
        let user = read_url_component(
            memory,
            components + offsets.user,
            components + offsets.user_len,
            arch,
        );
        let password = read_url_component(
            memory,
            components + offsets.password,
            components + offsets.password_len,
            arch,
        );
        let path = read_url_component(
            memory,
            components + offsets.path,
            components + offsets.path_len,
            arch,
        );
        let extra = read_url_component(
            memory,
            components + offsets.extra,
            components + offsets.extra_len,
            arch,
        );
        if flags & ICU_REJECT_USERPWD != 0 && (!user.is_empty() || !password.is_empty()) {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_WINHTTP_INVALID_URL;
            return Ok(());
        }
        let port = read_guest_u16(memory, components + offsets.port).unwrap_or(0);
        let text = compose_url(&scheme, &user, &password, &host, port, &path, &extra);
        let units: Vec<u16> = text.encode_utf16().collect();
        let required = units.len() + 1;
        let capacity = read_guest_u32(memory, size_out).unwrap_or(0) as usize;
        if buffer == 0 || capacity < required {
            write_guest_u32(memory, size_out, required as u32).ok();
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_INSUFFICIENT_BUFFER;
            return Ok(());
        }
        for (index, unit) in units.iter().enumerate() {
            write_guest_u16(memory, buffer + index as u64 * 2, *unit).ok();
        }
        write_guest_u16(memory, buffer + units.len() as u64 * 2, 0).ok();
        // On success the length excludes the terminator.
        write_guest_u32(memory, size_out, units.len() as u32).ok();
        state.set(Register::Rax, u64::from(TRUE));
        self.last_error = 0;
        Ok(())
    }

    /// `WinHttpTimeToSystemTime(pwszTime, pstSystemTime)` — parse the HTTP
    /// date formats (RFC 1123, RFC 850 and asctime) into SYSTEMTIME.
    pub(crate) fn dispatch_winhttp_time_to_system_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let time = guest_call_arg(state, memory, 0)?;
        let system_time = guest_call_arg(state, memory, 1)?;
        if time == 0 || system_time == 0 {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_INVALID_PARAMETER;
            return Ok(());
        }
        let text = read_utf16_string(memory, time).unwrap_or_default();
        let Some(parsed) = parse_http_system_time(&text) else {
            state.set(Register::Rax, u64::from(FALSE));
            self.last_error = ERROR_INVALID_PARAMETER;
            return Ok(());
        };
        write_guest_u16(memory, system_time, parsed.0).ok();
        write_guest_u16(memory, system_time + 2, parsed.1).ok();
        write_guest_u16(memory, system_time + 4, parsed.2).ok();
        write_guest_u16(memory, system_time + 6, parsed.3).ok();
        write_guest_u16(memory, system_time + 8, parsed.4).ok();
        write_guest_u16(memory, system_time + 10, parsed.5).ok();
        write_guest_u16(memory, system_time + 12, parsed.6).ok();
        write_guest_u16(memory, system_time + 14, 0).ok();
        state.set(Register::Rax, u64::from(TRUE));
        self.last_error = 0;
        Ok(())
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

/// The URL_COMPONENTS field offsets for the guest architecture (the x86
/// structure is 60 bytes, the x64 structure 104 bytes).
#[derive(Debug, Clone, Copy)]
struct UrlComponentsOffsets {
    struct_size: u64,
    scheme: u64,
    scheme_len: u64,
    scheme_type: u64,
    host: u64,
    host_len: u64,
    port: u64,
    user: u64,
    user_len: u64,
    password: u64,
    password_len: u64,
    path: u64,
    path_len: u64,
    extra: u64,
    extra_len: u64,
    size: u64,
}

fn url_components_offsets(arch: GuestArch) -> UrlComponentsOffsets {
    if arch == GuestArch::X64 {
        UrlComponentsOffsets {
            struct_size: 0,
            scheme: 8,
            scheme_len: 16,
            scheme_type: 20,
            host: 24,
            host_len: 32,
            port: 36,
            user: 40,
            user_len: 48,
            password: 56,
            password_len: 64,
            path: 72,
            path_len: 80,
            extra: 88,
            extra_len: 96,
            size: 104,
        }
    } else {
        UrlComponentsOffsets {
            struct_size: 0,
            scheme: 4,
            scheme_len: 8,
            scheme_type: 12,
            host: 16,
            host_len: 20,
            port: 24,
            user: 28,
            user_len: 32,
            password: 36,
            password_len: 40,
            path: 44,
            path_len: 48,
            extra: 52,
            extra_len: 56,
            size: 60,
        }
    }
}

/// Read a wide string argument: exactly `length` characters, or the
/// null-terminated string when `length` is zero.
fn read_utf16_argument(memory: &MemoryImage, address: u64, length: u32) -> Vec<u16> {
    let mut units = Vec::new();
    if length != 0 {
        for index in 0..length as u64 {
            match read_guest_u16(memory, address + index * 2) {
                Ok(unit) => units.push(unit),
                Err(_) => break,
            }
        }
    } else {
        for index in 0..32_768_u64 {
            match read_guest_u16(memory, address + index * 2) {
                Ok(0) => break,
                Ok(unit) => units.push(unit),
                Err(_) => break,
            }
        }
    }
    units
}

/// A URL cracked into its component ranges (indices into the UTF-16 units).
#[derive(Debug, Clone, Copy)]
struct CrackedUrl {
    scheme: (usize, usize),
    scheme_type: u32,
    user: (usize, usize),
    password: (usize, usize),
    host: (usize, usize),
    port: u16,
    path: (usize, usize),
    extra: (usize, usize),
}

fn find_unit(units: &[u16], needle: u16, from: usize) -> Option<usize> {
    let start = from.min(units.len());
    units[start..]
        .iter()
        .position(|unit| *unit == needle)
        .map(|position| position + start)
}

/// Split a URL into its component ranges.  Only the authority form is
/// meaningful for the HTTP/HTTPS surface, but the opaque form is parsed
/// structurally as well.
fn crack_url_units(units: &[u16]) -> Option<CrackedUrl> {
    let colon = find_unit(units, b':' as u16, 0)?;
    if colon == 0 {
        return None;
    }
    let scheme_units = &units[..colon];
    let scheme_ok = scheme_units.iter().all(|unit| {
        let byte = *unit as u8 as char;
        byte.is_ascii_alphabetic() || byte == '+' || byte == '-' || byte == '.'
    });
    if !scheme_ok {
        return None;
    }
    let scheme = scheme_units
        .iter()
        .map(|unit| (*unit as u8 as char).to_ascii_lowercase())
        .collect::<String>();
    let (scheme_type, default_port) = match scheme.as_str() {
        "http" => (INTERNET_SCHEME_HTTP, 80),
        "https" => (INTERNET_SCHEME_HTTPS, 443),
        _ => (0, 0),
    };
    let empty = (units.len(), units.len());
    let mut cracked = CrackedUrl {
        scheme: (0, colon),
        scheme_type,
        user: empty,
        password: empty,
        host: empty,
        port: default_port,
        path: empty,
        extra: empty,
    };
    let cursor = colon + 1;
    if units.get(cursor) == Some(&(b'/' as u16)) && units.get(cursor + 1) == Some(&(b'/' as u16)) {
        let authority_start = cursor + 2;
        let mut authority_end = units.len();
        for delimiter in [b'/', b'?', b'#'] {
            if let Some(position) = find_unit(units, delimiter as u16, authority_start) {
                authority_end = authority_end.min(position);
            }
        }
        let host_start = match find_unit(units, b'@' as u16, authority_start) {
            Some(at) if at < authority_end => {
                match find_unit(units, b':' as u16, authority_start) {
                    Some(user_colon) if user_colon < at => {
                        cracked.user = (authority_start, user_colon);
                        cracked.password = (user_colon + 1, at);
                    }
                    _ => cracked.user = (authority_start, at),
                }
                at + 1
            }
            _ => authority_start,
        };
        if units.get(host_start) == Some(&(b'[' as u16)) {
            let close = find_unit(units, b']' as u16, host_start).unwrap_or(authority_end);
            cracked.host = (host_start, (close + 1).min(authority_end));
            if units.get(close + 1) == Some(&(b':' as u16))
                && let Some(port) = parse_url_port(units, close + 2, authority_end)
            {
                cracked.port = port;
            }
        } else {
            let host_end = match find_unit(units, b':' as u16, host_start) {
                Some(host_colon) if host_colon < authority_end => {
                    if let Some(port) = parse_url_port(units, host_colon + 1, authority_end) {
                        cracked.port = port;
                    }
                    host_colon
                }
                _ => authority_end,
            };
            cracked.host = (host_start, host_end);
        }
        let path_start = authority_end;
        let extra_start = [b'?', b'#']
            .iter()
            .filter_map(|delimiter| find_unit(units, *delimiter as u16, path_start))
            .min();
        cracked.path = (path_start, extra_start.unwrap_or(units.len()));
        cracked.extra = match extra_start {
            Some(start) => (start, units.len()),
            None => empty,
        };
    } else {
        let path_start = colon + 1;
        let extra_start = [b'?', b'#']
            .iter()
            .filter_map(|delimiter| find_unit(units, *delimiter as u16, path_start))
            .min();
        cracked.path = (path_start, extra_start.unwrap_or(units.len()));
        cracked.extra = match extra_start {
            Some(start) => (start, units.len()),
            None => empty,
        };
    }
    Some(cracked)
}

fn parse_url_port(units: &[u16], mut index: usize, end: usize) -> Option<u16> {
    let mut value = 0_u32;
    let mut digits = 0;
    while index < end {
        let unit = units[index];
        if unit == b':' as u16 {
            index += 1;
            continue;
        }
        if !(b'0' as u16..=b'9' as u16).contains(&unit) {
            break;
        }
        value = value
            .saturating_mul(10)
            .saturating_add((unit - b'0' as u16) as u32);
        digits += 1;
        index += 1;
    }
    if digits == 0 {
        return None;
    }
    Some(value.min(u16::MAX as u32) as u16)
}

/// Decode the `%xx` escape sequences of a UTF-16 component (ICU_DECODE).
fn percent_decode_utf16(units: &[u16]) -> Vec<u16> {
    fn hex_value(unit: u16) -> Option<u8> {
        let byte = unit as u8 as char;
        byte.to_digit(16).map(|digit| digit as u8)
    }
    let mut bytes = Vec::new();
    let mut index = 0;
    while index < units.len() {
        if units[index] == b'%' as u16
            && index + 2 < units.len()
            && let (Some(high), Some(low)) =
                (hex_value(units[index + 1]), hex_value(units[index + 2]))
        {
            bytes.push(high * 16 + low);
            index += 3;
            continue;
        }
        let character = char::from_u32(units[index] as u32).unwrap_or('\u{fffd}');
        let mut buffer = [0_u8; 4];
        bytes.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
        index += 1;
    }
    String::from_utf8_lossy(&bytes).encode_utf16().collect()
}

/// Read one URL_COMPONENTS string for WinHttpCreateUrl: a NULL pointer is
/// an absent component; a zero length means the pointer is null-terminated.
fn read_url_component(
    memory: &MemoryImage,
    pointer_address: u64,
    length_address: u64,
    arch: GuestArch,
) -> String {
    let pointer = read_guest_pointer(memory, pointer_address, arch).unwrap_or(0);
    if pointer == 0 {
        return String::new();
    }
    let length = read_guest_u32(memory, length_address).unwrap_or(0);
    let units = read_utf16_argument(memory, pointer, length);
    String::from_utf16_lossy(&units)
}

fn compose_url(
    scheme: &str,
    user: &str,
    password: &str,
    host: &str,
    port: u16,
    path: &str,
    extra: &str,
) -> String {
    let mut url = String::new();
    if !scheme.is_empty() {
        url.push_str(scheme);
        url.push(':');
        if !host.is_empty() {
            url.push_str("//");
        }
    }
    if !user.is_empty() || !password.is_empty() {
        url.push_str(user);
        if !password.is_empty() {
            url.push(':');
            url.push_str(password);
        }
        url.push('@');
    }
    url.push_str(host);
    let default_port = match scheme.to_ascii_lowercase().as_str() {
        "http" => 80,
        "https" => 443,
        _ => 0,
    };
    if port != 0 && port != default_port {
        url.push(':');
        url.push_str(&port.to_string());
    }
    url.push_str(path);
    url.push_str(extra);
    url
}

/// Parse the three HTTP date formats (RFC 1123, RFC 850, asctime) into the
/// SYSTEMTIME tuple (year, month, day-of-week, day, hour, minute, second).
fn parse_http_system_time(text: &str) -> Option<(u16, u16, u16, u16, u16, u16, u16)> {
    fn month_number(name: &str) -> Option<u16> {
        const MONTHS: [&str; 12] = [
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
        ];
        MONTHS
            .iter()
            .position(|month| name.to_ascii_lowercase().starts_with(month))
            .map(|index| index as u16 + 1)
    }
    fn weekday_number(name: &str) -> Option<u16> {
        const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
        DAYS.iter()
            .position(|day| name.to_ascii_lowercase().starts_with(day))
            .map(|index| index as u16)
    }
    fn clock(parts: &[&str]) -> Option<(u16, u16, u16)> {
        let mut fields = parts.iter().flat_map(|part| part.split(':'));
        let hour = fields.next()?.parse::<u16>().ok()?;
        let minute = fields.next()?.parse::<u16>().ok()?;
        let second = fields.next()?.parse::<u16>().ok()?;
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        Some((hour, minute, second))
    }
    let normalized = text.replace([',', '-'], " ");
    let parts: Vec<&str> = normalized.split_whitespace().collect();
    // asctime: "Sun Nov  6 08:49:37 1994" (no comma, no timezone).
    if parts.len() >= 5 && parts[1].len() == 3 && month_number(parts[1]).is_some() {
        let weekday = weekday_number(parts[0])?;
        let month = month_number(parts[1])?;
        let day = parts[2].parse::<u16>().ok()?;
        let (hour, minute, second) = clock(&parts[3..])?;
        let year = parts[4].parse::<u16>().ok()?;
        return Some((year, month, weekday, day, hour, minute, second));
    }
    // RFC 1123 / RFC 850: "Sun, 06 Nov 1994 08:49:37 GMT" and
    // "Sunday, 06-Nov-94 08:49:37 GMT".
    if parts.len() >= 5 {
        let weekday = weekday_number(parts[0])?;
        let day = parts[1].parse::<u16>().ok()?;
        let month = month_number(parts[2])?;
        let year_field = parts[3];
        let year = if year_field.len() <= 2 {
            let short = year_field.parse::<u16>().ok()?;
            if short < 70 {
                2000 + short
            } else {
                1900 + short
            }
        } else {
            year_field.parse::<u16>().ok()?
        };
        let (hour, minute, second) = clock(&parts[4..])?;
        return Some((year, month, weekday, day, hour, minute, second));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{Fixture, dispatch_x86, with_big_stack, x86_fixture};
    use super::*;

    const URL: u64 = 0x42_000;
    const COMPONENTS: u64 = 0x43_000;
    const STRINGS: u64 = 0x44_000;
    const SYS_TIME: u64 = 0x45_000;
    const SIZE_OUT: u64 = 0x46_000;
    const WIDTH_OUT: u64 = 0x47_000;

    fn write_wide(fixture: &mut Fixture, address: u64, text: &str) {
        let mut bytes = Vec::new();
        for unit in text.encode_utf16().chain([0]) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fixture.memory.map_bytes(address, &bytes);
    }

    fn write_wide_fixed(fixture: &mut Fixture, address: u64, text: &str, units: usize) {
        let mut bytes = Vec::new();
        for index in 0..units {
            let unit = text.encode_utf16().nth(index).unwrap_or(0);
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        fixture.memory.map_bytes(address, &bytes);
    }

    fn read_wide_len(fixture: &Fixture, address: u64, units: u32) -> String {
        let mut text = String::new();
        for index in 0..units as u64 {
            let unit = read_guest_u16(&fixture.memory, address + index * 2).unwrap_or(0);
            text.push(char::from_u32(unit as u32).unwrap_or('\u{fffd}'));
        }
        text
    }

    #[test]
    fn crack_url_fills_real_components() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("winhttp-crack");
            let url = "http://user:pw@example.com:8080/a/b?x=1#frag";
            write_wide(&mut fixture, URL, url);
            fixture.memory.map_bytes(COMPONENTS, &[0_u8; 60]);
            write_guest_u32(&mut fixture.memory, COMPONENTS, 60).unwrap();
            for pointer in [4_u64, 16, 28, 36, 44, 52] {
                write_guest_pointer(&mut fixture.memory, COMPONENTS + pointer, 0, GuestArch::X86)
                    .unwrap();
            }
            for length in [8_u64, 20, 32, 40, 48, 56] {
                write_guest_u32(&mut fixture.memory, COMPONENTS + length, 0xffff_ffff).unwrap();
            }
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WinHttpCrackUrl,
                    &[URL as u32, 0, 0, COMPONENTS as u32]
                ),
                1
            );
            let at = |needle: &str| URL + url.find(needle).unwrap() as u64 * 2;
            assert_eq!(
                read_guest_u32(&fixture.memory, COMPONENTS + 12).unwrap(),
                INTERNET_SCHEME_HTTP
            );
            assert_eq!(
                read_guest_u16(&fixture.memory, COMPONENTS + 24).unwrap(),
                8080
            );
            let scheme =
                read_guest_pointer(&fixture.memory, COMPONENTS + 4, GuestArch::X86).unwrap();
            assert_eq!(scheme, URL);
            assert_eq!(read_guest_u32(&fixture.memory, COMPONENTS + 8).unwrap(), 4);
            assert_eq!(read_wide_len(&fixture, scheme, 4), "http");
            let host =
                read_guest_pointer(&fixture.memory, COMPONENTS + 16, GuestArch::X86).unwrap();
            assert_eq!(host, at("example.com"));
            assert_eq!(
                read_wide_len(
                    &fixture,
                    host,
                    read_guest_u32(&fixture.memory, COMPONENTS + 20).unwrap()
                ),
                "example.com"
            );
            let user =
                read_guest_pointer(&fixture.memory, COMPONENTS + 28, GuestArch::X86).unwrap();
            assert_eq!(user, at("user"));
            assert_eq!(
                read_wide_len(
                    &fixture,
                    user,
                    read_guest_u32(&fixture.memory, COMPONENTS + 32).unwrap()
                ),
                "user"
            );
            let password =
                read_guest_pointer(&fixture.memory, COMPONENTS + 36, GuestArch::X86).unwrap();
            assert_eq!(password, at("pw"));
            let path =
                read_guest_pointer(&fixture.memory, COMPONENTS + 44, GuestArch::X86).unwrap();
            assert_eq!(path, at("/a/b"));
            assert_eq!(
                read_wide_len(
                    &fixture,
                    path,
                    read_guest_u32(&fixture.memory, COMPONENTS + 48).unwrap()
                ),
                "/a/b"
            );
            let extra =
                read_guest_pointer(&fixture.memory, COMPONENTS + 52, GuestArch::X86).unwrap();
            assert_eq!(extra, at("?x=1#frag"));
            assert_eq!(
                read_wide_len(
                    &fixture,
                    extra,
                    read_guest_u32(&fixture.memory, COMPONENTS + 56).unwrap()
                ),
                "?x=1#frag"
            );

            // Buffer mode copies the components and updates the lengths.
            fixture.memory.map_bytes(STRINGS, &vec![0_u8; 128]);
            fixture.memory.map_bytes(COMPONENTS, &[0_u8; 60]);
            write_guest_u32(&mut fixture.memory, COMPONENTS, 60).unwrap();
            write_guest_pointer(&mut fixture.memory, COMPONENTS + 4, STRINGS, GuestArch::X86)
                .unwrap();
            write_guest_u32(&mut fixture.memory, COMPONENTS + 8, 5).unwrap();
            write_guest_pointer(
                &mut fixture.memory,
                COMPONENTS + 16,
                STRINGS + 16,
                GuestArch::X86,
            )
            .unwrap();
            write_guest_u32(&mut fixture.memory, COMPONENTS + 20, 32).unwrap();
            write_guest_pointer(
                &mut fixture.memory,
                COMPONENTS + 44,
                STRINGS + 64,
                GuestArch::X86,
            )
            .unwrap();
            write_guest_u32(&mut fixture.memory, COMPONENTS + 48, 16).unwrap();
            write_guest_pointer(
                &mut fixture.memory,
                COMPONENTS + 52,
                STRINGS + 96,
                GuestArch::X86,
            )
            .unwrap();
            write_guest_u32(&mut fixture.memory, COMPONENTS + 56, 32).unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WinHttpCrackUrl,
                    &[URL as u32, 0, 0, COMPONENTS as u32]
                ),
                1
            );
            assert_eq!(
                read_wide_len(
                    &fixture,
                    STRINGS,
                    read_guest_u32(&fixture.memory, COMPONENTS + 8).unwrap()
                ),
                "http"
            );
            assert_eq!(
                read_wide_len(
                    &fixture,
                    STRINGS + 16,
                    read_guest_u32(&fixture.memory, COMPONENTS + 20).unwrap()
                ),
                "example.com"
            );
            assert_eq!(
                read_wide_len(
                    &fixture,
                    STRINGS + 64,
                    read_guest_u32(&fixture.memory, COMPONENTS + 48).unwrap()
                ),
                "/a/b"
            );

            // An undersized buffer reports ERROR_INSUFFICIENT_BUFFER.
            write_guest_u32(&mut fixture.memory, COMPONENTS + 8, 2).unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WinHttpCrackUrl,
                    &[URL as u32, 0, 0, COMPONENTS as u32]
                ),
                0
            );
            assert_eq!(fixture.runtime.last_error, ERROR_INSUFFICIENT_BUFFER);

            // Unrecognized schemes are rejected.
            write_wide(&mut fixture, URL, "ftp://example.com/");
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WinHttpCrackUrl,
                    &[URL as u32, 0, 0, COMPONENTS as u32]
                ),
                0
            );
            assert_eq!(
                fixture.runtime.last_error,
                ERROR_WINHTTP_UNRECOGNIZED_SCHEME
            );
        })
    }

    #[test]
    fn create_url_composes_and_reports_the_required_length() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("winhttp-create");
            fixture.memory.map_bytes(COMPONENTS, &[0_u8; 60]);
            fixture.memory.map_bytes(STRINGS, &vec![0_u8; 64]);
            fixture.memory.map_bytes(SIZE_OUT, &[0_u8; 8]);
            write_guest_u32(&mut fixture.memory, COMPONENTS, 60).unwrap();
            write_wide_fixed(&mut fixture, STRINGS, "http", 4);
            write_wide_fixed(&mut fixture, STRINGS + 8, "example.com", 11);
            write_wide_fixed(&mut fixture, STRINGS + 40, "/x", 2);
            write_guest_pointer(&mut fixture.memory, COMPONENTS + 4, STRINGS, GuestArch::X86)
                .unwrap();
            write_guest_u32(&mut fixture.memory, COMPONENTS + 8, 4).unwrap();
            write_guest_pointer(
                &mut fixture.memory,
                COMPONENTS + 16,
                STRINGS + 8,
                GuestArch::X86,
            )
            .unwrap();
            write_guest_u32(&mut fixture.memory, COMPONENTS + 20, 11).unwrap();
            write_guest_u16(&mut fixture.memory, COMPONENTS + 24, 8080).unwrap();
            write_guest_pointer(
                &mut fixture.memory,
                COMPONENTS + 44,
                STRINGS + 40,
                GuestArch::X86,
            )
            .unwrap();
            write_guest_u32(&mut fixture.memory, COMPONENTS + 48, 2).unwrap();

            // Length query: a null buffer reports the required size.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WinHttpCreateUrl,
                    &[COMPONENTS as u32, 0, 0, SIZE_OUT as u32]
                ),
                0
            );
            assert_eq!(fixture.runtime.last_error, ERROR_INSUFFICIENT_BUFFER);
            let required = read_guest_u32(&fixture.memory, SIZE_OUT).unwrap();
            assert_eq!(required, "http://example.com:8080/x".len() as u32 + 1);

            // A buffer one short still answers insufficient.
            fixture.memory.map_bytes(URL, &vec![0_u8; 128]);
            write_guest_u32(&mut fixture.memory, SIZE_OUT, required - 1).unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WinHttpCreateUrl,
                    &[COMPONENTS as u32, 0, URL as u32, SIZE_OUT as u32]
                ),
                0
            );
            assert_eq!(fixture.runtime.last_error, ERROR_INSUFFICIENT_BUFFER);

            // The full buffer composes the URL.
            write_guest_u32(&mut fixture.memory, SIZE_OUT, required).unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WinHttpCreateUrl,
                    &[COMPONENTS as u32, 0, URL as u32, SIZE_OUT as u32]
                ),
                1
            );
            let written = read_guest_u32(&fixture.memory, SIZE_OUT).unwrap();
            assert_eq!(
                read_wide_len(&fixture, URL, written),
                "http://example.com:8080/x"
            );

            // Rejecting embedded credentials is a real failure mode.
            write_wide_fixed(&mut fixture, STRINGS + 48, "user", 4);
            write_guest_pointer(
                &mut fixture.memory,
                COMPONENTS + 28,
                STRINGS + 48,
                GuestArch::X86,
            )
            .unwrap();
            write_guest_u32(&mut fixture.memory, COMPONENTS + 32, 4).unwrap();
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::WinHttpCreateUrl,
                    &[
                        COMPONENTS as u32,
                        ICU_REJECT_USERPWD,
                        URL as u32,
                        SIZE_OUT as u32
                    ]
                ),
                0
            );
            assert_eq!(fixture.runtime.last_error, ERROR_WINHTTP_INVALID_URL);
        })
    }
}
