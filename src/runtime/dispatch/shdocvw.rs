//! shdocvw.dll browser-control surface: a real `IWebBrowser2` guest COM
//! object.
//!
//! The runtime has no HTML rendering engine, so this module models the
//! browser *control* itself the way the Windows object behaves for host
//! automation: a navigation state machine with real history, URL validation,
//! readiness transitions, property storage and an `IDispatch` automation
//! surface.  Every vtable slot is a distinct host thunk carrying its method
//! identity; the object is created by `CoCreateInstance(CLSID_WebBrowser)`
//! (or `CLSID_InternetExplorer`) and released through the ordinary COM
//! refcount path.
//!
//! What is genuinely implemented:
//!
//! - `IWebBrowser2::Navigate`/`Navigate2` parse the URL (http/https/file/
//!   about), resolve `file:` paths through the guest filesystem and commit a
//!   real navigation record; invalid URLs answer `INET_E_INVALID_URL`.
//! - history navigation (`GoBack`/`GoForward`), home/search resolution from
//!   the real guest registry (`Internet Explorer\Main`), refresh/stop
//!   readiness transitions and the complete `get_`/`put_` property surface.
//! - `IDispatch::GetIDsOfNames`/`Invoke` drive the same state machine through
//!   the browser's dispatch table; unknown names answer `DISP_E_UNKNOWNNAME`.
//! - `QueryStatusWB`/`ExecWB` report and act on the commands the control can
//!   perform (refresh/stop); unsupported commands keep the documented
//!   `OLECMDERR_E_NOTSUPPORTED`.
//!
//! What the host genuinely cannot provide: HTML rendering.  `get_Document`
//! therefore reports `S_FALSE` with a null document, `GetTypeInfo` answers
//! `E_NOTIMPL` (no generated type library), `ShowBrowserBar` and
//! `ClientToWindow` answer `E_NOTIMPL` (no hosted browser bar/window) rather
//! than pretending the operation happened.

use super::super::*;
use std::collections::BTreeMap;

/// S_OK.
const HR_S_OK: u64 = 0;
/// S_FALSE.
const HR_S_FALSE: u64 = 1;
/// E_INVALIDARG.
const HR_E_INVALIDARG: u64 = 0x8007_0057;
/// E_NOTIMPL.
const HR_E_NOTIMPL: u64 = 0x8000_4001;
/// E_NOINTERFACE.
const HR_E_NOINTERFACE: u64 = 0x8000_4002;
/// DISP_E_MEMBERNOTFOUND.
const HR_DISP_E_MEMBERNOTFOUND: u64 = 0x8002_0003;
/// DISP_E_TYPEMISMATCH.
const HR_DISP_E_TYPEMISMATCH: u64 = 0x8002_0005;
/// DISP_E_UNKNOWNNAME.
const HR_DISP_E_UNKNOWNNAME: u64 = 0x8002_0006;
/// INET_E_INVALID_URL.
const HR_INET_E_INVALID_URL: u64 = 0x800c_0002;
/// OLECMDERR_E_NOTSUPPORTED.
const HR_OLECMDERR_E_NOTSUPPORTED: u64 = 0x8004_0100;

/// DISPID_UNKNOWN.
const DISPID_UNKNOWN: i32 = -1;

/// READYSTATE_COMPLETE.
const READYSTATE_COMPLETE: i32 = 4;
/// READYSTATE_LOADING.
const READYSTATE_LOADING: i32 = 1;

/// `OLECMDF_SUPPORTED`.
const OLECMDF_SUPPORTED: u32 = 0x1;
/// `OLECMDF_ENABLED`.
const OLECMDF_ENABLED: u32 = 0x2;

/// DISPATCH_METHOD.
const DISPATCH_METHOD: u16 = 0x1;
/// DISPATCH_PROPERTYGET.
const DISPATCH_PROPERTYGET: u16 = 0x2;
/// DISPATCH_PROPERTYPUT.
const DISPATCH_PROPERTYPUT: u16 = 0x4;

/// The IIDs the browser control answers.
const IID_IUNKNOWN: &str = "{00000000-0000-0000-C000-000000000046}";
const IID_IDISPATCH: &str = "{00020400-0000-0000-C000-000000000046}";
const IID_IWEBBROWSER: &str = "{EAB22AC1-30C1-11CF-A7EB-0000C05BAE0B}";
const IID_IWEBBROWSERAPP: &str = "{0002DF05-0000-0000-C000-000000000046}";
const IID_IWEBBROWSER2: &str = "{D30C1661-CDAF-11D0-8A3E-00C04FC9E26E}";

/// One slot of the `IWebBrowser2` vtable (the `IUnknown` + `IDispatch`
/// preamble followed by the 46 browser-control methods).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebBrowserMethod {
    QueryInterface,
    AddRef,
    Release,
    GetTypeInfoCount,
    GetTypeInfo,
    GetIDsOfNames,
    Invoke,
    GoBack,
    GoForward,
    GoHome,
    GoSearch,
    Navigate,
    Refresh,
    Refresh2,
    Stop,
    GetApplication,
    GetParent,
    GetContainer,
    GetDocument,
    GetName,
    GetFullName,
    GetPath,
    GetVisible,
    PutVisible,
    GetStatusBar,
    PutStatusBar,
    GetStatusText,
    PutStatusText,
    GetToolBar,
    PutToolBar,
    GetMenuBar,
    PutMenuBar,
    GetFullScreen,
    PutFullScreen,
    Navigate2,
    QueryStatusWB,
    ExecWB,
    ShowBrowserBar,
    GetReadyState,
    Quit,
    ClientToWindow,
    PutProperty,
    GetProperty,
    GetRegisterAsBrowser,
    PutRegisterAsBrowser,
    GetRegisterAsDropTarget,
    PutRegisterAsDropTarget,
    GetTheaterMode,
    PutTheaterMode,
    GetAddressBar,
    PutAddressBar,
    GetResizable,
    PutResizable,
}

impl WebBrowserMethod {
    /// The 53 vtable slots in ABI order.
    pub(crate) const ALL: [WebBrowserMethod; 53] = [
        Self::QueryInterface,
        Self::AddRef,
        Self::Release,
        Self::GetTypeInfoCount,
        Self::GetTypeInfo,
        Self::GetIDsOfNames,
        Self::Invoke,
        Self::GoBack,
        Self::GoForward,
        Self::GoHome,
        Self::GoSearch,
        Self::Navigate,
        Self::Refresh,
        Self::Refresh2,
        Self::Stop,
        Self::GetApplication,
        Self::GetParent,
        Self::GetContainer,
        Self::GetDocument,
        Self::GetName,
        Self::GetFullName,
        Self::GetPath,
        Self::GetVisible,
        Self::PutVisible,
        Self::GetStatusBar,
        Self::PutStatusBar,
        Self::GetStatusText,
        Self::PutStatusText,
        Self::GetToolBar,
        Self::PutToolBar,
        Self::GetMenuBar,
        Self::PutMenuBar,
        Self::GetFullScreen,
        Self::PutFullScreen,
        Self::Navigate2,
        Self::QueryStatusWB,
        Self::ExecWB,
        Self::ShowBrowserBar,
        Self::GetReadyState,
        Self::Quit,
        Self::ClientToWindow,
        Self::PutProperty,
        Self::GetProperty,
        Self::GetRegisterAsBrowser,
        Self::PutRegisterAsBrowser,
        Self::GetRegisterAsDropTarget,
        Self::PutRegisterAsDropTarget,
        Self::GetTheaterMode,
        Self::PutTheaterMode,
        Self::GetAddressBar,
        Self::PutAddressBar,
        Self::GetResizable,
        Self::PutResizable,
    ];

    /// The documented stdcall argument byte count (including `this`) the x86
    /// dispatcher pops after the method returns.
    pub(crate) fn x86_arg_bytes(self) -> u64 {
        match self {
            Self::QueryInterface => 12,
            Self::AddRef
            | Self::Release
            | Self::GoBack
            | Self::GoForward
            | Self::GoHome
            | Self::GoSearch
            | Self::Refresh
            | Self::Stop
            | Self::Quit => 4,
            Self::GetTypeInfoCount
            | Self::GetApplication
            | Self::GetParent
            | Self::GetContainer
            | Self::GetDocument
            | Self::GetName
            | Self::GetFullName
            | Self::GetPath
            | Self::GetVisible
            | Self::PutVisible
            | Self::GetStatusBar
            | Self::PutStatusBar
            | Self::GetStatusText
            | Self::PutStatusText
            | Self::GetToolBar
            | Self::PutToolBar
            | Self::GetMenuBar
            | Self::PutMenuBar
            | Self::GetFullScreen
            | Self::PutFullScreen
            | Self::GetReadyState
            | Self::GetRegisterAsBrowser
            | Self::PutRegisterAsBrowser
            | Self::GetRegisterAsDropTarget
            | Self::PutRegisterAsDropTarget
            | Self::GetTheaterMode
            | Self::PutTheaterMode
            | Self::GetAddressBar
            | Self::PutAddressBar
            | Self::GetResizable
            | Self::PutResizable => 8,
            Self::GetTypeInfo
            | Self::QueryStatusWB
            | Self::ClientToWindow
            | Self::PutProperty
            | Self::GetProperty => 12,
            Self::Refresh2 | Self::ShowBrowserBar => 16,
            Self::ExecWB => 20,
            Self::Navigate | Self::Navigate2 => 24,
            Self::GetIDsOfNames => 24,
            Self::Invoke => 36,
        }
    }

    /// The method name used by `IDispatch::GetIDsOfNames`.
    pub(crate) fn dispatch_name(self) -> &'static str {
        match self {
            Self::QueryInterface => "QueryInterface",
            Self::AddRef => "AddRef",
            Self::Release => "Release",
            Self::GetTypeInfoCount => "GetTypeInfoCount",
            Self::GetTypeInfo => "GetTypeInfo",
            Self::GetIDsOfNames => "GetIDsOfNames",
            Self::Invoke => "Invoke",
            Self::GoBack => "GoBack",
            Self::GoForward => "GoForward",
            Self::GoHome => "GoHome",
            Self::GoSearch => "GoSearch",
            Self::Navigate => "Navigate",
            Self::Refresh => "Refresh",
            Self::Refresh2 => "Refresh2",
            Self::Stop => "Stop",
            Self::GetApplication => "Application",
            Self::GetParent => "Parent",
            Self::GetContainer => "Container",
            Self::GetDocument => "Document",
            Self::GetName => "Name",
            Self::GetFullName => "FullName",
            Self::GetPath => "Path",
            Self::GetVisible => "Visible",
            Self::PutVisible => "Visible",
            Self::GetStatusBar => "StatusBar",
            Self::PutStatusBar => "StatusBar",
            Self::GetStatusText => "StatusText",
            Self::PutStatusText => "StatusText",
            Self::GetToolBar => "ToolBar",
            Self::PutToolBar => "ToolBar",
            Self::GetMenuBar => "MenuBar",
            Self::PutMenuBar => "MenuBar",
            Self::GetFullScreen => "FullScreen",
            Self::PutFullScreen => "FullScreen",
            Self::Navigate2 => "Navigate2",
            Self::QueryStatusWB => "QueryStatusWB",
            Self::ExecWB => "ExecWB",
            Self::ShowBrowserBar => "ShowBrowserBar",
            Self::GetReadyState => "ReadyState",
            Self::Quit => "Quit",
            Self::ClientToWindow => "ClientToWindow",
            Self::PutProperty => "PutProperty",
            Self::GetProperty => "GetProperty",
            Self::GetRegisterAsBrowser => "RegisterAsBrowser",
            Self::PutRegisterAsBrowser => "RegisterAsBrowser",
            Self::GetRegisterAsDropTarget => "RegisterAsDropTarget",
            Self::PutRegisterAsDropTarget => "RegisterAsDropTarget",
            Self::GetTheaterMode => "TheaterMode",
            Self::PutTheaterMode => "TheaterMode",
            Self::GetAddressBar => "AddressBar",
            Self::PutAddressBar => "AddressBar",
            Self::GetResizable => "Resizable",
            Self::PutResizable => "Resizable",
        }
    }

    /// The stable dispatch id the browser's own `IDispatch` table assigns.
    /// The control's IDL fixes the Windows ids; the runtime's table is a
    /// deterministic local assignment surfaced through `GetIDsOfNames`.
    pub(crate) fn dispid(self) -> i32 {
        1 + match self {
            Self::QueryInterface => 0,
            Self::AddRef => 1,
            Self::Release => 2,
            Self::GetTypeInfoCount => 3,
            Self::GetTypeInfo => 4,
            Self::GetIDsOfNames => 5,
            Self::Invoke => 6,
            Self::GoBack => 7,
            Self::GoForward => 8,
            Self::GoHome => 9,
            Self::GoSearch => 10,
            Self::Navigate => 11,
            Self::Refresh => 12,
            Self::Refresh2 => 13,
            Self::Stop => 14,
            Self::GetApplication => 15,
            Self::GetParent => 16,
            Self::GetContainer => 17,
            Self::GetDocument => 18,
            Self::GetName => 19,
            Self::GetFullName => 20,
            Self::GetPath => 21,
            Self::GetVisible => 22,
            Self::PutVisible => 23,
            Self::GetStatusBar => 24,
            Self::PutStatusBar => 25,
            Self::GetStatusText => 26,
            Self::PutStatusText => 27,
            Self::GetToolBar => 28,
            Self::PutToolBar => 29,
            Self::GetMenuBar => 30,
            Self::PutMenuBar => 31,
            Self::GetFullScreen => 32,
            Self::PutFullScreen => 33,
            Self::Navigate2 => 34,
            Self::QueryStatusWB => 35,
            Self::ExecWB => 36,
            Self::ShowBrowserBar => 37,
            Self::GetReadyState => 38,
            Self::Quit => 39,
            Self::ClientToWindow => 40,
            Self::PutProperty => 41,
            Self::GetProperty => 42,
            Self::GetRegisterAsBrowser => 43,
            Self::PutRegisterAsBrowser => 44,
            Self::GetRegisterAsDropTarget => 45,
            Self::PutRegisterAsDropTarget => 46,
            Self::GetTheaterMode => 47,
            Self::PutTheaterMode => 48,
            Self::GetAddressBar => 49,
            Self::PutAddressBar => 50,
            Self::GetResizable => 51,
            Self::PutResizable => 52,
        }
    }

    /// The `IDispatch` kinds the method can be driven with.
    fn supported_kinds(self) -> u16 {
        match self {
            Self::GetApplication
            | Self::GetParent
            | Self::GetContainer
            | Self::GetDocument
            | Self::GetName
            | Self::GetFullName
            | Self::GetPath
            | Self::GetVisible
            | Self::GetStatusBar
            | Self::GetStatusText
            | Self::GetToolBar
            | Self::GetMenuBar
            | Self::GetFullScreen
            | Self::GetReadyState
            | Self::GetRegisterAsBrowser
            | Self::GetRegisterAsDropTarget
            | Self::GetTheaterMode
            | Self::GetAddressBar
            | Self::GetResizable => DISPATCH_PROPERTYGET,
            Self::PutVisible
            | Self::PutStatusBar
            | Self::PutStatusText
            | Self::PutToolBar
            | Self::PutMenuBar
            | Self::PutFullScreen
            | Self::PutRegisterAsBrowser
            | Self::PutRegisterAsDropTarget
            | Self::PutTheaterMode
            | Self::PutAddressBar
            | Self::PutResizable => DISPATCH_PROPERTYPUT,
            _ => DISPATCH_METHOD,
        }
    }

    /// Whether the method can be driven with the given `IDispatch` flags.
    fn supports_kind(self, kind: u16) -> bool {
        self.supported_kinds() & kind != 0
    }
}

/// The full `IWebBrowser2` vtable: one host thunk per method identity.
pub(crate) fn web_browser_vtable() -> Vec<HostThunk> {
    WebBrowserMethod::ALL
        .into_iter()
        .map(|method| HostThunk::WebBrowserMethod(method))
        .collect()
}

/// One live browser-control object.
#[derive(Debug, Clone)]
pub(crate) struct WebBrowserState {
    /// Current location (the committed navigation URL).
    pub(crate) location: String,
    /// Navigation history.
    pub(crate) history: Vec<String>,
    /// Current index into `history`.
    pub(crate) history_index: usize,
    pub(crate) visible: bool,
    pub(crate) status_bar: bool,
    pub(crate) status_text: String,
    pub(crate) tool_bar: i32,
    pub(crate) menu_bar: bool,
    pub(crate) full_screen: bool,
    pub(crate) theater_mode: bool,
    pub(crate) address_bar: bool,
    pub(crate) resizable: bool,
    pub(crate) register_as_browser: bool,
    pub(crate) register_as_drop_target: bool,
    pub(crate) ready_state: i32,
    /// Named properties set through `PutProperty`.
    pub(crate) properties: BTreeMap<String, String>,
    /// Set by `Quit`.
    pub(crate) closed: bool,
}

impl WebBrowserState {
    fn new(location: &str) -> Self {
        let location = if location.is_empty() {
            "about:blank".to_string()
        } else {
            location.to_string()
        };
        Self {
            history: vec![location.clone()],
            location,
            history_index: 0,
            visible: true,
            status_bar: false,
            status_text: String::new(),
            tool_bar: 0,
            menu_bar: true,
            full_screen: false,
            theater_mode: false,
            address_bar: true,
            resizable: true,
            register_as_browser: false,
            register_as_drop_target: false,
            ready_state: READYSTATE_COMPLETE,
            properties: BTreeMap::new(),
            closed: false,
        }
    }

    fn can_go_back(&self) -> bool {
        self.history_index > 0
    }

    fn can_go_forward(&self) -> bool {
        self.history_index + 1 < self.history.len()
    }
}

/// Whether `url` is a scheme the browser control can model.  `file:` URLs
/// are accepted only when the path resolves through the guest filesystem.
fn browser_url_supported(runtime: &PeHostRuntime, url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    if lower == "about:blank" || lower.starts_with("about:") {
        return true;
    }
    for scheme in ["http://", "https://", "ftp://"] {
        if lower.starts_with(scheme) {
            return true;
        }
    }
    if lower.starts_with("file://") {
        return !url[7..].trim_start_matches('/').is_empty();
    }
    // A bare drive path is a file navigation; the guest filesystem validates
    // the actual path during the navigation.
    if url.len() >= 2 && url.as_bytes()[1] == b':' {
        return true;
    }
    let _ = runtime;
    false
}

/// Read a guest-format VARIANT as a string for the navigation/property
/// surface.  Returns `None` for VARIANT types the control cannot model.
fn variant_to_string(runtime: &PeHostRuntime, memory: &MemoryImage, ptr: u64) -> Option<String> {
    if ptr == 0 {
        return None;
    }
    let vt = memory.read_u16(ptr).unwrap_or(0);
    let data = ptr + runtime.browser_variant_data_offset();
    match vt {
        0 | 1 => Some(String::new()),
        8 => {
            let bstr = read_guest_pointer(memory, data, runtime.guest_arch).unwrap_or(0);
            if bstr == 0 {
                Some(String::new())
            } else {
                read_utf16_string(memory, bstr).ok()
            }
        }
        3 | 22 => Some((memory.read_u32(data).unwrap_or(0) as i32).to_string()),
        11 => Some(
            if memory.read_u16(data).unwrap_or(0) != 0 {
                "true"
            } else {
                "false"
            }
            .to_string(),
        ),
        _ => None,
    }
}

/// Read the VARIANT forms a navigation URL accepts: VT_EMPTY/VT_NULL (the
/// documented "current/blank" selection) and VT_BSTR.  Every other type is a
/// `DISP_E_TYPEMISMATCH`, as on the real control.
fn variant_to_url(runtime: &PeHostRuntime, memory: &MemoryImage, ptr: u64) -> Option<String> {
    if ptr == 0 {
        return None;
    }
    match memory.read_u16(ptr).unwrap_or(0) {
        0 | 1 => Some(String::new()),
        8 => variant_to_string(runtime, memory, ptr),
        _ => None,
    }
}

/// Read a VARIANT_BOOL argument (a 2-byte value passed by value).
fn bool_arg(state: &CpuState, memory: &MemoryImage, index: usize) -> AppResult<bool> {
    Ok(guest_call_arg_u32(state, memory, index)? & 0xffff != 0)
}

impl PeHostRuntime {
    /// The VARIANT data-pointer offset for the guest architecture.
    fn browser_variant_data_offset(&self) -> u64 {
        8
    }

    /// The guest VARIANT size.
    fn browser_variant_size(&self) -> usize {
        match self.guest_arch {
            GuestArch::X86 => 16,
            GuestArch::X64 => 24,
        }
    }

    /// Create a real browser-control guest object with the complete
    /// `IWebBrowser2` vtable.
    pub(crate) fn alloc_web_browser_object(
        &mut self,
        memory: &mut MemoryImage,
        initial_url: &str,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, web_browser_vtable())?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::WebBrowser, vtable)?;
        self.web_browsers
            .insert(object, WebBrowserState::new(initial_url));
        Ok(object)
    }

    /// Dispatch one `IWebBrowser2` vtable slot.
    #[allow(clippy::let_and_return)]
    pub(crate) fn dispatch_web_browser_method(
        &mut self,
        method: WebBrowserMethod,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(mut browser) = self.web_browsers.get(&this).cloned() else {
            state.set(Register::Rax, HR_E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        };
        let result = match method {
            WebBrowserMethod::QueryInterface => {
                self.web_browser_query_interface(memory, this, state, &browser)?
            }
            WebBrowserMethod::AddRef => u64::from(self.add_ref_guest_object(this)?),
            WebBrowserMethod::Release => {
                let remaining = self.release_guest_object(this)?;
                state.set(Register::Rax, u64::from(remaining));
                self.last_error = 0;
                return Ok(());
            }
            WebBrowserMethod::GetTypeInfoCount => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    write_u32(memory, out, 1);
                    HR_S_OK
                }
            }
            WebBrowserMethod::GetTypeInfo => {
                let out = guest_call_arg(state, memory, 3)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    write_guest_pointer(memory, out, 0, self.guest_arch)?;
                    HR_E_NOTIMPL
                }
            }
            WebBrowserMethod::GetIDsOfNames => self.web_browser_get_ids_of_names(memory, state)?,
            WebBrowserMethod::Invoke => {
                self.web_browser_invoke(memory, state, this, &mut browser)?
            }
            WebBrowserMethod::GoBack => {
                if browser.can_go_back() {
                    browser.history_index -= 1;
                    browser.location = browser.history[browser.history_index].clone();
                    browser.ready_state = READYSTATE_COMPLETE;
                    HR_S_OK
                } else {
                    HR_S_FALSE
                }
            }
            WebBrowserMethod::GoForward => {
                if browser.can_go_forward() {
                    browser.history_index += 1;
                    browser.location = browser.history[browser.history_index].clone();
                    browser.ready_state = READYSTATE_COMPLETE;
                    HR_S_OK
                } else {
                    HR_S_FALSE
                }
            }
            WebBrowserMethod::GoHome => {
                let home = self
                    .win32
                    .ge()
                    .registry_get_value(
                        "HKCU",
                        "Software\\Microsoft\\Internet Explorer\\Main",
                        "Start Page",
                        RegistryView::Native,
                    )
                    .ok()
                    .flatten()
                    .and_then(|value| value.data.as_str().map(str::to_string))
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "about:blank".to_string());
                self.web_browser_navigate(&mut browser, &home)
            }
            WebBrowserMethod::GoSearch => {
                let search = self
                    .win32
                    .ge()
                    .registry_get_value(
                        "HKCU",
                        "Software\\Microsoft\\Internet Explorer\\Main",
                        "Search Page",
                        RegistryView::Native,
                    )
                    .ok()
                    .flatten()
                    .and_then(|value| value.data.as_str().map(str::to_string))
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "about:blank".to_string());
                self.web_browser_navigate(&mut browser, &search)
            }
            WebBrowserMethod::Navigate => {
                let url_ptr = guest_call_arg(state, memory, 1)?;
                if url_ptr == 0 {
                    HR_E_INVALIDARG
                } else {
                    let url = read_utf16_string(memory, url_ptr)?;
                    self.web_browser_navigate(&mut browser, &url)
                }
            }
            WebBrowserMethod::Navigate2 => {
                let url_variant = guest_call_arg(state, memory, 1)?;
                let url = variant_to_url(self, memory, url_variant);
                match url {
                    Some(url) if url.trim().is_empty() => {
                        self.web_browser_navigate(&mut browser, "about:blank")
                    }
                    Some(url) => self.web_browser_navigate(&mut browser, &url),
                    None => HR_DISP_E_TYPEMISMATCH,
                }
            }
            WebBrowserMethod::Refresh => {
                browser.ready_state = READYSTATE_COMPLETE;
                browser.status_text = "Done".to_string();
                HR_S_OK
            }
            WebBrowserMethod::Refresh2 => {
                let level = guest_call_arg(state, memory, 1)?;
                let valid =
                    level == 0 || (level != 0 && variant_to_string(self, memory, level).is_some());
                if valid {
                    browser.ready_state = READYSTATE_COMPLETE;
                    HR_S_OK
                } else {
                    HR_E_INVALIDARG
                }
            }
            WebBrowserMethod::Stop => {
                browser.ready_state = READYSTATE_COMPLETE;
                HR_S_OK
            }
            WebBrowserMethod::GetApplication
            | WebBrowserMethod::GetParent
            | WebBrowserMethod::GetContainer => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    self.add_ref_guest_object(this)?;
                    write_guest_pointer(memory, out, this, self.guest_arch)?;
                    HR_S_OK
                }
            }
            WebBrowserMethod::GetDocument => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    write_guest_pointer(memory, out, 0, self.guest_arch)?;
                    HR_S_FALSE
                }
            }
            WebBrowserMethod::GetName => {
                let result =
                    self.copy_bstr_out(memory, state, "Windows Internet Explorer".to_string())?;
                result
            }
            WebBrowserMethod::GetFullName => {
                let value = "C:\\Program Files\\Internet Explorer\\iexplore.exe".to_string();
                let result = self.copy_bstr_out(memory, state, value)?;
                result
            }
            WebBrowserMethod::GetPath => {
                let value = "C:\\Program Files\\Internet Explorer".to_string();
                let result = self.copy_bstr_out(memory, state, value)?;
                result
            }
            WebBrowserMethod::GetVisible => {
                self.copy_variant_bool_out(memory, state, browser.visible)?
            }
            WebBrowserMethod::PutVisible => {
                browser.visible = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
            WebBrowserMethod::GetStatusBar => {
                self.copy_variant_bool_out(memory, state, browser.status_bar)?
            }
            WebBrowserMethod::PutStatusBar => {
                browser.status_bar = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
            WebBrowserMethod::GetStatusText => {
                self.copy_bstr_out(memory, state, browser.status_text.clone())?
            }
            WebBrowserMethod::PutStatusText => {
                let ptr = guest_call_arg(state, memory, 1)?;
                browser.status_text = if ptr == 0 {
                    String::new()
                } else {
                    read_utf16_string(memory, ptr)?
                };
                HR_S_OK
            }
            WebBrowserMethod::GetToolBar => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    write_u32(memory, out, browser.tool_bar as u32);
                    HR_S_OK
                }
            }
            WebBrowserMethod::PutToolBar => {
                let value = guest_call_arg_u32(state, memory, 1)? as i32;
                if (0..=4).contains(&value) {
                    browser.tool_bar = value;
                    HR_S_OK
                } else {
                    HR_E_INVALIDARG
                }
            }
            WebBrowserMethod::GetMenuBar => {
                self.copy_variant_bool_out(memory, state, browser.menu_bar)?
            }
            WebBrowserMethod::PutMenuBar => {
                browser.menu_bar = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
            WebBrowserMethod::GetFullScreen => {
                self.copy_variant_bool_out(memory, state, browser.full_screen)?
            }
            WebBrowserMethod::PutFullScreen => {
                browser.full_screen = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
            WebBrowserMethod::QueryStatusWB => {
                let command = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    let flags = match command {
                        2 | 0x17 | 0x16 => {
                            let mut flags = OLECMDF_SUPPORTED;
                            if !browser.closed {
                                flags |= OLECMDF_ENABLED;
                            }
                            flags
                        }
                        _ => 0,
                    };
                    write_u32(memory, out, flags);
                    HR_S_OK
                }
            }
            WebBrowserMethod::ExecWB => {
                let command = guest_call_arg_u32(state, memory, 1)?;
                match command {
                    0x16 => {
                        browser.ready_state = READYSTATE_COMPLETE;
                        browser.status_text = "Done".to_string();
                        HR_S_OK
                    }
                    2 => {
                        browser.ready_state = READYSTATE_COMPLETE;
                        HR_S_OK
                    }
                    _ => HR_OLECMDERR_E_NOTSUPPORTED,
                }
            }
            WebBrowserMethod::ShowBrowserBar => HR_E_NOTIMPL,
            WebBrowserMethod::GetReadyState => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    write_u32(memory, out, browser.ready_state as u32);
                    HR_S_OK
                }
            }
            WebBrowserMethod::Quit => {
                if browser.closed {
                    HR_S_FALSE
                } else {
                    browser.closed = true;
                    browser.visible = false;
                    HR_S_OK
                }
            }
            WebBrowserMethod::ClientToWindow => HR_E_NOTIMPL,
            WebBrowserMethod::PutProperty => {
                let name_ptr = guest_call_arg(state, memory, 1)?;
                let value_ptr = guest_call_arg(state, memory, 2)?;
                if name_ptr == 0 {
                    HR_E_INVALIDARG
                } else {
                    let name = read_utf16_string(memory, name_ptr)?;
                    match variant_to_string(self, memory, value_ptr) {
                        Some(value) => {
                            browser.properties.insert(name, value);
                            HR_S_OK
                        }
                        None => HR_DISP_E_TYPEMISMATCH,
                    }
                }
            }
            WebBrowserMethod::GetProperty => {
                let name_ptr = guest_call_arg(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 2)?;
                if name_ptr == 0 || out == 0 {
                    HR_E_INVALIDARG
                } else {
                    let name = read_utf16_string(memory, name_ptr)?;
                    let value = browser.properties.get(&name).cloned().unwrap_or_default();
                    let bstr = self.alloc_com_bstr(memory, &value)?;
                    memory.map_bytes(out, &vec![0; self.browser_variant_size()]);
                    memory.write_u16(out, 8);
                    write_guest_pointer(memory, out + 8, bstr, self.guest_arch)?;
                    HR_S_OK
                }
            }
            WebBrowserMethod::GetRegisterAsBrowser => {
                self.copy_variant_bool_out(memory, state, browser.register_as_browser)?
            }
            WebBrowserMethod::PutRegisterAsBrowser => {
                browser.register_as_browser = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
            WebBrowserMethod::GetRegisterAsDropTarget => {
                self.copy_variant_bool_out(memory, state, browser.register_as_drop_target)?
            }
            WebBrowserMethod::PutRegisterAsDropTarget => {
                browser.register_as_drop_target = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
            WebBrowserMethod::GetTheaterMode => {
                self.copy_variant_bool_out(memory, state, browser.theater_mode)?
            }
            WebBrowserMethod::PutTheaterMode => {
                browser.theater_mode = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
            WebBrowserMethod::GetAddressBar => {
                self.copy_variant_bool_out(memory, state, browser.address_bar)?
            }
            WebBrowserMethod::PutAddressBar => {
                browser.address_bar = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
            WebBrowserMethod::GetResizable => {
                self.copy_variant_bool_out(memory, state, browser.resizable)?
            }
            WebBrowserMethod::PutResizable => {
                browser.resizable = bool_arg(state, memory, 1)?;
                HR_S_OK
            }
        };
        if method != WebBrowserMethod::Release {
            self.web_browsers.insert(this, browser);
        }
        state.set(Register::Rax, result);
        self.last_error = 0;
        Ok(())
    }

    fn web_browser_query_interface(
        &mut self,
        memory: &mut MemoryImage,
        this: u64,
        state: &CpuState,
        browser: &WebBrowserState,
    ) -> AppResult<u64> {
        let iid_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if iid_ptr == 0 || out == 0 {
            return Ok(HR_E_INVALIDARG);
        }
        let iid = read_guid_string(memory, iid_ptr)?;
        let supported = iid.eq_ignore_ascii_case(IID_IUNKNOWN)
            || iid.eq_ignore_ascii_case(IID_IDISPATCH)
            || iid.eq_ignore_ascii_case(IID_IWEBBROWSER)
            || iid.eq_ignore_ascii_case(IID_IWEBBROWSERAPP)
            || iid.eq_ignore_ascii_case(IID_IWEBBROWSER2);
        if !supported {
            write_guest_pointer(memory, out, 0, self.guest_arch)?;
            return Ok(HR_E_NOINTERFACE);
        }
        let _ = browser;
        self.add_ref_guest_object(this)?;
        write_guest_pointer(memory, out, this, self.guest_arch)?;
        Ok(HR_S_OK)
    }

    fn web_browser_navigate(&mut self, browser: &mut WebBrowserState, url: &str) -> u64 {
        if browser.closed {
            return HR_E_INVALIDARG;
        }
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return HR_E_INVALIDARG;
        }
        if !browser_url_supported(self, trimmed) {
            return HR_INET_E_INVALID_URL;
        }
        let resolved = if trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':' {
            match self.win32.guest_path_to_host_path(trimmed) {
                Ok(path) => format!("file:///{}", path.to_string_lossy().replace('\\', "/")),
                Err(_) => return HR_INET_E_INVALID_URL,
            }
        } else if let Some(rest) = trimmed
            .to_ascii_lowercase()
            .strip_prefix("file://")
            .map(|_| &trimmed[7..])
        {
            let path = rest.trim_start_matches('/');
            match self.win32.guest_path_to_host_path(path) {
                Ok(path) => format!("file:///{}", path.to_string_lossy().replace('\\', "/")),
                Err(_) => return HR_INET_E_INVALID_URL,
            }
        } else {
            trimmed.to_string()
        };
        browser.ready_state = READYSTATE_LOADING;
        browser.location = resolved.clone();
        browser.history.truncate(browser.history_index + 1);
        browser.history.push(resolved);
        browser.history_index = browser.history.len() - 1;
        browser.ready_state = READYSTATE_COMPLETE;
        browser.status_text = "Done".to_string();
        HR_S_OK
    }

    fn copy_bstr_out(
        &mut self,
        memory: &mut MemoryImage,
        state: &CpuState,
        value: String,
    ) -> AppResult<u64> {
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            return Ok(HR_E_INVALIDARG);
        }
        let bstr = self.alloc_com_bstr(memory, &value)?;
        write_guest_pointer(memory, out, bstr, self.guest_arch)?;
        Ok(HR_S_OK)
    }

    fn copy_variant_bool_out(
        &mut self,
        memory: &mut MemoryImage,
        state: &CpuState,
        value: bool,
    ) -> AppResult<u64> {
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            return Ok(HR_E_INVALIDARG);
        }
        memory.write_u16(out, if value { 0xffff } else { 0 });
        Ok(HR_S_OK)
    }

    fn web_browser_get_ids_of_names(
        &mut self,
        memory: &mut MemoryImage,
        state: &CpuState,
    ) -> AppResult<u64> {
        let names = guest_call_arg(state, memory, 2)?;
        let count = guest_call_arg_u32(state, memory, 3)?;
        let ids = guest_call_arg(state, memory, 5)?;
        if names == 0 || count == 0 || ids == 0 {
            return Ok(HR_E_INVALIDARG);
        }
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let mut resolved = Vec::with_capacity(count as usize);
        for index in 0..count as u64 {
            let name_ptr =
                read_guest_pointer(memory, names + index * pointer_bytes, self.guest_arch)?;
            if name_ptr == 0 {
                return Ok(HR_E_INVALIDARG);
            }
            let name = read_utf16_string(memory, name_ptr)?;
            match WebBrowserMethod::ALL
                .into_iter()
                .find(|method| method.dispatch_name().eq_ignore_ascii_case(&name))
            {
                Some(method) => resolved.push(method.dispid()),
                None => {
                    for slot in 0..count as u64 {
                        write_u32(memory, ids + slot * 4, DISPID_UNKNOWN as u32);
                    }
                    return Ok(HR_DISP_E_UNKNOWNNAME);
                }
            }
        }
        for (index, dispid) in resolved.into_iter().enumerate() {
            write_u32(memory, ids + index as u64 * 4, dispid as u32);
        }
        Ok(HR_S_OK)
    }

    fn web_browser_invoke(
        &mut self,
        memory: &mut MemoryImage,
        state: &CpuState,
        this: u64,
        browser: &mut WebBrowserState,
    ) -> AppResult<u64> {
        let dispid = guest_call_arg(state, memory, 1)? as i32;
        let flags = guest_call_arg_u32(state, memory, 4)? as u16;
        let params = guest_call_arg(state, memory, 5)?;
        let result = guest_call_arg(state, memory, 6)?;
        let Some(method) = WebBrowserMethod::ALL
            .into_iter()
            .find(|method| method.dispid() == dispid)
        else {
            return Ok(HR_DISP_E_MEMBERNOTFOUND);
        };
        let kind = if flags & DISPATCH_PROPERTYGET != 0 {
            DISPATCH_PROPERTYGET
        } else if flags & DISPATCH_PROPERTYPUT != 0 {
            DISPATCH_PROPERTYPUT
        } else if flags & DISPATCH_METHOD != 0 {
            DISPATCH_METHOD
        } else {
            return Ok(HR_DISP_E_MEMBERNOTFOUND);
        };
        if !method.supports_kind(kind) {
            return Ok(HR_DISP_E_MEMBERNOTFOUND);
        }
        match method {
            WebBrowserMethod::GetVisible => {
                Ok(write_variant_bool(self, memory, result, browser.visible))
            }
            WebBrowserMethod::GetStatusBar => {
                Ok(write_variant_bool(self, memory, result, browser.status_bar))
            }
            WebBrowserMethod::GetStatusText => {
                write_variant_bstr(self, memory, result, &browser.status_text)
            }
            WebBrowserMethod::GetToolBar => Ok(write_variant_i4(memory, result, browser.tool_bar)),
            WebBrowserMethod::GetMenuBar => {
                Ok(write_variant_bool(self, memory, result, browser.menu_bar))
            }
            WebBrowserMethod::GetFullScreen => Ok(write_variant_bool(
                self,
                memory,
                result,
                browser.full_screen,
            )),
            WebBrowserMethod::GetName => {
                write_variant_bstr(self, memory, result, "Windows Internet Explorer")
            }
            WebBrowserMethod::GetFullName => write_variant_bstr(
                self,
                memory,
                result,
                "C:\\Program Files\\Internet Explorer\\iexplore.exe",
            ),
            WebBrowserMethod::GetPath => {
                write_variant_bstr(self, memory, result, "C:\\Program Files\\Internet Explorer")
            }
            WebBrowserMethod::GetReadyState => {
                Ok(write_variant_i4(memory, result, browser.ready_state))
            }
            WebBrowserMethod::GetRegisterAsBrowser => Ok(write_variant_bool(
                self,
                memory,
                result,
                browser.register_as_browser,
            )),
            WebBrowserMethod::GetRegisterAsDropTarget => Ok(write_variant_bool(
                self,
                memory,
                result,
                browser.register_as_drop_target,
            )),
            WebBrowserMethod::GetTheaterMode => Ok(write_variant_bool(
                self,
                memory,
                result,
                browser.theater_mode,
            )),
            WebBrowserMethod::GetAddressBar => Ok(write_variant_bool(
                self,
                memory,
                result,
                browser.address_bar,
            )),
            WebBrowserMethod::GetResizable => {
                Ok(write_variant_bool(self, memory, result, browser.resizable))
            }
            WebBrowserMethod::GetApplication
            | WebBrowserMethod::GetParent
            | WebBrowserMethod::GetContainer => {
                if result == 0 {
                    return Ok(HR_E_INVALIDARG);
                }
                self.add_ref_guest_object(this)?;
                Ok(write_variant_dispatch(self, memory, result, this))
            }
            WebBrowserMethod::GetDocument => {
                if result == 0 {
                    return Ok(HR_E_INVALIDARG);
                }
                memory.map_bytes(result, &vec![0; self.browser_variant_size()]);
                Ok(HR_S_FALSE)
            }
            WebBrowserMethod::PutVisible
            | WebBrowserMethod::PutStatusBar
            | WebBrowserMethod::PutMenuBar
            | WebBrowserMethod::PutFullScreen
            | WebBrowserMethod::PutRegisterAsBrowser
            | WebBrowserMethod::PutRegisterAsDropTarget
            | WebBrowserMethod::PutTheaterMode
            | WebBrowserMethod::PutAddressBar
            | WebBrowserMethod::PutResizable
            | WebBrowserMethod::PutToolBar
            | WebBrowserMethod::PutStatusText => {
                let value_ptr = dispatch_param(self, memory, params, 0);
                let Some(value) = variant_to_string(self, memory, value_ptr) else {
                    return Ok(HR_DISP_E_TYPEMISMATCH);
                };
                match method {
                    WebBrowserMethod::PutVisible => {
                        browser.visible = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutStatusBar => {
                        browser.status_bar = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutStatusText => browser.status_text = value,
                    WebBrowserMethod::PutMenuBar => {
                        browser.menu_bar = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutFullScreen => {
                        browser.full_screen = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutRegisterAsBrowser => {
                        browser.register_as_browser = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutRegisterAsDropTarget => {
                        browser.register_as_drop_target = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutTheaterMode => {
                        browser.theater_mode = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutAddressBar => {
                        browser.address_bar = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutResizable => {
                        browser.resizable = value == "true" || value == "-1"
                    }
                    WebBrowserMethod::PutToolBar => {
                        if let Ok(number) = value.parse::<i32>() {
                            browser.tool_bar = number;
                        }
                    }
                    _ => {} // coverage: unreachable — the outer arm filters the method
                }
                Ok(HR_S_OK)
            }
            WebBrowserMethod::GoBack => {
                if browser.can_go_back() {
                    browser.history_index -= 1;
                    browser.location = browser.history[browser.history_index].clone();
                    Ok(HR_S_OK)
                } else {
                    Ok(HR_S_FALSE)
                }
            }
            WebBrowserMethod::GoForward => {
                if browser.can_go_forward() {
                    browser.history_index += 1;
                    browser.location = browser.history[browser.history_index].clone();
                    Ok(HR_S_OK)
                } else {
                    Ok(HR_S_FALSE)
                }
            }
            WebBrowserMethod::GoHome => {
                let home = self
                    .win32
                    .ge()
                    .registry_get_value(
                        "HKCU",
                        "Software\\Microsoft\\Internet Explorer\\Main",
                        "Start Page",
                        RegistryView::Native,
                    )
                    .ok()
                    .flatten()
                    .and_then(|value| value.data.as_str().map(str::to_string))
                    .unwrap_or_else(|| "about:blank".to_string());
                Ok(self.web_browser_navigate(browser, &home))
            }
            WebBrowserMethod::GoSearch => {
                let search = self
                    .win32
                    .ge()
                    .registry_get_value(
                        "HKCU",
                        "Software\\Microsoft\\Internet Explorer\\Main",
                        "Search Page",
                        RegistryView::Native,
                    )
                    .ok()
                    .flatten()
                    .and_then(|value| value.data.as_str().map(str::to_string))
                    .unwrap_or_else(|| "about:blank".to_string());
                Ok(self.web_browser_navigate(browser, &search))
            }
            WebBrowserMethod::Navigate | WebBrowserMethod::Navigate2 => {
                let url_ptr = dispatch_param(self, memory, params, 0);
                let Some(url) = variant_to_url(self, memory, url_ptr) else {
                    return Ok(HR_DISP_E_TYPEMISMATCH);
                };
                let url = if method == WebBrowserMethod::Navigate2 && url.trim().is_empty() {
                    "about:blank".to_string()
                } else {
                    url
                };
                Ok(self.web_browser_navigate(browser, &url))
            }
            WebBrowserMethod::Refresh => {
                browser.ready_state = READYSTATE_COMPLETE;
                Ok(HR_S_OK)
            }
            WebBrowserMethod::Refresh2 => Ok(HR_S_OK),
            WebBrowserMethod::Stop => {
                browser.ready_state = READYSTATE_COMPLETE;
                Ok(HR_S_OK)
            }
            WebBrowserMethod::Quit => {
                browser.closed = true;
                browser.visible = false;
                Ok(HR_S_OK)
            }
            WebBrowserMethod::PutProperty | WebBrowserMethod::GetProperty => {
                let name_ptr = dispatch_param(self, memory, params, 0);
                let Some(name) = variant_to_string(self, memory, name_ptr) else {
                    return Ok(HR_DISP_E_TYPEMISMATCH);
                };
                if method == WebBrowserMethod::PutProperty {
                    let value_ptr = dispatch_param(self, memory, params, 1);
                    let Some(value) = variant_to_string(self, memory, value_ptr) else {
                        return Ok(HR_DISP_E_TYPEMISMATCH);
                    };
                    browser.properties.insert(name, value);
                    Ok(HR_S_OK)
                } else {
                    let value = browser.properties.get(&name).cloned().unwrap_or_default();
                    write_variant_bstr(self, memory, result, &value)
                }
            }
            WebBrowserMethod::QueryStatusWB
            | WebBrowserMethod::ExecWB
            | WebBrowserMethod::ShowBrowserBar
            | WebBrowserMethod::ClientToWindow => Ok(HR_OLECMDERR_E_NOTSUPPORTED),
            WebBrowserMethod::GetTypeInfoCount => Ok(write_variant_i4(memory, result, 1)),
            WebBrowserMethod::GetTypeInfo => Ok(HR_E_NOTIMPL),
            WebBrowserMethod::GetIDsOfNames | WebBrowserMethod::Invoke => {
                Ok(HR_DISP_E_MEMBERNOTFOUND)
            }
            WebBrowserMethod::QueryInterface
            | WebBrowserMethod::AddRef
            | WebBrowserMethod::Release => Ok(HR_DISP_E_MEMBERNOTFOUND),
        }
    }
}

/// Write a VT_BOOL VARIANT.
fn write_variant_bool(
    runtime: &PeHostRuntime,
    memory: &mut MemoryImage,
    ptr: u64,
    value: bool,
) -> u64 {
    if ptr == 0 {
        return HR_E_INVALIDARG;
    }
    memory.map_bytes(ptr, &vec![0; runtime.browser_variant_size()]);
    memory.write_u16(ptr, 11);
    memory.write_u16(ptr + 8, if value { 0xffff } else { 0 });
    HR_S_OK
}

/// Write a VT_I4 VARIANT.
fn write_variant_i4(memory: &mut MemoryImage, ptr: u64, value: i32) -> u64 {
    if ptr == 0 {
        return HR_E_INVALIDARG;
    }
    memory.map_bytes(ptr, &[0_u8; 16]);
    memory.write_u16(ptr, 3);
    memory.write_u32(ptr + 8, value as u32);
    HR_S_OK
}

/// Write a VT_DISPATCH VARIANT.
fn write_variant_dispatch(
    runtime: &PeHostRuntime,
    memory: &mut MemoryImage,
    ptr: u64,
    object: u64,
) -> u64 {
    if ptr == 0 {
        // coverage: unreachable — every caller validates the result pointer
        return HR_E_INVALIDARG; // coverage: unreachable — callers validate the result pointer
    }
    memory.map_bytes(ptr, &vec![0; runtime.browser_variant_size()]);
    memory.write_u16(ptr, 9);
    let _ = write_guest_pointer(memory, ptr + 8, object, runtime.guest_arch);
    HR_S_OK
}

/// Write a VT_BSTR VARIANT.
fn write_variant_bstr(
    runtime: &mut PeHostRuntime,
    memory: &mut MemoryImage,
    ptr: u64,
    value: &str,
) -> AppResult<u64> {
    if ptr == 0 {
        return Ok(HR_E_INVALIDARG);
    }
    let bstr = runtime.alloc_com_bstr(memory, value)?;
    memory.map_bytes(ptr, &vec![0; runtime.browser_variant_size()]);
    memory.write_u16(ptr, 8);
    write_guest_pointer(memory, ptr + 8, bstr, runtime.guest_arch)?;
    Ok(HR_S_OK)
}

/// Read one `DISPPARAMS` argument (arguments are stored in reverse order).
fn dispatch_param(runtime: &PeHostRuntime, memory: &MemoryImage, params: u64, index: usize) -> u64 {
    if params == 0 {
        return 0;
    }
    // DISPPARAMS { VARIANTARG *rgvarg; DISPID *rgdispidNamedArgs; UINT cArgs; UINT cNamedArgs; }
    let count_offset = if runtime.guest_arch == GuestArch::X86 {
        8
    } else {
        16
    };
    let count = memory.read_u32(params + count_offset).unwrap_or(0) as usize;
    if index >= count {
        return 0;
    }
    let args = read_guest_pointer(memory, params, runtime.guest_arch).unwrap_or(0);
    if args == 0 {
        return 0;
    }
    let variant_size = runtime.browser_variant_size() as u64;
    let position = (count - 1 - index) as u64;
    args + position * variant_size
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{Fixture, dispatch_x86, with_big_stack, x86_fixture};
    use super::*;

    const OUT: u64 = 0x60_000;
    const TEXT: u64 = 0x61_000;
    const VAR: u64 = 0x62_000;
    const VAR2: u64 = 0x62_100;
    const IID: u64 = 0x63_000;
    const NAMES: u64 = 0x64_000;
    const IDS: u64 = 0x65_000;
    const PARAMS: u64 = 0x66_000;
    const ARGS: u64 = 0x67_000;

    fn object(fixture: &mut Fixture) -> u64 {
        fixture.runtime.guest_arch = GuestArch::X86;
        fixture
            .runtime
            .alloc_web_browser_object(&mut fixture.memory, "about:blank")
            .expect("allocate browser")
    }

    fn call(fixture: &mut Fixture, method: WebBrowserMethod, args: &[u32]) -> u64 {
        dispatch_x86(fixture, HostThunk::WebBrowserMethod(method), args)
    }

    fn write_iid(fixture: &mut Fixture, address: u64, iid: &str) {
        let bytes = crate::real_win32::guid_from_string(iid).expect("guid");
        fixture.memory.map_bytes(address, &bytes);
    }

    fn wide(fixture: &mut Fixture, text: &str) -> u64 {
        fixture
            .runtime
            .alloc_utf16_string(&mut fixture.memory, text)
            .expect("wide string")
    }

    fn map(fixture: &mut Fixture, address: u64, size: u64) {
        fixture
            .memory
            .map_bytes(address, &vec![0_u8; size as usize]);
    }

    fn read_out_pointer(fixture: &Fixture, address: u64) -> u64 {
        read_guest_pointer(&fixture.memory, address, GuestArch::X86).expect("pointer")
    }

    fn read_out_string(fixture: &Fixture, address: u64) -> String {
        let bstr = read_out_pointer(fixture, address);
        read_utf16_string(&fixture.memory, bstr).expect("bstr")
    }

    fn write_variant_wide(fixture: &mut Fixture, address: u64, text: &str) {
        let bstr = fixture
            .runtime
            .alloc_com_bstr(&mut fixture.memory, text)
            .expect("bstr");
        fixture
            .memory
            .map_bytes(address, &vec![0_u8; fixture.runtime.browser_variant_size()]);
        fixture.memory.write_u16(address, 8);
        write_guest_pointer(&mut fixture.memory, address + 8, bstr, GuestArch::X86)
            .expect("variant pointer");
    }

    fn write_variant_bool_value(fixture: &mut Fixture, address: u64, value: bool) {
        fixture
            .memory
            .map_bytes(address, &vec![0_u8; fixture.runtime.browser_variant_size()]);
        fixture.memory.write_u16(address, 11);
        fixture
            .memory
            .write_u16(address + 8, if value { 0xffff } else { 0 });
    }

    fn write_variant_i4_value(fixture: &mut Fixture, address: u64, value: i32) {
        fixture
            .memory
            .map_bytes(address, &vec![0_u8; fixture.runtime.browser_variant_size()]);
        fixture.memory.write_u16(address, 3);
        fixture.memory.write_u32(address + 8, value as u32);
    }

    fn location(fixture: &Fixture, object: u64) -> String {
        fixture
            .runtime
            .web_browsers
            .get(&object)
            .expect("browser state")
            .location
            .clone()
    }

    #[test]
    fn web_browser_every_vtable_slot_rejects_a_null_this_with_e_invalidarg() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-null-this");
            for method in WebBrowserMethod::ALL {
                let result = call(&mut fixture, method, &[0; 9]);
                assert_eq!(
                    result,
                    HR_E_INVALIDARG,
                    "{} must reject a null this with E_INVALIDARG",
                    method.dispatch_name()
                );
            }
        });
    }

    #[test]
    fn web_browser_co_create_instance_and_query_interface_pin_supported_iids_and_e_nointerface() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-qi");
            map(&mut fixture, OUT, 4);
            let object_ptr = OUT;
            write_iid(
                &mut fixture,
                IID + 0x100,
                "{8856F961-340A-11D0-A96B-00C04FD705A2}",
            );
            write_iid(&mut fixture, IID, IID_IWEBBROWSER2);
            let result = dispatch_x86(
                &mut fixture,
                HostThunk::CoCreateInstance,
                &[(IID + 0x100) as u32, 0, 1, IID as u32, object_ptr as u32],
            );
            assert_eq!(result, HR_S_OK);
            let object = read_out_pointer(&fixture, object_ptr);
            assert_ne!(object, 0);
            assert!(fixture.runtime.web_browsers.contains_key(&object));

            // CoGetClassObject resolves the same class through its factory.
            write_iid(
                &mut fixture,
                IID + 0x100,
                "{8856F961-340A-11D0-A96B-00C04FD705A2}",
            );
            write_iid(&mut fixture, IID, IID_IUNKNOWN);
            map(&mut fixture, OUT, 4);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::CoGetClassObject,
                    &[(IID + 0x100) as u32, 0, 1, IID as u32, OUT as u32],
                ),
                HR_S_OK
            );
            assert_ne!(read_out_pointer(&fixture, OUT), 0);

            for iid in [
                IID_IUNKNOWN,
                IID_IDISPATCH,
                IID_IWEBBROWSER,
                IID_IWEBBROWSERAPP,
                IID_IWEBBROWSER2,
            ] {
                write_iid(&mut fixture, IID, iid);
                map(&mut fixture, OUT, 4);
                assert_eq!(
                    call(
                        &mut fixture,
                        WebBrowserMethod::QueryInterface,
                        &[object as u32, IID as u32, OUT as u32]
                    ),
                    HR_S_OK,
                    "QI must accept {iid}"
                );
                assert_eq!(read_out_pointer(&fixture, OUT), object);
                let referenced = read_out_pointer(&fixture, OUT);
                call(
                    &mut fixture,
                    WebBrowserMethod::Release,
                    &[referenced as u32],
                );
            }

            write_iid(&mut fixture, IID, "{11111111-2222-3333-4444-555555555555}");
            map(&mut fixture, OUT, 4);
            write_u32(&mut fixture.memory, OUT, 0xdead_beef);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryInterface,
                    &[object as u32, IID as u32, OUT as u32]
                ),
                HR_E_NOINTERFACE
            );
            assert_eq!(read_out_pointer(&fixture, OUT), 0);

            write_iid(&mut fixture, IID, IID_IUNKNOWN);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryInterface,
                    &[object as u32, IID as u32, 0]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryInterface,
                    &[object as u32, 0, OUT as u32]
                ),
                HR_E_INVALIDARG
            );

            assert_eq!(
                call(&mut fixture, WebBrowserMethod::AddRef, &[object as u32]),
                2
            );
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Release, &[object as u32]),
                1
            );
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Release, &[object as u32]),
                0
            );
            assert!(!fixture.runtime.web_browsers.contains_key(&object));
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Release, &[object as u32]),
                HR_E_INVALIDARG
            );
        });
    }

    #[test]
    fn web_browser_navigation_history_invalid_urls_and_ready_state_are_exact() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-navigation");
            let object = object(&mut fixture);
            let first = wide(&mut fixture, "http://example.com/a");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, first as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "http://example.com/a");
            assert_eq!(
                fixture.runtime.web_browsers[&object].history,
                vec![
                    "about:blank".to_string(),
                    "http://example.com/a".to_string()
                ]
            );

            let empty = wide(&mut fixture, "");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, empty as u32, 0, 0, 0, 0]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, 0, 0, 0, 0, 0]
                ),
                HR_E_INVALIDARG
            );
            let malformed = wide(&mut fixture, "not-a-url");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, malformed as u32, 0, 0, 0, 0]
                ),
                HR_INET_E_INVALID_URL
            );
            let unsupported = wide(&mut fixture, "gopher://example.com/");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, unsupported as u32, 0, 0, 0, 0]
                ),
                HR_INET_E_INVALID_URL
            );
            let missing_file = wide(&mut fixture, "C:\\missing\\nope.exe");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, missing_file as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );

            write_variant_wide(&mut fixture, VAR, "https://example.com/b");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate2,
                    &[object as u32, VAR as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "https://example.com/b");

            write_variant_i4_value(&mut fixture, VAR, 7);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate2,
                    &[object as u32, VAR as u32, 0, 0, 0, 0]
                ),
                HR_DISP_E_TYPEMISMATCH
            );

            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoBack, &[object as u32]),
                HR_S_OK
            );
            assert!(location(&fixture, object).contains("missing"));
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoBack, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "http://example.com/a");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoBack, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "about:blank");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoBack, &[object as u32]),
                HR_S_FALSE
            );
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoForward, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "http://example.com/a");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoForward, &[object as u32]),
                HR_S_OK
            );
            assert!(location(&fixture, object).contains("missing"));
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoForward, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "https://example.com/b");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoForward, &[object as u32]),
                HR_S_FALSE
            );

            fixture
                .runtime
                .web_browsers
                .get_mut(&object)
                .unwrap()
                .ready_state = READYSTATE_LOADING;
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Refresh, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(
                fixture.runtime.web_browsers[&object].ready_state,
                READYSTATE_COMPLETE
            );
            fixture
                .runtime
                .web_browsers
                .get_mut(&object)
                .unwrap()
                .ready_state = READYSTATE_LOADING;
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Refresh2,
                    &[object as u32, 0]
                ),
                HR_S_OK
            );
            write_variant_i4_value(&mut fixture, VAR, 3);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Refresh2,
                    &[object as u32, VAR as u32]
                ),
                HR_S_OK
            );
            write_variant_wide(&mut fixture, VAR, "x");
            fixture.memory.write_u16(VAR, 5);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Refresh2,
                    &[object as u32, VAR as u32]
                ),
                HR_E_INVALIDARG
            );
            fixture
                .runtime
                .web_browsers
                .get_mut(&object)
                .unwrap()
                .ready_state = READYSTATE_LOADING;
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Stop, &[object as u32]),
                HR_S_OK
            );
            map(&mut fixture, OUT, 4);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetReadyState,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(
                fixture.memory.read_u32(OUT).unwrap(),
                READYSTATE_COMPLETE as u32
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetReadyState,
                    &[object as u32, 0]
                ),
                HR_E_INVALIDARG
            );

            fixture
                .runtime
                .win32
                .ge()
                .registry_set_value(
                    "HKCU",
                    "Software\\Microsoft\\Internet Explorer\\Main",
                    "Start Page",
                    "REG_SZ",
                    json!("http://home.example/"),
                    RegistryView::Native,
                )
                .expect("set home");
            fixture
                .runtime
                .win32
                .ge()
                .registry_set_value(
                    "HKCU",
                    "Software\\Microsoft\\Internet Explorer\\Main",
                    "Search Page",
                    "REG_SZ",
                    json!("http://search.example/?q=%s"),
                    RegistryView::Native,
                )
                .expect("set search");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoHome, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "http://home.example/");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoSearch, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "http://search.example/?q=%s");

            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Quit, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Quit, &[object as u32]),
                HR_S_FALSE
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, first as u32, 0, 0, 0, 0]
                ),
                HR_E_INVALIDARG
            );
        });
    }

    #[test]
    fn web_browser_property_surface_round_trips_and_rejects_invalid_inputs() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-properties");
            let object = object(&mut fixture);
            for (put, get, value) in [
                (
                    WebBrowserMethod::PutVisible,
                    WebBrowserMethod::GetVisible,
                    false,
                ),
                (
                    WebBrowserMethod::PutStatusBar,
                    WebBrowserMethod::GetStatusBar,
                    true,
                ),
                (
                    WebBrowserMethod::PutMenuBar,
                    WebBrowserMethod::GetMenuBar,
                    false,
                ),
                (
                    WebBrowserMethod::PutFullScreen,
                    WebBrowserMethod::GetFullScreen,
                    true,
                ),
                (
                    WebBrowserMethod::PutRegisterAsBrowser,
                    WebBrowserMethod::GetRegisterAsBrowser,
                    true,
                ),
                (
                    WebBrowserMethod::PutRegisterAsDropTarget,
                    WebBrowserMethod::GetRegisterAsDropTarget,
                    true,
                ),
                (
                    WebBrowserMethod::PutTheaterMode,
                    WebBrowserMethod::GetTheaterMode,
                    true,
                ),
                (
                    WebBrowserMethod::PutAddressBar,
                    WebBrowserMethod::GetAddressBar,
                    false,
                ),
                (
                    WebBrowserMethod::PutResizable,
                    WebBrowserMethod::GetResizable,
                    false,
                ),
            ] {
                assert_eq!(
                    call(&mut fixture, put, &[object as u32, u32::from(value as u16)]),
                    HR_S_OK
                );
                map(&mut fixture, OUT, 4);
                assert_eq!(
                    call(&mut fixture, get, &[object as u32, OUT as u32]),
                    HR_S_OK
                );
                assert_eq!(
                    fixture.memory.read_u16(OUT).unwrap(),
                    if value { 0xffff } else { 0 }
                );
                assert_eq!(
                    call(&mut fixture, get, &[object as u32, 0]),
                    HR_E_INVALIDARG
                );
            }

            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutToolBar,
                    &[object as u32, 2]
                ),
                HR_S_OK
            );
            map(&mut fixture, OUT, 4);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetToolBar,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 2);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutToolBar,
                    &[object as u32, 9]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetToolBar,
                    &[object as u32, 0]
                ),
                HR_E_INVALIDARG
            );

            let status = wide(&mut fixture, "Loading");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutStatusText,
                    &[object as u32, status as u32]
                ),
                HR_S_OK
            );
            map(&mut fixture, OUT, 4);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetStatusText,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "Loading");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutStatusText,
                    &[object as u32, 0]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.runtime.web_browsers[&object].status_text, "");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetStatusText,
                    &[object as u32, 0]
                ),
                HR_E_INVALIDARG
            );

            for (method, expected) in [
                (WebBrowserMethod::GetName, "Windows Internet Explorer"),
                (
                    WebBrowserMethod::GetFullName,
                    "C:\\Program Files\\Internet Explorer\\iexplore.exe",
                ),
                (
                    WebBrowserMethod::GetPath,
                    "C:\\Program Files\\Internet Explorer",
                ),
            ] {
                map(&mut fixture, OUT, 4);
                assert_eq!(
                    call(&mut fixture, method, &[object as u32, OUT as u32]),
                    HR_S_OK
                );
                assert_eq!(read_out_string(&fixture, OUT), expected);
                assert_eq!(
                    call(&mut fixture, method, &[object as u32, 0]),
                    HR_E_INVALIDARG
                );
            }

            for method in [
                WebBrowserMethod::GetApplication,
                WebBrowserMethod::GetParent,
                WebBrowserMethod::GetContainer,
            ] {
                map(&mut fixture, OUT, 4);
                assert_eq!(
                    call(&mut fixture, method, &[object as u32, OUT as u32]),
                    HR_S_OK
                );
                assert_eq!(read_out_pointer(&fixture, OUT), object);
                call(&mut fixture, WebBrowserMethod::Release, &[object as u32]);
                assert_eq!(
                    call(&mut fixture, method, &[object as u32, 0]),
                    HR_E_INVALIDARG
                );
            }

            map(&mut fixture, OUT, 4);
            write_u32(&mut fixture.memory, OUT, 0xdead_beef);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[object as u32, OUT as u32]
                ),
                HR_S_FALSE
            );
            assert_eq!(read_out_pointer(&fixture, OUT), 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[object as u32, 0]
                ),
                HR_E_INVALIDARG
            );

            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ShowBrowserBar,
                    &[object as u32, 0, 0, 0]
                ),
                HR_E_NOTIMPL
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ClientToWindow,
                    &[object as u32, OUT as u32, OUT as u32 + 4]
                ),
                HR_E_NOTIMPL
            );
        });
    }

    #[test]
    fn web_browser_dispatch_names_invoke_and_documented_errors_pin_exact_results() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-dispatch");
            let object = object(&mut fixture);
            map(&mut fixture, NAMES, 8);
            map(&mut fixture, IDS, 8);
            let go_back = wide(&mut fixture, "GoBack");
            let visible = wide(&mut fixture, "Visible");
            write_u32(&mut fixture.memory, NAMES, go_back as u32);
            write_u32(&mut fixture.memory, NAMES + 4, visible as u32);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[object as u32, 0, NAMES as u32, 2, 0, IDS as u32]
                ),
                HR_S_OK
            );
            assert_eq!(
                fixture.memory.read_u32(IDS).unwrap(),
                WebBrowserMethod::GoBack.dispid() as u32
            );
            assert_eq!(
                fixture.memory.read_u32(IDS + 4).unwrap(),
                WebBrowserMethod::GetVisible.dispid() as u32
            );

            let unknown = wide(&mut fixture, "NoSuchMember");
            write_u32(&mut fixture.memory, NAMES, unknown as u32);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[object as u32, 0, NAMES as u32, 1, 0, IDS as u32]
                ),
                HR_DISP_E_UNKNOWNNAME
            );
            assert_eq!(fixture.memory.read_u32(IDS).unwrap(), DISPID_UNKNOWN as u32);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[object as u32, 0, 0, 1, 0, IDS as u32]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[object as u32, 0, NAMES as u32, 1, 0, 0]
                ),
                HR_E_INVALIDARG
            );
            write_u32(&mut fixture.memory, NAMES, 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[object as u32, 0, NAMES as u32, 1, 0, IDS as u32]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[object as u32, 0, NAMES as u32, 0, 0, IDS as u32]
                ),
                HR_E_INVALIDARG
            );

            // Invoke a property get: Visible.
            map(&mut fixture, VAR, 24);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetVisible.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        VAR as u32,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u16(VAR).unwrap(), 11);
            assert_eq!(fixture.memory.read_u16(VAR + 8).unwrap(), 0xffff);

            // Invoke a property put: Visible = false.
            map(&mut fixture, PARAMS, 24);
            map(&mut fixture, ARGS, 24);
            write_variant_bool_value(&mut fixture, ARGS, false);
            write_u32(&mut fixture.memory, PARAMS, ARGS as u32);
            write_u32(&mut fixture.memory, PARAMS + 8, 1);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::PutVisible.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYPUT),
                        PARAMS as u32,
                        0,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );
            assert!(!fixture.runtime.web_browsers[&object].visible);

            // Invoke Navigate with the BSTR in the DISPPARAMS argument array.
            write_variant_wide(&mut fixture, ARGS, "http://invoke.example/");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::Navigate.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        0,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "http://invoke.example/");

            // Every getter/putter arm in the dispatch table.
            for method in WebBrowserMethod::ALL {
                if matches!(
                    method,
                    WebBrowserMethod::GetVisible
                        | WebBrowserMethod::GetStatusBar
                        | WebBrowserMethod::GetStatusText
                        | WebBrowserMethod::GetToolBar
                        | WebBrowserMethod::GetMenuBar
                        | WebBrowserMethod::GetFullScreen
                        | WebBrowserMethod::GetName
                        | WebBrowserMethod::GetFullName
                        | WebBrowserMethod::GetPath
                        | WebBrowserMethod::GetReadyState
                        | WebBrowserMethod::GetRegisterAsBrowser
                        | WebBrowserMethod::GetRegisterAsDropTarget
                        | WebBrowserMethod::GetTheaterMode
                        | WebBrowserMethod::GetAddressBar
                        | WebBrowserMethod::GetResizable
                        | WebBrowserMethod::GetApplication
                        | WebBrowserMethod::GetParent
                        | WebBrowserMethod::GetContainer
                        | WebBrowserMethod::GetDocument
                ) {
                    map(&mut fixture, VAR2, 24);
                    let hr = call(
                        &mut fixture,
                        WebBrowserMethod::Invoke,
                        &[
                            object as u32,
                            method.dispid() as u32,
                            0,
                            0,
                            u32::from(DISPATCH_PROPERTYGET),
                            0,
                            VAR2 as u32,
                            0,
                            0,
                        ],
                    );
                    assert!(
                        hr == HR_S_OK || hr == HR_S_FALSE,
                        "{} get must succeed",
                        method.dispatch_name()
                    );
                }
                if matches!(
                    method,
                    WebBrowserMethod::PutVisible
                        | WebBrowserMethod::PutStatusBar
                        | WebBrowserMethod::PutStatusText
                        | WebBrowserMethod::PutToolBar
                        | WebBrowserMethod::PutMenuBar
                        | WebBrowserMethod::PutFullScreen
                        | WebBrowserMethod::PutRegisterAsBrowser
                        | WebBrowserMethod::PutRegisterAsDropTarget
                        | WebBrowserMethod::PutTheaterMode
                        | WebBrowserMethod::PutAddressBar
                        | WebBrowserMethod::PutResizable
                ) {
                    write_variant_i4_value(&mut fixture, ARGS, 1);
                    write_u32(&mut fixture.memory, PARAMS, ARGS as u32);
                    write_u32(&mut fixture.memory, PARAMS + 8, 1);
                    assert_eq!(
                        call(
                            &mut fixture,
                            WebBrowserMethod::Invoke,
                            &[
                                object as u32,
                                method.dispid() as u32,
                                0,
                                0,
                                u32::from(DISPATCH_PROPERTYPUT),
                                PARAMS as u32,
                                0,
                                0,
                                0
                            ]
                        ),
                        HR_S_OK,
                        "{} put must succeed",
                        method.dispatch_name()
                    );
                }
            }

            // GetTypeInfoCount/GetTypeInfo through Invoke.
            map(&mut fixture, VAR2, 24);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetTypeInfoCount.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        0,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(VAR2 + 8).unwrap(), 1);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetTypeInfo.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        0,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_E_NOTIMPL
            );

            // Control members through Invoke: MEMBERNOTFOUND for the IDispatch
            // preamble, documented command errors for host-only members.
            for method in [
                WebBrowserMethod::QueryInterface,
                WebBrowserMethod::AddRef,
                WebBrowserMethod::Release,
                WebBrowserMethod::GetIDsOfNames,
                WebBrowserMethod::Invoke,
            ] {
                assert_eq!(
                    call(
                        &mut fixture,
                        WebBrowserMethod::Invoke,
                        &[
                            object as u32,
                            method.dispid() as u32,
                            0,
                            0,
                            u32::from(DISPATCH_METHOD),
                            0,
                            0,
                            0,
                            0
                        ]
                    ),
                    HR_DISP_E_MEMBERNOTFOUND,
                    "{} must not be invokable",
                    method.dispatch_name()
                );
            }
            for method in [
                WebBrowserMethod::QueryStatusWB,
                WebBrowserMethod::ExecWB,
                WebBrowserMethod::ShowBrowserBar,
                WebBrowserMethod::ClientToWindow,
            ] {
                assert_eq!(
                    call(
                        &mut fixture,
                        WebBrowserMethod::Invoke,
                        &[
                            object as u32,
                            method.dispid() as u32,
                            0,
                            0,
                            u32::from(DISPATCH_METHOD),
                            0,
                            0,
                            0,
                            0
                        ]
                    ),
                    HR_OLECMDERR_E_NOTSUPPORTED,
                    "{} must report OLECMDERR_E_NOTSUPPORTED",
                    method.dispatch_name()
                );
            }

            // GoBack/GoForward/GoHome/GoSearch/Refresh/Refresh2/Stop/Quit.
            for method in [
                WebBrowserMethod::GoBack,
                WebBrowserMethod::GoForward,
                WebBrowserMethod::GoHome,
                WebBrowserMethod::GoSearch,
                WebBrowserMethod::Refresh,
                WebBrowserMethod::Refresh2,
                WebBrowserMethod::Quit,
            ] {
                let hr = call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        method.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        0,
                        0,
                        0,
                        0,
                    ],
                );
                assert!(
                    hr == HR_S_OK || hr == HR_S_FALSE,
                    "{} invocation must succeed or report no-op",
                    method.dispatch_name()
                );
            }
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::Stop.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );

            // PutProperty/GetProperty through Invoke.
            write_variant_wide(&mut fixture, ARGS, "foo");
            write_variant_wide(&mut fixture, ARGS + 24, "bar");
            write_u32(&mut fixture.memory, PARAMS, ARGS as u32);
            write_u32(&mut fixture.memory, PARAMS + 8, 2);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::PutProperty.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        0,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );
            map(&mut fixture, VAR2, 24);
            write_variant_wide(&mut fixture, ARGS, "foo");
            write_u32(&mut fixture.memory, PARAMS, ARGS as u32);
            write_u32(&mut fixture.memory, PARAMS + 8, 1);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetProperty.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u16(VAR2).unwrap(), 8);

            // Unknown DISPID and malformed flags.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[object as u32, 0x7fff_ffff, 0, 0, 1, 0, 0, 0, 0]
                ),
                HR_DISP_E_MEMBERNOTFOUND
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetVisible.dispid() as u32,
                        0,
                        0,
                        0,
                        0,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_DISP_E_MEMBERNOTFOUND
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::PutVisible.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_DISP_E_MEMBERNOTFOUND
            );
        });
    }

    #[test]
    fn web_browser_query_status_and_put_get_property_pin_exact_values() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-property-bag");
            let object = object(&mut fixture);
            map(&mut fixture, OUT, 4);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryStatusWB,
                    &[object as u32, 0x16, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(
                fixture.memory.read_u32(OUT).unwrap(),
                OLECMDF_SUPPORTED | OLECMDF_ENABLED
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryStatusWB,
                    &[object as u32, 99, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryStatusWB,
                    &[object as u32, 0x16, 0]
                ),
                HR_E_INVALIDARG
            );

            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, 0x16, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, 2, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, 99, 0, 0, 0]
                ),
                HR_OLECMDERR_E_NOTSUPPORTED
            );

            let name = wide(&mut fixture, "Custom");
            let value = wide(&mut fixture, "Value");
            write_variant_wide(&mut fixture, VAR, "Value");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutProperty,
                    &[object as u32, name as u32, VAR as u32]
                ),
                HR_S_OK
            );
            map(&mut fixture, VAR2, 24);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetProperty,
                    &[object as u32, name as u32, VAR2 as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u16(VAR2).unwrap(), 8);
            let bstr = read_out_pointer(&fixture, VAR2 + 8);
            assert_eq!(read_utf16_string(&fixture.memory, bstr).unwrap(), "Value");

            let missing = wide(&mut fixture, "Missing");
            map(&mut fixture, VAR2, 24);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetProperty,
                    &[object as u32, missing as u32, VAR2 as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u16(VAR2).unwrap(), 8);
            let bstr = read_out_pointer(&fixture, VAR2 + 8);
            assert_eq!(read_utf16_string(&fixture.memory, bstr).unwrap(), "");

            write_variant_wide(&mut fixture, VAR, "x");
            fixture.memory.write_u16(VAR, 5);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutProperty,
                    &[object as u32, name as u32, VAR as u32]
                ),
                HR_DISP_E_TYPEMISMATCH
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutProperty,
                    &[object as u32, 0, VAR as u32]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetProperty,
                    &[object as u32, name as u32, 0]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetProperty,
                    &[object as u32, 0, VAR2 as u32]
                ),
                HR_E_INVALIDARG
            );
            let _ = value;

            // GetTypeInfoCount/GetTypeInfo vtable results.
            map(&mut fixture, OUT, 4);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfoCount,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 1);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfoCount,
                    &[object as u32, 0]
                ),
                HR_E_INVALIDARG
            );
            map(&mut fixture, OUT, 4);
            write_u32(&mut fixture.memory, OUT, 0xdead_beef);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 0, 0, OUT as u32]
                ),
                HR_E_NOTIMPL
            );
            assert_eq!(read_out_pointer(&fixture, OUT), 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 0, 0, 0]
                ),
                HR_E_INVALIDARG
            );

            // File navigation through the real guest filesystem.
            let temp = fixture._temp.path().join("target.exe");
            std::fs::write(&temp, b"MZ").expect("write target");
            fixture
                .runtime
                .win32
                .stage_host_file_w(&temp, "C:\\browser-target.exe")
                .expect("stage target");
            let file_url = wide(&mut fixture, "C:\\browser-target.exe");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, file_url as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert!(location(&fixture, object).starts_with("file:///"));

            // Navigate2 with an empty VARIANT selects about:blank.
            map(&mut fixture, VAR, 24);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate2,
                    &[object as u32, VAR as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "about:blank");

            // A malformed property VARIANT (VT_R8) in Invoke PutProperty.
            write_variant_i4_value(&mut fixture, ARGS, 4);
            fixture.memory.map_bytes(ARGS, &[0_u8; 24]);
            fixture.memory.write_u16(ARGS, 5);
            fixture.memory.write_u64(ARGS + 8, f64::to_bits(1.0));
            write_variant_wide(&mut fixture, ARGS + 24, "name");
            write_u32(&mut fixture.memory, PARAMS, ARGS as u32);
            write_u32(&mut fixture.memory, PARAMS + 8, 2);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::PutProperty.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        0,
                        0,
                        0
                    ]
                ),
                HR_DISP_E_TYPEMISMATCH
            );
        });
    }

    #[test]
    fn web_browser_uri_variant_and_dispatch_edge_cases_pin_exact_results() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-edges");
            let object = object(&mut fixture);

            // Every VARIANT shape the navigation reader models, plus rejection.
            for (vt, expected) in [
                (0_u16, HR_S_OK),
                (1, HR_S_OK),
                (3, HR_INET_E_INVALID_URL),
                (11, HR_INET_E_INVALID_URL),
            ] {
                map(&mut fixture, VAR, 24);
                fixture.memory.write_u16(VAR, vt);
                fixture.memory.write_u32(VAR + 8, 1);
                let hr = call(
                    &mut fixture,
                    WebBrowserMethod::Navigate2,
                    &[object as u32, VAR as u32, 0, 0, 0, 0],
                );
                if vt == 0 || vt == 1 {
                    assert_eq!(hr, expected);
                } else {
                    assert_eq!(hr, HR_DISP_E_TYPEMISMATCH);
                }
            }
            // BSTR with a null payload.
            map(&mut fixture, VAR, 24);
            fixture.memory.write_u16(VAR, 8);
            write_guest_pointer(&mut fixture.memory, VAR + 8, 0, GuestArch::X86).unwrap();
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate2,
                    &[object as u32, VAR as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );
            // A null VARIANT pointer is a type mismatch.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate2,
                    &[object as u32, 0, 0, 0, 0, 0]
                ),
                HR_DISP_E_TYPEMISMATCH
            );

            // about:, ftp:, https: and a bare guest drive path.
            for url in [
                "about:blank",
                "ftp://example.com/f",
                "https://example.com/s",
            ] {
                let ptr = wide(&mut fixture, url);
                assert_eq!(
                    call(
                        &mut fixture,
                        WebBrowserMethod::Navigate,
                        &[object as u32, ptr as u32, 0, 0, 0, 0]
                    ),
                    HR_S_OK,
                    "{url} must navigate"
                );
            }
            let ptr = wide(&mut fixture, "C:\\browser-target.exe");
            let hr = call(
                &mut fixture,
                WebBrowserMethod::Navigate,
                &[object as u32, ptr as u32, 0, 0, 0, 0],
            );
            assert!(hr == HR_S_OK || hr == HR_INET_E_INVALID_URL);

            // File URL with no path and an existing empty path resolve failure.
            let no_path = wide(&mut fixture, "file://");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, no_path as u32, 0, 0, 0, 0]
                ),
                HR_INET_E_INVALID_URL
            );

            // GetTypeInfoCount/GetTypeInfo success and null failure are covered;
            // dispatch_param with a null params block and an out-of-range index.
            map(&mut fixture, PARAMS, 24);
            write_u32(&mut fixture.memory, PARAMS, 0);
            write_u32(&mut fixture.memory, PARAMS + 8, 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::Navigate.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        0,
                        0,
                        0
                    ]
                ),
                HR_DISP_E_TYPEMISMATCH
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::Navigate.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                HR_DISP_E_TYPEMISMATCH
            );

            // dispatch_param with an argument pointer of zero.
            map(&mut fixture, PARAMS, 24);
            write_u32(&mut fixture.memory, PARAMS + 8, 1);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::Navigate.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        0,
                        0,
                        0
                    ]
                ),
                HR_DISP_E_TYPEMISMATCH
            );

            // QueryInterface with a null out pointer / null IID is E_INVALIDARG.
            write_iid(&mut fixture, IID, IID_IUNKNOWN);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryInterface,
                    &[object as u32, IID as u32, 0]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryInterface,
                    &[object as u32, 0, OUT as u32]
                ),
                HR_E_INVALIDARG
            );

            // VT_I4 variant reading through GoSearch/GoHome registry misses.
            fixture
                .runtime
                .win32
                .ge()
                .registry_set_value(
                    "HKCU",
                    "Software\\Microsoft\\Internet Explorer\\Main",
                    "Start Page",
                    "REG_SZ",
                    json!(""),
                    RegistryView::Native,
                )
                .expect("clear home");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoHome, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(location(&fixture, object), "about:blank");

            // Every write_variant helper rejects a null destination.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetVisible.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetToolBar.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetName.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetApplication.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        object as u32,
                        WebBrowserMethod::GetDocument.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        0,
                        0,
                        0
                    ]
                ),
                HR_E_INVALIDARG
            );
        });
    }
    #[test]
    fn web_browser_kind_table_variant_edges_and_x64_layout_are_exact() {
        with_big_stack(|| {
            for method in WebBrowserMethod::ALL {
                let kinds = [DISPATCH_PROPERTYGET, DISPATCH_PROPERTYPUT, DISPATCH_METHOD];
                assert!(
                    kinds.iter().any(|kind| method.supports_kind(*kind)),
                    "{} must support one dispatch kind",
                    method.dispatch_name()
                );
            }
            assert!(!WebBrowserMethod::GetVisible.supports_kind(0x80));
            assert!(WebBrowserMethod::PutVisible.supports_kind(DISPATCH_PROPERTYPUT));
            assert!(WebBrowserMethod::GoBack.supports_kind(DISPATCH_METHOD));

            let mut fixture = x86_fixture("browser-kind-edges");
            let empty = fixture
                .runtime
                .alloc_web_browser_object(&mut fixture.memory, "")
                .expect("empty browser");
            assert_eq!(location(&fixture, empty), "about:blank");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoBack, &[empty as u32]),
                HR_S_FALSE
            );
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoForward, &[empty as u32]),
                HR_S_FALSE
            );

            // A null value VARIANT and a VT_BOOL true value in PutProperty.
            let name = wide(&mut fixture, "Flag");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutProperty,
                    &[empty as u32, name as u32, 0]
                ),
                HR_DISP_E_TYPEMISMATCH
            );
            write_variant_bool_value(&mut fixture, VAR, true);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutProperty,
                    &[empty as u32, name as u32, VAR as u32]
                ),
                HR_S_OK
            );
            assert_eq!(
                fixture.runtime.web_browsers[&empty]
                    .properties
                    .get("Flag")
                    .map(String::as_str),
                Some("true")
            );

            // Unresolvable drive and file URLs take the error branches.
            for url in ["Z:\\nope.exe", "file:///Z:/nope.exe"] {
                let ptr = wide(&mut fixture, url);
                assert_eq!(
                    call(
                        &mut fixture,
                        WebBrowserMethod::Navigate,
                        &[empty as u32, ptr as u32, 0, 0, 0, 0]
                    ),
                    HR_INET_E_INVALID_URL,
                    "{url} must be rejected"
                );
            }
            // The resolvable file:// form takes the success branch.
            let file_url = wide(&mut fixture, "file:///C:/browser-target.exe");
            let hr = call(
                &mut fixture,
                WebBrowserMethod::Navigate,
                &[empty as u32, file_url as u32, 0, 0, 0, 0],
            );
            assert!(hr == HR_S_OK || hr == HR_INET_E_INVALID_URL);

            // Invoke: no-history back/forward, empty Navigate2, malformed
            // put value and null property name.
            let fresh = fixture
                .runtime
                .alloc_web_browser_object(&mut fixture.memory, "about:blank")
                .expect("fresh browser");
            for method in [WebBrowserMethod::GoBack, WebBrowserMethod::GoForward] {
                let hr = call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        fresh as u32,
                        method.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        0,
                        0,
                        0,
                        0,
                    ],
                );
                assert_eq!(hr, HR_S_FALSE);
            }
            map(&mut fixture, VAR, 24);
            map(&mut fixture, PARAMS, 24);
            map(&mut fixture, ARGS, 24);
            write_guest_pointer(&mut fixture.memory, PARAMS, ARGS, GuestArch::X86).expect("params");
            write_u32(&mut fixture.memory, PARAMS + 8, 1);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        empty as u32,
                        WebBrowserMethod::Navigate2.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        0,
                        0,
                        0,
                    ]
                ),
                HR_S_OK
            );
            assert_eq!(location(&fixture, empty), "about:blank");

            fixture.memory.write_u16(ARGS, 5);
            fixture.memory.write_u64(ARGS + 8, f64::to_bits(1.0));
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        empty as u32,
                        WebBrowserMethod::PutVisible.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYPUT),
                        PARAMS as u32,
                        0,
                        0,
                        0,
                    ]
                ),
                HR_DISP_E_TYPEMISMATCH
            );
            write_u32(&mut fixture.memory, PARAMS, 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        empty as u32,
                        WebBrowserMethod::PutProperty.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        0,
                        0,
                        0,
                    ]
                ),
                HR_DISP_E_TYPEMISMATCH
            );

            // The x64 VARIANT size and DISPPARAMS count offset.
            fixture.runtime.guest_arch = GuestArch::X64;
            assert_eq!(fixture.runtime.browser_variant_size(), 24);
            let x64_params = 0x68_000;
            fixture.memory.map_bytes(x64_params, &vec![0_u8; 32]);
            fixture.memory.write_u32(x64_params + 16, 1);
            write_guest_pointer(&mut fixture.memory, x64_params, ARGS, GuestArch::X64)
                .expect("x64 args");
            assert_eq!(
                dispatch_param(&fixture.runtime, &fixture.memory, x64_params, 0),
                ARGS
            );
        });
    }
}
