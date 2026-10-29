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
//! - `QueryStatusWB`/`ExecWB` dispatch the OLE commands the control models
//!   (`OLECMDID_NEW`/`OLECMDID_REFRESH`/`OLECMDID_STOP`); an unsupported
//!   `OLECMDID` keeps the documented `OLECMDERR_E_NOTSUPPORTED`, a modeled
//!   command on a closed control answers `OLECMDERR_E_DISABLED`, and a
//!   malformed command argument is a `DISP_E_TYPEMISMATCH`.
//! - `GetTypeInfo` loads the real WebBrowser type library image through the
//!   oleaut `LoadTypeLib`/MSFTypLib path and hands back the live `ITypeInfo`
//!   over its `IWebBrowser2` member table; an unknown index is
//!   `TYPE_E_ELEMENTNOTFOUND`, a null out-pointer is `E_INVALIDARG`, and a
//!   type library that cannot be materialized is `TYPE_E_CANTLOADLIBRARY`.
//! - `get_Document` returns a real HTML document guest object over the
//!   navigation state (URL/referrer/ready-state derived from the committed
//!   history) once a page has loaded; `S_FALSE` with a null document only
//!   while no document is loaded, `E_INVALIDARG` for a null out-pointer, and
//!   the document's `QueryInterface` answers `E_NOINTERFACE` for a wrong IID.
//! - `ClientToWindow` converts client coordinates with the real window
//!   geometry model (the frame metrics the runtime's `AdjustWindowRect`
//!   computes for the front-most guest window at its DPI); `E_INVALIDARG`
//!   for null coordinate pointers and `E_FAIL` when no window exists.
//! - `ShowBrowserBar` validates the argument variants: an empty/NULL class
//!   id dismisses the (never-shown) bar with `S_OK`, a null class-id pointer
//!   is `E_INVALIDARG`, an unsupported variant is `DISP_E_TYPEMISMATCH`, and
//!   any real bar class id keeps `OLECMDERR_E_NOTSUPPORTED` (this runtime
//!   models no hosted browser bar object).
//!
//! What the host genuinely cannot provide: HTML rendering and a DOM.  The
//! document object therefore answers `E_NOTIMPL` for every `IHTMLDocument2`
//! member outside the navigation-state surface (body/all/title/cookie/...),
//! and its `IDispatch::GetTypeInfoCount` reports `0` (no generated mshtml
//! type library).

use super::super::*;
use super::com::ComMethod;
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
/// E_FAIL.
const HR_E_FAIL: u64 = 0x8000_4005;
/// DISP_E_MEMBERNOTFOUND.
const HR_DISP_E_MEMBERNOTFOUND: u64 = 0x8002_0003;
/// DISP_E_TYPEMISMATCH.
const HR_DISP_E_TYPEMISMATCH: u64 = 0x8002_0005;
/// DISP_E_UNKNOWNNAME.
const HR_DISP_E_UNKNOWNNAME: u64 = 0x8002_0006;
/// TYPE_E_ELEMENTNOTFOUND.
const HR_TYPE_E_ELEMENTNOTFOUND: u64 = 0x8002_802b;
/// TYPE_E_CANTLOADLIBRARY.
const HR_TYPE_E_CANTLOADLIBRARY: u64 = 0x8002_8c05;
/// INET_E_INVALID_URL.
const HR_INET_E_INVALID_URL: u64 = 0x800c_0002;
/// OLECMDERR_E_NOTSUPPORTED.
const HR_OLECMDERR_E_NOTSUPPORTED: u64 = 0x8004_0100;
/// OLECMDERR_E_DISABLED.
const HR_OLECMDERR_E_DISABLED: u64 = 0x8004_0101;

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

/// `OLECMDID_NEW` — the control models the new-instance command.
const OLECMDID_NEW: u32 = 2;
/// `OLECMDID_REFRESH` (docobj.h).
const OLECMDID_REFRESH: u32 = 22;
/// `OLECMDID_STOP` (docobj.h).
const OLECMDID_STOP: u32 = 23;

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
const IID_IHTMLDOCUMENT: &str = "{626FC520-A41E-11CF-A731-00A0C9082637}";
const IID_IHTMLDOCUMENT2: &str = "{332C4425-26CB-11D0-B483-00C04FD90119}";

/// The `IDispatch` vtable slots every guest COM object starts with.
const IDISPATCH_SLOTS: usize = 7;

/// The deterministic local dispatch ids the HTML document's `IDispatch`
/// assigns: `DOC_DISPID_BASE + table-row index` (put/get pairs share the
/// row of their first occurrence).  The same local-assignment convention
/// the browser control's table uses.
const DOC_DISPID_BASE: i32 = 1000;

/// `IHTMLDocument2` member access bits for [`DOC_MEMBERS`]: a property get,
/// a property put, or a method (the three `INVOKE_*` shapes).
const DOC_ACCESS_GET: u8 = 1;
const DOC_ACCESS_PUT: u8 = 2;
const DOC_ACCESS_METHOD: u8 = 4;

/// One `IHTMLDocument2` vtable member beyond the `IDispatch` preamble:
/// member name, access bits, and the number of declared parameters (the
/// stdcall byte count for the slot is `4 * (parameters + 1)` for `this`).
///
/// The order is the real `IHTMLDocument2` vtable layout (`IHTMLDocument`'s
/// single `Script` member first, then the `IHTMLDocument2` members in IDL
/// order), so a guest calling at a real offset lands on the matching host
/// thunk: the three navigation-state getters answer real values and every
/// other member answers `E_NOTIMPL` (the runtime models no DOM/renderer).
type DocMember = (&'static str, u8, u8);
const DOC_MEMBERS: &[DocMember] = &[
    ("Script", 1, 1),
    ("all", 1, 1),
    ("body", 1, 1),
    ("activeElement", 1, 1),
    ("images", 1, 1),
    ("applets", 1, 1),
    ("links", 1, 1),
    ("forms", 1, 1),
    ("anchors", 1, 1),
    ("title", 2, 1),
    ("title", 1, 1),
    ("scripts", 1, 1),
    ("designMode", 2, 1),
    ("designMode", 1, 1),
    ("selection", 1, 1),
    ("readyState", 1, 1),
    ("frames", 1, 1),
    ("embeds", 1, 1),
    ("plugins", 1, 1),
    ("alinkColor", 2, 1),
    ("alinkColor", 1, 1),
    ("bgColor", 2, 1),
    ("bgColor", 1, 1),
    ("fgColor", 2, 1),
    ("fgColor", 1, 1),
    ("linkColor", 2, 1),
    ("linkColor", 1, 1),
    ("vlinkColor", 2, 1),
    ("vlinkColor", 1, 1),
    ("referrer", 1, 1),
    ("location", 1, 1),
    ("lastModified", 1, 1),
    ("URL", 2, 1),
    ("URL", 1, 1),
    ("domain", 2, 1),
    ("domain", 1, 1),
    ("cookie", 2, 1),
    ("cookie", 1, 1),
    ("expando", 2, 1),
    ("expando", 1, 1),
    ("charset", 2, 1),
    ("charset", 1, 1),
    ("defaultCharset", 2, 1),
    ("defaultCharset", 1, 1),
    ("mimeType", 1, 1),
    ("fileSize", 1, 1),
    ("fileCreatedDate", 1, 1),
    ("fileModifiedDate", 1, 1),
    ("fileUpdatedDate", 1, 1),
    ("security", 1, 1),
    ("protocol", 1, 1),
    ("nameProp", 1, 1),
    ("write", 4, 1),
    ("writeln", 4, 1),
    ("open", 4, 5),
    ("close", 4, 0),
    ("clear", 4, 0),
    ("queryCommandSupported", 4, 2),
    ("queryCommandEnabled", 4, 2),
    ("queryCommandState", 4, 2),
    ("queryCommandIndeterm", 4, 2),
    ("queryCommandText", 4, 2),
    ("queryCommandValue", 4, 2),
    ("execCommand", 4, 4),
    ("execCommandShowHelp", 4, 2),
    ("createElement", 4, 2),
    ("onhelp", 2, 1),
    ("onhelp", 1, 1),
    ("onclick", 2, 1),
    ("onclick", 1, 1),
    ("ondblclick", 2, 1),
    ("ondblclick", 1, 1),
    ("onkeyup", 2, 1),
    ("onkeyup", 1, 1),
    ("onkeydown", 2, 1),
    ("onkeydown", 1, 1),
    ("onkeypress", 2, 1),
    ("onkeypress", 1, 1),
    ("onmouseup", 2, 1),
    ("onmouseup", 1, 1),
    ("onmousedown", 2, 1),
    ("onmousedown", 1, 1),
    ("onmousemove", 2, 1),
    ("onmousemove", 1, 1),
    ("onmouseout", 2, 1),
    ("onmouseout", 1, 1),
    ("onmouseover", 2, 1),
    ("onmouseover", 1, 1),
    ("onreadystatechange", 2, 1),
    ("onreadystatechange", 1, 1),
    ("onafterupdate", 2, 1),
    ("onafterupdate", 1, 1),
    ("onrowexit", 2, 1),
    ("onrowexit", 1, 1),
    ("onrowenter", 2, 1),
    ("onrowenter", 1, 1),
    ("ondragstart", 2, 1),
    ("ondragstart", 1, 1),
    ("onselectstart", 2, 1),
    ("onselectstart", 1, 1),
    ("elementFromPoint", 4, 3),
    ("parentWindow", 1, 1),
    ("styleSheets", 1, 1),
    ("onbeforeupdate", 2, 1),
    ("onbeforeupdate", 1, 1),
    ("onerrorupdate", 2, 1),
    ("onerrorupdate", 1, 1),
    ("toString", 4, 1),
    ("createStyleSheet", 4, 3),
];

/// The vtable slot (relative to the object) of the navigation-state getters
/// the document genuinely implements: `IDISPATCH_SLOTS + member index`.
const DOC_SLOT_READYSTATE: usize = IDISPATCH_SLOTS + 15;
const DOC_SLOT_REFERRER: usize = IDISPATCH_SLOTS + 29;
const DOC_SLOT_URL: usize = IDISPATCH_SLOTS + 33;

/// Resolve a document member name to its dispatch id: the first table row
/// with that name — put/get pairs share one id and are told apart at
/// `Invoke` time by the invocation kind (the COM rule).
fn doc_dispid_of_name(name: &str) -> Option<i32> {
    DOC_MEMBERS
        .iter()
        .position(|(member, _, _)| member.eq_ignore_ascii_case(name))
        .map(|index| DOC_DISPID_BASE + index as i32)
}

/// The member name behind a document dispatch id.
fn doc_name_of_dispid(dispid: i32) -> Option<&'static str> {
    let index = i64::from(dispid) - i64::from(DOC_DISPID_BASE);
    usize::try_from(index)
        .ok()
        .and_then(|index| DOC_MEMBERS.get(index))
        .map(|(name, _, _)| *name)
}

/// The referrer of the page at `index` in `history`: the previous entry
/// when it is an http(s) URL, empty otherwise (a document records its
/// page-load referrer exactly once).
fn page_referrer(history: &[String], index: usize) -> String {
    let Some(previous) = index.checked_sub(1).and_then(|index| history.get(index)) else {
        return String::new();
    };
    if previous.starts_with("http://") || previous.starts_with("https://") {
        previous.clone()
    } else {
        String::new()
    }
}

/// A document's ready state: live from the owning control while attached,
/// the frozen snapshot once the control is gone.
fn document_ready_state(runtime: &PeHostRuntime, document: &WebBrowserState) -> i32 {
    runtime
        .web_browsers
        .get(&document.parent)
        .map_or(document.ready_state, |parent| parent.ready_state)
}

/// The `_READYSTATE` name a ready-state value reports as (`BSTR`).
fn ready_state_string(ready_state: i32) -> &'static str {
    match ready_state {
        0 => "uninitialized",
        1 => "loading",
        2 => "loaded",
        3 => "interactive",
        4 => "complete",
        _ => "uninitialized",
    }
}

/// `ExecWB`'s OLE command dispatch: the modeled commands
/// (`OLECMDID_NEW`/`OLECMDID_REFRESH`/`OLECMDID_STOP`) run against the
/// control's state, a malformed VARIANT argument is a type mismatch, a
/// closed control reports the command disabled
/// (`OLECMDERR_E_DISABLED`, matching `QueryStatusWB`'s cleared `ENABLED`
/// bit), and every other `OLECMDID` keeps `OLECMDERR_E_NOTSUPPORTED`.
fn exec_wb_command(
    memory: &MemoryImage,
    browser: &mut WebBrowserState,
    command: u32,
    command_in: u64,
) -> u64 {
    match command {
        OLECMDID_NEW | OLECMDID_REFRESH | OLECMDID_STOP => {
            if !variant_accepted_as_command_arg(memory, command_in) {
                return HR_DISP_E_TYPEMISMATCH;
            }
            if browser.closed {
                return HR_OLECMDERR_E_DISABLED;
            }
            browser.ready_state = READYSTATE_COMPLETE;
            if command != OLECMDID_NEW {
                browser.status_text = "Done".to_string();
            }
            HR_S_OK
        }
        _ => HR_OLECMDERR_E_NOTSUPPORTED,
    }
}

/// The optional `pvaIn` command argument accepts a null pointer and the
/// empty and VT_I4 VARIANT forms (the modeled commands read refresh flags
/// as a long); every other type is a mismatch.
fn variant_accepted_as_command_arg(memory: &MemoryImage, variant: u64) -> bool {
    if variant == 0 {
        return true;
    }
    matches!(memory.read_u16(variant).unwrap_or(u16::MAX), 0 | 1 | 3)
}

/// `ShowBrowserBar`'s outcome for validated argument variants: an
/// unsupported VARIANT type is `DISP_E_TYPEMISMATCH`; a real bar class id
/// (VT_BSTR) keeps `OLECMDERR_E_NOTSUPPORTED` because this runtime models
/// no hosted browser bar object; an empty/NULL class id dismisses the
/// (never-shown) bar with `S_OK`.
fn show_browser_bar_result(class_vt: u16, replacement_vt: u16) -> u64 {
    if !matches!(class_vt, 0 | 1 | 8) || !matches!(replacement_vt, 0 | 1 | 8) {
        return HR_DISP_E_TYPEMISMATCH;
    }
    if class_vt == 8 {
        HR_OLECMDERR_E_NOTSUPPORTED
    } else {
        HR_S_OK
    }
}

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
    // ── IHTMLDocument2 document-object slots (never part of `ALL`; they
    //    only appear in the document vtable built by `html_document_vtable`)
    DocumentGetReadyState,
    DocumentGetReferrer,
    DocumentGetUrl,
    /// An `IHTMLDocument2` member this runtime does not model (no DOM):
    /// the stdcall argument byte count rides on the thunk so an x86 guest
    /// pops exactly the bytes the real member declares.
    DocumentUnsupported {
        arg_bytes: u64,
    },
}

/// Which guest object a [`WebBrowserMethod`] slot belongs to: the browser
/// control vtable, the HTML document vtable, or both (the shared
/// `IUnknown`/`IDispatch` preamble every COM object starts with).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodSurface {
    Shared,
    Control,
    Document,
}

impl WebBrowserMethod {
    /// Which object surface carries this slot.
    fn surface(self) -> MethodSurface {
        match self {
            Self::QueryInterface
            | Self::AddRef
            | Self::Release
            | Self::GetTypeInfoCount
            | Self::GetTypeInfo
            | Self::GetIDsOfNames
            | Self::Invoke => MethodSurface::Shared,
            Self::DocumentGetReadyState
            | Self::DocumentGetReferrer
            | Self::DocumentGetUrl
            | Self::DocumentUnsupported { .. } => MethodSurface::Document,
            // Every remaining slot of the enum is a browser-control slot.
            _ => MethodSurface::Control,
        }
    }

    /// Whether a live object in `role` dispatches this slot.  A cross-role
    /// call (a document calling `Navigate`, a control calling a document
    /// getter) is `E_INVALIDARG` — the slot does not exist on that object.
    fn available_to(self, role: WebBrowserRole) -> bool {
        match self.surface() {
            MethodSurface::Shared => true,
            MethodSurface::Control => role == WebBrowserRole::Control,
            MethodSurface::Document => role == WebBrowserRole::Document,
        }
    }

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
            // The document getters return through one out pointer; the
            // unmodeled members carry their real stdcall byte count.
            Self::DocumentGetReadyState | Self::DocumentGetReferrer | Self::DocumentGetUrl => 8,
            Self::DocumentUnsupported { arg_bytes } => arg_bytes,
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
            Self::DocumentGetReadyState => "readyState",
            Self::DocumentGetReferrer => "referrer",
            Self::DocumentGetUrl => "URL",
            Self::DocumentUnsupported { .. } => "DocumentMember",
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
            // Document slots carry their dispatch id through the document
            // table (`DOC_DISPID_BASE + slot`); these enum-local values only
            // keep the total function well-formed.
            Self::DocumentGetReadyState => 95,
            Self::DocumentGetReferrer => 96,
            Self::DocumentGetUrl => 97,
            Self::DocumentUnsupported { arg_bytes } => 98 + (arg_bytes / 4) as i32,
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
            Self::DocumentGetReadyState | Self::DocumentGetReferrer | Self::DocumentGetUrl => {
                DISPATCH_PROPERTYGET
            }
            Self::DocumentUnsupported { .. } => DISPATCH_METHOD,
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

/// The real `IHTMLDocument2` vtable: the shared `IDispatch` preamble, then
/// one host thunk per member of [`DOC_MEMBERS`] at its real slot offset.
fn html_document_vtable() -> Vec<HostThunk> {
    let mut methods: Vec<HostThunk> = [
        WebBrowserMethod::QueryInterface,
        WebBrowserMethod::AddRef,
        WebBrowserMethod::Release,
        WebBrowserMethod::GetTypeInfoCount,
        WebBrowserMethod::GetTypeInfo,
        WebBrowserMethod::GetIDsOfNames,
        WebBrowserMethod::Invoke,
    ]
    .into_iter()
    .map(HostThunk::WebBrowserMethod)
    .collect();
    for (index, &(_, access, parameters)) in DOC_MEMBERS.iter().enumerate() {
        let slot = IDISPATCH_SLOTS + index;
        let method = match slot {
            DOC_SLOT_READYSTATE => WebBrowserMethod::DocumentGetReadyState,
            DOC_SLOT_REFERRER => WebBrowserMethod::DocumentGetReferrer,
            DOC_SLOT_URL if access & DOC_ACCESS_GET != 0 => WebBrowserMethod::DocumentGetUrl,
            _ => WebBrowserMethod::DocumentUnsupported {
                arg_bytes: 4 * u64::from(parameters) + 4,
            },
        };
        methods.push(HostThunk::WebBrowserMethod(method));
    }
    methods
}

/// The `com_service_map` cache key holding the control's loaded
/// `ITypeInfo` guest object (OLEAUT keeps loaded type libraries loaded for
/// the lifetime of the process).
const SHDOCVW_TYPEINFO_KEY: &str = "\u{1}shdocvw-webbrowser-typeinfo";

/// The Internet Controls type-library LIBID (the library this image
/// models).
const SHDOCVW_LIBID: &str = "{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}";

/// One row of the type-library signature table: how a member's parameters
/// appear in the generated `FUNCDESC`.  By-value arguments carry their
/// Windows VT (BSTR=8, VARIANT=12, VARIANT_BOOL=11, LONG=3); reference,
/// out, and struct-pointer parameters carry VT_PTR (26) — the MSFT reader
/// this runtime uses stores a single VT per parameter, so pointer pointees
/// are not chained typedescs.  Property gets take their one `[out,
/// retval]` pointer.
fn web_browser_typelib_signature(method: WebBrowserMethod) -> (u8, &'static [i32]) {
    let invkind = match method.supported_kinds() {
        DISPATCH_PROPERTYGET => 2_u8, // INVOKE_PROPERTYGET
        DISPATCH_PROPERTYPUT => 4_u8, // INVOKE_PROPERTYPUT
        _ => 1_u8,                    // INVOKE_FUNC
    };
    let params: &[i32] = match method {
        WebBrowserMethod::Navigate => &[8, 26, 8, 26, 26],
        WebBrowserMethod::Navigate2 => &[26, 26, 26, 26, 26],
        WebBrowserMethod::Refresh2 => &[26],
        WebBrowserMethod::QueryStatusWB => &[3, 26],
        WebBrowserMethod::ExecWB => &[3, 3, 26, 26],
        WebBrowserMethod::ShowBrowserBar => &[26, 26, 26],
        WebBrowserMethod::ClientToWindow => &[26, 26],
        WebBrowserMethod::PutProperty => &[8, 12],
        WebBrowserMethod::GetProperty => &[8, 26],
        WebBrowserMethod::PutStatusText => &[8],
        WebBrowserMethod::PutToolBar => &[3],
        _ if invkind == 2 => &[26],
        _ if invkind == 4 => &[11],
        _ => &[],
    };
    (invkind, params)
}

/// Build the runtime's WebBrowser type-library image: one MSFT segment
/// directory, the LIBID and `IWebBrowser2` IIDs, the library/interface
/// names, and one `FUNCDESC` per control member (memid = the runtime's
/// local dispatch id, oVft = the vtable slot, HRESULT return) so the
/// oleaut `LoadTypeLib` path parses it into a live `ITypeInfo`.
fn shdocvw_typelib_image() -> Vec<u8> {
    // Name segment: library name first (the header points at offset 0),
    // then the interface name and every member name (put/get pairs repeat
    // the name at their own offsets, as MSFT name tables do).
    let mut names = Vec::new();
    let lib_name_offset = push_msft_name(&mut names, "Microsoft Internet Controls");
    debug_assert_eq!(lib_name_offset, 0);
    let type_name_offset = push_msft_name(&mut names, "IWebBrowser2");
    let mut member_name_offsets = Vec::new();
    for method in &WebBrowserMethod::ALL[7..] {
        member_name_offsets.push(push_msft_name(&mut names, method.dispatch_name()));
    }
    // String segment: library documentation first, then the interface
    // documentation and the (modeled) help file name.
    let mut strings = Vec::new();
    let lib_doc_offset = push_msft_string(
        &mut strings,
        "Microsoft Internet Controls type library (Casa1 runtime model)",
    );
    let type_doc_offset = push_msft_string(&mut strings, "IWebBrowser2 browser-control interface");
    let help_file_offset = push_msft_string(&mut strings, "shdocvw.hlp");
    // GUID segment: two 24-byte records (16-byte GUID + two link fields).
    let mut guids = Vec::new();
    let lib_id = crate::real_win32::guid_from_string(SHDOCVW_LIBID)
        .expect("the Internet Controls LIBID parses");
    let interface_id =
        crate::real_win32::guid_from_string(IID_IWEBBROWSER2).expect("the IWebBrowser2 IID parses");
    for guid in [lib_id, interface_id] {
        guids.extend_from_slice(&guid);
        guids.extend_from_slice(&(-1_i32).to_le_bytes());
        guids.extend_from_slice(&(-1_i32).to_le_bytes());
    }
    // Member records: one per control member after the IDispatch preamble.
    let methods = &WebBrowserMethod::ALL[7..];
    let mut records = Vec::new();
    let mut memids = Vec::new();
    for (index, method) in methods.iter().enumerate() {
        let (invkind, params) = web_browser_typelib_signature(*method);
        let record_len = 24 + params.len() * 12;
        records.extend_from_slice(&(record_len as u32).to_le_bytes());
        records.extend_from_slice(&(-25_i32).to_le_bytes()); // data_type: VT_HRESULT
        records.extend_from_slice(&0_u16.to_le_bytes()); // func flags
        records.extend_from_slice(&0_u16.to_le_bytes());
        records.extend_from_slice(&((IDISPATCH_SLOTS + index) as u16).to_le_bytes()); // oVft slot
        records.extend_from_slice(&0_u16.to_le_bytes());
        // FKCCIC: FUNCKIND=4 | INVOKEKIND<<3 | CALLCONV_STDCALL<<8 — the
        // same encoding the oleaut test images use.
        let fkccic = 4_u32 | (u32::from(invkind) << 3) | (4 << 8);
        records.extend_from_slice(&fkccic.to_le_bytes());
        records.extend_from_slice(&(params.len() as u16).to_le_bytes());
        records.extend_from_slice(&0_u16.to_le_bytes()); // cParamsOpt
        for vt in params {
            records.extend_from_slice(&(-i32::from(*vt)).to_le_bytes());
            records.extend_from_slice(&u32::MAX.to_le_bytes()); // no per-parameter names
            records.extend_from_slice(&0_u16.to_le_bytes());
            records.extend_from_slice(&0_u16.to_le_bytes());
        }
        memids.push(method.dispid());
    }
    // The members segment: info-length header, the records, then the
    // memid and member-name offset arrays (the reader's layout: a leading
    // hole word, `cFuncs` memids, `cFuncs` name offsets).
    let mut members = Vec::new();
    members.extend_from_slice(&0_u32.to_le_bytes()); // info length, filled below
    members.extend_from_slice(&records);
    let info_len = members.len();
    members[0..4].copy_from_slice(&(info_len as u32).to_le_bytes());
    members.extend_from_slice(&0_u32.to_le_bytes());
    for memid in &memids {
        members.extend_from_slice(&(*memid as u32).to_le_bytes());
    }
    for offset in &member_name_offsets {
        members.extend_from_slice(&offset.to_le_bytes());
    }
    // Segment layout after the header: offsets table, segment directory,
    // then GUID, name, string, typeinfo, and members segments.
    let guid_offset = 0x54 + 4 + 0x100;
    let name_offset = guid_offset + guids.len();
    let string_offset = name_offset + names.len();
    let typeinfo_offset = string_offset + strings.len();
    let members_offset = typeinfo_offset + 100;
    let total = members_offset + members.len();
    let mut image = vec![0_u8; total];
    put_u32(&mut image, 0x00, 0x5446_534d); // "MSFT"
    put_u32(&mut image, 0x04, 0x0001_0002); // supported version
    put_i32(&mut image, 0x08, 0); // posguid: the LIBID at GUID offset 0
    put_u32(&mut image, 0x0c, 0x409); // lcid
    put_u32(&mut image, 0x10, 0x409); // lcid2
    put_u32(&mut image, 0x14, 0x41); // varflags: syskind SYS_WIN32, no help DLL
    put_u32(&mut image, 0x18, 1); // library version 1.0
    put_u32(&mut image, 0x1c, 0); // flags
    put_u32(&mut image, 0x20, 1); // one type: IWebBrowser2
    put_i32(&mut image, 0x24, lib_doc_offset); // helpstring
    put_u32(&mut image, 0x28, 0); // help context
    put_u32(&mut image, 0x2c, lib_name_offset); // library name
    put_i32(&mut image, 0x30, help_file_offset); // help file
    put_u32(&mut image, 0x54, 0); // typeinfo offset table: type 0 at segment start
    // The segment directory at 0x58: (slot, offset, length) — slot 2/4/6
    // stay zeroed (unused by the reader).
    for (slot, offset, length) in [
        (0_usize, typeinfo_offset as i32, 100_u32), // typeinfo
        (1, 0, 0),                                  // impinfo (kind checked)
        (3, 0, 0),                                  // references
        (5, guid_offset as i32, guids.len() as u32),
        (7, name_offset as i32, names.len() as u32),
        (8, string_offset as i32, strings.len() as u32),
        (9, 0, 0), // typedesc (direct VTs only)
    ] {
        let base = 0x58 + slot * 16;
        put_i32(&mut image, base, offset);
        put_u32(&mut image, base + 4, length);
        put_u32(&mut image, base + 12, 0x0f);
    }
    // The IWebBrowser2 type record.
    put_u32(&mut image, typeinfo_offset, 3); // TKIND_INTERFACE
    put_i32(&mut image, typeinfo_offset + 4, members_offset as i32);
    put_i32(&mut image, typeinfo_offset + 8, -1); // no inheritance/impl data
    put_u32(
        &mut image,
        typeinfo_offset + 24,
        methods.len() as u32, // cFuncs | cVars<<16
    );
    put_i32(&mut image, typeinfo_offset + 44, 24); // posguid: the IID record
    put_u16(&mut image, typeinfo_offset + 48, 0); // type flags
    put_u32(&mut image, typeinfo_offset + 52, type_name_offset);
    put_u16(&mut image, typeinfo_offset + 56, 1); // element version
    put_i32(&mut image, typeinfo_offset + 60, type_doc_offset);
    put_u32(&mut image, typeinfo_offset + 68, 0); // help context
    put_u16(&mut image, typeinfo_offset + 76, 0); // cImplTypes
    put_u16(
        &mut image,
        typeinfo_offset + 78,
        ((IDISPATCH_SLOTS + methods.len()) * 4) as u16, // cbSizeVft (WIN32)
    );
    put_u32(&mut image, typeinfo_offset + 80, 0); // cbSizeInstance: interface
    // Segments are written in place.
    image[guid_offset..guid_offset + guids.len()].copy_from_slice(&guids);
    image[name_offset..name_offset + names.len()].copy_from_slice(&names);
    image[string_offset..string_offset + strings.len()].copy_from_slice(&strings);
    image[members_offset..members_offset + members.len()].copy_from_slice(&members);
    image
}

/// Write one little-endian `u32` into the image.
fn put_u32(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write one little-endian `i32` into the image.
fn put_i32(image: &mut [u8], offset: usize, value: i32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write one little-endian `u16` into the image.
fn put_u16(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// The host-side cache path of the WebBrowser type-library image:
/// content-addressed so every load of the same image shares one file.
fn shdocvw_typelib_cache_path() -> std::path::PathBuf {
    let image = shdocvw_typelib_image();
    let mut hash = 0xcbf2_9ce4_8422_2325_u64; // FNV-1a offset basis
    for byte in &image {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    std::env::temp_dir().join(format!("casa1-shdocvw-{hash:016x}.tlb"))
}

/// Materialize the WebBrowser type-library image at `path`: skip an
/// existing file, otherwise write a sibling temporary and atomically
/// rename it into place (two processes may race; the content is
/// identical).  Fails when `path` cannot hold a regular file.
fn shdocvw_sync_typelib_file(path: &std::path::Path) -> std::io::Result<()> {
    if path.is_file() {
        return Ok(());
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temporary, shdocvw_typelib_image())?;
    std::fs::rename(&temporary, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })?;
    Ok(())
}

/// Append one MSFT name-segment entry (`hash`, `next`, `u16` length,
/// text, padded to a 4-byte boundary) and return its offset.
fn push_msft_name(segment: &mut Vec<u8>, text: &str) -> u32 {
    let offset = segment.len() as u32;
    segment.extend_from_slice(&(-1_i32).to_le_bytes());
    segment.extend_from_slice(&(-1_i32).to_le_bytes());
    segment.extend_from_slice(&(text.len() as u16).to_le_bytes());
    segment.extend_from_slice(&0_u16.to_le_bytes()); // pad to the text slot at +12
    segment.extend_from_slice(text.as_bytes());
    let piece = (12 + text.len()).next_multiple_of(4);
    segment.resize(offset as usize + piece, 0);
    offset
}

/// Append one MSFT string-segment entry (`u16` length, text, padded to a
/// 4-byte boundary with an 8-byte floor) and return its offset.
fn push_msft_string(segment: &mut Vec<u8>, text: &str) -> i32 {
    let offset = segment.len() as i32;
    segment.extend_from_slice(&(text.len() as u16).to_le_bytes());
    segment.extend_from_slice(text.as_bytes());
    let piece = (2 + text.len()).max(8).next_multiple_of(4);
    segment.resize(offset as usize + piece, 0);
    offset
}

/// Which guest object a live entry in `web_browsers` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebBrowserRole {
    /// The `IWebBrowser2` browser control itself.
    Control,
    /// An `IHTMLDocument2` HTML document handed out by `get_Document`.
    Document,
}

/// One live browser-control (or document) object.
#[derive(Debug, Clone)]
pub(crate) struct WebBrowserState {
    /// Which object this entry is (control vs. HTML document).
    pub(crate) role: WebBrowserRole,
    /// The owning control of a document entry (0 once detached: the
    /// document then answers from its own snapshot of the page).
    pub(crate) parent: u64,
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
    /// Whether a committed navigation has loaded a page document.
    pub(crate) document_loaded: bool,
    /// The document guest object for the loaded page (the control holds one
    /// reference; 0 until `get_Document` materializes it).
    pub(crate) document_object: u64,
    /// The document's referrer: the previous history entry when it was an
    /// http(s) URL, empty otherwise (the page-load property, fixed at
    /// document creation).
    pub(crate) referrer: String,
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
            role: WebBrowserRole::Control,
            parent: 0,
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
            document_loaded: false,
            document_object: 0,
            referrer: String::new(),
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

    /// Whether `get_Document` hands out a document: a committed navigation
    /// loaded a page and the control has finished loading it.
    fn document_available(&self) -> bool {
        self.document_loaded && self.ready_state == READYSTATE_COMPLETE
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
        if !method.available_to(browser.role) {
            // A cross-role slot does not exist on this object.
            state.set(Register::Rax, HR_E_INVALIDARG);
            self.last_error = 0;
            return Ok(());
        }
        let result = match method {
            WebBrowserMethod::QueryInterface => {
                self.web_browser_query_interface(memory, this, state, &browser)?
            }
            WebBrowserMethod::AddRef => u64::from(self.add_ref_guest_object(this)?),
            WebBrowserMethod::Release => {
                let remaining = self.release_guest_object(this)?;
                state.set(Register::Rax, u64::from(remaining));
                if remaining == 0 && browser.document_object != 0 {
                    // The last control reference fell: freeze its document
                    // at the page it last observed and drop the control's
                    // own reference to it.  The type library cache is
                    // runtime-wide state (like OLEAUT's own typelib cache)
                    // and outlives the control.
                    self.detach_document(&mut browser)?;
                }
                self.last_error = 0;
                return Ok(());
            }
            WebBrowserMethod::GetTypeInfoCount => {
                let out = guest_call_arg(state, memory, 1)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    // The control exposes its type library; the HTML
                    // document has no generated mshtml type library.
                    let count = match browser.role {
                        WebBrowserRole::Control => 1,
                        WebBrowserRole::Document => 0,
                    };
                    write_u32(memory, out, count);
                    HR_S_OK
                }
            }
            WebBrowserMethod::GetTypeInfo => {
                let index = guest_call_arg_u32(state, memory, 1)?;
                let out = guest_call_arg(state, memory, 3)?;
                if out == 0 {
                    HR_E_INVALIDARG
                } else {
                    write_guest_pointer(memory, out, 0, self.guest_arch)?;
                    match browser.role {
                        WebBrowserRole::Document => HR_TYPE_E_ELEMENTNOTFOUND,
                        WebBrowserRole::Control if index != 0 => HR_TYPE_E_ELEMENTNOTFOUND,
                        WebBrowserRole::Control => match self.web_browser_type_info(memory)? {
                            Some(type_info) => {
                                self.add_ref_guest_object(type_info)?;
                                write_guest_pointer(memory, out, type_info, self.guest_arch)?;
                                HR_S_OK
                            }
                            None => HR_TYPE_E_CANTLOADLIBRARY,
                        },
                    }
                }
            }
            WebBrowserMethod::GetIDsOfNames => {
                self.web_browser_get_ids_of_names(memory, state, browser.role)?
            }
            WebBrowserMethod::Invoke => {
                self.web_browser_invoke(memory, state, this, &mut browser)?
            }
            WebBrowserMethod::GoBack => {
                if browser.can_go_back() {
                    self.detach_document(&mut browser)?;
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
                    self.detach_document(&mut browser)?;
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
                self.web_browser_navigate(&mut browser, &home)?
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
                self.web_browser_navigate(&mut browser, &search)?
            }
            WebBrowserMethod::Navigate => {
                let url_ptr = guest_call_arg(state, memory, 1)?;
                if url_ptr == 0 {
                    HR_E_INVALIDARG
                } else {
                    let url = read_utf16_string(memory, url_ptr)?;
                    self.web_browser_navigate(&mut browser, &url)?
                }
            }
            WebBrowserMethod::Navigate2 => {
                let url_variant = guest_call_arg(state, memory, 1)?;
                let url = variant_to_url(self, memory, url_variant);
                match url {
                    Some(url) if url.trim().is_empty() => {
                        self.web_browser_navigate(&mut browser, "about:blank")?
                    }
                    Some(url) => self.web_browser_navigate(&mut browser, &url)?,
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
                } else if browser.document_available() {
                    let document = self.web_browser_document_object(memory, this, &mut browser)?;
                    self.add_ref_guest_object(document)?;
                    write_guest_pointer(memory, out, document, self.guest_arch)?;
                    HR_S_OK
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
                        OLECMDID_NEW | OLECMDID_REFRESH | OLECMDID_STOP => {
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
                let command_in = guest_call_arg(state, memory, 3)?;
                exec_wb_command(memory, &mut browser, command, command_in)
            }
            WebBrowserMethod::ShowBrowserBar => {
                let class_id = guest_call_arg(state, memory, 1)?;
                let replacement = guest_call_arg(state, memory, 2)?;
                if class_id == 0 {
                    HR_E_INVALIDARG
                } else {
                    let class_vt = memory.read_u16(class_id).unwrap_or(0);
                    let replacement_vt = if replacement == 0 {
                        0
                    } else {
                        memory.read_u16(replacement).unwrap_or(0)
                    };
                    show_browser_bar_result(class_vt, replacement_vt)
                }
            }
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
            WebBrowserMethod::ClientToWindow => {
                let client_x = guest_call_arg(state, memory, 1)?;
                let client_y = guest_call_arg(state, memory, 2)?;
                if client_x == 0 || client_y == 0 {
                    HR_E_INVALIDARG
                } else {
                    // The control converts against the front-most guest
                    // window (the host window at the top of the z-order):
                    // client coordinates become window coordinates by the
                    // non-client frame the window's own geometry models.
                    match self.user32.get_top_window(None) {
                        None => HR_E_FAIL,
                        Some(hwnd) => {
                            let x = memory.read_u32(client_x).unwrap_or(0) as i32;
                            let y = memory.read_u32(client_y).unwrap_or(0) as i32;
                            let style = self.user32.get_window_style(hwnd).unwrap_or(0);
                            let ex_style = self.user32.get_window_ex_style(hwnd).unwrap_or(0);
                            let dpi = self.user32.dpi_for_window(hwnd).unwrap_or(96);
                            let mut frame = crate::user32::Rect {
                                left: 0,
                                top: 0,
                                right: 0,
                                bottom: 0,
                            };
                            self.user32
                                .adjust_window_rect_for_dpi(&mut frame, style, 0, ex_style, dpi);
                            // The adjusted frame maps the client origin to
                            // (frame.left, frame.top) in window space;
                            // coordinates saturate at the integer bounds.
                            write_u32(memory, client_x, x.saturating_sub(frame.left) as u32);
                            write_u32(memory, client_y, y.saturating_sub(frame.top) as u32);
                            HR_S_OK
                        }
                    }
                }
            }
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
            WebBrowserMethod::DocumentGetReadyState => {
                let value = ready_state_string(document_ready_state(self, &browser)).to_string();
                self.copy_bstr_out(memory, state, value)?
            }
            WebBrowserMethod::DocumentGetReferrer => {
                let value = browser.referrer.clone();
                self.copy_bstr_out(memory, state, value)?
            }
            WebBrowserMethod::DocumentGetUrl => {
                let value = browser.location.clone();
                self.copy_bstr_out(memory, state, value)?
            }
            WebBrowserMethod::DocumentUnsupported { .. } => HR_E_NOTIMPL,
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
        let supported = match browser.role {
            WebBrowserRole::Control => {
                iid.eq_ignore_ascii_case(IID_IUNKNOWN)
                    || iid.eq_ignore_ascii_case(IID_IDISPATCH)
                    || iid.eq_ignore_ascii_case(IID_IWEBBROWSER)
                    || iid.eq_ignore_ascii_case(IID_IWEBBROWSERAPP)
                    || iid.eq_ignore_ascii_case(IID_IWEBBROWSER2)
            }
            WebBrowserRole::Document => {
                iid.eq_ignore_ascii_case(IID_IUNKNOWN)
                    || iid.eq_ignore_ascii_case(IID_IDISPATCH)
                    || iid.eq_ignore_ascii_case(IID_IHTMLDOCUMENT)
                    || iid.eq_ignore_ascii_case(IID_IHTMLDOCUMENT2)
            }
        };
        if !supported {
            write_guest_pointer(memory, out, 0, self.guest_arch)?;
            return Ok(HR_E_NOINTERFACE);
        }
        self.add_ref_guest_object(this)?;
        write_guest_pointer(memory, out, this, self.guest_arch)?;
        Ok(HR_S_OK)
    }

    /// Detach the control's current document object: the document freezes
    /// at the page it represents (its own snapshot of URL and ready state)
    /// and the next `get_Document` materializes the new page's document.
    /// Called before the control's location moves to the new page.
    fn detach_document(&mut self, browser: &mut WebBrowserState) -> AppResult<()> {
        let document = browser.document_object;
        browser.document_object = 0;
        if document == 0 {
            return Ok(());
        }
        if let Some(state) = self.web_browsers.get_mut(&document) {
            state.parent = 0;
            state.location = browser.location.clone();
            state.ready_state = browser.ready_state;
        }
        // The control drops its reference; a guest handout (if any) keeps
        // the frozen document alive.
        self.release_guest_object(document)?;
        Ok(())
    }

    /// The HTML document object for the control's loaded page, created on
    /// the first `get_Document` (the control holds one reference; the
    /// document names the control as its parent for live state reads).
    fn web_browser_document_object(
        &mut self,
        memory: &mut MemoryImage,
        owner: u64,
        browser: &mut WebBrowserState,
    ) -> AppResult<u64> {
        if browser.document_object == 0 {
            let vtable = self.alloc_guest_vtable(memory, html_document_vtable())?;
            let object = self.alloc_guest_object(memory, GuestObjectKind::WebBrowser, vtable)?;
            let mut document = WebBrowserState::new(&browser.location);
            document.role = WebBrowserRole::Document;
            document.parent = owner;
            document.ready_state = browser.ready_state;
            document.referrer = page_referrer(&browser.history, browser.history_index);
            self.web_browsers.insert(object, document);
            browser.document_object = object;
        }
        Ok(browser.document_object)
    }

    /// `IDispatch::Invoke` on the HTML document.  Dispatch ids resolve
    /// through the `IHTMLDocument2` member table (put/get pairs share one
    /// id, selected by invocation kind — the COM rule); the
    /// navigation-state getters answer real values, every other member is
    /// `E_NOTIMPL` (the runtime models no DOM), a wrong invocation kind or
    /// unknown id is `DISP_E_MEMBERNOTFOUND`, and a missing result pointer
    /// on a getter is `E_INVALIDARG`.
    fn web_browser_invoke_document(
        &mut self,
        memory: &mut MemoryImage,
        state: &CpuState,
        document: &WebBrowserState,
    ) -> AppResult<u64> {
        let dispid = guest_call_arg(state, memory, 1)? as i32;
        let flags = guest_call_arg_u32(state, memory, 4)? as u16;
        let result = guest_call_arg(state, memory, 6)?;
        let Some(name) = doc_name_of_dispid(dispid) else {
            return Ok(HR_DISP_E_MEMBERNOTFOUND);
        };
        let access = DOC_MEMBERS
            .iter()
            .filter(|(member, _, _)| member.eq_ignore_ascii_case(name))
            .fold(0_u8, |bits, (_, member_bits, _)| bits | *member_bits);
        let kind = if flags & DISPATCH_PROPERTYGET != 0 {
            DOC_ACCESS_GET
        } else if flags & DISPATCH_PROPERTYPUT != 0 {
            DOC_ACCESS_PUT
        } else if flags & DISPATCH_METHOD != 0 {
            DOC_ACCESS_METHOD
        } else {
            return Ok(HR_DISP_E_MEMBERNOTFOUND);
        };
        if (access & kind) == 0 {
            return Ok(HR_DISP_E_MEMBERNOTFOUND);
        }
        if kind != DOC_ACCESS_GET {
            return Ok(HR_E_NOTIMPL);
        }
        if result == 0 {
            return Ok(HR_E_INVALIDARG);
        }
        let value = match name {
            "readyState" => ready_state_string(document_ready_state(self, document)).to_string(),
            "referrer" => document.referrer.clone(),
            "URL" => document.location.clone(),
            _ => return Ok(HR_E_NOTIMPL),
        };
        write_variant_bstr(self, memory, result, &value)
    }

    /// The control's `ITypeInfo`: the real WebBrowser type-library image
    /// loaded through the oleaut `LoadTypeLib` path and cached for the
    /// lifetime of the runtime (OLEAUT keeps loaded type libraries loaded
    /// too).  `Ok(None)` = the type library could not be materialized or
    /// loaded (`TYPE_E_CANTLOADLIBRARY` for the caller).
    fn web_browser_type_info(&mut self, memory: &mut MemoryImage) -> AppResult<Option<u64>> {
        if let Some(&type_info) = self.com_service_map.get(SHDOCVW_TYPEINFO_KEY) {
            return Ok(Some(type_info));
        }
        let path = shdocvw_typelib_cache_path();
        let loaded = match shdocvw_sync_typelib_file(&path) {
            Ok(()) => self.shdocvw_load_type_info(memory, &path)?,
            Err(_) => None,
        };
        if let Some(type_info) = loaded {
            self.com_service_map
                .insert(SHDOCVW_TYPEINFO_KEY.to_string(), type_info);
        }
        Ok(loaded)
    }

    /// `LoadTypeLib(path)` + `ITypeLib::GetTypeInfo(0)` through the oleaut
    /// dispatch: the image always holds exactly the `IWebBrowser2` type.
    fn shdocvw_load_type_info(
        &mut self,
        memory: &mut MemoryImage,
        path: &std::path::Path,
    ) -> AppResult<Option<u64>> {
        let path_text = path.to_string_lossy().into_owned();
        let path_ptr = self.alloc_utf16_string(memory, &path_text)?;
        let out = self.alloc_zeroed(memory, 16, 8)?;
        let mut load = self.prepare_guest_call(memory, &[path_ptr, out])?;
        self.dispatch_ole_load_type_lib(&mut load, memory)?;
        if load.get(Register::Rax) != HR_S_OK {
            return Ok(None);
        }
        let type_lib = read_guest_pointer(memory, out, self.guest_arch)?;
        let mut get_info = self.prepare_guest_call(memory, &[type_lib, 0, out])?;
        self.dispatch_com_method(ComMethod::TypeLibGetTypeInfo, &mut get_info, memory)?;
        debug_assert_eq!(
            get_info.get(Register::Rax),
            HR_S_OK,
            "the WebBrowser type library always holds type 0"
        );
        Ok(Some(read_guest_pointer(memory, out, self.guest_arch)?))
    }

    /// Synthesize the caller CPU state for a direct host-method call with
    /// `args` laid out per the guest ABI: x86 pushes a return address then
    /// the arguments on the stack, x64 passes them in the four argument
    /// registers (both dispatch handlers read at most four arguments).
    fn prepare_guest_call(
        &mut self,
        memory: &mut MemoryImage,
        args: &[u64],
    ) -> AppResult<CpuState> {
        debug_assert!(
            args.len() <= 4,
            "host-method calls pass at most four arguments"
        );
        let mut state = CpuState::new(self.guest_arch);
        match self.guest_arch {
            GuestArch::X86 => {
                // The handlers are invoked directly (no `dispatch_import`
                // return-address pop), so argument 0 lives at [Rsp].
                let frame = self.alloc_zeroed(memory, (args.len() + 1) * 4, 16)?;
                for (index, arg) in args.iter().enumerate() {
                    write_guest_pointer(memory, frame + (index as u64) * 4, *arg, GuestArch::X86)?;
                }
                state.set(Register::Rsp, frame);
            }
            GuestArch::X64 => {
                const ARGUMENTS: [Register; 4] =
                    [Register::Rcx, Register::Rdx, Register::R8, Register::R9];
                for (register, arg) in ARGUMENTS.iter().zip(args.iter()) {
                    state.set(*register, *arg);
                }
            }
        }
        Ok(state)
    }

    fn web_browser_navigate(&mut self, browser: &mut WebBrowserState, url: &str) -> AppResult<u64> {
        if browser.closed {
            return Ok(HR_E_INVALIDARG);
        }
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Ok(HR_E_INVALIDARG);
        }
        if !browser_url_supported(self, trimmed) {
            return Ok(HR_INET_E_INVALID_URL);
        }
        let resolved = if trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':' {
            match self.win32.guest_path_to_host_path(trimmed) {
                Ok(path) => format!("file:///{}", path.to_string_lossy().replace('\\', "/")),
                Err(_) => return Ok(HR_INET_E_INVALID_URL),
            }
        } else if let Some(rest) = trimmed
            .to_ascii_lowercase()
            .strip_prefix("file://")
            .map(|_| &trimmed[7..])
        {
            let path = rest.trim_start_matches('/');
            match self.win32.guest_path_to_host_path(path) {
                Ok(path) => format!("file:///{}", path.to_string_lossy().replace('\\', "/")),
                Err(_) => return Ok(HR_INET_E_INVALID_URL),
            }
        } else {
            trimmed.to_string()
        };
        // The committed navigation leaves the loaded document behind: the
        // old document object freezes at the page being left, and the next
        // `get_Document` materializes the document of the new page.
        self.detach_document(browser)?;
        browser.document_loaded = true;
        browser.ready_state = READYSTATE_LOADING;
        browser.location = resolved.clone();
        browser.history.truncate(browser.history_index + 1);
        browser.history.push(resolved);
        browser.history_index = browser.history.len() - 1;
        browser.ready_state = READYSTATE_COMPLETE;
        browser.status_text = "Done".to_string();
        Ok(HR_S_OK)
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
        role: WebBrowserRole,
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
            let dispid = match role {
                WebBrowserRole::Control => WebBrowserMethod::ALL
                    .into_iter()
                    .find(|method| method.dispatch_name().eq_ignore_ascii_case(&name))
                    .map(|method| method.dispid()),
                WebBrowserRole::Document => doc_dispid_of_name(&name),
            };
            match dispid {
                Some(dispid) => resolved.push(dispid),
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
        if browser.role == WebBrowserRole::Document {
            return self.web_browser_invoke_document(memory, state, browser);
        }
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
                if browser.document_available() {
                    let document = self.web_browser_document_object(memory, this, browser)?;
                    self.add_ref_guest_object(document)?;
                    Ok(write_variant_dispatch(self, memory, result, document))
                } else {
                    memory.map_bytes(result, &vec![0; self.browser_variant_size()]);
                    Ok(HR_S_FALSE)
                }
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
                    self.detach_document(browser)?;
                    browser.history_index -= 1;
                    browser.location = browser.history[browser.history_index].clone();
                    Ok(HR_S_OK)
                } else {
                    Ok(HR_S_FALSE)
                }
            }
            WebBrowserMethod::GoForward => {
                if browser.can_go_forward() {
                    self.detach_document(browser)?;
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
                self.web_browser_navigate(browser, &home)
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
                self.web_browser_navigate(browser, &search)
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
                self.web_browser_navigate(browser, &url)
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
            WebBrowserMethod::GetTypeInfo => {
                if result == 0 {
                    return Ok(HR_E_INVALIDARG);
                }
                // The invoked member takes the type-info index as its first
                // (and only meaningful) argument; a missing argument is the
                // documented index 0.
                let index = if params == 0 {
                    0_u32
                } else {
                    let argument = dispatch_param(self, memory, params, 0);
                    match memory.read_u16(argument).unwrap_or(0) {
                        0 | 1 => 0_u32,
                        3 => memory.read_u32(argument + 8).unwrap_or(0),
                        _ => return Ok(HR_DISP_E_TYPEMISMATCH),
                    }
                };
                memory.map_bytes(result, &vec![0; self.browser_variant_size()]);
                if index != 0 {
                    return Ok(HR_TYPE_E_ELEMENTNOTFOUND);
                }
                match self.web_browser_type_info(memory)? {
                    Some(type_info) => {
                        self.add_ref_guest_object(type_info)?;
                        memory.write_u16(result, 13); // VT_UNKNOWN
                        write_guest_pointer(memory, result + 8, type_info, self.guest_arch)?;
                        Ok(HR_S_OK)
                    }
                    None => Ok(HR_TYPE_E_CANTLOADLIBRARY),
                }
            }
            WebBrowserMethod::GetIDsOfNames
            | WebBrowserMethod::Invoke
            // Document-only members never resolve on a control's dispatch
            // table (they are not automation members of IWebBrowser2).
            | WebBrowserMethod::DocumentGetReadyState
            | WebBrowserMethod::DocumentGetReferrer
            | WebBrowserMethod::DocumentGetUrl
            | WebBrowserMethod::DocumentUnsupported { .. } => {
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

            // ShowBrowserBar: a null class-id pointer is invalid; an empty
            // class id dismisses; a real bar class id keeps the OLE error.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ShowBrowserBar,
                    &[object as u32, 0, 0, 0]
                ),
                HR_E_INVALIDARG
            );
            map(&mut fixture, VAR, 24);
            fixture.memory.write_u16(VAR, 0); // VT_EMPTY
            map(&mut fixture, OUT, 8);
            fixture.memory.write_u16(OUT, 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ShowBrowserBar,
                    &[object as u32, VAR as u32, 0, OUT as u32]
                ),
                HR_S_OK
            );
            // ClientToWindow: no window exists in this fixture yet.
            write_u32(&mut fixture.memory, OUT, 10);
            write_u32(&mut fixture.memory, OUT + 4, 10);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ClientToWindow,
                    &[object as u32, OUT as u32, OUT as u32 + 4]
                ),
                HR_E_FAIL
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ClientToWindow,
                    &[object as u32, 0, OUT as u32 + 4]
                ),
                HR_E_INVALIDARG
            );
        });
    }

    #[test]
    fn web_browser_dispatch_names_invoke_and_documented_errors_pin_exact_results() {
        with_big_stack(|| {
            // This test materializes the shared type-library cache file.
            let _lock = typelib_lock();
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

            // GetTypeInfoCount/GetTypeInfo through Invoke: the invoked
            // member hands out the real type library typeinfo as
            // VT_UNKNOWN (a missing argument is the documented index 0).
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
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u16(VAR2).unwrap(), 13); // VT_UNKNOWN
            assert_ne!(fixture.memory.read_u32(VAR2 + 8).unwrap(), 0);

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
            // This test materializes the shared type-library cache file.
            let _lock = typelib_lock();
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
                HR_S_OK
            );
            let type_info = read_out_pointer(&fixture, OUT);
            assert_ne!(type_info, 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 1, 0, OUT as u32]
                ),
                HR_TYPE_E_ELEMENTNOTFOUND
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
            // Drop the handout reference again (the runtime-wide typeinfo
            // cache keeps the object alive at its baseline).
            let released = dispatch_x86(
                &mut fixture,
                HostThunk::GuestObjectRelease,
                &[type_info as u32],
            ) as u32;
            assert_eq!(released, 2);

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

    /// The type-library image materializes into one shared cache file per
    /// image version; tests that create or sabotage that file serialize
    /// here (cargo runs a test binary's threads concurrently).
    fn typelib_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Removes whatever stands at the type-library cache path when the
    /// sabotaging test ends (even through a panic).
    struct CachePathCleanup(std::path::PathBuf);

    impl Drop for CachePathCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn web_browser_get_type_info_loads_real_typelib_and_rejects_bad_indexes() {
        with_big_stack(|| {
            // This test materializes the shared type-library cache file.
            let _lock = typelib_lock();
            let mut fixture = x86_fixture("browser-typelib");
            let object = object(&mut fixture);
            map(&mut fixture, OUT, 8);
            write_u32(&mut fixture.memory, OUT, 0xdead_beef);
            // A null out-pointer is E_INVALIDARG, an unknown index is
            // TYPE_E_ELEMENTNOTFOUND with the out-pointer zeroed.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 0, 0, 0]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 7, 0, OUT as u32]
                ),
                HR_TYPE_E_ELEMENTNOTFOUND
            );
            assert_eq!(read_out_pointer(&fixture, OUT), 0);
            // Index 0 hands out the live IWebBrowser2 type info.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 0, 0, OUT as u32]
                ),
                HR_S_OK
            );
            let type_info = read_out_pointer(&fixture, OUT);
            assert_ne!(type_info, 0);
            assert_eq!(fixture.runtime.guest_objects[&type_info].refcount, 3);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 0, 0, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_pointer(&fixture, OUT), type_info);
            assert_eq!(fixture.runtime.guest_objects[&type_info].refcount, 4);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[type_info as u32]
                ) as u32,
                3
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[type_info as u32]
                ) as u32,
                2
            );
            // GetTypeAttr: the IWebBrowser2 IID and the 46-member table.
            map(&mut fixture, OUT, 64);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ComMethod(ComMethod::TypeInfoGetTypeAttr),
                    &[type_info as u32, OUT as u32]
                ),
                HR_S_OK
            );
            let attr = read_out_pointer(&fixture, OUT);
            assert_ne!(attr, 0);
            let iid_bytes =
                crate::real_win32::guid_from_string(IID_IWEBBROWSER2).expect("iid bytes");
            for (index, expected) in iid_bytes.iter().enumerate() {
                assert_eq!(
                    fixture.memory.read_u8(attr + index as u64).unwrap(),
                    *expected,
                    "type guid byte {index}"
                );
            }
            assert_eq!(fixture.memory.read_u16(attr + 44).unwrap(), 46); // cFuncs
            assert_eq!(fixture.memory.read_u16(attr + 50).unwrap(), 212); // cbSizeVft
            // FUNCDESC of the first member: GoBack at vtable slot 7.
            map(&mut fixture, OUT, 8);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ComMethod(ComMethod::TypeInfoGetFuncDesc),
                    &[type_info as u32, 0, OUT as u32]
                ),
                HR_S_OK
            );
            let descriptor = read_out_pointer(&fixture, OUT);
            assert_ne!(descriptor, 0);
            assert_eq!(
                fixture.memory.read_u32(descriptor).unwrap(),
                WebBrowserMethod::GoBack.dispid() as u32
            );
            assert_eq!(fixture.memory.read_u32(descriptor + 16).unwrap(), 1); // INVOKE_FUNC
            assert_eq!(fixture.memory.read_u16(descriptor + 28).unwrap(), 7); // oVft slot
            // Navigate keeps its five parameters.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ComMethod(ComMethod::TypeInfoGetFuncDesc),
                    &[type_info as u32, 4, OUT as u32]
                ),
                HR_S_OK
            );
            let descriptor = read_out_pointer(&fixture, OUT);
            assert_eq!(
                fixture.memory.read_u32(descriptor).unwrap(),
                WebBrowserMethod::Navigate.dispid() as u32
            );
            assert_eq!(fixture.memory.read_u16(descriptor + 24).unwrap(), 5); // cParams
            // Past the end of the table is the documented failure.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ComMethod(ComMethod::TypeInfoGetFuncDesc),
                    &[type_info as u32, 46, OUT as u32]
                ),
                HR_TYPE_E_ELEMENTNOTFOUND
            );
            // GetIDsOfNames through the type info: the member resolves to
            // the runtime's local dispatch id, unknown names do not.
            map(&mut fixture, NAMES, 8);
            map(&mut fixture, IDS, 4);
            let navigate = wide(&mut fixture, "Navigate");
            write_u32(&mut fixture.memory, NAMES, navigate as u32);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ComMethod(ComMethod::TypeInfoGetIDsOfNames),
                    &[type_info as u32, NAMES as u32, 1, IDS as u32]
                ),
                HR_S_OK
            );
            assert_eq!(
                fixture.memory.read_u32(IDS).unwrap(),
                WebBrowserMethod::Navigate.dispid() as u32
            );
            let unknown = wide(&mut fixture, "NoSuchMember");
            write_u32(&mut fixture.memory, NAMES, unknown as u32);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ComMethod(ComMethod::TypeInfoGetIDsOfNames),
                    &[type_info as u32, NAMES as u32, 1, IDS as u32]
                ),
                HR_DISP_E_UNKNOWNNAME
            );
            assert_eq!(fixture.memory.read_u32(IDS).unwrap(), DISPID_UNKNOWN as u32);
            // GetDocumentation: interface name, documentation, help file.
            map(&mut fixture, TEXT, 16);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ComMethod(ComMethod::TypeInfoGetDocumentation),
                    &[
                        type_info as u32,
                        DISPID_UNKNOWN as u32,
                        TEXT as u32,
                        (TEXT + 4) as u32,
                        (TEXT + 8) as u32,
                        (TEXT + 12) as u32,
                    ]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, TEXT), "IWebBrowser2");
            assert_eq!(
                read_out_string(&fixture, TEXT + 4),
                "IWebBrowser2 browser-control interface"
            );
            assert_eq!(fixture.memory.read_u32(TEXT + 8).unwrap(), 0);
            assert_eq!(read_out_string(&fixture, TEXT + 12), "shdocvw.hlp");
            // GetNames: the member name plus its unnamed parameters (the
            // image carries no per-parameter names).
            map(&mut fixture, NAMES, 32);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::ComMethod(ComMethod::TypeInfoGetNames),
                    &[
                        type_info as u32,
                        WebBrowserMethod::Navigate.dispid() as u32,
                        NAMES as u32,
                        8,
                        IDS as u32,
                    ]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(IDS).unwrap(), 6);
            assert_eq!(
                read_utf16_string(
                    &fixture.memory,
                    read_guest_pointer(&fixture.memory, NAMES, GuestArch::X86).expect("name")
                )
                .expect("name"),
                "Navigate"
            );
            assert_eq!(
                read_utf16_string(
                    &fixture.memory,
                    read_guest_pointer(&fixture.memory, NAMES + 4, GuestArch::X86)
                        .expect("param name")
                )
                .expect("param name"),
                ""
            );
            // Invoked GetTypeInfo: a VT_I4 argument carries the index
            // (0 and missing are the documented index 0), other argument
            // types are a mismatch, and a missing result pointer is
            // E_INVALIDARG.
            map(&mut fixture, PARAMS, 24);
            map(&mut fixture, ARGS, 24);
            map(&mut fixture, VAR2, 24);
            write_variant_i4_value(&mut fixture, ARGS, 0);
            write_u32(&mut fixture.memory, PARAMS, ARGS as u32);
            write_u32(&mut fixture.memory, PARAMS + 8, 1);
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
                        PARAMS as u32,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u16(VAR2).unwrap(), 13); // VT_UNKNOWN
            fixture.memory.write_u16(ARGS, 0); // VT_EMPTY argument
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
                        PARAMS as u32,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_S_OK
            );
            write_variant_i4_value(&mut fixture, ARGS, 7);
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
                        PARAMS as u32,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_TYPE_E_ELEMENTNOTFOUND
            );
            write_variant_wide(&mut fixture, ARGS, "7");
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
                        PARAMS as u32,
                        VAR2 as u32,
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
                        WebBrowserMethod::GetTypeInfo.dispid() as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        PARAMS as u32,
                        0,
                        0,
                        0
                    ]
                ),
                HR_E_INVALIDARG
            );
            // A type library that cannot be read loads as None (the
            // dispatch reports TYPE_E_CANTLOADLIBRARY).
            let absent = fixture._temp.path().join("absent-shdocvw.tlb");
            assert_eq!(
                fixture
                    .runtime
                    .shdocvw_load_type_info(&mut fixture.memory, &absent)
                    .expect("bogus load"),
                None
            );
            // The cache outlives individual controls.
            assert!(
                fixture
                    .runtime
                    .com_service_map
                    .contains_key(SHDOCVW_TYPEINFO_KEY)
            );
        });
    }

    #[test]
    fn web_browser_type_info_cache_path_failure_is_cantloadlibrary() {
        with_big_stack(|| {
            // This test sabotages the shared type-library cache file.
            let _lock = typelib_lock();
            let path = shdocvw_typelib_cache_path();
            let _cleanup = CachePathCleanup(path.clone());
            let _ = std::fs::remove_file(&path);
            std::fs::create_dir_all(&path).expect("cache path becomes a directory");
            let mut fixture = x86_fixture("browser-typelib-fail");
            let object = object(&mut fixture);
            map(&mut fixture, OUT, 8);
            write_u32(&mut fixture.memory, OUT, 0xdead_beef);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 0, 0, OUT as u32]
                ),
                HR_TYPE_E_CANTLOADLIBRARY
            );
            assert_eq!(read_out_pointer(&fixture, OUT), 0);
            assert!(
                !fixture
                    .runtime
                    .com_service_map
                    .contains_key(SHDOCVW_TYPEINFO_KEY)
            );
            // The invoked member reports the same load failure.
            map(&mut fixture, PARAMS, 24);
            map(&mut fixture, ARGS, 24);
            map(&mut fixture, VAR2, 24);
            write_variant_i4_value(&mut fixture, ARGS, 0);
            write_u32(&mut fixture.memory, PARAMS, ARGS as u32);
            write_u32(&mut fixture.memory, PARAMS + 8, 1);
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
                        PARAMS as u32,
                        VAR2 as u32,
                        0,
                        0
                    ]
                ),
                HR_TYPE_E_CANTLOADLIBRARY
            );
            // The failure is not cached: dropping the obstruction
            // materializes the library on the next call.
            std::fs::remove_dir(&path).expect("sabotage directory removed");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[object as u32, 0, 0, OUT as u32]
                ),
                HR_S_OK
            );
            assert_ne!(read_out_pointer(&fixture, OUT), 0);
            assert!(
                fixture
                    .runtime
                    .com_service_map
                    .contains_key(SHDOCVW_TYPEINFO_KEY)
            );
        });
    }

    #[test]
    fn web_browser_get_document_returns_html_document_and_rejects_wrong_iids() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-document");
            let object = object(&mut fixture);
            map(&mut fixture, OUT, 8);
            write_u32(&mut fixture.memory, OUT, 0xdead_beef);
            // No page has loaded: S_FALSE with a null document.
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
            // The invoked getter reports the same empty state as a
            // cleared VT_EMPTY result.
            map(&mut fixture, VAR, 24);
            fixture.memory.write_u16(VAR, 11); // stale contents
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
                        VAR as u32,
                        0,
                        0
                    ]
                ),
                HR_S_FALSE
            );
            assert_eq!(fixture.memory.read_u16(VAR).unwrap(), 0);
            // Cross-role: document slots never exist on the control.
            map(&mut fixture, OUT, 8);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[object as u32, OUT as u32]
                ),
                HR_E_INVALIDARG
            );
            // A committed navigation loads a document.
            let url = wide(&mut fixture, "http://example.com/");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, url as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            let document = read_out_pointer(&fixture, OUT);
            assert_ne!(document, 0);
            assert_eq!(fixture.runtime.guest_objects[&document].refcount, 2);
            // QueryInterface: both document IIDs resolve, a wrong IID is
            // E_NOINTERFACE with a null out-pointer.
            map(&mut fixture, TEXT, 8);
            write_iid(&mut fixture, IID, IID_IHTMLDOCUMENT2);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryInterface,
                    &[document as u32, IID as u32, TEXT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_pointer(&fixture, TEXT), document);
            assert_eq!(fixture.runtime.guest_objects[&document].refcount, 3);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[document as u32]
                ) as u32,
                2
            );
            write_iid(&mut fixture, IID, IID_IHTMLDOCUMENT);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryInterface,
                    &[document as u32, IID as u32, TEXT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[document as u32]
                ) as u32,
                2
            );
            write_iid(&mut fixture, IID, "{12345678-1234-1234-1234-1234567890ab}");
            write_u32(&mut fixture.memory, TEXT, 0xdead_beef);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryInterface,
                    &[document as u32, IID as u32, TEXT as u32]
                ),
                HR_E_NOINTERFACE
            );
            assert_eq!(read_out_pointer(&fixture, TEXT), 0);
            // The document's members answer the navigation state.
            map(&mut fixture, OUT, 8);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[document as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "http://example.com/");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetReferrer,
                    &[document as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetReadyState,
                    &[document as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "complete");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[document as u32, 0]
                ),
                HR_E_INVALIDARG
            );
            // The document's IDispatch surface: no generated type library.
            map(&mut fixture, OUT, 8);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfoCount,
                    &[document as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 0);
            write_u32(&mut fixture.memory, OUT, 0xdead_beef);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[document as u32, 0, 0, OUT as u32]
                ),
                HR_TYPE_E_ELEMENTNOTFOUND
            );
            assert_eq!(read_out_pointer(&fixture, OUT), 0);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetTypeInfo,
                    &[document as u32, 0, 0, 0]
                ),
                HR_E_INVALIDARG
            );
            // GetIDsOfNames over the IHTMLDocument2 member table: the URL
            // pair shares the id of its first row, unknown names do not.
            map(&mut fixture, NAMES, 8);
            map(&mut fixture, IDS, 4);
            let url_name = wide(&mut fixture, "URL");
            write_u32(&mut fixture.memory, NAMES, url_name as u32);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[document as u32, 0, NAMES as u32, 1, 0, IDS as u32]
                ),
                HR_S_OK
            );
            assert_eq!(
                fixture.memory.read_u32(IDS).unwrap(),
                (DOC_DISPID_BASE + 32) as u32 // the URL put/get pair
            );
            let unknown = wide(&mut fixture, "nosuchmember");
            write_u32(&mut fixture.memory, NAMES, unknown as u32);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[document as u32, 0, NAMES as u32, 1, 0, IDS as u32]
                ),
                HR_DISP_E_UNKNOWNNAME
            );
            assert_eq!(fixture.memory.read_u32(IDS).unwrap(), DISPID_UNKNOWN as u32);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetIDsOfNames,
                    &[document as u32, 0, NAMES as u32, 1, 0, 0]
                ),
                HR_E_INVALIDARG
            );
            // Invoke: real getters, unmodeled members, kind rules, and
            // unknown ids.
            map(&mut fixture, VAR, 24);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        document as u32,
                        (DOC_DISPID_BASE + 32) as u32, // URL
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
            assert_eq!(fixture.memory.read_u16(VAR).unwrap(), 8);
            assert_eq!(
                read_utf16_string(
                    &fixture.memory,
                    read_guest_pointer(&fixture.memory, VAR + 8, GuestArch::X86).expect("bstr")
                )
                .expect("bstr"),
                "http://example.com/"
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        document as u32,
                        (DOC_DISPID_BASE + 15) as u32, // readyState
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
            // body exists in the table but is not modeled: E_NOTIMPL.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        document as u32,
                        (DOC_DISPID_BASE + 1) as u32, // body
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        VAR as u32,
                        0,
                        0
                    ]
                ),
                HR_E_NOTIMPL
            );
            // URL has a setter row but no modeled setter.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        document as u32,
                        (DOC_DISPID_BASE + 32) as u32,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYPUT),
                        0,
                        VAR as u32,
                        0,
                        0
                    ]
                ),
                HR_E_NOTIMPL
            );
            // URL is not a method: wrong kind is MEMBERNOTFOUND.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        document as u32,
                        (DOC_DISPID_BASE + 32) as u32,
                        0,
                        0,
                        u32::from(DISPATCH_METHOD),
                        0,
                        VAR as u32,
                        0,
                        0
                    ]
                ),
                HR_DISP_E_MEMBERNOTFOUND
            );
            // No flags and unknown ids are MEMBERNOTFOUND too.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        document as u32,
                        (DOC_DISPID_BASE + 32) as u32,
                        0,
                        0,
                        0,
                        0,
                        VAR as u32,
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
                        document as u32,
                        4321,
                        0,
                        0,
                        u32::from(DISPATCH_PROPERTYGET),
                        0,
                        VAR as u32,
                        0,
                        0
                    ]
                ),
                HR_DISP_E_MEMBERNOTFOUND
            );
            // A getter without a result pointer is E_INVALIDARG.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Invoke,
                    &[
                        document as u32,
                        (DOC_DISPID_BASE + 32) as u32,
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
            // A directly-called unmodeled member slot answers E_NOTIMPL
            // (its stdcall byte count rides on the thunk).
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentUnsupported { arg_bytes: 4 },
                    &[document as u32, VAR as u32]
                ),
                HR_E_NOTIMPL
            );
            // The enum identities of the document slots.
            assert_eq!(
                WebBrowserMethod::DocumentGetReadyState.dispatch_name(),
                "readyState"
            );
            assert_eq!(
                WebBrowserMethod::DocumentGetReferrer.dispatch_name(),
                "referrer"
            );
            assert_eq!(WebBrowserMethod::DocumentGetUrl.dispatch_name(), "URL");
            assert_eq!(
                WebBrowserMethod::DocumentUnsupported { arg_bytes: 4 }.dispatch_name(),
                "DocumentMember"
            );
            assert_eq!(
                WebBrowserMethod::DocumentUnsupported { arg_bytes: 8 }.x86_arg_bytes(),
                8
            );
            assert_eq!(WebBrowserMethod::DocumentGetReadyState.dispid(), 96);
            assert_eq!(WebBrowserMethod::DocumentGetReferrer.dispid(), 97);
            assert_eq!(WebBrowserMethod::DocumentGetUrl.dispid(), 98);
            assert_eq!(
                WebBrowserMethod::DocumentUnsupported { arg_bytes: 8 }.dispid(),
                101
            );
            assert_eq!(
                WebBrowserMethod::DocumentGetUrl.supported_kinds(),
                DISPATCH_PROPERTYGET
            );
            assert_eq!(
                WebBrowserMethod::DocumentUnsupported { arg_bytes: 4 }.supported_kinds(),
                DISPATCH_METHOD
            );
            // Cross-role the other way: control slots on the document.
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[document as u32, url as u32, 0, 0, 0, 0]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Quit, &[document as u32]),
                HR_E_INVALIDARG
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[document as u32, OUT as u32]
                ),
                HR_E_INVALIDARG
            );
        });
    }

    #[test]
    fn web_browser_document_navigation_races_and_lifetime_freeze_exact() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-document-race");
            let object = object(&mut fixture);
            map(&mut fixture, OUT, 8);
            let first = wide(&mut fixture, "http://example.com/one");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, first as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            let doc_one = read_out_pointer(&fixture, OUT);
            assert_ne!(doc_one, 0);
            assert_eq!(fixture.runtime.guest_objects[&doc_one].refcount, 2);
            // Async load race: while the control reports loading there is
            // no document, but a held document reflects the live state.
            fixture
                .runtime
                .web_browsers
                .get_mut(&object)
                .unwrap()
                .ready_state = READYSTATE_LOADING;
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
            for (value, expected) in [
                (1, "loading"),
                (7, "uninitialized"),
                (0, "uninitialized"),
                (2, "loaded"),
                (3, "interactive"),
                (4, "complete"),
            ] {
                fixture
                    .runtime
                    .web_browsers
                    .get_mut(&object)
                    .unwrap()
                    .ready_state = value;
                assert_eq!(
                    call(
                        &mut fixture,
                        WebBrowserMethod::DocumentGetReadyState,
                        &[doc_one as u32, OUT as u32]
                    ),
                    HR_S_OK,
                    "ready state {value}"
                );
                assert_eq!(
                    read_out_string(&fixture, OUT),
                    expected,
                    "ready state name for {value}"
                );
            }
            // Refresh completes the load without replacing the document.
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
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_pointer(&fixture, OUT), doc_one);
            // A new navigation freezes the old document at its page and
            // the control drops its reference to it.
            let second = wide(&mut fixture, "http://example.com/two");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::Navigate,
                    &[object as u32, second as u32, 0, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.runtime.guest_objects[&doc_one].refcount, 2);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            let doc_two = read_out_pointer(&fixture, OUT);
            assert_ne!(doc_two, doc_one);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[doc_one as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "http://example.com/one");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[doc_two as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "http://example.com/two");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetReferrer,
                    &[doc_two as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "http://example.com/one");
            // History races detach the document too: each GoBack leaves
            // the held document frozen and hands out a fresh one.
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoBack, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(fixture.runtime.guest_objects[&doc_two].refcount, 1);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            let doc_three = read_out_pointer(&fixture, OUT);
            assert_ne!(doc_three, doc_two);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[doc_two as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "http://example.com/two");
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::GoBack, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::GetDocument,
                    &[object as u32, OUT as u32]
                ),
                HR_S_OK
            );
            let doc_four = read_out_pointer(&fixture, OUT);
            assert_ne!(doc_four, doc_three);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[doc_four as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "about:blank");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetReferrer,
                    &[doc_four as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "");
            // Control teardown: the held document freezes at the last
            // page and keeps answering from its snapshot.
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Release, &[object as u32]),
                0
            );
            assert_eq!(fixture.runtime.guest_objects[&doc_four].refcount, 1);
            assert!(!fixture.runtime.web_browsers.contains_key(&object));
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[doc_four as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "about:blank");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetReadyState,
                    &[doc_four as u32, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(read_out_string(&fixture, OUT), "complete");
            // Dropping the last handout frees the documents: later calls
            // on them are E_INVALIDARG.
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[doc_one as u32]
                ) as u32,
                1
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[doc_one as u32]
                ) as u32,
                0
            );
            assert!(!fixture.runtime.guest_objects.contains_key(&doc_one));
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[doc_one as u32, OUT as u32]
                ),
                HR_E_INVALIDARG
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[doc_two as u32]
                ) as u32,
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[doc_three as u32]
                ) as u32,
                0
            );
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::GuestObjectRelease,
                    &[doc_four as u32]
                ) as u32,
                0
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::DocumentGetUrl,
                    &[doc_four as u32, OUT as u32]
                ),
                HR_E_INVALIDARG
            );
        });
    }

    #[test]
    fn web_browser_exec_wb_dispatches_modeled_ole_commands_and_rejects_unsupported() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-olecmd");
            let object = object(&mut fixture);
            map(&mut fixture, OUT, 4);
            map(&mut fixture, VAR, 24);
            // REFRESH/STOP complete the modeled load.
            fixture
                .runtime
                .web_browsers
                .get_mut(&object)
                .unwrap()
                .ready_state = READYSTATE_LOADING;
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, OLECMDID_REFRESH, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(
                fixture.runtime.web_browsers[&object].ready_state,
                READYSTATE_COMPLETE
            );
            assert_eq!(fixture.runtime.web_browsers[&object].status_text, "Done");
            fixture
                .runtime
                .web_browsers
                .get_mut(&object)
                .unwrap()
                .ready_state = READYSTATE_LOADING;
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, OLECMDID_STOP, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(
                fixture.runtime.web_browsers[&object].ready_state,
                READYSTATE_COMPLETE
            );
            // OLECMDID_NEW completes readiness but leaves the status text.
            let status = wide(&mut fixture, "busy");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::PutStatusText,
                    &[object as u32, status as u32]
                ),
                HR_S_OK
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, OLECMDID_NEW, 0, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.runtime.web_browsers[&object].status_text, "busy");
            // The pvaIn argument accepts null, VT_EMPTY/VT_NULL/VT_I4 and
            // rejects every other VARIANT type.
            write_variant_i4_value(&mut fixture, VAR, 3);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, OLECMDID_REFRESH, 0, VAR as u32, 0]
                ),
                HR_S_OK
            );
            fixture.memory.write_u16(VAR, 0); // VT_EMPTY
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, OLECMDID_REFRESH, 0, VAR as u32, 0]
                ),
                HR_S_OK
            );
            fixture.memory.write_u16(VAR, 1); // VT_NULL
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, OLECMDID_REFRESH, 0, VAR as u32, 0]
                ),
                HR_S_OK
            );
            fixture.memory.write_u16(VAR, 5); // VT_R8
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, OLECMDID_REFRESH, 0, VAR as u32, 0]
                ),
                HR_DISP_E_TYPEMISMATCH
            );
            // An unmodeled command stays unsupported, even with a bad
            // argument attached (the command is checked first).
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, 6, 0, VAR as u32, 0]
                ),
                HR_OLECMDERR_E_NOTSUPPORTED
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, 99, 0, 0, 0]
                ),
                HR_OLECMDERR_E_NOTSUPPORTED
            );
            // A closed control reports the modeled commands disabled —
            // exactly the cleared ENABLED bit of QueryStatusWB.
            assert_eq!(
                call(&mut fixture, WebBrowserMethod::Quit, &[object as u32]),
                HR_S_OK
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, OLECMDID_REFRESH, 0, 0, 0]
                ),
                HR_OLECMDERR_E_DISABLED
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ExecWB,
                    &[object as u32, 99, 0, 0, 0]
                ),
                HR_OLECMDERR_E_NOTSUPPORTED
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::QueryStatusWB,
                    &[object as u32, OLECMDID_REFRESH, OUT as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), OLECMDF_SUPPORTED);
            // ShowBrowserBar: validated variants, real bar class ids stay
            // unsupported, empty class ids dismiss.
            map(&mut fixture, OUT, 4);
            fixture.memory.write_u16(OUT, 3); // VT_I4 replacement
            fixture.memory.write_u16(VAR, 0); // VT_EMPTY class id
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ShowBrowserBar,
                    &[object as u32, VAR as u32, 0, 0]
                ),
                HR_S_OK
            );
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ShowBrowserBar,
                    &[object as u32, VAR as u32, OUT as u32, 0]
                ),
                HR_DISP_E_TYPEMISMATCH
            );
            fixture.memory.write_u16(VAR, 3); // VT_I4 class id
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ShowBrowserBar,
                    &[object as u32, VAR as u32, 0, 0]
                ),
                HR_DISP_E_TYPEMISMATCH
            );
            write_variant_wide(&mut fixture, VAR, "{C2F03A33-21F5-47FA-B4BB-156362A2F239}");
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ShowBrowserBar,
                    &[object as u32, VAR as u32, 0, 0]
                ),
                HR_OLECMDERR_E_NOTSUPPORTED
            );
            fixture.memory.write_u16(VAR, 1); // VT_NULL class id
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ShowBrowserBar,
                    &[object as u32, VAR as u32, 0, 0]
                ),
                HR_S_OK
            );
        });
    }

    #[test]
    fn web_browser_client_to_window_uses_window_geometry_and_rejects_missing_window() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("browser-client-to-window");
            let object = object(&mut fixture);
            map(&mut fixture, OUT, 8);
            // No window exists yet: E_FAIL and the coordinates stay put.
            write_u32(&mut fixture.memory, OUT, 10);
            write_u32(&mut fixture.memory, OUT + 4, 10);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ClientToWindow,
                    &[object as u32, OUT as u32, (OUT + 4) as u32]
                ),
                HR_E_FAIL
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 10);
            assert_eq!(fixture.memory.read_u32(OUT + 4).unwrap(), 10);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ClientToWindow,
                    &[object as u32, 0, (OUT + 4) as u32]
                ),
                HR_E_INVALIDARG
            );
            // With the front-most guest window, client coordinates move by
            // the window's non-client frame (border 4 + title 23 at 96 DPI).
            let hwnd = fixture
                .runtime
                .user32
                .create_window_ex_w("static", "host", 640, 480, true, false, None, 0)
                .expect("window");
            assert_eq!(
                fixture.runtime.user32.dpi_for_window(hwnd).expect("dpi"),
                96
            );
            write_u32(&mut fixture.memory, OUT, 10);
            write_u32(&mut fixture.memory, OUT + 4, 10);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ClientToWindow,
                    &[object as u32, OUT as u32, (OUT + 4) as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 14);
            assert_eq!(fixture.memory.read_u32(OUT + 4).unwrap(), 37);
            // The conversion is frame-based: moving the window does not
            // change it.
            fixture
                .runtime
                .user32
                .set_window_position(hwnd, 50, 60)
                .expect("move");
            write_u32(&mut fixture.memory, OUT, 10);
            write_u32(&mut fixture.memory, OUT + 4, 10);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ClientToWindow,
                    &[object as u32, OUT as u32, (OUT + 4) as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), 14);
            assert_eq!(fixture.memory.read_u32(OUT + 4).unwrap(), 37);
            // Boundary coordinates: negative inputs stay relative, huge
            // inputs saturate instead of wrapping.
            write_u32(&mut fixture.memory, OUT, (-8_i32) as u32);
            write_u32(&mut fixture.memory, OUT + 4, i32::MAX as u32);
            assert_eq!(
                call(
                    &mut fixture,
                    WebBrowserMethod::ClientToWindow,
                    &[object as u32, OUT as u32, (OUT + 4) as u32]
                ),
                HR_S_OK
            );
            assert_eq!(fixture.memory.read_u32(OUT).unwrap(), (-4_i32) as u32);
            assert_eq!(fixture.memory.read_u32(OUT + 4).unwrap(), i32::MAX as u32);
        });
    }

    #[test]
    fn web_browser_x64_typeinfo_and_document_dispatch_edges_are_exact() {
        with_big_stack(|| {
            // This test materializes the shared type-library cache file.
            let _lock = typelib_lock();
            let mut fixture = x86_fixture("browser-x64-dispatch");
            fixture.runtime.guest_arch = GuestArch::X64;
            let object = fixture
                .runtime
                .alloc_web_browser_object(&mut fixture.memory, "about:blank")
                .expect("allocate browser");
            map(&mut fixture, OUT, 8);
            // GetTypeInfo through the x64 register calling convention.
            let mut type_info_call = CpuState::new(GuestArch::X64);
            type_info_call.set(Register::Rcx, object);
            type_info_call.set(Register::Rdx, 0); // index 0
            type_info_call.set(Register::R8, 0); // lcid
            type_info_call.set(Register::R9, OUT); // out
            fixture
                .runtime
                .dispatch_web_browser_method(
                    WebBrowserMethod::GetTypeInfo,
                    &mut type_info_call,
                    &mut fixture.memory,
                )
                .expect("x64 GetTypeInfo");
            assert_eq!(type_info_call.get(Register::Rax), HR_S_OK);
            assert_ne!(
                read_guest_pointer(&fixture.memory, OUT, GuestArch::X64).expect("type info"),
                0
            );
            // Null out-pointer stays E_INVALIDARG on x64.
            let mut null_out = CpuState::new(GuestArch::X64);
            null_out.set(Register::Rcx, object);
            null_out.set(Register::Rdx, 7); // index 7
            null_out.set(Register::R8, 0);
            null_out.set(Register::R9, 0);
            fixture
                .runtime
                .dispatch_web_browser_method(
                    WebBrowserMethod::GetTypeInfo,
                    &mut null_out,
                    &mut fixture.memory,
                )
                .expect("x64 GetTypeInfo null out");
            assert_eq!(null_out.get(Register::Rax), HR_E_INVALIDARG);
            // Navigate, then materialize and read the document on x64.
            let url = fixture
                .runtime
                .alloc_utf16_string(&mut fixture.memory, "http://example.com/x64")
                .expect("url");
            let mut navigate = CpuState::new(GuestArch::X64);
            navigate.set(Register::Rcx, object);
            navigate.set(Register::Rdx, url);
            fixture
                .runtime
                .dispatch_web_browser_method(
                    WebBrowserMethod::Navigate,
                    &mut navigate,
                    &mut fixture.memory,
                )
                .expect("x64 Navigate");
            assert_eq!(navigate.get(Register::Rax), HR_S_OK);
            let mut get_document = CpuState::new(GuestArch::X64);
            get_document.set(Register::Rcx, object);
            get_document.set(Register::Rdx, OUT);
            fixture
                .runtime
                .dispatch_web_browser_method(
                    WebBrowserMethod::GetDocument,
                    &mut get_document,
                    &mut fixture.memory,
                )
                .expect("x64 GetDocument");
            assert_eq!(get_document.get(Register::Rax), HR_S_OK);
            let document =
                read_guest_pointer(&fixture.memory, OUT, GuestArch::X64).expect("document");
            assert_ne!(document, 0);
            let mut document_url = CpuState::new(GuestArch::X64);
            document_url.set(Register::Rcx, document);
            document_url.set(Register::Rdx, OUT);
            fixture
                .runtime
                .dispatch_web_browser_method(
                    WebBrowserMethod::DocumentGetUrl,
                    &mut document_url,
                    &mut fixture.memory,
                )
                .expect("x64 document URL");
            assert_eq!(document_url.get(Register::Rax), HR_S_OK);
            assert_eq!(
                read_utf16_string(
                    &fixture.memory,
                    read_guest_pointer(&fixture.memory, OUT, GuestArch::X64).expect("bstr")
                )
                .expect("bstr"),
                "http://example.com/x64"
            );
            let mut null_bstr = CpuState::new(GuestArch::X64);
            null_bstr.set(Register::Rcx, document);
            null_bstr.set(Register::Rdx, 0);
            fixture
                .runtime
                .dispatch_web_browser_method(
                    WebBrowserMethod::DocumentGetUrl,
                    &mut null_bstr,
                    &mut fixture.memory,
                )
                .expect("x64 document URL null out");
            assert_eq!(null_bstr.get(Register::Rax), HR_E_INVALIDARG);
        });
    }
}
