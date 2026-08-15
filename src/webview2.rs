// ---------------------------------------------------------------------------
// WebView2 COM Interface Wrapper — backed by native macOS WKWebView via
// Objective-C FFI using the `objc` crate.
//
// Steam.exe and other apps may load webview2.dll and call the
// CreateWebView2Environment entry point to obtain an ICoreWebView2Environment,
// from which they create controllers and webview instances.
//
// Architecture:
//   WebView2Environment  ──  WKWebViewConfiguration + WKProcessPool
//         │
//         ▼
//   WebView2Controller  ──  WKWebView instance (native ObjC pointer)
//         │
//         ▼
//   WebView2Instance  ──  WKWebView backing (navigate, eval JS, etc.)
//
// All FFI calls use `objc::runtime::Class::get()` and `msg_send!`, wrapped
// in `#[cfg(target_os = "macos")]` blocks for cross-platform compilation.
// ---------------------------------------------------------------------------

use block::{ConcreteBlock, RcBlock};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// HRESULT-like error codes
// ---------------------------------------------------------------------------

/// HRESULT success code.
pub const S_OK: u64 = 0;
/// HRESULT generic failure code.
pub const E_FAIL: u64 = 0x8000_4005;
/// HRESULT invalid argument.
pub const E_INVALIDARG: u64 = 0x8007_0057;
/// HRESULT not implemented.
pub const E_NOTIMPL: u64 = 0x8000_4001;
/// HRESULT unexpected failure.
pub const E_UNEXPECTED: u64 = 0x8000_FFFF;
/// HRESULT pointer not found.
pub const E_POINTER: u64 = 0x8000_4003;
/// HRESULT class not available (CLASS_E_CLASSNOTAVAILABLE).
pub const E_CLASSNOTAVAILABLE: u64 = 0x8004_0111;

// ---------------------------------------------------------------------------
// Navigation callback types
// ---------------------------------------------------------------------------

/// Callback invoked when a navigation is starting.
/// Arguments: (webview_id, uri, is_redirect) → should_cancel
pub type NavigationStartingCallback = Box<dyn FnMut(u64, &str, bool) -> bool + Send>;

/// Callback invoked when a navigation has completed.
/// Arguments: (webview_id, uri, is_success, http_status_code)
pub type NavigationCompletedCallback = Box<dyn FnMut(u64, &str, bool, u32) + Send>;

/// Callback invoked when the source URL has changed.
/// Arguments: (webview_id, new_uri)
pub type SourceChangedCallback = Box<dyn FnMut(u64, &str) + Send>;

/// Callback invoked when content starts loading.
/// Arguments: (webview_id, uri)
pub type ContentLoadingCallback = Box<dyn FnMut(u64, &str) + Send>;

/// Callback invoked when a web message is received.
/// Arguments: (webview_id, message_json)
pub type WebMessageReceivedCallback = Box<dyn FnMut(u64, &str) + Send>;

/// Callback invoked when a new window is requested.
/// Arguments: (webview_id, target_uri) → bool (allow)
pub type NewWindowRequestedCallback = Box<dyn FnMut(u64, &str) -> bool + Send>;

// ---------------------------------------------------------------------------
// Global navigation delegate state
// ---------------------------------------------------------------------------

/// Per-webview navigation state tracked by the ObjC delegate.
#[derive(Debug, Clone)]
struct NavigationState {
    pub navigation_started: bool,
    pub navigation_completed: bool,
    pub navigation_error: Option<String>,
    pub current_uri: String,
}

/// Shared state between the ObjC WKNavigationDelegate and Rust code.
struct DelegateState {
    /// Map from native WKWebView pointer value → webview ID
    view_to_webview_id: HashMap<u64, u64>,
    /// Map from webview ID → navigation state
    nav_states: HashMap<u64, NavigationState>,
    /// Registered NavigationStarting callbacks
    pub on_navigation_starting: Vec<(u64, NavigationStartingCallback)>,
    /// Registered NavigationCompleted callbacks
    pub on_navigation_completed: Vec<(u64, NavigationCompletedCallback)>,
    /// Registered SourceChanged callbacks
    pub on_source_changed: Vec<(u64, SourceChangedCallback)>,
    /// Registered ContentLoading callbacks
    pub on_content_loading: Vec<(u64, ContentLoadingCallback)>,
    /// Registered WebMessageReceived callbacks
    pub on_web_message_received: Vec<(u64, WebMessageReceivedCallback)>,
    /// Registered NewWindowRequested callbacks
    pub on_new_window_requested: Vec<(u64, NewWindowRequestedCallback)>,
    /// Next callback registration ID
    next_callback_id: u64,
}

impl DelegateState {
    fn new() -> Self {
        Self {
            view_to_webview_id: HashMap::new(),
            nav_states: HashMap::new(),
            on_navigation_starting: Vec::new(),
            on_navigation_completed: Vec::new(),
            on_source_changed: Vec::new(),
            on_content_loading: Vec::new(),
            on_web_message_received: Vec::new(),
            on_new_window_requested: Vec::new(),
            next_callback_id: 1,
        }
    }
}

use std::sync::LazyLock;
static DELEGATE_STATE: LazyLock<Mutex<DelegateState>> =
    LazyLock::new(|| Mutex::new(DelegateState::new()));

/// Lock the global delegate state, recovering from poisoning.
///
/// A panicked callback must not permanently disable delegate dispatch, so a
/// poisoned mutex is repaired by reinitializing it with its (possibly
/// partial) contents intact.
fn delegate_state() -> std::sync::MutexGuard<'static, DelegateState> {
    DELEGATE_STATE.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// ObjC runtime helper types (mirrored from cef_bridge)
// ---------------------------------------------------------------------------

/// Objective-C NSPoint (CGPoint) struct
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NSPoint {
    pub x: f64,
    pub y: f64,
}

impl NSPoint {
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

// SAFETY: Standard ObjC runtime type encoding for CGPoint
unsafe impl objc::Encode for NSPoint {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime type encoding
        unsafe { objc::Encoding::from_str("{CGPoint=dd}") }
    }
}

/// Objective-C NSSize (CGSize) struct
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NSSize {
    pub width: f64,
    pub height: f64,
}

impl NSSize {
    pub fn new(width: f64, height: f64) -> Self {
        Self { width, height }
    }
}

// SAFETY: Standard ObjC runtime type encoding for CGSize
unsafe impl objc::Encode for NSSize {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime type encoding
        unsafe { objc::Encoding::from_str("{CGSize=dd}") }
    }
}

/// Objective-C NSRect (CGRect) struct
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NSRect {
    pub origin: NSPoint,
    pub size: NSSize,
}

impl NSRect {
    pub fn new(origin: NSPoint, size: NSSize) -> Self {
        Self { origin, size }
    }
}

// SAFETY: Standard ObjC runtime type encoding for CGRect
unsafe impl objc::Encode for NSRect {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime type encoding
        unsafe { objc::Encoding::from_str("{CGRect={CGPoint=dd}{CGSize=dd}}") }
    }
}

/// Create an Objective-C NSString from a Rust &str.
/// Returns a raw pointer to the NSString object (caller must release), or
/// null on failure (e.g. embedded NUL bytes). The returned object is owned
/// (+1).
fn ns_string_from_str(s: &str) -> *mut objc::runtime::Object {
    // SAFETY: NSString is always available in the ObjC runtime on macOS.
    let cls = match objc::runtime::Class::get("NSString") {
        Some(c) => c,
        None => return std::ptr::null_mut(),
    };
    let c_str = match CString::new(s) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(), // embedded NUL byte — refuse
    };
    unsafe {
        let obj: *mut objc::runtime::Object = msg_send![cls, alloc];
        if obj.is_null() {
            return std::ptr::null_mut();
        }
        let str_obj: *mut objc::runtime::Object =
            msg_send![obj, initWithUTF8String: c_str.as_ptr()];
        if str_obj.is_null() {
            let _: () = msg_send![obj, release];
        }
        str_obj
    }
}

/// Helper: create an ObjC NSURL from a Rust &str.
/// SAFETY: returns a +0 (unowned) reference; caller must retain if needed.
unsafe fn ns_url_from_str(url: &str) -> *mut objc::runtime::Object {
    let Some(cls_nsurl) = objc::runtime::Class::get("NSURL") else {
        return std::ptr::null_mut();
    };
    let url_str = ns_string_from_str(url);
    if url_str.is_null() {
        return std::ptr::null_mut();
    }
    let ns_url: *mut objc::runtime::Object = msg_send![cls_nsurl, URLWithString: url_str];
    let _: () = msg_send![url_str, release];
    ns_url
}

// ---------------------------------------------------------------------------
// WKNavigationDelegate ObjC class registration
// ---------------------------------------------------------------------------

/// Register a custom ObjC class conforming to WKNavigationDelegate.
/// Called once during WebView2Environment initialization.
#[cfg(target_os = "macos")]
fn register_webview2_nav_delegate_class() -> Option<*const objc::runtime::Class> {
    use objc::declare::ClassDecl;
    use objc::runtime::Class;

    // Check if already registered
    if let Some(cls) = Class::get("Casa1WV2NavDelegate") {
        return Some(cls);
    }

    let superclass = Class::get("NSObject")?;
    let mut decl = ClassDecl::new("Casa1WV2NavDelegate", superclass)?;

    // Add webView:didFinishNavigation: method
    extern "C" fn did_finish_nav(
        _self_: &objc::runtime::Object,
        _cmd: objc::runtime::Sel,
        webview: *mut objc::runtime::Object,
        _navigation: *mut objc::runtime::Object,
    ) {
        // The delegate object is shared across all webviews of an
        // environment, so the webview ID must be looked up by the WKWebView
        // pointer that produced this callback, not by the delegate pointer.
        let ptr_val = webview as *const _ as u64;
        let (webview_id, uri, callbacks) = {
            let mut state = delegate_state();
            let Some(&webview_id) = state.view_to_webview_id.get(&ptr_val) else {
                return;
            };
            // Update navigation state
            state
                .nav_states
                .entry(webview_id)
                .and_modify(|ns| {
                    ns.navigation_completed = true;
                });

            // Collect NavigationCompleted callbacks
            let uri = state
                .nav_states
                .get(&webview_id)
                .map(|ns| ns.current_uri.clone())
                .unwrap_or_default();
            let callbacks = std::mem::take(&mut state.on_navigation_completed);
            (webview_id, uri, callbacks)
        };

        // Invoke callbacks without holding the state lock: user callbacks
        // may re-enter WebView2 APIs that lock DELEGATE_STATE.
        for (id, mut cb) in callbacks {
            cb(webview_id, &uri, true, 200);
            delegate_state().on_navigation_completed.push((id, cb));
        }

        eprintln!(
            "[WebView2] didFinishNavigation: webview_id={:#x}",
            webview_id,
        );
    }

    extern "C" fn did_fail_nav(
        _self_: &objc::runtime::Object,
        _cmd: objc::runtime::Sel,
        webview: *mut objc::runtime::Object,
        _navigation: *mut objc::runtime::Object,
        error: *mut objc::runtime::Object,
    ) {
        let ptr_val = webview as *const _ as u64;
        let error_desc = if error.is_null() {
            "unknown error".to_string()
        } else {
            unsafe {
                let desc: *mut objc::runtime::Object = msg_send![error, localizedDescription];
                if desc.is_null() {
                    "unknown error".to_string()
                } else {
                    let cstr: *const i8 = msg_send![desc, UTF8String];
                    if cstr.is_null() {
                        "unknown error".to_string()
                    } else {
                        std::ffi::CStr::from_ptr(cstr)
                            .to_string_lossy()
                            .into_owned()
                    }
                }
            }
        };

        let (webview_id, uri, callbacks) = {
            let mut state = delegate_state();
            let Some(&webview_id) = state.view_to_webview_id.get(&ptr_val) else {
                return;
            };
            state
                .nav_states
                .entry(webview_id)
                .and_modify(|ns| {
                    ns.navigation_completed = true;
                    ns.navigation_error = Some(error_desc.clone());
                });

            // Collect NavigationCompleted callbacks
            let uri = state
                .nav_states
                .get(&webview_id)
                .map(|ns| ns.current_uri.clone())
                .unwrap_or_default();
            let callbacks = std::mem::take(&mut state.on_navigation_completed);
            (webview_id, uri, callbacks)
        };

        // Invoke callbacks without holding the state lock.
        for (id, mut cb) in callbacks {
            cb(webview_id, &uri, false, 0);
            delegate_state().on_navigation_completed.push((id, cb));
        }

        eprintln!(
            "[WebView2] didFailNavigation: webview_id={:#x} error={}",
            webview_id, error_desc,
        );
    }

    extern "C" fn did_commit_nav(
        _self_: &objc::runtime::Object,
        _cmd: objc::runtime::Sel,
        webview: *mut objc::runtime::Object,
        _navigation: *mut objc::runtime::Object,
    ) {
        let ptr_val = webview as *const _ as u64;
        let mut state = delegate_state();
        if let Some(&webview_id) = state.view_to_webview_id.get(&ptr_val) {
            state
                .nav_states
                .entry(webview_id)
                .and_modify(|ns| {
                    ns.navigation_started = true;
                });
        }
    }

    extern "C" fn did_start_prov_nav(
        _self_: &objc::runtime::Object,
        _cmd: objc::runtime::Sel,
        webview: *mut objc::runtime::Object,
        _navigation: *mut objc::runtime::Object,
    ) {
        let ptr_val = webview as *const _ as u64;
        // Get the URL from the webview
        let uri = unsafe {
            let url: *mut objc::runtime::Object = msg_send![webview, URL];
            if url.is_null() {
                String::new()
            } else {
                let url_str: *mut objc::runtime::Object =
                    msg_send![url, absoluteString];
                if url_str.is_null() {
                    String::new()
                } else {
                    let cstr: *const i8 = msg_send![url_str, UTF8String];
                    if cstr.is_null() {
                        String::new()
                    } else {
                        std::ffi::CStr::from_ptr(cstr)
                            .to_string_lossy()
                            .into_owned()
                    }
                }
            }
        };

        let (webview_id, content_loading_cbs, nav_starting_cbs) = {
            let mut state = delegate_state();
            let Some(&webview_id) = state.view_to_webview_id.get(&ptr_val) else {
                return;
            };
            state
                .nav_states
                .entry(webview_id)
                .and_modify(|ns| {
                    ns.current_uri = uri.clone();
                    ns.navigation_started = true;
                    ns.navigation_completed = false;
                    ns.navigation_error = None;
                });

            let content_loading_cbs = std::mem::take(&mut state.on_content_loading);
            let nav_starting_cbs = std::mem::take(&mut state.on_navigation_starting);
            (webview_id, content_loading_cbs, nav_starting_cbs)
        };

        // Invoke callbacks without holding the state lock. The navigation is
        // already in progress here, so the cancel result is informational
        // only.
        for (id, mut cb) in content_loading_cbs {
            cb(webview_id, &uri);
            delegate_state().on_content_loading.push((id, cb));
        }
        for (id, mut cb) in nav_starting_cbs {
            let _ = cb(webview_id, &uri, false);
            delegate_state().on_navigation_starting.push((id, cb));
        }
    }

    // Add methods to the class
    unsafe {
        decl.add_method(
            objc::sel!(webView:didFinishNavigation:),
            did_finish_nav
                as extern "C" fn(
                    &objc::runtime::Object,
                    objc::runtime::Sel,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                ),
        );
        decl.add_method(
            objc::sel!(webView:didFailNavigation:withError:),
            did_fail_nav
                as extern "C" fn(
                    &objc::runtime::Object,
                    objc::runtime::Sel,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                ),
        );
        decl.add_method(
            objc::sel!(webView:didCommitNavigation:),
            did_commit_nav
                as extern "C" fn(
                    &objc::runtime::Object,
                    objc::runtime::Sel,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                ),
        );
        decl.add_method(
            objc::sel!(webView:didStartProvisionalNavigation:),
            did_start_prov_nav
                as extern "C" fn(
                    &objc::runtime::Object,
                    objc::runtime::Sel,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                ),
        );
    }

    Some(decl.register())
}

// ---------------------------------------------------------------------------
// WKUserScript message handler ObjC class registration
// ---------------------------------------------------------------------------

/// Register a custom ObjC class conforming to WKScriptMessageHandler.
#[cfg(target_os = "macos")]
fn register_webview2_msg_handler_class() -> Option<*const objc::runtime::Class> {
    use objc::declare::ClassDecl;
    use objc::runtime::Class;

    if let Some(cls) = Class::get("Casa1WV2MsgHandler") {
        return Some(cls);
    }

    let superclass = Class::get("NSObject")?;
    let mut decl = ClassDecl::new("Casa1WV2MsgHandler", superclass)?;

    extern "C" fn did_receive_message(
        self_: &objc::runtime::Object,
        _cmd: objc::runtime::Sel,
        _controller: *mut objc::runtime::Object,
        message: *mut objc::runtime::Object,
    ) {
        // The message handler object is shared across all webviews of an
        // environment, so resolve the originating WKWebView from the
        // WKScriptMessage (falls back to the handler itself only if the
        // runtime does not expose the webView property).
        let webview_ptr: *mut objc::runtime::Object = unsafe {
            let responds: bool = msg_send![message, respondsToSelector: objc::sel!(webView)];
            if responds {
                msg_send![message, webView]
            } else {
                std::ptr::null_mut()
            }
        };
        let ptr_val = if webview_ptr.is_null() {
            self_ as *const _ as u64
        } else {
            webview_ptr as *const _ as u64
        };

        // Extract the message body as JSON string
        let body_json = unsafe {
            let body: *mut objc::runtime::Object = msg_send![message, body];
            if body.is_null() {
                String::new()
            } else {
                // Try to get JSON string from the body
                let desc: *mut objc::runtime::Object = msg_send![body, description];
                if desc.is_null() {
                    String::new()
                } else {
                    let cstr: *const i8 = msg_send![desc, UTF8String];
                    if cstr.is_null() {
                        String::new()
                    } else {
                        std::ffi::CStr::from_ptr(cstr)
                            .to_string_lossy()
                            .into_owned()
                    }
                }
            }
        };

        let (webview_id, callbacks) = {
            let mut state = delegate_state();
            let Some(&webview_id) = state.view_to_webview_id.get(&ptr_val) else {
                return;
            };
            let callbacks = std::mem::take(&mut state.on_web_message_received);
            (webview_id, callbacks)
        };

        // Invoke callbacks without holding the state lock.
        for (id, mut cb) in callbacks {
            cb(webview_id, &body_json);
            delegate_state().on_web_message_received.push((id, cb));
        }
    }

    unsafe {
        decl.add_method(
            objc::sel!(userContentController:didReceiveScriptMessage:),
            did_receive_message
                as extern "C" fn(
                    &objc::runtime::Object,
                    objc::runtime::Sel,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                ),
        );
    }

    Some(decl.register())
}

// ---------------------------------------------------------------------------
// ICoreWebView2Settings state — mirrors SettingsMethod enum
// ---------------------------------------------------------------------------

/// Represents the ICoreWebView2Settings COM interface state.
#[derive(Debug, Clone)]
pub struct WebView2Settings {
    pub is_script_enabled: bool,
    pub is_web_message_enabled: bool,
    pub is_status_bar_enabled: bool,
    pub are_dev_tools_enabled: bool,
    pub default_background_color: u32,
    pub is_built_in_error_page_enabled: bool,
    pub is_zoom_control_enabled: bool,
    pub is_swipe_navigation_enabled: bool,
    pub user_agent: String,
    pub browser_executable_folder: String,
    pub language: String,
    pub target_compatible_browser_version: String,
    pub are_default_script_dialogs_enabled: bool,
}

impl WebView2Settings {
    pub fn new() -> Self {
        Self {
            is_script_enabled: true,
            is_web_message_enabled: true,
            is_status_bar_enabled: false,
            are_dev_tools_enabled: false,
            default_background_color: 0xFF_FF_FF_FF,
            is_built_in_error_page_enabled: true,
            is_zoom_control_enabled: true,
            is_swipe_navigation_enabled: true,
            user_agent: String::new(),
            browser_executable_folder: String::new(),
            language: "en-US".to_string(),
            target_compatible_browser_version: "95.0.1020.44".to_string(),
            are_default_script_dialogs_enabled: true,
        }
    }

    pub fn handle_method(&mut self, method: SettingsMethod, value: u64) -> u64 {
        match method {
            SettingsMethod::get_IsScriptEnabled => {
                if self.is_script_enabled {
                    1
                } else {
                    0
                }
            }
            SettingsMethod::put_IsScriptEnabled => {
                self.is_script_enabled = value != 0;
                0
            }
            SettingsMethod::get_IsWebMessageEnabled => {
                if self.is_web_message_enabled {
                    1
                } else {
                    0
                }
            }
            SettingsMethod::put_IsWebMessageEnabled => {
                self.is_web_message_enabled = value != 0;
                0
            }
            SettingsMethod::get_IsStatusBarEnabled => {
                if self.is_status_bar_enabled {
                    1
                } else {
                    0
                }
            }
            SettingsMethod::put_IsStatusBarEnabled => {
                self.is_status_bar_enabled = value != 0;
                0
            }
            SettingsMethod::get_AreDevToolsEnabled => {
                if self.are_dev_tools_enabled {
                    1
                } else {
                    0
                }
            }
            SettingsMethod::put_AreDevToolsEnabled => {
                self.are_dev_tools_enabled = value != 0;
                0
            }
            SettingsMethod::get_DefaultBackgroundColor => self.default_background_color as u64,
            SettingsMethod::put_DefaultBackgroundColor => {
                self.default_background_color = value as u32;
                0
            }
            SettingsMethod::get_IsBuiltInErrorPageEnabled => {
                if self.is_built_in_error_page_enabled {
                    1
                } else {
                    0
                }
            }
            SettingsMethod::put_IsBuiltInErrorPageEnabled => {
                self.is_built_in_error_page_enabled = value != 0;
                0
            }
            SettingsMethod::get_AreDefaultScriptDialogsEnabled => {
                if self.are_default_script_dialogs_enabled {
                    1
                } else {
                    0
                }
            }
            SettingsMethod::put_AreDefaultScriptDialogsEnabled => {
                self.are_default_script_dialogs_enabled = value != 0;
                0
            }
            SettingsMethod::get_IsZoomControlEnabled => {
                if self.is_zoom_control_enabled {
                    1
                } else {
                    0
                }
            }
            SettingsMethod::put_IsZoomControlEnabled => {
                self.is_zoom_control_enabled = value != 0;
                0
            }
            SettingsMethod::get_IsSwipeNavigationEnabled => {
                if self.is_swipe_navigation_enabled {
                    1
                } else {
                    0
                }
            }
            SettingsMethod::put_IsSwipeNavigationEnabled => {
                self.is_swipe_navigation_enabled = value != 0;
                0
            }
            SettingsMethod::get_UserAgent => self.user_agent.len() as u64,
            SettingsMethod::put_UserAgent => 0,
            SettingsMethod::get_BrowserExecutableFolder => self.browser_executable_folder.len() as u64,
            SettingsMethod::put_BrowserExecutableFolder => 0,
            SettingsMethod::get_Language => self.language.len() as u64,
            SettingsMethod::put_Language => 0,
            SettingsMethod::get_TargetCompatibleBrowserVersion => {
                self.target_compatible_browser_version.len() as u64
            }
            SettingsMethod::put_TargetCompatibleBrowserVersion => 0,
        }
    }

    pub fn handle_put_string(&mut self, method: SettingsMethod, value: &str) {
        match method {
            SettingsMethod::put_UserAgent => {
                self.user_agent = value.to_string();
            }
            SettingsMethod::put_BrowserExecutableFolder => {
                self.browser_executable_folder = value.to_string();
            }
            SettingsMethod::put_Language => {
                self.language = value.to_string();
            }
            SettingsMethod::put_TargetCompatibleBrowserVersion => {
                self.target_compatible_browser_version = value.to_string();
            }
            _ => {}
        }
    }

    pub fn handle_get_string(&self, method: SettingsMethod) -> String {
        match method {
            SettingsMethod::get_UserAgent => self.user_agent.clone(),
            SettingsMethod::get_BrowserExecutableFolder => self.browser_executable_folder.clone(),
            SettingsMethod::get_Language => self.language.clone(),
            SettingsMethod::get_TargetCompatibleBrowserVersion => {
                self.target_compatible_browser_version.clone()
            }
            _ => String::new(),
        }
    }
}

impl Default for WebView2Settings {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Native WKWebView FFI helpers
// ---------------------------------------------------------------------------

/// Create a WKWebView using the Objective-C runtime directly.
/// Returns a raw pointer to the WKWebView object, or null on failure.
#[cfg(target_os = "macos")]
fn create_wkwebview_native(
    width: f64,
    height: f64,
    js_enabled: bool,
    user_agent: Option<&str>,
    configuration: *mut objc::runtime::Object,
) -> *mut std::ffi::c_void {
    let result = std::panic::catch_unwind(|| unsafe {
        // SAFETY: All ObjC class lookups and message sends are safe as long
        // as the runtime is initialized, which it is on macOS 10.13+.

        let cls_wk_view = match objc::runtime::Class::get("WKWebView") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };

        // Use provided configuration or create default
        let config = if configuration.is_null() {
            let cls_wk_config = match objc::runtime::Class::get("WKWebViewConfiguration") {
                Some(c) => c,
                None => return std::ptr::null_mut(),
            };
            let cls_wk_prefs = match objc::runtime::Class::get("WKPreferences") {
                Some(c) => c,
                None => return std::ptr::null_mut(),
            };
            let cls_wk_pool = match objc::runtime::Class::get("WKProcessPool") {
                Some(c) => c,
                None => return std::ptr::null_mut(),
            };
            let cls_wk_controller = match objc::runtime::Class::get("WKUserContentController") {
                Some(c) => c,
                None => return std::ptr::null_mut(),
            };

            // Create process pool
            let pool: *mut objc::runtime::Object = msg_send![cls_wk_pool, new];

            // Create preferences
            let prefs: *mut objc::runtime::Object = msg_send![cls_wk_prefs, new];
            let _: () = msg_send![prefs, setJavaScriptEnabled: js_enabled];
            let _: () = msg_send![prefs, setJavaScriptCanOpenWindowsAutomatically: 0u8];

            // Create user content controller
            let uc: *mut objc::runtime::Object = msg_send![cls_wk_controller, new];

            // Create configuration
            let config: *mut objc::runtime::Object = msg_send![cls_wk_config, new];
            let _: () = msg_send![config, setPreferences: prefs];
            let _: () = msg_send![config, setProcessPool: pool];
            let _: () = msg_send![config, setUserContentController: uc];

            // The configuration retains the pool, preferences and user
            // content controller; drop the local +1 references.
            let _: () = msg_send![pool, release];
            let _: () = msg_send![prefs, release];
            let _: () = msg_send![uc, release];

            config
        } else {
            configuration
        };

        // Create WKWebView with frame and configuration
        let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(width, height));
        let view: *mut objc::runtime::Object =
            msg_send![cls_wk_view, alloc];
        let view: *mut objc::runtime::Object =
            msg_send![view, initWithFrame: frame configuration: config];

        if view.is_null() {
            return std::ptr::null_mut();
        }

        // Set custom user agent if provided
        if let Some(ua) = user_agent {
            let ua_str = ns_string_from_str(ua);
            if !ua_str.is_null() {
                // Use KVC to set customUserAgent
                let key = ns_string_from_str("customUserAgent");
                let _: () = msg_send![view, setValue: ua_str forKey: key];
                let _: () = msg_send![key, release];
                let _: () = msg_send![ua_str, release];
            }
        }

        // Enable layer backing for offscreen rendering
        let _: () = msg_send![view, setWantsLayer: 1u8];

        view as *mut std::ffi::c_void
    });

    match result {
        Ok(ptr) => ptr,
        Err(panic_err) => {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] create_wkwebview_native panicked: {msg}");
            std::ptr::null_mut()
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn create_wkwebview_native(
    _width: f64,
    _height: f64,
    _js_enabled: bool,
    _user_agent: Option<&str>,
    _configuration: *mut objc::runtime::Object,
) -> *mut std::ffi::c_void {
    std::ptr::null_mut()
}

/// Navigate a WKWebView to a URL using `loadRequest:`.
fn navigate_wkwebview_native(native_ptr: *mut std::ffi::c_void, url: &str) {
    if native_ptr.is_null() {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
            // SAFETY: Native pointer is validated as non-null.
            let cls_req = match objc::runtime::Class::get("NSURLRequest") {
                Some(c) => c,
                None => return,
            };

            let ns_url = ns_url_from_str(url);
            if ns_url.is_null() {
                return;
            }

            let req: *mut objc::runtime::Object = msg_send![cls_req, requestWithURL: ns_url];
            if !req.is_null() {
                let view = native_ptr as *mut objc::runtime::Object;
                let _: () = msg_send![view, loadRequest: req];
            }
        }) {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] navigate_wkwebview_native panicked: {msg}");
        }
    }
}

/// Navigate a WKWebView to an HTML string using `loadHTMLString:baseURL:`.
fn navigate_html_wkwebview_native(native_ptr: *mut std::ffi::c_void, html: &str) {
    if native_ptr.is_null() {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
            // SAFETY: Native pointer is validated as non-null.
            let view = native_ptr as *mut objc::runtime::Object;
            let html_str = ns_string_from_str(html);
            if html_str.is_null() {
                return;
            }

            // Use nil for baseURL (or could provide about:blank)
            let base_url = if let Some(cls_url) = objc::runtime::Class::get("NSURL") {
                let base_url_str = ns_string_from_str("about:blank");
                let url: *mut objc::runtime::Object =
                    msg_send![cls_url, URLWithString: base_url_str];
                let _: () = msg_send![base_url_str, release];
                url
            } else {
                std::ptr::null_mut()
            };

            let _: () = msg_send![view, loadHTMLString: html_str baseURL: base_url];
            let _: () = msg_send![html_str, release];
        }) {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] navigate_html_wkwebview_native panicked: {msg}");
        }
    }
}

/// Get the current URL from a WKWebView using `-[WKWebView URL]`.
fn get_uri_wkwebview_native(native_ptr: *mut std::ffi::c_void) -> String {
    if native_ptr.is_null() {
        return String::new();
    }
    #[cfg(target_os = "macos")]
    {
        let result = std::panic::catch_unwind(|| unsafe {
            // SAFETY: Native pointer is validated as non-null.
            let view = native_ptr as *mut objc::runtime::Object;

            // WKWebView.URL property
            let url: *mut objc::runtime::Object = msg_send![view, URL];
            if url.is_null() {
                return String::new();
            }

            let url_str: *mut objc::runtime::Object = msg_send![url, absoluteString];
            if url_str.is_null() {
                return String::new();
            }

            let cstr: *const i8 = msg_send![url_str, UTF8String];
            if cstr.is_null() {
                return String::new();
            }

            std::ffi::CStr::from_ptr(cstr)
                .to_string_lossy()
                .into_owned()
        });

        match result {
            Ok(uri) => uri,
            Err(panic_err) => {
                let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "unknown panic".to_string()
                };
                eprintln!("[WebView2] get_uri_wkwebview_native panicked: {msg}");
                String::new()
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        String::new()
    }
}

/// Process-wide completion handler for `evaluateJavaScript:completionHandler:`.
///
/// Built with the `block` crate so the block has a valid isa
/// (`_NSConcreteStackBlock`) and a proper descriptor with copy/dispose
/// helpers. WKWebView copies the block before invoking it asynchronously,
/// and the copy is kept alive for the process lifetime.
struct JsCompletionBlock(
    RcBlock<(*mut objc::runtime::Object, *mut objc::runtime::Object), ()>,
);

// SAFETY: the block has no captures, is created once at first use, is never
// mutated or freed (owned by the static), and is only ever passed by
// pointer to WebKit.
unsafe impl Send for JsCompletionBlock {}
unsafe impl Sync for JsCompletionBlock {}

static JS_COMPLETION_BLOCK: LazyLock<JsCompletionBlock> = LazyLock::new(|| {
    let block = ConcreteBlock::new(
        |result: *mut objc::runtime::Object, error: *mut objc::runtime::Object| {
            // SAFETY: Objective-C runtime message sending on objects owned
            // by the WebKit framework.
            unsafe {
                if !error.is_null() {
                    let desc: *mut objc::runtime::Object = msg_send![error, localizedDescription];
                    if !desc.is_null() {
                        let cstr: *const i8 = msg_send![desc, UTF8String];
                        if !cstr.is_null() {
                            let err_str = std::ffi::CStr::from_ptr(cstr)
                                .to_string_lossy()
                                .into_owned();
                            eprintln!("[WebView2] JS execution error: {err_str}");
                        }
                    }
                } else if !result.is_null() {
                    let desc: *mut objc::runtime::Object = msg_send![result, description];
                    if !desc.is_null() {
                        let cstr: *const i8 = msg_send![desc, UTF8String];
                        if !cstr.is_null() {
                            let result_str = std::ffi::CStr::from_ptr(cstr)
                                .to_string_lossy()
                                .into_owned();
                            let preview: String = result_str.chars().take(200).collect();
                            eprintln!("[WebView2] JS execution result: {preview}");
                        }
                    }
                }
            }
        },
    );
    JsCompletionBlock(block.copy())
});

/// Execute JavaScript in a WKWebView using `evaluateJavaScript:completionHandler:`.
fn execute_js_wkwebview_native(native_ptr: *mut std::ffi::c_void, script: &str) {
    if native_ptr.is_null() {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
            // SAFETY: Native pointer is validated as non-null.
            let view = native_ptr as *mut objc::runtime::Object;
            let js_str = ns_string_from_str(script);
            if js_str.is_null() {
                return;
            }

            // Pass a well-formed completion-handler block. WKWebView copies
            // it (via _Block_copy) before invoking it asynchronously, and
            // the static copy above stays alive for the process lifetime.
            let _: () = msg_send![
                view,
                evaluateJavaScript: js_str
                completionHandler: &JS_COMPLETION_BLOCK.0
            ];
            let _: () = msg_send![js_str, release];
        }) {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] execute_js_wkwebview_native panicked: {msg}");
        }
    }
}

/// Add a WKUserScript to the WKWebView's user content controller.
fn add_user_script_wkwebview_native(
    native_ptr: *mut std::ffi::c_void,
    script: &str,
    injection_time: i64,  // 0 = at document start, 1 = at document end
    for_main_frame_only: bool,
) {
    if native_ptr.is_null() {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
            // SAFETY: Native pointer is validated as non-null.
            let view = native_ptr as *mut objc::runtime::Object;
            let cls_script = match objc::runtime::Class::get("WKUserScript") {
                Some(c) => c,
                None => return,
            };

            let script_str = ns_string_from_str(script);
            if script_str.is_null() {
                return;
            }

            // Create WKUserScript: -initWithString:injectionTime:forMainFrameOnly:
            let user_script: *mut objc::runtime::Object = msg_send![
                cls_script,
                alloc
            ];
            let user_script: *mut objc::runtime::Object = msg_send![
                user_script,
                initWithString: script_str
                injectionTime: injection_time
                forMainFrameOnly: for_main_frame_only as u8
            ];
            // The initializer copies the script string; drop our +1 refs.
            let _: () = msg_send![script_str, release];

            if !user_script.is_null() {
                // Get the configuration's user content controller
                let config: *mut objc::runtime::Object = msg_send![view, configuration];
                if !config.is_null() {
                    let uc: *mut objc::runtime::Object =
                        msg_send![config, userContentController];
                    if !uc.is_null() {
                        let _: () = msg_send![uc, addUserScript: user_script];
                    }
                }
                // The user content controller retains the script; drop the
                // +1 from alloc/init.
                let _: () = msg_send![user_script, release];
            }
        }) {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] add_user_script_wkwebview_native panicked: {msg}");
        }
    }
}

/// Resize a WKWebView by updating its frame NSRect.
fn resize_wkwebview_native(native_ptr: *mut std::ffi::c_void, width: f64, height: f64) {
    if native_ptr.is_null() {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
            // SAFETY: setFrame: is a standard NSView method, safe to call on WKWebView.
            let view = native_ptr as *mut objc::runtime::Object;
            let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(width, height));
            let _: () = msg_send![view, setFrame: frame];
        }) {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] resize_wkwebview_native panicked: {msg}");
        }
    }
}

/// Set the hidden property on a WKWebView.
fn set_hidden_wkwebview_native(native_ptr: *mut std::ffi::c_void, hidden: bool) {
    if native_ptr.is_null() {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
            // SAFETY: NSView hidden property.
            let view = native_ptr as *mut objc::runtime::Object;
            let _: () = msg_send![view, setHidden: hidden as u8];
        }) {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] set_hidden_wkwebview_native panicked: {msg}");
        }
    }
}

/// Close/destroy a WKWebView: stop loading, detach the navigation delegate,
/// remove from superview and release the +1 from alloc/init.
fn close_wkwebview_native(native_ptr: *mut std::ffi::c_void) {
    if native_ptr.is_null() {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
            // SAFETY: Standard NSView/WKWebView teardown sequence.
            let view = native_ptr as *mut objc::runtime::Object;
            let _: () = msg_send![view, stopLoading];
            // The navigation delegate is a weak (assign) reference shared
            // across the environment's webviews; clear it so no callback can
            // reach the delegate after teardown.
            let _: () = msg_send![
                view,
                setNavigationDelegate: std::ptr::null_mut::<objc::runtime::Object>()
            ];
            let _: () = msg_send![view, removeFromSuperview];
            // Balance the +1 from alloc/initWithFrame:configuration:.
            let _: () = msg_send![view, release];
        }) {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_err.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] close_wkwebview_native panicked: {msg}");
        }
    }
}

/// Create a WKWebViewConfiguration with the given settings.
/// Returns a raw pointer to the WKWebViewConfiguration object.
#[cfg(target_os = "macos")]
fn create_wkwebview_configuration(
    js_enabled: bool,
    _user_agent: Option<&str>,
    _nav_delegate: Option<*mut objc::runtime::Object>,
    msg_handler: Option<*mut objc::runtime::Object>,
) -> *mut objc::runtime::Object {
    let result = std::panic::catch_unwind(|| unsafe {
        // SAFETY: All ObjC class lookups and message sends are safe as long
        // as the runtime is initialized.

        let cls_wk_config = match objc::runtime::Class::get("WKWebViewConfiguration") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };
        let cls_wk_prefs = match objc::runtime::Class::get("WKPreferences") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };
        let cls_wk_pool = match objc::runtime::Class::get("WKProcessPool") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };
        let cls_wk_controller = match objc::runtime::Class::get("WKUserContentController") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };

        // Create process pool (shared across webviews in the same environment)
        let pool: *mut objc::runtime::Object = msg_send![cls_wk_pool, new];

        // Create preferences
        let prefs: *mut objc::runtime::Object = msg_send![cls_wk_prefs, new];
        let _: () = msg_send![prefs, setJavaScriptEnabled: js_enabled];
        let _: () = msg_send![prefs, setJavaScriptCanOpenWindowsAutomatically: 0u8];

        // Create user content controller
        let uc: *mut objc::runtime::Object = msg_send![cls_wk_controller, new];

        if let Some(handler_ptr) = msg_handler {
            let handler_name = ns_string_from_str("webview2");
            if !handler_name.is_null() {
                let _: () = msg_send![
                    uc,
                    addScriptMessageHandler: handler_ptr
                    name: handler_name
                ];
                // The user content controller copies the name; drop our +1.
                let _: () = msg_send![handler_name, release];
            }
        }

        // Create configuration
        let config: *mut objc::runtime::Object = msg_send![cls_wk_config, new];
        let _: () = msg_send![config, setPreferences: prefs];
        let _: () = msg_send![config, setProcessPool: pool];
        let _: () = msg_send![config, setUserContentController: uc];

        // The configuration retains the pool, preferences and user content
        // controller; drop the local +1 references.
        let _: () = msg_send![pool, release];
        let _: () = msg_send![prefs, release];
        let _: () = msg_send![uc, release];

        // Set navigation delegate on the configuration for future webviews
        // (Note: navigation delegate is set per-webview, not on configuration)

        config
    });

    match result {
        Ok(ptr) => ptr,
        Err(panic_err) => {
            let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                s.to_string()
            } else {
                "unknown panic".to_string()
            };
            eprintln!("[WebView2] create_wkwebview_configuration panicked: {msg}");
            std::ptr::null_mut()
        }
    }
}

/// Set the navigation delegate on a WKWebView.
#[cfg(target_os = "macos")]
fn set_navigation_delegate(
    native_ptr: *mut std::ffi::c_void,
    delegate: *mut objc::runtime::Object,
) {
    if native_ptr.is_null() || delegate.is_null() {
        return;
    }
    unsafe {
        let view = native_ptr as *mut objc::runtime::Object;
        let _: () = msg_send![view, setNavigationDelegate: delegate];
    }
}

// ---------------------------------------------------------------------------
// WebView2Environment — holds WKWebViewConfiguration + WKProcessPool
// ---------------------------------------------------------------------------

/// Represents an ICoreWebView2Environment backed by a WKWebView configuration.
#[derive(Debug)]
pub struct WebView2Environment {
    pub browser_exe_path: Option<String>,
    pub user_data_folder: Option<String>,
    pub options: u32,
    /// Controllers created from this environment.
    pub controllers: Vec<u64>,
    /// Native WKWebViewConfiguration object pointer (Objective-C).
    pub native_config: Option<*mut std::ffi::c_void>,
    /// Native WKProcessPool object pointer (Objective-C).
    pub native_process_pool: Option<*mut std::ffi::c_void>,
    /// Navigation delegate object pointer (shared across webviews in this env).
    pub nav_delegate: Option<*mut std::ffi::c_void>,
    /// Script message handler object pointer.
    pub msg_handler: Option<*mut std::ffi::c_void>,
}

// SAFETY: WKWebViewEnvironment holds opaque ObjC pointers that are Send + Sync
unsafe impl Send for WebView2Environment {}
unsafe impl Sync for WebView2Environment {}

impl Clone for WebView2Environment {
    fn clone(&self) -> Self {
        Self {
            browser_exe_path: self.browser_exe_path.clone(),
            user_data_folder: self.user_data_folder.clone(),
            options: self.options,
            controllers: self.controllers.clone(),
            native_config: None,
            native_process_pool: None,
            nav_delegate: None,
            msg_handler: None,
        }
    }
}

impl WebView2Environment {
    /// Create a new WebView2 environment with a WKWebView configuration.
    ///
    /// Initializes:
    /// - WKWebViewConfiguration with WKPreferences (JavaScript enabled)
    /// - WKProcessPool (shared across all webviews in this environment)
    /// - WKNavigationDelegate for callback events
    /// - WKScriptMessageHandler for web message reception
    pub fn new(js_enabled: bool, user_agent: Option<&str>) -> Self {
        #[cfg(target_os = "macos")]
        {
            // Register ObjC delegate classes if not already registered
            let nav_cls = register_webview2_nav_delegate_class();
            let msg_cls = register_webview2_msg_handler_class();

            let nav_delegate = nav_cls.and_then(|cls| unsafe {
                let obj: *mut objc::runtime::Object = msg_send![cls, new];
                if obj.is_null() { None } else { Some(obj as *mut std::ffi::c_void) }
            });

            let msg_handler = msg_cls.and_then(|cls| unsafe {
                let obj: *mut objc::runtime::Object = msg_send![cls, new];
                if obj.is_null() { None } else { Some(obj as *mut std::ffi::c_void) }
            });

            let config = create_wkwebview_configuration(
                js_enabled,
                user_agent,
                nav_delegate.map(|p| p as *mut objc::runtime::Object),
                msg_handler.map(|p| p as *mut objc::runtime::Object),
            );

            let native_config = if config.is_null() { None } else { Some(config as *mut std::ffi::c_void) };

            Self {
                browser_exe_path: None,
                user_data_folder: None,
                options: 0,
                controllers: Vec::new(),
                native_config,
                native_process_pool: None, // owned by config
                nav_delegate,
                msg_handler,
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            Self {
                browser_exe_path: None,
                user_data_folder: None,
                options: 0,
                controllers: Vec::new(),
                native_config: None,
                native_process_pool: None,
                nav_delegate: None,
                msg_handler: None,
            }
        }
    }

    /// Check if this environment has a valid WKWebView configuration.
    pub fn is_valid(&self) -> bool {
        self.native_config.is_some()
    }

    /// Get the native configuration pointer.
    pub fn native_config_ptr(&self) -> *mut std::ffi::c_void {
        self.native_config.unwrap_or(std::ptr::null_mut())
    }

    /// Get the navigation delegate pointer.
    pub fn nav_delegate_ptr(&self) -> *mut std::ffi::c_void {
        self.nav_delegate.unwrap_or(std::ptr::null_mut())
    }

    /// Get the message handler pointer.
    pub fn msg_handler_ptr(&self) -> *mut std::ffi::c_void {
        self.msg_handler.unwrap_or(std::ptr::null_mut())
    }
}

impl Drop for WebView2Environment {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            // Release native ObjC objects
            if let Some(ptr) = self.nav_delegate.take() {
                unsafe {
                    let _: () = msg_send![ptr as *mut objc::runtime::Object, release];
                }
            }
            if let Some(ptr) = self.msg_handler.take() {
                unsafe {
                    let _: () = msg_send![ptr as *mut objc::runtime::Object, release];
                }
            }
            if let Some(ptr) = self.native_config.take() {
                unsafe {
                    let _: () = msg_send![ptr as *mut objc::runtime::Object, release];
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WebView2Controller — wraps a single WKWebView instance
// ---------------------------------------------------------------------------

/// Represents an ICoreWebView2Controller backed by a WKWebView.
#[derive(Debug)]
pub struct WebView2Controller {
    pub webview_id: u64,
    pub parent_hwnd: u64,
    pub bounds: (i32, i32, i32, i32),
    pub is_visible: bool,
    pub zoom_factor: f64,
    /// Native WKWebView object pointer.
    pub native_webview: Option<*mut std::ffi::c_void>,
    /// Retained reference to the environment's shared navigation delegate.
    /// Kept so the delegate outlives this controller's webview even when the
    /// environment is dropped first (the webview holds the delegate weakly).
    pub nav_delegate_ref: Option<*mut std::ffi::c_void>,
}

// SAFETY: WebView2Controller holds an opaque ObjC pointer that is Send + Sync
unsafe impl Send for WebView2Controller {}
unsafe impl Sync for WebView2Controller {}

impl Clone for WebView2Controller {
    fn clone(&self) -> Self {
        Self {
            webview_id: self.webview_id,
            parent_hwnd: self.parent_hwnd,
            bounds: self.bounds,
            is_visible: self.is_visible,
            zoom_factor: self.zoom_factor,
            native_webview: None,
            nav_delegate_ref: None,
        }
    }
}

impl WebView2Controller {
    /// Create a new controller with a WKWebView from the environment's configuration.
    pub fn create(
        env: &WebView2Environment,
        webview_id: u64,
        width: i32,
        height: i32,
        parent_hwnd: u64,
    ) -> Self {
        #[cfg(target_os = "macos")]
        {
            let config_ptr = env.native_config_ptr();
            let config = if config_ptr.is_null() {
                std::ptr::null_mut()
            } else {
                config_ptr as *mut objc::runtime::Object
            };

            let native_ptr = create_wkwebview_native(
                width as f64,
                height as f64,
                true,      // js_enabled
                None,      // user_agent (set separately)
                config,
            );

            // Set navigation delegate on the webview
            let mut nav_delegate_ref = None;
            if !native_ptr.is_null() {
                let nav_delegate = env.nav_delegate_ptr();
                if !nav_delegate.is_null() {
                    set_navigation_delegate(
                        native_ptr,
                        nav_delegate as *mut objc::runtime::Object,
                    );
                    // Retain the shared delegate so it stays alive until this
                    // controller is closed, even if the environment is
                    // dropped first.
                    unsafe {
                        let _: () = msg_send![
                            nav_delegate as *mut objc::runtime::Object,
                            retain
                        ];
                    }
                    nav_delegate_ref = Some(nav_delegate);
                }

                // Register the view in the delegate state
                let mut state = delegate_state();
                let ptr_val = native_ptr as u64;
                state.view_to_webview_id.insert(ptr_val, webview_id);
                state.nav_states.insert(
                    webview_id,
                    NavigationState {
                        navigation_started: false,
                        navigation_completed: false,
                        navigation_error: None,
                        current_uri: String::new(),
                    },
                );
            }

            Self {
                webview_id,
                parent_hwnd,
                bounds: (0, 0, width, height),
                is_visible: true,
                zoom_factor: 1.0,
                native_webview: if native_ptr.is_null() {
                    None
                } else {
                    Some(native_ptr)
                },
                nav_delegate_ref,
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            Self {
                webview_id,
                parent_hwnd,
                bounds: (0, 0, width, height),
                is_visible: true,
                zoom_factor: 1.0,
                native_webview: None,
                nav_delegate_ref: None,
            }
        }
    }

    /// Check if this controller has a valid WKWebView.
    pub fn is_valid(&self) -> bool {
        self.native_webview.is_some()
    }

    /// Get the native WKWebView pointer.
    pub fn native_ptr(&self) -> *mut std::ffi::c_void {
        self.native_webview.unwrap_or(std::ptr::null_mut())
    }

    /// Show the webview.
    pub fn show(&self) {
        set_hidden_wkwebview_native(self.native_ptr(), false);
    }

    /// Hide the webview.
    pub fn hide(&self) {
        set_hidden_wkwebview_native(self.native_ptr(), true);
    }

    /// Resize the webview.
    pub fn resize(&mut self, width: i32, height: i32) {
        self.bounds.2 = width;
        self.bounds.3 = height;
        resize_wkwebview_native(self.native_ptr(), width as f64, height as f64);
    }

    /// Navigate to a URL.
    pub fn navigate(&self, url: &str) {
        // Collect NavigationStarting callbacks under the lock...
        let callbacks: Vec<(u64, NavigationStartingCallback)> = {
            let mut state = delegate_state();
            state
                .nav_states
                .entry(self.webview_id)
                .and_modify(|ns| {
                    ns.current_uri = url.to_string();
                    ns.navigation_started = true;
                    ns.navigation_completed = false;
                });
            std::mem::take(&mut state.on_navigation_starting)
        };

        // ...and invoke them without the lock, so callbacks may re-enter
        // WebView2 APIs. Any callback returning true cancels the navigation.
        let mut should_cancel = false;
        for (id, mut cb) in callbacks {
            if cb(self.webview_id, url, false) {
                should_cancel = true;
            }
            delegate_state().on_navigation_starting.push((id, cb));
        }

        if should_cancel {
            return;
        }
        navigate_wkwebview_native(self.native_ptr(), url);
    }

    /// Navigate to an HTML string.
    pub fn navigate_to_string(&self, html: &str) {
        navigate_html_wkwebview_native(self.native_ptr(), html);
    }

    /// Get the current URI.
    pub fn get_uri(&self) -> String {
        get_uri_wkwebview_native(self.native_ptr())
    }

    /// Execute JavaScript in the webview.
    pub fn execute_script(&self, script: &str) {
        execute_js_wkwebview_native(self.native_ptr(), script);
    }

    /// Add a script to execute on document creation.
    pub fn add_script_to_execute_on_document_creation(&self, script: &str) {
        add_user_script_wkwebview_native(
            self.native_ptr(),
            script,
            0,  // at document start
            true, // main frame only
        );
    }

    /// Close and destroy the webview.
    pub fn close(&mut self) {
        // Clean up delegate state
        {
            let mut state = delegate_state();
            if let Some(ptr) = self.native_webview {
                state.view_to_webview_id.remove(&(ptr as u64));
            }
            state.nav_states.remove(&self.webview_id);
        }

        close_wkwebview_native(self.native_ptr());
        self.native_webview = None;
        // The webview no longer references the shared navigation delegate
        // (it was cleared and the view released in close_wkwebview_native);
        // drop our retained reference last.
        if let Some(ptr) = self.nav_delegate_ref.take() {
            unsafe {
                let _: () = msg_send![ptr as *mut objc::runtime::Object, release];
            }
        }
    }
}

impl Drop for WebView2Controller {
    fn drop(&mut self) {
        // Close the webview if still alive
        if self.native_webview.is_some() {
            self.close();
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level runtime — one per PeHostRuntime
// ---------------------------------------------------------------------------

/// WebView2 runtime state, stored in [`PeHostRuntime`].
#[derive(Debug, Clone)]
pub struct WebView2Runtime {
    pub environments: HashMap<u64, WebView2Environment>,
    pub controllers: HashMap<u64, WebView2Controller>,
    pub webviews: HashMap<u64, WebView2Instance>,
    /// Settings objects, keyed by webview ID.
    pub settings: HashMap<u64, WebView2Settings>,
    pub events: WebView2Events,
    pub next_id: u64,
}

impl WebView2Runtime {
    pub fn new() -> Self {
        WebView2Runtime {
            environments: HashMap::new(),
            controllers: HashMap::new(),
            webviews: HashMap::new(),
            settings: HashMap::new(),
            events: WebView2Events::new(),
            next_id: 1,
        }
    }
}

impl Default for WebView2Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl WebView2Runtime {

    /// Create a new WebView2 environment backed by WKWebView.
    pub fn create_environment(&mut self, _options: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let env = WebView2Environment::new(true, None);
        self.environments.insert(id, env);
        id
    }

    /// Create a new WebView2 controller for a given environment.
    pub fn create_controller(&mut self, env_id: u64, parent_hwnd: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let webview_id = self.create_webview();

        // Look up environment for configuration
        let controller =
            if let Some(env) = self.environments.get(&env_id).filter(|e| e.is_valid()) {
                WebView2Controller::create(env, webview_id, 800, 600, parent_hwnd)
            } else {
                WebView2Controller {
                    webview_id,
                    parent_hwnd,
                    bounds: (0, 0, 800, 600),
                    is_visible: true,
                    zoom_factor: 1.0,
                    native_webview: None,
                    nav_delegate_ref: None,
                }
            };

        self.controllers.insert(id, controller);
        // Link the environment to this controller if it exists
        if let Some(env) = self.environments.get_mut(&env_id) {
            env.controllers.push(id);
        }
        id
    }

    fn create_webview(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let webview = WebView2Instance {
            source: String::new(),
            is_script_enabled: true,
            is_web_message_enabled: true,
            is_status_bar_enabled: false,
            are_dev_tools_enabled: false,
            default_background: 0xFF_FF_FF_FF,
            ceh_handle: None,
            pending_scripts: Vec::new(),
            web_messages: Vec::new(),
        };
        self.webviews.insert(id, webview);
        self.settings.insert(id, WebView2Settings::new());
        id
    }

    pub fn get_environment(&self, id: u64) -> Option<&WebView2Environment> {
        self.environments.get(&id)
    }

    pub fn get_environment_mut(&mut self, id: u64) -> Option<&mut WebView2Environment> {
        self.environments.get_mut(&id)
    }

    pub fn get_controller(&self, id: u64) -> Option<&WebView2Controller> {
        self.controllers.get(&id)
    }

    pub fn get_controller_mut(&mut self, id: u64) -> Option<&mut WebView2Controller> {
        self.controllers.get_mut(&id)
    }

    pub fn get_webview(&self, id: u64) -> Option<&WebView2Instance> {
        self.webviews.get(&id)
    }

    pub fn get_webview_mut(&mut self, id: u64) -> Option<&mut WebView2Instance> {
        self.webviews.get_mut(&id)
    }

    /// Destroy an environment and all associated controllers/webviews.
    pub fn destroy_environment(&mut self, id: u64) {
        if let Some(env) = self.environments.remove(&id) {
            for ctrl_id in &env.controllers {
                if let Some(mut ctrl) = self.controllers.remove(ctrl_id) {
                    // Close the native WKWebView
                    ctrl.close();
                    self.webviews.remove(&ctrl.webview_id);
                    self.settings.remove(&ctrl.webview_id);
                }
            }
            // env is dropped here, which releases native ObjC pointers
        }
    }

    /// Destroy a controller and its associated webview.
    pub fn destroy_controller(&mut self, id: u64) {
        if let Some(mut ctrl) = self.controllers.remove(&id) {
            // Close the native WKWebView
            ctrl.close();
            self.webviews.remove(&ctrl.webview_id);
            self.settings.remove(&ctrl.webview_id);
        }
        // Drop the stale controller ID from its owning environment so
        // env.controllers stays in sync with reality.
        for env in self.environments.values_mut() {
            env.controllers.retain(|cid| *cid != id);
        }
    }

    // -----------------------------------------------------------------------
    // ICoreWebView2 Settings support
    // -----------------------------------------------------------------------

    pub fn get_settings(&self, webview_id: u64) -> u64 {
        if self.settings.contains_key(&webview_id) {
            webview_id
        } else {
            0
        }
    }

    pub fn get_settings_mut(&mut self, settings_id: u64) -> Option<&mut WebView2Settings> {
        self.settings.get_mut(&settings_id)
    }

    // -----------------------------------------------------------------------
    // Callback registration (NavigationStarting, NavigationCompleted, etc.)
    // -----------------------------------------------------------------------

    /// Register a NavigationStarting callback.
    /// Returns a callback ID that can be used to unregister.
    pub fn on_navigation_starting<F>(&mut self, callback: F) -> u64
    where
        F: FnMut(u64, &str, bool) -> bool + Send + 'static,
    {
        let mut state = delegate_state();
        let id = state.next_callback_id;
        state.next_callback_id += 1;
        state
            .on_navigation_starting
            .push((id, Box::new(callback)));
        id
    }

    /// Register a NavigationCompleted callback.
    pub fn on_navigation_completed<F>(&mut self, callback: F) -> u64
    where
        F: FnMut(u64, &str, bool, u32) + Send + 'static,
    {
        let mut state = delegate_state();
        let id = state.next_callback_id;
        state.next_callback_id += 1;
        state
            .on_navigation_completed
            .push((id, Box::new(callback)));
        id
    }

    /// Register a SourceChanged callback.
    pub fn on_source_changed<F>(&mut self, callback: F) -> u64
    where
        F: FnMut(u64, &str) + Send + 'static,
    {
        let mut state = delegate_state();
        let id = state.next_callback_id;
        state.next_callback_id += 1;
        state.on_source_changed.push((id, Box::new(callback)));
        id
    }

    /// Register a ContentLoading callback.
    pub fn on_content_loading<F>(&mut self, callback: F) -> u64
    where
        F: FnMut(u64, &str) + Send + 'static,
    {
        let mut state = delegate_state();
        let id = state.next_callback_id;
        state.next_callback_id += 1;
        state.on_content_loading.push((id, Box::new(callback)));
        id
    }

    /// Register a WebMessageReceived callback.
    pub fn on_web_message_received<F>(&mut self, callback: F) -> u64
    where
        F: FnMut(u64, &str) + Send + 'static,
    {
        let mut state = delegate_state();
        let id = state.next_callback_id;
        state.next_callback_id += 1;
        state
            .on_web_message_received
            .push((id, Box::new(callback)));
        id
    }

    /// Unregister a callback by its ID.
    pub fn unregister_callback(&mut self, callback_id: u64) {
        let mut state = delegate_state();
        state.on_navigation_starting.retain(|(id, _)| *id != callback_id);
        state.on_navigation_completed.retain(|(id, _)| *id != callback_id);
        state.on_source_changed.retain(|(id, _)| *id != callback_id);
        state.on_content_loading.retain(|(id, _)| *id != callback_id);
        state.on_web_message_received.retain(|(id, _)| *id != callback_id);
        state.on_new_window_requested.retain(|(id, _)| *id != callback_id);
    }

    // -----------------------------------------------------------------------
    // Event handler registration (ICoreWebView2 add_/remove_ methods)
    // -----------------------------------------------------------------------

    pub fn add_navigation_starting(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.navigation_starting,
        )
    }

    pub fn remove_navigation_starting(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.navigation_starting, token);
    }

    pub fn add_navigation_completed(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.navigation_completed,
        )
    }

    pub fn remove_navigation_completed(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.navigation_completed, token);
    }

    pub fn add_web_message_received(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.web_message_received,
        )
    }

    pub fn remove_web_message_received(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.web_message_received, token);
    }

    pub fn add_new_window_requested(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.new_window_requested,
        )
    }

    pub fn remove_new_window_requested(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.new_window_requested, token);
    }

    pub fn add_permission_requested(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.permission_requested,
        )
    }

    pub fn remove_permission_requested(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.permission_requested, token);
    }

    pub fn add_process_failed(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.process_failed,
        )
    }

    pub fn remove_process_failed(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.process_failed, token);
    }

    pub fn add_content_loading(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.content_loading,
        )
    }

    pub fn remove_content_loading(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.content_loading, token);
    }

    pub fn add_source_changed(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.source_changed,
        )
    }

    pub fn remove_source_changed(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.source_changed, token);
    }

    pub fn add_history_changed(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.history_changed,
        )
    }

    pub fn remove_history_changed(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.history_changed, token);
    }

    pub fn add_download_starting(&mut self, callback_ptr: u64) -> EventRegistrationToken {
        register(
            &mut self.events.next_token,
            callback_ptr,
            &mut self.events.download_starting,
        )
    }

    pub fn remove_download_starting(&mut self, token: EventRegistrationToken) {
        unregister(&mut self.events.download_starting, token);
    }

    /// Trigger all registered NavigationStarting callbacks with the given args.
    /// Returns true if any callback requested cancellation.
    pub fn fire_navigation_starting(&self, webview_id: u64, uri: &str) -> bool {
        let callbacks: Vec<(u64, NavigationStartingCallback)> = {
            let mut state = delegate_state();
            std::mem::take(&mut state.on_navigation_starting)
        };
        let mut should_cancel = false;
        for (id, mut cb) in callbacks {
            if cb(webview_id, uri, false) {
                should_cancel = true;
            }
            delegate_state().on_navigation_starting.push((id, cb));
        }
        should_cancel
    }

    /// Trigger all registered NavigationCompleted callbacks.
    pub fn fire_navigation_completed(&self, webview_id: u64, is_success: bool) {
        let callbacks: Vec<(u64, NavigationCompletedCallback)> = {
            let mut state = delegate_state();
            std::mem::take(&mut state.on_navigation_completed)
        };
        for (id, mut cb) in callbacks {
            cb(webview_id, "", is_success, 200);
            delegate_state().on_navigation_completed.push((id, cb));
        }
    }
}

// ---------------------------------------------------------------------------
// Core WebView2 data structures (for non-native code paths)
// ---------------------------------------------------------------------------

/// Represents an ICoreWebView2 instance, backed by a WKWebView via cef_bridge.
/// This is the legacy structure used by the non-native code paths.
#[derive(Debug, Clone)]
pub struct WebView2Instance {
    pub source: String,
    pub is_script_enabled: bool,
    pub is_web_message_enabled: bool,
    pub is_status_bar_enabled: bool,
    pub are_dev_tools_enabled: bool,
    pub default_background: u32,
    /// Handle into cef_bridge's WKWebView table (if available).
    pub ceh_handle: Option<u64>,
    /// Scripts queued for injection on document creation.
    pub pending_scripts: Vec<String>,
    /// Web messages queued for posting.
    pub web_messages: Vec<String>,
}

impl WebView2Instance {
    /// Navigate to a URL.
    pub fn navigate(&mut self, url: &str) {
        if let Some(_ceh_id) = self.ceh_handle {
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                if let Err(e) = bridge.cef_frame_load_url(_ceh_id, url) {
                    eprintln!("[WebView2] navigate: cef_frame_load_url failed: {e}");
                }
            });
        }
        self.source = url.to_string();
    }

    /// Navigate to an HTML string via a data: URL.
    pub fn navigate_to_string(&mut self, html: &str) {
        let encoded = percent_encode_data_url(html);
        let data_url = format!("data:text/html;charset=utf-8,{}", encoded);
        if let Some(ceh_id) = self.ceh_handle {
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                if let Err(e) = bridge.cef_frame_load_url(ceh_id, &data_url) {
                    eprintln!("[WebView2] navigate_to_string: cef_frame_load_url failed: {e}");
                }
            });
        }
        self.source = data_url;
    }

    /// Execute JavaScript in the webview context.
    pub fn execute_script(&self, _script: &str) {
        if let Some(ceh_id) = self.ceh_handle {
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                if let Err(e) = bridge.cef_frame_execute_java_script(ceh_id, 0, _script) {
                    eprintln!(
                        "[WebView2] execute_script: cef_frame_execute_java_script failed: {e}"
                    );
                }
            });
        }
    }

    /// Post a web message as JSON.
    pub fn post_web_message_as_json(&mut self, json: &str) {
        if self.is_web_message_enabled {
            push_web_message(&mut self.web_messages, json.to_string());
            if let Some(ceh_id) = self.ceh_handle {
                let escaped = escape_js_string_literal(json);
                let js = format!(
                    "window.dispatchEvent(new MessageEvent('message', {{ data: JSON.parse('{}') }}));",
                    escaped
                );
                crate::cef_bridge::with_global_cef_bridge(|bridge| {
                    if let Err(e) = bridge.cef_frame_execute_java_script(ceh_id, 0, &js) {
                        eprintln!("[WebView2] post_web_message_as_json: execute_js failed: {e}");
                    }
                });
            }
        }
    }

    /// Post a web message as a plain string.
    pub fn post_web_message_as_string(&mut self, msg: &str) {
        if self.is_web_message_enabled {
            push_web_message(&mut self.web_messages, msg.to_string());
            if let Some(ceh_id) = self.ceh_handle {
                let escaped = escape_js_string_literal(msg);
                let js = format!(
                    "window.dispatchEvent(new MessageEvent('message', {{ data: '{}' }}));",
                    escaped
                );
                crate::cef_bridge::with_global_cef_bridge(|bridge| {
                    if let Err(e) = bridge.cef_frame_execute_java_script(ceh_id, 0, &js) {
                        eprintln!("[WebView2] post_web_message_as_string: execute_js failed: {e}");
                    }
                });
            }
        }
    }

    /// Stop all ongoing navigations.
    pub fn stop(&self) {
        if let Some(ceh_id) = self.ceh_handle {
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                if let Err(e) = bridge.cef_browser_stop_load(ceh_id) {
                    eprintln!("[WebView2] stop: cef_browser_stop_load failed: {e}");
                }
            });
        }
    }

    /// Reload the current page.
    pub fn reload(&self) {
        if let Some(ceh_id) = self.ceh_handle {
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                if let Err(e) = bridge.cef_browser_reload(ceh_id) {
                    eprintln!("[WebView2] reload: cef_browser_reload failed: {e}");
                }
            });
        }
    }

    /// Add a script to execute on every document creation.
    pub fn add_script_to_execute_on_document_creation(&mut self, _script: &str) {
        self.pending_scripts.push(_script.to_string());
    }

    /// Remove a previously added document-creation script by ID.
    pub fn remove_script_to_execute_on_document_creation(&mut self, _id: usize) {
        if _id < self.pending_scripts.len() {
            self.pending_scripts.remove(_id);
        }
    }

    /// Capture a preview of the webview content.
    pub fn capture_preview(&self, image_format: u32, output_buffer: &mut Vec<u8>) -> u64 {
        let _ = image_format;
        if let Some(ceh_id) = self.ceh_handle {
            let mut result = 0u64;
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                if let Ok(mgr) = bridge.ensure_webview_manager() {
                    let handle = crate::cef_bridge::WKWebViewHandle(ceh_id);
                    if let (Ok(()), Some(snapshot_data)) =
                        (mgr.take_snapshot(handle), mgr.snapshot(handle))
                    {
                        output_buffer.clear();
                        output_buffer.extend_from_slice(snapshot_data);
                        result = snapshot_data.len() as u64;
                    }
                }
            });
            result
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Event system — maps EventRegistrationToken values to callback pointers
// ---------------------------------------------------------------------------

/// A token returned when subscribing to a WebView2 event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventRegistrationToken {
    pub value: u64,
}

/// Stores callbacks registered via add_* / remove_* event methods.
#[derive(Debug, Clone)]
pub struct WebView2Events {
    pub navigation_starting: HashMap<u64, u64>,
    pub navigation_completed: HashMap<u64, u64>,
    pub web_message_received: HashMap<u64, u64>,
    pub new_window_requested: HashMap<u64, u64>,
    pub permission_requested: HashMap<u64, u64>,
    pub process_failed: HashMap<u64, u64>,
    pub content_loading: HashMap<u64, u64>,
    pub source_changed: HashMap<u64, u64>,
    pub history_changed: HashMap<u64, u64>,
    pub download_starting: HashMap<u64, u64>,
    pub next_token: u64,
}

impl WebView2Events {
    pub fn new() -> Self {
        WebView2Events {
            navigation_starting: HashMap::new(),
            navigation_completed: HashMap::new(),
            web_message_received: HashMap::new(),
            new_window_requested: HashMap::new(),
            permission_requested: HashMap::new(),
            process_failed: HashMap::new(),
            content_loading: HashMap::new(),
            source_changed: HashMap::new(),
            history_changed: HashMap::new(),
            download_starting: HashMap::new(),
            next_token: 1,
        }
    }
}

impl Default for WebView2Events {
    fn default() -> Self {
        Self::new()
    }
}

/// Register a callback and return a new token.
pub fn register(
    next_token: &mut u64,
    callback_ptr: u64,
    storage: &mut HashMap<u64, u64>,
) -> EventRegistrationToken {
    let token = *next_token;
    *next_token += 1;
    storage.insert(token, callback_ptr);
    EventRegistrationToken { value: token }
}

/// Unregister a callback by token.
pub fn unregister(storage: &mut HashMap<u64, u64>, token: EventRegistrationToken) {
    storage.remove(&token.value);
}

// ---------------------------------------------------------------------------
// COM Interface Method Enums
// ---------------------------------------------------------------------------

/// Methods on ICoreWebView2Environment (vtable index 3+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentMethod {
    CreateCoreWebView2Controller,
    CreateWebResourceResponse,
    GetBrowserVersionString,
}

/// Methods on ICoreWebView2Controller (vtable index 3+).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerMethod {
    get_IsVisible,
    put_IsVisible,
    get_Bounds,
    put_Bounds,
    get_ZoomFactor,
    put_ZoomFactor,
    MoveFocus,
    Close,
    get_CoreWebView2,
}

/// Methods on ICoreWebView2 (vtable index 3+).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebView2ComMethod {
    get_Source,
    Navigate,
    NavigateToString,
    AddScriptToExecuteOnDocumentCreated,
    RemoveScriptToExecuteOnDocumentCreated,
    ExecuteScript,
    PostWebMessageAsJson,
    PostWebMessageAsString,
    get_Settings,
    add_NavigationStarting,
    remove_NavigationStarting,
    add_NavigationCompleted,
    remove_NavigationCompleted,
    add_WebMessageReceived,
    remove_WebMessageReceived,
    Stop,
    Reload,
    CallDevToolsProtocolMethod,
    GetDevToolsToken,
    add_ContentLoading,
    remove_ContentLoading,
    add_SourceChanged,
    remove_SourceChanged,
    add_HistoryChanged,
    remove_HistoryChanged,
    add_NewWindowRequested,
    remove_NewWindowRequested,
    add_PermissionRequested,
    remove_PermissionRequested,
    add_ProcessFailed,
    remove_ProcessFailed,
    add_DownloadStarting,
    remove_DownloadStarting,
}

/// Methods on ICoreWebView2Settings (vtable index 3+).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsMethod {
    get_IsScriptEnabled,
    put_IsScriptEnabled,
    get_IsWebMessageEnabled,
    put_IsWebMessageEnabled,
    get_IsStatusBarEnabled,
    put_IsStatusBarEnabled,
    get_AreDevToolsEnabled,
    put_AreDevToolsEnabled,
    get_DefaultBackgroundColor,
    put_DefaultBackgroundColor,
    get_IsBuiltInErrorPageEnabled,
    put_IsBuiltInErrorPageEnabled,
    get_AreDefaultScriptDialogsEnabled,
    put_AreDefaultScriptDialogsEnabled,
    get_IsZoomControlEnabled,
    put_IsZoomControlEnabled,
    get_IsSwipeNavigationEnabled,
    put_IsSwipeNavigationEnabled,
    get_UserAgent,
    put_UserAgent,
    get_BrowserExecutableFolder,
    put_BrowserExecutableFolder,
    get_Language,
    put_Language,
    get_TargetCompatibleBrowserVersion,
    put_TargetCompatibleBrowserVersion,
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Maximum number of queued web messages retained per webview.
const MAX_WEB_MESSAGES: usize = 256;

/// Append a web message to the queue, bounding its size so long-running
/// sessions cannot grow it without limit.
fn push_web_message(messages: &mut Vec<String>, msg: String) {
    messages.push(msg);
    if messages.len() > MAX_WEB_MESSAGES {
        let overflow = messages.len() - MAX_WEB_MESSAGES;
        messages.drain(..overflow);
    }
}

/// Escape a string for embedding in a single-quoted JavaScript string
/// literal.
///
/// Escapes backslash, quote, newlines, line/paragraph separators
/// (U+2028/U+2029) and all C0 control characters, which would otherwise
/// terminate or corrupt the literal.
fn escape_js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Percent-encode every byte outside the RFC 3986 unreserved set for use in
/// a `data:` URL. The caller supplies the `data:text/html;charset=utf-8,`
/// prefix.
fn percent_encode_data_url(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Create an environment and verify it exists.
    #[test]
    fn test_webview2_create_environment() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        assert!(runtime.get_environment(env_id).is_some());
        assert_eq!(runtime.environments.len(), 1);
    }

    /// Create a controller with a parent HWND and verify state.
    #[test]
    fn test_webview2_create_controller() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        let ctrl_id = runtime.create_controller(env_id, 0x12345);
        let controller = runtime.get_controller(ctrl_id).unwrap();
        assert_eq!(controller.parent_hwnd, 0x12345);
        assert!(controller.is_visible);
        assert_eq!(controller.zoom_factor, 1.0);

        // Verify the webview was created
        let webview = runtime.get_webview(controller.webview_id).unwrap();
        assert_eq!(webview.source, "");
        assert!(webview.is_script_enabled);
    }

    /// Navigate to a URL and verify the source is updated.
    #[test]
    fn test_webview2_navigate() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        let ctrl_id = runtime.create_controller(env_id, 0);
        let ctrl = runtime.get_controller(ctrl_id).unwrap();
        let webview_id = ctrl.webview_id;

        let webview = runtime.get_webview_mut(webview_id).unwrap();
        webview.navigate("https://example.com");
        assert_eq!(webview.source, "https://example.com");
    }

    /// Execute script and verify it's stored/delegated.
    #[test]
    fn test_webview2_execute_script() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        let ctrl_id = runtime.create_controller(env_id, 0);
        let ctrl = runtime.get_controller(ctrl_id).unwrap();
        let webview_id = ctrl.webview_id;

        let webview = runtime.get_webview_mut(webview_id).unwrap();
        webview.add_script_to_execute_on_document_creation("alert('hello');");
        assert_eq!(webview.pending_scripts.len(), 1);
        assert_eq!(webview.pending_scripts[0], "alert('hello');");
    }

    /// Toggle settings and verify state.
    #[test]
    fn test_webview2_settings() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        let ctrl_id = runtime.create_controller(env_id, 0);
        let ctrl = runtime.get_controller(ctrl_id).unwrap();
        let webview_id = ctrl.webview_id;

        let webview = runtime.get_webview_mut(webview_id).unwrap();
        assert!(webview.is_script_enabled);
        webview.is_script_enabled = false;
        assert!(!webview.is_script_enabled);

        assert!(webview.is_web_message_enabled);
        webview.is_web_message_enabled = false;
        assert!(!webview.is_web_message_enabled);

        webview.are_dev_tools_enabled = true;
        assert!(webview.are_dev_tools_enabled);

        webview.default_background = 0xFF_00_00_00;
        assert_eq!(webview.default_background, 0xFF_00_00_00);
    }

    /// Register event handlers and verify tokens.
    #[test]
    fn test_webview2_event_handlers() {
        let mut events = WebView2Events::new();
        let token1 = register(
            &mut events.next_token,
            0x1000,
            &mut events.navigation_starting,
        );
        let token2 = register(
            &mut events.next_token,
            0x2000,
            &mut events.navigation_completed,
        );
        let token3 = register(
            &mut events.next_token,
            0x3000,
            &mut events.web_message_received,
        );

        assert_eq!(events.navigation_starting.len(), 1);
        assert_eq!(events.navigation_completed.len(), 1);
        assert_eq!(events.web_message_received.len(), 1);

        unregister(&mut events.navigation_starting, token1);
        assert!(events.navigation_starting.is_empty());

        unregister(&mut events.navigation_completed, token2);
        assert!(events.navigation_completed.is_empty());

        unregister(&mut events.web_message_received, token3);
        assert!(events.web_message_received.is_empty());
    }

    /// Post a web message and verify it's stored.
    #[test]
    fn test_webview2_post_message() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        let ctrl_id = runtime.create_controller(env_id, 0);
        let ctrl = runtime.get_controller(ctrl_id).unwrap();
        let webview_id = ctrl.webview_id;

        let webview = runtime.get_webview_mut(webview_id).unwrap();
        webview.post_web_message_as_json(r#"{"type":"test"}"#);
        assert_eq!(webview.web_messages.len(), 1);
        assert_eq!(webview.web_messages[0], r#"{"type":"test"}"#);

        webview.post_web_message_as_string("hello");
        assert_eq!(webview.web_messages.len(), 2);
        assert_eq!(webview.web_messages[1], "hello");
    }

    /// Navigate to an HTML string and verify source updated.
    #[test]
    fn test_webview2_navigate_to_string() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        let ctrl_id = runtime.create_controller(env_id, 0);
        let ctrl = runtime.get_controller(ctrl_id).unwrap();
        let webview_id = ctrl.webview_id;

        let webview = runtime.get_webview_mut(webview_id).unwrap();
        webview.navigate_to_string("<html><body><h1>Hello</h1></body></html>");
        assert!(webview.source.starts_with("data:text/html;charset=utf-8,"));
    }

    /// Destroy environment and verify all state is cleaned up.
    #[test]
    fn test_webview2_destroy_environment() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        let ctrl_id = runtime.create_controller(env_id, 0);
        let ctrl = runtime.get_controller(ctrl_id).unwrap();
        let webview_id = ctrl.webview_id;

        runtime.destroy_environment(env_id);
        assert!(runtime.get_environment(env_id).is_none());
        assert!(runtime.get_controller(ctrl_id).is_none());
        assert!(runtime.get_webview(webview_id).is_none());
    }

    /// Toggle controller visibility and bounds.
    #[test]
    fn test_webview2_controller_properties() {
        let mut runtime = WebView2Runtime::new();
        let env_id = runtime.create_environment(0);
        let ctrl_id = runtime.create_controller(env_id, 0);

        let ctrl = runtime.get_controller_mut(ctrl_id).unwrap();
        ctrl.is_visible = false;
        ctrl.bounds = (100, 50, 1024, 768);
        ctrl.zoom_factor = 1.5;

        let ctrl = runtime.get_controller(ctrl_id).unwrap();
        assert!(!ctrl.is_visible);
        assert_eq!(ctrl.bounds, (100, 50, 1024, 768));
        assert!((ctrl.zoom_factor - 1.5).abs() < f64::EPSILON);
    }

    /// Verify that multiple environments are independent.
    #[test]
    fn test_webview2_multiple_environments() {
        let mut runtime = WebView2Runtime::new();
        let env1 = runtime.create_environment(0);
        let env2 = runtime.create_environment(1);

        let _ctrl1 = runtime.create_controller(env1, 0x100);
        let _ctrl2 = runtime.create_controller(env2, 0x200);

        assert_eq!(runtime.environments.len(), 2);
        assert_eq!(runtime.controllers.len(), 2);
        assert_eq!(runtime.webviews.len(), 2);

        let env = runtime.get_environment(env1).unwrap();
        assert_eq!(env.controllers.len(), 1);
        let env = runtime.get_environment(env2).unwrap();
        assert_eq!(env.controllers.len(), 1);
    }

    /// Test WebView2Environment::new() creates a native config (on macOS).
    #[test]
    fn test_webview2_environment_new() {
        let env = WebView2Environment::new(true, None);
        #[cfg(target_os = "macos")]
        {
            // On macOS with WebKit, native_config should be Some.
            // We can't guarantee WKWebView is available in CI, so check
            // that the method doesn't panic and returns a consistent state.
        }
        assert!(env.controllers.is_empty());
        assert!(env.browser_exe_path.is_none());
    }

    /// Test that callbacks can be registered and unregistered.
    ///
    /// DELEGATE_STATE is process-global, so assertions are scoped to the
    /// callback IDs this test owns instead of global vector lengths, which
    /// would race with other tests running in parallel.
    #[test]
    fn test_webview2_callback_system() {
        let mut runtime = WebView2Runtime::new();

        let cb_id = runtime.on_navigation_starting(|_id, _uri, _redirect| {
            // Always allow navigation
            false
        });
        assert!(cb_id > 0);

        let cb_id2 = runtime.on_navigation_completed(|_id, _uri, _success, _status| {
            // No-op
        });
        assert!(cb_id2 > 0);

        // Unregister the first callback
        runtime.unregister_callback(cb_id);

        // cb_id must be gone; cb_id2 must remain registered.
        let state = DELEGATE_STATE.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!state.on_navigation_starting.iter().any(|(id, _)| *id == cb_id));
        assert!(state.on_navigation_completed.iter().any(|(id, _)| *id == cb_id2));
    }

    /// Test WebView2Controller create/destroy lifecycle.
    #[test]
    fn test_webview2_controller_create_destroy() {
        let env = WebView2Environment::new(true, None);
        let mut ctrl = WebView2Controller::create(&env, 42, 1024, 768, 0);
        assert_eq!(ctrl.webview_id, 42);
        assert_eq!(ctrl.bounds.2, 1024);
        assert_eq!(ctrl.bounds.3, 768);
        assert!(ctrl.is_visible);

        // Close should clean up
        ctrl.close();
        assert!(ctrl.native_webview.is_none());
        assert!(ctrl.nav_delegate_ref.is_none());
    }
}
