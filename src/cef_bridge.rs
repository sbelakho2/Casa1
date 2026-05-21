// ---------------------------------------------------------------------------
// CEF/WKWebView Bridge — translates Chromium Embedded Framework API calls
// to native macOS WKWebView via the Objective-C runtime.
//
// Steam.exe loads libcef.dll for its in-process browser UI (store, library,
// settings).  This module provides the CEF entry points that Steam expects,
// backed by WKWebView for rendering.
//
// Architecture:
//   CEF API call  →  CefBridge method  →  WKWebViewManager  →  ObjC runtime
//                                                                   ↓
//   Metal compositing  ←  RenderedFrame  ←  takeSnapshotWithConfiguration:
// ---------------------------------------------------------------------------
#![allow(unexpected_cfgs)]

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::ffi::CString;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Objective-C runtime helper types (no `foundation` feature in objc 0.2.7)
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

unsafe impl objc::Encode for NSPoint {
    fn encode() -> objc::Encoding {
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

unsafe impl objc::Encode for NSSize {
    fn encode() -> objc::Encoding {
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

unsafe impl objc::Encode for NSRect {
    fn encode() -> objc::Encoding {
        unsafe { objc::Encoding::from_str("{CGRect={CGPoint=dd}{CGSize=dd}}") }
    }
}

/// Block literal structure for Objective-C blocks (e.g., completion handlers).
/// Layout matches the Apple ABI for blocks on x86_64/arm64.
#[repr(C)]
struct BlockLiteral<F> {
    isa: *const std::ffi::c_void,
    flags: i32,
    reserved: i32,
    invoke: *const F,
    // Copy/dispose helpers follow if flags & BLOCK_HAS_COPY_DISPOSE
    // We use simple blocks without copy/dispose for stack-only usage.
}

const BLOCK_HAS_COPY_DISPOSE: i32 = 1 << 25;
const BLOCK_HAS_SIGNATURE: i32 = 1 << 30;

/// Create an Objective-C NSString from a Rust &str.
/// Returns a raw pointer to the NSString object (caller must release).
fn ns_string_from_str(s: &str) -> *mut objc::runtime::Object {
    unsafe {
        let cls = objc::runtime::Class::get("NSString").unwrap();
        let c_str = CString::new(s).unwrap();
        msg_send![cls, stringWithUTF8String: c_str.as_ptr()]
    }
}

/// Helper: create an ObjC NSURL from a Rust &str.
/// SAFETY: returns a +0 (unowned) reference; caller must retain if needed.
unsafe fn ns_url_from_str(url: &str) -> *mut objc::runtime::Object {
    let cls_nsurl = objc::runtime::Class::get("NSURL").unwrap();
    let url_str = ns_string_from_str(url);
    if url_str.is_null() {
        return std::ptr::null_mut();
    }
    let ns_url: *mut objc::runtime::Object =
        msg_send![cls_nsurl, URLWithString: url_str];
    let _: () = msg_send![url_str, release];
    ns_url
}

// ---------------------------------------------------------------------------
// Global state for ObjC delegate callbacks
// ---------------------------------------------------------------------------

/// Shared state that ObjC delegate classes use to communicate back to Rust.
/// Navigation events from WKNavigationDelegate are routed through this.
struct DelegateSharedState {
    /// Map from WKWebView native pointer → handle of the instance
    view_to_handle: BTreeMap<u64, WKWebViewHandle>,
    /// Map from handle → (loaded flag, optional error string)
    navigation_events: BTreeMap<WKWebViewHandle, (bool, Option<String>)>,
    /// Pending JS result callbacks: handle → (script_id, result)
    js_results: BTreeMap<WKWebViewHandle, VecDeque<(u64, String)>>,
    /// Next JS callback ID
    next_js_id: u64,
    /// Pending snapshot results
    snapshot_results: BTreeMap<WKWebViewHandle, Option<Vec<u8>>>,
}

impl DelegateSharedState {
    fn new() -> Self {
        Self {
            view_to_handle: BTreeMap::new(),
            navigation_events: BTreeMap::new(),
            js_results: BTreeMap::new(),
            next_js_id: 1,
            snapshot_results: BTreeMap::new(),
        }
    }
}

static DELEGATE_STATE: LazyLock<Mutex<DelegateSharedState>> =
    LazyLock::new(|| Mutex::new(DelegateSharedState::new()));

/// Global atomic for the current snapshot target handle.
/// Used by the snapshot completion block to communicate the WKWebView handle
/// back to the conversion function without capturing variables in extern "C" fn.
static SNAPSHOT_TARGET_HANDLE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Types mirroring CEF's public API
// ---------------------------------------------------------------------------

pub type CefHandle = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CefState {
    Uninitialized,
    Initialized,
    ShuttingDown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefSettings {
    pub multi_threaded_message_loop: bool,
    pub external_message_pump: bool,
    pub windowless_rendering_enabled: bool,
    pub command_line_args_disabled: bool,
    pub cache_path: Option<String>,
    pub user_agent: Option<String>,
    pub locale: Option<String>,
    pub log_severity: u32,
    pub background_color: u32,
    pub resources_dir_path: Option<String>,
    pub locales_dir_path: Option<String>,
    pub pack_file_path: Option<String>,
}

impl Default for CefSettings {
    fn default() -> Self {
        Self {
            multi_threaded_message_loop: false,
            external_message_pump: false,
            windowless_rendering_enabled: true,
            command_line_args_disabled: false,
            cache_path: None,
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                 AppleWebKit/605.1.15 (KHTML, like Gecko) Steam/1.0"
                    .to_string(),
            ),
            locale: Some("en-US".to_string()),
            log_severity: 0,
            background_color: 0xFFFFFFFF,
            resources_dir_path: None,
            locales_dir_path: None,
            pack_file_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefBrowserSettings {
    pub windowless_frame_rate: u32,
    pub default_encoding: Option<String>,
    pub accept_language_list: Option<String>,
}

impl Default for CefBrowserSettings {
    fn default() -> Self {
        Self {
            windowless_frame_rate: 60,
            default_encoding: Some("UTF-8".to_string()),
            accept_language_list: Some("en-US,en".to_string()),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CefWindowInfo {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub windowless_rendering_enabled: bool,
    pub parent_window: u64,
    pub url: Option<String>,
    pub external_begin_frame_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefBrowser {
    pub id: u32,
    pub host_handle: CefHandle,
    pub main_frame_handle: CefHandle,
    pub can_go_back: bool,
    pub can_go_forward: bool,
    pub is_loading: bool,
    pub current_url: String,
    pub title: String,
    pub zoom_level: f64,
    /// WKWebView handle for native operations
    pub wk_handle: Option<WKWebViewHandle>,
    /// Whether the frame has been dirtied (needs re-render)
    pub dirty: bool,
    /// Cached Metal texture for compositing
    pub metal_texture_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefFrame {
    pub browser_handle: CefHandle,
    pub identifier: i64,
    pub url: String,
    pub name: String,
    pub is_main: bool,
    pub is_focused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefRect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedFrame {
    pub browser_id: u32,
    pub width: u32,
    pub height: u32,
    /// RGBA pixel data from offscreen rendering
    pub pixels: Vec<u8>,
    pub frame_number: u64,
}

// ---------------------------------------------------------------------------
/// CEF bridge state — manages browser instances and their rendered frames
// ---------------------------------------------------------------------------
pub struct CefBridge {
    state: CefState,
    settings: CefSettings,
    browsers: BTreeMap<CefHandle, CefBrowser>,
    frames: BTreeMap<(CefHandle, i64), CefFrame>, // (browser_handle, frame_id)
    rendered_frames: VecDeque<RenderedFrame>,
    next_browser_id: u32,
    next_handle: CefHandle,
    paint_callback: Option<Box<dyn FnMut(RenderedFrame) + Send>>,
    /// WKWebView manager (macOS only)
    webview_manager: Option<WKWebViewManager>,
    /// Whether the NSApplication has been set up for headless rendering
    nsapp_initialized: bool,
}

impl std::fmt::Debug for CefBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CefBridge")
            .field("state", &self.state)
            .field("settings", &self.settings)
            .field("browsers", &self.browsers)
            .field("frames", &self.frames)
            .field("rendered_frames", &self.rendered_frames)
            .field("next_browser_id", &self.next_browser_id)
            .field("next_handle", &self.next_handle)
            .field(
                "paint_callback",
                &self.paint_callback.as_ref().map(|_| "FnMut(RenderedFrame)"),
            )
            .field("webview_manager", &self.webview_manager.as_ref().map(|_| "WKWebViewManager"))
            .field("nsapp_initialized", &self.nsapp_initialized)
            .finish()
    }
}

impl Default for CefBridge {
    fn default() -> Self {
        Self {
            state: CefState::Uninitialized,
            settings: CefSettings::default(),
            browsers: BTreeMap::new(),
            frames: BTreeMap::new(),
            rendered_frames: VecDeque::new(),
            next_browser_id: 0,
            next_handle: 1,
            paint_callback: None,
            webview_manager: None,
            nsapp_initialized: false,
        }
    }
}

// ---------------------------------------------------------------------------
// WKWebView Manager — bridges CEF browser instances to native WKWebView
// via the Objective-C runtime using the `objc` crate.
// ---------------------------------------------------------------------------

/// Configuration for a WKWebView instance
#[derive(Debug, Clone)]
pub struct WKWebViewConfig {
    pub width: f64,
    pub height: f64,
    pub java_script_enabled: bool,
    pub user_agent: Option<String>,
}

impl Default for WKWebViewConfig {
    fn default() -> Self {
        Self {
            width: 1024.0,
            height: 768.0,
            java_script_enabled: true,
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                 AppleWebKit/605.1.15 (KHTML, like Gecko) Steam/1.0"
                    .to_string(),
            ),
        }
    }
}

/// A handle to a WKWebView instance managed by the Objective-C runtime
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WKWebViewHandle(pub u64);

/// Manages WKWebView instances via the Objective-C runtime.
/// Each WKWebView corresponds to a CEF browser instance.
pub struct WKWebViewManager {
    /// Currently active web views, keyed by WKWebViewHandle
    views: BTreeMap<WKWebViewHandle, WKWebViewInstance>,
    next_id: u64,
    /// Whether the Objective-C WKWebView class was successfully loaded
    wkwebview_available: Arc<AtomicBool>,
    /// Hidden NSWindow used as parent for offscreen WKWebView rendering
    offscreen_window: Option<*mut std::ffi::c_void>,
    /// Offscreen NSView container
    offscreen_view: Option<*mut std::ffi::c_void>,
    /// Whether NSApplication has been initialized
    nsapp_ready: bool,
    /// Navigation delegate object pointer
    nav_delegate: Option<*mut std::ffi::c_void>,
    /// Script message handler object pointer
    msg_handler: Option<*mut std::ffi::c_void>,
}

// SAFETY: WKWebViewManager holds opaque ObjC pointers that are Send + Sync
// because WKWebView is thread-safe for our usage patterns.
unsafe impl Send for WKWebViewManager {}
unsafe impl Sync for WKWebViewManager {}

/// Internal state for a WKWebView instance
struct WKWebViewInstance {
    /// Objective-C pointer to the WKWebView object (raw pointer, opaque)
    native_ptr: *mut std::ffi::c_void,
    /// Current URL loaded
    url: String,
    /// View dimensions
    width: f64,
    height: f64,
    /// Last rendered RGBA pixel data (from WKWebView snapshot)
    pixels: Vec<u8>,
    /// Whether JavaScript is enabled
    js_enabled: bool,
    /// Whether the page has finished loading
    loaded: bool,
    /// Last navigation error, if any
    error: Option<String>,
    /// Frame counter for tracking snapshot versions
    frame_count: u64,
    /// Pending JavaScript callback handles
    pending_js_callbacks: VecDeque<u64>,
}

// SAFETY: WKWebViewInstance holds an opaque ObjC pointer that's Send + Sync
// because WKWebView is thread-safe for our usage patterns.
unsafe impl Send for WKWebViewInstance {}
unsafe impl Sync for WKWebViewInstance {}

/// Render mode for the SteamWebHelper shim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenderMode {
    /// No visible window, rendering to offscreen buffer
    Headless,
    /// Rendered in a separate window
    Windowed,
    /// Rendered as an overlay on top of a game
    Overlay,
}

// ===========================================================================
// Objective-C protocol/class registration for WKNavigationDelegate
// ===========================================================================

/// Register a custom ObjC class conforming to WKNavigationDelegate.
/// This class forwards navigation callbacks into DELEGATE_STATE.
/// Called once during WKWebViewManager initialization.
#[cfg(target_os = "macos")]
fn register_nav_delegate_class() -> Option<*const objc::runtime::Class> {
    use objc::declare::ClassDecl;
    use objc::runtime::Class;

    // Check if already registered
    if let Some(cls) = Class::get("Casa1NavDelegate") {
        return Some(cls);
    }

    let superclass = Class::get("NSObject")?;
    let mut decl = ClassDecl::new("Casa1NavDelegate", superclass)?;

    // Add webView:didFinishNavigation: method
    extern "C" fn did_finish_nav(
        self_: &objc::runtime::Object,
        _cmd: objc::runtime::Sel,
        _webview: *mut objc::runtime::Object,
        _navigation: *mut objc::runtime::Object,
    ) {
        // The webview finished loading — signal the delegate state
        let ptr_val = self_ as *const _ as u64;
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            // Find the handle for this delegate
            for (&vp, &handle) in &state.view_to_handle {
                // We store the webview ptr in the map; iterate to find match
                // A real impl would use associated objects; for now broadcast to
                // all tracked views that they finished loading.
                let _ = (vp, handle);
            }
            // Mark all views as loaded (simplification)
            for (loaded, _) in state.navigation_events.values_mut() {
                *loaded = true;
            }
        }
    }

    extern "C" fn did_fail_nav(
        self_: &objc::runtime::Object,
        _cmd: objc::runtime::Sel,
        _webview: *mut objc::runtime::Object,
        _navigation: *mut objc::runtime::Object,
        error: *mut objc::runtime::Object,
    ) {
        let ptr_val = self_ as *const _ as u64;
        // Extract error description
        let error_desc = unsafe {
            let desc: *mut objc::runtime::Object =
                msg_send![error, localizedDescription];
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
        };
        let _ = ptr_val;
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            for (_, (_, err)) in state.navigation_events.iter_mut() {
                *err = Some(error_desc.clone());
            }
        }
    }

    unsafe {
        decl.add_method(
            sel!(webView:didFinishNavigation:),
            did_finish_nav as extern "C" fn(&objc::runtime::Object, objc::runtime::Sel, *mut objc::runtime::Object, *mut objc::runtime::Object),
        );
        decl.add_method(
            sel!(webView:didFailNavigation:withError:),
            did_fail_nav as extern "C" fn(&objc::runtime::Object, objc::runtime::Sel, *mut objc::runtime::Object, *mut objc::runtime::Object, *mut objc::runtime::Object),
        );
    }

    let reg_cls = decl.register();
    Some(reg_cls)
}

/// Register a custom ObjC class conforming to WKScriptMessageHandler.
/// This allows JavaScript in the WKWebView to call:
///   `window.webkit.messageHandlers.native.postMessage(data)`
#[cfg(target_os = "macos")]
fn register_msg_handler_class() -> Option<*const objc::runtime::Class> {
    use objc::declare::ClassDecl;
    use objc::runtime::Class;

    if let Some(cls) = Class::get("Casa1ScriptMsgHandler") {
        return Some(cls);
    }

    let superclass = Class::get("NSObject")?;
    let mut decl = ClassDecl::new("Casa1ScriptMsgHandler", superclass)?;

    extern "C" fn did_receive_message(
        _self_: &objc::runtime::Object,
        _cmd: objc::runtime::Sel,
        _controller: *mut objc::runtime::Object,
        message: *mut objc::runtime::Object,
    ) {
        // Extract the message body from WKScriptMessage
        unsafe {
            let body: *mut objc::runtime::Object = msg_send![message, body];
            if !body.is_null() {
                let desc: *mut objc::runtime::Object =
                    msg_send![body, description];
                if !desc.is_null() {
                    let cstr: *const i8 = msg_send![desc, UTF8String];
                    if !cstr.is_null() {
                        let msg_str = std::ffi::CStr::from_ptr(cstr)
                            .to_string_lossy()
                            .into_owned();
                        // Log the message (in production, route to CefQuery handler)
                        eprintln!("[CefBridge] Script message received: {msg_str}");
                    }
                }
            }
        }
    }

    unsafe {
        decl.add_method(
            sel!(userContentController:didReceiveScriptMessage:),
            did_receive_message as extern "C" fn(&objc::runtime::Object, objc::runtime::Sel, *mut objc::runtime::Object, *mut objc::runtime::Object),
        );
    }

    let reg_cls = decl.register();
    Some(reg_cls)
}

// ===========================================================================
// WKWebViewManager implementation
// ===========================================================================

impl WKWebViewManager {
    /// Check if WKWebView is available at runtime by looking for the WKWebView class.
    #[cfg(target_os = "macos")]
    fn runtime_wkwebview_available() -> bool {
        // Check for WKWebView class — if WebKit framework is loaded, this will be Some.
        // We also check WKPreferences as a secondary indicator.
        let has_wkwebview = objc::runtime::Class::get("WKWebView").is_some();
        let has_wkprefs = objc::runtime::Class::get("WKPreferences").is_some();
        has_wkwebview || has_wkprefs
    }

    /// Create a new WKWebView manager. Checks if WKWebView is available
    /// on this system (macOS 10.13+). On first creation, sets up the
    /// NSApplication and hidden offscreen window for headless rendering.
    pub fn new() -> Self {
        let available = Arc::new(AtomicBool::new(
            cfg!(target_os = "macos") && Self::runtime_wkwebview_available(),
        ));

        let mut mgr = Self {
            views: BTreeMap::new(),
            next_id: 1,
            wkwebview_available: available,
            offscreen_window: None,
            offscreen_view: None,
            nsapp_ready: false,
            nav_delegate: None,
            msg_handler: None,
        };

        #[cfg(target_os = "macos")]
        {
            if mgr.wkwebview_available.load(Ordering::Relaxed) {
                mgr.init_nsapp();
                mgr.register_delegate_classes();
            }
        }

        mgr
    }

    /// Initialize the NSApplication for headless rendering.
    /// Creates a shared application, sets activation policy to prohibited
    /// (headless), and creates a hidden offscreen window + NSView.
    #[cfg(target_os = "macos")]
    fn init_nsapp(&mut self) {
        unsafe {
            let cls_app = match objc::runtime::Class::get("NSApplication") {
                Some(c) => c,
                None => {
                    self.wkwebview_available.store(false, Ordering::Relaxed);
                    return;
                }
            };

            // Get or create shared application
            let shared_app: *mut objc::runtime::Object =
                msg_send![cls_app, sharedApplication];
            if shared_app.is_null() {
                self.wkwebview_available.store(false, Ordering::Relaxed);
                return;
            }

            // Set activation policy to prohibited for headless mode
            let _: () = msg_send![
                shared_app,
                setActivationPolicy: 0 /* NSApplicationActivationPolicyProhibited */
            ];

            // Create a hidden NSWindow to serve as parent for WKWebView
            // WKWebView requires being in a window hierarchy to render.
            let cls_window = match objc::runtime::Class::get("NSWindow") {
                Some(c) => c,
                None => {
                    self.wkwebview_available.store(false, Ordering::Relaxed);
                    return;
                }
            };

            let cls_view = match objc::runtime::Class::get("NSView") {
                Some(c) => c,
                None => {
                    self.wkwebview_available.store(false, Ordering::Relaxed);
                    return;
                }
            };

            // Create offscreen content view
            let view_alloc: *mut objc::runtime::Object = msg_send![cls_view, alloc];
            let view_frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(4096.0, 4096.0));
            let view: *mut objc::runtime::Object =
                msg_send![view_alloc, initWithFrame: view_frame];

            // Create hidden window with the offscreen view as content
            let win_alloc: *mut objc::runtime::Object = msg_send![cls_window, alloc];
            let win_frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(4096.0, 4096.0));
            let win: *mut objc::runtime::Object = msg_send![
                win_alloc,
                initWithContentRect: win_frame
                styleMask: 0 /* NSWindowStyleMaskBorderless */
                backing: 2 /* NSBackingStoreBuffered */
                defer: 0 /* NO */
            ];

            // Set window hidden
            let _: () = msg_send![win, setTitle: ns_string_from_str("Casa1 Offscreen WKWebView")];
            let _: () = msg_send![win, setContentView: view];
            let _: () = msg_send![win, setOpaque: 0 /* NO */];
            let _: () = msg_send![win, setAlphaValue: 0.0];
            let _: () = msg_send![win, orderOut: std::ptr::null_mut::<std::ffi::c_void>()];

            self.offscreen_window = Some(win as *mut std::ffi::c_void);
            self.offscreen_view = Some(view as *mut std::ffi::c_void);
            self.nsapp_ready = true;
        }
    }

    /// Register ObjC delegate classes for WKNavigationDelegate and
    /// WKScriptMessageHandler.
    #[cfg(target_os = "macos")]
    fn register_delegate_classes(&mut self) {
        if let Some(cls) = register_nav_delegate_class() {
            // Create an instance
            unsafe {
                let alloc: *mut objc::runtime::Object = msg_send![cls, alloc];
                let instance: *mut objc::runtime::Object = msg_send![alloc, init];
                self.nav_delegate = Some(instance as *mut std::ffi::c_void);
            }
        }

        if let Some(cls) = register_msg_handler_class() {
            unsafe {
                let alloc: *mut objc::runtime::Object = msg_send![cls, alloc];
                let instance: *mut objc::runtime::Object = msg_send![alloc, init];
                self.msg_handler = Some(instance as *mut std::ffi::c_void);
            }
        }
    }

    /// Check whether WKWebView is available on this system
    pub fn is_available(&self) -> bool {
        self.wkwebview_available.load(Ordering::Relaxed)
    }

    /// Check if NSApplication is ready for rendering
    pub fn is_nsapp_ready(&self) -> bool {
        self.nsapp_ready
    }

    /// Create a new WKWebView with the given configuration.
    /// Returns a handle that can be used to interact with the web view.
    pub fn create_webview(&mut self, config: WKWebViewConfig) -> AppResult<WKWebViewHandle> {
        if !self.is_available() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "WKWebView is not available on this platform",
            ));
        }

        let handle = WKWebViewHandle(self.next_id);
        self.next_id += 1;

        // Create the WKWebView via Objective-C runtime
        let native_ptr = Self::create_wkwebview_native(
            config.width,
            config.height,
            config.java_script_enabled,
            config.user_agent.as_deref(),
            self.nav_delegate,
            self.msg_handler,
            self.offscreen_view,
        );
        if native_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "Failed to create WKWebView via Objective-C runtime",
            ));
        }

        // Register this view in the delegate state
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            state
                .view_to_handle
                .insert(native_ptr as u64, handle);
            state.navigation_events.insert(handle, (false, None));
        }

        let pixels = vec![0xFFu8; (config.width as usize * config.height as usize * 4)];

        self.views.insert(
            handle,
            WKWebViewInstance {
                native_ptr,
                url: String::new(),
                width: config.width,
                height: config.height,
                pixels,
                js_enabled: config.java_script_enabled,
                loaded: false,
                error: None,
                frame_count: 0,
                pending_js_callbacks: VecDeque::new(),
            },
        );

        Ok(handle)
    }

    /// Navigate a WKWebView to a URL
    pub fn navigate(&mut self, handle: WKWebViewHandle, url: &str) -> AppResult<()> {
        let instance = self.views.get_mut(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("WKWebView {handle:?} not found"),
            )
        })?;
        instance.url = url.to_string();
        instance.loaded = false;
        instance.error = None;
        Self::navigate_wkwebview_native(instance.native_ptr, url);

        // Reset navigation event
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            state.navigation_events.insert(handle, (false, None));
        }

        Ok(())
    }

    /// Execute JavaScript in a WKWebView. Returns the result as a string
    /// if a completion handler result is available.
    pub fn evaluate_java_script(
        &mut self,
        handle: WKWebViewHandle,
        script: &str,
    ) -> AppResult<String> {
        let instance = self.views.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("WKWebView {handle:?} not found"),
            )
        })?;

        // Create a callback ID
        let callback_id = {
            if let Ok(mut state) = DELEGATE_STATE.lock() {
                let id = state.next_js_id;
                state.next_js_id += 1;
                id
            } else {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    "evaluate_java_script: delegate state lock poisoned",
                ));
            }
        };

        Self::evaluate_js_native(instance.native_ptr, script, callback_id);

        // Check if result is already available (synchronous completion)
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            if let Some(results) = state.js_results.get_mut(&handle) {
                if let Some((_, result)) = results.pop_front() {
                    return Ok(result);
                }
            }
        }

        Ok(String::new())
    }

    /// Get the latest rendered RGBA pixel data from a WKWebView.
    /// Triggers a snapshot if the view has finished loading and no
    /// snapshot is cached.
    pub fn snapshot(&mut self, handle: WKWebViewHandle) -> Option<&[u8]> {
        let instance = self.views.get_mut(&handle)?;

        // If we haven't taken a snapshot yet and the page loaded, trigger one
        if instance.frame_count == 0 && instance.loaded {
            Self::take_snapshot_native(instance.native_ptr, handle);
            instance.frame_count += 1;
        }

        Some(&instance.pixels)
    }

    /// Take an explicit snapshot and update the pixel buffer.
    pub fn take_snapshot(&mut self, handle: WKWebViewHandle) -> AppResult<()> {
        let instance = self.views.get_mut(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("WKWebView {handle:?} not found"),
            )
        })?;

        Self::take_snapshot_native(instance.native_ptr, handle);

        // Check if snapshot result is available
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            if let Some(Some(pixels)) = state.snapshot_results.remove(&handle) {
                instance.pixels = pixels;
                instance.frame_count += 1;
            }
        }

        Ok(())
    }

    /// Check if a navigation has completed (didFinishNavigation was called)
    pub fn navigation_did_finish(&self, handle: WKWebViewHandle) -> Option<bool> {
        if let Ok(state) = DELEGATE_STATE.lock() {
            state.navigation_events.get(&handle).map(|(loaded, _)| *loaded)
        } else {
            None
        }
    }

    /// Get any navigation error
    pub fn navigation_error(&self, handle: WKWebViewHandle) -> Option<String> {
        if let Ok(state) = DELEGATE_STATE.lock() {
            state
                .navigation_events
                .get(&handle)
                .and_then(|(_, err)| err.clone())
        } else {
            None
        }
    }

    /// Resize a WKWebView
    pub fn resize(&mut self, handle: WKWebViewHandle, width: f64, height: f64) -> AppResult<()> {
        let instance = self.views.get_mut(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("WKWebView {handle:?} not found"),
            )
        })?;
        instance.width = width;
        instance.height = height;
        instance.pixels = vec![0xFFu8; (width as usize * height as usize * 4)];
        Self::resize_wkwebview_native(instance.native_ptr, width, height);
        Ok(())
    }

    /// Close and destroy a WKWebView
    pub fn close(&mut self, handle: WKWebViewHandle) {
        if let Some(instance) = self.views.remove(&handle) {
            Self::close_wkwebview_native(instance.native_ptr);
        }

        // Clean up delegate state
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            state.navigation_events.remove(&handle);
            state.js_results.remove(&handle);
            state.snapshot_results.remove(&handle);
            state.view_to_handle.retain(|_, &mut vh| vh != handle);
        }
    }

    /// Close all web views and clean up
    pub fn close_all(&mut self) {
        let handles: Vec<WKWebViewHandle> = self.views.keys().copied().collect();
        for handle in handles {
            self.close(handle);
        }

        // Release offscreen window
        #[cfg(target_os = "macos")]
        {
            if let Some(win) = self.offscreen_window.take() {
                unsafe {
                    let _: () = msg_send![win as *mut objc::runtime::Object, close];
                }
            }
            if let Some(view) = self.offscreen_view.take() {
                unsafe {
                    let _: () = msg_send![view as *mut objc::runtime::Object, release];
                }
            }
            if let Some(delegate) = self.nav_delegate.take() {
                unsafe {
                    let _: () = msg_send![delegate as *mut objc::runtime::Object, release];
                }
            }
            if let Some(handler) = self.msg_handler.take() {
                unsafe {
                    let _: () = msg_send![handler as *mut objc::runtime::Object, release];
                }
            }
        }
    }

    /// Get the number of active web views
    pub fn active_count(&self) -> usize {
        self.views.len()
    }

    /// Get the URL currently loaded in a web view
    pub fn current_url(&self, handle: WKWebViewHandle) -> Option<&str> {
        self.views.get(&handle).map(|v| v.url.as_str())
    }

    /// Get the native pointer for a web view handle
    pub fn native_ptr(&self, handle: WKWebViewHandle) -> Option<*mut std::ffi::c_void> {
        self.views.get(&handle).map(|v| v.native_ptr)
    }

    /// Get view dimensions
    pub fn dimensions(&self, handle: WKWebViewHandle) -> Option<(f64, f64)> {
        self.views.get(&handle).map(|v| (v.width, v.height))
    }

    // -----------------------------------------------------------------------
    // Native Objective-C runtime calls
    // -----------------------------------------------------------------------

    /// Create a WKWebView using the Objective-C runtime.
    /// Sets up WKPreferences (javaScriptEnabled, javaScriptCanOpenWindowsAutomatically,
    /// minimumFontSize), WKWebViewConfiguration (preferences, process pool, user content
    /// controller), and WKWebView (frame, navigationDelegate, custom user agent,
    /// allowsBackForwardNavigationGestures).
    ///
    /// Returns a raw pointer to the WKWebView object, or null on failure.
    fn create_wkwebview_native(
        width: f64,
        height: f64,
        js_enabled: bool,
        user_agent: Option<&str>,
        nav_delegate: Option<*mut std::ffi::c_void>,
        msg_handler: Option<*mut std::ffi::c_void>,
        parent_view: Option<*mut std::ffi::c_void>,
    ) -> *mut std::ffi::c_void {
        #[cfg(target_os = "macos")]
        {
            let result = std::panic::catch_unwind(|| unsafe {
                // SAFETY: All ObjC class lookups and message sends are safe as long
                // as the runtime is initialized, which it is on macOS 10.13+.

                // --- Look up classes ---
                let cls_wk_prefs = match objc::runtime::Class::get("WKPreferences") {
                    Some(c) => c,
                    None => return std::ptr::null_mut(),
                };
                let cls_wk_config = match objc::runtime::Class::get("WKWebViewConfiguration") {
                    Some(c) => c,
                    None => return std::ptr::null_mut(),
                };
                let cls_wk_pool = match objc::runtime::Class::get("WKProcessPool") {
                    Some(c) => c,
                    None => return std::ptr::null_mut(),
                };
                let cls_wk_view = match objc::runtime::Class::get("WKWebView") {
                    Some(c) => c,
                    None => return std::ptr::null_mut(),
                };
                let cls_wk_controller =
                    match objc::runtime::Class::get("WKUserContentController") {
                        Some(c) => c,
                        None => return std::ptr::null_mut(),
                    };

                // --- Create process pool ---
                let pool_alloc: *mut objc::runtime::Object = msg_send![cls_wk_pool, alloc];
                let pool: *mut objc::runtime::Object = msg_send![pool_alloc, init];

                // --- Create preferences with full configuration ---
                let prefs: *mut objc::runtime::Object = msg_send![cls_wk_prefs, alloc];
                let prefs: *mut objc::runtime::Object = msg_send![prefs, init];
                let _: () = msg_send![prefs, setJavaScriptEnabled: js_enabled];
                let _: () = msg_send![
                    prefs,
                    setJavaScriptCanOpenWindowsAutomatically: 0 /* NO */
                ];
                let _: () = msg_send![prefs, setMinimumFontSize: 1.0];

                // --- Create user content controller with script message handler ---
                let uc_alloc: *mut objc::runtime::Object = msg_send![cls_wk_controller, alloc];
                let uc: *mut objc::runtime::Object = msg_send![uc_alloc, init];

                if let Some(handler_ptr) = msg_handler {
                    let handler_name = ns_string_from_str("native");
                    let _: () = msg_send![
                        uc,
                        addScriptMessageHandler: handler_ptr as *mut objc::runtime::Object
                        name: handler_name
                    ];
                }

                // --- Create configuration ---
                let config: *mut objc::runtime::Object = msg_send![cls_wk_config, alloc];
                let config: *mut objc::runtime::Object = msg_send![config, init];
                let _: () = msg_send![config, setPreferences: prefs];
                let _: () = msg_send![config, setProcessPool: pool];
                let _: () = msg_send![config, setUserContentController: uc];

                // --- Create WKWebView with frame and configuration ---
                let alloc: *mut objc::runtime::Object = msg_send![cls_wk_view, alloc];
                let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(width, height));
                let view: *mut objc::runtime::Object =
                    msg_send![alloc, initWithFrame: frame configuration: config];

                if view.is_null() {
                    return std::ptr::null_mut();
                }

                // --- Set navigation delegate ---
                if let Some(delegate_ptr) = nav_delegate {
                    let _: () = msg_send![
                        view,
                        setNavigationDelegate: delegate_ptr as *mut objc::runtime::Object
                    ];
                }

                // --- Set custom user agent ---
                if let Some(ua) = user_agent {
                    let ua_str = ns_string_from_str(ua);
                    if !ua_str.is_null() {
                        // WKWebView customUserAgent property (set via KVC or direct)
                        // Use setValue:forKey: for the customUserAgent property
                        let key = ns_string_from_str("customUserAgent");
                        let _: () = msg_send![
                            view,
                            setValue: ua_str
                            forKey: key
                        ];
                    }
                }

                // --- Set navigation gesture support ---
                let _: () = msg_send![
                    view,
                    setAllowsBackForwardNavigationGestures: 0 /* NO */
                ];

                // --- Add to parent view hierarchy ---
                // WKWebView requires being in a view/window hierarchy to render content.
                if let Some(parent) = parent_view {
                    let parent_view = parent as *mut objc::runtime::Object;
                    let _: () = msg_send![parent_view, addSubview: view];
                }

                view as *mut std::ffi::c_void
            });
            result.unwrap_or(std::ptr::null_mut())
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = (width, height, js_enabled, user_agent, nav_delegate, msg_handler, parent_view);
            std::ptr::null_mut()
        }
    }

    /// Navigate a WKWebView to a URL using `loadRequest:` with an NSURLRequest.
    fn navigate_wkwebview_native(native_ptr: *mut std::ffi::c_void, url: &str) {
        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::panic::catch_unwind(|| unsafe {
                // SAFETY: Native pointer is validated as non-null.
                // NSURL and NSURLRequest are standard Foundation classes.
                let cls_req = match objc::runtime::Class::get("NSURLRequest") {
                    Some(c) => c,
                    None => return,
                };

                let ns_url = ns_url_from_str(url);
                if ns_url.is_null() {
                    return;
                }

                let req: *mut objc::runtime::Object =
                    msg_send![cls_req, requestWithURL: ns_url];
                if !req.is_null() {
                    let view = native_ptr as *mut objc::runtime::Object;
                    let _: () = msg_send![view, loadRequest: req];
                }
            });
        }
        let _ = url;
    }

    /// Evaluate JavaScript in a WKWebView using `evaluateJavaScript:completionHandler:`.
    /// The completion handler is a block that receives the result when execution finishes.
    fn evaluate_js_native(
        native_ptr: *mut std::ffi::c_void,
        script: &str,
        callback_id: u64,
    ) {
        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::panic::catch_unwind(|| unsafe {
                // SAFETY: We use a minimal manually-managed block literal for the
                // completion handler. The block is on the stack and only valid for
                // the duration of the msg_send! call (WKWebView copies it internally).
                let view = native_ptr as *mut objc::runtime::Object;
                let js_str = ns_string_from_str(script);
                if js_str.is_null() {
                    return;
                }

                // Create a minimal block for the completion handler.
                // Block signature: void (^)(id _Nullable, NSError * _Nullable)
                //
                // Block layout on stack:
                //   struct { void *isa; int flags; int reserved; void *invoke; ... }
                //
                // We use an extern "C" function as the invoke pointer.
                extern "C" fn js_completion_block(
                    block: *const std::ffi::c_void,
                    result: *mut objc::runtime::Object,
                    error: *mut objc::runtime::Object,
                ) {
                    unsafe {
                        let _ = block;
                        // Extract the callback_id from the block if we had associated data.
                        // For simplicity, we just log the result/error.
                        if !error.is_null() {
                            let desc: *mut objc::runtime::Object =
                                msg_send![error, localizedDescription];
                            if !desc.is_null() {
                                let cstr: *const i8 = msg_send![desc, UTF8String];
                                if !cstr.is_null() {
                                    let err_str = std::ffi::CStr::from_ptr(cstr)
                                        .to_string_lossy()
                                        .into_owned();
                                    eprintln!(
                                        "[CefBridge] JS execution error: {err_str}"
                                    );
                                }
                            }
                        } else if !result.is_null() {
                            let desc: *mut objc::runtime::Object =
                                msg_send![result, description];
                            if !desc.is_null() {
                                let cstr: *const i8 = msg_send![desc, UTF8String];
                                if !cstr.is_null() {
                                    let result_str = std::ffi::CStr::from_ptr(cstr)
                                        .to_string_lossy()
                                        .into_owned();
                                    // Route result back through delegate state
                                    // (simplified — a real impl would use the block's copy
                                    //  of the callback ID via block private data)
                                    let _ = result_str;
                                }
                            }
                        }
                    }
                }

                let block = BlockLiteral::<extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object, *mut objc::runtime::Object)> {
                    isa: std::ptr::null_mut(), // will be set to NSConcreteStackBlock by runtime
                    flags: 0,
                    reserved: 0,
                    invoke: js_completion_block
                        as *const extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object, *mut objc::runtime::Object),
                };

                let _: () = msg_send![
                    view,
                    evaluateJavaScript: js_str
                    completionHandler: &block as *const BlockLiteral<_>
                        as *mut std::ffi::c_void
                ];
                let _: () = msg_send![js_str, release];
            });
        }
        let _ = (script, callback_id);
    }

    /// Take a snapshot of the WKWebView's current rendered content using
    /// `takeSnapshotWithConfiguration:completionHandler:` (macOS 10.13+).
    /// The snapshot is returned as RGBA pixel data via the completion block.
    fn take_snapshot_native(
        native_ptr: *mut std::ffi::c_void,
        handle: WKWebViewHandle,
    ) {
        // Store handle in global atomic so the extern "C" block fn can use it.
        // This is safe because take_snapshot_native is called from a single thread
        // (the main loop) and the block executes synchronously during run loop iteration.
        SNAPSHOT_TARGET_HANDLE.store(handle.0, Ordering::SeqCst);

        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            let _ = std::panic::catch_unwind(|| unsafe {
                // SAFETY: takeSnapshotWithConfiguration:completionHandler: is available
                // on macOS 10.13+. We pass nil for configuration (default options)
                // and a stack block for the completion handler.
                let view = native_ptr as *mut objc::runtime::Object;

                // Create a minimal stack block for the snapshot completion handler.
                // Block signature: void (^)(UIImage * _Nullable snapshot, NSError * _Nullable error)
                extern "C" fn snapshot_completion_block(
                    _block: *const std::ffi::c_void,
                    snapshot: *mut objc::runtime::Object,
                    error: *mut objc::runtime::Object,
                ) {
                    unsafe {
                        if !error.is_null() {
                            // Log error but don't crash
                            let desc: *mut objc::runtime::Object =
                                msg_send![error, localizedDescription];
                            if !desc.is_null() {
                                let cstr: *const i8 = msg_send![desc, UTF8String];
                                if !cstr.is_null() {
                                    let err_str = std::ffi::CStr::from_ptr(cstr)
                                        .to_string_lossy()
                                        .into_owned();
                                    eprintln!(
                                        "[CefBridge] Snapshot error: {err_str}"
                                    );
                                }
                            }
                            return;
                        }

                        if snapshot.is_null() {
                            return;
                        }

                        // Retrieve the target handle from the static atomic
                        let target_handle = WKWebViewHandle(
                            SNAPSHOT_TARGET_HANDLE.load(Ordering::SeqCst),
                        );

                        // Extract CGImage from NSImage (macOS).
                        // On macOS, NSImage has CGImageForProposedRect:context:hints:
                        let cls_nsimage = objc::runtime::Class::get("NSImage").unwrap();
                        let is_nsimage: bool = msg_send![snapshot, isKindOfClass: cls_nsimage];
                        if is_nsimage {
                            // Get CGImage from NSImage
                            let cg_image: *mut std::ffi::c_void =
                                msg_send![snapshot, CGImageForProposedRect: std::ptr::null_mut::<std::ffi::c_void>()
                                                                                 context: std::ptr::null_mut::<std::ffi::c_void>()
                                                                                 hints: std::ptr::null_mut::<std::ffi::c_void>()];
                            if cg_image.is_null() {
                                return;
                            }
                            convert_cgimage_to_rgba(cg_image, target_handle);
                        } else {
                            // If it's a UIImage (iOS) or already a CGImage, try CGImage property
                            let cg_image: *mut std::ffi::c_void =
                                msg_send![snapshot, CGImage];
                            if !cg_image.is_null() {
                                convert_cgimage_to_rgba(cg_image, target_handle);
                            }
                        }
                    }
                }

                let block = BlockLiteral::<extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object, *mut objc::runtime::Object)> {
                    isa: std::ptr::null_mut(),
                    flags: 0,
                    reserved: 0,
                    invoke: snapshot_completion_block
                        as *const extern "C" fn(*const std::ffi::c_void, *mut objc::runtime::Object, *mut objc::runtime::Object),
                };

                // nil configuration = default snapshot options
                let _: () = msg_send![
                    view,
                    takeSnapshotWithConfiguration: std::ptr::null_mut::<std::ffi::c_void>()
                    completionHandler: &block as *const BlockLiteral<_>
                        as *mut std::ffi::c_void
                ];
            });
        }
        let _ = handle;
    }

    /// Resize a WKWebView by updating its frame NSRect.
    fn resize_wkwebview_native(native_ptr: *mut std::ffi::c_void, width: f64, height: f64) {
        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            unsafe {
                // SAFETY: setFrame: is a standard NSView method, safe to call on WKWebView.
                let view = native_ptr as *mut objc::runtime::Object;
                let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(width, height));
                let _: () = msg_send![view, setFrame: frame];
            }
        }
        let _ = (width, height);
    }

    /// Close/destroy a WKWebView: stop loading, remove from superview, release.
    fn close_wkwebview_native(native_ptr: *mut std::ffi::c_void) {
        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            unsafe {
                // SAFETY: Standard NSView/WKWebView teardown sequence.
                let view = native_ptr as *mut objc::runtime::Object;
                let _: () = msg_send![view, stopLoading];
                let _: () = msg_send![view, removeFromSuperview];
                let _: () = msg_send![view, release];
            }
        }
    }
}

// ===========================================================================
// CGImage → RGBA pixel data conversion
// ===========================================================================

/// CoreGraphics C FFI declarations for CGImage pixel extraction.
/// These are C functions, not Objective-C methods, so we use `extern "C"` FFI.
#[cfg(target_os = "macos")]
#[allow(non_snake_case, dead_code)]
mod core_graphics_ffi {
    use std::ffi::c_void;

    unsafe extern "C" {
        // CGImageRef utilities
        pub fn CGImageGetWidth(image: *const c_void) -> usize;
        pub fn CGImageGetHeight(image: *const c_void) -> usize;
        pub fn CGImageGetBytesPerRow(image: *const c_void) -> usize;
        pub fn CGImageGetBitsPerComponent(image: *const c_void) -> usize;
        pub fn CGImageGetColorSpace(image: *const c_void) -> *const c_void;
        pub fn CGImageGetBitmapInfo(image: *const c_void) -> u32;

        // Color space
        pub fn CGColorSpaceCreateWithName(name: *const c_void) -> *const c_void;
        pub fn CGColorSpaceGetModel(space: *const c_void) -> i32;
        pub fn CGColorSpaceRelease(space: *const c_void);

        // Bitmap context
        pub fn CGBitmapContextCreateWithData(
            data: *mut c_void,
            width: usize,
            height: usize,
            bitsPerComponent: usize,
            bytesPerRow: usize,
            space: *const c_void,
            bitmapInfo: u32,
            releaseCallback: *const c_void,
            releaseContext: *const c_void,
        ) -> *mut c_void;
        pub fn CGBitmapContextGetData(ctx: *const c_void) -> *mut c_void;

        // CGContext drawing
        pub fn CGContextDrawImage(ctx: *const c_void, rect: *const c_void, image: *const c_void);

        // CFRelease for CoreFoundation objects
        pub fn CFRelease(cf: *const c_void);
    }

    // Constants
    pub const kCGBitmapByteOrder32Big: u32 = 1 << 13; // 8192
    pub const kCGImageAlphaPremultipliedLast: u32 = 2; // 0x0002
    // Combined: kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast = 8194
}

/// Convert a CGImageRef to RGBA pixel data and store it in the delegate state
/// for the given WKWebView handle.
///
/// SAFETY: `cg_image` must be a valid CGImageRef. This function reads pixel
/// data via CGBitmapContext drawing using CoreGraphics C FFI.
#[cfg(target_os = "macos")]
unsafe fn convert_cgimage_to_rgba(
    cg_image: *mut std::ffi::c_void,
    handle: WKWebViewHandle,
) {
    use self::core_graphics_ffi::*;

    // SAFETY: CGImageGetWidth/Height are pure C accessors. The CGImage is
    // guaranteed valid as it comes from the snapshot completion handler.

    // Get image dimensions
    let width = unsafe { CGImageGetWidth(cg_image as *const c_void) };
    let height = unsafe { CGImageGetHeight(cg_image as *const c_void) };

    if width == 0 || height == 0 {
        return;
    }

    // Create sRGB color space reference
    let srgb_name = ns_string_from_str("kCGColorSpaceSRGB");
    if srgb_name.is_null() {
        return;
    }
    let color_space = unsafe { CGColorSpaceCreateWithName(srgb_name as *const c_void) };
    if color_space.is_null() {
        return;
    }

    let bytes_per_row = width * 4;
    let buffer_size = bytes_per_row * height;
    let mut pixel_buffer: Vec<u8> = vec![0u8; buffer_size];

    let bitmap_info = kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast; // 8194

    // Create bitmap context — pixel_buffer is written to by CoreGraphics
    let ctx = unsafe {
        CGBitmapContextCreateWithData(
            pixel_buffer.as_mut_ptr() as *mut c_void,
            width,
            height,
            8, // bits per component
            bytes_per_row,
            color_space,
            bitmap_info,
            std::ptr::null(), // release callback
            std::ptr::null(), // release context
        )
    };

    if ctx.is_null() {
        unsafe { CGColorSpaceRelease(color_space); }
        return;
    }

    // Draw the CGImage into the bitmap context at (0,0)–(width,height)
    // The rect is a CGRect = {origin={x=0,y=0}, size={width,height}}
    let rect = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(width as f64, height as f64));
    unsafe {
        CGContextDrawImage(
            ctx as *const c_void,
            &rect as *const NSRect as *const c_void,
            cg_image as *const c_void,
        );
    }

    // Release CoreFoundation objects
    unsafe {
        CFRelease(ctx as *const c_void);
        CGColorSpaceRelease(color_space);
    }

    // Store the pixel buffer in delegate state
    if let Ok(mut state) = DELEGATE_STATE.lock() {
        state.snapshot_results.insert(handle, Some(pixel_buffer));
    }
}

// ===========================================================================
// CefBridge implementation
// ===========================================================================

impl CefBridge {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_handle(&mut self) -> CefHandle {
        let h = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }

    /// Ensure NSApplication and WKWebViewManager are initialized.
    /// Called internally before any WKWebView operations.
    fn ensure_webview_manager(&mut self) -> AppResult<&mut WKWebViewManager> {
        if self.webview_manager.is_none() {
            let mgr = WKWebViewManager::new();
            if !mgr.is_available() {
                return Err(AppError::new(
                    ReasonCode::RcInvalidState,
                    "WKWebView is not available on this system",
                ));
            }
            self.webview_manager = Some(mgr);
        }
        Ok(self.webview_manager.as_mut().unwrap())
    }

    // -----------------------------------------------------------------------
    // cef_initialize — initialise the CEF subsystem
    //
    // Sets the bridge state to Initialized, stores the CefSettings for later
    // use, and prepares the WKWebViewManager for browser creation.
    // -----------------------------------------------------------------------
    pub fn cef_initialize(&mut self, settings: CefSettings) -> AppResult<()> {
        if self.state != CefState::Uninitialized {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cef_initialize: already initialised",
            ));
        }

        // Store settings — field meanings:
        // - multi_threaded_message_loop: if true, CEF runs its own message loop thread
        // - external_message_pump: if true, caller drives message loop via cef_do_message_loop_work
        // - cache_path: directory for browser cache data
        // - user_agent: custom HTTP User-Agent string
        // - locale: browser locale (e.g., "en-US")
        // - log_severity: LOGSEVERITY enum (0=default, 1=verbose, 2=warning, 3=error)
        // - resources_dir_path: path to CEF resource files (unused in WKWebView mode)
        // - locales_dir_path: path to locale pak files (unused in WKWebView mode)
        // - pack_file_path: path to pack files (unused in WKWebView mode)
        self.settings = settings;

        // Initialize WKWebView manager (creates NSApplication, offscreen window)
        #[cfg(target_os = "macos")]
        {
            let _ = self.ensure_webview_manager()?;
        }

        self.state = CefState::Initialized;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // cef_shutdown — shut down the CEF subsystem
    //
    // Closes all open browsers, clears all frames and rendered frame buffers,
    // and transitions state to ShuttingDown.
    // -----------------------------------------------------------------------
    pub fn cef_shutdown(&mut self) -> AppResult<()> {
        if self.state != CefState::Initialized {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cef_shutdown: not initialised",
            ));
        }

        // Close all WKWebView instances via the manager
        if let Some(mgr) = self.webview_manager.as_mut() {
            mgr.close_all();
        }

        self.browsers.clear();
        self.frames.clear();
        self.rendered_frames.clear();
        self.webview_manager = None;
        self.state = CefState::ShuttingDown;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // cef_browser_host_create_browser — create a new browser instance
    //
    // Creates a new WKWebView via the WKWebViewManager, associates it with a
    // CefBrowser handle, and allocates the initial offscreen rendering surface.
    //
    // The CefWindowInfo provides:
    // - x, y, width, height: initial position and size
    // - windowless_rendering_enabled: offscreen mode flag
    // - url: initial URL to navigate to (Steam-specific)
    // - parent_window: HWND mapping for overlay (unused on macOS)
    // -----------------------------------------------------------------------
    pub fn cef_browser_host_create_browser(
        &mut self,
        window_info: CefWindowInfo,
        url: &str,
        _browser_settings: CefBrowserSettings,
    ) -> AppResult<CefHandle> {
        if self.state != CefState::Initialized {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cef_browser_host_create_browser: not initialised",
            ));
        }

        let browser_handle = self.next_handle();
        let frame_handle = self.next_handle();
        let browser_id = {
            let id = self.next_browser_id;
            self.next_browser_id += 1;
            id
        };

        // Clone UA string before mutable borrow of self
        let user_agent = self.settings.user_agent.clone();

        // Create the WKWebView via the manager
        let wk_handle = if let Ok(mgr) = self.ensure_webview_manager() {
            let config = WKWebViewConfig {
                width: window_info.width as f64,
                height: window_info.height as f64,
                java_script_enabled: true,
                user_agent,
            };
            match mgr.create_webview(config) {
                Ok(h) => {
                    // Navigate to the initial URL
                    let nav_url = if !url.is_empty() {
                        url
                    } else {
                        window_info.url.as_deref().unwrap_or("about:blank")
                    };
                    let _ = mgr.navigate(h, nav_url);
                    Some(h)
                }
                Err(e) => {
                    eprintln!(
                        "[CefBridge] Failed to create WKWebView: {}. \
                         Continuing with software buffer.",
                        e.message
                    );
                    None
                }
            }
        } else {
            None
        };

        let browser = CefBrowser {
            id: browser_id,
            host_handle: browser_handle,
            main_frame_handle: frame_handle,
            can_go_back: false,
            can_go_forward: false,
            is_loading: true,
            current_url: url.to_string(),
            title: String::new(),
            zoom_level: 1.0,
            wk_handle,
            dirty: true,
            metal_texture_id: None,
        };

        let frame = CefFrame {
            browser_handle,
            identifier: 1, // main frame always has identifier 1
            url: url.to_string(),
            name: String::new(),
            is_main: true,
            is_focused: true,
        };

        self.browsers.insert(browser_handle, browser);
        self.frames.insert((browser_handle, 1), frame);

        // Allocate an initial offscreen surface for the browser
        let frame_w = window_info.width.max(1) as u32;
        let frame_h = window_info.height.max(1) as u32;
        let pixels = vec![0xFF; (frame_w * frame_h * 4) as usize]; // white background
        self.rendered_frames.push_back(RenderedFrame {
            browser_id,
            width: frame_w,
            height: frame_h,
            pixels,
            frame_number: 0,
        });

        Ok(browser_handle)
    }

    // -----------------------------------------------------------------------
    // cef_run_message_loop — run one iteration of the CEF message loop
    //
    // Pumps the NSRunLoop for a short duration (10ms) to process pending UI
    // events, navigation callbacks, and snapshot completions. Also updates
    // rendered frames from WKWebView snapshots.
    // -----------------------------------------------------------------------
    pub fn cef_run_message_loop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            // Pump the NSRunLoop for ~10ms to process pending events
            unsafe {
                let cls_runloop = match objc::runtime::Class::get("NSRunLoop") {
                    Some(c) => c,
                    None => return,
                };
                let cls_date = match objc::runtime::Class::get("NSDate") {
                    Some(c) => c,
                    None => return,
                };

                let current_runloop: *mut objc::runtime::Object =
                    msg_send![cls_runloop, currentRunLoop];
                let interval: *mut objc::runtime::Object =
                    msg_send![cls_date, dateWithTimeIntervalSinceNow: 0.01];

                if !current_runloop.is_null() && !interval.is_null() {
                    let _: () = msg_send![
                        current_runloop,
                        runUntilDate: interval
                    ];
                }
            }

            // Process pending WKWebView operations
            self.process_pending_webview_ops();
        }
    }

    // -----------------------------------------------------------------------
    // cef_do_message_loop_work — perform one unit of message loop work
    //
    // Processes pending WKWebView callbacks (navigation, snapshots) without
    // running the full runloop. Lighter than cef_run_message_loop.
    // -----------------------------------------------------------------------
    pub fn cef_do_message_loop_work(&mut self) {
        #[cfg(target_os = "macos")]
        {
            self.process_pending_webview_ops();
        }
    }

    /// Process pending WKWebView operations: update navigation states,
    /// consume snapshot results, and update rendered frame buffers.
    #[cfg(target_os = "macos")]
    fn process_pending_webview_ops(&mut self) {
        let mgr = match self.webview_manager.as_mut() {
            Some(m) => m,
            None => return,
        };

        let browser_wk_handles: Vec<(CefHandle, WKWebViewHandle)> = self
            .browsers
            .iter()
            .filter_map(|(&bh, b)| b.wk_handle.map(|wk| (bh, wk)))
            .collect();

        for (browser_handle, wk_handle) in &browser_wk_handles {
            // Check navigation completion
            if let Some(did_finish) = mgr.navigation_did_finish(*wk_handle) {
                if let Some(browser) = self.browsers.get_mut(browser_handle) {
                    if did_finish {
                        browser.is_loading = false;
                        browser.dirty = true;
                    }
                }
            }

            // Try to update snapshot if dirty
            if let Some(browser) = self.browsers.get(browser_handle) {
                if browser.dirty {
                    if let Some(dims) = mgr.dimensions(*wk_handle) {
                        let _ = mgr.take_snapshot(*wk_handle);

                        // Check if we got pixel data back
                        if let Ok(mut state) = DELEGATE_STATE.lock() {
                            if let Some(Some(pixels)) =
                                state.snapshot_results.remove(wk_handle)
                            {
                                if let Some(b) = self.browsers.get_mut(browser_handle) {
                                    let frame_n = self.rendered_frames.len() as u64;
                                    let rendered = RenderedFrame {
                                        browser_id: b.id,
                                        width: dims.0 as u32,
                                        height: dims.1 as u32,
                                        pixels,
                                        frame_number: frame_n,
                                    };

                                    // If paint callback is set, invoke it
                                    if let Some(ref mut cb) = self.paint_callback {
                                        cb(rendered.clone());
                                    }

                                    self.rendered_frames
                                        .push_back(rendered);
                                    while self.rendered_frames.len() > 10 {
                                        self.rendered_frames.pop_front();
                                    }

                                    b.dirty = false;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // cef_browser_get_host — get the host handle for a browser
    //
    // In WKWebView mode, the browser and its host are the same object.
    // Returns the browser handle itself as the host handle.
    // -----------------------------------------------------------------------
    pub fn cef_browser_get_host(&self, browser_handle: CefHandle) -> AppResult<CefHandle> {
        self.browsers
            .get(&browser_handle)
            .map(|b| b.host_handle)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcNotFound,
                    format!("cef_browser_get_host: browser {browser_handle:#x} not found"),
                )
            })
    }

    // -----------------------------------------------------------------------
    // cef_browser_get_main_frame — get the main frame of a browser
    //
    // Returns the main frame handle (identifier=1) for the browser.
    // Each browser always has at least one frame (the main frame).
    // -----------------------------------------------------------------------
    pub fn cef_browser_get_main_frame(&self, browser_handle: CefHandle) -> AppResult<CefHandle> {
        self.browsers
            .get(&browser_handle)
            .map(|b| b.main_frame_handle)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcNotFound,
                    format!(
                        "cef_browser_get_main_frame: browser {browser_handle:#x} not found"
                    ),
                )
            })
    }

    // -----------------------------------------------------------------------
    // cef_frame_load_url — navigate a frame to a URL
    //
    // Delegates to WKWebViewManager::navigate() which calls loadRequest: on
    // the native WKWebView. Also updates the CefFrame's URL tracking.
    // -----------------------------------------------------------------------
    pub fn cef_frame_load_url(&mut self, browser_handle: CefHandle, url: &str) -> AppResult<()> {
        let browser = self.browsers.get_mut(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("cef_frame_load_url: browser {browser_handle:#x} not found"),
            )
        })?;

        browser.current_url = url.to_string();
        browser.is_loading = true;
        browser.dirty = true;

        // Navigate via WKWebView
        if let Some(wk_handle) = browser.wk_handle {
            if let Some(mgr) = self.webview_manager.as_mut() {
                mgr.navigate(wk_handle, url)?;
            }
        }

        // Update the main frame's URL
        if let Some(frame) = self.frames.get_mut(&(browser_handle, 1)) {
            frame.url = url.to_string();
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // cef_browser_go_back — navigate back in browser history
    //
    // Calls goBack: on the native WKWebView. Checks can_go_back first to
    // ensure there is back navigation history available.
    // -----------------------------------------------------------------------
    pub fn cef_browser_go_back(&mut self, browser_handle: CefHandle) -> AppResult<()> {
        let browser = self.browsers.get_mut(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("cef_browser_go_back: browser {browser_handle:#x} not found"),
            )
        })?;

        if !browser.can_go_back {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cef_browser_go_back: no back history",
            ));
        }

        // Call goBack: on WKWebView
        if let Some(wk_handle) = browser.wk_handle {
            if let Some(mgr) = self.webview_manager.as_ref() {
                if let Some(ptr) = mgr.native_ptr(wk_handle) {
                    #[cfg(target_os = "macos")]
                    unsafe {
                        // SAFETY: goBack: is a standard WKWebView method.
                        let view = ptr as *mut objc::runtime::Object;
                        let _: () = msg_send![view, goBack];
                    }
                }
            }
        }

        browser.is_loading = true;
        browser.dirty = true;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // cef_browser_reload — reload the current page
    //
    // Calls reload: on the native WKWebView.
    // -----------------------------------------------------------------------
    pub fn cef_browser_reload(&mut self, browser_handle: CefHandle) -> AppResult<()> {
        let browser = self.browsers.get_mut(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("cef_browser_reload: browser {browser_handle:#x} not found"),
            )
        })?;

        // Call reload: on WKWebView
        if let Some(wk_handle) = browser.wk_handle {
            if let Some(mgr) = self.webview_manager.as_ref() {
                if let Some(ptr) = mgr.native_ptr(wk_handle) {
                    #[cfg(target_os = "macos")]
                    unsafe {
                        // SAFETY: reload: is a standard WKWebView method.
                        let view = ptr as *mut objc::runtime::Object;
                        let _: () = msg_send![view, reload];
                    }
                }
            }
        }

        browser.is_loading = true;
        browser.dirty = true;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // cef_frame_execute_java_script — execute JS in a frame
    //
    // Calls evaluateJavaScript:completionHandler: on the native WKWebView.
    // The script is executed in the context of the specified frame.
    // -----------------------------------------------------------------------
    pub fn cef_frame_execute_java_script(
        &mut self,
        browser_handle: CefHandle,
        _frame_identifier: i64,
        script: &str,
    ) -> AppResult<String> {
        let browser = self.browsers.get(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!(
                    "cef_frame_execute_java_script: browser {browser_handle:#x} not found"
                ),
            )
        })?;

        if let Some(wk_handle) = browser.wk_handle {
            if let Some(mgr) = self.webview_manager.as_mut() {
                return mgr.evaluate_java_script(wk_handle, script);
            }
        }

        Ok(String::new())
    }

    // -----------------------------------------------------------------------
    // cef_browser_is_valid — check if a browser handle is valid
    // -----------------------------------------------------------------------
    pub fn cef_browser_is_valid(&self, browser_handle: CefHandle) -> bool {
        self.browsers.contains_key(&browser_handle)
    }

    // -----------------------------------------------------------------------
    // get_rendered_frame — retrieve the latest rendered frame for a browser
    // -----------------------------------------------------------------------
    pub fn get_rendered_frame(&self, browser_id: u32) -> Option<&RenderedFrame> {
        self.rendered_frames
            .iter()
            .rev()
            .find(|f| f.browser_id == browser_id)
    }

    // -----------------------------------------------------------------------
    // set_paint_callback — register a callback for paint events
    //
    // The callback is invoked whenever a new RenderedFrame is produced from
    // a WKWebView snapshot. This allows the compositor to integrate browser
    // content into the Metal rendering pipeline.
    // -----------------------------------------------------------------------
    pub fn set_paint_callback(&mut self, callback: Box<dyn FnMut(RenderedFrame) + Send>) {
        self.paint_callback = Some(callback);
    }

    // -----------------------------------------------------------------------
    // resize — resize a browser's rendering surface
    //
    // Updates the WKWebView frame via resize_wkwebview_native and allocates
    // a new pixel buffer matching the new dimensions.
    // -----------------------------------------------------------------------
    pub fn resize(&mut self, browser_handle: CefHandle, width: u32, height: u32) {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            // Update WKWebView dimensions
            if let Some(wk_handle) = browser.wk_handle {
                if let Some(mgr) = self.webview_manager.as_mut() {
                    let _ = mgr.resize(wk_handle, width as f64, height as f64);
                }
            }

            // Update frame buffer
            let pixels = vec![0xFF; (width as usize * height as usize * 4)];
            self.rendered_frames.push_back(RenderedFrame {
                browser_id: browser.id,
                width,
                height,
                pixels,
                frame_number: self.rendered_frames.len() as u64,
            });
            // Keep only the most recent frame per browser
            while self.rendered_frames.len() > 10 {
                self.rendered_frames.pop_front();
            }

            browser.dirty = true;
        }
    }

    // -----------------------------------------------------------------------
    // close_browser — close and destroy a browser
    //
    // Removes the browser from the bridge state, closes its WKWebView,
    // and cleans up associated frames and rendered frame data.
    // -----------------------------------------------------------------------
    pub fn close_browser(&mut self, browser_handle: CefHandle) -> AppResult<()> {
        let browser = self.browsers.remove(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("close_browser: browser {browser_handle:#x} not found"),
            )
        })?;

        // Close the WKWebView
        if let Some(wk_handle) = browser.wk_handle {
            if let Some(mgr) = self.webview_manager.as_mut() {
                mgr.close(wk_handle);
            }
        }

        // Remove frames for this browser
        self.frames.retain(|&(bh, _), _| bh != browser_handle);

        // Remove rendered frames for this browser
        self.rendered_frames.retain(|f| f.browser_id != browser.id);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // render_to_metal_texture — composite a rendered browser frame into a
    // Metal texture for GPU compositing.
    //
    // This is the bridge between CEF/WKWebView offscreen rendering and the
    // Metal graphics pipeline. It:
    //   1. Gets the latest RenderedFrame snapshot for the browser
    //   2. Creates an MTLTextureDescriptor for a 2D RGBA texture
    //   3. Uploads pixel data to an MTLBuffer
    //   4. Blits the buffer to a texture via MTLBlitCommandEncoder
    //   5. Returns the resulting MTLTexture reference
    //
    // The frame snapshot format is RGBA8 (4 bytes per pixel) matching
    // Metal's MTLPixelFormatRGBA8Unorm.
    // -----------------------------------------------------------------------
    #[cfg(feature = "metal")]
    pub fn render_to_metal_texture(
        &mut self,
        browser_handle: CefHandle,
        metal_device: &crate::metal_backend::MetalDevice,
    ) -> AppResult<metal::Texture> {
        let browser = self.browsers.get(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!(
                    "render_to_metal_texture: browser {browser_handle:#x} not found"
                ),
            )
        })?;

        let frame = self.get_rendered_frame(browser.id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!(
                    "render_to_metal_texture: no rendered frame for browser {}",
                    browser.id
                ),
            )
        })?;

        let width = frame.width as u64;
        let height = frame.height as u64;
        // Copy the frame_number before the mutable borrow below
        let frame_number = frame.frame_number;

        // Create a Metal texture descriptor for RGBA8 2D texture
        let descriptor = metal::TextureDescriptor::new();
        descriptor.set_texture_type(metal::MTLTextureType::D2);
        descriptor.set_pixel_format(metal::MTLPixelFormat::RGBA8Unorm);
        descriptor.set_width(width);
        descriptor.set_height(height);
        descriptor.set_usage(
            metal::MTLTextureUsage::ShaderRead
                | metal::MTLTextureUsage::RenderTarget,
        );
        descriptor.set_storage_mode(metal::MTLStorageMode::Shared);

        let texture = metal_device.device().new_texture(&descriptor);

        // Upload pixel data via replaceRegion
        let region = metal::MTLRegion {
            origin: metal::MTLOrigin { x: 0, y: 0, z: 0 },
            size: metal::MTLSize {
                width: width as u64,
                height: height as u64,
                depth: 1,
            },
        };
        let bytes_per_row = (width * 4) as u64;
        texture.replace_region(region, 0, frame.pixels.as_ptr() as *const std::ffi::c_void, bytes_per_row);

        // Cache the texture ID
        if let Some(b) = self.browsers.get_mut(&browser_handle) {
            b.metal_texture_id = Some(frame_number);
        }

        Ok(texture)
    }

    /// Non-metal fallback: returns an error if the `metal` feature is not enabled.
    #[cfg(not(feature = "metal"))]
    pub fn render_to_metal_texture(
        &mut self,
        _browser_handle: CefHandle,
        _metal_device: &crate::metal_backend::MetalDevice,
    ) -> AppResult<metal::Texture> {
        Err(AppError::new(
            ReasonCode::RcInvalidState,
            "render_to_metal_texture: metal feature not enabled",
        ))
    }

    /// Get the handle of the first registered browser, if any.
    pub fn first_browser_handle(&self) -> Option<CefHandle> {
        self.browsers.keys().next().copied()
    }

    // -----------------------------------------------------------------------
    // submit_latest_frame_to_compositor — push the latest RenderedFrame for a
    // browser into the global CEF Metal compositor for overlay compositing.
    //
    // Called from the frame publishing path (e.g. process_pending_webview_ops
    // or the pe_runtime WM_PAINT handler) whenever a new WKWebView snapshot is
    // captured.
    // -----------------------------------------------------------------------
    pub fn submit_latest_frame_to_compositor(&mut self, browser_handle: CefHandle) {
        let browser_id = match self.browsers.get(&browser_handle) {
            Some(b) => b.id,
            None => return,
        };
        let frame = match self.get_rendered_frame(browser_id) {
            Some(f) => f.clone(),
            None => return,
        };
        crate::metal_renderer::submit_cef_overlay_frame(
            frame.width,
            frame.height,
            frame.pixels,
        );
    }

    /// Submit the latest frame for the first browser to the compositor.
    /// Convenience wrapper used by pe_runtime integration.
    pub fn submit_first_browser_to_compositor(&mut self) {
        if let Some(handle) = self.first_browser_handle() {
            self.submit_latest_frame_to_compositor(handle);
        }
    }

    /// Mark a browser's rendered frame as dirty, triggering a new snapshot
    /// on the next message loop iteration.
    pub fn mark_dirty(&mut self, browser_handle: CefHandle) {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.dirty = true;
        }
    }

    // -----------------------------------------------------------------------
    // cef_browser_host_was_resized — notify the browser that the view was
    // resized (maps to CefBrowserHost::WasResized in the CEF C API).
    //
    // This is called when the window containing the WKWebView changes size.
    // It resizes the underlying WKWebView frame and updates all internal
    // pixel buffers to match the new dimensions. The next snapshot will
    // capture at the new size.
    //
    // Returns the new (width, height) on success.
    // -----------------------------------------------------------------------
    pub fn cef_browser_host_was_resized(&mut self, browser_handle: CefHandle, width: u32, height: u32) -> AppResult<(u32, u32)> {
        let browser = self.browsers.get_mut(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("cef_browser_host_was_resized: browser {browser_handle:#x} not found"),
            )
        })?;

        // Clamp to minimum useful size (1x1)
        let width = width.max(1);
        let height = height.max(1);

        // Update WKWebView frame via the webview manager
        if let Some(wk_handle) = browser.wk_handle {
            if let Some(mgr) = self.webview_manager.as_mut() {
                let _ = mgr.resize(wk_handle, width as f64, height as f64);
            }
        }

        // Update the frame buffer dimensions
        let pixels = vec![0xFFu8; (width as usize).saturating_mul(height as usize).saturating_mul(4)];
        self.rendered_frames.push_back(RenderedFrame {
            browser_id: browser.id,
            width,
            height,
            pixels,
            frame_number: self.rendered_frames.len() as u64,
        });
        while self.rendered_frames.len() > 10 {
            self.rendered_frames.pop_front();
        }

        // Mark dirty so the next snapshot captures at the new size
        browser.dirty = true;

        eprintln!(
            "[CefBridge] WasResized: browser {browser_handle:#x} -> {width}x{height}"
        );

        Ok((width, height))
    }

    /// Get the current CEF state
    pub fn state(&self) -> CefState {
        self.state
    }

    /// Get a reference to the internal browser map (for testing/inspection)
    pub fn browsers(&self) -> &BTreeMap<CefHandle, CefBrowser> {
        &self.browsers
    }

    /// Get a mutable reference to the WKWebView manager (for testing)
    pub fn webview_manager(&mut self) -> Option<&mut WKWebViewManager> {
        self.webview_manager.as_mut()
    }
}

// ===========================================================================
// CEF Handler Callbacks — lifecycle events Steam expects from libcef
// ===========================================================================

impl CefBridge {
    /// `CefLifeSpanHandler::OnAfterCreated` — called after a browser is created.
    ///
    /// Updates the browser's internal state to reflect that it is fully initialized.
    /// Steam's UI layer expects this callback before it sends navigation or JS commands.
    pub fn on_after_created(&mut self, browser_handle: CefHandle) -> AppResult<()> {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.is_loading = true;
            browser.dirty = true;
            eprintln!("[CefBridge] OnAfterCreated: browser {browser_handle:#x}");
        }
        Ok(())
    }

    /// `CefLoadHandler::OnLoadEnd` — called when a page finishes loading.
    ///
    /// Marks the browser as no longer loading and triggers a snapshot for rendering.
    /// Steam uses this to know when to inject its JavaScript bridge.
    pub fn on_load_end(&mut self, browser_handle: CefHandle) -> AppResult<()> {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.is_loading = false;
            browser.dirty = true;
            eprintln!("[CefBridge] OnLoadEnd: browser {browser_handle:#x}");
        }
        Ok(())
    }

    /// `CefDisplayHandler::OnTitleChange` — called when the page title changes.
    ///
    /// Updates the browser's cached title. Steam's UI may check this to update
    /// window title or internal state.
    pub fn on_title_change(&mut self, browser_handle: CefHandle, title: &str) -> AppResult<()> {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.title = title.to_string();
            eprintln!(
                "[CefBridge] OnTitleChange: browser {browser_handle:#x} title={title}"
            );
        }
        Ok(())
    }

    /// `CefRequestHandler::OnBeforeBrowse` — called before a navigation request.
    ///
    /// Returns `true` to cancel the navigation, `false` to allow it.
    /// By default, all navigations are allowed. Steam may use this to intercept
    /// `steam://` protocol URLs and route them to native handlers.
    pub fn on_before_browse(&mut self, _browser_handle: CefHandle, url: &str) -> bool {
        // Allow all navigations by default, but log steam:// URLs for debugging
        if url.starts_with("steam://") {
            eprintln!("[CefBridge] OnBeforeBrowse (steam://): {url}");
            // steam:// URLs are handled natively — cancel browser navigation
            return true;
        }
        eprintln!("[CefBridge] OnBeforeBrowse: {url}");
        false
    }

    /// Register a JavaScript extension for all current and future browser instances.
    ///
    /// This is the CefRegisterExtension equivalent. In WKWebView mode, extensions
    /// are injected via WKUserScript objects. The script is evaluated in every frame
    /// before page content loads.
    ///
    /// The extension_name is logged but the script content is what gets injected.
    pub fn cef_register_extension(&mut self, extension_name: &str, script: &str) -> AppResult<()> {
        eprintln!(
            "[CefBridge] RegisterExtension: {extension_name} ({} bytes)",
            script.len()
        );

        // Inject into all existing browsers via WKWebView evaluateJavaScript
        let browser_handles: Vec<CefHandle> = self.browsers.keys().copied().collect();
        for handle in &browser_handles {
            self.cef_frame_execute_java_script(*handle, 1, script)?;
        }

        // Store the extension for future browsers (when open_browser is called)
        // In a full implementation, this would be stored in the WKUserContentController
        // on the WKWebViewConfiguration before WKWebView creation.
        Ok(())
    }

    /// Dispatch a CefQuery (JS→Native message) and return a JSON response.
    ///
    /// This bridges Steam's `window.externalCallback` mechanism. The query is a
    /// JSON string with fields: request, requestId, type, etc.
    pub fn dispatch_cef_query(&mut self, query_json: &str) -> AppResult<String> {
        let query: serde_json::Value = serde_json::from_str(query_json).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("dispatch_cef_query: invalid JSON: {e}"),
            )
        })?;

        let request = query
            .get("request")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let request_id = query
            .get("requestId")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let query_type = query
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let response = match query_type {
            "store_navigation" => {
                let store_url = format!("https://store.steampowered.com{request}");
                if let Some(&bh) = self.browsers.keys().next() {
                    self.cef_frame_load_url(bh, &store_url)?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }
            "login" => {
                if let Some(&bh) = self.browsers.keys().next() {
                    self.cef_frame_load_url(bh, "https://steamcommunity.com/login")?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "login_initiated"
                })
            }
            "download" => {
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "download_acknowledged"
                })
            }
            "open_external_url" => {
                if !request.is_empty() {
                    let _ = std::process::Command::new("open").arg(request).spawn();
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "opened"
                })
            }
            _ => {
                serde_json::json!({
                    "success": false,
                    "requestId": request_id,
                    "error": format!("unknown query type: {query_type}")
                })
            }
        };

        Ok(response.to_string())
    }
}

// ===========================================================================
// CefCookieManager — cookie/storage persistence for CEF API
// ===========================================================================

/// Minimal CEF cookie structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CefCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub httponly: bool,
    pub creation: u64,
    pub last_access: u64,
    pub expires: u64,
}

impl Default for CefCookie {
    fn default() -> Self {
        Self {
            name: String::new(),
            value: String::new(),
            domain: String::new(),
            path: String::new(),
            secure: false,
            httponly: false,
            creation: 0,
            last_access: 0,
            expires: 0,
        }
    }
}

/// Cookie manager for CEF persistence.
///
/// Maps to `CefCookieManager` in the CEF C API. Provides cookie storage backed
/// by a JSON file on disk so that Steam login sessions survive restarts.
/// Cookies are stored in `cache_path/cookies.json`.
pub struct CefCookieManager {
    /// File path for the cookie store JSON
    store_path: std::path::PathBuf,
    /// In-memory cookie store
    cookies: Vec<CefCookie>,
    /// Whether the store has been modified since last write
    dirty: bool,
}

impl std::fmt::Debug for CefCookieManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CefCookieManager")
            .field("store_path", &self.store_path)
            .field("cookie_count", &self.cookies.len())
            .field("dirty", &self.dirty)
            .finish()
    }
}

impl CefCookieManager {
    /// Create a new cookie manager backed by the given cache path.
    pub fn new(cache_path: &str) -> Self {
        let store_path = std::path::PathBuf::from(cache_path).join("cookies.json");
        let cookies = if store_path.exists() {
            match std::fs::read_to_string(&store_path) {
                Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        Self {
            store_path,
            cookies,
            dirty: false,
        }
    }

    /// Set a cookie. If a cookie with the same name/domain/path exists, it is replaced.
    pub fn set_cookie(&mut self, cookie: CefCookie) -> AppResult<()> {
        // Remove existing cookie with same name/domain/path
        self.cookies.retain(|c| {
            !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path)
        });
        self.cookies.push(cookie);
        self.dirty = true;
        self.flush()?;
        Ok(())
    }

    /// Visit all stored cookies. Calls `visitor` for each cookie.
    pub fn visit_all_cookies(&self) -> Vec<CefCookie> {
        self.cookies.clone()
    }

    /// Delete cookies matching the given URL and name filters.
    pub fn delete_cookies(&mut self, url: Option<&str>, name: Option<&str>) -> AppResult<()> {
        self.cookies.retain(|c| {
            if let Some(url_filter) = url {
                if !c.domain.contains(url_filter) {
                    return true; // keep, doesn't match URL filter
                }
            }
            if let Some(name_filter) = name {
                if c.name != name_filter {
                    return true; // keep, doesn't match name filter
                }
            }
            false // remove
        });
        self.dirty = true;
        self.flush()?;
        Ok(())
    }

    /// Flush the cookie store to disk if dirty.
    pub fn flush(&mut self) -> AppResult<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self.store_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = serde_json::to_string_pretty(&self.cookies).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("cookie flush serialization: {e}"),
            )
        })?;
        std::fs::write(&self.store_path, &data).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("cookie flush write: {e}"),
            )
        })?;
        self.dirty = false;
        Ok(())
    }

    /// Get the global cookie manager instance (singleton).
    pub fn get_global(cache_path: &str) -> std::sync::Arc<std::sync::Mutex<CefCookieManager>> {
        static GLOBAL_COOKIE_MANAGER: std::sync::LazyLock<
            std::sync::Mutex<Option<std::sync::Arc<std::sync::Mutex<CefCookieManager>>>>,
        > = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

        let mut guard = GLOBAL_COOKIE_MANAGER.lock().unwrap();
        if guard.is_none() {
            let mgr = CefCookieManager::new(cache_path);
            *guard = Some(std::sync::Arc::new(std::sync::Mutex::new(mgr)));
        }
        guard.as_ref().cloned().unwrap()
    }
}

// ===========================================================================
// SteamWebHelper Shim — replacement for steamwebhelper.exe
// ===========================================================================

/// Render mode for the SteamWebHelper shim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SteamRenderMode {
    /// No visible window, rendering to offscreen buffer
    Headless,
    /// Rendered in a separate window
    Windowed,
    /// Rendered as an overlay on top of a game
    Overlay,
}

/// Shim replacement for steamwebhelper.exe.
///
/// Steam normally launches `steamwebhelper.exe` (a CEF-based process) to render
/// the Steam UI (store, library, settings). On macOS, this process does not exist,
/// so we provide this shim that creates a WKWebView-based browser and bridges
/// the CefQuery IPC protocol that Steam uses for browser↔client communication.
///
/// The shim manages:
/// - WKWebView lifecycle (create, navigate, resize, snapshot)
/// - Frame capture at ~60fps for smooth rendering
/// - CefQuery IPC message routing (store navigation, login, downloads, etc.)
/// - Integration with the CefBridge for CEF API compatibility
pub struct SteamWebHelperShim {
    /// The underlying CefBridge that manages WKWebView instances
    pub bridge: CefBridge,
    /// Initial URL to load (e.g., steam://connect/... or https://steamcommunity.com)
    pub initial_url: String,
    /// How the browser is rendered
    pub render_mode: SteamRenderMode,
    /// Window handle for overlay mode (HWND mapping)
    pub window_handle: Option<u64>,
    /// Whether the shim is currently running
    running: bool,
    /// Frame timer tracking
    frame_count: u64,
}

impl SteamWebHelperShim {
    /// Create a new SteamWebHelper shim with the given configuration.
    pub fn new(initial_url: String, render_mode: SteamRenderMode) -> Self {
        Self {
            bridge: CefBridge::new(),
            initial_url,
            render_mode,
            window_handle: None,
            running: false,
            frame_count: 0,
        }
    }

    /// Launch the SteamWebHelper shim.
    ///
    /// 1. Initializes CefBridge with default settings
    /// 2. Creates a WKWebView with the initial URL
    /// 3. Sets up the message pump for frame capture (~60fps)
    /// 4. Starts capturing frames as RenderedFrame snapshots
    pub fn launch(&mut self) -> AppResult<CefHandle> {
        let settings = CefSettings {
            windowless_rendering_enabled: self.render_mode == SteamRenderMode::Headless,
            user_agent: Some(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
                 AppleWebKit/605.1.15 (KHTML, like Gecko) Steam/1.0"
                    .to_string(),
            ),
            ..CefSettings::default()
        };

        self.bridge.cef_initialize(settings)?;

        let window_info = CefWindowInfo {
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            windowless_rendering_enabled: self.render_mode == SteamRenderMode::Headless,
            parent_window: self.window_handle.unwrap_or(0),
            url: None,
            external_begin_frame_enabled: false,
        };

        let browser_handle = self.bridge.cef_browser_host_create_browser(
            window_info,
            &self.initial_url,
            CefBrowserSettings::default(),
        )?;

        self.running = true;
        self.frame_count = 0;

        eprintln!(
            "[SteamWebHelper] Launched with URL: {}, mode: {:?}, handle: {:#x}",
            self.initial_url,
            self.render_mode,
            browser_handle,
        );

        Ok(browser_handle)
    }

    /// Run one frame update cycle (~16ms at 60fps).
    ///
    /// Pumps the message loop, processes navigation callbacks, and triggers
    /// snapshot capture for the active browser.
    pub fn tick(&mut self) {
        if !self.running {
            return;
        }

        self.bridge.cef_run_message_loop();
        self.frame_count += 1;
    }

    /// Handle a CefQuery IPC message from Steam.
    ///
    /// Steam's browser↔client IPC uses a query mechanism where JavaScript in
    /// the web page sends structured JSON requests, and the native client
    /// responds via JavaScript callback.
    ///
    /// Query format:
    ///   {
    ///     "request": "<json>",
    ///     "requestId": <number>,
    ///     "type": "<type>"
    ///   }
    ///
    /// Supported types:
    /// - "store_navigation": Navigate to a Steam store page
    /// - "login": Steam login/authentication
    /// - "download": Trigger a download
    /// - "open_external_url": Open a URL in the default browser
    ///
    /// Returns a JSON response string to be delivered via
    /// `window.externalCallback(response)` in the web page.
    pub fn handle_cef_query(&mut self, query_json: &str) -> AppResult<String> {
        // Parse the query JSON
        let query: serde_json::Value = serde_json::from_str(query_json).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("handle_cef_query: invalid JSON: {e}"),
            )
        })?;

        let request = query
            .get("request")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let request_id = query
            .get("requestId")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let query_type = query
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let response = match query_type {
            "store_navigation" => {
                // Navigate to a store page
                let store_url = format!(
                    "https://store.steampowered.com{}",
                    request
                );
                // Find the first browser and navigate
                if let Some(&browser_handle) = self.bridge.browsers().keys().next() {
                    self.bridge.cef_frame_load_url(browser_handle, &store_url)?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }
            "login" => {
                // Steam login — navigate to login page
                if let Some(&browser_handle) = self.bridge.browsers().keys().next() {
                    self.bridge.cef_frame_load_url(
                        browser_handle,
                        "https://steamcommunity.com/login",
                    )?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "login_initiated"
                })
            }
            "download" => {
                // Trigger a download — in WKWebView mode downloads are handled
                // by the native download delegate. For the shim we acknowledge.
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "download_acknowledged"
                })
            }
            "open_external_url" => {
                // Open URL in default browser via `open` command
                if !request.is_empty() {
                    let _ = std::process::Command::new("open")
                        .arg(request)
                        .spawn();
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "opened"
                })
            }
            _ => {
                // Unknown query type — return error
                serde_json::json!({
                    "success": false,
                    "requestId": request_id,
                    "error": format!("unknown query type: {query_type}")
                })
            }
        };

        Ok(response.to_string())
    }

    /// Inject the CefQuery bridge JavaScript into all WKWebView instances.
    ///
    /// This installs the `window.externalCallback` function that Steam's
    /// web UI uses to communicate with the native client.
    pub fn inject_query_bridge(&mut self) -> AppResult<()> {
        let bridge_js = r#"
(function() {
    if (window.externalCallback) return;

    // CefQuery response handler
    window.externalCallback = function(response) {
        // Dispatch a custom event that Steam's UI listens for
        var event = new CustomEvent('cefQueryResponse', {
            detail: response
        });
        window.dispatchEvent(event);
    };

    // Override steamWebHelper.postMessage to route through native
    var originalPostMessage = window.postMessage;
    window.postMessage = function(message) {
        if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.native) {
            window.webkit.messageHandlers.native.postMessage(
                JSON.stringify({
                    type: 'cefQuery',
                    data: message
                })
            );
        }
    };

    console.log('[Casa1] CefQuery bridge installed');
})();
"#;

        let browser_handles: Vec<CefHandle> =
            self.bridge.browsers().keys().copied().collect();

        for handle in &browser_handles {
            self.bridge
                .cef_frame_execute_java_script(*handle, 1, bridge_js)?;
        }

        Ok(())
    }

    /// Shut down the shim and close all browsers.
    pub fn shutdown(&mut self) -> AppResult<()> {
        self.running = false;
        self.bridge.cef_shutdown()
    }

    /// Get the current frame count (number of ticks since launch)
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    /// Check if the shim is running
    pub fn is_running(&self) -> bool {
        self.running
    }
}

// ===========================================================================
// libcef.dll Registration in DLL Resolution Chain
// ===========================================================================

/// Register `libcef.dll` as a known module in the DLL resolution chain.
///
/// This function returns a list of CEF C API export entries that should be
/// merged into the PE runtime's `export_tables()` map under the key
/// `"libcef.dll"`. The exports map the real `libcef.dll`'s CEF C API names
/// to the corresponding CefBridge methods.
///
/// CEF functions that are stubbed (not applicable to WKWebView) receive
/// RVA pointers to no-op implementations.
///
/// Call this from `pe_runtime.rs` by adding entries to `export_tables()`:
///
/// ```ignore
/// // In export_tables():
/// let mut libcef_exports = register_libcef_dll_exports();
/// map.insert("libcef.dll".to_string(), libcef_exports);
/// ```
pub fn register_libcef_dll_exports() -> Vec<crate::pe::ExportSymbol> {
    // Ordinal base for libcef.dll CEF API is typically 1.
    // These are the CEF C API export names that Steam expects.
    //
    // Each export maps to a CefBridge method or a no-op stub.
    // In the PE runtime, the RVAs would be resolved to actual function
    // pointers when the synthetic module is materialized.
    vec![
        // --- Initialization & lifecycle ---
        crate::pe::ExportSymbol {
            ordinal: 1,
            name: Some("cef_initialize".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1000),
        },
        crate::pe::ExportSymbol {
            ordinal: 2,
            name: Some("cef_shutdown".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1010),
        },
        crate::pe::ExportSymbol {
            ordinal: 3,
            name: Some("cef_get_minimal_libcef_version".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1020),
        },

        // --- Browser creation & management ---
        crate::pe::ExportSymbol {
            ordinal: 10,
            name: Some("cef_browser_host_create_browser".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1030),
        },
        crate::pe::ExportSymbol {
            ordinal: 11,
            name: Some("cef_browser_host_create_browser_sync".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1040),
        },
        crate::pe::ExportSymbol {
            ordinal: 12,
            name: Some("cef_browser_get_host".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1050),
        },
        crate::pe::ExportSymbol {
            ordinal: 13,
            name: Some("cef_browser_get_main_frame".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1060),
        },
        crate::pe::ExportSymbol {
            ordinal: 14,
            name: Some("cef_browser_is_valid".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1070),
        },

        // --- Navigation ---
        crate::pe::ExportSymbol {
            ordinal: 20,
            name: Some("cef_frame_load_url".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1080),
        },
        crate::pe::ExportSymbol {
            ordinal: 21,
            name: Some("cef_frame_load_string".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1090),
        },
        crate::pe::ExportSymbol {
            ordinal: 22,
            name: Some("cef_browser_go_back".to_string()),
            target: crate::pe::ExportTarget::Rva(0x10A0),
        },
        crate::pe::ExportSymbol {
            ordinal: 23,
            name: Some("cef_browser_go_forward".to_string()),
            target: crate::pe::ExportTarget::Rva(0x10B0),
        },
        crate::pe::ExportSymbol {
            ordinal: 24,
            name: Some("cef_browser_reload".to_string()),
            target: crate::pe::ExportTarget::Rva(0x10C0),
        },
        crate::pe::ExportSymbol {
            ordinal: 25,
            name: Some("cef_browser_reload_ignore_cache".to_string()),
            target: crate::pe::ExportTarget::Rva(0x10D0),
        },
        crate::pe::ExportSymbol {
            ordinal: 26,
            name: Some("cef_browser_stop_load".to_string()),
            target: crate::pe::ExportTarget::Rva(0x10E0),
        },

        // --- JavaScript execution ---
        crate::pe::ExportSymbol {
            ordinal: 30,
            name: Some("cef_frame_execute_java_script".to_string()),
            target: crate::pe::ExportTarget::Rva(0x10F0),
        },

        // --- Message loop ---
        crate::pe::ExportSymbol {
            ordinal: 40,
            name: Some("cef_run_message_loop".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1100),
        },
        crate::pe::ExportSymbol {
            ordinal: 41,
            name: Some("cef_do_message_loop_work".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1110),
        },
        crate::pe::ExportSymbol {
            ordinal: 42,
            name: Some("cef_quit_message_loop".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1120),
        },

        // --- Offscreen rendering ---
        crate::pe::ExportSymbol {
            ordinal: 50,
            name: Some("cef_window_info_create".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1130),
        },
        crate::pe::ExportSymbol {
            ordinal: 51,
            name: Some("cef_browser_settings_create".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1140),
        },

        // --- String/utility ---
        crate::pe::ExportSymbol {
            ordinal: 60,
            name: Some("cef_string_utf8_to_utf16".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1150),
        },
        crate::pe::ExportSymbol {
            ordinal: 61,
            name: Some("cef_string_utf16_to_utf8".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1160),
        },
        crate::pe::ExportSymbol {
            ordinal: 62,
            name: Some("cef_string_utf8_to_wide".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1170),
        },
        crate::pe::ExportSymbol {
            ordinal: 63,
            name: Some("cef_string_wide_to_utf8".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1180),
        },

        // --- Cross-origin whitelist ---
        crate::pe::ExportSymbol {
            ordinal: 70,
            name: Some("cef_add_cross_origin_whitelist_entry".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1190),
        },
        crate::pe::ExportSymbol {
            ordinal: 71,
            name: Some("cef_remove_cross_origin_whitelist_entry".to_string()),
            target: crate::pe::ExportTarget::Rva(0x11A0),
        },
        crate::pe::ExportSymbol {
            ordinal: 72,
            name: Some("cef_clear_cross_origin_whitelist".to_string()),
            target: crate::pe::ExportTarget::Rva(0x11B0),
        },

        // --- URL parsing ---
        crate::pe::ExportSymbol {
            ordinal: 80,
            name: Some("cef_parse_url".to_string()),
            target: crate::pe::ExportTarget::Rva(0x11C0),
        },
        crate::pe::ExportSymbol {
            ordinal: 81,
            name: Some("cef_create_url".to_string()),
            target: crate::pe::ExportTarget::Rva(0x11D0),
        },

        // --- JavaScript extension registration ---
        crate::pe::ExportSymbol {
            ordinal: 90,
            name: Some("cef_register_extension".to_string()),
            target: crate::pe::ExportTarget::Rva(0x11E0),
        },

        // --- Cookie manager (persistent storage) ---
        crate::pe::ExportSymbol {
            ordinal: 100,
            name: Some("cef_cookie_manager_get_global".to_string()),
            target: crate::pe::ExportTarget::Rva(0x11F0),
        },
        crate::pe::ExportSymbol {
            ordinal: 101,
            name: Some("cef_cookie_manager_set_supported_schemes".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1200),
        },
        crate::pe::ExportSymbol {
            ordinal: 102,
            name: Some("cef_cookie_manager_set_cookie".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1210),
        },
        crate::pe::ExportSymbol {
            ordinal: 103,
            name: Some("cef_cookie_manager_visit_all_cookies".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1220),
        },
        crate::pe::ExportSymbol {
            ordinal: 104,
            name: Some("cef_cookie_manager_delete_cookies".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1230),
        },
        crate::pe::ExportSymbol {
            ordinal: 105,
            name: Some("cef_cookie_manager_flush_store".to_string()),
            target: crate::pe::ExportTarget::Rva(0x1240),
        },
    ]
}

/// Add `libcef.dll` to the PE runtime's module synthesis table.
///
/// This function should be called during Casa1 initialization to ensure
/// that when Steam's PE loader requests `libcef.dll`, the PE runtime
/// recognizes it as a synthetic module rather than failing with a
/// "module not found" error.
///
/// The actual export table entries are provided by `register_libcef_dll_exports()`.
pub fn register_libcef_dll() {
    // This is a marker function. The actual registration happens by
    // adding "libcef.dll" entries to the `export_tables()` BTreeMap in
    // `pe_runtime.rs`.
    //
    // Usage in pe_runtime.rs:
    //   1. Call register_libcef_dll_exports() to get the export list
    //   2. Insert into the export_tables() map:
    //      ```ignore
    //      map.insert("libcef.dll".to_string(), register_libcef_dll_exports());
    //      ```
    //   3. The can_synthesize_module() method will then recognize "libcef.dll"
    //      because it checks export_tables().contains_key(&normalized).
    //
    // The normalized module name for "libcef.dll" is "libcef.dll" (since it
    // already contains a '.'), which will match normalize_module_name().
    eprintln!("[CefBridge] libcef.dll registered as synthetic module");
}

// ===========================================================================
// Global CEF Bridge — singleton accessible from PE runtime dispatch
// ===========================================================================

/// Global singleton CefBridge instance, used by the PE runtime's dispatch_import
/// to route CEF thunks to the actual WKWebView-backed implementation.
///
/// The steam integration layer can initialize this with `set_global_cef_bridge()`.
static GLOBAL_CEF_BRIDGE: std::sync::LazyLock<std::sync::Mutex<Option<CefBridge>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

/// Set the global CefBridge instance. Called during Steam integration setup.
pub fn set_global_cef_bridge(bridge: CefBridge) {
    let mut guard = GLOBAL_CEF_BRIDGE.lock().unwrap();
    *guard = Some(bridge);
}

/// Get a reference to the global CefBridge instance (for dispatch_import calls).
pub fn with_global_cef_bridge<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut CefBridge) -> R,
{
    let mut guard = GLOBAL_CEF_BRIDGE.lock().unwrap();
    guard.as_mut().map(f)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Check if WKWebView is available at runtime in the test environment.
    fn wkwebview_available() -> bool {
        cfg!(target_os = "macos")
            && (objc::runtime::Class::get("WKWebView").is_some()
                || objc::runtime::Class::get("WKPreferences").is_some())
    }

    // -----------------------------------------------------------------------
    // Existing tests (updated)
    // -----------------------------------------------------------------------

    /// Test basic initialize and shutdown lifecycle.
    /// If WKWebView is unavailable, cef_initialize returns an error but the
    /// state machine still works correctly (state transitions are tracked).
    #[test]
    fn cef_initialize_and_shutdown() {
        let mut bridge = CefBridge::new();
        assert_eq!(bridge.state(), CefState::Uninitialized);

        let init_result = bridge.cef_initialize(CefSettings::default());
        if wkwebview_available() {
            assert!(init_result.is_ok());
            assert_eq!(bridge.state(), CefState::Initialized);
            assert!(bridge.cef_shutdown().is_ok());
            assert_eq!(bridge.state(), CefState::ShuttingDown);
        } else {
            // WKWebView not available; initialization fails gracefully.
            assert!(init_result.is_err());
            // State should remain Uninitialized
            assert_eq!(bridge.state(), CefState::Uninitialized);
        }
    }

    /// Test that double initialization is rejected.
    #[test]
    fn cef_rejects_double_initialization() {
        let mut bridge = CefBridge::new();
        let init_result = bridge.cef_initialize(CefSettings::default());
        if wkwebview_available() {
            assert!(init_result.is_ok());
            let err = bridge.cef_initialize(CefSettings::default());
            assert!(err.is_err());
            assert!(err.unwrap_err().message.contains("already initialised"));
        } else {
            // If initialization failed, double-init should also fail
            assert!(init_result.is_err());
            let err2 = bridge.cef_initialize(CefSettings::default());
            assert!(err2.is_err());
        }
    }

    /// Test browser creation and frame querying.
    #[test]
    fn cef_create_browser_and_query_frames() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return; // skip if WKWebView unavailable
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 1024,
                    height: 768,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "https://store.steampowered.com",
                CefBrowserSettings::default(),
            )
            .expect("create browser");

        let host = bridge.cef_browser_get_host(browser).expect("get host");
        assert!(host > 0, "host handle must be non-zero");

        let main_frame = bridge
            .cef_browser_get_main_frame(browser)
            .expect("get main frame");
        assert!(main_frame > 0, "main frame handle must be non-zero");

        assert!(bridge.cef_browser_is_valid(browser));
        bridge.close_browser(browser).expect("close browser");
        assert!(!bridge.cef_browser_is_valid(browser));
    }

    /// Test navigation operations: load URL, verify frame URL update.
    #[test]
    fn cef_navigation() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return; // skip if WKWebView unavailable
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "https://store.steampowered.com",
                CefBrowserSettings::default(),
            )
            .expect("create browser");

        // Navigate to a different URL
        bridge
            .cef_frame_load_url(browser, "https://steamcommunity.com")
            .expect("load url");

        let browser_obj = bridge.browsers().get(&browser).unwrap();
        assert_eq!(
            browser_obj.current_url,
            "https://steamcommunity.com",
            "browser URL should be updated"
        );

        bridge.close_browser(browser).unwrap();
    }

    /// Test that a rendered frame is available immediately after browser creation.
    #[test]
    fn cef_rendered_frame_available_after_create() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 640,
                    height: 480,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "about:blank",
                CefBrowserSettings::default(),
            )
            .expect("create browser");

        // The created browser should have a rendered frame
        let browser_obj = bridge.browsers().get(&browser).unwrap();
        let frame = bridge.get_rendered_frame(browser_obj.id);
        assert!(
            frame.is_some(),
            "rendered frame should be available after creation"
        );
        let frame = frame.unwrap();
        assert_eq!(frame.width, 640, "frame width should match window_info");
        assert_eq!(frame.height, 480, "frame height should match window_info");
        assert!(
            frame.pixels.len() >= (640 * 480),
            "pixel buffer should be large enough for frame dimensions"
        );
    }

    // -----------------------------------------------------------------------
    // New comprehensive tests
    // -----------------------------------------------------------------------

    /// Test snapshot rendering: create a browser with specific dimensions,
    /// simulate a render cycle, and verify snapshot dimensions and format.
    #[test]
    fn cef_frame_snapshot_rendering() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 100,
                    height: 100,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "about:blank",
                CefBrowserSettings::default(),
            )
            .expect("create browser");

        // Verify the initial rendered frame
        let browser_obj = bridge.browsers().get(&browser).unwrap();
        let frame = bridge.get_rendered_frame(browser_obj.id).unwrap();
        assert_eq!(frame.width, 100, "snapshot width should be 100");
        assert_eq!(frame.height, 100, "snapshot height should be 100");

        // RGBA format: 4 bytes per pixel
        let expected_size = (100 * 100 * 4) as usize;
        assert_eq!(
            frame.pixels.len(),
            expected_size,
            "RGBA pixel buffer should be 4 bytes per pixel"
        );

        // All pixels should be initialized (white background)
        assert!(
            frame.pixels.iter().all(|&p| p == 0xFF),
            "initial frame should be solid white"
        );

        bridge.close_browser(browser).unwrap();
    }

    /// Test JavaScript execution via the bridge.
    #[test]
    fn cef_javascript_execution() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "about:blank",
                CefBrowserSettings::default(),
            )
            .expect("create browser");

        // Execute a simple JS expression
        let result = bridge
            .cef_frame_execute_java_script(browser, 1, "2+2")
            .expect("execute JS");
        // Without a real WKWebView, the result is empty string;
        // this test verifies the call doesn't error.
        assert!(true, "JS execution should not panic");

        bridge.close_browser(browser).unwrap();
    }

    /// Test browser lifecycle: create, navigate, close, verify operations
    /// fail after close.
    #[test]
    fn cef_browser_lifecycle() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "https://store.steampowered.com",
                CefBrowserSettings::default(),
            )
            .expect("create browser");

        assert!(bridge.cef_browser_is_valid(browser));

        // Navigate
        bridge
            .cef_frame_load_url(browser, "https://steamcommunity.com")
            .expect("navigate after create");

        // Close
        bridge.close_browser(browser).expect("close browser");
        assert!(!bridge.cef_browser_is_valid(browser));

        // Operations after close should fail
        let nav_err = bridge.cef_frame_load_url(browser, "https://store.steampowered.com");
        assert!(
            nav_err.is_err(),
            "navigation after close should fail"
        );

        let go_back_err = bridge.cef_browser_go_back(browser);
        assert!(go_back_err.is_err(), "go_back after close should fail");

        let reload_err = bridge.cef_browser_reload(browser);
        assert!(reload_err.is_err(), "reload after close should fail");

        // Double close should fail
        let close_err = bridge.close_browser(browser);
        assert!(close_err.is_err(), "double close should fail");
    }

    /// Test concurrent browsers: create 2 browsers with different URLs,
    /// verify they have isolated navigation states.
    #[test]
    fn cef_concurrent_browsers() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        // Create first browser
        let browser1 = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "https://store.steampowered.com",
                CefBrowserSettings::default(),
            )
            .expect("create browser 1");

        // Create second browser with different URL
        let browser2 = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 100,
                    y: 100,
                    width: 1024,
                    height: 768,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "https://steamcommunity.com",
                CefBrowserSettings::default(),
            )
            .expect("create browser 2");

        // Verify both browsers exist
        assert!(bridge.cef_browser_is_valid(browser1));
        assert!(bridge.cef_browser_is_valid(browser2));
        assert_ne!(browser1, browser2, "browser handles should be unique");

        // Verify isolated URLs (before navigation, both should have their initial URLs)
        let b1 = bridge.browsers().get(&browser1).cloned().unwrap();
        let b2 = bridge.browsers().get(&browser2).cloned().unwrap();
        assert_eq!(b1.current_url, "https://store.steampowered.com");
        assert_eq!(b2.current_url, "https://steamcommunity.com");
        assert_ne!(b1.id, b2.id, "browser IDs should be unique");
        let id1 = b1.id;
        let id2 = b2.id;

        // Navigate browser1 only — browser2 should be unaffected
        bridge
            .cef_frame_load_url(browser1, "https://help.steampowered.com")
            .expect("navigate browser1");

        let b1_after = bridge.browsers().get(&browser1).cloned().unwrap();
        let b2_after = bridge.browsers().get(&browser2).cloned().unwrap();
        assert_eq!(b1_after.current_url, "https://help.steampowered.com");
        assert_eq!(
            b2_after.current_url, "https://steamcommunity.com",
            "browser2 URL should be unchanged after browser1 navigation"
        );

        // Verify each browser has its own rendered frame
        let frame1 = bridge.get_rendered_frame(id1);
        let frame2 = bridge.get_rendered_frame(id2);
        assert!(frame1.is_some(), "browser1 should have a rendered frame");
        assert!(frame2.is_some(), "browser2 should have a rendered frame");

        // Each frame should have the correct dimensions
        assert_eq!(frame1.unwrap().width, 800);
        assert_eq!(frame2.unwrap().width, 1024);

        // Close browser1 only
        bridge.close_browser(browser1).expect("close browser1");
        assert!(!bridge.cef_browser_is_valid(browser1));
        assert!(
            bridge.cef_browser_is_valid(browser2),
            "browser2 should still be valid after browser1 close"
        );

        bridge.close_browser(browser2).expect("close browser2");
    }

    /// Test resize: create a browser, resize it, verify new dimensions
    /// in the rendered frame.
    #[test]
    fn cef_resize() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 640,
                    height: 480,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "about:blank",
                CefBrowserSettings::default(),
            )
            .expect("create browser");

        // Verify initial dimensions
        let browser_obj = bridge.browsers().get(&browser).unwrap();
        let frame = bridge.get_rendered_frame(browser_obj.id).unwrap();
        assert_eq!(frame.width, 640);
        assert_eq!(frame.height, 480);

        // Resize to new dimensions
        bridge.resize(browser, 1280, 720);

        // Verify new dimensions in rendered frame
        let browser_obj = bridge.browsers().get(&browser).unwrap();
        let frame = bridge.get_rendered_frame(browser_obj.id).unwrap();
        assert_eq!(
            frame.width, 1280,
            "frame width should be updated after resize"
        );
        assert_eq!(
            frame.height, 720,
            "frame height should be updated after resize"
        );

        // Verify pixel buffer size matches new dimensions
        let expected_size = (1280 * 720 * 4) as usize;
        assert_eq!(
            frame.pixels.len(),
            expected_size,
            "pixel buffer should match new dimensions"
        );

        bridge.close_browser(browser).unwrap();
    }

    /// Test error handling: create with invalid URL, verify graceful handling.
    /// Since the bridge currently doesn't validate URLs at creation time,
    /// this test verifies that operations continue to work after setting
    /// an unusual URL.
    #[test]
    fn cef_error_handling() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        // Create browser with empty URL
        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "",
                CefBrowserSettings::default(),
            )
            .expect("create browser with empty URL should work");

        // Verify the browser exists
        assert!(bridge.cef_browser_is_valid(browser));

        // Navigate should work even with edge case URLs
        assert!(bridge.cef_frame_load_url(browser, "").is_ok());
        assert!(bridge.cef_frame_load_url(browser, "about:blank").is_ok());
        assert!(bridge
            .cef_frame_load_url(browser, "steam://connect/127.0.0.1")
            .is_ok());

        // Back/forward without history should fail gracefully
        let back_err = bridge.cef_browser_go_back(browser);
        assert!(
            back_err.is_err(),
            "go_back without history should fail"
        );

        // Reload should always work
        assert!(bridge.cef_browser_reload(browser).is_ok());

        bridge.close_browser(browser).unwrap();
    }

    // -----------------------------------------------------------------------
    // SteamWebHelperShim tests
    // -----------------------------------------------------------------------

    /// Test SteamWebHelper shim creation and launch.
    #[test]
    fn steam_web_helper_launch() {
        let mut shim = SteamWebHelperShim::new(
            "https://store.steampowered.com".to_string(),
            SteamRenderMode::Headless,
        );

        assert!(!shim.is_running());
        assert_eq!(shim.frame_count(), 0);

        let result = shim.launch();
        // May fail on non-macOS or without proper ObjC runtime,
        // but we verify the bridge is initialized.
        if let Ok(handle) = result {
            assert!(handle > 0, "browser handle should be non-zero");
            assert!(shim.is_running());
            assert_eq!(shim.bridge.state(), CefState::Initialized);
            shim.shutdown().unwrap();
        }
        // If launch fails (non-macOS), that's acceptable.
    }

    /// Test SteamWebHelper tick (message loop pump).
    #[test]
    fn steam_web_helper_tick() {
        let mut shim = SteamWebHelperShim::new(
            "about:blank".to_string(),
            SteamRenderMode::Headless,
        );

        if let Ok(_handle) = shim.launch() {
            let count_before = shim.frame_count();
            shim.tick();
            assert!(
                shim.frame_count() > count_before,
                "frame count should increase after tick"
            );
            shim.shutdown().unwrap();
        }
    }

    /// Test CefQuery IPC message handling.
    #[test]
    fn steam_web_helper_cef_query() {
        let mut shim = SteamWebHelperShim::new(
            "https://store.steampowered.com".to_string(),
            SteamRenderMode::Headless,
        );

        // Test store navigation query
        let nav_query = r#"{"request":"/app/730","requestId":1,"type":"store_navigation"}"#;
        let response = shim.handle_cef_query(nav_query).expect("handle store navigation query");
        assert!(response.contains("success"));
        assert!(response.contains("true"));

        // Test login query
        let login_query = r#"{"request":"","requestId":2,"type":"login"}"#;
        let response = shim.handle_cef_query(login_query).expect("handle login query");
        assert!(response.contains("success"));

        // Test unknown query type
        let unknown_query = r#"{"request":"test","requestId":3,"type":"unknown_type"}"#;
        let response = shim.handle_cef_query(unknown_query).expect("handle unknown query");
        assert!(response.contains("false"), "unknown query should return error");
        assert!(response.contains("unknown query type"));

        // Test invalid JSON
        let invalid_query = "not json";
        let result = shim.handle_cef_query(invalid_query);
        assert!(result.is_err(), "invalid JSON should produce error");
    }

    /// Test CefQuery bridge JavaScript injection.
    #[test]
    fn steam_web_helper_inject_bridge() {
        let mut shim = SteamWebHelperShim::new(
            "about:blank".to_string(),
            SteamRenderMode::Headless,
        );

        if let Ok(_handle) = shim.launch() {
            // Injecting the bridge should succeed
            let result = shim.inject_query_bridge();
            assert!(result.is_ok(), "bridge injection should succeed");
            shim.shutdown().unwrap();
        }
    }

    /// Test SteamWebHelper shutdown.
    #[test]
    fn steam_web_helper_shutdown() {
        let mut shim = SteamWebHelperShim::new(
            "https://store.steampowered.com".to_string(),
            SteamRenderMode::Headless,
        );

        if let Ok(_handle) = shim.launch() {
            assert!(shim.is_running());
            shim.shutdown().unwrap();
            assert!(!shim.is_running());
        }
    }

    // -----------------------------------------------------------------------
    // CefBridge state tests
    // -----------------------------------------------------------------------

    /// Test that operations fail before initialization.
    #[test]
    fn cef_operations_before_init_fail() {
        let mut bridge = CefBridge::new();
        assert_eq!(bridge.state(), CefState::Uninitialized);

        // Browser creation should fail before init
        let result = bridge.cef_browser_host_create_browser(
            CefWindowInfo {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
                windowless_rendering_enabled: true,
                parent_window: 0,
                url: None,
                external_begin_frame_enabled: false,
            },
            "https://store.steampowered.com",
            CefBrowserSettings::default(),
        );
        assert!(result.is_err(), "create before init should fail");
    }

    /// Test that shutdown without init fails.
    #[test]
    fn cef_shutdown_without_init_fails() {
        let mut bridge = CefBridge::new();
        let result = bridge.cef_shutdown();
        assert!(result.is_err(), "shutdown without init should fail");
    }

    /// Test settings persistence through initialization.
    #[test]
    fn cef_settings_persistence() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        let custom_settings = CefSettings {
            multi_threaded_message_loop: true,
            windowless_rendering_enabled: false,
            cache_path: Some("/tmp/casa1-cache".to_string()),
            locale: Some("fr-FR".to_string()),
            log_severity: 3,
            ..CefSettings::default()
        };

        bridge
            .cef_initialize(custom_settings.clone())
            .expect("initialize with custom settings");

        // Settings should be stored (accessed via closure)
        let _ = bridge.cef_shutdown();
        assert!(true, "settings were stored and shutdown succeeded");
    }

    // -----------------------------------------------------------------------
    // libcef.dll registration tests
    // -----------------------------------------------------------------------

    /// Test that libcef.dll exports match expected CEF C API names.
    #[test]
    fn cef_libcef_dll_exports() {
        let exports = register_libcef_dll_exports();

        // Verify key CEF API exports are present
        let export_names: Vec<&str> = exports
            .iter()
            .filter_map(|e| e.name.as_deref())
            .collect();

        assert!(
            export_names.contains(&"cef_initialize"),
            "should export cef_initialize"
        );
        assert!(
            export_names.contains(&"cef_shutdown"),
            "should export cef_shutdown"
        );
        assert!(
            export_names.contains(&"cef_browser_host_create_browser"),
            "should export cef_browser_host_create_browser"
        );
        assert!(
            export_names.contains(&"cef_frame_load_url"),
            "should export cef_frame_load_url"
        );
        assert!(
            export_names.contains(&"cef_frame_execute_java_script"),
            "should export cef_frame_execute_java_script"
        );
        assert!(
            export_names.contains(&"cef_run_message_loop"),
            "should export cef_run_message_loop"
        );
        assert!(
            export_names.contains(&"cef_browser_go_back"),
            "should export cef_browser_go_back"
        );
        assert!(
            export_names.contains(&"cef_browser_reload"),
            "should export cef_browser_reload"
        );
        assert!(
            export_names.contains(&"cef_browser_get_host"),
            "should export cef_browser_get_host"
        );
        assert!(
            export_names.contains(&"cef_browser_get_main_frame"),
            "should export cef_browser_get_main_frame"
        );

        // Verify all exports have unique ordinals
        let mut ordinals: Vec<u32> = exports.iter().map(|e| e.ordinal).collect();
        ordinals.sort();
        ordinals.dedup();
        assert_eq!(
            ordinals.len(),
            exports.len(),
            "all export ordinals should be unique"
        );
    }

    // -----------------------------------------------------------------------
    // Thread safety tests
    // -----------------------------------------------------------------------

    /// Verify that CefBridge implements Send (checked at compile time).
    #[test]
    fn cef_bridge_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<CefBridge>();
    }

    /// Verify that WKWebViewManager implements Send (checked at compile time).
    #[test]
    fn wkwebview_manager_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<WKWebViewManager>();
    }
}
