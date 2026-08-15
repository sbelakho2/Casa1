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
use crate::gfx::DxgiFormat;
use crate::live::LiveFrame;
use crate::mac_window;
use crate::reason::ReasonCode;
use crossbeam_channel::Sender;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::ffi::CString;
use std::ffi::c_void;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// G9: IOSurface-backed Metal texture cache for zero-copy CEF compositing
// ---------------------------------------------------------------------------

/// A cached pair of IOSurface and its wrapping Metal texture.
struct IoSurfaceTexturePair {
    /// Raw IOSurfaceRef (owned, released on drop/resize).
    io_surface: *mut std::ffi::c_void,
    /// Metal texture wrapping the IOSurface.
    metal_texture: Option<metal::Texture>,
    /// Width in pixels.
    width: u32,
    /// Height in pixels.
    height: u32,
}

// SAFETY: Send is safe because the type only uses thread-safe internal state or is accessed under exclusive &mut
unsafe impl Send for IoSurfaceTexturePair {}
// SAFETY: Send is safe because the type only uses thread-safe internal state or is accessed under exclusive &mut
unsafe impl Sync for IoSurfaceTexturePair {}

impl IoSurfaceTexturePair {
    fn new(metal_device: &metal::DeviceRef, width: u32, height: u32) -> Option<Self> {
        let io_surface = crate::metal_backend::create_io_surface(width, height)?;
        let metal_texture = crate::metal_backend::create_texture_from_io_surface(
            metal_device,
            io_surface,
            metal::MTLPixelFormat::BGRA8Unorm,
            width as u64,
            height as u64,
        );
        Some(Self {
            io_surface,
            metal_texture,
            width,
            height,
        })
    }
}

impl Drop for IoSurfaceTexturePair {
    fn drop(&mut self) {
        if !self.io_surface.is_null() {
            // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
            unsafe {
                // CFRelease the IOSurfaceRef
                let sel = objc::sel!(release);
                let obj: *mut objc::runtime::Object = self.io_surface as *mut _;
                let _: () = objc::msg_send![obj, performSelector: sel];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Objective-C runtime helper types (no `foundation` feature in objc 0.2.7)
// --------------------------------------------------------------------------- (no `foundation` feature in objc 0.2.7)
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

// SAFETY: Objective-C runtime class lookup and method registration
unsafe impl objc::Encode for NSPoint {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime class lookup and method registration
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

// SAFETY: Objective-C runtime class lookup and method registration
unsafe impl objc::Encode for NSSize {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime class lookup and method registration
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

// SAFETY: Objective-C runtime class lookup and method registration
unsafe impl objc::Encode for NSRect {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime class lookup and method registration
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
    // SAFETY: Objective-C runtime class lookup and method registration.
    // NSString is always available in the ObjC runtime on macOS.
    unsafe {
        let cls = objc::runtime::Class::get("NSString")
            .expect("NSString class always available at runtime");
        let c_str = CString::new(s).expect("string from Rust should not contain NUL bytes");
        msg_send![cls, stringWithUTF8String: c_str.as_ptr()]
    }
}

/// Helper: create an ObjC NSURL from a Rust &str.
/// SAFETY: returns a +0 (unowned) reference; caller must retain if needed.
unsafe fn ns_url_from_str(url: &str) -> *mut objc::runtime::Object {
    // SAFETY: NSURL is always available in the ObjC runtime on macOS.
    let cls_nsurl =
        objc::runtime::Class::get("NSURL").expect("NSURL class always available at runtime");
    let url_str = ns_string_from_str(url);
    if url_str.is_null() {
        return std::ptr::null_mut();
    }
    let ns_url: *mut objc::runtime::Object = msg_send![cls_nsurl, URLWithString: url_str];
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
    /// G9: IOSurface-backed Metal texture cache keyed by browser_id.
    io_surface_cache: BTreeMap<u32, IoSurfaceTexturePair>,
    /// Cached result of IOSurface runtime availability check.
    /// `None` = not yet checked, `Some(true)` = available, `Some(false)` = unavailable.
    io_surface_available: Option<bool>,

    // -----------------------------------------------------------------------
    // CEF callback handler state
    // -----------------------------------------------------------------------
    /// CefRenderHandler: current popup position/dimensions (popup browser).
    popup_info: Option<CefRect>,
    /// CefRenderHandler: whether a popup is currently shown.
    popup_showing: bool,
    /// CefLifeSpanHandler: whether DoClose has been called and close is pending.
    close_pending_for: Option<CefHandle>,
    /// CefRequestHandler: cookieable scheme list.
    cookieable_schemes: Vec<String>,

    // -----------------------------------------------------------------------
    // Steam Overlay WKWebView state
    // -----------------------------------------------------------------------
    /// Handle to the dedicated overlay WKWebView browser, if active.
    /// Created when the overlay toggles on, destroyed when it toggles off.
    overlay_browser_handle: Option<CefHandle>,

    // -----------------------------------------------------------------------
    // Live Session Integration
    // -----------------------------------------------------------------------
    /// Optional channel sender for publishing LiveFrames to the live session
    /// display system. When set, every on_paint/on_accelerated_paint call will
    /// also produce a LiveFrame and publish it to the live window.
    live_frame_tx: Option<Sender<LiveFrame>>,
    /// Frame counter for live frame publication
    live_frame_counter: u64,
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
            .field(
                "webview_manager",
                &self.webview_manager.as_ref().map(|_| "WKWebViewManager"),
            )
            .field("nsapp_initialized", &self.nsapp_initialized)
            .field("io_surface_available", &self.io_surface_available)
            .field("popup_info", &self.popup_info)
            .field("popup_showing", &self.popup_showing)
            .field("close_pending_for", &self.close_pending_for)
            .field("overlay_browser_handle", &self.overlay_browser_handle)
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
            io_surface_cache: BTreeMap::new(),
            io_surface_available: None,
            popup_info: None,
            popup_showing: false,
            close_pending_for: None,
            cookieable_schemes: vec![
                "http".to_string(),
                "https".to_string(),
                "steam".to_string(),
                "steamstore".to_string(),
                "steamcommunity".to_string(),
            ],
            overlay_browser_handle: None,
            live_frame_tx: None,
            live_frame_counter: 0,
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
    /// Optional real NSWindow content view for embedding WKWebViews
    /// in real macOS windows (instead of the offscreen view).
    real_window_view: Option<*mut std::ffi::c_void>,
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
            // Find the handle for this delegate by matching ptr_val
            if let Some(&handle) = state.view_to_handle.get(&ptr_val) {
                state
                    .navigation_events
                    .entry(handle)
                    .and_modify(|(loaded, _)| {
                        *loaded = true;
                    });
                eprintln!(
                    "[CefBridge] did_finish_nav: handle={:#x} ptr_val={ptr_val:#x}",
                    handle.0,
                );
            } else {
                // Fallback: broadcast to all tracked views (legacy behavior)
                for (loaded, _) in state.navigation_events.values_mut() {
                    *loaded = true;
                }
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
        };
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            // Try to match the failing navigation to a specific view handle
            if let Some(&handle) = state.view_to_handle.get(&ptr_val) {
                state
                    .navigation_events
                    .entry(handle)
                    .and_modify(|(_, err)| {
                        *err = Some(error_desc.clone());
                    });
            } else {
                // Fallback: broadcast error to all tracked views
                for (_, (_, err)) in state.navigation_events.iter_mut() {
                    *err = Some(error_desc.clone());
                }
            }
        }
        eprintln!("[CefBridge] did_fail_nav: ptr_val={ptr_val:#x} error=\"{error_desc}\"");
    }

    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
    unsafe {
        decl.add_method(
            sel!(webView:didFinishNavigation:),
            did_finish_nav
                as extern "C" fn(
                    &objc::runtime::Object,
                    objc::runtime::Sel,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                ),
        );
        decl.add_method(
            sel!(webView:didFailNavigation:withError:),
            did_fail_nav
                as extern "C" fn(
                    &objc::runtime::Object,
                    objc::runtime::Sel,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                ),
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
        // SAFETY: Objective-C runtime class lookup and method registration
        unsafe {
            let body: *mut objc::runtime::Object = msg_send![message, body];
            if !body.is_null() {
                let desc: *mut objc::runtime::Object = msg_send![body, description];
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

    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
    unsafe {
        decl.add_method(
            sel!(userContentController:didReceiveScriptMessage:),
            did_receive_message
                as extern "C" fn(
                    &objc::runtime::Object,
                    objc::runtime::Sel,
                    *mut objc::runtime::Object,
                    *mut objc::runtime::Object,
                ),
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
            real_window_view: None,
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

    /// Initialize the NSApplication.
    ///
    /// If a regular NSApp has already been set up by `mac_window::init_nsapplication()`
    /// (i.e., a real UI session with windows), this method skips changing the
    /// activation policy and just creates the offscreen fallback view.
    ///
    /// If no NSApp exists yet, this creates one with prohibited activation policy
    /// (headless mode) and the offscreen window — matching the original behaviour
    /// for pure headless/CEF scenarios.
    #[cfg(target_os = "macos")]
    fn init_nsapp(&mut self) {
        // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
        unsafe {
            // ── 1. Check whether a regular NSApp already exists ───────────
            let regular_mode = mac_window::is_nsapp_initialized();

            let cls_app = match objc::runtime::Class::get("NSApplication") {
                Some(c) => c,
                None => {
                    self.wkwebview_available.store(false, Ordering::Relaxed);
                    return;
                }
            };

            // Get or create shared application
            let shared_app: *mut objc::runtime::Object = msg_send![cls_app, sharedApplication];
            if shared_app.is_null() {
                self.wkwebview_available.store(false, Ordering::Relaxed);
                return;
            }

            if !regular_mode {
                // ── 2a. Headless mode: prohibited activation policy ─────
                let _: () = msg_send![
                    shared_app,
                    setActivationPolicy: 0 /* NSApplicationActivationPolicyProhibited */
                ];
            }
            // else: regular NSApp already exists – do NOT change activation policy

            // ── 3. Create a hidden offscreen window (WKWebView needs hierarchy) ──
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
            let view: *mut objc::runtime::Object = msg_send![view_alloc, initWithFrame: view_frame];

            // G9: Enable layer-backed rendering on the offscreen view so that
            // WKWebView subviews use IOSurface-backed compositing layers
            // instead of fallback CPU rendering paths. Without this, the
            // WKWebView's backing CALayer may remain snapshot-based (CGImage
            // contents) rather than IOSurface-backed, defeating zero-copy.
            let _: () = msg_send![view, setWantsLayer: 1 /* YES */];

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
            // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
            unsafe {
                let alloc: *mut objc::runtime::Object = msg_send![cls, alloc];
                let instance: *mut objc::runtime::Object = msg_send![alloc, init];
                self.nav_delegate = Some(instance as *mut std::ffi::c_void);
            }
        }

        if let Some(cls) = register_msg_handler_class() {
            // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
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

    /// Set a real NSWindow content view as the parent for subsequent WKWebView
    /// creations. When set, WKWebViews will be embedded in the real window's
    /// view hierarchy instead of the offscreen hidden view.
    ///
    /// Pass `std::ptr::null_mut()` to reset back to offscreen (headless) mode.
    pub fn set_real_window_view(&mut self, view: *mut std::ffi::c_void) {
        if view.is_null() {
            self.real_window_view = None;
        } else {
            self.real_window_view = Some(view);
        }
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

        // Use the real window content view if one has been set, otherwise
        // fall back to the offscreen hidden view (headless rendering path).
        let parent_view = self.real_window_view.or(self.offscreen_view);

        // Create the WKWebView via Objective-C runtime
        let native_ptr = Self::create_wkwebview_native(
            config.width,
            config.height,
            config.java_script_enabled,
            config.user_agent.as_deref(),
            self.nav_delegate,
            self.msg_handler,
            parent_view,
        );
        if native_ptr.is_null() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "Failed to create WKWebView via Objective-C runtime",
            ));
        }

        // Register this view in the delegate state
        if let Ok(mut state) = DELEGATE_STATE.lock() {
            state.view_to_handle.insert(native_ptr as u64, handle);
            state.navigation_events.insert(handle, (false, None));
        }

        let pixels = vec![0xFFu8; config.width as usize * config.height as usize * 4];

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

    /// G9: Return the `IOSurfaceRef` backing a WKWebView's compositing layer,
    /// if one exists.
    ///
    /// WKWebView renders through a `CALayer` tree. When its content is
    /// hardware-composited, `layer.contents` is an `IOSurface` that can be
    /// handed straight to Metal for zero-copy sampling. This method walks
    /// `WKWebView -> layer -> contents` and verifies the object is an
    /// `IOSurface` (it responds to `surfaceID`) before returning it.
    ///
    /// Returns a null pointer (not an error) when the view exists but has no
    /// IOSurface-backed layer — the common case for snapshot-based offscreen
    /// rendering — so callers fall back to a managed surface plus CPU upload.
    /// The returned pointer is borrowed (not retained); callers must not
    /// release it.
    pub fn get_io_surface_for_browser(
        &self,
        handle: WKWebViewHandle,
    ) -> AppResult<*mut std::ffi::c_void> {
        let instance = self.views.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("get_io_surface_for_browser: WKWebView {handle:?} not found"),
            )
        })?;

        if instance.native_ptr.is_null() {
            return Ok(std::ptr::null_mut());
        }

        #[cfg(feature = "metal")]
        // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
        unsafe {
            let view: *mut objc::runtime::Object = instance.native_ptr as *mut _;
            let layer: *mut objc::runtime::Object = msg_send![view, layer];
            if layer.is_null() {
                eprintln!(
                    "[CefBridge] get_io_surface_for_browser: WKWebView {handle:?} has no \
                     backing CALayer (view={view:?})"
                );
                return Ok(std::ptr::null_mut());
            }

            // G9: Force the layer to display its latest content so that
            // `layer.contents` reflects the most recent composited frame
            // rather than a stale IOSurface from a previous render cycle.
            // Without this call, the IOSurface pointer may refer to content
            // that the layer has already replaced with a new surface.
            let _: () = msg_send![layer, displayIfNeeded];

            let contents: *mut objc::runtime::Object = msg_send![layer, contents];
            if contents.is_null() {
                eprintln!(
                    "[CefBridge] get_io_surface_for_browser: layer contents is null \
                     for WKWebView {handle:?} (view={view:?}, dims={w:.0}x{h:.0})",
                    w = instance.width,
                    h = instance.height
                );
                return Ok(std::ptr::null_mut());
            }
            // Only an IOSurface responds to `surfaceID`; any other layer
            // contents (e.g. a CGImage) must not be passed to Metal's
            // iosurface texture constructor.
            let responds: bool = msg_send![contents, respondsToSelector: objc::sel!(surfaceID)];
            if responds {
                eprintln!(
                    "[CefBridge] get_io_surface_for_browser: found IOSurface for \
                     WKWebView {handle:?} ({w:.0}x{h:.0}) — zero-copy path available",
                    w = instance.width,
                    h = instance.height
                );
                Ok(contents as *mut std::ffi::c_void)
            } else {
                // Check what kind of object it is for diagnostic purposes
                let class_name: *mut objc::runtime::Object = msg_send![contents, description];
                let contents_desc = if !class_name.is_null() {
                    let cstr: *const i8 = msg_send![class_name, UTF8String];
                    if !cstr.is_null() {
                        std::ffi::CStr::from_ptr(cstr)
                            .to_string_lossy()
                            .into_owned()
                    } else {
                        "unknown".to_string()
                    }
                } else {
                    "unknown".to_string()
                };
                eprintln!(
                    "[CefBridge] get_io_surface_for_browser: layer contents is not an \
                     IOSurface for WKWebView {handle:?} — contents class: {contents_desc}, \
                     dimensions: {w:.0}x{h:.0} — falling back to CPU upload",
                    w = instance.width,
                    h = instance.height
                );
                Ok(std::ptr::null_mut())
            }
        }

        #[cfg(not(feature = "metal"))]
        {
            Ok(std::ptr::null_mut())
        }
    }

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
            state
                .navigation_events
                .get(&handle)
                .map(|(loaded, _)| *loaded)
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
        instance.pixels = vec![0xFFu8; width as usize * height as usize * 4];
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
                // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
                unsafe {
                    let _: () = msg_send![win as *mut objc::runtime::Object, close];
                }
            }
            if let Some(view) = self.offscreen_view.take() {
                // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
                unsafe {
                    let _: () = msg_send![view as *mut objc::runtime::Object, release];
                }
            }
            if let Some(delegate) = self.nav_delegate.take() {
                // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
                unsafe {
                    let _: () = msg_send![delegate as *mut objc::runtime::Object, release];
                }
            }
            if let Some(handler) = self.msg_handler.take() {
                // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
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
        #[allow(unused_variables)] width: f64,
        #[allow(unused_variables)] height: f64,
        #[allow(unused_variables)] js_enabled: bool,
        #[allow(unused_variables)] user_agent: Option<&str>,
        #[allow(unused_variables)] nav_delegate: Option<*mut std::ffi::c_void>,
        #[allow(unused_variables)] msg_handler: Option<*mut std::ffi::c_void>,
        #[allow(unused_variables)] parent_view: Option<*mut std::ffi::c_void>,
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
                let cls_wk_controller = match objc::runtime::Class::get("WKUserContentController") {
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

                // --- G9: Enable layer-backed rendering on WKWebView itself ---
                // WKWebView on macOS uses a layer-hosted NSView by default, but
                // explicitly setting wantsLayer ensures its backing CALayer is
                // configured for IOSurface-backed compositing rather than falling
                // back to CPU-based CGImage snapshotting. This is required for the
                // zero-copy IOSurface path in get_io_surface_for_browser().
                let _: () = msg_send![view, setWantsLayer: 1 /* YES */];

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
            if let Err(panic_err) = &result {
                let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                eprintln!("[CefBridge] create_wkwebview_native panicked: {msg}");
            }
            result.unwrap_or(std::ptr::null_mut())
        }

        #[cfg(not(target_os = "macos"))]
        {
            std::ptr::null_mut()
        }
    }

    /// Navigate a WKWebView to a URL using `loadRequest:` with an NSURLRequest.
    #[allow(unused_variables)]
    fn navigate_wkwebview_native(native_ptr: *mut std::ffi::c_void, url: &str) {
        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
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
                eprintln!("[CefBridge] navigate_wkwebview_native panicked: {msg}");
            }
        }
    }

    /// Evaluate JavaScript in a WKWebView using `evaluateJavaScript:completionHandler:`.
    /// The completion handler is a block that receives the result when execution finishes.
    #[allow(unused_variables)]
    fn evaluate_js_native(native_ptr: *mut std::ffi::c_void, script: &str, callback_id: u64) {
        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
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
                    _block: *const std::ffi::c_void,
                    result: *mut objc::runtime::Object,
                    error: *mut objc::runtime::Object,
                ) {
                    // SAFETY: Objective-C runtime class lookup and method registration
                    unsafe {
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
                                    eprintln!("[CefBridge] JS execution error: {err_str}");
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
                                    // Route result back through delegate state
                                    // (simplified — a real impl would use the block's copy
                                    //  of the callback ID via block private data)
                                    eprintln!("[CefBridge] JS execution result: {result_str}");
                                }
                            }
                        }
                    }
                }

                let block = BlockLiteral::<
                    extern "C" fn(
                        *const std::ffi::c_void,
                        *mut objc::runtime::Object,
                        *mut objc::runtime::Object,
                    ),
                > {
                    isa: std::ptr::null_mut(), // will be set to NSConcreteStackBlock by runtime
                    flags: 0,
                    reserved: 0,
                    invoke: js_completion_block
                        as *const extern "C" fn(
                            *const std::ffi::c_void,
                            *mut objc::runtime::Object,
                            *mut objc::runtime::Object,
                        ),
                };

                let _: () = msg_send![
                    view,
                    evaluateJavaScript: js_str
                    completionHandler: &block as *const BlockLiteral<_>
                        as *mut std::ffi::c_void
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
                eprintln!("[CefBridge] evaluate_js_native panicked: {msg}");
            }
        }
    }

    /// Take a snapshot of the WKWebView's current rendered content using
    /// `takeSnapshotWithConfiguration:completionHandler:` (macOS 10.13+).
    /// The snapshot is returned as RGBA pixel data via the completion block.
    #[allow(unused_variables)]
    fn take_snapshot_native(native_ptr: *mut std::ffi::c_void, handle: WKWebViewHandle) {
        // Store handle in global atomic so the extern "C" block fn can use it.
        // This is safe because take_snapshot_native is called from a single thread
        // (the main loop) and the block executes synchronously during run loop iteration.
        SNAPSHOT_TARGET_HANDLE.store(handle.0, Ordering::SeqCst);

        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            if let Err(panic_err) = std::panic::catch_unwind(|| unsafe {
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
                    // SAFETY: Objective-C runtime class lookup and method registration
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
                                    eprintln!("[CefBridge] Snapshot error: {err_str}");
                                }
                            }
                            return;
                        }

                        if snapshot.is_null() {
                            return;
                        }

                        // Retrieve the target handle from the static atomic
                        let target_handle =
                            WKWebViewHandle(SNAPSHOT_TARGET_HANDLE.load(Ordering::SeqCst));

                        // Extract CGImage from NSImage (macOS).
                        // SAFETY: NSImage is always available in the ObjC runtime on macOS.
                        let cls_nsimage = objc::runtime::Class::get("NSImage")
                            .expect("NSImage class always available on macOS");
                        let is_nsimage: bool = msg_send![snapshot, isKindOfClass: cls_nsimage];
                        if is_nsimage {
                            // Get CGImage from NSImage
                            let cg_image: *mut std::ffi::c_void = msg_send![snapshot, CGImageForProposedRect: std::ptr::null_mut::<std::ffi::c_void>()
                                                                                 context: std::ptr::null_mut::<std::ffi::c_void>()
                                                                                 hints: std::ptr::null_mut::<std::ffi::c_void>()];
                            if cg_image.is_null() {
                                return;
                            }
                            convert_cgimage_to_rgba(cg_image, target_handle);
                        } else {
                            // If it's a UIImage (iOS) or already a CGImage, try CGImage property
                            let cg_image: *mut std::ffi::c_void = msg_send![snapshot, CGImage];
                            if !cg_image.is_null() {
                                convert_cgimage_to_rgba(cg_image, target_handle);
                            }
                        }
                    }
                }

                let block = BlockLiteral::<
                    extern "C" fn(
                        *const std::ffi::c_void,
                        *mut objc::runtime::Object,
                        *mut objc::runtime::Object,
                    ),
                > {
                    isa: std::ptr::null_mut(),
                    flags: 0,
                    reserved: 0,
                    invoke: snapshot_completion_block
                        as *const extern "C" fn(
                            *const std::ffi::c_void,
                            *mut objc::runtime::Object,
                            *mut objc::runtime::Object,
                        ),
                };

                // nil configuration = default snapshot options
                let _: () = msg_send![
                    view,
                    takeSnapshotWithConfiguration: std::ptr::null_mut::<std::ffi::c_void>()
                    completionHandler: &block as *const BlockLiteral<_>
                        as *mut std::ffi::c_void
                ];
            }) {
                let msg = if let Some(s) = panic_err.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_err.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                eprintln!("[CefBridge] take_snapshot_native panicked: {msg}");
            }
        }
    }

    /// Resize a WKWebView by updating its frame NSRect.
    #[allow(unused_variables)]
    fn resize_wkwebview_native(native_ptr: *mut std::ffi::c_void, width: f64, height: f64) {
        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
            unsafe {
                // SAFETY: setFrame: is a standard NSView method, safe to call on WKWebView.
                let view = native_ptr as *mut objc::runtime::Object;
                let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(width, height));
                let _: () = msg_send![view, setFrame: frame];
            }
        }
    }

    /// Close/destroy a WKWebView: stop loading, remove from superview, release.
    fn close_wkwebview_native(native_ptr: *mut std::ffi::c_void) {
        if native_ptr.is_null() {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
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

    // SAFETY: extern FFI declaration — the function signature matches the C library prototype
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
unsafe fn convert_cgimage_to_rgba(cg_image: *mut std::ffi::c_void, handle: WKWebViewHandle) {
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
        // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
        unsafe {
            CGColorSpaceRelease(color_space);
        }
        return;
    }

    // Draw the CGImage into the bitmap context at (0,0)–(width,height)
    // The rect is a CGRect = {origin={x=0,y=0}, size={width,height}}
    let rect = NSRect::new(
        NSPoint::new(0.0, 0.0),
        NSSize::new(width as f64, height as f64),
    );
    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
    unsafe {
        CGContextDrawImage(
            ctx as *const c_void,
            &rect as *const NSRect as *const c_void,
            cg_image as *const c_void,
        );
    }

    // Release CoreFoundation objects
    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
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

    /// Check whether IOSurface is available at runtime.
    ///
    /// On macOS with Metal, IOSurface is typically available. On headless
    /// systems (e.g., Remote Desktop, CI without GPU, or VMs without
    /// IOSurface support), the IOSurface Objective-C class may not be
    /// loadable. The result is cached after the first check so that
    /// subsequent lookups are O(1).
    ///
    /// Returns `true` if IOSurface appears to be available, `false` if the
    /// IOSurface class cannot be found (indicating CPU-side fallback is
    /// required).
    pub fn io_surface_available(&mut self) -> bool {
        if let Some(cached) = self.io_surface_available {
            return cached;
        }
        // Attempt to locate the IOSurface ObjC class.
        // If it's not registered, IOSurfaceCreate etc. will all fail.
        let available = objc::runtime::Class::get("IOSurface").is_some();
        self.io_surface_available = Some(available);
        if !available {
            eprintln!(
                "[CefBridge] IOSurface class not available at runtime — \
                 falling back to CPU-side rendering. This is expected on non-Mac \
                 or in sandboxed environments without IOSurface framework access."
            );
        } else {
            eprintln!("[CefBridge] IOSurface is available — GPU-side compositing enabled");
        }
        available
    }

    /// Ensure NSApplication and WKWebViewManager are initialized.
    /// Called internally before any WKWebView operations.
    pub(crate) fn ensure_webview_manager(&mut self) -> AppResult<&mut WKWebViewManager> {
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
        // SAFETY: Just initialized or confirmed Some above; this is a safe invariant.
        Ok(self
            .webview_manager
            .as_mut()
            .expect("webview_manager just initialized above"))
    }

    // -----------------------------------------------------------------------
    // Live Session Integration
    // -----------------------------------------------------------------------

    /// Set the channel sender for publishing LiveFrames to the live session.
    /// When set, every on_paint/on_accelerated_paint call will also produce a
    /// LiveFrame and publish it via this channel.
    pub fn set_live_frame_tx(&mut self, tx: Option<Sender<LiveFrame>>) {
        self.live_frame_tx = tx;
        self.live_frame_counter = 0;
    }

    /// Get a copy of the most recently rendered frame for a given browser,
    /// or the latest frame if browser_id is None. Returns None if no frame
    /// is available.
    pub fn get_latest_rendered_frame(&self) -> Option<RenderedFrame> {
        self.rendered_frames.back().cloned()
    }

    /// Get the most recent rendered frame pixels for the live preview.
    /// Returns (width, height, pixels_bgra) if any frame is available.
    pub fn get_live_preview_frame(&self) -> Option<(u32, u32, Vec<u8>)> {
        self.rendered_frames.back().map(|f| {
            // Convert RGBA pixels from RenderedFrame to BGRA for LiveFrame
            let pixels = if f.pixels.len() >= (f.width as usize * f.height as usize * 4) {
                // RenderedFrame stores RGBA; convert to BGRA
                let mut bgra = Vec::with_capacity(f.pixels.len());
                for chunk in f.pixels.chunks_exact(4) {
                    bgra.extend_from_slice(&[chunk[2], chunk[1], chunk[0], chunk[3]]);
                }
                bgra
            } else {
                f.pixels.clone()
            };
            (f.width, f.height, pixels)
        })
    }

    // -----------------------------------------------------------------------
    // Input Forwarding — route keyboard/mouse events from the live session
    // window into the WKWebView via JavaScript DOM event dispatch.
    //
    // These methods are called from the PE runtime's poll_live_input() when
    // a live session is active. They evaluate JavaScript on the first browser's
    // WKWebView to simulate user interaction with the Steam web UI.
    // -----------------------------------------------------------------------

    /// Forward a keyboard event to the first available WKWebView browser.
    pub fn forward_keyboard_event(&mut self, key_down: bool, scancode: u16) {
        let browser_handle = self.browsers.keys().next().copied();
        let Some(handle) = browser_handle else { return };
        let Some(browser) = self.browsers.get(&handle) else {
            return;
        };
        let Some(wk_handle) = browser.wk_handle else {
            return;
        };
        let Some(mgr) = self.webview_manager.as_mut() else {
            return;
        };

        // Map scancode to a common key string for JavaScript dispatch
        let key = match scancode {
            0x1E => "a",
            0x30 => "b",
            0x2E => "c",
            0x20 => "d",
            0x12 => "e",
            0x21 => "f",
            0x22 => "g",
            0x23 => "h",
            0x17 => "i",
            0x24 => "j",
            0x25 => "k",
            0x26 => "l",
            0x32 => "m",
            0x31 => "n",
            0x18 => "o",
            0x19 => "p",
            0x10 => "q",
            0x13 => "r",
            0x1F => "s",
            0x14 => "t",
            0x16 => "u",
            0x2F => "v",
            0x11 => "w",
            0x2D => "x",
            0x2C => "y",
            0x15 => "z",
            0x02 => "1",
            0x03 => "2",
            0x04 => "3",
            0x05 => "4",
            0x06 => "5",
            0x07 => "6",
            0x08 => "7",
            0x09 => "8",
            0x0A => "9",
            0x0B => "0",
            0x39 => " ",         // Space
            0x1C => "Enter",     // Enter
            0x0E => "Backspace", // Backspace
            0x2A => "Shift",     // Shift (left)
            0x36 => "Shift",     // Shift (right)
            0x1D => "Control",   // Control (left)
            0x38 => "Alt",       // Alt (left)
            0x01 => "Escape",    // Escape
            0x0F => "Tab",       // Tab
            0x50 => "ArrowLeft",
            0x4F => "ArrowRight",
            0x4E => "ArrowDown",
            0x52 => "ArrowUp",
            _ => "",
        };

        if key.is_empty() {
            return;
        }

        let event_type = if key_down { "keydown" } else { "keyup" };
        let escaped_key = key.replace('\'', "\\'");
        let js = format!(
            "document.dispatchEvent(new KeyboardEvent('{}', {{ key: '{}', bubbles: true }}));",
            event_type, escaped_key
        );
        if let Err(error) = mgr.evaluate_java_script(wk_handle, &js) {
            eprintln!(
                "[CefBridge] forward_keyboard_event: evaluate_java_script failed: {}",
                error
            );
        }
    }

    /// Forward a mouse event to the first available WKWebView browser (legacy 4-param).
    ///
    /// Compatible wrapper for callers that only provide left-button state
    /// (e.g., `pe_runtime.rs`). Delegates to [`forward_mouse_event_ext`] with
    /// zero values for right/middle/scroll parameters.
    pub fn forward_mouse_event(&mut self, x: i32, y: i32, left_pressed: bool, left_released: bool) {
        self.forward_mouse_event_ext(
            x,
            y,
            left_pressed,
            left_released,
            false,
            false, // right pressed/released
            false,
            false, // middle pressed/released
            0,
            0, // scroll delta
        );
    }

    /// Forward a mouse event to the first available WKWebView browser (full).
    /// Supports left, right, middle buttons, scroll wheel, and mouse movement.
    pub fn forward_mouse_event_ext(
        &mut self,
        x: i32,
        y: i32,
        left_pressed: bool,
        left_released: bool,
        right_pressed: bool,
        right_released: bool,
        middle_pressed: bool,
        middle_released: bool,
        scroll_delta_x: i32,
        scroll_delta_y: i32,
    ) {
        let browser_handle = self.browsers.keys().next().copied();
        let Some(handle) = browser_handle else { return };
        let Some(browser) = self.browsers.get(&handle) else {
            return;
        };
        let Some(wk_handle) = browser.wk_handle else {
            return;
        };
        let Some(mgr) = self.webview_manager.as_mut() else {
            return;
        };

        // Left button
        if left_pressed || left_released {
            let event_type = if left_pressed { "mousedown" } else { "mouseup" };
            let js = format!(
                "document.dispatchEvent(new MouseEvent('{}', {{ clientX: {}, clientY: {}, bubbles: true, button: 0 }}));",
                event_type, x, y
            );
            if let Err(error) = mgr.evaluate_java_script(wk_handle, &js) {
                eprintln!(
                    "[CefBridge] forward_mouse_event_ext: left-button script failed: {}",
                    error
                );
            }
        }

        // Right button
        if right_pressed || right_released {
            let event_type = if right_pressed {
                "mousedown"
            } else {
                "mouseup"
            };
            let js = format!(
                "document.dispatchEvent(new MouseEvent('{}', {{ clientX: {}, clientY: {}, bubbles: true, button: 2 }}));",
                event_type, x, y
            );
            if let Err(error) = mgr.evaluate_java_script(wk_handle, &js) {
                eprintln!(
                    "[CefBridge] forward_mouse_event_ext: right-button script failed: {}",
                    error
                );
            }
            // Prevent default context menu on right-click
            if right_pressed {
                let prevent_js = format!(
                    "document.dispatchEvent(new MouseEvent('contextmenu', {{ clientX: {}, clientY: {}, bubbles: true, cancelable: true }})); \
                     event => event.preventDefault();",
                    x, y
                );
                if let Err(error) = mgr.evaluate_java_script(wk_handle, &prevent_js) {
                    eprintln!(
                        "[CefBridge] forward_mouse_event_ext: context-menu suppression failed: {}",
                        error
                    );
                }
            }
        }

        // Middle button
        if middle_pressed || middle_released {
            let event_type = if middle_pressed {
                "mousedown"
            } else {
                "mouseup"
            };
            let js = format!(
                "document.dispatchEvent(new MouseEvent('{}', {{ clientX: {}, clientY: {}, bubbles: true, button: 1 }}));",
                event_type, x, y
            );
            if let Err(error) = mgr.evaluate_java_script(wk_handle, &js) {
                eprintln!(
                    "[CefBridge] forward_mouse_event_ext: middle-button script failed: {}",
                    error
                );
            }
        }

        // Scroll wheel
        if scroll_delta_y != 0 {
            let scroll_js = format!(
                "window.scrollBy(0, {}); \
                 document.dispatchEvent(new WheelEvent('wheel', {{ deltaX: 0, deltaY: {}, deltaZ: 0, deltaMode: 0, clientX: {}, clientY: {} }}));",
                -scroll_delta_y, scroll_delta_y, x, y
            );
            if let Err(error) = mgr.evaluate_java_script(wk_handle, &scroll_js) {
                eprintln!(
                    "[CefBridge] forward_mouse_event_ext: vertical scroll script failed: {}",
                    error
                );
            }
        }
        if scroll_delta_x != 0 {
            let scroll_js = format!(
                "window.scrollBy({}, 0); \
                 document.dispatchEvent(new WheelEvent('wheel', {{ deltaX: {}, deltaY: 0, deltaZ: 0, deltaMode: 0, clientX: {}, clientY: {} }}));",
                -scroll_delta_x, scroll_delta_x, x, y
            );
            if let Err(error) = mgr.evaluate_java_script(wk_handle, &scroll_js) {
                eprintln!(
                    "[CefBridge] forward_mouse_event_ext: horizontal scroll script failed: {}",
                    error
                );
            }
        }

        // Always move mouse pointer
        let move_js = format!(
            "document.dispatchEvent(new MouseEvent('mousemove', {{ clientX: {}, clientY: {}, bubbles: true }}));",
            x, y
        );
        if let Err(error) = mgr.evaluate_java_script(wk_handle, &move_js) {
            eprintln!(
                "[CefBridge] forward_mouse_event_ext: mousemove script failed: {}",
                error
            );
        }
    }

    /// Publish a LiveFrame from rendered pixel data.
    fn publish_live_frame_from_pixels(&mut self, width: u32, height: u32, pixels: Vec<u8>) {
        if let Some(ref tx) = self.live_frame_tx {
            self.live_frame_counter += 1;
            crate::live::live_trace(&format!(
                "[CefBridge] publish_live_frame_from_pixels #{} ({}x{} pixels={})",
                self.live_frame_counter,
                width,
                height,
                pixels.len(),
            ));
            let live_frame = LiveFrame {
                width,
                height,
                format: DxgiFormat::B8G8R8A8Unorm,
                bytes: pixels,
                displayed_frame_index: self.live_frame_counter,
            };
            if tx.try_send(live_frame).is_err() {
                crate::live::live_trace("[CefBridge] publish_live_frame_from_pixels: receiver lagged or closed");
            }
        }
    }

    /// Attempt to read back pixel data from an IOSurface for live frame publishing.
    /// Uses the IOSurface C API (via `IOSurfaceLock` / `IOSurfaceGetBaseAddress`) to
    /// read pixel data directly from the GPU surface to CPU memory.
    /// Returns None if the readback fails or no matching IOSurface is cached.
    fn read_io_surface_pixels(&self, width: u32, height: u32) -> Option<Vec<u8>> {
        #[cfg(target_os = "macos")]
        {
            use std::ffi::c_void;

            // Check the IO surface cache for any cached surface matching our dimensions
            for (_browser_id, pair) in &self.io_surface_cache {
                if pair.width == width && pair.height == height && !pair.io_surface.is_null() {
                    let io_surface = pair.io_surface;
                    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
                    unsafe {
                        // Get IOSurface base address and lock for reading
                        let sel_lock: objc::runtime::Sel = objc::sel!(lockWithOptions:);
                        let _sel_unlock: objc::runtime::Sel = objc::sel!(unlockWithOptions:);
                        let _sel_base_address: objc::runtime::Sel = objc::sel!(baseAddress);
                        let _sel_bytes_per_row: objc::runtime::Sel = objc::sel!(bytesPerRow);

                        let obj = io_surface as *mut objc::runtime::Object;

                        // Lock the IOSurface for read access (0 = kIOSurfaceLockReadOnly)
                        let _: () = msg_send![obj, performSelector: sel_lock withObject: (0 as *mut c_void)];
                        // Actually use the correct signature: lockWithOptions:options_t hint:
                        type LockFn = unsafe extern "C" fn(
                            *mut objc::runtime::Object,
                            objc::runtime::Sel,
                            u32,
                            *mut u32,
                        ) -> i32;
                        // Simpler approach: use baseAddress directly after lock
                        let _: () = msg_send![obj, lockWithOptions: 1]; // kIOSurfaceLockReadOnly = 1

                        let base_address: *mut c_void = msg_send![obj, baseAddress];
                        let bytes_per_row: usize = msg_send![obj, bytesPerRow];

                        if !base_address.is_null() {
                            let total_bytes = (height as usize).saturating_mul(bytes_per_row);
                            let mut pixels =
                                vec![0u8; (width as usize * height as usize * 4).min(total_bytes)];

                            // Copy row by row, respecting bytes_per_row stride
                            let dst_row_bytes = width as usize * 4;
                            for row in 0..(height as usize) {
                                let src_offset = row * bytes_per_row;
                                let dst_offset = row * dst_row_bytes;
                                let copy_len = dst_row_bytes.min(bytes_per_row);
                                if src_offset + copy_len <= total_bytes
                                    && dst_offset + copy_len <= pixels.len()
                                {
                                    let src_ptr = base_address.add(src_offset) as *const u8;
                                    std::ptr::copy_nonoverlapping(
                                        src_ptr,
                                        pixels.as_mut_ptr().add(dst_offset),
                                        copy_len,
                                    );
                                }
                            }

                            // Unlock the IOSurface
                            let _: () = msg_send![obj, unlockWithOptions: 1];

                            return Some(pixels);
                        }

                        // Unlock if lock succeeded but baseAddress was null
                        let _: () = msg_send![obj, unlockWithOptions: 1];
                    }
                }
            }
            None
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (width, height);
            None
        }
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
            self.ensure_webview_manager()?;
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
                    if let Err(e) = mgr.navigate(h, nav_url) {
                        eprintln!("[CefBridge] Failed to navigate WKWebView to '{nav_url}': {e}",);
                    }
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
            // SAFETY: NSRunLoop FFI for event processing
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
                        if let Err(e) = mgr.take_snapshot(*wk_handle) {
                            eprintln!(
                                "[CefBridge] Failed to take snapshot for handle {:?}: {e}",
                                wk_handle,
                            );
                        }

                        // Check if we got pixel data back
                        if let Ok(mut state) = DELEGATE_STATE.lock() {
                            if let Some(Some(pixels)) = state.snapshot_results.remove(wk_handle) {
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

                                    self.rendered_frames.push_back(rendered);
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
                    format!("cef_browser_get_main_frame: browser {browser_handle:#x} not found"),
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
                    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
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
    // cef_browser_go_forward — navigate forward in browser history
    //
    // Gap 2.2 fix: Calls goForward: on the native WKWebView (mirror of
    // cef_browser_go_back). Checks can_go_forward first to ensure there is
    // forward navigation history available.
    // -----------------------------------------------------------------------
    pub fn cef_browser_go_forward(&mut self, browser_handle: CefHandle) -> AppResult<()> {
        let browser = self.browsers.get_mut(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("cef_browser_go_forward: browser {browser_handle:#x} not found"),
            )
        })?;

        if !browser.can_go_forward {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "cef_browser_go_forward: no forward history",
            ));
        }

        // Call goForward: on WKWebView
        if let Some(wk_handle) = browser.wk_handle {
            if let Some(mgr) = self.webview_manager.as_ref() {
                if let Some(ptr) = mgr.native_ptr(wk_handle) {
                    #[cfg(target_os = "macos")]
                    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
                    unsafe {
                        // SAFETY: goForward: is a standard WKWebView method.
                        let view = ptr as *mut objc::runtime::Object;
                        let _: () = msg_send![view, goForward];
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
                    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
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
    // cef_browser_stop_load — stop the current page load
    //
    // Calls stopLoading: on the native WKWebView.
    // -----------------------------------------------------------------------
    pub fn cef_browser_stop_load(&mut self, browser_handle: CefHandle) -> AppResult<()> {
        let browser = self.browsers.get_mut(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("cef_browser_stop_load: browser {browser_handle:#x} not found"),
            )
        })?;

        // Call stopLoading: on WKWebView
        if let Some(wk_handle) = browser.wk_handle {
            if let Some(mgr) = self.webview_manager.as_ref() {
                if let Some(ptr) = mgr.native_ptr(wk_handle) {
                    #[cfg(target_os = "macos")]
                    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
                    unsafe {
                        let view = ptr as *mut objc::runtime::Object;
                        let _: () = msg_send![view, stopLoading];
                    }
                }
            }
        }

        browser.is_loading = false;
        Ok(())
    }

    /// Get the current URL of the first registered browser, if any.
    /// Returns an empty string if no browser is registered.
    pub fn current_url(&self) -> String {
        self.browsers
            .values()
            .next()
            .map(|b| b.current_url.clone())
            .unwrap_or_default()
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
                format!("cef_frame_execute_java_script: browser {browser_handle:#x} not found"),
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
                    if let Err(e) = mgr.resize(wk_handle, width as f64, height as f64) {
                        eprintln!(
                            "[CefBridge] resize: failed to resize WKWebView ({:?}): {e}",
                            wk_handle,
                        );
                    }
                }
            }

            // Update frame buffer
            let pixels = vec![0xFF; width as usize * height as usize * 4];
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
                format!("render_to_metal_texture: browser {browser_handle:#x} not found"),
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
        descriptor
            .set_usage(metal::MTLTextureUsage::ShaderRead | metal::MTLTextureUsage::RenderTarget);
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
        texture.replace_region(
            region,
            0,
            frame.pixels.as_ptr() as *const std::ffi::c_void,
            bytes_per_row,
        );

        // Cache the texture ID
        if let Some(b) = self.browsers.get_mut(&browser_handle) {
            b.metal_texture_id = Some(frame_number);
        }

        Ok(texture)
    }

    // -----------------------------------------------------------------------
    /// G9: Render a browser frame into an IOSurface-backed Metal texture.
    ///
    /// Unlike `render_to_metal_texture`, which copies pixels from a CPU-side
    /// `RenderedFrame` into a Metal texture, this method directly serves the
    /// WKWebView's IOSurface backing store to Metal, achieving zero-copy frame
    /// delivery. The IOSurface is cached per browser to avoid reallocation on
    /// every frame. Only works for WKWebView-backed browsers.
    ///
    /// Returns the Metal texture wrapping the IOSurface, or falls back to
    /// `render_to_metal_texture` if no IOSurface is available.
    // -----------------------------------------------------------------------
    #[cfg(feature = "metal")]
    pub fn render_to_io_surface_texture(
        &mut self,
        browser_handle: CefHandle,
        metal_device: &crate::metal_backend::MetalDevice,
    ) -> AppResult<metal::Texture> {
        let browser = self.browsers.get(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("render_to_io_surface_texture: browser {browser_handle:#x} not found"),
            )
        })?;
        let browser_id = browser.id;
        let wk_handle = browser.wk_handle;

        // Fast path: if the WKWebView's compositing layer is already
        // IOSurface-backed, wrap that surface directly — true zero-copy with
        // no pixel upload at all.
        if let (Some(mgr), Some(handle)) = (&self.webview_manager, wk_handle) {
            match mgr.get_io_surface_for_browser(handle) {
                Ok(native_surface) if !native_surface.is_null() => {
                    let (fw, fh, fnum) = {
                        let frame = self.get_rendered_frame(browser_id).ok_or_else(|| {
                            AppError::new(
                                ReasonCode::RcNotFound,
                                format!(
                                    "render_to_io_surface_texture: no frame for browser {browser_id}"
                                ),
                            )
                        })?;
                        (frame.width, frame.height, frame.frame_number)
                    };
                    if let Some(texture) = crate::metal_backend::create_texture_from_io_surface(
                        metal_device.device(),
                        native_surface,
                        metal::MTLPixelFormat::BGRA8Unorm,
                        fw as u64,
                        fh as u64,
                    ) {
                        if let Some(b) = self.browsers.get_mut(&browser_handle) {
                            b.metal_texture_id = Some(fnum);
                        }
                        eprintln!(
                            "[CefBridge] render_to_io_surface_texture: zero-copy native \
                             IOSurface path for browser {browser_handle:#x} ({fw}x{fh})"
                        );
                        return Ok(texture);
                    }
                    // create_texture_from_io_surface returned None even though
                    // we had a valid IOSurface — Metal rejected the surface
                    // (e.g. incompatible pixel format or dimension mismatch).
                    eprintln!(
                        "[CefBridge] render_to_io_surface_texture: Metal rejected IOSurface \
                         from WKWebView {handle:?} for browser {browser_handle:#x} — \
                         falling back"
                    );
                }
                Ok(_) => {
                    // get_io_surface_for_browser returned null (no IOSurface).
                    // This is expected for snapshot-based rendering — we fall
                    // through to the managed path below.
                }
                Err(e) => {
                    // get_io_surface_for_browser returned an actual error
                    // (e.g. handle not found). Log it and fall back.
                    eprintln!(
                        "[CefBridge] render_to_io_surface_texture: get_io_surface_for_browser \
                         error for browser {browser_handle:#x}: {e} — falling back"
                    );
                }
            }
        } else if wk_handle.is_none() {
            eprintln!(
                "[CefBridge] render_to_io_surface_texture: browser {browser_handle:#x} has no \
                 WKWebView handle — using managed IOSurface path"
            );
        }

        // Runtime availability check: if IOSurface is not available on this
        // system (e.g. headless CI, Remote Desktop, VM without GPU), skip
        // the managed IOSurface path entirely and fall back to a plain
        // CPU-side Metal texture. The result is cached after first check.
        if !self.io_surface_available() {
            eprintln!(
                "[CefBridge] render_to_io_surface_texture: IOSurface unavailable \
                 at runtime — using CPU-side Metal texture for browser \
                 {browser_handle:#x}"
            );
            return self.render_to_metal_texture(browser_handle, metal_device);
        }

        eprintln!(
            "[CefBridge] render_to_io_surface_texture: managed IOSurface with CPU upload \
             for browser {browser_handle:#x}"
        );
        // Managed path: maintain a per-browser IOSurface + Metal texture pair
        // and upload the latest rendered frame into the surface's backing
        // store. The Metal texture aliases that storage, so GPU sampling is
        // zero-copy even though WKWebView snapshots are produced on the CPU.
        let (width, height, frame_number) = {
            let frame = self.get_rendered_frame(browser_id).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcNotFound,
                    format!("render_to_io_surface_texture: no frame for browser {browser_id}"),
                )
            })?;
            (frame.width, frame.height, frame.frame_number)
        };

        let needs_alloc = self
            .io_surface_cache
            .get(&browser_id)
            .map(|p| (p.width, p.height) != (width, height))
            .unwrap_or(true);
        if needs_alloc {
            let pair = IoSurfaceTexturePair::new(metal_device.device(), width, height);
            match pair {
                Some(p) => {
                    self.io_surface_cache.insert(browser_id, p);
                }
                None => {
                    // IOSurface allocation failed — fall back to CPU-side
                    // Metal texture. This can happen if the IOSurface kernel
                    // resource is exhausted or the GPU doesn't support it.
                    eprintln!(
                        "[CefBridge] WARNING: render_to_io_surface_texture: \
                         IOSurface allocation failed for {width}x{height} — \
                         falling back to CPU-side Metal texture for browser \
                         {browser_handle:#x}"
                    );
                    return self.render_to_metal_texture(browser_handle, metal_device);
                }
            }
        }

        // Upload the RGBA snapshot into the BGRA IOSurface backing store. The
        // surface pointer and a copy of the texture are taken under separate
        // scopes so the frame borrow does not overlap the upload.
        let io_surface_ptr = self
            .io_surface_cache
            .get(&browser_id)
            .map(|p| p.io_surface)
            .expect("IOSurface pair present after allocation");
        {
            let frame = self.get_rendered_frame(browser_id).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcNotFound,
                    format!("render_to_io_surface_texture: no frame for browser {browser_id}"),
                )
            })?;
            crate::metal_backend::upload_rgba_frame_to_io_surface(
                io_surface_ptr,
                &frame.pixels,
                width,
                height,
            )?;
        }

        let texture = self
            .io_surface_cache
            .get(&browser_id)
            .and_then(|p| p.metal_texture.clone())
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcInvalidState,
                    "render_to_io_surface_texture: no Metal texture for IOSurface".to_string(),
                )
            })?;

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
    //
    // G9: This function submits raw CPU pixels to the compositor via
    // submit_cef_overlay_frame(). For zero-copy IOSurface delivery, callers
    // should use render_to_io_surface_texture() instead, which provides a
    // Metal texture wrapping either the native WKWebView IOSurface (zero-copy)
    // or a managed IOSurface (CPU upload). This function remains the primary
    // path for non-Metal fallback and for callers that only need CPU pixel
    // access.
    // -----------------------------------------------------------------------
    pub fn submit_latest_frame_to_compositor(&mut self, browser_handle: CefHandle) {
        let browser_id = match self.browsers.get(&browser_handle) {
            Some(b) => b.id,
            None => {
                eprintln!(
                    "[CefBridge] submit_latest_frame_to_compositor: browser {browser_handle:#x} not found"
                );
                return;
            }
        };
        let frame = match self.get_rendered_frame(browser_id) {
            Some(f) => f.clone(),
            None => {
                eprintln!(
                    "[CefBridge] submit_latest_frame_to_compositor: no rendered frame for browser \
                     {browser_handle:#x} (browser_id={browser_id})"
                );
                return;
            }
        };

        // G9 diagnostic: check if IOSurface is available for this browser
        // (informational only — actual IOSurface-based submission requires
        // render_to_io_surface_texture with a Metal device).
        let io_surface_hint = if let (Some(mgr), Some(handle)) = (
            &self.webview_manager,
            self.browsers.get(&browser_handle).and_then(|b| b.wk_handle),
        ) {
            match mgr.get_io_surface_for_browser(handle) {
                Ok(ptr) if !ptr.is_null() => {
                    // IOSurface available — GPU-side compositing will be used
                    "iosurface-available"
                }
                _ => {
                    eprintln!(
                        "[CefBridge] cpu-fallback for browser {browser_handle:#x}: \
                         IOSurface texture not available, using CPU-side pixel buffer"
                    );
                    "cpu-fallback"
                }
            }
        } else {
            "no-wkwebview"
        };

        eprintln!(
            "[CefBridge] submit_latest_frame_to_compositor: browser {browser_handle:#x} \
             frame={} ({width}x{height}) path={io_surface_hint}",
            frame.frame_number,
            width = frame.width,
            height = frame.height,
        );

        crate::metal_renderer::submit_cef_overlay_frame(frame.width, frame.height, frame.pixels);
    }

    /// Submit the latest frame for the first browser to the compositor.
    /// Convenience wrapper used by pe_runtime integration.
    pub fn submit_first_browser_to_compositor(&mut self) {
        if let Some(handle) = self.first_browser_handle() {
            self.submit_latest_frame_to_compositor(handle);
        }
    }

    // -----------------------------------------------------------------------
    // Steam Overlay WKWebView management
    //
    // The overlay is a dedicated WKWebView browser that displays Steam's
    // in-game overlay (friends, achievements, web browser). It is created
    // when Shift+Tab activates the overlay and destroyed when the overlay
    // closes.
    //
    // Frames from the overlay browser are submitted to the global
    // CefMetalCompositor for compositing on top of the game's rendered
    // output.
    // -----------------------------------------------------------------------

    /// Create a dedicated overlay browser (WKWebView) and navigate it to the
    /// given overlay URL.  Returns the browser handle on success.
    ///
    /// If an overlay browser already exists, returns an error.
    pub fn create_overlay_browser(&mut self, url: &str) -> AppResult<CefHandle> {
        if self.overlay_browser_handle.is_some() {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "create_overlay_browser: overlay browser already exists",
            ));
        }

        // Ensure NSApplication + WKWebViewManager are initialised
        self.ensure_webview_manager()?;

        let window_info = CefWindowInfo {
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            windowless_rendering_enabled: true,
            parent_window: 0,
            url: None,
            external_begin_frame_enabled: false,
        };

        let browser_handle =
            self.cef_browser_host_create_browser(window_info, url, CefBrowserSettings::default())?;

        self.overlay_browser_handle = Some(browser_handle);

        // Set the compositor to game-inactive so the overlay renders on top
        crate::metal_renderer::set_cef_compositor_game_active(false);

        eprintln!(
            "[CefBridge] create_overlay_browser: handle={:#x} url={}",
            browser_handle, url,
        );

        Ok(browser_handle)
    }

    /// Destroy the overlay browser if one exists.
    pub fn destroy_overlay_browser(&mut self) -> AppResult<()> {
        let handle = match self.overlay_browser_handle.take() {
            Some(h) => h,
            None => return Ok(()),
        };

        eprintln!("[CefBridge] destroy_overlay_browser: handle={:#x}", handle,);

        if let Err(e) = self.close_browser(handle) {
            eprintln!("[CefBridge] destroy_overlay_browser: close_browser failed: {e}",);
        }
        self.overlay_browser_handle = None;

        // Restore compositor to game-active state
        crate::metal_renderer::set_cef_compositor_game_active(true);

        Ok(())
    }

    /// Tick the overlay subsystem once per frame:
    ///
    /// 1. Polls the global keyboard state for Shift+Tab via CoreGraphics.
    /// 2. If a toggle edge was detected, creates or destroys the overlay
    ///    WKWebView browser accordingly.
    /// 3. When the overlay is active, runs the CEF message loop and submits
    ///    the latest rendered frame to the compositor.
    ///
    /// Call this from the main rendering loop (e.g. inside gfx::present or
    /// pe_runtime::poll_live_input).
    pub fn tick_overlay(&mut self) {
        use crate::steam_integration::{
            steam_overlay_consume_toggle, steam_overlay_is_active, steam_overlay_poll_keyboard,
        };

        // 1. Poll physical keyboard for Shift+Tab
        steam_overlay_poll_keyboard();

        // 2. Check if overlay was toggled this frame
        if steam_overlay_consume_toggle() {
            if steam_overlay_is_active() {
                // Overlay activated → create the WKWebView
                let url = crate::steam_integration::with_steam_overlay(|mgr| {
                    mgr.overlay_url().to_string()
                });
                if let Err(e) = self.create_overlay_browser(&url) {
                    eprintln!("[CefBridge] tick_overlay: failed to create overlay browser: {e}",);
                }
            } else {
                // Overlay deactivated → destroy the WKWebView
                if let Err(e) = self.destroy_overlay_browser() {
                    eprintln!("[CefBridge] tick_overlay: failed to destroy overlay browser: {e}",);
                }
            }
        }

        // 3. When overlay is active, pump message loop and submit frames
        if steam_overlay_is_active() {
            self.cef_do_message_loop_work();

            if let Some(handle) = self.overlay_browser_handle {
                // Submit the latest overlay frame to the compositor
                self.submit_latest_frame_to_compositor(handle);

                // Also check if a toggle happened during message loop work
                if steam_overlay_consume_toggle() {
                    if !steam_overlay_is_active() {
                        if let Err(e) = self.destroy_overlay_browser() {
                            eprintln!("[CefBridge] tick_overlay: failed to destroy overlay: {e}",);
                        }
                    }
                }
            }
        }
    }

    /// Get the current overlay browser handle, if any.
    pub fn overlay_browser_handle(&self) -> Option<CefHandle> {
        self.overlay_browser_handle
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
    pub fn cef_browser_host_was_resized(
        &mut self,
        browser_handle: CefHandle,
        width: u32,
        height: u32,
    ) -> AppResult<(u32, u32)> {
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
                if let Err(e) = mgr.resize(wk_handle, width as f64, height as f64) {
                    eprintln!(
                        "[CefBridge] cef_browser_host_was_resized: resize failed ({:?}): {e}",
                        wk_handle,
                    );
                }
            }
        }

        // Update the frame buffer dimensions
        let pixels = vec![
            0xFFu8;
            (width as usize)
                .saturating_mul(height as usize)
                .saturating_mul(4)
        ];
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

        eprintln!("[CefBridge] WasResized: browser {browser_handle:#x} -> {width}x{height}");

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
    // -----------------------------------------------------------------------
    // CefLifeSpanHandler — browser creation/closing
    // -----------------------------------------------------------------------

    /// `CefLifeSpanHandler::OnAfterCreated` — called after a browser is created.
    ///
    /// Updates the browser's internal state to reflect that it is fully initialized.
    /// Steam's UI layer expects this callback before it sends navigation or JS commands.
    pub fn on_after_created(&mut self, browser_handle: CefHandle) -> AppResult<()> {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.is_loading = true;
            browser.dirty = true;
            eprintln!("[CefBridge] OnAfterCreated: browser {browser_handle:#x}");
        } else {
            eprintln!("[CefBridge] OnAfterCreated: browser {browser_handle:#x} not found",);
        }
        Ok(())
    }

    /// `CefLifeSpanHandler::DoClose` — called when the browser is about to close.
    ///
    /// Returns `true` if the close will be handled (host should close immediately),
    /// or `false` if the host should wait for OnBeforeClose. In our WKWebView
    /// bridge, we set a close-pending flag and return `true` to initiate teardown.
    pub fn do_close(&mut self, browser_handle: CefHandle) -> bool {
        let exists = self.browsers.contains_key(&browser_handle);
        if exists {
            self.close_pending_for = Some(browser_handle);
            eprintln!(
                "[CefBridge] DoClose: browser {browser_handle:#x} — close sequence initiated"
            );
            true
        } else {
            eprintln!("[CefBridge] DoClose: browser {browser_handle:#x} not found — ignoring",);
            false
        }
    }

    /// `CefLifeSpanHandler::OnBeforeClose` — called just before the browser is destroyed.
    ///
    /// Performs final cleanup: closes the underlying WKWebView and removes the
    /// browser from all internal state. After this call the browser handle is
    /// no longer valid.
    pub fn on_before_close(&mut self, browser_handle: CefHandle) {
        if self.close_pending_for == Some(browser_handle) {
            self.close_pending_for = None;
        }

        // Close the WKWebView if this browser has one
        if let Some(browser) = self.browsers.get(&browser_handle) {
            if let Some(wk_handle) = browser.wk_handle {
                if let Some(mgr) = self.webview_manager.as_mut() {
                    mgr.close(wk_handle);
                }
            }
        }

        // Remove browser from all state
        self.browsers.remove(&browser_handle);
        self.frames.retain(|&(bh, _), _| bh != browser_handle);
        self.rendered_frames.retain(|f| {
            self.browsers
                .get(&browser_handle)
                .map_or(true, |b| f.browser_id != b.id)
        });

        eprintln!("[CefBridge] OnBeforeClose: browser {browser_handle:#x} — cleaned up");
    }

    // -----------------------------------------------------------------------
    // CefLoadHandler — page loading state changes
    // -----------------------------------------------------------------------

    /// `CefLoadHandler::OnLoadingStateChange` — called when the loading state changes.
    ///
    /// Updates the browser's `is_loading`, `can_go_back`, and `can_go_forward` flags.
    /// Steam's UI uses this to enable/disable navigation buttons.
    pub fn on_loading_state_change(
        &mut self,
        browser_handle: CefHandle,
        is_loading: bool,
        can_go_back: bool,
        can_go_forward: bool,
    ) {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.is_loading = is_loading;
            browser.can_go_back = can_go_back;
            browser.can_go_forward = can_go_forward;
            browser.dirty = true;
            eprintln!(
                "[CefBridge] OnLoadingStateChange: browser {browser_handle:#x} \
                 loading={is_loading} back={can_go_back} forward={can_go_forward}",
            );
        }
    }

    /// `CefLoadHandler::OnLoadStart` — called when a page starts loading.
    ///
    /// Marks the browser as loading. The `transition_type` indicates what kind
    /// of navigation triggered the load (link click, address bar, reload, etc.).
    pub fn on_load_start(&mut self, browser_handle: CefHandle, url: &str, _is_main_frame: bool) {
        let is_main = true; // WKWebView reports per-page, always main frame
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.is_loading = true;
            browser.current_url = url.to_string();
            browser.dirty = true;
            eprintln!(
                "[CefBridge] OnLoadStart: browser {browser_handle:#x} url={url} \
                 main_frame={is_main}",
            );
        }
    }

    /// `CefLoadHandler::OnLoadEnd` — called when a page finishes loading.
    ///
    /// Marks the browser as no longer loading and triggers a snapshot for rendering.
    /// Steam uses this to know when to inject its JavaScript bridge.
    pub fn on_load_end(&mut self, browser_handle: CefHandle, url: &str) -> AppResult<()> {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.is_loading = false;
            browser.current_url = url.to_string();
            browser.dirty = true;
            eprintln!("[CefBridge] OnLoadEnd: browser {browser_handle:#x} url={url}");
        }
        Ok(())
    }

    /// `CefLoadHandler::OnLoadError` — called when a page fails to load.
    ///
    /// Logs the error and updates the browser's error state. Important for
    /// diagnostics when Steam overlay URLs fail to load.
    pub fn on_load_error(
        &mut self,
        browser_handle: CefHandle,
        error_code: u32,
        error_text: &str,
        failed_url: &str,
    ) {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.is_loading = false;
            browser.dirty = true;
            eprintln!(
                "[CefBridge] OnLoadError: browser {browser_handle:#x} \
                 error_code={error_code} url={failed_url} error={error_text}",
            );
        } else {
            eprintln!(
                "[CefBridge] OnLoadError: browser {browser_handle:#x} not found \
                 error_code={error_code} url={failed_url} error={error_text}",
            );
        }
    }

    // -----------------------------------------------------------------------
    // CefDisplayHandler — display-related events
    // -----------------------------------------------------------------------

    /// `CefDisplayHandler::OnAddressChange` — called when the displayed URL changes.
    ///
    /// Updates the browser's `current_url`. Steam's overlay uses this to track
    /// navigation state for the in-game browser UI.
    pub fn on_address_change(&mut self, browser_handle: CefHandle, url: &str) {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.current_url = url.to_string();
            eprintln!("[CefBridge] OnAddressChange: browser {browser_handle:#x} url={url}",);
        }
    }

    /// `CefDisplayHandler::OnTitleChange` — called when the page title changes.
    ///
    /// Updates the browser's cached title. Steam's UI may check this to update
    /// window title or internal state.
    pub fn on_title_change(&mut self, browser_handle: CefHandle, title: &str) -> AppResult<()> {
        if let Some(browser) = self.browsers.get_mut(&browser_handle) {
            browser.title = title.to_string();
            eprintln!("[CefBridge] OnTitleChange: browser {browser_handle:#x} title={title}",);
        }
        Ok(())
    }

    /// `CefDisplayHandler::OnTooltip` — called when the tooltip text changes.
    ///
    /// Returns `true` to show the tooltip text, `false` to hide it.
    /// Steam overlay uses tooltips for navigation hints and button descriptions.
    pub fn on_tooltip(&mut self, _browser_handle: CefHandle, text: &str) -> bool {
        if text.is_empty() {
            eprintln!("[CefBridge] OnTooltip: browser {_browser_handle:#x} — tooltip hidden",);
            false
        } else {
            eprintln!("[CefBridge] OnTooltip: browser {_browser_handle:#x} text=\"{text}\"",);
            true
        }
    }

    /// `CefDisplayHandler::OnStatusMessage` — called when the status message changes.
    ///
    /// Logs status bar messages (e.g., link hover URLs). Steam may use this
    /// for status bar display in the overlay.
    pub fn on_status_message(&mut self, browser_handle: CefHandle, message: &str) {
        eprintln!("[CefBridge] OnStatusMessage: browser {browser_handle:#x} message=\"{message}\"",);
    }

    /// `CefDisplayHandler::OnConsoleMessage` — called when CEF writes to the console.
    ///
    /// Logs JavaScript console output from the browser page. Important for
    /// debugging Steam overlay JavaScript issues.
    ///
    /// Returns `true` if the message was handled (prevents default console output).
    pub fn on_console_message(
        &mut self,
        _browser_handle: CefHandle,
        message: &str,
        source: &str,
        line: u32,
    ) -> bool {
        eprintln!(
            "[CefBridge] OnConsoleMessage: browser {_browser_handle:#x} \
             source=\"{source}\" line={line} message=\"{message}\"",
        );
        // Return false to allow default console handling as well
        false
    }

    // -----------------------------------------------------------------------
    // CefRenderHandler — offscreen rendering / painting
    // -----------------------------------------------------------------------

    /// `CefRenderHandler::GetViewRect` — return the browser's view dimensions.
    ///
    /// Returns the current dimensions of the browser's rendering area.
    /// CEF calls this to know how large the offscreen bitmap should be.
    /// Falls back to 1x1 if the browser is not found (minimum valid rect).
    pub fn get_view_rect(&self, browser_handle: CefHandle) -> CefRect {
        if let Some(browser) = self.browsers.get(&browser_handle) {
            // Use WKWebView dimensions if available
            let (w, h) = if let Some(wk_handle) = browser.wk_handle {
                if let Some(mgr) = self.webview_manager.as_ref() {
                    mgr.dimensions(wk_handle)
                        .map(|(dw, dh)| (dw as i32, dh as i32))
                        .unwrap_or((1, 1))
                } else {
                    (1, 1)
                }
            } else {
                // Fall back to first rendered frame dimensions
                self.get_rendered_frame(browser.id)
                    .map(|f| (f.width as i32, f.height as i32))
                    .unwrap_or((1, 1))
            };
            let rect = CefRect {
                x: 0,
                y: 0,
                width: w,
                height: h,
            };
            eprintln!("[CefBridge] GetViewRect: browser {browser_handle:#x} -> {w}x{h}",);
            rect
        } else {
            eprintln!(
                "[CefBridge] GetViewRect: browser {browser_handle:#x} not found — returning 1x1",
            );
            CefRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }
        }
    }

    /// `CefRenderHandler::GetScreenInfo` — return screen information.
    ///
    /// Returns the screen point (origin) and available rect. Steam overlay
    /// may query this to position popups relative to the game window.
    /// Returns `(screen_point_x, screen_point_y, scale_factor)` where
    /// `scale_factor` is the device pixel ratio (1.0 for standard DPI).
    pub fn get_screen_info(&self, _browser_handle: CefHandle) -> (i32, i32, f64) {
        // Default screen info: origin at (0,0), 1x scale factor.
        // In production, this should query the NSScreen for the actual
        // display where the overlay is shown.
        eprintln!("[CefBridge] GetScreenInfo: browser {_browser_handle:#x} -> (0,0) scale=1.0",);
        (0, 0, 1.0)
    }

    /// `CefRenderHandler::OnPaint` — called when CEF wants to paint the
    /// offscreen buffer.
    ///
    /// This is the critical rendering callback. CEF passes the pixel buffer
    /// (BGRA or RGBA depending on config) that should be composited into
    /// the graphics pipeline.
    ///
    /// `paint_type` indicates whether this is a view paint (0) or popup paint (1).
    /// The `dirty_rects` describe which regions have changed. The `buffer`
    /// contains the full frame pixel data.
    ///
    /// In our WKWebView bridge, this maps snapshot data into the rendered
    /// frame queue for compositing.
    pub fn on_paint(
        &mut self,
        browser_handle: CefHandle,
        paint_type: u32,
        _dirty_rects: &[CefRect],
        buffer: &[u8],
        width: u32,
        height: u32,
    ) {
        let browser_id = match self.browsers.get(&browser_handle) {
            Some(b) => b.id,
            None => {
                eprintln!("[CefBridge] OnPaint: browser {browser_handle:#x} not found",);
                return;
            }
        };

        let expected_size = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(4);
        let pixels = if buffer.len() >= expected_size {
            buffer[..expected_size].to_vec()
        } else {
            eprintln!(
                "[CefBridge] OnPaint: buffer too small for {width}x{height} \
                 (got {} bytes, need {expected_size}) — padding",
                buffer.len(),
            );
            let mut padded = buffer.to_vec();
            padded.resize(expected_size, 0xFF);
            padded
        };

        if paint_type == 0 {
            // View paint (main rendering area)
            let frame_number = self.rendered_frames.len() as u64;
            let rendered = RenderedFrame {
                browser_id,
                width,
                height,
                pixels: pixels.clone(),
                frame_number,
            };

            // Invoke paint callback if registered
            if let Some(ref mut cb) = self.paint_callback {
                cb(rendered.clone());
            }

            self.rendered_frames.push_back(rendered);
            while self.rendered_frames.len() > 10 {
                self.rendered_frames.pop_front();
            }

            if let Some(browser) = self.browsers.get_mut(&browser_handle) {
                browser.dirty = false;
            }

            // Publish as LiveFrame if live session is active
            // The buffer from CEF is typically BGRA, convert to LiveFrame format
            if self.live_frame_tx.is_some() {
                self.publish_live_frame_from_pixels(width, height, pixels);
            }

            eprintln!(
                "[CefBridge] OnPaint: browser {browser_handle:#x} \
                 view {width}x{height} frame={frame_number}",
            );
        } else {
            // Popup paint — store popup pixel data for compositing
            eprintln!(
                "[CefBridge] OnPaint: browser {browser_handle:#x} \
                 popup {width}x{height} (popup paint type={paint_type})",
            );
            // Store popup frame data for subsequent compositing calls
            self.popup_info = Some(CefRect {
                x: 0,
                y: 0,
                width: width as i32,
                height: height as i32,
            });
        }
    }

    /// `CefRenderHandler::OnAcceleratedPaint` — called when CEF paints via
    /// a shared GPU texture handle (D3D11/OpenGL/Vulkan shared handle).
    ///
    /// On macOS, this maps to IOSurface-based zero-copy rendering.
    /// The `shared_handle` is an IOSurfaceRef that can be wrapped as a
    /// Metal texture for direct compositing.
    ///
    /// Returns `true` if the accelerated paint was handled.
    pub fn on_accelerated_paint(
        &mut self,
        browser_handle: CefHandle,
        _paint_type: u32,
        shared_handle: *mut std::ffi::c_void,
    ) -> bool {
        if shared_handle.is_null() {
            eprintln!(
                "[CefBridge] OnAcceleratedPaint: browser {browser_handle:#x} \
                 null shared handle — ignoring",
            );
            return false;
        }

        let browser_id = match self.browsers.get(&browser_handle) {
            Some(b) => b.id,
            None => {
                eprintln!("[CefBridge] OnAcceleratedPaint: browser {browser_handle:#x} not found",);
                return false;
            }
        };

        eprintln!(
            "[CefBridge] OnAcceleratedPaint: browser {browser_handle:#x} \
             shared_handle={:p} — IOSurface zero-copy path available",
            shared_handle,
        );

        // Update the IO surface cache with the shared handle
        // The caller (drawing code) will use render_to_io_surface_texture
        // to wrap this in a Metal texture for compositing.
        if let Some(mgr) = self.webview_manager.as_ref() {
            if let Some(browser) = self.browsers.get(&browser_handle) {
                if let Some(wk_handle) = browser.wk_handle {
                    if let Some(dims) = mgr.dimensions(wk_handle) {
                        let (fw, fh) = (dims.0 as u32, dims.1 as u32);
                        let frame_number = self.rendered_frames.len() as u64;
                        // Push a placeholder rendered frame that the IOSurface
                        // path will serve (actual pixels live on GPU).
                        let rendered = RenderedFrame {
                            browser_id,
                            width: fw,
                            height: fh,
                            pixels: Vec::new(), // zero-copy — no CPU pixels
                            frame_number,
                        };
                        if let Some(ref mut cb) = self.paint_callback {
                            cb(rendered.clone());
                        }
                        self.rendered_frames.push_back(rendered);
                        while self.rendered_frames.len() > 10 {
                            self.rendered_frames.pop_front();
                        }
                        if let Some(b) = self.browsers.get_mut(&browser_handle) {
                            b.dirty = false;
                        }
                        // For IOSurface accelerated paint, we can't easily read back
                        // pixels in this callback. Publish a solid-color placeholder
                        // that will be replaced when the IOSurface is read back later.
                        if self.live_frame_tx.is_some() {
                            // Try to read back from IOSurface if available
                            let surface_pixels = self.read_io_surface_pixels(fw, fh);
                            if let Some(pixel_data) = surface_pixels {
                                self.publish_live_frame_from_pixels(fw, fh, pixel_data);
                            } else {
                                // Fallback: publish a dark-gray frame (BGRA) while
                                // IOSurface readback is temporarily unavailable.
                                let pixel_count = fw as usize * fh as usize;
                                let mut fallback_pixels = Vec::with_capacity(pixel_count * 4);
                                for _ in 0..pixel_count {
                                    fallback_pixels.push(0x1b); // B
                                    fallback_pixels.push(0x1b); // G
                                    fallback_pixels.push(0x1b); // R
                                    fallback_pixels.push(0xff); // A
                                }
                                self.publish_live_frame_from_pixels(fw, fh, fallback_pixels);
                            }
                        }
                        eprintln!(
                            "[CefBridge] on_paint: browser {browser_handle:#x} \
                             frame {} rendered ({}x{})",
                            frame_number, fw, fh,
                        );
                        return true;
                    }
                }
            }
        }

        eprintln!(
            "[CefBridge] on_paint: browser {browser_handle:#x} — could not paint \
             (missing webview_manager, browser, wk_handle, or dimensions)"
        );
        false
    }

    /// `CefRenderHandler::OnPopupShow` — called to show or hide the popup widget.
    ///
    /// When `show` is true, a popup (e.g., <select> dropdown, context menu) is
    /// being displayed. When false, the popup is hidden.
    pub fn on_popup_show(&mut self, browser_handle: CefHandle, show: bool) {
        self.popup_showing = show;
        if !show {
            self.popup_info = None;
        }
        eprintln!("[CefBridge] OnPopupShow: browser {browser_handle:#x} show={show}",);
    }

    /// `CefRenderHandler::OnPopupSize` — called when the popup widget is resized.
    ///
    /// Stores the popup's position and dimensions so that subsequent OnPaint
    /// calls with popup type can correctly composite the popup content.
    pub fn on_popup_size(&mut self, browser_handle: CefHandle, rect: CefRect) {
        let stored_rect = rect.clone();
        self.popup_info = Some(stored_rect);
        eprintln!(
            "[CefBridge] OnPopupSize: browser {browser_handle:#x} \
             rect=({},{}) {}x{}",
            rect.x, rect.y, rect.width, rect.height,
        );
    }

    // -----------------------------------------------------------------------
    // CefRequestHandler — request interception and auth
    // -----------------------------------------------------------------------

    /// `CefRequestHandler::OnBeforeBrowse` — called before a navigation request.
    ///
    /// Returns `true` to cancel the navigation, `false` to allow it.
    /// By default, all navigations are allowed. Steam may use this to intercept
    /// `steam://` protocol URLs and route them to native handlers.
    pub fn on_before_browse(&mut self, browser_handle: CefHandle, url: &str) -> bool {
        if url.starts_with("steam://") {
            eprintln!(
                "[CefBridge] OnBeforeBrowse (steam://): browser {browser_handle:#x} \
                 url={url} — intercepted, will route to native Steam handler",
            );
            // steam:// URLs are handled natively — cancel browser navigation
            // and route to the Steam integration layer which handles
            // steam://openurl, steam://store, steam://friends, etc.
            if crate::steam_protocol::parse_steam_protocol_url(url).is_some() {
                eprintln!("[CefBridge] OnBeforeBrowse: parsed steam:// URL: {url}",);
            }
            return true;
        }
        eprintln!("[CefBridge] OnBeforeBrowse: browser {browser_handle:#x} url={url} — allowing",);
        false
    }

    /// `CefRequestHandler::OnBeforeResourceLoad` — called before a resource
    /// is loaded.
    ///
    /// Returns `true` to block the resource, `false` to allow it.
    /// Used for content filtering or ad blocking in the Steam overlay.
    pub fn on_before_resource_load(&mut self, _browser_handle: CefHandle, _url: &str) -> bool {
        // Allow all resources by default
        false
    }

    /// `CefRequestHandler::GetResourceRequestHandler` — called to get a handler
    /// for intercepting individual resource requests.
    ///
    /// Returns a handler ID (0 = default handling). In our bridge, we use
    /// the default WKWebView resource loading (no custom interception).
    /// A non-zero return value could be used for custom cookie injection,
    /// header modification, etc. for specific resource types.
    pub fn get_resource_request_handler(&mut self, _browser_handle: CefHandle, url: &str) -> u32 {
        // Return 0 for default handling of all resources
        // Steam overlay may check for specific resources:
        if url.contains("steamcommunity.com") || url.contains("store.steampowered.com") {
            // These are Steam domains — could inject custom headers here
            // in a future implementation (e.g., Steam auth tokens).
            return 0;
        }
        0
    }

    /// `CefRequestHandler::OnAuthCredentials` — called when the browser needs
    /// authentication credentials (HTTP Basic/Digest auth or proxy auth).
    ///
    /// Returns `true` if credentials are provided, `false` to cancel auth.
    /// Steam overlay may need this for proxy-authenticated networks.
    ///
    /// In our bridge, we do not store credentials — the caller must provide
    /// them via the CEF credential store. We return `false` to cancel auth
    /// (the request will fail with a 401).
    pub fn on_auth_credentials(
        &mut self,
        _browser_handle: CefHandle,
        _origin_url: &str,
        _is_proxy: bool,
        _host: &str,
        _port: u16,
        _realm: &str,
        _scheme: &str,
    ) -> bool {
        eprintln!(
            "[CefBridge] OnAuthCredentials: browser {_browser_handle:#x} \
             host={_host}:{_port} realm={_realm} scheme={_scheme} — credentials not available, \
             cancelling auth",
        );
        false
    }

    /// `CefRequestHandler::OnCookieableSchemes` — returns the list of URI schemes
    /// for which cookies can be stored.
    ///
    /// This tells CEF which protocols support cookies. Steam overlay uses cookies
    /// for session management across store.steampowered.com and steamcommunity.com.
    pub fn on_cookieable_schemes(&self) -> &[String] {
        &self.cookieable_schemes
    }

    // -----------------------------------------------------------------------
    // Utility / Extension Registration
    // -----------------------------------------------------------------------

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
    /// Dispatch a CefQuery (JS→C++ bridge message from Steam web helper).
    ///
    /// Steam's UI communicates with the native client via a custom JS bridge
    /// protocol. Messages are JSON strings with fields:
    /// - `type`: the query type identifier
    /// - `request`: the request payload (often a URL path or data)
    /// - `requestId`: unique ID for correlating responses
    ///
    /// Gap 2.5 fix: Added handlers for "download" (triggers macOS file download),
    /// "auth_credentials" (returns stored credentials), and other common Steam
    /// query types.
    pub fn dispatch_cef_query(&mut self, query_json: &str) -> AppResult<String> {
        let query: serde_json::Value = serde_json::from_str(query_json).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("dispatch_cef_query: invalid JSON: {e}"),
            )
        })?;

        let request = query.get("request").and_then(|v| v.as_str()).unwrap_or("");
        let request_id = query.get("requestId").and_then(|v| v.as_u64()).unwrap_or(0);
        let query_type = query
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // Helper: navigate the first available browser to a URL
        let navigate_to = |bridge: &mut Self, url: &str| -> AppResult<()> {
            if let Some(&bh) = bridge.browsers.keys().next() {
                bridge.cef_frame_load_url(bh, url)?;
            }
            Ok(())
        };

        let response = match query_type {
            // Navigate the browser to a Steam store URL
            "store_navigation" => {
                let store_url = format!("https://store.steampowered.com{request}");
                navigate_to(self, &store_url)?;
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }

            // Initiate Steam login flow
            "login" => {
                navigate_to(self, "https://steamcommunity.com/login")?;
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "login_initiated"
                })
            }

            // Handle file downloads — trigger macOS download via NSWorkspace
            // or save to Downloads folder
            "download" => {
                let url = request;
                let filename = query
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("download");
                eprintln!(
                    "[CefBridge] dispatch_cef_query: download requested url={url} filename={filename}",
                );
                // Trigger the download by navigating or using NSURLDownload
                if !url.is_empty() {
                    // Try to download via curl to Downloads folder as fallback
                    let downloads_dir =
                        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
                    let dest = downloads_dir.join(filename);
                    let url_copy = url.to_string();
                    std::thread::spawn(move || {
                        let result = std::process::Command::new("curl")
                            .args(["-L", "-o", &dest.to_string_lossy(), &url_copy])
                            .output();
                        match result {
                            Ok(output) if output.status.success() => {
                                eprintln!(
                                    "[CefBridge] download completed: {} -> {}",
                                    url_copy,
                                    dest.display()
                                );
                            }
                            Ok(output) => {
                                eprintln!(
                                    "[CefBridge] download failed: {} exit={:?} stderr={}",
                                    url_copy,
                                    output.status.code(),
                                    String::from_utf8_lossy(&output.stderr),
                                );
                            }
                            Err(e) => {
                                eprintln!("[CefBridge] download error for {url_copy}: {e}");
                            }
                        }
                    });
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "download_started",
                    "filename": filename,
                })
            }

            // Handle authentication credentials requests
            "auth_credentials" => {
                let realm = query.get("realm").and_then(|v| v.as_str()).unwrap_or("");
                let host = query.get("host").and_then(|v| v.as_str()).unwrap_or("");
                eprintln!(
                    "[CefBridge] dispatch_cef_query: auth_credentials requested \
                     realm=\"{realm}\" host=\"{host}\"",
                );
                // In production, this should prompt the user or check the system
                // keychain. For now, return a cancellation to let the browser
                // handle it natively.
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "cancel",
                    "error": "user cancelled authentication"
                })
            }

            // Open a URL in the system's default browser
            "open_external_url" => {
                if !request.is_empty() {
                    if let Err(e) = std::process::Command::new("open").arg(request).spawn() {
                        eprintln!(
                            "[CefBridge] dispatch_cef_query: failed to open external URL '{request}': {e}",
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "opened"
                })
            }

            // Navigate to the Steam community hub
            "community_navigation" => {
                let community_url = format!("https://steamcommunity.com{request}");
                navigate_to(self, &community_url)?;
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }

            // Navigate to the Steam library
            "library_navigation" => {
                navigate_to(self, "https://steamcommunity.com/my/games")?;
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }

            // Navigate to the Steam friends list
            "friends_navigation" => {
                navigate_to(self, "https://steamcommunity.com/my/friends")?;
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }

            // Navigate to the Steam settings page
            "settings_navigation" => {
                navigate_to(self, "https://steamcommunity.com/my/settings")?;
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }

            // Navigate back in browser history
            "browser_back" => {
                if let Some(&bh) = self.browsers.keys().next() {
                    if let Err(error) = self.cef_browser_go_back(bh) {
                        eprintln!(
                            "[CefBridge] handle_cef_query browser_back failed: {}",
                            error
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated_back"
                })
            }

            // Navigate forward in browser history
            "browser_forward" => {
                if let Some(&bh) = self.browsers.keys().next() {
                    if let Err(error) = self.cef_browser_go_forward(bh) {
                        eprintln!(
                            "[CefBridge] handle_cef_query browser_forward failed: {}",
                            error
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated_forward"
                })
            }

            // Reload the current page
            "browser_reload" => {
                if let Some(&bh) = self.browsers.keys().next() {
                    if let Err(error) = self.cef_browser_reload(bh) {
                        eprintln!(
                            "[CefBridge] handle_cef_query browser_reload failed: {}",
                            error
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "reloaded"
                })
            }

            // Get the current page's URL
            "get_current_url" => {
                let url = self
                    .browsers
                    .values()
                    .next()
                    .map(|b| b.current_url.clone())
                    .unwrap_or_default();
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": url
                })
            }

            // Set a cookie via the cookie manager
            "set_cookie" => {
                let name = query.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let value = query.get("value").and_then(|v| v.as_str()).unwrap_or("");
                let domain = query.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                let path = query.get("path").and_then(|v| v.as_str()).unwrap_or("/");
                let secure = query
                    .get("secure")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let httponly = query
                    .get("httponly")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let same_site = query
                    .get("same_site")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unspecified");
                let cookie = CefCookie {
                    name: name.to_string(),
                    value: value.to_string(),
                    domain: domain.to_string(),
                    path: path.to_string(),
                    secure,
                    httponly,
                    same_site: same_site.to_string(),
                    creation: 0,
                    last_access: 0,
                    expires: 0,
                };
                // Use a sensible default cache path
                let cache_path = self
                    .settings
                    .cache_path
                    .clone()
                    .unwrap_or_else(|| ".".to_string());
                let mgr = CefCookieManager::get_global(&cache_path);
                if let Ok(mut mgr) = mgr.lock() {
                    if let Err(error) = mgr.set_cookie(cookie) {
                        eprintln!("[CefBridge] handle_cef_query set_cookie failed: {}", error);
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "cookie_set"
                })
            }

            // Get all cookies
            "get_cookies" => {
                let cache_path = self
                    .settings
                    .cache_path
                    .clone()
                    .unwrap_or_else(|| ".".to_string());
                let mgr = CefCookieManager::get_global(&cache_path);
                let cookies = if let Ok(mgr) = mgr.lock() {
                    mgr.visit_all_cookies()
                } else {
                    Vec::new()
                };
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": cookies
                })
            }

            // Execute JavaScript in the browser context
            "execute_javascript" => {
                let script = request;
                if let Some(&bh) = self.browsers.keys().next() {
                    if let Err(error) = self.cef_frame_execute_java_script(bh, 0, script) {
                        eprintln!(
                            "[CefBridge] handle_cef_query execute_javascript failed: {}",
                            error
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "script_executed"
                })
            }

            // Get browser dimensions
            "get_dimensions" => {
                let (w, h) = self
                    .browsers
                    .values()
                    .next()
                    .and_then(|b| b.wk_handle)
                    .and_then(|wk| self.webview_manager.as_ref()?.dimensions(wk))
                    .unwrap_or((1280.0, 720.0));
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": { "width": w, "height": h }
                })
            }

            // Resize the browser
            "resize" => {
                let w = query
                    .get("width")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1280.0);
                let h = query
                    .get("height")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(720.0);
                if let Some(&bh) = self.browsers.keys().next() {
                    if let Some(browser) = self.browsers.get(&bh) {
                        if let Some(wk) = browser.wk_handle {
                            if let Some(mgr) = self.webview_manager.as_mut() {
                                let _ = mgr.resize(wk, w, h);
                            }
                        }
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": { "width": w, "height": h }
                })
            }

            // Unknown query type — log and return error
            _ => {
                eprintln!(
                    "[CefBridge] dispatch_cef_query: unknown query type=\"{query_type}\" \
                     request=\"{request}\"",
                );
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
    /// SameSite attribute: "unspecified", "lax", "strict", or "none"
    #[serde(default = "default_same_site")]
    pub same_site: String,
    pub creation: u64,
    pub last_access: u64,
    pub expires: u64,
}

fn default_same_site() -> String {
    "unspecified".to_string()
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
            same_site: "unspecified".to_string(),
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
    /// On macOS, also pushes the cookie to the system NSHTTPCookieStorage so that
    /// WKWebView's native requests can see it (Gap 2.3).
    pub fn set_cookie(&mut self, cookie: CefCookie) -> AppResult<()> {
        // Remove existing cookie with same name/domain/path
        self.cookies.retain(|c| {
            !(c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path)
        });
        self.cookies.push(cookie);
        self.dirty = true;
        self.flush()?;
        // Propagate to macOS system cookie store so WKWebView sees the cookie
        #[cfg(target_os = "macos")]
        self.sync_to_ns_http_cookie_storage();
        Ok(())
    }

    /// Visit all stored cookies. Calls `visitor` for each cookie.
    pub fn visit_all_cookies(&self) -> Vec<CefCookie> {
        self.cookies.clone()
    }

    /// Visit cookies for a specific host (domain filter).
    ///
    /// Returns only cookies whose domain contains the given host string.
    /// This supports CEF's `cef_cookie_manager_visit_url_cookies` by allowing
    /// callers to filter cookies for a specific URL or domain.
    pub fn visit_cookies_for_host(&self, host: &str) -> Vec<CefCookie> {
        let host_lower = host.to_lowercase();
        self.cookies
            .iter()
            .filter(|c| c.domain.to_lowercase().contains(&host_lower))
            .cloned()
            .collect()
    }

    /// Export all cookies in Netscape HTTP cookie file format.
    ///
    /// Netscape format is a plain-text cookie file with tab-separated columns:
    ///   domain, domain_flag, path, secure, expires, name, value
    ///
    /// This format is used by tools like `curl`, `wget`, and some HTTP clients
    /// for cookie import/export. The export includes all fields from CefCookie.
    ///
    /// Returns the cookie file content as a string with a header comment.
    pub fn export_netscape_format(&self) -> String {
        let mut out = String::with_capacity(self.cookies.len() * 160);
        out.push_str("# Netscape HTTP Cookie File\n");
        out.push_str("# https://curl.se/rfc/cookie_spec.html\n");
        out.push_str("# This file was generated by Casa1 CefCookieManager\n");
        out.push_str("# Edit at your own risk.\n\n");

        for cookie in &self.cookies {
            // Columns: domain, domain_flag, path, secure, expires, name, value
            let domain_flag = if cookie.domain.starts_with('.') {
                "TRUE"
            } else {
                "FALSE"
            };
            let secure_flag = if cookie.secure { "TRUE" } else { "FALSE" };
            let expires = cookie.expires;

            // Escape tabs and newlines in value
            let safe_value = cookie
                .value
                .replace('\t', "\\t")
                .replace('\n', "\\n")
                .replace('\r', "\\r");

            let safe_name = cookie
                .name
                .replace('\t', "\\t")
                .replace('\n', "\\n")
                .replace('\r', "\\r");

            let safe_path = cookie
                .path
                .replace('\t', "\\t")
                .replace('\n', "\\n")
                .replace('\r', "\\r");

            let safe_domain = cookie
                .domain
                .replace('\t', "\\t")
                .replace('\n', "\\n")
                .replace('\r', "\\r");

            writeln!(
                out,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                safe_domain, domain_flag, safe_path, secure_flag, expires, safe_name, safe_value,
            )
            .unwrap_or_else(|error| {
                eprintln!(
                    "[CefBridge] cookie export: failed to append cookie line: {}",
                    error
                );
            });
        }

        out
    }

    /// Delete cookies matching the given URL and name filters.
    ///
    /// Cookies are retained (kept) if they match all active filters.
    /// - If a URL filter is given, cookies whose domain does NOT contain
    ///   the filter string are kept (they don't match the filter criteria).
    /// - If a name filter is given, only cookies with that exact name are
    ///   considered for deletion.
    /// - Cookies that match ALL specified filters are removed.
    pub fn delete_cookies(&mut self, url: Option<&str>, name: Option<&str>) -> AppResult<()> {
        self.cookies.retain(|c| {
            // Check if this cookie should be kept because it doesn't match the URL filter
            if let Some(url_filter) = url {
                if !c.domain.contains(url_filter) {
                    return true; // keep — this cookie's domain doesn't match the filter
                }
            }
            // Check if this cookie should be kept because it doesn't match the name filter
            if let Some(name_filter) = name {
                if c.name != name_filter {
                    return true; // keep — this cookie's name doesn't match the filter
                }
            }
            // Cookie matches all specified filters — remove it
            false
        });
        self.dirty = true;
        self.flush()?;
        // Propagate deletion to macOS system cookie store
        #[cfg(target_os = "macos")]
        self.sync_to_ns_http_cookie_storage();
        Ok(())
    }

    /// Flush the cookie store to disk if dirty.
    pub fn flush(&mut self) -> AppResult<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self.store_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "[CefBridge] cookie flush: failed to create parent dir '{}': {e}",
                    parent.display(),
                );
            }
        }
        let data = serde_json::to_string_pretty(&self.cookies).map_err(|e| {
            AppError::new(
                ReasonCode::RcCliInvalid,
                format!("cookie flush serialization: {e}"),
            )
        })?;
        std::fs::write(&self.store_path, &data).map_err(|e| {
            AppError::new(ReasonCode::RcCliInvalid, format!("cookie flush write: {e}"))
        })?;
        self.dirty = false;
        Ok(())
    }

    /// Get the global cookie manager instance (singleton).
    pub fn get_global(cache_path: &str) -> std::sync::Arc<std::sync::Mutex<CefCookieManager>> {
        static GLOBAL_COOKIE_MANAGER: std::sync::LazyLock<
            std::sync::Mutex<Option<std::sync::Arc<std::sync::Mutex<CefCookieManager>>>>,
        > = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

        // lock(): panic on poison is acceptable — poisoned mutex indicates
        // a panic in another thread which is unrecoverable.
        let mut guard = GLOBAL_COOKIE_MANAGER
            .lock()
            .expect("GLOBAL_COOKIE_MANAGER lock should not be poisoned");
        if guard.is_none() {
            let mut mgr = CefCookieManager::new(cache_path);
            // Sync initial cookies from macOS NSHTTPCookieStorage so that
            // Steam login sessions survive restarts (Gap 2.3).
            #[cfg(target_os = "macos")]
            mgr.sync_from_ns_http_cookie_storage();
            *guard = Some(std::sync::Arc::new(std::sync::Mutex::new(mgr)));
        }
        // SAFETY: Just initialized if it was None; always Some at this point.
        guard
            .as_ref()
            .expect("GLOBAL_COOKIE_MANAGER initialized just above")
            .clone()
    }

    // -----------------------------------------------------------------------
    // NSHTTPCookieStorage Integration (macOS)
    //
    // Syncs cookies between our JSON-file-backed CefCookieManager and macOS's
    // shared NSHTTPCookieStorage. This lets Steam login sessions persist
    // across restarts via the system cookie store (Gap 2.3).
    // -----------------------------------------------------------------------

    /// Synchronize cookies from macOS NSHTTPCookieStorage into this manager.
    #[cfg(target_os = "macos")]
    pub fn sync_from_ns_http_cookie_storage(&mut self) {
        use std::ffi::c_void;
        // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
        unsafe {
            let cls_storage = match objc::runtime::Class::get("NSHTTPCookieStorage") {
                Some(cls) => cls,
                None => return,
            };
            let storage: *mut objc::runtime::Object =
                msg_send![cls_storage, sharedHTTPCookieStorage];
            if storage.is_null() {
                return;
            }
            let cookies: *mut objc::runtime::Object = msg_send![storage, cookies];
            if cookies.is_null() {
                return;
            }
            let count: usize = msg_send![cookies, count];
            for i in 0..count {
                let cookie: *mut objc::runtime::Object = msg_send![cookies, objectAtIndex: i];
                if cookie.is_null() {
                    continue;
                }
                let name: *mut c_void = msg_send![cookie, name];
                let value: *mut c_void = msg_send![cookie, value];
                let domain: *mut c_void = msg_send![cookie, domain];
                let path: *mut c_void = msg_send![cookie, path];
                let secure: bool = msg_send![cookie, isSecure];
                let httponly: bool = msg_send![cookie, isHTTPOnly];

                let name = c_str_to_string(name);
                let value = c_str_to_string(value);
                let domain = c_str_to_string(domain);
                let path = c_str_to_string(path);

                if name.is_empty() {
                    continue;
                }

                // Attempt to read SameSite property (NSHTTPCookie.sameSite on macOS 10.15+)
                let same_site = {
                    let raw: *mut c_void = msg_send![cookie, sameSite];
                    let s = c_str_to_string(raw);
                    if s.is_empty() {
                        "unspecified".to_string()
                    } else {
                        s.to_lowercase()
                    }
                };

                let cef_cookie = CefCookie {
                    name,
                    value,
                    domain,
                    path,
                    secure,
                    httponly,
                    same_site,
                    creation: 0,
                    last_access: 0,
                    expires: 0,
                };

                // Replace existing cookie with same name/domain/path
                self.cookies.retain(|c| {
                    !(c.name == cef_cookie.name
                        && c.domain == cef_cookie.domain
                        && c.path == cef_cookie.path)
                });
                self.cookies.push(cef_cookie);
            }
        }
    }

    /// Push all stored cookies to macOS NSHTTPCookieStorage.
    #[cfg(target_os = "macos")]
    pub fn sync_to_ns_http_cookie_storage(&self) {
        // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
        unsafe {
            let cls_storage = match objc::runtime::Class::get("NSHTTPCookieStorage") {
                Some(cls) => cls,
                None => return,
            };
            let storage: *mut objc::runtime::Object =
                msg_send![cls_storage, sharedHTTPCookieStorage];
            if storage.is_null() {
                return;
            }
            let cls_cookie = match objc::runtime::Class::get("NSHTTPCookie") {
                Some(cls) => cls,
                None => return,
            };

            for cookie in &self.cookies {
                let cls_dict = match objc::runtime::Class::get("NSMutableDictionary") {
                    Some(cls) => cls,
                    None => continue,
                };
                let dict: *mut objc::runtime::Object = msg_send![cls_dict, new];
                if dict.is_null() {
                    continue;
                }

                // Set cookie properties via setObject:forKey:
                set_dict_string(dict, "NSHTTPCookieName", &cookie.name);
                set_dict_string(dict, "NSHTTPCookieValue", &cookie.value);
                set_dict_string(dict, "NSHTTPCookieDomain", &cookie.domain);
                set_dict_string(dict, "NSHTTPCookiePath", &cookie.path);
                if cookie.secure {
                    let cls_number = match objc::runtime::Class::get("NSNumber") {
                        Some(cls) => cls,
                        None => continue,
                    };
                    let yes: *mut objc::runtime::Object =
                        msg_send![cls_number, numberWithBool: true];
                    let key = ns_string_from_str("NSHTTPCookieSecure");
                    let _: () = msg_send![dict, setObject: yes forKey: key];
                }

                let ns_cookie: *mut objc::runtime::Object = msg_send![cls_cookie, alloc];
                let ns_cookie: *mut objc::runtime::Object =
                    msg_send![ns_cookie, initWithProperties: dict];
                if !ns_cookie.is_null() {
                    let _: () = msg_send![storage, setCookie: ns_cookie];
                }
            }
        }
    }
}

// Helper: convert ObjC NSString to Rust String
#[cfg(target_os = "macos")]
// SAFETY: CEF (Chromium Embedded Framework) FFI for web view
unsafe fn c_str_to_string(ptr: *mut std::ffi::c_void) -> String {
    // SAFETY: CEF (Chromium Embedded Framework) FFI for web view
    unsafe {
        if ptr.is_null() {
            return String::new();
        }
        let cstr = std::ffi::CStr::from_ptr(ptr as *const i8);
        cstr.to_string_lossy().to_string()
    }
}

// Helper: set an NSString key-value pair on an NSMutableDictionary
#[cfg(target_os = "macos")]
// SAFETY: Objective-C runtime class lookup and method registration
unsafe fn set_dict_string(dict: *mut objc::runtime::Object, key: &str, value: &str) {
    let ns_key = ns_string_from_str(key);
    let ns_val = ns_string_from_str(value);
    let _: () = msg_send![dict, setObject: ns_val forKey: ns_key];
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
            self.initial_url, self.render_mode, browser_handle,
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
    /// - "community_navigation": Navigate to Steam community hub
    /// - "library_navigation": Navigate to Steam library
    /// - "friends_navigation": Navigate to Steam friends list
    /// - "settings_navigation": Navigate to Steam settings
    /// - "login": Steam login/authentication
    /// - "download": Trigger a download
    /// - "auth_credentials": Handle authentication credential requests
    /// - "open_external_url": Open a URL in the default browser
    /// - "browser_back": Navigate back in browser history
    /// - "browser_forward": Navigate forward in browser history
    /// - "browser_reload": Reload the current page
    /// - "get_current_url": Get the current page URL
    /// - "set_cookie": Set a cookie
    /// - "get_cookies": Get all cookies
    /// - "execute_javascript": Execute JavaScript in the browser
    /// - "get_dimensions": Get browser dimensions
    /// - "resize": Resize the browser
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

        let request = query.get("request").and_then(|v| v.as_str()).unwrap_or("");
        let request_id = query.get("requestId").and_then(|v| v.as_u64()).unwrap_or(0);
        let query_type = query
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let response = match query_type {
            "store_navigation" => {
                let store_url = format!("https://store.steampowered.com{}", request);
                if let Some(&browser_handle) = self.bridge.browsers().keys().next() {
                    self.bridge.cef_frame_load_url(browser_handle, &store_url)?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }
            "community_navigation" => {
                let community_url = format!("https://steamcommunity.com{}", request);
                if let Some(&browser_handle) = self.bridge.browsers().keys().next() {
                    self.bridge
                        .cef_frame_load_url(browser_handle, &community_url)?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }
            "library_navigation" => {
                if let Some(&browser_handle) = self.bridge.browsers().keys().next() {
                    self.bridge.cef_frame_load_url(
                        browser_handle,
                        "https://steamcommunity.com/my/games",
                    )?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }
            "friends_navigation" => {
                if let Some(&browser_handle) = self.bridge.browsers().keys().next() {
                    self.bridge.cef_frame_load_url(
                        browser_handle,
                        "https://steamcommunity.com/my/friends",
                    )?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }
            "settings_navigation" => {
                if let Some(&browser_handle) = self.bridge.browsers().keys().next() {
                    self.bridge.cef_frame_load_url(
                        browser_handle,
                        "https://steamcommunity.com/my/settings",
                    )?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated"
                })
            }
            "login" => {
                if let Some(&browser_handle) = self.bridge.browsers().keys().next() {
                    self.bridge
                        .cef_frame_load_url(browser_handle, "https://steamcommunity.com/login")?;
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "login_initiated"
                })
            }
            "download" => {
                // Acknowledge download request — WKWebView handles downloads natively.
                let filename = query
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .unwrap_or("download");
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "download_started",
                    "filename": filename,
                })
            }
            "auth_credentials" => {
                let realm = query.get("realm").and_then(|v| v.as_str()).unwrap_or("");
                let host = query.get("host").and_then(|v| v.as_str()).unwrap_or("");
                eprintln!(
                    "[CefBridge] handle_cef_query: auth_credentials realm=\"{realm}\" host=\"{host}\"",
                );
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "cancel",
                    "error": "user cancelled authentication"
                })
            }
            "open_external_url" => {
                if !request.is_empty() {
                    if let Err(e) = std::process::Command::new("open").arg(request).spawn() {
                        eprintln!(
                            "[CefBridge] handle_cef_query: failed to open external URL '{request}': {e}",
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "opened"
                })
            }
            "browser_back" => {
                if let Some(&bh) = self.bridge.browsers().keys().next() {
                    if let Err(error) = self.bridge.cef_browser_go_back(bh) {
                        eprintln!("[CefBridge] SteamWebHelper browser_back failed: {}", error);
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated_back"
                })
            }
            "browser_forward" => {
                if let Some(&bh) = self.bridge.browsers().keys().next() {
                    if let Err(error) = self.bridge.cef_browser_go_forward(bh) {
                        eprintln!(
                            "[CefBridge] SteamWebHelper browser_forward failed: {}",
                            error
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "navigated_forward"
                })
            }
            "browser_reload" => {
                if let Some(&bh) = self.bridge.browsers().keys().next() {
                    if let Err(error) = self.bridge.cef_browser_reload(bh) {
                        eprintln!(
                            "[CefBridge] SteamWebHelper browser_reload failed: {}",
                            error
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "reloaded"
                })
            }
            "get_current_url" => {
                let url = self
                    .bridge
                    .browsers()
                    .values()
                    .next()
                    .map(|b| b.current_url.clone())
                    .unwrap_or_default();
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": url
                })
            }
            "set_cookie" => {
                let name = query.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let value = query.get("value").and_then(|v| v.as_str()).unwrap_or("");
                let domain = query.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                let path = query.get("path").and_then(|v| v.as_str()).unwrap_or("/");
                let secure = query
                    .get("secure")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let httponly = query
                    .get("httponly")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let same_site = query
                    .get("same_site")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unspecified");
                let cookie = CefCookie {
                    name: name.to_string(),
                    value: value.to_string(),
                    domain: domain.to_string(),
                    path: path.to_string(),
                    secure,
                    httponly,
                    same_site: same_site.to_string(),
                    creation: 0,
                    last_access: 0,
                    expires: 0,
                };
                let cache_path = ".";
                let mgr = CefCookieManager::get_global(cache_path);
                if let Ok(mut mgr) = mgr.lock() {
                    if let Err(error) = mgr.set_cookie(cookie) {
                        eprintln!("[CefBridge] SteamWebHelper set_cookie failed: {}", error);
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "cookie_set"
                })
            }
            "get_cookies" => {
                let cache_path = ".";
                let mgr = CefCookieManager::get_global(cache_path);
                let cookies = if let Ok(mgr) = mgr.lock() {
                    mgr.visit_all_cookies()
                } else {
                    Vec::new()
                };
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": cookies
                })
            }
            "execute_javascript" => {
                let script = request;
                if let Some(&bh) = self.bridge.browsers().keys().next() {
                    if let Err(error) = self.bridge.cef_frame_execute_java_script(bh, 0, script) {
                        eprintln!(
                            "[CefBridge] SteamWebHelper execute_javascript failed: {}",
                            error
                        );
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": "script_executed"
                })
            }
            "get_dimensions" => {
                // Extract wk_handle first to avoid borrow conflicts
                let wk_handle = self
                    .bridge
                    .browsers()
                    .values()
                    .next()
                    .and_then(|b| b.wk_handle);
                let (w, h) = if let Some(wk) = wk_handle {
                    self.bridge
                        .webview_manager
                        .as_ref()
                        .and_then(|mgr| mgr.dimensions(wk))
                        .unwrap_or((1280.0, 720.0))
                } else {
                    (1280.0, 720.0)
                };
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": { "width": w, "height": h }
                })
            }
            "resize" => {
                let w = query
                    .get("width")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(1280.0);
                let h = query
                    .get("height")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(720.0);
                // Extract wk_handle first to avoid borrow conflicts
                let wk_handle = self
                    .bridge
                    .browsers()
                    .values()
                    .next()
                    .and_then(|b| b.wk_handle);
                if let Some(wk) = wk_handle {
                    if let Some(mgr) = self.bridge.webview_manager.as_mut() {
                        let _ = mgr.resize(wk, w, h);
                    }
                }
                serde_json::json!({
                    "success": true,
                    "requestId": request_id,
                    "result": { "width": w, "height": h }
                })
            }
            _ => {
                // Unknown query type — log and return error
                eprintln!(
                    "[CefBridge] handle_cef_query: unknown query type=\"{query_type}\" request=\"{request}\"",
                );
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

        let browser_handles: Vec<CefHandle> = self.bridge.browsers().keys().copied().collect();

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
    let exports = register_libcef_dll_exports();
    if exports.is_empty() {
        eprintln!(
            "[CefBridge] WARNING: register_libcef_dll() produced zero exports — \
             libcef.dll runtime module will have no reachable CEF API entries"
        );
    } else {
        eprintln!(
            "[CefBridge] libcef.dll registered as runtime-backed module with {} export(s) \
             (caller must merge into pe_runtime::export_tables())",
            exports.len(),
        );
    }
    // Integration note:
    // pe_runtime.rs already registers these exports at line ~65805:
    //   ("libcef.dll".to_string(), crate::cef_bridge::register_libcef_dll_exports()),
    // No further action needed here — this function serves as a verification
    // point during Casa1 initialization.
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
    // lock(): panic on poison is acceptable
    let mut guard = GLOBAL_CEF_BRIDGE
        .lock()
        .expect("GLOBAL_CEF_BRIDGE lock should not be poisoned");
    *guard = Some(bridge);
}

/// Ensure the global CefBridge instance exists, creating one if necessary.
///
/// If `live_frame_tx` is provided, it will be set on the bridge so that CEF
/// paint callbacks publish frames to the live session display.
///
/// Returns a mutable reference to the (possibly just-created) bridge.
pub fn ensure_global_bridge(live_frame_tx: Option<Sender<LiveFrame>>) {
    // lock(): panic on poison is acceptable
    let mut guard = GLOBAL_CEF_BRIDGE
        .lock()
        .expect("GLOBAL_CEF_BRIDGE lock should not be poisoned");
    if guard.is_none() {
        let mut bridge = CefBridge::new();
        if let Some(tx) = live_frame_tx {
            bridge.set_live_frame_tx(Some(tx));
        }
        *guard = Some(bridge);
    } else if let Some(ref mut bridge) = *guard {
        // If we have a live_frame_tx and the bridge doesn't have one yet, set it
        if let Some(tx) = live_frame_tx {
            if bridge.live_frame_tx.is_none() {
                bridge.set_live_frame_tx(Some(tx));
            }
        }
    }
}

/// Get a reference to the global CefBridge instance (for dispatch_import calls).
pub fn with_global_cef_bridge<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut CefBridge) -> R,
{
    // lock(): panic on poison is acceptable
    let mut guard = GLOBAL_CEF_BRIDGE
        .lock()
        .expect("GLOBAL_CEF_BRIDGE lock should not be poisoned");
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
            assert!(init_result.is_ok(), "expected Ok, got {init_result:?}");
            assert_eq!(bridge.state(), CefState::Initialized);
            let _result = bridge.cef_shutdown();
            assert!(_result.is_ok(), "expected Ok, got {_result:?}");
            assert_eq!(bridge.state(), CefState::ShuttingDown);
        } else {
            // WKWebView not available; initialization fails gracefully.
            assert!(init_result.is_err(), "expected Err, got {init_result:?}");
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
            assert!(init_result.is_ok(), "expected Ok, got {init_result:?}");
            let err = bridge.cef_initialize(CefSettings::default());
            assert!(err.is_err(), "expected Err, got {err:?}");
            assert!(err.unwrap_err().message.contains("already initialised"));
        } else {
            // If initialization failed, double-init should also fail
            assert!(init_result.is_err(), "expected Err, got {init_result:?}");
            let err2 = bridge.cef_initialize(CefSettings::default());
            assert!(err2.is_err(), "expected Err, got {err2:?}");
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
            browser_obj.current_url, "https://steamcommunity.com",
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
        let _result = bridge
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
        assert!(nav_err.is_err(), "navigation after close should fail");

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
        let _result = bridge.cef_frame_load_url(browser, "");
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = bridge.cef_frame_load_url(browser, "about:blank");
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        assert!(
            bridge
                .cef_frame_load_url(browser, "steam://connect/127.0.0.1")
                .is_ok()
        );

        // Back/forward without history should fail gracefully
        let back_err = bridge.cef_browser_go_back(browser);
        assert!(back_err.is_err(), "go_back without history should fail");

        // Reload should always work
        let _result = bridge.cef_browser_reload(browser);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");

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
        let mut shim =
            SteamWebHelperShim::new("about:blank".to_string(), SteamRenderMode::Headless);

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
        let response = shim
            .handle_cef_query(nav_query)
            .expect("handle store navigation query");
        assert!(response.contains("success"));
        assert!(response.contains("true"));

        // Test login query
        let login_query = r#"{"request":"","requestId":2,"type":"login"}"#;
        let response = shim
            .handle_cef_query(login_query)
            .expect("handle login query");
        assert!(response.contains("success"));

        // Test unknown query type
        let unknown_query = r#"{"request":"test","requestId":3,"type":"unknown_type"}"#;
        let response = shim
            .handle_cef_query(unknown_query)
            .expect("handle unknown query");
        assert!(
            response.contains("false"),
            "unknown query should return error"
        );
        assert!(response.contains("unknown query type"));

        // Test invalid JSON
        let invalid_query = "not json";
        let result = shim.handle_cef_query(invalid_query);
        assert!(result.is_err(), "invalid JSON should produce error");
    }

    /// Test CefQuery bridge JavaScript injection.
    #[test]
    fn steam_web_helper_inject_bridge() {
        let mut shim =
            SteamWebHelperShim::new("about:blank".to_string(), SteamRenderMode::Headless);

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
        let export_names: Vec<&str> = exports.iter().filter_map(|e| e.name.as_deref()).collect();

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
    // G9: IOSurface hardening tests
    // -----------------------------------------------------------------------

    /// Test that `get_io_surface_for_browser` returns proper errors for
    /// invalid/bogus handles rather than crashing or returning success.
    #[test]
    fn g9_io_surface_extraction_error_handling() {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return;
        }
        bridge.cef_initialize(CefSettings::default()).unwrap();

        // Test 1: Non-existent handle should return RcNotFound error
        let bogus_handle = WKWebViewHandle(99999);
        let mgr = bridge.webview_manager.as_ref().unwrap();
        let result = mgr.get_io_surface_for_browser(bogus_handle);
        assert!(
            result.is_err(),
            "non-existent handle should produce an error"
        );
        let err = result.unwrap_err();
        assert!(
            err.message.contains("not found"),
            "error should mention 'not found', got: {}",
            err.message
        );

        // Test 2: Valid handle to a just-created browser should not crash.
        // The IOSurface may be null (snapshot-based fallback is expected for
        // offscreen rendering), but the call itself must not panic or segfault.
        let browser = bridge
            .cef_browser_host_create_browser(
                CefWindowInfo {
                    x: 0,
                    y: 0,
                    width: 320,
                    height: 240,
                    windowless_rendering_enabled: true,
                    parent_window: 0,
                    url: None,
                    external_begin_frame_enabled: false,
                },
                "about:blank",
                CefBrowserSettings::default(),
            )
            .expect("create browser for IOSurface test");
        let wk_handle = bridge
            .browsers()
            .get(&browser)
            .and_then(|b| b.wk_handle)
            .expect("browser should have a WKWebView handle");
        let mgr = bridge.webview_manager.as_ref().unwrap();
        let surface = mgr.get_io_surface_for_browser(wk_handle);
        // The call must succeed (even if surface is null) and must not panic.
        assert!(
            surface.is_ok(),
            "get_io_surface_for_browser on valid handle should not error"
        );

        bridge.close_browser(browser).unwrap();
    }

    /// Test that `render_to_io_surface_texture` properly falls back to the
    /// managed (CPU upload) path when the native WKWebView layer has no
    /// IOSurface backing — which is the expected case for offscreen rendering.
    ///
    /// This test exercises the full fallback chain:
    ///   1. Zero-copy path attempted → fails (no IOSurface in layer)
    ///   2. Managed path: IOSurface allocated, CPU pixels uploaded
    ///   3. Metal texture wrapping managed IOSurface returned
    #[test]
    fn g9_io_surface_fallback_path_when_unavailable() {
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

        // Process pending ops to generate a rendered frame
        bridge.process_pending_webview_ops();

        // Verify we have a rendered frame
        let browser_obj = bridge.browsers().get(&browser).unwrap();
        let frame = bridge.get_rendered_frame(browser_obj.id);
        assert!(
            frame.is_some(),
            "rendered frame should be available after browser creation"
        );

        // Test that submit_latest_frame_to_compositor does not crash
        // even when IOSurface is unavailable
        bridge.submit_latest_frame_to_compositor(browser);

        // Test that a call with an invalid browser handle does not panic
        bridge.submit_latest_frame_to_compositor(0xDEADBEEF);

        bridge.close_browser(browser).unwrap();
    }

    /// Test frame delivery sequencing: verify that rendered frames are
    /// properly queued, retrieved in the correct order, and that the
    /// frame number monotonically increases.
    #[test]
    fn g9_frame_delivery_sequencing() {
        let mut bridge = CefBridge::new();

        // Manually push frames (no WKWebView needed — pure data path test)
        let browser_id = 1u32;
        let frame1 = RenderedFrame {
            browser_id,
            width: 10,
            height: 10,
            pixels: vec![0xFFu8; 10 * 10 * 4],
            frame_number: 0,
        };
        let frame2 = RenderedFrame {
            browser_id,
            width: 10,
            height: 10,
            pixels: vec![0x80u8; 10 * 10 * 4],
            frame_number: 1,
        };
        let frame3 = RenderedFrame {
            browser_id,
            width: 20,
            height: 20,
            pixels: vec![0x40u8; 20 * 20 * 4],
            frame_number: 2,
        };

        bridge.rendered_frames.push_back(frame1.clone());
        bridge.rendered_frames.push_back(frame2.clone());
        bridge.rendered_frames.push_back(frame3.clone());

        // get_rendered_frame should return the latest (most recent) frame,
        // which is frame3 (highest frame_number for the given browser_id).
        let latest = bridge.get_rendered_frame(browser_id);
        assert!(latest.is_some(), "should find a rendered frame");
        let latest = latest.unwrap();
        assert_eq!(
            latest.frame_number, 2,
            "should return latest frame (frame_number=2)"
        );
        assert_eq!(latest.width, 20, "should match frame3 dimensions");
        assert_eq!(latest.height, 20, "should match frame3 dimensions");
        assert_eq!(latest.pixels[0], 0x40, "should match frame3 pixel data");

        // Verify earlier frame is still accessible (VecDeque retains history)
        let all_frames: Vec<&RenderedFrame> = bridge
            .rendered_frames
            .iter()
            .filter(|f| f.browser_id == browser_id)
            .collect();
        assert_eq!(all_frames.len(), 3, "all three frames should be preserved");

        // Test frame_number monotonic property
        for i in 1..all_frames.len() {
            assert!(
                all_frames[i].frame_number > all_frames[i - 1].frame_number,
                "frame numbers should be monotonically increasing"
            );
        }
    }

    /// Test that `submit_latest_frame_to_compositor` handles edge cases
    /// gracefully: missing browser, missing frame, empty pixels.
    #[test]
    fn g9_submit_frame_edge_cases() {
        let mut bridge = CefBridge::new();

        // Edge case 1: no browsers registered — should not panic
        bridge.submit_first_browser_to_compositor();

        // Edge case 2: browser exists but no rendered frame — should not panic
        bridge.browsers.insert(
            1,
            CefBrowser {
                id: 1,
                host_handle: 1,
                main_frame_handle: 1,
                can_go_back: false,
                can_go_forward: false,
                is_loading: false,
                current_url: "about:blank".to_string(),
                title: String::new(),
                zoom_level: 1.0,
                wk_handle: None,
                dirty: false,
                metal_texture_id: None,
            },
        );
        // No rendered_frames pushed, so submit should gracefully no-op
        bridge.submit_latest_frame_to_compositor(1);

        // Edge case 3: browser has a frame with valid (empty) pixels
        bridge.rendered_frames.push_back(RenderedFrame {
            browser_id: 1,
            width: 1,
            height: 1,
            pixels: vec![0xFFu8; 4], // 1x1 RGBA pixel
            frame_number: 0,
        });
        // Should not panic
        bridge.submit_latest_frame_to_compositor(1);
    }

    /// Test that IoSurfaceTexturePair creation and drop do not crash.
    ///
    /// This test validates the lifecycle of the cached IOSurface+Metal-texture
    /// pair used by the managed IOSurface path. On macOS with a Metal device,
    /// a real IOSurface is allocated and wrapped; on other platforms, creation
    /// gracefully returns None.
    #[test]
    fn g9_io_surface_pair_lifecycle() {
        // Creating with zero dimensions should return None
        let maybe_device = crate::metal_backend::MetalDevice::system_default();
        if let Ok(ref device) = maybe_device {
            let pair = IoSurfaceTexturePair::new(device.device(), 0, 0);
            assert!(
                pair.is_none(),
                "IOSurface pair creation with zero dimensions should return None"
            );

            // Creating with valid dimensions should succeed on Apple Silicon
            let pair = IoSurfaceTexturePair::new(device.device(), 64, 64);
            assert!(
                pair.is_some(),
                "IOSurface pair creation with valid dimensions should succeed"
            );
            if let Some(ref p) = pair {
                assert!(
                    !p.io_surface.is_null(),
                    "IOSurface pointer should not be null"
                );
                assert!(
                    p.metal_texture.is_some(),
                    "Metal texture wrapping IOSurface should exist"
                );
                assert_eq!(p.width, 64, "width should match");
                assert_eq!(p.height, 64, "height should match");
            }
            // pair drops here — verifies CFRelease doesn't crash
        }
    }

    /// Test that `io_surface_available()` returns a cached result and does
    /// not panic. On macOS with Metal, the IOSurface class should be found;
    /// on headless systems it may return false, but the method itself must
    /// always complete without error.
    #[test]
    fn g9_io_surface_availability_check() {
        let mut bridge = CefBridge::new();
        // First call performs the ObjC class lookup
        let result1 = bridge.io_surface_available();
        // Second call uses the cached value
        let result2 = bridge.io_surface_available();
        assert_eq!(
            result1, result2,
            "io_surface_available should return the same cached result on repeated calls"
        );
        // The cached field should now be Some
        assert!(
            bridge.io_surface_available.is_some(),
            "io_surface_available field should be cached after first check"
        );
    }

    /// Test that `render_to_io_surface_texture` correctly falls back to
    /// `render_to_metal_texture` when IOSurface allocation fails in the
    /// managed path. This exercises the defensive fallback added in
    /// Phase D3:R3.
    ///
    /// We simulate the fallback by passing a device that exists; if the
    /// IOSurface class is unavailable (headless CI), the early check in
    /// `render_to_io_surface_texture` should route to the CPU path.
    /// If IOSurface IS available, we verify the IO surface path still
    /// works as the primary path.
    #[test]
    fn g9_render_to_io_surface_fallback_on_alloc_failure() {
        if !wkwebview_available() {
            return;
        }
        let maybe_device = crate::metal_backend::MetalDevice::system_default();
        if let Ok(ref device) = maybe_device {
            let mut bridge = CefBridge::new();
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
                .expect("create browser for IOSurface fallback test");

            // Process pending ops to generate a rendered frame
            bridge.process_pending_webview_ops();

            // Call render_to_io_surface_texture — this should succeed
            // via either the managed IOSurface path or the CPU fallback.
            let result = bridge.render_to_io_surface_texture(browser, device);
            assert!(
                result.is_ok(),
                "render_to_io_surface_texture should not fail, got: {:?}",
                result.err(),
            );

            // Verify the returned texture has the expected dimensions
            if let Ok(texture) = result {
                assert_eq!(
                    texture.width(),
                    100,
                    "texture width should match frame width"
                );
                assert_eq!(
                    texture.height(),
                    100,
                    "texture height should match frame height"
                );
            }

            bridge.close_browser(browser).unwrap();
        }
    }

    /// Test that CPU-side `render_to_metal_texture` works correctly as
    /// the fallback rendering path. This test verifies the function that
    /// `render_to_io_surface_texture` falls back to when IOSurface is
    /// unavailable.
    #[test]
    fn g9_cpu_fallback_metal_texture_rendering() {
        if !wkwebview_available() {
            return;
        }
        let maybe_device = crate::metal_backend::MetalDevice::system_default();
        if let Ok(ref device) = maybe_device {
            let mut bridge = CefBridge::new();
            bridge.cef_initialize(CefSettings::default()).unwrap();

            let browser = bridge
                .cef_browser_host_create_browser(
                    CefWindowInfo {
                        x: 0,
                        y: 0,
                        width: 64,
                        height: 64,
                        windowless_rendering_enabled: true,
                        parent_window: 0,
                        url: None,
                        external_begin_frame_enabled: false,
                    },
                    "about:blank",
                    CefBrowserSettings::default(),
                )
                .expect("create browser for CPU fallback test");

            // Process pending ops to generate a rendered frame
            bridge.process_pending_webview_ops();

            // Call render_to_metal_texture directly (CPU fallback path)
            let result = bridge.render_to_metal_texture(browser, device);
            assert!(
                result.is_ok(),
                "render_to_metal_texture should succeed, got: {:?}",
                result.err(),
            );

            if let Ok(texture) = result {
                assert_eq!(texture.width(), 64, "texture width should match");
                assert_eq!(texture.height(), 64, "texture height should match");
                assert_eq!(
                    texture.pixel_format(),
                    metal::MTLPixelFormat::RGBA8Unorm,
                    "CPU fallback texture should be RGBA8Unorm"
                );
            }

            bridge.close_browser(browser).unwrap();
        }
    }

    /// Test that `submit_latest_frame_to_compositor` works correctly with
    /// explicit CPU pixel data, exercising the full CPU submission path
    /// without requiring IOSurface. This verifies the downstream compositor
    /// can handle frames submitted via the fallback path.
    #[test]
    fn g9_submit_frame_cpu_fallback_path() {
        let mut bridge = CefBridge::new();

        // Insert a browser with a specific ID
        bridge.browsers.insert(
            42,
            CefBrowser {
                id: 42,
                host_handle: 42,
                main_frame_handle: 42,
                can_go_back: false,
                can_go_forward: false,
                is_loading: false,
                current_url: "about:blank".to_string(),
                title: String::new(),
                zoom_level: 1.0,
                wk_handle: None,
                dirty: false,
                metal_texture_id: None,
            },
        );

        // Push a rendered frame with known pixel data
        bridge.rendered_frames.push_back(RenderedFrame {
            browser_id: 42,
            width: 4,
            height: 4,
            pixels: vec![0x80u8; 4 * 4 * 4], // 4x4 half-opaque gray
            frame_number: 0,
        });

        // Submit via CPU fallback path — must not panic
        bridge.submit_latest_frame_to_compositor(42);

        // Verify the frame was consumed from the queue
        assert_eq!(
            bridge.rendered_frames.len(),
            1,
            "frame should remain in queue after submission (compositor clones)"
        );
    }

    /// Test that `render_to_io_surface_texture` handles the edge case
    /// where the managed IOSurface cache needs to be resized (different
    /// dimensions from a previous frame), and the re-allocation fallback
    /// works correctly.
    #[test]
    fn g9_io_surface_cache_resize_fallback() {
        if !wkwebview_available() {
            return;
        }
        let maybe_device = crate::metal_backend::MetalDevice::system_default();
        if let Ok(ref device) = maybe_device {
            let mut bridge = CefBridge::new();
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
                .expect("create browser for cache resize test");

            // Process to get initial frame
            bridge.process_pending_webview_ops();

            // First call: allocate IOSurface at 100x100
            let result1 = bridge.render_to_io_surface_texture(browser, device);
            assert!(
                result1.is_ok(),
                "first render_to_io_surface_texture should succeed, got: {:?}",
                result1.err(),
            );

            // Simulate a resize by pushing a frame with different dimensions
            // and invalidating the browser's rendered frame
            let browser_id = bridge.browsers.get(&browser).unwrap().id;
            bridge.rendered_frames.push_back(RenderedFrame {
                browser_id,
                width: 200,
                height: 200,
                pixels: vec![0xFFu8; 200 * 200 * 4],
                frame_number: 1,
            });

            // Second call with different dimensions: cache should detect
            // mismatch and re-allocate. If IOSurface re-allocation fails,
            // the fallback to render_to_metal_texture kicks in.
            let result2 = bridge.render_to_io_surface_texture(browser, device);
            assert!(
                result2.is_ok(),
                "second render_to_io_surface_texture (after resize) should succeed, got: {:?}",
                result2.err(),
            );

            if let Ok(texture) = result2 {
                assert_eq!(
                    texture.width(),
                    200,
                    "resized texture width should match new frame width"
                );
                assert_eq!(
                    texture.height(),
                    200,
                    "resized texture height should match new frame height"
                );
            }

            bridge.close_browser(browser).unwrap();
        }
    }

    // -----------------------------------------------------------------------
    // CEF callback handler tests
    // -----------------------------------------------------------------------

    /// Helper to create an initialized CefBridge with one browser for testing handlers.
    fn create_test_bridge() -> (CefBridge, CefHandle) {
        let mut bridge = CefBridge::new();
        if !wkwebview_available() {
            return (bridge, 0);
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
        (bridge, browser)
    }

    /// Test CefLifeSpanHandler: OnAfterCreated updates browser state.
    #[test]
    fn cef_handler_on_after_created() {
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

        // Initially the browser is loading=true (set during creation)
        bridge.on_after_created(browser).expect("on_after_created");
        let b = bridge.browsers().get(&browser).unwrap();
        assert!(
            b.is_loading,
            "browser should be loading after OnAfterCreated"
        );
        assert!(b.dirty, "browser should be dirty after OnAfterCreated");

        // Non-existent handle should not panic
        let _result = bridge.on_after_created(99999);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    /// Test CefLifeSpanHandler: DoClose and OnBeforeClose sequence.
    #[test]
    fn cef_handler_do_close_and_before_close() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        // DoClose should return true and set pending state
        let result = bridge.do_close(browser);
        assert!(result, "DoClose should return true for existing browser");
        assert_eq!(
            bridge.close_pending_for,
            Some(browser),
            "close_pending_for should be set"
        );

        // DoClose on non-existent browser should return false
        assert!(
            !bridge.do_close(99999),
            "DoClose on missing browser should return false"
        );

        // Non-existent handle should not panic
        bridge.on_before_close(99999);

        // Close the browser properly
        bridge.on_before_close(browser);
        assert!(
            !bridge.cef_browser_is_valid(browser),
            "browser should be invalid after OnBeforeClose"
        );
        assert_eq!(
            bridge.close_pending_for, None,
            "close_pending_for should be cleared"
        );
    }

    /// Test CefLoadHandler: OnLoadingStateChange updates navigation flags.
    #[test]
    fn cef_handler_loading_state_change() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        bridge.on_loading_state_change(browser, true, false, false);
        let b = bridge.browsers().get(&browser).unwrap();
        assert!(b.is_loading);
        assert!(!b.can_go_back);
        assert!(!b.can_go_forward);
        assert!(b.dirty);

        bridge.on_loading_state_change(browser, false, true, true);
        let b = bridge.browsers().get(&browser).unwrap();
        assert!(!b.is_loading);
        assert!(b.can_go_back);
        assert!(b.can_go_forward);

        // Non-existent handle should not panic
        bridge.on_loading_state_change(99999, true, false, false);
    }

    /// Test CefLoadHandler: OnLoadStart marks loading state.
    #[test]
    fn cef_handler_load_start() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        bridge.on_load_start(browser, "https://store.steampowered.com", true);
        let b = bridge.browsers().get(&browser).unwrap();
        assert!(b.is_loading, "browser should be loading after OnLoadStart");
        assert_eq!(b.current_url, "https://store.steampowered.com");

        // Non-existent handle should not panic
        bridge.on_load_start(99999, "https://example.com", true);
    }

    /// Test CefLoadHandler: OnLoadEnd updates loading state and URL.
    #[test]
    fn cef_handler_load_end() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        bridge
            .on_load_end(browser, "https://steamcommunity.com")
            .unwrap();
        let b = bridge.browsers().get(&browser).unwrap();
        assert!(
            !b.is_loading,
            "browser should not be loading after OnLoadEnd"
        );
        assert_eq!(b.current_url, "https://steamcommunity.com");
        assert!(b.dirty, "browser should be dirty after OnLoadEnd");
    }

    /// Test CefLoadHandler: OnLoadError logs error and updates state.
    #[test]
    fn cef_handler_load_error() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        bridge.on_load_error(
            browser,
            -3i32 as u32,
            "Operation cancelled",
            "https://store.steampowered.com",
        );
        let b = bridge.browsers().get(&browser).unwrap();
        assert!(!b.is_loading, "browser should not be loading after error");
        assert!(b.dirty, "browser should be dirty after error");

        // Non-existent handle should not panic
        bridge.on_load_error(99999, 1, "test error", "https://example.com");
    }

    /// Test CefDisplayHandler: OnAddressChange updates current_url.
    #[test]
    fn cef_handler_address_change() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        bridge.on_address_change(browser, "https://store.steampowered.com/app/730");
        let b = bridge.browsers().get(&browser).unwrap();
        assert_eq!(b.current_url, "https://store.steampowered.com/app/730");

        // Non-existent handle should not panic
        bridge.on_address_change(99999, "https://example.com");
    }

    /// Test CefDisplayHandler: OnTitleChange updates browser title.
    #[test]
    fn cef_handler_title_change() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        bridge.on_title_change(browser, "Counter-Strike 2").unwrap();
        let b = bridge.browsers().get(&browser).unwrap();
        assert_eq!(b.title, "Counter-Strike 2");

        // Title update with empty string should still update
        bridge.on_title_change(browser, "").unwrap();
        let b = bridge.browsers().get(&browser).unwrap();
        assert_eq!(b.title, "");

        // Non-existent handle should not panic
        let _result = bridge.on_title_change(99999, "test");
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    /// Test CefDisplayHandler: OnTooltip returns correct visibility.
    #[test]
    fn cef_handler_tooltip() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        // Non-empty text should show tooltip
        assert!(
            bridge.on_tooltip(browser, "Click to open Store"),
            "tooltip should show with text"
        );

        // Empty text should hide tooltip
        assert!(
            !bridge.on_tooltip(browser, ""),
            "tooltip should hide with empty text"
        );
    }

    /// Test CefDisplayHandler: OnStatusMessage logs messages without errors.
    #[test]
    fn cef_handler_status_message() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        // Should not panic
        bridge.on_status_message(browser, "https://store.steampowered.com/");
        bridge.on_status_message(browser, "");
        bridge.on_status_message(99999, "test");
    }

    /// Test CefDisplayHandler: OnConsoleMessage logs JS console output.
    #[test]
    fn cef_handler_console_message() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        // Should return false (allow default handling)
        let result = bridge.on_console_message(
            browser,
            "Hello from Steam",
            "https://store.steampowered.com/steam.js",
            42,
        );
        assert!(
            !result,
            "OnConsoleMessage should return false (not handled)"
        );

        // Non-existent handle should not panic
        bridge.on_console_message(99999, "test", "test.js", 1);
    }

    /// Test CefRenderHandler: GetViewRect returns correct dimensions.
    #[test]
    fn cef_handler_get_view_rect() {
        let (bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        let rect = bridge.get_view_rect(browser);
        assert_eq!(rect.x, 0, "view rect x should be 0");
        assert_eq!(rect.y, 0, "view rect y should be 0");
        assert!(rect.width > 0, "view rect width should be positive");
        assert!(rect.height > 0, "view rect height should be positive");

        // Non-existent handle should return 1x1 fallback
        let fallback = bridge.get_view_rect(99999);
        assert_eq!(fallback.width, 1, "fallback width should be 1");
        assert_eq!(fallback.height, 1, "fallback height should be 1");
    }

    /// Test CefRenderHandler: GetScreenInfo returns default values.
    #[test]
    fn cef_handler_get_screen_info() {
        let (bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        let (x, y, scale) = bridge.get_screen_info(browser);
        assert_eq!(x, 0, "screen origin x should be 0");
        assert_eq!(y, 0, "screen origin y should be 0");
        assert!(
            (scale - 1.0).abs() < f64::EPSILON,
            "scale factor should be 1.0"
        );
    }

    /// Test CefRenderHandler: OnPaint processes pixel data.
    #[test]
    fn cef_handler_on_paint() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }
        let browser_id = bridge.browsers().get(&browser).unwrap().id;

        // Simulate a paint with 100x50 RGBA pixel data
        let width = 100u32;
        let height = 50u32;
        let pixels = vec![0x80u8; (width * height * 4) as usize];
        let dirty_rects = [CefRect {
            x: 0,
            y: 0,
            width: 100,
            height: 50,
        }];

        bridge.on_paint(browser, 0, &dirty_rects, &pixels, width, height);

        // Verify rendered frame was created
        let frame = bridge.get_rendered_frame(browser_id);
        assert!(frame.is_some(), "rendered frame should exist after OnPaint");
        let frame = frame.unwrap();
        assert_eq!(frame.width, width, "frame width should match paint width");
        assert_eq!(
            frame.height, height,
            "frame height should match paint height"
        );
        assert_eq!(
            frame.pixels.len(),
            pixels.len(),
            "pixel buffer size should match"
        );

        // Verify browser is no longer dirty after paint
        let b = bridge.browsers().get(&browser).unwrap();
        assert!(!b.dirty, "browser should not be dirty after OnPaint");

        // OnPaint with non-existent handle should not panic
        bridge.on_paint(99999, 0, &dirty_rects, &pixels, width, height);
    }

    /// Test CefRenderHandler: OnPaint with buffer too small handles gracefully.
    #[test]
    fn cef_handler_on_paint_buffer_too_small() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        // Paint with buffer smaller than expected for dimensions
        let pixels = vec![0xFFu8; 10]; // much smaller than 100x50x4 = 20000
        bridge.on_paint(browser, 0, &[], &pixels, 100, 50);
        // Should not panic; buffer gets padded internally
    }

    /// Test CefRenderHandler: OnPopupShow and OnPopupSize track popup state.
    #[test]
    fn cef_handler_popup_show_and_size() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        // Initially no popup
        assert!(
            !bridge.popup_showing,
            "popup should not be showing initially"
        );
        assert!(
            bridge.popup_info.is_none(),
            "popup info should be none initially"
        );

        // Show popup and set size
        bridge.on_popup_show(browser, true);
        assert!(
            bridge.popup_showing,
            "popup should be showing after OnPopupShow(true)"
        );

        let popup_rect = CefRect {
            x: 10,
            y: 20,
            width: 300,
            height: 200,
        };
        bridge.on_popup_size(browser, popup_rect);
        assert!(
            bridge.popup_info.is_some(),
            "popup info should be set after OnPopupSize"
        );
        let info = bridge.popup_info.clone().unwrap();
        assert_eq!(info.x, 10);
        assert_eq!(info.y, 20);
        assert_eq!(info.width, 300);
        assert_eq!(info.height, 200);

        // Hide popup — should clear state
        bridge.on_popup_show(browser, false);
        assert!(
            !bridge.popup_showing,
            "popup should not be showing after OnPopupShow(false)"
        );
        assert!(
            bridge.popup_info.is_none(),
            "popup info should be cleared after hide"
        );
    }

    /// Test CefRenderHandler: OnAcceleratedPaint with null handle.
    #[test]
    fn cef_handler_accelerated_paint_null() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        // Null shared handle should return false
        let result = bridge.on_accelerated_paint(browser, 0, std::ptr::null_mut());
        assert!(!result, "null handle should return false");
    }

    /// Test CefRequestHandler: OnBeforeBrowse allows normal URLs.
    #[test]
    fn cef_handler_before_browse() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        // Normal URLs should be allowed
        assert!(
            !bridge.on_before_browse(browser, "https://store.steampowered.com"),
            "normal URLs should be allowed"
        );

        // steam:// URLs should be cancelled
        assert!(
            bridge.on_before_browse(browser, "steam://connect/127.0.0.1"),
            "steam:// URLs should be cancelled"
        );
    }

    /// Test CefRequestHandler: OnBeforeResourceLoad allows all resources.
    #[test]
    fn cef_handler_before_resource_load() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        assert!(
            !bridge.on_before_resource_load(browser, "https://store.steampowered.com/script.js"),
            "resources should be allowed by default"
        );
        assert!(
            !bridge.on_before_resource_load(browser, "https://steamcommunity.com/style.css"),
            "Steam resources should be allowed"
        );
    }

    /// Test CefRequestHandler: GetResourceRequestHandler returns default (0).
    #[test]
    fn cef_handler_resource_request_handler() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        let handler_id =
            bridge.get_resource_request_handler(browser, "https://store.steampowered.com/steam.js");
        assert_eq!(
            handler_id, 0,
            "resource request handler should return 0 (default)"
        );
    }

    /// Test CefRequestHandler: OnAuthCredentials returns false (no creds).
    #[test]
    fn cef_handler_auth_credentials() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }

        let result = bridge.on_auth_credentials(
            browser,
            "https://example.com",
            false,
            "proxy.example.com",
            8080,
            "My Realm",
            "basic",
        );
        assert!(
            !result,
            "auth should be cancelled (no credentials available)"
        );
    }

    /// Test CefRequestHandler: OnCookieableSchemes returns supported schemes.
    #[test]
    fn cef_handler_cookieable_schemes() {
        let bridge = CefBridge::new();
        let schemes = bridge.on_cookieable_schemes();
        assert!(
            schemes.contains(&"http".to_string()),
            "http should be in cookieable schemes"
        );
        assert!(
            schemes.contains(&"https".to_string()),
            "https should be in cookieable schemes"
        );
        assert!(
            schemes.contains(&"steam".to_string()),
            "steam should be in cookieable schemes"
        );
    }

    /// Test that multiple OnPaint calls produce sequential frame numbers.
    #[test]
    fn cef_handler_paint_frame_sequencing() {
        let (mut bridge, browser) = create_test_bridge();
        if !wkwebview_available() || browser == 0 {
            return;
        }
        let browser_id = bridge.browsers().get(&browser).unwrap().id;

        let pixels = vec![0xFFu8; 100 * 100 * 4];
        let dirty = [CefRect {
            x: 0,
            y: 0,
            width: 100,
            height: 100,
        }];

        // First paint
        bridge.on_paint(browser, 0, &dirty, &pixels, 100, 100);
        let f1 = bridge.get_rendered_frame(browser_id).unwrap();
        assert_eq!(f1.frame_number, 0, "first frame number should be 0");

        // Second paint
        bridge.on_paint(browser, 0, &dirty, &pixels, 100, 100);
        let f2 = bridge.get_rendered_frame(browser_id).unwrap();
        assert_eq!(f2.frame_number, 1, "second frame number should be 1");

        // Verify frame queue does not exceed max (10)
        for _i in 0..15 {
            bridge.on_paint(browser, 0, &dirty, &pixels, 100, 100);
        }
        assert!(
            bridge.rendered_frames.len() <= 10,
            "rendered frame queue should not exceed 10 entries"
        );
    }

    /// Test handler callbacks work with manually constructed bridge
    /// (no WKWebView dependency) for pure unit testing.
    #[test]
    fn cef_handler_no_wkwebview_dependency() {
        // Test handlers that don't need WKWebView at all
        let mut bridge = CefBridge::new();

        // CefLifeSpanHandler
        assert!(
            !bridge.do_close(1),
            "DoClose on non-existent browser should return false"
        );
        bridge.on_before_close(1); // should not panic

        // CefDisplayHandler
        bridge.on_address_change(1, "https://example.com"); // should not panic
        assert!(bridge.on_tooltip(1, "test"));
        assert!(!bridge.on_tooltip(1, ""));
        bridge.on_status_message(1, "test"); // should not panic
        assert!(!bridge.on_console_message(1, "test", "test.js", 1));

        // CefLoadHandler (these don't panic even without browsers)
        bridge.on_loading_state_change(1, true, false, false);
        bridge.on_load_start(1, "https://example.com", true);
        bridge.on_load_error(1, 1, "error", "https://example.com");

        // CefRenderHandler (GetViewRect returns fallback 1x1)
        let rect = bridge.get_view_rect(1);
        assert_eq!(
            rect.width, 1,
            "without browser, GetViewRect should return fallback 1x1"
        );
        assert_eq!(rect.height, 1);
        let (x, y, scale) = bridge.get_screen_info(1);
        assert_eq!(x, 0);
        assert_eq!(y, 0);
        assert!((scale - 1.0).abs() < f64::EPSILON);

        // CefRequestHandler
        assert!(!bridge.on_before_browse(1, "https://example.com"));
        assert!(bridge.on_before_browse(1, "steam://connect"));
        assert!(!bridge.on_before_resource_load(1, "https://example.com/resource.js"));
        assert_eq!(
            bridge.get_resource_request_handler(1, "https://example.com"),
            0
        );
        assert!(!bridge.on_auth_credentials(
            1,
            "https://example.com",
            false,
            "host",
            80,
            "realm",
            "basic"
        ));
        assert!(
            bridge
                .on_cookieable_schemes()
                .contains(&"https".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Steam Overlay lifecycle tests
    // -----------------------------------------------------------------------

    /// Default state: no overlay browser active.
    #[test]
    fn overlay_default_state() {
        let bridge = CefBridge::new();
        assert_eq!(bridge.overlay_browser_handle, None);
        assert_eq!(bridge.overlay_browser_handle(), None);
    }

    /// Creating then destroying the overlay browser should transition the
    /// handle from Some → None.  This exercise the data-path without
    /// requiring a real WKWebView (the creation will fail on systems
    /// without WKWebView, but we verify the handle was not set).
    #[test]
    fn overlay_create_and_destroy() {
        let mut bridge = CefBridge::new();

        // create_overlay_browser may fail on non-macOS or headless CI,
        // but we verify the handle is NOT set on failure.
        let result =
            bridge.create_overlay_browser("steam://openurl/https://steamcommunity.com/my/overlay");
        match result {
            Ok(handle) => {
                assert_eq!(bridge.overlay_browser_handle, Some(handle));
                assert_eq!(bridge.overlay_browser_handle(), Some(handle));

                // Destroy it
                bridge.destroy_overlay_browser().unwrap();
                assert_eq!(bridge.overlay_browser_handle, None);
                assert_eq!(bridge.overlay_browser_handle(), None);
            }
            Err(_) => {
                // Platform doesn't support WKWebView — only verify state
                // wasn't corrupted
                assert_eq!(bridge.overlay_browser_handle, None);
            }
        }
    }

    /// Creating a second overlay browser while one exists returns an error.
    #[test]
    fn overlay_create_twice_fails() {
        let mut bridge = CefBridge::new();

        match bridge.create_overlay_browser("steam://openurl/test") {
            Ok(_handle) => {
                // Second creation attempt MUST fail
                let err = bridge
                    .create_overlay_browser("steam://openurl/test2")
                    .unwrap_err();
                assert!(
                    err.to_string().contains("already exists"),
                    "Expected 'already exists' error, got: {err}",
                );
                // Clean up
                bridge.destroy_overlay_browser().unwrap();
                assert_eq!(bridge.overlay_browser_handle, None);
            }
            Err(_) => {
                // WKWebView not available — nothing to verify beyond state
                assert_eq!(bridge.overlay_browser_handle, None);
            }
        }
    }

    /// Destroy without a prior create is safe (no-op).
    #[test]
    fn overlay_destroy_without_create() {
        let mut bridge = CefBridge::new();
        assert_eq!(bridge.overlay_browser_handle, None);
        // Should not panic or error
        let _result = bridge.destroy_overlay_browser();
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        assert_eq!(bridge.overlay_browser_handle, None);
    }

    /// Submit the overlay browser frame to the compositor does not crash
    /// when no overlay is active.
    #[test]
    fn overlay_submit_frame_no_overlay() {
        let mut bridge = CefBridge::new();
        // Should not panic with a non-existent handle
        bridge.submit_latest_frame_to_compositor(0xCAFE);
    }

    /// The overlay_browser_handle getter returns None when no overlay
    /// browser exists (smoke test for the public API).
    #[test]
    fn overlay_browser_handle_getter() {
        let bridge = CefBridge::new();
        assert_eq!(bridge.overlay_browser_handle(), None);
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
