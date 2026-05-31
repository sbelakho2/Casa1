// ---------------------------------------------------------------------------
// macOS Real Window Creation — NSWindow / NSView / CAMetalLayer utilities
//
// Provides Objective-C FFI helpers for creating and managing real macOS
// windows backed by NSWindow. Used by user32.rs to materialize Win32 HWNDs
// as native NSWindows, and by metal_backend.rs to attach CAMetalLayers.
// ---------------------------------------------------------------------------

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use std::sync::Mutex;
use std::sync::OnceLock;
use objc::Encode;

// ── Safe raw-pointer wrapper for use in statics ──────────────────────────

/// Wrapper around `*mut c_void` that implements `Send` + `Sync`.
/// SAFETY: Pointers are only accessed behind a `Mutex` and under the
/// assumption that the main thread (or serialised access) handles them.
#[derive(Debug, Clone, Copy)]
struct SafePtr(*mut std::ffi::c_void);
unsafe impl Send for SafePtr {}
unsafe impl Sync for SafePtr {}

impl SafePtr {
    fn null() -> Self {
        Self(std::ptr::null_mut())
    }
    fn as_ptr(self) -> *mut std::ffi::c_void {
        self.0
    }
    fn is_null(self) -> bool {
        self.0.is_null()
    }
}

impl From<*mut std::ffi::c_void> for SafePtr {
    fn from(p: *mut std::ffi::c_void) -> Self {
        Self(p)
    }
}

// ── NSApplication singleton state ────────────────────────────────────────

/// Global NSApplication state: tracks whether `NSApp` has been initialized.
static NSAPP_INITIALIZED: OnceLock<Mutex<bool>> = OnceLock::new();

/// Return whether `NSApp` has been initialized (public accessor for other modules).
pub fn is_nsapp_initialized() -> bool {
    *NSAPP_INITIALIZED
        .get_or_init(|| Mutex::new(false))
        .lock()
        .unwrap()
}

fn nsapp_initialized() -> bool {
    is_nsapp_initialized()
}

fn set_nsapp_initialized(val: bool) {
    *NSAPP_INITIALIZED
        .get_or_init(|| Mutex::new(false))
        .lock()
        .unwrap() = val;
}

/// Global pointer to the shared NSApplication instance.
static SHARED_NSAPP: OnceLock<Mutex<SafePtr>> = OnceLock::new();

fn shared_nsapp() -> Option<*mut std::ffi::c_void> {
    let ptr = SHARED_NSAPP
        .get_or_init(|| Mutex::new(SafePtr::null()))
        .lock()
        .unwrap();
    let p = ptr.as_ptr();
    if p.is_null() { None } else { Some(p) }
}

fn set_shared_nsapp(ptr: *mut std::ffi::c_void) {
    *SHARED_NSAPP
        .get_or_init(|| Mutex::new(SafePtr::null()))
        .lock()
        .unwrap() = SafePtr::from(ptr);
}

/// Global mapping from HWND (u32) to NSWindow pointer, for real window operations.
static HWND_TO_NSWINDOW: OnceLock<Mutex<std::collections::BTreeMap<u32, SafePtr>>> =
    OnceLock::new();

fn hwnd_to_nswindow_map() -> &'static Mutex<std::collections::BTreeMap<u32, SafePtr>> {
    HWND_TO_NSWINDOW
        .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
}

/// Store an NSWindow pointer for a given HWND.
pub fn associate_hwnd_nswindow(hwnd: u32, ns_window: *mut std::ffi::c_void) {
    hwnd_to_nswindow_map().lock().unwrap().insert(hwnd, SafePtr::from(ns_window));
}

/// Retrieve the NSWindow pointer for a given HWND, if any.
pub fn nswindow_for_hwnd(hwnd: u32) -> Option<*mut std::ffi::c_void> {
    hwnd_to_nswindow_map().lock().unwrap().get(&hwnd).map(|s| s.as_ptr())
}

/// Remove the association for a given HWND and return the NSWindow pointer.
pub fn remove_hwnd_nswindow(hwnd: u32) -> Option<*mut std::ffi::c_void> {
    hwnd_to_nswindow_map().lock().unwrap().remove(&hwnd).map(|s| s.as_ptr())
}

// ── NSPoint / NSSize / NSRect structs (mirrored from cef_bridge) ────────

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

unsafe impl objc::Encode for NSPoint {
    fn encode() -> objc::Encoding {
        unsafe { objc::Encoding::from_str("{CGPoint=dd}") }
    }
}

unsafe impl objc::Encode for NSSize {
    fn encode() -> objc::Encoding {
        unsafe { objc::Encoding::from_str("{CGSize=dd}") }
    }
}

unsafe impl objc::Encode for NSRect {
    fn encode() -> objc::Encoding {
        unsafe { objc::Encoding::from_str("{CGRect={CGPoint=dd}{CGSize=dd}}") }
    }
}

// ── NSApplication style masks ────────────────────────────────────────────

/// Maps Win32 window styles to NSWindow style masks.
pub fn map_window_style_to_ns_style(style: u32, _ex_style: u32) -> i32 {
    // NSWindowStyleMask constants
    const NSWindowStyleMaskBorderless: i32 = 0;
    const NSWindowStyleMaskTitled: i32 = 1;
    const NSWindowStyleMaskClosable: i32 = 2;
    const NSWindowStyleMaskMiniaturizable: i32 = 4;
    const NSWindowStyleMaskResizable: i32 = 8;

    // WS_POPUP
    const WS_POPUP: u32 = 0x8000_0000;
    // WS_CHILD
    const WS_CHILD: u32 = 0x4000_0000;
    // WS_CAPTION = WS_BORDER | WS_DLGFRAME
    const WS_CAPTION: u32 = 0x00C0_0000;
    const WS_THICKFRAME: u32 = 0x0004_0000;
    const WS_SYSMENU: u32 = 0x0008_0000;
    const WS_MINIMIZEBOX: u32 = 0x0002_0000;
    const WS_MAXIMIZEBOX: u32 = 0x0001_0000;

    if style & WS_CHILD != 0 {
        // Child windows are borderless views, not real NSWindows
        return NSWindowStyleMaskBorderless;
    }

    if style & WS_POPUP != 0 {
        // Popup windows have a border but are not titled
        return NSWindowStyleMaskTitled | NSWindowStyleMaskClosable;
    }

    // Overlapped windows
    let mut ns_style = NSWindowStyleMaskBorderless;
    if style & WS_CAPTION != 0 {
        ns_style |= NSWindowStyleMaskTitled;
        ns_style |= NSWindowStyleMaskClosable;
    }
    if style & WS_THICKFRAME != 0 {
        ns_style |= NSWindowStyleMaskResizable;
    }
    if style & WS_SYSMENU != 0 {
        ns_style |= NSWindowStyleMaskClosable;
        ns_style |= NSWindowStyleMaskMiniaturizable;
    }
    if style & WS_MINIMIZEBOX != 0 {
        ns_style |= NSWindowStyleMaskMiniaturizable;
    }
    if style & WS_MAXIMIZEBOX != 0 {
        ns_style |= NSWindowStyleMaskResizable;
    }

    ns_style
}

// ── NSApplication initialization ─────────────────────────────────────────

/// Initialize NSApplication with regular activation policy.
/// Should be called once at process startup, before any window creation.
/// Returns true if initialization was successful.
pub fn init_nsapplication() -> bool {
    if nsapp_initialized() {
        return true;
    }

    #[cfg(target_os = "macos")]
    unsafe {
        let cls_app = match objc::runtime::Class::get("NSApplication") {
            Some(c) => c,
            None => return false,
        };

        let shared_app: *mut objc::runtime::Object = msg_send![cls_app, sharedApplication];
        if shared_app.is_null() {
            return false;
        }

        // Set regular activation policy (shows in Dock, menu bar)
        let _: () = msg_send![
            shared_app,
            setActivationPolicy: 0 /* NSApplicationActivationPolicyRegular */
        ];

        // Finish launching so we have a proper menu bar and run loop
        let _: () = msg_send![shared_app, finishLaunching];

        set_shared_nsapp(shared_app as *mut std::ffi::c_void);
        set_nsapp_initialized(true);
        true
    }

    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Initialize NSApplication with prohibited activation policy (headless).
/// Used when we don't want UI but need NSApp for WKWebView rendering.
pub fn init_nsapplication_headless() -> bool {
    if nsapp_initialized() {
        return true;
    }

    #[cfg(target_os = "macos")]
    unsafe {
        let cls_app = match objc::runtime::Class::get("NSApplication") {
            Some(c) => c,
            None => return false,
        };

        let shared_app: *mut objc::runtime::Object = msg_send![cls_app, sharedApplication];
        if shared_app.is_null() {
            return false;
        }

        let _: () = msg_send![
            shared_app,
            setActivationPolicy: 2 /* NSApplicationActivationPolicyProhibited */
        ];

        let _: () = msg_send![shared_app, finishLaunching];

        set_shared_nsapp(shared_app as *mut std::ffi::c_void);
        set_nsapp_initialized(true);
        true
    }

    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

// ── NSWindow creation ────────────────────────────────────────────────────

/// Create a real NSWindow with the given properties.
/// Returns a raw pointer to the NSWindow, or null on failure.
pub fn create_nswindow(
    title: &str,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    style: u32,
    ex_style: u32,
) -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    unsafe {
        // Ensure NSApp is initialized
        if !nsapp_initialized() {
            if !init_nsapplication() {
                return std::ptr::null_mut();
            }
        }

        let cls_window = match objc::runtime::Class::get("NSWindow") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };

        let cls_view = match objc::runtime::Class::get("NSView") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };

        // macOS uses a flipped coordinate system where y=0 is bottom.
        // We need to convert from Win32 (top-left origin).
        // For now, use the screen height to flip if needed.
        let screen_frame: NSRect = {
            let screen: *mut objc::runtime::Object =
                msg_send![cls_window, performSelector: objc::sel!(screen)];
            msg_send![screen, frame]
        };
        let screen_height = screen_frame.size.height;
        let flipped_y = screen_height - (y as f64) - (height as f64);

        let frame = NSRect::new(
            NSPoint::new(x as f64, flipped_y),
            NSSize::new(width as f64, height as f64),
        );

        let ns_style = map_window_style_to_ns_style(style, ex_style);

        // Create content view
        let view_alloc: *mut objc::runtime::Object = msg_send![cls_view, alloc];
        let view: *mut objc::runtime::Object = msg_send![view_alloc, initWithFrame: frame];

        // Create window
        let win_alloc: *mut objc::runtime::Object = msg_send![cls_window, alloc];
        let win: *mut objc::runtime::Object = msg_send![
            win_alloc,
            initWithContentRect: frame
            styleMask: ns_style
            backing: 2 /* NSBackingStoreBuffered */
            defer: 0 /* NO */
        ];

        if win.is_null() {
            return std::ptr::null_mut();
        }

        // Set title
        let title_ns = ns_string_from_str(title);
        let _: () = msg_send![win, setTitle: title_ns];

        // Set content view
        let _: () = msg_send![win, setContentView: view];

        // Release the title string (we created it with a temporary)
        let _: () = msg_send![title_ns, release];

        // Handle window delegate for close notifications
        // Auto-releases on close
        let _: () = msg_send![win, setReleasedWhenClosed: 1 /* YES */];

        win as *mut std::ffi::c_void
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (title, x, y, width, height, style, ex_style);
        std::ptr::null_mut()
    }
}

/// Show (order front) or hide (order out) an NSWindow.
pub fn show_nswindow(ns_window: *mut std::ffi::c_void, show: bool) {
    #[cfg(target_os = "macos")]
    unsafe {
        if ns_window.is_null() {
            return;
        }
        let win: *mut objc::runtime::Object = ns_window as *mut _;
        if show {
            let _: () = msg_send![win, makeKeyAndOrderFront: std::ptr::null_mut::<std::ffi::c_void>()];
            // Also activate the app so the window appears
            if let Some(app) = shared_nsapp() {
                let app_obj: *mut objc::runtime::Object = app as *mut _;
                let _: () = msg_send![app_obj, activateIgnoringOtherApps: 1 /* YES */];
            }
        } else {
            let _: () = msg_send![win, orderOut: std::ptr::null_mut::<std::ffi::c_void>()];
        }
    }
    let _ = (ns_window, show);
}

/// Set the title of an NSWindow.
pub fn set_nswindow_title(ns_window: *mut std::ffi::c_void, title: &str) {
    #[cfg(target_os = "macos")]
    unsafe {
        if ns_window.is_null() {
            return;
        }
        let win: *mut objc::runtime::Object = ns_window as *mut _;
        let title_ns = ns_string_from_str(title);
        let _: () = msg_send![win, setTitle: title_ns];
        let _: () = msg_send![title_ns, release];
    }
    let _ = (ns_window, title);
}

/// Set the frame (position and size) of an NSWindow.
pub fn set_nswindow_frame(
    ns_window: *mut std::ffi::c_void,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
) {
    #[cfg(target_os = "macos")]
    unsafe {
        if ns_window.is_null() {
            return;
        }
        let win: *mut objc::runtime::Object = ns_window as *mut _;

        // Get screen height for coordinate flipping
        let cls_window = objc::runtime::Class::get("NSWindow").unwrap();
        let screen: *mut objc::runtime::Object =
            msg_send![cls_window, performSelector: objc::sel!(screen)];
        let screen_frame: NSRect = msg_send![screen, frame];
        let screen_height = screen_frame.size.height;
        let flipped_y = screen_height - (y as f64) - (height as f64);

        let frame = NSRect::new(
            NSPoint::new(x as f64, flipped_y),
            NSSize::new(width as f64, height as f64),
        );
        let _: () = msg_send![win, setFrame: frame display: 1 /* YES */ animate: 0 /* NO */];
    }
    let _ = (ns_window, x, y, width, height);
}

/// Force display refresh of an NSWindow.
pub fn update_nswindow(ns_window: *mut std::ffi::c_void) {
    #[cfg(target_os = "macos")]
    unsafe {
        if ns_window.is_null() {
            return;
        }
        let win: *mut objc::runtime::Object = ns_window as *mut _;
        let _: () = msg_send![win, display];
    }
    let _ = ns_window;
}

/// Get the content view NSView of an NSWindow.
pub fn nswindow_content_view(ns_window: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    unsafe {
        if ns_window.is_null() {
            return std::ptr::null_mut();
        }
        let win: *mut objc::runtime::Object = ns_window as *mut _;
        let view: *mut objc::runtime::Object = msg_send![win, contentView];
        view as *mut std::ffi::c_void
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = ns_window;
        std::ptr::null_mut()
    }
}

/// Close and release an NSWindow.
pub fn close_nswindow(ns_window: *mut std::ffi::c_void) {
    #[cfg(target_os = "macos")]
    unsafe {
        if ns_window.is_null() {
            return;
        }
        let win: *mut objc::runtime::Object = ns_window as *mut _;
        let _: () = msg_send![win, close];
    }
    let _ = ns_window;
}

// ── NSView sublayer management ───────────────────────────────────────────

/// Add a CALayer as a sublayer of a view's layer.
pub fn add_sublayer_to_view(view_ptr: *mut std::ffi::c_void, layer_ptr: *mut std::ffi::c_void) {
    #[cfg(target_os = "macos")]
    unsafe {
        if view_ptr.is_null() || layer_ptr.is_null() {
            return;
        }
        let view: *mut objc::runtime::Object = view_ptr as *mut _;
        let layer: *mut objc::runtime::Object = layer_ptr as *mut _;

        // Ensure the view is layer-backed
        let _: () = msg_send![view, setWantsLayer: 1 /* YES */];

        let sublayers: *mut objc::runtime::Object = msg_send![view, performSelector: objc::sel!(layer)];
        let _: () = msg_send![sublayers, addSublayer: layer];
    }
    let _ = (view_ptr, layer_ptr);
}

/// Set the frame of a CALayer sublayer.
pub fn set_layer_frame(layer_ptr: *mut std::ffi::c_void, x: f64, y: f64, width: f64, height: f64) {
    #[cfg(target_os = "macos")]
    unsafe {
        if layer_ptr.is_null() {
            return;
        }
        let layer: *mut objc::runtime::Object = layer_ptr as *mut _;
        let frame = NSRect::new(NSPoint::new(x, y), NSSize::new(width, height));
        let _: () = msg_send![layer, setFrame: frame];
    }
    let _ = (layer_ptr, x, y, width, height);
}

// ── CAMetalLayer attachment ──────────────────────────────────────────────

/// Create a CAMetalLayer and attach it as a sublayer of the NSWindow's content view.
/// Returns the CAMetalLayer pointer, or null on failure.
pub fn attach_cametal_layer_to_window(
    ns_window: *mut std::ffi::c_void,
    metal_device_ptr: *mut std::ffi::c_void,
    width: u32,
    height: u32,
) -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    unsafe {
        if ns_window.is_null() || metal_device_ptr.is_null() {
            return std::ptr::null_mut();
        }

        let cls_metal_layer = match objc::runtime::Class::get("CAMetalLayer") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };

        let layer: *mut objc::runtime::Object = msg_send![cls_metal_layer, layer];
        if layer.is_null() {
            return std::ptr::null_mut();
        }

        // Set device
        let device: *mut objc::runtime::Object = metal_device_ptr as *mut _;
        let _: () = msg_send![layer, setDevice: device];

        // Set pixel format
        // MTLPixelFormatBGRA8Unorm = 80
        let _: () = msg_send![layer, setPixelFormat: 80u64];

        // Set drawable size
        let size = NSSize::new(width as f64, height as f64);
        let _: () = msg_send![layer, setDrawableSize: size];

        // Set opaque
        let _: () = msg_send![layer, setOpaque: 1 /* YES */];

        // Set framebufferOnly = false (allows sampling)
        let _: () = msg_send![layer, setFramebufferOnly: 0 /* NO */];

        // Set presentsWithTransaction = false
        let _: () = msg_send![layer, setPresentsWithTransaction: 0 /* NO */];

        // Get the content view
        let win: *mut objc::runtime::Object = ns_window as *mut _;
        let content_view: *mut objc::runtime::Object = msg_send![win, contentView];

        // Ensure view is layer-backed
        let _: () = msg_send![content_view, setWantsLayer: 1 /* YES */];

        // Set the layer as the content view's backing layer
        let _: () = msg_send![content_view, setLayer: layer];

        layer as *mut std::ffi::c_void
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (ns_window, metal_device_ptr, width, height);
        std::ptr::null_mut()
    }
}

// ── NSEvent polling for message pump ─────────────────────────────────────

/// Poll a single NSEvent from the event queue (non-blocking).
/// Returns the raw NSEvent pointer, or null if no event available.
pub fn poll_nsevent() -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    unsafe {
        // NSEventType constants
        // NSEventMaskAny = NSULongMax
        let mask: u64 = !0u64;
        // NSDefaultRunLoopMode
        let mode: *mut std::ffi::c_void = {
            let cls = match objc::runtime::Class::get("NSDefaultRunLoopMode") {
                Some(c) => c,
                None => return std::ptr::null_mut(),
            };
            // NSDefaultRunLoopMode is a string constant NSString*
            let ptr: *mut std::ffi::c_void = msg_send![cls, performSelector: objc::sel!(new)];
            ptr
        };

        let cls_event = match objc::runtime::Class::get("NSEvent") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };

        let event: *mut objc::runtime::Object = msg_send![
            cls_event,
            nextEventMatchingMask: mask
            untilDate: std::ptr::null_mut::<std::ffi::c_void>() /* nil = no wait */
            inMode: mode
            dequeue: 1 /* YES */
        ];

        event as *mut std::ffi::c_void
    }

    #[cfg(not(target_os = "macos"))]
    {
        std::ptr::null_mut()
    }
}

/// Get the NSEventType of an NSEvent.
pub fn nsevent_type(event: *mut std::ffi::c_void) -> u64 {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return !0u64; // invalid
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        msg_send![ev, type]
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        !0u64
    }
}

/// Get the key code from an NSEvent.
pub fn nsevent_key_code(event: *mut std::ffi::c_void) -> u16 {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return 0;
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        msg_send![ev, keyCode]
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        0
    }
}

/// Get mouse location from an NSEvent.
pub fn nsevent_mouse_location(event: *mut std::ffi::c_void) -> (f64, f64) {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return (0.0, 0.0);
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        let pt: NSPoint = msg_send![ev, locationInWindow];
        (pt.x, pt.y)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        (0.0, 0.0)
    }
}

/// Get the window number from an NSEvent.
pub fn nsevent_window_number(event: *mut std::ffi::c_void) -> i32 {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return 0;
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        msg_send![ev, windowNumber]
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        0
    }
}

/// Get the characters from a key event.
pub fn nsevent_characters(event: *mut std::ffi::c_void) -> Option<String> {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return None;
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        let chars: *mut objc::runtime::Object = msg_send![ev, characters];
        if chars.is_null() {
            return None;
        }
        // Convert NSString to Rust String via UTF8
        let cstr: *const i8 = msg_send![chars, UTF8String];
        if cstr.is_null() {
            return None;
        }
        let s = std::ffi::CStr::from_ptr(cstr).to_string_lossy().into_owned();
        Some(s)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        None
    }
}

/// Get the modifier flags from an NSEvent.
pub fn nsevent_modifier_flags(event: *mut std::ffi::c_void) -> u64 {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return 0;
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        msg_send![ev, modifierFlags]
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        0
    }
}

/// Get the button number from a mouse event.
pub fn nsevent_button_number(event: *mut std::ffi::c_void) -> i32 {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return -1;
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        msg_send![ev, buttonNumber]
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        -1
    }
}

/// Get the click count from a mouse event.
pub fn nsevent_click_count(event: *mut std::ffi::c_void) -> i32 {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return 0;
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        msg_send![ev, clickCount]
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        0
    }
}

/// Get the delta X and delta Y from a scroll/mouse event.
pub fn nsevent_delta(event: *mut std::ffi::c_void) -> (f64, f64) {
    #[cfg(target_os = "macos")]
    unsafe {
        if event.is_null() {
            return (0.0, 0.0);
        }
        let ev: *mut objc::runtime::Object = event as *mut _;
        let dx: f64 = msg_send![ev, deltaX];
        let dy: f64 = msg_send![ev, deltaY];
        (dx, dy)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = event;
        (0.0, 0.0)
    }
}

/// Retrieve the window for a given window number.
pub fn nswindow_from_number(window_number: i32) -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    unsafe {
        let cls = match objc::runtime::Class::get("NSWindow") {
            Some(c) => c,
            None => return std::ptr::null_mut(),
        };
        let win: *mut objc::runtime::Object = msg_send![cls, windowWithWindowNumber: window_number];
        win as *mut std::ffi::c_void
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = window_number;
        std::ptr::null_mut()
    }
}

// ── Helper Functions ─────────────────────────────────────────────────────

/// Convert a Rust &str to an Objective-C NSString.
/// Caller must `release` the returned object when done.
unsafe fn ns_string_from_str(s: &str) -> *mut objc::runtime::Object {
    #[cfg(target_os = "macos")]
    unsafe {
        let cls = objc::runtime::Class::get("NSString").unwrap();
        let bytes = s.as_ptr();
        let len = s.len();
        let alloc: *mut objc::runtime::Object = msg_send![cls, alloc];
        let result: *mut objc::runtime::Object = msg_send![
            alloc,
            initWithBytes: bytes
            length: len
            encoding: 4 /* NSUTF8StringEncoding */
        ];
        result
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = s;
        std::ptr::null_mut()
    }
}

// ── NSPasteboard clipboard integration ────────────────────────────────────
//
// These functions use macOS NSPasteboard via Objective-C FFI to provide
// real clipboard integration for the Win32 clipboard APIs.

/// Open the macOS general pasteboard and clear its contents.
/// Returns true on success.
pub fn nspasteboard_clear() -> bool {
    #[cfg(target_os = "macos")]
    unsafe {
        let cls = match objc::runtime::Class::get("NSPasteboard") {
            Some(c) => c,
            None => return false,
        };
        let pasteboard: *mut objc::runtime::Object = msg_send![cls, generalPasteboard];
        if pasteboard.is_null() {
            return false;
        }
        let count: i64 = msg_send![pasteboard, clearContents];
        count >= 0
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = ();
        false
    }
}

/// Set string data on the macOS general pasteboard for a given format.
/// Maps Win32 clipboard format identifiers to NSPasteboard types:
/// - CF_TEXT / CF_OEMTEXT → NSPasteboardTypeString (public.utf8-plain-text)
/// - CF_UNICODETEXT → NSPasteboardTypeString
/// All other formats are stored as raw data with a custom type.
/// Returns true on success.
pub fn nspasteboard_set_data(format: u32, data: &[u8]) -> bool {
    #[cfg(target_os = "macos")]
    unsafe {
        let cls = match objc::runtime::Class::get("NSPasteboard") {
            Some(c) => c,
            None => return false,
        };
        let pasteboard: *mut objc::runtime::Object = msg_send![cls, generalPasteboard];
        if pasteboard.is_null() {
            return false;
        }

        // Determine the pasteboard type string based on format
        let (is_string, pb_type) = match format {
            1 | 7 => (true, "public.utf8-plain-text"), // CF_TEXT, CF_OEMTEXT
            13 => (true, "public.utf8-plain-text"),     // CF_UNICODETEXT
            _ => (false, "public.data"),                // raw data
        };

        if is_string {
            // Convert bytes to NSString
            let s = std::str::from_utf8(data).unwrap_or("");
            let cls_nsstring = objc::runtime::Class::get("NSString").unwrap();
            let ns_string: *mut objc::runtime::Object = msg_send![cls_nsstring, alloc];
            let ns_string: *mut objc::runtime::Object = msg_send![
                ns_string,
                initWithBytes: s.as_ptr()
                length: s.len() as u64
                encoding: 4 /* NSUTF8StringEncoding */
            ];
            if ns_string.is_null() {
                return false;
            }
            let arr: *mut objc::runtime::Object = msg_send![
                cls_nsstring, // NSArray actually
                alloc
            ];
            // Use objc to create an NSArray with the string
            let cls_nsarray = objc::runtime::Class::get("NSArray").unwrap();
            let objects = [ns_string];
            let arr: *mut objc::runtime::Object = msg_send![
                cls_nsarray,
                arrayWithObjects: objects.as_ptr()
                count: 1usize
            ];
            let result: i64 = msg_send![pasteboard, declareTypes: arr owner: std::ptr::null_mut::<objc::runtime::Object>()];
            let _: () = msg_send![ns_string, release];
            result >= 0
        } else {
            // Store as raw NSData
            let cls_nsdata = objc::runtime::Class::get("NSData").unwrap();
            let ns_data: *mut objc::runtime::Object = msg_send![
                cls_nsdata,
                dataWithBytes: data.as_ptr()
                length: data.len() as u64
            ];
            if ns_data.is_null() {
                return false;
            }
            let pb_type_ns = NSString_from_str(pb_type);
            if pb_type_ns.is_null() {
                let _: () = msg_send![ns_data, release];
                return false;
            }
            let result: i64 = msg_send![pasteboard, setData: ns_data forType: pb_type_ns];
            let _: () = msg_send![ns_data, release];
            let _: () = msg_send![pb_type_ns, release];
            result > 0
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (format, data);
        false
    }
}

/// Get string/raw data from the macOS general pasteboard.
/// Returns None if the requested format is not available.
pub fn nspasteboard_get_data(format: u32, max_len: usize) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    unsafe {
        let cls = match objc::runtime::Class::get("NSPasteboard") {
            Some(c) => c,
            None => return None,
        };
        let pasteboard: *mut objc::runtime::Object = msg_send![cls, generalPasteboard];
        if pasteboard.is_null() {
            return None;
        }

        let pb_type = match format {
            1 | 7 | 13 => "public.utf8-plain-text", // CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT
            _ => "public.data",
        };

        let pb_type_ns = NSString_from_str(pb_type);
        if pb_type_ns.is_null() {
            return None;
        }

        let data: *mut objc::runtime::Object = msg_send![pasteboard, dataForType: pb_type_ns];
        let _: () = msg_send![pb_type_ns, release];

        if data.is_null() {
            return None;
        }

        let len: u64 = msg_send![data, length];
        if len == 0 {
            return Some(Vec::new());
        }
        let read_len = (len as usize).min(max_len);
        let mut buf = vec![0u8; read_len];
        let bytes: *const std::ffi::c_void = msg_send![data, bytes];
        if bytes.is_null() {
            return None;
        }
        std::ptr::copy_nonoverlapping(bytes as *const u8, buf.as_mut_ptr(), read_len);
        Some(buf)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (format, max_len);
        None
    }
}

/// Check if the macOS general pasteboard contains data in the given format.
pub fn nspasteboard_is_format_available(format: u32) -> bool {
    #[cfg(target_os = "macos")]
    unsafe {
        let cls = match objc::runtime::Class::get("NSPasteboard") {
            Some(c) => c,
            None => return false,
        };
        let pasteboard: *mut objc::runtime::Object = msg_send![cls, generalPasteboard];
        if pasteboard.is_null() {
            return false;
        }

        let pb_type = match format {
            1 | 7 | 13 => "public.utf8-plain-text",
            _ => "public.data",
        };
        let pb_type_ns = NSString_from_str(pb_type);
        if pb_type_ns.is_null() {
            return false;
        }
        let type_obj: *mut objc::runtime::Object = pb_type_ns;
        let ns_array: *mut objc::runtime::Object = msg_send![objc::runtime::Class::get("NSArray").unwrap(), arrayWithObject: type_obj];
        let available: bool = msg_send![pasteboard, availableTypeFromArray: ns_array];
        let _: () = msg_send![pb_type_ns, release];
        available
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = format;
        false
    }
}

/// Helper: create an NSString from a Rust &str (returns a retained object).
#[cfg(target_os = "macos")]
unsafe fn NSString_from_str(s: &str) -> *mut objc::runtime::Object {
    let cls = objc::runtime::Class::get("NSString").unwrap();
    let bytes = s.as_ptr();
    let len = s.len() as u64;
    let alloc: *mut objc::runtime::Object = msg_send![cls, alloc];
    let ns_string: *mut objc::runtime::Object = msg_send![
        alloc,
        initWithBytes: bytes
        length: len
        encoding: 4 /* NSUTF8StringEncoding */
    ];
    ns_string
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── NSPoint / NSSize / NSRect ─────────────────────────────────────────

    #[test]
    fn test_nspoint_creation() {
        let pt = NSPoint::new(10.5, 20.3);
        assert!((pt.x - 10.5).abs() < f64::EPSILON);
        assert!((pt.y - 20.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_nssize_creation() {
        let sz = NSSize::new(1920.0, 1080.0);
        assert!((sz.width - 1920.0).abs() < f64::EPSILON);
        assert!((sz.height - 1080.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_nsrect_creation() {
        let rect = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(800.0, 600.0));
        assert!((rect.origin.x).abs() < f64::EPSILON);
        assert!((rect.origin.y).abs() < f64::EPSILON);
        assert!((rect.size.width - 800.0).abs() < f64::EPSILON);
        assert!((rect.size.height - 600.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_nspoint_encoding() {
        let encoding = NSPoint::encode();
        assert_eq!(encoding.as_str(), "{CGPoint=dd}");
    }

    #[test]
    fn test_nssize_encoding() {
        let encoding = NSSize::encode();
        assert_eq!(encoding.as_str(), "{CGSize=dd}");
    }

    #[test]
    fn test_nsrect_encoding() {
        let encoding = NSRect::encode();
        assert_eq!(encoding.as_str(), "{CGRect={CGPoint=dd}{CGSize=dd}}");
    }

    // ── Window style mapping ──────────────────────────────────────────────

    const WS_BORDER: u32 = 0x0080_0000;
    const WS_CAPTION: u32 = 0x00C0_0000;
    const WS_CHILD: u32 = 0x4000_0000;
    const WS_MINIMIZEBOX: u32 = 0x0002_0000;
    const WS_MAXIMIZEBOX: u32 = 0x0001_0000;
    const WS_POPUP: u32 = 0x8000_0000;
    const WS_SYSMENU: u32 = 0x0008_0000;
    const WS_THICKFRAME: u32 = 0x0004_0000;
    const WS_VISIBLE: u32 = 0x1000_0000;
    const WS_OVERLAPPEDWINDOW: u32 = WS_CAPTION | WS_SYSMENU | WS_THICKFRAME
        | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
    const WS_POPUPWINDOW: u32 = WS_POPUP | WS_BORDER | WS_SYSMENU;
    const WS_OVERLAPPED: u32 = 0x0000_0000;

    const NSWindowStyleMaskBorderless: i32 = 0;
    const NSWindowStyleMaskTitled: i32 = 1;
    const NSWindowStyleMaskClosable: i32 = 2;
    const NSWindowStyleMaskMiniaturizable: i32 = 4;
    const NSWindowStyleMaskResizable: i32 = 8;

    #[test]
    fn test_map_style_child_window() {
        // Child windows should always be borderless
        let style = WS_CHILD | WS_VISIBLE;
        let result = map_window_style_to_ns_style(style, 0);
        assert_eq!(result, NSWindowStyleMaskBorderless);
    }

    #[test]
    fn test_map_style_overlapped_window() {
        // WS_OVERLAPPEDWINDOW → titled + closable + resizable + miniaturizable
        let result = map_window_style_to_ns_style(WS_OVERLAPPEDWINDOW, 0);
        assert!(result & NSWindowStyleMaskTitled != 0);
        assert!(result & NSWindowStyleMaskClosable != 0);
        assert!(result & NSWindowStyleMaskResizable != 0);
        assert!(result & NSWindowStyleMaskMiniaturizable != 0);
    }

    #[test]
    fn test_map_style_popup_window() {
        // Popup window → titled + closable (not resizable, not miniaturizable)
        let result = map_window_style_to_ns_style(WS_POPUPWINDOW, 0);
        assert!(result & NSWindowStyleMaskTitled != 0);
        assert!(result & NSWindowStyleMaskClosable != 0);
        // Popup without thickframe → not resizable
        assert!(result & NSWindowStyleMaskResizable == 0);
    }

    #[test]
    fn test_map_style_borderless() {
        // A plain overlapped window (style=0) → borderless
        let result = map_window_style_to_ns_style(WS_OVERLAPPED, 0);
        assert_eq!(result, NSWindowStyleMaskBorderless);
    }

    #[test]
    fn test_map_style_minimize_box() {
        // A window with only WS_MINIMIZEBOX → miniaturizable
        let result = map_window_style_to_ns_style(WS_MINIMIZEBOX, 0);
        assert!(result & NSWindowStyleMaskMiniaturizable != 0);
    }

    #[test]
    fn test_map_style_thickframe() {
        // WS_THICKFRAME alone → resizable (but not titled)
        let style = WS_THICKFRAME;
        let result = map_window_style_to_ns_style(style, 0);
        assert!(result & NSWindowStyleMaskResizable != 0);
        // But without caption → not titled
        assert!(result & NSWindowStyleMaskTitled == 0);
    }

    #[test]
    fn test_map_style_sysmenu_only() {
        // WS_SYSMENU alone → closable + miniaturizable
        let result = map_window_style_to_ns_style(WS_SYSMENU, 0);
        assert!(result & NSWindowStyleMaskClosable != 0);
        assert!(result & NSWindowStyleMaskMiniaturizable != 0);
    }

    // ── HWND ↔ NSWindow association ───────────────────────────────────────

    #[test]
    fn test_hwnd_association() {
        // Fresh map should have nothing
        assert!(nswindow_for_hwnd(1).is_none());
        assert!(remove_hwnd_nswindow(1).is_none());

        // Associate
        let ptr: *mut std::ffi::c_void = 0xDEAD_BEEF as *mut _;
        associate_hwnd_nswindow(42, ptr);

        // Retrieve
        let retrieved = nswindow_for_hwnd(42);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap() as usize, 0xDEAD_BEEF);

        // Remove
        let removed = remove_hwnd_nswindow(42);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap() as usize, 0xDEAD_BEEF);

        // Should be gone
        assert!(nswindow_for_hwnd(42).is_none());
    }

    #[test]
    fn test_hwnd_association_multiple() {
        let ptr1: *mut std::ffi::c_void = 0x1000 as *mut _;
        let ptr2: *mut std::ffi::c_void = 0x2000 as *mut _;
        let ptr3: *mut std::ffi::c_void = 0x3000 as *mut _;

        associate_hwnd_nswindow(1, ptr1);
        associate_hwnd_nswindow(2, ptr2);
        associate_hwnd_nswindow(3, ptr3);

        assert_eq!(nswindow_for_hwnd(1).unwrap() as usize, 0x1000);
        assert_eq!(nswindow_for_hwnd(2).unwrap() as usize, 0x2000);
        assert_eq!(nswindow_for_hwnd(3).unwrap() as usize, 0x3000);

        // Overwrite
        let ptr4: *mut std::ffi::c_void = 0x4000 as *mut _;
        associate_hwnd_nswindow(2, ptr4);
        assert_eq!(nswindow_for_hwnd(2).unwrap() as usize, 0x4000);

        // Cleanup
        remove_hwnd_nswindow(1);
        remove_hwnd_nswindow(2);
        remove_hwnd_nswindow(3);
    }

    #[test]
    fn test_hwnd_association_nonexistent() {
        assert!(nswindow_for_hwnd(99999).is_none());
        assert!(remove_hwnd_nswindow(99999).is_none());
    }

    #[test]
    fn test_nsapp_initialization_state() {
        // Should not be initialised yet (we never called init_nsapplication in tests)
        // Note: this test relies on the fact that tests run in a fresh environment.
        // If another test initializes NSApp, this might fail intermittently.
        // We only check that is_nsapp_initialized() returns a bool.
        let _init = is_nsapp_initialized();
        // Just verify it doesn't panic — the actual value depends on test ordering
    }

    #[test]
    fn test_nsapp_initialized_toggle() {
        // Before: should be false (we don't call init_nsapplication in tests)
        // Just verify we can call the functions without panicking
        let before = is_nsapp_initialized();
        set_nsapp_initialized(true);
        let after = is_nsapp_initialized();
        assert!(after);
        // Reset so we don't affect other tests
        set_nsapp_initialized(before);
    }

    // ── Layer frame helpers ───────────────────────────────────────────────

    #[test]
    fn test_set_layer_frame_null() {
        // Should not panic
        set_layer_frame(std::ptr::null_mut(), 0.0, 0.0, 100.0, 100.0);
    }

    #[test]
    fn test_add_sublayer_to_view_null() {
        // Should not panic
        add_sublayer_to_view(std::ptr::null_mut(), std::ptr::null_mut());
        add_sublayer_to_view(0x1 as *mut _, std::ptr::null_mut());
        add_sublayer_to_view(std::ptr::null_mut(), 0x1 as *mut _);
    }

    // ── NSEvent query helpers (non-macOS stubs) ───────────────────────────

    #[test]
    fn test_nsevent_query_stubs() {
        // These return default values on non-macOS platforms
        let event = std::ptr::null_mut();

        let etype = nsevent_type(event);
        assert_eq!(etype, !0u64); // invalid on any platform for null event

        let key_code = nsevent_key_code(event);
        assert_eq!(key_code, 0);

        let (mx, my) = nsevent_mouse_location(event);
        assert!((mx).abs() < f64::EPSILON);
        assert!((my).abs() < f64::EPSILON);

        let win_num = nsevent_window_number(event);
        assert_eq!(win_num, 0);

        let chars = nsevent_characters(event);
        assert!(chars.is_none());

        let mod_flags = nsevent_modifier_flags(event);
        assert_eq!(mod_flags, 0);

        let btn = nsevent_button_number(event);
        assert_eq!(btn, -1);

        let click = nsevent_click_count(event);
        assert_eq!(click, 0);

        let (dx, dy) = nsevent_delta(event);
        assert!((dx).abs() < f64::EPSILON);
        assert!((dy).abs() < f64::EPSILON);
    }

    #[test]
    fn test_nswindow_from_number_null() {
        // With window number 0, should return null on all platforms
        let result = nswindow_from_number(0);
        assert!(result.is_null());
    }
}
