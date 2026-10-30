// ---------------------------------------------------------------------------
// macOS Real Window Creation — NSWindow / NSView / CAMetalLayer utilities
//
// Provides Objective-C FFI helpers for creating and managing real macOS
// windows backed by NSWindow. Used by user32.rs to materialize Win32 HWNDs
// as native NSWindows, and by metal_backend.rs to attach CAMetalLayers.
//
// # Thread Safety
//
// **All AppKit calls MUST run on the main thread.** AppKit is not
// thread-safe and many operations (NSWindow creation, CAMetalLayer
// attachment, NSApplication initialization) will crash or corrupt state
// when called from a background thread.
//
// Every public function in this module automatically dispatches to the
// main thread via GCD `dispatch_sync_f` when called from a background
// thread.  Callers never need to worry about which thread they are on.
// ---------------------------------------------------------------------------

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

// ── Explicit main-thread work queue ──────────────────────────────────
//
// We **cannot** use GCD `dispatch_sync_f` because the main thread runs a
// custom loop in `run_live_host_session()` (live.rs) and never enters the
// GCD run loop — so blocks dispatched to the main queue would NEVER be
// processed, causing a deadlock.
//
// Instead, we maintain an explicit work queue.  Worker threads push
// `MainQueueItem`s with a completion signal, then block until the main
// thread processes the item and signals completion.  The main thread
// calls `pump_main_queue()` at the top of every iteration of its loop.

/// Completion state for one main-queue item.
///
/// `panic` carries the caught panic payload so the submitting thread can
/// resume the unwind after the completion signal, even though the closure's
/// return value was never produced.
struct MainQueueCompletion {
    done: bool,
    panic: Option<Box<dyn std::any::Any + Send>>,
}

/// A work item enqueued by a background thread for execution on the main
/// thread.  `done` is set to `true` (and the associated `Condvar` signaled)
/// after `work` has finished executing.
struct MainQueueItem {
    work: Box<dyn FnMut() + Send>,
    done: Arc<(Mutex<MainQueueCompletion>, Condvar)>,
}

// SAFETY: `work` is executed on the main thread, never concurrently.
// The `Send` bound is needed for `Mutex<VecDeque<...>>` but the actual
// execution is serialised on the main thread via `pump_main_queue()`.
unsafe impl Send for MainQueueItem {}

static MAIN_QUEUE: MainQueue = MainQueue {
    pending: Mutex::new(VecDeque::new()),
};

struct MainQueue {
    pending: Mutex<VecDeque<MainQueueItem>>,
}

/// Execute a closure synchronously on the main thread.
///
/// When called from a background thread on macOS, the closure is enqueued
/// in the explicit `MAIN_QUEUE` and the caller blocks until the main
/// thread processes it via `pump_main_queue()`.  When called from the
/// main thread (or on non-macOS), the closure runs directly.
///
/// This is the replacement for the old `assert_main_thread()` panic —
/// instead of crashing, we properly dispatch to the main thread so that
/// the PE runtime worker can safely call AppKit APIs.
///
/// # Invariant
///
/// The main loop MUST keep calling [`pump_main_queue`] as long as
/// background threads may call this function — including during teardown,
/// right up until the process exits. If the loop stops pumping while a
/// thread is blocked here, that thread waits forever. The wait is bounded
/// (10s) with a warning so a stalled main loop is diagnosable; the closure
/// is still guaranteed to run and the returned value is always valid.
fn run_on_main<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    #[cfg(target_os = "macos")]
    if unsafe { libc::pthread_main_np() == 0 } {
        // Stack-allocate MaybeUninit to hold the result, avoiding any
        // `Send` requirement on R (e.g. *mut c_void is !Send).
        let mut result_storage = std::mem::MaybeUninit::<R>::uninit();
        let result_ptr: *mut R = result_storage.as_mut_ptr();

        let done = Arc::new((
            Mutex::new(MainQueueCompletion {
                done: false,
                panic: None,
            }),
            Condvar::new(),
        ));
        let done_clone = Arc::clone(&done);

        let mut f = Some(f);

        // Build a closure that will execute F on the main thread and always
        // signal completion, even when F panics (the panic payload is handed
        // back to the waiting caller).  This closure may capture !Send types
        // (e.g. raw pointers from the AppKit FFI), but it will only ever run
        // on the main thread (inside pump_main_queue), so we unsafely assert
        // Send via transmute.
        let boxed: Box<dyn FnMut()> = Box::new(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Some(f) = f.take() {
                    // SAFETY: result_ptr is valid and written at most once;
                    // a panic skips the write and is surfaced to the caller.
                    unsafe {
                        std::ptr::write(result_ptr, f());
                    }
                }
            }));
            let (lock, cvar) = &*done_clone;
            let mut completed = lock.lock().unwrap();
            completed.done = true;
            completed.panic = outcome.err();
            cvar.notify_one();
        });

        // SAFETY: Box<dyn FnMut()> and Box<dyn FnMut() + Send> have the same
        // layout (data pointer + vtable pointer). The closure is only ever
        // executed on the main thread, so asserting Send is sound.
        let work: Box<dyn FnMut() + Send> = unsafe { std::mem::transmute(boxed) };

        // Clone done before moving it into MainQueueItem, so we can
        // still reference it for the wait below.
        let done_for_wait = Arc::clone(&done);
        let item = MainQueueItem { work, done };

        // Push the work item onto the queue.
        MAIN_QUEUE.pending.lock().unwrap().push_back(item);

        // Block until the main thread processes this item. The wait is bounded
        // so that a stalled main loop (e.g. during shutdown) is diagnosable;
        // when it fires we keep waiting because the result is only valid after
        // the closure has actually run.
        let (lock, cvar) = &*done_for_wait;
        let mut completed = lock.lock().unwrap();
        let mut warned = false;
        while !completed.done {
            let (guard, timeout) = cvar
                .wait_timeout(completed, std::time::Duration::from_secs(10))
                .unwrap();
            completed = guard;
            if timeout.timed_out() && !warned {
                warned = true;
                eprintln!(
                    "[mac_window] run_on_main: main queue has not been pumped for 10s; \
                     is the main loop still calling pump_main_queue()?"
                );
            }
        }
        let panic = completed.panic.take();
        drop(completed);
        if let Some(panic) = panic {
            std::panic::resume_unwind(panic);
        }

        // SAFETY: After the Condvar signals, the closure has written result_ptr.
        return unsafe { result_storage.assume_init() };
    }

    // Already on the main thread (or not macOS): run directly.
    f()
}

/// Process all pending main-thread work items.
///
/// Must be called from the **main thread** — typically at the top of each
/// iteration of `run_live_host_session()`'s event loop, and also during
/// teardown so that no background thread is left blocked in
/// [`run_on_main`].  Each pending `MainQueueItem` is executed and its
/// completion signal is set, unblocking the background thread that
/// submitted it.
pub fn pump_main_queue() {
    #[cfg(target_os = "macos")]
    // SAFETY: pthread_main_np is a simple POSIX query.
    debug_assert!(
        unsafe { libc::pthread_main_np() != 0 },
        "pump_main_queue() must be called from the main thread"
    );
    drain_main_queue(); // coverage: unreachable
} // coverage: unreachable

/// Execute every pending item, isolated from panics.
///
/// Split from [`pump_main_queue`] so the panic-isolation behavior can be
/// exercised by tests (the libtest harness runs on a worker thread).
fn drain_main_queue() {
    let items = {
        let mut pending = MAIN_QUEUE.pending.lock().unwrap();
        std::mem::take(&mut *pending)
    };
    for mut item in items {
        // One panicking task must not abort the pump or leave the submitting
        // thread blocked forever: catch it, then always signal completion.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (item.work)()));
        let (lock, cvar) = &*item.done;
        let mut completed = lock.lock().unwrap();
        completed.done = true;
        if let Err(payload) = outcome {
            completed.panic.get_or_insert(payload);
        }
        cvar.notify_one();
    }
}

// ── Safe raw-pointer wrapper for use in statics ──────────────────────────

/// Wrapper around `*mut c_void` that implements `Send` + `Sync`.
/// SAFETY: Pointers are only accessed behind a `Mutex` and under the
/// assumption that the main thread (or serialised access) handles them.
#[derive(Debug, Clone, Copy)]
struct SafePtr(*mut std::ffi::c_void);
// SAFETY: Send is safe because the type only uses thread-safe internal state or is accessed under exclusive &mut
unsafe impl Send for SafePtr {}
// SAFETY: Send is safe because the type only uses thread-safe internal state or is accessed under exclusive &mut
unsafe impl Sync for SafePtr {}

impl SafePtr {
    fn null() -> Self {
        Self(std::ptr::null_mut())
    }
    fn as_ptr(self) -> *mut std::ffi::c_void {
        self.0
    }
    #[allow(dead_code)] // safe-pointer null check helper
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

/// Force-create real NSWindows even when the process is not inside a `.app`
/// bundle.  Set this before launching any guest PE image that requires a
/// native window (e.g. Steam.exe in the casa1-runner process).
static FORCE_WINDOW_CREATION: OnceLock<Mutex<bool>> = OnceLock::new();

/// Enable forced window creation mode.
///
/// When enabled, `init_nsapplication()` and `create_nswindow()` will create
/// real macOS NSWindows even if the current process is not a proper `.app`
/// bundle.  This is necessary for the `casa1-runner` binary which runs PE
/// images that expect real HWNDs backed by NSWindows.
pub fn set_force_window_creation(force: bool) {
    *FORCE_WINDOW_CREATION
        .get_or_init(|| Mutex::new(false))
        .lock()
        .unwrap() = force;
}

/// Check whether forced window creation mode is active.
pub fn force_window_creation() -> bool {
    *FORCE_WINDOW_CREATION
        .get_or_init(|| Mutex::new(false))
        .lock()
        .unwrap()
}

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

fn process_is_app_bundle() -> bool {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        let Some(cls_bundle) = objc::runtime::Class::get("NSBundle") else {
            return false;
        };
        let main_bundle: *mut objc::runtime::Object = msg_send![cls_bundle, mainBundle];
        if main_bundle.is_null() {
            return false;
        }
        let bundle_path: *mut objc::runtime::Object = msg_send![main_bundle, bundlePath];
        if bundle_path.is_null() {
            return false;
        }
        let cstr: *const i8 = msg_send![bundle_path, UTF8String];
        if cstr.is_null() {
            return false;
        }
        std::ffi::CStr::from_ptr(cstr)
            .to_string_lossy()
            .ends_with(".app")
    }

    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Global mapping from HWND (u32) to NSWindow pointer, for real window operations.
static HWND_TO_NSWINDOW: OnceLock<Mutex<std::collections::BTreeMap<u32, SafePtr>>> =
    OnceLock::new();

fn hwnd_to_nswindow_map() -> &'static Mutex<std::collections::BTreeMap<u32, SafePtr>> {
    HWND_TO_NSWINDOW.get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
}

/// Store an NSWindow pointer for a given HWND.
pub fn associate_hwnd_nswindow(hwnd: u32, ns_window: *mut std::ffi::c_void) {
    hwnd_to_nswindow_map()
        .lock()
        .unwrap()
        .insert(hwnd, SafePtr::from(ns_window));
}

/// Retrieve the NSWindow pointer for a given HWND, if any.
pub fn nswindow_for_hwnd(hwnd: u32) -> Option<*mut std::ffi::c_void> {
    hwnd_to_nswindow_map()
        .lock()
        .unwrap()
        .get(&hwnd)
        .map(|s| s.as_ptr())
}

/// Remove the association for a given HWND and return the NSWindow pointer.
pub fn remove_hwnd_nswindow(hwnd: u32) -> Option<*mut std::ffi::c_void> {
    hwnd_to_nswindow_map()
        .lock()
        .unwrap()
        .remove(&hwnd)
        .map(|s| s.as_ptr())
}

/// Resolve the HWND associated with an NSWindow pointer.
///
/// The close delegate uses this to turn a native window-close gesture into
/// a `WM_CLOSE` for the owning guest window.  Returns `None` when the window
/// is not associated with any live HWND (e.g. a stale/stub window).
pub fn hwnd_for_nswindow(ns_window: *mut std::ffi::c_void) -> Option<u32> {
    if ns_window.is_null() {
        return None;
    }
    hwnd_to_nswindow_map()
        .lock()
        .unwrap()
        .iter()
        .find(|(_hwnd, ptr)| ptr.as_ptr() == ns_window)
        .map(|(hwnd, _)| *hwnd)
}

/// Native window-close requests waiting to be delivered as `WM_CLOSE`.
///
/// The AppKit delegate's `windowShouldClose:` runs on the main thread and
/// cannot touch the guest message queue directly; it records the HWND here
/// and the runtime drains it into the queue.
static PENDING_WINDOW_CLOSES: OnceLock<Mutex<Vec<u32>>> = OnceLock::new();

fn pending_window_closes() -> &'static Mutex<Vec<u32>> {
    PENDING_WINDOW_CLOSES.get_or_init(|| Mutex::new(Vec::new()))
}

fn queue_window_close(hwnd: u32) {
    pending_window_closes().lock().unwrap().push(hwnd);
}

/// Drain all native close gestures that have not yet been delivered.
pub fn take_pending_close_requests() -> Vec<u32> {
    std::mem::take(&mut *pending_window_closes().lock().unwrap())
}

#[cfg(test)]
/// Test hook: record a close gesture exactly as the AppKit delegate would.
pub(crate) fn queue_close_request_for_test(hwnd: u32) {
    queue_window_close(hwnd);
}

#[cfg(test)]
pub(crate) static CLOSE_QUEUE_TEST_LOCK: Mutex<()> = Mutex::new(());

/// NSWindows created (and therefore owned) by [`create_nswindow`].
///
/// Only these get the balancing `release` in [`close_nswindow`]; externally
/// supplied windows (perf harnesses, tests) are closed but not released.
static OWNED_NSWINDOWS: OnceLock<Mutex<std::collections::BTreeSet<usize>>> = OnceLock::new();

fn owned_nswindows() -> &'static Mutex<std::collections::BTreeSet<usize>> {
    OWNED_NSWINDOWS.get_or_init(|| Mutex::new(std::collections::BTreeSet::new()))
}

/// Mark an NSWindow as owned by this module.  Returns whether it was already
/// owned.
pub(crate) fn mark_nswindow_owned(ns_window: *mut std::ffi::c_void) -> bool {
    !owned_nswindows().lock().unwrap().insert(ns_window as usize)
}

#[cfg(test)]
/// Test hook: create a fresh stub NSWindow instance (not the shared one).
pub(crate) fn stub_window_instance_for_test() -> *mut std::ffi::c_void {
    use objc::runtime::{Class, Object, class_createInstance};
    let class = Class::get("Casa1User32StubWindow")
        .or_else(|| Class::get("NSObject"))
        .expect("stub class");
    // SAFETY: class is a registered Objective-C class.
    let instance: *mut Object = unsafe { class_createInstance(class, 0) };
    instance as *mut std::ffi::c_void
}

/// The shared NSWindowDelegate whose `windowShouldClose:` posts `WM_CLOSE`
/// and refuses the AppKit close (returns NO).
#[cfg(target_os = "macos")]
unsafe fn window_close_delegate() -> *mut objc::runtime::Object {
    use objc::runtime::{
        Class, Object, Sel, class_addMethod, objc_allocateClassPair, objc_registerClassPair,
    };

    static DELEGATE: OnceLock<Mutex<SafePtr>> = OnceLock::new();

    unsafe extern "C" fn window_should_close(
        _this: *mut Object,
        _cmd: Sel,
        sender: *mut Object,
    ) -> i8 {
        if !sender.is_null()
            && let Some(hwnd) = hwnd_for_nswindow(sender as *mut std::ffi::c_void)
        {
            queue_window_close(hwnd);
        }
        // NO: AppKit must not close/release the window.  Destruction happens
        // only when the guest calls DestroyWindow.
        0
    }

    let slot = DELEGATE.get_or_init(|| Mutex::new(SafePtr::null()));
    let mut stored = slot.lock().unwrap();
    if !stored.as_ptr().is_null() {
        return stored.as_ptr() as *mut Object;
    }
    let cls: *mut Class = match Class::get("Casa1WindowDelegate") {
        Some(existing) => existing as *const Class as *mut Class, // coverage: unreachable
        None => {
            let Some(superclass) = Class::get("NSObject") else {
                return std::ptr::null_mut(); // coverage: unreachable
            };
            let allocated =
                unsafe { objc_allocateClassPair(superclass, c"Casa1WindowDelegate".as_ptr(), 0) };
            if allocated.is_null() {
                return std::ptr::null_mut(); // coverage: unreachable
            }
            // SAFETY: the method implementation matches the
            // `windowShouldClose:` BOOL@:@ signature exactly.
            let added = unsafe {
                let imp: objc::runtime::Imp = std::mem::transmute(window_should_close as *const ());
                class_addMethod(
                    allocated,
                    Sel::register("windowShouldClose:"),
                    imp,
                    c"c@:@".as_ptr(),
                )
            };
            if !added {
                return std::ptr::null_mut(); // coverage: unreachable
            }
            unsafe { objc_registerClassPair(allocated) };
            allocated
        }
    };
    let instance: *mut Object = unsafe { msg_send![cls, new] };
    if instance.is_null() {
        return std::ptr::null_mut(); // coverage: unreachable
    }
    stored.0 = instance as *mut std::ffi::c_void;
    instance
}

#[cfg(not(target_os = "macos"))]
unsafe fn window_close_delegate() -> *mut std::ffi::c_void {
    std::ptr::null_mut()
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

// SAFETY: Objective-C runtime class lookup and instance creation
unsafe impl objc::Encode for NSPoint {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime class lookup and instance creation
        unsafe { objc::Encoding::from_str("{CGPoint=dd}") }
    }
}

// SAFETY: Objective-C runtime class lookup and instance creation
unsafe impl objc::Encode for NSSize {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime class lookup and instance creation
        unsafe { objc::Encoding::from_str("{CGSize=dd}") }
    }
}

// SAFETY: Objective-C runtime class lookup and instance creation
unsafe impl objc::Encode for NSRect {
    fn encode() -> objc::Encoding {
        // SAFETY: Objective-C runtime class lookup and instance creation
        unsafe { objc::Encoding::from_str("{CGRect={CGPoint=dd}{CGSize=dd}}") }
    }
}

// ── NSScreenInfo / NSScreen enumeration ──────────────────────────────────

/// Information about a single NSScreen, used to populate Win32 monitor data.
#[derive(Debug, Clone)]
pub struct NSScreenInfo {
    pub display_id: u32,
    pub name: String,
    /// (x, y, width, height) in points
    pub frame: (f64, f64, f64, f64),
    pub backing_scale_factor: f64,
    /// (x, y, width, height) in points (visible / excludes menu bar, Dock)
    pub work_frame: (f64, f64, f64, f64),
    pub is_main: bool,
}

/// Enumerate all available NSScreens and return their info.
///
/// Uses the real `[NSScreen screens]` API via `msg_send!` and the `objc` crate.
/// On non-macOS targets this returns an empty vec.
pub fn enumerate_nscreens() -> Vec<NSScreenInfo> {
    #[cfg(target_os = "macos")]
    {
        // In headless processes (CLI/test binaries) there is no main loop
        // pumping the dispatch queue, so block before dispatching rather than
        // inside the queued closure (which would hang forever).  A headless
        // process has no NSScreens anyway.
        if is_headless() {
            return Vec::new();
        }
    }
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            let mut result = Vec::new();
            if !process_is_app_bundle() {
                return result;
            }
            let screens: *mut objc::runtime::Object = msg_send![objc::class!(NSScreen), screens];
            if screens.is_null() {
                return result;
            }
            let count: usize = msg_send![screens, count];
            let num_key: *mut objc::runtime::Object =
                msg_send![objc::class!(NSString), stringWithUTF8String: c"NSScreenNumber".as_ptr()];
            for i in 0..count {
                let screen: *mut objc::runtime::Object = msg_send![screens, objectAtIndex: i];
                if screen.is_null() {
                    continue;
                }
                let frame: NSRect = msg_send![screen, frame];
                let visible_frame: NSRect = msg_send![screen, visibleFrame];
                let scale: f64 = msg_send![screen, backingScaleFactor];
                let is_main: bool = msg_send![screen, isMainScreen];
                let desc: *mut objc::runtime::Object = msg_send![screen, deviceDescription];
                let display_id_obj: *mut objc::runtime::Object =
                    msg_send![desc, objectForKey: num_key];
                let display_id: u32 = msg_send![display_id_obj, unsignedIntValue];
                // Get localized name
                let name_obj: *mut objc::runtime::Object = msg_send![screen, localizedName];
                let name_str = if !name_obj.is_null() {
                    let cstr: *const i8 = msg_send![name_obj, UTF8String];
                    if !cstr.is_null() {
                        std::ffi::CStr::from_ptr(cstr)
                            .to_string_lossy()
                            .into_owned()
                    } else {
                        format!("Display {}", display_id)
                    }
                } else {
                    format!("Display {}", display_id)
                };
                result.push(NSScreenInfo {
                    display_id,
                    name: name_str,
                    frame: (
                        frame.origin.x,
                        frame.origin.y,
                        frame.size.width,
                        frame.size.height,
                    ),
                    backing_scale_factor: scale,
                    work_frame: (
                        visible_frame.origin.x,
                        visible_frame.origin.y,
                        visible_frame.size.width,
                        visible_frame.size.height,
                    ),
                    is_main,
                });
            }
            result
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Vec::new()
    }
}

/// Get the backing scale factor for the screen that hosts the given NSWindow.
///
/// Defaults to 2.0 (Retina) if the screen cannot be queried.
pub fn get_backing_scale_factor(nswindow: *mut std::ffi::c_void) -> f64 {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if nswindow.is_null() {
                return 2.0;
            }
            let win: *mut objc::runtime::Object = nswindow as *mut _;
            let screen: *mut objc::runtime::Object = msg_send![win, screen];
            if screen.is_null() {
                return 2.0;
            }
            let scale: f64 = msg_send![screen, backingScaleFactor];
            scale
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = nswindow;
        2.0
    }
}

/// Set `contentsScale` on a CAMetalLayer to match the backing scale factor.
pub fn set_layer_contents_scale(layer: *mut std::ffi::c_void, scale: f64) {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if layer.is_null() {
                return;
            }
            let l: *mut objc::runtime::Object = layer as *mut _;
            let _: () = msg_send![l, setContentsScale: scale];
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (layer, scale);
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
        // Windows popups have a border but no caption (title bar) unless
        // WS_CAPTION (both WS_BORDER|WS_DLGFRAME) is set; a titled NSWindow
        // would add a title bar and close button, changing the look of menus
        // and tooltips.
        if style & WS_CAPTION == WS_CAPTION {
            return NSWindowStyleMaskTitled | NSWindowStyleMaskClosable;
        }
        return NSWindowStyleMaskBorderless;
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
///
/// When `set_force_window_creation(true)` has been called, this function
/// will initialise NSApp even without a `.app` bundle, skipping the
/// `setActivationPolicy:` call (which raises an uncatchable exception on
/// non-bundled executables) but still calling `finishLaunching` so that
/// real NSWindows can be created.
pub fn init_nsapplication() -> bool {
    // Quick check (no dispatch needed) — reading a OnceLock is thread-safe.
    if nsapp_initialized() {
        return true;
    }

    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            let cls_app = match objc::runtime::Class::get("NSApplication") {
                Some(c) => c,
                None => return false,
            };

            let shared_app: *mut objc::runtime::Object = msg_send![cls_app, sharedApplication];
            if shared_app.is_null() {
                return false;
            }

            // If forced window creation is active, skip the bundle check and
            // `setActivationPolicy:` (which raises uncatchable ObjC exceptions
            // on non-bundled executables).  We still call `finishLaunching` so
            // that NSApp is in a usable state and NSWindows can be created.
            if force_window_creation() {
                let _: () = msg_send![shared_app, finishLaunching];
                set_shared_nsapp(shared_app as *mut std::ffi::c_void);
                set_nsapp_initialized(true);
                eprintln!("[mac_window] init_nsapplication: forced mode (no bundle)");
                return true;
            }

            // Detect whether we are running as a proper .app bundle with an
            // Info.plist.  Non-bundled executables (e.g. `cargo test` binaries)
            // cannot safely call `setActivationPolicy:` or create NSWindows —
            // these raise uncatchable NSInternalInconsistencyExceptions that
            // cause immediate SIGABRT ("Rust cannot catch foreign exceptions").
            //
            // [`NSBundle mainBundle`] returns a bundle object even for non-bundled
            // executables, but [`bundleIdentifier`] returns nil when there is no
            // Info.plist.  Messaging nil in ObjC is safe (returns zero/nil), so
            // this detection never throws.
            let is_bundled = {
                let cls_bundle = match objc::runtime::Class::get("NSBundle") {
                    Some(c) => c,
                    None => return false,
                };
                let main_bundle: *mut objc::runtime::Object = msg_send![cls_bundle, mainBundle];
                if main_bundle.is_null() {
                    false
                } else {
                    let bid: *mut objc::runtime::Object = msg_send![main_bundle, bundleIdentifier];
                    !bid.is_null()
                }
            };

            if !is_bundled {
                return false;
            }

            // Bundled process: safe to fully initialise AppKit.
            let _: () = msg_send![shared_app, finishLaunching];
            let _: () = msg_send![
                shared_app,
                setActivationPolicy: 0 /* NSApplicationActivationPolicyRegular */
            ];

            set_shared_nsapp(shared_app as *mut std::ffi::c_void);
            set_nsapp_initialized(true);
            true
        })
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
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
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
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

// ── NSWindow creation ────────────────────────────────────────────────────

/// Convert a Win32 top-down Y (measured from the top of the primary display)
/// into Cocoa's bottom-up Y, flipping against the primary screen height.
///
/// `screens[0]` is the display that owns the menu bar, i.e. the origin for
/// Win32 screen coordinates.  Using any other screen's height offsets the
/// window vertically on multi-monitor setups.
pub(crate) fn flip_y(primary_height: f64, y: i32, height: u32) -> f64 {
    primary_height - f64::from(y) - f64::from(height)
}

/// The height of the primary display (`NSScreen.screens[0]`).
///
/// Falls back to the main screen and finally to `None` when AppKit cannot
/// enumerate a display.
///
/// Must be called on the main thread.
#[cfg(target_os = "macos")]
// SAFETY: AppKit FFI for window management on macOS
unsafe fn primary_screen_height() -> Option<f64> {
    let cls_screen = objc::runtime::Class::get("NSScreen")?;
    let screens: *mut objc::runtime::Object = msg_send![cls_screen, screens];
    if !screens.is_null() {
        let count: usize = msg_send![screens, count];
        if count > 0 {
            let primary: *mut objc::runtime::Object = msg_send![screens, objectAtIndex: 0usize];
            if !primary.is_null() {
                let frame: NSRect = msg_send![primary, frame];
                return Some(frame.size.height);
            } // coverage: unreachable
        } // coverage: unreachable
    }
    let main: *mut objc::runtime::Object = msg_send![cls_screen, mainScreen];
    if main.is_null() {
        None // coverage: unreachable
    } else {
        let frame: NSRect = msg_send![main, frame]; // coverage: unreachable
        Some(frame.size.height) // coverage: unreachable
    }
}

/// Create a real NSWindow with the given properties.
/// Returns a raw pointer to the NSWindow, or null on failure.
///
/// When `set_force_window_creation(true)` has been called, this function
/// will create the NSWindow even if the process is not a `.app` bundle.
pub fn create_nswindow(
    title: &str,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    style: u32,
    ex_style: u32,
) -> *mut std::ffi::c_void {
    // Convert &str to String for Send bound across the dispatch boundary.
    let title = title.to_string();
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            // If forced window creation is active, skip the bundle check so
            // that real NSWindows are created even for the casa1-runner process.
            if !force_window_creation() && !process_is_app_bundle() {
                // AppKit window materialization from a plain CLI/test executable is not
                // reliable on macOS and can raise Objective-C exceptions that Rust
                // cannot catch. Keep the Win32 window logically alive but headless
                // unless we are running from a real `.app` bundle.
                return std::ptr::null_mut();
            }

            // Ensure NSApp is initialized
            if !nsapp_initialized() && !init_nsapplication() {
                return std::ptr::null_mut();
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
            // Flip against the primary screen (screens[0]); Win32 screen
            // coordinates are measured top-down from its top edge.
            // coverage: unreachable
            let primary_height = primary_screen_height().unwrap_or(height as f64); // coverage: unreachable
            let flipped_y = flip_y(primary_height, y, height); // coverage: unreachable

            // Win32 width/height describe the OUTER window frame.  NSWindow's
            // initWithContentRect: takes a content rect, so convert with the
            // same AppKit math used later by setFrame: an outer/content mix-up
            // here makes the first MoveWindow resize a titled window.
            #[rustfmt::skip]
            let outer_frame = NSRect::new(NSPoint::new(x as f64, flipped_y), NSSize::new(width as f64, height as f64)); // coverage: unreachable
            let ns_style = map_window_style_to_ns_style(style, ex_style);
            let frame: NSRect = msg_send![ // coverage: unreachable
                cls_window, // coverage: unreachable
                contentRectForFrameRect: outer_frame // coverage: unreachable
                styleMask: ns_style // coverage: unreachable
            ];

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
                let _: () = msg_send![view, release]; // coverage: unreachable
                return std::ptr::null_mut(); // coverage: unreachable
            }

            // Set title
            let title_ns = ns_string_from_str(&title);
            let _: () = msg_send![win, setTitle: title_ns];

            // Set content view; the window retains it, so drop our +1.
            let _: () = msg_send![win, setContentView: view];
            let _: () = msg_send![view, release]; // coverage: unreachable

            // Release the title string (we created it with a temporary)
            let _: () = msg_send![title_ns, release];

            // The delegate refuses AppKit closes and posts WM_CLOSE instead;
            // releasedWhenClosed:NO keeps [NSWindow close] from releasing the
            // window behind DestroyWindow's back.
            let delegate = window_close_delegate(); // coverage: unreachable
            // Messaging a nil delegate is a harmless no-op, so no branch.
            let _: () = msg_send![win, setDelegate: delegate]; // coverage: unreachable
            let _: () = msg_send![win, setReleasedWhenClosed: 0 /* NO */]; // coverage: unreachable

            // Record ownership before the pointer escapes so close_nswindow
            // knows it must balance create's +1.
            mark_nswindow_owned(win as *mut std::ffi::c_void); // coverage: unreachable
            win as *mut std::ffi::c_void
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (title, x, y, width, height, style, ex_style);
        std::ptr::null_mut()
    }
}

/// Activate the host application.
///
/// macOS 14 deprecated `activateIgnoringOtherApps:` in favour of `activate`,
/// so prefer the modern selector when the running AppKit provides it.
#[cfg(target_os = "macos")]
// SAFETY: AppKit FFI for window management on macOS
unsafe fn activate_application() {
    let Some(app) = shared_nsapp() else {
        return;
    };
    // coverage: unreachable
    let app_obj: *mut objc::runtime::Object = app as *mut _; // coverage: unreachable
    let activate_selector = objc::sel!(activate); // coverage: unreachable
    let responds: bool = msg_send![app_obj, respondsToSelector: activate_selector]; // coverage: unreachable
    #[rustfmt::skip]
    let _: () = if responds { // coverage: unreachable
        msg_send![app_obj, activate] // coverage: unreachable
    } else {
        msg_send![app_obj, activateIgnoringOtherApps: 1 /* YES */] // coverage: unreachable
    }; // coverage: unreachable
}

/// Show (order front) or hide (order out) an NSWindow.
pub fn show_nswindow(ns_window: *mut std::ffi::c_void, show: bool) {
    show_nswindow_with_activation(ns_window, show, false);
}

/// Show/hide an NSWindow and optionally activate the host application.
///
/// Only the first eligible top-level, non-popup window (without
/// `WS_EX_NOACTIVATE`) is activated by user32; every other window is ordered
/// front without stealing focus from another application.
pub fn show_nswindow_with_activation(ns_window: *mut std::ffi::c_void, show: bool, activate: bool) {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if ns_window.is_null() {
                return;
            }
            let win: *mut objc::runtime::Object = ns_window as *mut _;
            if show {
                let _: () =
                    msg_send![win, makeKeyAndOrderFront: std::ptr::null_mut::<std::ffi::c_void>()];
                if activate {
                    activate_application();
                }
            } else {
                let _: () = msg_send![win, orderOut: std::ptr::null_mut::<std::ffi::c_void>()];
            }
        })
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (ns_window, show, activate);
}

/// Set the title of an NSWindow.
pub fn set_nswindow_title(ns_window: *mut std::ffi::c_void, title: &str) {
    // Convert &str to String for Send bound across the dispatch boundary.
    let title = title.to_string();
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if ns_window.is_null() {
                return;
            }
            let win: *mut objc::runtime::Object = ns_window as *mut _;
            let title_ns = ns_string_from_str(&title);
            let _: () = msg_send![win, setTitle: title_ns];
            let _: () = msg_send![title_ns, release];
        })
    }
    #[cfg(not(target_os = "macos"))]
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
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if ns_window.is_null() {
                return;
            }
            let win: *mut objc::runtime::Object = ns_window as *mut _;

            // macOS uses a flipped coordinate system where y=0 is bottom.
            // Flip against the primary screen (screens[0]), the origin of
            // Win32 screen coordinates.
            let primary_height = primary_screen_height().unwrap_or(height as f64); // coverage: unreachable
            let flipped_y = flip_y(primary_height, y, height);

            let frame = NSRect::new(
                NSPoint::new(x as f64, flipped_y),
                NSSize::new(width as f64, height as f64),
            );
            let _: () = msg_send![win, setFrame: frame display: 1 /* YES */ animate: 0 /* NO */];
        })
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (ns_window, x, y, width, height);
}

/// Force display refresh of an NSWindow.
pub fn update_nswindow(ns_window: *mut std::ffi::c_void) {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if ns_window.is_null() {
                return;
            }
            let win: *mut objc::runtime::Object = ns_window as *mut _;
            let _: () = msg_send![win, display];
        })
    }
    #[cfg(not(target_os = "macos"))]
    let _ = ns_window;
}

/// Get the content view NSView of an NSWindow.
pub fn nswindow_content_view(ns_window: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if ns_window.is_null() {
                return std::ptr::null_mut();
            }
            let win: *mut objc::runtime::Object = ns_window as *mut _;
            let view: *mut objc::runtime::Object = msg_send![win, contentView];
            view as *mut std::ffi::c_void
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = ns_window;
        std::ptr::null_mut()
    }
}

/// Get the current content (client) size of an NSWindow.
///
/// The content area excludes the title bar and frame borders, so user32 can
/// expose a `GetClientRect` distinct from the outer `GetWindowRect`.
pub fn nswindow_content_size(ns_window: *mut std::ffi::c_void) -> Option<(u32, u32)> {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if ns_window.is_null() {
                return None;
            }
            let win: *mut objc::runtime::Object = ns_window as *mut _;
            let content: NSRect = msg_send![win, contentLayoutRect];
            Some((
                content.size.width.max(0.0).round() as u32,
                content.size.height.max(0.0).round() as u32,
            ))
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = ns_window;
        None
    }
}

/// Remove any HWND→NSWindow association pointing at the given window pointer.
///
/// `[NSWindow close]` releases the window when `releasedWhenClosed` is set, so
/// any map entry left behind would dangle; this drops them.
fn remove_hwnd_nswindow_by_ptr(ns_window: *mut std::ffi::c_void) {
    if ns_window.is_null() {
        return;
    }
    let mut map = hwnd_to_nswindow_map().lock().unwrap();
    map.retain(|_hwnd, ptr| ptr.as_ptr() != ns_window);
}

/// Close and release an NSWindow.
pub fn close_nswindow(ns_window: *mut std::ffi::c_void) {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if ns_window.is_null() {
                return;
            }
            let win: *mut objc::runtime::Object = ns_window as *mut _;
            let _: () = msg_send![win, close];
            // `releasedWhenClosed` is NO (DestroyWindow is the only owner of
            // the window lifetime), so close does not release: drop our +1
            // from alloc/init here.  Drop the map entry first so a later
            // lookup cannot observe the freed pointer.
            remove_hwnd_nswindow_by_ptr(ns_window);
            let owned = owned_nswindows()
                .lock()
                .unwrap()
                .remove(&(ns_window as usize));
            if owned {
                let _: () = msg_send![win, release];
            }
        })
    }
    #[cfg(not(target_os = "macos"))]
    let _ = ns_window;
}

// ── NSView sublayer management ───────────────────────────────────────────

/// Add a CALayer as a sublayer of a view's layer.
pub fn add_sublayer_to_view(view_ptr: *mut std::ffi::c_void, layer_ptr: *mut std::ffi::c_void) {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if view_ptr.is_null() || layer_ptr.is_null() {
                return;
            }
            let view: *mut objc::runtime::Object = view_ptr as *mut _;
            let layer: *mut objc::runtime::Object = layer_ptr as *mut _;

            // Ensure the view is layer-backed
            let _: () = msg_send![view, setWantsLayer: 1 /* YES */];

            let sublayers: *mut objc::runtime::Object =
                msg_send![view, performSelector: objc::sel!(layer)];
            let _: () = msg_send![sublayers, addSublayer: layer];
        })
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (view_ptr, layer_ptr);
}

/// Set the frame of a CALayer sublayer.
pub fn set_layer_frame(layer_ptr: *mut std::ffi::c_void, x: f64, y: f64, width: f64, height: f64) {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if layer_ptr.is_null() {
                return;
            }
            let layer: *mut objc::runtime::Object = layer_ptr as *mut _;
            let frame = NSRect::new(NSPoint::new(x, y), NSSize::new(width, height));
            let _: () = msg_send![layer, setFrame: frame];
        })
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (layer_ptr, x, y, width, height);
}

// ── CAMetalLayer attachment ──────────────────────────────────────────────

/// Attach a pre-created CAMetalLayer (from a MetalSwapchain) to an NSWindow's
/// content view.
///
/// Unlike the old implementation, this function **does not** create a new
/// CAMetalLayer — it uses the layer already created and configured by the
/// MetalSwapchain (which has the correct pixel format, colour space, device,
/// etc. already set).  Only window-specific properties (contentsScale) and
/// the view-layer attachment are applied here.
///
/// `metal_layer_ptr` must be a valid `CAMetalLayer *`.
/// Returns the CAMetalLayer pointer on success, or null on failure.
pub fn attach_cametal_layer_to_window(
    ns_window: *mut std::ffi::c_void,
    metal_layer_ptr: *mut std::ffi::c_void,
    width: u32,
    height: u32,
) -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if ns_window.is_null() || metal_layer_ptr.is_null() {
                return std::ptr::null_mut();
            }

            let layer: *mut objc::runtime::Object = metal_layer_ptr as *mut _;

            // Set contentsScale for Retina / High-DPI support, then size the
            // drawable in *pixels* (drawableSize is pixel-based, so it must be
            // scaled by contentsScale or the layer renders at half resolution).
            let scale = get_backing_scale_factor(ns_window);
            let _: () = msg_send![layer, setContentsScale: scale];
            let size = NSSize::new((width as f64) * scale, (height as f64) * scale);
            let _: () = msg_send![layer, setDrawableSize: size];

            // Get the content view.
            let win: *mut objc::runtime::Object = ns_window as *mut _;
            let content_view: *mut objc::runtime::Object = msg_send![win, contentView];
            if content_view.is_null() {
                return std::ptr::null_mut();
            }

            // Ensure view is layer-backed.
            let _: () = msg_send![content_view, setWantsLayer: 1 /* YES */];

            // Attach the swapchain's existing Metal layer as the content view's
            // backing layer.  The layer already has device, pixelFormat, colour
            // space, opaque, framebufferOnly, presentsWithTransaction configured
            // by MetalSwapchain::new().
            let _: () = msg_send![content_view, setLayer: layer];

            layer as *mut std::ffi::c_void
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (ns_window, metal_layer_ptr, width, height);
        std::ptr::null_mut()
    }
}

// ── NSEvent polling for message pump ─────────────────────────────────────

/// Poll a single NSEvent from the event queue (non-blocking).
/// Returns the raw NSEvent pointer, or null if no event available.
pub fn poll_nsevent() -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            // NSEventType constants
            // NSEventMaskAny = NSULongMax
            let mask: u64 = !0u64;
            // NSDefaultRunLoopMode is an NSString* constant, not an ObjC class
            // (Class::get("NSDefaultRunLoopMode") always failed). Fetch it via
            // the NSRunLoop class method; the returned constant needs no release.
            let mode: *mut std::ffi::c_void = {
                let cls = match objc::runtime::Class::get("NSRunLoop") {
                    Some(c) => c,
                    None => return std::ptr::null_mut(),
                };
                let mode_obj: *mut objc::runtime::Object = msg_send![cls, defaultRunLoopMode];
                mode_obj as *mut std::ffi::c_void
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
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        std::ptr::null_mut()
    }
}

/// Get the NSEventType of an NSEvent.
pub fn nsevent_type(event: *mut std::ffi::c_void) -> u64 {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
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
    // SAFETY: AppKit FFI for window management on macOS
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
    // SAFETY: AppKit FFI for window management on macOS
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
    // SAFETY: AppKit FFI for window management on macOS
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
    // SAFETY: AppKit FFI for window management on macOS
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
        let s = std::ffi::CStr::from_ptr(cstr)
            .to_string_lossy()
            .into_owned();
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
    // SAFETY: AppKit FFI for window management on macOS
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
    // SAFETY: AppKit FFI for window management on macOS
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
    // SAFETY: AppKit FFI for window management on macOS
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
    // SAFETY: AppKit FFI for window management on macOS
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
///
/// Returns null if:
/// - NSApp has not been initialized (calling `[NSWindow windowWithWindowNumber:]`
///   without NSApp raises an ObjC exception that Rust cannot catch).
/// - No window with the given number exists.
/// - The `NSWindow` class is unavailable.
pub fn nswindow_from_number(window_number: i32) -> *mut std::ffi::c_void {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        // `[NSWindow windowWithWindowNumber:]` internally uses NSApp; calling it
        // without an initialized NSApp raises an uncatchable ObjC exception.
        if !nsapp_initialized() {
            return std::ptr::null_mut();
        }
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
// SAFETY: Objective-C runtime class lookup and instance creation
unsafe fn ns_string_from_str(s: &str) -> *mut objc::runtime::Object {
    #[cfg(target_os = "macos")]
    // SAFETY: Objective-C runtime class lookup and instance creation
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

// ── Headless detection ────────────────────────────────────────────────────

/// Returns `true` if the current process is running in a headless environment
/// where AppKit screen/window/pasteboard APIs should not be called.
///
/// A process is considered headless when:
/// - It is not running inside a `.app` bundle, **and**
/// - `NSApplication` has not been initialized, **and**
/// - Force window creation mode has not been enabled.
///
/// When headless, callers should use software fallbacks instead of AppKit.
pub fn is_headless() -> bool {
    #[cfg(target_os = "macos")]
    {
        // If NSApp has been initialized, we are not headless.
        if is_nsapp_initialized() {
            return false;
        }
        // If force window creation is active, treat as not headless.
        if force_window_creation() {
            return false;
        }
        // If running as an app bundle, not headless.
        if process_is_app_bundle() {
            return false;
        }
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

// ── NSPasteboard clipboard integration ────────────────────────────────────
//
// These functions use macOS NSPasteboard via Objective-C FFI to provide
// real clipboard integration for the Win32 clipboard APIs.
//
// In headless mode (CLI tools, test binaries), these functions return
// default values without calling AppKit APIs.

/// Open the macOS general pasteboard and clear its contents.
/// Returns true on success.
///
/// In headless mode, returns `false` without calling AppKit.
pub fn nspasteboard_clear() -> bool {
    #[cfg(target_os = "macos")]
    {
        // In headless processes (CLI/test binaries) there is no main loop
        // pumping the dispatch queue, so block before dispatching rather than
        // inside the queued closure (which would hang forever).
        if is_headless() {
            return false;
        }
    }
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            // Guard: skip AppKit call in headless mode.
            if is_headless() {
                return false;
            }
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
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Set string data on the macOS general pasteboard for a given format.
/// Maps Win32 clipboard format identifiers to NSPasteboard types:
/// - CF_TEXT / CF_OEMTEXT → NSPasteboardTypeString (public.utf8-plain-text)
/// - CF_UNICODETEXT → NSPasteboardTypeString
///
/// All other formats are stored as raw data with a custom type.
/// Returns true on success.
pub fn nspasteboard_set_data(format: u32, data: &[u8]) -> bool {
    // Convert &[u8] to Vec<u8> for Send bound across the dispatch boundary.
    let data = data.to_vec();
    #[cfg(target_os = "macos")]
    {
        // In headless processes (CLI/test binaries) there is no main loop
        // pumping the dispatch queue, so block before dispatching rather than
        // inside the queued closure (which would hang forever).
        if is_headless() {
            return false;
        }
    }
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            // Guard: skip AppKit call in headless mode.
            if is_headless() {
                return false;
            }
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
                13 => (true, "public.utf8-plain-text"),    // CF_UNICODETEXT
                _ => (false, "public.data"),               // raw data
            };

            if is_string {
                // Convert bytes to NSString
                let s = std::str::from_utf8(&data).unwrap_or("");
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
        })
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
    {
        // In headless processes (CLI/test binaries) there is no main loop
        // pumping the dispatch queue, so block before dispatching rather than
        // inside the queued closure (which would hang forever).
        if is_headless() {
            return None;
        }
    }
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            // Guard: skip AppKit call in headless mode.
            if is_headless() {
                return None;
            }
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
        })
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
    {
        // In headless processes (CLI/test binaries) there is no main loop
        // pumping the dispatch queue, so block before dispatching rather than
        // inside the queued closure (which would hang forever).
        if is_headless() {
            return false;
        }
    }
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            // Guard: skip AppKit call in headless mode.
            if is_headless() {
                return false;
            }
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
            let ns_array: *mut objc::runtime::Object =
                msg_send![objc::runtime::Class::get("NSArray").unwrap(), arrayWithObject: type_obj];
            // `availableTypeFromArray:` returns an NSString* (or nil). Reading
            // it as a bool would only look at the low byte of the pointer and
            // yield false negatives for 256-byte-aligned objects.
            let available: *mut objc::runtime::Object =
                msg_send![pasteboard, availableTypeFromArray: ns_array];
            let _: () = msg_send![pb_type_ns, release];
            !available.is_null()
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = format;
        false
    }
}

/// Helper: create an NSString from a Rust &str (returns a retained object).
#[cfg(target_os = "macos")]
// SAFETY: Objective-C runtime class lookup and instance creation
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

/// Flash the NSWindow's dock icon to indicate attention is needed.
/// This calls `[NSApplication requestUserAttention:]` on macOS.
/// On non-macOS platforms this is a no-op.
pub fn flash_nswindow(_hwnd: u32, flash: bool) -> bool {
    #[cfg(target_os = "macos")]
    // SAFETY: AppKit FFI for window management on macOS
    unsafe {
        run_on_main(move || {
            if !flash {
                // Nothing requested — success (no-op).
                return true;
            }
            use objc::runtime::Object;
            let app_cls = match objc::runtime::Class::get("NSApplication") {
                Some(c) => c,
                None => return false,
            };
            let shared_app: *mut Object = msg_send![app_cls, sharedApplication];
            if shared_app.is_null() {
                return false;
            }
            // NSInformationalRequest = 0, NSCriticalRequest = 1.
            // `requestUserAttention:` returns void — do not read a return value.
            let _: () = msg_send![shared_app, requestUserAttention: 0u64];
            true
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (_hwnd, flash);
        false
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use objc::Encode;

    static ASSOCIATION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn on_main_thread() -> bool {
        // SAFETY: pthread_main_np is a simple POSIX query.
        unsafe { libc::pthread_main_np() != 0 }
    }

    // ── NSPoint / NSSize / NSRect ─────────────────────────────────────────

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
    const WS_OVERLAPPEDWINDOW: u32 =
        WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
    const WS_POPUPWINDOW: u32 = WS_POPUP | WS_BORDER | WS_SYSMENU;
    const WS_OVERLAPPED: u32 = 0x0000_0000;

    const NSWindowStyleMaskBorderless: i32 = 0;
    const NSWindowStyleMaskTitled: i32 = 1;
    const NSWindowStyleMaskClosable: i32 = 2;
    const NSWindowStyleMaskMiniaturizable: i32 = 4;
    const NSWindowStyleMaskResizable: i32 = 8;

    // ── HWND ↔ NSWindow association ───────────────────────────────────────

    // ── Layer frame helpers ───────────────────────────────────────────────

    // ── NSEvent query helpers (non-macOS stubs) ───────────────────────────

    #[test]
    fn flip_y_secondary_screen_height_mismatch_is_rejected() {
        // Primary 1080p: y=0 is the top edge, so a 100px window starts at 980.
        assert_eq!(flip_y(1080.0, 0, 100), 980.0);
        assert_eq!(flip_y(1080.0, 200, 50), 830.0);
        // Flipping against a different display height is a mismatch.
        assert_ne!(flip_y(1080.0, 0, 100), flip_y(1440.0, 0, 100));
    }

    fn pump_until_queued() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while MAIN_QUEUE.pending.lock().unwrap().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "background run_on_main never enqueued"
            );
            std::thread::yield_now();
        }
        drain_main_queue();
    }

    #[test]
    fn run_on_main_background_worker_boundary_completes_and_propagates_panic() {
        let worker = std::thread::spawn(|| run_on_main(|| 7_i32));
        pump_until_queued();
        assert_eq!(worker.join().expect("worker"), 7);

        let panicking =
            std::thread::spawn(|| run_on_main(|| -> i32 { panic!("casa1-run-on-main-panic") }));
        pump_until_queued();
        assert_eq!(panicking.join().is_err(), true);
    }

    #[test]
    fn window_close_delegate_no_duplicate_close_boundary() {
        let _lock = CLOSE_QUEUE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = take_pending_close_requests();
        // SAFETY: the delegate class/method is registered by this call.
        let delegate = unsafe { window_close_delegate() };
        assert_eq!(delegate.is_null(), false);
        assert_eq!(unsafe { window_close_delegate() }, delegate);

        let sender = 0x1000_usize as *mut objc::runtime::Object;
        associate_hwnd_nswindow(0x00c0_1234, sender as *mut std::ffi::c_void);
        let returned: i8 = unsafe { msg_send![delegate, windowShouldClose: sender] };
        assert_eq!(returned, 0);
        assert_eq!(take_pending_close_requests(), vec![0x00c0_1234]);

        let null_sender = std::ptr::null_mut::<objc::runtime::Object>();
        let returned: i8 = unsafe { msg_send![delegate, windowShouldClose: null_sender] };
        assert_eq!(returned, 0);
        assert_eq!(take_pending_close_requests(), Vec::<u32>::new());
        let _ = remove_hwnd_nswindow(0x00c0_1234);
    }

    #[test]
    fn pending_close_requests_drain_exactly_once_no_duplicate() {
        let _lock = CLOSE_QUEUE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = take_pending_close_requests();
        queue_close_request_for_test(0x00c0_ffee);
        assert_eq!(take_pending_close_requests(), vec![0x00c0_ffee]);
        assert_eq!(take_pending_close_requests(), Vec::<u32>::new());
    }

    #[test]
    fn pump_main_queue_panicking_item_never_blocks_completion() {
        let done = Arc::new((
            Mutex::new(MainQueueCompletion {
                done: false,
                panic: None,
            }),
            Condvar::new(),
        ));
        MAIN_QUEUE.pending.lock().unwrap().push_back(MainQueueItem {
            work: Box::new(|| panic!("casa1-test-main-queue-panic")),
            done: Arc::clone(&done),
        });
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ran_clone = Arc::clone(&ran);
        let second_done = Arc::new((
            Mutex::new(MainQueueCompletion {
                done: false,
                panic: None,
            }),
            Condvar::new(),
        ));
        MAIN_QUEUE.pending.lock().unwrap().push_back(MainQueueItem {
            work: Box::new(move || {
                ran_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            }),
            done: Arc::clone(&second_done),
        });

        // A panicking item must not propagate out of the pump.
        drain_main_queue();

        let (lock, _) = &*done;
        assert_eq!(lock.lock().unwrap().done, true);
        assert_eq!(ran.load(std::sync::atomic::Ordering::SeqCst), true);
        let (second_lock, _) = &*second_done;
        assert_eq!(second_lock.lock().unwrap().done, true);
    }
}
