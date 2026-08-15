//! Casa1 Helper Binary
//!
//! On macOS, this binary serves as the handler for steam:// URL protocol
//! activations. When the user clicks a steam:// link in a browser, macOS
//! activates this binary and passes the URL as a command-line argument or
//! via the NSAppleEventManager `kAEGetURL` event.
//!
//! This module sets up an NSAppleEventManager handler that receives URL
//! activation events from the macOS system and forwards them to Casa1's
//! Steam protocol handler for parsing and dispatch.

#[macro_use]
extern crate objc;

#[cfg(target_os = "macos")]
mod macos_url_handler {
    use casa1::steam_integration::SteamProtocolIntegration;
    use casa1::steam_protocol::SteamProtocolDispatchResult;
    use objc::runtime::{Class, Imp, Object, Sel, sel_registerName};
    use std::ffi::{CStr, c_char};
    use std::sync::OnceLock;

    /// kAEGetURL direct parameter ('----').
    const KEY_DIRECT_OBJECT: u32 = 0x2D2D_2D2D;

    /// Dynamically-created NSObject subclass that implements
    /// `handleGetURLEvent:withReplyEvent:`.  `NSApplication` itself does not
    /// implement that selector, so registering it as the event-handler
    /// target would raise an unrecognized-selector exception when an
    /// AppleEvent is delivered.  Stored as `usize` so the `OnceLock` stays
    /// `Send + Sync`.
    static URL_HANDLER_CLASS: OnceLock<usize> = OnceLock::new();

    /// Obtain (creating on first use) the URL-handler NSObject subclass.
    ///
    /// SAFETY: the returned class pointer is valid for the lifetime of the
    /// process; the class is registered exactly once.
    fn url_handler_class() -> *mut Class {
        *URL_HANDLER_CLASS.get_or_init(|| unsafe {
            let superclass = class!(NSObject);
            let name = c"Casa1HelperURLHandler".as_ptr();
            let cls = objc::runtime::objc_allocateClassPair(superclass, name, 0);
            if cls.is_null() {
                // Class already exists (e.g. previous registration in the
                // same process): look it up instead.
                return (class!(Casa1HelperURLHandler) as *const Class as *mut Class) as usize;
            }
            let sel = sel_registerName(c"handleGetURLEvent:withReplyEvent:".as_ptr());
            // "v@:@@" = void return, self, _cmd, event, reply.
            let types = c"v@:@@".as_ptr();
            let handler: unsafe extern "C" fn(*mut Object, Sel, *mut Object, *mut Object) =
                url_event_handler;
            // SAFETY: function pointers are all pointer-sized; ObjC calls
            // through the declared method signature.
            let imp: Imp = std::mem::transmute(handler);
            objc::runtime::class_addMethod(cls, sel, imp, types);
            objc::runtime::objc_registerClassPair(cls);
            cls as usize
        }) as *mut Class
    }

    /// Forward a single steam:// URL to the Steam integration.
    fn handle_steam_url(url: &str) -> bool {
        let integration = SteamProtocolIntegration::new();
        match integration.handle_url(url) {
            SteamProtocolDispatchResult::Handled
            | SteamProtocolDispatchResult::ShowFriends
            | SteamProtocolDispatchResult::NavigateSection(_)
            | SteamProtocolDispatchResult::NavigateBrowser(_) => {
                eprintln!("[Casa1Helper] Handled steam:// URL: {url}");
                true
            }
            SteamProtocolDispatchResult::LaunchGame(app_id, action) => {
                eprintln!(
                    "[Casa1Helper] Launching game {app_id} (action={:?})",
                    action.unwrap_or_default()
                );
                // In production, this would call into the game execution
                // pipeline (Phase 4).
                true
            }
            SteamProtocolDispatchResult::InstallGame(app_id) => {
                eprintln!("[Casa1Helper] Installing game {app_id}");
                // In production, this would trigger the CDN download pipeline.
                true
            }
            SteamProtocolDispatchResult::Unrecognized(cmd) => {
                eprintln!("[Casa1Helper] Unrecognized command: {cmd}");
                false
            }
            SteamProtocolDispatchResult::Error(msg) => {
                eprintln!("[Casa1Helper] Error handling URL: {msg}");
                false
            }
        }
    }

    /// Objective-C method implementation of
    /// `handleGetURLEvent:withReplyEvent:` on the Casa1HelperURLHandler class.
    ///
    /// Extracts the URL from the AppleEvent's direct parameter and forwards
    /// it to the Steam integration.
    ///
    /// SAFETY: called by the ObjC runtime with valid `self`/`_cmd`; `event`
    /// is an NSAppleEventDescriptor pointer when non-null.
    unsafe extern "C" fn url_event_handler(
        _this: *mut Object,
        _cmd: Sel,
        event: *mut Object,
        _reply: *mut Object,
    ) {
        if event.is_null() {
            eprintln!("[Casa1Helper] AppleEvent with null event object");
            return;
        }
        let descriptor: *mut Object =
            msg_send![event, paramDescriptorForKeyword: KEY_DIRECT_OBJECT];
        if descriptor.is_null() {
            eprintln!("[Casa1Helper] AppleEvent missing direct object");
            return;
        }
        let url_string: *mut Object = msg_send![descriptor, stringValue];
        if url_string.is_null() {
            eprintln!("[Casa1Helper] AppleEvent direct object is not a string");
            return;
        }
        let c_string: *const c_char = msg_send![url_string, UTF8String];
        if c_string.is_null() {
            eprintln!("[Casa1Helper] AppleEvent URL string has no UTF-8 bytes");
            return;
        }
        // SAFETY: `UTF8String` returns a NUL-terminated C string for the
        // lifetime of `url_string`, which is alive for the whole call.
        let url = unsafe { CStr::from_ptr(c_string) }
            .to_string_lossy()
            .to_string();
        eprintln!("[Casa1Helper] AppleEvent steam:// URL: {url}");
        handle_steam_url(&url);
    }

    /// Register the kAEGetURL AppleEvent handler.
    ///
    /// This hooks into the macOS event dispatch system to receive URL
    /// activation events (e.g., when a user clicks a steam:// link in a
    /// browser). When received, the URL is forwarded to Casa1's
    /// `SteamProtocolIntegration` for parsing and dispatch.  The handler is
    /// installed on a dedicated NSObject subclass that implements the
    /// selector, never on `NSApplication` itself.
    pub fn register_url_event_handler() {
        unsafe {
            let apple_event_mgr = class!(NSAppleEventManager);
            let shared_mgr: *mut Object = msg_send![apple_event_mgr, sharedAppleEventManager];
            if shared_mgr.is_null() {
                eprintln!("[Casa1Helper] NSAppleEventManager unavailable; URL handler not registered");
                return;
            }

            // kAEGetURL = 'GURL'
            let gurl: u32 = 0x4755_524c; // 'GURL' as FourCharCode

            let handler_class = url_handler_class();
            let handler: *mut Object = msg_send![handler_class, new];

            // Set the handler for kAEGetURL events.
            // sel_registerName expects *const i8
            let selector = sel_registerName(c"handleGetURLEvent:withReplyEvent:".as_ptr());
            let _: () = msg_send![shared_mgr,
                setEventHandler: handler
                andSelector: selector
                forEventClass: gurl
                andEventID: gurl
            ];

            // Also handle 'GURL' as kEventClassInternet / 'GURL' (kAEInternetEvent)
            let _: () = msg_send![shared_mgr,
                setEventHandler: handler
                andSelector: selector
                forEventClass: 0x696E_6574 // 'inet' as FourCharCode
                andEventID: gurl
            ];

            // The event manager retains the handler object.
            let _: () = msg_send![handler, release];
        }

        let integration = SteamProtocolIntegration::new_registered();
        eprintln!(
            "[Casa1Helper] Registered steam:// URL handler (handler={})",
            integration.handler.is_registered(),
        );
    }

    /// Process command-line arguments for steam:// URLs.
    ///
    /// macOS passes steam:// URLs as command-line arguments to the helper
    /// binary. This function extracts and processes them.
    pub fn process_command_line_urls() -> bool {
        let args: Vec<String> = std::env::args().collect();
        let mut handled_any = false;

        // Skip the first argument (program name)
        for arg in &args[1..] {
            if arg.starts_with("steam://") {
                if handle_steam_url(arg) {
                    handled_any = true;
                }
            } else if arg == "-silent" || arg == "--silent" {
                // Silently handle; no output needed
                handled_any = true;
            } else if arg == "-register" || arg == "--register" {
                // Just register the protocol handler and exit.
                // (main() also handles this fast path before calling us, so
                // registration happens exactly once per invocation.)
                register_url_event_handler();
                std::process::exit(0);
            }
        }

        handled_any
    }
}

fn main() {
    // Check if we have steam:// URLs on the command line
    let args: Vec<String> = std::env::args().collect();

    #[cfg(target_os = "macos")]
    {
        let has_protocol_url = args.iter().any(|a| a.starts_with("steam://"));
        let wants_register = args.iter().any(|a| a == "-register" || a == "--register");

        if wants_register {
            // Fast path: register the handler and exit without touching the
            // diagnostics fallback (registration is NOT run twice).
            macos_url_handler::register_url_event_handler();
            std::process::exit(0);
        }

        if has_protocol_url {
            // Process the steam:// URLs passed on the command line directly;
            // skip the unconditional registration so it does not double-run.
            let handled = macos_url_handler::process_command_line_urls();
            if handled {
                std::process::exit(0);
            }
        } else {
            // No URL work: install the AppleEvent handler so an already
            // running helper instance can receive steam:// activations,
            // then fall through to the diagnostics entry point.
            macos_url_handler::register_url_event_handler();
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Non-macOS: still try to handle steam:// URLs
        if args.iter().any(|a| a.starts_with("steam://")) {
            let integration = SteamProtocolIntegration::new();
            for arg in &args[1..] {
                if arg.starts_with("steam://") {
                    let dispatched = integration.dispatch_url(arg);
                    if dispatched {
                        eprintln!("[Casa1Helper] Handled: {arg}");
                    } else {
                        eprintln!("[Casa1Helper] Failed to handle: {arg}");
                    }
                }
            }
            std::process::exit(0);
        }
    }

    // If no steam:// URLs, fall back to the normal helper main function.
    std::process::exit(casa1::diagnostics::helper_main(std::env::args_os()));
}
