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
    use objc::runtime::{Object, sel_registerName};

    /// Register the kAEGetURL AppleEvent handler.
    ///
    /// This hooks into the macOS event dispatch system to receive URL
    /// activation events (e.g., when a user clicks a steam:// link in a
    /// browser). When received, the URL is forwarded to Casa1's
    /// `SteamProtocolIntegration` for parsing and dispatch.
    pub fn register_url_event_handler() {
        unsafe {
            let ns_app = class!(NSApplication);
            let shared_app: *mut Object = msg_send![ns_app, sharedApplication];

            let apple_event_mgr = class!(NSAppleEventManager);
            let shared_mgr: *mut Object = msg_send![apple_event_mgr, sharedAppleEventManager];

            // kAEGetURL = 'GURL'
            let gurl: u32 = 0x4755524c; // 'GURL' as FourCharCode

            // Set the handler for kAEGetURL events.
            // sel_registerName expects *const i8
            let selector = sel_registerName(c"handleGetURLEvent:withReplyEvent:".as_ptr());
            let _: () = msg_send![shared_mgr,
                setEventHandler: shared_app
                andSelector: selector
                forEventClass: gurl
                andEventID: gurl
            ];

            // Also handle 'GURL' as kEventClassInternet / 'GURL' (kAEInternetEvent)
            let _: () = msg_send![shared_mgr,
                setEventHandler: shared_app
                andSelector: selector
                forEventClass: 0x696E6574 // 'inet' as FourCharCode
                andEventID: gurl
            ];
        }

        let integration = SteamProtocolIntegration::new_registered();
        eprintln!(
            "[Casa1Helper] Registered steam:// URL handler (handler={})",
            integration.handler.is_registered(),
        );
    }

    /// Handle a single steam:// URL activation.
    ///
    /// This is called when the helper receives a URL from the macOS event
    /// system or from the command line.
    pub fn handle_steam_url(url: &str) -> bool {
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
                // Just register the protocol handler and exit
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
        // Register the macOS URL event handler so that future steam://
        // URL activations are received even after startup.
        macos_url_handler::register_url_event_handler();
    }

    // Process any steam:// URLs passed as command-line arguments
    let has_protocol_url = args.iter().any(|a| a.starts_with("steam://"));

    if has_protocol_url {
        #[cfg(target_os = "macos")]
        {
            let handled = macos_url_handler::process_command_line_urls();
            if handled {
                std::process::exit(0);
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            // Non-macOS: still try to handle steam:// URLs
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
