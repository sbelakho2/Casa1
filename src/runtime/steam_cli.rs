//! Steam command-line argument parsing (verbatim).

// ---------------------------------------------------------------------------
// Steam Command-Line Argument Processing
//
// Steam.exe accepts a variety of command-line arguments that control its
// startup behavior. These are parsed before the PE runtime begins execution
// to configure the environment appropriately.
//
// Common Steam command-line flags:
//   -applaunch <appid> [args...]    Launch a game with optional arguments
//   -silent                         Start minimized to tray
//   -login <username> <password>    Auto-login with credentials
//   -dev                            Developer mode
//   -console                        Enable developer console
//   -no-browser                     Skip CEF/WKWebView initialization
//   -offline                        Start in offline mode
//   -bigpicture / -tenfoot          Start in Big Picture mode
//   steam://run/<appid>             Direct protocol URL
// ---------------------------------------------------------------------------

/// Steam command-line flags parsed from the program arguments.
#[derive(Debug, Clone, Default)]
pub struct SteamCliFlags {
    /// Launch a game with the given app ID.
    pub applaunch: Option<u32>,
    /// Additional arguments for -applaunch.
    pub applaunch_args: Vec<String>,
    /// Start minimized to the system tray.
    pub silent: bool,
    /// Auto-login username.
    pub login_username: Option<String>,
    /// Auto-login password.
    pub login_password: Option<String>,
    /// Enable developer mode.
    pub dev: bool,
    /// Enable developer console.
    pub console: bool,
    /// Skip browser (CEF) initialization.
    pub no_browser: bool,
    /// Start in offline mode.
    pub offline: bool,
    /// Start in Big Picture mode.
    pub big_picture: bool,
}

impl SteamCliFlags {
    /// Parse Steam command-line flags from the program arguments.
    ///
    /// This only processes flags that come after the program name, which is
    /// the standard convention for Steam.exe invocations.
    pub fn parse(args: &[String]) -> Self {
        let mut flags = Self::default();
        let mut i = 0;

        while i < args.len() {
            let arg = &args[i];

            // Direct steam:// protocol URL
            if arg.starts_with("steam://") {
                // Protocol URLs are handled by SteamProtocolHandler;
                // we mark them here for tracing.
                if arg.contains("/run/") || arg.contains("/launch/") {
                    // Extract app_id from the URL
                    for part in arg.split('/') {
                        if let Ok(id) = part.parse::<u32>() {
                            flags.applaunch = Some(id);
                            break;
                        }
                    }
                }
                i += 1;
                continue;
            }

            match arg.as_str() {
                "-applaunch" | "-launch" => {
                    if i + 1 < args.len()
                        && let Ok(id) = args[i + 1].parse::<u32>()
                    {
                        flags.applaunch = Some(id);
                        i += 2;
                        // Collect game-specific arguments (everything up
                        // to the next flag)
                        while i < args.len() && !args[i].starts_with('-') {
                            flags.applaunch_args.push(args[i].clone());
                            i += 1;
                        }
                        continue;
                    }
                }
                "-silent" | "-silentlaunch" => {
                    flags.silent = true;
                }
                "-login" => {
                    if i + 1 < args.len() {
                        flags.login_username = Some(args[i + 1].clone());
                        i += 1;
                    }
                    if i + 1 < args.len() {
                        flags.login_password = Some(args[i + 1].clone());
                        i += 1;
                    }
                }
                "-dev" => {
                    flags.dev = true;
                }
                "-console" => {
                    flags.console = true;
                }
                "-no-browser" | "-nobrowser" => {
                    flags.no_browser = true;
                }
                "-offline" => {
                    flags.offline = true;
                }
                "-bigpicture" | "-tenfoot" => {
                    flags.big_picture = true;
                }
                _ => {
                    // Unknown flag or positional argument — ignore
                }
            }
            i += 1;
        }

        flags
    }

    /// Check whether any game launch flags were specified.
    pub fn has_launch_command(&self) -> bool {
        self.applaunch.is_some()
    }

    /// Get the app ID to launch, if any.
    pub fn launch_app_id(&self) -> Option<u32> {
        self.applaunch
    }
}

/// Process Steam command-line arguments and return the parsed flags.
///
/// This is called by `execute_with_options` when the program being executed
/// is Steam.exe or any Steam-related binary, allowing the PE runtime to
/// configure behavior based on command-line flags before execution begins.
pub fn process_steam_command_line(args: &[String]) -> SteamCliFlags {
    SteamCliFlags::parse(args)
}

/// Check whether a set of args contains a steam:// protocol URL.
pub fn has_steam_protocol_url(args: &[String]) -> bool {
    args.iter().any(|arg| arg.starts_with("steam://"))
}

/// Extract all steam:// protocol URLs from a list of arguments.
pub fn extract_steam_protocol_urls(args: &[String]) -> Vec<String> {
    args.iter()
        .filter(|arg| arg.starts_with("steam://"))
        .cloned()
        .collect()
}
