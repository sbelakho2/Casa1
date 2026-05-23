//! macOS `.app` Bundle Generator for Casa1.
//!
//! Creates standard macOS `.app` bundles for installed Windows applications,
//! including `Info.plist`, wrapper executable, icon resources, and Launch
//! Services registration.
//!
//! ## Bundle Structure
//! ```text
//! Foo.app/
//!   Contents/
//!     Info.plist
//!     PkgInfo
//!     MacOS/
//!       casa1-wrapper   (executable script)
//!     Resources/
//!       icon.icns
//!     Frameworks/
//! ```

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Configuration for creating an app bundle.
#[derive(Debug, Clone, Serialize)]
pub struct AppBundleConfig {
    /// Display name of the application.
    pub app_name: String,
    /// The executable to launch (path inside the GE filesystem).
    pub executable_path: String,
    /// Optional arguments to pass to the executable.
    pub args: Option<String>,
    /// The GE directory name to use when launching.
    pub ge_name: String,
    /// Optional ICNS icon data.
    pub icon_data: Option<Vec<u8>>,
    /// Optional bundle identifier (defaults to com.casa1.<normalized_name>).
    pub bundle_id: Option<String>,
    /// Minimum macOS version (defaults to "14.0").
    pub min_system_version: Option<String>,
    /// Whether the app supports high resolutions (defaults to true).
    pub high_resolution: Option<bool>,
    /// URL schemes to register (e.g., "steam").
    pub url_schemes: Vec<String>,
    /// NSApplication category (defaults to "public.app-category.utilities").
    pub app_category: Option<String>,
}

impl Default for AppBundleConfig {
    fn default() -> Self {
        Self {
            app_name: String::new(),
            executable_path: String::new(),
            args: None,
            ge_name: String::new(),
            icon_data: None,
            bundle_id: None,
            min_system_version: Some("14.0".to_string()),
            high_resolution: Some(true),
            url_schemes: Vec::new(),
            app_category: Some("public.app-category.utilities".to_string()),
        }
    }
}

/// Normalize an app name to a valid bundle identifier component.
fn normalize_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '-' })
        .collect();
    sanitized.trim_matches('-').to_lowercase()
}

/// Generate a bundle identifier from app name.
fn generate_bundle_id(app_name: &str) -> String {
    let normalized = normalize_name(app_name);
    if normalized.is_empty() {
        "com.casa1.unknown".to_string()
    } else {
        format!("com.casa1.{}", normalized)
    }
}

/// Generate the Contents/Info.plist XML content.
fn generate_info_plist(config: &AppBundleConfig) -> String {
    let bundle_id = config
        .bundle_id
        .clone()
        .unwrap_or_else(|| generate_bundle_id(&config.app_name));
    let min_version = config
        .min_system_version
        .as_deref()
        .unwrap_or("14.0");
    let high_res = config.high_resolution.unwrap_or(true);
    let app_cat = config
        .app_category
        .as_deref()
        .unwrap_or("public.app-category.utilities");

    let mut plist = String::new();
    plist.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    plist.push_str(r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">"#);
    plist.push_str(r#"<plist version="1.0">"#);
    plist.push_str(r#"<dict>"#);

    // Basic bundle metadata
    plist.push_str(&format!(
        r#"<key>CFBundleExecutable</key><string>casa1-wrapper</string>"#
    ));
    plist.push_str(&format!(
        r#"<key>CFBundleIdentifier</key><string>{}</string>"#,
        xml_escape(&bundle_id)
    ));
    plist.push_str(&format!(
        r#"<key>CFBundleName</key><string>{}</string>"#,
        xml_escape(&config.app_name)
    ));
    plist.push_str(&format!(
        r#"<key>CFBundleDisplayName</key><string>{}</string>"#,
        xml_escape(&config.app_name)
    ));
    plist.push_str(&format!(
        r#"<key>CFBundleIconFile</key><string>icon</string>"#
    ));
    plist.push_str(&format!(
        r#"<key>CFBundlePackageType</key><string>APPL</string>"#
    ));
    plist.push_str(&format!(
        r#"<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>"#
    ));
    plist.push_str(&format!(
        r#"<key>CFBundleVersion</key><string>1</string>"#
    ));
    plist.push_str(&format!(
        r#"<key>CFBundleShortVersionString</key><string>1.0</string>"#
    ));
    plist.push_str(&format!(
        r#"<key>LSMinimumSystemVersion</key><string>{}</string>"#,
        xml_escape(min_version)
    ));
    plist.push_str(&format!(
        r#"<key>NSHighResolutionCapable</key><{}/>"#,
        if high_res { "true" } else { "false" }
    ));
    plist.push_str(&format!(
        r#"<key>LSApplicationCategoryType</key><string>{}</string>"#,
        xml_escape(app_cat)
    ));

    // Document types (optional, for future use)
    // URL schemes
    if !config.url_schemes.is_empty() {
        plist.push_str(r#"<key>CFBundleURLTypes</key><array>"#);
        for scheme in &config.url_schemes {
            plist.push_str(r#"<dict>"#);
            plist.push_str(r#"<key>CFBundleURLName</key>"#);
            plist.push_str(&format!(
                r#"<string>{}</string>"#,
                xml_escape(&format!("{} URL", scheme))
            ));
            plist.push_str(r#"<key>CFBundleURLSchemes</key><array>"#);
            plist.push_str(&format!(r#"<string>{}</string>"#, xml_escape(scheme)));
            plist.push_str(r#"</array>"#);
            plist.push_str(r#"</dict>"#);
        }
        plist.push_str(r#"</array>"#);
    }

    plist.push_str(r#"</dict>"#);
    plist.push_str(r#"</plist>"#);
    plist
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
}

/// Generate the casa1-wrapper shell script.
fn generate_wrapper_script(config: &AppBundleConfig) -> String {
    let exe_path = &config.executable_path;
    let ge_name = &config.ge_name;
    let args_str = match &config.args {
        Some(a) => {
            let quoted = shlex::try_quote(a).unwrap_or_else(|_| std::borrow::Cow::Owned(a.clone()));
            format!("--args {}", quoted)
        }
        None => String::new(),
    };

    format!(
        r#"#!/bin/bash
# Casa1 App Wrapper for {}
# Generated by Casa1 v{}
# This script launches the Windows application inside the Casa1 guest environment.

CASA1_BIN="$(cd "$(dirname "$0")/../../.." && pwd)/casa1"
if [ ! -x "$CASA1_BIN" ]; then
    CASA1_BIN="$(command -v casa1)"
fi
if [ ! -x "$CASA1_BIN" ]; then
    CASA1_BIN="$(command -v macwin)"
fi
if [ ! -x "$CASA1_BIN" ]; then
    osascript -e 'display dialog "Casa1 could not be found. Please install Casa1 and try again." buttons {{"OK"}} default button "OK"'
    exit 1
fi

exec "$CASA1_BIN" ge:run --ge "{}" --exe "{}" {}
"#,
        config.app_name,
        env!("CARGO_PKG_VERSION"),
        ge_name,
        exe_path,
        args_str,
    )
}

/// Generate the PkgInfo file (optional but standard).
fn generate_pkginfo() -> Vec<u8> {
    b"APPLcasa".to_vec()
}

/// Create a macOS `.app` bundle for a Windows application.
///
/// Returns the path to the created `.app` bundle.
pub fn create_app_bundle(config: &AppBundleConfig, apps_dir: &Path) -> AppResult<PathBuf> {
    let normalized_name = normalize_name(&config.app_name);
    if normalized_name.is_empty() {
        return Err(AppError::new(
            ReasonCode::RcCliInvalid,
            "application name is empty or invalid",
        ));
    }

    let app_name = format!("{}.app", &config.app_name);
    let app_path = apps_dir.join(&app_name);

    // Create directory structure
    let contents_dir = app_path.join("Contents");
    let macos_dir = contents_dir.join("MacOS");
    let resources_dir = contents_dir.join("Resources");
    let frameworks_dir = contents_dir.join("Frameworks");

    fs::create_dir_all(&macos_dir).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to create MacOS directory in app bundle: {}", app_path.display()),
            &e,
        )
    })?;
    fs::create_dir_all(&resources_dir).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to create Resources directory in app bundle: {}", app_path.display()),
            &e,
        )
    })?;
    fs::create_dir_all(&frameworks_dir).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to create Frameworks directory in app bundle: {}", app_path.display()),
            &e,
        )
    })?;

    // Write Info.plist
    let plist = generate_info_plist(config);
    fs::write(contents_dir.join("Info.plist"), &plist).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write Info.plist: {}", app_path.display()),
            &e,
        )
    })?;

    // Write PkgInfo
    fs::write(contents_dir.join("PkgInfo"), generate_pkginfo()).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write PkgInfo: {}", app_path.display()),
            &e,
        )
    })?;

    // Write wrapper script
    let wrapper_script = generate_wrapper_script(config);
    let wrapper_path = macos_dir.join("casa1-wrapper");
    fs::write(&wrapper_path, &wrapper_script).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write wrapper script: {}", wrapper_path.display()),
            &e,
        )
    })?;

    // Make wrapper executable
    let mut perms = fs::metadata(&wrapper_path)
        .map_err(|e| AppError::from_io(ReasonCode::RcIo, "failed to get wrapper metadata", &e))?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&wrapper_path, perms).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to set wrapper permissions: {}", wrapper_path.display()),
            &e,
        )
    })?;

    // Write icon if provided
    if let Some(ref icon_data) = config.icon_data {
        let icon_path = resources_dir.join("icon.icns");
        fs::write(&icon_path, icon_data).map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to write icon: {}", icon_path.display()),
                &e,
            )
        })?;
    }

    // Register with Launch Services
    register_with_launch_services(&app_path)?;

    Ok(app_path)
}

/// Register an app bundle with macOS Launch Services.
///
/// This makes the app discoverable in Spotlight, Launchpad, and the
/// "Open With" menu.
pub fn register_with_launch_services(app_path: &Path) -> AppResult<()> {
    use std::process::Command;

    // CoreServices LSRegisterURL via /usr/bin/lsregister
    let lsregister_path = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";

    let status = Command::new(lsregister_path)
        .arg("-f")
        .arg(app_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to run lsregister for Launch Services registration of {}", app_path.display()),
                &e,
            )
        })?;

    if !status.success() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!(
                "lsregister failed with status {} while registering {}",
                status,
                app_path.display()
            ),
        ));
    }

    Ok(())
}

/// Check if an app bundle is registered with Launch Services by searching.
pub fn is_app_registered(app_name: &str) -> AppResult<bool> {
    use std::process::Command;

    let app_bundle = format!("{}.app", app_name);
    let output = Command::new("mdfind")
        .arg("kMDItemFSName")
        .arg(&app_bundle)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                "failed to run mdfind for app registration check",
                &e,
            )
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(&app_bundle))
}

/// List all Casa1-installed app bundles in the given apps directory.
pub fn list_installed_apps(apps_dir: &Path) -> AppResult<Vec<InstalledApp>> {
    let mut apps = Vec::new();

    if !apps_dir.exists() {
        return Ok(apps);
    }

    let entries = fs::read_dir(apps_dir).map_err(|e| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to read apps directory: {}", apps_dir.display()),
            &e,
        )
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to read directory entry: {}", apps_dir.display()),
                &e,
            )
        })?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "app") {
            let plist_path = path.join("Contents").join("Info.plist");
            if plist_path.exists() {
                let plist_content = fs::read_to_string(&plist_path).unwrap_or_default();
                let bundle_id = extract_plist_value(&plist_content, "CFBundleIdentifier");
                let display_name = extract_plist_value(&plist_content, "CFBundleDisplayName")
                    .or_else(|| extract_plist_value(&plist_content, "CFBundleName"))
                    .unwrap_or_else(|| {
                        path.file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default()
                    });

                apps.push(InstalledApp {
                    name: display_name,
                    bundle_id: bundle_id.unwrap_or_default(),
                    path: path.to_path_buf(),
                });
            }
        }
    }

    Ok(apps)
}

/// Information about an installed app bundle.
#[derive(Debug, Clone, Serialize)]
pub struct InstalledApp {
    pub name: String,
    pub bundle_id: String,
    pub path: PathBuf,
}

/// Uninstall (remove) an app bundle and deregister from Launch Services.
pub fn uninstall_app(app_path: &Path) -> AppResult<()> {
    // First, deregister from Launch Services
    let lsregister_path = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
    let _ = std::process::Command::new(lsregister_path)
        .arg("-u")
        .arg(app_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // Remove the app bundle
    if app_path.exists() {
        fs::remove_dir_all(app_path).map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to remove app bundle: {}", app_path.display()),
                &e,
            )
        })?;
    }

    Ok(())
}

/// Extract a string value from an Info.plist XML by key.
fn extract_plist_value(plist_xml: &str, key: &str) -> Option<String> {
    let pattern = format!("<key>{}</key><string>", key);
    if let Some(start) = plist_xml.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = plist_xml[value_start..].find("</string>") {
            return Some(plist_xml[value_start..value_start + end].to_string());
        }
    }
    None
}

/// Prevent App Nap during gameplay using NSProcessInfo activity assertion.
pub fn prevent_app_nap() -> AppResult<()> {
    // Use the Objective-C runtime to create an activity assertion
    // This prevents macOS from throttling the app during gameplay
    let result: u64 = unsafe {
        let cls = objc::class!(NSProcessInfo);
        let info: *mut objc::runtime::Object = msg_send![cls, processInfo];
        if info.is_null() {
            return Err(AppError::new(ReasonCode::RcIo, "NSProcessInfo is null"));
        }
        let reason: *mut objc::runtime::Object = msg_send![objc::class!(NSString), stringWithUTF8String: c"Casa1 Game Activity".as_ptr()];
        let activity: u64 = msg_send![info, beginActivityWithOptions: 0x00FFFFFF reason: reason];
        let _ = reason;
        activity
    };
    if result == 0 {
        return Err(AppError::new(
            ReasonCode::RcIo,
            "failed to create NSProcessActivity assertion",
        ));
    }
    Ok(())
}

/// End the App Nap prevention activity.
pub fn allow_app_nap(activity_id: u64) {
    if activity_id == 0 {
        return;
    }
    unsafe {
        let cls = objc::class!(NSProcessInfo);
        let info: *mut objc::runtime::Object = msg_send![cls, processInfo];
        if !info.is_null() {
            let _: () = msg_send![info, endActivity: activity_id];
        }
    }
}

/// Set the application's Dock tile to show the given app icon and name.
pub fn set_dock_icon(icon_data: &[u8]) -> AppResult<()> {
    unsafe {
        let cls = objc::class!(NSImage);
        let data: *mut objc::runtime::Object = msg_send![objc::class!(NSData), dataWithBytes: icon_data.as_ptr() as *const std::ffi::c_void length: icon_data.len() as u64];
        let image: *mut objc::runtime::Object = msg_send![cls, alloc];
        let image: *mut objc::runtime::Object = msg_send![image, initWithData: data];
        if image.is_null() {
            return Err(AppError::new(ReasonCode::RcIo, "failed to create NSImage for dock icon"));
        }
        let app_cls = objc::class!(NSApplication);
        let app: *mut objc::runtime::Object = msg_send![app_cls, sharedApplication];
        let _: () = msg_send![app, setApplicationIconImage: image];
        let _: () = msg_send![image, release];
    }
    Ok(())
}

/// Set the application's activation policy.
///
/// When `regular` is `true`, sets the policy to
/// `NSApplicationActivationPolicyRegular` (value 0), which allows the app
/// to appear in the Dock and receive focus.  When `regular` is `false`, sets
/// the policy to `NSApplicationActivationPolicyProhibited` (value 2), which
/// hides the app from the Dock and prevents it from becoming active.
///
/// This is useful when transitioning between the game environment (where the
/// Casa1 window should behave as a regular app) and background/headless modes.
pub fn set_activation_policy(regular: bool) -> AppResult<()> {
    let policy = if regular { 0i64 } else { 2i64 };
    unsafe {
        // SAFETY: NSApplication's sharedApplication and setActivationPolicy:
        // are well-defined Cocoa calls.  The NSApp singleton is guaranteed to
        // exist once NSApplicationLoad() or [NSApplication sharedApplication]
        // has been called.  Passing an integer enum value (0 or 2) for the
        // policy parameter is valid per the AppKit specification.
        let app_cls = objc::class!(NSApplication);
        let app: *mut objc::runtime::Object = msg_send![app_cls, sharedApplication];
        if app.is_null() {
            return Err(AppError::new(
                ReasonCode::RcIo,
                "NSApp is null — Cocoa application not initialized",
            ));
        }
        let result: i64 = msg_send![app, setActivationPolicy: policy];
        if result != 0 {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!(
                    "setActivationPolicy returned {} for policy={}",
                    result, policy
                ),
            ));
        }
    }
    Ok(())
}

/// Add a Spotlight metadata import for the app bundle.
pub fn add_spotlight_metadata(app_path: &Path) -> AppResult<()> {
    use std::process::Command;

    let status = Command::new("mdimport")
        .arg(app_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| {
            AppError::from_io(
                ReasonCode::RcIo,
                format!("failed to run mdimport for Spotlight indexing of {}", app_path.display()),
                &e,
            )
        })?;

    if !status.success() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("mdimport failed with status {}", status),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("Test App"), "test-app");
        assert_eq!(normalize_name("Hello-World"), "hello-world");
        assert_eq!(normalize_name("My App 2024"), "my-app-2024");
        assert_eq!(normalize_name(""), "");
    }

    #[test]
    fn test_generate_bundle_id() {
        assert_eq!(generate_bundle_id("Tetris"), "com.casa1.tetris");
        assert_eq!(generate_bundle_id("My Game"), "com.casa1.my-game");
        assert_eq!(generate_bundle_id(""), "com.casa1.unknown");
    }

    #[test]
    fn test_generate_info_plist() {
        let config = AppBundleConfig {
            app_name: "TestApp".to_string(),
            bundle_id: Some("com.example.test".to_string()),
            ..Default::default()
        };
        let plist = generate_info_plist(&config);
        assert!(plist.contains("CFBundleIdentifier"));
        assert!(plist.contains("com.example.test"));
        assert!(plist.contains("TestApp"));
        assert!(plist.contains("casa1-wrapper"));
        assert!(plist.contains("</plist>"));
    }

    #[test]
    fn test_generate_wrapper_script() {
        let config = AppBundleConfig {
            app_name: "Test Game".to_string(),
            executable_path: r"C:\Games\game.exe".to_string(),
            ge_name: "my-ge".to_string(),
            ..Default::default()
        };
        let script = generate_wrapper_script(&config);
        assert!(script.contains("C:\\Games\\game.exe"));
        assert!(script.contains("my-ge"));
        assert!(script.contains("App Wrapper"));
        assert!(script.starts_with("#!/bin/bash"));
    }

    #[test]
    fn test_generate_pkginfo() {
        let pkginfo = generate_pkginfo();
        assert_eq!(pkginfo.len(), 8);
        assert_eq!(&pkginfo[..4], b"APPL");
    }

    #[test]
    fn test_extract_plist_value() {
        let plist = r#"<plist><dict><key>CFBundleName</key><string>MyApp</string></dict></plist>"#;
        assert_eq!(extract_plist_value(plist, "CFBundleName"), Some("MyApp".to_string()));
        assert_eq!(extract_plist_value(plist, "CFBundleIdentifier"), None);
    }

    #[test]
    fn test_create_app_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let apps_dir = tmp.path().join("Applications");
        fs::create_dir_all(&apps_dir).unwrap();

        let config = AppBundleConfig {
            app_name: "TestBundle".to_string(),
            executable_path: "test.exe".to_string(),
            ge_name: "test-ge".to_string(),
            ..Default::default()
        };

        let result = create_app_bundle(&config, &apps_dir);
        assert!(result.is_ok());

        let app_path = result.unwrap();
        assert!(app_path.exists());
        assert!(app_path.join("Contents").join("Info.plist").exists());
        assert!(app_path.join("Contents").join("MacOS").join("casa1-wrapper").exists());
        assert!(app_path.join("Contents").join("PkgInfo").exists());

        // Check wrapper is executable
        let metadata = fs::metadata(app_path.join("Contents").join("MacOS").join("casa1-wrapper")).unwrap();
        assert!(metadata.permissions().mode() & 0o111 != 0);

        // Clean up
        let _ = fs::remove_dir_all(&app_path);
    }

    #[test]
    fn test_list_installed_apps() {
        let tmp = tempfile::tempdir().unwrap();
        let apps_dir = tmp.path().join("Applications");
        fs::create_dir_all(&apps_dir).unwrap();

        // Create a test app bundle
        let config = AppBundleConfig {
            app_name: "ListTest".to_string(),
            executable_path: "game.exe".to_string(),
            ge_name: "test-ge".to_string(),
            ..Default::default()
        };

        let _ = create_app_bundle(&config, &apps_dir).unwrap();

        let apps = list_installed_apps(&apps_dir).unwrap();
        assert!(!apps.is_empty());
        assert!(apps.iter().any(|a| a.name == "ListTest"));
    }

    #[test]
    fn test_uninstall_app() {
        let tmp = tempfile::tempdir().unwrap();
        let apps_dir = tmp.path().join("Applications");
        fs::create_dir_all(&apps_dir).unwrap();

        let config = AppBundleConfig {
            app_name: "ToRemove".to_string(),
            executable_path: "game.exe".to_string(),
            ge_name: "test-ge".to_string(),
            ..Default::default()
        };

        let app_path = create_app_bundle(&config, &apps_dir).unwrap();
        assert!(app_path.exists());

        let _ = uninstall_app(&app_path);
        assert!(!app_path.exists());
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("hello"), "hello");
        assert_eq!(xml_escape("a&b"), "a&amp;b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("\"quote\""), "&quot;quote&quot;");
        }

        #[test]
        fn test_generate_info_plist_with_url_schemes() {
            let config = AppBundleConfig {
                app_name: "SteamApp".to_string(),
                url_schemes: vec!["steam".to_string()],
                ..Default::default()
            };
            let plist = generate_info_plist(&config);
            assert!(plist.contains("CFBundleURLTypes"));
            assert!(plist.contains("steam"));
        }
}
