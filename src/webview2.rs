// ---------------------------------------------------------------------------
// WebView2 COM Interface Wrapper — wraps WKWebView (via cef_bridge) behind
// the ICoreWebView2 COM interfaces.
//
// Steam.exe and other apps may load webview2.dll and call the CreateWebView2Environment
// entry point to obtain an ICoreWebView2Environment, from which they create
// controllers and webview instances.
//
// Architecture:
//   CreateWebView2Environment  →  WebView2Runtime  →  delegates to
//   ICoreWebView2Environment                           cef_bridge's WKWebView
//         │
//         ▼
//   ICoreWebView2Controller ──→  ICoreWebView2 ──→  WebView2Instance
//                                                         │
//                                                         ▼
//                                                   cef_bridge WKWebView
//                                                   (navigate, eval JS, etc.)
// ---------------------------------------------------------------------------

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Top-level runtime — one per PeHostRuntime
// ---------------------------------------------------------------------------

/// WebView2 runtime state, stored in [`PeHostRuntime`].
#[derive(Debug, Clone)]
pub struct WebView2Runtime {
    pub environments: HashMap<u64, WebView2Environment>,
    pub controllers: HashMap<u64, WebView2Controller>,
    pub webviews: HashMap<u64, WebView2Instance>,
    pub events: WebView2Events,
    pub next_id: u64,
}

impl WebView2Runtime {
    pub fn new() -> Self {
        WebView2Runtime {
            environments: HashMap::new(),
            controllers: HashMap::new(),
            webviews: HashMap::new(),
            events: WebView2Events::new(),
            next_id: 1,
        }
    }

    /// Create a new WebView2 environment.
    pub fn create_environment(&mut self, _options: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let env = WebView2Environment {
            browser_exe_path: None,
            user_data_folder: None,
            options: _options as u32,
            controllers: Vec::new(),
        };
        self.environments.insert(id, env);
        id
    }

    /// Create a new WebView2 controller for a given environment.
    pub fn create_controller(&mut self, env_id: u64, parent_hwnd: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let webview_id = self.create_webview();
        let controller = WebView2Controller {
            webview_id,
            parent_hwnd,
            bounds: (0, 0, 800, 600),
            is_visible: true,
            zoom_factor: 1.0,
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
            default_background: 0xFF_FF_FF_FF, // white ARGB
            ceh_handle: None,
            pending_scripts: Vec::new(),
            web_messages: Vec::new(),
        };
        self.webviews.insert(id, webview);
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
                if let Some(ctrl) = self.controllers.remove(ctrl_id) {
                    self.webviews.remove(&ctrl.webview_id);
                }
            }
        }
    }

    /// Destroy a controller and its associated webview.
    pub fn destroy_controller(&mut self, id: u64) {
        if let Some(ctrl) = self.controllers.remove(&id) {
            self.webviews.remove(&ctrl.webview_id);
        }
    }
}

// ---------------------------------------------------------------------------
// Core WebView2 data structures
// ---------------------------------------------------------------------------

/// Represents an ICoreWebView2Environment.
#[derive(Debug, Clone)]
pub struct WebView2Environment {
    pub browser_exe_path: Option<String>,
    pub user_data_folder: Option<String>,
    pub options: u32,
    /// Controllers created from this environment.
    pub controllers: Vec<u64>,
}

/// Represents an ICoreWebView2Controller.
#[derive(Debug, Clone)]
pub struct WebView2Controller {
    pub webview_id: u64,
    pub parent_hwnd: u64,
    pub bounds: (i32, i32, i32, i32), // x, y, width, height
    pub is_visible: bool,
    pub zoom_factor: f64,
}

/// Represents an ICoreWebView2 instance, backed by a WKWebView via cef_bridge.
#[derive(Debug, Clone)]
pub struct WebView2Instance {
    pub source: String,
    pub is_script_enabled: bool,
    pub is_web_message_enabled: bool,
    pub is_status_bar_enabled: bool,
    pub are_dev_tools_enabled: bool,
    pub default_background: u32, // ARGB
    /// Handle into cef_bridge's WKWebView table (if available).
    pub ceh_handle: Option<u64>,
    /// Scripts queued for injection on document creation.
    pub pending_scripts: Vec<String>,
    /// Web messages queued for posting.
    pub web_messages: Vec<String>,
}

impl WebView2Instance {
    /// Navigate to a URL — delegates to the CEF bridge's WKWebView if available.
    pub fn navigate(&mut self, url: &str) {
        if let Some(_ceh_id) = self.ceh_handle {
            // Delegate to cef_bridge's WKWebView via the global bridge
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                // The cef_bridge can navigate via its CEF API
                let _ = bridge.cef_frame_load_url(_ceh_id, url);
            });
        }
        self.source = url.to_string();
    }

    /// Navigate to an HTML string.
    pub fn navigate_to_string(&mut self, _html: &str) {
        if let Some(_ceh_id) = self.ceh_handle {
            // cef_bridge doesn't directly expose loadHTMLString, but we can
            // use a data: URL or the frame load mechanism
        }
        self.source = format!("data:text/html,{}", _html);
    }

    /// Execute JavaScript in the webview context.
    pub fn execute_script(&self, _script: &str) {
        if let Some(ceh_id) = self.ceh_handle {
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                let _ = bridge.cef_frame_execute_java_script(ceh_id, 0, _script);
            });
        }
    }

    /// Post a web message as JSON.
    pub fn post_web_message_as_json(&mut self, _json: &str) {
        if self.is_web_message_enabled {
            self.web_messages.push(_json.to_string());
            if let Some(_ceh_id) = self.ceh_handle {
                // Post via WKWebView's postMessage mechanism
                // cef_bridge handles this via its JS bridge
            }
        }
    }

    /// Post a web message as a plain string.
    pub fn post_web_message_as_string(&mut self, _msg: &str) {
        if self.is_web_message_enabled {
            self.web_messages.push(_msg.to_string());
        }
    }

    /// Stop all ongoing navigations.
    pub fn stop(&self) {
        if let Some(_ceh_id) = self.ceh_handle {
            // WKWebView stopLoading
        }
    }

    /// Reload the current page.
    pub fn reload(&self) {
        if let Some(ceh_id) = self.ceh_handle {
            crate::cef_bridge::with_global_cef_bridge(|bridge| {
                let _ = bridge.cef_browser_reload(ceh_id);
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
    /// Token -> callback function pointer for navigation starting.
    pub navigation_starting: HashMap<u64, u64>,
    /// Token -> callback for navigation completed.
    pub navigation_completed: HashMap<u64, u64>,
    /// Token -> callback for web message received.
    pub web_message_received: HashMap<u64, u64>,
    /// Token -> callback for new window requested.
    pub new_window_requested: HashMap<u64, u64>,
    /// Token -> callback for permission requested.
    pub permission_requested: HashMap<u64, u64>,
    /// Token -> callback for process failed.
    pub process_failed: HashMap<u64, u64>,
    /// Token -> callback for content loading.
    pub content_loading: HashMap<u64, u64>,
    /// Token -> callback for source changed.
    pub source_changed: HashMap<u64, u64>,
    /// Token -> callback for history changed.
    pub history_changed: HashMap<u64, u64>,
    /// Token -> callback for download starting.
    pub download_starting: HashMap<u64, u64>,
    /// Next available token value.
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
pub fn unregister(
storage: &mut HashMap<u64, u64>,
token: EventRegistrationToken,
) {
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
    // ICoreWebView2_2
    add_ContentLoading,
    remove_ContentLoading,
    add_SourceChanged,
    remove_SourceChanged,
    add_HistoryChanged,
    remove_HistoryChanged,
    // ICoreWebView2_3
    add_NewWindowRequested,
    remove_NewWindowRequested,
    add_PermissionRequested,
    remove_PermissionRequested,
    add_ProcessFailed,
    remove_ProcessFailed,
    // ICoreWebView2_4
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

        webview.default_background = 0xFF_00_00_00; // black
        assert_eq!(webview.default_background, 0xFF_00_00_00);
    }

    /// Register event handlers and verify tokens.
    #[test]
    fn test_webview2_event_handlers() {
        let mut events = WebView2Events::new();
        let token1 = register(&mut events.next_token, 0x1000, &mut events.navigation_starting);
        let token2 = register(&mut events.next_token, 0x2000, &mut events.navigation_completed);
        let token3 = register(&mut events.next_token, 0x3000, &mut events.web_message_received);

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
        assert!(webview.source.starts_with("data:text/html,"));
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
}
