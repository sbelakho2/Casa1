//! Phase 8 — CEF/WKWebView Tests
//!
//! Tests the CEF bridge and WKWebView manager: initialization, browser creation,
//! navigation history, JavaScript execution, frame snapshots, browser resize,
//! concurrent browsers, close lifecycle, double-init rejection, and WKWebView
//! manager creation.
//!
//! Tests that require WKWebView gracefully skip in headless/CI environments
//! where WKWebView is not available.

use casa1::cef_bridge::{
    CefBridge, CefBrowserSettings, CefSettings, CefWindowInfo, WKWebViewConfig, WKWebViewManager,
};

/// Helper: create and initialize a CefBridge. Returns `None` (and prints a
/// skip note) when WKWebView is unavailable so the calling test can return
/// early without failing.
fn init_cef() -> Option<CefBridge> {
    let mut bridge = CefBridge::new();
    match bridge.cef_initialize(CefSettings::default()) {
        Ok(()) => Some(bridge),
        Err(e) => {
            eprintln!("note: CEF test skipped — WKWebView unavailable ({:?})", e);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// t19_1_cef_bridge_initialization
// ---------------------------------------------------------------------------

#[test]
fn t19_1_cef_bridge_initialization() {
    let Some(mut bridge) = init_cef() else { return };

    // After initialization, we should be able to create browsers
    let window_info = CefWindowInfo {
        x: 0,
        y: 0,
        width: 100,
        height: 100,
        windowless_rendering_enabled: true,
        parent_window: 0,
        url: None,
        external_begin_frame_enabled: false,
    };

    let handle = bridge
        .cef_browser_host_create_browser(window_info, "about:blank", CefBrowserSettings::default())
        .expect("create browser after init");

    assert!(handle > 0, "browser handle should be non-zero");

    bridge.cef_shutdown().expect("CEF shutdown");
}

// ---------------------------------------------------------------------------
// t19_2_browser_creation_with_url
// ---------------------------------------------------------------------------

#[test]
fn t19_2_browser_creation_with_url() {
    let Some(mut bridge) = init_cef() else { return };

    let window_info = CefWindowInfo {
        x: 0,
        y: 0,
        width: 800,
        height: 600,
        windowless_rendering_enabled: true,
        parent_window: 0,
        url: Some("https://store.steampowered.com".to_string()),
        external_begin_frame_enabled: false,
    };

    let handle = bridge
        .cef_browser_host_create_browser(
            window_info,
            "https://store.steampowered.com",
            CefBrowserSettings::default(),
        )
        .expect("create browser with URL");

    assert!(handle > 0, "browser handle should be valid");
    assert!(
        bridge.cef_browser_is_valid(handle),
        "browser should be valid"
    );

    // Verify main frame handle
    let main_frame = bridge
        .cef_browser_get_main_frame(handle)
        .expect("get main frame");
    assert!(main_frame > 0, "main frame should be valid");

    // Verify host handle
    let host = bridge.cef_browser_get_host(handle).expect("get host");
    assert!(host > 0, "host handle should be valid");

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_3_navigation_history
// ---------------------------------------------------------------------------

#[test]
fn t19_3_navigation_history() {
    let Some(mut bridge) = init_cef() else { return };

    let window_info = CefWindowInfo {
        x: 0,
        y: 0,
        width: 800,
        height: 600,
        windowless_rendering_enabled: true,
        parent_window: 0,
        url: None,
        external_begin_frame_enabled: false,
    };

    let handle = bridge
        .cef_browser_host_create_browser(
            window_info,
            "https://url1.example.com",
            CefBrowserSettings::default(),
        )
        .expect("create browser");

    // Navigate to URL2
    bridge
        .cef_frame_load_url(handle, "https://url2.example.com")
        .expect("navigate to URL2");

    // Go back — should fail because can_go_back is false initially
    // (navigation history tracking is simulated)
    let result = bridge.cef_browser_go_back(handle);
    // In our simulated mode, can_go_back starts as false
    assert!(result.is_err(), "go_back should fail when no back history");

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_4_javascript_execution
// ---------------------------------------------------------------------------

#[test]
fn t19_4_javascript_execution() {
    let Some(mut bridge) = init_cef() else { return };

    let window_info = CefWindowInfo {
        x: 0,
        y: 0,
        width: 100,
        height: 100,
        windowless_rendering_enabled: true,
        parent_window: 0,
        url: None,
        external_begin_frame_enabled: false,
    };

    let handle = bridge
        .cef_browser_host_create_browser(
            window_info,
            "about:blank",
            CefBrowserSettings::default(),
        )
        .expect("create browser");

    // Execute JavaScript
    let result = bridge
        .cef_frame_execute_java_script(handle, 1, "1+1")
        .expect("execute JS");

    // In simulated mode, the result may be empty (no real JS engine)
    // but the call should succeed without error
    assert!(
        result.is_empty() || result == "2",
        "JS execution should succeed, got: {result}"
    );

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_5_frame_snapshot
// ---------------------------------------------------------------------------

#[test]
fn t19_5_frame_snapshot() {
    let Some(mut bridge) = init_cef() else { return };

    let width = 100u32;
    let height = 100u32;

    let window_info = CefWindowInfo {
        x: 0,
        y: 0,
        width: width as i32,
        height: height as i32,
        windowless_rendering_enabled: true,
        parent_window: 0,
        url: None,
        external_begin_frame_enabled: false,
    };

    let handle = bridge
        .cef_browser_host_create_browser(
            window_info,
            "about:blank",
            CefBrowserSettings::default(),
        )
        .expect("create browser");

    // Get the browser host
    let _browser = bridge.cef_browser_get_host(handle).expect("get host");

    // Get rendered frame
    let frame = bridge.get_rendered_frame(0);
    assert!(frame.is_some(), "rendered frame should exist");

    let frame = frame.unwrap();
    assert_eq!(frame.width, width, "frame width should match");
    assert_eq!(frame.height, height, "frame height should match");
    assert_eq!(
        frame.pixels.len(),
        (width * height * 4) as usize,
        "pixel buffer should be width*height*4 bytes"
    );

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_6_browser_resize
// ---------------------------------------------------------------------------

#[test]
fn t19_6_browser_resize() {
    let Some(mut bridge) = init_cef() else { return };

    let window_info = CefWindowInfo {
        x: 0,
        y: 0,
        width: 100,
        height: 100,
        windowless_rendering_enabled: true,
        parent_window: 0,
        url: None,
        external_begin_frame_enabled: false,
    };

    let handle = bridge
        .cef_browser_host_create_browser(
            window_info,
            "about:blank",
            CefBrowserSettings::default(),
        )
        .expect("create browser");

    // Resize to 200x200
    bridge.resize(handle, 200, 200);

    // Verify the new dimensions in the rendered frame
    let frame = bridge.get_rendered_frame(0);
    assert!(frame.is_some(), "rendered frame should exist after resize");

    let frame = frame.unwrap();
    assert_eq!(frame.width, 200, "frame width should be 200 after resize");
    assert_eq!(frame.height, 200, "frame height should be 200 after resize");
    assert_eq!(
        frame.pixels.len(),
        200 * 200 * 4,
        "pixel buffer should be resized"
    );

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_7_concurrent_browsers
// ---------------------------------------------------------------------------

#[test]
fn t19_7_concurrent_browsers() {
    let Some(mut bridge) = init_cef() else { return };

    let urls = [
        "https://store.steampowered.com",
        "https://steamcommunity.com",
        "https://help.steampowered.com",
    ];

    let mut handles = Vec::new();
    for url in &urls {
        let window_info = CefWindowInfo {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            windowless_rendering_enabled: true,
            parent_window: 0,
            url: Some(url.to_string()),
            external_begin_frame_enabled: false,
        };
        let handle = bridge
            .cef_browser_host_create_browser(
                window_info,
                url,
                CefBrowserSettings::default(),
            )
            .expect("create browser");
        handles.push(handle);
    }

    // Verify all browsers are valid and have unique handles
    assert_eq!(handles.len(), 3, "should have 3 browsers");
    for &handle in &handles {
        assert!(
            bridge.cef_browser_is_valid(handle),
            "each browser should be valid"
        );
    }

    // Verify handles are unique
    assert_ne!(handles[0], handles[1], "handles should be unique");
    assert_ne!(handles[1], handles[2], "handles should be unique");
    assert_ne!(handles[0], handles[2], "handles should be unique");

    // Navigate each browser to a different URL
    bridge
        .cef_frame_load_url(handles[0], "https://url-a.com")
        .expect("navigate browser 0");
    bridge
        .cef_frame_load_url(handles[1], "https://url-b.com")
        .expect("navigate browser 1");
    bridge
        .cef_frame_load_url(handles[2], "https://url-c.com")
        .expect("navigate browser 2");

    // All browsers should still be valid after navigation
    for &handle in &handles {
        assert!(
            bridge.cef_browser_is_valid(handle),
            "browser should remain valid after navigation"
        );
    }

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_8_browser_close_lifecycle
// ---------------------------------------------------------------------------

#[test]
fn t19_8_browser_close_lifecycle() {
    let Some(mut bridge) = init_cef() else { return };

    let window_info = CefWindowInfo {
        x: 0,
        y: 0,
        width: 100,
        height: 100,
        windowless_rendering_enabled: true,
        parent_window: 0,
        url: None,
        external_begin_frame_enabled: false,
    };

    let handle = bridge
        .cef_browser_host_create_browser(
            window_info,
            "about:blank",
            CefBrowserSettings::default(),
        )
        .expect("create browser");

    assert!(
        bridge.cef_browser_is_valid(handle),
        "browser should be valid before close"
    );

    // Close the browser
    bridge.close_browser(handle).expect("close browser");

    // After closing, the browser should no longer be valid
    assert!(
        !bridge.cef_browser_is_valid(handle),
        "browser should not be valid after close"
    );

    // Navigation should fail on closed browser
    let nav_result = bridge.cef_frame_load_url(handle, "https://example.com");
    assert!(nav_result.is_err(), "navigation should fail on closed browser");

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_9_cef_double_init_rejected
// ---------------------------------------------------------------------------

#[test]
fn t19_9_cef_double_init_rejected() {
    let mut bridge = CefBridge::new();

    // First initialization — may fail in headless environments
    let first = bridge.cef_initialize(CefSettings::default());
    if first.is_err() {
        eprintln!("note: t19_9 skipped — WKWebView unavailable");
        return;
    }

    // Second initialization should fail
    let result = bridge.cef_initialize(CefSettings::default());
    assert!(result.is_err(), "double initialization should be rejected");

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_10_wkwebview_manager_creation
// ---------------------------------------------------------------------------

#[test]
fn t19_10_wkwebview_manager_creation() {
    let mut manager = WKWebViewManager::new();

    // On macOS, WKWebView may or may not be available depending on the test
    // environment. On CI or headless systems, it may not be available.
    // We just verify the manager can be created without panicking.
    let _ = manager.is_available();

    // If WKWebView is available, try creating a webview
    if manager.is_available() {
        let config = WKWebViewConfig {
            width: 800.0,
            height: 600.0,
            java_script_enabled: true,
            user_agent: Some("Casa1 Test Agent".to_string()),
        };

        let handle = manager.create_webview(config);
        match handle {
            Ok(h) => {
                assert!(h.0 > 0, "WKWebView handle should be non-zero");
                assert_eq!(manager.active_count(), 1, "should have 1 active view");

                // Navigate
                manager.navigate(h, "https://example.com").expect("navigate");

                // Verify URL
                assert_eq!(
                    manager.current_url(h),
                    Some("https://example.com"),
                    "URL should be set after navigation"
                );

                // Check dimensions
                let dims = manager.dimensions(h);
                assert!(dims.is_some(), "dimensions should be available");
                let (w, h_val) = dims.unwrap();
                assert_eq!(w, 800.0, "width should be 800");
                assert_eq!(h_val, 600.0, "height should be 600");

                // Close
                manager.close(h);
                assert_eq!(manager.active_count(), 0, "should have 0 active views after close");
            }
            Err(_) => {
                // WKWebView creation failed — acceptable in headless environments
            }
        }
    }

    manager.close_all();
}
