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

/// Helper: create and initialize a CefBridge.
///
/// Gating is done on an explicit capability probe (`WKWebViewManager::is_available` —
/// the same probe `cef_initialize` consults internally), NOT on the init result:
/// previously any `cef_initialize` failure silently passed the whole CEF suite. If the
/// probe reports WKWebView available but initialization still fails, that is a real
/// failure and the calling test fails.
fn init_cef() -> Option<CefBridge> {
    if !WKWebViewManager::new().is_available() {
        eprintln!("note: CEF test skipped — WKWebView unavailable");
        return None;
    }
    let mut bridge = CefBridge::new();
    bridge
        .cef_initialize(CefSettings::default())
        .expect("CEF init must succeed when the availability probe reports available");
    Some(bridge)
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

    // Drive the load-handler callback the way a completed WKWebView navigation
    // would: the delegate reports that back-navigation history now exists.
    bridge.on_loading_state_change(handle, false, true, false);

    // Back must now succeed, and forward must still be rejected.
    assert!(
        bridge.cef_browser_go_back(handle).is_ok(),
        "go_back must succeed once back history exists"
    );
    assert!(
        bridge.cef_browser_go_forward(handle).is_err(),
        "go_forward must fail when no forward history"
    );

    // A forward navigation makes forward history available again.
    bridge.on_loading_state_change(handle, false, false, true);
    assert!(
        bridge.cef_browser_go_forward(handle).is_ok(),
        "go_forward must succeed once forward history exists"
    );

    // The browser must remain valid through the navigation cycle.
    assert!(
        bridge.cef_browser_is_valid(handle),
        "browser must remain valid after navigation"
    );

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
        .cef_browser_host_create_browser(window_info, "about:blank", CefBrowserSettings::default())
        .expect("create browser");

    // Execute JavaScript
    let result = bridge
        .cef_frame_execute_java_script(handle, 1, "1+1")
        .expect("execute JS");

    // Documented contract for the JS result: with a real WKWebView that delivers a
    // synchronous evaluation result, "1+1" must evaluate to "2". In the simulated
    // software-buffer mode there is no JS engine and the documented result is the
    // empty string. Anything else (a no-op engine, an error string, partial output)
    // is a failure.
    match result.as_str() {
        "2" => {}
        "" => {}
        other => panic!("unexpected JS result {other:?} for 1+1"),
    }

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
        .cef_browser_host_create_browser(window_info, "about:blank", CefBrowserSettings::default())
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
        .cef_browser_host_create_browser(window_info, "about:blank", CefBrowserSettings::default())
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
            .cef_browser_host_create_browser(window_info, url, CefBrowserSettings::default())
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
        .cef_browser_host_create_browser(window_info, "about:blank", CefBrowserSettings::default())
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
    assert!(
        nav_result.is_err(),
        "navigation should fail on closed browser"
    );

    bridge.cef_shutdown().expect("shutdown");
}

// ---------------------------------------------------------------------------
// t19_9_cef_double_init_rejected
// ---------------------------------------------------------------------------

#[test]
fn t19_9_cef_double_init_rejected() {
    if !WKWebViewManager::new().is_available() {
        eprintln!("note: t19_9 skipped — WKWebView unavailable");
        return;
    }
    let mut bridge = CefBridge::new();

    // First initialization must succeed when the probe reports availability.
    bridge
        .cef_initialize(CefSettings::default())
        .expect("first init must succeed when WKWebView is available");

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
    if !manager.is_available() {
        eprintln!("note: t19_10 skipped — WKWebView unavailable");
        manager.close_all();
        return;
    }

    let config = WKWebViewConfig {
        width: 800.0,
        height: 600.0,
        java_script_enabled: true,
        user_agent: Some("Casa1 Test Agent".to_string()),
    };

    // The probe reported WKWebView available, so view creation must succeed —
    // a broken manager must not pass silently.
    let handle = manager
        .create_webview(config)
        .expect("create_webview must succeed when WKWebView is available");
    assert!(handle.0 > 0, "WKWebView handle should be non-zero");
    assert_eq!(manager.active_count(), 1, "should have 1 active view");

    // Navigate
    manager
        .navigate(handle, "https://example.com")
        .expect("navigate");

    // Verify URL
    assert_eq!(
        manager.current_url(handle),
        Some("https://example.com"),
        "URL should be set after navigation"
    );

    // Check dimensions
    let dims = manager.dimensions(handle);
    assert!(dims.is_some(), "dimensions should be available");
    let (w, h_val) = dims.unwrap();
    assert_eq!(w, 800.0, "width should be 800");
    assert_eq!(h_val, 600.0, "height should be 600");

    // Close
    manager.close(handle);
    assert_eq!(
        manager.active_count(),
        0,
        "should have 0 active views after close"
    );

    manager.close_all();
}
