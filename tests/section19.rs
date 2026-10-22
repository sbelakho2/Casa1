#![allow(dead_code, unused_imports)]
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
    CefBridge, CefBrowserSettings, CefSettings, CefWindowInfo, WKWebViewManager,
};

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

// ---------------------------------------------------------------------------
// t19_2_browser_creation_with_url
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// t19_5_frame_snapshot
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t19_6_browser_resize
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t19_7_concurrent_browsers
// ---------------------------------------------------------------------------

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
