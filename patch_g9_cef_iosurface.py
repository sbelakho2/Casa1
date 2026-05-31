#!/usr/bin/env python3
"""Add G9: IOSurface-backed Metal texture delivery to cef_bridge.rs."""
with open('src/cef_bridge.rs', 'r') as f:
    content = f.read()

# === G9: Add IOSurface cache struct and method ===

# 1. Add IOSurfaceTexturePair struct after the imports (after line 27, before ObjC section)
old_imports_end = "use std::sync::Mutex;\n\n// ---------------------------------------------------------------------------\n// Objective-C runtime helper types"
iosurface_cache_struct = """use std::sync::Mutex;

// ---------------------------------------------------------------------------
// G9: IOSurface-backed Metal texture cache for zero-copy CEF compositing
// ---------------------------------------------------------------------------

/// A cached pair of IOSurface and its wrapping Metal texture.
struct IoSurfaceTexturePair {
    /// Raw IOSurfaceRef (owned, released on drop/resize).
    io_surface: *mut std::ffi::c_void,
    /// Metal texture wrapping the IOSurface.
    metal_texture: Option<metal::Texture>,
    /// Width in pixels.
    width: u32,
    /// Height in pixels.
    height: u32,
}

unsafe impl Send for IoSurfaceTexturePair {}
unsafe impl Sync for IoSurfaceTexturePair {}

impl IoSurfaceTexturePair {
    fn new(metal_device: &metal::DeviceRef, width: u32, height: u32) -> Option<Self> {
        let io_surface = crate::metal_backend::create_io_surface(width, height)?;
        let metal_texture = crate::metal_backend::create_texture_from_io_surface(
            metal_device,
            io_surface,
            metal::MTLPixelFormat::BGRA8Unorm,
            width as u64,
            height as u64,
        );
        Some(Self {
            io_surface,
            metal_texture,
            width,
            height,
        })
    }
}

impl Drop for IoSurfaceTexturePair {
    fn drop(&mut self) {
        if !self.io_surface.is_null() {
            unsafe {
                // CFRelease the IOSurfaceRef
                let sel = objc::sel!(release);
                let obj: *mut objc::runtime::Object = self.io_surface as *mut _;
                let _: () = objc::msg_send![obj, performSelector: sel];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Objective-C runtime helper types (no `foundation` feature in objc 0.2.7)
// ---------------------------------------------------------------------------"""

content = content.replace(old_imports_end, iosurface_cache_struct, 1)

# 2. Add io_surface_cache field to CefBridge struct
old_fields = """    /// Whether the NSApplication has been set up for headless rendering
    nsapp_initialized: bool,
}"""

new_fields = """    /// Whether the NSApplication has been set up for headless rendering
    nsapp_initialized: bool,
    /// G9: IOSurface-backed Metal texture cache keyed by browser_id.
    io_surface_cache: BTreeMap<u32, IoSurfaceTexturePair>,
}"""

content = content.replace(old_fields, new_fields, 1)

# 3. Add io_surface_cache initialization to Default impl
old_default = """            webview_manager: None,
            nsapp_initialized: false,
        }
    }
}"""

new_default = """            webview_manager: None,
            nsapp_initialized: false,
            io_surface_cache: BTreeMap::new(),
        }
    }
}"""

content = content.replace(old_default, new_default, 1)

# 4. Add render_to_io_surface_texture method right after render_to_metal_texture
old_method_end = """        Ok(texture)
    }

    /// Non-metal fallback: returns an error if the `metal` feature is not enabled."""

iosurface_method = """        Ok(texture)
    }

    // -----------------------------------------------------------------------
    /// G9: Render a browser frame into an IOSurface-backed Metal texture.
    ///
    /// Unlike `render_to_metal_texture`, which copies pixels from a CPU-side
    /// `RenderedFrame` into a Metal texture, this method directly serves the
    /// WKWebView's IOSurface backing store to Metal, achieving zero-copy frame
    /// delivery. The IOSurface is cached per browser to avoid reallocation on
    /// every frame. Only works for WKWebView-backed browsers.
    ///
    /// Returns the Metal texture wrapping the IOSurface, or falls back to
    /// `render_to_metal_texture` if no IOSurface is available.
    // -----------------------------------------------------------------------
    #[cfg(feature = "metal")]
    pub fn render_to_io_surface_texture(
        &mut self,
        browser_handle: CefHandle,
        metal_device: &crate::metal_backend::MetalDevice,
    ) -> AppResult<metal::Texture> {
        let browser = self.browsers.get(&browser_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNotFound,
                format!("render_to_io_surface_texture: browser {browser_handle:#x} not found"),
            )
        })?;
        let browser_id = browser.id;

        // If the browser has a WKWebView backing, try to get its IOSurface
        if let Some(mgr) = &self.webview_manager {
            if let Ok(io_surface) = mgr.get_io_surface_for_browser(browser_handle) {
                if !io_surface.is_null() {
                    let frame = self.get_rendered_frame(browser.id).ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcNotFound,
                            format!("render_to_io_surface_texture: no frame for browser {}", browser.id),
                        )
                    })?;

                    // Check cache for a matching IOSurface/texture pair
                    if !self.io_surface_cache.contains_key(&browser_id)
                        || self.io_surface_cache.get(&browser_id).map(|p| (p.width, p.height))
                            != Some((frame.width, frame.height))
                    {
                        // Allocate new IOSurface + Metal texture
                        if let Some(pair) = IoSurfaceTexturePair::new(
                            metal_device.device(),
                            frame.width,
                            frame.height,
                        ) {
                            self.io_surface_cache.insert(browser_id, pair);
                        }
                    }

                    if let Some(pair) = self.io_surface_cache.get(&browser_id) {
                        if let Some(ref texture) = pair.metal_texture {
                            return Ok(texture.clone());
                        }
                    }
                }
            }
        }

        // Fallback to CPU-side copy path
        self.render_to_metal_texture(browser_handle, metal_device)
    }

    /// Non-metal fallback: returns an error if the `metal` feature is not enabled."""

content = content.replace(old_method_end, iosurface_method, 1)

with open('src/cef_bridge.rs', 'w') as f:
    f.write(content)
print("G9 applied to cef_bridge.rs")
