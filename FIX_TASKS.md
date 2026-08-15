# AUDIT_FINDINGS.md

- **Batch:** cef-bridge-audit-1
- **File(s):** src/cef_bridge.rs (8006 lines, read in full, sequential)
- **Lines:** 1–8006
- **Date:** 2026-08-15
- **Clippy:** `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (see `## Clippy` and `## Build`)

---

## [CRITICAL] Block literals passed to WKWebView completion handlers have NULL `isa` and flags=0 — `_Block_copy` will crash

- File: src/cef_bridge.rs:158
- File: src/cef_bridge.rs:1586
- File: src/cef_bridge.rs:1702

- Description: `BlockLiteral` is built with `isa: std::ptr::null_mut()` and `flags: 0` for both `evaluateJavaScript:completionHandler:` (line 1586–1602) and `takeSnapshotWithConfiguration:completionHandler:` (line 1702–1718). WKWebView copies completion blocks (they run asynchronously); `_Block_copy` reads `block->isa` to locate the block class. With `isa == NULL` this is a NULL-pointer dereference / crash. The comment "will be set to NSConcreteStackBlock by runtime" is false — the runtime never patches the `isa` of a stack block. With `flags == 0` there is also no `BLOCK_HAS_SIGNATURE`, which breaks block-signature introspection paths. Additionally, a stack block's lifetime is only "the duration of the msg_send! call" (comment, line 1531–1533); WKWebView retains the block past the call, so the block memory is invalid the moment the function returns.
- Fix suggestion: Use a proper heap block: set `isa` to the `_NSConcreteStackBlock` symbol (`objc::runtime::sel!`-style extern symbol via `std::ffi::c_void` cast of `_NSConcreteStackBlock`), set `flags = BLOCK_HAS_COPY_DISPOSE | BLOCK_HAS_SIGNATURE` and provide copy/dispose/signature descriptors (or use the `block2`/`objc2` crate's `RcBlock`/`ConcreteBlock`). If keeping a stack block is mandatory, the API must be invoked synchronously with no retention — not possible for these WKWebView APIs, so a heap/`RcBlock` block is required.

## [CRITICAL] Over-release of autoreleased NSStrings — double-free crash

- File: src/cef_bridge.rs:197
- File: src/cef_bridge.rs:1610
- File: src/cef_bridge.rs:175

- Description: `ns_string_from_str` returns the result of `+[NSString stringWithUTF8String:]`, a convenience constructor that returns an **autoreleased** object (+0). The doc comment claims "caller must release", which is wrong. `ns_url_from_str` then sends `release` to `url_str` (line 197) and `evaluate_js_native` sends `release` to `js_str` (line 1610). Both over-release an autoreleased object; the next autorelease-pool drain (every AppKit runloop cycle) double-frees it → heap corruption/crash. Every `navigate()` and `evaluate_java_script()` call is affected. (Conversely, `handler_name` (1392), `ua_str`/`key` (1427–1436) and `set_dict_string` (5081–5085) do not release, which is correct for +0 — the code is inconsistent.)
- Fix suggestion: Remove both `release` calls (lines 197 and 1610), or change `ns_string_from_str` to create a +1 object (`alloc` + `initWithUTF8String:`) with an RAII wrapper, and consistently release or not. Minimal fix: delete the two `msg_send![...release]` lines and fix the doc comment.

## [CRITICAL] `IoSurfaceTexturePair::drop` sends ObjC `release` to a CoreFoundation IOSurfaceRef — UB/crash

- File: src/cef_bridge.rs:73
- File: src/cef_bridge.rs:49

- Description: `create_io_surface` (src/metal_backend.rs:1395) returns a **+1 retained CoreFoundation `IOSurfaceRef`** documented as "caller must CFRelease". `Drop for IoSurfaceTexturePair` instead calls `performSelector: release` via `objc_msgSend` (line 81). IOSurface is a CF object, not an NSObject; `objc_msgSend` dereferences a garbage `isa` pointer → crash/UB on every cache eviction, resize, or `close_browser` that drops a cached pair. The `unsafe impl Send/Sync` (lines 50–52) additionally lets the drop occur on any thread, widening the UB.
- Fix suggestion: In `Drop`, use `CFRelease(self.io_surface as *const c_void)` (declare `CFRelease` in the `core_graphics_ffi` extern block, line 1821, or use the `core_foundation` crate already used by `metal_backend`). Keep the null check.

## [CRITICAL] `render_to_metal_texture` reads out of bounds when `frame.pixels` is empty/short

- File: src/cef_bridge.rs:3089
- File: src/cef_bridge.rs:4052

- Description: `on_accelerated_paint` pushes a placeholder `RenderedFrame` with `pixels: Vec::new()` (line 4052). `render_to_metal_texture` then calls `texture.replace_region(region, 0, frame.pixels.as_ptr(), bytes_per_row)` with **no length check** — it reads `width*height*4` bytes from a zero-length Vec (possibly a dangling pointer) → OOB read/segfault. Reachable when the zero-copy IOSurface path is unavailable and the caller falls back (`render_to_io_surface_texture` line 3204, or a direct compositor call). The managed path's `upload_rgba_frame_to_io_surface` does guard length (returns Err) — only the CPU path is unguarded.
- Fix suggestion: At line 3089, verify `frame.pixels.len() >= width as usize * height as usize * 4` and return `RcInvalidState`/fall back otherwise, mirroring `upload_rgba_frame_to_io_surface` (metal_backend.rs:1225). Also stop producing empty-pixels frames in `on_accelerated_paint` — allocate a zeroed buffer of `fw*fh*4`.

---

## [HIGH] `on_before_close` keeps rendered frames of the closed browser (inverted retain predicate)

- File: src/cef_bridge.rs:3680

- Description: The browser is removed from `self.browsers` at line 3678, *then* `rendered_frames.retain(|f| self.browsers.get(&browser_handle).map_or(true, |b| f.browser_id != b.id))` runs. The lookup now always returns `None`, so `map_or(true, ...)` keeps **every** frame, including the closed browser's — the opposite of intent. `get_rendered_frame(browser_id)` keeps returning stale frames for a dead browser, and memory is retained until `cef_shutdown`. Compare `close_browser` (line 3019), which does it correctly by capturing `browser.id` before removal.
- Fix suggestion: Capture `let browser_id = browser.id;` before `self.browsers.remove(...)` (or before line 3678) and use `self.rendered_frames.retain(|f| f.browser_id != browser_id);`.

## [HIGH] Navigation-delegate → view mapping never matches; every navigation event is broadcast to all browsers

- File: src/cef_bridge.rs:601
- File: src/cef_bridge.rs:988

- Description: `view_to_handle` is keyed by the **WKWebView** native pointer (`state.view_to_handle.insert(native_ptr as u64, handle)` line 988), but the delegate callbacks compute `ptr_val = self_ as u64` where `self_` is the **shared `Casa1NavDelegate` instance** (one instance created in `register_delegate_classes` line 913–915, assigned to every webview). The key can never match, so the code always falls into the "broadcast to all" fallback — and then unconditionally marks *all* views loaded (lines 628–631), making the first loop dead. Result: any navigation completion (or failure, lines 659–673) sets `is_loading`/error state on every browser. With multiple browsers (main + overlay) one page finishing marks the other as loaded, so snapshots/rendering state is wrong.
- Fix suggestion: Store the handle on the delegate instance (associated object or ivar via `ClassDecl` + `add_ivar`) and pass the webview pointer (`_webview` argument, currently ignored) as the lookup key; remove the unconditional "mark all" loop. Minimal fix: key `view_to_handle` by the delegate pointer after registering a per-view delegate instance.

## [HIGH] `SNAPSHOT_TARGET_HANDLE` global atomic races between overlapping snapshots

- File: src/cef_bridge.rs:238
- File: src/cef_bridge.rs:1632
- File: src/cef_bridge.rs:1675

- Description: `take_snapshot_native` stores the target handle in a process-global static before the async call, and the completion block reads it back (line 1675). If a second snapshot is taken before the first completion runs (main browser + overlay both dirty, or multiple `CefBridge` instances in tests), the first completion stores its pixels under the second handle → pixels applied to the wrong view, or dropped. The static is shared across all bridge instances (tests create many), so cross-bridge corruption is possible. The comment's "single thread" assumption is false: the completion is delivered by the runloop after arbitrary interleaving.
- Fix suggestion: Pass the handle through block private data (allocate a block that captures it, or use a per-view completion closure via `RcBlock`), or serialize snapshots (queue one in-flight snapshot at a time per handle) instead of a global. Minimal: keep a per-instance in-flight set and reject overlapping snapshots.

## [HIGH] `read_io_surface_pixels`: lock/unlock imbalance and ignored lock return codes — surface left locked

- File: src/cef_bridge.rs:2319
- File: src/cef_bridge.rs:2328
- File: src/cef_bridge.rs:2357

- Description: The surface is locked twice — once via `performSelector: lockWithOptions: withObject:` (line 2319, options=0) and again via `lockWithOptions: 1` (line 2328) — while all return codes are ignored. Only a single `unlockWithOptions: 1` is issued (line 2357, and again at 2363 in the null-base path). Depending on IOSurface lock semantics the first lock can persist → the surface stays locked, subsequent locks from the compositor/upload path (`upload_rgba_frame_to_io_surface`) fail, and GPU reads of a CPU-locked surface are undefined → stall/black frames. Data is also read without verifying the lock actually succeeded.
- Fix suggestion: Lock exactly once with `kIOSurfaceLockReadOnly` (1), check the return code, and unlock once on every path (RAII guard, as in `metal_backend.rs:1259`). Delete the spurious `performSelector` lock at line 2319.

## [HIGH] `sync_from_ns_http_cookie_storage` reads NSString objects as C strings — OOB read/garbage

- File: src/cef_bridge.rs:4957
- File: src/cef_bridge.rs:5067

- Description: `msg_send![cookie, name]` (and `value`/`domain`/`path`/`sameSite`) returns an **NSString object pointer**, but `c_str_to_string` casts it to `*const i8` and runs `CStr::from_ptr` over the object's memory as if it were a NUL-terminated char buffer (the code never calls `UTF8String` here). This reads the object header/payload bytes as a string — garbage values, and a read that can run past the allocation → OOB read or crash. The same helper is used on the `sameSite` value.
- Fix suggestion: In `sync_from_ns_http_cookie_storage`, extract the C string properly: `let utf8: *const i8 = msg_send![name_obj, UTF8String];` then `CStr::from_ptr(utf8)` (matching the correct pattern used at lines 649, 735, 1109, 1560). Keep `c_str_to_string` only for `UTF8String` results.

## [HIGH] Snapshot RGBA buffer is vertically flipped (`CGContextDrawImage` bottom-left origin)

- File: src/cef_bridge.rs:1891
- File: src/cef_bridge.rs:1897

- Description: `convert_cgimage_to_rgba` draws into a raw `CGBitmapContextCreateWithData` buffer with `CGContextDrawImage` and no coordinate transform. Quartz bitmap contexts use a bottom-left origin, so the resulting row-0-first RGBA buffer is upside down relative to the top-left-origin buffers the compositor expects (WKWebView snapshot CGImage is not pre-flipped). Rendered Steam UI will appear vertically inverted unless the consumer flips again — no flip was found in the downstream paths here.
- Fix suggestion: Apply `CGContextTranslateCTM(ctx, 0, height)` + `CGContextScaleCTM(ctx, 1, -1)` before `CGContextDrawImage` (add the two extern fns), or draw via `CGContextDrawImage` into an explicitly flipped rect. Verify against the compositor's expected orientation.

## [HIGH] `dispatch_cef_query` "download" writes arbitrary files via curl with attacker-controlled filename

- File: src/cef_bridge.rs:4312
- File: src/cef_bridge.rs:4326

- Description: The `download` handler takes `filename` directly from the query JSON (originating from web-page JS via the CefQuery bridge) and runs `curl -L -o <cwd>/<filename> <url>` in a spawned thread. `filename` can contain path separators (`../../...`) or be absolute (`/Users/...`), turning this into an arbitrary file-write primitive with the user's privileges. There is no sanitization, allowlist, or check that the destination stays inside a Downloads directory.
- Fix suggestion: Sanitize the filename (reject `/`, `\`, `..`, leading `.`), force the destination into a fixed Downloads directory (`NSDownloadsDirectory`), and validate the URL scheme (http/https) before spawning. Also cap concurrent download threads.

## [HIGH] `on_accelerated_paint` discards the shared IOSurface and fabricates empty placeholder frames

- File: src/cef_bridge.rs:4037
- File: src/cef_bridge.rs:4048
- File: src/cef_bridge.rs:4092

- Description: The comment says the shared handle is stored in the IO surface cache, but `shared_handle` is never stored anywhere — the `io_surface_cache` only ever contains self-allocated surfaces. The function pushes a `RenderedFrame` with `pixels: Vec::new()` and returns `true` ("handled"), which (a) feeds the empty frame into `get_rendered_frame`/`submit_latest_frame_to_compositor`, feeding the CRITICAL #4 OOB read, (b) publishes a gray placeholder to the live session instead of the real surface, and (c) falsely reports success to the CEF caller. The zero-copy promise of this path is not implemented.
- Fix suggestion: Either cache `shared_handle` per browser (and have `render_to_io_surface_texture` wrap it), or return `false` and don't push placeholder frames. At minimum, push a zero-filled buffer sized `fw*fh*4` so downstream length checks pass.

## [HIGH] ObjC object leaks in `create_wkwebview_native` — unbounded across browser churn

- File: src/cef_bridge.rs:1374
- File: src/cef_bridge.rs:1378
- File: src/cef_bridge.rs:1388
- File: src/cef_bridge.rs:1401

- Description: `pool`, `prefs`, `uc`, `config` are created with `alloc`+`init` (+1 each) and handed to `setProcessPool:`/`setPreferences:`/`setUserContentController:`/`initWithFrame:configuration:` (all strong properties), then never released; `config` (+1) is retained by the view and never released. Each webview creation leaks config/prefs/pool/uc (plus the `"native"`, UA, and KVC-key NSStrings are +0 so those are fine). Steam creates and destroys browsers repeatedly over a session → unbounded memory growth in WebKit.
- Fix suggestion: After wiring, `release` the four temporary +1 objects: `msg_send![config, release]` after `initWithFrame:configuration:` (view retains), and `prefs`/`pool`/`uc` after assigning to the config (config retains them). Verify each property is strong (they are).

---

## [MEDIUM] Wrong scancode → arrow-key mapping

- File: src/cef_bridge.rs:2091

- Description: `0x50 => "ArrowLeft", 0x4F => "ArrowRight", 0x4E => "ArrowDown", 0x52 => "ArrowUp"` doesn't match PC scancodes: Up=0x48, Down=0x50, Left=0x4B, Right=0x4D (and 0x4E/0x4F/0x52 are keypad +/PgDn/Ins). Arrow navigation in the Steam UI will produce wrong keys.
- Fix suggestion: Map 0x48→ArrowUp, 0x50→ArrowDown, 0x4B→ArrowLeft, 0x4D→ArrowRight (confirm which scancode set the caller provides; if keypad codes are intended, use the keypad-arrow keys 0x4B/0x4D/0x48/0x50 anyway).

## [MEDIUM] Context-menu suppression JS is a discarded no-op

- File: src/cef_bridge.rs:2197

- Description: The injected script ends with `event => event.preventDefault();` — a standalone arrow-function expression that is created and discarded. It is never bound to the dispatched event (no `addEventListener`), so the right-click context menu is not suppressed, contradicting the intent.
- Fix suggestion: Register a real listener before dispatching, e.g. `window.addEventListener('contextmenu', e => e.preventDefault(), { once: true }); document.dispatchEvent(new MouseEvent('contextmenu', {...}));` — and note synthetic events are untrusted, so the native menu may still appear; also guard against double-registration.

## [MEDIUM] `frame_number` is derived from `rendered_frames.len()` — non-monotonic, recycled values

- File: src/cef_bridge.rs:2645
- File: src/cef_bridge.rs:3952
- File: src/cef_bridge.rs:4045
- File: src/cef_bridge.rs:3585
- File: src/cef_bridge.rs:2983

- Description: `frame_number: self.rendered_frames.len() as u64` — the queue is capped at 10 (pop_front), so after 10 frames the length shrinks and the numbering cycles 0..9. Consumers use `frame_number` as a freshness key (`b.metal_texture_id = Some(frame_number)`, lines 3098, 3156, 3286): a recycled number makes a stale texture look current. The sequencing test `g9_frame_delivery_sequencing` passes only because it bypasses the cap.
- Fix suggestion: Keep a monotonically increasing per-browser (or global) counter in `CefBridge` (e.g. increment `live_frame_counter`-style field) and use it for `frame_number`.

## [MEDIUM] `take_snapshot`/`snapshot` result checks are effectively dead — snapshots never update pixels via these paths

- File: src/cef_bridge.rs:1193
- File: src/cef_bridge.rs:1180

- Description: `take_snapshot_native` is asynchronous (completion runs later on the runloop); the immediate `DELEGATE_STATE.snapshot_results.remove(&handle)` check right after the call almost always sees `None`, so `instance.pixels` is never updated through `take_snapshot`, and `snapshot()`'s `frame_count == 0 && loaded` gate fires only once and increments the counter regardless of success — if the completion never arrives (silent failure), the view stays white forever with no retry.
- Fix suggestion: Only bump `frame_count` when a result is actually consumed, and consume results in the runloop-driven path (`process_pending_webview_ops`), removing the immediate-check code or making it poll with a timeout. Add a failure flag so a lost snapshot triggers a retry.

## [MEDIUM] Integer overflow in pixel-buffer sizing for extreme dimensions

- File: src/cef_bridge.rs:2539
- File: src/cef_bridge.rs:992
- File: src/cef_bridge.rs:2977

- Description: `vec![0xFF; (frame_w * frame_h * 4) as usize]` computes in `u32` (`frame_w`, `frame_h` are u32) — for dims ≥ ~2^15 each the product overflows: debug builds panic, release builds wrap to a tiny buffer that then mismatches `width`/`height` (OOB later). Same class at line 992 (`config.width as usize * config.height as usize * 4` with unvalidated f64→usize) and 2977. `cef_browser_host_was_resized` (3574–3579) correctly uses `saturating_mul` — the others don't.
- Fix suggestion: Compute in `usize` with `saturating_mul` (and reject 0), e.g. `let n = (frame_w as usize).saturating_mul(frame_h as usize).saturating_mul(4);` then `vec![0xFF; n]`, plus a sane cap (e.g. 16K×16K) before allocating.

## [MEDIUM] Unvalidated/negative window dimensions reach WKWebView while buffer clamps differently

- File: src/cef_bridge.rs:2478
- File: src/cef_bridge.rs:2537

- Description: `cef_browser_host_create_browser` passes `window_info.width as f64` (possibly negative i32) straight into `WKWebViewConfig`, while the frame buffer clamps with `.max(1)`. Negative/zero dims produce a `-1×-1` WKWebView frame and empty pixel buffers (`width as usize` of a negative f64 → 0), and `resize()` (2962) also skips the clamp — inconsistent and produces empty buffers used by `render_to_metal_texture` (CRITICAL #4).
- Fix suggestion: Clamp `width`/`height` to `>= 1` at the top of `cef_browser_host_create_browser` (before `as f64`) and in `resize`.

## [MEDIUM] Global cookie manager ignores later `cache_path`s; `handle_cef_query` and `dispatch_cef_query` disagree on store

- File: src/cef_bridge.rs:4899
- File: src/cef_bridge.rs:5452
- File: src/cef_bridge.rs:4535

- Description: `get_global(cache_path)` only honors the first path (singleton); the second query path uses `"."` (cwd) instead of `settings.cache_path`, so the two query handlers read/write different `cookies.json` files. Cookies set via one handler are invisible to the other; a stray `cookies.json` lands in the working directory.
- Fix suggestion: Store the cache path in the singleton at first creation and make both handlers use `settings.cache_path` (falling back to a fixed app-support dir, never `"."`).

## [MEDIUM] Cookie sync leaks ObjC objects per cookie per sync

- File: src/cef_bridge.rs:5032
- File: src/cef_bridge.rs:5053

- Description: `[NSMutableDictionary new]` (+1) and `[NSHTTPCookie alloc] initWithProperties:` (+1) are never released; `setCookie:` retains the cookie, and the dict is dropped by reference loss. `sync_to_ns_http_cookie_storage` runs on every `set_cookie`/`delete_cookies` for every cookie → unbounded leak over a long session with frequent cookie writes.
- Fix suggestion: After `setCookie:`, send `release` to `ns_cookie` and `dict` (or use autorelease/`objc2`-style ownership wrappers).

## [MEDIUM] Global bridge mutex held while running user closure — self-deadlock on re-entry

- File: src/cef_bridge.rs:5928

- Description: `with_global_cef_bridge` and `ensure_global_bridge` hold `GLOBAL_CEF_BRIDGE.lock()` while invoking the caller's closure (and `set_live_frame_tx` paths). If the closure (e.g. a PE import dispatch path) calls back into `with_global_cef_bridge`, the non-reentrant `std::sync::Mutex` deadlocks. The same pattern applies to `DELEGATE_STATE` locks held across user-callback invocations in `process_pending_webview_ops` (line 2642–2667) — there the closure is `self.paint_callback`, which could call back into the bridge.
- Fix suggestion: Extract the data needed by the closure inside the lock, drop the guard, then call the closure (e.g. clone the `Arc`/handle out). For `paint_callback`, invoke it after releasing `DELEGATE_STATE`.

## [MEDIUM] `steam://` URLs are cancelled but never routed to the Steam handler

- File: src/cef_bridge.rs:4149

- Description: `on_before_browse` returns `true` for `steam://` URLs (cancelling navigation) but only logs the parse result of `parse_steam_protocol_url`; it never dispatches to `steam_protocol`/`steam_integration`. Steam UI links (e.g. `steam://store/...`) silently do nothing.
- Fix suggestion: After parsing, dispatch the parsed action to the Steam protocol handler (or return `false` to let WKWebView attempt it) — wire the parse result to an actual handler instead of logging.

## [MEDIUM] `evaluate_java_script` pop/mismatch: queued results are never correlated with `callback_id`

- File: src/cef_bridge.rs:1150
- File: src/cef_bridge.rs:1167

- Description: `callback_id` is allocated (`next_js_id`) and passed to `evaluate_js_native`, but the completion block never enqueues into `state.js_results` (it only logs), and the reader pops the front entry regardless of id. The async result path is entirely dead: callers always get `""` even on success, and if anything ever did insert, concurrent evaluations would mis-route results.
- Fix suggestion: Implement the block to post `(callback_id, result)` into `state.js_results` and pop only entries matching the requested id; otherwise drop the id/queue machinery and return an explicit error or empty result.

## [MEDIUM] No `Drop` for `WKWebViewManager`/`CefBridge` — resources leak if bridge dropped without `cef_shutdown`

- File: src/cef_bridge.rs:515
- File: src/cef_bridge.rs:371

- Description: Dropping a `CefBridge` (or the manager) without calling `cef_shutdown` leaks every live WKWebView, the offscreen window/view, delegate instances, and IOSurface pairs (the `io_surface_cache` also has no cleanup path in `close_browser`/`on_before_close` — closed browsers' surfaces stay allocated).
- Fix suggestion: Implement `Drop for WKWebViewManager` calling `close_all()`, and `Drop for CefBridge` that tears down browsers/manager/io_surface_cache. Also remove closed browsers from `io_surface_cache` in `close_browser`.

---

## [PERF] Full-frame clone per tick in `submit_latest_frame_to_compositor`

- File: src/cef_bridge.rs:3335

- Description: Called every `tick_overlay`/compositor pass; `frame.clone()` copies the entire RGBA buffer (~3.7 MB at 1280×720) each frame even when the frame is unchanged. The queue is capped at 10, so up to 10 stale full copies may also be cloned before the newest is found.
- Fix suggestion: Pass `&RenderedFrame`/slice to `submit_cef_overlay_frame` (change signature), or skip submission when `frame_number` hasn't changed since last submit.

## [PERF] Multiple full-buffer copies in `on_paint` hot path

- File: src/cef_bridge.rs:3957

- Description: `pixels: pixels.clone()` (line 3957), `cb(rendered.clone())` (3963), plus `publish_live_frame_from_pixels(width, height, pixels)` — 2–3 full copies of the frame per paint. Same in `process_pending_webview_ops` (2656–2659) and `on_accelerated_paint` (4056–4058).
- Fix suggestion: Move the buffer once (`cb(rendered)` borrowing, or `Arc<Vec<u8>>`); invoke the callback with a reference and push the owned buffer.

## [PERF] Per-frame heap allocations in `process_pending_webview_ops`

- File: src/cef_bridge.rs:2613

- Description: `browser_wk_handles: Vec` is allocated on every call (every message-loop iteration, ~60 Hz), plus per-iteration `DELEGATE_STATE` lock/scan. Also `get_live_preview_frame` (2004) rebuilds a full BGRA vec on every call.
- Fix suggestion: Cache the handle list and invalidate on browser create/close, or iterate `self.browsers` directly with a cloned small vec only when dirty; convert BGRA lazily only when a live subscriber is actually connected.

## [PERF] `get_live_preview_frame` full conversion + clone per call

- File: src/cef_bridge.rs:2004

- Description: Every call clones the latest frame's pixels and performs a per-pixel RGBA→BGRA conversion even if nothing consumed the previous preview. Unnecessary when `live_frame_tx` is unset or the frame hasn't changed.
- Fix suggestion: Cache the converted BGRA buffer keyed by `frame_number`, and skip conversion when no subscriber is present.

---

## [LOW] Dead code and unused bindings

- File: src/cef_bridge.rs:2312
- File: src/cef_bridge.rs:1785
- File: src/cef_bridge.rs:88

- Description: `_sel_unlock`/`_sel_base_address`/`_sel_bytes_per_row` bindings (2312–2314) are unused; `core_graphics_ffi` declares `CGColorSpaceGetModel`, `CGImageGetBitsPerComponent`, `CGImageGetColorSpace`, `CGImageGetBitmapInfo` never used (module has `#[allow(dead_code)]`); duplicate comment block at lines 88–90; the first broadcast loop in `did_finish_nav` (623–627) is made redundant by the unconditional loop at 628–631.
- Fix suggestion: Remove unused bindings/declarations, fix the duplicated header comment, delete the redundant loop.

## [LOW] `on_load_start` ignores its `is_main_frame` parameter

- File: src/cef_bridge.rs:3720

- Description: `_is_main_frame` is ignored and `let is_main = true;` is hard-coded with a comment asserting WKWebView is "always main frame" — but the parameter carries real information from the caller and the code logs the fabricated value.
- Fix suggestion: Use the parameter (`let is_main = _is_main_frame;`).

## [LOW] No-op test assertions (`assert!(true, ...)`)

- File: src/cef_bridge.rs:6206
- File: src/cef_bridge.rs:6643

- Description: `assert!(true, "JS execution should not panic")` and `assert!(true, "settings were stored...")` assert nothing; the "no panic" property they claim is already guaranteed by the preceding calls (a panic would fail the test anyway).
- Fix suggestion: Delete the `assert!(true, ...)` lines.

## [LOW] `cef_shutdown` permanently blocks re-initialization

- File: src/cef_bridge.rs:2418

- Description: State ends at `ShuttingDown` and `cef_initialize` only accepts `Uninitialized`, so a second `cef_initialize` after shutdown fails — unlike real CEF, which supports re-init. If Steam ever reinitializes after shutdown, browser creation silently breaks.
- Fix suggestion: Accept `ShuttingDown` in `cef_initialize` (reset state and re-run init), or document the single-shot constraint.

## [LOW] Silent padding of undersized paint buffers

- File: src/cef_bridge.rs:3940

- Description: When CEF provides a buffer shorter than `width*height*4`, the code pads with opaque white and reports a successful frame — content is wrong but no error surfaces. Acceptable as a fallback, but there is no log of the produced garbage frame downstream (only the "padding" eprintln) and `browser.dirty` is cleared.
- Fix suggestion: Keep padding but return an error/flag so the caller can retry the snapshot rather than compositing synthetic content.

## [LOW] `evaluate_java_script` silently returns `""` on missing result

- File: src/cef_bridge.rs:1174

- Description: When no queued result exists (always, per the dead queue noted above), the API returns `Ok(String::new())`, indistinguishable from a page that legitimately evaluated to empty. Callers can't tell success from failure.
- Fix suggestion: Return `Err(RcTimeout/RcNotFound)` when the result never arrives, or document the empty-ok semantics.

---

## Clippy

Run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (rustc/clippy 1.96.0). All warnings below are for `src/cef_bridge.rs` (62 warning sites, all `warn`-level; no `error` in this file):

- `clippy::collapsible_if` (51 sites): 1166, 1167, 1204, 2621, 2622, 2631, 2632, 2642, 2643, 2729, 2765, 2766, 2807, 2808, 2840, 2841, 2873, 2874, 2919, 2965, 2966, 3009, 3509, 3510, 3562, 3563, 3669, 3670, 4040, 4041, 4042, 4383, 4440, 4457, 4474, 4541, 4576, 4617, 4618, 4619, 4850, 4856, 4877, 5354, 5368, 5380, 5395, 5454, 5481, 5534, 5919 — use `if let ... && let ...` chains (rust-2024 let-chains) or nested `and_then`.
- `clippy::too_many_arguments`: 2138 (`forward_mouse_event_ext`, 11 args — bundle into a `MouseEventState` struct), 4195 (`on_auth_credentials`, 8 args — CEF-signature mirror; suppress or group).
- `clippy::new_without_default`: 784 (`WKWebViewManager` — add `impl Default`).
- `clippy::for_kv_map`: 2305 — use `.values()`.
- `clippy::zero_ptr`: 2319 — use `std::ptr::null_mut::<c_void>()`.
- `clippy::unnecessary_cast`: 3083, 3084, 3088 — drop `as u64`.
- `clippy::unnecessary_map_or`: 3681 — use `is_none_or(|b| ...)` (also fixes the HIGH finding #5 logic if applied correctly — prefer the explicit fix there).
- `clippy::assertions_on_constants`: 6206, 6643 (tests) — delete the `assert!(true, ...)` lines.

## Build

- `cargo clippy --all-targets --no-deps` **failed to complete compilation**: `error: could not compile casa1 (lib) due to 19 previous errors` and `error: could not compile casa1 (lib test) due to 27 previous errors`. **None of the errors are in src/cef_bridge.rs.** All errors are `deny`-level lints in other files, e.g.:
  - `clippy::absurd_extreme_comparisons` — src/crash_recovery.rs:536
  - `clippy::approx_constant` — src/d3d11.rs:3687
  - `clippy::not_unsafe_ptr_arg_deref` — src/jit.rs:34,49,71,72,73,84,109; src/metal_backend.rs:1237 (and more)
- Consequence for this audit: the `#[cfg(test)] mod tests` in cef_bridge.rs (lines 5943–8006) were linted but never compiled/run because the test target aborts on the other files' errors. Findings in tests (assertions_on_constants) are from lint pass only.
- `--all-features` was not used (per instructions; system ffmpeg is environmental).
