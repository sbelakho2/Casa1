# AUDIT_FINDINGS.md

- **Batch:** audit-webview-wmi (worktree `audit-webview-wmi`)
- **Files:** `src/webview2.rs` (2666 lines), `src/wmi.rs` (2543 lines) — whole files, every line read
- **Date:** 2026-08-15
- **Auditor role:** senior code auditor; audit-only, no source modified

Summary: 3 CRITICAL, 2 HIGH, 8 MEDIUM, 9 LOW — 22 findings total.
Clippy: 12 warnings for webview2.rs, 19 for wmi.rs (listed below). Build: see `## Build`.

---

## [CRITICAL] Panic on non-ASCII WQL input in `split_by_and` (byte/char index mix)

- File: src/wmi.rs:1487-1497
- Description: `split_by_and` iterates `chars` with a **char index** `i`, but then slices the **uppercased byte string**: `&upper[i..i + 3] == "AND"` (and guards with `i + 3 < s.len()`, also mixing char index with byte length). For any WHERE clause containing a multi-byte UTF-8 character before the slice position (e.g. `SELECT * FROM Win32_Processor WHERE Name = 'Café'`), `i` is a char index that lands mid-codepoint in `upper`'s byte space, so `upper[i..i+3]` panics with "byte index is not a char boundary". This runs on every `ExecQuery`/`CreateInstanceEnum`-driven parse of a guest-supplied WQL string (untrusted input from the emulated guest) and is reachable even with no `AND` present at all, since the slice is evaluated for every index.
- Fix suggestion: iterate over char indices in *bytes*: use `s.char_indices().collect::<Vec<_>>()` (or scan `s.bytes()` and track position via `char_indices`), and do the boundary checks against `upper` using byte indices (`i` from `char_indices`), e.g. `for (byte_idx, ch) in s.char_indices() { if depth == 0 && byte_idx + 3 <= upper.len() && &upper[byte_idx..byte_idx+3] == "AND" { ... } }` and replace `i + 3 < s.len()` with `byte_idx + 3 <= upper.len()`.

## [CRITICAL] Malformed Objective-C block passed as JS completion handler (garbage copy function, null isa)

- File: src/webview2.rs:1016-1046
- Description: `execute_js_wkwebview_native` builds a `StackBlock` with `flags: 1 << 25` (`BLOCK_HAS_COPY_DISPOSE`) and `isa: null`, but the `BlockDescriptor` (lines 1018-1022) contains only `{reserved, size}` — no copy/dispose function pointers — and `isa` is never set to `_NSConcreteStackBlock`. `WKWebView` copies the completion-handler block before invoking it asynchronously; `_Block_copy` sees `BLOCK_HAS_COPY_DISPOSE` and calls `descriptor->copy` read from 16 bytes past the 16-byte descriptor (garbage), and block layout logic expects a valid `isa`. Result: crash / UB on every `execute_script` that reaches a completion handler.
- Fix suggestion: build a correct block — resolve `_NSConcreteStackBlock` (e.g. `dlsym(RTLD_DEFAULT, "_NSConcreteStackBlock")`), set `flags = 0` (no captures, no copy/dispose needed) and keep the 16-byte descriptor, or provide a full descriptor with real copy/dispose functions if the flag is kept; alternatively pass `null`/`nil` as the completion handler, which `evaluateJavaScript:completionHandler:` accepts when the result is not needed.

## [CRITICAL] Use-after-free of shared WKNavigationDelegate when environment is dropped before its webviews

- File: src/webview2.rs:1342-1345, 1499-1506, 1416-1438
- Description: each `WebView2Environment` creates one nav-delegate object (`msg_send![cls, new]`, +1) and every controller sets it as the WKWebView's `navigationDelegate` — which is a **weak (assign)** reference. `Drop for WebView2Environment` (1416-1438) `release`s the delegate, deallocating it while any webview still points at it. This is reachable when `WebView2Runtime` is dropped (HashMap drop order of `environments`/`controllers` is unspecified) or when an env is dropped directly (`environments.remove(...)`, standalone `WebView2Environment::new` + `WebView2Controller::create` usage). The next WKWebView navigation callback then messages a deallocated object → use-after-free crash. (The `msg_handler` is retained by the user content controller, so it survives, but `removeScriptMessageHandler:` is never called and the handler's lifetime is tied to the never-released webview — see leak findings.)
- Fix suggestion: make the delegate's lifetime strictly dominate the controllers' (e.g. hold a strong reference to the delegate in each `WebView2Controller` and release only after the webview is closed and its `navigationDelegate` set to nil), or clear `setNavigationDelegate:nil` in `close_wkwebview_native`, or reference-count the delegate per environment.

## [HIGH] `view_to_webview_id` keyed by webview pointer but looked up by delegate pointer — navigation/message callbacks never fire

- File: src/webview2.rs:253, 308, 346, 365, 514 (lookups), 1511 (insertion)
- Description: `WebView2Controller::create` registers `state.view_to_webview_id.insert(native_ptr as u64, webview_id)` — keyed by the **WKWebView pointer**. All ObjC delegate/message-handler methods compute `let ptr_val = self_ as *const _ as u64;` — the **delegate / handler object pointer** (a single instance created per environment at lines 1342-1350, shared by all webviews, and never inserted into the map). The lookup therefore always misses, so `didFinishNavigation`, `didFailNavigation`, `didCommitNavigation`, `didStartProvisionalNavigation`, and `userContentController:didReceiveScriptMessage:` are all silent no-ops: NavigationCompleted/SourceChanged/ContentLoading/WebMessageReceived never fire from real page activity (only the manually fired NavigationStarting in `WebView2Controller::navigate` works).
- Fix suggestion: key by the actual webview: in the nav delegate methods use the `webview` argument (`webview as *const _ as u64`); in the message handler use `msg_send![message, webView]` (WKScriptMessage exposes `webView`); fall back to `self_` only if a delegate→webview registration is maintained.

## [HIGH] User callbacks invoked while holding the non-reentrant `DELEGATE_STATE` mutex — deadlock

- File: src/webview2.rs:251-279, 307-334, 364-414, 513-521, 1581-1596
- Description: all `on_navigation_starting`/`on_navigation_completed`/`on_content_loading`/`on_web_message_received` callbacks (user-supplied `FnMut + Send` closures) are invoked inside `if let Ok(mut state) = DELEGATE_STATE.lock() { ... }` scopes (the `collect()`/`drop(callbacks)` pattern does not release the lock). Any callback that calls back into WebView2Runtime/Controller APIs that lock the same `std::sync::Mutex` — `navigate` (1581), `unregister_callback` (1902), `on_navigation_starting` (1824), `close` (1629) — deadlocks the process. `if let Ok(...)` also silently swallows poisoning after a panicked callback, permanently disabling all delegate state.
- Fix suggestion: clone the callback list and the argument strings under the lock, `drop(state)`, then invoke callbacks outside the lock; on lock failure return/queue instead of silently continuing.

## [MEDIUM] ObjC object leaks: NSStrings, WKProcessPool/WKPreferences/WKUserContentController per env

- File: src/webview2.rs:764-778, 798-803, 886-897, 972, 1080, 1237-1242, 1226-1249
- Description: `ns_string_from_str` returns +1 objects that are never released: `ua_str`/`key` (798-803), `html_str`/`base_url_str` (886-897, every HTML navigation), `js_str` (972, every `execute_script`), `script_str` (1080, every add-user-script), `handler_name` (1237-1242). Additionally `create_wkwebview_native` (764-778) and `create_wkwebview_configuration` (1226-1249) create `pool`/`prefs`/`uc` with `new` (+1) and set them on the config (which retains) but never release the local refs → 3 leaked objects per environment creation.
- Fix suggestion: release each +1 object with `msg_send![..., release]` after use (or use autorelease), and release `pool`/`prefs`/`uc` after `setPreferences:`/`setProcessPool:`/`setUserContentController:`.

## [MEDIUM] WKWebView never released on close — per-controller leak and stale delegate

- File: src/webview2.rs:1171-1193, 1627-1638
- Description: the view is created with `alloc`/`initWithFrame:configuration:` (+1) and `close_wkwebview_native` only calls `stopLoading` + `removeFromSuperview`; the object is never `release`d, and `close()` never clears `navigationDelegate` or removes the script message handler. Every destroyed controller leaks the WKWebView (and its retained config) for the process lifetime.
- Fix suggestion: in `close_wkwebview_native` (or `WebView2Controller::close`), `setNavigationDelegate:nil`, `removeScriptMessageHandler` with the "webview2" name, and `release` the view after teardown; guard against double-release in `Drop`.

## [MEDIUM] `NavigationStarting` cancel return value ignored and event fired after navigation already started

- File: src/webview2.rs:1590-1595, 408-412
- Description: `NavigationStartingCallback` returns `bool` ("should_cancel") per its contract (line 51), but `WebView2Controller::navigate` and `did_start_prov_nav` discard the result (`map` collects `(*id, cb(...))` into a Vec that is dropped) — navigation always proceeds, so guest code that relies on cancelling (e.g. intercepting navigations) gets wrong behavior. Also the callback fires *after* `navigate_wkwebview_native` already started loading / after the provisional navigation began.
- Fix suggestion: capture the callback's bool under the lock, and if any callback returns `true`, skip the native `loadRequest`; fire NavigationStarting before initiating navigation (in `navigate`, before calling the native function).

## [MEDIUM] Wrong HRESULT constant: `E_CLASSNOTAVAILABLE`

- File: src/webview2.rs:43
- Description: `pub const E_CLASSNOTAVAILABLE: u64 = 0x8004_0117;` — the correct COM value for `CLASS_E_CLASSNOTAVAILABLE` is `0x8004_0111`. A guest checking the returned HRESULT will not recognize the error.
- Fix suggestion: change to `0x8004_0111`.

## [MEDIUM] `web_messages` grows unboundedly

- File: src/webview2.rs:2124, 2147
- Description: `post_web_message_as_json`/`post_web_message_as_string` push every message into `self.web_messages` and nothing ever drains/removes entries — unbounded memory growth in long-running sessions that post messages (no cap, no consumption API).
- Fix suggestion: bound the queue (e.g. retain only the last N messages or drain after delivery) or document it as a ring buffer.

## [MEDIUM] Event-token registration system is dead code — stored callbacks never invoked

- File: src/webview2.rs:1916-2056
- Description: `add_*`/`remove_*` store `token → callback_ptr` in `WebView2Events` maps, but the only fire methods (`fire_navigation_starting`, `fire_navigation_completed`, lines 2037-2056) only `eprintln!` and never call the stored pointers; no fire method exists for content_loading/source_changed/web_message_received/etc. Any guest that registers via `add_NavigationStarting` etc. and expects callbacks gets none. (The parallel `on_*`/`unregister_callback` DelegateState path partially works, but is also globally scoped — see next finding.)
- Fix suggestion: either implement real dispatch (invoke the stored callback pointers with marshalled args) or remove the token APIs and route everything through one mechanism.

## [MEDIUM] WQL LIKE misparsed when the value contains the literal word "LIKE"

- File: src/wmi.rs:1514-1525
- Description: `parse_simple_condition` searches `trimmed.to_uppercase().find("LIKE")` over the *whole* condition, including quoted values, and the LIKE branch does not validate the property with `is_simple_property` (unlike the operator branches). E.g. `SELECT * FROM Win32_Processor WHERE Name = 'LIKE'` produces `Simple { property: "Name = '", op: Like, ... }` → `evaluate_condition` looks up property `"Name = '"` → misses → query silently returns empty results (wrong behavior, no error).
- Fix suggestion: only treat LIKE as an operator when the token is bounded by whitespace/quote boundaries and `is_simple_property(before)` holds, mirroring the `!=`/`<=` branch logic; otherwise fall through to the operator loop.

## [MEDIUM] `parent_hwnd` dropped in the native controller path

- File: src/webview2.rs:1696-1720, 1526
- Description: `create_controller(env_id, parent_hwnd)` passes only `(env, webview_id, width, height)` to `WebView2Controller::create`; the native path hardcodes `parent_hwnd: 0` (line 1526). The guest's HWND association is lost for native controllers, so window-parented behavior (bounds/visibility tied to the guest window) is wrong.
- Fix suggestion: thread `parent_hwnd` into `WebView2Controller::create` and store it.

## [LOW] Post-message JS injection escaping incomplete (U+2028/U+2029 and friends)

- File: src/webview2.rs:2126-2133, 2149-2156
- Description: the JS string literal only escapes `\`, `'`, `\n`, `\r`. A message containing U+2028/U+2029 (JS line terminators) breaks out of the string literal; `JSON.parse('...')` also mis-parses certain payloads, potentially throwing into page context. Escape `\u2028`/`\u2029` (and ideally `\b`/`\f`/`\t`/`<`) or build the literal with `JSON.stringify` semantics.
- Fix suggestion: escape at least `\u2028`, `\u2029`, `\u0000-\u001F`, and quote with `JSON.stringify` when embedding JSON.

## [LOW] `percent_encode_data_url` gaps: no charset, reserved chars unencoded

- File: src/webview2.rs:2652-2665
- Description: `?`, `&`, `=`, `+`, `,`, `;`, `@`, `/`, `:` are left raw (mostly benign in a `data:` URL) and no `charset=` is emitted, so multi-byte UTF-8 HTML is percent-encoded per byte and can render as mojibake (latin-1 interpretation). Also `#` inside the HTML is encoded — good — but content after an unencoded `?` may be dropped by some parsers.
- Fix suggestion: emit `data:text/html;charset=utf-8,` and percent-encode all bytes outside the unreserved set (or use base64 encoding for the payload).

## [LOW] Dead no-op block in `WebView2Environment::new`

- File: src/webview2.rs:1362-1366
- Description: `if let (Some(_nd), Ok(_state)) = (nav_delegate, DELEGATE_STATE.lock()) { ... }` acquires the lock and does nothing — dead code that also suggests a half-finished registration (the delegate is never associated with the map used by the callback handlers).
- Fix suggestion: remove the block, or implement the intended registration (which is what finding HIGH #4 needs).

## [LOW] `env.controllers` keeps stale controller IDs after `destroy_controller`

- File: src/webview2.rs:1789-1796
- Description: `destroy_controller` removes the controller/webview/settings but does not remove the controller ID from its environment's `controllers` Vec; later `destroy_environment` iterates the stale IDs (harmless `remove` misses, but the Vec keeps growing and `env.controllers.len()` no longer reflects reality).
- Fix suggestion: remove `id` from the owning environment's `controllers` in `destroy_controller` (or drop the bookkeeping Vec).

## [LOW] Global `DELEGATE_STATE` never cleaned up; cross-instance and cross-test leakage

- File: src/webview2.rs:124-126, 1824-1910, 2625-2628
- Description: callback registrations and nav states live in a process-global `LazyLock<Mutex<...>>`; nothing purges registrations for destroyed runtimes/webviews, and `next_callback_id`/vectors persist across `WebView2Runtime` instances. Unit test `test_webview2_callback_system` asserts global vector lengths, which is flaky when tests run in parallel (in-module and with other modules). Poisoning of the global mutex silently disables all delegate functionality.
- Fix suggestion: scope state per runtime instance or purge on destroy; make tests use independent state.

## [LOW] `os_version` Darwin fallback wrong for macOS 10.x

- File: src/wmi.rs:156-163
- Description: `major - 9` maps Darwin 23→14 correctly for modern macOS, but for Darwin 17/18/19 (macOS 10.13-10.15) it yields "8.0"/"9.0"/"10.0" instead of "10.13"-"10.15". Only hits when `kern.osproductversion` is unavailable, but the result is then silently wrong.
- Fix suggestion: special-case Darwin < 20 (map 17→10.13, 18→10.14, 19→10.15) before the subtract-9 rule.

## [LOW] WQL LIKE pattern interpolated into regex without escaping metacharacters

- File: src/wmi.rs:1641-1647
- Description: guest-supplied LIKE patterns replace only `%`→`.*` and `_`→`.`; other regex metachars (`(`, `[`, `+`, `*`, `|`, `{`) pass through into the compiled regex, giving wrong match semantics (and invalid patterns fall back to a plain compare at 1646, which then behaves differently). The `regex` crate is not ReDoS-prone, so impact is wrong results, not hangs.
- Fix suggestion: escape regex metacharacters first (`regex::escape` on the pattern), then replace `%`/`_`, or implement a small glob matcher directly.

## [LOW] Wrong CFNumber type constant (works by accident on 64-bit)

- File: src/wmi.rs:823, 867
- Description: `const KCF_NUMBER_S64_TYPE: u32 = 14;` — 14 is `kCFNumberCFIndexType`, not `kCFNumberSInt64Type` (which is 4). `CFNumberGetValue` converts to `CFIndex` (long, 8 bytes on LP64) so it happens to fill the `i64` correctly on 64-bit macOS, but the constant is wrong and would truncate on a 32-bit target.
- Fix suggestion: use `4` (`kCFNumberSInt64Type`).

## [LOW] `Win32ProcessorProvider::enum_objects` rebuilds a full object per core (redundant syscalls)

- File: src/wmi.rs:560-563
- Description: one `build_object()` per physical core, each re-running 3 sysctls (`hw.physicalcpu`, `hw.logicalcpu`, `hw.cpufrequency`) and cloning strings — O(cores) duplicate work and duplicated identical objects where WMI expects one object per installed processor.
- Fix suggestion: build the object once and clone it per entry (or return a single object), moving the sysctl reads out of the loop.

---

## Clippy

Full run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (completed, output `clippy_out.txt`). All warnings below are for the audited files; no clippy **error** references `src/webview2.rs` or `src/wmi.rs` (see `## Build`).

`src/webview2.rs` (12 warnings):
- 307:9, 345:9, 364:9, 513:9 — collapsible_if (DELEGATE_STATE lock blocks)
- 564:5 — new_without_default (`WebView2Settings`)
- 1240:42 — unnecessary_cast (`handler_ptr as *mut objc::runtime::Object`)
- 1675:5 — new_without_default (`WebView2Runtime`)
- 2038:39, 2049:39 — for_kv_map (`fire_navigation_starting`/`fire_navigation_completed`)
- 2209:21 — collapsible_if (`capture_preview`)
- 2252:5 — new_without_default (`WebView2Events`)
- 2388:1 — items_after_test_module (`percent_encode_data_url` after `mod tests`)

`src/wmi.rs` (19 warnings):
- 156:5, 157:9 — collapsible_if (`os_version` fallback)
- 349:1 — derivable_impls (`Default for WmiPropertyValue`)
- 588:44, 589:40, 590:39, 591:44 — unnecessary_cast (`as u64` no-ops)
- 677:9 — collapsible_if (`get_gpu_name`)
- 717:51, 732:17, 826:51, 841:17 — manual_c_str_literals (`"\0"` literals)
- 1021:21 — collapsible_if (`ifconfig` parse)
- 1112:21 — collapsible_match (`get_object` MACAddress)
- 1533:13, 1534:17, 1553:13, 1554:17 — collapsible_if (`parse_simple_condition` operator loop)
- 1712:5 — too_many_arguments (`connect_server`)

## Build

`cargo clippy --all-targets --no-deps` completed (05:10 UTC); the crate is **not** clippy-clean: `casa1` (lib) fails with 19 deny-level clippy errors and `casa1` (lib test) with 27, all located in other files (crash_recovery.rs, d3d11.rs, jit.rs, metal_backend.rs, pe_runtime.rs, security.rs, video_decoder.rs, winhttp.rs, cpu.rs, d2d.rs, dwrite.rs, seh.rs — e.g. not_unsafe_ptr_arg_deref, approx_constant, double_comparisons). No errors reference `src/webview2.rs` or `src/wmi.rs`; both files only produce the warnings listed above. Nothing failed in the audited files; the environmental ffmpeg note was not applicable to this run.
