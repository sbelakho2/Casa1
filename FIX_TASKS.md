# Audit Findings — Batch: mac-gfx

- **Files:** `src/mac_window.rs` (1955 lines), `src/metal_renderer.rs` (1323 lines), `src/gdiplus_render.rs` (1834 lines), `src/shader_compiler.rs` (1831 lines) — every line read, in order.
- **Date:** 2026-08-15
- **Toolchain:** clippy 1.96.0, `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (see `## Clippy` / `## Build` sections).

---

## [CRITICAL] Out-of-bounds read of CEF pixel buffer in Metal texture upload

- File: `src/metal_renderer.rs:478-493` (assumption at line 487: `bytes_per_row = (width as u64) * 4`)
- Description: `upload_cef_overlay_if_needed()` calls `texture.replace_region(region, 0, frame.pixels.as_ptr(), bytes_per_row)` assuming `pixels.len() == width*height*4`. The size is never validated against `pixels.len()`. `submit_cef_overlay_frame()` (line 921) is a public API; a frame with mismatched dimensions/length (guest/CEF-driven, untrusted) makes Metal read up to `width*height*4` bytes from a shorter heap buffer — OOB read (UB). Same class of bug in `draw_image`/`draw_image_rect` (`gdiplus_render.rs:1300,1351`) but those are bounds-checked via `src_idx + 3 >= src_pixels.len()` (they skip, not crash).
- Fix suggestion: before upload, `if frame.pixels.len() < (width as usize) * (height as usize) * 4 { return Ok(()) }` (or log + skip). Clamp region size to what the buffer can provide.

## [HIGH] `draw_ellipse` i32 arithmetic overflow → debug panic / release hang or garbage

- File: `src/gdiplus_render.rs:586-647`
- Description: `rx`,`ry` are `i32` derived from guest-supplied f32 widths. `d1 = ry*ry - rx*rx*ry + rx*rx/4`, `2*ry*ry*dx`, `rx*rx*ry*ry` and the loop condition `dx*ry*ry < dy*rx*rx` all overflow i32 at moderate sizes (e.g. rx=ry=1500: `rx*rx*ry ≈ 3.4e9 > i32::MAX`). Debug builds panic; release builds wrap, which can keep `d1 < 0` forever → `dx` grows unboundedly → infinite loop (hang). Same overflow pattern in `fill_polygon` step arithmetic (see below).
- Fix suggestion: compute in `i64` (or `f64`) throughout `draw_ellipse`; clamp `rx`,`ry` to a sane max (e.g. ≤ 2^15) before the midpoint loop.

## [HIGH] Generated domain shader writes through `device const` pointer — MSL will not compile

- File: `src/shader_compiler.rs:866` (declared `device const float4* _ds_tessellated_vertices`) and `:971` (`_ds_tessellated_vertices[_ds_vert_id] = _ds_position;`)
- Description: The domain-shader template declares the tessellated-vertex buffer `const` but then writes to it. Metal rejects assignment through a const-qualified pointer, so every generated Ds shader fails to compile — tessellation path is always broken.
- Fix suggestion: drop `const` on `_ds_tessellated_vertices` (and write to a separate output buffer if the input must stay const).

## [HIGH] Tessellation semantic attributes swapped (SV_TESSFACTOR ↔ SV_INSIDETESSFACTOR)

- File: `src/shader_compiler.rs:53-54`
- Description: `SV_TESSFACTOR` (edge factors) maps to `[[patch(tess_level_inner)]]` and `SV_INSIDETESSFACTOR` (inside factors) maps to `[[patch(tess_level_outer)]]`. HLSL SV_TessFactor = outer (edge) factors, SV_InsideTessFactor = inner; Metal `tess_level_outer`/`tess_level_inner` match respectively. The two mappings are swapped — tessellated output will be wrong whenever these semantics are present.
- Fix suggestion: `SV_TESSFACTOR => "[[patch(tess_level_outer)]]"`, `SV_INSIDETESSFACTOR => "[[patch(tess_level_inner)]]"`.

## [HIGH] VS/PS entry points are skeletons: stage_in inputs and translated instructions are dropped

- File: `src/shader_compiler.rs:448-506` (`generate_vertex_entry`) and `:508-575` (`generate_fragment_entry`)
- Description: The generated vertex function signature is `vertex VertexOutput fn(uint vid [[vertex_id]], uint instance_id [[instance_id]], ...)` — it never declares `VertexInput in [[stage_in]]`, so the `VertexInput` struct generated at lines 394-412 is dead and all D3D input-assembly vertex attributes are lost. Every output is hardcoded to `{}(0)` (zero). `emit_instruction_body()` (the translated DXIL instructions, `set_instructions`) is never called for VS/PS — only for Cs/Gs/Hs/Ds. Any real vertex/fragment shader therefore produces constant/zero output regardless of the DXIL body.
- Fix suggestion: add `VertexInput in [[stage_in]]` when `inputs` is non-empty, copy inputs to outputs per semantic (at minimum pass through), and emit `emit_instruction_body(source)` inside the entry point after locals.

## [HIGH] Unbounded arc segment count → OOM/hang from untrusted sweep angle

- File: `src/gdiplus_render.rs:837` (`let segments = 64.max((sweep_angle.abs() * 0.5) as i32);`)
- Description: `sweep_angle` comes from guest GDI+ calls (`GdipDrawArc`/`GdipDrawPie`). A large sweep (e.g. 1e9°) saturates `segments` toward `i32::MAX` (2.1e9) — the loop at line 845 pushes up to 2.1e9 `GdiplusPointF`s (≈34 GB) → OOM abort; `fill_pie` then builds an edge table over the same vector. A plain hang/DoS reachable from untrusted input.
- Fix suggestion: cap segments (e.g. `64.max((sweep_angle.abs() * 0.5).min(4096.0) as i32)`).

## [HIGH] CEF overlay pixel format inconsistent between IOSurface and CPU paths (R/B swap on one path)

- File: `src/metal_renderer.rs:440` (IOSurface path: `MTLPixelFormat::BGRA8Unorm`) vs `:463` (CPU path: `MTLPixelFormat::RGBA8Unorm`)
- Description: The same overlay texture is filled either by aliasing an IOSurface as BGRA8Unorm or by uploading `frame.pixels` as RGBA8Unorm. The compositor's own `create_io_surface` (metal_backend.rs:1395) documents surfaces as `'BGRA'`, and the same MSL shader samples both — so one of the two paths renders the overlay with red/blue swapped. Behavior also flips depending on which path a given frame takes.
- Fix suggestion: pick one canonical layout (BGRA, matching IOSurface) and use `BGRA8Unorm` + matching byte-order upload in both paths; add a unit test asserting both paths sample identical colors.

---

## [MEDIUM] `poll_nsevent` can never return an event (and the whole NSEvent subsystem is dead)

- File: `src/mac_window.rs:1077-1085`
- Description: `NSDefaultRunLoopMode` is an `NSString*` global constant, not an ObjC class. `objc::runtime::Class::get("NSDefaultRunLoopMode")` always returns `None`, so `poll_nsevent()` always returns null on macOS — no native NSEvents can ever be polled. (Even if the lookup succeeded, `performSelector: new` on the constant would be wrong, and the resulting object is never released.) Note also that `poll_nsevent` and every `nsevent_*` accessor have zero production callers — the whole polling path is dead code.
- Fix suggestion: obtain the run-loop mode via `[NSRunLoop defaultRunLoopMode]` (or `NSDefaultRunLoopMode` via `NSRunLoop` class method) — or delete the subsystem until wired up; at minimum don't claim the mask/mode handling works.

## [MEDIUM] `nswindow_content_view` violates the module's main-thread contract

- File: `src/mac_window.rs:923-933`
- Description: Every other public AppKit helper dispatches through `run_on_main`; this function sends `contentView` directly. If any background/PE-runtime thread ever calls it, AppKit's main-thread-only API is used off the main thread (undefined behavior, potential crash). Currently no callers, but the module documents "Every public function in this module automatically dispatches to the main thread."
- Fix suggestion: wrap in `run_on_main(move || ...)` like the other helpers.

## [MEDIUM] Dead allocation leaked on every string clipboard write

- File: `src/mac_window.rs:1476-1479`
- Description: `let _arr = msg_send![cls_nsstring, alloc]` allocates an NSString instance (comment even says "NSArray actually") that is never used, never released, and is wrong on both counts. Every `nspasteboard_set_data` call for text formats leaks one object; the subsequent `arrayWithObjects:` is the correct path.
- Fix suggestion: delete the `_arr` block entirely.

## [MEDIUM] Object pointer returned through a `bool` in `nspasteboard_is_format_available`

- File: `src/mac_window.rs:1606-1611`
- Description: `availableTypeFromArray:` returns `NSString*`; the result is read as `bool`. Reading a pointer as a 1-byte bool yields false whenever the returned object's low byte is 0 (any 256-byte-aligned object — plausible for AppKit's immortal constant type strings) → false negatives on available formats. Also the temporary `ns_array` is never released (autoreleased by factory method, so acceptable, but fragile).
- Fix suggestion: declare `let available: *mut objc::runtime::Object = msg_send![...]` and use `!available.is_null()`.

## [MEDIUM] CAMetalLayer `drawableSize` not scaled by `contentsScale`; content view not null-checked

- File: `src/mac_window.rs:1032-1045`
- Description: `setDrawableSize:` is called with `(width, height)` in (presumed point) units while `contentsScale` is set from the backing scale factor (line 1037-1038). For a Retina scale of 2.0 the drawable must be `width*scale × height*scale` pixels; otherwise the layer renders at half resolution (blurry) or is upscaled. Also `content_view` from `[win contentView]` is not null-checked before `setWantsLayer:`/`setLayer:` (nil messaging is safe, but the function then reports success without attaching anything).
- Fix suggestion: `setDrawableSize:` with `width * scale, height * scale` (pixels) and `if content_view.is_null() { return null; }`.

## [MEDIUM] `releasedWhenClosed: YES` leaves stale (dangling) NSWindow pointers in HWND map

- File: `src/mac_window.rs:794` (setReleasedWhenClosed) with `:271-303` (HWND_TO_NSWINDOW map)
- Description: `close_nswindow` → `[win close]` releases the window (retain from `alloc`). The `HWND_TO_NSWINDOW` map retains the raw pointer until `remove_hwnd_nswindow` is called; if any code path accesses the map after the window was closed without removing the entry, it dereferences freed memory. user32.rs removes the entry on NcDestroy/DestroyWindow, but a window closed by other paths (e.g. `[NSWindow close]` from AppKit side or `WM_CLOSE` handled elsewhere) leaves a dangling entry.
- Fix suggestion: explicitly `remove_hwnd_nswindow` inside `close_nswindow` (or drop `setReleasedWhenClosed` and manage the retain/release explicitly).

## [MEDIUM] `fill_polygon` scanline step arithmetic overflows i32

- File: `src/gdiplus_render.rs:798` (`let x = x_at_min + step * (scan_y - y_min);`)
- Description: `step` is `dx as i32` and `scan_y - y_min` can be large; for extreme-but-plausible guest coordinates the i32 multiply overflows → debug panic; release wraps and fills wrong (possibly negative→clamped-to-0) regions. Related to the same overflow theme as `draw_ellipse`.
- Fix suggestion: use `i64` for `step` and `x`, then clamp to the bitmap before pushing into `intersections`.

## [MEDIUM] `draw_image_rect` u32 underflow panics on zero-size source

- File: `src/gdiplus_render.rs:1347-1350`
- Description: `(src_width - 1) as f32` underflows when `src_width == 0` → debug-build panic (release wraps to a huge float, silently wrong scaling). `src_width`/`src_height` are caller-supplied (guest image dimensions).
- Fix suggestion: guard `if src_width == 0 || src_height == 0 { return; }` at the top.

## [MEDIUM] Negative (bottom-up) strides silently produce no output

- File: `src/gdiplus_render.rs:100-102` (`put_pixel`), `:184` (`brush_color_at`), `:1300` (`draw_image`)
- Description: GDI/GDI+ bitmaps can have negative stride (bottom-up DIBs). Here `idx = y*stride + x*4` becomes negative → the `idx < 0` guard returns, so every pixel of a bottom-up surface is dropped (texture sampling likewise returns transparent black). Silent wrong rendering rather than a crash.
- Fix suggestion: if `stride < 0`, flip the row index (`y` measured from the bottom: `idx = (height-1-y)*stride + x*4`) or document/up-convert at the caller.

## [MEDIUM] `fill_path` merges all figures into one polygon

- File: `src/gdiplus_render.rs:1184-1263`
- Description: All `GdiplusPathElement`s (including disjoint figures and `StartFigure`/`CloseFigure`, which are ignored) are appended into a single `poly_points` vector and filled as one polygon — scanline fill will connect unrelated figures with spurious fills, and self-intersecting combinations produce artifacts. Non-convex/self-intersecting input is explicitly out of scope of `fill_polygon` ("convex or simple polygon").
- Fix suggestion: fill each connected figure separately (split on `StartFigure`/`CloseFigure` and on element type boundaries), or at minimum document the limitation and skip multi-figure paths.

## [MEDIUM] `translate_hlsl_intrinsic("mul")` emits a comment, breaking generated MSL

- File: `src/shader_compiler.rs:1063`
- Description: `"mul" => "/* mul -> matrix multiply */"` — when this replacement is inlined into an MSL expression (as the translator does for other intrinsics), the expression loses its value: `float4 r = /* mul ... */;` is a syntax error, and `x = /* mul ... */ * y;` is invalid. Matrix multiply is one of the most common HLSL intrinsics.
- Fix suggestion: translate `mul(a,b)` contextually (matrix/vector multiply in MSL is `a * b` or `a * b` with the transpose convention handled) — at minimum return `"*"` or generate an explicit `mul` helper function.

## [MEDIUM] Barrier after divergent early-return in generated geometry shader (Metal UB)

- File: `src/shader_compiler.rs:733` (`if (_gs_base + {input_verts} > _gs_vertex_count) return;`) combined with `:611-614` (final `threadgroup_barrier`)
- Description: When the instruction body contains barriers, the kernel appends a `threadgroup_barrier` (line 612) after code that may have already returned in some threads — a barrier reached by only a subset of threads is undefined behavior in Metal and can hang the GPU.
- Fix suggestion: move the bounds check to a per-thread flag (`if (ok) { ...barrier... }` guarded), or emit the early return only when the body has no barriers.

## [MEDIUM] IOSurface ownership is never resolved: leaked or dangling

- File: `src/metal_renderer.rs:777` (`pending_io_surface: Option<IoSurfacePtr>`), `:828-831`, `:836`, and `:931-939`
- Description: `submit_io_surface_frame` stores a raw IOSurfaceRef with no retain and nothing ever `CFRelease`s it: submitting twice leaks the previous surface; if the producer releases after submit, `create_texture_from_io_surface` (called later, off the producer's stack) uses a dangling pointer. The doc comment on `submit_cef_overlay_io_surface` ("must be a valid IOSurfaceRef") doesn't state ownership. (Path is currently dead — no callers — but the contract is a trap for the next caller.)
- Fix suggestion: define ownership explicitly: retain on submit + release on `take_pending_frame`/texture creation failure, or require the caller to keep it alive until the frame is consumed; document it.

## [MEDIUM] Presenting an unrendered drawable when overlay is active but no texture exists

- File: `src/metal_renderer.rs:630-673` (`composite_and_present`)
- Description: When `steam_overlay_is_active()`, `present()` routes through `composite_and_present()`. If `cef_overlay_texture` is `None` (no frame yet) the command buffer contains no render pass at all, yet the freshly acquired drawable is presented — the game's rendered content is dropped/black for that frame. If `ensure_cef_overlay_pipeline` errors, the command buffer is also left uncommitted (dropped without commit).
- Fix suggestion: when the overlay texture is missing, fall back to the normal present path (`cmd_buffer.present_drawable` on the drawable the game rendered to, or skip present entirely); commit/`end_encoding` error paths.

## [MEDIUM] `BlendFactor::BlendFactor` maps to Metal `BlendAlpha` (wrong for RGB channels)

- File: `src/metal_renderer.rs:1050`
- Description: D3D `D3D11_BLEND_BLEND_FACTOR` applies the per-draw blend constant to all components. Metal has `BlendColor` (uses RGB of the blend color) and `BlendAlpha` (uses A only). Mapping both RGB and alpha blend factors to `BlendAlpha` means the RGB factor is wrong whenever a game uses `BLEND_FACTOR` with a non-1.0 color.
- Fix suggestion: translate RGB factors to `MTLBlendFactor::BlendColor` and alpha factors to `BlendAlpha` (split the single mapping into rgb/alpha variants), or emit a dedicated blend-factors branch.

## [MEDIUM] Window Y-flip uses main-screen height regardless of target display

- File: `src/mac_window.rs:755` and `:892`
- Description: `flipped_y = screen_height - y - height` uses `[NSScreen mainScreen].frame.height` (create path) or the window's current screen (set-frame path). On multi-monitor setups with differing heights, windows positioned on a secondary display land at the wrong vertical offset (Windows Y coordinates are relative to the primary monitor's top-left, but each macOS screen has its own global frame origin).
- Fix suggestion: resolve the target screen via the requested position (nearest screen whose frame contains `(x, y)`) and flip against that screen's frame; fall back to the main screen.

## [MEDIUM] `run_on_main` can deadlock / lose wakeups on shutdown

- File: `src/mac_window.rs:66-124`
- Description: A background thread blocks on the condvar until `pump_main_queue()` runs its item. If the main loop never pumps again (shutdown, or a background thread calls an AppKit helper before the loop starts), the thread hangs forever. Additionally, if the process tears down while items are queued, the `done` condvar is never signaled (notified threads parked on the queue). The `Send` transmute at lines 100-101 is also only sound because the main loop is the sole pump — worth an explicit assertion (`debug_assert` on `pthread_main_np`) inside `pump_main_queue`.
- Fix suggestion: document the invariant; add a `Drop`/shutdown path that signals pending items, and consider a bounded wait + timeout for callers during teardown.

## [MEDIUM] WS_POPUP windows are created with a full title bar

- File: `src/mac_window.rs:531-534`
- Description: Popup windows map to `Titled | Closable`, giving them a title bar and close button; Windows popups have a border but no caption (WS_POPUP alone has no caption; `WS_POPUPWINDOW` = border+sysmenu). This changes look/behavior for menus and tooltips.
- Fix suggestion: for `WS_POPUP` without `WS_CAPTION`, return `NSWindowStyleMaskBorderless` (with a thin border via `hasShadow`/borderless) or `Titled` only if `WS_CAPTION` is set.

---

## [LOW] Dead code: `clip_rect_for_bounds`

- File: `src/gdiplus_render.rs:131-141`
- Description: Private helper with no callers (crate has `#![allow(dead_code)]`, so clippy misses it). Also contains the `bw as i32 - 1` underflow pattern if `bw == 0`.
- Fix suggestion: remove it, or use it in `draw_ellipse`/`fill_ellipse` to replace the ad-hoc clamps.

## [LOW] `draw_string` uses byte offsets instead of character indices

- File: `src/gdiplus_render.rs:1397-1398`
- Description: `text.char_indices()` yields byte offsets, so multi-byte UTF-8 characters get over-wide spacing (`i as i32 * char_w` skips per byte, not per char). Placeholder renderer, but trivially fixable.
- Fix suggestion: use `text.chars().enumerate()` (or `char_indices()` with a separate counter).

## [LOW] `FrameContext`/`begin_frame`/`end_frame` never commit or present

- File: `src/metal_renderer.rs:360-380, 981-1030`
- Description: `begin_frame` creates a command buffer that is never committed (dropped → no GPU work), and `end_frame` only bumps a counter; no present occurs in this flow. If any caller uses this API expecting frames to render, nothing is submitted (currently dead — `present()` is the live path).
- Fix suggestion: remove the API or make it commit the buffer; document that it's a stub.

## [LOW] `resize_cef_overlay` ignores its width/height parameters

- File: `src/metal_renderer.rs:676-681`
- Description: Both args unused (only forces texture realloc). Misleading API.
- Fix suggestion: drop the params or store them.

## [LOW] Dead vsync/frame-pacing and IOSurface submission APIs

- File: `src/metal_renderer.rs:883-892` (`should_composite`, no callers) and `:931-939` (`submit_cef_overlay_io_surface`, no callers)
- Description: `should_composite` updates `last_vsync_timestamp` but is never invoked; the fixed 16.67ms `vsync_interval_ns` also ignores the actual display refresh rate. Dead code plus latent IOSurface ownership hazard (see MEDIUM finding).
- Fix suggestion: wire `should_composite` into the present path (or delete), and derive the interval from `CVDisplayLink`/`CADisplayLink`.

## [LOW] Shader cache hash parameter allows path traversal

- File: `src/shader_compiler.rs:999-1052` (`get`/`put`/`get_source`/`put_source`/`cache_path`)
- Description: `cache_dir.join(format!("{hash}.metallib"))` — a public API taking an arbitrary string; a hash containing `/` or `..` escapes the cache directory (read/write of arbitrary files). Internal callers use hex `dxil_hash` output, so latent only.
- Fix suggestion: validate the hash (e.g. `hash.chars().all(|c| c.is_ascii_hexdigit())`) before joining.

## [LOW] Hull-shader tess-factor comment/index mismatch for triangle patches

- File: `src/shader_compiler.rs:828-841`
- Description: For `PatchType::Triangle` the loop writes factors `0..=3` where index 3 is the inside factor (Metal layout), but it's emitted as `// edge factor 3`. Quad writes edges 0-3 and inside 4-5 correctly. Cosmetic, but misleading for future maintenance; the inside factor is also hardcoded to 1.0 (placeholder).
- Fix suggestion: label index 3 as the inside factor for triangles, and note the factors are placeholders.

## [LOW] Generated GS default emit assigns float3/float2 to float4 slots

- File: `src/shader_compiler.rs:749-750` (`_gs_out[1] = _gs_normal;` / `_gs_out[2] = _gs_texcoord;` with `_gs_out` being `device float4*`)
- Description: MSL does not implicitly convert float3/float2 → float4; the generated code likely fails to compile. Needs a quick check by compiling one generated GS.
- Fix suggestion: emit `float4(_gs_normal, 0.0)` / `float4(_gs_texcoord, 0.0, 0.0)`.

## [LOW] Void ObjC method read as `u64`; `_hwnd` ignored

- File: `src/mac_window.rs:1655-1658` (`flash_nswindow`)
- Description: `requestUserAttention:` returns void; the return is declared `u64` (reads an undefined register, discarded — harmless but wrong). `_hwnd` and `_flash=false` are ignored; the function returns `true` even when nothing happened.
- Fix suggestion: type the return as `()`, and return meaningful success.

## [LOW] `hlsl_type_to_msl` silently maps unknown types to `float4`

- File: `src/shader_compiler.rs:71-95`
- Description: Unknown/unsupported HLSL types (e.g. `matrix<float,3,4>`, `float3x4`, structured buffers) become `float4`, silently corrupting shader data layouts instead of failing loudly.
- Fix suggestion: return an `AppResult`/error (or generate `// ERROR: unknown type` MSL) for unsupported types.

---

## [PERF] String-keyed depth-stencil cache allocates on every lookup

- File: `src/metal_renderer.rs:345` (`let key = format!("{depth_enable}_{depth_write_enable}_{:?}", depth_func);`)
- Description: `format!` allocates a String per call and BTreeMap lookups are O(log n); this runs per draw call in the hot path. Only 8 functions × 2 bools = 32 states exist.
- Fix suggestion: use a tuple key `(bool, bool, ComparisonFunc)` with `BTreeMap`/`HashMap` (or a 32-entry array indexed by `(depth_enable<<2 | depth_write_enable<<1 | func)`).

## [PERF] `mach_absolute_time` conversion can overflow; unused path

- File: `src/metal_renderer.rs:954-974`
- Description: `mach_time * timebase.numer as u64` multiplies in u64 before dividing; with a numer of 125 and a long-running timer value this can wrap (timebase is usually 1/1 on Apple Silicon, so latent). Also the whole `should_composite`/timestamp machinery is dead (see LOW finding).
- Fix suggestion: use `libc::clock_gettime(CLOCK_MONOTONIC)` nanoseconds, or compute in 128-bit/checked math.

---

## Clippy

Run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (clippy 1.96.0), output in `clippy_out.txt`. Warnings referencing the four audited files (none are errors):

- `src/mac_window.rs`: `needless_return` ×16 (lines 393, 465, 475, 490, 579, 659, 710, 812, 841, 866, 910, 947, 966, 990, 1025, 1072, 1406, 1441, 1527, 1584, 1645 — the `return run_on_main(...)` pattern is intentional to satisfy `#[cfg]` blocks, so these are stylistic), `manual_c_str_literals` (403), `doc_lazy_continuation` (1433-1434), `collapsible_if` (724).
- `src/metal_renderer.rs`: `collapsible_if` (507, 651), `new_without_default` for `CefMetalCompositor` (792), `explicit_auto_deref` (916).
- `src/gdiplus_render.rs`: `too_many_arguments` ×16 (87, 301, 417, 449, 528, 564, 705, 859, 889, 912, 944, 1283, 1325, 1379), `unnecessary_cast` (100×2). Note: `too_many_arguments` is structural (renderer signature); no functional impact.
- `src/shader_compiler.rs`: `useless_format` ×4 (717, 727, 835, 838).

No clippy warnings in these files for: `unsafe_op_in_unsafe_fn`, `unwrap_used`, `unnecessary_unwrap` (a few `.unwrap()`s exist, e.g. metal_renderer.rs:654, mac_window.rs:1336, 1465, 1481, 1493, 1608 — all on guaranteed-present classes/index 0, so not flagged and low risk).

## Build

`cargo clippy --all-targets --no-deps` did **not** fully complete: the `casa1` lib-test target aborted with **27 clippy lint errors** (denied lints) — none of them reference the four audited files (errors are in `user32.rs` unsafe-raw-pointer fns, `shader.rs` arithmetic, `video_decoder.rs`, `steam_protocol.rs`, etc.). `casa1` (lib) checked clean of errors with 1271 warnings. Because the lib-test target failed, bin targets were not reached. A normal `cargo build` may still succeed since these are lint-level, not rustc, errors — verify with `cargo build` if needed. Per instructions, missing system ffmpeg under `--all-features` was not exercised (no `--all-features` used).

---

## Summary

- **CRITICAL:** 1 — **HIGH:** 6 — **MEDIUM:** 18 — **LOW:** 10 — **PERF:** 2
- **Total findings:** 37
- Report: `AUDIT_FINDINGS.md` (this file) in the worktree root.
- Note: no source files were modified; only `AUDIT_FINDINGS.md` and the clippy log `clippy_out.txt` were created.
