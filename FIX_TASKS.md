# AUDIT_FINDINGS.md

- **Batch**: Casa1 full-codebase audit — batch 1
- **Files** (all read line-by-line, in full):
  - `src/dwrite.rs` (1527 lines)
  - `src/live.rs` (1074 lines)
  - `src/icon.rs` (521 lines)
  - `src/denuvo.rs` (1259 lines)
  - `src/anticheat.rs` (1148 lines)
  - `src/host_thunks.rs` (713 lines)
  - `src/reason.rs` (558 lines)
- **Date**: 2026-08-15
- **Total findings**: 25 (1 CRITICAL, 7 HIGH, 7 MEDIUM, 8 LOW, 2 PERF)

---

## [CRITICAL] u32 overflow in draw() pixel-buffer sizing can under-allocate and then be overrun by Core Graphics

- File: src/dwrite.rs:1061-1066, 1204-1210
- Description: `let width = (self.metrics.width.max(1.0)) as u32;` — the f32→u32 cast saturates, so a guest-controlled huge `font_size`/`max_width` (e.g. `1e9`) yields `width`/`height` near `u32::MAX`. The buffer sizes are computed in u32: `(width * height * 4) as usize` (line 1065) and `row_bytes = bmp_w * 4; buf_size = (row_bytes * bmp_h) as usize` (lines 1208-1210). In release builds the multiplication wraps, allocating a tiny `Vec`, after which `CGBitmapContextCreate` (line 1213) writes `bmp_w * bmp_h * 4` bytes into `pixel_buf` → **heap buffer overflow (memory corruption)**. In debug builds the same multiplication panics. Sizes that do not overflow still cause multi-GB `vec!` allocations (OOM abort).
- Fix suggestion: compute sizes with `usize` and checked arithmetic and enforce a sane cap, e.g. `let w = (self.metrics.width.max(1.0)) as usize; let h = ...; let pixels = w.checked_mul(h).and_then(|n| n.checked_mul(4)).filter(|n| *n <= MAX_BUF)`, returning `None`/error when out of range. Apply the same to `row_bytes`/`buf_size` in the bitmap path.

---

## [HIGH] CTLineDraw is dlopen'd from CoreGraphics; the symbol lives in CoreText — draw() always returns None

- File: src/dwrite.rs:1142-1144
- Description: `cg_lib.get(b"CTLineDraw")` resolves the symbol against CoreGraphics.framework, but `CTLineDraw` is a CoreText API (CTLine.h). The lookup fails on macOS, `?` propagates `None`, and the entire `draw()` rendering path (attributed string → CTLine → bitmap context) silently returns `None`/empty bitmaps. Every other CoreText symbol in this file is loaded from `ct_lib` (lines 443-532), so this is an inconsistency, not a design choice.
- Fix suggestion: load `CTLineDraw` from the CoreText library handle (the factory's `ct_lib` or a separate `libloading::Library::new("/System/Library/Frameworks/CoreText.framework/CoreText")`), and do not fail the whole draw when only that symbol is missing — degrade to the empty-bitmap fallback.

---

## [HIGH] `unwrap()` on a possibly-None function pointer in measure_text

- File: src/dwrite.rs:765
- Description: The `if let` guard (lines 752-762) binds `create_line`, `get_typographic_bounds`, `create_attr_str`, `create_dict` — but not `ct_font_create_with_name`, which is then `unwrap()`ed at line 765. Core Text symbols are loaded one-by-one via `load_symbol` (each may independently fail), so a partially failed dlopen (CTFontCreateWithName missing while the other four present) panics. Every other use of the same pointer in the file is guarded with `if let Some(...)`.
- Fix suggestion: add `Some(create_font)` to the destructuring pattern at line 752 and use it instead of `self.ct_font_create_with_name.unwrap()`.

---

## [HIGH] Panic on malformed ICO: entry offset beyond EOF produces an inverted slice

- File: src/icon.rs:242-244
- Description: For untrusted ICO data, `entry.offset` can exceed `ico_data.len()` (e.g. `offset = 0xFFFF_FF00`, file length 100). Then `data_start > ico_data.len()`, `data_end = min(data_start + size, len) = len < data_start`, and `ico_data[data_start..data_end]` panics ("slice index starts at X but ends at Y"). This is reachable from any user-supplied `.ico`/PE icon resource.
- Fix suggestion: `let data_start = entry.offset as usize; if data_start >= ico_data.len() { continue; }` (or return an error), then `let data_end = data_start.saturating_add(entry.size as usize).min(ico_data.len());`.

---

## [HIGH] dib_to_png halves the height a second time — all non-PNG icons produce half-height PNGs

- File: src/icon.rs:141-170 (callers: 300, 347 via icon_to_png)
- Description: `dib_to_png` receives the **logical** icon height: `ico_to_icns` passes `display_height` (ICO entry height, e.g. 32) and `pe::extract_all_icons_from_pe` stores `display_height` (pe.rs:3211), while the DIB payload already encodes the doubled height (XOR mask + AND mask). `let actual_height = height / 2` (line 142) therefore halves the logical height again: a 32×32 icon renders as a 32×16 PNG, reading only the first half of the DIB rows (and mis-translating the vertical flip). Every raw (non-PNG-embedded) icon is affected.
- Fix suggestion: parse `biHeight` from the DIB's own BITMAPINFOHEADER (or the raw data length / `row_size`) and halve exactly once; or change the contract so callers pass the doubled DIB height and fix both call sites. The icon's `height` field should remain the logical height for ICNS type selection.

---

## [HIGH] Division by zero in audio resampler on guest-controlled sample rate

- File: src/live.rs:980-985
- Description: `input_sample_rate` comes from the guest's `WaveFormat` (audio.rs:26-29) and is untrusted. When `input_sample_rate == 0` and it differs from the host rate, `(input_frames as u64 * output_sample_rate as u64) / input_sample_rate as u64` panics (integer division by zero) on the live host thread, taking down the session. The `input_frames == 0` early return does not protect this because `input_frames` depends only on `samples.len()`.
- Fix suggestion: guard with `let input_sample_rate = input_sample_rate.max(1);` (and `output_sample_rate.max(1)`) before any division, or reject the chunk with an error.

---

## [HIGH] Scroll wheel delta double-counted (treated as absolute position)

- File: src/live.rs:422-437
- Description: minifb 0.27's `get_scroll_wheel()` returns the **delta accumulated since the last update** (the backend accumulates `NSEvent deltaX/deltaY` and zeroes it on read). This code treats it as a cumulative position: `scroll.1 - previous_scroll.1` subtracts the previous delta from the current delta, so every event is wrong by the previous value and the sign can invert (e.g. successive deltas 5.0, 2.0 are reported as +5, −3; a delta after a no-scroll frame is also wrong because `previous_scroll` is only refreshed on scroll frames).
- Fix suggestion: send `delta_x: scroll.0 as i32, delta_y: scroll.1 as i32` directly and delete `previous_scroll`.

---

## [HIGH] Default anti-cheat module hashes are hashes of path strings — integrity checks on them always fail

- File: src/anticheat.rs:639-737 (populate_default_modules), 476-514 (check_integrity)
- Description: `populate_default_modules` sets `code_hash = sha256_hash(path.as_bytes())` (line 735) — a hash of the DLL path string — but `check_integrity` computes the SHA-256 of actual guest memory contents and compares. For any default module (ntdll, kernel32, ...) the comparison can never match → `passed = false` (tampering reported). Worse, the fake bases (`0x7FF0_0000`…) are not mapped in guest memory, so `memory.read_bytes(base, size)?` (line 483) errors and the whole check fails. This module list is exactly what the shim presents to the guest anti-cheat as its trusted loaded-module snapshot.
- Fix suggestion: populate default modules via `add_module_from_memory` from actually mapped guest memory, or keep default entries but skip/auto-pass integrity checks for them (only compare hashes for modules registered with real memory content).

---

## [MEDIUM] Guest frame dimensions used to create the window before any validation

- File: src/live.rs:181-189
- Description: `frame.width as usize / frame.height as usize` (u32 from the guest frame pipeline, untrusted) are passed straight to `create_window` (line 182) → `minifb::Window::new` with unbounded dimensions (possible OOM/panic inside minifb) before the checked-mul validation in `decode_frame_buffer_into` (line 730) runs. Additionally, a decode/export error propagates via `?` and aborts the whole session.
- Fix suggestion: validate and cap dimensions (e.g. `w <= 16384 && h <= 16384` and `w*h <= ~100 MP`) before `create_window`; return a controlled error.

---

## [MEDIUM] Worker thread is detached (never joined) on early error return

- File: src/live.rs:182, 187, 189, 278-285
- Description: `run_live_host_session` holds `worker: JoinHandle`. The `?` operators at lines 182/187/189 return from the function on window-creation/export/decode errors, dropping the `JoinHandle` and leaving the PE worker thread running detached (no join, no stop notification). The join only happens on the normal-exit path (line 278).
- Fix suggestion: restructure so the worker is always joined, e.g. wrap the loop in a closure that returns `AppResult`, then always `worker.join()` after it (map join errors separately).

---

## [MEDIUM] Palette (bpp < 8) icons decode garbage — every pixel reads the same bytes

- File: src/icon.rs:151-163
- Description: For 1/4/8-bpp palette icons, `bpp as usize / 8 == 0`, so `src_pixel = src_row + x * 0` — every pixel in a row reads the same 4 bytes and the palette is never consulted → wrong colors (and reads beyond the pixel data into the AND mask). The module claims to support arbitrary ICO entries (`bpp` is a free field from untrusted headers).
- Fix suggestion: reject bpp not in {24, 32} with `RcPeParseInvalid`, or implement palette lookup (parse the color table, then index it per pixel).

---

## [MEDIUM] Registry: unloaded shims can never be re-activated

- File: src/anticheat.rs:777-794, 797-804
- Description: `unload_driver` sets `ShimState::Unloaded` but keeps the entry; a later `try_load_driver` for the same name hits `self.shims.contains_key(&key) → return Ok(true)` without calling `load()` again. A game that unloads and reloads its anti-cheat driver (common during module updates/restarts) silently leaves the shim dead while the caller believes it is loaded.
- Fix suggestion: in `try_load_driver`, if an existing shim is not `Active`, re-run `shim.load()` (state `NotLoaded`/`Unloaded` → `Active`).

---

## [MEDIUM] Inconsistent base-address convention across denuvo trigger/decrypt paths

- File: src/denuvo.rs:244-248 (detect_triggers), 639/699 (decrypt_v6/v7), 656/716 (map_bytes)
- Description: `detect_triggers` computes `abs_addr = base + section.rva` when `rva < base` and keys triggers by the resulting **absolute** address (line 277), while `decrypt_v6_section`/`decrypt_v7_section` use raw `section.rva` for `memory.map_bytes` and trigger lookups, and `in_section` checks (line 274) compare targets against raw `s.rva`. With a non-zero image base, auto-detected trigger keys and the guest addresses passed to `handle_trigger` disagree (triggers never fire), and decrypted bytes may be written at the wrong guest address. Currently latent — only tests (base = 0) exercise this module, which is not yet wired into the runtime.
- Fix suggestion: pick one convention (RVAs everywhere; add `base` once at the guest→host boundary) and use it for trigger keys, `in_section` tests, and `map_bytes`.

---

## [MEDIUM] Layout width collapses to 0 when max_width <= 0 (unwrapped text)

- File: src/dwrite.rs:856
- Description: In the fallback `measure_text`, `width.min(max_width)` clamps the natural text width to `max_width` even when `max_width <= 0` (i.e. `DWRITE_WORD_WRAPPING_NO_WRAP` with no width limit), so a non-empty layout reports `width == 0.0`, breaking hit-testing/overhang/draw sizing for that common DWrite usage.
- Fix suggestion: only clamp when `max_width > 0.0`: `let width = if max_width > 0.0 { width.min(max_width) } else { width };` (mirror the `max_height` handling at line 857).

---

## [MEDIUM] Unchecked section index in integrity-trigger dispatch; triggers_failed is dead

- File: src/denuvo.rs:395-405, 154/346
- Description: `handle_trigger` → `TriggerType::IntegrityCheck` → `self.base.verify_integrity(memory, idx)` is called with a `section_index` that is only user-controlled via `add_trigger` (denuvo.rs:753-770); unlike `handle_decrypt_trigger` (line 370) there is no bounds check. The base method returns `Err` (security.rs uses `.get()`), so no panic — but the error aborts the whole trigger handling. Separately, `triggers_failed` is declared (line 154) and never incremented anywhere, so failed triggers are silently untracked.
- Fix suggestion: bounds-check `section_index` before dispatch and `self.triggers_failed += 1` when a handler returns `Err`.

---

## [LOW] Always-true test assertion (also clippy error)

- File: src/dwrite.rs:1398 (test `test_dwrite_create_factory`)
- Description: `assert!(!factory.font_collection.families.is_empty() || true)` is constant `true`; clippy errors with `overly_complex_bool_expr` (deny-by-default), which currently blocks the test target build.
- Fix suggestion: `assert!(!factory.font_collection.families.is_empty());` or remove the vacuous check.

---

## [LOW] Dead width/height==0 check in draw()

- File: src/dwrite.rs:1063
- Description: `width == 0 || height == 0` can never be true because of `.max(1.0)` on the preceding lines (1061-1062) — dead branch.
- Fix suggestion: remove the check (the guard that matters is `self.text.is_empty()`).

---

## [LOW] Dead code and never-populated fields in font enumeration

- File: src/dwrite.rs:896-900, 938-949, 933
- Description: `style_name_key` is created and released but never used (896-900, 999); the `cf_number_get_value` block (938-949) is a no-op (`weight_key` created/released, `_dict` never queried); `stretch` is always `DWRITE_FONT_STRETCH_NORMAL` (line 933) — font stretch is never read from Core Text, so every enumerated font reports "Normal" stretch.
- Fix suggestion: delete the dead block and unused key; populate stretch from `CTFontDescriptorCopyAttribute` traits (or accept the limitation explicitly).

---

## [LOW] CF object leaks on early returns in draw()

- File: src/dwrite.rs:1157-1158, 1106-1109
- Description: If `cf_string_create(&self.text)` or `cf_string_create(KCT_FONT_ATTRIBUTE_NAME)` returns `None`, the `?` returns before `release(cf_name)`/`release(font)` → per-call CF leaks. Additionally the device RGB color space (line 1106) is never released (no `CGColorSpaceRelease` is loaded) → one leak per `draw()` call.
- Fix suggestion: convert the `?`s to explicit `release(...)` + `return None` (as done at lines 1171-1177), and load/call `CGColorSpaceRelease` after the context is created.

---

## [LOW] Wrap placement off-by-one for glyphs crossing max_width

- File: src/dwrite.rs:698-709
- Description: Each glyph's position is pushed at the current cursor and only *then* is the wrap reset applied, so the glyph that pushes the line past `max_width` is placed at the end of the current line and the *next* glyph starts the new line. DWrite breaks before the offending glyph. Visible as a one-glyph positioning difference in `measure_glyphs`/`glyph_positions` consumers (hit-testing, overhang).
- Fix suggestion: check `cursor_x + advance > max_width` before pushing, and push the overflowing glyph on the new line at x=0.

---

## [LOW] `count * 2` can overflow usize in sized UTF-16 reads with huge max_units

- File: src/host_thunks.rs:269-271
- Description: `let count = (length as usize).min(max_units); validate_guest_pointer(memory, ptr, count * 2)?` — if a caller passes a large `max_units`/`length`, `count * 2` wraps, the upfront range check validates the wrong (tiny) range, and the read loop then walks `ptr + i*2` for up to `count` units (`read_u16(...).unwrap_or(0)` — no UB, but garbage reads and a huge `units` allocation).
- Fix suggestion: `let bytes = count.checked_mul(2).ok_or(...)?;` before validation, and/or cap `count` to a fixed maximum.

---

## [LOW] Doc/comment mismatches

- File: src/icon.rs:223 (and anticheat.rs:1045); src/live.rs:243
- Description: `motherboard_serial` doc says "32 ASCII chars" but the value is 64 hex chars (test asserts 64); `live.rs:243` contains an orphaned comment fragment ("permission toggle occurs. The race window is microseconds.") left over from a removed block, and the JIT watchdog's `force_break_all_chains()` note about racing the executing worker is worth a proper explanation.
- Fix suggestion: fix the doc strings and complete/remove the dangling comment.

---

## [LOW] `trigger_points` vs detected-trigger key-space mixing; O(n·m) trigger scan

- File: src/denuvo.rs:190-202, 256-292
- Description: Config `trigger_points` are inserted verbatim (raw RVAs) while `detect_triggers` inserts absolute addresses (see MEDIUM #13 for the convention issue); `section_index` assignment (217-224) is O(triggers × sections) per section, i.e. O(T·S²) total, and the byte-scan loop re-checks all sections per `E8` opcode (O(size·S)) — slow for multi-MB sections. `initialize` runs this once, so impact is bounded.
- Fix suggestion: normalize key space in one place; iterate sections first and test only the current section's range when scanning; compute the containment check via a sorted interval list.

---

## [PERF] Per-call dlopen + 5× dlsym on every draw()

- File: src/dwrite.rs:1097-1144
- Description: Each `DWriteTextLayout::draw()` opens CoreGraphics with `libloading::Library::new` and resolves `CGColorSpaceCreateDeviceRGB`, `CGBitmapContextCreate`, `CGContextRelease`, `CGContextTranslateCTM`, `CGContextSetRGBFillColor`, `CTLineDraw`. Text drawing happens per-frame in UI paths; this adds 6 dyld calls + one dlopen per draw.
- Fix suggestion: resolve these once (lazily cached in `DWriteFactory` alongside the other symbols, or in a `OnceLock`/`static`).

---

## [PERF] check_integrity auto-registers an unbounded module list

- File: src/anticheat.rs:498-503
- Description: Every integrity check on a region with no containing module inserts a new `ModuleInfo` ("region_<addr>") into `self.modules`, which then participates in all future containment lookups (line 487-494, linear scan) and clones (`query_module_list`). Over a long session with many distinct checked regions this grows without bound and makes each check O(n).
- Fix suggestion: keep auto-registered regions in a separate bounded map (or dedupe + cap), and/or index modules by base for O(log n) containment.

---

## Clippy

Command: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` (no `--all-features`, per instructions). In-scope results: **1 error + 39 warnings** (out of 1427 warnings / 27 errors crate-wide; the rest belong to other files). `src/reason.rs` is clean.

**Error (deny-by-default):**
- `src/dwrite.rs:1398` — `overly_complex_bool_expr` — `assert!(!… || true)` is always true (test). This is the only in-scope error; the other 26 lint errors are in out-of-scope files (jit.rs, crash_recovery.rs, d3d11.rs, …).

**Warnings:**
- `src/anticheat.rs:432` — `manual_pattern_char_comparison` (rsplit closure → `['\\', '/']`)
- `src/anticheat.rs:564,570,576` — `needless_borrows_for_generic_args` (`&seed_bytes`)
- `src/anticheat.rs:586` — `unnecessary_cast` (`(seed & 0xFF) as u32`)
- `src/anticheat.rs:866,869` — `needless_range_loop` (index-only `i` in `derive_ascii_hex`)
- `src/denuvo.rs:474` — `let_and_return` (get_rdtsc_value)
- `src/denuvo.rs:505` — `collapsible_if`
- `src/denuvo.rs:945,1093,1173` — `manual_repeat_n` (test padding)
- `src/denuvo.rs:1006` — `manual_range_contains`
- `src/dwrite.rs:394` — `new_without_default` (DWriteFactory)
- `src/dwrite.rs:602,962` — `manual_clamp` (`max(..).min(..)` → `clamp`)
- `src/dwrite.rs:842` — `manual_checked_ops` (manual checked division)
- `src/dwrite.rs:843` — `manual_div_ceil`
- `src/dwrite.rs:1251` — `needless_return`
- `src/host_thunks.rs:561,574,587,601,618,673` — `iter_cloned_collect` (`.iter().copied().collect()` → `.to_vec()`)
- `src/icon.rs:143,451` — `manual_div_ceil` (test at 451)
- `src/icon.rs:155,156,157,159,161` — `unnecessary_cast` (`usize → usize`)
- `src/icon.rs:472` — `op_ref` (test)
- `src/live.rs:164` — `manual_is_multiple_of`
- `src/live.rs:323,425,426,448,449` — `collapsible_if`

## Build

- The library target compiled and clippy ran to completion. No build failures in the assigned files.
- `casa1 (lib test)` did not reach "Finished": the test target stops at 27 **deny-by-default lint errors**, of which exactly one is in scope (`src/dwrite.rs:1398`, see Clippy section). The other 26 are in out-of-scope files (`src/jit.rs`, `src/crash_recovery.rs`, `src/d3d11.rs`, …).
- `--all-features` was intentionally not used (missing system ffmpeg is environmental; ignored per instructions).
