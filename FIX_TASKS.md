# Audit Findings — Casa1 `src/real_win32.rs`

- **Batch:** audit-real-win32 (whole-file audit, sequential read of every line)
- **Files:** `src/real_win32.rs` (11939 lines, 100% read)
- **Lines:** 1–11939
- **Date:** 2026-08-15
- **Commands:** `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` (completed; see Build section)
- **Method:** manual read of all 11939 lines + clippy output filtered to this file

---

## [CRITICAL] Non-NUL-terminated byte slices passed to `NSString stringWithUTF8String:` (heap overread / UB)

- File: src/real_win32.rs:1548
- File: src/real_win32.rs:1667
- Description: `title.as_bytes().as_ptr()` (line 1548) and `fname.as_bytes().as_ptr()` (line 1667) are passed as C strings to `stringWithUTF8String:`. Rust `String`/`&str` buffers are not NUL-terminated, so Objective-C reads past the end of the heap allocation. The `title`/`fname` values originate from guest-controlled input (browse dialog title, directory entry names), making this an untrusted-input heap overread → UB/crash.
- Fix suggestion: Wrap in `std::ffi::CString::new(...)` and pass `cstr.as_ptr()` (as done correctly at lines 2093, 2118, 2378, 3047). Handle interior-NUL bytes by lossy replacement.

## [CRITICAL] `ShellView::create_view_window` transmutes guest-controlled `u64` into an ObjC object pointer

- File: src/real_win32.rs:1647
- Description: `std::mem::transmute(parent_handle as *mut objc::runtime::Object)` converts an untrusted `u64` (guest HWND) directly into a pointer, then immediately sends ObjC messages (`frame`, `addSubview:`) to it. Any non-null garbage value sends messages to an invalid object → crash/UB. Same pattern at 1712 and 1737 (guarded only by `view_handle != 0`, but `view_handle` is itself a raw pointer stored as `u64` with no validation).
- Fix suggestion: Validate the handle against a host-side registry of live window objects before transmuting (e.g., the same map used by the window subsystem), and return an error/0 for unknown handles. At minimum, check the pointer against known-allocated objects before any `msg_send!`.

## [CRITICAL] `evaluateJavaScript:completionHandler:` returns `void` but result is read as an object pointer

- File: src/real_win32.rs:3064
- Description: `let result: *mut objc::runtime::Object = objc::msg_send![wv, evaluateJavaScript: nsstr completionHandler: ...];` — the selector returns `void`; the code then reads `result` (garbage register contents) and, if non-null, sends `UTF8String` to it → UB. Also, on modern macOS the completion handler is async and the API signature requires a handler; passing `null` and expecting a synchronous return value is incorrect regardless.
- Fix suggestion: Do not read a return value for a `void` method. Use the `completionHandler:` block (via `objc::block`) to receive the result asynchronously, or drop the result entirely.

## [CRITICAL] `safe_array_get_element` / `safe_array_put_element` panic on untrusted SAFEARRAY descriptors

- File: src/real_win32.rs:4859
- File: src/real_win32.rs:4903
- Description: Both functions read `sa_data[2]`, `sa_data[3]` and `sa_data[bound_offset .. bound_offset+8]` **before** any length validation (the `safe_array_access_data` length check at line 4836 happens *after* the first unchecked reads, and `bound_offset = 20 + dim*8` is not checked against `sa_data.len()` at all). A truncated/malicious guest-supplied SAFEARRAY (len < 4, or small buffer with large `cDims`) causes `index out of bounds` panics. Additionally, `safe_array_get_element` slices `sa_data[offset..offset + elem_size]` with `offset = base_offset + flat_index*elem_size` where `base_offset` comes straight from the guest-controlled handle field → out-of-bounds slice panic. These are panics reachable from untrusted input.
- Fix suggestion: Validate `sa_data.len()` against `4 + c_dims*8 + data` before any indexing; verify `base_offset + flat_index*elem_size + elem_size <= sa_data.len()` and return `Err` instead of slicing. Compute all offsets with `checked_*` arithmetic.

## [CRITICAL] `safe_array_get_lbound` / `safe_array_get_ubound` index out of bounds

- File: src/real_win32.rs:4954
- File: src/real_win32.rs:4978
- Description: Only `len < 20` is checked, but `bound_offset = 20 + (dim-1)*8` is not verified against `sa_data.len()`. `dim` is bounded only by `c_dims` (a u16 from guest data, up to 65535); e.g., a 20-byte buffer with `cDims=1` and `dim=1` → `sa_data[20..]` → panic.
- Fix suggestion: Check `bound_offset + 8 <= sa_data.len()` before reading, return `Err` otherwise.

## [CRITICAL] `serialise_node` unbounded recursion → stack overflow on deeply nested XML

- File: src/real_win32.rs:2757
- File: src/real_win32.rs:2709
- File: src/real_win32.rs:2729
- Description: `serialise_node` recurses once per nesting level with no depth guard. `roxmltree 0.20`'s `Document::parse` (used by `load_xml`, `select_nodes`, `transform_node`, `get_elements_by_tag_name`, `save`) imposes no document-depth limit, so a guest-supplied XML file with e.g. 100k nested elements parses successfully and then overflows the stack when serialized. Also `"  ".repeat(depth)` is O(depth²) string allocation across the tree.
- Fix suggestion: Add an explicit depth counter (cap ~256) and stop/error beyond it; alternatively serialize iteratively with an explicit stack. Also escape text/attribute values (see HIGH finding below).

## [CRITICAL] `format_with_spec`/`format_with_spec_float`: width underflow panics for `%#1x` (and `%#1X`)

- File: src/real_win32.rs:5330
- File: src/real_win32.rs:5348
- File: src/real_win32.rs:5646
- File: src/real_win32.rs:5662
- Description: `width = w - prefix.len()` with `w == 1` and `prefix == "0x"` (alternate form, non-zero value) underflows `usize`. In debug builds this panics at the subtraction; in release it wraps to a huge width and `format!("{:0>width$}", ...)` panics with capacity overflow / attempts an enormous allocation → OOM. The format string is guest-controlled (`sprintf` shim) → panic reachable from untrusted input.
- Fix suggestion: Use `w.saturating_sub(prefix.len())` (or `w.checked_sub(...).unwrap_or(0)`).

## [HIGH] Negative numbers lose their sign in all sprintf formats

- File: src/real_win32.rs:5284
- File: src/real_win32.rs:5616
- File: src/real_win32.rs:5705
- Description: In every format branch the sign is computed as `if value < 0 { "" } else ...` and the magnitude is formatted with `abs`/`unsigned_abs`, so `crt_sprintf_int(-42, "%d")` returns `"42"`, `crt_sprintf_float(-1.5, "%f")` returns `"1.500000"` — the minus sign is silently dropped everywhere (%d, %i, %u-adjacent, %f, %e, %g). Definite wrong output for guest-visible CRT formatting.
- Fix suggestion: `let sign = if value < 0 { "-" } else if force_sign { "+" } ...` (and `format!("{sign}{abs}")`), matching the float variant's abs handling.

## [HIGH] `%d`/`%i` ignore the zero-pad flag

- File: src/real_win32.rs:5299
- Description: In the `d`/`i` branch, `pad_char` is computed (`'0'` when zero_pad) but never used; width padding always uses spaces (`{:>width$}`). `%08d` on `42` yields `"      42"` instead of `"00000042"` (the `u`/`x`/`X`/`o` branches do honor `pad_char`).
- Fix suggestion: Apply `pad_char == '0'` padding for `d`/`i` as well (mind the sign prefix position).

## [HIGH] `%f` zero-padding inserts zeros at the wrong position

- File: src/real_win32.rs:5401
- File: src/real_win32.rs:5709
- Description: `let dot_pos = s.find('.')...; s = format!("{}{}{}", &s[..int_part_len], zeros, &s[int_part_len..])` inserts the pad zeros immediately before the decimal point — i.e., **after** the existing integer digits and sign. `%08.2f` on `1.5` produces `"1.000000.50"`-style garbage (`"+1000.50"`) instead of `"00001.50"`.
- Fix suggestion: Insert zeros between the sign (if any) and the first digit: pad `int_part_len - sign_len`.

## [HIGH] `variant_to_f64` VT_R4 returns the bit pattern, not the value

- File: src/real_win32.rs:4685
- Description: `f32::from_bits(v.data as u32).to_bits() as f64` converts the f32 to its bit pattern (`u32`) and then casts the *integer* bits to f64. Any numeric coercion of a VT_R4 variant (e.g., `VariantChangeType` to VT_I4) yields garbage (1.0f32 → 1065353216.0). Should be `f32::from_bits(v.data as u32) as f64`.
- Fix suggestion: Drop `.to_bits()`.

## [HIGH] `VariantChangeType` VT_BSTR allocates a BSTR then discards it, sets `data = 0`

- File: src/real_win32.rs:4628
- Description: `let _bstr = sys_alloc_string(&wide); dst.vt = VT_BSTR; dst.data = 0;` — the freshly allocated BSTR buffer is dropped (never handed to the guest) and the destination holds a null BSTR pointer. Callers then dereference a null BSTR → crash or wrong data; also a wasted allocation per conversion.
- Fix suggestion: Either write the BSTR into guest memory and store the pointer in `dst.data`, or return a clear error for BSTR conversion if guest memory is unavailable.

## [HIGH] `element_size()` returns wrong sizes for pointer/CLSID variant types

- File: src/real_win32.rs:5009
- Description: `VT_LPSTR`/`VT_LPWSTR` (30/31) and `VT_PTR` (26) fall into `_ => 4`; on x64 pointers are 8 bytes. `VT_CLSID` (72) also falls to 4 (should be 16). `SafeArrayCreate` of these types sizes the data region wrong → guest reads/writes out of bounds of the buffer.
- Fix suggestion: Add `VT_LPSTR | VT_LPWSTR | VT_PTR | VT_UNKNOWN | VT_DISPATCH => 8`, `VT_CLSID => 16` to `element_size`.

## [HIGH] `sh_browse_for_folder_w` returns the Desktop path when the user cancels

- File: src/real_win32.rs:1554
- Description: `if result == 1 { ... return Some(selected) }` and the fall-through after the block returns `Some(pidl_from_path(&ShellFolder::desktop().path))` — so a cancelled dialog yields the Desktop PIDL as if it were selected. The doc comment promises `None` on cancel. Games will then treat a cancel as "user picked Desktop".
- Fix suggestion: `return None` when `result != 1` (NSFileHandlingPanelCancelButton), matching the documented contract.

## [HIGH] `register_drag_drop` discards the caller's `DropTargetImpl`

- File: src/real_win32.rs:1921
- Description: The `_target: DropTargetImpl` parameter is ignored; a fresh `DropTargetImpl::new(window_handle)` is registered instead, losing the caller's `drag_data`, `last_effect`, etc. The API silently drops data and never stores the target the caller set up.
- Fix suggestion: Store the passed `target` (dedupe by handle; return `DRAGDROP_E_ALREADYREGISTERED` only for a genuinely different target).

## [HIGH] XML serialization writes unescaped text and attribute values → malformed XML on save

- File: src/real_win32.rs:2771
- File: src/real_win32.rs:2796
- Description: `serialise_node` pushes `attr.value()` and text nodes raw. Text containing `<`, `>`, `&`, or quotes produces invalid XML; `XmlDomDocument::save` then persists corrupted output (data corruption). Also comments/PIs are silently dropped, changing round-trip content.
- Fix suggestion: Escape `& < > " '` in attribute values and `& < >` in text, and preserve comments/PIs (or explicitly document dropping them).

## [HIGH] `PropertyStore::commit` PKEY_TITLE rename allows path traversal

- File: src/real_win32.rs:2429
- Description: `parent.join(new_name)` — if `new_name` is absolute (or contains `..`), `PathBuf::join` replaces/escapes the directory and `std::fs::rename` moves the file anywhere the host user can write. `new_name` comes from guest-controlled `IPropertyStore::SetValue`. A malicious guest can overwrite arbitrary host files this way.
- Fix suggestion: Reject `new_name` containing path separators or `..`, and require it to be a plain file name (`Path::file_name()` round-trip check).

## [HIGH] ServiceControlManager / COM EXE registry spawn guest-controlled executables on the host

- File: src/real_win32.rs:9154
- File: src/real_win32.rs:10559
- File: src/real_win32.rs:3912
- Description: `CreateServiceW`/`StartServiceW` store a guest-supplied `executable_path` and `std::process::Command::new(path).spawn()` executes it on the host; `ComExeServerRegistry::register_class_object` does the same with a guest CLSID→path mapping. A guest that can write a host-executable script/binary (e.g., via `std::fs::write` shims) achieves arbitrary host code execution outside the emulated sandbox. Also note the `open_sc_manager` SCM is *also* duplicating `Advapi32Manager` (dead-code duplication, LOW).
- Fix suggestion: Do not spawn guest-supplied paths; simulate service/COM-server processes with synthetic PIDs only (the code already falls back to synthetic PIDs on spawn failure — make that the only path), or whitelist paths inside the GE root and validate the file is a native host binary.

## [HIGH] Async `RegNotifyChangeKeyValue` never signals the event handle → guest wait hangs

- File: src/real_win32.rs:10483
- Description: The `async_notify` path calls `tracker.subscribe(...)` and returns `Pending`, but nothing ever signals `event_handle`: `notify_change` only `eprintln!`s "would signal N event handles" (line 10350). A guest thread waiting on the Win32 event blocks forever unless some external code polls `subscriptions_for_key` — which nothing in this file does.
- Fix suggestion: Either signal the event in `notify_change` (via the event subsystem), or have `reg_notify_change_key_value` poll the version for the guest (blocking until change/timeout) instead of returning `Pending`.

## [HIGH] `RegNotifyChangeKeyValue` treats timeout `0` as immediate timeout instead of INFINITE wait

- File: src/real_win32.rs:10491
- Description: Win32 `RegNotifyChangeKeyValue` with `dwMilliseconds == 0` means wait forever; this code returns `(version, Timeout)` immediately for `timeout.is_zero()`.
- Fix suggestion: Treat `timeout.is_zero()` as infinite (poll until change), and only return `Timeout` when a finite deadline passes.

## [HIGH] `safe_array_get_lbound`/`get_ubound` panic (see CRITICAL #5) — dup, merged above

- (merged with CRITICAL entry)

---

## [MEDIUM] BCrypt AES mode is chosen by key length; GCM tag handling diverges from BCrypt

- File: src/real_win32.rs:7366
- File: src/real_win32.rs:7452
- Description: `encrypt`/`decrypt` pick AES-128-CBC for 16-byte keys and AES-256-GCM for 32-byte keys. Real BCrypt keys do not encode the chaining mode (set via `BCryptSetProperty(BCRYPT_CHAINING_MODE)`); a 16-byte AES-GCM key or a 32-byte AES-CBC key gets silently misprocessed → wrong ciphertext/integrity failure. GCM paths also return/expect the raw tag appended by `aes_gcm`'s `encrypt_in_place` (aes-gcm v0.10 appends 16 bytes) — callers that hand BCrypt a separate tag buffer will fail.
- Fix suggestion: Track the chaining mode as key state (set via a setter) instead of inferring from key length; document and handle the tag explicitly.

## [MEDIUM] `BCryptDeriveKey` SP80056A allows unbounded output length → memory exhaustion

- File: src/real_win32.rs:7724
- Description: `output_len` is guest-controlled; the loop `while derived.len() < output_len` allocates unboundedly (SHA-256 blocks of 32 bytes) → DoS for large `output_len`.
- Fix suggestion: Cap `output_len` (e.g., 64 KB) or allocate with `Vec::try_reserve` and error out.

## [MEDIUM] `BCryptGenerateKeyPair` accepts arbitrary RSA key size → slow/memory-exhausting generation

- File: src/real_win32.rs:7153
- Description: `key_len` is guest-controlled and passed straight to `RsaPrivateKey::new` (e.g., `key_len = 2^30` → enormous computation). Also `key_len` below valid sizes returns errors (acceptable).
- Fix suggestion: Clamp `bits` to the BCrypt-supported range (e.g., 512..=16384, step 64) before generation.

## [MEDIUM] `UrlMonikerObject::bind_to_storage` swallows HTTP errors → returns empty body as success

- File: src/real_win32.rs:3512
- Description: `response.bytes().unwrap_or_default().to_vec()` converts any download failure into `Ok(vec![])`, so callers can't distinguish "downloaded empty content" from "network failed". Also blocks the calling (possibly emulation) thread for up to 30 s.
- Fix suggestion: Propagate `Err` on `bytes()` failure; document the blocking behavior or move to an async path.

## [MEDIUM] `pidl_from_path` truncates sizes to u16 for very long paths

- File: src/real_win32.rs:1165
- Description: `item_size = 2 + item_data_len * 2` and `total_size = (2 + item_size + 2) as u16` truncate silently for paths longer than ~32k UTF-16 units (guest-controlled path strings). The resulting PIDL is malformed; `pidl_to_path` then returns `None` (no crash, but silent data loss).
- Fix suggestion: Return `Option`/`Result` and fail (or split into multiple PIDL items) when sizes exceed `u16::MAX`.

## [MEDIUM] `ShellView`/`MsHtmlDocument` object lifecycle leaks

- File: src/real_win32.rs:1631
- File: src/real_win32.rs:2972
- Description: `create_view_window` can be called twice — the first NSView leaks (only the latest handle is tracked) and both are added to the parent. The WKWebView created in `create_webview` is never released anywhere (no destroy path), and `MsHtmlDocumentObject::new` eagerly creates a webview for every COM instance even if never used. `destroy_view_window` correctly releases once, but relies on callers never double-creating.
- Fix suggestion: Track a single `Option<u64>` view handle; release the previous view/webview when re-creating or when the object is dropped; create the webview lazily.

## [MEDIUM] `ComExeServerRegistry` re-registration leaks the running process; revoke kills without `wait()`

- File: src/real_win32.rs:10553
- Description: Registering the same CLSID twice overwrites the entry without killing the previous child (orphaned process, handle lost). `revoke_class_object` calls `child.kill()` without `child.wait()`, leaving a zombie until the `Child` is dropped. Same pattern as the `com_exe_servers` Vec in `ComApartmentState::co_create_instance_with_clsctx` (line 3914), which is never reaped at all.
- Fix suggestion: Kill+wait the replaced child before overwriting; add `wait()` after `kill()`; reap `com_exe_servers` entries (or drop that mechanism — see host-execution finding).

## [MEDIUM] `CoCreateInstance` with CLSCTX_LOCAL_SERVER spawns a server, then creates the object in-process anyway

- File: src/real_win32.rs:3892
- Description: When only `LOCAL_SERVER` is requested and the (fake) server EXE exists, the code spawns it and then falls through to `dll_get_class_object`, creating an in-process object that the spawned server knows nothing about. The spawned child is never terminated and can never serve the instance.
- Fix suggestion: For LOCAL_SERVER, either return the out-of-process result path or fail cleanly; don't both spawn and create in-process.

## [MEDIUM] `XInputManager::update_state` never maintains `packet_number`

- File: src/real_win32.rs:6641
- Description: `packet_number` is only whatever the caller passes in the `XInputState`. Games commonly poll `packet_number` to detect state changes; a constant 0 makes games skip/throttle input processing or mis-detect connection changes.
- Fix suggestion: Increment `packet_number` on every `update_state` (unless the caller explicitly provides a newer one).

## [MEDIUM] `ThreadPoolManager::pop_work_callback` removes the work item, breaking re-submission

- File: src/real_win32.rs:7920
- Description: Windows thread-pool work objects can be submitted repeatedly; here the first execution removes the `TpWork` from the map, so a subsequent `SubmitThreadpoolWork(id)` fails with "not found" (same for waits in `pop_signaled_waits`). Timers, by contrast, stay registered.
- Fix suggestion: Reset `submitted = false` (and keep the record) instead of removing it; remove only on `CloseThreadpoolWork`.

## [MEDIUM] `control_service` SERVICE_CONTROL_SHUTDOWN (0x05) orphans the child process

- File: src/real_win32.rs:9229
- Description: The 0x05 branch sets `status = Stopped` and `pid = None` but never kills/removes the spawned child from `self.children` — the process keeps running and the `Child` handle leaks (unlike STOP 0x01 which kills and waits).
- Fix suggestion: Mirror the 0x01 handling: kill+wait the child and remove it from `children` before clearing `pid`.

## [MEDIUM] Registry change tracker: prefix matching without key-boundary; unbounded growth

- File: src/real_win32.rs:10341
- File: src/real_win32.rs:10361
- Description: `key.starts_with(sub_key)` matches `HKLM\Software\MyApp` also for `HKLM\Software\MyAppEvil` → false notifications. `subscribe` appends duplicates for repeated calls with the same `(key, event_handle)` (never deduped), and `versions`/`subscriptions` grow without bound for guest-controlled key names → unbounded memory.
- Fix suggestion: Compare on key boundaries (`key == sub_key || key.starts_with(sub_key + "\\")`); dedupe subscriptions by `(key, event_handle)`; cap the maps or require explicit unsubscribe.

## [MEDIUM] `TaskbarListObject` per-HWND HashMaps grow unboundedly

- File: src/real_win32.rs:1105
- Description: `set_progress_value`/`set_progress_state`/`set_overlay_icon`/`set_thumbnail_tooltip` insert into per-HWND maps keyed by guest-supplied `u64` values; `delete_tab` never cleans the side maps. A guest cycling bogus HWNDs grows all four maps without limit.
- Fix suggestion: Prune the maps in `delete_tab` (and/or on `hr_init` reset), or bound the number of tracked HWNDs.

## [MEDIUM] `MsHtmlDocument::write`/`writeln` unbounded string growth

- File: src/real_win32.rs:3015
- Description: Guest code can append HTML without limit before `close()` — unbounded host memory growth from guest-controlled writes.
- Fix suggestion: Cap accumulated content (e.g., a few MB) or stream it to the webview as it grows.

## [MEDIUM] `SyncBarrier::enter` busy-waits with pure `spin_loop` (no yield) on a shared-core emulator

- File: src/real_win32.rs:8063
- Description: Waiting threads spin on `generation` with `std::hint::spin_loop()` only. In a cooperatively-scheduled emulator where the last thread may not get CPU while others spin, this can livelock; even otherwise it burns a core per waiter.
- Fix suggestion: Use `std::thread::yield_now()` (or a Condvar) in the wait loop, and/or cap the spin count before yielding.

## [MEDIUM] XPath attribute predicates are parsed but ignored

- File: src/real_win32.rs:10934
- Description: `matches_xpath_name` strips `[@attr='value']` predicates (documented as supported at line 10824) but never evaluates them — `selectNodes("item[@x='1']")` returns *all* `item` elements.
- Fix suggestion: Evaluate the predicate against `node.attributes()` in `evaluate_xpath`/`evaluate_path` (and support `[@attr]` presence checks), or remove the claim of support.

## [MEDIUM] `ShellFolder::get_attributes_of` uses wrong constant for symlinks

- File: src/real_win32.rs:11865
- Description: `attrs |= 0x00000008; // SFGAO_LINK (not STORAGE)` — 0x8 is `SFGAO_STORAGE`; `SFGAO_LINK` is `0x80000000`. Symlinks are reported as STORAGE.
- Fix suggestion: Use the correct constant (`0x80000000`) or drop the attribute.

## [MEDIUM] `ShellFolder::set_name_of` allows absolute `new_name` to escape the folder

- File: src/real_win32.rs:1362
- Description: `self.path.join(new_name)` with an absolute `new_name` (guest-controlled) renames a file to an arbitrary host path (same class as the PKEY_TITLE finding).
- Fix suggestion: Validate `new_name` is a plain file name (no separators, no `..`) before renaming.

## [MEDIUM] `FileVersionInfo::parse` uses hardcoded offsets that may not match real VS_VERSIONINFO resources

- File: src/real_win32.rs:6365
- Description: The code checks the `VS_FIXEDFILEINFO` signature at offset 40 and fields at 48/52/56/64. A standard `VS_VERSIONINFO` resource has the fixed file info at offset ~6 (after the 6-byte root header), so genuine Windows version resources will fail the signature check → games see no version info. Only consistent if the crate's own resource writer uses this exact layout.
- Fix suggestion: Parse the wLength/wValueLength-prefixed structure instead of fixed offsets (or document the required layout and validate against the producer).

## [MEDIUM] `HtmlPersistStream::load` accepts UTF-8 only

- File: src/real_win32.rs:10772
- Description: `String::from_utf8` rejects UTF-16LE (with BOM) HTML — common for real MSHTML streams — so loading such content silently fails (`false`).
- Fix suggestion: Detect and decode UTF-16 BOMs (and fall back to lossy UTF-8).

## [MEDIUM] Thread-pool timer `set_timer` with `due_time_ms == 0` never fires

- File: src/real_win32.rs:7862
- Description: `timer.is_set = due_time_ms > 0` — Windows `SetThreadpoolTimer` with a due time of 0 means "due immediately"; here the timer is silently never set.
- Fix suggestion: Track `is_set` separately from the due value (set always, with 0 meaning now).

---

## [LOW] Dead code and unused scaffolding

- File: src/real_win32.rs:5030 (`MsvcCrt::next_file_descriptor`, `open_files`, `CrtFileRecord` — maintained but never read/written after init; file-descriptor tracking is entirely non-functional)
- File: src/real_win32.rs:4760 (`SafeArrayDescriptor` struct never used; SAFEARRAYs are handled as raw bytes)
- File: src/real_win32.rs:3552 (`ComClassEntry` struct never referenced)
- File: src/real_win32.rs:1455 (`let _child_pidl = child.pidl.clone();` — pointless clone)
- File: src/real_win32.rs:7789 (`ThreadPoolManager::start_time` never read)
- File: src/real_win32.rs:5143 (`crt_beginthreadex` returns hardcoded `Ok(42)`)
- File: src/real_win32.rs:4357 (`apartment_message_pump` always returns `false`; the "pump loop" exits immediately)
- File: src/real_win32.rs:8797 vs 9000 — two parallel SCM implementations (`Advapi32Manager` and `ServiceControlManager`) with overlapping API; both are live, inviting divergence (one pre-seeds Steam services, the other doesn't).

## [LOW] `%G`/`%g` produce identical output

- File: src/real_win32.rs:5462
- File: src/real_win32.rs:5750
- Description: Both branches use `format!("{}{:.prec$}", ...)` — `%G` should uppercase the exponent (e.g., `1E+06`), but outputs lowercase `1e6`.
- Fix suggestion: Use `{:.prec$E}`-style for the `G` case (as the `e`/`E` branch already does).

## [LOW] `MsHtmlDocument::get_all` mis-parses self-closing tags

- File: src/real_win32.rs:10684
- Description: `<br/>` yields tag name `"br/"` (the `/` is kept). Also doctype/comments handling is ad hoc.
- Fix suggestion: Trim a trailing `/` before recording the tag name.

## [LOW] `variant_to_string`/`variant_to_f64` treat VT_BSTR/VT_LPWSTR as unreadable (returns 0/empty)

- File: src/real_win32.rs:4696
- File: src/real_win32.rs:4733
- Description: Documented as "would dereference guest memory" — string variants coerce to 0/"" in numeric/string conversions, so `VariantChangeType(BSTR → I4)` of `"42"` yields 0 instead of 42.
- Fix suggestion: If guest memory access is available, read the wide string; otherwise return a conversion error rather than a silently wrong value.

## [LOW] `ComApartmentState::co_initialize` always returns success even for conflicting models

- File: src/real_win32.rs:3649
- Description: Re-init with a *different* apartment model returns `Ok(())` (real COM returns `RPC_E_CHANGED_MODE`); per-thread `co_initialize_ex` similarly returns `Ok` for already-initialized threads (should be S_FALSE — harmless, but callers can't distinguish).
- Fix suggestion: Track the previous model and return an error/S_FALSE accordingly.

## [LOW] `do_drag_drop` always returns `DROPEFFECT_NONE`

- File: src/real_win32.rs:1950
- Description: Documented stub (no NSDraggingSession), but it *does* mutate the pasteboard then reports "cancelled" — a drop that the host pasteboard received is reported as none.
- Fix suggestion: Either remove the pasteboard side effect or report the effect the pasteboard actually holds.

## [LOW] `UrlMonikerObject::is_running` mishandles `file://localhost/...` and query strings

- File: src/real_win32.rs:11065
- Description: `trim_start_matches("file://")` leaves `localhost/...` (path check fails) and `http://host/path?x` is accepted as "running" regardless of reachability (documented tradeoff).
- Fix suggestion: Parse the URL properly (strip host part for file://, reject if host non-empty).

## [LOW] Thread-pool timer due times are u32 — wrap after ~49.7 days

- File: src/real_win32.rs:7973
- Description: `due_time_ms.wrapping_add(period_ms)` wraps u32 after ~49 days of uptime; a wrapped timer fires immediately then re-arms from the small value. Long-running games with day-scale timers misbehave.
- Fix suggestion: Store due times as u64.

## [LOW] `get_node_type` returns `"element"` for any non-empty document

- File: src/real_win32.rs:10854
- Description: The node type is not derived from the parsed document (always "element" when the XML string is non-empty).
- Fix suggestion: Return the actual `NodeType` of the document element.

---

## [PERF] Per-call allocations / O(n²) in hot paths

- File: src/real_win32.rs:11654 (`get_device_state` builds a fresh `Vec` per poll — called every frame/input poll; mouse/joystick paths could write into a caller-provided buffer)
- File: src/real_win32.rs:8163 and 8440 (`sym_from_addr`/`find_module_for_address` linear-scan all symbols/modules; `stack_walk` also re-scans per frame → O(frames × symbols); use a sorted structure or cache)
- File: src/real_win32.rs:2458 (`PropertyStore::get_at` collects all keys into a Vec per call)
- File: src/real_win32.rs:2709 (`get_elements_by_tag_name` re-serializes every matching subtree → O(n²) for many matches)
- File: src/real_win32.rs:1302 (`enum_objects` clones the full entry list; `ShellFolder::new` re-reads the whole directory on every BindToObject)
- File: src/real_win32.rs:11717 (`set_key_state` appends to `buffered_data` with no bound — unbounded growth if the guest never drains)
- File: src/real_win32.rs:3391 (`MsHtmlDocumentObject::new` eagerly creates a WKWebView per COM instance even when the document is never rendered)

---

## Clippy

`cargo clippy --all-targets --no-deps` warnings/errors referencing `src/real_win32.rs` (60 warnings + 1 error in this file):

**ERROR (build-breaking, this file):**
- `clippy::approx_constant` (denied): src/real_win32.rs:9474 — `3.14` in test; use `f64::consts::PI`.

**Warnings (grouped by lint):**
- `new_without_default` (12): 2537, 2597, 2956, 3282, 3357, 3634, 5047, 6510, 6996, 7793, 8135, 8804, 9013 (DeltaTree, XmlDomDocument, MsHtmlDocument, MsHtmlScript, MsHtmlTxtRange, ComApartmentState, MsvcCrt, XInputManager, BCryptContext, ThreadPoolManager, DbgHelpContext, Advapi32Manager, ServiceControlManager)
- `collapsible_if` (14): 2429, 2734, 5299, 5436, 5467, 5734, 5751, 5777, 8167, 8443, 10601, 11843, 11858, 11871
- `useless_transmute` (5): 1647, 1712, 1737, 3045, 3060 (ptr→ptr transmutes; note 1647 is also the CRITICAL untrusted-pointer finding)
- `manual_c_str_literals` (2): 1965, 2382 (`"NSDragPboard\0"`, `"kMDItemAuthors\0"` literals — use `c"..."`/`CString`)
- `too_many_arguments` (3): 8393 (rtl_capture_stack_back_trace, 8/7), 10466 (reg_notify_change_key_value, 8/7), 11752 (update_joystick_state, 10/7)
- `unnecessary_cast` (3): 6873, 6875 (u32→u32), 8761 (usize→usize)
- `needless_borrow` (2): 6854, 7727
- `map_or` (2): 10627, 10628
- `manual_map` (1): 7927
- `manual_str_repeat` / `repeat_with_take` (4): 5405 (×2), 5713 (×2)
- `if_same_then_else` (1): 5462 (the %g/%G bug above)
- `iter_kv_map` (1): 8270
- `map_entry` (1): 5133
- `manual_contains` (1): 4101
- `type_complexity` (1): 4219
- `should_implement_trait` (1): 1399 (`EnumIdList::next` — confusable with `Iterator::next`)
- `empty_line_after_doc_comment` (1): 4444
- `bool_comparison` (1): 9708
- `collapsible_if`/`unnecessary_wraps` etc. as grouped above

## Build

- Command: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` → **FAILED** (not finished cleanly).
- `casa1` lib: 1271 warnings, **19 errors** — all 19 errors are in other files (cpu.rs, jit.rs, metal_backend.rs, d3d11.rs, d2d.rs, dwrite.rs, winhttp.rs, video_decoder.rs, seh.rs, security.rs, crash_recovery.rs, pe_runtime.rs).
- `casa1` lib test: 1415 warnings, **27 errors** — 26 in other files + **1 in this file**: `clippy::approx_constant` at src/real_win32.rs:9474 (test `crt_atof_various_inputs`, `3.14` should be `f64::consts::PI`).
- Consequence: the crate does not pass `cargo clippy` today; the error in this file blocks `--all-targets` on the test target even after the other files are fixed.
- Note: `--all-features` was intentionally not used (missing system ffmpeg is environmental); no errors attributable to that.
