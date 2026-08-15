# AUDIT_FINDINGS.md

- Batch: scm-imports-2026-08-15 (worktree `audit-scm-imports`)
- Files: `src/scm.rs` (3402 lines), `src/import_coverage.rs` (2466 lines) — read in full, in order (1–3402, 1–2466)
- Date: 2026-08-15
- Method: full line-by-line read + `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (completed; see `## Build`)

Severity counts: CRITICAL 3 · HIGH 3 · MEDIUM 10 · LOW 9 · PERF 3 · **Total 28**

---

## [CRITICAL] Path traversal in virtio-fs: guest paths escape the shared directory

- File: src/scm.rs:1668
- Description: `guest_to_host_path` only strips leading `/` and calls `Path::join`. The doc comment claims "Path traversal (`..`) is resolved but confined to the shared directory", but no confinement exists: a guest-supplied path like `../../etc/passwd` or `..%2f..` (via `stat`, `open`, `read`, `write`, `seek`, `mkdir`, `unlink`, `readdir`) resolves to an arbitrary host path. The "handles" never pin a host fd either (see MEDIUM finding), so even a sanitized open does not bound the attack surface. A compromised/guest-side caller can read, write, and delete arbitrary files on the host (e.g., `unlink("../../../../etc/passwd")`).
- Fix suggestion: canonicalize and verify containment before any operation: `let canon = fs::canonicalize(&host_root.join(cleaned)).map_err(...)?; if !canon.starts_with(&canonical_root) { return Err(...) }` (use `std::path::Component::ParentDir` rejection or canonicalize + prefix check), and reject `..`/NUL components up front.

## [CRITICAL] `write_framebuffer` panics on out-of-bounds slice indexing with guest-controlled coordinates

- File: src/scm.rs:2716
- Description: The controller's framebuffer writer (documented as "called by guest display driver" — untrusted input) never validates `x`, and uses plain subtraction for `y`:
  - Line 2718: `self.virtio_gpu.framebuffer_height - y` underflows (panics in debug; wraps in release) when `y > 720`.
  - Line 2720: `pixels.len() - src_start` underflows when `src_start > pixels.len()`.
  - Line 2721: `x` is used directly — e.g. `x = 1280, y = 719, width = height = 1` yields `dst_start == fb.len()`, then line 2727 `framebuffer[dst_start..dst_end]` panics with OOB slice index in both debug and release.
  - A single malicious call (e.g., `write_framebuffer(0, 1000, 100, 100, &big_pixels)`) crashes the process. Contrast with `VirtioGpuMetal::update_scanout` (line 1420) which clamps correctly via `saturating_sub`.
- Fix suggestion: mirror `update_scanout`: `let cx = x.min(fb_width.saturating_sub(...))`, `let cy = y.min(fb_height.saturating_sub(...))`, use `checked_sub`/`checked_mul` for all offsets and return `AppResult<()>`/early-return instead of slicing; also guard `width*4 <= pixels.len()` per row before computing `src_end`.

## [CRITICAL] `setDeviceDevices:` is not a real ObjC selector — VM creation aborts on macOS

- File: src/scm.rs:1096
- Description: `VZVirtualMachineConfiguration` exposes the property `devices`, whose setter is `setDevices:`. `msg_send![vz_config, setDeviceDevices: devices_array]` dispatches to a non-existent selector → `doesNotRecognizeSelector:` → `NSInvalidArgumentException` (uncaught; Rust cannot catch ObjC exceptions) → process abort. This runs in the production path `create_vz_virtual_machine` under `#[cfg(all(target_os = "macos", not(test)))]`, i.e. every real VM launch with the macOS build crashes at config setup.
- Fix suggestion: change the selector to `setDevices:` (and consider adding a compile-time check by calling the method through an explicit `sel_registerName`/`respondsToSelector:` guard).

---

## [HIGH] `vz_start_sync` completion handler treats failure as success

- File: src/scm.rs:444
- Description: Both branches of `if error.is_null() { … } else { … }` store `true` into `VZ_COMPLETION_RESULT`; the `if` is dead logic (clippy `if_same_then_else` flags it). `start()` therefore reports `Ok`/`VmState::Running` even when the VZ start completed with an NSError, and the failure `ReasonCode::RcRunnerSpawnFailed` path is unreachable. Subsequent VM ops then fail with confusing state.
- Fix suggestion: store `error.is_null()` (i.e. `true` only when the error pointer is nil) and return `false`/fail in the error branch; keep the timeout branch as-is.

## [HIGH] ObjC block ABI violation: `BlockLiteral` missing descriptor, flags constant is wrong

- File: src/scm.rs:171
- Description: `BLOCK_FLAGS_STACK = 1 << 30` is actually `BLOCK_HAS_SIGNATURE` in Apple's libclosure (there is no "stack" flag). The `BlockLiteral` struct (lines 175–181) also lacks the mandatory trailing `Block_descriptor` (contains block size/copy-dispose pointers) that every block layout must have. If the Virtualization framework copies the block (the documented behavior for async VZ completion handlers — start/stop/pause/resume/requestStop are all asynchronous), `_Block_copy` reads the missing descriptor from stack garbage → garbage size/function pointers → crash or UB. It currently "works" only if the callee never copies the block.
- Fix suggestion: use the canonical layout `{ isa, flags, reserved, invoke, descriptor }` with a real `_NSConcreteStackBlock` isa, or better, replace the hand-rolled blocks with a proper block/closure library (e.g. `block2`/`objc2` with `&block as *const _`), or with synchronous VZ calls where available.

## [HIGH] `ScmController::new` eagerly allocates up to 4 GiB of zeroed memory, unbounded by untrusted config

- File: src/scm.rs:2556
- Description: `memory_size = (config.memory_mb as usize).max(256) * 1024 * 1024` allocates `vec![0u8; …]` on every `ScmController::new` / `ScmRunnerIntegration::new` — 4 GiB for the default 4096 MB config, even when SCM is disabled. `memory_mb` is loaded from untrusted config: a large value makes the allocation fail and abort the process (OOM); `.max(256)` only sets a floor. `Clone` (derived) copies the whole buffer again.
- Fix suggestion: cap `memory_mb` (e.g. `clamp(256, 16384)`) and allocate lazily (e.g. `Option<Vec<u8>>`/`Arc<Mutex<…>>` populated only when SCM actually runs), or map the region with `mmap` + `MAP_NORESERVE` instead of a zeroed Vec.

---

## [MEDIUM] Cross-instance race on static completion-result flags

- File: src/scm.rs:436
- Description: `VZ_START/STOP/PAUSE/RESUME/REQSTOP_RESULT` are process-global `AtomicBool`s shared by all `VZVirtualMachineHandle`s. Two concurrent VM operations on different handles interleave: thread A resets the flag, starts VM A; thread B resets the flag, starts VM B; whichever completion fires first satisfies the other's wait loop, so thread A/B can return "success" before its own VM actually completed (or after its own start failed — see HIGH finding). Same pattern at lines 483, 526, 569, 612.
- Fix suggestion: use per-handle state (store the result in a `Mutex<Option<…>>`/`Condvar` member of the handle, or per-call channel) instead of a `static`.

## [MEDIUM] Panic on interior NUL bytes in untrusted path/string config (`CString::new(...).unwrap()`)

- File: src/scm.rs:838
- Description: `CString::new(kernel_path/initrd_path/command_line/efi_path/mount_tag/shared_dir/mac/path).unwrap()` (lines 838, 850, 862, 882, 956, 963, 994, 1035; also 673, 680, 750 for constants) panics if a string from untrusted `ScmConfig`/`VZVirtualMachineConfiguration` contains `\0`. This is a reachable panic from attacker-controlled config.
- Fix suggestion: use `.map_err(...)`/`.ok_or_else(|| AppError::new(ReasonCode::RcFsPathInvalid, "path contains NUL"))` and propagate an `AppResult` error.

## [MEDIUM] `pump_run_loop` leaks autoreleased objects and builds an unused NSArray every iteration

- File: src/scm.rs:666
- Description: Each loop iteration (up to 30 s per wait) creates `NSArray`/`NSString`/`NSDate` objects via class methods that return autoreleased objects; the `modes` array is created, null-checked, then never used (dead code — `runMode:` is called with a separately built `ns_default_mode`). In a Rust thread without an `NSAutoreleasePool`, every iteration leaks ~3 ObjC objects; thousands leak during a 30 s wait.
- Fix suggestion: delete the unused `modes` array, reuse a single `NSDate`/mode string (build once outside the loop), and wrap the loop body in `objc_autoreleasePoolPush`/`Pop`.

## [MEDIUM] `VirtioGpuMetal` leaks Metal resources on drop

- File: src/scm.rs:1294
- Description: `metal_texture` (`MTLTexture*`) and `command_queue` (`MTLCommandQueue*`) are retained (lines 1378, 1396) but only released in `resize` (1566–1575). There is no `Drop` impl, so every dropped GPU leaks a texture and a command queue; `flush_to_metal` error paths compound this (command buffers never released on error returns).
- Fix suggestion: implement `Drop for VirtioGpuMetal` that releases `metal_texture`/`command_queue`, and release the `cmd_buffer`/`blit_encoder` on the error paths in `flush_to_metal`.

## [MEDIUM] u32 overflow in `update_scanout` row stride can panic (debug) or copy wrong data (release)

- File: src/scm.rs:1428
- Description: `src_start = (row * width * 4) as usize` uses the unclamped, guest-controlled `width`. With `width` ≈ 2^30 and `row ≥ 1` the u32 product overflows: panic in debug builds (overflow checks), silently wrapped (wrong source region) in release. `src_end`/bounds checks then `break`, so no OOB, but behavior is wrong and a guest can crash debug builds.
- Fix suggestion: compute in `usize` with `checked_mul` (`row as usize * width as usize * 4`) and treat overflow as a clamp/error; or stride by the clamped width after clamping.

## [MEDIUM] Unbounded buffer/queue growth from guest-side flooding

- File: src/scm.rs:2019
- Description: Several structures grow without bound when the counterparty stalls: `VirtioNetBridge.tx_buffer` (every `send_packet` extends; drained only on `tick`), `rx_buffer` (loopback at scm.rs:2918–2923 extends it; drained only by guest `receive_packet` — a guest that never reads grows RAM forever), `irp_queue` (2487), `dpc_queue` (2522), `measurement_log` (2195), `file_handles` (1696, handles never closed by guest), `dirty_rects` (1443, if `flush_to_metal` is not called). `rx_buffer.drain(..copy_len)` is also O(n) per read.
- Fix suggestion: impose per-structure caps (e.g. max packet queue bytes, max IRPs/DPCs, max open handles, max dirty rects) with `RcOutOfMemory`-style errors or eviction, and use `VecDeque` with a bounded read window.

## [MEDIUM] Duplicate and misattributed functions in `steam_exe_imports` skew the report

- File: src/import_coverage.rs:77
- Description: The kernel32 list contains duplicates (`WaitForSingleObject` at 77 and 99; `GetTickCount64` at 82 and 88) which double-count `total`/`covered` and inflate `total_imports` (793 entries vs 788 unique). It also misattributes `GetUserNameA/W` (kernel32 141–142 — these are advapi32 exports) and `DoDragDrop` (shell32 571 — an ole32 export), which are then falsely reported as "missing" from the wrong DLL. Any consumer trusting the JSON totals gets wrong numbers.
- Fix suggestion: deduplicate each list (or use a `BTreeSet`-based comparison), and move `GetUserNameA/W` to advapi32 and `DoDragDrop` to ole32 (remove from shell32).

## [MEDIUM] Coverage data is circular: `known_covered_functions` is a near-verbatim copy of `steam_exe_imports`

- File: src/import_coverage.rs:988
- Description: `known_covered_functions` (lines 988–1942) is a manual copy of the import list (788 of 793 names identical; only `DebugBreak`, `ClipCursor`, `GetClipCursor` differ). The report therefore never reflects the actual PE runtime implementation state — it will always show ≈99.6% coverage by construction, regardless of what is really implemented. This defeats the module's stated purpose ("cross-references with known Steam.exe imports … shows covered vs missing") and gives false confidence (DebugBreak/ClipCursor/GetClipCursor are the only "missing" functions ever reported).
- Fix suggestion: derive "covered" from the real runtime export registry (e.g. query the PE runtime's registered export tables like `generate_pe_coverage_report` does) instead of a hand-maintained copy; at minimum, add a test asserting the list tracks an authoritative source and fail CI when the two lists drift.

## [MEDIUM] Serial port device is created without an attachment; `SerialHandler::File` is ignored

- File: src/scm.rs:1021
- Description: `VZDeviceConfiguration::SerialPort` creates a bare `VZSerialPortConfiguration` with no attachment (no `VZFileHandleSerialPortAttachment`), and the `SerialHandler` enum (`File(String)`/`Null`) is never consulted — guest serial output goes nowhere. `configure_arm64_vm` always adds a serial port (1259–1261), so on macOS the config will likely fail `validateWithError:` (serial configs require an attachment), and even if it passes, the configured file handler is silently dead.
- Fix suggestion: wire `SerialHandler::File` to a `VZFileHandleSerialPortAttachment` (host-side log file) and `Null` to a discarded fd; skip adding the device when a `Null` handler is intended, or implement it properly.

## [MEDIUM] virtio-fs handles do not pin host files: every op reopens by path

- File: src/scm.rs:1731
- Description: `open()` stores only a path; `read`/`write`/`seek` reopen the file and re-seek on every call. Consequences: (a) TOCTOU — a file swapped/deleted after `open` yields wrong content or spurious errors, unlike Windows handle semantics; (b) writes always go to the current file at the path, and a directory handle fails at read time; (c) 3 syscalls (open+seek+read/write) per I/O op — unnecessary overhead in a per-frame path.
- Fix suggestion: keep an `Option<std::fs::File>` (opened per access mode at `open`) in `VirtioFsFileHandle`, seek through it, and drop the reopen pattern.

---

## [LOW] VZ state values 4 (starting) / 5 (stopping) misreported as `VmState::Error`

- File: src/scm.rs:400
- Description: `match raw_state { 0..3 … _ => Error }` — VZVirtualMachineState also includes `starting = 4` and `stopping = 5`; transient states are reported as a hard error.
- Fix suggestion: map 4/5 to a transitional variant or keep the last known state instead of `Error`.

## [LOW] `uptime_seconds` is never updated

- File: src/scm.rs:2549
- Description: `uptime_seconds` is initialized (2556) and reset (2607) but never incremented in `tick()` or anywhere else — dead field.
- Fix suggestion: increment in `tick` from elapsed wall time, or remove the field.

## [LOW] `configure_secure_boot` is a no-op; secure-boot / Windows-EFI paths are unwired

- File: src/scm.rs:2138
- Description: `configure_secure_boot` only checks for an empty path — it never configures any VZ object despite its doc comment; it is also never called from `create_vz_virtual_machine`. `SecureBootConfig` created in `ScmRunnerIntegration::new` (2808) is stored but unused; `BootLoaderType::WindowsEfi`/`VZBootLoader::Windows` are never constructed by product code (`launch_vm` hardcodes `LinuxKernel`, 2844) — the "Windows EFI boot" path and the anti-cheat/driver story are unimplemented.
- Fix suggestion: either implement (wire `VZEFIBootLoader` + `VZEFIVariableStore` + `secure_boot` platform config) or mark the API `todo!()`-free and document as unsupported.

## [LOW] `satisfy_integrity_check` always returns true past a base-address check and ignores the hash

- File: src/scm.rs:2746
- Description: Any address ≥ `ntoskrnl_base` passes integrity checks; `_expected_hash` is unused. This is a permanent "satisfied" stub for anti-cheat queries — no actual verification. If intended as a placeholder, it should be gated behind a clearly-marked stub; as written it silently disables the integrity contract.
- Fix suggestion: implement real hash comparison over guest memory or return `false`/error until implemented.

## [LOW] Unused variable `_dll_lower`

- File: src/import_coverage.rs:1965
- Description: `let _dll_lower = dll.to_lowercase();` is dead code (allocation for nothing).
- Fix suggestion: delete the line.

## [LOW] `read()`/`write()` truncate byte counts to u32

- File: src/scm.rs:1750
- Description: `bytes_read as u32` (and 1796 `bytes_written as u32`) truncate on 64-bit if a single op moves > 4 GiB; also the virtio-fs API loses precision vs the u64 positions tracked in the handle.
- Fix suggestion: return `u64` (or cap the per-call buffer length at `u32::MAX`).

## [LOW] Negative seek offsets with `whence = 0` wrap instead of failing

- File: src/scm.rs:1812
- Description: `SeekFrom::Start(offset as u64)` turns a negative offset into a huge u64; on macOS seeking past EOF succeeds (sparse), so `seek(handle, -5, SEEK_SET)` silently succeeds instead of returning an error like Windows.
- Fix suggestion: reject `offset < 0` for `SEEK_SET` with an `RcFsPathInvalid`-style error.

## [LOW] Fake PIDs can collide across services

- File: src/scm.rs:2391
- Description: `pid_value = 1000 + (service_database.len() % 60000)` is derived from the map length — a restart that adds services in a different order, or ≥ 60k services, yields colliding or unstable PIDs, and PIDs change after unrelated service creation.
- Fix suggestion: keep a monotonic PID counter or assign from a stable hash of the service name.

## [LOW] Re-entering `launch_vm` silently drops the running VM handle without stopping it

- File: src/scm.rs:2840
- Description: `launch_vm` doesn't guard against being called twice: a second call creates a new VM, and `self.vm_handle = Some(vm2)` drops the first handle (ObjC `release`) without `stop()` — the first guest keeps running, and `net_bridge`/`fs_bridge`/`controller` states are overwritten. Also, if `start_vm()` (2874) fails mid-sequence, `vm_handle` remains started while the error propagates.
- Fix suggestion: return `RcInvalidState` if `vm_handle.is_some()`/`vm_state == Running`, or shut the previous VM down before replacing.

---

## [PERF] O(n²) lookups in report generation

- File: src/import_coverage.rs:1977
- Description: `generate_import_coverage_report` does `dll_covered_lower.contains(&func_lower)` — a linear scan per import (≈150 × 150 per DLL; fine today, but scales poorly). `generate_pe_coverage_report` does `exports.iter().any(...)` per import thunk (2211–2219, 2255–2263) — for a large PE (thousands of imports × thousands of exports) this is quadratic, with a `String::to_lowercase()` allocation per thunk and per entry.
- Fix suggestion: build `BTreeSet`/`HashSet` of lowercase covered names once per DLL, and a `BTreeMap<&str, ordinal>`/name→ordinal index of exports per DLL for O(log n) lookups.

## [PERF] Busy-wait/yield loop in the synchronous VZ wrappers

- File: src/scm.rs:467
- Description: All five `vz_*_sync` loops spin `while !flag { pump_run_loop(); yield_now(); }` for up to 30 s. Each iteration pumps the run loop (~10 ms), so CPU burn is moderate, but the `yield_now` + atomic polling pattern is a busy-wait and burns one core for the duration of every VM op (start/stop/pause/resume can each take seconds).
- Fix suggestion: block on a `Condvar`/semaphore signaled from the completion handler instead of polling, or use VZ's async callback on a dedicated queue.

## [PERF] Per-I/O syscall overhead in virtio-fs

- File: src/scm.rs:1731
- Description: Every `read`/`write`/`seek` issues open + seek + I/O syscalls (see MEDIUM finding on handle semantics); with per-frame guest I/O this multiplies syscalls 3× per operation.
- Fix suggestion: persistent fd in the handle (same fix as the MEDIUM finding above).

---

## Clippy

Warnings referencing the audited files (`cargo clippy --all-targets --no-deps`, rustc 1.96):

src/scm.rs (8):
- `if_same_then_else` — src/scm.rs:444 (identical branches in `vz_start_sync` completion handler; see HIGH finding)
- `collapsible_if` — src/scm.rs:705 (Drop delegate)
- `derivable_impls` — src/scm.rs:2084 (`SecureBootConfig` manual `Default`)
- `derivable_impls` — src/scm.rs:2123 (`MeasuredLaunchState` manual `Default`)
- `collapsible_if` — src/scm.rs:2143 (`configure_secure_boot`)
- `needless_borrows_for_generic_args` — src/scm.rs:2181 (`hasher.update(&state.pcr_values[pcr_index])`)
- `collapsible_if` — src/scm.rs:2918 (tick net loopback)

src/import_coverage.rs (7):
- `unnecessary_to_owned` ×7 — src/import_coverage.rs:2396–2402 (test asserts `contains_key(&"kernel32.dll".to_string())` etc.)

## Build

`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` completed but the crate does **not** compile: `error: could not compile casa1 (lib)` — 19 errors; `(lib test)` — 27 errors. All errors are in files **outside** the audited scope: src/jit.rs (7), src/metal_backend.rs (6), src/cpu.rs (3), src/d3d11.rs (2), src/d2d.rs (2), src/winhttp.rs, src/video_decoder.rs, src/seh.rs, src/security.rs, src/pe_runtime.rs, src/dwrite.rs, src/crash_recovery.rs (1 each). Error classes include not-unsafe public fns dereferencing raw pointers, always-true/false min/max comparisons, `set_len` on uninitialized buffer, and logic-bug booleans. No errors reference src/scm.rs or src/import_coverage.rs; both audited files compile with only the warnings listed above. Full output preserved in `clippy_out.txt` (1543 warning/error lines).
