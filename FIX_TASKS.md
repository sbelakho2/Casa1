# Casa1 Test Audit — AUDIT_FINDINGS.md

## Audit metadata
- **Batch**: Casa1 test-correctness audit (batch 1, worktree `audit-tests-ac`)
- **Files audited** (every line read in full):
  - `tests/section1.rs` (3140 lines)
  - `tests/section2.rs` (1066 lines)
  - `tests/section3.rs` (562 lines)
  - `tests/section8.rs` (563 lines)
  - `tests/section9.rs` (689 lines)
  - `tests/section10.rs` (606 lines)
  - `tests/section11.rs` (407 lines)
  - `tests/section12.rs` (388 lines)
  - `tests/section13.rs` (576 lines)
  - Supporting: `tests/support/mod.rs` (2570 lines), `src/bin/casa1-oracle.rs` (oracle harness)
- **Date**: 2026-08-15
- **Method**: full sequential read of every line; `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps`; per-file `cargo test --test <stem>` runs.

---

## [HIGH] t01_19 "forwarder chain too deep" test never calls any forwarder code — pure theater
- File: `tests/section1.rs:2512-2545` (also `tests/section1.rs:2505-2506`)
- Description: `t01_19_forwarder_chain_too_deep_returns_none` claims to verify the `MAX_FORWARDER_DEPTH` overflow protection in `pe_runtime.rs`, but never invokes `pe_runtime::export_tables()`, the forwarder resolver, or any function that could "return None". It only inserts strings `"forwarder_0".."forwarder_8"` into a `HashSet` and asserts `visited.len()` is 8, then 9, then `> 8` — i.e. it proves `HashSet::insert` works. The test would pass identically on an implementation with NO forwarder depth limit at all (e.g., an infinite-recursion bug). The `max_depth = 8` value is a local variable, not the production constant, so the "limit" it asserts is self-invented. This is false confidence on a security-relevant path (stack-overflow protection in export forwarding).
- Fix suggestion: Call the actual resolver with a chain of 9+ forwarders and assert it returns `None`/fails; import/compare the real `MAX_FORWARDER_DEPTH` constant from `pe_runtime.rs` instead of declaring `let max_depth = 8` locally. `t01_18_forwarded_exports_cache_hit` (line 2477) has the same pattern (`let max_depth: usize = 8; assert_eq!(max_depth, 8)`) — delete that tautology and, if "cache hit" is meant, exercise an actual forwarder-cache lookup.

## [HIGH] Seven Steam tests silently excluded by stale `#[ignore]` reasons — flagship coverage never runs
- File: `tests/section13.rs:58, 103, 149, 174, 209, 271, 366` (t13_1..t13_7)
- Description: All seven are marked `#[ignore] // requires real Steam client and network access`, but they are fully in-process simulations: `SteamClient::new("C:/GEs/SteamFresh")` with hardcoded guest paths, in-memory IPC (`\\.\pipe\SteamClient` / `SteamSharedMem`), self-imported test certificates, no real sockets, no real Steam. They would run in CI without external dependencies (t13_8/t13_9 prove the loader path runs fine), yet they are permanently excluded, so Steam boot/login/update/integrity/prerequisite/zero-touch coverage is silently dropped. The same stale-reason pattern excludes the 6 `ge_install_steam_zero_touch_*` tests in `tests/section1.rs` (lines 455, 653, 818, 984, 1149, 1363) whose installers are synthetic `sample_pe_bytes()` and whose payloads are temp files.
- Fix suggestion: Remove `#[ignore]` from the simulated Steam tests (run them in CI); keep ignores only for tests that genuinely require zig-built real PEs or an external Steam GE, and update the reason comment to the real constraint.

## [HIGH] t9_1 golden-signature test is failing — expected string is stale/wrong, and the format is maximally brittle
- File: `tests/section9.rs:239-246` (assertion at `:246`), helper `submission_signature` at `:15-31`
- Description: Test run: `t9_1_d3d11_conformance_microtests_and_frame_diffs_match_reference ... FAILED` — `assertion failed: submission.signature.contains(binding_signature)`. The hand-built 800-char `binding_signature` does not appear in the implementation's submission signature, so the suite is red. Additionally, the expected full signature is assembled in the test from implementation-derived values (`gpu_profile`, `depth_store_action`) concatenated with a hand-formatted template — any harmless format change (field order, `scissor=none`, `topo=none`, whitespace) breaks the test even when behavior is correct, and the digest/`hash` expectations are computed from the same self-assembled string.
- Fix suggestion: Either update the expected string to match the current canonical format (verify by diffing the actual signature), or parse the signature and assert on semantic fields (draw counts, render-target/dsv ids, per-stage bindings) instead of a full-string `contains`. Add a checked-in golden file rather than embedding a re-derived template.

## [HIGH] t10_7 uses a sample rate the implementation rejects — test can never pass as written
- File: `tests/section10.rs:559-568` (panic at `:568`)
- Description: Test run: `t10_7_xaudio2_channel_mixing_resampling_and_latency ... FAILED` — panic `create source voice: AppError { code: RcAudioUnsupported, message: "unsupported audio format: 1 channels, 12000 Hz" }`. The test creates a 12 kHz mono source voice, which the audio subsystem explicitly does not support (t10_1 successfully uses 24 kHz, so 12 kHz is below the supported band). The `.expect("create source voice")` converts the rejection into a panic instead of an assertion, and the test's final checks are weak (only `samples.len() == 12`, `latency_ms <= 50`, `crc32 != 0`) — so even if the fixture were fixed, it would not verify resampling correctness or channel layout.
- Fix suggestion: Use a supported source format (e.g., 24 kHz mono) or use a format the engine documents as supported; assert on the actual resampled/mixed channel values (e.g., first output frame) rather than lengths and non-zero CRC.

## [MEDIUM] t10_6 asserts an unverified assumption about DirectSound write-cursor semantics — currently failing
- File: `tests/section10.rs:490-494` (assertion at `:494`)
- Description: Test run: `t10_6_direct_sound_cursor_looping_lock_unlock ... FAILED` — `assertion failed: write_cursor >= samples.len() as u32 * 4`. The test assumes the write cursor advances by written bytes (4 floats → ≥ 16), but the implementation reports a smaller cursor value (samples-based or not advanced until mix). The expectation is a hardcoded guess about internal semantics, so the test is either a false failure or documents a real discrepancy — with no diagnostic detail it cannot tell which, and the suite is red.
- Fix suggestion: Verify against the engine's documented cursor units (bytes vs samples, and when it advances); assert the documented invariant, or weaken to "cursor is queryable and monotonically non-decreasing after writes".

## [MEDIUM] t10_1 asserts exact `f32` equality on DSP output — brittle to any mixer/resampler change
- File: `tests/section10.rs:108-114`
- Description: `assert_eq!(rendered.samples, expected)` compares bit-exact floats (e.g., `-0.19375`, `0.056250006`) computed by hand against the reverb/resampling mix. Any legitimate change to filter coefficients, reverb tail, or resample phase (even at the 1-ulp level) breaks the test, and the comment says "within tolerance" while the assertion has zero tolerance. It currently passes, but it is a classic brittle golden test.
- Fix suggestion: Compare with a small epsilon (e.g., `|a-b| <= 1e-6` element-wise) or compare the CRC of quantized output; keep one exact-vector test if a fixed-point reference is truly wanted.

## [MEDIUM] t10_4 "torture" test contains no assertions at all — smoke test that cannot fail on wrong behavior
- File: `tests/section10.rs:376-406`
- Description: The underflow/overflow torture loop only calls `write_render_frames`/`drain_audio_client` with `.expect(...)`; there is no `assert!`/`assert_eq!` anywhere. A bug that drops frames, corrupts data, or mis-sizes buffers would pass as long as no error is returned. Despite the name, the input list `[1, 8, 0, 3, 10, 2]` is fixed, not random.
- Fix suggestion: Assert on returned frame counts/consumed positions per iteration (and on buffer-size metadata after `write_render_frames`), or at minimum verify the final drained sample count equals the total written.

## [MEDIUM] Registry watcher tests depend on 20–100 ms wall-clock timeouts — flaky under load
- File: `tests/section2.rs:656-680` (100/20 ms waits), `tests/section2.rs:719-725` (50 ms waits per operation)
- Description: `t2_4_registry_notify_suite...` counts wakes by polling `wait_for_change(Duration::from_millis(50))` once per operation; `registry_watchers_receive_change_notifications` asserts a negative case with a 20 ms wait. On a loaded CI machine, a notification arriving after the timeout makes `wake_count != suite.expected_wake_count` (or the negative assertion fail) even though the watcher is correct — timing-dependent flakiness on the main notify path.
- Fix suggestion: Use a blocking wait with an explicit deadline (e.g., `wait_for_change` until a 5 s budget is exhausted) or drain the notification channel and assert on received events rather than timeout-gated booleans.

## [PERF] `indirect_import_calls_land_on_pe_host_thunks` exceeds 15 minutes without completing — suite hangs
- File: `tests/section1.rs:407-453`
- Description: Test run: the test never completed; `casa1-runner` (the emulated PE execution) sat at <1% CPU for >20 minutes and was killed. This is the only non-ignored real-PE test, and it blocks the whole section1 binary. Either the x64 emulation of this zig-built binary is pathologically slow, or the run deadlocks in the emulator — either way the test as-is cannot run in CI. (Note: the neighboring `real_external_windows_*` tests were ignored, plausibly for exactly this reason — this one was accidentally left enabled.)
- Fix suggestion: Mark it `#[ignore]` with the real reason (emulated real-PE execution is too slow / hangs) or add a bounded runner timeout with `--timeout` so the harness fails fast; investigate the low-CPU state (possible deadlock) separately.

## [PERF] `canonical_json_is_identical_across_100_dtm_runs` spawns 100 sequential CLI subprocesses (~10 min)
- File: `tests/section1.rs:179-204`
- Description: Each iteration runs `ge:create` + `ge:run` as subprocesses; the test took on the order of 10 minutes in this run (observed "running for over 60 seconds" for an extended period). It is a strong determinism check, but at ~10 min it dominates the section1 wall-clock budget.
- Fix suggestion: Run the comparisons with a smaller N (e.g., 20) plus a couple of in-process runs, or run the loop in parallel threads with isolated GE roots; keep 100 only in a nightly/CI-scheduled job.

## [LOW] t8_4 compares `pso_cache_key` against itself with identical arguments
- File: `tests/section8.rs:455-474`
- Description: Both sides of the `assert_eq!(pso_cache_key(...), pso_cache_key(...))` pass the same two keys (`output_a.cache_key`/`output_b.cache_key`, which were already asserted equal). The call is self-comparing with identical inputs, so it can only prove the function is deterministic, not that keys are correct (e.g., a key that ignores all inputs would pass).
- Fix suggestion: Assert concrete expected key content, or compare keys produced from intentionally different state lists/inputs and assert inequality.

## [LOW] t8_5 hit-ratio assertion is redundant with the preceding exact equality
- File: `tests/section8.rs:496`
- Description: `assert!((second_run.hits as f32 / inputs.len() as f32) >= 0.95)` is trivially true given the line above already asserts `second_run.hits == 20`. No additional information.
- Fix suggestion: Delete the redundant ratio assertion (or replace with a deliberately partial-cache scenario that actually tests eviction).

## [LOW] t12_1 manifest-hash expectation re-implements the production algorithm in the test
- File: `tests/section12.rs:8-22` (helper `expected_manifest_hash`), used at `:129-145`
- Description: The test re-derives the expected tree hash by lowercasing paths, `path|sha256` lines, registry lines, and sorting — mirroring the engine's own hashing conventions. If the production convention itself is wrong (wrong normalization, wrong separator, wrong sort key), both sides agree and the test passes. It only detects divergence, not correctness.
- Fix suggestion: Keep one test per known-good checked-in manifest hash (golden file) for at least one scenario, so a change in the hashing convention itself is caught.

## [LOW] t13_8 asserts on exact error-message substrings
- File: `tests/section13.rs:461, 494-498`
- Description: `assert!(appmanifest_error.message.contains("appid must be numeric"))` and `.contains("missing Steam metadata field Executable")` couple the test to message wording; a reworded (or localized) message breaks the test even though the error path is correct, and the tests do not check the error reason codes at all.
- Fix suggestion: Assert on `error.code` (and any structured field), keep message-substring checks only as a secondary `if`-guarded diagnostic.

## [LOW] t2_1 duplicates the hand-written path-parsing test with the same six cases
- File: `tests/section2.rs:99-137` vs `tests/section2.rs:140-168`
- Description: `windows_path_parsing_handles_normalization_devices_long_paths_and_reserved_names` hand-checks the exact same cases (normalization, verbatim, device namespace, NUL, long path with/without policy) that `t2_1_path_edge_suite_matches_independent_oracle` covers via the oracle (see `src/bin/casa1-oracle.rs:62-90`). Two copies of the same expectations; if one is updated they silently diverge.
- Fix suggestion: Keep the oracle-driven suite as the source of truth and fold the hand-written test into it (or extend the oracle suite and delete the duplicate).

---

## Clippy
- Command: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` (whole-crate, ran to completion of available targets).
- **No diagnostics reference any assigned test file**: `tests/section1.rs`, `section2.rs`, `section3.rs`, `section8.rs`, `section9.rs`, `section10.rs`, `section11.rs`, `section12.rs`, `section13.rs`, or `tests/support` appear zero times in `clippy_out.txt`.
- The run aborted before linting integration-test targets: `casa1 (lib)` failed with 19 error-level lints and `casa1 (lib test)` with 27 (1415 warnings, mostly duplicates). The error-level lints are all in library sources (e.g., `src/crash_recovery.rs:536` min/max comparison always-true, `src/media.rs`/others approximate `PI`/`E`/`TAU` constants, `not_unsafe_ptr_arg_deref` on public functions, `set_len` after reserve, always-zero operations, equal operands to `&&`/`||`, a boolean-logic-bug lint) — pre-existing, unrelated to the test files, and consistent with a repo clippy config that denies those lints. No action for this audit's files; integration-test targets would need the lib lints fixed (or `--no-deps` with `-A` for the offending lints) before test-file lint output is obtainable.

## Test results
All test binaries compiled successfully (no compile failures). Run with `CARGO_BUILD_JOBS=4 cargo test --test <stem>` (whole-crate build first, ~cached).

| File | Passed | Failed | Ignored | Notes |
|---|---|---|---|---|
| `tests/section1.rs` | 26 | 0 | 16 | 1 test did not finish: `indirect_import_calls_land_on_pe_host_thunks` — running >20 min at <1% CPU, killed after the 15-min hang threshold |
| `tests/section2.rs` | 14 | 0 | 0 | 2.79 s |
| `tests/section3.rs` | 9 | 0 | 0 | 0.24 s |
| `tests/section8.rs` | 6 | 0 | 0 | 0.01 s |
| `tests/section9.rs` | 3 | 1 | 0 | failure below |
| `tests/section10.rs` | 6 | 2 | 0 | failures below |
| `tests/section11.rs` | 4 | 0 | 0 | 0.05 s |
| `tests/section12.rs` | 4 | 0 | 0 | |
| `tests/section13.rs` | 2 | 0 | 7 | 7 ignored (see HIGH finding) |

Failing tests (name — one-line summary):
- `t9_1_d3d11_conformance_microtests_and_frame_diffs_match_reference` — `tests/section9.rs:246`: `submission.signature.contains(binding_signature)` failed (hand-built expected binding string not present in actual submission signature).
- `t10_6_direct_sound_cursor_looping_lock_unlock` — `tests/section10.rs:494`: `write_cursor >= samples.len() * 4` failed (write cursor below 16 after writing 4 float samples).
- `t10_7_xaudio2_channel_mixing_resampling_and_latency` — `tests/section10.rs:568`: panic `create source voice: unsupported audio format: 1 channels, 12000 Hz` (fixture uses unsupported 12 kHz mono source).

## Summary
- **CRITICAL**: 0
- **HIGH**: 4
- **MEDIUM**: 4
- **PERF**: 2
- **LOW**: 5
- **Total findings**: 15
# AUDIT_FINDINGS.md

## Audit batch: tests-b (sections 4-7)

- Files: `tests/section4.rs` (958 lines), `tests/section5.rs` (524), `tests/section6.rs` (1969), `tests/section7.rs` (517)
- Date: 2026-08-15
- Method: every line read in order; clippy whole-crate run; per-file `cargo test` runs.

---

## [CRITICAL] t7_3 "reference frame hash" is a copy of the implementation, SSIM asserted against a hardcoded stub

- File: tests/section7.rs:11-26, 442-446
- Description: `render_scene` (src/gfx.rs:2703-2722) never renders a frame: it builds a string from scene fields, hashes it, and returns hardcoded `ssim: 1.0` and empty `validation_errors`. `reference_frame_hash` in the test reproduces the implementation's exact signature format string (`"{}|{:?}|{:02x}{:02x}{:02x}{:02x}|{}|{}|{:?}"`) including the engine's own `format_mapping(...).strategy` — i.e. the "independent reference" is a copy-paste of the implementation, not an oracle. The test then asserts `artifact.ssim ≈ 1.0`, which is true only because the implementation hardcodes `ssim: 1.0`. On the graphics rendering critical path, this gives false confidence: any implementation that computes any hash over the same fields and returns 1.0 passes, including one that renders nothing at all (which is exactly the current state).
- Fix suggestion: render an actual frame (e.g., via the command-list execution path or a software rasterizer) and compare pixels/hashes against a genuinely independent computation; assert SSIM against a reference frame comparison, not against the constant 1.0; drop `reference_frame_hash` or base it on independently computed fields only (no engine functions).

## [HIGH] t6_23 "shader_table_parsing" never checks any parsed shader-table data

- File: tests/section6.rs:1879-1924
- Description: All three sub-cases assert only `is_ok()` on `dispatch_rays`. Nothing verifies the raygen/miss/hit-group start addresses, sizes, strides, or width/height/depth are parsed or stored anywhere. The implementation returns `Ok(())` early for zero raygen address and zero dimensions (src/d3d12.rs:1391-1396) and otherwise records the desc without any validation; an implementation that discards the entire desc and returns Ok passes this test. The test name promises "shader table parsing" verification that never happens. Additionally, the "no raygen shader accepted as no-op" expectation enshrines an early-return stub behavior rather than real D3D12 semantics (DispatchRays without a raygen shader is invalid).
- Fix suggestion: after a non-trivial dispatch, assert the recorded command contains the exact shader-table addresses/sizes/strides and dimensions (e.g., via the closed command list or execution plan); add negative tests for out-of-bounds/inconsistent tables.

## [MEDIUM] t5_2 overlapped READ content is never verified

- File: tests/section5.rs:141-150
- Description: `read_file_overlapped(file, 4, 2)` is only checked via `assert_eq!(get_overlapped_result(read.id), read)` — comparing the bookkeeping record against itself. The 4 bytes read from offset 2 (should be `b"XYZf"` given the earlier overlapped writes) are never asserted. A buggy read returning wrong data passes. (The test name also claims "randomized" though nothing is randomized.)
- Fix suggestion: assert the returned read buffer equals the expected bytes (`b"XYZf"`), and assert the overlapped result's `bytes_transferred`.

## [MEDIUM] t5_4 toolhelp module enumeration asserted by exact hardcoded list

- File: tests/section5.rs:418-431
- Description: `assert_eq!(normalized_modules, vec!["C:\\Program Files\\Game\\snapshot.exe", "kernel32.dll", "ntdll.dll"])` is an exact-match against a hardcoded enumeration. Any legitimate addition to the mock's module list (e.g., `user32.dll`, the executable's own image on a different loader layout) breaks the test. The filter `entry.process_id != std::process::id()` also silently discards whatever modules the mock attributes to the host PID, so the assertion can pass while the host-process modules (which the mock does enumerate) are wrong.
- Fix suggestion: assert membership (contains) for the expected modules and exact count only if the enumeration contract is intentionally closed; keep the host-filter assertion separate and explicit.

## [MEDIUM] t6_24 feature-query portion contains zero assertions

- File: tests/section6.rs:1932-1945
- Description: `let _raytracing_supported = caps.raytracing;`, `let _ = raytracing_available;`, `let _ = mesh_available;` — the "feature query" half of the test discards every result. Only the PSO storage part (dxil bytecode, unknown pointer → None) is actually asserted. A query returning wrong values passes.
- Fix suggestion: assert raytracing/mesh capability booleans against the adapter's metal family (or the profile used to build the backend), e.g., `assert_eq!(raytracing_available, caps.raytracing)` with a pinned expectation.

## [MEDIUM] t6_10 root constants binding never verified

- File: tests/section6.rs:1077-1085
- Description: After `record_set_root_constants(list, vec![1..8])`, the only assertion is `stored.root_constants == 8`, a getter round-trip of the desc that was already known. Nothing checks that the constants were recorded on the list; the implementation pushes `Command::SetRootConstants { values }` with no validation against the root signature (src/gfx.rs:1957-1966), so an implementation that drops the values and returns Ok passes. (Contrast with t7_2, which correctly asserts `closed.commands[0]` and `plan.root_constants_log`.)
- Fix suggestion: assert the recorded command values, and add a negative case (more constants than the root signature allows → error).

## [MEDIUM] t6_20 test name contradicts its own assertion (zero-dim dispatch)

- File: tests/section6.rs:1713-1726
- Description: Named `mesh_dispatch_zero_dimensions_is_noop`, it asserts `plan.render_passes[0].draw_calls == 1` — the opposite of a no-op. `record_dispatch_mesh` (src/gfx.rs:2054-2065) unconditionally pushes `Command::DispatchMesh`, and execution counts it as a draw, so the test enshrines that a 0×0×0 dispatch still registers a draw call; a buggy emulator that miscounts mesh dispatches passes. Either the assertion is wrong (a no-op should add no draw) or the name is wrong.
- Fix suggestion: decide the intended semantics: assert `draw_calls == 0` (or no render pass) for a zero-size dispatch, or rename the test and assert the dispatched command explicitly.

## [MEDIUM] t6_17 GenericRead bitmask deviates from D3D12 and the "combined bits" case is not independent

- File: tests/section6.rs:1496-1537
- Description: The expected value for `ResourceState::GenericRead` is `0x0AC3`, but the D3D12 spec value is `0xFFF` (VB|IB|RTV|SRV|UAV|DS_READ|NPSR|PSR|SO|IA|CD|CS). The "combined bits" check at lines 1531-1537 re-uses exactly the same `0xAC3` pattern as the single-state case, so it never exercises decoding of an independent combination (e.g., 0xFFF or RT|SRV|SO). Because `to_d3d12_bits` and `from_d3d12_bits` are only round-trip tested against each other, symmetric encode/decode bugs (or a nonstandard constant) go undetected.
- Fix suggestion: pin `GenericRead` to the spec value 0xFFF (or justify the deviation), and test `from_d3d12_bits` with bit patterns not produced by any single state.

## [MEDIUM] t7_4 asserts the Metal validation gate's hardcoded empty result

- File: tests/section7.rs:450-477
- Description: `render_scene` returns `validation_errors: Vec::new()` unconditionally (src/gfx.rs:2717-2721) — the Metal validation gate is never invoked. The test asserting `validation_errors.is_empty()` therefore passes regardless of whether validation would catch anything; a broken validation gate reports zero errors and the suite stays green.
- Fix suggestion: introduce a validation path that actually inspects the recorded command list/plan (barrier order, descriptor ranges, render-pass actions) and feed both valid and intentionally invalid scenes; assert errors are found for invalid scenes.

## [MEDIUM] t7_1 adapter vendor/device assertions depend on the host GPU

- File: tests/section7.rs:31-32
- Description: `GraphicsBackend::new()` builds the adapter from the real host GPU (`detected_host_gpu_profile`, src/gfx.rs:1186-1187, 3294-3305). `assert_eq!(backend.adapter().vendor_id, 0x106b)` only holds on Apple-GPU hosts; on Intel Macs or NVIDIA/AMD eGPU machines the vendor is 0x10de/0x1002 and the test fails. This is machine-state dependence for assertions that are not the point of the test.
- Fix suggestion: construct the backend with an explicit pinned profile (`GraphicsBackend::with_host_profile(host_gpu_profile_from_name("Apple M3 Pro"))`) or drop the adapter assertions to environment-agnostic ones.

## [MEDIUM] t7_5 "frame times stable" asserts a constant equals itself

- File: tests/section7.rs:506-516
- Description: `frame_time_us` is a pure function of `sync_interval` (16_666 µs for sync=1, src/gfx.rs:1390-1393), so all 512 frames have identical times and `assert_eq!(min, max)` is trivially true — it would also pass if the frame time were 10 seconds. The soak loop does not exercise timing, boundedness, or leaks beyond `live_resource_count == 2`.
- Fix suggestion: assert `frame_time_us == 16_666` (pinning the value) or, if real timing is intended, use a range assertion; keep the live-resource leak check but add cycle/allocator counters if the goal is soak behavior.

## [LOW] t4_7 random-sequence test never compares the ordering log

- File: tests/section4.rs:337-340
- Description: Both the engine and the in-file reference produce an `ordering_log`, but the test only compares `memory_hash` and `flags`; barrier/atomic ordering regressions would go unnoticed (the dedicated atomic test does compare the log, but only for the fixed sequence).
- Fix suggestion: also assert `summary.ordering_log == expected.ordering_log` in the randomized loop.

## [LOW] t4_7 JIT assertion matches on generated assembly text

- File: tests/section4.rs:360-366
- Description: `promoted.arm64.instructions.iter().any(|line| line.contains("movz"))` is brittle to legitimate codegen changes (e.g., materializing 0x11223344 via movk/orr sequences). It would also pass if any unrelated instruction line happened to contain "movz".
- Fix suggestion: assert on the translated IR/opcode representation rather than assembly text, or pin the whole assembly snippet.

## [LOW] t5_1 "independent" file-information reference pins unpopulated placeholder fields

- File: tests/section5.rs:55-61, 510-523
- Description: `independent_file_information` hand-builds a struct with zero timestamps and empty attributes. The assertion passes only because the implementation does not populate creation/access/write times or attributes; if the shim is made more correct (real timestamps), the test breaks — the "reference" is not an independent oracle, just a mirror of the placeholder state.
- Fix suggestion: compute expected timestamps from the host filesystem (`metadata().created()`/`modified()`) or assert only the fields the contract guarantees (path/size/is_directory).

## [LOW] t5_3 environment-block and inherited-handle assertions are weak/tautological

- File: tests/section5.rs:204-216
- Description: `process.environment_block_utf16 == environment_block` compares the engine's output against the same public `build_environment_block_utf16` the engine uses — tautological. `inherited_handles.len() == 1` is an exact count that breaks if the engine inherits standard handles by default.
- Fix suggestion: assert the block decodes back to the input map (round-trip through a real parser) and assert inherited handles by predicate (contains the event) rather than exact length.

## [LOW] t6_4 xinput assertions accept arbitrary garbage

- File: tests/section6.rs:606-623
- Description: `packet_number >= 1`, `!state.buttons.is_empty()`, `xinput_get_keystroke().is_some()`, and a discarded `xinput_get_battery_information` result would all pass for a buggy implementation returning any non-empty values; the battery result (`let _ = ...`) is never asserted.
- Fix suggestion: assert concrete values: packet number matches the attach sequence, buttons contain "A"/"Start" (etc.), battery level matches the spec (100/87/100), and keystroke contents match the injected buttons.

## [LOW] t6_8 root-signature round-trip is storage-only and internally inconsistent

- File: tests/section6.rs:892-946
- Description: `descriptor_tables: vec![2, 3, 1]` does not correspond to the three `parameters` (only one actual descriptor table); the test asserts the inconsistent field round-trips verbatim, which verifies storage, not root-signature semantics.
- Fix suggestion: derive `descriptor_tables` from the parameters and assert the derived value, or remove the redundant field from the test data.

## [LOW] t6_16 visibility-flags test is a pure getter round-trip

- File: tests/section6.rs:1478-1487
- Description: `visibility_offsets` just returns the stored `BTreeMap` (including the empty-slice case for Hull), so the test can only fail if storage is broken — it cannot detect wrong visibility semantics.
- Fix suggestion: exercise the offset computation through `root_signature_desc` after a create/round-trip, or add assertions that offsets are derived from parameter visibility when not supplied.

## [LOW] t7_1 MeshShaders assertion is self-referential

- File: tests/section7.rs:38-41
- Description: `query_feature(MeshShaders) == (metal_family != "apple7" && metal_family != "apple8")` derives both sides from the same `family` value (capabilities.mesh_shaders = family >= 9, metal_family = "apple{family}", src/gfx.rs:3310-3325), so a wrong family computation would still satisfy the equation.
- Fix suggestion: assert against a pinned profile (e.g., apple9 → true, apple8 → false) using `with_host_profile`.

---

## Clippy

Command: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt`

- No warnings or errors reference `tests/section4.rs`, `tests/section5.rs`, `tests/section6.rs`, or `tests/section7.rs`.
- The clippy run itself failed to compile the crate due to 27 pre-existing `src/*` errors (deny-level clippy lints such as `not_unsafe_ptr_arg_deref` in src/mac_window.rs, `approx_constant` in src/steam_* / src/video*, `uninit_vec`, `logic_bug`, etc.) plus 1415 warnings — all outside the audited files. The test binaries therefore were not built by clippy; they were built and run by `cargo test` (rustc) without issue.

## Test results

| File | Passed | Failed | Notes |
|---|---|---|---|
| tests/section4.rs | 8 | 3 | see below |
| tests/section5.rs | 6 | 0 | |
| tests/section6.rs | 17 | 0 (run aborted) | 7 user32 tests HUNG (see below) |
| tests/section7.rs | 5 | 1 | see below |

### section4 — failing tests
- `random_sequences_vs_independent_reference_and_tiered_cache` — engine `execute_ir_with_memory_hash` returns empty memory_hash `""` vs reference hash `88c81a7e...` (tests/section4.rs:338).
- `instruction_vectors_vs_independent_reference_exact_flags_fp_and_cpuid` — same empty vs `0ab2b8f9...` (tests/section4.rs:224).
- `atomic_torture_and_barrier_ordering_match_reference_hash` — same empty vs `99ff6795...` (tests/section4.rs:416).

These are legitimate test failures, not test faults: the independent in-file references compute a real SHA-256 over memory while the engine's `execute_ir_with_memory_hash` returns `""` — the tests correctly detect an unimplemented memory-hash feature.

### section6 — hang
- `t6_1` through `t6_7` (all 7 user32 tests) hang indefinitely after the 17 D3D12 tests complete (~0.01 s); the test process stays in `S` state at 0% CPU. Common factor: every hung test calls `create_window_ex_w`, which touches real NSWindow creation (`mac_window`) off the main thread; the D3D12-only tests complete. Recorded per instructions (>15 min: 15:56) and terminated; the run was killed before producing a final result line.

### section7 — failing test
- `t7_1_dxgi_swapchain_oracle_suite_matches_expected_present_resize_and_latency_behavior` — panicked at tests/section7.rs:32: `backend.adapter().device_id >= 0x1000` failed. Root cause is the host-GPU-derived adapter (src/gfx.rs:1186-1187): on this Apple M5 Pro the Apple-family device IDs are 0x0007–0x000B (src/gfx.rs:271-277), all < 0x1000, so the expectation is wrong for most Apple Silicon hosts. This is the failure of the brittle expectation flagged in finding [MEDIUM] t7_1, not a swapchain-behavior regression (the vend/`vendor_id == 0x106b` check passed, and all other 5 tests passed).
