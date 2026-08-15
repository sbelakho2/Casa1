# AUDIT_FINDINGS.md

- **Batch:** Casa1 test-suite audit — batch 2 (audit-tests-de-2 worktree)
- **Files audited:** `tests/section14.rs` (126 lines), `tests/section15.rs` (170), `tests/section16.rs` (622), `tests/section17.rs` (405), `tests/section18.rs` (443), `tests/section19.rs` (469), `tests/section20.rs` (571), `tests/section21.rs` (557), `tests/section22.rs` (834), `tests/section23.rs` (898), `tests/section24.rs` (638), `tests/section25.rs` (1502), `tests/global_invariants.rs` (347). Every line of every file was read in full.
- **Date:** 2026-08-15
- **Auditor note:** Implementation cross-checks (`src/vkgl.rs`, `src/media.rs`, `src/shader.rs`, `src/win32.rs`, `src/security.rs`, `src/diagnostics.rs`) were performed to verify suspected circular/tautological test logic before classifying severity.

---

## [CRITICAL] "Windows reference" hashes are self-referential — rendering tests validate the implementation against itself

- File: tests/section14.rs:7-25, 54, 72
- Description: `t14_1_vulkan_loader_runs_sample_and_matches_windows_reference_hash` and `t14_2_opengl_sample_matches_windows_reference_hash` claim to match a "Windows reference hash", but the expected hash is computed in the test from the *same* inputs and the *same format string* the implementation hashes (`src/vkgl.rs:172-184` computes `sha256("vk|VulkanOnMetal|1.3.280|{name}|{draw_calls}|{compute_dispatches}|{clear_color:?}")`; the test's `expected_vulkan_hash` is byte-for-byte the same expression). There is no actual Windows reference value anywhere. Any stub that formats the sample struct and hashes it — with zero rendering — passes. Compounding this, `frame.ssim == 1.0` is asserted, and the implementation hardcodes `ssim: 1.0` (`src/vkgl.rs:184`), so the "SSIM" assertion is also circular. This gives false confidence on the core Vulkan/Metal graphics path.
- Fix suggestion: Remove the local recomputation and pin real golden values captured from a known-good Windows/D3D run (or from a verified reference renderer). Assert on actual rendered pixel content, not on a hash of the input parameters. Drop or make meaningful the `ssim == 1.0` assertion (e.g. render two known frames and compare).

## [CRITICAL] Media "golden" hashes/CRC/drift are self-referential and the tests are all `#[ignore]`d

- File: tests/section15.rs:8-29, 64-71, 76-80, 87-101
- Description: `t15_1`/`t15_2` replicate the implementation's own synthetic formulas instead of Windows reference data: `expected_frame_hashes` mirrors `decode_golden_clip` (`src/media.rs:3402-3417`), `expected_audio_crc` is an exact copy of `synthesize_audio_samples` (`src/media.rs:3492-3502`), and `t15_2`'s `expected_drift` is the test's copy of `measure_av_drift_ms` (`src/media.rs:3426-3433`). All three pass on any implementation that replays the same formulas, with no real decode/playback occurring. Additionally all three tests are `#[ignore]`d ("requires real GPU/audio hardware"), so even this circular coverage never runs in CI.
- Fix suggestion: Pin hashes/CRC/drift captured from a real Windows playback reference, or restructure the code so the expected values are not derived from the same helper formulas the implementation uses. If the tests genuinely need GPU/audio hardware, keep them ignored but document the gap; the self-referential assertions should still be replaced with fixture-based values.

## [HIGH] Tautological assertions in GNS networking tests — can never fail

- File: tests/section25.rs:1283-1286, 1362-1365, 1374-1377, 1409-1410
- Description: `t25_18`, `t25_20`, and `t25_21` contain assertions of the form `assert!(send_result.is_ok() || send_result.is_err(), ...)` — a Rust `Result` is always one of these, so the assertion is provably true and can never fail. `t25_20` is named "encryption/decryption round-trip" but never decrypts or verifies anything: it sends and then accepts `messages.is_empty() || messages.len() == 1` (any outcome except ≥2). `t25_21` "session key generation" admits it cannot inspect keys and asserts only handle-uniqueness plus the same tautologies. These tests pass on any implementation, including one that performs no encryption at all.
- Fix suggestion: Replace tautologies with real behavioral checks: verify encrypted bytes differ from plaintext, decrypt and compare, assert deterministic queue contents, and expose/inspect the session keys (or test `SessionCipher` directly, as `t25_02` already does well).

---

## [HIGH] Section24 smoke tests contain no assertions — guest crashes pass

- File: tests/section24.rs:161-176, 189-203, 215-228, 242-255, 268-280, 293-306, 319-331, 344-357, 370-382, 395-407, 420-432, 445-457, 470-483, 496-508, 579-638
- Description: All 14 per-DLL smoke tests (`t24_01..t24_14` `*_smoke`) and `t24_16_kernel32_key_functions` are pure `eprintln!` scripts with zero assertions. Comments claim to "verify execution doesn't crash during user32 dispatch" etc., but `guest_exceptions` and `exit_code` are only printed, never asserted; the only failure mode is `execute_with_options` returning `Err`. A runtime that throws guest exceptions on every thunk dispatch and exits non-zero still passes every smoke test. `t24_16` even prints "We don't assert specific counts" and merely warns if no trace events were captured.
- Fix suggestion: Assert `result.guest_exceptions.is_empty()`, assert non-zero trace coverage (e.g. expected thunk call-ids present), and fail on unexpected non-zero `exit_code` (or assert a documented expected code).

## [HIGH] `require_steam_ge()` fails instead of skipping — whole section24 file depends on machine state

- File: tests/section24.rs:39-58
- Description: The module doc says tests "will be skipped at runtime with a clear message" when the Steam GE is absent, and the helper comment says the same, but `require_steam_ge()` calls `panic!("SKIP: ...")` — a panic is a test FAILURE, not a skip. None of the 30 tests are `#[ignore]`d, and the path `ges/steam-live-run-x86` is a hardcoded relative path resolved against the process CWD. On any CI machine without the Steam GE (or without the workspace CWD), all 30 tests fail — the opposite of the documented intent. (The `ges/steam-live-run-x86` directory is not present in this worktree.)
- Fix suggestion: Use a real skip mechanism (e.g. `eprintln!` + `return`, or `#[ignore]` with a runtime guard) so the suite is green-but-skipped without the GE; resolve the GE root via `CARGO_MANIFEST_DIR`/env var instead of the relative CWD.

## [HIGH] t16_8 asserts a wrong structured-buffer stride and never checks field offsets

- File: tests/section16.rs:620-621 (and 602-605)
- Description: `t16_8_cbuffer_and_structured_packing` asserts `packing.stride == 20` for a `pos`(12 B, align 4) + `uv`(8 B, align 4) struct, but `pack_structured_fields` aligns the total stride to 16 (`src/shader.rs:3947`: `align_up(offset, 16)`), yielding 32. The test FAILS against the current implementation; the expected value 20 is naive no-alignment math and is wrong for a Metal-targeted structured buffer. Separately, the cbuffer half of the test only asserts field names survive (`packed.fields[0].name == "offsetA"`), never the offsets/sizes that `pack_cbuffer` computes — the actual packing logic is untested.
- Fix suggestion: Compute the expected stride per the documented alignment rule (16-byte stride → 32) or drop the hardcoded constant and assert per-field offsets/sizes against hand-computed D3D packing values; add negative/alignment cases (vec3+vec4, arrays, matrices).

## [HIGH] t18_2 enshrines stub behavior — `max_instances` is hardcoded to 1 in the implementation

- File: tests/section18.rs:87-95 (request 5 instances at line 78; assert `max_instances == 1` at line 92)
- Description: `get_named_pipe_info` returns `(1, 1, max_size, max_size)` with `max_instances` hardcoded to 1 (`src/win32.rs:2930-2931`) regardless of the 5 requested via `create_named_pipe_w`. The test asserts 1, thereby blessing a real compatibility bug: the requested instance count is silently ignored, and on actual Windows `GetNamedPipeInfo` returns the configured value. The test validates the stub instead of the contract. The same function also returns identical `out_buffer_size`/`in_buffer_size` (both `max_size`), and the test's comment acknowledges this non-Windows normalization and asserts it (lines 93-95).
- Fix suggestion: Have the implementation store and return the requested `max_instances` (and per-direction buffer sizes), and assert those values; keep the test as the guard that catches this class of bug.

## [HIGH] t16_7 "GLSL translation errors" contains no error-path assertions

- File: tests/section16.rs:547-573
- Description: Despite the name, every assertion expects success: empty source `assert!(result.is_ok())`, a basic VS, a basic FS, and a uniform shader. No invalid GLSL (bad syntax, unsupported stage, bad intrinsic, oversized source) is ever fed to `GlslToMslTranslator`. A translator that accepts everything (or wraps everything in a fixed template) passes.
- Fix suggestion: Feed genuinely invalid inputs and assert `Err` with the expected reason code, and assert on emitted MSL content (not just `is_ok`) for the valid cases.

---

## [MEDIUM] t20_6 cache-miss assertion is a near-tautology

- File: tests/section20.rs:293-311
- Description: `stats1.misses >= 1 || stats1.hits == 0` ("first compile should miss") is satisfied by a cache that counts hits and misses simultaneously, or one that never records anything — the miss is not actually required. The subsequent `stats2.hits >= 1` is the only real check.
- Fix suggestion: Assert `stats1.hits == 0 && stats1.misses == 1` exactly.

## [MEDIUM] t20_7 cache-eviction test passes on a no-op cache

- File: tests/section20.rs:318-344
- Description: After inserting 10 entries into a 4000-byte cache the test asserts `total_size <= 4500` and `len() < 10`. A cache that stores nothing (len 0, size 0) passes both. Nothing verifies the eviction policy (oldest evicted, size accounting, re-insertion).
- Fix suggestion: Insert entries, assert they are retrievable while resident, then force eviction and assert the oldest (not the newest) is gone; assert `len() > 0` so a no-op cache fails.

## [MEDIUM] CEF/WKWebView tests pass vacuously whenever initialization fails

- File: tests/section19.rs:18-27, 35, 64, 110, 151, 189, 234, 276, 344, 391-398; tests/section17.rs:327-337
- Description: `init_cef()` returns `None` on ANY `cef_initialize` failure, and every `t19_*` test then `return`s immediately, passing with zero assertions executed. `t19_10` also silently accepts `create_webview` returning `Err`. The stated intent is to skip in headless CI, but the mechanism cannot distinguish "headless environment" from "CEF bridge is completely broken" — if `cef_initialize` regresses, the entire CEF suite (10+ tests) still reports green. `t17_7` duplicates this pattern (and duplicates t19_1/t19_2's browser-creation coverage).
- Fix suggestion: Gate on an explicit capability probe (e.g. `WKWebViewManager::is_available()`) instead of the init result, or `#[ignore]` these tests in headless environments via an env var; at minimum, keep at least one test that fails when init fails outside a marked headless environment.

## [MEDIUM] t19_4 JS-execution assertion accepts a no-op engine

- File: tests/section19.rs:169-178
- Description: `assert!(result.is_empty() || result == "2")` passes when the executor returns nothing at all — the common case in the simulated mode. Only a non-empty, non-"2" result fails. The "1+1" evaluation is effectively untested.
- Fix suggestion: In simulated mode, assert the documented simulated result exactly; if a real JS engine is available, execute and assert the actual computed value.

## [MEDIUM] t23_4 asserts the runtime's self-reported trace events

- File: tests/section23.rs:498-570
- Description: `t23_4_steam_regression` verifies "no SteamZeroRecord event" and "SteamRecordTablePostExec `table_populated=true`" — both events are emitted by the same runtime under test. A buggy runtime that reports `table_populated=true` without populating anything (or stops emitting the workaround event) passes. The check is self-verification, not an independent invariant. (Also `#[ignore]`d, like all of section23.)
- Fix suggestion: Read the record table directly from guest memory (e.g. via `MemoryImage` after execution) and assert the global at `0x42a270` has non-zero entries, independent of trace-event claims.

## [MEDIUM] Print-only diagnostics pass on any implementation

- File: tests/section23.rs:285-362 (t23_2), 594-872 (t23_5), 71-278 (t23_1)
- Description: `t23_2_steam_import_coverage` has zero assertions; `t23_5_x86_decode_coverage` states outright that it "does not assert anything" and only prints a report. `t23_1`'s only assertion is that at least one trace event exists. These can never fail and provide no regression protection; worse, they are `#[ignore]`d so they are not even run as diagnostics.
- Fix suggestion: Add real assertions (e.g. min import-coverage %, zero decode errors on known sections, expected opcode set) or convert these to non-test binaries/documentation tools.

## [MEDIUM] Shader translation tests only check template text, not translation output

- File: tests/section20.rs:125-279 (t20_1..t20_5), 480-502 (t20_pack_cbuffer_matrix)
- Description: The "full translation" tests assert only that the emitted MSL contains `"vertex"`/`"fragment"`/`"kernel"`/`"ps"`/`"cs_"` substrings. `t20_4` asserts `msl.contains("ps")` — a substring that matches almost anything. Any implementation that wraps the input in a generic stage-tagged template passes, and the synthetic DXIL contains no real LLVM bitcode, so no instruction translation is exercised. `t20_pack_cbuffer_matrix` asserts only `size_bytes >= 32` with no offsets.
- Fix suggestion: Build real (or at least instruction-bearing) DXIL bitcode and assert on generated MSL statements; test cbuffer offsets against hand-computed D3D packing values.

## [MEDIUM] t22_5 "steamstub_decrypt" never exercises decryption

- File: tests/section22.rs:292-351
- Description: The test builds a mock PE with a `STUB` header and an XOR-encrypted code section, then calls `detect_steamstub` and asserts header fields — but no decrypt call is ever made and the decrypted code bytes are never verified. The critical decrypt path (the point of the test name) is untested; a decrypter that returns garbage passes.
- Fix suggestion: Call the decrypt/emulator path and assert the decrypted section equals the original `i ^ 0xAB` payload, plus test a wrong-key failure.

## [MEDIUM] t22_3 asserts values the test itself constructed

- File: tests/section22.rs:209-210
- Description: `assert_eq!(sample.name, "triangle_test")` and `assert_eq!(sample.draw_calls, 1)` re-assert the literals written into the struct two lines earlier; they can only fail if the literal and the assertion disagree (a typo). The remainder of the test only checks `supported`/backend flags.
- Fix suggestion: Delete the self-assertions; assert behavior (render the sample, validate state/lifecycle) instead.

## [MEDIUM] t19_3 navigation-history test is one-sided

- File: tests/section19.rs:108-143
- Description: It asserts only that `go_back` fails when there is no history. It never loads a second page and verifies `can_go_back` becomes true, never tests `go_forward`, and never verifies the current-URL/history list after navigation — the "navigation history" feature is untested.
- Fix suggestion: After `cef_frame_load_url`, assert back/forward capability flips and that a subsequent `go_back` succeeds and restores the previous URL.

## [MEDIUM] t16_5 shader-binding test: trivial self-assertion and never exercises the bindless path

- File: tests/section16.rs:444-475
- Description: `assert_eq!(plan.constant_buffer_size, 32)` asserts the value written into the freshly constructed `RootConstantsPlan` (self-referential, cannot fail). `assert!(!bufs[0].bindless_indirection)` is annotated "count > 64" but the test only uses counts 1-2, so the bindless branch is never constructed or asserted.
- Fix suggestion: Test with >64 descriptors to exercise `bindless_indirection`, and drop the constructed-constant assertion or verify it against the root-signature bytes.

## [MEDIUM] t25_01/t25_11/t25_12 skip their assertions when no CM server is reachable

- File: tests/section25.rs:34-39, 47-54, 864-868, 931-935
- Description: The "connect-dependent" tests `return` early on `connect(None)` failure, which means on any machine without Steam CM reachability the entire test body after the first `connect` silently passes with nothing asserted. The skip is intentional and documented, but it makes the connect/handshake/heartbeat paths effectively untested in most environments (including CI).
- Fix suggestion: Split deterministic in-memory assertions (which can run regardless) from network-dependent ones; assert the deterministic parts unconditionally, and use `#[ignore]` or a marked env var for the network parts instead of silently passing.

## [MEDIUM] i5_1 soak gate relies on noisy `ps` RSS measurement

- File: tests/global_invariants.rs:116-180
- Description: `growth_percent < 5.0` is computed from `ps -o rss=` of the test process. RSS on macOS is noisy (allocator arenas, page-cache, parallel test threads, other cargo activity), so a <5% bound on a process that also runs the rest of the test binary can flake on loaded machines. The 256-iteration warmup mitigates but does not eliminate this. `assert_eq!(backend.live_resource_count(), 2)` also couples the test to the swapchain's internal backbuffer accounting (2 buffers).
- Fix suggestion: Track allocations via an injected allocator/accounting hook instead of RSS; or assert a looser bound with retries; decouple the live-resource expectation from swapchain internals (assert `<= 2` plus a delta-based check).

## [MEDIUM] t18_9 claims security-descriptor verification but verifies nothing

- File: tests/section18.rs:375-402
- Description: The comment says "Verify the pipe was created (the security descriptor pointer is stored internally)", but no assertion inspects the descriptor; the test only checks that the pipe still connects. `Some(0xDEADBEEF)` is a fake pointer that is never validated to be stored or applied.
- Fix suggestion: Expose the stored descriptor (or a query API) and assert it round-trips; otherwise rename the test to reflect what it actually checks.

---

## [LOW] Behavioral verifier tests only its own bookkeeping

- File: tests/section22.rs:671-715
- Description: `t22_11` feeds the verifier steps that are marked passed and asserts they were recorded as passed (`9/9`). No failing step, no `begin_step` without `end_step`, and no negative summary path are tested; a verifier that always returns success passes.
- Fix suggestion: Add a case with `end_step(.., false, ..)` asserting `all_passed()` is false and the summary reflects the failure.

## [LOW] t22_12 end-to-end test duplicates section21 coverage

- File: tests/section22.rs:721-834
- Description: The D3D12 E2E flow (swapchain → RTV → root sig → PSO → record → execute → present) is nearly identical to `t21_4`/`t21_10` in section21 (render-pass count, draw-call count, fence value, sync interval). The extra verifier/stress segments are self-checks of the same classes as t22_11/t22_10.
- Fix suggestion: Keep the E2E test but vary the assertions (e.g. verify present advances the frame index, backbuffer contents change after clear), reducing duplication.

## [LOW] Named-pipe round-trip is tested three+ times across files

- File: tests/section17.rs:146-184 (t17_3); tests/section18.rs:17-62 (t18_1), 321-369 (t18_8), 408-443 (t18_10)
- Description: `t17_3` and `t18_1` are the same server→client→server round-trip on the same simulated pipe implementation; `t18_8`/`t18_10` re-exercise the same path with slightly different call sequences. Maintenance and failure triage are duplicated.
- Fix suggestion: Keep one canonical round-trip test and make the others assert distinct behaviors (peek semantics, disconnect/reconnect, security descriptor).

## [LOW] t17_5/t17_8 test only default config values, not the named behaviors

- File: tests/section17.rs:250-270 (t17_5), 379-405 (t17_8)
- Description: `t17_5_steam_service_registration` never registers a service — it asserts `ScmConfig::default()` fields (`cpu_count == 4`, `memory_mb == 4096`, `enabled == false`). `t17_8_steam_network_initialization` never initializes the network — it asserts initial enum values of a fresh `SteamProtocolStack`. Both would pass with the config/state structs completely inert.
- Fix suggestion: Exercise the actual registration/init APIs (create service, verify state transitions; perform a connect attempt and assert state machine moves), or rename tests to "defaults".

## [LOW] Weak one-liner assertions

- File: tests/section20.rs:457-461 (`t20_shader_cache_compute_key_sha256` asserts only 64 hex chars), 538-571 (`t20_dxil_opcode_*` assert only operator-char presence `-`, `*`, `&`, `==`, `!=`, covering 5 of dozens of opcodes), 463-468 (`t20_root_signature_empty` — fine), 478-502 (duplicates t16_8's cbuffer weakness)
- Description: These verify format trivia rather than semantics (e.g. the opcode tests never check operand order, result naming, or type handling). A wrong operator mapping that happens to contain the expected character passes.
- Fix suggestion: Assert full generated statements (e.g. `_r = a - b;`) and expand opcode coverage; pin known cache-key values rather than length.

## [LOW] t25_14 re-tests URL-parsing cases already covered by t25_08

- File: tests/section25.rs:1084-1165
- Description: `steam://friends/`, `steam://friends`, `steam://friends/add/...` and the `https://` rejection cases are exact duplicates of `t25_08` lines 637-653 and 701-704.
- Fix suggestion: Merge the extra cases (`open/friends`, query params) into `t25_08` and delete the duplicate test.

## [LOW] Duplicate test-name prefixes (`t16_1_*` × 4) and duplicate dxil fixture assertion

- File: tests/section16.rs:77, 130, 148, 183; tests/section16.rs:537-541 vs 366-367
- Description: Four tests share the `t16_1_` prefix (entitlement audit), making test filters/names ambiguous; `t16_6`'s final fixture check (`fuzz_summary(...).starts_with("err:")`) duplicates the stricter `starts_with("err:2101:")` in `t16_4`.
- Fix suggestion: Renumber to unique `t16_1a..t16_1d` (or `t16_1_*` distinct suffix names), and drop the weaker duplicate assertion.

## [LOW] t15_3's error-path checks are sound but its "valid" inputs are self-built

- File: tests/section15.rs:104-170
- Description: `classify_input` asserts `Valid` for containers built with the test's own `build_container_bytes` — acceptable, but combined with the self-referential golden hashes above, the whole media file tests the implementation's own construction rules. `"/tmp/rogue/codec.dylib"` also hardcodes a POSIX path (works only on macOS/Unix hosts).
- Fix suggestion: Add real-world sample media bytes as fixtures (even truncated ones) and use `std::env::temp_dir()` for the rogue path.

## [LOW] t14_4 asserts implementation error-message wording

- File: tests/section14.rs:117-126
- Description: `assert!(vk.message.contains("vulkan-1.dll"))` / `contains("opengl32.dll")` couples the test to message strings; a rewording of the message breaks the test without any behavioral change.
- Fix suggestion: Assert only `ReasonCode` and keep message-content checks as hints, or assert on a stable hint key.

## [PERF] Section24 smoke tests are pathologically slow (15 × full Steam.exe emulation)

- File: tests/section24.rs:101-121, 161-508, 579-638
- Description: Each `*_smoke` test executes Steam.exe under the PE runtime with budgets of 200K-1M instructions in DTM mode; observed wall time was >60s per test and growing (the first full run was aborted after 16 tests finished and 15 tests had each exceeded 60s; a second run likewise exceeded 15 minutes cumulatively). The full file is not practical to run in CI.
- Fix suggestion: Consolidate into one smoke run (single execution shared across DLL checks via a test-suite-level once guard), reduce the budget, or move to a nightly-only marker; the tests also need real assertions (see the HIGH finding above) to be worth the cost.

## [MEDIUM] t16_1 embedded-entitlement tests fail on this machine (currently failing, environment-dependent)

- File: tests/section16.rs:148-181, 183-250
- Description: Both tests that sign a copy of the test binary with `/usr/bin/codesign` FAILED here: the audit reports `unexpected entitlement target: casa1-runner:missing_allow_jit` even though the copy was signed with `allow-jit` entitlements (ad-hoc signature). The tests depend on `codesign -d --entitlements :-` behavior of the host macOS version and on the signability of the copied binary; they also only run on macOS (the non-macOS guard is a silent `return`, not a skip). Either the entitlement-extraction path in `audit_embedded_entitlements` (`src/security.rs:171-196`) has a bug (stderr fallback picks up non-entitlement output) or the environment differs — in either case the tests are currently red and give no signal about the code under test's logic.
- Fix suggestion: Diagnose the codesign extraction path (compare `codesign -d --entitlements :-` output directly); add a machine-state guard that skips only when codesign cannot sign, and fail otherwise. Non-macOS should skip explicitly rather than pass silently.

## [LOW] i5_2's final assertions re-check data the test itself constructed

- File: tests/global_invariants.rs:199-273
- Description: `crash_codes` is populated by the test itself with `ReasonCode::RcMemoryAccessViolation`, so `crash_codes.len() == 24` and `all(...)` re-assert what the loop just pushed (they cannot fail unless the loop body changes). The meaningful checks are the per-iteration ones (exit code 0, launch flags, validation errors, zip exists). Also `#[ignore]`d.
- Fix suggestion: Drop the redundant final assertions, or derive the expected code list from the simulated exceptions and compare.

---

## Clippy

- Command run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt`
- Result: clippy **failed to complete** — `casa1` (lib) fails with 19 lint-level errors and `casa1` (lib test) with 27 errors (all in `src/`, e.g. `src/pe_runtime.rs`, `src/cpu.rs`, `src/security.rs`, `src/diagnostics.rs`; 1415 warnings emitted). This is a pre-existing condition of the crate, out of this batch's scope.
- **No warnings or errors reference any of the assigned test files** (`tests/section14.rs` through `tests/section25.rs`, `tests/global_invariants.rs`) — zero hits when searching clippy output for these paths. The test files are clippy-clean; the crate's `--all-targets` clippy gate cannot be green until the src errors are fixed.
- Note: `tests/section20.rs` carries `#![allow(clippy::cloned_ref_to_slice_refs)]` and `tests/section23.rs` carries `#![allow(clippy::unnecessary_sort_by)]` / `#![allow(clippy::type_complexity)]` — file-level allows that suppress lints for the whole file rather than for the specific sites; prefer targeted `#[allow]` attributes.

## Test results

All runs: `CARGO_BUILD_JOBS=4 cargo test --test <stem>` (default filters; `#[ignore]`d tests excluded unless noted).

| File | Pass | Fail | Ignored | Notes |
|---|---|---|---|---|
| section14 | 4 | 0 | 0 | all pass |
| section15 | 0 | 0 | 3 | **entire file `#[ignore]`d** — nothing runs |
| section16 | 8 | 3 | 0 | see failures below |
| section17 | 8 | 0 | 0 | all pass |
| section18 | 10 | 0 | 0 | all pass |
| section19 | 10 | 0 | 0 | all pass (all skip-capable via `init_cef`) |
| section20 | 22 | 0 | 0 | all pass |
| section21 | 10 | 0 | 0 | all pass |
| section22 | 12 | 0 | 0 | all pass |
| section23 | 0 | 0 | 5 | **entire file `#[ignore]`d** (manual diagnostics) |
| section24 | 16 | 0 | 0 | 15 coverage tests + aggregate pass; **15 smoke tests + t24_16 exceeded 60s each and the run was aborted/hung** (>15 min cumulative; see PERF finding) |
| section25 | 24 | 0 | 0 | all pass (3 connect-dependent tests skip internally) |
| global_invariants | 5 | 0 | 1 | i5_2 ignored |

Failing tests (section16):

- `t16_1_embedded_entitlement_audit_reads_actual_signed_binaries` — FAILED: `assertion failed: report.approved`; embedded audit of a codesign-signed copy reports `casa1-runner:missing_allow_jit`.
- `t16_1_entitlement_audit_cli_enforces_signed_binary_set_end_to_end` — FAILED: macwin CLI exits non-zero with `RC_ENTITLEMENT_AUDIT_FAILED`, hint `unexpected entitlement target: casa1-runner:missing_allow_jit`.
- `t16_8_cbuffer_and_structured_packing` — FAILED: `assertion 'left == right' failed: left: 32, right: 20` (structured stride: implementation aligns to 16, test expects unaligned 20).

Hangs: `section24` smoke tests (`t24_01_kernel32_smoke` … `t24_14_wsock32_smoke`, `t24_16_kernel32_key_functions`) each ran >60 s (Steam.exe emulation with 200K-1M instruction budgets); a full run was not completed within the 15-minute hang allowance. Coverage tests in the same file complete in seconds.
# AUDIT_FINDINGS.md

## Batch: audit-tests-f-2 — Test-Suite Correctness Audit

**Files audited (every line read):**
- tests/section26.rs (1148 lines) — D3D11/D3D12 device, DXIL parser, MSL generation, Metal backend, Vulkan loader, gfx lifecycle, NTFS ADS
- tests/section27.rs (1682 lines) — diagnostics, SSIM/PSNR, BehavioralVerifier, StressTestRunner, Steam protocol dispatch, FramePacer, MSAA resolve
- tests/section28.rs (1048 lines) — DXR raytracing bridge (BLAS/TLAS, copy modes, postbuild info, DispatchRays, PSO)
- tests/section28_com.rs (1735 lines) — COM subsystem (CoCreateInstance, apartments, refcounting, IDispatch, BSTR, VARIANT, SAFEARRAY, GUID, functional objects)

**Date:** 2026-08-15

**Method:** Every line of the four files was read. Test expectations were cross-checked against the implementation (src/d3d12.rs, src/gfx.rs, src/shader.rs, src/shader_compiler.rs, src/diagnostics.rs, src/steam_protocol.rs, src/perf.rs, src/real_fs.rs, src/real_win32.rs, src/vkgl.rs, src/metal_backend.rs, src/d3d11.rs, src/ge.rs, src/canonical.rs). Whole-crate clippy run executed; all four test binaries compiled and ran.

---

## [CRITICAL] t27_08 asserts only tautologies while performing real network I/O to Steam CM servers

- File: tests/section27.rs:623-690 (tautologies at 632-635, 640-643, 647-650, 654-657, 661-664, 668-671)
- Description: Every assertion in this test is `assert!(x || !x)`, which is equivalent to `assert!(true)` for any boolean: `connected || !connected`, `logon_result || !logon_result`, `browse_result || !browse_result`, `download_result || !download_result`, `launch_result || !launch_result`, `workflow_result || !workflow_result`. The test passes on any implementation whatsoever, including one where every `run_*` method is a stub returning garbage. Worse, the test actually exercises the real network path: `run_connect_to_cm` → `SteamProtocolStack::connect(None)` performs DNS resolution and TCP connections to the real Steam CM servers `cm1..cm5.steampowered.com:27017` (src/steam_protocol.rs:112-118, 1842-1889, 10 s connect timeout each), and `run_send_logon` would attempt an encrypted logon with the literal credentials `"test_user"/"test_pass"` if a connection succeeds. This directly violates the project's own zero-touch policy: src/steam_protocol.rs:4487-4505 (`steam_zero_touch_default_servers_not_contacted`) states DEFAULT_CM_SERVERS "must never be resolved or connected to in unit tests" and gates live tests behind `STEAM_LIVE_TEST`. The test is machine/network-dependent (it passed here only because the connections failed fast; on a machine with a route to Steam it attempts authentication), can hang for minutes (5 servers × 10 s per connect × up to 6 calls), and gives false confidence on the critical Steam boot→login→workflow path. Note the `#![allow(clippy::overly_complex_bool_expr)]` at lines 1-2 was added to silence the lints this pattern produces.
- Fix suggestion: Gate the live-workflow calls behind `steam_live_tests_enabled()` (like the src unit tests) or delete them; replace the tautologies with real assertions on observable behavior, e.g. assert that each attempted step is recorded in `verifier.results` with the correct `BehavioralTestStep`, that a failed step carries the error string, and that `all_passed()`/`summary()` are consistent with the recorded results.

## [HIGH] t28_11 "RAYTRACING_TIER_1_1 feature level verification" contains no effective assertion

- File: tests/section28.rs:746-773
- Description: The test named for D3D12_RAYTRACING_TIER_1_1 verification asserts nothing on the common path. The first block is conditional (`if device_info.features.raytracing { assert!(argument_buffers || unified_memory) }` — a trivially-true property unrelated to tier verification that only runs when raytracing is already enabled). The second block is a literal no-op whose own comment says "Always true check - validates the caps struct is accessible": `if !device_info.adapter.name.is_empty() { let _ = caps.raytracing; }` discards the value. A build with raytracing entirely broken or feature detection always returning false would pass this test unchanged.
- Fix suggestion: Assert the actual contract, e.g. `device_info.features.raytracing == caps.raytracing`, assert tier-1.1 capabilities (raytracing implies argument buffers / unified memory on this backend), and assert a concrete observable: `build_raytracing_acceleration_structure` / `dispatch_rays` succeed only when the feature is reported — or drop the test name's tier claim and assert the constant plumbing directly.

---

## [MEDIUM] t26_10 "Vulkan Shader Compilation" verifies only hardcoded stub constants

- File: tests/section26.rs:529-577
- Description: `vkgl::vulkan_loader()` unconditionally returns a constant `VulkanLoader` (supported=true, VulkanOnMetal, fixed API version, fixed extension lists, src/vkgl.rs:79-105) with no MoltenVK probe, and `load_vulkan_loader(false)` rejects on a parameter. Every assertion in the test re-checks those constants, so it passes identically on any machine with or without Vulkan/MoltenVK, and no shader is ever compiled despite the test name. It would not catch a broken or missing Vulkan stack.
- Fix suggestion: Either rename to reflect it tests the loader-reporting contract (and add negative/API-consistency checks), or add a real capability probe (e.g. attempt a vkInstance/vkDevice creation via the loaded loader and assert behavior), plus at least one actual shader compile through `render_sample`/shader module loading with a real assertion on the artifact.

## [MEDIUM] t26_23 ADS read-back assertions skipped entirely when the write fails

- File: tests/section26.rs:1019-1055
- Description: `if let Ok(()) = write_result { ... }` — if `write_alternate_stream` fails for any reason (unsupported xattr, broken ADS layer, permission error, bug), every read-back/listing/deletion assertion is skipped and the test passes. A completely broken ADS implementation that fails all writes would report green; the comment even frames this as "acceptable". The deletion-verification (read_after.is_err()) is inside the same conditional, so nothing is verified on the failure path.
- Fix suggestion: Assert the failure path explicitly: on `Err`, assert the error is the documented platform-unsupported reason code and verify the file itself is unaffected; keep the full round-trip assertions unconditional where xattr is expected to work (macOS), and only skip on an explicit, asserted unsupported-platform signal rather than any `Err`.

## [MEDIUM] t26_25 multiple-stream test gates every assertion on all three writes succeeding

- File: tests/section26.rs:1111-1146
- Description: `if r1.is_ok() && r2.is_ok() && r3.is_ok() { ... }` — if any single stream write fails, the entire test body (listing, per-stream data equality for all three streams) is skipped and the test passes with zero assertions executed. Partial failures (1 of 3 writes succeeding) are indistinguishable from full success.
- Fix suggestion: Iterate per-stream and assert each write result independently (a failed write for stream N should still not suppress the assertions for streams N-1/N+1); assert listing contains exactly the streams whose writes succeeded; or fail the test outright when writes are unsupported instead of silently passing.

## [MEDIUM] t27_03 detect_text_regions on the varied frame asserts only `len < 100`

- File: tests/section27.rs:267-273
- Description: The frame is deliberately constructed with a 10×10 white block on gray (which the implementation reliably detects as 1 region — contrast 127 > 80), but the test asserts only `regions2.len() < 100`, i.e. it passes even if detection returns 0 regions (fully broken detector) or 99. The comment admits "may or may not detect regions… just verify no panic".
- Fix suggestion: Assert the deterministic outcome for this input: the 10×10 white-on-gray block must produce exactly 1 region (implementation provably yields 1), and assert the region's location/size (`x == 0`, `y == 0`, 32×32 block) or at minimum `!regions2.is_empty()`.

## [MEDIUM] t27_03 compare_frames "should NOT pass" assertion is a near-tautology

- File: tests/section27.rs:240-244
- Description: `assert!(!result_diff.passes || result_diff.ssim >= 0.9)` — the disjunction makes the check pass whenever `passes == false` (which is the expected outcome), so it never actually verifies the rejection. A broken `compare_frames` that returned `passes = true` with `ssim = 0.5` for different frames would sail through. The comment itself says "may not pass".
- Fix suggestion: Assert the definite expectation: red vs. blue at tolerance 0.0 must yield `pixel_match_percentage == 0.0` and `passes == false` (both are deterministic given the implementation and the input frames).

## [MEDIUM] t27_05 color-space verification asserts self-equality (`r1 == r1`)

- File: tests/section27.rs:419-421
- Description: `assert!(r1 == r1)` (and r2, r3) is a no-op assertion — any bool equals itself. The surrounding code calls `verify_color_space` for three color spaces on the same frame but never asserts the results are meaningful or consistent (e.g. that sRGB/DisplayP3 pass while LinearSRGB rejects mid-gray 128, or that identical frames produce identical verdicts across calls).
- Fix suggestion: Replace with real cross-space assertions: `r1` should be `true` (mid-gray is valid sRGB/DisplayP3), `r3 == r1`, and assert the documented LinearSRGB rejection for sRGB-encoded values, or drop the vacuous asserts.

## [MEDIUM] t27_21 "Metal backend resolve_msaa integration" never performs a resolve

- File: tests/section27.rs:1554-1621
- Description: Despite the name, no MSAA resolve is executed. The test creates an MSAA and a resolve texture, asserts `MsaaResolveConfig` field values (`sample_count == 4`, `resolve_mode as u32 == 0` — which pins the enum ordering), and checks the textures exist with width 64. `resolve_msaa_texture` (the function under test per the header comment) is never called; the test would pass if the resolve path were entirely removed or produced garbage. The in-test comment concedes "For a full integration test, this would be done within a render pass."
- Fix suggestion: Actually invoke the resolve (drive a real render pass / encoder, or call the backend resolve entry point exposed for this purpose) and assert the resolve output differs from the raw MSAA texture / matches the documented Average filter; otherwise rename the test to "MsaaResolveConfig construction" and drop the integration claim.

## [MEDIUM] t28_10 asserts `num_blas == 1` for a 3-instance TLAS — cements a stub shortcut

- File: tests/section28.rs:734-739
- Description: The implementation hardcodes `num_blas = 1` for every TLAS serialization (src/d3d12.rs:1172-1176) regardless of instance count or referenced BLASes. Per D3D12, `D3D12_SERIALIZATION_INFO::NumBottomLevelAccelerationStructurePointers` is the number of *unique* BLAS pointers referenced by the TLAS instances. With 3 instances (and no instance data supplied at all), the correct answer is not deterministically 1; the test asserts the stub's shortcut verbatim, so a later correct implementation would fail this test and the stub's wrong behavior is certified as expected.
- Fix suggestion: Build a real TLAS referencing 2-3 distinct BLASes and assert `num_blas == <distinct BLAS count>`; if the API cannot express instance→BLAS references yet, assert the documented limitation explicitly (e.g. error or 0) instead of asserting the placeholder value as correct.

## [MEDIUM] t28_09 "serialization round-trip" verifies only record cloning, not serialization

- File: tests/section28.rs:600-675
- Description: SERIALIZE (mode 3) and DESERIALIZE (mode 4) in the implementation just clone the in-memory metadata record to the destination address (src/d3d12.rs:1232-1250); no bytes are written or read. The test asserts only `result.is_ok()` and that a record exists at the deserialize address — i.e. it validates the bookkeeping, not any serialization semantics. A round-trip that lost all geometry data would pass.
- Fix suggestion: Write identifiable payload bytes into the serialize-destination buffer and assert they are present/parsed after deserialize (or assert that serialize produces the documented header layout: serialized size + pointer table), and compare source/dest metadata (size, is_top_level) as in t28_03.

## [MEDIUM] t26_11 "Shader Feature Detection" has zero assertions on features

- File: tests/section26.rs:583-611
- Description: The test named for feature detection reads every capability (`let _unified = caps.unified_memory; ...`) and feature query (`let _tearing = backend.query_feature(...)`) and discards all of them. The only assertions are three `format_mapping` checks, which belong to format mapping, not feature detection. A backend reporting no features at all would pass.
- Fix suggestion: Assert the documented baseline feature set (unified memory on Apple Silicon, query_feature(Tearing) == true per gfx.rs:1264-1271, format mappings for the three formats), or rename the test to match what it checks.

## [MEDIUM] t28c_01 asserts CoCreateInstance succeeds with a mismatched IID, codifying missing validation

- File: tests/section28_com.rs:117-129
- Description: The test asserts that `co_create_instance(SHELL_LINK, IDISPATCH, ...)` returns Ok "because validation happens at QueryInterface time". Real CoCreateInstance performs an initial QI of the requested IID against the class factory and returns E_NOINTERFACE when unsupported; the implementation stores the requested IID without checking it against `supported_iids` (src/real_win32.rs:3941-3967). The test thus blesses the permissive stub behavior — a fix implementing spec-compliant IID validation would be rejected by this test.
- Fix suggestion: Assert the spec behavior instead: `co_create_instance(SHELL_LINK, IDISPATCH)` should return an error (E_NOINTERFACE / RcComClassNotRegistered), while `co_create_instance(SHELL_LINK, ISHELLLINKW)` and `IUNKNOWN` succeed — matching how t28c_11 already asserts IID checks for CoGetClassObject.

---

## [LOW] t27_15 first-frame delta assertion is a tautology

- File: tests/section27.rs:1020-1023
- Description: `assert!(delta.is_zero() || delta > Duration::ZERO)` — every `Duration` satisfies this (it cannot be negative), so the assertion that "first frame delta should be zero" never checks anything. The implementation does return ZERO, so the assertion should be exact.
- Fix suggestion: `assert!(delta.is_zero(), "first frame delta should be zero")`.

## [LOW] t27_09 asserts exact default `duration_seconds == 60`

- File: tests/section27.rs:739-743
- Description: The test asserts the exact Default value (60) in addition to the earlier `> 0` check. It is correct today but duplicates the Default impl; a legitimate default change (e.g. 120 s) breaks the test for no behavioral reason. This also makes the test an implementation-echo rather than a contract check.
- Fix suggestion: Keep `duration_seconds > 0` plus `cycle_interval_seconds == 5` only if those are a documented contract; otherwise drop the exact-value assert or move it into the Default impl's own unit tests.

## [LOW] t27_12 asserts `elapsed_seconds == 0`

- File: tests/section27.rs:873-876
- Description: The network-resilience test asserts the runner reports `elapsed_seconds == 0`, which is an implementation artifact (the runner never measures elapsed time, src/diagnostics.rs:1693-1695) rather than a behavior of the resilience mechanism. If the runner starts measuring real elapsed time (a likely fix), the test breaks despite correct behavior.
- Fix suggestion: Drop the `elapsed_seconds` assertion, or gate it on `network_disconnects == 0` (the only case where elapsed could legitimately be 0).

## [LOW] t28_02 bakes the implementation's size-estimate formula into the assertion

- File: tests/section28.rs:168-171
- Description: `assert!(accel.size >= 64 + 2 * 64)` reproduces the stub's estimate layout (64-byte header + per-instance 72 bytes, src/d3d12.rs:1079-1082) with a slightly-off constant (64 vs. actual 72) so it is not even an exact echo. A real Metal `acceleration_structure_sizes_with_descriptor`-driven implementation with a different (correct) layout would fail this arbitrary floor.
- Fix suggestion: Assert the documented contract instead: `size >= 256` (the documented minimum, src/d3d12.rs:1103) and `size > 0`, plus `built == true` and `is_top_level == true`.

## [LOW] t28_01–t28_15 duplicate ~80-line setup blocks; copy-mode tests are near-identical

- File: tests/section28.rs:38-1048 (e.g. allocator/root-signature/PSO/list boilerplate at 70-87, 136-151, 209-224, ...)
- Description: Every test repeats the identical command-list setup (~15 lines of allocator/root-signature/PSO/list creation plus the geometry/desc construction), and t28_03 (COPY), t28_04 (COMPACT), t28_14 (VISUALIZE) differ only in the mode constant and addresses; t28_09 covers SERIALIZE/DESERIALIZE with the same shape. This makes the file ~1048 lines where a `fn build_blas(runtime, addr) -> (list, ...)` helper plus a mode-parameterized copy test would be ~300. Maintenance risk: a signature change to the setup APIs requires 15 identical edits.
- Fix suggestion: Factor `fn setup_list(runtime, label) -> CommandListId`, `fn build_blas(runtime, list, base_addr) -> u64` and a parameterized `copy_mode_roundtrip(mode)` helper; keep the per-mode assertions distinct.

## [LOW] t26_13 descriptor comments are misaligned with the byte data

- File: tests/section26.rs:740-742
- Description: The comment "// descriptor 1: SRV at register 1, space 0" is attached to the line holding descriptor 0's bytes (`0x03, 0x00, 0x00, 0x01, 0x00, 0x00`), and the comment calls kind 0x03 "CBV" while `parse_root_kind` maps 0x03 to `Cbuffer` and 0x01 to `Texture` (src/shader.rs:4363-4371). The test itself is correct; the comments are misleading for anyone reading the fixture.
- Fix suggestion: Move each comment onto the line of the byte block it describes and use the actual kind names (Cbuffer/Texture) or the DXIL names used by the parser.

## [LOW] t28c_06c-f VariantCopy tests assert the stub's shallow pointer copy

- File: tests/section28_com.rs:645-721
- Description: The tests copy variants whose `data` is a fake pointer (0x1234, 0xDEAD, 0xBEEF, 0xCAFE) and assert `data` is copied unchanged. This certifies the shallow copy (src/real_win32.rs:4527-4535). Real `VariantCopy` deep-copies BSTRs and AddRefs VT_UNKNOWN/VT_DISPATCH; a buggy implementation that never frees or refcounts reference-typed variants is invisible to these tests, and a correct deep-copy implementation would fail them. (t28c_06g at least covers source preservation across types.)
- Fix suggestion: For VT_BSTR/VT_UNKNOWN/VT_DISPATCH, allocate real objects (e.g. via `sys_alloc_string`, or registered COM objects) and assert deep-copy/refcount semantics: freed source string must not invalidate the copy, and AddRef must have been called on the copied UNKNOWN/DISPATCH.

## [LOW] t27_01 error-path test depends on helper-binary build state

- File: tests/section27.rs:109-117
- Description: `doctor()` resolves `casa1-helper` via `util::sibling_binary` (src/diagnostics.rs:142) and, when the binary happens to be present (e.g. after a full `cargo build`), spawns it against `/nonexistent_casa1_root` — the test then passes through a different error path (helper exit status or write failure) than when the helper is absent. The `is_err()` expectation holds in both cases here, but the path taken is machine/build-dependent and the test can't distinguish "helper missing" from "helper failed".
- Fix suggestion: Make the test hermetic — construct the environment so the failure is deterministic (e.g. assert only on the Err outcome and the non-empty error message as done, but avoid relying on which layer fails) or inject a fake helper path; consider gating on helper presence and asserting the reason code.

---

## Clippy

Command: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` (no `--all-features`; system ffmpeg absence irrelevant — build never got that far).

Result: **clippy fails at the library level**; the run never reached the integration-test targets, so there is no clippy output for any of the four assigned test files.

- The `casa1` lib produced 19 clippy **errors** (1271 warnings) — e.g. `unsafe_op_in_unsafe_fn` (pe_runtime.rs ~lines 40981-43674, many), `approx_constant` (audio_format.rs:180-235, several), `eq_op`/`nonminimal_bool` (security.rs:3097), a `manual_strip` logic-bug assert `!x || true` (dwrite.rs:1398), `eq_op` in winhttp.rs:3624.
- The lib-test target then produced 27 further errors (1415 warnings total), e.g. `set_len` uninitialized values, approx constants, "this boolean expression contains a logic bug".
- All error locations are in `src/*.rs`; none reference tests/section26.rs, tests/section27.rs, tests/section28.rs, or tests/section28_com.rs.

Relevant to this audit: the tautological assertions in tests/section27.rs (t27_08, t27_15, t27_05) are pre-emptively silenced by `#![allow(clippy::overly_complex_bool_expr)]` / `#![allow(clippy::needless_range_loop)]` at the top of the file (lines 1-2) — the author suppressed the very lint that would flag the vacuous conditions.

## Test results

All four test binaries compiled and ran to completion on this machine (macOS, 2026-08-15). No test failed; no test binary failed to compile. No hang > 15 min (section27 total run was 1.65 s — Steam CM connections failed fast on this network, which is itself evidence of the environment dependence in t27_08).

| File | Result | Pass | Fail | Time |
|---|---|---|---|---|
| tests/section26.rs | PASS | 25 | 0 | 0.05 s |
| tests/section27.rs | PASS | 22 | 0 | 1.65 s |
| tests/section28.rs | PASS | 15 | 0 | 0.00 s |
| tests/section28_com.rs | PASS | 38 | 0 | 0.00 s |

Failing tests: none.

Note: t26_07/t26_08/t26_09 and t27_21 exercise the real Metal device; they passed here (GPU present). The skip-on-no-GPU paths in those tests are graceful, but mean the Metal surface is untested on headless CI.
# AUDIT FINDINGS — Tests (batch: sections 29–37)

- **Batch:** Casa1 test-suite audit, batch 3 (sections 29–37)
- **Files audited (all read in full, line-by-line):**
  tests/section29_process.rs (456), tests/section30_app_bundle.rs (671),
  tests/section31_vulkan.rs (853), tests/section32_opengl.rs (558),
  tests/section33_gdi.rs (1788), tests/section34_video.rs (1403),
  tests/section34_phase3.rs (861), tests/section35_d3d.rs (792),
  tests/section35_system_insns.rs (323), tests/section36_authenticode.rs (258),
  tests/section37_integration.rs (997)
- **Date:** 2026-08-15
- **Commands run:** `cargo clippy --all-targets --no-deps` (failed in the library before
  reaching test targets; re-run with `-- --cap-lints warn` to reach test targets),
  `cargo test --test <stem>` for all 11 binaries.

---

## [CRITICAL] ECDSA verification test is a tautology on a security-critical path

- File: tests/section37_integration.rs:768
- Description: `e7_crypto_ecdsa_p256_verify` asserts `result.is_ok() || result.is_err()`,
  which can never fail (any return value passes). The "valid" signature is a made-up
  hex blob (`3044...` at line 760) that is not a signature over the message for the
  given public key, and there is no negative case. A broken `ecdsa_p256_verify` that
  returns `Ok(())` for arbitrary input (or a stub) passes this test, giving false
  confidence in a security-critical verification path. This is the only crypto test in
  the batch with no real assertion.
- Fix suggestion: Generate a real P-256 key pair in the test (e.g., `p256::ecdsa`
  `SigningKey`), sign a message, assert `is_ok()` on the valid (message, signature)
  pair, and assert `is_err()` on a tampered message. Delete the fake DER blob.

## [HIGH] GDI+ lifecycle/save-restore/container tests simulate the library in-test instead of exercising it

- File: tests/section33_gdi.rs:60 (t33_01), 616 (t33_21), 702 (t33_22)
- Description: `t33_01_startup_shutdown_lifecycle` sets `state.initialized`/`token` and
  clears `objects`/`graphics_from_hdc` by hand — it never calls any startup/shutdown
  entry point. `t33_21_graphics_save_restore` and `t33_22_graphics_begin_end_container`
  manually push `GdiplusContainer` entries onto `container_stack` and restore fields by
  hand — the exact logic a `GdipSaveGraphics`/`GdipRestoreGraphics`/
  `GdipBeginContainer`/`GdipEndContainer` implementation would own. A no-op or broken
  implementation of these APIs passes these tests unchanged. The file header claims
  coverage of "Graphics save/restore containers (begin/end container, save/restore)"
  that does not exist. Same pattern (hand-written state mutations, read back through
  `state.get`) covers matrix ops t33_12–18, world transform t33_19, clip t33_20,
  quality t33_30 — none exercise the thunk/dispatch layer.
- Fix suggestion: Exercise the actual GDI+ API surface (call the Gdip* dispatch /
  HostThunk-backed methods if implemented; if they are not implemented, mark these
  tests `#[ignore]` or delete and add real API tests). At minimum rename to reflect
  they are object-table tests, not GDI+ behavior tests.

## [HIGH] Authenticode test asserts `Valid` for a self-signed cert that real chain validation rejects

- File: tests/section36_authenticode.rs:212
- Description: `authenticode_accepts_valid_signature` signs with a freshly built
  self-signed certificate (`build_certificate`, Profile::Root) and asserts
  `verify_pe_authenticode(&pe) == AuthenticodeVerdict::Valid`. The verifier performs
  real chain validation up to the system trust store (src/security.rs:4142
  `SecTrustEvaluateWithError`), so the verdict is
  `Invalid("chain validation failed: certificate chain not trusted ...")` — the test
  FAILS (observed). A verifier that skipped trust validation would pass this test, so
  it can only pass on a lenient/buggy implementation. The remaining 4 tests in the
  file (tamper, unsigned, garbage table, malformed headers) are sound.
- Fix suggestion: Either (a) establish trust for the test certificate (import into the
  trust store if the API supports it), (b) assert the documented contract for
  untrusted roots (`Invalid`/`Untrusted`), or (c) if the intended contract is
  "cryptographic validity only, no trust enforcement", that decision belongs in the
  implementation — make the test express the actual contract and update the header
  comment ("assert that verify_pe_authenticode accepts it" is not true).

## [MEDIUM] Wrong expected constant: D3D12 PIXEL_SHADER_RESOURCE bit (test failure)

- File: tests/section35_d3d.rs:698
- Description: `t35_33_resource_state_to_d3d12_bits` asserts
  `ResourceState::PixelShaderResource.to_d3d12_bits() == 0x8`. Per the D3D12 resource
  state enum, `D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE = 0x80` (0x8 is
  `UNORDERED_ACCESS`). The implementation returns 0x80 (correct); the test constant is
  wrong, producing a failing test that misattributes an implementation bug. `Common`
  (0) and `RenderTarget` (0x4) assertions in the same test are correct.
- Fix suggestion: Change expected value to `0x80`; consider adding `UnorderedAccess`
  (`0x8`) and `NonPixelShaderResource` (`0x40`) cases.

## [MEDIUM] Wrong expected constant: D3D10_BIND_RENDER_TARGET (test failure)

- File: tests/section35_d3d.rs:758
- Description: `t35_37_d3d10_constants` asserts `D3D10_BIND_RENDER_TARGET == 16`.
  Per d3d10.h, `D3D10_BIND_RENDER_TARGET = 0x20` (32); `0x10` is
  `D3D10_BIND_STREAM_OUTPUT`. The implementation's 0x20 is correct. All other
  constants asserted in the test match d3d10.h.
- Fix suggestion: Change to `assert_eq!(D3D10_BIND_RENDER_TARGET, 32)` (and optionally
  assert `D3D10_BIND_STREAM_OUTPUT == 16`).

## [MEDIUM] Deferred-context draw test fails because no render target is bound

- File: tests/section35_d3d.rs:330
- Description: `t35_15_d3d11_deferred_context` calls `deferred.draw(3)` on a fresh
  deferred context with no render target/depth target bound, then
  `finish_command_list`. The implementation rejects the draw with
  `RcD3dInvalidState` ("draw command recorded but neither render target nor depth
  target is bound"), so the test fails (observed). The test is missing setup: on a
  real D3D11 deferred context, drawing without an OM target is also invalid.
- Fix suggestion: Create a texture, RTV, bind it via the deferred context
  (`OMSetRenderTargets` equivalent), then draw and assert the command list contains
  the draw (and the RT bind).

## [MEDIUM] MfTransform output errors are swallowed

- File: tests/section34_video.rs:574
- Description: `let output = transform.process_output().unwrap_or(None);` discards the
  `Result`; if `process_output` always errors, the test still passes (the `if let`
  body is skipped). This is exactly the "swallow failures then assert unrelated state"
  pattern. The same file's t34_02/03/16 use `let _ = ...` on decode results and then
  assert nothing on non-macOS/non-ffmpeg builds.
- Fix suggestion: `let output = transform.process_output().expect("process_output");
  assert!(output.is_some());` (or assert the error contract if the transform cannot
  produce output without a real decoder).

## [MEDIUM] PTS-ordering test passes vacuously when the decoder produces no frames

- File: tests/section34_video.rs:155
- Description: `t34_04_frame_pts_ordering` wraps its only assertions in
  `if !frames.is_empty()` — if `flush()` returns nothing (no decoder, no frames), the
  test passes without checking anything. The decode calls' results are also discarded
  (`let _ =`), so a decoder that silently drops all input passes.
- Fix suggestion: Assert `!frames.is_empty()` first (with a decoder-availability guard
  if needed), then check PTS monotonicity; or assert the no-decoder error contract.

## [MEDIUM] Conditional decoder assertions vanish on non-macOS builds

- File: tests/section34_video.rs:86, 116, 566
- Description: `if cfg!(any(target_os = "macos", feature = "ffmpeg")) { assert!(...) }`
  means on Linux without the `ffmpeg` feature these tests contain zero assertions and
  pass on any behavior. Only one arm is ever compiled; the "no decoder → Err" contract
  is never asserted (t34_03 has an `else` arm, but t34_02 and t34_16 do not).
- Fix suggestion: Use `#[cfg(...)]` split tests with real assertions in both branches
  (Ok-with-decoder vs Err-without-decoder), so every build asserts something.

## [MEDIUM] Session-position test is wall-clock timing dependent

- File: tests/section34_video.rs:769
- Description: `t34_23_session_position_tracking` sleeps 2 ms then asserts
  `pos_after_start < 10_000` (µs) against a position computed from
  `std::time::Instant` (src/media.rs:2182). Under CI scheduling load, the elapsed time
  between `start()` and `get_position()` can exceed 10 ms, making the test flaky.
  The `pos_after_start > 0` and freeze/resume assertions are fine.
- Fix suggestion: Relax the upper bound (e.g., `< 1_000_000`) or inject a clock /
  fixed start time so the assertion is deterministic.

## [MEDIUM] Activation-context test discards the meaningful check

- File: tests/section37_integration.rs:315
- Description: `e7_build_activation_context_from_pe_manifest` computes
  `_has_vc_dlls` (the real property: the VC143 manifest yields msvcp/vcruntime
  bindings) but never asserts it (underscore name), asserting instead the trivial
  `plan.vc_runtime_bindings.len() <= 10`. The whole body is also gated on
  `if let Some(ref manifest)` — if `embedded_manifest` were `None`, the test would
  pass with no assertions. A broken manifest/activation-context parser passes.
- Fix suggestion: Assert `_has_vc_dlls` is true for the sample PE (it embeds a
  `Microsoft.VC143.CRT` dependency) and assert `plan.vc_runtime_assemblies` contains
  the VC143 identity; assert the manifest is present rather than conditionally
  skipping.

## [MEDIUM] XAPO tests assert only "output is not all zeros" — pass on a pass-through

- File: tests/section34_phase3.rs:415, 478
- Description: `t34_xapo_equalizer_processes_audio` and
  `t34_xapo_effect_chain_process` assert `output.iter().any(|&s| s != 0.0)`. A
  pass-through or identity effect produces non-zero output for a non-zero input, so
  these assertions cannot distinguish "effect applied" from "effect does nothing".
- Fix suggestion: Feed a DC constant (e.g., all 0.5) and assert the output converges
  to the expected per-band gain value for the configured parameters (compute the
  expected DC response), or compare against a reference biquad implementation.

## [MEDIUM] PE icon fixture declares a DIB size too small; most pixel data is never written

- File: tests/section30_app_bundle.rs:252 (size 0x0A28), 269 (0x0A28), 279
  (`resize(bmp_header_offset + 0x0A28)`), 303 (pixel writes guarded by `pixel_off + 4
  <= pe.len()`)
- Description: The fixture's RT_ICON data entry and GRPICONDIRENTRY declare size
  `0x0A28` (2600 bytes), but a 32×32×32bpp DIB with AND mask is
  40 + 4096 + 128 = 4264 bytes (0x10A8). The buffer is sized to 0x1C28, so pixel rows
  for y = 0..11 (the top 12 rows of the icon) are silently skipped by the length
  guard, and the extractor (src/pe.rs:3187, uses the declared resource size) returns
  truncated data. Tests only check `!icon.data.is_empty()` and dimensions, so the
  truncation is invisible and the "round-trip" tests operate on a black-topped icon.
  The comment "approx for 32×32 32bpp DIB" masks the off-by-1664 error.
- Fix suggestion: Declare size 0x10A8 in both places, resize the buffer to
  `bmp_header_offset + 0x10A8`, and add an assertion
  `assert_eq!(icon.data.len(), 4264)` (and verify a known pixel value survives the
  round trip).

## [MEDIUM] D3D10 map/unmap "round-trip" test never verifies data

- File: tests/section35_d3d.rs:114
- Description: `t35_04_d3d10_map_unmap_update_roundtrip` writes 64 bytes via
  `update_subresource`, then `map()` is asserted only `!mapped.is_empty()`. The
  mapped contents are never compared to the written data, and after `unmap` with
  modified data the buffer is never re-read. A map that returns garbage (or always
  zeros) passes.
- Fix suggestion: `assert_eq!(mapped, data);` after map, and after `unmap` with
  `modified`, map again and `assert_eq!(mapped, modified)`.

## [MEDIUM] WebSocket buffer-type test asserts a tautology

- File: tests/section34_phase3.rs:90
- Description: `t34_websocket_buffer_types` builds an array literal of 6 enum
  variants and asserts `types.len() == 6` — always true by construction; the test
  cannot fail and verifies nothing beyond compilation.
- Fix suggestion: Assert per-variant behavior (e.g., discriminants map to the WinHTTP
  `WINHTTP_WEB_SOCKET_BUFFER_TYPE` values: 0..=5), or remove the test.

## [LOW] No-assertion tests (setup-only or discarded results)

- File: tests/section35_d3d.rs:667 (t35_30: `let _ = device.update_subresource(...)`),
  tests/section35_d3d.rs:791 (t35_40: `let _ = device.memoryless_depth_targets();`),
  tests/section33_gdi.rs:982 (t33_29: `let _handle = ...` "just verify no panic")
- Description: These tests perform an action and discard the result, asserting
  nothing. They pass if the operation errors, panics inside a swallowed path, or is
  a complete no-op.
- Fix suggestion: Assert the result (`is_ok()`/`is_err()` per contract) and/or assert
  resulting state (e.g., `memoryless_depth_targets()` returns a bool and device is
  usable; `update_subresource` returns Ok).

## [LOW] Comment promises a check that does not exist (YUV→RGB black pixel)

- File: tests/section34_video.rs:324
- Description: The comment "…(with standard YUV→RGB, Y=0 may produce non-zero due to
  chroma, so just check it's less than the white pixel)" describes an assertion that
  was never written; only the Y=255 pixel is checked.
- Fix suggestion: Either implement the stated comparison
  (`rgba_of_black_pixel < rgba_of_white_pixel` component-wise) or fix the comment.

## [LOW] InstallShield test name contradicts its assertion

- File: tests/section34_phase3.rs:790
- Description: `t34_iss_parse_comments_ignored` asserts `comments.len() == 3` — i.e.,
  comment lines are PRESERVED as `IssCommand::Comment` entries — while the name says
  they are "ignored". If the parser later drops comments (matching the name), the
  test fails; the name and assertion pin opposite semantics.
- Fix suggestion: Rename to `t34_iss_parse_comments_recorded` or assert that comment
  commands are not executed/recorded as other command types.

## [LOW] CPU test comment claims memory access the test never performs

- File: tests/section37_integration.rs:799
- Description: `e7_cpu_execute_ir_with_mapped_memory` maps bytes at 0x1000 and the
  comment says "Read value from memory into RAX", but the IR instructions are only
  `MovImm`/`AddImm`; the mapped memory is never touched, so the "CPU + Memory
  integration" aspect is untested.
- Fix suggestion: Add a `MovMem`/`Load` IR instruction reading 0x1000 into RAX and
  assert the loaded value participates in the computation.

## [LOW] Misleading "block-aligned" comment in AES-CBC test

- File: tests/section37_integration.rs:699
- Description: The comment claims the 24-byte plaintext is "block-aligned (multiple
  of 16)" — 24 is not a multiple of 16, which is exactly why the test pads to 32
  bytes. The assertions themselves are correct.
- Fix suggestion: Correct the comment (e.g., "24 bytes — not block-aligned, so pad").

## [LOW] Brittle: exact handle values / impl-detail assertions

- File: tests/section33_gdi.rs:1244 (t33_35 hardcodes `0xDD010000..0xDD010002`),
  tests/section29_process.rs:148 (t29 asserts consecutive process/thread IDs are
  `+1`), tests/section34_phase3.rs:449 (XAPO hardcodes 7 built-ins)
- Description: These pin implementation details (handle base, counter increments,
  registry size). They are deliberate contract tests but will break on any legitimate
  change (e.g., IDs derived from PIDs, new built-in effect). `assert!(h1 < h2)` would
  retain the real property.
- Fix suggestion: Keep monotonicity/inequality assertions; assert exact values only
  where they are an explicit ABI contract.

## [LOW] MoltenVK expanded-path test depends on environment

- File: tests/section31_vulkan.rs:476
- Description: `t31_09_moltenvk_search_paths` asserts
  `expanded.len() > static_paths.len()`; expansion adds entries only when `$HOME` is
  set and `current_exe()` succeeds. In a stripped environment (unset HOME) the test
  fails.
- Fix suggestion: Assert the static paths and "contains ~/MoltenVK when HOME is set"
  with an env guard; do not assert on the count.

## [LOW] draw_string test pins placeholder rendering internals

- File: tests/section33_gdi.rs:1733
- Description: `t33_47_renderer_draw_string` asserts the exact pixel at (5,5) equals
  white. The implementation is an explicit placeholder (block per character,
  src/gdiplus_render.rs:1379 "Placeholder"). Any real font rendering change breaks
  the test, and it cannot detect wrong text.
- Fix suggestion: Assert that a block region is painted at the expected coordinates
  (e.g., any non-zero pixel within the first char block), or switch to a golden
  bitmap once real rendering exists.

## [LOW] Clippy: clone on Copy type

- File: tests/section35_d3d.rs:620
- Description: `let b = a.clone();` where `DxgiFormat` is `Copy` —
  `clippy::clone_on_copy` warning (the only clippy warning in the audited files).
- Fix suggestion: `let b = a;`

---

## Clippy

- Plain `cargo clippy --all-targets --no-deps` does not complete: the **library**
  fails with 19–27 deny-by-default lint errors (e.g., `absurd_extreme_comparisons` in
  src/crash_recovery.rs:536, `eq_op` in src/security.rs:3097, `not_unsafe_ptr_arg_deref`
  in several files, `uninit_vec`, `almost_swapped`), so test targets are never
  reached. Re-ran with `cargo clippy --all-targets --no-deps -- --cap-lints warn`
  (1415 warnings, lib + tests).
- Findings referencing the audited test files (from clippy_out2.txt):
  - `tests/section35_d3d.rs:620` — `clippy::clone_on_copy` (see LOW finding above).
  - No other warnings/errors reference the 11 audited test files.
- Note: clippy errors in the library are out of scope for this test audit but block
  the prescribed clippy command; worth fixing separately.

## Test results

| Test binary | Result | Pass/Fail |
|---|---|---|
| section29_process | PASS | 20/20 |
| section30_app_bundle | PASS | 13/13 |
| section31_vulkan | FAIL | 18/20 |
| section32_opengl | PASS | 10/10 |
| section33_gdi | PASS | 48/48 |
| section34_video | PASS | 45/45 |
| section34_phase3 | PASS | 48/48 |
| section35_d3d | FAIL | 35/40 |
| section35_system_insns | FAIL | 10/12 |
| section36_authenticode | FAIL | 4/5 |
| section37_integration | PASS | 23/23 |

No test binary failed to compile. No run hung (max observed: section36 at ~10 s;
RSA-2048 keygen dominates).

Failing tests (name — 1-line summary):

- section31_vulkan:
  - `t31_18_state_updates_after_validation` — `create_device(99999, …)` returns
    `Ok(1)`; the implementation never validates the physical-device handle
    (src/vkgl.rs:2564), so the "invalid handle must fail" expectation fails.
  - `t31_19_malformed_spirv_rejected` — header-only SPIR-V (5 words, no instructions)
    returns `Ok(7)`; the translator accepts an instruction-less module
    (src/vkgl.rs:2790 only checks length/magic). Both failures indicate genuine
    validation gaps in the implementation; the test expectations are defensible.
- section35_d3d:
  - `t35_15_d3d11_deferred_context` — `finish_command_list` errors
    (`RcD3dInvalidState`: no render/depth target bound); test records a draw without
    binding an OM target (test fault — see MEDIUM finding).
  - `t35_24_dxgi_format_unknown` — `DxgiFormat::from_u32(0)` returns
    `R32G32B32A32Float`; per DXGI, 0 is `UNKNOWN` (implementation table bug,
    src/gfx.rs:78 — test expectation correct).
  - `t35_25_dxgi_format_common_values` — `from_u32(87)` returns `R16Snorm`;
    DXGI_FORMAT_B8G8R8A8_UNORM is 87 (implementation table bug, src/gfx.rs:99 — test
    expectation correct).
  - `t35_33_resource_state_to_d3d12_bits` — test expects `PixelShaderResource → 0x8`;
    correct D3D12 value is 0x80 (test fault — see MEDIUM finding).
  - `t35_37_d3d10_constants` — test expects `D3D10_BIND_RENDER_TARGET == 16`;
    correct value is 0x20 (test fault — see MEDIUM finding).
- section35_system_insns:
  - `xsave_xrstor_round_trip_preserves_ymm_upper` — XSTATE_BV at base+512 is 0xE7
    (231), test expects 0b111; implementation announces AVX-512 state bits (5–7) it
    does not save/restore (implementation bug; test expectation correct).
  - `in_reads_zero_into_accumulator` — `IN AL, 0x60` leaves RAX unchanged; the
    implementation never writes the zero result into AL (implementation gap; test
    expectation correct).
- section36_authenticode:
  - `authenticode_accepts_valid_signature` — verdict is
    `Invalid("chain validation failed: certificate chain not trusted …")` for the
    self-signed test cert; verifier does real chain validation (test fault — see
    HIGH finding).

## Summary counts

- CRITICAL: 1
- HIGH: 2
- MEDIUM: 12
- LOW: 9 (including 1 clippy)
- Total findings: 24
