# AUDIT_FINDINGS.md — Casa1 Fuzz Targets & Performance Benchmarks

**Batch:** audit-fuzz-benches-2
**Date:** 2026-08-15
**Auditor role:** Senior code auditor (audit-only; no source files modified)

**Files audited (read in full, in order):**
- fuzz/fuzz_targets/filesystem_path.rs (30 lines)
- fuzz/fuzz_targets/http_headers.rs (53 lines)
- fuzz/fuzz_targets/http_response.rs (25 lines)
- fuzz/fuzz_targets/pe_parser.rs (82 lines)
- fuzz/fuzz_targets/registry_path.rs (13 lines)
- fuzz/fuzz_targets/spirv_parser.rs (32 lines)
- fuzz/fuzz_targets/steam_protocol.rs (83 lines)
- fuzz/fuzz_targets/url_handling.rs (50 lines)
- fuzz/fuzz_targets/video_packet.rs (33 lines)
- fuzz/fuzz_targets/websocket.rs (58 lines)
- fuzz/fuzz_targets/winhttp_url.rs (64 lines)
- fuzz/Cargo.toml (114 lines)
- benches/perf_benchmarks.rs (1630 lines)

Supporting verification (read-only): src/security.rs, src/steam.rs, src/pe.rs, src/winhttp.rs, src/wininet.rs, src/network.rs, src/jit.rs, src/perf.rs, src/audio.rs, src/real_fs.rs, src/video_decoder.rs, tests/section_fuzz.rs.

---

## [CRITICAL] Fuzz target `websocket.rs` exercises only trivial enum conversions — harness cannot fail

- File: fuzz/fuzz_targets/websocket.rs:6-58
- Description: The target never touches any WebSocket protocol code. It only runs `WinHttpWebSocketBufferType::try_from_u32` (src/winhttp.rs:136-149) and `WinHttpWebSocketCloseStatus::from_code`/`try_from_u32` (src/winhttp.rs:173-217) — pure, total `match` statements on u16/u32 values with catch-all arms. There is no allocation, no pointer arithmetic, no parsing and no code path that can panic or exhibit UB; a crash is impossible by construction. The real WebSocket machinery (tungstenite-backed frames behind `#[cfg(feature = "websocket")]`, src/winhttp.rs:241-316, and `WinHttpWebSocketState`, src/winhttp.rs:221) is never reached. The target name is misleading: "websocket" implies frame/header/masking parsing coverage that does not exist.
- Fix suggestion: Remove the target, or rework it to feed bytes into actual WebSocket parsing (RFC 6455 frame header/mask/close-code validation; e.g., any byte-level frame parser in `casa1::network` / `casa1::winhttp`, such as a handshake-response or frame-header decoder). If no byte-level parser exists, the target should be deleted rather than kept as a false coverage signal.

## [CRITICAL] `http_headers.rs` and `winhttp_url.rs` perform real blocking network requests inside the fuzz loop

- File: fuzz/fuzz_targets/http_headers.rs:46-52; fuzz/fuzz_targets/winhttp_url.rs:39-48
- Description: Both targets call `wininet::create_url_moniker(text, None)` (and `create_url_moniker_ex`) on every valid-UTF-8 input. That function (src/wininet.rs:2033-2105) builds a `reqwest::blocking::Client` and issues a real `client.get(url).send()` with a 30-second timeout. Consequences: (a) each fuzz iteration is dominated by DNS/connect/response latency (up to 30 s for hanging hosts) instead of parser coverage, making the targets effectively unusable for fuzzing; (b) the fuzzer drives arbitrary outbound connections to whatever host strings appear in its corpus (unintended network side effects); (c) the comment "Only test URLs that look vaguely HTTP-ish to avoid excessive Err paths" (http_headers.rs:47) is not implemented — no filter exists.
- Fix suggestion: Delete the moniker calls from the fuzz targets (the moniker code is an HTTP fetch shim, not a parser), or gate them behind a feature/flag that is off in fuzzing builds, or replace with a pure URL-moniker-construction stub that does not perform I/O.

## [CRITICAL] `bench_network_websocket_buffer` measures no WebSocket code, leaks sockets per iteration, and panics via `.expect`

- File: benches/perf_benchmarks.rs:1080-1119
- Description: (a) Despite its name, the bench never exercises WebSocket logic — `bind`/`listen`/`connect` are bookkeeping-only when the internal listener map is used (src/network.rs:999-1146), and the measured body is an in-memory `send` that appends to the peer's `recv_queue` (src/network.rs:1172-1198). (b) Each iteration creates a new socket pair (`sock_c` + the accepted server socket) that is never closed; sockets accumulate in `NetworkStack.sockets`/`pending_accept` forever — unbounded growth inside the measured region. (c) The accepted socket's recv queue is never drained and caps at `MAX_SOCKET_RECEIVE_QUEUE` = 16 MB (src/network.rs:138); once the queue fills, `send` returns `Err(RcSocketReceiveQueueFull)` and `net.send(...).expect("send")` panics — after ~256 iterations for the 65536-byte payload and ~4096 for 4096 bytes, all well within a normal Criterion run. The bench cannot produce valid results.
- Fix suggestion: Create one persistent connected socket pair before the loop; drain the peer queue inside the loop (or use real TCP); drop the `.expect` and handle errors; and either exercise actual WebSocket frame code or rename the bench to reflect that it measures in-memory socket send.

## [CRITICAL] `many_imports_pe` produces a PE with zero imports — `bench_pe_parse_large_image`/`bench_pe_map_large_image` measure nothing that scales with import count

- File: benches/perf_benchmarks.rs:794-861, 1173-1185, 1187-1207
- Description: The synthetic PE claims `{64,200,500}_imports` but no imports are ever parsed: (a) `minimal_pe` writes all-zero data directories (perf_benchmarks.rs:200-204) and `many_imports_pe` never sets `IMAGE_DIRECTORY_ENTRY_IMPORT` in the optional header, so `parse_import_directory` returns early on `virtual_address == 0` (src/pe.rs:1656-1662); (b) the ILT/IAT arrays place the zero terminator at index 0 (perf_benchmarks.rs:825-834, 839-846), and `read_import_thunks` stops at the first zero entry (src/pe.rs:2471-2472); (c) the DLL-name RVA points at 0xBF4, which is never written (zeros). The benches therefore measure raw file-size parsing only — the "high import count" workload is silently ineffective, and the per-count timing differences are not import-resolution costs.
- Fix suggestion: Set data directory entry 1 (RVA 0x400, size = real table size); write `kernel32.dll\0` at 0xBF4; put the zero terminator at the END of the ILT/IAT arrays; use true ordinal/name entries (ordinal number or name-RVA without the snap-by-ordinal flag). Optionally assert `parsed.imports.len() == count`.

---

## [HIGH] `many_sections_pe` optional header is written 24 bytes short — section table is read misaligned

- File: benches/perf_benchmarks.rs:239-291; benches/perf_benchmarks.rs:555-567, 1209-1221
- Description: The builder declares `size_of_optional_header = 0xF0` (240 bytes) but writes only magic(2) + 86 pad + 128 bytes of data directories = 216 bytes (0xD8). The parser computes `section_table_offset = optional_offset + size_of_optional_header` (src/pe.rs:778), so it reads section entries starting at 0x188 while the builder placed them at 0x170 — every parsed entry is a 24-byte-shifted blend of two written entries (names, virtual sizes and addresses misaligned). `parse` silently succeeds or produces garbage sections; `bench_pe_parse_many_sections` / `_large` never assert `parse().is_ok()` or section counts, so the "N sections" claim does not reflect a valid PE.
- Fix suggestion: Write the full PE32+ optional header (112 bytes) plus 16 data directories so the file matches the declared 0xF0, or set `size_of_optional_header = 0xD8`. Add an assertion on the parsed section count and validity.

## [HIGH] `bench_jit_constant_folding` and `bench_jit_dead_code_elimination` measure the identical tier1 pipeline with no proof the named pass ran

- File: benches/perf_benchmarks.rs:460-498
- Description: Both benches call `compiler.compile_tier1(...)` (src/jit.rs:3788), which per its doc runs constant folding + DCE + register allocation combined. There is no assertion that folding/DCE actually happened (no comparison of compiled output size vs tier0, no IR-size check), so if the optimizer is broken or disabled these benches silently measure unoptimized compilation and still report "constant_fold"/"dce" results. The inputs are also conceptually swapped: `mov_eax_block` (overwritten MOVs) is described as "dead assignments that constant folding resolves", but dead-assignment elimination is DCE's job, while `dead_eax_block` feeds the DCE bench through the same single code path — the two benches differ only in input bytes.
- Fix suggestion: Assert a measurable effect of the pass (e.g., compiled block byte length strictly smaller than tier0 output for the same IR), or benchmark the optimizer passes directly; correct the input/pass pairing.

## [HIGH] Inline-cache benches never hit — call sites do not repeat despite the "mix of hits and misses" comment

- File: benches/perf_benchmarks.rs:518-536, 1227-1244
- Description: `let call_site = 0x1000 + (i as u64 * 0x40)` with `i` strictly increasing means every lookup uses a never-seen call site: each iteration is a pure miss/insert (with eviction after `max_entries`). `InlineCache::lookup` (src/jit.rs:4827) only hits when the same call_site is looked up again. So the bench measures a 100%-miss workload (hit_rate ≈ 0) while the comment claims a mix of hits and misses, and `hit_rate()` is never asserted — a cache that never cached anything would produce identical results. `bench_fast_thunk_inline_cache` is byte-for-byte the same bench under another name (no fast-thunk dispatch is exercised).
- Fix suggestion: Use repeating call sites, e.g. `0x1000 + ((i as u64 % max_entries as u64) * 0x40)` for the hit portion and a distinct stream for misses; assert an expected hit rate (e.g., `>= 0.5`); delete or differentiate the fast_thunk duplicate.

## [HIGH] Benchmarks contain no correctness assertions — errors read as speedups

- File: benches/perf_benchmarks.rs:297-310 (decode nop), 312-355 (decode alu/simd/control_flow), 373-403 (full pipeline), 409-458 (tier compiles), 500-536 (tier promotion, inline cache), 542-567 (PE parse), 943-1038 (audio mix), 1299-1336 (interpreter/decode throughput)
- Description: `decode_block` returns `AppResult` but the decode benches `bb(decoded)` without asserting success or decoded-instruction counts, so a decoder regression that rejects NOPs/ALU/SSE/CMP inputs would be reported as a faster benchmark. `bench_pe_parse_minimal` black-boxes the `Result` without `is_ok()`. `compile_tier0/1/2` results are discarded, so a compile failure measures the error path. `TieredCompiler::record_execution` returns `Some(tier)` on promotion (src/jit.rs:3703) but the result is discarded in both tier-promotion benches (500-516, 1246-1262) — a broken promotion policy is undetectable. `mix_direct_sound_buffer` returns `AppResult` (src/audio.rs:1707) and `bb(out)` ignores errors.
- Fix suggestion: `.expect()` on Results, and assert expected outcomes (e.g., decoded instruction count == input size/avg-encoding, `parse` is `Ok`, tier == expected after N execs, hit_rate in range). A benchmark that cannot fail is measuring nothing.

---

## [MEDIUM] Most fuzz targets are determinism-only — no semantic invariants asserted

- File: fuzz/fuzz_targets/filesystem_path.rs:6-13; http_response.rs:6-13; registry_path.rs:6-13; spirv_parser.rs:6-13; video_packet.rs:6-13; url_handling.rs:7-17; winhttp_url.rs:7-14
- Description: All these targets run the same pure function twice and `assert_eq!` the summaries. For deterministic, pure parsers this property is trivially true; it catches no bug class that libFuzzer's default panic/UB detection misses, and none of the targets validate parser invariants (e.g., that `parse_ntfs_path` returns an ADS-free `file_path`, that a successfully parsed SPIR-V module has the expected magic, that cracked URLs have sane host/port splits). A semantically-wrong-but-deterministic parser passes silently. Coverage feedback still works, so these are weak rather than useless, but the assertion layer adds little.
- Fix suggestion: Add per-parser invariant assertions inside the target (checks on Ok results: lengths, structure, round-trips where cheap), and keep the determinism check only where the parser has state.

## [MEDIUM] `video_packet.rs` only exercises SPS NAL parsing — PPS/IDR/SEI paths uncovered

- File: fuzz/fuzz_targets/video_packet.rs:19-31
- Description: `parse_h264_annex_b` is exercised (start-code splitting), but of the NAL units produced, only type 7 (SPS) reaches deeper code (`parse_h264_sps`); PPS (type 8), IDR (5), non-IDR (1), SEI (6) and AUD (9) are skipped. The resulting `(w, h)` from `parse_h264_sps` is only stringified — no check that valid SPS yields non-zero dimensions or that malformed SPS yields (0,0) rather than panicking (a (0,0) result would also pass). Coverage of the SPS parser itself is input-starved: SPS is only reached when the fuzzer constructs an Annex-B stream containing a type-7 NAL, which random bytes rarely produce.
- Fix suggestion: Feed every NAL type into its parser, assert `(w, h)` invariants, and add seed corpus entries containing real H.264 Annex-B streams.

## [MEDIUM] `steam_protocol.rs` compares `Debug` strings instead of values for round-trip checks

- File: fuzz/fuzz_targets/steam_protocol.rs:42-48, 51-58
- Description: `SteamMessage` lacks `PartialEq`, so determinism and round-trip checks compare `format!("{:?}", ...)`. This is brittle: any nondeterministic or unstable field in the Debug impl (maps, pointers, unbounded strings) makes the asserts meaningless or flaky, and it allocates two strings per check inside the hot fuzz loop (plus `msg.clone()`). The deserialize/serialize round-trip is otherwise a good check and should be kept.
- Fix suggestion: Derive `PartialEq` (or add a semantic equality helper) for `SteamMessage` and `ExtendedHeader` and compare values directly.

## [MEDIUM] Duplicated and misnamed benchmark groups

- File: benches/perf_benchmarks.rs:1227-1262, 1299-1336, 943-1038, 643-664, 618-641
- Description: `bench_fast_thunk_inline_cache` (1227) and `bench_fast_thunk_tier_promotion` (1246) are identical copies of `bench_jit_inline_cache` / `bench_jit_tier_promotion` (different constants only) yet claim to measure "fast-thunk dispatch" — no `FastThunkTable` or dispatch code is touched. `bench_cpu_interpreter_throughput` (1299) is the same workload as `bench_cpu_full_pipeline` (373) with a free function instead of the engine wrapper. The three audio mix benches (943-1038) are near-identical, differing only in the configured `sample_rate`, which does not change the measured per-iteration work (fixed frame counts). `bench_gfx_upload_streaming` (643-664) measures only the O(1) bookkeeping of `GpuUploadStreamer::allocate` (src/perf.rs:866-919) — no bytes are uploaded. `bench_gfx_shader_compiler_submit` (618-641) measures job-queue insertion bookkeeping and allocates `format!("sha256:{i}")` Strings inside the measured region (allocation in measured region), while no shader is compiled.
- Fix suggestion: Delete the fast_thunk duplicates or make them exercise real fast-thunk dispatch; keep one interpreter benchmark; drop two of the three audio benches or vary frame counts; rename upload/shader benches to state they measure bookkeeping only, and move string construction out of the measured closure.

---

## [LOW] `pe_parser.rs` deep APIs are reachable only on valid PEs — no seed corpus

- File: fuzz/fuzz_targets/pe_parser.rs:16-43
- Description: This is the strongest target (exercises `find_resource_blob`, `parse_clr_header`, `find_resource_group_icons`, `map_image`, `build_activation_context` on top of `pe::parse`), but all of those run only when random fuzz bytes parse as a structurally valid PE, which is rare. Without corpus seeds containing real PEs, the extra APIs are effectively dead code in practice. Minor: the http_headers.rs fragment loop (lines 40-43) reruns Test 1 on 1..16-byte prefixes with no additional coverage.
- Fix suggestion: Add a `corpus/` directory of valid PE binaries (and real HTTP requests) so the deep paths are reached; drop the fragment loop.

## [LOW] `bench_gfx_upload_streaming` name overstates what is measured; ring wrap never tested

- File: benches/perf_benchmarks.rs:643-664
- Description: The bench measures `allocate()` only (a hash lookup + offset bump, src/perf.rs:866-919); the ring never wraps during a single iteration and the `AppResult` is discarded, so allocation failure or wrap behavior (the actual "streaming" semantics) is untested and invisible. 
- Fix suggestion: Assert `Ok` and, for a separate bench, iterate past ring capacity to exercise the wrap path.

---

## fuzz/Cargo.toml

- Structure is correct: all 14 `[[bin]]` entries (fuzz_targets/*.rs) are declared with `test = false, doc = false, bench = false`; `libfuzzer-sys = "0.4"` and the `casa1` path dependency are appropriate; `[workspace]` isolation is the standard cargo-fuzz layout. No wrong dependencies or features found. Note: because it is a standalone workspace, the fuzz targets are invisible to the root `cargo clippy --all-targets` invocation, which is why no clippy results reference them.

## Clippy

- Command: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` → **exit 101 (failed)**.
- `casa1` (lib): 19 errors (deny-level lints) + 1271 warnings; `casa1` (lib test): 27 errors + 1415 warnings (1262 duplicates).
- Error locations are all in src/: cpu.rs, pe_runtime.rs, d3d11.rs, dwrite.rs, metal_backend.rs, real_win32.rs, security.rs, seh.rs, winhttp.rs, crash_recovery.rs, d2d.rs, jit.rs, video_decoder.rs (e.g., "comparison involving the minimum or maximum element … always true", "approximate value of f64::consts::PI/TAU", "public function might dereference a raw pointer but is not marked unsafe", "calling set_len() immediately after reserving", "equal expressions as operands to &&/||", "operation will always return zero", "logic bug in boolean expression").
- **No warnings/errors reference any assigned file**: the bench target was never reached (clippy aborts after the lib test failure) and the fuzz targets live in a separate workspace. Recommend fixing the 19 deny-level lib errors first (they block all-target clippy runs for the whole crate), then re-running to lint benches.

## Build/test

- `CARGO_BUILD_JOBS=4 cargo test --test section_fuzz` → **exit 0, 11/11 tests passed** (0.00 s): fuzz regression fixtures and all explicit regressions (PE/HTTP/Steam/WinHTTP/WinINet) pass.
- `CARGO_BUILD_JOBS=4 cargo bench --no-run` → **exit 0**; `perf_benchmarks.rs` compiled cleanly (8 warnings in the lib itself — unreachable expression, unused variables — none in the bench file). No hang: completed within the session.
