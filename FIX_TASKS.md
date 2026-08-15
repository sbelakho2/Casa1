# AUDIT_FINDINGS.md

**Batch:** Casa1 diagnostics/perf/telemetry/trace audit
**Files:** `src/diagnostics.rs` (2836 lines), `src/perf.rs` (2252 lines), `src/telemetry.rs` (1145 lines), `src/trace.rs` (577 lines) — all lines read
**Date:** 2026-08-15

---

## [HIGH] `build_minidump` writes the CONTEXT blob at end-of-file, not at `context_rva`

- File: `src/diagnostics.rs:2355` (step 3c/3d), `2257-2265` (RVA computation)
- Description: After all stream slots are emitted in RVA order (3c), `cursor` is already past `context_rva` (which lies between the exception stream and SystemInfo). In step 3d the padding loop `while cursor < context_rva` never executes, so `final_buf.extend_from_slice(&context_data)` *appends* the CONTEXT at EOF. The exception stream's `context_stream_rva` therefore points at zero padding followed by SystemInfo bytes, and the real CONTEXT sits at an unexpected trailing offset. Any consumer (WinDbg, breakpad, etc.) reading `ThreadContext` gets garbage; the directory/stream layout no longer matches the file layout. The existing tests only check the header, so this goes unnoticed.
- Fix suggestion: Emit the context in position in the single ordered pass — e.g., in the 3c loop, when `cursor == context_rva`, write `context_data` before the next slot; drop the post-hoc 3d/3e logic. Add a test asserting `buf[context_rva..context_rva + context_size]` equals the context bytes.

---

## [MEDIUM] `MinidumpExceptionStream` omits `ThreadContext.data_size` (164 vs 168 spec bytes)

- File: `src/diagnostics.rs:1844`, `2413`
- Description: Spec `MINIDUMP_EXCEPTION_STREAM` ends with a `MINIDUMP_LOCATION_DESCRIPTOR ThreadContext` (`data_size` + `rva`, 8 bytes). The code writes only a `u32` rva (4 bytes), so the stream and its directory `data_size` are 4 bytes short and the context size is unknown to consumers (verified: struct size 164, spec 168).
- Fix suggestion: Replace `context_stream_rva: u32` with `thread_context: MinidumpLocationDescriptor` and set `data_size = context_data.len()`.

## [MEDIUM] `MinidumpContext` layout deviates from the real AMD64 CONTEXT

- File: `src/diagnostics.rs:1855`, `1913`
- Description: Only 6 debug registers (`dr0..dr3, dr6, dr7`) are declared — the real CONTEXT has 8 (`Dr4`/`Dr5` reserved) — shifting every field after `dr3` by 16 bytes. The XMM0-15 / VectorRegister area after `FloatSave` is absent. Total size is 912 bytes vs 1232 for the real `CONTEXT_AMD64` (the internal test asserting 912 passes because it matches this nonstandard layout). `context_flags` advertises `CONTEXT_FULL | CONTEXT_AMD64` including `CONTEXT_FLOATING_POINT`, so a debugger walking registers reads past the blob into the next stream.
- Fix suggestion: Match the real layout (add `dr4`, `dr5`, and the XMM/vector register arrays), or stop advertising `CONTEXT_FLOATING_POINT`/`CONTEXT_DEBUG_REGISTERS` and document the shortened context; assert the size against the known AMD64 CONTEXT size.

## [MEDIUM] `MinidumpHeader` field offsets are wrong (36 vs 32 spec bytes)

- File: `src/diagnostics.rs:1808`, `2325`
- Description: An extra `_reserved: u32` between `check_sum` and `time_date_stamp` shifts `time_date_stamp` to offset 24 and `flags` to offset 28. Spec header is 32 bytes: `CheckSum@16, TimeDateStamp@20, Flags@24`. The internal parser (`parse_minidump_header` reads flags at offset 24) disagrees with the writer's own layout, so a round-tripped dump reports the timestamp value as flags (verified: struct size 36).
- Fix suggestion: Remove the `_reserved` field (header is 32 bytes) and keep the 128-byte pad before the directory.

## [MEDIUM] `MinidumpSystemInfo` is 16 bytes short (40 vs 56 spec bytes)

- File: `src/diagnostics.rs:1959`, `2433`
- Description: `_reserved: [u32; 3]` provides 12 bytes where the spec has `SuiteMask` (u32) + `Reserved2[3]` (u32×3) = 16 bytes after `csd_version_rva` (verified: struct size 40, spec 56). Consumers read the SuiteMask at a wrong offset / truncated stream.
- Fix suggestion: Add `suite_mask: u32` followed by `_reserved2: [u32; 3]`.

## [MEDIUM] `export_diagnostics` can zip itself and re-zip previous exports; slurps whole files

- File: `src/diagnostics.rs:195` (`File::create` at 198, `WalkDir` at 207, `read_to_end` at 235)
- Description: The output zip is created *before* the walk. If `output_zip` is inside `ge.root` (typical: diagnostics dir), the walk includes the just-created empty zip (archived as a 0-byte entry into itself), and repeated runs nest every previous zip into the new one — unbounded growth of the archive and of the source tree. Independently, each file is fully read into RAM (`read_to_end`), so a multi-GB log spikes memory.
- Fix suggestion: Skip any path that canonicalizes to the output zip (compare canonicalized paths), and stream file contents into the ZipWriter with `io::copy` instead of buffering whole files.

## [MEDIUM] Network-resilience stress test can deadlock when a connect fails

- File: `src/diagnostics.rs:1669`, `1676`
- Description: The helper thread blocks in `listener.accept()` (first or second accept). If the client's initial `TcpStream::connect` fails, or the reconnect connect fails, the main thread calls `helper.join()` while the helper waits forever for a connection that will never arrive on that listener — the stress test hangs.
- Fix suggestion: Don't join unconditionally. Make the helper exit on accept failure/error with a bounded wait (e.g., nonblocking accept + short sleep budget), or drive the helper with a channel so it exits when the client gives up.

## [MEDIUM] `BlockChainingCache` chain bookkeeping: duplicate chains, stale chains, unbounded `chains` growth

- File: `src/perf.rs:125` (`try_chain`), `169` (`break_chain`), `246` (`invalidate_range`)
- Description: `try_chain` has no `is_chained` guard, so repeated calls push duplicate `BlockChain` entries for the same from/to, inflating `total_chains_active` and growing `chains` without bound. `break_chain` only marks entries inactive (never removes them), so the Vec grows forever and every break is O(n). `invalidate_range` removes blocks but leaves chains whose `from_address` was removed counted as active.
- Fix suggestion: Return early in `try_chain` when `block.is_chained`; prune inactive chains (or periodically compact); in `invalidate_range`, deactivate chains whose from/to blocks were removed.

## [MEDIUM] `ParallelShaderCompiler` retains completed/failed jobs forever

- File: `src/perf.rs:552`
- Description: `jobs` is a `BTreeMap` with no removal/purge API — every submitted job (per unique shader hash) is retained for the process lifetime. Over long sessions this is unbounded memory growth, and `pending_jobs()` rescans the entire map on each call.
- Fix suggestion: Add a prune/purge for terminal (`Completed`/`Failed`) jobs with an LRU cap or age threshold; track pending jobs in a queue instead of scanning all jobs.

## [MEDIUM] `GpuUploadStreamer::allocate` silently overlaps in-flight allocations within a frame

- File: `src/perf.rs:883`
- Description: When `write_offset + size > buffer.size`, the code wraps `write_offset` back to 0 even *within the same frame* (no generation check), handing out an offset that may still be in use by an earlier allocation of the same frame. Later uploads to that offset overwrite live data — GPU data corruption. The second check against `ring_buffer_size` (lines 899-911) makes the behavior even less predictable when `buffer.size != ring_buffer_size`.
- Fix suggestion: Only wrap on a frame boundary (`frame_used != frame`); otherwise return an error (or allocate from a fresh buffer) when the current frame's remaining space is insufficient. Use `checked_add` for `write_offset + size`.

---

## [LOW] `compare_frames` with mismatched dimensions silently compares misaligned data

- File: `src/diagnostics.rs:929`
- Description: `compute_ssim`/`compute_psnr` use `captured`'s width/height but index both buffers with those strides. A reference of different dimensions passes the byte-count check and is compared row-misaligned, yielding plausible-looking but wrong SSIM/PSNR/pass verdicts.
- Fix suggestion: Fail or warn explicitly when `captured.width != reference.width || captured.height != reference.height`.

## [LOW] Unnecessary `unsafe` block around `libc::geteuid`

- File: `src/diagnostics.rs:616`
- Description: `geteuid` is not an unsafe function; the `unsafe` block adds no value and invites copy-paste of unsafe patterns.
- Fix suggestion: `let euid = libc::geteuid() as u32;`

## [LOW] `probe_filesystem` write probe is limited to `<root>/tmp` — false negatives and litter

- File: `src/diagnostics.rs:592`
- Description: The writable probe only exercises `<root>/tmp`; if that subdirectory cannot be created (root writable but `tmp` missing) the probe reports `writable=false` even though the GE is writable. If `remove_file` fails, a probe file is left behind.
- Fix suggestion: Probe directly in `path` (or create and remove the `tmp` directory itself) and clean up on the error path.

## [LOW] Dead statement `let _ = current_rva + size;`

- File: `src/diagnostics.rs:2318`
- Description: Leftover from a refactor; the Memory64List slot RVA is never advanced (harmless today only because it is the last stream). Misleading for future edits.
- Fix suggestion: Remove the statement (or actually track the RVA).

## [LOW] Integer robustness in pixel helpers (u32 wraps / u32→usize truncation)

- File: `src/diagnostics.rs:922` (`pixel_count as u32`), `973`, `1031` (`w * h * 4` in u32)
- Description: `compute_pixel_diff` truncates totals above 4 Gpix; `detect_text_regions`/`verify_color_space` compute `w*h*4` in u32 (wraps for dims > ~2^30 px). No OOB occurs (inner loops bounds-check), but results silently degrade.
- Fix suggestion: Do all dimension math in `usize` with `checked_mul`, returning an error/empty result on overflow.

## [LOW] `BehavioralVerifier::run_browse_store` ignores its `url` argument

- File: `src/diagnostics.rs:1370`
- Description: Always calls `request_package_info(0)`; the `url` parameter is dead. The recorded step name (`BrowseStore(url)`) can disagree with what actually ran.
- Fix suggestion: Either use `url` (if the protocol stack supports it) or drop the parameter and document the stub behavior.

## [LOW] Stress-test memory/GPU leak tests don't exercise leak paths

- File: `src/diagnostics.rs:1512`, `1554`
- Description: The allocator closure is only polled 100 times with no allocation activity between samples; any monotonic allocator (high-water-mark GPU heap, arena) triggers false positives, and genuine leaks between iterations are missed. The 1%/1024-byte and 5% thresholds are arbitrary.
- Fix suggestion: Allocate/free a controlled workload between samples (e.g., the closure should allocate and release per iteration) and base the verdict on end-vs-start after a defined workload.

## [LOW] `MmappedFile` exposes a raw `ptr`; `Send`/`Sync` rely on caller discipline

- File: `src/perf.rs:1507`, `1515`
- Description: `pub ptr: *mut u8` can be copied out and dereferenced after `close()`/`drop()` (munmap) — use-after-free. The `unsafe impl Send/Sync` is only sound if callers never copy the pointer and never mutate concurrently.
- Fix suggestion: Make the pointer private, expose only bounds-checked `read`, and document the Send/Sync contract; consider a generation/arc-guarded handle.

## [LOW] Telemetry persistence uses a fixed `{path}.tmp` — cross-process clobber, stale temp

- File: `src/telemetry.rs:274`
- Description: Two processes with the same persistence path can overwrite each other's temp file and rename the other process's (possibly half-written) data into place; a crash between write and rename leaks a `.tmp` file forever.
- Fix suggestion: Use a unique temp name (pid + random suffix), and remove the temp file on write failure.

## [LOW] Duplicated condition in `map_import_to_gap`

- File: `src/telemetry.rs:646`
- Description: `dll_lower.contains("d3d10") || dll_lower.contains("d3d10")` — identical operands; the second arm was probably meant for a different name (e.g. `"d3d10_1"`). Dead condition; D3D10-family DLLs may be misclassified.
- Fix suggestion: Replace the second operand with the intended name or drop the duplicate.

## [LOW] `merge_events` re-indexes events by merge order, not by time

- File: `src/trace.rs:245`
- Description: Runner events are indexed 0..n before guest events, so `event_index` does not reflect the true chronological sequence across the two sources; consumers relying on `event_index` ordering get a wrong timeline.
- Fix suggestion: Sort merged events by a timestamp/sequence field before re-indexing, or document that ordering is runner-then-guest.

---

## [PERF] `export_diagnostics` slurps every file fully into memory

- File: `src/diagnostics.rs:235`
- Description: `read_to_end` per file — a GE tree with multi-GB logs/streams causes multi-GB peak RSS during export.
- Fix suggestion: Stream with `io::copy` from the file to the ZipWriter.

## [PERF] `AddressTranslationCache::insert` does an O(n) full-map scan per insertion

- File: `src/perf.rs:463` (also `lookup` at 447)
- Description: LRU eviction runs `min_by_key` over every entry — O(n) per insert on the page-translation hot path; `lookup` also performs three hash probes (contains_key + get_mut + get).
- Fix suggestion: Use a doubly-linked LRU list (or clock/second-chance) and a single `get_mut` in `lookup`.

## [PERF] `AsyncFileReader::submit_read` reads the entire file for a ranged request

- File: `src/perf.rs:1191`
- Description: `std::fs::read(&path)` loads the whole file even when only `size` bytes at `offset` are requested — memory spike equal to file size and I/O proportional to it, defeating the offset/size API.
- Fix suggestion: Open the file in the worker and `seek(offset)` + `read_exact(take(size))`.

## [PERF] `FileCache::insert` eviction is O(n²) per burst

- File: `src/perf.rs:1349`
- Description: Each eviction rescans all entries via `min_by_key`; inserting k files into a full cache costs O(k·n) with repeated clones of keys.
- Fix suggestion: Keep an ordered structure by `last_access` (e.g., BTreeMap<(u64, String), …>) for O(log n) eviction.

## [PERF] `TelemetryCollector` persists the full JSON file on every record

- File: `src/telemetry.rs:193` (`maybe_persist` at 513)
- Description: Every `record_*` call takes three mutexes (enabled, data, persistence_path) and, when a persistence path is set, synchronously serializes and writes the entire dataset to disk *per event* — and these recorders sit on emulation failure paths (unsupported imports/instructions, COM dispatch). Large datasets make this O(dataset) per record.
- Fix suggestion: Batch persistence (periodic flush / flush on drop / dirty flag), and replace the `enabled` Mutex with an atomic flag checked before locking `data`.

---

## Clippy

`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` — unique warnings referencing the audited files (all LOW-style; see Build note below for why the run aborted):

**src/diagnostics.rs**
- `:1433` let_and_return (`run_full_workflow` returns a let binding)
- `:1622` collapsible_if (network-resilience test)
- `:1745` collapsible_if (multi-game cycling test)

**src/perf.rs**
- `:60` new_without_default (`BlockChainingCache`)
- `:343` let_and_return (`LazyJitProfiler::record_execution`)
- `:449` collapsible_if (`AddressTranslationCache::lookup`)
- `:465` collapsible_if (`AddressTranslationCache::insert`)
- `:777` collapsible_if (`flush_current_batch`)
- `:1164` new_without_default (`AsyncFileReader`)
- `:1355` collapsible_if (`FileCache` eviction)
- `:1428` new_without_default (`PathResolutionCache`)

**src/telemetry.rs**
- `:77` derivable_impls (`Default for TelemetryData`)
- `:333`, `:337`, `:341`, `:346`, `:454` unnecessary_sort_by (`sort_by` on frequency → `sort_by_key`)
- `:515` collapsible_if (`maybe_persist`)
- `:1043` len_zero (test)

**src/trace.rs**
- `:533` needless_borrows_for_generic_args (test)

## Build

The clippy run **did not complete**: `casa1` (lib) failed with 19 errors and `casa1` (lib test) with 27 errors, all clippy deny-by-default lints located in files **outside this audit's scope** — e.g. `src/security.rs:3097` (eq_op), `src/d2d.rs:974` (erasing_op), `src/dwrite.rs:1398` (logic bug), `src/winhttp.rs:3624` (eq_op), `src/pe_runtime.rs:48799` (set_len on reserved buffer), `src/jit.rs:34`, `src/metal_backend.rs:1237`, `src/video_decoder.rs:573` (missing_safety_doc), `src/cpu.rs` (approx constants), plus further `f64`-constant lints. No error referenced `src/diagnostics.rs`, `src/perf.rs`, `src/telemetry.rs`, or `src/trace.rs`; the crate itself currently does not pass `cargo clippy --all-targets`. This is a code-lint failure in other modules, not the environmental ffmpeg issue.
