# AUDIT_FINDINGS.md

- **Batch:** audit-win32 (fresh worktree `audit-win32`, baseline `d0f8283`)
- **File:** `src/win32.rs` — 4993 lines, read in full (4 sequential passes, lines 1–4993)
- **Date:** 2026-08-15
- **Severity counts:** CRITICAL 4 · HIGH 4 · MEDIUM 11 · LOW 10 · PERF 5 — **34 findings total**
- **Method:** line-by-line read + `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (whole crate; see `## Build`)

---

## [CRITICAL] `read_file` panics on slice when file position is beyond EOF

- File: src/win32.rs:1797
- Description: `let start = file.position as usize; let end = start.saturating_add(length).min(bytes.len()); Ok(bytes[start..end].to_vec())`. `set_file_pointer_ex` (line 1945) rejects only *negative* pointers, so a guest may seek past EOF (e.g. `SetFilePointerEx(h, 1000, FILE_BEGIN)` on a 5-byte file). Then `start > bytes.len()` while `end = bytes.len()`, giving `bytes[start..end]` with `start > end` → slice-index panic. Fully reachable from guest-controlled file operations; crashes the emulator process.
- Fix suggestion: clamp `start` first: `let start = (file.position as usize).min(bytes.len());` then `let end = start.saturating_add(length).min(bytes.len());`.

## [CRITICAL] `write_file` position arithmetic overflows / aborts on huge seek positions

- File: src/win32.rs:1843
- Description: `let start = file.position as usize;` then `contents.resize(start, 0)` and `contents.resize(start + bytes.len(), 0)` with unchecked `start + bytes.len()`. A guest that seeks to `u64::MAX` (allowed by `set_file_pointer_ex`, only negative rejected) and writes any data will either overflow-panic (debug) or attempt a ~16 EiB `Vec` allocation → allocator abort (release). Same pattern in `write_file_overlapped` (lines 2289–2296).
- Fix suggestion: bound the position before use: reject/error when `file.position > isize::MAX as u64` (or clamp to a sane cap), and use `checked_add(start, bytes.len())` with an `RcMemoryAccessViolation` error on overflow.

## [CRITICAL] `wait_for_multiple_objects` wait-all with auto-reset objects loops forever (hang, 100% CPU)

- File: src/win32.rs:1521
- Description: With `wait_all == true`, the first pass (line 1522) calls `wait_for_single_object` which **consumes** auto-reset event signals (and acquires mutexes / decrements semaphore counts). The second pass (line 1539 `all_signaled`) then re-waits on the same handles, which now fail for auto-reset events / owned mutexes, so `all_signaled` is never true. With `timeout_ms == u32::MAX` (INFINITE) the deadline is `None` (line 1502) and `timeout_ms != 0` is true, so the `sleep(1ms)` loop never exits → infinite hang with ~1ms-spaced polling forever. Even finite timeouts burn ~1000 iterations/sec of polling. Unit test `wait_for_multiple_objects_wait_all` (line 4682) only covers manual-reset events and codifies the broken Timeout-index convention.
- Fix suggestion: compute signal state non-destructively for the wait-all check (peek: check `signaled`/`owner_thread_id.is_none()`/`count > 0` without mutating), or track the results of the first pass; for INFINITE timeout use a real blocking wait (condvar) or cap iterations.

## [CRITICAL] `map_view_of_file` panics via `next_power_of_two` on guest-controlled size

- File: src/win32.rs:3172
- Description: `let size = bytes_to_map.max(0x1000).next_power_of_two();` — `usize::next_power_of_two()` panics on overflow (input > 2^63 on 64-bit). `bytes_to_map` is derived from the guest's `MapViewOfFile` size and is not validated. Also note the mapping ignores `offset`/`bytes_to_map` entirely and never ties the region to the section's backing `data` (see MEDIUM below).
- Fix suggestion: use `checked_next_power_of_two()` and return an `AppError` (e.g. `RcCliInvalid`) on `None`/overflow.

---

## [HIGH] `call_named_pipe` writes into a dead buffer and completes overlapped requests with 0 bytes

- File: src/win32.rs:2431
- Description: `pipe.buffer = request.to_vec();` stores the request into `PipeObject.buffer`, but every read path (`read_file` lines 1805–1817, `peek_named_pipe`, `call_named_pipe_w`) reads from `self.named_pipes[name].buffer` — `PipeObject.buffer` is never read anywhere. Data written via `call_named_pipe` is therefore invisible to the server. Additionally the completion uses `request.len_hint(request_id_len(request, request_id_len_inner(request))) as u32` (line 2446), a chain of identity functions (`PipeRequestLen` trait lines 4163–4179) that always evaluates to **0**, so `bytes_transferred` is always 0. The function also returns the request echo as the "response" (line 2455).
- Fix suggestion: write the request into the shared `NamedPipeState.buffer` (as `call_named_pipe_w` does) and remove the `PipeRequestLen`/`request_id_len`/`request_id_len_inner` dead chain, completing the overlapped request with the actual byte count (or 0 for a pure-connect completion).

## [HIGH] `open_named_event` can never return a handle

- File: src/win32.rs:1613
- Description: The chain `get(name).and_then(upgrade).and_then(|_event_rc| { ... None })` unconditionally evaluates to `None` — `OpenEvent` by name always fails even when the event exists. The comment says "Return the first handle matching this named event" but no handle is ever returned. The `create_event` path (line 1088) has the name→`Weak` mapping available.
- Fix suggestion: store the event name on the `EventObject` (or maintain a name→handle map like `named_mutexes`), then return the handle from the upgrade branch instead of `None`.

## [HIGH] Named mutex/semaphore name tables hold stale closed handles forever

- File: src/win32.rs:1578
- Description: `named_mutexes` / `named_semaphores` map name→Handle, but `close_handle` never removes these entries. After the guest closes a named mutex/semaphore, `create_named_mutex` with the same name returns the dead handle value (which is never reused since `next_handle` is monotonic), and every subsequent wait/`release_mutex` on it fails with "invalid handle". Same issue for `named_pipes` (HIGH finding below). Windows semantics require a fresh object after the last handle closes.
- Fix suggestion: in `close_handle`, when the entry's object is a Mutex/Semaphore (and refcount reaches 0), remove its name from `named_mutexes`/`named_semaphores`; or validate the stored handle is still live before returning it.

## [HIGH] `named_pipes` entries never removed on close; recreate of same pipe name always fails

- File: src/win32.rs:2853
- Description: `create_named_pipe_w` errors with `RcFsAlreadyExists` if the name is in `self.named_pipes` (line 2853), but nothing ever removes entries from `named_pipes` when pipe handles are closed or disconnected. A server that closes its pipe and tries to recreate it (normal Win32 pattern, e.g. accept-loop) permanently fails. The `Arc<Mutex<VecDeque<u8>>>` buffer also keeps all stale data alive forever.
- Fix suggestion: remove the `named_pipes` entry when the last pipe handle for that name is closed in `close_handle` (track per-name handle counts or scan `handles`), and clear `connected`/buffer when a server endpoint is closed.

---

## [MEDIUM] Inconsistent "already existed" flag between `create_event` and `create_named_mutex`/`create_named_semaphore`

- File: src/win32.rs:1578
- Description: `create_event` returns `(handle, true)` when the named event already exists and `(handle, false)` when newly created (lines 1088–1114). `create_named_mutex` (line 1578–1584) and `create_named_semaphore` (line 1599–1605) return the *opposite*: `(handle, false)` for existing and `(handle, true)` for newly created. Callers of `CreateMutex`/`CreateSemaphore` that check "existed" (for `ERROR_ALREADY_EXISTS` / initial-ownership semantics) get inverted results depending on which function they use.
- Fix suggestion: pick one convention (mirror `create_event`: second element = existed) and apply it to all three, updating callers.

## [MEDIUM] Timeout return index `handles.len() - 1` violates Win32 wait semantics

- File: src/win32.rs:1552
- Description: `WaitForMultipleObjects` returns `WAIT_TIMEOUT` (0x102) on timeout, not an index. Returning `handles.len().saturating_sub(1)` (lines 1552, 1568) yields 0 for an empty slice and an apparently-valid index otherwise; a caller that uses the index when `status != Timeout`-discriminated can index an unsignaled handle. The unit tests at lines 4692–4707 codify this behavior.
- Fix suggestion: return the index only for `Object0`/`Abandoned`; on timeout return a sentinel (`usize::MAX`) or restructure the API so the index is `Option<usize>`.

## [MEDIUM] `wait_for_single_object` never actually blocks; nonzero timeouts return spurious Timeout

- File: src/win32.rs:1395
- Description: For events/mutexes/semaphores/threads/timers the `timeout_ms` parameter is ignored ("timeout_ms unused in non-blocking path") and the wait returns immediately with `Timeout` when not signaled. A guest that does `WaitForSingleObject(event, 5000)` expecting to block gets an instant timeout and will busy-loop. Only the `Process` path blocks (via condvar). This is a semantic gap vs. Windows that is easy for guest code to trip over.
- Fix suggestion: implement a tick-based wait loop honoring `timeout_ms` (similar to `wait_for_multiple_objects`'s deadline loop) or explicitly document/handle in the caller that waits are non-blocking.

## [MEDIUM] `get_overlapped_result` with `wait=true` errors instead of blocking

- File: src/win32.rs:2341
- Description: `OverlappedState::Pending if wait` returns `RcWin32Timeout` immediately. `GetOverlappedResult(..., bWait=TRUE)` must block until the overlapped op completes (or fail only on error). Guest code doing a blocking `GetOverlappedResult` will see a spurious failure.
- Fix suggestion: loop on the request state with a sleep+recheck until `Completed`/`Cancelled` (bounded by the pending IO's expected completion), or return `Pending` and let the caller retry.

## [MEDIUM] `map_view_of_file` ignores offset/size and never associates the region with section data

- File: src/win32.rs:3168
- Description: `let _offset = offset; let _bytes_to_map = bytes_to_map;` — both parameters are discarded; the resulting `VirtualRegion` has no link to the `SharedMemorySection`'s `Arc<Mutex<Vec<u8>>>`, and only a single page is committed (`BTreeSet::from([base])`) regardless of `size`. Guest reads at the returned address will never observe the section's contents, and `MapViewOfFile` with non-zero offset reads the wrong data. `UnmapViewOfFile` also blindly removes any region.
- Fix suggestion: store a back-reference to the section (`Arc<Mutex<Vec<u8>>>` or mmap) in `VirtualRegion` and have the memory model route accesses to it; honor `offset` by starting the view at `data[offset..offset+bytes_to_map]` and commit all pages in `size`.

## [MEDIUM] `read_file_overlapped` offset+length addition can overflow

- File: src/win32.rs:2252
- Description: `let end = ((offset as usize) + length).min(bytes.len());` — `offset + length` is unchecked; with a guest-supplied near-`u64::MAX` offset it overflow-panics in debug builds and silently wraps in release (wrong byte counts). 
- Fix suggestion: use `offset as usize` saturating/clamped before adding: `let start = (offset as usize).min(bytes.len()); let end = start.saturating_add(length).min(bytes.len());` and derive `transferred` from that.

## [MEDIUM] `get_named_pipe_info` returns hardcoded wrong values

- File: src/win32.rs:2931
- Description: Returns `(1, 1, max_size, max_size)` — pipe mode is hardcoded to `1` (PIPE_NOWAIT) even for pipes created with `PIPE_WAIT` (stored in `state.pipe_mode`), `max_instances` is hardcoded to `1` (ignores `state.max_instances`), and the computed `cur_size` (`let cur = ...`) is discarded.
- Fix suggestion: return `(state.pipe_mode & 0x3, state.max_instances, out_size, in_size)` from `NamedPipeState`, using the actual stored values.

## [MEDIUM] `connect_named_pipe_internal` non-overlapped path errors instead of blocking

- File: src/win32.rs:2405
- Description: When `overlapped == false` and the pipe is not yet connected, the function returns `RcPipeBusy` immediately. Win32 `ConnectNamedPipe` with a non-overlapped handle blocks until a client connects. Server accept-loops using blocking `ConnectNamedPipe` will fail instantly.
- Fix suggestion: for the non-overlapped case, poll `state.connected` on the `data_ready` condvar (or the shared state) until connected, honoring the caller's timeout if any.

## [MEDIUM] Heap allocator never reuses freed space; monotonic `next_address` leaks address space

- File: src/win32.rs:2603
- Description: `heap_alloc`/`heap_realloc` only ever bump `state.next_address` (`address + size + alignment`); `heap_free` removes the allocation but the slot is never reclaimed. A guest heap that alloc/frees in a loop (common) will grow the "high-water" pointer without bound and eventually collide/overflow; `heap_realloc` also always *moves* allocations, invalidating pointers even when in-place growth would be possible.
- Fix suggestion: maintain a free list of freed (address, size) blocks, reuse them in `heap_alloc`, and try in-place growth in `heap_realloc` when the next block is free.

## [MEDIUM] Guest-controlled unbounded `Vec` allocations abort instead of failing

- File: src/win32.rs:2604
- Description: `heap_alloc` (`vec![0_u8; size]`, line 2604), `create_file_mapping_w` (`vec![0_u8; maximum_size.max(1)]`, line 3124) and `create_named_pipe_w` (`VecDeque::with_capacity(buf_size)`, line 2876) allocate directly from guest-supplied sizes. Windows `HeapAlloc`/`CreateFileMapping`/`CreateNamedPipe` fail gracefully (`ERROR_NOT_ENOUGH_MEMORY`); here an absurd size aborts the process (Rust OOM abort). 
- Fix suggestion: cap sizes (e.g. refuse > `isize::MAX`, or a configurable per-API limit) and return an `AppError` (RcCliInvalid / RcIo) instead of allocating.

## [MEDIUM] `virtual_alloc` at a fixed address can commit outside the region and clobber protection

- File: src/win32.rs:2470
- Description: `memory_regions.entry(base).or_insert_with(...)` reuses an existing region, then unconditionally overwrites `region.protection` and commits `page_count` pages computed from the *new* size. A second `VirtualAlloc(addr, larger_size, MEM_COMMIT)` commits pages beyond the region's `size`, which `virtual_query` (line 2524, `address < base + size`) reports as free while the committed set disagrees; the protection change also affects the pre-existing region. `virtual_free(Decommit)` (line 2497) ignores the requested range and decommits the whole region.
- Fix suggestion: on an existing region, extend `region.size` to `max(old, new)` before committing; only apply the new protection to the new range; make decommit range-aware (or at least verify the range).

---

## [LOW] Dead `live_pacing` field and identity-only `paced_sleep_duration_ms`

- File: src/win32.rs:772
- Description: `TimeState.live_pacing` is set in `new_with_live_pacing` (line 859) but never read anywhere; `paced_sleep_duration_ms` (line 4059) ignores its `_live_pacing` argument and is only exercised by tests. Consequence: in non-DTM mode there is no real-time pacing of `Sleep` (host sleeps 1 ms regardless, line 3366), so guest timing drifts from wall-clock — likely intended to be controlled by `live_pacing`.
- Fix suggestion: either wire `live_pacing` into `sleep`/`sleep_ex` (host-sleep the full requested duration when enabled) or remove the field and function.

## [LOW] `server_disconnected` is written but never read

- File: src/win32.rs:624
- Description: Set in `disconnect_named_pipe` (line 3001), never consulted anywhere; disconnect state is only partially reflected (`connected = false`).
- Fix suggestion: either use it in `wait_named_pipe_w`/`connect_named_pipe`/`read_file` semantics or remove it.

## [LOW] `IoCompletionAssociation` fields and `concurrent_threads` are dead

- File: src/win32.rs:746
- Description: `port_handle`/`completion_key` carry `#[allow(dead_code)]` and are never read after `create_io_completion_port` inserts them; `IoCompletionPortObject.concurrent_threads` is copied to `_concurrent_threads` and dropped (line 1202). `concurrent_threads` affects Windows completion-port throttling semantics.
- Fix suggestion: remove the dead fields, or use `concurrent_threads` in `dequeue_io_completion_packets`.

## [LOW] Handle-generation machinery is ineffective because handle values are never reused

- File: src/win32.rs:3853
- Description: `next_handle` is monotonic (`saturating_add(4)`), so closed handle values are never reallocated and `handle_generations` is only ever read as `0` (line 3854); generation checks can never fail on a live handle. The test `handle_reuse_gets_new_generation_after_close` (line 4495) is vacuous: `next_handle` cannot wrap with 258 allocations, so `h2 == h1` never holds.
- Fix suggestion: implement actual handle-value recycling (free list of closed values + generation increment on close) or drop the generation machinery and its tests.

## [LOW] `close_handle` refcount>1 path is unreachable

- File: src/win32.rs:1769
- Description: `entry.descriptor.refcount` is set to 1 in `insert_object` (line 3862) and never incremented anywhere (duplication creates a new handle value via `insert_object`), so the `refcount -= 1; re-insert` branch can never execute.
- Fix suggestion: remove the branch, or increment refcount when `duplicate_handle` shares the same underlying object and only close the ge handle at refcount 0.

## [LOW] `open_named_pipe_client` clones shared-buffer Arcs then discards them

- File: src/win32.rs:3064
- Description: `let (_buf, _ready) = { ... (state.buffer.clone(), state.data_ready.clone()) }` — the cloned `Arc`s are immediately dropped; the returned `PipeObject` has no connection to the shared buffer (it works only because `read_file`/`write_file` re-lookup by name). Misleading and fragile.
- Fix suggestion: store the `Arc<Mutex<VecDeque<u8>>>`/`Arc<Condvar>` on `PipeObject` and use them directly in `read_file`/`write_file`, or delete the clones.

## [LOW] `tls_alloc` slot counter can wrap

- File: src/win32.rs:3291
- Description: `self.next_tls_slot += 1` is unchecked u32 arithmetic; after 2^32 `TlsAlloc` calls it wraps and starts handing out already-in-use slot indices.
- Fix suggestion: saturating add with an error, or a free-list.

## [LOW] `get_temp_file_name_w` can return the same name for consecutive calls

- File: src/win32.rs:2217
- Description: Uniqueness is derived from `self.next_handle`, which only advances on handle creation. Two consecutive `GetTempFileNameW` calls with the same prefix/directory (no handle created in between) produce identical names; the second `fs::write` silently truncates the first file. Windows guarantees unique names.
- Fix suggestion: maintain a dedicated monotonic counter (or include a timestamp) for temp-file names.

## [LOW] `set_named_pipe_handle_state` stores `mode` without the PIPE_WAIT/NOWAIT mask

- File: src/win32.rs:2955
- Description: `state.pipe_mode = mode;` stores the raw value, while `create_named_pipe_w` masks with `pipe_mode & 0x0000_0003` (line 2883); `get_named_pipe_info`/wait semantics then see inconsistent mode bits.
- Fix suggestion: apply the same `& 0x0000_0003` mask (plus READMODE bit handling) as in creation.

## [LOW] `next_handle` saturation silently aliases handles after 2^30 allocations

- File: src/win32.rs:3853
- Description: After `next_handle` saturates at `u32::MAX`, every subsequent `insert_object` reuses the same value, overwriting the existing map entry → handle aliasing and double-close of unrelated objects. Impractical today but the guard is absent.
- Fix suggestion: detect saturation (`next_handle == u32::MAX`) and return an error from `insert_object`, or use a proper free-list.

## [LOW] `thread_apcs` and `com_apartments` entries leak on thread exit

- File: src/win32.rs:819
- Description: `thread_apcs`/`com_apartments` are keyed by thread id and never cleaned in `cleanup_exited_thread_state`; guests that spawn/join many threads with queued APCs or CoInitializeEx accumulate unbounded entries.
- Fix suggestion: remove the thread's entries in `cleanup_exited_thread_state` (and `threads.remove`).

## [LOW] `sleep_ex`/`sleep` report success where Windows may return `WAIT_IO_COMPLETION`

- File: src/win32.rs:3389
- Description: Fine when no APC is pending; but after the alertable check pops one APC, the function still advances the clock and sleeps — acceptable, though the comment/API contract isn't documented. Minor; no action strictly required.

---

## [PERF] Every `write_file` triggers a full config save to disk

- File: src/win32.rs:1875
- Description: `write_file` → `sync_entry` (line 1875) → `self.ge.save_config()` (line 3745) serializes the entire `GameEnvironment` config JSON after **every** write. Games writing logs/saves in a loop pay a full-config serialization + disk write per syscall. Same for `stage_host_file_w`, `create_file_w`, temp files, `move_file_ex_w`, `copy_file_ex_w`.
- Fix suggestion: batch/dirty-flag config persistence (save on explicit flush, exit, or throttled timer) instead of per-operation.

## [PERF] `read_file`/`write_file` read and rewrite the entire file per call

- File: src/win32.rs:1790
- Description: `read_file` does `fs::read(&file.host_path)` (whole file into memory) then slices; `write_file` (lines 1832–1857) reads the whole file, resizes, and `fs::write`s the whole file back. For any multi-MB file this is O(file size) per syscall and O(n²) across a download/streaming workload, with repeated allocations.
- Fix suggestion: keep a real `File` handle (via `OpenOptions`) and use `seek`/`read`/`write` at the current position; use the existing `ge_handle` for I/O.

## [PERF] `virtual_query` is a linear scan of all regions per call

- File: src/win32.rs:2523
- Description: Every `VirtualQuery` iterates the whole `memory_regions` BTreeMap; games querying memory in loops (allocation probes, heap walks) get O(n) per query / O(n²) total. Also `region.base_address + region.size as u64` can overflow for regions at high addresses.
- Fix suggestion: keep regions in an ordered structure and binary-search the containing region (BTreeMap keys already sorted — use `range(..=address)` and take the last), and use `checked_add`.

## [PERF] `overlapped` request map grows without bound

- File: src/win32.rs:3900
- Description: `insert_overlapped` (line 3900) inserts into `self.overlapped`, but nothing ever removes entries (`cancel_io_ex`/`get_overlapped_result` only read/mutate state). Long-running guests with continuous overlapped I/O leak one entry (handle + event + state) per op — unbounded memory growth.
- Fix suggestion: remove the entry from `get_overlapped_result` on completion, and in `cancel_io_ex` when the request is final.

## [PERF] Unbounded per-handle/per-name bookkeeping maps

- File: src/win32.rs:3855
- Description: `handle_history` grows one entry per handle value ever allocated (never pruned), `shared_memory_sections` entries are never removed (named sections persist forever, and each carries an unused `MmapBacking` — a real mmap per named section, lines 3125–3130), and `time.drift_log` grows without bound for sleeps with drift (lines 3399–3405).
- Fix suggestion: prune `handle_history` (keep recent N), remove `shared_memory_sections` entries when the last handle to a named section closes, drop or reuse the `mmap_backing`, and cap `drift_log`.

---

## Clippy

`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` — warnings referencing `src/win32.rs` (all style-level; no correctness warnings for this file):

| Line | Lint | Note |
|---|---|---|
| 165 | `needless_as_bytes` | `input.as_bytes().len()` → `input.len()` |
| 600 | `collapsible_str_replace` | two `replace` → `replace(['\\','/'], "_")` |
| 1088, 1371, 1374, 1508, 1509, 1510, 1511, 1550, 2431, 2953, 3375, 3378, 4215 | `collapsible_if` | nested `if let` chains |
| 1530 | `collapsible_match` | `if !wait_all` into match guard |
| 1615 | `unnecessary_lazy_evaluations` | `and_then(|_| ... None)` (see HIGH finding on `open_named_event`) |
| 1634, 2839 | `too_many_arguments` | `create_file_w` (8), `create_named_pipe_w` (11) |
| 3338 | `unnecessary_sort_by` | use `sort_by_key` |
| 3988 | `manual_is_multiple_of` | `backslashes % 2 == 0` |
| 4961 | `single_match` (test) | `match result` → `if let` |

## Build

Whole-crate clippy **failed to complete**: `casa1` (lib) — 19 errors; `casa1` (lib test) — 27 errors. **None of the errors are in `src/win32.rs`** (verified: all error sites are in e.g. `src/crash_recovery.rs:536`, `src/d3d11.rs:3687`, `src/jit.rs:34`, `src/pe_runtime.rs`, plus `not_unsafe_ptr_arg_deref`/`uninit_vec`/`logic_bug`/`approx_constant` errors in other files). Because the crate failed, later-file diagnostics may be incomplete, but `win32.rs` was fully checked; its 19 warnings are listed above. The `--all-features` flag was not used (missing system ffmpeg is environmental, per instructions).
