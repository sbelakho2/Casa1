# Audit Findings

- Batch: seh-threads (Batch 1 of full-codebase audit)
- Files: `src/seh.rs` (3813 lines), `src/threads.rs` (2142 lines) — both read in full, in order
- Date: 2026-08-15
- Method: manual line-by-line review + `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (whole crate; see `## Build`)

---

## [HIGH] UWOP_SET_FPREG restores RSP with the wrong sign (add instead of subtract)

- File: src/seh.rs:494-500
- Description: Per the x64 UNWIND_INFO spec, UWOP_SET_FPREG establishes the frame register as `RSP_final + frame_offset*16` at the end of the prolog (e.g. `sub rsp, 0x100; lea rbp, [rsp+0x100]`), so the unwind effect must be `RSP = R[frame_reg] - frame_offset*16`. The code does `context.rsp = fp_val.wrapping_add(offset as u64)` — the wrong direction. For any nonzero `frame_offset` (valid range 0..240), RSP is restored 2×offset too high: saved-register reads, the return-address pop and every subsequent frame's unwind read garbage guest memory, yielding wrong registers/RIP and, potentially, an unwind that walks into unmapped memory or an infinite re-unwind. The existing test (`test_virtual_unwind_set_frame_pointer`) only exercises offset 0, where both formulas agree, so the bug is untested.
- Fix suggestion: Change to `context.rsp = fp_val.wrapping_sub(offset as u64);` and add a test with `frame_offset > 0` (e.g. header byte `(offset<<4)|reg`, codes `[PUSH, ALLOC, SET_FPREG]` with a `lea rbp,[rsp+N]` prolog).

## [HIGH] unwind_cache keyed by RVA only — cross-image RVA collision returns another image's unwind info

- File: src/seh.rs:1354-1365 (also 1462-1484, 1526-1544; cache field at 1301-1305)
- Description: `unwind_cache: HashMap<u32, UnwindInfo>` is keyed solely by RVA. `get_unwind_info`/`dispatch` scan `self.unwind_data` (all registered images, HashMap iteration order) and cache the first blob in which `parse_unwind_info(data, rva)` returns `Some`. Every PE image's unwind data starts near RVA 0x1000, and the JIT image (`JIT_IMAGE_BASE = 0`, registered in src/jit.rs:5695-5696) shares the same RVA space, so with two or more images the same RVA is cached from whichever blob is visited first and reused for the other image — wrong unwind codes → wrong register restores, garbage RIP, exception mis-dispatch. `parse_unwind_info` has no validation that the RVA actually falls inside a valid UNWIND_INFO, so "first parse wins" virtually always succeeds.
- Fix suggestion: Key the cache by `(image_base, rva)` (and make `get_unwind_info` take `image_base`), or store unwind data per-image with image-relative lookup, and clear/namespace the cache per image in `register_unwind_data` instead of one global RVA→info map.

## [HIGH] EHANDLER/UHANDLER frames are "handled" without ever invoking the handler — exceptions silently swallowed

- File: src/seh.rs:1487-1490 (also 1571-1577) and src/seh.rs:1257-1289 (`seh_dispatch`)
- Description: In `SehSubsystem::dispatch`, the moment any frame's UNWIND_INFO has `UNW_FLAG_EHANDLER`/`UNW_FLAG_UHANDLER` set, `dispatch` returns `Ok(())` — the language-specific handler is never called, can never decline (EXCEPTION_CONTINUE_SEARCH), and the exception record is never consulted. The runtime (src/pe_runtime.rs:48084 uses this on the fault path) treats this as "handled" and presumably retries the faulting instruction → livelock for any persistent fault in a function that has an exception handler, and total loss of catch/finally semantics. `seh_dispatch` is likewise a stub: it returns `HandlerFound` for the first scope whose range contains the fault RIP, with no language-handler invocation and no check of the exception code/params (its own comment at 1278-1281 admits this).
- Fix suggestion: Call the frame's handler (guest callback) before claiming success; propagate `EXCEPTION_CONTINUE_SEARCH` up the unwind when the handler declines, and only return Ok when the handler actually claims the exception. For `seh_dispatch`, invoke the scope's language handler and honor its return value instead of unconditionally returning `HandlerFound`.

## [HIGH] `unwind_frames` and `rtl_unwind` have unbounded frame walks — infinite loop on cyclic/corrupt guest stack

- File: src/seh.rs:672-736 (`unwind_frames`) and src/seh.rs:774-894 (`rtl_unwind`)
- Description: Both loops have no frame-count limit and no RSP-progress check (unlike `dispatch`, which has `MAX_UNWIND_FRAMES = 4096` at 1432 and a `prev_rsp` guard). In `virtual_unwind` the return-address pop advances `rsp += 8` unconditionally even when the memory read fails (seh.rs:585-590); if a guest-controlled stack repeatedly reads a return address inside the same mapped function (or the reader keeps failing), RIP stays in one function, RSP grows by 8 per iteration, `Completed` is returned forever, and both functions spin indefinitely (hang/DoS). `dispatch` is bounded and therefore safe; these two are not.
- Fix suggestion: Add the same `MAX_UNWIND_FRAMES` cap and `rsp > prev_rsp` progress check used in `dispatch` to both loops (and to the `frames_unwound` counter in `rtl_unwind`, which currently is only used to pick the Ok/Err message).

## [MEDIUM] `seh_dispatch` compares image-relative fault RVA against function-relative scope offsets

- File: src/seh.rs:1263-1282
- Description: `ScopeRecord` is documented as "Beginning offset (relative to function start)" (951-953), but `seh_dispatch` computes `fault_offset = rip - image_base` (image-relative RVA) and compares it directly against `scope.begin_offset/end_offset`. Unless the function happens to start at RVA 0, every in-scope check is shifted by the function's start offset, so guarded regions match at the wrong addresses (handlers claimed for unrelated faults or missed for real ones). The `ScopeTable.count` field is also ignored (`scopes` is iterated directly), so a table with `count != scopes.len()` misbehaves.
- Fix suggestion: Compute `fault_offset = fault_rva - function_begin_rva` (look up the enclosing RuntimeFunction first) before scope comparison, and either validate `count == scopes.len()` or drop the field.

## [MEDIUM] `rtl_restore_context`: bitwise-OR pattern where alternation was intended

- File: src/seh.rs:639-651
- Description: `match veh_result { EXCEPTION_CONTINUE_EXECUTION | EXCEPTION_HANDLED => ... }` — the pattern is the constant `-1 | 1 == -1`, i.e. it matches only `EXCEPTION_CONTINUE_EXECUTION`; `EXCEPTION_HANDLED` (1) falls through to `_`. Both arms currently return `Ok(())`, so behavior is unchanged today, but this is a latent bug: any future divergence between the arms (or a guest handler returning 1) will take the wrong path. Also, `rtl_restore_context` never actually transfers control / restores registers — it always returns Ok without applying the context (stub).
- Fix suggestion: Use `EXCEPTION_CONTINUE_EXECUTION | EXCEPTION_HANDLED =>` as two arms or `if veh_result != EXCEPTION_CONTINUE_SEARCH { return Ok(()) }`; apply the context registers before returning (or document the stub).

## [MEDIUM] Vectored continue handler dispatch has no re-entrancy guard

- File: src/seh.rs:1222-1248
- Description: `dispatch_vectored_handlers` is protected by the thread-local `VEH_DISPATCH_DEPTH` (max 8), but `dispatch_vectored_continue_handlers` is not. A continue handler that triggers an exception which the runtime re-dispatches (VEH → SEH → continue handlers) recurses without bound → host stack overflow. The recursion can be driven by guest handler code.
- Fix suggestion: Reuse `VehDepthGuard` (or add an equivalent guard) around `dispatch_vectored_continue_handlers`.

## [MEDIUM] PushMachineFrame arithmetic uses plain `+` on guest-controlled RSP — overflow panic in debug builds

- File: src/seh.rs:551, 558, 563
- Description: `context.rsp + rip_offset`, `context.rsp + rsp_offset`, `context.rsp += error_code_offset + 40` use non-wrapping arithmetic. RSP is validated only as nonzero/8-aligned (460), so a guest context with `rsp` near `u64::MAX` (e.g. `0xFFFF_FFFF_FFFF_FFD8`) overflows: panic in debug builds, silent wrap in release. Every other stack computation in this function uses `wrapping_add`; these three are inconsistent.
- Fix suggestion: Use `wrapping_add`/`wrapping_add`-based offsets consistently (or bounds-check `rsp` against a sane stack range).

## [LOW] `restore_context` is a stub that returns only RIP

- File: src/seh.rs:610-612
- Description: Documented as "Copies all register values from context into the CPU state, including RIP" but only returns `context.rip`; no register state is actually restored. Either incomplete by design (caller applies state) — then the doc is misleading — or unfinished logic.
- Fix suggestion: Either implement full context restore or update the doc and rename to reflect that it returns the target RIP.

## [LOW] Unknown/invalid UNWIND_INFO versions accepted silently

- File: src/seh.rs:181-183, 315-318
- Description: Version 0 and versions ≥ 2 are parsed and used as if valid (a test at 3473-3487 explicitly blesses this). Per the PE/COFF spec, only version 1 is defined; garbage version fields in corrupt .pdata produce mis-parsed unwind codes. Unknown UWOP opcodes are also silently skipped (316-317) rather than treated as a parse failure.
- Fix suggestion: Return `None` for `version != 1` (and optionally for unknown opcodes) so corrupt data fails closed instead of mis-unwinding.

## [LOW] Dead code: `_info` read, unreachable `HandlerFound` arm, log-only variable

- File: src/seh.rs:205-206 (`let _info = data[code_offset + 1];` — value never used); src/seh.rs:1571-1577 (the `HandlerFound` arm in `dispatch` is unreachable: if the frame had EHANDLER/UHANDLER flags it already returned at 1488, and CHAININFO frames return `Collided` at 581 before the handler check at 594); src/seh.rs:712 (`handler_address` computed only for `eprintln!`).
- Description: No functional impact, but the dead `HandlerFound` arm signals confusion about the dispatch contract (see the HIGH "swallowed handlers" finding).
- Fix suggestion: Remove or wire up; delete `_info`; drop `handler_address` or keep for logging only.

## [LOW] VEH chain: unbounded growth, lock-poisoning silently disables handlers, last-chance order differs from Windows

- File: src/seh.rs:1051-1068, 1136-1146, 1149-1167
- Description: (a) `VEH_CHAIN` grows without bound if the guest registers handlers repeatedly (no cap; Windows has none either, but guest-facing shims should be bounded); (b) every `if let Ok(chain) = VEH_CHAIN.lock()` silently skips on poison — after one poisoned lock, all handlers are permanently skipped; (c) last-chance handlers run in registration order, whereas Windows runs last-chance handlers in reverse registration order.
- Fix suggestion: Recover from poison with `lock_with_recovery`-style handling; iterate last-chance in reverse; optionally cap the chain.

## [PERF] `find_runtime_function` is a linear scan per frame per exception; per-fault allocation churn

- File: src/seh.rs:1346-1351, 1447-1449; 1129-1146, 1420
- Description: Each unwind step does an O(pdata_entries) scan (games have tens of thousands of RuntimeFunction entries), so a full exception dispatch is O(frames × entries). `dispatch_vectored_handlers` clones every handler Arc and the whole `ExceptionPointers` (record + context with 16 XMMs) on every fault, and `dispatch` clones the full `X64Context` — notable allocation cost on the fault path.
- Fix suggestion: Binary-search or sort+index the pdata table (entries are sorted by begin_addr in practice); snapshot only `Arc` handles; avoid the context clone by unwinding a borrowed copy only when mutation is actually needed.

---

## [HIGH] `GuestThreadPool::queue_work` spawns a new never-exiting OS thread per work item and discards the item

- File: src/threads.rs:579-622
- Description: Each `queue_work` call pushes a work item AND spawns a fresh OS thread (`std::thread::spawn` at 587) whose loop never terminates until pool shutdown. N queued work items → N threads (unbounded thread creation; each idles with a 10 ms sleep). Worse, the spawned worker pops the queue itself and throws the item away (`let _ = item;`, 611) — the guest callback is never executed by the pool thread, and `dequeue_work()` (620-622, documented as "called from pe_runtime's dispatch loop") races with the worker for the same pop. If the worker wins the race, the work item is permanently lost; guest callbacks silently never run. `Drop` (629-633) sets the shutdown flag but never joins the spawned threads.
- Fix suggestion: Keep a fixed worker-pool (like `EnhancedGuestThreadPool`), or have the spawned thread hand the item back (e.g. push to `completed_queue`) instead of discarding it; never pop from two places at once; join or detach threads on drop.

## [HIGH] `EnhancedGuestThreadPool` drops callback `context`/`flags`, and timers/wait registrations are never serviced

- File: src/threads.rs:1387-1393 (context lost), 1420-1460 (timers/waits), 1405-1417
- Description: Worker threads record only `item.callback` into `completed_queue` — the guest callback's `context` parameter and `flags` are dropped, so the runtime can only invoke the callback with the wrong (zeroed) parameter. Additionally, nothing in this file ever reads `timer_queue` or `wait_registrations`: `create_timer`/`delete_timer`/`register_wait` only mutate maps/vectors, no worker fires timers or polls wait handles, so CreateTimerQueueTimer/RegisterWaitForSingleObject callbacks never fire and `wait_registrations` grows without bound. `completed_queue` is also unbounded if the runtime doesn't drain it.
- Fix suggestion: Push the whole `ThreadPoolWorkItem` (or `(callback, context, flags)`) to `completed_queue`; add a servicing loop (or document that the runtime must poll and actually deliver timer/APC-style callbacks); bound `wait_registrations` and `completed_queue`.

## [MEDIUM] `condvar.wait(...).unwrap()` panics on poisoned mutex, defeating the poison-recovery design

- File: src/threads.rs:211, 255, 322, 370, 389, 855-869
- Description: `lock_with_recovery` deliberately survives mutex poisoning, but every condition-variable wait is `state = self.condvar.wait(state).unwrap()` (and `wait_timeout_while(...).unwrap()` / `wait_while(...).unwrap()` in `sleep_cs`). `Condvar::wait` re-locks the guard's mutex, and std returns `Err(PoisonError)` when that mutex is poisoned — so after any host panic inside a guest mutex holder, every subsequent waiter panics instead of recovering, cascading the panic across all guest threads. This contradicts the documented WAIT_ABANDONED recovery semantics (lines 27-33).
- Fix suggestion: Replace the unwraps with poison recovery (e.g. `match self.condvar.wait(state) { Ok(g) => g, Err(p) => p.into_inner() }`) in `GuestMutex::acquire`, `GuestSemaphore::wait`, `GuestEvent::wait`, `GuestSRWLock::acquire_exclusive/acquire_shared` and `sleep_cs`.

## [MEDIUM] `GuestSRWLock`: mismatched `release_shared` deadlocks the lock forever; writer starvation

- File: src/threads.rs:396-402 (release), 367-372, 386-392 (acquires)
- Description: `release_shared` unconditionally decrements with no underflow guard: a single erroneous release at state 0 leaves state = −1, after which `acquire_shared` blocks forever (`while *state < 0`) and `acquire_exclusive` blocks forever (`while *state != 0`) — a permanent, unrecoverable deadlock of the whole lock (guest code can trigger this via a double release). Separately, `acquire_exclusive` has no writer preference: a continuous stream of `acquire_shared` calls can starve the writer indefinitely (Windows SRW locks have a bias/fairness mechanism).
- Fix suggestion: Validate release calls (track owner/reader counts and reject underflow, or clamp with an error), and add writer-preference (e.g. block new readers while an exclusive waiter is pending).

## [MEDIUM] `GuestBarrier::new(0)` → `wait()` never returns

- File: src/threads.rs:460-464
- Description: `StdBarrier::new(0)` does not panic (verified on rustc 1.96), but with 0 participants every `wait()` increments a count that can never equal 0, so all callers block forever. A guest requesting a barrier with count 0 hangs the calling thread permanently. (Also, on a barrier created with a larger count, the extra `participant_count` field is never kept in sync with the std barrier if it's ever re-initialized.)
- Fix suggestion: Reject 0 (`if participant_count == 0 { ... error/return }`) or map it to an immediate no-op; consider storing the count in one place only.

## [MEDIUM] Global `FIBER_MANAGER` mutex: fibers are process-global, but Windows fibers are per-thread

- File: src/threads.rs:1155-1162, 1231-1261
- Description: All guest threads share one `FIBER_MANAGER` and a single `current_fiber_id`. Two guest threads switching fibers concurrently on different host threads mutate each other's current-fiber state (the manager's `current_fiber_id` and each fiber's `is_executing`), so a fiber switch on thread A can be observed as "current" by thread B, and `save_current_state` can save the wrong thread's CPU state into the wrong fiber. There is also lock contention on every fiber operation (every SwitchToFiber serializes through the global mutex).
- Fix suggestion: Keep fiber state per guest thread (e.g. a thread-local/`BTreeMap<thread_id, GuestFiberManager>`), or at minimum validate that switch targets belong to the same thread.

## [MEDIUM] `create_fiber` with a guest-supplied `stack_size` panics on mmap failure

- File: src/threads.rs:961-981, 1193-1203
- Description: `MmapStack::new` panics (`panic!("mmap...failed")` and `expect("stack size overflow")`) when the OS refuses the allocation. `stack_size` originates from the guest (CreateFiber/ConvertThreadToFiberEx shims pass it through), so a guest can request an absurd size and crash the host process instead of getting an error. (mmap failure is also possible under normal memory pressure.)
- Fix suggestion: Return `Result`/`Option` from `MmapStack::new` and `create_fiber`, and map failure to an `AppError` (Windows returns NULL + ERROR_NOT_ENOUGH_MEMORY).

## [MEDIUM] `GuestInitOnce`: a panicking init closure poisons `std::sync::Once` and every later `call_once` panics

- File: src/threads.rs:443-446
- Description: If the init closure panics, `std::sync::Once` replays the panic for every subsequent `call_once` (the `completed` flag stays false). Guest-controlled init callbacks that fault therefore turn every later InitOnce caller into a host panic.
- Fix suggestion: Wrap the closure: `self.inner.call_once(|| { let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)); if r.is_err() { /* reset Once via Once::reset() (unstable) or track failure */ } })`, or track a `failed` flag and return an error instead of re-running.

## [LOW] `MutexState.abandoned` is never set — WAIT_ABANDONED semantics absent

- File: src/threads.rs:163-170, 229-233
- Description: `abandoned` is written nowhere (always false), so `is_abandoned()` can never return true and the documented "abandoned mutex detected at the guest level via WAIT_ABANDONED" behavior (lines 27-33) is dead code. A guest whose owner thread terminates without release will deadlock new waiters instead of observing abandonment.
- Fix suggestion: Set `abandoned = true` when a thread is removed from the registry while owning the mutex (and reset it on next acquire), then expose the flag to the shim.

## [LOW] `GuestApcQueue::deliver` silently discards APCs

- File: src/threads.rs:686-720
- Description: `deliver()` pops APCs, logs them, and throws them away (`let _ = apc;`); the callbacks are never invoked or returned. The real API is `deliver_apcs()` (1488-1513). `deliver()` is dead/misleading code — a caller using it loses every APC.
- Fix suggestion: Remove `deliver()` or make it delegate to `deliver_apcs` and return the entries.

## [LOW] `GuestFiberContext::initialize_state` underflows RSP for the primary fiber

- File: src/threads.rs:1106-1114
- Description: `state.gpr[4] = self.stack_base - 8;` — the primary fiber (`new_from_thread`) has `stack_base = 0`, so RSP wraps to `0xFFFF_FFFF_FFFF_FFF8`. If anything calls `initialize_state` on the primary fiber, the guest runs with a garbage stack pointer. (Created fibers are safe: their stack_base ≥ 4096.)
- Fix suggestion: Return an error/skip for `stack_allocation.is_none()` fibers, or initialize primary-fiber RSP from the actual thread stack.

## [LOW] `switch_to` stores the wrong `previous_fiber`; `delete_fiber` can leave `current_fiber_id` dangling

- File: src/threads.rs:1242, 1264-1276
- Description: `current.previous_fiber = Some(target_id)` stores the fiber being switched TO (the next fiber), not the fiber that ran before the current one, so any consumer of `previous_fiber` gets the inverse. `delete_fiber` removes the fiber but does not update `current_fiber_id` if the deleted fiber was current, leaving subsequent `save_current_state`/`switch_to` operating on a stale ID (get_mut then silently no-ops).
- Fix suggestion: Set `previous_fiber = Some(current_id)` before switching (or drop the field); clear/adjust `current_fiber_id` in `delete_fiber`.

## [LOW] `GuestSemaphore::release` saturating-add edge case; IOCP uses unbounded channel + wrong error code

- File: src/threads.rs:264-275; 497-510
- Description: (a) With `count == u32::MAX` (and `max_count == u32::MAX`), `saturating_add` makes `new_count == count`, so the release "succeeds" without incrementing and still notifies a waiter — spurious wakeup and wrong return value. (b) `GuestIoCompletionPort` uses an unbounded channel (unbounded queue growth if producers outpace consumers), and `post` failure maps to `ReasonCode::RcUnimplInsn` ("unimplemented instruction") — wrong error classification for a send failure.
- Fix suggestion: Use `checked_add` and reject overflow; bound the channel (or document); map send failure to a meaningful reason code (e.g. a resource/handle error).

## [LOW] Redundant unsafe `Send`/`Sync` impls; pools' `Drop` never joins worker threads

- File: src/threads.rs:547-548; 629-633, 1473-1477
- Description: `SharedGuestState` only contains `Arc<Mutex<...>>`/`AtomicBool`/`CpuEngineConfig` (enums, Strings, BTreeSet — all auto `Send + Sync`), so the `unsafe impl Send/Sync` is unnecessary; if `CpuEngineConfig` or `MemoryImage` ever gains a non-`Send` field, the unsafe impl silently becomes unsound. Both pools set `shutdown` in `Drop` but never `join` their `JoinHandle`s, so workers are dropped detached (they exit within one poll interval, so the leak is small — but a join on drop would make shutdown deterministic).
- Fix suggestion: Remove the unsafe impls (or add a static_assert-style check); join worker handles in `Drop` with a short timeout.

## [PERF] Polling loops with 5-10 ms sleeps and eager worker threads

- File: src/threads.rs:613 (10 ms), 1395 (5 ms), 913 (5 ms), 1369-1402 (workers spawned eagerly in `start()`)
- Description: `GuestThreadPool` workers, `EnhancedGuestThreadPool` workers, and `sleep_with_polling` all busy-poll with fixed sleeps even when idle — each idle pool thread wakes ~100-200 times/second and burns CPU; `sleep_with_polling`'s wake detection latency is up to 5 ms (and if the `pump` closure always returns true it never sleeps at all). `EnhancedGuestThreadPool::start` spawns `num_workers` threads immediately, even with no work queued.
- Fix suggestion: Use the condvar (`wake_generation` + `notify`) for real blocking instead of polling when a pump is not required, or sleep longer (e.g. exponential backoff) when queues are empty; spawn workers lazily on first `queue_work`.

---

## Clippy

Run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt`

Diagnostics referencing the audited files (lib + lib test):

- **ERROR (deny-by-default `clippy::erasing_op`, breaks the build)** — src/seh.rs:1978:32 — `(0 & 0x1f) << 3` is always zero (test helper `make_unwind_info`). Fix: compute flags arithmetically (e.g. `flags << 3`) or use a constant.
- Warnings, src/seh.rs:
  - `clippy::identity_op` ("this operation has no effect"): 1978:18, 2003:18, 2095:18, 2388:18, 2595:18, 2655:18, 2659:18 (test byte-building, `(0 << 4) | op`).
  - `clippy::collapsible_if`: 481, 506, 517, 594.
  - `clippy::clone_on_copy` (`RuntimeFunction`): 799, 1377.
  - `clippy::for_kv_map` ("iterate on a map's values"): 1357, 1469, 1532.
  - `clippy::derivable_impls`: 88 (X64Context Default can be derived).
  - `clippy::doc_markdown` (doc list item overindented): 752, 753, 755, 762, 763.
  - `clippy::vec_init_then_push`: 1637, 1824, 1977, 2087, 2381, 2588, 2648.
  - `clippy::unusual_byte_groupings` (hex digit grouping): 1667, 1777, 1791, 2565, 2776, 2823, 2897, 2974, 2993, 3167, 3393, 3406, 3548, 3662, 3771.
  - `clippy::useless_vec`: 2374.
  - `clippy::field_reassign_with_default`: ~50 occurrences in tests (1913-1914, 2173-2174, 2191-2192, 2227-2228, 2268-2269, 2355-2356, 2429-2430, 2462-2463, 2485-2486, 2538-2539, 2628-2629, 2698-2699, 2803-2804, 2856-2857, 2920-2921, 2950-2951, 2978-2979, 3108-3109, 3144-3145, 3203-3204, 3425-3427, 3683-3684, 3707-3708, 3717-3718, 3727-3728).
- Warnings, src/threads.rs:
  - `clippy::new_without_default`: 173 (GuestMutex), 356 (GuestSRWLock), 436 (GuestInitOnce), 570 (GuestThreadPool), 1175 (GuestFiberManager).
  - `clippy::collapsible_if`: 905, 1290.
  - `clippy::needless_if`: 1269-1270 (delete_fiber callback loop).
  - `clippy::doc_markdown` (doc list item without indentation): 348.

All warnings above are stylistic/`#[cfg(test)]`-only except the build-breaking error at seh.rs:1978:32.

## Build

- `cargo clippy --all-targets --no-deps` **FAILED**: "could not compile `casa1` (lib) due to 19 previous errors; could not compile `casa1` (lib test) due to 27 previous errors" — the crate does not pass clippy as configured. Of those, exactly **one error is in the audited scope**: src/seh.rs:1978:32 (`clippy::erasing_op`, deny-by-default, in `#[cfg(test)]` code). The remaining errors are in other files (src/d2d.rs, src/d3d11.rs, and others — outside this batch's scope). Type-checking itself succeeded for the audited files (all errors are lint-level). `--all-features` was not used (missing system ffmpeg is environmental and was ignored, per instructions).

---

## Summary

- CRITICAL: 0
- HIGH: 6
- MEDIUM: 9
- LOW: 10
- PERF: 3
- Total findings: 28 (build additionally broken by 1 in-scope clippy error; 4 in-scope HIGHs are in `seh.rs` production paths (`dispatch`, `virtual_unwind`, unwind cache) — the top fixes are the SET_FPREG sign, the RVA-only unwind cache, and invoking handlers instead of swallowing exceptions.)
