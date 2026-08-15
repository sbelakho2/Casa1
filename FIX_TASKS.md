# Audit Findings — src/steam_integration.rs

- **Batch:** Casa1 code audit (worktree `audit-steam-integration`)
- **Files:** `src/steam_integration.rs` (5071 lines, whole file)
- **Lines:** 1–5071 (read in sequential chunks, every line covered)
- **Date:** 2026-08-15
- **Method:** manual line-by-line review + `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (full run, see `clippy_out.txt`)

---

## [CRITICAL] Unbounded allocation from attacker-controlled length prefix in Steam IPC

- File: src/steam_integration.rs:897 (also :932)
- Description: `SteamIpcManager::send_message` reads a 4-byte length from the peer and does `let response_len = u32::from_le_bytes(len_buf) as usize; let mut response = vec![0u8; response_len];` with no cap. `receive_message` does the same for `msg_len`. The listener is bound on `127.0.0.1:<port>` (default 57343), so any local process (or a misbehaving service) can connect and send a length of `0xFFFFFFFF`, forcing a ~4 GiB allocation → OOM abort of the whole emulator process. Reachable from untrusted network input.
- Fix suggestion: Cap lengths (e.g. reject `len > 16 MiB` or `len > max_msg_size` config) before allocating; allocate incrementally with a fixed-size buffer, or use `try_reserve` and return `AppError` on failure.

## [CRITICAL] Path traversal: cloud sync writes remote file names outside the storage directory

- File: src/steam_integration.rs:3509 (loop), :3533–3541, :3711–3738
- Description: `sync_from_cloud` takes `rel_path` keys from the untrusted sync-server JSON listing and passes them to `file_write`, which does `self.base_path.join(rel_path)` with no containment check. A server (or MITM) returning `"../../../../.ssh/authorized_keys"` (or any `..` path, absolute path) causes arbitrary host file writes. `ensure_parent_dir` also joins the untrusted path.
- Fix suggestion: Validate every `rel_path` before use: reject absolute paths and any component equal to `..` (e.g. normalize with `Path::components()` and verify no `Component::ParentDir`/`RootDir`/`Prefix`), or resolve `base_path.join(rel)` and require it starts with `base_path`.

## [CRITICAL] Path traversal: depot manifest filenames written outside output_dir

- File: src/steam_integration.rs:1286
- Description: In `SteamClient::download_app`, `let file_output = output_dir.join(&manifest.filename);` where `manifest.filename` comes from the CM-server-provided depot manifest payload (`parse_depot_manifest(&msg.payload, None)`), i.e. untrusted network data. A manifest entry containing `..` (or an absolute path) escapes `output_dir` and overwrites arbitrary files, which is then written by `download_file`.
- Fix suggestion: Sanitize `manifest.filename` the same way as above (reject `..` components and absolute paths) before joining with `output_dir`.

## [CRITICAL] Password transmitted in plaintext as a deliberate fallback

- File: src/steam_integration.rs:1241–1251
- Description: `encrypt_password` falls back from RSA-OAEP to an XOR "session key" cipher, and finally to `pw_bytes.to_vec()` — sending the user's Steam password unencrypted over the network when the RSA key and session key are unavailable (e.g. degraded handshake). Credential exposure on the auth path; the "AES" fallback is a trivially reversible XOR, not real encryption.
- Fix suggestion: Never transmit raw credentials. Fail the login with an explicit `AppError` (e.g. "no encryption key available, refusing to send plaintext password") instead of falling through to plaintext; remove or properly implement the XOR fallback.

---

## [HIGH] IPC request/response protocol can never complete — `send_message` hangs forever

- File: src/steam_integration.rs:859–909, :915–955
- Description: `send_message` connects a fresh TCP stream to the loopback port, writes a length-prefixed message, then blocks in `read_exact` waiting for a response. Nothing in `SteamIpcManager` ever writes a response: `receive_message` accepts one connection, reads the request, and drops the stream without replying; no thread services the listener (`listener` is only polled when `receive_message` is explicitly called). Every `send_message` therefore blocks indefinitely (blocking socket, no timeout) unless some unrelated process listens on the port. This deadlocks any caller thread.
- Fix suggestion: Either implement a real responder loop (accept + parse + reply) servicing the listener, or give `send_message` a read timeout (e.g. `TcpStream::set_read_timeout`) and treat a timeout as an error; document the intended responder.

## [HIGH] `assert_eq!` on network-derived state can panic in `connect_and_login`

- File: src/steam_integration.rs:1132
- Description: After `self.stack.connect(server)?`, the code asserts `assert_eq!(self.stack.state, ConnectionState::Ready)`. `connect` performs a network handshake against a server-controlled endpoint; if it returns `Ok` without leaving the stack in `Ready` (stub mode, protocol variant, error-path quirk), the process panics. Panic reachable from untrusted input.
- Fix suggestion: Replace the assertion with an explicit check returning `AppError::new(ReasonCode::RcWin32Timeout, ...)` (or `RcNetProtocolError`) when `state != ConnectionState::Ready`.

## [HIGH] Failed cloud download truncates local file and marks it Synced (silent data loss)

- File: src/steam_integration.rs:3536, :3543–3555
- Description: `sync_from_cloud` does `let data = dl_resp.bytes().unwrap_or_default();` — any transfer/decoding error becomes an empty byte slice, which is then `file_write`n (truncating the existing local file to 0 bytes) and recorded as `SyncStatus::Synced` with the remote mtime. The file is then never retried (remote mtime is no longer newer), so the corruption is permanent.
- Fix suggestion: On `bytes()` error (or empty body for a non-empty remote file), skip the download, leave the file untouched, log an error, and keep the previous sync status so it is retried on the next sync.

## [HIGH] `SteamServiceProcess::start` blocks for the entire service lifetime

- File: src/steam_integration.rs:476–500
- Description: `pe_runtime::execute` (verified at `src/pe_runtime.rs:4008–4027`) runs the guest PE synchronously to completion and returns `PeExecutionResult` only when the program exits. SteamService.exe is a long-running service, so `start()` (and hence `SteamIpcManager::start`) blocks the calling thread for the whole service lifetime; `ServiceState` stays `Starting`, `stop()` is unreachable, and stub pipe responses report "not running". State is only set to `Running`/`Error` after the process exits.
- Fix suggestion: Spawn the service on a dedicated thread (or use the native `std::process::Command` path for the PE case via a runner subprocess) and set state `Running` immediately after launch; or treat the PE path as non-blocking with an explicit exit callback.

---

## [MEDIUM] `detect_changes` has a dead branch; `SyncStatus::Conflict` is never produced

- File: src/steam_integration.rs:3614–3626
- Description: Inside the "not synced before" branch the condition is `*current_mtime > state.remote_mtime` and the inner `if` tests the *identical* condition (`if *current_mtime > state.remote_mtime { SyncStatus::LocalChanged } else { SyncStatus::RemoteChanged }`), so the `else` (RemoteChanged) is dead code and both-sides-changed files are always labeled `LocalChanged`. `SyncStatus::Conflict` is never set anywhere, yet `sync_from_cloud` contains a `Conflict` branch, making last-write-wins conflict resolution effectively local-always-wins.
- Fix suggestion: Track both sides independently (local mtime vs stored `state.local_mtime` and remote mtime vs `state.remote_mtime`) and set `Conflict` when both changed; remove the duplicated condition.

## [MEDIUM] `receive_messages_on_listen_socket` ignores the listen-socket handle

- File: src/steam_integration.rs:1602–1607
- Description: The method discards `_listen_handle` and returns `gns.poll_incoming_messages()` — i.e. all messages from all sessions, regardless of which listen socket they belong to. A game polling one listen socket can receive messages intended for another listen socket / connection, causing cross-game or cross-session misrouting.
- Fix suggestion: Track which connections belong to which listen socket in `listen_sockets` and filter `poll_incoming_messages()` results by the connection handles recorded for `_listen_handle`.

## [MEDIUM] `pipe_requests` queue grows without bound

- File: src/steam_integration.rs:577–578, :670–672
- Description: `handle_pipe_request` pushes every request (`request.to_vec()` plus `Instant`) into `pipe_requests`; nothing in the codebase drains it (`drain_pipe_requests` has no callers found in `src/`). Every `CreatePipe`/`CallNamedPipe` request from Steam.exe accumulates memory indefinitely.
- Fix suggestion: Drain or bound the queue — e.g. cap at N entries (drop oldest), or only queue when the consumer is registered; otherwise remove the queue entirely.

## [MEDIUM] `indicate_achievement_progress` auto-unlock is not persisted and uses wrong unlock time

- File: src/steam_integration.rs:2508–2515
- Description: When progress reaches max, `self.achievements.insert(name.to_string(), 1)` stores unlock time `1` (1970) instead of the current epoch seconds used by `set_achievement`, and — unlike `set_achievement` — never calls `save_to_config`, so the unlock is lost on restart while progress bars report it unlocked.
- Fix suggestion: Reuse the same timestamp logic as `set_achievement` (UNIX_EPOCH seconds) and call `save_to_config()` after the insert.

## [MEDIUM] `write_screenshot` never validates RGBA buffer size; unchecked dimension arithmetic

- File: src/steam_integration.rs:4017–4023, :4206–4268
- Description: `let _expected = (width as usize) * (height as usize) * 4;` is computed and discarded; `encode_rgba_to_png` silently emits a corrupt PNG when `rgba.len() != width*height*4` (rows truncated/skipped). Width/height come from the guest via FFI; huge values cause `raw_len = height * (1 + width*4)` to wrap (release) or overflow (debug) and drive a giant allocation/loop, i.e. a guest-triggerable DoS with no bounds check.
- Fix suggestion: Validate `rgba.len() == width*height*4` (checked multiply) and return an `AppError` on mismatch; use checked arithmetic for `raw_len`/`stride` and cap dimensions.

## [MEDIUM] Unescaped key character breaks (or breaks out of) injected overlay JavaScript

- File: src/steam_integration.rs:2055–2075
- Description: `key_char` is interpolated as `format!("'{}'", c)` into a JS `KeyboardEvent` constructor without escaping. For `'` or `\` the generated script is a JS syntax error, so those keystrokes are silently dropped (and the string could escape the literal if the char set grows beyond a single char). All overlay JS injection sites share this pattern.
- Fix suggestion: Emit the key as a numeric code (e.g. `String::from_utf8_lossy` + JSON-encode, or use `keyCode` only and pass `key: ''`), or escape with `serde_json::to_string(&c.to_string())`.

## [MEDIUM] `build_command_line` joins args with spaces without quoting

- File: src/steam_integration.rs:117–135
- Description: `args.join(" ")` produces an ambiguous command line when `ge_root` (and thus the Steam.exe path) or any `launch_args` element contains spaces (common on macOS: `/Users/John Doe/...`). The line is re-split somewhere downstream, mis-parsing the executable path and arguments.
- Fix suggestion: Quote each argument containing whitespace (wrap in `"` with inner-`"` escaping) or pass an argument vector instead of a joined string.

## [MEDIUM] Cross-app collision: single global stats/friends config per user

- File: src/steam_integration.rs:2236–2244, :2599–2607
- Description: `SteamUserStats` and `SteamFriends` persist to one fixed file (`~/Library/Application Support/Casa1/config/user_stats.json`, `friends_config.json`) with no app-id partitioning. Stats/achievements from different games (and different GE roots) with the same names overwrite each other, and games see each other's leaderboards.
- Fix suggestion: Key the config path (or the JSON contents) by app id / GE root, e.g. `user_stats_{app_id}.json`, or store per-app sections in the snapshot.

## [MEDIUM] Cloud upload/download URLs are not percent-encoded

- File: src/steam_integration.rs:3393, :3533
- Description: `format!("{server_url}/api/v1/cloud/upload/{rel_path}")` and the download equivalent interpolate raw file names into URLs. Names containing spaces, `#`, `?`, or `%` produce malformed requests (or address the wrong server resource).
- Fix suggestion: Percent-encode each path segment (e.g. `urlencoding`/`percent-encoding` crate) before formatting the URL.

## [MEDIUM] `flush_message_on_connection` loses queued messages on send error

- File: src/steam_integration.rs:1698–1703
- Description: The whole `pending_outgoing` batch is removed from the map before sending; if any `gns.send_message` fails (`?`), the remaining queued messages are silently dropped (data loss) rather than kept for retry.
- Fix suggestion: Send all messages first and only remove the successfully flushed ones (or remove on success at the end, keeping the batch on error).

---

## [PERF] Per-call allocation + sort in index-based getters (hot API surface)

- File: src/steam_integration.rs:2346–2350, :2440–2444, :2720–2723, :2759–2762, :2816–2819, :3005–3008, :3032–3036, :3115–3118, :3795–3806, :3931–3936
- Description: Every call to `get_achievement_name`, `get_leaderboard_name`, `get_friend_by_index`, `get_invite_by_index`, `get_clan_by_index`, `get_lobby_by_index`, `get_lobby_member_by_index`, `get_lobby_search_result`, `get_file_name/size`, `get_ugc_item_name` builds a fresh `Vec` (and sorts) of keys. Games poll these getters in render loops → O(n) allocation + O(n log n) per call.
- Fix suggestion: Cache a sorted key `Vec` per map, invalidated on mutation (or store an insertion-order Vec alongside the map), and return `Option` indexes into it.

## [PERF] Unbounded in-memory collections

- File: src/steam_integration.rs:2791–2800 (`chat_messages` per friend), :3085–3098 (lobby `chat_messages`), :3955–3957 (`screenshots` Vec), :1094/1323–1327 (`lobby_sessions`), :1720–1730 (`pending_outgoing`)
- Description: Chat histories, screenshot entries, per-peer GNS sessions, and flush queues grow forever with no trimming, eviction, or close path (sessions created in `send_lobby_message`/`send_message_to_user` are never closed). Long sessions leak memory linearly.
- Fix suggestion: Cap histories (ring buffer or trim to N), evict idle GNS sessions (e.g. LRU), close sessions when peers go offline, and bound `pending_outgoing` per connection.

## [PERF] Full-tree directory walks for size/count queries

- File: src/steam_integration.rs:238–242, :993–999
- Description: `verify_installation` walks the entire Steam tree just to count files, and `scan_library` walks every game directory recursively to sum sizes. On large installs (shadercache/htmlcache with 100k+ files) these are multi-second blocking syscall storms.
- Fix suggestion: Skip `shadercache`/`htmlcache`/`dumps` when counting, use `metadata` of manifest files for sizes, or make the scans async/off-thread.

## [PERF] Cloud sync loads whole files into memory

- File: src/steam_integration.rs:3384 (`fs::read`), :3536 (`dl_resp.bytes()`)
- Description: `sync_to_cloud` reads each local file fully into RAM and `sync_from_cloud` downloads each remote file fully into memory before writing. Multi-GB saves cause large transient allocations.
- Fix suggestion: Stream with `std::io::copy` between file and request/response bodies instead of materializing whole buffers.

---

## [LOW] Dead fields / dead data

- File: src/steam_integration.rs:799 (`SteamIpcManager::stream` never used), :347 (`attempted_native` never read), :3959 (`SteamScreenshots::locations` written, never read), :3596 (`let _now = ...` unused), :4018 (`let _expected = ...` unused)
- Description: Unused state and locals that indicate unfinished wiring or are pure noise.
- Fix suggestion: Remove the fields/local bindings, or wire them to the intended behavior (e.g. actually use `stream` for connection reuse, `attempted_native` for fallback logic).

## [LOW] `connection_details` is write-mostly dead; status reads come from GNS

- File: src/steam_integration.rs:1494–1495, :1705–1707, :1724–1730, :1653–1662
- Description: `ConnectionDetail`/`connection_details` are populated (pending_reliable) but `get_connection_status` reads `gns.connection_state()` instead, so the details map is never consumed; `ConnectionDetail` duplicates `SteamNetworkingConnectionStatus`.
- Fix suggestion: Populate `SteamNetworkingConnectionStatus` from `connection_details` (or delete the dead map/struct).

## [LOW] `dispatch_url` reports success for unimplemented actions

- File: src/steam_integration.rs:719–762
- Description: `LaunchGame`, `NavigateBrowser`, `InstallGame` only `eprintln!` and return `true` — games are not launched, pages not navigated. Callers believe the action succeeded.
- Fix suggestion: Return `false` (or a `NotImplemented` result) until the backing subsystems are wired, so callers can fall back.

## [LOW] Test helper constants are wrong (`machine_name`, subsystems)

- File: src/steam_integration.rs:4822, :4830–4847
- Description: `0x01c4` is `IMAGE_FILE_MACHINE_ARMNT`, not ARM64 (ARM64 is `0xAA64`); the subsystem list omits `IMAGE_SUBSYSTEM_NATIVE_WINDOWS = 8`. Test-only, but misleads diagnostics.
- Fix suggestion: Fix the constant (`0xAA64 => "ARM64"`, add `8 => "NATIVE_WINDOWS"`).

## [LOW] `steam_smoke_pe_parse` indexes raw file bytes without bounds checks

- File: src/steam_integration.rs:4924–4933
- Description: `bytes[0x3c..0x40]` and `bytes[subsystem_offset..subsystem_offset+2]` (where `pe_offset` comes from the file itself) panic on truncated/malformed input. Test-only, but the test asserts on a real file that may vary.
- Fix suggestion: Guard with `bytes.len()` checks and `panic!` with a clear message (or `return` the failure) before slicing.

## [LOW] `repr(C)` connection-status struct uses `u32` where the Steam SDK uses signed `int`

- File: src/steam_integration.rs:1741–1753
- Description: `send_rate_bytes_per_sec`, `pending_unreliable`, `pending_reliable`, `sent_unacked_reliable` are `u32`; Steam's `SteamNetworkingConnectionStatus_t` declares them `int` (i32). If this struct is exported to guest binaries via FFI, negative sentinel values are misinterpreted.
- Fix suggestion: Use `i32` for the four count/rate fields to match the SDK layout exactly.

## [LOW] `with_steam_overlay` unwraps a poisoned mutex

- File: src/steam_integration.rs:1995
- Description: `GLOBAL_STEAM_OVERLAY.lock().unwrap()` panics if any thread ever panicked while holding the lock; overlay callbacks then become fatal.
- Fix suggestion: Use `lock().unwrap_or_else(|e| e.into_inner())` or a `parking_lot::Mutex` (no poisoning).

## [LOW] `parse_app_manifest` pollutes the flat map with nested-block keys

- File: src/steam_integration.rs:1028–1045
- Description: Lines inside nested blocks (e.g. `"InstalledDepots" { "480000" "480" }`) are parsed as top-level key/value pairs and inserted into the result map, so callers see bogus keys like `"480000"`. The parser is not block-aware.
- Fix suggestion: Track brace depth and only parse key/value pairs at depth 1 (or skip lines inside blocks).

## [LOW] Cloud quota is not enforced on writes; stale PID after stop

- File: src/steam_integration.rs:3711–3738, :508–540, :646–652
- Description: `file_write` updates `quota_used` but never rejects writes above `quota_total` (quota is advisory only). `SteamServiceProcess::stop` never resets `service_pid`, so `pid()` can return a stale PID after the child is gone (and `libc::kill`'s return is unchecked in the SIGTERM path, with a small PID-reuse race during the 500 ms grace window).
- Fix suggestion: Reject/flag writes exceeding `quota_total`; reset `service_pid = 0` in `stop()` and check `kill()`'s return value.

---

## Clippy

`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` — completed. No errors reference `src/steam_integration.rs`; 21 warnings do (all style-level). Listing them by line:

- `src/steam_integration.rs:276` — `new_without_default` (SteamNamedPipeManager)
- `src/steam_integration.rs:1099` — `new_without_default` (SteamClient)
- `src/steam_integration.rs:1242` — `needless_borrow` (`if let Some(ref key)`)
- `src/steam_integration.rs:1323` — `map_entry` (contains_key + insert on lobby_sessions)
- `src/steam_integration.rs:1393` — `collapsible_if`
- `src/steam_integration.rs:1502` — `new_without_default` (SteamNetworkingSockets)
- `src/steam_integration.rs:1776` — `new_without_default` (SteamNetworkingMessages)
- `src/steam_integration.rs:1996` — `explicit_auto_deref` (`f(&mut *guard)`)
- `src/steam_integration.rs:2078` — `collapsible_if` (overlay key JS exec)
- `src/steam_integration.rs:2109` — `collapsible_if` (overlay mouse move JS exec)
- `src/steam_integration.rs:2147` — `collapsible_if` (overlay mouse button JS exec)
- `src/steam_integration.rs:2183` — `collapsible_if` (overlay wheel JS exec)
- `src/steam_integration.rs:2281` — `collapsible_if` (SteamUserStats save)
- `src/steam_integration.rs:2408` — `unwrap_or_default` (`or_insert_with(Vec::new)`)
- `src/steam_integration.rs:2410` — `unnecessary_sort_by` (use `sort_by_key(Reverse)`)
- `src/steam_integration.rs:2657` — `collapsible_if` (SteamFriends save)
- `src/steam_integration.rs:3341` — `collapsible_if` (sync client init)
- `src/steam_integration.rs:3417` — `collapsible_if` (quota response parse)
- `src/steam_integration.rs:4289` — `needless_range_loop` (CRC table init)
- `src/steam_integration.rs:4571` — `collapsible_if` (advance_position)
- `src/steam_integration.rs:4955` — `print_literal` (test println)

## Build

- `cargo clippy --all-targets --no-deps` reached the end of the crate but **failed to compile**: `casa1 (lib)` — 19 errors / 1271 warnings; `casa1 (lib test)` — 27 errors / 1415 warnings. **All 27 errors are in other files** (e.g. `src/dwrite.rs:1398` overly_complex_bool_expr, `src/d3d11.rs:3687` approx_constant, `src/video_decoder.rs:573` not_unsafe_ptr_arg_deref, `src/steam_input.rs`, `src/user32.rs`). None reference `src/steam_integration.rs`. Whole-crate warnings were capped at 1262 duplicates; the 21 unique warnings above cover this file.
- `--all-features` was not used (missing system ffmpeg is environmental and was ignored per instructions).

---

### Summary

- CRITICAL: 4
- HIGH: 5
- MEDIUM: 10
- PERF: 4
- LOW: 9
- **Total: 32 findings**
