# Casa1 Steam Audit — Findings Report

- Batch: audit-steam-protocol (fresh worktree)
- Files audited (read fully, line by line):
  - `src/steam_protocol.rs` (4525 lines)
  - `src/steam.rs` (2871 lines)
  - `src/steam_launch.rs` (960 lines)
- Date: 2026-08-15
- Method: full read of all three files (2000-line chunks), `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` run to completion, findings deduplicated by highest severity.

Severity counts: **CRITICAL 2 · HIGH 8 · MEDIUM 9 · LOW 14 · PERF 3** — total **36 findings** (+ 34 clippy warnings, see Clippy section).

---

## [CRITICAL] Unsigned underflow on untrusted chunk offsets → panic / giant allocation

- File: src/steam.rs:2264-2268
- File: src/steam.rs:2304-2308
- Description: `download_file_chunks` and `download_file_chunks_ext` compute `let pad = (chunk.offset - offset) as usize;` where `offset = assembled.len()` and `chunk.offset` comes from the (untrusted, network-fetched) depot manifest. If chunks are out of order, overlapping, or have an offset smaller than the current buffer length, `chunk.offset - offset` underflows: panic in debug builds; in release it wraps to a near-`u64::MAX` value and `extend(std::iter::repeat(0u8).take(pad))` attempts an enormous allocation → OOM abort or long hang. A malformed/malicious manifest trivially triggers this (e.g. two chunks with offset 0). Note `steam_protocol.rs::download_file` (2795-2829) guards the same operation correctly; this code does not.
- Fix suggestion: Use `chunk.offset.saturating_sub(offset)` plus an explicit error when `chunk.offset < offset` (chunk order/overlap violation), and validate `chunk.offset + chunk_data.len() <= file_size` before extending.

## [CRITICAL] Unbounded allocations from untrusted lengths → OOM abort (process crash)

- File: src/steam_protocol.rs:2682, 2718
- File: src/steam_protocol.rs:2795
- File: src/steam.rs:1894, 2260, 2300
- File: src/steam.rs:2579, 2649
- Description: Multiple sites pre-allocate memory sized directly by untrusted values read from depot manifests / SteamPipe files with no upper bound:
  - `parse_depot_manifest`: `Vec::with_capacity(file_count as usize)` / `Vec::with_capacity(chunk_count as usize)` — `file_count = 0xFFFFFFF0` with a 24-byte input requests a >100 GB Vec → allocation failure → abort.
  - `download_file`: `vec![0u8; manifest.size as usize]` — a manifest `size` of e.g. 2^63 requests an exabyte buffer → abort.
  - `FileDownload::new` and both `download_file_chunks*`: `Vec::with_capacity(size as usize)` with u64 size — same abort; also pre-allocates full file sizes even before any download.
  - `parse_steampipe_csm` / `parse_steampipe_csb`: `Vec::with_capacity(file_count as usize)` / `Vec::with_capacity(depot_count)` from file headers.
  All of these are reachable from network responses (`fetch_depot_manifest`) or on-disk files the user may open.
- Fix suggestion: Cap counts/sizes (e.g. reject `file_count > 1_000_000`, `size > available_len` checks, or use `try_reserve`/`try_reserve_exact` and return `AppError` on failure). For `download_file`, verify `manifest.size` against the sum of chunk sizes and against free space before allocating.

---

## [HIGH] Unbounded frame allocation from network `total_len` (up to 4 GiB) — DoS

- File: src/steam_protocol.rs:2118-2119
- File: src/steam_protocol.rs:2282
- File: src/steam_protocol.rs:2450
- Description: `receive_messages`, `read_encrypt_request` and `read_encrypt_result` each do `vec![0u8; total_len as usize]` with `total_len` a u32 read directly from the network frame header. A server (or attacker able to reach the CM port) can send `total_len = 0xFFFFFFFF` → 4 GiB allocation + zero-fill, then a 30 s `read_exact` stall; repeated frames drive memory exhaustion. No sanity cap against a plausible max message size.
- Fix suggestion: Reject frames whose `total_len` exceeds a configurable maximum (e.g. 16 MiB) or the negotiated protocol bounds before allocating; return `RcNetProtocolError`.

## [HIGH] `start_download` double-counts total bytes

- File: src/steam.rs:2332, 1947
- Description: `start_download` computes `total_bytes` as the sum of all manifest sizes and passes it to `DownloadSession::new`, then calls `session.add_file(file)` for each file, and `add_file` does `self.progress.total_bytes += file.size` again. `progress.total_bytes` ends up exactly 2× the real size → `overall_progress()`/`DownloadProgress::update` report half the real percentage and ETA is wrong for every session.
- Fix suggestion: Either drop the `total_bytes` parameter from `DownloadSession::new` (rely solely on `add_file`), or remove the `+=` in `add_file`.

## [HIGH] Compressed chunks can never verify (SHA-1 checked against uncompressed hash)

- File: src/steam.rs:2219-2247
- Description: `download_chunk` checks `data.len() == expected_size` where `expected_size` is `compressed_size` for compressed chunks, then verifies `sha1_hash(&chunk_data) == chunk.chunk_id`. `chunk_id` is the SHA-1 of the *uncompressed* chunk content, but the code verifies the hash of the raw (still compressed) bytes and explicitly does not decompress ("decompression would use the SteamPipe format … For now, pass through raw data"). Every compressed chunk therefore fails SHA-1; since the vast majority of Steam depot chunks are compressed, real downloads always fail.
- Fix suggestion: Implement the decompression path (Oodle/zlib per SteamPipe) before hashing, or return a clear `RcNotImplemented`-style error for `compressed_size > 0` chunks instead of a misleading "SHA-1 mismatch".

## [HIGH] TURN XOR attributes keyed with STUN magic cookie instead of transaction ID (RFC 5766)

- File: src/steam_protocol.rs:1456-1463 (XOR-RELAYED-ADDRESS parse)
- File: src/steam_protocol.rs:1682-1689 (XOR-PEER-ADDRESS parse)
- File: src/steam_protocol.rs:1737-1743 (encode_xor_peer_address)
- Description: RFC 5766 §6.3/§9.2 specifies that for TURN, XOR-RELAYED-ADDRESS and XOR-PEER-ADDRESS are obfuscated by XORing with the **transaction ID** of the corresponding Allocate/CreatePermission request (port XORed with the first 2 bytes of the txid, address with the first 16 bytes). The code XORs with `STUN_MAGIC_COOKIE` (0x2112A442) everywhere. Result: the relayed address parsed from Allocate responses and the peer addresses encoded in CreatePermission/Send are wrong → TURN relay broken end-to-end (permissions created for the wrong peer, relayed address misreported).
- Fix suggestion: Thread the per-request `tx_id` into the XOR-encode/decode helpers for TURN attributes (STUN XOR-MAPPED-ADDRESS correctly uses the magic cookie — leave that one alone).

## [HIGH] TURN Send/Data message-type class bits wrong — relay traffic never sent or received

- File: src/steam_protocol.rs:1600-1601
- File: src/steam_protocol.rs:1652-1654
- Description: `send_via_turn` calls `build_stun_request(TURN_METHOD_SEND, …)` producing message type 0x0006 (request class). A TURN *Send indication* must have the indication class bit set: 0x0016 (0x0006 | 0x0010); the comment at line 1600 even says "method with 0x0010 indication class" but it is never applied. Likewise `receive_turn_data` compares the received type with `TURN_METHOD_DATA` = 0x0007, but real Data indications arrive as 0x0017 (0x0007 | 0x0010) → the check never matches and inbound relayed data is silently dropped.
- Fix suggestion: OR the indication bit (`0x0010`) into the method for Send and Data handling on both the encode and decode sides, and define the constants as `0x0016` / `0x0017` (or apply the bitmask).

## [HIGH] `receive_turn_data` consumes and drops datagrams that are not from the relay

- File: src/steam_protocol.rs:1634-1644
- Description: In the `recv_from` loop, datagrams whose source is not the TURN relay are `continue`d, with a comment claiming "poll_incoming_messages will pick it up on the next call". That is false: `recv_from` has already removed the datagram from the socket buffer, so any peer→local P2P packet is silently lost whenever TURN and direct UDP traffic share the socket. Under TURN use, inbound P2P traffic is dropped.
- Fix suggestion: Don't drain the socket here for unrelated traffic — only accept from the relay address in the first place, or buffer skipped datagrams and deliver them through `incoming_queue`.

---

## [MEDIUM] `http_get_chunk` has no TLS and wrong default port for https

- File: src/steam_protocol.rs:2875-2966
- File: src/steam_protocol.rs:2891
- Description: For `record.https == true` (port 443) the code still opens a raw `TcpStream` and speaks plaintext HTTP — no TLS handshake at all — so HTTPS content servers can never be used. Also `url.port().unwrap_or(80)` yields port 80 even for `https://` URLs lacking an explicit port. Additionally the response is accumulated unboundedly (`response` Vec with no Content-Length cap) and the body offset is located via `String::from_utf8_lossy(&response).find("\r\n\r\n")`, whose byte indices diverge from the raw buffer when the body contains non-UTF-8 bytes (binary chunk data) — the separator search can land in the middle of the body if headers are split oddly.
- Fix suggestion: Use a real HTTPS client (reqwest is already a dependency) with response-size limits and Content-Length handling; fall back to `url.port().unwrap_or(if https { 443 } else { 80 })`; search for `\r\n\r\n` on the raw bytes instead of the lossy string.

## [MEDIUM] `connect()` aborts on handshake failure instead of trying the next CM server

- File: src/steam_protocol.rs:1871-1892
- Description: When TCP connect succeeds but `perform_encryption_handshake()` fails (`?` at line 1885), the error is returned immediately; the remaining servers in `DEFAULT_CM_SERVERS` are never tried, the state is left as `Encrypting`, and the half-open `TcpStream` stays in `self.stream` until the next `connect()`. Re-connect attempts do not close the previous stream (leaked socket until replaced).
- Fix suggestion: On handshake error, close the stream, reset state to `Disconnected`, and continue the server loop; only return the aggregate error after all servers are exhausted.

## [MEDIUM] `drain_messages` swallows all protocol errors

- File: src/steam_protocol.rs:2176-2181
- Description: `Err(_) => break` discards the error, so a bad magic, truncated frame, or decryption failure mid-stream looks exactly like "queue drained" (`Ok(count)`). Callers cannot distinguish a clean drain from a broken connection, and the CTR cipher state has already advanced past the bad frame, so subsequent decryption is permanently desynchronized without any signal.
- Fix suggestion: Propagate the first error (`return Err(e)`), or expose a `last_error` field; on any parse/decrypt failure also consider tearing down the connection since CTR state is unrecoverable.

## [MEDIUM] STUN binding response type is never validated

- File: src/steam_protocol.rs:866-896
- Description: `perform_stun_binding` verifies the magic cookie and transaction ID but never checks the message type is `STUN_BINDING_RESPONSE` (0x0101). A STUN error response (0x0111) with a matching transaction ID would be processed as a success and its attributes parsed — or fail with a misleading "no mapped address" error. Minor, but it makes failure modes incorrect.
- Fix suggestion: Read the first two bytes and require 0x0101 (success response) before parsing attributes.

## [MEDIUM] CDN routing `port` attribute silently truncated to u16

- File: src/steam_protocol.rs:2522
- Description: `let port: u16 = self.parse_xml_attr(line, "port").unwrap_or(443) as u16;` — `parse_xml_attr` returns `Option<u32>`; any value > 65535 (e.g. an attacker-controlled routing response) is silently truncated, connecting to a wrong port. Likewise `cell_id`/`weight` are unbounded u32 from the response.
- Fix suggestion: Parse `port` as `u16` directly and reject values out of range (`try_from`), with a bounds check for `cell_id`/`weight`.

## [MEDIUM] VDF parser recursion is unbounded → stack overflow on adversarial input

- File: src/steam.rs:1262-1365
- Description: `parse_vdf_map` recurses once per `{` and there is no nesting-depth limit. `parse_appmanifest`/`parse_installscript`/`parse_libraryfolders_for_app` run it on files loaded from disk (`appmanifest_*.acf`, `installscript.vdf`, `libraryfolders.vdf`) that may be user-supplied; a deeply nested document (tens of thousands of braces) overflows the stack → abort.
- Fix suggestion: Track a depth counter in `parse_vdf_map` and error out above a small limit (e.g. 128).

## [MEDIUM] `report_health` never matches the servers it is called with

- File: src/steam.rs:2431, 1770-1784
- Description: `process_downloads` calls `self.server_list.report_health(&server_url, false, None)` where `server_url` is a full base URL like `https://content1.steampowered.com:443`, but `report_health` looks up `r.proto.host == host` (bare hostname). The lookup never matches, so a failing server is never marked unhealthy and failover/health tracking is a silent no-op.
- Fix suggestion: Extract the host (e.g. `server_url.split("://").nth(1)?.split(':').next()`) before calling `report_health`, or match on the base URL instead of the host.

## [MEDIUM] `parse_depot_manifest` silently returns partial results on truncated input

- File: src/steam_protocol.rs:2684-2761
- Description: Every per-entry bounds check `break`s out of the loop instead of returning an error, so a truncated/corrupt manifest returns `Ok` with a subset of files (possibly zero files, no error). Callers (`fetch_depot_manifest`, `download_file`) then proceed on incomplete data; only downstream checksum mismatches reveal the corruption.
- Fix suggestion: Return `RcNetProtocolError` when a field read would run past the buffer; do not `break` on malformed entries.

## [MEDIUM] `SteamProtocolHandler::register` declares LaunchServices symbol without linking the framework

- File: src/steam_protocol.rs:3540-3554
- Description: `extern "C" { fn LSSetDefaultHandlerForURLScheme(...) }` has no `#[link(name = "ApplicationServices", kind = "framework")]` (or CoreServices) attribute, and neither `Cargo.toml` nor a `build.rs` links the framework. The symbol lives in ApplicationServices/CoreServices on macOS; without a link directive the final binary link is at risk of failing with an undefined symbol (clippy does not link, so this is currently latent). Also `CString::new("steam").unwrap()` and `new_verbose()` setting `registered = true` are minor oddities.
- Fix suggestion: Add `#[link(name = "ApplicationServices", kind = "framework")]` to the extern block (or use the `lsregister` subprocess approach already used in `app_bundle.rs`); initialize `registered: false` in `new_verbose` if registration hasn't actually occurred.

---

## [LOW] Direct `BTreeMap` indexing on `path_case` can panic

- File: src/steam.rs:433, 747, 753
- Description: `self.path_case[&format!("{}/steam.exe", self.ge_root)]` and `self.path_case[&executable_normalized]` use `Index`, which panics if the key is missing. Today `files` and `path_case` are written together (`write_file`, `install_depot` staged_case), but the invariant is implicit: e.g. launching a game after a `self.files.insert` that bypasses `write_file` would panic instead of returning `AppError`.
- Fix suggestion: Use `path_case.get(...)` and return an `AppError` when absent.

## [LOW] `commit_staged_file` silently drops zero-size files

- File: src/steam.rs:2760-2764
- Description: `if !file.data.is_empty()` skips legitimate empty files (size-0 assets), which then disappear from the committed depot (and `files.is_empty()` then errors out confusingly for an all-empty depot).
- Fix suggestion: Include files whose declared size is 0 (track state, not data emptiness).

## [LOW] `rsa_wrap_aes_key` rebuilds the RSA key instead of using the stored one

- File: src/steam_protocol.rs:2352-2360 (also 2220-2228)
- Description: The public key is reconstructed from the modulus in `perform_encryption_handshake`, stored in `self.rsa_public_key`, then reconstructed *again* inside `rsa_wrap_aes_key`. Wasteful and creates a second validation surface; the two could diverge.
- Fix suggestion: Have `rsa_wrap_aes_key` take/use `self.rsa_public_key` directly.

## [LOW] GNS channel number parsed from the wire but discarded

- File: src/steam_protocol.rs:1228-1248, 1186-1213
- Description: `poll_incoming_messages` reads the 4-byte channel from each datagram into `_channel` and then always builds `SteamNetworkingMessage { channel: 0, … }`; `fallback_send` also drops its `_channel` parameter. Multi-channel support is documented but non-functional.
- Fix suggestion: Propagate `channel` into `SteamNetworkingMessage` on both paths.

## [LOW] SDR send path does not wrap in an SDR datagram (doc/code mismatch)

- File: src/steam_protocol.rs:1122-1132
- Description: The doc for `send_message` promises "the message is wrapped in an SDR datagram first" when the relay is configured, but the code sends the raw GCM packet directly to `sdr_relay`. If any peer actually expects SDR framing, relayed sends are malformed.
- Fix suggestion: Implement the SDR wrap or fix the doc/comment.

## [LOW] STUN length field truncated to u16 for large payloads

- File: src/steam_protocol.rs:1342 (also 853)
- Description: `(request.len() - 20) as u16` truncates silently for `TURN_ATTR_DATA` payloads larger than 65515 bytes → malformed TURN Send indications for big messages.
- Fix suggestion: Check `request.len() - 20 <= u16::MAX` and error out (or cap data size) before sending.

## [LOW] `urlencoding_decode` mangles non-ASCII path segments

- File: src/steam_protocol.rs:3439-3457
- Description: Percent-decoded bytes are pushed as `(h << 4 | l) as char` (byte→char), so non-ASCII segments (e.g. percent-encoded UTF-8 in `steam://` URLs) produce garbage; also an invalid escape silently emits a literal `%` and the `+`→space rule is applied to path segments (should be query-only).
- Fix suggestion: Decode into `Vec<u8>` and use `String::from_utf8_lossy`, or use `url`'s percent-decoding APIs.

## [LOW] `disconnect()` retains credentials and RSA key

- File: src/steam_protocol.rs:1903-1913
- Description: `disconnect` clears stream/cipher/session state but leaves `rsa_public_key`, `auth.username`, `auth.password_encrypted`, and tokens in memory (no zeroization). Security hygiene issue for a client that may hold passwords.
- Fix suggestion: Clear `rsa_public_key` and the `auth` fields (or zeroize `password_encrypted`/tokens) on disconnect.

## [LOW] `ExtendedHeader.size` is ignored on receive

- File: src/steam_protocol.rs:2137-2155
- Description: `receive_messages` uses all bytes after the 44-byte header as payload; the header's own `size` field is never cross-checked. Trailing/garbage bytes silently become part of the payload and framing stays misaligned.
- Fix suggestion: Validate `ext_header.size == plaintext.len() - TOTAL_SIZE` (or at least `<=`).

## [LOW] Redundant/dead state transitions in GNS

- File: src/steam_protocol.rs:1282-1283 (`close_session`: `Closing` immediately overwritten by `Closed`)
- File: src/steam_protocol.rs:1061-1071 (`create_session`: inserts `Connecting`, immediately re-inserts `Connected`)
- Description: Dead assignments; `accept_session` can then never see the `Connecting` state produced by `create_session`, only by direct map manipulation (as the test does).
- Fix suggestion: Remove the duplicate insert; keep only `Connected` (or a real two-phase create).

## [LOW] `new_verbose()` marks the handler as registered

- File: src/steam_protocol.rs:3510-3515
- Description: `registered: true` in `new_verbose` means `register()` becomes a no-op for a handler that never registered — likely a copy-paste of intent, since "verbose" shouldn't imply registration.
- Fix suggestion: Set `registered: false` (or rename the flag semantics).

## [LOW] `steam_app_manifest_bytes` doesn't escape quotes/backslashes

- File: src/steam.rs:1070-1092
- Description: `game_name`, `install_dir`, `launch_exe` are interpolated raw into the `.acf` VDF; names containing `"` or `\` produce a malformed file that the project's own VDF parser can't round-trip.
- Fix suggestion: Escape `\` and `"` per VDF rules before emitting.

## [LOW] `http_get_with_retry` shift overflow for large retry counts

- File: src/steam.rs:2829
- Description: `1u64 << attempt` panics (debug) / wraps (release) when `max_retries >= 64`. Current callers pass 1-3, but the API is public-ish and unbounded.
- Fix suggestion: Cap the backoff (e.g. `1u64 << attempt.min(20)`).

## [LOW] `create_install_manifest` ignores its `_depot_manifests` parameter

- File: src/steam.rs:2791-2809
- Description: Dead parameter; the manifest mapping is a plain clone of `downloaded_files`. Either use the parameter or drop it.

## [LOW] `parse_steampipe_csm` entry bounds check requires 44 bytes but only 40 are consumed

- File: src/steam.rs:2583-2616
- Description: Per-entry fixed fields are 8+20+4+4+4 = 40 bytes, but the check demands `offset + 44 <= data.len()`. Final entries with short filenames (`name_len + padding < 4`) are spuriously rejected as "truncated". The 4-byte "filename hash placeholder" mentioned in the comment is never read.
- Fix suggestion: Align the guard with the actual consumed size (40 + name_len + padding).

## [LOW] `parse_steampipe_csb` advances past all remaining data once a manifest is found

- File: src/steam.rs:2699-2713
- Description: When a `.csm` probe succeeds, `chunk_offset = data.len()`, so any subsequent depot's data region is consumed; multi-depot bundles with trailing manifests fail with "data truncated" for later depots.
- Fix suggestion: Parse the manifest length from the header and advance `chunk_offset` by exactly that much.

## [LOW] `steam_launch` environment duplicated between override profile and runner env

- File: src/steam_launch.rs:261-469 vs 512-619
- Description: `build_steam_override_profile` and `build_steam_environment` independently hardcode the same `CASA1_*` env set; the two can drift (they already differ slightly) and `build_steam_environment` is not used by `create_steam_job` (whose env is empty, populated later by `child_environment`).
- Fix suggestion: Derive both from a single `steam_env_vars(profile)` helper.

## [LOW] VDF tokenizer lacks `/* */` comments and escaped quotes

- File: src/steam.rs:1275-1320
- Description: Only `//` line comments are handled; real-world VDF (and files this tool itself can emit, e.g. libraryfolders with escaped paths) can use `/* */` or `\"` escapes, which tokenize as errors or as literal characters.
- Fix suggestion: Handle `/* */` and `\"` in `tokenize_vdf`.

---

## [PERF] `self_update` clones the entire file map twice per update

- File: src/steam.rs:438-439
- Description: `let files_snapshot = self.files.clone(); let path_case_snapshot = self.path_case.clone();` duplicates every installed byte (potentially GBs of game data) in memory for the whole update, even on the success path where the snapshots are never used.
- Fix suggestion: Clone lazily only when a rollback becomes necessary (or track a journal of writes to undo).

## [PERF] Downloads buffer every file 2-3× in memory

- File: src/steam.rs:2260, 2286 (`download_file_chunks`: `assembled` + `file.data = assembled.clone()`)
- File: src/steam.rs:2300 (`download_file_chunks_ext` allocates the full file up front)
- File: src/steam.rs:1215-1259 (`collect_payload_files` reads whole payload tree into RAM)
- Description: Full-file `Vec` pre-allocation plus clone for each file, and whole-tree reads for payload collection. For multi-GB depots this multiplies peak memory and causes the OOM risk noted in the CRITICAL finding.
- Fix suggestion: Stream to disk (temp file) instead of RAM staging; avoid `clone` by moving `assembled` into `file.data` and returning the same buffer.

---

## Clippy

Run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (whole crate, completed).

Warnings referencing the audited files (34 total; **0 errors** in the audited files):

`src/steam.rs`:
- 1741 `unused_enumerate_index` (seed_defaults)
- 1866 `manual_checked_ops` (eta_secs division — matches the guarded-division pattern)
- 2148 `collapsible_if` (select_best_server)
- 2268, 2307 `manual_repeat_n` (pad fill — note: `repeat_n` doesn't fix the CRITICAL underflow finding; the pad value itself is the problem)
- 2417, 2426, 2731 `collapsible_if`
- 2703 `single_match` (parse_steampipe_csb manifest probe)

`src/steam_protocol.rs`:
- 83 `needless_lifetimes` (get_slice)
- 700 `type_complexity` (signal_r)
- 717, 1803 `new_without_default` (GameNetworkingSockets, SteamProtocolStack)
- 914, 1468 `collapsible_match` (STUN/TURN attribute parsing)
- 1139 `unnecessary_cast`
- 1337 `manual_repeat_n`
- 1638 `unnecessary_map_or`
- 2548 `needless_range_loop` (parse_cdn_routing)
- 2663 `let_and_return`
- 3314, 3444, 3445 `redundant_closure`
- 3351, 3361, 3371, 3381, 3391, 3399, 3411, 3421 `len_zero`
- 3697 `collapsible_if`

`src/steam_launch.rs`:
- 937, 951 `field_reassign_with_default` (tests)

## Build

- Command completed (whole-crate compile), but `cargo clippy` exits non-zero crate-wide: 19 errors in the lib (deny-level lints) and 27 in the lib-test target, all in **files outside the audited scope**: `src/video_decoder.rs` (`not_unsafe_ptr_arg_deref`, etc.), `src/crash_recovery.rs:536`, `src/d3d11.rs:3687`, `src/pe_runtime.rs:48799`, `src/security.rs:3097`, `src/winhttp.rs:3624`. No clippy errors reference `steam_protocol.rs`, `steam.rs`, or `steam_launch.rs`.
- Full `clippy_out.txt` retained in the worktree root for reference.
