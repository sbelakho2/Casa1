# Audit Findings — Batch 1: src/network.rs, src/real_net.rs

- **Batch:** audit-network (worktree `audit-network`)
- **Files:** `src/network.rs` (4737 lines), `src/real_net.rs` (1350 lines) — both read in full, in order, every line
- **Date:** 2026-08-15
- **Tooling:** `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (whole crate; output in `clippy_out.txt`)

Severity counts: **CRITICAL 4 | HIGH 6 | MEDIUM 17 | LOW 16 | PERF 2 | total 45**

---

## [CRITICAL] `read_body` — usize overflow leads to panic on guest-controlled count

- File: src/network.rs:1881
- Description: `let end = (read_offset + count).min(body.len());` — `read_offset` and `count` are guest-influenced `usize` values (`win_http_read_data`/`internet_read_file` take `count: usize`). Once `read_offset > 0` (any prior read), a `count` near `usize::MAX` overflows the addition: in debug builds the `+` panics ("attempt to add with overflow"); in release builds it wraps so `end < read_offset` and `body[read_offset..end]` panics with an out-of-bounds slice. Current in-tree callers (steam.rs) pass small constants, but the API is `pub` on the shim layer and the count is not validated anywhere.
- Fix suggestion: `let end = read_offset.saturating_add(count).min(body.len());` and return an error (or empty) if `end < read_offset`; alternatively clamp `count` up-front.

## [CRITICAL] `parse_http_response` — `from_utf8_lossy` offset skew causes out-of-bounds slice panic on untrusted server data

- File: src/network.rs:646, 699
- Description: `body_start` is computed from `String::from_utf8_lossy(raw)` (`response_str.find("\r\n\r\n")` / `response_str.len()`), then applied to the *raw* bytes: `raw[body_start..]`. For each invalid UTF-8 byte before the header separator, `response_str` is 2 bytes longer than `raw` (1 byte → 3-byte U+FFFD), so `body_start` can exceed `raw.len()` → "byte index out of range" panic; short of a panic, the body is silently mis-sliced (first N bytes dropped). Reachable from any malicious/odd server response in `http_get` (Steam CDN path).
- Fix suggestion: locate `\r\n\r\n` directly in `raw` (`raw.windows(4).position(|w| w == b"\r\n\r\n")`) and compute offsets on raw bytes; only lossy-convert the already-delimited header text for parsing.

## [CRITICAL] `recv` on a real stream allocates the full guest-supplied length — OOM abort

- File: src/network.rs:1201-1214
- Description: `let mut bytes = vec![0; length.max(1)];` — `length` is guest-controlled (e.g. guest `recv(sock, 0xFFFFFFFF)` via pe_runtime.rs:31395, or a large WSARecv total). A 4 GiB (or larger) allocation on the host aborts the process on OOM; even successful allocations are wasteful since only the currently-available bytes are read. No cap is applied to `length` for real sockets (the mock path is capped by `recv_queue.len()`).
- Fix suggestion: clamp the buffer to a bounded size (e.g. `min(length, MAX_SOCKET_RECEIVE_QUEUE)`) and loop reads into a pre-sized buffer; return the bytes actually read.

## [CRITICAL] QUIC layer deadlocks/panics — spawned tasks on an undriven current-thread tokio runtime

- File: src/network.rs:2820-2824, 3114-3126, 3189-3214, 3232-3267
- Description: `QUIC_RUNTIME` is built with `Builder::new_current_thread()` and is never entered (`block_on` is never called anywhere in the crate). Every operation does `QUIC_RUNTIME.spawn(async {...})` followed by a blocking `std::sync::mpsc` `recv()` on the calling thread. Tasks on a current-thread runtime are only polled while the runtime is driven (inside `block_on`), so the spawned futures never progress and `recv()` blocks forever — a permanent hang of any caller thread. Additionally, `quinn::Endpoint::new` internally spawns driver tasks via `tokio::spawn`, which requires an active runtime context on the calling thread; since none exists, endpoint creation can panic instead of hang. Either way, `quic_create_connection`, `quic_udp_send`, `quic_udp_recv` are unusable.
- Fix suggestion: drive the runtime per call (`QUIC_RUNTIME.block_on(async { ... })`) with a timeout wrapper (e.g. `tokio::time::timeout`), or use `Builder::new_multi_thread()`; never mix blocking `recv()` with undriven spawns.

---

## [HIGH] `closesocket` leaves stale `listeners`/`pending_accept` state

- File: src/network.rs:1269-1281
- Description: Closing a socket removes it from `sockets`/`real_tcp_streams` but never from `self.listeners` or `self.pending_accept`. Consequences: (a) the address can never be re-bound — `bind` reports WSAEADDRINUSE forever; (b) every later `connect()` to that address still finds the stale listener, creates a server socket and pushes it onto the dead listener's `pending_accept` queue, which is never drained — unbounded ghost-socket growth and leaked `SocketRecord`s per connect.
- Fix suggestion: on close, remove the socket from `listeners` (only if it maps to this id) and drop `pending_accept.remove(&socket)`; also purge `pending_accept` entries whose queued ids are no longer alive.

## [HIGH] `RealHttpClient::add_cookie_header` ignores URL — cookies sent to every origin

- File: src/real_net.rs:491-509
- Description: `add_cookie_header(request, _url)` joins *all* cookies from the jar into a single `Cookie` header regardless of domain, path, or `secure`, and `_url` is unused. A cookie stored for one host is sent to every subsequent request (including cross-host and insecure HTTP), which is both a correctness and a credential-leakage bug in the real network stack (Steam login cookies).
- Fix suggestion: parse the request URL, filter `cookie_jar` with domain/path/secure matching (reuse `network::cookie_matches` semantics), and skip cookies for mismatched hosts.

## [HIGH] `quic_udp_send` opens bidi streams but `quic_udp_recv` waits for uni streams — peer handshake mismatch

- File: src/network.rs:3192 (`open_bi`), 3236 (`accept_uni`)
- Description: Send uses `connection.open_bi()`; receive uses `connection.accept_uni()`. Two Casa1 QUIC endpoints talking to each other can never complete a send/recv exchange: the sender's bidi stream is never accepted and the receiver's uni-stream accept never matches. Even with a correct runtime this makes the API deadlock between peers; `accept_uni` has no timeout.
- Fix suggestion: pick one direction consistently (e.g. both `open_bi`/`accept_bi`, or use `open_uni`/`accept_uni`), and apply a timeout to the accept.

## [HIGH] `http_get` — no read timeout and unbounded response accumulation

- File: src/network.rs:556-641
- Description: The response loop (`response.extend_from_slice(&buf[..n])` until EOF) has no size cap and no read timeout on the blocking TCP/TLS stream. A server that streams data (or stalls) makes the host allocate unbounded memory or block indefinitely — both hang/DoS the content-manager path that fetches Steam CDN data.
- Fix suggestion: set `read_timeout` on the stream (e.g. 15 s), cap `response` at a limit (e.g. reuse `MAX_HTTP_HEADER_BYTES`-style constant or a 256 MB cap), and error out when exceeded.

## [HIGH] `poll_sockets` — `FD_SET` writes past `fd_set` for fds >= FD_SETSIZE (1024)

- File: src/real_net.rs:1064-1106
- Description: macOS `fd_set` holds 1024 bits; `libc::FD_SET(fd, ...)` with `fd >= 1024` writes beyond the struct (stack memory corruption). The code does not check `fd < FD_SETSIZE` before `FD_SET`, nor does it bail when `max_fd >= FD_SETSIZE`. With a long-running emulator plus a game, 1024+ open fds is plausible, and this is UB/stack smashing.
- Fix suggestion: guard `if fd as usize >= libc::FD_SETSIZE { return Err(...) }` before `FD_SET`, or (better) use `libc::poll`/kqueue, which has no such limit.

## [HIGH] Non-blocking sockets: `connect` blocks during connect and has no timeout

- File: src/network.rs:1094-1137
- Description: For real TCP, `TcpStream::connect(candidate)` always performs a blocking connect; non-blocking mode is applied *after* connect returns. Windows semantics for a non-blocking socket are to return immediately with WSAEWOULDBLOCK (connect in progress). Steam and games using non-blocking connect will stall (and can hang on unreachable hosts — `TcpStream::connect` has no timeout; DNS via `to_socket_addrs` is also blocking).
- Fix suggestion: implement non-blocking connect (`connect_nonblocking`/`TcpStream::connect` on a `set_nonblocking(true)` socket, check `WouldBlock` → WSAEWOULDBLOCK), or at minimum bound connect with `connect_timeout` when blocking.

---

## [MEDIUM] `recv` on a real stream with length 0 blocks and can return 1 byte

- File: src/network.rs:1204-1211
- Description: `vec![0; length.max(1)]` turns a 0-length recv into a 1-byte read: on a blocking stream this blocks until data arrives (Windows would return 0 immediately), and then returns 1 byte instead of 0. On a non-blocking stream with no data it returns WSAEWOULDBLOCK instead of `Ok(0)`.
- Fix suggestion: short-circuit `if length == 0 { return Ok(Vec::new()); }` before touching the stream.

## [MEDIUM] `websocket_send` buffer grows without bound in `NetworkStack`

- File: src/network.rs:1555-1570
- Description: `ws.send_buffer.extend_from_slice(data)` has no cap in this layer (the `MAX_WEBSOCKET_SEND_BUFFER` limit is only enforced in winhttp.rs, so direct `NetworkStack` users bypass it). Repeated sends from guest code exhaust host memory. `receive_buffer` likewise has no producer-side cap here.
- Fix suggestion: enforce `MAX_WEBSOCKET_SEND_BUFFER`/`MAX_WEBSOCKET_RECEIVE_SPILL` inside `websocket_send` (and wherever `receive_buffer` is written), returning an error when exceeded.

## [MEDIUM] `close_handle` orphans child records (session/connection/request leaks)

- File: src/network.rs:1520-1525
- Description: Closing a session or connection removes only that map entry; its connections/requests (and their response bodies) remain in `http_connections`/`http_requests` forever. A long-running Steam session that repeatedly opens/closes WinHTTP handles leaks unboundedly.
- Fix suggestion: when removing a session, remove its connections; when removing a connection, remove its requests (and WebSocket records referencing them).

## [MEDIUM] `http_traces` / `cipher_log` grow without bound

- File: src/network.rs:1847, 1860-1868
- Description: Every `send_request` appends to `self.http_traces` and `self.cipher_log` with no cap or eviction. Over the lifetime of the emulator process this is unbounded memory growth (each trace is several heap strings).
- Fix suggestion: cap the vecs (e.g. keep last N=1024 entries, using a ring buffer or `VecDeque` with `pop_front`).

## [MEDIUM] Kerberos FFI leaks the SPN `CString` on every call

- File: src/network.rs:2472-2476
- Description: `spn.into_raw()` transfers ownership and the allocation is never reclaimed (`CString::from_raw` + drop is never called, on any path — including the `gss_import_name` failure path). Each `kerberos_get_ticket_macos` call leaks `service.len()+1` bytes permanently.
- Fix suggestion: keep the `CString` alive for the duration of the call (e.g. hold it in a local and pass `spn.as_ptr()`; only `into_raw` if ownership must transfer to GSS, which it does not need to).

## [MEDIUM] Kerberos GSS context is never deleted (`gss_delete_sec_context` missing)

- File: src/network.rs:2500-2526, 2574-2583
- Description: After a successful `gss_init_sec_context` the `context` handle (which holds ticket/credential material) is never released; cleanup only releases `output_token` and `target_name`. Leaks the GSS security context (memory + credential state) per call.
- Fix suggestion: call `gss_delete_sec_context(&mut minor_status, &mut context, GSS_C_NO_BUFFER)` in the cleanup block when `context` is non-null.

## [MEDIUM] `gss_display_status` called with invalid `status_type` (0)

- File: src/network.rs:2548-2556
- Description: GSSAPI defines `GSS_C_GSS_CODE = 1` and `GSS_C_MECH_CODE = 2`; passing `0` is not a valid status type, so error reporting silently fails (or returns garbage) on the failure path.
- Fix suggestion: pass `1` (GSS_C_GSS_CODE).

## [MEDIUM] `build_spnego_token` does not produce a spec-compliant SPNEGO token

- File: src/network.rs:2696-2754
- Description: The doc comment describes `SEQUENCE { SPNEGO OID; [0] EXPLICIT { ... } }`, but the code emits `SEQUENCE { [0] {krb5 OID}, [2] {OCTET STRING} }` — no SPNEGO mechTypes OID list, no negTokenInit wrapper per RFC 4178. Real servers will reject the Authorization: Negotiate value. Additionally, `(kerberos_ticket.len() as u16)` truncates ticket lengths > 65535 into malformed DER.
- Fix suggestion: build a proper `NegTokenInit` (use `der` crate, already a dependency): `SEQUENCE { mechTypes [0] {OID krb5}, mechToken [2] OCTET STRING }`, with a variable-length DER length encoder for >65535 lengths.

## [MEDIUM] `tcp_connect` (real_net) tries only the first resolved address — no family/order fallback

- File: src/real_net.rs:653-676
- Description: `RealDnsResolver::resolve` can return multiple addresses (e.g. IPv6 first), but only `addrs.first()` is used. If that address is unroutable/unreachable (common with IPv6-first resolution on v4-only networks), connect fails even though a later address (IPv4) would work.
- Fix suggestion: iterate the address list and try each until one connects (with per-attempt timeout).

## [MEDIUM] Duplicate `Set-Cookie` headers overwrite each other in `process_response`

- File: src/real_net.rs:516-528
- Description: All response headers are folded into a `BTreeMap<String, String>`, so when a server sends multiple `Set-Cookie` headers only the last one survives; all earlier cookies are silently dropped (multi-cookie responses are common).
- Fix suggestion: accumulate `set-cookie` values separately (e.g. collect into `Vec<String>` from `response.headers().get_all("set-cookie")`) before parsing.

## [MEDIUM] `Set-Cookie` parsing splits on `,` — breaks `Expires` dates

- File: src/real_net.rs:522-527
- Description: `set_cookies.split(',')` mangles attributes that legally contain commas, e.g. `Expires=Wed, 09-Jun-2026 12:00:00 GMT` — the date fragment becomes a bogus separate cookie entry (and `parse_set_cookie` then yields a cookie with a `name` of `09-Jun...` or is dropped).
- Fix suggestion: split on `,` only when not inside a quoted/date context, or use `reqwest::cookie::Jar`/`cookie` crate parsing instead of a hand-rolled splitter.

## [MEDIUM] `parse_set_cookie` — case-sensitive attributes, no expiry handling

- File: src/real_net.rs:555-588
- Description: `strip_prefix("domain=")`/`path=`/`secure` are case-sensitive (spec requires case-insensitive attribute names), and `Max-Age`/`Expires` are ignored entirely, so cookies never expire and are re-sent forever. Combined with the absent size cap, the jar grows without bound.
- Fix suggestion: compare attribute names case-insensitively; parse `Max-Age`/`Expires` and drop expired cookies in `store_cookie`/`cookie_snapshot`.

## [MEDIUM] `process_response` reads response body unbounded into memory

- File: src/real_net.rs:530-535
- Description: `response.bytes()` materializes the whole body (any size, any transfer duration within the 30 s timeout) with no cap. A malicious server can exhaust host memory.
- Fix suggestion: check `Content-Length` (and streamed-read cap) against a limit before/while reading.

## [MEDIUM] `RealTcpListener::accept` loses non-blocking mode; non-blocking accept errors aren't mapped to WSAEWOULDBLOCK

- File: src/real_net.rs:182-203, 784-797
- Description: Accepted sockets are always created with `nonblocking: false` even when the listener is non-blocking, and a WouldBlock error from a non-blocking listener is wrapped as a generic `RcIo` error instead of the WinSock WSAEWOULDBLOCK code — guest code relying on non-blocking accept loops misbehaves.
- Fix suggestion: inherit `listener.nonblocking` into the accepted `RealTcpSocket` (and call `set_nonblocking` on the stream), and map `WouldBlock` to `RcWinsockWouldBlock` in `tcp_accept`.

## [MEDIUM] `parse_host_port` mis-parses unbracketed IPv6

- File: src/network.rs:3028-3051
- Description: Input like `"::1"` (no port, no brackets) hits `rsplit_once(':')`, yielding hostname `":"` and port `1` instead of host `::1`/default port. `quic_create_connection("::1")` then builds `[::]:1` and fails DNS. (Bracketed `[::1]:443` works.)
- Fix suggestion: detect unbracketed IPv6 (`input.matches(':').count() >= 2` and doesn't start with `[`) and treat the whole input as the host with `default_port`.

## [MEDIUM] `RealDnsResolver::resolve` fails for unbracketed IPv6 hosts

- File: src/real_net.rs:64-74
- Description: `format!("{host}:{port}")` produces `::1:80` for `host = "::1"`, which `ToSocketAddrs` cannot parse (IPv6 must be bracketed).
- Fix suggestion: bracket the host when it contains `:` and isn't already bracketed (`format!("[{host}]:{port}")`).

## [MEDIUM] `quic_create_listener` — endpoint created but never accepts connections

- File: src/network.rs:2998-3024
- Description: The listener endpoint is stored but nothing ever calls `endpoint.accept()` (which also requires async driving, absent here). The advertised "create QUIC listener" API can never produce an accepted connection — unfinished feature.
- Fix suggestion: implement an accept loop (spawn `while let Some(conn) = endpoint.accept().await` and park connections), or document/return `NotImplemented` until driven.

---

## [LOW] `map_wsa_error` maps unknown errors to 0 instead of a WSA code

- File: src/network.rs:2013-2023
- Description: The `_ => 0` arm silently reports "success" as the last error for unmapped failures (e.g. `InvalidInput`, `Interrupted`, `Other`); guest `WSAGetLastError` then returns 0.
- Fix suggestion: map to a generic code (e.g. `WSAEINVAL` or `WSASYSCALLFAILURE = 10107`).

## [LOW] `ensure_wsa` (real_net) — no-op statement and missing error code

- File: src/real_net.rs:634-640
- Description: `self.last_wsa_error;` is a statement with no effect (clippy: `no_effect`), and unlike `NetworkStack::ensure_wsa_started`, it never sets `last_wsa_error = WSANOTINITIALISED` (10093), so `wsa_get_last_error` is stale after a failed pre-init call.
- Fix suggestion: set `self.last_wsa_error = 10093;` and drop the no-op expression.

## [LOW] `From<AddressFamily> for SocketAddr` always returns IPv4 any

- File: src/real_net.rs:37-42
- Description: The conversion ignores `V6` and always yields `0.0.0.0:0`; any caller converting `AddressFamily::V6` gets a V4 address.
- Fix suggestion: match on the family and return `[::]:0` for `V6`, or remove the impl if unused.

## [LOW] `static mut` GSS OID globals

- File: src/network.rs:2407-2408
- Description: `pub static mut GSS_C_NT_USER_NAME` / `GSS_C_NT_HOSTBASED_SERVICE` are mutable statics (unsafe to access from multiple threads) and are never used at all.
- Fix suggestion: delete them, or make them `static` `*const`/`AtomicPtr` if a future caller needs them.

## [LOW] Dead fields, never-populated maps, and no-op stubs

- File: src/network.rs:88 (`QuicConfig::log_fallback`), 488-492 + 894-895 (`alt_svc_entries`, `connection_protocols`, `session_protocol_flags` never populated), 2803 (`QuicState::next_id` unused), 2991-2994 (`http_socket_combine_ssl_scalers` no-op stub)
- Description: Declared state and APIs that are never used or wired up (HTTP/3 discovery/negotiation results are recorded nowhere); the `combine_ssl_scalers` "scaling" function just returns its input.
- Fix suggestion: wire the maps into `send_request`/header processing, remove dead fields, and implement or remove the stub.

## [LOW] `Clone for NetworkStack` panics on `try_clone` failure

- File: src/network.rs:708-721
- Description: `stream.try_clone().expect("failed to clone host TCP stream")` panics if any live `TcpStream` fails to duplicate (e.g. closed/EBADF), turning a clone of a partially-torn-down stack into a crash.
- Fix suggestion: skip/remove streams that fail to clone (or return `AppResult` from clone).

## [LOW] `RealNetworkStack::http_client` uses `unwrap` after manual `is_none` check

- File: src/real_net.rs:953-958
- Description: `Ok(self.http_client.as_mut().unwrap())` — safe today but an avoidable panic site; future edits could invalidate the invariant.
- Fix suggestion: `let client = self.http_client.get_or_insert(RealHttpClient::new()?);`

## [LOW] `http_download(&self)` requires the client to have been initialized by another call

- File: src/real_net.rs:996-1002
- Description: `http_get`/`http_post` lazily create the client, but `http_download` takes `&self` and errors "HTTP client not initialized" unless some other call ran first — inconsistent API behavior.
- Fix suggestion: make it `&mut self` and lazily initialize like the other methods.

## [LOW] `tcp_connect` maps every connect failure to WSAECONNREFUSED (10061)

- File: src/real_net.rs:670-676
- Description: DNS failures, timeouts, and network-unreachable errors all set `last_wsa_error = 10061`, misleading guest error reporting (host-not-found/timeout codes never surface).
- Fix suggestion: map by error kind (reuse `map_wsa_error`-style logic, e.g. `WouldBlock`→10035, `TimedOut`→10060, DNS failure→11001).

## [LOW] `tls_connect` — no connect timeout

- File: src/real_net.rs:893-898
- Description: `TcpStream::connect((host, port))` can block for minutes on unreachable hosts, with no timeout option.
- Fix suggestion: accept an optional timeout and use `TcpStream::connect_timeout`.

## [LOW] `RealTlsStream::nonblocking` field is never set or consulted

- File: src/real_net.rs:288-316
- Description: The field is written only at construction (`false`); no non-blocking/timeout API exists for TLS streams, so callers cannot get non-blocking TLS.
- Fix suggestion: add `set_nonblocking`/`set_timeout` forwarding to the underlying `TcpStream` (via `get_ref`/`get_mut`).

## [LOW] `tcp_listen` ignores the backlog and prints to stderr on every listen

- File: src/real_net.rs:761-764
- Description: The requested `backlog` is discarded (std `TcpListener` uses its own default) and `eprintln!` fires for every non-zero backlog — noisy for Steam servers that always pass a backlog. Windows `listen(backlog)` semantics are not honored.
- Fix suggestion: use `libc::listen(fd, backlog)` via `AsRawFd` (or drop the eprintln), and cap the backlog.

## [LOW] `parse_spnego_token` silently truncates oversized DER length fields

- File: src/network.rs:2613-2629, 2641-2657, 2665-2681
- Description: `l = (l << 8) | byte` with `num_bytes >= 9` discards high bits on `usize` (no panic; shift discards), so adversarial tokens with long-form lengths produce garbage lengths. All subsequent slices are bounds-checked, so impact is limited to mis-parsing (returns None), but the length arithmetic should still be validated.
- Fix suggestion: reject `num_bytes > size_of::<usize>()` (or > 8) and bound `l` against the remaining token length.

## [LOW] `select` reports real streams with EOF (FIONREAD == 0) as not readable

- File: src/network.rs:1315-1343
- Description: On Windows a closed/EOF socket is readable (read returns 0); here `bytes_available(stream)? > 0` stays false after the peer closes, so a guest select/poll loop can spin waiting for readability that never signals.
- Fix suggestion: treat stream EOF as readable (track `shutdown`/EOF state on the record, or fall back to `peek`).

## [LOW] `recv` mock path uses `expect("recv queue entry")`

- File: src/network.rs:1229-1233
- Description: `record.recv_queue.pop_front().expect(...)` — provably safe today (`count` is min'd with the queue length), but an unnecessary panic site in a guest-facing path.
- Fix suggestion: use `if let Some(b) = ... { bytes.push(b) } else { break }`.

## [LOW] Test busy-wait spin (`thread::yield_now()` loop)

- File: src/real_net.rs:1196-1198
- Description: `tcp_connect_and_exchange_data` spins on an `AtomicBool` until the listener thread signals readiness; also, the test's server thread blocks on `accept` while the test body drops the join handle — the test only checks the spin-up path, and a scheduler hiccup makes it slow/flaky.
- Fix suggestion: use a `Condvar`/`mpsc` channel, or simply hand the port back via the join value.

---

## [PERF] `security find-certificate` subprocess spawned per QUIC connection

- File: src/network.rs:2900-2911 (called from `quic_root_certs` ← `quic_client_config` ← `quic_create_connection`)
- Description: Each QUIC client connection forks a `security` process (plus reads up to 5 cert files) to build the root store; for connection-per-request workloads this is a heavyweight per-connection cost.
- Fix suggestion: cache the root store (e.g. `OnceLock<RootCertStore>`).

## [PERF] `wsa_poll`/`select` do O(n²) `contains` lookups

- File: src/network.rs:1345-1355
- Description: `wsa_poll` builds `readable`/`writable` then calls `readable.contains(socket)`/`writable.contains(socket)` per socket — quadratic in the number of polled sockets. Poll sets are typically small, but under a game with hundreds of sockets this adds up.
- Fix suggestion: build the poll results in one pass with a single iteration over the (sorted) result vectors, or use `HashSet`.

---

## Clippy

Warnings from the clippy run that reference the audited files (all emitted before the crate-wide compile failure; see Build):

`src/network.rs`:
- `empty_line_after_doc_comments` — src/network.rs:37 (doc comment on `HttpProtocolFlags`)
- `len_without_is_empty` — src/network.rs:293 (`PinnedCertificates::len`)
- `too_many_arguments` — src/network.rs:916 (`add_route`, 9/7)
- `collapsible_if` — src/network.rs:1271 (closesocket), 2900 (load_native_certs), 3030 and 3044 (parse_host_port)
- `manual_strip` — src/network.rs:3036 (`rest[1..]` after `starts_with(':')`)
- `single_match` — src/network.rs:4135 (test `dns_unknown_host_falls_back_to_system`)

`src/real_net.rs`:
- `new_without_default` — src/real_net.rs:606 (`RealNetworkStack::new`)
- `no_effect` — src/real_net.rs:636 (`self.last_wsa_error;`)
- `needless_borrows_for_generic_args` — src/real_net.rs:668 (`TcpStream::connect(&socket_addr)`)
- `unnecessary_mut_passed` — src/real_net.rs:1122, 1131 (`FD_ISSET(..., &mut read_set)`)
- `items_after_test_module` — src/real_net.rs:1145 (`impl RealNetworkStack` defined after `mod tests`)

## Build

`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` **failed to compile** (so no clippy `--no-deps` final verdict): `error: could not compile 'casa1' (lib) due to 19 previous errors` and `(lib test) due to 27 previous errors`. All 19 lib errors are deny-level clippy lints in **other** files — e.g. `crash_recovery.rs:536` (absurd_extreme_comparisons), `jit.rs:34/49/71/...` (not_unsafe_ptr_arg_deref, 12×), `pe_runtime.rs:48799` (uninit_vec), `security.rs:3097` and `winhttp.rs:3624` (nonminimal_bool), `d2d.rs:974` (identity_op), plus approx-constant errors. **None** of the errors reference `src/network.rs` or `src/real_net.rs`; both files were fully analyzed (their warnings appear above). The failure is a pre-existing crate-wide condition (new clippy deny lints / environmental), not caused by the audited files.
