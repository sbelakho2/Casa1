# AUDIT_FINDINGS.md — Casa1 HTTP stack audit

- **Batch:** audit-http
- **Files:** `src/winhttp.rs` (4745 lines), `src/wininet.rs` (2313 lines) — read in full, sequentially
- **Lines:** winhttp.rs 1–4745; wininet.rs 1–2313
- **Date:** 2026-08-15
- **Tooling:** `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (no `--all-features`); manual code review

Severity legend: CRITICAL = crash/UB/security/data corruption; HIGH = definite wrong behavior; MEDIUM = edge-case bug; LOW = quality/dead code; PERF = performance.

---

## [CRITICAL] Guest-controlled `url_length` slice panics on non-UTF-8 boundary (InternetCrackUrlW / InternetCanonicalizeUrlW)

- File: `src/winhttp.rs:1736` and `src/winhttp.rs:1809` (identical copies in `src/wininet.rs:1175` and `src/wininet.rs:1260`)
- Description: `let url = if (url_length as usize) < url.len() { &url[..url_length as usize] } else { url };` slices a Rust `&str` at an arbitrary guest-supplied byte offset. `url_length` is passed straight from the guest (`pe_runtime.rs:36782` `guest_call_arg_u32` / `pe_runtime.rs:36810`) and is a UTF-16-unit count per WinINet semantics, which rarely equals a UTF-8 character boundary. Any URL containing non-ASCII characters (or any odd/garbage `url_length`) panics the host process with a string-slice-out-of-bounds. Reachable from untrusted guest input via `HostThunk::InternetCrackUrlW` (`pe_runtime.rs:36791`) and `HostThunk::InternetCanonicalizeUrlW` (`pe_runtime.rs:36819`). The wininet.rs copies are currently unreferenced but carry the same bug.
- Fix suggestion: Truncate at a char boundary instead of slicing blindly, e.g. slice `&url[..url_length.min(url.len())]` and then `char_indices()`-trim the tail, or validate `url.is_char_boundary(url_length as usize)` and clamp to the nearest boundary. Also cap `url_length` against the string length before slicing.

## [HIGH] Out-of-bounds index in CRL serial scan can panic on crafted CRL bytes

- File: `src/winhttp.rs:4387` (also `:4389-4390`)
- Description: In `check_serial_in_crl`, after parsing a revoked-certificate entry the walker advances with `pos = pos + 1 + der_length_size(crl_der[pos + 1] as usize) + crl_der[pos + 1] as usize;`. If the last TLV of `tbsCertList` starts at the final byte of the CRL buffer (`pos + 1 == crl_der.len()`), `crl_der[pos + 1]` is an out-of-bounds index → panic. The CRL bytes come from a network fetch of a URL embedded in the certificate (attacker-controllable). Additionally the advance uses the raw length byte (short-form only), so long-form lengths mis-advance and produce false parse results. `verify_certificate` (the only caller) is currently unreferenced (dead code), so this is not yet exploitable end-to-end, but the function is `pub`.
- Fix suggestion: Replace the raw-byte advance with a bounds-checked `der_read_length` call (mirror the branch at line 4395), e.g. `let len_off = pos + 1; if let Some(l) = der_read_length(crl_der, &mut len_off) { pos = len_off + l; } else { break; }`, and guard `pos + 1 < crl_der.len()`.

## [HIGH] NTLM Type 1 (NEGOTIATE) message has wrong payload offsets and omits UNICODE flag

- File: `src/winhttp.rs:3060-3106`
- Description: Fixed header is 32 bytes; payload is appended as [domain][workstation]. Declared `domain_offset = 32 + ws_len` and `ws_offset = 32` are both wrong whenever both domain and workstation are non-empty (the common corporate case): actual positions are 32 and 32+domain_len. More critically, the message never sets `NEGOTIATE_UNICODE` (0x00000001) while encoding all strings as UTF-16LE — per the NTLM spec servers may reject or misparse the message. Result: NTLM authentication fails against real servers.
- Fix suggestion: Compute offsets from the actual append order (domain at 32, workstation at 32+domain_len) and include `NEGOTIATE_UNICODE` in the flags word.

## [HIGH] NTLM Type 3 (AUTHENTICATE) payload offsets are off by 8 bytes and UNICODE flag missing

- File: `src/winhttp.rs:3282-3355`
- Description: The fixed header (signature+type+5×sec-buf+session key+flags) is 64 bytes, but the 8-byte OS Version block is appended before the payload, so the payload actually starts at 72. All declared offsets (`lm_offset = 64`, `ntlm_offset`, `domain_offset`, `user_offset`, `ws_offset`) are 8 bytes short, so every server-side parse of the payload is garbage. The flags field also lacks `NEGOTIATE_UNICODE` (and `NEGOTIATE_VERSION` is set even though the flag for it is not), and the LM response is 24 zero bytes.
- Fix suggestion: Include the 8-byte version in the fixed-header size (base offsets at 72) and set the UNICODE/VERSION flags consistent with the actual message layout.

## [HIGH] NTLMv2 response blob missing the 0x01010000 signature and reserved field

- File: `src/winhttp.rs:3375-3406`
- Description: `compute_ntlmv2_response` builds the NT-Proof blob starting directly with the timestamp. Per MS-NLMP the blob must begin with `0x01010000` (respType+hiRespType+reserved1+reserved2) followed by 4 reserved bytes before the timestamp. As written the blob is malformed and the derived session key differs from the server's computation — authentication will be rejected.
- Fix suggestion: Prepend `[0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]` (8 bytes) before the timestamp.

## [HIGH] FTP greeting terminator comparison is always false → 30 s stall on every FTP connect

- File: `src/wininet.rs:596`
- Description: `if greeting.len() >= 4 && &greeting[greeting.len() - 4..] == b"\r\n"` compares a 4-byte slice to a 2-byte array — always false. The banner-read loop therefore never terminates on a complete greeting and runs until the 30 s read timeout (`Err(TimedOut)`), adding a mandatory 30-second stall to every FTP connection. The banner status (220) is never validated, and the timeout error is silently swallowed.
- Fix suggestion: Check the last two bytes: `greeting.ends_with(b"\r\n")` (and optionally validate the leading "220" code).

## [HIGH] WinINet scheme inference ignores INTERNET_FLAG_SECURE; port 0 is treated as https

- File: `src/wininet.rs:525-530` and `src/wininet.rs:786-790`
- Description: `InternetConnection` has no secure flag; `INTERNET_FLAG_SECURE` passed to `internet_connect_w` is only logged, and `http_send_request_w` infers the scheme purely from the port: `if port == 443 || port == 0 { "https" } else { "http" }`. Consequences: a guest requesting TLS (`INTERNET_FLAG_SECURE`, e.g. port 80) silently gets plaintext HTTP — credentials/headers go unencrypted; and port 0 (WinINet's "default port" convention) produces `https://host:0` which cannot connect at all.
- Fix suggestion: Store the secure flag on `InternetConnection` at connect time (from `INTERNET_FLAG_SECURE`) and use it in `http_send_request_w`; treat port 0 as 80/443 based on that flag instead of a raw port comparison.

## [HIGH] WinHTTP FTP path is dead on arrival — no control connection is ever established

- File: `src/winhttp.rs:394` (map), `src/winhttp.rs:2137-2143` (only consumer)
- Description: `ftp_control` is only read (via `ftp_command`); nothing in the codebase ever inserts a `TcpStream` into it. All WinHTTP-path FTP operations (`ftp_open_file_w`, `ftp_get_file_w`, `ftp_put_file_w`, etc., dispatched from `pe_runtime.rs:37052`/`:37085`) immediately fail with "FTP: no control connection for handle". Meanwhile the WinINet stack (wininet.rs) has a working control-connection setup — the WinHTTP FTP feature is entirely broken.
- Fix suggestion: Either wire `win_http_connect`/`internet_connect_w` to also populate `WinHttpStack::ftp_control` for FTP service connections, or remove the WinHTTP FTP API and route those host thunks to the WinINet stack.

## [HIGH] WinINet FTP transfer operations swallow errors and always return success

- File: `src/wininet.rs:1562-1593` (`ftp_get_file_w`), `src/wininet.rs:1596-1634` (`ftp_put_file_w`), `src/wininet.rs:1637-1646` (`ftp_delete_file_w`)
- Description: RETR command failures are logged and ignored (`if let Err(e) = self.ftp_command(...) { eprintln! }`), then an empty data read produces an empty local file while the function still returns `Ok(true)`. `std::fs::write` failure is logged but also returns `Ok(true)`. `ftp_put_file_w` ignores STOR failures and write/flush errors, returning `Ok(true)` even when nothing was uploaded. `ftp_delete_file_w` ignores the DELE response entirely and always returns `Ok(true)`. `_fail_if_exists` is ignored, so existing local files are silently overwritten. Callers cannot distinguish success from failure — data loss / silent corruption.
- Fix suggestion: Propagate errors: check the RETR/STOR/DELE response codes (e.g. reject non-2xx/3xx), return `Err` on `fs::write` failure, and honor `_fail_if_exists`.

## [HIGH] WinINet `ftp_open_file_w` discards downloaded data and sends QUIT

- File: `src/wininet.rs:1518-1558`
- Description: The function reads the entire file from the data connection into `_file_data` and immediately drops it, stores a transfer record with no data, and then sends `QUIT` on the control connection — which closes the server-side control session. Subsequent FTP commands on the same connection handle fail (the stale stream stays in `ftp_control_streams`). Any caller using the returned handle to read file data gets nothing, and the connection is poisoned.
- Fix suggestion: Cache the downloaded bytes (as winhttp.rs:2311-2318 does with `ftp_file_data`) or stream them on demand; do not send QUIT; let the guest close the handle.

## [HIGH] Unbounded HTTP response buffering (memory DoS) in WinHTTP; WinINet limit is post-download

- File: `src/winhttp.rs:1166`; `src/wininet.rs:942-955`
- Description: `response.bytes()` reads the complete body into memory with no size limit in winhttp (a malicious server can stream gigabytes; the request body is capped at 256 MB but the response is not). WinINet does enforce `MAX_WININET_RESPONSE_BODY`, but only *after* the whole body has been downloaded and cloned, so the limit does not prevent the allocation.
- Fix suggestion: Cap via `response.content_length()` pre-check and a streaming read (`bytes_stream()` / `Read::take(MAX + 1)`) that aborts once the cap is exceeded.

---

## [MEDIUM] Unknown HTTP verbs silently mapped to GET

- File: `src/winhttp.rs:1063-1071`; `src/wininet.rs:840-848`
- Description: Any verb outside GET/POST/PUT/DELETE/HEAD/PATCH (e.g. OPTIONS, PROPFIND, CONNECT, custom verbs) is silently sent as GET, changing semantics and payload handling. Guest-visible wrong behavior (a PROPFIND becomes a GET with the body dropped).
- Fix suggestion: Use `reqwest::Method::from_bytes` on the verb and return an error for unrepresentable verbs instead of defaulting to GET.

## [MEDIUM] `WinHttpCloseHandle` leaks FTP sockets, listing caches, and cert contexts

- File: `src/winhttp.rs:856-879`
- Description: Closing a connection handle does not remove `ftp_control` (the live `TcpStream` socket stays open until process exit), nor `ftp_current_dir`/`ftp_binary_mode`/`ftp_data_addr`/`ftp_listing_cache`/`ftp_listing_index`/`revocation_handlers`/`client_cert_contexts`. Repeated open/close of FTP connections leaks file descriptors and unbounded map growth. (wininet.rs `internet_close_handle` handles its equivalents correctly at wininet.rs:1014-1018.)
- Fix suggestion: Remove all per-handle maps in `win_http_close_handle`, matching the WinINet cleanup pattern.

## [MEDIUM] WinINet FTP login failures are swallowed; handle returned as valid

- File: `src/wininet.rs:662-666` (connect failure), `src/wininet.rs:631-657` (PASS/530 handling)
- Description: If the TCP connect or login fails (e.g. 530 on PASS), the function logs and still returns `Ok(handle)` with no usable control stream, or with a stream in a failed-auth state. Downstream operations then fail confusingly instead of the connect call failing.
- Fix suggestion: Propagate connect/login errors as `Err` (or mark the connection unusable and fail subsequent operations deterministically).

## [MEDIUM] `InternetSetOptionW` INTERNET_OPTION_PROXY has no effect on requests

- File: `src/wininet.rs:1051-1097`
- Description: The option stores the parsed proxy string into `session.proxy` (and never parses the bypass list), but `http_send_request_w` only consults `self.proxy`, which is never updated. A guest configuring a proxy via `InternetSetOptionW` gets direct connections anyway (or, if `set_proxy` was used, stale config).
- Fix suggestion: Update `self.proxy` (and the bypass list) in `internet_set_option_w`, or read `session.proxy` when building the request.

## [MEDIUM] Connect/Receive timeout options are stored but never applied

- File: `src/winhttp.rs:1449-1457`; `src/wininet.rs:1106-1121`
- Description: `WINHTTP_OPTION_CONNECT_TIMEOUT`/`INTERNET_OPTION_CONNECT_TIMEOUT`/`INTERNET_OPTION_RECEIVE_TIMEOUT` write `timeout_ms`, which is never read; the reqwest client is hardcoded to 30 s (`winhttp.rs:1045`, `wininet.rs:811`). Guests setting a 5 s timeout still wait 30 s (and a 120 s timeout is clamped to 30 s).
- Fix suggestion: Apply `timeout_ms` when building the client per request (`Duration::from_millis(req.timeout_ms as u64)`), defaulting to 30 s.

## [MEDIUM] Reqwest client cached with the first request's proxy settings; https proxies silently dropped

- File: `src/winhttp.rs:1041-1061`
- Description: `self.client.get_or_insert_with(...)` captures `proxy_cfg`/`should_bypass` from the first request; later `WinHttpSetOption(WINHTTP_OPTION_PROXY)` changes (winhttp.rs:1408-1414) never rebuild the client, so proxy changes are ignored. Additionally `reqwest::Proxy::http` is used for both `http://` and `https://` proxy URLs — https proxies fail `Proxy::http` and are silently discarded (`if let Ok(proxy) = ...`). WinINet builds a fresh client per request (so it is not affected by the cache issue).
- Fix suggestion: Rebuild the client when the proxy config changes (track a config generation/checksum), and use `Proxy::https`/`Proxy::all` for `https://` proxy URLs; log instead of silently ignoring invalid proxy configs.

## [MEDIUM] FTP RETR response never checked — server error yields empty file with success

- File: `src/winhttp.rs:2307-2311` and `src/winhttp.rs:2346-2350`
- Description: `let _retr_response = self.ftp_command(...)` ignores the RETR reply; on a 550 (file not found) the data connection closes immediately, `ftp_read_data` returns empty, and the local file is written empty with `Ok(true)` (winhttp) or the cached data is empty. (wininet.rs has the same flaw, covered in the HIGH finding above.)
- Fix suggestion: Inspect the RETR response; on non-2xx/3xx, abort with an error before writing the file.

## [MEDIUM] FTP command injection via unsanitized CR/LF in guest-controlled operands

- File: `src/winhttp.rs:2307, 2418, 2436, 2444, 2461, 2501, 2518, 2542`; `src/wininet.rs:607, 635, 1527, 1579, 1620, 1642, 1655, 1664, 1682, 1722, 1740, 1763`
- Description: Commands are built as `format!("RETR {file_name}")` etc. and sent with `\r\n` appended. Filenames/patterns (and USER/PASS strings) are not sanitized: an operand containing `\r\n` injects arbitrary FTP commands into the control stream. Server-controlled listing names returned by NLST can carry such data back into RETR/DELE (server-mediated injection).
- Fix suggestion: Reject operands containing `\r`/`\n` (return an error) before building the command.

## [MEDIUM] Cookie jar: domain attribute trusted unchecked, secure flag ignored, jar grows unbounded

- File: `src/winhttp.rs:633-655` and `src/winhttp.rs:696-752`; `src/wininet.rs:307-327` and `src/wininet.rs:365-416`
- Description: `parse_and_store_set_cookie` stores the cookie under whatever `Domain` attribute the server sent (`self.set_cookie(&cookie.domain.clone(), ...)`) with no validation that the domain is a parent of the responding host — a server can inject cookies for arbitrary hosts, which are then sent to those hosts on future requests. `get_cookies` never filters on `secure`, so secure cookies are sent over plaintext HTTP. Expired cookies are skipped but never pruned, and there is no cap on jar size: an attacker server issuing unbounded `Set-Cookie` headers grows memory without limit.
- Fix suggestion: Store under the responding host and validate `Domain` against the host suffix; skip `secure` cookies for http schemes; prune expired entries and cap the jar (e.g. LRU).

## [MEDIUM] Proxy bypass uses substring matching — wrong hosts bypass the proxy

- File: `src/winhttp.rs:764-784` (`should_bypass_proxy`), `src/winhttp.rs:3718-3729` (no_proxy), `src/wininet.rs:425-443`
- Description: `url.contains(bypass)` treats a bypass entry like `example.com` as matching `https://notexample.com/` and `https://example.com.evil.net/`; `no_proxy` matching has the same flaw. Traffic to hosts that should be proxied goes direct (privacy/security: the direct path bypasses the corporate proxy), and `*.` prefix handling still uses substring containment.
- Fix suggestion: Match on the URL host with proper suffix rules: parse the host and compare `host == entry || host.ends_with(&format!(".{entry}"))`.

## [MEDIUM] `win_http_set_option_extended` SECURITY_FLAGS overwrites HTTP protocol flags

- File: `src/winhttp.rs:4688-4706`
- Description: `WINHTTP_OPTION_SECURITY_FLAGS` (31) writes the security flags into `session.enabled_protocols`, clobbering any previously set `WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL` flags (159). A guest enabling revocation checking (0x08000000) silently disables HTTP/2-3 negotiation state.
- Fix suggestion: Store security flags in a dedicated field; do not reuse `enabled_protocols`.

## [MEDIUM] Response-header queries are case-sensitive

- File: `src/winhttp.rs:1330-1338`
- Description: `win_http_query_headers` looks up `req.response_headers.get(header_name)`; keys come from reqwest's `HeaderName::to_string()` (lowercase), while WinHTTP/WinINet are case-insensitive. A guest querying `"Content-Type"` or `"Content-Length"` gets `RcNetHttpHeaderNotFound` even when the header exists.
- Fix suggestion: Store headers lowercase and lowercase the query, or perform a case-insensitive scan.

## [MEDIUM] PAC / CRL / OCSP network fetches without timeout or size limit

- File: `src/winhttp.rs:3669-3679` (`fetch_pac_script`), `src/winhttp.rs:4232-4248` (CRL fetch), `src/winhttp.rs:4118-4160` (OCSP POST)
- Description: `reqwest::blocking::get` uses the default client with no timeout — a non-responding PAC/CRL server blocks the emulator thread indefinitely; `response.text()`/`bytes()` have no size cap. (The OCSP POST has a 10 s timeout but its response is also uncapped.)
- Fix suggestion: Use a client with an explicit timeout (e.g. 10 s) and read with a byte cap (`Read::take`).

## [MEDIUM] PAC evaluator logic flaws (`find_return_in_block`)

- File: `src/winhttp.rs:3611-3630` (and `src/winhttp.rs:3624` duplicated condition)
- Description: `find_return_in_block` locates the current line via `position(|l| *l == current_line)` — if the identical line text appears earlier in the script (common: repeated `if (dnsDomainIs(host, ".example.com")) {` blocks), the search starts from the wrong index and returns the wrong (or no) proxy. The scan also continues past `}` without terminating the block, so the returned value can belong to a later `if` block. The `l == "}" || l == "}"` duplicate is a build-breaking clippy error (see Clippy section).
- Fix suggestion: Pass the line index instead of matching by value, and stop scanning at the first unmatched `}`.

## [MEDIUM] PAC "SOCKS" result is prefixed with `http://`

- File: `src/winhttp.rs:3705-3711`
- Description: `if let Some(proxy_str) = result.strip_prefix("SOCKS ") { return Some(format!("socks5://{}", proxy_str)); }` — a PAC returning `SOCKS proxy:1080` yields `socks5://proxy:1080` (correct), but a raw `socks5://...` string (from env `all_proxy`, which often carries the scheme) falls through to the fallback at line 3709-3711 and becomes `http://socks5://host:port` — a malformed URL that silently fails (or is routed wrong).
- Fix suggestion: Detect `socks4`/`socks5` schemes explicitly and only add `http://` when the result has no scheme.

## [MEDIUM] Proxy credentials leaked to stderr logs

- File: `src/winhttp.rs:1415-1418` (`WinHttpSetOption: proxy set to {proxy_url}`), `src/winhttp.rs:3765-3807` (`winhttp_set_proxy_config` logs `config={:?}`), `src/wininet.rs:1086-1089`
- Description: Proxy URLs frequently embed `user:password@` (e.g. `http://user:pass@proxy:8080`); logging the full proxy string (or `Debug` of the config) writes credentials to stderr. `win_http_set_credentials` also prints the user name (winhttp.rs:1636-1641).
- Fix suggestion: Redact userinfo when logging proxy URLs (`format!("{}://{}@{}", scheme, "[redacted]", host)`), and drop `{:?}` of configs containing auth.

## [MEDIUM] OCSP/CRL revocation machinery is dead code and misreads revocation status

- File: `src/winhttp.rs:4043-4164` (`check_ocsp_revocation`), `src/winhttp.rs:4466-4510` (`verify_certificate`), `src/winhttp.rs:4654-4658` (`get_pinned_cert_hash`)
- Description: `verify_certificate` has no callers in the crate, and `get_pinned_cert_hash` unconditionally returns `None`, so the OCSP/CRL checks never run. Independently, the OCSP logic treats `ENUMERATED 0x0a 0x01 <status>` with `status == 1` as "revoked" — but status 1 is `malformedRequest`; "revoked" is encoded inside `responseBytes.certStatus` (tag 0xa1) and is never examined. Also the OCSP request body `[0x30, 0x00]` is an empty DER sequence that real responders reject, so even if reached the check is non-functional.
- Fix suggestion: Either remove the dead functions or wire them into the request path with a correct OCSP client (parse `CertStatus` 0xa1), and treat only `successful(0)` responses as conclusive.

## [MEDIUM] `extract_spki_der` performs unchecked length arithmetic on untrusted DER

- File: `src/winhttp.rs:424-510`; `src/wininet.rs:176-240`
- Description: `read_tag`/`skip_tlv` accept arbitrarily large lengths (up to 127 length bytes). `*offset += len` and `off + outer_len` can overflow usize (debug builds panic on overflow; release builds wrap), and the final `data[spki_start..spki_end]` slice is only guarded by wrapped comparisons — a crafted DER (e.g. from a TLS peer in `verify_certificate_pin`, winhttp.rs:599-611) can panic. Exploitability is reduced because the input is the TLS-validated leaf certificate, but the parser should be hardened.
- Fix suggestion: Reject lengths that exceed the remaining buffer immediately in `read_tag` (compare `*offset + len` against `data.len()` before advancing), and cap `num_bytes` (e.g. ≤ 4, as `der_read_length` at winhttp.rs:3883 does).

## [MEDIUM] Per-request reqwest client in WinINet (no connection reuse)

- File: `src/wininet.rs:808-838`
- Description: A brand-new `reqwest::blocking::Client` (new TLS stack, new connection pool) is built on every `HttpSendRequestW`. Each request pays full TCP+TLS handshakes; keep-alive pooling across requests is lost. Games issuing many small requests see significant latency.
- Fix suggestion: Cache the client per (proxy, timeout) config on the stack, like winhttp.rs:1041 does, or store it on the session.

## [MEDIUM] Global bind-status-callback registry grows unbounded

- File: `src/wininet.rs:1988-2026`
- Description: `BIND_STATUS_CALLBACKS` is a process-global `Mutex<HashMap<u64, _>>`; `register_bind_status_callback` never evicts and nothing enforces revocation. A guest registering callbacks with fresh context handles leaks entries for the process lifetime.
- Fix suggestion: Cap the map size (evict oldest on overflow) or key by a guest-visible handle with mandatory revocation.

---

## [PERF] `Vec::drain` in read paths makes small-buffer reads O(n²)

- File: `src/winhttp.rs:1276` (`req.response_body.drain(..to_read)`), `src/winhttp.rs:1284` (`ftp_file_data.drain`), `src/winhttp.rs:2074` (`ws.receive_buffer.drain`), `src/wininet.rs:1006`
- Description: Each `WinHttpReadData`/`InternetReadFile` call with a small buffer shifts the entire remaining response; a 100 MB body read in 4 KB chunks performs ~25 000 memmoves of ~50 MB average — quadratic. Also retains full capacity forever.
- Fix suggestion: Maintain a read offset (`cursor`) into the Vec and only drop/truncate at completion (or use a `VecDeque`/`Bytes`).

## [PERF] FTP command reader does one syscall per byte

- File: `src/winhttp.rs:2152-2190`; `src/wininet.rs:1373-1414`
- Description: Both `ftp_command` implementations read the control response with `let mut buf = [0u8; 1]` in a loop — one `read()` syscall per byte of every response. A 16 KB banner costs 16 K syscalls.
- Fix suggestion: Read into a 4-8 KB buffer and process the lines from it.

## [PERF] Response bodies double-buffered / cloned in hot paths

- File: `src/winhttp.rs:1116` (`req.body.clone()` up to 256 MB), `src/winhttp.rs:1166-1172` (`response.bytes()` then `response_body = body_bytes.clone()`), `src/wininet.rs:896` and `src/wininet.rs:942-956`
- Description: The full response is materialized twice (once in `body_bytes`, once in `req.response_body`), and POST bodies are cloned per send. Peak memory is ~2× body size.
- Fix suggestion: Move the `Bytes` into the request record (no clone) and take ownership of the body (`std::mem::take`) instead of cloning.

## [PERF] FTP data reads have no timeout and no size limit; whole files cached in RAM

- File: `src/winhttp.rs:2261-2278` and `src/winhttp.rs:2311`; `src/wininet.rs:1493-1510`
- Description: The PASV data stream is used in blocking mode without a read timeout, so a stalled server hangs the transfer indefinitely; data is read until EOF with no cap (unbounded memory), and winhttp caches the entire file in `ftp_file_data` before returning a handle.
- Fix suggestion: Set a read timeout (as done for the control stream at wininet.rs:577-582) and cap the transfer size (e.g. 256 MB) with an error.

## [PERF] WinINet `ftp_find_next_file_w` re-splits the listing on every call

- File: `src/wininet.rs:1803-1826`
- Description: Each call does `file_list.split('\n').collect()` over the whole listing to index one entry — O(n²) across a full enumeration.
- Fix suggestion: Pre-split once into `FtpTransfer` (or the stack) and store the parsed Vec plus index.

## [PERF] `create_url_moniker` buffers the full body twice

- File: `src/wininet.rs:2078-2105`
- Description: `response.bytes()` loads the entire download, then the chunk loop copies it into `data` again; `downloaded`/`total` are `u32` (truncate above 4 GiB) and there is no size cap.
- Fix suggestion: Stream via `bytes_stream()` into `data` with a cap, and use `u64`/`usize` counters.

---

## [LOW] Misc findings

### [LOW] WinHTTP handle space starts at 0 — first handle is the invalid/null value
- File: `src/winhttp.rs:518` (`next_handle: 0`), `src/winhttp.rs:824-828`
- Description: The first `win_http_open` returns handle `0`, which Win32 semantics treat as invalid/NULL; guest code comparing handles against 0 misbehaves. (wininet.rs correctly starts at 1, wininet.rs:159.)
- Fix suggestion: Start `next_handle` at 1.

### [LOW] `hex_decode` is dead code and panics on non-ASCII input if ever used
- File: `src/winhttp.rs:560-565`; `src/wininet.rs:259-264`
- Description: No callers anywhere. The `&hex[i..(i+2).min(hex.len())]` slicing steps by byte offset and will panic on a non-ASCII (multi-byte UTF-8) hex string.
- Fix suggestion: Remove the functions, or iterate `bytes()` / `is_char_boundary`-checked.

### [LOW] `client.build().expect(...)` can panic
- File: `src/winhttp.rs:1060`
- Description: Reqwest client construction failure (TLS backend misconfig, invalid options) panics instead of returning an error, unlike the WinINet path (wininet.rs:833-838) which maps the error.
- Fix suggestion: Use `map_err` like wininet.rs.

### [LOW] Status callbacks are stored but never invoked
- File: `src/winhttp.rs:1555-1570`; `src/wininet.rs:1142-1163`
- Description: `callback`/`callback_notify_flags` are recorded but no notification is ever dispatched to the guest; the API is a no-op that apps rely on for progress/state.
- Fix suggestion: Implement a dispatch (or document and return an error for unsupported flag combinations).

### [LOW] `InternetGetLastResponseInfoW` returns a hardcoded code and empty text
- File: `src/winhttp.rs:1722-1724`; `src/wininet.rs:1134-1137`
- Description: Always returns `(12002, last_response_error)` where `last_response_error` is only written on WinINet send failure (wininet.rs:906) and never in winhttp; 12002 is `ERROR_INTERNET_CANNOT_CONNECT` — not the actual last error.
- Fix suggestion: Populate `last_response_error` from the actual last failure and return the matching WinINet error code.

### [LOW] Dead state: unused fields and never-read maps
- File: `src/winhttp.rs:411-416` (`revocation_handlers`, `client_cert_contexts`, `pac_cache`, `ftp_data_addr`), `src/winhttp.rs:115` (`callback`), `src/winhttp.rs:88` (`enabled_protocols` never read beyond QUERY), `src/wininet.rs:68-75` (`session.proxy`/`proxy_bypass` never read), `src/wininet.rs:42-49` (`FtpTransfer.session_handle` actually stores the connection handle, wininet.rs:1537)
- Description: Several maps are written but never read (`revocation_handlers`, `client_cert_contexts`, `pac_cache`, `ftp_data_addr`), so PAC caching and revocation/cert features silently do nothing; several struct fields shadow real state.
- Fix suggestion: Remove or wire up; fix the `FtpTransfer.session_handle` semantic misuse.

### [LOW] `internet_canonicalize_url_w` leaves bare `%` unencoded and drops trailing slashes
- File: `src/wininet.rs:1270-1314` and `src/wininet.rs:2129-2160`
- Description: `'%' => false` in `needs_percent_encoding` means `100%` canonicalizes to `100%` instead of `100%25` (the preserve-check only affects valid `%HH`). `collapse_dot_segments` also removes trailing slashes (`/a/` → `/a`) despite the comment claiming they are preserved.
- Fix suggestion: Encode `%` unless followed by two hex digits; re-append a trailing `/` when the original path ended with one.

### [LOW] WebSocket text mode derived from the Sec-WebSocket-Protocol header value
- File: `src/winhttp.rs:1873-1879`
- Description: `is_text_mode` matches the negotiated *subprotocol* header (`"text"`/`"text-only"`), which is unrelated to frame encoding; a client negotiating subprotocol `chat` gets a binary-mode buffer type. (Each send already passes its own `buffer_type`, so the impact is limited to the stored state.)
- Fix suggestion: Initialize `buffer_type` from the guest's send/receive usage or leave it Binary and let per-call buffer types govern.

### [LOW] `response.bytes().unwrap_or_default()` swallows read errors
- File: `src/winhttp.rs:1166`; `src/wininet.rs:942`
- Description: A mid-body network error silently produces an empty/truncated body with success status; guests see a successful request with truncated data.
- Fix suggestion: Propagate the error (return `Err`) unless the response is HEAD/204/304.

### [LOW] `u32` truncation of sizes/lengths
- File: `src/winhttp.rs:1277` and `src/winhttp.rs:1304`; `src/wininet.rs:1008` and `src/wininet.rs:1045`; `src/wininet.rs:2068` and `src/wininet.rs:2088`
- Description: `read`/`query_data_available` results and moniker sizes cast `usize`/`u64` to `u32`; buffers/bodies above 4 GiB wrap.
- Fix suggestion: Clamp or return an overflow error instead of truncating.

### [LOW] Deprecated `SecTrustEvaluate` used in FFI
- File: `src/winhttp.rs:4547`
- Description: `SecTrustEvaluate` is deprecated on modern macOS (replaced by `SecTrustEvaluateWithError`); the FFI path may return stale results or be unavailable in future OS versions. Memory management in the FFI block is otherwise balanced (all CF objects released).
- Fix suggestion: Use `SecTrustEvaluateWithError`.

### [LOW] `win_http_query_auth_schemes` scans all response headers, not just WWW-Authenticate
- File: `src/winhttp.rs:1687-1713`
- Description: Any header whose value contains "basic"/"ntlm"/"digest"/"negotiate" (e.g. a body header or a descriptive one) is treated as a supported scheme; also matches substrings like "notbasic".
- Fix suggestion: Restrict the scan to `WWW-Authenticate`/`Proxy-Authenticate` headers and parse scheme tokens properly.

---

## Clippy

`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` — see `clippy_out.txt` in the worktree root for full output.

**Lints in audited files (93 references):**

- `error (clippy::eq_op)`: equal expressions as operands of `||` — `src/winhttp.rs:3624` (`l == "}" || l == "}"`). This is 1 of the 27 deny-level errors that fail the build (see Build).
- `warning (clippy::collapsible_if)` — 48 sites, incl. winhttp.rs:642, 730, 777, 1046, 1224, 2194, 2206, 2485, 3435-3472, 3526-3735, 4088-4457; wininet.rs:315, 436, 686, 891, 1434, 1706, 1921, 2035-2099.
- `warning (clippy::clone_double_ref)` — winhttp.rs:2779, 2783, 3010; wininet.rs:2302, 2305 (`&[...]` → `std::slice::from_ref`).
- `warning (clippy::let_else)` — winhttp.rs:788, 791; wininet.rs:446, 449.
- `warning (clippy::collapsible_match)` — winhttp.rs:1423, 1451; wininet.rs:1116.
- `warning (clippy::char_lit_as_u8)` — winhttp.rs:1773; wininet.rs:1220, 1332.
- `warning (clippy::op_ref)` — winhttp.rs:4139, 4143 (taken reference of right operand).
- `warning (clippy::type_complexity)` — winhttp.rs:1735; wininet.rs:1174.
- `warning (clippy::too_many_arguments)` — wininet.rs:514, 675.
- `warning (clippy::manual_strip)` — winhttp.rs:3572, 3618.
- `warning (clippy::get_first)` — winhttp.rs:804; wininet.rs:461.
- `warning (clippy::match_single_binding)` — winhttp.rs:1442; wininet.rs:1100.
- `warning (clippy::match_like_matches_macro)` — winhttp.rs:1448.
- `warning (clippy::needless_return)` — wininet.rs:2221.
- `warning (clippy::redundant_closure_for_method_calls)` — wininet.rs:2091.
- `warning (clippy::needless_borrow)` — wininet.rs:1921.
- `warning (clippy::needless_question_mark)` — winhttp.rs:4240.
- `warning (clippy::bool_to_int_with_if)` — wininet.rs:2221 area.
- `warning (clippy::unnecessary_cast)` — winhttp.rs:3384 (`u64`→`u64`).
- `warning (clippy::manual_div_ceil)` — winhttp.rs:4171.
- `warning (clippy::manual_is_multiple_of)` — winhttp.rs:3163.
- `warning (clippy::redundant_else)` — winhttp.rs:4457.
- `warning (clippy::useless_format)` — winhttp.rs:4149.
- `warning (clippy::needless_lifetimes)` — wininet.rs:1174 area.
- `warning (clippy::iter_overeager_cloned)` — wininet.rs:891.
- `warning (clippy::needless_borrows_for_generic_args)` — wininet.rs:1434.
- `warning (clippy::redundant_locals)` — wininet.rs:1218 (`let hostpart = hostpart;`).
- `warning (clippy::manual_let_else)` — wininet.rs:891 area.
- `warning (clippy::needless_continue)` — winhttp.rs:3624 area.
- `warning (clippy::needless_range_loop)` — winhttp.rs:3615.
- `warning (clippy::needless_bool)` — winhttp.rs:3624.
- `warning (clippy::redundant_field_names)` — winhttp.rs:1687.
- `warning (clippy::map_iteration_duplicate)` — winhttp.rs:1687 area.
- `warning (clippy::new_without_default)` — winhttp.rs:513 (`WinHttpStack` has no `Default`).

## Build

`cargo clippy --all-targets --no-deps` **FAILED**: `error: could not compile 'casa1' (lib test) due to 27 previous errors; 1415 warnings emitted`.

- 26 of the 27 errors are in files outside this audit's scope (cpu.rs, real_win32.rs, d3d11.rs, pe_runtime.rs, security.rs, dwrite.rs, crash_recovery.rs, seh.rs, d2d.rs, metal_backend.rs, jit.rs, video_decoder.rs).
- 1 error is in scope: `clippy::eq_op` at `src/winhttp.rs:3624` — `if l == "}" || l == "}"` (duplicate operand) in `find_return_in_block`. This blocks compilation of the test target and must be fixed.
- Note: the errors are deny-level lint violations; the library itself appears to compile apart from these lint gates. `--all-features` was not used per audit instructions (missing system ffmpeg is environmental).
