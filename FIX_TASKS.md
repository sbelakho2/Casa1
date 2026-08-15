# AUDIT_FINDINGS.md

- Batch: audit-fs-sandbox (batch 1)
- Files: `src/real_fs.rs` (2058 lines), `src/sandbox.rs` (1263 lines), `src/wsl.rs` (1141 lines), `src/crash_recovery.rs` (1211 lines) — every line read in full.
- Date: 2026-08-15
- Build: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (whole crate; failed, see `## Build`)

Severity legend: CRITICAL = crash/UB/security/data corruption; HIGH = definite wrong behavior; MEDIUM = edge-case bug; LOW = quality/dead code; PERF = performance.

---

## [CRITICAL] validate_path_access allowlist matched by raw prefix — sandbox escape

- File: src/sandbox.rs:577-582
- Description: `normalized.starts_with(&p.replace('\\', "/"))` performs a plain string-prefix test with no path-component boundary and no canonicalization. Two concrete bypasses:
  1. Allowed root `C:\Windows\System32` also admits `C:\Windows\System32Malware\x.exe` (sibling directory sharing the prefix).
  2. Allowed root `C:\Windows\System32` also admits `C:\Windows\System32\..\..\..\Users\Public\steam.exe` (traversal *through* an allowed prefix to anywhere else).
  Either defeats the AppContainer-style path restriction entirely.
- Fix suggestion: after normalizing separators, compare canonical forms (`canonicalize()` on both sides when the path exists, else lexically normalize `..`/`.` first) and require the requested path to equal the allowed path or be a descendant at a component boundary (`path == allowed || path.strip_prefix(allowed).is_some_and(|r| r.starts_with('/'))`).

## [CRITICAL] Empty allow list is fail-open ("no restrictions")

- File: src/sandbox.rs:573-576
- Description: `validate_path_access` returns `Ok(())` whenever the profile's read or write list is empty. For an AppContainer-style isolation feature the default must be deny; with this design a profile that has never been given explicit grants is fully unrestricted — any caller treating this as an enforcement point gets a permission bypass.
- Fix suggestion: fail closed (deny when the list is empty) and make "unrestricted" an explicit, separately-named profile flag; document which call sites rely on the current fail-open behavior.

## [CRITICAL] macOS fallback executes guest-supplied command on the host via /bin/bash -c

- File: src/wsl.rs:553-556 (also 538-604, 271-274)
- Description: `launch_wsl_command_macos` runs the guest-supplied command with `/bin/bash -c <command>` directly on the host with the Casa1 user's full privileges whenever Docker is absent. The command originates from emulated (untrusted) guest code via the wslapi.dll surface (`WslLaunch`/`WslLaunchInteractive`); `check_tool_available` even interpolates the caller's string into `"which {tool}"` (line 272), so a guest-supplied `tool` such as `x; rm -rf ~` is executed by the host shell. This is a host privilege boundary bypass: the "sandbox" gives guest code native host execution.
- Fix suggestion: do not fall back to native bash execution; return a clear "no Linux runtime available" error unless a container/VM path is actually enforced, and stop interpolating caller strings into shell commands (pass `tool` as an argv argument of `which`).

## [CRITICAL] map_wsl_to_windows_path panics on non-ASCII drive component

- File: src/wsl.rs:706-708
- Description: `let drive = rest[..1].to_ascii_uppercase();` and `let path_part = &rest[1..];` slice `rest` at byte index 1. `rest` is taken from untrusted input (`/mnt/` + arbitrary bytes). For any multibyte first character (e.g. `/mnt/é`, `/mnt/€`, `/mnt/ÿ`) byte index 1 is not a UTF-8 char boundary and `rest[..1]` panics ("byte index 1 is not a char boundary"), crashing the process. No length/ASCII check guards it (only `rest.len() >= 2`, which passes for `é`).
- Fix suggestion: validate `rest` is a single ASCII alphabetic drive letter first (`rest.len() == 1 || rest.as_bytes()[0].is_ascii_alphabetic()`, or use `rest.get(..1)` / `chars().next()`), and return `None` otherwise.

---

## [HIGH] list_alternate_streams TOCTOU slice panic

- File: src/real_fs.rs:926
- Description: `parse_xattr_list(&buf[..result as usize])` slices by the *second* `listxattr` return value. The buffer was sized by the *first* query (`buf_size`). If the xattr list grows between the two calls (another process/thread — including the guest — adding an xattr concurrently), `result > buf.len()` and the slice index panics. Panic is reachable from normal concurrent filesystem state, not just adversarial input.
- Fix suggestion: clamp the slice (`let n = (result as usize).min(buf.len());`), or loop calling `listxattr` with `ERANGE` handling until the buffer is large enough.

## [HIGH] WindowsPathResolver follows symlinks with no containment verification

- File: src/real_fs.rs:248-269 (resolve_component), 223-245 (resolve)
- Description: `exact.exists()` and the case-insensitive fallback (`entry.path()`, returned verbatim at line 262) both resolve through symlinks, and no layer re-verifies that the final path stays under `ge_root` (no `canonicalize` + prefix check, no `symlink_metadata` check). Any symlink inside `drive_c` (pre-existing, installed by a game, or created by the guest) pointing outside — e.g. to `$HOME`, `/etc`, or another app's data — makes `open_file`/`copy_file`/`move_file`/`delete_file`/ADS operations read/write/delete files outside the sandbox. `..` handling in `normalize_windows_path` is sound (verified: it cannot climb above the root), so symlinks are the remaining escape.
- Fix suggestion: after resolving, `canonicalize()` and require `starts_with(ge_root_canonical)`; use `symlink_metadata`/`openat`-style resolution to refuse crossing symlinks, and mirror the same check inside `open_file`/`delete_file`/`move_file`/`copy_file` before acting.

## [HIGH] backup_read_file unbounded allocation from untrusted file size

- File: src/real_fs.rs:1159
- Description: `let mut data = vec![0u8; size as usize];` allocates `metadata.len()` bytes. `size` is guest-controlled: a large or sparse file under `drive_c` (easily multi-GB/TB) forces a matching allocation → OOM abort of the emulator process (DoS). No cap, no streaming.
- Fix suggestion: stream in bounded chunks (e.g. 1 MiB) or cap the total allocation and return an error beyond a configured limit.

## [HIGH] AppContainer capability → SID mapping does not match Windows well-known capability SIDs

- File: src/sandbox.rs:64-80
- Description: The SIDs assigned are wrong versus the documented well-known capability SIDs (S-1-15-3-*): `internetClient` is S-1-15-3-1, `internetClientServer` S-1-15-3-2, `privateNetworkClientServer` S-1-15-3-3, `documentsLibrary` S-1-15-3-4, `picturesLibrary` S-1-15-3-5, `videosLibrary` S-1-15-3-6, `musicLibrary` S-1-15-3-7, `enterpriseAuthentication` S-1-15-3-8, `sharedUserCertificates` S-1-15-3-9, `removableStorage` S-1-15-3-10. The code instead maps DocumentsLibrary→1, PicturesLibrary→2, VideosLibrary→3, MusicLibrary→4, EnterpriseAuthentication→5, SharedUserCertificates→6, RemovableStorage→7, InternetClient→8, InternetClientServer→9, PrivateNetworkClientServer→10; `CodeGeneration`/`RunFullTrust`/`AllowExecution` have no well-known capability SID at all. Any consumer of `to_sid()` produces tokens/ACLs that grant the wrong capabilities.
- Fix suggestion: correct the discriminant table to the documented values (or drop the fabricated entries), and add tests asserting the exact S-1-15-3-N strings against the spec table.

## [HIGH] WSL command launchers deadlock on output > pipe buffer

- File: src/wsl.rs:468-469 + 507-530 (windows), 557-558 + 580-603 (macos bash), 621-622 + 644-667 (docker)
- Description: All three launchers pipe stdout/stderr but never read them while the child runs — they busy-poll `try_wait()` + `sleep(50ms)`. Once the child writes more than the ~64 KiB pipe capacity it blocks forever; the parent then only hits the timeout (30/60 s), kills the child, and reports `timed_out` with empty output. Any command with large output (builds, `find`, dumps) deterministically fails.
- Fix suggestion: drain the pipes concurrently (two reader threads feeding `wait_with_output()`-style collection, or spawn with `Stdio::inherit`/temp files), and poll `try_wait` only as a completion check while the readers run.

## [HIGH] Build-breaking clippy error: always-true comparison in Gregorian era math

- File: src/crash_recovery.rs:535-536
- Description: `let era = if z >= 0 { z } else { z - 146096 } / 146097;` — `z: u64` (days + 719468 ≥ 719468 always), so `z >= 0` is always true and the `else` branch is dead. The deny-by-default lint `absurd_extreme_comparisons` fires, and the enclosing `#[allow(unused_comparisons)]` does not suppress it → the whole crate fails to compile (clippy build error, one of the 19). Functional impact of the math itself is nil for real timestamps (no underflow possible since `z ≥ 719468`), but the branch is misleading and the crate cannot build.
- Fix suggestion: delete the `if` and keep `let era = z / 146097;` (remove the stale `#[allow(unused_comparisons)]`).

---

## [MEDIUM] share_mode and delete_on_close are dead fields — Windows semantics unimplemented

- File: src/real_fs.rs:345, 351, 494, 497
- Description: `GuestFile.share_mode` is always set to 0 and never consulted (no share-mode conflict enforcement despite the module header claiming "share modes, byte-range locks"), and `delete_on_close` is always `false` with no `Drop` impl, so `FILE_FLAG_DELETE_ON_CLOSE` is never honored. Guest programs relying on either behave incorrectly (e.g. locks not rejected, temp files never deleted).
- Fix suggestion: implement share-mode checking in `open_file` (track open handles per real path) and delete the file in a `Drop` impl when `delete_on_close` is set; or remove the dead fields and the header claim.

## [MEDIUM] ADS sidecar path traversal via stream name (non-macOS builds)

- File: src/real_fs.rs:1051-1059 (`ads_sidecar_path`), 1070-1078 (`ads_sidecar_path_for`), used by `backup_write_file` at 1214 and `write_alternate_stream` at 795-811
- Description: `format!("{}__{}", file_name, stream_name)` concatenates the stream name into a filesystem path without validation. A stream name containing `..` or `/` (from a guest-supplied path like `file.exe:..\..\..\host.txt`) escapes the `.casa1_ads/` directory and writes/reads/deletes arbitrary files. macOS builds are shielded only because xattr names reject `/`, but the module is compiled for other targets too.
- Fix suggestion: validate/sanitize `stream_name` (reject `/`, `\`, `..`, NUL; e.g. percent-encode) before building the sidecar name.

## [MEDIUM] generate_wsb_xml performs no XML escaping

- File: src/sandbox.rs:497-516
- Description: `folder.host_path` and `folder.sandbox_path` (user/guest-configurable) are interpolated into the `.wsb` XML verbatim. Paths containing `&`, `<`, `>`, or `"` produce malformed XML or inject elements (e.g. a `HostFolder` containing `<Networking>Enable</Networking>` alters the sandbox configuration).
- Fix suggestion: escape XML entities (`&`, `<`, `>`, `"`, `'`) before interpolation (no XML crate needed for five replacements).

## [MEDIUM] validate_path_access is never wired into any file operation

- File: src/sandbox.rs:559-589
- Description: Nothing in the audited files invokes `validate_path_access` or `SandboxManager` at I/O time: `RealFilesystem::open_file`/`copy_file`/`move_file`/`delete_file`/ADS operations (src/real_fs.rs) perform zero authorization. The AppContainer machinery here is purely bookkeeping/advisory; a caller believing a profile restricts paths gets no enforcement. (`FilesystemSandbox` in src/security.rs exists and is tested from sandbox.rs, but nothing in real_fs.rs calls it.)
- Fix suggestion: call the path check (or `FilesystemSandbox::authorize`) inside `open_file` and the mutating real_fs entry points before any syscall, or explicitly document that this module is non-enforcing.

## [MEDIUM] docker timeout kills the client, orphaning the container

- File: src/wsl.rs:630-643
- Description: On timeout, `child.kill()` terminates the `docker` CLI process; the container itself keeps running (`docker run --rm` only removes the container after it exits, and the client death does not stop it). Every timed-out launch leaks a running container (repeatable, unbounded).
- Fix suggestion: use `docker run` with `--name` + `docker rm -f <name>` on timeout (or use the Docker API to kill by container ID), and `wait()` the client before returning.

## [MEDIUM] `wsl.exe --list --verbose` parsing produces bogus distributions

- File: src/wsl.rs:430-455
- Description: Parsing assumes fixed `NAME STATE VERSION` whitespace columns: the `*` default marker (e.g. `* Ubuntu-22.04 Running 2`) is taken as the name (distro named `"*"`), and distro names containing spaces (e.g. "Kali Linux") shift columns — the state/version fields then misparse (version `"Running"` fails `parse::<u32>` and silently defaults to WSL_VERSION_2). Windows-only path, but wrong data is registered as distributions.
- Fix suggestion: strip a leading `*`, split on the header's column positions, or use `wsl.exe --list` (no verbose) plus a separate version query; skip unparseable lines instead of defaulting.

## [MEDIUM] Sub-second WSL launch timeouts are truncated

- File: src/wsl.rs:822-826
- Description: `Some(timeout_ms / 1000)` floors: `timeout_ms` in 1..=999 maps to `Some(0)`, so the poll loop's `elapsed().as_secs() > 0` fires at the first whole second — a 500 ms timeout behaves as ~1 s, and any caller passing 1-999 ms gets a different timeout than requested. (`timeout_ms == 0` correctly means "no timeout".)
- Fix suggestion: compute seconds as `(timeout_ms + 999) / 1000` and compare with milliseconds (`elapsed().as_millis() > timeout_ms`) in the poll loop.

---

## [LOW] ENODATA from getxattr mapped to generic error, not "not found"

- File: src/real_fs.rs:665-675, 697-703, 831-847
- Description: `Error::last_os_error()` on macOS `ENODATA` (96) does not map to `ErrorKind::NotFound`, so a missing ADS stream returns `RcUnimplInsn` instead of `RcFsNotFound` — error-contract mismatch for callers that distinguish "stream absent".
- Fix suggestion: also check `err.raw_os_error() == Some(libc::ENODATA)` (and `ENOATTR`) before returning `RcFsNotFound`.

## [LOW] Dead duplicate branch in is_drive_letter_colon

- File: src/real_fs.rs:149-157
- Description: Two consecutive identical `if pos == 1 && prev.is_ascii_alphabetic() { return true; }` blocks; the second is unreachable. Also, a colon at pos 1 preceded by a letter is always treated as a drive spec even for relative paths like `a:b` (no drive semantics) — benign here, but the duplicate indicates leftover code.
- Fix suggestion: remove the duplicated branch; if drive-relative forms (`C:foo`) must be distinguished from ADS, decide explicitly.

## [LOW] Empty dead block in open_file

- File: src/real_fs.rs:479-481
- Description: `if !create && !can_write { // Open existing only }` contains only a comment — dead code.
- Fix suggestion: delete the block (and add a comment on the `OpenOptions` instead).

## [LOW] com.apple.quarantine payload missing UUID component

- File: src/real_fs.rs:989
- Description: `format!("Casa1;{:x};", timestamp)` writes an `app;timestamp;` quarantine xattr without the trailing UUID that macOS `quarantine` entries normally carry; some tooling (and Gatekeeper-adjacent logic) may not treat the file as quarantined.
- Fix suggestion: append a UUID hex (e.g. from a random 16 bytes) to match the `app;ts;uuid` format.

## [LOW] UNC/device paths misparsed

- File: src/real_fs.rs:313-320
- Description: `\\?\UNC\server\share` (after stripping `\\?\`) has no colon, so it falls to the default `("C", path)` branch and maps into `drive_c/UNC/server/share` instead of a share mapping; likewise `\\.\` prefixes bypass the intended "DEV" handling whenever the remainder contains no colon. Semantic divergence only (still contained under `ge_root`).
- Fix suggestion: handle `\\?\UNC\...` explicitly (map to a `drive_z`-style share directory or error) before the generic colon search.

## [LOW] Wrong ReasonCode for ordinary I/O errors

- File: src/real_fs.rs:364, 376, 382, 388, 486, 516, 580, 602, 698, 773, 919
- Description: `GuestFile`/`RealFilesystem` I/O failures are reported as `RcUnimplInsn` ("unimplemented instruction") — the wrong reason class for read/write/seek/metadata errors; masks real failures in telemetry.
- Fix suggestion: use an I/O-appropriate `ReasonCode` (e.g. `RcFsIoError`/existing fs codes) for these paths.

## [LOW] ads_sidecar_to_stream not inverse of sidecar encoding

- File: src/real_fs.rs:1083-1092
- Description: Decode uses `rfind("__")` while encode (1077) concatenates `name__stream`; a base name or stream name containing `__` round-trips to the wrong `(base, stream)` pair (encode is ambiguous).
- Fix suggestion: make encoding unambiguous (e.g. escape `__` in components) or decode with `find("__")` plus a documented rule.

## [LOW] environment_summary hardcodes app_container_available = true

- File: src/sandbox.rs:547
- Description: `app_container_available: true` unconditionally (and `capabilities_enforceable` only checks the compile-time OS), even on hosts with no AppContainer support — the summary is not trustworthy for UI/decision code.
- Fix suggestion: report actual support (feature flag or detection result) instead of a constant.

## [LOW] SandboxManager.enabled flag is never consulted by any check

- File: src/sandbox.rs:305-312
- Description: `set_enabled(false)` changes a stored bool, but neither `validate_path_access` nor `environment_summary` honors it — toggling "sandbox off" has no behavioral effect, which may surprise callers relying on it as a kill switch.
- Fix suggestion: have `validate_path_access` return unrestricted (or fail closed, per design) when disabled, and document the semantics.

## [LOW] AppContainer SID derived from 48 bits of SipHash (DefaultHasher)

- File: src/sandbox.rs:607-617
- Description: `generate_app_container_sid` uses only 48 of the 64 hash bits across three 16-bit parts; `DefaultHasher::new()` is deterministic, so SIDs are guessable and two distinct profile names can collide (profile 2 then becomes invisible to `get_profile_by_sid`). Not attacker-controlled to harmful effect, but weak identity.
- Fix suggestion: use the full 64-bit hash in four parts, or a real random 128-bit SID tail, and treat collisions as errors.

## [LOW] WslApi::launch_interactive ignores _use_cwd and is not interactive

- File: src/wsl.rs:801-813
- Description: `_use_cwd` is unused and `launch_interactive` behaves identically to `launch` (piped, non-TTY, same timeout-less path) — the API surface does not do what its name/documentation implies for callers that rely on cwd or interactivity.
- Fix suggestion: implement cwd handling (`--cd` or `current_dir`) and a real interactive/TTY mode, or drop the parameter and rename the API.

## [LOW] Windows launcher does not reap child after timeout kill

- File: src/wsl.rs:479-506
- Description: On timeout the code runs `taskkill` and returns without `wait()`ing the child; the `Child` handle is dropped with the process potentially not yet reaped (zombie until the parent exits), and the timeout path never drains the pipes.
- Fix suggestion: `child.kill()`/`child.wait()` (or `wait_with_output`) after `taskkill` succeeds before returning.

## [LOW] WslApi::register_distribution leaves state stuck at Installing

- File: src/wsl.rs:768-777
- Description: New distributions are inserted with `state: Installing` and nothing ever transitions them to `Stopped`/`Running`; a caller observing the state machine sees "Installing" forever.
- Fix suggestion: expose a state-transition on registration completion (or start at `Stopped`).

## [LOW] Crash dump tmp file left behind on interrupted write

- File: src/crash_recovery.rs:338-340
- Description: `crash_<ts>_<pid>.json.tmp` is never cleaned up if the process dies between `fs::write` and `fs::rename` (tests even assert the tmp file persists). Leftover files accumulate; `load_all_dumps`/`cleanup_old_dumps` ignore them forever (`.tmp` extension), so disk grows unboundedly if crashes are frequent.
- Fix suggestion: prune stale `*.json.tmp` files during `cleanup_old_dumps` (age-based).

## [LOW] Dump filename collision for same second + same pid

- File: src/crash_recovery.rs:331
- Description: `crash_{timestamp}_{pid}.json` — two crashes of the same guest pid within the same second (or two processes with equal guest pids) overwrite each other's dump (silent data loss of the earlier dump); concurrent saves share the same `.tmp` name and can clobber each other.
- Fix suggestion: append a counter or unique suffix (e.g. nanos or a monotonic id) to the filename.

## [LOW] attempt_count can overflow u32

- File: src/crash_recovery.rs:229
- Description: `self.attempt_count += 1;` — after 2^32 crashes it wraps (debug: panic, release: wrap to 0, re-enabling restarts). Practically unreachable, but the counter is used in `should_restart` comparisons.
- Fix suggestion: use `saturating_add(1)`.

## [LOW] Doc example for record_crash does not match the signature

- File: src/crash_recovery.rs:14-21
- Description: The usage example calls `record_crash(12345, Some(-6), "SIGABRT", &telemetry_snapshot, &installer_state)` but the real signature is `(pid, exit_code, signal, signal_name, telemetry, installer)` — missing `exit_code`; copy-pasting the example does not compile.
- Fix suggestion: update the example to the actual signature.

---

## [PERF] Case-insensitive resolution re-reads the directory for every missing component

- File: src/real_fs.rs:256
- Description: `resolve_component` issues one `fs::read_dir` syscall per path component that misses an exact match. Deep paths with casing differences on cold caches cost O(depth) directory scans (and each scan allocates entry strings).
- Fix suggestion: keep the exact-match fast path (already present), but consider caching per-directory entry sets for the lifetime of a single resolve chain, or resolving once with a single traversal.

## [PERF] validate_path_access allocates per allow-entry per call

- File: src/sandbox.rs:578-580
- Description: `p.replace('\\', "/")` allocates a new String for every allowed entry on every check, and entries are rescanned from scratch each call (O(n) allocations on the hot path if this ever becomes enforcement).
- Fix suggestion: pre-normalize the allowlists once (store them already `\`→`/`-normalized, lowercased if case-insensitive matching is added) and compare against precomputed slices.

## [PERF] detect_wsl_platform spawns up to 4 subprocesses serially on every construction

- File: src/wsl.rs:326-373
- Description: Every `WslSupport::new()`/`with_distributions()`/`Default` run blocks on `docker` → `colima` → `multipass` → `limactl` `--version` probes in sequence (each a full process spawn, up to hundreds of ms). Called from constructors, including in test/startup paths, this is avoidable startup latency.
- Fix suggestion: probe once lazily (e.g. `OnceCell`/cached `WslPlatformInfo`) and/or run the probes concurrently; only probe until the first hit.

## [PERF] cleanup_old_dumps removes from the front of a Vec in a loop (O(n²))

- File: src/crash_recovery.rs:434-451
- Description: `dump_files.remove(0)` inside two while loops shifts the whole vector on every iteration. Bounded by dump counts in practice (small n), but trivially fixable.
- Fix suggestion: iterate with `Vec::drain(..n)` or a cursor index, collecting removed paths first.

---

## Clippy

Warnings/errors emitted for the audited files (`cargo clippy --all-targets --no-deps`, rustc 1.96.0):

- src/crash_recovery.rs:536 — **ERROR** `absurd_extreme_comparisons`: `z >= 0` always true for `u64` (deny-by-default; breaks the build; see HIGH finding above).
- src/crash_recovery.rs:369 — `unnecessary_map_or` (`path.extension().map_or(true, |e| e != "json")` → `is_none_or`).
- src/crash_recovery.rs:372 — `collapsible_if` (nested `if let Ok(json)` / `if let Ok(dump)`).
- src/crash_recovery.rs:408 — `unnecessary_map_or` (same pattern as 369).
- src/crash_recovery.rs:413 — `collapsible_if`.
- src/crash_recovery.rs:893 — `needless_borrows_for_generic_args` (`&dir.path()` in test).
- src/real_fs.rs:930 — `manual_map` (`if let Some(...) { Some(..) } else { None }`).
- src/real_fs.rs:1029 — `collapsible_if`.
- src/real_fs.rs:1037 — `collapsible_if`.
- src/real_fs.rs:1175 — `single_match` (backup_read_file stream enumeration).
- src/real_fs.rs:1920 — `needless_borrows_for_generic_args` (test).
- src/wsl.rs:254 — `useless_format` (constant string in `Err(format!(...))`).
- src/wsl.rs:328 — `collapsible_if` (docker probe).
- src/wsl.rs:338 — `collapsible_if` (colima probe).
- src/wsl.rs:339 — `collapsible_if` (colima inner).
- src/wsl.rs:350 — `collapsible_if` (multipass probe).
- src/wsl.rs:351 — `collapsible_if` (multipass inner).
- src/wsl.rs:362 — `collapsible_if` (limactl probe).
- src/wsl.rs:363 — `collapsible_if` (limactl inner).
- src/wsl.rs:547 — `collapsible_if` (docker_check gate).
- src/sandbox.rs — no warnings.

## Build

`CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` **fails**: `error: could not compile 'casa1' (lib) due to 19 previous errors; 1271 warnings emitted` (lib test: 27 errors). 18 of the errors are in out-of-scope files (jit.rs, metal_backend.rs, cpu.rs, d2d.rs, d3d11.rs, pe_runtime.rs, security.rs, video_decoder.rs, winhttp.rs, dwrite.rs, real_win32.rs, seh.rs). The one in-scope error is src/crash_recovery.rs:536 (`absurd_extreme_comparisons`, see HIGH finding). The `--all-features` variant was intentionally not run (missing system ffmpeg is environmental); no other build steps were attempted.

## Summary

- CRITICAL: 4
- HIGH: 6
- MEDIUM: 7
- LOW: 17
- PERF: 4
- Total findings: 38
