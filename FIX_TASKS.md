# AUDIT_FINDINGS — Batch 1: installer / app bundle / print

- Date: 2026-08-15
- Files audited (all lines read):
  - `src/installer.rs` (3859 lines)
  - `src/app_bundle.rs` (1249 lines)
  - `src/print.rs` (868 lines)
- Tooling: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (full-crate build; see `## Clippy` / `## Build`)
- Scope notes: installer engines parse untrusted PE/CAB/NSIS/Inno payloads from guest-controlled installer EXEs; `print.rs` is driven by Win32 thunks in `pe_runtime.rs` that pass guest-controlled strings (e.g. `StartDocPrinterW` reads the document name from guest memory — confirmed at `src/pe_runtime.rs:34767`).

---

## [CRITICAL] Unchecked slice index in `apply_patch_cycle` panics on untrusted chunk offsets

- File: `src/installer.rs:746` (`assembled = vec![0; replacement.len()]`), `src/installer.rs:756-757`
- Description: `let end = offset + bytes.len(); assembled[*offset..end].copy_from_slice(bytes);` indexes `assembled` with `offset`/`end` taken from `PatchOperation.download_chunks` (serde-deserialized, guest-controlled). `offset` may exceed `replacement.len()`, or `offset + bytes.len()` may overflow/overshoot, so `assembled[*offset..end]` panics with index-out-of-bounds — a reachable panic in library code from untrusted input.
- Fix suggestion: validate each chunk before copying:
  ```rust
  let end = offset.checked_add(bytes.len()).filter(|&e| e <= assembled.len());
  let Some(end) = end else { /* rollback + return Err(RcIo) */ };
  ```

## [CRITICAL] OOB reads on truncated PE headers (3 sites share the bug)

- File: `src/installer.rs:840-860` (`extract_exe_overlay`), `src/installer.rs:923-949` (`read_pe_version_string`), `src/installer.rs:3002-3009` (`has_installshield_sections`)
- Description: All three check only `e_lfanew + 4 <= data.len()` (or `data.len() < 64`) before indexing `data[e_lfanew + 6]`, `data[e_lfanew + 20]`, `data[e_lfanew + 21]`, `data[e_lfanew + 24]`, `data[e_lfanew + 25]`. A file sized between `e_lfanew+4` and `e_lfanew+26` bytes triggers index-out-of-bounds panic. Reachable from any untrusted PE (e.g. `detect_installer_type` → `InstallShieldEngine::detect` → `extract_exe_overlay`).
- Fix suggestion: after validating the `PE\0\0` signature, require `e_lfanew + 28 <= data.len()` (COFF header + magic field) before reading any optional-header/COFF fields; return `RcPeParseInvalid`/`Ok(None)` otherwise.

## [CRITICAL] CAB file-entry loop indexes past parsed folder table → panic

- File: `src/installer.rs:1152-1166` (folder parse loop `break`s early on truncation), `src/installer.rs:1219-1223`
- Description: `folder_count` is an untrusted u16; if the CAB is truncated so fewer folder entries fit, the loop `break`s and `folder_blocks_offset`/`folder_comp_type` are shorter than `folder_count`. A `CFFILE` entry with `folder_idx < folder_count` but `folder_idx >= pushed.len()` then does `folder_blocks_offset[folder_idx]` → panic. Untrusted CAB ⇒ reachable panic.
- Fix suggestion: track the actual parsed count and guard `if folder_idx >= folder_blocks_offset.len() { continue; }` (use the parsed length, not `folder_count`).

## [CRITICAL] NSIS entry chain can loop forever on cyclic `next_header`

- File: `src/installer.rs:2128-2229` (loop body), `src/installer.rs:2228` (`offset = next_header;`)
- Description: `next_header` is an untrusted u32 offset with no visited-set, no monotonicity requirement, and no iteration cap. A chain `A → B → A` (or any cycle) makes `extract_nsis_entries` spin forever — a hang/DoS on a malicious installer. (Forward jumps are bounds-checked by `offset + 12 > overlay.len()`, but cycles are not.)
- Fix suggestion: keep a `BTreeSet<usize>` (or a step cap, e.g. 1_000_000 entries) of visited offsets; break when revisiting a header offset, and bound total iterations.

## [CRITICAL] Shell-command injection in generated `casa1-wrapper` script

- File: `src/app_bundle.rs:199-224` (`generate_wrapper_script`)
- Description: `exe_path` and `ge_name` (both guest/user-controlled `AppBundleConfig` fields) are interpolated unescaped into `exec "$CASA1_BIN" ge:run --ge "{}" --exe "{}" {}`. A value containing `"`, `$()`, backticks, or newlines injects arbitrary bash into a script that Launch Services executes later. `app_name` is also interpolated into the comment line (line 201) — a newline in `app_name` breaks out of the comment and adds a command line. Note `args` *is* `shlex::try_quote`d (line 193) — the other three fields are not.
- Fix suggestion: build the command with `Command::new` + `arg()` and `std::os::unix::process::CommandExt`-free string, or `shlex::quote` every interpolated value (including the comment line, or strip newlines from `app_name`); ideally generate the wrapper via `Command` serialization instead of bash string assembly.

## [HIGH] `create_app_bundle` writes outside `apps_dir` via raw app name (path traversal)

- File: `src/app_bundle.rs:236-245`
- Description: `normalize_name` is used only for the emptiness check; the actual directory name is `format!("{}.app", &config.app_name)` with the *raw* name. An `app_name` of `"../Evil"` or `"a/b"` writes/creates directories outside `apps_dir` (nested paths). Untrusted `app_name` (e.g. from a game's name) ⇒ arbitrary filesystem writes.
- Fix suggestion: use `normalize_name(&config.app_name)` for the bundle directory name (and keep a separate display name for the plist), or reject names containing `/`, `\`, `..`, and `:`.

## [HIGH] Unbounded zlib/deflate decompression (zip-bomb DoS)

- File: `src/installer.rs:1051-1058` (`decompress_zlib_block`), callers `extract_nsis_entries` (2190), `extract_cab_files` (1258), `InnoSetupEngine::install` (2725)
- Description: `decoder.read_to_end(&mut decompressed)` has no output cap; compressed data inside untrusted installers can expand to gigabytes, exhausting memory. NSIS/Inno/CAB payloads are attacker-controlled files.
- Fix suggestion: read with a cap (e.g. `decoder.take(MAX + 1).read_to_end(...)` and error when the cap is exceeded), or stream decompressed output in bounded chunks into the engine rather than materializing one giant Vec.

## [HIGH] CAB `CFDATA` layout misparse for compressed folders (spec error + silent garbage)

- File: `src/installer.rs:1232-1245`
- Description: Real CAB `CFDATA` is `cbData(u16) @0, cbUncomp(u16) @2, checksum(u32) @4` when the checksum flag (CFHEADER flags bit 0x2, not the folder compression type) is set. The code instead derives header size from the folder's compression type (`comp_type == 0 → 6 bytes, else 8`) and, for compressed folders, reads `comp_size` at offset 2 (which is actually `cbUncomp`) and `uncomp_size` at 4-5 (half the checksum) — sizes are swapped/corrupted for checksummed compressed blocks. Additionally MSZIP (type 1) blocks carry a 4-byte `CKBB` prefix and are raw-deflate, so the zlib attempt fails, the raw-deflate fallback fails, and the code silently appends the *compressed* bytes as file data (line 1269) instead of erroring.
- Fix suggestion: parse `cbData`/`cbUncomp` at fixed offsets 0/2, determine checksum presence from the CAB `flags` field (bit 0x2, passed in), skip the u32 checksum when present, and error out (or emit a warning) when both zlib and deflate decode fail instead of extending raw bytes.

## [MEDIUM] CAB reserved-area size parsed but never applied

- File: `src/installer.rs:1137-1147`
- Description: `_reserved_size` is computed when `flags & 4 != 0`, but `folders_offset` is hardcoded to `36`; CABs with a reserved header area (flags bit 2) are parsed at the wrong offset and extraction silently yields nothing/wrong data. Unfinished logic.
- Fix suggestion: `folders_offset = 36 + reserved_size` (and fold the value into the parse instead of `let _reserved_size`).

## [MEDIUM] `classify_dotnet_version` parses `net48` as minor 48

- File: `src/installer.rs:145-150`
- Description: For two-digit no-dot monikers (`net48`, `net20`…), `rest.parse::<u32>()` yields `minor = 48` instead of `8`. It only "works" by accident: `mono_supports_netfx(4, 48)` matches none of the `n<=5/6/7/8` arms and falls through to `(4, _) => mono >= 6`, so the requirement is still met — but the error message (line 667) then claims `.NET 4.8 requires Mono 5.x`, which contradicts the actual check, and any future precise-minor logic is wrong.
- Fix suggestion: parse the last digit(s) after the leading `4` as the minor directly (e.g. `rest[1..].parse()` then split `x.y` digits into `major.minor`), e.g. `net48 → (4, 8)`.

## [MEDIUM] Registry keys not normalized consistently → detection misses

- File: `src/installer.rs:2984-2986` (`normalize_path`), `src/installer.rs:1030-1045` (`register_installed_app` normalizes), `src/installer.rs:463-466` (`msiexec_install` inserts raw keys), `src/installer.rs:1796-1798` / `2472-2475` (`handle_on_begin` / `detect_partial_install` substring checks)
- Description: `register_installed_app` writes keys lowercased with `/`, but `msiexec_install`/`run_gui_installer` insert component keys exactly as supplied (e.g. `HKLM\Software\…` backslashes/mixed case). Detectors that substring-match `"windows/currentversion/uninstall"` (lowercase, forward-slash) then miss MSI-written keys, so `detect_partial_install`/OnBegin existing-install detection silently fails for those installers.
- Fix suggestion: normalize registry keys through one function (mirror of `normalize_path`, e.g. `normalize_registry_key`) in all insertion paths, and use the same normalization in the substring detectors.

## [HIGH] Print job files written to CWD with unsanitized, guest-controlled filename (path traversal)

- File: `src/print.rs:156` (`let filename = format!("print_{}_{}.pdf", job_id, document_name.replace(' ', "_"));`)
- Description: `document_name` is read from guest memory (`StartDocPrinterW`, `pe_runtime.rs:34767`) and used directly in the path; it is only `' '`→`_` sanitized. `document_name = "../../etc/x"` (or containing `/`, `..`) escapes the CWD and overwrites arbitrary files relative to it (e.g. `print_1_../../Users/victim/important.pdf`). Also writes into whatever the host CWD happens to be.
- Fix suggestion: sanitize to `[A-Za-z0-9_-]` (drop/replace everything else) and write into a fixed, owned output dir (e.g. `$HOME/Documents/Casa1-prints` or the temp dir), never into CWD from a raw guest string.

## [HIGH] Generated PDF has wrong object numbers (`/Contents`, `/F1` refs) — malformed output

- File: `src/print.rs:343-409` (`build_pdf_objects`)
- Description: `content_obj_num` is initialized to `3 + actual_pages * 2` (i.e. *after* all page objects) and incremented per page, so each page object references `/Contents N 0 R` where `N = 3 + 2*pages + 2*p` — that is the font-object range, or out of range entirely (`N` exceeds `objects.len()` for the last page; for a single page the `/F1` ref is `6 0 R`, which does not exist among 5 objects). Page content streams and the Helvetica font are unreachable, so the PDF is malformed (blank/error pages in strict readers). The unit tests only assert string presence, so this passes CI.
- Fix suggestion: content stream object number should be `4 + 2*p` (font objects appended after the page/content pairs at `3 + 2*pages + p`), e.g.:
  ```rust
  let content_obj = 4 + page_num * 2;
  let font_obj = 3 + actual_pages * 2 + page_num;
  // push page obj referencing content_obj and font_obj, then push content
  ```

## [MEDIUM] PDF stream `/Length` is a guess, not the actual byte length

- File: `src/print.rs:369-399`
- Description: `/Length` is computed as `120 + safe_name.len() + [spool_hex.len() + 50]` / `80 + safe_name.len()`, which does not equal the real stream byte count (fixed text length is mis-estimated; page-number digits and UTF-8 multi-byte names shift it). Incorrect `/Length` violates PDF 32000-1 (viewers may truncate or fail to parse streams). Additionally, for multi-page documents the `spool_hex` data is never emitted at all (only the single-page branch uses it).
- Fix suggestion: build the content string first, then set `/Length {content.len()}`; include spool data on page 1 in the multi-page case too (or drop the hex dump feature).

## [MEDIUM] Completed print jobs (and their spool data) are never freed

- File: `src/print.rs:53` (`jobs: HashMap`), `src/print.rs:111-127` (insert), `src/print.rs:129-161` (`end_doc_printer` marks `Completed` but never removes)
- Description: Every `StartDocPrinter`/`EndDocPrinter` cycle leaves the `PrintJob` — including the full `spool_data` Vec (potentially large, grown by `write_printer` without any cap) — in `jobs` forever. A long-running emulated guest that prints repeatedly leaks memory unboundedly. `active_jobs` entries also linger if a doc is never ended.
- Fix suggestion: remove the job from `jobs` after the PDF is written (or keep a bounded ring of completed jobs), and prune `active_jobs` in `close_printer`; optionally cap per-job spool size.

## [MEDIUM] App-Nap activity tokens are ObjC objects cast to `u64` and never released

- File: `src/app_bundle.rs:514-523` (`beginActivityWithOptions:`), `src/app_bundle.rs:534-545`
- Description: `beginActivityWithOptions:reason:` returns an `id` (a +1 retained token object), which is captured as `u64` and never `release`d — one ObjC object leak per `prevent_app_nap`/`allow_app_nap` cycle. Passing the raw token back to `endActivity:` works by pointer size, but the token is still leaked.
- Fix suggestion: keep the token as `*mut Object` (or a boxed pointer) in a small registry and `msg_send![token, release]` (or `objc::rc::Retained`) when ending the activity; drop the `u64` handle.

## [MEDIUM] Temp PDFs from `show_print_dialog` are never deleted

- File: `src/print.rs:255-278`
- Description: Each call writes `/tmp/casa1_print_{nanos}.pdf` and never removes it — unbounded temp-file accumulation for a guest that prints via the dialog repeatedly.
- Fix suggestion: delete the temp file after `open` spawns (or in a `Drop` guard), or write into a per-process temp dir that is cleaned up.

## [LOW] `ISc(` end-of-CAB search is off by one

- File: `src/installer.rs:1330-1336`
- Description: `.skip(1).position(...)` yields `pos` such that the next marker starts at content offset `pos + 1`, but `end = pos + 4` — one byte short of the marker start, so 3 bytes of the trailing `ISc(` marker are included in the CAB slice (garbage trailing bytes; harmless for the lenient parser, wrong boundaries).
- Fix suggestion: `end = pos + 1` (start of next marker) or `end = pos + 5` (include the full marker); `pos + 1` is cleaner.

## [LOW] `run_gui_installer` clones entire state that is never used

- File: `src/installer.rs:414-416`
- Description: `_files_snapshot`/`_registry_snapshot` clone the full `files`/`registry` maps on every GUI install and are never read (the comment admits there is no failure path). Dead code plus an avoidable O(state) allocation on every install.
- Fix suggestion: remove the snapshots until a real rollback path exists (or gate them behind the actual error branch).

## [LOW] Dead/misleading variables

- File: `src/installer.rs:1938` (`failed` always empty), `src/installer.rs:2694` (`_header_size` unused), `src/print.rs:355` (`_page_obj_num` unused), `src/print.rs:358` (`_page_y` unused), `src/print.rs:44-48,226-238` (`PrinterDc.job_id` never assigned anywhere in the crate)
- Description: Bookkeeping variables that are computed but never used, suggesting unfinished logic (particularly `failed` and `job_id`).
- Fix suggestion: remove them or implement the intended behavior (e.g. report actual failures from `handle_on_register_files`, set `job_id` when a DC starts a job).

## [LOW] `open_printer(None)` returns `None` after the default printer is deleted; handles are never validated

- File: `src/print.rs:91-100`, `src/print.rs:106-127`
- Description: If the only (default) printer is deleted, `open_printer(None)` fails instead of restoring/creating a default. `start_doc_printer` accepts any numeric handle (no existence check) and overwrites `active_jobs` for an already-busy printer. `next_job_id` is a `u32` that wraps silently, colliding with live jobs after 4G jobs.
- Fix suggestion: re-create the default printer on `open_printer(None)` miss; validate the handle in `start_doc_printer`; use `u64` (or checked) job IDs.

## [LOW] `create_app_bundle` aborts after partially creating the bundle when `lsregister` fails

- File: `src/app_bundle.rs:342-345`, `src/register_with_launch_services` `src/app_bundle.rs:352-387`
- Description: Bundle files are fully written, then `register_with_launch_services` failure turns the whole `create_app_bundle` into an error, leaving a partially-registered bundle on disk and no cleanup. Registration is auxiliary to bundle creation.
- Fix suggestion: treat LS registration failure as a warning (log/telemetry) and return `Ok(app_path)`, or clean up the created bundle on error.

## [LOW] `normalize_name`/`is_app_registered` weaknesses

- File: `src/app_bundle.rs:70-82`, `src/app_bundle.rs:390-410`
- Description: `normalize_name` keeps non-ASCII alphanumerics (e.g. `é`), producing `CFBundleIdentifier` components that are not valid ASCII bundle-ID segments. `is_app_registered` uses `mdfind` (Spotlight), which can be disabled/stale — false negatives are likely; `stdout.contains(&app_bundle)` also matches a name inside another path.
- Fix suggestion: restrict to ASCII alphanumerics/`-`/`.` in `normalize_name`; for registration checks prefer `lsregister -dump` filtering or a direct `Info.plist` existence check.

## [LOW] `uninstall_app` TOCTOU / swallowed deregistration errors

- File: `src/app_bundle.rs:471-496`
- Description: `app_path.exists()` then `remove_dir_all` is a classic TOCTOU (path swapped to a directory/important path between check and remove — remove_dir_all then deletes the wrong target); the `lsregister -u` failure is only `eprintln!`-ed (deliberate, but no indication to caller).
- Fix suggestion: attempt `remove_dir_all` directly and map the error; re-check type (`is_dir`, not symlink) before removal, or remove only under the app dir root.

## [PERF] Installer detection re-reads the whole file up to 4× (plus per-engine re-reads)

- File: `src/installer.rs:2957-2978` (`detect_installer_type`), `src/installer.rs:1080-1108` / `2088-2117` / `2382-2425` (each `detect` calls `fs::read` then `read_pe_version_string` (reads again) and `extract_exe_overlay` (reads again))
- Description: Detection reads the entire installer file once for the MSI check and again per engine; `InstallShieldEngine::detect` alone triggers up to 3 full reads. For multi-hundred-MB installers this is several GB of redundant I/O per detection.
- Fix suggestion: read the file once (with size cap) and pass `&[u8]` through the detection pipeline; add a `detect_from_bytes` API and reuse it in `detect_installer_type`.

## [PERF] CAB folder data decompressed once per file

- File: `src/installer.rs:1169-1290` (`extract_cab_files` — folder decompression loop nested inside the per-file loop)
- Description: Each file entry re-decompresses the entire containing folder (`folder_decompressed` rebuilt from `block_start` per file). O(files × folder size) decompression work for a CAB with many small files.
- Fix suggestion: decompress each folder once (cache by `folder_idx`), then slice out each file's bytes.

---

## Clippy

Command: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps` (full-crate; output in `clippy_out.txt`). All lints below are `warning`-level; none of the three audited files produced any clippy `error`.

`src/app_bundle.rs`:
- `clippy::useless_format` ×6 — `app_bundle.rs:114, 129, 132, 135, 138, 139` — `plist.push_str(&format!(...literal...))`; use string literals / `.to_string()`.
- `clippy::unnecessary_map_or` — `app_bundle.rs:437` — `map_or(false, |ext| ext == "app")` → `is_some_and(...)`.

`src/installer.rs`:
- `clippy::unnecessary_map_or` — `installer.rs:52, 1091, 1100, 2099, 2107, 2393, 2401, 2414` — `.ok().flatten().map_or(false, …)` → `.is_some_and(...)`.
- `clippy::manual_strip` ×2 — `installer.rs:124, 133` — `&v["netcoreapp".len()..]` / `&v[3..]` → `strip_prefix`.
- `clippy::manual_pattern_char_comparison` — `installer.rs:118` — `c == 'v' || c == 'V'` → `['v', 'V']`.
- `clippy::collapsible_match` — `installer.rs:1552`; `clippy::collapsible_if` ×4 — `installer.rs:2436, 2442, 2629, 2959`.
- `clippy::for_kv_map` — `installer.rs:1941` — iterate `engine.files.keys()`.
- `clippy::if_same_then_else` — `installer.rs:1945-1949` — both `low.contains("msvc") || low.contains("vcruntime")` and `low.contains("msvcp")` branches return `"vc141"`; the `msvcp` branch is dead (relates to the dead-logic note in the LOW `failed`/version finding).
- `clippy::useless_format` ×4 — `installer.rs:2777, 2781, 2789, 2793` — `format!` around constant registry-key strings.

`src/print.rs`:
- `clippy::map_entry` — `print.rs:204` — `contains_key` + `insert` on `printers` → `Entry::Occupied`.

## Build

- `cargo clippy --all-targets --no-deps` **failed** at the lint level: `could not compile 'casa1' (lib) due to 19 previous errors; 1271 warnings` and `(lib test) due to 27 previous errors; 1415 warnings`.
- All 27 errors are **outside the audited scope** (pre-existing deny-level clippy lints): `src/cpu.rs`, `src/pe_runtime.rs`, `src/jit.rs`, `src/seh.rs`, `src/security.rs`, `src/d3d11.rs`, `src/dwrite.rs`, `src/d2d.rs`, `src/metal_backend.rs`, `src/real_win32.rs`, `src/winhttp.rs`, `src/video_decoder.rs`, `src/crash_recovery.rs`. None reference `installer.rs`, `app_bundle.rs`, or `print.rs`.
- No compilation errors (`rustc` diagnostics) exist for the three audited files; the only diagnostics for them are the warnings listed above.
