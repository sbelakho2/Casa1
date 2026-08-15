# AUDIT_FINDINGS.md

**Batch:** audit-support-ops-2
**Date:** 2026-08-15
**Auditor role:** Senior code auditor (audit-only; no files modified)

**Files audited (all read in full, every line):**
- `tests/support/mod.rs` (2570 lines)
- `tests/section_fuzz.rs` (263 lines)
- `.github/workflows/ci.yml` (103 lines)
- `.github/workflows/nightly.yml` (99 lines)
- `.github/workflows/release.yml` (175 lines)
- `ci/audit_release_entitlements.sh` (79 lines)
- `ci/check_audit.sh` (59 lines)
- `ci/check_licenses.sh` (143 lines)
- `ci/check_release_gate.sh` (125 lines)
- `ci/check_release_smoke.sh` (275 lines)
- `ci/check_reproducible.sh` (149 lines)
- `ci/smoke-test.sh` (207 lines)
- `run_analysis.sh` (33 lines)
- `fix_brittle_asserts.py` (83 lines)

---

## [CRITICAL] fix_brittle_asserts.py rewrites 40+ files in place with regexes that can generate invalid Rust; no backup, dry-run, or compile verification

- File: fix_brittle_asserts.py:37-81
- Description: The script walks all of `tests/` plus 36 hardcoded `src/*.rs` files and writes every changed file back in place (`open(filepath, 'w')`) with no backup, no `--dry-run`, no git safety, and no post-rewrite compile check. Bugs in the rewrite rules produce invalid Rust:
  1. Patterns 1/2 (`r'assert!\((\w+)\.is_ok\(\)\)'` and the `.is_err()` variant, lines 44-55) capture any `\w+` identifier and inject it into the format string `{<ident>:?}`. For keyword/type-name prefixes this is a compile error — verified with rustc: `format!("{self:?}")` fails with E0424 ("`self` value is a keyword only available in methods with a `self` parameter"); `Some(x).is_ok()` would produce `{Some:?}` (no such variable), likewise `None`. Any occurrence rewrites a working file into one that no longer compiles.
  2. Patterns 3/4 (lines 60-71) replace `assert!(expr.method(args)).is_ok())` with `let _result = expr.method(args);\n    assert!(...)`. The `let` statement is not an expression: inserted into a `match` arm, `if` condition, closure expression position, or any expression context, it is a syntax error. `[^)]*` also cannot span nested parentheses, so multi-arg calls containing `)` (e.g. tuples, nested calls) silently do not match — the very assertions the tool is meant to fix get skipped while adjacent ones get rewritten inconsistently.
  3. Pattern 3/4 operates on `src/*.rs` production code (not just tests) and modifies non-test code whenever a matching `assert!(...)` exists.
  4. The replacement introduces a variable named `_result` that can collide with existing bindings in the same scope, and the reported replacement count (`count`, `rel_count`, lines 74-78) is computed from diff-set arithmetic and is not a real count.
- Fix suggestion: Add `--dry-run` (print diffs, require explicit `--write`), verify with `cargo check` after rewriting, restrict patterns to statement contexts and to `tests/` files, exclude keywords (`self`, `Self`, `Some`, `None`, `Result`, …) from the `(\w+)` capture (use `\b(?!self|Self|Some|None)\w+`), and parse parens in pattern 3/4 (or require the argument list to have balanced parens) instead of `[^)]*`.

## [HIGH] check_licenses.sh fails every time on macOS CI: GNU-only `grep -P` (and `\s` in sed)

- File: ci/check_licenses.sh:27
- Description: `LICENSE="$(grep -P '^license\s*=' Cargo.toml | head -1 | sed 's/^license\s*=\s*"\(.*\)"/\1/' || true)"` uses `grep -P`, a GNU grep extension. The BSD grep shipped with macOS (and on GitHub `macos-latest` runners) errors `grep: illegal option -- P`; the `|| true` swallows it, `LICENSE` is empty, and the script reports "Cargo.toml is missing the 'license' field" and fails (verified: `grep -P` fails on this machine). The `sed` `\s` in the same pipeline is also GNU-only. Consequence: the `check-licenses` job of `release.yml` (which runs on `macos-latest`) can never pass, so the release gate is permanently red regardless of the actual license state (fails when it should pass).
- Fix suggestion: Use POSIX-compatible patterns, e.g. `grep '^license[[:space:]]*='` and `sed -E 's/^license[[:space:]]*=[[:space:]]*"([^"]*)"/\1/'`.

## [HIGH] check_licenses.sh python3 fallback license scan always passes (`$?` read after `|| true`)

- File: ci/check_licenses.sh:101-110
- Description: The metadata-based license scan runs `python3 -c "..." 2>&1 || true` and then checks `if [[ $? -eq 0 ]]`. Because `$?` is evaluated after the `|| true` compound, it is always 0 (the exit status of `true`), even when the python script detected incompatible licenses and exited 1. The branch can never fail: when the python script prints "!! Potentially incompatible licenses found: [...]" the script still prints "Dependency license scan via metadata — OK" and increments PASS. The exit code must be captured before `|| true`.
- Fix suggestion: `if python3 -c "..."; then ... else ... fi` directly, or capture `python3 ... ; status=$?` before applying `|| true` and test `$status`.

## [HIGH] check_licenses.sh `cargo license` failures are swallowed into a pass

- File: ci/check_licenses.sh:53-68
- Description: `LICENSE_OUTPUT="$(cargo license --do-not-bundle --transitive 2>/dev/null || true)"` turns any `cargo license` failure (missing/unparseable license in a dependency, network error, tool crash) into an empty string; the loop then finds zero "problematic" lines and reports "All dependency licenses appear compatible — OK" + PASS. A dependency whose license cannot be resolved therefore passes the gate silently.
- Fix suggestion: Drop `|| true` (let `set -e` handle failure), or capture the exit status and count a non-zero exit as a FAIL.

## [HIGH] smoke-test.sh coverage-threshold check can never fail (wrong llvm-cov JSON traversal)

- File: ci/smoke-test.sh:100-154
- Description: The coverage gate looks for per-file data at `data[].totals.classes.items[]` (`d.get('totals', {}).get('classes', {}).get('items', [])`). `cargo llvm-cov --json` output has no `classes` key in `totals` and per-file coverage lives in `data[].files[]` (with `summary.lines`). The python one-liner therefore always returns nothing, `COVERED` stays empty, no module is ever compared against its threshold, `COVERAGE_FAILED` stays false, and the step always reports "coverage thresholds — OK" (PASS). The advertised 70/60/50% thresholds for pe/security/runtime/installer modules are never enforced. Additionally, `cargo llvm-cov ... || true` (line 100) swallows generator failures, after which the missing JSON is treated as a PASS ("coverage JSON not generated — skipping threshold check", line 151-154).
- Fix suggestion: Iterate `data[].files[]`, read `file["summary"]["lines"]["percent"]` (or covered/count) and match on `filename.endswith(module)`. Treat a missing/empty JSON as a FAIL when llvm-cov was invoked.

## [HIGH] smoke-test.sh license check always fails on macOS (GNU-only `grep -P`)

- File: ci/smoke-test.sh:185
- Description: `LICENSE=$(grep -P '^license\s*=' Cargo.toml | ... || true)` — same BSD grep incompatibility as check_licenses.sh:27 (verified failing on this machine). On macOS the smoke test always reports "Cargo.toml is missing the 'license' field" and exits 1, so the pre-commit smoke test can never pass on macOS even though Cargo.toml has `license` (it is present at line 2).
- Fix suggestion: Use POSIX `grep '^license[[:space:]]*='`.

## [HIGH] audit_release_entitlements.sh silently reports "OK" for the dev-insecure-tls check on macOS (GNU-only `grep -Pzo`)

- File: ci/audit_release_entitlements.sh:74-80
- Description: The release safety check that `dev-insecure-tls` is not in default features uses `grep -Pzo '(?s)\[features\].*?default\s*=\s*\[([^\]]*)\]'`. On macOS BSD grep, `-P` errors and the pipeline yields nothing, so `grep -q 'dev-insecure-tls'` never matches and the script prints "OK: dev-insecure-tls is not in default features." — a silent bypass of a release-blocking security check on the platform the project actually targets. (Same GNU-only `grep -oP` issue at lines 9 and 26 for `.cargo/config.toml` target detection: on macOS the extraction silently fails; if a `target = "..."` is ever added there, the script looks in `target/release` while artifacts land in `target/<triple>/release`, producing spurious "missing release binary" failures.)
- Fix suggestion: Replace the `-Pzo` regex with portable POSIX tools, e.g. extract the `[features]`..`default` region with `awk`, then `grep -q 'dev-insecure-tls'`. For target detection use `grep -o 'target[[:space:]]*=[[:space:]]*"[^"]*"'`.

## [HIGH] check_release_gate.sh "CI And Release Readiness" section check never matches on macOS (`\s` in bash regex), release gate always fails

- File: ci/check_release_gate.sh:43,77
- Description: Both regexes use `\s`: `^##\s+(.+)` (section tracking) and `^##\s+CI\ And\ Release\ Readiness` (targeted section check). Bash on macOS (3.2.57 system bash and Homebrew bash alike) uses the macOS libc `regcomp`, which does not support `\s` in ERE; verified on this machine: `[[ "## CI And Release Readiness" =~ ^##\s+CI\ And\ Release\ Readiness ]]` → no match. The targeted section is therefore never entered: `SECTION_TOTAL` stays 0, the script fails with "No items found in 'CI And Release Readiness' section", and the `check-checklist-gate` job (and hence the whole release gate) can never pass on `macos-latest` even when every checklist item is `[x]` (currently all 253 items are checked, so the failure is purely the platform-regex bug). Note the global `- [ ]` scan (line 48) is POSIX-clean and works; the `- [x]` comparison (line 89) also rejects the renderer-standard `- [X]` (uppercase) form.
- Fix suggestion: Use `[[ "$line" =~ ^##[[:space:]]+... ]]` or plain glob/`case` matching, e.g. `case "$line" in "## CI And Release Readiness"*)`. Accept `[x]`/`[X]`.

## [MEDIUM] section_fuzz.rs fuzz regression suite passes vacuously when fixtures are missing

- File: tests/section_fuzz.rs:19-27,74-81
- Description: `fuzz_fixtures()` returns an empty vec when `tests/fixtures/fuzz/` is missing or contains no `.bin` files, and the test then prints a note and passes. The entire fuzz-regression guard (the only protection against panic regressions in seven parsers) silently turns green if the fixtures are accidentally deleted, emptied, or excluded (e.g. by a `.gitignore`/packaging change). A regression suite whose data vanishes should fail, not pass. (Fixtures currently exist — 10 `.bin` files — so the suite is live today; the hazard is future drift.)
- Fix suggestion: Assert `!fixtures.is_empty()` inside the test (or fail the run when the fixture directory is absent), with a clear message to regenerate fixtures.

## [MEDIUM] section_fuzz.rs `wininet_` fixtures are fuzzed against the winhttp parsers; `wininet::create_url_moniker` is never exercised by fixtures

- File: tests/section_fuzz.rs:46-68,113-164
- Description: `classify_fixture` maps `wininet_` → `"winhttp"`, and `run_parser("winhttp")` only invokes `WinHttpStack::internet_crack_url_w` and `ntlm_parse_challenge_msg`. The committed fixture `tests/fixtures/fuzz/wininet_empty_url.bin` (named for the wininet parser per the file's own naming contract `<parser>_<description>.bin`) therefore never reaches `casa1::wininet::create_url_moniker`; only the standalone `regression_wininet_empty_url` test covers it, and only with `b""`. Additionally, any fixture with an unrecognized prefix is classified `"unknown"` and `run_parser` performs a no-op — those fixtures validate nothing at all.
- Fix suggestion: Add a `"wininet"` case to `run_parser` calling `casa1::wininet::create_url_moniker`, or rename/redistribute the fixture; make `"unknown"` kinds push a failure instead of silently passing.

## [MEDIUM] tests/support/mod.rs PE32 sample declares incorrect directory sizes / 64-bit-oriented load-config offsets

- File: tests/support/mod.rs:243-244,308,379-380
- Description: The PE32 (`SamplePeFormat::Pe32`) fixture reserves a TLS directory of 24 bytes (`tls_directory_size = 24`, line 111) but registers directory entry 9 with size 40 (line 379), and reserves a load-config of 0x5c bytes (line 110) but registers directory entry 10 with size 0x94 (line 380) — both sizes are the PE32+ values. The load-config body is also written with PE32+ offsets (SecurityCookie at +0x60, GuardCF fields at +0x68..+0x90, lines 245-272) rather than the documented PE32 layout (SecurityCookie at +0x40, SEHandlerTable at +0x44, ...; lines 273-301 mirror that invented layout instead). These shared-fixture wrong values don't fail today only because the parsers under test happen not to validate size-vs-struct or these offsets strictly; any stricter or differently-implemented parser (or a test asserting on directory sizes) will either silently read beyond the reserved region or fail spuriously — a latent harness fault affecting every test built on `sample_pe32_bytes()`.
- Fix suggestion: Derive directory sizes from the actual reserved lengths (`tls_directory_size`, `load_config_size`) instead of hardcoding 40/0x94, and use the documented IMAGE_LOAD_CONFIG_DIRECTORY32 offsets for the PE32 branch.

## [MEDIUM] check_reproducible.sh can compare stale artifacts; `--skip-clean` (used by release.yml) never verifies a clean rebuild

- File: ci/check_reproducible.sh:37-38,54-55,86-92,137
- Description: `BUILD1_DIR` is never removed before the "first" build, and with `--skip-clean` (the mode the release workflow uses, release.yml:157) `BUILD2_DIR` is not removed either; both directories are only deleted at the very end of the script (line 137), so an interrupted or failed run (or a restored `target/` cache / pre-existing local dirs) leaves both populated. On the next run the two "builds" are incremental rebuilds (or no-ops if the sources are unchanged), so the hashes compare previously produced artifacts — the check can pass trivially against binaries built from different or older sources, and in the non-skip mode it compares a possibly-stale incremental build against a fresh one, which can also mismatch for non-determinism reasons unrelated to reproducibility. The check only genuinely validates reproducibility when both directories start empty (fresh CI checkout). It also requires two full release builds of six binaries (~20+ minutes each) in the release gate.
- Fix suggestion: Always `rm -rf "$BUILD1_DIR" "$BUILD2_DIR"` at the start (before build 1) and remove `--skip-clean` semantics from the release path, or build both into fresh `mktemp -d` dirs.

## [MEDIUM] check_release_smoke.sh validates a hand-crafted app bundle and never fails on signing; two binaries' checks are non-fatal

- File: ci/check_release_smoke.sh:125-138,152-243,251-263
- Description: (a) `casa1-oracle --help` and `casa1-test-guest --help` failures are deliberately non-fatal — the else branches still do `PASS=$((PASS + 1))` — so these two shipped binaries are only verified to exist, never to run. (b) The "app bundle structure" test builds a minimal `.app` by hand and then verifies the structure it just created; it does not exercise any of Casa1's own bundling code, so it cannot catch regressions in the real bundler. (c) The code-signing section only prints "⚠ not signed (expected...)" and unconditionally increments PASS (line 259) whether or not any binary is signed; the "release binaries are signed" claim (header comment) is never enforced here. (The only real signing enforcement lives in `ci/audit_release_entitlements.sh`, which is not wired into any workflow — see next finding.)
- Fix suggestion: Make the oracle/test-guest checks blocking, invoke the project's real bundling entry point (or `macwin`/`casa1` bundle subcommand) instead of fabricating a bundle, and fail (or at least report a count) when binaries are unsigned.

## [MEDIUM] ci/audit_release_entitlements.sh is not referenced by any workflow or script — the release signing/entitlement audit never runs in CI

- File: ci/audit_release_entitlements.sh:1-80 (and .github/workflows/release.yml:10-175)
- Description: Grep across `.github/workflows/` and `ci/` shows `audit_release_entitlements.sh` is invoked nowhere; the release gate (`release.yml`) never runs it, and `check_release_smoke.sh`'s signing check is non-failing (previous finding). The only script that actually verifies JIT entitlements, ad-hoc signing, and the binary list against Cargo.toml is therefore dead in CI: a release can pass the entire gate with unsigned or wrongly-entitled binaries. (Secondary: its `[[bin]]` count comparison at lines 32-38 currently matches — 6 `[[bin]]` entries — so no false alarm there today.)
- Fix suggestion: Add it as a `release.yml` job (with `needs` wiring into `release-gate`) or invoke it from `check_release_smoke.sh`.

## [MEDIUM] ci.yml warning-count job never fails and counts nothing actionable

- File: .github/workflows/ci.yml:97-103
- Description: The job runs `cargo check --all-targets`, counts lines starting exactly with `warning:`, prints the number, and at most emits a workflow notice (`::warning::`); it exits 0 in every case. It can neither block a merge nor alert a human reliably (the notice is easily missed), and `grep -c '^warning:'` misses multi-line and macro-expanded warnings while double-counting warnings repeated across targets. It is also not a dependency of any gate, so it validates nothing.
- Fix suggestion: Either remove the job or make it fail on non-zero counts (with an allow-list), and use `-D warnings` in the check/clippy jobs for real enforcement.

## [LOW] check_audit.sh unconditionally ignores RUSTSEC-2024-0370 even though the crate is not in the tree

- File: ci/check_audit.sh:37 (also ci/smoke-test.sh:173)
- Description: `cargo audit --ignore RUSTSEC-2024-0370` permanently exempts the advisory for `proc-macro-error` (INFO: unmaintained, no patched version). `grep` of `Cargo.lock` finds zero occurrences of `proc-macro-error`, so the ignore is currently dead weight — but it establishes a blanket-ignore pattern in both the release gate and the smoke test that could mask a future real vulnerability if carried forward.
- Fix suggestion: Remove the `--ignore` (the advisory is INFO-level and the crate is absent), or document why it is needed and scope it with a comment + audit.toml.

## [LOW] smoke-test.sh contains a dead `elif` duplicating its own `if` condition

- File: ci/smoke-test.sh:172-181
- Description: `if command -v cargo-audit &>/dev/null; then ... elif command -v cargo-audit &>/dev/null; then ... else ... fi` — the `elif` tests the identical condition as the `if`, making the second branch unreachable. The intended structure was presumably `if ...; then ... elif ! command -v cargo-audit; then ...`. Behavior is accidentally correct (the reachable `else` prints the same skip message and passes), but the duplicated condition is a maintenance trap.
- Fix suggestion: Collapse the two branches into `if`/`else`.

## [LOW] check_audit.sh reports "Total direct dependencies" from a non-dependency count

- File: ci/check_audit.sh:25-29
- Description: `cargo metadata --format-version 1 --no-deps` with `--no-deps` returns only workspace packages (here a single crate), so the printed "Total direct dependencies" is always `1` and the trend-tracking purpose is defeated. The comment and metric are misleading.
- Fix suggestion: Drop `--no-deps` for the count, or label the metric accurately.

## [LOW] tests/support/mod.rs: `SAMPLE_HASH` constant is unused

- File: tests/support/mod.rs:17
- Description: `pub const SAMPLE_HASH: &str = "0123...";` is never referenced anywhere in the module or (per grep) the test suite; it is a dead constant that suggests tests intended to assert on a hash of the sample PE but never do — worth either wiring in or removing so a future reader does not assume hash assertions exist.
- Fix suggestion: Use it in a sanity test asserting the sample PE's sha256, or delete it.

---

## Clippy

Command run: `CARGO_BUILD_JOBS=4 cargo clippy --all-targets --no-deps 2>&1 | tee clippy_out.txt` (output: `clippy_out.txt`, 21850 lines, ~15 min).

- The whole-crate clippy run **aborts on deny-by-default clippy "correctness" lints in `src/`** (out of scope for this batch): `error: could not compile `casa1` (lib) due to 19 previous errors; 1271 warnings emitted` and `error: could not compile `casa1` (lib test) due to 27 previous errors; 1415 warnings emitted`. Examples: `absurd_extreme_comparisons` (src/crash_recovery.rs:536), `not_unsafe_ptr_arg_deref` (8 occurrences), `uninit_vec` (src/…:11560), `eq_op` (src/…:14191), `approx_constant` (src/…:17026+), `diverging_sub_expression`/`always_zero` (src/…:17413+), `logic_bug` (src/…:18217), `or_fun_call`-style `eq_op` (src/…:19323). Because compilation aborts at the lib, the test targets (including `tests/section_fuzz` and the integration tests built on `tests/support/mod.rs`) are **never checked by clippy**.
- **For the assigned files: zero clippy warnings/errors reference `tests/support/mod.rs` or `tests/section_fuzz.rs`** (0 matches for either path in `clippy_out.txt`) — but note this is only because the test targets were not reached, not because they were verified clean. Re-run clippy on the test targets once the src lint errors are fixed.
- Implication for CI (informational): the `ci.yml` clippy job (`-D warnings -A future-incompatible`) and `release.yml` `check-clippy` job will likewise fail on these deny-by-default src lints; `--all-features` (ci.yml:46, nightly.yml:31) additionally requires system ffmpeg on the runner (environmental, per audit instructions).

## Test results

- `CARGO_BUILD_JOBS=4 cargo test --test section_fuzz 2>&1 | tee test_out_section_fuzz.txt` (output: `test_out_section_fuzz.txt`):
  - Compile: `Finished \`test\` profile [unoptimized + debuginfo] target(s) in 1m 47s` — no hang.
  - Result: `test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s` — all 11 tests pass (1 fixture no-panic test over 10 `.bin` fixtures + 10 explicit regression tests).
  - 10 compiler warnings during the build; **none reference `tests/support/mod.rs` or `tests/section_fuzz.rs`**.
- `bash -n` (syntax check) on all 8 assigned `.sh` files: **all pass** (`ci/audit_release_entitlements.sh`, `ci/check_audit.sh`, `ci/check_licenses.sh`, `ci/check_release_gate.sh`, `ci/check_release_smoke.sh`, `ci/check_reproducible.sh`, `ci/smoke-test.sh`, `run_analysis.sh`).
- `python3 -m py_compile fix_brittle_asserts.py`: **passes** (syntax OK; logic bugs are behavioral, see CRITICAL finding).
- Platform behavior verified empirically on this macOS host: `grep -P` fails (BSD grep), `\s` in bash `=~` never matches, `format!("{self:?}")` is a rustc compile error (E0424) — the three environmental facts underpinning the HIGH findings.

## Summary

- CRITICAL: 1
- HIGH: 7
- MEDIUM: 7
- LOW: 4
- **Total findings: 19**

Report written to `AUDIT_FINDINGS.md` in the worktree root. No source files were modified; the only artifacts created are this report plus the run logs `clippy_out.txt` and `test_out_section_fuzz.txt` required by the audit procedure.
