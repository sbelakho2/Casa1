# Local Validation

This document describes how to validate Casa1 locally before committing or
pushing changes. These checks mirror what CI runs on every pull request.

## Quick Smoke Test (Pre-Commit)

Run these commands before every commit to catch issues early:

```bash
# 1. Check formatting
cargo fmt --all -- --check

# 2. Check compilation (all targets including tests and benches)
cargo check --all-targets

# 3. Run library unit tests (fast, no I/O)
cargo test --lib --quiet
```

**Expected outcome**: All three commands exit with code 0. If `cargo fmt`
reports differences, run `cargo fmt --all` to fix them automatically.

## Full Validation

Run these commands before pushing or opening a pull request:

### Step 1: Format

```bash
cargo fmt --all
```

This automatically reformats all Rust source files. Commit any changes.

### Step 2: Lint

```bash
cargo clippy --all-targets -- -D warnings
```

Clippy enforces style and correctness lints. The `-D warnings` flag treats all
warnings as errors, ensuring the codebase stays clean.

**Common issues**:
- `unused_imports` — remove the import
- `dead_code` — add `#[allow(dead_code)]` or remove the code
- `non_snake_case` — already allowed via `#![allow(non_snake_case)]` in
  [`src/lib.rs`](../src/lib.rs) for Windows API compatibility

### Step 3: Test

```bash
cargo test --all-targets --quiet
```

This runs all unit tests, integration tests, and doc tests. The `--quiet` flag
reduces output noise while still reporting failures.

**Test categories**:
- **Library tests** (`--lib`): Fast unit tests for individual modules
- **Integration tests** (`--test`): Cross-module tests in [`tests/`](../tests/)
- **Binary tests** (`--bins`): Tests for the CLI binaries
- **Doc tests** (`--doc`): Examples in doc comments

### Step 4: Fuzz Build Check

```bash
cargo +nightly fuzz build
```

Verifies that all fuzz targets in [`fuzz/fuzz_targets/`](../fuzz/fuzz_targets/)
compile successfully. This catches issues with nightly-only APIs or feature
gating.

**Prerequisites**:
```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

### Step 5: Benchmark Build Check (Optional)

```bash
cargo bench --no-run
```

Verifies that the benchmark suite in [`benches/perf_benchmarks.rs`](../benches/perf_benchmarks.rs)
compiles. Benchmarks use the `criterion` framework.

## Validation Matrix

| Check | Command | When to Run | Exit Code |
|-------|---------|-------------|-----------|
| Format check | `cargo fmt --all -- --check` | Every commit | 0 |
| Compilation | `cargo check --all-targets` | Every commit | 0 |
| Unit tests | `cargo test --lib --quiet` | Every commit | 0 |
| Clippy | `cargo clippy --all-targets -- -D warnings` | Every PR | 0 |
| Full tests | `cargo test --all-targets --quiet` | Every PR | 0 |
| Fuzz build | `cargo +nightly fuzz build` | Every PR | 0 |
| Bench build | `cargo bench --no-run` | Every PR | 0 |

## CI Equivalence

The local validation commands are designed to match the CI pipeline. If all
local checks pass, CI should also pass (barring environment-specific issues
like macOS version differences).

### Additional CI Checks

CI may run additional checks that are harder to run locally:

- **UBSAN** (Undefined Behaviour Sanitizer) — requires nightly Rust
- **Release entitlement audit** — [`ci/audit_release_entitlements.sh`](../ci/audit_release_entitlements.sh)
- **Security audit** — `cargo audit` for known vulnerabilities

To run the UBSAN check locally:

```bash
# See ci/run_nightly_ubsan_if_supported.sh for details
cargo +nightly test -Zsanitizer=undefined --target aarch64-apple-darwin
```

## Troubleshooting

### `cargo fmt` Reports Differences

```bash
# Fix automatically
cargo fmt --all
git add -A
git commit --amend
```

### Clippy Warnings

```bash
# Auto-fix some issues
cargo clippy --fix --allow-dirty

# For remaining issues, follow the suggested fixes
cargo clippy --all-targets -- -D warnings 2>&1 | less
```

### Test Failures

```bash
# Run a specific test with verbose output
cargo test --lib -- test_name --nocapture

# Run tests for a specific module
cargo test --lib -- cpu::tests

# Run with backtrace
RUST_BACKTRACE=1 cargo test --lib -- test_name
```

### Fuzz Build Fails

```bash
# Ensure nightly toolchain is up to date
rustup update nightly

# Check fuzz targets individually
cargo +nightly fuzz build pe_parser
cargo +nightly fuzz build dxil_parser
```
