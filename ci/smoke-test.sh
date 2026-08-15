#!/usr/bin/env bash
# ci/smoke-test.sh — Fast pre-commit smoke test for Casa1
#
# Runs library and binary compilation checks plus unit tests.
# Excludes integration tests, ignored tests, and long-running suites.
#
# Usage:
#   ./ci/smoke-test.sh          # run smoke tests
#   ./ci/smoke-test.sh --quiet  # suppress progress output

set -euo pipefail

QUIET=false
if [[ "${1:-}" == "--quiet" ]]; then
    QUIET=true
fi

info() {
    if [[ "$QUIET" == "false" ]]; then
        echo ":: $*"
    fi
}

PASS=0
FAIL=0

run_step() {
    local name="$1"
    shift
    info "$name ..."
    if "$@" 2>&1 | while IFS= read -r line; do
        if [[ "$QUIET" == "false" ]]; then
            printf "   %s\n" "$line"
        fi
    done; then
        PASS=$((PASS + 1))
        info "$name — OK"
    else
        FAIL=$((FAIL + 1))
        echo "!! $name — FAILED" >&2
    fi
}

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

info "=== Casa1 Smoke Test ==="

# Step 1: Compile-check all targets (libs, bins, tests, benches)
run_step "cargo check --all-targets" cargo check --all-targets

# Step 2: Run unit tests (lib only, fast)
run_step "cargo test --lib" cargo test --lib

# Step 3: Run binary smoke tests
run_step "cargo test --bins" cargo test --bins

# Step 4: Fuzz target build check (requires nightly + cargo-fuzz)
if command -v cargo-fuzz &>/dev/null; then
    if rustup toolchain list | grep -q nightly; then
        run_step "cargo +nightly fuzz build" \
            cargo +nightly fuzz build --manifest-path fuzz/Cargo.toml

        # Step 4b: Short smoke runs for each fuzz target (2 seconds each)
        info "Fuzz smoke runs (2s each) ..."
        FUZZ_TARGETS=$(cd fuzz && cargo +nightly fuzz list 2>/dev/null || echo "")
        if [[ -n "$FUZZ_TARGETS" ]]; then
            for target in $FUZZ_TARGETS; do
                run_step "cargo +nightly fuzz run $target -- -max_total_time=2 -runs=1000" \
                    cargo +nightly fuzz run "$target" -- -max_total_time=2 -runs=1000
            done
        else
            info "No fuzz targets listed — skipping individual runs"
            PASS=$((PASS + 1))
        fi
    else
        info "nightly toolchain not installed — skipping fuzz build step"
        info "(install with: rustup toolchain install nightly)"
        PASS=$((PASS + 1))
    fi
else
    info "cargo-fuzz not installed — skipping fuzz build step"
    info "(install with: cargo install cargo-fuzz && rustup toolchain install nightly)"
fi

# Step 5: Media container fuzz regression (non-fatal, requires nightly + cargo-fuzz)
if command -v cargo-fuzz &>/dev/null && rustup toolchain list | grep -q nightly; then
    run_step "cargo +nightly fuzz run media_container -- -max_total=500 -runs=1000" \
        cargo +nightly fuzz run media_container -- -max_total=500 -runs=1000
fi

# Step 6: Coverage check — only if cargo-llvm-cov or cargo-tarpaulin is available
# Minimum thresholds for critical modules (line coverage %):
#   parser (pe, pe_runtime): 70%
#   security (security, sandbox, anticheat): 60%
#   runtime (cpu, jit, seh, threads): 50%
#   installer (installer, scm): 50%
if command -v cargo-llvm-cov &>/dev/null; then
    info "cargo-llvm-cov available — generating coverage report ..."
    # Generate a JSON summary for threshold checking. A failing generator
    # (or empty output) is a FAIL, not a silent skip.
    if ! cargo llvm-cov --no-clean --lib --bins --json > target/coverage.json 2>/dev/null; then
        echo "!! cargo llvm-cov failed — coverage threshold check could not run" >&2
        FAIL=$((FAIL + 1))
    elif [[ ! -s target/coverage.json ]]; then
        echo "!! coverage JSON empty — coverage threshold check could not run" >&2
        FAIL=$((FAIL + 1))
    else
        # Check critical module coverage thresholds
        MODULES=(
            "src/pe.rs:70"
            "src/pe_runtime.rs:70"
            "src/security.rs:60"
            "src/sandbox.rs:60"
            "src/anticheat.rs:60"
            "src/cpu.rs:50"
            "src/jit.rs:50"
            "src/seh.rs:50"
            "src/threads.rs:50"
            "src/installer.rs:50"
        )
        COVERAGE_FAILED=false
        for entry in "${MODULES[@]}"; do
            MODULE_FILE="${entry%%:*}"
            THRESHOLD="${entry#*:}"
            # Extract coverage percentage from JSON using python3 or jq
            if command -v python3 &>/dev/null; then
                COVERED=$(python3 -c "
import json
with open('target/coverage.json') as f:
    data = json.load(f)
target = '$MODULE_FILE'
for d in data.get('data', []):
    for f in d.get('files', []):
        if f.get('filename', '').endswith(target):
            summary = f.get('summary', {}).get('lines', {})
            covered = summary.get('covered', 0)
            count = summary.get('count', 0)
            print(covered, count)
            break
" 2>/dev/null)
                if [[ -n "$COVERED" ]]; then
                    read -r cov_lines total_lines <<< "$COVERED"
                    if [[ "$total_lines" -gt 0 ]]; then
                        PCT=$(( cov_lines * 100 / total_lines ))
                        if [[ "$PCT" -lt "$THRESHOLD" ]]; then
                            echo "!! Coverage for $MODULE_FILE: ${PCT}% (threshold: ${THRESHOLD}%)" >&2
                            COVERAGE_FAILED=true
                        else
                            info "Coverage for $MODULE_FILE: ${PCT}% (threshold: ${THRESHOLD}%)"
                        fi
                    else
                        echo "!! No covered lines recorded for $MODULE_FILE — cannot verify threshold" >&2
                        COVERAGE_FAILED=true
                    fi
                else
                    echo "!! No coverage data found for $MODULE_FILE — cannot verify threshold" >&2
                    COVERAGE_FAILED=true
                fi
            else
                echo "!! python3 not available — cannot verify coverage thresholds" >&2
                COVERAGE_FAILED=true
            fi
        done
        if [[ "$COVERAGE_FAILED" == "true" ]]; then
            echo "!! Some modules below coverage threshold" >&2
            FAIL=$((FAIL + 1))
        else
            PASS=$((PASS + 1))
            info "coverage thresholds — OK"
        fi
    fi
elif command -v cargo-tarpaulin &>/dev/null; then
    info "cargo-tarpaulin available — running coverage on critical modules..."
    # Run tarpaulin on lib and bins only (fast), target critical modules
    run_step "cargo tarpaulin --lib --bins --ignore-tests --out Html --output-dir target/coverage" \
        cargo tarpaulin --lib --bins --ignore-tests --out Html --output-dir target/coverage
else
    info "coverage tools not installed — skipping coverage step"
    info "(install with: cargo install cargo-llvm-cov llvm-tools-preview || cargo install cargo-tarpaulin)"
    PASS=$((PASS + 1))
fi

# Step 7: Fuzz regression test suite
if ls tests/fixtures/fuzz/*.bin 2>/dev/null | head -1 | grep -q .; then
    run_step "cargo test --test section_fuzz" cargo test --test section_fuzz
fi

# Step 8: Dependency audit (if cargo-audit is available)
if command -v cargo-audit &>/dev/null; then
    run_step "cargo audit" cargo audit
else
    info "cargo-audit not installed — skipping dependency audit"
    info "(install with: cargo install cargo-audit)"
    PASS=$((PASS + 1))
fi

# Step 9: License check (quick project-level check)
info "Checking Cargo.toml for license field ..."
LICENSE=$(grep '^license[[:space:]]*=' Cargo.toml | head -1 | sed -E 's/^license[[:space:]]*=[[:space:]]*"([^"]*)"/\1/' || true)
if [[ -n "$LICENSE" ]]; then
    info "License field present: $LICENSE"
    PASS=$((PASS + 1))
else
    echo "!! Cargo.toml is missing the 'license' field" >&2
    FAIL=$((FAIL + 1))
fi

# Summary
echo ""
echo "=== Smoke Test Summary ==="
echo "   Passed: $PASS"
echo "   Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "!! Some steps failed. Fix before committing."
    exit 1
else
    info "All smoke tests passed."
    exit 0
fi
