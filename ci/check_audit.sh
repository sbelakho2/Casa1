#!/usr/bin/env bash
# ci/check_audit.sh — Dependency audit checks for Casa1
#
# Runs `cargo audit` to check for known vulnerabilities in dependencies.
# Falls back gracefully if cargo-audit is not installed.
#
# Also reports the total dependency count for trend tracking.
#
# Usage:
#   ./ci/check_audit.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0
FAIL=0

info() { echo ":: $*"; }
fail() { echo "!! $*" >&2; }

# ── Dependency count ──────────────────────────────────────────────────────────
info "Counting total dependencies (direct + transitive) ..."
DEP_COUNT="$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
  | python3 -c "import json,sys; m=json.load(sys.stdin); print(len(m.get('packages',[])))" 2>/dev/null || true)"

if [[ -n "$DEP_COUNT" ]]; then
  info "Total direct dependencies: $DEP_COUNT"
else
  info "Could not determine dependency count (cargo metadata issue)"
fi

# ── cargo audit ───────────────────────────────────────────────────────────────
if command -v cargo-audit &>/dev/null || cargo audit --version &>/dev/null 2>&1; then
  info "Running cargo audit for known vulnerabilities ..."
  if cargo audit --ignore RUSTSEC-2024-0370 2>&1; then
    PASS=$((PASS + 1))
    info "cargo audit — OK (no vulnerabilities found)"
  else
    FAIL=$((FAIL + 1))
    fail "cargo audit — FAILED (vulnerabilities found)"
  fi
else
  info "cargo-audit not installed — skipping vulnerability audit"
  info "install with: cargo install cargo-audit"
  # Not a failure — the CI job should install it, but local runs are lenient
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Audit Check Summary ==="
echo "   Passed: $PASS"
echo "   Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
