#!/usr/bin/env bash
# ci/check_reproducible.sh — Release artifact reproducibility check for Casa1
#
# Verifies that building from the same commit produces identical binaries
# (bit-for-bit reproducible builds).
#
# This check:
#   1. Builds all release binaries once.
#   2. Cleans only the build artifacts (keeps src/ intact).
#   3. Rebuilds all release binaries identically.
#   4. Compares SHA-256 hashes of both builds.
#
# If the builds are deterministic, the hashes will match.
# Non-determinism can arise from timestamps, file paths, or compiler version.
#
# Usage:
#   ./ci/check_reproducible.sh [--skip-clean]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SKIP_CLEAN=false
if [[ "${1:-}" == "--skip-clean" ]]; then
  SKIP_CLEAN=true
fi

PASS=0
FAIL=0

info() { echo ":: $*"; }
fail() { echo "!! $*" >&2; }

# Resolve target directory
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
BUILD1_DIR="$TARGET_DIR/reproducible-build-1"
BUILD2_DIR="$TARGET_DIR/reproducible-build-2"

BINARIES=(
  casa1
  macwin
  casa1-runner
  casa1-helper
  casa1-test-guest
  casa1-oracle
)

# ── First build ───────────────────────────────────────────────────────────────
info "=== Reproducible Build Check ==="
info ""
info "First build (into $BUILD1_DIR) ..."

CARGO_TARGET_DIR="$BUILD1_DIR" \
  cargo build --release --bins 2>&1

# Verify all binaries were produced
BIN_DIR="$BUILD1_DIR/release"
MISSING=0
for binary in "${BINARIES[@]}"; do
  if [[ ! -x "$BIN_DIR/$binary" ]]; then
    fail "First build missing binary: $binary"
    MISSING=$((MISSING + 1))
  fi
done

if [[ $MISSING -gt 0 ]]; then
  fail "First build produced only partial binaries ($MISSING missing)"
  exit 1
fi
info "First build complete — all ${#BINARIES[@]} binaries produced"
PASS=$((PASS + 1))

# ── Compute first hashes ─────────────────────────────────────────────────────
info "Computing SHA-256 hashes of first build ..."
declare -A HASHES1
for binary in "${BINARIES[@]}"; do
  HASHES1["$binary"]="$(shasum -a 256 "$BIN_DIR/$binary" | cut -d' ' -f1)"
  info "  $binary: ${HASHES1[$binary]}"
done

# ── Second build ──────────────────────────────────────────────────────────────
info ""
info "Second build (into $BUILD2_DIR) ..."

if [[ "$SKIP_CLEAN" == "false" ]]; then
  # Only remove the previous build artifacts, not the entire target
  rm -rf "$BUILD2_DIR"
fi

CARGO_TARGET_DIR="$BUILD2_DIR" \
  cargo build --release --bins 2>&1

BIN_DIR2="$BUILD2_DIR/release"
MISSING2=0
for binary in "${BINARIES[@]}"; do
  if [[ ! -x "$BIN_DIR2/$binary" ]]; then
    fail "Second build missing binary: $binary"
    MISSING2=$((MISSING2 + 1))
  fi
done

if [[ $MISSING2 -gt 0 ]]; then
  fail "Second build produced only partial binaries ($MISSING2 missing)"
  exit 1
fi
info "Second build complete — all ${#BINARIES[@]} binaries produced"
PASS=$((PASS + 1))

# ── Compare hashes ────────────────────────────────────────────────────────────
info ""
info "Comparing SHA-256 hashes ..."
ALL_MATCH=true
for binary in "${BINARIES[@]}"; do
  HASH2="$(shasum -a 256 "$BIN_DIR2/$binary" | cut -d' ' -f1)"
  if [[ "${HASHES1[$binary]}" == "$HASH2" ]]; then
    info "  ✅ $binary: MATCH"
  else
    fail "  ❌ $binary: MISMATCH"
    fail "     Build 1: ${HASHES1[$binary]}"
    fail "     Build 2: $HASH2"
    ALL_MATCH=false
  fi
done

if [[ "$ALL_MATCH" == "true" ]]; then
  info "All binaries are reproducible — OK"
  PASS=$((PASS + 1))
else
  fail "Some binaries are not reproducible"
  FAIL=$((FAIL + 1))
fi

# ── Clean up temporary build directories ─────────────────────────────────────
info ""
info "Cleaning up temporary build directories ..."
rm -rf "$BUILD1_DIR" "$BUILD2_DIR"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Reproducible Build Check Summary ==="
echo "   Passed: $PASS"
echo "   Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
info "All checks passed — builds are reproducible."
exit 0
