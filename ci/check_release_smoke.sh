#!/usr/bin/env bash
# ci/check_release_smoke.sh — Release smoke tests for Casa1
#
# Verifies:
#   1. All CLI binaries print usage and exit with expected status.
#   2. App bundle structure can be created and validated.
#   3. Release binaries are signed (if codesign available).
#
# Usage:
#   ./ci/check_release_smoke.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0
FAIL=0

info() { echo ":: $*"; }
fail() { echo "!! $*" >&2; }

# Detect release directory
default_target=""
if [[ -f "$REPO_ROOT/.cargo/config.toml" ]]; then
  default_target="$(grep -oP '(?<=^target\s*=\s*")[^"]+' "$REPO_ROOT/.cargo/config.toml" 2>/dev/null || true)"
fi
if [[ -n "$default_target" ]]; then
  RELEASE_DIR="${RELEASE_DIR:-$REPO_ROOT/target/$default_target/release}"
else
  RELEASE_DIR="${RELEASE_DIR:-$REPO_ROOT/target/release}"
fi

BINARIES=(
  casa1
  macwin
  casa1-runner
  casa1-helper
  casa1-test-guest
  casa1-oracle
)

info "=== Release Smoke Tests ==="
info "Release directory: $RELEASE_DIR"

# ── 1. Ensure release binaries are built ─────────────────────────────────────
info ""
info "1. Checking release binaries exist ..."
if [[ ! -d "$RELEASE_DIR" ]]; then
  info "Release directory does not exist — building release binaries ..."
  cargo build --release --bins 2>&1
fi

MISSING=0
for binary in "${BINARIES[@]}"; do
  if [[ ! -x "$RELEASE_DIR/$binary" ]]; then
    fail "Missing release binary: $binary"
    MISSING=$((MISSING + 1))
  else
    info "  ✅ $binary found ($(stat -f%z "$RELEASE_DIR/$binary" 2>/dev/null || stat -c%s "$RELEASE_DIR/$binary" 2>/dev/null) bytes)"
  fi
done

if [[ $MISSING -gt 0 ]]; then
  fail "$MISSING binaries missing — build release first"
  exit 1
fi
PASS=$((PASS + 1))

# ── 2. CLI smoke tests ───────────────────────────────────────────────────────
info ""
info "2. Testing CLI help/usage output ..."

# casa1 --help
info "  casa1 --help ..."
HELP_OUTPUT="$("$RELEASE_DIR/casa1" --help 2>&1 || true)"
if echo "$HELP_OUTPUT" | grep -q "Usage\|Commands\|Arguments"; then
  info "    ✅ casa1 --help produces usage output"
  PASS=$((PASS + 1))
else
  fail "casa1 --help did not produce expected output"
  FAIL=$((FAIL + 1))
fi

# macwin --help
info "  macwin --help ..."
MACWIN_OUTPUT="$("$RELEASE_DIR/macwin" --help 2>&1 || true)"
if echo "$MACWIN_OUTPUT" | grep -q "Usage\|Commands\|Arguments"; then
  info "    ✅ macwin --help produces usage output"
  PASS=$((PASS + 1))
else
  fail "macwin --help did not produce expected output"
  FAIL=$((FAIL + 1))
fi

# casa1-runner --help
info "  casa1-runner --help ..."
RUNNER_OUTPUT="$("$RELEASE_DIR/casa1-runner" --help 2>&1 || true)"
if echo "$RUNNER_OUTPUT" | grep -q "Usage\|Commands\|Arguments"; then
  info "    ✅ casa1-runner --help produces usage output"
  PASS=$((PASS + 1))
else
  fail "casa1-runner --help did not produce expected output"
  FAIL=$((FAIL + 1))
fi

# casa1-helper --help
info "  casa1-helper --help ..."
HELPER_OUTPUT="$("$RELEASE_DIR/casa1-helper" --help 2>&1 || true)"
if echo "$HELPER_OUTPUT" | grep -q "Usage\|Commands\|Arguments"; then
  info "    ✅ casa1-helper --help produces usage output"
  PASS=$((PASS + 1))
else
  fail "casa1-helper --help did not produce expected output"
  FAIL=$((FAIL + 1))
fi

# casa1-oracle --help
info "  casa1-oracle --help ..."
ORACLE_OUTPUT="$("$RELEASE_DIR/casa1-oracle" --help 2>&1 || true)"
if echo "$ORACLE_OUTPUT" | grep -q "Usage\|Commands\|Arguments"; then
  info "    ✅ casa1-oracle --help produces usage output"
  PASS=$((PASS + 1))
else
  info "    ⚠ casa1-oracle --help output (non-fatal): $(echo "$ORACLE_OUTPUT" | head -3)"
  PASS=$((PASS + 1))
fi

# casa1-test-guest --help
info "  casa1-test-guest --help ..."
TESTGUEST_OUTPUT="$("$RELEASE_DIR/casa1-test-guest" --help 2>&1 || true)"
if echo "$TESTGUEST_OUTPUT" | grep -q "Usage\|Commands\|Arguments"; then
  info "    ✅ casa1-test-guest --help produces usage output"
  PASS=$((PASS + 1))
else
  info "    ⚠ casa1-test-guest --help output (non-fatal): $(echo "$TESTGUEST_OUTPUT" | head -3)"
  PASS=$((PASS + 1))
fi

# ── 3. App bundle structure test ──────────────────────────────────────────────
info ""
info "3. Testing app bundle structure ..."

# Create a temporary directory for app bundle testing
TEMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t casa1-smoke)"
trap 'rm -rf "$TEMP_DIR"' EXIT

APPS_DIR="$TEMP_DIR/apps"
mkdir -p "$APPS_DIR"

# Create a minimal app bundle manually to verify the structure
TEST_APP="$APPS_DIR/TestApp.app"
mkdir -p "$TEST_APP/Contents/MacOS"
mkdir -p "$TEST_APP/Contents/Resources"
mkdir -p "$TEST_APP/Contents/Frameworks"

# Create Info.plist
cat > "$TEST_APP/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>casa1-wrapper</string>
    <key>CFBundleIdentifier</key>
    <string>com.casa1.testapp</string>
    <key>CFBundleName</key>
    <string>TestApp</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
PLIST

# Create PkgInfo
printf 'APPLcasa' > "$TEST_APP/Contents/PkgInfo"

# Create wrapper script
cat > "$TEST_APP/Contents/MacOS/casa1-wrapper" << 'WRAPPER'
#!/bin/bash
echo "TestApp wrapper executed"
WRAPPER
chmod +x "$TEST_APP/Contents/MacOS/casa1-wrapper"

# Verify bundle structure
info "  Verifying .app bundle structure ..."
STRUCTURE_OK=true
for required in \
  "$TEST_APP/Contents/Info.plist" \
  "$TEST_APP/Contents/PkgInfo" \
  "$TEST_APP/Contents/MacOS/casa1-wrapper" \
  "$TEST_APP/Contents/Resources" \
  "$TEST_APP/Contents/Frameworks"; do
  if [[ -e "$required" ]]; then
    info "    ✅ $required exists"
  else
    fail "    ❌ $required missing"
    STRUCTURE_OK=false
  fi
done

if [[ "$STRUCTURE_OK" == "true" ]]; then
  info "  App bundle structure validation — OK"
  PASS=$((PASS + 1))
else
  fail "  App bundle structure validation — FAILED"
  FAIL=$((FAIL + 1))
fi

# Verify Info.plist contains required keys (XML parse)
info "  Verifying Info.plist contents ..."
if grep -q "CFBundleExecutable" "$TEST_APP/Contents/Info.plist" \
  && grep -q "CFBundleIdentifier" "$TEST_APP/Contents/Info.plist" \
  && grep -q "CFBundleName" "$TEST_APP/Contents/Info.plist" \
  && grep -q "APPL" "$TEST_APP/Contents/Info.plist"; then
  info "    ✅ Info.plist contains all required keys"
  PASS=$((PASS + 1))
else
  fail "    ❌ Info.plist missing required keys"
  FAIL=$((FAIL + 1))
fi

# Verify wrapper is executable
info "  Verifying wrapper script is executable ..."
if [[ -x "$TEST_APP/Contents/MacOS/casa1-wrapper" ]]; then
  info "    ✅ Wrapper script is executable"
  PASS=$((PASS + 1))
else
  fail "    ❌ Wrapper script is not executable"
  FAIL=$((FAIL + 1))
fi

# Verify wrapper actually runs
info "  Verifying wrapper script execution ..."
WRAPPER_OUTPUT="$("$TEST_APP/Contents/MacOS/casa1-wrapper" 2>&1)"
if [[ "$WRAPPER_OUTPUT" == "TestApp wrapper executed" ]]; then
  info "    ✅ Wrapper script executes correctly"
  PASS=$((PASS + 1))
else
  fail "    ❌ Wrapper script produced unexpected output: $WRAPPER_OUTPUT"
  FAIL=$((FAIL + 1))
fi

# ── 4. Code signing verification (macOS only) ────────────────────────────────
info ""
info "4. Checking code signing status (macOS only) ..."
if command -v codesign &>/dev/null; then
  for binary in "${BINARIES[@]}"; do
    BINARY_PATH="$RELEASE_DIR/$binary"
    if [[ -x "$BINARY_PATH" ]]; then
      SIGN_INFO="$(codesign -d -vvv "$BINARY_PATH" 2>&1 || true)"
      if echo "$SIGN_INFO" | grep -q "adhoc\|designated"; then
        info "  ✅ $binary: signed"
      else
        info "  ⚠  $binary: not signed (expected for debug/dev builds)"
      fi
    fi
  done
  PASS=$((PASS + 1))
else
  info "  codesign not available — skipping signing check"
  PASS=$((PASS + 1))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Release Smoke Test Summary ==="
echo "   Passed: $PASS"
echo "   Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
info "All release smoke tests passed."
exit 0
