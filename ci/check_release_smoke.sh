#!/usr/bin/env bash
# ci/check_release_smoke.sh — Release smoke tests for Casa1
#
# Verifies:
#   1. All CLI binaries print usage and exit with expected status.
#   2. App bundle structure can be created and validated.
#   3. Release binaries are signed (if codesign available), including the
#      allow-jit entitlement on casa1-runner.
#   4. JIT self-test: a dedicated --jit-self-test CLI on the packaged runner
#      when one exists; otherwise the JIT unit tests (cargo test --lib jit::).
#      In release mode the packaged-runner PE execution covers JIT instead,
#      because release mode refuses to build anything.
#   5. Minimal PE execution through the packaged runner (the bounded
#      casa1-tetris-smoke.exe fixture runs to a clean exit via macwin ->
#      casa1-runner, exercising the real JIT on Apple Silicon).
#   6. Effective steam:launch profile surface (steam:launch --help exposes
#      the performance/profile flags; there is no dry-run mode yet).
#
# Release mode (CASA1_PRODUCT_BUNDLE=1 or CI_RELEASE=1): missing binaries
# FAIL the smoke test — the script never silently rebuilds release artifacts,
# because a rebuilt binary would not be the one that was signed and tested.
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
  default_target="$(sed -nE 's/^target[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$REPO_ROOT/.cargo/config.toml" | head -1)"
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

RELEASE_MODE=0
if [[ -n "${CASA1_PRODUCT_BUNDLE:-}" || -n "${CI_RELEASE:-}" ]]; then
  RELEASE_MODE=1
  info "Release mode: ON (missing binaries will FAIL, never silently rebuilt)"
fi

# ── 1. Ensure release binaries are built ─────────────────────────────────────
info ""
info "1. Checking release binaries exist ..."
if [[ ! -d "$RELEASE_DIR" ]]; then
  if [[ $RELEASE_MODE -eq 1 ]]; then
    fail "Release directory $RELEASE_DIR does not exist"
    fail "Release mode refuses to rebuild — build and sign the release artifacts first"
    exit 1
  fi
  info "Release directory does not exist — building release binaries ..."
  cargo build --release --bins 2>&1
fi

MISSING=0
for binary in "${BINARIES[@]}"; do
  if [[ ! -x "$RELEASE_DIR/$binary" ]]; then
    if [[ $RELEASE_MODE -eq 1 ]]; then
      fail "Missing release binary: $binary — release mode fails closed (no rebuild)"
    else
      fail "Missing release binary: $binary"
    fi
    MISSING=$((MISSING + 1))
  else
    info "  ✅ $binary found ($(stat -f%z "$RELEASE_DIR/$binary" 2>/dev/null || stat -c%s "$RELEASE_DIR/$binary" 2>/dev/null) bytes)"
  fi
done

if [[ $MISSING -gt 0 ]]; then
  if [[ $RELEASE_MODE -eq 1 ]]; then
    fail "$MISSING binaries missing — build and sign the release artifacts first (release mode never rebuilds)"
  else
    fail "$MISSING binaries missing — build release first"
  fi
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
  fail "casa1-oracle --help did not produce expected output: $(echo "$ORACLE_OUTPUT" | head -3)"
  FAIL=$((FAIL + 1))
fi

# casa1-test-guest --help
info "  casa1-test-guest --help ..."
TESTGUEST_OUTPUT="$("$RELEASE_DIR/casa1-test-guest" --help 2>&1 || true)"
if echo "$TESTGUEST_OUTPUT" | grep -q "Usage\|Commands\|Arguments"; then
  info "    ✅ casa1-test-guest --help produces usage output"
  PASS=$((PASS + 1))
else
  fail "casa1-test-guest --help did not produce expected output: $(echo "$TESTGUEST_OUTPUT" | head -3)"
  FAIL=$((FAIL + 1))
fi

# ── 3. App bundle structure test (via the real bundler) ───────────────────────
info ""
info "3. Testing app bundle creation ..."

# Create a temporary directory for app bundle testing
TEMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t casa1-smoke)"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Use the project's real bundling entry point (macwin apps:install, which
# calls create_app_bundle()) so regressions in the bundler itself are caught.
# A throwaway Game Environment is created under CASA1_GES_ROOT so the test
# never touches real environments or Launch Services.
export CASA1_GES_ROOT="$TEMP_DIR/ges"
GE_NAME="smoke-test-ge"

BUNDLE_TEST_OK=true
if ! "$RELEASE_DIR/macwin" ge:create --name "$GE_NAME" --arch x64 --winver win11-23h2 \
    > "$TEMP_DIR/ge-create.json" 2>&1; then
  fail "macwin ge:create failed — cannot test app bundling"
  fail "$(head -5 "$TEMP_DIR/ge-create.json")"
  FAIL=$((FAIL + 1))
  BUNDLE_TEST_OK=false
elif ! "$RELEASE_DIR/macwin" apps:install \
    --ge "$GE_NAME" \
    --exe /bin/echo \
    --app-name TestApp \
    --bundle-id com.casa1.testapp \
    --skip-launch-services \
    > "$TEMP_DIR/apps-install.json" 2>&1; then
  fail "macwin apps:install failed — cannot test app bundling"
  fail "$(head -5 "$TEMP_DIR/apps-install.json")"
  FAIL=$((FAIL + 1))
  BUNDLE_TEST_OK=false
fi

if [[ "$BUNDLE_TEST_OK" == "true" ]]; then
  # Extract the created .app path from the JSON response
  TEST_APP="$(python3 -c "
import json, sys
try:
    data = json.load(open('$TEMP_DIR/apps-install.json'))
    print(data.get('app_path', ''))
except Exception:
    print('')
")"

  if [[ -z "$TEST_APP" ]]; then
    fail "apps:install response did not include an app_path"
    fail "$(cat "$TEMP_DIR/apps-install.json")"
    FAIL=$((FAIL + 1))
  elif [[ ! -d "$TEST_APP" ]]; then
    fail "bundler reported app_path that does not exist: $TEST_APP"
    FAIL=$((FAIL + 1))
  else
    info "  Bundler created: $TEST_APP"

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

    # Verify Info.plist contains required keys
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

    # Verify the wrapper launches through the real ge:run path (it must NOT
    # be executed here — that would start the guest environment)
    info "  Verifying wrapper script content ..."
    if grep -q "ge:run" "$TEST_APP/Contents/MacOS/casa1-wrapper" \
      && grep -q "$GE_NAME" "$TEST_APP/Contents/MacOS/casa1-wrapper"; then
      info "    ✅ Wrapper invokes ge:run for the configured environment"
      PASS=$((PASS + 1))
    else
      fail "    ❌ Wrapper script does not invoke the real ge:run launcher"
      FAIL=$((FAIL + 1))
    fi
  fi
fi

# ── 4. Code signing verification (macOS only) ────────────────────────────────
info ""
info "4. Checking code signing (macOS only) ..."
if command -v codesign &>/dev/null; then
  # Verify the as-built signature is present and valid. The release process is
  # responsible for signing (Developer ID, hardened runtime, JIT entitlements);
  # this gate must NOT re-sign the artifacts, or it would only ever verify its
  # own manufactured signature and mask a broken release signing step.
  SIGN_FAILED=false
  for binary in "${BINARIES[@]}"; do
    BINARY_PATH="$RELEASE_DIR/$binary"
    if [[ ! -x "$BINARY_PATH" ]]; then
      continue
    fi
    if ! /usr/bin/codesign --verify --strict "$BINARY_PATH" &>/dev/null; then
      fail "  ❌ $binary: signature invalid or missing (as built by the release)"
      SIGN_FAILED=true
    else
      info "  ✅ $binary: signature valid"
    fi
  done

  if [[ "$SIGN_FAILED" == "true" ]]; then
    fail "  ❌ codesign verification failed for one or more release binaries"
    FAIL=$((FAIL + 1))
  fi

  # casa1-runner must carry the JIT entitlement (allow-jit) in its embedded
  # signature; without it the runner cannot JIT-compile on macOS.
  RUNNER_PATH="$RELEASE_DIR/casa1-runner"
  if [[ -x "$RUNNER_PATH" ]] && /usr/bin/codesign -d --entitlements - "$RUNNER_PATH" 2>/dev/null | grep -q "allow-jit"; then
    info "  ✅ casa1-runner: allow-jit entitlement present"
  elif [[ -x "$RUNNER_PATH" ]]; then
    fail "  ❌ casa1-runner: allow-jit entitlement missing"
    FAIL=$((FAIL + 1))
  fi
else
  info "  codesign not available — skipping signing check"
  PASS=$((PASS + 1))
fi

# ── 5. JIT self-test ─────────────────────────────────────────────────────────
info ""
info "5. JIT self-test ..."

# Preferred: a dedicated self-test flag on the packaged runner. No such CLI
# exists today (src/cli.rs and src/runner.rs expose no self-test command),
# so we fall back to the JIT unit tests. In release mode we must not build
# anything, so JIT execution is validated by the packaged-runner PE
# execution in step 6 (guest code runs through the real JIT on Apple
# Silicon when the allow-jit-signed runner carries the entitlement).
if "$RELEASE_DIR/casa1-runner" --jit-self-test >/dev/null 2>&1; then
  info "  ✅ casa1-runner --jit-self-test passed"
  PASS=$((PASS + 1))
elif [[ $RELEASE_MODE -eq 1 ]]; then
  info "  --jit-self-test is not implemented on the packaged runner yet;"
  info "  release mode refuses rebuilds, so JIT is covered by step 6"
  info "  (packaged-runner PE execution through the real JIT)."
else
  info "  --jit-self-test not implemented; running the JIT unit tests as the"
  info "  self-test: cargo test --lib jit::"
  if cargo test --lib jit:: >/dev/null 2>&1; then
    info "  ✅ JIT unit self-test passed (cargo test --lib jit::)"
    PASS=$((PASS + 1))
  else
    fail "  ❌ JIT unit self-test failed (cargo test --lib jit::)"
    FAIL=$((FAIL + 1))
  fi
fi

# ── 6. Minimal PE execution through the packaged runner ──────────────────────
info ""
info "6. Minimal PE execution through the packaged runner ..."

# The bounded casa1-tetris-smoke.exe fixture (TETRIS_SMOKE build) renders a
# frame and exits on its own; running it through macwin -> casa1-runner
# exercises the packaged runner end to end, including JIT execution on
# Apple Silicon. The throwaway GE from step 3 is reused, so no real
# environment is touched.
TETRIS_PE="$REPO_ROOT/games/windows_tetris/dist/casa1-tetris-smoke.exe"
if [[ ! -f "$TETRIS_PE" ]]; then
  fail "  ❌ Missing PE fixture: $TETRIS_PE"
  FAIL=$((FAIL + 1))
elif [[ ! -d "$CASA1_GES_ROOT/$GE_NAME" ]]; then
  fail "  ❌ Throwaway GE '$GE_NAME' missing (ge:create failed earlier) — cannot run PE fixture"
  FAIL=$((FAIL + 1))
else
  if "$RELEASE_DIR/macwin" ge:run --ge "$GE_NAME" --exe "$TETRIS_PE" --dtm \
      > "$TEMP_DIR/ge-run.json" 2>&1; then
    info "  ✅ Packaged runner executed $TETRIS_PE to a clean exit (exit 0)"
    PASS=$((PASS + 1))
  else
    fail "  ❌ Packaged runner failed on $TETRIS_PE"
    fail "$(head -5 "$TEMP_DIR/ge-run.json")"
    FAIL=$((FAIL + 1))
  fi
fi

# ── 7. Effective steam:launch profile test ───────────────────────────────────
info ""
info "7. steam:launch profile surface test ..."

# No profile dry-run/print mode exists on steam:launch yet, so the
# effective-profile smoke is: the subcommand parses and --help exposes the
# profile/performance flags that construct the launch profile (--performance,
# --no-jit, --offline, --debug, --ge). Once a dry-run is added, replace this
# with an actual profile dry-run invocation.
STEAM_HELP="$("$RELEASE_DIR/macwin" steam:launch --help 2>&1 || true)"
if echo "$STEAM_HELP" | grep -q -- "--performance" \
  && echo "$STEAM_HELP" | grep -q -- "--no-jit" \
  && echo "$STEAM_HELP" | grep -q -- "--ge" \
  && echo "$STEAM_HELP" | grep -q "Usage"; then
  info "  ✅ steam:launch --help exposes the launch/profile flags"
  PASS=$((PASS + 1))
else
  fail "  ❌ steam:launch --help did not expose the expected profile flags"
  fail "$(echo "$STEAM_HELP" | head -5)"
  FAIL=$((FAIL + 1))
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
