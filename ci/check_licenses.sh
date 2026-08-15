#!/usr/bin/env bash
# ci/check_licenses.sh — License and supply-chain checks for Casa1
#
# Verifies that:
#   1. Cargo.toml has a valid license field.
#   2. All dependencies have OSI-approved or compatible licenses.
#   3. No dependency uses a copyleft license that would be incompatible.
#
# Uses `cargo license` if available, otherwise falls back to metadata inspection.
#
# Usage:
#   ./ci/check_licenses.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PASS=0
FAIL=0

info() { echo ":: $*"; }
fail() { echo "!! $*" >&2; }

# ── 1. Verify Cargo.toml has a license field ─────────────────────────────────
info "Checking Cargo.toml for license field ..."
LICENSE="$(grep '^license[[:space:]]*=' Cargo.toml | head -1 | sed -E 's/^license[[:space:]]*=[[:space:]]*"([^"]*)"/\1/' || true)"
if [[ -z "$LICENSE" ]]; then
  fail "Cargo.toml is missing the 'license' field"
  FAIL=$((FAIL + 1))
else
  info "License field: $LICENSE"
  # Accept common permissive licenses
  case "$LICENSE" in
    MIT|"MIT OR Apache-2.0"|"Apache-2.0 OR MIT"|"Apache-2.0"|"MIT/Apache-2.0"|"BSD-3-Clause"|"BSD-2-Clause"|"ISC"|"Unlicense"|"CC0-1.0")
      info "License '$LICENSE' is OSI-approved / compatible — OK"
      PASS=$((PASS + 1))
      ;;
    *)
      fail "License '$LICENSE' may not be OSI-approved — verify compatibility"
      FAIL=$((FAIL + 1))
      ;;
  esac
fi

# ── 2. Check dependency licenses ─────────────────────────────────────────────
info ""
info "Checking dependency licenses ..."

# Use cargo-license if available, otherwise use cargo metadata + python3
if command -v cargo-license &>/dev/null; then
  info "Using cargo-license for dependency license scan ..."
  if ! LICENSE_OUTPUT="$(cargo license --do-not-bundle --transitive 2>&1)"; then
    fail "cargo license failed — dependency licenses could not be verified"
    FAIL=$((FAIL + 1))
  else
    # Known problematic license patterns
    PROBLEMATIC=0
    while IFS= read -r line; do
      case "$line" in
        *"GPL"*|*"AGPL"*|*"LGPL"*|*"CC-BY-NC"*|*"CC-BY-ND"*|*"BUSL"*|*"SSPL"*)
          fail "Potentially incompatible license found: $line"
          PROBLEMATIC=$((PROBLEMATIC + 1))
          ;;
      esac
    done <<< "$LICENSE_OUTPUT"

    if [[ $PROBLEMATIC -eq 0 ]]; then
      info "All dependency licenses appear compatible — OK"
      PASS=$((PASS + 1))
    else
      fail "Found $PROBLEMATIC dependencies with potentially incompatible licenses"
      FAIL=$((FAIL + 1))
    fi
  fi
elif command -v python3 &>/dev/null; then
  info "Using cargo metadata + python3 for license scan ..."
  if python3 -c "
import json, subprocess, sys

result = subprocess.run(
    ['cargo', 'metadata', '--format-version', '1'],
    capture_output=True, text=True, cwd='$REPO_ROOT'
)
if result.returncode != 0:
    print('!! cargo metadata failed')
    sys.exit(1)

metadata = json.loads(result.stdout)
# Collect unique license expressions from all packages
licenses = set()
for pkg in metadata.get('packages', []):
    lic = pkg.get('license')
    if lic:
        licenses.add(lic)

# Check for known incompatible licenses
incompatible = [l for l in licenses if any(x in l.upper() for x in ['GPL', 'AGPL', 'LGPL', 'CC-BY-NC', 'BUSL', 'SSPL'])]
if incompatible:
    print(f'!! Potentially incompatible licenses found: {incompatible}')
    sys.exit(1)
else:
    print(f'    All {len(licenses)} unique license expressions appear compatible')
" 2>&1; then
    info "Dependency license scan via metadata — OK"
    PASS=$((PASS + 1))
  else
    fail "Dependency license scan found issues"
    FAIL=$((FAIL + 1))
  fi
else
  info "Neither cargo-license nor python3 available — skipping dependency license scan"
  info "Install with: cargo install cargo-license"
fi

# ── 3. Check for supply-chain metadata ───────────────────────────────────────
info ""
info "Checking supply-chain metadata ..."

# Check for .cargo/audit.toml or deny.toml (deny configuration)
if [[ -f "$REPO_ROOT/deny.toml" ]]; then
  info "Found deny.toml — cargo-deny configuration present"
fi

# Check that Cargo.lock is present (pinned dependencies)
if [[ -f "$REPO_ROOT/Cargo.lock" ]]; then
  info "Cargo.lock present — dependencies are pinned — OK"
  PASS=$((PASS + 1))
else
  fail "Cargo.lock missing — dependencies are not pinned"
  FAIL=$((FAIL + 1))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== License Check Summary ==="
echo "   Passed: $PASS"
echo "   Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
  exit 1
fi
exit 0
