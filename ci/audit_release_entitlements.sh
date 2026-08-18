#!/usr/bin/env bash
# ci/audit_release_entitlements.sh — Release entitlement audit for Casa1
#
# Default mode: builds the release binaries, ad-hoc signs them (with the
# JIT entitlement on casa1-runner), and audits the entitlement structure.
# This validates entitlement policy but manufactures its own signatures.
#
# --verify-existing-signatures mode: refuses to build and refuses to sign
# anything. It only VERIFIES the signatures already present on the release
# binaries: each binary must carry a valid Developer ID signature, and the
# entitlement audit (including com.apple.security.cs.allow-jit on
# casa1-runner) is run against the existing signed binaries. Any unsigned,
# ad-hoc-signed, or missing binary fails the audit — the gate fails closed.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

verify_only=0
case "${1:-}" in
  --verify-existing-signatures) verify_only=1 ;;
  "") ;;
  *) echo "usage: $0 [--verify-existing-signatures]" >&2; exit 2 ;;
esac

# Detect the default target if configured in .cargo/config.toml
default_target=""
if [[ -f "$repo_root/.cargo/config.toml" ]]; then
  default_target="$(sed -nE 's/^target[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' "$repo_root/.cargo/config.toml" | head -1)"
fi
if [[ -n "$default_target" ]]; then
  release_dir="${RELEASE_DIR:-$repo_root/target/$default_target/release}"
else
  release_dir="${RELEASE_DIR:-$repo_root/target/release}"
fi

cd "$repo_root"

if [[ $verify_only -eq 1 ]]; then
  echo "Mode: --verify-existing-signatures (verify only; nothing will be built or re-signed)"
else
  cargo build --release --bins
fi

# IMPORTANT: This list must stay in sync with [[bin]] entries in Cargo.toml.
# The verification step below will catch mismatches.
binaries=(
  casa1
  macwin
  casa1-runner
  casa1-helper
  casa1-test-guest
  casa1-oracle
)

# Verify the binary list matches Cargo.toml [[bin]] entries
expected_count="$(grep -c '^\[\[bin\]\]' Cargo.toml)"
actual_count="${#binaries[@]}"
if [[ "$expected_count" -ne "$actual_count" ]]; then
  echo "ERROR: Cargo.toml defines $expected_count binaries but this script lists $actual_count." >&2
  echo "Please update the 'binaries' array in $0 to match." >&2
  exit 1
fi

for binary in "${binaries[@]}"; do
  if [[ ! -x "$release_dir/$binary" ]]; then
    echo "missing release binary: $release_dir/$binary" >&2
    exit 1
  fi
done

if [[ $verify_only -eq 1 ]]; then
  # -------------------------------------------------------------------------
  # Verify-only mode: never sign, never rebuild. Every binary must already
  # carry a valid Developer ID signature with the expected entitlements.
  # -------------------------------------------------------------------------
  SIGN_FAILED=false
  for binary in "${binaries[@]}"; do
    path="$release_dir/$binary"
    if ! /usr/bin/codesign --verify --strict "$path" &>/dev/null; then
      echo "ERROR: $binary: signature invalid or missing (expected an existing Developer ID signature)" >&2
      SIGN_FAILED=true
      continue
    fi
    if ! /usr/bin/codesign -dv "$path" 2>&1 | grep -q "Developer ID Application"; then
      echo "ERROR: $binary: signature is not a Developer ID Application signature" >&2
      echo "  (ad-hoc or unknown identity found — the release gate requires Developer ID)" >&2
      SIGN_FAILED=true
      continue
    fi
    echo "OK: $binary: valid Developer ID signature"
  done
  if [[ "$SIGN_FAILED" == true ]]; then
    echo "ERROR: one or more binaries failed signature verification." >&2
    echo "  The release process must sign every binary with the Developer ID identity;" >&2
    echo "  this audit never re-signs." >&2
    exit 1
  fi
else
  for binary in casa1 macwin casa1-helper casa1-test-guest casa1-oracle; do
    /usr/bin/codesign --force --sign - "$release_dir/$binary" &>/dev/null
  done

  /usr/bin/codesign \
    --force \
    --sign - \
    --entitlements "$repo_root/ci/entitlements/casa1-runner.plist" \
    "$release_dir/casa1-runner" &>/dev/null
fi

# The entitlement audit reads the embedded entitlements of the binaries as
# they are signed right now (ad-hoc in default mode, pre-existing Developer
# ID signatures in verify-only mode) and fails when the expected set,
# including com.apple.security.cs.allow-jit on casa1-runner, is missing.
"$release_dir/macwin" security:audit-entitlements \
  --jit-owner casa1-runner \
  --require-approved \
  --binary "$release_dir/casa1" \
  --binary "$release_dir/macwin" \
  --binary "$release_dir/casa1-runner" \
  --binary "$release_dir/casa1-helper" \
  --binary "$release_dir/casa1-test-guest" \
  --binary "$release_dir/casa1-oracle"

# ---------------------------------------------------------------------------
# Verify that insecure development features are NOT enabled in release builds
# ---------------------------------------------------------------------------
echo "Checking Cargo.toml for insecure default features..."

# Extract the default = [...] array from [features] and ensure dev-insecure-tls
# is not present. This prevents accidental inclusion of TLS bypass in release.
# (POSIX tools only — grep -P/-Pzo are GNU extensions unavailable on macOS.)
# The scan never `exit`s early (a `[features.x]` sub-table must not disable
# the check), and it fails closed when no top-level default array is found.
default_features="$(
  awk '
    /^\[features\]/ { in_features = 1; next }
    in_features && /^\[/ { in_features = 0 }
    in_features && /^default[[:space:]]*=/ { found = 1; depth = 0 }
    found {
        depth += gsub(/\[/, "[")
        depth -= gsub(/\]/, "]")
        print
        if (depth <= 0) { found = 0 }
    }
' Cargo.toml
)"
if [ -z "$default_features" ]; then
  echo "ERROR: could not locate the top-level [features] default array in Cargo.toml." >&2
  echo "Refusing to gate a release on an unverifiable feature list." >&2
  exit 1
fi
if echo "$default_features" | grep -q 'dev-insecure-tls'; then
  echo "ERROR: 'dev-insecure-tls' found in default features in Cargo.toml." >&2
  echo "Remove it before cutting a release." >&2
  exit 1
fi

echo "OK: dev-insecure-tls is not in default features."