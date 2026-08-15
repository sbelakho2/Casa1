#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
cargo build --release --bins

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

for binary in casa1 macwin casa1-helper casa1-test-guest casa1-oracle; do
  /usr/bin/codesign --force --sign - "$release_dir/$binary" &>/dev/null
done

/usr/bin/codesign \
  --force \
  --sign - \
  --entitlements "$repo_root/ci/entitlements/casa1-runner.plist" \
  "$release_dir/casa1-runner" &>/dev/null

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