#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Detect the default target if configured in .cargo/config.toml
default_target=""
if [[ -f "$repo_root/.cargo/config.toml" ]]; then
  default_target="$(grep -oP '(?<=^target\s*=\s*")[^"]+' "$repo_root/.cargo/config.toml" 2>/dev/null || true)"
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