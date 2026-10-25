#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail() { echo "::error::$*" >&2; exit 1; }

command -v rustc >/dev/null 2>&1 || fail "rustc is not on PATH"
rustc +nightly --version >/dev/null 2>&1 \
  || fail "the nightly toolchain is required for UBSAN"
host_target="$(rustc +nightly -vV | awk '/^host:/ { print $2 }')"
[[ -n "$host_target" ]] || fail "cannot determine the nightly host target"

# -Zbuild-std rebuilds std from source; without rust-src the real invocation
# below would fail even though the sanitizer probe succeeds. Check it before
# claiming support so an environment gap is reported as such.
nightly_sysroot="$(rustc +nightly --print sysroot)"
rust_src="$nightly_sysroot/lib/rustlib/src/rust/library"
[[ -d "$rust_src" ]] \
  || fail "rust-src is missing at $rust_src (install the rust-src component for nightly)"

# Meta tests invoke cargo from inside the lib test harness; AGENTS forbids
# running them. The sanctioned suite never executes them, and UBSAN must not
# either. ci/meta-tests.txt is the classification output for that invariant.

targets=("$host_target")
case "$host_target" in
  aarch64-apple-darwin)
    targets+=(x86_64-apple-darwin)
    ;;
  x86_64-apple-darwin)
    targets+=(aarch64-apple-darwin)
    ;;
esac

probe_ubsan_support() {
  local target="$1"
  rustc +nightly - \
    --crate-name casa1_ubsan_probe \
    --crate-type bin \
    --print=file-names \
    -Zsanitizer=undefined \
    --target "$target" <<'EOF'
fn main() {}
EOF
}

for target in "${targets[@]}"; do
  echo "probing nightly UBSAN support for $target"
  set +e
  probe_output="$(probe_ubsan_support "$target" 2>&1)"
  probe_status=$?
  set -e

  if [[ $probe_status -eq 0 ]]; then
    if [[ "$target" == "$host_target" ]]; then
      echo "nightly UBSAN supported on $target; running serialized test targets"
      test_args=(--test-threads=1)
      while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        test_args+=(--skip "$name")
      done < ci/meta-tests.txt
      # Explicit target selection: lib + bins + integration tests, no doctests
      # or examples. -Zbuild-std is the sanitizer-compatible std build, and
      # RUSTFLAGS carries the sanitizer to the rebuilt crate graph.
      RUSTFLAGS='-Zsanitizer=undefined' \
        cargo +nightly test -Zbuild-std --target "$target" \
        --lib --bins --tests -- "${test_args[@]}"
      exit 0
    fi

    echo "nightly UBSAN is accepted for $target, but the current runner host target is $host_target; skipping full-suite execution on the non-host target"
    continue
  fi

  if grep -Fq 'incorrect value `undefined`' <<<"$probe_output" \
    && grep -Fq 'unstable option `sanitizer`' <<<"$probe_output"; then
    echo "$probe_output"
    continue
  fi

  echo "$probe_output"
  exit $probe_status
done

echo "nightly UBSAN is currently unsupported for all probed targets: ${targets[*]}"