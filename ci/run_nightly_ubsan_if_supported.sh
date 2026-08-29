#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

host_target="$(rustc +nightly -vV | awk '/^host:/ { print $2 }')"

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
      echo "nightly UBSAN supported on $target; running serialized full suite"
      RUSTFLAGS='-Zsanitizer=undefined' cargo +nightly test -Zbuild-std --target "$target" -- --test-threads=1
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