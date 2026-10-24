#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == "--self-test" ]]; then
  exec python3 "$root/test_perf_gate.py"
fi
exec python3 "$root/check_perf.py" "$@"
