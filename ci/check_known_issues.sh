#!/usr/bin/env bash
# ci/check_known_issues.sh — Require every KNOWN-ISSUE marker in tests/ to
# carry a tracking/evidence reference.
#
# A KNOWN-ISSUE comment is only acceptable when its block references where
# the defect is tracked or evidenced:
#   * a source reference ("src/...:line"),
#   * an issue URL ("https://..." or "b/..."),
#   * a dated verification ("verified YYYY-MM-DD").
# Any KNOWN-ISSUE block without such a marker fails the check.
#
# Usage:
#   ./ci/check_known_issues.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0

# Each KNOWN-ISSUE marker's comment block continues while lines start with
# optional whitespace followed by "//"; collect the whole block so the
# marker may appear on any of its lines.
while IFS=: read -r file line rest; do
  # Collect the whole comment block starting at the marker line.
  block="$(awk -v start="$line" '
    NR < start { next }
    /^[[:space:]]*\/\// { print; next }
    { exit }
  ' "$file")"
  if ! grep -qE 'src/|https?://|b/[0-9]+|verified [0-9]{4}-[0-9]{2}-[0-9]{2}' <<<"$block"; then
    echo "!! $file:$line: KNOWN-ISSUE without a tracking/evidence marker" >&2
    FAIL=1
  fi
done < <(grep -RIn -- "KNOWN-ISSUE" tests/ || true)

if [[ $FAIL -ne 0 ]]; then
  echo "!! KNOWN-ISSUE markers must reference an issue/evidence entry (src/ path, issue URL, or verified date)" >&2
  exit 1
fi

echo ":: all KNOWN-ISSUE markers carry a tracking/evidence reference"
