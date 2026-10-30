#!/usr/bin/env bash
# ci/check_forbidden_patterns.sh — fail CI on newly introduced dangerous
# patterns that have a reviewed allowlist of existing call sites.
#
# Patterns checked:
#   rcx_state_get          state.get(Register::Rcx) inside the Win32 dispatch
#                          and router (the caller-saved RCX slot must not be
#                          read from guest state after a host call clobbers it)
#   command_new            std::process::Command::new outside the allowlist
#                          (process spawns must be explicit and reviewed)
#   guest_path_to_host_path guest_path_to_host_path callers outside the
#                          allowlist (path translation is a sandbox boundary)
#
# The allowlist is ci/forbidden-patterns-allowlist.tsv: one exact
# occurrence count per (pattern, file). A new file or a higher count fails;
# removing occurrences never fails (lower the baseline when deleting a site).
#
# Usage:
#   ./ci/check_forbidden_patterns.sh

set -euo pipefail

cd "$(dirname "$0")/.."

ALLOW="ci/forbidden-patterns-allowlist.tsv"
if [[ ! -f "$ALLOW" ]]; then
  echo "::error::$ALLOW is missing" >&2
  exit 1
fi

if ! command -v rg >/dev/null 2>&1; then
  echo "::error::ripgrep (rg) is required for the forbidden-pattern gate" >&2
  exit 1
fi

FAIL=0

check_pattern() {
  local key="$1"
  local pattern="$2"
  shift 2
  local actual
  actual="$(rg -c -F -- "$pattern" "$@" 2>/dev/null || true)"

  local file count allowed
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    file="${line%:*}"
    count="${line##*:}"
    allowed="$(awk -F'\t' -v k="$key" -v f="$file" '$1==k && $2==f {print $3; exit}' "$ALLOW")"
    if [[ -z "$allowed" ]]; then
      echo "::error::new '$key' occurrence in $file (not in $ALLOW)" >&2
      FAIL=1
    elif (( count > allowed )); then
      echo "::error::$key in $file: $count occurrence(s), allowlist permits $allowed" >&2
      FAIL=1
    fi
  done <<< "$actual"

  local seen
  seen="$(printf '%s\n' "$actual" | awk -F: 'NF {print $1}')"
  while IFS=$'\t' read -r entry_key entry_file entry_count; do
    [[ "$entry_key" == "$key" ]] || continue
    if ! grep -qxF "$entry_file" <<< "$seen"; then
      echo "::notice::$key reduce detected in $entry_file (baseline $entry_count, now 0); lower the allowlist" >&2
    fi
  done < <(awk -F'\t' '$1 !~ /^#/ {print}' "$ALLOW")
}

check_pattern rcx_state_get 'state.get(Register::Rcx)' src/runtime/dispatch src/runtime/router
check_pattern command_new 'Command::new' src build.rs
check_pattern guest_path_to_host_path 'guest_path_to_host_path' src

if (( FAIL )); then
  echo "::error::forbidden-pattern gate FAILED — add the new call site only after review, or update $ALLOW deliberately" >&2
  exit 1
fi

echo "OK: no new forbidden-pattern call sites"
