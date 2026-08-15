#!/usr/bin/env bash
# ci/check_release_gate.sh — Final release gate for Casa1
#
# Verifies that all release-blocker items in checklist.md are checked ([x])
# before allowing a release to proceed.
#
# This script reads the checklist and ensures:
#   1. Every non-comment, non-empty line that starts with "- [ ]" is flagged.
#   2. All lines in the "CI And Release Readiness" section are checked.
#   3. A summary of unchecked items is printed.
#
# Usage:
#   ./ci/check_release_gate.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKLIST="$REPO_ROOT/checklist.md"

PASS=0
FAIL=0

info() { echo ":: $*"; }
fail() { echo "!! $*" >&2; }

if [[ ! -f "$CHECKLIST" ]]; then
  fail "checklist.md not found at $CHECKLIST"
  exit 1
fi

info "=== Release Gate Checklist Verification ==="
info "Checklist: $CHECKLIST"
info ""

# ── Count unchecked items ─────────────────────────────────────────────────────
info "Scanning for unchecked items ..."

UNCHECKED=()
CURRENT_SECTION=""

while IFS= read -r line; do
  # Detect section headers (## ...)
  if [[ "$line" =~ ^##\s+(.+) ]]; then
    CURRENT_SECTION="${BASH_REMATCH[1]}"
  fi

  # Check for unchecked checklist items
  if [[ "$line" =~ ^-\ \[ \] ]]; then
    ITEM="${line#- \[ \] }"
    UNCHECKED+=("[$CURRENT_SECTION] $ITEM")
  fi
done < "$CHECKLIST"

UNCHECKED_COUNT="${#UNCHECKED[@]}"

if [[ $UNCHECKED_COUNT -eq 0 ]]; then
  info "✅ All checklist items are checked!"
  PASS=$((PASS + 1))
else
  fail "❌ Found $UNCHECKED_COUNT unchecked checklist item(s):"
  fail ""
  for item in "${UNCHECKED[@]}"; do
    fail "   - $item"
  done
  FAIL=$((FAIL + 1))
fi

# ── Specifically check the CI And Release Readiness section ───────────────────
info ""
info "Checking 'CI And Release Readiness' section specifically ..."

IN_SECTION=false
SECTION_UNCHECKED=0
SECTION_TOTAL=0

while IFS= read -r line; do
  if [[ "$line" =~ ^##\s+CI\ And\ Release\ Readiness ]]; then
    IN_SECTION=true
    continue
  fi
  if [[ "$IN_SECTION" == true ]]; then
    # Stop at next section
    if [[ "$line" =~ ^##\s+ ]]; then
      break
    fi
    if [[ "$line" =~ ^-\ \[ \] ]]; then
      SECTION_UNCHECKED=$((SECTION_UNCHECKED + 1))
      SECTION_TOTAL=$((SECTION_TOTAL + 1))
    elif [[ "$line" =~ ^-\ \[x\] ]]; then
      SECTION_TOTAL=$((SECTION_TOTAL + 1))
    fi
  fi
done < "$CHECKLIST"

if [[ $SECTION_TOTAL -eq 0 ]]; then
  fail "No items found in 'CI And Release Readiness' section"
  FAIL=$((FAIL + 1))
elif [[ $SECTION_UNCHECKED -eq 0 ]]; then
  info "✅ All $SECTION_TOTAL items in 'CI And Release Readiness' section are checked"
  PASS=$((PASS + 1))
else
  fail "❌ $SECTION_UNCHECKED/$SECTION_TOTAL items unchecked in 'CI And Release Readiness' section"
  FAIL=$((FAIL + 1))
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Release Gate Summary ==="
echo "   Passed: $PASS"
echo "   Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "❌ RELEASE GATE BLOCKED — $UNCHECKED_COUNT unchecked item(s) in checklist"
  echo ""
  echo "To proceed with a release, mark the following items as [x] in checklist.md:"
  for item in "${UNCHECKED[@]}"; do
    echo "   - [ ] $item"
  done
  exit 1
fi

echo ""
echo "🎉 All release gate checks PASSED — release may proceed."
exit 0
