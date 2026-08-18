#!/usr/bin/env bash
# ci/check_release_gate.sh — Final release gate for Casa1 (evidence model)
#
# The gate no longer inspects checklist.md. checklist.md is a human tracking
# document and is NOT executable evidence. Release decisions are made from a
# machine-readable release-evidence.json produced by the release pipeline
# (Steam E2E workflow + signed-candidate validation), and this script fails
# CLOSED: any missing file, missing field, hash mismatch, or "not pass"
# value blocks the release.
#
# Verification steps:
#   1. release-evidence.json exists and parses as JSON.
#   2. Its "commit" field matches the current git HEAD exactly.
#   3. Every required acceptance field carries the value "pass".
#   4. The Steam E2E artifact (steam_e2e_artifact) is present, its content
#      digest (steam_e2e_artifact_sha256) matches, its embedded commit.txt
#      equals HEAD ("the artifact belongs to the same commit"), and its
#      embedded release-evidence.json is byte-identical to the one being
#      validated.
#   5. The signed candidate file (signed_candidate) is present and its
#      sha256 matches signed_candidate_sha256 — i.e. the hash recorded in
#      the evidence is the hash of the exact artifact that was tested.
#
# The Steam E2E artifact content digest is deterministic across machines:
#   digest = sha256( sha256(commit.txt) + sha256(acceptance.json)
#                    + sha256(milestones.json) )   (hex strings, no newlines)
# computed over the extracted artifact contents. GitHub zip downloads can
# vary byte-for-byte, so the digest is computed over contents, never over
# the zip container.
#
# Example release-evidence.json schema (v1):
#
#   {
#     "schema_version": 1,
#     "commit": "71b81ddb685eb033e928199f98d5c7495f9d7136",
#     "steam_e2e_artifact": "steam-e2e-evidence",            // dir or zip name
#     "steam_e2e_artifact_sha256": "<content digest of the artifact>",
#     "steam_e2e_acceptance": "pass",
#     "steam_e2e_milestones": "pass",
#     "signed_jit_selftest": "pass",
#     "cargo_tests": "pass",
#     "signed_candidate": "Casa1-0.2.0-signed.zip",          // exact file tested
#     "signed_candidate_sha256": "<sha256 of signed_candidate>"
#   }
#
# Required "pass" fields: steam_e2e_acceptance, steam_e2e_milestones,
# signed_jit_selftest, cargo_tests.
#
# Usage:
#   RELEASE_EVIDENCE_FILE=<path>  ./ci/check_release_gate.sh   (default: <repo>/release-evidence.json)
#   RELEASE_EVIDENCE_DIR=<dir>    ./ci/check_release_gate.sh   (default: dir of the evidence file)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_FILE="${RELEASE_EVIDENCE_FILE:-$REPO_ROOT/release-evidence.json}"
EVIDENCE_DIR="${RELEASE_EVIDENCE_DIR:-$(cd "$(dirname "$EVIDENCE_FILE")" && pwd)}"

PASS=0
FAIL=0

info() { echo ":: $*"; }
fail() { echo "!! $*" >&2; }

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

# Deterministic content digest of the Steam E2E evidence bundle:
# sha256 over the concatenated per-file sha256s of commit.txt,
# acceptance.json, and milestones.json (hex strings, no newlines).
bundle_digest() {
  local dir="$1"
  local acc=""
  for f in commit.txt acceptance.json milestones.json; do
    [[ -f "$dir/$f" ]] || return 1
    acc="$acc$(sha256_of "$dir/$f")"
  done
  printf '%s' "$acc" | shasum -a 256 | awk '{print $1}'
}

info "=== Release Gate: Evidence Verification ==="
info "Evidence file: $EVIDENCE_FILE"
info ""

# ── 1. Evidence file exists and parses ───────────────────────────────────────
if [[ ! -f "$EVIDENCE_FILE" ]]; then
  fail "release-evidence.json not found at $EVIDENCE_FILE"
  fail "The release gate fails closed: evidence of the Steam E2E run and the"
  fail "signed candidate must exist before a release may proceed."
  exit 1
fi

EVIDENCE="$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.dumps(json.load(f)))
except Exception as e:
    print("INVALID:" + str(e), file=sys.stderr)
    sys.exit(1)
' "$EVIDENCE_FILE")"

info "  ✅ release-evidence.json parses as JSON"
PASS=$((PASS + 1))

# ── 2. Commit matches HEAD ───────────────────────────────────────────────────
HEAD_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)"
if [[ -z "$HEAD_COMMIT" ]]; then
  fail "cannot determine git HEAD — refusing to gate"
  exit 1
fi

EVIDENCE_COMMIT="$(printf '%s' "$EVIDENCE" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d.get("commit", ""))
')"

if [[ "$EVIDENCE_COMMIT" == "$HEAD_COMMIT" ]]; then
  info "  ✅ evidence commit matches HEAD ($HEAD_COMMIT)"
  PASS=$((PASS + 1))
else
  fail "evidence commit ($EVIDENCE_COMMIT) does not match HEAD ($HEAD_COMMIT)"
  FAIL=$((FAIL + 1))
fi

# ── 3. Required acceptance fields are all "pass" ─────────────────────────────
PASS_FIELDS=(steam_e2e_acceptance steam_e2e_milestones signed_jit_selftest cargo_tests)
for field in "${PASS_FIELDS[@]}"; do
  value="$(printf '%s' "$EVIDENCE" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d.get(sys.argv[1], "<missing>"))
' "$field")"
  if [[ "$value" == "pass" ]]; then
    info "  ✅ $field: pass"
    PASS=$((PASS + 1))
  else
    fail "$field is not \"pass\" (got: $value)"
    FAIL=$((FAIL + 1))
  fi
done

# ── 4. Steam E2E artifact belongs to this commit ─────────────────────────────
ARTIFACT="$(printf '%s' "$EVIDENCE" | python3 -c '
import json, sys
print(json.load(sys.stdin).get("steam_e2e_artifact", ""))
')"
EXPECTED_ARTIFACT_DIGEST="$(printf '%s' "$EVIDENCE" | python3 -c '
import json, sys
print(json.load(sys.stdin).get("steam_e2e_artifact_sha256", ""))
')"

if [[ -z "$ARTIFACT" || -z "$EXPECTED_ARTIFACT_DIGEST" ]]; then
  fail "evidence is missing steam_e2e_artifact and/or steam_e2e_artifact_sha256"
  FAIL=$((FAIL + 1))
else
  ARTIFACT_PATH="$EVIDENCE_DIR/$ARTIFACT"
  if [[ -d "$ARTIFACT_PATH" ]]; then
    # Directory artifact (local workflow / extracted zip)
    ARTIFACT_ROOT="$ARTIFACT_PATH"
  elif [[ -f "$ARTIFACT_PATH" && "$ARTIFACT_PATH" == *.zip ]]; then
    # Zip artifact (as uploaded by the Steam E2E workflow)
    TMP_EXTRACT="$(mktemp -d)"
    trap 'rm -rf "$TMP_EXTRACT"' EXIT
    if ! unzip -q -o "$ARTIFACT_PATH" -d "$TMP_EXTRACT" 2>/dev/null; then
      fail "cannot extract artifact $ARTIFACT_PATH"
      FAIL=$((FAIL + 1))
      ARTIFACT_ROOT=""
    else
      ARTIFACT_ROOT="$TMP_EXTRACT"
    fi
  else
    ARTIFACT_ROOT=""
    fail "Steam E2E artifact not found: $ARTIFACT_PATH"
    FAIL=$((FAIL + 1))
  fi

  if [[ -n "${ARTIFACT_ROOT:-}" ]]; then
    if ! ACTUAL_DIGEST="$(bundle_digest "$ARTIFACT_ROOT")"; then
      fail "artifact is missing evidence files (commit.txt/acceptance.json/milestones.json) — it does not tie to any commit"
      FAIL=$((FAIL + 1))
    else
      if [[ "$ACTUAL_DIGEST" == "$EXPECTED_ARTIFACT_DIGEST" ]]; then
        info "  ✅ steam_e2e_artifact_sha256 matches the artifact content digest"
        PASS=$((PASS + 1))
      else
        fail "steam_e2e_artifact_sha256 mismatch: evidence records $EXPECTED_ARTIFACT_DIGEST, artifact yields $ACTUAL_DIGEST"
        FAIL=$((FAIL + 1))
      fi
    fi

    # The artifact must have been produced from exactly this commit.
    ARTIFACT_COMMIT="$(cat "$ARTIFACT_ROOT/commit.txt" 2>/dev/null || true)"
    if [[ "$ARTIFACT_COMMIT" == "$HEAD_COMMIT" ]]; then
      info "  ✅ artifact commit marker matches HEAD (same commit)"
      PASS=$((PASS + 1))
    else
      fail "artifact commit marker ($ARTIFACT_COMMIT) does not match HEAD ($HEAD_COMMIT) — artifact was not built from this commit"
      FAIL=$((FAIL + 1))
    fi

    # The artifact's embedded evidence must be the evidence being validated.
    if [[ -f "$ARTIFACT_ROOT/release-evidence.json" ]]; then
      if cmp -s "$ARTIFACT_ROOT/release-evidence.json" "$EVIDENCE_FILE"; then
        info "  ✅ artifact's embedded release-evidence.json is byte-identical"
        PASS=$((PASS + 1))
      else
        fail "artifact's embedded release-evidence.json differs from $EVIDENCE_FILE"
        FAIL=$((FAIL + 1))
      fi
    else
      fail "artifact does not embed release-evidence.json"
      FAIL=$((FAIL + 1))
    fi
  fi
fi

# ── 5. Signed candidate hash matches the exact artifact tested ───────────────
CANDIDATE="$(printf '%s' "$EVIDENCE" | python3 -c '
import json, sys
print(json.load(sys.stdin).get("signed_candidate", ""))
')"
EXPECTED_CANDIDATE_SHA="$(printf '%s' "$EVIDENCE" | python3 -c '
import json, sys
print(json.load(sys.stdin).get("signed_candidate_sha256", ""))
')"

if [[ -z "$CANDIDATE" || -z "$EXPECTED_CANDIDATE_SHA" ]]; then
  fail "evidence is missing signed_candidate and/or signed_candidate_sha256"
  FAIL=$((FAIL + 1))
else
  CANDIDATE_PATH="$EVIDENCE_DIR/$CANDIDATE"
  if [[ ! -f "$CANDIDATE_PATH" ]]; then
    fail "signed candidate not found: $CANDIDATE_PATH"
    FAIL=$((FAIL + 1))
  elif [[ "$(sha256_of "$CANDIDATE_PATH")" != "$EXPECTED_CANDIDATE_SHA" ]]; then
    fail "signed candidate hash mismatch: $CANDIDATE was modified or replaced since it was tested"
    FAIL=$((FAIL + 1))
  else
    info "  ✅ signed candidate sha256 matches the artifact tested"
    PASS=$((PASS + 1))
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Release Gate Summary ==="
echo "   Passed: $PASS"
echo "   Failed: $FAIL"

if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "❌ RELEASE GATE BLOCKED — evidence does not support a release."
  echo ""
  echo "To proceed, re-run the Steam E2E workflow for this exact commit and"
  echo "re-test the signed candidate, then regenerate release-evidence.json"
  echo "with hashes of the exact artifacts tested (see docs/RELEASE_PROCESS.md)."
  exit 1
fi

echo ""
echo "🎉 Release gate PASSED — evidence ties the Steam E2E run and the signed"
echo "candidate to this exact commit ($HEAD_COMMIT)."
exit 0
