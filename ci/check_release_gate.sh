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
#   6. When api-report evidence is present (api_report / api_report_sha256 /
#      api_report_provenance fields, or an api-completeness.json.provenance.json
#      sidecar next to the evidence), it must be commit-bound: the provenance
#      commit and tree match HEAD, report_sha256 matches the report bytes, the
#      canonical report hash (volatile `generated_at` excluded) reproduces, and
#      the sidecar attests two-run determinism. api_report_provenance may be a
#      path string (legacy) or the full provenance object inline; when
#      api_report_provenance_sha256 is present for inline provenance, the
#      canonical inline content hash must match too. Nothing is required when
#      the fields and sidecar are absent, so older evidence keeps working.
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
# Optional api-report binding (all fields checked when present):
#
#     "api_report": "api-completeness.json",
#     "api_report_sha256": "<sha256 of api-completeness.json>",
#     "api_report_provenance": "api-completeness.json.provenance.json"
#                              // or the full provenance object inline
#     "api_report_provenance_sha256": "<sha256 of canonical inline provenance>"
#     "tree": "<git tree hash recorded by the provenance sidecar>"
#
# When the evidence does not declare the api-report fields, the gate falls back
# to <evidence-dir>/api-completeness.json.provenance.json if that file exists.
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
CANONICALIZER="$REPO_ROOT/ci/canonical_api_report.py"

PASS=0
FAIL=0

info() { echo ":: $*"; }
fail() { echo "!! $*" >&2; }

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

json_field() {
  printf '%s' "$1" | python3 -c '
import json, sys
print(json.load(sys.stdin).get(sys.argv[1], ""))
' "$2"
}

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
HEAD_TREE="$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}' 2>/dev/null || true)"
if [[ -z "$HEAD_COMMIT" ]]; then
  fail "cannot determine git HEAD — refusing to gate"
  exit 1
fi

EVIDENCE_COMMIT="$(json_field "$EVIDENCE" commit)"

if [[ "$EVIDENCE_COMMIT" == "$HEAD_COMMIT" ]]; then
  info "  ✅ evidence commit matches HEAD ($HEAD_COMMIT)"
  PASS=$((PASS + 1))
else
  fail "evidence commit ($EVIDENCE_COMMIT) does not match git rev-parse HEAD ($HEAD_COMMIT) — the evidence was produced for a different commit"
  FAIL=$((FAIL + 1))
fi

EVIDENCE_TREE="$(json_field "$EVIDENCE" tree)"
if [[ -n "$EVIDENCE_TREE" ]]; then
  if [[ "$EVIDENCE_TREE" == "$HEAD_TREE" ]]; then
    info "  ✅ evidence tree matches HEAD tree ($HEAD_TREE)"
    PASS=$((PASS + 1))
  else
    fail "evidence tree ($EVIDENCE_TREE) does not match HEAD tree ($HEAD_TREE) — the evidence was produced from a different source tree"
    FAIL=$((FAIL + 1))
  fi
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

# ── 6. Commit-bound api-report provenance (checked when present) ─────────────
API_REPORT="$(json_field "$EVIDENCE" api_report)"
API_REPORT_SHA="$(json_field "$EVIDENCE" api_report_sha256)"
API_PROVENANCE_KIND="$(printf '%s' "$EVIDENCE" | python3 -c '
import json, sys
value = json.load(sys.stdin).get("api_report_provenance")
if value is None or value == "":
    print("absent")
elif isinstance(value, str):
    print("path")
elif isinstance(value, dict):
    print("inline")
else:
    print("invalid")
')"
DEFAULT_PROVENANCE="$EVIDENCE_DIR/api-completeness.json.provenance.json"

PROVENANCE=""
PROVENANCE_PATH=""
PROV_PARSE_FAILED=false
DECLARED=false
if [[ -n "$API_REPORT" || -n "$API_REPORT_SHA" ]]; then
  DECLARED=true
fi
if [[ "$API_PROVENANCE_KIND" == "path" ]]; then
  DECLARED=true
  API_PROVENANCE="$(json_field "$EVIDENCE" api_report_provenance)"
  if [[ -n "$API_PROVENANCE" ]]; then
    PROVENANCE_PATH="$EVIDENCE_DIR/$API_PROVENANCE"
  fi
elif [[ "$API_PROVENANCE_KIND" == "inline" ]]; then
  DECLARED=true
  PROVENANCE="$(printf '%s' "$EVIDENCE" | python3 -c '
import json, sys
print(json.dumps(json.load(sys.stdin)["api_report_provenance"], sort_keys=True, separators=(",", ":")))
')"
elif [[ "$API_PROVENANCE_KIND" == "invalid" ]]; then
  DECLARED=true
  PROV_PARSE_FAILED=true
  fail "evidence api_report_provenance must be a path string or an inline object"
  FAIL=$((FAIL + 1))
fi
if [[ "$API_PROVENANCE_KIND" == "absent" && -z "$PROVENANCE" && -z "$PROVENANCE_PATH" && -f "$DEFAULT_PROVENANCE" ]]; then
  PROVENANCE_PATH="$DEFAULT_PROVENANCE"
  DECLARED=true
fi

if [[ "$DECLARED" == false ]]; then
  info "  (no api-report provenance present — commit-bound report check skipped)"
else
  if [[ -z "$PROVENANCE" && -n "$PROVENANCE_PATH" && -f "$PROVENANCE_PATH" ]]; then
    if ! PROVENANCE="$(python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.dumps(json.load(f)))
except Exception as e:
    print("INVALID:" + str(e), file=sys.stderr)
    sys.exit(1)
' "$PROVENANCE_PATH")"; then
      fail "api-report provenance is not valid JSON: $PROVENANCE_PATH"
      FAIL=$((FAIL + 1))
      PROV_PARSE_FAILED=true
    else
      info "  ✅ api-report provenance parses as JSON ($PROVENANCE_PATH)"
      PASS=$((PASS + 1))
    fi
  elif [[ -z "$PROVENANCE" && -n "$PROVENANCE_PATH" ]]; then
    fail "api-report provenance file not found: $PROVENANCE_PATH"
    FAIL=$((FAIL + 1))
    PROV_PARSE_FAILED=true
  elif [[ -z "$PROVENANCE" && "$PROV_PARSE_FAILED" == false ]]; then
    fail "evidence declares api-report fields but no provenance sidecar exists"
    fail "  expected $DEFAULT_PROVENANCE or an api_report_provenance path/inline object"
    FAIL=$((FAIL + 1))
    PROV_PARSE_FAILED=true
  elif [[ -n "$PROVENANCE" ]]; then
    info "  ✅ api-report provenance is inline in the evidence"
    PASS=$((PASS + 1))
  fi

  if [[ -n "$PROVENANCE" ]]; then
    if [[ "$API_PROVENANCE_KIND" == "inline" ]]; then
      API_PROV_SHA="$(json_field "$EVIDENCE" api_report_provenance_sha256)"
      if [[ -n "$API_PROV_SHA" ]]; then
        ACTUAL_PROV_SHA="$(printf '%s' "$PROVENANCE" | python3 -c '
import hashlib, sys
print(hashlib.sha256(sys.stdin.buffer.read().strip()).hexdigest())
')"
        if [[ "$ACTUAL_PROV_SHA" == "$API_PROV_SHA" ]]; then
          info "  ✅ api-report inline provenance sha256 matches api_report_provenance_sha256"
          PASS=$((PASS + 1))
        else
          fail "api-report inline provenance sha256 mismatch: evidence records $API_PROV_SHA, recomputation yields $ACTUAL_PROV_SHA"
          FAIL=$((FAIL + 1))
        fi
      fi
    fi

    PROV_COMMIT="$(json_field "$PROVENANCE" commit)"
    if [[ "$PROV_COMMIT" == "$HEAD_COMMIT" ]]; then
      info "  ✅ api-report provenance commit matches HEAD ($HEAD_COMMIT)"
      PASS=$((PASS + 1))
    else
      fail "api-report provenance commit ($PROV_COMMIT) does not match git rev-parse HEAD ($HEAD_COMMIT) — the report was not produced from this commit"
      FAIL=$((FAIL + 1))
    fi

    PROV_TREE="$(json_field "$PROVENANCE" tree)"
    if [[ -n "$PROV_TREE" ]]; then
      if [[ "$PROV_TREE" == "$HEAD_TREE" ]]; then
        info "  ✅ api-report provenance tree matches HEAD tree ($HEAD_TREE)"
        PASS=$((PASS + 1))
      else
        fail "api-report provenance tree ($PROV_TREE) does not match HEAD tree ($HEAD_TREE)"
        FAIL=$((FAIL + 1))
      fi
    fi

    PROV_REPORT_NAME="$(json_field "$PROVENANCE" report)"
    if [[ -n "$API_REPORT" ]]; then
      REPORT_PATH="$EVIDENCE_DIR/$API_REPORT"
    elif [[ -n "$PROV_REPORT_NAME" ]]; then
      REPORT_PATH="$EVIDENCE_DIR/$(basename "$PROV_REPORT_NAME")"
    else
      REPORT_PATH="$EVIDENCE_DIR/api-completeness.json"
    fi

    if [[ ! -f "$REPORT_PATH" ]]; then
      fail "api report not found: $REPORT_PATH (referenced by the provenance sidecar)"
      FAIL=$((FAIL + 1))
    else
      ACTUAL_REPORT_SHA="$(sha256_of "$REPORT_PATH")"
      PROV_REPORT_SHA="$(json_field "$PROVENANCE" report_sha256)"
      if [[ -n "$PROV_REPORT_SHA" && "$PROV_REPORT_SHA" == "$ACTUAL_REPORT_SHA" ]]; then
        info "  ✅ api-report provenance report_sha256 matches the report bytes"
        PASS=$((PASS + 1))
      else
        fail "api report sha256 mismatch: provenance records ${PROV_REPORT_SHA:-<missing>}, $REPORT_PATH yields $ACTUAL_REPORT_SHA"
        FAIL=$((FAIL + 1))
      fi

      if [[ -n "$API_REPORT_SHA" && "$API_REPORT_SHA" != "$ACTUAL_REPORT_SHA" ]]; then
        fail "evidence api_report_sha256 ($API_REPORT_SHA) does not match $REPORT_PATH ($ACTUAL_REPORT_SHA)"
        FAIL=$((FAIL + 1))
      fi

      PROV_CANONICAL_SHA="$(json_field "$PROVENANCE" canonical_report_sha256)"
      if [[ -n "$PROV_CANONICAL_SHA" ]]; then
        if ACTUAL_CANONICAL_SHA="$(python3 "$CANONICALIZER" "$REPORT_PATH" 2>/dev/null)"; then
          if [[ "$ACTUAL_CANONICAL_SHA" == "$PROV_CANONICAL_SHA" ]]; then
            info "  ✅ api-report canonical sha reproduces (volatile 'generated_at' excluded)"
            PASS=$((PASS + 1))
          else
            fail "api-report canonical sha mismatch: provenance records $PROV_CANONICAL_SHA, recomputation yields $ACTUAL_CANONICAL_SHA"
            FAIL=$((FAIL + 1))
          fi
        else
          fail "cannot canonicalize api report at $REPORT_PATH"
          FAIL=$((FAIL + 1))
        fi
      fi
    fi

    PROV_REPRODUCIBLE="$(printf '%s' "$PROVENANCE" | python3 -c '
import json, sys
print(json.load(sys.stdin).get("determinism", {}).get("reproducible", ""))
')"
    if [[ "$PROV_REPRODUCIBLE" == "True" ]]; then
      info "  ✅ api-report determinism: reproducible over 2 runs"
      PASS=$((PASS + 1))
    else
      fail "api-report provenance does not attest reproducibility (determinism.reproducible=$PROV_REPRODUCIBLE)"
      FAIL=$((FAIL + 1))
    fi
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
