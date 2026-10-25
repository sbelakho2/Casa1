#!/usr/bin/env bash
# ci/api_report_provenance.sh — commit-bound provenance sidecar for api-completeness.json.
#
# The CI api-gate job generates api-completeness.json from the checked-out
# commit. This script makes that evidence commit-bound and reproducible:
#
#   1. Re-runs the report command twice into temporary outputs and compares
#      their CANONICAL forms (report JSON with the volatile `generated_at`
#      field removed; see ci/canonical_api_report.py). Any other difference
#      fails the step.
#   2. Re-checks the supplied report against the re-run output, so the report
#      that gets uploaded is the one the command actually reproduces.
#   3. Writes <report>.provenance.json next to the report with commit SHA,
#      tree hash, rustc/cargo versions, feature set, UTC timestamp, report
#      hashes, the exact command, and the determinism verdict.
#   4. When --test-manifest is supplied, verifies the compiled-test manifest
#      and records its byte hash + canonical digest in the same sidecar, so
#      the provenance hash covers the evidence manifest too.
#
# Usage:
#   ci/api_report_provenance.sh <report.json> \
#     [--command '<cmd with {out}>'] [--test-manifest <manifest.json>]
#
# Optional --command must contain the literal {out} placeholder; it is replaced
# with a temporary output path for each reproducibility run. Default:
#   cargo run --bin casa1-oracle -- api-report --gate none --out {out}
#
# CASA1_TEST_MANIFEST is honoured as an environment fallback for
# --test-manifest.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANONICALIZER="$REPO_ROOT/ci/canonical_api_report.py"
DEFAULT_COMMAND="cargo run --bin casa1-oracle -- api-report --gate none --out {out}"

usage() {
  echo "usage: ci/api_report_provenance.sh <report.json> [--command '<cmd with {out}>'] [--test-manifest <manifest.json>]"
}
fail() { echo "!! $*" >&2; }
info() { echo ":: $*"; }
sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

REPORT=""
COMMAND=""
TEST_MANIFEST="${CASA1_TEST_MANIFEST:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --command)
      [[ $# -ge 2 ]] || { fail "--command requires a value"; usage >&2; exit 2; }
      COMMAND="$2"; shift 2 ;;
    --command=*) COMMAND="${1#--command=}"; shift ;;
    --test-manifest)
      [[ $# -ge 2 ]] || { fail "--test-manifest requires a value"; usage >&2; exit 2; }
      TEST_MANIFEST="$2"; shift 2 ;;
    --test-manifest=*) TEST_MANIFEST="${1#--test-manifest=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) fail "unknown option: $1"; usage >&2; exit 2 ;;
    *)
      [[ -z "$REPORT" ]] || { fail "unexpected argument: $1"; usage >&2; exit 2; }
      REPORT="$1"; shift ;;
  esac
done
if [[ -z "$REPORT" && $# -gt 0 ]]; then
  REPORT="$1"; shift
fi
[[ $# -eq 0 ]] || { fail "unexpected argument: $1"; usage >&2; exit 2; }

[[ -n "$REPORT" ]] || { usage >&2; exit 2; }
[[ -f "$REPORT" ]] || { fail "report not found: $REPORT"; exit 1; }
COMMAND="${COMMAND:-$DEFAULT_COMMAND}"
if [[ "$COMMAND" != *"{out}"* ]]; then
  fail "--command must contain the literal {out} placeholder (the report path)"
  exit 2
fi

for tool in python3 rustc cargo git; do
  command -v "$tool" >/dev/null 2>&1 || { fail "required tool not found on PATH: $tool"; exit 1; }
done

COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)" || {
  fail "cannot determine git HEAD in $REPO_ROOT — refusing to write provenance"
  exit 1
}
TREE="$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}' 2>/dev/null)" || {
  fail "cannot determine git tree in $REPO_ROOT — refusing to write provenance"
  exit 1
}
if [[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]]; then
  WORKTREE_CLEAN=true
else
  WORKTREE_CLEAN=false
fi

RUSTC_VERSION="$(rustc --version)"
RUSTC_HOST="$(rustc -vV | awk '/^host:/{print $2}')"
CARGO_VERSION="$(cargo --version)"
TIMESTAMP_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

FEATURES_JSON="$(python3 - "$REPO_ROOT/Cargo.toml" <<'PY'
import json
import sys

try:
    import tomllib

    with open(sys.argv[1], "rb") as handle:
        manifest = tomllib.load(handle)
    features = manifest.get("features", {})
    print(json.dumps({
        "selection": "default features (no --features flag passed)",
        "enabled": sorted(features.get("default", [])),
        "declared": sorted(features.keys()),
    }))
except Exception as exc:  # noqa: BLE001 - provenance must still be written
    print(json.dumps({
        "selection": "default features (no --features flag passed)",
        "enabled": [],
        "declared": [],
        "error": str(exc),
    }))
PY
)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

run_report() {
  local out="$1"
  local log="$2"
  local rendered="${COMMAND//\{out\}/$out}"
  if ! ( cd "$REPO_ROOT" && eval "$rendered" ) >"$log" 2>&1; then
    fail "report command failed: $rendered"
    cat "$log" >&2 || true
    return 1
  fi
  if [[ ! -f "$out" ]]; then
    fail "report command did not write $out: $rendered"
    cat "$log" >&2 || true
    return 1
  fi
}

RUN1="$TMP_DIR/run1.json"
RUN2="$TMP_DIR/run2.json"
info "reproducibility run 1/2: $COMMAND"
run_report "$RUN1" "$TMP_DIR/run1.log"
info "reproducibility run 2/2: $COMMAND"
run_report "$RUN2" "$TMP_DIR/run2.log"

CANON1="$TMP_DIR/run1.canonical.json"
CANON2="$TMP_DIR/run2.canonical.json"
CANON_PROVIDED="$TMP_DIR/provided.canonical.json"
python3 "$CANONICALIZER" --json "$RUN1" > "$CANON1" || { fail "cannot canonicalize run 1"; exit 1; }
python3 "$CANONICALIZER" --json "$RUN2" > "$CANON2" || { fail "cannot canonicalize run 2"; exit 1; }
python3 "$CANONICALIZER" --json "$REPORT" > "$CANON_PROVIDED" || { fail "cannot canonicalize report $REPORT"; exit 1; }

CANON1_SHA="$(sha256_of "$CANON1")"
CANON2_SHA="$(sha256_of "$CANON2")"
CANON_PROVIDED_SHA="$(sha256_of "$CANON_PROVIDED")"

if [[ "$CANON1_SHA" != "$CANON2_SHA" ]]; then
  fail "api report is NOT deterministic: two runs of the command differ beyond the volatile 'generated_at' field"
  fail "  run1 canonical sha256: $CANON1_SHA"
  fail "  run2 canonical sha256: $CANON2_SHA"
  fail "  fix the nondeterminism in the report (CI must produce reproducible evidence)"
  exit 1
fi
if [[ "$CANON_PROVIDED_SHA" != "$CANON1_SHA" ]]; then
  fail "api report $REPORT is not reproducible: its canonical form differs from a fresh run"
  fail "  provided canonical sha256: $CANON_PROVIDED_SHA"
  fail "  fresh run canonical sha256: $CANON1_SHA"
  exit 1
fi

REPORT_SHA="$(sha256_of "$REPORT")"
SIDECAR="$REPORT.provenance.json"

TEST_MANIFEST_SHA=""
TEST_MANIFEST_CANONICAL_SHA=""
if [[ -n "$TEST_MANIFEST" ]]; then
  [[ -f "$TEST_MANIFEST" ]] || { fail "test manifest not found: $TEST_MANIFEST"; exit 1; }
  python3 "$REPO_ROOT/ci/evidence_manifest.py" \
    --verify "$TEST_MANIFEST" --require-head --quiet \
    || { fail "test manifest failed verification: $TEST_MANIFEST"; exit 1; }
  TEST_MANIFEST_SHA="$(sha256_of "$TEST_MANIFEST")"
  TEST_MANIFEST_CANONICAL_SHA="$(python3 "$REPO_ROOT/ci/evidence_manifest.py" \
    --print-digest "$TEST_MANIFEST" --require-head)" || {
      fail "cannot compute the canonical test manifest digest: $TEST_MANIFEST"
      exit 1
    }
  info "test manifest: $(basename "$TEST_MANIFEST")"
  info "  sha256:           $TEST_MANIFEST_SHA"
  info "  canonical sha256: $TEST_MANIFEST_CANONICAL_SHA"
fi

export PROV_REPORT="$(basename "$REPORT")"
export PROV_TIMESTAMP_UTC="$TIMESTAMP_UTC"
export PROV_COMMIT="$COMMIT"
export PROV_TREE="$TREE"
export PROV_WORKTREE_CLEAN="$WORKTREE_CLEAN"
export PROV_RUSTC_VERSION="$RUSTC_VERSION"
export PROV_RUSTC_HOST="$RUSTC_HOST"
export PROV_CARGO_VERSION="$CARGO_VERSION"
export PROV_FEATURES_JSON="$FEATURES_JSON"
export PROV_COMMAND="$COMMAND"
export PROV_REPORT_SHA256="$REPORT_SHA"
export PROV_CANON1_SHA="$CANON1_SHA"
export PROV_CANON2_SHA="$CANON2_SHA"
export PROV_CANON_PROVIDED_SHA="$CANON_PROVIDED_SHA"
PROV_TEST_MANIFEST=""
if [[ -n "$TEST_MANIFEST" ]]; then
  PROV_TEST_MANIFEST="$(basename "$TEST_MANIFEST")"
fi
export PROV_TEST_MANIFEST
export PROV_TEST_MANIFEST_SHA="$TEST_MANIFEST_SHA"
export PROV_TEST_MANIFEST_CANONICAL_SHA="$TEST_MANIFEST_CANONICAL_SHA"

python3 - "$SIDECAR" <<'PY'
import json
import os
import sys

sidecar = {
    "schema_version": 1,
    "kind": "casa1-api-report-provenance",
    "report": os.environ["PROV_REPORT"],
    "timestamp_utc": os.environ["PROV_TIMESTAMP_UTC"],
    "commit": os.environ["PROV_COMMIT"],
    "tree": os.environ["PROV_TREE"],
    "git_worktree_clean": os.environ["PROV_WORKTREE_CLEAN"] == "true",
    "rustc_version": os.environ["PROV_RUSTC_VERSION"],
    "rustc_host": os.environ["PROV_RUSTC_HOST"],
    "cargo_version": os.environ["PROV_CARGO_VERSION"],
    "target_triple": os.environ["PROV_RUSTC_HOST"],
    "feature_set": json.loads(os.environ["PROV_FEATURES_JSON"]),
    "command": os.environ["PROV_COMMAND"],
    "report_sha256": os.environ["PROV_REPORT_SHA256"],
    "canonical_report_sha256": os.environ["PROV_CANON_PROVIDED_SHA"],
    "canonicalization": {
        "tool": "ci/canonical_api_report.py",
        "excluded_volatile_fields": ["generated_at"],
        "method": "json parse, drop volatile fields, sort keys, compact separators",
    },
    "determinism": {
        "method": "run-report-command-twice-and-compare-canonical-json",
        "runs": 2,
        "run1_canonical_sha256": os.environ["PROV_CANON1_SHA"],
        "run2_canonical_sha256": os.environ["PROV_CANON2_SHA"],
        "provided_canonical_sha256": os.environ["PROV_CANON_PROVIDED_SHA"],
        "reproducible": True,
    },
}
if os.environ.get("PROV_TEST_MANIFEST"):
    sidecar["test_manifest"] = os.environ["PROV_TEST_MANIFEST"]
    sidecar["test_manifest_sha256"] = os.environ["PROV_TEST_MANIFEST_SHA"]
    sidecar["test_manifest_canonical_sha256"] = os.environ[
        "PROV_TEST_MANIFEST_CANONICAL_SHA"
    ]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(sidecar, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

info "provenance sidecar: $SIDECAR"
info "  commit:  $COMMIT"
info "  tree:    $TREE"
info "  report sha256:            $REPORT_SHA"
info "  canonical report sha256:  $CANON_PROVIDED_SHA"
if [[ -n "$TEST_MANIFEST" ]]; then
  info "  test manifest sha256:     $TEST_MANIFEST_SHA"
  info "  test manifest canonical:  $TEST_MANIFEST_CANONICAL_SHA"
fi
info "  determinism: reproduced over 2 runs (canonical form, 'generated_at' excluded)"
