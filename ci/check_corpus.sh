#!/usr/bin/env bash
# Real-application corpus job: inventory a PE corpus and run it through Casa1.
#
# Required:
#   CASA1_CORPUS_DIR   directory tree containing real Windows .exe/.dll titles
# Optional:
#   CASA1_CORPUS_TIMEOUT_MS  per-title timeout (default 30000)
#   CASA1_CORPUS_RUNNER      explicit casa1-runner path
#
# The script proves both tools are deterministic and that a second corpus run is
# resume-safe (unchanged titles are skipped, not re-executed).
set -euo pipefail
cd "$(dirname "$0")/.."

: "${CASA1_CORPUS_DIR:?CASA1_CORPUS_DIR must point at a real Windows PE corpus}"
if [ ! -d "$CASA1_CORPUS_DIR" ]; then
  echo "check_corpus: not a directory: $CASA1_CORPUS_DIR" >&2
  exit 1
fi

timeout_ms="${CASA1_CORPUS_TIMEOUT_MS:-30000}"
runner="${CASA1_CORPUS_RUNNER:-$PWD/target/debug/casa1-runner}"
artifacts="$(mktemp -d "${TMPDIR:-/tmp}/casa1-corpus-job.XXXXXX")"
trap 'rm -rf "$artifacts"' EXIT

oracle="$PWD/target/debug/casa1-oracle"

cargo build --quiet --bin casa1-oracle --bin casa1-runner

"$oracle" inventory \
  --pe-dir "$CASA1_CORPUS_DIR" \
  --out "$artifacts/inventory-1.json"
"$oracle" inventory \
  --pe-dir "$CASA1_CORPUS_DIR" \
  --out "$artifacts/inventory-2.json"
cmp "$artifacts/inventory-1.json" "$artifacts/inventory-2.json"
echo "check_corpus: inventory is deterministic"

"$oracle" corpus \
  --corpus "$CASA1_CORPUS_DIR" \
  --out "$artifacts/corpus-1.json" \
  --timeout-ms "$timeout_ms" \
  --work-dir "$artifacts/work" \
  --runner "$runner" \
  --human
cp "$artifacts/corpus-1.json" "$artifacts/corpus-first.json"
"$oracle" corpus \
  --corpus "$CASA1_CORPUS_DIR" \
  --out "$artifacts/corpus-1.json" \
  --timeout-ms "$timeout_ms" \
  --work-dir "$artifacts/work" \
  --runner "$runner" \
  --human

python3 - "$artifacts/corpus-1.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
if report["summary"]["executed"] != 0:
    raise SystemExit(
        f"check_corpus: resume-safe run re-executed {report['summary']['executed']} title(s)"
    )
if report["summary"]["skipped_unchanged"] != report["discovered_title_count"]:
    raise SystemExit("check_corpus: resume-safe run did not skip every unchanged title")
for title in report["titles"]:
    if title["execution"] != "skipped_unchanged":
        raise SystemExit(f"check_corpus: {title['path']} was not skipped")
    if not title["outcome_hash"]:
        raise SystemExit(f"check_corpus: {title['path']} has no outcome hash")
print(
    "check_corpus: resume-safe corpus run skipped "
    f"{report['summary']['skipped_unchanged']} unchanged title(s)"
)
PY

# Force a fresh execution and prove the outcome-defining fields (not timing
# or RSS) hash identically to the first run.
"$oracle" corpus \
  --corpus "$CASA1_CORPUS_DIR" \
  --out "$artifacts/corpus-3.json" \
  --timeout-ms "$timeout_ms" \
  --work-dir "$artifacts/work" \
  --runner "$runner" \
  --force \
  --human

python3 - "$artifacts/corpus-first.json" "$artifacts/corpus-3.json" <<'PY'
import json
import sys

def outcome_hashes(path):
    report = json.load(open(path, encoding="utf-8"))
    return sorted(
        (title["path"], title["sha256"], title["outcome_hash"])
        for title in report["titles"]
    )

first = outcome_hashes(sys.argv[1])
second = outcome_hashes(sys.argv[2])
if first != second:
    raise SystemExit("check_corpus: forced re-run changed deterministic outcome hashes")
print(f"check_corpus: {len(first)} outcome hash(es) are deterministic across re-runs")
PY
