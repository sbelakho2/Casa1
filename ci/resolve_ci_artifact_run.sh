#!/usr/bin/env bash
# ci/resolve_ci_artifact_run.sh — resolve the ci.yml run that owns a given artifact.
#
# The release pipeline needs the commit-bound api-completeness-<sha> artifact
# produced by the CI workflow for the same commit. GitHub only lets
# actions/download-artifact@v4 fetch another run's artifacts when the run id is
# pinned, so this script resolves that id via the GitHub API (through the gh
# CLI) and verifies the artifact actually exists in the run.
#
# Usage:
#   GITHUB_SHA=<sha> GITHUB_REPOSITORY=<owner/repo> GH_TOKEN=<token> \
#     ci/resolve_ci_artifact_run.sh <artifact-name>
#
# stdout: key=value lines suitable for $GITHUB_OUTPUT
#     run_id=<id>
#     run_url=<url>
#     artifact_id=<id>
# All diagnostics go to stderr; the script exits non-zero (fail closed) when no
# ci.yml run for the exact SHA contains the artifact.
#
# Environment:
#   GH_TOKEN (or an authenticated gh)  required for the API calls
#   GITHUB_SHA                         commit whose runs are searched
#   GITHUB_REPOSITORY                  owner/repo
#   CASA1_CI_WORKFLOW                  workflow file to search (default: ci.yml)

set -euo pipefail

usage() {
  echo "usage: ci/resolve_ci_artifact_run.sh <artifact-name>" >&2
}

fail() { echo "!! $*" >&2; }

ARTIFACT="${1:-}"
[[ -n "$ARTIFACT" ]] || { usage; exit 2; }
[[ $# -eq 1 ]] || { fail "unexpected extra arguments"; usage; exit 2; }

: "${GITHUB_SHA:?GITHUB_SHA must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"
WORKFLOW="${CASA1_CI_WORKFLOW:-ci.yml}"

for tool in gh python3; do
  command -v "$tool" >/dev/null 2>&1 || { fail "required tool not found on PATH: $tool"; exit 1; }
done

if ! RUNS_JSON="$(gh run list --workflow="$WORKFLOW" --commit "$GITHUB_SHA" --limit 10 \
  --json databaseId,headSha,status,conclusion,url 2>/dev/null)"; then
  fail "gh run list failed for $WORKFLOW @ $GITHUB_SHA (check GH_TOKEN and actions: read permission)"
  exit 1
fi

RESOLVED="$(RUNS_JSON="$RUNS_JSON" ARTIFACT="$ARTIFACT" GITHUB_SHA="$GITHUB_SHA" \
  GITHUB_REPOSITORY="$GITHUB_REPOSITORY" python3 - <<'PY'
import json
import os
import subprocess

runs = json.loads(os.environ["RUNS_JSON"])
artifact = os.environ["ARTIFACT"]
sha = os.environ["GITHUB_SHA"]
repo = os.environ["GITHUB_REPOSITORY"]

for run in runs:
    if run.get("headSha") != sha:
        continue
    run_id = run["databaseId"]
    proc = subprocess.run(
        ["gh", "api", f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        continue
    for art in json.loads(proc.stdout).get("artifacts", []):
        if art.get("name") == artifact:
            print(json.dumps({
                "run_id": run_id,
                "run_url": run.get("url", ""),
                "artifact_id": art.get("id"),
                "run_status": run.get("status", ""),
                "run_conclusion": run.get("conclusion", ""),
            }))
            raise SystemExit(0)
raise SystemExit(0)
PY
)"

if [[ -z "$RESOLVED" ]]; then
  fail "no $WORKFLOW run for commit $GITHUB_SHA contains artifact '$ARTIFACT'"
  fail "The release path fails closed: CI must have produced the commit-bound"
  fail "api-completeness artifact for this exact SHA (run missing, still running,"
  fail "artifact expired, or its upload failed)."
  exit 1
fi

RUN_ID="$(printf '%s' "$RESOLVED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')"
RUN_URL="$(printf '%s' "$RESOLVED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_url"])')"
ARTIFACT_ID="$(printf '%s' "$RESOLVED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["artifact_id"])')"
RUN_STATUS="$(printf '%s' "$RESOLVED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_status"])')"
RUN_CONCLUSION="$(printf '%s' "$RESOLVED" | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_conclusion"])')"

[[ -n "$RUN_ID" && "$RUN_ID" != "None" ]] || { fail "resolved run has no databaseId"; exit 1; }
[[ -n "$ARTIFACT_ID" && "$ARTIFACT_ID" != "None" ]] || { fail "resolved artifact has no id"; exit 1; }

echo ":: notice: $WORKFLOW run $RUN_ID ($RUN_STATUS/$RUN_CONCLUSION) owns $ARTIFACT (artifact $ARTIFACT_ID) for $GITHUB_SHA" >&2

echo "run_id=$RUN_ID"
echo "run_url=$RUN_URL"
echo "artifact_id=$ARTIFACT_ID"
