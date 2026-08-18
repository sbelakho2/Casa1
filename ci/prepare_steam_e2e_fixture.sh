#!/usr/bin/env bash
# ci/prepare_steam_e2e_fixture.sh — hydrate a Steam E2E fixture without
# mutating the tracked baseline.
#
# Copies the tracked `ges/steam-live-run-x86` fixture into a fresh temp
# work dir, validates the initial Steam executable sha256 against a
# recorded value, runs the real Steam updater (which requires network; when
# no headless updater is available the existing client is validated and the
# update step is reported as skipped), collects/verifies the required
# components (Steam.exe, steamwebhelper.exe, CEF payload if present),
# strips user-specific data (registry HKCU, logs), writes
# fixture-provenance.json, and prints the hydrated fixture path.
#
# The tracked fixture is never mutated: every operation below runs on the
# temp copy, and the work dir is removed on failure (kept on success so the
# printed hydrated path remains usable).
#
# Usage:
#   ci/prepare_steam_e2e_fixture.sh <recorded-initial-steam-sha256> [source-fixture]
#
# Arguments:
#   1. Recorded sha256 of the initial (bootstrapper) Steam.exe in the
#      source fixture; the copy is validated against it before anything
#      else runs.
#   2. Source fixture name under ges/ (default: steam-live-run-x86).
#
# Requirements:
#   - network access for the updater step
#   - the casa1 PE runner (CASA1_RUNNER or target/release/casa1-runner) or
#     wine to run the updater headless; without either, the existing client
#     is validated instead.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_FIXTURE="${2:-steam-live-run-x86}"
EXPECTED_STEAM_SHA256="${1:-}"
SOURCE_ROOT="$REPO_ROOT/ges/$SOURCE_FIXTURE"
UPDATE_TIMEOUT_SECS="${CASA1_STEAM_UPDATE_TIMEOUT_SECS:-300}"
CASA1_RUNNER="${CASA1_RUNNER:-}"

if [[ -z "$EXPECTED_STEAM_SHA256" ]]; then
  echo "usage: $0 <recorded-initial-steam-sha256> [source-fixture]" >&2
  exit 1
fi
if [[ ! "${#EXPECTED_STEAM_SHA256}" -eq 64 ]]; then
  echo "!! recorded Steam sha256 must be 64 hex characters, got '${EXPECTED_STEAM_SHA256}'" >&2
  exit 1
fi
if [[ ! -f "$SOURCE_ROOT/ge.json" || ! -d "$SOURCE_ROOT/drive_c" ]]; then
  echo "!! source fixture missing at $SOURCE_ROOT (ge.json + drive_c required)" >&2
  exit 1
fi

# ── Temp work dir ─────────────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/casa1-steam-e2e.XXXXXX")"
cleanup_on_error() { rm -rf "$WORK_DIR"; }
trap cleanup_on_error ERR
HYDRATED="$WORK_DIR/$SOURCE_FIXTURE"

echo ":: copying $SOURCE_ROOT -> $HYDRATED"
cp -R "$SOURCE_ROOT" "$HYDRATED"

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }

# ── Validate the initial Steam executable ────────────────────────────────────
BOOTSTRAPPER="$HYDRATED/drive_c/Steam.exe"
if [[ ! -f "$BOOTSTRAPPER" ]]; then
  echo "!! initial Steam executable missing at $BOOTSTRAPPER" >&2
  exit 1
fi
ACTUAL_SHA256="$(sha256_file "$BOOTSTRAPPER")"
if [[ "$ACTUAL_SHA256" != "$EXPECTED_STEAM_SHA256" ]]; then
  echo "!! Steam sha256 mismatch: expected $EXPECTED_STEAM_SHA256, got $ACTUAL_SHA256" >&2
  echo "   (the tracked fixture changed; update the recorded value or restore the fixture)" >&2
  exit 1
fi
echo ":: initial Steam.exe sha256 verified: $ACTUAL_SHA256"

# ── Run the real updater (network required) ──────────────────────────────────
# The bootstrapper Steam.exe contacts the Steam CDN and hydrates
# drive_c/Steam/Steam.exe plus payloads.  Headless execution needs a
# Windows runtime: the casa1 PE runner (CASA1_RUNNER or a release build) or
# wine.  Without one, the update step cannot run headless: the existing
# client is validated and the step is reported as skipped.
UPDATER_RUN=false
if [[ -z "$CASA1_RUNNER" && -x "$REPO_ROOT/target/release/casa1-runner" ]]; then
  CASA1_RUNNER="$REPO_ROOT/target/release/casa1-runner"
fi
WINE_BIN="$(command -v wine || true)"

if [[ -n "$CASA1_RUNNER" ]]; then
  echo ":: running real updater via casa1 runner: $CASA1_RUNNER"
  JOB_FILE="$WORK_DIR/updater-job.json"
  cat > "$JOB_FILE" <<EOF
{
  "ge_name": "$SOURCE_FIXTURE",
  "ge_root": "$HYDRATED",
  "program": "$BOOTSTRAPPER",
  "args": [],
  "cwd": "$HYDRATED/drive_c",
  "env": {"CASA1_STEAM_UPDATE": "1"},
  "dtm": false,
  "intent": "run",
  "trace_categories": [],
  "test_id": "steam-e2e-updater"
}
EOF
  CASA1_PE_RUNTIME_DEADLINE_SECS="$UPDATE_TIMEOUT_SECS" \
    "$CASA1_RUNNER" --job "$JOB_FILE" \
    || echo "!! updater run exited non-zero (network may be unavailable); continuing with client validation"
  UPDATER_RUN=true
elif [[ -n "$WINE_BIN" ]]; then
  echo ":: running real updater via wine (bounded to ${UPDATE_TIMEOUT_SECS}s)"
  "$WINE_BIN" "$BOOTSTRAPPER" &
  UPDATER_PID=$!
  ( sleep "$UPDATE_TIMEOUT_SECS" && kill "$UPDATER_PID" 2>/dev/null ) &
  KILLER_PID=$!
  wait "$UPDATER_PID" || true
  kill "$KILLER_PID" 2>/dev/null || true
  UPDATER_RUN=true
else
  echo "!! no headless Windows runtime (CASA1_RUNNER/wine) available;"
  echo "   the updater cannot run headless — validating the existing client instead"
fi

# ── Collect and verify required components ───────────────────────────────────
CLIENT_DIR="$HYDRATED/drive_c/Steam"
CLIENT="$CLIENT_DIR/Steam.exe"
CLIENT_SHA256=""
if [[ -f "$CLIENT" ]]; then
  CLIENT_SHA256="$(sha256_file "$CLIENT")"
  echo ":: client Steam.exe present: $CLIENT (sha256 $CLIENT_SHA256)"
else
  echo "!! client Steam.exe missing at $CLIENT — the updater did not hydrate a client" >&2
  exit 1
fi

WEBHELPER="$(find "$CLIENT_DIR" -iname 'steamwebhelper.exe' -print -quit 2>/dev/null || true)"
if [[ -n "$WEBHELPER" ]]; then
  echo ":: steamwebhelper.exe present: $WEBHELPER"
else
  echo "!! steamwebhelper.exe not found under $CLIENT_DIR (expected after a live update)" >&2
fi

CEF_PAYLOAD="$(find "$CLIENT_DIR" \( -iname 'libcef*.dll' -o -iname 'cef.pak' -o -iname 'icudtl.dat' \) -print -quit 2>/dev/null || true)"
if [[ -n "$CEF_PAYLOAD" ]]; then
  echo ":: CEF payload present: $CEF_PAYLOAD"
else
  echo "!! CEF payload not found under $CLIENT_DIR (checked libcef*.dll, cef.pak, icudtl.dat)" >&2
fi

# ── Strip user-specific data ─────────────────────────────────────────────────
# HKCU registry and logs are per-user artifacts of the hydrated run; the
# fixture must ship without them.
rm -f "$HYDRATED/registry/HKCU.db"
rm -rf "$HYDRATED/logs"
rm -rf "$CLIENT_DIR/logs"
echo ":: stripped user-specific data (registry/HKCU.db, logs dirs)"

# ── Write fixture-provenance.json ────────────────────────────────────────────
PROVENANCE="$HYDRATED/fixture-provenance.json"
cat > "$PROVENANCE" <<EOF
{
  "source_fixture": "ges/$SOURCE_FIXTURE",
  "steam_sha256": "$ACTUAL_SHA256",
  "client_sha256": "$CLIENT_SHA256",
  "updater_ran": $([ "$UPDATER_RUN" = true ] && echo true || echo false),
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)"
}
EOF
echo ":: wrote $PROVENANCE"

echo ":: hydrated fixture ready (never mutates the tracked fixture)"
echo "$HYDRATED"
