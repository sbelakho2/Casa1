#!/usr/bin/env bash
# ci/prepare_steam_e2e_fixture.sh — hydrate a Steam E2E fixture without
# mutating the tracked baseline.
#
# Copies the tracked `ges/steam-live-run-x86` fixture into a fresh temp
# work dir, validates the initial Steam executable sha256 against a
# recorded value, runs the real Steam updater (network required; headless
# execution needs the casa1 PE runner or wine), collects/verifies the
# required components (Steam.exe, steamwebhelper.exe, CEF payload),
# strips user-specific data (registry HKCU, logs), writes
# fixture-provenance.json, and prints the hydrated fixture path.
#
# FAIL-CLOSED: any updater failure exits non-zero; UPDATER_RUN=true is
# recorded only when the updater GUEST exited 0 (from the runner's stdout
# outcome JSON — never from the runner's own process exit); a missing
# steamwebhelper.exe or missing CEF resources FAIL the script (no
# warnings-only); the final "ready" message prints only when the updated
# Steam client is present, steamwebhelper.exe is present, CEF resources are
# present, and fixture-provenance.json was written.
#
# The tracked fixture is never mutated: every operation below runs on the
# temp copy, and the work dir is removed on failure (kept on success so the
# printed hydrated path remains usable).
#
# STDOUT CONTRACT: the hydrated fixture path is the ONLY stdout output —
# every progress/info message goes to stderr, so `FIXTURE_ROOT="$(...)"`
# captures exactly the path (the workflow feeds it to CASA1_STEAM_E2E_GE_ROOT).
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
#     wine to run the updater headless, plus python3 to read the runner's
#     guest-exit semantics from its stdout outcome JSON.  Without either,
#     the script fails closed: a hydration that cannot run the real updater
#     cannot claim an updated client.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_FIXTURE="${2:-steam-live-run-x86}"
EXPECTED_STEAM_SHA256="${1:-}"
SOURCE_ROOT="$REPO_ROOT/ges/$SOURCE_FIXTURE"
UPDATE_TIMEOUT_SECS="${CASA1_STEAM_UPDATE_TIMEOUT_SECS:-300}"
CASA1_RUNNER="${CASA1_RUNNER:-}"

# Progress/info messages go to STDERR: stdout carries ONLY the final
# hydrated fixture path (see the STDOUT CONTRACT above).
info() { echo ":: $*" >&2; }

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

info "copying $SOURCE_ROOT -> $HYDRATED"
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
info "initial Steam.exe sha256 verified: $ACTUAL_SHA256"

# ── Run the real updater (network required) ──────────────────────────────────
# The bootstrapper Steam.exe contacts the Steam CDN and hydrates
# drive_c/Steam/Steam.exe plus payloads.  Headless execution needs a
# Windows runtime: the casa1 PE runner (CASA1_RUNNER or a release build) or
# wine.  FAIL-CLOSED: without a runtime, or when the updater GUEST did not
# exit 0, the hydration cannot claim an updated client — the script exits
# non-zero and UPDATER_RUN is never recorded as true.
#
# Honest updater-exit semantics: the casa1 runner's own process exit 0 only
# means the runner produced an outcome (the run may have ended by harness
# deadline or an unsupported instruction without the updater ever exiting).
# The updater exited 0 ONLY when the runner's stdout outcome JSON reports a
# GuestExit with code 0 — `guest_exit_code == 0`.  The runner prints
# nothing but that JSON on stdout.
UPDATER_RUN=false
if [[ -z "$CASA1_RUNNER" && -x "$REPO_ROOT/target/release/casa1-runner" ]]; then
  CASA1_RUNNER="$REPO_ROOT/target/release/casa1-runner"
fi
WINE_BIN="$(command -v wine || true)"

if [[ -n "$CASA1_RUNNER" ]]; then
  info "running real updater via casa1 runner: $CASA1_RUNNER"
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
  # The runner's stdout is the RunnerOutcome JSON (progress goes to stderr).
  if UPDATER_OUTCOME="$(CASA1_PE_RUNTIME_DEADLINE_SECS="$UPDATE_TIMEOUT_SECS" \
      "$CASA1_RUNNER" --job "$JOB_FILE" 2>"$WORK_DIR/updater-runner.stderr")"; then
    :
  else
    UPDATER_RUNNER_STATUS=$?
    echo "!! casa1 runner failed (exit $UPDATER_RUNNER_STATUS) — no updater" >&2
    echo "   outcome was produced; hydration fails closed" >&2
    if [[ -s "$WORK_DIR/updater-runner.stderr" ]]; then
      cat "$WORK_DIR/updater-runner.stderr" >&2
    fi
    exit 1
  fi
  echo "$UPDATER_OUTCOME" > "$WORK_DIR/updater-outcome.json"
  # The updater exited 0 ONLY when the outcome's guest_exit_code is 0 (a
  # GuestExit); any other termination (deadline, unsupported instruction)
  # reports guest_exit_code null and fails the hydration closed.
  if python3 - "$WORK_DIR/updater-outcome.json" <<'PY'
import json, sys
try:
    outcome = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as e:
    sys.stderr.write(f"updater outcome JSON unparseable: {e}\n")
    sys.exit(1)
if outcome.get("guest_exit_code") == 0:
    sys.exit(0)
sys.stderr.write(
    f"updater did not exit 0 (guest_exit_code={outcome.get('guest_exit_code')!r}, "
    f"termination={outcome.get('termination')!r})\n"
)
sys.exit(1)
PY
  then
    UPDATER_RUN=true
    info "updater exited 0 (guest_exit_code 0 from the runner outcome)"
  else
    echo "!! updater did not exit 0 — the Steam client was not updated" >&2
    echo "   (network may be unavailable or the updater failed); hydration fails closed" >&2
    exit 1
  fi
elif [[ -n "$WINE_BIN" ]]; then
  info "running real updater via wine (bounded to ${UPDATE_TIMEOUT_SECS}s)"
  "$WINE_BIN" "$BOOTSTRAPPER" &
  UPDATER_PID=$!
  ( sleep "$UPDATE_TIMEOUT_SECS" && kill "$UPDATER_PID" 2>/dev/null ) &
  KILLER_PID=$!
  if wait "$UPDATER_PID"; then
    UPDATER_RUN=true
    info "wine updater exited 0"
  else
    kill "$KILLER_PID" 2>/dev/null || true
    echo "!! wine updater failed or was killed by the timeout — hydration fails closed" >&2
    exit 1
  fi
  kill "$KILLER_PID" 2>/dev/null || true
else
  echo "!! no headless Windows runtime (CASA1_RUNNER/wine) available — the real" >&2
  echo "   updater cannot run headless.  Hydration fails closed: a fixture that was" >&2
  echo "   not updated by the real Steam updater is not a valid E2E fixture." >&2
  exit 1
fi

# ── Collect and verify required components ───────────────────────────────────
CLIENT_DIR="$HYDRATED/drive_c/Steam"
CLIENT="$CLIENT_DIR/Steam.exe"
CLIENT_SHA256=""
if [[ -f "$CLIENT" ]]; then
  CLIENT_SHA256="$(sha256_file "$CLIENT")"
  info "client Steam.exe present: $CLIENT (sha256 $CLIENT_SHA256)"
else
  echo "!! client Steam.exe missing at $CLIENT — the updater did not hydrate a client" >&2
  exit 1
fi

WEBHELPER="$(find "$CLIENT_DIR" -iname 'steamwebhelper.exe' -print -quit 2>/dev/null || true)"
if [[ -n "$WEBHELPER" ]]; then
  info "steamwebhelper.exe present: $WEBHELPER"
else
  echo "!! steamwebhelper.exe not found under $CLIENT_DIR (required after a live update)" >&2
  exit 1
fi

CEF_PAYLOAD="$(find "$CLIENT_DIR" \( -iname 'libcef*.dll' -o -iname 'cef.pak' -o -iname 'icudtl.dat' \) -print -quit 2>/dev/null || true)"
if [[ -n "$CEF_PAYLOAD" ]]; then
  info "CEF payload present: $CEF_PAYLOAD"
else
  echo "!! CEF payload not found under $CLIENT_DIR (checked libcef*.dll, cef.pak, icudtl.dat)" >&2
  exit 1
fi

# ── Strip user-specific data ─────────────────────────────────────────────────
# HKCU registry and logs are per-user artifacts of the hydrated run; the
# fixture must ship without them.
rm -f "$HYDRATED/registry/HKCU.db"
rm -rf "$HYDRATED/logs"
rm -rf "$CLIENT_DIR/logs"
info "stripped user-specific data (registry/HKCU.db, logs dirs)"

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
info "wrote $PROVENANCE"

# ── Final readiness gate (fail-closed) ───────────────────────────────────────
# The "ready" message prints ONLY when every required component is present
# and the provenance was written.  It goes to STDERR like every other
# message: the hydrated fixture path below is the ONLY stdout output.
READY=1
[[ -f "$CLIENT" ]] || READY=0
[[ -n "$WEBHELPER" ]] || READY=0
[[ -n "$CEF_PAYLOAD" ]] || READY=0
[[ -f "$PROVENANCE" ]] || READY=0
if [[ "$READY" -eq 1 ]]; then
  info "hydrated fixture ready (never mutates the tracked fixture)"
  echo "$HYDRATED"
else
  echo "!! hydration incomplete: client=$([ -f "$CLIENT" ] && echo yes || echo no) \
webhelper=$([ -n "$WEBHELPER" ] && echo yes || echo no) \
cef=$([ -n "$CEF_PAYLOAD" ] && echo yes || echo no) \
provenance=$([ -f "$PROVENANCE" ] && echo yes || echo no)" >&2
  exit 1
fi
