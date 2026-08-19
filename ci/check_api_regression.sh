#!/usr/bin/env bash
# API regression gate.
#
# Compares a freshly generated api-completeness.json registry against the
# committed baseline (ci/api-baseline.json) and FAILS on any compatibility
# regression:
#
#   - a new Stub implementation (an API that was not a Stub became one)
#   - a new Unsupported implementation (an API that was not Unsupported
#     became one)
#   - an Implemented -> Partial downgrade
#   - a loss of semantic coverage (Differential/Unit -> None or weaker)
#   - a new API ambiguity (duplicate (DLL, export) keys in the registry)
#
# Reviewed baseline updates are allowed: regenerate the baseline with
# `cargo run --bin casa1-oracle -- api-report --gate none --out ci/api-baseline.json`
# and commit it together with the intentional change.
#
# Usage: ci/check_api_regression.sh <new-report.json> [baseline.json]
set -euo pipefail

NEW_REPORT="${1:?usage: check_api_regression.sh <new-report.json> [baseline.json]}"
BASELINE="${2:-ci/api-baseline.json}"

python3 - "$NEW_REPORT" "$BASELINE" <<'PYEOF'
import json
import sys

LEVEL_RANK = {"Unsupported": 0, "Stub": 1, "Partial": 2, "Implemented": 3}
COVERAGE_RANK = {"None": 0, "Unit": 1, "SubsystemScenario": 2, "Differential": 3, "Conformance": 4}

def load_registry(path):
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    rows = report.get("registry")
    if rows is None:
        print(f"::error::registry missing from {path} (report shape changed?)")
        sys.exit(1)
    registry = {}
    for row in rows:
        key = f"{row['dll'].lower()}!{row['export'].lower()}"
        if key in registry:
            print(f"::error::API ambiguity: duplicate registry key {key} in {path}")
            sys.exit(1)
        registry[key] = row
    return registry

new_path, baseline_path = sys.argv[1], sys.argv[2]
new = load_registry(new_path)
baseline = load_registry(baseline_path)

failures = []

for key, row in new.items():
    impl = row["implementation"]
    coverage = row["semantic_test_coverage"]
    old = baseline.get(key)
    if old is None:
        # Newly registered API: only a Stub/Unsupported entry is a regression.
        if impl in ("Stub", "Unsupported"):
            failures.append(
                f"new {impl} API: {key} (was not present in the baseline)"
            )
        continue
    old_impl = old["implementation"]
    old_coverage = old["semantic_test_coverage"]
    if impl in ("Stub", "Unsupported") and old_impl not in ("Stub", "Unsupported"):
        failures.append(f"new {impl}: {key} (was {old_impl})")
    elif old_impl == "Implemented" and impl == "Partial":
        failures.append(f"Implemented -> Partial downgrade: {key}")
    elif impl == "Partial" and old_impl == "Implemented":
        failures.append(f"Implemented -> Partial downgrade: {key}")
    if COVERAGE_RANK.get(coverage, 0) < COVERAGE_RANK.get(old_coverage, 0):
        failures.append(
            f"semantic coverage loss: {key} ({old_coverage} -> {coverage})"
        )

if failures:
    print(f"::error::API regression: {len(failures)} regression(s) against {baseline_path}")
    for failure in sorted(failures):
        print(f"  - {failure}")
    print("If the change is intentional, regenerate the baseline with:")
    print("  cargo run --bin casa1-oracle -- api-report --gate none --out ci/api-baseline.json")
    sys.exit(1)

print(
    f"api-regression: OK — {len(new)} registry entries checked against "
    f"{baseline_path} ({len(baseline)} baseline entries), no regressions"
)
PYEOF
