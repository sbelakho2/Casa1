#!/usr/bin/env bash
# The one central gate: formatting, build, and adversarial tests only.
# Only affected code is tested; changed executable lines must be 100% covered.
#
# The compiled-test manifest is built here (not inside a lib test) so every
# declared conformance/scenario evidence suite/function (and every
# oracle-advertised differential category) is proven against actually compiled
# test targets. An unbound declaration fails the gate. The manifest is written
# to ci/test-manifest.json and uploaded by CI for release provenance.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 ci/test_classification.py --check
cargo fmt --all -- --check
cargo build --features vulkan,opengl,websocket
python3 ci/evidence_manifest.py --write ci/test-manifest.json
python3 ci/run_tests.py --lib --affected --coverage
python3 ci/run_tests.py --tests-only --affected
