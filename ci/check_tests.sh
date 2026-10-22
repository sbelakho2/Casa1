#!/usr/bin/env bash
# The one central gate: formatting, build, and adversarial tests only.
# Only affected code is tested; changed executable lines must be 100% covered.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 ci/test_classification.py --check
cargo fmt --all -- --check
cargo build --features vulkan,opengl,websocket
python3 ci/run_tests.py --lib --affected --coverage
python3 ci/run_tests.py --tests-only --affected
