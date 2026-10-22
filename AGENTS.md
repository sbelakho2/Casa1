# Casa1 contributor/agent rules

## Testing policy

- New tests MUST exercise a failure path, invalid/edge input, boundary condition,
  concurrency/race, resource lifecycle, or adversarial condition.
- Do not add happy-path-only tests: existing happy-path coverage is sufficient,
  and duplicated success-path tests are not accepted.
- Prefer one adversarial test that pins an error code/state transition over
  several success variants.

## Validation policy (compute discipline)

- NEVER call `cargo test` directly. The only sanctioned runner is
  `python3 ci/run_tests.py --module <name>` (module-filtered, adversarial tests
  only). It serializes runs through a lock, so concurrent agents cannot
  duplicate work.
- Only affected code is tested: `--affected` selects tests for the modules your
  change touches (worktree vs `CASA1_BASE_REF`, default `origin/main`). Do not
  run cold modules.
- Every test must pin its exact expected outcome (assert_eq!/assert_ne!/
  assert_matches!, an exact panic message, or an exact error/status). Tests
  without a pinned expectation are classified VAGUE and are never run; the
  expectation map lives in `ci/expectations.json`.
- Happy-path tests are DELETED from the tree: they must not exist in source,
  the suite, or CI. `ci/delete_happy_paths.py` enforces this; never add one.
- Only pinned adversarial tests execute. Vague tests, meta tests that invoke
  cargo, and conformance evidence anchors stay out of the gate; anchors remain
  compiled only because the API gate binds to them.
- Coverage must be 100% for every changed executable line. The gate fails when
  an affected line is uncovered (`ci/coverage_gate.py`, lcov from
  `cargo-llvm-cov`/llvm instrumentation).
- The central gate (one per wave, run by the integrator) is
  `bash ci/check_tests.sh`: fmt check, build, affected adversarial lib tests
  with coverage, then affected adversarial integration tests.
- CI is Kiwi-CI: `.kiwi/pipeline.yaml`, run with `kiwi run`; do not introduce
  per-agent CI runs.
- Compilation checks use `cargo check --lib`; do not run full library or
  section suites per change.
- Use targeted `rg`/`rustfmt --check` instead of rebuilding to answer questions.
- Agents using isolated `CARGO_TARGET_DIR`s must delete them before finishing; the
  runner cleans its coverage directory automatically.

## Editing policy

- Never copy or overwrite a whole file; make targeted in-place edits and re-read
  before re-applying when another writer is active.
- Respect file ownership boundaries given in a task; report cross-file hooks
  instead of editing another owner's files.
- No commits unless explicitly requested by the operator.
