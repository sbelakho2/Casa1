# Release Hardening: Evidence Manifest and Protected-Main Policy

This document covers the machinery added for audit items #233-236 and
#241-245. It is intentionally operational: every rule below is either enforced
by a script in `ci/` or listed in the manual GitHub-settings remainder because
GitHub server state is not repository state.

## 1. Compiled-test evidence manifest

`ci/evidence_manifest.py` is the single source of truth for "is the declared
evidence actually compiled?".

It performs three steps:

1. Reads the `COVERAGE_EVIDENCE` registry in `src/api_coverage.rs` and groups
   the declared ids into:
   - `casa1-conformance:<suite>` / `casa1-scenario:<suite>` — a test target
     (`tests/<suite>.rs`) or a test function that must be present in a
     compiled test executable and runnable;
   - `windows-oracle:<category>` — a differential category the oracle
     advertises must be in `src/windows_oracle.rs::ALL_CATEGORIES`, have a
     real executor in `windows_reference/src/win32.rs`, and be mandatory in
     `.github/workflows/windows-oracle.yml --required-categories`.
     Categories that the oracle does not advertise at all are recorded in
     `deferred_differential` with a concrete reason and reported as
     `::warning::`: they are an API-database declaration defect (fix
     `src/api_coverage.rs` or implement the category), not something a
     compiled-test manifest can bind. The oracle's own
     `--required-categories` list is always enforced strictly.
2. Compiles the real test targets with
   `cargo test --no-run --lib --bins --tests --features
   vulkan,opengl,websocket --message-format=json`, then asks every compiled
   test executable for `--list` and `--list --ignored`. Tests are never
   executed, so cargo-invoking meta tests are not run. Meta tests and ignored
   tests are never accepted as evidence.
3. Writes a deterministic manifest with:
   - `commit` and `tree`;
   - `declared` ids;
   - sorted targets (`name`, `kind`, `src_path`, `tests`, `ignored`);
   - `bindings` for every declared id;
   - `unbound` entries with a concrete reason;
   - `manifest_sha256`, the canonical hash over the fields above (volatile
     toolchain/host data is excluded, so the same source produces the same
     hash on every runner).

Commands:

```bash
# Central gate (also invoked by ci/check_tests.sh):
python3 ci/evidence_manifest.py --write ci/test-manifest.json

# Verify an existing artifact without compiling: self-hash, current source
# declarations, bindings, ignored/meta exclusions, and HEAD/tree.
python3 ci/evidence_manifest.py \
  --verify ci/test-manifest.json --require-head

# The canonical hash folded into release provenance:
python3 ci/evidence_manifest.py \
  --print-digest ci/test-manifest.json --require-head
```

The gate exits non-zero when any bindable declared suite/function or
oracle-advertised differential category is unbound. It is not possible to
"pass" by deleting the artifact or by declaring an evidence id that only
exists in a comment or a test that is ignored, cargo-invoking, or absent from
the compiled targets. `ci/evidence_manifest.py --targets-json <file>` exists
only as a test seam; CI always compiles.

### Wiring

- `ci/check_tests.sh` builds the manifest after the build and before the
  affected adversarial tests. `ci/test-manifest.json` is a generated artifact:
  regenerate it per commit and do not commit it (it embeds the commit/tree and
  the compiled target list).
- `.kiwi/pipeline.yaml` runs the same manifest step.
- `.github/workflows/ci.yml` uploads `test-manifest-<sha>` from the `test`
  job (even on failure, so the failure is diagnosable).
- `.github/workflows/release.yml` downloads that artifact from the same CI run
  that owns `api-completeness-<sha>` and passes it to
  `ci/fold_api_report_provenance.py`.
- `ci/check_release_gate.sh` requires:
  - `test_manifest`, `test_manifest_sha256`,
    `test_manifest_canonical_sha256` in `release-evidence.json`;
  - the manifest file next to the evidence;
  - a byte-hash and canonical-hash match;
  - `evidence_manifest.py --verify --require-head` to pass, including
    re-reading the declarations from the checked-out source and rejecting
    any stale/unbound conformance or scenario suite/function.
- `ci/api_report_provenance.sh` also accepts `--test-manifest` (or
  `CASA1_TEST_MANIFEST`) and records the same byte/canonical hashes in its
  sidecar when a manifest is available.

The release evidence therefore carries the manifest hash, and the release
gate cannot be satisfied with a stale manifest from another commit or a
manifest that omits a declared suite. Differential categories the oracle does
not implement are surfaced as explicit warnings in every manifest run and in
`--print-manual`-style release output; they do not silently pass as bound
evidence.

## 2. CI and release policy check

`ci/check_release_policy.py` reads `ci/release-policy.json` and verifies the
in-repo part of the protected-main/release policy:

- every required CI/release job still exists;
- the aggregate `CI Gate` and `Release Gate` jobs run with `if: always()` and
  need every required job;
- the required status contexts for `main` (`CI Gate`, `Windows Oracle`) are
  real job names, and the Windows oracle aggregate needs all three stages;
- the Windows oracle reference build command and required categories are
  present, and `CharUpperW`/`snprintf` are statically linked through
  `user32`/`legacy_stdio_definitions` (the `__imp_*` link fix);
- the dev API gate is named for completeness + regression and runs
  `api-report --gate completeness` plus the regression comparison;
- the release gate runs the completeness gate;
- the manifest is produced, uploaded, folded, and verified;
- nightly installs FFmpeg with a usable `PKG_CONFIG_PATH`, invokes UBSAN
  through `ci/run_nightly_ubsan_if_supported.sh`, skips cargo-invoking meta
  tests, and never requests the nonexistent `metal` feature;
- no workflow contains force-push, forced-delete, branch-delete,
  hard-reset, or hook-skipping commands.

Run it locally:

```bash
python3 ci/check_release_policy.py --root .
python3 ci/check_release_policy.py --root . --print-manual
```

`policy-check` is a CI job and `CI Gate` needs it. `Release Gate` runs the
same check. A cosmetic rename or deletion of a gate job therefore fails CI;
the names and the commands are both checked.

## 3. Nightly guarantees

- **All-features / FFmpeg**: `all-features-test` installs Homebrew FFmpeg and
  exports `PKG_CONFIG_PATH=$(brew --prefix)/lib/pkgconfig` before
  `cargo test --all-features`, then prints the discovered `libavcodec`
  version so a missing/incompatible system library is visible in the log.
- **UBSAN**: `ci/run_nightly_ubsan_if_supported.sh` requires the nightly
  toolchain and the `rust-src` component (needed by `-Zbuild-std`), probes
  `-Zsanitizer=undefined`, and runs lib + bin + integration test targets with
  `RUSTFLAGS='-Zsanitizer=undefined' cargo +nightly test -Zbuild-std
  --target <host> --lib --bins --tests`. It passes `--skip` for every name in
  `ci/meta-tests.txt`, so no cargo-invoking meta test runs inside the lib test
  harness. Unsupported sanitizer environments are reported explicitly; a
  supported environment that fails fails the job.
- **No `metal` feature**: Metal is unconditional; `--features metal` is
  forbidden by the policy check in `.github/workflows/*.yml`,
  `.kiwi/*.yaml`, and `ci/*.sh`.
- **Job naming**: the dev job is
  `API Completeness and Coverage Regression Gate`; the release job executes
  `api-report --gate completeness`. The policy check requires both the names
  and the commands, not just one or the other.

## 4. Manual GitHub settings (not representable in the repository)

Repository code cannot create branch protection, tag protection, or
environment reviewers. An administrator must apply the following and verify
them with the GitHub API. The in-repo policy check guarantees that the jobs
and status contexts referenced below keep existing with the right semantics.

### Branch protection for `main`

Required status check: **CI Gate** (the aggregate job). Use strict/up-to-date
checks, enforce for administrators, require at least one approving review,
dismiss stale reviews, and disable force pushes and deletions.

```bash
gh api --method PUT repos/:owner/:repo/branches/main/protection \
  -F required_status_checks[strict]=true \
  -f 'required_status_checks[contexts][]=CI Gate' \
  -F enforce_admins=true \
  -F required_pull_request_reviews[dismiss_stale_reviews]=true \
  -F required_pull_request_reviews[required_approving_review_count]=1 \
  -F restrictions=null \
  -F allow_force_pushes=false \
  -F allow_deletions=false
```

Verify:

```bash
gh api repos/:owner/:repo/branches/main/protection
```

Expected: `required_status_checks.contexts` contains exactly `CI Gate`,
`enforce_admins.enabled` is `true`, `allow_force_pushes.enabled` is `false`,
and `allow_deletions.enabled` is `false`.

### Tags and environments

- Protect `v*` release tags from update/deletion with GitHub tag protection
  rules (this is server-side and is not expressible in this repository).
- Protect the self-hosted release environment with required reviewers. The
  release workflow is `workflow_dispatch` only; `Release Gate` aggregates the
  signed build, Steam E2E, smoke, entitlements, evidence, and policy checks.
- Keep `GITHUB_TOKEN` read-only by default and require approval for first-time
  contributors in `Actions > General`.

### What remains manual

The policy manifest records the intended values, but only these server-side
actions can apply them:

1. Branch protection rule for `main` (required check `CI Gate`, strict,
   admins enforced, one approval, stale-review dismissal).
2. Force-push and branch-deletion disabled for `main`.
3. Tag protection for `v*`.
4. Release environment reviewers and default token permissions.

Everything else — job existence, aggregate gating, completeness/regression
semantics, manifest generation/upload/folding/verification, nightly FFmpeg
and UBSAN invocation, absence of a `metal` feature, and absence of destructive
git commands in workflows — is enforced from this repository by
`ci/check_release_policy.py` and `ci/check_tests.sh`.

## 5. Failure recovery

- **Unbound conformance suite**: add/restore the test target or test function,
  or remove/downgrade the declaration in `src/api_coverage.rs` (owned by the
  classification/evidence owner). Re-run
  `python3 ci/evidence_manifest.py --write ci/test-manifest.json`.
- **Unbound/deferred differential category**: implement the category in
  `src/windows_oracle.rs` and `windows_reference/src/win32.rs`, add it to the
  capture workflow's `--required-categories`, or downgrade the declaration in
  `src/api_coverage.rs`. A category the oracle advertises but the reference
  executor or required-category list omits fails the manifest; a category the
  oracle does not advertise is reported as a warning and must be fixed at the
  declaration site.
- **Release gate manifest failure**: the artifact is stale, from another
  commit, unbound, or not the one the CI test job produced. Re-run the CI
  test job for the exact release SHA and re-run the release workflow.
- **Policy failure**: update `ci/release-policy.json` only together with an
  intentional, reviewed workflow change; do not delete a required job or
  weaken a gate to make the check pass.
