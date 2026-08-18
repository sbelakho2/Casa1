# External Integration Tests

This document describes how to run integration tests that interact with
external services, real hardware, or the live Steam platform.

## Test Isolation Strategy

Casa1's test suite is designed to be fully offline by default. Tests that
contact external services or require special hardware are gated behind
environment variables or marked with `#[ignore]`. This ensures that:

1. `cargo test` works on any machine without network access
2. CI is deterministic and fast
3. Developers can opt into external tests when needed

## Steam E2E Tests

Real Steam end-to-end acceptance tests run the REAL Steam client
(`ges/steam/drive_c/Steam/Steam.exe`) under the Casa1 PE runtime with a
bounded wall-clock deadline, then evaluate the written steam-bootstrap
artifact against the S0-S13 acceptance ladder
([`casa1::steam_acceptance`](../src/steam_acceptance.rs)). These tests
require the `CASA1_STEAM_E2E` environment variable set to `1`:

- Steam client fixture present (`ges/steam/`)
- A live Steam CDN reachable for the network stages
- A bounded deadline (`CASA1_PE_RUNTIME_DEADLINE_SECS`, default 300 s)

### Running Steam E2E Tests

```bash
# The real Steam E2E acceptance test (sections 41 and 23)
CASA1_STEAM_E2E=1 cargo test --release --test section41_steam_e2e -- --ignored --nocapture

# Steam first-divergence diagnostic (same run, prints the divergence report)
CASA1_STEAM_E2E=1 cargo test --release --test section23 -- --ignored --nocapture

# With an explicit deadline override (seconds)
CASA1_STEAM_E2E=1 CASA1_PE_RUNTIME_DEADLINE_SECS=600 \
  cargo test --release --test section41_steam_e2e -- --ignored --nocapture
```

Without `CASA1_STEAM_E2E=1` the tests are skipped with a message, even when
`--ignored` forces them.

### Steam E2E Artifacts

Each run writes `<short-sha>-steam-bootstrap.{json,log}` into
`ges/steam/diagnostics/`. The JSON artifact carries the run provenance
(commit, fixture hashes, Steam executable sha256, execution mode), the
milestone counters, the authoritative termination, and the acceptance
evidence. The nightly `steam-e2e` workflow uploads this directory as
`steam-e2e-<sha>` for every run, including failed ones.

### Steam E2E Fixture Preparation

The tracked fixture never carries user-specific data. To hydrate a
network-updated fixture without mutating the tracked baseline:

```bash
./ci/prepare_steam_e2e_fixture.sh <recorded-initial-steam-sha256>
```

The script copies `ges/steam-live-run-x86` to a temp work dir, validates
the bootstrapper sha256 against the recorded value, runs the real updater
(network required; when no headless runtime is available it validates the
existing client and reports the update step as skipped), verifies the
required components, strips HKCU registry and logs, writes
`fixture-provenance.json`, and prints the hydrated path. The tracked
fixture is never mutated.

## Test Classification

| Category | Tests | Gate | Network |
|----------|-------|------|---------|
| Model tests (deterministic, no emulation) | section40, section38 | offline | ❌ |
| Bootstrap fixture tests (tracked GE, no live Steam) | section24, section38, section36 | `ges/steam-live-run-x86` present | ❌ |
| Real-network Steam E2E (live client + CDN) | section41, section23 | `CASA1_STEAM_E2E=1` + `--ignored` | ✅ |
| Signed JIT release acceptance | release gate (`ci/check_release_gate.sh`, release workflow) | signing env / release checklist | ❌ |

### When Steam Tests Are Skipped

Without `CASA1_STEAM_E2E=1`, all Steam E2E tests are skipped with a clear
message. This is the default behaviour in CI.

## Network Tests

Tests that contact external network services are marked with `#[ignore]`. This
includes:

- HTTP/HTTPS requests to real servers
- DNS resolution of real hostnames
- WebSocket connections to real endpoints
- QUIC connections to real servers

### Running Network Tests

```bash
# Run all ignored tests (includes network tests)
cargo test -- --ignored

# Run a specific ignored test
cargo test --test section7_network -- --ignored test_real_http_request
```

### ⚠️ Warnings for Network Tests

- **Non-deterministic**: Network tests may fail due to connectivity issues,
  server downtime, or rate limiting.
- **Slow**: Network tests involve real I/O and may take seconds per test.
- **Side effects**: Some tests may create real resources (e.g., upload files to
  Steam Cloud). Use a test account when possible.
- **Never in CI**: Network tests should not be part of the CI gate. They are
  for manual validation only, with the exception of the dedicated nightly
  Steam E2E workflow.

## Writing External Tests

### Gating with Environment Variables

Use the `CASA1_STEAM_E2E` environment variable for Steam E2E tests:

```rust
#[test]
#[ignore = "requires live Steam E2E environment"]
fn test_steam_e2e() {
    if std::env::var("CASA1_STEAM_E2E").as_deref() != Ok("1") {
        eprintln!("skipping: set CASA1_STEAM_E2E=1 to run");
        return;
    }
    // ... real Steam run + acceptance evaluation ...
}
```

### Gating with `#[ignore]`

Use `#[ignore]` for network tests that should not run by default:

```rust
#[test]
#[ignore = "requires network access"]
fn test_real_dns_resolution() {
    // ... test that contacts real DNS ...
}
```

### Best Practices

1. **Always print a skip message** so developers know the test exists:
   ```rust
   if std::env::var("CASA1_STEAM_E2E").as_deref() != Ok("1") {
       eprintln!("skipping: set CASA1_STEAM_E2E=1 to run");
       return;
   }
   ```

2. **Use timeouts** for network operations to prevent hanging:
   ```rust
   let client = reqwest::blocking::Client::builder()
       .timeout(std::time::Duration::from_secs(10))
       .build()
       .unwrap();
   ```

3. **Clean up resources** — delete any files uploaded to Steam Cloud, close
   connections, etc.

4. **Document prerequisites** — if a test requires specific hardware (e.g., a
   VR headset), note it in the test's doc comment.

## Test Execution Summary

| Command | What It Runs | External? |
|---------|-------------|-----------|
| `cargo test` | Unit + integration tests | ❌ Offline only |
| `cargo test -- --ignored` | Ignored tests (incl. network) | ✅ Requires network |
| `CASA1_STEAM_E2E=1 cargo test --release --test section41_steam_e2e -- --ignored --nocapture` | Real Steam E2E acceptance | ✅ Requires Steam + network |
| `cargo test --all-targets --quiet` | Full offline suite | ❌ Offline only |

## CI Configuration

CI runs the offline test suite only:

```yaml
# .github/workflows/ci.yml (example)
- run: cargo test --all-targets --quiet
```

The dedicated nightly `steam-e2e` workflow (`.github/workflows/steam-e2e.yml`)
runs the real Steam E2E acceptance on a schedule and on demand
(`workflow_dispatch`), and uploads the Steam diagnostics artifacts for every
run. All other external tests are never run in CI; they are intended for
manual validation before releases or when modifying networking/Steam
subsystems.
