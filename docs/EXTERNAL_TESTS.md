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

## Steam Integration Tests

Real Steam integration tests require the `CASAS1_STEAM_INTEGRATION` environment
variable to be set. These tests interact with the live Steam API and require:

- Steam to be installed and running
- A valid Steam account (may require login)
- Network access to Steam servers

### Running Steam Integration Tests

```bash
# Enable Steam integration tests
CASAS1_STEAM_INTEGRATION=1 cargo test --test section5_steam

# Or run all tests with Steam integration
CASAS1_STEAM_INTEGRATION=1 cargo test --all-targets
```

### What Steam Tests Cover

- Steam API initialization and shutdown
- Steam user authentication
- Steam app ownership verification
- Steam Cloud (remote storage) read/write
- Steam Networking Sockets (via QUIC)
- Steam Input (controller) enumeration
- SteamVR initialization (if headset is connected)

### When Steam Tests Are Skipped

Without `CASAS1_STEAM_INTEGRATION=1`, all Steam integration tests are silently
skipped. This is the default behaviour in CI.

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
  for manual validation only.

## Writing External Tests

### Gating with Environment Variables

Use the `CASAS1_STEAM_INTEGRATION` environment variable for Steam tests:

```rust
#[test]
fn test_steam_api_init() {
    if std::env::var("CASAS1_STEAM_INTEGRATION").is_err() {
        eprintln!("skipping: set CASAS1_STEAM_INTEGRATION=1 to run");
        return;
    }
    // ... real Steam API test ...
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
   if std::env::var("CASAS1_STEAM_INTEGRATION").is_err() {
       eprintln!("skipping: set CASAS1_STEAM_INTEGRATION=1 to run");
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
| `cargo test -- --ignored` | Network tests | ✅ Requires network |
| `CASAS1_STEAM_INTEGRATION=1 cargo test` | All tests including Steam | ✅ Requires Steam |
| `cargo test --all-targets --quiet` | Full offline suite | ❌ Offline only |

## CI Configuration

CI runs the offline test suite only:

```yaml
# .github/workflows/ci.yml (example)
- run: cargo test --all-targets --quiet
```

External tests are never run in CI. They are intended for manual validation
before releases or when modifying networking/Steam subsystems.
