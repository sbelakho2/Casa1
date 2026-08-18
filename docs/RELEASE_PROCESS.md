# Release Process

This document describes the end-to-end process for creating a Casa1 release,
including code signing, entitlements, notarization, and packaging.

## Prerequisites

- macOS 13+ (Ventura) with Xcode Command Line Tools
- Apple Developer ID (for code signing and notarization)
- Valid Developer ID Application certificate installed in Keychain
- App-specific password for `notarytool` (stored in Keychain)
- Rust toolchain with `aarch64-apple-darwin` and `x86_64-apple-darwin` targets

## Release Gate

**All CI checks must pass before proceeding with a release, and the release
gate is evidence-based: it fails closed.** The gate does not read this
checklist — it verifies `release-evidence.json` (see
[`ci/check_release_gate.sh`](../ci/check_release_gate.sh)):

- `release-evidence.json` exists, its `commit` matches the exact release
  commit, and every required acceptance field is `"pass"`.
- Steam E2E evidence is required: the `steam-e2e` workflow's artifact
  (`steam-e2e-<sha>`) must exist for the exact commit, its content digest
  (`steam_e2e_artifact_sha256`) must match, and its embedded `commit.txt`
  must equal the release HEAD — the evidence belongs to the same commit.
- The signed candidate hash (`signed_candidate_sha256`) must match the
  sha256 of the exact artifact that was smoke-tested and E2E-tested; the
  file must be present at `signed_candidate`. Record the hash at release
  time from the candidate you actually test — never reuse a hash from a
  different build.

```bash
# Verify all checks pass locally
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --tests
(cd fuzz && cargo +nightly fuzz build)
cargo bench --no-run
```

Do not proceed if any check fails. Fix the issue and re-run.

## Step 1: Version Bump

Update the version in [`Cargo.toml`](../Cargo.toml):

```toml
[package]
name = "casa1"
version = "0.2.0"  # Update this
```

Commit with message:

```
chore: bump version to 0.2.0
```

## Step 2: Build Release Binaries

Build optimized binaries for both architectures:

```bash
# Apple Silicon
cargo build --release --target aarch64-apple-darwin

# Intel
cargo build --release --target x86_64-apple-darwin
```

### Build Configuration

The release profile uses Cargo's default optimisations:

```toml
[profile.release]
# Inherits Cargo defaults: opt-level = 3, lto = false
```

For benchmarking builds, debug info is enabled:

```toml
[profile.bench]
debug = 1
```

## Step 3: Code Signing

All binaries must be signed with a Developer ID certificate.

### Signing with `codesign`

```bash
# Sign non-JIT binaries with ad-hoc signature (for local testing)
for binary in casa1 macwin casa1-helper casa1-test-guest casa1-oracle; do
    /usr/bin/codesign --force --sign - "target/release/$binary"
done

# Sign casa1-runner with JIT entitlements
/usr/bin/codesign \
    --force \
    --sign - \
    --entitlements ci/entitlements/casa1-runner.plist \
    target/release/casa1-runner
```

### Production Signing with Developer ID

Replace `-` (ad-hoc) with your Developer ID Application certificate identity:

```bash
IDENTITY="Developer ID Application: Your Name (TEAMID)"

for binary in casa1 macwin casa1-helper casa1-test-guest casa1-oracle; do
    /usr/bin/codesign --force --sign "$IDENTITY" \
        --options runtime \
        "target/release/$binary"
done

/usr/bin/codesign \
    --force \
    --sign "$IDENTITY" \
    --options runtime \
    --entitlements ci/entitlements/casa1-runner.plist \
    target/release/casa1-runner
```

The `--options runtime` flag enables the hardened runtime, which is required
for notarization.

### Inside-Out Signing (never `codesign --deep`)

`codesign --deep` re-signs nested code with the outer invocation and can
produce inconsistent nested signatures. Sign from the inside out, verifying
each layer before the next:

```bash
IDENTITY="Developer ID Application: Your Name (TEAMID)"

# 1. Innermost first: the JIT runner with its allow-jit entitlement.
/usr/bin/codesign --force --sign "$IDENTITY" --options runtime \
    --entitlements ci/entitlements/casa1-runner.plist \
    Casa1.app/Contents/MacOS/casa1-runner
/usr/bin/codesign --verify --strict --verbose=2 \
    Casa1.app/Contents/MacOS/casa1-runner

# 2. Other nested executables inside the bundle.
for binary in casa1 macwin casa1-helper casa1-test-guest casa1-oracle; do
    /usr/bin/codesign --force --sign "$IDENTITY" --options runtime \
        "Casa1.app/Contents/MacOS/$binary"
    /usr/bin/codesign --verify --strict --verbose=2 \
        "Casa1.app/Contents/MacOS/$binary"
done

# 3. Outer app bundle last.
/usr/bin/codesign --force --sign "$IDENTITY" --options runtime \
    Casa1.app
/usr/bin/codesign --verify --strict --verbose=2 Casa1.app

# 4. Notarize, staple, and verify the notarization.
xcrun notarytool submit <candidate.zip> ... --wait
xcrun stapler staple Casa1.app
xcrun stapler validate Casa1.app
spctl --assess --type execute --verbose=4 Casa1.app
```

### JIT Runtime Self-Test on the Packaged Candidate

The signed `casa1-runner` must prove the production JIT path (allow-jit +
MAP_JIT) before the gate passes. Run the release smoke suite in release
mode against the packaged candidate — it refuses to rebuild anything and
fails closed when binaries are missing:

```bash
CI_RELEASE=1 ./ci/check_release_smoke.sh
# JIT self-test: --jit-self-test CLI when it exists, otherwise the JIT unit
# tests (cargo test --lib jit::) in dev mode; in release mode JIT execution
# is validated by running the packaged runner on a bounded PE fixture.
# The suite also verifies allow-jit on the signed runner and exercises the
# steam:launch profile surface.
```

### Record the Exact Candidate Hash

After the signed, notarized candidate exists and passes smoke/E2E, record
its identity in `release-evidence.json`:

```bash
shasum -a 256 Casa1-0.2.0-signed.zip   # -> signed_candidate_sha256
# signed_candidate = the exact filename hashed above.
```

The release gate compares this hash against the file at
`signed_candidate`; a rebuilt or replaced candidate fails the gate.

## Step 4: Entitlements

The entitlements file is located at
[`ci/entitlements/casa1-runner.plist`](../ci/entitlements/casa1-runner.plist):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
</dict>
</plist>
```

### JIT Entitlement

The `com.apple.security.cs.allow-jit` entitlement is **required** for
`casa1-runner` because it uses `MAP_JIT` to allocate executable memory for
JIT-compiled guest code. Without this entitlement, the hardened runtime blocks
JIT allocation and the emulator cannot function.

### Entitlement Audit

The CI script [`ci/audit_release_entitlements.sh`](../ci/audit_release_entitlements.sh)
verifies that:

1. All expected binaries are present in the release directory
2. The binary list matches the `[[bin]]` entries in `Cargo.toml`
3. `casa1-runner` has the JIT entitlement
4. Other binaries do **not** have the JIT entitlement

Run the audit locally:

```bash
# Default mode: builds + ad-hoc signs + audits the entitlement structure
./ci/audit_release_entitlements.sh

# Release mode: verifies ONLY the existing Developer ID signatures and
# entitlements (including allow-jit on the runner); refuses to build or
# re-sign anything, and fails closed on unsigned/ad-hoc/missing binaries
./ci/audit_release_entitlements.sh --verify-existing-signatures
```

## Step 5: Notarization

Notarization is required for distribution outside the Mac App Store. It
validates that the binary is signed with a Developer ID and passes Apple's
malware checks.

### Submit for Notarization

```bash
# Create a ZIP of the signed binaries
ditto -c -k --keepParent target/release/casa1.app casa1-0.2.0.zip

# Submit to Apple
xcrun notarytool submit casa1-0.2.0.zip \
    --apple-id "your@email.com" \
    --team-id "TEAMID" \
    --password "@keychain:AC_PASSWORD" \
    --wait

# Check status
xcrun notarytool log <submission-id> \
    --apple-id "your@email.com" \
    --team-id "TEAMID" \
    --password "@keychain:AC_PASSWORD"
```

### Staple the Ticket

After notarization succeeds, staple the ticket to the binary:

```bash
xcrun stapler staple target/release/casa1.app
```

## Step 6: Package as macOS App Bundle

Casa1 is packaged as a standard macOS `.app` bundle:

```
Casa1.app/
├── Contents/
│   ├── Info.plist          # Application metadata
│   ├── MacOS/
│   │   ├── casa1           # Main executable
│   │   ├── casa1-runner    # JIT runner (with entitlements)
│   │   ├── casa1-helper    # Privileged helper
│   │   ├── casa1-oracle    # Oracle model server
│   │   └── macwin          # CLI entry point
│   ├── Resources/
│   │   └── AppIcon.icns    # Application icon
│   └── Frameworks/
│       └── (none)          # All dependencies statically linked
```

### Creating the App Bundle

```bash
# Create the bundle structure
mkdir -p Casa1.app/Contents/MacOS
mkdir -p Casa1.app/Contents/Resources

# Copy binaries
cp target/release/casa1 Casa1.app/Contents/MacOS/
cp target/release/casa1-runner Casa1.app/Contents/MacOS/
cp target/release/casa1-helper Casa1.app/Contents/MacOS/
cp target/release/casa1-oracle Casa1.app/Contents/MacOS/
cp target/release/macwin Casa1.app/Contents/MacOS/

# Create Info.plist
cat > Casa1.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Casa1</string>
    <key>CFBundleDisplayName</key>
    <string>Casa1</string>
    <key>CFBundleIdentifier</key>
    <string>com.casa1.app</string>
    <key>CFBundleVersion</key>
    <string>0.2.0</string>
    <key>CFBundleShortVersionString</key>
    <string>0.2.0</string>
    <key>CFBundleExecutable</key>
    <string>casa1</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
</dict>
</plist>
EOF

# Sign the entire app bundle — inside out, NOT --deep (see "Inside-Out
# Signing" above). --deep can produce inconsistent nested signatures.
# Sign Casa1.app/Contents/MacOS/casa1-runner (with entitlements) first,
# verify, then the other nested executables, then the outer bundle.
```

## Step 7: Create Distribution Archive

```bash
# Create a DMG (optional)
hdiutil create -volname "Casa1 0.2.0" \
    -srcfolder Casa1.app \
    -ov -format UDZO \
    casa1-0.2.0.dmg

# Or create a ZIP
ditto -c -k --keepParent Casa1.app casa1-0.2.0.zip
```

## Step 8: Tag and Publish

```bash
# Create a git tag
git tag -a v0.2.0 -m "Release 0.2.0"
git push origin v0.2.0

# Create a GitHub release and attach the archive
gh release create v0.2.0 casa1-0.2.0.dmg \
    --title "Casa1 0.2.0" \
    --notes "Release notes here"
```

## Release Checklist

- [ ] All CI checks pass (including `cargo test --tests`)
- [ ] Version bumped in `Cargo.toml`
- [ ] Release binaries built for `aarch64-apple-darwin` and `x86_64-apple-darwin`
- [ ] Steam E2E evidence exists for the exact commit (`steam-e2e-<sha>` artifact; section41 with `CASA1_STEAM_E2E=1`)
- [ ] All binaries signed with Developer ID, inside-out (runner with allow-jit first, then nested, then outer bundle — never `--deep`)
- [ ] JIT runtime self-test passes on the packaged candidate (`CI_RELEASE=1 ./ci/check_release_smoke.sh`)
- [ ] Exact candidate hash recorded in `release-evidence.json` (`signed_candidate_sha256` of the file actually tested)
- [ ] Entitlement audit passes against the existing signatures (`./ci/audit_release_entitlements.sh --verify-existing-signatures`)
- [ ] Release gate passes (`./ci/check_release_gate.sh` — evidence model, fails closed)
- [ ] Notarization submitted and approved
- [ ] Notarization ticket stapled
- [ ] App bundle created with correct structure
- [ ] Distribution archive (DMG or ZIP) created
- [ ] Git tag created and pushed
- [ ] GitHub release published with attached archive
