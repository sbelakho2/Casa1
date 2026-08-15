# Security Model

## Overview

Casa1 is a Windows compatibility layer for macOS. It emulates the Windows
environment at the user-space level, allowing Windows applications (including
games) to run on macOS without a hypervisor or kernel extension. This document
describes Casa1's security architecture, threat model, and documented
non-goals.

---

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Malicious PE tampering | Authenticode signature verification, code integrity enforcement |
| Filesystem escape from sandbox | Path canonicalization, symlink resolution, mount boundary checks |
| Unauthorised network access | Network policy enforcement (allowlists, protocol filtering) |
| XXE injection in entitlement XML | Parser-level reject of DOCTYPE, CDATA, comments, entities |
| Weak/broken crypto used for Casa1's own security | BCryptRuntime compatibility/security separation, documented classifications |
| Process protection bypass | PPL emulation, protected process light (PPL) registry |
| Crash-based information leaks | Crash artifact redaction (PII stripping) |
| DRM integrity check tampering | Integrity check emulation, force-pass controls for SteamStub |

### Out of Scope (Non-Goals)

| Non-Goal | Rationale |
|----------|-----------|
| Kernel-level protection | Casa1 runs entirely in user space; no kext/virtualisation |
| Anti-cheat bypass | Casa1 does not attempt to defeat EasyAntiCheat, BattlEye, or Vanguard |
| DRM circumvention | Only SteamStub DRM is supported for compatibility; no cracking tools |
| Full chain-of-trust boot | No measured boot, secure boot, or TPM emulation |
| Side-channel attack resistance | No mitigations for cache timing, Spectre, Meltdown, etc. |
| Memory corruption prevention | No ASLR/DEP beyond what the guest process provides |
| Network MITM prevention | TLS is handled by the guest; Casa1 does not inspect encrypted traffic |

---

## Sandbox Isolation Boundaries

### Path Canonicalization

Filesystem sandbox enforcement is implemented in
[`src/sandbox.rs`](../src/sandbox.rs) and [`src/real_fs.rs`](../src/real_fs.rs).

The following bypass vectors are mitigated:

1. **Symlink traversal** — `resolve_sandbox_path()` resolves all symlinks via
   `std::fs::canonicalize()` before authorizing access.
2. **`..` path traversal** — Both Windows-style (`..`) and POSIX-style (`../`)
   components are normalized before resolution.
3. **Case-insensitive comparison** — macOS (APFS, case-insensitive by default)
   uses case-insensitive path comparison to prevent case-manipulation bypass.
4. **Null byte injection** — Paths containing null bytes (`\0`) are rejected
   outright.
5. **Mount boundary crossing** — On macOS, files on mounted volumes outside
   the GE root are rejected.
6. **TOCTOU races** — Between path canonicalization and access, the resolved
   path is locked/checked; see [`sandbox_reject_toctou_path_swap` test](../src/sandbox.rs:1059).

### Sensitive Path Blocks

The following macOS system paths are blocked from guest access:

- `/System/`, `/Library/`, `/private/`, `/etc/`, `/tmp/`, `/var/`, `/dev/`,
  `/usr/lib/`, `/usr/bin/`, `/bin/`, `/sbin/`, `/cores/`, `/Volumes/`
- User home directory paths containing `.ssh`, `.aws`, `.gnupg`, `.config`,
  `Keychains`, `Cookies`

### Network Policy

Network access is governed by [`NetworkPolicyEnforcer`](../src/security.rs:320)
with three profiles:

- `Permissive` — all outbound connections allowed
- `Restricted` — only allowlisted hosts/IPs allowed
- `BlockAll` — all outbound connections denied

DNS rebinding is checked by resolving the hostname at connection time and
verifying it against the allowlist.

---

## Cryptographic Trust Model

### Algorithm Classification

All cryptographic implementations in [`src/security.rs`](../src/security.rs)
(BCryptRuntime) follow a strict classification:

#### Compatibility Hashes (DO NOT USE for Casa1's own security)

These are implemented solely for emulating Windows BCrypt API calls made by
guest applications. They are **broken** for security purposes:

| Algorithm | Status | Reason |
|-----------|--------|--------|
| MD5 | Broken | Collision attacks, chosen-prefix attacks |
| SHA-1 | Broken | SHAttered, SHAMBLES, chosen-prefix attacks |
| HMAC-MD5 | Broken | MD5 collisions break HMAC security |
| HMAC-SHA1 | Broken | SHA-1 weaknesses propagate |
| 3DES | Broken | Sweet32, small block size |
| RC2/RC4 | Broken | Known vulnerabilities, deprecated |

#### Security Hashes (safe for Casa1's own use)

These are used for Casa1's own integrity checks and data protection:

| Algorithm | Use |
|-----------|-----|
| SHA-256 | Authenticode verification, integrity check regions, code integrity |
| SHA-384 | Certificate chain validation (SHA-384 with ECDSA P-384) |
| SHA-512 | Hash storage (BCrypt export, fallback) |
| HMAC-SHA256 | PBKDF2 derivation, secret agreement key derivation |
| HMAC-SHA384 | Compatibility with Windows CNG |
| HMAC-SHA512 | Compatibility with Windows CNG |
| AES-128-CBC | Guest SteamStub DRM decryption |
| AES-256-CBC | Guest SteamStub DRM decryption |
| AES-256-GCM | GameNetworkingSockets peer-to-peer encryption |
| AES-256-CTR | SessionCipher Steam GC protocol encryption |

### Key Management

| Component | Key Source | Notes |
|-----------|-----------|-------|
| SteamStub app key | Derived from app ID + ticket via HMAC-SHA256 | Static per game; fixed zero IV for AES-CBC |
| BCrypt RSA keypairs | Generated via `getrandom()` | Used for DRM emulation only |
| BCrypt ECDH/ECDSA/DH | Generated via `getrandom()` | Used for DRM emulation only |
| SessionCipher | SHA-256 derived from Steam session key | Directional sub-keys (send/recv) |
| GNS session keys | `rand::thread_rng()` 32-byte random | Per-connection AES-256-GCM |

### Fixed IV Warning

`decrypt_aes()` in SteamStub uses a **fixed zero IV** (`[0u8; 16]`). This is
acceptable because:

1. The per-game app key provides key variation across titles.
2. SteamStub uses AES-CBC in decrypt-only mode (no encryption).
3. SteamStub has its own integrity checks on the decrypted data.
4. Casa1's own encryption (GNS, SessionCipher) uses random nonces/IVs.

---

## Entitlement Validation Trust

### Entitlement XML Sanitisation

Entitlement plist files are processed by
[`sanitize_entitlement_xml()`](../src/security.rs:586) which rejects:

- **DOCTYPE declarations** — Prevents XXE and entity expansion (billion laughs).
- **XML comments** (`<!-- -->`) — Prevents content smuggling past simple scanners.
- **CDATA sections** (`<![CDATA[ ]]`) — Prevents embedding that bypasses
  structural validation.
- **Processing instructions** (`<? ... ?>`) — Strips non-standard PI elements.
- **Unknown entity references** (`&unknown;`) — Only standard XML entities
  (`&`, `<`, `>`, `"`, `'`) and numeric character references
  are allowed.

The parser does **not** use a full XML parser for sanitisation (by design), as
roxmltree is used downstream for actual plist parsing.

### Authenticode Verification

PE file signatures are verified via:

1. **PE image hash** — Hash is computed over the PE file excluding the
   Certificate Table (per Authenticode specification).
2. **SpcIndirectDataContent** — The hash OID and digest value are extracted
   from PKCS#7 SignedData.
3. **RSA signature verification** — Supports SHA-256, SHA-384, SHA-512, and
   SHA-1 hash algorithms with RSA PKCS#1 v1.5.
4. **Certificate chain validation** — Uses the macOS Security Framework (FFI)
   for X.509 chain building and trust evaluation.
5. **Code integrity policy** — Three levels: `Disabled` (no verification),
   `Enhanced` (warn on failure), `Strict` (reject on failure).

---

## DRM Emulation Limitations

### SteamStub (V2/V3)

Casa1 supports loading and decrypting SteamStub DRM for compatibility with
Steam games. Key limitations:

- **No key extraction** — Casa1 does not extract Steam decryption keys; the
  app key must be derived from the app ID and a valid ticket.
- **No online validation** — Casa1 does not communicate with Steam servers
  for ticket validation.
- **Integrity checks** — SteamStub integrity checks are emulated; `force_pass`
  can bypass them (for testing only).
- **V3 relocations** — Only basic relocation fixups are applied.

### Denuvo

Casa1 has a minimal Denuvo emulator that handles:

- Code section decryption (AES-CBC with rolling keys)
- Trigger point detection
- License token verification (local only; no online activation)
- Integrity check verification

**Denuvo is NOT fully supported.** The emulator handles only specific titles
and configurations.

### Other Packers

- UPX unpacking (NRV2B/NRV2E/LZMA decompression) — Supported
- ASPack unpacking (aPLib decompression) — Supported
- MPRESS, Themida — Detection only; no unpacking support

---

## Anti-Cheat Detection

Casa1 provides anti-debug and process protection emulation sufficient to pass
basic anti-cheat integrity checks for titles that run in compatibility mode.

**This is not a guarantee against any specific anti-cheat system.** Casa1 does
not attempt to defeat kernel-level anti-cheat (EAC, BattlEye, Vanguard).

---

## Code Integrity

The [`enforce_code_integrity()`](../src/security.rs:7224) function provides
CI (Code Integrity) emulation with three policy levels:

| Policy | Behaviour |
|--------|-----------|
| `Disabled` | No signature verification; all images allowed |
| `Enhanced` | Verify signature; log warning on failure (CI logging) |
| `Strict` | Verify signature; return error on failure (CI enforcement) |

---

## Secure Development Practices

- **Unsafe code review**: All `unsafe` blocks require `// SAFETY:` comments;
  see [`docs/UNSAFE_REVIEW.md`](UNSAFE_REVIEW.md) for rules.
- **Fuzz testing**: The `fuzz/` directory contains fuzz targets for PE parsing,
  HTTP handling, filesystem paths, and network protocols.
- **Sanitiser builds**: Nightly builds can enable AddressSanitiser and
  LeakSanitiser via `cargo +nightly test -Z sanitizer=address`.
- **Test coverage**: All sandbox enforcement, cryptographic operations, and
  entitlement sanitisation have unit tests.
