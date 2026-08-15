# Dependencies

This document describes all system and Rust dependencies required to build,
test, and run Casa1.

## System Dependencies

### Required (Bundled with macOS)

| Dependency | Purpose | Installed With |
|-----------|---------|---------------|
| **Metal framework** | GPU translation backend for D3D → Metal | macOS SDK (Xcode CLI tools) |
| **CoreAudio** | Audio backend for XAudio2/DirectSound translation | macOS SDK (Xcode CLI tools) |
| **CoreFoundation** | Low-level data types, run loops, property lists | macOS SDK (Xcode CLI tools) |
| **CoreGraphics** | 2D rendering, window management, event handling | macOS SDK (Xcode CLI tools) |
| **Objective-C runtime** | Bridging to Metal, AppKit, and other macOS frameworks | macOS SDK (Xcode CLI tools) |
| **clang / ld** | Compiling Objective-C bridging code and linking | Xcode Command Line Tools |

Install everything at once:

```bash
xcode-select --install
```

### Optional System Dependencies

| Dependency | Purpose | Install |
|-----------|---------|---------|
| **FFmpeg** | Video/audio decoding via `ffmpeg` feature flag | `brew install ffmpeg` |
| **MoltenVK** | Vulkan translation layer (bundled via feature flag) | Included via `moltenvk` feature |
| **ANGLE** | OpenGL translation layer (bundled via feature flag) | Included via `angle` feature |

## Rust Dependencies (Cargo)

### Core Dependencies

These are always required and listed in `[dependencies]` in
[`Cargo.toml`](../Cargo.toml):

| Crate | Version | Purpose |
|-------|---------|---------|
| `clap` | 4.5 | Command-line argument parsing (derive macro) |
| `libc` | 0.2 | POSIX / macOS system calls (`mmap`, `pthread_jit_write_protect_np`, signals) |
| `serde` + `serde_json` | 1.0 | Serialization for game environments, traces, telemetry |
| `sha2` | 0.10 | SHA-256 hashing for integrity checks |
| `uuid` | 1.18 | Unique identifiers for sessions, resources |
| `metal` | 0.31 | Rust bindings to the Metal framework |
| `objc` | 0.2 | Objective-C runtime interop |
| `block` | 0.1 | Objective-C block support |
| `core-foundation` | 0.10 | CoreFoundation bindings |
| `core-graphics` | 0.24 | CoreGraphics bindings |
| `cpal` | 0.15 | Cross-platform audio (wraps CoreAudio on macOS) |
| `minifb` | 0.27 | Minimal framebuffer window for testing |
| `reqwest` | 0.12 | HTTP client (native-tls backend) |
| `native-tls` | 0.2 | TLS via macOS Security.framework |
| `rustls` | 0.23 | TLS implementation (Rust) |
| `tokio` | 1 | Async runtime for networking |
| `quinn` | 0.11 | QUIC protocol (used for Steam networking) |
| `rand` / `getrandom` | 0.8 / 0.2 | Cryptographic random number generation |
| `ecdsa` / `p256` / `p384` | 0.16 / 0.13 | Elliptic curve cryptography |
| `rsa` | 0.9 | RSA signature verification |
| `x509-cert` | 0.2 | X.509 certificate parsing |
| `cms` | 0.2 | Cryptographic Message Syntax (code signing) |
| `regex` | 1.11 | Pattern matching for path resolution |
| `flate2` | 1.1 | DEFLATE compression/decompression |
| `png` | 0.17 | PNG image encoding/decoding |
| `walkdir` | 2.5 | Directory traversal |
| `zip` | 2.4 | ZIP archive handling |
| `libloading` | 0.8 | Dynamic library loading |
| `crossbeam-channel` | 0.5 | Multi-producer multi-consumer channels |

### Optional Dependencies (Feature-Gated)

| Crate | Feature Flag | Purpose |
|-------|-------------|---------|
| `tungstenite` | `websocket` | WebSocket protocol support |
| `ffmpeg-next` | `ffmpeg` | Video/audio decoding via FFmpeg |

### Dev Dependencies

These are only needed for testing and benchmarking:

| Crate | Version | Purpose |
|-------|---------|---------|
| `tempfile` | 3.20 | Temporary files and directories for tests |
| `criterion` | 0.5 | Statistical benchmarking framework |
| `proptest` | 1 | Property-based testing |
| `cms` (builder) | 0.2 | CMS test fixture generation |
| `x509-cert` (builder) | 0.2 | X.509 test certificate generation |

### Fuzz Dependencies

Fuzzing uses a separate workspace in [`fuzz/Cargo.toml`](../fuzz/Cargo.toml):

| Crate | Version | Purpose |
|-------|---------|---------|
| `libfuzzer-sys` | 0.4 | libFuzzer bindings for Rust |

## Toolchain Requirements

| Tool | Required For | Install |
|------|-------------|---------|
| **Rust stable** (1.85+) | Building, testing, benchmarking | `rustup default stable` |
| **Rust nightly** | Fuzzing (`cargo-fuzz`), UBSAN | `rustup toolchain install nightly` |
| **cargo-fuzz** | Fuzz target compilation | `cargo install cargo-fuzz` |

### Installing Fuzzing Tools

```bash
# Install nightly toolchain
rustup toolchain install nightly

# Install cargo-fuzz
cargo install cargo-fuzz

# Verify
cargo +nightly fuzz build
```

## Dependency Graph Overview

```
casa1
├── metal (GPU backend)
│   ├── objc (Objective-C runtime)
│   └── block (ObjC blocks)
├── cpal (Audio)
│   └── CoreAudio (system)
├── reqwest (HTTP)
│   └── native-tls → Security.framework (system)
├── quinn (QUIC/Steam networking)
│   └── rustls (TLS)
├── ffmpeg-next (optional, video decoding)
└── tungstenite (optional, WebSocket)
```

## Updating Dependencies

```bash
# Check for outdated dependencies
cargo outdated

# Update all dependencies within SemVer bounds
cargo update

# Audit for known vulnerabilities
cargo audit
```

> **Note**: `cargo audit` requires the `cargo-audit` crate:
> `cargo install cargo-audit`
