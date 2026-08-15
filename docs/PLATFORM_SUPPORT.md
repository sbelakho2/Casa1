# Platform Support

This document describes the host platforms, CPU architectures, and system
requirements for building and running Casa1.

## Supported Host Platforms

| Platform | Architecture | Status | Notes |
|----------|-------------|--------|-------|
| macOS 13+ (Ventura) | Apple Silicon (aarch64) | **Primary target** | Full JIT, Metal, CoreAudio |
| macOS 13+ (Ventura) | Intel (x86_64) | Secondary target | Interpreter-only, no JIT |

### Why macOS 13 (Ventura) Minimum?

Casa1 depends on several APIs introduced or stabilised in macOS 13:

- **Metal 3** — the Metal backend uses features from the Metal 3 toolchain
  (including argument buffer tier 2 and mesh shaders where available).
- **`MAP_JIT`** — the `mmap(2)` flag `MAP_JIT` was introduced in macOS 11 but
  gained reliable behaviour across all Apple Silicon Macs by macOS 13.
- **Virtualization framework** — optional KVM-like acceleration requires macOS
  13+ for the most stable API surface.

## CPU Architecture Details

### Apple Silicon (aarch64) — Primary Target

- **CPU emulation**: x86 (32-bit) and x64 (64-bit) guest code is translated to
  ARM64 IR and then either interpreted or JIT-compiled.
- **JIT compilation**: Uses `MAP_JIT` with `pthread_jit_write_protect_np()` to
  follow Apple's W^X (Write XOR Execute) requirements. See
  [`src/jit.rs`](../src/jit.rs) for implementation details.
- **Metal rendering**: Direct3D 10/11/12 calls are translated to Metal render
  and compute pipelines via the Metal backend in
  [`src/metal_backend.rs`](../src/metal_backend.rs) and
  [`src/metal_renderer.rs`](../src/metal_renderer.rs).
- **Audio**: XAudio2 and DirectSound are translated to CoreAudio via
  [`cpal`](https://crates.io/crates/cpal).

### Intel (x86_64) — Secondary Target

- **CPU emulation**: x86 and x64 guest code runs through the same IR
  translation layer, but execution is interpreter-only (no JIT on Intel hosts).
- **GPU backends**: Metal is still available on Intel Macs, though performance
  may be lower than on Apple Silicon. Vulkan (via MoltenVK) and OpenGL (via
  ANGLE) are also supported.
- **Audio**: Identical CoreAudio path as Apple Silicon.

## System Requirements

### Required

| Component | Minimum Version | Purpose |
|-----------|----------------|---------|
| macOS | 13.0 (Ventura) | Host operating system |
| Xcode Command Line Tools | Latest | `clang`, `ld`, SDK headers |
| Metal framework | Bundled with macOS | GPU translation backend |
| Rust toolchain | 1.85+ (edition 2024) | Build compiler |
| Cargo | Bundled with Rust | Build system |

### Installing Xcode Command Line Tools

```bash
xcode-select --install
```

This installs the SDK headers, `clang`, and the system linker required to
compile the Metal, CoreAudio, and Objective-C bridging code.

### Verifying Your Toolchain

```bash
# Check Rust version (must support edition 2024)
rustc --version

# Check Xcode CLI tools
xcode-select -p

# Quick build check
cargo check
```

## Guest Architecture Support

| Guest Architecture | Emulation Mode | JIT Support |
|--------------------|---------------|-------------|
| x86 (32-bit) | IR translation → ARM64 | ✅ on aarch64 host |
| x64 (64-bit) | IR translation → ARM64 | ✅ on aarch64 host |

Both x86 and x64 guest binaries are supported. The CPU emulation layer in
[`src/cpu.rs`](../src/cpu.rs) translates x86/x64 instructions into an
intermediate representation (IR) that is then either interpreted or compiled
to native ARM64 machine code by the JIT engine in [`src/jit.rs`](../src/jit.rs).

## GPU Backend Matrix

| Backend | macOS Apple Silicon | macOS Intel | Library |
|---------|-------------------|-------------|---------|
| Metal | ✅ Native | ✅ Supported | Bundled with macOS |
| Vulkan | ✅ Via MoltenVK | ✅ Via MoltenVK | MoltenVK (optional) |
| OpenGL | ✅ Via ANGLE | ✅ Via ANGLE | ANGLE (optional) |

All three GPU backends can be enabled simultaneously via feature flags. See
[FEATURE_FLAGS.md](./FEATURE_FLAGS.md) for details.

## Known Platform-Specific Issues

- **Intel Macs**: JIT compilation is not available. Guest code runs through the
  interpreter, which is significantly slower than JIT.
- **Rosetta 2**: Running the Casa1 binary under Rosetta 2 (i.e., compiling for
  x86_64 and running on Apple Silicon) is not supported. Always compile
  natively for `aarch64-apple-darwin` on Apple Silicon Macs.
- **iOS / tvOS / visionOS**: Not supported. Casa1 targets macOS only.

## Building for a Specific Architecture

```bash
# Build natively for Apple Silicon
cargo build --target aarch64-apple-darwin --release

# Build natively for Intel
cargo build --target x86_64-apple-darwin --release

# Build a universal binary (requires both targets)
rustup target add x86_64-apple-darwin
rustup target add aarch64-apple-darwin
cargo build --target aarch64-apple-darwin --release
cargo build --target x86_64-apple-darwin --release
# Then use lipo to create a universal binary
lipo -create \
  target/aarch64-apple-darwin/release/casa1 \
  target/x86_64-apple-darwin/release/casa1 \
  -output target/universal/release/casa1
```
