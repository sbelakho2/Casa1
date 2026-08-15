# Feature Flags

Casa1 uses Cargo feature flags to enable or disable optional functionality at
compile time. Features are configured in [`Cargo.toml`](../Cargo.toml) under
the `[features]` section.

## Default Features

The following features are enabled by default:

```toml
default = ["metal", "vulkan", "opengl"]
```

This means a plain `cargo build` includes all three GPU translation backends.

## Feature Flag Reference

### `metal` (default)

- **Status**: Enabled by default
- **Dependencies**: `metal` crate, `objc`, `block`, `core-foundation`, `core-graphics`
- **Purpose**: Enables the Metal GPU backend for translating Direct3D 10/11/12
  calls to native Metal render and compute pipelines.
- **When to disable**: Only if you want a minimal build without GPU support or
  are building on a platform without Metal (not recommended for macOS).

```bash
# Build without Metal
cargo build --no-default-features --features vulkan,opengl
```

### `vulkan` (default)

- **Status**: Enabled by default
- **Dependencies**: None (runtime loads MoltenVK if available)
- **Purpose**: Enables the Vulkan GPU backend. On macOS, Vulkan is translated
  to Metal via MoltenVK at runtime.
- **Implied by**: `moltenvk`

```bash
# Build with only Vulkan
cargo build --no-default-features --features vulkan
```

### `opengl` (default)

- **Status**: Enabled by default
- **Dependencies**: None (runtime loads ANGLE if available)
- **Purpose**: Enables the OpenGL GPU backend. On macOS, OpenGL is translated
  to Metal via ANGLE at runtime.
- **Implied by**: `angle`

```bash
# Build with only OpenGL
cargo build --no-default-features --features opengl
```

### `moltenvk`

- **Status**: Optional (implies `vulkan`)
- **Purpose**: Explicitly enables Vulkan via MoltenVK. This is a convenience
  alias that also enables the `vulkan` feature.
- **Use case**: When you want to guarantee MoltenVK is available and want the
  Vulkan path specifically.

```toml
# In Cargo.toml
moltenvk = ["vulkan"]
```

```bash
cargo build --features moltenvk
```

### `angle`

- **Status**: Optional (implies `opengl`)
- **Purpose**: Explicitly enables OpenGL via ANGLE. This is a convenience
  alias that also enables the `opengl` feature.
- **Use case**: When you want to guarantee ANGLE is available and want the
  OpenGL path specifically.

```toml
# In Cargo.toml
angle = ["opengl"]
```

```bash
cargo build --features angle
```

### `websocket`

- **Status**: Optional
- **Dependency**: `tungstenite` 0.26
- **Purpose**: Enables WebSocket protocol support for guest applications that
  use WinHTTP WebSocket extensions.
- **When to enable**: When running guest applications that require WebSocket
  connectivity.

```toml
# In Cargo.toml
websocket = ["tungstenite"]
```

```bash
cargo build --features websocket
```

### `ffmpeg`

- **Status**: Optional
- **Dependency**: `ffmpeg-next` 7.0
- **System requirement**: FFmpeg libraries must be installed on the system
  (`brew install ffmpeg`).
- **Purpose**: Enables hardware-accelerated video and audio decoding via
  FFmpeg. Without this feature, Casa1 uses built-in software decoders which
  support fewer codecs.
- **When to enable**: When guest applications require video playback with
  codecs not supported by the built-in decoders (e.g., H.265/HEVC, VP9).

```toml
# In Cargo.toml
ffmpeg = ["ffmpeg-next"]
```

```bash
# Install FFmpeg system library first
brew install ffmpeg

# Build with FFmpeg support
cargo build --features ffmpeg
```

### `proptest`

- **Status**: Optional
- **Purpose**: Enables property-based testing strategies within the crate.
  This is used for generating random but valid test inputs for CPU emulation,
  PE parsing, and other subsystems.
- **When to enable**: During development and testing, not needed for release
  builds.

```bash
cargo test --features proptest
```

### `dev-insecure-tls`

- **Status**: Optional — **NOT for release builds**
- **Purpose**: Disables TLS certificate verification for development and
  testing. This allows intercepting HTTPS traffic for debugging.
- **⚠️ WARNING**: Never use this feature in production or release builds. It
  disables critical security protections.

```bash
# Development only!
cargo build --features dev-insecure-tls
```

## Feature Combinations

### Minimal Build (No GPU Backends)

```bash
cargo build --no-default-features
```

This produces a binary with CPU emulation only — no GPU translation. Useful for
headless testing or server-side PE analysis.

### Full Build (All Features)

```bash
cargo build --all-features
```

> **Note**: `--all-features` includes `dev-insecure-tls`. Do not distribute
> binaries built with `--all-features`.

### Production Build

```bash
cargo build --release
```

Uses default features (Metal + Vulkan + OpenGL). This is the recommended
configuration for end users.

### Testing with All Safe Features

```bash
cargo test --features "websocket,ffmpeg,proptest"
```

## Checking Feature Configuration

```bash
# List all available features
cargo metadata --format-version=1 | jq '.packages[] | select(.name=="casa1") | .features'

# Check which features are enabled for a specific build
cargo build --features "metal,websocket" -v 2>&1 | grep "features:"
```

## Adding a New Feature Flag

To add a new feature flag:

1. Add the feature to `[features]` in [`Cargo.toml`](../Cargo.toml)
2. Add any optional dependency to `[dependencies]` with `optional = true`
3. Use `#[cfg(feature = "my-feature")]` in source code to gate the code
4. Document the feature in this file
5. Add the feature to the CI matrix in `.github/workflows/`
