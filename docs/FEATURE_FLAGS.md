# Feature Flags

Casa1 uses Cargo feature flags to enable or disable optional functionality at
compile time. Features are configured in [`Cargo.toml`](../Cargo.toml) under
the `[features]` section.

## Host Backend Model: Metal Is Mandatory

Metal is the **mandatory host backend on macOS**. The `metal`, `objc`,
`block`, `core-foundation`, `core-graphics` and related dependencies are
unconditional, and there is deliberately **no `metal` feature flag**: every
build — including `--no-default-features` — compiles and exports the Metal
backend (`metal_backend::MetalGpuBackend`).

The `vulkan` and `opengl` features do **not** select a host backend. They
switch the **guest-side translation path**: whether Casa1 registers
`vulkan-1.dll` / `opengl32.dll` export thunks that translate guest Vulkan/OpenGL
calls onto the Metal host backend. Disabling them removes the guest
translation path; the host backend remains Metal.

## Default Features

The following features are enabled by default:

```toml
default = ["vulkan", "opengl"]
```

This means a plain `cargo build` includes both guest-translation paths
(Vulkan and OpenGL) on top of the always-present Metal host backend.

## Feature Flag Reference

### `vulkan` (default)

- **Status**: Enabled by default
- **Dependencies**: None (MoltenVK is loaded at runtime if available)
- **Purpose**: Enables the **Vulkan guest-translation path** — `vulkan-1.dll`
  thunk registration so guest binaries can resolve Vulkan API functions,
  translated to Metal at runtime (via MoltenVK where available). The host
  backend is always Metal.
- **Implied by**: `moltenvk`
- **Observable**: `casa1::vkgl::vulkan_translation_enabled()` reports the
  compiled-in state; `register_vulkan_dll()` returns an empty table when the
  feature is off.

```bash
# Build with only the Vulkan guest-translation path
cargo build --no-default-features --features vulkan
```

### `opengl` (default)

- **Status**: Enabled by default
- **Dependencies**: None (ANGLE is loaded at runtime if available)
- **Purpose**: Enables the **OpenGL guest-translation path** — `opengl32.dll`
  thunk registration so guest binaries can resolve OpenGL/WGL API functions,
  translated to Metal at runtime (via ANGLE where available). The host
  backend is always Metal.
- **Implied by**: `angle`
- **Observable**: `casa1::vkgl::opengl_translation_enabled()` reports the
  compiled-in state; `register_opengl_dll()` returns an empty table when the
  feature is off.

```bash
# Build with only the OpenGL guest-translation path
cargo build --no-default-features --features opengl
```

### `moltenvk`

- **Status**: Optional (implies `vulkan`)
- **Purpose**: Convenience alias that also enables the `vulkan` feature.

```toml
# In Cargo.toml
moltenvk = ["vulkan"]
```

### `angle`

- **Status**: Optional (implies `opengl`)
- **Purpose**: Convenience alias that also enables the `opengl` feature.

```toml
# In Cargo.toml
angle = ["opengl"]
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

### `nightly_alloc_error_hook`

- **Status**: Optional — stable builds are unaffected
- **Purpose**: Forward-compat hook for `std::alloc::set_alloc_error_hook`,
  which is nightly-only. Declared so `unexpected_cfgs` remains enabled
  without flagging the cfg.

## Feature Combinations

### Minimal Build (No Guest GPU Translation Paths)

```bash
cargo build --no-default-features
```

This produces a binary with CPU emulation and the **mandatory Metal host
backend**, but without the Vulkan/OpenGL guest-translation thunk paths.

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

Uses default features (Vulkan + OpenGL guest-translation paths over the
mandatory Metal host backend). This is the recommended configuration for end
users.

### Testing with All Safe Features

```bash
cargo test --features "websocket,ffmpeg,proptest"
```

## Checking Feature Configuration

```bash
# List all available features
cargo metadata --format-version=1 | jq '.packages[] | select(.name=="casa1") | .features'

# Check which features are enabled for a specific build
cargo build --features "vulkan,websocket" -v 2>&1 | grep "features:"
```

## Build-Matrix Truth Test

`tests/section44_backend_matrix.rs` asserts the backend feature model:

- the default build exports the Metal backend (`metal_backend::MetalGpuBackend`);
- `--no-default-features` still exports the Metal backend (it is mandatory):
  `cargo test --no-default-features --test section44_backend_matrix`;
- the `vulkan`/`opengl` features toggle their guest-translation symbols
  (`vkgl::vulkan_translation_enabled()` / `vkgl::opengl_translation_enabled()`
  and the `register_vulkan_dll()` / `register_opengl_dll()` tables).

## Adding a New Feature Flag

To add a new feature flag:

1. Add the feature to `[features]` in [`Cargo.toml`](../Cargo.toml)
2. Add any optional dependency to `[dependencies]` with `optional = true`
3. Use `#[cfg(feature = "my-feature")]` in source code to gate the code
4. Document the feature in this file
5. Add the feature to the CI matrix in `.github/workflows/`
