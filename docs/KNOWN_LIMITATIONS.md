# Known Limitations

This document lists known limitations of Casa1, separated from inline code
comments for easy reference. These are architectural or implementation
constraints that are unlikely to be resolved in the near term.

## Supported

- Windows Steam client
- Apple Silicon
- Supported macOS versions
- Steam bootstrap/update
- Steam login/store/library UI once proven
- CEF UI
- Metal output
- Basic input/audio/network
- Supported Windows games meeting documented requirements

## Not Automatically Guaranteed

- Anti-cheat drivers
- Kernel-mode DRM
- SteamVR
- All Steam Overlay paths
- .NET Framework games
- Every Vulkan/OpenGL extension
- Every Windows application

### block v0.1.6 Future Compatibility

**Limitation**: The `block` crate v0.1.6 (a transitive dependency) produces a
warning during compilation: *"the following packages contain code that will be
rejected by a future version of Rust: block v0.1.6"*.

**Reason**: This is a pre-existing transitive dependency issue originating from
upstream crates that depend on `block` v0.1.6. The crate uses older Rust idioms
that trigger compiler deprecation warnings. This is not actionable within Casa1
itself — it will be resolved automatically when upstream dependencies update
their `block` crate dependency to a newer, compatible version.

**Impact**: The warning is cosmetic only. It does not affect correctness,
safety, or functionality of Casa1 builds. CI warning-count checking should
be configured to ignore this known upstream warning, or the relevant CI step
should tolerate this specific transitive dependency warning.

## CPU Emulation

### No x86-on-x86 JIT

**Limitation**: JIT compilation is only available when running on an ARM64
(Apple Silicon) host. On Intel (x86_64) Macs, guest code runs through the
interpreter, which is significantly slower.

**Reason**: The JIT compiler in [`src/jit.rs`](../src/jit.rs) translates x86/x64
guest instructions to ARM64 native code. There is no x86 → x86 JIT path because
the project's primary target is Apple Silicon.



### Guest Debugging is Limited to GDB Stub

**Limitation**: Debugging guest code is only supported via a GDB remote stub.
There is no integrated GUI debugger or integration with Xcode/lldb for guest
code.

**Reason**: Guest code runs in an emulated environment with its own address
space and register set. Native debuggers cannot attach to emulated processes.



## Graphics

### GDI-Only Bootstrapper Live Preview

**Limitation**: Applications that render exclusively via GDI (e.g., the 32-bit
Steam.exe bootstrapper) do not produce D3D11/DXGI swapchain presents. The live
session window would remain blank until a D3D-capable process launches. This has
been mitigated by extending the GDI window preview system to capture and
publish rasterized frames from GDI drawing operations (`FillRect`, `DrawText`,
`BitBlt`, etc.).

**Mitigation** ([`src/pe_runtime.rs`](../src/pe_runtime.rs:9897)):

1. **GDI frame capture**: Every GDI drawing operation that targets a visible
   window triggers `publish_live_window_preview_if_needed()`, which composites
   window chrome, GDI window surface content, CEF overlay, and cursor into a
   `LiveFrame` and sends it through the live session channel.
2. **Rate-limited publication**: GDI previews are rate-limited to ~30 FPS
   (one publication per 33 ms) to avoid flooding the frame channel.
3. **Periodic re-publication**: During idle periods (when no GDI operations are
   occurring), `republish_gdi_preview()` re-sends the last cached GDI frame
   every ~50 ms via the main execution loop. This ensures the live window
   continuously displays content even when the bootstrapper enters a wait state.
4. **Graceful handover**: Once the guest process starts producing D3D swapchain
   presents, the `published_live_frame` flag is set to `true`, and
   `republish_gdi_preview()` becomes a no-op — real D3D-captured frames take
   over seamlessly.

**Limitation**: GDI previews are rasterized composites — they do not reflect
hardware-accelerated rendering and may have lower quality than native D3D
captures. This is only relevant during the initial bootstrapper phase before
D3D rendering begins.

### D3D9 Requires an Explicit Feature Flag

**Limitation**: Direct3D 9 support is provided via a compatibility shim
([`Direct3D9Shim`](../src/d3d11.rs:862)) that is disabled by default and
gated behind the `RcD3d9NotSupported` error. When enabled, the shim provides
basic fixed-function rendering via Metal translation — including device
creation, vertex/index buffers, textures, state block tracking, and present.

**Reason**: Casa1 focuses on D3D10+ translation via Metal. The D3D9 shim
covers the most common fixed-function patterns but may not handle every
legacy D3D9 API call. Games with complex pixel/vertex shader emulation
or obscure D3D9 extensions may still fail.

**Enabling**: Set the appropriate GE configuration to enable the D3D9 shim:
```json
{ "d3d9": true }
```



### Vulkan Requires MoltenVK on macOS

**Limitation**: Vulkan support on macOS is implemented via MoltenVK, which
translates Vulkan calls to Metal. This adds overhead and may not support all
Vulkan extensions.

**Reason**: macOS does not provide native Vulkan drivers. MoltenVK is the
standard translation layer maintained by the Khronos Group.


### OpenGL Requires ANGLE on macOS

**Limitation**: OpenGL support on macOS is implemented via ANGLE (Almost Native
Graphics Layer Engine), which translates OpenGL ES to Metal. Apple has
deprecated native OpenGL on macOS.

**Reason**: Apple removed OpenGL from macOS 14 (Sonoma). ANGLE provides a
compatibility layer for applications that still require OpenGL.

## Media

### FFmpeg is Optional and Requires System Library

**Limitation**: FFmpeg-backed video and audio decoding requires the `ffmpeg`
feature flag AND a system-installed FFmpeg library. Without it, Casa1 uses
built-in software decoders with limited codec support.

**Reason**: FFmpeg is licensed under LGPL/GPL which may create licensing
concerns for some users. Making it optional allows Casa1 to be distributed
without FFmpeg dependencies.


## Win32 API Coverage

### Some Win32 APIs are Stubbed

**Limitation**: Some Windows API functions are stubbed — they return
`ERROR_CALL_NOT_IMPLEMENTED` or a default value without performing the expected
operation. This is tracked by the import coverage system in
[`src/import_coverage.rs`](../src/import_coverage.rs).

**Reason**: The Win32 API surface is enormous (tens of thousands of functions).
Casa1 implements the most commonly used APIs and stubs the rest to prevent
crashes.

**Impact**: Guest applications that call stubbed APIs may:
- Return default values (often 0 or NULL)
- Report success without performing the operation
- Log a telemetry event for tracking

**Checking coverage**: Run the import coverage report to see which functions
are implemented vs. stubbed:
```bash
cargo run --bin macwin -- import-coverage
```

### .NET Framework is Not Supported

**Limitation**: Guest applications that require the .NET Framework (CLR) will
not run. Casa1 does not include a .NET runtime.

**Reason**: .NET requires a full Common Language Runtime with JIT compilation,
garbage collection, and a large class library. This is beyond the scope of
Casa1's Win32 compatibility layer.


## Networking

### WebSocket Requires Feature Flag

**Limitation**: WebSocket support is not included by default. Guest applications
that use WinHTTP WebSocket extensions will fail without the `websocket` feature.



## Security

### `dev-insecure-tls` Must Never Be Used in Production

**Limitation**: The `dev-insecure-tls` feature disables TLS certificate
verification. It exists solely for development and testing.

**Reason**: Some test environments use self-signed certificates or MITM proxies
for debugging. The feature makes this possible without modifying the application.

**⚠️ WARNING**: Binaries built with `dev-insecure-tls` must NEVER be
distributed or used with real user data. Always verify this feature is disabled
in release builds:
```bash
# Verify the feature is not enabled
cargo build --release -v 2>&1 | grep "dev-insecure-tls"
# Should produce no output
```

## Performance

### Interpreter Mode is Slow

**Limitation**: On Intel Macs (or when JIT is disabled), guest code runs through
the interpreter. This is approximately 10–50× slower than JIT-compiled code.

**Reason**: The interpreter decodes and executes each instruction individually
without caching native code.

### SIGBUS Handler Overhead

**Limitation**: The SIGBUS handler for on-demand guest memory page
synchronization adds overhead for memory-intensive guest applications. See
[`src/jit.rs`](../src/jit.rs) for implementation details.

**Reason**: Guest memory pages must be synchronized between the host's virtual
memory system and Casa1's `MemoryImage` on demand. This is triggered by SIGBUS
signals when the JIT accesses unmapped pages.

## Platform

### macOS Only

**Limitation**: Casa1 only runs on macOS. There are no plans to support Linux
or Windows as host platforms.

**Reason**: Casa1 relies on Metal, CoreAudio, and other macOS-specific
frameworks for GPU and audio translation.

### Minimum macOS 13 (Ventura)

**Limitation**: Casa1 requires macOS 13 (Ventura) or later. It will not run on
Monterey, Big Sur, or earlier.

**Reason**: Casa1 uses Metal 3 features and `MAP_JIT` APIs that require macOS
13+ for reliable operation.

## Reporting Additional Limitations

If you encounter a limitation not listed here, please open a GitHub issue with:

1. The guest application name and version
2. The expected behavior vs. actual behavior
3. Any error messages or log output
4. Your macOS version and Mac model
