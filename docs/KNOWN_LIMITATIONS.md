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

### Vulkan Requires MoltenVK on macOS

**Limitation**: Vulkan support on macOS is implemented via MoltenVK, which
translates Vulkan calls to Metal. This adds overhead and may not support all
Vulkan extensions.

**Reason**: macOS does not provide native Vulkan drivers. MoltenVK is the
standard translation layer maintained by the Khronos Group.


### OpenGL Is the Built-In Software Compatibility Implementation

**Limitation**: Guest OpenGL is served by Casa1's own OpenGL 1.1 compatibility
machine ([`src/runtime/dispatch/opengl.rs`](../src/runtime/dispatch/opengl.rs)):
fixed-function state, matrix stacks, immediate mode, client arrays, texture
state, WGL contexts, and GLU helpers — rendered by a software rasterizer into a
per-context framebuffer. This is a real semantic implementation for legacy
fixed-function OpenGL, not a translation of the host's (deprecated) OpenGL and
not ANGLE.

**Reason**: Apple deprecated native OpenGL on macOS. Casa1's software path is
deterministic and testable; modern-OpenGL features (shader-based core profiles)
and GPU-accelerated OpenGL performance are not provided by it. The final
architecture targets OpenGL → Casa GPU IR → Metal, with the software rasterizer
retained as the deterministic reference/fallback path.

**Impact**: Legacy OpenGL 1.1 applications run semantically; performance is
software-rasterized, and applications requiring OpenGL 2.0+ features do not
have a working path through this surface.

## Media

### FFmpeg is Optional and Requires System Library

**Limitation**: FFmpeg-backed video and audio decoding requires the `ffmpeg`
feature flag AND a system-installed FFmpeg library. Without it, Casa1 uses
built-in software decoders with limited codec support.

**Reason**: FFmpeg is licensed under LGPL/GPL which may create licensing
concerns for some users. Making it optional allows Casa1 to be distributed
without FFmpeg dependencies.


## Win32 API Coverage

### The API-Compatibility Ledger Is the Authoritative Gap List

**Limitation**: Win32 compatibility is not binary — an export can be callable
without being exact, and a subsystem can be absent even when its failure
contract is implemented faithfully. The API database ([`src/api_database.rs`](../src/api_database.rs))
now tracks this on independent axes per export — dispatch level, semantic
fidelity (exact / restricted / approximate / synthetic-environment /
canned-response) and subsystem capability (full / partial / absent) — and this
document's authoritative, machine-generated part is the
[API-Compatibility Ledger](KNOWN_LIMITATIONS.compat.md). The ledger is emitted
from the registry itself, so the limitations document can never drift from the
database:

```bash
cargo run --bin casa1-oracle -- api-limitations --out docs/KNOWN_LIMITATIONS.compat.md
```

**Impact**: Regenerate the ledger after any dispatch/metadata change that
alters semantic truth. Hand-maintained sections below describe the same gaps
in prose; the ledger is the precise per-API statement.

**Checking coverage**: Run the import coverage report to see which guest
imports reach implemented vs. canned/unsupported semantics:
```bash
cargo run --bin macwin -- import-coverage
```

### .NET Framework is Not Supported

**Limitation**: Guest applications that require the .NET Framework (CLR) will
not run. Casa1 does not include a .NET runtime.

**Reason**: .NET requires a full Common Language Runtime with JIT compilation,
garbage collection, and a large class library. This is beyond the scope of
Casa1's Win32 compatibility layer.

**Modeled behavior**: `mscoree.dll`/`mscorwks.dll` export dispatch is callable
and honest — activation answers `COR_E_CLRNOTAVAILABLE`, directory queries fail
as they would on a Windows machine with no CLR installed — but the ledger
records the CLR capability as **absent** (fidelity `synthetic-environment`).
Six callable exports must never be read as ".NET support".


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
