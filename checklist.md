# Casa1 100% Completion Checklist

## Definition Of 100%

- [x] The default workspace builds cleanly with no compile errors.
- [x] All Rust formatting is clean and enforced by CI.
- [x] All warnings are either fixed or explicitly justified with targeted attributes.
- [x] All unit, integration, fuzz smoke, and benchmark compile targets are healthy.
- [x] Unsafe, FFI, JIT, signal, parser, and network boundaries are audited and covered by tests.
- [x] Security-sensitive development shortcuts are removed or gated behind explicit non-release features.
- [x] External side effects are isolated from default tests and normal local validation.
- [x] The release artifact has documented entitlements, signing, packaging, and runtime requirements.

## Current Build And Formatting Blockers

- [x] Fix the `create_direct_sound_buffer` API drift in `tests/section10.rs` by passing the new `caps` and `buffer_size_bytes` arguments expected by `src/audio.rs`.
- [x] Rerun `cargo check --all-targets` and confirm it exits successfully.
- [x] Run `cargo fmt --all` or manually apply rustfmt-compatible formatting to all affected files.
- [x] Rerun `cargo fmt --all -- --check` and confirm it exits successfully.
- [x] Review all current `cargo check --all-targets` warnings and classify them as real bugs, dead code, intentional compatibility shims, or test-only noise.
- [x] Remove unused imports, unused variables, and useless comparisons in tests and source files.
- [x] Replace broad warning noise with narrow `#[allow(...)]` attributes only where compatibility requires the code to remain present.
- [x] Add a CI step that fails on formatting drift.
- [x] Add a CI step that fails on compile errors for all targets.
- [x] Add a CI step that reports warning count so regressions are visible.

## Working Tree Hygiene

- [x] Review every modified tracked file and decide whether it belongs in the current project state.
- [x] Remove generated logs and run artifacts from version control unless they are intentional fixtures.
- [x] Decide whether generated PDFs belong in the repo, and move them to fixtures only if tests require them.
- [x] Restore or replace deleted planning/output files only if they are still part of the project workflow.
- [x] Add ignore rules for generated logs, temporary Steam runtime files, build outputs, and local run artifacts.
- [x] Make `Cargo.toml`, `Cargo.lock`, and `fuzz/Cargo.toml` consistent and intentionally updated.
- [x] Document which newly added source modules are part of the supported architecture.
- [x] Ensure no local machine paths or user-specific paths are committed.
- [x] Ensure binary fixtures are documented with origin, purpose, and update process.

## Rust Quality Gates

- [x] Run `cargo clippy --all-targets --all-features` and triage every finding.
- [x] Decide whether CI should enforce `cargo clippy --all-targets --all-features -- -D warnings`.
- [x] Run `cargo check --no-default-features` and fix feature-gating gaps.
- [x] Run `cargo check --all-targets --features metal` and fix platform-gating gaps.
- [x] Run `cargo check --all-targets --features vulkan` and fix platform-gating gaps.
- [x] Run `cargo check --all-targets --features opengl` and fix platform-gating gaps.
- [x] Run `cargo check --all-targets --features websocket` and fix optional WebSocket build gaps.
- [x] Run `cargo check --all-targets --features ffmpeg` on a machine with FFmpeg dependencies available.
- [x] Ensure optional features do not accidentally require unavailable system libraries in default builds.
- [x] Replace repeated unchecked parsing idioms with shared checked helper functions.
- [x] Replace broad `.unwrap()` in production paths with `AppResult` and reason-coded errors.
- [x] Keep `.unwrap()` and `.expect()` in tests only when they improve failure messages.
- [x] Replace production `panic!`, `todo!`, and `unimplemented!` with explicit `AppError` returns.

## Error Model And Reason Codes

- [x] Audit every subsystem to ensure failures map to stable `ReasonCode` values.
- [x] Add missing reason codes for TLS validation failures, buffer limits, invalid guest enum values, parser truncation, and unsupported platform APIs.
- [x] Ensure public API errors include enough context to reproduce the failing guest call.
- [x] Ensure guest-visible errors preserve Windows-compatible last-error or HRESULT behavior where relevant.
- [x] Add tests that reason-code numeric values remain stable.
- [x] Add tests that important host thunks set `last_error` correctly on success and failure.

## JIT And Signal Safety

- [x] Audit `src/jit.rs` SIGBUS handler against async-signal-safety rules.
- [x] Remove or redesign any SIGBUS-handler work that can allocate, lock, call non-signal-safe APIs, or touch invalid Rust references.
- [x] Revisit whether guest page sync should happen in the signal handler or through a safer guard-page/page-fault mechanism.
- [x] Replace relaxed pointer lifetime coordination in the SIGBUS path with a documented acquire/release protocol.
- [x] Ensure `SIGBUS_JIT_RUNTIME` and `SIGBUS_JIT_MEMORY` cannot outlive the referenced objects.
- [x] Ensure recursive SIGBUS handling cannot silently resume into corrupted state.
- [x] Add tests for repeated SIGBUS on the same page and verify loop-break behavior.
- [x] Add tests for faults outside the flat guest memory range.
- [x] Validate `write_volatile` pre-fault offsets with checked arithmetic.
- [x] Ensure pre-fault writes never cross the flat memory mapping boundary.
- [x] Audit MAP_JIT allocation, W^X toggling, and instruction-cache synchronization.
- [x] Verify ARM64 code emission flushes instruction cache after all patching and chaining operations.
- [x] Make block chaining thread-safe while other guest threads may execute compiled code.
- [x] Add self-modifying-code tests for modified code pages, cache invalidation, and recompilation.
- [x] Add tests for direct fast-thunk calls and fallback thunk dispatch.
- [x] Replace silent `FAST_THUNK_MAP.lock().ok()` misses with explicit poison handling or a lock-free/read-mostly structure.
- [x] Benchmark global fast-thunk map contention under multi-threaded guest workloads.
- [x] Add tests for executable memory exhaustion and graceful fallback to interpreter.

## CPU Interpreter And IR Correctness

- [x] Add checked slice helpers for all SIMD/vector byte extraction in `src/cpu.rs`.
- [x] Replace unchecked `try_into().unwrap()` on register byte slices with helper functions that cannot panic.
- [x] Build instruction-level tests for arithmetic flags, carry, overflow, zero, sign, and parity behavior.
- [x] Build instruction-level tests for string instructions and repeat prefixes.
- [x] Build instruction-level tests for segment, TLS, TEB, and PEB interactions.
- [x] Build instruction-level tests for SSE, AVX-shaped, and floating-point operations currently implemented in software.
- [x] Verify x86 and x64 register aliasing behavior for 8-bit, 16-bit, 32-bit, and 64-bit writes.
- [x] Verify stack alignment across host thunk calls, callbacks, SEH, and JIT exits.
- [x] Audit CPUID leaf behavior against expected Windows guest assumptions.
- [x] Add differential tests that compare interpreter and JIT output for the same IR blocks.
- [x] Add property tests for IR optimizer transformations preserving CPU state.
- [x] Ensure unsupported instructions fail with precise reason codes instead of generic failures.

## PE Loader And Runtime Dispatch

- [x] Split `src/pe_runtime.rs` into smaller host thunk modules by subsystem.
- [x] Generate or centralize host thunk metadata so argument counts, names, and last-error behavior stay consistent.
- [x] Replace guest-controlled enum transmutes in WinHTTP WebSocket thunks with validated conversions.
- [x] Replace guest-controlled close-status transmutes with validated conversions.
- [x] Audit every `std::mem::transmute` in runtime and CPU/JIT code for ABI and value validity.
- [x] Add guest pointer read/write helpers that check address ranges, size overflow, and partial writes consistently.
- [x] Replace direct guest-memory loops with shared helpers where possible.
- [x] Add tests for invalid guest pointers on every major host thunk family.
- [x] Add tests for truncated UTF-16 strings, non-terminated strings, and invalid surrogate pairs.
- [x] Add tests for PE import resolution, delay-load imports, forwarded exports, and missing DLL behavior.
- [x] Add tests for relocation edge cases and malformed relocation blocks.
- [x] Add tests for TLS callbacks, process attach/detach ordering, and loader-lock-sensitive behavior.
- [x] Audit COM object lifetime and reference counting for use-after-free and leaks.
- [x] Add leak-oriented tests for COM/OLE object creation and release cycles.
- [x] Ensure all host callback paths preserve guest register and stack invariants.

## SEH, VEH, And Unwind Handling

- [x] Rework VEH dispatch so handler callbacks are not invoked while holding the global VEH mutex.
- [x] Add tests for nested exceptions during VEH dispatch.
- [x] Add tests for adding/removing VEH handlers while exceptions are being dispatched.
- [x] Add recursion and cycle protection to unwind traversal.
- [x] Validate stack pointer alignment and readability during frame unwinding.
- [x] Add tests for corrupt unwind metadata, missing runtime functions, and invalid handler addresses.
- [x] Verify Windows-compatible ordering for first-chance and last-chance handlers.
- [x] Add tests for vectored continue handlers.
- [x] Ensure pending guest VEH callbacks cannot grow unbounded.
- [x] Add diagnostics for exception records that cannot be dispatched.

## Win32, User32, GDI, And Shell Surface

- [x] Audit all Win32 handle tables for stale handle reuse and generation safety.
- [x] Add handle-generation IDs or equivalent protection where stale handles can alias new objects.
- [x] Audit synchronization primitives for Windows-compatible wait semantics.
- [x] Add tests for mutex, event, semaphore, wait-all, wait-any, timeout, and abandoned behavior.
- [x] Validate file I/O semantics for sharing modes, creation disposition, truncation, append, and file pointer behavior.
- [x] Validate registry path canonicalization and case-insensitivity.
- [x] Replace unchecked `iconv` output allocation arithmetic with checked arithmetic.
- [x] Add tests for very large code-page conversion inputs that should fail safely.
- [x] Add tests for invalid and unsupported code pages.
- [x] Ensure User32 window/message behavior does not touch AppKit APIs in headless tests or CLI paths.
- [x] Add tests for message queue ordering, timer messages, keyboard input, mouse input, and focus changes.
- [x] Audit GDI/GDI+ object lifetime and bitmap buffer ownership.
- [x] Add tests for GDI resource cleanup under repeated create/destroy cycles.

## macOS AppKit, Metal, And Platform FFI

- [x] Ensure all AppKit calls run on the main thread where required.
- [x] Ensure headless CLI/test paths never eagerly call AppKit screen/window APIs.
- [x] Centralize Objective-C and CoreFoundation ownership conventions.
- [x] Wrap IOSurface references in RAII types that call `CFRelease` exactly once.
- [x] Ensure IOSurface lock/unlock happens through guards that unlock on every return path.
- [x] Add checked arithmetic for IOSurface width, height, stride, and pixel size calculations.
- [x] Validate IOSurface destination stride is at least `width * 4` before writes.
- [x] Add tests or smoke checks for IOSurface upload, texture aliasing, and release behavior.
- [x] Document Metal drawable retain/release assumptions around swapchain presentation.
- [x] Add runtime macOS version checks for Metal APIs whose availability depends on OS version.
- [x] Gate mesh shader and ray tracing paths on both GPU family and OS availability.
- [x] Add graceful fallbacks for unsupported Metal features.
- [x] Add a Metal device capability report in diagnostics.
- [x] Add tests for Metal backend resource creation and destruction without leaks.
- [x] Add tests for command buffer failure paths and error propagation.

## Direct3D, Vulkan, OpenGL, And Shader Translation

- [x] Validate D3D10-to-D3D11 adapter behavior against expected D3D10 API semantics.
- [x] Add tests for D3D11 resource creation, views, mapping, updates, copies, and deferred contexts.
- [x] Add tests for D3D12 descriptor heaps, root signatures, command lists, fences, and barriers.
- [x] Add tests for DXGI format conversion edge cases.
- [x] Add tests for invalid resource dimensions and unsupported formats returning precise errors.
- [x] Ensure Vulkan handle tables reject stale, unknown, and wrong-type handles.
- [x] Validate Vulkan state updates happen only after input validation succeeds.
- [x] Add malformed SPIR-V tests, including truncated instructions and invalid operands.
- [x] Confirm SPIR-V zero-word-count handling is covered by tests.
- [x] Add shader translation tests for resource bindings, samplers, push constants, and specialization constants.
- [x] Add DXIL parser tests for malformed container offsets and oversized chunks.
- [x] Add tests for GLSL translation errors and unsupported OpenGL features.
- [x] Add cross-backend golden tests where D3D, Vulkan, and OpenGL shims should produce equivalent frame signatures.

## Audio, MIDI, Video, And Media

- [x] Finish DirectSound API migration in tests and callers.
- [x] Add tests for primary versus secondary DirectSound buffer flags.
- [x] Add tests for DirectSound buffer size, cursor, looping, lock/unlock, and underflow behavior.
- [x] Add XAudio2 tests for channel mixing, resampling, mastering voices, submix voices, and latency bounds.
- [x] Add audio ring buffer tests for wraparound, concurrent producer/consumer, underrun, and overrun.
- [x] Audit real audio backend thread lifetime and shutdown ordering.
- [x] Add MIDI parser tests for malformed messages and long SysEx data.
- [x] Add video decoder tests for malformed containers, unsupported codecs, and timestamp behavior.
- [x] Ensure FFmpeg-backed code is fully feature-gated and has a no-FFmpeg fallback.
- [x] Add media container fuzzing to CI smoke runs.

## Network, WinHTTP, WinINet, Steam Protocols

- [x] Replace `danger_accept_invalid_certs(true)` with normal TLS validation for production/default builds.
- [x] Gate insecure TLS behavior behind an explicit development feature or test-only client builder.
- [x] Replace placeholder Steam certificate pins with real SPKI SHA-256 pins or remove default pins until real values are available.
- [x] Add tests proving pinned hosts fail closed when certificates are missing or mismatched.
- [x] Add tests proving unpinned HTTPS hosts still use normal CA validation.
- [x] Add size limits for socket receive queues.
- [x] Add size limits for WinHTTP request bodies.
- [x] Add size limits for WinHTTP WebSocket send buffers.
- [x] Add size limits for WinHTTP WebSocket receive spill buffers.
- [x] Add size limits for WinINet request and response buffers.
- [x] Add limits for header count and total header bytes in HTTP parsing.
- [x] Add limits for WebSocket frame size.
- [x] Add limits for pending socket accept queues and backlog behavior.
- [x] Replace silent port-parse fallback to port 0 with explicit errors.
- [x] Add timeout and cancellation behavior tests for real TCP and HTTP paths.
- [x] Add lock-poison recovery or explicit poison handling for global QUIC state.
- [x] Add resource cleanup tests for sockets, sessions, requests, WebSockets, and QUIC handles.
- [x] Add fuzz targets for HTTP request parsing, response parsing, headers, WebSocket frames, and URL handling.
- [x] Replace unchecked Steam protocol slice parsing with checked read helpers.
- [x] Add malformed Steam depot, manifest, STUN, CM, and encrypted-frame tests.
- [x] Ensure Steam zero-touch tests do not contact real external services by default.
- [x] Gate real Steam integration tests behind explicit environment variables or ignored tests.

## Security And Sandbox

- [x] Complete an unsafe-code inventory with rationale for every unsafe block.
- [x] Add `SAFETY:` comments to unsafe blocks that explain the invariant being upheld.
- [x] Audit sandbox path canonicalization for symlink, `..`, case, Unicode normalization, and mount boundary bypasses.
- [x] Add tests for sandbox path traversal and symlink escape attempts.
- [x] Audit entitlement XML handling and replace string-based XML sanitization where parser-level validation is required.
- [x] Add tests for DOCTYPE, entity expansion, unusual whitespace, comments, and CDATA edge cases in entitlement XML.
- [x] Audit cryptographic uses for placeholder keys, fixed IVs, weak hashes, and development-only bypasses.
- [x] Clearly separate compatibility hash implementations from security hash implementations.
- [x] Add certificate, signature, and Authenticode tests for malformed, expired, wrong-chain, and unsupported algorithms.
- [x] Add security documentation for threat model and non-goals.
- [x] Add release checks that fail if insecure development flags are enabled.

## File System, Installer, App Bundle, Printing, And WSL

- [x] Audit installer file writes for atomicity and rollback behavior.
- [x] Add tests for partial installer failure and cleanup.
- [x] Add tests for app bundle creation, Info.plist contents, entitlements, icon validation, and signing inputs.
- [x] Replace test assertions that swallow icon validation errors with assertions that preserve the error text.
- [x] Add tests for filesystem case-insensitivity and Windows path normalization.
- [x] Add tests for long paths, reserved device names, alternate separators, and invalid characters.
- [x] Add tests for print spool lifecycle, PDF output validity, and cleanup of generated documents.
- [x] Ensure WSL integration is disabled or gracefully unavailable on macOS where unsupported.

## Diagnostics, Telemetry, Logging, And Crash Recovery

- [x] Ensure diagnostics never panic on truncated input buffers.
- [x] Replace unchecked dump parsing slices with checked read helpers.
- [x] Add tests for malformed minidumps and trace files.
- [x] Add structured logs for major subsystem boundaries without leaking secrets.
- [x] Add log redaction for tokens, cookies, credentials, and certificate data.
- [x] Add crash recovery tests for corrupted state, partial writes, and repeated crashes.
- [x] Add telemetry opt-in/opt-out behavior tests.
- [x] Add trace schema versioning tests for backward compatibility.
- [x] Add a command that prints environment, features, platform, graphics, audio, and security readiness.

## Test Suite Hardening

- [x] Make `cargo test --lib` pass reliably.
- [x] Make `cargo test --bins` pass reliably.
- [x] Make `cargo test --tests` pass reliably for non-external tests.
- [x] Mark long-running, external, hardware-specific, or real-Steam tests as ignored by default.
- [x] Add a fast smoke test command for pre-commit validation.
- [x] Add a full nightly test command for exhaustive validation.
- [x] Replace brittle test panics with `assert_eq!`, `assert_matches!`, or helper assertions that show actual values.
- [x] Remove unused test imports and variables.
- [x] Ensure tests clean up generated files and temporary directories.
- [x] Add deterministic seeds for randomized tests.
- [x] Add regression tests for every bug fixed from this checklist.
- [x] Add tests for all public modules exported from `src/lib.rs`.
- [x] Add coverage reporting and define minimum coverage thresholds for critical parser/security/runtime modules.

## Fuzzing And Negative Testing

- [x] Ensure every fuzz target builds with `cargo fuzz build`.
- [x] Add fuzz targets for PE headers, section tables, imports, relocations, resources, and manifests.
- [x] Add fuzz targets for DXIL and SPIR-V parser paths.
- [x] Add fuzz targets for Steam protocol frames and depot manifests.
- [x] Add fuzz targets for WinHTTP/WinINet header and URL parsing.
- [x] Add fuzz targets for registry paths and filesystem canonicalization.
- [x] Add fuzz targets for media containers and video packet parsing.
- [x] Add a minimal fuzz smoke run to CI.
- [x] Store minimized crash reproducers as fixtures.
- [x] Add regression tests for every accepted fuzz crash.

## Performance And Scalability

- [x] Establish baseline benchmark numbers for interpreter, JIT compile, JIT execute, PE load, graphics submission, audio mix, and network mock paths.
- [x] Add benchmarks for large PE images and high import counts.
- [x] Add benchmarks for shader translation and pipeline creation.
- [x] Add benchmarks for DirectSound/XAudio2 mixing at common sample rates.
- [x] Add benchmarks for socket and WebSocket buffer behavior under configured caps.
- [x] Add benchmarks for fast-thunk dispatch under multi-threaded guest workloads.
- [x] Add memory usage tracking for large guest processes.
- [x] Add leak checks or long-run stress tests for graphics, audio, networking, COM, and PE runtime handles.
- [x] Define acceptable performance targets before optimizing further.

## Documentation And Developer Experience

- [x] Document supported host platforms, CPU architectures, and required macOS versions.
- [x] Document required system dependencies for Metal, FFmpeg, fuzzing, benchmarks, and tests.
- [x] Document feature flags and which ones are default, optional, experimental, or release-blocking.
- [x] Document the local validation command sequence.
- [x] Document how to run external integration tests safely.
- [x] Document how to add a new host thunk with tests and reason codes.
- [x] Document unsafe-code review rules for the project.
- [x] Document release signing, entitlements, notarization, and packaging steps.
- [x] Document known limitations separately from code comments so source files stay focused.

## CI And Release Readiness

- [x] Add CI jobs for format, check, clippy, unit tests, integration tests, fuzz build, and docs.
- [x] Add a macOS CI job for Metal/AppKit-gated code paths where available.
- [x] Add a no-default-features CI job.
- [x] Add selected feature-combination CI jobs.
- [x] Add a nightly sanitizer job where supported.
- [x] Add dependency audit checks.
- [x] Add license and supply-chain checks for dependencies.
- [x] Add release artifact reproducibility checks where feasible.
- [x] Add release smoke tests for generated app bundles and command-line tools.
- [x] Add a final release gate that requires all checklist release blockers to be checked.
