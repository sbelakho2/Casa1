//! Casa1 — Windows compatibility layer for macOS.
//!
//! This crate implements a comprehensive Windows API compatibility layer
//! that allows Windows x86/x64 binaries to run on Apple Silicon and macOS.
//! It includes CPU emulation, JIT compilation, PE loading, Win32 API shims,
//! Direct3D/DirectSound/XAudio2 translation to Metal/CoreAudio, and more.
//!
//! # Documentation
//!
//! - [Platform Support](../docs/PLATFORM_SUPPORT.md) — supported host platforms and architectures
//! - [Dependencies](../docs/DEPENDENCIES.md) — system and Rust dependencies
//! - [Feature Flags](../docs/FEATURE_FLAGS.md) — compile-time feature configuration
//! - [Local Validation](../docs/VALIDATION.md) — pre-commit and CI validation commands
//! - [External Tests](../docs/EXTERNAL_TESTS.md) — running integration tests with external services
//! - [Host Thunk Guide](../docs/HOST_THUNK_GUIDE.md) — how to add new host thunks
//! - [Unsafe Code Review](../docs/UNSAFE_REVIEW.md) — rules for writing and reviewing unsafe code
//! - [Release Process](../docs/RELEASE_PROCESS.md) — signing, notarization, and packaging
//! - [Known Limitations](../docs/KNOWN_LIMITATIONS.md) — current architectural and implementation limits
//!
//! # Feature Flags
//!
//! Metal is the **mandatory** host backend on macOS: the `metal`/`objc`/
//! `core-foundation` dependencies are unconditional and there is no `metal`
//! feature flag — every build includes the Metal backend.
//!
//! - `vulkan` (default): Vulkan **guest-translation** path (`vulkan-1.dll`
//!   thunk registration); the host backend remains Metal
//! - `opengl` (default): OpenGL **guest-translation** path (`opengl32.dll`
//!   thunk registration); the host backend remains Metal
//! - `moltenvk`: Vulkan via MoltenVK (implies `vulkan`)
//! - `angle`: OpenGL via ANGLE (implies `opengl`)
//! - `websocket`: WebSocket support via tungstenite
//! - `ffmpeg`: FFmpeg-backed video/audio decoding
//! - `proptest`: Property-based testing support
//! - `dev-insecure-tls`: Development-only insecure TLS (**NOT for release**)
//!
//! # Supported Platforms
//!
//! - macOS 13+ (Ventura) on Apple Silicon (aarch64) — primary target
//! - macOS 13+ (Ventura) on Intel (x86_64) — secondary target
//!
//! # Module Architecture
//!
//! The crate is organized into the following subsystems:
//!
//! **Core emulation:**
//! - [`cpu`] — x86/x64 CPU interpreter and JIT backend
//! - [`jit`] — ARM64 JIT compiler with block chaining and SIGBUS handling
//! - [`pe`] — PE image parsing (headers, sections, imports, relocations)
//! - [`pe_runtime`] — PE loader and runtime dispatch (host thunks)
//! - [`seh`] — Structured Exception Handling and Vectored Exception Handling
//! - [`threads`] — Guest thread management
//! - [`reason`] — Stable error/reason codes for all failure modes
//!
//! **Win32 API translation:**
//! - [`win32`] — Core Win32 kernel/user API shims
//! - [`user32`] — Window management and message dispatch
//! - [`gdiplus_render`] — GDI+ rendering via Metal/CoreGraphics
//! - [`d2d`] — Direct2D translation
//! - [`dwrite`] — DirectWrite text rendering
//! - [`print`] — Print spooler and PDF generation
//! - [`icon`] — Icon extraction and cursor handling
//!
//! **Graphics translation (D3D → Metal/Vulkan/OpenGL):**
//! - [`d3d10`] — Direct3D 10 to Metal/Vulkan translation
//! - [`d3d11`] — Direct3D 11 to Metal/Vulkan translation
//! - [`d3d12`] — Direct3D 12 to Metal/Vulkan translation
//! - [`gfx`] — Shared graphics pipeline infrastructure
//! - [`metal_backend`] — Metal GPU backend
//! - [`metal_renderer`] — Metal rendering pipeline
//! - [`vkgl`] — Vulkan/OpenGL backend abstraction
//! - [`shader`] — Shader translation (DXIL, SPIR-V)
//! - [`shader_compiler`] — Async shader compilation pipeline
//! - [`async_pipeline_compiler`] — Background pipeline state compilation
//!
//! **Audio and media:**
//! - [`audio`] — DirectSound/XAudio2 translation
//! - [`audio_format`] — Audio format conversion utilities
//! - [`audio_ring_buffer`] — Lock-free ring buffer for audio streaming
//! - [`real_audio`] — Host audio backend (CoreAudio/cpal)
//! - [`midi`] — MIDI parser and synthesizer
//! - [`media`] — Media container parsing
//! - [`video_decoder`] — Video decoding (optional FFmpeg)
//!
//! **Network and Steam:**
//! - [`winhttp`] — WinHTTP API translation
//! - [`wininet`] — WinINet API translation
//! - [`network`] — TLS, certificate pinning, and socket management
//! - [`steam`] — Steam API (ISteamClient) translation
//! - [`steam_acceptance`] — Steam E2E acceptance evaluator (S0-S13)
//! - [`steam_input`] — Steam Input API
//! - [`steam_integration`] — Steam integration (friends, achievements)
//! - [`steam_launch`] — Steam game launch orchestration
//! - [`steam_protocol`] — Steam wire protocol (depot, STUN, CM)
//! - [`steamvr`] — SteamVR translation
//!
//! **Security and sandbox:**
//! - [`security`] — Code signing, Authenticode, certificate validation
//! - [`sandbox`] — Filesystem sandbox with path canonicalization
//! - [`anticheat`] — Anti-cheat compatibility shims
//! - [`denuvo`] — Denuvo DRM compatibility layer
//!
//! **File system and storage:**
//! - [`real_fs`] — Host filesystem abstraction (case-insensitive paths, symlinks)
//! - [`canonical`] — Path canonicalization and normalization
//! - [`installer`] — NSIS/MSI installer support
//! - [`scm`] — Service Control Manager
//! - [`app_bundle`] — macOS .app bundle creation
//! - [`wsl`] — WSL guest support
//!
//! **Input and HID:**
//! - [`real_hid`] — Host HID (keyboard, mouse, gamepad)
//!
//! **Diagnostics and monitoring:**
//! - [`logging`] — Structured logging with redaction
//! - [`diagnostics`] — System diagnostics and capability reporting
//! - [`telemetry`] — Opt-in telemetry
//! - [`crash_recovery`] — Crash state recovery and minidump handling
//! - [`trace`] — Guest execution tracing
//! - [`perf`] — Performance counters and benchmarking
//! - [`import_coverage`] — Import dispatch coverage tracking
//!
//! **Guest environment:**
//! - [`ge`] — Guest Environment (Wine prefix equivalent)
//! - [`live`] — Live guest process management
//! - [`runner`] — Guest process runner and I/O multiplexing
//! - [`guest_support`] — Guest-side support library
//! - [`cef_bridge`] — Chromium Embedded Framework bridge
//! - [`webview2`] — WebView2 API translation
//! - [`mac_window`] — macOS native window integration
//!
//! **CLI and auxiliary:**
//! - [`cli`] — CLI argument parsing and command dispatch
//! - [`error`] — Error types and result helpers
//! - [`util`] — Shared utility functions
//! - [`main`](main) — Binary entry point
//! - [`macwin`](bin/macwin.rs) — Main CLI binary
//! - [`casa1-runner`](bin/casa1-runner.rs) — Guest process runner binary
//! - [`casa1-helper`](bin/casa1-helper.rs) — Helper binary for privileged operations
//! - [`casa1-test-guest`](bin/casa1-test-guest.rs) — Guest-mode test harness
//! - [`casa1-oracle`](bin/casa1-oracle.rs) — CPUID oracle binary
//! - [`wmi`] — WMI provider implementation
//! - [`winmm`] — Windows Multimedia API translation

// Naming conventions: Windows and macOS API constants/types use their native
// naming conventions (PascalCase, camelCase, kConstantStyle) for compatibility.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#[macro_use]
extern crate objc;

pub mod anticheat;
pub mod api_coverage;
pub mod api_database;
pub mod app_bundle;
pub mod async_pipeline_compiler;
pub mod audio;
pub mod audio_format;
pub mod audio_ring_buffer;
pub mod canonical;
pub mod cef_bridge;
pub mod cli;
pub mod compatibility_profile;
pub mod cpu;
pub mod crash_recovery;
pub mod d2d;
pub mod d3d10;
pub mod d3d11;
pub mod d3d12;
pub mod denuvo;
pub mod diagnostics;
pub mod dwrite;
pub mod error;
pub mod gdiplus_render;
pub mod ge;
pub mod gfx;
pub mod guest_support;
pub mod host_thunks;
pub mod icon;
pub mod import_coverage;
pub mod installer;
pub mod jit;
pub mod live;
pub mod logging;
pub mod mac_window;
pub mod media;
pub mod metal_backend;
pub mod metal_renderer;
pub mod midi;
pub mod network;
pub mod ntdll;
pub mod oracle_suites;
pub mod pe;
pub mod pe_runtime;
pub mod perf;
pub mod print;
pub mod real_audio;
pub mod real_fs;
pub mod real_hid;
pub mod real_net;
pub mod real_win32;
pub mod reason;
pub mod runner;
pub mod runtime;
pub use crate::runtime::object_manager::ObjectId;
pub use crate::runtime::process::{
    EnvironmentBlock, GuestProcess, InitialProcessContext, ProcessExitState, allocate_guest_pid,
};
pub mod runtime_events;
pub mod sandbox;
pub mod scm;
pub mod security;
pub mod seh;
pub mod shader;
pub mod shader_compiler;
pub mod steam;
pub mod steam_acceptance;
pub mod steam_input;
pub mod steam_integration;
pub mod steam_launch;
pub mod steam_milestones;
pub mod steam_protocol;
pub mod steamvr;
pub mod telemetry;
pub mod threads;
pub mod trace;
pub mod user32;
pub mod util;
pub mod video_decoder;
pub mod vkgl;
pub mod vm;
// WebView2 COM interface types use Windows-style naming (ICoreWebView2*, IID_*).
// These are defined to match the upstream API surface exactly.
#[allow(non_camel_case_types)]
pub mod webview2;
pub mod win32;
pub mod windows_oracle;
pub mod winhttp;
pub mod wininet;
pub mod winmm;
pub mod wmi;
pub mod workloads {
    pub mod steam;
}
pub mod wsl;

pub const PRODUCT_NAME: &str = "Casa1";
pub const CLI_NAME: &str = "macwin";
pub const BUILD_ID: &str = concat!("casa1-", env!("CARGO_PKG_VERSION"));
pub const TRACE_FORMAT_VERSION: u32 = 1;
pub const TRACE_CACHE_VERSION: u32 = 1;
