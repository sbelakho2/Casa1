//! Build script: emits `CASA1_REFERENCE_TARGET`, the compiler target triple
//! of the reference executable (e.g. `x86_64-pc-windows-msvc`).
//!
//! The triple comes from the build script's `TARGET` environment variable —
//! the `TARGET` var is only defined for build scripts, never for the crate
//! being compiled, so `env!("TARGET")` is not possible on stable Rust.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=CASA1_REFERENCE_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
