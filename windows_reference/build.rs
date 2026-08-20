//! Build script: emits `CASA1_REFERENCE_TARGET`, the compiler target triple
//! of the reference executable (e.g. `x86_64-pc-windows-msvc`).
//!
//! The triple comes from the build script's `TARGET` environment variable —
//! the `TARGET` var is only defined for build scripts, never for the crate
//! being compiled, so `env!("TARGET")` is not possible on stable Rust.
//!
//! On Windows the build script additionally embeds an application
//! compatibility manifest into the reference executable: WITHOUT a manifest,
//! GetVersionExW / VerifyVersionInfoW are shimmed by the OS to the
//! pre-Windows-10 version (6.2.9200) for a manifestless process, which would
//! break the `version` differential's Windows-10-family shape contract.  A
//! manifested process reports the REAL version (10.0.<build>), consistent
//! with RtlGetVersion.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=CASA1_REFERENCE_TARGET={target}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // Windows 10 compatibility GUID; a manifest with a supportedOS
        // entry makes GetVersionExW report the actual OS version.
        let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
"#;
        let out = std::env::var("OUT_DIR").expect("OUT_DIR");
        let path = std::path::Path::new(&out).join("casa1-reference.manifest");
        std::fs::write(&path, manifest).expect("write reference manifest");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", path.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
