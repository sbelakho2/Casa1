//! Build script: emits the `CASA1_COMMIT_SHA` and `CASA1_DIRTY` environment
//! variables used by the steam-bootstrap run artifact provenance.
//!
//! Both degrade gracefully when git (or the `.git` directory) is absent:
//! `CASA1_COMMIT_SHA` falls back to `unknown` and `CASA1_DIRTY` to `true`
//! (an unprovable-clean tree is reported dirty, never the reverse).

use std::process::Command;

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn main() {
    let commit_sha = git_output(&["rev-parse", "HEAD"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let dirty = git_output(&["status", "--porcelain"])
        .map(|porcelain| !porcelain.is_empty())
        .unwrap_or(true);
    println!("cargo:rustc-env=CASA1_COMMIT_SHA={commit_sha}");
    println!("cargo:rustc-env=CASA1_DIRTY={dirty}");
    println!("cargo:rerun-if-changed=build.rs");
    if std::path::Path::new(".git/HEAD").exists() {
        println!("cargo:rerun-if-changed=.git/HEAD");
    }
}
