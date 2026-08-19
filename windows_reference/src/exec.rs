//! Platform-neutral dispatch for the reference executable.
//!
//! On Windows the executors are real Win32/CRT calls (the reference IS
//! Windows). On any other platform the crate still compiles and runs, but
//! every vector produces an explicit `unsupported_platform` result — the
//! workspace check and the differential comparison both fail loudly if a
//! non-Windows reference output is ever treated as Windows truth.

use serde_json::Value;

#[cfg(not(windows))]
#[path = "stub.rs"]
mod stub;
#[cfg(windows)]
#[path = "win32.rs"]
mod win32;

#[cfg(not(windows))]
use stub as backend;
#[cfg(windows)]
use win32 as backend;

/// Execute one vector against the platform backend.
pub fn execute(category: &str, input: &Value) -> Value {
    backend::execute(category, input)
}
