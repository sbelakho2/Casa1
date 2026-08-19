//! Non-Windows stubs. Every vector reports `unsupported_platform`; the
//! differential comparison treats this as a diff on every vector, which is
//! the correct behavior (a non-Windows build is never Windows truth).

use serde_json::{Value, json};

pub fn execute(category: &str, _input: &Value) -> Value {
    json!({ "error": "unsupported_platform", "category": category })
}
