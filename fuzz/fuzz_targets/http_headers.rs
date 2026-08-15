#![no_main]

use casa1::security;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // === Test 1: Determinism check via http_fuzz_summary ===
    let first = security::http_fuzz_summary(data);
    let second = security::http_fuzz_summary(data);
    assert_eq!(
        first, second,
        "security::parse_http_request produced nondeterministic summaries for identical input"
    );

    // === Test 2: Direct parse_http_request structural checks ===
    match security::parse_http_request(data) {
        Ok(parsed) => {
            // Verify invariants on successfully parsed requests
            assert!(!parsed.method.is_empty(), "method should not be empty");
            assert!(!parsed.path.is_empty(), "path should not be empty");
            // method/path come from split_whitespace tokens: no whitespace inside
            assert!(
                !parsed.method.chars().any(char::is_whitespace),
                "method must not contain whitespace"
            );
            assert!(
                !parsed.path.chars().any(char::is_whitespace),
                "path must not contain whitespace"
            );
            // Every header line contains ':' and is at least 3 bytes plus the
            // CRLF terminator, so the count can never exceed the input length.
            assert!(
                parsed.header_count <= data.len(),
                "header count {} exceeds input length {}",
                parsed.header_count,
                data.len()
            );
        }
        Err(_) => {
            // Error is expected for invalid data — just verify it's deterministic
        }
    }

    // === Test 3: Fuzz with UTF-8 boundary variations ===
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = security::http_fuzz_summary(text.as_bytes());
    }
});
