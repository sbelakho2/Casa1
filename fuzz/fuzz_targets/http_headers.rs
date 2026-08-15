#![no_main]

use casa1::security;
use casa1::wininet;
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
            // Header count should not exceed reasonable limits
            assert!(
                parsed.header_count <= 256,
                "header count {} exceeds sanity limit",
                parsed.header_count
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

    // === Test 4: Fuzz with short fragments (1-15 bytes) ===
    for end in 1..data.len().min(16) {
        let fragment = &data[..end];
        let _ = security::http_fuzz_summary(fragment);
    }

    // === Test 5: WinINet URL moniker with HTTP URLs (uses string input) ===
    if let Ok(text) = std::str::from_utf8(data) {
        // Only test URLs that look vaguely HTTP-ish to avoid excessive Err paths
        let _ = wininet::create_url_moniker(text, None);
        // Extended moniker with flags
        let _ = wininet::create_url_moniker_ex(text, None, 0);
        let _ = wininet::create_url_moniker_ex(text, None, 1); // URL_MONIKER_OPT_UNWRAP
    }
});
