#![no_main]

use casa1::security;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = security::http_fuzz_summary(data);
    let second = security::http_fuzz_summary(data);
    assert_eq!(
        first, second,
        "security::parse_http_request produced nondeterministic summaries for identical input"
    );
});