#![no_main]

use casa1::steam;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = steam::registry_path_fuzz_summary(data);
    let second = steam::registry_path_fuzz_summary(data);
    assert_eq!(
        first, second,
        "steam::split_registry_entry produced nondeterministic summaries for identical input"
    );

    // Invariant: an "ok:" summary requires at least 3 non-empty path
    // segments, so the input itself must be non-empty.
    if let Ok(text) = std::str::from_utf8(data) {
        let summary = steam::registry_path_fuzz_summary(data);
        if summary.starts_with("ok:") {
            assert!(!text.is_empty(), "ok summary for empty input");
            assert!(summary.len() > 3, "malformed ok summary: {summary}");
        }
    }
});
