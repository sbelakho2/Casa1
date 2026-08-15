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
});
