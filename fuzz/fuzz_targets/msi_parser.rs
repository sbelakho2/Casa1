#![no_main]

use casa1::installer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = installer::msi_fuzz_summary(data);
    let second = installer::msi_fuzz_summary(data);
    assert_eq!(
        first, second,
        "installer::parse_msi_script produced nondeterministic summaries for identical input"
    );
});