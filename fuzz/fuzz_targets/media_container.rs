#![no_main]

use casa1::media::MediaShim;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shim = MediaShim::new("C:/fuzz/ge");
    let first = format!("{:?}", shim.classify_input(data));
    let second = format!("{:?}", shim.classify_input(data));
    assert_eq!(
        first, second,
        "media::parse_container produced nondeterministic classifications for identical input"
    );
});