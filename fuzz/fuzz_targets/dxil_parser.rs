#![no_main]

use casa1::shader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = shader::fuzz_summary(data);
    let second = shader::fuzz_summary(data);
    assert_eq!(
        first, second,
        "shader::parse_dxil_container produced nondeterministic summaries for identical input"
    );
});