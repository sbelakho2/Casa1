#![no_main]

use casa1::pe;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse_summary(data);
    let second = parse_summary(data);
    assert_eq!(
        first, second,
        "pe::parse produced nondeterministic summaries for identical input"
    );
});

fn parse_summary(data: &[u8]) -> String {
    match pe::parse(data) {
        Ok(image) => format!(
            "ok:{}:{}:{}:{}:{}:{}:{}",
            image.machine,
            image.sections.len(),
            image.imports.len(),
            image.delay_imports.len(),
            image.exports.len(),
            image.relocations.len(),
            image.tls_directory.as_ref().map(|tls| tls.callbacks.len()).unwrap_or(0)
        ),
        Err(error) => format!(
            "err:{}:{}:{}",
            error.code.as_u32(),
            error.message,
            error.reproduction_hints.join("|")
        ),
    }
}