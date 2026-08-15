#![no_main]

use casa1::vkgl::SpirvTranslator;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse_summary(data);
    let second = parse_summary(data);
    assert_eq!(
        first, second,
        "SpirvTranslator::parse produced nondeterministic summaries for identical input"
    );
});

fn parse_summary(data: &[u8]) -> String {
    // Convert raw bytes to u32 words (little-endian).
    // If the input length is not a multiple of 4, pad with zeroes.
    let mut padded = data.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(0);
    }
    let words: Vec<u32> = padded
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();

    let mut translator = SpirvTranslator::new();
    match translator.parse(&words) {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("err:{}:{}", e.code.as_u32(), e.message),
    }
}
