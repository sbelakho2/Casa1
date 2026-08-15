#![no_main]

use casa1::vkgl::SpirvTranslator;
use libfuzzer_sys::fuzz_target;

const SPIRV_MAGIC: u32 = 0x0723_0203;

fuzz_target!(|data: &[u8]| {
    let words = to_words(data);
    let first = parse_summary(&words);
    let second = parse_summary(&words);
    assert_eq!(
        first, second,
        "SpirvTranslator::parse produced nondeterministic summaries for identical input"
    );
});

fn parse_summary(words: &[u32]) -> String {
    let mut translator = SpirvTranslator::new();
    match translator.parse(words) {
        Ok(()) => {
            // A successful parse requires a valid SPIR-V header, so the magic
            // number of the input must match.
            assert_eq!(
                words.first().copied(),
                Some(SPIRV_MAGIC),
                "parse succeeded without the SPIR-V magic number"
            );
            // Parsing is idempotent: a second translator must also succeed.
            let mut second = SpirvTranslator::new();
            assert!(
                second.parse(words).is_ok(),
                "parse succeeded once but failed on re-parse"
            );
            "ok".to_string()
        }
        Err(e) => format!("err:{}:{}", e.code.as_u32(), e.message),
    }
}

fn to_words(data: &[u8]) -> Vec<u32> {
    // Convert raw bytes to u32 words (little-endian).
    // If the input length is not a multiple of 4, pad with zeroes.
    let mut padded = data.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(0);
    }
    padded
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}
