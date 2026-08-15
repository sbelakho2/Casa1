#![no_main]

use casa1::video_decoder::{parse_h264_annex_b, parse_h264_sps};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse_summary(data);
    let second = parse_summary(data);
    assert_eq!(
        first, second,
        "video packet parsing produced nondeterministic summaries for identical input"
    );
});

fn parse_summary(data: &[u8]) -> String {
    // Parse H.264 Annex B byte stream into NAL units
    let nalus = parse_h264_annex_b(data);

    // Invariants on the split: NAL units are non-empty, non-overlapping
    // slices of the input, so their total size never exceeds it.
    let mut total_len = 0usize;
    for nalu in &nalus {
        assert!(!nalu.is_empty(), "NAL unit must not be empty");
        total_len += nalu.len();
    }
    assert!(
        total_len <= data.len(),
        "NAL units total {total_len} exceeds input length {}",
        data.len()
    );

    let mut sps_summaries: Vec<String> = Vec::new();
    for nalu in &nalus {
        // NAL unit type is in the first byte's lower 5 bits
        let nal_type = nalu[0] & 0x1F;
        // Exercise the SPS parser on every NAL payload: it is the only
        // deep bit-level H.264 parser and must handle arbitrary bytes.
        let (w, h) = parse_h264_sps(nalu);
        if nal_type == 7 {
            sps_summaries.push(format!("sps:{}x{}", w, h));
        }
    }

    format!("nalus:{}:{}", nalus.len(), sps_summaries.join(","))
}
