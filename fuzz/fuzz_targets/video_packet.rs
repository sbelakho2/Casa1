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

    let mut sps_summaries: Vec<String> = Vec::new();
    for nalu in &nalus {
        // NAL unit type is in the first byte's lower 5 bits
        if !nalu.is_empty() {
            let nal_type = nalu[0] & 0x1F;
            // NAL type 7 = SPS (Sequence Parameter Set)
            if nal_type == 7 {
                let (w, h) = parse_h264_sps(nalu);
                sps_summaries.push(format!("sps:{}x{}", w, h));
            }
        }
    }

    format!("nalus:{}:{}", nalus.len(), sps_summaries.join(","))
}
