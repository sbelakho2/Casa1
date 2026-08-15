#![no_main]

use casa1::real_fs::parse_ntfs_path;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse_summary(data);
    let second = parse_summary(data);
    assert_eq!(
        first, second,
        "filesystem path parsing produced nondeterministic summaries for identical input"
    );
});

fn parse_summary(data: &[u8]) -> String {
    let input = String::from_utf8_lossy(data);
    let trimmed = input.trim();

    // Test NTFS path parsing (ADS detection)
    let (file_path, stream) = parse_ntfs_path(&input);

    match stream {
        Some(ads) => {
            // The stream type defaults to "$DATA", so it can never be empty
            assert!(!ads.stream_type.is_empty(), "ADS stream type is empty");
            format!(
                "ads_ok:{}:{}:{}",
                file_path.len(),
                ads.stream_name,
                ads.stream_type,
            )
        }
        None => {
            // Without an ADS, the path is returned verbatim (trimmed)
            assert!(
                trimmed.is_empty() || file_path == trimmed,
                "no-ADS path {file_path:?} != trimmed input {trimmed:?}"
            );
            format!("no_ads:{}", file_path.len())
        }
    }
}
