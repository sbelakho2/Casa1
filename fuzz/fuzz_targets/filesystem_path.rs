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

    // Test NTFS path parsing (ADS detection)
    let (file_path, stream) = parse_ntfs_path(&input);

    match stream {
        Some(ads) => format!(
            "ads_ok:{}:{}:{}",
            file_path.len(),
            ads.stream_name,
            ads.stream_type,
        ),
        None => format!("no_ads:{}", file_path.len()),
    }
}
