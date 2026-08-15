#![no_main]

use casa1::steam_protocol;
use casa1::winhttp::WinHttpStack;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let input_ref: &str = input.as_ref();

    let first = parse_summary(input_ref);
    let second = parse_summary(input_ref);
    assert_eq!(
        first, second,
        "URL handling produced nondeterministic summaries for identical input"
    );
});

fn parse_summary(input: &str) -> String {
    // Test steam:// URL parsing (comprehensive)
    let steam_result = match steam_protocol::parse_steam_protocol_url(input) {
        Some(url) => {
            assert!(
                url.raw_url
                    .chars()
                    .next()
                    .map_or(false, |c| c.is_ascii_alphabetic()),
                "parsed URL {url:?} has no alphabetic scheme start"
            );
            format!(
                "steam_ok:{}:{}:{}",
                format!("{:?}", url.command),
                url.query_params.len(),
                url.raw_url.len(),
            )
        }
        None => "steam_err:parse_failed".to_string(),
    };

    // Test WinHttp URL cracking
    let stack = WinHttpStack::new();
    let crack_result = match stack.internet_crack_url_w(input, input.len() as u32) {
        Ok((scheme, host, port, path, user, pass)) => {
            // A cracked URL always yields a non-empty scheme and path
            assert!(!scheme.is_empty(), "cracked scheme is empty");
            assert!(!path.is_empty(), "cracked path is empty");
            format!(
                "crack_ok:{}:{}:{}:{}:{}:{}",
                scheme,
                host,
                port,
                path,
                user.is_some(),
                pass.is_some(),
            )
        }
        Err(e) => format!("crack_err:{}:{}", e.code.as_u32(), e.message),
    };

    // Test WinHttp URL canonicalization
    let canon_result = stack.internet_canonicalize_url_w(input, input.len() as u32);

    format!("{}|{}|canon_len:{}", steam_result, crack_result, canon_result.len())
}
