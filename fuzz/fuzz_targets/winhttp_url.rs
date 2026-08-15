#![no_main]

use casa1::winhttp::{ntlm_parse_challenge_msg, WinHttpStack};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse_summary(data);
    let second = parse_summary(data);
    assert_eq!(
        first, second,
        "WinHTTP/WinINet parsing produced nondeterministic summaries for identical input"
    );
});

fn parse_summary(data: &[u8]) -> String {
    let stack = WinHttpStack::new();
    let input = String::from_utf8_lossy(data);
    let url = input.as_ref();

    // === WinHTTP URL cracking ===
    let crack_result = match stack.internet_crack_url_w(url, url.len() as u32) {
        Ok((scheme, host, port, path, user, pass)) => {
            // Invariants on a successfully cracked URL: scheme defaults to
            // "http" and path defaults to "/", so both are never empty.
            assert!(
                !scheme.is_empty(),
                "cracked URL must have a non-empty scheme"
            );
            assert!(
                !path.is_empty(),
                "cracked URL must have a non-empty path"
            );
            format!("crack_ok:{}:{}:{}:{}:{}:{}", scheme, host, port, path, user.is_some(), pass.is_some())
        }
        Err(e) => format!("crack_err:{}:{}", e.code.as_u32(), e.message),
    };

    // === WinHTTP URL canonicalization ===
    let canon_result = stack.internet_canonicalize_url_w(url, url.len() as u32);

    // === NTLM challenge message parsing (uses raw bytes directly) ===
    let ntlm_result = match ntlm_parse_challenge_msg(data) {
        Some(challenge) => {
            // A valid Type-2 challenge message always yields the 8-byte
            // server challenge.
            assert_eq!(
                challenge.len(),
                8,
                "NTLM challenge must be exactly 8 bytes"
            );
            "ntlm_ok".to_string()
        }
        None => "ntlm_err:parse_failed".to_string(),
    };

    format!("{}|canon_len:{}|{}", crack_result, canon_result.len(), ntlm_result)
}
