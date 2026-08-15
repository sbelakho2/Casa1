#![no_main]

use casa1::winhttp::{ntlm_parse_challenge_msg, WinHttpStack};
use casa1::wininet;
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
        Ok((scheme, host, port, path, user, pass)) => format!(
            "crack_ok:{}:{}:{}:{}:{}:{}",
            scheme,
            host,
            port,
            path,
            user.is_some(),
            pass.is_some(),
        ),
        Err(e) => format!("crack_err:{}:{}", e.code.as_u32(), e.message),
    };

    // === WinHTTP URL canonicalization ===
    let canon_result = stack.internet_canonicalize_url_w(url, url.len() as u32);

    // === WinINet URL moniker creation ===
    let moniker_result = match wininet::create_url_moniker(url, None) {
        Ok(moniker) => format!("moniker_ok:{}", moniker.len()),
        Err(e) => format!("moniker_err:{}:{}", e.code.as_u32(), e.message),
    };

    // === WinINet URL moniker (extended) ===
    let moniker_ex_result = match wininet::create_url_moniker_ex(url, None, 0) {
        Ok(moniker) => format!("moniker_ex_ok:{}", moniker.len()),
        Err(e) => format!("moniker_ex_err:{}:{}", e.code.as_u32(), e.message),
    };

    // === NTLM challenge message parsing (uses raw bytes directly) ===
    let ntlm_result = match ntlm_parse_challenge_msg(data) {
        Some(challenge) => format!("ntlm_ok:{}", challenge.len()),
        None => "ntlm_err:parse_failed".to_string(),
    };

    format!(
        "{}|canon_len:{}|{}|{}|{}",
        crack_result,
        canon_result.len(),
        ntlm_result,
        moniker_result,
        moniker_ex_result,
    )
}
