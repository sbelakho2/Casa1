#![no_main]

use casa1::network;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse_summary(data);
    let second = parse_summary(data);
    assert_eq!(
        first, second,
        "network::parse_http_response produced nondeterministic summaries for identical input"
    );
});

fn parse_summary(data: &[u8]) -> String {
    match network::parse_http_response(data) {
        Ok(response) => format!(
            "ok:{}:{}:{}",
            response.status,
            response.headers.len(),
            response.body.len(),
        ),
        Err(error) => format!("err:{}:{}", error.code.as_u32(), error.message),
    }
}
