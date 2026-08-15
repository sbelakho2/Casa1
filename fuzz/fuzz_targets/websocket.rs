#![no_main]

use casa1::winhttp::{WinHttpWebSocketBufferType, WinHttpWebSocketCloseStatus};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test WebSocket buffer type parsing (u32 discriminant)
    if data.len() >= 4 {
        let val = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
        let first = buffer_type_summary(val);
        let second = buffer_type_summary(val);
        assert_eq!(
            first, second,
            "WinHttpWebSocketBufferType::try_from_u32 produced nondeterministic results"
        );
    }

    // Test WebSocket close status parsing (u16 code)
    if data.len() >= 2 {
        let code = u16::from_ne_bytes([data[0], data[1]]);
        let first = close_status_summary(code);
        let second = close_status_summary(code);
        assert_eq!(
            first, second,
            "WinHttpWebSocketCloseStatus::from_code produced nondeterministic results"
        );
    }

    // Test WebSocket close status u32 validation
    if data.len() >= 4 {
        let val = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
        let first = close_status_u32_summary(val);
        let second = close_status_u32_summary(val);
        assert_eq!(
            first, second,
            "WinHttpWebSocketCloseStatus::try_from_u32 produced nondeterministic results"
        );
    }
});

fn buffer_type_summary(val: u32) -> String {
    match WinHttpWebSocketBufferType::try_from_u32(val) {
        Ok(bt) => format!("ok:{}", format!("{:?}", bt)),
        Err(e) => format!("err:{}", e.code.as_u32()),
    }
}

fn close_status_summary(code: u16) -> String {
    let status = WinHttpWebSocketCloseStatus::from_code(code);
    format!("ok:{}:{}", format!("{:?}", status), code)
}

fn close_status_u32_summary(val: u32) -> String {
    match WinHttpWebSocketCloseStatus::try_from_u32(val) {
        Ok(status) => format!("ok:{}", format!("{:?}", status)),
        Err(e) => format!("err:{}", e.code.as_u32()),
    }
}
