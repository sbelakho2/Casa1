#![no_main]

use casa1::steam_protocol;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // === Test 1: Steam protocol URL parsing (existing) ===
    let input = String::from_utf8_lossy(data);
    let first = url_parse_summary(&input);
    let second = url_parse_summary(&input);
    assert_eq!(
        first, second,
        "steam_protocol URL parsing produced nondeterministic summaries for identical input"
    );

    // === Test 2: ExtendedHeader deserialisation ===
    // ExtendedHeader::TOTAL_SIZE = 44 bytes. We use the raw input bytes
    // directly to stress the deserialiser at various lengths.
    let header_result = steam_protocol::ExtendedHeader::deserialize(data);
    let header_result2 = steam_protocol::ExtendedHeader::deserialize(data);
    assert_eq!(
        header_result, header_result2,
        "ExtendedHeader::deserialize produced nondeterministic results"
    );

    // Round-trip test: serialize the deserialized header (if valid) and
    // verify that re-deserializing yields the same result.
    if let Some(ref hdr) = header_result {
        let serialized = hdr.serialize();
        let re_deserialized = steam_protocol::ExtendedHeader::deserialize(&serialized);
        assert_eq!(
            Some(hdr.clone()),
            re_deserialized,
            "ExtendedHeader round-trip failed"
        );
    }

    // === Test 3: SteamMessage deserialisation from raw frames ===
    // A valid frame has: 4-byte magic + 4-byte len + body.
    // SteamMessage does not implement PartialEq, so we compare Debug
    // representations for determinism checking.
    let msg_result = steam_protocol::deserialize_message(data);
    let msg_result2 = steam_protocol::deserialize_message(data);
    assert_eq!(
        format!("{:?}", msg_result),
        format!("{:?}", msg_result2),
        "deserialize_message produced nondeterministic results"
    );

    // Round-trip test for successfully deserialized messages.
    if let Some(ref msg) = msg_result {
        let frame = steam_protocol::serialize_message(msg);
        let re_deserialized = steam_protocol::deserialize_message(&frame);
        assert_eq!(
            format!("{:?}", Some(msg.clone())),
            format!("{:?}", re_deserialized),
            "SteamMessage round-trip failed"
        );
    }

    // === Test 4: EMsg mapping ===
    if data.len() >= 4 {
        let emsg_val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let first = steam_protocol::map_emsg(emsg_val);
        let second = steam_protocol::map_emsg(emsg_val);
        assert_eq!(
            first, second,
            "map_emsg produced nondeterministic results"
        );
    }
});

fn url_parse_summary(input: &str) -> String {
    match steam_protocol::parse_steam_protocol_url(input) {
        Some(url) => format!(
            "ok:{}:{}:{}",
            format!("{:?}", url.command),
            url.query_params.len(),
            url.raw_url.len(),
        ),
        None => "err:parse_failed".to_string(),
    }
}
