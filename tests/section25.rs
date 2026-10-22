#![allow(dead_code, unused_imports)]
//! Section 25 — Steam Networking Conformance Test Suite
//!
//! Phase 6.5.1 from the execution plan.  Covers the entire Steam networking
//! protocol stack: CM connectivity, encryption, message serialization, EMsg
//! mapping, CDN routing, depot manifest parsing, file checksum verification,
//! `steam://` URL parsing, GameNetworkingSockets lifecycle, heartbeat
//! management, and round-trip property tests.
//!
//! Connect-dependent behavior is exercised deterministically against a closed
//! loopback port (no external network). Real Steam CM connectivity is only
//! attempted when the `STEAM_LIVE_TEST` env var is set — the default CM
//! servers must never be contacted in unit tests
//! (src/steam_protocol.rs `steam_zero_touch_default_servers_not_contacted`).

use casa1::steam_protocol::{GameNetworkingSockets, GnsConnectionState, SteamProtocolStack};
use std::io::Write;

fn steam_live_tests_enabled() -> bool {
    std::env::var("STEAM_LIVE_TEST").is_ok()
}

fn closed_loopback_addr() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

// ===========================================================================
// t25_01 — CM Connect / Disconnect
// ===========================================================================

// ===========================================================================
// t25_02 — Encrypt / Decrypt Round-Trip
// ===========================================================================

// ===========================================================================
// t25_03 — Message Serialization
// ===========================================================================

// ===========================================================================
// t25_04 — EMsg Mapping
// ===========================================================================

// ===========================================================================
// t25_05 — CDN Routing Parsing
// ===========================================================================

#[test]
fn t25_05_cdn_routing_parsing() {
    let stack = SteamProtocolStack::new();

    // Realistic CDN response body with contentServer tags
    let cdn_body = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<contentServerList>
  <contentServer cell=\"1234\" https=\"true\" port=\"443\" weight=\"100\">
    steam.cdn.steamusercontent.com
  </contentServer>
  <contentServer cell=\"5678\" https=\"false\" port=\"80\" weight=\"50\">
    cdn2.steamcontent.com
  </contentServer>
</contentServerList>";
    let servers = stack
        .parse_cdn_routing(cdn_body)
        .expect("CDN routing parsing should succeed for valid XML");
    assert_eq!(servers.len(), 2, "should parse 2 content servers");
    assert_eq!(servers[0].host, "steam.cdn.steamusercontent.com");
    assert_eq!(servers[0].port, 443);
    assert!(servers[0].https);
    assert_eq!(servers[0].cell_id, 1234);
    assert_eq!(servers[0].weight, 100);
    assert_eq!(servers[1].host, "cdn2.steamcontent.com");
    assert_eq!(servers[1].port, 80);
    assert!(!servers[1].https);
    assert_eq!(servers[1].cell_id, 5678);
    assert_eq!(servers[1].weight, 50);

    // Empty body returns empty vec
    let empty_servers = stack
        .parse_cdn_routing("")
        .expect("empty body should parse without error");
    assert!(
        empty_servers.is_empty(),
        "empty CDN body should yield empty server list"
    );

    // Malformed XML (non-XML text) — handle gracefully, either error or empty
    let malformed_result = stack.parse_cdn_routing("this is not XML at all");
    match malformed_result {
        Ok(servers) => {
            assert!(
                servers.is_empty(),
                "malformed XML should produce empty list"
            );
        }
        Err(_) => {
            // Error is also acceptable — we just don't panic
        }
    }
}

// ===========================================================================
// t25_06 — Depot Manifest Parsing
// ===========================================================================

#[test]
fn t25_06_depot_manifest_parsing() {
    let stack = SteamProtocolStack::new();

    // Build a minimal valid depot manifest binary:
    // Header: version(4) file_count(4) total_size(8) flags(4) depot_id(4) = 24 bytes
    // Then for each file entry:
    //   filename_len(4) filename(N) size(8) checksum(20) chunk_count(4) [chunks...]
    let manifest_data = {
        let mut data = Vec::new();
        // Header
        data.extend_from_slice(&1u32.to_le_bytes()); // version
        data.extend_from_slice(&1u32.to_le_bytes()); // file_count
        data.extend_from_slice(&256u64.to_le_bytes()); // total_size
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&12345u32.to_le_bytes()); // depot_id

        // File entry
        let filename = b"test_file.bin";
        data.extend_from_slice(&(filename.len() as u32).to_le_bytes());
        data.extend_from_slice(filename);
        data.extend_from_slice(&256u64.to_le_bytes()); // size
        data.extend_from_slice(&[0xAB; 20]); // checksum (SHA-1)
        data.extend_from_slice(&0u32.to_le_bytes()); // chunk_count (no chunks)
        data
    };

    let manifests = stack
        .parse_depot_manifest(&manifest_data, None)
        .expect("minimal valid manifest should parse");
    assert_eq!(manifests.len(), 1, "should parse 1 manifest entry");
    assert_eq!(manifests[0].filename, "test_file.bin");
    assert_eq!(manifests[0].size, 256);
    assert_eq!(manifests[0].depot_id, 12345);
    assert!(manifests[0].chunks.is_empty());

    // Manifest with chunk entries
    let manifest_with_chunks = {
        let mut data = Vec::new();
        // Header
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 file
        data.extend_from_slice(&512u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&67890u32.to_le_bytes());

        // File entry
        let filename = b"chunky_file.dat";
        data.extend_from_slice(&(filename.len() as u32).to_le_bytes());
        data.extend_from_slice(filename);
        data.extend_from_slice(&512u64.to_le_bytes());
        data.extend_from_slice(&[0xCD; 20]); // checksum
        data.extend_from_slice(&2u32.to_le_bytes()); // 2 chunks

        // Chunk 1
        data.extend_from_slice(&[0x11; 20]); // chunk_id
        data.extend_from_slice(&0u64.to_le_bytes()); // offset
        data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // crc
        data.extend_from_slice(&256u32.to_le_bytes()); // size
        data.extend_from_slice(&200u32.to_le_bytes()); // compressed_size

        // Chunk 2
        data.extend_from_slice(&[0x22; 20]); // chunk_id
        data.extend_from_slice(&256u64.to_le_bytes()); // offset
        data.extend_from_slice(&0xCAFEBABEu32.to_le_bytes()); // crc
        data.extend_from_slice(&256u32.to_le_bytes()); // size
        data.extend_from_slice(&0u32.to_le_bytes()); // compressed_size (uncompressed)
        data
    };

    let chunked = stack
        .parse_depot_manifest(&manifest_with_chunks, None)
        .expect("manifest with chunks should parse");
    assert_eq!(chunked.len(), 1);
    assert_eq!(chunked[0].chunks.len(), 2, "should have 2 chunks");

    // Check ChunkInfo fields for chunk 1
    let chunk1 = &chunked[0].chunks[0];
    assert_eq!(chunk1.chunk_id, [0x11; 20]);
    assert_eq!(chunk1.offset, 0);
    assert_eq!(chunk1.crc, 0xDEADBEEF);
    assert_eq!(chunk1.size, 256);
    assert_eq!(chunk1.compressed_size, 200);

    // Check ChunkInfo fields for chunk 2
    let chunk2 = &chunked[0].chunks[1];
    assert_eq!(chunk2.chunk_id, [0x22; 20]);
    assert_eq!(chunk2.offset, 256);
    assert_eq!(chunk2.crc, 0xCAFEBABE);
    assert_eq!(chunk2.size, 256);
    assert_eq!(chunk2.compressed_size, 0);

    // Empty manifest (header only, file_count = 0)
    let empty_manifest = {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes()); // version
        data.extend_from_slice(&0u32.to_le_bytes()); // file_count = 0
        data.extend_from_slice(&0u64.to_le_bytes()); // total_size
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&0u32.to_le_bytes()); // depot_id
        data
    };

    let empty = stack
        .parse_depot_manifest(&empty_manifest, None)
        .expect("empty manifest (0 files) should parse");
    assert!(
        empty.is_empty(),
        "manifest with file_count=0 should yield empty list"
    );

    // Invalid (too-short) manifest
    let too_short = stack.parse_depot_manifest(&[0u8; 4], None);
    assert!(
        too_short.is_err(),
        "too-short manifest data should return error"
    );

    // Invalid UTF-8 in filename — the parser uses String::from_utf8_lossy,
    // so it should still succeed but with replacement characters.
    let invalid_utf8_manifest = {
        let mut data = Vec::new();
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&128u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&42u32.to_le_bytes());

        // Filename with invalid UTF-8 bytes (0xFF is not valid in UTF-8)
        let bad_filename = [0xFF, 0xFE, 0x00, 0x62, 0x69, 0x6E]; // 0xFF 0xFE 0x00 "bin"
        data.extend_from_slice(&(bad_filename.len() as u32).to_le_bytes());
        data.extend_from_slice(&bad_filename);
        data.extend_from_slice(&128u64.to_le_bytes());
        data.extend_from_slice(&[0xEF; 20]); // checksum
        data.extend_from_slice(&0u32.to_le_bytes()); // chunk_count
        data
    };

    let lossy_result = stack.parse_depot_manifest(&invalid_utf8_manifest, None);
    // Should succeed (uses from_utf8_lossy) or fail — both acceptable
    if let Ok(manifests) = lossy_result {
        assert_eq!(manifests.len(), 1);
        // The filename will have replacement characters, but it should not panic
        eprintln!("Lossy filename: {:?}", manifests[0].filename);
    }
}

// ===========================================================================
// t25_07 — File Checksum Verification
// ===========================================================================

#[test]
fn t25_07_file_checksum_verification() {
    use sha1::{Digest, Sha1};
    use tempfile::NamedTempFile;

    // Create a temp file with known content
    let content = b"Hello, Steam checksum verification!";
    let mut tmp = NamedTempFile::new().expect("failed to create temp file");
    tmp.write_all(content).expect("failed to write temp file");
    tmp.flush().expect("failed to flush temp file");

    let filepath = tmp.path();

    // Compute SHA-1 hash of the content
    let expected_hash = Sha1::digest(content);
    let mut hash_array = [0u8; 20];
    hash_array.copy_from_slice(&expected_hash);

    // Verify matching hash returns Ok(true)
    let result = SteamProtocolStack::verify_file_checksum(filepath, &hash_array)
        .expect("verify_file_checksum should not return Err for an existing file");
    assert!(result, "matching checksum should return Ok(true)");

    // Verify mismatched hash returns Ok(false)
    let wrong_hash = [0x42u8; 20];
    let result2 = SteamProtocolStack::verify_file_checksum(filepath, &wrong_hash)
        .expect("verify_file_checksum should not return Err for mismatched hash");
    assert!(!result2, "mismatched checksum should return Ok(false)");

    // Non-existent file path — should return Ok(false), not Err
    let non_existent = std::path::Path::new("/tmp/__nonexistent_file_for_test_25_07__");
    let result3 = SteamProtocolStack::verify_file_checksum(non_existent, &hash_array);
    match result3 {
        Ok(false) => {} // Acceptable: returns Ok(false)
        Ok(true) => panic!("non-existent file should not have matching checksum"),
        Err(_) => {} // Also acceptable: returns Err with RcIo
    }
}

// ===========================================================================
// t25_08 — Steam Protocol URL Parsing
// ===========================================================================

// ===========================================================================
// t25_09 — GNS Session Lifecycle
// ===========================================================================

#[test]
fn t25_09_gns_session_lifecycle() {
    let mut gns = GameNetworkingSockets::new();

    // Create a session, verify handle is non-zero
    let handle = gns.create_session().expect("create_session should succeed");
    assert_ne!(handle, 0, "GNS session handle should be non-zero");

    // After creation, state should be Connected (create_session transitions
    // from Connecting → Connected internally)
    let state = gns.connection_state(handle);
    assert_eq!(
        state,
        Some(GnsConnectionState::Connected),
        "newly created session should be Connected"
    );

    // Accept the session (it is already Connected; accept_session expects
    // Connecting state, so this should fail with RcInvalidState)
    let accept_result = gns.accept_session(handle);
    assert!(
        accept_result.is_err(),
        "accept_session should fail for already-Connected session"
    );

    // Send a message on the session
    let msg_data = b"Hello GNS world!";
    gns.send_message(handle, msg_data, 0)
        .expect("send_message should succeed");

    // Poll for incoming messages
    let messages = gns
        .poll_incoming_messages()
        .expect("poll_incoming_messages should succeed");
    assert_eq!(messages.len(), 1, "should have 1 incoming message");
    assert_eq!(messages[0].data, msg_data);
    assert_eq!(messages[0].conn, handle);

    // Close the session
    gns.close_session(handle)
        .expect("close_session should succeed");
    assert_eq!(
        gns.connection_state(handle),
        None,
        "session should be removed after close"
    );

    // Verify operations on closed session return errors
    let send_err = gns.send_message(handle, b"should fail", 0);
    assert!(
        send_err.is_err(),
        "send_message on closed session should return error"
    );

    let accept_err = gns.accept_session(handle);
    assert!(
        accept_err.is_err(),
        "accept_session on closed session should return error"
    );

    let close_err = gns.close_session(handle);
    assert!(
        close_err.is_err(),
        "close_session on already-closed session should return error"
    );
}

// ===========================================================================
// t25_10 — GNS Multiple Sessions
// ===========================================================================

// ===========================================================================
// t25_11 — Frame Encryption Sequence
// ===========================================================================

// ===========================================================================
// t25_12 — Heartbeat Interval
// ===========================================================================

#[test]
fn t25_12_heartbeat_interval() {
    let mut stack = SteamProtocolStack::new();

    // heartbeat_needed() should return true because last_heartbeat is None
    // (the implementation returns true when last_heartbeat is None).
    assert!(
        stack.heartbeat_needed(),
        "heartbeat_needed should return true when not connected (last_heartbeat is None)"
    );

    // send_heartbeat() should fail gracefully when not connected
    let heartbeat_result = stack.send_heartbeat();
    assert!(
        heartbeat_result.is_err(),
        "send_heartbeat should return error when not connected"
    );

    // After the failed heartbeat attempt, heartbeat_needed should still
    // behave the same way (last_heartbeat is still None because send
    // failed before setting it).
    assert!(
        stack.heartbeat_needed(),
        "heartbeat_needed should still return true after failed send"
    );

    if steam_live_tests_enabled() {
        // Live path (opt-in only): after a real connect, the heartbeat state
        // changes.
        stack.connect(None).expect("live connect must succeed");
        assert!(
            !stack.heartbeat_needed(),
            "heartbeat_needed should return false shortly after connect"
        );

        // Send a heartbeat manually
        stack
            .send_heartbeat()
            .expect("send_heartbeat should succeed when connected");
        assert!(
            !stack.heartbeat_needed(),
            "heartbeat_needed should return false after sending heartbeat"
        );

        stack.disconnect().expect("disconnect should succeed");
    } else {
        // Deterministic no-network part: a failed connect attempt must not
        // alter the heartbeat state (no last_heartbeat is recorded).
        let closed = closed_loopback_addr();
        let _ = stack.connect(Some(&closed.to_string()));
        assert!(
            stack.heartbeat_needed(),
            "heartbeat_needed must remain true after a failed connect"
        );
    }
}

// ===========================================================================
// t25_13 — Serialize / Deserialize Round-Trip Properties
// ===========================================================================

// ===========================================================================
// t25_15 — GNS UDP socket creation and binding
// ===========================================================================

// ---------------------------------------------------------------------------
// t25_16: GNS STUN server configuration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t25_17: GNS SDR relay configuration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t25_18: GNS session lifecycle with peer routing
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t25_19: GNS session lifecycle — create, close, state transitions
// ---------------------------------------------------------------------------

#[test]
fn t25_19_gns_session_lifecycle_state_transitions() {
    let mut gns = GameNetworkingSockets::new();

    // Create session
    let handle = gns.create_session().unwrap();
    assert_eq!(
        gns.connection_state(handle),
        Some(GnsConnectionState::Connected),
        "New session should be Connected"
    );

    // Close session
    gns.close_session(handle).unwrap();
    assert_eq!(
        gns.connection_state(handle),
        None,
        "Closed session should return None"
    );

    // Closing a non-existent session should error
    let close_result = gns.close_session(9999);
    assert!(
        close_result.is_err(),
        "Closing non-existent session should error"
    );

    // Creating multiple sessions yields unique handles
    let h1 = gns.create_session().unwrap();
    let h2 = gns.create_session().unwrap();
    assert_ne!(h1, h2, "Session handles should be unique");
    gns.close_session(h1).unwrap();
    gns.close_session(h2).unwrap();
}

// ---------------------------------------------------------------------------
// t25_20: GNS message encryption/decryption round-trip with session keys
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t25_21: GNS create_session with send/recv key management
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// t25_22: GNS in-memory fallback message queue
// ---------------------------------------------------------------------------

#[test]
fn t25_22_gns_in_memory_fallback_queue() {
    let mut gns = GameNetworkingSockets::new();

    // Without a UDP socket, messages use the in-memory fallback
    let handle = gns.create_session().unwrap();

    // Send a message (will use fallback since no UDP socket)
    gns.send_message(handle, b"fallback message", 0).unwrap();

    // Poll messages — should get the fallback message
    let messages = gns.poll_incoming_messages().unwrap();
    assert_eq!(
        messages.len(),
        1,
        "Should receive 1 message from fallback queue"
    );
    assert_eq!(
        messages[0].data, b"fallback message",
        "Message data should match"
    );
    assert_eq!(messages[0].conn, handle, "Message connection should match");
    assert_eq!(messages[0].channel, 0, "Default channel should be 0");

    // Second poll should be empty
    let messages = gns.poll_incoming_messages().unwrap();
    assert!(messages.is_empty(), "Second poll should be empty");

    gns.close_session(handle).unwrap();
}

// ---------------------------------------------------------------------------
// t25_23: GNS multi-message fallback queue
// ---------------------------------------------------------------------------

#[test]
fn t25_23_gns_multi_message_fallback_queue() {
    let mut gns = GameNetworkingSockets::new();

    let h1 = gns.create_session().unwrap();
    let h2 = gns.create_session().unwrap();

    // Send multiple messages via fallback
    gns.send_message(h1, b"msg1", 0).unwrap();
    gns.send_message(h2, b"msg2", 0).unwrap();
    gns.send_message(h1, b"msg3", 0).unwrap();

    // Poll all messages
    let messages = gns.poll_incoming_messages().unwrap();
    assert_eq!(messages.len(), 3, "Should receive all 3 messages");

    // Messages should be in order
    assert_eq!(messages[0].data, b"msg1");
    assert_eq!(messages[0].conn, h1);
    assert_eq!(messages[1].data, b"msg2");
    assert_eq!(messages[1].conn, h2);
    assert_eq!(messages[2].data, b"msg3");
    assert_eq!(messages[2].conn, h1);

    gns.close_session(h1).unwrap();
    gns.close_session(h2).unwrap();
}

// ---------------------------------------------------------------------------
// t25_24: GNS session without keys behaves correctly
// ---------------------------------------------------------------------------

#[test]
fn t25_24_gns_session_without_keys_send_error() {
    let mut gns = GameNetworkingSockets::new();

    // Creating a session auto-generates keys, so we can't test missing keys
    // via create_session. But we can verify that sending after close fails.
    let handle = gns.create_session().unwrap();
    gns.close_session(handle).unwrap();

    // Sending on a closed session should error
    let send_result = gns.send_message(handle, b"data", 0);
    assert!(
        send_result.is_err(),
        "Sending on closed session should error"
    );
}
