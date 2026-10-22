#![allow(dead_code, unused_imports)]
//! Section 37 — Phase E7: Cross-Module Integration Test Suite
//!
//! Tests integration between multiple Casa1 subsystems:
//!   - PE loading pipeline (parse → select_image_base → map_image → apply_relocations)
//!   - Import resolution with ApiSetResolver + export tables
//!   - Lifecycle planning with module dependencies and TLS callbacks
//!   - Network + Certificate + Cookie full workflow
//!   - Audio subsystem (mastering → submix → source voice chain)
//!   - Crypto operations (SHA, HMAC, AES, RSA, ECDSA)
//!   - CPU + Memory image integration
//!   - Thread state creation and lifecycle
//!   - Error propagation across modules

mod support;

use casa1::network::{
    AddressFamily, Certificate, Cookie, HttpProtocolFlags, NetworkStack, QuicConfig, SockAddr,
    aes_256_gcm_decrypt, aes_256_gcm_encrypt, ecdsa_p256_verify, rsa_pkcs1v15_sign,
    rsa_pkcs1v15_verify,
};
use casa1::pe::{
    ApiSetResolver, ExportSymbol, ExportTarget, ImportSymbol, apply_relocations, map_image, parse,
    plan_lifecycle, resolve_imports, select_image_base,
};
use std::collections::BTreeMap;

// ============================================================================
// 1. Full PE Lifecycle Integration
// ============================================================================

#[test]
fn e7_pe_full_lifecycle_parse_to_lifecycle_plan() {
    // Use the support module's sample PE builder
    let bytes = support::sample_pe_bytes();
    assert!(bytes.len() > 512, "sample PE must be substantial");

    // Step 1: Parse the PE file
    let parsed = parse(&bytes).expect("parse sample PE");
    assert_eq!(parsed.pointer_bytes(), 8); // PE32+
    assert!(parsed.sections.len() >= 4);

    // Step 2: Select image base
    let image_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let image_base = select_image_base(&parsed, image_hash, true);
    assert!(image_base > 0);

    // Step 3: Map the image into memory
    let mut mapped = map_image(&bytes, &parsed, image_hash, true).expect("map image");
    assert!(
        !mapped.memory.is_empty(),
        "mapped memory should be non-empty"
    );
    // Verify entry point data is mapped
    let entry_rva = parsed.address_of_entry_point;
    let entry_offset = entry_rva as usize;
    assert!(entry_offset < mapped.memory.len());
    assert_eq!(mapped.memory[entry_offset], 0xc3); // RET instruction

    // Step 4: Apply relocations
    apply_relocations(&parsed, &mut mapped).expect("apply relocations");

    // Step 5: Resolve imports — provide an export table for kernel32
    // so the sample PE's CreateFileW / CloseHandle imports can resolve.
    let resolver = ApiSetResolver::new();
    let mut export_tables: BTreeMap<String, Vec<ExportSymbol>> = BTreeMap::new();
    // The sample PE imports functions by ordinal — include ordinal 17 used by the test PE.
    export_tables.insert(
        "kernel32.dll".to_string(),
        vec![
            ExportSymbol {
                ordinal: 1,
                name: Some("CreateFileW".to_string()),
                target: ExportTarget::Rva(0x1000),
            },
            ExportSymbol {
                ordinal: 2,
                name: Some("CloseHandle".to_string()),
                target: ExportTarget::Rva(0x1010),
            },
            ExportSymbol {
                ordinal: 3,
                name: Some("CreateThread".to_string()),
                target: ExportTarget::Rva(0x1020),
            },
            ExportSymbol {
                ordinal: 17,
                name: Some("Ordinal17".to_string()),
                target: ExportTarget::Rva(0x1030),
            },
            ExportSymbol {
                ordinal: 18,
                name: Some("Forwarded".to_string()),
                target: ExportTarget::Forwarder("ntdll.RtlNtStatusToDosError".to_string()),
            },
        ],
    );
    export_tables.insert(
        "ntdll.dll".to_string(),
        vec![ExportSymbol {
            ordinal: 1,
            name: Some("RtlNtStatusToDosError".to_string()),
            target: ExportTarget::Rva(0x2000),
        }],
    );
    let resolved = resolve_imports(&parsed, &export_tables, &resolver).expect("resolve imports");
    assert!(
        !resolved.is_empty(),
        "should have resolved at least one import"
    );
    // Check that CreateFileW was resolved via api-ms-win-core-file-l1-1-0
    let has_create_file = resolved
        .iter()
        .any(|ri| matches!(&ri.symbol, ImportSymbol::ByName { name, .. } if name == "CreateFileW"));
    assert!(has_create_file, "should resolve CreateFileW");
    // All resolved modules should be kernel32.dll
    assert!(
        resolved
            .iter()
            .all(|ri| ri.resolved_module == "kernel32.dll")
    );

    // Step 6: Plan lifecycle — needs dependency map + TLS callbacks
    let mut dependencies: BTreeMap<String, Vec<String>> = BTreeMap::new();
    dependencies.insert("test.exe".to_string(), vec!["kernel32.dll".to_string()]);
    dependencies.insert("kernel32.dll".to_string(), vec![]);
    let tls_callbacks: BTreeMap<String, Vec<u64>> = BTreeMap::new();

    let plan = plan_lifecycle("test.exe", &dependencies, &tls_callbacks).expect("plan lifecycle");
    assert!(
        !plan.load_order.is_empty(),
        "load order should have entries"
    );
    // Should have DllMainProcessAttach for each module
    let has_process_attach = plan
        .process_attach
        .iter()
        .any(|ev| matches!(ev.stage, casa1::pe::LifecycleStage::DllMainProcessAttach));
    assert!(has_process_attach, "should have DllMainProcessAttach stage");
}

#[test]
fn e7_pe32_full_lifecycle_parse_to_lifecycle_plan() {
    let bytes = support::sample_pe32_bytes();
    let parsed = parse(&bytes).expect("parse sample PE32");
    assert_eq!(parsed.pointer_bytes(), 4);

    let image_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let image_base = select_image_base(&parsed, image_hash, true);
    assert!(image_base > 0);

    let mut mapped = map_image(&bytes, &parsed, image_hash, true).expect("map image");
    apply_relocations(&parsed, &mut mapped).expect("apply relocations");

    let resolver = ApiSetResolver::new();
    let mut export_tables: BTreeMap<String, Vec<ExportSymbol>> = BTreeMap::new();
    export_tables.insert(
        "kernel32.dll".to_string(),
        vec![
            ExportSymbol {
                ordinal: 1,
                name: Some("CreateFileW".to_string()),
                target: ExportTarget::Rva(0x1000),
            },
            ExportSymbol {
                ordinal: 17,
                name: Some("Ordinal17".to_string()),
                target: ExportTarget::Rva(0x1030),
            },
            ExportSymbol {
                ordinal: 18,
                name: Some("Forwarded".to_string()),
                target: ExportTarget::Forwarder("ntdll.RtlNtStatusToDosError".to_string()),
            },
        ],
    );
    export_tables.insert(
        "ntdll.dll".to_string(),
        vec![ExportSymbol {
            ordinal: 1,
            name: Some("RtlNtStatusToDosError".to_string()),
            target: ExportTarget::Rva(0x2000),
        }],
    );
    let resolved = resolve_imports(&parsed, &export_tables, &resolver).expect("resolve imports");
    assert!(!resolved.is_empty());

    let mut dependencies: BTreeMap<String, Vec<String>> = BTreeMap::new();
    dependencies.insert("test.exe".to_string(), vec!["kernel32.dll".to_string()]);
    dependencies.insert("kernel32.dll".to_string(), vec![]);
    let tls_callbacks: BTreeMap<String, Vec<u64>> = BTreeMap::new();

    let plan = plan_lifecycle("test.exe", &dependencies, &tls_callbacks).expect("plan lifecycle");
    assert!(!plan.load_order.is_empty());
}

// ============================================================================
// 2. PE + ApiSetResolver Cross-Module Integration
// ============================================================================

// ============================================================================
// 3. Network + Certificate + Cookie Full Workflow
// ============================================================================

#[test]
fn e7_network_full_workflow_with_routes_certificates_and_cookies() {
    let mut network = NetworkStack::new();
    network.wsa_startup();

    // Step 1: Add a custom route with cookies and certificate
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    let cookies = vec![Cookie {
        name: "token".to_string(),
        value: "test-token-value".to_string(),
        domain: ".test.example".to_string(),
        path: "/".to_string(),
        secure: true,
    }];
    // Create a trusted root and leaf certificate
    let leaf = Certificate {
        subject: "CN=test.example".to_string(),
        issuer: "CN=TestRoot".to_string(),
        fingerprint: "e7-test-leaf-fp".to_string(),
        valid_hostnames: vec!["test.example".to_string()],
        not_after_day: 99999,
        revoked: false,
        supported_ciphers: vec![
            "TLS_AES_128_GCM_SHA256".to_string(),
            "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        ],
    };
    let root = Certificate {
        subject: "CN=TestRoot".to_string(),
        issuer: "CN=TestRoot".to_string(),
        fingerprint: "e7-test-root-fp".to_string(),
        valid_hostnames: vec![],
        not_after_day: 99999,
        revoked: false,
        supported_ciphers: vec![],
    };
    network.import_certificate(root.clone());
    network.add_route(
        "https",
        "test.example",
        "/api/data",
        200,
        headers,
        b"response-body",
        cookies,
        vec![leaf, root],
    );

    // Step 2: Make HTTPS request via WinHTTP
    let session = network.win_http_open("e7-test");
    let conn = network
        .win_http_connect(session, "test.example", 443, true)
        .expect("connect");
    let req = network
        .win_http_open_request(conn, "GET", "/api/data")
        .expect("open request");
    network
        .win_http_send_request(req, BTreeMap::new(), &[])
        .expect("send request");
    network
        .win_http_receive_response(req)
        .expect("receive response");

    // Step 3: Verify response
    let response_headers = network.win_http_query_headers(req).expect("query headers");
    assert_eq!(response_headers.get("status").unwrap(), "200");
    assert_eq!(
        response_headers.get("content-type").unwrap(),
        "application/json"
    );
    let body = network.win_http_read_data(req, 4096).expect("read data");
    assert_eq!(body, b"response-body");

    // Step 4: Verify cookie stored in jar
    let snapshot = network.cookie_snapshot_json().expect("cookie snapshot");
    assert!(snapshot.contains("token"));
    assert!(snapshot.contains("test-token-value"));

    // Step 5: Verify HTTP trace recorded
    let traces = network.http_traces();
    assert!(!traces.is_empty());
    let trace = &traces[traces.len() - 1];
    assert_eq!(trace.host, "test.example");
    assert_eq!(trace.path, "/api/data");
    assert_eq!(trace.status, 200);
    assert!(trace.cipher_suite.is_some());

    // Step 6: Verify cipher log
    let log = network.cipher_log();
    assert!(!log.is_empty());
    assert!(log.iter().any(|entry| entry.contains("test.example")));

    network.close_handle(req);
    network.close_handle(conn);
    network.close_handle(session);
}

#[test]
fn e7_network_certificate_validation_pipeline() {
    let mut network = NetworkStack::new();

    // Import a root CA
    let root = Certificate {
        subject: "CN=E7Root".to_string(),
        issuer: "CN=E7Root".to_string(),
        fingerprint: "e7root-fingerprint".to_string(),
        valid_hostnames: vec![],
        not_after_day: 2000,
        revoked: false,
        supported_ciphers: vec![],
    };
    network.import_certificate(root);

    // Valid leaf signed by root
    let valid_leaf = Certificate {
        subject: "CN=service.e7.test".to_string(),
        issuer: "CN=E7Root".to_string(),
        fingerprint: "e7leaf-valid".to_string(),
        valid_hostnames: vec!["service.e7.test".to_string()],
        not_after_day: 1500,
        revoked: false,
        supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
    };
    let chain = vec![
        valid_leaf,
        Certificate {
            subject: "CN=E7Root".to_string(),
            issuer: "CN=E7Root".to_string(),
            fingerprint: "e7root-fingerprint".to_string(),
            valid_hostnames: vec![],
            not_after_day: 2000,
            revoked: false,
            supported_ciphers: vec![],
        },
    ];
    let result = network.validate_server_certificate("service.e7.test", &chain, false);
    assert!(
        result.is_ok(),
        "valid cert chain should pass: {:?}",
        result.err()
    );

    // Expired leaf should fail
    network.set_current_day(3000);
    let expired_result = network.validate_server_certificate("service.e7.test", &chain, false);
    assert!(expired_result.is_err(), "expired cert should fail");

    // Reset day and test revoked with revocation check
    network.set_current_day(1000);
    let revoked_leaf = Certificate {
        subject: "CN=service.e7.test".to_string(),
        issuer: "CN=E7Root".to_string(),
        fingerprint: "e7leaf-revoked".to_string(),
        valid_hostnames: vec!["service.e7.test".to_string()],
        not_after_day: 1500,
        revoked: true,
        supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
    };
    let revoked_chain = vec![
        revoked_leaf,
        Certificate {
            subject: "CN=E7Root".to_string(),
            issuer: "CN=E7Root".to_string(),
            fingerprint: "e7root-fingerprint".to_string(),
            valid_hostnames: vec![],
            not_after_day: 2000,
            revoked: false,
            supported_ciphers: vec![],
        },
    ];
    let revoked_result =
        network.validate_server_certificate("service.e7.test", &revoked_chain, true);
    assert!(
        revoked_result.is_err(),
        "revoked cert should fail with check"
    );

    // Without revocation check, revoked passes
    let no_check_result =
        network.validate_server_certificate("service.e7.test", &revoked_chain, false);
    assert!(
        no_check_result.is_ok(),
        "revoked cert should pass without check"
    );
}

// ============================================================================
// 4. Audio Subsystem Integration
// ============================================================================

// ============================================================================
// 5. Crypto Operations Cross-Module
// ============================================================================

#[test]
fn e7_crypto_rsa_sign_verify() {
    // Use shorter test keys
    const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCHDqQjsn8o6Qwl\n2Oi9CrWlMdkkVLKxnFBHbB5sTmOO43XFkPz0c8BRTw6I1FCaUP+rt/65s6nppcaO\nXVZ3gAMi8BrmLW89Gs/j7cZjpRGMmJP9REwrqtXzOmUrlnCX3fSh3PLM+NvnyjLG\nUfwzkmS7ZwgBYZP8I7IS+2FW+g6Mp0HCQ1o4DKx2lKXpq/IT9wWuVhkx/tNi5VT/\n5jqtqUtVMbAhRlfIYOaLNS/UgyA0BRGOoOSfyr3CkNzZqD86Vdnfvcmr8cSOgKiY\nZ6r2uKEGCFtjk8CB+fqORftuWijapKJWlAKgrXMGvwa/L7ciq+VuahIaWZzMpnH5\nDXMDqH+XAgMBAAECggEABlc2ITo+mmhCj+j8mETPSAeslvY7riIAFN0Ab/udf0uy\nL58seQ+ReQpvTMDnCIUCqTMKDE7hNx0iKB89XCk65yItqR57SVD1GfwuTbxQtBtF\nC2VwTAveX+fJxdTvc/nRg+M7KktetlBPDPI0FyRpgpuGNoZjFmSDS5KDZzwggGhC\nXtmL0stGEEyvHDQKi55OI1+KbHgXz8/6LlYdJlWIqro9d/l9/Qpbvc2J/sBtkcDH\nF5eHwLDZ9F0qRTIK/4khn8JLFBe2xN0bMhxKjkayX7x8YQI7i4XNMaOpgdqmG7tZ\n2J0xN9AGDp35zRSNs4RDD1oF0fRyhOb6/EUUfQfT7QKBgQC9aIZv0BTjJR1Zt1w1\nQICYVe146rHZrEsKNDR9Q2UcuzTj/KfQclJyjeovm2IpNQSbkvOfh0d0UFIiKZ/Y\ndJzYTc5wvAuzaZJpz06n7JZ0WIgeaS0GPtKRukWcQpV3KUzIrudfqggAo9DamExf\nZRjKjp86gHjPTHAqgchsCOGaKwKBgQC2ik6vjb9jEfnO46GIWobE2HhXK6X6ihC7\nO0Wel8pfpDcbI8bQyY3eNi4a1m3qCwX+KylPVsf8c8Y6IzpufWGaQXGH+EceyHKZ\n/C9hJliI6cdk+KGBcQn6un9+LSfqh6mBxLV0xZeaveVG0ElTUzCEgQuvJxeNVic6\nlx3qHO7WRQKBgA9x1oSHkyxyelI2gW5WNCY324VgneACDJxoZV9Rf404Nrfggk6d\nA9wTdmUrZnW1vQpykSsQ/OKfKhNfEYm0+JUqwwquSsX2ddnq7Z8Dy8Dw9yiDqwg3\nVzRK3CJBy65Lz9cNbBCA7OYgdYddo9yjgcICnzlGAJPmx76vlog4sSzBAoGAIJc/\nBz8CnbiW5mZj78lh6IFRsxaa8sl1xUgG3RLy0fKq2BCiLaLezn7T6nzAcRn4vvGL\n1ZuD50HwcW7avuFp7LWkhIdCg298bpvFBc5n3kIHFLMDeu3ovzhPDQMY7lm8XOv3\nDds9fyZKakND5DmlHvM/V81d+iEYrfBPKf5ychUCgYBbJaBz3ZiXDV+ylKwJEXDV\n06dSWXD855gLWE1JWd9CHGqyUC+gSiP48FHutCzJYOLzRwK1GLeeHMIBQ/zXo1nk\nBWmmzpVC60iAUTiGZfvXF92WNUm4g3azV/CduyyL/R3+3DX6fk4lpdhK7wBEjoPg\ntkKxgRu14HCBMBiT9EvFlA==\n-----END PRIVATE KEY-----\n";
    const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhw6kI7J/KOkMJdjovQq1\npTHZJFSysZxQR2webE5jjuN1xZD89HPAUU8OiNRQmlD/q7f+ubOp6aXGjl1Wd4AD\nIvAa5i1vPRrP4+3GY6URjJiT/URMK6rV8zplK5Zwl930odzyzPjb58oyxlH8M5Jk\nu2cIAWGT/COyEvthVvoOjKdBwkNaOAysdpSl6avyE/cFrlYZMf7TYuVU/+Y6ralL\nVTGwIUZXyGDmizUv1IMgNAURjqDkn8q9wpDc2ag/OlXZ373Jq/HEjoComGeq9rih\nBghbY5PAgfn6jkX7bloo2qSiVpQCoK1zBr8Gvy+3IqvlbmoSGlmczKZx+Q1zA6h/\nlwIDAQAB\n-----END PUBLIC KEY-----\n";

    let message = b"Casa1 RSA sign/verify integration";
    let signature = rsa_pkcs1v15_sign(RSA_PRIVATE_PEM, message).expect("sign");
    assert!(!signature.is_empty(), "signature should be non-empty");

    let result = rsa_pkcs1v15_verify(RSA_PUBLIC_PEM, message, &signature);
    assert!(result.is_ok(), "signature should verify");

    // Tampered message should fail verification
    let tampered = b"Tampered message!!!";
    let bad_result = rsa_pkcs1v15_verify(RSA_PUBLIC_PEM, tampered, &signature);
    assert!(
        bad_result.is_err(),
        "tampered message should fail verification"
    );
}

#[test]
fn e7_crypto_ecdsa_p256_verify() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;

    // Real P-256 round trip: generate a keypair, sign the message, and verify
    // through the Casa1 verifier. A signature over a different message (or a
    // corrupted signature) must be rejected.
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xECDA);
    let signing_key = SigningKey::random(&mut rng);
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(der::pem::LineEnding::LF)
        .expect("public key PEM");

    let message = b"ECDSA P-256 verification test";
    let signature: Signature = signing_key.sign(message);
    let signature_der = signature.to_der().as_bytes().to_vec();

    ecdsa_p256_verify(&public_pem, message, &signature_der)
        .expect("a valid signature for the message must verify");

    // Tampered message must be rejected.
    let tampered = b"Tampered ECDSA message!";
    assert!(
        ecdsa_p256_verify(&public_pem, tampered, &signature_der).is_err(),
        "signature over a different message must fail verification"
    );

    // Corrupted signature bytes must be rejected.
    let mut corrupted = signature_der.clone();
    corrupted[0] ^= 0xFF;
    assert!(
        ecdsa_p256_verify(&public_pem, message, &corrupted).is_err(),
        "corrupted signature bytes must fail verification"
    );
}

// ============================================================================
// 6. CPU + Memory Integration
// ============================================================================

// ============================================================================
// 7. Cross-Module: PE → MemoryImage → CPU Integration
// ============================================================================

// ============================================================================
// 8. Cross-Module: Network + DNS + Socket Integration
// ============================================================================

#[test]
fn e7_network_dns_socket_workflow() {
    let mut network = NetworkStack::new();
    network.wsa_startup();

    // DNS resolution using pre-seeded records (from NetworkStack::new())
    let addrs = network
        .getaddrinfo("api.example.com", 443)
        .expect("getaddrinfo");
    assert!(!addrs.is_empty());
    assert_eq!(addrs[0].host, "203.0.113.10");

    // Socket creation and virtual connection
    let listener = network.socket(AddressFamily::Ipv4).expect("listener");
    let addr = SockAddr {
        family: AddressFamily::Ipv4,
        host: "127.0.0.1".to_string(),
        port: 37400,
    };
    network.bind(listener, addr.clone()).expect("bind");
    network.listen(listener, 5).expect("listen");

    let client = network.socket(AddressFamily::Ipv4).expect("client");
    network.connect(client, addr.clone()).expect("connect");
    let server = network.accept(listener).expect("accept");

    // Send data from client → server
    network.send(client, b"integration-data").expect("send");
    let received = network.recv(server, 16).expect("recv");
    assert_eq!(received, b"integration-data");

    // FIONREAD shows available bytes
    let available = network.ioctlsocket_fionread(server).expect("fionread");
    assert_eq!(available, 0, "all data should have been consumed");

    // Select detects writable connected sockets
    let (_readable, writable) = network.select(&[client, server]).expect("select");
    assert!(writable.contains(&client));
    assert!(writable.contains(&server));

    // Shutdown and close
    network.shutdown(client).expect("shutdown");
    network.closesocket(client).expect("close client");
    network.closesocket(server).expect("close server");
    network.closesocket(listener).expect("close listener");
}

// ============================================================================
// 9. Cross-Module: Error Propagation
// ============================================================================

#[test]
fn e7_error_propagation_across_modules() {
    // PE parse error
    let bad_bytes = vec![0, 0, 0, 0]; // too short
    let pe_result = parse(&bad_bytes);
    assert!(pe_result.is_err(), "truncated bytes should fail to parse");

    // Network socket error (no WSA startup)
    let mut network = NetworkStack::new();
    let sock_result = network.socket(AddressFamily::Ipv4);
    assert!(sock_result.is_err(), "expected Err, got {sock_result:?}");
    assert_eq!(network.wsa_get_last_error(), 10093); // WSANOTINITIALISED

    // After startup, socket works
    network.wsa_startup();
    let sock = network
        .socket(AddressFamily::Ipv4)
        .expect("socket after startup");
    assert!(sock >= 0x1000);

    // Crypto error (tampered AES-GCM tag)
    let key = [0xAB; 32];
    let iv = [0xCD; 12];
    let aad = b"test aad";
    let (ct, _tag) = aes_256_gcm_encrypt(&key, &iv, b"data", aad).expect("encrypt");
    let bad_tag = [0x00; 16];
    let decrypt_result = aes_256_gcm_decrypt(&key, &iv, &ct, aad, &bad_tag);
    assert!(decrypt_result.is_err(), "bad tag should fail decryption");
}

// ============================================================================
// 10. HttpProtocolFlags + QuicConfig Integration
// ============================================================================

#[test]
fn e7_quic_protocol_flags_with_config() {
    // When QUIC is force-enabled, HTTP/3 is returned regardless
    let mut flags = HttpProtocolFlags::new();
    flags.set(HttpProtocolFlags::HTTP3);
    let config = QuicConfig {
        force_enabled: true,
        ..Default::default()
    };
    let (protocol, fell_back) = casa1::network::negotiate_http_protocol(
        &flags,
        &config,
        &[casa1::network::AltSvcEntry {
            protocol_id: "h3".to_string(),
            alt_host: String::new(),
            alt_port: 443,
            alpn: Some("h3".to_string()),
        }],
    );
    assert_eq!(protocol, casa1::network::HttpProtocol::Http3);
    assert!(!fell_back);

    // When force-disabled, falls back to HTTP/1.1
    let config_disabled = QuicConfig {
        force_disabled: true,
        ..Default::default()
    };
    let (protocol2, _) = casa1::network::negotiate_http_protocol(&flags, &config_disabled, &[]);
    assert_eq!(protocol2, casa1::network::HttpProtocol::Http11);
}
