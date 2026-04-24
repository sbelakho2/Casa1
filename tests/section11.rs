use casa1::network::{
    aes_128_cbc_decrypt, aes_128_cbc_encrypt, aes_256_gcm_decrypt, aes_256_gcm_encrypt,
    ecdsa_p256_verify, hmac_sha256, rsa_pkcs1v15_sign, rsa_pkcs1v15_verify, secure_random,
    sha1_hash, sha256_hash, AddressFamily, Certificate, Cookie, NetworkStack, SockAddr,
};
use casa1::reason::ReasonCode;
use std::collections::BTreeMap;

const MESSAGE: &[u8] = b"Casa1 network crypto vector\n";
const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCHDqQjsn8o6Qwl\n2Oi9CrWlMdkkVLKxnFBHbB5sTmOO43XFkPz0c8BRTw6I1FCaUP+rt/65s6nppcaO\nXVZ3gAMi8BrmLW89Gs/j7cZjpRGMmJP9REwrqtXzOmUrlnCX3fSh3PLM+NvnyjLG\nUfwzkmS7ZwgBYZP8I7IS+2FW+g6Mp0HCQ1o4DKx2lKXpq/IT9wWuVhkx/tNi5VT/\n5jqtqUtVMbAhRlfIYOaLNS/UgyA0BRGOoOSfyr3CkNzZqD86Vdnfvcmr8cSOgKiY\nZ6r2uKEGCFtjk8CB+fqORftuWijapKJWlAKgrXMGvwa/L7ciq+VuahIaWZzMpnH5\nDXMDqH+XAgMBAAECggEABlc2ITo+mmhCj+j8mETPSAeslvY7riIAFN0Ab/udf0uy\nL58seQ+ReQpvTMDnCIUCqTMKDE7hNx0iKB89XCk65yItqR57SVD1GfwuTbxQtBtF\nC2VwTAveX+fJxdTvc/nRg+M7KktetlBPDPI0FyRpgpuGNoZjFmSDS5KDZzwggGhC\nXtmL0stGEEyvHDQKi55OI1+KbHgXz8/6LlYdJlWIqro9d/l9/Qpbvc2J/sBtkcDH\nF5eHwLDZ9F0qRTIK/4khn8JLFBe2xN0bMhxKjkayX7x8YQI7i4XNMaOpgdqmG7tZ\n2J0xN9AGDp35zRSNs4RDD1oF0fRyhOb6/EUUfQfT7QKBgQC9aIZv0BTjJR1Zt1w1\nQICYVe146rHZrEsKNDR9Q2UcuzTj/KfQclJyjeovm2IpNQSbkvOfh0d0UFIiKZ/Y\ndJzYTc5wvAuzaZJpz06n7JZ0WIgeaS0GPtKRukWcQpV3KUzIrudfqggAo9DamExf\nZRjKjp86gHjPTHAqgchsCOGaKwKBgQC2ik6vjb9jEfnO46GIWobE2HhXK6X6ihC7\nO0Wel8pfpDcbI8bQyY3eNi4a1m3qCwX+KylPVsf8c8Y6IzpufWGaQXGH+EceyHKZ\n/C9hJliI6cdk+KGBcQn6un9+LSfqh6mBxLV0xZeaveVG0ElTUzCEgQuvJxeNVic6\nlx3qHO7WRQKBgA9x1oSHkyxyelI2gW5WNCY324VgneACDJxoZV9Rf404Nrfggk6d\nA9wTdmUrZnW1vQpykSsQ/OKfKhNfEYm0+JUqwwquSsX2ddnq7Z8Dy8Dw9yiDqwg3\nVzRK3CJBy65Lz9cNbBCA7OYgdYddo9yjgcICnzlGAJPmx76vlog4sSzBAoGAIJc/\nBz8CnbiW5mZj78lh6IFRsxaa8sl1xUgG3RLy0fKq2BCiLaLezn7T6nzAcRn4vvGL\n1ZuD50HwcW7avuFp7LWkhIdCg298bpvFBc5n3kIHFLMDeu3ovzhPDQMY7lm8XOv3\nDds9fyZKakND5DmlHvM/V81d+iEYrfBPKf5ychUCgYBbJaBz3ZiXDV+ylKwJEXDV\n06dSWXD855gLWE1JWd9CHGqyUC+gSiP48FHutCzJYOLzRwK1GLeeHMIBQ/zXo1nk\nBWmmzpVC60iAUTiGZfvXF92WNUm4g3azV/CduyyL/R3+3DX6fk4lpdhK7wBEjoPg\ntkKxgRu14HCBMBiT9EvFlA==\n-----END PRIVATE KEY-----\n";
const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhw6kI7J/KOkMJdjovQq1\npTHZJFSysZxQR2webE5jjuN1xZD89HPAUU8OiNRQmlD/q7f+ubOp6aXGjl1Wd4AD\nIvAa5i1vPRrP4+3GY6URjJiT/URMK6rV8zplK5Zwl930odzyzPjb58oyxlH8M5Jk\nu2cIAWGT/COyEvthVvoOjKdBwkNaOAysdpSl6avyE/cFrlYZMf7TYuVU/+Y6ralL\nVTGwIUZXyGDmizUv1IMgNAURjqDkn8q9wpDc2ag/OlXZ373Jq/HEjoComGeq9rih\nBghbY5PAgfn6jkX7bloo2qSiVpQCoK1zBr8Gvy+3IqvlbmoSGlmczKZx+Q1zA6h/\nlwIDAQAB\n-----END PUBLIC KEY-----\n";
const ECDSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPjYt919yJcGTho/pY00Zy9Gegq8t\n/HKI7RNLcR8eZTL6b+jDSzqJNxL3f2g62soLB8AaK7UNQYuJcvkxji+sRQ==\n-----END PUBLIC KEY-----\n";

fn hex_decode(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.chars();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let value = high.to_digit(16).expect("hex high") * 16 + low.to_digit(16).expect("hex low");
        bytes.push(value as u8);
    }
    bytes
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[test]
fn t11_1_winsock_differential_suite_matches_blocking_nonblocking_dns_and_error_code_oracles() {
    let mut stack = NetworkStack::new();
    stack.wsa_startup();
    let listener = stack.socket(AddressFamily::Ipv4).expect("create listener socket");
    stack
        .bind(
            listener,
            SockAddr {
                family: AddressFamily::Ipv4,
                host: "127.0.0.1".to_string(),
                port: 27015,
            },
        )
        .expect("bind listener");
    stack.listen(listener, 4).expect("listen");
    let duplicate = stack.socket(AddressFamily::Ipv4).expect("create duplicate socket");
    let bind_error = stack
        .bind(
            duplicate,
            SockAddr {
                family: AddressFamily::Ipv4,
                host: "127.0.0.1".to_string(),
                port: 27015,
            },
        )
        .expect_err("duplicate bind must fail");
    assert_eq!(bind_error.code, ReasonCode::RcIo);
    assert_eq!(stack.wsa_get_last_error(), 10048);

    let client = stack.socket(AddressFamily::Ipv4).expect("create client socket");
    stack.ioctlsocket_fionbio(client, true).expect("enable nonblocking mode");
    stack
        .connect(
            client,
            SockAddr {
                family: AddressFamily::Ipv4,
                host: "127.0.0.1".to_string(),
                port: 27015,
            },
        )
        .expect("connect to listener");
    let (readable, writable) = stack.select(&[listener, client]).expect("select sockets");
    assert!(writable.contains(&client));
    assert!(readable.contains(&listener));
    let polled = stack.wsa_poll(&[listener, client]).expect("poll sockets");
    assert!(polled.iter().any(|entry| entry.socket == listener && entry.readable));
    let accepted = stack.accept(listener).expect("accept pending connection");
    let (_, writable_after_accept) = stack
        .select(&[listener, client, accepted])
        .expect("select sockets after accept");
    let polled = stack
        .wsa_poll(&[listener, client, accepted])
        .expect("poll sockets after accept");
    assert!(polled.iter().any(|entry| entry.socket == client && entry.writable));
    assert!(writable_after_accept.contains(&client));

    stack.send(client, b"ping").expect("send bytes");
    assert_eq!(stack.recv(accepted, 4).expect("recv bytes"), b"ping");
    let would_block = stack.recv(client, 4).expect_err("empty nonblocking recv must fail");
    assert_eq!(would_block.code, ReasonCode::RcWinsockWouldBlock);
    assert_eq!(stack.wsa_get_last_error(), 10035);

    let addresses = stack.getaddrinfo("example.com", 443).expect("resolve example.com");
    assert_eq!(addresses.len(), 2);
    assert_eq!(addresses[0].family, AddressFamily::Ipv4);
    assert_eq!(addresses[1].family, AddressFamily::Ipv6);
    stack.freeaddrinfo();
    let missing = stack.getaddrinfo("missing.example", 443).expect_err("missing host must fail");
    assert_eq!(missing.code, ReasonCode::RcDnsNotFound);
    assert_eq!(stack.wsa_get_last_error(), 11001);

    let unopened = stack.socket(AddressFamily::Ipv4).expect("create unopened client");
    let refused = stack
        .connect(
            unopened,
            SockAddr {
                family: AddressFamily::Ipv4,
                host: "127.0.0.1".to_string(),
                port: 12345,
            },
        )
        .expect_err("connect to unopened port must fail");
    assert_eq!(refused.code, ReasonCode::RcIo);
    assert_eq!(stack.wsa_get_last_error(), 10061);
    stack.shutdown(client).expect("shutdown client");
    stack.closesocket(client).expect("close client socket");
    stack.wsa_cleanup();
}

#[test]
fn t11_2_http_replay_suite_matches_status_headers_cookie_persistence_and_proxy_oracles() {
    let mut stack = NetworkStack::new();
    let root = Certificate {
        subject: "Casa1 Root".to_string(),
        issuer: "Casa1 Root".to_string(),
        fingerprint: "root-1".to_string(),
        valid_hostnames: vec!["Casa1 Root".to_string()],
        not_after_day: 365,
        revoked: false,
        supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
    };
    let leaf = Certificate {
        subject: "api.example.com".to_string(),
        issuer: "Casa1 Root".to_string(),
        fingerprint: "leaf-1".to_string(),
        valid_hostnames: vec!["api.example.com".to_string()],
        not_after_day: 365,
        revoked: false,
        supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
    };
    stack.import_certificate(root.clone());
    stack.add_route(
        "https",
        "api.example.com",
        "/login",
        200,
        BTreeMap::from([("x-casa1-route".to_string(), "login".to_string())]),
        br#"{"ok":true}"#,
        vec![Cookie {
            name: "session".to_string(),
            value: "abc123".to_string(),
            domain: ".example.com".to_string(),
            path: "/store".to_string(),
            secure: true,
        }],
        vec![leaf.clone(), root.clone()],
    );
    stack.add_route(
        "https",
        "api.example.com",
        "/store/cart",
        200,
        BTreeMap::from([("x-casa1-route".to_string(), "cart".to_string())]),
        b"cart",
        Vec::new(),
        vec![leaf.clone(), root.clone()],
    );
    assert!(!stack.keychain_mapping_enabled());
    stack.set_env_proxy(Some("http://env.proxy:8080".to_string()));
    stack.set_system_proxy(Some("http://system.proxy:3128".to_string()), true);

    let session = stack.win_http_open("Casa1");
    stack
        .win_http_set_proxy(session, Some("http://explicit.proxy:9000".to_string()))
        .expect("set explicit proxy");
    let connection = stack
        .win_http_connect(session, "api.example.com", 443, true)
        .expect("connect winhttp");
    let request = stack
        .win_http_open_request(connection, "POST", "/login")
        .expect("open request");
    stack
        .win_http_send_request(request, BTreeMap::new(), b"{}")
        .expect("send request");
    stack
        .win_http_receive_response(request)
        .expect("receive response");
    let headers = stack.win_http_query_headers(request).expect("query headers");
    assert_eq!(headers.get("status").expect("status header"), "200");
    assert_eq!(headers.get("x-casa1-route").expect("route header"), "login");
    assert_eq!(stack.win_http_read_data(request, 32).expect("read login body"), br#"{"ok":true}"#);

    let snapshot = stack.cookie_snapshot_json().expect("cookie snapshot");
    let mut restored = NetworkStack::new();
    restored.import_certificate(root.clone());
    restored.add_route(
        "https",
        "api.example.com",
        "/store/cart",
        200,
        BTreeMap::from([("x-casa1-route".to_string(), "cart".to_string())]),
        b"cart",
        Vec::new(),
        vec![leaf.clone(), root.clone()],
    );
    restored.load_cookie_snapshot_json(&snapshot).expect("load cookies");
    restored.set_system_proxy(Some("http://system.proxy:3128".to_string()), true);
    let wininet_session = restored.internet_open("Casa1 launcher");
    let wininet_connection = restored
        .internet_connect(wininet_session, "api.example.com", 443, true)
        .expect("connect wininet");
    let wininet_request = restored
        .http_open_request(wininet_connection, "GET", "/store/cart")
        .expect("open wininet request");
    restored
        .http_send_request(wininet_request, BTreeMap::new(), b"")
        .expect("send wininet request");
    assert_eq!(restored.internet_read_file(wininet_request, 16).expect("read wininet body"), b"cart");
    let trace = restored.http_traces().last().expect("http trace");
    assert_eq!(trace.cookie_header, "session=abc123");
    assert_eq!(trace.proxy, Some("http://system.proxy:3128".to_string()));
    assert_eq!(trace.cipher_suite, Some("TLS_AES_128_GCM_SHA256".to_string()));
    assert_eq!(restored.export_certificates(), vec![root]);
}

#[test]
fn t11_3_tls_negative_cases_reject_expired_wrong_hostname_and_untrusted_chains_like_windows() {
    let root = Certificate {
        subject: "Casa1 Root".to_string(),
        issuer: "Casa1 Root".to_string(),
        fingerprint: "root-1".to_string(),
        valid_hostnames: vec!["Casa1 Root".to_string()],
        not_after_day: 365,
        revoked: false,
        supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
    };
    let valid_leaf = Certificate {
        subject: "api.example.com".to_string(),
        issuer: "Casa1 Root".to_string(),
        fingerprint: "leaf-valid".to_string(),
        valid_hostnames: vec!["api.example.com".to_string()],
        not_after_day: 365,
        revoked: false,
        supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
    };
    let expired_leaf = Certificate {
        not_after_day: 1,
        ..valid_leaf.clone()
    };
    let wrong_host_leaf = Certificate {
        valid_hostnames: vec!["other.example.com".to_string()],
        ..valid_leaf.clone()
    };
    let untrusted_root = Certificate {
        fingerprint: "root-2".to_string(),
        subject: "Untrusted Root".to_string(),
        ..root.clone()
    };

    let mut stack = NetworkStack::new();
    stack.import_certificate(root.clone());
    stack.set_current_day(10);
    assert_eq!(
        stack
            .validate_server_certificate("api.example.com", &[valid_leaf.clone(), root.clone()], true)
            .expect("valid TLS chain"),
        "TLS_AES_128_GCM_SHA256"
    );

    let expired = stack
        .validate_server_certificate("api.example.com", &[expired_leaf, root.clone()], true)
        .expect_err("expired cert must be rejected");
    assert_eq!(expired.code, ReasonCode::RcTlsCertRejected);
    let wrong_host = stack
        .validate_server_certificate("api.example.com", &[wrong_host_leaf, root.clone()], true)
        .expect_err("hostname mismatch must be rejected");
    assert_eq!(wrong_host.code, ReasonCode::RcTlsCertRejected);
    let untrusted = stack
        .validate_server_certificate("api.example.com", &[valid_leaf, untrusted_root], true)
        .expect_err("untrusted root must be rejected");
    assert_eq!(untrusted.code, ReasonCode::RcTlsCertRejected);
}

#[test]
fn t11_4_crypto_test_vectors_match_reference_outputs_and_secure_rng_is_not_reused() {
    assert_eq!(
        hex_encode(&sha1_hash(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex_encode(&sha256_hash(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex_encode(&hmac_sha256(&[0x0b; 20], b"Hi There").expect("HMAC-SHA256 vector")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );

    let cbc_key = hex_decode("2b7e151628aed2a6abf7158809cf4f3c");
    let cbc_iv = hex_decode("000102030405060708090a0b0c0d0e0f");
    let plaintext = hex_decode("6bc1bee22e409f96e93d7e117393172a");
    let ciphertext = aes_128_cbc_encrypt(
        &cbc_key.clone().try_into().expect("AES-128 key"),
        &cbc_iv.clone().try_into().expect("AES-CBC IV"),
        &plaintext,
    )
    .expect("AES-CBC encrypt");
    assert_eq!(hex_encode(&ciphertext), "7649abac8119b246cee98e9b12e9197d");
    assert_eq!(
        aes_128_cbc_decrypt(
            &cbc_key.try_into().expect("AES-128 key"),
            &cbc_iv.try_into().expect("AES-CBC IV"),
            &ciphertext,
        )
        .expect("AES-CBC decrypt"),
        plaintext
    );

    let gcm_key = [0_u8; 32];
    let gcm_nonce = [0_u8; 12];
    let gcm_plaintext = [0_u8; 16];
    let (gcm_ciphertext, gcm_tag) = aes_256_gcm_encrypt(&gcm_key, &gcm_nonce, &gcm_plaintext, b"")
        .expect("AES-GCM encrypt");
    assert_eq!(hex_encode(&gcm_ciphertext), "cea7403d4d606b6e074ec5d3baf39d18");
    assert_eq!(hex_encode(&gcm_tag), "d0d1c8a799996bf0265b98b5d48ab919");
    assert_eq!(
        aes_256_gcm_decrypt(&gcm_key, &gcm_nonce, &gcm_ciphertext, b"", &gcm_tag)
            .expect("AES-GCM decrypt"),
        gcm_plaintext
    );

    let rsa_signature = rsa_pkcs1v15_sign(RSA_PRIVATE_PEM, MESSAGE).expect("RSA sign");
    assert_eq!(
        hex_encode(&rsa_signature),
        "6f139a973312bc6db5eda84ad42c5c4678e18ea84c41b943e12878a48a06bc6e0b6ade8c255e9e25643e9c5e8f34fd3097186e2cc4308b1701315ee4a6a83fe91647e4f92a7e9a817163ee835b46d9e6a530e803511c74cb7ffc3cffd57ebbf07f74b5e691d0418c60506a57ff4bebd0998f41658e33fc6bea99c9ca115068aa8a4db233707c97fdcdbef4c5b998c176fece1c2f562c5fa1884ad5645a5ad8c812669699768400d3e794799a8757fd3f233fcd898b17218fd1cc01148e9b17367bd64e630c588f0e3460309a23ad3ab9076d741876c72b539e6e8008fbfec3d203677c26f8530a1fc3b1eefdf01f1f678b3e677a9c134d1dd3806987364294fb"
    );
    rsa_pkcs1v15_verify(RSA_PUBLIC_PEM, MESSAGE, &rsa_signature).expect("RSA verify");
    let ecdsa_signature = hex_decode(
        "3045022100ed404327e0e50b9e371e55c38e411e67ad091f47ffaa597050cba2dd352467bb02205659f8687fd513860a5b212b9f2a8ed3dab64c2282c920c3c237f3c50757daa2",
    );
    ecdsa_p256_verify(ECDSA_PUBLIC_PEM, MESSAGE, &ecdsa_signature).expect("ECDSA verify");

    let rng_a = secure_random(32);
    let rng_b = secure_random(32);
    assert_ne!(rng_a, rng_b);
    assert!(rng_a.iter().any(|byte| *byte != 0));
    assert!(rng_b.iter().any(|byte| *byte != 0));
}