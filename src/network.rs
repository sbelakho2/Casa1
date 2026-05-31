use crate::error::{AppError, AppResult};
use base64::{Engine as _, engine::general_purpose};
use der::{Decode, Encode};
use x509_cert::Certificate as X509Certificate;
use std::time::Duration;
use crate::reason::ReasonCode;
use aes::Aes128;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use rand::rngs::OsRng;
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::net::{Shutdown as NetShutdown, SocketAddr as NetSocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;

type HmacSha256 = Hmac<Sha256>;

/// ---------------------------------------------------------------------------
/// QUIC/HTTP3 Support
/// ---------------------------------------------------------------------------

/// Protocol flags matching Windows WINHTTP_PROTOCOL_FLAGS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProtocolFlags(pub u32);

impl HttpProtocolFlags {
    pub const HTTP2: u32 = 0x0001;
    pub const HTTP3: u32 = 0x0002;

    pub fn new() -> Self {
        Self(0)
    }

    pub fn contains(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    pub fn set(&mut self, flag: u32) {
        self.0 |= flag;
    }
}

impl Default for HttpProtocolFlags {
    fn default() -> Self {
        Self::new()
    }
}

/// An entry parsed from an Alt-Svc header (used for HTTP/3 discovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AltSvcEntry {
    /// The ALPN protocol ID (e.g. "h3", "h2", "h3-29").
    pub protocol_id: String,
    /// The host to use for this alternative service (may be empty for same host).
    pub alt_host: String,
    /// The port for this alternative service.
    pub alt_port: u16,
    /// Optional ALPN token for TLS negotiation.
    pub alpn: Option<String>,
}

/// Configuration for QUIC/HTTP3 support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Whether QUIC/HTTP3 is force-enabled (if true, an error is raised when
    /// HTTP/3 is requested but unavailable).
    pub force_enabled: bool,
    /// Whether QUIC/HTTP3 is force-disabled (if true, HTTP/3 is never used).
    pub force_disabled: bool,
    /// Whether to log QUIC fallback events.
    pub log_fallback: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            force_enabled: false,
            force_disabled: false,
            log_fallback: true,
        }
    }
}

/// The current protocol being used for an HTTP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpProtocol {
    Http11,
    Http2,
    Http3,
}

impl HttpProtocol {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "h2",
            Self::Http3 => "h3",
        }
    }
}

pub type SocketId = u64;
pub type HttpSessionId = u64;
pub type HttpConnectionId = u64;
pub type HttpRequestId = u64;

const WSAEWOULDBLOCK: i32 = 10035;
const WSAEADDRINUSE: i32 = 10048;
const WSAECONNRESET: i32 = 10054;
const WSAENOTCONN: i32 = 10057;
const WSAETIMEDOUT: i32 = 10060;
const WSAECONNREFUSED: i32 = 10061;
const WSANOTINITIALISED: i32 = 10093;
const WSAHOST_NOT_FOUND: i32 = 11001;

// ---------------------------------------------------------------------------
// G8: Certificate pinning — HPKP-style public key pinning
// ---------------------------------------------------------------------------

/// A single certificate pin entry: maps a hostname to a set of accepted SPKI
/// fingerprints (base64-encoded SHA-256 of the SubjectPublicKeyInfo).
#[derive(Debug, Clone)]
pub struct CertificatePin {
    /// The hostname this pin applies to (e.g. "example.com").
    pub hostname: String,
    /// Base64-encoded SHA-256 SPKI fingerprints that are accepted.
    pub fingerprints: Vec<String>,
}

/// Manages certificate pin expectations for known hosts.
///
/// Pinning enforces that the server's certificate chain contains at least one
/// public key whose SPKI fingerprint matches an expected value. This prevents
/// MITM attacks even if a CA is compromised.
///
/// # Implementation Notes
/// `native_tls` does not expose the peer certificate chain after the TLS
/// handshake in its public API. Therefore pinning is implemented via:
/// 1. Pre-connection configuration (store pin expectations)
/// 2. Custom TLS builder that would inspect certificates if available
/// 3. Post-connection verification using raw TLS stream inspection
#[derive(Debug, Default)]
pub struct PinnedCertificates {
    /// Pins indexed by hostname (lowercase).
    pins: BTreeMap<String, Vec<String>>,
}

impl PinnedCertificates {
    /// Create a new empty pin set.
    pub fn new() -> Self {
        Self {
            pins: BTreeMap::new(),
        }
    }

    /// Add a pin for a specific hostname.
    ///
    /// `fingerprint` is a base64-encoded SHA-256 hash of the DER-encoded SPKI.
    pub fn add_pin(&mut self, hostname: &str, fingerprint: &str) {
        let host = hostname.to_lowercase();
        self.pins.entry(host).or_default().push(fingerprint.to_string());
    }

    /// Add multiple pins for a hostname.
    pub fn add_pins(&mut self, hostname: &str, fingerprints: &[String]) {
        let host = hostname.to_lowercase();
        self.pins.entry(host).or_default().extend_from_slice(fingerprints);
    }

    /// Check if a hostname has any pins configured.
    pub fn has_pins_for(&self, hostname: &str) -> bool {
        self.pins.contains_key(&hostname.to_lowercase())
    }

    /// Get the pins for a hostname, if any.
    pub fn pins_for(&self, hostname: &str) -> Option<&Vec<String>> {
        self.pins.get(&hostname.to_lowercase())
    }

    /// Verify a certificate chain against the pins for the given hostname.
    ///
    /// Returns `Ok(())` if:
    /// - No pins are configured for the hostname (no pinning required)
    /// - At least one certificate in the chain has a matching SPKI fingerprint
    ///
    /// Returns `Err(AppError)` if pins are configured but none match.
    ///
    /// # Implementation
    /// Each DER-encoded certificate in `der_certs` is parsed using the
    /// `x509-cert` crate. The SubjectPublicKeyInfo (SPKI) is extracted and
    /// re-encoded to DER bytes, then SHA-256 hashed and base64-encoded.
    /// The resulting fingerprint is compared against the configured pins.
    /// If no certificate matches, the connection is rejected (fail-closed).
    pub fn verify(&self, hostname: &str, der_certs: &[Vec<u8>]) -> AppResult<()> {
        let host = hostname.to_lowercase();
        if let Some(expected_pins) = self.pins.get(&host) {
            for der in der_certs {
                // Parse the DER-encoded X.509 certificate
                let cert = X509Certificate::from_der(der).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetConnectionFailed,
                        format!(
                            "certificate pinning: failed to parse DER certificate for {host}: {e}"
                        ),
                    )
                })?;

                // Re-encode the SubjectPublicKeyInfo to DER bytes
                let spki_der = cert
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()
                    .map_err(|e| {
                        AppError::new(
                            ReasonCode::RcNetConnectionFailed,
                            format!(
                                "certificate pinning: failed to encode SPKI for {host}: {e}"
                            ),
                        )
                    })?;

                // Compute SHA-256 hash of the DER-encoded SPKI
                let hash = Sha256::digest(&spki_der);

                // Base64-encode the hash and compare against expected pins
                let fingerprint = general_purpose::STANDARD.encode(hash);
                if expected_pins.iter().any(|pin| pin == &fingerprint) {
                    return Ok(());
                }
            }

            // No certificate matched any pin — fail closed
            return Err(AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!(
                    "certificate pinning: no matching SPKI fingerprint for {host} \
                     (checked {} certificate(s))",
                    der_certs.len(),
                ),
            ));
        }
        Ok(())
    }

    /// Clear all pins.
    pub fn clear(&mut self) {
        self.pins.clear();
    }

    /// Number of hostnames with pins configured.
    pub fn len(&self) -> usize {
        self.pins.len()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SockAddr {
    pub family: AddressFamily,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollState {
    pub socket: SocketId,
    pub readable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedAddr {
    pub family: AddressFamily,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub fingerprint: String,
    pub valid_hostnames: Vec<String>,
    pub not_after_day: i64,
    pub revoked: bool,
    pub supported_ciphers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpTrace {
    pub stack: String,
    pub host: String,
    pub path: String,
    pub proxy: Option<String>,
    pub cookie_header: String,
    pub cipher_suite: Option<String>,
    pub status: u16,
}

#[derive(Debug, Clone)]
struct SocketRecord {
    family: AddressFamily,
    nonblocking: bool,
    bound_addr: Option<SockAddr>,
    state: SocketState,
    recv_queue: VecDeque<u8>,
}

#[derive(Debug, Clone)]
enum SocketState {
    Created,
    Bound(SockAddr),
    Listening { _addr: SockAddr, _backlog: usize },
    Connected { peer: SocketId },
    ConnectedReal { _peer: SockAddr },
    Shutdown,
    Closed,
}

#[derive(Debug, Clone)]
struct HttpSessionRecord {
    stack: String,
    proxy_override: Option<String>,
}

#[derive(Debug, Clone)]
struct HttpConnectionRecord {
    session: HttpSessionId,
    host: String,
    _port: u16,
    secure: bool,
}

#[derive(Debug, Clone)]
struct HttpRequestRecord {
    connection: HttpConnectionId,
    _method: String,
    path: String,
    response: Option<HttpResponseRecord>,
    read_offset: usize,
}

#[derive(Debug, Clone)]
struct HttpResponseTemplate {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    cookies: Vec<Cookie>,
    certificate_chain: Vec<Certificate>,
}

#[derive(Debug, Clone)]
struct HttpResponseRecord {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
struct ProxySettings {
    env_proxy: Option<String>,
    system_proxy: Option<String>,
    map_system_proxy: bool,
}

#[derive(Debug, Clone)]
struct AddressFamilyRecord {
    family: AddressFamily,
    host: String,
}

#[derive(Debug)]
pub struct NetworkStack {
    next_id: u64,
    wsa_refcount: u32,
    last_wsa_error: i32,
    sockets: BTreeMap<SocketId, SocketRecord>,
    real_tcp_streams: BTreeMap<SocketId, TcpStream>,
    listeners: BTreeMap<SockAddr, SocketId>,
    pending_accept: BTreeMap<SocketId, VecDeque<SocketId>>,
    dns_records: BTreeMap<String, Vec<AddressFamilyRecord>>,
    http_sessions: BTreeMap<HttpSessionId, HttpSessionRecord>,
    http_connections: BTreeMap<HttpConnectionId, HttpConnectionRecord>,
    http_requests: BTreeMap<HttpRequestId, HttpRequestRecord>,
    routes: BTreeMap<(String, String, String), HttpResponseTemplate>,
    cookie_jar: Vec<Cookie>,
    proxy_settings: ProxySettings,
    trust_store: BTreeMap<String, Certificate>,
    keychain_mapping_enabled: bool,
    current_day: i64,
    http_traces: Vec<HttpTrace>,
    cipher_log: Vec<String>,
    /// QUIC protocol configuration (HTTP/3 detection + fallback)
    pub quic_config: QuicConfig,
    /// Track Alt-Svc entries discovered from response headers (host -> entries)
    pub alt_svc_entries: BTreeMap<String, Vec<AltSvcEntry>>,
    /// The negotiated HTTP protocol per connection (connection_id -> protocol)
    pub connection_protocols: BTreeMap<HttpConnectionId, HttpProtocol>,
    /// The enabled HTTP protocol flags per session (session_id -> flags)
    pub session_protocol_flags: BTreeMap<HttpSessionId, HttpProtocolFlags>,
}

impl Default for NetworkStack {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple HTTP GET response for content server communication.
#[derive(Debug, Clone)]
pub struct SimpleHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl NetworkStack {
    /// Perform a simple HTTP GET request to a content server.
    ///
    /// This uses a real TCP connection and sends an HTTP/1.1 GET request,
    /// returning the parsed response. Used by the content manager to fetch
    /// CDN server lists, depot manifests, and chunks from Steam content servers.
    pub fn http_get(&mut self, url_str: &str) -> AppResult<SimpleHttpResponse> {
        let url = url::Url::parse(url_str).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetDnsResolutionFailed,
                format!("NetworkStack: invalid URL: {e}"),
            )
        })?;

        let host = url.host_str().ok_or_else(|| {
            AppError::new(ReasonCode::RcNetDnsResolutionFailed, "NetworkStack: no host in URL")
        })?;

        let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = url.path();
        let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
        let request_path = format!("{path}{query}");

        let addr_str = format!("{host}:{port}");
        let addr = addr_str.to_socket_addrs().map_err(|e| {
            AppError::new(
                ReasonCode::RcNetDnsResolutionFailed,
                format!("NetworkStack: DNS resolution for {host} failed: {e}"),
            )
        })?
        .next()
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNetDnsResolutionFailed,
                format!("NetworkStack: no address for {host}"),
            )
        })?;

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(15)).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("NetworkStack: connect to {host} failed: {e}"),
            )
        })?;

        // For HTTPS, we'd need TLS. For Steam content servers, both HTTP and HTTPS are used.
        // If HTTPS, use native-tls for a TLS connection.
        let use_tls = url.scheme() == "https";

        if use_tls {
            #[cfg(feature = "native-tls")]
            {
                let connector = native_tls::TlsConnector::new().map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetConnectionFailed,
                        format!("NetworkStack: TLS connector creation failed: {e}"),
                    )
                })?;
                let mut tls_stream = connector.connect(host, stream).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetConnectionFailed,
                        format!("NetworkStack: TLS handshake with {host} failed: {e}"),
                    )
                })?;

                let request = format!(
                    "GET {request_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Casa1/0.1.0\r\nAccept: */*\r\n\r\n"
                );
                tls_stream.write_all(request.as_bytes()).map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetWriteFailed,
                        format!("NetworkStack: HTTP GET (TLS) failed: {e}"),
                    )
                })?;

                let mut response = Vec::new();
                let mut buf = [0u8; 16384];
                loop {
                    match tls_stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => response.extend_from_slice(&buf[..n]),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            return Err(AppError::new(
                                ReasonCode::RcNetReadFailed,
                                format!("NetworkStack: TLS read failed: {e}"),
                            ));
                        }
                    }
                }
                return parse_http_response(&response);
            }

            #[cfg(not(feature = "native-tls"))]
            {
                let _ = stream;
                return Err(AppError::new(
                    ReasonCode::RcNetConnectionFailed,
                    "NetworkStack: HTTPS not supported without native-tls feature",
                ));
            }
        }

        // Plain HTTP
        let mut tcp_stream = stream;
        let request = format!(
            "GET {request_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Casa1/0.1.0\r\nAccept: */*\r\n\r\n"
        );
        tcp_stream.write_all(request.as_bytes()).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetWriteFailed,
                format!("NetworkStack: HTTP GET failed: {e}"),
            )
        })?;

        let mut response = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            match tcp_stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(AppError::new(
                        ReasonCode::RcNetReadFailed,
                        format!("NetworkStack: HTTP read failed: {e}"),
                    ));
                }
            }
        }
        parse_http_response(&response)
    }
}

/// Parse an HTTP response into a SimpleHttpResponse.
fn parse_http_response(raw: &[u8]) -> AppResult<SimpleHttpResponse> {
    let response_str = String::from_utf8_lossy(raw);

    // Parse status line: HTTP/1.1 200 OK
    let status = if let Some(end_of_line) = response_str.find("\r\n") {
        let status_line = &response_str[..end_of_line];
        let parts: Vec<&str> = status_line.split(' ').collect();
        if parts.len() >= 2 {
            parts[1].parse::<u16>().unwrap_or(0)
        } else {
            0
        }
    } else {
        0
    };

    // Find headers and body separator
    let mut headers = BTreeMap::new();
    let body_start;

    if let Some(header_end) = response_str.find("\r\n\r\n") {
        let header_section = &response_str[..header_end];
        // Skip the status line, parse headers
        for line in header_section.lines().skip(1) {
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim().to_string();
                let value = line[colon + 1..].trim().to_string();
                headers.insert(key.to_lowercase(), value);
            }
        }
        body_start = header_end + 4;
    } else {
        body_start = response_str.len();
    };

    let body = raw[body_start..].to_vec();

    Ok(SimpleHttpResponse {
        status,
        headers,
        body,
    })
}

impl Clone for NetworkStack {
    fn clone(&self) -> Self {
        let real_tcp_streams = self
            .real_tcp_streams
            .iter()
            .map(|(socket, stream)| {
                (
                    *socket,
                    stream
                        .try_clone()
                        .expect("failed to clone host TCP stream for NetworkStack"),
                )
            })
            .collect();
        Self {
            next_id: self.next_id,
            wsa_refcount: self.wsa_refcount,
            last_wsa_error: self.last_wsa_error,
            sockets: self.sockets.clone(),
            real_tcp_streams,
            listeners: self.listeners.clone(),
            pending_accept: self.pending_accept.clone(),
            dns_records: self.dns_records.clone(),
            http_sessions: self.http_sessions.clone(),
            http_connections: self.http_connections.clone(),
            http_requests: self.http_requests.clone(),
            routes: self.routes.clone(),
            cookie_jar: self.cookie_jar.clone(),
            proxy_settings: self.proxy_settings.clone(),
            trust_store: self.trust_store.clone(),
            keychain_mapping_enabled: self.keychain_mapping_enabled,
            current_day: self.current_day,
            http_traces: self.http_traces.clone(),
            cipher_log: self.cipher_log.clone(),
            quic_config: self.quic_config.clone(),
            alt_svc_entries: self.alt_svc_entries.clone(),
            connection_protocols: self.connection_protocols.clone(),
            session_protocol_flags: self.session_protocol_flags.clone(),
        }
    }
}

impl NetworkStack {
    pub fn new() -> Self {
        let mut routes = BTreeMap::new();
        let root = Certificate {
            subject: "CN=TestRoot".to_string(),
            issuer: "CN=TestRoot".to_string(),
            fingerprint: "fp:test-root".to_string(),
            valid_hostnames: vec![],
            not_after_day: 99999,
            revoked: false,
            supported_ciphers: vec![],
        };
        let api_cert = Certificate {
            subject: "CN=api.example.com".to_string(),
            issuer: "CN=TestRoot".to_string(),
            fingerprint: "fp:api.example.com".to_string(),
            valid_hostnames: vec!["api.example.com".to_string()],
            not_after_day: 99999,
            revoked: false,
            supported_ciphers: vec!["TLS_AES_128_GCM_SHA256".to_string()],
        };
        let mut trust_store = BTreeMap::new();
        trust_store.insert(root.fingerprint.clone(), root);
        routes.insert(
            ("https".to_string(), "api.example.com".to_string(), "/login".to_string()),
            HttpResponseTemplate {
                status: 200,
                headers: BTreeMap::from([("x-casa1-route".to_string(), "login".to_string())]),
                body: br#"{"ok":true}"#.to_vec(),
                cookies: vec![Cookie {
                    name: "session".to_string(),
                    value: "abc123".to_string(),
                    domain: ".example.com".to_string(),
                    path: "/store".to_string(),
                    secure: true,
                }],
                certificate_chain: vec![api_cert.clone(), Certificate {
                    subject: "CN=TestRoot".to_string(),
                    issuer: "CN=TestRoot".to_string(),
                    fingerprint: "fp:test-root".to_string(),
                    valid_hostnames: vec![],
                    not_after_day: 99999,
                    revoked: false,
                    supported_ciphers: vec![],
                }],
            },
        );
        routes.insert(
            ("https".to_string(), "api.example.com".to_string(), "/store/cart".to_string()),
            HttpResponseTemplate {
                status: 200,
                headers: BTreeMap::from([("x-casa1-route".to_string(), "cart".to_string())]),
                body: b"cart".to_vec(),
                cookies: Vec::new(),
                certificate_chain: vec![api_cert, Certificate {
                    subject: "CN=TestRoot".to_string(),
                    issuer: "CN=TestRoot".to_string(),
                    fingerprint: "fp:test-root".to_string(),
                    valid_hostnames: vec![],
                    not_after_day: 99999,
                    revoked: false,
                    supported_ciphers: vec![],
                }],
            },
        );
        routes.insert(
            ("http".to_string(), "launcher.example.com".to_string(), "/patch".to_string()),
            HttpResponseTemplate {
                status: 204,
                headers: BTreeMap::from([("x-casa1-route".to_string(), "patch".to_string())]),
                body: Vec::new(),
                cookies: Vec::new(),
                certificate_chain: Vec::new(),
            },
        );
        Self {
            next_id: 0x1000,
            wsa_refcount: 0,
            last_wsa_error: 0,
            sockets: BTreeMap::new(),
            real_tcp_streams: BTreeMap::new(),
            listeners: BTreeMap::new(),
            pending_accept: BTreeMap::new(),
            dns_records: BTreeMap::from([
                (
                    "example.com".to_string(),
                    vec![
                        AddressFamilyRecord {
                            family: AddressFamily::Ipv4,
                            host: "93.184.216.34".to_string(),
                        },
                        AddressFamilyRecord {
                            family: AddressFamily::Ipv6,
                            host: "2606:2800:220:1:248:1893:25c8:1946".to_string(),
                        },
                    ],
                ),
                (
                    "api.example.com".to_string(),
                    vec![AddressFamilyRecord {
                        family: AddressFamily::Ipv4,
                        host: "203.0.113.10".to_string(),
                    }],
                ),
                (
                    "launcher.example.com".to_string(),
                    vec![AddressFamilyRecord {
                        family: AddressFamily::Ipv4,
                        host: "203.0.113.20".to_string(),
                    }],
                ),
            ]),
            http_sessions: BTreeMap::new(),
            http_connections: BTreeMap::new(),
            http_requests: BTreeMap::new(),
            routes,
            cookie_jar: Vec::new(),
            proxy_settings: ProxySettings::default(),
            trust_store,
            keychain_mapping_enabled: false,
            current_day: 0,
            http_traces: Vec::new(),
            cipher_log: Vec::new(),
            quic_config: QuicConfig::default(),
            alt_svc_entries: BTreeMap::new(),
            connection_protocols: BTreeMap::new(),
            session_protocol_flags: BTreeMap::new(),
        }
    }

    pub fn set_current_day(&mut self, day: i64) {
        self.current_day = day;
    }

    pub fn keychain_mapping_enabled(&self) -> bool {
        self.keychain_mapping_enabled
    }

    pub fn http_traces(&self) -> &[HttpTrace] {
        &self.http_traces
    }

    pub fn cipher_log(&self) -> &[String] {
        &self.cipher_log
    }

    pub fn add_route(
        &mut self,
        scheme: &str,
        host: &str,
        path: &str,
        status: u16,
        headers: BTreeMap<String, String>,
        body: &[u8],
        cookies: Vec<Cookie>,
        certificate_chain: Vec<Certificate>,
    ) {
        self.routes.insert(
            (scheme.to_string(), host.to_string(), path.to_string()),
            HttpResponseTemplate {
                status,
                headers,
                body: body.to_vec(),
                cookies,
                certificate_chain,
            },
        );
    }

    pub fn import_certificate(&mut self, certificate: Certificate) {
        self.trust_store
            .insert(certificate.fingerprint.clone(), certificate);
    }

    pub fn export_certificates(&self) -> Vec<Certificate> {
        self.trust_store.values().cloned().collect()
    }

    pub fn set_env_proxy(&mut self, proxy: Option<String>) {
        self.proxy_settings.env_proxy = proxy;
    }

    pub fn set_system_proxy(&mut self, proxy: Option<String>, enabled: bool) {
        self.proxy_settings.system_proxy = proxy;
        self.proxy_settings.map_system_proxy = enabled;
    }

    pub fn cookie_snapshot_json(&self) -> AppResult<String> {
        serde_json::to_string(&self.cookie_jar).map_err(|error| {
            AppError::new(ReasonCode::RcIo, "failed to encode cookie snapshot")
                .with_hint(error.to_string())
        })
    }

    pub fn load_cookie_snapshot_json(&mut self, snapshot: &str) -> AppResult<()> {
        self.cookie_jar = serde_json::from_str(snapshot).map_err(|error| {
            AppError::new(ReasonCode::RcIo, "failed to decode cookie snapshot")
                .with_hint(error.to_string())
        })?;
        Ok(())
    }

    pub fn wsa_startup(&mut self) {
        self.wsa_refcount += 1;
        self.last_wsa_error = 0;
    }

    pub fn wsa_cleanup(&mut self) {
        self.wsa_refcount = self.wsa_refcount.saturating_sub(1);
        self.last_wsa_error = 0;
    }

    pub fn socket(&mut self, family: AddressFamily) -> AppResult<SocketId> {
        self.ensure_wsa_started()?;
        let id = self.alloc_id();
        self.sockets.insert(
            id,
            SocketRecord {
                family,
                nonblocking: false,
                bound_addr: None,
                state: SocketState::Created,
                recv_queue: VecDeque::new(),
            },
        );
        self.last_wsa_error = 0;
        Ok(id)
    }

    pub fn bind(&mut self, socket: SocketId, addr: SockAddr) -> AppResult<()> {
        self.ensure_wsa_started()?;
        if self.listeners.contains_key(&addr)
            || self
                .sockets
                .values()
                .any(|record| matches!(&record.state, SocketState::Bound(existing) if existing == &addr))
        {
            self.last_wsa_error = WSAEADDRINUSE;
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("address already in use: {}:{}", addr.host, addr.port),
            ));
        }
        let record = self.socket_record_mut(socket)?;
        record.bound_addr = Some(addr.clone());
        record.state = SocketState::Bound(addr);
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn listen(&mut self, socket: SocketId, backlog: usize) -> AppResult<()> {
        self.ensure_wsa_started()?;
        let addr = match &self.socket_record(socket)?.state {
            SocketState::Bound(addr) => addr.clone(),
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    "listen requires a bound socket",
                ));
            }
        };
        self.socket_record_mut(socket)?.state = SocketState::Listening {
            _addr: addr.clone(),
            _backlog: backlog,
        };
        self.listeners.insert(addr, socket);
        self.pending_accept.entry(socket).or_default();
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn accept(&mut self, socket: SocketId) -> AppResult<SocketId> {
        self.ensure_wsa_started()?;
        let nonblocking = self.socket_record(socket)?.nonblocking;
        let queue = self.pending_accept.entry(socket).or_default();
        match queue.pop_front() {
            Some(client_socket) => {
                self.last_wsa_error = 0;
                Ok(client_socket)
            }
            None if nonblocking => {
                self.last_wsa_error = WSAEWOULDBLOCK;
                Err(AppError::new(
                    ReasonCode::RcWinsockWouldBlock,
                    "non-blocking accept would block",
                ))
            }
            None => {
                self.last_wsa_error = 0;
                Err(AppError::new(
                    ReasonCode::RcIo,
                    "no pending connections",
                ))
            }
        }
    }

    pub fn connect(&mut self, socket: SocketId, addr: SockAddr) -> AppResult<()> {
        self.ensure_wsa_started()?;
        if let Some(listener) = self.listeners.get(&addr).copied() {
            let server_socket = self.alloc_id();
            let family = self.socket_record(socket)?.family;
            self.sockets.insert(
                server_socket,
                SocketRecord {
                    family,
                    nonblocking: false,
                    bound_addr: Some(addr.clone()),
                    state: SocketState::Connected { peer: socket },
                    recv_queue: VecDeque::new(),
                },
            );
            let record = self.socket_record_mut(socket)?;
            if record.bound_addr.is_none() {
                record.bound_addr = Some(default_sockaddr(family));
            }
            record.state = SocketState::Connected { peer: server_socket };
            self.pending_accept
                .entry(listener)
                .or_default()
                .push_back(server_socket);
            self.last_wsa_error = 0;
            return Ok(());
        }

        let (family, nonblocking) = {
            let record = self.socket_record(socket)?;
            (record.family, record.nonblocking)
        };
        let mut addrs = (addr.host.as_str(), addr.port).to_socket_addrs().map_err(|error| {
            self.last_wsa_error = WSAHOST_NOT_FOUND;
            AppError::new(
                ReasonCode::RcDnsNotFound,
                format!("DNS lookup failed for {}:{}: {error}", addr.host, addr.port),
            )
        })?;
        let candidate = addrs
            .find(|candidate| socket_addr_matches_family(candidate, family))
            .ok_or_else(|| {
                self.last_wsa_error = WSAECONNREFUSED;
                AppError::new(
                    ReasonCode::RcIo,
                    format!("no {family:?} address available for {}:{}", addr.host, addr.port),
                )
            })?;
        let stream = TcpStream::connect(candidate).map_err(|error| {
            self.last_wsa_error = map_wsa_error(&error);
            AppError::new(
                ReasonCode::RcIo,
                format!("TCP connect to {}:{} failed: {error}", addr.host, addr.port),
            )
        })?;
        stream.set_nonblocking(nonblocking).map_err(|error| {
            self.last_wsa_error = map_wsa_error(&error);
            AppError::new(
                ReasonCode::RcIo,
                format!("failed to set nonblocking mode on {}:{}: {error}", addr.host, addr.port),
            )
        })?;
        let local_addr = stream.local_addr().ok().map(sockaddr_from_std);
        self.real_tcp_streams.insert(socket, stream);

        let record = self.socket_record_mut(socket)?;
        if record.bound_addr.is_none() {
            record.bound_addr = local_addr.or_else(|| Some(default_sockaddr(family)));
        }
        record.state = SocketState::ConnectedReal { _peer: addr };
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn getsockname(&mut self, socket: SocketId) -> AppResult<SockAddr> {
        self.ensure_wsa_started()?;
        let record = self.socket_record(socket)?;
        let addr = record
            .bound_addr
            .clone()
            .unwrap_or_else(|| default_sockaddr(record.family));
        self.last_wsa_error = 0;
        Ok(addr)
    }

    pub fn send(&mut self, socket: SocketId, bytes: &[u8]) -> AppResult<usize> {
        self.ensure_wsa_started()?;
        if let Some(stream) = self.real_tcp_streams.get_mut(&socket) {
            let written = stream.write(bytes).map_err(|error| {
                self.last_wsa_error = map_wsa_error(&error);
                AppError::new(ReasonCode::RcIo, format!("TCP send failed on socket {socket}: {error}"))
            })?;
            self.last_wsa_error = 0;
            return Ok(written);
        }
        let peer = match self.socket_record(socket)?.state {
            SocketState::Connected { peer } => peer,
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    "send requires a connected socket",
                ));
            }
        };
        self.socket_record_mut(peer)?
            .recv_queue
            .extend(bytes.iter().copied());
        self.last_wsa_error = 0;
        Ok(bytes.len())
    }

    pub fn recv(&mut self, socket: SocketId, length: usize) -> AppResult<Vec<u8>> {
        self.ensure_wsa_started()?;
        if let Some(stream) = self.real_tcp_streams.get_mut(&socket) {
            let mut bytes = vec![0; length.max(1)];
            let read = stream.read(&mut bytes).map_err(|error| {
                self.last_wsa_error = map_wsa_error(&error);
                AppError::new(ReasonCode::RcIo, format!("TCP recv failed on socket {socket}: {error}"))
            })?;
            bytes.truncate(read);
            self.last_wsa_error = 0;
            return Ok(bytes);
        }
        let nonblocking = self.socket_record(socket)?.nonblocking;
        if self.socket_record(socket)?.recv_queue.is_empty() {
            if nonblocking {
                self.last_wsa_error = WSAEWOULDBLOCK;
                return Err(AppError::new(
                    ReasonCode::RcWinsockWouldBlock,
                    "non-blocking recv would block",
                ));
            }
            self.last_wsa_error = 0;
            return Ok(Vec::new());
        }
        let record = self.socket_record_mut(socket)?;
        let count = length.min(record.recv_queue.len());
        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            bytes.push(record.recv_queue.pop_front().expect("recv queue entry"));
        }
        self.last_wsa_error = 0;
        Ok(bytes)
    }

    pub fn setsockopt(&mut self, socket: SocketId, _level: i32, _option_name: i32, _value: &[u8]) -> AppResult<()> {
        self.ensure_wsa_started()?;
        let _ = self.socket_record(socket)?;
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn shutdown(&mut self, socket: SocketId) -> AppResult<()> {
        self.ensure_wsa_started()?;
        if let Some(stream) = self.real_tcp_streams.get(&socket) {
            stream.shutdown(NetShutdown::Both).map_err(|error| {
                self.last_wsa_error = map_wsa_error(&error);
                AppError::new(ReasonCode::RcIo, format!("shutdown failed on socket {socket}: {error}"))
            })?;
        }
        self.socket_record_mut(socket)?.state = SocketState::Shutdown;
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn closesocket(&mut self, socket: SocketId) -> AppResult<()> {
        self.ensure_wsa_started()?;
        if let Some(stream) = self.real_tcp_streams.remove(&socket) {
            let _ = stream.shutdown(NetShutdown::Both);
        }
        self.socket_record_mut(socket)?.state = SocketState::Closed;
        self.sockets.remove(&socket);
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn ioctlsocket_fionbio(&mut self, socket: SocketId, nonblocking: bool) -> AppResult<()> {
        self.ensure_wsa_started()?;
        self.socket_record_mut(socket)?.nonblocking = nonblocking;
        if let Some(stream) = self.real_tcp_streams.get_mut(&socket) {
            stream.set_nonblocking(nonblocking).map_err(|error| {
                self.last_wsa_error = map_wsa_error(&error);
                AppError::new(
                    ReasonCode::RcIo,
                    format!("failed to set nonblocking mode on socket {socket}: {error}"),
                )
            })?;
        }
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn ioctlsocket_fionread(&mut self, socket: SocketId) -> AppResult<u32> {
        self.ensure_wsa_started()?;
        if let Some(stream) = self.real_tcp_streams.get(&socket) {
            let available = bytes_available(stream)?;
            self.last_wsa_error = 0;
            return Ok(available);
        }
        let available = self.socket_record(socket)?.recv_queue.len().min(u32::MAX as usize) as u32;
        self.last_wsa_error = 0;
        Ok(available)
    }

    pub fn select(&self, sockets: &[SocketId]) -> AppResult<(Vec<SocketId>, Vec<SocketId>)> {
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        for socket in sockets {
            let record = self.socket_record(*socket)?;
            let can_read = if let Some(stream) = self.real_tcp_streams.get(socket) {
                bytes_available(stream)? > 0
            } else {
                !record.recv_queue.is_empty()
                    || self
                        .pending_accept
                        .get(socket)
                        .is_some_and(|pending| !pending.is_empty())
            };
            let can_write = matches!(
                record.state,
                SocketState::Connected { .. }
                    | SocketState::ConnectedReal { .. }
                    | SocketState::Listening { .. }
            );
            if can_read {
                readable.push(*socket);
            }
            if can_write {
                writable.push(*socket);
            }
        }
        Ok((readable, writable))
    }

    pub fn wsa_poll(&self, sockets: &[SocketId]) -> AppResult<Vec<PollState>> {
        let (readable, writable) = self.select(sockets)?;
        Ok(sockets
            .iter()
            .map(|socket| PollState {
                socket: *socket,
                readable: readable.contains(socket),
                writable: writable.contains(socket),
            })
            .collect())
    }

    pub fn getaddrinfo(&mut self, host: &str, port: u16) -> AppResult<Vec<ResolvedAddr>> {
        self.ensure_wsa_started()?;
        if let Some(records) = self.dns_records.get(host) {
            self.last_wsa_error = 0;
            return Ok(records
                .iter()
                .map(|record| ResolvedAddr {
                    family: record.family,
                    host: record.host.clone(),
                    port,
                })
                .collect());
        }

        let addrs = (host, port).to_socket_addrs().map_err(|error| {
            self.last_wsa_error = WSAHOST_NOT_FOUND;
            AppError::new(
                ReasonCode::RcDnsNotFound,
                format!("DNS lookup failed for {host}: {error}"),
            )
        })?;
        let resolved = addrs
            .map(|addr| ResolvedAddr {
                family: if addr.is_ipv6() {
                    AddressFamily::Ipv6
                } else {
                    AddressFamily::Ipv4
                },
                host: addr.ip().to_string(),
                port: addr.port(),
            })
            .collect::<Vec<_>>();
        if resolved.is_empty() {
            self.last_wsa_error = WSAHOST_NOT_FOUND;
            return Err(AppError::new(
                ReasonCode::RcDnsNotFound,
                format!("DNS lookup returned no addresses for {host}"),
            ));
        }
        self.last_wsa_error = 0;
        Ok(resolved)
    }

    pub fn freeaddrinfo(&mut self) {
        self.last_wsa_error = 0;
    }

    pub fn wsa_get_last_error(&self) -> i32 {
        self.last_wsa_error
    }

    pub fn wsa_set_last_error(&mut self, error: i32) {
        self.last_wsa_error = error;
    }

    pub fn win_http_open(&mut self, _user_agent: &str) -> HttpSessionId {
        self.open_session("winhttp")
    }

    pub fn internet_open(&mut self, _user_agent: &str) -> HttpSessionId {
        self.open_session("wininet")
    }

    pub fn win_http_set_proxy(&mut self, session: HttpSessionId, proxy: Option<String>) -> AppResult<()> {
        self.http_session_mut(session)?.proxy_override = proxy;
        Ok(())
    }

    pub fn win_http_connect(
        &mut self,
        session: HttpSessionId,
        host: &str,
        port: u16,
        secure: bool,
    ) -> AppResult<HttpConnectionId> {
        self.open_connection(session, host, port, secure)
    }

    pub fn internet_connect(
        &mut self,
        session: HttpSessionId,
        host: &str,
        port: u16,
        secure: bool,
    ) -> AppResult<HttpConnectionId> {
        self.open_connection(session, host, port, secure)
    }

    pub fn win_http_open_request(
        &mut self,
        connection: HttpConnectionId,
        method: &str,
        path: &str,
    ) -> AppResult<HttpRequestId> {
        self.open_request(connection, method, path)
    }

    pub fn http_open_request(
        &mut self,
        connection: HttpConnectionId,
        method: &str,
        path: &str,
    ) -> AppResult<HttpRequestId> {
        self.open_request(connection, method, path)
    }

    pub fn win_http_send_request(
        &mut self,
        request: HttpRequestId,
        headers: BTreeMap<String, String>,
        body: &[u8],
    ) -> AppResult<()> {
        self.send_request(request, headers, body)
    }

    pub fn http_send_request(
        &mut self,
        request: HttpRequestId,
        headers: BTreeMap<String, String>,
        body: &[u8],
    ) -> AppResult<()> {
        self.send_request(request, headers, body)
    }

    pub fn win_http_receive_response(&mut self, request: HttpRequestId) -> AppResult<()> {
        self.http_request(request)?;
        Ok(())
    }

    pub fn win_http_query_headers(&self, request: HttpRequestId) -> AppResult<BTreeMap<String, String>> {
        let response = self
            .http_request(request)?
            .response
            .as_ref()
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, "request has no response"))?;
        let mut headers = response.headers.clone();
        headers.insert("status".to_string(), response.status.to_string());
        Ok(headers)
    }

    pub fn win_http_read_data(&mut self, request: HttpRequestId, count: usize) -> AppResult<Vec<u8>> {
        self.read_body(request, count)
    }

    pub fn internet_read_file(&mut self, request: HttpRequestId, count: usize) -> AppResult<Vec<u8>> {
        self.read_body(request, count)
    }

    pub fn close_handle(&mut self, handle: u64) {
        self.http_requests.remove(&handle);
        self.http_connections.remove(&handle);
        self.http_sessions.remove(&handle);
    }

    pub fn validate_server_certificate(
        &self,
        host: &str,
        chain: &[Certificate],
        revocation_check: bool,
    ) -> AppResult<String> {
        let leaf = chain.first().ok_or_else(|| {
            AppError::new(ReasonCode::RcTlsCertRejected, "TLS chain is empty")
        })?;
        if !leaf.valid_hostnames.iter().any(|candidate| candidate == host) {
            return Err(AppError::new(
                ReasonCode::RcTlsCertRejected,
                format!("certificate hostname mismatch for {host}"),
            ));
        }
        if self.current_day > leaf.not_after_day {
            return Err(AppError::new(
                ReasonCode::RcTlsCertRejected,
                format!("certificate for {host} is expired"),
            ));
        }
        if revocation_check && leaf.revoked {
            return Err(AppError::new(
                ReasonCode::RcTlsCertRejected,
                format!("certificate for {host} is revoked"),
            ));
        }
        let root = chain.last().ok_or_else(|| {
            AppError::new(ReasonCode::RcTlsCertRejected, "TLS chain is empty")
        })?;
        if !self.trust_store.contains_key(&root.fingerprint) {
            return Err(AppError::new(
                ReasonCode::RcTlsCertRejected,
                format!("untrusted root {}", root.subject),
            ));
        }
        let client_supported = [
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
        ];
        client_supported
            .iter()
            .find(|suite| leaf.supported_ciphers.iter().any(|candidate| candidate == **suite))
            .map(|suite| (*suite).to_string())
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcTlsCertRejected,
                    format!("no mutually supported cipher for {host}"),
                )
            })
    }

    fn open_session(&mut self, stack: &str) -> HttpSessionId {
        let id = self.alloc_id();
        self.http_sessions.insert(
            id,
            HttpSessionRecord {
                stack: stack.to_string(),
                proxy_override: None,
            },
        );
        id
    }

    fn open_connection(
        &mut self,
        session: HttpSessionId,
        host: &str,
        port: u16,
        secure: bool,
    ) -> AppResult<HttpConnectionId> {
        self.http_session(session)?;
        let id = self.alloc_id();
        self.http_connections.insert(
            id,
            HttpConnectionRecord {
                session,
                host: host.to_string(),
                _port: port,
                secure,
            },
        );
        Ok(id)
    }

    fn open_request(
        &mut self,
        connection: HttpConnectionId,
        method: &str,
        path: &str,
    ) -> AppResult<HttpRequestId> {
        self.http_connection(connection)?;
        let id = self.alloc_id();
        self.http_requests.insert(
            id,
            HttpRequestRecord {
                connection,
                _method: method.to_string(),
                path: path.to_string(),
                response: None,
                read_offset: 0,
            },
        );
        Ok(id)
    }

    fn send_request(
        &mut self,
        request: HttpRequestId,
        _headers: BTreeMap<String, String>,
        _body: &[u8],
    ) -> AppResult<()> {
        let (path, stack, host, secure, proxy_override) = {
            let request_record = self.http_request(request)?;
            let connection = self.http_connection(request_record.connection)?;
            let session = self.http_session(connection.session)?;
            (
                request_record.path.clone(),
                session.stack.clone(),
                connection.host.clone(),
                connection.secure,
                session.proxy_override.clone(),
            )
        };
        let scheme = if secure { "https" } else { "http" };
        let template = self
            .routes
            .get(&(scheme.to_string(), host.clone(), path.clone()))
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, format!("no route for {scheme}://{host}{path}")))?
            .clone();
        let proxy = proxy_override
            .or_else(|| self.proxy_settings.env_proxy.clone())
            .or_else(|| {
                self.proxy_settings
                    .map_system_proxy
                    .then(|| self.proxy_settings.system_proxy.clone())
                    .flatten()
            });
        let cookie_header = self.cookie_header_for_request(&host, &path, secure);
        let cipher_suite = if secure {
            let suite = self.validate_server_certificate(&host, &template.certificate_chain, true)?;
            self.cipher_log.push(format!("{host}:{suite}"));
            Some(suite)
        } else {
            None
        };
        for cookie in template.cookies {
            self.store_cookie(cookie);
        }
        self.http_request_mut(request)?.response = Some(HttpResponseRecord {
            status: template.status,
            headers: template.headers.clone(),
            body: template.body.clone(),
        });
        self.http_traces.push(HttpTrace {
            stack,
            host,
            path,
            proxy,
            cookie_header,
            cipher_suite,
            status: template.status,
        });
        Ok(())
    }

    fn read_body(&mut self, request: HttpRequestId, count: usize) -> AppResult<Vec<u8>> {
        let (body, read_offset) = {
            let record = self.http_request(request)?;
            let response = record
                .response
                .as_ref()
                .ok_or_else(|| AppError::new(ReasonCode::RcIo, "request has no response"))?;
            (response.body.clone(), record.read_offset)
        };
        let end = (read_offset + count).min(body.len());
        self.http_request_mut(request)?.read_offset = end;
        Ok(body[read_offset..end].to_vec())
    }

    fn store_cookie(&mut self, cookie: Cookie) {
        self.cookie_jar.retain(|existing| {
            !(existing.name == cookie.name
                && existing.domain == cookie.domain
                && existing.path == cookie.path)
        });
        self.cookie_jar.push(cookie);
    }

    fn cookie_header_for_request(&self, host: &str, path: &str, secure: bool) -> String {
        self.cookie_jar
            .iter()
            .filter(|cookie| cookie_matches(cookie, host, path, secure))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn ensure_wsa_started(&mut self) -> AppResult<()> {
        if self.wsa_refcount == 0 {
            self.last_wsa_error = WSANOTINITIALISED;
            return Err(AppError::new(
                ReasonCode::RcIo,
                "Winsock has not been started",
            ));
        }
        Ok(())
    }

    fn socket_record(&self, socket: SocketId) -> AppResult<&SocketRecord> {
        self.sockets.get(&socket).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown socket {socket}"))
        })
    }

    fn socket_record_mut(&mut self, socket: SocketId) -> AppResult<&mut SocketRecord> {
        self.sockets.get_mut(&socket).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown socket {socket}"))
        })
    }

    fn http_session(&self, session: HttpSessionId) -> AppResult<&HttpSessionRecord> {
        self.http_sessions.get(&session).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown HTTP session {session}"))
        })
    }

    fn http_session_mut(&mut self, session: HttpSessionId) -> AppResult<&mut HttpSessionRecord> {
        self.http_sessions.get_mut(&session).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown HTTP session {session}"))
        })
    }

    fn http_connection(&self, connection: HttpConnectionId) -> AppResult<&HttpConnectionRecord> {
        self.http_connections.get(&connection).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown HTTP connection {connection}"))
        })
    }

    fn http_request(&self, request: HttpRequestId) -> AppResult<&HttpRequestRecord> {
        self.http_requests.get(&request).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown HTTP request {request}"))
        })
    }

    fn http_request_mut(&mut self, request: HttpRequestId) -> AppResult<&mut HttpRequestRecord> {
        self.http_requests.get_mut(&request).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown HTTP request {request}"))
        })
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 4;
        id
    }
}

fn default_sockaddr(family: AddressFamily) -> SockAddr {
    match family {
        AddressFamily::Ipv4 => SockAddr {
            family,
            host: "0.0.0.0".to_string(),
            port: 0,
        },
        AddressFamily::Ipv6 => SockAddr {
            family,
            host: "::".to_string(),
            port: 0,
        },
    }
}

fn socket_addr_matches_family(addr: &NetSocketAddr, family: AddressFamily) -> bool {
    matches!((addr, family), (NetSocketAddr::V4(_), AddressFamily::Ipv4) | (NetSocketAddr::V6(_), AddressFamily::Ipv6))
}

fn sockaddr_from_std(addr: NetSocketAddr) -> SockAddr {
    SockAddr {
        family: if addr.is_ipv6() {
            AddressFamily::Ipv6
        } else {
            AddressFamily::Ipv4
        },
        host: addr.ip().to_string(),
        port: addr.port(),
    }
}

fn bytes_available(stream: &TcpStream) -> AppResult<u32> {
    let mut available: i32 = 0;
    unsafe {
        let result = libc::ioctl(stream.as_raw_fd(), libc::FIONREAD, &mut available);
        if result < 0 {
            return Err(AppError::new(ReasonCode::RcIo, "FIONREAD ioctl failed"));
        }
    }
    Ok(available.max(0) as u32)
}

fn map_wsa_error(error: &std::io::Error) -> i32 {
    match error.kind() {
        std::io::ErrorKind::WouldBlock => WSAEWOULDBLOCK,
        std::io::ErrorKind::AddrInUse => WSAEADDRINUSE,
        std::io::ErrorKind::ConnectionRefused => WSAECONNREFUSED,
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe => WSAECONNRESET,
        std::io::ErrorKind::NotConnected => WSAENOTCONN,
        std::io::ErrorKind::TimedOut => WSAETIMEDOUT,
        _ => 0,
    }
}

pub fn sha1_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn sha256_hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

pub fn hmac_sha256(key: &[u8], bytes: &[u8]) -> AppResult<Vec<u8>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|error: hmac::digest::InvalidLength| {
        AppError::new(ReasonCode::RcCryptoInvalid, "invalid HMAC key")
            .with_hint(error.to_string())
    })?;
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn aes_128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> AppResult<Vec<u8>> {
    if !plaintext.len().is_multiple_of(16) {
        return Err(AppError::new(
            ReasonCode::RcCryptoInvalid,
            "AES-CBC plaintext must be block aligned",
        ));
    }
    let mut buffer = plaintext.to_vec();
    let result = Encryptor::<Aes128>::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut buffer, plaintext.len())
        .map_err(|error| {
            AppError::new(ReasonCode::RcCryptoInvalid, "AES-CBC encryption failed")
                .with_hint(error.to_string())
        })?;
    Ok(result.to_vec())
}

pub fn aes_128_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> AppResult<Vec<u8>> {
    if !ciphertext.len().is_multiple_of(16) {
        return Err(AppError::new(
            ReasonCode::RcCryptoInvalid,
            "AES-CBC ciphertext must be block aligned",
        ));
    }
    let mut buffer = ciphertext.to_vec();
    let result = Decryptor::<Aes128>::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|error| {
            AppError::new(ReasonCode::RcCryptoInvalid, "AES-CBC decryption failed")
                .with_hint(error.to_string())
        })?;
    Ok(result.to_vec())
}

pub fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> AppResult<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "invalid AES-GCM key")
            .with_hint(error.to_string())
    })?;
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, &mut buffer)
        .map_err(|error| {
            AppError::new(ReasonCode::RcCryptoInvalid, "AES-GCM encryption failed")
                .with_hint(error.to_string())
        })?;
    Ok((buffer, tag.to_vec()))
}

pub fn aes_256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    tag: &[u8],
) -> AppResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "invalid AES-GCM key")
            .with_hint(error.to_string())
    })?;
    let mut buffer = ciphertext.to_vec();
    let tag = Tag::from_slice(tag);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, &mut buffer, tag)
        .map_err(|error| {
            AppError::new(ReasonCode::RcCryptoInvalid, "AES-GCM decryption failed")
                .with_hint(error.to_string())
        })?;
    Ok(buffer)
}

pub fn rsa_pkcs1v15_sign(private_pem: &str, message: &[u8]) -> AppResult<Vec<u8>> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "invalid RSA private key")
            .with_hint(error.to_string())
    })?;
    let signing_key = SigningKey::<Sha256>::new(private_key);
    Ok(signing_key.sign(message).to_vec())
}

pub fn rsa_pkcs1v15_verify(public_pem: &str, message: &[u8], signature: &[u8]) -> AppResult<()> {
    let public_key = RsaPublicKey::from_public_key_pem(public_pem).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "invalid RSA public key")
            .with_hint(error.to_string())
    })?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature = RsaSignature::try_from(signature).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "invalid RSA signature bytes")
            .with_hint(error.to_string())
    })?;
    verifying_key.verify(message, &signature).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "RSA signature verification failed")
            .with_hint(error.to_string())
    })
}

pub fn ecdsa_p256_verify(public_pem: &str, message: &[u8], signature_der: &[u8]) -> AppResult<()> {
    let public_key = EcdsaVerifyingKey::from_public_key_pem(public_pem).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "invalid ECDSA public key")
            .with_hint(error.to_string())
    })?;
    let signature = EcdsaSignature::from_der(signature_der).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "invalid ECDSA signature bytes")
            .with_hint(error.to_string())
    })?;
    public_key.verify(message, &signature).map_err(|error| {
        AppError::new(ReasonCode::RcCryptoInvalid, "ECDSA signature verification failed")
            .with_hint(error.to_string())
    })
}

pub fn secure_random(length: usize) -> Vec<u8> {
    use rand::RngCore;

    let mut bytes = vec![0_u8; length];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    bytes
}

fn cookie_matches(cookie: &Cookie, host: &str, path: &str, secure: bool) -> bool {
    let domain_matches = if let Some(domain) = cookie.domain.strip_prefix('.') {
        host == domain || host.ends_with(&format!(".{domain}"))
    } else {
        host == cookie.domain
    };
    let path_matches = path.starts_with(&cookie.path);
    let secure_matches = !cookie.secure || secure;
    domain_matches && path_matches && secure_matches
}

/// ---------------------------------------------------------------------------
/// QUIC/HTTP3 — Alt-Svc header parser
/// ---------------------------------------------------------------------------
///
/// Parses the `Alt-Svc` HTTP response header into a list of `AltSvcEntry`.
///
/// The Alt-Svc header advertises alternative services (e.g. HTTP/3 over QUIC)
/// that the client can use in future requests. Format:
///
/// ```text
/// Alt-Svc: h3=":443"; ma=2592000, h3-29=":443"; ma=2592000
/// Alt-Svc: h3="example.com:443"; ma=2592000
/// ```
pub fn parse_alt_svc_header(header_value: &str) -> Vec<AltSvcEntry> {
    let mut entries = Vec::new();

    for part in header_value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Each part looks like: h3=":443"; ma=2592000
        // Split by ';' to get protocol=host:port and parameters
        let segments: Vec<&str> = part.split(';').collect();
        if segments.is_empty() {
            continue;
        }

        let proto_segment = segments[0].trim();
        // Parse protocol_id="host:port"
        if let Some(eq_pos) = proto_segment.find('=') {
            let protocol_id = proto_segment[..eq_pos].trim().to_string();
            let host_port_part = proto_segment[eq_pos + 1..].trim();

            // Remove surrounding quotes
            let host_port = host_port_part
                .trim_matches('"')
                .trim_matches('\'');

            if host_port.is_empty() {
                continue;
            }

            // Parse optional host:port, default port based on protocol
            let (alt_host, alt_port) = if let Some(colon_pos) = host_port.rfind(':') {
                let host = host_port[..colon_pos].to_string();
                let port_str = &host_port[colon_pos + 1..];
                let port: u16 = port_str.parse().unwrap_or(443);
                // If host is empty (e.g. ":443"), it means same origin host
                (host, port)
            } else {
                // Just a port number (e.g. "443")
                let port: u16 = host_port.parse().unwrap_or(443);
                (String::new(), port)
            };

            // Extract ALPN from protocol_id (e.g. "h3", "h3-29")
            let alpn = if protocol_id.starts_with("h3") {
                Some(protocol_id.clone())
            } else if protocol_id == "h2" {
                Some("h2".to_string())
            } else {
                None
            };

            entries.push(AltSvcEntry {
                protocol_id,
                alt_host,
                alt_port,
                alpn,
            });
        }
    }

    entries
}

/// Check if an ALPN protocol ID indicates HTTP/3 (QUIC).
pub fn is_quic_alpn(protocol_id: &str) -> bool {
    protocol_id == "h3"
        || protocol_id.starts_with("h3-")
        || protocol_id == "quic"
}

/// Select the best available HTTP protocol based on enabled flags and
/// whether QUIC is supported on this platform.
///
/// Returns the negotiated protocol and whether a fallback occurred.
pub fn negotiate_http_protocol(
    enabled_flags: &HttpProtocolFlags,
    quic_config: &QuicConfig,
    alt_svc_entries: &[AltSvcEntry],
) -> (HttpProtocol, bool) {
    // Check if there's an Alt-Svc entry advertising HTTP/3
    let has_h3_advertisement = alt_svc_entries.iter().any(|e| is_quic_alpn(&e.protocol_id));

    let quic_requested = enabled_flags.contains(HttpProtocolFlags::HTTP3)
        || has_h3_advertisement;

    let mut fallback_occurred = false;

    if quic_requested && !quic_config.force_disabled {
        if quic_config.force_enabled {
            // QUIC is force-enabled but not available on this platform
            // Return HTTP/3 anyway - callers must handle the error
            (HttpProtocol::Http3, false)
        } else {
            // QUIC requested but not available - fall back to HTTP/2
            fallback_occurred = true;
            let has_h2 = enabled_flags.contains(HttpProtocolFlags::HTTP2);
            if has_h2 {
                (HttpProtocol::Http2, true)
            } else {
                (HttpProtocol::Http11, true)
            }
        }
    } else if enabled_flags.contains(HttpProtocolFlags::HTTP2) {
        (HttpProtocol::Http2, false)
    } else {
        (HttpProtocol::Http11, false)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressFamily, AltSvcEntry, Certificate, Cookie, HttpProtocol, HttpProtocolFlags,
        NetworkStack, QuicConfig, SockAddr, is_quic_alpn, negotiate_http_protocol,
        parse_alt_svc_header,
    };
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn winsock_round_trip_preserves_socket_names() {
        let mut network = NetworkStack::new();
        network.wsa_startup();

        let listener = network.socket(AddressFamily::Ipv4).expect("listener socket");
        assert_eq!(listener & 0x3, 0);
        assert!(listener >= 0x1000);
        let listener_addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27015,
        };
        network.bind(listener, listener_addr.clone()).expect("bind listener");
        network.listen(listener, 1).expect("listen");

        let client = network.socket(AddressFamily::Ipv4).expect("client socket");
        assert_eq!(client & 0x3, 0);
        assert!(client >= 0x1000);
        network.connect(client, listener_addr.clone()).expect("connect");
        let server = network.accept(listener).expect("accept");

        assert_eq!(network.getsockname(listener).expect("listener name"), listener_addr);
        assert_eq!(network.getsockname(server).expect("server name"), listener_addr);

        network.send(client, b"ping").expect("send");
        assert_eq!(network.recv(server, 4).expect("recv"), b"ping");

        network.setsockopt(client, 0, 0, &[]).expect("setsockopt");
    }

    #[test]
    fn winsock_getaddrinfo_falls_back_to_host_dns() {
        let mut network = NetworkStack::new();
        network.wsa_startup();

        let addrs = network.getaddrinfo("localhost", 80).expect("resolve localhost");

        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|addr| addr.family == AddressFamily::Ipv4 || addr.family == AddressFamily::Ipv6));
    }

    #[test]
    fn winsock_real_tcp_connect_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind host listener");
        let addr = listener.local_addr().expect("listener addr");
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept host connection");
            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).expect("read ping");
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").expect("write pong");
        });

        let mut network = NetworkStack::new();
        network.wsa_startup();
        let socket = network.socket(AddressFamily::Ipv4).expect("client socket");
        network
            .connect(
                socket,
                SockAddr {
                    family: AddressFamily::Ipv4,
                    host: addr.ip().to_string(),
                    port: addr.port(),
                },
            )
            .expect("connect to host listener");

        network.send(socket, b"ping").expect("send ping");
        assert_eq!(network.recv(socket, 4).expect("recv pong"), b"pong");

        worker.join().expect("join host listener");
    }

    // --- QUIC/HTTP3 tests ---

    #[test]
    fn quic_alt_svc_parses_basic_h3() {
        let header = "h3=\":443\"; ma=2592000";
        let entries = parse_alt_svc_header(header);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol_id, "h3");
        assert_eq!(entries[0].alt_host, "");
        assert_eq!(entries[0].alt_port, 443);
        assert_eq!(entries[0].alpn, Some("h3".to_string()));
    }

    #[test]
    fn quic_alt_svc_parses_multiple_entries() {
        let header = "h3=\":443\"; ma=2592000, h3-29=\":443\"; ma=2592000";
        let entries = parse_alt_svc_header(header);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol_id, "h3");
        assert_eq!(entries[1].protocol_id, "h3-29");
        assert_eq!(entries[1].alpn, Some("h3-29".to_string()));
    }

    #[test]
    fn quic_alt_svc_parses_with_host() {
        let header = "h3=\"alt.example.com:8443\"; ma=2592000";
        let entries = parse_alt_svc_header(header);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol_id, "h3");
        assert_eq!(entries[0].alt_host, "alt.example.com");
        assert_eq!(entries[0].alt_port, 8443);
    }

    #[test]
    fn quic_alt_svc_handles_empty_input() {
        assert!(parse_alt_svc_header("").is_empty());
        assert!(parse_alt_svc_header("   ").is_empty());
    }

    #[test]
    fn quic_is_quic_alpn_detection() {
        assert!(is_quic_alpn("h3"));
        assert!(is_quic_alpn("h3-29"));
        assert!(is_quic_alpn("h3-32"));
        assert!(is_quic_alpn("quic"));
        assert!(!is_quic_alpn("h2"));
        assert!(!is_quic_alpn("http/1.1"));
    }

    #[test]
    fn quic_protocol_flags_defaults() {
        let flags = HttpProtocolFlags::new();
        assert!(!flags.contains(HttpProtocolFlags::HTTP3));
        assert!(!flags.contains(HttpProtocolFlags::HTTP2));
    }

    #[test]
    fn quic_protocol_flags_set_and_check() {
        let mut flags = HttpProtocolFlags::new();
        flags.set(HttpProtocolFlags::HTTP3);
        assert!(flags.contains(HttpProtocolFlags::HTTP3));
        assert!(!flags.contains(HttpProtocolFlags::HTTP2));

        let mut flags2 = HttpProtocolFlags::new();
        flags2.set(HttpProtocolFlags::HTTP2);
        assert!(flags2.contains(HttpProtocolFlags::HTTP2));
        assert!(!flags2.contains(HttpProtocolFlags::HTTP3));
    }

    #[test]
    fn quic_negotiate_falls_back_to_http2_when_quic_unavailable() {
        let mut flags = HttpProtocolFlags::new();
        flags.set(HttpProtocolFlags::HTTP2);
        flags.set(HttpProtocolFlags::HTTP3);

        let config = QuicConfig::default(); // force_disabled: false, force_enabled: false

        let alt_svc_entries = vec![AltSvcEntry {
            protocol_id: "h3".to_string(),
            alt_host: String::new(),
            alt_port: 443,
            alpn: Some("h3".to_string()),
        }];

        let (protocol, fell_back) = negotiate_http_protocol(&flags, &config, &alt_svc_entries);
        assert_eq!(protocol, HttpProtocol::Http2);
        assert!(fell_back);
    }

    #[test]
    fn quic_negotiate_uses_http2_when_only_http2_enabled() {
        let mut flags = HttpProtocolFlags::new();
        flags.set(HttpProtocolFlags::HTTP2);

        let config = QuicConfig::default();
        let alt_svc: Vec<AltSvcEntry> = Vec::new();

        let (protocol, fell_back) = negotiate_http_protocol(&flags, &config, &alt_svc);
        assert_eq!(protocol, HttpProtocol::Http2);
        assert!(!fell_back);
    }

    #[test]
    fn quic_negotiate_uses_http11_when_no_flags_set() {
        let flags = HttpProtocolFlags::new();
        let config = QuicConfig::default();
        let alt_svc: Vec<AltSvcEntry> = Vec::new();

        let (protocol, fell_back) = negotiate_http_protocol(&flags, &config, &alt_svc);
        assert_eq!(protocol, HttpProtocol::Http11);
        assert!(!fell_back);
    }

    #[test]
    fn quic_force_disabled_prevents_quic_usage() {
        let mut flags = HttpProtocolFlags::new();
        flags.set(HttpProtocolFlags::HTTP3);

        let config = QuicConfig {
            force_disabled: true,
            ..Default::default()
        };

        let alt_svc = vec![AltSvcEntry {
            protocol_id: "h3".to_string(),
            alt_host: String::new(),
            alt_port: 443,
            alpn: Some("h3".to_string()),
        }];

        let (protocol, fell_back) = negotiate_http_protocol(&flags, &config, &alt_svc);
        assert_eq!(protocol, HttpProtocol::Http11);
        assert!(!fell_back);
    }

    // --- HTTP route-based request/response lifecycle (WinHTTP) ---

    #[test]
    fn http_route_lifecycle_winhttp_round_trip() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let session = network.win_http_open("test-agent");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open request");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send request");
        network
            .win_http_receive_response(req)
            .expect("receive response");
        let headers = network.win_http_query_headers(req).expect("query headers");
        assert_eq!(headers.get("status").unwrap(), "200");
        assert_eq!(headers.get("x-casa1-route").unwrap(), "login");
        let body = network.win_http_read_data(req, 1024).expect("read data");
        assert_eq!(body, br#"{"ok":true}"#);
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
    }

    #[test]
    fn http_route_matches_http_and_https_schemes() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        // HTTPS → api.example.com /login
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("https connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open req");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        let h = network.win_http_query_headers(req).expect("headers");
        assert_eq!(h.get("x-casa1-route").unwrap(), "login");
        network.close_handle(req);
        network.close_handle(conn);
        // HTTP → launcher.example.com /patch
        let conn2 = network
            .win_http_connect(session, "launcher.example.com", 80, false)
            .expect("http connect");
        let req2 = network
            .win_http_open_request(conn2, "GET", "/patch")
            .expect("open req2");
        network
            .win_http_send_request(req2, BTreeMap::new(), &[])
            .expect("send2");
        let h2 = network.win_http_query_headers(req2).expect("headers2");
        assert_eq!(h2.get("x-casa1-route").unwrap(), "patch");
        assert_eq!(h2.get("status").unwrap(), "204");
        network.close_handle(req2);
        network.close_handle(conn2);
        network.close_handle(session);
    }

    #[test]
    fn http_route_not_found_returns_error() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/nonexistent")
            .expect("open");
        let result = network.win_http_send_request(req, BTreeMap::new(), &[]);
        assert!(result.is_err());
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
    }

    #[test]
    fn http_route_custom_route_added_via_add_route() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_string(), "text/plain".to_string());
        network.add_route(
            "http",
            "custom.test",
            "/hello",
            200,
            headers,
            b"world",
            Vec::new(),
            Vec::new(),
        );
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "custom.test", 80, false)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/hello")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        let h = network.win_http_query_headers(req).expect("headers");
        assert_eq!(h.get("status").unwrap(), "200");
        assert_eq!(h.get("content-type").unwrap(), "text/plain");
        let body = network.win_http_read_data(req, 1024).expect("read");
        assert_eq!(body, b"world");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
    }

    #[test]
    fn http_route_wininet_api_round_trip() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let session = network.internet_open("test-agent");
        let conn = network
            .internet_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .http_open_request(conn, "GET", "/store/cart")
            .expect("open");
        network
            .http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        let body = network.internet_read_file(req, 1024).expect("read");
        assert_eq!(body, b"cart");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
    }

    // --- Cookie management tests ---

    #[test]
    fn cookie_stored_from_route_and_visible_in_snapshot() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        // The default route for api.example.com /login includes a session cookie
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        let snapshot = network.cookie_snapshot_json().expect("snapshot");
        assert!(snapshot.contains("session"));
        assert!(snapshot.contains("abc123"));
    }

    #[test]
    fn cookie_snapshot_round_trip_preserves_cookies() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        let snapshot = network.cookie_snapshot_json().expect("snapshot");
        let mut network2 = NetworkStack::new();
        network2
            .load_cookie_snapshot_json(&snapshot)
            .expect("load");
        let snapshot2 = network2.cookie_snapshot_json().expect("snapshot2");
        assert_eq!(snapshot, snapshot2);
    }

    #[test]
    fn cookie_jar_empty_initially() {
        let network = NetworkStack::new();
        let snapshot = network.cookie_snapshot_json().expect("snapshot");
        assert_eq!(snapshot, "[]");
    }

    #[test]
    fn cookie_jar_rejects_invalid_json() {
        let mut network = NetworkStack::new();
        let result = network.load_cookie_snapshot_json("not valid json");
        assert!(result.is_err());
    }

    // --- Certificate validation tests ---

    fn make_test_cert(hostname: &str, day: i64, revoked: bool) -> Certificate {
        Certificate {
            subject: format!("CN={}", hostname),
            issuer: "CN=TestRoot".to_string(),
            fingerprint: format!("fp:{}:{}", hostname, day),
            valid_hostnames: vec![hostname.to_string()],
            not_after_day: day + 30,
            revoked,
            supported_ciphers: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
        }
    }

    fn make_root_cert() -> Certificate {
        Certificate {
            subject: "CN=TestRoot".to_string(),
            issuer: "CN=TestRoot".to_string(),
            fingerprint: "fp:root".to_string(),
            valid_hostnames: vec![],
            not_after_day: 99999,
            revoked: false,
            supported_ciphers: vec![],
        }
    }

    #[test]
    fn certificate_validate_hostname_match_succeeds() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let leaf = make_test_cert("example.com", 100, false);
        let chain = vec![leaf, Certificate {
            fingerprint: "fp:root".to_string(),
            ..make_root_cert()
        }];
        let suite = network
            .validate_server_certificate("example.com", &chain, false)
            .expect("should validate");
        assert_eq!(suite, "TLS_AES_128_GCM_SHA256");
    }

    #[test]
    fn certificate_validate_hostname_mismatch_rejected() {
        let network = NetworkStack::new();
        let leaf = make_test_cert("example.com", 100, false);
        let chain = vec![leaf];
        let result = network.validate_server_certificate("wrong.com", &chain, false);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_validate_expired_rejected() {
        let network = NetworkStack::new();
        let leaf = make_test_cert("example.com", 5, false);
        let mut network = network;
        network.set_current_day(100);
        let chain = vec![leaf];
        let result = network.validate_server_certificate("example.com", &chain, false);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_validate_revoked_when_checking() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let leaf = make_test_cert("example.com", 100, true); // revoked
        let chain = vec![leaf, Certificate {
            fingerprint: "fp:root".to_string(),
            ..make_root_cert()
        }];
        let result = network.validate_server_certificate("example.com", &chain, true);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_validate_not_revoked_when_not_checking() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let leaf = make_test_cert("example.com", 100, true); // revoked
        let chain = vec![leaf, Certificate {
            fingerprint: "fp:root".to_string(),
            ..make_root_cert()
        }];
        // revocation_check = false, so revoked cert passes
        let result = network.validate_server_certificate("example.com", &chain, false);
        assert!(result.is_ok());
    }

    #[test]
    fn certificate_validate_untrusted_root_rejected() {
        let network = NetworkStack::new();
        let leaf = make_test_cert("example.com", 100, false);
        let chain = vec![leaf, make_root_cert()];
        let result = network.validate_server_certificate("example.com", &chain, false);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_validate_no_shared_cipher_rejected() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let leaf = Certificate {
            supported_ciphers: vec!["TLS_ECDHE_RSA_WITH_RC4_128_SHA".to_string()],
            ..make_test_cert("example.com", 100, false)
        };
        let chain = vec![leaf, Certificate {
            fingerprint: "fp:root".to_string(),
            ..make_root_cert()
        }];
        let result = network.validate_server_certificate("example.com", &chain, false);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_validate_empty_chain_rejected() {
        let network = NetworkStack::new();
        let result = network.validate_server_certificate("example.com", &[], false);
        assert!(result.is_err());
    }

    #[test]
    fn certificate_validate_imported_root_succeeds() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let leaf = make_test_cert("secure.example", 200, false);
        let chain = vec![leaf, Certificate {
            fingerprint: "fp:root".to_string(),
            ..make_root_cert()
        }];
        let result = network.validate_server_certificate("secure.example", &chain, false);
        assert!(result.is_ok());
    }

    #[test]
    fn certificate_export_contains_imported() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let certs = network.export_certificates();
        assert!(!certs.is_empty());
        assert!(certs.iter().any(|c| c.fingerprint == "fp:root"));
    }

    // --- Socket operation tests ---

    #[test]
    fn socket_ipv6_create_bind_listen_connect() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let listener = network.socket(AddressFamily::Ipv6).expect("socket");
        assert_eq!(listener & 0x3, 0);
        let addr = SockAddr {
            family: AddressFamily::Ipv6,
            host: "::1".to_string(),
            port: 37000,
        };
        network.bind(listener, addr.clone()).expect("bind");
        network.listen(listener, 1).expect("listen");

        let client = network.socket(AddressFamily::Ipv6).expect("client");
        network.connect(client, addr.clone()).expect("connect");
        let server = network.accept(listener).expect("accept");

        assert_eq!(network.getsockname(listener).expect("name"), addr);
        assert_eq!(network.getsockname(server).expect("name"), addr);

        network.send(client, b"ipv6-ping").expect("send");
        assert_eq!(network.recv(server, 9).expect("recv"), b"ipv6-ping");
    }

    #[test]
    fn socket_nonblocking_accept_returns_wouldblock() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let sock = network.socket(AddressFamily::Ipv4).expect("socket");
        let addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27016,
        };
        network.bind(sock, addr).expect("bind");
        network.listen(sock, 1).expect("listen");
        network
            .ioctlsocket_fionbio(sock, true)
            .expect("set nonblocking");
        let result = network.accept(sock);
        assert!(result.is_err());
        assert_eq!(network.wsa_get_last_error(), 10035); // WSAEWOULDBLOCK
    }

    #[test]
    fn socket_duplicate_bind_returns_addr_in_use() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let s1 = network.socket(AddressFamily::Ipv4).expect("s1");
        let addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27017,
        };
        network.bind(s1, addr.clone()).expect("bind s1");
        let s2 = network.socket(AddressFamily::Ipv4).expect("s2");
        let result = network.bind(s2, addr);
        assert!(result.is_err());
        assert_eq!(network.wsa_get_last_error(), 10048); // WSAEADDRINUSE
    }

    #[test]
    fn socket_nonblocking_recv_returns_wouldblock() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let sock = network.socket(AddressFamily::Ipv4).expect("socket");
        network
            .ioctlsocket_fionbio(sock, true)
            .expect("set nonblocking");
        // Connect to a listener first so state is Connected
        let listener = network.socket(AddressFamily::Ipv4).expect("listener");
        let addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27018,
        };
        network.bind(listener, addr.clone()).expect("bind");
        network.listen(listener, 1).expect("listen");
        network.connect(sock, addr).expect("connect");
        // recv on empty queue with nonblocking
        let result = network.recv(sock, 4);
        assert!(result.is_err());
        assert_eq!(network.wsa_get_last_error(), 10035); // WSAEWOULDBLOCK
    }

    #[test]
    fn socket_select_detects_readable_and_writable() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let listener = network.socket(AddressFamily::Ipv4).expect("listener");
        let addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27019,
        };
        network.bind(listener, addr.clone()).expect("bind");
        network.listen(listener, 1).expect("listen");

        let client = network.socket(AddressFamily::Ipv4).expect("client");
        network.connect(client, addr.clone()).expect("connect");

        // Listener with pending accept should be readable
        // Select BEFORE accept so the pending connection is still in the queue
        let (readable, writable) = network
            .select(&[client, listener])
            .expect("select");
        assert!(readable.contains(&listener));
        // Client should be writable (connected)
        assert!(writable.contains(&client));

        let server = network.accept(listener).expect("accept");

        // Both connected sockets should be writable
        let (readable2, writable2) = network
            .select(&[client, server])
            .expect("select");
        assert!(writable2.contains(&client));
        assert!(writable2.contains(&server));

        // Send data -> server becomes readable
        network.send(client, b"data").expect("send");
        let (readable3, _) = network.select(&[server]).expect("select");
        assert!(readable3.contains(&server));
    }

    #[test]
    fn socket_poll_returns_state_for_each_socket() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let sock = network.socket(AddressFamily::Ipv4).expect("socket");
        let states = network.wsa_poll(&[sock]).expect("poll");
        assert_eq!(states.len(), 1);
        // Created sockets are not readable or writable
        assert!(!states[0].readable);
        assert!(!states[0].writable);
    }

    #[test]
    fn socket_ioctlsocket_fionread_returns_available_bytes() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let listener = network.socket(AddressFamily::Ipv4).expect("listener");
        let addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27020,
        };
        network.bind(listener, addr.clone()).expect("bind");
        network.listen(listener, 1).expect("listen");
        let client = network.socket(AddressFamily::Ipv4).expect("client");
        network.connect(client, addr).expect("connect");
        let server = network.accept(listener).expect("accept");
        network.send(client, b"12345").expect("send");
        let available = network
            .ioctlsocket_fionread(server)
            .expect("fionread");
        assert_eq!(available, 5);
    }

    #[test]
    fn socket_shutdown_and_close_lifecycle() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let sock = network.socket(AddressFamily::Ipv4).expect("socket");
        network.shutdown(sock).expect("shutdown");
        network.closesocket(sock).expect("close");
        // After close, operations on the socket should fail
        let result = network.getsockname(sock);
        assert!(result.is_err());
    }

    #[test]
    fn socket_operations_fail_without_wsa_startup() {
        let mut network = NetworkStack::new();
        let result = network.socket(AddressFamily::Ipv4);
        assert!(result.is_err());
        assert_eq!(network.wsa_get_last_error(), 10093); // WSANOTINITIALISED
    }

    #[test]
    fn socket_wsa_startup_cleanup_refcount() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        assert!(network.socket(AddressFamily::Ipv4).is_ok());
        network.wsa_cleanup();
        // refcount goes to 0, next operation fails
        network.wsa_cleanup();
        let result = network.socket(AddressFamily::Ipv4);
        assert!(result.is_err());
    }

    #[test]
    fn socket_bind_fails_if_not_created() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let result = network.bind(99999, SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 1,
        });
        assert!(result.is_err());
    }

    // --- DNS resolution tests ---

    #[test]
    fn dns_resolves_preseeded_records() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let addrs = network
            .getaddrinfo("api.example.com", 443)
            .expect("resolve");
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.host == "203.0.113.10"));
        assert!(addrs.iter().all(|a| a.port == 443));
    }

    #[test]
    fn dns_resolves_preseeded_ipv6() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let addrs = network.getaddrinfo("example.com", 80).expect("resolve");
        assert!(addrs.iter().any(|a| a.family == AddressFamily::Ipv6));
        assert!(addrs.iter().any(|a| a.host == "2606:2800:220:1:248:1893:25c8:1946"));
    }

    #[test]
    fn dns_unknown_host_falls_back_to_system() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        // "unknown-host-xyz.test" should not be in pre-seeded records
        let result = network.getaddrinfo("unknown-host-xyz.test", 80);
        // May either fail (DNS not found) or succeed via system DNS
        // We just check it doesn't panic
        match result {
            Ok(addrs) => assert!(!addrs.is_empty()),
            Err(_) => {}
        }
    }

    #[test]
    fn dns_freeaddrinfo_clears_error() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        network.wsa_set_last_error(11001);
        network.freeaddrinfo();
        assert_eq!(network.wsa_get_last_error(), 0);
    }

    // --- Proxy settings tests ---

    #[test]
    fn proxy_env_proxy_appears_in_traces() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        network.set_env_proxy(Some("http://proxy.env:8080".to_string()));
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        let traces = network.http_traces();
        assert!(!traces.is_empty());
        assert_eq!(
            traces.last().unwrap().proxy.as_deref(),
            Some("http://proxy.env:8080")
        );
    }

    #[test]
    fn proxy_system_proxy_appears_in_traces() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        network.set_system_proxy(Some("http://system.proxy:3128".to_string()), true);
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        let traces = network.http_traces();
        assert!(!traces.is_empty());
        assert_eq!(
            traces.last().unwrap().proxy.as_deref(),
            Some("http://system.proxy:3128")
        );
    }

    #[test]
    fn proxy_system_proxy_not_used_when_disabled() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        network.set_system_proxy(Some("http://system.proxy:3128".to_string()), false);
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        let traces = network.http_traces();
        assert!(traces.last().unwrap().proxy.is_none());
    }

    #[test]
    fn proxy_session_override_takes_precedence() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        network.set_env_proxy(Some("http://env.proxy:8080".to_string()));
        let session = network.win_http_open("test");
        network
            .win_http_set_proxy(session, Some("http://session.override:9090".to_string()))
            .expect("set proxy");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        let traces = network.http_traces();
        assert_eq!(
            traces.last().unwrap().proxy.as_deref(),
            Some("http://session.override:9090")
        );
    }

    #[test]
    fn proxy_none_when_not_configured() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        let traces = network.http_traces();
        assert!(traces.last().unwrap().proxy.is_none());
    }

    // --- HTTP traces and cipher log tests ---

    #[test]
    fn http_traces_recorded_per_request() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let session = network.win_http_open("test");
        // First request
        let conn1 = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect1");
        let req1 = network
            .win_http_open_request(conn1, "GET", "/login")
            .expect("open1");
        network
            .win_http_send_request(req1, BTreeMap::new(), &[])
            .expect("send1");
        network.close_handle(req1);
        network.close_handle(conn1);
        // Second request
        let conn2 = network
            .win_http_connect(session, "launcher.example.com", 80, false)
            .expect("connect2");
        let req2 = network
            .win_http_open_request(conn2, "GET", "/patch")
            .expect("open2");
        network
            .win_http_send_request(req2, BTreeMap::new(), &[])
            .expect("send2");
        network.close_handle(req2);
        network.close_handle(conn2);
        network.close_handle(session);
        let traces = network.http_traces();
        assert_eq!(traces.len(), 2);
        // First trace is HTTPS /login
        assert_eq!(traces[0].host, "api.example.com");
        assert_eq!(traces[0].path, "/login");
        assert_eq!(traces[0].stack, "winhttp");
        assert_eq!(traces[0].status, 200);
        assert!(traces[0].cipher_suite.is_some());
        // Second trace is HTTP /patch
        assert_eq!(traces[1].host, "launcher.example.com");
        assert_eq!(traces[1].path, "/patch");
        assert_eq!(traces[1].status, 204);
        assert!(traces[1].cipher_suite.is_none()); // HTTP, no cipher
    }

    #[test]
    fn cipher_log_records_suites_for_https() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        // Import root so validation passes
        let root = make_root_cert();
        network.import_certificate(root);
        // Add route with certificate chain
        let mut headers = BTreeMap::new();
        headers.insert("x-test".to_string(), "tls".to_string());
        let leaf = make_test_cert("tls.test", 100, false);
        network.add_route(
            "https",
            "tls.test",
            "/secure",
            200,
            headers,
            b"ok",
            Vec::new(),
            vec![leaf, Certificate {
                fingerprint: "fp:root".to_string(),
                ..make_root_cert()
            }],
        );
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "tls.test", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/secure")
            .expect("open");
        network
            .win_http_send_request(req, BTreeMap::new(), &[])
            .expect("send");
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        let log = network.cipher_log();
        assert!(!log.is_empty());
        assert!(log[0].contains("tls.test"));
    }

    #[test]
    fn http_traces_empty_initially() {
        let network = NetworkStack::new();
        assert!(network.http_traces().is_empty());
        assert!(network.cipher_log().is_empty());
    }

    // --- close_handle tests ---

    #[test]
    fn close_handle_removes_nested_handles() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let session = network.win_http_open("test");
        let conn = network
            .win_http_connect(session, "api.example.com", 443, true)
            .expect("connect");
        let req = network
            .win_http_open_request(conn, "GET", "/login")
            .expect("open");
        // Close all three
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
        // After closing, operations should fail
        assert!(network.win_http_connect(session, "x", 80, false).is_err());
        // But new handles work
        let s2 = network.win_http_open("test2");
        assert!(s2 >= 0x1000);
    }

    // --- QUIC/HTTP3 additional negotiation tests ---

    #[test]
    fn quic_negotiate_http3_force_enabled_returns_h3() {
        let mut flags = HttpProtocolFlags::new();
        flags.set(HttpProtocolFlags::HTTP3);
        let config = QuicConfig {
            force_enabled: true,
            ..Default::default()
        };
        let alt_svc = vec![AltSvcEntry {
            protocol_id: "h3".to_string(),
            alt_host: String::new(),
            alt_port: 443,
            alpn: Some("h3".to_string()),
        }];
        let (protocol, fell_back) = negotiate_http_protocol(&flags, &config, &alt_svc);
        assert_eq!(protocol, HttpProtocol::Http3);
        assert!(!fell_back);
    }

    #[test]
    fn quic_negotiate_h3_without_alt_svc_falls_back() {
        let mut flags = HttpProtocolFlags::new();
        flags.set(HttpProtocolFlags::HTTP2);
        flags.set(HttpProtocolFlags::HTTP3);
        let config = QuicConfig::default();
        let alt_svc: Vec<AltSvcEntry> = Vec::new();
        // No Alt-Svc advertising h3, but HTTP3 flag is set → still tries QUIC and falls back
        let (protocol, fell_back) = negotiate_http_protocol(&flags, &config, &alt_svc);
        // The function checks has_h3_advertisement OR quic_requested flag
        // With the flag set, quic_requested is true even without alt-svc entries
        assert_eq!(protocol, HttpProtocol::Http2);
        assert!(fell_back);
    }

    #[test]
    fn quic_negotiate_h3_without_h2_falls_back_to_http11() {
        let mut flags = HttpProtocolFlags::new();
        flags.set(HttpProtocolFlags::HTTP3);
        // No HTTP2 flag set
        let config = QuicConfig::default();
        let alt_svc: Vec<AltSvcEntry> = Vec::new();
        let (protocol, fell_back) = negotiate_http_protocol(&flags, &config, &alt_svc);
        assert_eq!(protocol, HttpProtocol::Http11);
        assert!(fell_back);
    }

    #[test]
    fn quic_alt_svc_parses_with_quic_protocol_id() {
        let header = "quic=\":443\"; ma=2592000";
        let entries = parse_alt_svc_header(header);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol_id, "quic");
        assert_eq!(entries[0].alt_port, 443);
    }

    #[test]
    fn quic_alt_svc_parses_multiple_attributes() {
        let header = "h3=\":443\"; ma=2592000; persist=1";
        let entries = parse_alt_svc_header(header);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol_id, "h3");
    }

    // --- Cookie matching edge cases (tested via public helper) ---

    #[test]
    fn cookie_alt_svc_header_with_spaces_and_empty_parts() {
        // Extra whitespace and empty segments between commas
        let entries = parse_alt_svc_header("h3=\":443\"; ma=2592000,  , h3-29=\":443\"; ma=86400");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol_id, "h3");
        assert_eq!(entries[1].protocol_id, "h3-29");
    }

    #[test]
    fn cookie_alt_svc_handles_missing_alpn() {
        let entries = parse_alt_svc_header("h3=\":443\"; ma=2592000");
        assert_eq!(entries[0].alpn, Some("h3".to_string()));
    }

    // --- NetworkStack keychain, default, current_day ---

    #[test]
    fn network_stack_default_keychain_mapping_disabled() {
        let network = NetworkStack::new();
        assert!(!network.keychain_mapping_enabled());
    }

    #[test]
    fn network_stack_default_is_new() {
        let default = NetworkStack::default();
        let new = NetworkStack::new();
        // Can't directly compare, just verify both work
        assert!(default.http_traces().is_empty());
        assert!(new.http_traces().is_empty());
    }

    #[test]
    fn network_stack_set_current_day_affects_expiry() {
        let mut network = NetworkStack::new();
        network.set_current_day(500);
        // Certificate validation uses current_day
        let leaf = make_test_cert("test.local", 100, false);
        let chain = vec![leaf.clone()];
        let result = network.validate_server_certificate("test.local", &chain, false);
        assert!(result.is_err()); // expired because current_day (500) > not_after_day (130)
    }

    #[test]
    fn network_stack_wsa_get_set_last_error() {
        let mut network = NetworkStack::new();
        assert_eq!(network.wsa_get_last_error(), 0);
        network.wsa_set_last_error(11001);
        assert_eq!(network.wsa_get_last_error(), 11001);
        network.wsa_set_last_error(0);
        assert_eq!(network.wsa_get_last_error(), 0);
    }
}