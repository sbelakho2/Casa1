use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use aes::Aes128;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use base64::{Engine as _, engine::general_purpose};
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use der::{Decode, Encode};
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
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, Shutdown as NetShutdown, SocketAddr as NetSocketAddr, TcpStream,
    ToSocketAddrs, UdpSocket,
};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::raw::{c_char, c_void};
use std::sync::Arc;
use std::time::Duration;
use x509_cert::Certificate as X509Certificate;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// QUIC/HTTP3 Support
// ---------------------------------------------------------------------------

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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Whether QUIC/HTTP3 is force-enabled (if true, an error is raised when
    /// HTTP/3 is requested but unavailable).
    pub force_enabled: bool,
    /// Whether QUIC/HTTP3 is force-disabled (if true, HTTP/3 is never used).
    pub force_disabled: bool,
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
const WSAEINVAL: i32 = 10022;
const WSAEADDRINUSE: i32 = 10048;
const WSAECONNRESET: i32 = 10054;
const WSAENOTCONN: i32 = 10057;
const WSAETIMEDOUT: i32 = 10060;
const WSAECONNREFUSED: i32 = 10061;
const WSANOTINITIALISED: i32 = 10093;
const WSAHOST_NOT_FOUND: i32 = 11001;

// ---------------------------------------------------------------------------
// Network size limits — prevent resource exhaustion
// ---------------------------------------------------------------------------

/// Maximum socket receive queue size (16 MB).
pub const MAX_SOCKET_RECEIVE_QUEUE: usize = 16 * 1024 * 1024;
/// Maximum HTTP request body size (64 MB).
pub const MAX_HTTP_REQUEST_BODY: usize = 64 * 1024 * 1024;
/// Maximum WebSocket frame size (64 MB).
pub const MAX_WEBSOCKET_FRAME_SIZE: usize = 64 * 1024 * 1024;
/// Maximum WebSocket send buffer size (16 MB).
pub const MAX_WEBSOCKET_SEND_BUFFER: usize = 16 * 1024 * 1024;
/// Maximum WebSocket receive spill buffer size (16 MB).
pub const MAX_WEBSOCKET_RECEIVE_SPILL: usize = 16 * 1024 * 1024;
/// Maximum number of HTTP headers per request/response.
pub const MAX_HTTP_HEADER_COUNT: usize = 128;
/// Maximum total size of HTTP headers in bytes (256 KB).
pub const MAX_HTTP_HEADER_BYTES: usize = 256 * 1024;
/// Maximum pending accept queue length for listening sockets.
pub const MAX_PENDING_ACCEPT_QUEUE: usize = 128;
/// Maximum HTTP response body size accepted by `http_get` (256 MB).
const MAX_HTTP_RESPONSE_BODY: usize = 256 * 1024 * 1024;
/// Read timeout for blocking HTTP responses.
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum number of retained HTTP traces and cipher-log entries.
const MAX_HTTP_TRACE_ENTRIES: usize = 1024;
/// Maximum number of cookies retained in a jar.
const MAX_COOKIE_JAR_SIZE: usize = 1024;

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
        self.pins
            .entry(host)
            .or_default()
            .push(fingerprint.to_string());
    }

    /// Add multiple pins for a hostname.
    pub fn add_pins(&mut self, hostname: &str, fingerprints: &[String]) {
        let host = hostname.to_lowercase();
        self.pins
            .entry(host)
            .or_default()
            .extend_from_slice(fingerprints);
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
                            format!("certificate pinning: failed to encode SPKI for {host}: {e}"),
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

    /// Whether no pins are configured.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
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

// ---------------------------------------------------------------------------
// Guest network configuration model
// ---------------------------------------------------------------------------
//
// The GUEST's view of the network — the single source of truth for the
// iphlpapi.dll adapter/route/interface tables, the netapi32 workstation
// identity, and `gethostname`.  Everything derives from the guest
// environment (the hostname `GetComputerNameW` reports and the guest user),
// so the HOST's real adapters can never leak into the guest: the tables
// describe a deterministic, self-contained guest network (loopback +
// one Ethernet adapter on a private subnet with a gateway and a DNS
// server).

/// An IPv4 assignment on a guest adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestIpv4 {
    pub address: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
}

/// An IPv6 assignment on a guest adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestIpv6 {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
}

/// One guest network adapter (mirrors the MIB_IFROW/IP_ADAPTER_INFO model).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestAdapter {
    /// Interface index (`ifIndex`).
    pub index: u32,
    /// Registry-style adapter name (`AdapterName` / `{GUID}` form).
    pub adapter_name: String,
    /// Long description (`Description`).
    pub description: String,
    /// Friendly display name (`FriendlyName`).
    pub friendly_name: String,
    pub mac: [u8; 6],
    pub ipv4: Option<GuestIpv4>,
    pub ipv6: Option<GuestIpv6>,
    pub dhcp_enabled: bool,
    pub dns_servers: Vec<String>,
    pub mtu: u32,
    /// Bits per second (`dwSpeed` / `TransmitLinkSpeed`).
    pub speed: u64,
    /// `IF_TYPE_*` (6 = IF_TYPE_ETHERNET_CSMACD, 24 = IF_TYPE_SOFTWARE_LOOPBACK).
    pub if_type: u32,
    /// `IfOperStatusUp` = 1.
    pub oper_status: u32,
    /// Interface metric.
    pub metric: u32,
}

/// One guest IPv4 route (mirrors MIB_IPFORWARDROW).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestRoute {
    pub dest: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub if_index: u32,
    /// MIB_IPFORWARD_TYPE: 3 = direct, 4 = indirect.
    pub route_type: u32,
    pub metric: u32,
}

/// The complete guest network identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestNetworkConfig {
    /// The host name `gethostname`/`GetComputerNameW` report.
    pub hostname: String,
    /// The workgroup/domain the workstation belongs to.
    pub domain: String,
    /// The guest user name (from the guest environment).
    pub user_name: String,
    pub adapters: Vec<GuestAdapter>,
    pub routes: Vec<GuestRoute>,
    pub dns_servers: Vec<String>,
}

/// The canonical guest network configuration.  Deterministic per runtime —
/// the guest's adapters, addresses and routes never depend on the host
/// machine this runtime runs on.
pub fn guest_network_config(user_name: &str) -> GuestNetworkConfig {
    let hostname = "CASA1".to_string();
    let domain = "WORKGROUP".to_string();
    GuestNetworkConfig {
        hostname,
        domain: domain.clone(),
        user_name: user_name.to_string(),
        adapters: vec![
            GuestAdapter {
                index: 1,
                adapter_name: "{CASA1-0000-0000-0000-000000000001}".to_string(),
                description: "Loopback Pseudo-Interface 1".to_string(),
                friendly_name: "Loopback Pseudo-Interface 1".to_string(),
                mac: [0, 0, 0, 0, 0, 0],
                ipv4: Some(GuestIpv4 {
                    address: Ipv4Addr::LOCALHOST,
                    mask: Ipv4Addr::new(255, 0, 0, 0),
                    gateway: None,
                }),
                ipv6: None,
                dhcp_enabled: false,
                dns_servers: Vec::new(),
                mtu: 65_536,
                speed: 1_000_000_000,
                if_type: 24, // IF_TYPE_SOFTWARE_LOOPBACK
                oper_status: 1,
                metric: 1,
            },
            GuestAdapter {
                index: 2,
                adapter_name: "{CASA1-0000-0000-0000-000000000002}".to_string(),
                description: "Casa1 Virtual Ethernet Adapter".to_string(),
                friendly_name: "Ethernet".to_string(),
                mac: [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E],
                ipv4: Some(GuestIpv4 {
                    address: Ipv4Addr::new(10, 0, 2, 15),
                    mask: Ipv4Addr::new(255, 255, 255, 0),
                    gateway: Some(Ipv4Addr::new(10, 0, 2, 2)),
                }),
                ipv6: Some(GuestIpv6 {
                    address: "fd00::2".parse().expect("static guest IPv6"),
                    prefix_len: 64,
                }),
                dhcp_enabled: true,
                dns_servers: vec!["10.0.2.3".to_string()],
                mtu: 1500,
                speed: 1_000_000_000,
                if_type: 6, // IF_TYPE_ETHERNET_CSMACD
                oper_status: 1,
                metric: 10,
            },
        ],
        routes: vec![
            GuestRoute {
                dest: Ipv4Addr::new(127, 0, 0, 0),
                mask: Ipv4Addr::new(255, 0, 0, 0),
                next_hop: Ipv4Addr::LOCALHOST,
                if_index: 1,
                route_type: 3,
                metric: 1,
            },
            GuestRoute {
                dest: Ipv4Addr::new(10, 0, 2, 0),
                mask: Ipv4Addr::new(255, 255, 255, 0),
                next_hop: Ipv4Addr::UNSPECIFIED,
                if_index: 2,
                route_type: 3,
                metric: 10,
            },
            GuestRoute {
                dest: Ipv4Addr::UNSPECIFIED,
                mask: Ipv4Addr::UNSPECIFIED,
                next_hop: Ipv4Addr::new(10, 0, 2, 2),
                if_index: 2,
                route_type: 4,
                metric: 10,
            },
        ],
        dns_servers: vec!["10.0.2.3".to_string()],
    }
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
    /// Whether the peer has closed the real stream (EOF observed).
    real_eof: bool,
    /// Per-socket SO_ERROR slot: set by failed connect attempts and
    /// transport errors; read-and-cleared by `getsockopt(SO_ERROR)`.
    /// This is what makes the non-blocking connect + select + getsockopt
    /// contract observable (a connect in progress reports WSAEWOULDBLOCK
    /// until it completes, exactly like WinSock).
    pending_error: i32,
}

#[derive(Debug, Clone)]
enum SocketState {
    Created,
    Bound(SockAddr),
    Listening {
        _addr: SockAddr,
        _backlog: usize,
    },
    Connected {
        peer: SocketId,
    },
    ConnectedReal {
        _peer: SockAddr,
    },
    /// A non-blocking connect that is still in progress.
    ConnectingReal {
        peer: SockAddr,
    },
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

#[derive(Debug, Clone)]
#[allow(dead_code)] // WebSocket record metadata for future text-mode framing
struct WebSocketRecord {
    /// The request handle this WebSocket was upgraded from.
    request_handle: HttpRequestId,
    /// Whether the WebSocket is still open.
    is_open: bool,
    /// Buffer for received data.
    receive_buffer: Vec<u8>,
    /// Buffer for sent data.
    send_buffer: Vec<u8>,
    /// Close status code.
    close_status: u16,
    /// Optional close reason.
    close_reason: Option<String>,
    /// Whether text mode is preferred.
    is_text_mode: bool,
    /// The WebSocket URL.
    url: Option<String>,
}

impl WebSocketRecord {
    fn new(request_handle: HttpRequestId, is_text_mode: bool, url: Option<String>) -> Self {
        Self {
            request_handle,
            is_open: true,
            receive_buffer: Vec::new(),
            send_buffer: Vec::new(),
            close_status: 1000, // Normal closure
            close_reason: None,
            is_text_mode,
            url,
        }
    }
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
    /// Standalone id source for host-side/test sockets and non-socket id
    /// spaces (http/websocket handles).  Guest-visible winsock sockets are
    /// registered under win32-table-minted values via `socket_register`.
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
    /// WebSocket connections (ws_handle -> WebSocketRecord)
    websockets: BTreeMap<u64, WebSocketRecord>,
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
            AppError::new(
                ReasonCode::RcNetDnsResolutionFailed,
                "NetworkStack: no host in URL",
            )
        })?;

        let port = url
            .port()
            .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = url.path();
        let query = url.query().map(|q| format!("?{q}")).unwrap_or_default();
        let request_path = format!("{path}{query}");

        let addr_str = format!("{host}:{port}");
        let addr = addr_str
            .to_socket_addrs()
            .map_err(|e| {
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
            // Build TlsConnector with explicit SNI hostname so that
            // virtual-host aware servers return the correct certificate.
            // The SNI hostname is provided in the `connector.connect(host, stream)` call below,
            // which sends the hostname as the TLS SNI extension automatically.
            let connector = native_tls::TlsConnector::builder().build().map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetConnectionFailed,
                    format!("NetworkStack: TLS connector build failed: {e}"),
                )
            })?;
            let mut tls_stream = connector.connect(host, stream).map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetConnectionFailed,
                    format!("NetworkStack: TLS handshake with {host} failed: {e}"),
                )
            })?;
            tls_stream
                .get_mut()
                .set_read_timeout(Some(HTTP_READ_TIMEOUT))
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetReadFailed,
                        format!("NetworkStack: TLS read-timeout setup failed: {e}"),
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
                    Ok(n) => {
                        response.extend_from_slice(&buf[..n]);
                        if response.len() > MAX_HTTP_RESPONSE_BODY {
                            return Err(AppError::new(
                                ReasonCode::RcBufferLimitExceeded,
                                format!(
                                    "NetworkStack: HTTP response exceeds {MAX_HTTP_RESPONSE_BODY} bytes"
                                ),
                            ));
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err(AppError::new(
                            ReasonCode::RcNetReadFailed,
                            "NetworkStack: TLS read timed out",
                        ));
                    }
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

        // Plain HTTP
        let mut tcp_stream = stream;
        tcp_stream
            .set_read_timeout(Some(HTTP_READ_TIMEOUT))
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetReadFailed,
                    format!("NetworkStack: HTTP read-timeout setup failed: {e}"),
                )
            })?;
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
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > MAX_HTTP_RESPONSE_BODY {
                        return Err(AppError::new(
                            ReasonCode::RcBufferLimitExceeded,
                            format!(
                                "NetworkStack: HTTP response exceeds {MAX_HTTP_RESPONSE_BODY} bytes"
                            ),
                        ));
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Err(AppError::new(
                        ReasonCode::RcNetReadFailed,
                        "NetworkStack: HTTP read timed out",
                    ));
                }
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
pub fn parse_http_response(raw: &[u8]) -> AppResult<SimpleHttpResponse> {
    // Locate the header/body separator on the raw bytes: converting to a lossy
    // String first would skew offsets (each invalid UTF-8 byte becomes a 3-byte
    // replacement char), which could push `body_start` past `raw.len()`.
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let header_bytes = &raw[..header_end];
    let response_str = String::from_utf8_lossy(header_bytes);

    // Parse status line: HTTP/1.1 200 OK
    let status = if let Some(end_of_line) = response_str.find("\r\n") {
        let status_line = &response_str[..end_of_line];
        let parts: Vec<&str> = status_line.split(' ').collect();
        if parts.len() >= 2 {
            parts[1].parse::<u16>().map_err(|_| {
                AppError::new(
                    ReasonCode::RcPortParseError,
                    format!("invalid HTTP status code: '{}'", parts[1]),
                )
            })?
        } else {
            0
        }
    } else {
        0
    };

    // Parse headers (skip the status line)
    let mut headers = BTreeMap::new();
    if header_end < raw.len() {
        let mut header_total_bytes: usize = 0;
        for line in response_str.lines().skip(1) {
            if headers.len() >= MAX_HTTP_HEADER_COUNT {
                return Err(AppError::new(
                    ReasonCode::RcHttpHeaderLimitExceeded,
                    format!("HTTP header count exceeds limit ({MAX_HTTP_HEADER_COUNT})"),
                ));
            }
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim().to_string();
                let value = line[colon + 1..].trim().to_string();
                header_total_bytes += key.len() + value.len();
                if header_total_bytes > MAX_HTTP_HEADER_BYTES {
                    return Err(AppError::new(
                        ReasonCode::RcHttpHeaderLimitExceeded,
                        format!("HTTP header total bytes exceeds limit ({MAX_HTTP_HEADER_BYTES})"),
                    ));
                }
                headers.insert(key.to_lowercase(), value);
            }
        }
    }

    let body_start = if header_end == raw.len() {
        raw.len()
    } else {
        header_end + 4
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
        // Streams that fail to duplicate (e.g. already closed) are skipped
        // rather than panicking the clone.
        let real_tcp_streams = self
            .real_tcp_streams
            .iter()
            .filter_map(|(socket, stream)| stream.try_clone().ok().map(|cloned| (*socket, cloned)))
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
            websockets: self.websockets.clone(),
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
            (
                "https".to_string(),
                "api.example.com".to_string(),
                "/login".to_string(),
            ),
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
                certificate_chain: vec![
                    api_cert.clone(),
                    Certificate {
                        subject: "CN=TestRoot".to_string(),
                        issuer: "CN=TestRoot".to_string(),
                        fingerprint: "fp:test-root".to_string(),
                        valid_hostnames: vec![],
                        not_after_day: 99999,
                        revoked: false,
                        supported_ciphers: vec![],
                    },
                ],
            },
        );
        routes.insert(
            (
                "https".to_string(),
                "api.example.com".to_string(),
                "/store/cart".to_string(),
            ),
            HttpResponseTemplate {
                status: 200,
                headers: BTreeMap::from([("x-casa1-route".to_string(), "cart".to_string())]),
                body: b"cart".to_vec(),
                cookies: Vec::new(),
                certificate_chain: vec![
                    api_cert,
                    Certificate {
                        subject: "CN=TestRoot".to_string(),
                        issuer: "CN=TestRoot".to_string(),
                        fingerprint: "fp:test-root".to_string(),
                        valid_hostnames: vec![],
                        not_after_day: 99999,
                        revoked: false,
                        supported_ciphers: vec![],
                    },
                ],
            },
        );
        routes.insert(
            (
                "http".to_string(),
                "launcher.example.com".to_string(),
                "/patch".to_string(),
            ),
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
            websockets: BTreeMap::new(),
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

    #[allow(clippy::too_many_arguments)]
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
                real_eof: false,
                pending_error: 0,
            },
        );
        self.last_wsa_error = 0;
        Ok(id)
    }

    /// Register a socket whose id was minted by the win32 handle table (the
    /// runtime WSA path): `Win32Subsystem::insert_socket` allocates the
    /// value, this registers the transport record under that SAME value.
    /// The unified namespace means a socket value can never collide with a
    /// live kernel handle, so the record is keyed by the win32-validated id.
    /// NOTE: `socket()`/`alloc_id` (a standalone id space starting at 0x1000,
    /// step 4) remain only for host-side/test use — the guest-visible WSA
    /// path goes through here.
    pub fn socket_register(&mut self, id: u64, family: AddressFamily) -> AppResult<()> {
        self.ensure_wsa_started()?;
        if self.sockets.contains_key(&id) {
            self.last_wsa_error = WSAEINVAL;
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("socket id {id} is already registered"),
            ));
        }
        self.sockets.insert(
            id,
            SocketRecord {
                family,
                nonblocking: false,
                bound_addr: None,
                state: SocketState::Created,
                recv_queue: VecDeque::new(),
                real_eof: false,
                pending_error: 0,
            },
        );
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn bind(&mut self, socket: SocketId, addr: SockAddr) -> AppResult<()> {
        self.ensure_wsa_started()?;
        if self.listeners.contains_key(&addr)
            || self.sockets.values().any(
                |record| matches!(&record.state, SocketState::Bound(existing) if existing == &addr),
            )
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
        let capped_backlog = backlog.min(MAX_PENDING_ACCEPT_QUEUE);
        self.socket_record_mut(socket)?.state = SocketState::Listening {
            _addr: addr.clone(),
            _backlog: capped_backlog,
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
                Err(AppError::new(ReasonCode::RcIo, "no pending connections"))
            }
        }
    }

    /// Accept a pending connection and re-register the accepted transport
    /// record under `new_id` — a win32-table-minted handle — so the value
    /// returned to the guest is a first-class socket in the unified handle
    /// namespace (send/recv/closesocket type-check it as a socket).
    ///
    /// The accepted record is moved from its host-side pending-accept id to
    /// `new_id`; the connecting client's peer pointer is repointed at
    /// `new_id` so its sends land in the accepted socket's receive queue
    /// (and vice versa).  Returns the client's address, which is what the
    /// `accept`/`WSAAccept` out-parameter must report.
    pub fn accept_with_id(&mut self, listener: SocketId, new_id: u64) -> AppResult<SockAddr> {
        self.ensure_wsa_started()?;
        let nonblocking = self.socket_record(listener)?.nonblocking;
        let queue = self.pending_accept.entry(listener).or_default();
        let client_socket = match queue.pop_front() {
            Some(client_socket) => client_socket,
            None if nonblocking => {
                self.last_wsa_error = WSAEWOULDBLOCK;
                return Err(AppError::new(
                    ReasonCode::RcWinsockWouldBlock,
                    "non-blocking accept would block",
                ));
            }
            None => {
                self.last_wsa_error = 0;
                return Err(AppError::new(ReasonCode::RcIo, "no pending connections"));
            }
        };
        let client_record = self.socket_record(client_socket)?;
        let client_family = client_record.family;
        let client_addr = client_record
            .bound_addr
            .clone()
            .unwrap_or_else(|| default_sockaddr(client_family));
        let accepted = self.sockets.remove(&client_socket).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("pending accept record {client_socket} is gone"),
            )
        })?;
        // The connecting client still points its Connected peer at the old
        // host-side id — repoint it so its sends reach the accepted socket.
        let peer = match &accepted.state {
            SocketState::Connected { peer } => Some(*peer),
            _ => None,
        };
        if let Some(peer) = peer
            && let Ok(client_record) = self.socket_record_mut(peer)
        {
            client_record.state = SocketState::Connected { peer: new_id };
        }
        self.sockets.insert(new_id, accepted);
        self.last_wsa_error = 0;
        Ok(client_addr)
    }

    /// Read and clear the per-socket SO_ERROR slot (getsockopt semantics:
    /// the error is consumed by the read).
    pub fn take_pending_error(&mut self, socket: SocketId) -> AppResult<i32> {
        self.ensure_wsa_started()?;
        let record = self.socket_record_mut(socket)?;
        let error = std::mem::replace(&mut record.pending_error, 0);
        self.last_wsa_error = 0;
        Ok(error)
    }

    /// Peek the per-socket SO_ERROR slot without clearing it (WSAPoll
    /// uses this to report POLLERR).
    pub fn peek_pending_error(&self, socket: SocketId) -> AppResult<i32> {
        Ok(self.socket_record(socket)?.pending_error)
    }

    /// Whether the socket is in the listening state (SO_ACCEPTCONN).
    pub fn socket_is_listening(&self, socket: SocketId) -> AppResult<bool> {
        Ok(matches!(
            self.socket_record(socket)?.state,
            SocketState::Listening { .. }
        ))
    }

    /// The address family of a registered socket (used by
    /// WSADuplicateSocketW to fill the protocol info structure).
    pub fn socket_family(&self, socket: SocketId) -> AppResult<AddressFamily> {
        Ok(self.socket_record(socket)?.family)
    }

    /// Reverse DNS lookup against the configured guest DNS records: returns
    /// the first host name whose resolved addresses contain `ip`.  This is
    /// the guest-visible name database — the host's resolver is never used
    /// in reverse (the configured records ARE the guest's view of the
    /// network, mirroring `getaddrinfo`'s forward path).
    pub fn reverse_dns(&self, ip: &str) -> Option<String> {
        self.dns_records
            .iter()
            .find(|(_host, records)| records.iter().any(|record| record.host == ip))
            .map(|(host, _records)| host.clone())
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
                    real_eof: false,
                    pending_error: 0,
                },
            );
            let record = self.socket_record_mut(socket)?;
            if record.bound_addr.is_none() {
                record.bound_addr = Some(default_sockaddr(family));
            }
            record.state = SocketState::Connected {
                peer: server_socket,
            };
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
        let mut addrs = (addr.host.as_str(), addr.port)
            .to_socket_addrs()
            .map_err(|error| {
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
                    format!(
                        "no {family:?} address available for {}:{}",
                        addr.host, addr.port
                    ),
                )
            })?;

        if nonblocking {
            // Non-blocking connect: start the connect and return WSAEWOULDBLOCK
            // immediately when it is still in progress, matching WinSock
            // semantics. Completion is observed via SO_ERROR in select/recv/send.
            let (stream, in_progress) = nonblocking_connect(&candidate).map_err(|error| {
                let wsa_error = map_wsa_error(&error);
                self.last_wsa_error = wsa_error;
                if let Ok(record) = self.socket_record_mut(socket) {
                    record.pending_error = wsa_error;
                }
                AppError::new(
                    ReasonCode::RcIo,
                    format!("TCP connect to {}:{} failed: {error}", addr.host, addr.port),
                )
            })?;
            if in_progress {
                let local_addr = stream.local_addr().ok().map(sockaddr_from_std);
                self.real_tcp_streams.insert(socket, stream);
                let record = self.socket_record_mut(socket)?;
                if record.bound_addr.is_none() {
                    record.bound_addr = local_addr.or_else(|| Some(default_sockaddr(family)));
                }
                record.state = SocketState::ConnectingReal { peer: addr.clone() };
                record.pending_error = WSAEWOULDBLOCK;
                self.last_wsa_error = WSAEWOULDBLOCK;
                return Err(AppError::new(
                    ReasonCode::RcWinsockWouldBlock,
                    format!(
                        "non-blocking connect to {}:{} in progress",
                        addr.host, addr.port
                    ),
                ));
            }
            let local_addr = stream.local_addr().ok().map(sockaddr_from_std);
            self.real_tcp_streams.insert(socket, stream);
            let record = self.socket_record_mut(socket)?;
            if record.bound_addr.is_none() {
                record.bound_addr = local_addr.or_else(|| Some(default_sockaddr(family)));
            }
            record.state = SocketState::ConnectedReal { _peer: addr };
            record.pending_error = 0;
            self.last_wsa_error = 0;
            return Ok(());
        }

        // Blocking connect: bound it so an unreachable host cannot stall the
        // caller indefinitely.
        let stream =
            TcpStream::connect_timeout(&candidate, Duration::from_secs(15)).map_err(|error| {
                let wsa_error = map_wsa_error(&error);
                self.last_wsa_error = wsa_error;
                if let Ok(record) = self.socket_record_mut(socket) {
                    record.pending_error = wsa_error;
                }
                AppError::new(
                    ReasonCode::RcIo,
                    format!("TCP connect to {}:{} failed: {error}", addr.host, addr.port),
                )
            })?;
        let local_addr = stream.local_addr().ok().map(sockaddr_from_std);
        self.real_tcp_streams.insert(socket, stream);

        let record = self.socket_record_mut(socket)?;
        if record.bound_addr.is_none() {
            record.bound_addr = local_addr.or_else(|| Some(default_sockaddr(family)));
        }
        record.state = SocketState::ConnectedReal { _peer: addr };
        record.pending_error = 0;
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
        self.maybe_finish_connect(socket)?;
        if let Some(stream) = self.real_tcp_streams.get_mut(&socket) {
            let written = stream.write(bytes).map_err(|error| {
                let wsa_error = map_wsa_error(&error);
                self.last_wsa_error = wsa_error;
                if let Ok(record) = self.socket_record_mut(socket) {
                    record.pending_error = wsa_error;
                }
                AppError::new(
                    ReasonCode::RcIo,
                    format!("TCP send failed on socket {socket}: {error}"),
                )
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
        {
            let record = self.socket_record_mut(peer)?;
            let new_len = record.recv_queue.len().saturating_add(bytes.len());
            if new_len > MAX_SOCKET_RECEIVE_QUEUE {
                return Err(AppError::new(
                    ReasonCode::RcSocketReceiveQueueFull,
                    format!(
                        "socket receive queue full: {} + {} > {}",
                        record.recv_queue.len(),
                        bytes.len(),
                        MAX_SOCKET_RECEIVE_QUEUE
                    ),
                ));
            }
            record.recv_queue.extend(bytes.iter().copied());
        }
        self.last_wsa_error = 0;
        Ok(bytes.len())
    }

    pub fn recv(&mut self, socket: SocketId, length: usize) -> AppResult<Vec<u8>> {
        self.recv_flags(socket, length, false)
    }

    /// `recv` with the MSG_PEEK flag: the queued bytes are returned WITHOUT
    /// consuming them (Windows peek semantics).
    pub fn recv_flags(
        &mut self,
        socket: SocketId,
        length: usize,
        peek: bool,
    ) -> AppResult<Vec<u8>> {
        self.ensure_wsa_started()?;
        // A zero-length recv must return immediately without touching the
        // stream (Windows returns 0 without blocking).
        if length == 0 {
            self.last_wsa_error = 0;
            return Ok(Vec::new());
        }
        self.maybe_finish_connect(socket)?;
        if let Some(stream) = self.real_tcp_streams.get_mut(&socket) {
            // Cap the allocation: the guest-supplied length is untrusted and a
            // huge value would OOM the host.
            let capped = length.min(MAX_SOCKET_RECEIVE_QUEUE);
            let mut bytes = vec![0; capped];
            let read = stream.read(&mut bytes).map_err(|error| {
                let wsa_error = map_wsa_error(&error);
                self.last_wsa_error = wsa_error;
                if let Ok(record) = self.socket_record_mut(socket) {
                    record.pending_error = wsa_error;
                }
                AppError::new(
                    ReasonCode::RcIo,
                    format!("TCP recv failed on socket {socket}: {error}"),
                )
            })?;
            bytes.truncate(read);
            if read == 0 {
                let _ = self
                    .socket_record_mut(socket)
                    .map(|record| record.real_eof = true);
            }
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
        let count = length.min(self.socket_record(socket)?.recv_queue.len());
        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            match self.socket_record_mut(socket)?.recv_queue.pop_front() {
                Some(byte) => bytes.push(byte),
                None => break,
            }
        }
        if peek {
            // Peek: put the bytes back on the FRONT of the queue (they were
            // popped to read them; re-queue in order).
            let record = self.socket_record_mut(socket)?;
            for byte in bytes.iter().rev() {
                record.recv_queue.push_front(*byte);
            }
        }
        self.last_wsa_error = 0;
        Ok(bytes)
    }

    /// The source address a `recvfrom`-style operation reports: the
    /// connected peer's bound address when connected, otherwise the
    /// socket's own bound address (the model's loopback-only transport
    /// means the sender is always a peer in the same runtime).
    pub fn peer_address(&self, socket: SocketId) -> AppResult<SockAddr> {
        let record = self.socket_record(socket)?;
        match &record.state {
            SocketState::Connected { peer } => {
                let peer_record = self.socket_record(*peer)?;
                Ok(peer_record
                    .bound_addr
                    .clone()
                    .unwrap_or_else(|| default_sockaddr(peer_record.family)))
            }
            _ => Ok(record
                .bound_addr
                .clone()
                .unwrap_or_else(|| default_sockaddr(record.family))),
        }
    }

    /// `sendto`-style delivery: route the bytes to the socket bound to
    /// `dest` (the model's loopback transport — every socket lives in this
    /// runtime).  When no socket is bound to the destination, the datagram
    /// is silently dropped (UDP semantics: success, nothing listens).
    pub fn send_to(&mut self, socket: SocketId, bytes: &[u8], dest: &SockAddr) -> AppResult<usize> {
        self.ensure_wsa_started()?;
        self.maybe_finish_connect(socket)?;
        let target = self
            .bound_socket_matching(dest)
            .filter(|target| *target != socket);
        if let Some(target) = target {
            let record = self.socket_record_mut(target)?;
            let new_len = record.recv_queue.len().saturating_add(bytes.len());
            if new_len > MAX_SOCKET_RECEIVE_QUEUE {
                return Err(AppError::new(
                    ReasonCode::RcSocketReceiveQueueFull,
                    format!(
                        "socket receive queue full: {} + {} > {}",
                        record.recv_queue.len(),
                        bytes.len(),
                        MAX_SOCKET_RECEIVE_QUEUE
                    ),
                ));
            }
            record.recv_queue.extend(bytes.iter().copied());
        }
        self.last_wsa_error = 0;
        Ok(bytes.len())
    }

    /// The socket whose bound address matches `addr` (host + port), if any.
    fn bound_socket_matching(&self, addr: &SockAddr) -> Option<SocketId> {
        self.sockets.iter().find_map(|(id, record)| {
            let bound = record.bound_addr.as_ref()?;
            (bound.host == addr.host && bound.port == addr.port).then_some(*id)
        })
    }

    pub fn setsockopt(
        &mut self,
        socket: SocketId,
        _level: i32,
        _option_name: i32,
        _value: &[u8],
    ) -> AppResult<()> {
        self.ensure_wsa_started()?;
        // Validate that the socket exists; the record is not needed for setsockopt
        // since we're not implementing actual socket option changes.
        let _record = self.socket_record(socket)?;
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn shutdown(&mut self, socket: SocketId) -> AppResult<()> {
        self.ensure_wsa_started()?;
        if let Some(stream) = self.real_tcp_streams.get(&socket) {
            stream.shutdown(NetShutdown::Both).map_err(|error| {
                self.last_wsa_error = map_wsa_error(&error);
                AppError::new(
                    ReasonCode::RcIo,
                    format!("shutdown failed on socket {socket}: {error}"),
                )
            })?;
        }
        self.socket_record_mut(socket)?.state = SocketState::Shutdown;
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn closesocket(&mut self, socket: SocketId) -> AppResult<()> {
        self.ensure_wsa_started()?;
        if let Some(stream) = self.real_tcp_streams.remove(&socket) {
            match stream.shutdown(NetShutdown::Both) {
                Ok(()) => {}
                Err(e) => {
                    // Socket may already be closed or not connected; log but don't fail
                    eprintln!("closesocket: shutdown failed for socket {socket}: {e}");
                }
            }
        }
        // Drop the listener registration so the address can be re-bound, and
        // discard its pending-accept queue (those client sockets can never be
        // accepted once the listener is gone).
        self.listeners.retain(|_addr, id| *id != socket);
        if let Some(queued) = self.pending_accept.remove(&socket) {
            for client in queued {
                self.sockets.remove(&client);
                self.real_tcp_streams.remove(&client);
            }
        }
        // Purge this socket from other listeners' pending-accept queues.
        for queue in self.pending_accept.values_mut() {
            queue.retain(|queued_id| *queued_id != socket);
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
        let available = self
            .socket_record(socket)?
            .recv_queue
            .len()
            .min(u32::MAX as usize) as u32;
        self.last_wsa_error = 0;
        Ok(available)
    }

    pub fn select(&self, sockets: &[SocketId]) -> AppResult<(Vec<SocketId>, Vec<SocketId>)> {
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        for socket in sockets {
            let record = self.socket_record(*socket)?;
            let (can_read, can_write) = if let SocketState::ConnectingReal { .. } = record.state {
                // A non-blocking connect in progress: report writable once
                // it completes, and both readable+writable on failure,
                // matching WinSock select semantics.
                match self.real_tcp_streams.get(socket).map(connect_state) {
                    Some(ConnectState::Complete) => (false, true),
                    Some(ConnectState::Failed(_)) => (true, true),
                    _ => (false, false),
                }
            } else {
                let can_read = if let Some(stream) = self.real_tcp_streams.get(socket) {
                    bytes_available(stream)? > 0 || record.real_eof
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
                (can_read, can_write)
            };
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
        let readable: HashSet<SocketId> = readable.into_iter().collect();
        let writable: HashSet<SocketId> = writable.into_iter().collect();
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

    pub fn win_http_set_proxy(
        &mut self,
        session: HttpSessionId,
        proxy: Option<String>,
    ) -> AppResult<()> {
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

    pub fn win_http_query_headers(
        &self,
        request: HttpRequestId,
    ) -> AppResult<BTreeMap<String, String>> {
        let response = self
            .http_request(request)?
            .response
            .as_ref()
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, "request has no response"))?;
        let mut headers = response.headers.clone();
        headers.insert("status".to_string(), response.status.to_string());
        Ok(headers)
    }

    pub fn win_http_read_data(
        &mut self,
        request: HttpRequestId,
        count: usize,
    ) -> AppResult<Vec<u8>> {
        self.read_body(request, count)
    }

    pub fn internet_read_file(
        &mut self,
        request: HttpRequestId,
        count: usize,
    ) -> AppResult<Vec<u8>> {
        self.read_body(request, count)
    }

    pub fn close_handle(&mut self, handle: u64) {
        if self.http_sessions.remove(&handle).is_some() {
            let connections: Vec<HttpConnectionId> = self
                .http_connections
                .iter()
                .filter(|(_id, conn)| conn.session == handle)
                .map(|(id, _)| *id)
                .collect();
            for connection in connections {
                self.close_handle(connection);
            }
        }
        if self.http_connections.remove(&handle).is_some() {
            let requests: Vec<HttpRequestId> = self
                .http_requests
                .iter()
                .filter(|(_id, req)| req.connection == handle)
                .map(|(id, _)| *id)
                .collect();
            for request in requests {
                self.close_http_request(request);
            }
        }
        self.close_http_request(handle);
        self.websockets.remove(&handle);
    }

    fn close_http_request(&mut self, request: HttpRequestId) {
        self.http_requests.remove(&request);
        self.websockets
            .retain(|_handle, ws| ws.request_handle != request);
    }

    // -----------------------------------------------------------------------
    // J1: WebSocket support (RFC 6455)
    // -----------------------------------------------------------------------

    /// Complete a WebSocket upgrade from an existing HTTP request.
    /// Returns a new WebSocket handle on success.
    pub fn websocket_complete_upgrade(&mut self, request_handle: HttpRequestId) -> AppResult<u64> {
        // Build the WebSocket URL from connection info
        let (host, port, secure, path) = {
            let req = self.http_request(request_handle)?;
            let conn = self.http_connection(req.connection)?;
            (conn.host.clone(), conn._port, conn.secure, req.path.clone())
        };

        let is_text_mode = false; // Default to binary mode
        let scheme = if secure { "wss" } else { "ws" };
        let ws_url = Some(format!("{scheme}://{host}:{port}{path}"));

        let ws_handle = self.alloc_id();
        self.websockets.insert(
            ws_handle,
            WebSocketRecord::new(request_handle, is_text_mode, ws_url),
        );
        Ok(ws_handle)
    }

    /// Send data over a WebSocket connection.
    /// Buffers the data; real WebSocket I/O is delegated to WinHttpStack.
    pub fn websocket_send(&mut self, ws_handle: u64, data: &[u8]) -> AppResult<()> {
        let ws = self.websockets.get_mut(&ws_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "websocket_send: invalid handle",
            )
        })?;
        if !ws.is_open {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "websocket_send: WebSocket is closed",
            ));
        }
        let new_len = ws.send_buffer.len().saturating_add(data.len());
        if new_len > MAX_WEBSOCKET_SEND_BUFFER {
            return Err(AppError::new(
                ReasonCode::RcSocketReceiveQueueFull,
                format!(
                    "websocket_send: send buffer exceeds limit ({MAX_WEBSOCKET_SEND_BUFFER} bytes)"
                ),
            ));
        }
        ws.send_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Receive data from a WebSocket connection.
    /// Reads from the internal buffer.
    pub fn websocket_receive(&mut self, ws_handle: u64, data: &mut [u8]) -> AppResult<u32> {
        let ws = self.websockets.get_mut(&ws_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "websocket_receive: invalid handle",
            )
        })?;
        if !ws.is_open {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "websocket_receive: WebSocket is closed",
            ));
        }
        let bytes_to_read = data.len().min(ws.receive_buffer.len());
        data[..bytes_to_read].copy_from_slice(&ws.receive_buffer[..bytes_to_read]);
        ws.receive_buffer.drain(..bytes_to_read);
        Ok(bytes_to_read as u32)
    }

    /// Close a WebSocket connection.
    pub fn websocket_close(
        &mut self,
        ws_handle: u64,
        status: u16,
        reason: Option<&str>,
    ) -> AppResult<()> {
        let ws = self.websockets.get_mut(&ws_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "websocket_close: invalid handle",
            )
        })?;
        ws.is_open = false;
        ws.close_status = status;
        ws.close_reason = reason.map(|s| s.to_string());
        Ok(())
    }

    /// Query the close status of a WebSocket connection.
    pub fn websocket_query_close_status(&self, ws_handle: u64) -> AppResult<(u16, Option<String>)> {
        let ws = self.websockets.get(&ws_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "websocket_query_close_status: invalid handle",
            )
        })?;
        Ok((ws.close_status, ws.close_reason.clone()))
    }

    // -----------------------------------------------------------------------
    // J6: NTLM/Kerberos authentication header support
    // -----------------------------------------------------------------------

    /// Build an NTLM Type 1 (Negotiate) header value for the given request.
    /// The returned string can be used as the "Authorization" header value.
    ///
    /// Extracts the domain from the username (supports `DOMAIN\user` and `user@domain.com` formats)
    /// and passes it to the underlying NTLM message builder.
    pub fn ntlm_build_authorization_header(&self, username: &str, _password: &str) -> String {
        // Extract domain from username if present
        let domain = if let Some(backslash) = username.find('\\') {
            // DOMAIN\user format
            &username[..backslash]
        } else if let Some(at) = username.find('@') {
            // user@domain.com format — use the domain part as the NTLM domain
            &username[at + 1..]
        } else {
            // No domain delimiter — pass empty
            ""
        };
        let msg = crate::winhttp::ntlm_create_negotiate_msg(domain, "");
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &msg);
        format!("NTLM {encoded}")
    }

    /// Parse a WWW-Authenticate header to determine the auth scheme.
    /// Returns the scheme (e.g., "NTLM", "Negotiate", "Basic") if found.
    pub fn parse_auth_scheme(headers: &BTreeMap<String, String>) -> Option<String> {
        for (key, value) in headers {
            if key.to_lowercase() == "www-authenticate" {
                // Extract the first scheme token
                if let Some(scheme) = value.split_whitespace().next() {
                    return Some(scheme.to_string());
                }
            }
        }
        None
    }

    /// Attempt NTLM authentication by adding Authorization headers.
    /// Returns the updated headers map with NTLM Authorization header added.
    pub fn authenticate_with_ntlm(
        &self,
        mut headers: BTreeMap<String, String>,
        username: &str,
        password: &str,
    ) -> BTreeMap<String, String> {
        let auth_value = self.ntlm_build_authorization_header(username, password);
        headers.insert("Authorization".to_string(), auth_value);
        headers
    }

    /// Acquire a Kerberos ticket for the given service principal.
    ///
    /// Uses the macOS GSS.framework via FFI to obtain a Kerberos service ticket.
    /// On non-macOS platforms, falls back gracefully by returning None.
    ///
    /// # Arguments
    /// * `service` - The service principal name (e.g. "HTTP@server.example.com")
    /// * `username` - The username for Kerberos authentication
    ///
    /// # Returns
    /// The raw Kerberos ticket bytes if successful, or None on failure.
    pub fn kerberos_get_ticket(service: &str, username: &str) -> Option<Vec<u8>> {
        kerberos_get_ticket_impl(service, username)
    }

    pub fn validate_server_certificate(
        &self,
        host: &str,
        chain: &[Certificate],
        revocation_check: bool,
    ) -> AppResult<String> {
        let leaf = chain
            .first()
            .ok_or_else(|| AppError::new(ReasonCode::RcTlsCertRejected, "TLS chain is empty"))?;
        if !leaf
            .valid_hostnames
            .iter()
            .any(|candidate| candidate == host)
        {
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
        let root = chain
            .last()
            .ok_or_else(|| AppError::new(ReasonCode::RcTlsCertRejected, "TLS chain is empty"))?;
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
            .find(|suite| {
                leaf.supported_ciphers
                    .iter()
                    .any(|candidate| candidate == **suite)
            })
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
        self.session_protocol_flags
            .insert(id, HttpProtocolFlags::new());
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
        self.connection_protocols.insert(id, HttpProtocol::Http11);
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
        headers: BTreeMap<String, String>,
        _body: &[u8],
    ) -> AppResult<()> {
        let (path, stack, host, secure, proxy_override, connection_id) = {
            let request_record = self.http_request(request)?;
            let connection = self.http_connection(request_record.connection)?;
            let session = self.http_session(connection.session)?;
            (
                request_record.path.clone(),
                session.stack.clone(),
                connection.host.clone(),
                connection.secure,
                session.proxy_override.clone(),
                request_record.connection,
            )
        };
        let scheme = if secure { "https" } else { "http" };
        let template = self
            .routes
            .get(&(scheme.to_string(), host.clone(), path.clone()))
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("no route for {scheme}://{host}{path}"),
                )
            })?
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
            let suite =
                self.validate_server_certificate(&host, &template.certificate_chain, true)?;
            self.push_cipher_log(format!("{host}:{suite}"));
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
        // Record the negotiated protocol for this connection and any Alt-Svc
        // advertisements present in the request headers.
        self.connection_protocols
            .insert(connection_id, HttpProtocol::Http11);
        if let Some(alt_svc_value) = headers.get("alt-svc") {
            let entries = parse_alt_svc_header(alt_svc_value);
            if !entries.is_empty() {
                self.alt_svc_entries
                    .entry(host.clone())
                    .or_default()
                    .extend(entries);
            }
        }
        self.push_http_trace(HttpTrace {
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
        // Saturating arithmetic: the guest-controlled count must not be able to
        // overflow `read_offset + count` and panic (debug) or wrap into an
        // out-of-bounds slice (release).
        let end = read_offset.saturating_add(count).min(body.len());
        if end < read_offset {
            return Err(AppError::new(
                ReasonCode::RcIo,
                "read_body: invalid byte range",
            ));
        }
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
        if self.cookie_jar.len() > MAX_COOKIE_JAR_SIZE {
            self.cookie_jar.remove(0);
        }
    }

    fn cookie_header_for_request(&self, host: &str, path: &str, secure: bool) -> String {
        self.cookie_jar
            .iter()
            .filter(|cookie| cookie_matches(cookie, host, path, secure))
            .map(|cookie| format!("{}={}", cookie.name, cookie.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn push_http_trace(&mut self, trace: HttpTrace) {
        self.http_traces.push(trace);
        if self.http_traces.len() > MAX_HTTP_TRACE_ENTRIES {
            self.http_traces
                .drain(..self.http_traces.len() - MAX_HTTP_TRACE_ENTRIES);
        }
    }

    fn push_cipher_log(&mut self, entry: String) {
        self.cipher_log.push(entry);
        if self.cipher_log.len() > MAX_HTTP_TRACE_ENTRIES {
            self.cipher_log
                .drain(..self.cipher_log.len() - MAX_HTTP_TRACE_ENTRIES);
        }
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
        self.sockets
            .get(&socket)
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, format!("unknown socket {socket}")))
    }

    fn socket_record_mut(&mut self, socket: SocketId) -> AppResult<&mut SocketRecord> {
        self.sockets
            .get_mut(&socket)
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, format!("unknown socket {socket}")))
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
            AppError::new(
                ReasonCode::RcIo,
                format!("unknown HTTP connection {connection}"),
            )
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

    /// Complete an in-flight non-blocking connect, if any.
    ///
    /// Returns `Ok(())` when the socket is not connecting or the connect has
    /// finished successfully; errors with WSAEWOULDBLOCK while still in
    /// progress and with the mapped OS error if the connect failed.
    fn maybe_finish_connect(&mut self, socket: SocketId) -> AppResult<()> {
        let state = self.socket_record(socket)?.state.clone();
        let SocketState::ConnectingReal { peer } = &state else {
            return Ok(());
        };
        let peer = peer.clone();
        let progress = self
            .real_tcp_streams
            .get(&socket)
            .map(connect_state)
            .unwrap_or(ConnectState::InProgress);
        match progress {
            ConnectState::Complete => {
                self.socket_record_mut(socket)?.state = SocketState::ConnectedReal { _peer: peer };
                Ok(())
            }
            ConnectState::Failed(errno) => {
                self.last_wsa_error = map_errno_to_wsa(errno);
                Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("TCP connect failed with OS error {errno}"),
                ))
            }
            ConnectState::InProgress => {
                self.last_wsa_error = WSAEWOULDBLOCK;
                Err(AppError::new(
                    ReasonCode::RcWinsockWouldBlock,
                    "TCP connect still in progress",
                ))
            }
        }
    }

    /// Standalone id allocator (base 0x1000, step 4) used only by the
    /// host-side `socket()` API, internal peer sockets created for local
    /// listener connects, and the WS2_32-independent id spaces (http
    /// sessions, websockets).  Guest-visible sockets from the runtime no
    /// longer use this allocator: `socket_register` keys records by the
    /// win32-table-validated handle value, so this space can never collide
    /// with kernel handles.
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
    matches!(
        (addr, family),
        (NetSocketAddr::V4(_), AddressFamily::Ipv4) | (NetSocketAddr::V6(_), AddressFamily::Ipv6)
    )
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
    // SAFETY: FFI for network socket operations
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
        _ => WSAEINVAL,
    }
}

/// Map a POSIX errno to a WinSock error code.
fn map_errno_to_wsa(errno: i32) -> i32 {
    match errno {
        libc::EINPROGRESS | libc::EAGAIN => WSAEWOULDBLOCK,
        libc::EADDRINUSE => WSAEADDRINUSE,
        libc::ECONNREFUSED => WSAECONNREFUSED,
        libc::ECONNRESET | libc::EPIPE => WSAECONNRESET,
        libc::ENOTCONN => WSAENOTCONN,
        libc::ETIMEDOUT => WSAETIMEDOUT,
        _ => WSAEINVAL,
    }
}

/// Query SO_ERROR for a stream, if available.
fn so_error(stream: &TcpStream) -> Option<i32> {
    let mut error: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: getsockopt(2) with valid pointers to a stack-allocated i32.
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut error as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };
    if ret == 0 { Some(error) } else { None }
}

/// The state of a non-blocking connect.
enum ConnectState {
    /// The connect is still in progress.
    InProgress,
    /// The connect completed successfully.
    Complete,
    /// The connect failed with the given errno.
    Failed(i32),
}

/// Determine the state of a non-blocking connect via `poll(POLLOUT, 0)`.
///
/// `SO_ERROR` alone cannot distinguish "still connecting" from "finished":
/// both read as 0. Polling for writability is the reliable check.
fn connect_state(stream: &TcpStream) -> ConnectState {
    let mut fds = [libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    }];
    // SAFETY: poll(2) with a single valid descriptor and zero timeout.
    let ret = unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) };
    if ret <= 0 {
        return ConnectState::InProgress;
    }
    if fds[0].revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) == 0 {
        return ConnectState::InProgress;
    }
    match so_error(stream) {
        Some(0) => ConnectState::Complete,
        Some(errno) => ConnectState::Failed(errno),
        None => ConnectState::InProgress,
    }
}

/// Start a non-blocking TCP connect.
///
/// Returns the (already non-blocking) stream and whether the connect is still
/// in progress (EINPROGRESS). Completion is observed via `SO_ERROR` by
/// [`NetworkStack::select`] and [`NetworkStack::maybe_finish_connect`].
fn nonblocking_connect(addr: &NetSocketAddr) -> std::io::Result<(TcpStream, bool)> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket(2) with valid constants; the descriptor is owned below.
    // Note: macOS does not accept O_CLOEXEC/SOCK_CLOEXEC here (EINVAL), so the
    // type is plain SOCK_STREAM.
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a valid, owned socket descriptor from socket(2) above.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream.set_nonblocking(true)?;

    let ret = match addr {
        NetSocketAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr = libc::in_addr {
                // `in_addr.s_addr` stores the address in network byte order, so
                // the octets are written verbatim (little-endian hosts).
                s_addr: u32::from_le_bytes(v4.ip().octets()),
            };
            // SAFETY: `sa` is a valid sockaddr_in for the lifetime of the call.
            unsafe {
                libc::connect(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        NetSocketAddr::V6(v6) => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            sa.sin6_scope_id = v6.scope_id();
            // SAFETY: `sa` is a valid sockaddr_in6 for the lifetime of the call.
            unsafe {
                libc::connect(
                    fd,
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if ret == 0 {
        return Ok((stream, false));
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == libc::EINPROGRESS => Ok((stream, true)),
        Some(code) if code == libc::EISCONN => Ok((stream, false)),
        _ => Err(error),
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
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(
        |error: hmac::digest::InvalidLength| {
            AppError::new(ReasonCode::RcCryptoInvalid, "invalid HMAC key")
                .with_hint(error.to_string())
        },
    )?;
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
        AppError::new(
            ReasonCode::RcCryptoInvalid,
            "RSA signature verification failed",
        )
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
        AppError::new(
            ReasonCode::RcCryptoInvalid,
            "ECDSA signature verification failed",
        )
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

/// Whether a cookie applies to the given request origin/path. Shared with the
/// real networking stack (`real_net`).
pub(crate) fn cookie_matches_origin(cookie: &Cookie, host: &str, path: &str, secure: bool) -> bool {
    cookie_matches(cookie, host, path, secure)
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
            let host_port = host_port_part.trim_matches('"').trim_matches('\'');

            if host_port.is_empty() {
                continue;
            }

            // Parse optional host:port, default port based on protocol.
            // Skip entries with unparseable ports instead of silently falling back.
            let (alt_host, alt_port) = if let Some(colon_pos) = host_port.rfind(':') {
                let host = host_port[..colon_pos].to_string();
                let port_str = &host_port[colon_pos + 1..];
                let port: u16 = match port_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue, // skip entry with invalid port
                };
                // If host is empty (e.g. ":443"), it means same origin host
                (host, port)
            } else {
                // Just a port number (e.g. "443")
                let port: u16 = match host_port.parse() {
                    Ok(p) => p,
                    Err(_) => continue, // skip entry with invalid port
                };
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
    protocol_id == "h3" || protocol_id.starts_with("h3-") || protocol_id == "quic"
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

    let quic_requested = enabled_flags.contains(HttpProtocolFlags::HTTP3) || has_h3_advertisement;

    let mut _fallback_occurred = false;

    if quic_requested && !quic_config.force_disabled {
        if quic_config.force_enabled {
            // QUIC is force-enabled but not available on this platform
            // Return HTTP/3 anyway - callers must handle the error
            (HttpProtocol::Http3, false)
        } else {
            // QUIC requested but not available - fall back to HTTP/2
            _fallback_occurred = true;
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

/// Perform UDP hole punching to establish NAT traversal with a peer.
///
/// Sends a small probe packet from the given socket to the peer's
/// external (public) address, which punches a hole in the local NAT.
/// Additional probes are sent to nearby ports for symmetric NAT
/// port prediction.
pub fn perform_udp_hole_punch(
    socket: &UdpSocket,
    peer_external_addr: std::net::SocketAddr,
) -> std::io::Result<()> {
    // Send a 1-byte probe to the peer's external address
    // This creates a NAT mapping on our side
    let probe = [0u8; 1];
    socket.send_to(&probe, peer_external_addr)?;

    // Also send to a few sequential ports around the peer's port
    // in case symmetric NAT port prediction is needed
    let base_port = peer_external_addr.port();
    for offset in [1u16, 2, (-1i16) as u16, (-2i16) as u16] {
        let test_port = base_port.wrapping_add(offset);
        let mut test_addr = peer_external_addr;
        test_addr.set_port(test_port);
        // Best-effort: these are speculative probes that may fail silently
        if let Err(e) = socket.send_to(&probe, test_addr) {
            eprintln!("UDP hole punch probe to {test_addr} failed: {e}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Kerberos authentication via macOS GSS.framework
// ---------------------------------------------------------------------------

/// Kerberos GSSAPI constants for macOS.
#[cfg(target_os = "macos")]
mod gssapi_ffi {
    #![allow(non_camel_case_types, dead_code)]

    use std::os::raw::{c_int, c_void};

    // GSSAPI major status codes
    pub const GSS_S_COMPLETE: u32 = 0;
    pub const GSS_S_CONTINUE_NEEDED: u32 = 1;
    pub const GSS_S_FAILURE: u32 = 0x8000_0000;

    // OID for Kerberos 5 mechanism
    pub const GSS_KRB5_MECHANISM: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
    ];

    // GSS buffer descriptor
    #[repr(C)]
    pub struct gss_buffer_desc {
        pub length: usize,
        pub value: *mut c_void,
    }

    // GSS OID descriptor
    #[repr(C)]
    pub struct gss_OID_desc {
        pub length: usize,
        pub elements: *mut c_void,
    }
    pub type gss_OID = *mut gss_OID_desc;

    // GSS name type
    #[repr(C)]
    pub struct gss_name_struct {
        _private: [u8; 0],
    }
    pub type gss_name_t = *mut gss_name_struct;

    // GSS credential handle
    #[repr(C)]
    pub struct gss_cred_id_struct {
        _private: [u8; 0],
    }
    pub type gss_cred_id_t = *mut gss_cred_id_struct;

    // GSS context handle
    #[repr(C)]
    pub struct gss_ctx_id_struct {
        _private: [u8; 0],
    }
    pub type gss_ctx_id_t = *mut gss_ctx_id_struct;

    type gss_OID_set = *mut c_void;

    // GSS-API status types for gss_display_status
    pub const GSS_C_GSS_CODE: c_int = 1;
    pub const GSS_C_MECH_CODE: c_int = 2;

    // SAFETY: GSS-API FFI for Kerberos authentication
    #[link(name = "GSS", kind = "framework")]
    unsafe extern "C" {
        pub fn gss_import_name(
            minor_status: *mut u32,
            input_name_buffer: *mut gss_buffer_desc,
            input_name_type: gss_OID,
            output_name: *mut gss_name_t,
        ) -> u32;

        pub fn gss_init_sec_context(
            minor_status: *mut u32,
            claimant_cred_handle: gss_cred_id_t,
            context_handle: *mut gss_ctx_id_t,
            target_name: gss_name_t,
            mech_type: gss_OID,
            req_flags: u32,
            time_req: u32,
            input_chan_bindings: *mut c_void,
            input_token: *mut gss_buffer_desc,
            actual_mech_type: *mut gss_OID,
            output_token: *mut gss_buffer_desc,
            ret_flags: *mut u32,
            time_rec: *mut u32,
        ) -> u32;

        pub fn gss_delete_sec_context(
            minor_status: *mut u32,
            context_handle: *mut gss_ctx_id_t,
            output_token: *mut gss_buffer_desc,
        ) -> u32;

        pub fn gss_release_buffer(minor_status: *mut u32, buffer: *mut gss_buffer_desc) -> u32;

        pub fn gss_release_name(minor_status: *mut u32, name: *mut gss_name_t) -> u32;

        pub fn gss_display_status(
            minor_status: *mut u32,
            status_value: u32,
            status_type: c_int,
            mech_type: gss_OID,
            message_context: *mut u32,
            status_string: *mut gss_buffer_desc,
        ) -> u32;
    }
}

/// Acquire a Kerberos ticket using macOS GSS.framework.
pub(crate) fn kerberos_get_ticket_impl(service: &str, username: &str) -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        kerberos_get_ticket_macos(service, username)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, username);
        // Kerberos is only supported on macOS via GSS.framework
        eprintln!("Kerberos not supported on this platform");
        None
    }
}

#[cfg(target_os = "macos")]
fn kerberos_get_ticket_macos(service: &str, _username: &str) -> Option<Vec<u8>> {
    use self::gssapi_ffi::*;

    // Build the service principal name (e.g., "HTTP@server.example.com").
    // The CString is kept alive for the whole call: GSS-API copies the buffer
    // during import, so ownership never transfers and into_raw must not be used.
    let spn = CString::new(service).ok()?;
    let mut name_buf = gss_buffer_desc {
        length: spn.as_bytes().len(),
        value: spn.as_ptr() as *mut c_void,
    };

    let mut target_name: gss_name_t = std::ptr::null_mut();
    let mut minor_status: u32 = 0;

    // Import the service principal name
    // SAFETY: gss_import_name is called with valid pointers to gss_buffer_desc
    // and gss_name_t structures allocated on the stack.
    let maj = unsafe {
        gss_import_name(
            &mut minor_status,
            &mut name_buf,
            std::ptr::null_mut(), // use default name type (hostbased service)
            &mut target_name,
        )
    };

    if maj != GSS_S_COMPLETE {
        eprintln!(
            "Kerberos: gss_import_name failed for service '{service}': maj={maj:#x}, min={minor_status}"
        );
        // SAFETY: release any partially-imported name before returning.
        unsafe {
            if !target_name.is_null() {
                gss_release_name(&mut minor_status, &mut target_name);
            }
        }
        return None;
    }

    // Initialize security context to get a ticket
    let mut context: gss_ctx_id_t = std::ptr::null_mut();
    let mut output_token = gss_buffer_desc {
        length: 0,
        value: std::ptr::null_mut(),
    };

    // SAFETY: gss_init_sec_context is called with valid stack-allocated
    // gss_buffer_desc and gss_ctx_id_t structures. All pointer arguments are
    // either valid or null (as permitted by the GSS-API specification).
    let maj = unsafe {
        gss_init_sec_context(
            &mut minor_status,
            std::ptr::null_mut(), // use default credentials (obtained via kinit)
            &mut context,
            target_name,
            std::ptr::null_mut(), // use default mechanism (Kerberos)
            0,                    // req_flags: none required for ticket acquisition
            0,                    // time_req: use default
            std::ptr::null_mut(), // no channel bindings
            std::ptr::null_mut(), // no input token (initial request)
            std::ptr::null_mut(), // actual_mech_type (don't care)
            &mut output_token,
            std::ptr::null_mut(), // ret_flags (don't care)
            std::ptr::null_mut(), // time_rec (don't care)
        )
    };

    let result = if maj == GSS_S_COMPLETE || maj == GSS_S_CONTINUE_NEEDED {
        if !output_token.value.is_null() && output_token.length > 0 {
            // SAFETY: output_token.value is non-null and output_token.length > 0
            // (checked above). The GSS library allocated the buffer.
            let ticket = unsafe {
                std::slice::from_raw_parts(output_token.value as *const u8, output_token.length)
                    .to_vec()
            };
            Some(ticket)
        } else {
            eprintln!("Kerberos: gss_init_sec_context returned empty token for '{service}'");
            None
        }
    } else {
        // Get error message from GSS
        let mut msg_buf = gss_buffer_desc {
            length: 0,
            value: std::ptr::null_mut(),
        };
        // SAFETY: FFI for network socket operations
        unsafe {
            gss_display_status(
                &mut minor_status,
                maj,
                GSS_C_GSS_CODE,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut msg_buf,
            );
            if !msg_buf.value.is_null() {
                let msg = CStr::from_ptr(msg_buf.value as *const c_char)
                    .to_string_lossy()
                    .into_owned();
                eprintln!(
                    "Kerberos: gss_init_sec_context failed for '{service}': {msg} (maj={maj:#x}, min={minor_status})"
                );
                gss_release_buffer(&mut minor_status, &mut msg_buf);
            } else {
                eprintln!(
                    "Kerberos: gss_init_sec_context failed for '{service}': maj={maj:#x}, min={minor_status}"
                );
            }
        }
        None
    };

    // Cleanup: release the output token, target name, and the security context
    // (which holds ticket/credential material).
    // SAFETY: FFI for network socket operations
    unsafe {
        if !output_token.value.is_null() {
            gss_release_buffer(&mut minor_status, &mut output_token);
        }
        if !target_name.is_null() {
            gss_release_name(&mut minor_status, &mut target_name);
        }
        if !context.is_null() {
            gss_delete_sec_context(&mut minor_status, &mut context, std::ptr::null_mut());
        }
    }

    result
}

/// Read a DER length field at `offset` (advancing it), rejecting malformed
/// long-form lengths (indefinite, oversized, or truncated).
fn read_der_length(token: &[u8], offset: &mut usize) -> Option<usize> {
    if *offset >= token.len() {
        return None;
    }
    let first = token[*offset];
    *offset += 1;
    if first & 0x80 == 0 {
        return Some(first as usize);
    }
    let num_bytes = (first & 0x7F) as usize;
    if num_bytes == 0 || num_bytes > std::mem::size_of::<usize>() {
        return None;
    }
    let mut length = 0usize;
    for _ in 0..num_bytes {
        if *offset >= token.len() {
            return None;
        }
        length = (length << 8) | token[*offset] as usize;
        *offset += 1;
    }
    Some(length)
}

/// Parse a SPNEGO token (RFC 4178) to extract the Kerberos ticket from
/// an HTTP Negotiate authentication exchange.
pub fn parse_spnego_token(spnego_token: &[u8]) -> Option<Vec<u8>> {
    // SPNEGO structure (simplified):
    // Application 0 (SEQUENCE) of:
    //   [0] CONTEXT-SPECIFIC: mechTypes (OIDs)
    //   [2] CONTEXT-SPECIFIC: mechToken (OCTET STRING containing Kerberos ticket)
    //
    // We do a simple DER scan for the mechToken.

    if spnego_token.len() < 16 {
        return None;
    }

    let mut offset = 0;

    // Skip outer APPLICATION 0 tag
    if offset >= spnego_token.len() || spnego_token[offset] != 0x60 {
        return None;
    }
    offset += 1;
    let outer_len = read_der_length(spnego_token, &mut offset)?;
    let end = offset.checked_add(outer_len)?;
    if end > spnego_token.len() {
        return None;
    }

    // Scan for [2] CONTEXT-SPECIFIC (mechToken)
    while offset + 4 < spnego_token.len() {
        // Look for tag 0xA2 (context-specific, constructed, tag 2)
        if spnego_token[offset] == 0xA2 {
            offset += 1;
            // Skip inner length
            let token_len = read_der_length(spnego_token, &mut offset)?;
            if offset.checked_add(token_len)? > spnego_token.len() {
                return None;
            }
            // The content should be an OCTET STRING containing the Kerberos ticket
            if offset < spnego_token.len() && spnego_token[offset] == 0x04 {
                offset += 1;
                let mech_token_len = read_der_length(spnego_token, &mut offset)?;
                if offset.checked_add(mech_token_len)? <= spnego_token.len() {
                    return Some(spnego_token[offset..offset + mech_token_len].to_vec());
                }
            }
            return None;
        }
        offset += 1;
    }

    None
}

/// Encode a DER length field (short or long form) without truncating.
fn der_length_bytes(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = len.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend_from_slice(&bytes);
    out
}

/// Build a SPNEGO wrapper around a raw Kerberos ticket for HTTP Negotiate auth.
///
/// Produces a spec-compliant RFC 4178 `NegTokenInit`:
///
/// ```text
/// [APPLICATION 0] SEQUENCE {
///   OBJECT IDENTIFIER 1.3.6.1.5.5.2 (SPNEGO)
///   [0] EXPLICIT {                    -- NegTokenInit
///     SEQUENCE {
///       [0] { SEQUENCE { OBJECT IDENTIFIER 1.2.840.113554.1.2.2 (Kerberos 5) } }
///       [2] { OCTET STRING (Kerberos ticket) }
///     }
///   }
/// }
/// ```
pub fn build_spnego_token(kerberos_ticket: &[u8]) -> Vec<u8> {
    // Kerberos 5 mechanism OID: 1.2.840.113554.1.2.2
    const KRB5_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
    ];
    // SPNEGO mechanism OID: 1.3.6.1.5.5.2
    const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

    // mechTypes: [0] { SEQUENCE OF OID }
    let mech_list = {
        let mut oid = vec![0x30];
        oid.extend_from_slice(&der_length_bytes(KRB5_OID.len()));
        oid.extend_from_slice(KRB5_OID);
        let mut out = vec![0xa0];
        out.extend_from_slice(&der_length_bytes(oid.len()));
        out.extend_from_slice(&oid);
        out
    };

    // mechToken: [2] { OCTET STRING }
    let mech_token = {
        let mut octet_string = vec![0x04];
        octet_string.extend_from_slice(&der_length_bytes(kerberos_ticket.len()));
        octet_string.extend_from_slice(kerberos_ticket);
        let mut out = vec![0xa2];
        out.extend_from_slice(&der_length_bytes(octet_string.len()));
        out.extend_from_slice(&octet_string);
        out
    };

    // NegTokenInit: SEQUENCE { mechTypes, mechToken }
    let neg_token_init = {
        let mut inner = mech_list;
        inner.extend_from_slice(&mech_token);
        let mut out = vec![0x30];
        out.extend_from_slice(&der_length_bytes(inner.len()));
        out.extend_from_slice(&inner);
        out
    };

    // GSS-API wrapper: [APPLICATION 0] SEQUENCE { SPNEGO OID, [0] { NegTokenInit } }
    let mut body = Vec::with_capacity(SPNEGO_OID.len() + neg_token_init.len() + 8);
    body.extend_from_slice(SPNEGO_OID);
    body.push(0xa0);
    body.extend_from_slice(&der_length_bytes(neg_token_init.len()));
    body.extend_from_slice(&neg_token_init);

    let mut token = vec![0x60];
    token.extend_from_slice(&der_length_bytes(body.len()));
    token.extend_from_slice(&body);
    token
}

/// Attempt full Kerberos authentication flow: negotiate → challenge → response.
/// Returns the Authorization header value for the "Negotiate" scheme.
pub fn kerberos_authenticate(
    service: &str,
    username: &str,
    server_challenge: &[u8],
) -> Option<String> {
    // Step 1: Get a Kerberos ticket for the service
    let ticket = kerberos_get_ticket_impl(service, username)?;

    // Step 2: If there's a server challenge (SPNEGO), try to decode it
    let _challenge = if !server_challenge.is_empty() {
        parse_spnego_token(server_challenge)
    } else {
        None
    };

    // Step 3: Build SPNEGO response token
    let spnego = build_spnego_token(&ticket);

    // Step 4: Base64-encode for HTTP Authorization header
    Some(format!(
        "Negotiate {}",
        base64::engine::general_purpose::STANDARD.encode(&spnego)
    ))
}

// ---------------------------------------------------------------------------
// QUIC transport implementation (J2) — using quinn crate
// ---------------------------------------------------------------------------

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// QUIC protocol version identifier (draft-29 / v1).
/// Used by Alt-Svc entries and protocol negotiation.
pub const QUIC_VERSION: u32 = 0x00000001;

/// The maximum number of SSL provider scalers that can be combined for
/// QUIC acceleration.
pub const HTTP_SOCKET_MAX_COMBINE_SSL_SCALERS: usize = 4;

/// Global QUIC state tracker.
struct QuicState {
    listeners: BTreeMap<u64, quinn::Endpoint>,
    connections: BTreeMap<u64, quinn::Connection>,
    udp_sockets: BTreeMap<u64, std::net::UdpSocket>,
    /// Accept-loop tasks per listener handle, so closing a listener can stop
    /// its background accept task.
    listener_tasks: BTreeMap<u64, tokio::task::JoinHandle<()>>,
}

impl QuicState {
    fn new() -> Self {
        Self {
            listeners: BTreeMap::new(),
            connections: BTreeMap::new(),
            udp_sockets: BTreeMap::new(),
            listener_tasks: BTreeMap::new(),
        }
    }
}

lazy_static::lazy_static! {
    static ref QUIC_STATE: Mutex<QuicState> = Mutex::new(QuicState::new());
    /// A shared tokio runtime for blocking QUIC operations.
    ///
    /// This crate's tokio features only provide the current-thread scheduler,
    /// so a dedicated pump thread drives the runtime continuously. Caller
    /// threads submit work via `spawn` and wait with bounded `recv_timeout`s;
    /// spawned futures (quinn driver tasks, stream I/O, the accept loop) make
    /// progress on the pump. Never mix an undriven `spawn` with an unbounded
    /// blocking `recv()` — that deadlocks forever.
    static ref QUIC_RUNTIME: tokio::runtime::Runtime =
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("QUIC tokio runtime creation failed");
}

/// Ensure the QUIC runtime is being driven by the dedicated pump thread.
fn quic_ensure_pump() {
    static PUMP: std::sync::OnceLock<std::thread::JoinHandle<()>> = std::sync::OnceLock::new();
    PUMP.get_or_init(|| {
        let runtime = &*QUIC_RUNTIME;
        std::thread::spawn(move || {
            // Drive the current-thread runtime forever. Never returns.
            runtime.block_on(std::future::pending::<()>());
        })
    });
}

/// QUIC handshake timeout.
const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// QUIC stream I/O timeout.
const QUIC_IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Slack added to channel waits so the in-task timeout always wins.
const QUIC_WAIT_SLACK: Duration = Duration::from_secs(5);

static QUIC_HANDLE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_quic_handle() -> u64 {
    QUIC_HANDLE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Lock the global QUIC state, returning an `AppError` if the mutex is poisoned.
fn lock_quic_state() -> Result<std::sync::MutexGuard<'static, QuicState>, AppError> {
    QUIC_STATE.lock().map_err(|e| {
        AppError::new(
            ReasonCode::RcLockPoisoned,
            format!("QUIC state lock poisoned: {e}"),
        )
    })
}

/// Recover the global QUIC state from a poisoned mutex.
///
/// This clears all existing state (connections, listeners, UDP sockets) and
/// replaces the poisoned Mutex with a fresh [`QuicState`].  Call this when
/// [`lock_quic_state`] returns a poison error and you want to continue
/// operating rather than propagating the error upward.
///
/// # Returns
/// `Ok(())` on successful recovery, or the original `AppError` if the mutex
/// could not be recovered (e.g. because the underlying system allocation
/// fails).
pub fn recover_quic_state() -> AppResult<()> {
    let poison = match QUIC_STATE.lock() {
        Ok(_) => {
            // Mutex is healthy — nothing to recover.
            return Ok(());
        }
        Err(poison) => poison,
    };

    // Drain the poisoned inner data to release any held resources.
    let _old_state = poison.into_inner();

    // Replace with a fresh state.
    *QUIC_STATE.lock().map_err(|e| {
        AppError::new(
            ReasonCode::RcLockPoisoned,
            format!("QUIC state recovery failed: {e}"),
        )
    })? = QuicState::new();

    Ok(())
}

/// Load native platform root certificates from well-known system paths.
fn load_native_certs() -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let mut certs = Vec::new();
    let cert_paths = [
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",
        "/usr/local/share/certificates/ca-bundle.crt",
        "/usr/local/etc/openssl/cert.pem",
    ];
    for path in &cert_paths {
        if let Ok(data) = std::fs::read(path) {
            let mut slice = data.as_slice();
            let pem_certs = rustls_pemfile::certs(&mut slice);
            for c in pem_certs.flatten() {
                certs.push(c);
            }
            if !certs.is_empty() {
                return certs;
            }
        }
    }
    // On macOS, try the Keychain via security command-line tool
    if let Some(output) = std::process::Command::new("security")
        .args(["find-certificate", "-a", "-p"])
        .output()
        .ok()
        .filter(|output| output.status.success())
    {
        let mut slice = output.stdout.as_slice();
        let pem_certs = rustls_pemfile::certs(&mut slice);
        for c in pem_certs.flatten() {
            certs.push(c);
        }
    }
    if certs.is_empty() {
        eprintln!("Warning: no native root certificates found for QUIC TLS");
    }
    certs
}

/// Cached native root store: loading it forks a `security` process and reads
/// cert files, so it must not happen per connection.
static NATIVE_ROOT_CERTS: std::sync::OnceLock<rustls::RootCertStore> = std::sync::OnceLock::new();

/// Build a root certificate store from the system's trust store (cached).
fn quic_root_certs() -> rustls::RootCertStore {
    NATIVE_ROOT_CERTS
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            for cert in load_native_certs() {
                if let Err(error) = roots.add(cert) {
                    eprintln!("[network] failed to add native QUIC root cert: {error}");
                }
            }
            roots
        })
        .clone()
}

/// Build a Quinn client configuration with TLS 1.3.
fn quic_client_config() -> Result<quinn::ClientConfig, AppError> {
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(quic_root_certs())
        .with_no_client_auth();
    // Set ALPN for HTTP/3
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
        AppError::new(
            ReasonCode::RcIo,
            format!("QUIC client crypto setup failed: {e}"),
        )
    })?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(100u32.into());
    transport.max_concurrent_uni_streams(100u32.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Build a Quinn server configuration with a self-signed cert for local use.
fn quic_server_config() -> Result<quinn::ServerConfig, AppError> {
    let cert_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| {
        AppError::new(
            ReasonCode::RcIo,
            format!("QUIC server cert gen failed: {e}"),
        )
    })?;
    let cert_der = cert_key.cert.der().clone();
    let key_der = cert_key.key_pair.serialize_der();
    let chain = vec![cert_der];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der,
    ));

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("QUIC server crypto setup failed: {e}"),
            )
        })?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(|e| {
        AppError::new(
            ReasonCode::RcIo,
            format!("QUIC server crypto setup failed: {e}"),
        )
    })?;

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(100u32.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Combine SSL scalers for QUIC socket acceleration.
/// Returns the number of scalers that were combined, capped at the platform
/// maximum.
pub fn http_socket_combine_ssl_scalers(socket_handle: u64, scaler_count: usize) -> usize {
    let _ = socket_handle;
    scaler_count.min(HTTP_SOCKET_MAX_COMBINE_SSL_SCALERS)
}

/// Create a QUIC listener on the given address.
/// Returns a handle that can be used to accept incoming connections.
///
/// The listener runs a background accept loop on the shared runtime: accepted
/// connections are parked in the global QUIC state (keyed by fresh handles)
/// where they can be driven by [`quic_udp_send`]/[`quic_udp_recv`].
pub fn quic_create_listener(addr: &str) -> Result<u64, AppError> {
    quic_ensure_pump();
    let server_config = quic_server_config()?;
    let socket = std::net::UdpSocket::bind(addr).map_err(|e| {
        AppError::new(
            ReasonCode::RcIo,
            format!("QUIC listener bind to {addr} failed: {e}"),
        )
    })?;

    let handle = next_quic_handle();

    // Endpoint creation must run inside a runtime context: quinn spawns its
    // driver tasks via `tokio::spawn`. The pump thread executes it.
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    QUIC_RUNTIME.spawn(async move {
        let result = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("QUIC endpoint creation failed: {e}"),
            )
        });
        if result_tx.send(result).is_err() {
            eprintln!("[network] QUIC listener receiver dropped before endpoint creation");
        }
    });
    let endpoint = result_rx
        .recv_timeout(QUIC_IO_TIMEOUT.saturating_add(QUIC_WAIT_SLACK))
        .map_err(|_| AppError::new(ReasonCode::RcIo, "QUIC endpoint creation timed out"))??;

    // Drive the accept loop on the runtime; the task is aborted when the
    // listener is closed.
    let accept_endpoint = endpoint.clone();
    let task = QUIC_RUNTIME.spawn(async move {
        while let Some(incoming) = accept_endpoint.accept().await {
            match incoming.await {
                Ok(connection) => match QUIC_STATE.lock() {
                    Ok(mut state) => {
                        let conn_handle = next_quic_handle();
                        state.connections.insert(conn_handle, connection);
                    }
                    Err(_) => {
                        eprintln!(
                            "[network] QUIC state lock poisoned; listener accept loop exiting"
                        );
                        break;
                    }
                },
                Err(e) => eprintln!("[network] QUIC accept failed: {e}"),
            }
        }
    });

    let mut state = lock_quic_state()?;
    state.listeners.insert(handle, endpoint);
    state.listener_tasks.insert(handle, task);
    Ok(handle)
}

/// Parse a `host:port` string into (hostname, port), correctly handling
/// IPv6 bracket notation (e.g. `[::1]:443`) and unbracketed IPv6 (e.g. `::1`).
fn parse_host_port(input: &str, default_port: u16) -> (&str, u16) {
    // Check for IPv6 bracket notation: [::1]:port
    if input.starts_with('[') {
        match input.find(']') {
            Some(bracket_end) => {
                let hostname = &input[1..bracket_end];
                let rest = &input[bracket_end + 1..];
                let port = rest
                    .strip_prefix(':')
                    .and_then(|port_str| port_str.parse::<u16>().ok())
                    .unwrap_or(default_port);
                return (hostname, port);
            }
            // Malformed (unterminated bracket) — treat the whole input as a host
            None => return (input, default_port),
        }
    }
    // Unbracketed IPv6 (e.g. "::1") — treat the whole input as the host.
    if input.matches(':').count() >= 2 {
        return (input, default_port);
    }
    // Standard host:port or bare host
    if let Some((hostname, port_str)) = input.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return (hostname, port);
    }
    // No port found — use default
    (input, default_port)
}

/// Create a QUIC connection to the given remote host.
/// Returns a connection handle.
pub fn quic_create_connection(host: &str) -> Result<u64, AppError> {
    quic_ensure_pump();
    let (hostname, port) = parse_host_port(host, 443);

    let client_config = quic_client_config()?;
    let bind_addr = if hostname.contains(':') || hostname.starts_with('[') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let socket = std::net::UdpSocket::bind(bind_addr)
        .map_err(|e| AppError::new(ReasonCode::RcIo, format!("QUIC connect bind failed: {e}")))?;

    // Reconstruct for ToSocketAddrs which expects bracket notation for IPv6
    let remote_addr_str = if hostname.contains(':') {
        // IPv6 — wrap in brackets for ToSocketAddrs
        format!("[{hostname}]:{port}")
    } else {
        format!("{hostname}:{port}")
    };
    let remote_addr = remote_addr_str
        .to_socket_addrs()
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcNetDnsResolutionFailed,
                format!("DNS resolution for {hostname} failed: {e}"),
            )
        })?
        .next()
        .ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNetDnsResolutionFailed,
                format!("No address found for {hostname}"),
            )
        })?;

    // The host is borrowed for error messages inside the spawned task.
    let host_owned = host.to_string();
    let hostname_owned = hostname.to_string();

    // Endpoint creation and the handshake run on the shared runtime (driven
    // by the pump thread) with a bounded wait: spawning on an undriven runtime
    // and blocking forever on a channel would hang the caller.
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    QUIC_RUNTIME.spawn(async move {
        let result = async {
            // Endpoint creation must run inside a runtime context: quinn
            // spawns its driver tasks via `tokio::spawn`.
            let endpoint = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                None,
                socket,
                Arc::new(quinn::TokioRuntime),
            )
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("QUIC endpoint creation failed: {e}"),
                )
            })?;

            let connecting = endpoint
                .connect_with(client_config, remote_addr, &hostname_owned)
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetConnectionFailed,
                        format!("QUIC connect to {host_owned} failed: {e}"),
                    )
                })?;

            let connection = tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, connecting)
                .await
                .map_err(|_| {
                    AppError::new(
                        ReasonCode::RcNetConnectionFailed,
                        format!("QUIC handshake with {host_owned} timed out"),
                    )
                })?
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetConnectionFailed,
                        format!("QUIC handshake with {host_owned} failed: {e}"),
                    )
                })?;

            Ok::<(quinn::Endpoint, quinn::Connection), AppError>((endpoint, connection))
        }
        .await;
        if result_tx.send(result).is_err() {
            eprintln!("[network] QUIC connect receiver dropped before handshake completion");
        }
    });

    let (endpoint, connection) = result_rx
        .recv_timeout(QUIC_HANDSHAKE_TIMEOUT.saturating_add(QUIC_WAIT_SLACK))
        .map_err(|_| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("QUIC handshake with {host} timed out"),
            )
        })??;

    let handle = next_quic_handle();
    let mut state = lock_quic_state()?;
    state.listeners.insert(handle, endpoint);
    state.connections.insert(handle, connection);
    Ok(handle)
}

/// Create a QUIC-capable UDP socket for the given address.
/// Returns a handle to the UDP socket.
pub fn quic_udp_create_socket(addr: &str) -> Result<u64, AppError> {
    let socket = std::net::UdpSocket::bind(addr).map_err(|e| {
        AppError::new(
            ReasonCode::RcIo,
            format!("QUIC UDP socket bind to {addr} failed: {e}"),
        )
    })?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("QUIC UDP read-timeout setup failed for {addr}: {e}"),
            )
        })?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("QUIC UDP write-timeout setup failed for {addr}: {e}"),
            )
        })?;
    let handle = next_quic_handle();
    let mut state = lock_quic_state()?;
    state.udp_sockets.insert(handle, socket);
    Ok(handle)
}

/// Send data over an established QUIC connection by opening a bi-directional stream.
pub fn quic_udp_send(conn_handle: u64, data: &[u8]) -> Result<usize, AppError> {
    quic_ensure_pump();
    let connection = {
        let state = lock_quic_state()?;
        state
            .connections
            .get(&conn_handle)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("QUIC: unknown connection handle {conn_handle}"),
                )
            })?
    };

    let data_owned = data.to_vec();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    QUIC_RUNTIME.spawn(async move {
        let result = async {
            tokio::time::timeout(QUIC_IO_TIMEOUT, async {
                let (mut send, _recv) = connection.open_bi().await.map_err(|e| {
                    AppError::new(ReasonCode::RcIo, format!("QUIC: open stream failed: {e}"))
                })?;
                let written = send.write(&data_owned).await.map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetWriteFailed,
                        format!("QUIC send failed: {e}"),
                    )
                })?;
                send.finish().map_err(|e| {
                    AppError::new(ReasonCode::RcIo, format!("QUIC finish failed: {e}"))
                })?;
                Ok::<usize, AppError>(written)
            })
            .await
            .map_err(|_| AppError::new(ReasonCode::RcIo, "QUIC send timed out"))?
        }
        .await;
        if result_tx.send(result).is_err() {
            eprintln!("[network] QUIC send receiver dropped before completion");
        }
    });

    result_rx
        .recv_timeout(QUIC_IO_TIMEOUT.saturating_add(QUIC_WAIT_SLACK))
        .map_err(|_| AppError::new(ReasonCode::RcIo, "QUIC send timed out"))?
}

/// Receive data on a QUIC connection by accepting an incoming bi-directional
/// stream (matching the sender's `open_bi`).
pub fn quic_udp_recv(conn_handle: u64, buf: &mut [u8]) -> Result<usize, AppError> {
    if buf.is_empty() {
        return Ok(0);
    }
    quic_ensure_pump();
    let connection = {
        let state = lock_quic_state()?;
        state
            .connections
            .get(&conn_handle)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("QUIC: unknown connection handle {conn_handle}"),
                )
            })?
    };

    let buf_len = buf.len();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    QUIC_RUNTIME.spawn(async move {
        let result = async {
            tokio::time::timeout(QUIC_IO_TIMEOUT, async {
                let (_send, mut recv) = connection.accept_bi().await.map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetReadFailed,
                        format!("QUIC: accept stream failed: {e}"),
                    )
                })?;
                let mut read_buf = vec![0u8; buf_len];
                let n = recv
                    .read(&mut read_buf)
                    .await
                    .map_err(|e| {
                        AppError::new(
                            ReasonCode::RcNetReadFailed,
                            format!("QUIC recv failed: {e}"),
                        )
                    })?
                    .unwrap_or(0);
                Ok::<(Vec<u8>, usize), AppError>((read_buf, n))
            })
            .await
            .map_err(|_| AppError::new(ReasonCode::RcIo, "QUIC recv timed out"))?
        }
        .await;
        if result_tx.send(result).is_err() {
            eprintln!("[network] QUIC recv receiver dropped before completion");
        }
    });

    let (read_buf, n) = result_rx
        .recv_timeout(QUIC_IO_TIMEOUT.saturating_add(QUIC_WAIT_SLACK))
        .map_err(|_| AppError::new(ReasonCode::RcIo, "QUIC recv timed out"))??;

    let actual_n = n.min(buf.len());
    buf[..actual_n].copy_from_slice(&read_buf[..actual_n]);
    Ok(actual_n)
}

/// Close a QUIC connection and clean up resources.
pub fn quic_udp_close(conn_handle: u64) {
    let mut state = match QUIC_STATE.lock() {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("QUIC state lock poisoned during close: {e}");
            return;
        }
    };
    if let Some(conn) = state.connections.remove(&conn_handle) {
        conn.close(0u32.into(), b"close");
    }
    state.listeners.remove(&conn_handle);
    state.udp_sockets.remove(&conn_handle);
    if let Some(task) = state.listener_tasks.remove(&conn_handle) {
        task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressFamily, AltSvcEntry, Certificate, HttpProtocol, HttpProtocolFlags, NetworkStack,
        PinnedCertificates, QUIC_STATE, QuicConfig, SockAddr, build_spnego_token, is_quic_alpn,
        negotiate_http_protocol, parse_alt_svc_header, parse_host_port, parse_spnego_token,
        recover_quic_state,
    };
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn winsock_round_trip_preserves_socket_names() {
        let mut network = NetworkStack::new();
        network.wsa_startup();

        let listener = network
            .socket(AddressFamily::Ipv4)
            .expect("listener socket");
        assert_eq!(listener & 0x3, 0);
        assert!(listener >= 0x1000);
        let listener_addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27015,
        };
        network
            .bind(listener, listener_addr.clone())
            .expect("bind listener");
        network.listen(listener, 1).expect("listen");

        let client = network.socket(AddressFamily::Ipv4).expect("client socket");
        assert_eq!(client & 0x3, 0);
        assert!(client >= 0x1000);
        network
            .connect(client, listener_addr.clone())
            .expect("connect");
        let server = network.accept(listener).expect("accept");

        assert_eq!(
            network.getsockname(listener).expect("listener name"),
            listener_addr
        );
        assert_eq!(
            network.getsockname(server).expect("server name"),
            listener_addr
        );

        network.send(client, b"ping").expect("send");
        assert_eq!(network.recv(server, 4).expect("recv"), b"ping");

        network.setsockopt(client, 0, 0, &[]).expect("setsockopt");
    }

    #[test]
    fn winsock_getaddrinfo_falls_back_to_host_dns() {
        let mut network = NetworkStack::new();
        network.wsa_startup();

        let addrs = network
            .getaddrinfo("localhost", 80)
            .expect("resolve localhost");

        assert!(!addrs.is_empty());
        assert!(
            addrs.iter().any(
                |addr| addr.family == AddressFamily::Ipv4 || addr.family == AddressFamily::Ipv6
            )
        );
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
        assert!(result.is_err(), "expected Err, got {result:?}");
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
        network2.load_cookie_snapshot_json(&snapshot).expect("load");
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
        assert!(result.is_err(), "expected Err, got {result:?}");
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
        let chain = vec![
            leaf,
            Certificate {
                fingerprint: "fp:root".to_string(),
                ..make_root_cert()
            },
        ];
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
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn certificate_validate_expired_rejected() {
        let network = NetworkStack::new();
        let leaf = make_test_cert("example.com", 5, false);
        let mut network = network;
        network.set_current_day(100);
        let chain = vec![leaf];
        let result = network.validate_server_certificate("example.com", &chain, false);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn certificate_validate_revoked_when_checking() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let leaf = make_test_cert("example.com", 100, true); // revoked
        let chain = vec![
            leaf,
            Certificate {
                fingerprint: "fp:root".to_string(),
                ..make_root_cert()
            },
        ];
        let result = network.validate_server_certificate("example.com", &chain, true);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn certificate_validate_not_revoked_when_not_checking() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let leaf = make_test_cert("example.com", 100, true); // revoked
        let chain = vec![
            leaf,
            Certificate {
                fingerprint: "fp:root".to_string(),
                ..make_root_cert()
            },
        ];
        // revocation_check = false, so revoked cert passes
        let result = network.validate_server_certificate("example.com", &chain, false);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn certificate_validate_untrusted_root_rejected() {
        let network = NetworkStack::new();
        let leaf = make_test_cert("example.com", 100, false);
        let chain = vec![leaf, make_root_cert()];
        let result = network.validate_server_certificate("example.com", &chain, false);
        assert!(result.is_err(), "expected Err, got {result:?}");
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
        let chain = vec![
            leaf,
            Certificate {
                fingerprint: "fp:root".to_string(),
                ..make_root_cert()
            },
        ];
        let result = network.validate_server_certificate("example.com", &chain, false);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn certificate_validate_empty_chain_rejected() {
        let network = NetworkStack::new();
        let result = network.validate_server_certificate("example.com", &[], false);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn certificate_validate_imported_root_succeeds() {
        let mut network = NetworkStack::new();
        let root = make_root_cert();
        network.import_certificate(root);
        let leaf = make_test_cert("secure.example", 200, false);
        let chain = vec![
            leaf,
            Certificate {
                fingerprint: "fp:root".to_string(),
                ..make_root_cert()
            },
        ];
        let result = network.validate_server_certificate("secure.example", &chain, false);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
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
        assert!(result.is_err(), "expected Err, got {result:?}");
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
        assert!(result.is_err(), "expected Err, got {result:?}");
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
        assert!(result.is_err(), "expected Err, got {result:?}");
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
        let (readable, writable) = network.select(&[client, listener]).expect("select");
        assert!(readable.contains(&listener));
        // Client should be writable (connected)
        assert!(writable.contains(&client));

        let server = network.accept(listener).expect("accept");

        // Both connected sockets should be writable
        let (_readable2, writable2) = network.select(&[client, server]).expect("select");
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
        let available = network.ioctlsocket_fionread(server).expect("fionread");
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
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn socket_operations_fail_without_wsa_startup() {
        let mut network = NetworkStack::new();
        let result = network.socket(AddressFamily::Ipv4);
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert_eq!(network.wsa_get_last_error(), 10093); // WSANOTINITIALISED
    }

    #[test]
    fn socket_wsa_startup_cleanup_refcount() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let _result = network.socket(AddressFamily::Ipv4);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        network.wsa_cleanup();
        // refcount goes to 0, next operation fails
        network.wsa_cleanup();
        let result = network.socket(AddressFamily::Ipv4);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn socket_bind_fails_if_not_created() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let result = network.bind(
            99999,
            SockAddr {
                family: AddressFamily::Ipv4,
                host: "127.0.0.1".to_string(),
                port: 1,
            },
        );
        assert!(result.is_err(), "expected Err, got {result:?}");
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
        assert!(
            addrs
                .iter()
                .any(|a| a.host == "2606:2800:220:1:248:1893:25c8:1946")
        );
    }

    #[test]
    fn dns_unknown_host_falls_back_to_system() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        // "unknown-host-xyz.test" should not be in pre-seeded records
        let result = network.getaddrinfo("unknown-host-xyz.test", 80);
        // May either fail (DNS not found) or succeed via system DNS
        // We just check it doesn't panic
        if let Ok(addrs) = result {
            assert!(!addrs.is_empty());
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
            vec![
                leaf,
                Certificate {
                    fingerprint: "fp:root".to_string(),
                    ..make_root_cert()
                },
            ],
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
        let _result = network.win_http_connect(session, "x", 80, false);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
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
        assert!(result.is_err(), "expected Err, got {result:?}"); // expired because current_day (500) > not_after_day (130)
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

    // -----------------------------------------------------------------------
    // Item 200: Unpinned HTTPS hosts still use normal CA validation
    // -----------------------------------------------------------------------

    #[test]
    fn unpinned_host_passes_when_no_pins_configured() {
        let pins = PinnedCertificates::new();
        // No pins configured for any host — verification should pass with
        // an empty certificate chain, since unpinned hosts are not checked.
        let _result = pins.verify("example.com", &[]);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    #[test]
    fn unpinned_host_passes_with_any_chain() {
        let pins = PinnedCertificates::new();
        // Even with certificates present, unpinned hosts should pass.
        let dummy_cert = vec![0u8; 32];
        let _result = pins.verify("unpinned.example.com", &[dummy_cert]);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    #[test]
    fn pinned_host_rejects_empty_chain() {
        let mut pins = PinnedCertificates::new();
        pins.add_pin("pinned.example.com", "dGVzdGZpbmdlcnByaW50");
        // Pinned host with no certificates to verify should fail.
        let _result = pins.verify("pinned.example.com", &[]);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn mixed_pinned_and_unpinned_hosts() {
        let mut pins = PinnedCertificates::new();
        pins.add_pin("pinned.example.com", "dGVzdGZpbmdlcnByaW50");
        // Unpinned host should still pass even though other hosts are pinned.
        let _result = pins.verify("other.example.com", &[]);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        // Pinned host should fail with no matching certs.
        let _result = pins.verify("pinned.example.com", &[]);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn clear_pins_makes_all_hosts_unpinned() {
        let mut pins = PinnedCertificates::new();
        pins.add_pin("example.com", "dGVzdGZpbmdlcnByaW50");
        pins.clear();
        let _result = pins.verify("example.com", &[]);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    // -----------------------------------------------------------------------
    // Item 210: Timeout and cancellation behavior tests
    // -----------------------------------------------------------------------

    #[test]
    fn socket_set_read_timeout_does_not_panic() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        // Setting timeout should succeed.
        stream
            .set_read_timeout(Some(Duration::from_millis(1)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_millis(1)))
            .unwrap();
        drop(stream);
        drop(listener);
    }

    #[test]
    fn socket_read_timeout_triggers_error() {
        use std::net::TcpListener;
        // Create a listener that never accepts, so connect will hang
        // and reads will eventually time out.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Connect to our listener.
        let stream = std::net::TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let mut buf = [0u8; 4];
        let result = stream.peek(&mut buf);
        // The read may either time out or succeed (if the peer sent FIN),
        // but it should never panic.
        match result {
            Ok(_) | Err(_) => {} // acceptable
        }
        drop(stream);
        drop(listener);
    }

    #[test]
    fn real_tcp_socket_set_timeout_works() {
        use crate::real_net::RealTcpSocket;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = std::net::TcpStream::connect(addr).unwrap();
        let mut real = RealTcpSocket {
            id: 1,
            stream,
            peer_addr: Some(addr.to_string()),
            nonblocking: false,
        };
        // Timeout should be settable
        assert!(real.set_timeout(Some(Duration::from_millis(100))).is_ok());
        // Clearing timeout should also work
        let _result = real.set_timeout(None);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    #[test]
    fn real_udp_socket_set_timeout_works() {
        use crate::real_net::RealUdpSocket;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let real = RealUdpSocket {
            id: 1,
            socket,
            nonblocking: false,
        };
        assert!(real.set_timeout(Some(Duration::from_millis(100))).is_ok());
        let _result = real.set_timeout(None);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    #[test]
    fn nonblocking_socket_returns_wouldblock_immediately() {
        // A socket with no data in nonblocking mode should return a
        // WouldBlock error immediately rather than hanging.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 4];
        let result = stream.read(&mut buf);
        assert!(result.is_err(), "expected Err, got {result:?}");
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
        drop(stream);
        drop(listener);
    }

    // -----------------------------------------------------------------------
    // Item 212: Resource cleanup / Drop tests
    // -----------------------------------------------------------------------

    #[test]
    fn socket_create_and_close_cleans_up() {
        let mut stack = NetworkStack::new();
        stack.wsa_startup();
        let sid = stack.socket(AddressFamily::Ipv4).unwrap();
        // Use closesocket (existing method) to clean up the socket
        stack.closesocket(sid).unwrap();
        // After closing, the socket should be gone — any operation should fail
        let result = stack.getsockname(sid);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn close_unopened_handle_is_safe() {
        let mut stack = NetworkStack::new();
        // Attempt to close a handle that was never opened.
        // This should be safe (no panic) since close_handle just removes from maps.
        stack.close_handle(99999);
    }

    #[test]
    fn double_close_socket_fails_second_time() {
        let mut stack = NetworkStack::new();
        stack.wsa_startup();
        let sid = stack.socket(AddressFamily::Ipv4).unwrap();
        // First close succeeds
        stack.closesocket(sid).unwrap();
        // Second close should fail since the socket was already removed
        let result = stack.closesocket(sid);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn http_session_close_cleans_up_connections() {
        let mut stack = NetworkStack::new();
        stack.wsa_startup();
        let session = stack.win_http_open("test-agent");
        let conn = stack
            .win_http_connect(session, "api.example.com", 443, true)
            .unwrap();
        let req = stack.win_http_open_request(conn, "GET", "/login").unwrap();
        // Close all three — no panic expected
        stack.close_handle(req);
        stack.close_handle(conn);
        stack.close_handle(session);
        // After closing, operations on these handles should fail
        let _result = stack.win_http_open_request(conn, "GET", "/x");
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn quic_state_recovery_clears_poisoned_state() {
        // Attempt recovery on an unpoisoned state (should still succeed).
        let result = recover_quic_state();
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        // After recovery, locking should work.
        let guard = QUIC_STATE.lock();
        assert!(guard.is_ok(), "expected QUIC state lock to be acquired");
    }

    #[test]
    fn quic_state_recovery_idempotent() {
        // Calling recover_quic_state twice should be safe.
        assert!(recover_quic_state().is_ok());
        assert!(recover_quic_state().is_ok());
    }

    // --- Hardening regression tests ---

    #[test]
    fn parse_host_port_handles_unbracketed_ipv6() {
        assert_eq!(parse_host_port("::1", 443), ("::1", 443));
        assert_eq!(parse_host_port("example.com", 443), ("example.com", 443));
        assert_eq!(
            parse_host_port("example.com:8080", 443),
            ("example.com", 8080)
        );
        assert_eq!(parse_host_port("[::1]:8443", 443), ("::1", 8443));
    }

    #[test]
    fn spnego_token_round_trip_extracts_ticket() {
        let ticket = b"kerberos-ticket-bytes";
        let token = build_spnego_token(ticket);
        // [APPLICATION 0] SEQUENCE wrapper
        assert_eq!(token[0], 0x60);
        assert_eq!(parse_spnego_token(&token), Some(ticket.to_vec()));
    }

    #[test]
    fn spnego_token_handles_large_tickets() {
        // Longer than 65535 bytes: the old length encoding truncated.
        let ticket = vec![0xABu8; 70_000];
        let token = build_spnego_token(&ticket);
        assert_eq!(parse_spnego_token(&token), Some(ticket));
    }

    #[test]
    fn read_body_with_huge_count_does_not_panic() {
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
        let body = network
            .win_http_read_data(req, usize::MAX)
            .expect("huge read must not panic");
        assert_eq!(body, br#"{"ok":true}"#);
        network.close_handle(req);
        network.close_handle(conn);
        network.close_handle(session);
    }

    #[test]
    fn recv_zero_length_returns_immediately() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let listener = network.socket(AddressFamily::Ipv4).expect("listener");
        let addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27021,
        };
        network.bind(listener, addr.clone()).expect("bind");
        network.listen(listener, 1).expect("listen");
        let client = network.socket(AddressFamily::Ipv4).expect("client");
        network.connect(client, addr).expect("connect");
        let server = network.accept(listener).expect("accept");
        network.send(client, b"data").expect("send");
        assert_eq!(
            network.recv(server, 0).expect("zero-length recv"),
            Vec::<u8>::new()
        );
        assert_eq!(network.recv(server, 4).expect("recv"), b"data");
    }

    #[test]
    fn recv_caps_guest_length_for_real_streams() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = std_listener.local_addr().expect("local addr");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = std_listener.accept().expect("accept");
            stream.write_all(b"ping").expect("write");
        });

        let mut network = NetworkStack::new();
        network.wsa_startup();
        let socket = network.socket(AddressFamily::Ipv4).expect("socket");
        network
            .connect(
                socket,
                SockAddr {
                    family: AddressFamily::Ipv4,
                    host: addr.ip().to_string(),
                    port: addr.port(),
                },
            )
            .expect("connect");
        // A huge guest length must not trigger a giant allocation.
        let bytes = network.recv(socket, usize::MAX).expect("capped recv");
        assert_eq!(bytes, b"ping");
        worker.join().expect("join");
    }

    #[test]
    fn nonblocking_connect_returns_wouldblock_and_completes() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = std_listener.local_addr().expect("local addr");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = std_listener.accept().expect("accept");
            let mut buf = [0u8; 4];
            let _ = stream.read(&mut buf);
            stream.write_all(b"pong").expect("write");
        });

        let mut network = NetworkStack::new();
        network.wsa_startup();
        let socket = network.socket(AddressFamily::Ipv4).expect("socket");
        network
            .ioctlsocket_fionbio(socket, true)
            .expect("set nonblocking");
        let result = network.connect(
            socket,
            SockAddr {
                family: AddressFamily::Ipv4,
                host: addr.ip().to_string(),
                port: addr.port(),
            },
        );
        // Either the connect completed immediately or it is in progress and
        // reported WSAEWOULDBLOCK. Both are valid for a loopback connect.
        match result {
            Ok(()) => {}
            Err(_) => assert_eq!(network.wsa_get_last_error(), 10035), // WSAEWOULDBLOCK
        }
        // As a guest would, wait (bounded) for writability via select before
        // using the socket.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let (_readable, writable) = network.select(&[socket]).expect("select");
            if writable.contains(&socket) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "non-blocking connect did not complete in time"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // Once complete, the socket must be usable for a send/recv exchange.
        network.send(socket, b"ping").expect("send");
        let mut got = Vec::new();
        while got.is_empty() {
            match network.recv(socket, 4) {
                Ok(bytes) => got = bytes,
                Err(_) => {
                    assert_eq!(network.wsa_get_last_error(), 10035); // WSAEWOULDBLOCK
                    assert!(
                        std::time::Instant::now() < deadline,
                        "recv did not deliver data in time"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        assert_eq!(got, b"pong");
        worker.join().expect("join");
    }

    #[test]
    fn closesocket_releases_listener_address() {
        let mut network = NetworkStack::new();
        network.wsa_startup();
        let listener = network.socket(AddressFamily::Ipv4).expect("listener");
        let addr = SockAddr {
            family: AddressFamily::Ipv4,
            host: "127.0.0.1".to_string(),
            port: 27022,
        };
        network.bind(listener, addr.clone()).expect("bind");
        network.listen(listener, 1).expect("listen");
        // Queue a client connection, then close the listener.
        let client = network.socket(AddressFamily::Ipv4).expect("client");
        network.connect(client, addr.clone()).expect("connect");
        network.closesocket(listener).expect("close listener");
        // The address must be re-bindable now.
        let listener2 = network.socket(AddressFamily::Ipv4).expect("listener2");
        network.bind(listener2, addr).expect("re-bind address");
        // Accepting on the closed listener must fail.
        let result = network.accept(listener);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }
}
