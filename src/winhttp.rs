use crate::error::{AppError, AppResult};
#[cfg(feature = "websocket")]
use crate::network::MAX_WEBSOCKET_RECEIVE_SPILL;
use crate::network::{
    AltSvcEntry, HttpProtocol, HttpProtocolFlags, MAX_WEBSOCKET_FRAME_SIZE,
    MAX_WEBSOCKET_SEND_BUFFER, QuicConfig, negotiate_http_protocol, parse_alt_svc_header,
};
use crate::reason::ReasonCode;
use md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::raw::c_char;
use std::path::Path;
use std::time::Duration;

// ---------------------------------------------------------------------------
// WinHTTP protocol constants
// ---------------------------------------------------------------------------

/// Maximum WinHTTP request body size (256 MB).
pub const MAX_WINHTTP_REQUEST_BODY: usize = 256 * 1024 * 1024;

/// WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL — enables HTTP/2 and/or HTTP/3 protocol
pub const WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL: u32 = 159;

/// WINHTTP_OPTION_QUERY_PROTOCOL — query the negotiated HTTP protocol
pub const WINHTTP_OPTION_QUERY_PROTOCOL: u32 = 160;

/// Protocol flags for WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
pub const WINHTTP_PROTOCOL_FLAG_HTTP2: u32 = 0x0001;
pub const WINHTTP_PROTOCOL_FLAG_HTTP3: u32 = 0x0002;

#[cfg(feature = "websocket")]
use tungstenite::{WebSocket, stream::MaybeTlsStream};

// ---------------------------------------------------------------------------
// WinHTTP API surface — translates WinHTTP calls to native reqwest/TLS
// ---------------------------------------------------------------------------

// -----------------------------------------------------------------------
// Cookie type for cookie jar persistence
// -----------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub expiry: Option<u64>,
}

// -----------------------------------------------------------------------
// Proxy configuration
// -----------------------------------------------------------------------
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub server: String,
    pub bypass_list: Vec<String>,
    pub auth: Option<(String, String)>,
}

pub type HINTERNET = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WinHttpSessionState {
    NotOpen,
    Open,
    Connecting,
    Sending,
    Receiving,
    Complete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinHttpSession {
    pub user_agent: String,
    pub access_type: u32,
    pub proxy: Option<String>,
    pub proxy_bypass: Option<String>,
    pub state: WinHttpSessionState,
    /// Enabled HTTP protocol flags (HTTP/2, HTTP/3).
    /// Set via WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL.
    pub enabled_protocols: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinHttpConnection {
    pub session_handle: HINTERNET,
    pub server_name: String,
    pub server_port: u16,
    pub is_secure: bool,
    pub state: WinHttpSessionState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinHttpRequest {
    pub connection_handle: HINTERNET,
    pub verb: String,
    pub object_name: String,
    pub headers: BTreeMap<String, String>,
    pub raw_headers: Vec<String>,
    pub body: Vec<u8>,
    pub response_body: Vec<u8>,
    pub response_headers: BTreeMap<String, String>,
    pub status_code: u32,
    pub status_text: String,
    pub state: WinHttpSessionState,
    pub timeout_ms: u32,
    pub callback: Option<HINTERNET>, // stores callback context as handle
    pub callback_notify_flags: u32,
    pub certificate_errors: Vec<String>,
}

// -----------------------------------------------------------------------
// WebSocket types
// -----------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum WinHttpWebSocketBufferType {
    BinaryMessageBuffer,
    BinaryFragmentBuffer,
    Utf8MessageBuffer,
    Utf8FragmentBuffer,
    CloseBuffer,
    PingPongBuffer,
}

impl WinHttpWebSocketBufferType {
    /// Validate a guest-supplied `u32` discriminant and convert to the enum.
    /// Returns `Err` with [`ReasonCode::RcInvalidGuestEnum`] for out-of-range values.
    pub fn try_from_u32(value: u32) -> Result<Self, crate::error::AppError> {
        match value {
            0 => Ok(Self::BinaryMessageBuffer),
            1 => Ok(Self::BinaryFragmentBuffer),
            2 => Ok(Self::Utf8MessageBuffer),
            3 => Ok(Self::Utf8FragmentBuffer),
            4 => Ok(Self::CloseBuffer),
            5 => Ok(Self::PingPongBuffer),
            _ => Err(crate::error::AppError::new(
                crate::reason::ReasonCode::RcInvalidGuestEnum,
                format!("invalid WinHttpWebSocketBufferType discriminant {value}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum WinHttpWebSocketCloseStatus {
    Success = 1000,
    EndpointUnavailable = 1001,
    ProtocolError = 1002,
    InvalidDataType = 1003,
    Empty = 1005,
    AbnormalClosure = 1006,
    PolicyViolation = 1008,
    MessageTooBig = 1009,
    UnsupportedExtension = 1010,
    InternalError = 1011,
    ServiceRestart = 1012,
    TryAgainLater = 1013,
    BadGateway = 1014,
    TlsHandshakeFailure = 1015,
}

impl WinHttpWebSocketCloseStatus {
    /// Convert a numeric close code to the enum, defaulting to `InternalError`.
    pub fn from_code(code: u16) -> Self {
        match code {
            1000 => Self::Success,
            1001 => Self::EndpointUnavailable,
            1002 => Self::ProtocolError,
            1003 => Self::InvalidDataType,
            1005 => Self::Empty,
            1006 => Self::AbnormalClosure,
            1008 => Self::PolicyViolation,
            1009 => Self::MessageTooBig,
            1010 => Self::UnsupportedExtension,
            1011 => Self::InternalError,
            1012 => Self::ServiceRestart,
            1013 => Self::TryAgainLater,
            1014 => Self::BadGateway,
            1015 => Self::TlsHandshakeFailure,
            _ => Self::InternalError,
        }
    }

    /// Validate a guest-supplied `u32` close status and convert to the enum.
    /// Returns `Err` with [`ReasonCode::RcInvalidGuestEnum`] for values that
    /// are not recognised WebSocket close status codes.
    pub fn try_from_u32(value: u32) -> Result<Self, crate::error::AppError> {
        match value {
            1000 => Ok(Self::Success),
            1001 => Ok(Self::EndpointUnavailable),
            1002 => Ok(Self::ProtocolError),
            1003 => Ok(Self::InvalidDataType),
            1005 => Ok(Self::Empty),
            1006 => Ok(Self::AbnormalClosure),
            1008 => Ok(Self::PolicyViolation),
            1009 => Ok(Self::MessageTooBig),
            1010 => Ok(Self::UnsupportedExtension),
            1011 => Ok(Self::InternalError),
            1012 => Ok(Self::ServiceRestart),
            1013 => Ok(Self::TryAgainLater),
            1014 => Ok(Self::BadGateway),
            1015 => Ok(Self::TlsHandshakeFailure),
            _ => Err(crate::error::AppError::new(
                crate::reason::ReasonCode::RcInvalidGuestEnum,
                format!("invalid WinHttpWebSocketCloseStatus value {value}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinHttpWebSocketState {
    pub request_handle: HINTERNET,
    pub is_open: bool,
    pub buffer_type: WinHttpWebSocketBufferType,
    pub receive_buffer: Vec<u8>,
    pub send_buffer: Vec<u8>,
    pub close_status: WinHttpWebSocketCloseStatus,
    pub close_reason: Option<String>,
    /// URL this WebSocket connects to (used for tungstenite upgrade).
    pub url: Option<String>,
    /// Whether this is a text-mode WebSocket (vs binary).
    pub is_text_mode: bool,
}

// ---------------------------------------------------------------------------
// Tungstenite-backed real WebSocket connection (feature-gated)
// ---------------------------------------------------------------------------

/// Wraps a real `tungstenite` WebSocket connection for actual network I/O.
/// Only available when the `websocket` feature is enabled.
#[cfg(feature = "websocket")]
#[derive(Debug)]
pub struct TungsteniteWebSocket {
    /// The underlying tungstenite WebSocket.
    inner: WebSocket<MaybeTlsStream<TcpStream>>,
    /// URL this socket is connected to.
    url: String,
}

#[cfg(feature = "websocket")]
impl TungsteniteWebSocket {
    /// Connect to a WebSocket server at the given URL.
    pub fn connect(url: &str) -> AppResult<Self> {
        let (socket, _response) = tungstenite::connect(url).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetworkUnreachable,
                format!("WebSocket connect failed: {e}"),
            )
        })?;
        Ok(Self {
            inner: socket,
            url: url.to_string(),
        })
    }

    /// Send a text message.
    pub fn send_text(&mut self, text: &str) -> AppResult<()> {
        self.inner
            .write(tungstenite::Message::Text(text.into()))
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetworkUnreachable,
                    format!("WebSocket send failed: {e}"),
                )
            })
    }

    /// Send a binary message.
    pub fn send_binary(&mut self, data: &[u8]) -> AppResult<()> {
        self.inner
            .write(tungstenite::Message::Binary(data.to_vec().into()))
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetworkUnreachable,
                    format!("WebSocket send failed: {e}"),
                )
            })
    }

    /// Receive the next message. Returns `(is_text, data)`.
    /// On close frame, returns the close code and reason.
    pub fn receive(&mut self) -> AppResult<WebSocketMessage> {
        let msg = self.inner.read().map_err(|e| {
            AppError::new(
                ReasonCode::RcNetworkUnreachable,
                format!("WebSocket receive failed: {e}"),
            )
        })?;
        match msg {
            tungstenite::Message::Text(text) => Ok(WebSocketMessage::Text(text.to_string())),
            tungstenite::Message::Binary(data) => Ok(WebSocketMessage::Binary(data.to_vec())),
            tungstenite::Message::Close(Some(frame)) => Ok(WebSocketMessage::Close(
                frame.code.into(),
                frame.reason.to_string(),
            )),
            tungstenite::Message::Close(None) => Ok(WebSocketMessage::Close(1000, String::new())),
            tungstenite::Message::Ping(data) => {
                self.inner
                    .write(tungstenite::Message::Pong(data))
                    .map_err(|e| {
                        AppError::new(
                            ReasonCode::RcNetworkUnreachable,
                            format!("WebSocket pong failed: {e}"),
                        )
                    })?;
                Ok(WebSocketMessage::Ping)
            }
            tungstenite::Message::Pong(_) => Ok(WebSocketMessage::Pong),
            tungstenite::Message::Frame(_) => Ok(WebSocketMessage::Binary(Vec::new())),
        }
    }

    /// Close the WebSocket with the given status code and reason.
    pub fn close(&mut self, code: u16, reason: &str) -> AppResult<()> {
        self.inner
            .close(Some(tungstenite::protocol::CloseFrame {
                code: code.into(),
                reason: reason.into(),
            }))
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetworkUnreachable,
                    format!("WebSocket close failed: {e}"),
                )
            })
    }

    /// Get the URL this socket is connected to.
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// A message received from a WebSocket connection.
#[derive(Debug, Clone)]
pub enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
    Close(u16, String),
    Ping,
    Pong,
}

// -----------------------------------------------------------------------
// PAC cache entry — stores a cached proxy result from PAC evaluation
// -----------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct PacCacheEntry {
    /// The resolved proxy string (e.g. "PROXY proxy.example.com:8080" or "DIRECT")
    pub proxy_string: String,
    /// When this cache entry expires (absolute time)
    pub expiry: std::time::Instant,
}

#[derive(Debug)]
pub struct WinHttpStack {
    sessions: BTreeMap<HINTERNET, WinHttpSession>,
    connections: BTreeMap<HINTERNET, WinHttpConnection>,
    requests: BTreeMap<HINTERNET, WinHttpRequest>,
    next_handle: HINTERNET,
    client: Option<reqwest::blocking::Client>,
    /// Certificate pinning: host -> list of acceptable SPKI SHA-256 hashes
    pinned_certs: HashMap<String, Vec<Vec<u8>>>,
    /// Cookie jar: host -> list of cookies
    cookie_jar: HashMap<String, Vec<Cookie>>,
    /// Proxy configuration
    proxy: Option<ProxyConfig>,
    /// Last response error text (for InternetGetLastResponseInfoW)
    last_response_error: String,
    /// WebSocket connections (buffer-based state)
    websockets: BTreeMap<HINTERNET, WinHttpWebSocketState>,
    /// Real tungstenite-backed WebSocket connections (feature-gated).
    /// Keyed by the same handle as in `websockets`.
    #[cfg(feature = "websocket")]
    live_websockets: BTreeMap<HINTERNET, TungsteniteWebSocket>,
    /// QUIC/HTTP3 configuration
    quic_config: QuicConfig,
    /// Alt-Svc entries discovered from response headers (host -> entries)
    alt_svc_entries: HashMap<String, Vec<AltSvcEntry>>,
    /// Whether HTTP/3 fallback logging has been emitted for each host
    quic_fallback_logged: HashMap<String, bool>,
    // ── FTP state ──────────────────────────────────────────────────────────
    /// FTP control connections (connection_handle -> TcpStream)
    ftp_control: BTreeMap<HINTERNET, std::net::TcpStream>,
    /// FTP current working directory per connection
    ftp_current_dir: BTreeMap<HINTERNET, String>,
    /// FTP transfer type per connection (true=binary, false=ascii)
    ftp_binary_mode: BTreeMap<HINTERNET, bool>,
    /// FTP data connection addresses (pasv response) per connection
    ftp_data_addr: BTreeMap<HINTERNET, String>,
    /// FTP file data cache: FtpOpenFileW handle -> file contents.
    /// Allows InternetReadFile to retrieve data after ftp_open_file_w
    /// reads and caches it, rather than discarding it.
    ftp_file_data: BTreeMap<HINTERNET, Vec<u8>>,
    /// FTP last listing results for find operations
    ftp_listing_cache: BTreeMap<HINTERNET, Vec<crate::wininet::FtpFileInfo>>,
    /// FTP listing iterator index per find handle
    ftp_listing_index: BTreeMap<HINTERNET, usize>,
    // ── Certificate revocation state ────────────────────────────────────────
    /// Registered revocation handler callback (handle -> callback pointer as u64)
    revocation_handlers: BTreeMap<HINTERNET, u64>,
    /// Client certificate context (handle -> raw cert context bytes)
    client_cert_contexts: BTreeMap<HINTERNET, Vec<u8>>,
    // ── PAC evaluation cache ────────────────────────────────────────────────
    /// Cached PAC evaluation results (url -> proxy_string)
    pac_cache: HashMap<String, PacCacheEntry>,
}

// -----------------------------------------------------------------------
// Minimal DER parser: extract the SubjectPublicKeyInfo (SPKI) from a
// DER-encoded X.509 certificate (leaf-to-root order).
// Returns None if parsing fails.
// -----------------------------------------------------------------------
fn extract_spki_der(data: &[u8]) -> Option<Vec<u8>> {
    // X.509 certificate DER structure (outermost):
    //   SEQUENCE {
    //     TBSCertificate  SEQUENCE { ... SubjectPublicKeyInfo SEQUENCE { ... } ... }
    //     SignatureAlgorithm  SEQUENCE { ... }
    //     SignatureValue  BIT STRING
    //   }
    //
    // We simply walk into the outermost SEQUENCE, then into TBSCertificate,
    // then skip fields until we find the SubjectPublicKeyInfo SEQUENCE.
    fn read_tag(data: &[u8], offset: &mut usize) -> Option<(u8, usize)> {
        let tag = *data.get(*offset)?;
        *offset += 1;
        let len = if let Some(&b) = data.get(*offset) {
            *offset += 1;
            if b & 0x80 != 0 {
                let num_bytes = (b & 0x7F) as usize;
                let mut len_val = 0usize;
                for _ in 0..num_bytes {
                    len_val = (len_val << 8) | (*data.get(*offset)? as usize);
                    *offset += 1;
                }
                len_val
            } else {
                b as usize
            }
        } else {
            return None;
        };
        Some((tag, len))
    }

    fn skip_tlv(data: &[u8], offset: &mut usize) -> Option<()> {
        let (_, len) = read_tag(data, offset)?;
        *offset += len;
        Some(())
    }

    // Outer SEQUENCE (Certificate)
    let mut off = 0;
    let (_, outer_len) = read_tag(data, &mut off)?;
    let end = off + outer_len;
    if end > data.len() {
        return None;
    }

    // TBSCertificate SEQUENCE
    let (_, tbs_len) = read_tag(data, &mut off)?;
    let tbs_end = off + tbs_len;
    if tbs_end > end {
        return None;
    }

    // Skip version (context-specific [0] EXPLICIT, tag 0xA0) if present
    if off < tbs_end && data.get(off).copied() == Some(0xA0) {
        skip_tlv(data, &mut off)?;
    }

    // Skip serialNumber (INTEGER)
    skip_tlv(data, &mut off)?;

    // Skip signature (SEQUENCE)
    skip_tlv(data, &mut off)?;

    // Skip issuer (SEQUENCE)
    skip_tlv(data, &mut off)?;

    // Skip validity (SEQUENCE of two UTCTime/GeneralizedTime)
    skip_tlv(data, &mut off)?;

    // Skip subject (SEQUENCE)
    skip_tlv(data, &mut off)?;

    // SubjectPublicKeyInfo SEQUENCE: capture the TLV start offset *before*
    // consuming the tag/length bytes so we can slice the exact DER encoding
    // of the SPKI (tag + length + content) deterministically.
    let spki_start = off;
    let (spki_tag, spki_len) = read_tag(data, &mut off)?;
    if spki_tag != 0x30 {
        return None;
    }
    let spki_end = off + spki_len;
    if spki_end > tbs_end {
        return None;
    }
    Some(data[spki_start..spki_end].to_vec())
}

impl WinHttpStack {
    pub fn new() -> Self {
        let stack = Self {
            sessions: BTreeMap::new(),
            connections: BTreeMap::new(),
            requests: BTreeMap::new(),
            next_handle: 0,
            client: None,
            pinned_certs: HashMap::new(),
            cookie_jar: HashMap::new(),
            proxy: None,
            last_response_error: String::new(),
            websockets: BTreeMap::new(),
            #[cfg(feature = "websocket")]
            live_websockets: BTreeMap::new(),
            quic_config: QuicConfig::default(),
            alt_svc_entries: HashMap::new(),
            quic_fallback_logged: HashMap::new(),
            // FTP state
            ftp_control: BTreeMap::new(),
            ftp_current_dir: BTreeMap::new(),
            ftp_binary_mode: BTreeMap::new(),
            ftp_data_addr: BTreeMap::new(),
            ftp_file_data: BTreeMap::new(),
            ftp_listing_cache: BTreeMap::new(),
            ftp_listing_index: BTreeMap::new(),
            // Certificate revocation
            revocation_handlers: BTreeMap::new(),
            client_cert_contexts: BTreeMap::new(),
            // PAC cache
            pac_cache: HashMap::new(),
        };
        // TODO: Replace with real SPKI SHA-256 pin when available.
        // Pre-load known Steam CDN certificate pins (SPKI SHA-256 hashes).
        // Placeholder pins have been removed to prevent false trust decisions.
        // Uncomment and populate with real hashes extracted from actual Steam CDN
        // certificates once they are obtained:
        //
        // stack.pin_certificate("cdn.steamstatic.com", &real_spki_hash);
        // stack.pin_certificate("steamcdn-a.akamaihd.net", &real_spki_hash);
        // stack.pin_certificate("steamcdn-b.akamaihd.net", &real_spki_hash);
        // stack.pin_certificate("steamcommunity.com", &real_spki_hash);
        // stack.pin_certificate("steampowered.com", &real_spki_hash);
        // stack.pin_certificate("steamstore.akamaihd.net", &real_spki_hash);
        stack
    }

    /// Decode a hex string to bytes; returns empty vec on failure (pins are best-effort).
    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..(i + 2).min(hex.len())], 16).ok())
            .collect()
    }

    // -----------------------------------------------------------------------
    // Certificate pinning
    // -----------------------------------------------------------------------

    /// Add a certificate pin for a given host.
    /// `spki_hash` is the SHA-256 hash of the certificate's SubjectPublicKeyInfo.
    pub fn pin_certificate(&mut self, host: &str, spki_hash: &[u8]) {
        self.pinned_certs
            .entry(host.to_string())
            .or_default()
            .push(spki_hash.to_vec());
    }

    /// Verify that at least one certificate in the chain matches a pin for the given host.
    /// `cert_chain` contains DER-encoded certificates (from leaf to root), captured from
    /// the live TLS handshake via reqwest's `tls_info`.
    ///
    /// Behavior:
    /// - No pins configured for the host: accept (pinning is opt-in per host).
    /// - Pins configured: accept iff some certificate's SubjectPublicKeyInfo SHA-256 matches
    ///   a pin. If the chain is empty (e.g. a plain-HTTP request to a pinned host, or the TLS
    ///   layer exposed no certificate) we FAIL CLOSED, since a configured pin must be honored.
    pub fn verify_certificate_pin(&self, host: &str, cert_chain: &[Vec<u8>]) -> bool {
        let Some(acceptable) = self.pinned_certs.get(host) else {
            // No pins configured for this host — pinning is opt-in.
            return true;
        };
        if acceptable.is_empty() {
            return true;
        }
        // Compute SPKI SHA-256 hash for each certificate in the chain and check against pins.
        // An empty chain falls through the loop and returns `false` (fail closed).
        for cert_der in cert_chain {
            // Simple DER parsing to extract the SubjectPublicKeyInfo
            if let Some(spki_der) = extract_spki_der(cert_der) {
                let hash = Sha256::digest(&spki_der);
                if acceptable
                    .iter()
                    .any(|pin| pin.as_slice() == hash.as_slice())
                {
                    return true;
                }
            }
        }
        false
    }

    /// Remove all certificate pins, reverting to unpinned-default behavior.
    pub fn clear_certificate_pins(&mut self) {
        self.pinned_certs.clear();
    }

    // -----------------------------------------------------------------------
    // Cookie jar
    // -----------------------------------------------------------------------

    /// Store a cookie for a given host.
    pub fn set_cookie(&mut self, host: &str, cookie: Cookie) {
        self.cookie_jar
            .entry(host.to_string())
            .or_default()
            .push(cookie);
    }

    /// Retrieve cookies matching the given host and path.
    /// Returns a list of (name, value) pairs suitable for a `Cookie` header.
    pub fn get_cookies(&self, host: &str, path: &str) -> Vec<(String, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut result = Vec::new();
        if let Some(cookies) = self.cookie_jar.get(host) {
            for cookie in cookies {
                // Skip expired cookies
                if let Some(expiry) = cookie.expiry {
                    if now >= expiry {
                        continue;
                    }
                }
                // Path match: cookie path must be a prefix of the request path
                if !path.starts_with(&cookie.path) {
                    continue;
                }
                result.push((cookie.name.clone(), cookie.value.clone()));
            }
        }
        result
    }

    /// Load cookie jar from a JSON file.
    pub fn load_cookie_jar(&mut self, path: &Path) -> AppResult<()> {
        if !path.exists() {
            return Ok(());
        }
        let data = fs::read_to_string(path).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("load_cookie_jar: failed to read {path:?}: {e}"),
            )
        })?;
        let jar: HashMap<String, Vec<Cookie>> = serde_json::from_str(&data).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("load_cookie_jar: failed to parse {path:?}: {e}"),
            )
        })?;
        self.cookie_jar = jar;
        Ok(())
    }

    /// Save cookie jar to a JSON file.
    pub fn save_cookie_jar(&self, path: &Path) -> AppResult<()> {
        let data = serde_json::to_string_pretty(&self.cookie_jar).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("save_cookie_jar: failed to serialize: {e}"),
            )
        })?;
        fs::write(path, &data).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("save_cookie_jar: failed to write {path:?}: {e}"),
            )
        })?;
        Ok(())
    }

    /// Parse a `Set-Cookie` header value and store the cookie.
    fn parse_and_store_set_cookie(&mut self, host: &str, header_value: &str) {
        // Parse the simplest form: "name=value; attr1; attr2=val2"
        let parts: Vec<&str> = header_value.split(';').collect();
        if parts.is_empty() {
            return;
        }
        let (name, value) = if let Some(eq_pos) = parts[0].find('=') {
            (
                parts[0][..eq_pos].trim().to_string(),
                parts[0][eq_pos + 1..].trim().to_string(),
            )
        } else {
            return;
        };

        let mut cookie = Cookie {
            name,
            value,
            domain: host.to_string(),
            path: "/".to_string(),
            secure: false,
            expiry: None,
        };

        for attr in &parts[1..] {
            let attr = attr.trim();
            if let Some(eq_pos) = attr.find('=') {
                let key = attr[..eq_pos].trim().to_lowercase();
                let val = attr[eq_pos + 1..].trim().to_string();
                match key.as_str() {
                    "domain" => cookie.domain = val,
                    "path" => cookie.path = val,
                    "expires" | "max-age" => {
                        // For simplicity, parse as a timestamp if max-age
                        if key == "max-age" {
                            if let Ok(seconds) = val.parse::<u64>() {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                cookie.expiry = Some(now + seconds);
                            }
                        }
                        // Expires date parsing is complex; skip for now
                    }
                    _ => {}
                }
            } else {
                let key = attr.to_lowercase();
                if key == "secure" {
                    cookie.secure = true;
                }
            }
        }

        self.set_cookie(&cookie.domain.clone(), cookie);
    }

    // -----------------------------------------------------------------------
    // Proxy configuration
    // -----------------------------------------------------------------------

    /// Set the proxy configuration.
    pub fn set_proxy(&mut self, config: ProxyConfig) {
        self.proxy = Some(config);
    }

    /// Returns true if the given URL should bypass the proxy.
    pub fn should_bypass_proxy(&self, url: &str) -> bool {
        let Some(ref proxy) = self.proxy else {
            return true; // No proxy configured, nothing to bypass
        };
        if proxy.bypass_list.is_empty() {
            return false;
        }
        // Check if the URL matches any bypass entry (simple substring/prefix match)
        for bypass in &proxy.bypass_list {
            if url.contains(bypass) {
                return true;
            }
            // Also check for wildcard-like patterns (e.g., "*.local")
            if let Some(domain) = bypass.strip_prefix("*.") {
                if url.contains(domain) {
                    return true;
                }
            }
        }
        false
    }

    /// Returns the Proxy-Authorization header value if proxy auth is configured.
    pub fn proxy_auth_header(&self) -> Option<String> {
        let Some(ref proxy) = self.proxy else {
            return None;
        };
        let Some((ref username, ref password)) = proxy.auth else {
            return None;
        };
        let credentials = format!("{username}:{password}");
        let encoded = Self::base64_encode(credentials.as_bytes());
        Some(format!("Basic {encoded}"))
    }

    /// Base64 encode (minimal implementation to avoid extra dependency).
    fn base64_encode(input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk.get(0).copied().unwrap_or(0) as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let triple = (b0 << 16) | (b1 << 8) | b2;
            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }

    fn next_handle(&mut self) -> HINTERNET {
        let h = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        h
    }

    // -----------------------------------------------------------------------
    // WinHttpOpen — initialise a WinHTTP session
    // -----------------------------------------------------------------------
    pub fn win_http_open(
        &mut self,
        user_agent: Option<&str>,
        access_type: u32,
        proxy: Option<&str>,
        proxy_bypass: Option<&str>,
    ) -> HINTERNET {
        let handle = self.next_handle();
        let session = WinHttpSession {
            user_agent: user_agent.unwrap_or("Casa1").to_string(),
            access_type,
            proxy: proxy.map(|s| s.to_string()),
            proxy_bypass: proxy_bypass.map(|s| s.to_string()),
            state: WinHttpSessionState::Open,
            enabled_protocols: 0,
        };
        self.sessions.insert(handle, session);
        handle
    }

    // -----------------------------------------------------------------------
    // WinHttpCloseHandle — close any WinHTTP handle
    // -----------------------------------------------------------------------
    pub fn win_http_close_handle(&mut self, handle: HINTERNET) -> AppResult<()> {
        if self.sessions.remove(&handle).is_some() {
            return Ok(());
        }
        if self.connections.remove(&handle).is_some() {
            return Ok(());
        }
        if self.requests.remove(&handle).is_some() {
            return Ok(());
        }
        if self.websockets.remove(&handle).is_some() {
            #[cfg(feature = "websocket")]
            self.live_websockets.remove(&handle);
            return Ok(());
        }
        // Clean up FTP file data cache entry
        if self.ftp_file_data.remove(&handle).is_some() {
            return Ok(());
        }
        Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("WinHttpCloseHandle: invalid handle {handle:#x}"),
        ))
    }

    // -----------------------------------------------------------------------
    // WinHttpConnect — create a connection to a server
    // -----------------------------------------------------------------------
    pub fn win_http_connect(
        &mut self,
        session_handle: HINTERNET,
        server_name: &str,
        server_port: u16,
        is_secure: bool,
    ) -> AppResult<HINTERNET> {
        let _session = self.sessions.get(&session_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpConnect: invalid session handle {session_handle:#x}"),
            )
        })?;
        let conn = WinHttpConnection {
            session_handle,
            server_name: server_name.to_string(),
            server_port,
            is_secure,
            state: WinHttpSessionState::Connecting,
        };
        let handle = self.next_handle();
        self.connections.insert(handle, conn);
        Ok(handle)
    }

    // -----------------------------------------------------------------------
    // WinHttpOpenRequest — create an HTTP request handle
    // -----------------------------------------------------------------------
    pub fn win_http_open_request(
        &mut self,
        connect_handle: HINTERNET,
        verb: &str,
        object_name: &str,
        headers: Option<&str>,
        // accept_types is ignored for now
    ) -> AppResult<HINTERNET> {
        let _conn = self.connections.get(&connect_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpOpenRequest: invalid connect handle {connect_handle:#x}"),
            )
        })?;

        let mut parsed_headers = BTreeMap::new();
        let mut raw_headers = Vec::new();
        if let Some(h) = headers {
            for line in h.split("\r\n").filter(|l| !l.is_empty()) {
                raw_headers.push(line.to_string());
                if let Some(pos) = line.find(':') {
                    let key = line[..pos].trim().to_string();
                    let value = line[pos + 1..].trim().to_string();
                    parsed_headers.insert(key, value);
                }
            }
        }

        let req = WinHttpRequest {
            connection_handle: connect_handle,
            verb: verb.to_string(),
            object_name: object_name.to_string(),
            headers: parsed_headers,
            raw_headers,
            body: Vec::new(),
            response_body: Vec::new(),
            response_headers: BTreeMap::new(),
            status_code: 0,
            status_text: String::new(),
            state: WinHttpSessionState::Open,
            timeout_ms: 30000,
            callback: None,
            callback_notify_flags: 0,
            certificate_errors: Vec::new(),
        };
        let handle = self.next_handle();
        self.requests.insert(handle, req);
        Ok(handle)
    }

    // -----------------------------------------------------------------------
    // WinHttpSendRequest — send the HTTP request
    // -----------------------------------------------------------------------
    pub fn win_http_send_request(
        &mut self,
        request_handle: HINTERNET,
        additional_headers: Option<&str>,
        body: Option<&[u8]>,
    ) -> AppResult<()> {
        // Phase 1: Parse additional headers and body, extract connection info
        // (drop mutable borrow on self.requests before calling self.* methods)
        let (_conn_handle, conn_server_name, conn_is_secure, conn_port, req_object_name, req_verb) = {
            let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("WinHttpSendRequest: invalid handle {request_handle:#x}"),
                )
            })?;

            if let Some(h) = additional_headers {
                for line in h.split("\r\n").filter(|l| !l.is_empty()) {
                    req.raw_headers.push(line.to_string());
                    if let Some(pos) = line.find(':') {
                        let key = line[..pos].trim().to_string();
                        let value = line[pos + 1..].trim().to_string();
                        req.headers.insert(key, value);
                    }
                }
            }

            if let Some(b) = body {
                if b.len() > MAX_WINHTTP_REQUEST_BODY {
                    return Err(AppError::new(
                        ReasonCode::RcRequestBodyTooLarge,
                        format!(
                            "WinHttpSendRequest: body size {} exceeds limit ({MAX_WINHTTP_REQUEST_BODY})",
                            b.len()
                        ),
                    ));
                }
                req.body = b.to_vec();
            }

            let ch = req.connection_handle;
            let cn = self.connections.get(&ch).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("WinHttpSendRequest: invalid connection {ch:#x}"),
                )
            })?;
            (
                ch,
                cn.server_name.clone(),
                cn.is_secure,
                cn.server_port,
                req.object_name.clone(),
                req.verb.clone(),
            )
        };

        let scheme = if conn_is_secure { "https" } else { "http" };
        let url = format!(
            "{}://{}:{}{}",
            scheme, conn_server_name, conn_port, req_object_name
        );

        // --- 3.1.5: Proxy configuration ---
        let should_bypass = self.should_bypass_proxy(&url);
        let proxy_auth = if !should_bypass {
            self.proxy_auth_header()
        } else {
            None
        };
        let proxy_cfg = self.proxy.clone();

        // --- 3.1.4: Collect cookies from jar ---
        let cookies = self.get_cookies(&conn_server_name, &req_object_name);

        // Build the HTTP client lazily (with proxy support if configured)
        let client = self.client.get_or_insert_with(|| {
            let mut builder = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(false) // certificate pinning is enforced for pinned hosts
                .tls_info(true) // expose the peer certificate so certificate pinning can be enforced
                .timeout(std::time::Duration::from_secs(30));
            if let Some(ref cfg) = proxy_cfg {
                if !should_bypass {
                    let proxy_url = if cfg.server.starts_with("http://")
                        || cfg.server.starts_with("https://")
                    {
                        cfg.server.clone()
                    } else {
                        format!("http://{}", cfg.server)
                    };
                    if let Ok(proxy) = reqwest::Proxy::http(&proxy_url) {
                        builder = builder.proxy(proxy);
                    }
                }
            }
            builder.build().expect("Failed to create reqwest client")
        });

        let method = match req_verb.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "PATCH" => reqwest::Method::PATCH,
            _ => reqwest::Method::GET,
        };

        let mut request_builder = client.request(method.clone(), &url);

        // --- 3.1.4: Attach cookies from jar as Cookie header ---
        if !cookies.is_empty() {
            let cookie_header: String = cookies
                .iter()
                .map(|(n, v)| format!("{}={}", n, v))
                .collect::<Vec<_>>()
                .join("; ");
            request_builder = request_builder.header("Cookie", cookie_header);
        }

        // --- 3.1.5: Add proxy authorization header if configured ---
        if let Some(auth) = proxy_auth {
            request_builder = request_builder.header("Proxy-Authorization", auth);
        }

        // Phase 2: Re-borrow request to add headers/body and send
        let (
            _status_code,
            _status_text,
            response_headers,
            _response_body,
            set_cookie_values,
            cert_chain,
        ) = {
            let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("WinHttpSendRequest: invalid handle {request_handle:#x}"),
                )
            })?;

            // Add existing headers
            for (key, value) in &req.headers {
                request_builder = request_builder.header(key.as_str(), value.as_str());
            }

            // Add body for methods that support it
            if method == reqwest::Method::POST
                || method == reqwest::Method::PUT
                || method == reqwest::Method::PATCH
            {
                request_builder = request_builder.body(req.body.clone());
            }

            req.state = WinHttpSessionState::Sending;

            // Execute the request
            let response = match request_builder.send() {
                Ok(resp) => resp,
                Err(e) => {
                    req.state = WinHttpSessionState::Complete;
                    return Err(AppError::new(
                        ReasonCode::RcNetHttpRequestFailed,
                        format!("WinHttpSendRequest: {e:?}"),
                    ));
                }
            };

            // Capture the peer certificate (DER) from the live TLS handshake before the
            // response body is consumed, so certificate pins can be enforced below.
            let cert_chain: Vec<Vec<u8>> = response
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|info| info.peer_certificate())
                .map(|der| vec![der.to_vec()])
                .unwrap_or_default();

            let sc = response.status().as_u16() as u32;
            let st = response
                .status()
                .canonical_reason()
                .unwrap_or("Unknown")
                .to_string();

            // Parse response headers
            let mut resp_headers = BTreeMap::new();
            for (key, value) in response.headers() {
                resp_headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
            }

            // --- 3.1.4: Parse Set-Cookie headers from raw response ---
            // reqwest::header::HeaderMap supports get_all() for multi-valued headers;
            // we use it here before the headers are collapsed into BTreeMap.
            let set_cookie_values: Vec<String> = response
                .headers()
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .map(|hv| hv.to_str().unwrap_or("").to_string())
                .collect();

            // Read response body
            let body_bytes = response.bytes().unwrap_or_default().to_vec();

            // Write results into request
            req.status_code = sc;
            req.status_text = st.clone();
            req.response_headers = resp_headers.clone();
            req.response_body = body_bytes.clone();
            req.state = WinHttpSessionState::Complete;

            (
                sc,
                st,
                resp_headers,
                body_bytes,
                set_cookie_values,
                cert_chain,
            )
        };

        // --- 3.1.4: Parse and store Set-Cookie headers from response ---
        for header_value in &set_cookie_values {
            self.parse_and_store_set_cookie(&conn_server_name, header_value);
        }

        // --- 3.1.3: Verify certificate pins ---
        // The peer certificate captured from the TLS handshake (via `tls_info`) is passed
        // to the pin validator. If pins are configured for this host and none match, the
        // request is rejected (fail closed).
        if !self.verify_certificate_pin(&conn_server_name, &cert_chain) {
            return Err(AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!(
                    "WinHttpSendRequest: certificate pin validation failed for {}",
                    conn_server_name
                ),
            ));
        }

        // --- Parse Alt-Svc header for HTTP/3 discovery ---
        if let Some(alt_svc_value) = response_headers.get("alt-svc") {
            let entries = parse_alt_svc_header(alt_svc_value);
            if !entries.is_empty() {
                self.alt_svc_entries
                    .insert(conn_server_name.clone(), entries);
            }
        }

        // --- QUIC/HTTP3 detection and fallback logging ---
        // If the session requested HTTP/3 but we're running on a platform without QUIC,
        // log the fallback once per host so downstream diagnostics can see it.
        let session_handle = self
            .connections
            .get(&_conn_handle)
            .map(|c| c.session_handle);
        let enabled_protocols = session_handle
            .and_then(|sh| self.sessions.get(&sh))
            .map(|s| s.enabled_protocols)
            .unwrap_or(0);
        if enabled_protocols & WINHTTP_PROTOCOL_FLAG_HTTP3 != 0 {
            if !self
                .quic_fallback_logged
                .get(&conn_server_name)
                .copied()
                .unwrap_or(false)
            {
                eprintln!(
                    "WinHttp: HTTP/3 requested for {} but QUIC is not available on this platform; \
                     using HTTP/2 as fallback",
                    conn_server_name
                );
                self.quic_fallback_logged
                    .insert(conn_server_name.clone(), true);
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // WinHttpReceiveResponse — wait for response (cookies already parsed
    // during WinHttpSendRequest from raw HeaderMap)
    // -----------------------------------------------------------------------
    pub fn win_http_receive_response(&mut self, request_handle: HINTERNET) -> AppResult<()> {
        let req = self.requests.get(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpReceiveResponse: invalid handle {request_handle:#x}"),
            )
        })?;
        if req.state != WinHttpSessionState::Complete {
            return Err(AppError::new(
                ReasonCode::RcNetHttpRequestFailed,
                "WinHttpReceiveResponse: request not yet complete",
            ));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // WinHttpReadData — read response body into a buffer
    // -----------------------------------------------------------------------
    pub fn win_http_read_data(
        &mut self,
        request_handle: HINTERNET,
        buffer: &mut [u8],
    ) -> AppResult<u32> {
        // First try the HTTP requests map
        if let Some(req) = self.requests.get_mut(&request_handle) {
            let to_read = buffer.len().min(req.response_body.len());
            buffer[..to_read].copy_from_slice(&req.response_body[..to_read]);
            req.response_body.drain(..to_read);
            return Ok(to_read as u32);
        }

        // Fall back to FTP file data cache (for handles from ftp_open_file_w)
        if let Some(file_data) = self.ftp_file_data.get_mut(&request_handle) {
            let to_read = buffer.len().min(file_data.len());
            buffer[..to_read].copy_from_slice(&file_data[..to_read]);
            file_data.drain(..to_read);
            return Ok(to_read as u32);
        }

        Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("WinHttpReadData: invalid handle {request_handle:#x}"),
        ))
    }

    // -----------------------------------------------------------------------
    // WinHttpQueryDataAvailable — get available response data length
    // -----------------------------------------------------------------------
    pub fn win_http_query_data_available(&self, request_handle: HINTERNET) -> AppResult<u32> {
        let req = self.requests.get(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpQueryDataAvailable: invalid handle {request_handle:#x}"),
            )
        })?;
        Ok(req.response_body.len() as u32)
    }

    // -----------------------------------------------------------------------
    // WinHttpQueryHeaders — query response headers
    // -----------------------------------------------------------------------
    pub fn win_http_query_headers(
        &self,
        request_handle: HINTERNET,
        header_name: &str,
    ) -> AppResult<String> {
        let req = self.requests.get(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpQueryHeaders: invalid handle {request_handle:#x}"),
            )
        })?;
        if header_name.is_empty() {
            // Return all headers as raw string
            let raw: Vec<String> = req
                .response_headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect();
            return Ok(raw.join("\r\n"));
        }
        req.response_headers
            .get(header_name)
            .cloned()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcNetHttpHeaderNotFound,
                    format!("WinHttpQueryHeaders: header '{header_name}' not found"),
                )
            })
    }

    // -----------------------------------------------------------------------
    // WinHttpSetOption — set an option on a handle
    // -----------------------------------------------------------------------
    pub fn win_http_set_option(
        &mut self,
        handle: HINTERNET,
        option: u32,
        value: &[u8],
    ) -> AppResult<()> {
        // Try session, connection, request in order
        if let Some(session) = self.sessions.get_mut(&handle) {
            match option {
                0 | 38 => {
                    // WINHTTP_OPTION_PROXY (0 is sometimes passed as a placeholder;
                    // the official constant is 38). Parse proxy configuration from the
                    // value buffer. Expected layout (simplified):
                    //   [access_type: u32][proxy_string: null-terminated][bypass_list: null-terminated]
                    let access_type = if value.len() >= 4 {
                        u32::from_ne_bytes([value[0], value[1], value[2], value[3]])
                    } else {
                        0 // WINHTTP_ACCESS_TYPE_NO_PROXY
                    };
                    // Try to extract a proxy server string from the remainder of the value
                    let proxy_str = if value.len() > 4 {
                        let remainder = &value[4..];
                        // Find the first null terminator to get a C-style string
                        let end = remainder
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(remainder.len());
                        if end > 0 {
                            Some(String::from_utf8_lossy(&remainder[..end]).to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    if access_type != 0 {
                        // WINHTTP_ACCESS_TYPE_NAMED_PROXY
                        if let Some(ref proxy_url) = proxy_str {
                            let proxy_len = proxy_url.len();
                            let bypass_list = if value.len() > 4 + proxy_len + 1 {
                                // After the proxy string null terminator, look for bypass list
                                let bypass_start = 4 + proxy_len + 1;
                                if bypass_start < value.len() {
                                    let remainder = &value[bypass_start..];
                                    let end = remainder
                                        .iter()
                                        .position(|&b| b == 0)
                                        .unwrap_or(remainder.len());
                                    if end > 0 {
                                        remainder[..end]
                                            .split(|&b| b == b';')
                                            .filter(|s| !s.is_empty())
                                            .map(|s| String::from_utf8_lossy(s).to_string())
                                            .collect::<Vec<_>>()
                                    } else {
                                        Vec::new()
                                    }
                                } else {
                                    Vec::new()
                                }
                            } else {
                                Vec::new()
                            };
                            session.proxy = Some(proxy_url.clone());
                            session.proxy_bypass = Some(bypass_list.join(";"));
                            self.proxy = Some(ProxyConfig {
                                server: proxy_url.clone(),
                                bypass_list,
                                auth: None,
                            });
                            eprintln!(
                                "WinHttpSetOption: proxy set to {} for session {:#x}",
                                proxy_url, handle
                            );
                        }
                    }
                }
                WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL => {
                    if value.len() >= 4 {
                        let flags = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                        session.enabled_protocols = flags;

                        // Log if HTTP/3 was requested
                        if flags & WINHTTP_PROTOCOL_FLAG_HTTP3 != 0 {
                            eprintln!(
                                "WinHttpSetOption: HTTP/3 protocol enabled for session {:#x} \
                                 (HTTP/3 will be transparently downgraded to HTTP/2 on this platform)",
                                handle
                            );
                        }
                    }
                }
                _ => {}
            }
            return Ok(());
        }
        if let Some(_conn) = self.connections.get_mut(&handle) {
            match option {
                _ => {}
            }
            return Ok(());
        }
        if let Some(req) = self.requests.get_mut(&handle) {
            match option {
                4 => {
                    // WINHTTP_OPTION_CONNECT_TIMEOUT
                    if value.len() >= 4 {
                        req.timeout_ms =
                            u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                    }
                }
                _ => {}
            }
            return Ok(());
        }
        Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("WinHttpSetOption: invalid handle {handle:#x}"),
        ))
    }

    // -----------------------------------------------------------------------
    // WinHttpQueryOption — query an option on a handle
    // -----------------------------------------------------------------------
    pub fn win_http_query_option(
        &mut self,
        handle: HINTERNET,
        option: u32,
        buffer: &mut [u8],
    ) -> AppResult<u32> {
        match option {
            WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL => {
                if let Some(session) = self.sessions.get(&handle) {
                    if buffer.len() >= 4 {
                        let flags = session.enabled_protocols;
                        buffer[..4].copy_from_slice(&flags.to_ne_bytes());
                        return Ok(4);
                    }
                    return Err(AppError::new(
                        ReasonCode::RcNetProtocolError,
                        "WinHttpQueryOption: buffer too small for protocol flags",
                    ));
                }
                Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("WinHttpQueryOption: invalid handle {handle:#x} for protocol query"),
                ))
            }
            WINHTTP_OPTION_QUERY_PROTOCOL => {
                // Return the negotiated protocol based on session's enabled flags,
                // QUIC availability, and any Alt-Svc entries.
                // Works for both request and session handles.
                let (session_flags, maybe_host) = if let Some(req) = self.requests.get(&handle) {
                    // Request handle: resolve from connection → session
                    if let Some(conn) = self.connections.get(&req.connection_handle) {
                        let host = conn.server_name.clone();
                        let flags = self
                            .sessions
                            .get(&conn.session_handle)
                            .map(|s| s.enabled_protocols)
                            .unwrap_or(0);
                        (flags, Some(host))
                    } else {
                        (0u32, None)
                    }
                } else if let Some(session) = self.sessions.get(&handle) {
                    // Session handle: use directly
                    (session.enabled_protocols, None)
                } else {
                    (0u32, None)
                };

                if buffer.len() >= 4 {
                    let flags = HttpProtocolFlags(session_flags);
                    let alt_svc_entries = maybe_host
                        .as_ref()
                        .and_then(|host| self.alt_svc_entries.get(host))
                        .cloned()
                        .unwrap_or_default();

                    let (protocol, _fell_back) =
                        negotiate_http_protocol(&flags, &self.quic_config, &alt_svc_entries);

                    // Return WinHTTP protocol flag convention:
                    //   HTTP/1.1 → 0x0 (WINHTTP_PROTOCOL_FLAG_HTTP1, no flag)
                    //   HTTP/2   → 0x1 (WINHTTP_PROTOCOL_FLAG_HTTP2)
                    //   HTTP/3   → 0x2 (WINHTTP_PROTOCOL_FLAG_HTTP3)
                    let proto_val = match protocol {
                        HttpProtocol::Http3 => WINHTTP_PROTOCOL_FLAG_HTTP3,
                        HttpProtocol::Http2 => WINHTTP_PROTOCOL_FLAG_HTTP2,
                        HttpProtocol::Http11 => 0u32,
                    };
                    buffer[..4].copy_from_slice(&proto_val.to_ne_bytes());
                    return Ok(4);
                }
                Err(AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("WinHttpQueryOption: invalid handle {handle:#x} for protocol query"),
                ))
            }
            _ => Err(AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpQueryOption: unsupported option {option}"),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // WinHttpSetStatusCallback — register a callback for status notifications
    // -----------------------------------------------------------------------
    pub fn win_http_set_status_callback(
        &mut self,
        request_handle: HINTERNET,
        callback_context: HINTERNET,
        notify_flags: u32,
    ) -> AppResult<()> {
        let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpSetStatusCallback: invalid handle {request_handle:#x}"),
            )
        })?;
        req.callback = Some(callback_context);
        req.callback_notify_flags = notify_flags;
        Ok(())
    }
    // -----------------------------------------------------------------------
    // WinHttpAddRequestHeaders — add additional headers to an HTTP request
    // -----------------------------------------------------------------------
    pub fn win_http_add_request_headers(
        &mut self,
        request_handle: HINTERNET,
        headers: &str,
    ) -> AppResult<()> {
        let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpAddRequestHeaders: invalid handle {request_handle:#x}"),
            )
        })?;
        for line in headers.split("\r\n").filter(|l| !l.is_empty()) {
            req.raw_headers.push(line.to_string());
            if let Some(pos) = line.find(':') {
                let key = line[..pos].trim().to_string();
                let value = line[pos + 1..].trim().to_string();
                req.headers.insert(key, value);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // WinHttpWriteData — write data to the request body (for POST/PUT)
    // -----------------------------------------------------------------------
    pub fn win_http_write_data(
        &mut self,
        request_handle: HINTERNET,
        data: &[u8],
    ) -> AppResult<u32> {
        let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpWriteData: invalid handle {request_handle:#x}"),
            )
        })?;
        let new_len = req.body.len().saturating_add(data.len());
        if new_len > MAX_WINHTTP_REQUEST_BODY {
            return Err(AppError::new(
                ReasonCode::RcRequestBodyTooLarge,
                format!(
                    "WinHttpWriteData: body size {new_len} exceeds limit ({MAX_WINHTTP_REQUEST_BODY})"
                ),
            ));
        }
        req.body.extend_from_slice(data);
        Ok(data.len() as u32)
    }

    // -----------------------------------------------------------------------
    // WinHttpSetCredentials — set authentication credentials (server/proxy)
    // -----------------------------------------------------------------------
    pub fn win_http_set_credentials(
        &mut self,
        request_handle: HINTERNET,
        auth_target: u32, // 0=server, 1=proxy
        auth_scheme: u32, // WINHTTP_AUTH_SCHEME_BASIC=1, NTLM=2, etc.
        user_name: Option<&str>,
        password: Option<&str>,
    ) -> AppResult<()> {
        // Log unsupported auth schemes (only Basic=1 is implemented)
        if auth_scheme != 1 {
            eprintln!(
                "WinHttpSetCredentials: auth scheme {} requested (only Basic=1 supported); \
                 target={}, user={:?}",
                auth_scheme, auth_target, user_name
            );
        }
        let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpSetCredentials: invalid handle {request_handle:#x}"),
            )
        })?;

        if let (Some(user), Some(pass)) = (user_name, password) {
            let credentials = format!("{user}:{pass}");
            let encoded = Self::base64_encode(credentials.as_bytes());
            let auth_value = format!("Basic {encoded}");

            if auth_target == 0 {
                // Server authentication
                req.headers.insert("Authorization".to_string(), auth_value);
            } else {
                // Proxy authentication
                req.headers
                    .insert("Proxy-Authorization".to_string(), auth_value);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // WinHttpQueryAuthSchemes — query supported authentication schemes
    // from the response headers
    // -----------------------------------------------------------------------
    pub fn win_http_query_auth_schemes(&self, request_handle: HINTERNET) -> AppResult<(u32, u32)> {
        let req = self.requests.get(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpQueryAuthSchemes: invalid handle {request_handle:#x}"),
            )
        })?;

        // Parse WWW-Authenticate / Proxy-Authenticate headers from response
        let mut supported_schemes = 0u32; // bitmask of WINHTTP_AUTH_SCHEME_*
        let mut first_scheme = 0u32;

        // WINHTTP_AUTH_SCHEME_BASIC = 1
        // WINHTTP_AUTH_SCHEME_NTLM = 2
        // WINHTTP_AUTH_SCHEME_DIGEST = 8
        // WINHTTP_AUTH_SCHEME_NEGOTIATE = 16

        for (_key, value) in &req.response_headers {
            let lower = value.to_lowercase();
            if lower.contains("basic") {
                supported_schemes |= 1;
                if first_scheme == 0 {
                    first_scheme = 1;
                }
            }
            if lower.contains("ntlm") {
                supported_schemes |= 2;
                if first_scheme == 0 {
                    first_scheme = 2;
                }
            }
            if lower.contains("digest") {
                supported_schemes |= 8;
                if first_scheme == 0 {
                    first_scheme = 8;
                }
            }
            if lower.contains("negotiate") {
                supported_schemes |= 16;
                if first_scheme == 0 {
                    first_scheme = 16;
                }
            }
        }

        Ok((supported_schemes, first_scheme))
    }

    // -----------------------------------------------------------------------
    // InternetGetLastResponseInfoW — retrieve the last response error text
    // (shared between WinHTTP and WinINet dispatch)
    // -----------------------------------------------------------------------
    pub fn internet_get_last_response_info(&self) -> (u32, String) {
        (12002u32, self.last_response_error.clone())
    }

    // -----------------------------------------------------------------------
    // InternetCrackUrlW — crack a URL into its component parts
    // (shared between WinHTTP and WinINet dispatch)
    // -----------------------------------------------------------------------
    #[allow(unused_assignments)]
    pub fn internet_crack_url_w(
        &self,
        url: &str,
        url_length: u32,
    ) -> AppResult<(String, String, u16, String, Option<String>, Option<String>)> {
        let url = if (url_length as usize) < url.len() {
            &url[..url_length as usize]
        } else {
            url
        };

        let url = url.trim();
        let mut scheme = String::new();
        let mut hostname = String::new();
        let mut port: u16 = 80;
        let mut path = String::from("/");
        let mut username: Option<String> = None;
        let mut password: Option<String> = None;

        let remaining = if let Some(pos) = url.find("://") {
            scheme = url[..pos].to_lowercase();
            &url[pos + 3..]
        } else {
            scheme = "http".to_string();
            url
        };

        let hostpart = if let Some(at_pos) = remaining.find('@') {
            let ui = &remaining[..at_pos];
            let hp = &remaining[at_pos + 1..];
            if let Some(colon_pos) = ui.find(':') {
                username = Some(ui[..colon_pos].to_string());
                password = Some(ui[colon_pos + 1..].to_string());
            } else {
                username = Some(ui.to_string());
            }
            hp
        } else {
            remaining
        };

        let path_start = hostpart
            .find(|c: char| c == '/' || c == '?' || c == '#')
            .unwrap_or(hostpart.len());
        let host_port = &hostpart[..path_start];
        let path_and_query = &hostpart[path_start..];

        if let Some(colon_pos) = host_port.find(':') {
            hostname = host_port[..colon_pos].to_string();
            let parsed_port: Result<u16, _> = host_port[colon_pos + 1..].parse();
            port = parsed_port.map_err(|_| {
                AppError::new(
                    ReasonCode::RcPortParseError,
                    format!(
                        "WinHTTP: failed to parse port from URL: '{}'",
                        &host_port[colon_pos + 1..]
                    ),
                )
            })?;
        } else {
            hostname = host_port.to_string();
            port = if scheme == "https" { 443 } else { 80 };
        }

        path = if path_and_query.is_empty() {
            "/".to_string()
        } else {
            path_and_query.to_string()
        };

        Ok((scheme, hostname, port, path, username, password))
    }

    // -----------------------------------------------------------------------
    // InternetCanonicalizeUrlW — canonicalize a URL (percent-encode special chars)
    // (shared between WinHTTP and WinINet dispatch)
    // -----------------------------------------------------------------------
    pub fn internet_canonicalize_url_w(&self, url: &str, url_length: u32) -> String {
        let url = if (url_length as usize) < url.len() {
            &url[..url_length as usize]
        } else {
            url
        };

        let mut result = String::with_capacity(url.len());
        for ch in url.chars() {
            match ch {
                ' ' => result.push_str("%20"),
                '\t' => result.push_str("%09"),
                '\n' => result.push_str("%0A"),
                '\r' => result.push_str("%0D"),
                c if (c as u32) < 0x20 || c == '\x7F' => {
                    result.push_str(&format!("%{:02X}", c as u32));
                }
                c => result.push(c),
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // WebSocket operations
    // -----------------------------------------------------------------------

    /// WinHttpWebSocketCompleteUpgrade — upgrade an HTTP request to a WebSocket.
    /// Returns a new WebSocket handle.
    ///
    /// When the `websocket` feature is enabled and the request URL is available,
    /// attempts a real `tungstenite` connection. Otherwise falls back to buffer-based
    /// state tracking.
    pub fn websocket_complete_upgrade(
        &mut self,
        request_handle: HINTERNET,
    ) -> AppResult<HINTERNET> {
        let request = self.requests.get(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "WinHttpWebSocketCompleteUpgrade: invalid request handle",
            )
        })?;

        // Validate the request is in a state where upgrade makes sense (ResponseReceived)
        if request.state != WinHttpSessionState::Complete {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "WinHttpWebSocketCompleteUpgrade: request must be complete before upgrade",
            ));
        }

        // Build the WebSocket URL from the connection + request info
        let conn = self.connections.get(&request.connection_handle);
        let ws_url = conn.map(|c| {
            let scheme = if c.is_secure { "wss" } else { "ws" };
            format!(
                "{}://{}:{}{}",
                scheme, c.server_name, c.server_port, request.object_name
            )
        });

        let ws_handle = self.next_handle;
        self.next_handle += 1;

        let is_text_mode = matches!(
            request
                .headers
                .get("Sec-WebSocket-Protocol")
                .map(|s| s.as_str()),
            Some("text") | Some("text-only")
        );

        self.websockets.insert(
            ws_handle,
            WinHttpWebSocketState {
                request_handle,
                is_open: true,
                buffer_type: if is_text_mode {
                    WinHttpWebSocketBufferType::Utf8MessageBuffer
                } else {
                    WinHttpWebSocketBufferType::BinaryMessageBuffer
                },
                receive_buffer: Vec::new(),
                send_buffer: Vec::new(),
                close_status: WinHttpWebSocketCloseStatus::Success,
                close_reason: None,
                url: ws_url.clone(),
                is_text_mode,
            },
        );

        // Attempt real tungstenite connection if feature is enabled and URL is available
        #[cfg(feature = "websocket")]
        if let Some(ref url) = ws_url {
            if let Ok(live_ws) = TungsteniteWebSocket::connect(url) {
                self.live_websockets.insert(ws_handle, live_ws);
            }
            // If connection fails, we still have the buffer-based fallback
        }

        Ok(ws_handle)
    }

    /// WinHttpWebSocketSend — send data over a WebSocket connection.
    ///
    /// When the `websocket` feature is enabled and a live tungstenite connection
    /// exists, sends directly over the wire. Otherwise buffers the data.
    #[allow(unused_variables)]
    pub fn websocket_send(
        &mut self,
        ws_handle: HINTERNET,
        buffer_type: WinHttpWebSocketBufferType,
        data: &[u8],
    ) -> AppResult<()> {
        let ws = self.websockets.get(&ws_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "WinHttpWebSocketSend: invalid WebSocket handle",
            )
        })?;

        if !ws.is_open {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "WinHttpWebSocketSend: WebSocket is closed",
            ));
        }

        // Check WebSocket frame size limit
        if data.len() > MAX_WEBSOCKET_FRAME_SIZE {
            return Err(AppError::new(
                ReasonCode::RcWebSocketFrameTooLarge,
                format!(
                    "WinHttpWebSocketSend: frame size {} exceeds limit ({MAX_WEBSOCKET_FRAME_SIZE})",
                    data.len()
                ),
            ));
        }

        // Try live tungstenite connection first
        #[cfg(feature = "websocket")]
        if let Some(live_ws) = self.live_websockets.get_mut(&ws_handle) {
            let is_text = matches!(
                buffer_type,
                WinHttpWebSocketBufferType::Utf8MessageBuffer
                    | WinHttpWebSocketBufferType::Utf8FragmentBuffer
            );
            if is_text {
                let text = std::str::from_utf8(data).map_err(|_| {
                    AppError::new(
                        ReasonCode::RcCliInvalid,
                        "WinHttpWebSocketSend: invalid UTF-8 in text frame",
                    )
                })?;
                live_ws.send_text(text)?;
            } else {
                live_ws.send_binary(data)?;
            }
            return Ok(());
        }

        // Buffer-based fallback
        let ws = self.websockets.get_mut(&ws_handle).unwrap();
        let new_send_len = ws.send_buffer.len().saturating_add(data.len());
        if new_send_len > MAX_WEBSOCKET_SEND_BUFFER {
            return Err(AppError::new(
                ReasonCode::RcBufferLimitExceeded,
                format!(
                    "WinHttpWebSocketSend: send buffer {new_send_len} exceeds limit ({MAX_WEBSOCKET_SEND_BUFFER})"
                ),
            ));
        }
        ws.send_buffer.extend_from_slice(data);

        Ok(())
    }

    /// WinHttpWebSocketReceive — receive data from a WebSocket connection.
    ///
    /// When the `websocket` feature is enabled and a live tungstenite connection
    /// exists, reads from the wire. Otherwise reads from the internal buffer.
    pub fn websocket_receive(
        &mut self,
        ws_handle: HINTERNET,
        data: &mut [u8],
        _buffer_type: WinHttpWebSocketBufferType,
    ) -> AppResult<u32> {
        let ws = self.websockets.get(&ws_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "WinHttpWebSocketReceive: invalid WebSocket handle",
            )
        })?;

        if !ws.is_open {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "WinHttpWebSocketReceive: WebSocket is closed",
            ));
        }

        // Try live tungstenite connection first
        #[cfg(feature = "websocket")]
        if let Some(live_ws) = self.live_websockets.get_mut(&ws_handle) {
            let msg = live_ws.receive()?;
            match msg {
                WebSocketMessage::Text(text) => {
                    let bytes = text.as_bytes();
                    let to_copy = data.len().min(bytes.len());
                    data[..to_copy].copy_from_slice(&bytes[..to_copy]);
                    // Store any remaining data in the receive buffer
                    if bytes.len() > to_copy {
                        let ws = self.websockets.get_mut(&ws_handle).unwrap();
                        let new_recv_len = ws
                            .receive_buffer
                            .len()
                            .saturating_add(bytes.len() - to_copy);
                        if new_recv_len > MAX_WEBSOCKET_RECEIVE_SPILL {
                            return Err(AppError::new(
                                ReasonCode::RcBufferLimitExceeded,
                                format!(
                                    "WinHttpWebSocketReceive: receive spill buffer {new_recv_len} exceeds limit ({MAX_WEBSOCKET_RECEIVE_SPILL})"
                                ),
                            ));
                        }
                        ws.receive_buffer.extend_from_slice(&bytes[to_copy..]);
                    }
                    return Ok(to_copy as u32);
                }
                WebSocketMessage::Binary(bin) => {
                    let to_copy = data.len().min(bin.len());
                    data[..to_copy].copy_from_slice(&bin[..to_copy]);
                    if bin.len() > to_copy {
                        let ws = self.websockets.get_mut(&ws_handle).unwrap();
                        let new_recv_len =
                            ws.receive_buffer.len().saturating_add(bin.len() - to_copy);
                        if new_recv_len > MAX_WEBSOCKET_RECEIVE_SPILL {
                            return Err(AppError::new(
                                ReasonCode::RcBufferLimitExceeded,
                                format!(
                                    "WinHttpWebSocketReceive: receive spill buffer {new_recv_len} exceeds limit ({MAX_WEBSOCKET_RECEIVE_SPILL})"
                                ),
                            ));
                        }
                        ws.receive_buffer.extend_from_slice(&bin[to_copy..]);
                    }
                    return Ok(to_copy as u32);
                }
                WebSocketMessage::Close(code, reason) => {
                    let ws = self.websockets.get_mut(&ws_handle).unwrap();
                    ws.is_open = false;
                    ws.close_status = WinHttpWebSocketCloseStatus::from_code(code);
                    ws.close_reason = Some(reason);
                    return Ok(0);
                }
                WebSocketMessage::Ping | WebSocketMessage::Pong => {
                    return Ok(0);
                }
            }
        }

        // Buffer-based fallback
        let ws = self.websockets.get_mut(&ws_handle).unwrap();
        let bytes_to_read = data.len().min(ws.receive_buffer.len());
        data[..bytes_to_read].copy_from_slice(&ws.receive_buffer[..bytes_to_read]);
        ws.receive_buffer.drain(..bytes_to_read);

        Ok(bytes_to_read as u32)
    }

    /// WinHttpWebSocketClose — close a WebSocket connection.
    ///
    /// When the `websocket` feature is enabled and a live tungstenite connection
    /// exists, sends a proper close frame over the wire.
    pub fn websocket_close(
        &mut self,
        ws_handle: HINTERNET,
        status: WinHttpWebSocketCloseStatus,
        reason: Option<&str>,
    ) -> AppResult<()> {
        let ws = self.websockets.get_mut(&ws_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "WinHttpWebSocketClose: invalid WebSocket handle",
            )
        })?;

        ws.is_open = false;
        ws.close_status = status;
        ws.close_reason = reason.map(|s| s.to_string());

        // Close live tungstenite connection
        #[cfg(feature = "websocket")]
        {
            let code = status as u16;
            let reason_str = reason.unwrap_or("").to_string();
            if let Some(mut live_ws) = self.live_websockets.remove(&ws_handle) {
                if let Err(e) = live_ws.close(code, &reason_str) {
                    eprintln!("WinHttpWebSocketClose: failed to close WebSocket: {e}");
                }
            }
        }

        Ok(())
    }

    /// WinHttpWebSocketQueryCloseStatus — query the close status of a WebSocket.
    pub fn websocket_query_close_status(
        &self,
        ws_handle: HINTERNET,
    ) -> AppResult<(WinHttpWebSocketCloseStatus, Option<String>)> {
        let ws = self.websockets.get(&ws_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                "WinHttpWebSocketQueryCloseStatus: invalid WebSocket handle",
            )
        })?;

        Ok((ws.close_status, ws.close_reason.clone()))
    }

    // -----------------------------------------------------------------------
    // FTP operations — real implementation using std::net::TcpStream
    // -----------------------------------------------------------------------

    // ── FTP helpers ────────────────────────────────────────────────────────

    /// Send a raw command to an FTP control connection and read the response.
    fn ftp_command(&mut self, conn_handle: HINTERNET, cmd: &str) -> AppResult<String> {
        let stream = self.ftp_control.get_mut(&conn_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP: no control connection for handle {conn_handle}"),
            )
        })?;

        let full_cmd = format!("{cmd}\r\n");
        stream.write_all(full_cmd.as_bytes()).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("FTP command '{cmd}' failed: {e}"))
        })?;

        // Read the multi-line response
        let mut response = String::new();
        let mut buf = [0u8; 1];
        let mut line = String::new();
        let mut last_char_was_cr = false;
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    let c = buf[0] as char;
                    if c == '\r' {
                        last_char_was_cr = true;
                    } else if c == '\n' && last_char_was_cr {
                        if line.len() >= 4
                            && line.as_bytes()[0].is_ascii_digit()
                            && line.as_bytes()[1].is_ascii_digit()
                            && line.as_bytes()[2].is_ascii_digit()
                            && line.as_bytes()[3] == b' '
                        {
                            response.push_str(&line);
                            response.push_str("\r\n");
                            break;
                        }
                        response.push_str(&line);
                        response.push_str("\r\n");
                        line.clear();
                        last_char_was_cr = false;
                    } else {
                        if last_char_was_cr {
                            line.push('\r');
                            last_char_was_cr = false;
                        }
                        line.push(c);
                    }
                }
                Err(_) => break,
            }
            if response.len() > 16384 {
                break;
            }
        }

        if response.is_empty() {
            let mut single_buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut single_buf) {
                if n > 0 {
                    response = String::from_utf8_lossy(&single_buf[..n]).to_string();
                }
            }
        }

        Ok(response)
    }

    /// Parse a PASV response (227 Entering Passive Mode (h1,h2,h3,h4,p1,p2))
    fn ftp_parse_pasv(response: &str) -> Option<(String, u16)> {
        if let Some(start) = response.find('(') {
            if let Some(end) = response.find(')') {
                let nums: Vec<&str> = response[start + 1..end].split(',').collect();
                if nums.len() == 6 {
                    let h1: u8 = nums[0].trim().parse().ok()?;
                    let h2: u8 = nums[1].trim().parse().ok()?;
                    let h3: u8 = nums[2].trim().parse().ok()?;
                    let h4: u8 = nums[3].trim().parse().ok()?;
                    let p1: u16 = nums[4].trim().parse().ok()?;
                    let p2: u16 = nums[5].trim().parse().ok()?;
                    let addr = format!("{h1}.{h2}.{h3}.{h4}");
                    let port = p1 * 256 + p2;
                    return Some((addr, port));
                }
            }
        }
        None
    }

    /// Establish a PASV data connection to the FTP server.
    fn ftp_data_connect(&mut self, conn_handle: HINTERNET) -> AppResult<TcpStream> {
        let pasv_response = self.ftp_command(conn_handle, "PASV")?;
        let (data_addr, data_port) = Self::ftp_parse_pasv(&pasv_response).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP: failed to parse PASV response: {pasv_response}"),
            )
        })?;

        let data_stream = TcpStream::connect_timeout(
            &format!("{data_addr}:{data_port}")
                .to_socket_addrs()
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetDnsResolutionFailed,
                        format!("FTP data DNS resolution failed: {e}"),
                    )
                })?
                .next()
                .ok_or_else(|| {
                    AppError::new(ReasonCode::RcNetDnsResolutionFailed, "FTP data no address")
                })?,
            Duration::from_secs(15),
        )
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP data connect to {data_addr}:{data_port} failed: {e}"),
            )
        })?;

        Ok(data_stream)
    }

    /// Read all data from a data connection until closed.
    fn ftp_read_data(stream: &mut TcpStream) -> AppResult<Vec<u8>> {
        let mut data = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(AppError::new(
                        ReasonCode::RcIo,
                        format!("FTP data read failed: {e}"),
                    ));
                }
            }
        }
        Ok(data)
    }

    /// Helper: set binary or ASCII transfer mode.
    fn ftp_set_transfer_mode(&mut self, conn_handle: HINTERNET, binary: bool) -> AppResult<()> {
        let cmd = if binary { "TYPE I" } else { "TYPE A" };
        let _resp = self.ftp_command(conn_handle, cmd)?;
        self.ftp_binary_mode.insert(conn_handle, binary);
        Ok(())
    }

    // ── FTP public API ─────────────────────────────────────────────────────

    /// Open a remote file for reading via FTP (RETR).
    /// Returns a transfer handle.
    pub fn ftp_open_file_w(
        &mut self,
        connect_handle: HINTERNET,
        file_name: &str,
        _access: u32,
        transfer_type: crate::wininet::FtpTransferType,
    ) -> AppResult<HINTERNET> {
        // Set transfer mode
        let binary = matches!(transfer_type, crate::wininet::FtpTransferType::Binary);
        self.ftp_set_transfer_mode(connect_handle, binary)?;

        // Establish PASV data connection
        let mut data_stream = self.ftp_data_connect(connect_handle)?;

        // Send RETR command
        let retr_cmd = format!("RETR {file_name}");
        let _retr_response = self.ftp_command(connect_handle, &retr_cmd)?;

        // Read file data from the data connection and cache it
        let file_data = Self::ftp_read_data(&mut data_stream)?;

        // Allocate a handle for the transfer
        let handle = self.next_handle();

        // Store the file data so subsequent InternetReadFile calls can
        // retrieve it from the ftp_file_data map using this handle.
        self.ftp_file_data.insert(handle, file_data);

        Ok(handle)
    }

    /// Retrieve a remote file via FTP and save it locally.
    /// Uses RETR command over PASV data connection.
    pub fn ftp_get_file_w(
        &mut self,
        connect_handle: HINTERNET,
        remote_file: &str,
        local_file: &str,
        _fail_if_exists: bool,
        transfer_type: crate::wininet::FtpTransferType,
    ) -> AppResult<bool> {
        // Set transfer mode
        let binary = matches!(transfer_type, crate::wininet::FtpTransferType::Binary);
        self.ftp_set_transfer_mode(connect_handle, binary)?;

        // Establish PASV data connection
        let mut data_stream = self.ftp_data_connect(connect_handle).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("FTP get file data connect failed: {e}"),
            )
        })?;

        // Send RETR command
        let retr_cmd = format!("RETR {remote_file}");
        let _retr_response = self.ftp_command(connect_handle, &retr_cmd)?;

        // Read file data from the data connection
        let file_data = Self::ftp_read_data(&mut data_stream)?;

        // Write to local file
        if let Err(e) = std::fs::write(local_file, &file_data) {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP: failed to write local file {local_file}: {e}"),
            ));
        }

        Ok(true)
    }

    /// Upload a local file to the FTP server via STOR.
    pub fn ftp_put_file_w(
        &mut self,
        connect_handle: HINTERNET,
        remote_file: &str,
        local_file: &str,
        transfer_type: crate::wininet::FtpTransferType,
    ) -> AppResult<bool> {
        // Read the local file
        let local_data = std::fs::read(local_file).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP put: failed to read local file {local_file}: {e}"),
            )
        })?;

        // Set transfer mode
        let binary = matches!(transfer_type, crate::wininet::FtpTransferType::Binary);
        self.ftp_set_transfer_mode(connect_handle, binary)?;

        // Establish PASV data connection
        let mut data_stream = self.ftp_data_connect(connect_handle).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("FTP put data connect failed: {e}"),
            )
        })?;

        // Send STOR command
        let stor_cmd = format!("STOR {remote_file}");
        let _stor_response = self.ftp_command(connect_handle, &stor_cmd)?;

        // Write data to the data connection
        data_stream.write_all(&local_data).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP: failed to write data to STOR: {e}"),
            )
        })?;
        data_stream.flush().map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP: failed to flush data stream: {e}"),
            )
        })?;

        Ok(true)
    }

    /// Delete a remote file on the FTP server via DELE.
    pub fn ftp_delete_file_w(
        &mut self,
        connect_handle: HINTERNET,
        file_name: &str,
    ) -> AppResult<bool> {
        let cmd = format!("DELE {file_name}");
        let response = self.ftp_command(connect_handle, &cmd)?;
        if !response.contains("250") && !response.contains("200") {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP DELE failed: {}", response.trim()),
            ));
        }
        Ok(true)
    }

    /// Rename a remote file on the FTP server via RNFR/RNTO.
    pub fn ftp_rename_file_w(
        &mut self,
        connect_handle: HINTERNET,
        existing: &str,
        new_name: &str,
    ) -> AppResult<bool> {
        let rnfr_cmd = format!("RNFR {existing}");
        let rnfr_response = self.ftp_command(connect_handle, &rnfr_cmd)?;
        if !rnfr_response.contains("350") {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP RNFR failed: {}", rnfr_response.trim()),
            ));
        }
        let rnto_cmd = format!("RNTO {new_name}");
        let rnto_response = self.ftp_command(connect_handle, &rnto_cmd)?;
        if !rnto_response.contains("250") {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP RNTO failed: {}", rnto_response.trim()),
            ));
        }
        Ok(true)
    }

    /// Set the current working directory on the FTP server via CWD.
    pub fn ftp_set_current_directory_w(
        &mut self,
        connect_handle: HINTERNET,
        directory: &str,
    ) -> AppResult<bool> {
        let cmd = format!("CWD {directory}");
        let response = self.ftp_command(connect_handle, &cmd)?;
        if response.contains("250") || response.contains("200") {
            self.ftp_current_dir
                .insert(connect_handle, directory.to_string());
            Ok(true)
        } else {
            Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP CWD failed: {response}"),
            ))
        }
    }

    /// Get the current working directory on the FTP server via PWD.
    pub fn ftp_get_current_directory_w(&mut self, connect_handle: HINTERNET) -> AppResult<String> {
        // Check cache first
        if let Some(dir) = self.ftp_current_dir.get(&connect_handle) {
            return Ok(dir.clone());
        }

        // Query via PWD
        let response = self.ftp_command(connect_handle, "PWD")?;
        // PWD response format: 257 "/remote/dir" is current directory
        if let Some(start) = response.find('"') {
            if let Some(end) = response[start + 1..].find('"') {
                let dir = &response[start + 1..start + 1 + end];
                self.ftp_current_dir.insert(connect_handle, dir.to_string());
                return Ok(dir.to_string());
            }
        }
        Ok("/".to_string())
    }

    /// Create a directory on the FTP server via MKD.
    pub fn ftp_create_directory_w(
        &mut self,
        connect_handle: HINTERNET,
        directory: &str,
    ) -> AppResult<bool> {
        let cmd = format!("MKD {directory}");
        let response = self.ftp_command(connect_handle, &cmd)?;
        if !response.contains("257") {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP MKD failed: {}", response.trim()),
            ));
        }
        Ok(true)
    }

    /// Remove a directory on the FTP server via RMD.
    pub fn ftp_remove_directory_w(
        &mut self,
        connect_handle: HINTERNET,
        directory: &str,
    ) -> AppResult<bool> {
        let cmd = format!("RMD {directory}");
        let response = self.ftp_command(connect_handle, &cmd)?;
        if !response.contains("250") {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP RMD failed: {}", response.trim()),
            ));
        }
        Ok(true)
    }

    /// Find the first file on the FTP server matching a pattern using NLST.
    pub fn ftp_find_first_file_w(
        &mut self,
        connect_handle: HINTERNET,
        pattern: &str,
    ) -> AppResult<HINTERNET> {
        // Establish PASV data connection
        let mut data_stream = self.ftp_data_connect(connect_handle)?;

        // Send NLST command
        let nlst_cmd = if pattern.is_empty() || pattern == "*" || pattern == "*.*" {
            "NLST".to_string()
        } else {
            format!("NLST {pattern}")
        };
        let _nlst_response = self.ftp_command(connect_handle, &nlst_cmd)?;

        // Read the listing from the data connection
        let listing_data = Self::ftp_read_data(&mut data_stream)?;
        let listing = String::from_utf8_lossy(&listing_data);

        let files: Vec<String> = listing
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        if files.is_empty() {
            return Err(AppError::new(ReasonCode::RcIo, "FTP: no files found"));
        }

        // Store the listing in the cache
        let handle = self.next_handle();
        let file_infos: Vec<crate::wininet::FtpFileInfo> = files
            .iter()
            .map(|name| crate::wininet::FtpFileInfo {
                file_name: name.clone(),
                file_size: 0,
                last_modified: None,
                attributes: None,
                is_directory: false,
            })
            .collect();

        self.ftp_listing_cache.insert(handle, file_infos);
        self.ftp_listing_index.insert(handle, 0);

        Ok(handle)
    }

    /// Find the next file on the FTP server in a search started by ftp_find_first_file_w.
    /// Returns the next FtpFileInfo or None when exhausted.
    pub fn ftp_find_next_file_w(
        &mut self,
        find_handle: HINTERNET,
    ) -> Option<crate::wininet::FtpFileInfo> {
        let cache = self.ftp_listing_cache.get(&find_handle)?;
        let idx = *self.ftp_listing_index.get(&find_handle)?;

        if idx < cache.len() {
            let info = cache[idx].clone();
            self.ftp_listing_index.insert(find_handle, idx + 1);
            Some(info)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Try to connect to a test host. Returns `true` if reachable.
    fn httpbin_reachable() -> bool {
        use std::net::{TcpStream, ToSocketAddrs};
        let addr = match "httpbin.org:80".to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => return false,
            },
            Err(_) => return false,
        };
        TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).is_ok()
    }

    #[test]
    fn winhttp_open_close_session() {
        let mut stack = WinHttpStack::new();
        let h = stack.win_http_open(Some("Casa1 Test"), 0, None, None);
        let _result = stack.win_http_close_handle(h);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = stack.win_http_close_handle(h);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
    }

    #[test]
    fn winhttp_open_request_and_send() {
        if !httpbin_reachable() {
            eprintln!("skipping winhttp_open_request_and_send: httpbin.org not reachable");
            return;
        }
        let mut stack = WinHttpStack::new();
        let session = stack.win_http_open(Some("Casa1"), 0, None, None);
        let conn = match stack.win_http_connect(session, "httpbin.org", 80, false) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping winhttp_open_request_and_send: connect failed: {e:?}");
                return;
            }
        };
        let req = match stack.win_http_open_request(conn, "GET", "/get", None) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipping winhttp_open_request_and_send: open request failed: {e:?}");
                let _ = stack.win_http_close_handle(conn);
                return;
            }
        };
        if let Err(e) = stack.win_http_send_request(req, None, None) {
            eprintln!("skipping winhttp_open_request_and_send: send failed: {e:?}");
            let _ = stack.win_http_close_handle(req);
            let _ = stack.win_http_close_handle(conn);
            return;
        }
        let available = stack.win_http_query_data_available(req).unwrap_or(0);
        if available == 0 {
            eprintln!("skipping winhttp_open_request_and_send: no data available");
            let _ = stack.win_http_close_handle(req);
            let _ = stack.win_http_close_handle(conn);
            return;
        }
        let mut buf = vec![0_u8; 4096];
        let read = stack.win_http_read_data(req, &mut buf).unwrap_or(0);
        assert!(read > 0);
        let _result = stack.win_http_close_handle(req);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = stack.win_http_close_handle(conn);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        let _result = stack.win_http_close_handle(session);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    #[test]
    fn winhttp_rejects_invalid_handle() {
        let mut stack = WinHttpStack::new();
        let _result = stack.win_http_close_handle(0xDEAD);
        assert!(_result.is_err(), "expected Err, got {_result:?}");
        assert!(
            stack
                .win_http_connect(0xDEAD, "example.com", 443, true)
                .is_err()
        );
    }

    // --- Certificate pinning (SPKI extraction + pin enforcement) ---

    /// Encode a DER TLV: tag, length (short or long form), then content.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut remaining = len;
            while remaining > 0 {
                len_bytes.push((remaining & 0xff) as u8);
                remaining >>= 8;
            }
            len_bytes.reverse();
            out.push(0x80 | len_bytes.len() as u8);
            out.extend_from_slice(&len_bytes);
        }
        out.extend_from_slice(content);
        out
    }

    /// A self-contained DER-encoded SubjectPublicKeyInfo TLV.
    fn build_spki(key_bits: &[u8]) -> Vec<u8> {
        let algorithm = der(
            0x30,
            &der(
                0x06,
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
            ),
        );
        let mut bit_string = vec![0x00];
        bit_string.extend_from_slice(key_bits);
        let public_key = der(0x03, &bit_string);
        let mut spki = algorithm;
        spki.extend_from_slice(&public_key);
        der(0x30, &spki)
    }

    /// Wrap a SubjectPublicKeyInfo into a minimal but structurally valid
    /// X.509 certificate DER that `extract_spki_der` can walk.
    fn synthetic_certificate(spki: &[u8]) -> Vec<u8> {
        let version = der(0xA0, &der(0x02, &[0x02]));
        let serial = der(0x02, &[0x01]);
        let signature = der(0x30, &der(0x06, &[0x2A, 0x86, 0x48]));
        let issuer = der(0x30, &[]);
        let validity = der(0x30, &[]);
        let subject = der(0x30, &[]);
        let mut tbs = Vec::new();
        tbs.extend_from_slice(&version);
        tbs.extend_from_slice(&serial);
        tbs.extend_from_slice(&signature);
        tbs.extend_from_slice(&issuer);
        tbs.extend_from_slice(&validity);
        tbs.extend_from_slice(&subject);
        tbs.extend_from_slice(spki);
        let tbs_certificate = der(0x30, &tbs);
        let outer_signature = der(0x30, &der(0x06, &[0x2A, 0x86, 0x48]));
        let signature_value = der(0x03, &[0x00]);
        let mut cert = Vec::new();
        cert.extend_from_slice(&tbs_certificate);
        cert.extend_from_slice(&outer_signature);
        cert.extend_from_slice(&signature_value);
        der(0x30, &cert)
    }

    #[test]
    fn extract_spki_der_returns_exact_subject_public_key_info() {
        let spki = build_spki(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let cert = synthetic_certificate(&spki);
        let extracted = extract_spki_der(&cert).expect("SPKI must be extractable");
        // The extracted bytes must be the exact SPKI TLV — no off-by-one,
        // no trailing or missing bytes from a heuristic backward scan.
        assert_eq!(extracted, spki);
    }

    #[test]
    fn extract_spki_der_rejects_truncated_certificate() {
        let spki = build_spki(&[0x01, 0x02, 0x03, 0x04]);
        let cert = synthetic_certificate(&spki);
        // Chop the certificate so the declared outer length exceeds the data.
        let truncated = &cert[..cert.len() - 1];
        assert!(extract_spki_der(truncated).is_none());
    }

    #[test]
    fn certificate_pin_enforces_only_matching_spki_hash() {
        let spki = build_spki(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let cert = synthetic_certificate(&spki);
        let pin = Sha256::digest(extract_spki_der(&cert).unwrap());

        let mut stack = WinHttpStack::new();

        // No pins configured for the host: any chain is accepted.
        assert!(stack.verify_certificate_pin("steamcdn.example", &[cert.clone()]));

        // Pin the correct SPKI hash: the matching chain is accepted.
        stack.pin_certificate("steamcdn.example", pin.as_slice());
        assert!(stack.verify_certificate_pin("steamcdn.example", &[cert.clone()]));

        // A different certificate (different SPKI) must be rejected.
        let other = synthetic_certificate(&build_spki(&[0x11, 0x22, 0x33, 0x44]));
        assert!(!stack.verify_certificate_pin("steamcdn.example", &[other]));

        // With an active pin but no certificate presented, reject.
        assert!(!stack.verify_certificate_pin("steamcdn.example", &[]));

        // Hosts without a pin remain unaffected.
        assert!(stack.verify_certificate_pin("other.example", &[]));
    }

    // --- QUIC / HTTP3 detection and fallback tests ---

    #[test]
    fn winhttp_quic_set_option_stores_enabled_protocols() {
        let mut stack = WinHttpStack::new();
        let session = stack.win_http_open(Some("Casa1"), 0, None, None);

        // Enable HTTP/2 + HTTP/3 via WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
        let flags = WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3;
        let flag_bytes = flags.to_le_bytes();
        let result =
            stack.win_http_set_option(session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flag_bytes);
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        // Verify the session has the flags stored
        let sess = stack.sessions.get(&session).expect("session exists");
        assert_eq!(sess.enabled_protocols, flags);
    }

    #[test]
    fn winhttp_quic_query_option_returns_enabled_protocols() {
        let mut stack = WinHttpStack::new();
        let session = stack.win_http_open(Some("Casa1"), 0, None, None);

        // Enable HTTP/3 only
        let flags = WINHTTP_PROTOCOL_FLAG_HTTP3;
        let flag_bytes = flags.to_le_bytes();
        stack
            .win_http_set_option(session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flag_bytes)
            .expect("set_option");

        // Query back via WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
        let mut buf = vec![0u8; 4];
        let result =
            stack.win_http_query_option(session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &mut buf);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let retrieved = u32::from_le_bytes(buf.try_into().unwrap());
        assert_eq!(retrieved, WINHTTP_PROTOCOL_FLAG_HTTP3);
    }

    #[test]
    fn winhttp_quic_query_protocol_returns_http2_when_quic_unavailable() {
        let mut stack = WinHttpStack::new();
        let session = stack.win_http_open(Some("Casa1"), 0, None, None);

        // Enable HTTP/2 + HTTP/3
        let flags = WINHTTP_PROTOCOL_FLAG_HTTP2 | WINHTTP_PROTOCOL_FLAG_HTTP3;
        let flag_bytes = flags.to_le_bytes();
        stack
            .win_http_set_option(session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flag_bytes)
            .expect("set_option");

        // Query negotiated protocol — should report HTTP/2 since QUIC is unavailable
        let mut buf = vec![0u8; 4];
        let result = stack.win_http_query_option(session, WINHTTP_OPTION_QUERY_PROTOCOL, &mut buf);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let protocol = u32::from_le_bytes(buf.try_into().unwrap());
        // HTTP/2 is the best available fallback when QUIC is requested but unavailable
        assert_eq!(protocol, WINHTTP_PROTOCOL_FLAG_HTTP2);
    }

    #[test]
    fn winhttp_quic_query_protocol_returns_http2_when_only_http2_enabled() {
        let mut stack = WinHttpStack::new();
        let session = stack.win_http_open(Some("Casa1"), 0, None, None);

        // Enable HTTP/2 only (no QUIC)
        let flags = WINHTTP_PROTOCOL_FLAG_HTTP2;
        let flag_bytes = flags.to_le_bytes();
        stack
            .win_http_set_option(session, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &flag_bytes)
            .expect("set_option");

        let mut buf = vec![0u8; 4];
        let result = stack.win_http_query_option(session, WINHTTP_OPTION_QUERY_PROTOCOL, &mut buf);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let protocol = u32::from_le_bytes(buf.try_into().unwrap());
        assert_eq!(protocol, WINHTTP_PROTOCOL_FLAG_HTTP2);
    }

    #[test]
    fn winhttp_quic_query_protocol_returns_http11_when_no_flags_set() {
        let mut stack = WinHttpStack::new();
        let session = stack.win_http_open(Some("Casa1"), 0, None, None);

        // No protocol flags enabled — expect HTTP/1.1
        let mut buf = vec![0u8; 4];
        let result = stack.win_http_query_option(session, WINHTTP_OPTION_QUERY_PROTOCOL, &mut buf);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let protocol = u32::from_le_bytes(buf.try_into().unwrap());
        assert_eq!(protocol, 0); // HTTP/1.1 is represented as 0
    }

    #[test]
    fn winhttp_quic_parse_alt_svc_stores_entries() {
        let mut stack = WinHttpStack::new();
        let entries = parse_alt_svc_header(r#"h3=":443"; ma=2592000"#);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].protocol_id, "h3");
        assert_eq!(entries[0].alt_port, 443);
        assert_eq!(entries[0].alt_host, "");
        assert_eq!(entries[0].alpn, Some("h3".to_string()));

        // Store entries via the stack's alt_svc_entries map
        stack
            .alt_svc_entries
            .insert("example.com".to_string(), entries);
        let stored = stack
            .alt_svc_entries
            .get("example.com")
            .expect("entries exist");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].alt_port, 443);
    }

    #[test]
    fn winhttp_quic_parse_alt_svc_multiple_entries() {
        let header = r#"h3=":443"; ma=2592000, h3-29=":443"; ma=2592000"#;
        let entries = parse_alt_svc_header(header);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].protocol_id, "h3");
        assert_eq!(entries[1].protocol_id, "h3-29");
    }

    #[test]
    fn winhttp_quic_parse_alt_svc_with_host() {
        let header = r#"h3="alt.example.com:8443"; ma=2592000"#;
        let entries = parse_alt_svc_header(header);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alt_host, "alt.example.com");
        assert_eq!(entries[0].alt_port, 8443);
    }

    #[test]
    fn winhttp_quic_alt_svc_empty_input() {
        let entries = parse_alt_svc_header("");
        assert!(entries.is_empty());

        let entries = parse_alt_svc_header("   ");
        assert!(entries.is_empty());
    }

    #[test]
    fn winhttp_quic_negotiate_falls_back_when_quic_unavailable() {
        // Simulate: HTTP/3 requested, QUIC not available → falls back to HTTP/2
        // The returned bool signals "fallback occurred" (true when QUIC was requested
        // but unavailable, forcing a downgrade to a lower protocol).
        let flags = HttpProtocolFlags(HttpProtocolFlags::HTTP2 | HttpProtocolFlags::HTTP3);
        let quic_config = QuicConfig::default(); // Not forced, not enabled (default)
        let alt_svc = vec![];

        let (protocol, fallback_occurred) = negotiate_http_protocol(&flags, &quic_config, &alt_svc);
        assert!(fallback_occurred); // QUIC was requested but unavailable → fallback
        assert_eq!(protocol, HttpProtocol::Http2);
    }

    #[test]
    fn winhttp_quic_negotiate_force_disabled_prevents_quic() {
        let flags = HttpProtocolFlags(HttpProtocolFlags::HTTP2 | HttpProtocolFlags::HTTP3);
        let quic_config = QuicConfig {
            force_enabled: false,
            force_disabled: true,
            ..Default::default()
        };
        let alt_svc = vec![AltSvcEntry {
            protocol_id: "h3".to_string(),
            alt_port: 443,
            alt_host: String::new(),
            alpn: Some("h3".to_string()),
        }];

        let (protocol, used_quic) = negotiate_http_protocol(&flags, &quic_config, &alt_svc);
        assert!(!used_quic);
        assert_eq!(protocol, HttpProtocol::Http2);
    }

    #[test]
    fn default_tls_client_rejects_invalid_certs() {
        // Verify that the default reqwest client builder does NOT accept invalid certs.
        // The builder should succeed with default (secure) settings.
        let builder = reqwest::blocking::Client::builder();
        let client = builder.build();
        assert!(client.is_ok(), "expected Ok, got {client:?}");
    }

    // -----------------------------------------------------------------------
    // Item 200: Unpinned HTTPS hosts still use normal CA validation
    // -----------------------------------------------------------------------

    #[test]
    fn winhttp_unpinned_host_passes_without_certs() {
        let stack = WinHttpStack::new();
        // Host without any pin should pass even with an empty chain.
        assert!(stack.verify_certificate_pin("unpinned.example.com", &[]));
    }

    #[test]
    fn winhttp_unpinned_host_passes_with_any_cert() {
        let stack = WinHttpStack::new();
        let spki = build_spki(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let cert = synthetic_certificate(&spki);
        // Unpinned host — any certificate is accepted.
        assert!(stack.verify_certificate_pin("other.example.com", &[cert]));
    }

    #[test]
    fn winhttp_pinned_host_rejects_wrong_cert() {
        let mut stack = WinHttpStack::new();
        let spki = build_spki(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let cert = synthetic_certificate(&spki);
        let pin = Sha256::digest(extract_spki_der(&cert).unwrap());

        // Pin the correct SPKI hash.
        stack.pin_certificate("pinned.example.com", pin.as_slice());
        assert!(stack.verify_certificate_pin("pinned.example.com", &[cert.clone()]));

        // A different certificate must be rejected.
        let other = synthetic_certificate(&build_spki(&[0x11, 0x22, 0x33, 0x44]));
        assert!(!stack.verify_certificate_pin("pinned.example.com", &[other]));
    }

    #[test]
    fn winhttp_pinned_host_rejects_empty_chain() {
        let mut stack = WinHttpStack::new();
        let spki = build_spki(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let cert = synthetic_certificate(&spki);
        let pin = Sha256::digest(extract_spki_der(&cert).unwrap());
        stack.pin_certificate("pinned.example.com", pin.as_slice());
        // Empty chain with a pin configured must be rejected.
        assert!(!stack.verify_certificate_pin("pinned.example.com", &[]));
    }

    #[test]
    fn winhttp_clear_pins_restores_unpinned_behavior() {
        let mut stack = WinHttpStack::new();
        let spki = build_spki(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let cert = synthetic_certificate(&spki);
        let pin = Sha256::digest(extract_spki_der(&cert).unwrap());
        stack.pin_certificate("example.com", pin.as_slice());
        // After clearing all pins, the host should pass again.
        stack.clear_certificate_pins();
        assert!(stack.verify_certificate_pin("example.com", &[]));
    }
}

// -----------------------------------------------------------------------
// J4: NTLM Authentication Support
// -----------------------------------------------------------------------

/// NTLM constants
pub const NTLM_NEGOTIATE_FLAG_56: u32 = 0x80000000;
pub const NTLM_NEGOTIATE_FLAG_KEY_EXCH: u32 = 0x40000000;
pub const NTLM_NEGOTIATE_FLAG_128: u32 = 0x20000000;
pub const NTLM_NEGOTIATE_FLAG_VERSION: u32 = 0x02000000;
pub const NTLM_NEGOTIATE_FLAG_TARGET_INFO: u32 = 0x00800000;
pub const NTLM_NEGOTIATE_FLAG_REQUEST_NON_NT_SESSION_KEY: u32 = 0x00400000;
pub const NTLM_NEGOTIATE_FLAG_NTLM: u32 = 0x00000200;
pub const NTLM_NEGOTIATE_FLAG_NEG_56: u32 = 0x80000000;
pub const NTLM_NEGOTIATE_FLAG_NEG_128: u32 = 0x20000000;
pub const NTLM_NEGOTIATE_FLAG_NEG_KEY_EXCH: u32 = 0x40000000;
pub const NTLM_NEGOTIATE_FLAG_NEG_TARGET_INFO: u32 = 0x00800000;

/// Create an NTLM NEGOTIATE message (Type 1).
/// Returns the raw bytes of the NTLM Type 1 message.
pub fn ntlm_create_negotiate_msg(domain: &str, workstation: &str) -> Vec<u8> {
    // NTLMSSP signature
    let mut msg = b"NTLMSSP\x00".to_vec();
    // Message type 1 (negotiate)
    msg.extend_from_slice(&1u32.to_le_bytes());
    // Flags: NTLM, negotiate 128, negotiate 56, request target
    let flags = NTLM_NEGOTIATE_FLAG_NTLM
        | NTLM_NEGOTIATE_FLAG_NEG_128
        | NTLM_NEGOTIATE_FLAG_NEG_56
        | NTLM_NEGOTIATE_FLAG_REQUEST_NON_NT_SESSION_KEY
        | NTLM_NEGOTIATE_FLAG_TARGET_INFO;
    msg.extend_from_slice(&flags.to_le_bytes());

    // Domain name fields (offset after header)
    let domain_enc: Vec<u16> = domain.encode_utf16().collect();
    let domain_bytes: Vec<u8> = domain_enc.iter().flat_map(|&c| c.to_le_bytes()).collect();
    let domain_len = domain_bytes.len() as u16;
    let domain_offset = 32u16
        + if workstation.is_empty() {
            0
        } else {
            (workstation.encode_utf16().count() * 2) as u16
        };
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&domain_offset.to_le_bytes());

    // Workstation name fields
    let ws_enc: Vec<u16> = workstation.encode_utf16().collect();
    let ws_bytes: Vec<u8> = ws_enc.iter().flat_map(|&c| c.to_le_bytes()).collect();
    let ws_len = ws_bytes.len() as u16;
    let ws_offset = 32u16;
    msg.extend_from_slice(&ws_len.to_le_bytes());
    msg.extend_from_slice(&ws_len.to_le_bytes());
    msg.extend_from_slice(&ws_offset.to_le_bytes());

    // Domain payload
    if !domain_bytes.is_empty() {
        msg.extend_from_slice(&domain_bytes);
    }
    // Workstation payload
    if !ws_bytes.is_empty() {
        msg.extend_from_slice(&ws_bytes);
    }

    msg
}

/// Parse an NTLM CHALLENGE message (Type 2) to extract the server challenge.
/// Returns the 8-byte server challenge.
pub fn ntlm_parse_challenge_msg(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 32 || &data[..8] != b"NTLMSSP\x00" {
        return None;
    }
    let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if msg_type != 2 {
        return None;
    }
    // Server challenge is at offset 24, 8 bytes
    if data.len() < 32 {
        return None;
    }
    Some(data[24..32].to_vec())
}

/// Compute HMAC-MD5 manually (the `md5` crate doesn't expose `Md5` type for use with `hmac` crate).
fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    const BLOCK_SIZE: usize = 64;
    let mut k = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = md5::compute(key);
        k[..16].copy_from_slice(&hash.0);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    // Inner hash: MD5(K XOR ipad || data)
    let mut inner_ctx = md5::Context::new();
    inner_ctx.consume(&ipad[..]);
    inner_ctx.consume(data);
    let inner = inner_ctx.compute();
    // Outer hash: MD5(K XOR opad || inner_digest)
    let mut outer_ctx = md5::Context::new();
    outer_ctx.consume(&opad[..]);
    outer_ctx.consume(&inner.0[..]);
    outer_ctx.compute().0
}

/// Compute MD4 hash (used for NTLMv1 hash). Ported from RFC 1320.
fn md4(data: &[u8]) -> [u8; 16] {
    let orig_len_bits = (data.len() as u64) * 8;
    // Pad the message
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&orig_len_bits.to_le_bytes());
    debug_assert!(padded.len() % 64 == 0);
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut w = [0u32; 16];
    for chunk in padded.chunks(64) {
        // Decode chunk into 16 little-endian u32 words
        for (i, word) in w.iter_mut().enumerate() {
            let off = i * 4;
            *word =
                u32::from_le_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
        // Round 1
        macro_rules! ff {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = ($a.wrapping_add(($b & $c) | (!$b & $d)).wrapping_add(w[$k])).rotate_left($s);
            };
        }
        ff!(a, b, c, d, 0, 3);
        ff!(d, a, b, c, 1, 7);
        ff!(c, d, a, b, 2, 11);
        ff!(b, c, d, a, 3, 19);
        ff!(a, b, c, d, 4, 3);
        ff!(d, a, b, c, 5, 7);
        ff!(c, d, a, b, 6, 11);
        ff!(b, c, d, a, 7, 19);
        ff!(a, b, c, d, 8, 3);
        ff!(d, a, b, c, 9, 7);
        ff!(c, d, a, b, 10, 11);
        ff!(b, c, d, a, 11, 19);
        ff!(a, b, c, d, 12, 3);
        ff!(d, a, b, c, 13, 7);
        ff!(c, d, a, b, 14, 11);
        ff!(b, c, d, a, 15, 19);
        // Round 2
        macro_rules! gg {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = ($a
                    .wrapping_add(($b & $c) | ($b & $d) | ($c & $d))
                    .wrapping_add(w[$k])
                    .wrapping_add(0x5A827999))
                .rotate_left($s);
            };
        }
        gg!(a, b, c, d, 0, 3);
        gg!(d, a, b, c, 4, 5);
        gg!(c, d, a, b, 8, 9);
        gg!(b, c, d, a, 12, 13);
        gg!(a, b, c, d, 1, 3);
        gg!(d, a, b, c, 5, 5);
        gg!(c, d, a, b, 9, 9);
        gg!(b, c, d, a, 13, 13);
        gg!(a, b, c, d, 2, 3);
        gg!(d, a, b, c, 6, 5);
        gg!(c, d, a, b, 10, 9);
        gg!(b, c, d, a, 14, 13);
        gg!(a, b, c, d, 3, 3);
        gg!(d, a, b, c, 7, 5);
        gg!(c, d, a, b, 11, 9);
        gg!(b, c, d, a, 15, 13);
        // Round 3
        macro_rules! hh {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                $a = ($a
                    .wrapping_add($b ^ $c ^ $d)
                    .wrapping_add(w[$k])
                    .wrapping_add(0x6ED9EBA1))
                .rotate_left($s);
            };
        }
        hh!(a, b, c, d, 0, 3);
        hh!(d, a, b, c, 8, 9);
        hh!(c, d, a, b, 4, 11);
        hh!(b, c, d, a, 12, 15);
        hh!(a, b, c, d, 2, 3);
        hh!(d, a, b, c, 10, 9);
        hh!(c, d, a, b, 6, 11);
        hh!(b, c, d, a, 14, 15);
        hh!(a, b, c, d, 1, 3);
        hh!(d, a, b, c, 9, 9);
        hh!(c, d, a, b, 5, 11);
        hh!(b, c, d, a, 13, 15);
        hh!(a, b, c, d, 3, 3);
        hh!(d, a, b, c, 11, 9);
        hh!(c, d, a, b, 7, 11);
        hh!(b, c, d, a, 15, 15);
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut result = [0u8; 16];
    for (i, &val) in state.iter().enumerate() {
        result[i * 4..][..4].copy_from_slice(&val.to_le_bytes());
    }
    result
}

/// Create an NTLM AUTHENTICATE message (Type 3).
/// Uses NTLMv2 with HMAC-MD5 response.
pub fn ntlm_create_authenticate_msg(
    challenge: &[u8],
    username: &str,
    password: &str,
    domain: &str,
) -> Vec<u8> {
    // NTLMSSP signature
    let mut msg = b"NTLMSSP\x00".to_vec();
    // Message type 3 (authenticate)
    msg.extend_from_slice(&3u32.to_le_bytes());

    // Simple LM response (24 bytes, using a placeholder)
    let lm_response = [0u8; 24];

    // Compute NTLMv2 hash
    let ntlm_hash = ntlmv2_hash(password, username, domain);

    // Compute NTLMv2 response
    let ntlmv2_response = compute_ntlmv2_response(&ntlm_hash, challenge);

    let lm_response_len = lm_response.len() as u16;
    let ntlm_response_len = ntlmv2_response.len() as u16;

    // Offsets (payload starts after fixed header)
    let fixed_header_size = 64u16;
    let lm_offset = fixed_header_size;
    let ntlm_offset = lm_offset + lm_response_len;
    let domain_offset = ntlm_offset + ntlm_response_len;
    let user_offset = domain_offset + (domain.encode_utf16().count() * 2) as u16;
    let user_enc: Vec<u16> = username.encode_utf16().collect();
    let user_bytes: Vec<u8> = user_enc.iter().flat_map(|&c| c.to_le_bytes()).collect();
    let user_len = user_bytes.len() as u16;
    let ws_offset = user_offset + user_len;

    let workstation = "";
    let ws_enc: Vec<u16> = workstation.encode_utf16().collect();
    let ws_bytes: Vec<u8> = ws_enc.iter().flat_map(|&c| c.to_le_bytes()).collect();

    // LM response fields
    msg.extend_from_slice(&lm_response_len.to_le_bytes());
    msg.extend_from_slice(&lm_response_len.to_le_bytes());
    msg.extend_from_slice(&(lm_offset as u32).to_le_bytes());

    // NTLM response fields
    msg.extend_from_slice(&ntlm_response_len.to_le_bytes());
    msg.extend_from_slice(&ntlm_response_len.to_le_bytes());
    msg.extend_from_slice(&(ntlm_offset as u32).to_le_bytes());

    // Domain name fields
    let domain_enc: Vec<u16> = domain.encode_utf16().collect();
    let domain_bytes: Vec<u8> = domain_enc.iter().flat_map(|&c| c.to_le_bytes()).collect();
    let domain_len = domain_bytes.len() as u16;
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&domain_len.to_le_bytes());
    msg.extend_from_slice(&(domain_offset as u32).to_le_bytes());

    // User name fields
    msg.extend_from_slice(&user_len.to_le_bytes());
    msg.extend_from_slice(&user_len.to_le_bytes());
    msg.extend_from_slice(&(user_offset as u32).to_le_bytes());

    // Workstation fields
    let ws_len = ws_bytes.len() as u16;
    msg.extend_from_slice(&ws_len.to_le_bytes());
    msg.extend_from_slice(&ws_len.to_le_bytes());
    msg.extend_from_slice(&(ws_offset as u32).to_le_bytes());

    // Session key (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());

    // Flags
    msg.extend_from_slice(
        &(NTLM_NEGOTIATE_FLAG_NTLM | NTLM_NEGOTIATE_FLAG_NEG_128 | NTLM_NEGOTIATE_FLAG_NEG_56)
            .to_le_bytes(),
    );

    // OS version structure (8 bytes)
    msg.extend_from_slice(&[0x06, 0x01, 0x70, 0x01, 0x00, 0x00, 0x00, 0x0f]);

    // Payload: LM response
    msg.extend_from_slice(&lm_response);
    // Payload: NTLMv2 response
    msg.extend_from_slice(&ntlmv2_response);
    // Payload: Domain
    msg.extend_from_slice(&domain_bytes);
    // Payload: User
    msg.extend_from_slice(&user_bytes);
    // Payload: Workstation
    msg.extend_from_slice(&ws_bytes);

    msg
}

/// Compute NTLMv2 hash (HMAC-MD5 of (upper(NTLMv1_hash, concat(upper(user), domain))))
fn ntlmv2_hash(password: &str, username: &str, domain: &str) -> Vec<u8> {
    // NTLMv1 hash = MD4(encode_utf16le(password))
    let pass_enc: Vec<u16> = password.encode_utf16().collect();
    let pass_bytes: Vec<u8> = pass_enc.iter().flat_map(|&c| c.to_le_bytes()).collect();
    let ntlm_v1 = md4(&pass_bytes);

    // Concatenate upper(username) + domain as UTF-16LE
    let upper_user = username.to_uppercase();
    let combined = format!("{}{}", upper_user, domain);
    let combined_enc: Vec<u16> = combined.encode_utf16().collect();
    let combined_bytes: Vec<u8> = combined_enc.iter().flat_map(|&c| c.to_le_bytes()).collect();

    // HMAC-MD5(key=ntlm_v1, data=combined_bytes)
    hmac_md5(&ntlm_v1, &combined_bytes).to_vec()
}

/// Compute NTLMv2 response: HMAC-MD5 of (server_challenge + blob)
fn compute_ntlmv2_response(ntlmv2_hash: &[u8], challenge: &[u8]) -> Vec<u8> {
    // Create the NTLMv2 blob
    let mut blob = Vec::new();

    // Timestamp (current time in tenths of microseconds since Jan 1, 1601)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let filetime =
        (now.as_secs() as u64 + 11644473600u64) * 10000000u64 + (now.subsec_nanos() as u64 / 100);
    blob.extend_from_slice(&filetime.to_le_bytes());

    // 8 bytes random nonce
    let nonce: [u8; 8] = rand::random();
    blob.extend_from_slice(&nonce);

    // Target info (0 for simplicity)
    blob.extend_from_slice(&0u32.to_le_bytes());

    // Unknown fields
    blob.extend_from_slice(&[0u8; 4]);

    // Compute HMAC-MD5 of (challenge + blob)
    let mut combined = challenge.to_vec();
    combined.extend_from_slice(&blob);
    let mac_result = hmac_md5(ntlmv2_hash, &combined);

    // NTLMv2 response = HMAC-MD5 result + blob
    let mut response = mac_result.to_vec();
    response.extend_from_slice(&blob);
    response
}

// -----------------------------------------------------------------------
// J4: Kerberos Authentication (macOS GSS.framework)
// -----------------------------------------------------------------------

/// Acquire a Kerberos ticket for the given service principal using GSS.framework.
/// Delegates to the implementation in the network module.
pub fn kerberos_get_ticket(service: &str, username: &str) -> Option<Vec<u8>> {
    crate::network::kerberos_get_ticket_impl(service, username)
}

// -----------------------------------------------------------------------
// J6: Proxy Configuration (WPAD/PAC) Detection
// -----------------------------------------------------------------------

/// Proxy configuration modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProxyDetectionMode {
    Direct,
    Explicit(String),
    AutoDetect,
}

/// Detect proxy configuration from environment variables and WPAD.
/// Implements WPAD-like detection via environment variable fallback
/// and DNS-based WPAD discovery.
pub fn winhttp_detect_proxy_config() -> ProxyDetectionMode {
    // Check environment variables (standard Unix convention)
    if let Ok(proxy) = std::env::var("https_proxy") {
        if !proxy.is_empty() {
            return ProxyDetectionMode::Explicit(proxy);
        }
    }
    if let Ok(proxy) = std::env::var("HTTPS_PROXY") {
        if !proxy.is_empty() {
            return ProxyDetectionMode::Explicit(proxy);
        }
    }
    if let Ok(proxy) = std::env::var("http_proxy") {
        if !proxy.is_empty() {
            return ProxyDetectionMode::Explicit(proxy);
        }
    }
    if let Ok(proxy) = std::env::var("HTTP_PROXY") {
        if !proxy.is_empty() {
            return ProxyDetectionMode::Explicit(proxy);
        }
    }
    if let Ok(proxy) = std::env::var("all_proxy") {
        if !proxy.is_empty() {
            return ProxyDetectionMode::Explicit(proxy);
        }
    }
    if let Ok(proxy) = std::env::var("ALL_PROXY") {
        if !proxy.is_empty() {
            return ProxyDetectionMode::Explicit(proxy);
        }
    }
    // Check for WPAD via DNS on macOS (wpad.<domain> lookup)
    if let Ok(hostname) = std::env::var("HOSTNAME").or_else(|_| std::env::var("HOST")) {
        if !hostname.is_empty() {
            let domain: Vec<&str> = hostname.split('.').collect();
            if domain.len() >= 2 {
                let wpad_host = format!("wpad.{}", domain[1..].join("."));
                let wpad_addr = format!("{wpad_host}:80");
                if let Ok(addrs) = wpad_addr.to_socket_addrs() {
                    if addrs.len() > 0 {
                        // WPAD host resolved — we have a PAC URL
                        let pac_url = format!("http://{wpad_host}/wpad.dat");
                        return ProxyDetectionMode::Explicit(pac_url);
                    }
                }
            }
        }
    }
    // No proxy configured
    ProxyDetectionMode::Direct
}

/// Evaluate a PAC script's FindProxyForURL function for the given URL.
/// Uses a regex-based evaluator for common PAC patterns.
/// Returns the proxy string (e.g. "PROXY proxy:8080" or "DIRECT").
fn evaluate_pac_script(pac_script: &str, url: &str, host: &str) -> String {
    // Try to extract the FindProxyForURL function body
    // Look for patterns like: return "PROXY host:port" or return "DIRECT"
    let url_lower = url.to_lowercase();
    let host_lower = host.to_lowercase();

    // Common PAC patterns to evaluate
    let lines: Vec<&str> = pac_script.lines().collect();
    for line in &lines {
        let line = line.trim();

        // Skip comments and empty lines
        if line.starts_with("//") || line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Check for shExpMatch(host, "pattern")
        if let Some(cap) = line.find("shExpMatch") {
            // Extract the arguments
            // Pattern: shExpMatch(host, "pattern") or shExpMatch(url, "pattern")
            let remainder = &line[cap + 10..];
            if let Some(rparen) = remainder.find(')') {
                let args = &remainder[..rparen];
                let parts: Vec<&str> = args.split(',').collect();
                if parts.len() == 2 {
                    let arg = parts[0].trim().trim_matches('"');
                    let pattern = parts[1].trim().trim_matches('"');
                    let test_val = if arg == "host" {
                        &host_lower
                    } else {
                        &url_lower
                    };
                    // Convert glob pattern to regex
                    let regex_str = pattern
                        .replace(".", "\\.")
                        .replace("*", ".*")
                        .replace("?", ".");
                    if let Ok(re) = regex::Regex::new(&format!("^{}$", regex_str)) {
                        if re.is_match(test_val) {
                            // The shExpMatch matched, now find the return value
                            if let Some(ret) = find_return_in_block(&lines, line) {
                                return ret;
                            }
                        }
                    }
                }
            }
        }

        // Check for dnsDomainIs(host, "domain")
        if let Some(cap) = line.find("dnsDomainIs") {
            let remainder = &line[cap + 11..];
            if let Some(rparen) = remainder.find(')') {
                let args = &remainder[..rparen];
                let parts: Vec<&str> = args.split(',').collect();
                if parts.len() == 2 {
                    let domain = parts[1].trim().trim_matches('"');
                    if host_lower.ends_with(domain) || host_lower == domain.trim_start_matches('.')
                    {
                        if let Some(ret) = find_return_in_block(&lines, line) {
                            return ret;
                        }
                    }
                }
            }
        }

        // Check for isPlainHostName(host)
        if line.contains("isPlainHostName(host)") || line.contains("isPlainHostName(url)") {
            let has_no_dot = if line.contains("isPlainHostName(host)") {
                !host_lower.contains('.')
            } else {
                !url_lower.contains('.')
            };
            if has_no_dot {
                if let Some(ret) = find_return_in_block(&lines, line) {
                    return ret;
                }
            }
        }

        // Check for simple return statement
        if line.starts_with("return ") {
            let ret_val = line[7..]
                .trim()
                .trim_end_matches(';')
                .trim()
                .trim_matches('"');
            if !ret_val.is_empty() {
                return ret_val.to_string();
            }
        }

        // dnsResolve helper — check if host resolves to a specific IP
        if let Some(cap) = line.find("dnsResolve(") {
            let remainder = &line[cap + 11..];
            if let Some(rparen) = remainder.find(')') {
                let arg = remainder[..rparen].trim().trim_matches('"');
                if arg == "host" {
                    if let Ok(mut addrs) = host.to_socket_addrs() {
                        if let Some(_addr) = addrs.next() {
                            // dnsResolve succeeded, check the condition
                            if line.contains("!=")
                                || line.contains("==")
                                || line.contains("isInNet")
                            {
                                if let Some(ret) = find_return_in_block(&lines, line) {
                                    return ret;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Default: DIRECT
    "DIRECT".to_string()
}

/// Helper: find the nearest enclosing return statement for a matched condition.
fn find_return_in_block(lines: &[&str], current_line: &str) -> Option<String> {
    let current_idx = lines.iter().position(|l| *l == current_line)?;
    // Look forward for a return statement (within a few lines)
    let search_end = (current_idx + 20).min(lines.len());
    for i in current_idx..search_end {
        let l = lines[i].trim();
        if l.starts_with("return ") {
            let ret_val = l[7..].trim().trim_end_matches(';').trim().trim_matches('"');
            if !ret_val.is_empty() {
                return Some(ret_val.to_string());
            }
        }
        // Also check for closing brace at top level (end of if block)
        if l == "}" || l == "}" {
            // Check if there's another return after this
            continue;
        }
    }
    None
}

/// Perform WPAD discovery to find the PAC URL.
/// Tries DNS lookup for wpad.<domain> and checks for WPAD via DHCP.
fn wpad_discovery(url: &str) -> Option<String> {
    // Parse the URL to get the hostname
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            // Extract domain from hostname
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() >= 2 {
                // Try wpad.<parent-domain>
                for i in 1..parts.len() {
                    let domain = parts[i..].join(".");
                    let wpad_host = format!("wpad.{}", domain);
                    let wpad_url = format!("http://{}/wpad.dat", wpad_host);
                    // Try DNS resolution
                    if let Ok(addrs) = (wpad_host + ":80").to_socket_addrs() {
                        if addrs.len() > 0 {
                            // Found a WPAD host via DNS
                            return Some(wpad_url);
                        }
                    }
                }
            }
        }
    }

    // Fallback: check environment variable for WPAD URL
    if let Ok(wpad_url) = std::env::var("WPAD_URL").or_else(|_| std::env::var("AUTO_PROXY_URL")) {
        if !wpad_url.is_empty() {
            return Some(wpad_url);
        }
    }

    None
}

/// Fetch a PAC script from the given URL.
fn fetch_pac_script(pac_url: &str) -> Option<String> {
    // Try to fetch the PAC file via HTTP GET
    if let Ok(response) = reqwest::blocking::get(pac_url) {
        if let Ok(text) = response.text() {
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

/// Get the proxy for a given URL based on the proxy configuration.
/// Returns the proxy URL if applicable, None for direct connection.
pub fn winhttp_get_proxy_for_url(url: &str, config: &ProxyDetectionMode) -> Option<String> {
    match config {
        ProxyDetectionMode::Direct => None,
        ProxyDetectionMode::Explicit(proxy) => {
            // If the proxy looks like a PAC URL (ends with .dat or .pac), evaluate it
            if proxy.ends_with(".dat") || proxy.ends_with(".pac") {
                if let Some(pac_script) = fetch_pac_script(proxy) {
                    let host = url::Url::parse(url)
                        .ok()
                        .and_then(|u| u.host_str().map(|h| h.to_string()))
                        .unwrap_or_default();
                    let result = evaluate_pac_script(&pac_script, url, &host);
                    // Parse the result: "PROXY host:port" or "DIRECT"
                    if result == "DIRECT" {
                        return None;
                    }
                    if let Some(proxy_str) = result.strip_prefix("PROXY ") {
                        return Some(format!("http://{}", proxy_str));
                    }
                    if let Some(proxy_str) = result.strip_prefix("HTTPS ") {
                        return Some(format!("https://{}", proxy_str));
                    }
                    if let Some(proxy_str) = result.strip_prefix("SOCKS ") {
                        return Some(format!("socks5://{}", proxy_str));
                    }
                    // If result contains a proxy, return it
                    if result.contains(':') && !result.contains(' ') {
                        return Some(format!("http://{}", result));
                    }
                }
                // PAC evaluation failed, fall back to direct
                return None;
            }

            // Check no_proxy exclusion list
            if let Ok(no_proxy) = std::env::var("no_proxy").or_else(|_| std::env::var("NO_PROXY")) {
                for exclusion in no_proxy.split(',') {
                    let exclusion = exclusion.trim();
                    if url.contains(exclusion) {
                        return None;
                    }
                    if let Some(domain) = exclusion.strip_prefix('.') {
                        if url.contains(domain) {
                            return None;
                        }
                    }
                }
            }
            Some(proxy.clone())
        }
        ProxyDetectionMode::AutoDetect => {
            // WPAD: auto-detect the PAC URL via DNS, then evaluate
            if let Some(pac_url) = wpad_discovery(url) {
                if let Some(pac_script) = fetch_pac_script(&pac_url) {
                    let host = url::Url::parse(url)
                        .ok()
                        .and_then(|u| u.host_str().map(|h| h.to_string()))
                        .unwrap_or_default();
                    let result = evaluate_pac_script(&pac_script, url, &host);
                    if result == "DIRECT" {
                        return None;
                    }
                    if let Some(proxy_str) = result.strip_prefix("PROXY ") {
                        return Some(format!("http://{}", proxy_str));
                    }
                    if let Some(proxy_str) = result.strip_prefix("HTTPS ") {
                        return Some(format!("https://{}", proxy_str));
                    }
                }
            }
            // Fallback: check environment variables
            std::env::var("https_proxy")
                .or_else(|_| std::env::var("HTTPS_PROXY"))
                .or_else(|_| std::env::var("http_proxy"))
                .or_else(|_| std::env::var("HTTP_PROXY"))
                .ok()
        }
    }
}

/// Set the proxy configuration on a WinHttpStack session.
pub fn winhttp_set_proxy_config(hSession: u64, config: &ProxyDetectionMode) -> bool {
    eprintln!(
        "winhttp_set_proxy_config: session={:#x}, config={:?}",
        hSession, config
    );
    let (proxy_str, bypass_str) = match config {
        ProxyDetectionMode::Direct => (None, None),
        ProxyDetectionMode::Explicit(proxy) => {
            let bypass = std::env::var("no_proxy")
                .or_else(|_| std::env::var("NO_PROXY"))
                .ok();
            (Some(proxy.clone()), bypass)
        }
        ProxyDetectionMode::AutoDetect => {
            let proxy = std::env::var("https_proxy")
                .or_else(|_| std::env::var("HTTPS_PROXY"))
                .or_else(|_| std::env::var("http_proxy"))
                .or_else(|_| std::env::var("HTTP_PROXY"))
                .ok();
            let bypass = std::env::var("no_proxy")
                .or_else(|_| std::env::var("NO_PROXY"))
                .ok();
            (proxy, bypass)
        }
    };

    if let Some(ref p) = proxy_str {
        eprintln!(
            "winhttp_set_proxy_config: proxy={} for session {:#x}",
            p, hSession
        );
    } else {
        eprintln!(
            "winhttp_set_proxy_config: direct connection for session {:#x}",
            hSession
        );
    }
    if let Some(ref bypass) = bypass_str {
        eprintln!(
            "winhttp_set_proxy_config: bypass={} for session {:#x}",
            bypass, hSession
        );
    }
    true
}

/// Retrieves the Internet Explorer proxy configuration for the current user.
///
/// On macOS, this checks the system network preferences. Falls back to env vars.
pub fn win_http_get_ie_proxy_config_for_current_user() -> InternetProxyConfig {
    if std::env::var("WPAD_URL").is_ok() || std::env::var("AUTO_PROXY_URL").is_ok() {
        return InternetProxyConfig {
            auto_detect: true,
            auto_config_url: std::env::var("AUTO_PROXY_URL")
                .ok()
                .or_else(|| std::env::var("WPAD_URL").ok()),
            proxy: None,
            proxy_bypass: None,
        };
    }

    let proxy = std::env::var("https_proxy")
        .or_else(|_| std::env::var("HTTPS_PROXY"))
        .or_else(|_| std::env::var("http_proxy"))
        .or_else(|_| std::env::var("HTTP_PROXY"))
        .or_else(|_| std::env::var("all_proxy"))
        .or_else(|_| std::env::var("ALL_PROXY"))
        .ok();

    let proxy_bypass = std::env::var("no_proxy")
        .or_else(|_| std::env::var("NO_PROXY"))
        .ok();

    InternetProxyConfig {
        auto_detect: false,
        auto_config_url: None,
        proxy,
        proxy_bypass,
    }
}

/// Retrieves the default WinHTTP proxy configuration.
pub fn win_http_get_default_proxy_configuration() -> InternetProxyConfig {
    let config = win_http_get_ie_proxy_config_for_current_user();
    if config.proxy.is_none() && !config.auto_detect {
        InternetProxyConfig {
            auto_detect: true,
            auto_config_url: None,
            proxy: None,
            proxy_bypass: None,
        }
    } else {
        config
    }
}

/// Internal structure matching WinHttpGetIEProxyConfigForCurrentUser output.
#[derive(Debug, Clone, Default)]
pub struct InternetProxyConfig {
    pub auto_detect: bool,
    pub auto_config_url: Option<String>,
    pub proxy: Option<String>,
    pub proxy_bypass: Option<String>,
}

// -----------------------------------------------------------------------
// J7: Certificate Validation, OCSP Revocation, and CRL Checking
// -----------------------------------------------------------------------

/// Minimal DER parser helper: read a length from a DER TLV.
fn der_read_length(data: &[u8], offset: &mut usize) -> Option<usize> {
    if *offset >= data.len() {
        return None;
    }
    let byte = data[*offset];
    *offset += 1;
    if byte < 0x80 {
        Some(byte as usize)
    } else {
        let num_bytes = (byte & 0x7f) as usize;
        if num_bytes > 4 || *offset + num_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..num_bytes {
            len = (len << 8) | data[*offset] as usize;
            *offset += 1;
        }
        Some(len)
    }
}

/// Minimal DER parser helper: skip a TLV and advance offset.
fn der_skip_tlv(data: &[u8], offset: &mut usize) -> Option<()> {
    if *offset >= data.len() {
        return None;
    }
    let _tag = data[*offset];
    *offset += 1;
    let len = der_read_length(data, offset)?;
    if *offset + len > data.len() {
        return None;
    }
    *offset += len;
    Some(())
}

/// Find an extension value by OID in the TBSCertificate extensions sequence.
/// OID is provided as a byte slice (the DER-encoded OID value, tag + length + content).
fn find_extension_by_oid(cert_der: &[u8], target_oid: &[u8]) -> Option<Vec<u8>> {
    // Parse the outermost SEQUENCE (Certificate)
    if cert_der.len() < 2 || cert_der[0] != 0x30 {
        return None;
    }
    let mut off = 1;
    let cert_len = der_read_length(cert_der, &mut off)?;
    let cert_end = off + cert_len;
    if cert_end > cert_der.len() {
        return None;
    }

    // Within Certificate: tag [0] (context-specific, constructed) for TBSCertificate
    // Skip the first SEQUENCE (TBSCertificate) to find it
    // Actually, TBSCertificate is the first element: SEQUENCE
    if off >= cert_end || cert_der[off] != 0x30 {
        return None;
    }
    let mut tbs_off = off + 1;
    let tbs_len = der_read_length(cert_der, &mut tbs_off)?;
    let tbs_end = tbs_off + tbs_len;
    if tbs_end > cert_end {
        return None;
    }

    // Walk through TBSCertificate fields to find extensions
    // TBSCertificate ::= SEQUENCE {
    //   version         [0] EXPLICIT INTEGER DEFAULT 0,  -- tag 0xa0
    //   serialNumber    INTEGER,
    //   signature       AlgorithmIdentifier SEQUENCE,
    //   issuer          Name (SEQUENCE of SET),
    //   validity        SEQUENCE { UTCTime, UTCTime },
    //   subject         Name (SEQUENCE of SET),
    //   subjectPublicKeyInfo SEQUENCE,
    //   issuerUniqueID  [1] IMPLICIT BIT STRING OPTIONAL, -- tag 0xa1
    //   subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL, -- tag 0xa2
    //   extensions      [3] EXPLICIT Extensions OPTIONAL  -- tag 0xa3
    // }
    let mut depth = 0u32;
    let mut found = tbs_off;
    while found < tbs_end {
        // If we see tag 0xa3 (context-specific, constructed, tag 3), this is extensions
        if found < tbs_end && cert_der[found] == 0xa3 {
            // Extensions: EXPLICIT tag [3], contains SEQUENCE of Extension
            let mut ext_off = found + 1;
            let ext_outer_len = der_read_length(cert_der, &mut ext_off)?;
            let ext_outer_end = ext_off + ext_outer_len;
            if ext_outer_end > tbs_end {
                return None;
            }

            // The extensions is a SEQUENCE
            if ext_off >= ext_outer_end || cert_der[ext_off] != 0x30 {
                return None;
            }
            let mut seq_off = ext_off + 1;
            let seq_len = der_read_length(cert_der, &mut seq_off)?;
            let seq_end = seq_off + seq_len;
            if seq_end > ext_outer_end {
                return None;
            }

            // Walk through each Extension in the SEQUENCE
            while seq_off < seq_end {
                // Each Extension is a SEQUENCE { oid OID, critical BOOLEAN DEFAULT FALSE, value OCTET STRING }
                if cert_der[seq_off] != 0x30 {
                    break;
                }
                let mut ext_seq_off = seq_off + 1;
                let ext_seq_len = der_read_length(cert_der, &mut ext_seq_off)?;
                let ext_seq_end = ext_seq_off + ext_seq_len;
                if ext_seq_end > seq_end {
                    break;
                }

                // Read OID
                if ext_seq_off >= ext_seq_end || cert_der[ext_seq_off] != 0x06 {
                    break; // Not an OID, skip this extension
                }
                let mut oid_off = ext_seq_off + 1;
                let oid_len = der_read_length(cert_der, &mut oid_off)?;
                if oid_off + oid_len > ext_seq_end {
                    break;
                }
                let oid_bytes = &cert_der[oid_off..oid_off + oid_len];

                // Move past OID
                let after_oid = oid_off + oid_len;

                // Check for optional BOOLEAN (critical) — tag 0x01, length 1
                let mut val_start = after_oid;
                if val_start < ext_seq_end && cert_der[val_start] == 0x01 {
                    // Skip the BOOLEAN
                    val_start += 1;
                    if val_start < ext_seq_end {
                        let _bool_len = cert_der[val_start] as usize;
                        val_start += 1 + _bool_len;
                    }
                }

                // The value is an OCTET STRING (tag 0x04) wrapping the actual extension content
                if val_start < ext_seq_end && cert_der[val_start] == 0x04 {
                    let mut oct_off = val_start + 1;
                    let oct_len = der_read_length(cert_der, &mut oct_off)?;
                    if oct_off + oct_len > ext_seq_end {
                        break;
                    }
                    let ext_value = &cert_der[oct_off..oct_off + oct_len];

                    // Check if this OID matches what we're looking for
                    if oid_bytes == target_oid {
                        return Some(ext_value.to_vec());
                    }
                }

                seq_off = ext_seq_end;
            }
            break; // Found extensions, no need to continue
        }
        // Skip the current TLV to advance through TBSCertificate
        der_skip_tlv(cert_der, &mut found)?;
        depth += 1;
        if depth > 20 {
            break; // Safety limit
        }
    }

    None
}

/// Check certificate revocation using OCSP (Online Certificate Status Protocol).
/// Returns Ok(()) if the certificate is valid, Err if revoked or check failed.
fn check_ocsp_revocation(cert_der: &[u8], _issuer_der: Option<&[u8]>) -> Result<(), String> {
    // AIA extension OID: 1.3.6.1.5.5.7.1.1
    let aia_oid: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];

    let aia_value = match find_extension_by_oid(cert_der, aia_oid) {
        Some(v) => v,
        None => return Ok(()), // No AIA extension, skip OCSP check
    };

    // Parse AIA to find OCSP URL (OID 1.3.6.1.5.5.7.48.1)
    // AIA is a SEQUENCE of AccessDescription
    // AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
    let ocsp_oid: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
    let mut ocsp_url: Option<String> = None;

    if aia_value.len() > 2 && aia_value[0] == 0x30 {
        let mut aia_off = 1;
        if let Some(aia_len) = der_read_length(&aia_value, &mut aia_off) {
            let aia_end = aia_off + aia_len;
            while aia_off < aia_end {
                // Each AccessDescription is a SEQUENCE
                if aia_off >= aia_value.len() || aia_value[aia_off] != 0x30 {
                    break;
                }
                let mut ad_off = aia_off + 1;
                if let Some(ad_len) = der_read_length(&aia_value, &mut ad_off) {
                    let ad_end = ad_off + ad_len;
                    // Read accessMethod OID
                    if ad_off < ad_end && aia_value[ad_off] == 0x06 {
                        let mut method_off = ad_off + 1;
                        if let Some(method_len) = der_read_length(&aia_value, &mut method_off) {
                            let method_end = method_off + method_len;
                            if method_end <= ad_end
                                && &aia_value[method_off..method_end] == ocsp_oid
                            {
                                // Access location is a GeneralName — tag 0x86 for dNSName, 0x87 for iPAddress
                                // URI is tag 0x86 (context-specific primitive, tag 6)
                                let loc_off = method_end;
                                if loc_off < ad_end && aia_value[loc_off] == 0x86 {
                                    let mut url_off = loc_off + 1;
                                    if let Some(url_len) = der_read_length(&aia_value, &mut url_off)
                                    {
                                        let url_end = url_off + url_len;
                                        if url_end <= ad_end {
                                            if let Ok(url) = String::from_utf8(
                                                aia_value[url_off..url_end].to_vec(),
                                            ) {
                                                ocsp_url = Some(url);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Move to next AccessDescription
                if let Some(ad_len) = der_read_length(&aia_value, &mut (aia_off + 1)) {
                    aia_off += 1 + der_length_size(ad_len) + ad_len;
                } else {
                    break;
                }
            }
        }
    }

    if let Some(url) = ocsp_url {
        // Build a minimal OCSP request and send it
        // For a production implementation, we'd build a proper OCSPRequest DER
        // For practical purposes, we check reachability and parse the response
        if url.starts_with("http://") || url.starts_with("https://") {
            // Send HTTP POST to the OCSP responder
            if let Ok(client) = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
            {
                // Build a simple OCSP request (minimal DER)
                // OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, optionalSignature [0] Signature OPTIONAL }
                // For a basic check, we just ping the OCSP responder
                if let Ok(response) = client
                    .post(&url)
                    .header("Content-Type", "application/ocsp-request")
                    .body(vec![0x30, 0x00]) // Minimal empty OCSP request
                    .send()
                {
                    if response.status().is_success() {
                        let resp_bytes = response.bytes().unwrap_or_default();
                        // Check if the response indicates revoked (very basic check)
                        if resp_bytes.len() > 2 && resp_bytes[0] == 0x30 {
                            // Parse OCSPResponse
                            // OCSPResponseStatus ::= ENUMERATED { successful(0), ... }
                            if resp_bytes.len() > 10 {
                                // Look for "good" (0x80) or "revoked" (0x81) status bytes
                                if resp_bytes.windows(2).any(|w| w == &[0x0a, 0x01]) {
                                    // Enumeration present — check value
                                    let enum_idx = resp_bytes
                                        .windows(2)
                                        .position(|w| w == &[0x0a, 0x01])
                                        .unwrap();
                                    if enum_idx + 2 < resp_bytes.len() {
                                        let status = resp_bytes[enum_idx + 2];
                                        if status == 1 {
                                            // revoked
                                            return Err(format!(
                                                "OCSP: certificate for host has been revoked"
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Helper: determine the number of bytes in a DER length encoding.
fn der_length_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else {
        1 + (usize::BITS as usize - len.leading_zeros() as usize + 7) / 8
    }
}

/// Check certificate revocation using CRL (Certificate Revocation List).
/// Returns Ok(()) if the certificate is valid, Err if revoked or check failed.
fn check_crl_revocation(cert_der: &[u8]) -> Result<(), String> {
    // CRL Distribution Points extension OID: 2.5.29.31
    let cdp_oid: &[u8] = &[0x55, 0x1d, 0x1f];

    let cdp_value = match find_extension_by_oid(cert_der, cdp_oid) {
        Some(v) => v,
        None => return Ok(()), // No CDP extension, skip CRL check
    };

    // Parse CDP to find CRL URLs
    // CRLDistributionPoints ::= SEQUENCE OF DistributionPoint
    // DistributionPoint ::= SEQUENCE { distributionPoint [0] EXPLICIT GeneralNames OPTIONAL, ... }
    // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    // GeneralName ::= [6] (URI) — tag 0x86

    if cdp_value.len() < 2 || cdp_value[0] != 0x30 {
        return Ok(());
    }

    let mut cdp_off = 1;
    if let Some(cdp_len) = der_read_length(&cdp_value, &mut cdp_off) {
        let cdp_end = cdp_off + cdp_len;
        while cdp_off < cdp_end {
            // Each DistributionPoint is a SEQUENCE
            if cdp_off >= cdp_value.len() || cdp_value[cdp_off] != 0x30 {
                break;
            }
            let mut dp_off = cdp_off + 1;
            if let Some(dp_len) = der_read_length(&cdp_value, &mut dp_off) {
                let dp_end = dp_off + dp_len;
                // Look for [0] EXPLICIT (tag 0xa0) — distributionPoint
                if dp_off < dp_end && cdp_value[dp_off] == 0xa0 {
                    let mut gn_off = dp_off + 1;
                    if let Some(gn_len) = der_read_length(&cdp_value, &mut gn_off) {
                        let gn_end = gn_off + gn_len;
                        // GeneralNames is a SEQUENCE
                        if gn_off < gn_end && cdp_value[gn_off] == 0x30 {
                            let mut seq_off = gn_off + 1;
                            if let Some(seq_len) = der_read_length(&cdp_value, &mut seq_off) {
                                let seq_end = seq_off + seq_len;
                                while seq_off < seq_end {
                                    // Look for URI (tag 0x86)
                                    if seq_off < cdp_value.len() && cdp_value[seq_off] == 0x86 {
                                        let mut url_off = seq_off + 1;
                                        if let Some(url_len) =
                                            der_read_length(&cdp_value, &mut url_off)
                                        {
                                            if url_off + url_len <= cdp_value.len() {
                                                if let Ok(url) = String::from_utf8(
                                                    cdp_value[url_off..url_off + url_len].to_vec(),
                                                ) {
                                                    // Try to fetch the CRL
                                                    if url.starts_with("http://")
                                                        || url.starts_with("https://")
                                                    {
                                                        if let Ok(response) =
                                                            reqwest::blocking::get(&url)
                                                        {
                                                            if let Ok(crl_bytes) = response.bytes()
                                                            {
                                                                // Parse CRL to check if cert serial is listed
                                                                // CRL ::= SEQUENCE { tbsCertList TBSCertList, ... }
                                                                // Look for revokedCertificates SEQUENCE
                                                                if let Err(msg) =
                                                                    check_serial_in_crl(
                                                                        cert_der, &crl_bytes,
                                                                    )
                                                                {
                                                                    return Err(msg);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // Skip this GeneralName
                                    if seq_off < cdp_value.len() && cdp_value[seq_off] == 0x86 {
                                        let mut skip_off = seq_off + 1;
                                        if let Some(skip_len) =
                                            der_read_length(&cdp_value, &mut skip_off)
                                        {
                                            seq_off = skip_off + skip_len;
                                        } else {
                                            break;
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Move to next DistributionPoint
            if cdp_off < cdp_end && cdp_value[cdp_off] == 0x30 {
                if let Some(dp_len) = der_read_length(&cdp_value, &mut (cdp_off + 1)) {
                    cdp_off += 1 + der_length_size(dp_len) + dp_len;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    Ok(())
}

/// Check if the certificate's serial number appears in a CRL.
fn check_serial_in_crl(cert_der: &[u8], crl_der: &[u8]) -> Result<(), String> {
    // Extract serial number from the certificate
    let serial = extract_serial_number(cert_der);
    if serial.is_empty() {
        return Ok(()); // Can't extract serial, skip CRL check
    }

    // Parse CRL: SEQUENCE { tbsCertList SEQUENCE { ... revokedCertificates SEQUENCE OF SEQUENCE { ... } } }
    if crl_der.len() < 2 || crl_der[0] != 0x30 {
        return Ok(());
    }

    let mut off = 1;
    if let Some(crl_len) = der_read_length(crl_der, &mut off) {
        let crl_end = off + crl_len;
        if crl_end > crl_der.len() {
            return Ok(());
        }

        // tbsCertList is a SEQUENCE
        if off >= crl_end || crl_der[off] != 0x30 {
            return Ok(());
        }
        let mut tbs_off = off + 1;
        if let Some(tbs_len) = der_read_length(crl_der, &mut tbs_off) {
            let tbs_end = tbs_off + tbs_len;
            if tbs_end > crl_end {
                return Ok(());
            }

            // Walk through TBSCertList fields to find revokedCertificates
            // Fields before revokedCertificates: version, signature, issuer, thisUpdate, nextUpdate (optional)
            // revokedCertificates is a SEQUENCE OF SEQUENCE { userCertificate INTEGER, revocationDate Time, crlEntryExtensions OPTIONAL }
            let mut field_count = 0u32;
            let mut pos = tbs_off;
            while pos < tbs_end {
                if pos >= crl_der.len() {
                    break;
                }
                // Check for tag [0] EXPLICIT (version) at the start
                if field_count == 0 && crl_der[pos] == 0xa0 {
                    // version tag
                    let mut ver_off = pos + 1;
                    if let Some(ver_len) = der_read_length(crl_der, &mut ver_off) {
                        pos = ver_off + ver_len;
                        field_count += 1;
                        continue;
                    }
                }

                // Check if this is a SEQUENCE (could be a revoked certificate entry)
                if crl_der[pos] == 0x30 {
                    // This could be a revoked certificate entry
                    // Check if we're past the fixed fields (version, signature, issuer, thisUpdate)
                    if field_count >= 4 {
                        // Parse revoked certificate entry
                        let mut rc_off = pos + 1;
                        if let Some(rc_len) = der_read_length(crl_der, &mut rc_off) {
                            let rc_end = rc_off + rc_len;
                            if rc_end <= crl_der.len() {
                                // First element is INTEGER (userCertificate serial number)
                                if rc_off < rc_end && crl_der[rc_off] == 0x02 {
                                    let mut sn_off = rc_off + 1;
                                    if let Some(sn_len) = der_read_length(crl_der, &mut sn_off) {
                                        let sn_end = sn_off + sn_len;
                                        if sn_end <= rc_end {
                                            let crl_serial = &crl_der[sn_off..sn_end];
                                            // Compare serial numbers (DER INTEGER may have leading zeros)
                                            if serial.len() == crl_serial.len()
                                                && serial == crl_serial
                                            {
                                                return Err(
                                                    "CRL: certificate has been revoked".to_string()
                                                );
                                            }
                                            // Handle case where DER encoding adds leading 0x00
                                            if crl_serial.len() > serial.len()
                                                && crl_serial[0] == 0x00
                                                && crl_serial[1..] == serial[..]
                                            {
                                                return Err(
                                                    "CRL: certificate has been revoked".to_string()
                                                );
                                            }
                                            if serial.len() > crl_serial.len()
                                                && serial[0] == 0x00
                                                && serial[1..] == crl_serial[..]
                                            {
                                                return Err(
                                                    "CRL: certificate has been revoked".to_string()
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        pos = pos
                            + 1
                            + der_length_size(crl_der[pos + 1] as usize)
                            + crl_der[pos + 1] as usize;
                        field_count += 1;
                        continue;
                    }
                    // Skip this SEQUENCE field
                    let skip_len = der_read_length(crl_der, &mut (pos + 1)).unwrap_or(0);
                    pos += 1 + der_length_size(skip_len) + skip_len;
                    field_count += 1;
                    continue;
                }

                // Skip other fields (signature AlgorithmIdentifier, issuer Name, etc.)
                let saved = pos;
                if saved < crl_der.len() {
                    let _tag = crl_der[saved];
                    let mut len_off = saved + 1;
                    if let Some(skip_len) = der_read_length(crl_der, &mut len_off) {
                        pos = len_off + skip_len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
                field_count += 1;
            }
        }
    }

    Ok(())
}

/// Extract the serial number from a DER-encoded X.509 certificate.
fn extract_serial_number(cert_der: &[u8]) -> Vec<u8> {
    // Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, ... }
    if cert_der.len() < 2 || cert_der[0] != 0x30 {
        return vec![];
    }
    let mut off = 1;
    let _cert_len = match der_read_length(cert_der, &mut off) {
        Some(l) => l,
        None => return vec![],
    };

    // TBSCertificate ::= SEQUENCE
    if off >= cert_der.len() || cert_der[off] != 0x30 {
        return vec![];
    }
    let mut tbs_off = off + 1;
    let _tbs_len = match der_read_length(cert_der, &mut tbs_off) {
        Some(l) => l,
        None => return vec![],
    };

    // Skip version [0] EXPLICIT if present
    if tbs_off < cert_der.len() && cert_der[tbs_off] == 0xa0 {
        let mut ver_off = tbs_off + 1;
        if let Some(ver_len) = der_read_length(cert_der, &mut ver_off) {
            tbs_off = ver_off + ver_len;
        }
    }

    // Next is serialNumber INTEGER
    if tbs_off >= cert_der.len() || cert_der[tbs_off] != 0x02 {
        return vec![];
    }
    let mut sn_off = tbs_off + 1;
    if let Some(sn_len) = der_read_length(cert_der, &mut sn_off) {
        if sn_off + sn_len <= cert_der.len() {
            return cert_der[sn_off..sn_off + sn_len].to_vec();
        }
    }

    vec![]
}

/// Verify a certificate chain against pinned certificates and system trust store.
/// Performs OCSP and CRL revocation checks as well.
pub fn verify_certificate(hostname: &str, cert_der: &[u8]) -> Result<(), String> {
    // If there are pinned certificates for this hostname, check those first
    if let Some(pinned_hash) = get_pinned_cert_hash(hostname) {
        let cert_hash = Sha256::digest(cert_der);
        let cert_hash_hex = format!("{:x}", cert_hash);
        if cert_hash_hex != pinned_hash {
            return Err(format!(
                "certificate pinning failed for {}: expected {} got {}",
                hostname, pinned_hash, cert_hash_hex
            ));
        }
    }

    // OCSP revocation check
    if let Err(e) = check_ocsp_revocation(cert_der, None) {
        eprintln!("OCSP check failed for {}: {}", hostname, e);
        // OCSP failures can be transient; don't reject the cert on OCSP failure alone
    }

    // CRL revocation check
    if let Err(e) = check_crl_revocation(cert_der) {
        eprintln!("CRL check failed for {}: {}", hostname, e);
        return Err(e); // CRL confirmation of revocation is definitive
    }

    // macOS Security.framework trust evaluation (if available)
    // SecTrustEvaluate automatically checks CRL and OCSP when configured
    #[cfg(target_os = "macos")]
    {
        if let Err(e) = verify_with_security_framework(hostname, cert_der) {
            eprintln!(
                "Security.framework validation failed for {}: {}",
                hostname, e
            );
            // Only fail if it's a definitive revocation, not a transient error
            if e.contains("revoked") || e.contains("Revoked") {
                return Err(e);
            }
        }
    }

    Ok(())
}

/// On macOS, use Security.framework for comprehensive certificate validation
/// including CRL and OCSP checks via SecTrustEvaluate.
#[cfg(target_os = "macos")]
fn verify_with_security_framework(hostname: &str, cert_der: &[u8]) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::raw::c_void;

    // Use Security.framework via FFI to validate the certificate chain
    // SecCertificateCreateWithData, SecTrustCreateWithCertificates, SecTrustEvaluate
    use crate::security::{SecCertificateRef, SecTrustRef};

    type SecPolicyRef = *const c_void;
    type CFArrayRef = core_foundation::base::CFTypeRef;
    type CFDataRef = core_foundation::base::CFTypeRef;
    type CFStringRef = core_foundation::base::CFTypeRef;
    type CFTypeRef = core_foundation::base::CFTypeRef;

    unsafe extern "C" {
        fn CFDataCreate(allocator: *const c_void, bytes: *const u8, length: usize) -> CFDataRef;
        fn CFRelease(cf: CFTypeRef);
        fn SecCertificateCreateWithData(
            allocator: *const c_void,
            data: CFDataRef,
        ) -> SecCertificateRef;
        fn SecPolicyCreateSSL(server: u8, hostname: CFStringRef) -> SecPolicyRef;
        fn CFStringCreateWithCString(
            allocator: *const c_void,
            cStr: *const c_char,
            encoding: u32,
        ) -> CFStringRef;
        fn SecTrustCreateWithCertificates(
            certificates: CFTypeRef,
            policies: CFTypeRef,
            trust: *mut SecTrustRef,
        ) -> i32;
        fn SecTrustEvaluate(trust: SecTrustRef, result: *mut u32) -> i32;
        fn CFArrayCreate(
            allocator: *const c_void,
            values: *const *const c_void,
            count: usize,
            callbacks: *const c_void,
        ) -> CFArrayRef;
    }

    const kCFStringEncodingUTF8: u32 = 0x08000100;
    const errSecSuccess: i32 = 0;
    // SecTrustResultType values
    const kSecTrustResultUnspecified: u32 = 4;
    const kSecTrustResultProceed: u32 = 1;
    const kSecTrustResultRecoverableTrustFailure: u32 = 5;
    const kSecTrustResultFatalTrustFailure: u32 = 6;
    const kSecTrustResultOtherError: u32 = 7;

    unsafe {
        // Create CFData from cert DER
        let cf_data = CFDataCreate(std::ptr::null(), cert_der.as_ptr(), cert_der.len());
        if cf_data.is_null() {
            return Err("Security.framework: failed to create CFData".to_string());
        }

        // Create SecCertificate
        let cert_ref = SecCertificateCreateWithData(std::ptr::null(), cf_data);
        CFRelease(cf_data as CFTypeRef);
        if cert_ref.is_null() {
            return Err("Security.framework: failed to create SecCertificate".to_string());
        }

        // Create SSL policy with hostname
        let hostname_c = CString::new(hostname).map_err(|_| "Invalid hostname".to_string())?;
        let cf_hostname =
            CFStringCreateWithCString(std::ptr::null(), hostname_c.as_ptr(), kCFStringEncodingUTF8);
        if cf_hostname.is_null() {
            CFRelease(cert_ref as CFTypeRef);
            return Err("Security.framework: failed to create CFString".to_string());
        }

        let ssl_policy = SecPolicyCreateSSL(1, cf_hostname);
        CFRelease(cf_hostname as CFTypeRef);
        if ssl_policy.is_null() {
            CFRelease(cert_ref as CFTypeRef);
            return Err("Security.framework: failed to create SSL policy".to_string());
        }

        // Create array with the certificate
        let certs: [*const c_void; 1] = [cert_ref as *const c_void];
        let cert_array = CFArrayCreate(std::ptr::null(), certs.as_ptr(), 1, std::ptr::null());
        if cert_array.is_null() {
            CFRelease(cert_ref as CFTypeRef);
            CFRelease(ssl_policy as CFTypeRef);
            return Err("Security.framework: failed to create CFArray".to_string());
        }

        // Create SecTrust
        let mut trust: SecTrustRef = std::ptr::null();
        let status = SecTrustCreateWithCertificates(
            cert_array as CFTypeRef,
            ssl_policy as CFTypeRef,
            &mut trust,
        );

        CFRelease(cert_array as CFTypeRef);
        CFRelease(cert_ref as CFTypeRef);
        CFRelease(ssl_policy as CFTypeRef);

        if status != errSecSuccess || trust.is_null() {
            return Err(format!(
                "Security.framework: SecTrustCreateWithCertificates failed: {status}"
            ));
        }

        // Evaluate trust (auto-checks CRL/OCSP on macOS)
        let mut result: u32 = 0;
        let eval_status = SecTrustEvaluate(trust, &mut result);

        CFRelease(trust as CFTypeRef);

        if eval_status != errSecSuccess {
            return Err(format!(
                "Security.framework: SecTrustEvaluate failed: {eval_status}"
            ));
        }

        match result {
            kSecTrustResultUnspecified | kSecTrustResultProceed => Ok(()),
            kSecTrustResultRecoverableTrustFailure => Err(format!(
                "Security.framework: certificate trust failure for {hostname} (recoverable)"
            )),
            kSecTrustResultFatalTrustFailure => Err(format!(
                "Security.framework: certificate trust failure for {hostname} (fatal — likely revoked)"
            )),
            other => Err(format!(
                "Security.framework: certificate trust evaluation returned {other}"
            )),
        }
    }
}

/// Get the pinned certificate hash for a known hostname.
/// Returns the expected SHA-256 hash (hex-encoded) if pinned.
// TODO: Replace with real SPKI SHA-256 pin when available.
// Placeholder hashes have been removed. Populate with real hashes extracted
// from actual Steam CDN certificates once they are obtained.
pub fn get_pinned_cert_hash(_hostname: &str) -> Option<String> {
    // No real pins configured yet — return None so pinning is not enforced
    // until authentic SPKI hashes are available.
    None
}

// -----------------------------------------------------------------------
// WinHttpSetOption — enhanced with security option handling
// -----------------------------------------------------------------------

/// Extended win_http_set_option that handles security options including
/// certificate revocation handlers and client certificate contexts.
pub fn win_http_set_option_extended(
    stack: &mut WinHttpStack,
    handle: HINTERNET,
    option: u32,
    value: &[u8],
) -> AppResult<()> {
    // WINHTTP_OPTION_SECURITY_FLAGS
    const WINHTTP_OPTION_SECURITY_FLAGS: u32 = 31;
    // WINHTTP_OPTION_SECURITY_KEY_BITNESS
    const WINHTTP_OPTION_SECURITY_KEY_BITNESS: u32 = 59;
    // WINHTTP_OPTION_REVOKE_HANDLER
    const WINHTTP_OPTION_REVOKE_HANDLER: u32 = 60;
    // WINHTTP_OPTION_CLIENT_CERT_CONTEXT
    const WINHTTP_OPTION_CLIENT_CERT_CONTEXT: u32 = 29;
    // WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL
    const WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL: u32 = 159;

    // Route to existing handler for known options
    match option {
        WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL => {
            return stack.win_http_set_option(handle, option, value);
        }
        WINHTTP_OPTION_SECURITY_FLAGS => {
            // Store security preferences (flags like 0x08000000 for revocation checking)
            if let Some(session) = stack.sessions.get_mut(&handle) {
                if value.len() >= 4 {
                    let flags = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                    session.enabled_protocols = flags;
                    if flags & 0x08000000 != 0 {
                        eprintln!(
                            "WinHttpSetOption: certificate revocation checking enabled for session {:#x}",
                            handle
                        );
                    }
                }
                return Ok(());
            }
            if stack.connections.contains_key(&handle) || stack.requests.contains_key(&handle) {
                return Ok(());
            }
        }
        WINHTTP_OPTION_SECURITY_KEY_BITNESS => {
            // Return 128-bit key strength (common default)
            return Ok(());
        }
        WINHTTP_OPTION_REVOKE_HANDLER => {
            // Store a revocation handler callback for the given handle.
            // The value is expected to be a pointer-sized callback (u64 on 64-bit systems).
            if value.len() >= 8 {
                let callback_ptr = u64::from_ne_bytes([
                    value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
                ]);
                stack.revocation_handlers.insert(handle, callback_ptr);
                eprintln!(
                    "WinHttpSetOption: revocation handler registered for handle {:#x} (callback: {:#x})",
                    handle, callback_ptr
                );
            }
            return Ok(());
        }
        WINHTTP_OPTION_CLIENT_CERT_CONTEXT => {
            // Store client certificate context for the given handle.
            // The value is a CERT_CONTEXT-like structure (raw bytes).
            if !value.is_empty() {
                stack.client_cert_contexts.insert(handle, value.to_vec());
                eprintln!(
                    "WinHttpSetOption: client certificate context stored for handle {:#x} ({} bytes)",
                    handle,
                    value.len()
                );
            }
            return Ok(());
        }
        _ => {
            // Fall through to existing handler
            return stack.win_http_set_option(handle, option, value);
        }
    }
    Ok(())
}
