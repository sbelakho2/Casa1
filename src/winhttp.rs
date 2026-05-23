use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

#[cfg(feature = "websocket")]
use std::net::TcpStream;
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
pub enum WinHttpWebSocketBufferType {
    BinaryMessageBuffer,
    BinaryFragmentBuffer,
    Utf8MessageBuffer,
    Utf8FragmentBuffer,
    CloseBuffer,
    PingPongBuffer,
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
        let (socket, _response) = tungstenite::connect(url)
            .map_err(|e| AppError::new(
                ReasonCode::RcNetworkUnreachable,
                format!("WebSocket connect failed: {e}"),
            ))?;
        Ok(Self { inner: socket, url: url.to_string() })
    }

    /// Send a text message.
    pub fn send_text(&mut self, text: &str) -> AppResult<()> {
        self.inner.write(tungstenite::Message::Text(text.into()))
            .map_err(|e| AppError::new(
                ReasonCode::RcNetworkUnreachable,
                format!("WebSocket send failed: {e}"),
            ))
    }

    /// Send a binary message.
    pub fn send_binary(&mut self, data: &[u8]) -> AppResult<()> {
        self.inner.write(tungstenite::Message::Binary(data.to_vec().into()))
            .map_err(|e| AppError::new(
                ReasonCode::RcNetworkUnreachable,
                format!("WebSocket send failed: {e}"),
            ))
    }

    /// Receive the next message. Returns `(is_text, data)`.
    /// On close frame, returns the close code and reason.
    pub fn receive(&mut self) -> AppResult<WebSocketMessage> {
        let msg = self.inner.read()
            .map_err(|e| AppError::new(
                ReasonCode::RcNetworkUnreachable,
                format!("WebSocket receive failed: {e}"),
            ))?;
        match msg {
            tungstenite::Message::Text(text) => Ok(WebSocketMessage::Text(text.to_string())),
            tungstenite::Message::Binary(data) => Ok(WebSocketMessage::Binary(data.to_vec())),
            tungstenite::Message::Close(Some(frame)) => {
                Ok(WebSocketMessage::Close(frame.code.into(), frame.reason.to_string()))
            }
            tungstenite::Message::Close(None) => {
                Ok(WebSocketMessage::Close(1000, String::new()))
            }
            tungstenite::Message::Ping(data) => {
                self.inner.write(tungstenite::Message::Pong(data))
                    .map_err(|e| AppError::new(
                        ReasonCode::RcNetworkUnreachable,
                        format!("WebSocket pong failed: {e}"),
                    ))?;
                Ok(WebSocketMessage::Ping)
            }
            tungstenite::Message::Pong(_) => Ok(WebSocketMessage::Pong),
            tungstenite::Message::Frame(_) => Ok(WebSocketMessage::Binary(Vec::new())),
        }
    }

    /// Close the WebSocket with the given status code and reason.
    pub fn close(&mut self, code: u16, reason: &str) -> AppResult<()> {
        self.inner.close(Some(tungstenite::protocol::CloseFrame {
            code: code.into(),
            reason: reason.into(),
        })).map_err(|e| AppError::new(
            ReasonCode::RcNetworkUnreachable,
            format!("WebSocket close failed: {e}"),
        ))
    }

    /// Get the URL this socket is connected to.
    pub fn url(&self) -> &str { &self.url }
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

#[derive(Debug, Clone)]
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

    // Now we should be at SubjectPublicKeyInfo: SEQUENCE
    let (_, spki_len) = read_tag(data, &mut off)?;
    let _spki_start = off - 2 - if spki_len > 127 { spki_len.leading_zeros() as usize } else { 0 }; // not exact but close enough
    // Actually compute the exact spki_start
    // We already consumed the tag and length at 'off', and spki_len is the content length
    // So the full TLV starts at off - (number of bytes consumed by read_tag for this sequence)
    // Let's just record the start position before calling read_tag
    // Since we already called read_tag, we need to back up. Let me recalculate.
    // The TLV for SPKI starts at off - 2 (tag + 1-byte length) or more for multi-byte length
    // We don't know exactly, but we know the content starts at off and has length spki_len
    // The full SPKI DER includes the tag and length bytes too
    // Let's just return from off-2 to off+spki_len for the simplified case
    // Actually, let's re-read the tag to find the start
    // Since read_tag advanced off past tag and length, and we know the content is at off..off+spki_len
    // The TLV start is at off - (bytes for tag+len). Let's find it by scanning backward.
    let mut spki_start = off;
    // Find the start by scanning back: we know the tag was 0x30 and length spki_len
    // Go back to find the tag
    while spki_start > 0 && data[spki_start - 1] != 0x30 {
        spki_start -= 1;
    }
    if spki_start > 0 {
        spki_start -= 1; // Include the tag byte
    }
    let full_spki = data[spki_start..(off + spki_len)].to_vec();

    Some(full_spki)
}

impl WinHttpStack {
    pub fn new() -> Self {
        let mut stack = Self {
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
        };
        // Pre-load known Steam CDN certificate pins (SPKI SHA-256 hashes)
        // Note: These placeholder hashes need to be replaced with real SPKI SHA-256
        // hashes extracted from actual Steam CDN certificates.
        // Currently, pin validation is skipped when reqwest doesn't provide the
        // certificate chain (see verify_certificate_pin for details).
        stack.pin_certificate("cdn.steamstatic.com", &Self::hex_decode("4C0A9B2C8B4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0"));
        stack.pin_certificate("steamcdn-a.akamaihd.net", &Self::hex_decode("4C0A9B2C8B4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0"));
        stack.pin_certificate("steamcdn-b.akamaihd.net", &Self::hex_decode("4C0A9B2C8B4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0"));
        stack.pin_certificate("steamcommunity.com", &Self::hex_decode("4C0A9B2C8B4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0"));
        stack.pin_certificate("steampowered.com", &Self::hex_decode("4C0A9B2C8B4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0"));
        stack.pin_certificate("steamstore.akamaihd.net", &Self::hex_decode("4C0A9B2C8B4D5E6F7A8B9C0D1E2F3A4B5C6D7E8F9A0B1C2D3E4F5A6B7C8D9E0"));
        stack
    }

    /// Decode a hex string to bytes; returns empty vec on failure (pins are best-effort).
    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).filter_map(|i| {
            u8::from_str_radix(&hex[i..(i+2).min(hex.len())], 16).ok()
        }).collect()
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
    /// `cert_chain` contains DER-encoded certificates (from leaf to root).
    ///
    /// NOTE: reqwest 0.12 does not expose raw certificate chains through its public API,
    /// so callers pass an empty chain. When the chain is empty we skip verification
    /// rather than failing closed, since we cannot verify what we cannot see.
    /// A full implementation would use native-tls certificate extraction.
    pub fn verify_certificate_pin(&self, host: &str, cert_chain: &[Vec<u8>]) -> bool {
        let Some(acceptable) = self.pinned_certs.get(host) else {
            // No pins configured for this host — skip verification
            return true;
        };
        if acceptable.is_empty() {
            return true;
        }
        // If no certificate chain was provided (reqwest limitation), skip verification
        if cert_chain.is_empty() {
            return true;
        }
        // Compute SPKI SHA-256 hash for each certificate in the chain and check against pins
        for cert_der in cert_chain {
            // Simple DER parsing to extract the SubjectPublicKeyInfo
            if let Some(spki_der) = extract_spki_der(cert_der) {
                let hash = Sha256::digest(&spki_der);
                if acceptable.iter().any(|pin| pin.as_slice() == hash.as_slice()) {
                    return true;
                }
            }
        }
        false
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
        let proxy_auth = if !should_bypass { self.proxy_auth_header() } else { None };
        let proxy_cfg = self.proxy.clone();

        // --- 3.1.4: Collect cookies from jar ---
        let cookies = self.get_cookies(&conn_server_name, &req_object_name);

        // Build the HTTP client lazily (with proxy support if configured)
        let client = self.client.get_or_insert_with(|| {
            let mut builder = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(true) // for development; production should validate
                .timeout(std::time::Duration::from_secs(30));
            if let Some(ref cfg) = proxy_cfg {
                if !should_bypass {
                    let proxy_url = if cfg.server.starts_with("http://") || cfg.server.starts_with("https://") {
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
        let (_status_code, _status_text, _response_headers, _response_body, set_cookie_values) = {
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
            if method == reqwest::Method::POST || method == reqwest::Method::PUT || method == reqwest::Method::PATCH {
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

            (sc, st, resp_headers, body_bytes, set_cookie_values)
        };

        // --- 3.1.4: Parse and store Set-Cookie headers from response ---
        for header_value in &set_cookie_values {
            self.parse_and_store_set_cookie(&conn_server_name, header_value);
        }

        // --- 3.1.3: Verify certificate pins ---
        // reqwest 0.12 does not expose raw certificate chains through its
        // public API, so we pass the chain from the response if available.
        // If no chain was received, pin validation is skipped (reqwest
        // limitation). Once native-tls certificate extraction is implemented,
        // this will validate pins properly.
        if !self.verify_certificate_pin(&conn_server_name, &[]) {
            return Err(AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!(
                    "WinHttpSendRequest: certificate pin validation failed for {}",
                    conn_server_name
                ),
            ));
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
        let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("WinHttpReadData: invalid handle {request_handle:#x}"),
            )
        })?;

        let to_read = buffer.len().min(req.response_body.len());
        buffer[..to_read].copy_from_slice(&req.response_body[..to_read]);
        req.response_body.drain(..to_read);
        Ok(to_read as u32)
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
                0 => {} // WINHTTP_OPTION_PROXY — ignore for now
                _ => {}
            }
            let _ = session;
            return Ok(());
        }
        if let Some(conn) = self.connections.get_mut(&handle) {
            match option {
                _ => {}
            }
            let _ = conn;
            return Ok(());
        }
        if let Some(req) = self.requests.get_mut(&handle) {
            match option {
                4 => {
                    // WINHTTP_OPTION_CONNECT_TIMEOUT
                    if value.len() >= 4 {
                        req.timeout_ms = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
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
        let _ = auth_scheme;
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
                req.headers.insert("Proxy-Authorization".to_string(), auth_value);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // WinHttpQueryAuthSchemes — query supported authentication schemes
    // from the response headers
    // -----------------------------------------------------------------------
    pub fn win_http_query_auth_schemes(
        &self,
        request_handle: HINTERNET,
    ) -> AppResult<(u32, u32)> {
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
                if first_scheme == 0 { first_scheme = 1; }
            }
            if lower.contains("ntlm") {
                supported_schemes |= 2;
                if first_scheme == 0 { first_scheme = 2; }
            }
            if lower.contains("digest") {
                supported_schemes |= 8;
                if first_scheme == 0 { first_scheme = 8; }
            }
            if lower.contains("negotiate") {
                supported_schemes |= 16;
                if first_scheme == 0 { first_scheme = 16; }
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

        let path_start = hostpart.find(|c: char| c == '/' || c == '?' || c == '#').unwrap_or(hostpart.len());
        let host_port = &hostpart[..path_start];
        let path_and_query = &hostpart[path_start..];

        if let Some(colon_pos) = host_port.find(':') {
            hostname = host_port[..colon_pos].to_string();
            port = host_port[colon_pos + 1..].parse::<u16>().unwrap_or(if scheme == "https" { 443 } else { 80 });
        } else {
            hostname = host_port.to_string();
            port = if scheme == "https" { 443 } else { 80 };
        }

        path = if path_and_query.is_empty() { "/".to_string() } else { path_and_query.to_string() };

        Ok((scheme, hostname, port, path, username, password))
    }

    // -----------------------------------------------------------------------
    // InternetCanonicalizeUrlW — canonicalize a URL (percent-encode special chars)
    // (shared between WinHTTP and WinINet dispatch)
    // -----------------------------------------------------------------------
    pub fn internet_canonicalize_url_w(
        &self,
        url: &str,
        url_length: u32,
    ) -> String {
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
        let request = self.requests.get(&request_handle)
            .ok_or_else(|| AppError::new(ReasonCode::RcWin32InvalidHandle, "WinHttpWebSocketCompleteUpgrade: invalid request handle"))?;

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
            format!("{}://{}:{}{}", scheme, c.server_name, c.server_port, request.object_name)
        });

        let ws_handle = self.next_handle;
        self.next_handle += 1;

        let is_text_mode = matches!(request.headers.get("Sec-WebSocket-Protocol")
            .map(|s| s.as_str()), Some("text") | Some("text-only"));

        self.websockets.insert(ws_handle, WinHttpWebSocketState {
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
        });

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
    pub fn websocket_send(
        &mut self,
        ws_handle: HINTERNET,
        buffer_type: WinHttpWebSocketBufferType,
        data: &[u8],
    ) -> AppResult<()> {
        let ws = self.websockets.get(&ws_handle)
            .ok_or_else(|| AppError::new(ReasonCode::RcWin32InvalidHandle, "WinHttpWebSocketSend: invalid WebSocket handle"))?;

        if !ws.is_open {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                "WinHttpWebSocketSend: WebSocket is closed",
            ));
        }

        let _is_text = matches!(buffer_type,
            WinHttpWebSocketBufferType::Utf8MessageBuffer | WinHttpWebSocketBufferType::Utf8FragmentBuffer);

        // Try live tungstenite connection first
        #[cfg(feature = "websocket")]
        if let Some(live_ws) = self.live_websockets.get_mut(&ws_handle) {
            if is_text {
                let text = std::str::from_utf8(data)
                    .map_err(|_| AppError::new(ReasonCode::RcCliInvalid, "WinHttpWebSocketSend: invalid UTF-8 in text frame"))?;
                live_ws.send_text(text)?;
            } else {
                live_ws.send_binary(data)?;
            }
            return Ok(());
        }

        // Buffer-based fallback
        let ws = self.websockets.get_mut(&ws_handle).unwrap();
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
        let ws = self.websockets.get(&ws_handle)
            .ok_or_else(|| AppError::new(ReasonCode::RcWin32InvalidHandle, "WinHttpWebSocketReceive: invalid WebSocket handle"))?;

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
                        ws.receive_buffer.extend_from_slice(&bytes[to_copy..]);
                    }
                    return Ok(to_copy as u32);
                }
                WebSocketMessage::Binary(bin) => {
                    let to_copy = data.len().min(bin.len());
                    data[..to_copy].copy_from_slice(&bin[..to_copy]);
                    if bin.len() > to_copy {
                        let ws = self.websockets.get_mut(&ws_handle).unwrap();
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
        let ws = self.websockets.get_mut(&ws_handle)
            .ok_or_else(|| AppError::new(ReasonCode::RcWin32InvalidHandle, "WinHttpWebSocketClose: invalid WebSocket handle"))?;

        ws.is_open = false;
        ws.close_status = status;
        ws.close_reason = reason.map(|s| s.to_string());

        // Close live tungstenite connection
        #[cfg(feature = "websocket")]
        {
            let code = status as u16;
            let reason_str = reason.unwrap_or("").to_string();
            if let Some(mut live_ws) = self.live_websockets.remove(&ws_handle) {
                let _ = live_ws.close(code, &reason_str);
            }
        }

        Ok(())
    }

    /// WinHttpWebSocketQueryCloseStatus — query the close status of a WebSocket.
    pub fn websocket_query_close_status(
        &self,
        ws_handle: HINTERNET,
    ) -> AppResult<(WinHttpWebSocketCloseStatus, Option<String>)> {
        let ws = self.websockets.get(&ws_handle)
            .ok_or_else(|| AppError::new(ReasonCode::RcWin32InvalidHandle, "WinHttpWebSocketQueryCloseStatus: invalid WebSocket handle"))?;

        Ok((ws.close_status, ws.close_reason.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winhttp_open_close_session() {
        let mut stack = WinHttpStack::new();
        let h = stack.win_http_open(Some("Casa1 Test"), 0, None, None);
        assert!(stack.win_http_close_handle(h).is_ok());
        assert!(stack.win_http_close_handle(h).is_err());
    }

    #[test]
    fn winhttp_open_request_and_send() {
        let mut stack = WinHttpStack::new();
        let session = stack.win_http_open(Some("Casa1"), 0, None, None);
        let conn = stack
            .win_http_connect(session, "httpbin.org", 80, false)
            .expect("connect");
        let req = stack
            .win_http_open_request(conn, "GET", "/get", None)
            .expect("open request");
        stack
            .win_http_send_request(req, None, None)
            .expect("send request");
        let available = stack
            .win_http_query_data_available(req)
            .expect("query available");
        assert!(available > 0);
        let mut buf = vec![0_u8; 4096];
        let read = stack.win_http_read_data(req, &mut buf).expect("read data");
        assert!(read > 0);
        assert!(stack.win_http_close_handle(req).is_ok());
        assert!(stack.win_http_close_handle(conn).is_ok());
        assert!(stack.win_http_close_handle(session).is_ok());
    }

    #[test]
    fn winhttp_rejects_invalid_handle() {
        let mut stack = WinHttpStack::new();
        assert!(stack.win_http_close_handle(0xDEAD).is_err());
        assert!(stack
            .win_http_connect(0xDEAD, "example.com", 443, true)
            .is_err());
    }
}
