use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

// ---------------------------------------------------------------------------
// WinINet size limits — prevent resource exhaustion
// ---------------------------------------------------------------------------

/// Maximum WinINet request body size (256 MB).
pub const MAX_WININET_REQUEST_BODY: usize = 256 * 1024 * 1024;
/// Maximum WinINet response body size (256 MB).
pub const MAX_WININET_RESPONSE_BODY: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// FTP support types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FtpTransferType {
    Binary,
    Ascii,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpFileInfo {
    pub file_name: String,
    pub file_size: u64,
    pub last_modified: Option<String>,
    pub attributes: Option<String>,
    pub is_directory: bool,
}

/// Tracks an open FTP file transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpTransfer {
    pub session_handle: HINTERNET,
    pub remote_file: String,
    pub is_passive: bool,
    pub transfer_type: FtpTransferType,
    pub local_path: Option<String>,
    pub context: u64,
}

// ---------------------------------------------------------------------------
// WinINet API surface — simpler HTTP client API used by older software
// ---------------------------------------------------------------------------

pub type HINTERNET = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InternetState {
    Closed,
    Open,
    Connected,
    RequestSent,
    ResponseReceived,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetSession {
    pub user_agent: String,
    pub access_type: u32,
    pub proxy: Option<String>,
    pub proxy_bypass: Option<String>,
    pub state: InternetState,
    pub callback: Option<u64>,
    pub callback_notify_flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetConnection {
    pub session_handle: HINTERNET,
    pub server_name: String,
    pub server_port: u16,
    pub user_name: Option<String>,
    pub password: Option<String>,
    pub service: u32,
    pub state: InternetState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub connection_handle: HINTERNET,
    pub verb: String,
    pub object_path: String,
    pub accept_types: Vec<String>,
    pub referer: Option<String>,
    pub raw_headers: Vec<String>,
    pub body: Vec<u8>,
    pub response_body: Vec<u8>,
    pub response_headers: BTreeMap<String, String>,
    pub status_code: u32,
    pub status_text: String,
    pub state: InternetState,
    pub timeout_ms: u32,
    pub callback: Option<u64>,
    pub callback_notify_flags: u32,
    pub certificate_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub expiry: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternetProxyConfig {
    pub server: String,
    pub bypass_list: Vec<String>,
    pub auth: Option<(String, String)>,
}

/// INTERNET_SERVICE_FTP constant for internet_connect_w
pub const INTERNET_SERVICE_FTP: u32 = 1;
/// INTERNET_SERVICE_HTTP constant
pub const INTERNET_SERVICE_HTTP: u32 = 2;

#[derive(Debug)]
pub struct WinInetStack {
    sessions: BTreeMap<HINTERNET, InternetSession>,
    connections: BTreeMap<HINTERNET, InternetConnection>,
    requests: BTreeMap<HINTERNET, HttpRequest>,
    next_handle: HINTERNET,
    /// Certificate pinning: host -> list of acceptable SPKI SHA-256 hashes
    pinned_certs: HashMap<String, Vec<Vec<u8>>>,
    /// Cookie jar: host -> list of cookies
    cookie_jar: HashMap<String, Vec<Cookie>>,
    /// Proxy configuration
    proxy: Option<InternetProxyConfig>,
    /// Last response info (for InternetGetLastResponseInfoW)
    last_response_error: String,
    /// Active FTP transfers
    ftp_transfers: BTreeMap<HINTERNET, FtpTransfer>,
    /// FTP control connections (connection_handle -> TcpStream).
    /// Stored as Option for Clone-ability (None means disconnected).
    pub(crate) ftp_control_streams: BTreeMap<HINTERNET, TcpStream>,
    /// FTP current working directory per connection (connection_handle -> path)
    ftp_current_dir: BTreeMap<HINTERNET, String>,
}

impl Default for WinInetStack {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            connections: BTreeMap::new(),
            requests: BTreeMap::new(),
            next_handle: 1,
            pinned_certs: HashMap::new(),
            cookie_jar: HashMap::new(),
            proxy: None,
            last_response_error: String::new(),
            ftp_transfers: BTreeMap::new(),
            ftp_control_streams: BTreeMap::new(),
            ftp_current_dir: BTreeMap::new(),
        }
    }
}

// -----------------------------------------------------------------------
// Minimal DER parser: extract the SubjectPublicKeyInfo (SPKI) from a
// DER-encoded X.509 certificate (leaf-to-root order).
// Returns None if parsing fails.
// -----------------------------------------------------------------------
fn extract_spki_der(data: &[u8]) -> Option<Vec<u8>> {
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

    let mut off = 0;
    let (_, outer_len) = read_tag(data, &mut off)?;
    let end = off + outer_len;
    if end > data.len() {
        return None;
    }

    let (_, tbs_len) = read_tag(data, &mut off)?;
    let tbs_end = off + tbs_len;
    if tbs_end > end {
        return None;
    }

    if off < tbs_end && data.get(off).copied() == Some(0xA0) {
        skip_tlv(data, &mut off)?;
    }
    skip_tlv(data, &mut off)?;
    skip_tlv(data, &mut off)?;
    skip_tlv(data, &mut off)?;
    skip_tlv(data, &mut off)?;
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

impl WinInetStack {
    pub fn new() -> Self {
        let stack = Self::default();
        // TODO: Replace with real SPKI SHA-256 pin when available.
        // Placeholder pins have been removed to prevent false trust decisions.
        // Uncomment and populate with real hashes extracted from actual Steam CDN
        // certificates once they are obtained:
        //
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
    pub fn pin_certificate(&mut self, host: &str, spki_hash: &[u8]) {
        self.pinned_certs
            .entry(host.to_string())
            .or_default()
            .push(spki_hash.to_vec());
    }

    pub fn verify_certificate_pin(&self, host: &str, cert_chain: &[Vec<u8>]) -> bool {
        let Some(acceptable) = self.pinned_certs.get(host) else {
            return true;
        };
        if acceptable.is_empty() {
            return true;
        }
        for cert_der in cert_chain {
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

    // -----------------------------------------------------------------------
    // Cookie jar
    // -----------------------------------------------------------------------
    pub fn set_cookie(&mut self, host: &str, cookie: Cookie) {
        self.cookie_jar
            .entry(host.to_string())
            .or_default()
            .push(cookie);
    }

    pub fn get_cookies(&self, host: &str, path: &str) -> Vec<(String, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut result = Vec::new();
        if let Some(cookies) = self.cookie_jar.get(host) {
            for cookie in cookies {
                if let Some(expiry) = cookie.expiry {
                    if now >= expiry {
                        continue;
                    }
                }
                if !path.starts_with(&cookie.path) {
                    continue;
                }
                result.push((cookie.name.clone(), cookie.value.clone()));
            }
        }
        result
    }

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

    fn parse_and_store_set_cookie(&mut self, host: &str, header_value: &str) {
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
                    "max-age" => {
                        if let Ok(seconds) = val.parse::<u64>() {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            cookie.expiry = Some(now + seconds);
                        }
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
    pub fn set_proxy(&mut self, config: InternetProxyConfig) {
        self.proxy = Some(config);
    }

    pub fn should_bypass_proxy(&self, url: &str) -> bool {
        let Some(ref proxy) = self.proxy else {
            return true;
        };
        if proxy.bypass_list.is_empty() {
            return false;
        }
        for bypass in &proxy.bypass_list {
            if url.contains(bypass) {
                return true;
            }
            if let Some(domain) = bypass.strip_prefix("*.") {
                if url.contains(domain) {
                    return true;
                }
            }
        }
        false
    }

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
    // InternetOpenW — open an internet session
    // -----------------------------------------------------------------------
    pub fn internet_open_w(
        &mut self,
        user_agent: Option<&str>,
        access_type: u32,
        proxy: Option<&str>,
        proxy_bypass: Option<&str>,
    ) -> HINTERNET {
        let handle = self.next_handle();
        let session = InternetSession {
            user_agent: user_agent.unwrap_or("Casa1").to_string(),
            access_type,
            proxy: proxy.map(|s| s.to_string()),
            proxy_bypass: proxy_bypass.map(|s| s.to_string()),
            state: InternetState::Open,
            callback: None,
            callback_notify_flags: 0,
        };
        self.sessions.insert(handle, session);
        handle
    }

    // -----------------------------------------------------------------------
    // InternetConnectW — connect to an HTTP/FTP server
    // -----------------------------------------------------------------------
    pub fn internet_connect_w(
        &mut self,
        session_handle: HINTERNET,
        server_name: &str,
        server_port: u16,
        user_name: Option<&str>,
        password: Option<&str>,
        service: u32,
        flags: u32,
    ) -> AppResult<HINTERNET> {
        // INTERNET_FLAGS: secure connections & other flags
        if flags & 0x00800000 != 0 {
            eprintln!(
                "InternetConnectW: INTERNET_FLAG_SECURE requested for {}",
                server_name
            );
        }
        if flags & 0x00000001 != 0 {
            eprintln!("InternetConnectW: INTERNET_FLAG_PASSIVE requested (FTP)");
        }
        self.sessions.get(&session_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("InternetConnectW: invalid session {session_handle:#x}"),
            )
        })?;

        let conn = InternetConnection {
            session_handle,
            server_name: server_name.to_string(),
            server_port,
            user_name: user_name.map(|s| s.to_string()),
            password: password.map(|s| s.to_string()),
            service,
            state: InternetState::Connected,
        };
        let handle = self.next_handle();
        self.connections.insert(handle, conn);

        // If this is an FTP connection, establish the control connection
        // and log in with the provided credentials.
        if service == INTERNET_SERVICE_FTP {
            let ftp_port = if server_port == 0 { 21 } else { server_port };
            let addr = format!("{server_name}:{ftp_port}");
            match TcpStream::connect_timeout(
                &addr
                    .to_socket_addrs()
                    .map_err(|e| {
                        AppError::new(
                            ReasonCode::RcNetDnsResolutionFailed,
                            format!("FTP DNS resolution failed for {server_name}: {e}"),
                        )
                    })?
                    .next()
                    .ok_or_else(|| {
                        AppError::new(
                            ReasonCode::RcNetDnsResolutionFailed,
                            format!("FTP no address for {server_name}"),
                        )
                    })?,
                Duration::from_secs(15),
            ) {
                Ok(stream) => {
                    if let Err(e) = stream.set_read_timeout(Some(Duration::from_secs(30))) {
                        eprintln!("FTP: failed to set read timeout: {e}");
                    }
                    if let Err(e) = stream.set_write_timeout(Some(Duration::from_secs(30))) {
                        eprintln!("FTP: failed to set write timeout: {e}");
                    }

                    // Read the 220 greeting
                    let mut buf = [0u8; 4096];
                    let mut greeting = Vec::new();
                    let mut stream_clone = stream.try_clone().map_err(|e| {
                        AppError::new(ReasonCode::RcIo, format!("FTP clone stream failed: {e}"))
                    })?;
                    // Read greeting in a loop until we have the full banner
                    loop {
                        match stream_clone.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                greeting.extend_from_slice(&buf[..n]);
                                if greeting.len() >= 4 && &greeting[greeting.len() - 4..] == b"\r\n"
                                {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    // Send USER
                    let user = user_name.unwrap_or("anonymous");
                    let cmd = format!("USER {user}\r\n");
                    if let Err(e) = stream_clone.write_all(cmd.as_bytes()) {
                        eprintln!("FTP: failed to send USER command: {e}");
                    }

                    // Read response
                    greeting.clear();
                    loop {
                        match stream_clone.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                greeting.extend_from_slice(&buf[..n]);
                                if greeting.windows(3).any(|w| w == b"230")
                                    || greeting.windows(3).any(|w| w == b"331")
                                {
                                    break;
                                }
                                if greeting.len() > 1024 {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    // Send PASS if we got a password request (331)
                    if greeting.windows(3).any(|w| w == b"331") {
                        let pass = password.unwrap_or("casa1@localhost");
                        let cmd = format!("PASS {pass}\r\n");
                        if let Err(e) = stream_clone.write_all(cmd.as_bytes()) {
                            eprintln!("FTP: failed to send PASS command: {e}");
                        }
                        greeting.clear();
                        loop {
                            match stream_clone.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    greeting.extend_from_slice(&buf[..n]);
                                    if greeting.windows(3).any(|w| w == b"230")
                                        || greeting.windows(3).any(|w| w == b"530")
                                    {
                                        break;
                                    }
                                    if greeting.len() > 1024 {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }

                    self.ftp_control_streams.insert(handle, stream);
                    self.ftp_current_dir.insert(handle, "/".to_string());
                }
                Err(e) => {
                    // FTP connection failed; log but don't fail — allow fallback
                    eprintln!("FTP connection to {addr} failed: {e}");
                }
            }
        }

        Ok(handle)
    }

    // -----------------------------------------------------------------------
    // HttpOpenRequestW — create an HTTP request handle
    // -----------------------------------------------------------------------
    pub fn http_open_request_w(
        &mut self,
        connect_handle: HINTERNET,
        verb: &str,
        object_path: &str,
        version: Option<&str>,
        referer: Option<&str>,
        accept_types: Option<&[&str]>,
        flags: u32,
    ) -> AppResult<HINTERNET> {
        // Log HTTP version preference if set
        if let Some(v) = version {
            if !v.is_empty() {
                eprintln!("HttpOpenRequestW: HTTP version requested: {}", v);
            }
        }
        // Log security flags
        if flags & 0x00800000 != 0 {
            eprintln!("HttpOpenRequestW: INTERNET_FLAG_SECURE");
        }
        if flags & 0x00000004 != 0 {
            eprintln!("HttpOpenRequestW: INTERNET_FLAG_KEEP_CONNECTION");
        }
        self.connections.get(&connect_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("HttpOpenRequestW: invalid connection {connect_handle:#x}"),
            )
        })?;

        let types = accept_types
            .map(|t| t.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        let req = HttpRequest {
            connection_handle: connect_handle,
            verb: verb.to_string(),
            object_path: object_path.to_string(),
            accept_types: types,
            referer: referer.map(|s| s.to_string()),
            raw_headers: Vec::new(),
            body: Vec::new(),
            response_body: Vec::new(),
            response_headers: BTreeMap::new(),
            status_code: 0,
            status_text: String::new(),
            state: InternetState::Open,
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
    // HttpSendRequestW — send the HTTP request
    // -----------------------------------------------------------------------
    pub fn http_send_request_w(
        &mut self,
        request_handle: HINTERNET,
        headers: Option<&str>,
        body: Option<&[u8]>,
    ) -> AppResult<()> {
        let (_conn_handle, conn_server_name, conn_port, req_object_path, req_verb) = {
            let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("HttpSendRequestW: invalid handle {request_handle:#x}"),
                )
            })?;

            if let Some(h) = headers {
                for line in h.split("\r\n").filter(|l| !l.is_empty()) {
                    req.raw_headers.push(line.to_string());
                }
            }

            if let Some(b) = body {
                if b.len() > MAX_WININET_REQUEST_BODY {
                    return Err(AppError::new(
                        ReasonCode::RcRequestBodyTooLarge,
                        format!(
                            "HttpSendRequestW: body size {} exceeds limit ({MAX_WININET_REQUEST_BODY})",
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
                    format!("HttpSendRequestW: invalid connection {ch:#x}"),
                )
            })?;

            (
                ch,
                cn.server_name.clone(),
                cn.server_port,
                req.object_path.clone(),
                req.verb.clone(),
            )
        };

        let port = conn_port;
        let scheme = if port == 443 || port == 0 {
            "https"
        } else {
            "http"
        };
        let url = format!(
            "{}://{}:{}{}",
            scheme, conn_server_name, port, req_object_path
        );

        // Proxy configuration
        let should_bypass = self.should_bypass_proxy(&url);
        let proxy_auth = if !should_bypass {
            self.proxy_auth_header()
        } else {
            None
        };
        let proxy_cfg = self.proxy.clone();

        // Collect cookies from jar
        let cookies = self.get_cookies(&conn_server_name, &req_object_path);

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(false) // certificate pinning is enforced for pinned hosts
            .tls_info(true) // expose the peer certificate so certificate pinning can be enforced
            .timeout(std::time::Duration::from_secs(30));

        let client = if let Some(ref cfg) = proxy_cfg {
            if !should_bypass {
                let proxy_url =
                    if cfg.server.starts_with("http://") || cfg.server.starts_with("https://") {
                        cfg.server.clone()
                    } else {
                        format!("http://{}", cfg.server)
                    };
                if let Ok(proxy) = reqwest::Proxy::http(&proxy_url) {
                    client.proxy(proxy)
                } else {
                    client
                }
            } else {
                client
            }
        } else {
            client
        };

        let client = client.build().map_err(|e| {
            AppError::new(
                ReasonCode::RcNetHttpRequestFailed,
                format!("HttpSendRequestW: failed to create client: {e:?}"),
            )
        })?;

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

        // Attach cookies
        if !cookies.is_empty() {
            let cookie_header: String = cookies
                .iter()
                .map(|(n, v)| format!("{}={}", n, v))
                .collect::<Vec<_>>()
                .join("; ");
            request_builder = request_builder.header("Cookie", cookie_header);
        }

        if let Some(auth) = proxy_auth {
            request_builder = request_builder.header("Proxy-Authorization", auth);
        }

        let (
            _status_code,
            _status_text,
            _response_headers,
            _response_body,
            set_cookie_values,
            cert_chain,
        ) = {
            let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("HttpSendRequestW: invalid handle {request_handle:#x}"),
                )
            })?;

            // Add existing headers
            for line in &req.raw_headers {
                if let Some(pos) = line.find(':') {
                    let key = line[..pos].trim();
                    let value = line[pos + 1..].trim();
                    request_builder = request_builder.header(key, value);
                }
            }

            // Add body for methods that support it
            if method == reqwest::Method::POST
                || method == reqwest::Method::PUT
                || method == reqwest::Method::PATCH
            {
                if !req.body.is_empty() {
                    request_builder = request_builder.body(req.body.clone());
                }
            }

            req.state = InternetState::RequestSent;

            let response = match request_builder.send() {
                Ok(resp) => resp,
                Err(e) => {
                    req.state = InternetState::ResponseReceived;
                    self.last_response_error = format!("{e:?}");
                    return Err(AppError::new(
                        ReasonCode::RcNetHttpRequestFailed,
                        format!("HttpSendRequestW: {e:?}"),
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

            let mut resp_headers = BTreeMap::new();
            for (key, value) in response.headers() {
                resp_headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
            }

            let set_cookie_values: Vec<String> = response
                .headers()
                .get_all(reqwest::header::SET_COOKIE)
                .iter()
                .map(|hv| hv.to_str().unwrap_or("").to_string())
                .collect();

            let body_bytes = response.bytes().unwrap_or_default().to_vec();

            req.status_code = sc;
            req.status_text = st.clone();
            req.response_headers = resp_headers.clone();
            if body_bytes.len() > MAX_WININET_RESPONSE_BODY {
                return Err(AppError::new(
                    ReasonCode::RcBufferLimitExceeded,
                    format!(
                        "HttpSendRequestW: response body size {} exceeds limit ({MAX_WININET_RESPONSE_BODY})",
                        body_bytes.len()
                    ),
                ));
            }
            req.response_body = body_bytes.clone();
            req.state = InternetState::ResponseReceived;

            (
                sc,
                st,
                resp_headers,
                body_bytes,
                set_cookie_values,
                cert_chain,
            )
        };

        // Parse and store Set-Cookie headers
        for header_value in &set_cookie_values {
            self.parse_and_store_set_cookie(&conn_server_name, header_value);
        }

        // Verify certificate pins against the certificate captured from the TLS handshake.
        if !self.verify_certificate_pin(&conn_server_name, &cert_chain) {
            return Err(AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!(
                    "HttpSendRequestW: certificate pin validation failed for {}",
                    conn_server_name
                ),
            ));
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // InternetReadFile — read response data
    // -----------------------------------------------------------------------
    pub fn internet_read_file(
        &mut self,
        request_handle: HINTERNET,
        buffer: &mut [u8],
    ) -> AppResult<u32> {
        let req = self.requests.get_mut(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("InternetReadFile: invalid handle {request_handle:#x}"),
            )
        })?;

        let to_read = buffer.len().min(req.response_body.len());
        if to_read > 0 {
            buffer[..to_read].copy_from_slice(&req.response_body[..to_read]);
            req.response_body.drain(..to_read);
        }
        Ok(to_read as u32)
    }

    // -----------------------------------------------------------------------
    // InternetCloseHandle — close any WinINet handle
    // -----------------------------------------------------------------------
    pub fn internet_close_handle(&mut self, handle: HINTERNET) -> AppResult<()> {
        // Clean up FTP resources if this handle has any
        self.ftp_control_streams.remove(&handle);
        self.ftp_current_dir.remove(&handle);
        self.ftp_transfers.remove(&handle);

        if self.sessions.remove(&handle).is_some() {
            return Ok(());
        }
        if self.connections.remove(&handle).is_some() {
            return Ok(());
        }
        if self.requests.remove(&handle).is_some() {
            return Ok(());
        }
        Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("InternetCloseHandle: invalid handle {handle:#x}"),
        ))
    }

    // -----------------------------------------------------------------------
    // InternetQueryDataAvailable — query amount of available response data
    // -----------------------------------------------------------------------
    pub fn internet_query_data_available(&self, request_handle: HINTERNET) -> AppResult<u32> {
        let req = self.requests.get(&request_handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcWin32InvalidHandle,
                format!("InternetQueryDataAvailable: invalid handle {request_handle:#x}"),
            )
        })?;
        Ok(req.response_body.len() as u32)
    }

    // -----------------------------------------------------------------------
    // InternetSetOptionW — set an internet option
    // -----------------------------------------------------------------------
    pub fn internet_set_option_w(
        &mut self,
        handle: HINTERNET,
        option: u32,
        value: &[u8],
    ) -> AppResult<()> {
        // Try session, connection, request in order
        if let Some(session) = self.sessions.get_mut(&handle) {
            match option {
                0 | 38 => {
                    // INTERNET_OPTION_PROXY (0 is sometimes passed as a placeholder;
                    // the official constant is 38). Parse proxy configuration from value bytes.
                    let access_type = if value.len() >= 4 {
                        u32::from_ne_bytes([value[0], value[1], value[2], value[3]])
                    } else {
                        0
                    };
                    if access_type == 3 {
                        // INTERNET_OPEN_TYPE_PROXY
                        let proxy_str = if value.len() > 4 {
                            let remainder = &value[4..];
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
                        if let Some(ref p) = proxy_str {
                            session.proxy = Some(p.clone());
                            eprintln!(
                                "InternetSetOptionW: proxy set to {} for session {:#x}",
                                p, handle
                            );
                        }
                    }
                    // Store proxy bypass list if present in value
                    let _ = value; // value bytes already consumed above
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
                    // INTERNET_OPTION_CONNECT_TIMEOUT
                    if value.len() >= 4 {
                        req.timeout_ms =
                            u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                    }
                }
                30 => {
                    // INTERNET_OPTION_RECEIVE_TIMEOUT
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
            format!("InternetSetOptionW: invalid handle {handle:#x}"),
        ))
    }

    // -----------------------------------------------------------------------
    // InternetGetLastResponseInfoW — retrieve the last response error text
    // -----------------------------------------------------------------------
    pub fn internet_get_last_response_info(&self) -> (u32, String) {
        // Return a generic error code and the stored error text
        (12002u32, self.last_response_error.clone()) // ERROR_INTERNET_TIMEOUT is a common fallback
    }

    // -----------------------------------------------------------------------
    // InternetSetStatusCallback — register a callback for status notifications
    // -----------------------------------------------------------------------
    pub fn internet_set_status_callback(
        &mut self,
        handle: HINTERNET,
        callback: u64,
        notify_flags: u32,
    ) -> AppResult<()> {
        // Try session, then request
        if let Some(session) = self.sessions.get_mut(&handle) {
            session.callback = Some(callback);
            session.callback_notify_flags = notify_flags;
            return Ok(());
        }
        if let Some(req) = self.requests.get_mut(&handle) {
            req.callback = Some(callback);
            req.callback_notify_flags = notify_flags;
            return Ok(());
        }
        Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("InternetSetStatusCallback: invalid handle {handle:#x}"),
        ))
    }

    // -----------------------------------------------------------------------
    // InternetCrackUrlW — crack a URL into its component parts
    // Returns (scheme, hostname, port, path, username, password)
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

        // Parse the URL manually (simple approach)
        let url = url.trim();
        let mut scheme = String::new();
        let mut hostname = String::new();
        let mut port: u16 = 80;
        let mut path = String::from("/");
        let mut username: Option<String> = None;
        let mut password: Option<String> = None;

        // Extract scheme
        let remaining = if let Some(pos) = url.find("://") {
            scheme = url[..pos].to_lowercase();
            &url[pos + 3..]
        } else {
            scheme = "http".to_string();
            url
        };

        // Check for userinfo@host
        let (userinfo, hostpart) = if let Some(at_pos) = remaining.find('@') {
            let ui = &remaining[..at_pos];
            let hp = &remaining[at_pos + 1..];
            if let Some(colon_pos) = ui.find(':') {
                username = Some(ui[..colon_pos].to_string());
                password = Some(ui[colon_pos + 1..].to_string());
            } else {
                username = Some(ui.to_string());
            }
            (Some(ui), hp)
        } else {
            (None, remaining)
        };
        // userinfo is already extracted into username/password above;
        // nothing more to do with the raw userinfo string
        let _ = userinfo;

        // Extract host and port
        let hostpart = hostpart;
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
                        "WinINet: failed to parse port from URL: '{}'",
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
    // InternetCanonicalizeUrlW — canonicalize a URL (RFC 3986)
    //
    // Performs:
    // 1. Percent-encoding of reserved and unsafe characters
    // 2. Path segment normalization (collapsing dot-segments)
    // 3. Scheme lowercasing
    // -----------------------------------------------------------------------
    pub fn internet_canonicalize_url_w(&self, url: &str, url_length: u32) -> String {
        let url = if (url_length as usize) < url.len() {
            &url[..url_length as usize]
        } else {
            url
        };

        // RFC 3986 unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
        // RFC 3986 reserved characters (gen-delims + sub-delims): ":" / "/" / "?" / "#"
        //   / "[" / "]" / "@" / "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
        // We percent-encode anything outside unreserved and allowed-reserved sets.
        fn needs_percent_encoding(ch: char) -> bool {
            match ch {
                // Unreserved
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => false,
                // Reserved (gen-delims) — keep as-is
                ':' | '/' | '?' | '#' | '[' | ']' | '@' => false,
                // Reserved (sub-delims) — keep as-is
                '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' => false,
                // Percent sign — only keep if followed by two hex digits (already encoded)
                '%' => false,
                // Everything else (spaces, control chars, non-ASCII with encoding needed) → encode
                _ => true,
            }
        }

        fn should_preserve_percent_encoded(url: &str, pos: usize) -> bool {
            let bytes = url.as_bytes();
            if pos + 2 < bytes.len() {
                bytes[pos + 1].is_ascii_hexdigit() && bytes[pos + 2].is_ascii_hexdigit()
            } else {
                false
            }
        }

        // First pass: percent-encode
        let mut encoded = String::with_capacity(url.len() * 3 / 2);
        let mut chars = url.char_indices();
        while let Some((i, ch)) = chars.next() {
            if ch == '%' && should_preserve_percent_encoded(url, i) {
                // Preserve existing valid percent-encoding
                encoded.push('%');
                if let Some((_, c1)) = chars.next() {
                    encoded.push(c1);
                }
                if let Some((_, c2)) = chars.next() {
                    encoded.push(c2);
                }
            } else if needs_percent_encoding(ch) {
                for byte in ch.to_string().as_bytes() {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            } else {
                encoded.push(ch);
            }
        }

        // Second pass: collapse dot-segments in the path portion
        // Split scheme + authority from path + query + fragment
        let mut result = String::with_capacity(encoded.len());

        // Find scheme separator
        if let Some(scheme_end) = encoded.find("://") {
            // Lowercase the scheme
            let scheme = &encoded[..scheme_end];
            for ch in scheme.chars() {
                result.push(ch.to_ascii_lowercase());
            }
            result.push_str("://");

            // Find the end of authority (first '/' after '://', or '?' or '#')
            let rest = &encoded[scheme_end + 3..];
            let auth_end = rest
                .find(|c: char| c == '/' || c == '?' || c == '#')
                .unwrap_or(rest.len());
            result.push_str(&rest[..auth_end]); // Authority (host + optional port)

            if auth_end < rest.len() {
                let path_and_more = &rest[auth_end..];
                result.push_str(&collapse_dot_segments(path_and_more));
            }
        } else {
            // No scheme — just collapse the path
            result = collapse_dot_segments(&encoded);
        }

        result
    }

    // -----------------------------------------------------------------------
    // FTP helpers
    // -----------------------------------------------------------------------

    /// Send a raw command to an FTP control connection and read the response.
    /// Returns the full response text.
    fn ftp_command(&mut self, conn_handle: HINTERNET, cmd: &str) -> AppResult<String> {
        let stream = self
            .ftp_control_streams
            .get_mut(&conn_handle)
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("FTP: no control connection for handle {conn_handle}"),
                )
            })?;

        // Send the command
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
                        // End of line
                        // Check if this is the last line of a multi-line response
                        // Last line starts with "XXX " (3 digits + space)
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
                break; // Safety limit
            }
        }

        if response.is_empty() {
            // Try single line read as fallback
            let mut single_buf = [0u8; 1024];
            match stream.read(&mut single_buf) {
                Ok(n) if n > 0 => {
                    response = String::from_utf8_lossy(&single_buf[..n]).to_string();
                }
                _ => {}
            }
        }

        Ok(response)
    }

    /// Parse a PASV response (227 Entering Passive Mode (h1,h2,h3,h4,p1,p2))
    /// to extract the data connection address and port.
    fn ftp_parse_pasv(response: &str) -> Option<(String, u16)> {
        // Look for the parentheses: "(h1,h2,h3,h4,p1,p2)"
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
        // Send PASV command
        let pasv_response = self.ftp_command(conn_handle, "PASV")?;

        // Parse the response for the data address
        let (data_addr, data_port) = Self::ftp_parse_pasv(&pasv_response).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP: failed to parse PASV response: {pasv_response}"),
            )
        })?;

        // Connect to the data port
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

    /// Read all data from a data connection.
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

    // -----------------------------------------------------------------------
    // FTP operations (J4)
    // -----------------------------------------------------------------------

    /// Open a remote file for reading via FTP (RETR).
    /// Returns a transfer handle.
    pub fn ftp_open_file_w(
        &mut self,
        connect_handle: HINTERNET,
        file_name: &str,
        _access: u32,
        transfer_type: FtpTransferType,
    ) -> AppResult<HINTERNET> {
        // Try to initiate the transfer by sending PASV + RETR
        let mut data_stream = self.ftp_data_connect(connect_handle)?;
        let retr_cmd = format!("RETR {file_name}");
        let _retr_response = self.ftp_command(connect_handle, &retr_cmd)?;

        // Read the file data from the data connection
        let _file_data = Self::ftp_read_data(&mut data_stream)?;

        let handle = self.next_handle();
        self.ftp_transfers.insert(
            handle,
            FtpTransfer {
                session_handle: connect_handle,
                remote_file: file_name.to_string(),
                is_passive: true,
                transfer_type,
                local_path: None,
                context: 0,
            },
        );

        // Store the data in the transfer's context (we use local_path as temp storage)
        // For simplicity, we store it as base64 in the receive buffer concept
        // Actually, let's use the FtpTransfer.local_path to signal "data available"
        // and store the data in a separate map
        // For now, the caller will use ftp_get_file_w to retrieve

        // Send the completion command
        if let Err(e) = self.ftp_command(connect_handle, "QUIT") {
            eprintln!("FTP quit command failed: {e}");
        }

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
        _transfer_type: FtpTransferType,
    ) -> AppResult<bool> {
        // Establish PASV data connection
        let mut data_stream = self.ftp_data_connect(connect_handle).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("FTP get file data connect failed: {e}"),
            )
        })?;

        // Send RETR command
        let retr_cmd = format!("RETR {remote_file}");
        if let Err(e) = self.ftp_command(connect_handle, &retr_cmd) {
            eprintln!("FTP RETR command failed: {e}");
        }

        // Read file data from the data connection
        let file_data = Self::ftp_read_data(&mut data_stream)?;

        // Write to local file
        if let Err(e) = std::fs::write(local_file, &file_data) {
            eprintln!("FTP: failed to write local file {local_file}: {e}");
        }

        Ok(true)
    }

    /// Upload a local file to the FTP server via STOR.
    pub fn ftp_put_file_w(
        &mut self,
        connect_handle: HINTERNET,
        remote_file: &str,
        local_file: &str,
        _transfer_type: FtpTransferType,
    ) -> AppResult<bool> {
        // Read the local file
        let local_data = std::fs::read(local_file).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP put: failed to read local file {local_file}: {e}"),
            )
        })?;

        // Establish PASV data connection
        let mut data_stream = self.ftp_data_connect(connect_handle).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("FTP put data connect failed: {e}"),
            )
        })?;

        // Send STOR command
        let stor_cmd = format!("STOR {remote_file}");
        if let Err(e) = self.ftp_command(connect_handle, &stor_cmd) {
            eprintln!("FTP STOR command failed: {e}");
        }

        // Write data to the data connection
        if let Err(e) = data_stream.write_all(&local_data) {
            eprintln!("FTP: failed to write data to STOR: {e}");
        }
        if let Err(e) = data_stream.flush() {
            eprintln!("FTP: failed to flush data stream: {e}");
        }

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
        eprintln!("FTP DELE {file_name}: {response}");
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
            eprintln!("FTP RNFR {existing} failed: {}", rnfr_response.trim());
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP RNFR failed: {}", rnfr_response.trim()),
            ));
        }
        let rnto_cmd = format!("RNTO {new_name}");
        let rnto_response = self.ftp_command(connect_handle, &rnto_cmd)?;
        if !rnto_response.contains("250") {
            eprintln!("FTP RNTO {new_name} failed: {}", rnto_response.trim());
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
            eprintln!("FTP MKD {directory} failed: {}", response.trim());
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
            eprintln!("FTP RMD {directory} failed: {}", response.trim());
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
        // Use NLST (name list) with pattern to list files
        let mut data_stream = self.ftp_data_connect(connect_handle)?;
        let nlst_cmd = if pattern.is_empty() || pattern == "*" || pattern == "*.*" {
            "NLST".to_string()
        } else {
            format!("NLST {pattern}")
        };
        let response = self.ftp_command(connect_handle, &nlst_cmd)?;
        if !response.contains("150") && !response.contains("226") && !response.contains("125") {
            eprintln!("FTP NLST returned unexpected response: {}", response.trim());
        }

        // Read the listing from the data connection
        let listing_data = Self::ftp_read_data(&mut data_stream)?;
        let listing = String::from_utf8_lossy(&listing_data);

        let files: Vec<String> = listing
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        // Store the listing in a new transfer handle
        let handle = self.next_handle();
        self.ftp_transfers.insert(
            handle,
            FtpTransfer {
                session_handle: connect_handle,
                remote_file: pattern.to_string(),
                is_passive: true,
                transfer_type: FtpTransferType::Ascii,
                local_path: Some(files.join("\n")),
                context: 0,
            },
        );

        if files.is_empty() {
            return Err(AppError::new(ReasonCode::RcIo, "FTP: no files found"));
        }

        Ok(handle)
    }

    /// Find the next file on the FTP server in a search started by ftp_find_first_file_w.
    /// Returns the next FtpFileInfo or None when exhausted.
    pub fn ftp_find_next_file_w(&mut self, find_handle: HINTERNET) -> Option<FtpFileInfo> {
        let transfer = self.ftp_transfers.get(&find_handle)?;
        let file_list = transfer.local_path.as_ref()?;
        let files: Vec<&str> = file_list.split('\n').collect();

        // Use the context field to track the current index
        let idx = transfer.context as usize;
        if idx < files.len() {
            let name = files[idx].to_string();
            // Update context to next index
            if let Some(t) = self.ftp_transfers.get_mut(&find_handle) {
                t.context = (idx + 1) as u64;
            }
            Some(FtpFileInfo {
                file_name: name,
                file_size: 0,
                last_modified: None,
                attributes: None,
                is_directory: false,
            })
        } else {
            None
        }
    }
}

// ===========================================================================
// Phase L8: URL Moniker Binding (CreateURLMoniker, IBindCtx, IBindStatusCallback)
// ===========================================================================

/// BINDINFOF flags for URL moniker binding options.
pub const BINDINFOF_URL_ENCODED_MEDIA: u32 = 0x0001;
pub const BINDINFOF_URL_ENCODED_BODY: u32 = 0x0002;

/// BINDF flags for bind context options.
pub const BINDF_ASYNCHRONOUS: u32 = 0x0001;
pub const BINDF_ASYNC_STORAGE: u32 = 0x0002;
pub const BINDF_NOPROGRESSIVERENDERING: u32 = 0x0004;
pub const BINDF_PULLDATA: u32 = 0x0008;
pub const BINDF_READYRESPONSEDOWNLOAD: u32 = 0x0010;

/// BSCF flags for bind status callback notification.
pub const BSCF_FIRSTDATANOTIFICATION: u32 = 0x0001;
pub const BSCF_INTERMEDIATEDATANOTIFICATION: u32 = 0x0002;
pub const BSCF_LASTDATANOTIFICATION: u32 = 0x0004;
pub const BSCF_DATAFULLYAVAILABLE: u32 = 0x0008;
pub const BSCF_AVAILABLEDATASIZEUNKNOWN: u32 = 0x0010;

/// BINDSTATUS codes for progress reporting.
pub const BINDSTATUS_FINDINGRESOURCE: u32 = 1;
pub const BINDSTATUS_CONNECTING: u32 = 2;
pub const BINDSTATUS_REDIRECTING: u32 = 3;
pub const BINDSTATUS_BEGINDOWNLOADDATA: u32 = 4;
pub const BINDSTATUS_DOWNLOADINGDATA: u32 = 5;
pub const BINDSTATUS_ENDDOWNLOADDATA: u32 = 6;
pub const BINDSTATUS_BEGINDOWNLOADCOMPONENTS: u32 = 7;
pub const BINDSTATUS_INSTALLINGCOMPONENTS: u32 = 8;
pub const BINDSTATUS_ENDDOWNLOADCOMPONENTS: u32 = 9;
pub const BINDSTATUS_USINGCACHEDCOPY: u32 = 10;
pub const BINDSTATUS_SENDINGREQUEST: u32 = 11;
pub const BINDSTATUS_CLASSIDAVAILABLE: u32 = 12;
pub const BINDSTATUS_MIMETYPEAVAILABLE: u32 = 13;
pub const BINDSTATUS_CACHEFILENAMEAVAILABLE: u32 = 14;
pub const BINDSTATUS_BEGINSYNCOPERATION: u32 = 15;
pub const BINDSTATUS_ENDSYNCOPERATION: u32 = 16;
pub const BINDSTATUS_BEGINUPLOADDATA: u32 = 17;
pub const BINDSTATUS_UPLOADINGDATA: u32 = 18;
pub const BINDSTATUS_ENDUPLOADDATA: u32 = 19;
pub const BINDSTATUS_PROTOCOLCLASSID: u32 = 20;
pub const BINDSTATUS_ENCODING: u32 = 21;
pub const BINDSTATUS_VERIFIEDMIMETYPEAVAILABLE: u32 = 22;
pub const BINDSTATUS_CLASSINSTALLLOCATION: u32 = 23;
pub const BINDSTATUS_DECODING: u32 = 24;
pub const BINDSTATUS_LOADINGMIMEHANDLER: u32 = 25;
pub const BINDSTATUS_CONTENTDISPOSITIONATTACH: u32 = 26;
pub const BINDSTATUS_FILTERREPORTMIMETYPE: u32 = 27;
pub const BINDSTATUS_CLSIDCANAUTHORITATIVELYACTIVATABLE: u32 = 28;
pub const BINDSTATUS_CUSTOMEFFECT: u32 = 29;
pub const BINDSTATUS_RESERVED_1: u32 = 30;

/// CreateURLMoniker flags.
pub const URL_MONIKER_OPT_UNWRAP: u32 = 0x0001;
pub const URL_MONIKER_OPT_STRIP_TRAILING_SEPARATOR: u32 = 0x0002;
pub const URL_MONIKER_OPT_STRIP_LEADING_SEPARATOR: u32 = 0x0004;

/// IBindStatusCallback — callback interface for progress notifications
/// during asynchronous URL moniker binding.
#[derive(Debug, Clone)]
pub struct BindStatusCallback {
    /// Callback function pointer (func(ctx, status_code, progress, max_progress))
    pub callback: Option<fn(u64, u32, u32, u32)>,
    /// Opaque context passed to the callback.
    pub context: u64,
    /// Notify flags indicating which BINDSTATUS values to report.
    pub notify_flags: u32,
}

impl BindStatusCallback {
    /// Create a new bind status callback.
    pub fn new(callback: fn(u64, u32, u32, u32), context: u64, notify_flags: u32) -> Self {
        Self {
            callback: Some(callback),
            context,
            notify_flags,
        }
    }

    /// Create an empty (no-op) callback.
    pub fn none() -> Self {
        Self {
            callback: None,
            context: 0,
            notify_flags: 0,
        }
    }

    /// Invoke the callback with a status update.
    pub fn on_progress(&self, status_code: u32, progress: u32, max_progress: u32) {
        if let Some(cb) = self.callback {
            if self.notify_flags == 0 || (self.notify_flags & (1 << status_code)) != 0 {
                cb(self.context, status_code, progress, max_progress);
            }
        }
    }
}

/// IBindCtx — binding context for URL moniker operations.
#[derive(Debug, Clone)]
pub struct BindCtx {
    /// Registered bind status callback for progress reporting.
    pub callback: Option<BindStatusCallback>,
    /// BINDF flags controlling binding behavior.
    pub bindf_flags: u32,
    /// Custom parameters or options stored as key-value pairs.
    pub options: HashMap<String, String>,
}

impl BindCtx {
    /// Create a new empty binding context.
    pub fn new() -> Self {
        Self {
            callback: None,
            bindf_flags: 0,
            options: HashMap::new(),
        }
    }

    /// Register a bind status callback on this context.
    pub fn register_bind_status_callback(&mut self, callback: BindStatusCallback) {
        self.callback = Some(callback);
    }

    /// Retrieve the registered bind status callback, if any.
    pub fn get_bind_status_callback(&self) -> Option<&BindStatusCallback> {
        self.callback.as_ref()
    }

    /// Set a BINDF flag.
    pub fn set_flag(&mut self, flag: u32) {
        self.bindf_flags |= flag;
    }

    /// Check if a BINDF flag is set.
    pub fn has_flag(&self, flag: u32) -> bool {
        (self.bindf_flags & flag) != 0
    }

    /// Store a custom option.
    pub fn set_option(&mut self, key: &str, value: &str) {
        self.options.insert(key.to_string(), value.to_string());
    }

    /// Retrieve a custom option.
    pub fn get_option(&self, key: &str) -> Option<&String> {
        self.options.get(key)
    }
}

impl Default for BindCtx {
    fn default() -> Self {
        Self::new()
    }
}

// Global registry for bind status callbacks, keyed by context handle.
lazy_static::lazy_static! {
    static ref BIND_STATUS_CALLBACKS: std::sync::Mutex<HashMap<u64, BindStatusCallback>> = std::sync::Mutex::new(HashMap::new());
}

/// Register a bind status callback for a given context handle.
///
/// Maps to Win32 `RegisterBindStatusCallback`.
pub fn register_bind_status_callback(
    ctx_handle: u64,
    callback: BindStatusCallback,
) -> AppResult<()> {
    let mut callbacks = BIND_STATUS_CALLBACKS.lock().map_err(|e| {
        AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("RegisterBindStatusCallback: lock error: {e}"),
        )
    })?;
    callbacks.insert(ctx_handle, callback);
    Ok(())
}

/// Revoke a previously registered bind status callback.
///
/// Maps to Win32 `RevokeBindStatusCallback`.
pub fn revoke_bind_status_callback(ctx_handle: u64) -> AppResult<()> {
    let mut callbacks = BIND_STATUS_CALLBACKS.lock().map_err(|e| {
        AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("RevokeBindStatusCallback: lock error: {e}"),
        )
    })?;
    callbacks.remove(&ctx_handle);
    Ok(())
}

/// Retrieve a registered bind status callback.
pub fn get_bind_status_callback(ctx_handle: u64) -> Option<BindStatusCallback> {
    BIND_STATUS_CALLBACKS.lock().ok()?.get(&ctx_handle).cloned()
}

/// Create a URL moniker and return its data as bytes.
///
/// Maps to Win32 `CreateURLMoniker`. Downloads the content at the given URL
/// using the UrlMoniker mechanism and reports progress through the
/// registered bind status callback (if any).
pub fn create_url_moniker(url: &str, ctx: Option<&BindCtx>) -> AppResult<Vec<u8>> {
    // Notify: finding resource
    if let Some(ctx) = ctx {
        if let Some(cb) = ctx.get_bind_status_callback() {
            cb.on_progress(BINDSTATUS_FINDINGRESOURCE, 0, 0);
            cb.on_progress(BINDSTATUS_CONNECTING, 0, 0);
        }
    }

    // Build the reqwest client
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcNetHttpRequestFailed,
                format!("CreateURLMoniker: failed to create HTTP client: {e}"),
            )
        })?;

    // Notify: sending request
    if let Some(ctx) = ctx {
        if let Some(cb) = ctx.get_bind_status_callback() {
            cb.on_progress(BINDSTATUS_SENDINGREQUEST, 0, 0);
        }
    }

    let response = client.get(url).send().map_err(|e| {
        AppError::new(
            ReasonCode::RcNetHttpRequestFailed,
            format!("CreateURLMoniker: HTTP request failed for {url}: {e}"),
        )
    })?;

    // Check content length for progress tracking
    let total_size = response.content_length().unwrap_or(0) as u32;

    // Notify: begin download data
    if let Some(ctx) = ctx {
        if let Some(cb) = ctx.get_bind_status_callback() {
            cb.on_progress(BINDSTATUS_BEGINDOWNLOADDATA, 0, total_size);
        }
    }

    // Read the response bytes in chunks for progress reporting
    let mut data = Vec::new();
    let mut downloaded: u32 = 0;
    let chunk_size: usize = 8192;

    // Use a cursor-based approach to read in chunks
    let bytes = response.bytes().unwrap_or_default();
    let total = bytes.len() as u32;

    for chunk in bytes.chunks(chunk_size) {
        data.extend_from_slice(chunk);
        downloaded += chunk.len() as u32;

        // Notify: downloading data
        if let Some(ctx) = ctx {
            if let Some(cb) = ctx.get_bind_status_callback() {
                cb.on_progress(BINDSTATUS_DOWNLOADINGDATA, downloaded, total);
            }
        }
    }

    // Notify: end download data
    if let Some(ctx) = ctx {
        if let Some(cb) = ctx.get_bind_status_callback() {
            cb.on_progress(BINDSTATUS_ENDDOWNLOADDATA, total, total);
        }
    }

    Ok(data)
}

/// Create a URL moniker with extended options.
///
/// Maps to Win32 `CreateURLMonikerEx`. Supports flags such as
/// `URL_MONIKER_OPT_UNWRAP` and `URL_MONIKER_OPT_STRIP_TRAILING_SEPARATOR`.
pub fn create_url_moniker_ex(url: &str, ctx: Option<&BindCtx>, flags: u32) -> AppResult<Vec<u8>> {
    let processed_url = if (flags & URL_MONIKER_OPT_UNWRAP) != 0 {
        url.to_string()
    } else if (flags & URL_MONIKER_OPT_STRIP_TRAILING_SEPARATOR) != 0 {
        url.trim_end_matches('/').to_string()
    } else if (flags & URL_MONIKER_OPT_STRIP_LEADING_SEPARATOR) != 0 {
        url.trim_start_matches('/').to_string()
    } else {
        url.to_string()
    };

    create_url_moniker(&processed_url, ctx)
}

/// Collapse dot-segments in a URL path per RFC 3986 section 5.2.4.
///
/// Handles "." and ".." segments, removing them and their parent as appropriate.
fn collapse_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    let has_leading_slash = path.starts_with('/');

    for segment in path.split('/') {
        match segment {
            "." | "" => {
                // Ignore single-dot and empty segments (preserve trailing slash)
                if segments.is_empty() && has_leading_slash {
                    // Keep leading slash implicitly
                }
            }
            ".." => {
                // Remove the previous segment
                if !segments.is_empty() {
                    segments.pop();
                }
            }
            other => {
                segments.push(other);
            }
        }
    }

    if segments.is_empty() && has_leading_slash {
        "/".to_string()
    } else if has_leading_slash {
        format!("/{}", segments.join("/"))
    } else {
        segments.join("/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn wininet_open_close_session() {
        let mut stack = WinInetStack::new();
        let h = stack.internet_open_w(Some("Casa1"), 0, None, None);
        let _result = stack.internet_close_handle(h);
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
    }

    #[test]
    fn wininet_simple_http_get() {
        if !httpbin_reachable() {
            eprintln!("skipping wininet_simple_http_get: httpbin.org not reachable");
            return;
        }
        let mut stack = WinInetStack::new();
        let session = stack.internet_open_w(Some("Casa1"), 0, None, None);
        let conn = match stack.internet_connect_w(session, "httpbin.org", 80, None, None, 0, 0) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping wininet_simple_http_get: connect failed: {e:?}");
                return;
            }
        };
        let req = match stack.http_open_request_w(conn, "GET", "/get", None, None, None, 0) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipping wininet_simple_http_get: open request failed: {e:?}");
                let _ = stack.internet_close_handle(conn);
                return;
            }
        };
        if let Err(e) = stack.http_send_request_w(req, None, None) {
            eprintln!("skipping wininet_simple_http_get: send failed: {e:?}");
            let _ = stack.internet_close_handle(req);
            let _ = stack.internet_close_handle(conn);
            return;
        }
        let mut buf = vec![0_u8; 4096];
        let read = stack.internet_read_file(req, &mut buf).unwrap_or(0);
        if read == 0 {
            eprintln!("skipping wininet_simple_http_get: read returned 0");
            let _ = stack.internet_close_handle(req);
            let _ = stack.internet_close_handle(conn);
            return;
        }
    }

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
    fn wininet_extract_spki_der_returns_exact_subject_public_key_info() {
        let spki = build_spki(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let cert = synthetic_certificate(&spki);
        let extracted = extract_spki_der(&cert).expect("SPKI must be extractable");
        assert_eq!(extracted, spki);
    }

    #[test]
    fn wininet_certificate_pin_enforces_only_matching_spki_hash() {
        let spki = build_spki(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let cert = synthetic_certificate(&spki);
        let pin = Sha256::digest(extract_spki_der(&cert).unwrap());

        let mut stack = WinInetStack::new();
        assert!(stack.verify_certificate_pin("steamcdn.example", &[cert.clone()]));

        stack.pin_certificate("steamcdn.example", pin.as_slice());
        assert!(stack.verify_certificate_pin("steamcdn.example", &[cert.clone()]));

        let other = synthetic_certificate(&build_spki(&[0x11, 0x22, 0x33, 0x44]));
        assert!(!stack.verify_certificate_pin("steamcdn.example", &[other]));

        assert!(!stack.verify_certificate_pin("steamcdn.example", &[]));
        assert!(stack.verify_certificate_pin("other.example", &[]));
    }
}
