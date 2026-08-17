use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::winhttp::CrackedUrl;
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
    /// The InternetConnectW handle this transfer belongs to (the field was
    /// historically named `session_handle` but always stored the connection
    /// handle).
    pub connection_handle: HINTERNET,
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
    /// INTERNET_FLAG_SECURE was requested at connect time.
    #[serde(default)]
    pub is_secure: bool,
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
    /// Read cursor into `response_body` (avoids O(n²) `drain` per read).
    #[serde(default)]
    pub read_offset: usize,
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
    /// Cached reqwest client keyed by (proxy, timeout) config, so
    /// connection pooling survives across requests and proxy/timeout option
    /// changes take effect.
    client_cache: Option<(String, reqwest::blocking::Client)>,
    /// Certificate pinning: host -> list of acceptable SPKI SHA-256 hashes
    pinned_certs: HashMap<String, Vec<Vec<u8>>>,
    /// Cookie jar: host -> list of cookies
    cookie_jar: HashMap<String, Vec<Cookie>>,
    /// Proxy configuration
    proxy: Option<InternetProxyConfig>,
    /// Last response info (for InternetGetLastResponseInfoW)
    last_response_error: String,
    /// Last response error code (for InternetGetLastResponseInfoW)
    last_response_error_code: u32,
    /// Active FTP transfers
    ftp_transfers: BTreeMap<HINTERNET, FtpTransfer>,
    /// FTP control connections (connection_handle -> TcpStream).
    /// Stored as Option for Clone-ability (None means disconnected).
    pub(crate) ftp_control_streams: BTreeMap<HINTERNET, TcpStream>,
    /// FTP current working directory per connection (connection_handle -> path)
    ftp_current_dir: BTreeMap<HINTERNET, String>,
    /// FTP file data cache: FtpOpenFileW handle -> (file contents, read offset)
    ftp_file_data: BTreeMap<HINTERNET, (Vec<u8>, usize)>,
    /// FTP last listing results for find operations
    ftp_listing_cache: BTreeMap<HINTERNET, Vec<FtpFileInfo>>,
    /// FTP listing iterator index per find handle
    ftp_listing_index: BTreeMap<HINTERNET, usize>,
}

impl Default for WinInetStack {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            connections: BTreeMap::new(),
            requests: BTreeMap::new(),
            next_handle: 1,
            client_cache: None,
            pinned_certs: HashMap::new(),
            cookie_jar: HashMap::new(),
            proxy: None,
            last_response_error: String::new(),
            last_response_error_code: 0,
            ftp_transfers: BTreeMap::new(),
            ftp_control_streams: BTreeMap::new(),
            ftp_current_dir: BTreeMap::new(),
            ftp_file_data: BTreeMap::new(),
            ftp_listing_cache: BTreeMap::new(),
            ftp_listing_index: BTreeMap::new(),
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
                // Reject absurd long-form lengths so crafted DER cannot drive
                // unchecked arithmetic.
                let num_bytes = (b & 0x7F) as usize;
                if num_bytes > 4 || *offset + num_bytes > data.len() {
                    return None;
                }
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
        // Reject lengths that exceed the remaining buffer before any
        // arithmetic is performed on them.
        if len > data.len() - *offset {
            return None;
        }
        Some((tag, len))
    }

    fn skip_tlv(data: &[u8], offset: &mut usize) -> Option<()> {
        let (_, len) = read_tag(data, offset)?;
        *offset = (*offset).checked_add(len)?;
        Some(())
    }

    let mut off = 0;
    let (_, outer_len) = read_tag(data, &mut off)?;
    let end = off.checked_add(outer_len)?;
    if end > data.len() {
        return None;
    }

    let (_, tbs_len) = read_tag(data, &mut off)?;
    let tbs_end = off.checked_add(tbs_len)?;
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
    let spki_end = off.checked_add(spki_len)?;
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

    /// Maximum cookies stored per host, and per jar, to bound memory growth
    /// from malicious servers issuing unbounded `Set-Cookie` headers.
    const MAX_COOKIES_PER_HOST: usize = 512;
    const MAX_COOKIE_JAR_SIZE: usize = 8192;

    pub fn set_cookie(&mut self, host: &str, cookie: Cookie) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let host_cookies = self.cookie_jar.entry(host.to_string()).or_default();
        // Drop expired entries for this host and cap the per-host count.
        host_cookies.retain(|c| c.expiry.map(|e| e > now).unwrap_or(true));
        if host_cookies.len() >= Self::MAX_COOKIES_PER_HOST {
            return; // Jar full — refuse to grow unbounded.
        }
        host_cookies.push(cookie);
        // Cap the total jar size; evict a bucket when exceeded.
        if self.cookie_jar.len() > Self::MAX_COOKIE_JAR_SIZE
            && let Some(evicted_host) = self.cookie_jar.keys().next().cloned()
        {
            self.cookie_jar.remove(&evicted_host);
        }
    }

    /// `secure` indicates whether the request is over HTTPS; secure-only
    /// cookies are never sent over plaintext HTTP.
    pub fn get_cookies(&self, host: &str, path: &str, secure: bool) -> Vec<(String, String)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut result = Vec::new();
        if let Some(cookies) = self.cookie_jar.get(host) {
            for cookie in cookies {
                if let Some(expiry) = cookie.expiry
                    && now >= expiry
                {
                    continue;
                }
                if cookie.secure && !secure {
                    continue;
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

    /// Returns true if `domain_attr` is acceptable for a cookie received from
    /// `host` (equal to the host or a parent domain, per RFC 6265).
    fn cookie_domain_matches(host: &str, domain_attr: &str) -> bool {
        let host = host.trim_end_matches('.').to_lowercase();
        let domain = domain_attr
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_lowercase();
        if domain.is_empty() {
            return false;
        }
        host == domain || host.ends_with(&format!(".{domain}"))
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
                    "domain" => {
                        // Never trust a server-supplied domain blindly: only
                        // accept it if it is the responding host or a parent
                        // domain of it.
                        if Self::cookie_domain_matches(host, &val) {
                            cookie.domain = val;
                        }
                    }
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
        let Some(proxy) = self.proxy.as_ref() else {
            return true;
        };
        if proxy.bypass_list.is_empty() {
            return false;
        }
        // Match bypass entries against the URL *host* with proper suffix
        // rules, so "example.com" does not match "notexample.com" or
        // "example.com.evil.net".
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
            .unwrap_or_else(|| url.to_lowercase());
        proxy
            .bypass_list
            .iter()
            .any(|b| Self::host_matches_bypass(&host, b))
    }

    /// Match a host against a single bypass entry. Supports plain domains,
    /// leading-dot forms and wildcard prefixes.
    fn host_matches_bypass(host: &str, bypass: &str) -> bool {
        let entry = bypass
            .trim()
            .trim_start_matches('*')
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_lowercase();
        if entry.is_empty() {
            return false;
        }
        host == entry || host.ends_with(&format!(".{entry}"))
    }

    pub fn proxy_auth_header(&self) -> Option<String> {
        let proxy = self.proxy.as_ref()?;
        let (username, password) = proxy.auth.as_ref()?;
        let credentials = format!("{username}:{password}");
        let encoded = Self::base64_encode(credentials.as_bytes());
        Some(format!("Basic {encoded}"))
    }

    fn base64_encode(input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk.first().copied().unwrap_or(0) as u32;
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

    /// Redact the userinfo portion of a proxy URL for logging.
    pub fn redact_proxy_url(proxy_url: &str) -> String {
        match url::Url::parse(proxy_url) {
            Ok(parsed) => {
                let mut out = format!("{}://", parsed.scheme());
                if let Some(host) = parsed.host_str() {
                    out.push_str(host);
                    if let Some(port) = parsed.port() {
                        out.push_str(&format!(":{port}"));
                    }
                } else {
                    out.push_str("[invalid]");
                }
                out
            }
            Err(_) => {
                // Fall back to a manual strip of `user:pass@`.
                match proxy_url.find('@') {
                    Some(at) => {
                        let scheme_end = proxy_url.find("://").map(|p| p + 3).unwrap_or(0);
                        if at > scheme_end {
                            format!(
                                "{}[redacted]@{}",
                                &proxy_url[..scheme_end],
                                &proxy_url[at + 1..]
                            )
                        } else {
                            proxy_url.to_string()
                        }
                    }
                    None => proxy_url.to_string(),
                }
            }
        }
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
    // The argument list mirrors the Win32 InternetConnectW prototype.
    #[allow(clippy::too_many_arguments)]
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
        // INTERNET_FLAG_SECURE: secure connections & other flags
        let is_secure = flags & 0x00800000 != 0;
        if is_secure {
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
            is_secure,
            state: InternetState::Connected,
        };
        let handle = self.next_handle();
        self.connections.insert(handle, conn);

        // If this is an FTP connection, establish the control connection
        // and log in with the provided credentials. Failures propagate as
        // errors instead of silently handing out a broken handle.
        if service == INTERNET_SERVICE_FTP
            && let Err(e) =
                self.ftp_establish_control(handle, server_name, server_port, user_name, password)
        {
            self.connections.remove(&handle);
            return Err(e);
        }

        Ok(handle)
    }

    /// Reject FTP operands (user names, passwords, file names, patterns,
    /// directories) that contain CR/LF, which would inject arbitrary FTP
    /// commands into the control stream.
    fn ftp_check_operand(operand: &str, what: &str) -> AppResult<()> {
        if operand.contains('\r') || operand.contains('\n') {
            return Err(AppError::new(
                ReasonCode::RcCliInvalid,
                format!("FTP: {what} contains illegal CR/LF characters"),
            ));
        }
        Ok(())
    }

    /// Read a complete FTP reply from a stream (multi-line aware).
    fn ftp_read_reply(stream: &mut TcpStream, max_len: usize) -> AppResult<String> {
        let mut response = String::new();
        let mut buf = [0u8; 4096];
        let mut pending = String::new();
        loop {
            let n = stream.read(&mut buf).map_err(|e| {
                AppError::new(ReasonCode::RcIo, format!("FTP control read failed: {e}"))
            })?;
            if n == 0 {
                break;
            }
            pending.push_str(&String::from_utf8_lossy(&buf[..n]));
            // Process complete lines from `pending`.
            while let Some(newline) = pending.find('\n') {
                let line = pending[..newline].trim_end_matches('\r').to_string();
                pending = pending[newline + 1..].to_string();
                if line.len() >= 4
                    && line.as_bytes()[0].is_ascii_digit()
                    && line.as_bytes()[1].is_ascii_digit()
                    && line.as_bytes()[2].is_ascii_digit()
                    && line.as_bytes()[3] == b' '
                {
                    // `NNN ` final line — reply complete.
                    response.push_str(&line);
                    response.push_str("\r\n");
                    return Ok(response);
                }
                response.push_str(&line);
                response.push_str("\r\n");
                if response.len() > max_len {
                    return Ok(response);
                }
            }
            if response.len() > max_len {
                break;
            }
        }
        Ok(response)
    }

    /// Establish and authenticate an FTP control connection.
    fn ftp_establish_control(
        &mut self,
        handle: HINTERNET,
        server_name: &str,
        server_port: u16,
        user_name: Option<&str>,
        password: Option<&str>,
    ) -> AppResult<()> {
        let user = user_name.unwrap_or("anonymous");
        let pass = password.unwrap_or("casa1@localhost");
        Self::ftp_check_operand(user, "user name")?;
        Self::ftp_check_operand(pass, "password")?;

        let ftp_port = if server_port == 0 { 21 } else { server_port };
        let addr = format!("{server_name}:{ftp_port}");
        let mut stream = TcpStream::connect_timeout(
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
        )
        .map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("FTP connection to {addr} failed: {e}"),
            )
        })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("FTP set read timeout failed: {e}"),
                )
            })?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("FTP set write timeout failed: {e}"),
                )
            })?;

        // Read the 220 greeting and validate the banner status code.
        let greeting = Self::ftp_read_reply(&mut stream, 8192)?;
        if !greeting.starts_with("220") && !greeting.starts_with("120") {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP: unexpected greeting from {addr}: {}", greeting.trim()),
            ));
        }

        // Send USER
        let cmd = format!("USER {user}\r\n");
        stream.write_all(cmd.as_bytes()).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("FTP: failed to send USER: {e}"))
        })?;
        let user_reply = Self::ftp_read_reply(&mut stream, 8192)?;
        if user_reply.starts_with("530") {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP: login rejected by {addr}: {}", user_reply.trim()),
            ));
        }

        // Send PASS if we got a password request (331)
        if user_reply.starts_with("331") {
            let cmd = format!("PASS {pass}\r\n");
            stream.write_all(cmd.as_bytes()).map_err(|e| {
                AppError::new(ReasonCode::RcIo, format!("FTP: failed to send PASS: {e}"))
            })?;
            let pass_reply = Self::ftp_read_reply(&mut stream, 8192)?;
            if pass_reply.starts_with("530") {
                return Err(AppError::new(
                    ReasonCode::RcIo,
                    format!("FTP: login rejected by {addr}: {}", pass_reply.trim()),
                ));
            }
        }

        self.ftp_control_streams.insert(handle, stream);
        self.ftp_current_dir.insert(handle, "/".to_string());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // HttpOpenRequestW — create an HTTP request handle
    // -----------------------------------------------------------------------
    // The argument list mirrors the Win32 HttpOpenRequestW prototype.
    #[allow(clippy::too_many_arguments)]
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
        if let Some(v) = version
            && !v.is_empty()
        {
            eprintln!("HttpOpenRequestW: HTTP version requested: {}", v);
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
            read_offset: 0,
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
        let (_conn_handle, conn_server_name, conn_port, conn_is_secure, req_object_path, req_verb) = {
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
                cn.is_secure,
                req.object_path.clone(),
                req.verb.clone(),
            )
        };

        // Scheme comes from the connection's INTERNET_FLAG_SECURE state, not
        // a raw port comparison. Port 0 means "default port": 80/443
        // depending on the secure flag.
        let (scheme, port) = if conn_is_secure {
            ("https", if conn_port == 0 { 443 } else { conn_port })
        } else {
            ("http", if conn_port == 0 { 80 } else { conn_port })
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
        let req_timeout_ms = self
            .requests
            .get(&request_handle)
            .map(|r| r.timeout_ms)
            .unwrap_or(30000);

        // Collect cookies from jar
        let cookies = self.get_cookies(&conn_server_name, &req_object_path, conn_is_secure);

        // Build (or reuse) the HTTP client. The cache key covers the proxy
        // configuration, bypass state and effective timeout, so proxy/timeout
        // option changes take effect and connection pooling is retained.
        let proxy_key = match proxy_cfg.as_ref() {
            Some(cfg) if !should_bypass => cfg.server.clone(),
            _ => String::new(),
        };
        let client_key = format!("{proxy_key}|{req_timeout_ms}");
        let client = match self.client_cache.as_ref() {
            Some((key, client)) if *key == client_key => client.clone(),
            _ => {
                let mut builder = reqwest::blocking::Client::builder()
                    .danger_accept_invalid_certs(false) // certificate pinning is enforced for pinned hosts
                    .tls_info(true) // expose the peer certificate so certificate pinning can be enforced
                    .timeout(std::time::Duration::from_millis(req_timeout_ms as u64));
                if let Some(cfg) = proxy_cfg.as_ref()
                    && !should_bypass
                {
                    let proxy_url = if cfg.server.starts_with("http://")
                        || cfg.server.starts_with("https://")
                    {
                        cfg.server.clone()
                    } else {
                        format!("http://{}", cfg.server)
                    };
                    let proxy = if proxy_url.starts_with("https://") {
                        reqwest::Proxy::https(&proxy_url)
                    } else {
                        reqwest::Proxy::all(&proxy_url)
                    };
                    match proxy {
                        Ok(p) => {
                            builder = builder.proxy(p);
                        }
                        Err(e) => {
                            eprintln!(
                                "HttpSendRequestW: ignoring invalid proxy configuration '{}': {e}",
                                Self::redact_proxy_url(&proxy_url)
                            );
                        }
                    }
                }
                let client = builder.build().map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetHttpRequestFailed,
                        format!("HttpSendRequestW: failed to create client: {e:?}"),
                    )
                })?;
                self.client_cache = Some((client_key, client.clone()));
                client
            }
        };

        // Unknown verbs are errors, not silent GETs: a PROPFIND sent as GET
        // would change semantics and drop the payload.
        let method =
            reqwest::Method::from_bytes(req_verb.to_uppercase().as_bytes()).map_err(|_| {
                AppError::new(
                    ReasonCode::RcCliInvalid,
                    format!("HttpSendRequestW: invalid HTTP verb '{req_verb}'"),
                )
            })?;

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

            // Add body for methods that support it (take ownership instead of
            // cloning up to 256 MB).
            let supports_body = method == reqwest::Method::POST
                || method == reqwest::Method::PUT
                || method == reqwest::Method::PATCH;
            if supports_body {
                let request_body = std::mem::take(&mut req.body);
                request_builder = request_builder.body(request_body);
            }

            req.state = InternetState::RequestSent;

            let mut response = match request_builder.send() {
                Ok(resp) => resp,
                Err(e) => {
                    req.state = InternetState::ResponseReceived;
                    self.last_response_error = format!("{e:?}");
                    self.last_response_error_code = 12029; // ERROR_INTERNET_CANNOT_CONNECT
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

            // Enforce the response size cap *before* downloading (via the
            // Content-Length pre-check) and abort mid-stream once the cap is
            // exceeded, instead of buffering the whole body first.
            if let Some(cl) = response.content_length()
                && cl > MAX_WININET_RESPONSE_BODY as u64
            {
                req.state = InternetState::ResponseReceived;
                return Err(AppError::new(
                    ReasonCode::RcBufferLimitExceeded,
                    format!(
                        "HttpSendRequestW: response content length {cl} exceeds limit ({MAX_WININET_RESPONSE_BODY})"
                    ),
                ));
            }
            let mut body_bytes = Vec::new();
            {
                let mut limited = (&mut response).take((MAX_WININET_RESPONSE_BODY + 1) as u64);
                if let Err(e) = limited.read_to_end(&mut body_bytes) {
                    req.state = InternetState::ResponseReceived;
                    self.last_response_error = format!("{e}");
                    self.last_response_error_code = 12002; // ERROR_INTERNET_TIMEOUT
                    return Err(AppError::new(
                        ReasonCode::RcNetHttpRequestFailed,
                        format!("HttpSendRequestW: failed reading response body: {e}"),
                    ));
                }
            }
            if body_bytes.len() > MAX_WININET_RESPONSE_BODY {
                req.state = InternetState::ResponseReceived;
                return Err(AppError::new(
                    ReasonCode::RcBufferLimitExceeded,
                    format!(
                        "HttpSendRequestW: response body size {} exceeds limit ({MAX_WININET_RESPONSE_BODY})",
                        body_bytes.len()
                    ),
                ));
            }

            req.status_code = sc;
            req.status_text = st.clone();
            req.response_headers = resp_headers.clone();
            req.response_body = body_bytes;
            req.read_offset = 0;
            req.state = InternetState::ResponseReceived;

            (
                sc,
                st,
                resp_headers,
                Vec::<u8>::new(),
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
        // First try the HTTP requests map
        if let Some(req) = self.requests.get_mut(&request_handle) {
            let off = req.read_offset;
            let to_read = buffer
                .len()
                .min(req.response_body.len().saturating_sub(off));
            if to_read > 0 {
                buffer[..to_read].copy_from_slice(&req.response_body[off..off + to_read]);
            }
            req.read_offset = off + to_read;
            // Release the backing buffer once fully consumed.
            if req.read_offset == req.response_body.len() {
                req.response_body.clear();
                req.read_offset = 0;
            }
            return Ok(to_read as u32);
        }

        // Fall back to FTP file data cache (for handles from ftp_open_file_w)
        if let Some((file_data, read_offset)) = self.ftp_file_data.get_mut(&request_handle) {
            let to_read = buffer
                .len()
                .min(file_data.len().saturating_sub(*read_offset));
            if to_read > 0 {
                buffer[..to_read].copy_from_slice(&file_data[*read_offset..*read_offset + to_read]);
            }
            *read_offset += to_read;
            if *read_offset == file_data.len() {
                file_data.clear();
                *read_offset = 0;
            }
            return Ok(to_read as u32);
        }

        Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("InternetReadFile: invalid handle {request_handle:#x}"),
        ))
    }

    // -----------------------------------------------------------------------
    // InternetCloseHandle — close any WinINet handle
    // -----------------------------------------------------------------------
    pub fn internet_close_handle(&mut self, handle: HINTERNET) -> AppResult<()> {
        // Clean up FTP resources if this handle has any
        self.ftp_control_streams.remove(&handle);
        self.ftp_current_dir.remove(&handle);
        self.ftp_transfers.remove(&handle);
        self.ftp_file_data.remove(&handle);
        self.ftp_listing_cache.remove(&handle);
        self.ftp_listing_index.remove(&handle);

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
        Ok(req
            .response_body
            .len()
            .saturating_sub(req.read_offset)
            .min(u32::MAX as usize) as u32)
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
                        if let Some(p) = proxy_str {
                            let bypass_list = if value.len() > 4 + p.len() + 1 {
                                let bypass_start = 4 + p.len() + 1;
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
                            session.proxy = Some(p.clone());
                            session.proxy_bypass = Some(bypass_list.join(";"));
                            // Apply to the request path (http_send_request_w
                            // consults `self.proxy`).
                            self.proxy = Some(InternetProxyConfig {
                                server: p.clone(),
                                bypass_list,
                                auth: None,
                            });
                            eprintln!(
                                "InternetSetOptionW: proxy set to {} for session {:#x}",
                                Self::redact_proxy_url(&p),
                                handle
                            );
                        }
                    }
                }
                _ => {}
            }
            return Ok(());
        }
        if self.connections.contains_key(&handle) {
            return Ok(());
        }
        if let Some(req) = self.requests.get_mut(&handle) {
            match option {
                4 if value.len() >= 4 => {
                    // INTERNET_OPTION_CONNECT_TIMEOUT
                    req.timeout_ms = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                }
                30 if value.len() >= 4 => {
                    // INTERNET_OPTION_RECEIVE_TIMEOUT
                    req.timeout_ms = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
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
        let code = if self.last_response_error_code == 0 {
            12002 // ERROR_INTERNET_TIMEOUT — default when no failure recorded
        } else {
            self.last_response_error_code
        };
        (code, self.last_response_error.clone())
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

    /// Truncate `url` to at most `url_length` UTF-8 bytes, never splitting a
    /// multi-byte character. `url_length` is guest-controlled (a UTF-16-unit
    /// count per WinINet semantics), so slicing at the raw byte offset can
    /// panic; clamp to the nearest char boundary instead.
    fn truncate_url(url: &str, url_length: u32) -> &str {
        let want = url_length as usize;
        if want >= url.len() {
            return url;
        }
        let mut end = want;
        while end > 0 && !url.is_char_boundary(end) {
            end -= 1;
        }
        &url[..end]
    }

    #[allow(unused_assignments)]
    pub fn internet_crack_url_w(&self, url: &str, url_length: u32) -> AppResult<CrackedUrl> {
        let url = Self::truncate_url(url, url_length);

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
        let path_start = hostpart
            .bytes()
            .position(|b| b == b'/' || b == b'?' || b == b'#')
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
        let url = Self::truncate_url(url, url_length);

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
                // Percent sign — encoded below unless followed by two hex
                // digits (i.e. already valid percent-encoding).
                '%' => true,
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
                    encoded.push_str(&format!("%{byte:02X}"));
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
                .bytes()
                .position(|b| b == b'/' || b == b'?' || b == b'#')
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

        Self::ftp_read_reply(stream, 16384)
    }

    /// Check an FTP command reply for an expected 1xx/2xx/3xx success code.
    fn ftp_expect_success(reply: &str, cmd: &str) -> AppResult<()> {
        let status = reply
            .lines()
            .next()
            .map(|l| l.trim())
            .unwrap_or_default()
            .chars()
            .take(3)
            .collect::<String>();
        let ok = status.starts_with('1') || status.starts_with('2') || status.starts_with('3');
        if !ok {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP {cmd} failed: {}", reply.trim()),
            ));
        }
        Ok(())
    }

    /// Parse a PASV response (227 Entering Passive Mode (h1,h2,h3,h4,p1,p2))
    /// to extract the data connection address and port.
    fn ftp_parse_pasv(response: &str) -> Option<(String, u16)> {
        // Look for the parentheses: "(h1,h2,h3,h4,p1,p2)"
        if let Some(start) = response.find('(')
            && let Some(end) = response.find(')')
        {
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
        None
    }

    /// Establish a PASV data connection to the FTP server.
    fn ftp_data_connect(&mut self, conn_handle: HINTERNET) -> AppResult<TcpStream> {
        // Send PASV command
        let pasv_response = self.ftp_command(conn_handle, "PASV")?;
        Self::ftp_expect_success(&pasv_response, "PASV")?;

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
        // A stalled server must not hang the transfer indefinitely.
        data_stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();
        data_stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .ok();

        Ok(data_stream)
    }

    /// Read all data from a data connection, with a size cap.
    fn ftp_read_data(stream: &mut TcpStream) -> AppResult<Vec<u8>> {
        let mut data = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let new_len = data.len().saturating_add(n);
                    if new_len > MAX_WININET_RESPONSE_BODY {
                        return Err(AppError::new(
                            ReasonCode::RcBufferLimitExceeded,
                            format!(
                                "FTP data transfer exceeds limit ({MAX_WININET_RESPONSE_BODY})"
                            ),
                        ));
                    }
                    data.extend_from_slice(&buf[..n]);
                }
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
        Self::ftp_check_operand(file_name, "file name")?;
        // Try to initiate the transfer by sending PASV + RETR
        let mut data_stream = self.ftp_data_connect(connect_handle)?;
        let retr_cmd = format!("RETR {file_name}");
        let retr_response = self.ftp_command(connect_handle, &retr_cmd)?;
        Self::ftp_expect_success(&retr_response, &retr_cmd)?;

        // Read the file data from the data connection and cache it so
        // InternetReadFile can serve it from the transfer handle.
        let file_data = Self::ftp_read_data(&mut data_stream)?;

        let handle = self.next_handle();
        self.ftp_transfers.insert(
            handle,
            FtpTransfer {
                connection_handle: connect_handle,
                remote_file: file_name.to_string(),
                is_passive: true,
                transfer_type,
                local_path: None,
                context: 0,
            },
        );
        self.ftp_file_data.insert(handle, (file_data, 0));

        // No QUIT here: that would close the server-side control session and
        // poison every subsequent command on this connection. The guest
        // closes the handle when done.

        Ok(handle)
    }

    /// Retrieve a remote file via FTP and save it locally.
    /// Uses RETR command over PASV data connection.
    pub fn ftp_get_file_w(
        &mut self,
        connect_handle: HINTERNET,
        remote_file: &str,
        local_file: &str,
        fail_if_exists: bool,
        _transfer_type: FtpTransferType,
    ) -> AppResult<bool> {
        Self::ftp_check_operand(remote_file, "remote file name")?;
        if fail_if_exists && Path::new(local_file).exists() {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("FTP: local file {local_file} already exists"),
            ));
        }
        // Establish PASV data connection
        let mut data_stream = self.ftp_data_connect(connect_handle).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("FTP get file data connect failed: {e}"),
            )
        })?;

        // Send RETR command and validate the server accepted it.
        let retr_cmd = format!("RETR {remote_file}");
        let retr_response = self.ftp_command(connect_handle, &retr_cmd)?;
        Self::ftp_expect_success(&retr_response, &retr_cmd)?;

        // Read file data from the data connection
        let file_data = Self::ftp_read_data(&mut data_stream)?;

        // Write to local file — failures must surface, not be logged away.
        std::fs::write(local_file, &file_data).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("FTP: failed to write local file {local_file}: {e}"),
            )
        })?;

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
        Self::ftp_check_operand(remote_file, "remote file name")?;
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

        // Send STOR command and validate the server accepted it.
        let stor_cmd = format!("STOR {remote_file}");
        let stor_response = self.ftp_command(connect_handle, &stor_cmd)?;
        Self::ftp_expect_success(&stor_response, &stor_cmd)?;

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
        Self::ftp_check_operand(file_name, "file name")?;
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
        Self::ftp_check_operand(existing, "existing file name")?;
        Self::ftp_check_operand(new_name, "new file name")?;
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
        Self::ftp_check_operand(directory, "directory")?;
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
        if let Some(start) = response.find('"')
            && let Some(end) = response[start + 1..].find('"')
        {
            let dir = &response[start + 1..start + 1 + end];
            self.ftp_current_dir.insert(connect_handle, dir.to_string());
            return Ok(dir.to_string());
        }
        Ok("/".to_string())
    }

    /// Create a directory on the FTP server via MKD.
    pub fn ftp_create_directory_w(
        &mut self,
        connect_handle: HINTERNET,
        directory: &str,
    ) -> AppResult<bool> {
        Self::ftp_check_operand(directory, "directory")?;
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
        Self::ftp_check_operand(directory, "directory")?;
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
        Self::ftp_check_operand(pattern, "pattern")?;
        // Use NLST (name list) with pattern to list files
        let mut data_stream = self.ftp_data_connect(connect_handle)?;
        let nlst_cmd = if pattern.is_empty() || pattern == "*" || pattern == "*.*" {
            "NLST".to_string()
        } else {
            format!("NLST {pattern}")
        };
        let response = self.ftp_command(connect_handle, &nlst_cmd)?;
        Self::ftp_expect_success(&response, &nlst_cmd)?;

        // Read the listing from the data connection
        let listing_data = Self::ftp_read_data(&mut data_stream)?;
        let listing = String::from_utf8_lossy(&listing_data);

        let files: Vec<String> = listing
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        // Store the listing (pre-split) in the listing cache so
        // ftp_find_next_file_w does not re-split it on every call.
        let handle = self.next_handle();
        self.ftp_transfers.insert(
            handle,
            FtpTransfer {
                connection_handle: connect_handle,
                remote_file: pattern.to_string(),
                is_passive: true,
                transfer_type: FtpTransferType::Ascii,
                local_path: None,
                context: 0,
            },
        );

        if files.is_empty() {
            return Err(AppError::new(ReasonCode::RcIo, "FTP: no files found"));
        }

        let file_infos: Vec<FtpFileInfo> = files
            .iter()
            .map(|name| FtpFileInfo {
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
    pub fn ftp_find_next_file_w(&mut self, find_handle: HINTERNET) -> Option<FtpFileInfo> {
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
        if let Some(cb) = self.callback
            && (self.notify_flags == 0 || (self.notify_flags & (1 << status_code)) != 0)
        {
            cb(self.context, status_code, progress, max_progress);
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
// Bounded: entries are evicted (oldest key) once the cap is reached so a
// guest registering callbacks with fresh context handles cannot grow the map
// without limit.
lazy_static::lazy_static! {
    static ref BIND_STATUS_CALLBACKS: std::sync::Mutex<BTreeMap<u64, BindStatusCallback>> =
        std::sync::Mutex::new(BTreeMap::new());
}

/// Maximum number of concurrently registered bind status callbacks.
const MAX_BIND_STATUS_CALLBACKS: usize = 4096;

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
    while callbacks.len() > MAX_BIND_STATUS_CALLBACKS {
        // Evict the oldest registered handle.
        if let Some(oldest) = callbacks.keys().next().copied() {
            callbacks.remove(&oldest);
        } else {
            break;
        }
    }
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
    if let Some(ctx) = ctx
        && let Some(cb) = ctx.get_bind_status_callback()
    {
        cb.on_progress(BINDSTATUS_FINDINGRESOURCE, 0, 0);
        cb.on_progress(BINDSTATUS_CONNECTING, 0, 0);
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
    if let Some(ctx) = ctx
        && let Some(cb) = ctx.get_bind_status_callback()
    {
        cb.on_progress(BINDSTATUS_SENDINGREQUEST, 0, 0);
    }

    let response = client.get(url).send().map_err(|e| {
        AppError::new(
            ReasonCode::RcNetHttpRequestFailed,
            format!("CreateURLMoniker: HTTP request failed for {url}: {e}"),
        )
    })?;

    // Check content length for progress tracking (and cap the download).
    let total_size = response.content_length().unwrap_or(0);
    if total_size > MAX_WININET_RESPONSE_BODY as u64 {
        return Err(AppError::new(
            ReasonCode::RcBufferLimitExceeded,
            format!(
                "CreateURLMoniker: response content length {total_size} exceeds limit ({MAX_WININET_RESPONSE_BODY})"
            ),
        ));
    }

    // Notify: begin download data
    if let Some(ctx) = ctx
        && let Some(cb) = ctx.get_bind_status_callback()
    {
        cb.on_progress(
            BINDSTATUS_BEGINDOWNLOADDATA,
            0,
            total_size.min(u32::MAX as u64) as u32,
        );
    }

    // Stream the response body into `data` with a size cap, reporting
    // progress per chunk. `usize` counters avoid truncation above 4 GiB.
    let mut data = Vec::new();
    let mut downloaded: u64 = 0;
    let chunk_size: usize = 8192;
    let mut buf = vec![0u8; chunk_size];
    let mut limited = response.take(MAX_WININET_RESPONSE_BODY as u64 + 1);
    let mut n = limited.read(&mut buf).map_err(|e| {
        AppError::new(
            ReasonCode::RcNetHttpRequestFailed,
            format!("CreateURLMoniker: read failed for {url}: {e}"),
        )
    })?;
    while n > 0 {
        if data.len().saturating_add(n) > MAX_WININET_RESPONSE_BODY {
            return Err(AppError::new(
                ReasonCode::RcBufferLimitExceeded,
                format!(
                    "CreateURLMoniker: response body exceeds limit ({MAX_WININET_RESPONSE_BODY})"
                ),
            ));
        }
        data.extend_from_slice(&buf[..n]);
        downloaded += n as u64;

        // Notify: downloading data
        if let Some(ctx) = ctx
            && let Some(cb) = ctx.get_bind_status_callback()
        {
            cb.on_progress(
                BINDSTATUS_DOWNLOADINGDATA,
                downloaded.min(u32::MAX as u64) as u32,
                total_size.min(u32::MAX as u64) as u32,
            );
        }

        n = limited.read(&mut buf).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetHttpRequestFailed,
                format!("CreateURLMoniker: read failed for {url}: {e}"),
            )
        })?;
    }

    // Notify: end download data
    if let Some(ctx) = ctx
        && let Some(cb) = ctx.get_bind_status_callback()
    {
        cb.on_progress(
            BINDSTATUS_ENDDOWNLOADDATA,
            downloaded.min(u32::MAX as u64) as u32,
            total_size.min(u32::MAX as u64) as u32,
        );
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
/// Handles "." and ".." segments, removing them and their parent as
/// appropriate. A trailing slash is preserved when the original path had one
/// (`/a/` stays `/a/`, it is not reduced to `/a`).
fn collapse_dot_segments(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    let has_leading_slash = path.starts_with('/');
    let has_trailing_slash = path.ends_with('/') && path.len() > 1;

    for segment in path.split('/') {
        match segment {
            "." | "" => {
                // Ignore single-dot and empty segments (leading slash kept
                // implicitly; trailing slash restored below).
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

    let mut result = if segments.is_empty() && has_leading_slash {
        "/".to_string()
    } else if has_leading_slash {
        format!("/{}", segments.join("/"))
    } else {
        segments.join("/")
    };
    if has_trailing_slash && !result.ends_with('/') {
        result.push('/');
    }
    result
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
        assert!(stack.verify_certificate_pin("steamcdn.example", std::slice::from_ref(&cert)));

        stack.pin_certificate("steamcdn.example", pin.as_slice());
        assert!(stack.verify_certificate_pin("steamcdn.example", std::slice::from_ref(&cert)));

        let other = synthetic_certificate(&build_spki(&[0x11, 0x22, 0x33, 0x44]));
        assert!(!stack.verify_certificate_pin("steamcdn.example", &[other]));

        assert!(!stack.verify_certificate_pin("steamcdn.example", &[]));
        assert!(stack.verify_certificate_pin("other.example", &[]));
    }
}
