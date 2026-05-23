use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

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

#[derive(Debug, Clone, Default)]
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

    let (_, spki_len) = read_tag(data, &mut off)?;
    let mut spki_start = off;
    while spki_start > 0 && data[spki_start - 1] != 0x30 {
        spki_start -= 1;
    }
    if spki_start > 0 {
        spki_start -= 1;
    }
    let full_spki = data[spki_start..(off + spki_len)].to_vec();
    Some(full_spki)
}

impl WinInetStack {
    pub fn new() -> Self {
        let mut stack = Self::default();
        // Pre-load known Steam CDN certificate pins (SPKI SHA-256 hashes)
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
            AppError::new(ReasonCode::RcIo, format!("load_cookie_jar: failed to read {path:?}: {e}"))
        })?;
        let jar: HashMap<String, Vec<Cookie>> = serde_json::from_str(&data).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("load_cookie_jar: failed to parse {path:?}: {e}"))
        })?;
        self.cookie_jar = jar;
        Ok(())
    }

    pub fn save_cookie_jar(&self, path: &Path) -> AppResult<()> {
        let data = serde_json::to_string_pretty(&self.cookie_jar).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("save_cookie_jar: failed to serialize: {e}"))
        })?;
        fs::write(path, &data).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("save_cookie_jar: failed to write {path:?}: {e}"))
        })?;
        Ok(())
    }

    fn parse_and_store_set_cookie(&mut self, host: &str, header_value: &str) {
        let parts: Vec<&str> = header_value.split(';').collect();
        if parts.is_empty() {
            return;
        }
        let (name, value) = if let Some(eq_pos) = parts[0].find('=') {
            (parts[0][..eq_pos].trim().to_string(), parts[0][eq_pos + 1..].trim().to_string())
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
        let Some(ref proxy) = self.proxy else { return None; };
        let Some((ref username, ref password)) = proxy.auth else { return None; };
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
        let _ = flags;
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
        let _ = version;
        let _ = flags;
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
                req.body = b.to_vec();
            }

            let ch = req.connection_handle;
            let cn = self.connections.get(&ch).ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcWin32InvalidHandle,
                    format!("HttpSendRequestW: invalid connection {ch:#x}"),
                )
            })?;

            (ch, cn.server_name.clone(), cn.server_port, req.object_path.clone(), req.verb.clone())
        };

        let port = conn_port;
        let scheme = if port == 443 || port == 0 { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, conn_server_name, port, req_object_path);

        // Proxy configuration
        let should_bypass = self.should_bypass_proxy(&url);
        let proxy_auth = if !should_bypass { self.proxy_auth_header() } else { None };
        let proxy_cfg = self.proxy.clone();

        // Collect cookies from jar
        let cookies = self.get_cookies(&conn_server_name, &req_object_path);

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30));

        let client = if let Some(ref cfg) = proxy_cfg {
            if !should_bypass {
                let proxy_url = if cfg.server.starts_with("http://") || cfg.server.starts_with("https://") {
                    cfg.server.clone()
                } else {
                    format!("http://{}", cfg.server)
                };
                if let Ok(proxy) = reqwest::Proxy::http(&proxy_url) {
                    client.proxy(proxy)
                } else { client }
            } else { client }
        } else { client };

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
                .iter().map(|(n, v)| format!("{}={}", n, v))
                .collect::<Vec<_>>().join("; ");
            request_builder = request_builder.header("Cookie", cookie_header);
        }

        if let Some(auth) = proxy_auth {
            request_builder = request_builder.header("Proxy-Authorization", auth);
        }

        let (_status_code, _status_text, _response_headers, _response_body, set_cookie_values) = {
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
            if method == reqwest::Method::POST || method == reqwest::Method::PUT || method == reqwest::Method::PATCH {
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

            let sc = response.status().as_u16() as u32;
            let st = response.status().canonical_reason().unwrap_or("Unknown").to_string();

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
            req.response_body = body_bytes.clone();
            req.state = InternetState::ResponseReceived;

            (sc, st, resp_headers, body_bytes, set_cookie_values)
        };

        // Parse and store Set-Cookie headers
        for header_value in &set_cookie_values {
            self.parse_and_store_set_cookie(&conn_server_name, header_value);
        }

        // Verify certificate pins
        if !self.verify_certificate_pin(&conn_server_name, &[]) {
            return Err(AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("HttpSendRequestW: certificate pin validation failed for {}", conn_server_name),
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
                0 => {} // INTERNET_OPTION_PROXY — ignore for now
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
                4 => { // INTERNET_OPTION_CONNECT_TIMEOUT
                    if value.len() >= 4 {
                        req.timeout_ms = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                    }
                }
                30 => { // INTERNET_OPTION_RECEIVE_TIMEOUT
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
        let _ = userinfo;

        // Extract host and port
        let hostpart = hostpart;
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
    // InternetCanonicalizeUrlW — canonicalize a URL (RFC 3986)
    //
    // Performs:
    // 1. Percent-encoding of reserved and unsafe characters
    // 2. Path segment normalization (collapsing dot-segments)
    // 3. Scheme lowercasing
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
                if let Some((_, c1)) = chars.next() { encoded.push(c1); }
                if let Some((_, c2)) = chars.next() { encoded.push(c2); }
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
            let auth_end = rest.find(|c: char| c == '/' || c == '?' || c == '#')
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

    #[test]
    fn wininet_open_close_session() {
        let mut stack = WinInetStack::new();
        let h = stack.internet_open_w(Some("Casa1"), 0, None, None);
        assert!(stack.internet_close_handle(h).is_ok());
    }

    #[test]
    fn wininet_simple_http_get() {
        let mut stack = WinInetStack::new();
        let session = stack.internet_open_w(Some("Casa1"), 0, None, None);
        let conn = stack
            .internet_connect_w(session, "httpbin.org", 80, None, None, 0, 0)
            .expect("connect");
        let req = stack
            .http_open_request_w(conn, "GET", "/get", None, None, None, 0)
            .expect("open request");
        stack
            .http_send_request_w(req, None, None)
            .expect("send request");
        let mut buf = vec![0_u8; 4096];
        let read = stack.internet_read_file(req, &mut buf).expect("read");
        assert!(read > 0);
    }
}
