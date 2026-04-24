use crate::error::{AppError, AppResult};
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

type HmacSha256 = Hmac<Sha256>;

pub type SocketId = u64;
pub type HttpSessionId = u64;
pub type HttpConnectionId = u64;
pub type HttpRequestId = u64;

const WSAEWOULDBLOCK: i32 = 10035;
const WSAEADDRINUSE: i32 = 10048;
const WSAECONNREFUSED: i32 = 10061;
const WSANOTINITIALISED: i32 = 10093;
const WSAHOST_NOT_FOUND: i32 = 11001;

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
    state: SocketState,
    recv_queue: VecDeque<u8>,
}

#[derive(Debug, Clone)]
enum SocketState {
    Created,
    Bound(SockAddr),
    Listening { _addr: SockAddr, _backlog: usize },
    Connected { peer: SocketId },
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

#[derive(Debug, Clone)]
pub struct NetworkStack {
    next_id: u64,
    wsa_refcount: u32,
    last_wsa_error: i32,
    sockets: BTreeMap<SocketId, SocketRecord>,
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
}

impl Default for NetworkStack {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkStack {
    pub fn new() -> Self {
        let mut routes = BTreeMap::new();
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
                certificate_chain: Vec::new(),
            },
        );
        routes.insert(
            ("https".to_string(), "api.example.com".to_string(), "/store/cart".to_string()),
            HttpResponseTemplate {
                status: 200,
                headers: BTreeMap::from([("x-casa1-route".to_string(), "cart".to_string())]),
                body: b"cart".to_vec(),
                cookies: Vec::new(),
                certificate_chain: Vec::new(),
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
            next_id: 1,
            wsa_refcount: 0,
            last_wsa_error: 0,
            sockets: BTreeMap::new(),
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
            trust_store: BTreeMap::new(),
            keychain_mapping_enabled: false,
            current_day: 0,
            http_traces: Vec::new(),
            cipher_log: Vec::new(),
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
        self.socket_record_mut(socket)?.state = SocketState::Bound(addr);
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
        let Some(listener) = self.listeners.get(&addr).copied() else {
            self.last_wsa_error = WSAECONNREFUSED;
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("connection refused for {}:{}", addr.host, addr.port),
            ));
        };
        let server_socket = self.alloc_id();
        let family = self.socket_record(socket)?.family;
        self.sockets.insert(
            server_socket,
            SocketRecord {
                family,
                nonblocking: false,
                state: SocketState::Connected { peer: socket },
                recv_queue: VecDeque::new(),
            },
        );
        self.socket_record_mut(socket)?.state = SocketState::Connected { peer: server_socket };
        self.pending_accept
            .entry(listener)
            .or_default()
            .push_back(server_socket);
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn send(&mut self, socket: SocketId, bytes: &[u8]) -> AppResult<usize> {
        self.ensure_wsa_started()?;
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

    pub fn shutdown(&mut self, socket: SocketId) -> AppResult<()> {
        self.ensure_wsa_started()?;
        self.socket_record_mut(socket)?.state = SocketState::Shutdown;
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn closesocket(&mut self, socket: SocketId) -> AppResult<()> {
        self.ensure_wsa_started()?;
        self.socket_record_mut(socket)?.state = SocketState::Closed;
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn ioctlsocket_fionbio(&mut self, socket: SocketId, nonblocking: bool) -> AppResult<()> {
        self.ensure_wsa_started()?;
        self.socket_record_mut(socket)?.nonblocking = nonblocking;
        self.last_wsa_error = 0;
        Ok(())
    }

    pub fn select(&self, sockets: &[SocketId]) -> AppResult<(Vec<SocketId>, Vec<SocketId>)> {
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        for socket in sockets {
            let record = self.socket_record(*socket)?;
            let can_read = !record.recv_queue.is_empty()
                || self
                    .pending_accept
                    .get(socket)
                    .is_some_and(|pending| !pending.is_empty());
            let can_write = matches!(
                record.state,
                SocketState::Connected { .. } | SocketState::Listening { .. }
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
        let Some(records) = self.dns_records.get(host) else {
            self.last_wsa_error = WSAHOST_NOT_FOUND;
            return Err(AppError::new(
                ReasonCode::RcDnsNotFound,
                format!("DNS lookup failed for {host}"),
            ));
        };
        self.last_wsa_error = 0;
        Ok(records
            .iter()
            .map(|record| ResolvedAddr {
                family: record.family,
                host: record.host.clone(),
                port,
            })
            .collect())
    }

    pub fn freeaddrinfo(&mut self) {
        self.last_wsa_error = 0;
    }

    pub fn wsa_get_last_error(&self) -> i32 {
        self.last_wsa_error
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
        self.next_id += 1;
        id
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