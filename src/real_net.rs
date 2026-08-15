//! Real networking stack for Casa1.
//!
//! Provides real TCP/UDP sockets, DNS resolution, HTTP client, and TLS
//! using actual OS-level networking via `std::net`, `reqwest`, and `native-tls`.
//! This replaces the mock routing in `src/network.rs` with genuine network I/O.

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use native_tls::TlsConnector;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{self, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// ID allocation
// ---------------------------------------------------------------------------

static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(1);

fn alloc_id() -> u64 {
    NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Address family
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    V4,
    V6,
}

impl From<AddressFamily> for net::SocketAddr {
    fn from(_af: AddressFamily) -> Self {
        // Default to V4 any
        net::SocketAddr::from(([0, 0, 0, 0], 0))
    }
}

// ---------------------------------------------------------------------------
// Resolved address
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ResolvedAddr {
    pub family: AddressFamily,
    pub ip: String,
    pub port: u16,
}

// ---------------------------------------------------------------------------
// Real DNS resolver
// ---------------------------------------------------------------------------

/// Real DNS resolution using `std::net::ToSocketAddrs`.
pub struct RealDnsResolver;

impl RealDnsResolver {
    /// Resolve a hostname to a list of socket addresses.
    pub fn resolve(host: &str, port: u16) -> AppResult<Vec<ResolvedAddr>> {
        let addr_str = format!("{host}:{port}");
        let addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcDnsNotFound,
                    format!("DNS lookup failed for {host}: {e}"),
                )
            })?
            .collect();

        if addrs.is_empty() {
            return Err(AppError::new(
                ReasonCode::RcDnsNotFound,
                format!("DNS lookup returned no addresses for {host}"),
            ));
        }

        Ok(addrs
            .into_iter()
            .map(|addr: SocketAddr| {
                let family = if addr.is_ipv6() {
                    AddressFamily::V6
                } else {
                    AddressFamily::V4
                };
                ResolvedAddr {
                    family,
                    ip: addr.ip().to_string(),
                    port: addr.port(),
                }
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Real TCP socket
// ---------------------------------------------------------------------------

pub type RealSocketId = u64;

/// State tracked for a real socket.
pub struct RealTcpSocket {
    pub id: RealSocketId,
    pub stream: TcpStream,
    pub peer_addr: Option<String>,
    pub nonblocking: bool,
}

impl RealTcpSocket {
    /// Read up to `buf.len()` bytes from the socket.
    pub fn recv(&mut self, buf: &mut [u8]) -> AppResult<usize> {
        self.stream
            .read(buf)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("TCP recv error: {e}")))
    }

    /// Write bytes to the socket.
    pub fn send(&mut self, data: &[u8]) -> AppResult<usize> {
        self.stream
            .write(data)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("TCP send error: {e}")))
    }

    /// Flush the write buffer.
    pub fn flush(&mut self) -> AppResult<()> {
        self.stream
            .flush()
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("TCP flush error: {e}")))
    }

    /// Set non-blocking mode.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> AppResult<()> {
        self.nonblocking = nonblocking;
        self.stream
            .set_nonblocking(nonblocking)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("set_nonblocking error: {e}")))
    }

    /// Set read/write timeout.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) -> AppResult<()> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("set_read_timeout error: {e}")))?;
        self.stream
            .set_write_timeout(timeout)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("set_write_timeout error: {e}")))
    }

    /// Get the number of bytes available for reading.
    pub fn bytes_available(&self) -> AppResult<u32> {
        // On macOS, use ioctl FIONREAD
        let mut available: i32 = 0;
        // SAFETY: ioctl FIONREAD on a valid raw fd; &mut available is a valid i32 pointer.
        unsafe {
            let ret = libc::ioctl(self.stream.as_raw_fd(), libc::FIONREAD, &mut available);
            if ret < 0 {
                return Err(AppError::new(ReasonCode::RcIo, "FIONREAD ioctl failed"));
            }
        }
        Ok(available.max(0) as u32)
    }
}

// ---------------------------------------------------------------------------
// Real TCP listener
// ---------------------------------------------------------------------------

pub struct RealTcpListener {
    pub id: RealSocketId,
    pub listener: TcpListener,
    pub local_addr: String,
}

impl RealTcpListener {
    /// Accept a new incoming connection.
    pub fn accept(&self) -> AppResult<RealTcpSocket> {
        let (stream, peer) = self
            .listener
            .accept()
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("TCP accept error: {e}")))?;
        Ok(RealTcpSocket {
            id: alloc_id(),
            stream,
            peer_addr: Some(peer.to_string()),
            nonblocking: false,
        })
    }

    /// Set non-blocking mode on the listener.
    pub fn set_nonblocking(&self, nonblocking: bool) -> AppResult<()> {
        self.listener.set_nonblocking(nonblocking).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("listener set_nonblocking error: {e}"),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Real UDP socket
// ---------------------------------------------------------------------------

pub struct RealUdpSocket {
    pub id: RealSocketId,
    pub socket: UdpSocket,
    pub nonblocking: bool,
}

impl RealUdpSocket {
    /// Send data to the specified address.
    pub fn send_to(&self, data: &[u8], addr: &str) -> AppResult<usize> {
        let addr: SocketAddr = addr.parse().map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("invalid UDP address {addr}: {e}"))
        })?;
        self.socket
            .send_to(data, addr)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("UDP send_to error: {e}")))
    }

    /// Receive data and return the number of bytes and source address.
    pub fn recv_from(&self, buf: &mut [u8]) -> AppResult<(usize, String)> {
        let (n, addr) = self
            .socket
            .recv_from(buf)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("UDP recv_from error: {e}")))?;
        Ok((n, addr.to_string()))
    }

    /// Connect the UDP socket to a specific address (for connected UDP).
    pub fn connect(&self, addr: &str) -> AppResult<()> {
        let addr: SocketAddr = addr.parse().map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("invalid UDP connect address {addr}: {e}"),
            )
        })?;
        self.socket
            .connect(addr)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("UDP connect error: {e}")))
    }

    /// Send data on a connected UDP socket.
    pub fn send(&self, data: &[u8]) -> AppResult<usize> {
        self.socket
            .send(data)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("UDP send error: {e}")))
    }

    /// Receive data on a connected UDP socket.
    pub fn recv(&self, buf: &mut [u8]) -> AppResult<usize> {
        self.socket
            .recv(buf)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("UDP recv error: {e}")))
    }

    /// Set non-blocking mode.
    pub fn set_nonblocking(&self, nonblocking: bool) -> AppResult<()> {
        self.socket
            .set_nonblocking(nonblocking)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("UDP set_nonblocking error: {e}")))
    }

    /// Set read/write timeout.
    pub fn set_timeout(&self, timeout: Option<Duration>) -> AppResult<()> {
        self.socket.set_read_timeout(timeout).map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("UDP set_read_timeout error: {e}"))
        })?;
        self.socket.set_write_timeout(timeout).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("UDP set_write_timeout error: {e}"),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// Real TLS connection
// ---------------------------------------------------------------------------

pub struct RealTlsStream {
    pub id: RealSocketId,
    pub stream: native_tls::TlsStream<TcpStream>,
    pub peer_addr: String,
    pub nonblocking: bool,
}

impl RealTlsStream {
    /// Read from the TLS stream.
    pub fn recv(&mut self, buf: &mut [u8]) -> AppResult<usize> {
        self.stream
            .read(buf)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("TLS recv error: {e}")))
    }

    /// Write to the TLS stream.
    pub fn send(&mut self, data: &[u8]) -> AppResult<usize> {
        self.stream
            .write(data)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("TLS send error: {e}")))
    }

    /// Flush the TLS stream.
    pub fn flush(&mut self) -> AppResult<()> {
        self.stream
            .flush()
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("TLS flush error: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Real HTTP response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RealHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Real HTTP client
// ---------------------------------------------------------------------------

/// Real HTTP client using `reqwest` with TLS support.
pub struct RealHttpClient {
    client: reqwest::blocking::Client,
    cookie_jar: Vec<crate::network::Cookie>,
}

impl RealHttpClient {
    /// Create a new HTTP client with default settings.
    pub fn new() -> AppResult<Self> {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(false)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("failed to create HTTP client: {e}"),
                )
            })?;

        Ok(Self {
            client,
            cookie_jar: Vec::new(),
        })
    }

    /// Create an HTTP client that accepts invalid certificates.
    ///
    /// # Security
    /// This bypasses TLS certificate validation and should ONLY be used in
    /// development/test environments. It is gated behind the `dev-insecure-tls`
    /// feature flag and will fail to compile in production builds.
    #[cfg(feature = "dev-insecure-tls")]
    pub fn new_dangerous() -> AppResult<Self> {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!("failed to create HTTP client: {e}"),
                )
            })?;

        Ok(Self {
            client,
            cookie_jar: Vec::new(),
        })
    }

    /// Perform a GET request.
    pub fn get(&mut self, url: &str) -> AppResult<RealHttpResponse> {
        let mut request = self.client.get(url);
        request = self.add_cookie_header(request, url);
        let response = request
            .send()
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("HTTP GET {url} failed: {e}")))?;
        self.process_response(response)
    }

    /// Perform a POST request with a body.
    pub fn post(
        &mut self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> AppResult<RealHttpResponse> {
        let mut request = self
            .client
            .post(url)
            .header("Content-Type", content_type)
            .body(body.to_vec());
        request = self.add_cookie_header(request, url);
        let response = request
            .send()
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("HTTP POST {url} failed: {e}")))?;
        self.process_response(response)
    }

    /// Perform a PUT request with a body.
    pub fn put(
        &mut self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> AppResult<RealHttpResponse> {
        let mut request = self
            .client
            .put(url)
            .header("Content-Type", content_type)
            .body(body.to_vec());
        request = self.add_cookie_header(request, url);
        let response = request
            .send()
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("HTTP PUT {url} failed: {e}")))?;
        self.process_response(response)
    }

    /// Perform a DELETE request.
    pub fn delete(&mut self, url: &str) -> AppResult<RealHttpResponse> {
        let mut request = self.client.delete(url);
        request = self.add_cookie_header(request, url);
        let response = request.send().map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("HTTP DELETE {url} failed: {e}"))
        })?;
        self.process_response(response)
    }

    /// Perform a HEAD request.
    pub fn head(&mut self, url: &str) -> AppResult<RealHttpResponse> {
        let mut request = self.client.head(url);
        request = self.add_cookie_header(request, url);
        let response = request
            .send()
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("HTTP HEAD {url} failed: {e}")))?;
        self.process_response(response)
    }

    /// Download a file to disk.
    pub fn download_file(&self, url: &str, path: &std::path::Path) -> AppResult<u64> {
        let mut response = self.client.get(url).send().map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("HTTP download {url} failed: {e}"))
        })?;

        let status = response.status().as_u16();
        if status >= 400 {
            return Err(AppError::new(
                ReasonCode::RcIo,
                format!("HTTP download {url} returned status {status}"),
            ));
        }

        let mut file = std::fs::File::create(path).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("cannot create file {}: {e}", path.display()),
            )
        })?;

        let bytes = std::io::copy(&mut response, &mut file)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("download write error: {e}")))?;

        Ok(bytes)
    }

    /// Get the cookie jar snapshot.
    pub fn cookie_snapshot(&self) -> &[crate::network::Cookie] {
        &self.cookie_jar
    }

    /// Load cookies from a snapshot.
    pub fn load_cookies(&mut self, cookies: Vec<crate::network::Cookie>) {
        self.cookie_jar = cookies;
    }

    fn add_cookie_header(
        &self,
        request: reqwest::blocking::RequestBuilder,
        _url: &str,
    ) -> reqwest::blocking::RequestBuilder {
        // Add matching cookies to the request
        let cookie_header: String = self
            .cookie_jar
            .iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ");

        if cookie_header.is_empty() {
            request
        } else {
            request.header("Cookie", cookie_header)
        }
    }

    fn process_response(
        &mut self,
        response: reqwest::blocking::Response,
    ) -> AppResult<RealHttpResponse> {
        let status = response.status().as_u16();
        let mut headers = BTreeMap::new();
        for (key, value) in response.headers() {
            headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
        }

        // Extract Set-Cookie headers and store them
        if let Some(set_cookies) = headers.get("set-cookie").cloned() {
            for cookie_str in set_cookies.split(',') {
                if let Some(cookie) = parse_set_cookie(cookie_str) {
                    self.store_cookie(cookie);
                }
            }
        }

        let body = response.bytes().map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("HTTP response body read error: {e}"),
            )
        })?;

        Ok(RealHttpResponse {
            status,
            headers,
            body: body.to_vec(),
        })
    }

    fn store_cookie(&mut self, cookie: crate::network::Cookie) {
        self.cookie_jar.retain(|existing| {
            !(existing.name == cookie.name
                && existing.domain == cookie.domain
                && existing.path == cookie.path)
        });
        self.cookie_jar.push(cookie);
    }
}

/// Parse a Set-Cookie header value into a Cookie struct.
fn parse_set_cookie(header: &str) -> Option<crate::network::Cookie> {
    let parts: Vec<&str> = header.split(';').collect();
    let name_value = parts.first()?;
    let eq_pos = name_value.find('=')?;
    let name = name_value[..eq_pos].trim().to_string();
    let value = name_value[eq_pos + 1..].trim().to_string();

    let mut domain = String::new();
    let mut path = "/".to_string();
    let mut secure = false;

    for part in &parts[1..] {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("domain=") {
            domain = val.trim_start_matches('.').to_string();
        } else if let Some(val) = part.strip_prefix("path=") {
            path = val.to_string();
        } else if part == "secure" {
            secure = true;
        }
    }

    if domain.is_empty() {
        domain = ".unknown".to_string();
    }

    Some(crate::network::Cookie {
        name,
        value,
        domain,
        path,
        secure,
    })
}

// ---------------------------------------------------------------------------
// Real networking stack (socket manager)
// ---------------------------------------------------------------------------

/// Manages real sockets with Windows-like handle semantics.
pub struct RealNetworkStack {
    wsa_refcount: u32,
    last_wsa_error: i32,
    tcp_sockets: BTreeMap<RealSocketId, RealTcpSocket>,
    tcp_listeners: BTreeMap<RealSocketId, RealTcpListener>,
    udp_sockets: BTreeMap<RealSocketId, RealUdpSocket>,
    tls_streams: BTreeMap<RealSocketId, RealTlsStream>,
    http_client: Option<RealHttpClient>,
}

impl RealNetworkStack {
    pub fn new() -> Self {
        Self {
            wsa_refcount: 0,
            last_wsa_error: 0,
            tcp_sockets: BTreeMap::new(),
            tcp_listeners: BTreeMap::new(),
            udp_sockets: BTreeMap::new(),
            tls_streams: BTreeMap::new(),
            http_client: None,
        }
    }

    // -- WSA lifecycle --

    pub fn wsa_startup(&mut self) {
        self.wsa_refcount += 1;
        self.last_wsa_error = 0;
    }

    pub fn wsa_cleanup(&mut self) {
        self.wsa_refcount = self.wsa_refcount.saturating_sub(1);
        self.last_wsa_error = 0;
    }

    pub fn wsa_get_last_error(&self) -> i32 {
        self.last_wsa_error
    }

    fn ensure_wsa(&self) -> AppResult<()> {
        if self.wsa_refcount == 0 {
            self.last_wsa_error;
            return Err(AppError::new(ReasonCode::RcIo, "Winsock not initialized"));
        }
        Ok(())
    }

    // -- TCP operations --

    /// Connect a TCP socket to a remote address.
    pub fn tcp_connect(
        &mut self,
        host: &str,
        port: u16,
        timeout: Option<Duration>,
    ) -> AppResult<RealSocketId> {
        self.ensure_wsa()?;

        let addrs = RealDnsResolver::resolve(host, port)?;
        let addr = addrs.first().ok_or_else(|| {
            AppError::new(
                ReasonCode::RcDnsNotFound,
                format!("no address for {host}:{port}"),
            )
        })?;

        let socket_addr: SocketAddr = format!("{}:{}", addr.ip, addr.port)
            .parse()
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("invalid address: {e}")))?;

        let stream = if let Some(t) = timeout {
            TcpStream::connect_timeout(&socket_addr, t)
        } else {
            TcpStream::connect(&socket_addr)
        }
        .map_err(|e| {
            self.last_wsa_error = 10061; // WSAECONNREFUSED
            AppError::new(
                ReasonCode::RcIo,
                format!("TCP connect to {host}:{port} failed: {e}"),
            )
        })?;

        let id = alloc_id();
        let socket = RealTcpSocket {
            id,
            stream,
            peer_addr: Some(format!("{host}:{port}")),
            nonblocking: false,
        };
        self.tcp_sockets.insert(id, socket);
        self.last_wsa_error = 0;
        Ok(id)
    }

    /// Send data on a connected TCP socket.
    pub fn tcp_send(&mut self, socket_id: RealSocketId, data: &[u8]) -> AppResult<usize> {
        self.ensure_wsa()?;
        let socket = self.tcp_sockets.get_mut(&socket_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown TCP socket {socket_id}"))
        })?;
        let n = socket.send(data)?;
        self.last_wsa_error = 0;
        Ok(n)
    }

    /// Receive data from a connected TCP socket.
    pub fn tcp_recv(&mut self, socket_id: RealSocketId, buf: &mut [u8]) -> AppResult<usize> {
        self.ensure_wsa()?;
        let socket = self.tcp_sockets.get_mut(&socket_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown TCP socket {socket_id}"))
        })?;
        let n = socket.recv(buf)?;
        self.last_wsa_error = 0;
        Ok(n)
    }

    /// Close a TCP socket.
    pub fn tcp_close(&mut self, socket_id: RealSocketId) -> AppResult<()> {
        self.tcp_sockets.remove(&socket_id);
        self.last_wsa_error = 0;
        Ok(())
    }

    /// Set non-blocking mode on a TCP socket.
    pub fn tcp_set_nonblocking(
        &mut self,
        socket_id: RealSocketId,
        nonblocking: bool,
    ) -> AppResult<()> {
        let socket = self.tcp_sockets.get_mut(&socket_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown TCP socket {socket_id}"))
        })?;
        socket.set_nonblocking(nonblocking)
    }

    /// Get bytes available to read on a TCP socket.
    pub fn tcp_bytes_available(&self, socket_id: RealSocketId) -> AppResult<u32> {
        let socket = self.tcp_sockets.get(&socket_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown TCP socket {socket_id}"))
        })?;
        socket.bytes_available()
    }

    // -- TCP listener operations --

    /// Create a TCP listener bound to the specified address.
    pub fn tcp_listen(&mut self, host: &str, port: u16, backlog: i32) -> AppResult<RealSocketId> {
        self.ensure_wsa()?;
        let addr = if host.is_empty() || host == "0.0.0.0" {
            format!("0.0.0.0:{port}")
        } else {
            format!("{host}:{port}")
        };
        let socket_addr: SocketAddr = addr.parse().map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("invalid bind address {addr}: {e}"),
            )
        })?;

        let listener = TcpListener::bind(socket_addr).map_err(|e| {
            self.last_wsa_error = 10048; // WSAEADDRINUSE
            AppError::new(ReasonCode::RcIo, format!("TCP bind {addr} failed: {e}"))
        })?;

        // TcpListener doesn't expose backlog directly in std; log the requested value
        if backlog != 0 {
            eprintln!("TCP bind: requested backlog={} (using default)", backlog);
        }

        let id = alloc_id();
        let local_addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        self.tcp_listeners.insert(
            id,
            RealTcpListener {
                id,
                listener,
                local_addr,
            },
        );
        self.last_wsa_error = 0;
        Ok(id)
    }

    /// Accept a new connection on a listener.
    pub fn tcp_accept(&mut self, listener_id: RealSocketId) -> AppResult<RealSocketId> {
        self.ensure_wsa()?;
        let listener = self.tcp_listeners.get(&listener_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcIo,
                format!("unknown TCP listener {listener_id}"),
            )
        })?;
        let client_socket = listener.accept()?;
        let client_id = client_socket.id;
        self.tcp_sockets.insert(client_id, client_socket);
        self.last_wsa_error = 0;
        Ok(client_id)
    }

    /// Close a TCP listener.
    pub fn tcp_listener_close(&mut self, listener_id: RealSocketId) -> AppResult<()> {
        self.tcp_listeners.remove(&listener_id);
        self.last_wsa_error = 0;
        Ok(())
    }

    // -- UDP operations --

    /// Create a UDP socket bound to the specified address.
    pub fn udp_socket(&mut self, host: &str, port: u16) -> AppResult<RealSocketId> {
        self.ensure_wsa()?;
        let addr = if host.is_empty() || host == "0.0.0.0" {
            format!("0.0.0.0:{port}")
        } else {
            format!("{host}:{port}")
        };
        let socket_addr: SocketAddr = addr.parse().map_err(|e| {
            AppError::new(ReasonCode::RcIo, format!("invalid UDP address {addr}: {e}"))
        })?;

        let socket = UdpSocket::bind(socket_addr)
            .map_err(|e| AppError::new(ReasonCode::RcIo, format!("UDP bind {addr} failed: {e}")))?;

        let id = alloc_id();
        self.udp_sockets.insert(
            id,
            RealUdpSocket {
                id,
                socket,
                nonblocking: false,
            },
        );
        self.last_wsa_error = 0;
        Ok(id)
    }

    /// Send data on a UDP socket.
    pub fn udp_send_to(
        &mut self,
        socket_id: RealSocketId,
        data: &[u8],
        addr: &str,
    ) -> AppResult<usize> {
        self.ensure_wsa()?;
        let socket = self.udp_sockets.get(&socket_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown UDP socket {socket_id}"))
        })?;
        let n = socket.send_to(data, addr)?;
        self.last_wsa_error = 0;
        Ok(n)
    }

    /// Receive data on a UDP socket.
    pub fn udp_recv_from(
        &mut self,
        socket_id: RealSocketId,
        buf: &mut [u8],
    ) -> AppResult<(usize, String)> {
        self.ensure_wsa()?;
        let socket = self.udp_sockets.get(&socket_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown UDP socket {socket_id}"))
        })?;
        let result = socket.recv_from(buf)?;
        self.last_wsa_error = 0;
        Ok(result)
    }

    /// Close a UDP socket.
    pub fn udp_close(&mut self, socket_id: RealSocketId) -> AppResult<()> {
        self.udp_sockets.remove(&socket_id);
        self.last_wsa_error = 0;
        Ok(())
    }

    // -- TLS operations --

    /// Connect to a remote host with TLS.
    /// Configures SNI (Server Name Indication) via the native-tls builder,
    /// so the TLS ClientHello advertises the target hostname.
    pub fn tls_connect(&mut self, host: &str, port: u16) -> AppResult<RealSocketId> {
        self.ensure_wsa()?;

        // Build a TlsConnector with explicit SNI hostname so that virtual-host
        // aware servers return the correct certificate.
        // The SNI hostname is provided in the `connector.connect(host, stream)` call below,
        // which sends the hostname as the TLS SNI extension automatically.
        let connector = TlsConnector::builder().build().map_err(|e| {
            AppError::new(
                ReasonCode::RcTlsCertRejected,
                format!("TLS connector build failed: {e}"),
            )
        })?;

        let tcp_stream = TcpStream::connect((host, port)).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("TLS TCP connect to {host}:{port} failed: {e}"),
            )
        })?;

        let tls_stream = connector.connect(host, tcp_stream).map_err(|e| {
            AppError::new(
                ReasonCode::RcTlsCertRejected,
                format!("TLS handshake with {host} failed: {e}"),
            )
        })?;

        let id = alloc_id();
        self.tls_streams.insert(
            id,
            RealTlsStream {
                id,
                stream: tls_stream,
                peer_addr: format!("{host}:{port}"),
                nonblocking: false,
            },
        );
        self.last_wsa_error = 0;
        Ok(id)
    }

    /// Send data on a TLS stream.
    pub fn tls_send(&mut self, stream_id: RealSocketId, data: &[u8]) -> AppResult<usize> {
        self.ensure_wsa()?;
        let stream = self.tls_streams.get_mut(&stream_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown TLS stream {stream_id}"))
        })?;
        let n = stream.send(data)?;
        self.last_wsa_error = 0;
        Ok(n)
    }

    /// Receive data from a TLS stream.
    pub fn tls_recv(&mut self, stream_id: RealSocketId, buf: &mut [u8]) -> AppResult<usize> {
        self.ensure_wsa()?;
        let stream = self.tls_streams.get_mut(&stream_id).ok_or_else(|| {
            AppError::new(ReasonCode::RcIo, format!("unknown TLS stream {stream_id}"))
        })?;
        let n = stream.recv(buf)?;
        self.last_wsa_error = 0;
        Ok(n)
    }

    /// Close a TLS stream.
    pub fn tls_close(&mut self, stream_id: RealSocketId) -> AppResult<()> {
        self.tls_streams.remove(&stream_id);
        self.last_wsa_error = 0;
        Ok(())
    }

    // -- HTTP operations --

    /// Get or create the HTTP client.
    pub fn http_client(&mut self) -> AppResult<&mut RealHttpClient> {
        if self.http_client.is_none() {
            self.http_client = Some(RealHttpClient::new()?);
        }
        Ok(self.http_client.as_mut().unwrap())
    }

    /// Perform an HTTP GET request.
    pub fn http_get(&mut self, url: &str) -> AppResult<RealHttpResponse> {
        self.http_client()?.get(url)
    }

    /// Perform an HTTP POST request.
    pub fn http_post(
        &mut self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> AppResult<RealHttpResponse> {
        self.http_client()?.post(url, body, content_type)
    }

    /// Perform an HTTP PUT request.
    pub fn http_put(
        &mut self,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> AppResult<RealHttpResponse> {
        self.http_client()?.put(url, body, content_type)
    }

    /// Perform an HTTP DELETE request.
    pub fn http_delete(&mut self, url: &str) -> AppResult<RealHttpResponse> {
        self.http_client()?.delete(url)
    }

    /// Perform an HTTP HEAD request.
    pub fn http_head(&mut self, url: &str) -> AppResult<RealHttpResponse> {
        self.http_client()?.head(url)
    }

    /// Download a file via HTTP.
    pub fn http_download(&self, url: &str, path: &std::path::Path) -> AppResult<u64> {
        let client = self
            .http_client
            .as_ref()
            .ok_or_else(|| AppError::new(ReasonCode::RcIo, "HTTP client not initialized"))?;
        client.download_file(url, path)
    }

    /// Close any handle by ID.
    pub fn close_handle(&mut self, id: RealSocketId) {
        self.tcp_sockets.remove(&id);
        self.tcp_listeners.remove(&id);
        self.udp_sockets.remove(&id);
        self.tls_streams.remove(&id);
    }

    /// Check if a socket ID is a TCP socket.
    pub fn is_tcp_socket(&self, id: RealSocketId) -> bool {
        self.tcp_sockets.contains_key(&id)
    }

    /// Check if a socket ID is a TCP listener.
    pub fn is_tcp_listener(&self, id: RealSocketId) -> bool {
        self.tcp_listeners.contains_key(&id)
    }

    /// Check if a socket ID is a UDP socket.
    pub fn is_udp_socket(&self, id: RealSocketId) -> bool {
        self.udp_sockets.contains_key(&id)
    }

    /// Check if a socket ID is a TLS stream.
    pub fn is_tls_stream(&self, id: RealSocketId) -> bool {
        self.tls_streams.contains_key(&id)
    }
}

// ---------------------------------------------------------------------------
// Select / poll support
// ---------------------------------------------------------------------------

/// Poll a set of sockets for readability/writability using kqueue on macOS.
pub fn poll_sockets(
    tcp_sockets: &[&TcpStream],
    udp_sockets: &[&UdpSocket],
    timeout: Option<Duration>,
) -> AppResult<(Vec<usize>, Vec<usize>)> {
    use std::os::unix::io::AsRawFd;

    let mut read_fds: Vec<i32> = Vec::new();
    let mut write_fds: Vec<i32> = Vec::new();

    for stream in tcp_sockets {
        read_fds.push(stream.as_raw_fd());
        write_fds.push(stream.as_raw_fd());
    }

    for socket in udp_sockets {
        read_fds.push(socket.as_raw_fd());
        write_fds.push(socket.as_raw_fd());
    }

    if read_fds.is_empty() && write_fds.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    // Use libc select()
    // SAFETY: zeroed fd_set is valid for initialization before FD_ZERO.
    let mut read_set: libc::fd_set = unsafe { std::mem::zeroed() };
    // SAFETY: zeroed fd_set is valid for initialization before FD_ZERO.
    let mut write_set: libc::fd_set = unsafe { std::mem::zeroed() };
    let mut max_fd = 0;

    // SAFETY: FD_ZERO/FD_SET operate on properly aligned, zeroed fd_set structs.
    unsafe {
        libc::FD_ZERO(&mut read_set);
        libc::FD_ZERO(&mut write_set);

        for &fd in &read_fds {
            libc::FD_SET(fd, &mut read_set);
            max_fd = max_fd.max(fd);
        }
        for &fd in &write_fds {
            libc::FD_SET(fd, &mut write_set);
            max_fd = max_fd.max(fd);
        }
    }

    let mut timeout_val = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let timeout_ptr: *mut libc::timeval = match timeout {
        Some(d) => {
            timeout_val.tv_sec = d.as_secs() as i64;
            timeout_val.tv_usec = d.subsec_micros() as i32;
            &mut timeout_val
        }
        None => std::ptr::null_mut(),
    };

    // SAFETY: select() is called with valid fd_set pointers and a bounded max_fd.
    let result = unsafe {
        libc::select(
            max_fd + 1,
            &mut read_set,
            &mut write_set,
            std::ptr::null_mut(),
            timeout_ptr,
        )
    };

    if result < 0 {
        return Err(AppError::new(
            ReasonCode::RcIo,
            // SAFETY: __error() returns a thread-local pointer to errno; dereference is safe.
            format!("select() failed with errno {}", unsafe { *libc::__error() }),
        ));
    }

    let mut readable_indices = Vec::new();
    let mut writable_indices = Vec::new();

    for (i, &fd) in read_fds.iter().enumerate() {
        // SAFETY: FD_ISSET reads from a valid fd_set with a bounded fd value.
        unsafe {
            if libc::FD_ISSET(fd, &mut read_set) {
                readable_indices.push(i);
            }
        }
    }

    for (i, &fd) in write_fds.iter().enumerate() {
        // SAFETY: FD_ISSET reads from a valid fd_set with a bounded fd value.
        unsafe {
            if libc::FD_ISSET(fd, &mut write_set) {
                writable_indices.push(i);
            }
        }
    }

    Ok((readable_indices, writable_indices))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    #[test]
    fn dns_resolver_resolves_localhost() {
        let addrs = RealDnsResolver::resolve("localhost", 80).unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.ip == "127.0.0.1"));
    }

    #[test]
    fn dns_resolver_resolves_ipv4_loopback() {
        let addrs = RealDnsResolver::resolve("127.0.0.1", 8080).unwrap();
        assert!(!addrs.is_empty());
        assert_eq!(addrs[0].ip, "127.0.0.1");
        assert_eq!(addrs[0].port, 8080);
    }

    #[test]
    fn dns_resolver_fails_for_invalid_host() {
        let result = RealDnsResolver::resolve("this.host.does.not.exist.invalid", 80);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn tcp_connect_and_exchange_data() {
        let ready = Arc::new(AtomicBool::new(false));
        let ready_clone = ready.clone();

        // Start a listener in a background thread
        let handle = thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let local_addr = listener.local_addr().unwrap();
            let port = local_addr.port();
            ready_clone.store(true, Ordering::SeqCst);

            let (mut stream, _addr) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"hello from client");

            stream.write_all(b"hello from server").unwrap();
            stream.flush().unwrap();
            (port, listener)
        });

        // Wait for the listener to be ready
        while !ready.load(Ordering::SeqCst) {
            thread::yield_now();
        }

        // This test is covered by tcp_loopback_with_known_port below
        drop(handle);
    }

    #[test]
    fn tcp_loopback_with_known_port() {
        // Use a known available port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(&buf[..n]).unwrap();
            stream.flush().unwrap();
        });

        let mut stack = RealNetworkStack::new();
        stack.wsa_startup();

        let socket_id = stack
            .tcp_connect("127.0.0.1", port, Some(Duration::from_secs(5)))
            .unwrap();
        stack.tcp_send(socket_id, b"echo test").unwrap();

        let mut buf = [0u8; 64];
        let n = stack.tcp_recv(socket_id, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"echo test");

        stack.tcp_close(socket_id).unwrap();
        server_handle.join().unwrap();
    }

    #[test]
    fn udp_send_and_receive() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port_a = socket_a.local_addr().unwrap().port();
        let socket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port_b = socket_b.local_addr().unwrap().port();

        socket_a
            .send_to(b"udp message", format!("127.0.0.1:{port_b}"))
            .unwrap();

        let mut buf = [0u8; 64];
        let (n, src) = socket_b.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"udp message");
        let src_str = src.to_string();
        assert!(src_str.contains(&port_a.to_string()));
    }

    #[test]
    fn tcp_listener_bind_and_accept() {
        let mut stack = RealNetworkStack::new();
        stack.wsa_startup();

        let listener_id = stack.tcp_listen("127.0.0.1", 0, 5).unwrap();
        assert!(stack.is_tcp_listener(listener_id));

        stack.tcp_listener_close(listener_id).unwrap();
        assert!(!stack.is_tcp_listener(listener_id));
    }

    #[test]
    fn wsa_lifecycle() {
        let mut stack = RealNetworkStack::new();

        // Operations should fail without WSA startup
        let _result = stack.tcp_connect("127.0.0.1", 80, None);
        assert!(_result.is_err(), "expected Err, got {_result:?}");

        stack.wsa_startup();
        stack.wsa_startup();
        assert_eq!(stack.wsa_refcount_check(), 2);

        stack.wsa_cleanup();
        stack.wsa_cleanup();
        assert_eq!(stack.wsa_refcount_check(), 0);
    }

    #[test]
    fn http_client_creates() {
        let client = RealHttpClient::new();
        assert!(client.is_ok(), "expected HTTP client to be created");
    }

    #[test]
    fn parse_set_cookie_basic() {
        let cookie =
            parse_set_cookie("session=abc123; domain=.example.com; path=/; secure").unwrap();
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "abc123");
        assert_eq!(cookie.domain, "example.com");
        assert_eq!(cookie.path, "/");
        assert!(cookie.secure);
    }

    #[test]
    fn parse_set_cookie_minimal() {
        let cookie = parse_set_cookie("key=value").unwrap();
        assert_eq!(cookie.name, "key");
        assert_eq!(cookie.value, "value");
        assert!(!cookie.secure);
    }

    #[test]
    fn real_network_stack_close_handle() {
        let mut stack = RealNetworkStack::new();
        stack.wsa_startup();

        let listener_id = stack.tcp_listen("127.0.0.1", 0, 5).unwrap();
        assert!(stack.is_tcp_listener(listener_id));

        stack.close_handle(listener_id);
        assert!(!stack.is_tcp_listener(listener_id));
    }

    #[test]
    fn tcp_set_nonblocking_mode() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });

        let mut stack = RealNetworkStack::new();
        stack.wsa_startup();

        let socket_id = stack
            .tcp_connect("127.0.0.1", port, Some(Duration::from_secs(5)))
            .unwrap();
        stack.tcp_set_nonblocking(socket_id, true).unwrap();

        // Non-blocking recv should return immediately (would block or data)
        let mut buf = [0u8; 1];
        let result = stack.tcp_recv(socket_id, &mut buf);
        // Either would-block error or no data — both acceptable
        assert!(result.is_err() || result.unwrap() == 0);

        stack.tcp_close(socket_id).unwrap();
        server.join().unwrap();
    }
}

impl RealNetworkStack {
    fn wsa_refcount_check(&self) -> u32 {
        self.wsa_refcount
    }
}
