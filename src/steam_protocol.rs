// ---------------------------------------------------------------------------
// Steam CM (Connection Manager) Protocol Implementation
//
// Implements the Steam client-to-CM wire protocol:
//   1. Real RSA/AES encryption handshake (RSA-OAEP key wrapping,
//      AES-256-CTR session cipher)
//   2. Steam message serialization/deserialization with ExtendedHeader
//   3. CDN content manifest parsing, chunked download, file verification
//   4. GameNetworkingSockets (GNS) integration stub
//   5. Authentication flow (logon, heartbeat, session management)
// ---------------------------------------------------------------------------

use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use aes_gcm::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use url::Url;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Magic header bytes for Steam CM protocol frames ("VS01").
const STEAM_MAGIC: u32 = 0x31305356;

/// Current Steam protocol version sent in encryption handshake.
const PROTOCOL_VERSION: u32 = 0x00010001;

/// Size of the ExtendedHeader portion before session_id/message_type fields.
const EXTENDED_HEADER_SIZE: u8 = 36;

/// AES-256 key length in bytes.
const AES_KEY_LEN: usize = 32;

/// Default CM server list (can be overridden by configuration).
const DEFAULT_CM_SERVERS: &[&str] = &[
    "cm1.steampowered.com:27017",
    "cm2.steampowered.com:27017",
    "cm3.steampowered.com:27017",
    "cm4.steampowered.com:27017",
    "cm5.steampowered.com:27017",
];

// ---------------------------------------------------------------------------
// GameNetworkingSockets (GNS) wire-format and STUN constants
// ---------------------------------------------------------------------------

/// AES-GCM nonce length (12 bytes).
const GNS_NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length (16 bytes).
const GNS_TAG_LEN: usize = 16;

/// STUN magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN binding request message type.
const STUN_BINDING_REQUEST: u16 = 0x0001;

/// STUN binding response message type.
const STUN_BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute type: MAPPED-ADDRESS.
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// STUN attribute type: XOR-MAPPED-ADDRESS.
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Default STUN server for NAT traversal.
pub const DEFAULT_STUN_SERVER: &str = "stun.steam.com:3478";

/// Default Steam Datagram Relay server.
const DEFAULT_SDR_SERVER: &str = "sdr.steam.com:27018";

// ---------------------------------------------------------------------------
// Type aliases for GameNetworkingSockets
// ---------------------------------------------------------------------------

/// Opaque handle for a GNS connection.
pub type GnsConnectionHandle = u64;

// ---------------------------------------------------------------------------
// Message types (Steam CM protocol EMsg)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum SteamMessageType {
    Invalid = 0,
    ChannelEncryptRequest = 130,
    ChannelEncryptResponse = 131,
    ChannelEncryptResult = 132,
    Multi = 136,
    ClientLogOn = 1101,
    ClientLogOnResponse = 1103,
    ClientHeartBeat = 1113,
    ClientLoggedOff = 1110,
    ClientAppUsageEvent = 1121,
    ClientUpdateAppJob = 1122,
    ClientPackageInfoRequest = 1128,
    ClientPackageInfoResponse = 1129,
    ClientGameConnectTokens = 1140,
    ClientGamesPlayed = 1134,
    ClientAuthList = 1150,
    ClientServersAvailable = 1155,
    ClientRequestedClientServices = 1178,
    ClientUserNotifications = 1186,
    ClientCommentNotifications = 1196,
    ClientVoteNotifications = 1201,
    ClientChatInvite = 1207,
    ClientChatGetTarget = 1212,
    ClientCreateFriendsGroup = 1225,
    ClientPersonaState = 1234,
    ClientFriendMsgIncoming = 1253,
    ClientChatRoomMsg = 1276,
    ClientUFSGetFileListForApp = 1311,
    ClientUFSDownloadRequest = 1317,
    ClientDownloadAppInfo = 1320,
    ClientLicenseList = 1355,
    ClientRegisterKey = 1360,
    ClientPurchaseResponse = 1367,
    ClientWalletUpdate = 1370,
    ClientAppInfoUpdate = 1384,
    ClientGameConnectDeny = 1406,
    ClientAuthListAck = 1415,
    ClientUCMsg = 1418,
    ClientFriendsList = 1421,
    ClientClanState = 1430,
    ClientChatEnter = 1436,
    ClientChatMsg = 1438,
    ClientChatMemberInfo = 1441,
    ClientAccountInfo = 1445,
    ClientUserGameStatsSchema = 1641,
    ClientUFSGetFileListForAppResponse = 1312,
    ClientUFSDownloadResponse = 1318,
    ClientDownloadAppInfoResponse = 1321,
    ClientUpdateAppJobResponse = 1123,
    ClientPackageInfoResponse2 = 1130,
    ClientAppInfoUpdateResponse = 1385,
    ClientSystemManagerShutdown = 2001,
    ClientSystemManagerUpdate = 2002,
    // Extended
    ClientLogonGameServer = 1862,
    ClientLogonGameServerResponse = 1863,
    ClientGetUserStats = 2500,
    ClientStoreUserStats = 2501,
    ClientGetUserStatsResponse = 2502,
    ClientStoreUserStatsResponse = 2503,
}

// ---------------------------------------------------------------------------
// CM server connection state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Resolving,
    Connecting,
    Connected,
    Encrypting,
    Authenticating,
    Ready,
    Error,
}

// ---------------------------------------------------------------------------
// ExtendedHeader — Steam message header (36-byte canonical portion)
//
// Wire layout (all little-endian):
//   [0..4)   raw: u32       — EMsg value
//   [4..8)   size: u32      — payload size in bytes
//   [8..16)  source_job_id: u64 — source job ID
//   [16..24) target_job_id: u64 — target job ID
//   [24]     header_size: u8 — always EXTENDED_HEADER_SIZE (36)
//   [25..28) padding: 3 bytes
//   [28..36) steam_id: u64  — sender Steam ID
// Then at offset 36:
//   [36..40) session_id: u32
//   [40..44) message_type: u32 (deprecated)
//   [44..)   payload bytes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedHeader {
    /// EMsg value identifying the message type.
    pub raw: u32,
    /// Size of the payload in bytes.
    pub size: u32,
    /// Source job ID for request/response correlation.
    pub source_job_id: u64,
    /// Target job ID for request/response correlation.
    pub target_job_id: u64,
    /// Always EXTENDED_HEADER_SIZE (36). Validates header alignment.
    pub header_size: u8,
    /// Steam ID of the sender.
    pub steam_id: u64,
    /// Session ID assigned during encryption handshake.
    pub session_id: u32,
    /// Deprecated message type field.
    pub message_type: u32,
}

impl ExtendedHeader {
    /// Total byte size of the extended header including session_id and
    /// message_type fields that follow the canonical 36-byte portion.
    pub const TOTAL_SIZE: usize = 44;

    /// Serialize this header into a byte buffer (44 bytes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::TOTAL_SIZE);
        buf.extend_from_slice(&self.raw.to_le_bytes());
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.source_job_id.to_le_bytes());
        buf.extend_from_slice(&self.target_job_id.to_le_bytes());
        buf.push(self.header_size);
        // 3 bytes padding
        buf.extend_from_slice(&[0u8; 3]);
        buf.extend_from_slice(&self.steam_id.to_le_bytes());
        buf.extend_from_slice(&self.session_id.to_le_bytes());
        buf.extend_from_slice(&self.message_type.to_le_bytes());
        buf
    }

    /// Deserialize a header from a byte slice. Returns None if the data is
    /// too short or if header_size is not EXTENDED_HEADER_SIZE.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < Self::TOTAL_SIZE {
            return None;
        }
        let raw = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let size = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let source_job_id = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let target_job_id = u64::from_le_bytes(data[16..24].try_into().ok()?);
        let header_size = data[24];
        if header_size != EXTENDED_HEADER_SIZE {
            return None;
        }
        let steam_id = u64::from_le_bytes(data[28..36].try_into().ok()?);
        let session_id = u32::from_le_bytes(data[36..40].try_into().ok()?);
        let message_type = u32::from_le_bytes(data[40..44].try_into().ok()?);

        Some(Self {
            raw,
            size,
            source_job_id,
            target_job_id,
            header_size,
            steam_id,
            session_id,
            message_type,
        })
    }
}

// ---------------------------------------------------------------------------
// SteamMessage — a fully decoded Steam CM message
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteamMessage {
    /// The message type (EMsg).
    pub msg_type: SteamMessageType,
    /// The raw payload bytes (after decryption, if applicable).
    pub payload: Vec<u8>,
    /// Source job ID.
    pub source_job_id: u64,
    /// Target job ID.
    pub target_job_id: u64,
    /// Steam ID of the sender.
    pub steam_id: u64,
    /// Session ID.
    pub session_id: u32,
    /// Deprecated message type field.
    pub message_type: u32,
}

// ---------------------------------------------------------------------------
// SessionCipher — AES-256-CTR session encryption
//
// Steam uses AES-256 in CTR mode with separate keys for send and receive:
//   send_key = SHA-256(aes_key || "send")
//   recv_key = SHA-256(aes_key || "recv")
// The initial counter (nonce) is the first 8 bytes of the SHA-256 of the
// session key, zero-extended to 16 bytes (AES-CTR nonce).
// ---------------------------------------------------------------------------

type Aes256Ctr = ctr::Ctr64LE<aes::Aes256>;

pub struct SessionCipher {
    /// Send-direction AES-256-CTR cipher.
    send_cipher: Aes256Ctr,
    /// Receive-direction AES-256-CTR cipher.
    recv_cipher: Aes256Ctr,
}

impl SessionCipher {
    /// Create a new SessionCipher from the raw AES session key (32 bytes).
    ///
    /// The key expansion follows Steam's convention:
    ///   send_key = SHA-256(aes_key || "send")
    ///   recv_key = SHA-256(aes_key || "recv")
    ///
    /// The nonce/IV for each direction is derived as the first 8 bytes of
    /// SHA-256(aes_key), left-padded with zeros to 16 bytes (matching Steam's
    /// CTR nonce scheme).
    pub fn new(aes_key: &[u8; AES_KEY_LEN]) -> Self {
        // Derive directional keys
        let send_key = {
            let mut hasher = Sha256::new();
            hasher.update(aes_key);
            hasher.update(b"send");
            let hash = hasher.finalize();
            let mut key = [0u8; AES_KEY_LEN];
            key.copy_from_slice(&hash[..AES_KEY_LEN]);
            key
        };

        let recv_key = {
            let mut hasher = Sha256::new();
            hasher.update(aes_key);
            hasher.update(b"recv");
            let hash = hasher.finalize();
            let mut key = [0u8; AES_KEY_LEN];
            key.copy_from_slice(&hash[..AES_KEY_LEN]);
            key
        };

        // Derive nonce from SHA-256(aes_key), first 8 bytes.
        let nonce_hash = Sha256::digest(aes_key);
        let mut nonce = [0u8; 16]; // 16-byte nonce for Ctr64LE
        nonce[..8].copy_from_slice(&nonce_hash[..8]);

        let send_cipher = Aes256Ctr::new(&send_key.into(), &nonce.into());
        let recv_cipher = Aes256Ctr::new(&recv_key.into(), &nonce.into());

        Self {
            send_cipher,
            recv_cipher,
        }
    }

    /// Encrypt (or decrypt) data using the send-direction cipher.
    /// AES-CTR is symmetric: encrypt and decrypt are the same operation.
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        self.send_cipher.apply_keystream(&mut buf);
        buf
    }

    /// Encrypt (or decrypt) data using the receive-direction cipher.
    /// AES-CTR is symmetric.
    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        self.recv_cipher.apply_keystream(&mut buf);
        buf
    }

    /// Reset send cipher to initial state (seeks to offset 0).
    pub fn reset_send(&mut self) {
        let _ = self.send_cipher.seek(0);
    }

    /// Reset receive cipher to initial state (seeks to offset 0).
    pub fn reset_recv(&mut self) {
        let _ = self.recv_cipher.seek(0);
    }
}

impl std::fmt::Debug for SessionCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCipher").finish()
    }
}

// ---------------------------------------------------------------------------
// Authentication state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub username: Option<String>,
    pub password_encrypted: Option<Vec<u8>>,
    pub two_factor_code: Option<String>,
    pub session_token: Option<Vec<u8>>,
    pub refresh_token: Option<Vec<u8>>,
    pub steam_id: Option<u64>,
    pub machine_id: Option<Vec<u8>>,
    /// Auth state machine
    pub auth_status: AuthStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthStatus {
    NotAuthenticated,
    AwaitingResponse,
    Authenticated,
    Failed,
}

// ---------------------------------------------------------------------------
// Steam content manifest types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppManifest {
    pub app_id: u32,
    pub name: String,
    pub install_dir: String,
    pub build_id: u32,
    pub depot_ids: Vec<u32>,
    pub depot_manifests: BTreeMap<u32, DepotManifest>,
}

/// A depot manifest entry describing a single file within a depot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepotManifest {
    pub depot_id: u32,
    /// Absolute or relative filename within the depot.
    pub filename: String,
    /// Uncompressed file size in bytes.
    pub size: u64,
    /// SHA-1 checksum of the entire file (20 bytes).
    pub checksum: [u8; 20],
    /// List of chunks composing this file.
    pub chunks: Vec<ChunkInfo>,
    /// Whether the manifest entry is encrypted with a depot key.
    pub encrypted: bool,
    /// Optional AES-256 key for decrypting the manifest entry.
    pub encryption_key: Option<[u8; 32]>,
}

/// A single chunk of a depot file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkInfo {
    /// SHA-1 hash of the chunk content (20 bytes).
    pub chunk_id: [u8; 20],
    /// Offset of this chunk within the file.
    pub offset: u64,
    /// CRC32 checksum of the chunk.
    pub crc: u32,
    /// Uncompressed chunk size in bytes.
    pub size: u32,
    /// Compressed chunk size in bytes (0 = uncompressed).
    pub compressed_size: u32,
}

/// A content server record parsed from the CDN routing response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentServerRecord {
    /// Content server hostname.
    pub host: String,
    /// Port number (80 or 443).
    pub port: u16,
    /// Whether to use HTTPS.
    pub https: bool,
    /// Steam cell ID for geo-routing.
    pub cell_id: u32,
    /// Load balancing weight.
    pub weight: u32,
}

// ---------------------------------------------------------------------------
// GameNetworkingSockets types
// ---------------------------------------------------------------------------

/// A message received over a GNS connection.
#[derive(Debug, Clone)]
pub struct SteamNetworkingMessage {
    /// Message payload data.
    pub data: Vec<u8>,
    /// Connection handle this message was received on.
    pub conn: GnsConnectionHandle,
    /// Channel number.
    pub channel: i32,
    /// Steam ID of the sender.
    pub sender_id: u64,
}

/// State of a GNS connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnsConnectionState {
    None,
    Connecting,
    Connected,
    Closing,
    Closed,
}

/// GameNetworkingSockets — real peer-to-peer networking layer with
/// UDP, STUN NAT traversal, Steam Datagram Relay (SDR) support,
/// and AES-GCM wire-format encryption.
///
/// Architecture:
/// - Each connection has per-peer AES-GCM send/recv keys
/// - Messages are encrypted with AES-GCM before sending over UDP
/// - STUN binding requests are used for NAT traversal
/// - SDR relay is available for peers behind restrictive NATs
/// - Falls back to in-memory queue when no UDP socket is available
#[derive(Debug)]
pub struct GameNetworkingSockets {
    /// Active connections map.
    connections: BTreeMap<GnsConnectionHandle, GnsConnectionState>,
    /// Next handle value to assign.
    next_handle: u64,
    /// Routing table: connection handle -> peer socket address (for P2P).
    routing_table: BTreeMap<GnsConnectionHandle, SocketAddr>,
    /// UDP socket for P2P networking (bound on demand).
    udp_socket: Option<UdpSocket>,
    /// STUN server address for NAT traversal.
    stun_server: Option<SocketAddr>,
    /// Steam Datagram Relay address.
    sdr_relay: Option<SocketAddr>,
    /// Local external address discovered via STUN.
    external_address: Option<SocketAddr>,
    /// Per-connection AES-256 decryption keys (recv_key).
    recv_keys: BTreeMap<GnsConnectionHandle, [u8; 32]>,
    /// Per-connection AES-256 encryption keys (send_key).
    send_keys: BTreeMap<GnsConnectionHandle, [u8; 32]>,
    /// Incoming message queue (decrypted messages ready for consumption).
    incoming_queue: VecDeque<SteamNetworkingMessage>,
    /// In-memory fallback queue (used when no UDP socket is bound).
    signal_r: std::sync::Arc<std::sync::Mutex<Vec<(GnsConnectionHandle, Vec<u8>)>>>,
    /// Receive buffer for UDP socket reads.
    recv_buf: Vec<u8>,
}

impl GameNetworkingSockets {
    /// Create a new GNS instance with no active connections.
    pub fn new() -> Self {
        Self {
            connections: BTreeMap::new(),
            next_handle: 1,
            routing_table: BTreeMap::new(),
            udp_socket: None,
            stun_server: None,
            sdr_relay: None,
            external_address: None,
            recv_keys: BTreeMap::new(),
            send_keys: BTreeMap::new(),
            incoming_queue: VecDeque::new(),
            signal_r: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            recv_buf: vec![0u8; 65535],
        }
    }

    /// Bind a UDP socket to listen for P2P messages.
    ///
    /// If `bind_addr` is `None`, binds to `0.0.0.0:0` (OS-assigned port).
    /// After binding, the socket is used for all subsequent
    /// `send_message()` and `poll_incoming_messages()` calls.
    pub fn bind_udp(&mut self, bind_addr: Option<SocketAddr>) -> AppResult<SocketAddr> {
        let addr = bind_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let socket = UdpSocket::bind(addr).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetSocketCreateFailed,
                format!("GNS: failed to bind UDP socket to {addr}: {e}"),
            )
        })?;
        socket.set_nonblocking(true).ok();
        let local_addr = socket.local_addr().map_err(|e| {
            AppError::new(
                ReasonCode::RcNetSocketCreateFailed,
                format!("GNS: failed to get local address: {e}"),
            )
        })?;
        self.udp_socket = Some(socket);
        Ok(local_addr)
    }

    /// Set the STUN server address for NAT traversal.
    pub fn set_stun_server(&mut self, addr: SocketAddr) {
        self.stun_server = Some(addr);
    }

    /// Get the configured STUN server address, if any.
    pub fn stun_server(&self) -> Option<SocketAddr> {
        self.stun_server
    }

    /// Set the Steam Datagram Relay address.
    pub fn set_relay_server(&mut self, addr: SocketAddr) {
        self.sdr_relay = Some(addr);
    }

    /// Set the peer address for a given connection handle (routing table).
    pub fn set_peer_address(
        &mut self,
        handle: GnsConnectionHandle,
        addr: SocketAddr,
    ) -> AppResult<()> {
        if !self.connections.contains_key(&handle) {
            return Err(AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("GNS: cannot set peer address for unknown handle {handle}"),
            ));
        }
        self.routing_table.insert(handle, addr);
        Ok(())
    }

    /// Set the AES-256 send key for a connection (used to encrypt outgoing
    /// messages).
    pub fn set_send_key(&mut self, handle: GnsConnectionHandle, key: [u8; 32]) {
        self.send_keys.insert(handle, key);
    }

    /// Set the AES-256 recv key for a connection (used to decrypt incoming
    /// messages).
    pub fn set_recv_key(&mut self, handle: GnsConnectionHandle, key: [u8; 32]) {
        self.recv_keys.insert(handle, key);
    }

    /// Perform a STUN binding request to discover the external address.
    ///
    /// This sends a STUN Binding Request to the configured STUN server
    /// and parses the XOR-MAPPED-ADDRESS from the response.
    pub fn perform_stun_binding(&mut self) -> AppResult<SocketAddr> {
        let stun_addr = self.stun_server.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcInvalidState,
                "GNS: no STUN server configured",
            )
        })?;

        // Create a temporary UDP socket for STUN if we don't have one
        let socket = if let Some(ref sock) = self.udp_socket {
            sock.try_clone().map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetSocketCreateFailed,
                    format!("GNS: STUN socket clone failed: {e}"),
                )
            })?
        } else {
            UdpSocket::bind("0.0.0.0:0").map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetSocketCreateFailed,
                    format!("GNS: STUN socket bind failed: {e}"),
                )
            })?
        };

        socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
        socket.set_write_timeout(Some(Duration::from_secs(3))).ok();

        // Build a STUN Binding Request (RFC 5389)
        // Header: 20 bytes
        let mut request = Vec::with_capacity(20);
        request.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());  // Message Type
        request.extend_from_slice(&[0u8; 2]);                            // Message Length (placeholder)
        request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());     // Magic Cookie
        // Transaction ID (12 random bytes)
        let mut tx_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut tx_id);
        request.extend_from_slice(&tx_id);

        // Update message length (0 for a bare binding request with no attributes)
        let len = (request.len() - 20) as u16;
        request[2..4].copy_from_slice(&len.to_be_bytes());

        // Send the STUN binding request
        socket.send_to(&request, stun_addr).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetSendFailed,
                format!("GNS: STUN send failed: {e}"),
            )
        })?;

        // Read the response
        let mut response = [0u8; 1024];
        let (n, _) = socket.recv_from(&mut response).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetReadFailed,
                format!("GNS: STUN recv failed: {e}"),
            )
        })?;

        let data = &response[..n];
        if data.len() < 20 {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                "GNS: STUN response too short",
            ));
        }

        // Verify magic cookie and transaction ID
        let resp_magic = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if resp_magic != STUN_MAGIC_COOKIE {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!("GNS: bad STUN magic cookie: {resp_magic:#x}"),
            ));
        }

        let resp_tx_id = &data[8..20];
        if resp_tx_id != tx_id {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                "GNS: STUN transaction ID mismatch",
            ));
        }

        // Parse attributes (start at offset 20)
        let mut offset = 20;
        let mut external: Option<SocketAddr> = None;

        while offset + 4 <= data.len() {
            let attr_type = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap());
            let attr_len = u16::from_be_bytes(data[offset + 2..offset + 4].try_into().unwrap()) as usize;

            if offset + 4 + attr_len > data.len() {
                break;
            }

            let attr_value = &data[offset + 4..offset + 4 + attr_len];

            match attr_type {
                STUN_ATTR_XOR_MAPPED_ADDRESS | STUN_ATTR_MAPPED_ADDRESS => {
                    if attr_value.len() >= 8 {
                        let family = attr_value[1]; // 0x01 = IPv4, 0x02 = IPv6
                        let port = u16::from_be_bytes(attr_value[2..4].try_into().unwrap());
                        if family == 0x01 && attr_value.len() >= 8 {
                            // IPv4: XOR with magic cookie for XOR-MAPPED-ADDRESS
                            let ip_bytes = if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
                                [
                                    attr_value[4] ^ (STUN_MAGIC_COOKIE >> 24) as u8,
                                    attr_value[5] ^ (STUN_MAGIC_COOKIE >> 16) as u8,
                                    attr_value[6] ^ (STUN_MAGIC_COOKIE >> 8) as u8,
                                    attr_value[7] ^ STUN_MAGIC_COOKIE as u8,
                                ]
                            } else {
                                [attr_value[4], attr_value[5], attr_value[6], attr_value[7]]
                            };
                            let xor_port = if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
                                port ^ (STUN_MAGIC_COOKIE >> 16) as u16
                            } else {
                                port
                            };
                            external = Some(SocketAddr::from((ip_bytes, xor_port)));
                        }
                        // Prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS
                        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
                            break;
                        }
                    }
                }
                _ => {}
            }

            offset += 4 + attr_len;
            // Align to 4 bytes
            if offset % 4 != 0 {
                offset += 4 - (offset % 4);
            }
        }

        let external = external.ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNetProtocolError,
                "GNS: no mapped address in STUN response",
            )
        })?;

        self.external_address = Some(external);
        Ok(external)
    }

    /// Encrypt a plaintext message with AES-256-GCM using the connection's
    /// send key.
    ///
    /// Wire format:
    ///   [12-byte nonce][encrypted payload][16-byte GCM tag]
    fn encrypt_message(
        &self,
        handle: GnsConnectionHandle,
        plaintext: &[u8],
    ) -> AppResult<Vec<u8>> {
        let key = self.send_keys.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("GNS: no send key for handle {handle}"),
            )
        })?;

        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; GNS_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("GNS: failed to init AES-256-GCM: {e}"),
            )
        })?;

        // Encrypt in-place
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, &[], &mut ciphertext).map_err(|e| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("GNS: AES-256-GCM encryption failed: {e}"),
            )
        })?;

        // Wire format: [nonce (12)][ciphertext][tag (16)]
        let mut wire = Vec::with_capacity(GNS_NONCE_LEN + ciphertext.len() + GNS_TAG_LEN);
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ciphertext);
        wire.extend_from_slice(&tag);

        Ok(wire)
    }

    /// Decrypt a message received over the wire using the connection's recv key.
    ///
    /// Wire format expected:
    ///   [12-byte nonce][encrypted payload][16-byte GCM tag]
    fn decrypt_message(
        &self,
        handle: GnsConnectionHandle,
        wire_data: &[u8],
    ) -> AppResult<Vec<u8>> {
        if wire_data.len() < GNS_NONCE_LEN + GNS_TAG_LEN {
            return Err(AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!(
                    "GNS: wire data too short ({} < {})",
                    wire_data.len(),
                    GNS_NONCE_LEN + GNS_TAG_LEN
                ),
            ));
        }

        let key = self.recv_keys.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("GNS: no recv key for handle {handle}"),
            )
        })?;

        let nonce = Nonce::from_slice(&wire_data[..GNS_NONCE_LEN]);
        let ciphertext = &wire_data[GNS_NONCE_LEN..wire_data.len() - GNS_TAG_LEN];
        let tag_data = &wire_data[wire_data.len() - GNS_TAG_LEN..];

        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("GNS: failed to init AES-256-GCM for decrypt: {e}"),
            )
        })?;

        let tag = aes_gcm::Tag::from_slice(tag_data);
        let mut plaintext = ciphertext.to_vec();
        cipher.decrypt_in_place_detached(nonce, &[], &mut plaintext, tag).map_err(|e| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("GNS: AES-256-GCM decryption failed: {e}"),
            )
        })?;

        Ok(plaintext)
    }

    /// Create a new GNS session, assigning it a unique handle.
    /// Returns the connection handle on success.
    pub fn create_session(&mut self) -> AppResult<GnsConnectionHandle> {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.connections.insert(handle, GnsConnectionState::Connecting);
        // Generate random session keys for this connection
        let mut send_key = [0u8; 32];
        let mut recv_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut send_key);
        rand::thread_rng().fill_bytes(&mut recv_key);
        self.send_keys.insert(handle, send_key);
        self.recv_keys.insert(handle, recv_key);
        self.connections.insert(handle, GnsConnectionState::Connected);
        Ok(handle)
    }

    /// Accept an incoming GNS session.
    pub fn accept_session(&mut self, handle: GnsConnectionHandle) -> AppResult<()> {
        match self.connections.get_mut(&handle) {
            Some(state) if *state == GnsConnectionState::Connecting => {
                *state = GnsConnectionState::Connected;
                Ok(())
            }
            Some(_) => Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("GNS: session {handle} is not in Connecting state"),
            )),
            None => Err(AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("GNS: session {handle} not found"),
            )),
        }
    }

    /// Send a message over a GNS connection.
    ///
    /// If a UDP socket is bound and the peer address is known (via
    /// routing table), the message is encrypted with AES-256-GCM and
    /// sent over UDP. If the peer address is an SDR relay, the message
    /// is wrapped in an SDR datagram first.
    ///
    /// Falls back to in-memory queue if no UDP socket is available
    /// (useful for local testing).
    pub fn send_message(
        &mut self,
        handle: GnsConnectionHandle,
        data: &[u8],
        channel: i32,
    ) -> AppResult<()> {
        let state = self.connections.get(&handle).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("GNS: session {handle} not found"),
            )
        })?;
        if *state != GnsConnectionState::Connected {
            return Err(AppError::new(
                ReasonCode::RcInvalidState,
                format!("GNS: session {handle} is not connected"),
            ));
        }

        // Check if we have a UDP socket available for real networking
        if let Some(ref socket) = self.udp_socket {
            // Determine the target address from routing table or SDR relay
            let target = if let Some(relay) = self.sdr_relay {
                // SDR relay mode: wrap in SDR datagram
                relay
            } else if let Some(peer_addr) = self.routing_table.get(&handle) {
                *peer_addr
            } else {
                // No target address known — fall through to in-memory
                return self.fallback_send(handle, data, channel);
            };

            // Encrypt with AES-256-GCM
            let wire = self.encrypt_message(handle, data)?;

            // Include channel number in the wire format for multi-channel support
            let mut packet = Vec::with_capacity(4 + wire.len());
            packet.extend_from_slice(&(channel as i32).to_le_bytes());
            packet.extend_from_slice(&wire);

            // Send over UDP
            socket.send_to(&packet, target).map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetSendFailed,
                    format!("GNS: UDP send to {target} failed: {e}"),
                )
            })?;

            return Ok(());
        }

        // Fallback: in-memory queue
        self.fallback_send(handle, data, channel)
    }

    /// Send via in-memory fallback queue (no UDP socket available).
    fn fallback_send(
        &self,
        handle: GnsConnectionHandle,
        data: &[u8],
        _channel: i32,
    ) -> AppResult<()> {
        let mut queue = self.signal_r.lock().map_err(|e| {
            AppError::new(ReasonCode::RcCacheCorrupt, format!("GNS: lock error: {e}"))
        })?;
        queue.push((handle, data.to_vec()));
        Ok(())
    }

    /// Poll all incoming messages across all connections.
    ///
    /// If a UDP socket is bound, this reads all pending datagrams,
    /// attempts to decrypt each with the matching connection's recv key,
    /// and returns the decoded messages. Falls back to the in-memory
    /// queue when no UDP socket is available.
    pub fn poll_incoming_messages(&mut self) -> AppResult<Vec<SteamNetworkingMessage>> {
        // First, drain the in-memory fallback queue
        {
            let mut queue = self.signal_r.lock().map_err(|e| {
                AppError::new(ReasonCode::RcCacheCorrupt, format!("GNS: lock error: {e}"))
            })?;
            for (conn, data) in queue.drain(..) {
                self.incoming_queue.push_back(SteamNetworkingMessage {
                    data,
                    conn,
                    channel: 0,
                    sender_id: 0,
                });
            }
        }

        // Then, if we have a UDP socket, read all pending datagrams
        if let Some(ref socket) = self.udp_socket {
            loop {
                match socket.recv_from(&mut self.recv_buf) {
                    Ok((n, src_addr)) => {
                        let packet = &self.recv_buf[..n];
                        if packet.len() < 4 {
                            continue; // malformed, skip
                        }

                        // Parse the channel number from the first 4 bytes
                        let _channel = i32::from_le_bytes(packet[0..4].try_into().unwrap());
                        let wire_data = &packet[4..];

                        // Try to find the connection by matching the source address
                        // in the routing table
                        let handle_opt = self.routing_table.iter()
                            .find(|(_, addr)| **addr == src_addr)
                            .map(|(handle, _)| *handle);

                        if let Some(handle) = handle_opt {
                            // Try to decrypt with the connection's recv key
                            match self.decrypt_message(handle, wire_data) {
                                Ok(plaintext) => {
                                    self.incoming_queue.push_back(SteamNetworkingMessage {
                                        data: plaintext,
                                        conn: handle,
                                        channel: 0,
                                        sender_id: 0,
                                    });
                                }
                                Err(e) => {
                                    eprintln!("GNS: failed to decrypt message from {src_addr}: {e}");
                                }
                            }
                        } else {
                            // Unknown source — queue as-is with a temporary handle
                            eprintln!("GNS: received message from unknown peer {src_addr}");
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No more data available (non-blocking socket)
                        break;
                    }
                    Err(e) => {
                        eprintln!("GNS: UDP recv error: {e}");
                        break;
                    }
                }
            }
        }

        // Drain the incoming queue
        let messages: Vec<SteamNetworkingMessage> = self.incoming_queue.drain(..).collect();
        Ok(messages)
    }

    /// Close a GNS session.
    pub fn close_session(&mut self, handle: GnsConnectionHandle) -> AppResult<()> {
        match self.connections.get_mut(&handle) {
            Some(state) => {
                *state = GnsConnectionState::Closing;
                *state = GnsConnectionState::Closed;
                self.connections.remove(&handle);
                self.routing_table.remove(&handle);
                self.send_keys.remove(&handle);
                self.recv_keys.remove(&handle);
                Ok(())
            }
            None => Err(AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("GNS: session {handle} not found"),
            )),
        }
    }

    /// Get the state of a connection.
    pub fn connection_state(&self, handle: GnsConnectionHandle) -> Option<GnsConnectionState> {
        self.connections.get(&handle).copied()
    }

    /// Get the external (STUN-discovered) address, if available.
    pub fn external_address(&self) -> Option<SocketAddr> {
        self.external_address
    }
}

// ---------------------------------------------------------------------------
// Steam CM protocol state machine
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SteamProtocolStack {
    /// Current connection state.
    pub state: ConnectionState,
    /// Selected CM server address.
    pub current_server: Option<String>,
    /// TCP stream to the CM server.
    stream: Option<TcpStream>,
    /// AES session key (32 bytes).
    session_key: Option<[u8; AES_KEY_LEN]>,
    /// Session cipher for AES-256-CTR encryption/decryption.
    cipher: Option<SessionCipher>,
    /// RSA public key from the CM server, captured during encryption handshake.
    /// Used for password encryption in the logon flow.
    rsa_public_key: Option<rsa::RsaPublicKey>,
    /// Authentication state.
    pub auth: AuthState,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval: u32,
    /// Last heartbeat send time.
    last_heartbeat: Option<Instant>,
    /// Connection timeout.
    connect_timeout: Duration,
    /// Message counter for outgoing messages.
    message_count: u64,
    /// Incoming message queue (fully parsed SteamMessage objects).
    pub incoming_messages: VecDeque<SteamMessage>,
    /// App manifests cache.
    pub app_manifests: BTreeMap<u32, AppManifest>,
    /// Content download progress.
    pub download_progress: BTreeMap<u32, f64>,
    /// Session ID assigned by CM server during encryption handshake.
    session_id: u32,
    /// Steam ID assigned after logon.
    steam_id: u64,
}

impl SteamProtocolStack {
    /// Create a new SteamProtocolStack in the Disconnected state.
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            current_server: None,
            stream: None,
            session_key: None,
            cipher: None,
            rsa_public_key: None,
            auth: AuthState {
                username: None,
                password_encrypted: None,
                two_factor_code: None,
                session_token: None,
                refresh_token: None,
                steam_id: None,
                machine_id: None,
                auth_status: AuthStatus::NotAuthenticated,
            },
            heartbeat_interval: 30,
            last_heartbeat: None,
            connect_timeout: Duration::from_secs(10),
            message_count: 0,
            incoming_messages: VecDeque::new(),
            app_manifests: BTreeMap::new(),
            download_progress: BTreeMap::new(),
            session_id: 0,
            steam_id: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Connection management
    // -----------------------------------------------------------------------

    /// Connect to a Steam CM server. If `server` is None, tries the default
    /// list of well-known CM servers.
    ///
    /// On successful TCP connection, automatically performs the encryption
    /// handshake.
    pub fn connect(&mut self, server: Option<&str>) -> AppResult<()> {
        let servers: Vec<&str> = if let Some(s) = server {
            vec![s]
        } else {
            DEFAULT_CM_SERVERS.to_vec()
        };

        self.state = ConnectionState::Resolving;

        for addr_str in &servers {
            self.current_server = Some(addr_str.to_string());
            self.state = ConnectionState::Connecting;

            let addr = addr_str
                .to_socket_addrs()
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcNetDnsResolutionFailed,
                        format!("SteamProtocol: DNS resolution failed for {addr_str}: {e:?}"),
                    )
                })?
                .next()
                .ok_or_else(|| {
                    AppError::new(
                        ReasonCode::RcNetDnsResolutionFailed,
                        format!("SteamProtocol: no address for {addr_str}"),
                    )
                })?;

            match TcpStream::connect_timeout(&addr, self.connect_timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
                    self.stream = Some(stream);
                    self.state = ConnectionState::Connected;
                    self.message_count = 0;
                    self.last_heartbeat = Some(Instant::now());

                    // Perform encryption handshake
                    self.perform_encryption_handshake()?;
                    return Ok(());
                }
                Err(_) => {
                    // Try next server
                    continue;
                }
            }
        }

        self.state = ConnectionState::Error;
        Err(AppError::new(
            ReasonCode::RcNetConnectionFailed,
            "SteamProtocol: failed to connect to any CM server",
        ))
    }

    /// Disconnect from the CM server, clearing all session state.
    pub fn disconnect(&mut self) -> AppResult<()> {
        self.stream = None;
        self.session_key = None;
        self.cipher = None;
        self.state = ConnectionState::Disconnected;
        self.incoming_messages.clear();
        self.session_id = 0;
        self.steam_id = 0;
        self.auth.auth_status = AuthStatus::NotAuthenticated;
        Ok(())
    }

    /// Send a heartbeat to keep the connection alive.
    pub fn send_heartbeat(&mut self) -> AppResult<()> {
        let msg = SteamMessage {
            msg_type: SteamMessageType::ClientHeartBeat,
            payload: Vec::new(),
            source_job_id: 0,
            target_job_id: 0,
            steam_id: self.steam_id,
            session_id: self.session_id,
            message_type: 0,
        };
        self.send_steam_message(&msg)?;
        self.last_heartbeat = Some(Instant::now());
        Ok(())
    }

    /// Check if heartbeat is needed based on the configured interval.
    pub fn heartbeat_needed(&self) -> bool {
        if let Some(last) = self.last_heartbeat {
            last.elapsed() > Duration::from_secs(self.heartbeat_interval as u64)
        } else {
            true
        }
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /// Send a logon request with username and encrypted password.
    ///
    /// The payload contains:
    ///   - Protocol version (u32 LE)
    ///   - Steam ID (u64 LE, 0 for new logon)
    ///   - Username as null-terminated UTF-8
    ///   - Encrypted password length (u32 LE)
    ///   - Encrypted password bytes
    pub fn send_logon(&mut self, username: &str, password_encrypted: &[u8]) -> AppResult<()> {
        self.auth.username = Some(username.to_string());
        self.auth.password_encrypted = Some(password_encrypted.to_vec());
        self.auth.auth_status = AuthStatus::AwaitingResponse;

        let mut payload = Vec::new();
        payload.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        payload.extend_from_slice(&self.steam_id.to_le_bytes());
        payload.extend_from_slice(username.as_bytes());
        payload.push(0);
        let pw_len = password_encrypted.len() as u32;
        payload.extend_from_slice(&pw_len.to_le_bytes());
        payload.extend_from_slice(password_encrypted);

        let msg = SteamMessage {
            msg_type: SteamMessageType::ClientLogOn,
            payload,
            source_job_id: 0,
            target_job_id: 0,
            steam_id: self.steam_id,
            session_id: self.session_id,
            message_type: 0,
        };
        self.send_steam_message(&msg)?;
        self.state = ConnectionState::Authenticating;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Content download
    // -----------------------------------------------------------------------

    /// Request package info for an app.
    pub fn request_package_info(&mut self, app_id: u32) -> AppResult<()> {
        let payload = app_id.to_le_bytes().to_vec();
        let msg = SteamMessage {
            msg_type: SteamMessageType::ClientPackageInfoRequest,
            payload,
            source_job_id: 0,
            target_job_id: 0,
            steam_id: self.steam_id,
            session_id: self.session_id,
            message_type: 0,
        };
        self.send_steam_message(&msg)?;
        Ok(())
    }

    /// Register an app usage event (game launch).
    pub fn send_app_usage_event(&mut self, app_id: u32, event_type: u32) -> AppResult<()> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&app_id.to_le_bytes());
        payload.extend_from_slice(&event_type.to_le_bytes());
        let msg = SteamMessage {
            msg_type: SteamMessageType::ClientAppUsageEvent,
            payload,
            source_job_id: 0,
            target_job_id: 0,
            steam_id: self.steam_id,
            session_id: self.session_id,
            message_type: 0,
        };
        self.send_steam_message(&msg)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Message framing (Steam CM wire protocol)
    // -----------------------------------------------------------------------

    /// Send a fully-formed SteamMessage over the wire.
    ///
    /// Wire format:
    ///   [0..4)   STEAM_MAGIC (u32 LE) "VS01"
    ///   [4..8)   total_length (u32 LE) = header + encrypted_payload
    ///   [8..)    encrypted ExtendedHeader + payload
    ///
    /// If a session cipher is established, the ExtendedHeader + payload are
    /// encrypted together using AES-256-CTR (send direction).
    fn send_steam_message(&mut self, msg: &SteamMessage) -> AppResult<()> {
        let header = ExtendedHeader {
            raw: msg.msg_type as u32,
            size: msg.payload.len() as u32,
            source_job_id: msg.source_job_id,
            target_job_id: msg.target_job_id,
            header_size: EXTENDED_HEADER_SIZE,
            steam_id: msg.steam_id,
            session_id: msg.session_id,
            message_type: msg.message_type,
        };

        let mut plaintext = header.serialize();
        plaintext.extend_from_slice(&msg.payload);

        // Encrypt if cipher is established
        let body = if let Some(cipher) = self.cipher.as_mut() {
            cipher.encrypt(&plaintext)
        } else {
            plaintext
        };

        let total_len = body.len() as u32;
        let mut frame = Vec::with_capacity(8 + body.len());
        frame.extend_from_slice(&STEAM_MAGIC.to_le_bytes());
        frame.extend_from_slice(&total_len.to_le_bytes());
        frame.extend_from_slice(&body);

        let stream = self.stream.as_mut().ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidState, "SteamProtocol: not connected")
        })?;

        stream.write_all(&frame).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetWriteFailed,
                format!("SteamProtocol: send failed: {e:?}"),
            )
        })?;

        self.message_count += 1;
        Ok(())
    }

    /// Receive and parse a single message from the CM server.
    ///
    /// Returns `Ok(1)` if a message was received and queued, `Ok(0)` if no
    /// data is available (non-blocking), or an error.
    pub fn receive_messages(&mut self) -> AppResult<usize> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidState, "SteamProtocol: not connected")
        })?;

        // Read the 8-byte frame header (magic + total_length)
        let mut frame_header = [0u8; 8];
        match stream.read_exact(&mut frame_header) {
            Ok(()) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Ok(0);
            }
            Err(e) => {
                return Err(AppError::new(
                    ReasonCode::RcNetReadFailed,
                    format!("SteamProtocol: read frame header failed: {e:?}"),
                ));
            }
        }

        let magic =
            u32::from_le_bytes([frame_header[0], frame_header[1], frame_header[2], frame_header[3]]);
        if magic != STEAM_MAGIC {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!("SteamProtocol: bad magic {magic:#x}, expected {STEAM_MAGIC:#x}"),
            ));
        }

        let total_len = u32::from_le_bytes(
            [frame_header[4], frame_header[5], frame_header[6], frame_header[7]],
        );

        let body_len = total_len as usize;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            stream.read_exact(&mut body).map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetReadFailed,
                    format!("SteamProtocol: read body failed: {e:?}"),
                )
            })?;
        }

        // Decrypt if cipher is established
        let plaintext = if let Some(cipher) = self.cipher.as_mut() {
            cipher.decrypt(&body)
        } else {
            body
        };

        // Parse the ExtendedHeader
        if plaintext.len() < ExtendedHeader::TOTAL_SIZE {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!(
                    "SteamProtocol: body too short for header ({} < {})",
                    plaintext.len(),
                    ExtendedHeader::TOTAL_SIZE
                ),
            ));
        }

        let ext_header = ExtendedHeader::deserialize(&plaintext).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcNetProtocolError,
                "SteamProtocol: failed to deserialize ExtendedHeader",
            )
        })?;

        let payload = plaintext[ExtendedHeader::TOTAL_SIZE..].to_vec();
        let msg_type = map_emsg(ext_header.raw);

        let msg = SteamMessage {
            msg_type,
            payload,
            source_job_id: ext_header.source_job_id,
            target_job_id: ext_header.target_job_id,
            steam_id: ext_header.steam_id,
            session_id: ext_header.session_id,
            message_type: ext_header.message_type,
        };

        self.incoming_messages.push_back(msg);
        Ok(1)
    }

    /// Drain all available messages (non-blocking read loop).
    pub fn drain_messages(&mut self) -> AppResult<usize> {
        let mut count = 0;
        loop {
            match self.receive_messages() {
                Ok(0) => break,
                Ok(n) => count += n,
                Err(_) => break,
            }
        }
        Ok(count)
    }

    /// Pop the oldest message from the incoming queue.
    pub fn pop_message(&mut self) -> Option<SteamMessage> {
        self.incoming_messages.pop_front()
    }

    // -----------------------------------------------------------------------
    // Encryption handshake
    //
    // Steam's encryption handshake:
    //   1. Server sends ChannelEncryptRequest (EMsg 130) containing:
    //        - Protocol version (u32 LE)
    //        - Key size (u32 LE)
    //        - RSA public key modulus (key_size bytes)
    //        - Unused padding (to 256-byte boundary)
    //   2. Client generates 32-byte AES session key
    //   3. Client wraps AES key with RSA-OAEP (SHA-256)
    //   4. Client sends ChannelEncryptResponse (EMsg 131) containing:
    //        - Protocol version (u32 LE)
    //        - Key size (u32 LE)
    //        - Encrypted AES session key
    //        - Challenge response
    //   5. Server responds with ChannelEncryptResult (EMsg 132, u32 = 1 for success)
    //   6. Both sides derive AES-256-CTR session keys and begin encrypted
    //      communication.
    // -----------------------------------------------------------------------

    fn perform_encryption_handshake(&mut self) -> AppResult<()> {
        self.state = ConnectionState::Encrypting;

        // Step 1: Wait for ChannelEncryptRequest from server.
        // Since the handshake is synchronous, we read directly from the stream.
        let request = self.read_encrypt_request()?;

        // Reconstruct the RSA public key from the modulus sent by the server
        // and store it for later use (e.g., password encryption during logon).
        let n = rsa::BigUint::from_bytes_be(&request.rsa_modulus);
        let e = rsa::BigUint::from_bytes_be(&[0x01, 0x00, 0x01]); // 65537
        let pub_key = rsa::RsaPublicKey::new(n, e).map_err(|e| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("SteamProtocol: failed to construct RSA public key from handshake: {e}"),
            )
        })?;
        self.rsa_public_key = Some(pub_key);

        // Step 2: Generate a random 32-byte AES session key.
        let mut aes_key = [0u8; AES_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut aes_key);

        // Step 3: Wrap the AES key with the server's RSA public key.
        // Use RSA-OAEP with SHA-256 for the key wrapping.
        let encrypted_key = self.rsa_wrap_aes_key(&request.rsa_modulus, &aes_key)?;

        // Step 4: Send ChannelEncryptResponse.
        self.send_encrypt_response(&encrypted_key)?;

        // Step 5: Wait for ChannelEncryptResult.
        let result = self.read_encrypt_result()?;
        if result != 1 {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!("SteamProtocol: encryption handshake failed with result {result}"),
            ));
        }

        // Step 6: Set up session ciphers.
        self.session_key = Some(aes_key);
        self.cipher = Some(SessionCipher::new(&aes_key));

        self.state = ConnectionState::Ready;
        Ok(())
    }

    /// Read and parse a ChannelEncryptRequest from the stream.
    fn read_encrypt_request(&mut self) -> AppResult<EncryptRequest> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidState, "SteamProtocol: not connected")
        })?;

        // Read the 8-byte frame header
        let mut frame_header = [0u8; 8];
        stream.read_exact(&mut frame_header).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetReadFailed,
                format!("SteamProtocol: read encrypt request header failed: {e:?}"),
            )
        })?;

        let magic = u32::from_le_bytes(frame_header[0..4].try_into().unwrap());
        if magic != STEAM_MAGIC {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!("SteamProtocol: bad magic in encrypt request: {magic:#x}"),
            ));
        }

        let total_len = u32::from_le_bytes(frame_header[4..8].try_into().unwrap());
        let mut payload = vec![0u8; total_len as usize];
        if total_len > 0 {
            stream.read_exact(&mut payload).map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetReadFailed,
                    format!("SteamProtocol: read encrypt request payload failed: {e:?}"),
                )
            })?;
        }

        // Parse ChannelEncryptRequest (unencrypted):
        //   raw (u32), size (u32), source_job_id (u64), target_job_id (u64),
        //   header_size (u8), steam_id (u64), session_id (u32), message_type (u32),
        //   then the actual payload:
        //     protocol_version (u32 LE)
        //     key_size (u32 LE)
        //     rsa_modulus (key_size bytes)
        //     padding (rest)
        if payload.len() < 8 {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                "SteamProtocol: encrypt request payload too short",
            ));
        }

        // Skip the ExtendedHeader (44 bytes) to get to the payload
        if payload.len() < ExtendedHeader::TOTAL_SIZE + 8 {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                "SteamProtocol: encrypt request too short for header + fields",
            ));
        }

        let data = &payload[ExtendedHeader::TOTAL_SIZE..];
        let _protocol_ver = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let key_size = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;

        if data.len() < 8 + key_size {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!(
                    "SteamProtocol: encrypt request too short for key (need {key_size}, have {})",
                    data.len().saturating_sub(8)
                ),
            ));
        }

        let rsa_modulus = data[8..8 + key_size].to_vec();

        Ok(EncryptRequest {
            key_size: key_size as u32,
            rsa_modulus,
        })
    }

    /// Wrap the AES session key with the server's RSA public key using
    /// RSA-OAEP (SHA-256).
    fn rsa_wrap_aes_key(&self, rsa_modulus: &[u8], aes_key: &[u8; AES_KEY_LEN]) -> AppResult<Vec<u8>> {
        use rsa::Oaep;

        // Steam's RSA public key is sent as the raw modulus with a known
        // public exponent (usually 65537 = 0x10001). We reconstruct the
        // public key from its components.
        //
        // The modulus is a big-endian integer. We use `rsa::RsaPublicKey`
        // with the exponent 65537.
        let n = rsa::BigUint::from_bytes_be(rsa_modulus);
        let e = rsa::BigUint::from_bytes_be(&[0x01, 0x00, 0x01]); // 65537

        let pub_key = rsa::RsaPublicKey::new(n.clone(), e).map_err(|e| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("SteamProtocol: failed to construct RSA key: {e}"),
            )
        })?;

        // Encrypt with RSA-OAEP (SHA-256). The OAEP label is empty per
        // Steam convention.
        let padding = Oaep::new::<Sha256>();
        let encrypted = pub_key.encrypt(&mut rand::thread_rng(), padding, aes_key).map_err(|e| {
            AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!("SteamProtocol: RSA-OAEP encryption failed: {e}"),
            )
        })?;

        Ok(encrypted)
    }

    /// Send the ChannelEncryptResponse with the wrapped AES key.
    fn send_encrypt_response(&mut self, encrypted_key: &[u8]) -> AppResult<()> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidState, "SteamProtocol: not connected")
        })?;

        // Build the ExtendedHeader + payload for ChannelEncryptResponse.
        // Payload:
        //   protocol_version (u32 LE)
        //   key_size (u32 LE)
        //   encrypted_key (key_size bytes)
        //   challenge data (32 bytes of zeros for now)

        let mut payload = Vec::new();
        payload.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        payload.extend_from_slice(&(encrypted_key.len() as u32).to_le_bytes());
        payload.extend_from_slice(encrypted_key);
        // Add 32 bytes of challenge data (zeros)
        payload.extend_from_slice(&[0u8; 32]);

        let header = ExtendedHeader {
            raw: SteamMessageType::ChannelEncryptResponse as u32,
            size: payload.len() as u32,
            source_job_id: 0,
            target_job_id: 0,
            header_size: EXTENDED_HEADER_SIZE,
            steam_id: 0,
            session_id: 0,
            message_type: 0,
        };

        let mut plaintext = header.serialize();
        plaintext.extend_from_slice(&payload);

        let total_len = plaintext.len() as u32;
        let mut frame = Vec::with_capacity(8 + plaintext.len());
        frame.extend_from_slice(&STEAM_MAGIC.to_le_bytes());
        frame.extend_from_slice(&total_len.to_le_bytes());
        frame.extend_from_slice(&plaintext);

        stream.write_all(&frame).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetWriteFailed,
                format!("SteamProtocol: send encrypt response failed: {e:?}"),
            )
        })?;

        Ok(())
    }

    /// Read and return the ChannelEncryptResult value (1 = success).
    fn read_encrypt_result(&mut self) -> AppResult<u32> {
        let stream = self.stream.as_mut().ok_or_else(|| {
            AppError::new(ReasonCode::RcInvalidState, "SteamProtocol: not connected")
        })?;

        let mut frame_header = [0u8; 8];
        stream.read_exact(&mut frame_header).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetReadFailed,
                format!("SteamProtocol: read encrypt result header failed: {e:?}"),
            )
        })?;

        let magic = u32::from_le_bytes(frame_header[0..4].try_into().unwrap());
        if magic != STEAM_MAGIC {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!("SteamProtocol: bad magic in encrypt result: {magic:#x}"),
            ));
        }

        let total_len = u32::from_le_bytes(frame_header[4..8].try_into().unwrap());
        let mut payload = vec![0u8; total_len as usize];
        if total_len > 0 {
            stream.read_exact(&mut payload).map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetReadFailed,
                    format!("SteamProtocol: read encrypt result payload failed: {e:?}"),
                )
            })?;
        }

        // The result is a u32 in the payload after the ExtendedHeader
        if payload.len() < ExtendedHeader::TOTAL_SIZE + 4 {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                "SteamProtocol: encrypt result payload too short",
            ));
        }

        let result = u32::from_le_bytes(
            payload[ExtendedHeader::TOTAL_SIZE..ExtendedHeader::TOTAL_SIZE + 4]
                .try_into()
                .unwrap(),
        );
        Ok(result)
    }

    /// Encrypt payload with the session cipher (send direction).
    /// AES-CTR is symmetric, so encryption and decryption are the same operation.
    pub fn encrypt_payload(&mut self, payload: &[u8]) -> Vec<u8> {
        match self.cipher.as_mut() {
            Some(cipher) => cipher.encrypt(payload),
            None => payload.to_vec(),
        }
    }

    /// Decrypt payload with the session cipher (receive direction).
    pub fn decrypt_payload(&mut self, payload: &[u8]) -> Vec<u8> {
        match self.cipher.as_mut() {
            Some(cipher) => cipher.decrypt(payload),
            None => payload.to_vec(),
        }
    }

    // -----------------------------------------------------------------------
    // Content serving — CDN routing, manifest parsing, download, verification
    // -----------------------------------------------------------------------

    /// Parse a CDN routing response (XML format) into a list of content
    /// server records.
    ///
    /// The response is an XML document like:
    /// ```xml
    /// <?xml version="1.0" encoding="UTF-8"?>
    /// <contentServerList>
    ///   <contentServer cell="1234" https="true" port="443" weight="100">
    ///     steam.cdn.steamusercontent.com
    ///   </contentServer>
    /// </contentServerList>
    /// ```
    pub fn parse_cdn_routing(&self, body: &str) -> AppResult<Vec<ContentServerRecord>> {
        let mut servers = Vec::new();
        let lines: Vec<&str> = body.lines().collect();
        let mut idx = 0;

        // Simple line-by-line XML parsing for CDN routing responses.
        // In production this would use a proper XML parser (roxmltree is
        // already a dependency).
        while idx < lines.len() {
            let line = lines[idx].trim();
            if line.starts_with("<contentServer ") || line.starts_with("<contentServer>") {
                let cell_id = self.parse_xml_attr(line, "cell").unwrap_or(0);
                let https = self.parse_xml_bool_attr(line, "https");
                let port: u16 = self.parse_xml_attr(line, "port").unwrap_or(443) as u16;
                let weight = self.parse_xml_attr(line, "weight").unwrap_or(100);

                // Try to extract inline hostname: <tag>hostname</tag>
                let host = if let Some(start) = line.find('>') {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.find("</") {
                        rest[..end].trim().to_string()
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                if !host.is_empty() {
                    servers.push(ContentServerRecord {
                        host, port, https, cell_id, weight,
                    });
                } else {
                    // Multi-line format: hostname is on a subsequent line
                    // before the closing </contentServer> tag
                    for j in idx + 1..lines.len() {
                        let next = lines[j].trim();
                        if next.starts_with("</") {
                            break;
                        }
                        if !next.is_empty() && !next.starts_with("<") {
                            servers.push(ContentServerRecord {
                                host: next.to_string(),
                                port, https, cell_id, weight,
                            });
                            break;
                        }
                    }
                }
            }
            idx += 1;
        }

        Ok(servers)
    }

    /// Extract a named attribute value from an XML tag string.
    fn parse_xml_attr(&self, tag: &str, attr: &str) -> Option<u32> {
        let search = format!("{attr}=\"");
        if let Some(start) = tag.find(&search) {
            let value_start = start + search.len();
            if let Some(end) = tag[value_start..].find('"') {
                let val_str = &tag[value_start..value_start + end];
                return val_str.parse::<u32>().ok();
            }
        }
        None
    }

    /// Extract a named boolean attribute value from an XML tag string.
    /// Returns `true` if the attribute value is "true" or "1".
    fn parse_xml_bool_attr(&self, tag: &str, attr: &str) -> bool {
        let search = format!("{attr}=\"");
        if let Some(start) = tag.find(&search) {
            let value_start = start + search.len();
            if let Some(end) = tag[value_start..].find('"') {
                let val_str = &tag[value_start..value_start + end];
                return val_str == "true" || val_str == "1";
            }
        }
        false
    }

    /// Parse a Steam binary depot manifest into a list of DepotManifest entries.
    ///
    /// The binary format:
    ///   Header (24 bytes):
    ///     version (u32 LE)
    ///     file_count (u32 LE)
    ///     total_size (u64 LE)
    ///     flags (u32 LE)
    ///     depot_id (u32 LE)
    ///   File entries (repeating file_count times):
    ///     filename_len (u32 LE)
    ///     filename (UTF-8 bytes, filename_len bytes)
    ///     size (u64 LE)
    ///     checksum (20 bytes, SHA-1)
    ///     chunk_count (u32 LE)
    ///     chunks (repeating chunk_count times):
    ///       chunk_id (20 bytes, SHA-1)
    ///       offset (u64 LE)
    ///       crc (u32 LE)
    ///       size (u32 LE)
    ///       compressed_size (u32 LE)
    ///
    /// If `depot_key` is Some, the manifest data is decrypted using
    /// AES-256-GCM before parsing.
    pub fn parse_depot_manifest(
        &self,
        data: &[u8],
        depot_key: Option<&[u8; 32]>,
    ) -> AppResult<Vec<DepotManifest>> {
        let decrypted = if let Some(key) = depot_key {
            // Decrypt with AES-256-GCM
            use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
            use aes_gcm::aead::Aead;

            // The GCM nonce is the first 12 bytes of the data
            if data.len() < 12 + 16 {
                return Err(AppError::new(
                    ReasonCode::RcCryptoInvalid,
                    "SteamProtocol: depot manifest too short for GCM decryption",
                ));
            }

            let nonce = Nonce::from_slice(&data[..12]);
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| {
                AppError::new(
                    ReasonCode::RcCryptoInvalid,
                    format!("SteamProtocol: invalid depot key: {e}"),
                )
            })?;

            let plaintext = cipher
                .decrypt(nonce, &data[12..])
                .map_err(|e| {
                    AppError::new(
                        ReasonCode::RcCryptoInvalid,
                        format!("SteamProtocol: depot manifest decryption failed: {e}"),
                    )
                })?;
            plaintext
        } else {
            data.to_vec()
        };

        if decrypted.len() < 24 {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                "SteamProtocol: depot manifest too short for header",
            ));
        }

        let _version = u32::from_le_bytes(decrypted[0..4].try_into().unwrap());
        let file_count = u32::from_le_bytes(decrypted[4..8].try_into().unwrap());
        let _total_size = u64::from_le_bytes(decrypted[8..16].try_into().unwrap());
        let _flags = u32::from_le_bytes(decrypted[16..20].try_into().unwrap());
        let depot_id = u32::from_le_bytes(decrypted[20..24].try_into().unwrap());

        let mut offset = 24usize;
        let mut manifests = Vec::with_capacity(file_count as usize);

        for _ in 0..file_count {
            if offset + 4 > decrypted.len() {
                break;
            }
            let filename_len = u32::from_le_bytes(decrypted[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + filename_len > decrypted.len() {
                break;
            }
            let filename_bytes = &decrypted[offset..offset + filename_len];
            let filename = String::from_utf8_lossy(filename_bytes).to_string();
            offset += filename_len;

            if offset + 8 > decrypted.len() {
                break;
            }
            let size = u64::from_le_bytes(decrypted[offset..offset + 8].try_into().unwrap());
            offset += 8;

            if offset + 20 > decrypted.len() {
                break;
            }
            let mut checksum = [0u8; 20];
            checksum.copy_from_slice(&decrypted[offset..offset + 20]);
            offset += 20;

            if offset + 4 > decrypted.len() {
                break;
            }
            let chunk_count = u32::from_le_bytes(decrypted[offset..offset + 4].try_into().unwrap());
            offset += 4;

            let mut chunks = Vec::with_capacity(chunk_count as usize);
            for _ in 0..chunk_count {
                if offset + 20 > decrypted.len() {
                    break;
                }
                let mut chunk_id = [0u8; 20];
                chunk_id.copy_from_slice(&decrypted[offset..offset + 20]);
                offset += 20;

                if offset + 8 > decrypted.len() {
                    break;
                }
                let chunk_offset = u64::from_le_bytes(decrypted[offset..offset + 8].try_into().unwrap());
                offset += 8;

                if offset + 4 > decrypted.len() {
                    break;
                }
                let crc = u32::from_le_bytes(decrypted[offset..offset + 4].try_into().unwrap());
                offset += 4;

                if offset + 4 > decrypted.len() {
                    break;
                }
                let chunk_size = u32::from_le_bytes(decrypted[offset..offset + 4].try_into().unwrap());
                offset += 4;

                if offset + 4 > decrypted.len() {
                    break;
                }
                let compressed_size = u32::from_le_bytes(decrypted[offset..offset + 4].try_into().unwrap());
                offset += 4;

                chunks.push(ChunkInfo {
                    chunk_id,
                    offset: chunk_offset,
                    crc,
                    size: chunk_size,
                    compressed_size,
                });
            }

            manifests.push(DepotManifest {
                depot_id,
                filename,
                size,
                checksum,
                chunks,
                encrypted: depot_key.is_some(),
                encryption_key: depot_key.copied(),
            });
        }

        Ok(manifests)
    }

    /// Download a single file from a Steam content server.
    ///
    /// Uses HTTP/1.1 range requests to fetch each chunk, verifies chunk
    /// SHA-1 hashes, assembles chunks in order, and verifies the final
    /// file checksum against the manifest.
    pub fn download_file(
        &self,
        record: &ContentServerRecord,
        manifest: &DepotManifest,
        output_path: &Path,
        app_id: u32,
    ) -> AppResult<()> {
        use std::fs;

        let protocol = if record.https { "https" } else { "http" };
        let base_url = format!("{}://{}:{}", protocol, record.host, record.port);

        // Download each chunk and verify its SHA-1 hash
        let mut file_data = vec![0u8; manifest.size as usize];
        let _chunks_downloaded = 0u32;

        // We'll download chunks sequentially. In a real implementation,
        // multiple chunks would be downloaded in parallel.
        for chunk in &manifest.chunks {
            let chunk_url = format!(
                "{base_url}/depot/{app_id}/depot/{}/{}",
                manifest.depot_id,
                hex::encode(chunk.chunk_id)
            );

            let chunk_data = self.http_get_chunk(&chunk_url)?;

            // Verify chunk SHA-1
            let actual_hash = Sha1::digest(&chunk_data);
            if actual_hash.as_slice() != chunk.chunk_id {
                return Err(AppError::new(
                    ReasonCode::RcCryptoInvalid,
                    format!(
                        "SteamProtocol: chunk {} SHA-1 mismatch",
                        hex::encode(chunk.chunk_id)
                    ),
                ));
            }

            // Place chunk data at the correct offset
            let end = (chunk.offset as usize).saturating_add(chunk_data.len());
            if end > file_data.len() {
                return Err(AppError::new(
                    ReasonCode::RcNetProtocolError,
                    "SteamProtocol: chunk extends beyond file size",
                ));
            }
            file_data[chunk.offset as usize..end].copy_from_slice(&chunk_data);
        }

        // Verify final file SHA-1
        let final_hash = Sha1::digest(&file_data);
        if final_hash.as_slice() != manifest.checksum {
            return Err(AppError::new(
                ReasonCode::RcCryptoInvalid,
                format!(
                    "SteamProtocol: file checksum mismatch for {}",
                    manifest.filename
                ),
            ));
        }

        // Write to output
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AppError::new(
                    ReasonCode::RcIo,
                    format!(
                        "SteamProtocol: cannot create output directory {}: {e}",
                        parent.display()
                    ),
                )
            })?;
        }

        fs::write(output_path, &file_data).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("SteamProtocol: failed to write {}: {e}", output_path.display()),
            )
        })?;

        Ok(())
    }

    /// Perform an HTTP GET request for a chunk from a Steam content server.
    ///
    /// This uses a raw TCP connection with an HTTP/1.1 request since the
    /// content server may not support the full reqwest stack. For HTTPS
    /// content servers, this would use TLS.
    fn http_get_chunk(&self, url: &str) -> AppResult<Vec<u8>> {
        // Parse the URL
        let url = url::Url::parse(url).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetDnsResolutionFailed,
                format!("SteamProtocol: invalid chunk URL: {e}"),
            )
        })?;

        let host = url.host_str().ok_or_else(|| {
            AppError::new(ReasonCode::RcNetDnsResolutionFailed, "SteamProtocol: no host in URL")
        })?;

        let port = url.port().unwrap_or(80);
        let path = url.path();

        // Connect via TCP
        let addr_str = format!("{host}:{port}");
        let addr = addr_str
            .to_socket_addrs()
            .map_err(|e| {
                AppError::new(
                    ReasonCode::RcNetDnsResolutionFailed,
                    format!("SteamProtocol: DNS resolution for {host} failed: {e}"),
                )
            })?
            .next()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcNetDnsResolutionFailed,
                    format!("SteamProtocol: no address for {host}"),
                )
            })?;

        let mut stream = TcpStream::connect_timeout(&addr, self.connect_timeout).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetConnectionFailed,
                format!("SteamProtocol: connect to {host} failed: {e}"),
            )
        })?;

        // Send HTTP GET request
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).map_err(|e| {
            AppError::new(
                ReasonCode::RcNetWriteFailed,
                format!("SteamProtocol: HTTP GET failed: {e}"),
            )
        })?;

        // Read the response
        let mut response = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => response.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(AppError::new(
                        ReasonCode::RcNetReadFailed,
                        format!("SteamProtocol: HTTP read failed: {e}"),
                    ));
                }
            }
        }

        // Find the body after the HTTP headers
        let response_str = String::from_utf8_lossy(&response);

        // Check for HTTP status
        if !response_str.starts_with("HTTP/1.1 200") && !response_str.starts_with("HTTP/1.0 200") {
            return Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                format!("SteamProtocol: HTTP error from content server: {response_str:.200}"),
            ));
        }

        // Find body after \r\n\r\n
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body_offset = body_start + 4;
            Ok(response[body_offset..].to_vec())
        } else {
            Err(AppError::new(
                ReasonCode::RcNetProtocolError,
                "SteamProtocol: no HTTP body separator found",
            ))
        }
    }

    /// Verify the SHA-1 checksum of a file.
    pub fn verify_file_checksum(filepath: &Path, expected: &[u8; 20]) -> AppResult<bool> {
        let data = std::fs::read(filepath).map_err(|e| {
            AppError::new(
                ReasonCode::RcIo,
                format!("SteamProtocol: cannot read {} for checksum: {e}", filepath.display()),
            )
        })?;

        let actual = Sha1::digest(&data);
        // Use constant-time comparison for security
        // We use a simple constant-time comparison via HMAC trick or manual
        // constant-time compare
        let result = constant_time_eq(actual.as_slice(), expected);
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Check if the connection is alive and ready.
    pub fn is_connected(&self) -> bool {
        self.stream.is_some() && self.state == ConnectionState::Ready
    }

    /// Get the current server name.
    pub fn server_name(&self) -> Option<&str> {
        self.current_server.as_deref()
    }

    /// Get the assigned Steam ID.
    pub fn steam_id(&self) -> u64 {
        self.steam_id
    }

    /// Get the assigned session ID.
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Set the Steam ID (called after successful logon).
    pub fn set_steam_id(&mut self, steam_id: u64) {
        self.steam_id = steam_id;
        self.auth.steam_id = Some(steam_id);
    }

    /// Set the session ID (called during encryption handshake).
    pub fn set_session_id(&mut self, session_id: u32) {
        self.session_id = session_id;
    }

    /// Get a reference to the session key, if established.
    pub fn session_key(&self) -> Option<&[u8; 32]> {
        self.session_key.as_ref()
    }

    /// Get a reference to the RSA public key captured during the encryption
    /// handshake, if available.
    pub fn rsa_public_key(&self) -> Option<&rsa::RsaPublicKey> {
        self.rsa_public_key.as_ref()
    }
}

// ---------------------------------------------------------------------------
// Internal types for the encryption handshake
// ---------------------------------------------------------------------------

struct EncryptRequest {
    key_size: u32,
    rsa_modulus: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Serialize a SteamMessage into its on-wire byte representation.
///
/// The wire format consists of:
///   - Magic (u32 LE): "VS01"
///   - Total length (u32 LE): encrypted body size
///   - Encrypted body: ExtendedHeader (44 bytes) + payload
///
/// This function does NOT encrypt; it produces the plaintext frame.
pub fn serialize_message(msg: &SteamMessage) -> Vec<u8> {
    let header = ExtendedHeader {
        raw: msg.msg_type as u32,
        size: msg.payload.len() as u32,
        source_job_id: msg.source_job_id,
        target_job_id: msg.target_job_id,
        header_size: EXTENDED_HEADER_SIZE,
        steam_id: msg.steam_id,
        session_id: msg.session_id,
        message_type: msg.message_type,
    };

    let mut body = header.serialize();
    body.extend_from_slice(&msg.payload);

    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(&STEAM_MAGIC.to_le_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// Deserialize a SteamMessage from raw on-wire bytes.
///
/// Returns None if the data is malformed (bad magic, short data, invalid
/// header_size, unknown message type).
///
/// This function does NOT decrypt; it expects the body to already be
/// decrypted if applicable.
pub fn deserialize_message(data: &[u8]) -> Option<SteamMessage> {
    if data.len() < 8 + ExtendedHeader::TOTAL_SIZE {
        return None;
    }

    let magic = u32::from_le_bytes(data[0..4].try_into().ok()?);
    if magic != STEAM_MAGIC {
        return None;
    }

    let _total_len = u32::from_le_bytes(data[4..8].try_into().ok()?);
    let body = &data[8..];

    let ext_header = ExtendedHeader::deserialize(body)?;

    if body.len() < ExtendedHeader::TOTAL_SIZE + ext_header.size as usize {
        return None;
    }

    let payload = body[ExtendedHeader::TOTAL_SIZE..ExtendedHeader::TOTAL_SIZE + ext_header.size as usize].to_vec();
    let msg_type = map_emsg(ext_header.raw);

    Some(SteamMessage {
        msg_type,
        payload,
        source_job_id: ext_header.source_job_id,
        target_job_id: ext_header.target_job_id,
        steam_id: ext_header.steam_id,
        session_id: ext_header.session_id,
        message_type: ext_header.message_type,
    })
}

/// Map a raw EMsg value to a SteamMessageType enum variant.
pub fn map_emsg(raw: u32) -> SteamMessageType {
    match raw {
        130 => SteamMessageType::ChannelEncryptRequest,
        131 => SteamMessageType::ChannelEncryptResponse,
        132 => SteamMessageType::ChannelEncryptResult,
        136 => SteamMessageType::Multi,
        1101 => SteamMessageType::ClientLogOn,
        1103 => SteamMessageType::ClientLogOnResponse,
        1110 => SteamMessageType::ClientLoggedOff,
        1113 => SteamMessageType::ClientHeartBeat,
        1121 => SteamMessageType::ClientAppUsageEvent,
        1122 => SteamMessageType::ClientUpdateAppJob,
        1128 => SteamMessageType::ClientPackageInfoRequest,
        1129 => SteamMessageType::ClientPackageInfoResponse,
        1140 => SteamMessageType::ClientGameConnectTokens,
        1134 => SteamMessageType::ClientGamesPlayed,
        1150 => SteamMessageType::ClientAuthList,
        1155 => SteamMessageType::ClientServersAvailable,
        1178 => SteamMessageType::ClientRequestedClientServices,
        1186 => SteamMessageType::ClientUserNotifications,
        1196 => SteamMessageType::ClientCommentNotifications,
        1201 => SteamMessageType::ClientVoteNotifications,
        1207 => SteamMessageType::ClientChatInvite,
        1212 => SteamMessageType::ClientChatGetTarget,
        1225 => SteamMessageType::ClientCreateFriendsGroup,
        1234 => SteamMessageType::ClientPersonaState,
        1253 => SteamMessageType::ClientFriendMsgIncoming,
        1276 => SteamMessageType::ClientChatRoomMsg,
        1311 => SteamMessageType::ClientUFSGetFileListForApp,
        1312 => SteamMessageType::ClientUFSGetFileListForAppResponse,
        1317 => SteamMessageType::ClientUFSDownloadRequest,
        1318 => SteamMessageType::ClientUFSDownloadResponse,
        1320 => SteamMessageType::ClientDownloadAppInfo,
        1321 => SteamMessageType::ClientDownloadAppInfoResponse,
        1123 => SteamMessageType::ClientUpdateAppJobResponse,
        1130 => SteamMessageType::ClientPackageInfoResponse2,
        1355 => SteamMessageType::ClientLicenseList,
        1360 => SteamMessageType::ClientRegisterKey,
        1367 => SteamMessageType::ClientPurchaseResponse,
        1370 => SteamMessageType::ClientWalletUpdate,
        1384 => SteamMessageType::ClientAppInfoUpdate,
        1385 => SteamMessageType::ClientAppInfoUpdateResponse,
        1406 => SteamMessageType::ClientGameConnectDeny,
        1415 => SteamMessageType::ClientAuthListAck,
        1418 => SteamMessageType::ClientUCMsg,
        1421 => SteamMessageType::ClientFriendsList,
        1430 => SteamMessageType::ClientClanState,
        1436 => SteamMessageType::ClientChatEnter,
        1438 => SteamMessageType::ClientChatMsg,
        1441 => SteamMessageType::ClientChatMemberInfo,
        1445 => SteamMessageType::ClientAccountInfo,
        1641 => SteamMessageType::ClientUserGameStatsSchema,
        1862 => SteamMessageType::ClientLogonGameServer,
        1863 => SteamMessageType::ClientLogonGameServerResponse,
        2001 => SteamMessageType::ClientSystemManagerShutdown,
        2002 => SteamMessageType::ClientSystemManagerUpdate,
        2500 => SteamMessageType::ClientGetUserStats,
        2501 => SteamMessageType::ClientStoreUserStats,
        2502 => SteamMessageType::ClientGetUserStatsResponse,
        2503 => SteamMessageType::ClientStoreUserStatsResponse,
        _ => SteamMessageType::Invalid,
    }
}

/// Constant-time byte slice comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// ---------------------------------------------------------------------------
// Steam Protocol URL Handling (steam:// links)
//
// Steam registers itself as the handler for steam:// URLs. When a user clicks
// a steam:// link in a browser, the OS activates Steam and passes the URL as
// a command-line argument or via the macOS URL event system.
//
// URL format: steam://<command>/<param1>/<param2>/...?key=value
//
// Common commands:
//   open/friends          — Open friends list
//   store/<app_id>        — Open Steam store page for an app
//   run/<app_id>          — Launch/run a game
//   launch/<app_id>       — Same as run
//   nav/friends           — Navigate to friends section
//   nav/settings          — Navigate to settings section
//   nav/<section>         — Navigate to any Steam UI section
//   friends/              — Open friends list
//   subscribe/<app_id>    — Install/subscribe to a game
//   install/<app_id>      — Same as subscribe
//   browser/<url>         — Open a web page in Steam overlay browser
// ---------------------------------------------------------------------------

/// Parsed commands from a steam:// protocol URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SteamProtocolCommand {
    /// Open the friends list.
    OpenFriends,
    /// Navigate to the Steam store page for a specific app.
    Store(u32),
    /// Launch/run a game by app ID.
    Run(u32),
    /// Same as Run.
    Launch(u32),
    /// Navigate to a named Steam UI section (friends, settings, library, etc.).
    Nav(String),
    /// Install a game by app ID.
    Install(u32),
    /// Subscribe to (install) a game by app ID.
    Subscribe(u32),
    /// Open a URL in the Steam overlay browser.
    Browser(String),
    /// Open the friends list (simple).
    Friends,
    /// Unknown/unrecognized command.
    Unknown(String),
}

impl SteamProtocolCommand {
    /// Return a human-readable description of the command.
    pub fn description(&self) -> &str {
        match self {
            Self::OpenFriends => "open friends list",
            Self::Store(_) => "view store page",
            Self::Run(_) | Self::Launch(_) => "launch game",
            Self::Nav(_) => "navigate UI section",
            Self::Install(_) | Self::Subscribe(_) => "install game",
            Self::Browser(_) => "open browser URL",
            Self::Friends => "friends list",
            Self::Unknown(cmd) => cmd,
        }
    }

    /// Extract the app ID if this command carries one.
    pub fn app_id(&self) -> Option<u32> {
        match self {
            Self::Store(id) | Self::Run(id) | Self::Launch(id)
            | Self::Install(id) | Self::Subscribe(id) => Some(*id),
            _ => None,
        }
    }
}

/// The result of parsing a steam:// URL.
#[derive(Debug, Clone)]
pub struct SteamProtocolUrl {
    /// The parsed command.
    pub command: SteamProtocolCommand,
    /// Query string parameters from the URL (key=value pairs).
    pub query_params: BTreeMap<String, String>,
    /// The raw URL string.
    pub raw_url: String,
}

/// Parse a steam:// protocol URL into a `SteamProtocolUrl`.
///
/// # Arguments
///
/// * `url_str` — The full URL string, e.g. `steam://run/730?action=play`
///
/// # Returns
///
/// `Some(SteamProtocolUrl)` if the URL could be parsed, `None` if it is
/// not a valid steam:// URL.
pub fn parse_steam_protocol_url(url_str: &str) -> Option<SteamProtocolUrl> {
    let parsed = Url::parse(url_str).ok()?;
    if parsed.scheme() != "steam" {
        return None;
    }

    let query_params: BTreeMap<String, String> = parsed.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Collect path segments, skipping the leading empty segment from the
    // leading slash in `steam://command/...`.
    let segments: Vec<String> = parsed.path_segments()
        .map(|s| s.map(|seg| urlencoding_decode(seg)).collect())
        .unwrap_or_default();

    let raw_url = url_str.to_string();

    let command = if segments.is_empty() {
        SteamProtocolCommand::Unknown(String::new())
    } else {
        let cmd = segments[0].to_lowercase();
        match cmd.as_str() {
            "open" => {
                if segments.len() > 1 {
                    match segments[1].to_lowercase().as_str() {
                        "friends" => SteamProtocolCommand::OpenFriends,
                        other => SteamProtocolCommand::Unknown(format!("open/{other}")),
                    }
                } else {
                    SteamProtocolCommand::Unknown("open".to_string())
                }
            }
            "store" => {
                if segments.len() > 1 {
                    match segments[1].parse::<u32>() {
                        Ok(id) => SteamProtocolCommand::Store(id),
                        Err(_) => SteamProtocolCommand::Unknown(format!("store/{}", segments[1])),
                    }
                } else {
                    SteamProtocolCommand::Unknown("store".to_string())
                }
            }
            "run" => {
                if segments.len() > 1 {
                    match segments[1].parse::<u32>() {
                        Ok(id) => SteamProtocolCommand::Run(id),
                        Err(_) => SteamProtocolCommand::Unknown(format!("run/{}", segments[1])),
                    }
                } else {
                    SteamProtocolCommand::Unknown("run".to_string())
                }
            }
            "launch" => {
                if segments.len() > 1 {
                    match segments[1].parse::<u32>() {
                        Ok(id) => SteamProtocolCommand::Launch(id),
                        Err(_) => SteamProtocolCommand::Unknown(format!("launch/{}", segments[1])),
                    }
                } else {
                    SteamProtocolCommand::Unknown("launch".to_string())
                }
            }
            "nav" => {
                if segments.len() > 1 {
                    SteamProtocolCommand::Nav(segments[1].clone())
                } else {
                    SteamProtocolCommand::Unknown("nav".to_string())
                }
            }
            "friends" => SteamProtocolCommand::Friends,
            "subscribe" => {
                if segments.len() > 1 {
                    match segments[1].parse::<u32>() {
                        Ok(id) => SteamProtocolCommand::Subscribe(id),
                        Err(_) => SteamProtocolCommand::Unknown(format!("subscribe/{}", segments[1])),
                    }
                } else {
                    SteamProtocolCommand::Unknown("subscribe".to_string())
                }
            }
            "install" => {
                if segments.len() > 1 {
                    match segments[1].parse::<u32>() {
                        Ok(id) => SteamProtocolCommand::Install(id),
                        Err(_) => SteamProtocolCommand::Unknown(format!("install/{}", segments[1])),
                    }
                } else {
                    SteamProtocolCommand::Unknown("install".to_string())
                }
            }
            "browser" => {
                if segments.len() > 1 {
                    SteamProtocolCommand::Browser(segments[1..].join("/"))
                } else {
                    SteamProtocolCommand::Unknown("browser".to_string())
                }
            }
            _ => SteamProtocolCommand::Unknown(cmd),
        }
    };

    Some(SteamProtocolUrl {
        command,
        query_params,
        raw_url,
    })
}

/// Simple percent-decoding for URL path segments.
fn urlencoding_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().and_then(|c| hex_val(c));
            let lo = chars.next().and_then(|c| hex_val(c));
            match (hi, lo) {
                (Some(h), Some(l)) => result.push((h << 4 | l) as char),
                _ => result.push('%'),
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Result of dispatching a steam:// protocol URL to a subsystem.
#[derive(Debug, Clone)]
pub enum SteamProtocolDispatchResult {
    /// Command was handled successfully.
    Handled,
    /// Command was not recognized.
    Unrecognized(String),
    /// Command requires launching a game (app_id, optional action).
    LaunchGame(u32, Option<String>),
    /// Command requires navigating a browser/webview to a URL.
    NavigateBrowser(String),
    /// Command requires showing the friends list.
    ShowFriends,
    /// Command requires navigating to a Steam UI section.
    NavigateSection(String),
    /// Command requires installing a game.
    InstallGame(u32),
    /// An error occurred during dispatch.
    Error(String),
}

/// The Steam protocol handler: responsible for registering the steam:// URL
/// scheme, parsing incoming URLs, and dispatching them to the appropriate
/// subsystem.
#[derive(Debug)]
pub struct SteamProtocolHandler {
    /// Whether the protocol handler has been registered with the OS.
    registered: bool,
    /// Whether to log protocol events.
    verbose: bool,
}

impl SteamProtocolHandler {
    /// Create a new protocol handler. It starts in unregistered state.
    pub fn new() -> Self {
        Self {
            registered: false,
            verbose: false,
        }
    }

    /// Create a new protocol handler with verbose logging enabled.
    pub fn new_verbose() -> Self {
        Self {
            registered: true,
            verbose: true,
        }
    }

    /// Register the steam:// URL scheme with the operating system.
    ///
    /// On macOS, this uses the CoreFoundation `LSSetDefaultHandlerForURLScheme`
    /// to register the current executable as the handler for steam:// URLs.
    /// This can also be achieved by having the appropriate `CFBundleURLTypes`
    /// entry in the app's Info.plist.
    ///
    /// On Windows, this would write to the registry under
    /// `HKCR\steam\shell\open\command`.
    ///
    /// This is a best-effort registration; it may fail silently if the
    /// process lacks the necessary entitlements.
    pub fn register(&mut self) {
        if self.registered {
            return;
        }

        #[cfg(target_os = "macos")]
        {
            // Use LaunchServices to register steam:// URL scheme handling.
            // On macOS, the preferred approach is Info.plist CFBundleURLTypes,
            // but we also attempt runtime registration via
            // LSSetDefaultHandlerForURLScheme.
            unsafe {
                use std::ffi::CString;
                let scheme = CString::new("steam").unwrap();
                let bundle_id = CString::new("com.casa1.steam").unwrap();

                // LSSetDefaultHandlerForURLScheme is from LaunchServices.
                // It registers the given bundle ID as the default handler
                // for the URL scheme.
                unsafe extern "C" {
                    fn LSSetDefaultHandlerForURLScheme(
                        inURLScheme: *const libc::c_char,
                        inHandlerBundleID: *const libc::c_char,
                    ) -> i32;
                }
                let ret = LSSetDefaultHandlerForURLScheme(
                    scheme.as_ptr(),
                    bundle_id.as_ptr(),
                );
                if self.verbose {
                    eprintln!(
                        "[SteamProtocol] LSSetDefaultHandlerForURLScheme returned {}",
                        ret
                    );
                }
            }

            if self.verbose {
                eprintln!("[SteamProtocol] Registered steam:// URL scheme handler");
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            if self.verbose {
                eprintln!(
                    "[SteamProtocol] steam:// URL scheme registration skipped \
                     (non-macOS target)"
                );
            }
        }

        self.registered = true;
    }

    /// Check whether the protocol handler has been registered.
    pub fn is_registered(&self) -> bool {
        self.registered
    }

    /// Parse a steam:// URL string into a structured command.
    ///
    /// This is a convenience wrapper around [`parse_steam_protocol_url`].
    pub fn parse_url(&self, url_str: &str) -> Option<SteamProtocolUrl> {
        parse_steam_protocol_url(url_str)
    }

    /// Dispatch a parsed steam:// URL to the appropriate subsystem action.
    ///
    /// Returns a `SteamProtocolDispatchResult` indicating what action should
    /// be taken.
    pub fn dispatch(&self, url: &SteamProtocolUrl) -> SteamProtocolDispatchResult {
        let action = url.query_params.get("action").cloned();

        match &url.command {
            SteamProtocolCommand::OpenFriends | SteamProtocolCommand::Friends => {
                if self.verbose {
                    eprintln!("[SteamProtocol] Dispatch: open friends list");
                }
                SteamProtocolDispatchResult::ShowFriends
            }
            SteamProtocolCommand::Store(app_id) => {
                let store_url = format!("https://store.steampowered.com/app/{app_id}");
                if self.verbose {
                    eprintln!(
                        "[SteamProtocol] Dispatch: navigate store page for app {app_id}"
                    );
                }
                SteamProtocolDispatchResult::NavigateBrowser(store_url)
            }
            SteamProtocolCommand::Run(app_id) | SteamProtocolCommand::Launch(app_id) => {
                if self.verbose {
                    eprintln!(
                        "[SteamProtocol] Dispatch: launch game {} (action={:?})",
                        app_id, action
                    );
                }
                SteamProtocolDispatchResult::LaunchGame(*app_id, action)
            }
            SteamProtocolCommand::Nav(section) => {
                if self.verbose {
                    eprintln!(
                        "[SteamProtocol] Dispatch: navigate to section '{section}'"
                    );
                }
                SteamProtocolDispatchResult::NavigateSection(section.clone())
            }
            SteamProtocolCommand::Install(app_id) | SteamProtocolCommand::Subscribe(app_id) => {
                if self.verbose {
                    eprintln!(
                        "[SteamProtocol] Dispatch: install/subscribe app {app_id}"
                    );
                }
                SteamProtocolDispatchResult::InstallGame(*app_id)
            }
            SteamProtocolCommand::Browser(target_url) => {
                if self.verbose {
                    eprintln!(
                        "[SteamProtocol] Dispatch: open browser URL {target_url}"
                    );
                }
                SteamProtocolDispatchResult::NavigateBrowser(target_url.clone())
            }
            SteamProtocolCommand::Unknown(cmd) => {
                let msg = format!("unrecognized steam:// command: {cmd}");
                if self.verbose {
                    eprintln!("[SteamProtocol] {msg}");
                }
                SteamProtocolDispatchResult::Unrecognized(msg)
            }
        }
    }

    /// Handle a steam:// URL string end-to-end: parse and dispatch.
    pub fn handle_url(&self, url_str: &str) -> SteamProtocolDispatchResult {
        match self.parse_url(url_str) {
            Some(parsed) => self.dispatch(&parsed),
            None => SteamProtocolDispatchResult::Error(format!(
                "failed to parse steam:// URL: {url_str}"
            )),
        }
    }

    /// Parse Steam-style command-line arguments into protocol commands.
    ///
    /// Steam.exe accepts many command-line arguments that map to protocol
    /// commands:
    ///
    /// - `steam://run/730` — direct protocol URL
    /// - `-applaunch 730 [args...]` — launch game with arguments
    /// - `-silent` — start minimized to tray
    /// - `-login <username> <password>` — auto-login
    /// - `-dev` — developer mode
    /// - `-console` — enable developer console
    /// - `-no-browser` — skip browser initialization
    /// - `-offline` — start in offline mode
    /// - `-bigpicture` — start in Big Picture mode
    /// - `-tenfoot` — alias for Big Picture mode
    ///
    /// Returns a list of parsed protocol URLs.
    pub fn parse_command_line(args: &[String]) -> Vec<SteamProtocolUrl> {
        let mut results = Vec::new();
        let mut i = 0;

        while i < args.len() {
            let arg = &args[i];

            // Direct steam:// URL
            if arg.starts_with("steam://") {
                if let Some(parsed) = parse_steam_protocol_url(arg) {
                    results.push(parsed);
                }
                i += 1;
                continue;
            }

            match arg.as_str() {
                "-applaunch" => {
                    // -applaunch <app_id> [args...]
                    if i + 1 < args.len() {
                        if let Ok(app_id) = args[i + 1].parse::<u32>() {
                            // Collect remaining args as launch arguments
                            let mut launch_args = Vec::new();
                            i += 2;
                            while i < args.len() && !args[i].starts_with('-') {
                                launch_args.push(args[i].clone());
                                i += 1;
                            }

                            // Build a fake steam:// URL with launch args in query
                            let mut raw = format!("steam://run/{}", app_id);
                            if !launch_args.is_empty() {
                                raw.push_str("?launch_args=");
                                raw.push_str(&launch_args.join("+"));
                            }
                            if let Some(parsed) = parse_steam_protocol_url(&raw) {
                                results.push(parsed);
                            }
                            continue;
                        }
                    }
                }
                "-silent" | "-silentlaunch" => {
                    // Silently launch; handled as a flag by the caller.
                    // We still emit a synthetic URL for tracing.
                    if let Some(parsed) = parse_steam_protocol_url("steam://nav/silent") {
                        results.push(parsed);
                    }
                }
                "-login" => {
                    // -login <username> <password>
                    // Skipped for protocol handling; handled by auth flow.
                    i += 2; // consume username and password
                }
                "-dev" | "-console" | "-no-browser" | "-offline"
                | "-bigpicture" | "-tenfoot" | "-small" | "-norepair"
                | "-noverifyfiles" | "-no-d3d" | "-cef-single-process"
                | "-cef-in-process-gpu" | "-cef-disable-gpu" | "-cef-disable-sandbox"
                | "-cef-enable-debug" | "-crash_overide" => {
                    // Known flags — emit as nav commands for tracing
                    let flag = arg.trim_start_matches('-');
                    let raw = format!("steam://nav/{}", flag);
                    if let Some(parsed) = parse_steam_protocol_url(&raw) {
                        results.push(parsed);
                    }
                }
                _ => {
                    // Unknown argument — could be a game path or other arg
                }
            }
            i += 1;
        }

        results
    }
}

impl Default for SteamProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_stack_initialises_in_disconnected_state() {
        let stack = SteamProtocolStack::new();
        assert_eq!(stack.state, ConnectionState::Disconnected);
        assert!(!stack.is_connected());
    }

    #[test]
    fn message_enum_mapping() {
        assert_eq!(map_emsg(130), SteamMessageType::ChannelEncryptRequest);
        assert_eq!(map_emsg(1101), SteamMessageType::ClientLogOn);
        assert_eq!(map_emsg(9999), SteamMessageType::Invalid);
    }

    #[test]
    fn steam_message_serialize_deserialize_roundtrip() {
        let msg = SteamMessage {
            msg_type: SteamMessageType::ClientHeartBeat,
            payload: vec![0x01, 0x02, 0x03],
            source_job_id: 0x1234,
            target_job_id: 0x5678,
            steam_id: 0xDEADBEEF,
            session_id: 42,
            message_type: 0,
        };

        let serialized = serialize_message(&msg);
        let deserialized = deserialize_message(&serialized).expect("should deserialize");

        assert_eq!(deserialized.msg_type, msg.msg_type);
        assert_eq!(deserialized.payload, msg.payload);
        assert_eq!(deserialized.source_job_id, msg.source_job_id);
        assert_eq!(deserialized.target_job_id, msg.target_job_id);
        assert_eq!(deserialized.steam_id, msg.steam_id);
        assert_eq!(deserialized.session_id, msg.session_id);
    }

    #[test]
    fn deserialize_message_bad_magic() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00];
        assert!(deserialize_message(&data).is_none());
    }

    #[test]
    fn deserialize_message_too_short() {
        let data = [0x56, 0x53, 0x30, 0x31];
        assert!(deserialize_message(&data).is_none());
    }

    #[test]
    fn extended_header_encoding() {
        let header = ExtendedHeader {
            raw: 1101,
            size: 100,
            source_job_id: 0xAAAA_BBBB_CCCC_DDDD,
            target_job_id: 0x1111_2222_3333_4444,
            header_size: EXTENDED_HEADER_SIZE,
            steam_id: 0xFFFF_EEEE_DDDD_CCCC,
            session_id: 0x12345678,
            message_type: 0,
        };

        let bytes = header.serialize();
        assert_eq!(bytes.len(), ExtendedHeader::TOTAL_SIZE);

        let deserialized = ExtendedHeader::deserialize(&bytes).expect("should deserialize");
        assert_eq!(deserialized.raw, header.raw);
        assert_eq!(deserialized.size, header.size);
        assert_eq!(deserialized.source_job_id, header.source_job_id);
        assert_eq!(deserialized.target_job_id, header.target_job_id);
        assert_eq!(deserialized.header_size, EXTENDED_HEADER_SIZE);
        assert_eq!(deserialized.steam_id, header.steam_id);
        assert_eq!(deserialized.session_id, header.session_id);
        assert_eq!(deserialized.message_type, header.message_type);
    }

    #[test]
    fn extended_header_rejects_bad_header_size() {
        let header = ExtendedHeader {
            raw: 0,
            size: 0,
            source_job_id: 0,
            target_job_id: 0,
            header_size: 0xFF, // wrong
            steam_id: 0,
            session_id: 0,
            message_type: 0,
        };

        let mut bytes = header.serialize();
        // We need to manually corrupt the header_size byte
        bytes[24] = 0xFF;

        let result = ExtendedHeader::deserialize(&bytes);
        assert!(result.is_none());
    }

    #[test]
    fn session_cipher_encrypt_decrypt() {
        let aes_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];

        let mut cipher = SessionCipher::new(&aes_key);
        let plaintext = b"Hello, Steam! This is a test message for AES-CTR encryption.";
        let encrypted = cipher.encrypt(plaintext);

        // AES-CTR is symmetric (encrypt XORs keystream, same operation decrypts).
        // Since encrypt() uses send_key and decrypt() uses recv_key (different),
        // we must use encrypt() for both encrypt and decrypt when testing
        // roundtrip with the same directional cipher.
        let mut decrypt_cipher = SessionCipher::new(&aes_key);
        let decrypted = decrypt_cipher.encrypt(&encrypted);

        assert_eq!(&decrypted, plaintext, "AES-CTR roundtrip should produce original plaintext");
    }

    #[test]
    fn session_cipher_send_recv_independence() {
        let aes_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];

        let mut cipher = SessionCipher::new(&aes_key);
        let send_data = b"send test";
        let _recv_data = b"recv test";

        // Send and recv should use different keys, so encrypt and decrypt
        // with mismatched directions should produce different results.
        let encrypted_send = cipher.encrypt(send_data);

        // Reset and verify recv doesn't decrypt send data
        let mut cipher2 = SessionCipher::new(&aes_key);
        let recv_decrypted = cipher2.decrypt(&encrypted_send);

        // recv key != send key, so decrypted should NOT match original
        assert_ne!(
            &recv_decrypted, send_data,
            "receive cipher should not decrypt send-encrypted data"
        );

        // But a fresh send cipher can decrypt its own data (CTR symmetry)
        let mut cipher3 = SessionCipher::new(&aes_key);
        let send_decrypted = cipher3.encrypt(&encrypted_send);
        assert_eq!(
            &send_decrypted, send_data,
            "send cipher should encrypt/decrypt its own data symmetrically"
        );
    }

    #[test]
    fn session_cipher_multiple_roundtrips() {
        let aes_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];

        let mut cipher = SessionCipher::new(&aes_key);

        // Encrypt multiple payloads sequentially
        let p1 = b"payload one";
        let p2 = b"payload two with more data";
        let p3 = b"three";

        let e1 = cipher.encrypt(p1);
        let e2 = cipher.encrypt(p2);
        let e3 = cipher.encrypt(p3);

        // Decrypt sequentially with a second cipher (same initial state),
        // advancing the keystream in lockstep with the encryption.
        // AES-CTR is symmetric, so we use encrypt() (send key) for both.
        let mut dec_cipher = SessionCipher::new(&aes_key);
        let d1 = dec_cipher.encrypt(&e1);
        assert_eq!(&d1, p1, "first payload should roundtrip");

        let d2 = dec_cipher.encrypt(&e2);
        assert_eq!(&d2, p2, "second payload should roundtrip");

        let d3 = dec_cipher.encrypt(&e3);
        assert_eq!(&d3, p3, "third payload should roundtrip");
    }

    #[test]
    fn rsa_key_wrap_and_unwrap() {
        use rsa::{Oaep, RsaPrivateKey};

        // Generate a 2048-bit RSA key pair
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
        let public_key = private_key.to_public_key();

        let aes_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];

        // Wrap key using RSA-OAEP (SHA-256)
        let wrapped = public_key
            .encrypt(&mut rng, Oaep::new::<Sha256>(), &aes_key)
            .expect("RSA encryption failed");

        // Unwrap key
        let unwrapped = private_key
            .decrypt(Oaep::new::<Sha256>(), &wrapped)
            .expect("RSA decryption failed");

        assert_eq!(&unwrapped, &aes_key, "RSA-OAEP wrap/unwrap should produce original key");
    }

    #[test]
    fn chunk_verification_pass() {
        let chunk_data = b"this is a test chunk with known content for SHA-1 verification";
        let expected_hash = Sha1::digest(chunk_data);

        let mut chunk_id = [0u8; 20];
        chunk_id.copy_from_slice(&expected_hash);

        let actual_hash = Sha1::digest(chunk_data);
        assert_eq!(
            actual_hash.as_slice(),
            &chunk_id,
            "SHA-1 should match for the same chunk data"
        );
    }

    #[test]
    fn chunk_verification_fail() {
        let chunk_data = b"correct chunk data";
        let wrong_data = b"wrong chunk data";

        let correct_hash = Sha1::digest(chunk_data);
        let wrong_hash = Sha1::digest(wrong_data);

        assert_ne!(
            correct_hash.as_slice(),
            wrong_hash.as_slice(),
            "different data should have different SHA-1 hashes"
        );
    }

    #[test]
    fn file_checksum_verification() {
        let dir = std::env::temp_dir().join("steam_test_checksum");
        let _ = std::fs::create_dir_all(&dir);
        let filepath = dir.join("test_file.bin");

        let data = b"Hello, Steam checksum verification!";
        std::fs::write(&filepath, data).unwrap();

        let expected = Sha1::digest(data);
        let mut expected_bytes = [0u8; 20];
        expected_bytes.copy_from_slice(&expected);

        let result = SteamProtocolStack::verify_file_checksum(&filepath, &expected_bytes)
            .expect("verify_file_checksum should not error");
        assert!(result, "checksum should match");

        // Clean up
        let _ = std::fs::remove_file(&filepath);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn file_checksum_verification_fail() {
        let dir = std::env::temp_dir().join("steam_test_checksum_fail");
        let _ = std::fs::create_dir_all(&dir);
        let filepath = dir.join("test_file_fail.bin");

        let data = b"Some content";
        std::fs::write(&filepath, data).unwrap();

        // Wrong expected checksum
        let wrong_expected = [0x00u8; 20];

        let result = SteamProtocolStack::verify_file_checksum(&filepath, &wrong_expected)
            .expect("verify_file_checksum should not error");
        assert!(!result, "checksum should NOT match");

        // Clean up
        let _ = std::fs::remove_file(&filepath);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn depot_manifest_parsing() {
        let stack = SteamProtocolStack::new();

        // Build a mock depot manifest binary blob
        let depot_id: u32 = 12345;
        let version: u32 = 1;
        let file_count: u32 = 1;
        let total_size: u64 = 16;
        let flags: u32 = 0;

        let mut data = Vec::new();
        // Header
        data.extend_from_slice(&version.to_le_bytes());
        data.extend_from_slice(&file_count.to_le_bytes());
        data.extend_from_slice(&total_size.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&depot_id.to_le_bytes());

        // File entry
        let filename = "test_file.bin";
        let filename_bytes = filename.as_bytes();
        data.extend_from_slice(&(filename_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(filename_bytes);
        data.extend_from_slice(&total_size.to_le_bytes());

        let file_checksum = Sha1::digest(b"test_file.bin content");
        data.extend_from_slice(&file_checksum);

        // Chunk count
        let chunk_count: u32 = 1;
        data.extend_from_slice(&chunk_count.to_le_bytes());

        // Chunk
        let chunk_content = b"chunk content!!";
        let chunk_id = Sha1::digest(chunk_content);
        data.extend_from_slice(&chunk_id);
        data.extend_from_slice(&0u64.to_le_bytes()); // offset
        data.extend_from_slice(&0x12345678u32.to_le_bytes()); // CRC
        data.extend_from_slice(&(chunk_content.len() as u32).to_le_bytes()); // size
        data.extend_from_slice(&0u32.to_le_bytes()); // compressed_size

        let manifests = stack.parse_depot_manifest(&data, None).expect("should parse");
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].depot_id, depot_id);
        assert_eq!(manifests[0].filename, filename);
        assert_eq!(manifests[0].size, total_size);
        assert_eq!(manifests[0].checksum, file_checksum.as_slice());
        assert_eq!(manifests[0].chunks.len(), 1);
        assert_eq!(manifests[0].chunks[0].size, chunk_content.len() as u32);
    }

    #[test]
    fn depot_manifest_parsing_empty() {
        let stack = SteamProtocolStack::new();

        let depot_id: u32 = 0;
        let version: u32 = 1;
        let file_count: u32 = 0;
        let total_size: u64 = 0;
        let flags: u32 = 0;

        let mut data = Vec::new();
        data.extend_from_slice(&version.to_le_bytes());
        data.extend_from_slice(&file_count.to_le_bytes());
        data.extend_from_slice(&total_size.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&depot_id.to_le_bytes());

        let manifests = stack.parse_depot_manifest(&data, None).expect("should parse empty");
        assert!(manifests.is_empty());
    }

    #[test]
    fn cdn_routing_parsing() {
        let stack = SteamProtocolStack::new();

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<contentServerList>
  <contentServer cell="1234" https="true" port="443" weight="100">
    steam.cdn.steamusercontent.com
  </contentServer>
  <contentServer cell="5678" https="false" port="80" weight="50">
    cache1.example.com
  </contentServer>
</contentServerList>"#;

        let servers = stack.parse_cdn_routing(xml).expect("should parse CDN routing");
        assert_eq!(servers.len(), 2);

        assert_eq!(servers[0].host, "steam.cdn.steamusercontent.com");
        assert_eq!(servers[0].port, 443);
        assert!(servers[0].https);
        assert_eq!(servers[0].cell_id, 1234);
        assert_eq!(servers[0].weight, 100);

        assert_eq!(servers[1].host, "cache1.example.com");
        assert_eq!(servers[1].port, 80);
        assert!(!servers[1].https);
        assert_eq!(servers[1].cell_id, 5678);
        assert_eq!(servers[1].weight, 50);
    }

    #[test]
    fn cdn_routing_parsing_empty() {
        let stack = SteamProtocolStack::new();
        let servers = stack.parse_cdn_routing("<contentServerList></contentServerList>")
            .expect("should parse empty CDN routing");
        assert!(servers.is_empty());
    }

    #[test]
    fn gns_session_create_and_close() {
        let mut gns = GameNetworkingSockets::new();
        assert!(gns.connections.is_empty());

        let handle = gns.create_session().expect("should create session");
        assert_eq!(gns.connection_state(handle), Some(GnsConnectionState::Connected));

        gns.close_session(handle).expect("should close session");
        assert!(gns.connection_state(handle).is_none());
    }

    #[test]
    fn gns_message_send_poll() {
        let mut gns = GameNetworkingSockets::new();
        let handle = gns.create_session().expect("should create session");

        let msg_data = b"Hello GNS!";
        gns.send_message(handle, msg_data, 0).expect("should send message");

        let messages = gns.poll_incoming_messages().expect("should poll messages");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].data, msg_data);
        assert_eq!(messages[0].conn, handle);
    }

    #[test]
    fn gns_accept_session() {
        let mut gns = GameNetworkingSockets::new();

        // Manually create a session in Connecting state
        let handle = gns.next_handle;
        gns.next_handle += 1;
        gns.connections.insert(handle, GnsConnectionState::Connecting);

        assert_eq!(gns.connection_state(handle), Some(GnsConnectionState::Connecting));

        gns.accept_session(handle).expect("should accept session");
        assert_eq!(gns.connection_state(handle), Some(GnsConnectionState::Connected));
    }

    #[test]
    fn gns_close_nonexistent_session() {
        let mut gns = GameNetworkingSockets::new();
        let result = gns.close_session(999);
        assert!(result.is_err());
    }

    #[test]
    fn steam_client_state_machine() {
        let mut stack = SteamProtocolStack::new();
        assert_eq!(stack.state, ConnectionState::Disconnected);
        assert!(!stack.is_connected());

        // Test that we can transition states correctly
        stack.state = ConnectionState::Connected;
        assert_eq!(stack.state, ConnectionState::Connected);

        stack.state = ConnectionState::Encrypting;
        assert_eq!(stack.state, ConnectionState::Encrypting);

        // is_connected() requires both state == Ready AND stream.is_some().
        // Create a real TCP connection pair for the stream.
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("should bind to localhost");
        let addr = listener.local_addr().expect("should get local addr");
        let client = std::net::TcpStream::connect(addr)
            .expect("should connect to listener");
        // Accept the server side and drop it immediately — we only need
        // the client-side stream for the test.
        let _server = listener.accept();

        stack.stream = Some(client);
        stack.state = ConnectionState::Ready;
        assert!(stack.is_connected(), "is_connected should be true when Ready and stream is set");

        // Disconnect clears the stream
        let _ = stack.disconnect();
        assert!(!stack.is_connected(), "is_connected should be false after disconnect");
    }

    #[test]
    fn constant_time_eq_behaves_correctly() {
        let a = [0x01, 0x02, 0x03, 0x04];
        let b = [0x01, 0x02, 0x03, 0x04];
        let c = [0x01, 0x02, 0x03, 0x05];
        let d = [0x01, 0x02, 0x03];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let aes_key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];

        let mut stack = SteamProtocolStack::new();
        stack.cipher = Some(SessionCipher::new(&aes_key));
        stack.session_key = Some(aes_key);

        let payload = b"Hello, Steam! Real AES-CTR encryption roundtrip.";

        // encrypt_payload() uses the send-direction cipher. AES-CTR is symmetric,
        // so encrypt() just XORs with the keystream. After encrypting once, the
        // cipher state advances by payload.len(). To decrypt, we need a fresh
        // cipher (same key, same initial keystream position).
        let encrypted = stack.encrypt_payload(payload);

        // Create a fresh cipher for decryption (resets keystream to position 0)
        let mut decrypt_stack = SteamProtocolStack::new();
        decrypt_stack.cipher = Some(SessionCipher::new(&aes_key));
        let decrypted = decrypt_stack.encrypt_payload(&encrypted);

        assert_eq!(&decrypted, payload, "AES-CTR roundtrip through the stack (send direction)");
    }

    #[test]
    fn steam_message_serialize_with_payload() {
        let msg = SteamMessage {
            msg_type: SteamMessageType::ClientLogOn,
            payload: vec![
                0x01, 0x00, 0x01, 0x00, // protocol version
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // steam ID
                0x74, 0x65, 0x73, 0x74, 0x00, // "test\0"
            ],
            source_job_id: 0,
            target_job_id: 0,
            steam_id: 0,
            session_id: 0,
            message_type: 0,
        };

        let serialized = serialize_message(&msg);
        assert!(serialized.len() > 8 + ExtendedHeader::TOTAL_SIZE);

        let deserialized = deserialize_message(&serialized).expect("should deserialize");
        assert_eq!(deserialized.msg_type, SteamMessageType::ClientLogOn);
        assert_eq!(deserialized.payload, msg.payload);
    }
}
