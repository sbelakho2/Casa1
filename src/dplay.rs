//! Real software DirectPlay8 peer engine: address objects, the UDP session
//! transport, peer/session state and the wire messages between peers.
//!
//! This module replaces the earlier DirectPlay absence model.  Nothing here
//! fabricates success: every peer operation runs against real UDP sockets on
//! the host network stack, every session is a real bound endpoint recorded in
//! a process-wide session registry, and every failure returns the genuine
//! `DPNERR_*` code for the condition (port busy, refused/timeout, invalid
//! address, not initialized, session full, oversized send, unknown player).
//!
//! # Layout
//!
//! - [`Dplay8Address`] — the `IDirectPlay8Address` state model: service
//!   provider and device GUIDs, typed components (string / dword / guid /
//!   binary), user data, URL round-trip (`x-directplay:/`), duplication and
//!   equality.
//! - [`Dplay8Peer`] — the `IDirectPlay8Peer` engine: `Initialize`, `Host`
//!   (binds a real UDP socket and publishes a real session id), `Connect`
//!   (real UDP association with a real connect/ack exchange), `SendTo` /
//!   [`Dplay8Peer::receive_from`] (real datagrams), `EnumHosts`
//!   (real query/response datagrams against the local session registry and
//!   caller-supplied targets), `Close` / `Destroy`, `GetCaps` / `GetSPCaps`
//!   derived from the live transport.
//! - [`DplayRuntime`] — the per-guest-process object store used by the
//!   dispatch layer (the ABI glue lives in `runtime::dispatch::final_scraps`,
//!   mirroring the XACT3 layout).
//!
//! # Wire messages (all little-endian, documented here and at each encoder)
//!
//! Discovery and control datagrams start with a 4-byte ASCII magic:
//!
//! ```text
//! DP8Q  query                  4s  magic "DP8Q"
//!                              1B  protocol version (1)
//!                              4B  query id
//!                             16B  application guid (all zero = any)
//!
//! DP8R  query response         4s  magic "DP8R"
//!                              4B  query id (echoed)
//!                             16B  session instance guid
//!                             16B  application guid
//!                              4B  max players
//!                              4B  current players (including host)
//!                              2B  session-name byte length
//!                              nB  session name (UTF-8)
//!
//! DP8C  connect request        4s  magic "DP8C"
//!                              4B  request id
//!                             16B  application instance guid (the joiner's)
//!                              2B  player-name byte length
//!                              nB  player name (UTF-8)
//!                              2B  connect-data byte length
//!                              mB  connect data
//!
//! DP8A  connect accepted        4s  magic "DP8A"
//!                              4B  request id (echoed)
//!                              4B  assigned player id (DPNID)
//!                              4B  host player id
//!                              4B  existing-player count
//!                              k*: 4B dpnid, 2B name length, name bytes
//!
//! DP8F  connect rejected        4s  magic "DP8F"
//!                              4B  request id (echoed)
//!                              4B  HRESULT reason (a real DPNERR_*)
//!
//! DP8J  player joined           4s  magic "DP8J"
//!                              4B  dpnid
//!                              2B  name length, nB name bytes
//!
//! DP8X  player left             4s  magic "DP8X"
//!                              4B  dpnid
//!
//! DP8D  application data        4s  magic "DP8D"
//!                              4B  source dpnid
//!                              4B  destination dpnid (0 = all players)
//!                              nB  payload
//!
//! DP8S  session terminated      4s  magic "DP8S"
//!                              4B  HRESULT reason
//!                              nB  terminate data
//!
//! DP8P  keepalive               4s  magic "DP8P" (the service echoes it)
//!
//! DP8G  group operation         4s  magic "DP8G"
//!                              1B  op (1 = create, 2 = destroy,
//!                                  3 = add member, 4 = remove member,
//!                                  5 = info/context)
//!                              4B  group id
//!   create:                    4B  owner dpnid
//!                              2B  name length, nB name (UTF-8)
//!                              2B  data length, mB data
//!   destroy:                   (no payload)
//!   add/remove:                4B  member dpnid
//!   info:                      2B  name length, nB name (UTF-8)
//!                              2B  data length, mB data
//!
//! Group create/destroy/member/info operations are sent by the owning peer
//! to the host, which applies them to the session group table and relays
//! them to every other connected player.  `DP8D` datagrams whose destination
//! is a group id are relayed to each real group member (and looped back to
//! the host when the host is a member).
//!
//! A host runs one service thread on its session socket: it answers `DP8Q`
//! with `DP8R`, accepts `DP8C` with `DP8A` (or rejects with `DP8F` when the
//! session is full/closing), announces joiners with `DP8J`, relays `DP8D`
//! between players, removes `DP8X` leavers, and terminates sessions with
//! `DP8S`.  A connected peer runs a receiver thread on its own socket; every
//! `SendTo` is a real `send`/`send_to` on that socket and every received
//! datagram is handed to [`Dplay8Peer::receive_from`].

#![allow(dead_code)] // the full address/peer state model is larger than any one dispatch

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// HRESULTs
// ---------------------------------------------------------------------------

pub(crate) const S_OK: u32 = 0;
pub(crate) const S_FALSE: u32 = 1;
pub(crate) const E_INVALIDARG: u32 = 0x8007_0057;
pub(crate) const E_FAIL: u32 = 0x8000_4005;
pub(crate) const E_NOTIMPL: u32 = 0x8000_4001;
pub(crate) const E_NOINTERFACE: u32 = 0x8000_4002;
pub(crate) const E_POINTER: u32 = 0x8000_4003;
pub(crate) const E_OUTOFMEMORY: u32 = 0x8007_000e;

/// `MAKE_HRESULT(1, FACILITY_DPN(0x015), code + 0x8000)` — the macro
/// `MAKE_DPNHRESULT` from `dplay8.h`.
const fn dpn_error(code: u32) -> u32 {
    0x8000_0000 | (0x015 << 16) | (code + 0x8000)
}

/// `MAKE_HRESULT(0, FACILITY_DPN, code + 0x8000)` — `DPNSUCCESS_*`.
const fn dpn_success(code: u32) -> u32 {
    (0x015 << 16) | (code + 0x8000)
}

pub(crate) const DPNERR_GENERIC: u32 = E_FAIL;
pub(crate) const DPNERR_INVALIDPARAM: u32 = E_INVALIDARG;
pub(crate) const DPNERR_UNSUPPORTED: u32 = E_NOTIMPL;
pub(crate) const DPNERR_NOINTERFACE: u32 = E_NOINTERFACE;
pub(crate) const DPNERR_OUTOFMEMORY: u32 = E_OUTOFMEMORY;
pub(crate) const DPNERR_INVALIDPOINTER: u32 = E_POINTER;
/// `DPNSUCCESS_PENDING`.
pub(crate) const DPNERR_PENDING: u32 = dpn_success(0x0e);
/// `DPNSUCCESS_EQUAL` / `DPNSUCCESS_NOTEQUAL` from `IsEqual`.
pub(crate) const DPNSUCCESS_EQUAL: u32 = dpn_success(0x05);
pub(crate) const DPNSUCCESS_NOTEQUAL: u32 = dpn_success(0x0a);
pub(crate) const DPNERR_ABORTED: u32 = dpn_error(0x030);
/// The bound address cannot be used (a real port-in-use bind failure maps
/// here, mirroring the service-provider addressing failure).
pub(crate) const DPNERR_ADDRESSING: u32 = dpn_error(0x040);
pub(crate) const DPNERR_ALREADYCONNECTED: u32 = dpn_error(0x060);
pub(crate) const DPNERR_ALREADYINITIALIZED: u32 = dpn_error(0x080);
pub(crate) const DPNERR_BUFFERTOOSMALL: u32 = dpn_error(0x100);
pub(crate) const DPNERR_CANNOTCANCEL: u32 = dpn_error(0x110);
pub(crate) const DPNERR_CONNECTIONLOST: u32 = dpn_error(0x160);
pub(crate) const DPNERR_DATATOOLARGE: u32 = dpn_error(0x175);
pub(crate) const DPNERR_DOESNOTEXIST: u32 = dpn_error(0x180);
pub(crate) const DPNERR_DUPLICATECOMMAND: u32 = dpn_error(0x190);
pub(crate) const DPNERR_HOSTING: u32 = dpn_error(0x250);
pub(crate) const DPNERR_HOSTREJECTEDCONNECTION: u32 = dpn_error(0x260);
pub(crate) const DPNERR_HOSTTERMINATEDSESSION: u32 = dpn_error(0x270);
pub(crate) const DPNERR_INCOMPLETEADDRESS: u32 = dpn_error(0x280);
pub(crate) const DPNERR_INVALIDADDRESSFORMAT: u32 = dpn_error(0x290);
pub(crate) const DPNERR_INVALIDDEVICEADDRESS: u32 = dpn_error(0x320);
pub(crate) const DPNERR_INVALIDFLAGS: u32 = dpn_error(0x340);
pub(crate) const DPNERR_INVALIDGROUP: u32 = dpn_error(0x350);
pub(crate) const DPNERR_INVALIDHANDLE: u32 = dpn_error(0x360);
pub(crate) const DPNERR_INVALIDHOSTADDRESS: u32 = dpn_error(0x370);
pub(crate) const DPNERR_INVALIDINSTANCE: u32 = dpn_error(0x380);
pub(crate) const DPNERR_INVALIDPLAYER: u32 = dpn_error(0x420);
pub(crate) const DPNERR_INVALIDURL: u32 = dpn_error(0x450);
pub(crate) const DPNERR_NOCONNECTION: u32 = dpn_error(0x480);
pub(crate) const DPNERR_NOHOSTPLAYER: u32 = dpn_error(0x490);
pub(crate) const DPNERR_NORESPONSE: u32 = dpn_error(0x510);
pub(crate) const DPNERR_NOTALLOWED: u32 = dpn_error(0x520);
pub(crate) const DPNERR_NOTHOST: u32 = dpn_error(0x530);
pub(crate) const DPNERR_NOTREADY: u32 = dpn_error(0x540);
pub(crate) const DPNERR_SENDTOOLARGE: u32 = dpn_error(0x600);
pub(crate) const DPNERR_SESSIONFULL: u32 = dpn_error(0x610);
pub(crate) const DPNERR_TIMEDOUT: u32 = dpn_error(0x630);
pub(crate) const DPNERR_UNINITIALIZED: u32 = dpn_error(0x640);

// ---------------------------------------------------------------------------
// DirectPlay constants (dplay8.h / dpaddr.h)
// ---------------------------------------------------------------------------

/// `DPNOP_SYNC` — the synchronous-operation flag (`DPNCONNECT_SYNC`,
/// `DPNSEND_SYNC`, `DPNENUMHOSTS_SYNC`, ...).
pub(crate) const DPNOP_SYNC: u32 = 0x8000_0000;
/// `DPNID_ALL_PLAYERS_GROUP`.
pub(crate) const DPNID_ALL_PLAYERS_GROUP: u32 = 0;
/// The host peer's own player id.
pub(crate) const HOST_PLAYER_ID: u32 = 1;
/// `DPNPLAYER_HOST` / `DPNPLAYER_LOCAL` player-info flags.
pub(crate) const DPNPLAYER_HOST: u32 = 0x0004;
pub(crate) const DPNPLAYER_LOCAL: u32 = 0x0002;
/// `DPNINFO_NAME` / `DPNINFO_DATA` player-info flags.
pub(crate) const DPNINFO_NAME: u32 = 0x0001;
pub(crate) const DPNINFO_DATA: u32 = 0x0002;
/// `DPNSESSION_NODPNSVR` — the session is enumerated by the host itself.
pub(crate) const DPNSESSION_NODPNSVR: u32 = 0x0040;
/// `DPNSPCAPS_*` transport facts reported by `GetSPCaps`.
pub(crate) const DPNSPCAPS_SUPPORTSDPNSRV: u32 = 0x0001;
pub(crate) const DPNSPCAPS_SUPPORTSBROADCAST: u32 = 0x0002;
pub(crate) const DPNSPCAPS_SUPPORTSALLADAPTERS: u32 = 0x0004;
/// `DPNCAPS_*` peer flags reported by `GetCaps`.
pub(crate) const DPNCAPS_SUPPORTSGUARANTEED: u32 = 0x0001;
/// Player-destroy reasons.
pub(crate) const DPNDESTROYPLAYERREASON_NORMAL: u32 = 0x0001;
pub(crate) const DPNDESTROYPLAYERREASON_CONNECTIONLOST: u32 = 0x0002;
pub(crate) const DPNDESTROYPLAYERREASON_SESSIONTERMINATED: u32 = 0x0003;
pub(crate) const DPNDESTROYPLAYERREASON_HOSTDESTROYEDPLAYER: u32 = 0x0004;

/// `DPNA_DATATYPE_*` — the address component types.
pub(crate) const DPNA_DATATYPE_STRING: u32 = 0x0000_0001;
pub(crate) const DPNA_DATATYPE_DWORD: u32 = 0x0000_0002;
pub(crate) const DPNA_DATATYPE_GUID: u32 = 0x0000_0003;
pub(crate) const DPNA_DATATYPE_BINARY: u32 = 0x0000_0004;
pub(crate) const DPNA_DATATYPE_STRING_ANSI: u32 = 0x0000_0005;
/// `DPNA_INDEX_INVALID`.
pub(crate) const DPNA_INDEX_INVALID: u32 = 0xFFFF_FFFF;

/// Address component keys (`dpaddr.h`).
pub(crate) const DPNA_HEADER: &str = "x-directplay:/";
pub(crate) const DPNA_KEY_APPLICATION_INSTANCE: &str = "applicationinstance";
pub(crate) const DPNA_KEY_DEVICE: &str = "device";
pub(crate) const DPNA_KEY_HOSTNAME: &str = "hostname";
pub(crate) const DPNA_KEY_PORT: &str = "port";
pub(crate) const DPNA_KEY_PROVIDER: &str = "provider";
pub(crate) const DPNA_KEY_PROGRAM: &str = "program";
pub(crate) const DPNA_VALUE_TCPIPPROVIDER: &str = "IP";

/// The TCP/IP DirectPlay8 service provider GUID `CLSID_DP8SP_TCPIP`
/// (`{EBFE7BA0-628D-11D2-AE0F-006097B01411}`) in Windows in-memory layout.
pub(crate) const CLSID_DP8SP_TCPIP: [u8; 16] = [
    0xa0, 0x7b, 0xfe, 0xeb, 0x8d, 0x62, 0xd2, 0x11, 0xae, 0x0f, 0x00, 0x60, 0x97, 0xb0, 0x14, 0x11,
];

/// `CLSID_DirectPlay8Address` (`{934A9523-A3CA-4BC5-ADA0-D6D95D979421}`).
pub(crate) const CLSID_DIRECTPLAY8_ADDRESS: [u8; 16] = [
    0x23, 0x95, 0x4a, 0x93, 0xca, 0xa3, 0xc5, 0x4b, 0xad, 0xa0, 0xd6, 0xd9, 0x5d, 0x97, 0x94, 0x21,
];
/// `IID_IDirectPlay8Address` (`{83783300-4063-4C8A-9DB3-82830A7FEB31}`).
pub(crate) const IID_IDIRECTPLAY8_ADDRESS: [u8; 16] = [
    0x00, 0x33, 0x78, 0x83, 0x63, 0x40, 0x8a, 0x4c, 0x9d, 0xb3, 0x82, 0x83, 0x0a, 0x7f, 0xeb, 0x31,
];
/// `CLSID_DirectPlay8Peer` (`{286F484D-375E-4458-A272-B138E2F80A6A}`).
pub(crate) const CLSID_DIRECTPLAY8_PEER: [u8; 16] = [
    0x4d, 0x48, 0x6f, 0x28, 0x5e, 0x37, 0x58, 0x44, 0xa2, 0x72, 0xb1, 0x38, 0xe2, 0xf8, 0x0a, 0x6a,
];
/// `IID_IDirectPlay8Peer` (`{5102DACF-241B-11D3-AEA7-006097B01411}`).
pub(crate) const IID_IDIRECTPLAY8_PEER: [u8; 16] = [
    0xcf, 0xda, 0x02, 0x51, 0x1b, 0x24, 0xd3, 0x11, 0xae, 0xa7, 0x00, 0x60, 0x97, 0xb0, 0x14, 0x11,
];
/// `IID_IUnknown`.
pub(crate) const IID_IUNKNOWN: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// The engine's documented MTU-safe application payload ceiling: a DirectPlay
/// message above this is rejected with `DPNERR_DATATOOLARGE` instead of being
/// fragmented or silently truncated.
pub(crate) const MAX_MESSAGE_PAYLOAD: usize = 1200;
/// The receive buffer for one datagram (larger than the payload ceiling so
/// oversized sends can be diagnosed rather than truncated).
const RECEIVE_BUFFER: usize = 65_535;
/// Default connect wait and enumeration windows.
pub(crate) const DEFAULT_CONNECT_TIMEOUT_MS: u32 = 5_000;
pub(crate) const DEFAULT_ENUM_TIMEOUT_MS: u32 = 500;
pub(crate) const DEFAULT_ENUM_RETRY_INTERVAL_MS: u32 = 250;
/// The keepalive interval reported by `GetCaps`.
pub(crate) const DEFAULT_KEEPALIVE_MS: u32 = 30_000;
/// The service thread wake-up period (also bounds `Close` latency).
const SERVICE_TICK_MS: u64 = 50;
/// The documented service receive-buffer size reported by `GetSPCaps`.
const SERVICE_SYSTEM_BUFFER_SIZE: u32 = 8192;

// ---------------------------------------------------------------------------
// GUID helpers
// ---------------------------------------------------------------------------

/// The canonical Windows GUID string for an in-memory GUID blob.
pub(crate) fn guid_to_string(guid: &[u8; 16]) -> String {
    format!(
        "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid[3],
        guid[2],
        guid[1],
        guid[0],
        guid[5],
        guid[4],
        guid[7],
        guid[6],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

/// Parse `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (braces optional) into the
/// Windows in-memory layout; `None` for anything malformed.
pub(crate) fn guid_from_string(text: &str) -> Option<[u8; 16]> {
    let trimmed = text.trim();
    let inner = if let Some(rest) = trimmed.strip_prefix('{') {
        rest.strip_suffix('}')?
    } else {
        trimmed
    };
    let parts: Vec<&str> = inner.split('-').collect();
    if parts.len() != 5 || parts[0].len() != 8 || parts[1].len() != 4 || parts[2].len() != 4 {
        return None;
    }
    if parts[3].len() != 4 || parts[4].len() != 12 {
        return None;
    }
    let d1 = u32::from_str_radix(parts[0], 16).ok()?;
    let d2 = u16::from_str_radix(parts[1], 16).ok()?;
    let d3 = u16::from_str_radix(parts[2], 16).ok()?;
    let flat: String = parts[3..].concat();
    if flat.len() != 16 {
        return None;
    }
    let mut data4 = [0u8; 8];
    for (index, byte) in data4.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&flat[index * 2..index * 2 + 2], 16).ok()?;
    }
    let mut guid = [0u8; 16];
    guid[0..4].copy_from_slice(&d1.to_le_bytes());
    guid[4..6].copy_from_slice(&d2.to_le_bytes());
    guid[6..8].copy_from_slice(&d3.to_le_bytes());
    guid[8..16].copy_from_slice(&data4);
    Some(guid)
}

/// A fresh v4 GUID blob.
pub(crate) fn random_guid() -> [u8; 16] {
    uuid::Uuid::new_v4().into_bytes()
}

// ---------------------------------------------------------------------------
// IDirectPlay8Address state model
// ---------------------------------------------------------------------------

/// One typed address component (`DPNA_DATATYPE_*` payload).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DplayAddressComponent {
    pub(crate) data_type: u32,
    pub(crate) data: Vec<u8>,
}

impl DplayAddressComponent {
    /// The UTF-16LE text of a string component.
    pub(crate) fn string(&self) -> Option<String> {
        if self.data_type != DPNA_DATATYPE_STRING {
            return None;
        }
        Some(decode_utf16_bytes(&self.data))
    }

    /// The DWORD value of a dword component.
    pub(crate) fn dword(&self) -> Option<u32> {
        if self.data_type != DPNA_DATATYPE_DWORD || self.data.len() < 4 {
            return None;
        }
        Some(u32::from_le_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ]))
    }

    /// The GUID value of a guid component.
    pub(crate) fn guid(&self) -> Option<[u8; 16]> {
        if self.data_type != DPNA_DATATYPE_GUID || self.data.len() != 16 {
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&self.data);
        Some(guid)
    }
}

/// The state of one `IDirectPlay8Address` object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Dplay8Address {
    components: Vec<(String, DplayAddressComponent)>,
    user_data: Vec<u8>,
}

impl Dplay8Address {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The number of stored components (the provider GUID counts as the
    /// `provider` component, exactly as the real address object stores it).
    pub(crate) fn num_components(&self) -> u32 {
        self.components.len() as u32
    }

    /// Find a component by name (case-insensitive, like the real object).
    pub(crate) fn component(&self, name: &str) -> Option<&DplayAddressComponent> {
        self.components
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, component)| component)
    }

    /// The component at `index`, if any.
    pub(crate) fn component_at(&self, index: u32) -> Option<(&str, &DplayAddressComponent)> {
        self.components
            .get(index as usize)
            .map(|(key, component)| (key.as_str(), component))
    }

    fn upsert(&mut self, name: &str, component: DplayAddressComponent) {
        if let Some(entry) = self
            .components
            .iter_mut()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
        {
            entry.1 = component;
        } else {
            self.components.push((name.to_string(), component));
        }
    }

    /// `AddComponent` — validate the type and payload size, then upsert.
    pub(crate) fn add_component(&mut self, name: &str, data_type: u32, data: &[u8]) -> u32 {
        if name.is_empty() || name.len() > 256 {
            return DPNERR_INVALIDPARAM;
        }
        match data_type {
            DPNA_DATATYPE_DWORD if data.len() == 4 => {}
            DPNA_DATATYPE_GUID if data.len() == 16 => {}
            DPNA_DATATYPE_STRING | DPNA_DATATYPE_STRING_ANSI if !data.is_empty() => {}
            DPNA_DATATYPE_BINARY if !data.is_empty() => {}
            _ => return DPNERR_INVALIDPARAM,
        }
        self.upsert(
            name,
            DplayAddressComponent {
                data_type,
                data: data.to_vec(),
            },
        );
        S_OK
    }

    /// `SetSP` — store the provider GUID as the `provider` component.
    pub(crate) fn set_sp(&mut self, guid: &[u8; 16]) -> u32 {
        self.upsert(
            DPNA_KEY_PROVIDER,
            DplayAddressComponent {
                data_type: DPNA_DATATYPE_GUID,
                data: guid.to_vec(),
            },
        );
        S_OK
    }

    /// `GetSP`.
    pub(crate) fn get_sp(&self) -> Option<[u8; 16]> {
        self.component(DPNA_KEY_PROVIDER)
            .and_then(DplayAddressComponent::guid)
    }

    /// `SetDevice` — store the adapter GUID as the `device` component.
    pub(crate) fn set_device(&mut self, guid: &[u8; 16]) -> u32 {
        self.upsert(
            DPNA_KEY_DEVICE,
            DplayAddressComponent {
                data_type: DPNA_DATATYPE_GUID,
                data: guid.to_vec(),
            },
        );
        S_OK
    }

    /// `GetDevice`.
    pub(crate) fn get_device(&self) -> Option<[u8; 16]> {
        self.component(DPNA_KEY_DEVICE)
            .and_then(DplayAddressComponent::guid)
    }

    /// `Clear`.
    pub(crate) fn clear(&mut self) {
        self.components.clear();
        self.user_data.clear();
    }

    /// `SetUserData` / `GetUserData`.
    pub(crate) fn set_user_data(&mut self, data: &[u8]) {
        self.user_data = data.to_vec();
    }

    pub(crate) fn user_data(&self) -> &[u8] {
        &self.user_data
    }

    /// `Duplicate`.
    pub(crate) fn duplicate(&self) -> Self {
        self.clone()
    }

    /// `SetEqual`.
    pub(crate) fn set_equal(&mut self, other: &Dplay8Address) {
        *self = other.clone();
    }

    /// `IsEqual` — provider/device/components/user data must all match.
    pub(crate) fn is_equal(&self, other: &Dplay8Address) -> bool {
        if self.components.len() != other.components.len() || self.user_data != other.user_data {
            return false;
        }
        self.components.iter().all(|(name, component)| {
            other
                .component(name)
                .is_some_and(|candidate| candidate == component)
        })
    }

    /// Convenience: store a UTF-16 component.
    pub(crate) fn set_string(&mut self, name: &str, value: &str) -> u32 {
        self.add_component(name, DPNA_DATATYPE_STRING, &encode_utf16_bytes(value))
    }

    /// Convenience: read a UTF-16 component.
    pub(crate) fn string(&self, name: &str) -> Option<String> {
        self.component(name).and_then(DplayAddressComponent::string)
    }

    /// Convenience: store a dword component.
    pub(crate) fn set_dword(&mut self, name: &str, value: u32) -> u32 {
        self.add_component(name, DPNA_DATATYPE_DWORD, &value.to_le_bytes())
    }

    /// Convenience: read a dword component.
    pub(crate) fn dword(&self, name: &str) -> Option<u32> {
        self.component(name).and_then(DplayAddressComponent::dword)
    }

    pub(crate) fn set_hostname(&mut self, hostname: &str) -> u32 {
        self.set_string(DPNA_KEY_HOSTNAME, hostname)
    }

    pub(crate) fn hostname(&self) -> Option<String> {
        self.string(DPNA_KEY_HOSTNAME)
    }

    /// `SetPort` — the `port` component is a DWORD (`DPNA_DATATYPE_DWORD`).
    pub(crate) fn set_port(&mut self, port: u16) -> u32 {
        self.set_dword(DPNA_KEY_PORT, u32::from(port))
    }

    pub(crate) fn port(&self) -> Option<u16> {
        self.dword(DPNA_KEY_PORT).map(|port| port as u16)
    }

    /// The engine-view socket address of this address object.  The hostname
    /// must be an IP literal or `localhost`; the port component supplies the
    /// port.  No port means port 0 (the ephemeral endpoint the caller
    /// resolves itself).
    pub(crate) fn socket_addr(&self) -> Option<SocketAddr> {
        let host = self.hostname();
        let port = self.port().unwrap_or(0);
        match host.as_deref() {
            None | Some("") | Some("0.0.0.0") => {
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
            }
            Some("localhost") => Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
            Some(name) => name
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, port)),
        }
    }

    /// `BuildFromURLW` / `BuildFromURLA` — parse the `x-directplay:/`
    /// component URL and replace this object's state.  Malformed text yields
    /// `DPNERR_INVALIDURL`.
    pub(crate) fn build_from_url(&mut self, url: &str) -> u32 {
        let trimmed = url.trim();
        if trimmed.len() < DPNA_HEADER.len()
            || !trimmed[..DPNA_HEADER.len()].eq_ignore_ascii_case(DPNA_HEADER)
        {
            return DPNERR_INVALIDURL;
        }
        let rest = &trimmed[DPNA_HEADER.len()..];
        let mut components: Vec<(String, DplayAddressComponent)> = Vec::new();
        let mut user_data = Vec::new();
        let mut body = rest;
        if let Some((before, after)) = split_unescaped(body, '#') {
            body = before;
            user_data = percent_decode(after.as_bytes());
        }
        for entry in split_all_unescaped(body, ';') {
            if entry.is_empty() {
                continue;
            }
            let Some((raw_key, raw_value)) = split_unescaped(entry, '=') else {
                return DPNERR_INVALIDURL;
            };
            let key = String::from_utf8(percent_decode(raw_key.as_bytes())).unwrap_or_default();
            let value = percent_decode(raw_value.as_bytes());
            if key.is_empty() {
                return DPNERR_INVALIDURL;
            }
            components.push((key.clone(), url_value_to_component(&key, &value)));
        }
        self.components = components;
        self.user_data = user_data;
        S_OK
    }

    /// `GetURLW` / `GetURLA` — the canonical `x-directplay:/` URL of this
    /// object.  The provider component is emitted first, the remaining
    /// components in insertion order, percent-escaping the separators.
    pub(crate) fn url(&self) -> String {
        let mut out = String::from(DPNA_HEADER);
        let mut first = true;
        let mut ordered: Vec<&(String, DplayAddressComponent)> = Vec::new();
        if let Some(provider) = self
            .components
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(DPNA_KEY_PROVIDER))
        {
            ordered.push(provider);
        }
        ordered.extend(
            self.components
                .iter()
                .filter(|(key, _)| !key.eq_ignore_ascii_case(DPNA_KEY_PROVIDER)),
        );
        for (key, component) in ordered {
            if !first {
                out.push(';');
            }
            first = false;
            out.push_str(&percent_encode(key.as_bytes()));
            out.push('=');
            out.push_str(&percent_encode(&component_to_url_value(key, component)));
        }
        if !self.user_data.is_empty() {
            out.push('#');
            out.push_str(&percent_encode(&self.user_data));
        }
        out
    }
}

/// Decode a UTF-16LE byte string into text (unpaired surrogates are replaced).
fn decode_utf16_bytes(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Encode text into UTF-16LE bytes (no terminator; the guest ABI adds NULs).
pub(crate) fn encode_utf16_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// The component payload a URL value maps to: known keys get their typed
/// form, everything else stays a string component.
fn url_value_to_component(key: &str, value: &[u8]) -> DplayAddressComponent {
    if key.eq_ignore_ascii_case(DPNA_KEY_PORT) {
        if let Ok(text) = std::str::from_utf8(value) {
            if let Ok(port) = text.trim().parse::<u32>() {
                return DplayAddressComponent {
                    data_type: DPNA_DATATYPE_DWORD,
                    data: port.to_le_bytes().to_vec(),
                };
            }
        }
    }
    if key.eq_ignore_ascii_case(DPNA_KEY_PROVIDER) {
        if let Ok(text) = std::str::from_utf8(value) {
            if text.eq_ignore_ascii_case(DPNA_VALUE_TCPIPPROVIDER) {
                return DplayAddressComponent {
                    data_type: DPNA_DATATYPE_GUID,
                    data: CLSID_DP8SP_TCPIP.to_vec(),
                };
            }
            if let Some(guid) = guid_from_string(text) {
                return DplayAddressComponent {
                    data_type: DPNA_DATATYPE_GUID,
                    data: guid.to_vec(),
                };
            }
        }
    }
    if key.eq_ignore_ascii_case(DPNA_KEY_DEVICE)
        || key.eq_ignore_ascii_case(DPNA_KEY_APPLICATION_INSTANCE)
    {
        if let Ok(text) = std::str::from_utf8(value) {
            if let Some(guid) = guid_from_string(text) {
                return DplayAddressComponent {
                    data_type: DPNA_DATATYPE_GUID,
                    data: guid.to_vec(),
                };
            }
        }
    }
    DplayAddressComponent {
        data_type: DPNA_DATATYPE_STRING,
        data: encode_utf16_bytes(&String::from_utf8_lossy(value)),
    }
}

/// The URL text of a component value.
fn component_to_url_value(key: &str, component: &DplayAddressComponent) -> Vec<u8> {
    match component.data_type {
        DPNA_DATATYPE_DWORD => component
            .dword()
            .map(|value| value.to_string().into_bytes())
            .unwrap_or_default(),
        DPNA_DATATYPE_GUID => match component.guid() {
            Some(guid) if guid == CLSID_DP8SP_TCPIP => DPNA_VALUE_TCPIPPROVIDER.as_bytes().to_vec(),
            Some(guid) => guid_to_string(&guid).into_bytes(),
            None => Vec::new(),
        },
        DPNA_DATATYPE_BINARY => {
            let mut text = String::new();
            for byte in &component.data {
                text.push_str(&format!("{byte:02x}"));
            }
            text.into_bytes()
        }
        _ => {
            let _ = key;
            decode_utf16_bytes(&component.data).into_bytes()
        }
    }
}

fn percent_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for byte in data {
        match *byte {
            b'%' | b';' | b'=' | b'#' => out.push_str(&format!("%{byte:02X}")),
            0x20..=0x7e => out.push(*byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn percent_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        if data[index] == b'%' && index + 2 < data.len() {
            if let Ok(value) = u8::from_str_radix(
                std::str::from_utf8(&data[index + 1..index + 3]).unwrap_or(""),
                16,
            ) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(data[index]);
        index += 1;
    }
    out
}

/// Split at the first occurrence of `separator`.
fn split_unescaped(data: &str, separator: char) -> Option<(&str, &str)> {
    data.find(separator)
        .map(|index| (&data[..index], &data[index + separator.len_utf8()..]))
}

/// Split at every occurrence of `separator`.
fn split_all_unescaped(data: &str, separator: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut rest = data;
    while let Some((head, tail)) = split_unescaped(rest, separator) {
        parts.push(head);
        rest = tail;
    }
    parts.push(rest);
    parts
}

// ---------------------------------------------------------------------------
// Application descriptor and engine results
// ---------------------------------------------------------------------------

/// The engine subset of `DPN_APPLICATION_DESC`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DplayAppDesc {
    pub(crate) flags: u32,
    pub(crate) instance_guid: [u8; 16],
    pub(crate) application_guid: [u8; 16],
    pub(crate) max_players: u32,
    pub(crate) current_players: u32,
    pub(crate) session_name: String,
    pub(crate) password: String,
}

impl DplayAppDesc {
    pub(crate) fn new(session_name: &str, max_players: u32) -> Self {
        Self {
            session_name: session_name.to_string(),
            max_players,
            ..Default::default()
        }
    }
}

/// A received application datagram and its sender.
#[derive(Clone, Debug)]
pub(crate) struct ReceivedDatagram {
    pub(crate) from_dpnid: u32,
    pub(crate) from_addr: SocketAddr,
    pub(crate) data: Vec<u8>,
}

/// One player known to a peer.
#[derive(Clone, Debug)]
pub(crate) struct PlayerInfo {
    pub(crate) dpnid: u32,
    pub(crate) name: String,
    pub(crate) addr: SocketAddr,
    pub(crate) flags: u32,
}

/// One discovered session from `EnumHosts`.
#[derive(Clone, Debug)]
pub(crate) struct SessionInfo {
    pub(crate) address: SocketAddr,
    pub(crate) instance_guid: [u8; 16],
    pub(crate) application_guid: [u8; 16],
    pub(crate) session_name: String,
    pub(crate) current_players: u32,
    pub(crate) max_players: u32,
    pub(crate) latency_ms: u32,
}

/// `GetCaps` values, derived from the engine's real transport settings.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DplayCaps {
    pub(crate) flags: u32,
    pub(crate) connect_timeout_ms: u32,
    pub(crate) connect_retries: u32,
    pub(crate) timeout_until_keep_alive_ms: u32,
}

/// `GetSPCaps` values, derived from the real service thread/socket facts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DplaySpCaps {
    pub(crate) flags: u32,
    pub(crate) num_threads: u32,
    pub(crate) default_enum_count: u32,
    pub(crate) default_enum_retry_interval_ms: u32,
    pub(crate) default_enum_timeout_ms: u32,
    pub(crate) max_enum_payload_size: u32,
    pub(crate) buffers_per_thread: u32,
    pub(crate) system_buffer_size: u32,
}

/// `DPN_CONNECTION_INFO` counters, fed by the real send/receive paths.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DplayConnectionInfo {
    pub(crate) round_trip_latency_ms: u32,
    pub(crate) bytes_sent: u64,
    pub(crate) packets_sent: u64,
    pub(crate) bytes_received: u64,
    pub(crate) packets_received: u64,
    pub(crate) messages_received: u64,
}

// ---------------------------------------------------------------------------
// Wire messages
// ---------------------------------------------------------------------------

const MAGIC_QUERY: &[u8; 4] = b"DP8Q";
const MAGIC_RESPONSE: &[u8; 4] = b"DP8R";
const MAGIC_CONNECT: &[u8; 4] = b"DP8C";
const MAGIC_ACCEPT: &[u8; 4] = b"DP8A";
const MAGIC_REJECT: &[u8; 4] = b"DP8F";
const MAGIC_JOIN: &[u8; 4] = b"DP8J";
const MAGIC_LEAVE: &[u8; 4] = b"DP8X";
const MAGIC_DATA: &[u8; 4] = b"DP8D";
const MAGIC_TERMINATE: &[u8; 4] = b"DP8S";
const MAGIC_KEEPALIVE: &[u8; 4] = b"DP8P";
const MAGIC_GROUP: &[u8; 4] = b"DP8G";
const MAGIC_GROUP_DATA: &[u8; 4] = b"DP8M";
const MAGIC_ACK: &[u8; 4] = b"DP8K";
const GROUP_OP_CREATE: u8 = 1;
const GROUP_OP_DESTROY: u8 = 2;
const GROUP_OP_ADD_MEMBER: u8 = 3;
const GROUP_OP_REMOVE_MEMBER: u8 = 4;
const GROUP_OP_INFO: u8 = 5;
const GROUP_OP_ALLOCATE_REQUEST: u8 = 6;
const GROUP_OP_ALLOCATE_RESPONSE: u8 = 7;
/// Reliable group-control retry window: one retransmission per interval, up
/// to the attempt cap, before the message is considered undeliverable.
const GROUP_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const MAX_GROUP_SEND_ATTEMPTS: u32 = 20;
/// How many sender sequence numbers a receiver remembers for duplicate
/// suppression (the transport itself is a lossy, unordered datagram link).
const MAX_TRACKED_GROUP_SEQUENCES: usize = 4096;
const WIRE_PROTOCOL_VERSION: u8 = 1;

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, data: &[u8]) {
    put_u16(out, data.len().min(u16::MAX as usize) as u16);
    out.extend_from_slice(data);
}

fn get_u16(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn get_u32(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn get_guid(data: &[u8], at: usize) -> Option<[u8; 16]> {
    let bytes = data.get(at..at + 16)?;
    let mut guid = [0u8; 16];
    guid.copy_from_slice(bytes);
    Some(guid)
}

fn starts_with_magic(data: &[u8], magic: &[u8; 4]) -> bool {
    data.len() >= 4 && &data[..4] == magic
}

/// `DP8Q` encoder (layout in the module docs).
fn wire_query(query_id: u32, application_guid: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(25);
    out.extend_from_slice(MAGIC_QUERY);
    out.push(WIRE_PROTOCOL_VERSION);
    put_u32(&mut out, query_id);
    out.extend_from_slice(application_guid);
    out
}

fn parse_query(data: &[u8]) -> Option<(u8, u32, [u8; 16])> {
    if !starts_with_magic(data, MAGIC_QUERY) || data.len() < 25 {
        return None;
    }
    let version = data[4];
    let query_id = get_u32(data, 5)?;
    let application_guid = get_guid(data, 9)?;
    Some((version, query_id, application_guid))
}

/// `DP8R` encoder.
fn wire_response(query_id: u32, session: &SessionShared) -> Vec<u8> {
    let mut out = Vec::with_capacity(53 + session.name.len());
    out.extend_from_slice(MAGIC_RESPONSE);
    put_u32(&mut out, query_id);
    out.extend_from_slice(&session.instance_guid);
    out.extend_from_slice(&session.app_guid);
    put_u32(&mut out, session.max_players);
    put_u32(&mut out, 1 + session.remote_player_count());
    put_bytes(&mut out, session.name.as_bytes());
    out
}

fn parse_response(data: &[u8], from: SocketAddr) -> Option<SessionInfo> {
    if !starts_with_magic(data, MAGIC_RESPONSE) || data.len() < 52 {
        return None;
    }
    let instance_guid = get_guid(data, 8)?;
    let application_guid = get_guid(data, 24)?;
    let max_players = get_u32(data, 40)?;
    let current_players = get_u32(data, 44)?;
    let name_len = get_u16(data, 48)? as usize;
    let name = data
        .get(50..50 + name_len)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default();
    Some(SessionInfo {
        address: from,
        instance_guid,
        application_guid,
        session_name: name,
        current_players,
        max_players,
        latency_ms: 0,
    })
}

/// `DP8C` encoder.
fn wire_connect(
    request_id: u32,
    application_instance: &[u8; 16],
    player_name: &str,
    connect_data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(28 + player_name.len() + connect_data.len());
    out.extend_from_slice(MAGIC_CONNECT);
    put_u32(&mut out, request_id);
    out.extend_from_slice(application_instance);
    put_bytes(&mut out, player_name.as_bytes());
    put_bytes(&mut out, connect_data);
    out
}

fn parse_connect(data: &[u8]) -> Option<(u32, [u8; 16], String, Vec<u8>)> {
    if !starts_with_magic(data, MAGIC_CONNECT) || data.len() < 26 {
        return None;
    }
    let request_id = get_u32(data, 4)?;
    let instance = get_guid(data, 8)?;
    let name_len = get_u16(data, 24)? as usize;
    let name = data
        .get(26..26 + name_len)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())?;
    let data_len = get_u16(data, 26 + name_len)? as usize;
    let connect_data = data
        .get(28 + name_len..28 + name_len + data_len)
        .map(|bytes| bytes.to_vec())?;
    Some((request_id, instance, name, connect_data))
}

/// `DP8A` encoder.
fn wire_accept(
    request_id: u32,
    assigned_dpnid: u32,
    host_dpnid: u32,
    players: &[(u32, String)],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + players.len() * 8);
    out.extend_from_slice(MAGIC_ACCEPT);
    put_u32(&mut out, request_id);
    put_u32(&mut out, assigned_dpnid);
    put_u32(&mut out, host_dpnid);
    put_u32(&mut out, players.len() as u32);
    for (dpnid, name) in players {
        put_u32(&mut out, *dpnid);
        put_bytes(&mut out, name.as_bytes());
    }
    out
}

fn parse_accept(data: &[u8]) -> Option<(u32, u32, u32, Vec<(u32, String)>)> {
    if !starts_with_magic(data, MAGIC_ACCEPT) || data.len() < 20 {
        return None;
    }
    let request_id = get_u32(data, 4)?;
    let assigned = get_u32(data, 8)?;
    let host = get_u32(data, 12)?;
    let count = get_u32(data, 16)? as usize;
    let mut players = Vec::with_capacity(count.min(64));
    let mut offset = 20;
    for _ in 0..count.min(64) {
        let dpnid = get_u32(data, offset)?;
        let name_len = get_u16(data, offset + 4)? as usize;
        let name = data
            .get(offset + 6..offset + 6 + name_len)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())?;
        players.push((dpnid, name));
        offset += 6 + name_len;
    }
    Some((request_id, assigned, host, players))
}

/// `DP8F` encoder.
fn wire_reject(request_id: u32, reason: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(MAGIC_REJECT);
    put_u32(&mut out, request_id);
    put_u32(&mut out, reason);
    out
}

fn parse_reject(data: &[u8]) -> Option<(u32, u32)> {
    if !starts_with_magic(data, MAGIC_REJECT) || data.len() < 12 {
        return None;
    }
    Some((get_u32(data, 4)?, get_u32(data, 8)?))
}

/// `DP8J` encoder.
fn wire_join(dpnid: u32, name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + name.len());
    out.extend_from_slice(MAGIC_JOIN);
    put_u32(&mut out, dpnid);
    put_bytes(&mut out, name.as_bytes());
    out
}

fn parse_join(data: &[u8]) -> Option<(u32, String)> {
    if !starts_with_magic(data, MAGIC_JOIN) || data.len() < 10 {
        return None;
    }
    let dpnid = get_u32(data, 4)?;
    let name_len = get_u16(data, 8)? as usize;
    let name = data
        .get(10..10 + name_len)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())?;
    Some((dpnid, name))
}

/// `DP8X` encoder.
fn wire_leave(dpnid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(MAGIC_LEAVE);
    put_u32(&mut out, dpnid);
    out
}

fn parse_leave(data: &[u8]) -> Option<u32> {
    if !starts_with_magic(data, MAGIC_LEAVE) || data.len() < 8 {
        return None;
    }
    get_u32(data, 4)
}

/// `DP8D` encoder.
fn wire_data(source: u32, destination: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.extend_from_slice(MAGIC_DATA);
    put_u32(&mut out, source);
    put_u32(&mut out, destination);
    out.extend_from_slice(payload);
    out
}

fn parse_data(data: &[u8]) -> Option<(u32, u32, &[u8])> {
    if !starts_with_magic(data, MAGIC_DATA) || data.len() < 12 {
        return None;
    }
    Some((get_u32(data, 4)?, get_u32(data, 8)?, &data[12..]))
}

/// `DP8S` encoder.
fn wire_terminate(reason: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len());
    out.extend_from_slice(MAGIC_TERMINATE);
    put_u32(&mut out, reason);
    out.extend_from_slice(data);
    out
}

fn parse_terminate(data: &[u8]) -> Option<(u32, &[u8])> {
    if !starts_with_magic(data, MAGIC_TERMINATE) || data.len() < 8 {
        return None;
    }
    Some((get_u32(data, 4)?, &data[8..]))
}

/// A decoded `DP8G` group operation.  Every reliable group message carries
/// the sending player id and a per-sender sequence number; receivers use the
/// pair to suppress retransmitted duplicates and acknowledge receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
enum GroupWire {
    Create {
        sender: u32,
        sequence: u32,
        group_id: u32,
        owner: u32,
        name: String,
        data: Vec<u8>,
    },
    Destroy {
        sender: u32,
        sequence: u32,
        group_id: u32,
    },
    AddMember {
        sender: u32,
        sequence: u32,
        group_id: u32,
        dpnid: u32,
    },
    RemoveMember {
        sender: u32,
        sequence: u32,
        group_id: u32,
        dpnid: u32,
    },
    Info {
        sender: u32,
        sequence: u32,
        group_id: u32,
        name: String,
        data: Vec<u8>,
    },
    AllocateRequest {
        sender: u32,
        sequence: u32,
        owner: u32,
        name: String,
        data: Vec<u8>,
    },
    AllocateResponse {
        sender: u32,
        sequence: u32,
        group_id: u32,
        client: u32,
        request_sequence: u32,
        result: u32,
    },
}

fn group_header(out: &mut Vec<u8>, op: u8, group_id: u32, sender: u32, sequence: u32) {
    out.extend_from_slice(MAGIC_GROUP);
    out.push(op);
    put_u32(out, group_id);
    put_u32(out, sender);
    put_u32(out, sequence);
}

/// `DP8G` create encoder.
fn wire_group_create(
    sender: u32,
    sequence: u32,
    group_id: u32,
    owner: u32,
    name: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(23 + name.len() + data.len());
    group_header(&mut out, GROUP_OP_CREATE, group_id, sender, sequence);
    put_u32(&mut out, owner);
    put_bytes(&mut out, name.as_bytes());
    put_bytes(&mut out, data);
    out
}

/// `DP8G` destroy encoder.
fn wire_group_destroy(sender: u32, sequence: u32, group_id: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    group_header(&mut out, GROUP_OP_DESTROY, group_id, sender, sequence);
    out
}

/// `DP8G` add/remove member encoder.
fn wire_group_member(op: u8, sender: u32, sequence: u32, group_id: u32, dpnid: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(21);
    group_header(&mut out, op, group_id, sender, sequence);
    put_u32(&mut out, dpnid);
    out
}

/// `DP8G` info/context encoder.
fn wire_group_info(sender: u32, sequence: u32, group_id: u32, name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(19 + name.len() + data.len());
    group_header(&mut out, GROUP_OP_INFO, group_id, sender, sequence);
    put_bytes(&mut out, name.as_bytes());
    put_bytes(&mut out, data);
    out
}

/// `DP8G` client-to-host group id allocation request.
fn wire_group_allocate_request(
    sender: u32,
    sequence: u32,
    owner: u32,
    name: &str,
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(23 + name.len() + data.len());
    group_header(&mut out, GROUP_OP_ALLOCATE_REQUEST, 0, sender, sequence);
    put_u32(&mut out, owner);
    put_bytes(&mut out, name.as_bytes());
    put_bytes(&mut out, data);
    out
}

/// `DP8G` host-to-client group id allocation answer.
fn wire_group_allocate_response(
    sender: u32,
    sequence: u32,
    group_id: u32,
    client: u32,
    request_sequence: u32,
    result: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(29);
    group_header(
        &mut out,
        GROUP_OP_ALLOCATE_RESPONSE,
        group_id,
        sender,
        sequence,
    );
    put_u32(&mut out, client);
    put_u32(&mut out, request_sequence);
    put_u32(&mut out, result);
    out
}

fn parse_group(data: &[u8]) -> Option<GroupWire> {
    if !starts_with_magic(data, MAGIC_GROUP) || data.len() < 17 {
        return None;
    }
    let op = data[4];
    let group_id = get_u32(data, 5)?;
    let sender = get_u32(data, 9)?;
    let sequence = get_u32(data, 13)?;
    match op {
        GROUP_OP_CREATE | GROUP_OP_ALLOCATE_REQUEST => {
            let owner = get_u32(data, 17)?;
            let name_len = get_u16(data, 21)? as usize;
            let name = data.get(23..23 + name_len)?;
            let data_len = get_u16(data, 23 + name_len)? as usize;
            let payload = data.get(25 + name_len..25 + name_len + data_len)?;
            if op == GROUP_OP_CREATE {
                Some(GroupWire::Create {
                    sender,
                    sequence,
                    group_id,
                    owner,
                    name: String::from_utf8_lossy(name).into_owned(),
                    data: payload.to_vec(),
                })
            } else {
                Some(GroupWire::AllocateRequest {
                    sender,
                    sequence,
                    owner,
                    name: String::from_utf8_lossy(name).into_owned(),
                    data: payload.to_vec(),
                })
            }
        }
        GROUP_OP_DESTROY => Some(GroupWire::Destroy {
            sender,
            sequence,
            group_id,
        }),
        GROUP_OP_ADD_MEMBER | GROUP_OP_REMOVE_MEMBER => {
            let dpnid = get_u32(data, 17)?;
            if op == GROUP_OP_ADD_MEMBER {
                Some(GroupWire::AddMember {
                    sender,
                    sequence,
                    group_id,
                    dpnid,
                })
            } else {
                Some(GroupWire::RemoveMember {
                    sender,
                    sequence,
                    group_id,
                    dpnid,
                })
            }
        }
        GROUP_OP_INFO => {
            let name_len = get_u16(data, 17)? as usize;
            let name = data.get(19..19 + name_len)?;
            let data_len = get_u16(data, 19 + name_len)? as usize;
            let payload = data.get(21 + name_len..21 + name_len + data_len)?;
            Some(GroupWire::Info {
                sender,
                sequence,
                group_id,
                name: String::from_utf8_lossy(name).into_owned(),
                data: payload.to_vec(),
            })
        }
        GROUP_OP_ALLOCATE_RESPONSE => {
            let client = get_u32(data, 17)?;
            let request_sequence = get_u32(data, 21)?;
            let result = get_u32(data, 25)?;
            Some(GroupWire::AllocateResponse {
                sender,
                sequence,
                group_id,
                client,
                request_sequence,
                result,
            })
        }
        _ => None,
    }
}

/// `DP8M` reliable group-addressed application data encoder.
fn wire_group_data(source: u32, destination: u32, sequence: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(MAGIC_GROUP_DATA);
    put_u32(&mut out, source);
    put_u32(&mut out, destination);
    put_u32(&mut out, sequence);
    out.extend_from_slice(payload);
    out
}

fn parse_group_data(data: &[u8]) -> Option<(u32, u32, u32, &[u8])> {
    if !starts_with_magic(data, MAGIC_GROUP_DATA) || data.len() < 16 {
        return None;
    }
    Some((
        get_u32(data, 4)?,
        get_u32(data, 8)?,
        get_u32(data, 12)?,
        &data[16..],
    ))
}

/// `DP8K` group acknowledgement (sequence + acknowledging player).
fn wire_group_ack(sender: u32, sequence: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(MAGIC_ACK);
    put_u32(&mut out, sender);
    put_u32(&mut out, sequence);
    out
}

fn parse_group_ack(data: &[u8]) -> Option<(u32, u32)> {
    if !starts_with_magic(data, MAGIC_ACK) || data.len() < 12 {
        return None;
    }
    Some((get_u32(data, 4)?, get_u32(data, 8)?))
}

// ---------------------------------------------------------------------------
// Shared runtime pieces
// ---------------------------------------------------------------------------

/// A condition-variable receive queue with two independent consumers:
/// [`Dplay8Peer::receive_from`] (manual receive) and the registered message
/// handler.  Every transport datagram is appended to both queues, exactly like
/// the Windows service provider: an application that consumes a datagram with
/// `ReceiveFrom` still sees the same datagram through its message handler, and
/// each consumer observes every datagram at most once.
struct InboundQueue {
    manual: Mutex<VecDeque<ReceivedDatagram>>,
    handler: Mutex<VecDeque<ReceivedDatagram>>,
    cv: Condvar,
}

impl InboundQueue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            manual: Mutex::new(VecDeque::new()),
            handler: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        })
    }

    fn push(&self, message: ReceivedDatagram) {
        self.manual
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push_back(message.clone());
        self.handler
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push_back(message);
        self.cv.notify_all();
    }

    fn pop_timeout(&self, timeout: Duration) -> Option<ReceivedDatagram> {
        let deadline = Instant::now() + timeout;
        let mut queue = self
            .manual
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        loop {
            if let Some(message) = queue.pop_front() {
                return Some(message);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _) = self
                .cv
                .wait_timeout(queue, deadline - now)
                .unwrap_or_else(|poison| poison.into_inner());
            queue = guard;
        }
    }

    fn pop_handler(&self) -> Option<ReceivedDatagram> {
        self.handler
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .pop_front()
    }

    fn len(&self) -> usize {
        self.manual
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .len()
    }
}

/// Events produced by the transport threads for the guest-visible peer state.
#[derive(Clone, Debug)]
pub(crate) enum SessionEvent {
    PlayerJoined { dpnid: u32, name: String },
    PlayerLeft { dpnid: u32, reason: u32 },
    Terminated { reason: u32 },
}

struct EventQueue {
    queue: Mutex<VecDeque<SessionEvent>>,
}

impl EventQueue {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
        })
    }

    fn push(&self, event: SessionEvent) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        queue.push_back(event);
    }

    fn drain(&self) -> Vec<SessionEvent> {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        queue.drain(..).collect()
    }
}

/// One remote player on a hosted session.
#[derive(Clone, Debug)]
struct PlayerRecord {
    dpnid: u32,
    name: String,
    addr: SocketAddr,
}

/// One reliable group message awaiting acknowledgement.
struct PendingGroupMessage {
    message: Vec<u8>,
    destinations: BTreeSet<SocketAddr>,
    attempts: u32,
    next_retry: Instant,
}

/// The reliable layer over the unordered UDP group link: a per-sender
/// sequence space, an acknowledgement/retransmission table and the set of
/// sequence numbers already applied (duplicate suppression).
#[derive(Default)]
struct GroupReliability {
    next_sequence: u32,
    pending: BTreeMap<u32, PendingGroupMessage>,
    seen: BTreeMap<u32, BTreeSet<u32>>,
    duplicates_suppressed: u64,
}

impl GroupReliability {
    fn allocate_sequence(&mut self) -> u32 {
        let sequence = self.next_sequence.max(1);
        self.next_sequence = sequence.wrapping_add(1).max(1);
        sequence
    }

    fn record_pending(
        &mut self,
        sequence: u32,
        message: Vec<u8>,
        destinations: BTreeSet<SocketAddr>,
    ) {
        if destinations.is_empty() {
            return;
        }
        self.pending.insert(
            sequence,
            PendingGroupMessage {
                message,
                destinations,
                attempts: 1,
                next_retry: Instant::now() + GROUP_RETRY_INTERVAL,
            },
        );
    }

    /// Remember an inbound sequence.  Returns `true` for the first delivery,
    /// `false` for a retransmitted duplicate (which must be acknowledged but
    /// not applied or delivered again).
    fn note_inbound(&mut self, sender: u32, sequence: u32) -> bool {
        let seen = self.seen.entry(sender).or_default();
        if seen.contains(&sequence) {
            self.duplicates_suppressed = self.duplicates_suppressed.saturating_add(1);
            return false;
        }
        seen.insert(sequence);
        while seen.len() > MAX_TRACKED_GROUP_SEQUENCES {
            let Some(first) = seen.iter().next().copied() else {
                break;
            };
            seen.remove(&first);
        }
        true
    }

    fn acknowledge(&mut self, sequence: u32, from: Option<SocketAddr>) {
        if let Some(from) = from {
            if let Some(pending) = self.pending.get_mut(&sequence) {
                pending.destinations.remove(&from);
                if pending.destinations.is_empty() {
                    self.pending.remove(&sequence);
                }
            }
        } else {
            self.pending.remove(&sequence);
        }
    }

    fn cancel(&mut self, sequence: u32) {
        self.pending.remove(&sequence);
    }

    fn clear(&mut self) {
        self.pending.clear();
        self.seen.clear();
    }

    /// Retransmit every message whose retry interval elapsed.  Messages that
    /// exceed the bounded attempt count are dropped.
    fn retransmit(&mut self, mut send: impl FnMut(&[u8], SocketAddr)) {
        let now = Instant::now();
        let mut exhausted = Vec::new();
        for (sequence, pending) in self.pending.iter_mut() {
            if now < pending.next_retry {
                continue;
            }
            if pending.attempts >= MAX_GROUP_SEND_ATTEMPTS {
                exhausted.push(*sequence);
                continue;
            }
            for destination in pending.destinations.clone() {
                send(&pending.message, destination);
            }
            pending.attempts = pending.attempts.saturating_add(1);
            pending.next_retry = now + GROUP_RETRY_INTERVAL;
        }
        for sequence in exhausted {
            self.pending.remove(&sequence);
        }
    }
}

/// Host-authoritative group id allocation: the answer the host gave for one
/// client request, kept so a retransmitted request gets the same answer.
#[derive(Clone, Copy, Debug)]
struct GroupAllocation {
    group_id: u32,
    result: u32,
}

/// A hosted session: its real socket, its players and its service thread.
struct SessionShared {
    instance_guid: [u8; 16],
    app_guid: [u8; 16],
    name: String,
    max_players: u32,
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
    players: Mutex<BTreeMap<u32, PlayerRecord>>,
    next_dpnid: AtomicU32,
    groups: Mutex<BTreeMap<u32, GroupRecord>>,
    inbound: Arc<InboundQueue>,
    events: Arc<EventQueue>,
    reliability: Mutex<GroupReliability>,
    allocations: Mutex<BTreeMap<(u32, u32), GroupAllocation>>,
    drop_group_datagrams: AtomicU32,
    drop_ack_datagrams: AtomicU32,
    closing: AtomicBool,
    service: Mutex<Option<JoinHandle<()>>>,
}

impl SessionShared {
    fn remote_player_count(&self) -> u32 {
        self.players
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .len() as u32
    }

    fn player_addr(&self, dpnid: u32) -> Option<SocketAddr> {
        self.players
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&dpnid)
            .map(|player| player.addr)
    }

    fn snapshot_players(&self) -> Vec<PlayerRecord> {
        self.players
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .values()
            .cloned()
            .collect()
    }

    fn player_by_addr(&self, addr: SocketAddr) -> Option<u32> {
        self.players
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .values()
            .find(|player| player.addr == addr)
            .map(|player| player.dpnid)
    }

    fn group(&self, group_id: u32) -> Option<GroupRecord> {
        self.groups
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&group_id)
            .cloned()
    }

    fn group_snapshot(&self) -> Vec<GroupRecord> {
        self.groups
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .values()
            .cloned()
            .collect()
    }

    fn send_reliable_group(
        &self,
        destinations: BTreeSet<SocketAddr>,
        build: impl FnOnce(u32) -> Vec<u8>,
    ) {
        if destinations.is_empty() {
            return;
        }
        let mut reliability = self
            .reliability
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let sequence = reliability.allocate_sequence();
        let message = build(sequence);
        for destination in &destinations {
            let _ = self.socket.send_to(&message, *destination);
        }
        reliability.record_pending(sequence, message, destinations);
    }

    fn broadcast_reliable_group(&self, build: impl FnOnce(u32) -> Vec<u8>) {
        let destinations: BTreeSet<SocketAddr> = self
            .snapshot_players()
            .into_iter()
            .map(|player| player.addr)
            .collect();
        self.send_reliable_group(destinations, build);
    }

    fn relay_reliable_group(&self, except: u32, build: impl FnOnce(u32) -> Vec<u8>) {
        let destinations: BTreeSet<SocketAddr> = self
            .snapshot_players()
            .into_iter()
            .filter(|player| player.dpnid != except)
            .map(|player| player.addr)
            .collect();
        self.send_reliable_group(destinations, build);
    }

    fn send_group_ack(&self, destination: SocketAddr, sequence: u32) {
        let _ = self
            .socket
            .send_to(&wire_group_ack(HOST_PLAYER_ID, sequence), destination);
    }

    fn retransmit_group(&self) {
        let socket = Arc::clone(&self.socket);
        self.reliability
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .retransmit(move |message, destination| {
                let _ = socket.send_to(message, destination);
            });
    }
}

/// The process-wide registry of sessions hosted by this runtime (one entry
/// per real bound UDP endpoint).  `EnumHosts` and `DirectPlayEnumerateW` use
/// it as the local discovery seed; the wire query is still sent over UDP.
static LOCAL_SESSIONS: LazyLock<Mutex<BTreeMap<u64, Arc<SessionShared>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_REQUEST_ID: AtomicU32 = AtomicU32::new(1);

fn lock_sessions() -> MutexGuard<'static, BTreeMap<u64, Arc<SessionShared>>> {
    LOCAL_SESSIONS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn local_session_addresses() -> Vec<SocketAddr> {
    lock_sessions()
        .values()
        .map(|session| session.addr)
        .collect()
}

/// The real hosted sessions (for `DirectPlayEnumerateW`).
pub(crate) fn hosted_sessions() -> Vec<SessionInfo> {
    lock_sessions()
        .values()
        .map(|session| SessionInfo {
            address: session.addr,
            instance_guid: session.instance_guid,
            application_guid: session.app_guid,
            session_name: session.name.clone(),
            current_players: 1 + session.remote_player_count(),
            max_players: session.max_players,
            latency_ms: 0,
        })
        .collect()
}

/// Look up a session by instance GUID (the legacy `Open` path).
pub(crate) fn session_by_instance(instance_guid: &[u8; 16]) -> Option<SocketAddr> {
    lock_sessions()
        .values()
        .find(|session| &session.instance_guid == instance_guid)
        .map(|session| session.addr)
}

/// Counter block shared with the transport threads.
#[derive(Default)]
struct Counters {
    bytes_sent: AtomicU64,
    packets_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_received: AtomicU64,
}

/// The host's answer to a successful `DP8C`.
#[derive(Clone, Debug)]
struct ConnectAccept {
    assigned: u32,
    host: u32,
    players: Vec<(u32, String)>,
}

/// A pending `Connect` result.
struct ConnectWait {
    state: Mutex<Option<Result<ConnectAccept, u32>>>,
    cv: Condvar,
}

impl ConnectWait {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(None),
            cv: Condvar::new(),
        })
    }

    fn complete(&self, result: Result<ConnectAccept, u32>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.is_none() {
            *state = Some(result);
            self.cv.notify_all();
        }
    }

    fn wait(&self, timeout: Duration) -> Option<Result<ConnectAccept, u32>> {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        loop {
            if let Some(result) = state.clone() {
                return Some(result);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _) = self
                .cv
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poison| poison.into_inner());
            state = guard;
        }
    }
}

/// Reset a socket for the service/receiver loops.
fn configure_socket(socket: &UdpSocket) {
    let _ = socket.set_read_timeout(Some(Duration::from_millis(SERVICE_TICK_MS)));
}

fn map_bind_error(error: &io::Error) -> u32 {
    match error.kind() {
        io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::PermissionDenied => DPNERR_ADDRESSING,
        _ => DPNERR_GENERIC,
    }
}

/// The host session service loop: discovery, connect/ack, join/leave, data
/// relay and termination — all over the session's real UDP socket.
fn consume_drop(counter: &AtomicU32) -> bool {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
}

fn allocate_group_id(session: &SessionShared) -> u32 {
    loop {
        let candidate = session.next_dpnid.fetch_add(1, Ordering::SeqCst).max(2);
        let groups = session
            .groups
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if !groups.contains_key(&candidate) && session.player_addr(candidate).is_none() {
            break candidate;
        }
    }
}

fn session_service_loop(session: Arc<SessionShared>) {
    let mut buffer = vec![0u8; RECEIVE_BUFFER];
    loop {
        if session.closing.load(Ordering::SeqCst) {
            break;
        }
        session.retransmit_group();
        match session.socket.recv_from(&mut buffer) {
            Ok((length, from)) => {
                let datagram = &buffer[..length];
                if (starts_with_magic(datagram, MAGIC_GROUP)
                    || starts_with_magic(datagram, MAGIC_GROUP_DATA))
                    && consume_drop(&session.drop_group_datagrams)
                {
                    continue;
                }
                if starts_with_magic(datagram, MAGIC_ACK)
                    && consume_drop(&session.drop_ack_datagrams)
                {
                    continue;
                }
                if let Some((version, query_id, application_guid)) = parse_query(datagram) {
                    if version == WIRE_PROTOCOL_VERSION
                        && (application_guid == [0u8; 16] || application_guid == session.app_guid)
                    {
                        let response = wire_response(query_id, &session);
                        let _ = session.socket.send_to(&response, from);
                    }
                    continue;
                }
                if let Some((request_id, _instance, name, _connect_data)) = parse_connect(datagram)
                {
                    if session.closing.load(Ordering::SeqCst) {
                        let _ = session
                            .socket
                            .send_to(&wire_reject(request_id, DPNERR_HOSTTERMINATEDSESSION), from);
                        continue;
                    }
                    let remote = session.remote_player_count();
                    if session.max_players != 0 && 1 + remote >= session.max_players {
                        let _ = session
                            .socket
                            .send_to(&wire_reject(request_id, DPNERR_SESSIONFULL), from);
                        continue;
                    }
                    let dpnid = allocate_group_id(&session);
                    let existing: Vec<(u32, String)> = session
                        .snapshot_players()
                        .into_iter()
                        .map(|player| (player.dpnid, player.name))
                        .collect();
                    {
                        let mut players = session
                            .players
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner());
                        players.insert(
                            dpnid,
                            PlayerRecord {
                                dpnid,
                                name: name.clone(),
                                addr: from,
                            },
                        );
                    }
                    let accept = wire_accept(request_id, dpnid, HOST_PLAYER_ID, &existing);
                    let _ = session.socket.send_to(&accept, from);
                    let join = wire_join(dpnid, &name);
                    for player in session.snapshot_players() {
                        if player.dpnid != dpnid {
                            let _ = session.socket.send_to(&join, player.addr);
                        }
                    }
                    session
                        .events
                        .push(SessionEvent::PlayerJoined { dpnid, name });
                    continue;
                }
                if let Some((_ack_sender, sequence)) = parse_group_ack(datagram) {
                    if session.player_by_addr(from).is_some() {
                        session
                            .reliability
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .acknowledge(sequence, Some(from));
                    }
                    continue;
                }
                if let Some((source, destination, sequence, payload)) = parse_group_data(datagram) {
                    let Some(sender) = session.player_by_addr(from) else {
                        continue;
                    };
                    if source != sender {
                        continue;
                    }
                    let is_new = session
                        .reliability
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .note_inbound(source, sequence);
                    session.send_group_ack(from, sequence);
                    if !is_new {
                        continue;
                    }
                    if let Some(group) = session.group(destination) {
                        if group.members.contains(&HOST_PLAYER_ID) {
                            session.inbound.push(ReceivedDatagram {
                                from_dpnid: source,
                                from_addr: from,
                                data: payload.to_vec(),
                            });
                        }
                        let destinations: BTreeSet<SocketAddr> = group
                            .members
                            .iter()
                            .filter_map(|member| session.player_addr(*member))
                            .collect();
                        let payload = payload.to_vec();
                        session.send_reliable_group(destinations, |host_sequence| {
                            wire_group_data(source, destination, host_sequence, &payload)
                        });
                    } else if destination == DPNID_ALL_PLAYERS_GROUP {
                        session.inbound.push(ReceivedDatagram {
                            from_dpnid: source,
                            from_addr: from,
                            data: payload.to_vec(),
                        });
                        let destinations: BTreeSet<SocketAddr> = session
                            .snapshot_players()
                            .into_iter()
                            .filter(|player| player.dpnid != source)
                            .map(|player| player.addr)
                            .collect();
                        let payload = payload.to_vec();
                        session.send_reliable_group(destinations, |host_sequence| {
                            wire_group_data(source, destination, host_sequence, &payload)
                        });
                    }
                    continue;
                }
                if let Some((source, destination, payload)) = parse_data(datagram) {
                    // Only registered players may send or relay.
                    if session.player_addr(source).is_none() {
                        continue;
                    }
                    let received = ReceivedDatagram {
                        from_dpnid: source,
                        from_addr: from,
                        data: payload.to_vec(),
                    };
                    if destination == DPNID_ALL_PLAYERS_GROUP {
                        session.inbound.push(received);
                        let relay = wire_data(source, destination, payload);
                        for player in session.snapshot_players() {
                            if player.dpnid != source {
                                let _ = session.socket.send_to(&relay, player.addr);
                            }
                        }
                    } else if destination == HOST_PLAYER_ID {
                        session.inbound.push(received);
                    } else if let Some(addr) = session.player_addr(destination) {
                        let relay = wire_data(source, destination, payload);
                        let _ = session.socket.send_to(&relay, addr);
                    } else if let Some(group) = session.group(destination) {
                        let relay = wire_data(source, destination, payload);
                        for member in &group.members {
                            if *member == HOST_PLAYER_ID {
                                session.inbound.push(received.clone());
                            } else if let Some(addr) = session.player_addr(*member) {
                                let _ = session.socket.send_to(&relay, addr);
                            }
                        }
                    }
                    continue;
                }
                if let Some(operation) = parse_group(datagram) {
                    let Some(sender) = session.player_by_addr(from) else {
                        continue;
                    };
                    let (sequence, operation_sender) = match &operation {
                        GroupWire::Create {
                            sender, sequence, ..
                        }
                        | GroupWire::Destroy {
                            sender, sequence, ..
                        }
                        | GroupWire::AddMember {
                            sender, sequence, ..
                        }
                        | GroupWire::RemoveMember {
                            sender, sequence, ..
                        }
                        | GroupWire::Info {
                            sender, sequence, ..
                        }
                        | GroupWire::AllocateRequest {
                            sender, sequence, ..
                        }
                        | GroupWire::AllocateResponse {
                            sender, sequence, ..
                        } => (*sequence, *sender),
                    };
                    if operation_sender != sender {
                        continue;
                    }
                    let is_new = session
                        .reliability
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .note_inbound(sender, sequence);
                    session.send_group_ack(from, sequence);
                    if !is_new {
                        if matches!(&operation, GroupWire::AllocateRequest { .. }) {
                            if let Some(allocation) = session
                                .allocations
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .get(&(sender, sequence))
                                .copied()
                            {
                                session.send_reliable_group(
                                    BTreeSet::from([from]),
                                    |host_sequence| {
                                        wire_group_allocate_response(
                                            HOST_PLAYER_ID,
                                            host_sequence,
                                            allocation.group_id,
                                            sender,
                                            sequence,
                                            allocation.result,
                                        )
                                    },
                                );
                            }
                        }
                        continue;
                    }
                    match operation {
                        GroupWire::AllocateRequest {
                            owner, name, data, ..
                        } => {
                            let (result, group_id) = if data.len() > MAX_MESSAGE_PAYLOAD {
                                (DPNERR_DATATOOLARGE, 0)
                            } else if owner != HOST_PLAYER_ID
                                && session.player_addr(owner).is_none()
                            {
                                (DPNERR_INVALIDPLAYER, 0)
                            } else {
                                let group_id = allocate_group_id(&session);
                                session
                                    .groups
                                    .lock()
                                    .unwrap_or_else(|poison| poison.into_inner())
                                    .insert(
                                        group_id,
                                        GroupRecord {
                                            group_id,
                                            owner,
                                            name: name.clone(),
                                            data: data.clone(),
                                            members: BTreeSet::new(),
                                        },
                                    );
                                (S_OK, group_id)
                            };
                            session
                                .allocations
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .insert((sender, sequence), GroupAllocation { group_id, result });
                            let response_data = data.clone();
                            session.send_reliable_group(BTreeSet::from([from]), |host_sequence| {
                                wire_group_allocate_response(
                                    HOST_PLAYER_ID,
                                    host_sequence,
                                    group_id,
                                    sender,
                                    sequence,
                                    result,
                                )
                            });
                            if result == S_OK {
                                session.relay_reliable_group(sender, |host_sequence| {
                                    wire_group_create(
                                        HOST_PLAYER_ID,
                                        host_sequence,
                                        group_id,
                                        owner,
                                        &name,
                                        &response_data,
                                    )
                                });
                            }
                        }
                        GroupWire::Create {
                            group_id,
                            owner,
                            name,
                            data,
                            ..
                        } => {
                            if group_id < 2 || data.len() > MAX_MESSAGE_PAYLOAD {
                                continue;
                            }
                            let owner_exists =
                                owner == HOST_PLAYER_ID || session.player_addr(owner).is_some();
                            if !owner_exists {
                                continue;
                            }
                            let mut groups = session
                                .groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner());
                            if groups.contains_key(&group_id)
                                || session.player_addr(group_id).is_some()
                            {
                                continue;
                            }
                            groups.insert(
                                group_id,
                                GroupRecord {
                                    group_id,
                                    owner,
                                    name: name.clone(),
                                    data: data.clone(),
                                    members: BTreeSet::new(),
                                },
                            );
                            drop(groups);
                            session.relay_reliable_group(sender, |host_sequence| {
                                wire_group_create(
                                    HOST_PLAYER_ID,
                                    host_sequence,
                                    group_id,
                                    owner,
                                    &name,
                                    &data,
                                )
                            });
                        }
                        GroupWire::Destroy { group_id, .. } => {
                            let removed = session
                                .groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .remove(&group_id)
                                .is_some();
                            if removed {
                                session.relay_reliable_group(sender, |host_sequence| {
                                    wire_group_destroy(HOST_PLAYER_ID, host_sequence, group_id)
                                });
                            }
                        }
                        GroupWire::AddMember {
                            group_id, dpnid, ..
                        } => {
                            let player_exists =
                                dpnid == HOST_PLAYER_ID || session.player_addr(dpnid).is_some();
                            let changed = match session
                                .groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .get_mut(&group_id)
                            {
                                Some(group) if player_exists => group.members.insert(dpnid),
                                _ => false,
                            };
                            if changed {
                                session.relay_reliable_group(sender, |host_sequence| {
                                    wire_group_member(
                                        GROUP_OP_ADD_MEMBER,
                                        HOST_PLAYER_ID,
                                        host_sequence,
                                        group_id,
                                        dpnid,
                                    )
                                });
                            }
                        }
                        GroupWire::RemoveMember {
                            group_id, dpnid, ..
                        } => {
                            let changed = match session
                                .groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .get_mut(&group_id)
                            {
                                Some(group) => group.members.remove(&dpnid),
                                None => false,
                            };
                            if changed {
                                session.relay_reliable_group(sender, |host_sequence| {
                                    wire_group_member(
                                        GROUP_OP_REMOVE_MEMBER,
                                        HOST_PLAYER_ID,
                                        host_sequence,
                                        group_id,
                                        dpnid,
                                    )
                                });
                            }
                        }
                        GroupWire::Info {
                            group_id,
                            name,
                            data,
                            ..
                        } => {
                            if data.len() > MAX_MESSAGE_PAYLOAD {
                                continue;
                            }
                            let changed = match session
                                .groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .get_mut(&group_id)
                            {
                                Some(group) => {
                                    group.name = name.clone();
                                    group.data = data.clone();
                                    true
                                }
                                None => false,
                            };
                            if changed {
                                session.relay_reliable_group(sender, |host_sequence| {
                                    wire_group_info(
                                        HOST_PLAYER_ID,
                                        host_sequence,
                                        group_id,
                                        &name,
                                        &data,
                                    )
                                });
                            }
                        }
                        GroupWire::AllocateResponse { .. } => {}
                    }
                    continue;
                }
                if let Some(dpnid) = parse_leave(datagram) {
                    let removed = session
                        .players
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .remove(&dpnid);
                    if removed.is_some() {
                        let leave = wire_leave(dpnid);
                        for player in session.snapshot_players() {
                            let _ = session.socket.send_to(&leave, player.addr);
                        }
                        session.events.push(SessionEvent::PlayerLeft {
                            dpnid,
                            reason: DPNDESTROYPLAYERREASON_NORMAL,
                        });
                    }
                    continue;
                }
                if starts_with_magic(datagram, MAGIC_KEEPALIVE) {
                    let _ = session.socket.send_to(MAGIC_KEEPALIVE, from);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => {
                // A socket-level failure ends the service loop; the host
                // observes it through the session/player state.
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The DirectPlay8 peer
// ---------------------------------------------------------------------------

struct ClientTransport {
    socket: Arc<UdpSocket>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    host: SocketAddr,
    local_dpnid: u32,
    /// Group state replicated by the host over `DP8G`/`DP8M`.
    groups: Arc<Mutex<BTreeMap<u32, GroupRecord>>>,
    reliability: Arc<Mutex<GroupReliability>>,
    create_wait: Arc<GroupCreateWait>,
    drop_group_datagrams: Arc<AtomicU32>,
    drop_ack_datagrams: Arc<AtomicU32>,
}

impl ClientTransport {
    fn send_reliable(&self, build: impl FnOnce(u32) -> Vec<u8>) -> Option<u32> {
        let mut reliability = self
            .reliability
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let sequence = reliability.allocate_sequence();
        let message = build(sequence);
        if self.socket.send(&message).is_err() {
            return None;
        }
        reliability.record_pending(sequence, message, BTreeSet::from([self.host]));
        Some(sequence)
    }

    fn retransmit_group(&self) {
        let socket = Arc::clone(&self.socket);
        self.reliability
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .retransmit(move |message, _destination| {
                let _ = socket.send(message);
            });
    }

    fn pending_group_messages(&self) -> usize {
        self.reliability
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .pending
            .len()
    }
}

/// A pending host-authoritative group id allocation.
struct GroupCreateWait {
    state: Mutex<Option<Result<u32, u32>>>,
    cv: Condvar,
}

impl GroupCreateWait {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(None),
            cv: Condvar::new(),
        })
    }

    fn reset(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = None;
    }

    fn complete(&self, result: Result<u32, u32>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.is_none() {
            *state = Some(result);
            self.cv.notify_all();
        }
    }

    fn wait(&self, timeout: Duration) -> Option<Result<u32, u32>> {
        let deadline = Instant::now() + timeout;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        loop {
            if let Some(result) = *state {
                return Some(result);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _) = self
                .cv
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poison| poison.into_inner());
            state = guard;
        }
    }
}

/// A running asynchronous `EnumHosts` operation.
struct AsyncEnumHosts {
    cancel: Arc<AtomicBool>,
    results: Arc<Mutex<Vec<SessionInfo>>>,
    done: Arc<AtomicBool>,
    context: u64,
}

/// The asynchronous peer operations the engine can queue and cancel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AsyncOperationKind {
    Connect,
    SendTo,
    EnumHosts,
}

/// The engine behind `IDirectPlay8Peer`.
pub(crate) struct Dplay8Peer {
    initialized: bool,
    destroyed: bool,
    user_context: u64,
    message_handler: u64,
    app_desc: DplayAppDesc,
    local_dpnid: u32,
    host_dpnid: u32,
    session: Option<Arc<SessionShared>>,
    client: Option<ClientTransport>,
    inbound: Arc<InboundQueue>,
    events: Arc<EventQueue>,
    connect_wait: Arc<ConnectWait>,
    connection_lost: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,
    counters: Arc<Counters>,
    connect_timeout: Duration,
    enum_timeout: Duration,
    /// The player cache on the client side (host + peers announced by DP8J).
    player_cache: BTreeMap<u32, PlayerInfo>,
    /// The local group model (`CreateGroup`/`AddPlayerToGroup`/...).
    /// On a client this is the host-replicated copy (the same map the
    /// receiver thread updates from `DP8G`).
    groups: BTreeMap<u32, GroupRecord>,
    group_create_timeout: Duration,
    /// Pending asynchronous operations that `CancelAsyncOperation` can abort.
    pending_operations: BTreeMap<u32, AsyncOperationKind>,
    completed_operations: BTreeSet<u32>,
    next_async_operation: u32,
    enum_operations: BTreeMap<u32, AsyncEnumHosts>,
    /// The local player name/data set with `SetPeerInfo`.
    local_player_name: String,
    local_player_data: Vec<u8>,
    /// The `pvPlayerContext` passed to `Host`/`Connect` for the local player.
    local_context: u64,
    /// The local `DPN_BUFFER_DESC` send-queue depth (the engine sends each
    /// datagram immediately, so this stays zero).
    send_queue_messages: u32,
    send_queue_bytes: u32,
}

/// The local peer group model.
#[derive(Clone, Debug)]
pub(crate) struct GroupRecord {
    pub(crate) group_id: u32,
    pub(crate) owner: u32,
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) members: BTreeSet<u32>,
}

/// The real `DP8Q`/`DP8R` enumeration loop shared by synchronous and
/// asynchronous `EnumHosts`.  `cancel` is checked before every response and
/// on every receive timeout, so cancellation really stops new responses.
fn run_enum_hosts_query(
    application_guid: &[u8; 16],
    targets: &[SocketAddr],
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    mut on_response: impl FnMut(SessionInfo),
) -> Vec<SessionInfo> {
    let probe = match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
        Ok(socket) => socket,
        Err(_) => return Vec::new(),
    };
    let _ = probe.set_broadcast(true);
    let _ = probe.set_read_timeout(Some(Duration::from_millis(SERVICE_TICK_MS)));
    let mut destinations: Vec<SocketAddr> = Vec::new();
    for target in targets {
        let target = if target.ip().is_unspecified() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), target.port())
        } else {
            *target
        };
        if !destinations.contains(&target) {
            destinations.push(target);
        }
    }
    for addr in local_session_addresses() {
        if !destinations.contains(&addr) {
            destinations.push(addr);
        }
    }
    if destinations.is_empty() {
        return Vec::new();
    }
    let query_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::SeqCst);
    let query = wire_query(query_id, application_guid);
    let mut sent: BTreeMap<SocketAddr, Instant> = BTreeMap::new();
    for destination in &destinations {
        if probe.send_to(&query, destination).is_ok() {
            sent.insert(*destination, Instant::now());
        }
    }
    let deadline = Instant::now() + timeout;
    let mut results: Vec<SessionInfo> = Vec::new();
    let mut buffer = vec![0u8; RECEIVE_BUFFER];
    loop {
        if cancel.is_some_and(|cancel| cancel.load(Ordering::SeqCst)) {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let _ = probe.set_read_timeout(Some((deadline - now).min(Duration::from_millis(100))));
        match probe.recv_from(&mut buffer) {
            Ok((length, from)) => {
                let Some(mut info) = parse_response(&buffer[..length], from) else {
                    continue;
                };
                if application_guid != &[0u8; 16] && &info.application_guid != application_guid {
                    continue;
                }
                info.latency_ms = sent
                    .get(&from)
                    .map(|start| start.elapsed().as_millis() as u32)
                    .unwrap_or(0);
                if results
                    .iter()
                    .any(|existing| existing.instance_guid == info.instance_guid)
                {
                    continue;
                }
                if cancel.is_some_and(|cancel| cancel.load(Ordering::SeqCst)) {
                    break;
                }
                on_response(info.clone());
                results.push(info);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    results
}

impl Dplay8Peer {
    pub(crate) fn new() -> Self {
        Self {
            initialized: false,
            destroyed: false,
            user_context: 0,
            message_handler: 0,
            app_desc: DplayAppDesc::default(),
            local_dpnid: 0,
            host_dpnid: 0,
            session: None,
            client: None,
            inbound: InboundQueue::new(),
            events: EventQueue::new(),
            connect_wait: ConnectWait::new(),
            connection_lost: Arc::new(AtomicBool::new(false)),
            terminated: Arc::new(AtomicBool::new(false)),
            counters: Arc::new(Counters::default()),
            connect_timeout: Duration::from_millis(u64::from(DEFAULT_CONNECT_TIMEOUT_MS)),
            enum_timeout: Duration::from_millis(u64::from(DEFAULT_ENUM_TIMEOUT_MS)),
            player_cache: BTreeMap::new(),
            groups: BTreeMap::new(),
            group_create_timeout: Duration::from_millis(2_000),
            pending_operations: BTreeMap::new(),
            completed_operations: BTreeSet::new(),
            next_async_operation: 1,
            enum_operations: BTreeMap::new(),
            local_player_name: String::new(),
            local_player_data: Vec::new(),
            local_context: 0,
            send_queue_messages: 0,
            send_queue_bytes: 0,
        }
    }

    /// `Initialize`.
    pub(crate) fn initialize(
        &mut self,
        user_context: u64,
        message_handler: u64,
        flags: u32,
    ) -> u32 {
        if self.initialized {
            return DPNERR_ALREADYINITIALIZED;
        }
        if flags & !0x0000_0007 != 0 {
            return DPNERR_INVALIDFLAGS;
        }
        self.initialized = true;
        self.user_context = user_context;
        self.message_handler = message_handler;
        S_OK
    }

    pub(crate) fn is_initialized(&self) -> bool {
        self.initialized
    }

    pub(crate) fn user_context(&self) -> u64 {
        self.user_context
    }

    pub(crate) fn message_handler(&self) -> u64 {
        self.message_handler
    }

    /// Register the guest message handler before initialization.
    pub(crate) fn set_message_handler(&mut self, handler: u64) -> u32 {
        if self.initialized {
            return DPNERR_ALREADYINITIALIZED;
        }
        if handler == 0 {
            return DPNERR_INVALIDPOINTER;
        }
        self.message_handler = handler;
        S_OK
    }

    /// Replace the registered handler on a live peer.
    pub(crate) fn update_message_handler(&mut self, handler: u64) -> u32 {
        if !self.initialized {
            return DPNERR_UNINITIALIZED;
        }
        if handler == 0 {
            return DPNERR_INVALIDPOINTER;
        }
        self.message_handler = handler;
        S_OK
    }

    pub(crate) fn app_desc(&self) -> &DplayAppDesc {
        &self.app_desc
    }

    pub(crate) fn set_app_desc(&mut self, desc: DplayAppDesc) {
        self.app_desc = desc;
    }

    pub(crate) fn local_player_name(&self) -> &str {
        &self.local_player_name
    }

    pub(crate) fn set_local_player_name(&mut self, name: &str) {
        self.local_player_name = name.to_string();
    }

    pub(crate) fn local_player_data(&self) -> &[u8] {
        &self.local_player_data
    }

    pub(crate) fn set_local_player_data(&mut self, data: &[u8]) {
        self.local_player_data = data.to_vec();
    }

    pub(crate) fn set_local_context(&mut self, context: u64) {
        self.local_context = context;
    }

    pub(crate) fn local_context(&self) -> u64 {
        self.local_context
    }

    pub(crate) fn send_queue(&self) -> (u32, u32) {
        (self.send_queue_messages, self.send_queue_bytes)
    }

    pub(crate) fn local_dpnid(&self) -> u32 {
        self.local_dpnid
    }

    pub(crate) fn host_dpnid(&self) -> u32 {
        self.host_dpnid
    }

    pub(crate) fn is_hosting(&self) -> bool {
        self.session.is_some()
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    pub(crate) fn is_terminated(&self) -> bool {
        self.terminated.load(Ordering::SeqCst)
    }

    pub(crate) fn connection_lost(&self) -> bool {
        self.connection_lost.load(Ordering::SeqCst)
    }

    pub(crate) fn local_address(&self) -> Option<SocketAddr> {
        if let Some(session) = &self.session {
            return Some(session.addr);
        }
        self.client
            .as_ref()
            .and_then(|client| client.socket.local_addr().ok())
    }

    pub(crate) fn host_instance_guid(&self) -> Option<[u8; 16]> {
        self.session.as_ref().map(|session| session.instance_guid)
    }

    pub(crate) fn set_connect_timeout(&mut self, timeout: Duration) {
        self.connect_timeout = timeout;
    }

    pub(crate) fn set_enum_timeout(&mut self, timeout: Duration) {
        self.enum_timeout = timeout;
    }

    pub(crate) fn set_group_create_timeout(&mut self, timeout: Duration) {
        self.group_create_timeout = timeout;
    }

    /// Deterministic loss injection for the reliable group link: the next
    /// `group` group operation/data datagrams and the next `acks`
    /// acknowledgement datagrams received by this peer are dropped before
    /// processing.  Returns the previous counters.
    pub(crate) fn set_group_packet_loss(&mut self, group: u32, acks: u32) -> (u32, u32) {
        if let Some(session) = &self.session {
            let previous_group = session.drop_group_datagrams.swap(group, Ordering::SeqCst);
            let previous_acks = session.drop_ack_datagrams.swap(acks, Ordering::SeqCst);
            return (previous_group, previous_acks);
        }
        if let Some(client) = &self.client {
            let previous_group = client.drop_group_datagrams.swap(group, Ordering::SeqCst);
            let previous_acks = client.drop_ack_datagrams.swap(acks, Ordering::SeqCst);
            return (previous_group, previous_acks);
        }
        (0, 0)
    }

    pub(crate) fn group_duplicates_suppressed(&self) -> u64 {
        if let Some(session) = &self.session {
            return session
                .reliability
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .duplicates_suppressed;
        }
        if let Some(client) = &self.client {
            return client
                .reliability
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .duplicates_suppressed;
        }
        0
    }

    pub(crate) fn pending_group_messages(&self) -> usize {
        if let Some(session) = &self.session {
            return session
                .reliability
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .pending
                .len();
        }
        self.client
            .as_ref()
            .map(ClientTransport::pending_group_messages)
            .unwrap_or(0)
    }

    /// `Host` — bind the real session socket, publish the session and start
    /// the service thread.  A busy port reports `DPNERR_ADDRESSING`.
    pub(crate) fn host(&mut self, desc: &DplayAppDesc, bind: SocketAddr) -> u32 {
        if !self.initialized {
            return DPNERR_UNINITIALIZED;
        }
        if self.session.is_some() {
            return DPNERR_HOSTING;
        }
        if self.client.is_some() {
            return DPNERR_ALREADYCONNECTED;
        }
        let socket = match UdpSocket::bind(bind) {
            Ok(socket) => Arc::new(socket),
            Err(error) => return map_bind_error(&error),
        };
        configure_socket(&socket);
        let _ = socket.set_broadcast(true);
        let addr = match socket.local_addr() {
            Ok(addr) => addr,
            Err(_) => return DPNERR_GENERIC,
        };
        let mut app_desc = desc.clone();
        if app_desc.instance_guid == [0u8; 16] {
            app_desc.instance_guid = random_guid();
        }
        let session = Arc::new(SessionShared {
            instance_guid: app_desc.instance_guid,
            app_guid: app_desc.application_guid,
            name: app_desc.session_name.clone(),
            max_players: app_desc.max_players,
            addr,
            socket,
            players: Mutex::new(BTreeMap::new()),
            next_dpnid: AtomicU32::new(HOST_PLAYER_ID + 1),
            groups: Mutex::new(BTreeMap::new()),
            inbound: Arc::clone(&self.inbound),
            events: Arc::clone(&self.events),
            reliability: Mutex::new(GroupReliability::default()),
            allocations: Mutex::new(BTreeMap::new()),
            drop_group_datagrams: AtomicU32::new(0),
            drop_ack_datagrams: AtomicU32::new(0),
            closing: AtomicBool::new(false),
            service: Mutex::new(None),
        });
        let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::SeqCst);
        {
            let mut registry = lock_sessions();
            registry.insert(session_id, Arc::clone(&session));
        }
        let thread_session = Arc::clone(&session);
        let handle = thread::Builder::new()
            .name(format!("casa1-dplay8-session-{session_id}"))
            .spawn(move || session_service_loop(thread_session));
        match handle {
            Ok(handle) => {
                *session
                    .service
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner()) = Some(handle);
            }
            Err(_) => {
                lock_sessions().remove(&session_id);
                return DPNERR_OUTOFMEMORY;
            }
        }
        app_desc.current_players = 1;
        self.app_desc = app_desc;
        self.local_dpnid = HOST_PLAYER_ID;
        self.host_dpnid = HOST_PLAYER_ID;
        self.session = Some(session);
        S_OK
    }

    /// `Connect` — create the client socket, run the real `DP8C`/`DP8A`
    /// exchange with the host and wait for the answer.  No answer in the
    /// timeout window (or an ICMP port-unreachable on the connected socket)
    /// reports `DPNERR_NORESPONSE`; an explicit host rejection carries the
    /// host's `DPNERR_*`.
    pub(crate) fn connect(
        &mut self,
        host: SocketAddr,
        player_name: &str,
        connect_data: &[u8],
    ) -> u32 {
        if !self.initialized {
            return DPNERR_UNINITIALIZED;
        }
        if self.session.is_some() {
            return DPNERR_HOSTING;
        }
        if self.client.is_some() {
            return DPNERR_ALREADYCONNECTED;
        }
        if host.port() == 0 {
            return DPNERR_INCOMPLETEADDRESS;
        }
        let socket = match UdpSocket::bind(SocketAddr::new(host.ip(), 0)) {
            Ok(socket) => Arc::new(socket),
            Err(error) => return map_bind_error(&error),
        };
        configure_socket(&socket);
        if socket.connect(host).is_err() {
            return DPNERR_INVALIDHOSTADDRESS;
        }
        let shutdown = Arc::new(AtomicBool::new(false));
        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::SeqCst);
        let wait = Arc::clone(&self.connect_wait);
        let thread_socket = Arc::clone(&socket);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread_wait = Arc::clone(&wait);
        let thread_inbound = Arc::clone(&self.inbound);
        let thread_events = Arc::clone(&self.events);
        let thread_lost = Arc::clone(&self.connection_lost);
        let thread_terminated = Arc::clone(&self.terminated);
        let thread_counters = Arc::clone(&self.counters);
        let client_groups: Arc<Mutex<BTreeMap<u32, GroupRecord>>> =
            Arc::new(Mutex::new(BTreeMap::new()));
        let thread_groups = Arc::clone(&client_groups);
        let client_reliability = Arc::new(Mutex::new(GroupReliability::default()));
        let thread_reliability = Arc::clone(&client_reliability);
        let client_create_wait = GroupCreateWait::new();
        let thread_create_wait = Arc::clone(&client_create_wait);
        let client_drop_group = Arc::new(AtomicU32::new(0));
        let thread_drop_group = Arc::clone(&client_drop_group);
        let client_drop_ack = Arc::new(AtomicU32::new(0));
        let thread_drop_ack = Arc::clone(&client_drop_ack);
        let handle = thread::Builder::new()
            .name(format!("casa1-dplay8-client-{request_id}"))
            .spawn(move || {
                client_receive_loop(
                    thread_socket,
                    thread_inbound,
                    thread_events,
                    thread_wait,
                    thread_lost,
                    thread_terminated,
                    thread_shutdown,
                    thread_counters,
                    thread_groups,
                    thread_reliability,
                    thread_create_wait,
                    thread_drop_group,
                    thread_drop_ack,
                );
            });
        let handle = match handle {
            Ok(handle) => handle,
            Err(_) => return DPNERR_OUTOFMEMORY,
        };
        let request = wire_connect(
            request_id,
            &self.app_desc.instance_guid,
            player_name,
            connect_data,
        );
        if socket.send(&request).is_err() {
            shutdown.store(true, Ordering::SeqCst);
            let _ = handle.join();
            return DPNERR_NORESPONSE;
        }
        match wait.wait(self.connect_timeout) {
            Some(Ok(accept)) => {
                self.apply_accept(host, &accept);
                self.client = Some(ClientTransport {
                    socket,
                    shutdown,
                    thread: Some(handle),
                    host,
                    local_dpnid: self.local_dpnid,
                    groups: client_groups,
                    reliability: client_reliability,
                    create_wait: client_create_wait,
                    drop_group_datagrams: client_drop_group,
                    drop_ack_datagrams: client_drop_ack,
                });
                S_OK
            }
            Some(Err(reason)) => {
                shutdown.store(true, Ordering::SeqCst);
                let _ = handle.join();
                reason
            }
            None => {
                shutdown.store(true, Ordering::SeqCst);
                let _ = handle.join();
                DPNERR_NORESPONSE
            }
        }
    }

    /// Apply a successful accept datagram to this peer's state.
    fn apply_accept(&mut self, host: SocketAddr, accept: &ConnectAccept) {
        self.local_dpnid = accept.assigned;
        self.host_dpnid = accept.host;
        self.terminated.store(false, Ordering::SeqCst);
        self.player_cache.clear();
        self.player_cache.insert(
            accept.host,
            PlayerInfo {
                dpnid: accept.host,
                name: String::new(),
                addr: host,
                flags: DPNPLAYER_HOST,
            },
        );
        for (dpnid, name) in &accept.players {
            self.player_cache.insert(
                *dpnid,
                PlayerInfo {
                    dpnid: *dpnid,
                    name: name.clone(),
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    flags: 0,
                },
            );
        }
    }

    /// `SendTo` — one real datagram per call.
    pub(crate) fn send_to(&mut self, dpnid: u32, payload: &[u8]) -> u32 {
        if !self.initialized {
            return DPNERR_UNINITIALIZED;
        }
        if payload.len() > MAX_MESSAGE_PAYLOAD {
            return DPNERR_DATATOOLARGE;
        }
        if let Some(session) = &self.session {
            if dpnid == DPNID_ALL_PLAYERS_GROUP {
                let destinations: BTreeSet<SocketAddr> = session
                    .snapshot_players()
                    .into_iter()
                    .map(|player| player.addr)
                    .collect();
                session.send_reliable_group(destinations, |sequence| {
                    wire_group_data(HOST_PLAYER_ID, DPNID_ALL_PLAYERS_GROUP, sequence, payload)
                });
                self.inbound.push(ReceivedDatagram {
                    from_dpnid: HOST_PLAYER_ID,
                    from_addr: session.addr,
                    data: payload.to_vec(),
                });
                self.counters
                    .bytes_sent
                    .fetch_add(payload.len() as u64, Ordering::SeqCst);
                self.counters.packets_sent.fetch_add(1, Ordering::SeqCst);
                return S_OK;
            }
            if dpnid == HOST_PLAYER_ID {
                self.inbound.push(ReceivedDatagram {
                    from_dpnid: HOST_PLAYER_ID,
                    from_addr: session.addr,
                    data: payload.to_vec(),
                });
                self.counters
                    .bytes_sent
                    .fetch_add(payload.len() as u64, Ordering::SeqCst);
                self.counters.packets_sent.fetch_add(1, Ordering::SeqCst);
                return S_OK;
            }
            if let Some(group) = session.group(dpnid) {
                let mut destinations = BTreeSet::new();
                for member in &group.members {
                    if *member == HOST_PLAYER_ID {
                        self.inbound.push(ReceivedDatagram {
                            from_dpnid: HOST_PLAYER_ID,
                            from_addr: session.addr,
                            data: payload.to_vec(),
                        });
                    } else if let Some(addr) = session.player_addr(*member) {
                        destinations.insert(addr);
                    }
                }
                session.send_reliable_group(destinations, |sequence| {
                    wire_group_data(HOST_PLAYER_ID, dpnid, sequence, payload)
                });
                self.counters
                    .bytes_sent
                    .fetch_add(payload.len() as u64, Ordering::SeqCst);
                self.counters.packets_sent.fetch_add(1, Ordering::SeqCst);
                return S_OK;
            }
            let Some(addr) = session.player_addr(dpnid) else {
                return DPNERR_INVALIDPLAYER;
            };
            let message = wire_data(HOST_PLAYER_ID, dpnid, payload);
            if session.socket.send_to(&message, addr).is_err() {
                return DPNERR_NOCONNECTION;
            }
            self.counters
                .bytes_sent
                .fetch_add(payload.len() as u64, Ordering::SeqCst);
            self.counters.packets_sent.fetch_add(1, Ordering::SeqCst);
            return S_OK;
        }
        if let Some(client) = &self.client {
            let is_group = dpnid == DPNID_ALL_PLAYERS_GROUP || self.group(dpnid).is_some();
            if dpnid != DPNID_ALL_PLAYERS_GROUP
                && dpnid != self.host_dpnid
                && !self.player_cache.contains_key(&dpnid)
                && !is_group
            {
                return DPNERR_INVALIDPLAYER;
            }
            if is_group {
                if client
                    .send_reliable(|sequence| {
                        wire_group_data(self.local_dpnid, dpnid, sequence, payload)
                    })
                    .is_none()
                {
                    return DPNERR_CONNECTIONLOST;
                }
            } else {
                let message = wire_data(self.local_dpnid, dpnid, payload);
                if client.socket.send(&message).is_err() {
                    return DPNERR_CONNECTIONLOST;
                }
            }
            self.counters
                .bytes_sent
                .fetch_add(payload.len() as u64, Ordering::SeqCst);
            self.counters.packets_sent.fetch_add(1, Ordering::SeqCst);
            return S_OK;
        }
        DPNERR_NOCONNECTION
    }

    /// The receive side: the next real application datagram, waiting up to
    /// `timeout`.  Datagrams are produced by the transport threads from real
    /// socket reads.
    pub(crate) fn receive_from(&mut self, timeout: Duration) -> Option<ReceivedDatagram> {
        let message = self.inbound.pop_timeout(timeout);
        if let Some(message) = &message {
            self.counters
                .bytes_received
                .fetch_add(message.data.len() as u64, Ordering::SeqCst);
            self.counters
                .packets_received
                .fetch_add(1, Ordering::SeqCst);
        }
        message
    }

    /// Non-blocking receive used by the dispatch layer when draining pending
    /// guest callbacks.
    pub(crate) fn poll_receive(&mut self) -> Option<ReceivedDatagram> {
        if self.inbound.len() == 0 {
            return None;
        }
        self.receive_from(Duration::ZERO)
    }

    /// `EnumHosts` synchronous mode — send a real `DP8Q` to every target
    /// (plus every session hosted by this runtime) and collect the real
    /// `DP8R` answers.
    pub(crate) fn enum_hosts(
        &self,
        application_guid: &[u8; 16],
        targets: &[SocketAddr],
        timeout: Duration,
    ) -> Vec<SessionInfo> {
        run_enum_hosts_query(application_guid, targets, timeout, None, |_| {})
    }

    /// `EnumHosts` asynchronous mode — start the real enumeration on a worker
    /// and return the async operation handle.  Responses are drained by
    /// [`Self::poll_engine_events`] and delivered through the registered
    /// message handler until the window ends or the operation is cancelled.
    pub(crate) fn start_enum_hosts(
        &mut self,
        application_guid: &[u8; 16],
        targets: &[SocketAddr],
        timeout: Duration,
        context: u64,
    ) -> Result<u32, u32> {
        let handle = self.begin_async_operation(AsyncOperationKind::EnumHosts);
        let cancel = Arc::new(AtomicBool::new(false));
        let results = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_results = Arc::clone(&results);
        let worker_done = Arc::clone(&done);
        let application_guid = *application_guid;
        let targets = targets.to_vec();
        let spawn = thread::Builder::new()
            .name(format!("casa1-dplay8-enum-{handle}"))
            .spawn(move || {
                run_enum_hosts_query(
                    &application_guid,
                    &targets,
                    timeout,
                    Some(&worker_cancel),
                    |session| {
                        if !worker_cancel.load(Ordering::SeqCst) {
                            worker_results
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .push(session);
                        }
                    },
                );
                worker_done.store(true, Ordering::SeqCst);
            });
        if spawn.is_err() {
            self.pending_operations.remove(&handle);
            return Err(DPNERR_OUTOFMEMORY);
        }
        self.enum_operations.insert(
            handle,
            AsyncEnumHosts {
                cancel,
                results,
                done,
                context,
            },
        );
        Ok(handle)
    }

    /// `Close` — real session teardown: the host announces `DP8S` to every
    /// player, unregisters the session and joins the service thread; the
    /// client announces `DP8X` and joins its receiver thread.
    pub(crate) fn close(&mut self) -> u32 {
        if let Some(session) = self.session.take() {
            let terminate = wire_terminate(DPNERR_HOSTTERMINATEDSESSION, &[]);
            for player in session.snapshot_players() {
                let _ = session.socket.send_to(&terminate, player.addr);
            }
            session.closing.store(true, Ordering::SeqCst);
            let registry_id = lock_sessions()
                .iter()
                .find(|(_, candidate)| Arc::ptr_eq(candidate, &session))
                .map(|(id, _)| *id);
            if let Some(id) = registry_id {
                lock_sessions().remove(&id);
            }
            let handle = session
                .service
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .take();
            if let Some(handle) = handle {
                let _ = handle.join();
            }
            session
                .reliability
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clear();
            session
                .allocations
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clear();
        }
        if let Some(client) = self.client.take() {
            let _ = client.socket.send(&wire_leave(self.local_dpnid));
            client.shutdown.store(true, Ordering::SeqCst);
            if let Some(handle) = client.thread {
                let _ = handle.join();
            }
            client
                .reliability
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clear();
        }
        let enum_handles: Vec<u32> = self.enum_operations.keys().copied().collect();
        for handle in enum_handles {
            if let Some(operation) = self.enum_operations.remove(&handle) {
                operation.cancel.store(true, Ordering::SeqCst);
            }
            self.pending_operations.remove(&handle);
        }
        self.player_cache.clear();
        self.local_dpnid = 0;
        self.host_dpnid = 0;
        self.terminated.store(false, Ordering::SeqCst);
        S_OK
    }

    /// `DestroyPeer` (complete teardown).
    pub(crate) fn destroy(&mut self) -> u32 {
        let result = self.close();
        self.destroyed = true;
        result
    }

    /// `GetCaps` from the live engine settings.
    pub(crate) fn caps(&self) -> DplayCaps {
        DplayCaps {
            flags: DPNCAPS_SUPPORTSGUARANTEED,
            connect_timeout_ms: self.connect_timeout.as_millis() as u32,
            connect_retries: 1,
            timeout_until_keep_alive_ms: DEFAULT_KEEPALIVE_MS,
        }
    }

    /// `SetCaps`.
    pub(crate) fn set_caps(&mut self, caps: &DplayCaps) -> u32 {
        if caps.connect_timeout_ms == 0 {
            return DPNERR_INVALIDPARAM;
        }
        self.connect_timeout = Duration::from_millis(u64::from(caps.connect_timeout_ms));
        S_OK
    }

    /// `GetSPCaps` from the real service-thread/socket facts.
    pub(crate) fn sp_caps(&self) -> DplaySpCaps {
        DplaySpCaps {
            flags: DPNSPCAPS_SUPPORTSBROADCAST
                | DPNSPCAPS_SUPPORTSALLADAPTERS
                | DPNSPCAPS_SUPPORTSDPNSRV,
            num_threads: 1,
            default_enum_count: 1,
            default_enum_retry_interval_ms: DEFAULT_ENUM_RETRY_INTERVAL_MS,
            default_enum_timeout_ms: self.enum_timeout.as_millis() as u32,
            max_enum_payload_size: MAX_MESSAGE_PAYLOAD as u32,
            buffers_per_thread: 8,
            system_buffer_size: SERVICE_SYSTEM_BUFFER_SIZE,
        }
    }

    /// `SetSPCaps`.
    pub(crate) fn set_sp_caps(&mut self, caps: &DplaySpCaps) -> u32 {
        if caps.default_enum_timeout_ms == 0 {
            return DPNERR_INVALIDPARAM;
        }
        self.enum_timeout = Duration::from_millis(u64::from(caps.default_enum_timeout_ms));
        S_OK
    }

    /// Every player known to this peer (host included).
    pub(crate) fn players(&self) -> Vec<PlayerInfo> {
        let mut players = Vec::new();
        if let Some(session) = &self.session {
            players.push(PlayerInfo {
                dpnid: HOST_PLAYER_ID,
                name: if self.local_player_name.is_empty() {
                    self.app_desc.session_name.clone()
                } else {
                    self.local_player_name.clone()
                },
                addr: session.addr,
                flags: DPNPLAYER_HOST | DPNPLAYER_LOCAL,
            });
            for player in session.snapshot_players() {
                players.push(PlayerInfo {
                    dpnid: player.dpnid,
                    name: player.name,
                    addr: player.addr,
                    flags: 0,
                });
            }
        } else if self.client.is_some() {
            for player in self.player_cache.values() {
                players.push(player.clone());
            }
        }
        players
    }

    /// `DPN_CONNECTION_INFO` from the real transport counters.
    pub(crate) fn connection_info(&self) -> DplayConnectionInfo {
        DplayConnectionInfo {
            round_trip_latency_ms: 0,
            bytes_sent: self.counters.bytes_sent.load(Ordering::SeqCst),
            packets_sent: self.counters.packets_sent.load(Ordering::SeqCst),
            bytes_received: self.counters.bytes_received.load(Ordering::SeqCst),
            packets_received: self.counters.packets_received.load(Ordering::SeqCst),
            messages_received: self.counters.packets_received.load(Ordering::SeqCst),
        }
    }

    /// Register a pending asynchronous operation and return its real handle.
    pub(crate) fn begin_async_operation(&mut self, kind: AsyncOperationKind) -> u32 {
        let handle = self.next_async_operation.max(1);
        self.next_async_operation = handle.wrapping_add(1).max(1);
        self.pending_operations.insert(handle, kind);
        handle
    }

    /// Mark an asynchronous operation complete.  Returns `false` when the
    /// handle was cancelled or never existed (its completion must not run).
    pub(crate) fn complete_async_operation(&mut self, handle: u32) -> bool {
        if self.pending_operations.remove(&handle).is_none() {
            return false;
        }
        self.completed_operations.insert(handle);
        true
    }

    /// `CancelAsyncOperation` — a pending operation really stops being
    /// pending.  Unknown handles are `DPNERR_INVALIDHANDLE`; operations
    /// already completed are `DPNERR_CANNOTCANCEL`.
    pub(crate) fn cancel_async_operation(&mut self, handle: u32) -> u32 {
        if handle == 0 {
            return DPNERR_INVALIDHANDLE;
        }
        if self.pending_operations.remove(&handle).is_some() {
            if let Some(operation) = self.enum_operations.remove(&handle) {
                operation.cancel.store(true, Ordering::SeqCst);
            }
            return S_OK;
        }
        if self.completed_operations.contains(&handle) {
            return DPNERR_CANNOTCANCEL;
        }
        DPNERR_INVALIDHANDLE
    }

    pub(crate) fn async_operation_pending(&self, handle: u32) -> bool {
        self.pending_operations.contains_key(&handle)
    }

    /// Pull the real queued engine events — received datagrams, player
    /// create/destroy changes, session termination and asynchronous
    /// enumeration responses — into the guest-visible [`DplayEvent`] stream.
    pub(crate) fn poll_engine_events(&mut self) -> Vec<DplayEvent> {
        let mut events = Vec::new();
        for event in self.drain_events() {
            match event {
                SessionEvent::PlayerJoined { dpnid, .. } => {
                    events.push(DplayEvent::CreatePlayer { dpnid, context: 0 });
                }
                SessionEvent::PlayerLeft { dpnid, reason } => {
                    events.push(DplayEvent::DestroyPlayer {
                        dpnid,
                        reason,
                        context: 0,
                    });
                }
                SessionEvent::Terminated { reason } => {
                    events.push(DplayEvent::SessionLost { result: reason });
                }
            }
        }
        while let Some(message) = self.inbound.pop_handler() {
            events.push(DplayEvent::Receive {
                sender: message.from_dpnid,
                context: 0,
                data: message.data,
            });
        }
        let enum_handles: Vec<u32> = self.enum_operations.keys().copied().collect();
        for handle in enum_handles {
            let cancelled = self
                .enum_operations
                .get(&handle)
                .is_some_and(|operation| operation.cancel.load(Ordering::SeqCst));
            if cancelled {
                continue;
            }
            let (responses, done, context) = {
                let Some(operation) = self.enum_operations.get_mut(&handle) else {
                    continue;
                };
                let responses: Vec<SessionInfo> = operation
                    .results
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .drain(..)
                    .collect();
                (
                    responses,
                    operation.done.load(Ordering::SeqCst),
                    operation.context,
                )
            };
            for session in responses {
                events.push(DplayEvent::EnumHostsResponse {
                    context,
                    session,
                    async_op: handle,
                });
            }
            if done {
                self.enum_operations.remove(&handle);
                let _ = self.complete_async_operation(handle);
            }
        }
        events
    }

    /// Drain the transport-thread events (joins/leaves/termination).
    pub(crate) fn drain_events(&mut self) -> Vec<SessionEvent> {
        let events = self.events.drain();
        for event in &events {
            match event {
                SessionEvent::PlayerJoined { dpnid, name } => {
                    self.player_cache.entry(*dpnid).or_insert(PlayerInfo {
                        dpnid: *dpnid,
                        name: name.clone(),
                        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                        flags: 0,
                    });
                }
                SessionEvent::PlayerLeft { dpnid, .. } => {
                    self.player_cache.remove(dpnid);
                }
                SessionEvent::Terminated { .. } => {}
            }
        }
        events
    }

    // ── group model (local peer bookkeeping) ────────────────────────────────

    pub(crate) fn create_group(&mut self, name: &str, owner: u32, data: &[u8]) -> Result<u32, u32> {
        if owner != 0 && !self.player_exists(owner) {
            return Err(DPNERR_INVALIDPLAYER);
        }
        if data.len() > MAX_MESSAGE_PAYLOAD {
            return Err(DPNERR_DATATOOLARGE);
        }
        if let Some(session) = &self.session {
            // Group ids share the DPNID namespace: draw from the same real
            // allocation sequence as players so a group id can never be
            // mistaken for a player id by the data path.
            let group_id = session.next_dpnid.fetch_add(1, Ordering::SeqCst).max(2);
            session
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .insert(
                    group_id,
                    GroupRecord {
                        group_id,
                        owner,
                        name: name.to_string(),
                        data: data.to_vec(),
                        members: BTreeSet::new(),
                    },
                );
            let message_data = data.to_vec();
            session.broadcast_reliable_group(|sequence| {
                wire_group_create(
                    HOST_PLAYER_ID,
                    sequence,
                    group_id,
                    owner,
                    name,
                    &message_data,
                )
            });
            return Ok(group_id);
        }
        if let Some(client) = &self.client {
            // Host-authoritative group ids: ask the host, wait for its real
            // answer, and only then create the local group record.  The
            // request itself is retransmitted by the reliable group link; a
            // lost answer is retransmitted by the host.
            client.create_wait.reset();
            let local_dpnid = self.local_dpnid;
            let Some(request_sequence) = client.send_reliable(|sequence| {
                wire_group_allocate_request(local_dpnid, sequence, owner, name, data)
            }) else {
                return Err(DPNERR_CONNECTIONLOST);
            };
            match client.create_wait.wait(self.group_create_timeout) {
                Some(Ok(group_id)) => {
                    client
                        .groups
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .entry(group_id)
                        .or_insert_with(|| GroupRecord {
                            group_id,
                            owner,
                            name: name.to_string(),
                            data: data.to_vec(),
                            members: BTreeSet::new(),
                        });
                    Ok(group_id)
                }
                Some(Err(error)) => Err(error),
                None => {
                    client
                        .reliability
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .cancel(request_sequence);
                    Err(DPNERR_TIMEDOUT)
                }
            }
        } else {
            Err(DPNERR_NOCONNECTION)
        }
    }

    pub(crate) fn destroy_group(&mut self, group_id: u32) -> u32 {
        if let Some(session) = &self.session {
            if session
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(&group_id)
                .is_none()
            {
                return DPNERR_INVALIDGROUP;
            }
            session.broadcast_reliable_group(|sequence| {
                wire_group_destroy(HOST_PLAYER_ID, sequence, group_id)
            });
            return S_OK;
        }
        if let Some(client) = &self.client {
            if client
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .remove(&group_id)
                .is_none()
            {
                return DPNERR_INVALIDGROUP;
            }
            if client
                .send_reliable(|sequence| wire_group_destroy(self.local_dpnid, sequence, group_id))
                .is_none()
            {
                return DPNERR_CONNECTIONLOST;
            }
            return S_OK;
        }
        DPNERR_NOCONNECTION
    }

    pub(crate) fn add_player_to_group(&mut self, group_id: u32, dpnid: u32) -> u32 {
        if !self.player_exists(dpnid) {
            return DPNERR_INVALIDPLAYER;
        }
        if let Some(session) = &self.session {
            let inserted = match session
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get_mut(&group_id)
            {
                Some(group) => group.members.insert(dpnid),
                None => return DPNERR_INVALIDGROUP,
            };
            if !inserted {
                return DPNERR_DUPLICATECOMMAND;
            }
            session.broadcast_reliable_group(|sequence| {
                wire_group_member(
                    GROUP_OP_ADD_MEMBER,
                    HOST_PLAYER_ID,
                    sequence,
                    group_id,
                    dpnid,
                )
            });
            return S_OK;
        }
        if let Some(client) = &self.client {
            let inserted = match client
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get_mut(&group_id)
            {
                Some(group) => group.members.insert(dpnid),
                None => return DPNERR_INVALIDGROUP,
            };
            if !inserted {
                return DPNERR_DUPLICATECOMMAND;
            }
            let local_dpnid = self.local_dpnid;
            if client
                .send_reliable(|sequence| {
                    wire_group_member(GROUP_OP_ADD_MEMBER, local_dpnid, sequence, group_id, dpnid)
                })
                .is_none()
            {
                return DPNERR_CONNECTIONLOST;
            }
            return S_OK;
        }
        DPNERR_NOCONNECTION
    }

    pub(crate) fn remove_player_from_group(&mut self, group_id: u32, dpnid: u32) -> u32 {
        if let Some(session) = &self.session {
            let removed = match session
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get_mut(&group_id)
            {
                Some(group) => group.members.remove(&dpnid),
                None => return DPNERR_INVALIDGROUP,
            };
            if !removed {
                return DPNERR_INVALIDPLAYER;
            }
            session.broadcast_reliable_group(|sequence| {
                wire_group_member(
                    GROUP_OP_REMOVE_MEMBER,
                    HOST_PLAYER_ID,
                    sequence,
                    group_id,
                    dpnid,
                )
            });
            return S_OK;
        }
        if let Some(client) = &self.client {
            let removed = match client
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get_mut(&group_id)
            {
                Some(group) => group.members.remove(&dpnid),
                None => return DPNERR_INVALIDGROUP,
            };
            if !removed {
                return DPNERR_INVALIDPLAYER;
            }
            let local_dpnid = self.local_dpnid;
            if client
                .send_reliable(|sequence| {
                    wire_group_member(
                        GROUP_OP_REMOVE_MEMBER,
                        local_dpnid,
                        sequence,
                        group_id,
                        dpnid,
                    )
                })
                .is_none()
            {
                return DPNERR_CONNECTIONLOST;
            }
            return S_OK;
        }
        DPNERR_NOCONNECTION
    }

    /// `SetGroupInfo` — real name/data update, replicated to every peer.
    pub(crate) fn set_group_info(&mut self, group_id: u32, name: &str, data: &[u8]) -> u32 {
        if data.len() > MAX_MESSAGE_PAYLOAD {
            return DPNERR_DATATOOLARGE;
        }
        if let Some(session) = &self.session {
            let updated = match session
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get_mut(&group_id)
            {
                Some(group) => {
                    group.name = name.to_string();
                    group.data = data.to_vec();
                    true
                }
                None => false,
            };
            if !updated {
                return DPNERR_INVALIDGROUP;
            }
            let message_data = data.to_vec();
            session.broadcast_reliable_group(|sequence| {
                wire_group_info(HOST_PLAYER_ID, sequence, group_id, name, &message_data)
            });
            return S_OK;
        }
        if let Some(client) = &self.client {
            let updated = match client
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get_mut(&group_id)
            {
                Some(group) => {
                    group.name = name.to_string();
                    group.data = data.to_vec();
                    true
                }
                None => false,
            };
            if !updated {
                return DPNERR_INVALIDGROUP;
            }
            let local_dpnid = self.local_dpnid;
            if client
                .send_reliable(|sequence| {
                    wire_group_info(local_dpnid, sequence, group_id, name, data)
                })
                .is_none()
            {
                return DPNERR_CONNECTIONLOST;
            }
            return S_OK;
        }
        DPNERR_NOCONNECTION
    }

    /// The group context bytes as stored by `CreateGroup`/`SetGroupInfo`.
    pub(crate) fn group_context(&self, group_id: u32) -> Result<Vec<u8>, u32> {
        self.group(group_id)
            .map(|group| group.data)
            .ok_or(DPNERR_INVALIDGROUP)
    }

    /// Update only the group context bytes, keeping the name.
    pub(crate) fn set_group_context(&mut self, group_id: u32, data: &[u8]) -> u32 {
        let name = match self.group(group_id) {
            Some(group) => group.name,
            None => return DPNERR_INVALIDGROUP,
        };
        self.set_group_info(group_id, &name, data)
    }

    /// Host-side `DestroyPeer`/`DestroyClient`: remove the player, announce
    /// the departure to the remaining players and record the event.
    pub(crate) fn destroy_player(&mut self, dpnid: u32, _destroy_data: &[u8]) -> u32 {
        let Some(session) = &self.session else {
            return DPNERR_NOTHOST;
        };
        let removed = session
            .players
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&dpnid);
        if removed.is_none() {
            return DPNERR_INVALIDPLAYER;
        }
        let leave = wire_leave(dpnid);
        for player in session.snapshot_players() {
            let _ = session.socket.send_to(&leave, player.addr);
        }
        session.events.push(SessionEvent::PlayerLeft {
            dpnid,
            reason: DPNDESTROYPLAYERREASON_HOSTDESTROYEDPLAYER,
        });
        S_OK
    }

    pub(crate) fn groups(&self) -> Vec<GroupRecord> {
        if let Some(session) = &self.session {
            return session.group_snapshot();
        }
        if let Some(client) = &self.client {
            return client
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .values()
                .cloned()
                .collect();
        }
        self.groups.values().cloned().collect()
    }

    pub(crate) fn group(&self, group_id: u32) -> Option<GroupRecord> {
        if let Some(session) = &self.session {
            return session.group(group_id);
        }
        if let Some(client) = &self.client {
            return client
                .groups
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .get(&group_id)
                .cloned();
        }
        self.groups.get(&group_id).cloned()
    }

    pub(crate) fn player_exists(&self, dpnid: u32) -> bool {
        if dpnid == self.local_dpnid || dpnid == HOST_PLAYER_ID {
            return self.local_dpnid != 0;
        }
        if let Some(session) = &self.session {
            return session.player_addr(dpnid).is_some();
        }
        self.player_cache.contains_key(&dpnid)
    }
}

impl Drop for Dplay8Peer {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// The client receiver loop: parses accept/reject/data/group/ack/join/leave/
/// terminate datagrams from the real socket, acknowledges reliable group
/// messages, suppresses duplicates and feeds the peer's queues.
#[allow(clippy::too_many_arguments)]
fn client_receive_loop(
    socket: Arc<UdpSocket>,
    inbound: Arc<InboundQueue>,
    events: Arc<EventQueue>,
    wait: Arc<ConnectWait>,
    lost: Arc<AtomicBool>,
    terminated: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    counters: Arc<Counters>,
    groups: Arc<Mutex<BTreeMap<u32, GroupRecord>>>,
    reliability: Arc<Mutex<GroupReliability>>,
    create_wait: Arc<GroupCreateWait>,
    drop_group_datagrams: Arc<AtomicU32>,
    drop_ack_datagrams: Arc<AtomicU32>,
) {
    let _ = &counters;
    let host_addr = socket
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    let mut buffer = vec![0u8; RECEIVE_BUFFER];
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let send_socket = Arc::clone(&socket);
        reliability
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .retransmit(move |message, _destination| {
                let _ = send_socket.send(message);
            });
        match socket.recv(&mut buffer) {
            Ok(length) => {
                let datagram = &buffer[..length];
                if (starts_with_magic(datagram, MAGIC_GROUP)
                    || starts_with_magic(datagram, MAGIC_GROUP_DATA))
                    && consume_drop(&drop_group_datagrams)
                {
                    continue;
                }
                if starts_with_magic(datagram, MAGIC_ACK) && consume_drop(&drop_ack_datagrams) {
                    continue;
                }
                if let Some((_request_id, assigned, host, players)) = parse_accept(datagram) {
                    wait.complete(Ok(ConnectAccept {
                        assigned,
                        host,
                        players,
                    }));
                    continue;
                }
                if let Some((_request_id, reason)) = parse_reject(datagram) {
                    wait.complete(Err(reason));
                    continue;
                }
                if let Some((_ack_sender, sequence)) = parse_group_ack(datagram) {
                    reliability
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .acknowledge(sequence, None);
                    continue;
                }
                if let Some((source, _destination, sequence, payload)) = parse_group_data(datagram)
                {
                    let is_new = reliability
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .note_inbound(HOST_PLAYER_ID, sequence);
                    let _ = socket.send(&wire_group_ack(0, sequence));
                    if !is_new {
                        continue;
                    }
                    inbound.push(ReceivedDatagram {
                        from_dpnid: source,
                        from_addr: host_addr,
                        data: payload.to_vec(),
                    });
                    continue;
                }
                if let Some((source, _destination, payload)) = parse_data(datagram) {
                    inbound.push(ReceivedDatagram {
                        from_dpnid: source,
                        from_addr: host_addr,
                        data: payload.to_vec(),
                    });
                    continue;
                }
                if let Some(operation) = parse_group(datagram) {
                    let (sequence, sender) = match &operation {
                        GroupWire::Create {
                            sender, sequence, ..
                        }
                        | GroupWire::Destroy {
                            sender, sequence, ..
                        }
                        | GroupWire::AddMember {
                            sender, sequence, ..
                        }
                        | GroupWire::RemoveMember {
                            sender, sequence, ..
                        }
                        | GroupWire::Info {
                            sender, sequence, ..
                        }
                        | GroupWire::AllocateRequest {
                            sender, sequence, ..
                        }
                        | GroupWire::AllocateResponse {
                            sender, sequence, ..
                        } => (*sequence, *sender),
                    };
                    if sender != HOST_PLAYER_ID {
                        continue;
                    }
                    let is_new = reliability
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .note_inbound(HOST_PLAYER_ID, sequence);
                    let _ = socket.send(&wire_group_ack(0, sequence));
                    if !is_new {
                        continue;
                    }
                    match operation {
                        GroupWire::Create {
                            group_id,
                            owner,
                            name,
                            data,
                            ..
                        } => {
                            let mut groups =
                                groups.lock().unwrap_or_else(|poison| poison.into_inner());
                            let group = groups.entry(group_id).or_insert_with(|| GroupRecord {
                                group_id,
                                owner,
                                name: String::new(),
                                data: Vec::new(),
                                members: BTreeSet::new(),
                            });
                            group.owner = owner;
                            group.name = name;
                            group.data = data;
                        }
                        GroupWire::Destroy { group_id, .. } => {
                            groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .remove(&group_id);
                        }
                        GroupWire::AddMember {
                            group_id, dpnid, ..
                        } => {
                            // UDP may deliver the membership announcement
                            // before the create; keep it in a placeholder that
                            // the later create fills in.
                            groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .entry(group_id)
                                .or_insert_with(|| GroupRecord {
                                    group_id,
                                    owner: 0,
                                    name: String::new(),
                                    data: Vec::new(),
                                    members: BTreeSet::new(),
                                })
                                .members
                                .insert(dpnid);
                        }
                        GroupWire::RemoveMember {
                            group_id, dpnid, ..
                        } => {
                            if let Some(group) = groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .get_mut(&group_id)
                            {
                                group.members.remove(&dpnid);
                            }
                        }
                        GroupWire::Info {
                            group_id,
                            name,
                            data,
                            ..
                        } => {
                            if let Some(group) = groups
                                .lock()
                                .unwrap_or_else(|poison| poison.into_inner())
                                .get_mut(&group_id)
                            {
                                group.name = name;
                                group.data = data;
                            }
                        }
                        GroupWire::AllocateResponse {
                            result, group_id, ..
                        } => {
                            create_wait.complete(if result == S_OK {
                                Ok(group_id)
                            } else {
                                Err(result)
                            });
                        }
                        GroupWire::AllocateRequest { .. } => {}
                    }
                    continue;
                }
                if let Some((dpnid, name)) = parse_join(datagram) {
                    events.push(SessionEvent::PlayerJoined { dpnid, name });
                    continue;
                }
                if let Some(dpnid) = parse_leave(datagram) {
                    events.push(SessionEvent::PlayerLeft {
                        dpnid,
                        reason: DPNDESTROYPLAYERREASON_NORMAL,
                    });
                    continue;
                }
                if let Some((reason, _data)) = parse_terminate(datagram) {
                    terminated.store(true, Ordering::SeqCst);
                    events.push(SessionEvent::Terminated { reason });
                    continue;
                }
                // Discovery responses / keepalives are not part of the
                // connected transport; ignore them.
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                // ICMP port-unreachable on the connected UDP socket: the host
                // is not there.  A pending connect fails with NORESPONSE.
                lost.store(true, Ordering::SeqCst);
                wait.complete(Err(DPNERR_NORESPONSE));
                break;
            }
            Err(_) => {
                lost.store(true, Ordering::SeqCst);
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-guest-process object store (used by the dispatch layer)
// ---------------------------------------------------------------------------

/// The DirectPlay objects owned by one guest process.
#[derive(Default)]
pub(crate) struct DplayRuntime {
    pub(crate) objects: BTreeMap<u64, DplayObjectEntry>,
    pub(crate) vtables: BTreeMap<u8, u64>,
    pub(crate) pending: VecDeque<PendingDplayEvent>,
}

/// A queued guest-visible event together with the peer object that owns the
/// registered message handler.
pub(crate) struct PendingDplayEvent {
    pub(crate) owner: u64,
    pub(crate) event: DplayEvent,
}

impl DplayRuntime {
    pub(crate) fn push_event(&mut self, owner: u64, event: DplayEvent) {
        self.pending.push_back(PendingDplayEvent { owner, event });
    }

    /// Drop a queued completion whose async operation was cancelled.
    pub(crate) fn cancel_pending_async(&mut self, handle: u32) -> bool {
        let before = self.pending.len();
        self.pending
            .retain(|pending| pending.event.operation_handle() != Some(handle));
        self.pending.len() != before
    }
}

/// One reference-counted guest object.
pub(crate) struct DplayObjectEntry {
    pub(crate) refcount: u32,
    pub(crate) object: DplayObject,
}

/// The three object kinds the engine hands to a guest.
pub(crate) enum DplayObject {
    Address(Dplay8Address),
    Peer(Dplay8Peer),
    Legacy(LegacyPeer),
}

static DPLAY_RUNTIMES: LazyLock<Mutex<BTreeMap<u32, DplayRuntime>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(crate) fn lock_dplay_runtimes() -> MutexGuard<'static, BTreeMap<u32, DplayRuntime>> {
    DPLAY_RUNTIMES
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

// ---------------------------------------------------------------------------
// Legacy IDirectPlay4 peer (the DirectPlayCreate object)
// ---------------------------------------------------------------------------

/// One legacy player record.
#[derive(Clone, Debug)]
pub(crate) struct LegacyPlayer {
    pub(crate) player_id: u32,
    pub(crate) name: String,
    pub(crate) addr: Option<SocketAddr>,
    pub(crate) data: Vec<u8>,
    pub(crate) flags: u32,
}

/// The engine behind the legacy `DirectPlayCreate` object.  It wraps the same
/// [`Dplay8Peer`] transport: `Open` hosts or connects, `Send`/`Receive` move
/// real datagrams and `EnumSessions` runs the same real `DP8Q`/`DP8R`
/// discovery as `EnumHosts`.
pub(crate) struct LegacyPeer {
    pub(crate) initialized: bool,
    pub(crate) peer: Dplay8Peer,
    pub(crate) local_player: u32,
    pub(crate) players: BTreeMap<u32, LegacyPlayer>,
    pub(crate) next_player: u32,
    pub(crate) session_name: String,
    pub(crate) app_guid: [u8; 16],
    pub(crate) instance_guid: [u8; 16],
    pub(crate) max_players: u32,
}

impl LegacyPeer {
    pub(crate) fn new() -> Self {
        Self {
            initialized: false,
            peer: Dplay8Peer::new(),
            local_player: 0,
            players: BTreeMap::new(),
            next_player: 2,
            session_name: String::new(),
            app_guid: [0u8; 16],
            instance_guid: [0u8; 16],
            max_players: 0,
        }
    }

    pub(crate) fn engine(&self) -> &Dplay8Peer {
        &self.peer
    }

    pub(crate) fn engine_mut(&mut self) -> &mut Dplay8Peer {
        &mut self.peer
    }

    /// Legacy `Initialize`.
    pub(crate) fn initialize(&mut self) -> u32 {
        if self.initialized {
            return DPNERR_ALREADYINITIALIZED;
        }
        let result = self.peer.initialize(0, 0, 0);
        if result == S_OK {
            self.initialized = true;
        }
        result
    }

    /// Legacy `Open` with `DPSESSION_NEWGAME`: host a real session over the
    /// same transport and register the host player.
    pub(crate) fn open_host(&mut self, session_name: &str, max_players: u32) -> u32 {
        if !self.initialized {
            return DPNERR_UNINITIALIZED;
        }
        if self.local_player != 0 {
            return DPNERR_ALREADYCONNECTED;
        }
        let desc = DplayAppDesc::new(session_name, max_players);
        let result = self
            .peer
            .host(&desc, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        if result != S_OK {
            return result;
        }
        self.session_name = session_name.to_string();
        self.max_players = max_players;
        self.instance_guid = self.peer.host_instance_guid().unwrap_or([0u8; 16]);
        self.local_player = HOST_PLAYER_ID;
        self.players.insert(
            HOST_PLAYER_ID,
            LegacyPlayer {
                player_id: HOST_PLAYER_ID,
                name: session_name.to_string(),
                addr: self.peer.local_address(),
                data: Vec::new(),
                flags: DPNPLAYER_HOST | DPNPLAYER_LOCAL,
            },
        );
        S_OK
    }

    /// Legacy `Open` against a session discovered by `EnumSessions`: connect
    /// the same real transport to the hosted instance GUID.
    pub(crate) fn open_session(&mut self, instance_guid: &[u8; 16], player_name: &str) -> u32 {
        if !self.initialized {
            return DPNERR_UNINITIALIZED;
        }
        if self.local_player != 0 {
            return DPNERR_ALREADYCONNECTED;
        }
        let Some(addr) = session_by_instance(instance_guid) else {
            return DPNERR_INVALIDINSTANCE;
        };
        let result = self.peer.connect(addr, player_name, &[]);
        if result != S_OK {
            return result;
        }
        self.instance_guid = *instance_guid;
        self.local_player = self.peer.local_dpnid();
        for player in self.peer.players() {
            self.players.entry(player.dpnid).or_insert(LegacyPlayer {
                player_id: player.dpnid,
                name: player.name,
                addr: Some(player.addr),
                data: Vec::new(),
                flags: player.flags,
            });
        }
        S_OK
    }

    /// Legacy `CreatePlayer` — mint a real local player id on this peer.
    pub(crate) fn create_player(&mut self, name: &str) -> Result<u32, u32> {
        if !self.initialized {
            return Err(DPNERR_UNINITIALIZED);
        }
        if self.local_player == 0 {
            return Err(DPNERR_NOCONNECTION);
        }
        let player_id = if self.peer.is_hosting() {
            HOST_PLAYER_ID
        } else {
            let player_id = self.next_player.max(self.peer.local_dpnid().max(2));
            self.next_player = player_id + 1;
            player_id
        };
        self.players.insert(
            player_id,
            LegacyPlayer {
                player_id,
                name: name.to_string(),
                addr: self.peer.local_address(),
                data: Vec::new(),
                flags: DPNPLAYER_LOCAL,
            },
        );
        Ok(player_id)
    }

    /// Legacy `DestroyPlayer`.
    pub(crate) fn destroy_player(&mut self, player_id: u32) -> u32 {
        if self.players.remove(&player_id).is_none() {
            return DPNERR_INVALIDPLAYER;
        }
        S_OK
    }

    /// Legacy `Send` — a real datagram through the same engine.
    pub(crate) fn send(&mut self, from: u32, to: u32, data: &[u8]) -> u32 {
        if from != 0 && from != self.local_player {
            return DPNERR_INVALIDPLAYER;
        }
        self.peer.send_to(to, data)
    }

    /// Legacy `Receive` — the next real datagram.
    pub(crate) fn receive(&mut self, timeout: Duration) -> Option<ReceivedDatagram> {
        self.peer.receive_from(timeout)
    }

    /// Legacy `EnumSessions` — the same real discovery as `EnumHosts`.
    pub(crate) fn enum_sessions(&self, timeout: Duration) -> Vec<SessionInfo> {
        self.peer.enum_hosts(&self.app_guid, &[], timeout)
    }

    /// Legacy `GetPlayerAddress` view (the real bound peer address).
    pub(crate) fn player_address(&self, player_id: u32) -> Option<SocketAddr> {
        self.players
            .get(&player_id)
            .and_then(|player| player.addr)
            .or_else(|| {
                if player_id == self.local_player {
                    self.peer.local_address()
                } else {
                    None
                }
            })
    }

    /// Legacy `Close`.
    pub(crate) fn close(&mut self) -> u32 {
        let result = self.peer.close();
        self.local_player = 0;
        self.players.clear();
        result
    }
}

impl Drop for LegacyPeer {
    fn drop(&mut self) {
        let _ = self.peer.close();
    }
}

// ---------------------------------------------------------------------------
// Guest-facing interface tables
// ---------------------------------------------------------------------------

/// The guest-visible DirectPlay interfaces, keyed by the small ids the host
/// thunks carry.  The numeric values are private to this model; the guest
/// only ever sees them through the vtables the engine hands out.
pub(crate) const IFACE_ADDRESS: u8 = 0;
pub(crate) const IFACE_PEER: u8 = 1;
pub(crate) const IFACE_LEGACY: u8 = 2;

/// Vtable method indices (including the three `IUnknown` slots at 0..=2) and
/// the x86 stdcall argument word count including `this`, exactly per
/// `dpaddr.h` (`IDirectPlay8Address`) and `dplay8.h` (`IDirectPlay8Peer`),
/// plus the legacy `IDirectPlay4` table from `dplay.h`.
pub(crate) const ADDRESS_METHODS: &[(u16, u8)] = &[
    (0, 3),  // QueryInterface
    (1, 1),  // AddRef
    (2, 1),  // Release
    (3, 2),  // BuildFromURLW
    (4, 2),  // BuildFromURLA
    (5, 2),  // Duplicate
    (6, 2),  // SetEqual
    (7, 2),  // IsEqual
    (8, 1),  // Clear
    (9, 3),  // GetURLW
    (10, 3), // GetURLA
    (11, 2), // GetSP
    (12, 3), // GetUserData
    (13, 2), // SetSP
    (14, 3), // SetUserData
    (15, 2), // GetNumComponents
    (16, 5), // GetComponentByName
    (17, 7), // GetComponentByIndex
    (18, 5), // AddComponent
    (19, 2), // GetDevice
    (20, 2), // SetDevice
    (21, 3), // BuildFromDirectPlay4Address
];

pub(crate) const PEER_METHODS: &[(u16, u8)] = &[
    (0, 3),   // QueryInterface
    (1, 1),   // AddRef
    (2, 1),   // Release
    (3, 4),   // Initialize
    (4, 7),   // EnumServiceProviders
    (5, 3),   // CancelAsyncOperation
    (6, 12),  // Connect
    (7, 8),   // SendTo
    (8, 5),   // GetSendQueueInfo
    (9, 8),   // Host
    (10, 4),  // GetApplicationDesc
    (11, 3),  // SetApplicationDesc
    (12, 6),  // CreateGroup
    (13, 5),  // DestroyGroup
    (14, 6),  // AddPlayerToGroup
    (15, 6),  // RemovePlayerFromGroup
    (16, 6),  // SetGroupInfo
    (17, 5),  // GetGroupInfo
    (18, 4),  // EnumPlayersAndGroups
    (19, 5),  // EnumGroupMembers
    (20, 5),  // SetPeerInfo
    (21, 5),  // GetPeerInfo
    (22, 4),  // GetPeerAddress
    (23, 4),  // GetLocalHostAddresses
    (24, 2),  // Close
    (25, 12), // EnumHosts
    (26, 5),  // DestroyPeer
    (27, 3),  // ReturnBuffer
    (28, 4),  // GetPlayerContext
    (29, 4),  // GetGroupContext
    (30, 3),  // GetCaps
    (31, 3),  // SetCaps
    (32, 4),  // SetSPCaps
    (33, 4),  // GetSPCaps
    (34, 4),  // GetConnectionInfo
    (35, 4),  // RegisterLobby
    (36, 4),  // TerminateSession
];

/// The legacy `IDirectPlay4` table (`dplay.h`): 53 slots, three `IUnknown`
/// plus the `IDirectPlay2`/`IDirectPlay3`/`IDirectPlay4` method sets.
pub(crate) const LEGACY_METHODS: &[(u16, u8)] = &[
    (0, 3),   // QueryInterface
    (1, 1),   // AddRef
    (2, 1),   // Release
    (3, 3),   // AddPlayerToGroup
    (4, 1),   // Close
    (5, 6),   // CreateGroup
    (6, 7),   // CreatePlayer
    (7, 3),   // DeletePlayerFromGroup
    (8, 2),   // DestroyGroup
    (9, 2),   // DestroyPlayer
    (10, 5),  // EnumGroupPlayers
    (11, 4),  // EnumGroups
    (12, 4),  // EnumPlayers
    (13, 5),  // EnumSessions
    (14, 3),  // GetCaps
    (15, 5),  // GetGroupData
    (16, 4),  // GetGroupName
    (17, 3),  // GetMessageCount
    (18, 4),  // GetPlayerAddress
    (19, 4),  // GetPlayerCaps
    (20, 5),  // GetPlayerData
    (21, 4),  // GetPlayerName
    (22, 3),  // GetSessionDesc
    (23, 2),  // Initialize
    (24, 3),  // Open
    (25, 6),  // Receive
    (26, 6),  // Send
    (27, 5),  // SetGroupData
    (28, 4),  // SetGroupName
    (29, 5),  // SetPlayerData
    (30, 4),  // SetPlayerName
    (31, 3),  // SetSessionDesc
    (32, 3),  // AddGroupToGroup
    (33, 7),  // CreateGroupInGroup
    (34, 3),  // DeleteGroupFromGroup
    (35, 5),  // EnumConnections
    (36, 5),  // EnumGroupsInGroup
    (37, 5),  // GetGroupConnectionSettings
    (38, 3),  // InitializeConnection
    (39, 5),  // SecureOpen
    (40, 5),  // SendChatMessage
    (41, 5),  // SetGroupConnectionSettings
    (42, 3),  // StartSession
    (43, 3),  // GetGroupFlags
    (44, 3),  // GetGroupParent
    (45, 5),  // GetPlayerAccount
    (46, 3),  // GetPlayerFlags
    (47, 3),  // GetGroupOwner
    (48, 3),  // SetGroupOwner
    (49, 10), // SendEx
    (50, 6),  // GetMessageQueue
    (51, 3),  // CancelMessage
    (52, 4),  // CancelPriority
];

/// The vtable layout for one interface id.
pub(crate) fn interface_methods(interface: u8) -> &'static [(u16, u8)] {
    match interface {
        IFACE_ADDRESS => ADDRESS_METHODS,
        IFACE_PEER => PEER_METHODS,
        IFACE_LEGACY => LEGACY_METHODS,
        _ => &[],
    }
}

/// Human-readable method name for tracing/diagnostics.
pub(crate) fn method_name(interface: u8, method: u16) -> &'static str {
    match interface {
        IFACE_ADDRESS => match method {
            0 => "QueryInterface",
            1 => "AddRef",
            2 => "Release",
            3 => "BuildFromURLW",
            4 => "BuildFromURLA",
            5 => "Duplicate",
            6 => "SetEqual",
            7 => "IsEqual",
            8 => "Clear",
            9 => "GetURLW",
            10 => "GetURLA",
            11 => "GetSP",
            12 => "GetUserData",
            13 => "SetSP",
            14 => "SetUserData",
            15 => "GetNumComponents",
            16 => "GetComponentByName",
            17 => "GetComponentByIndex",
            18 => "AddComponent",
            19 => "GetDevice",
            20 => "SetDevice",
            21 => "BuildFromDirectPlay4Address",
            _ => "?",
        },
        IFACE_PEER => match method {
            0 => "QueryInterface",
            1 => "AddRef",
            2 => "Release",
            3 => "Initialize",
            4 => "EnumServiceProviders",
            5 => "CancelAsyncOperation",
            6 => "Connect",
            7 => "SendTo",
            8 => "GetSendQueueInfo",
            9 => "Host",
            10 => "GetApplicationDesc",
            11 => "SetApplicationDesc",
            12 => "CreateGroup",
            13 => "DestroyGroup",
            14 => "AddPlayerToGroup",
            15 => "RemovePlayerFromGroup",
            16 => "SetGroupInfo",
            17 => "GetGroupInfo",
            18 => "EnumPlayersAndGroups",
            19 => "EnumGroupMembers",
            20 => "SetPeerInfo",
            21 => "GetPeerInfo",
            22 => "GetPeerAddress",
            23 => "GetLocalHostAddresses",
            24 => "Close",
            25 => "EnumHosts",
            26 => "DestroyPeer",
            27 => "ReturnBuffer",
            28 => "GetPlayerContext",
            29 => "GetGroupContext",
            30 => "GetCaps",
            31 => "SetCaps",
            32 => "SetSPCaps",
            33 => "GetSPCaps",
            34 => "GetConnectionInfo",
            35 => "RegisterLobby",
            36 => "TerminateSession",
            _ => "?",
        },
        IFACE_LEGACY => match method {
            0 => "QueryInterface",
            1 => "AddRef",
            2 => "Release",
            3 => "AddPlayerToGroup",
            4 => "Close",
            5 => "CreateGroup",
            6 => "CreatePlayer",
            7 => "DeletePlayerFromGroup",
            8 => "DestroyGroup",
            9 => "DestroyPlayer",
            10 => "EnumGroupPlayers",
            11 => "EnumGroups",
            12 => "EnumPlayers",
            13 => "EnumSessions",
            14 => "GetCaps",
            15 => "GetGroupData",
            16 => "GetGroupName",
            17 => "GetMessageCount",
            18 => "GetPlayerAddress",
            19 => "GetPlayerCaps",
            20 => "GetPlayerData",
            21 => "GetPlayerName",
            22 => "GetSessionDesc",
            23 => "Initialize",
            24 => "Open",
            25 => "Receive",
            26 => "Send",
            27 => "SetGroupData",
            28 => "SetGroupName",
            29 => "SetPlayerData",
            30 => "SetPlayerName",
            31 => "SetSessionDesc",
            32 => "AddGroupToGroup",
            33 => "CreateGroupInGroup",
            34 => "DeleteGroupFromGroup",
            35 => "EnumConnections",
            36 => "EnumGroupsInGroup",
            37 => "GetGroupConnectionSettings",
            38 => "InitializeConnection",
            39 => "SecureOpen",
            40 => "SendChatMessage",
            41 => "SetGroupConnectionSettings",
            42 => "StartSession",
            43 => "GetGroupFlags",
            44 => "GetGroupParent",
            45 => "GetPlayerAccount",
            46 => "GetPlayerFlags",
            47 => "GetGroupOwner",
            48 => "SetGroupOwner",
            49 => "SendEx",
            50 => "GetMessageQueue",
            51 => "CancelMessage",
            52 => "CancelPriority",
            _ => "?",
        },
        _ => "?",
    }
}

/// Events the dispatch layer turns into guest callbacks.
#[derive(Clone, Debug)]
pub(crate) enum DplayEvent {
    CreatePlayer {
        dpnid: u32,
        context: u64,
    },
    DestroyPlayer {
        dpnid: u32,
        reason: u32,
        context: u64,
    },
    Receive {
        sender: u32,
        context: u64,
        data: Vec<u8>,
    },
    ConnectComplete {
        async_op: u32,
        context: u64,
        result: u32,
        dpnid: u32,
    },
    SendComplete {
        async_op: u32,
        context: u64,
        result: u32,
    },
    TerminateSession {
        result: u32,
        data: Vec<u8>,
    },
    SessionLost {
        result: u32,
    },
    EnumHostsResponse {
        context: u64,
        session: SessionInfo,
        async_op: u32,
    },
}

impl DplayEvent {
    /// The async-operation handle this event completes, if any.
    pub(crate) fn async_operation(&self) -> Option<u32> {
        match self {
            DplayEvent::ConnectComplete { async_op, .. }
            | DplayEvent::SendComplete { async_op, .. } => Some(*async_op),
            _ => None,
        }
    }

    /// The async-operation handle that produced this event, including
    /// streaming responses (an enumeration emits one response per host).
    pub(crate) fn operation_handle(&self) -> Option<u32> {
        match self {
            DplayEvent::ConnectComplete { async_op, .. }
            | DplayEvent::SendComplete { async_op, .. } => Some(*async_op),
            DplayEvent::EnumHostsResponse { async_op, .. } if *async_op != 0 => Some(*async_op),
            _ => None,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::HostThunk;
    use crate::runtime::dispatch::test_support::{dispatch_x86, with_big_stack, x86_fixture};
    use std::net::UdpSocket;

    fn localhost() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn started_peer() -> Dplay8Peer {
        let mut peer = Dplay8Peer::new();
        assert_eq!(peer.initialize(0, 0, 0), S_OK, "Initialize");
        peer
    }

    fn xor_shift(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    // ── address object ─────────────────────────────────────────────────────

    #[test]
    fn address_sp_component_and_url_round_trip() {
        let mut address = Dplay8Address::new();
        assert_eq!(address.set_sp(&CLSID_DP8SP_TCPIP), S_OK);
        assert_eq!(address.get_sp(), Some(CLSID_DP8SP_TCPIP));
        assert_eq!(address.set_hostname("127.0.0.1"), S_OK);
        assert_eq!(address.set_port(2302), S_OK);
        assert_eq!(address.hostname().as_deref(), Some("127.0.0.1"));
        assert_eq!(address.port(), Some(2302));
        assert_eq!(
            address.socket_addr(),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2302))
        );
        let url = address.url();
        assert_eq!(
            url,
            "x-directplay:/provider=IP;hostname=127.0.0.1;port=2302"
        );

        let mut rebuilt = Dplay8Address::new();
        assert_eq!(rebuilt.build_from_url(&url), S_OK);
        assert_eq!(rebuilt.url(), url, "URL round trip");
        assert_eq!(rebuilt.get_sp(), Some(CLSID_DP8SP_TCPIP));
        assert!(rebuilt.is_equal(&address), "rebuilt address is equal");
        assert_eq!(rebuilt.num_components(), 3);
        assert_eq!(
            rebuilt.component_at(0).map(|(name, _)| name.to_string()),
            Some("provider".to_string()),
            "the provider is the first component"
        );
    }

    #[test]
    fn address_url_special_characters_round_trip() {
        let mut address = Dplay8Address::new();
        assert_eq!(
            address.set_string("nameinfo", "semi;eq=hash#percent%"),
            S_OK
        );
        assert_eq!(address.set_port(6073), S_OK);
        let url = address.url();
        let mut rebuilt = Dplay8Address::new();
        assert_eq!(rebuilt.build_from_url(&url), S_OK);
        assert_eq!(
            rebuilt.string("nameinfo").as_deref(),
            Some("semi;eq=hash#percent%")
        );
        assert_eq!(rebuilt.port(), Some(6073));
    }

    #[test]
    fn address_build_from_url_rejects_malformed() {
        let mut address = Dplay8Address::new();
        assert_eq!(address.build_from_url("http://example/"), DPNERR_INVALIDURL);
        assert_eq!(
            address.build_from_url("x-directplay:/=oops"),
            DPNERR_INVALIDURL
        );
        assert_eq!(
            address.build_from_url("x-directplay:/noequals"),
            DPNERR_INVALIDURL
        );
        assert_eq!(
            address.num_components(),
            0,
            "rejected URL leaves state empty"
        );
    }

    #[test]
    fn address_duplicate_set_equal_clear_and_user_data() {
        let mut original = Dplay8Address::new();
        assert_eq!(original.set_hostname("10.0.0.1"), S_OK);
        assert_eq!(original.set_port(7), S_OK);
        original.set_user_data(b"casa1");
        let duplicate = original.duplicate();
        assert!(original.is_equal(&duplicate));

        let mut other = Dplay8Address::new();
        assert!(!other.is_equal(&original));
        other.set_equal(&duplicate);
        assert!(other.is_equal(&original));
        other.clear();
        assert_eq!(other.num_components(), 0);
        assert!(other.user_data().is_empty());

        let mut device = Dplay8Address::new();
        assert_eq!(device.set_device(&CLSID_DP8SP_TCPIP), S_OK);
        assert_eq!(device.get_device(), Some(CLSID_DP8SP_TCPIP));
        assert_eq!(
            device.add_component("raw", DPNA_DATATYPE_BINARY, &[1, 2, 3]),
            S_OK
        );
        assert_eq!(
            device.component("raw").map(|c| c.data.clone()),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            device.add_component("bad", DPNA_DATATYPE_DWORD, &[1, 2]),
            DPNERR_INVALIDPARAM
        );
    }

    // ── wire messages ──────────────────────────────────────────────────────

    #[test]
    fn wire_control_messages_round_trip() {
        let guid = random_guid();
        let query = wire_query(42, &guid);
        assert_eq!(parse_query(&query), Some((WIRE_PROTOCOL_VERSION, 42, guid)));
        assert_eq!(parse_query(&query[..10]), None, "truncated query rejected");
        assert_eq!(parse_query(b"NOPE"), None, "wrong magic rejected");

        let connect = wire_connect(7, &guid, "Player One", b"ticket");
        let (request, instance, name, data) = parse_connect(&connect).expect("connect");
        assert_eq!(request, 7);
        assert_eq!(instance, guid);
        assert_eq!(name, "Player One");
        assert_eq!(data, b"ticket");

        let accept = wire_accept(7, 3, 1, &[(2, "Two".to_string())]);
        let (request, assigned, host, players) = parse_accept(&accept).expect("accept");
        assert_eq!((request, assigned, host), (7, 3, 1));
        assert_eq!(players, vec![(2, "Two".to_string())]);

        let reject = wire_reject(7, DPNERR_SESSIONFULL);
        assert_eq!(parse_reject(&reject), Some((7, DPNERR_SESSIONFULL)));

        let join = wire_join(9, "Nine");
        assert_eq!(parse_join(&join), Some((9, "Nine".to_string())));
        let leave = wire_leave(9);
        assert_eq!(parse_leave(&leave), Some(9));

        let data_message = wire_data(9, 0, b"payload");
        let (source, destination, payload) = parse_data(&data_message).expect("data");
        assert_eq!(
            (source, destination, payload),
            (9, 0, b"payload".as_slice())
        );

        let terminate = wire_terminate(DPNERR_HOSTTERMINATEDSESSION, b"bye");
        let (reason, body) = parse_terminate(&terminate).expect("terminate");
        assert_eq!(reason, DPNERR_HOSTTERMINATEDSESSION);
        assert_eq!(body, b"bye");
        assert_eq!(parse_data(&data_message[..8]), None, "short data rejected");
    }

    // ── peer engine over real UDP ──────────────────────────────────────────

    #[test]
    fn host_connect_and_exchange_real_datagrams() {
        let mut host = started_peer();
        let desc = DplayAppDesc::new("Casa1 Exchange", 8);
        assert_eq!(
            host.host(&desc, localhost()),
            S_OK,
            "Host binds a real socket"
        );
        let host_addr = host.local_address().expect("host address");
        assert_ne!(host_addr.port(), 0, "a real ephemeral port");

        let mut client = started_peer();
        client.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(
            client.connect(host_addr, "Client One", b"connect-data"),
            S_OK,
            "Connect completes the real DP8C/DP8A exchange"
        );
        let client_id = client.local_dpnid();
        assert_ne!(client_id, 0);
        assert_eq!(client.host_dpnid(), HOST_PLAYER_ID);

        let host_players = host.players();
        assert_eq!(host_players.len(), 2, "host + client");
        assert!(host_players.iter().any(|p| p.dpnid == client_id));

        assert_eq!(client.send_to(HOST_PLAYER_ID, b"ping from client"), S_OK);
        let received = host
            .receive_from(Duration::from_secs(3))
            .expect("the host receives the real datagram");
        assert_eq!(received.data, b"ping from client");
        assert_eq!(received.from_dpnid, client_id);

        assert_eq!(host.send_to(client_id, b"pong from host"), S_OK);
        let received = client
            .receive_from(Duration::from_secs(3))
            .expect("the client receives the real datagram");
        assert_eq!(received.data, b"pong from host");
        assert_eq!(received.from_dpnid, HOST_PLAYER_ID);

        let host_counters = host.connection_info();
        assert!(host_counters.bytes_received >= 15);
        assert!(host_counters.packets_received >= 1);
        assert!(client.connection_info().bytes_sent >= 15);

        assert_eq!(host.close(), S_OK);
        assert_eq!(client.close(), S_OK);
    }

    #[test]
    fn host_with_max_players_rejects_second_client_with_session_full() {
        let mut host = started_peer();
        let mut desc = DplayAppDesc::new("Full House", 2);
        desc.max_players = 2;
        assert_eq!(host.host(&desc, localhost()), S_OK);
        let host_addr = host.local_address().expect("host address");

        let mut first = started_peer();
        first.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(first.connect(host_addr, "First", &[]), S_OK);

        let mut second = started_peer();
        second.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(
            second.connect(host_addr, "Second", &[]),
            DPNERR_SESSIONFULL,
            "the host rejects with the real session-full error"
        );
        assert_eq!(host.players().len(), 2);
        first.close();
        host.close();
    }

    #[test]
    fn joining_peer_announces_to_existing_clients() {
        let mut host = started_peer();
        assert_eq!(
            host.host(&DplayAppDesc::new("Announce", 8), localhost()),
            S_OK
        );
        let host_addr = host.local_address().expect("host address");

        let mut observer = started_peer();
        observer.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(observer.connect(host_addr, "Observer", &[]), S_OK);

        let mut joiner = started_peer();
        joiner.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(joiner.connect(host_addr, "Joiner", &[]), S_OK);
        let joiner_id = joiner.local_dpnid();

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let events = observer.drain_events();
            if events.iter().any(
                |event| matches!(event, SessionEvent::PlayerJoined { dpnid, .. } if *dpnid == joiner_id),
            ) {
                break;
            }
            assert!(Instant::now() < deadline, "joiner announcement arrived");
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            observer
                .players()
                .iter()
                .any(|player| player.dpnid == joiner_id)
        );

        observer.close();
        joiner.close();
        host.close();
    }

    #[test]
    fn enum_hosts_discovers_real_local_session() {
        let mut host = started_peer();
        let mut desc = DplayAppDesc::new("Enumeration Target", 6);
        desc.application_guid = [7u8; 16];
        assert_eq!(host.host(&desc, localhost()), S_OK);
        let host_addr = host.local_address().expect("host address");
        let instance = host.host_instance_guid().expect("instance guid");

        let scout = started_peer();
        let found = scout.enum_hosts(&[7u8; 16], &[host_addr], Duration::from_secs(2));
        let session = found
            .iter()
            .find(|session| session.instance_guid == instance)
            .expect("the real session is discovered over UDP");
        assert_eq!(session.session_name, "Enumeration Target");
        assert_eq!(session.address, host_addr);
        assert_eq!(session.max_players, 6);
        assert_eq!(session.current_players, 1);

        let other_application =
            scout.enum_hosts(&[9u8; 16], &[host_addr], Duration::from_millis(300));
        assert!(
            !other_application
                .iter()
                .any(|session| session.instance_guid == instance),
            "application-guid filtering"
        );

        assert_eq!(host.close(), S_OK);
        let after_close = scout.enum_hosts(&[7u8; 16], &[host_addr], Duration::from_millis(300));
        assert!(
            !after_close
                .iter()
                .any(|session| session.instance_guid == instance),
            "a closed session is no longer discoverable"
        );
    }

    #[test]
    fn host_busy_port_reports_addressing() {
        let occupied = UdpSocket::bind(localhost()).expect("occupy a port");
        let addr = occupied.local_addr().expect("port");
        let mut peer = started_peer();
        assert_eq!(
            peer.host(&DplayAppDesc::new("Busy", 4), addr),
            DPNERR_ADDRESSING,
            "a busy port is a real addressing failure"
        );
        assert!(!peer.is_hosting());
    }

    #[test]
    fn connect_without_answer_times_out_with_noresponse() {
        let silent = UdpSocket::bind(localhost()).expect("silent host");
        let addr = silent.local_addr().expect("port");
        let mut peer = started_peer();
        peer.set_connect_timeout(Duration::from_millis(250));
        assert_eq!(peer.connect(addr, "Nobody", &[]), DPNERR_NORESPONSE);
        assert!(!peer.is_connected());
    }

    #[test]
    fn connect_to_closed_port_reports_noresponse() {
        let closed = UdpSocket::bind(localhost()).expect("pick a port");
        let addr = closed.local_addr().expect("port");
        drop(closed);
        let mut peer = started_peer();
        peer.set_connect_timeout(Duration::from_millis(500));
        assert_eq!(peer.connect(addr, "Nobody", &[]), DPNERR_NORESPONSE);
    }

    #[test]
    fn operations_before_initialize_return_uninitialized() {
        let mut peer = Dplay8Peer::new();
        assert_eq!(
            peer.host(&DplayAppDesc::new("x", 4), localhost()),
            DPNERR_UNINITIALIZED
        );
        assert_eq!(peer.connect(localhost(), "x", &[]), DPNERR_UNINITIALIZED);
        assert_eq!(peer.send_to(0, b"x"), DPNERR_UNINITIALIZED);
        assert_eq!(peer.initialize(0, 0, 0), S_OK);
        assert_eq!(peer.initialize(0, 0, 0), DPNERR_ALREADYINITIALIZED);
        assert_eq!(peer.initialize(0, 0, 1 << 20), DPNERR_ALREADYINITIALIZED);
    }

    #[test]
    fn send_error_paths() {
        let mut host = started_peer();
        assert_eq!(host.host(&DplayAppDesc::new("Sends", 4), localhost()), S_OK);
        let host_addr = host.local_address().expect("host address");
        let mut client = started_peer();
        client.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(client.connect(host_addr, "Sender", &[]), S_OK);

        assert_eq!(
            client.send_to(4242, b"unknown player"),
            DPNERR_INVALIDPLAYER
        );
        let oversized = vec![0u8; MAX_MESSAGE_PAYLOAD + 1];
        assert_eq!(
            client.send_to(HOST_PLAYER_ID, &oversized),
            DPNERR_DATATOOLARGE
        );

        let mut idle = started_peer();
        assert_eq!(idle.send_to(HOST_PLAYER_ID, b"nobody"), DPNERR_NOCONNECTION);

        client.close();
        host.close();
    }

    #[test]
    fn caps_and_sp_caps_come_from_transport_facts() {
        let mut host = started_peer();
        assert_eq!(host.host(&DplayAppDesc::new("Caps", 4), localhost()), S_OK);
        let caps = host.caps();
        assert_eq!(caps.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
        assert_eq!(caps.connect_retries, 1);
        assert_eq!(caps.timeout_until_keep_alive_ms, DEFAULT_KEEPALIVE_MS);

        let sp_caps = host.sp_caps();
        assert_eq!(sp_caps.num_threads, 1, "one real service thread");
        assert!(sp_caps.flags & DPNSPCAPS_SUPPORTSBROADCAST != 0);
        assert!(sp_caps.flags & DPNSPCAPS_SUPPORTSALLADAPTERS != 0);
        assert_eq!(sp_caps.max_enum_payload_size as usize, MAX_MESSAGE_PAYLOAD);
        assert_eq!(sp_caps.default_enum_timeout_ms, DEFAULT_ENUM_TIMEOUT_MS);

        let updated = DplayCaps {
            flags: 0,
            connect_timeout_ms: 1500,
            connect_retries: 2,
            timeout_until_keep_alive_ms: 1000,
        };
        assert_eq!(host.set_caps(&updated), S_OK);
        assert_eq!(host.caps().connect_timeout_ms, 1500);
        let updated_sp = DplaySpCaps {
            flags: 0,
            num_threads: 2,
            default_enum_count: 2,
            default_enum_retry_interval_ms: 10,
            default_enum_timeout_ms: 42,
            max_enum_payload_size: 100,
            buffers_per_thread: 2,
            system_buffer_size: 1024,
        };
        assert_eq!(host.set_sp_caps(&updated_sp), S_OK);
        assert_eq!(host.sp_caps().default_enum_timeout_ms, 42);
        assert_eq!(
            host.set_caps(&DplayCaps {
                flags: 0,
                connect_timeout_ms: 0,
                connect_retries: 0,
                timeout_until_keep_alive_ms: 0,
            }),
            DPNERR_INVALIDPARAM
        );
        host.close();
    }

    #[test]
    fn host_close_terminates_connected_client() {
        let mut host = started_peer();
        assert_eq!(
            host.host(&DplayAppDesc::new("Terminate", 4), localhost()),
            S_OK
        );
        let host_addr = host.local_address().expect("host address");
        let mut client = started_peer();
        client.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(client.connect(host_addr, "Leaver", &[]), S_OK);

        assert_eq!(host.close(), S_OK);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !client.is_terminated() {
            let _ = client.drain_events();
            assert!(Instant::now() < deadline, "the client observes DP8S");
            thread::sleep(Duration::from_millis(20));
        }
        client.close();
    }

    #[test]
    fn group_model_is_real_bookkeeping() {
        let mut host = started_peer();
        assert_eq!(
            host.host(&DplayAppDesc::new("Groups", 4), localhost()),
            S_OK
        );
        let group = host
            .create_group("Team", HOST_PLAYER_ID, b"data")
            .expect("group");
        assert_eq!(host.add_player_to_group(group, HOST_PLAYER_ID), S_OK);
        assert_eq!(
            host.add_player_to_group(group, HOST_PLAYER_ID),
            DPNERR_DUPLICATECOMMAND
        );
        assert_eq!(host.remove_player_from_group(group, HOST_PLAYER_ID), S_OK);
        assert_eq!(
            host.remove_player_from_group(group, HOST_PLAYER_ID),
            DPNERR_INVALIDPLAYER
        );
        assert_eq!(host.destroy_group(group), S_OK);
        assert_eq!(host.destroy_group(group), DPNERR_INVALIDGROUP);
        host.close();
    }

    #[test]
    fn manual_receive_and_handler_observe_the_same_datagrams() {
        let mut host = started_peer();
        assert_eq!(
            host.host(&DplayAppDesc::new("Dual Consumers", 4), localhost()),
            S_OK
        );
        let host_addr = host.local_address().expect("host address");
        let mut client = started_peer();
        client.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(client.connect(host_addr, "Sender", &[]), S_OK);

        // Manual receive consumes its copy; the handler still receives an
        // independent event for the same datagram.
        assert_eq!(client.send_to(HOST_PLAYER_ID, b"manual-first"), S_OK);
        let manual = host
            .receive_from(Duration::from_secs(3))
            .expect("manual receive");
        assert_eq!(manual.data, b"manual-first");

        assert_eq!(client.send_to(HOST_PLAYER_ID, b"handler-first"), S_OK);
        let mut handled = Vec::new();
        assert!(
            wait_until(Duration::from_secs(3), || {
                for event in host.poll_engine_events() {
                    if let DplayEvent::Receive { data, .. } = event {
                        handled.push(data);
                    }
                }
                handled
                    .iter()
                    .any(|data| data.as_slice() == b"handler-first")
            }),
            "the message handler observes the real datagrams"
        );
        assert!(
            handled
                .iter()
                .any(|data| data.as_slice() == b"manual-first"),
            "a manually consumed datagram is still delivered to the handler"
        );

        // The handler consuming its copy does not steal the manual copy.
        let manual = host
            .receive_from(Duration::from_secs(3))
            .expect("manual receive after handler delivery");
        assert_eq!(manual.data, b"handler-first");
        assert!(host.poll_receive().is_none(), "no manual duplicate");
        assert!(
            !host
                .poll_engine_events()
                .iter()
                .any(|event| matches!(event, DplayEvent::Receive { .. })),
            "no handler duplicate"
        );

        client.close();
        host.close();
    }

    // ── guest dispatch (real vtables through the runtime dispatcher) ───────

    fn guest_put(memory: &mut crate::cpu::MemoryImage, address: u64, bytes: &[u8]) {
        memory.map_bytes(address, bytes);
    }

    fn guest_put_u32(memory: &mut crate::cpu::MemoryImage, address: u64, value: u32) {
        memory.map_bytes(address, &value.to_le_bytes());
    }

    fn guest_read_u32(memory: &crate::cpu::MemoryImage, address: u64) -> u32 {
        let bytes = memory.read_bytes(address, 4).expect("guest read");
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn guest_put_utf16(memory: &mut crate::cpu::MemoryImage, address: u64, text: &str) {
        let mut bytes = encode_utf16_bytes(text);
        bytes.extend_from_slice(&[0, 0]);
        memory.map_bytes(address, &bytes);
    }

    fn guest_call(
        fixture: &mut crate::runtime::dispatch::test_support::Fixture,
        this: u64,
        interface: u8,
        method: u16,
        args: &[u32],
    ) -> u64 {
        let words = interface_methods(interface)
            .iter()
            .find(|(index, _)| *index == method)
            .expect("method exists")
            .1;
        let mut stack_args = vec![this as u32];
        stack_args.extend_from_slice(args);
        dispatch_x86(
            fixture,
            HostThunk::Dplay8Method {
                interface,
                method,
                x86_arg_bytes: words.saturating_mul(4),
            },
            &stack_args,
        )
    }

    #[test]
    fn guest_direct_play8_create_initialize_host_and_close() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("dplay-guest-peer");
            let clsid = 0x40_000_u64;
            let iid = 0x40_100_u64;
            let out = 0x40_200_u64;
            guest_put(&mut fixture.memory, clsid, &CLSID_DIRECTPLAY8_PEER);
            guest_put(&mut fixture.memory, iid, &IID_IDIRECTPLAY8_PEER);
            guest_put_u32(&mut fixture.memory, out, 0);

            let hr = dispatch_x86(
                &mut fixture,
                HostThunk::DirectPlay8Create,
                &[clsid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, u64::from(S_OK), "DirectPlay8Create");
            let peer = guest_read_u32(&fixture.memory, out) as u64;
            assert_ne!(peer, 0, "a real peer object");
            let vtable = guest_read_u32(&fixture.memory, peer) as u64;
            assert_ne!(vtable, 0, "a populated vtable");

            // Initialize(0x1234, NULL handler, 0).
            assert_eq!(
                guest_call(&mut fixture, peer, IFACE_PEER, 3, &[0x1234, 0, 0]),
                u64::from(S_OK)
            );
            assert_eq!(
                guest_call(&mut fixture, peer, IFACE_PEER, 3, &[0, 0, 0]),
                u64::from(DPNERR_ALREADYINITIALIZED)
            );

            // One address object for the device list.
            let address_out = 0x40_300_u64;
            let address_iid = 0x40_320_u64;
            guest_put(&mut fixture.memory, address_iid, &IID_IDIRECTPLAY8_ADDRESS);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::DirectPlay8AddressCreate,
                    &[address_iid as u32, address_out as u32, 0],
                ),
                u64::from(S_OK)
            );
            let address = guest_read_u32(&fixture.memory, address_out) as u64;
            assert_ne!(address, 0);

            // DPN_APPLICATION_DESC (x86): name = "Casa1 Guest Session".
            let desc = 0x41_000_u64;
            let name = 0x42_000_u64;
            guest_put_utf16(&mut fixture.memory, name, "Casa1 Guest Session");
            guest_put(&mut fixture.memory, desc, &[0u8; 72]);
            guest_put_u32(&mut fixture.memory, desc, 72);
            guest_put_u32(&mut fixture.memory, desc + 40, 4);
            guest_put_u32(&mut fixture.memory, desc + 48, name as u32);

            let devices = 0x43_000_u64;
            guest_put_u32(&mut fixture.memory, devices, address as u32);
            let hr = guest_call(
                &mut fixture,
                peer,
                IFACE_PEER,
                9,
                &[desc as u32, devices as u32, 1, 0, 0, 0, 0],
            );
            assert_eq!(hr, u64::from(S_OK), "Host");
            assert!(
                hosted_sessions()
                    .iter()
                    .any(|session| session.session_name == "Casa1 Guest Session"),
                "the guest-hosted session is a real registry entry"
            );

            assert_eq!(
                guest_call(&mut fixture, peer, IFACE_PEER, 30, &[0x44_000, 0]),
                u64::from(S_OK),
                "GetCaps"
            );
            assert_ne!(guest_read_u32(&fixture.memory, 0x44_000), 0);

            assert_eq!(
                guest_call(&mut fixture, peer, IFACE_PEER, 24, &[0]),
                u64::from(S_OK)
            );
            assert_eq!(
                guest_call(&mut fixture, peer, IFACE_PEER, 2, &[]),
                0,
                "Release"
            );
        })
    }

    #[test]
    fn guest_address_vtable_url_round_trip() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("dplay-guest-address");
            let clsid = 0x40_000_u64;
            let iid = 0x40_100_u64;
            let out = 0x40_200_u64;
            guest_put(&mut fixture.memory, clsid, &CLSID_DIRECTPLAY8_ADDRESS);
            guest_put(&mut fixture.memory, iid, &IID_IDIRECTPLAY8_ADDRESS);
            let hr = dispatch_x86(
                &mut fixture,
                HostThunk::CoCreateInstance,
                &[clsid as u32, 0, 1, iid as u32, out as u32],
            );
            assert_eq!(
                hr,
                u64::from(S_OK),
                "CoCreateInstance(CLSID_DirectPlay8Address)"
            );
            let address = guest_read_u32(&fixture.memory, out) as u64;
            assert_ne!(address, 0);

            // AddComponent("hostname", "127.0.0.1", STRING).
            let key = 0x41_000_u64;
            let value = 0x41_100_u64;
            guest_put_utf16(&mut fixture.memory, key, "hostname");
            guest_put_utf16(&mut fixture.memory, value, "127.0.0.1");
            let value_size = 18u32; // bytes including the NUL
            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    18,
                    &[key as u32, value as u32, value_size, DPNA_DATATYPE_STRING],
                ),
                u64::from(S_OK)
            );
            // AddComponent("port", dword 2302).
            let port_key = 0x41_200_u64;
            let port_value = 0x41_220_u64;
            guest_put_utf16(&mut fixture.memory, port_key, "port");
            guest_put_u32(&mut fixture.memory, port_value, 2302);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    18,
                    &[port_key as u32, port_value as u32, 4, DPNA_DATATYPE_DWORD],
                ),
                u64::from(S_OK)
            );
            // SetSP(IID/CLSID of the TCP/IP provider).
            let sp = 0x41_300_u64;
            guest_put(&mut fixture.memory, sp, &CLSID_DP8SP_TCPIP);
            assert_eq!(
                guest_call(&mut fixture, address, IFACE_ADDRESS, 13, &[sp as u32]),
                u64::from(S_OK)
            );

            // GetNumComponents == 3.
            let count = 0x41_400_u64;
            assert_eq!(
                guest_call(&mut fixture, address, IFACE_ADDRESS, 15, &[count as u32]),
                u64::from(S_OK)
            );
            assert_eq!(guest_read_u32(&fixture.memory, count), 3);

            // GetURLW into a too-small buffer reports BUFFERTOOSMALL, then
            // succeeds with the exact needed count.
            let chars = 0x41_500_u64;
            let buffer = 0x41_600_u64;
            guest_put(&mut fixture.memory, buffer, &[0u8; 1024]);
            guest_put_u32(&mut fixture.memory, chars, 4);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    9,
                    &[buffer as u32, chars as u32],
                ),
                u64::from(DPNERR_BUFFERTOOSMALL)
            );
            let required = guest_read_u32(&fixture.memory, chars);
            assert!(required > 4);
            guest_put_u32(&mut fixture.memory, chars, required);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    9,
                    &[buffer as u32, chars as u32],
                ),
                u64::from(S_OK)
            );
            let url_bytes = fixture
                .memory
                .read_bytes(buffer, ((required as usize) - 1) * 2)
                .unwrap();
            let url = String::from_utf16_lossy(
                &url_bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<_>>(),
            );
            assert_eq!(
                url,
                "x-directplay:/provider=IP;hostname=127.0.0.1;port=2302"
            );

            // Duplicate + IsEqual.
            let duplicate_out = 0x41_700_u64;
            guest_put(&mut fixture.memory, duplicate_out, &[0u8; 8]);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    5,
                    &[duplicate_out as u32]
                ),
                u64::from(S_OK)
            );
            let duplicate = guest_read_u32(&fixture.memory, duplicate_out) as u64;
            assert_ne!(duplicate, 0);
            assert_eq!(
                guest_call(&mut fixture, address, IFACE_ADDRESS, 7, &[duplicate as u32]),
                u64::from(DPNSUCCESS_EQUAL)
            );
            assert_eq!(
                guest_call(&mut fixture, duplicate, IFACE_ADDRESS, 2, &[]),
                0
            );
            assert_eq!(guest_call(&mut fixture, address, IFACE_ADDRESS, 2, &[]), 0);
        })
    }

    #[test]
    fn guest_legacy_direct_play_create_hosts_and_closes() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("dplay-guest-legacy");
            let out = 0x40_200_u64;
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::DirectPlayCreate,
                    &[0, out as u32, 0]
                ),
                u64::from(S_OK),
                "DirectPlayCreate returns a real legacy object"
            );
            let legacy = guest_read_u32(&fixture.memory, out) as u64;
            assert_ne!(legacy, 0);

            assert_eq!(
                guest_call(&mut fixture, legacy, IFACE_LEGACY, 23, &[0]),
                u64::from(S_OK),
                "IDirectPlay4::Initialize"
            );

            // DPSESSIONDESC2 (x86) with DPSESSION_NEWGAME.
            let desc = 0x41_000_u64;
            let name = 0x42_000_u64;
            guest_put_utf16(&mut fixture.memory, name, "Legacy Casa1 Session");
            let mut ascii = b"Legacy Casa1 Session\0".to_vec();
            let ascii_name = 0x42_400_u64;
            guest_put(&mut fixture.memory, ascii_name, &ascii);
            ascii.clear();
            guest_put(&mut fixture.memory, desc, &[0u8; 80]);
            guest_put_u32(&mut fixture.memory, desc, 80);
            guest_put_u32(&mut fixture.memory, desc + 4, 1); // DPSESSION_NEWGAME
            guest_put_u32(&mut fixture.memory, desc + 40, 4);
            guest_put_u32(&mut fixture.memory, desc + 48, ascii_name as u32);
            assert_eq!(
                guest_call(&mut fixture, legacy, IFACE_LEGACY, 24, &[desc as u32, 1]),
                u64::from(S_OK),
                "IDirectPlay4::Open creates a real hosted session"
            );
            assert!(
                hosted_sessions()
                    .iter()
                    .any(|session| session.session_name == "Legacy Casa1 Session"),
                "the legacy session is real"
            );
            // EnumPlayers invokes the guest callback for the local player.
            let callback = 0x47_000_u64;
            let counter = 0x43_100_u64;
            let mut code = vec![0xFF, 0x05];
            code.extend_from_slice(&(counter as u32).to_le_bytes());
            code.extend_from_slice(&[0xB8, 1, 0, 0, 0, 0xC3]);
            guest_put(&mut fixture.memory, callback, &code);
            guest_put_u32(&mut fixture.memory, counter, 0);
            guest_put(&mut fixture.memory, 0x43_200, &[0u8; 8]);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    legacy,
                    IFACE_LEGACY,
                    12,
                    &[0, callback as u32, counter as u32, 0]
                ),
                u64::from(S_OK),
                "EnumPlayers over the real peer"
            );
            assert!(guest_read_u32(&fixture.memory, counter) >= 1);
            assert_eq!(
                guest_call(&mut fixture, legacy, IFACE_LEGACY, 4, &[]),
                u64::from(S_OK),
                "IDirectPlay4::Close"
            );
            assert_eq!(
                guest_call(&mut fixture, legacy, IFACE_LEGACY, 2, &[]),
                0,
                "Release"
            );
        })
    }

    #[test]
    fn guest_direct_play_enumerate_invokes_callback_for_real_sessions() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("dplay-guest-enumerate");
            let mut host = started_peer();
            assert_eq!(
                host.host(&DplayAppDesc::new("Enumerated Session", 4), localhost()),
                S_OK
            );

            // Guest callback stub: `inc dword ptr [counter]; mov eax, 1; ret`.
            let counter = 0x45_000_u64;
            guest_put_u32(&mut fixture.memory, counter, 0);
            let callback = 0x46_000_u64;
            let mut code = vec![0xFF, 0x05];
            code.extend_from_slice(&(counter as u32).to_le_bytes());
            code.extend_from_slice(&[0xB8, 1, 0, 0, 0, 0xC3]);
            guest_put(&mut fixture.memory, callback, &code);

            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::DirectPlayEnumerateW,
                    &[callback as u32, 0],
                ),
                u64::from(S_OK)
            );
            assert!(
                guest_read_u32(&fixture.memory, counter) >= 2,
                "the real service provider and the hosted session are enumerated"
            );
            host.close();
        })
    }

    // ── group replication, handler delivery and cancellation ───────────────

    fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if condition() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn wire_group_messages_round_trip() {
        let create = wire_group_create(3, 11, 7, 3, "Team", b"ctx");
        assert_eq!(
            parse_group(&create),
            Some(GroupWire::Create {
                sender: 3,
                sequence: 11,
                group_id: 7,
                owner: 3,
                name: "Team".to_string(),
                data: b"ctx".to_vec(),
            })
        );
        assert_eq!(
            parse_group(&wire_group_destroy(3, 12, 7)),
            Some(GroupWire::Destroy {
                sender: 3,
                sequence: 12,
                group_id: 7
            })
        );
        assert_eq!(
            parse_group(&wire_group_member(GROUP_OP_ADD_MEMBER, 3, 13, 7, 9)),
            Some(GroupWire::AddMember {
                sender: 3,
                sequence: 13,
                group_id: 7,
                dpnid: 9
            })
        );
        assert_eq!(
            parse_group(&wire_group_member(GROUP_OP_REMOVE_MEMBER, 3, 14, 7, 9)),
            Some(GroupWire::RemoveMember {
                sender: 3,
                sequence: 14,
                group_id: 7,
                dpnid: 9
            })
        );
        assert_eq!(
            parse_group(&wire_group_info(3, 15, 7, "Renamed", b"data")),
            Some(GroupWire::Info {
                sender: 3,
                sequence: 15,
                group_id: 7,
                name: "Renamed".to_string(),
                data: b"data".to_vec(),
            })
        );
        assert_eq!(
            parse_group(&wire_group_allocate_request(3, 16, 3, "New", b"ctx")),
            Some(GroupWire::AllocateRequest {
                sender: 3,
                sequence: 16,
                owner: 3,
                name: "New".to_string(),
                data: b"ctx".to_vec(),
            })
        );
        assert_eq!(
            parse_group(&wire_group_allocate_response(1, 17, 8, 3, 16, S_OK)),
            Some(GroupWire::AllocateResponse {
                sender: 1,
                sequence: 17,
                group_id: 8,
                client: 3,
                request_sequence: 16,
                result: S_OK,
            })
        );
        let group_data = wire_group_data(3, 7, 18, b"payload");
        assert_eq!(
            parse_group_data(&group_data),
            Some((3, 7, 18, b"payload".as_slice()))
        );
        let ack = wire_group_ack(1, 18);
        assert_eq!(parse_group_ack(&ack), Some((1, 18)));
        assert_eq!(parse_group(b"DP8G"), None);
        assert_eq!(parse_group(&create[..11]), None);
    }

    #[test]
    fn group_create_join_leave_context_and_send_to_members() {
        let mut host = started_peer();
        assert_eq!(
            host.host(&DplayAppDesc::new("Group Wire", 8), localhost()),
            S_OK
        );
        let host_addr = host.local_address().expect("host address");
        let mut first = started_peer();
        first.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(first.connect(host_addr, "First", &[]), S_OK);
        let mut second = started_peer();
        second.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(second.connect(host_addr, "Second", &[]), S_OK);
        let first_id = first.local_dpnid();
        let second_id = second.local_dpnid();

        let group = host
            .create_group("Team", HOST_PLAYER_ID, b"context")
            .expect("host group");
        assert_eq!(host.add_player_to_group(group, HOST_PLAYER_ID), S_OK);
        assert_eq!(host.add_player_to_group(group, first_id), S_OK);
        assert!(
            wait_until(Duration::from_secs(3), || {
                first.group(group).is_some_and(|group| {
                    group.name == "Team"
                        && group.members.contains(&HOST_PLAYER_ID)
                        && group.members.contains(&first_id)
                })
            }),
            "client replicates group name and real members"
        );
        assert!(
            wait_until(Duration::from_secs(3), || {
                second.group(group).is_some_and(|group| {
                    group.members.contains(&HOST_PLAYER_ID) && group.members.contains(&first_id)
                })
            }),
            "every peer enumerates the real group membership"
        );
        assert_eq!(first.group_context(group).expect("context"), b"context");

        // Host send: only members receive.
        assert_eq!(host.send_to(group, b"host-ping"), S_OK);
        assert_eq!(
            first
                .receive_from(Duration::from_secs(3))
                .expect("member receives host group datagram")
                .data,
            b"host-ping"
        );
        assert_eq!(
            host.receive_from(Duration::from_secs(3))
                .expect("host member gets its own group loopback")
                .data,
            b"host-ping"
        );
        thread::sleep(Duration::from_millis(150));
        assert!(
            second.poll_receive().is_none(),
            "non-member must not receive a group send"
        );

        // Client send: host and the sending member receive, the non-member does not.
        assert_eq!(first.send_to(group, b"member-ping"), S_OK);
        assert_eq!(
            host.receive_from(Duration::from_secs(3))
                .expect("host member receives client group datagram")
                .data,
            b"member-ping"
        );
        assert_eq!(
            first
                .receive_from(Duration::from_secs(3))
                .expect("sender that is a member gets the group loopback")
                .data,
            b"member-ping"
        );
        thread::sleep(Duration::from_millis(150));
        assert!(
            second.poll_receive().is_none(),
            "non-member must not receive a client group send"
        );

        // Context and info changes replicate.
        assert_eq!(first.set_group_context(group, b"new-context"), S_OK);
        assert!(
            wait_until(Duration::from_secs(3), || {
                host.group(group)
                    .is_some_and(|group| group.data == b"new-context")
                    && second
                        .group(group)
                        .is_some_and(|group| group.data == b"new-context")
            }),
            "group context round-trips over DP8G"
        );
        assert_eq!(first.set_group_info(group, "Renamed", b"info-data"), S_OK);
        assert!(
            wait_until(Duration::from_secs(3), || {
                host.group(group)
                    .is_some_and(|group| group.name == "Renamed" && group.data == b"info-data")
            }),
            "group info round-trips over DP8G"
        );

        // Client-created group is shared with the host and other peers.
        let client_group = first
            .create_group("Client Team", first_id, b"client-data")
            .expect("client group");
        assert!(
            wait_until(Duration::from_secs(3), || {
                host.group(client_group).is_some() && second.group(client_group).is_some()
            }),
            "client-created group reaches host and peers"
        );
        assert_eq!(first.destroy_group(client_group), S_OK);
        assert!(
            wait_until(Duration::from_secs(3), || {
                host.group(client_group).is_none() && second.group(client_group).is_none()
            }),
            "client group destroy replicates"
        );

        // Leaving the group stops delivery.
        assert_eq!(host.remove_player_from_group(group, first_id), S_OK);
        assert!(
            wait_until(Duration::from_secs(3), || {
                first
                    .group(group)
                    .is_some_and(|group| !group.members.contains(&first_id))
            }),
            "leave replicates to the member"
        );
        assert_eq!(host.send_to(group, b"after-leave"), S_OK);
        assert_eq!(
            host.receive_from(Duration::from_secs(3))
                .expect("host is still a member")
                .data,
            b"after-leave"
        );
        thread::sleep(Duration::from_millis(150));
        assert!(
            first.poll_receive().is_none(),
            "a removed member no longer receives group traffic"
        );

        assert_eq!(host.destroy_group(group), S_OK);
        assert!(
            wait_until(Duration::from_secs(3), || {
                first.group(group).is_none() && second.group(group).is_none()
            }),
            "group destroy replicates"
        );

        assert_eq!(host.send_to(4242, b"not a group"), DPNERR_INVALIDPLAYER);
        first.close();
        second.close();
        host.close();
        assert_ne!(first_id, 0);
        assert_ne!(second_id, 0);
    }

    #[test]
    fn group_replication_retransmits_under_loss_and_suppresses_duplicates() {
        let mut host = started_peer();
        assert_eq!(
            host.host(&DplayAppDesc::new("Lossy Groups", 8), localhost()),
            S_OK
        );
        let host_addr = host.local_address().expect("host address");
        let mut first = started_peer();
        first.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(first.connect(host_addr, "First", &[]), S_OK);
        let mut second = started_peer();
        second.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(second.connect(host_addr, "Second", &[]), S_OK);
        let first_id = first.local_dpnid();
        let second_id = second.local_dpnid();

        let group = host
            .create_group("Lossy Team", HOST_PLAYER_ID, b"context")
            .expect("host group");
        assert_eq!(host.add_player_to_group(group, first_id), S_OK);
        assert_eq!(host.add_player_to_group(group, second_id), S_OK);
        assert!(wait_until(Duration::from_secs(3), || {
            first.group(group).is_some() && second.group(group).is_some()
        }));

        // Drop the first group datagram for `second` and the first
        // acknowledgement arriving at the host.  The reliable layer must
        // retransmit, and the retransmitted duplicate must be suppressed.
        second.set_group_packet_loss(1, 0);
        host.set_group_packet_loss(0, 1);
        assert_eq!(
            host.set_group_info(group, "Lossy Renamed", b"new-context"),
            S_OK
        );
        assert!(
            wait_until(Duration::from_secs(4), || {
                second.group(group).is_some_and(|group| {
                    group.name == "Lossy Renamed" && group.data == b"new-context"
                })
            }),
            "dropped group state converges through retransmission"
        );
        assert!(
            wait_until(Duration::from_secs(3), || host.pending_group_messages()
                == 0),
            "all acknowledgements eventually complete the reliable sends"
        );
        assert!(
            first.group_duplicates_suppressed() + second.group_duplicates_suppressed() >= 1,
            "the retransmitted duplicate was suppressed, not reapplied"
        );

        // Group-addressed application data is reliable too: drop the first
        // delivery to the second member and observe exactly one delivery.
        second.set_group_packet_loss(1, 0);
        assert_eq!(host.send_to(group, b"lossy-data"), S_OK);
        let mut received = Vec::new();
        assert!(
            wait_until(Duration::from_secs(4), || {
                if let Some(message) = second.receive_from(Duration::ZERO) {
                    received.push(message.data);
                }
                received.iter().any(|data| data == b"lossy-data")
            }),
            "dropped group data converges through retransmission"
        );
        thread::sleep(Duration::from_millis(250));
        while let Some(message) = second.receive_from(Duration::ZERO) {
            received.push(message.data);
        }
        assert_eq!(
            received
                .iter()
                .filter(|data| data.as_slice() == b"lossy-data")
                .count(),
            1,
            "the application observes the group datagram exactly once"
        );

        first.close();
        second.close();
        host.close();
    }

    #[test]
    fn client_group_id_allocation_is_host_authoritative_and_times_out() {
        let mut host = started_peer();
        assert_eq!(
            host.host(&DplayAppDesc::new("Group Alloc", 8), localhost()),
            S_OK
        );
        let host_addr = host.local_address().expect("host address");
        let mut client = started_peer();
        client.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(client.connect(host_addr, "Allocator", &[]), S_OK);
        let client_id = client.local_dpnid();

        // Drop the first allocation request at the host: the client must
        // retransmit, and the host's assigned id must be the one returned.
        host.set_group_packet_loss(1, 0);
        let group = client
            .create_group("Allocated By Host", client_id, b"alloc-ctx")
            .expect("the host assigns a real group id");
        assert!(
            host.group(group)
                .is_some_and(|group| group.name == "Allocated By Host"),
            "the host really created the group under the assigned id"
        );
        assert!(client.group(group).is_some(), "the client adopted the id");
        assert!(
            wait_until(Duration::from_secs(3), || host.pending_group_messages()
                == 0),
            "the allocation request and response were acknowledged"
        );

        let mut timed_out = started_peer();
        timed_out.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(timed_out.connect(host_addr, "Timed Out", &[]), S_OK);
        timed_out.set_group_create_timeout(Duration::from_millis(180));
        host.set_group_packet_loss(1_000, 0);
        let result = timed_out.create_group("Never Allocated", timed_out.local_dpnid(), b"");
        host.set_group_packet_loss(0, 0);
        assert_eq!(
            result,
            Err(DPNERR_TIMEDOUT),
            "a host that never answers yields the real timeout error"
        );
        assert!(timed_out.groups().is_empty(), "no optimistic id was kept");

        timed_out.close();
        client.close();
        host.close();
    }

    #[test]
    fn session_close_discards_pending_group_retransmissions() {
        let mut host = started_peer();
        assert_eq!(
            host.host(&DplayAppDesc::new("Closing Retries", 4), localhost()),
            S_OK
        );
        let host_addr = host.local_address().expect("host address");
        let mut client = started_peer();
        client.set_connect_timeout(Duration::from_secs(3));
        assert_eq!(client.connect(host_addr, "Member", &[]), S_OK);

        // Every acknowledgement received by the host is dropped, leaving the
        // host's reliable group sends pending when the session closes.
        host.set_group_packet_loss(0, 1_000);
        let group = host
            .create_group("Pending Retries", HOST_PLAYER_ID, b"")
            .expect("host group");
        assert_eq!(host.add_player_to_group(group, client.local_dpnid()), S_OK);
        assert!(
            wait_until(Duration::from_secs(2), || host.pending_group_messages() > 0),
            "a reliable send is pending"
        );

        assert_eq!(host.close(), S_OK);
        assert_eq!(
            host.pending_group_messages(),
            0,
            "closing the session discards pending retransmissions"
        );
        client.close();
    }

    #[test]
    fn enum_hosts_async_returns_pending_and_cancel_stops_responses() {
        let mut host = started_peer();
        let mut desc = DplayAppDesc::new("Async Enum", 4);
        desc.application_guid = [5u8; 16];
        assert_eq!(host.host(&desc, localhost()), S_OK);
        let host_addr = host.local_address().expect("host address");
        let instance = host.host_instance_guid().expect("instance");

        let mut scout = started_peer();
        let handle = scout
            .start_enum_hosts(&[5u8; 16], &[host_addr], Duration::from_millis(600), 0x77)
            .expect("async operation");
        assert!(
            scout.async_operation_pending(handle),
            "EnumHosts returned a live async handle"
        );
        assert_eq!(scout.cancel_async_operation(handle), S_OK);
        thread::sleep(Duration::from_millis(150));
        let events = scout.poll_engine_events();
        assert!(
            !events.iter().any(|event| {
                matches!(
                    event,
                    DplayEvent::EnumHostsResponse { session, .. }
                        if session.instance_guid == instance
                )
            }),
            "a cancelled enumeration emits no further responses"
        );
        assert!(!scout.async_operation_pending(handle));
        assert_eq!(
            scout.cancel_async_operation(handle),
            DPNERR_INVALIDHANDLE,
            "the cancelled handle is gone"
        );

        let handle = scout
            .start_enum_hosts(&[5u8; 16], &[host_addr], Duration::from_millis(600), 0x88)
            .expect("second async operation");
        let mut found = false;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            for event in scout.poll_engine_events() {
                if let DplayEvent::EnumHostsResponse {
                    context,
                    session,
                    async_op,
                } = event
                {
                    if async_op == handle && context == 0x88 && session.instance_guid == instance {
                        found = true;
                    }
                }
            }
            if found {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            found,
            "async responses are delivered with the operation context"
        );
        assert!(
            wait_until(Duration::from_secs(3), || {
                let _ = scout.poll_engine_events();
                !scout.async_operation_pending(handle)
            }),
            "the operation completes when the enumeration window ends"
        );
        host.close();
    }

    #[test]
    fn async_operation_cancel_is_real() {
        let mut peer = started_peer();
        let pending = peer.begin_async_operation(AsyncOperationKind::Connect);
        assert!(peer.async_operation_pending(pending));
        assert_eq!(peer.cancel_async_operation(pending), S_OK);
        assert!(!peer.async_operation_pending(pending));
        assert_eq!(
            peer.cancel_async_operation(pending),
            DPNERR_INVALIDHANDLE,
            "an already cancelled handle is gone"
        );
        let completed = peer.begin_async_operation(AsyncOperationKind::SendTo);
        assert!(peer.complete_async_operation(completed));
        assert_eq!(
            peer.cancel_async_operation(completed),
            DPNERR_CANNOTCANCEL,
            "a completed operation cannot be cancelled"
        );
        assert!(!peer.complete_async_operation(completed));
        assert_eq!(peer.cancel_async_operation(0), DPNERR_INVALIDHANDLE);
    }

    #[test]
    fn message_handler_registration_error_semantics() {
        let mut peer = Dplay8Peer::new();
        assert_eq!(peer.set_message_handler(0x1234), S_OK);
        assert_eq!(peer.message_handler(), 0x1234);
        assert_eq!(peer.update_message_handler(0x5678), DPNERR_UNINITIALIZED);
        assert_eq!(peer.set_message_handler(0), DPNERR_INVALIDPOINTER);
        assert_eq!(peer.initialize(7, 0, 0), S_OK);
        assert_eq!(peer.set_message_handler(0x9999), DPNERR_ALREADYINITIALIZED);
        assert_eq!(peer.update_message_handler(0x5678), S_OK);
        assert_eq!(peer.message_handler(), 0x5678);
        assert_eq!(peer.update_message_handler(0), DPNERR_INVALIDPOINTER);
    }

    #[test]
    fn guest_message_handler_receives_real_events() {
        use crate::cpu::{CpuState, GuestArch, Register};
        with_big_stack(|| {
            let mut fixture = x86_fixture("dplay-message-handler");
            let msgid_out = 0x45_100_u64;
            let data_out = 0x45_200_u64;
            guest_put_u32(&mut fixture.memory, msgid_out, 0);
            guest_put_u32(&mut fixture.memory, data_out, 0);
            // Handler: record dwMessageType; for DPN_MSGID_RECEIVE record the
            // first four datagram bytes through pReceiveData.
            let handler = 0x46_000_u64;
            let mut code = vec![
                0x8B, 0x44, 0x24, 0x08, // mov eax,[esp+8]
                0xA3, // mov [msgid_out],eax
            ];
            code.extend_from_slice(&(msgid_out as u32).to_le_bytes());
            code.extend_from_slice(&[
                0x83, 0xF8, 0x01, // cmp eax, DPN_MSGID_RECEIVE
                0x75, 0x13, // jne done
                0x8B, 0x44, 0x24, 0x0C, // mov eax,[esp+12]
                0x8B, 0x40, 0x08, // mov eax,[eax+8] (pReceiveData)
                0x85, 0xC0, // test eax,eax
                0x74, 0x08, // jz done
                0x8B, 0x10, // mov edx,[eax]
                0x89, 0x15, // mov [data_out],edx
            ]);
            code.extend_from_slice(&(data_out as u32).to_le_bytes());
            code.extend_from_slice(&[0x33, 0xC0, 0xC3]); // xor eax,eax; ret
            guest_put(&mut fixture.memory, handler, &code);

            let mut host_peer = Dplay8Peer::new();
            assert_eq!(host_peer.initialize(0x55, handler, 0), S_OK);
            assert_eq!(
                host_peer.host(&DplayAppDesc::new("Handler", 4), localhost()),
                S_OK
            );
            let host_addr = host_peer.local_address().expect("host address");
            let pid = fixture.runtime.guest_pid;
            {
                let mut store = lock_dplay_runtimes();
                let runtime = store.entry(pid).or_default();
                runtime.objects.insert(
                    0x2000,
                    DplayObjectEntry {
                        refcount: 1,
                        object: DplayObject::Peer(host_peer),
                    },
                );
            }

            let mut client = started_peer();
            client.set_connect_timeout(Duration::from_secs(3));
            assert_eq!(client.connect(host_addr, "Sender", &[]), S_OK);
            assert_eq!(client.send_to(HOST_PLAYER_ID, b"ping"), S_OK);

            let mut state = CpuState::new(GuestArch::X86);
            fixture.memory.map_bytes(0x4F_000, &vec![0u8; 0x2000]);
            state.set(Register::Rsp, 0x50_000);
            let mut delivered = false;
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                fixture
                    .runtime
                    .drain_pending_dplay_events(&mut state, &mut fixture.memory)
                    .expect("drain dplay events");
                if guest_read_u32(&fixture.memory, msgid_out) == 1 {
                    delivered = true;
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(delivered, "DPN_MSGID_RECEIVE delivered to the handler");
            assert_eq!(guest_read_u32(&fixture.memory, data_out), 0x676E_6970);

            // Connect-complete and destroy/session-lost events, queued the
            // same way the dispatch layer queues them.
            let handle = {
                let mut store = lock_dplay_runtimes();
                let runtime = store.get_mut(&pid).expect("runtime");
                let handle = match &mut runtime.objects.get_mut(&0x2000).expect("peer").object {
                    DplayObject::Peer(peer) => {
                        peer.begin_async_operation(AsyncOperationKind::Connect)
                    }
                    _ => unreachable!(),
                };
                runtime.push_event(
                    0x2000,
                    DplayEvent::ConnectComplete {
                        async_op: handle,
                        context: 0,
                        result: S_OK,
                        dpnid: 2,
                    },
                );
                handle
            };
            guest_put_u32(&mut fixture.memory, msgid_out, 0);
            fixture
                .runtime
                .drain_pending_dplay_events(&mut state, &mut fixture.memory)
                .expect("drain connect complete");
            assert_eq!(
                guest_read_u32(&fixture.memory, msgid_out),
                7,
                "DPN_MSGID_CONNECT_COMPLETE delivered"
            );
            {
                let mut store = lock_dplay_runtimes();
                let runtime = store.get_mut(&pid).expect("runtime");
                runtime.push_event(
                    0x2000,
                    DplayEvent::DestroyPlayer {
                        dpnid: 2,
                        reason: DPNDESTROYPLAYERREASON_NORMAL,
                        context: 0,
                    },
                );
            }
            fixture
                .runtime
                .drain_pending_dplay_events(&mut state, &mut fixture.memory)
                .expect("drain destroy player");
            assert_eq!(
                guest_read_u32(&fixture.memory, msgid_out),
                4,
                "DPN_MSGID_DESTROY_PLAYER delivered"
            );
            {
                let mut store = lock_dplay_runtimes();
                let runtime = store.get_mut(&pid).expect("runtime");
                runtime.push_event(0x2000, DplayEvent::SessionLost { result: 0 });
            }
            fixture
                .runtime
                .drain_pending_dplay_events(&mut state, &mut fixture.memory)
                .expect("drain session lost");
            assert_eq!(
                guest_read_u32(&fixture.memory, msgid_out),
                10,
                "DPN_MSGID_SESSION_LOST delivered"
            );
            {
                let mut store = lock_dplay_runtimes();
                let runtime = store.get_mut(&pid).expect("runtime");
                assert!(runtime.pending.is_empty(), "all queued events delivered");
                let peer = match &mut runtime.objects.get_mut(&0x2000).expect("peer").object {
                    DplayObject::Peer(peer) => peer,
                    _ => unreachable!(),
                };
                assert_eq!(
                    peer.cancel_async_operation(handle),
                    DPNERR_CANNOTCANCEL,
                    "delivery completed the async operation"
                );
            }
            client.close();
            lock_dplay_runtimes().remove(&pid);
        })
    }

    #[test]
    fn guest_enum_hosts_async_returns_pending_and_cancel_stops_delivery() {
        use crate::cpu::{CpuState, GuestArch, Register};
        with_big_stack(|| {
            let mut host_peer = started_peer();
            let mut desc = DplayAppDesc::new("Async Guest Enum", 4);
            desc.application_guid = [6u8; 16];
            assert_eq!(host_peer.host(&desc, localhost()), S_OK);
            let host_addr = host_peer.local_address().expect("host address");

            let mut fixture = x86_fixture("dplay-enum-async");
            let msgid_out = 0x45_100_u64;
            guest_put_u32(&mut fixture.memory, msgid_out, 0);
            let handler = 0x46_000_u64;
            let mut code = vec![
                0x8B, 0x44, 0x24, 0x08, // mov eax,[esp+8]
                0xA3, // mov [msgid_out],eax
            ];
            code.extend_from_slice(&(msgid_out as u32).to_le_bytes());
            code.extend_from_slice(&[0x33, 0xC0, 0xC3]); // xor eax,eax; ret
            guest_put(&mut fixture.memory, handler, &code);

            let pid = fixture.runtime.guest_pid;
            let address_object = 0x2100_u64;
            {
                let mut address = Dplay8Address::new();
                assert_eq!(address.set_hostname("127.0.0.1"), S_OK);
                assert_eq!(address.set_port(host_addr.port()), S_OK);
                assert_eq!(address.set_sp(&CLSID_DP8SP_TCPIP), S_OK);
                let mut store = lock_dplay_runtimes();
                let runtime = store.entry(pid).or_default();
                let mut peer = Dplay8Peer::new();
                assert_eq!(peer.initialize(0x55, handler, 0), S_OK);
                runtime.objects.insert(
                    0x2000,
                    DplayObjectEntry {
                        refcount: 1,
                        object: DplayObject::Peer(peer),
                    },
                );
                runtime.objects.insert(
                    address_object,
                    DplayObjectEntry {
                        refcount: 1,
                        object: DplayObject::Address(address),
                    },
                );
            }
            let app_desc = 0x41_000_u64;
            guest_put(&mut fixture.memory, app_desc, &[0u8; 72]);
            guest_put_u32(&mut fixture.memory, app_desc, 72);
            let async_out = 0x47_000_u64;
            guest_put_u32(&mut fixture.memory, async_out, 0);
            let hr = guest_call(
                &mut fixture,
                0x2000,
                IFACE_PEER,
                25,
                &[
                    app_desc as u32,
                    address_object as u32,
                    0,
                    0,
                    0,
                    1,
                    0,
                    300,
                    0x1234,
                    async_out as u32,
                    0,
                ],
            );
            assert_eq!(
                hr,
                u64::from(DPNERR_PENDING),
                "async EnumHosts reports pending"
            );
            let handle = guest_read_u32(&fixture.memory, async_out);
            assert_ne!(handle, 0, "a real async handle was written");

            let mut state = CpuState::new(GuestArch::X86);
            fixture.memory.map_bytes(0x4F_000, &vec![0u8; 0x2000]);
            state.set(Register::Rsp, 0x50_000);
            let mut delivered = false;
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                fixture
                    .runtime
                    .drain_pending_dplay_events(&mut state, &mut fixture.memory)
                    .expect("drain enum response");
                if guest_read_u32(&fixture.memory, msgid_out) == 13 {
                    delivered = true;
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(delivered, "DPN_MSGID_ENUM_HOSTS_RESPONSE delivered");

            // A second operation cancelled before delivery must not run.
            guest_put_u32(&mut fixture.memory, msgid_out, 0);
            guest_put_u32(&mut fixture.memory, async_out, 0);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    0x2000,
                    IFACE_PEER,
                    25,
                    &[
                        app_desc as u32,
                        address_object as u32,
                        0,
                        0,
                        0,
                        1,
                        0,
                        1_000,
                        0x5678,
                        async_out as u32,
                        0,
                    ],
                ),
                u64::from(DPNERR_PENDING)
            );
            let cancel_handle = guest_read_u32(&fixture.memory, async_out);
            assert_eq!(
                guest_call(&mut fixture, 0x2000, IFACE_PEER, 5, &[cancel_handle]),
                u64::from(S_OK)
            );
            thread::sleep(Duration::from_millis(150));
            fixture
                .runtime
                .drain_pending_dplay_events(&mut state, &mut fixture.memory)
                .expect("drain after cancel");
            assert_eq!(
                guest_read_u32(&fixture.memory, msgid_out),
                0,
                "cancelled enumeration delivered no handler response"
            );

            host_peer.close();
            lock_dplay_runtimes().remove(&pid);
        })
    }

    #[test]
    fn guest_cancel_async_operation_cancels_queued_completion() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("dplay-cancel-async");
            let pid = fixture.runtime.guest_pid;
            let handle = {
                let mut store = lock_dplay_runtimes();
                let runtime = store.entry(pid).or_default();
                let mut peer = Dplay8Peer::new();
                assert_eq!(peer.initialize(0, 0, 0), S_OK);
                let handle = peer.begin_async_operation(AsyncOperationKind::Connect);
                runtime.objects.insert(
                    0x2000,
                    DplayObjectEntry {
                        refcount: 1,
                        object: DplayObject::Peer(peer),
                    },
                );
                runtime.push_event(
                    0x2000,
                    DplayEvent::ConnectComplete {
                        async_op: handle,
                        context: 0,
                        result: S_OK,
                        dpnid: 2,
                    },
                );
                handle
            };
            assert_eq!(
                guest_call(&mut fixture, 0x2000, IFACE_PEER, 5, &[handle],),
                u64::from(S_OK),
                "CancelAsyncOperation"
            );
            {
                let store = lock_dplay_runtimes();
                let runtime = store.get(&pid).expect("runtime");
                assert!(
                    runtime.pending.is_empty(),
                    "the queued completion was really removed"
                );
            }
            assert_eq!(
                guest_call(&mut fixture, 0x2000, IFACE_PEER, 5, &[handle]),
                u64::from(DPNERR_INVALIDHANDLE)
            );
            lock_dplay_runtimes().remove(&pid);
        })
    }

    #[test]
    fn guest_build_address_from_direct_play4_address() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("dplay-build-from-dp4");
            let out = 0x40_200_u64;
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::DirectPlayCreate,
                    &[0, out as u32, 0]
                ),
                u64::from(S_OK)
            );
            let legacy = guest_read_u32(&fixture.memory, out) as u64;
            assert_ne!(legacy, 0);
            assert_eq!(
                guest_call(&mut fixture, legacy, IFACE_LEGACY, 23, &[0]),
                u64::from(S_OK)
            );
            let desc = 0x41_000_u64;
            let ascii_name = 0x42_400_u64;
            guest_put(&mut fixture.memory, ascii_name, b"DP4 Address\0");
            guest_put(&mut fixture.memory, desc, &[0u8; 80]);
            guest_put_u32(&mut fixture.memory, desc, 80);
            guest_put_u32(&mut fixture.memory, desc + 4, 1);
            guest_put_u32(&mut fixture.memory, desc + 40, 4);
            guest_put_u32(&mut fixture.memory, desc + 48, ascii_name as u32);
            assert_eq!(
                guest_call(&mut fixture, legacy, IFACE_LEGACY, 24, &[desc as u32, 1]),
                u64::from(S_OK)
            );

            let address_iid = 0x43_000_u64;
            let address_out = 0x43_100_u64;
            guest_put(&mut fixture.memory, address_iid, &IID_IDIRECTPLAY8_ADDRESS);
            assert_eq!(
                dispatch_x86(
                    &mut fixture,
                    HostThunk::DirectPlay8AddressCreate,
                    &[address_iid as u32, address_out as u32, 0],
                ),
                u64::from(S_OK)
            );
            let address = guest_read_u32(&fixture.memory, address_out) as u64;
            assert_ne!(address, 0);

            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    21,
                    &[legacy as u32, 0]
                ),
                u64::from(S_OK),
                "BuildFromDirectPlay4Address converts the live endpoint"
            );
            let chars = 0x44_000_u64;
            let buffer = 0x44_100_u64;
            guest_put(&mut fixture.memory, buffer, &[0u8; 1024]);
            guest_put_u32(&mut fixture.memory, chars, 0);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    9,
                    &[buffer as u32, chars as u32]
                ),
                u64::from(DPNERR_BUFFERTOOSMALL)
            );
            let required = guest_read_u32(&fixture.memory, chars);
            assert!(required > 1);
            guest_put_u32(&mut fixture.memory, chars, required);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    9,
                    &[buffer as u32, chars as u32]
                ),
                u64::from(S_OK)
            );
            let url_bytes = fixture
                .memory
                .read_bytes(buffer, ((required as usize) - 1) * 2)
                .unwrap();
            let url = String::from_utf16_lossy(
                &url_bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<_>>(),
            );
            assert!(url.starts_with("x-directplay:/provider=IP;hostname="));
            assert!(!url.ends_with("port=0"), "real bound port: {url}");

            assert_eq!(
                guest_call(
                    &mut fixture,
                    address,
                    IFACE_ADDRESS,
                    21,
                    &[legacy as u32, 1]
                ),
                u64::from(DPNERR_INVALIDFLAGS)
            );
            assert_eq!(
                guest_call(&mut fixture, address, IFACE_ADDRESS, 21, &[0xDEAD, 0]),
                u64::from(DPNERR_INVALIDPARAM)
            );
            assert_eq!(
                guest_call(&mut fixture, legacy, IFACE_LEGACY, 4, &[]),
                u64::from(S_OK)
            );
        })
    }

    #[test]
    fn guest_group_info_members_and_context_are_real() {
        with_big_stack(|| {
            let mut fixture = x86_fixture("dplay-guest-group");
            let pid = fixture.runtime.guest_pid;
            let mut peer = Dplay8Peer::new();
            assert_eq!(peer.initialize(0, 0, 0), S_OK);
            assert_eq!(
                peer.host(&DplayAppDesc::new("Guest Groups", 4), localhost()),
                S_OK
            );
            {
                let mut store = lock_dplay_runtimes();
                store.entry(pid).or_default().objects.insert(
                    0x2000,
                    DplayObjectEntry {
                        refcount: 1,
                        object: DplayObject::Peer(peer),
                    },
                );
            }

            // DPN_GROUP_INFO (x86): name + context bytes.
            let info = 0x41_000_u64;
            let name = 0x42_000_u64;
            let data = 0x42_200_u64;
            guest_put_utf16(&mut fixture.memory, name, "Blue Team");
            guest_put(&mut fixture.memory, data, b"ctx!");
            guest_put(&mut fixture.memory, info, &[0u8; 32]);
            guest_put_u32(&mut fixture.memory, info, 32);
            guest_put_u32(&mut fixture.memory, info + 4, DPNINFO_NAME | DPNINFO_DATA);
            guest_put_u32(&mut fixture.memory, info + 8, name as u32);
            guest_put_u32(&mut fixture.memory, info + 12, data as u32);
            guest_put_u32(&mut fixture.memory, info + 16, 4);
            let group_out = 0x43_000_u64;
            guest_put_u32(&mut fixture.memory, group_out, 0);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    0x2000,
                    IFACE_PEER,
                    12,
                    &[info as u32, 0, 0, group_out as u32, 0]
                ),
                u64::from(S_OK)
            );
            let group = guest_read_u32(&mut fixture.memory, group_out);
            assert_ne!(group, 0);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    0x2000,
                    IFACE_PEER,
                    14,
                    &[group, HOST_PLAYER_ID]
                ),
                u64::from(S_OK)
            );

            // EnumGroupMembers returns the real member list.
            let members = 0x44_000_u64;
            let count = 0x44_100_u64;
            guest_put_u32(&mut fixture.memory, count, 8);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    0x2000,
                    IFACE_PEER,
                    19,
                    &[group, members as u32, count as u32]
                ),
                u64::from(S_OK)
            );
            assert_eq!(guest_read_u32(&mut fixture.memory, count), 1);
            assert_eq!(guest_read_u32(&mut fixture.memory, members), HOST_PLAYER_ID);

            // GetGroupInfo reports the real name/data pair.
            let size = 0x45_000_u64;
            let base = 0x45_100_u64;
            guest_put_u32(&mut fixture.memory, size, 0);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    0x2000,
                    IFACE_PEER,
                    17,
                    &[group, 0, size as u32]
                ),
                u64::from(DPNERR_BUFFERTOOSMALL)
            );
            let required = guest_read_u32(&mut fixture.memory, size);
            assert!(required > 24);
            guest_put(&mut fixture.memory, base, &vec![0u8; required as usize]);
            guest_put_u32(&mut fixture.memory, size, required);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    0x2000,
                    IFACE_PEER,
                    17,
                    &[group, base as u32, size as u32]
                ),
                u64::from(S_OK)
            );
            assert_eq!(
                guest_read_u32(&mut fixture.memory, base + 4),
                DPNINFO_NAME | DPNINFO_DATA
            );
            let group_name_ptr = guest_read_u32(&mut fixture.memory, base + 8) as u64;
            let group_data_ptr = guest_read_u32(&mut fixture.memory, base + 12) as u64;
            assert_eq!(
                guest_read_u32(&mut fixture.memory, base + 16),
                4,
                "real context size"
            );
            let group_name = fixture
                .memory
                .read_bytes(group_name_ptr, 18)
                .expect("group name bytes");
            assert_eq!(
                String::from_utf16_lossy(
                    &group_name
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .collect::<Vec<_>>()
                ),
                "Blue Team"
            );
            assert_eq!(
                fixture.memory.read_bytes(group_data_ptr, 4).unwrap(),
                b"ctx!"
            );

            // GetGroupContext returns the stored bytes.
            let context_out = 0x46_000_u64;
            guest_put_u32(&mut fixture.memory, context_out, 0);
            assert_eq!(
                guest_call(
                    &mut fixture,
                    0x2000,
                    IFACE_PEER,
                    29,
                    &[group, context_out as u32, 0]
                ),
                u64::from(S_OK)
            );
            let context_ptr = guest_read_u32(&mut fixture.memory, context_out) as u64;
            assert_ne!(context_ptr, 0);
            assert_eq!(fixture.memory.read_bytes(context_ptr, 4).unwrap(), b"ctx!");

            // SetGroupInfo replaces the real name/context.
            let new_name = 0x47_000_u64;
            guest_put_utf16(&mut fixture.memory, new_name, "Red Team");
            guest_put(&mut fixture.memory, info, &[0u8; 32]);
            guest_put_u32(&mut fixture.memory, info, 32);
            guest_put_u32(&mut fixture.memory, info + 4, DPNINFO_NAME | DPNINFO_DATA);
            guest_put_u32(&mut fixture.memory, info + 8, new_name as u32);
            guest_put_u32(&mut fixture.memory, info + 12, data as u32);
            guest_put_u32(&mut fixture.memory, info + 16, 4);
            assert_eq!(
                guest_call(&mut fixture, 0x2000, IFACE_PEER, 16, &[group, info as u32]),
                u64::from(S_OK)
            );
            {
                let store = lock_dplay_runtimes();
                let runtime = store.get(&pid).expect("runtime");
                let peer = match &runtime.objects.get(&0x2000).expect("peer").object {
                    DplayObject::Peer(peer) => peer,
                    _ => unreachable!(),
                };
                let stored = peer.group(group).expect("group");
                assert_eq!(stored.name, "Red Team");
                assert_eq!(stored.data, b"ctx!");
            }

            assert_eq!(
                guest_call(&mut fixture, 0x2000, IFACE_PEER, 13, &[group]),
                u64::from(S_OK)
            );
            lock_dplay_runtimes().remove(&pid);
        })
    }
}
