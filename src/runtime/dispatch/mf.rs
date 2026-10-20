//! Media Foundation dispatch: the mf.dll / mfplat.dll / mfreadwrite.dll
//! host thunks, in a dedicated module per the audit's modularity
//! requirement.  The guest-facing COM objects wrap the media pipeline
//! machinery in `crate::media` (sources, media types, buffers, samples,
//! sessions, clocks, event queues, source readers, sink writers, topology).
//!
//! Layer contract: every export returns an HRESULT in EAX (MF_E_* on
//! failure); the guest objects are `GuestObjectKind::Imf*` entries with a
//! vtable whose method slots dispatch through `HostThunk::Mf*` variants.

use super::super::*;
use super::unknown_preamble;
use crate::media::{Guid, ImfMediaBuffer, ImfMediaType, ImfSample, MfEventQueue};
use crate::runtime::state::{ComStreamState, ImfByteStreamState};

/// MFT_CATEGORY_VIDEO_DECODER {d6c02d4b-6833-45b4-971a-05a4b04bab91}
/// (the guest little-endian byte form).
const MFT_CATEGORY_VIDEO_DECODER: [u8; 16] = [
    0x4b, 0x2d, 0xc0, 0xd6, 0x33, 0x68, 0xb4, 0x45, 0x97, 0x1a, 0x05, 0xa4, 0xb0, 0x4b, 0xab, 0x91,
];
/// CLSID_Casa1VideoDecoderMFT {c1a1d2e3-5a5a-4b4b-9a9a-001122334455}
/// (the guest little-endian byte form).
const MFT_CASA1_VIDEO_DECODER_CLSID: [u8; 16] = [
    0xe3, 0xd2, 0xa1, 0xc1, 0x5a, 0x5a, 0x4b, 0x4b, 0x9a, 0x9a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
];
// ── Media Foundation HRESULT codes (the documented MF_E_* family) ─────────

const S_OK: u32 = 0x0000_0000;
const S_FALSE: u32 = 0x0000_0001;
const E_INVALIDARG: u32 = 0x8007_0057;
const E_NOTIMPL: u32 = 0x8000_4001;
const E_PENDING: u32 = 0x8000_000A;
#[allow(dead_code)] // reserved for the MF error surface
const E_NOINTERFACE: u32 = 0x8000_4002;
#[allow(dead_code)] // reserved for the interface error surface
const E_OUTOFMEMORY: u32 = 0x8007_000E;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_NOT_INITIALIZED: u32 = 0xC00D_36B0;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_INVALIDREQUEST: u32 = 0xC00D_36B2;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_NO_MORE_TYPES: u32 = 0xC00D_36B9;
const MF_E_UNSUPPORTED_SERVICE: u32 = 0xC00D_36BA;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_NO_SAMPLE_TIMESTAMP: u32 = 0xC00D_36A4;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_ATTRIBUTENOTFOUND: u32 = 0xC00D_36E6;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_NOTFOUND: u32 = 0xC00D_36B1;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_INVALIDMEDIATYPE: u32 = 0xC00D_36B4;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_UNSUPPORTED_BYTESTREAM_TYPE: u32 = 0xC00D_36C4;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_TOPO_COULD_NOT_OPEN: u32 = 0xC00D_5208;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_UNSUPPORTED_CHARACTERISTICS: u32 = 0xC00D_3E9E;

// ── Service registry GUIDs (the guest little-endian byte form) ────────────
// The MFGetService service identifiers and the interface IIDs the service
// providers answer.  All byte values below are the guest little-endian
// representation of the documented Windows GUIDs.

/// MF_RATE_CONTROL_SERVICE {866fa297-b802-4bf8-9dc9-5e3b6a9f53c9} (mfidl.h).
const SERVICE_MF_RATE_CONTROL: [u8; 16] = [
    0x97, 0xa2, 0x6f, 0x86, 0x02, 0xb8, 0xf8, 0x4b, 0x9d, 0xc9, 0x5e, 0x3b, 0x6a, 0x9f, 0x53, 0xc9,
];
/// MF_MEDIASESSION_SERVICE — the media-session service identifier the
/// session owner answers with its IMFMediaSession interface.  The Windows
/// SDK exports no constant under this name (no value is published in any
/// SDK header), so the runtime keeps a stable Casa1-defined identifier:
/// {b379a95c-76f1-49c1-af4c-23f7f628dfd1} in guest little-endian form.
const SERVICE_MF_MEDIA_SESSION: [u8; 16] = [
    0x5c, 0xa9, 0x79, 0xb3, 0xf1, 0x76, 0xc1, 0x49, 0xaf, 0x4c, 0x23, 0xf7, 0xf6, 0x28, 0xdf, 0xd1,
];
/// IID_IMFMediaSession {90377834-21d0-4dee-8214-ba2e3e6c1127}.
const IID_IMF_MEDIA_SESSION: [u8; 16] = [
    0x34, 0x78, 0x37, 0x90, 0xd0, 0x21, 0xee, 0x4d, 0x82, 0x14, 0xba, 0x2e, 0x3e, 0x6c, 0x11, 0x27,
];
/// IID_IMFRateControl {88ddcd21-03c3-4275-91ed-55ee3929328f}.
const IID_IMF_RATE_CONTROL: [u8; 16] = [
    0x21, 0xcd, 0xdd, 0x88, 0xc3, 0x03, 0x75, 0x42, 0x91, 0xed, 0x55, 0xee, 0x39, 0x29, 0x32, 0x8f,
];
/// IID_IMFRateSupport {0a9ccdbc-d797-4563-9667-94ec5d79292d}.
const IID_IMF_RATE_SUPPORT: [u8; 16] = [
    0xbc, 0xcd, 0x9c, 0x0a, 0x97, 0xd7, 0x63, 0x45, 0x96, 0x67, 0x94, 0xec, 0x5d, 0x79, 0x29, 0x2d,
];
/// IID_IUnknown {00000000-0000-0000-c000-000000000046}.
const IID_IUNKNOWN: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
/// IID_IMFAttributes {2cd2d921-c447-44a7-a13c-4adabfc247e3}.
const IID_IMF_ATTRIBUTES: [u8; 16] = [
    0x21, 0xd9, 0xd2, 0x2c, 0x47, 0xc4, 0xa7, 0x44, 0xa1, 0x3c, 0x4a, 0xda, 0xbf, 0xc2, 0x47, 0xe3,
];
/// IID_IMFByteStream {ad4c1b00-4bf7-422f-9175-756693d9130d} (mfobjects.h).
#[allow(dead_code)] // referenced by the MF service-resolution tests
const IID_IMF_BYTE_STREAM: [u8; 16] = [
    0x00, 0x1b, 0x4c, 0xad, 0xf7, 0x4b, 0x2f, 0x42, 0x91, 0x75, 0x75, 0x66, 0x93, 0xd9, 0x13, 0x0d,
];
/// IID_IMFMediaSource {279a808d-aec7-40c8-9c6b-a6b492c78a66} (mfidl.h).
const IID_IMF_MEDIA_SOURCE: [u8; 16] = [
    0x8d, 0x80, 0x9a, 0x27, 0xc7, 0xae, 0xc8, 0x40, 0x9c, 0x6b, 0xa6, 0xb4, 0x92, 0xc7, 0x8a, 0x66,
];
/// IID_IMFMediaSourceEx {3c9b2eb9-86d5-4514-a394-f56664f9f0d8} (mfidl.h).
const IID_IMF_MEDIA_SOURCE_EX: [u8; 16] = [
    0xb9, 0x2e, 0x9b, 0x3c, 0xd5, 0x86, 0x14, 0x45, 0xa3, 0x94, 0xf5, 0x66, 0x64, 0xf9, 0xf0, 0xd8,
];
/// IID_IMFPresentationDescriptor {03cb2711-24d7-4db6-a17f-f3a7a479a536}.
#[allow(dead_code)] // referenced by the MF service-resolution tests
const IID_IMF_PRESENTATION_DESCRIPTOR: [u8; 16] = [
    0x11, 0x27, 0xcb, 0x03, 0xd7, 0x24, 0xb6, 0x4d, 0xa1, 0x7f, 0xf3, 0xa7, 0xa4, 0x79, 0xa5, 0x36,
];
/// IID_IMFStreamDescriptor {56c03d9c-9dbb-45f5-ab4b-d80f47c05938}.
#[allow(dead_code)] // referenced by the MF service-resolution tests
const IID_IMF_STREAM_DESCRIPTOR: [u8; 16] = [
    0x9c, 0x3d, 0xc0, 0x56, 0xbb, 0x9d, 0xf5, 0x45, 0xab, 0x4b, 0xd8, 0x0f, 0x47, 0xc0, 0x59, 0x38,
];
/// IID_IMFMediaTypeHandler {e93dcf6c-4b07-4e1e-8123-aa16ed6eadf5}.
#[allow(dead_code)] // referenced by the MF service-resolution tests
const IID_IMF_MEDIA_TYPE_HANDLER: [u8; 16] = [
    0x6c, 0xcf, 0x3d, 0xe9, 0x07, 0x4b, 0x1e, 0x4e, 0x81, 0x23, 0xaa, 0x16, 0xed, 0x6e, 0xad, 0xf5,
];
/// IID_IMFSourceReader {70ae66f2-c809-4e4f-8915-bdcb406b7993} (mfreadwrite.h).
#[allow(dead_code)] // referenced by the MF service-resolution tests
const IID_IMF_SOURCE_READER: [u8; 16] = [
    0xf2, 0x66, 0xae, 0x70, 0x09, 0xc8, 0x4f, 0x4e, 0x89, 0x15, 0xbd, 0xcb, 0x40, 0x6b, 0x79, 0x93,
];
/// IID_IMFGetService {fa993888-4383-415a-a930-dd472a8cf6f7}.
#[allow(dead_code)] // referenced by the MF service-resolution tests
const IID_IMF_GET_SERVICE: [u8; 16] = [
    0x88, 0x38, 0x99, 0xfa, 0x83, 0x43, 0x5a, 0x41, 0xa9, 0x30, 0xdd, 0x47, 0x2a, 0x8c, 0xf6, 0xf7,
];
/// IID_IMFMediaEvent {df598932-f10c-4e39-bba2-c308f101daa3} (mfobjects.h).
#[allow(dead_code)] // referenced by the MF service-resolution tests
const IID_IMF_MEDIA_EVENT: [u8; 16] = [
    0x32, 0x89, 0x59, 0xdf, 0x0c, 0xf1, 0x39, 0x4e, 0xbb, 0xa2, 0xc3, 0x08, 0xf1, 0x01, 0xda, 0xa3,
];
/// MF_MEDIASOURCE_SERVICE {f09992f7-9fba-4c4a-a37f-8c47b4e1dfe7} (mfidl.h).
const SERVICE_MF_MEDIASOURCE: [u8; 16] = [
    0xf7, 0x92, 0x99, 0xf0, 0xba, 0x9f, 0x4a, 0x4c, 0xa3, 0x7f, 0x8c, 0x47, 0xb4, 0xe1, 0xdf, 0xe7,
];
/// MF_METADATA_PROVIDER_SERVICE {db214084-58a4-4d2e-b84f-6f755b2f7a0d}
/// (mfidl.h).  No real metadata/tag parser exists in the runtime, so no
/// provider is registered: the service stays genuinely unsupported.
#[allow(dead_code)] // referenced by the MF service-resolution tests
const SERVICE_MF_METADATA_PROVIDER: [u8; 16] = [
    0x84, 0x40, 0x21, 0xdb, 0xa4, 0x58, 0x2e, 0x4d, 0xb8, 0x4f, 0x6f, 0x75, 0x5b, 0x2f, 0x7a, 0x0d,
];
/// MF_BYTESTREAM_ORIGIN_NAME {fc358288-3cb6-460c-a424-b6681260375a}.
const SERVICE_MF_BYTESTREAM_ORIGIN_NAME: [u8; 16] = [
    0x88, 0x82, 0x35, 0xfc, 0xb6, 0x3c, 0x0c, 0x46, 0xa4, 0x24, 0xb6, 0x68, 0x12, 0x60, 0x37, 0x5a,
];
/// MF_BYTESTREAM_CONTENT_TYPE {fc358289-3cb6-460c-a424-b6681260375a}.
const SERVICE_MF_BYTESTREAM_CONTENT_TYPE: [u8; 16] = [
    0x89, 0x82, 0x35, 0xfc, 0xb6, 0x3c, 0x0c, 0x46, 0xa4, 0x24, 0xb6, 0x68, 0x12, 0x60, 0x37, 0x5a,
];
/// The real MF_E_* failure codes used by the source side.  Values are from
/// mferror.h.
const MF_E_UNSUPPORTED_REPRESENTATION: u32 = 0xC00D_36B7;
const MF_E_UNSUPPORTED_TIME_FORMAT: u32 = 0xC00D_36C5;
const MF_E_NO_EVENTS_AVAILABLE: u32 = 0xC00D_3E80;
const MF_E_SHUTDOWN: u32 = 0xC00D_3E85;
/// E_FAIL — the documented answer for operations on a closed byte stream.
const E_FAIL: u32 = 0x8000_4005;
const E_ACCESSDENIED: u32 = 0x8007_0005;

// ── MFBYTESTREAM_* and source-reader flags (mfobjects.h / mfreadwrite.h) ───
const MFBYTESTREAM_IS_READABLE: u32 = 0x1;
const MFBYTESTREAM_IS_WRITABLE: u32 = 0x2;
const MFBYTESTREAM_IS_SEEKABLE: u32 = 0x4;
const MFBYTESTREAM_DOES_NOT_USE_NETWORK: u32 = 0x800;
/// MFBYTESTREAM_SEEK_ORIGIN (msoBegin = 0, msoCurrent = 1).
const MSO_BEGIN: u32 = 0;
/// MF_SOURCE_READERF_* flags (mfreadwrite.h).
const MF_SOURCE_READERF_ENDOFSTREAM: u32 = 0x2;
#[allow(dead_code)] // reserved for the new-stream sample flag surface
const MF_SOURCE_READERF_NEWSTREAM: u32 = 0x4;

/// MFRATE_FORWARD (mfidl.h `_MFRATE_DIRECTION`).
const MFRATE_FORWARD: u32 = 0;
/// MFRATE_REVERSE (mfidl.h `_MFRATE_DIRECTION`).
const MFRATE_REVERSE: u32 = 1;

/// MF_E_UNSUPPORTED_RATE (mferror.h 0xC00D36D0).
const MF_E_UNSUPPORTED_RATE: u32 = 0xC00D_36D0;

/// The rate value the rate-support provider reports as the session's
/// slowest forward rate: no pipeline component in the runtime graph can
/// run slower than real time.
const MF_SESSION_SLOWEST_FORWARD_RATE: f32 = 1.0;

/// The standard MF interface vtable preamble: IUnknown + the first
/// interface method slots that the runtime dispatches.  The remaining slots
/// are filled with the interface's own methods.
#[allow(dead_code)] // the MF dispatch surface (methods are reached via the grouped HostThunk arm)
impl PeHostRuntime {
    /// `MFStartup(Version, dwFlags)` — initializes the MF runtime state.
    pub(crate) fn dispatch_mf_startup(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let version = guest_call_arg_u32(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        self.mf_runtime.started = true;
        self.mf_runtime.version = version;
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `MFShutdown()` — tears the MF runtime state down.
    pub(crate) fn dispatch_mf_shutdown(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.mf_runtime.started = false;
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `MFRequireProtectedEnvironment()` — the runtime has no protected
    /// media path; the documented success for unprotected content.
    pub(crate) fn dispatch_mf_require_protected_environment(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        state.set(Register::Rax, u64::from(S_OK));
        let _ = memory;
        Ok(())
    }

    /// `MFGetService(pUnk, guidService, riid, ppvObject)` — resolve the
    /// object to the owner of the requested service in its object graph and
    /// hand back a real provider object.
    ///
    /// Provider model: every guest object belongs to an object graph whose
    /// root owns service tables.  Today the media session is the only owner
    /// with providers (the session itself, plus its rate-control service);
    /// the session's topology and topology-node objects resolve up to their
    /// owning session.  Objects without a provider table, and service GUIDs
    /// no owner provides, answer `MF_E_UNSUPPORTED_SERVICE` (the documented
    /// Windows answer when the object does not own the service).
    pub(crate) fn dispatch_mf_get_service(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let p_unk = guest_call_arg(state, memory, 0)?;
        let service_ptr = guest_call_arg(state, memory, 1)?;
        let iid_ptr = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if service_ptr == 0 || iid_ptr == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        let mut service = [0_u8; 16];
        let service_bytes = memory.read_bytes(service_ptr, 16).unwrap_or_default();
        service.copy_from_slice(&service_bytes[..service_bytes.len().min(16)]);
        let mut iid = [0_u8; 16];
        let iid_bytes = memory.read_bytes(iid_ptr, 16).unwrap_or_default();
        iid.copy_from_slice(&iid_bytes[..iid_bytes.len().min(16)]);
        let Some(owner) = self.mf_service_owner(p_unk) else {
            // Not a runtime-registered object (or an object whose graph
            // owns no service): the documented unsupported-service answer.
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
            return Ok(());
        };
        match self.guest_object_kind(owner) {
            Ok(GuestObjectKind::ImfMediaSession) => {
                self.dispatch_mf_session_get_service(state, memory, owner, &service, &iid)
            }
            Ok(GuestObjectKind::ImfMediaSource) => {
                self.dispatch_mf_media_source_get_service(state, memory, owner, &service, &iid)
            }
            Ok(GuestObjectKind::ImfByteStream) => {
                self.dispatch_mf_byte_stream_get_service(state, memory, owner, &service, &iid)
            }
            _ => {
                state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
                Ok(())
            }
        }
    }

    /// Resolve a guest object to the owner of its services in the guest
    /// object graph:
    ///
    /// - a media session owns its own session services;
    /// - a session's topology objects and topology-node objects resolve to
    ///   the session that holds them (`mf_session_topologies` and the
    ///   topology's node table are the ownership edges).
    ///
    /// Everything else is its own (provider-less) root.
    fn mf_service_owner(&self, object: u64) -> Option<u64> {
        let kind = self.guest_object_kind(object).ok()?;
        match kind {
            GuestObjectKind::ImfMediaSession => {
                self.mf_sessions.contains_key(&object).then_some(object)
            }
            GuestObjectKind::ImfMediaSource => {
                // A real source owns MF_MEDIASOURCE_SERVICE on itself.
                self.mf_media_sources
                    .contains_key(&object)
                    .then_some(object)
            }
            GuestObjectKind::ImfByteStream => {
                self.mf_byte_streams.contains_key(&object).then_some(object)
            }
            GuestObjectKind::ImfTopology => self
                .mf_session_topologies
                .iter()
                .find(|(_, topology)| **topology == object)
                .map(|(session, _)| *session),
            GuestObjectKind::ImfTopologyNode => self.mf_session_for_topology_node(object),
            _ => None,
        }
    }

    /// Find the session that owns a topology node: the node's media-model
    /// id (its `TopologyNodeState.object`) must appear in the node table of
    /// a session's full topology.
    fn mf_session_for_topology_node(&self, node: u64) -> Option<u64> {
        let node_id = self.mf_topology_nodes.get(&node)?.object;
        if node_id == 0 {
            return None;
        }
        self.mf_session_topologies
            .iter()
            .find_map(|(session, topology)| {
                let topology = self.mf_topologies.get(topology)?;
                topology
                    .nodes
                    .iter()
                    .any(|entry| entry.id == node_id)
                    .then_some(*session)
            })
    }

    /// The media session's real provider table: the service GUIDs the
    /// session owner provides and the object handed out for the requested
    /// interface.  Returns `S_OK` after writing `ppvObject`, or
    /// `MF_E_UNSUPPORTED_SERVICE` when the session does not own the service
    /// (or does not answer the requested interface).
    fn dispatch_mf_session_get_service(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        session: u64,
        service: &[u8; 16],
        iid: &[u8; 16],
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 3)?;
        if service == &SERVICE_MF_MEDIA_SESSION {
            // The session service: the session itself.
            if iid == &IID_IMF_MEDIA_SESSION || iid == &IID_IUNKNOWN {
                write_guest_pointer(memory, out, session, self.guest_arch).ok();
                self.add_ref_guest_object(session)?;
                state.set(Register::Rax, u64::from(S_OK));
                return Ok(());
            }
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
            return Ok(());
        }
        if service == &SERVICE_MF_RATE_CONTROL {
            // The rate-control service: a real IMFRateControl /
            // IMFRateSupport object whose methods drive the owning
            // session's playback rate.  A fresh service object is handed
            // out per query (the guest releases it like any GetService
            // result); its owner-session registration lives in
            // `mf_rate_services`.
            let vtable = if iid == &IID_IMF_RATE_CONTROL || iid == &IID_IUNKNOWN {
                self.alloc_guest_vtable(memory, mf_rate_control_methods())?
            } else if iid == &IID_IMF_RATE_SUPPORT {
                self.alloc_guest_vtable(memory, mf_rate_support_methods())?
            } else {
                state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
                return Ok(());
            };
            let object =
                self.alloc_guest_object(memory, GuestObjectKind::ImfRateControlService, vtable)?;
            self.mf_rate_services.insert(object, session);
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
        Ok(())
    }

    /// The media source's real provider table.  `MF_MEDIASOURCE_SERVICE` is
    /// the documented Windows 8.1+ source service: it returns the source
    /// object itself for `IID_IMFMediaSource`, `IID_IMFMediaSourceEx` and
    /// `IID_IUnknown`.  `MF_METADATA_PROVIDER_SERVICE` is NOT registered:
    /// the runtime has no real container tag/metadata parser, so no provider
    /// is fabricated.
    fn dispatch_mf_media_source_get_service(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        source: u64,
        service: &[u8; 16],
        iid: &[u8; 16],
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 3)?;
        if service == &SERVICE_MF_MEDIASOURCE
            && (iid == &IID_IMF_MEDIA_SOURCE
                || iid == &IID_IMF_MEDIA_SOURCE_EX
                || iid == &IID_IUNKNOWN)
        {
            write_guest_pointer(memory, out, source, self.guest_arch).ok();
            self.add_ref_guest_object(source)?;
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
        Ok(())
    }

    /// The byte stream's attribute provider table.  A byte stream that knows
    /// its origin/content type exposes those documented attributes
    /// (`MF_BYTESTREAM_ORIGIN_NAME`, `MF_BYTESTREAM_CONTENT_TYPE`) through
    /// `MFGetService`: the service GUID is the attribute key and the returned
    /// object is an `IMFAttributes` store carrying exactly that attribute
    /// (the same attribute the Windows byte stream would set).  Streams
    /// without the attribute, and every other service GUID, answer
    /// `MF_E_UNSUPPORTED_SERVICE`.
    fn dispatch_mf_byte_stream_get_service(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        stream_object: u64,
        service: &[u8; 16],
        iid: &[u8; 16],
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 3)?;
        let Some(stream) = self.mf_byte_streams.get(&stream_object) else {
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
            return Ok(());
        };
        let value = if service == &SERVICE_MF_BYTESTREAM_ORIGIN_NAME {
            stream.origin_name.clone()
        } else if service == &SERVICE_MF_BYTESTREAM_CONTENT_TYPE {
            stream.content_type.clone()
        } else {
            None
        };
        let Some(value) = value else {
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
            return Ok(());
        };
        if iid != &IID_IMF_ATTRIBUTES && iid != &IID_IUNKNOWN {
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_attributes_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let key = mf_guid_from_bytes(service);
        let mut store = ImfMediaType::new();
        store.set_string(key, value);
        self.mf_media_types.insert(object, store);
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFRateControl::SetRate(fThin, flRate)` — set the owning media
    /// session's playback rate.  The session's clock/position machinery
    /// runs forward at real time, so the genuinely backed rates are the
    /// forward non-thinned rates from 1.0 up; anything else (thinned
    /// playback, slow motion, reverse) answers `MF_E_UNSUPPORTED_RATE`.
    pub(crate) fn dispatch_mf_rate_control_set_rate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let thin = guest_call_arg_u32(state, memory, 1)?;
        let rate = f32::from_bits(guest_call_arg_u32(state, memory, 2)?);
        let Some(&session) = self.mf_rate_services.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if thin != 0 || !rate.is_finite() || rate < MF_SESSION_SLOWEST_FORWARD_RATE {
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_RATE));
            return Ok(());
        }
        match self.mf_sessions.get_mut(&session) {
            Some(session_state) => {
                session_state.set_rate(rate);
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// `IMFRateControl::GetRate(pfThin, pflRate)` — the session's current
    /// playback rate (never thinned).
    pub(crate) fn dispatch_mf_rate_control_get_rate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let thin_out = guest_call_arg(state, memory, 1)?;
        let rate_out = guest_call_arg(state, memory, 2)?;
        let Some(&session) = self.mf_rate_services.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let Some(session_state) = self.mf_sessions.get(&session) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let rate = session_state.get_rate();
        if thin_out != 0 {
            write_u32(memory, thin_out, 0);
        }
        if rate_out != 0 {
            write_u32(memory, rate_out, rate.to_bits());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// The slowest/fastest forward rate of the session's rate-control
    /// service (`IMFRateSupport`).  Reverse and thinned playback are not
    /// backed by the session graph.
    fn dispatch_mf_rate_support_bound(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        fastest: bool,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let direction = guest_call_arg_u32(state, memory, 1)?;
        let thin = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if !self.mf_rate_services.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        match direction {
            MFRATE_FORWARD if thin == 0 => {}
            MFRATE_FORWARD | MFRATE_REVERSE => {
                // Thinned playback and reverse playback are not backed by
                // the session graph.
                state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_RATE));
                return Ok(());
            }
            _ => {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        }
        let bound = if fastest {
            // The session clock/position math scales by any finite forward
            // rate; no artificial ceiling is imposed on the fastest rate.
            f32::MAX
        } else {
            MF_SESSION_SLOWEST_FORWARD_RATE
        };
        if out != 0 {
            write_u32(memory, out, bound.to_bits());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFRateSupport::GetSlowestRate(eDirection, fThin, pflRate)`.
    pub(crate) fn dispatch_mf_rate_support_get_slowest_rate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_mf_rate_support_bound(state, memory, false)
    }

    /// `IMFRateSupport::GetFastestRate(eDirection, fThin, pflRate)`.
    pub(crate) fn dispatch_mf_rate_support_get_fastest_rate(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_mf_rate_support_bound(state, memory, true)
    }

    /// `IMFRateSupport::IsRateSupported(fThin, flRate,
    /// pflNearestSupportedRate)` — the session backs forward non-thinned
    /// rates from 1.0 up.
    pub(crate) fn dispatch_mf_rate_support_is_rate_supported(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let thin = guest_call_arg_u32(state, memory, 1)?;
        let rate = f32::from_bits(guest_call_arg_u32(state, memory, 2)?);
        let nearest_out = guest_call_arg(state, memory, 3)?;
        if !self.mf_rate_services.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let supported = thin == 0 && rate.is_finite() && rate >= MF_SESSION_SLOWEST_FORWARD_RATE;
        if !supported && nearest_out != 0 {
            write_u32(
                memory,
                nearest_out,
                MF_SESSION_SLOWEST_FORWARD_RATE.to_bits(),
            );
        }
        state.set(
            Register::Rax,
            u64::from(if supported {
                S_OK
            } else {
                MF_E_UNSUPPORTED_RATE
            }),
        );
        Ok(())
    }

    /// `MFAddPeriodicCallback(Callback, pContext, pdwKey)` — register a guest
    /// periodic callback; the key lets `MFCancelPeriodicCallback` remove it.
    pub(crate) fn dispatch_mf_add_periodic_callback(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let callback = guest_call_arg(state, memory, 0)?;
        let context = guest_call_arg(state, memory, 1)?;
        let key_out = guest_call_arg(state, memory, 2)?;
        let key = self.mf_runtime.next_periodic_callback_key;
        self.mf_runtime.next_periodic_callback_key = key.wrapping_add(1);
        self.mf_runtime
            .periodic_callbacks
            .insert(key, MfPeriodicCallback { callback, context });
        if key_out != 0 {
            write_guest_u32(memory, key_out, key).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCancelPeriodicCallback(dwKey)` — remove a registered callback.
    pub(crate) fn dispatch_mf_cancel_periodic_callback(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let key = guest_call_arg_u32(state, memory, 0)?;
        let removed = self.mf_runtime.periodic_callbacks.remove(&key);
        state.set(
            Register::Rax,
            u64::from(if removed.is_some() {
                S_OK
            } else {
                E_INVALIDARG
            }),
        );
        Ok(())
    }

    /// `MFGetSystemTime(pSystemTime)` — the 100-nanosecond interval since
    /// 1601-01-01 (the same basis as FILETIME).
    pub(crate) fn dispatch_mf_get_system_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out != 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let ticks = 116_444_736_000_000_000_u64
                + now.as_secs().saturating_mul(10_000_000)
                + u64::from(now.subsec_nanos()) / 100;
            write_guest_u64(memory, out, ticks).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }
    // ── Object creation exports ────────────────────────────────────────────

    /// `MFCreateAttributes(ppMFAttributes, cInitialSize)` — an IMFAttributes
    /// guest object.
    pub(crate) fn dispatch_mf_create_attributes(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        let _initial = guest_call_arg_u32(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_attributes_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfAttributes, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateMediaType(ppMFType)` — an IMFMediaType guest object backed
    /// by the media layer's type state.
    pub(crate) fn dispatch_mf_create_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_media_type_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_media_types.insert(object, ImfMediaType::new());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateMemoryBuffer(cbMaxLength, ppBuffer)` — an IMFMediaBuffer
    /// with the requested capacity.
    pub(crate) fn dispatch_mf_create_memory_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let capacity = guest_call_arg_u32(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_media_buffer_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaBuffer, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_media_buffers
            .insert(object, ImfMediaBuffer::new(capacity));
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateMediaBufferFromMediaType(pMediaType, cbSuggestedLength,
    /// cbAlignment, ppBuffer)` — a buffer sized from the media type's
    /// ALLOCATION_UNIT / frame size when available.
    pub(crate) fn dispatch_mf_create_media_buffer_from_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let media_type = guest_call_arg(state, memory, 0)?;
        let suggested = guest_call_arg_u32(state, memory, 1)?;
        let _alignment = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let capacity = match self.mf_media_types.get(&media_type) {
            Some(t) => t
                .get_uint32(&crate::media::MF_MT_MAJOR_TYPE)
                .unwrap_or(0)
                .max(suggested),
            None => suggested,
        };
        let vtable = self.alloc_guest_vtable(memory, mf_media_buffer_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaBuffer, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_media_buffers
            .insert(object, ImfMediaBuffer::new(capacity.max(1)));
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateSample(ppIMFSample)` — an IMFSample guest object.
    pub(crate) fn dispatch_mf_create_sample(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_sample_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfSample, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_samples.insert(object, ImfSample::new(Vec::new()));
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateEventQueue(ppMediaEventQueue)` — an IMFMediaEventQueue.
    pub(crate) fn dispatch_mf_create_event_queue(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_event_queue_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaEventQueue, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_event_queues.insert(object, MfEventQueue::new());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreatePresentationClock(ppPresentationClock)` — a clock object.
    pub(crate) fn dispatch_mf_create_presentation_clock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_clock_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfPresentationClock, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_clocks
            .insert(object, crate::media::PresentationClock::new());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateTopology(ppTopo)` — an IMFTopology object.
    pub(crate) fn dispatch_mf_create_topology(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_topology_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfTopology, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_topologies
            .insert(object, crate::media::Topology::new());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateTopologyNode(NodeType, ppNode)` — an IMFTopologyNode.
    pub(crate) fn dispatch_mf_create_topology_node(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let node_type = guest_call_arg_u32(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_topology_node_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfTopologyNode, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_topology_nodes.insert(
            object,
            crate::runtime::state::TopologyNodeState {
                node_type,
                object: 0,
                inputs: Vec::new(),
                outputs: Vec::new(),
                name: String::new(),
            },
        );
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateSourceResolver(ppISourceResolver)` — a source resolver.
    pub(crate) fn dispatch_mf_create_source_resolver(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 0)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_source_resolver_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfSourceResolver, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_source_resolvers.insert(object, ());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateMediaSession(pAttributes, ppSession)` — a media session.
    pub(crate) fn dispatch_mf_create_media_session(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _attributes = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_session_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaSession, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_sessions
            .insert(object, crate::media::MfMediaSession::new());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// Allocate a guest IMFByteStream object over an open runtime file
    /// handle (or a memory payload).
    fn mf_alloc_byte_stream_object(
        &mut self,
        memory: &mut MemoryImage,
        state: crate::runtime::state::ImfByteStreamState,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_byte_stream_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfByteStream, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        self.mf_byte_streams.insert(object, state);
        Ok(object)
    }

    /// Allocate a guest IMFMediaSource object (with the IMFMediaSourceEx
    /// vtable superset) over a presentation and its byte stream.
    fn mf_alloc_media_source_object(
        &mut self,
        memory: &mut MemoryImage,
        presentation: crate::media::MfPresentationDescriptor,
        byte_stream: u64,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_media_source_ex_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaSource, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        self.mf_media_sources.insert(
            object,
            crate::media::MfMediaSource::new(presentation, byte_stream),
        );
        Ok(object)
    }

    /// Allocate a guest IMFSourceReader object wired to its media source.
    fn mf_alloc_source_reader_object(
        &mut self,
        memory: &mut MemoryImage,
        reader: crate::media::SourceReader,
        source: u64,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_source_reader_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfSourceReader, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        let mut reader = reader;
        reader.set_source(source);
        self.mf_source_readers.insert(object, reader);
        if let Some(source) = self.mf_media_sources.get_mut(&source) {
            source.attach_reader(object);
        }
        Ok(object)
    }

    /// Read a byte stream's entire payload without moving its position.
    fn mf_byte_stream_read_all(&mut self, stream_object: u64) -> AppResult<Vec<u8>> {
        let Some(stream) = self.mf_byte_streams.get(&stream_object).cloned() else {
            return Ok(Vec::new());
        };
        if stream.file_handle != 0 {
            let length = self
                .win32
                .get_file_size_ex(stream.file_handle)
                .unwrap_or(stream.length);
            self.win32
                .set_file_pointer_ex(stream.file_handle, 0, crate::win32::SeekOrigin::Begin)
                .ok();
            Ok(self
                .win32
                .read_file(stream.file_handle, length as usize)
                .unwrap_or_default())
        } else {
            Ok(stream.data.clone())
        }
    }

    /// Open a real source graph from an URL or an existing byte stream:
    /// `(byte_stream, media_source, source_reader)` guest objects, or the
    /// guest HRESULT when the URL has no file backend / the data is not a
    /// supported container.
    ///
    /// The URL path opens the file through the runtime file tables
    /// (`CreateFileW` semantics: GE-relative path resolution, share state,
    /// access masks), wraps the handle in a real IMFByteStream, parses the
    /// container, and builds the source over the parsed presentation.
    fn mf_open_source_graph(
        &mut self,
        url: Option<&str>,
        stream: Option<u64>,
        memory: &mut MemoryImage,
    ) -> AppResult<Result<(u64, u64, u64), u32>> {
        if let Some(stream_object) = stream {
            if !self.mf_byte_streams.contains_key(&stream_object) {
                return Ok(Err(0x8007_0006)); // ERROR_INVALID_HANDLE
            }
            let data = self.mf_byte_stream_read_all(stream_object)?;
            let reader = match crate::media::SourceReader::from_data(data) {
                Ok(reader) => reader,
                Err(_) => return Ok(Err(MF_E_UNSUPPORTED_BYTESTREAM_TYPE)),
            };
            let presentation = reader.presentation(0, None);
            let source = self.mf_alloc_media_source_object(memory, presentation, stream_object)?;
            if source == 0 {
                return Ok(Err(E_OUTOFMEMORY));
            }
            let reader_object = self.mf_alloc_source_reader_object(memory, reader, source)?;
            if reader_object == 0 {
                return Ok(Err(E_OUTOFMEMORY));
            }
            return Ok(Ok((stream_object, source, reader_object)));
        }
        let Some(url) = url else {
            return Ok(Err(MF_E_UNSUPPORTED_BYTESTREAM_TYPE));
        };
        let path = url.strip_prefix("file://").unwrap_or(url);
        if path.starts_with("http://") || path.starts_with("https://") {
            // No network byte-stream handler is registered.
            return Ok(Err(MF_E_UNSUPPORTED_BYTESTREAM_TYPE));
        }
        let handle = match self.win32.create_file_w(
            path,
            crate::ge::FileAccess::read_only(),
            crate::ge::ShareMode::all(),
            crate::win32::CreationDisposition::OpenExisting,
            false,
            false,
            false,
        ) {
            Ok(handle) => handle,
            Err(_) => return Ok(Err(0x8007_0002)), // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
        };
        let length = self.win32.get_file_size_ex(handle).unwrap_or(0);
        let data = match self.win32.read_file(handle, length as usize) {
            Ok(data) => data,
            Err(_) => {
                self.win32.close_handle(handle).ok();
                return Ok(Err(0x8007_0002));
            }
        };
        self.win32
            .set_file_pointer_ex(handle, 0, crate::win32::SeekOrigin::Begin)
            .ok();
        let reader = match crate::media::SourceReader::from_data(data) {
            Ok(reader) => reader,
            Err(_) => {
                self.win32.close_handle(handle).ok();
                return Ok(Err(MF_E_UNSUPPORTED_BYTESTREAM_TYPE));
            }
        };
        let content_type = crate::media::mime_type_for_path(path).map(str::to_string);
        let byte_stream = self.mf_alloc_byte_stream_object(
            memory,
            crate::runtime::state::ImfByteStreamState::from_file(
                handle,
                length,
                false,
                Some(path.to_string()),
            ),
        )?;
        if byte_stream == 0 {
            self.win32.close_handle(handle).ok();
            return Ok(Err(E_OUTOFMEMORY));
        }
        if let Some(stream) = self.mf_byte_streams.get_mut(&byte_stream) {
            stream.content_type = content_type.clone();
        }
        let presentation = reader.presentation(length, content_type.as_deref());
        let source = self.mf_alloc_media_source_object(memory, presentation, byte_stream)?;
        if source == 0 {
            return Ok(Err(E_OUTOFMEMORY));
        }
        let reader_object = self.mf_alloc_source_reader_object(memory, reader, source)?;
        if reader_object == 0 {
            return Ok(Err(E_OUTOFMEMORY));
        }
        Ok(Ok((byte_stream, source, reader_object)))
    }

    /// `MFCreateSourceReaderFromURL(pwszURL, pAttributes, ppReader)` — opens
    /// the file through the runtime file tables and creates the real byte
    /// stream + media source + source reader graph.
    pub(crate) fn dispatch_mf_create_source_reader_from_url(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let url_ptr = guest_call_arg(state, memory, 0)?;
        let _attributes = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(url) = read_utf16_string(memory, url_ptr).ok() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        match self.mf_open_source_graph(Some(&url), None, memory)? {
            Ok((_byte_stream, _source, reader)) => {
                write_guest_pointer(memory, out, reader, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
            }
            Err(hr) => state.set(Register::Rax, u64::from(hr)),
        }
        Ok(())
    }

    /// `MFCreateSinkWriterFromMediaSink(pSink, pAttributes, ppSinkWriter)`
    /// — a sink writer over a media sink object (the media model writes the
    /// sink's output stream).
    pub(crate) fn dispatch_mf_create_sink_writer_from_media_sink(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _sink = guest_call_arg(state, memory, 0)?;
        let _attrs = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_sink_writer_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfSinkWriter, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_sink_writers
            .insert(object, crate::media::SinkWriter::new());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateSourceReaderFromByteStream(pByteStream, pAttributes,
    /// ppReader)` — reads the supplied byte stream's real payload, parses the
    /// container, and creates the media-source + reader graph over it.
    pub(crate) fn dispatch_mf_create_source_reader_from_byte_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let stream = guest_call_arg(state, memory, 0)?;
        let _attributes = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        match self.mf_open_source_graph(None, Some(stream), memory)? {
            Ok((_byte_stream, _source, reader)) => {
                write_guest_pointer(memory, out, reader, self.guest_arch).ok();
                state.set(Register::Rax, u64::from(S_OK));
            }
            Err(hr) => state.set(Register::Rax, u64::from(hr)),
        }
        Ok(())
    }

    /// `MFCreateSinkWriterFromURL(pwszOutputURL, pSinkAttributes,
    /// pAttributes, ppSinkWriter)` — a sink writer for the URL target.
    pub(crate) fn dispatch_mf_create_sink_writer_from_url(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let url_ptr = guest_call_arg(state, memory, 0)?;
        let _sink_attrs = guest_call_arg(state, memory, 1)?;
        let _attrs = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        let Some(url) = read_utf16_string(memory, url_ptr).ok() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_sink_writer_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfSinkWriter, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_sink_writers.insert(
            object,
            crate::media::SinkWriter::from_url(&url)
                .unwrap_or_else(|_| crate::media::SinkWriter::new()),
        );
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreatePresentationDescriptor(pStreamDescriptors, cStreamDescriptors,
    /// ppPresentationDescriptor)` — a presentation descriptor over the
    /// supplied real stream descriptors (NULL/0 gives the documented empty
    /// descriptor).
    pub(crate) fn dispatch_mf_create_presentation_descriptor(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let descriptors = guest_call_arg(state, memory, 0)?;
        let count = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let mut presentation = crate::media::MfPresentationDescriptor::empty();
        if descriptors != 0 && count > 0 {
            for index in 0..count {
                let pointer = read_guest_pointer(
                    memory,
                    descriptors + u64::from(index) * self.guest_arch.pointer_bytes() as u64,
                    self.guest_arch,
                )?;
                let Some(stream) = self.mf_stream_descriptors.get(&pointer).cloned() else {
                    state.set(Register::Rax, u64::from(E_INVALIDARG));
                    return Ok(());
                };
                presentation.streams.push(stream);
            }
            presentation.seekable = !presentation.streams.is_empty();
        }
        let object = self.alloc_mf_presentation_descriptor_object(memory, &presentation)?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateMFByteStreamOnStream(pStream, ppByteStream)` — an
    /// IMFByteStream over the IStream payload (a memory-backed readable,
    /// seekable stream of the copied bytes).
    pub(crate) fn dispatch_mf_create_mf_byte_stream_on_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let stream = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let payload = self
            .com_streams
            .get(&stream)
            .map(|s: &ComStreamState| s.data.clone())
            .unwrap_or_default();
        let object =
            self.mf_alloc_byte_stream_object(memory, ImfByteStreamState::from_bytes(payload))?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateFile(AccessMode, OpenMode, fFileFlags, pwszFileURL,
    /// ppIByteStream)` — a real file-backed IMFByteStream opened through the
    /// runtime file tables.
    pub(crate) fn dispatch_mf_create_file(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let access_mode = guest_call_arg_u32(state, memory, 0)?;
        let open_mode = guest_call_arg_u32(state, memory, 1)?;
        let _flags = guest_call_arg_u32(state, memory, 2)?;
        let url_ptr = guest_call_arg(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        let Some(path) = read_utf16_string(memory, url_ptr).ok() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let (read, write) = match access_mode {
            1 => (true, false), // MF_ACCESSMODE_READ
            2 => (false, true), // MF_ACCESSMODE_WRITE
            3 => (true, true),  // MF_ACCESSMODE_READWRITE
            _ => {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        };
        let creation = match open_mode {
            0 => crate::win32::CreationDisposition::OpenExisting, // FAIL_IF_NOT_EXIST
            1 => crate::win32::CreationDisposition::CreateNew,    // FAIL_IF_EXIST
            2 => crate::win32::CreationDisposition::CreateAlways, // RESET_IF_EXIST
            3 => crate::win32::CreationDisposition::OpenAlways,   // APPEND_IF_EXIST
            _ => {
                // MF_OPENMODE_DELETE_IF_EXIST has no runtime file-table
                // disposition; it is answered as an argument error instead
                // of silently opening a non-deleting stream.
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        };
        let handle = match self.win32.create_file_w(
            &path,
            crate::ge::FileAccess {
                read,
                write,
                delete: false,
            },
            crate::ge::ShareMode::all(),
            creation,
            false,
            false,
            false,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                state.set(Register::Rax, u64::from(win32_error_to_hresult(&error)));
                return Ok(());
            }
        };
        let length = if read {
            self.win32.get_file_size_ex(handle).unwrap_or(0)
        } else {
            0
        };
        let content_type = crate::media::mime_type_for_path(&path).map(str::to_string);
        let object = self.mf_alloc_byte_stream_object(
            memory,
            ImfByteStreamState::from_file(handle, length, write, Some(path.clone())),
        )?;
        if object == 0 {
            self.win32.close_handle(handle).ok();
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        if let Some(stream) = self.mf_byte_streams.get_mut(&object) {
            stream.content_type = content_type;
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateDXGIDeviceManager(resetToken, ppManager)` — an
    /// IMFDXGIDeviceManager with a reset token; device handles are
    /// allocated through OpenDeviceHandle and validated by the handle
    /// methods.
    pub(crate) fn dispatch_mf_create_dxgi_device_manager(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let reset_token = guest_call_arg_u32(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_dxgi_device_manager_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfDxgiDeviceManager, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_dxgi_device_managers.insert(
            object,
            MfDxgiDeviceManagerState {
                reset_token,
                ..Default::default()
            },
        );
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFDXGIDeviceManager::ResetDevice(resetToken)` — replace the reset
    /// token and invalidate the open device handles.
    pub(crate) fn dispatch_mf_dxgi_device_manager_reset_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let token = guest_call_arg_u32(state, memory, 1)?;
        let Some(manager) = self.mf_dxgi_device_managers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        manager.reset_token = token;
        manager.open_handles.clear();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFDXGIDeviceManager::OpenDeviceHandle(phDevice)` — allocate a
    /// device handle.
    pub(crate) fn dispatch_mf_dxgi_device_manager_open_device_handle(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(manager) = self.mf_dxgi_device_managers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let handle = manager.next_handle;
        manager.next_handle = manager.next_handle.wrapping_add(1);
        manager.open_handles.insert(handle);
        write_guest_pointer(memory, out, handle, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFDXGIDeviceManager::CloseDeviceHandle(hDevice)` — release a
    /// device handle.
    pub(crate) fn dispatch_mf_dxgi_device_manager_close_device_handle(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let handle = guest_call_arg(state, memory, 1)?;
        let Some(manager) = self.mf_dxgi_device_managers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let removed = manager.open_handles.remove(&handle);
        state.set(
            Register::Rax,
            u64::from(if removed { S_OK } else { E_INVALIDARG }),
        );
        Ok(())
    }

    /// `IMFDXGIDeviceManager::TestDevice(hDevice)` — S_OK when the handle
    /// is open.
    pub(crate) fn dispatch_mf_dxgi_device_manager_test_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let handle = guest_call_arg(state, memory, 1)?;
        let Some(manager) = self.mf_dxgi_device_managers.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let valid = manager.open_handles.contains(&handle);
        state.set(
            Register::Rax,
            u64::from(if valid { S_OK } else { E_INVALIDARG }),
        );
        Ok(())
    }

    /// `IMFDXGIDeviceManager::LockDevice(hDevice, riid, ppUnlockDevice)` —
    /// no D3D device is registered in the MF runtime — E_NOINTERFACE with a
    /// null output.
    pub(crate) fn dispatch_mf_dxgi_device_manager_lock_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _handle = guest_call_arg(state, memory, 1)?;
        let _riid = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(E_NOINTERFACE));
        Ok(())
    }

    /// `IMFDXGIDeviceManager::UnlockDevice(hDevice)` — no locked device —
    /// S_OK.
    pub(crate) fn dispatch_mf_dxgi_device_manager_unlock_device(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _handle = guest_call_arg(state, memory, 1)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFDXGIDeviceManager::GetVideoService(hDevice, riid, ppService)` —
    /// no video service provider in the MF runtime —
    /// `MF_E_UNSUPPORTED_SERVICE` with a null output.
    pub(crate) fn dispatch_mf_dxgi_device_manager_get_video_service(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _handle = guest_call_arg(state, memory, 1)?;
        let _riid = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
        Ok(())
    }

    /// `MFTEnumEx(category, flags, pInputType, pOutputType, pppMFTActivate,
    /// pnumMFTActivate)` — no third-party MFTs are registered — the
    /// documented empty enumeration.
    /// `MFTEnumEx(category, flags, pInputType, pOutputType, pppMFTActivate,
    /// pnumMFTActivate)` — the Casa1 Video Decoder MFT is registered in the
    /// video-decoder category; the enumeration hands out its activation
    /// object.
    pub(crate) fn dispatch_mf_enum_ex(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let category = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let _input = guest_call_arg(state, memory, 2)?;
        let _output = guest_call_arg(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        let count = guest_call_arg(state, memory, 5)?;
        let category_guid = memory.read_bytes(category, 16).unwrap_or_default();
        if category_guid != MFT_CATEGORY_VIDEO_DECODER {
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            }
            if count != 0 {
                write_u32(memory, count, 0);
            }
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        if out == 0 || count == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mft_activate_methods())?;
        let activate = self
            .alloc_guest_object(memory, GuestObjectKind::MftActivate, vtable)
            .unwrap_or(0);
        if activate == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_activates.insert(activate, 0_u32);
        write_guest_pointer(memory, out, activate, self.guest_arch).ok();
        write_u32(memory, count, 1);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::GetItem(guidKey, pValue)` — write the PROPVARIANT
    /// for the attribute.
    pub(crate) fn dispatch_mf_attr_get_item(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = guest_call_arg(state, memory, 1)?;
        let value = guest_call_arg(state, memory, 2)?;
        let Some(mt) = self.mf_media_types.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let key = read_mf_guid(memory, key);
        let Some((vt, bytes)) = mf_attribute_propvariant(&mt, key) else {
            state.set(Register::Rax, 0xc00d_36e5); // MF_E_ATTRIBUTENOTFOUND
            return Ok(());
        };
        if value != 0 {
            write_guest_u32(memory, value, vt).ok();
            if !bytes.is_empty() {
                memory.map_bytes(value + 8, &bytes);
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::GetItemType(guidKey, pType)` — the
    /// MF_ATTRIBUTE_TYPE.
    pub(crate) fn dispatch_mf_attr_get_item_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(mt) = self.mf_media_types.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let key = read_mf_guid(memory, key);
        let Some((vt, _)) = mf_attribute_propvariant(mt, key) else {
            state.set(Register::Rax, 0xc00d_36e5);
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, vt).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::CompareItem(guidKey, Value, pbResult)` — compare the
    /// attribute's value to the PROPVARIANT.
    pub(crate) fn dispatch_mf_attr_compare_item(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = guest_call_arg(state, memory, 1)?;
        let value = guest_call_arg(state, memory, 2)?;
        let result = guest_call_arg(state, memory, 3)?;
        let Some(mt) = self.mf_media_types.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let key = read_mf_guid(memory, key);
        let Some((vt, bytes)) = mf_attribute_propvariant(mt, key) else {
            state.set(Register::Rax, 0xc00d_36e5);
            return Ok(());
        };
        if result != 0 {
            let value_vt = read_guest_u32(memory, value).unwrap_or(0);
            let value_bytes = memory.read_bytes(value + 8, 64).unwrap_or_default();
            let equal = vt == value_vt
                && (bytes.is_empty()
                    || (value_bytes.len() >= bytes.len()
                        && value_bytes[..bytes.len()] == bytes[..]));
            write_guest_u32(memory, result, u32::from(equal)).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::GetAllocatedString(guidKey, ppwszValue,
    /// pcchLength)` — the task-allocated string copy.
    pub(crate) fn dispatch_mf_attr_get_allocated_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let length = guest_call_arg(state, memory, 3)?;
        let Some(mt) = self.mf_media_types.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let key = read_mf_guid(memory, key);
        let Some(text) = mt.get_string(&key).map(str::to_string) else {
            state.set(Register::Rax, 0xc00d_36e5);
            return Ok(());
        };
        let address = self.alloc_zeroed(memory, text.len() * 2 + 2, 8)?;
        for (i, unit) in text.encode_utf16().enumerate() {
            write_guest_u16(memory, address + (i as u64 * 2), unit).ok();
        }
        write_guest_u16(
            memory,
            address + (text.encode_utf16().count() as u64 * 2),
            0,
        )
        .ok();
        if out != 0 {
            write_guest_pointer(memory, out, address, self.guest_arch).ok();
        }
        if length != 0 {
            write_guest_u32(memory, length, text.encode_utf16().count() as u32).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::GetAllocatedBlob(guidKey, ppBuffer, pcbSize)` — the
    /// task-allocated blob copy.
    pub(crate) fn dispatch_mf_attr_get_allocated_blob(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let size = guest_call_arg(state, memory, 3)?;
        let Some(mt) = self.mf_media_types.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let key = read_mf_guid(memory, key);
        let Some(bytes) = mt.get_blob(&key).map(|b| b.to_vec()) else {
            state.set(Register::Rax, 0xc00d_36e5);
            return Ok(());
        };
        let address = self.alloc_zeroed(memory, bytes.len().max(1), 8)?;
        for (i, byte) in bytes.iter().enumerate() {
            memory.write_u8(address + i as u64, *byte);
        }
        if out != 0 {
            write_guest_pointer(memory, out, address, self.guest_arch).ok();
        }
        if size != 0 {
            write_guest_u32(memory, size, bytes.len() as u32).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::SetItem(guidKey, Value)` — set from a PROPVARIANT.
    pub(crate) fn dispatch_mf_attr_set_item(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = guest_call_arg(state, memory, 1)?;
        let value = guest_call_arg(state, memory, 2)?;
        let Some(mt) = self.mf_media_types.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let key = read_mf_guid(memory, key);
        let vt = read_guest_u32(memory, value).unwrap_or(0);
        let payload = read_guest_pointer(memory, value + 8, self.guest_arch).unwrap_or(0);
        match vt {
            19 => {
                // VT_UI4
                mt.set_uint32(key, payload as u32);
            }
            21 => {
                // VT_UI8
                mt.set_uint64(key, payload);
            }
            5 => {
                // VT_R8
                let bits = read_guest_u64(memory, value + 8).unwrap_or(0);
                mt.set_double(key, f64::from_bits(bits));
            }
            72 => {
                // VT_CLSID
                let guid_bytes = memory.read_bytes(payload, 16).unwrap_or_default();
                mt.set_guid(key, mf_guid_from_bytes(&guid_bytes));
            }
            31 => {
                // VT_LPWSTR
                let text = read_utf16_string(memory, payload).unwrap_or_default();
                mt.set_string(key, text);
            }
            _ => {
                state.set(Register::Rax, 0xc00d_36b4); // MF_E_INVALIDTYPE
                return Ok(());
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::DeleteAllItems()`.
    pub(crate) fn dispatch_mf_attr_delete_all_items(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(mt) = self.mf_media_types.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        mt.delete_all();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::LockStore()` / `UnlockStore()` — the store is
    /// single-threaded in the runtime.
    pub(crate) fn dispatch_mf_attr_lock_store(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::CopyAllItems(pDest)` — copy the attribute store.
    pub(crate) fn dispatch_mf_attr_copy_all_items(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let dest = guest_call_arg(state, memory, 1)?;
        let Some(source) = self.mf_media_types.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let Some(target) = self.mf_media_types.get_mut(&dest) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        for (key, value) in &source.attributes {
            target.attributes.insert(*key, value.clone());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSample::GetSampleFlags(pdwSampleFlags)` / `SetSampleFlags`.
    pub(crate) fn dispatch_mf_sample_get_sample_flags(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(sample) = self.mf_samples.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, sample.flags).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    pub(crate) fn dispatch_mf_sample_set_sample_flags(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let flags = guest_call_arg_u32(state, memory, 1)?;
        let Some(sample) = self.mf_samples.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        sample.flags = flags;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSample::GetTotalLength(pcbTotal)` — the sample's total byte
    /// length.
    pub(crate) fn dispatch_mf_sample_get_total_length(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(sample) = self.mf_samples.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, sample.buffer.len() as u32).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSample::CopyToBuffer(pBuffer)` — copy the sample's bytes into
    /// the target media buffer.
    pub(crate) fn dispatch_mf_sample_copy_to_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let Some(sample) = self.mf_samples.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let Some(target) = self.mf_media_buffers.get_mut(&buffer) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let copy = sample.buffer.len().min(target.max_length as usize);
        target.data = sample.buffer[..copy].to_vec();
        target.current_length = copy as u32;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSample::ConvertToContiguousBuffer(ppBuffer)` — a new buffer
    /// holding the sample's bytes.
    pub(crate) fn dispatch_mf_sample_convert_to_contiguous_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(sample) = self.mf_samples.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let vtable = self.alloc_guest_vtable(memory, mf_media_buffer_methods())?;
        let buffer = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaBuffer, vtable)
            .unwrap_or(0);
        if buffer == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let length = sample.buffer.len() as u32;
        self.mf_media_buffers.insert(
            buffer,
            ImfMediaBuffer {
                data: sample.buffer,
                max_length: length,
                current_length: length,
            },
        );
        if out != 0 {
            write_guest_pointer(memory, out, buffer, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::Compare(pTheirs, pbResult)` — the deep store
    /// comparison.
    pub(crate) fn dispatch_mf_attr_compare(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let theirs = guest_call_arg(state, memory, 1)?;
        let result = guest_call_arg(state, memory, 2)?;
        let Some(mine) = self.mf_media_types.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let Some(other) = self.mf_media_types.get(&theirs) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let equal = mine.attributes == other.attributes;
        if result != 0 {
            write_guest_u32(memory, result, u32::from(equal)).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFAttributes::GetUnknown` / `SetUnknown` — the stores hold no
    /// unknown-valued attributes; the documented not-found/type errors.
    pub(crate) fn dispatch_mf_attr_unknown(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        is_get: bool,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if is_get && out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(
            Register::Rax,
            if is_get {
                0xc00d_36e5 // MF_E_ATTRIBUTENOTFOUND
            } else {
                0xc00d_36b4 // MF_E_INVALIDTYPE
            },
        );
        Ok(())
    }

    // ── The completed interface surfaces ───────────────────────────────────

    /// `IMFMediaSession::SetTopology(dwTopologySetFlags, pTopology)` —
    /// the session's topology state.
    pub(crate) fn dispatch_mf_session_set_topology(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let topology = guest_call_arg(state, memory, 2)?;
        let Some(session) = self.mf_sessions.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if topology == 0 {
            session.clear_topologies();
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        let Some(topo) = self.mf_topologies.get(&topology).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let _ = session.set_topology(topo);
        self.mf_session_topologies.insert(this, topology);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSession::GetSessionCapabilities(pdwCaps)` — the session
    /// supports seek, pause, rate and time.
    pub(crate) fn dispatch_mf_session_get_capabilities(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.mf_sessions.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if out != 0 {
            // MFSESSIONCAP_SEEK | MFSESSIONCAP_PAUSE | MFSESSIONCAP_RATE |
            // MFSESSIONCAP_SEEK | MFSESSIONCAP_DOES_NOT_USE_NETWORK.
            write_guest_u32(memory, out, 0x0000_0001 | 0x0000_0002 | 0x0000_0008).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSession::GetFullTopology(dwGetFlags, dwTopologyId,
    /// ppFullTopology)` — the current topology object.
    pub(crate) fn dispatch_mf_session_get_full_topology(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let _id = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if !self.mf_sessions.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let topology = self.mf_session_topologies.get(&this).copied().unwrap_or(0);
        if topology == 0 {
            state.set(Register::Rax, 0xc00d_3701); // MF_E_INVALIDREQUEST
            return Ok(());
        }
        if out != 0 {
            write_guest_pointer(memory, out, topology, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSession::GetDescriptorFromTopology(pTopology,
    /// ppPresentationDescriptor)` — no presentation descriptor is attached.
    /// `IMFSession::GetDescriptorFromTopology(pTopology, ppPD)` — the real
    /// presentation descriptor of the media source wired into the topology
    /// graph; `MF_E_UNSUPPORTED_REPRESENTATION` when no source node carries a
    /// media source.
    pub(crate) fn dispatch_mf_session_get_descriptor_from_topology(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let topology = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if !self.mf_topologies.contains_key(&topology) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let source = self.mf_topology_source_objects().into_iter().next();
        let Some(source) = source else {
            if out != 0 {
                write_guest_pointer(memory, out, 0, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_REPRESENTATION));
            return Ok(());
        };
        let Some(presentation) = self
            .mf_media_sources
            .get(&source)
            .map(|source| source.presentation().clone())
        else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let descriptor = self.alloc_mf_presentation_descriptor_object(memory, &presentation)?;
        if descriptor == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        if out != 0 {
            write_guest_pointer(memory, out, descriptor, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// The guest IMFMediaSource objects wired into topology nodes (the
    /// topology side of the source graph).
    fn mf_topology_source_objects(&self) -> Vec<u64> {
        let mut sources: Vec<u64> = self
            .mf_topology_nodes
            .values()
            .map(|node| node.object)
            .filter(|object| self.mf_media_sources.contains_key(object))
            .collect();
        sources.sort_unstable();
        sources.dedup();
        sources
    }

    /// `IMFSinkWriter::SetInputMediaType(dwStreamIndex, pInputMediaType,
    /// pEncodingParameters)` — the stream's input type.
    pub(crate) fn dispatch_mf_sink_writer_set_input_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let type_ptr = guest_call_arg(state, memory, 2)?;
        let _params = guest_call_arg(state, memory, 3)?;
        let Some(mt) = self.mf_media_types.get(&type_ptr).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(sink) = self.mf_sink_writers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        sink.set_input_type(mt);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSinkWriter::Flush(dwStreamIndex)` — the pending data is
    /// committed.
    pub(crate) fn dispatch_mf_sink_writer_flush(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        if !self.mf_sink_writers.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSinkWriter::GetStatistics(dwStreamIndex, pStats)` — the frame
    /// count + the byte count.
    pub(crate) fn dispatch_mf_sink_writer_get_statistics(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let stats = guest_call_arg(state, memory, 2)?;
        let frame_count = self
            .mf_sink_writers
            .get(&this)
            .map(|sink| sink.current_frame_count())
            .unwrap_or(0);
        if stats != 0 {
            // The MF_SINK_WRITER_STATISTICS: cb(0), llLastTimestampReceived(8),
            // llLastTimestampEncoded(16), llLastTimestampProcessed(24),
            // llLastStreamProcessed(32), llCurrentMemoryUsage(40),
            // dwNumberOfFramesWritten(48), dwNumberOfSamplesWritten(52),
            // dwNumberOfEncodedFrames(56), dwNumberOfProcessedFrames(60),
            // dwNumberOfStreamTransitions(64).
            write_guest_u64(memory, stats, 80).ok();
            write_guest_u64(memory, stats + 8, 0).ok();
            write_guest_u64(memory, stats + 16, 0).ok();
            write_guest_u64(memory, stats + 24, 0).ok();
            write_guest_u64(memory, stats + 32, 0).ok();
            write_guest_u64(memory, stats + 40, 0).ok();
            write_guest_u32(memory, stats + 48, frame_count as u32).ok();
            write_guest_u32(memory, stats + 52, frame_count as u32).ok();
            write_guest_u32(memory, stats + 56, 0).ok();
            write_guest_u32(memory, stats + 60, 0).ok();
            write_guest_u32(memory, stats + 64, 0).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSinkWriter::GetServiceForStream` / `NotifyEndOfSegment` —
    /// the stream service is not exposed; the segment notification ends the
    /// stream.
    pub(crate) fn dispatch_mf_sink_writer_service(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, 0xc00d_36c4); // MF_E_INVALID_STREAM_DATA
        Ok(())
    }

    /// `IDispatch::GetTypeInfoCount(pctinfo)` — no typeinfo.
    pub(crate) fn dispatch_idispatch_get_type_info_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_guest_u32(memory, out, 0).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IDispatch::GetTypeInfo(iTInfo, lcid, ppTInfo)` — no typeinfo
    /// exists.
    pub(crate) fn dispatch_idispatch_get_type_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _index = guest_call_arg_u32(state, memory, 1)?;
        let _lcid = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, 0x8002_802b); // TYPE_E_ELEMENTNOTFOUND
        Ok(())
    }

    /// `IMFMediaSource::GetCharacteristics(pdwCharacteristics)` — the real
    /// characteristics of the parsed file presentation (seekable/pausable
    /// local source; never live).
    pub(crate) fn dispatch_mf_media_source_get_characteristics(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(source) = self.mf_media_sources.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, source.characteristics()).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// Allocate a guest IMFPresentationDescriptor object over a presentation
    /// descriptor.  The object also carries the descriptor's real
    /// `IMFAttributes` store (MF_PD_DURATION / MF_PD_SEEKABLE / ...).
    fn alloc_mf_presentation_descriptor_object(
        &mut self,
        memory: &mut MemoryImage,
        presentation: &crate::media::MfPresentationDescriptor,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_presentation_descriptor_methods())?;
        let descriptor = self
            .alloc_guest_object(memory, GuestObjectKind::ImfPresentationDescriptor, vtable)
            .unwrap_or(0);
        if descriptor == 0 {
            return Ok(0);
        }
        self.mf_presentation_descriptors
            .insert(descriptor, presentation.clone());
        self.mf_media_types
            .insert(descriptor, presentation.attributes());
        Ok(descriptor)
    }

    /// Allocate a guest IMFMediaEvent object carrying an exact MF event
    /// number, status and value.
    fn alloc_mf_event_object(
        &mut self,
        memory: &mut MemoryImage,
        mf_type: u32,
        status: u32,
        value: u64,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_event_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaEvent, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        self.mf_media_events.insert(
            object,
            crate::runtime::state::MfMediaEventState {
                event_type: mf_type,
                status,
                value,
            },
        );
        self.mf_media_types
            .insert(object, crate::media::ImfMediaType::new());
        Ok(object)
    }

    /// `IMFMediaSource::CreatePresentationDescriptor(ppPD)` — a real copy of
    /// the source's parsed presentation descriptor.
    pub(crate) fn dispatch_mf_media_source_create_presentation_descriptor(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some(source) = self.mf_media_sources.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let presentation = source.presentation().clone();
        let descriptor = self.alloc_mf_presentation_descriptor_object(memory, &presentation)?;
        if descriptor == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, descriptor, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// The position from an `IMFMediaSource::Start` PROPVARIANT: null and
    /// VT_EMPTY start at zero, VT_I8 is the 100-ns time, and
    /// PRESENTATION_CURRENT_POSITION keeps the current position.
    fn mf_start_position(
        &self,
        memory: &MemoryImage,
        start_position: u64,
        current: u64,
    ) -> Option<u64> {
        if start_position == 0 {
            return Some(0);
        }
        let vt = read_guest_u32(memory, start_position).unwrap_or(0);
        match vt {
            0 => Some(0), // VT_EMPTY
            20 => {
                // VT_I8
                let value = read_guest_u64(memory, start_position + 8).unwrap_or(0) as i64;
                if value == i64::MAX {
                    Some(current) // PRESENTATION_CURRENT_POSITION
                } else if value < 0 {
                    None
                } else {
                    Some(value as u64)
                }
            }
            _ => None,
        }
    }

    /// `IMFMediaSource::Start(pPD, pguidTimeFormat, pvarStartPosition)` —
    /// the real state transition: applies the descriptor's stream selection,
    /// seeks the attached source readers, then queues
    /// MESourceStarted/MEStreamStarted (or MESourceSeeked on a re-start).
    pub(crate) fn dispatch_mf_media_source_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let descriptor = guest_call_arg(state, memory, 1)?;
        let time_format = guest_call_arg(state, memory, 2)?;
        let start_position = guest_call_arg(state, memory, 3)?;
        let Some(source) = self.mf_media_sources.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if source.state() == crate::media::MfSourceState::Shutdown {
            state.set(Register::Rax, u64::from(MF_E_SHUTDOWN));
            return Ok(());
        }
        // Only GUID_NULL (or a null pointer) time format is backed: the
        // position is a 100-ns presentation time.
        if time_format != 0 {
            let bytes = memory.read_bytes(time_format, 16).unwrap_or_default();
            if bytes.iter().any(|byte| *byte != 0) {
                state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_TIME_FORMAT));
                return Ok(());
            }
        }
        let current = source.position();
        let Some(position) = self.mf_start_position(memory, start_position, current) else {
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_TIME_FORMAT));
            return Ok(());
        };
        // A guest presentation descriptor selects the streams the source
        // will play.
        if descriptor != 0 {
            let Some(pd) = self.mf_presentation_descriptors.get(&descriptor).cloned() else {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            };
            if let Some(source) = self.mf_media_sources.get_mut(&this) {
                for (index, stream) in pd.streams.iter().enumerate() {
                    source
                        .presentation_mut()
                        .set_stream_selected(index, stream.selected);
                }
            }
        }
        let readers = self
            .mf_media_sources
            .get(&this)
            .map(|source| source.readers().to_vec())
            .unwrap_or_default();
        for reader in readers {
            if let Some(reader) = self.mf_source_readers.get_mut(&reader) {
                reader.set_current_position(position);
            }
        }
        let Some(source) = self.mf_media_sources.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if source.start(Some(position)).is_err() {
            state.set(Register::Rax, u64::from(MF_E_INVALIDREQUEST));
            return Ok(());
        }
        // Real state change: complete parked BeginGetEvent requests with the
        // queued MESourceStarted/MENewStream/MEStreamStarted (or Seeked)
        // events.
        self.mf_source_pump_events(this, memory, false)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSource::Stop` — the real transition and events.
    pub(crate) fn dispatch_mf_media_source_stop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(source) = self.mf_media_sources.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        match source.stop() {
            Ok(()) => {
                self.mf_source_pump_events(this, memory, false)?;
                state.set(Register::Rax, u64::from(S_OK))
            }
            Err(_) => state.set(Register::Rax, u64::from(MF_E_SHUTDOWN)),
        }
        Ok(())
    }

    /// `IMFMediaSource::Pause` — the real transition and events.
    pub(crate) fn dispatch_mf_media_source_pause(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(source) = self.mf_media_sources.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        match source.pause() {
            Ok(()) => {
                self.mf_source_pump_events(this, memory, false)?;
                state.set(Register::Rax, u64::from(S_OK))
            }
            Err(_) => state.set(Register::Rax, u64::from(MF_E_INVALIDREQUEST)),
        }
        Ok(())
    }

    /// `IMFMediaSource::Shutdown` — the source moves to the terminal state
    /// (the guest object is released by the guest; the object stays alive
    /// until its last reference drops).
    pub(crate) fn dispatch_mf_media_source_shutdown(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(source) = self.mf_media_sources.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        source.shutdown();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaEventGenerator::GetEvent` on a media source — pulls the next
    /// real source event (the MESource*/MEStream*/MENewStream/
    /// MEEndOfPresentation sequence).
    pub(crate) fn dispatch_mf_media_source_get_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(source) = self.mf_media_sources.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if source.state() == crate::media::MfSourceState::Shutdown {
            state.set(Register::Rax, u64::from(MF_E_SHUTDOWN));
            return Ok(());
        }
        let Some(event) = source.get_event() else {
            state.set(Register::Rax, u64::from(MF_E_NO_EVENTS_AVAILABLE));
            return Ok(());
        };
        let value = event.pts.unwrap_or(0);
        let object =
            self.alloc_mf_event_object(memory, event.mf_type, event.status as u32, value)?;
        if object == 0 && out != 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaEventGenerator::BeginGetEvent` — parks the guest request on
    /// the MF async callback pump.  When a real event is already queued the
    /// call completes synchronously (`S_OK`, no callback — Windows contract);
    /// otherwise it returns `E_PENDING` and the callback's `Invoke` fires
    /// from the runtime servicing point
    /// ([`Self::drain_pending_mf_async_completions`]) once a real source
    /// state change (Start/Stop/Pause/seek) or the real end of file queues
    /// an event.
    pub(crate) fn dispatch_mf_media_source_begin_get_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let callback = guest_call_arg(state, memory, 1)?;
        let state_object = guest_call_arg(state, memory, 2)?;
        let Some(source) = self.mf_media_sources.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if source.state() == crate::media::MfSourceState::Shutdown {
            state.set(Register::Rax, u64::from(MF_E_SHUTDOWN));
            return Ok(());
        }
        if crate::media::has_mf_parked_request(
            self.guest_pid,
            this,
            crate::media::MfAsyncOp::GetEvent,
        ) {
            // A Begin is already parked for this source (the guest must
            // consume it with EndGetEvent/CancelGetEvent first).
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let callback_method = if callback != 0 {
            let Some(method) = self.mf_async_callback_method(memory, callback) else {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            };
            method
        } else {
            0
        };
        crate::media::park_mf_request(
            self.guest_pid,
            crate::media::MfParkedRequest {
                owner: this,
                op: crate::media::MfAsyncOp::GetEvent,
                callback_object: callback,
                callback_method,
                state_object,
            },
        );
        // Events already on the real queue complete synchronously; the
        // completion is recorded for EndGetEvent but the callback is not
        // invoked (Windows S_OK contract).
        if self.mf_source_pump_events(this, memory, true)? {
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_PENDING));
        }
        Ok(())
    }

    /// `IMFMediaEventGenerator::EndGetEvent` — retrieves the real event a
    /// completed `BeginGetEvent` produced (the event object was materialised
    /// when the event was queued, so this never allocates new state).
    pub(crate) fn dispatch_mf_media_source_end_get_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let result = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if !self.mf_media_sources.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let Some(completion) = crate::media::take_mf_result(self.guest_pid, result) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if completion.op != crate::media::MfAsyncOp::GetEvent || completion.event_object == 0 {
            // Not a GetEvent result: re-record it so its own EndX still
            // retrieves it, and reject the wrong completion.
            crate::media::record_mf_result(self.guest_pid, completion);
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if out != 0 {
            write_guest_pointer(memory, out, completion.event_object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `CancelGetEvent` — drops the parked `BeginGetEvent` request so its
    /// callback never fires.  `S_OK` when a request was pending, `S_FALSE`
    /// when there was nothing to cancel.
    pub(crate) fn dispatch_mf_media_source_cancel_get_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if !self.mf_media_sources.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let cancelled = crate::media::take_mf_parked_request(
            self.guest_pid,
            this,
            crate::media::MfAsyncOp::GetEvent,
        )
        .is_some();
        state.set(
            Register::Rax,
            u64::from(if cancelled { S_OK } else { S_FALSE }),
        );
        Ok(())
    }

    /// Resolve an `IMFAsyncCallback` object's `Invoke` entry point (vtable
    /// slot 4: QueryInterface, AddRef, Release, GetParameters, Invoke).
    fn mf_async_callback_method(&self, memory: &MemoryImage, callback: u64) -> Option<u64> {
        let pointer_bytes = self.guest_arch.pointer_bytes() as u64;
        let vtable = read_guest_pointer(memory, callback, self.guest_arch).ok()?;
        let method =
            read_guest_pointer(memory, vtable + 4 * pointer_bytes, self.guest_arch).ok()?;
        (method != 0).then_some(method)
    }

    /// Complete parked `BeginGetEvent` requests from the source's real event
    /// queue: while a request is parked and the source has a real event, the
    /// event becomes a guest `IMFMediaEvent` object and a real
    /// `IMFAsyncResult` is recorded.  `synchronous` marks a completion that
    /// happened inside `BeginGetEvent` itself (`S_OK`): the callback is not
    /// queued, only the result for `EndGetEvent`.
    fn mf_source_pump_events(
        &mut self,
        this: u64,
        memory: &mut MemoryImage,
        synchronous: bool,
    ) -> AppResult<bool> {
        let pid = self.guest_pid;
        let mut completed = false;
        loop {
            if !crate::media::has_mf_parked_request(pid, this, crate::media::MfAsyncOp::GetEvent) {
                break;
            }
            let Some(event) = self
                .mf_media_sources
                .get_mut(&this)
                .and_then(crate::media::MfMediaSource::get_event)
            else {
                break;
            };
            let Some(request) =
                crate::media::take_mf_parked_request(pid, this, crate::media::MfAsyncOp::GetEvent)
            else {
                break;
            };
            let value = event.pts.unwrap_or(0);
            let event_object =
                self.alloc_mf_event_object(memory, event.mf_type, event.status as u32, value)?;
            let result = self.alloc_mf_async_result(memory, request.state_object, S_OK)?;
            let mut completion = crate::media::MfAsyncCompletion {
                owner: this,
                op: crate::media::MfAsyncOp::GetEvent,
                result,
                status: S_OK,
                callback_object: request.callback_object,
                callback_method: request.callback_method,
                state_object: request.state_object,
                event_object,
                bytes: 0,
            };
            if synchronous {
                completion.callback_object = 0;
                completion.callback_method = 0;
                crate::media::record_mf_result(pid, completion);
            } else {
                crate::media::complete_mf_request(pid, completion);
            }
            completed = true;
        }
        Ok(completed)
    }

    /// Deliver the queued MF asynchronous completions of this process: each
    /// completion's `IMFAsyncCallback::Invoke` is invoked in guest context
    /// with the real `IMFAsyncResult`.  Runs only from the runtime servicing
    /// points (the block-dispatch safepoint and the message-loop idle drain)
    /// and from tests that poll for completion — never inline inside the
    /// Begin call that parked the request.
    pub(crate) fn drain_pending_mf_async_completions(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        while let Some(completion) = crate::media::pop_mf_completion(self.guest_pid) {
            if completion.callback_method == 0 {
                continue;
            }
            self.execute_guest_callback(
                state,
                memory,
                completion.callback_method,
                &[completion.callback_object, completion.result],
                "MFAsyncCallback::Invoke",
            )?;
        }
        Ok(())
    }

    /// `IMFMediaEventGenerator::QueueEvent` on a media source — the
    /// guest-supplied event number is queued and round-trips through
    /// `IMFMediaEvent::GetType`.
    pub(crate) fn dispatch_mf_media_source_queue_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let mf_type = guest_call_arg_u32(state, memory, 1)?;
        let _extended = guest_call_arg(state, memory, 2)?;
        let _status = guest_call_arg_u32(state, memory, 3)?;
        let _value = guest_call_arg(state, memory, 4)?;
        let Some(source) = self.mf_media_sources.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        source.queue_event_number(mf_type);
        self.mf_source_pump_events(this, memory, false)?;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSourceEx::GetSourceAttributes(ppAttributes)` — a fresh
    /// IMFAttributes store for the source (empty: the source exposes no
    /// additional source attributes beyond the presentation descriptor).
    pub(crate) fn dispatch_mf_media_source_get_source_attributes(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.mf_media_sources.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_attributes_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_media_types
            .insert(object, crate::media::ImfMediaType::new());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSourceEx::GetStreamAttributes(dwStreamID, ppAttributes)` —
    /// a fresh attribute store for a real presentation stream.
    pub(crate) fn dispatch_mf_media_source_get_stream_attributes(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream_id = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(source) = self.mf_media_sources.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if !source
            .presentation()
            .streams
            .iter()
            .any(|stream| stream.identifier == stream_id)
        {
            state.set(Register::Rax, 0xc00d_36b3); // MF_E_INVALIDSTREAMNUMBER
            return Ok(());
        }
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_attributes_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_media_types
            .insert(object, crate::media::ImfMediaType::new());
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSourceEx::SetD3DManager(pManager)` — the manager pointer is
    /// retained on the source for the (currently absent) hardware decode
    /// path; the software source accepts it like Windows does.
    pub(crate) fn dispatch_mf_media_source_set_d3d_manager(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let manager = guest_call_arg(state, memory, 1)?;
        if !self.mf_media_sources.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        self.mf_source_d3d_managers.insert(this, manager);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// The async source-resolver entry points: the resolver is synchronous
    /// in the runtime; the async begins answer the pending-object contract.
    pub(crate) fn dispatch_mf_source_resolver_begin(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, u64::from(E_NOTIMPL));
        Ok(())
    }

    /// Allocate a guest IMFStreamDescriptor object over a real stream
    /// descriptor (with its IMFAttributes store).
    fn alloc_mf_stream_descriptor_object(
        &mut self,
        memory: &mut MemoryImage,
        stream: &crate::media::MfStreamDescriptor,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_stream_descriptor_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfStreamDescriptor, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        self.mf_stream_descriptors.insert(object, stream.clone());
        self.mf_media_types
            .insert(object, stream.attributes.clone());
        Ok(object)
    }

    /// Allocate a guest IMFMediaTypeHandler object over a real handler
    /// state.
    fn alloc_mf_media_type_handler_object(
        &mut self,
        memory: &mut MemoryImage,
        handler: crate::media::MfMediaTypeHandlerState,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_media_type_handler_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaTypeHandler, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        self.mf_media_type_handlers.insert(object, handler);
        Ok(object)
    }

    /// Allocate a guest IMFMediaType object over a media type.
    fn alloc_mf_media_type_object(
        &mut self,
        memory: &mut MemoryImage,
        media_type: crate::media::ImfMediaType,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_media_type_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        self.mf_media_types.insert(object, media_type);
        Ok(object)
    }

    /// `IMFPresentationDescriptor::GetStreamDescriptorCount(pcStreams)`.
    pub(crate) fn dispatch_mf_presentation_descriptor_get_stream_descriptor_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(descriptor) = self.mf_presentation_descriptors.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out != 0 {
            write_u32(memory, out, descriptor.streams.len() as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFPresentationDescriptor::GetStreamDescriptorByIndex(index,
    /// pfSelected, ppDescriptor)` — a real stream descriptor for the parsed
    /// stream at `index`.
    pub(crate) fn dispatch_mf_presentation_descriptor_get_stream_descriptor_by_index(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let selected_out = guest_call_arg(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        let Some(stream) = self
            .mf_presentation_descriptors
            .get(&this)
            .and_then(|descriptor| descriptor.streams.get(index as usize))
            .cloned()
        else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if selected_out != 0 {
            write_u32(memory, selected_out, u32::from(stream.selected));
        }
        let object = self.alloc_mf_stream_descriptor_object(memory, &stream)?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFPresentationDescriptor::SelectStream(index)`.
    pub(crate) fn dispatch_mf_presentation_descriptor_select_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_mf_presentation_descriptor_set_stream(state, memory, true)
    }

    /// `IMFPresentationDescriptor::DeselectStream(index)`.
    pub(crate) fn dispatch_mf_presentation_descriptor_deselect_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_mf_presentation_descriptor_set_stream(state, memory, false)
    }

    fn dispatch_mf_presentation_descriptor_set_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        selected: bool,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let Some(descriptor) = self.mf_presentation_descriptors.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if descriptor.set_stream_selected(index as usize, selected) {
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
        }
        Ok(())
    }

    /// `IMFPresentationDescriptor::Clone(ppDescriptor)` — a deep copy of the
    /// real descriptor (including the stream selection).
    pub(crate) fn dispatch_mf_presentation_descriptor_clone(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(descriptor) = self.mf_presentation_descriptors.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let object = self.alloc_mf_presentation_descriptor_object(memory, &descriptor)?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFStreamDescriptor::GetStreamIdentifier(pdwStreamIdentifier)`.
    pub(crate) fn dispatch_mf_stream_descriptor_get_stream_identifier(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(stream) = self.mf_stream_descriptors.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out != 0 {
            write_u32(memory, out, stream.identifier);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFStreamDescriptor::GetMediaTypeHandler(ppHandler)` — the real
    /// handler over the stream's parsed native type.
    pub(crate) fn dispatch_mf_stream_descriptor_get_media_type_handler(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(stream) = self.mf_stream_descriptors.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let handler = crate::media::MfMediaTypeHandlerState::new(stream.media_type);
        let object = self.alloc_mf_media_type_handler_object(memory, handler)?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaTypeHandler::IsMediaTypeSupported(pType, ppMediaType)` — a
    /// candidate with the stream's major type is supported.
    pub(crate) fn dispatch_mf_media_type_handler_is_media_type_supported(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let type_ptr = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(handler) = self.mf_media_type_handlers.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(candidate) = self.mf_media_types.get(&type_ptr) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(
            Register::Rax,
            u64::from(if handler.is_type_supported(candidate) {
                S_OK
            } else {
                MF_E_INVALIDMEDIATYPE
            }),
        );
        Ok(())
    }

    /// `IMFMediaTypeHandler::GetMediaTypeCount(pdwTypeCount)`.
    pub(crate) fn dispatch_mf_media_type_handler_get_media_type_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(handler) = self.mf_media_type_handlers.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out != 0 {
            write_u32(memory, out, handler.available.len() as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaTypeHandler::GetMediaTypeByIndex(index, ppType)`.
    pub(crate) fn dispatch_mf_media_type_handler_get_media_type_by_index(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(media_type) = self
            .mf_media_type_handlers
            .get(&this)
            .and_then(|handler| handler.available.get(index as usize))
            .cloned()
        else {
            state.set(Register::Rax, u64::from(MF_E_NO_MORE_TYPES));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let object = self.alloc_mf_media_type_object(memory, media_type)?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaTypeHandler::SetCurrentMediaType(pType)`.
    pub(crate) fn dispatch_mf_media_type_handler_set_current_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let type_ptr = guest_call_arg(state, memory, 1)?;
        let Some(candidate) = self.mf_media_types.get(&type_ptr).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(handler) = self.mf_media_type_handlers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if handler.is_type_supported(&candidate) {
            handler.current = candidate;
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(MF_E_INVALIDMEDIATYPE));
        }
        Ok(())
    }

    /// `IMFMediaTypeHandler::GetCurrentMediaType(ppType)`.
    pub(crate) fn dispatch_mf_media_type_handler_get_current_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(media_type) = self
            .mf_media_type_handlers
            .get(&this)
            .map(|handler| handler.current.clone())
        else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let object = self.alloc_mf_media_type_object(memory, media_type)?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaTypeHandler::GetMajorType(pguidMajorType)`.
    pub(crate) fn dispatch_mf_media_type_handler_get_major_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(major) = self
            .mf_media_type_handlers
            .get(&this)
            .and_then(|handler| handler.current.get_guid(&crate::media::MF_MT_MAJOR_TYPE))
        else {
            state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND));
            return Ok(());
        };
        if out != 0 {
            write_guest_guid(memory, out, major);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSourceReader::GetStreamSelection(index, pfSelected)`.
    pub(crate) fn dispatch_mf_source_reader_get_stream_selection(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(reader) = self.mf_source_readers.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(track) = reader.resolve_stream_index(index) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out != 0 {
            write_u32(memory, out, u32::from(reader.get_stream_selection(track)));
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSourceReader::SetStreamSelection(index, selected)`.
    pub(crate) fn dispatch_mf_source_reader_set_stream_selection(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let selected = guest_call_arg_u32(state, memory, 2)?;
        let Some(reader) = self.mf_source_readers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        reader.set_stream_selection(index, selected != 0);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSourceReader::SetCurrentMediaType(index, pdwReserved, pType)`.
    pub(crate) fn dispatch_mf_source_reader_set_current_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let _reserved = guest_call_arg(state, memory, 2)?;
        let type_ptr = guest_call_arg(state, memory, 3)?;
        let Some(media_type) = self.mf_media_types.get(&type_ptr).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(reader) = self.mf_source_readers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(track) = reader.resolve_stream_index(index) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        match reader.set_current_media_type(track, &media_type) {
            Ok(()) => state.set(Register::Rax, u64::from(S_OK)),
            Err(_) => state.set(Register::Rax, u64::from(MF_E_INVALIDMEDIATYPE)),
        }
        Ok(())
    }

    /// `IMFSourceReader::SetCurrentPosition(guidTimeFormat, pvarPosition)`.
    pub(crate) fn dispatch_mf_source_reader_set_current_position(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let time_format = guest_call_arg(state, memory, 1)?;
        let position = guest_call_arg(state, memory, 2)?;
        if time_format != 0 {
            let bytes = memory.read_bytes(time_format, 16).unwrap_or_default();
            if bytes.iter().any(|byte| *byte != 0) {
                state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_TIME_FORMAT));
                return Ok(());
            }
        }
        let Some(position) = self.mf_start_position(memory, position, 0) else {
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_TIME_FORMAT));
            return Ok(());
        };
        let Some(reader) = self.mf_source_readers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        reader.set_current_position(position);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSourceReader::Flush(index)` — the reader holds no queued samples;
    /// the flush is the real no-buffered-data contract.
    pub(crate) fn dispatch_mf_source_reader_flush(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _index = guest_call_arg_u32(state, memory, 1)?;
        if !self.mf_source_readers.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFSourceReader::GetServiceForStream` — resolves the reader's real
    /// source through `MF_MEDIASOURCE_SERVICE`.
    pub(crate) fn dispatch_mf_source_reader_get_service_for_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _index = guest_call_arg_u32(state, memory, 1)?;
        let service_ptr = guest_call_arg(state, memory, 2)?;
        let iid_ptr = guest_call_arg(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        let Some(reader) = self.mf_source_readers.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let source = reader.source();
        if source == 0 || !self.mf_media_sources.contains_key(&source) {
            state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
            return Ok(());
        }
        let mut service = [0_u8; 16];
        let service_bytes = memory.read_bytes(service_ptr, 16).unwrap_or_default();
        service.copy_from_slice(&service_bytes[..service_bytes.len().min(16)]);
        let mut iid = [0_u8; 16];
        let iid_bytes = memory.read_bytes(iid_ptr, 16).unwrap_or_default();
        iid.copy_from_slice(&iid_bytes[..iid_bytes.len().min(16)]);
        if service == SERVICE_MF_MEDIASOURCE
            && (iid == IID_IMF_MEDIA_SOURCE
                || iid == IID_IMF_MEDIA_SOURCE_EX
                || iid == IID_IUNKNOWN)
        {
            self.add_ref_guest_object(source)?;
            if out != 0 {
                write_guest_pointer(memory, out, source, self.guest_arch).ok();
            }
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
        Ok(())
    }

    /// `IMFSourceReader::GetPresentationAttribute(index, guidAttribute,
    /// pvarAttribute)` — the real presentation attributes of the reader's
    /// source (duration/seekable/file size).
    pub(crate) fn dispatch_mf_source_reader_get_presentation_attribute(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _index = guest_call_arg_u32(state, memory, 1)?;
        let key = read_mf_guid(memory, guest_call_arg(state, memory, 2)?);
        let out = guest_call_arg(state, memory, 3)?;
        let Some(reader) = self.mf_source_readers.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let source = reader.source();
        let Some(presentation) = self
            .mf_media_sources
            .get(&source)
            .map(|source| source.presentation().clone())
        else {
            state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND));
            return Ok(());
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if key == crate::media::MF_PD_DURATION {
            write_guest_u32(memory, out, 21).ok(); // VT_UI8
            write_guest_u64(memory, out + 8, presentation.duration).ok();
        } else if key == crate::media::MF_PD_SEEKABLE {
            write_guest_u32(memory, out, 19).ok(); // VT_UI4
            write_guest_u32(memory, out + 8, u32::from(presentation.seekable)).ok();
        } else if key == crate::media::MF_PD_TOTAL_FILE_SIZE {
            write_guest_u32(memory, out, 21).ok();
            write_guest_u64(memory, out + 8, presentation.file_size).ok();
        } else {
            state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// The MFT stream-attribute methods: the transform's per-stream
    /// attribute stores.
    pub(crate) fn dispatch_mft_stream_attributes(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_attributes_methods())?;
        let store = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if store == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_media_types
            .insert(store, crate::media::ImfMediaType::new());
        if out != 0 {
            write_guest_pointer(memory, out, store, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::DeleteInputStream` / `AddInputStreams` /
    /// `SetOutputBounds` — the stream-count is fixed at 1/1.
    pub(crate) fn dispatch_mft_fixed_streams(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        state.set(Register::Rax, 0xc00d_36d4); // MF_E_INVALIDSTREAMNUMBER
        Ok(())
    }

    /// `IMFTransform::ProcessEvent` — the transform consumes no events.
    pub(crate) fn dispatch_mft_process_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── The MFT surface ────────────────────────────────────────────────────

    /// `IMFActivate::ActivateObject(riid, ppv)` — create the transform.
    pub(crate) fn dispatch_mf_activate_activate_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _riid = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if !self.mf_activates.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mft_transform_methods())?;
        let transform = self
            .alloc_guest_object(memory, GuestObjectKind::MftTransform, vtable)
            .unwrap_or(0);
        if transform == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_transforms
            .insert(transform, MftTransformState::default());
        if out != 0 {
            write_guest_pointer(memory, out, transform, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFActivate::GetGUID(guidKey, guidValue)` — the transform CLSID.
    pub(crate) fn dispatch_mf_activate_get_guid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _key = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if !self.mf_activates.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if out != 0 {
            memory.map_bytes(out, &MFT_CASA1_VIDEO_DECODER_CLSID);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFActivate::GetString(stringKey, pwszValue, cchBufSize,
    /// pchLen)` — the friendly name.
    pub(crate) fn dispatch_mf_activate_get_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _key = guest_call_arg(state, memory, 1)?;
        let buffer = guest_call_arg(state, memory, 2)?;
        let capacity = guest_call_arg_u32(state, memory, 3)?;
        let length = guest_call_arg(state, memory, 4)?;
        if !self.mf_activates.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let name = "Casa1 Video Decoder MFT";
        let units = name.encode_utf16().count() as u32;
        if buffer != 0 {
            if capacity < units + 1 {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
            for (i, unit) in name.encode_utf16().enumerate() {
                write_guest_u16(memory, buffer + (i as u64 * 2), unit).ok();
            }
            write_guest_u16(memory, buffer + (units as u64 * 2), 0).ok();
        }
        if length != 0 {
            write_guest_u32(memory, length, units).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFActivate::ShutdownObject()` — the activation is released.
    pub(crate) fn dispatch_mf_activate_shutdown_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        self.mf_activates.remove(&this);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFActivate::GetCount(pcItems)` — the activation attribute count.
    pub(crate) fn dispatch_mf_activate_get_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.mf_activates.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if out != 0 {
            write_guest_u32(memory, out, 1).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFActivate::GetItem(guidKey, pValue)` — the MFT_TRANSFORM_CLSID
    /// item.
    pub(crate) fn dispatch_mf_activate_get_item(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _key = guest_call_arg(state, memory, 1)?;
        let value = guest_call_arg(state, memory, 2)?;
        if !self.mf_activates.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if value != 0 {
            write_guest_u32(memory, value, 0x2000).ok(); // VT_CLSID
            memory.map_bytes(value + 8, &MFT_CASA1_VIDEO_DECODER_CLSID);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    fn mft_media_type_supported(mt: &crate::media::ImfMediaType) -> bool {
        let Some(major) = mt.get_guid(&crate::media::MF_MT_MAJOR_TYPE) else {
            return false;
        };
        if major != crate::media::MFMediaType_Video {
            return false;
        }
        let Some(subtype) = mt.get_guid(&crate::media::MF_MT_SUBTYPE) else {
            return false;
        };
        matches!(
            subtype,
            crate::media::MFVideoFormat_H264
                | crate::media::MFVideoFormat_H265
                | crate::media::MFVideoFormat_VP90
                | crate::media::MFVideoFormat_WMV3
                | crate::media::MFVideoFormat_NV12
        )
    }

    /// `IMFTransform::GetStreamLimits(pInputMinimum, pInputMaximum,
    /// pOutputMinimum, pOutputMaximum)` — 1/1/1/1.
    pub(crate) fn dispatch_mf_transform_get_stream_limits(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let input_min = guest_call_arg(state, memory, 1)?;
        let input_max = guest_call_arg(state, memory, 2)?;
        let output_min = guest_call_arg(state, memory, 3)?;
        let output_max = guest_call_arg(state, memory, 4)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        for (slot, value) in [
            (input_min, 1_u32),
            (input_max, 1),
            (output_min, 1),
            (output_max, 1),
        ] {
            if slot != 0 {
                write_guest_u32(memory, slot, value).ok();
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::GetStreamCounts(pcInputStreams, pcOutputStreams)`.
    pub(crate) fn dispatch_mf_transform_get_stream_counts(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let inputs = guest_call_arg(state, memory, 1)?;
        let outputs = guest_call_arg(state, memory, 2)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if inputs != 0 {
            write_guest_u32(memory, inputs, 1).ok();
        }
        if outputs != 0 {
            write_guest_u32(memory, outputs, 1).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::GetStreamIDs(dwInputIDArraySize, pdwInputIDs,
    /// dwOutputIDArraySize, pdwOutputIDs)`.
    pub(crate) fn dispatch_mf_transform_get_stream_ids(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let input_size = guest_call_arg_u32(state, memory, 1)?;
        let input_ids = guest_call_arg(state, memory, 2)?;
        let output_size = guest_call_arg_u32(state, memory, 3)?;
        let output_ids = guest_call_arg(state, memory, 4)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if input_size < 1 || output_size < 1 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        write_guest_u32(memory, input_ids, 0).ok();
        write_guest_u32(memory, output_ids, 0).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::GetStreamInfo(dwStreamID, pStreamInfo)` — the whole
    /// samples stream info.
    pub(crate) fn dispatch_mf_transform_get_stream_info(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let info = guest_call_arg(state, memory, 2)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        if info != 0 {
            // MFT_STREAM_INFO: hnsMaxLatency(0), dwFlags(8),
            // cbSize(12), cbMaxLookahead(16), cbAlignment(20),
            // pguidMajorType(24), pguidMinorType(32), pMediaType(40).
            write_guest_u32(memory, info + 8, 0x1).ok(); // WHOLE_SAMPLES
            let major = self.mft_video_major_type_scratch(memory)?;
            write_guest_pointer(memory, info + 24, major, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// The guest-resident video major-type GUID.
    fn mft_video_major_type_scratch(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let address = self.alloc_zeroed(memory, 32, 8)?;
        let guid = crate::media::MFMediaType_Video;
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&guid.data1.to_le_bytes());
        bytes.extend_from_slice(&guid.data2.to_le_bytes());
        bytes.extend_from_slice(&guid.data3.to_le_bytes());
        bytes.extend_from_slice(&guid.data4);
        memory.map_bytes(address, &bytes);
        Ok(address)
    }

    /// `IMFTransform::GetAttributes(pAttributes)` — the transform
    /// attribute store.
    pub(crate) fn dispatch_mf_transform_get_attributes(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let store = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if store == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let mut mt = crate::media::ImfMediaType::new();
        mt.set_guid(
            crate::media::MFT_TRANSFORM_CLSID_Attribute,
            crate::media::Guid::new(
                0xc1a1d2e3,
                0x5a5a,
                0x4b4b,
                [0x9a, 0x9a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ),
        );
        self.mf_media_types.insert(store, mt);
        if out != 0 {
            write_guest_pointer(memory, out, store, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::GetInputAvailableType(dwStreamID, dwTypeIndex,
    /// ppType)` — the supported video input types.
    pub(crate) fn dispatch_mf_transform_get_input_available_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let index = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let subtypes = [
            crate::media::MFVideoFormat_H264,
            crate::media::MFVideoFormat_H265,
            crate::media::MFVideoFormat_VP90,
            crate::media::MFVideoFormat_WMV3,
        ];
        let Some(subtype) = subtypes.get(index as usize) else {
            state.set(Register::Rax, 0xc00d_36d6); // MF_E_NO_MORE_TYPES
            return Ok(());
        };
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let mt_object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if mt_object == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let mut mt = crate::media::ImfMediaType::new();
        mt.set_guid(
            crate::media::MF_MT_MAJOR_TYPE,
            crate::media::MFMediaType_Video,
        );
        mt.set_guid(crate::media::MF_MT_SUBTYPE, *subtype);
        self.mf_media_types.insert(mt_object, mt);
        if out != 0 {
            write_guest_pointer(memory, out, mt_object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::GetOutputAvailableType` — the NV12/RGB32 outputs.
    pub(crate) fn dispatch_mf_transform_get_output_available_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let index = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        if !self.mf_transforms.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        let subtypes = [
            crate::media::MFVideoFormat_NV12,
            crate::media::MFVideoFormat_RGB32,
        ];
        let Some(subtype) = subtypes.get(index as usize) else {
            state.set(Register::Rax, 0xc00d_36d6);
            return Ok(());
        };
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let mt_object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if mt_object == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let mut mt = crate::media::ImfMediaType::new();
        mt.set_guid(
            crate::media::MF_MT_MAJOR_TYPE,
            crate::media::MFMediaType_Video,
        );
        mt.set_guid(crate::media::MF_MT_SUBTYPE, *subtype);
        self.mf_media_types.insert(mt_object, mt);
        if out != 0 {
            write_guest_pointer(memory, out, mt_object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::GetInputCurrentType(dwStreamID, ppType)` — the
    /// negotiated type.
    pub(crate) fn dispatch_mf_transform_get_input_current_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_mft_current_type(state, memory, true)
    }

    pub(crate) fn dispatch_mf_transform_get_output_current_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        self.dispatch_mft_current_type(state, memory, false)
    }

    fn dispatch_mft_current_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
        is_input: bool,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(transform) = self.mf_transforms.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let negotiated = if is_input {
            transform.input_type.clone()
        } else {
            transform.output_type.clone()
        };
        let Some(negotiated) = negotiated else {
            state.set(Register::Rax, 0xc00d_36d5); // MF_E_TRANSFORM_TYPE_NOT_SET
            return Ok(());
        };
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let mt_object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if mt_object == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_media_types.insert(mt_object, negotiated);
        if out != 0 {
            write_guest_pointer(memory, out, mt_object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::SetInputType(dwStreamID, pType, dwFlags)` — the
    /// video-type negotiation.
    pub(crate) fn dispatch_mf_transform_set_input_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let type_ptr = guest_call_arg(state, memory, 2)?;
        let flags = guest_call_arg_u32(state, memory, 3)?;
        let Some(transform) = self.mf_transforms.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if type_ptr == 0 {
            transform.input_type = None;
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        let Some(mt) = self.mf_media_types.get(&type_ptr).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if flags & 0x2 == 0 && !Self::mft_media_type_supported(&mt) {
            state.set(Register::Rax, 0xc00d_36b8); // MF_E_INVALIDMEDIATYPE
            return Ok(());
        }
        transform.input_type = Some(mt);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::SetOutputType` — the NV12/RGB32 output negotiation.
    pub(crate) fn dispatch_mf_transform_set_output_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let type_ptr = guest_call_arg(state, memory, 2)?;
        let flags = guest_call_arg_u32(state, memory, 3)?;
        let Some(transform) = self.mf_transforms.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if type_ptr == 0 {
            transform.output_type = None;
            state.set(Register::Rax, u64::from(S_OK));
            return Ok(());
        }
        let Some(mt) = self.mf_media_types.get(&type_ptr).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if flags & 0x2 == 0 && !Self::mft_media_type_supported(&mt) {
            state.set(Register::Rax, 0xc00d_36b8);
            return Ok(());
        }
        transform.output_type = Some(mt);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::GetInputStatus(dwStreamID, pdwFlags)` — accepts data
    /// when no sample is buffered.
    pub(crate) fn dispatch_mf_transform_get_input_status(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let Some(transform) = self.mf_transforms.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if out != 0 {
            let accepts = if transform.buffered.is_none() { 1 } else { 0 };
            write_guest_u32(memory, out, accepts).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::GetOutputStatus(pdwFlags)` — the pending output
    /// sample count.
    pub(crate) fn dispatch_mf_transform_get_output_status(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(transform) = self.mf_transforms.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if out != 0 {
            let pending = if transform.buffered.is_some() { 1 } else { 0 };
            write_guest_u32(memory, out, pending).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::ProcessInput(dwInputStreamID, pSample, dwFlags)` —
    /// buffer the input sample.
    pub(crate) fn dispatch_mf_transform_process_input(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let sample = guest_call_arg(state, memory, 2)?;
        let _flags = guest_call_arg_u32(state, memory, 3)?;
        let Some(transform) = self.mf_transforms.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if transform.input_type.is_none() || transform.output_type.is_none() {
            state.set(Register::Rax, 0xc00d_36d5); // MF_E_TRANSFORM_TYPE_NOT_SET
            return Ok(());
        }
        if transform.buffered.is_some() {
            state.set(Register::Rax, 0xc00d_36d8); // MF_E_NOTACCEPTING
            return Ok(());
        }
        let Some(sample_state) = self.mf_samples.get(&sample).cloned() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        transform.buffered = Some(sample_state);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::ProcessOutput(dwFlags, cOutputBufferCount,
    /// pOutputSamples, pdwStatus)` — produce the output sample.
    pub(crate) fn dispatch_mf_transform_process_output(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let count = guest_call_arg_u32(state, memory, 2)?;
        let samples = guest_call_arg(state, memory, 3)?;
        let status_out = guest_call_arg(state, memory, 4)?;
        let Some(transform) = self.mf_transforms.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if count == 0 || samples == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some(buffered) = transform.buffered.take() else {
            state.set(Register::Rax, 0xc00d_36d7); // MF_E_TRANSFORM_NEED_MORE_INPUT
            return Ok(());
        };
        let vtable = self.alloc_guest_vtable(memory, Vec::new())?;
        let output = self
            .alloc_guest_object(memory, GuestObjectKind::ImfSample, vtable)
            .unwrap_or(0);
        if output == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_samples.insert(output, buffered);
        // The MFT_OUTPUT_DATA_BUFFER: {dwStreamID(0), pSample(8),
        // dwStatus(16), pEvents(24)}.
        write_guest_u32(memory, samples, 0).ok();
        write_guest_pointer(memory, samples + 8, output, self.guest_arch).ok();
        write_guest_u32(memory, samples + 16, 0x1).ok(); // MF_SAMPLE_SAMPLE_READY
        write_guest_pointer(memory, samples + 24, 0, self.guest_arch).ok();
        if status_out != 0 {
            write_guest_u32(memory, status_out, 0).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFTransform::ProcessMessage(MFT_MESSAGE_TYPE eMessage, ULONG_PTR
    /// ulParam)` — the flush/streaming state.
    pub(crate) fn dispatch_mf_transform_process_message(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let message = guest_call_arg_u32(state, memory, 1)?;
        let _param = guest_call_arg(state, memory, 2)?;
        let Some(transform) = self.mf_transforms.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        match message {
            0x0000_0001 => {
                // MFT_MESSAGE_COMMAND_FLUSH
                transform.buffered = None;
            }
            0x0000_0002 => {
                // MFT_MESSAGE_COMMAND_DRAIN
                transform.streaming = true;
            }
            0x0000_0011 => {
                // MFT_MESSAGE_NOTIFY_BEGIN_STREAMING
                transform.streaming = true;
            }
            0x0000_0012 => {
                // MFT_MESSAGE_NOTIFY_END_STREAMING
                transform.streaming = false;
            }
            _ => {}
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// The unsupported IMFTransform methods.
    pub(crate) fn dispatch_mft_unsupported(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, 0xc00d_36c4); // MF_E_INVALID_STREAM_DATA
        Ok(())
    }

    /// `MFEnumDeviceSources(pAttributes, pppSourceActivate,
    /// pcSourceActivate)` — no audio/video capture devices — the documented
    /// empty enumeration.
    pub(crate) fn dispatch_mf_enum_device_sources(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _attributes = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let count = guest_call_arg(state, memory, 2)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        if count != 0 {
            write_u32(memory, count, 0);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    // ── Interface method dispatch (the vtable slots) ───────────────────────

    /// IMFAttributes::GetCount — the attribute count of the media-type
    /// object.
    pub(crate) fn dispatch_mf_attr_get_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let count = self
            .mf_media_types
            .get(&this)
            .map(|t| t.attribute_count())
            .unwrap_or(0);
        if out != 0 {
            write_u32(memory, out, count as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFAttributes::GetUINT32 — the documented MF_E_ATTRIBUTENOTFOUND when
    /// the key is absent.
    pub(crate) fn dispatch_mf_attr_get_uint32(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let out = guest_call_arg(state, memory, 2)?;
        match self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_uint32(&key))
        {
            Some(value) => {
                if out != 0 {
                    write_u32(memory, out, value);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND)),
        }
        Ok(())
    }

    /// IMFAttributes::SetUINT32.
    pub(crate) fn dispatch_mf_attr_set_uint32(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let value = guest_call_arg_u32(state, memory, 2)?;
        if let Some(t) = self.mf_media_types.get_mut(&this) {
            t.set_uint32(key, value);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFAttributes::GetUINT64.
    pub(crate) fn dispatch_mf_attr_get_uint64(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let out = guest_call_arg(state, memory, 2)?;
        match self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_uint64(&key))
        {
            Some(value) => {
                if out != 0 {
                    write_guest_u64(memory, out, value).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND)),
        }
        Ok(())
    }

    /// IMFAttributes::SetUINT64.
    pub(crate) fn dispatch_mf_attr_set_uint64(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let value = guest_call_arg(state, memory, 2)?;
        if let Some(t) = self.mf_media_types.get_mut(&this) {
            t.set_uint64(key, value);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFAttributes::GetGUID.
    pub(crate) fn dispatch_mf_attr_get_guid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let out = guest_call_arg(state, memory, 2)?;
        match self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_guid(&key))
        {
            Some(guid) => {
                if out != 0 {
                    write_guest_guid(memory, out, guid);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND)),
        }
        Ok(())
    }

    /// IMFAttributes::SetGUID.
    pub(crate) fn dispatch_mf_attr_set_guid(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let value = read_guest_guid(memory, guest_call_arg(state, memory, 2)?);
        if let Some(t) = self.mf_media_types.get_mut(&this) {
            t.set_guid(key, value);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFAttributes::GetString — the length-prefixed string contract
    /// (required size when the buffer is too small).
    pub(crate) fn dispatch_mf_attr_get_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let buffer = guest_call_arg(state, memory, 2)?;
        let capacity = guest_call_arg_u32(state, memory, 3)?;
        let required_out = guest_call_arg(state, memory, 4)?;
        match self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_string(&key))
        {
            Some(text) => {
                let units = text.encode_utf16().count() as u32 + 1;
                if required_out != 0 {
                    write_u32(memory, required_out, units);
                }
                if capacity >= units {
                    write_utf16_fixed_buffer(memory, buffer, units as usize, text);
                    state.set(Register::Rax, u64::from(S_OK));
                } else {
                    state.set(Register::Rax, u64::from(E_INVALIDARG));
                }
            }
            None => state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND)),
        }
        Ok(())
    }

    /// IMFAttributes::SetString.
    pub(crate) fn dispatch_mf_attr_set_string(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let value_ptr = guest_call_arg(state, memory, 2)?;
        let Some(value) = read_utf16_string(memory, value_ptr).ok() else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if let Some(t) = self.mf_media_types.get_mut(&this) {
            t.set_string(key, value);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFAttributes::GetBlobSize.
    pub(crate) fn dispatch_mf_attr_get_blob_size(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let out = guest_call_arg(state, memory, 2)?;
        match self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_blob(&key))
        {
            Some(blob) => {
                if out != 0 {
                    write_u32(memory, out, blob.len() as u32);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND)),
        }
        Ok(())
    }

    /// IMFAttributes::GetBlob — copies into the caller's buffer.
    pub(crate) fn dispatch_mf_attr_get_blob(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let buffer = guest_call_arg(state, memory, 2)?;
        let capacity = guest_call_arg_u32(state, memory, 3)?;
        match self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_blob(&key))
        {
            Some(blob) if (blob.len() as u32) <= capacity => {
                for (index, byte) in blob.iter().enumerate() {
                    memory.write_u8(buffer + index as u64, *byte);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            Some(_) => state.set(Register::Rax, u64::from(E_INVALIDARG)),
            None => state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND)),
        }
        Ok(())
    }

    /// IMFAttributes::SetBlob.
    pub(crate) fn dispatch_mf_attr_set_blob(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let blob_ptr = guest_call_arg(state, memory, 2)?;
        let blob_len = guest_call_arg_u32(state, memory, 3)?;
        let blob = memory
            .read_bytes(blob_ptr, blob_len as usize)
            .unwrap_or_default();
        if let Some(t) = self.mf_media_types.get_mut(&this) {
            t.set_blob(key, blob);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFAttributes::DeleteItem.
    pub(crate) fn dispatch_mf_attr_delete_item(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        if let Some(t) = self.mf_media_types.get_mut(&this) {
            t.delete_item(&key);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFMediaType::GetMajorType — derives from the media subtype.
    pub(crate) fn dispatch_mf_media_type_get_major_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let major = self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_guid(&crate::media::MF_MT_MAJOR_TYPE))
            .unwrap_or(Guid::new(0, 0, 0, [0; 8]));
        if out != 0 {
            write_guest_guid(memory, out, major);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFMediaBuffer::GetMaxLength.
    pub(crate) fn dispatch_mf_buffer_get_max_length(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let max_len = self
            .mf_media_buffers
            .get(&this)
            .map(|b| b.get_max_length())
            .unwrap_or(0);
        if out != 0 {
            write_u32(memory, out, max_len);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFMediaBuffer::GetCurrentLength.
    pub(crate) fn dispatch_mf_buffer_get_current_length(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let len = self
            .mf_media_buffers
            .get(&this)
            .map(|b| b.get_current_length())
            .unwrap_or(0);
        if out != 0 {
            write_u32(memory, out, len);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFMediaBuffer::SetCurrentLength.
    pub(crate) fn dispatch_mf_buffer_set_current_length(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let len = guest_call_arg_u32(state, memory, 1)?;
        if let Some(b) = self.mf_media_buffers.get_mut(&this) {
            if len > b.get_max_length() {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
            } else {
                b.set_current_length(len);
                state.set(Register::Rax, u64::from(S_OK));
            }
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFMediaBuffer::Lock — exposes the buffer payload; the data
    /// buffer is stored in the media layer state.
    pub(crate) fn dispatch_mf_buffer_lock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let data_out = guest_call_arg(state, memory, 1)?;
        let _max_out = guest_call_arg(state, memory, 2)?;
        let current_out = guest_call_arg(state, memory, 3)?;
        let payload = match self.mf_media_buffers.get_mut(&this) {
            Some(b) => b.lock().to_vec(),
            None => {
                state.set(Register::Rax, u64::from(E_NOINTERFACE));
                return Ok(());
            }
        };
        let guest = self
            .alloc_heap(memory, payload.len().max(1), true)
            .unwrap_or(0);
        if guest == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        for (index, byte) in payload.iter().enumerate() {
            memory.write_u8(guest + index as u64, *byte);
        }
        if data_out != 0 {
            write_guest_pointer(memory, data_out, guest, self.guest_arch).ok();
        }
        if current_out != 0 {
            let len = self
                .mf_media_buffers
                .get(&this)
                .map(|b| b.get_current_length())
                .unwrap_or(0);
            write_u32(memory, current_out, len);
        }
        self.mf_locked_buffer_data.insert(this, guest);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFMediaBuffer::Unlock — reads the locked guest buffer back into the
    /// media-layer state and releases it.
    pub(crate) fn dispatch_mf_buffer_unlock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if let Some(guest) = self.mf_locked_buffer_data.remove(&this) {
            if let Some(b) = self.mf_media_buffers.get_mut(&this) {
                let len = b.get_current_length() as usize;
                let bytes = memory.read_bytes(guest, len).unwrap_or_default();
                b.lock().copy_from_slice(&bytes);
            }
            self.heap_allocations.remove(&guest);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSample::GetBufferCount.
    pub(crate) fn dispatch_mf_sample_get_buffer_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let count = self.mf_samples.get(&this).map(|_s| 1_u32).unwrap_or(0);
        if out != 0 {
            write_u32(memory, out, count as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSample::GetBufferByIndex — returns the sample's buffer object.
    pub(crate) fn dispatch_mf_sample_get_buffer_by_index(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        let _ = index;
        let buffer = self.mf_samples.get(&this).map(|_s| 0_u64).unwrap_or(0);
        if out != 0 {
            write_guest_pointer(memory, out, buffer, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSample::AddBuffer — adds the buffer object to the sample.
    pub(crate) fn dispatch_mf_sample_add_buffer(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let _ = buffer;
        if let Some(_s) = self.mf_samples.get_mut(&this) {
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFSample::GetSampleTime.
    pub(crate) fn dispatch_mf_sample_get_sample_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        match self
            .mf_samples
            .get(&this)
            .and_then(|s| Some(s.get_sample_time()).filter(|t| *t != 0))
        {
            Some(time) => {
                if out != 0 {
                    write_guest_pointer(memory, out, time as u64, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_NO_SAMPLE_TIMESTAMP)),
        }
        Ok(())
    }

    /// IMFSample::SetSampleTime.
    pub(crate) fn dispatch_mf_sample_set_sample_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let time = guest_call_arg(state, memory, 1)?;
        if let Some(s) = self.mf_samples.get_mut(&this) {
            s.set_sample_time(time as i64);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFSample::GetSampleDuration.
    pub(crate) fn dispatch_mf_sample_get_sample_duration(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let duration = self
            .mf_samples
            .get(&this)
            .map(|s| s.get_sample_duration())
            .unwrap_or(0);
        if out != 0 {
            write_guest_pointer(memory, out, duration as u64, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSample::SetSampleDuration.
    pub(crate) fn dispatch_mf_sample_set_sample_duration(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let duration = guest_call_arg(state, memory, 1)?;
        if let Some(s) = self.mf_samples.get_mut(&this) {
            s.set_sample_duration(duration as i64);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFMediaEventQueue::QueueEvent.
    pub(crate) fn dispatch_mf_event_queue_queue_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let event_type = guest_call_arg_u32(state, memory, 1)?;
        let _guid = guest_call_arg(state, memory, 2)?;
        let _status = guest_call_arg_u32(state, memory, 3)?;
        let _value = guest_call_arg(state, memory, 4)?;
        if let Some(q) = self.mf_event_queues.get_mut(&this) {
            q.queue_mf_event(event_type);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFMediaEventQueue::GetEvent — the next queued event (the queue is
    /// drained; `MF_E_NO_EVENTS_AVAILABLE` when empty).
    pub(crate) fn dispatch_mf_event_queue_get_event(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        match self
            .mf_event_queues
            .get_mut(&this)
            .and_then(|q| q.get_event())
        {
            Some(event) => {
                let object =
                    self.alloc_mf_event_object(memory, event.mf_type, event.status as u32, 0)?;
                if object != 0 {
                    if out != 0 {
                        write_guest_pointer(memory, out, object, self.guest_arch).ok();
                    }
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_NO_EVENTS_AVAILABLE)),
        }
        Ok(())
    }

    /// IMFMediaSession::Start — starts the session clock and drives the real
    /// media sources wired into the topology graph.
    pub(crate) fn dispatch_mf_session_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _guid = guest_call_arg(state, memory, 1)?;
        let _pos = guest_call_arg(state, memory, 2)?;
        for source in self.mf_topology_source_objects() {
            if let Some(source) = self.mf_media_sources.get_mut(&source) {
                let position = source.position();
                let _ = source.start(Some(position));
            }
        }
        match self.mf_sessions.get_mut(&this) {
            Some(s) => {
                let _ = s.start();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFMediaSession::Pause.
    pub(crate) fn dispatch_mf_session_pause(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        for source in self.mf_topology_source_objects() {
            if let Some(source) = self.mf_media_sources.get_mut(&source) {
                let _ = source.pause();
            }
        }
        match self.mf_sessions.get_mut(&this) {
            Some(s) => {
                let _ = s.pause();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFMediaSession::Stop.
    pub(crate) fn dispatch_mf_session_stop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        for source in self.mf_topology_source_objects() {
            if let Some(source) = self.mf_media_sources.get_mut(&source) {
                let _ = source.stop();
            }
        }
        match self.mf_sessions.get_mut(&this) {
            Some(s) => {
                let _ = s.stop();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFMediaSession::Close.
    pub(crate) fn dispatch_mf_session_close(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        for source in self.mf_topology_source_objects() {
            if let Some(source) = self.mf_media_sources.get_mut(&source) {
                let _ = source.stop();
            }
        }
        match self.mf_sessions.get_mut(&this) {
            Some(s) => {
                let _ = s.stop();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFMediaSession::Shutdown — shuts down the real sources wired into
    /// the topology graph alongside the session object.
    pub(crate) fn dispatch_mf_session_shutdown(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        for source in self.mf_topology_source_objects() {
            if let Some(source) = self.mf_media_sources.get_mut(&source) {
                source.shutdown();
            }
        }
        self.mf_sessions.remove(&this);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFMediaSession::GetClock — the session's presentation clock object.
    pub(crate) fn dispatch_mf_session_get_clock(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let vtable = self.alloc_guest_vtable(memory, mf_clock_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfPresentationClock, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_clocks
            .insert(object, crate::media::PresentationClock::new());
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFPresentationClock::GetTime.
    pub(crate) fn dispatch_mf_clock_get_time(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let time = self
            .mf_clocks
            .get(&this)
            .map(|c| (c.get_time().as_nanos() / 100) as u64)
            .unwrap_or(0);
        if out != 0 {
            write_guest_pointer(memory, out, time, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFPresentationClock::Start.
    pub(crate) fn dispatch_mf_clock_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let pos = guest_call_arg(state, memory, 1)?;
        let _ = pos;
        if let Some(c) = self.mf_clocks.get_mut(&this) {
            c.start();
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFPresentationClock::Stop.
    pub(crate) fn dispatch_mf_clock_stop(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if let Some(c) = self.mf_clocks.get_mut(&this) {
            c.stop();
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFSinkWriter::AddStream — returns the stream index (the sink
    /// writer's stream table).
    pub(crate) fn dispatch_mf_sink_writer_add_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _media_type = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        match self.mf_sink_writers.get_mut(&this) {
            Some(_w) => {
                // The sink writer's stream table: the first AddStream returns
                // index 0 (the single output stream the media model writes).
                if out != 0 {
                    write_u32(memory, out, 0);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFSinkWriter::WriteSample — records the sample on the stream.
    pub(crate) fn dispatch_mf_sink_writer_write_sample(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg_u32(state, memory, 1)?;
        let sample = guest_call_arg(state, memory, 2)?;
        match self.mf_sink_writers.get_mut(&this) {
            Some(w) => {
                let sample_bytes = self
                    .mf_samples
                    .get(&sample)
                    .map(|s| s.get_buffer().to_vec())
                    .unwrap_or_default();
                let sample_obj = ImfSample::new(sample_bytes);
                let _ = w.write_sample(stream, &sample_obj);
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFSinkWriter::BeginWriting.
    pub(crate) fn dispatch_mf_sink_writer_begin_writing(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        match self.mf_sink_writers.get_mut(&this) {
            Some(w) => {
                let _ = w.begin_writing();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFSinkWriter::EndWriting.
    pub(crate) fn dispatch_mf_sink_writer_end_writing(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        match self.mf_sink_writers.get_mut(&this) {
            Some(w) => {
                let _ = w.end_writing();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFSourceReader::GetCurrentMediaType — the stream's negotiated
    /// current media type.
    pub(crate) fn dispatch_mf_source_reader_get_current_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let Some(reader) = self.mf_source_readers.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(track) = reader.resolve_stream_index(stream) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let media_type = match reader.get_current_media_type(track) {
            Ok(media_type) => media_type,
            Err(_) => {
                state.set(Register::Rax, u64::from(MF_E_INVALIDMEDIATYPE));
                return Ok(());
            }
        };
        let object = self.alloc_mf_media_type_object(memory, media_type)?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSourceReader::GetNativeMediaType — the stream's native type, or
    /// `MF_E_NO_MORE_TYPES` past the end of the enumeration.
    pub(crate) fn dispatch_mf_source_reader_get_native_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg_u32(state, memory, 1)?;
        let index = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        let Some(reader) = self.mf_source_readers.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(track) = reader.resolve_stream_index(stream) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        // Each demuxed track has exactly one native type: index 0.
        if index != 0 {
            state.set(Register::Rax, u64::from(MF_E_NO_MORE_TYPES));
            return Ok(());
        }
        let media_type = match reader.get_current_media_type(track) {
            Ok(media_type) => media_type,
            Err(_) => {
                state.set(Register::Rax, u64::from(MF_E_INVALIDMEDIATYPE));
                return Ok(());
            }
        };
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let object = self.alloc_mf_media_type_object(memory, media_type)?;
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSourceReader::ReadSample — reads the next real demuxed sample:
    /// the sample bytes, its 100-ns timestamp/duration and the
    /// MF_SOURCE_READERF_NEWSTREAM flag round-trip to the guest.  At the end
    /// of the file the flags carry MF_SOURCE_READERF_ENDOFSTREAM and the
    /// owning media source queues MEEndOfStream/MEEndOfPresentation.
    pub(crate) fn dispatch_mf_source_reader_read_sample(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let stream = guest_call_arg_u32(state, memory, 1)?;
        let _control = guest_call_arg_u32(state, memory, 2)?;
        let actual_out = guest_call_arg(state, memory, 3)?;
        let flags_out = guest_call_arg(state, memory, 4)?;
        let timestamp_out = guest_call_arg(state, memory, 5)?;
        let sample_out = guest_call_arg(state, memory, 6)?;
        let Some(reader) = self.mf_source_readers.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let Some(track) = reader.resolve_stream_index(stream) else {
            state.set(Register::Rax, 0xc00d_36b3); // MF_E_INVALIDSTREAMNUMBER
            return Ok(());
        };
        let source = reader.source();
        let sample = match reader.read_sample(track) {
            Ok(sample) => sample,
            Err(_) => {
                state.set(Register::Rax, u64::from(MF_E_INVALIDMEDIATYPE));
                return Ok(());
            }
        };
        if actual_out != 0 {
            write_u32(memory, actual_out, track);
        }
        match sample {
            Some(sample) => {
                let timestamp = sample.sample_time;
                let flags = sample.flags & MF_SOURCE_READERF_NEWSTREAM;
                let vtable = self.alloc_guest_vtable(memory, mf_sample_methods())?;
                let object = self
                    .alloc_guest_object(memory, GuestObjectKind::ImfSample, vtable)
                    .unwrap_or(0);
                if object == 0 {
                    state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
                    return Ok(());
                }
                self.mf_samples.insert(object, sample);
                if flags_out != 0 {
                    write_u32(memory, flags_out, flags);
                }
                if timestamp_out != 0 {
                    write_guest_u64(memory, timestamp_out, timestamp as u64).ok();
                }
                if sample_out != 0 {
                    write_guest_pointer(memory, sample_out, object, self.guest_arch).ok();
                }
            }
            None => {
                if flags_out != 0 {
                    write_u32(memory, flags_out, MF_SOURCE_READERF_ENDOFSTREAM);
                }
                if timestamp_out != 0 {
                    write_guest_u64(memory, timestamp_out, 0).ok();
                }
                if sample_out != 0 {
                    write_guest_pointer(memory, sample_out, 0, self.guest_arch).ok();
                }
                // The pull side reached the end of the file: the owning
                // source queues MEEndOfStream/MEEndOfPresentation.
                if let Some(source_state) = self.mf_media_sources.get_mut(&source) {
                    source_state.end_presentation();
                }
                // Real EOF is a real state change: deliver the queued
                // MEEndOf* events to a parked BeginGetEvent.
                self.mf_source_pump_events(source, memory, false)?;
            }
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::GetCapabilities — the real capability mask: memory
    /// streams are readable+seekable, file streams report the access the
    /// runtime handle was opened with.  Local streams do not use the network.
    pub(crate) fn dispatch_mf_byte_stream_get_capabilities(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        let mut capabilities = MFBYTESTREAM_IS_READABLE | MFBYTESTREAM_DOES_NOT_USE_NETWORK;
        if stream.seekable {
            capabilities |= MFBYTESTREAM_IS_SEEKABLE;
        }
        if stream.writable {
            capabilities |= MFBYTESTREAM_IS_WRITABLE;
        }
        if out != 0 {
            write_u32(memory, out, capabilities);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::SetLength — resize a memory stream, or truncate the
    /// real file-table file through SetFilePointer + SetEndOfFile.
    pub(crate) fn dispatch_mf_byte_stream_set_length(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let length = guest_call_arg(state, memory, 1)?;
        let Some(mut stream) = self.mf_byte_streams.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if !stream.writable {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        if stream.file_handle != 0 {
            if length > i64::MAX as u64 {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
            if self
                .win32
                .set_file_pointer_ex(
                    stream.file_handle,
                    length as i64,
                    crate::win32::SeekOrigin::Begin,
                )
                .and_then(|_| self.win32.set_end_of_file(stream.file_handle))
                .is_err()
            {
                state.set(Register::Rax, u64::from(E_ACCESSDENIED));
                return Ok(());
            }
        } else {
            let length = length.min(i64::MAX as u64) as usize;
            stream.data.resize(length, 0);
            stream.position = stream.position.min(length as u64);
        }
        stream.length = length;
        self.mf_byte_streams.insert(this, stream);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::GetCurrentPosition.
    pub(crate) fn dispatch_mf_byte_stream_get_current_position(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        let pos = stream.position;
        if out != 0 {
            write_guest_u64(memory, out, pos).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::SetCurrentPosition — a real seek: memory streams move
    /// their position, file streams re-point the runtime file-table handle.
    pub(crate) fn dispatch_mf_byte_stream_set_current_position(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let position = guest_call_arg(state, memory, 1)?;
        let Some(mut stream) = self.mf_byte_streams.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if position > i64::MAX as u64 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if stream.file_handle != 0
            && self
                .win32
                .set_file_pointer_ex(
                    stream.file_handle,
                    position as i64,
                    crate::win32::SeekOrigin::Begin,
                )
                .is_err()
        {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        stream.position = position;
        self.mf_byte_streams.insert(this, stream);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::IsEndOfStream — the terminal condition against the
    /// real stream length.
    pub(crate) fn dispatch_mf_byte_stream_is_end_of_stream(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        let length = if stream.file_handle != 0 {
            self.win32
                .get_file_size_ex(stream.file_handle)
                .unwrap_or(stream.length)
        } else {
            stream.data.len() as u64
        };
        if out != 0 {
            write_u32(memory, out, u32::from(stream.position >= length));
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::Read — copies from the stream payload at the current
    /// position.  File-backed streams read through the runtime file table,
    /// so the real handle's granted access and the shared file pointer
    /// govern the read.
    pub(crate) fn dispatch_mf_byte_stream_read(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let length = guest_call_arg_u32(state, memory, 2)?;
        let read_out = guest_call_arg(state, memory, 3)?;
        let Some(stream) = self.mf_byte_streams.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if length > 0 && buffer == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let (take, denied) = self.mf_byte_stream_read_bytes(this, buffer, length, memory)?;
        if denied {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        if read_out != 0 {
            write_u32(memory, read_out, take);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::Write — writes at the current position (memory streams
    /// grow their backing store; file streams write through the runtime file
    /// table).  A non-writable stream answers E_ACCESSDENIED.
    pub(crate) fn dispatch_mf_byte_stream_write(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let length = guest_call_arg_u32(state, memory, 2)?;
        let written_out = guest_call_arg(state, memory, 3)?;
        let Some(stream) = self.mf_byte_streams.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if !stream.writable {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        if length > 0 && buffer == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let (written, denied) = self.mf_byte_stream_write_bytes(this, buffer, length, memory)?;
        if denied {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        if written_out != 0 {
            write_u32(memory, written_out, written);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::GetLength.
    pub(crate) fn dispatch_mf_byte_stream_get_length(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        let len = if stream.file_handle != 0 {
            self.win32
                .get_file_size_ex(stream.file_handle)
                .unwrap_or(stream.length)
        } else {
            stream.data.len() as u64
        };
        if out != 0 {
            write_guest_u64(memory, out, len).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::Seek — MFBYTESTREAM_SEEK_ORIGIN (msoBegin/msoCurrent)
    /// over the real stream position; the resulting position is written back.
    pub(crate) fn dispatch_mf_byte_stream_seek(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let origin = guest_call_arg_u32(state, memory, 1)?;
        let offset = guest_call_arg(state, memory, 2)? as i64;
        let _flags = guest_call_arg_u32(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        let Some(mut stream) = self.mf_byte_streams.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if !stream.seekable {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        let base = match origin {
            MSO_BEGIN => 0_i128,
            1 => stream.position as i128,
            _ => {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
        };
        let next = base + offset as i128;
        if next < 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if next > i64::MAX as i128 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let next = next as u64;
        if stream.file_handle != 0
            && self
                .win32
                .set_file_pointer_ex(
                    stream.file_handle,
                    next as i64,
                    crate::win32::SeekOrigin::Begin,
                )
                .is_err()
        {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        stream.position = next;
        self.mf_byte_streams.insert(this, stream);
        if out != 0 {
            write_guest_u64(memory, out, next).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::Flush — flush the kernel file buffers of a file-backed
    /// stream.
    pub(crate) fn dispatch_mf_byte_stream_flush(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if stream.file_handle != 0 && self.win32.flush_file_buffers(stream.file_handle).is_err() {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::Close — closes the underlying runtime file handle (a
    /// memory stream drops its payload).
    pub(crate) fn dispatch_mf_byte_stream_close(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let Some(mut stream) = self.mf_byte_streams.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if stream.file_handle != 0 {
            let handle = stream.file_handle;
            self.win32.close_handle(handle).ok();
            stream.file_handle = 0;
        }
        stream.closed = true;
        stream.data.clear();
        stream.length = 0;
        self.mf_byte_streams.insert(this, stream);
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::BeginRead — performs the real read and completes it
    /// through the MF async callback pump: a real IMFAsyncResult is created
    /// and the guest callback's `Invoke` is queued for the servicing point
    /// ([`Self::drain_pending_mf_async_completions`]); `EndRead` then
    /// retrieves the real byte count.  Windows returns `E_PENDING` when the
    /// callback is used; a null callback keeps the synchronous completion
    /// (`S_OK`, bytes recorded for `EndRead`).
    pub(crate) fn dispatch_mf_byte_stream_begin_read(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let length = guest_call_arg_u32(state, memory, 2)?;
        let callback = guest_call_arg(state, memory, 3)?;
        let state_object = guest_call_arg(state, memory, 4)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if length > 0 && buffer == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let callback_method = if callback != 0 {
            let Some(method) = self.mf_async_callback_method(memory, callback) else {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            };
            method
        } else {
            0
        };
        let (read, access_denied) = self.mf_byte_stream_read_bytes(this, buffer, length, memory)?;
        if access_denied {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        let result = self.alloc_mf_async_result(memory, state_object, S_OK)?;
        if let Some(stream) = self.mf_byte_streams.get_mut(&this) {
            stream.last_async_result = result;
            stream.last_async_read = read;
        }
        if callback != 0 {
            crate::media::complete_mf_request(
                self.guest_pid,
                crate::media::MfAsyncCompletion {
                    owner: this,
                    op: crate::media::MfAsyncOp::Read,
                    result,
                    status: S_OK,
                    callback_object: callback,
                    callback_method,
                    state_object,
                    event_object: 0,
                    bytes: read,
                },
            );
            state.set(Register::Rax, u64::from(E_PENDING));
        } else {
            state.set(Register::Rax, u64::from(S_OK));
        }
        Ok(())
    }

    /// Read from a byte stream into the guest buffer, returning
    /// `(bytes_read, access_denied)`.
    fn mf_byte_stream_read_bytes(
        &mut self,
        object: u64,
        buffer: u64,
        length: u32,
        memory: &mut MemoryImage,
    ) -> AppResult<(u32, bool)> {
        let Some(stream) = self.mf_byte_streams.get(&object).cloned() else {
            return Ok((0, false));
        };
        let data = if stream.file_handle != 0 {
            if self
                .win32
                .set_file_pointer_ex(
                    stream.file_handle,
                    stream.position as i64,
                    crate::win32::SeekOrigin::Begin,
                )
                .is_err()
            {
                return Ok((0, true));
            }
            self.win32
                .read_file(stream.file_handle, length as usize)
                .unwrap_or_default()
        } else {
            let available = stream.data.len().saturating_sub(stream.position as usize);
            let take = available.min(length as usize);
            stream.data[stream.position as usize..stream.position as usize + take].to_vec()
        };
        let take = data.len() as u32;
        if !data.is_empty() {
            memory.map_bytes(buffer, &data);
        }
        if let Some(stream) = self.mf_byte_streams.get_mut(&object) {
            stream.position = stream.position.saturating_add(u64::from(take));
        }
        Ok((take, false))
    }

    /// Write `length` guest bytes into a byte stream, returning `(written,
    /// access_denied)`.
    fn mf_byte_stream_write_bytes(
        &mut self,
        object: u64,
        buffer: u64,
        length: u32,
        memory: &mut MemoryImage,
    ) -> AppResult<(u32, bool)> {
        let Some(stream) = self.mf_byte_streams.get(&object).cloned() else {
            return Ok((0, false));
        };
        if !stream.writable {
            return Ok((0, true));
        }
        let bytes = memory
            .read_bytes(buffer, length as usize)
            .unwrap_or_default();
        if stream.file_handle != 0 {
            if self
                .win32
                .set_file_pointer_ex(
                    stream.file_handle,
                    stream.position as i64,
                    crate::win32::SeekOrigin::Begin,
                )
                .is_err()
            {
                return Ok((0, true));
            }
            let written = match self.win32.write_file(stream.file_handle, &bytes) {
                Ok(written) => written,
                Err(_) => return Ok((0, true)),
            };
            if let Some(stream) = self.mf_byte_streams.get_mut(&object) {
                stream.position = stream.position.saturating_add(u64::from(written));
            }
            return Ok((written, false));
        }
        let start = stream.position as usize;
        let end = start.saturating_add(bytes.len());
        let mut data = stream.data.clone();
        if end > data.len() {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(&bytes);
        let written = bytes.len() as u32;
        if let Some(stream) = self.mf_byte_streams.get_mut(&object) {
            stream.data = data;
            stream.length = stream.length.max(end as u64);
            stream.position = stream.position.saturating_add(u64::from(written));
        }
        Ok((written, false))
    }

    /// Allocate a runtime IMFAsyncResult guest object (used by the
    /// synchronous BeginRead/BeginWrite completions).
    fn alloc_mf_async_result(
        &mut self,
        memory: &mut MemoryImage,
        state_object: u64,
        status: u32,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(memory, mf_async_result_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfAsyncResult, vtable)
            .unwrap_or(0);
        if object == 0 {
            return Ok(0);
        }
        self.mf_async_results.insert(
            object,
            crate::runtime::state::ImfAsyncResultState {
                state_object,
                status,
            },
        );
        Ok(object)
    }

    /// Drop the runtime-side state of a guest MF object on its final release:
    /// closes a byte stream's real file handle and forgets the per-object
    /// source/descriptor/event/reader state.
    pub(crate) fn destroy_mf_object_state(&mut self, address: u64) -> AppResult<()> {
        if let Some(stream) = self.mf_byte_streams.remove(&address) {
            if stream.file_handle != 0 {
                self.win32.close_handle(stream.file_handle).ok();
            }
        }
        self.mf_presentation_descriptors.remove(&address);
        self.mf_stream_descriptors.remove(&address);
        self.mf_media_type_handlers.remove(&address);
        self.mf_media_events.remove(&address);
        self.mf_media_types.remove(&address);
        self.mf_source_d3d_managers.remove(&address);
        self.mf_source_readers.remove(&address);
        self.mf_media_sources.remove(&address);
        self.guest_objects.remove(&address);
        Ok(())
    }

    /// IMFByteStream::EndRead — retrieves the real byte count of the
    /// `BeginRead` result (whether it completed through the callback pump or
    /// synchronously with a null callback).
    pub(crate) fn dispatch_mf_byte_stream_end_read(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let result = guest_call_arg(state, memory, 1)?;
        let read_out = guest_call_arg(state, memory, 2)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        let read = if let Some(completion) = crate::media::take_mf_result(self.guest_pid, result) {
            if completion.op != crate::media::MfAsyncOp::Read {
                crate::media::record_mf_result(self.guest_pid, completion);
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
            if let Some(stream) = self.mf_byte_streams.get_mut(&this) {
                if stream.last_async_result == result {
                    stream.last_async_result = 0;
                }
            }
            completion.bytes
        } else {
            if result == 0 || result != stream.last_async_result {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
            let read = stream.last_async_read;
            if let Some(stream) = self.mf_byte_streams.get_mut(&this) {
                stream.last_async_result = 0;
            }
            read
        };
        if read_out != 0 {
            write_u32(memory, read_out, read);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::BeginWrite — performs the real write and completes it
    /// through the MF async callback pump (see BeginRead): the guest
    /// callback's `Invoke` is queued with a real IMFAsyncResult and
    /// `EndWrite` retrieves the real byte count; a null callback keeps the
    /// synchronous `S_OK` completion.
    pub(crate) fn dispatch_mf_byte_stream_begin_write(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let length = guest_call_arg_u32(state, memory, 2)?;
        let callback = guest_call_arg(state, memory, 3)?;
        let state_object = guest_call_arg(state, memory, 4)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        if !stream.writable {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        let callback_method = if callback != 0 {
            let Some(method) = self.mf_async_callback_method(memory, callback) else {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            };
            method
        } else {
            0
        };
        // Drive the real write implementation, then capture the completion
        // in an IMFAsyncResult for EndWrite.
        let (written, denied) = self.mf_byte_stream_write_bytes(this, buffer, length, memory)?;
        if denied {
            state.set(Register::Rax, u64::from(E_ACCESSDENIED));
            return Ok(());
        }
        let result = self.alloc_mf_async_result(memory, state_object, S_OK)?;
        if let Some(stream) = self.mf_byte_streams.get_mut(&this) {
            stream.last_async_result = result;
            stream.last_async_written = written;
        }
        if callback != 0 {
            crate::media::complete_mf_request(
                self.guest_pid,
                crate::media::MfAsyncCompletion {
                    owner: this,
                    op: crate::media::MfAsyncOp::Write,
                    result,
                    status: S_OK,
                    callback_object: callback,
                    callback_method,
                    state_object,
                    event_object: 0,
                    bytes: written,
                },
            );
            state.set(Register::Rax, u64::from(E_PENDING));
        } else {
            state.set(Register::Rax, u64::from(S_OK));
        }
        Ok(())
    }

    /// IMFByteStream::EndWrite.
    pub(crate) fn dispatch_mf_byte_stream_end_write(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let result = guest_call_arg(state, memory, 1)?;
        let written_out = guest_call_arg(state, memory, 2)?;
        let Some(stream) = self.mf_byte_streams.get(&this) else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        if stream.closed {
            state.set(Register::Rax, u64::from(E_FAIL));
            return Ok(());
        }
        let written = if let Some(completion) = crate::media::take_mf_result(self.guest_pid, result)
        {
            if completion.op != crate::media::MfAsyncOp::Write {
                crate::media::record_mf_result(self.guest_pid, completion);
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
            if let Some(stream) = self.mf_byte_streams.get_mut(&this) {
                if stream.last_async_result == result {
                    stream.last_async_result = 0;
                }
            }
            completion.bytes
        } else {
            if result == 0 || result != stream.last_async_result {
                state.set(Register::Rax, u64::from(E_INVALIDARG));
                return Ok(());
            }
            let written = stream.last_async_written;
            if let Some(stream) = self.mf_byte_streams.get_mut(&this) {
                stream.last_async_result = 0;
            }
            written
        };
        if written_out != 0 {
            write_u32(memory, written_out, written);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFTopologyNode::GetObject — the node's wrapped object (a media
    /// source/sink pointer recorded at SetObject).
    pub(crate) fn dispatch_mf_topology_node_get_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let object = self
            .mf_topology_nodes
            .get(&this)
            .map(|n| n.object)
            .unwrap_or(0);
        if out != 0 {
            write_guest_pointer(memory, out, object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFTopologyNode::SetObject.
    pub(crate) fn dispatch_mf_topology_node_set_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let object = guest_call_arg(state, memory, 1)?;
        if let Some(n) = self.mf_topology_nodes.get_mut(&this) {
            n.object = object;
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFAttributes::GetItemByIndex — the (key, value) pair at an index.
    pub(crate) fn dispatch_mf_attr_get_item_by_index(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let index = guest_call_arg_u32(state, memory, 1)?;
        let key_out = guest_call_arg(state, memory, 2)?;
        let value_out = guest_call_arg(state, memory, 3)?;
        let Some((key, value)) = self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.attribute_at(index as usize))
        else {
            state.set(Register::Rax, 0x8007_0059); // MF_E_INVALIDINDEX
            return Ok(());
        };
        if key_out != 0 {
            write_guest_guid(memory, key_out, key);
        }
        if value_out != 0 {
            write_guest_guid(memory, value_out, value);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFAttributes::GetDouble.
    pub(crate) fn dispatch_mf_attr_get_double(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let out = guest_call_arg(state, memory, 2)?;
        match self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_double(&key))
        {
            Some(value) => {
                if out != 0 {
                    write_guest_double(memory, out, value);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND)),
        }
        Ok(())
    }

    /// IMFAttributes::SetDouble.
    pub(crate) fn dispatch_mf_attr_set_double(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let value = read_guest_double(memory, guest_call_arg(state, memory, 2)?);
        if let Some(t) = self.mf_media_types.get_mut(&this) {
            t.set_double(key, value);
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFAttributes::GetStringLength — the character count (incl. null).
    pub(crate) fn dispatch_mf_attr_get_string_length(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let key = read_guest_guid(memory, guest_call_arg(state, memory, 1)?);
        let out = guest_call_arg(state, memory, 2)?;
        match self
            .mf_media_types
            .get(&this)
            .and_then(|t| t.get_string(&key))
        {
            Some(text) => {
                if out != 0 {
                    write_u32(memory, out, text.encode_utf16().count() as u32 + 1);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_ATTRIBUTENOTFOUND)),
        }
        Ok(())
    }

    /// IMFMediaType::IsCompressedFormat.
    pub(crate) fn dispatch_mf_media_type_is_compressed_format(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let compressed = self
            .mf_media_types
            .get(&this)
            .map(|t| t.get_uint32(&crate::media::MF_MT_MAJOR_TYPE) == Some(0))
            .unwrap_or(false);
        if out != 0 {
            write_u32(memory, out, if compressed { 1 } else { 0 });
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSample::RemoveBufferByIndex — clears the sample's buffer slot.
    pub(crate) fn dispatch_mf_sample_remove_buffer_by_index(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _index = guest_call_arg_u32(state, memory, 1)?;
        if let Some(s) = self.mf_samples.get_mut(&this) {
            s.set_buffer(Vec::new());
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFSample::RemoveAllBuffers.
    pub(crate) fn dispatch_mf_sample_remove_all_buffers(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if let Some(s) = self.mf_samples.get_mut(&this) {
            s.set_buffer(Vec::new());
            state.set(Register::Rax, u64::from(S_OK));
        } else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
        }
        Ok(())
    }

    /// IMFTopology::AddNode.
    pub(crate) fn dispatch_mf_topology_add_node(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let node = guest_call_arg(state, memory, 1)?;
        match self.mf_topologies.get_mut(&this) {
            Some(topo) => {
                let node_id = topo.add_node(crate::media::TopologyNodeType::Source, "mf-node");
                self.mf_topology_nodes.insert(
                    node,
                    crate::runtime::state::TopologyNodeState {
                        node_type: 0,
                        object: node_id,
                        inputs: Vec::new(),
                        outputs: Vec::new(),
                        name: String::new(),
                    },
                );
                let _ = node;
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFTopology::GetNodeCount.
    pub(crate) fn dispatch_mf_topology_get_node_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let count = self
            .mf_topologies
            .get(&this)
            .map(|t| t.node_count())
            .unwrap_or(0);
        if out != 0 {
            write_u32(memory, out, count as u32);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSourceResolver::CreateObjectFromURL — no registered URL sources
    /// beyond the file reader — MF_E_UNSUPPORTED_BYTESTREAM_TYPE.
    pub(crate) fn dispatch_mf_source_resolver_create_object_from_url(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _url = guest_call_arg(state, memory, 1)?;
        let _flags = guest_call_arg_u32(state, memory, 2)?;
        let _iid = guest_call_arg(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_BYTESTREAM_TYPE));
        Ok(())
    }

    /// IMFMediaEvent::GetType.
    pub(crate) fn dispatch_mf_event_get_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let event_type = self
            .mf_media_events
            .get(&this)
            .map(|e| e.event_type)
            .unwrap_or(0);
        if out != 0 {
            write_u32(memory, out, event_type);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFMediaEvent::GetExtendedType — the runtime queues no extended-type
    /// events, so the documented GUID_NULL is written.
    pub(crate) fn dispatch_mf_event_get_extended_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.mf_media_events.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if out != 0 {
            memory.map_bytes(out, &[0_u8; 16]);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFMediaEvent::GetStatus(phrStatus) — the event's HRESULT status.
    pub(crate) fn dispatch_mf_event_get_status(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(event) = self.mf_media_events.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out != 0 {
            write_u32(memory, out, event.status);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFMediaEvent::GetValue(pvValue) — the event value as a VT_UI8
    /// PROPVARIANT (the runtime's modelled values are 64-bit positions).
    pub(crate) fn dispatch_mf_event_get_value(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(event) = self.mf_media_events.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out != 0 {
            write_guest_u32(memory, out, 21).ok(); // VT_UI8
            write_guest_u64(memory, out + 8, event.value).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFAsyncResult::GetState(ppunkState).
    pub(crate) fn dispatch_mf_async_result_get_state(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(result) = self.mf_async_results.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let state_object = result.state_object;
        if out != 0 {
            write_guest_pointer(memory, out, state_object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFAsyncResult::GetStatus(phrStatus).
    pub(crate) fn dispatch_mf_async_result_get_status(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        let Some(result) = self.mf_async_results.get(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        if out != 0 {
            write_u32(memory, out, result.status);
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFAsyncResult::SetStatus(hrStatus).
    pub(crate) fn dispatch_mf_async_result_set_status(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let status = guest_call_arg_u32(state, memory, 1)?;
        let Some(result) = self.mf_async_results.get_mut(&this) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        result.status = status;
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFAsyncResult::GetObject(ppObject) — the event a completed
    /// `BeginGetEvent` produced (0 for the byte-stream completions).
    pub(crate) fn dispatch_mf_async_result_get_object(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.mf_async_results.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if out != 0 {
            let event_object =
                crate::media::mf_result_event_object(self.guest_pid, this).unwrap_or(0);
            write_guest_pointer(memory, out, event_object, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFAsyncResult::GetCallback(ppCallback) — the callback the completion
    /// was parked with (0 for the synchronous completions).
    pub(crate) fn dispatch_mf_async_result_get_callback(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if !self.mf_async_results.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        if out != 0 {
            let callback =
                crate::media::mf_result_callback_object(self.guest_pid, this).unwrap_or(0);
            write_guest_pointer(memory, out, callback, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }
}

impl PeHostRuntime {
    /// The grouped dispatch arm: match the thunk and route to the COM/MF
    /// dispatch fns (kept OUT of the giant match per the audit's
    /// modularity requirement).
    /// `IMFMediaType::IsEqual(pIMediaType, pdwFlags)` — the attribute-store
    /// equality.
    pub(crate) fn dispatch_mf_media_type_is_equal(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let other = guest_call_arg(state, memory, 1)?;
        let flags = guest_call_arg(state, memory, 2)?;
        let Some(mine) = self.mf_media_types.get(&this).cloned() else {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        };
        let Some(theirs) = self.mf_media_types.get(&other) else {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        };
        let equal = mine.attributes == theirs.attributes;
        if flags != 0 {
            // MF_MEDIATYPE_EQUAL_MAJOR_TYPES etc. — the full equality.
            write_guest_u32(memory, flags, if equal { 0x1f } else { 0 }).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaType::GetRepresentation` / `FreeRepresentation` — the video
    /// representations are not exposed.
    pub(crate) fn dispatch_mf_media_type_representation(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        state.set(Register::Rax, 0xc00d_36b4); // MF_E_INVALIDTYPE
        Ok(())
    }

    pub(crate) fn dispatch_mf_or_com(
        &mut self,
        thunk: &HostThunk,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        use HostThunk::*;
        match thunk {
            MfStartup => self.dispatch_mf_startup(state, memory),
            MfShutdown => self.dispatch_mf_shutdown(state, memory),
            MfRequireProtectedEnvironment => {
                self.dispatch_mf_require_protected_environment(state, memory)
            }
            MfGetService => self.dispatch_mf_get_service(state, memory),
            MfAddPeriodicCallback => self.dispatch_mf_add_periodic_callback(state, memory),
            MfCancelPeriodicCallback => self.dispatch_mf_cancel_periodic_callback(state, memory),
            MfGetSystemTime => self.dispatch_mf_get_system_time(state, memory),
            MfCreateAttributes => self.dispatch_mf_create_attributes(state, memory),
            MfCreateMediaType => self.dispatch_mf_create_media_type(state, memory),
            MfCreateMemoryBuffer => self.dispatch_mf_create_memory_buffer(state, memory),
            MfCreateSample => self.dispatch_mf_create_sample(state, memory),
            MfCreateEventQueue => self.dispatch_mf_create_event_queue(state, memory),
            MfCreatePresentationClock => self.dispatch_mf_create_presentation_clock(state, memory),
            MfCreateTopology => self.dispatch_mf_create_topology(state, memory),
            MfCreateTopologyNode => self.dispatch_mf_create_topology_node(state, memory),
            MfCreateSourceResolver => self.dispatch_mf_create_source_resolver(state, memory),
            MfCreateMediaSession => self.dispatch_mf_create_media_session(state, memory),
            MfCreateSourceReaderFromUrl => {
                self.dispatch_mf_create_source_reader_from_url(state, memory)
            }
            MfCreateSourceReaderFromByteStream => {
                self.dispatch_mf_create_source_reader_from_byte_stream(state, memory)
            }
            MfCreateSinkWriterFromUrl => {
                self.dispatch_mf_create_sink_writer_from_url(state, memory)
            }
            MfCreateSinkWriterFromMediaSink => {
                self.dispatch_mf_create_sink_writer_from_media_sink(state, memory)
            }
            MfCreatePresentationDescriptor => {
                self.dispatch_mf_create_presentation_descriptor(state, memory)
            }
            MfCreateMfByteStreamOnStream => {
                self.dispatch_mf_create_mf_byte_stream_on_stream(state, memory)
            }
            MfCreateMediaBufferFromMediaType => {
                self.dispatch_mf_create_media_buffer_from_media_type(state, memory)
            }
            MfCreateDxgiDeviceManager => self.dispatch_mf_create_dxgi_device_manager(state, memory),
            MfDxgiDeviceManagerResetDevice => {
                self.dispatch_mf_dxgi_device_manager_reset_device(state, memory)
            }
            MfDxgiDeviceManagerOpenDeviceHandle => {
                self.dispatch_mf_dxgi_device_manager_open_device_handle(state, memory)
            }
            MfDxgiDeviceManagerCloseDeviceHandle => {
                self.dispatch_mf_dxgi_device_manager_close_device_handle(state, memory)
            }
            MfDxgiDeviceManagerTestDevice => {
                self.dispatch_mf_dxgi_device_manager_test_device(state, memory)
            }
            MfDxgiDeviceManagerLockDevice => {
                self.dispatch_mf_dxgi_device_manager_lock_device(state, memory)
            }
            MfDxgiDeviceManagerUnlockDevice => {
                self.dispatch_mf_dxgi_device_manager_unlock_device(state, memory)
            }
            MfDxgiDeviceManagerGetVideoService => {
                self.dispatch_mf_dxgi_device_manager_get_video_service(state, memory)
            }
            MftEnumEx => self.dispatch_mf_enum_ex(state, memory),
            MfEnumDeviceSources => self.dispatch_mf_enum_device_sources(state, memory),
            MfCreateSourceReaderFromMfByteStream => {
                self.dispatch_mf_create_source_reader_from_byte_stream(state, memory)
            }
            MfAttrGetCount => self.dispatch_mf_attr_get_count(state, memory),
            MfAttrGetItem => self.dispatch_mf_attr_get_item(state, memory),
            MfAttrGetItemType => self.dispatch_mf_attr_get_item_type(state, memory),
            MfAttrCompareItem => self.dispatch_mf_attr_compare_item(state, memory),
            MfAttrCompare => self.dispatch_mf_attr_compare(state, memory),
            MfAttrGetAllocatedString => self.dispatch_mf_attr_get_allocated_string(state, memory),
            MfAttrGetAllocatedBlob => self.dispatch_mf_attr_get_allocated_blob(state, memory),
            MfAttrGetUnknown => self.dispatch_mf_attr_unknown(state, memory, true),
            MfAttrSetItem => self.dispatch_mf_attr_set_item(state, memory),
            MfAttrSetUnknown => self.dispatch_mf_attr_unknown(state, memory, false),
            MfAttrDeleteAllItems => self.dispatch_mf_attr_delete_all_items(state, memory),
            MfAttrLockStore | MfAttrUnlockStore => self.dispatch_mf_attr_lock_store(state, memory),
            MfAttrCopyAllItems => self.dispatch_mf_attr_copy_all_items(state, memory),
            MfAttrGetItemByIndex => self.dispatch_mf_attr_get_item_by_index(state, memory),
            MfAttrGetUint32 => self.dispatch_mf_attr_get_uint32(state, memory),
            MfAttrGetUint64 => self.dispatch_mf_attr_get_uint64(state, memory),
            MfAttrGetDouble => self.dispatch_mf_attr_get_double(state, memory),
            MfAttrGetGuid => self.dispatch_mf_attr_get_guid(state, memory),
            MfAttrGetStringLength => self.dispatch_mf_attr_get_string_length(state, memory),
            MfAttrGetString => self.dispatch_mf_attr_get_string(state, memory),
            MfAttrGetBlobSize => self.dispatch_mf_attr_get_blob_size(state, memory),
            MfAttrGetBlob => self.dispatch_mf_attr_get_blob(state, memory),
            MfAttrSetUint32 => self.dispatch_mf_attr_set_uint32(state, memory),
            MfAttrSetUint64 => self.dispatch_mf_attr_set_uint64(state, memory),
            MfAttrSetDouble => self.dispatch_mf_attr_set_double(state, memory),
            MfAttrSetGuid => self.dispatch_mf_attr_set_guid(state, memory),
            MfAttrSetString => self.dispatch_mf_attr_set_string(state, memory),
            MfAttrSetBlob => self.dispatch_mf_attr_set_blob(state, memory),
            MfAttrDeleteItem => self.dispatch_mf_attr_delete_item(state, memory),
            MfMediaTypeGetMajorType => self.dispatch_mf_media_type_get_major_type(state, memory),
            MfMediaTypeIsCompressedFormat => {
                self.dispatch_mf_media_type_is_compressed_format(state, memory)
            }
            MfMediaTypeIsEqual => self.dispatch_mf_media_type_is_equal(state, memory),
            MfMediaTypeGetRepresentation | MfMediaTypeFreeRepresentation => {
                self.dispatch_mf_media_type_representation(state, memory)
            }
            MfBufferGetMaxLength => self.dispatch_mf_buffer_get_max_length(state, memory),
            MfBufferLock => self.dispatch_mf_buffer_lock(state, memory),
            MfBufferUnlock => self.dispatch_mf_buffer_unlock(state, memory),
            MfBufferGetCurrentLength => self.dispatch_mf_buffer_get_current_length(state, memory),
            MfBufferSetCurrentLength => self.dispatch_mf_buffer_set_current_length(state, memory),
            MfSampleGetBufferCount => self.dispatch_mf_sample_get_buffer_count(state, memory),
            MfSampleGetBufferByIndex => self.dispatch_mf_sample_get_buffer_by_index(state, memory),
            MfSampleAddBuffer => self.dispatch_mf_sample_add_buffer(state, memory),
            MfSampleRemoveBufferByIndex => {
                self.dispatch_mf_sample_remove_buffer_by_index(state, memory)
            }
            MfSampleRemoveAllBuffers => self.dispatch_mf_sample_remove_all_buffers(state, memory),
            MfSampleGetSampleTime => self.dispatch_mf_sample_get_sample_time(state, memory),
            MfSampleSetSampleTime => self.dispatch_mf_sample_set_sample_time(state, memory),
            MfSampleGetSampleDuration => self.dispatch_mf_sample_get_sample_duration(state, memory),
            MfSampleSetSampleFlags => self.dispatch_mf_sample_set_sample_flags(state, memory),
            MfSampleGetSampleFlags => self.dispatch_mf_sample_get_sample_flags(state, memory),
            MfSampleGetTotalLength => self.dispatch_mf_sample_get_total_length(state, memory),
            MfSampleCopyToBuffer => self.dispatch_mf_sample_copy_to_buffer(state, memory),
            MfSampleConvertToContiguousBuffer => {
                self.dispatch_mf_sample_convert_to_contiguous_buffer(state, memory)
            }
            MfSampleSetSampleDuration => self.dispatch_mf_sample_set_sample_duration(state, memory),
            MfEventQueueGetEvent => self.dispatch_mf_event_queue_get_event(state, memory),
            MfEventQueueQueueEvent => self.dispatch_mf_event_queue_queue_event(state, memory),
            MfClockGetTime => self.dispatch_mf_clock_get_time(state, memory),
            MfClockStart => self.dispatch_mf_clock_start(state, memory),
            MfClockStop => self.dispatch_mf_clock_stop(state, memory),
            MfRateControlSetRate => self.dispatch_mf_rate_control_set_rate(state, memory),
            MfRateControlGetRate => self.dispatch_mf_rate_control_get_rate(state, memory),
            MfRateSupportGetSlowestRate => {
                self.dispatch_mf_rate_support_get_slowest_rate(state, memory)
            }
            MfRateSupportGetFastestRate => {
                self.dispatch_mf_rate_support_get_fastest_rate(state, memory)
            }
            MfRateSupportIsRateSupported => {
                self.dispatch_mf_rate_support_is_rate_supported(state, memory)
            }
            MfSessionGetClock => self.dispatch_mf_session_get_clock(state, memory),
            MfSessionSetTopology => self.dispatch_mf_session_set_topology(state, memory),
            MfSessionGetSessionCapabilities => {
                self.dispatch_mf_session_get_capabilities(state, memory)
            }
            MfSessionGetFullTopology => self.dispatch_mf_session_get_full_topology(state, memory),
            MfSessionGetDescriptorFromTopology => {
                self.dispatch_mf_session_get_descriptor_from_topology(state, memory)
            }
            MfSinkWriterSetInputMediaType => {
                self.dispatch_mf_sink_writer_set_input_media_type(state, memory)
            }
            MfSinkWriterFlush => self.dispatch_mf_sink_writer_flush(state, memory),
            MfSinkWriterGetStatistics => self.dispatch_mf_sink_writer_get_statistics(state, memory),
            MfSinkWriterSendStreamSample | MfSinkWriterNotifyEndOfSegment => {
                self.dispatch_mf_sink_writer_service(state, memory)
            }
            MfSinkWriterGetServiceForStream => self.dispatch_mf_sink_writer_service(state, memory),
            IDispatchGetTypeInfoCount => self.dispatch_idispatch_get_type_info_count(state, memory),
            IDispatchGetTypeInfo => self.dispatch_idispatch_get_type_info(state, memory),
            MfMediaSourceGetCharacteristics => {
                self.dispatch_mf_media_source_get_characteristics(state, memory)
            }
            MfMediaSourceCreatePresentationDescriptor => {
                self.dispatch_mf_media_source_create_presentation_descriptor(state, memory)
            }
            MfMediaSourceStart => self.dispatch_mf_media_source_start(state, memory),
            MfMediaSourceStop => self.dispatch_mf_media_source_stop(state, memory),
            MfMediaSourcePause => self.dispatch_mf_media_source_pause(state, memory),
            MfMediaSourceShutdown => self.dispatch_mf_media_source_shutdown(state, memory),
            MfMediaSourceGetEvent => self.dispatch_mf_media_source_get_event(state, memory),
            MfMediaSourceBeginGetEvent => {
                self.dispatch_mf_media_source_begin_get_event(state, memory)
            }
            MfMediaSourceEndGetEvent => self.dispatch_mf_media_source_end_get_event(state, memory),
            MfMediaSourceQueueEvent => self.dispatch_mf_media_source_queue_event(state, memory),
            MfMediaSourceCancelGetEvent => {
                self.dispatch_mf_media_source_cancel_get_event(state, memory)
            }
            MfMediaSourceGetSourceAttributes => {
                self.dispatch_mf_media_source_get_source_attributes(state, memory)
            }
            MfMediaSourceGetStreamAttributes => {
                self.dispatch_mf_media_source_get_stream_attributes(state, memory)
            }
            MfMediaSourceSetD3dManager => {
                self.dispatch_mf_media_source_set_d3d_manager(state, memory)
            }
            MfCreateFile => self.dispatch_mf_create_file(state, memory),
            MfSourceResolverBegin => self.dispatch_mf_source_resolver_begin(state, memory),
            MftStreamAttributes => self.dispatch_mft_stream_attributes(state, memory),
            MftFixedStreams => self.dispatch_mft_fixed_streams(state, memory),
            MftProcessEvent => self.dispatch_mft_process_event(state, memory),
            MfSessionStart => self.dispatch_mf_session_start(state, memory),
            MfSessionPause => self.dispatch_mf_session_pause(state, memory),
            MfSessionStop => self.dispatch_mf_session_stop(state, memory),
            MfSessionClose => self.dispatch_mf_session_close(state, memory),
            MfSessionShutdown => self.dispatch_mf_session_shutdown(state, memory),
            MfSourceReaderGetCurrentMediaType => {
                self.dispatch_mf_source_reader_get_current_media_type(state, memory)
            }
            MfSourceReaderGetNativeMediaType => {
                self.dispatch_mf_source_reader_get_native_media_type(state, memory)
            }
            MfSourceReaderReadSample => self.dispatch_mf_source_reader_read_sample(state, memory),
            MfSourceReaderGetStreamSelection => {
                self.dispatch_mf_source_reader_get_stream_selection(state, memory)
            }
            MfSourceReaderSetStreamSelection => {
                self.dispatch_mf_source_reader_set_stream_selection(state, memory)
            }
            MfSourceReaderSetCurrentMediaType => {
                self.dispatch_mf_source_reader_set_current_media_type(state, memory)
            }
            MfSourceReaderSetCurrentPosition => {
                self.dispatch_mf_source_reader_set_current_position(state, memory)
            }
            MfSourceReaderFlush => self.dispatch_mf_source_reader_flush(state, memory),
            MfSourceReaderGetServiceForStream => {
                self.dispatch_mf_source_reader_get_service_for_stream(state, memory)
            }
            MfSourceReaderGetPresentationAttribute => {
                self.dispatch_mf_source_reader_get_presentation_attribute(state, memory)
            }
            MfSinkWriterAddStream => self.dispatch_mf_sink_writer_add_stream(state, memory),
            MfSinkWriterBeginWriting => self.dispatch_mf_sink_writer_begin_writing(state, memory),
            MfSinkWriterWriteSample => self.dispatch_mf_sink_writer_write_sample(state, memory),
            MfSinkWriterEndWriting => self.dispatch_mf_sink_writer_end_writing(state, memory),
            MfByteStreamGetCapabilities => {
                self.dispatch_mf_byte_stream_get_capabilities(state, memory)
            }
            MfByteStreamSetLength => self.dispatch_mf_byte_stream_set_length(state, memory),
            MfByteStreamGetCurrentPosition => {
                self.dispatch_mf_byte_stream_get_current_position(state, memory)
            }
            MfByteStreamSetCurrentPosition => {
                self.dispatch_mf_byte_stream_set_current_position(state, memory)
            }
            MfByteStreamIsEndOfStream => {
                self.dispatch_mf_byte_stream_is_end_of_stream(state, memory)
            }
            MfByteStreamRead => self.dispatch_mf_byte_stream_read(state, memory),
            MfByteStreamBeginRead => self.dispatch_mf_byte_stream_begin_read(state, memory),
            MfByteStreamEndRead => self.dispatch_mf_byte_stream_end_read(state, memory),
            MfByteStreamWrite => self.dispatch_mf_byte_stream_write(state, memory),
            MfByteStreamBeginWrite => self.dispatch_mf_byte_stream_begin_write(state, memory),
            MfByteStreamEndWrite => self.dispatch_mf_byte_stream_end_write(state, memory),
            MfByteStreamSeek => self.dispatch_mf_byte_stream_seek(state, memory),
            MfByteStreamFlush => self.dispatch_mf_byte_stream_flush(state, memory),
            MfByteStreamClose => self.dispatch_mf_byte_stream_close(state, memory),
            MfByteStreamGetLength => self.dispatch_mf_byte_stream_get_length(state, memory),
            MfTopologyAddNode => self.dispatch_mf_topology_add_node(state, memory),
            MfTopologyGetNodeCount => self.dispatch_mf_topology_get_node_count(state, memory),
            MfTopologyNodeGetObject => self.dispatch_mf_topology_node_get_object(state, memory),
            MfTopologyNodeSetObject => self.dispatch_mf_topology_node_set_object(state, memory),
            MfSourceResolverCreateObjectFromUrl => {
                self.dispatch_mf_source_resolver_create_object_from_url(state, memory)
            }
            MfPresentationDescriptorGetStreamDescriptorCount => {
                self.dispatch_mf_presentation_descriptor_get_stream_descriptor_count(state, memory)
            }
            MfPresentationDescriptorGetStreamDescriptorByIndex => self
                .dispatch_mf_presentation_descriptor_get_stream_descriptor_by_index(state, memory),
            MfPresentationDescriptorSelectStream => {
                self.dispatch_mf_presentation_descriptor_select_stream(state, memory)
            }
            MfPresentationDescriptorDeselectStream => {
                self.dispatch_mf_presentation_descriptor_deselect_stream(state, memory)
            }
            MfPresentationDescriptorClone => {
                self.dispatch_mf_presentation_descriptor_clone(state, memory)
            }
            MfStreamDescriptorGetStreamIdentifier => {
                self.dispatch_mf_stream_descriptor_get_stream_identifier(state, memory)
            }
            MfStreamDescriptorGetMediaTypeHandler => {
                self.dispatch_mf_stream_descriptor_get_media_type_handler(state, memory)
            }
            MfMediaTypeHandlerIsMediaTypeSupported => {
                self.dispatch_mf_media_type_handler_is_media_type_supported(state, memory)
            }
            MfMediaTypeHandlerGetMediaTypeCount => {
                self.dispatch_mf_media_type_handler_get_media_type_count(state, memory)
            }
            MfMediaTypeHandlerGetMediaTypeByIndex => {
                self.dispatch_mf_media_type_handler_get_media_type_by_index(state, memory)
            }
            MfMediaTypeHandlerSetCurrentMediaType => {
                self.dispatch_mf_media_type_handler_set_current_media_type(state, memory)
            }
            MfMediaTypeHandlerGetCurrentMediaType => {
                self.dispatch_mf_media_type_handler_get_current_media_type(state, memory)
            }
            MfMediaTypeHandlerGetMajorType => {
                self.dispatch_mf_media_type_handler_get_major_type(state, memory)
            }
            MfEventGetType => self.dispatch_mf_event_get_type(state, memory),
            MfEventGetExtendedType => self.dispatch_mf_event_get_extended_type(state, memory),
            MfEventGetStatus => self.dispatch_mf_event_get_status(state, memory),
            MfEventGetValue => self.dispatch_mf_event_get_value(state, memory),
            MfAsyncResultGetState => self.dispatch_mf_async_result_get_state(state, memory),
            MfAsyncResultGetStatus => self.dispatch_mf_async_result_get_status(state, memory),
            MfAsyncResultSetStatus => self.dispatch_mf_async_result_set_status(state, memory),
            MfAsyncResultGetObject => self.dispatch_mf_async_result_get_object(state, memory),
            MfAsyncResultGetCallback => self.dispatch_mf_async_result_get_callback(state, memory),
            MfActivateGetCount => self.dispatch_mf_activate_get_count(state, memory),
            MfActivateGetItem => self.dispatch_mf_activate_get_item(state, memory),
            MfActivateGetGuid => self.dispatch_mf_activate_get_guid(state, memory),
            MfActivateGetString => self.dispatch_mf_activate_get_string(state, memory),
            MfActivateActivateObject => self.dispatch_mf_activate_activate_object(state, memory),
            MfActivateShutdownObject => self.dispatch_mf_activate_shutdown_object(state, memory),
            MfTransformGetStreamLimits => {
                self.dispatch_mf_transform_get_stream_limits(state, memory)
            }
            MfTransformGetStreamCounts => {
                self.dispatch_mf_transform_get_stream_counts(state, memory)
            }
            MfTransformGetStreamIds => self.dispatch_mf_transform_get_stream_ids(state, memory),
            MfTransformGetStreamInfo => self.dispatch_mf_transform_get_stream_info(state, memory),
            MfTransformGetAttributes => self.dispatch_mf_transform_get_attributes(state, memory),
            MfTransformGetInputAvailableType => {
                self.dispatch_mf_transform_get_input_available_type(state, memory)
            }
            MfTransformGetOutputAvailableType => {
                self.dispatch_mf_transform_get_output_available_type(state, memory)
            }
            MfTransformSetInputType => self.dispatch_mf_transform_set_input_type(state, memory),
            MfTransformSetOutputType => self.dispatch_mf_transform_set_output_type(state, memory),
            MfTransformGetInputCurrentType => {
                self.dispatch_mf_transform_get_input_current_type(state, memory)
            }
            MfTransformGetOutputCurrentType => {
                self.dispatch_mf_transform_get_output_current_type(state, memory)
            }
            MfTransformGetInputStatus => self.dispatch_mf_transform_get_input_status(state, memory),
            MfTransformGetOutputStatus => {
                self.dispatch_mf_transform_get_output_status(state, memory)
            }
            MfTransformProcessInput => self.dispatch_mf_transform_process_input(state, memory),
            MfTransformProcessOutput => self.dispatch_mf_transform_process_output(state, memory),
            MfTransformProcessMessage => self.dispatch_mf_transform_process_message(state, memory),
            MftTransformUnsupported => self.dispatch_mft_unsupported(state, memory),
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted MF/COM thunk {thunk:?}"),
            )),
        }
    }
}

/// The IMFAttributes vtable (media types and attribute stores share it).
fn mf_attributes_methods() -> Vec<HostThunk> {
    // The true IMFAttributes vtable order: IUnknown + GetItem, GetItemType,
    // CompareItem, Compare, the typed getters, the setters, the store
    // management, GetCount/GetItemByIndex, CopyAllItems.
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfAttrGetItem);
    methods.push(HostThunk::MfAttrGetItemType);
    methods.push(HostThunk::MfAttrCompareItem);
    methods.push(HostThunk::MfAttrCompare);
    methods.push(HostThunk::MfAttrGetUint32);
    methods.push(HostThunk::MfAttrGetUint64);
    methods.push(HostThunk::MfAttrGetDouble);
    methods.push(HostThunk::MfAttrGetGuid);
    methods.push(HostThunk::MfAttrGetStringLength);
    methods.push(HostThunk::MfAttrGetString);
    methods.push(HostThunk::MfAttrGetAllocatedString);
    methods.push(HostThunk::MfAttrGetBlobSize);
    methods.push(HostThunk::MfAttrGetBlob);
    methods.push(HostThunk::MfAttrGetAllocatedBlob);
    methods.push(HostThunk::MfAttrGetUnknown);
    methods.push(HostThunk::MfAttrSetItem);
    methods.push(HostThunk::MfAttrSetUint32);
    methods.push(HostThunk::MfAttrSetUint64);
    methods.push(HostThunk::MfAttrSetDouble);
    methods.push(HostThunk::MfAttrSetGuid);
    methods.push(HostThunk::MfAttrSetString);
    methods.push(HostThunk::MfAttrSetBlob);
    methods.push(HostThunk::MfAttrSetUnknown);
    methods.push(HostThunk::MfAttrDeleteAllItems);
    methods.push(HostThunk::MfAttrDeleteItem);
    methods.push(HostThunk::MfAttrLockStore);
    methods.push(HostThunk::MfAttrUnlockStore);
    methods.push(HostThunk::MfAttrGetCount);
    methods.push(HostThunk::MfAttrGetItemByIndex);
    methods.push(HostThunk::MfAttrCopyAllItems);
    methods
}

/// The IMFMediaType vtable (attributes + the media-type methods).
fn mf_media_type_methods() -> Vec<HostThunk> {
    // The true IMFMediaType order: the attributes + GetMajorType,
    // IsCompressedFormat, IsEqual, GetRepresentation, FreeRepresentation.
    let mut methods = mf_attributes_methods();
    methods.push(HostThunk::MfMediaTypeGetMajorType);
    methods.push(HostThunk::MfMediaTypeIsCompressedFormat);
    methods.push(HostThunk::MfMediaTypeIsEqual);
    methods.push(HostThunk::MfMediaTypeGetRepresentation);
    methods.push(HostThunk::MfMediaTypeFreeRepresentation);
    methods
}

/// The IMFMediaBuffer vtable.
fn mf_media_buffer_methods() -> Vec<HostThunk> {
    // The true IMFMediaBuffer order: Lock, Unlock, GetCurrentLength,
    // SetCurrentLength, GetMaxLength.
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfBufferLock);
    methods.push(HostThunk::MfBufferUnlock);
    methods.push(HostThunk::MfBufferGetCurrentLength);
    methods.push(HostThunk::MfBufferSetCurrentLength);
    methods.push(HostThunk::MfBufferGetMaxLength);
    methods
}

/// The IMFSample vtable.
fn mf_sample_methods() -> Vec<HostThunk> {
    // The true IMFSample order: the flags, the timestamps, the buffers,
    // and the contiguous conversion.
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfSampleSetSampleFlags);
    methods.push(HostThunk::MfSampleGetSampleFlags);
    methods.push(HostThunk::MfSampleSetSampleTime);
    methods.push(HostThunk::MfSampleGetSampleTime);
    methods.push(HostThunk::MfSampleSetSampleDuration);
    methods.push(HostThunk::MfSampleGetSampleDuration);
    methods.push(HostThunk::MfSampleGetBufferCount);
    methods.push(HostThunk::MfSampleGetBufferByIndex);
    methods.push(HostThunk::MfSampleAddBuffer);
    methods.push(HostThunk::MfSampleRemoveBufferByIndex);
    methods.push(HostThunk::MfSampleRemoveAllBuffers);
    methods.push(HostThunk::MfSampleGetTotalLength);
    methods.push(HostThunk::MfSampleCopyToBuffer);
    methods.push(HostThunk::MfSampleConvertToContiguousBuffer);
    methods
}

/// The IMFMediaEventQueue vtable.
fn mf_event_queue_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfEventQueueGetEvent);
    methods.push(HostThunk::MfEventQueueQueueEvent);
    methods
}

/// The IMFPresentationClock vtable.
fn mf_clock_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfClockGetTime);
    methods.push(HostThunk::MfClockStart);
    methods.push(HostThunk::MfClockStop);
    methods
}

/// The IMFRateControl vtable (the session rate-control service object):
/// the real method order SetRate, GetRate.
fn mf_rate_control_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfRateControlSetRate);
    methods.push(HostThunk::MfRateControlGetRate);
    methods
}

/// The IMFRateSupport vtable (the session rate-support service object):
/// the real method order GetSlowestRate, GetFastestRate, IsRateSupported.
fn mf_rate_support_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfRateSupportGetSlowestRate);
    methods.push(HostThunk::MfRateSupportGetFastestRate);
    methods.push(HostThunk::MfRateSupportIsRateSupported);
    methods
}

/// The IMFMediaSession vtable.
fn mf_session_methods() -> Vec<HostThunk> {
    // The true IMFMediaSession order: SetTopology, ClearTopologies, Start,
    // Pause, Stop, Close, Shutdown, GetClock, GetSessionCapabilities,
    // GetFullTopology, GetDescriptorFromTopology.
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfSessionSetTopology);
    methods.push(HostThunk::MfSessionSetTopology); // ClearTopologies
    methods.push(HostThunk::MfSessionStart);
    methods.push(HostThunk::MfSessionPause);
    methods.push(HostThunk::MfSessionStop);
    methods.push(HostThunk::MfSessionClose);
    methods.push(HostThunk::MfSessionShutdown);
    methods.push(HostThunk::MfSessionGetClock);
    methods.push(HostThunk::MfSessionGetSessionCapabilities);
    methods.push(HostThunk::MfSessionGetFullTopology);
    methods.push(HostThunk::MfSessionGetDescriptorFromTopology);
    methods
}

/// The IMFSourceReader vtable (the true Windows order: GetStreamSelection,
/// SetStreamSelection, GetNativeMediaType, GetCurrentMediaType,
/// SetCurrentMediaType, SetCurrentPosition, ReadSample, Flush,
/// GetServiceForStream, GetPresentationAttribute).
fn mf_source_reader_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfSourceReaderGetStreamSelection);
    methods.push(HostThunk::MfSourceReaderSetStreamSelection);
    methods.push(HostThunk::MfSourceReaderGetNativeMediaType);
    methods.push(HostThunk::MfSourceReaderGetCurrentMediaType);
    methods.push(HostThunk::MfSourceReaderSetCurrentMediaType);
    methods.push(HostThunk::MfSourceReaderSetCurrentPosition);
    methods.push(HostThunk::MfSourceReaderReadSample);
    methods.push(HostThunk::MfSourceReaderFlush);
    methods.push(HostThunk::MfSourceReaderGetServiceForStream);
    methods.push(HostThunk::MfSourceReaderGetPresentationAttribute);
    methods
}

/// The IMFSinkWriter vtable.
fn mf_sink_writer_methods() -> Vec<HostThunk> {
    // The true IMFSinkWriter order: AddStream, SetInputMediaType,
    // BeginWriting, WriteSample, SendStreamSample, Flush,
    // NotifyEndOfSegment, EndWriting, GetServiceForStream, GetStatistics.
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfSinkWriterAddStream);
    methods.push(HostThunk::MfSinkWriterSetInputMediaType);
    methods.push(HostThunk::MfSinkWriterBeginWriting);
    methods.push(HostThunk::MfSinkWriterWriteSample);
    methods.push(HostThunk::MfSinkWriterSendStreamSample);
    methods.push(HostThunk::MfSinkWriterFlush);
    methods.push(HostThunk::MfSinkWriterNotifyEndOfSegment);
    methods.push(HostThunk::MfSinkWriterEndWriting);
    methods.push(HostThunk::MfSinkWriterGetServiceForStream);
    methods.push(HostThunk::MfSinkWriterGetStatistics);
    methods
}

/// The IMFByteStream vtable (the true Windows order: GetCapabilities,
/// GetLength, SetLength, GetCurrentPosition, SetCurrentPosition,
/// IsEndOfStream, Read, BeginRead, EndRead, Write, BeginWrite, EndWrite,
/// Seek, Flush, Close).
fn mf_byte_stream_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfByteStreamGetCapabilities);
    methods.push(HostThunk::MfByteStreamGetLength);
    methods.push(HostThunk::MfByteStreamSetLength);
    methods.push(HostThunk::MfByteStreamGetCurrentPosition);
    methods.push(HostThunk::MfByteStreamSetCurrentPosition);
    methods.push(HostThunk::MfByteStreamIsEndOfStream);
    methods.push(HostThunk::MfByteStreamRead);
    methods.push(HostThunk::MfByteStreamBeginRead);
    methods.push(HostThunk::MfByteStreamEndRead);
    methods.push(HostThunk::MfByteStreamWrite);
    methods.push(HostThunk::MfByteStreamBeginWrite);
    methods.push(HostThunk::MfByteStreamEndWrite);
    methods.push(HostThunk::MfByteStreamSeek);
    methods.push(HostThunk::MfByteStreamFlush);
    methods.push(HostThunk::MfByteStreamClose);
    methods
}

/// The IMFTopology vtable.
fn mf_topology_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfTopologyAddNode);
    methods.push(HostThunk::MfTopologyGetNodeCount);
    methods
}

/// The IMFTopologyNode vtable.
fn mf_topology_node_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfTopologyNodeGetObject);
    methods.push(HostThunk::MfTopologyNodeSetObject);
    methods
}

/// The IMFSourceResolver vtable.
fn mf_source_resolver_methods() -> Vec<HostThunk> {
    // The true IMFSourceResolver order: BeginCreateObjectFromURL,
    // BeginCreateObjectFromByteStream, EndCreateObjectFromURL,
    // EndCreateObjectFromByteStream, CancelObjectCreation,
    // CreateObjectFromURL, CreateObjectFromByteStream.
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfSourceResolverBegin);
    methods.push(HostThunk::MfSourceResolverBegin);
    methods.push(HostThunk::MfSourceResolverBegin);
    methods.push(HostThunk::MfSourceResolverBegin);
    methods.push(HostThunk::MfSourceResolverBegin);
    methods.push(HostThunk::MfSourceResolverCreateObjectFromUrl);
    methods.push(HostThunk::MfSourceResolverBegin);
    methods
}

/// The IMFDXGIDeviceManager vtable (IUnknown preamble + the 7 device
/// methods).
pub(crate) fn mf_dxgi_device_manager_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfDxgiDeviceManagerResetDevice);
    methods.push(HostThunk::MfDxgiDeviceManagerOpenDeviceHandle);
    methods.push(HostThunk::MfDxgiDeviceManagerCloseDeviceHandle);
    methods.push(HostThunk::MfDxgiDeviceManagerTestDevice);
    methods.push(HostThunk::MfDxgiDeviceManagerLockDevice);
    methods.push(HostThunk::MfDxgiDeviceManagerUnlockDevice);
    methods.push(HostThunk::MfDxgiDeviceManagerGetVideoService);
    methods
}

/// The IMFPresentationDescriptor vtable: the IMFAttributes base followed by
/// GetStreamDescriptorCount, GetStreamDescriptorByIndex, SelectStream,
/// DeselectStream, Clone.
fn mf_presentation_descriptor_methods() -> Vec<HostThunk> {
    let mut methods = mf_attributes_methods();
    methods.push(HostThunk::MfPresentationDescriptorGetStreamDescriptorCount);
    methods.push(HostThunk::MfPresentationDescriptorGetStreamDescriptorByIndex);
    methods.push(HostThunk::MfPresentationDescriptorSelectStream);
    methods.push(HostThunk::MfPresentationDescriptorDeselectStream);
    methods.push(HostThunk::MfPresentationDescriptorClone);
    methods
}

/// The IMFStreamDescriptor vtable: the IMFAttributes base followed by
/// GetStreamIdentifier and GetMediaTypeHandler.
fn mf_stream_descriptor_methods() -> Vec<HostThunk> {
    let mut methods = mf_attributes_methods();
    methods.push(HostThunk::MfStreamDescriptorGetStreamIdentifier);
    methods.push(HostThunk::MfStreamDescriptorGetMediaTypeHandler);
    methods
}

/// The IMFMediaTypeHandler vtable (the true order: IsMediaTypeSupported,
/// GetMediaTypeCount, GetMediaTypeByIndex, SetCurrentMediaType,
/// GetCurrentMediaType, GetMajorType).
fn mf_media_type_handler_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfMediaTypeHandlerIsMediaTypeSupported);
    methods.push(HostThunk::MfMediaTypeHandlerGetMediaTypeCount);
    methods.push(HostThunk::MfMediaTypeHandlerGetMediaTypeByIndex);
    methods.push(HostThunk::MfMediaTypeHandlerSetCurrentMediaType);
    methods.push(HostThunk::MfMediaTypeHandlerGetCurrentMediaType);
    methods.push(HostThunk::MfMediaTypeHandlerGetMajorType);
    methods
}

/// The IMFMediaSource vtable: the IMFMediaEventGenerator base (GetEvent,
/// BeginGetEvent, EndGetEvent, QueueEvent) followed by GetCharacteristics,
/// CreatePresentationDescriptor, Start, Stop, Pause, Shutdown.  The
/// runtime-extension CancelGetEvent slot is appended after the documented
/// surface (the Windows IMFMediaEventGenerator publishes no cancel method;
/// this runtime models the request lifetime explicitly).
fn mf_media_source_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfMediaSourceGetEvent);
    methods.push(HostThunk::MfMediaSourceBeginGetEvent);
    methods.push(HostThunk::MfMediaSourceEndGetEvent);
    methods.push(HostThunk::MfMediaSourceQueueEvent);
    methods.push(HostThunk::MfMediaSourceGetCharacteristics);
    methods.push(HostThunk::MfMediaSourceCreatePresentationDescriptor);
    methods.push(HostThunk::MfMediaSourceStart);
    methods.push(HostThunk::MfMediaSourceStop);
    methods.push(HostThunk::MfMediaSourcePause);
    methods.push(HostThunk::MfMediaSourceShutdown);
    methods.push(HostThunk::MfMediaSourceCancelGetEvent);
    methods
}

/// The IMFMediaSourceEx vtable: the IMFMediaSource methods followed by
/// GetSourceAttributes, GetStreamAttributes and SetD3DManager.
fn mf_media_source_ex_methods() -> Vec<HostThunk> {
    let mut methods = mf_media_source_methods();
    methods.push(HostThunk::MfMediaSourceGetSourceAttributes);
    methods.push(HostThunk::MfMediaSourceGetStreamAttributes);
    methods.push(HostThunk::MfMediaSourceSetD3dManager);
    methods
}

/// The IMFMediaEvent vtable: the IMFAttributes base followed by GetType,
/// GetExtendedType, GetStatus and GetValue.
fn mf_event_methods() -> Vec<HostThunk> {
    let mut methods = mf_attributes_methods();
    methods.push(HostThunk::MfEventGetType);
    methods.push(HostThunk::MfEventGetExtendedType);
    methods.push(HostThunk::MfEventGetStatus);
    methods.push(HostThunk::MfEventGetValue);
    methods
}

/// The IMFAsyncResult vtable (GetState, GetStatus, SetStatus, GetObject,
/// GetCallback) used by the synchronous BeginRead/BeginWrite completions.
fn mf_async_result_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfAsyncResultGetState);
    methods.push(HostThunk::MfAsyncResultGetStatus);
    methods.push(HostThunk::MfAsyncResultSetStatus);
    methods.push(HostThunk::MfAsyncResultGetObject);
    methods.push(HostThunk::MfAsyncResultGetCallback);
    methods
}

/// Write an f64 into guest memory.
#[allow(dead_code)] // used by the GetDouble path
fn write_guest_double(memory: &mut MemoryImage, address: u64, value: f64) {
    for (index, byte) in value.to_le_bytes().iter().enumerate() {
        memory.write_u8(address + index as u64, *byte);
    }
}

/// Read an f64 from guest memory.
#[allow(dead_code)] // used by the GetDouble path
fn read_guest_double(memory: &MemoryImage, address: u64) -> f64 {
    let mut bytes = [0_u8; 8];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = memory.read_u8(address + index as u64).unwrap_or(0);
    }
    f64::from_le_bytes(bytes)
}

/// Read a 16-byte GUID from guest memory.
#[allow(dead_code)] // used by the attribute paths
fn read_guest_guid(memory: &MemoryImage, address: u64) -> Guid {
    let mut bytes = [0_u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = memory.read_u8(address + index as u64).unwrap_or(0);
    }
    Guid::from_bytes_le(&bytes)
}

/// Write a 16-byte GUID into guest memory.
#[allow(dead_code)] // used by the attribute-by-index path
fn write_guest_guid(memory: &mut MemoryImage, address: u64, guid: Guid) {
    let bytes = guid.to_bytes_le();
    for (index, byte) in bytes.iter().enumerate() {
        memory.write_u8(address + index as u64, *byte);
    }
}

/// The IMFActivate vtable: the IUnknown preamble + the key attribute and
/// activation methods.
#[allow(dead_code)] // the activation vtable builder
fn mft_activate_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfActivateGetCount);
    methods.push(HostThunk::MfActivateGetItem);
    methods.push(HostThunk::MfActivateGetGuid);
    methods.push(HostThunk::MfActivateGetString);
    methods.push(HostThunk::MfActivateActivateObject);
    methods.push(HostThunk::MfActivateShutdownObject);
    methods
}

/// The IMFTransform vtable: the IUnknown preamble + the 17 transform
/// methods.
#[allow(dead_code)] // the transform vtable builder
fn mft_transform_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfTransformGetStreamLimits);
    methods.push(HostThunk::MfTransformGetStreamCounts);
    methods.push(HostThunk::MfTransformGetStreamIds);
    methods.push(HostThunk::MfTransformGetStreamInfo);
    methods.push(HostThunk::MfTransformGetAttributes);
    methods.push(HostThunk::MfTransformGetInputAvailableType);
    methods.push(HostThunk::MfTransformGetOutputAvailableType);
    methods.push(HostThunk::MfTransformSetInputType);
    methods.push(HostThunk::MfTransformSetOutputType);
    methods.push(HostThunk::MfTransformGetInputCurrentType);
    methods.push(HostThunk::MfTransformGetOutputCurrentType);
    methods.push(HostThunk::MfTransformGetInputStatus);
    methods.push(HostThunk::MfTransformGetOutputStatus);
    methods.push(HostThunk::MfTransformProcessInput);
    methods.push(HostThunk::MfTransformProcessOutput);
    methods.push(HostThunk::MfTransformProcessMessage);
    methods.push(HostThunk::MftTransformUnsupported);
    methods
}

/// Read a GUID from a guest pointer.
fn read_mf_guid(memory: &MemoryImage, pointer: u64) -> Guid {
    let bytes = memory.read_bytes(pointer, 16).unwrap_or_default();
    mf_guid_from_bytes(&bytes)
}

/// Map a runtime file-open failure to the Win32 HRESULT a guest expects.
fn win32_error_to_hresult(error: &crate::error::AppError) -> u32 {
    use crate::reason::ReasonCode;
    match error.code {
        ReasonCode::RcFsNotFound => 0x8007_0002, // HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
        ReasonCode::RcFsAlreadyExists => 0x8007_00B7, // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
        ReasonCode::RcHelperPermissionDenied => E_ACCESSDENIED,
        _ => 0x8007_0003, // HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)
    }
}

/// A GUID from the guest little-endian bytes (the data1..data4 fields).
fn mf_guid_from_bytes(bytes: &[u8]) -> Guid {
    if bytes.len() < 16 {
        return Guid::new(0, 0, 0, [0; 8]);
    }
    Guid::new(
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        [
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ],
    )
}

/// The PROPVARIANT (vt, bytes) for an attribute value.
fn mf_attribute_propvariant(mt: &ImfMediaType, key: Guid) -> Option<(u32, Vec<u8>)> {
    use crate::media::MediaTypeValue;
    match mt.attributes.get(&key) {
        Some(MediaTypeValue::Uint32(value)) => Some((19, value.to_le_bytes().to_vec())),
        Some(MediaTypeValue::Uint64(value)) => Some((21, value.to_le_bytes().to_vec())),
        Some(MediaTypeValue::Double(value)) => Some((5, value.to_bits().to_le_bytes().to_vec())),
        Some(MediaTypeValue::Guid(guid)) => {
            let mut bytes = Vec::with_capacity(16);
            bytes.extend_from_slice(&guid.data1.to_le_bytes());
            bytes.extend_from_slice(&guid.data2.to_le_bytes());
            bytes.extend_from_slice(&guid.data3.to_le_bytes());
            bytes.extend_from_slice(&guid.data4);
            Some((72, bytes))
        }
        Some(MediaTypeValue::String(text)) => {
            let mut bytes = Vec::new();
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            bytes.extend_from_slice(&0_u16.to_le_bytes());
            Some((31, bytes))
        }
        Some(MediaTypeValue::Blob(blob)) => Some((0x1011, blob.clone())),
        None => None,
    }
}

// ===========================================================================
// MFGetService tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ge::{GameEnvironment, GeArch};
    use tempfile::TempDir;

    /// A runtime configured for x86 guest calls, mirroring the runtime-wide
    /// test harness (deterministic per-arch thunk/data/heap bases).
    fn mf_test_runtime(name: &str) -> (PeHostRuntime, TempDir) {
        let temp_dir = TempDir::new().expect("temp dir");
        let ge = GameEnvironment::create_in(temp_dir.path(), name, GeArch::X86, "win11-23h2")
            .expect("create ge");
        let mut runtime = PeHostRuntime::new(ge, true, Vec::new(), None, None);
        runtime.guest_arch = GuestArch::X86;
        runtime.next_thunk_address = thunk_base_for_arch(GuestArch::X86);
        runtime.next_data_address = data_base_for_arch(GuestArch::X86);
        runtime.next_heap_address = heap_base_for_arch(GuestArch::X86);
        runtime
            .win32
            .reset_address_space(private_pages_base_for_arch(GuestArch::X86));
        runtime.x86_heap_region = 0;
        (runtime, temp_dir)
    }

    /// Dispatch an x86 thunk whose arguments are pushed on a scratch stack,
    /// exactly like the runtime-wide `dispatch_x86_thunk` helper.
    fn dispatch_x86_thunk(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        thunk: u64,
        args: &[u32],
    ) -> u64 {
        let stack = 0x50_000;
        memory.map_bytes(stack, &[0_u8; 0x200]);
        write_u32(memory, stack, 0xDEAD_BEEF);
        for (index, arg) in args.iter().enumerate() {
            write_u32(memory, stack + 4 + (index as u64 * 4), *arg);
        }
        let mut state = CpuState::new(GuestArch::X86);
        state.set(Register::Rsp, stack);
        runtime
            .dispatch_import(thunk, &mut state, memory)
            .unwrap_or_else(|error| panic!("dispatch x86 thunk: {error}"));
        state.get(Register::Rax)
    }

    /// Run a test body on an 8 MiB stack thread: guest dispatch recurses
    /// (the same harness the runtime-wide evidence tests use).
    fn with_big_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(body)
            .expect("spawn big-stack thread")
            .join()
            .expect("big-stack thread panicked")
    }

    fn write_guest_guid_bytes(memory: &mut MemoryImage, address: u64, bytes: &[u8; 16]) {
        memory.map_bytes(address, bytes);
    }

    /// Create a media session guest object through the MFCreateMediaSession
    /// thunk; returns the object address.
    fn create_session(runtime: &mut PeHostRuntime, memory: &mut MemoryImage) -> u64 {
        let create_session: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateMediaSession);
        let session_out = 0x41_000;
        let hr = dispatch_x86_thunk(runtime, memory, create_session, &[0, session_out as u32]);
        assert_eq!(hr, 0, "MFCreateMediaSession");
        let session = read_guest_pointer(memory, session_out, GuestArch::X86).unwrap();
        assert_ne!(session, 0);
        assert!(runtime.mf_sessions.contains_key(&session));
        session
    }

    #[test]
    fn mf_get_service_media_session_service_returns_the_session() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-service-session");
            let mut memory = MemoryImage::default();
            let session = create_session(&mut runtime, &mut memory);
            let get_service: u64 = runtime.alloc_host_thunk(HostThunk::MfGetService);

            let guid = 0x44_000;
            let iid = 0x44_100;
            let out = 0x44_200;
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_MEDIA_SESSION);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_MEDIA_SESSION);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, 0, "the session owns the media-session service");
            let service = read_guest_pointer(&memory, out, GuestArch::X86).unwrap();
            assert_eq!(service, session, "the service IS the session object");
            assert_eq!(
                runtime.guest_objects.get(&session).unwrap().refcount,
                2,
                "the handed-out interface carries its own reference"
            );

            // IUnknown is also an acceptable interface for the same service.
            write_guest_guid_bytes(&mut memory, iid, &IID_IUNKNOWN);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, 0);
            assert_eq!(
                read_guest_pointer(&memory, out, GuestArch::X86).unwrap(),
                session
            );
        })
    }

    #[test]
    fn mf_get_service_unsupported_service_and_interface() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-service-unsupported");
            let mut memory = MemoryImage::default();
            let session = create_session(&mut runtime, &mut memory);
            let get_service: u64 = runtime.alloc_host_thunk(HostThunk::MfGetService);

            let guid = 0x44_000;
            let iid = 0x44_100;
            let out = 0x44_200;
            // MF_TIMECODE_SERVICE {a0d502a7-0eb3-4885-b1b9-9feb0d083454}: a real
            // Windows service GUID the session does not own (ASF sources own it).
            let timecode_service: [u8; 16] = [
                0xa7, 0x02, 0xd5, 0xa0, 0xb3, 0x0e, 0x85, 0x48, 0xb1, 0xb9, 0x9f, 0xeb, 0x0d, 0x08,
                0x34, 0x54,
            ];
            write_guest_guid_bytes(&mut memory, guid, &timecode_service);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_MEDIA_SESSION);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_SERVICE as u64);
            assert_eq!(
                read_guest_pointer(&memory, out, GuestArch::X86).unwrap(),
                0,
                "the output pointer is nulled on failure"
            );

            // The media-session service answered with the wrong interface.
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_MEDIA_SESSION);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_RATE_CONTROL);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_SERVICE as u64);

            // The source-side services belong to real sources / byte streams,
            // never to the session object.
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_MEDIASOURCE);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_MEDIA_SOURCE);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_SERVICE as u64);
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_BYTESTREAM_ORIGIN_NAME);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_ATTRIBUTES);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_SERVICE as u64);
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_METADATA_PROVIDER);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_SERVICE as u64);
        })
    }

    #[test]
    fn mf_get_service_rate_control_set_and_get_rate() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-service-rate");
            let mut memory = MemoryImage::default();
            let session = create_session(&mut runtime, &mut memory);
            let get_service: u64 = runtime.alloc_host_thunk(HostThunk::MfGetService);
            let set_rate: u64 = runtime.alloc_host_thunk(HostThunk::MfRateControlSetRate);
            let get_rate: u64 = runtime.alloc_host_thunk(HostThunk::MfRateControlGetRate);

            let guid = 0x44_000;
            let iid = 0x44_100;
            let out = 0x44_200;
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_RATE_CONTROL);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_RATE_CONTROL);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, 0, "the session owns the rate-control service");
            let rate_control = read_guest_pointer(&memory, out, GuestArch::X86).unwrap();
            assert_ne!(rate_control, 0);
            assert_eq!(
                runtime.mf_rate_services.get(&rate_control).copied(),
                Some(session),
                "the service object is registered to its owning session"
            );
            assert_eq!(
                runtime.guest_object_kind(rate_control).unwrap(),
                GuestObjectKind::ImfRateControlService
            );

            // The session starts at 1.0x.
            let thin_out = 0x44_300;
            let rate_out = 0x44_310;
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_rate,
                &[rate_control as u32, thin_out as u32, rate_out as u32],
            );
            assert_eq!(hr, 0);
            assert_eq!(read_guest_u32(&memory, thin_out).unwrap(), 0);
            assert_eq!(
                read_guest_u32(&memory, rate_out).unwrap(),
                1.0_f32.to_bits()
            );

            // SetRate(2.0) is stored on the session (real rate semantics).
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_rate,
                &[rate_control as u32, 0, 2.0_f32.to_bits()],
            );
            assert_eq!(hr, 0);
            assert_eq!(runtime.mf_sessions.get(&session).unwrap().get_rate(), 2.0);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_rate,
                &[rate_control as u32, thin_out as u32, rate_out as u32],
            );
            assert_eq!(hr, 0);
            assert_eq!(
                read_guest_u32(&memory, rate_out).unwrap(),
                2.0_f32.to_bits()
            );

            // Unsupported rates: thinned playback, slow motion, reverse.
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_rate,
                &[rate_control as u32, 1, 1.0_f32.to_bits()],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_RATE as u64);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_rate,
                &[rate_control as u32, 0, 0.5_f32.to_bits()],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_RATE as u64);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_rate,
                &[rate_control as u32, 0, (-2.0_f32).to_bits()],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_RATE as u64);
            assert_eq!(
                runtime.mf_sessions.get(&session).unwrap().get_rate(),
                2.0,
                "a rejected rate never mutates the session"
            );
        })
    }

    #[test]
    fn mf_get_service_rate_support_bounds() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-service-rate-support");
            let mut memory = MemoryImage::default();
            let session = create_session(&mut runtime, &mut memory);
            let get_service: u64 = runtime.alloc_host_thunk(HostThunk::MfGetService);
            let slowest: u64 = runtime.alloc_host_thunk(HostThunk::MfRateSupportGetSlowestRate);
            let fastest: u64 = runtime.alloc_host_thunk(HostThunk::MfRateSupportGetFastestRate);
            let supported: u64 = runtime.alloc_host_thunk(HostThunk::MfRateSupportIsRateSupported);

            let guid = 0x44_000;
            let iid = 0x44_100;
            let out = 0x44_200;
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_RATE_CONTROL);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_RATE_SUPPORT);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, 0);
            let rate_support = read_guest_pointer(&memory, out, GuestArch::X86).unwrap();
            assert_ne!(rate_support, 0);
            assert_eq!(
                runtime.mf_rate_services.get(&rate_support).copied(),
                Some(session)
            );

            // Forward non-thinned: slowest 1.0, fastest unbounded.
            let rate_out = 0x44_300;
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                slowest,
                &[rate_support as u32, MFRATE_FORWARD, 0, rate_out as u32],
            );
            assert_eq!(hr, 0);
            assert_eq!(
                read_guest_u32(&memory, rate_out).unwrap(),
                MF_SESSION_SLOWEST_FORWARD_RATE.to_bits()
            );
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                fastest,
                &[rate_support as u32, MFRATE_FORWARD, 0, rate_out as u32],
            );
            assert_eq!(hr, 0);
            assert_eq!(
                read_guest_u32(&memory, rate_out).unwrap(),
                f32::MAX.to_bits()
            );

            // Reverse direction and thinning are not backed.
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                slowest,
                &[rate_support as u32, MFRATE_REVERSE, 0, rate_out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_RATE as u64);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                fastest,
                &[rate_support as u32, MFRATE_FORWARD, 1, rate_out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_RATE as u64);

            // IsRateSupported: >= 1.0x forward yes, slower rates carry the
            // nearest supported rate out.
            let nearest_out = 0x44_320;
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                supported,
                &[
                    rate_support as u32,
                    0,
                    4.0_f32.to_bits(),
                    nearest_out as u32,
                ],
            );
            assert_eq!(hr, 0);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                supported,
                &[
                    rate_support as u32,
                    0,
                    0.5_f32.to_bits(),
                    nearest_out as u32,
                ],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_RATE as u64);
            assert_eq!(
                read_guest_u32(&memory, nearest_out).unwrap(),
                MF_SESSION_SLOWEST_FORWARD_RATE.to_bits()
            );
        })
    }

    #[test]
    fn mf_get_service_rate_service_release_forgets_the_owner() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-service-rate-release");
            let mut memory = MemoryImage::default();
            let session = create_session(&mut runtime, &mut memory);
            let get_service: u64 = runtime.alloc_host_thunk(HostThunk::MfGetService);
            let release: u64 = runtime.alloc_host_thunk(HostThunk::GuestObjectRelease);
            let get_rate: u64 = runtime.alloc_host_thunk(HostThunk::MfRateControlGetRate);

            let guid = 0x44_000;
            let iid = 0x44_100;
            let out = 0x44_200;
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_RATE_CONTROL);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_RATE_CONTROL);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, 0);
            let rate_control = read_guest_pointer(&memory, out, GuestArch::X86).unwrap();
            let hr = dispatch_x86_thunk(&mut runtime, &mut memory, release, &[rate_control as u32]);
            assert_eq!(hr, 0, "release of the fresh reference");
            assert!(
                !runtime.mf_rate_services.contains_key(&rate_control),
                "releasing the service object drops its owner registration"
            );
            let rate_out = 0x44_300;
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_rate,
                &[rate_control as u32, 0, rate_out as u32],
            );
            assert_eq!(hr, E_NOINTERFACE as u64);
        })
    }

    #[test]
    fn mf_get_service_resolves_the_session_from_its_topology_graph() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-service-graph");
            let mut memory = MemoryImage::default();
            let session = create_session(&mut runtime, &mut memory);
            let create_topology: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateTopology);
            let create_node: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateTopologyNode);
            let add_node: u64 = runtime.alloc_host_thunk(HostThunk::MfTopologyAddNode);
            let set_topology: u64 = runtime.alloc_host_thunk(HostThunk::MfSessionSetTopology);
            let get_service: u64 = runtime.alloc_host_thunk(HostThunk::MfGetService);

            let topology_out = 0x41_100;
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_topology,
                &[topology_out as u32],
            );
            assert_eq!(hr, 0);
            let topology = read_guest_pointer(&memory, topology_out, GuestArch::X86).unwrap();

            let node_out = 0x41_200;
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                create_node,
                &[0, node_out as u32],
            );
            assert_eq!(hr, 0);
            let node = read_guest_pointer(&memory, node_out, GuestArch::X86).unwrap();

            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                add_node,
                &[topology as u32, node as u32],
            );
            assert_eq!(hr, 0);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                set_topology,
                &[session as u32, 0, topology as u32],
            );
            assert_eq!(hr, 0);
            assert_eq!(
                runtime.mf_session_topologies.get(&session).copied(),
                Some(topology)
            );

            // The topology object resolves to its owning session.
            let guid = 0x44_000;
            let iid = 0x44_100;
            let out = 0x44_200;
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_MEDIA_SESSION);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_MEDIA_SESSION);
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[topology as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, 0, "a session topology is owned by the session");
            assert_eq!(
                read_guest_pointer(&memory, out, GuestArch::X86).unwrap(),
                session
            );

            // And so does a topology node inside that topology.
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[node as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(
                hr, 0,
                "a node of the session topology is owned by the session"
            );
            assert_eq!(
                read_guest_pointer(&memory, out, GuestArch::X86).unwrap(),
                session
            );
        })
    }

    #[test]
    fn mf_get_service_objects_without_services_answer_unsupported() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-service-unowned");
            let mut memory = MemoryImage::default();
            let session = create_session(&mut runtime, &mut memory);
            let get_service: u64 = runtime.alloc_host_thunk(HostThunk::MfGetService);

            let guid = 0x44_000;
            let iid = 0x44_100;
            let out = 0x44_200;
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_MEDIA_SESSION);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_MEDIA_SESSION);

            // An object with no provider table (a media event queue) does not
            // own the session services.
            let create_queue: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateEventQueue);
            let queue_out = 0x41_300;
            let hr =
                dispatch_x86_thunk(&mut runtime, &mut memory, create_queue, &[queue_out as u32]);
            assert_eq!(hr, 0);
            let queue = read_guest_pointer(&memory, queue_out, GuestArch::X86).unwrap();
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[queue as u32, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_SERVICE as u64);
            assert_eq!(read_guest_pointer(&memory, out, GuestArch::X86).unwrap(), 0);

            // A pointer that is not a runtime-registered object at all.
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[0x00C0_FFEE, guid as u32, iid as u32, out as u32],
            );
            assert_eq!(hr, MF_E_UNSUPPORTED_SERVICE as u64);

            // Null output pointer is an argument error.
            let hr = dispatch_x86_thunk(
                &mut runtime,
                &mut memory,
                get_service,
                &[session as u32, guid as u32, iid as u32, 0],
            );
            assert_eq!(hr, E_INVALIDARG as u64);
        })
    }

    // =======================================================================
    // Real source-side tests: file-table byte streams, media sources,
    // descriptors, events and service resolution.
    // =======================================================================

    /// A minimal but fully valid MP4: `ftyp` + `moov` (one `vide` track with
    /// two 4-byte samples described by real `stbl` tables) + `mdat`.  The
    /// `stco` chunk offset is patched to the real `mdat` payload, so the
    /// demuxer reads the actual sample bytes.
    fn minimal_mp4_file() -> Vec<u8> {
        fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(8 + payload.len());
            out.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(payload);
            out
        }

        let ftyp = boxed(b"ftyp", b"mp42\0\0\0\0");
        let mut tkhd_payload = vec![0_u8; 12];
        tkhd_payload.extend_from_slice(&1_u32.to_be_bytes());
        let tkhd = boxed(b"tkhd", &tkhd_payload);
        let mut mdhd_payload = vec![0_u8; 12];
        mdhd_payload.extend_from_slice(&600_u32.to_be_bytes()); // timescale
        mdhd_payload.extend_from_slice(&1200_u32.to_be_bytes()); // duration (2 s)
        mdhd_payload.extend_from_slice(&[0_u8; 4]);
        let mdhd = boxed(b"mdhd", &mdhd_payload);
        let mut hdlr_payload = vec![0_u8; 8];
        hdlr_payload.extend_from_slice(b"vide");
        hdlr_payload.extend_from_slice(&[0_u8; 12]);
        let hdlr = boxed(b"hdlr", &hdlr_payload);
        let stsd = boxed(b"stsd", &[0_u8; 8]);
        let mut stts_payload = vec![0_u8; 4];
        stts_payload.extend_from_slice(&1_u32.to_be_bytes());
        stts_payload.extend_from_slice(&2_u32.to_be_bytes());
        stts_payload.extend_from_slice(&600_u32.to_be_bytes());
        let stts = boxed(b"stts", &stts_payload);
        let mut stsc_payload = vec![0_u8; 4];
        stsc_payload.extend_from_slice(&1_u32.to_be_bytes());
        stsc_payload.extend_from_slice(&1_u32.to_be_bytes());
        stsc_payload.extend_from_slice(&2_u32.to_be_bytes());
        stsc_payload.extend_from_slice(&1_u32.to_be_bytes());
        let stsc = boxed(b"stsc", &stsc_payload);
        let mut stsz_payload = vec![0_u8; 4];
        stsz_payload.extend_from_slice(&0_u32.to_be_bytes());
        stsz_payload.extend_from_slice(&2_u32.to_be_bytes());
        stsz_payload.extend_from_slice(&4_u32.to_be_bytes());
        stsz_payload.extend_from_slice(&4_u32.to_be_bytes());
        let stsz = boxed(b"stsz", &stsz_payload);
        let mut stco_payload = vec![0_u8; 4];
        stco_payload.extend_from_slice(&1_u32.to_be_bytes());
        stco_payload.extend_from_slice(&0_u32.to_be_bytes()); // patched below
        let stco = boxed(b"stco", &stco_payload);
        let stbl = boxed(b"stbl", &[stsd, stts, stsc, stsz, stco].concat());
        let minf = boxed(b"minf", &stbl);
        let mdia = boxed(b"mdia", &[mdhd, hdlr, minf].concat());
        let trak = boxed(b"trak", &[tkhd, mdia].concat());
        let moov = boxed(b"moov", &trak);
        let mdat = boxed(b"mdat", b"DATA0123");

        let mut file = Vec::new();
        file.extend_from_slice(&ftyp);
        file.extend_from_slice(&moov);
        let samples_offset = file.len() as u32 + 8;
        file.extend_from_slice(&mdat);
        let stco_type = file
            .windows(4)
            .position(|window| window == b"stco")
            .expect("stco box present");
        let offset_at = stco_type + 12;
        file[offset_at..offset_at + 4].copy_from_slice(&samples_offset.to_be_bytes());
        file
    }

    /// Write bytes into the sandbox at a guest-visible Windows path.
    fn write_sandbox_file(runtime: &PeHostRuntime, guest_path: &str, bytes: &[u8]) {
        let host_path = runtime
            .win32
            .ge()
            .host_path_for_windows_path(guest_path)
            .expect("host path");
        if let Some(parent) = host_path.parent() {
            std::fs::create_dir_all(parent).expect("create sandbox dir");
        }
        std::fs::write(&host_path, bytes).expect("write sandbox file");
    }

    /// Write a NUL-terminated UTF-16 string into guest memory.
    fn write_utf16(memory: &mut MemoryImage, address: u64, value: &str) {
        let mut bytes = Vec::with_capacity(value.len() * 2 + 2);
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
        memory.map_bytes(address, &bytes);
    }

    /// The real source graph created by `MFCreateSourceReaderFromURL`.
    struct SourceGraph {
        reader: u64,
        source: u64,
        byte_stream: u64,
    }

    fn create_source_graph(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        guest_path: &str,
    ) -> SourceGraph {
        let create_reader: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateSourceReaderFromUrl);
        let url = 0x42_000;
        write_utf16(memory, url, guest_path);
        let reader_out = 0x41_000;
        let hr = dispatch_x86_thunk(
            runtime,
            memory,
            create_reader,
            &[url as u32, 0, reader_out as u32],
        );
        assert_eq!(hr, 0, "MFCreateSourceReaderFromURL");
        let reader = read_guest_pointer(memory, reader_out, GuestArch::X86).unwrap();
        assert_ne!(reader, 0);
        let source = runtime.mf_source_readers.get(&reader).unwrap().source();
        assert_ne!(source, 0, "the reader is wired to a real source");
        let byte_stream = runtime.mf_media_sources.get(&source).unwrap().byte_stream();
        assert_ne!(byte_stream, 0, "the source is wired to a byte stream");
        SourceGraph {
            reader,
            source,
            byte_stream,
        }
    }

    /// Pull one source event and answer its real MF event number, or the
    /// HRESULT when the queue is empty.
    fn pull_source_event_type(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        source: u64,
    ) -> u64 {
        let get_event: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceGetEvent);
        let get_type: u64 = runtime.alloc_host_thunk(HostThunk::MfEventGetType);
        let event_out = 0x44_400;
        let hr = dispatch_x86_thunk(
            runtime,
            memory,
            get_event,
            &[source as u32, 0, event_out as u32],
        );
        if hr != 0 {
            return hr;
        }
        let event = read_guest_pointer(memory, event_out, GuestArch::X86).unwrap();
        assert_ne!(event, 0);
        let type_out = 0x44_410;
        let hr = dispatch_x86_thunk(runtime, memory, get_type, &[event as u32, type_out as u32]);
        assert_eq!(hr, 0);
        u64::from(read_guest_u32(memory, type_out).unwrap())
    }

    #[test]
    fn mf_source_reader_from_url_builds_real_byte_stream_and_source() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-source-graph");
            let mut memory = MemoryImage::default();
            let mp4 = minimal_mp4_file();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &mp4);
            let graph = create_source_graph(&mut runtime, &mut memory, "C:\\media\\clip.mp4");

            // The presentation is the real parsed file: one track, real
            // duration (1200/600 s), seekable, real file size.
            let source = runtime.mf_media_sources.get(&graph.source).unwrap();
            assert_eq!(source.state(), crate::media::MfSourceState::Stopped);
            assert_eq!(source.readers(), &[graph.reader]);
            let presentation = source.presentation().clone();
            assert_eq!(presentation.streams.len(), 1);
            assert_eq!(presentation.streams[0].identifier, 1);
            assert_eq!(presentation.duration, 20_000_000);
            assert!(presentation.seekable);
            assert_eq!(presentation.file_size, mp4.len() as u64);

            // The byte stream is backed by a real runtime file-table handle.
            let stream = runtime.mf_byte_streams.get(&graph.byte_stream).unwrap();
            assert_ne!(stream.file_handle, 0);
            assert_eq!(stream.length, mp4.len() as u64);
            assert!(stream.seekable);
            assert!(!stream.writable);
            assert_eq!(stream.content_type.as_deref(), Some("video/mp4"));
            assert_eq!(stream.origin_name.as_deref(), Some("C:\\media\\clip.mp4"));

            // IMFByteStream::GetLength / Read / IsEndOfStream / Seek over the
            // real file bytes.
            let get_length: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamGetLength);
            let length_out = 0x43_100;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_length,
                    &[graph.byte_stream as u32, length_out as u32]
                ),
                0
            );
            assert_eq!(
                read_guest_u64(&memory, length_out).unwrap(),
                mp4.len() as u64
            );

            let read: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamRead);
            let buffer = 0x43_200;
            let read_out = 0x43_210;
            // The stream starts at byte 0 of the real file.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    read,
                    &[graph.byte_stream as u32, buffer as u32, 8, read_out as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, read_out).unwrap(), 8);
            assert_eq!(memory.read_bytes(buffer, 8).unwrap(), mp4[..8].to_vec());

            // Seek to the real sample payload and read it back.
            let seek: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamSeek);
            let position_out = 0x43_230;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    seek,
                    &[
                        graph.byte_stream as u32,
                        0,
                        (mp4.len() - 8) as u32,
                        0,
                        position_out as u32
                    ]
                ),
                0
            );
            assert_eq!(
                read_guest_u64(&memory, position_out).unwrap(),
                (mp4.len() - 8) as u64
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    read,
                    &[graph.byte_stream as u32, buffer as u32, 8, read_out as u32]
                ),
                0
            );
            assert_eq!(memory.read_bytes(buffer, 8).unwrap(), b"DATA0123".to_vec());

            let at_end: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamIsEndOfStream);
            let end_out = 0x43_220;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    at_end,
                    &[graph.byte_stream as u32, end_out as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, end_out).unwrap(), 1);

            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    seek,
                    &[graph.byte_stream as u32, 0, 0, 0, position_out as u32]
                ),
                0
            );
            assert_eq!(read_guest_u64(&memory, position_out).unwrap(), 0);

            // MFGetService: the source owns MF_MEDIASOURCE_SERVICE for
            // IMFMediaSource/IMFMediaSourceEx/IUnknown only.
            let get_service: u64 = runtime.alloc_host_thunk(HostThunk::MfGetService);
            let guid = 0x44_000;
            let iid = 0x44_100;
            let out = 0x44_200;
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_MEDIASOURCE);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_MEDIA_SOURCE_EX);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_service,
                    &[graph.source as u32, guid as u32, iid as u32, out as u32]
                ),
                0
            );
            assert_eq!(
                read_guest_pointer(&memory, out, GuestArch::X86).unwrap(),
                graph.source
            );

            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_SOURCE_READER);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_service,
                    &[graph.source as u32, guid as u32, iid as u32, out as u32]
                ),
                MF_E_UNSUPPORTED_SERVICE as u64
            );

            // The metadata provider stays genuinely unsupported (no real tag
            // parser exists).
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_METADATA_PROVIDER);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_ATTRIBUTES);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_service,
                    &[graph.source as u32, guid as u32, iid as u32, out as u32]
                ),
                MF_E_UNSUPPORTED_SERVICE as u64
            );

            // The byte stream exposes its real origin/content-type attributes
            // through the attribute services.
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_BYTESTREAM_ORIGIN_NAME);
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_ATTRIBUTES);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_service,
                    &[
                        graph.byte_stream as u32,
                        guid as u32,
                        iid as u32,
                        out as u32
                    ]
                ),
                0
            );
            let origin_attrs = read_guest_pointer(&memory, out, GuestArch::X86).unwrap();
            let origin_key = Guid::from_bytes_le(&SERVICE_MF_BYTESTREAM_ORIGIN_NAME);
            assert_eq!(
                runtime
                    .mf_media_types
                    .get(&origin_attrs)
                    .unwrap()
                    .get_string(&origin_key),
                Some("C:\\media\\clip.mp4")
            );

            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_BYTESTREAM_CONTENT_TYPE);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_service,
                    &[
                        graph.byte_stream as u32,
                        guid as u32,
                        iid as u32,
                        out as u32
                    ]
                ),
                0
            );
            let content_attrs = read_guest_pointer(&memory, out, GuestArch::X86).unwrap();
            let content_key = Guid::from_bytes_le(&SERVICE_MF_BYTESTREAM_CONTENT_TYPE);
            assert_eq!(
                runtime
                    .mf_media_types
                    .get(&content_attrs)
                    .unwrap()
                    .get_string(&content_key),
                Some("video/mp4")
            );

            // A wrong interface for a backed attribute, and a service the
            // byte stream does not own.
            write_guest_guid_bytes(&mut memory, iid, &IID_IMF_GET_SERVICE);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_service,
                    &[
                        graph.byte_stream as u32,
                        guid as u32,
                        iid as u32,
                        out as u32
                    ]
                ),
                MF_E_UNSUPPORTED_SERVICE as u64
            );
            // Every sibling MF interface IID stays unsupported for the
            // byte-stream attribute services.
            for wrong_iid in [
                IID_IMF_BYTE_STREAM,
                IID_IMF_PRESENTATION_DESCRIPTOR,
                IID_IMF_STREAM_DESCRIPTOR,
                IID_IMF_MEDIA_TYPE_HANDLER,
                IID_IMF_MEDIA_EVENT,
            ] {
                write_guest_guid_bytes(&mut memory, iid, &wrong_iid);
                assert_eq!(
                    dispatch_x86_thunk(
                        &mut runtime,
                        &mut memory,
                        get_service,
                        &[
                            graph.byte_stream as u32,
                            guid as u32,
                            iid as u32,
                            out as u32
                        ]
                    ),
                    MF_E_UNSUPPORTED_SERVICE as u64
                );
            }
            write_guest_guid_bytes(&mut memory, guid, &SERVICE_MF_METADATA_PROVIDER);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_service,
                    &[
                        graph.byte_stream as u32,
                        guid as u32,
                        iid as u32,
                        out as u32
                    ]
                ),
                MF_E_UNSUPPORTED_SERVICE as u64
            );
        })
    }

    #[test]
    fn mf_source_reader_reads_real_samples_and_queues_end_of_presentation() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-read-sample");
            let mut memory = MemoryImage::default();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &minimal_mp4_file());
            let graph = create_source_graph(&mut runtime, &mut memory, "C:\\media\\clip.mp4");

            let read_sample: u64 = runtime.alloc_host_thunk(HostThunk::MfSourceReaderReadSample);
            let actual_out = 0x43_300;
            let flags_out = 0x43_310;
            let timestamp_out = 0x43_320;
            let sample_out = 0x43_330;
            let args = [
                graph.reader as u32,
                0xFFFF_FFFC, // MF_SOURCE_READER_FIRST_VIDEO_STREAM
                0,
                actual_out as u32,
                flags_out as u32,
                timestamp_out as u32,
                sample_out as u32,
            ];

            // First sample: the real bytes, first sample timestamp and the
            // MF_SOURCE_READERF_NEWSTREAM flag.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, read_sample, &args),
                0
            );
            assert_eq!(read_guest_u32(&memory, actual_out).unwrap(), 0);
            assert_ne!(read_guest_u32(&memory, flags_out).unwrap() & 0x4, 0);
            assert_eq!(read_guest_u64(&memory, timestamp_out).unwrap(), 0);
            let sample = read_guest_pointer(&memory, sample_out, GuestArch::X86).unwrap();
            assert_eq!(runtime.mf_samples.get(&sample).unwrap().buffer, b"DATA");

            // Second sample: 1 second later in 100-ns units.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, read_sample, &args),
                0
            );
            assert_eq!(read_guest_u32(&memory, flags_out).unwrap() & 0x4, 0);
            assert_eq!(read_guest_u64(&memory, timestamp_out).unwrap(), 10_000_000);
            let sample = read_guest_pointer(&memory, sample_out, GuestArch::X86).unwrap();
            assert_eq!(runtime.mf_samples.get(&sample).unwrap().buffer, b"0123");

            // Third read: the documented end-of-stream result.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, read_sample, &args),
                0
            );
            assert_eq!(
                read_guest_u32(&memory, flags_out).unwrap(),
                MF_SOURCE_READERF_ENDOFSTREAM
            );
            assert_eq!(
                read_guest_pointer(&memory, sample_out, GuestArch::X86).unwrap(),
                0
            );

            // EOF queued MEEndOfStream then MEEndOfPresentation on the source.
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                212
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                211
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                MF_E_NO_EVENTS_AVAILABLE as u64
            );
        })
    }

    #[test]
    fn mf_media_source_state_machine_seeks_the_attached_reader() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-source-states");
            let mut memory = MemoryImage::default();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &minimal_mp4_file());
            let graph = create_source_graph(&mut runtime, &mut memory, "C:\\media\\clip.mp4");

            let start: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceStart);
            let pause: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourcePause);
            let stop: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceStop);
            let shutdown: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceShutdown);

            // Start at the beginning: MESourceStarted/MENewStream/
            // MEStreamStarted, then the real Started state.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    start,
                    &[graph.source as u32, 0, 0, 0]
                ),
                0
            );
            assert_eq!(
                runtime.mf_media_sources.get(&graph.source).unwrap().state(),
                crate::media::MfSourceState::Started
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                201
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                205
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                202
            );

            // Pause is only legal from Started.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, pause, &[graph.source as u32]),
                0
            );
            assert_eq!(
                runtime.mf_media_sources.get(&graph.source).unwrap().state(),
                crate::media::MfSourceState::Paused
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                209
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                210
            );

            // A second Start is a real seek: MESourceSeeked/MEStreamSeeked and
            // the new 100-ns position.
            let position = 0x45_000;
            write_u32(&mut memory, position, 20); // VT_I8
            write_guest_u64(&mut memory, position + 8, 5_000_000).expect("propvariant");
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    start,
                    &[graph.source as u32, 0, 0, position as u32]
                ),
                0
            );
            assert_eq!(
                runtime.mf_media_sources.get(&graph.source).unwrap().state(),
                crate::media::MfSourceState::Started
            );
            assert_eq!(
                runtime
                    .mf_media_sources
                    .get(&graph.source)
                    .unwrap()
                    .position(),
                5_000_000
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                203
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                204
            );

            // The seek reached the attached reader: 5 s is past the 2 s
            // presentation, so the next ReadSample reports EOF and queues the
            // end-of-presentation events.
            let read_sample: u64 = runtime.alloc_host_thunk(HostThunk::MfSourceReaderReadSample);
            let flags_out = 0x43_310;
            let sample_out = 0x43_330;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    read_sample,
                    &[
                        graph.reader as u32,
                        0xFFFF_FFFC,
                        0,
                        0x43_300,
                        flags_out as u32,
                        0x43_320,
                        sample_out as u32
                    ]
                ),
                0
            );
            assert_eq!(
                read_guest_u32(&memory, flags_out).unwrap(),
                MF_SOURCE_READERF_ENDOFSTREAM
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                212
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                211
            );
            assert_eq!(
                runtime.mf_media_sources.get(&graph.source).unwrap().state(),
                crate::media::MfSourceState::Stopped
            );

            // Stop from the (ended) stopped state still answers the real
            // MESourceStopped/MEStreamStopped events.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, stop, &[graph.source as u32]),
                0
            );
            assert_eq!(
                runtime.mf_media_sources.get(&graph.source).unwrap().state(),
                crate::media::MfSourceState::Stopped
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                207
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                208
            );

            // Pause from Stopped is the real invalid-request error.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, pause, &[graph.source as u32]),
                MF_E_INVALIDREQUEST as u64
            );

            // Shutdown is terminal.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, shutdown, &[graph.source as u32]),
                0
            );
            assert_eq!(
                runtime.mf_media_sources.get(&graph.source).unwrap().state(),
                crate::media::MfSourceState::Shutdown
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    start,
                    &[graph.source as u32, 0, 0, 0]
                ),
                MF_E_SHUTDOWN as u64
            );
        })
    }

    #[test]
    fn mf_presentation_descriptor_exposes_real_file_metadata() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-descriptor");
            let mut memory = MemoryImage::default();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &minimal_mp4_file());
            let graph = create_source_graph(&mut runtime, &mut memory, "C:\\media\\clip.mp4");

            let create_pd: u64 =
                runtime.alloc_host_thunk(HostThunk::MfMediaSourceCreatePresentationDescriptor);
            let count: u64 = runtime
                .alloc_host_thunk(HostThunk::MfPresentationDescriptorGetStreamDescriptorCount);
            let by_index: u64 = runtime
                .alloc_host_thunk(HostThunk::MfPresentationDescriptorGetStreamDescriptorByIndex);
            let select: u64 =
                runtime.alloc_host_thunk(HostThunk::MfPresentationDescriptorSelectStream);
            let deselect: u64 =
                runtime.alloc_host_thunk(HostThunk::MfPresentationDescriptorDeselectStream);
            let clone: u64 = runtime.alloc_host_thunk(HostThunk::MfPresentationDescriptorClone);
            let attr_u64: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrGetUint64);
            let attr_u32: u64 = runtime.alloc_host_thunk(HostThunk::MfAttrGetUint32);
            let sd_identifier: u64 =
                runtime.alloc_host_thunk(HostThunk::MfStreamDescriptorGetStreamIdentifier);
            let sd_handler: u64 =
                runtime.alloc_host_thunk(HostThunk::MfStreamDescriptorGetMediaTypeHandler);
            let handler_count: u64 =
                runtime.alloc_host_thunk(HostThunk::MfMediaTypeHandlerGetMediaTypeCount);
            let handler_major: u64 =
                runtime.alloc_host_thunk(HostThunk::MfMediaTypeHandlerGetMajorType);
            let handler_current: u64 =
                runtime.alloc_host_thunk(HostThunk::MfMediaTypeHandlerGetCurrentMediaType);
            let handler_supported: u64 =
                runtime.alloc_host_thunk(HostThunk::MfMediaTypeHandlerIsMediaTypeSupported);

            let pd_out = 0x41_400;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create_pd,
                    &[graph.source as u32, pd_out as u32]
                ),
                0
            );
            let pd = read_guest_pointer(&memory, pd_out, GuestArch::X86).unwrap();
            assert_ne!(pd, 0);

            // The real duration/seekable attributes parsed from mdhd.
            let key = 0x45_100;
            let value = 0x45_200;
            write_guest_guid_bytes(
                &mut memory,
                key,
                &crate::media::MF_PD_DURATION.to_bytes_le(),
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    attr_u64,
                    &[pd as u32, key as u32, value as u32]
                ),
                0
            );
            assert_eq!(read_guest_u64(&memory, value).unwrap(), 20_000_000);
            write_guest_guid_bytes(
                &mut memory,
                key,
                &crate::media::MF_PD_SEEKABLE.to_bytes_le(),
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    attr_u32,
                    &[pd as u32, key as u32, value as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, value).unwrap(), 1);

            // One real stream descriptor.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, count, &[pd as u32, value as u32]),
                0
            );
            assert_eq!(read_guest_u32(&memory, value).unwrap(), 1);
            let selected_out = 0x45_300;
            let sd_out = 0x45_310;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    by_index,
                    &[pd as u32, 0, selected_out as u32, sd_out as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, selected_out).unwrap(), 1);
            let sd = read_guest_pointer(&memory, sd_out, GuestArch::X86).unwrap();
            assert_ne!(sd, 0);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    sd_identifier,
                    &[sd as u32, value as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, value).unwrap(), 1);

            // The handler enumerates the parsed native media type.
            let handler_out = 0x45_320;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    sd_handler,
                    &[sd as u32, handler_out as u32]
                ),
                0
            );
            let handler = read_guest_pointer(&memory, handler_out, GuestArch::X86).unwrap();
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    handler_count,
                    &[handler as u32, value as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, value).unwrap(), 1);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    handler_major,
                    &[handler as u32, key as u32]
                ),
                0
            );
            assert_eq!(
                memory.read_bytes(key, 16).unwrap(),
                crate::media::MFMediaType_Video.to_bytes_le().to_vec()
            );
            let media_type_out = 0x45_330;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    handler_current,
                    &[handler as u32, media_type_out as u32]
                ),
                0
            );
            let media_type = read_guest_pointer(&memory, media_type_out, GuestArch::X86).unwrap();
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    handler_supported,
                    &[handler as u32, media_type as u32, 0]
                ),
                0
            );

            // Stream selection is real state and Clone is a real copy.
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, deselect, &[pd as u32, 0]),
                0
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    by_index,
                    &[pd as u32, 0, selected_out as u32, sd_out as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, selected_out).unwrap(), 0);
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, select, &[pd as u32, 0]),
                0
            );
            let clone_out = 0x45_340;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    clone,
                    &[pd as u32, clone_out as u32]
                ),
                0
            );
            let cloned = read_guest_pointer(&memory, clone_out, GuestArch::X86).unwrap();
            assert_ne!(cloned, pd);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    count,
                    &[cloned as u32, value as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, value).unwrap(), 1);
        })
    }

    #[test]
    fn mf_create_file_byte_stream_reads_writes_and_seeks_real_files() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-create-file");
            let mut memory = MemoryImage::default();
            let mp4 = minimal_mp4_file();
            write_sandbox_file(&runtime, "C:\\media\\input.mp4", &mp4);

            let create: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateFile);
            let url = 0x42_000;
            write_utf16(&mut memory, url, "C:\\media\\input.mp4");
            let stream_out = 0x41_500;
            // MF_ACCESSMODE_READ=1, MF_OPENMODE_FAIL_IF_NOT_EXIST=0.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create,
                    &[1, 0, 0, url as u32, stream_out as u32]
                ),
                0
            );
            let stream = read_guest_pointer(&memory, stream_out, GuestArch::X86).unwrap();
            assert_ne!(runtime.mf_byte_streams.get(&stream).unwrap().file_handle, 0);

            // A missing file answers the real file-not-found HRESULT.
            let missing = 0x42_100;
            write_utf16(&mut memory, missing, "C:\\media\\missing.mp4");
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create,
                    &[1, 0, 0, missing as u32, stream_out as u32]
                ),
                0x8007_0002
            );

            // Read the real file start, then seek to the sample payload.
            let read: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamRead);
            let buffer = 0x43_400;
            let read_out = 0x43_410;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    read,
                    &[stream as u32, buffer as u32, 8, read_out as u32]
                ),
                0
            );
            assert_eq!(memory.read_bytes(buffer, 8).unwrap(), mp4[..8].to_vec());
            let set_position: u64 =
                runtime.alloc_host_thunk(HostThunk::MfByteStreamSetCurrentPosition);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    set_position,
                    &[stream as u32, (mp4.len() - 8) as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    read,
                    &[stream as u32, buffer as u32, 8, read_out as u32]
                ),
                0
            );
            assert_eq!(memory.read_bytes(buffer, 8).unwrap(), b"DATA0123".to_vec());
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    set_position,
                    &[stream as u32, (mp4.len() - 4) as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    read,
                    &[stream as u32, buffer as u32, 4, read_out as u32]
                ),
                0
            );
            assert_eq!(memory.read_bytes(buffer, 4).unwrap(), b"0123".to_vec());

            // A read-only stream denies Write.
            let write: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamWrite);
            let written_out = 0x43_420;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    write,
                    &[stream as u32, buffer as u32, 4, written_out as u32]
                ),
                E_ACCESSDENIED as u64
            );

            // A writable stream really writes through the file table.
            let writable_path = 0x42_200;
            write_utf16(&mut memory, writable_path, "C:\\media\\output.bin");
            let writable_out = 0x41_520;
            // MF_ACCESSMODE_READWRITE=3, MF_OPENMODE_RESET_IF_EXIST=2.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create,
                    &[3, 2, 0, writable_path as u32, writable_out as u32]
                ),
                0
            );
            let writable = read_guest_pointer(&memory, writable_out, GuestArch::X86).unwrap();
            memory.map_bytes(buffer, b"WXYZ");
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    write,
                    &[writable as u32, buffer as u32, 4, written_out as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, written_out).unwrap(), 4);
            let flush: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamFlush);
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, flush, &[writable as u32]),
                0
            );
            let close: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamClose);
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, close, &[writable as u32]),
                0
            );
            let host_path = runtime
                .win32
                .ge()
                .host_path_for_windows_path("C:\\media\\output.bin")
                .expect("host path");
            assert_eq!(std::fs::read(&host_path).unwrap(), b"WXYZ".to_vec());

            // A closed stream fails subsequent operations.
            let get_length: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamGetLength);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_length,
                    &[writable as u32, stream_out as u32]
                ),
                E_FAIL as u64
            );

            // FAIL_IF_EXIST on an existing file answers the real
            // already-exists HRESULT.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create,
                    &[1, 1, 0, writable_path as u32, stream_out as u32]
                ),
                0x8007_00B7
            );
        })
    }

    #[test]
    fn mf_create_source_reader_from_byte_stream_uses_the_real_stream() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-reader-from-stream");
            let mut memory = MemoryImage::default();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &minimal_mp4_file());

            let create_file: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateFile);
            let url = 0x42_000;
            write_utf16(&mut memory, url, "C:\\media\\clip.mp4");
            let stream_out = 0x41_500;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create_file,
                    &[1, 0, 0, url as u32, stream_out as u32]
                ),
                0
            );
            let stream = read_guest_pointer(&memory, stream_out, GuestArch::X86).unwrap();

            let create_reader: u64 =
                runtime.alloc_host_thunk(HostThunk::MfCreateSourceReaderFromByteStream);
            let reader_out = 0x41_000;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create_reader,
                    &[stream as u32, 0, reader_out as u32]
                ),
                0
            );
            let reader = read_guest_pointer(&memory, reader_out, GuestArch::X86).unwrap();
            let source = runtime.mf_source_readers.get(&reader).unwrap().source();
            assert_ne!(source, 0);
            assert_eq!(
                runtime.mf_media_sources.get(&source).unwrap().byte_stream(),
                stream,
                "the source consumes the supplied real byte stream"
            );

            // A handle that is not a runtime byte stream is invalid.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create_reader,
                    &[0x0000_DEAD, 0, reader_out as u32]
                ),
                0x8007_0006
            );
        })
    }

    #[test]
    fn mf_topology_source_graph_resolves_descriptor_and_drives_the_source() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-topology-source");
            let mut memory = MemoryImage::default();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &minimal_mp4_file());
            let graph = create_source_graph(&mut runtime, &mut memory, "C:\\media\\clip.mp4");

            let create_topology: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateTopology);
            let create_node: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateTopologyNode);
            let set_object: u64 = runtime.alloc_host_thunk(HostThunk::MfTopologyNodeSetObject);
            let add_node: u64 = runtime.alloc_host_thunk(HostThunk::MfTopologyAddNode);
            let create_session: u64 = runtime.alloc_host_thunk(HostThunk::MfCreateMediaSession);
            let set_topology: u64 = runtime.alloc_host_thunk(HostThunk::MfSessionSetTopology);
            let get_descriptor: u64 =
                runtime.alloc_host_thunk(HostThunk::MfSessionGetDescriptorFromTopology);
            let session_start: u64 = runtime.alloc_host_thunk(HostThunk::MfSessionStart);
            let session_stop: u64 = runtime.alloc_host_thunk(HostThunk::MfSessionStop);

            let topology_out = 0x41_600;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create_topology,
                    &[topology_out as u32]
                ),
                0
            );
            let topology = read_guest_pointer(&memory, topology_out, GuestArch::X86).unwrap();
            let node_out = 0x41_610;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create_node,
                    &[1, node_out as u32] // MF_TOPOLOGY_SOURCESTREAM_NODE
                ),
                0
            );
            let node = read_guest_pointer(&memory, node_out, GuestArch::X86).unwrap();
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    add_node,
                    &[topology as u32, node as u32]
                ),
                0
            );
            let session_out = 0x41_620;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    create_session,
                    &[0, session_out as u32]
                ),
                0
            );
            let session = read_guest_pointer(&memory, session_out, GuestArch::X86).unwrap();
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    set_topology,
                    &[session as u32, 0, topology as u32]
                ),
                0
            );

            // Without a source object the topology has no representation.
            let descriptor_out = 0x41_630;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_descriptor,
                    &[session as u32, topology as u32, descriptor_out as u32]
                ),
                MF_E_UNSUPPORTED_REPRESENTATION as u64
            );

            // Wire the real source into the node, then resolve its real
            // presentation descriptor through the session.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    set_object,
                    &[node as u32, graph.source as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    get_descriptor,
                    &[session as u32, topology as u32, descriptor_out as u32]
                ),
                0
            );
            let pd = read_guest_pointer(&memory, descriptor_out, GuestArch::X86).unwrap();
            assert_ne!(pd, 0);
            let count: u64 = runtime
                .alloc_host_thunk(HostThunk::MfPresentationDescriptorGetStreamDescriptorCount);
            let value = 0x45_500;
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, count, &[pd as u32, value as u32]),
                0
            );
            assert_eq!(read_guest_u32(&memory, value).unwrap(), 1);

            // Session Start/Stop drive the real source state machine and
            // queue its events.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    session_start,
                    &[session as u32, 0, 0]
                ),
                0
            );
            assert_eq!(
                runtime.mf_media_sources.get(&graph.source).unwrap().state(),
                crate::media::MfSourceState::Started
            );
            assert_eq!(
                pull_source_event_type(&mut runtime, &mut memory, graph.source),
                201
            );
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, session_stop, &[session as u32]),
                0
            );
            assert_eq!(
                runtime.mf_media_sources.get(&graph.source).unwrap().state(),
                crate::media::MfSourceState::Stopped
            );
        })
    }

    // ---- Adversarial async-pump coverage ---------------------------------

    const MF_CB_OBJECT: u64 = 0x62_000;
    const MF_CB_VTABLE: u64 = 0x62_100;
    const MF_CB_STUB: u64 = 0x62_200;
    const MF_CB_COUNT: u64 = 0x62_300;
    const MF_CB_RESULT: u64 = 0x62_304;
    const MF_CB_STACK: u64 = 0x52_000;

    /// Install a real x86 IMFAsyncCallback stub: it records the result
    /// pointer argument and increments an invocation counter, returning S_OK.
    fn install_mf_async_callback(memory: &mut MemoryImage) {
        memory.map_bytes(MF_CB_OBJECT, &[0_u8; 8]);
        memory.map_bytes(MF_CB_VTABLE, &[0_u8; 32]);
        memory.map_bytes(MF_CB_COUNT, &[0_u8; 8]);
        memory.map_bytes(MF_CB_STACK, &[0_u8; 0x400]);
        let mut code = Vec::new();
        // mov eax, [esp+8] (pAsyncResult)
        code.extend_from_slice(&[0x8B, 0x44, 0x24, 0x08]);
        // mov [MF_CB_RESULT], eax
        code.push(0xA3);
        code.extend_from_slice(&(MF_CB_RESULT as u32).to_le_bytes());
        // mov eax, [MF_CB_COUNT]
        code.push(0xA1);
        code.extend_from_slice(&(MF_CB_COUNT as u32).to_le_bytes());
        // add eax, 1
        code.extend_from_slice(&[0x05, 0x01, 0x00, 0x00, 0x00]);
        // mov [MF_CB_COUNT], eax
        code.push(0xA3);
        code.extend_from_slice(&(MF_CB_COUNT as u32).to_le_bytes());
        code.extend_from_slice(&[0x31, 0xC0, 0xC3]); // xor eax,eax; ret
        let mut stub = vec![0x90_u8; 0x40];
        stub[..code.len()].copy_from_slice(&code);
        memory.map_bytes(MF_CB_STUB, &stub);
        write_u32(memory, MF_CB_OBJECT, MF_CB_VTABLE as u32);
        // IMFAsyncCallback: QI(0) AddRef(1) Release(2) GetParameters(3)
        // Invoke(4).
        write_u32(memory, MF_CB_VTABLE + 16, MF_CB_STUB as u32);
    }

    fn mf_callback_count(memory: &MemoryImage) -> u32 {
        read_guest_u32(memory, MF_CB_COUNT).unwrap_or(0)
    }

    fn mf_callback_result(memory: &MemoryImage) -> u64 {
        u64::from(read_guest_u32(memory, MF_CB_RESULT).unwrap_or(0))
    }

    fn drain_mf(runtime: &mut PeHostRuntime, state: &mut CpuState, memory: &mut MemoryImage) {
        runtime
            .drain_pending_mf_async_completions(state, memory)
            .expect("drain MF completions");
    }

    fn begin_get_event(
        runtime: &mut PeHostRuntime,
        memory: &mut MemoryImage,
        source: u64,
        callback: u64,
    ) -> u64 {
        let thunk: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceBeginGetEvent);
        dispatch_x86_thunk(
            runtime,
            memory,
            thunk,
            &[source as u32, callback as u32, 0x7000],
        )
    }

    fn start_source(runtime: &mut PeHostRuntime, memory: &mut MemoryImage, source: u64) -> u64 {
        let thunk: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceStart);
        dispatch_x86_thunk(runtime, memory, thunk, &[source as u32, 0, 0, 0])
    }

    #[test]
    fn mf_begin_get_event_parks_cancels_and_delivers_exactly_once() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-async-events");
            let mut memory = MemoryImage::default();
            let mp4 = minimal_mp4_file();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &mp4);
            let graph = create_source_graph(&mut runtime, &mut memory, "C:\\media\\clip.mp4");
            install_mf_async_callback(&mut memory);

            let mut state = CpuState::new(GuestArch::X86);
            state.set(Register::Rsp, MF_CB_STACK);

            // No event is queued yet: the request parks with E_PENDING and no
            // callback may fire before a servicing point runs.
            assert_eq!(
                begin_get_event(&mut runtime, &mut memory, graph.source, MF_CB_OBJECT),
                u64::from(0x8000_000A_u32),
                "E_PENDING"
            );
            assert_eq!(mf_callback_count(&memory), 0);
            // A second Begin while one is parked is rejected.
            assert_eq!(
                begin_get_event(&mut runtime, &mut memory, graph.source, MF_CB_OBJECT),
                u64::from(E_INVALIDARG)
            );
            // Cancel drops the park; a second cancel reports S_FALSE.
            let cancel: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceCancelGetEvent);
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, cancel, &[graph.source as u32]),
                0
            );
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, cancel, &[graph.source as u32]),
                1,
                "S_FALSE"
            );

            // Park again, then a real state change (Start) completes it.
            assert_eq!(
                begin_get_event(&mut runtime, &mut memory, graph.source, MF_CB_OBJECT),
                u64::from(0x8000_000A_u32)
            );
            assert_eq!(start_source(&mut runtime, &mut memory, graph.source), 0);
            assert_eq!(
                mf_callback_count(&memory),
                0,
                "callback fires at servicing only"
            );
            drain_mf(&mut runtime, &mut state, &mut memory);
            assert_eq!(mf_callback_count(&memory), 1);
            let result = mf_callback_result(&memory);
            assert_ne!(result, 0, "the callback received a real IMFAsyncResult");
            // Draining again must not re-invoke the callback.
            drain_mf(&mut runtime, &mut state, &mut memory);
            assert_eq!(mf_callback_count(&memory), 1);

            // EndGetEvent returns the real event for that result, exactly once.
            let end: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceEndGetEvent);
            let event_out = 0x47_000;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    end,
                    &[graph.source as u32, result as u32, event_out as u32]
                ),
                0
            );
            let event = read_guest_pointer(&memory, event_out, GuestArch::X86).unwrap();
            assert_ne!(event, 0);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    end,
                    &[graph.source as u32, result as u32, event_out as u32]
                ),
                u64::from(E_INVALIDARG),
                "a completion is consumed exactly once"
            );
            // Junk result pointers are rejected without disturbing state.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    end,
                    &[graph.source as u32, 0xDEAD_0000_u32, event_out as u32]
                ),
                u64::from(E_INVALIDARG)
            );
            // A callback object whose vtable has a null Invoke slot is rejected.
            let broken = 0x63_000;
            let broken_vtable = 0x63_100;
            memory.map_bytes(broken, &[0_u8; 8]);
            memory.map_bytes(broken_vtable, &[0_u8; 32]);
            write_u32(&mut memory, broken, broken_vtable as u32);
            assert_eq!(
                begin_get_event(&mut runtime, &mut memory, graph.source, broken),
                u64::from(E_INVALIDARG)
            );
            // An unknown source object fails cleanly.
            assert_eq!(
                begin_get_event(&mut runtime, &mut memory, 0xDEAD_0000, MF_CB_OBJECT),
                u64::from(E_NOINTERFACE)
            );
        })
    }

    #[test]
    fn mf_begin_get_event_cancel_prevents_callback() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-async-cancel");
            let mut memory = MemoryImage::default();
            let mp4 = minimal_mp4_file();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &mp4);
            let graph = create_source_graph(&mut runtime, &mut memory, "C:\\media\\clip.mp4");
            install_mf_async_callback(&mut memory);
            let mut state = CpuState::new(GuestArch::X86);
            state.set(Register::Rsp, MF_CB_STACK);

            assert_eq!(
                begin_get_event(&mut runtime, &mut memory, graph.source, MF_CB_OBJECT),
                u64::from(0x8000_000A_u32)
            );
            let cancel: u64 = runtime.alloc_host_thunk(HostThunk::MfMediaSourceCancelGetEvent);
            assert_eq!(
                dispatch_x86_thunk(&mut runtime, &mut memory, cancel, &[graph.source as u32]),
                0
            );
            assert_eq!(start_source(&mut runtime, &mut memory, graph.source), 0);
            drain_mf(&mut runtime, &mut state, &mut memory);
            assert_eq!(
                mf_callback_count(&memory),
                0,
                "a cancelled request never invokes the callback"
            );
            assert_eq!(mf_callback_result(&memory), 0);
        })
    }

    #[test]
    fn mf_byte_stream_begin_read_is_async_and_exactly_once() {
        with_big_stack(|| {
            let (mut runtime, _tmp) = mf_test_runtime("mf-async-read");
            let mut memory = MemoryImage::default();
            let mp4 = minimal_mp4_file();
            write_sandbox_file(&runtime, "C:\\media\\clip.mp4", &mp4);
            let graph = create_source_graph(&mut runtime, &mut memory, "C:\\media\\clip.mp4");
            install_mf_async_callback(&mut memory);
            let mut state = CpuState::new(GuestArch::X86);
            state.set(Register::Rsp, MF_CB_STACK);

            let begin: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamBeginRead);
            let end: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamEndRead);
            let buffer = 0x48_000;
            memory.map_bytes(buffer, &[0_u8; 32]);

            // Invalid argument shapes are rejected before anything is queued.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    begin,
                    &[graph.byte_stream as u32, 0, 8, MF_CB_OBJECT as u32, 0]
                ),
                u64::from(E_INVALIDARG),
                "a null buffer with a length is invalid"
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    begin,
                    &[
                        graph.byte_stream as u32,
                        buffer as u32,
                        8,
                        0xDEAD_0000_u32,
                        0
                    ]
                ),
                u64::from(E_INVALIDARG),
                "an unmapped callback object is invalid"
            );
            assert_eq!(mf_callback_count(&memory), 0);

            // A null callback keeps the synchronous contract.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    begin,
                    &[graph.byte_stream as u32, buffer as u32, 8, 0, 0]
                ),
                0,
                "S_OK without a callback"
            );

            // With a callback the read completes asynchronously through the
            // pump: E_PENDING, callback only at the servicing point.
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    begin,
                    &[
                        graph.byte_stream as u32,
                        buffer as u32,
                        16,
                        MF_CB_OBJECT as u32,
                        0x99
                    ]
                ),
                u64::from(0x8000_000A_u32)
            );
            assert_eq!(mf_callback_count(&memory), 0);
            drain_mf(&mut runtime, &mut state, &mut memory);
            assert_eq!(mf_callback_count(&memory), 1);
            let result = mf_callback_result(&memory);
            assert_ne!(result, 0);

            // EndRead returns the real byte count exactly once.
            let read_out = 0x47_100;
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    end,
                    &[graph.byte_stream as u32, result as u32, read_out as u32]
                ),
                0
            );
            assert_eq!(read_guest_u32(&memory, read_out).unwrap(), 16);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    end,
                    &[graph.byte_stream as u32, result as u32, read_out as u32]
                ),
                u64::from(E_INVALIDARG)
            );

            // Closing the stream makes both halves fail with the real status.
            let close: u64 = runtime.alloc_host_thunk(HostThunk::MfByteStreamClose);
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    close,
                    &[graph.byte_stream as u32]
                ),
                0
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    begin,
                    &[
                        graph.byte_stream as u32,
                        buffer as u32,
                        8,
                        MF_CB_OBJECT as u32,
                        0
                    ]
                ),
                u64::from(E_FAIL)
            );
            assert_eq!(
                dispatch_x86_thunk(
                    &mut runtime,
                    &mut memory,
                    end,
                    &[graph.byte_stream as u32, result as u32, read_out as u32]
                ),
                u64::from(E_FAIL)
            );
        })
    }
}
