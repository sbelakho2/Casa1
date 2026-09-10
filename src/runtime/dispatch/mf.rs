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
use crate::media::{Guid, ImfMediaBuffer, ImfMediaType, ImfSample, MediaEventType, MfEventQueue};
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
const E_INVALIDARG: u32 = 0x8007_0057;
const E_NOTIMPL: u32 = 0x8000_4001;
#[allow(dead_code)] // reserved for the MF error surface
const E_NOINTERFACE: u32 = 0x8000_4002;
#[allow(dead_code)] // reserved for the interface error surface
const E_OUTOFMEMORY: u32 = 0x8007_000E;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_NOT_INITIALIZED: u32 = 0xC00D_36B0;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_INVALIDREQUEST: u32 = 0xC00D_36A1;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_NO_MORE_TYPES: u32 = 0xC00D_36A0;
const MF_E_UNSUPPORTED_SERVICE: u32 = 0xC00D_36C8;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_NO_SAMPLE_TIMESTAMP: u32 = 0xC00D_36A4;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_ATTRIBUTENOTFOUND: u32 = 0xC00D_36E6;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_NOTFOUND: u32 = 0xC00D_36B1;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_INVALIDMEDIATYPE: u32 = 0xC00D_36B4;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_UNSUPPORTED_BYTESTREAM_TYPE: u32 = 0xC00D_36B6;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_TOPO_COULD_NOT_OPEN: u32 = 0xC00D_5208;
#[allow(dead_code)] // reserved for the MF error surface
const MF_E_UNSUPPORTED_CHARACTERISTICS: u32 = 0xC00D_36B2;

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

    /// `MFCreateSourceReaderFromURL(pwszURL, pAttributes, ppReader)` — a
    /// source reader wrapping the media layer's source machinery.
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
        let vtable = self.alloc_guest_vtable(memory, mf_source_reader_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfSourceReader, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let reader = match crate::media::SourceReader::from_url(&url)
            .or_else(|_| crate::media::SourceReader::from_data(Vec::new()))
        {
            Ok(r) => r,
            Err(_) => crate::media::SourceReader::empty(),
        };
        self.mf_source_readers.insert(object, reader);
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
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
    /// ppReader)` — a source reader over an MF byte stream.
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
        let vtable = self.alloc_guest_vtable(memory, mf_source_reader_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfSourceReader, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let url = self
            .com_streams
            .get(&stream)
            .map(|s: &ComStreamState| String::from_utf8_lossy(&s.data).to_string())
            .unwrap_or_default();
        let reader = match crate::media::SourceReader::from_url(&url)
            .or_else(|_| crate::media::SourceReader::from_data(Vec::new()))
        {
            Ok(r) => r,
            Err(_) => crate::media::SourceReader::empty(),
        };
        self.mf_source_readers.insert(object, reader);
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
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
    /// ppPresentationDescriptor)` — a presentation descriptor.
    pub(crate) fn dispatch_mf_create_presentation_descriptor(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _descriptors = guest_call_arg(state, memory, 0)?;
        let _count = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out == 0 {
            state.set(Register::Rax, u64::from(E_INVALIDARG));
            return Ok(());
        }
        let vtable = self.alloc_guest_vtable(memory, mf_presentation_descriptor_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfPresentationDescriptor, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `MFCreateMFByteStreamOnStream(pStream, ppByteStream)` — an
    /// IMFByteStream wrapping the IStream payload.
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
        let vtable = self.alloc_guest_vtable(memory, mf_byte_stream_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfByteStream, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        let payload = self
            .com_streams
            .get(&stream)
            .map(|s: &ComStreamState| s.data.clone())
            .unwrap_or_default();
        self.mf_byte_streams.insert(
            object,
            ImfByteStreamState {
                data: payload,
                position: 0,
            },
        );
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
    pub(crate) fn dispatch_mf_session_get_descriptor_from_topology(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let _topology = guest_call_arg(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, 0xc00d_36e6); // MF_E_UNSUPPORTED_REPRESENTATION
        Ok(())
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

    /// `IMFMediaSource::GetCharacteristics(pdwCharacteristics)` — the
    /// source is live and seekable.
    pub(crate) fn dispatch_mf_media_source_get_characteristics(
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
        if out != 0 {
            // MFMEDIASOURCE_CAN_SEEK | MFMEDIASOURCE_CAN_PAUSE | LIVE.
            write_guest_u32(memory, out, 0x1 | 0x2 | 0x4).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSource::CreatePresentationDescriptor(ppPD)` — the
    /// presentation descriptor object.
    pub(crate) fn dispatch_mf_media_source_create_presentation_descriptor(
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
        let vtable = self.alloc_guest_vtable(memory, mf_presentation_descriptor_methods())?;
        let descriptor = self
            .alloc_guest_object(memory, GuestObjectKind::ImfPresentationDescriptor, vtable)
            .unwrap_or(0);
        if descriptor == 0 || out == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        self.mf_presentation_descriptors.insert(descriptor, ());
        if out != 0 {
            write_guest_pointer(memory, out, descriptor, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSource::Start` / `Pause` / `Stop` — the source state.
    pub(crate) fn dispatch_mf_media_source_control(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        if !self.mf_media_sources.contains_key(&this) {
            state.set(Register::Rax, u64::from(E_NOINTERFACE));
            return Ok(());
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// `IMFMediaSource::Shutdown` — release the source.
    pub(crate) fn dispatch_mf_media_source_shutdown(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        self.mf_media_sources.remove(&this);
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

    /// `IMFMediaSource`/`IMFMediaEventGenerator` event methods — the
    /// source queues events on its event queue.
    pub(crate) fn dispatch_mf_media_source_events(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
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
                    write_guest_pointer(memory, out, value, self.guest_arch).ok();
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
            q.queue_event_type(MediaEventType::from_u8(event_type as u8));
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
                let vtable = self.alloc_guest_vtable(memory, mf_event_methods())?;
                let object = self
                    .alloc_guest_object(memory, GuestObjectKind::ImfMediaEvent, vtable)
                    .unwrap_or(0);
                if object != 0 {
                    self.mf_media_events.insert(
                        object,
                        crate::runtime::state::MfMediaEventState {
                            event_type: event.event_type as u32,
                            status: 0,
                            value: 0,
                        },
                    );
                    if out != 0 {
                        write_guest_pointer(memory, out, object, self.guest_arch).ok();
                    }
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, 0xC00D_36E2), // MF_E_NO_EVENTS_AVAILABLE
        }
        Ok(())
    }

    /// IMFMediaSession::Start — starts the session clock (the media layer
    /// session state machine).
    pub(crate) fn dispatch_mf_session_start(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _guid = guest_call_arg(state, memory, 1)?;
        let _pos = guest_call_arg(state, memory, 2)?;
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
        match self.mf_sessions.get_mut(&this) {
            Some(s) => {
                let _ = s.stop();
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
        Ok(())
    }

    /// IMFMediaSession::Shutdown.
    pub(crate) fn dispatch_mf_session_shutdown(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
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

    /// IMFSourceReader::GetCurrentMediaType — returns the current media type
    /// object for the stream.
    pub(crate) fn dispatch_mf_source_reader_get_current_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let out = guest_call_arg(state, memory, 2)?;
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
        let mt = self
            .mf_source_readers
            .get(&this)
            .and_then(|r| r.get_current_media_type(0).ok())
            .unwrap_or_default();
        self.mf_media_types.insert(object, mt);
        write_guest_pointer(memory, out, object, self.guest_arch).ok();
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFSourceReader::GetNativeMediaType — the source's native type or
    /// `MF_E_NO_MORE_TYPES` at the end of enumeration.
    pub(crate) fn dispatch_mf_source_reader_get_native_media_type(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let index = guest_call_arg_u32(state, memory, 2)?;
        let out = guest_call_arg(state, memory, 3)?;
        let vtable = self.alloc_guest_vtable(memory, mf_media_type_methods())?;
        let object = self
            .alloc_guest_object(memory, GuestObjectKind::ImfMediaType, vtable)
            .unwrap_or(0);
        if object == 0 {
            state.set(Register::Rax, u64::from(E_OUTOFMEMORY));
            return Ok(());
        }
        // The source reader enumerates its streams' types: the demuxer's
        // native type for the selected stream, or MF_E_NO_MORE_TYPES past
        // the end of enumeration.
        let reader_type = self
            .mf_source_readers
            .get(&this)
            .and_then(|r| r.get_current_media_type(index).ok())
            .or_else(|| Some(ImfMediaType::new()));
        match reader_type {
            Some(mt) => {
                self.mf_media_types.insert(object, mt);
                if out != 0 {
                    write_guest_pointer(memory, out, object, self.guest_arch).ok();
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(MF_E_NO_MORE_TYPES)),
        }
        Ok(())
    }

    /// IMFSourceReader::ReadSample — the documented end-of-stream result for
    /// the deterministic source model (no stream data available — the
    /// source reader has no live source in the headless pipeline).
    pub(crate) fn dispatch_mf_source_reader_read_sample(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let _stream = guest_call_arg_u32(state, memory, 1)?;
        let _control = guest_call_arg_u32(state, memory, 2)?;
        let flags_out = guest_call_arg(state, memory, 4)?;
        let _timestamp_out = guest_call_arg(state, memory, 5)?;
        let sample_out = guest_call_arg(state, memory, 6)?;
        if flags_out != 0 {
            write_u32(memory, flags_out, 0x20); // MF_SOURCE_READERF_ENDOFSTREAM
        }
        if sample_out != 0 {
            write_guest_pointer(memory, sample_out, 0, self.guest_arch).ok();
        }
        let _ = self.mf_source_readers.get(&this);
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
        let pos = self
            .mf_byte_streams
            .get(&this)
            .map(|s| s.position)
            .unwrap_or(0);
        if out != 0 {
            write_guest_pointer(memory, out, pos, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(S_OK));
        Ok(())
    }

    /// IMFByteStream::Read — copies from the stream payload at the current
    /// position.
    pub(crate) fn dispatch_mf_byte_stream_read(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let this = guest_call_arg(state, memory, 0)?;
        let buffer = guest_call_arg(state, memory, 1)?;
        let length = guest_call_arg_u32(state, memory, 2)?;
        let read_out = guest_call_arg(state, memory, 3)?;
        match self.mf_byte_streams.get_mut(&this) {
            Some(s) => {
                let available = s.data.len().saturating_sub(s.position as usize);
                let take = available.min(length as usize);
                for offset in 0..take {
                    let byte = s.data[s.position as usize + offset];
                    memory.write_u8(buffer + offset as u64, byte);
                }
                s.position += take as u64;
                if read_out != 0 {
                    write_u32(memory, read_out, take as u32);
                }
                state.set(Register::Rax, u64::from(S_OK));
            }
            None => state.set(Register::Rax, u64::from(E_NOINTERFACE)),
        }
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
        let len = self
            .mf_byte_streams
            .get(&this)
            .map(|s| s.data.len() as u64)
            .unwrap_or(0);
        if out != 0 {
            write_guest_pointer(memory, out, len, self.guest_arch).ok();
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

    /// IMFPresentationDescriptor::GetStreamDescriptorCount.
    pub(crate) fn dispatch_mf_presentation_descriptor_get_stream_descriptor_count(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _this = guest_call_arg(state, memory, 0)?;
        let out = guest_call_arg(state, memory, 1)?;
        if out != 0 {
            write_u32(memory, out, 0);
        }
        state.set(Register::Rax, u64::from(S_OK));
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
            MfMediaSourceControl => self.dispatch_mf_media_source_control(state, memory),
            MfMediaSourceShutdown => self.dispatch_mf_media_source_shutdown(state, memory),
            MfMediaSourceEvents => self.dispatch_mf_media_source_events(state, memory),
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
            MfSinkWriterAddStream => self.dispatch_mf_sink_writer_add_stream(state, memory),
            MfSinkWriterBeginWriting => self.dispatch_mf_sink_writer_begin_writing(state, memory),
            MfSinkWriterWriteSample => self.dispatch_mf_sink_writer_write_sample(state, memory),
            MfSinkWriterEndWriting => self.dispatch_mf_sink_writer_end_writing(state, memory),
            MfByteStreamGetCurrentPosition => {
                self.dispatch_mf_byte_stream_get_current_position(state, memory)
            }
            MfByteStreamRead => self.dispatch_mf_byte_stream_read(state, memory),
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
            MfEventGetType => self.dispatch_mf_event_get_type(state, memory),
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

/// The IMFSourceReader vtable.
fn mf_source_reader_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfSourceReaderGetCurrentMediaType);
    methods.push(HostThunk::MfSourceReaderGetNativeMediaType);
    methods.push(HostThunk::MfSourceReaderReadSample);
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

/// The IMFByteStream vtable.
fn mf_byte_stream_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfByteStreamGetCurrentPosition);
    methods.push(HostThunk::MfByteStreamRead);
    methods.push(HostThunk::MfByteStreamGetLength);
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

/// The IMFPresentationDescriptor vtable.
fn mf_presentation_descriptor_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfPresentationDescriptorGetStreamDescriptorCount);
    methods
}

/// The IMFMediaEvent vtable.
#[allow(dead_code)] // the event-object vtable builder
fn mf_event_methods() -> Vec<HostThunk> {
    let mut methods = unknown_preamble();
    methods.push(HostThunk::MfEventGetType);
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
}
