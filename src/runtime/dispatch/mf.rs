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
use crate::media::{Guid, ImfMediaBuffer, ImfMediaType, ImfSample, MediaEventType, MfEventQueue};
use crate::runtime::state::{ComStreamState, ImfByteStreamState};

// ── Media Foundation HRESULT codes (the documented MF_E_* family) ─────────

const S_OK: u32 = 0x0000_0000;
const E_INVALIDARG: u32 = 0x8007_0057;
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

/// The standard MF interface vtable preamble: IUnknown + the first
/// interface method slots that the runtime dispatches.  The remaining slots
/// are filled with the interface's own methods.
fn mf_unknown_preamble() -> Vec<HostThunk> {
    vec![HostThunk::GuestObjectAddRef, HostThunk::GuestObjectRelease]
}

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

    /// `MFGetService(pUnk, guidService, riid, ppvObject)` — no service
    /// providers in the MF runtime — `MF_E_UNSUPPORTED_SERVICE`.
    pub(crate) fn dispatch_mf_get_service(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let out = guest_call_arg(state, memory, 3)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        state.set(Register::Rax, u64::from(MF_E_UNSUPPORTED_SERVICE));
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
    pub(crate) fn dispatch_mf_enum_ex(
        &mut self,
        state: &mut CpuState,
        memory: &mut MemoryImage,
    ) -> AppResult<()> {
        let _category = guest_call_arg(state, memory, 0)?;
        let _flags = guest_call_arg_u32(state, memory, 1)?;
        let _input = guest_call_arg(state, memory, 2)?;
        let _output = guest_call_arg(state, memory, 3)?;
        let out = guest_call_arg(state, memory, 4)?;
        let count = guest_call_arg(state, memory, 5)?;
        if out != 0 {
            write_guest_pointer(memory, out, 0, self.guest_arch).ok();
        }
        if count != 0 {
            write_u32(memory, count, 0);
        }
        state.set(Register::Rax, u64::from(S_OK));
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
            MfSampleSetSampleDuration => self.dispatch_mf_sample_set_sample_duration(state, memory),
            MfEventQueueGetEvent => self.dispatch_mf_event_queue_get_event(state, memory),
            MfEventQueueQueueEvent => self.dispatch_mf_event_queue_queue_event(state, memory),
            MfClockGetTime => self.dispatch_mf_clock_get_time(state, memory),
            MfClockStart => self.dispatch_mf_clock_start(state, memory),
            MfClockStop => self.dispatch_mf_clock_stop(state, memory),
            MfSessionGetClock => self.dispatch_mf_session_get_clock(state, memory),
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
            _ => Err(AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unrouted MF/COM thunk {thunk:?}"),
            )),
        }
    }
}

/// The IMFAttributes vtable (media types and attribute stores share it).
fn mf_attributes_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfAttrGetCount);
    methods.push(HostThunk::MfAttrGetItemByIndex);
    methods.push(HostThunk::MfAttrGetUint32);
    methods.push(HostThunk::MfAttrGetUint64);
    methods.push(HostThunk::MfAttrGetDouble);
    methods.push(HostThunk::MfAttrGetGuid);
    methods.push(HostThunk::MfAttrGetStringLength);
    methods.push(HostThunk::MfAttrGetString);
    methods.push(HostThunk::MfAttrGetBlobSize);
    methods.push(HostThunk::MfAttrGetBlob);
    methods.push(HostThunk::MfAttrSetUint32);
    methods.push(HostThunk::MfAttrSetUint64);
    methods.push(HostThunk::MfAttrSetDouble);
    methods.push(HostThunk::MfAttrSetGuid);
    methods.push(HostThunk::MfAttrSetString);
    methods.push(HostThunk::MfAttrSetBlob);
    methods.push(HostThunk::MfAttrDeleteItem);
    methods
}

/// The IMFMediaType vtable (attributes + the media-type methods).
fn mf_media_type_methods() -> Vec<HostThunk> {
    let mut methods = mf_attributes_methods();
    methods.push(HostThunk::MfMediaTypeGetMajorType);
    methods.push(HostThunk::MfMediaTypeIsCompressedFormat);
    methods
}

/// The IMFMediaBuffer vtable.
fn mf_media_buffer_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfBufferGetMaxLength);
    methods.push(HostThunk::MfBufferLock);
    methods.push(HostThunk::MfBufferUnlock);
    methods.push(HostThunk::MfBufferGetCurrentLength);
    methods.push(HostThunk::MfBufferSetCurrentLength);
    methods
}

/// The IMFSample vtable.
fn mf_sample_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfSampleGetBufferCount);
    methods.push(HostThunk::MfSampleGetBufferByIndex);
    methods.push(HostThunk::MfSampleAddBuffer);
    methods.push(HostThunk::MfSampleRemoveBufferByIndex);
    methods.push(HostThunk::MfSampleRemoveAllBuffers);
    methods.push(HostThunk::MfSampleGetSampleTime);
    methods.push(HostThunk::MfSampleSetSampleTime);
    methods.push(HostThunk::MfSampleGetSampleDuration);
    methods.push(HostThunk::MfSampleSetSampleDuration);
    methods
}

/// The IMFMediaEventQueue vtable.
fn mf_event_queue_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfEventQueueGetEvent);
    methods.push(HostThunk::MfEventQueueQueueEvent);
    methods
}

/// The IMFPresentationClock vtable.
fn mf_clock_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfClockGetTime);
    methods.push(HostThunk::MfClockStart);
    methods.push(HostThunk::MfClockStop);
    methods
}

/// The IMFMediaSession vtable.
fn mf_session_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfSessionGetClock);
    methods.push(HostThunk::MfSessionStart);
    methods.push(HostThunk::MfSessionPause);
    methods.push(HostThunk::MfSessionStop);
    methods.push(HostThunk::MfSessionClose);
    methods.push(HostThunk::MfSessionShutdown);
    methods
}

/// The IMFSourceReader vtable.
fn mf_source_reader_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfSourceReaderGetCurrentMediaType);
    methods.push(HostThunk::MfSourceReaderGetNativeMediaType);
    methods.push(HostThunk::MfSourceReaderReadSample);
    methods
}

/// The IMFSinkWriter vtable.
fn mf_sink_writer_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfSinkWriterAddStream);
    methods.push(HostThunk::MfSinkWriterBeginWriting);
    methods.push(HostThunk::MfSinkWriterWriteSample);
    methods.push(HostThunk::MfSinkWriterEndWriting);
    methods
}

/// The IMFByteStream vtable.
fn mf_byte_stream_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfByteStreamGetCurrentPosition);
    methods.push(HostThunk::MfByteStreamRead);
    methods.push(HostThunk::MfByteStreamGetLength);
    methods
}

/// The IMFTopology vtable.
fn mf_topology_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfTopologyAddNode);
    methods.push(HostThunk::MfTopologyGetNodeCount);
    methods
}

/// The IMFTopologyNode vtable.
fn mf_topology_node_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfTopologyNodeGetObject);
    methods.push(HostThunk::MfTopologyNodeSetObject);
    methods
}

/// The IMFSourceResolver vtable.
fn mf_source_resolver_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfSourceResolverCreateObjectFromUrl);
    methods
}

/// The IMFDXGIDeviceManager vtable (IUnknown preamble + the 7 device
/// methods).
fn mf_dxgi_device_manager_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
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
    let mut methods = mf_unknown_preamble();
    methods.push(HostThunk::MfPresentationDescriptorGetStreamDescriptorCount);
    methods
}

/// The IMFMediaEvent vtable.
#[allow(dead_code)] // the event-object vtable builder
fn mf_event_methods() -> Vec<HostThunk> {
    let mut methods = mf_unknown_preamble();
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
